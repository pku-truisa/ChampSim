/*
 *    Copyright 2023 The ChampSim Contributors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/*! @file
 *  This is a PIN tool that records all memory allocation and deallocation
 *  events to a binary trace file (malloc.bin). It does not generate any
 *  instruction-level trace — it focuses solely on heap/anon-mmap activity.
 *
 *  Hooked functions: malloc, calloc, realloc, posix_memalign,
 *  free, mmap (anonymous only), munmap.
 *
 *  aligned_alloc and memalign are NOT hooked. In glibc >= 2.16 they are
 *  thin wrappers around malloc (for small allocations) or mmap (for large
 *  ones via sysmalloc). Their IPOINT_AFTER callbacks cannot fire reliably
 *  due to tail-call optimization. The underlying malloc/mmap hooks capture
 *  these allocations with correct sizes and addresses, just recorded as
 *  type=malloc or type=mmap instead of type=aligned_alloc.
 *
 *  Key design: A depth counter (allocator_hook_depth) handles glibc's internal
 *  nested allocation calls (e.g. mmap inside malloc for large allocations).
 *  The inner call increments depth and returns silently; only the outermost
 *  user-level call writes the record. No manual "heal" mechanism is needed
 *  because every Before/After pair correctly manages depth.
 */

#include <fstream>
#include <iostream>
#include <cstdlib>
#include <cstring>
#include <unordered_set>

#include "pin.H"

/* ===================================================================== */
// Binary malloc trace record (40 bytes)
/* ===================================================================== */
struct malloc_instr {
  unsigned long long ip;       // caller's return address
  unsigned long long arg1;     // parameter 1
  unsigned long long arg2;     // parameter 2
  unsigned long long ret;      // return value
  unsigned char type;          // 1=malloc 2=free 3=mmap 4=munmap 5=calloc 6=realloc 7=aligned_alloc 8=posix_memalign 9=memalign
  unsigned char reserved[7];
};
static_assert(sizeof(malloc_instr) == 40, "malloc_instr must be exactly 40 bytes");

#ifndef MAP_ANONYMOUS
#define MAP_ANONYMOUS 0x20
#endif

/* ===================================================================== */
// Global state
/* ===================================================================== */
std::ofstream malloc_binfile;
std::unordered_set<ADDRINT> tracked_addresses;

ADDRINT pending_alloc_size = 0;
ADDRINT pending_alloc_memptr = 0;
ADDRINT pending_realloc_old_ptr = 0;
int pending_alloc_type = 0;
ADDRINT pending_alloc_ip = 0;

// Depth counter for allocator reentrancy protection.
INT32 allocator_hook_depth = 0;

/* ===================================================================== */
// Command line switches
/* ===================================================================== */
KNOB<std::string> KnobMallocOutputFile(KNOB_MODE_WRITEONCE, "pintool", "m", "malloc.bin",
                                       "specify file name for binary malloc trace output");

/* ===================================================================== */
// Utilities
/* ===================================================================== */
INT32 Usage()
{
  std::cerr << "This tool records all memory allocation and deallocation events." << std::endl
            << "Specify the binary malloc trace output file with -m (default: malloc.bin)" << std::endl << std::endl;
  std::cerr << KNOB_BASE::StringKnobSummary() << std::endl;
  return -1;
}

void write_malloc_instr(unsigned long long ip, unsigned char type,
                        unsigned long long arg1, unsigned long long arg2,
                        unsigned long long ret)
{
  if (malloc_binfile.is_open()) {
    malloc_instr rec;
    rec.ip = ip;
    rec.type = type;
    rec.arg1 = arg1;
    rec.arg2 = arg2;
    rec.ret = ret;
    std::memset(rec.reserved, 0, sizeof(rec.reserved));
    typename decltype(malloc_binfile)::char_type buf[sizeof(malloc_instr)];
    std::memcpy(buf, &rec, sizeof(malloc_instr));
    malloc_binfile.write(buf, sizeof(malloc_instr));
  }
}

/* ===================================================================== */
// Callback implementations
/* ===================================================================== */

// --- MALLOC ---
VOID MallocBefore(ADDRINT size, ADDRINT ip)
{
  if (allocator_hook_depth > 0) {
    allocator_hook_depth++;
    return;
  }
  allocator_hook_depth = 1;
  pending_alloc_size = size;
  pending_alloc_type = 1;
  pending_alloc_ip = ip;
}

VOID MallocAfter(ADDRINT ret)
{
  if (allocator_hook_depth > 1) { allocator_hook_depth--; return; }
  if (allocator_hook_depth == 0) return;
  allocator_hook_depth = 0;

  bool is_valid_type = (pending_alloc_type == 1 || pending_alloc_type == 5 ||
                        pending_alloc_type == 6);
  if (!is_valid_type) {
    pending_alloc_size = 0;
    pending_alloc_type = 0;
    pending_realloc_old_ptr = 0;
    return;
  }

  if (pending_alloc_type == 6) {
    write_malloc_instr(pending_alloc_ip, 6, pending_realloc_old_ptr, pending_alloc_size, ret);
    if (ret != 0) {
      tracked_addresses.insert(ret);
      if (pending_realloc_old_ptr != 0 && pending_realloc_old_ptr != ret) {
        auto it = tracked_addresses.find(pending_realloc_old_ptr);
        if (it != tracked_addresses.end()) tracked_addresses.erase(it);
      }
    }
  } else if (ret != 0) {
    write_malloc_instr(pending_alloc_ip, (unsigned char)pending_alloc_type, pending_alloc_size, 0, ret);
    tracked_addresses.insert(ret);
  }
  pending_alloc_size = 0;
  pending_alloc_type = 0;
  pending_realloc_old_ptr = 0;
}

// --- CALLOC ---
VOID CallocBefore(ADDRINT nmemb, ADDRINT size, ADDRINT ip)
{
  if (allocator_hook_depth > 0) { allocator_hook_depth++; return; }
  allocator_hook_depth = 1;
  pending_alloc_size = nmemb * size;
  pending_alloc_type = 5;
  pending_alloc_ip = ip;
}

// --- REALLOC ---
VOID ReallocBefore(ADDRINT ptr, ADDRINT size, ADDRINT ip)
{
  if (allocator_hook_depth > 0) { allocator_hook_depth++; return; }
  allocator_hook_depth = 1;
  pending_alloc_size = size;
  pending_alloc_type = 6;
  pending_alloc_ip = ip;
  pending_realloc_old_ptr = ptr;
}

// --- FREE ---
VOID FreeBefore(ADDRINT ptr, ADDRINT ip)
{
  if (ptr == 0) {
    if (allocator_hook_depth > 0) allocator_hook_depth++;
    return;
  }
  if (allocator_hook_depth > 0) { allocator_hook_depth++; return; }
  allocator_hook_depth = 1;

  auto it = tracked_addresses.find(ptr);
  if (it != tracked_addresses.end()) {
    write_malloc_instr((unsigned long long)ip, 2, (unsigned long long)ptr, 0, 0);
    tracked_addresses.erase(it);
  }
}

VOID FreeAfter()
{
  if (allocator_hook_depth > 1) { allocator_hook_depth--; return; }
  if (allocator_hook_depth == 0) return;
  allocator_hook_depth = 0;
}

// --- POSIX_MEMALIGN ---
VOID PosixMemalignBefore(ADDRINT memptr, ADDRINT size, ADDRINT ip)
{
  if (allocator_hook_depth > 0) { allocator_hook_depth++; return; }
  allocator_hook_depth = 1;
  pending_alloc_size = size;
  pending_alloc_type = 8;
  pending_alloc_memptr = memptr;
  pending_alloc_ip = ip;
}

VOID PosixMemalignAfter(ADDRINT ret, ADDRINT ip)
{
  if (allocator_hook_depth > 1) { allocator_hook_depth--; return; }
  if (allocator_hook_depth == 0) return;
  allocator_hook_depth = 0;

  if (pending_alloc_type != 8) {
    pending_alloc_size = 0;
    pending_alloc_type = 0;
    pending_alloc_memptr = 0;
    return;
  }

  if (ret == 0 && pending_alloc_memptr != 0) {
    ADDRINT allocated_addr = 0;
    PIN_SafeCopy(&allocated_addr, (VOID*)pending_alloc_memptr, sizeof(ADDRINT));
    if (allocated_addr != 0) {
      write_malloc_instr(pending_alloc_ip, 8, pending_alloc_size, 0, allocated_addr);
      tracked_addresses.insert(allocated_addr);
    }
  }
  pending_alloc_size = 0;
  pending_alloc_type = 0;
  pending_alloc_memptr = 0;
}

// --- MMAP ---
VOID MmapBefore(ADDRINT length, ADDRINT flags, ADDRINT ip)
{
  if (allocator_hook_depth > 0) { allocator_hook_depth++; return; }
  allocator_hook_depth = 1;

  if (!(flags & MAP_ANONYMOUS)) {
    allocator_hook_depth = 0;
    return;
  }
  pending_alloc_size = length;
  pending_alloc_type = 3;
  pending_alloc_ip = ip;
}

VOID MmapAfter(ADDRINT ret)
{
  if (allocator_hook_depth > 1) { allocator_hook_depth--; return; }
  if (allocator_hook_depth == 0) return;
  allocator_hook_depth = 0;

  if (pending_alloc_type != 3) {
    pending_alloc_size = 0;
    pending_alloc_type = 0;
    return;
  }
  if (ret != 0 && ret != (ADDRINT)-1) {
    write_malloc_instr(pending_alloc_ip, 3, pending_alloc_size, 0, ret);
    tracked_addresses.insert(ret);
  }
  pending_alloc_size = 0;
  pending_alloc_type = 0;
}

// --- MUNMAP ---
VOID MunmapBefore(ADDRINT addr, ADDRINT length, ADDRINT ip)
{
  if (addr == 0 || addr == (ADDRINT)-1) {
    if (allocator_hook_depth > 0) allocator_hook_depth++;
    return;
  }
  if (allocator_hook_depth > 0) { allocator_hook_depth++; return; }
  allocator_hook_depth = 1;

  auto it = tracked_addresses.find(addr);
  if (it != tracked_addresses.end()) {
    write_malloc_instr((unsigned long long)ip, 4, (unsigned long long)addr, (unsigned long long)length, 0);
    tracked_addresses.erase(it);
  }
}

VOID MunmapAfter()
{
  if (allocator_hook_depth > 1) { allocator_hook_depth--; return; }
  if (allocator_hook_depth == 0) return;
  allocator_hook_depth = 0;
}

/* ===================================================================== */
// ImageLoad
/* ===================================================================== */
VOID ImageLoad(IMG img, VOID* v)
{
  if (!IMG_Valid(img)) return;

  RTN rtn;
  bool instrumented = false;

  // malloc
  rtn = RTN_FindByName(img, "malloc");
  if (RTN_Valid(rtn)) {
    RTN_Open(rtn);
    RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)MallocBefore, IARG_FUNCARG_ENTRYPOINT_VALUE, 0, IARG_RETURN_IP, IARG_END);
    RTN_InsertCall(rtn, IPOINT_AFTER, (AFUNPTR)MallocAfter, IARG_FUNCRET_EXITPOINT_VALUE, IARG_END);
    RTN_Close(rtn);
    instrumented = true;
  }

  // calloc
  rtn = RTN_FindByName(img, "calloc");
  if (RTN_Valid(rtn)) {
    RTN_Open(rtn);
    RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)CallocBefore, IARG_FUNCARG_ENTRYPOINT_VALUE, 0, IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
                   IARG_RETURN_IP, IARG_END);
    RTN_InsertCall(rtn, IPOINT_AFTER, (AFUNPTR)MallocAfter, IARG_FUNCRET_EXITPOINT_VALUE, IARG_END);
    RTN_Close(rtn);
    instrumented = true;
  }

  // realloc
  rtn = RTN_FindByName(img, "realloc");
  if (RTN_Valid(rtn)) {
    RTN_Open(rtn);
    RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)ReallocBefore, IARG_FUNCARG_ENTRYPOINT_VALUE, 0, IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
                   IARG_RETURN_IP, IARG_END);
    RTN_InsertCall(rtn, IPOINT_AFTER, (AFUNPTR)MallocAfter, IARG_FUNCRET_EXITPOINT_VALUE, IARG_END);
    RTN_Close(rtn);
    instrumented = true;
  }

  // posix_memalign
  rtn = RTN_FindByName(img, "posix_memalign");
  if (RTN_Valid(rtn)) {
    RTN_Open(rtn);
    RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)PosixMemalignBefore, IARG_FUNCARG_ENTRYPOINT_VALUE, 0, IARG_FUNCARG_ENTRYPOINT_VALUE, 2,
                   IARG_RETURN_IP, IARG_END);
    RTN_InsertCall(rtn, IPOINT_AFTER, (AFUNPTR)PosixMemalignAfter, IARG_FUNCRET_EXITPOINT_VALUE, IARG_RETURN_IP, IARG_END);
    RTN_Close(rtn);
    instrumented = true;
  }

  // free
  rtn = RTN_FindByName(img, "free");
  if (RTN_Valid(rtn)) {
    RTN_Open(rtn);
    RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)FreeBefore, IARG_FUNCARG_ENTRYPOINT_VALUE, 0, IARG_RETURN_IP, IARG_END);
    RTN_InsertCall(rtn, IPOINT_AFTER, (AFUNPTR)FreeAfter, IARG_END);
    RTN_Close(rtn);
    instrumented = true;
  }

  // mmap
  rtn = RTN_FindByName(img, "mmap");
  if (RTN_Valid(rtn)) {
    RTN_Open(rtn);
    RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)MmapBefore, IARG_FUNCARG_ENTRYPOINT_VALUE, 1, IARG_FUNCARG_ENTRYPOINT_VALUE, 3,
                   IARG_RETURN_IP, IARG_END);
    RTN_InsertCall(rtn, IPOINT_AFTER, (AFUNPTR)MmapAfter, IARG_FUNCRET_EXITPOINT_VALUE, IARG_END);
    RTN_Close(rtn);
    instrumented = true;
  }

  // munmap
  rtn = RTN_FindByName(img, "munmap");
  if (RTN_Valid(rtn)) {
    RTN_Open(rtn);
    RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)MunmapBefore, IARG_FUNCARG_ENTRYPOINT_VALUE, 0, IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
                   IARG_RETURN_IP, IARG_END);
    RTN_InsertCall(rtn, IPOINT_AFTER, (AFUNPTR)MunmapAfter, IARG_END);
    RTN_Close(rtn);
    instrumented = true;
  }

  if (instrumented)
    std::cout << "[Object Tracer] Instrumenting: " << IMG_Name(img) << std::endl;
}

/* ===================================================================== */
VOID Fini(INT32 code, VOID* v)
{
  malloc_binfile.close();
  std::cout << "[Object Tracer] Binary malloc trace saved." << std::endl;
  std::cout << "  Tracked addresses at exit: " << tracked_addresses.size() << std::endl;
}

int main(int argc, char* argv[])
{
  PIN_InitSymbols();
  if (PIN_Init(argc, argv))
    return Usage();
  malloc_binfile.open(KnobMallocOutputFile.Value().c_str(), std::ios_base::binary | std::ios_base::trunc);
  if (!malloc_binfile) {
    std::cout << "Couldn't open binary malloc trace file. Exiting." << std::endl;
    exit(1);
  }
  IMG_AddInstrumentFunction(ImageLoad, 0);
  PIN_AddFiniFunction(Fini, 0);
  PIN_StartProgram();
  return 0;
}