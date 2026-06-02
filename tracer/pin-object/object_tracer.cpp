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
 *  The binary record format (malloc_instr, 40 bytes) is merged from
 *  inc/trace_instruction.h so that this tool is self-contained.
 */

#include <fstream>
#include <iostream>
#include <cstdlib>
#include <cstring>
#include <unordered_set>

#include "pin.H"

// ---------------------------------------------------------------------------
// Binary malloc trace record (40 bytes), merged from inc/trace_instruction.h
// ---------------------------------------------------------------------------
// type:
//   1=malloc  2=free  3=mmap  4=munmap  5=calloc  6=realloc
//   7=aligned_alloc  8=posix_memalign  9=memalign
struct malloc_instr {
  unsigned long long ip;       // caller's return address
  unsigned long long arg1;     // parameter 1 (alloc=size, free/munmap=ptr, realloc=old_ptr)
  unsigned long long arg2;     // parameter 2 (realloc=size, munmap=length; 0 otherwise)
  unsigned long long ret;      // return value (allocated address, 0=failure)
  unsigned char type;          // allocation event type
  unsigned char reserved[7];   // alignment padding (total = 40 bytes)
};
static_assert(sizeof(malloc_instr) == 40, "malloc_instr must be exactly 40 bytes");

#ifndef MAP_ANONYMOUS
#define MAP_ANONYMOUS 0x20  // Linux x86_64
#endif

/* ================================================================== */
// Global variables
/* ================================================================== */
std::ofstream malloc_binfile;
std::unordered_set<ADDRINT> tracked_addresses;

ADDRINT pending_alloc_size = 0;
ADDRINT pending_alloc_memptr = 0;   // for posix_memalign
ADDRINT pending_realloc_old_ptr = 0; // for realloc old pointer
int pending_alloc_type = 0;          // 0: none, 1: malloc, 3: mmap, 5: calloc, 6: realloc, 7: aligned_alloc, 8: posix_memalign, 9: memalign
ADDRINT pending_alloc_ip = 0;        // caller IP stored for After callbacks

// Depth counter for allocator reentrancy protection (fixes realloc nesting defects).
// Replaces the faulty boolean in_allocator_hook that could be prematurely cleared
// by inner After callbacks during glibc's internal malloc/free calls within realloc.
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
            << "Specify the binary malloc trace output file with -m (default: malloc.bin)" << std::endl
            << std::endl;
  std::cerr << KNOB_BASE::StringKnobSummary() << std::endl;
  return -1;
}

/* ===================================================================== */
// Binary malloc trace writing
/* ===================================================================== */
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
    for (int i = 0; i < 7; i++)
      rec.reserved[i] = 0;

    typename decltype(malloc_binfile)::char_type buf[sizeof(malloc_instr)];
    std::memcpy(buf, &rec, sizeof(malloc_instr));
    malloc_binfile.write(buf, sizeof(malloc_instr));
  }
}

/* ===================================================================== */
// Allocator analysis routines
//
// All Before/After callbacks use a depth counter (allocator_hook_depth)
// instead of a boolean reentrancy lock.  This correctly handles nested
// internal malloc/free/mmap/munmap calls within glibc's realloc, etc.
// Only the outermost user-level call writes records.
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
  pending_alloc_type = 1; // 1: malloc
  pending_alloc_ip = ip;
}

VOID MallocAfter(ADDRINT ret)
{
  if (allocator_hook_depth > 1) {
    allocator_hook_depth--;
    return;
  }
  if (allocator_hook_depth == 0)
    return;
  allocator_hook_depth = 0;

  // Handle different allocation types that use MallocAfter as the After callback
  // 1=malloc, 5=calloc, 6=realloc, 7=aligned_alloc
  bool is_valid_type = (pending_alloc_type == 1 || pending_alloc_type == 5 ||
                        pending_alloc_type == 6 || pending_alloc_type == 7);
  if (!is_valid_type) {
    pending_alloc_size = 0;
    pending_alloc_type = 0;
    return;
  }

  if (pending_alloc_type == 6) {
    // realloc: arg1=old_ptr, arg2=new_size, ret=new_ptr (or 0 on failure)
    write_malloc_instr(pending_alloc_ip, 6, pending_realloc_old_ptr, pending_alloc_size, ret);
    if (ret != 0) {
      tracked_addresses.insert(ret);
      // Remove old pointer if it differs from new one
      if (pending_realloc_old_ptr != 0 && pending_realloc_old_ptr != ret) {
        auto it = tracked_addresses.find(pending_realloc_old_ptr);
        if (it != tracked_addresses.end())
          tracked_addresses.erase(it);
      }
    }
  } else if (ret != 0) {
    // malloc/calloc/aligned_alloc: arg1=size, ret=allocated address
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
  if (allocator_hook_depth > 0) {
    allocator_hook_depth++;
    return;
  }
  allocator_hook_depth = 1;

  pending_alloc_size = nmemb * size;
  pending_alloc_type = 5; // 5: calloc
  pending_alloc_ip = ip;
}

// --- REALLOC ---
VOID ReallocBefore(ADDRINT ptr, ADDRINT size, ADDRINT ip)
{
  if (allocator_hook_depth > 0) {
    allocator_hook_depth++;
    return;
  }
  allocator_hook_depth = 1;

  pending_alloc_size = size;
  pending_alloc_type = 6; // 6: realloc
  pending_alloc_ip = ip;
  pending_realloc_old_ptr = ptr;
}

// --- ALIGNED_ALLOC ---
VOID AlignedAllocBefore(ADDRINT alignment, ADDRINT size, ADDRINT ip)
{
  if (allocator_hook_depth > 0) {
    allocator_hook_depth++;
    return;
  }
  allocator_hook_depth = 1;

  pending_alloc_size = size;
  pending_alloc_type = 7; // 7: aligned_alloc
  pending_alloc_ip = ip;
}

// --- FREE ---
VOID FreeBefore(ADDRINT ptr, ADDRINT ip)
{
  if (ptr == 0)
    return;

  if (allocator_hook_depth > 0) {
    allocator_hook_depth++;
    return;
  }
  allocator_hook_depth = 1;

  auto it = tracked_addresses.find(ptr);
  if (it != tracked_addresses.end()) {
    write_malloc_instr((unsigned long long)ip, 2, (unsigned long long)ptr, 0, 0);
    tracked_addresses.erase(it);
  }
  // Objects not in tracked_addresses are silently ignored (static memory, etc.)
}

VOID FreeAfter()
{
  if (allocator_hook_depth > 1) {
    allocator_hook_depth--;
    return;
  }
  if (allocator_hook_depth == 0)
    return;
  allocator_hook_depth = 0;
}

// --- POSIX_MEMALIGN ---
VOID PosixMemalignBefore(ADDRINT memptr, ADDRINT size, ADDRINT ip)
{
  if (allocator_hook_depth > 0) {
    allocator_hook_depth++;
    return;
  }
  allocator_hook_depth = 1;

  pending_alloc_size = size;
  pending_alloc_type = 8; // 8: posix_memalign
  pending_alloc_memptr = memptr;
  pending_alloc_ip = ip;
}

VOID PosixMemalignAfter(ADDRINT ret, ADDRINT ip)
{
  if (allocator_hook_depth > 1) {
    allocator_hook_depth--;
    return;
  }
  if (allocator_hook_depth == 0)
    return;
  allocator_hook_depth = 0;

  if (pending_alloc_type != 8) {
    pending_alloc_size = 0;
    pending_alloc_memptr = 0;
    return;
  }

  // For posix_memalign, the return value is the error code (0 on success).
  // The actual pointer is stored in *memptr.
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
  if (allocator_hook_depth > 0) {
    allocator_hook_depth++;
    return;
  }
  allocator_hook_depth = 1;

  // Only track anonymous mappings (MAP_ANONYMOUS)
  if (!(flags & MAP_ANONYMOUS)) {
    allocator_hook_depth = 0;
    return;
  }

  pending_alloc_size = length;
  pending_alloc_type = 3; // 3: mmap
  pending_alloc_ip = ip;
}

VOID MmapAfter(ADDRINT ret)
{
  if (allocator_hook_depth > 1) {
    allocator_hook_depth--;
    return;
  }
  if (allocator_hook_depth == 0)
    return;
  allocator_hook_depth = 0;

  if (pending_alloc_type != 3) {
    pending_alloc_size = 0;
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
  if (addr == 0 || addr == (ADDRINT)-1)
    return;

  if (allocator_hook_depth > 0) {
    allocator_hook_depth++;
    return;
  }
  allocator_hook_depth = 1;

  auto it = tracked_addresses.find(addr);
  if (it != tracked_addresses.end()) {
    write_malloc_instr((unsigned long long)ip, 4, (unsigned long long)addr, (unsigned long long)length, 0);
    tracked_addresses.erase(it);
  }
}

VOID MunmapAfter()
{
  if (allocator_hook_depth > 1) {
    allocator_hook_depth--;
    return;
  }
  if (allocator_hook_depth == 0)
    return;
  allocator_hook_depth = 0;
}

/* ===================================================================== */
// ImageLoad: Instrument allocator functions in every loaded image
//
// Only hook functions in images that actually define one of the target
// symbols.  The allocator_hook_depth counter prevents double-counting
// from nested internal glibc calls.
/* ===================================================================== */
VOID ImageLoad(IMG img, VOID* v)
{
  if (!IMG_Valid(img))
    return;

  bool has_symbols = false;
  const char* func_names[] = {"malloc", "calloc", "realloc", "free", "mmap", "munmap", "aligned_alloc", "posix_memalign"};
  for (const char* name : func_names) {
    RTN test_rtn = RTN_FindByName(img, name);
    if (RTN_Valid(test_rtn)) {
      has_symbols = true;
      break;
    }
  }
  if (!has_symbols)
    return;

  std::cout << "[Object Tracer] Instrumenting: " << IMG_Name(img) << std::endl;

  RTN rtn;

  // Hook malloc
  rtn = RTN_FindByName(img, "malloc");
  if (RTN_Valid(rtn)) {
    RTN_Open(rtn);
    RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)MallocBefore, IARG_FUNCARG_ENTRYPOINT_VALUE, 0, IARG_RETURN_IP, IARG_END);
    RTN_InsertCall(rtn, IPOINT_AFTER, (AFUNPTR)MallocAfter, IARG_FUNCRET_EXITPOINT_VALUE, IARG_END);
    RTN_Close(rtn);
  }

  // Hook calloc
  rtn = RTN_FindByName(img, "calloc");
  if (RTN_Valid(rtn)) {
    RTN_Open(rtn);
    RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)CallocBefore, IARG_FUNCARG_ENTRYPOINT_VALUE, 0, IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
                   IARG_RETURN_IP, IARG_END);
    RTN_InsertCall(rtn, IPOINT_AFTER, (AFUNPTR)MallocAfter, IARG_FUNCRET_EXITPOINT_VALUE, IARG_END);
    RTN_Close(rtn);
  }

  // Hook realloc
  rtn = RTN_FindByName(img, "realloc");
  if (RTN_Valid(rtn)) {
    RTN_Open(rtn);
    RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)ReallocBefore, IARG_FUNCARG_ENTRYPOINT_VALUE, 0, IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
                   IARG_RETURN_IP, IARG_END);
    RTN_InsertCall(rtn, IPOINT_AFTER, (AFUNPTR)MallocAfter, IARG_FUNCRET_EXITPOINT_VALUE, IARG_END);
    RTN_Close(rtn);
  }

  // Hook aligned_alloc
  rtn = RTN_FindByName(img, "aligned_alloc");
  if (RTN_Valid(rtn)) {
    RTN_Open(rtn);
    RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)AlignedAllocBefore, IARG_FUNCARG_ENTRYPOINT_VALUE, 0, IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
                   IARG_RETURN_IP, IARG_END);
    RTN_InsertCall(rtn, IPOINT_AFTER, (AFUNPTR)MallocAfter, IARG_FUNCRET_EXITPOINT_VALUE, IARG_END);
    RTN_Close(rtn);
  }

  // Hook posix_memalign
  rtn = RTN_FindByName(img, "posix_memalign");
  if (RTN_Valid(rtn)) {
    RTN_Open(rtn);
    RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)PosixMemalignBefore, IARG_FUNCARG_ENTRYPOINT_VALUE, 0, IARG_FUNCARG_ENTRYPOINT_VALUE, 2,
                   IARG_RETURN_IP, IARG_END);
    RTN_InsertCall(rtn, IPOINT_AFTER, (AFUNPTR)PosixMemalignAfter, IARG_FUNCRET_EXITPOINT_VALUE, IARG_RETURN_IP, IARG_END);
    RTN_Close(rtn);
  }

  // Hook free
  rtn = RTN_FindByName(img, "free");
  if (RTN_Valid(rtn)) {
    RTN_Open(rtn);
    RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)FreeBefore, IARG_FUNCARG_ENTRYPOINT_VALUE, 0, IARG_RETURN_IP, IARG_END);
    RTN_InsertCall(rtn, IPOINT_AFTER, (AFUNPTR)FreeAfter, IARG_END);
    RTN_Close(rtn);
  }

  // Hook mmap
  rtn = RTN_FindByName(img, "mmap");
  if (RTN_Valid(rtn)) {
    RTN_Open(rtn);
    RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)MmapBefore, IARG_FUNCARG_ENTRYPOINT_VALUE, 1, IARG_FUNCARG_ENTRYPOINT_VALUE, 3,
                   IARG_RETURN_IP, IARG_END);
    RTN_InsertCall(rtn, IPOINT_AFTER, (AFUNPTR)MmapAfter, IARG_FUNCRET_EXITPOINT_VALUE, IARG_END);
    RTN_Close(rtn);
  }

  // Hook munmap
  rtn = RTN_FindByName(img, "munmap");
  if (RTN_Valid(rtn)) {
    RTN_Open(rtn);
    RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)MunmapBefore, IARG_FUNCARG_ENTRYPOINT_VALUE, 0, IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
                   IARG_RETURN_IP, IARG_END);
    RTN_InsertCall(rtn, IPOINT_AFTER, (AFUNPTR)MunmapAfter, IARG_END);
    RTN_Close(rtn);
  }
}

/* ===================================================================== */
/*!
 * Print out analysis results.
 * This function is called when the application exits.
 * @param[in]   code            exit code of the application
 * @param[in]   v               value specified by the tool in the
 *                              PIN_AddFiniFunction function call
 */
VOID Fini(INT32 code, VOID* v)
{
  malloc_binfile.close();
  std::cout << "[Object Tracer] Binary malloc trace saved." << std::endl;
  std::cout << "  Tracked addresses at exit: " << tracked_addresses.size() << std::endl;
}

/* ===================================================================== */
/*!
 * The main procedure of the tool.
 * This function is called when the application image is loaded but not yet started.
 * @param[in]   argc            total number of elements in the argv array
 * @param[in]   argv            array of command line arguments,
 *                              including pin -t <toolname> -- ...
 */
int main(int argc, char* argv[])
{
  // Initialize PIN library. Print help message if -h(elp) is specified
  // in the command line or the command line is invalid
  PIN_InitSymbols();
  if (PIN_Init(argc, argv))
    return Usage();

  // Open binary malloc trace output
  malloc_binfile.open(KnobMallocOutputFile.Value().c_str(), std::ios_base::binary | std::ios_base::trunc);
  if (!malloc_binfile) {
    std::cout << "Couldn't open binary malloc trace file. Exiting." << std::endl;
    exit(1);
  }

  IMG_AddInstrumentFunction(ImageLoad, 0);

  // Register function to be called when the application exits
  PIN_AddFiniFunction(Fini, 0);

  // Start the program, never returns
  PIN_StartProgram();

  return 0;
}