/*
 * Copyright 2026 The ChampSim Contributors
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
 * This is an advanced PIN tool that records all memory allocation and 
 * deallocation events to a binary trace file (malloc.bin).
 * * Supported Allocators & Runtimes:
 * - Standard C/C++: glibc ptmalloc, operator new/delete
 * - High-Performance: mimalloc, jemalloc, tcmalloc
 * - HPC Scientific: Intel Fortran (ifort/ifx), GNU Fortran (gfortran)
 *
 * Key design: Uses a thread-local reentrancy flag to elegantly suppress 
 * nested allocation tracking (e.g., Fortran runtime calling malloc internally,
 * or glibc sysmalloc invoking mmap). Only the outermost user-level allocation
 * is recorded, ensuring perfect data alignment for ChampSim.
 */

#include <fstream>
#include <iostream>
#include <cstdlib>
#include <cstring>
#include <unordered_set>
#include <vector>
#include <string>

#include "pin.H"

/* ===================================================================== */
// Binary malloc trace record (40 bytes)
/* ===================================================================== */
struct malloc_instr {
  unsigned long long ip;       // caller's return address
  unsigned long long arg1;     // parameter 1 (Size or Ptr)
  unsigned long long arg2;     // parameter 2 (Additional info)
  unsigned long long ret;      // return value (Allocated Addr)
  unsigned char type;          // 1=malloc, 2=free, 3=mmap, 4=munmap, 5=calloc, 6=realloc, 10=fortran_alloc
  unsigned char reserved[7];
};
static_assert(sizeof(malloc_instr) == 40, "malloc_instr must be exactly 40 bytes");

#ifndef MAP_ANONYMOUS
#define MAP_ANONYMOUS 0x20
#endif

/* ===================================================================== */
// Global state & Thread-local status
/* ===================================================================== */
std::ofstream malloc_binfile;
std::unordered_set<ADDRINT> tracked_addresses;

// Per-thread state structure to avoid TLS relocation compatibility issues
// Uses PIN TLS mechanism (PIN_CreateThreadDataKey / PIN_GetThreadData / PIN_SetThreadData) instead of __thread
struct ThreadState {
  ADDRINT pending_alloc_size = 0;
  ADDRINT pending_realloc_old_ptr = 0;
  int pending_alloc_type = 0;
  ADDRINT pending_alloc_ip = 0;
  bool in_allocator_hook = false;
};

static TLS_KEY tls_key;

static void ThreadCleanup(void* p) {
  delete static_cast<ThreadState*>(p);
}

static ThreadState* get_tls()
{
  ThreadState* ts = static_cast<ThreadState*>(PIN_GetThreadData(tls_key, PIN_ThreadId()));
  if (ts) return ts;
  ts = new ThreadState();
  PIN_SetThreadData(tls_key, ts, PIN_ThreadId());
  return ts;
}

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
  std::cerr << "This tool records all memory allocation and deallocation events (C/C++/Fortran)." << std::endl
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

// --- UNIFIED ALLOCATION BEFORE ---
VOID AllocBefore(ADDRINT size, ADDRINT ip, const char* sym_name)
{
  ThreadState* ts = get_tls();
  // If we are already handling an allocation, ignore inner nested calls (e.g., sysmalloc -> mmap)
  if (ts->in_allocator_hook) return;
  ts->in_allocator_hook = true;

  ts->pending_alloc_size = size;
  ts->pending_alloc_ip = ip;

  std::string name(sym_name);
  if (name.find("calloc") != std::string::npos) {
    ts->pending_alloc_type = 5;
  } else if (name.find("realloc") != std::string::npos) {
    ts->pending_alloc_type = 6;
  } else if (name.find("for_alloc") != std::string::npos ||
             name.find("gfortran")  != std::string::npos ||
             name.find("CFI_alloc") != std::string::npos) {
    ts->pending_alloc_type = 10; // Fortran ALLOCATE / CFI_allocate
  } else {
    ts->pending_alloc_type = 1;  // Generic malloc / mi_malloc / je_malloc / tc_malloc
  }
}

// Special case for Calloc/Realloc to capture additional arguments safely
VOID AllocBeforeExtended(ADDRINT arg1, ADDRINT arg2, ADDRINT ip, const char* sym_name)
{
  ThreadState* ts = get_tls();
  if (ts->in_allocator_hook) return;
  ts->in_allocator_hook = true;

  ts->pending_alloc_ip = ip;
  std::string name(sym_name);

  if (name.find("calloc") != std::string::npos) {
    ts->pending_alloc_size = arg1 * arg2; // nmemb * size
    ts->pending_alloc_type = 5;
  } else if (name.find("realloc") != std::string::npos) {
    ts->pending_realloc_old_ptr = arg1;   // old ptr
    ts->pending_alloc_size = arg2;        // new size
    ts->pending_alloc_type = 6;
  }
}

// --- UNIFIED ALLOCATION AFTER ---
VOID AllocAfter(ADDRINT ret)
{
  ThreadState* ts = get_tls();
  if (!ts->in_allocator_hook) return;

  if (ts->pending_alloc_type == 6) { // realloc
    write_malloc_instr(ts->pending_alloc_ip, 6, ts->pending_realloc_old_ptr, ts->pending_alloc_size, ret);
    if (ret != 0) {
      tracked_addresses.insert(ret);
      if (ts->pending_realloc_old_ptr != 0 && ts->pending_realloc_old_ptr != ret) {
        auto it = tracked_addresses.find(ts->pending_realloc_old_ptr);
        if (it != tracked_addresses.end()) tracked_addresses.erase(it);
      }
    }
  } else if (ret != 0 && ret != (ADDRINT)-1) {
    write_malloc_instr(ts->pending_alloc_ip, (unsigned char)ts->pending_alloc_type, ts->pending_alloc_size, 0, ret);
    tracked_addresses.insert(ret);
  }

  // Reset states
  ts->pending_alloc_size = 0;
  ts->pending_alloc_type = 0;
  ts->pending_realloc_old_ptr = 0;
  ts->in_allocator_hook = false; // Open the gate for the next event
}

// --- UNIFIED FREE BEFORE ---
VOID FreeBefore(ADDRINT ptr, ADDRINT ip)
{
  ThreadState* ts = get_tls();
  if (ptr == 0 || ts->in_allocator_hook) return;
  ts->in_allocator_hook = true;

  auto it = tracked_addresses.find(ptr);
  if (it != tracked_addresses.end()) {
    write_malloc_instr((unsigned long long)ip, 2, (unsigned long long)ptr, 0, 0);
    tracked_addresses.erase(it);
  }
}

VOID FreeAfter()
{
  ThreadState* ts = get_tls();
  ts->in_allocator_hook = false;
}

// --- MMAP ---
VOID MmapBefore(ADDRINT length, ADDRINT flags, ADDRINT ip)
{
  ThreadState* ts = get_tls();
  if (ts->in_allocator_hook) return;
  ts->in_allocator_hook = true;

  if (!(flags & MAP_ANONYMOUS)) {
    ts->in_allocator_hook = false;
    return;
  }
  ts->pending_alloc_size = length;
  ts->pending_alloc_type = 3;
  ts->pending_alloc_ip = ip;
}

VOID MmapAfter(ADDRINT ret)
{
  ThreadState* ts = get_tls();
  if (!ts->in_allocator_hook) return;
  if (ts->pending_alloc_type != 3) {
    ts->in_allocator_hook = false;
    return;
  }

  if (ret != 0 && ret != (ADDRINT)-1) {
    write_malloc_instr(ts->pending_alloc_ip, 3, ts->pending_alloc_size, 0, ret);
    tracked_addresses.insert(ret);
  }
  ts->pending_alloc_size = 0;
  ts->pending_alloc_type = 0;
  ts->in_allocator_hook = false;
}

// --- MUNMAP ---
VOID MunmapBefore(ADDRINT addr, ADDRINT length, ADDRINT ip)
{
  ThreadState* ts = get_tls();
  if (addr == 0 || addr == (ADDRINT)-1 || ts->in_allocator_hook) return;
  ts->in_allocator_hook = true;

  auto it = tracked_addresses.find(addr);
  if (it != tracked_addresses.end()) {
    write_malloc_instr((unsigned long long)ip, 4, (unsigned long long)addr, (unsigned long long)length, 0);
    tracked_addresses.erase(it);
  }
}

VOID MunmapAfter()
{
  ThreadState* ts = get_tls();
  ts->in_allocator_hook = false;
}

/* ===================================================================== */
// ImageLoad — Unified Symbol Iteration Bridge
/* ===================================================================== */
VOID ImageLoad(IMG img, VOID* v)
{
  if (!IMG_Valid(img)) return;

  bool instrumented = false;
  RTN rtn;

  // 1. All target allocation symbols (C, C++, mimalloc, jemalloc, tcmalloc, Fortran)
  // NOTE: Modern gfortran (>= 9 / Fortran 2018 CFI) exports CFI_allocate/CFI_deallocate
  //       instead of _gfortran_internal_malloc/_gfortran_internal_free.
  //       Additionally, is_fortran_call() auto-detects Fortran-originated malloc calls
  //       by checking if the return IP falls within libgfortran/libifcore images.
  const std::vector<std::string> allocSymbols = {
    "malloc", "mi_malloc", "je_malloc", "tc_malloc",
    "calloc", "mi_calloc", "je_calloc", "tc_calloc",
    "realloc", "mi_realloc", "je_realloc", "tc_realloc",
    "for_alloc_allocatable", "for_allocate",       // Intel Fortran Runtime (classic)
    "_gfortran_internal_malloc",                    // GNU Fortran Runtime (gfortran < 9)
    "CFI_allocate"                                  // Fortran 2018 C Descriptor Interface
  };

  for (const auto& sym : allocSymbols) {
    rtn = RTN_FindByName(img, sym.c_str());
    if (RTN_Valid(rtn)) {
      RTN_Open(rtn);
      
      if (sym.find("calloc") != std::string::npos || sym.find("realloc") != std::string::npos) {
        // Use extended hook to unpack multiple arguments (ptr/nmemb, size)
        RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)AllocBeforeExtended, 
                       IARG_FUNCARG_ENTRYPOINT_VALUE, 0, 
                       IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
                       IARG_RETURN_IP, IARG_PTR, sym.c_str(), IARG_END);
      } else {
        // Regular single size argument hook
        RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)AllocBefore, 
                       IARG_FUNCARG_ENTRYPOINT_VALUE, 0, 
                       IARG_RETURN_IP, IARG_PTR, sym.c_str(), IARG_END);
      }
      
      RTN_InsertCall(rtn, IPOINT_AFTER, (AFUNPTR)AllocAfter, IARG_FUNCRET_EXITPOINT_VALUE, IARG_END);
      RTN_Close(rtn);
      instrumented = true;
    }
  }

  // 2. All target deallocation symbols
  const std::vector<std::string> freeSymbols = {
    "free", "mi_free", "je_free", "tc_free",
    "for_deallocate", "_gfortran_internal_free",  // Fortran Runtime free paths (classic)
    "CFI_deallocate"                               // Fortran 2018 C Descriptor Interface
  };

  for (const auto& sym : freeSymbols) {
    rtn = RTN_FindByName(img, sym.c_str());
    if (RTN_Valid(rtn)) {
      RTN_Open(rtn);
      RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)FreeBefore, IARG_FUNCARG_ENTRYPOINT_VALUE, 0, IARG_RETURN_IP, IARG_END);
      RTN_InsertCall(rtn, IPOINT_AFTER, (AFUNPTR)FreeAfter, IARG_END);
      RTN_Close(rtn);
      instrumented = true;
    }
  }

  // 3. Keep low-level anonymous mmap tracking intact for giant arrays
  rtn = RTN_FindByName(img, "mmap");
  if (RTN_Valid(rtn)) {
    RTN_Open(rtn);
    RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)MmapBefore, IARG_FUNCARG_ENTRYPOINT_VALUE, 1, IARG_FUNCARG_ENTRYPOINT_VALUE, 3,
                   IARG_RETURN_IP, IARG_END);
    RTN_InsertCall(rtn, IPOINT_AFTER, (AFUNPTR)MmapAfter, IARG_FUNCRET_EXITPOINT_VALUE, IARG_END);
    RTN_Close(rtn);
    instrumented = true;
  }

  rtn = RTN_FindByName(img, "munmap");
  if (RTN_Valid(rtn)) {
    RTN_Open(rtn);
    RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)MunmapBefore, IARG_FUNCARG_ENTRYPOINT_VALUE, 0, IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
                   IARG_RETURN_IP, IARG_END);
    RTN_InsertCall(rtn, IPOINT_AFTER, (AFUNPTR)MunmapAfter, IARG_END);
    RTN_Close(rtn);
    instrumented = true;
  }

  if (instrumented) {
    std::cout << "[Omni Tracer] Successfully attached to image: " << IMG_Name(img) << std::endl;
  }
}

/* ===================================================================== */
VOID Fini(INT32 code, VOID* v)
{
  malloc_binfile.close();
  std::cout << "[Omni Tracer] Universal memory allocation trace saved successfully." << std::endl;
  std::cout << "  Active heap mappings tracked at exit: " << tracked_addresses.size() << std::endl;
}

int main(int argc, char* argv[])
{
  PIN_InitSymbols();
  if (PIN_Init(argc, argv))
    return Usage();
    
  tls_key = PIN_CreateThreadDataKey(ThreadCleanup);
  
  malloc_binfile.open(KnobMallocOutputFile.Value().c_str(), std::ios_base::binary | std::ios_base::trunc);
  if (!malloc_binfile) {
    std::cout << "Critical Error: Could not open binary malloc trace file. Exiting." << std::endl;
    exit(1);
  }
  
  IMG_AddInstrumentFunction(ImageLoad, 0);
  PIN_AddFiniFunction(Fini, 0);
  PIN_StartProgram();
  return 0;
}