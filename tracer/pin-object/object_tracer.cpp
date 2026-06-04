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
 * Advanced Object Tracer v4 — stack-based pending, no depth counters.
 *
 * Design notes:
 *  - Each callback family uses a fixed-size ring stack: BEFORE pushes args,
 *    AFTER pops and writes.  No paired-depth tracking needed.
 *  - If Pin drops an AFTER callback (tail-call, JIT edge), at most one
 *    stack slot is leaked; subsequent pairs continue to work correctly.
 *  - free/munmap write immediately (they don't depend on AFTER).
 *  - aligned_alloc(3), memalign(3), and valloc(3) in glibc are thin wrappers
 *    that internally call malloc/mmap.  Our standard malloc/mmap hooks
 *    already capture these with correct sizes and addresses.  We do NOT
 *    explicitly instrument these symbols to avoid tail-call deadlocks.
 *  - posix_memalign(3) returns int status (not void*), and writes the
 *    real aligned address to *memptr.  We hook it specially with
 *    PIN_SafeCopy to extract the true address.
 */

#include <fstream>
#include <iostream>
#include <cstdlib>
#include <cstring>
#include <unordered_set>
#include <vector>

#include "pin.H"

/* ===================================================================== */
// Binary malloc trace record (32 bytes)
/* ===================================================================== */
struct malloc_instr {
  unsigned long long arg1;     // parameter 1 (Size or Ptr)
  unsigned long long arg2;     // parameter 2 (Alignment or extra)
  unsigned long long ret;      // return value (Allocated Addr)
  unsigned char type;          // 1=malloc, 2=free, 3=mmap, 4=munmap,
                               // 5=calloc, 6=realloc, 8=posix_memalign,
                               // 10=fortran_alloc, 16=realloc_inplace
  unsigned char reserved[7];
};
static_assert(sizeof(malloc_instr) == 32, "malloc_instr must be exactly 32 bytes");

#ifndef MAP_ANONYMOUS
#define MAP_ANONYMOUS 0x20
#endif

/* ===================================================================== */
// Global state & Thread-local status
/* ===================================================================== */
std::ofstream malloc_binfile;
std::unordered_set<ADDRINT> tracked_addresses;

// Single pending slot held between BEFORE and AFTER.
struct PendingAlloc {
  ADDRINT size       = 0;   // arg1 (size or old_ptr for realloc)
  ADDRINT arg2       = 0;   // arg2 (alignment or new_size for realloc)
  int     type       = 0;   // allocation type code
  ADDRINT posix_memptr = 0; // memptr for posix_memalign
};

// Fixed-size stack so that nested BEFORE/AFTER pairs don't lose outer frames.
constexpr int ALLOC_STACK_SIZE = 16;
constexpr int MMAP_STACK_SIZE  = 8;

struct ThreadState {
  PendingAlloc alloc_stack[ALLOC_STACK_SIZE];
  int          alloc_sp = 0;       // next write index; 0 = empty

  PendingAlloc mmap_stack[MMAP_STACK_SIZE];
  int          mmap_sp = 0;
};

static TLS_KEY tls_key;

static void ThreadCleanup(void* p) { delete static_cast<ThreadState*>(p); }

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
  std::cerr << "Object Tracer v4 — records malloc/free/mmap/munmap/posix_memalign/Fortran" << std::endl
            << "Usage: pin -t object_tracer_gemini.so -m malloc.bin -- <program>" << std::endl;
  std::cerr << KNOB_BASE::StringKnobSummary() << std::endl;
  return -1;
}

void write_malloc_instr(unsigned char type,
                        unsigned long long arg1, unsigned long long arg2,
                        unsigned long long ret)
{
  if (malloc_binfile.is_open()) {
    malloc_instr rec;
    rec.type = type; rec.arg1 = arg1; rec.arg2 = arg2; rec.ret = ret;
    std::memset(rec.reserved, 0, sizeof(rec.reserved));
    typename decltype(malloc_binfile)::char_type buf[sizeof(malloc_instr)];
    std::memcpy(buf, &rec, sizeof(malloc_instr));
    malloc_binfile.write(buf, sizeof(malloc_instr));
  }
}

/* ===================================================================== */
// Callback implementations — stack-based, no depth counters
/* ===================================================================== */

// --- MALLOC / C++ new (type=1) ---
VOID AllocBefore(ADDRINT size)
{
  ThreadState* ts = get_tls();
  auto& slot = ts->alloc_stack[ts->alloc_sp % ALLOC_STACK_SIZE];
  slot.size       = size;
  slot.arg2       = 0;
  slot.type       = 1;
  slot.posix_memptr = 0;
  ts->alloc_sp++;
}

// --- CALLOC (type=5) ---
VOID CallocBefore(ADDRINT nmemb, ADDRINT elem_size)
{
  ThreadState* ts = get_tls();
  auto& slot = ts->alloc_stack[ts->alloc_sp % ALLOC_STACK_SIZE];
  slot.size       = nmemb * elem_size;
  slot.arg2       = 0;
  slot.type       = 5;
  slot.posix_memptr = 0;
  ts->alloc_sp++;
}

// --- REALLOC (type=6 or 16) ---
VOID ReallocBefore(ADDRINT old_ptr, ADDRINT new_size)
{
  ThreadState* ts = get_tls();
  auto& slot = ts->alloc_stack[ts->alloc_sp % ALLOC_STACK_SIZE];
  slot.size       = old_ptr;    // arg1 = old_ptr for realloc
  slot.arg2       = new_size;   // arg2 = new_size for realloc
  slot.type       = 6;
  slot.posix_memptr = 0;
  ts->alloc_sp++;
}

// --- FORTRAN alloc (type=10) ---
VOID FortranAllocBefore(ADDRINT size)
{
  ThreadState* ts = get_tls();
  auto& slot = ts->alloc_stack[ts->alloc_sp % ALLOC_STACK_SIZE];
  slot.size       = size;
  slot.arg2       = 0;
  slot.type       = 10;
  slot.posix_memptr = 0;
  ts->alloc_sp++;
}

// --- UNIFIED AFTER (malloc / calloc / realloc / Fortran / C++ new) ---
// Pops the top stack frame and writes a record.  If sp==0 (no BEFORE matched),
// it's a no-op — harmless.
VOID AllocAfter(ADDRINT ret)
{
  ThreadState* ts = get_tls();
  if (ts->alloc_sp == 0) return;

  ts->alloc_sp--;
  const auto& slot = ts->alloc_stack[ts->alloc_sp % ALLOC_STACK_SIZE];

  if (slot.type == 6) {
    // realloc: arg1=old_ptr, arg2=new_size
    ADDRINT old_ptr  = slot.size;
    ADDRINT new_size = slot.arg2;
    unsigned char final_type = 6;
    if (ret == old_ptr && ret != 0) final_type = 16;
    write_malloc_instr(final_type, old_ptr, new_size, ret);
    if (old_ptr != 0) tracked_addresses.erase(old_ptr);
    if (ret != 0 && ret != (ADDRINT)-1) tracked_addresses.insert(ret);
  } else {
    if (ret != 0 && ret != (ADDRINT)-1) {
      write_malloc_instr((unsigned char)slot.type, slot.size, 0, ret);
      tracked_addresses.insert(ret);
    }
  }
}

// --- POSIX_MEMALIGN (type=8) ---
VOID PosixMemalignBefore(ADDRINT memptr, ADDRINT alignment, ADDRINT size)
{
  ThreadState* ts = get_tls();
  auto& slot = ts->alloc_stack[ts->alloc_sp % ALLOC_STACK_SIZE];
  slot.size       = size;
  slot.arg2       = alignment;
  slot.type       = 8;
  slot.posix_memptr = memptr;
  ts->alloc_sp++;
}

VOID PosixMemalignAfter(ADDRINT status)
{
  ThreadState* ts = get_tls();
  if (ts->alloc_sp == 0) return;

  ts->alloc_sp--;
  const auto& slot = ts->alloc_stack[ts->alloc_sp % ALLOC_STACK_SIZE];

  if (status == 0 && slot.posix_memptr != 0) {
    ADDRINT real_addr = 0;
    PIN_SafeCopy(&real_addr, (void*)slot.posix_memptr, sizeof(ADDRINT));
    if (real_addr != 0 && real_addr != (ADDRINT)-1) {
      write_malloc_instr(8, slot.size, slot.arg2, real_addr);
      tracked_addresses.insert(real_addr);
    }
  }
}

// --- FREE (type=2) — unconditional write, no stack needed ---
VOID FreeBefore(ADDRINT ptr)
{
  if (ptr == 0) return;
  write_malloc_instr(2, (unsigned long long)ptr, 0, 0);
  auto it = tracked_addresses.find(ptr);
  if (it != tracked_addresses.end()) {
    tracked_addresses.erase(it);
  }
}

// FreeAfter is a no-op in the stack model.
VOID FreeAfter() { /* nothing to do */ }

// --- MMAP (independent stack) ---
VOID MmapBefore(ADDRINT length, ADDRINT flags)
{
  if (!(flags & MAP_ANONYMOUS)) return;

  ThreadState* ts = get_tls();
  auto& slot = ts->mmap_stack[ts->mmap_sp % MMAP_STACK_SIZE];
  slot.size       = length;
  slot.arg2       = 0;
  slot.type       = 3;
  slot.posix_memptr = 0;
  ts->mmap_sp++;
}

VOID MmapAfter(ADDRINT ret)
{
  ThreadState* ts = get_tls();
  if (ts->mmap_sp == 0) return;

  ts->mmap_sp--;
  const auto& slot = ts->mmap_stack[ts->mmap_sp % MMAP_STACK_SIZE];

  if (ret != 0 && ret != (ADDRINT)-1) {
    write_malloc_instr(3, slot.size, 0, ret);
    tracked_addresses.insert(ret);
  }
}

// --- MUNMAP (type=4) — unconditional write ---
VOID MunmapBefore(ADDRINT addr, ADDRINT length)
{
  if (addr == 0 || addr == (ADDRINT)-1) return;
  write_malloc_instr(4, (unsigned long long)addr, (unsigned long long)length, 0);
  auto it = tracked_addresses.find(addr);
  if (it != tracked_addresses.end()) {
    tracked_addresses.erase(it);
  }
}

// MunmapAfter is a no-op.
VOID MunmapAfter() { /* nothing to do */ }

/* ===================================================================== */
// ImageLoad
/* ===================================================================== */
VOID ImageLoad(IMG img, VOID* v)
{
  if (!IMG_Valid(img)) return;

  RTN rtn;

  // --- posix_memalign (type=8) ---
  rtn = RTN_FindByName(img, "posix_memalign");
  if (RTN_Valid(rtn)) {
    RTN_Open(rtn);
    RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)PosixMemalignBefore,
                   IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
                   IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
                   IARG_FUNCARG_ENTRYPOINT_VALUE, 2,
                   IARG_END);
    RTN_InsertCall(rtn, IPOINT_AFTER, (AFUNPTR)PosixMemalignAfter,
                   IARG_FUNCRET_EXITPOINT_VALUE, IARG_END);
    RTN_Close(rtn);
  }

  // --- malloc-like (type=1): malloc, __libc_malloc, C++ new, jemalloc ---
  const std::vector<std::string> mallocSyms = {
    "malloc", "__libc_malloc",
    "mi_malloc", "je_malloc", "tc_malloc",
    "_Znwm", "_Znam"
  };
  for (const auto& sym : mallocSyms) {
    rtn = RTN_FindByName(img, sym.c_str());
    if (!RTN_Valid(rtn)) continue;
    RTN_Open(rtn);
    RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)AllocBefore,
                   IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
                   IARG_END);
    RTN_InsertCall(rtn, IPOINT_AFTER, (AFUNPTR)AllocAfter,
                   IARG_FUNCRET_EXITPOINT_VALUE, IARG_END);
    RTN_Close(rtn);
  }

  // --- calloc (type=5) ---
  const std::vector<std::string> callocSyms = {
    "calloc", "__libc_calloc",
    "mi_calloc", "je_calloc", "tc_calloc"
  };
  for (const auto& sym : callocSyms) {
    rtn = RTN_FindByName(img, sym.c_str());
    if (!RTN_Valid(rtn)) continue;
    RTN_Open(rtn);
    RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)CallocBefore,
                   IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
                   IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
                   IARG_END);
    RTN_InsertCall(rtn, IPOINT_AFTER, (AFUNPTR)AllocAfter,
                   IARG_FUNCRET_EXITPOINT_VALUE, IARG_END);
    RTN_Close(rtn);
  }

  // --- realloc (type=6) ---
  const std::vector<std::string> reallocSyms = {
    "realloc", "__libc_realloc",
    "mi_realloc", "je_realloc", "tc_realloc"
  };
  for (const auto& sym : reallocSyms) {
    rtn = RTN_FindByName(img, sym.c_str());
    if (!RTN_Valid(rtn)) continue;
    RTN_Open(rtn);
    RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)ReallocBefore,
                   IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
                   IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
                   IARG_END);
    RTN_InsertCall(rtn, IPOINT_AFTER, (AFUNPTR)AllocAfter,
                   IARG_FUNCRET_EXITPOINT_VALUE, IARG_END);
    RTN_Close(rtn);
  }

  // --- Fortran alloc (type=10) ---
  const std::vector<std::string> fortranAllocSyms = {
    "for_alloc_allocatable", "for_allocate", "CFI_allocate",
    "_gfortran_internal_malloc",
    "_gfortran_allocate", "_gfortran_allocate_array"
  };
  for (const auto& sym : fortranAllocSyms) {
    rtn = RTN_FindByName(img, sym.c_str());
    if (!RTN_Valid(rtn)) continue;
    RTN_Open(rtn);
    RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)FortranAllocBefore,
                   IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
                   IARG_END);
    RTN_InsertCall(rtn, IPOINT_AFTER, (AFUNPTR)AllocAfter,
                   IARG_FUNCRET_EXITPOINT_VALUE, IARG_END);
    RTN_Close(rtn);
  }

  // --- Free ---
  const std::vector<std::string> freeSyms = {
    "free", "__libc_free",
    "mi_free", "je_free", "tc_free",
    "for_deallocate", "_gfortran_internal_free", "CFI_deallocate",
    "_gfortran_deallocate",
    "_ZdlPv", "_ZdaPv"
  };
  for (const auto& sym : freeSyms) {
    rtn = RTN_FindByName(img, sym.c_str());
    if (!RTN_Valid(rtn)) continue;
    RTN_Open(rtn);
    RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)FreeBefore,
                   IARG_FUNCARG_ENTRYPOINT_VALUE, 0, IARG_END);
    RTN_InsertCall(rtn, IPOINT_AFTER, (AFUNPTR)FreeAfter, IARG_END);
    RTN_Close(rtn);
  }

  // --- mmap ---
  rtn = RTN_FindByName(img, "mmap");
  if (RTN_Valid(rtn)) {
    RTN_Open(rtn);
    RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)MmapBefore,
                   IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
                   IARG_FUNCARG_ENTRYPOINT_VALUE, 3,
                   IARG_END);
    RTN_InsertCall(rtn, IPOINT_AFTER, (AFUNPTR)MmapAfter,
                   IARG_FUNCRET_EXITPOINT_VALUE, IARG_END);
    RTN_Close(rtn);
  }

  // --- munmap ---
  rtn = RTN_FindByName(img, "munmap");
  if (RTN_Valid(rtn)) {
    RTN_Open(rtn);
    RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)MunmapBefore,
                   IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
                   IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
                   IARG_END);
    RTN_InsertCall(rtn, IPOINT_AFTER, (AFUNPTR)MunmapAfter, IARG_END);
    RTN_Close(rtn);
  }

  std::cout << "[Object Tracer v4] Instrumented: " << IMG_Name(img) << std::endl;
}

/* ===================================================================== */
VOID Fini(INT32 code, VOID* v)
{
  malloc_binfile.close();
  std::cout << "[Object Tracer v4] Trace saved. Active: " << tracked_addresses.size() << std::endl;
}

int main(int argc, char* argv[])
{
  PIN_InitSymbols();
  if (PIN_Init(argc, argv))
    return Usage();

  tls_key = PIN_CreateThreadDataKey(ThreadCleanup);

  malloc_binfile.open(KnobMallocOutputFile.Value().c_str(), std::ios_base::binary | std::ios_base::trunc);
  if (!malloc_binfile) {
    std::cout << "Error: Cannot open output file." << std::endl;
    exit(1);
  }

  IMG_AddInstrumentFunction(ImageLoad, 0);
  PIN_AddFiniFunction(Fini, 0);
  PIN_StartProgram();
  return 0;
}