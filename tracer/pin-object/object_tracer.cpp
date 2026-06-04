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
 * Advanced Object Tracer v5 — depth counter with saturation, thread-safe.
 *
 * Design notes:
 *  - Only the outermost caller (depth==0→1) records.  Inner nesting
 *    (depth 2..MAX_DEPTH) is silently counted and filtered in the AFTER
 *    callback.  Beyond MAX_DEPTH, the counter saturates to prevent
 *    permanent lock-up from lost AFTER callbacks.
 *  - PIN_LOCK protects tracked_addresses and malloc_binfile writes
 *    from OpenMP races.
 *  - free/munmap are only recorded when the pointer exists in
 *    tracked_addresses, suppressing glibc-internal free noise.
 *  - aligned_alloc(3), memalign(3), and valloc(3) are thin wrappers
 *    that internally call malloc/mmap — NOT instrumented.
 *  - posix_memalign(3) returns int status and writes the real address
 *    to *memptr; hooked specially with PIN_SafeCopy.
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
// Global state
/* ===================================================================== */
std::ofstream malloc_binfile;
std::unordered_set<ADDRINT> tracked_addresses;
static PIN_LOCK malloc_lock;

// Maximum nesting depth before saturation.
// After saturating, further nested BEFORE callbacks are silently ignored
// and the matching AFTER callbacks decrement the overflow counter.
// This prevents permanent lock-up when AFTER callbacks are lost.
constexpr int MAX_DEPTH = 16;

// Staged parameters held between outermost BEFORE and AFTER.
struct PendingAlloc {
  ADDRINT size          = 0;
  ADDRINT arg2          = 0;   // alignment (posix_memalign) or new_size (realloc)
  int     type          = 0;
  ADDRINT posix_memptr  = 0;
};

struct ThreadState {
  PendingAlloc pending;
  int alloc_depth         = 0;  // 0 = idle, 1 = outermost, 2..MAX_DEPTH = nested
  int alloc_overflow      = 0;  // counts lost AFTER frames beyond MAX_DEPTH
  int alloc_stuck_counter = 0;  // auto-reset when depth stays non-zero too long

  // mmap has its own independent depth tracking
  ADDRINT mmap_pending_size  = 0;
  int     mmap_depth         = 0;
  int     mmap_overflow      = 0;
  int     mmap_stuck_counter = 0;
};

constexpr int MAX_STUCK = 2;  // auto-reset threshold: force-reset after 2 stuck BEFORE calls

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
  std::cerr << "Object Tracer v5 — depth counter with saturation, thread-safe" << std::endl
            << "Usage: pin -t object_tracer.so -m malloc.bin -- <program>" << std::endl;
  std::cerr << KNOB_BASE::StringKnobSummary() << std::endl;
  return -1;
}

void write_malloc_instr_locked(unsigned char type,
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
// Callback implementations — depth counter with saturation, thread-safe
/* ===================================================================== */

// --- Helper: outermost BEFORE for depth-protected alloc family ---
static bool depth_outermost_before(ThreadState* ts, int alloc_type,
                                   ADDRINT size, ADDRINT arg2 = 0)
{
  if (ts->alloc_depth > 0) {
    if (ts->alloc_depth < MAX_DEPTH) {
      ts->alloc_depth++;      // nested — count but don't stage
    } else {
      ts->alloc_overflow++;   // push overflow to keep AFTER pairing
    }
    return false;             // not outermost
  }
  // Outermost: stage parameters
  ts->alloc_depth = 1;
  ts->pending = PendingAlloc{size, arg2, alloc_type, 0};
  return true;
}

// --- Stuck-depth auto-reset ---
static void try_auto_reset_depth(ThreadState* ts)
{
  if (ts->alloc_depth == 0) {
    ts->alloc_stuck_counter = 0;
    return;
  }
  ts->alloc_stuck_counter++;
  if (ts->alloc_stuck_counter >= MAX_STUCK) {
    // Depth permanently stuck (glibc init loss) — force reset
    ts->alloc_depth = 0;
    ts->alloc_overflow = 0;
    ts->alloc_stuck_counter = 0;
  }
}

// --- MALLOC / C++ new (type=1) ---
VOID AllocBefore(ADDRINT size)
{
  ThreadState* ts = get_tls();
  try_auto_reset_depth(ts);
  depth_outermost_before(ts, 1, size);
}

// --- CALLOC (type=5) ---
VOID CallocBefore(ADDRINT nmemb, ADDRINT elem_size)
{
  ThreadState* ts = get_tls();
  try_auto_reset_depth(ts);
  depth_outermost_before(ts, 5, nmemb * elem_size);
}

// --- REALLOC (type=6 or 16) ---
VOID ReallocBefore(ADDRINT old_ptr, ADDRINT new_size)
{
  ThreadState* ts = get_tls();
  try_auto_reset_depth(ts);
  if (ts->alloc_depth > 0) {
    if (ts->alloc_depth < MAX_DEPTH) ts->alloc_depth++;
    else ts->alloc_overflow++;
    return;
  }
  ts->alloc_depth = 1;
  ts->pending = PendingAlloc{old_ptr, new_size, 6, 0};
}

// --- FORTRAN alloc (type=10) ---
VOID FortranAllocBefore(ADDRINT size)
{
  ThreadState* ts = get_tls();
  try_auto_reset_depth(ts);
  depth_outermost_before(ts, 10, size);
}

// --- UNIFIED AFTER (all alloc families) ---
VOID AllocAfter(ADDRINT ret)
{
  ThreadState* ts = get_tls();
  if (ts->alloc_overflow > 0) { ts->alloc_overflow--; return; }
  if (ts->alloc_depth == 0) return;
  if (ts->alloc_depth > 1) { ts->alloc_depth--; return; }

  // depth == 1: outermost — write record
  ts->alloc_depth = 0;

  PIN_GetLock(&malloc_lock, PIN_ThreadId());

  if (ts->pending.type == 6) {
    ADDRINT old_ptr  = ts->pending.size;   // staged in size slot
    ADDRINT new_size = ts->pending.arg2;
    unsigned char final_type = 6;
    if (ret == old_ptr && ret != 0) final_type = 16;
    write_malloc_instr_locked(final_type, old_ptr, new_size, ret);
    if (old_ptr != 0) tracked_addresses.erase(old_ptr);
    if (ret != 0 && ret != (ADDRINT)-1) tracked_addresses.insert(ret);
  } else {
    if (ret != 0 && ret != (ADDRINT)-1) {
      write_malloc_instr_locked((unsigned char)ts->pending.type,
                                ts->pending.size, ts->pending.arg2, ret);
      tracked_addresses.insert(ret);
    }
  }

  PIN_ReleaseLock(&malloc_lock);
}

// --- POSIX_MEMALIGN (type=8) — uses depth counter, but BEFORE always stages ---
VOID PosixMemalignBefore(ADDRINT memptr, ADDRINT alignment, ADDRINT size)
{
  ThreadState* ts = get_tls();
  if (ts->alloc_depth > 0) {
    if (ts->alloc_depth < MAX_DEPTH) ts->alloc_depth++;
    else ts->alloc_overflow++;
    return;
  }
  ts->alloc_depth = 1;
  ts->pending = PendingAlloc{size, alignment, 8, memptr};
}

VOID PosixMemalignAfter(ADDRINT status)
{
  ThreadState* ts = get_tls();
  if (ts->alloc_overflow > 0) { ts->alloc_overflow--; return; }
  if (ts->alloc_depth == 0) return;
  if (ts->alloc_depth > 1) { ts->alloc_depth--; return; }

  ts->alloc_depth = 0;

  if (status == 0 && ts->pending.posix_memptr != 0) {
    ADDRINT real_addr = 0;
    PIN_SafeCopy(&real_addr, (void*)ts->pending.posix_memptr, sizeof(ADDRINT));
    if (real_addr != 0 && real_addr != (ADDRINT)-1) {
      PIN_GetLock(&malloc_lock, PIN_ThreadId());
      write_malloc_instr_locked(8, ts->pending.size, ts->pending.arg2, real_addr);
      tracked_addresses.insert(real_addr);
      PIN_ReleaseLock(&malloc_lock);
    }
  }
}

// --- FREE (type=2) — only write if tracked (suppresses glibc-internal free) ---
VOID FreeBefore(ADDRINT ptr)
{
  if (ptr == 0) return;

  PIN_GetLock(&malloc_lock, PIN_ThreadId());
  auto it = tracked_addresses.find(ptr);
  if (it != tracked_addresses.end()) {
    write_malloc_instr_locked(2, (unsigned long long)ptr, 0, 0);
    tracked_addresses.erase(it);
  }
  PIN_ReleaseLock(&malloc_lock);
}

VOID FreeAfter() { /* no-op */ }

// --- MMAP (independent depth + saturation) ---
VOID MmapBefore(ADDRINT length, ADDRINT flags)
{
  if (!(flags & MAP_ANONYMOUS)) return;

  ThreadState* ts = get_tls();
  if (ts->mmap_depth > 0) {
    if (ts->mmap_depth < MAX_DEPTH) ts->mmap_depth++;
    else ts->mmap_overflow++;
    return;
  }
  ts->mmap_depth = 1;
  ts->mmap_pending_size = length;
}

VOID MmapAfter(ADDRINT ret)
{
  ThreadState* ts = get_tls();
  if (ts->mmap_overflow > 0) { ts->mmap_overflow--; return; }
  if (ts->mmap_depth == 0) return;
  if (ts->mmap_depth > 1) { ts->mmap_depth--; return; }

  ts->mmap_depth = 0;

  if (ret != 0 && ret != (ADDRINT)-1) {
    PIN_GetLock(&malloc_lock, PIN_ThreadId());
    write_malloc_instr_locked(3, ts->mmap_pending_size, 0, ret);
    tracked_addresses.insert(ret);
    PIN_ReleaseLock(&malloc_lock);
  }
}

// --- MUNMAP (type=4) — only write if tracked ---
VOID MunmapBefore(ADDRINT addr, ADDRINT length)
{
  if (addr == 0 || addr == (ADDRINT)-1) return;

  PIN_GetLock(&malloc_lock, PIN_ThreadId());
  auto it = tracked_addresses.find(addr);
  if (it != tracked_addresses.end()) {
    write_malloc_instr_locked(4, (unsigned long long)addr, (unsigned long long)length, 0);
    tracked_addresses.erase(it);
  }
  PIN_ReleaseLock(&malloc_lock);
}

VOID MunmapAfter() { /* no-op */ }

// Forward declaration — used in ImageLoad's main() hook
VOID ResetDepthOnMain();

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

  // --- malloc-like (type=1) ---
  const std::vector<std::string> mallocSyms = {
    "malloc",
    "mi_malloc", "je_malloc", "tc_malloc",
    "_Znwm", "_Znam"
  };
  for (const auto& sym : mallocSyms) {
    rtn = RTN_FindByName(img, sym.c_str());
    if (!RTN_Valid(rtn)) continue;
    RTN_Open(rtn);
    RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)AllocBefore,
                   IARG_FUNCARG_ENTRYPOINT_VALUE, 0, IARG_END);
    RTN_InsertCall(rtn, IPOINT_AFTER, (AFUNPTR)AllocAfter,
                   IARG_FUNCRET_EXITPOINT_VALUE, IARG_END);
    RTN_Close(rtn);
  }

  // --- calloc (type=5) ---
  const std::vector<std::string> callocSyms = {
    "calloc",
    "mi_calloc", "je_calloc", "tc_calloc"
  };
  for (const auto& sym : callocSyms) {
    rtn = RTN_FindByName(img, sym.c_str());
    if (!RTN_Valid(rtn)) continue;
    RTN_Open(rtn);
    RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)CallocBefore,
                   IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
                   IARG_FUNCARG_ENTRYPOINT_VALUE, 1, IARG_END);
    RTN_InsertCall(rtn, IPOINT_AFTER, (AFUNPTR)AllocAfter,
                   IARG_FUNCRET_EXITPOINT_VALUE, IARG_END);
    RTN_Close(rtn);
  }

  // --- realloc (type=6) ---
  const std::vector<std::string> reallocSyms = {
    "realloc",
    "mi_realloc", "je_realloc", "tc_realloc"
  };
  for (const auto& sym : reallocSyms) {
    rtn = RTN_FindByName(img, sym.c_str());
    if (!RTN_Valid(rtn)) continue;
    RTN_Open(rtn);
    RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)ReallocBefore,
                   IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
                   IARG_FUNCARG_ENTRYPOINT_VALUE, 1, IARG_END);
    RTN_InsertCall(rtn, IPOINT_AFTER, (AFUNPTR)AllocAfter,
                   IARG_FUNCRET_EXITPOINT_VALUE, IARG_END);
    RTN_Close(rtn);
  }

  // --- Fortran alloc (type=10) ---
  const std::vector<std::string> fortranAllocSyms = {
    "for_alloc_allocatable", "for_allocate", "CFI_allocate",
    "_gfortran_internal_malloc",
    "_gfortran_allocate", "_gfortran_allocate_array",
    "f90_alloc", "f90_alloc04",
    "_f90_malloc", "pgf90_alloc"
  };
  for (const auto& sym : fortranAllocSyms) {
    rtn = RTN_FindByName(img, sym.c_str());
    if (!RTN_Valid(rtn)) continue;
    RTN_Open(rtn);
    RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)FortranAllocBefore,
                   IARG_FUNCARG_ENTRYPOINT_VALUE, 0, IARG_END);
    RTN_InsertCall(rtn, IPOINT_AFTER, (AFUNPTR)AllocAfter,
                   IARG_FUNCRET_EXITPOINT_VALUE, IARG_END);
    RTN_Close(rtn);
  }

  // --- Free ---
  const std::vector<std::string> freeSyms = {
    "free",
    "mi_free", "je_free", "tc_free",
    "for_deallocate", "_gfortran_internal_free", "CFI_deallocate",
    "_gfortran_deallocate",
    "f90_free", "_f90_free",
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

  // --- Reset depth at entry points (glibc init may have leaked depth) ---
  for (const char* entry : {"main", "MAIN__", "main_"}) {
    rtn = RTN_FindByName(img, entry);
    if (RTN_Valid(rtn)) {
      RTN_Open(rtn);
      RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)ResetDepthOnMain, IARG_END);
      RTN_Close(rtn);
    }
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

  std::cout << "[Object Tracer v5] Instrumented: " << IMG_Name(img) << std::endl;
}

// --- Reset depth counters at program entry (after glibc init) ---
VOID ResetDepthOnMain()
{
  ThreadState* ts = get_tls();
  ts->alloc_depth = 0;
  ts->alloc_overflow = 0;
  ts->mmap_depth = 0;
  ts->mmap_overflow = 0;
}

/* ===================================================================== */
VOID Fini(INT32 code, VOID* v)
{
  malloc_binfile.close();
  std::cout << "[Object Tracer v5] Trace saved. Active: " << tracked_addresses.size() << std::endl;
}

int main(int argc, char* argv[])
{
  PIN_InitSymbols();
  if (PIN_Init(argc, argv))
    return Usage();

  PIN_InitLock(&malloc_lock);
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