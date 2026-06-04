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
 * Advanced Object Tracer v3 — alloc_depth + posix_memalign specialized hook.
 *
 * Design notes:
 *  - aligned_alloc(3), memalign(3), and valloc(3) in glibc are thin wrappers
 *    that internally call malloc/mmap.  Our standard malloc/mmap hooks
 *    already capture these with correct sizes and addresses.  We do NOT
 *    explicitly instrument these symbols to avoid tail-call deadlocks.
 *  - posix_memalign(3) returns int status (not void*), and writes the
 *    real aligned address to *memptr.  We hook it specially with
 *    PIN_SafeCopy to extract the true address.
 *  - alloc_depth protects against inner nesting (glibc's sysmalloc→mmap,
 *    realloc→malloc→free chains, etc.).
 */

#include <fstream>
#include <iostream>
#include <cstdlib>
#include <cstring>
#include <algorithm>
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
  unsigned long long arg2;     // parameter 2 (Alignment or extra)
  unsigned long long ret;      // return value (Allocated Addr)
  unsigned char type;          // 1=malloc, 2=free, 3=mmap, 4=munmap,
                               // 5=calloc, 6=realloc, 8=posix_memalign,
                               // 10=fortran_alloc, 16=realloc_inplace
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

struct ThreadState {
  // malloc/calloc/realloc/free/posix_memalign path
  ADDRINT pending_alloc_size = 0;
  ADDRINT pending_realloc_old_ptr = 0;
  ADDRINT pending_alloc_alignment = 0;
  ADDRINT pending_posix_memptr = 0;
  int     pending_alloc_type = 0;
  ADDRINT pending_alloc_ip = 0;
  INT32   alloc_depth = 0;

  // mmap/munmap path (independent, avoids overwriting malloc pending state)
  ADDRINT mmap_pending_size = 0;
  ADDRINT mmap_pending_length = 0;   // for munmap
  int     mmap_pending_type = 0;     // 3=mmap, 4=munmap
  ADDRINT mmap_pending_ip = 0;
  INT32   mmap_depth = 0;
};

static TLS_KEY tls_key;

// Cached address range of the main executable (set once at ImageLoad time).
// Used to detect stale alloc_depth from runtime initialization:
// if alloc_depth > 0 but the current IP is in the user binary,
// the depth was corrupted by leaked runtime init calls — force-reset.
static ADDRINT g_user_low = 0;
static ADDRINT g_user_high = 0;

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
  std::cerr << "Object Tracer v3 — records malloc/free/mmap/munmap/posix_memalign/Fortran" << std::endl
            << "Usage: pin -t object_tracer_gemini.so -m malloc.bin -- <program>" << std::endl;
  std::cerr << KNOB_BASE::StringKnobSummary() << std::endl;
  return -1;
}

void write_malloc_instr(unsigned long long ip, unsigned char type,
                        unsigned long long arg1, unsigned long long arg2,
                        unsigned long long ret)
{
  if (malloc_binfile.is_open()) {
    malloc_instr rec;
    rec.ip = ip; rec.type = type; rec.arg1 = arg1; rec.arg2 = arg2; rec.ret = ret;
    std::memset(rec.reserved, 0, sizeof(rec.reserved));
    typename decltype(malloc_binfile)::char_type buf[sizeof(malloc_instr)];
    std::memcpy(buf, &rec, sizeof(malloc_instr));
    malloc_binfile.write(buf, sizeof(malloc_instr));
  }
}

/* ===================================================================== */
// Callback implementations
/* ===================================================================== */

// --- MALLOC / allocator variants / Fortran ---
VOID AllocBefore(ADDRINT size, ADDRINT ip, const char* sym_name)
{
  ThreadState* ts = get_tls();
  // If depth is non-zero but the allocation originates from the user binary
  // (not libc/libgfortran), the depth was leaked by lost AFTER callbacks
  // during runtime initialization.  Force-reset to capture user allocations.
  if (ts->alloc_depth > 0) {
    if (g_user_low != 0 && ip >= g_user_low && ip < g_user_high) {
      ts->alloc_depth = 0; // force reset — stale depth from runtime init
    } else {
      ts->alloc_depth++;
      return;
    }
  }

  ts->alloc_depth = 1;
  ts->pending_alloc_size = size;
  ts->pending_alloc_ip = ip;
  ts->pending_alloc_alignment = 0;

  std::string name(sym_name);
  if (name.find("for_alloc") != std::string::npos ||
      name.find("gfortran")  != std::string::npos ||
      name.find("CFI_alloc") != std::string::npos) {
    ts->pending_alloc_type = 10;
  } else {
    ts->pending_alloc_type = 1;
  }
}

// --- CALLOC / REALLOC ---
VOID AllocBeforeExtended(ADDRINT arg1, ADDRINT arg2, ADDRINT ip, const char* sym_name)
{
  ThreadState* ts = get_tls();
  if (ts->alloc_depth > 0) { ts->alloc_depth++; return; }

  ts->alloc_depth = 1;
  ts->pending_alloc_ip = ip;
  ts->pending_alloc_alignment = 0;

  std::string name(sym_name);
  if (name.find("calloc") != std::string::npos) {
    ts->pending_alloc_size = arg1 * arg2;
    ts->pending_alloc_type = 5;
  } else if (name.find("realloc") != std::string::npos) {
    ts->pending_realloc_old_ptr = arg1;
    ts->pending_alloc_size = arg2;
    ts->pending_alloc_type = 6;
  }
}

// --- UNIFIED AFTER (malloc / calloc / realloc / Fortran / C++ new) ---
// Only the outermost caller (alloc_depth==1) writes a record.
// Inner nesting (alloc_depth>1, e.g. realloc→malloc→free) only decrements.
VOID AllocAfter(ADDRINT ret)
{
  ThreadState* ts = get_tls();
  if (ts->alloc_depth == 0) return;
  if (ts->alloc_depth > 1) { ts->alloc_depth--; return; }

  // alloc_depth == 1: outer layer — write record
  ts->alloc_depth = 0;

  if (ts->pending_alloc_type == 6) {
    unsigned char final_type = 6;
    if (ret == ts->pending_realloc_old_ptr && ret != 0) final_type = 16;
    write_malloc_instr(ts->pending_alloc_ip, final_type,
                       ts->pending_realloc_old_ptr, ts->pending_alloc_size, ret);
    if (ts->pending_realloc_old_ptr != 0) tracked_addresses.erase(ts->pending_realloc_old_ptr);
    if (ret != 0 && ret != (ADDRINT)-1) tracked_addresses.insert(ret);
  } else {
    if (ret != 0 && ret != (ADDRINT)-1) {
      write_malloc_instr(ts->pending_alloc_ip, (unsigned char)ts->pending_alloc_type,
                         ts->pending_alloc_size, 0, ret);
      tracked_addresses.insert(ret);
    }
  }

  ts->pending_alloc_type = 0;
  ts->pending_realloc_old_ptr = 0;
}

// --- POSIX_MEMALIGN (type=8) ---
VOID PosixMemalignBefore(ADDRINT memptr, ADDRINT alignment, ADDRINT size, ADDRINT ip)
{
  ThreadState* ts = get_tls();
  if (ts->alloc_depth > 0) { ts->alloc_depth++; return; }

  ts->alloc_depth = 1;
  ts->pending_alloc_size = size;
  ts->pending_alloc_alignment = alignment;
  ts->pending_posix_memptr = memptr;
  ts->pending_alloc_type = 8;
  ts->pending_alloc_ip = ip;
}

VOID PosixMemalignAfter(ADDRINT status)
{
  ThreadState* ts = get_tls();
  if (ts->alloc_depth == 0) return;
  if (ts->alloc_depth > 1) { ts->alloc_depth--; return; }

  ts->alloc_depth = 0;

  if (status == 0 && ts->pending_posix_memptr != 0) {
    ADDRINT real_addr = 0;
    PIN_SafeCopy(&real_addr, (void*)ts->pending_posix_memptr, sizeof(ADDRINT));
    if (real_addr != 0 && real_addr != (ADDRINT)-1) {
      write_malloc_instr(ts->pending_alloc_ip, 8,
                         ts->pending_alloc_size, ts->pending_alloc_alignment, real_addr);
      tracked_addresses.insert(real_addr);
    }
  }

  ts->pending_posix_memptr = 0;
}

// --- FREE ---
VOID FreeBefore(ADDRINT ptr, ADDRINT ip)
{
  ThreadState* ts = get_tls();
  if (ptr == 0) return;
  // Free can nest inside realloc (realloc→malloc→free). In that case
  // alloc_depth is already >0 and FreeBefore only bumps it.
  if (ts->alloc_depth > 0) { ts->alloc_depth++; return; }

  ts->alloc_depth = 1;
  write_malloc_instr((unsigned long long)ip, 2, (unsigned long long)ptr, 0, 0);

  auto it = tracked_addresses.find(ptr);
  if (it != tracked_addresses.end()) {
    tracked_addresses.erase(it);
  }
}

VOID FreeAfter()
{
  ThreadState* ts = get_tls();
  if (ts->alloc_depth == 0) return;
  if (ts->alloc_depth > 1) { ts->alloc_depth--; return; }
  ts->alloc_depth = 0;
}

// --- MMAP (independent depth + pending fields to avoid polluting alloc path) ---
VOID MmapBefore(ADDRINT length, ADDRINT flags, ADDRINT ip)
{
  ThreadState* ts = get_tls();
  if (ts->mmap_depth > 0) { ts->mmap_depth++; return; }

  // Ignore mmap calls originating outside the user binary (e.g., Pin's own JIT code cache)
  if (g_user_low != 0 && !(ip >= g_user_low && ip < g_user_high)) {
    return;
  }

  ts->mmap_depth = 1;

  if (!(flags & MAP_ANONYMOUS)) {
    ts->mmap_depth = 0;
    return;
  }
  ts->mmap_pending_size = length;
  ts->mmap_pending_type = 3;
  ts->mmap_pending_ip = ip;
}

VOID MmapAfter(ADDRINT ret)
{
  ThreadState* ts = get_tls();
  if (ts->mmap_depth == 0) return;
  if (ts->mmap_depth > 1) { ts->mmap_depth--; return; }

  ts->mmap_depth = 0;

  if (ts->mmap_pending_type != 3) return;

  if (ret != 0 && ret != (ADDRINT)-1) {
    write_malloc_instr(ts->mmap_pending_ip, 3, ts->mmap_pending_size, 0, ret);
    tracked_addresses.insert(ret);
  }
  ts->mmap_pending_size = 0;
  ts->mmap_pending_type = 0;
}

// --- MUNMAP (independent depth + pending fields) ---
VOID MunmapBefore(ADDRINT addr, ADDRINT length, ADDRINT ip)
{
  ThreadState* ts = get_tls();
  if (addr == 0 || addr == (ADDRINT)-1) return;
  if (ts->mmap_depth > 0) { ts->mmap_depth++; return; }

  // Ignore munmap calls originating outside the user binary
  if (g_user_low != 0 && !(ip >= g_user_low && ip < g_user_high)) {
    return;
  }

  ts->mmap_depth = 1;
  ts->mmap_pending_type = 4;
  ts->mmap_pending_ip = ip;

  write_malloc_instr((unsigned long long)ip, 4, (unsigned long long)addr, (unsigned long long)length, 0);

  auto it = tracked_addresses.find(addr);
  if (it != tracked_addresses.end()) {
    tracked_addresses.erase(it);
  }
}

VOID MunmapAfter()
{
  ThreadState* ts = get_tls();
  if (ts->mmap_depth == 0) return;
  if (ts->mmap_depth > 1) { ts->mmap_depth--; return; }
  ts->mmap_depth = 0;
  ts->mmap_pending_type = 0;
}

/* ===================================================================== */
// ImageLoad
/* ===================================================================== */
VOID ImageLoad(IMG img, VOID* v)
{
  if (!IMG_Valid(img)) return;

  // Cache the main executable's address range for stale-depth detection
  if (IMG_IsMainExecutable(img)) {
    g_user_low = IMG_LowAddress(img);
    g_user_high = IMG_HighAddress(img);
  }

  RTN rtn;

  // --- posix_memalign (type=8) ---
  rtn = RTN_FindByName(img, "posix_memalign");
  if (RTN_Valid(rtn)) {
    RTN_Open(rtn);
    RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)PosixMemalignBefore,
                   IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
                   IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
                   IARG_FUNCARG_ENTRYPOINT_VALUE, 2,
                   IARG_RETURN_IP, IARG_END);
    RTN_InsertCall(rtn, IPOINT_AFTER, (AFUNPTR)PosixMemalignAfter,
                   IARG_FUNCRET_EXITPOINT_VALUE, IARG_END);
    RTN_Close(rtn);
  }

  // --- Standard allocations ---
  const std::vector<std::string> allocSyms = {
    "malloc", "calloc", "realloc",
    "for_alloc_allocatable", "for_allocate", "CFI_allocate",
    "_gfortran_internal_malloc",
    "mi_malloc", "je_malloc", "tc_malloc",
    "mi_calloc", "je_calloc", "tc_calloc",
    "mi_realloc", "je_realloc", "tc_realloc",
    "_Znwm", "_Znam"
  };
  for (const auto& sym : allocSyms) {
    rtn = RTN_FindByName(img, sym.c_str());
    if (!RTN_Valid(rtn)) continue;
    RTN_Open(rtn);
    if (sym.find("calloc") != std::string::npos ||
        sym.find("realloc") != std::string::npos) {
      RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)AllocBeforeExtended,
                     IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
                     IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
                     IARG_RETURN_IP, IARG_PTR, sym.c_str(), IARG_END);
    } else {
      RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)AllocBefore,
                     IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
                     IARG_RETURN_IP, IARG_PTR, sym.c_str(), IARG_END);
    }
    RTN_InsertCall(rtn, IPOINT_AFTER, (AFUNPTR)AllocAfter,
                   IARG_FUNCRET_EXITPOINT_VALUE, IARG_END);
    RTN_Close(rtn);
  }

  // --- Free ---
  const std::vector<std::string> freeSyms = {
    "free", "mi_free", "je_free", "tc_free",
    "for_deallocate", "_gfortran_internal_free", "CFI_deallocate",
    "_ZdlPv", "_ZdaPv"
  };
  for (const auto& sym : freeSyms) {
    rtn = RTN_FindByName(img, sym.c_str());
    if (!RTN_Valid(rtn)) continue;
    RTN_Open(rtn);
    RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)FreeBefore,
                   IARG_FUNCARG_ENTRYPOINT_VALUE, 0, IARG_RETURN_IP, IARG_END);
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
                   IARG_RETURN_IP, IARG_END);
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
                   IARG_RETURN_IP, IARG_END);
    RTN_InsertCall(rtn, IPOINT_AFTER, (AFUNPTR)MunmapAfter, IARG_END);
    RTN_Close(rtn);
  }

  std::cout << "[Object Tracer v3] Instrumented: " << IMG_Name(img) << std::endl;
}

/* ===================================================================== */
VOID Fini(INT32 code, VOID* v)
{
  malloc_binfile.close();
  std::cout << "[Object Tracer v3] Trace saved. Active: " << tracked_addresses.size() << std::endl;
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