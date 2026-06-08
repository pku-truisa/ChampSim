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
 * Advanced Object Tracer v5 — 23 fine-grained type codes, one per hooked symbol.
 * Fortran symbols (24-39) removed: gfortran compiles ALLOCATE directly to malloc.
 */

#include <fstream>
#include <iostream>
#include <cstdlib>
#include <cstring>
#include <unordered_set>
#include <unordered_map>
#include <vector>

#include "pin.H"

/* ===================================================================== */
// Fine-grained malloc type codes — one per hooked symbol (23 total)
/* ===================================================================== */
enum MallocType : unsigned char {
  TYPE_MALLOC                      = 1,
  TYPE_MI_MALLOC                   = 2,
  TYPE_JE_MALLOC                   = 3,
  TYPE_TC_MALLOC                   = 4,
  TYPE_ZNWM                        = 5,
  TYPE_ZNAM                        = 6,

  TYPE_CALLOC                      = 7,
  TYPE_MI_CALLOC                   = 8,
  TYPE_JE_CALLOC                   = 9,
  TYPE_TC_CALLOC                   = 10,

  TYPE_REALLOC                     = 11,
  TYPE_MI_REALLOC                  = 12,
  TYPE_JE_REALLOC                  = 13,
  TYPE_TC_REALLOC                  = 14,

  TYPE_POSIX_MEMALIGN              = 15,

  TYPE_MMAP                        = 16,
  TYPE_MUNMAP                      = 17,

  TYPE_FREE                        = 18,
  TYPE_MI_FREE                     = 19,
  TYPE_JE_FREE                     = 20,
  TYPE_TC_FREE                     = 21,
  TYPE_ZDLPV                       = 22,
  TYPE_ZDAPV                       = 23,
};

/* ===================================================================== */
// Binary malloc trace record (32 bytes)
/* ===================================================================== */
struct malloc_instr {
  unsigned long long arg1;
  unsigned long long arg2;
  unsigned long long ret;
  unsigned char type;
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

static std::unordered_map<unsigned char, unsigned long long> type_counts;
static PIN_LOCK stats_lock;

constexpr int MAX_DEPTH = 16;

struct PendingAlloc {
  ADDRINT size = 0;
  ADDRINT arg2 = 0;
  int type = 0;
  ADDRINT posix_memptr = 0;
};

struct ThreadState {
  PendingAlloc pending;
  int alloc_depth = 0;
  int alloc_overflow = 0;
  int alloc_stuck_counter = 0;
  ADDRINT mmap_pending_size = 0;
  int mmap_depth = 0;
  int mmap_overflow = 0;
  int mmap_stuck_counter = 0;
};

constexpr int MAX_STUCK = 2;
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
  std::cerr << "Object Tracer v5 — 23 fine-grained type codes (one per symbol)" << std::endl
            << "Usage: pin -t object_tracer.so -m malloc.bin -- <program>" << std::endl;
  std::cerr << KNOB_BASE::StringKnobSummary() << std::endl;
  return -1;
}

static const char* type_name(unsigned char t)
{
  switch (t) {
    case TYPE_MALLOC:         return "malloc";
    case TYPE_MI_MALLOC:      return "mi_malloc";
    case TYPE_JE_MALLOC:      return "je_malloc";
    case TYPE_TC_MALLOC:      return "tc_malloc";
    case TYPE_ZNWM:           return "_Znwm";
    case TYPE_ZNAM:           return "_Znam";
    case TYPE_CALLOC:         return "calloc";
    case TYPE_MI_CALLOC:      return "mi_calloc";
    case TYPE_JE_CALLOC:      return "je_calloc";
    case TYPE_TC_CALLOC:      return "tc_calloc";
    case TYPE_REALLOC:        return "realloc";
    case TYPE_MI_REALLOC:     return "mi_realloc";
    case TYPE_JE_REALLOC:     return "je_realloc";
    case TYPE_TC_REALLOC:     return "tc_realloc";
    case TYPE_POSIX_MEMALIGN: return "posix_memalign";
    case TYPE_MMAP:           return "mmap";
    case TYPE_MUNMAP:         return "munmap";
    case TYPE_FREE:           return "free";
    case TYPE_MI_FREE:        return "mi_free";
    case TYPE_JE_FREE:        return "je_free";
    case TYPE_TC_FREE:        return "tc_free";
    case TYPE_ZDLPV:          return "_ZdlPv";
    case TYPE_ZDAPV:          return "_ZdaPv";
    default:                  return "UNKNOWN";
  }
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
  PIN_GetLock(&stats_lock, PIN_ThreadId());
  type_counts[type]++;
  PIN_ReleaseLock(&stats_lock);
}

/* ===================================================================== */
// Callback implementations
/* ===================================================================== */
static bool depth_outermost_before(ThreadState* ts, int alloc_type,
                                   ADDRINT size, ADDRINT arg2 = 0)
{
  if (ts->alloc_depth > 0) {
    if (ts->alloc_depth < MAX_DEPTH) ts->alloc_depth++;
    else ts->alloc_overflow++;
    return false;
  }
  ts->alloc_depth = 1;
  ts->pending = PendingAlloc{size, arg2, alloc_type, 0};
  return true;
}

static void try_auto_reset_depth(ThreadState* ts)
{
  if (ts->alloc_depth == 0) { ts->alloc_stuck_counter = 0; return; }
  ts->alloc_stuck_counter++;
  if (ts->alloc_stuck_counter >= MAX_STUCK) {
    ts->alloc_depth = 0; ts->alloc_overflow = 0; ts->alloc_stuck_counter = 0;
  }
}

VOID AllocBefore(ADDRINT size, UINT32 alloc_type)
{
  ThreadState* ts = get_tls();
  try_auto_reset_depth(ts);
  depth_outermost_before(ts, (int)alloc_type, size);
}

VOID CallocBefore(ADDRINT nmemb, ADDRINT elem_size, UINT32 alloc_type)
{
  ThreadState* ts = get_tls();
  try_auto_reset_depth(ts);
  depth_outermost_before(ts, (int)alloc_type, nmemb * elem_size);
}

VOID ReallocBefore(ADDRINT old_ptr, ADDRINT new_size, UINT32 alloc_type)
{
  ThreadState* ts = get_tls();
  try_auto_reset_depth(ts);
  if (ts->alloc_depth > 0) {
    if (ts->alloc_depth < MAX_DEPTH) ts->alloc_depth++;
    else ts->alloc_overflow++;
    return;
  }
  ts->alloc_depth = 1;
  ts->pending = PendingAlloc{old_ptr, new_size, (int)alloc_type, 0};
}

VOID AllocAfter(ADDRINT ret)
{
  ThreadState* ts = get_tls();
  if (ts->alloc_overflow > 0) { ts->alloc_overflow--; return; }
  if (ts->alloc_depth == 0) return;
  if (ts->alloc_depth > 1) { ts->alloc_depth--; return; }
  ts->alloc_depth = 0;

  PIN_GetLock(&malloc_lock, PIN_ThreadId());

  int alloc_type = ts->pending.type;
  if (alloc_type >= 11 && alloc_type <= 14) {
    ADDRINT old_ptr = ts->pending.size;
    ADDRINT new_size = ts->pending.arg2;
    write_malloc_instr_locked((unsigned char)alloc_type, old_ptr, new_size, ret);
    if (old_ptr != 0) tracked_addresses.erase(old_ptr);
    if (ret != 0 && ret != (ADDRINT)-1) tracked_addresses.insert(ret);
  } else {
    if (ret != 0 && ret != (ADDRINT)-1) {
      write_malloc_instr_locked((unsigned char)alloc_type,
                                ts->pending.size, ts->pending.arg2, ret);
      tracked_addresses.insert(ret);
    }
  }
  PIN_ReleaseLock(&malloc_lock);
}

VOID PosixMemalignBefore(ADDRINT memptr, ADDRINT alignment, ADDRINT size)
{
  ThreadState* ts = get_tls();
  if (ts->alloc_depth > 0) {
    if (ts->alloc_depth < MAX_DEPTH) ts->alloc_depth++;
    else ts->alloc_overflow++;
    return;
  }
  ts->alloc_depth = 1;
  ts->pending = PendingAlloc{size, alignment, TYPE_POSIX_MEMALIGN, memptr};
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
      write_malloc_instr_locked(TYPE_POSIX_MEMALIGN, ts->pending.size, ts->pending.arg2, real_addr);
      tracked_addresses.insert(real_addr);
      PIN_ReleaseLock(&malloc_lock);
    }
  }
}

VOID FreeBefore(ADDRINT ptr, UINT32 free_type)
{
  if (ptr == 0) return;
  PIN_GetLock(&malloc_lock, PIN_ThreadId());
  auto it = tracked_addresses.find(ptr);
  if (it != tracked_addresses.end()) {
    write_malloc_instr_locked((unsigned char)free_type, (unsigned long long)ptr, 0, 0);
    tracked_addresses.erase(it);
  }
  PIN_ReleaseLock(&malloc_lock);
}

VOID FreeAfter() { /* no-op */ }

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
    write_malloc_instr_locked(TYPE_MMAP, ts->mmap_pending_size, 0, ret);
    tracked_addresses.insert(ret);
    PIN_ReleaseLock(&malloc_lock);
  }
}

VOID MunmapBefore(ADDRINT addr, ADDRINT length)
{
  if (addr == 0 || addr == (ADDRINT)-1) return;
  PIN_GetLock(&malloc_lock, PIN_ThreadId());
  auto it = tracked_addresses.find(addr);
  if (it != tracked_addresses.end()) {
    write_malloc_instr_locked(TYPE_MUNMAP, (unsigned long long)addr, (unsigned long long)length, 0);
    tracked_addresses.erase(it);
  }
  PIN_ReleaseLock(&malloc_lock);
}

VOID MunmapAfter() { /* no-op */ }

VOID ResetDepthOnMain();

/* ===================================================================== */
// ImageLoad — per-symbol fine-grained type registration (23 symbols)
/* ===================================================================== */
struct SymbolHook {
  const char* name;
  unsigned char type;
  enum { MALLOC, CALLOC, REALLOC, FREE } family;
};

static const SymbolHook all_symbols[] = {
  {"malloc",     TYPE_MALLOC,     SymbolHook::MALLOC},
  {"mi_malloc",  TYPE_MI_MALLOC,  SymbolHook::MALLOC},
  {"je_malloc",  TYPE_JE_MALLOC,  SymbolHook::MALLOC},
  {"tc_malloc",  TYPE_TC_MALLOC,  SymbolHook::MALLOC},
  {"_Znwm",      TYPE_ZNWM,       SymbolHook::MALLOC},
  {"_Znam",      TYPE_ZNAM,       SymbolHook::MALLOC},
  {"calloc",     TYPE_CALLOC,     SymbolHook::CALLOC},
  {"mi_calloc",  TYPE_MI_CALLOC,  SymbolHook::CALLOC},
  {"je_calloc",  TYPE_JE_CALLOC,  SymbolHook::CALLOC},
  {"tc_calloc",  TYPE_TC_CALLOC,  SymbolHook::CALLOC},
  {"realloc",    TYPE_REALLOC,    SymbolHook::REALLOC},
  {"mi_realloc", TYPE_MI_REALLOC, SymbolHook::REALLOC},
  {"je_realloc", TYPE_JE_REALLOC, SymbolHook::REALLOC},
  {"tc_realloc", TYPE_TC_REALLOC, SymbolHook::REALLOC},
  {"free",       TYPE_FREE,       SymbolHook::FREE},
  {"mi_free",    TYPE_MI_FREE,    SymbolHook::FREE},
  {"je_free",    TYPE_JE_FREE,    SymbolHook::FREE},
  {"tc_free",    TYPE_TC_FREE,    SymbolHook::FREE},
  {"_ZdlPv",     TYPE_ZDLPV,      SymbolHook::FREE},
  {"_ZdaPv",     TYPE_ZDAPV,      SymbolHook::FREE},
};

VOID ImageLoad(IMG img, VOID* v)
{
  if (!IMG_Valid(img)) return;
  RTN rtn;

  rtn = RTN_FindByName(img, "posix_memalign");
  if (RTN_Valid(rtn)) {
    RTN_Open(rtn);
    RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)PosixMemalignBefore,
                   IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
                   IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
                   IARG_FUNCARG_ENTRYPOINT_VALUE, 2, IARG_END);
    RTN_InsertCall(rtn, IPOINT_AFTER, (AFUNPTR)PosixMemalignAfter,
                   IARG_FUNCRET_EXITPOINT_VALUE, IARG_END);
    RTN_Close(rtn);
  }

  rtn = RTN_FindByName(img, "mmap");
  if (RTN_Valid(rtn)) {
    RTN_Open(rtn);
    RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)MmapBefore,
                   IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
                   IARG_FUNCARG_ENTRYPOINT_VALUE, 3, IARG_END);
    RTN_InsertCall(rtn, IPOINT_AFTER, (AFUNPTR)MmapAfter,
                   IARG_FUNCRET_EXITPOINT_VALUE, IARG_END);
    RTN_Close(rtn);
  }

  rtn = RTN_FindByName(img, "munmap");
  if (RTN_Valid(rtn)) {
    RTN_Open(rtn);
    RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)MunmapBefore,
                   IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
                   IARG_FUNCARG_ENTRYPOINT_VALUE, 1, IARG_END);
    RTN_InsertCall(rtn, IPOINT_AFTER, (AFUNPTR)MunmapAfter, IARG_END);
    RTN_Close(rtn);
  }

  for (const auto& sym : all_symbols) {
    rtn = RTN_FindByName(img, sym.name);
    if (!RTN_Valid(rtn)) continue;
    RTN_Open(rtn);
    switch (sym.family) {
      case SymbolHook::MALLOC:
        RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)AllocBefore,
                       IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
                       IARG_UINT32, sym.type, IARG_END);
        RTN_InsertCall(rtn, IPOINT_AFTER, (AFUNPTR)AllocAfter,
                       IARG_FUNCRET_EXITPOINT_VALUE, IARG_END);
        break;
      case SymbolHook::CALLOC:
        RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)CallocBefore,
                       IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
                       IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
                       IARG_UINT32, sym.type, IARG_END);
        RTN_InsertCall(rtn, IPOINT_AFTER, (AFUNPTR)AllocAfter,
                       IARG_FUNCRET_EXITPOINT_VALUE, IARG_END);
        break;
      case SymbolHook::REALLOC:
        RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)ReallocBefore,
                       IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
                       IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
                       IARG_UINT32, sym.type, IARG_END);
        RTN_InsertCall(rtn, IPOINT_AFTER, (AFUNPTR)AllocAfter,
                       IARG_FUNCRET_EXITPOINT_VALUE, IARG_END);
        break;
      case SymbolHook::FREE:
        RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)FreeBefore,
                       IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
                       IARG_UINT32, sym.type, IARG_END);
        RTN_InsertCall(rtn, IPOINT_AFTER, (AFUNPTR)FreeAfter, IARG_END);
        break;
    }
    RTN_Close(rtn);
  }

  for (const char* entry : {"main", "MAIN__", "main_"}) {
    rtn = RTN_FindByName(img, entry);
    if (RTN_Valid(rtn)) {
      RTN_Open(rtn);
      RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)ResetDepthOnMain, IARG_END);
      RTN_Close(rtn);
    }
  }

  std::cout << "[Object Tracer v5] Instrumented: " << IMG_Name(img) << std::endl;
}

VOID ResetDepthOnMain()
{
  ThreadState* ts = get_tls();
  ts->alloc_depth = 0; ts->alloc_overflow = 0;
  ts->mmap_depth = 0; ts->mmap_overflow = 0;
}

/* ===================================================================== */
VOID Fini(INT32 code, VOID* v)
{
  malloc_binfile.close();
  std::cout << "\n[Object Tracer v5] === Type Statistics ===" << std::endl;
  unsigned long long total = 0;
  for (const auto& [t, count] : type_counts) {
    std::cout << "  type " << (int)t << " (" << type_name(t) << "): " << count << std::endl;
    total += count;
  }
  std::cout << "  TOTAL: " << total << " records" << std::endl;
  std::cout << "[Object Tracer v5] Active tracked: " << tracked_addresses.size() << std::endl;
}

int main(int argc, char* argv[])
{
  PIN_InitSymbols();
  if (PIN_Init(argc, argv)) return Usage();
  PIN_InitLock(&malloc_lock);
  PIN_InitLock(&stats_lock);
  tls_key = PIN_CreateThreadDataKey(ThreadCleanup);
  malloc_binfile.open(KnobMallocOutputFile.Value().c_str(), std::ios_base::binary | std::ios_base::trunc);
  if (!malloc_binfile) { std::cout << "Error: Cannot open output file." << std::endl; exit(1); }
  IMG_AddInstrumentFunction(ImageLoad, 0);
  PIN_AddFiniFunction(Fini, 0);
  PIN_StartProgram();
  return 0;
}