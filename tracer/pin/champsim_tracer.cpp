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
 *  ChampSim Tracer — Produces instruction trace with embedded memory allocation events.
 *
 *  Memory allocation analysis logic is verbatim from object_tracer.cpp (v5):
 *  - Depth counter with saturation (MAX_DEPTH=16) and auto-reset (MAX_STUCK=2)
 *  - Thread-local state (TLS) + PIN_LOCK for thread safety
 *  - tracked_addresses set to filter free/munmap (suppress glibc-internal noise)
 *  - Independent mmap depth tracking
 *  - realloc_inplace (type=16) detection
 *  - posix_memalign passes alignment as source_memory[1]
 *  - C++ new/delete, mimalloc/jemalloc/tcmalloc
 *  - aligned_alloc and memalign are NOT hooked (thin wrappers that call malloc internally)
 */

#include <fstream>
#include <iostream>
#include <sstream>
#include <cstdlib>
#include <cstring>
#include <string>
#include <unordered_map>
#include <vector>
#include <algorithm>

#include "../../inc/trace_instruction.h"
#include "pin.H"

/* ===================================================================== */
// Binary malloc trace record (32 bytes) — same as object_tracer
/* ===================================================================== */
struct malloc_instr {
  unsigned long long arg1;     // parameter 1 (Size or Ptr)
  unsigned long long arg2;     // parameter 2 (Alignment or extra)
  unsigned long long ret;      // return value (Allocated Addr)
  unsigned char type;          // 1=malloc, 2=free, 3=mmap, 4=munmap,
                               // 5=calloc, 6=realloc, 8=posix_memalign,
                               // 16=realloc_inplace
  unsigned char reserved[7];
};
static_assert(sizeof(malloc_instr) == 32, "malloc_instr must be exactly 32 bytes");

using trace_instr_format_t = input_instr;

#ifndef MAP_ANONYMOUS
#define MAP_ANONYMOUS 0x20  // Linux x86_64
#endif

/* ================================================================== */
// Global variables
/* ================================================================== */

std::ofstream outfile;
trace_instr_format_t curr_instr;
INT64 trace_insts_left = 0;
INT64 fast_forward_insts_left = 0;
bool skip_dumping_instructions = false;
bool trace_limit_reached = false;

// Forward declarations
VOID insert_analysis_functions(INS ins);
VOID ResetCurrentInstruction(VOID* ip);

/* ================================================================== */
// Allocation tracking state — from object_tracer v5
/* ================================================================== */
struct TrackedAlloc { ADDRINT size; unsigned char type; };
std::unordered_map<ADDRINT, TrackedAlloc> tracked_allocations;
static PIN_LOCK malloc_lock;

// Maximum nesting depth before saturation.
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

constexpr int MAX_STUCK = 2;  // auto-reset threshold

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

// Pending malloc event to be embedded into the next instruction's trace record.
// Set by allocator After callbacks, consumed by ResetCurrentInstruction.
struct {
  unsigned char type = 0;            // is_malloc value
  unsigned long long arg1 = 0;       // source_memory[0] (size or ptr)
  unsigned long long arg2 = 0;       // source_memory[1]
  unsigned long long ret = 0;        // destination_memory[0]
} pending_instr_malloc;

/* ===================================================================== */
// Batch write buffer — accumulate records and flush in bulk
/* ===================================================================== */
template <size_t N = 4096>
struct TraceBuffer {
  trace_instr_format_t buffer[N];
  size_t count = 0;

  void push(const trace_instr_format_t& rec, std::ofstream& of) {
    buffer[count++] = rec;
    if (count == N) flush(of);
  }

  void flush(std::ofstream& of) {
    if (count == 0) return;
    of.write(reinterpret_cast<typename decltype(of)::char_type*>(buffer),
             sizeof(trace_instr_format_t) * count);
    count = 0;
  }
};

static TraceBuffer<4096> trace_buffer;

/* ===================================================================== */
// Command line switches
/* ===================================================================== */
KNOB<std::string> KnobOutputFile(KNOB_MODE_WRITEONCE, "pintool", "o", "champsim.trace", "specify file name for Champsim tracer output");

KNOB<UINT64> KnobFastForward(KNOB_MODE_WRITEONCE, "pintool", "s", "0", "How many instructions to fast-forward before tracing begins");

KNOB<UINT64> KnobTraceLen(KNOB_MODE_WRITEONCE, "pintool", "t", "0", "How many instructions to trace (0 for unlimited)");

KNOB<UINT64> KnobMallocThreshold(KNOB_MODE_WRITEONCE, "pintool", "k", "256", "Record malloc/free events only for allocations >= this size in bytes");

KNOB<std::string> KnobConfigFile(KNOB_MODE_WRITEONCE, "pintool", "c", "", "specify a config file for multi-segment trace (format: -s N -t N -o file per line)");

/* ===================================================================== */
// Multi-segment trace support
/* ===================================================================== */
struct TraceSegment {
  INT64 abs_skip;           // absolute skip from program start
  INT64 length;             // trace length
  std::string output_file;  // output file name
};

std::vector<TraceSegment> segments;
size_t current_segment_idx = 0;
INT64 total_instructions_passed = 0;  // cumulative instruction count from program start

// Forward declarations for multi-segment functions
void dump_tracked_allocations(std::ofstream& of);
void start_next_segment();

/* ===================================================================== */
// Utilities
/* ===================================================================== */

/*!
 *  Print out help message.
 */
INT32 Usage()
{
  std::cerr << "This tool creates a register and memory access trace" << std::endl
            << "Specify the output trace file with -o" << std::endl
            << "Specify the number of instructions to skip before tracing with -s" << std::endl
            << "Specify the number of instructions to trace with -t (0 for unlimited)" << std::endl
            << "Specify the minimum allocation size threshold with -k (default 256)" << std::endl
            << "Specify a multi-segment config file with -c" << std::endl
            << "  Config file format: one line per segment, each with -s N -t N -o filename" << std::endl
            << "  Example: echo '-s 100000000 -t 50000000 -o trace_0.champsim' > cfg.txt" << std::endl
            << std::endl;

  std::cerr << KNOB_BASE::StringKnobSummary() << std::endl;

  return -1;
}

void fast_forward_trace(UINT32 trace_size)
{
  fast_forward_insts_left -= trace_size;
  if (fast_forward_insts_left < 500) {
    std::cout << "Fast-forward almost done, switching to per instruction "
                 "fast-forward.\n";
    PIN_RemoveInstrumentation();
  }
}

void dump_tracked_allocations(std::ofstream& of)
{
  // Flush any buffered instruction records so baseline appears after them
  trace_buffer.flush(outfile);

  PIN_GetLock(&malloc_lock, PIN_ThreadId());
  for (const auto& [addr, info] : tracked_allocations) {
    curr_instr = {};
    curr_instr.is_malloc = info.type;
    curr_instr.source_memory[0] = info.size;
    curr_instr.destination_memory[0] = addr;

    typename decltype(outfile)::char_type buf[sizeof(trace_instr_format_t)];
    std::memcpy(buf, &curr_instr, sizeof(trace_instr_format_t));
    of.write(buf, sizeof(trace_instr_format_t));
  }
  PIN_ReleaseLock(&malloc_lock);
}

void fast_forward_ins()
{
  if (fast_forward_insts_left > 0) {
    fast_forward_insts_left -= 1;
    skip_dumping_instructions = true;
  } else if (skip_dumping_instructions) {
    // Fast-forward finished: dump all active allocations as baseline
    // memory state for Champsim's initial memory footprint.
    dump_tracked_allocations(outfile);

    // Clear any pending alloc event from the last fast-forward instruction
    pending_instr_malloc = {};

    std::cout << "Fast-forward finished, starting tracing. Baseline allocations: "
              << tracked_allocations.size() << std::endl;
    skip_dumping_instructions = false;
  }
}

// Parse multi-segment config file. Format: one segment per line:
//   -s N -t N -o filename
// Comments starting with '#' are ignored.  Blank lines are skipped.
// Segments must be sorted by ascending abs_skip.
void parse_config(const std::string& config_path)
{
  std::ifstream cfg(config_path);
  if (!cfg) {
    std::cerr << "Error: cannot open config file: " << config_path << std::endl;
    exit(1);
  }

  std::string line;
  int line_no = 0;
  INT64 prev_skip = -1;

  while (std::getline(cfg, line)) {
    line_no++;

    // strip comment
    auto comment_pos = line.find('#');
    if (comment_pos != std::string::npos)
      line = line.substr(0, comment_pos);

    // trim
    line.erase(0, line.find_first_not_of(" \t\r\n"));
    line.erase(line.find_last_not_of(" \t\r\n") + 1);

    if (line.empty()) continue;

    std::istringstream iss(line);
    TraceSegment seg;
    seg.length = 0;

    std::string token;
    while (iss >> token) {
      if (token == "-s") {
        if (!(iss >> seg.abs_skip)) {
          std::cerr << "Error in config line " << line_no << ": missing value for -s" << std::endl;
          exit(1);
        }
      } else if (token == "-t") {
        if (!(iss >> seg.length)) {
          std::cerr << "Error in config line " << line_no << ": missing value for -t" << std::endl;
          exit(1);
        }
      } else if (token == "-o") {
        if (!(iss >> seg.output_file)) {
          std::cerr << "Error in config line " << line_no << ": missing value for -o" << std::endl;
          exit(1);
        }
      } else {
        std::cerr << "Error in config line " << line_no << ": unexpected token '" << token << "'" << std::endl;
        exit(1);
      }
    }

    if (seg.output_file.empty()) {
      std::cerr << "Error in config line " << line_no << ": missing -o filename" << std::endl;
      exit(1);
    }
    if (seg.length < 0) {
      std::cerr << "Error in config line " << line_no << ": -t must be >= 0" << std::endl;
      exit(1);
    }

    // Validate ascending order of abs_skip
    if (seg.abs_skip < prev_skip) {
      std::cerr << "Error in config line " << line_no << ": -s values must be non-decreasing "
                << "(prev=" << prev_skip << ", cur=" << seg.abs_skip << ")" << std::endl;
      exit(1);
    }
    prev_skip = seg.abs_skip;

    segments.push_back(seg);
  }

  if (segments.empty()) {
    std::cerr << "Error: config file contains no valid segments" << std::endl;
    exit(1);
  }

  std::cout << "[ChampSim Tracer] Parsed " << segments.size() << " trace segment(s) from config." << std::endl;
  for (size_t i = 0; i < segments.size(); i++) {
    std::cout << "  segment " << i << ": skip=" << segments[i].abs_skip
              << " trace=" << segments[i].length
              << " output=" << segments[i].output_file << std::endl;
  }
}

// Switch to the next trace segment. Called when current segment ends.
// Sets up fast-forward for the next segment's absolute skip offset,
// opens the new output file, and resets all per-segment state.
void start_next_segment()
{
  current_segment_idx++;
  if (current_segment_idx >= segments.size()) {
    // No more segments — let program run to natural completion
    trace_limit_reached = true;
    std::cout << "[ChampSim Tracer] All segments completed. Letting program finish.\n";
    return;
  }

  const auto& seg = segments[current_segment_idx];

  // Compute how many more instructions to skip to reach abs_skip
  INT64 delta_skip = seg.abs_skip - total_instructions_passed;
  if (delta_skip < 0) delta_skip = 0;

  // Flush any buffered records to the current file before closing
  trace_buffer.flush(outfile);

  // Close previous output file
  if (outfile.is_open()) {
    outfile.close();
  }

  // Open new output file
  outfile.open(seg.output_file.c_str(), std::ios_base::binary | std::ios_base::trunc);
  if (!outfile) {
    std::cerr << "Error: cannot open output file: " << seg.output_file << std::endl;
    exit(1);
  }

  // Write allocation baseline for this segment
  dump_tracked_allocations(outfile);
  pending_instr_malloc = {};

  // Set up counters for this segment
  fast_forward_insts_left = delta_skip;
  trace_insts_left = seg.length;
  skip_dumping_instructions = (delta_skip > 0);

  // Reset trace_limit_reached so allocator callbacks run again
  trace_limit_reached = false;

  // Re-instrument if we're in fast-forward mode
  if (fast_forward_insts_left > 500) {
    std::cout << "[ChampSim Tracer] Segment " << current_segment_idx
              << ": fast-forwarding " << fast_forward_insts_left
              << " instructions (abs_skip=" << seg.abs_skip
              << "), then tracing " << seg.length
              << " instrs to " << seg.output_file << std::endl;
    PIN_RemoveInstrumentation();
  } else {
    std::cout << "[ChampSim Tracer] Segment " << current_segment_idx
              << ": no fast-forward needed (abs_skip=" << seg.abs_skip
              << "), tracing " << seg.length
              << " instrs to " << seg.output_file
              << ". Baseline allocations: " << tracked_allocations.size() << std::endl;
    skip_dumping_instructions = false;
  }
}

void check_end_of_trace()
{
  if (trace_insts_left > 0) {
    trace_insts_left -= 1;
    if (trace_insts_left == 0) {
      // Accumulate instruction count: abs_skip + length for this completed segment
      const auto& seg = segments.empty() ? TraceSegment{0, 0, ""} : segments[current_segment_idx];
      total_instructions_passed = seg.abs_skip + seg.length;

      if (!segments.empty() && current_segment_idx + 1 < segments.size()) {
        std::cout << "[ChampSim Tracer] Segment " << current_segment_idx
                  << " finished. Switching to next segment.\n";
        start_next_segment();
      } else {
        trace_limit_reached = true;
        std::cout << "Reaching trace length limit, terminating early.\n";
        if (segments.empty()) {
          // Single-segment mode: exit immediately
          PIN_ExitApplication(0);
        }
        // Multi-segment mode: let program run to natural exit (Fini will handle cleanup)
      }
    }
  }
}

template <typename Func>
void for_ins_in_trace(const TRACE& trace, Func f)
{
  for (BBL bbl = TRACE_BblHead(trace); BBL_Valid(bbl); bbl = BBL_Next(bbl)) {
    for (INS ins = BBL_InsHead(bbl); INS_Valid(ins); ins = INS_Next(ins)) {
      f(ins);
    }
  }
}

void insert_instrumentation(TRACE trace, void* v)
{
  if (fast_forward_insts_left > 500) {
    TRACE_InsertCall(trace, IPOINT_BEFORE, (AFUNPTR)fast_forward_trace, IARG_UINT32, TRACE_NumIns(trace), IARG_END);
  } else {
    for_ins_in_trace(trace, [](const INS& ins) {
      INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)fast_forward_ins, IARG_END);
      INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)check_end_of_trace, IARG_END);
      insert_analysis_functions(ins);
    });
  }
}

/* ===================================================================== */
// Analysis routines — instruction trace
/* ===================================================================== */

void ResetCurrentInstruction(VOID* ip)
{
  curr_instr = {};
  curr_instr.ip = (unsigned long long int)ip;

  // Embed pending malloc event into this instruction's trace record.
  // Set by allocator After callbacks, consumed here to pair the malloc
  // event with the next retiring instruction.
  if (pending_instr_malloc.type != 0) {
    curr_instr.is_malloc = pending_instr_malloc.type;
    curr_instr.source_memory[0] = pending_instr_malloc.arg1;
    curr_instr.source_memory[1] = pending_instr_malloc.arg2;
    curr_instr.destination_memory[0] = pending_instr_malloc.ret;
    pending_instr_malloc = {};  // consume the event
  }
}

void WriteCurrentInstruction()
{
  // During fast-forward, skip instruction writes — allocation baseline
  // is dumped in bulk when fast-forward ends.
  if (skip_dumping_instructions) return;

  trace_buffer.push(curr_instr, outfile);
}

void BranchOrNot(UINT32 taken)
{
  curr_instr.is_branch = 1;
  curr_instr.branch_taken = taken;
}

template <typename T>
void WriteToSet(T* begin, T* end, UINT32 r)
{
  auto set_end = std::find(begin, end, 0);
  auto found_reg = std::find(begin, set_end, r);
  *found_reg = r;
}

// =========================================================================
// Allocator analysis routines — from object_tracer v5
//
// Depth counter with saturation, thread-safe.
// Only the outermost user-level call writes records.
// Allocation events are embedded in-band into the instruction trace via
// pending_instr_malloc.
// =========================================================================

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
  if (trace_limit_reached) return;
  ThreadState* ts = get_tls();
  try_auto_reset_depth(ts);
  depth_outermost_before(ts, 1, size);
}

// --- CALLOC (type=5) ---
VOID CallocBefore(ADDRINT nmemb, ADDRINT elem_size)
{
  if (trace_limit_reached) return;
  ThreadState* ts = get_tls();
  try_auto_reset_depth(ts);
  depth_outermost_before(ts, 5, nmemb * elem_size);
}

// --- REALLOC (type=6 or 16) ---
VOID ReallocBefore(ADDRINT old_ptr, ADDRINT new_size)
{
  if (trace_limit_reached) return;
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
    // Always erase old_ptr from tracked set (free implied by realloc)
    if (old_ptr != 0) tracked_allocations.erase(old_ptr);
    // Only record realloc if new_size meets threshold
    if (new_size >= KnobMallocThreshold.Value() && ret != 0 && ret != (ADDRINT)-1) {
      pending_instr_malloc.type = final_type;
      pending_instr_malloc.arg1 = old_ptr;
      pending_instr_malloc.arg2 = new_size;
      pending_instr_malloc.ret = ret;
      tracked_allocations[ret] = {new_size, final_type};
    }
  } else {
    if (ret != 0 && ret != (ADDRINT)-1 && ts->pending.size >= KnobMallocThreshold.Value()) {
      pending_instr_malloc.type = (unsigned char)ts->pending.type;
      pending_instr_malloc.arg1 = ts->pending.size;
      pending_instr_malloc.arg2 = ts->pending.arg2;
      pending_instr_malloc.ret = ret;
      tracked_allocations[ret] = {ts->pending.size, (unsigned char)ts->pending.type};
    }
  }

  PIN_ReleaseLock(&malloc_lock);
}

// --- POSIX_MEMALIGN (type=8) — uses depth counter, but BEFORE always stages ---
VOID PosixMemalignBefore(ADDRINT memptr, ADDRINT alignment, ADDRINT size)
{
  if (trace_limit_reached) return;
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
    if (real_addr != 0 && real_addr != (ADDRINT)-1 && ts->pending.size >= KnobMallocThreshold.Value()) {
      PIN_GetLock(&malloc_lock, PIN_ThreadId());
      pending_instr_malloc.type = 8;
      pending_instr_malloc.arg1 = ts->pending.size;
      pending_instr_malloc.arg2 = ts->pending.arg2;   // alignment
      pending_instr_malloc.ret = real_addr;
      tracked_allocations[real_addr] = {ts->pending.size, 8};
      PIN_ReleaseLock(&malloc_lock);
    }
  }
}

// --- FREE (type=2) — only write if tracked (suppresses glibc-internal free) ---
VOID FreeBefore(ADDRINT ptr)
{
  if (ptr == 0) return;

  PIN_GetLock(&malloc_lock, PIN_ThreadId());
  auto it = tracked_allocations.find(ptr);
  if (it != tracked_allocations.end()) {
    pending_instr_malloc.type = 2;
    pending_instr_malloc.arg1 = (unsigned long long)ptr;
    pending_instr_malloc.arg2 = 0;
    pending_instr_malloc.ret = 0;
    tracked_allocations.erase(it);
  }
  PIN_ReleaseLock(&malloc_lock);
}

VOID FreeAfter() { /* no-op */ }

// --- MMAP (independent depth + saturation) ---
VOID MmapBefore(ADDRINT length, ADDRINT flags)
{
  if (trace_limit_reached) return;

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

  if (ret != 0 && ret != (ADDRINT)-1 && ts->mmap_pending_size >= KnobMallocThreshold.Value()) {
    PIN_GetLock(&malloc_lock, PIN_ThreadId());
    pending_instr_malloc.type = 3;
    pending_instr_malloc.arg1 = ts->mmap_pending_size;
    pending_instr_malloc.arg2 = 0;
    pending_instr_malloc.ret = ret;
    tracked_allocations[ret] = {ts->mmap_pending_size, 3};
    PIN_ReleaseLock(&malloc_lock);
  }
}

// --- MUNMAP (type=4) — only write if tracked ---
VOID MunmapBefore(ADDRINT addr, ADDRINT length)
{
  if (addr == 0 || addr == (ADDRINT)-1) return;

  PIN_GetLock(&malloc_lock, PIN_ThreadId());
  auto it = tracked_allocations.find(addr);
  if (it != tracked_allocations.end()) {
    pending_instr_malloc.type = 4;
    pending_instr_malloc.arg1 = (unsigned long long)addr;
    pending_instr_malloc.arg2 = (unsigned long long)length;
    pending_instr_malloc.ret = 0;
    tracked_allocations.erase(it);
  }
  PIN_ReleaseLock(&malloc_lock);
}

VOID MunmapAfter() { /* no-op */ }

// Forward declaration
VOID ResetDepthOnMain();

/* ===================================================================== */
// Automation analysis callbacks — instruction instrumentation
/* ===================================================================== */

// Is called for every instruction and instruments reads and writes
VOID insert_analysis_functions(INS ins)
{
  // begin each instruction with this function
  INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)ResetCurrentInstruction, IARG_INST_PTR, IARG_END);

  // instrument branch instructions
  if (INS_IsBranch(ins))
    INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)BranchOrNot, IARG_BRANCH_TAKEN, IARG_END);

  // instrument register reads
  UINT32 readRegCount = INS_MaxNumRRegs(ins);
  for (UINT32 i = 0; i < readRegCount; i++) {
    UINT32 regNum = INS_RegR(ins, i);
    INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)WriteToSet<unsigned char>, IARG_PTR, curr_instr.source_registers, IARG_PTR,
                   curr_instr.source_registers + NUM_INSTR_SOURCES, IARG_UINT32, regNum, IARG_END);
  }

  // instrument register writes
  UINT32 writeRegCount = INS_MaxNumWRegs(ins);
  for (UINT32 i = 0; i < writeRegCount; i++) {
    UINT32 regNum = INS_RegW(ins, i);
    INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)WriteToSet<unsigned char>, IARG_PTR, curr_instr.destination_registers, IARG_PTR,
                   curr_instr.destination_registers + NUM_INSTR_DESTINATIONS, IARG_UINT32, regNum, IARG_END);
  }

  // instrument memory reads and writes
  UINT32 memOperands = INS_MemoryOperandCount(ins);

  // Iterate over each memory operand of the instruction.
  for (UINT32 memOp = 0; memOp < memOperands; memOp++) {
    if (INS_MemoryOperandIsRead(ins, memOp))
      INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)WriteToSet<unsigned long long int>, IARG_PTR, curr_instr.source_memory, IARG_PTR,
                     curr_instr.source_memory + NUM_INSTR_SOURCES, IARG_MEMORYOP_EA, memOp, IARG_END);
    if (INS_MemoryOperandIsWritten(ins, memOp))
      INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)WriteToSet<unsigned long long int>, IARG_PTR, curr_instr.destination_memory, IARG_PTR,
                     curr_instr.destination_memory + NUM_INSTR_DESTINATIONS, IARG_MEMORYOP_EA, memOp, IARG_END);
  }

  // finalize each instruction with this function
  if (outfile)
    INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)WriteCurrentInstruction, IARG_END);
}

/* ===================================================================== */
// ImageLoad — from object_tracer v5 symbol coverage
// ===================================================================== */
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

  // --- Free ---
  const std::vector<std::string> freeSyms = {
    "free",
    "mi_free", "je_free", "tc_free",
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

  // --- Reset depth at entry point (glibc init may have leaked depth) ---
  for (const char* entry : {"main"}) {
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

  std::cout << "[ChampSim Tracer] Instrumented: " << IMG_Name(img) << std::endl;
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
  if (outfile.is_open()) {
    trace_buffer.flush(outfile);
    outfile.close();
  }
  std::cout << "[ChampSim Tracer] Trace saved. Active tracked: " << tracked_allocations.size() << std::endl;
}

/* ===================================================================== */
// SDE/PinPlay argument filter — verbatim from object_tracer.cpp v5
/* ===================================================================== */
static bool is_pinplay_arg(const std::string& arg)
{
  static const std::vector<std::string> pinplay_prefixes = {
    "-pinplay:", "-xyzzy", "-work-dir", "-use-cpuid-from-kit",
    "-chip-check", "-cpuid-in", "-bridge-save-mxcsr", "-bridge-set-mxcsr",
    "-cc_memory_size_64", "-follow-execv", "-virtual_segments",
    "-xed_ignore_unknown_reg", "-update-cpuid-from-host", "-sync-avx512-state",
    "-logfile", "-dcfg", "-dcfg:read_dcfg", "-log:mt", "-log:mp_mode",
    "-log:mp_atomic", "-log:fat", "-log:region_id", "-log:syminfo",
    "-log:pid", "-start_address", "-controller_log", "-controller_olog",
    "-pcregions:in", "-pcregions:merge_warmup", "-replay",
    "-replay:basename", "-replay:strace", "-replay:playout",
    "-replay:deadlock_timeout", "-reserve_memory", "--no_print_cmd"
  };
  for (const auto& pf : pinplay_prefixes) {
    if (arg == pf || arg.rfind(pf, 0) == 0) return true;
  }
  return false;
}

int main(int argc, char* argv[])
{
  PIN_InitSymbols();

  // Filter out PinPlay/SDE-specific arguments (e.g. -replay, -xyzzy)
  std::vector<char*> filtered;
  for (int i = 0; i < argc; i++) {
    std::string arg(argv[i]);
    if (is_pinplay_arg(arg)) {
      if (arg.find('=') == std::string::npos && i + 1 < argc &&
          argv[i+1][0] != '-') i++;
      continue;
    }
    filtered.push_back(argv[i]);
  }
  if (PIN_Init((int)filtered.size(), filtered.data()))
    return Usage();

  PIN_InitLock(&malloc_lock);
  tls_key = PIN_CreateThreadDataKey(ThreadCleanup);

  std::string config_path = KnobConfigFile.Value();

  if (!config_path.empty()) {
    // --- Multi-segment mode ---
    parse_config(config_path);

    // Initialize the first segment
    const auto& first = segments[0];

    // Prepare the first output file
    outfile.open(first.output_file.c_str(), std::ios_base::binary | std::ios_base::trunc);
    if (!outfile) {
      std::cerr << "Couldn't open output trace file: " << first.output_file << std::endl;
      exit(1);
    }

    fast_forward_insts_left = first.abs_skip;   // skip from program start
    trace_insts_left = first.length;
    trace_limit_reached = false;
    skip_dumping_instructions = (first.abs_skip > 0);

    std::cout << "[ChampSim Tracer] Multi-segment mode: " << segments.size() << " segments" << std::endl;
    std::cout << "[ChampSim Tracer] Segment 0: skip=" << first.abs_skip
              << " trace=" << first.length
              << " output=" << first.output_file << std::endl;
  } else {
    // --- Single-segment mode (backward compatible) ---
    trace_insts_left = KnobTraceLen.Value();
    fast_forward_insts_left = KnobFastForward.Value();

    outfile.open(KnobOutputFile.Value().c_str(), std::ios_base::binary | std::ios_base::trunc);
    if (!outfile) {
      std::cout << "Couldn't open output trace file. Exiting." << std::endl;
      exit(1);
    }
  }

  TRACE_AddInstrumentFunction(insert_instrumentation, 0);

  IMG_AddInstrumentFunction(ImageLoad, 0);

  PIN_AddFiniFunction(Fini, 0);

  PIN_StartProgram();

  return 0;
}
