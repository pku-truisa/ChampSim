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
 *  Three modes:
 *    No -m:               Compat mode — instruction trace ONLY, no allocation events.
 *                         Compatible with upstream ChampSim trace format.
 *                         Output: -o <file> (default champsim.trace)
 *    -m (no -a):          Embedded alloc mode — allocation events (instr_type=2)
 *                         embedded into the normal instruction trace.
 *                         Output: -o <file> (default champsim.trace)
 *    -m -a <file>:        Alloc-only mode — only allocation events, no instruction trace.
 *                         Output to <file> specified by -a.
 *
 *  Memory allocation analysis logic is verbatim from object_tracer.cpp (v5):
 *  - Depth counter with saturation (MAX_DEPTH=16) and auto-reset (MAX_STUCK=2)
 *  - Thread-local state (TLS) + PIN_LOCK for thread safety
 *  - tracked_addresses set to filter free/munmap (suppress glibc-internal noise)
 *  - Independent mmap depth tracking
 *  - realloc in-place detection (via source_memory[0] == destination_memory[0])
 *  - posix_memalign (type=10) and aligned_alloc (type=11) are hooked via RTN_ReplaceSignature
 */

#include <fstream>
#include <iostream>
#include <sstream>
#include <cstdlib>
#include <cstring>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>
#include <algorithm>

#include "../../inc/trace_instruction.h"
#include "pin.H"

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
bool instruction_count_mode = false;
static UINT64 total_instruction_count = 0;

// Mode flags:
//   compat_mode (no -m):          instruction trace ONLY, no allocation events
//   embedded_alloc_mode (-m):     instruction trace WITH embedded allocation events
//   alloc_only_mode (-m -a):      allocation events ONLY (no instruction trace)
bool compat_mode = true;
bool embedded_alloc_mode = false;
bool alloc_only_mode = false;

// For alloc-only mode: set of addresses tracked for this run
std::unordered_set<ADDRINT> tracked_addresses;
static std::unordered_map<unsigned char, unsigned long long> type_counts;
static PIN_LOCK stats_lock;

// Real function pointers (for RTN_ReplaceSignature)
static void* (*real_malloc)(size_t) = nullptr;
static void* (*real_calloc)(size_t, size_t) = nullptr;
static void* (*real_realloc)(void*, size_t) = nullptr;
static void  (*real_free)(void*) = nullptr;
static void* (*real_mmap)(void*, size_t, int, int, int, off_t) = nullptr;
static int   (*real_munmap)(void*, size_t) = nullptr;
static void* (*real_mremap)(void*, size_t, size_t, int, ...) = nullptr;
static int   (*real_posix_memalign)(void**, size_t, size_t) = nullptr;
static void* (*real_aligned_alloc)(size_t, size_t) = nullptr;

// Forward declarations
VOID insert_analysis_functions(INS ins);
VOID ResetCurrentInstruction(VOID* ip);

/* ================================================================== */
// Allocation tracking state — from object_tracer v5
/* ================================================================== */
struct TrackedAlloc { ADDRINT size; unsigned char type; ADDRINT caller_ip = 0; };
std::unordered_map<ADDRINT, TrackedAlloc> tracked_allocations;
static PIN_LOCK malloc_lock;

// Maximum nesting depth before saturation.
constexpr int MAX_DEPTH = 16;

struct ThreadState {
  int alloc_depth         = 0;  // 0 = idle, 1 = outermost, 2..MAX_DEPTH = nested
  int alloc_overflow      = 0;  // counts lost AFTER frames beyond MAX_DEPTH
  int alloc_stuck_counter = 0;  // auto-reset when depth stays non-zero too long

  // mmap has its own independent depth tracking
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
// Used only in embedded_alloc_mode.
struct {
  unsigned char type = 0;
  unsigned long long arg1 = 0;
  unsigned long long arg2 = 0;
  unsigned long long ret = 0;
  unsigned long long caller_ip = 0;
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
    of.write(reinterpret_cast<std::ofstream::char_type*>(buffer),
             sizeof(trace_instr_format_t) * count);
    count = 0;
  }
};

static TraceBuffer<4096> trace_buffer;

/* ===================================================================== */
// 40-byte malloc_instr format — compatible with object_tracer_wrapper.cpp
// and little_object_analyzer.py (v8+ auto-detects 32 vs 40 byte records).
// Fields: arg1, arg2, ret, caller_ip, type, reserved[7]
/* ===================================================================== */
struct malloc_instr {
  unsigned long long arg1;
  unsigned long long arg2;
  unsigned long long ret;
  unsigned long long caller_ip;
  unsigned char type;
  unsigned char reserved[7];
};
static_assert(sizeof(malloc_instr) == 40, "malloc_instr must be exactly 40 bytes");

/* ===================================================================== */
// Helper: write a 40-byte malloc_instr record directly to outfile
// Compatible with object_tracer_wrapper.cpp and little_object_analyzer.py formats.
/* ===================================================================== */
static void write_alloc_record_locked(unsigned char mtype,
                                      unsigned long long arg1,
                                      unsigned long long arg2,
                                      unsigned long long ret,
                                      unsigned long long caller_ip)
{
  malloc_instr rec;
  rec.type = mtype;
  rec.arg1 = arg1;
  rec.arg2 = arg2;
  rec.ret = ret;
  rec.caller_ip = caller_ip;
  std::memset(rec.reserved, 0, sizeof(rec.reserved));
  outfile.write(reinterpret_cast<std::ofstream::char_type*>(&rec), sizeof(malloc_instr));
  PIN_GetLock(&stats_lock, PIN_ThreadId());
  type_counts[mtype]++;
  PIN_ReleaseLock(&stats_lock);
}

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
            << "" << std::endl
            << "  Compat mode (default, no -m):" << std::endl
            << "    Produces instruction trace WITHOUT allocation events." << std::endl
            << "    Compatible with upstream ChampSim trace format." << std::endl
            << "    Output: -o <file> (default: champsim.trace)" << std::endl
            << "" << std::endl
            << "  Embedded alloc mode (-m, no -a):" << std::endl
            << "    Produces instruction trace WITH allocation events (instr_type=2)" << std::endl
            << "    embedded between normal instructions." << std::endl
            << "    Output: -o <file> (default: champsim.trace)" << std::endl
            << "" << std::endl
            << "  Alloc-only mode (-m -a <file>):" << std::endl
            << "    Produces ONLY allocation events (40-byte malloc_instr records" << std::endl
            << "    with caller_ip, compatible with little_object_analyzer.py), no instruction trace." << std::endl
            << "    Output: <file> specified by -a" << std::endl
            << "" << std::endl
            << "Options:" << std::endl
            << "  -o <file>   Output trace file (default: champsim.trace)" << std::endl
            << "  -s <N>      Skip N instructions before tracing" << std::endl
            << "  -t <N>      Trace N instructions (0 = unlimited)" << std::endl
            << "  -k <N>      Record alloc events only for requests >= N bytes (default: 256)" << std::endl
            << "  -c <file>   Multi-segment config file" << std::endl
            << "  -m          Enable allocation event recording" << std::endl
            << "  -a <file>   (with -m) Alloc-only mode: only allocation events to <file>" << std::endl
            << "  -f          Instruction count mode: count total instructions only" << std::endl
            << "              (incompatible with all other options)" << std::endl
            << std::endl;

  std::cerr << KNOB_BASE::StringKnobSummary() << std::endl;

  return -1;
}

void dump_tracked_allocations(std::ofstream& of)
{
  // In compat mode, do not dump allocation events
  if (compat_mode) return;

  // Flush any buffered instruction records so baseline appears after them
  trace_buffer.flush(outfile);

  PIN_GetLock(&malloc_lock, PIN_ThreadId());
  for (const auto& [addr, info] : tracked_allocations) {
    curr_instr = {};
    curr_instr.instr_type = 2;  // allocation event
    curr_instr.instr_info = info.type;
    curr_instr.source_memory[0] = info.size;
    curr_instr.destination_memory[0] = addr;
    curr_instr.destination_memory[1] = info.caller_ip;

    std::ofstream::char_type buf[sizeof(trace_instr_format_t)];
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

  // Notify user about the new segment
  if (fast_forward_insts_left > 0) {
    std::cout << "[ChampSim Tracer] Segment " << current_segment_idx
              << ": fast-forwarding " << fast_forward_insts_left
              << " instructions (abs_skip=" << seg.abs_skip
              << "), then tracing " << seg.length
              << " instrs to " << seg.output_file << std::endl;
  } else {
    skip_dumping_instructions = false;
    std::cout << "[ChampSim Tracer] Segment " << current_segment_idx
              << ": no fast-forward needed (abs_skip=" << seg.abs_skip
              << "), tracing " << seg.length
              << " instrs to " << seg.output_file
              << ". Baseline allocations: " << tracked_allocations.size() << std::endl;
  }
}

void check_end_of_trace()
{
  // Do not consume trace_insts_left while still in fast-forward
  if (fast_forward_insts_left > 0 || skip_dumping_instructions)
    return;

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
        PIN_ExitApplication(0);
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

static constexpr UINT64 PROGRESS_STEP = 100000000000ULL; // 100 billion
static UINT64 next_progress_milestone = PROGRESS_STEP;

VOID docount(UINT32 c)
{
  total_instruction_count += c;
  if (!alloc_only_mode && total_instruction_count >= next_progress_milestone) {
    std::cout << "[ChampSim Tracer] Progress: " << total_instruction_count
              << " instructions counted." << std::endl;
    next_progress_milestone += PROGRESS_STEP;
  }
}

void insert_count_instrumentation(TRACE trace, void* v)
{
  for (BBL bbl = TRACE_BblHead(trace); BBL_Valid(bbl); bbl = BBL_Next(bbl))
    BBL_InsertCall(bbl, IPOINT_BEFORE, (AFUNPTR)docount, IARG_UINT32, BBL_NumIns(bbl), IARG_END);
}

void insert_instrumentation(TRACE trace, void* v)
{
  if (alloc_only_mode) return;  // No instruction tracing in alloc-only mode

  // Unconditionally register all callbacks on every instruction.
  // Each callback has its own internal guard to handle the
  // fast-forward → tracing transition seamlessly at instruction granularity:
  //   - fast_forward_ins:   guards with fast_forward_insts_left > 0
  //   - check_end_of_trace: guards with fast_forward_insts_left > 0 || skip_dumping_instructions
  //   - insert_analysis_functions: guards by skipping output when skip_dumping_instructions is true
  for_ins_in_trace(trace, [](const INS& ins) {
    INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)fast_forward_ins, IARG_END);
    insert_analysis_functions(ins);
    INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)check_end_of_trace, IARG_END);
    INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)docount, IARG_UINT32, 1, IARG_END);
  });
}

/* ===================================================================== */
// Analysis routines — instruction trace
/* ===================================================================== */

void ResetCurrentInstruction(VOID* ip)
{
  // Step 1: If there is a pending allocation event, write it as an extra record
  // into the trace buffer BEFORE the current instruction. This preserves the
  // original instruction's IP and makes the allocation marker a no-op that
  // the tracereader will simply skip, without breaking the IP adjacency
  // needed for correct branch target computation (CALL → return address).
  if (pending_instr_malloc.type != 0 && !compat_mode) {
    trace_instr_format_t alloc_rec = {};
    alloc_rec.ip = (unsigned long long int)ip;
    alloc_rec.instr_type = 2;  // allocation event
    alloc_rec.instr_info = pending_instr_malloc.type;
    alloc_rec.source_memory[0] = pending_instr_malloc.arg1;
    alloc_rec.source_memory[1] = pending_instr_malloc.arg2;
    alloc_rec.destination_memory[0] = pending_instr_malloc.ret;
    alloc_rec.destination_memory[1] = pending_instr_malloc.caller_ip;
    trace_buffer.push(alloc_rec, outfile);
    pending_instr_malloc = {};  // consume the event
  }

  // Step 2: Record the current instruction normally (no longer overwritten
  // by allocation events). This ensures the instruction stream remains
  // contiguous and branch targets are computed correctly.
  curr_instr = {};
  curr_instr.ip = (unsigned long long int)ip;
}

void WriteCurrentInstruction()
{
  if (skip_dumping_instructions) return;

  trace_buffer.push(curr_instr, outfile);
}

void BranchOrNot(UINT32 taken)
{
  curr_instr.instr_type = 1;  // branch instruction
  curr_instr.instr_info = taken;
}

template <typename T>
void WriteToSet(T* begin, T* end, T r)
{
  auto set_end = std::find(begin, end, 0);
  // If the set is full (no zero slot found), do nothing
  if (set_end == end) return;
  auto found_reg = std::find(begin, set_end, r);
  *found_reg = r;
}

// =========================================================================
// Allocator analysis routines — from object_tracer v5
//
// Depth counter with saturation, thread-safe.
// Only the outermost user-level call writes records.
//
// Three modes:
//   compat_mode:         skip all allocation recording
//   embedded_alloc_mode: embed via pending_instr_malloc (then into instruction trace)
//   alloc_only_mode:     write 40-byte malloc_instr directly to outfile
// =========================================================================

/* Type name lookup for statistics display. */
static const char* malloc_type_name(unsigned char t)
{
  switch (t) {
    case 1:   return "malloc";
    case 2:   return "calloc";
    case 3:   return "realloc";
    case 4:   return "free";
    case 5:   return "mmap";
    case 6:   return "mmap64";
    case 7:   return "mremap";
    case 8:   return "munmap";
    case 9:   return "main-begin";
    case 10:  return "posix_memalign";
    case 11:  return "aligned_alloc";
    default:  return "UNKNOWN";
  }
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

// --- Stuck-depth auto-reset for mmap ---
static void try_auto_reset_mmap_depth(ThreadState* ts)
{
  if (ts->mmap_depth == 0) {
    ts->mmap_stuck_counter = 0;
    return;
  }
  ts->mmap_stuck_counter++;
  if (ts->mmap_stuck_counter >= MAX_STUCK) {
    // mmap_depth permanently stuck (glibc init loss) — force reset
    ts->mmap_depth = 0;
    ts->mmap_overflow = 0;
    ts->mmap_stuck_counter = 0;
  }
}

// =========================================================================
// Record helpers — forward declarations (defined later)
// =========================================================================
static void record_alloc_event(unsigned char coarse, unsigned long long arg1,
                               unsigned long long arg2, unsigned long long ret,
                               ADDRINT size_for_tracking, unsigned char coarse_for_tracking,
                               unsigned long long caller_ip);
static void record_free_event(unsigned long long ptr, unsigned long long caller_ip);

// =========================================================================
// Wrapper functions (RTN_ReplaceSignature) — from malloctrace methodology
//
// These functions replace the real_* functions at the instruction level,
// ensuring we capture the return value even when the function is optimized
// to not have a proper return instruction (e.g., tail-call optimized calloc).
// Depth tracking is maintained to suppress glibc-internal recursive calls.
// =========================================================================

// --- Helper: record an allocation event from a wrapper function ---
// Called inside NewMalloc, NewCalloc, NewRealloc, NewMmap, NewMremap, etc.
// Handles: compat_mode (skip), embedded_alloc_mode (pending_instr_malloc),
// alloc_only_mode (write 40-byte record), and tracked_addresses update.
static void wrapper_record_alloc(unsigned char mtype,
                                 unsigned long long arg1,
                                 unsigned long long arg2,
                                 ADDRINT ret,
                                 ADDRINT size_for_tracking,
                                 unsigned char coarse_for_tracking,
                                 ADDRINT caller_ip)
{
  if (compat_mode) return;
  if (ret == 0 || ret == (ADDRINT)-1) return;

  // In embedded_alloc mode, apply -k threshold filter
  if (embedded_alloc_mode && size_for_tracking < (ADDRINT)KnobMallocThreshold.Value())
    return;

  PIN_GetLock(&malloc_lock, PIN_ThreadId());
  record_alloc_event(mtype, arg1, arg2, (unsigned long long)ret,
                     size_for_tracking, coarse_for_tracking,
                     (unsigned long long)caller_ip);
  tracked_addresses.insert(ret);
  PIN_ReleaseLock(&malloc_lock);
}

// --- NEW MALLOC (type=1) ---
static void* NewMalloc(size_t size, ADDRINT caller_ip)
{
  ThreadState* ts = get_tls();
  try_auto_reset_depth(ts);

  // Inside a nested alloc call: pass through without recording
  if (ts->alloc_depth > 0) {
    if (ts->alloc_depth < MAX_DEPTH) ts->alloc_depth++;
    else ts->alloc_overflow++;
    return real_malloc(size);
  }

  // Outermost: track depth and call real function
  ts->alloc_depth = 1;
  void* ret = real_malloc(size);
  ts->alloc_depth = 0;

  wrapper_record_alloc(1, (unsigned long long)size, 0,
                       (ADDRINT)ret, (ADDRINT)size, 1, caller_ip);
  return ret;
}

// --- NEW CALLOC (type=2) ---
static void* NewCalloc(size_t nmemb, size_t elem_size, ADDRINT caller_ip)
{
  ThreadState* ts = get_tls();
  try_auto_reset_depth(ts);

  if (ts->alloc_depth > 0) {
    if (ts->alloc_depth < MAX_DEPTH) ts->alloc_depth++;
    else ts->alloc_overflow++;
    return real_calloc(nmemb, elem_size);
  }

  ts->alloc_depth = 1;
  void* ret = real_calloc(nmemb, elem_size);
  ts->alloc_depth = 0;

  wrapper_record_alloc(2, (unsigned long long)(nmemb * elem_size), 0,
                       (ADDRINT)ret, (ADDRINT)(nmemb * elem_size), 2, caller_ip);
  return ret;
}

// --- NEW REALLOC (type=3) ---
// Handles realloc(ptr, 0) → free(ptr) as type=4, realloc(NULL, size) → malloc(size),
// and normal realloc.
static void* NewRealloc(void* ptr, size_t new_size, ADDRINT caller_ip)
{
  ThreadState* ts = get_tls();
  try_auto_reset_depth(ts);

  if (ts->alloc_depth > 0) {
    if (ts->alloc_depth < MAX_DEPTH) ts->alloc_depth++;
    else ts->alloc_overflow++;
    return real_realloc(ptr, new_size);
  }

  ts->alloc_depth = 1;
  void* ret = real_realloc(ptr, new_size);
  ts->alloc_depth = 0;

  if (compat_mode) return ret;

  PIN_GetLock(&malloc_lock, PIN_ThreadId());

  ADDRINT old_ptr = (ADDRINT)ptr;

  if (new_size == 0 && old_ptr != 0) {
    // realloc(ptr, 0) = free(ptr) — record as free (type=4)
    tracked_allocations.erase(old_ptr);
    tracked_addresses.erase(old_ptr);
    record_free_event((unsigned long long)old_ptr, (unsigned long long)caller_ip);
  } else if (ret != nullptr && ret != (void*)-1) {
    // Successful realloc
    if (old_ptr != 0) {
      tracked_allocations.erase(old_ptr);
      tracked_addresses.erase(old_ptr);
    }
    // In embedded_alloc mode, apply -k threshold filter
    if (!embedded_alloc_mode || new_size >= KnobMallocThreshold.Value()) {
      record_alloc_event(3, (unsigned long long)old_ptr, (unsigned long long)new_size,
                         (unsigned long long)ret, (ADDRINT)new_size, 3,
                         (unsigned long long)caller_ip);
      tracked_addresses.insert((ADDRINT)ret);
    }
  }

  PIN_ReleaseLock(&malloc_lock);
  return ret;
}

// --- NEW FREE (type=4) — only free if address is tracked ---
static void NewFree(void* ptr, ADDRINT caller_ip)
{
  if (ptr == nullptr || compat_mode) {
    real_free(ptr);
    return;
  }

  PIN_GetLock(&malloc_lock, PIN_ThreadId());
  ADDRINT addr = (ADDRINT)ptr;
  auto it = tracked_addresses.find(addr);
  if (it != tracked_addresses.end()) {
    record_free_event((unsigned long long)addr, (unsigned long long)caller_ip);
    tracked_addresses.erase(it);
    tracked_allocations.erase(addr);
  }
  PIN_ReleaseLock(&malloc_lock);

  real_free(ptr);
}

// --- NEW MMAP (type=5) ---
static void* NewMmap(void* addr, size_t length, int prot, int flags, int fd, off_t offset, ADDRINT caller_ip)
{
  ThreadState* ts = get_tls();
  try_auto_reset_mmap_depth(ts);

  // Skip if we're inside a malloc/calloc/realloc — this mmap is an internal glibc detail
  if (ts->alloc_depth > 0) {
    return real_mmap(addr, length, prot, flags, fd, offset);
  }

  if (ts->mmap_depth > 0) {
    if (ts->mmap_depth < MAX_DEPTH) ts->mmap_depth++;
    else ts->mmap_overflow++;
    return real_mmap(addr, length, prot, flags, fd, offset);
  }

  ts->mmap_depth = 1;
  void* ret = real_mmap(addr, length, prot, flags, fd, offset);
  ts->mmap_depth = 0;

  if (ret != MAP_FAILED && !compat_mode) {
    // In embedded_alloc mode, apply -k threshold filter
    if (!embedded_alloc_mode || length >= KnobMallocThreshold.Value()) {
      PIN_GetLock(&malloc_lock, PIN_ThreadId());
      record_alloc_event(5, (unsigned long long)length, 0, (unsigned long long)ret,
                         (ADDRINT)length, 5, (unsigned long long)caller_ip);
      tracked_addresses.insert((ADDRINT)ret);
      PIN_ReleaseLock(&malloc_lock);
    }
  }
  return ret;
}

// --- NEW MMAP64 (type=6) ---
static void* NewMmap64(void* addr, size_t length, int prot, int flags, int fd, off_t offset, ADDRINT caller_ip)
{
  ThreadState* ts = get_tls();
  try_auto_reset_mmap_depth(ts);

  // Skip if we're inside a malloc/calloc/realloc
  if (ts->alloc_depth > 0) {
    return real_mmap(addr, length, prot, flags, fd, offset);
  }

  if (ts->mmap_depth > 0) {
    if (ts->mmap_depth < MAX_DEPTH) ts->mmap_depth++;
    else ts->mmap_overflow++;
    return real_mmap(addr, length, prot, flags, fd, offset);
  }

  ts->mmap_depth = 1;
  void* ret = real_mmap(addr, length, prot, flags, fd, offset);
  ts->mmap_depth = 0;

  if (ret != MAP_FAILED && !compat_mode) {
    // In embedded_alloc mode, apply -k threshold filter
    if (!embedded_alloc_mode || length >= KnobMallocThreshold.Value()) {
      PIN_GetLock(&malloc_lock, PIN_ThreadId());
      record_alloc_event(6, (unsigned long long)length, 0, (unsigned long long)ret,
                         (ADDRINT)length, 6, (unsigned long long)caller_ip);
      tracked_addresses.insert((ADDRINT)ret);
      PIN_ReleaseLock(&malloc_lock);
    }
  }
  return ret;
}

// --- NEW MREMAP (type=7) ---
static void* NewMremap(void* old_addr, size_t old_size, size_t new_size, int flags, void* new_addr, ADDRINT caller_ip)
{
  ThreadState* ts = get_tls();
  try_auto_reset_mmap_depth(ts);

  // Skip if we're inside a malloc/calloc/realloc
  if (ts->alloc_depth > 0) {
    return real_mremap(old_addr, old_size, new_size, flags, new_addr);
  }

  if (ts->mmap_depth > 0) {
    if (ts->mmap_depth < MAX_DEPTH) ts->mmap_depth++;
    else ts->mmap_overflow++;
    return real_mremap(old_addr, old_size, new_size, flags, new_addr);
  }

  ts->mmap_depth = 1;
  void* ret = real_mremap(old_addr, old_size, new_size, flags, new_addr);
  ts->mmap_depth = 0;

  if (ret != MAP_FAILED && !compat_mode) {
    // In embedded_alloc mode, apply -k threshold filter
    if (!embedded_alloc_mode || new_size >= KnobMallocThreshold.Value()) {
      PIN_GetLock(&malloc_lock, PIN_ThreadId());
      record_alloc_event(7, (unsigned long long)old_addr, (unsigned long long)old_size,
                         (unsigned long long)ret, (ADDRINT)new_size, 7,
                         (unsigned long long)caller_ip);
      tracked_addresses.insert((ADDRINT)ret);
      if ((ADDRINT)old_addr != 0) {
        tracked_addresses.erase((ADDRINT)old_addr);
        tracked_allocations.erase((ADDRINT)old_addr);
      }
      PIN_ReleaseLock(&malloc_lock);
    }
  }
  return ret;
}

// --- NEW MUNMAP (type=8) — only record if address is tracked ---
static int NewMunmap(void* addr, size_t length, ADDRINT caller_ip)
{
  if (addr == nullptr || addr == (void*)-1 || compat_mode) {
    return real_munmap(addr, length);
  }

  PIN_GetLock(&malloc_lock, PIN_ThreadId());
  ADDRINT a = (ADDRINT)addr;
  auto it = tracked_addresses.find(a);
  if (it != tracked_addresses.end()) {
    record_alloc_event(8, (unsigned long long)a, (unsigned long long)length, 0, 0, 8, (unsigned long long)caller_ip);
    tracked_addresses.erase(it);
  }
  PIN_ReleaseLock(&malloc_lock);

  return real_munmap(addr, length);
}

// --- NEW POSIX_MEMALIGN (type=10) ---
// posix_memalign cannot use a header due to alignment constraints,
// so we cannot do free tracking. We just record the allocation event.
static int NewPosixMemalign(void** memptr, size_t alignment, size_t size, ADDRINT caller_ip)
{
  if (compat_mode)
    return real_posix_memalign(memptr, alignment, size);

  int ret = real_posix_memalign(memptr, alignment, size);
  if (ret == 0 && *memptr != nullptr) {
    // In embedded_alloc mode, apply -k threshold filter
    if (!embedded_alloc_mode || size >= KnobMallocThreshold.Value()) {
      PIN_GetLock(&malloc_lock, PIN_ThreadId());
      record_alloc_event(10, (unsigned long long)size, (unsigned long long)alignment,
                         (unsigned long long)*memptr, (ADDRINT)size, 10,
                         (unsigned long long)caller_ip);
      tracked_addresses.insert((ADDRINT)*memptr);
      PIN_ReleaseLock(&malloc_lock);
    }
  }
  return ret;
}

// --- NEW ALIGNED_ALLOC (type=11) ---
// aligned_alloc cannot use a header due to alignment constraints,
// so we cannot do free tracking. We just record the allocation event.
static void* NewAlignedAlloc(size_t alignment, size_t size, ADDRINT caller_ip)
{
  if (compat_mode)
    return real_aligned_alloc(alignment, size);

  void* ret = real_aligned_alloc(alignment, size);
  if (ret != nullptr) {
    // In embedded_alloc mode, apply -k threshold filter
    if (!embedded_alloc_mode || size >= KnobMallocThreshold.Value()) {
      PIN_GetLock(&malloc_lock, PIN_ThreadId());
      record_alloc_event(11, (unsigned long long)size, (unsigned long long)alignment,
                         (unsigned long long)ret, (ADDRINT)size, 11,
                         (unsigned long long)caller_ip);
      tracked_addresses.insert((ADDRINT)ret);
      PIN_ReleaseLock(&malloc_lock);
    }
  }
  return ret;
}

// =========================================================================
// Record helpers — embed or write allocation/free events
//
// record_alloc_event / record_free_event:
//   In embedded_alloc_mode → set pending_instr_malloc (consumed by ResetCurrentInstruction).
//   In alloc_only_mode     → write 40-byte malloc_instr directly.
//   In compat_mode         → no-op (events not recorded).
// =========================================================================

// Helper: record an allocation event
// Note: caller_ip is stored in the 40-byte malloc_instr for analysis purposes
static void record_alloc_event(unsigned char coarse, unsigned long long arg1,
                               unsigned long long arg2, unsigned long long ret,
                               ADDRINT size_for_tracking, unsigned char coarse_for_tracking,
                               unsigned long long caller_ip)
{
  if (embedded_alloc_mode) {
    pending_instr_malloc.type = coarse;
    pending_instr_malloc.arg1 = arg1;
    pending_instr_malloc.arg2 = arg2;
    pending_instr_malloc.ret = ret;
    pending_instr_malloc.caller_ip = caller_ip;
  } else if (alloc_only_mode) {
    write_alloc_record_locked(coarse, arg1, arg2, ret, caller_ip);
  }
  if (!compat_mode && ret != 0 && ret != (ADDRINT)-1) {
    tracked_allocations[ret] = {size_for_tracking, coarse_for_tracking, static_cast<ADDRINT>(caller_ip)};
  }
}

// Helper: record a free event
static void record_free_event(unsigned long long ptr, unsigned long long caller_ip)
{
  if (embedded_alloc_mode) {
    pending_instr_malloc.type = 4;
    pending_instr_malloc.arg1 = ptr;
    pending_instr_malloc.arg2 = 0;
    pending_instr_malloc.ret = 0;
    pending_instr_malloc.caller_ip = caller_ip;
  } else if (alloc_only_mode) {
    write_alloc_record_locked(4, ptr, 0, 0, caller_ip);
  }
}

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
// ImageLoad — RTN_ReplaceSignature (from malloctrace methodology)
//
// Uses RTN_ReplaceSignature to replace all malloc/calloc/realloc/free/
// mmap/mmap64/mremap/munmap with wrapper functions that capture return
// values directly, avoiding IPOINT_AFTER issues with optimized functions.
// ===================================================================== */
VOID ImageLoad(IMG img, VOID* v)
{
  if (!IMG_Valid(img)) return;

  RTN rtn;

  // --- MALLOC (type=1) ---
  for (const char* name : {"malloc", "__libc_malloc"}) {
    if (real_malloc != nullptr) break;
    rtn = RTN_FindByName(img, name);
    if (RTN_Valid(rtn)) {
      real_malloc = (void* (*)(size_t))RTN_Funptr(rtn);
      RTN_ReplaceSignature(rtn, (AFUNPTR)NewMalloc,
                           IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
                           IARG_RETURN_IP,
                           IARG_END);
      break;
    }
  }

  // --- CALLOC (type=2) ---
  for (const char* name : {"calloc", "__libc_calloc", "__calloc"}) {
    if (real_calloc != nullptr) break;
    rtn = RTN_FindByName(img, name);
    if (RTN_Valid(rtn)) {
      real_calloc = (void* (*)(size_t, size_t))RTN_Funptr(rtn);
      RTN_ReplaceSignature(rtn, (AFUNPTR)NewCalloc,
                           IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
                           IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
                           IARG_RETURN_IP,
                           IARG_END);
      break;
    }
  }

  // --- REALLOC (type=3) ---
  for (const char* name : {"realloc", "__libc_realloc"}) {
    if (real_realloc != nullptr) break;
    rtn = RTN_FindByName(img, name);
    if (RTN_Valid(rtn)) {
      real_realloc = (void* (*)(void*, size_t))RTN_Funptr(rtn);
      RTN_ReplaceSignature(rtn, (AFUNPTR)NewRealloc,
                           IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
                           IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
                           IARG_RETURN_IP,
                           IARG_END);
      break;
    }
  }

  // --- FREE (type=4) ---
  for (const char* name : {"free", "__libc_free"}) {
    if (real_free != nullptr) break;
    rtn = RTN_FindByName(img, name);
    if (RTN_Valid(rtn)) {
      real_free = (void (*)(void*))RTN_Funptr(rtn);
      RTN_ReplaceSignature(rtn, (AFUNPTR)NewFree,
                           IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
                           IARG_RETURN_IP,
                           IARG_END);
      break;
    }
  }

  // --- MMAP (type=5) ---
  for (const char* name : {"mmap", "__libc_mmap"}) {
    if (real_mmap != nullptr) break;
    rtn = RTN_FindByName(img, name);
    if (RTN_Valid(rtn)) {
      real_mmap = (void* (*)(void*, size_t, int, int, int, off_t))RTN_Funptr(rtn);
      RTN_ReplaceSignature(rtn, (AFUNPTR)NewMmap,
                           IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
                           IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
                           IARG_FUNCARG_ENTRYPOINT_VALUE, 2,
                           IARG_FUNCARG_ENTRYPOINT_VALUE, 3,
                           IARG_FUNCARG_ENTRYPOINT_VALUE, 4,
                           IARG_FUNCARG_ENTRYPOINT_VALUE, 5,
                           IARG_RETURN_IP,
                           IARG_END);
      break;
    }
  }

  // --- MMAP64 (type=6) ---
  // Note: mmap64 uses the same real_mmap pointer (signature compatible)
  for (const char* name : {"mmap64", "__libc_mmap64"}) {
    if (real_mmap != nullptr) break;
    rtn = RTN_FindByName(img, name);
    if (RTN_Valid(rtn)) {
      real_mmap = (void* (*)(void*, size_t, int, int, int, off_t))RTN_Funptr(rtn);
      RTN_ReplaceSignature(rtn, (AFUNPTR)NewMmap64,
                           IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
                           IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
                           IARG_FUNCARG_ENTRYPOINT_VALUE, 2,
                           IARG_FUNCARG_ENTRYPOINT_VALUE, 3,
                           IARG_FUNCARG_ENTRYPOINT_VALUE, 4,
                           IARG_FUNCARG_ENTRYPOINT_VALUE, 5,
                           IARG_RETURN_IP,
                           IARG_END);
      break;
    }
  }

  // --- MREMAP (type=7) ---
  for (const char* name : {"mremap", "__libc_mremap"}) {
    if (real_mremap != nullptr) break;
    rtn = RTN_FindByName(img, name);
    if (RTN_Valid(rtn)) {
      real_mremap = (void* (*)(void*, size_t, size_t, int, ...))RTN_Funptr(rtn);
      RTN_ReplaceSignature(rtn, (AFUNPTR)NewMremap,
                           IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
                           IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
                           IARG_FUNCARG_ENTRYPOINT_VALUE, 2,
                           IARG_FUNCARG_ENTRYPOINT_VALUE, 3,
                           IARG_FUNCARG_ENTRYPOINT_VALUE, 4,
                           IARG_RETURN_IP,
                           IARG_END);
      break;
    }
  }

  // --- POSIX_MEMALIGN (type=10) ---
  for (const char* name : {"posix_memalign", "__libc_posix_memalign"}) {
    if (real_posix_memalign != nullptr) break;
    rtn = RTN_FindByName(img, name);
    if (RTN_Valid(rtn)) {
      real_posix_memalign = (int (*)(void**, size_t, size_t))RTN_Funptr(rtn);
      RTN_ReplaceSignature(rtn, (AFUNPTR)NewPosixMemalign,
                           IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
                           IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
                           IARG_FUNCARG_ENTRYPOINT_VALUE, 2,
                           IARG_RETURN_IP,
                           IARG_END);
      break;
    }
  }

  // --- ALIGNED_ALLOC (type=11) ---
  for (const char* name : {"aligned_alloc", "__libc_aligned_alloc"}) {
    if (real_aligned_alloc != nullptr) break;
    rtn = RTN_FindByName(img, name);
    if (RTN_Valid(rtn)) {
      real_aligned_alloc = (void* (*)(size_t, size_t))RTN_Funptr(rtn);
      RTN_ReplaceSignature(rtn, (AFUNPTR)NewAlignedAlloc,
                           IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
                           IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
                           IARG_RETURN_IP,
                           IARG_END);
      break;
    }
  }

  // --- MUNMAP (type=8) ---
  for (const char* name : {"munmap", "__libc_munmap"}) {
    if (real_munmap != nullptr) break;
    rtn = RTN_FindByName(img, name);
    if (RTN_Valid(rtn)) {
      real_munmap = (int (*)(void*, size_t))RTN_Funptr(rtn);
      RTN_ReplaceSignature(rtn, (AFUNPTR)NewMunmap,
                           IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
                           IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
                           IARG_RETURN_IP,
                           IARG_END);
      break;
    }
  }

  // Reset depth at entry point
  for (const char* entry : {"main", "MAIN__", "main_"}) {
    rtn = RTN_FindByName(img, entry);
    if (RTN_Valid(rtn)) {
      RTN_Open(rtn);
      RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)ResetDepthOnMain, IARG_END);
      RTN_Close(rtn);
    }
  }

  std::cout << "[ChampSim Tracer] Instrumented: " << IMG_Name(img) << std::endl;
}

// --- Reset depth counters at program entry (after glibc init) ---
// Also emits a type=9 marker record so analyzers know main() has started.
VOID ResetDepthOnMain()
{
  ThreadState* ts = get_tls();
  ts->alloc_depth = 0;
  ts->alloc_overflow = 0;
  ts->mmap_depth = 0;
  ts->mmap_overflow = 0;

  // Emit a main-begin marker (type=9) into the trace
  if (alloc_only_mode) {
    write_alloc_record_locked(9, 0, 0, 0, 0);
  } else if (embedded_alloc_mode) {
    pending_instr_malloc.type = 9;
    pending_instr_malloc.arg1 = 0;
    pending_instr_malloc.arg2 = 0;
    pending_instr_malloc.ret = 0;
    pending_instr_malloc.caller_ip = 0;
  }
  // compat_mode: no allocation event support, skip marker
}

/* ===================================================================== */
VOID Fini(INT32 code, VOID* v)
{
  if (outfile.is_open()) {
    trace_buffer.flush(outfile);
    outfile.close();
  }

  if (instruction_count_mode) {
    std::cout << "[ChampSim Tracer] Total instruction count: " << total_instruction_count << std::endl;
  } else if (compat_mode) {
    std::cout << "[ChampSim Tracer] Compat mode trace saved.\n";
  } else if (alloc_only_mode) {
    std::cout << "\n[ChampSim Tracer] === Alloc-only Mode Statistics ===" << std::endl;
    unsigned long long total = 0;
    for (const auto& [t, count] : type_counts) {
      std::cout << "  type " << (int)t << " (" << malloc_type_name(t) << "): " << count << std::endl;
      total += count;
    }
    std::cout << "  TOTAL: " << total << " allocation records" << std::endl;
    std::cout << "  Active tracked addresses: " << tracked_addresses.size() << std::endl;
  } else {
    std::cout << "[ChampSim Tracer] Embedded alloc trace saved. Active tracked: " << tracked_allocations.size() << std::endl;
  }
}

/* ===================================================================== */
// SDE/PinPlay argument filter
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
  // Scan argv for -m, -a, -f, and other flags before PIN_Init
  std::vector<char*> filtered;
  std::string alloc_only_filename;
  bool has_m_flag = false;
  bool has_a_flag = false;

  for (int i = 0; i < argc; i++) {
    std::string arg(argv[i]);
    if (is_pinplay_arg(arg)) {
      if (arg.find('=') == std::string::npos && i + 1 < argc &&
          argv[i+1][0] != '-') i++;
      continue;
    }
    if (arg == "-m") {
      has_m_flag = true;
      continue;  // do not pass -m to PIN_Init
    }
    if (arg == "-a") {
      has_a_flag = true;
      // -a takes a filename
      if (i + 1 < argc && argv[i+1][0] != '-') {
        alloc_only_filename = argv[++i];
      } else {
        std::cerr << "Error: -a requires a filename argument" << std::endl;
        return Usage();
      }
      continue;  // do not pass -a to PIN_Init
    }
    if (arg == "-f") {
      instruction_count_mode = true;
      continue;  // do not pass -f to PIN_Init
    }
    filtered.push_back(argv[i]);
  }

  // Determine mode
  if (instruction_count_mode) {
    // -f mode must be exclusive.
    // -m and -a are detected pre-PIN_Init; other options are checked post-PIN_Init via Knob values.
    if (has_m_flag || has_a_flag) {
      std::cerr << "[ChampSim Tracer] ERROR: -f mode is incompatible with -m or -a." << std::endl;
      std::cerr << "  Please use -f alone without any other options." << std::endl;
      exit(1);
    }
    compat_mode = false;
    embedded_alloc_mode = false;
    alloc_only_mode = false;
  } else if (has_m_flag && has_a_flag) {
    alloc_only_mode = true;
    embedded_alloc_mode = false;
    compat_mode = false;
  } else if (has_m_flag && !has_a_flag) {
    embedded_alloc_mode = true;
    alloc_only_mode = false;
    compat_mode = false;
  } else {
    compat_mode = true;
    embedded_alloc_mode = false;
    alloc_only_mode = false;
  }

  PIN_InitSymbols();

  if (PIN_Init((int)filtered.size(), filtered.data()))
    return Usage();

  PIN_InitLock(&malloc_lock);
  PIN_InitLock(&stats_lock);
  tls_key = PIN_CreateThreadDataKey(ThreadCleanup);

  if (instruction_count_mode) {
    // --- Instruction count mode (-f) ---
    // Count total instructions executed by the program.
    // No output file, no allocation tracing — just a counter.
    // Check for incompatible options via Knob values (check after PIN_Init so Knobs are parsed)
    if (KnobOutputFile.Value() != "champsim.trace" ||
        KnobFastForward.Value() != 0 ||
        KnobTraceLen.Value() != 0 ||
        KnobMallocThreshold.Value() != 256 ||
        !KnobConfigFile.Value().empty()) {
      std::cerr << "[ChampSim Tracer] ERROR: -f mode is incompatible with all other options "
                << "(-o, -s, -t, -k, -c)." << std::endl;
      std::cerr << "  Please use -f alone without any other options." << std::endl;
      exit(1);
    }
    std::cout << "[ChampSim Tracer] Instruction count mode (-f): counting total instructions only." << std::endl;

    TRACE_AddInstrumentFunction(insert_count_instrumentation, 0);
    PIN_AddFiniFunction(Fini, 0);
    PIN_StartProgram();
    return 0;
  }

  if (alloc_only_mode) {
    // --- Alloc-only mode (-m -a <file>) ---
    // Check for incompatible options
    if (KnobOutputFile.Value() != "champsim.trace" ||
        KnobFastForward.Value() != 0 ||
        KnobTraceLen.Value() != 0 ||
        KnobMallocThreshold.Value() != 256 ||
        !KnobConfigFile.Value().empty()) {
      std::cerr << "[ChampSim Tracer] ERROR: Alloc-only mode (-m -a) is incompatible with "
                << "-o, -s, -t, -k, and -c options." << std::endl;
      std::cerr << "  These options are ignored in alloc-only mode. Please remove them." << std::endl;
      exit(1);
    }

    outfile.open(alloc_only_filename.c_str(), std::ios_base::binary | std::ios_base::trunc);
    if (!outfile) {
      std::cout << "Error: Cannot open output file: " << alloc_only_filename << std::endl;
      exit(1);
    }
    std::cout << "[ChampSim Tracer] Alloc-only mode. Output: " << alloc_only_filename << std::endl;
    std::cout << "[ChampSim Tracer] Only allocation events will be recorded (no instruction trace).\n";

    IMG_AddInstrumentFunction(ImageLoad, 0);
    PIN_AddFiniFunction(Fini, 0);
    PIN_StartProgram();
    return 0;
  }

  if (embedded_alloc_mode) {
    // --- Embedded alloc mode (-m, no -a) ---
    outfile.open(KnobOutputFile.Value().c_str(), std::ios_base::binary | std::ios_base::trunc);
    if (!outfile) {
      std::cout << "Error: Cannot open output trace file: " << KnobOutputFile.Value() << std::endl;
      exit(1);
    }
    std::cout << "[ChampSim Tracer] Embedded alloc mode. Output: " << KnobOutputFile.Value() << std::endl;
    std::cout << "[ChampSim Tracer] Instruction trace with embedded allocation events.\n";

    // With -m, -s, -t, -c, -k still apply
    std::string config_path = KnobConfigFile.Value();
    if (!config_path.empty()) {
      parse_config(config_path);
      const auto& first = segments[0];
      fast_forward_insts_left = first.abs_skip;
      trace_insts_left = first.length;
      skip_dumping_instructions = (first.abs_skip > 0);
    } else {
      trace_insts_left = KnobTraceLen.Value();
      fast_forward_insts_left = KnobFastForward.Value();
    }

    TRACE_AddInstrumentFunction(insert_instrumentation, 0);
    IMG_AddInstrumentFunction(ImageLoad, 0);
    PIN_AddFiniFunction(Fini, 0);
    PIN_StartProgram();
    return 0;
  }

  // --- Compat mode (no -m, default) ---
  std::string config_path = KnobConfigFile.Value();

  if (!config_path.empty()) {
    parse_config(config_path);
    const auto& first = segments[0];

    outfile.open(first.output_file.c_str(), std::ios_base::binary | std::ios_base::trunc);
    if (!outfile) {
      std::cerr << "Couldn't open output trace file: " << first.output_file << std::endl;
      exit(1);
    }

    fast_forward_insts_left = first.abs_skip;
    trace_insts_left = first.length;
    skip_dumping_instructions = (first.abs_skip > 0);

    std::cout << "[ChampSim Tracer] Multi-segment mode: " << segments.size() << " segments" << std::endl;
    std::cout << "[ChampSim Tracer] Segment 0: skip=" << first.abs_skip
              << " trace=" << first.length
              << " output=" << first.output_file << std::endl;
  } else {
    trace_insts_left = KnobTraceLen.Value();
    fast_forward_insts_left = KnobFastForward.Value();

    outfile.open(KnobOutputFile.Value().c_str(), std::ios_base::binary | std::ios_base::trunc);
    if (!outfile) {
      std::cout << "Couldn't open output trace file. Exiting." << std::endl;
      exit(1);
    }
  }

  std::cout << "[ChampSim Tracer] Compat mode: instruction trace only, no allocation events.\n";

  TRACE_AddInstrumentFunction(insert_instrumentation, 0);
  // In compat mode, do NOT register ImageLoad — no allocator interception needed.
  // This avoids the runtime overhead of RTN_ReplaceSignature on malloc/calloc/realloc/free/mmap/etc.
  PIN_AddFiniFunction(Fini, 0);
  PIN_StartProgram();

  return 0;
}