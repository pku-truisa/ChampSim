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
  ADDRINT caller_ip     = 0;   // return address (caller IP)
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
// Helper: write a 64-byte alloc-only record directly to outfile
/* ===================================================================== */
static void write_alloc_record_locked(unsigned char coarse_type,
                                      unsigned long long arg1,
                                      unsigned long long arg2,
                                      unsigned long long ret,
                                      unsigned long long caller_ip)
{
  trace_instr_format_t rec = {};
  rec.instr_type = 2;
  rec.instr_info = coarse_type;
  rec.source_memory[0] = arg1;
  rec.source_memory[1] = arg2;
  rec.destination_memory[0] = ret;
  rec.destination_memory[1] = caller_ip;
  trace_buffer.push(rec, outfile);
  PIN_GetLock(&stats_lock, PIN_ThreadId());
  type_counts[coarse_type]++;
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
            << "    Produces ONLY allocation events (64-byte input_instr records" << std::endl
            << "    with instr_type=2), no instruction trace." << std::endl
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
  if (alloc_only_mode) return;  // No instruction tracing in alloc-only mode

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

  // In compat mode, skip embedding allocation events into instructions
  if (compat_mode) {
    pending_instr_malloc = {};
    return;
  }

  // Embed pending malloc event into this instruction's trace record
  // (embedded_alloc_mode only)
  if (pending_instr_malloc.type != 0) {
    curr_instr.instr_type = 2;  // allocation event
    curr_instr.instr_info = pending_instr_malloc.type;
    curr_instr.source_memory[0] = pending_instr_malloc.arg1;
    curr_instr.source_memory[1] = pending_instr_malloc.arg2;
    curr_instr.destination_memory[0] = pending_instr_malloc.ret;
    curr_instr.destination_memory[1] = pending_instr_malloc.caller_ip;
    pending_instr_malloc = {};  // consume the event
  }
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
//
// Three modes:
//   compat_mode:         skip all allocation recording
//   embedded_alloc_mode: embed via pending_instr_malloc (then into instruction trace)
//   alloc_only_mode:     write 64-byte input_instr with instr_type=2 directly to outfile
// =========================================================================

/* Type name lookup for statistics display. */
static const char* malloc_type_name(unsigned char t)
{
  switch (t) {
    case 1:   return "malloc";
    case 2:   return "mi_malloc";
    case 3:   return "je_malloc";
    case 4:   return "tc_malloc";
    case 5:   return "_Znwm";
    case 6:   return "_Znam";
    case 7:   return "calloc";
    case 8:   return "mi_calloc";
    case 9:   return "je_calloc";
    case 10:  return "tc_calloc";
    case 11:  return "realloc";
    case 12:  return "mi_realloc";
    case 13:  return "je_realloc";
    case 14:  return "tc_realloc";
    case 15:  return "posix_memalign";
    case 16:  return "mmap";
    case 17:  return "munmap";
    case 18:  return "free";
    case 19:  return "mi_free";
    case 20:  return "je_free";
    case 21:  return "tc_free";
    case 22:  return "_ZdlPv";
    case 23:  return "_ZdaPv";
    default:  return "UNKNOWN";
  }
}

/* Map fine-grained type (1-23) to coarse type used by instruction trace instr_info field. */
static unsigned char coarse_type(unsigned char fine_type)
{
  if (fine_type >= 1 && fine_type <= 6)  return 1;  // malloc-like
  if (fine_type >= 7 && fine_type <= 10) return 5;  // calloc-like
  if (fine_type >= 11 && fine_type <= 14) return 6;  // realloc-like
  if (fine_type == 15)  return 8;  // posix_memalign
  if (fine_type == 16)  return 3;  // mmap
  if (fine_type == 17)  return 4;  // munmap
  if (fine_type >= 18 && fine_type <= 23) return 2;  // free-like
  return 0;
}

// --- Helper: outermost BEFORE for depth-protected alloc family ---
static bool depth_outermost_before(ThreadState* ts, int alloc_type,
                                   ADDRINT size, ADDRINT caller_ip, ADDRINT arg2 = 0)
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
  ts->pending = PendingAlloc{size, arg2, alloc_type, 0, caller_ip};
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

// --- MALLOC / C++ new (type=1-6) ---
VOID AllocBefore(ADDRINT size, UINT32 alloc_type, ADDRINT caller_ip)
{
  if (trace_limit_reached) return;
  ThreadState* ts = get_tls();
  try_auto_reset_depth(ts);
  depth_outermost_before(ts, (int)alloc_type, size, caller_ip);
}

// --- CALLOC (type=7-10) ---
VOID CallocBefore(ADDRINT nmemb, ADDRINT elem_size, UINT32 alloc_type, ADDRINT caller_ip)
{
  if (trace_limit_reached) return;
  ThreadState* ts = get_tls();
  try_auto_reset_depth(ts);
  depth_outermost_before(ts, (int)alloc_type, nmemb * elem_size, caller_ip);
}

// --- REALLOC (type=11-14) ---
VOID ReallocBefore(ADDRINT old_ptr, ADDRINT new_size, UINT32 alloc_type, ADDRINT caller_ip)
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
  ts->pending = PendingAlloc{old_ptr, new_size, (int)alloc_type, 0, caller_ip};
}

// Helper: record an allocation event (used by both embedded and alloc-only modes)
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
    tracked_allocations[ret] = {size_for_tracking, coarse_for_tracking};
  }
}

// Helper: record a free event
static void record_free_event(unsigned long long ptr, unsigned long long caller_ip)
{
  if (embedded_alloc_mode) {
    pending_instr_malloc.type = 2;
    pending_instr_malloc.arg1 = ptr;
    pending_instr_malloc.arg2 = 0;
    pending_instr_malloc.ret = 0;
    pending_instr_malloc.caller_ip = caller_ip;
  } else if (alloc_only_mode) {
    write_alloc_record_locked(2, ptr, 0, 0, caller_ip);
  }
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

  int alloc_type = ts->pending.type;
  bool is_realloc = (alloc_type >= 11 && alloc_type <= 14);

  if (is_realloc) {
    ADDRINT old_ptr  = ts->pending.size;
    ADDRINT new_size = ts->pending.arg2;

    // Erase old_ptr from tracking sets
    if (old_ptr != 0) {
      tracked_allocations.erase(old_ptr);
      tracked_addresses.erase(old_ptr);
    }

    if (compat_mode) {
      // Skip all allocation events in compat mode
    } else if (ret != 0 && ret != (ADDRINT)-1) {
      unsigned char coarse = coarse_type((unsigned char)alloc_type);
      record_alloc_event(coarse, old_ptr, new_size, ret, new_size, coarse, ts->pending.caller_ip);
      // Track the returned address
      tracked_addresses.insert(ret);
    }
  } else {
    // Non-realloc (malloc, calloc, etc.)
    if (ret != 0 && ret != (ADDRINT)-1) {
      if (compat_mode) {
        // Skip all allocation events in compat mode
      } else {
        unsigned char coarse = coarse_type((unsigned char)alloc_type);
        record_alloc_event(coarse, ts->pending.size, ts->pending.arg2, ret,
                           ts->pending.size, coarse, ts->pending.caller_ip);
        tracked_addresses.insert(ret);
      }
    }
  }

  PIN_ReleaseLock(&malloc_lock);
}

// --- POSIX_MEMALIGN (type=15) ---
VOID PosixMemalignBefore(ADDRINT memptr, ADDRINT alignment, ADDRINT size, ADDRINT caller_ip)
{
  if (trace_limit_reached) return;
  ThreadState* ts = get_tls();
  if (ts->alloc_depth > 0) {
    if (ts->alloc_depth < MAX_DEPTH) ts->alloc_depth++;
    else ts->alloc_overflow++;
    return;
  }
  ts->alloc_depth = 1;
  ts->pending = PendingAlloc{size, alignment, 15, memptr, 0};
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
      if (compat_mode) return;
      PIN_GetLock(&malloc_lock, PIN_ThreadId());
      record_alloc_event(8, ts->pending.size, ts->pending.arg2, real_addr,
                         ts->pending.size, 8, ts->pending.caller_ip);
      tracked_addresses.insert(real_addr);
      PIN_ReleaseLock(&malloc_lock);
    }
  }
}

// --- FREE (type=18-23) — only write if tracked (suppresses glibc-internal free) ---
VOID FreeBefore(ADDRINT ptr, UINT32 free_type, ADDRINT caller_ip)
{
  if (ptr == 0 || compat_mode) return;

  PIN_GetLock(&malloc_lock, PIN_ThreadId());

  auto it = tracked_addresses.find(ptr);
  if (it != tracked_addresses.end()) {
    record_free_event((unsigned long long)ptr, 0);
    tracked_addresses.erase(it);
  }

  PIN_ReleaseLock(&malloc_lock);
}

VOID FreeAfter() { /* no-op */ }

// --- MMAP (independent depth + saturation) ---
VOID MmapBefore(ADDRINT length, ADDRINT flags, ADDRINT caller_ip)
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

  if (ret != 0 && ret != (ADDRINT)-1) {
    if (compat_mode) return;
    PIN_GetLock(&malloc_lock, PIN_ThreadId());
      record_alloc_event(3, ts->mmap_pending_size, 0, ret,
                       ts->mmap_pending_size, 3, 0);
    tracked_addresses.insert(ret);
    PIN_ReleaseLock(&malloc_lock);
  }
}

// --- MUNMAP (type=17) — only write if tracked ---
VOID MunmapBefore(ADDRINT addr, ADDRINT length, ADDRINT caller_ip)
{
  if (addr == 0 || addr == (ADDRINT)-1 || compat_mode) return;

  PIN_GetLock(&malloc_lock, PIN_ThreadId());

  auto it = tracked_addresses.find(addr);
  if (it != tracked_addresses.end()) {
    if (embedded_alloc_mode) {
      pending_instr_malloc.type = 4;
      pending_instr_malloc.arg1 = (unsigned long long)addr;
      pending_instr_malloc.arg2 = (unsigned long long)length;
      pending_instr_malloc.ret = 0;
    } else if (alloc_only_mode) {
      write_alloc_record_locked(4, (unsigned long long)addr, (unsigned long long)length, 0, 0);
    }
    tracked_addresses.erase(it);
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

// Symbol hook table — per-symbol fine-grained type registration
struct SymbolHook {
  const char* name;
  unsigned char type;
  enum { MALLOC, CALLOC, REALLOC, FREE } family;
};

static const SymbolHook all_symbols[] = {
  {"malloc",     1,  SymbolHook::MALLOC},
  {"mi_malloc",  2,  SymbolHook::MALLOC},
  {"je_malloc",  3,  SymbolHook::MALLOC},
  {"tc_malloc",  4,  SymbolHook::MALLOC},
  {"_Znwm",      5,  SymbolHook::MALLOC},
  {"_Znam",      6,  SymbolHook::MALLOC},
  {"calloc",     7,  SymbolHook::CALLOC},
  {"mi_calloc",  8,  SymbolHook::CALLOC},
  {"je_calloc",  9,  SymbolHook::CALLOC},
  {"tc_calloc",  10, SymbolHook::CALLOC},
  {"realloc",    11, SymbolHook::REALLOC},
  {"mi_realloc", 12, SymbolHook::REALLOC},
  {"je_realloc", 13, SymbolHook::REALLOC},
  {"tc_realloc", 14, SymbolHook::REALLOC},
  {"free",       18, SymbolHook::FREE},
  {"mi_free",    19, SymbolHook::FREE},
  {"je_free",    20, SymbolHook::FREE},
  {"tc_free",    21, SymbolHook::FREE},
  {"_ZdlPv",     22, SymbolHook::FREE},
  {"_ZdaPv",     23, SymbolHook::FREE},
};

/* ===================================================================== */
// ImageLoad
/* ===================================================================== */
VOID ImageLoad(IMG img, VOID* v)
{
  if (!IMG_Valid(img)) return;

  RTN rtn;

  // posix_memalign
  rtn = RTN_FindByName(img, "posix_memalign");
  if (RTN_Valid(rtn)) {
    RTN_Open(rtn);
    RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)PosixMemalignBefore,
                   IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
                   IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
                   IARG_FUNCARG_ENTRYPOINT_VALUE, 2,
                   IARG_RETURN_IP,
                   IARG_END);
    RTN_InsertCall(rtn, IPOINT_AFTER, (AFUNPTR)PosixMemalignAfter,
                   IARG_FUNCRET_EXITPOINT_VALUE, IARG_END);
    RTN_Close(rtn);
  }

  // malloc/calloc/realloc/free
  for (const auto& sym : all_symbols) {
    rtn = RTN_FindByName(img, sym.name);
    if (!RTN_Valid(rtn)) continue;
    RTN_Open(rtn);
    switch (sym.family) {
      case SymbolHook::MALLOC:
        RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)AllocBefore,
                       IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
                       IARG_UINT32, sym.type,
                       IARG_RETURN_IP, IARG_END);
        RTN_InsertCall(rtn, IPOINT_AFTER, (AFUNPTR)AllocAfter,
                       IARG_FUNCRET_EXITPOINT_VALUE, IARG_END);
        break;
      case SymbolHook::CALLOC:
        RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)CallocBefore,
                       IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
                       IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
                       IARG_UINT32, sym.type,
                       IARG_RETURN_IP, IARG_END);
        RTN_InsertCall(rtn, IPOINT_AFTER, (AFUNPTR)AllocAfter,
                       IARG_FUNCRET_EXITPOINT_VALUE, IARG_END);
        break;
      case SymbolHook::REALLOC:
        RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)ReallocBefore,
                       IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
                       IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
                       IARG_UINT32, sym.type,
                       IARG_RETURN_IP, IARG_END);
        RTN_InsertCall(rtn, IPOINT_AFTER, (AFUNPTR)AllocAfter,
                       IARG_FUNCRET_EXITPOINT_VALUE, IARG_END);
        break;
      case SymbolHook::FREE:
        RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)FreeBefore,
                       IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
                       IARG_UINT32, sym.type,
                       IARG_RETURN_IP, IARG_END);
        RTN_InsertCall(rtn, IPOINT_AFTER, (AFUNPTR)FreeAfter, IARG_END);
        break;
    }
    RTN_Close(rtn);
  }

  // mmap
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

  // Reset depth at entry point
  for (const char* entry : {"main", "MAIN__", "main_"}) {
    rtn = RTN_FindByName(img, entry);
    if (RTN_Valid(rtn)) {
      RTN_Open(rtn);
      RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)ResetDepthOnMain, IARG_END);
      RTN_Close(rtn);
    }
  }

  // munmap
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

  if (compat_mode) {
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
  // Scan argv for -m and -a before PIN_Init
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
    filtered.push_back(argv[i]);
  }

  // Determine mode
  if (has_m_flag && has_a_flag) {
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
  IMG_AddInstrumentFunction(ImageLoad, 0);
  PIN_AddFiniFunction(Fini, 0);
  PIN_StartProgram();

  return 0;
}