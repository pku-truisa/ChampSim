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
 *  This is an example of the PIN tool that demonstrates some basic PIN APIs
 *  and could serve as the starting point for developing your first PIN tool
 */

#include <fstream>
#include <iostream>
#include <stdlib.h>
#include <string.h>
#include <string>
#include <unordered_set>
#include <map>

#include "../../inc/trace_instruction.h"
#include "pin.H"

using trace_instr_format_t = input_instr;

#ifndef MAP_ANONYMOUS
#define MAP_ANONYMOUS 0x20  // Linux x86_64 
#endif

/* ================================================================== */
// Global variables
/* ================================================================== */

UINT64 instrCount = 0;
std::ofstream outfile;
trace_instr_format_t curr_instr;
INT64 trace_insts_left = 0;
INT64 fast_forward_insts_left = 0;
bool skip_dumping_instructions = false;

// Binary malloc trace output
std::ofstream malloc_binfile;
std::unordered_set<ADDRINT> tracked_addresses;
ADDRINT pending_alloc_size = 0;
ADDRINT pending_alloc_memptr = 0; // for posix_memalign
ADDRINT pending_realloc_old_ptr = 0; // for realloc old pointer
int pending_alloc_type = 0; // 0: none, 1: malloc, 3: mmap, 5: calloc, 6: realloc, 7: aligned_alloc, 8: posix_memalign, 9: memalign
bool trace_limit_reached = false;
ADDRINT pending_alloc_ip = 0; // caller IP stored for After callbacks

// Malloc hook to prevent malloc/free reentrancy
bool in_allocator_hook = false;

// Small allocation accumulator (size < k, not written to binary stream)
struct LittleAllocAccum {
  uint64_t count = 0;
  uint64_t raw_total = 0;    // sum of original sizes
  uint64_t aligned_total = 0; // sum of next_power_of_2(sizes)
};
std::map<int, LittleAllocAccum> little_stats; // key = alloc_type

static uint64_t next_power_of_2_64(uint64_t n) {
  if (n == 0) return 0;
  n--;
  n |= n >> 1;
  n |= n >> 2;
  n |= n >> 4;
  n |= n >> 8;
  n |= n >> 16;
  n |= n >> 32;
  n++;
  return n;
}

// Prototype
VOID insert_analysis_functions(INS ins);

/* ===================================================================== */
// Command line switches
/* ===================================================================== */
KNOB<std::string> KnobOutputFile(KNOB_MODE_WRITEONCE, "pintool", "o", "champsim.trace", "specify file name for Champsim tracer output");

KNOB<UINT64> KnobFastForward(KNOB_MODE_WRITEONCE, "pintool", "s", "0", "How many instructions to fast-forward before tracing begins");

KNOB<UINT64> KnobTraceLen(KNOB_MODE_WRITEONCE, "pintool", "t", "0", "How many instructions to trace (0 for unlimited)");

KNOB<std::string> KnobMallocOutputFile(KNOB_MODE_WRITEONCE, "pintool", "m", "malloc.bin", "specify file name for binary malloc trace output");

KNOB<UINT64> KnobMallocSizeThreshold(KNOB_MODE_WRITEONCE, "pintool", "k", "64", "Minimum allocation size to trace to binary (bytes, objects smaller than this go to little_malloc.log)");

KNOB<BOOL> KnobAllocOnly(KNOB_MODE_WRITEONCE, "pintool", "a", "0", "Only generate memory allocation trace, skip instruction trace");

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
            << "Specify the binary malloc trace output file with -m (default: malloc.bin)" << std::endl
            << "Specify minimum allocation size to trace with -k (default: 64)" << std::endl
            << "Use -a to only generate memory allocation trace (skip instruction trace)" << std::endl
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

void fast_forward_ins()
{
  if (fast_forward_insts_left > 0) {
    fast_forward_insts_left -= 1;
    skip_dumping_instructions = true;
  } else if (skip_dumping_instructions) {
    std::cout << "Fast-forward finished, starting tracing\n";
    skip_dumping_instructions = false;
  }
}

void check_end_of_trace()
{
  if (trace_insts_left > 0) {
    trace_insts_left -= 1;
    if (trace_insts_left == 0) {
      trace_limit_reached = true;
      std::cout << "Reaching trace length limit, terminating early.\n";
      PIN_ExitApplication(0);
    }
  }
  // If trace_insts_left == 0 initially, it means unlimited tracing - don't decrement or exit
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
  // In allocation-only mode, skip all instruction-level instrumentation.
  // Malloc hooks (ImageLoad) work independently via PIN's RTN instrumentation.
  if (KnobAllocOnly.Value()) {
    return;
  }
  
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
// Binary malloc trace writing
/* ===================================================================== */

const char* alloc_type_name(int t) {
  switch (t) {
    case 1: return "malloc";
    case 2: return "free";
    case 3: return "app_mmap";
    case 4: return "app_munmap";
    case 5: return "calloc";
    case 6: return "realloc";
    case 7: return "aligned_alloc";
    case 8: return "posix_memalign";
    case 9: return "memalign";
    default: return "unknown";
  }
}

void write_malloc_instr(unsigned long long ip, unsigned char type,
                         unsigned long long arg1, unsigned long long arg2,
                         unsigned long long ret)
{
  if (!trace_limit_reached && malloc_binfile.is_open()) {
    malloc_instr rec;
    rec.ip = ip;
    rec.type = type;
    rec.arg1 = arg1;
    rec.arg2 = arg2;
    rec.ret = ret;
    for (int i = 0; i < 7; i++) rec.reserved[i] = 0;
    
    typename decltype(malloc_binfile)::char_type buf[sizeof(malloc_instr)];
    std::memcpy(buf, &rec, sizeof(malloc_instr));
    malloc_binfile.write(buf, sizeof(malloc_instr));
  }
}

void accumulate_little(int alloc_type, ADDRINT size) {
  auto& acc = little_stats[alloc_type];
  acc.count++;
  acc.raw_total += size;
  acc.aligned_total += next_power_of_2_64(size);
}

/* ===================================================================== */
// Analysis routines
/* ===================================================================== */

void ResetCurrentInstruction(VOID* ip)
{
  curr_instr = {};
  curr_instr.ip = (unsigned long long int)ip;
}

void WriteCurrentInstruction()
{
  if (KnobAllocOnly.Value()) {
    // In allocation-only mode, skip writing instruction trace
    return;
  }
  
  typename decltype(outfile)::char_type buf[sizeof(trace_instr_format_t)];
  std::memcpy(buf, &curr_instr, sizeof(trace_instr_format_t));
  outfile.write(buf, sizeof(trace_instr_format_t));
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
  auto found_reg = std::find(begin, set_end, r); // check to see if this register is already in the list
  *found_reg = r;
}

VOID MallocBefore(ADDRINT size, ADDRINT ip)
{
  if (trace_limit_reached) return;

  if (in_allocator_hook) return;
  in_allocator_hook = true;

  pending_alloc_size = size;
  pending_alloc_type = 1; // 1: malloc
  pending_alloc_ip = ip;

  if (size < KnobMallocSizeThreshold.Value()) {
    accumulate_little(1, size);
  }
  // NOTE: in_allocator_hook is cleared in MallocAfter
}

VOID CallocBefore(ADDRINT nmemb, ADDRINT size, ADDRINT ip)
{
  if (trace_limit_reached) return;
  if (in_allocator_hook) return;
  in_allocator_hook = true;

  ADDRINT total_size = nmemb * size;
  pending_alloc_size = total_size;
  pending_alloc_type = 5; // 5: calloc
  pending_alloc_ip = ip;

  if (total_size < KnobMallocSizeThreshold.Value()) {
    accumulate_little(5, total_size);
  }
  // NOTE: in_allocator_hook is cleared in MallocAfter
}

VOID ReallocBefore(ADDRINT ptr, ADDRINT size, ADDRINT ip)
{
  if (trace_limit_reached) return;
  if (in_allocator_hook) return;
  in_allocator_hook = true;

  pending_alloc_size = size;
  pending_alloc_type = 6; // 6: realloc
  pending_alloc_ip = ip;
  pending_realloc_old_ptr = ptr; // save old pointer for After callback

  if (size < KnobMallocSizeThreshold.Value()) {
    accumulate_little(6, size);
  }
  // NOTE: in_allocator_hook is cleared in MallocAfter
}

VOID AlignedAllocBefore(ADDRINT alignment, ADDRINT size, ADDRINT ip)
{
  if (trace_limit_reached) return;
  if (in_allocator_hook) return;
  in_allocator_hook = true;

  pending_alloc_size = size;
  pending_alloc_type = 7; // 7: aligned_alloc
  pending_alloc_ip = ip;

  if (size < KnobMallocSizeThreshold.Value()) {
    accumulate_little(7, size);
  }
  // NOTE: in_allocator_hook is cleared in MallocAfter
}

VOID MallocAfter(ADDRINT ret)
{
  if (pending_alloc_type == 0) return;

  // Handle different allocation types that use MallocAfter as the After callback
  bool is_valid_type = (pending_alloc_type == 1 || pending_alloc_type == 5 || 
                        pending_alloc_type == 6 || pending_alloc_type == 7);
  
  if (!is_valid_type) {
    pending_alloc_size = 0;
    pending_alloc_type = 0;
    in_allocator_hook = false;
    return;
  }

  // Write big allocations (>= threshold) to binary trace
  if (!trace_limit_reached && pending_alloc_size >= KnobMallocSizeThreshold.Value()) {
    if (pending_alloc_type == 6) {
      // realloc: arg1=old_ptr, arg2=new_size, ret=new_ptr (or 0 on failure)
      write_malloc_instr(pending_alloc_ip, 6, pending_realloc_old_ptr, pending_alloc_size, ret);
      if (ret != 0) {
        tracked_addresses.insert(ret);
        // Remove old pointer from tracking if different
        if (pending_realloc_old_ptr != 0 && pending_realloc_old_ptr != ret) {
          auto it = tracked_addresses.find(pending_realloc_old_ptr);
          if (it != tracked_addresses.end()) {
            tracked_addresses.erase(it);
          }
        }
      }
    } else if (ret != 0) {
      // Non-realloc: arg1=size, ret=allocated address
      write_malloc_instr(pending_alloc_ip, (unsigned char)pending_alloc_type, pending_alloc_size, 0, ret);
      tracked_addresses.insert(ret);
    }
  }

  pending_alloc_size = 0;
  pending_alloc_type = 0;
  pending_realloc_old_ptr = 0;
  in_allocator_hook = false;
}

VOID FreeBefore(ADDRINT ptr, ADDRINT ip)
{
  if (ptr == 0) return;

  if (in_allocator_hook) return;
  in_allocator_hook = true;

  auto it = tracked_addresses.find(ptr);
  if (it == tracked_addresses.end()) {
    in_allocator_hook = false;
    return;
  }

  // Write to binary trace
  write_malloc_instr((unsigned long long)ip, 2, (unsigned long long)ptr, 0, 0);
  tracked_addresses.erase(it);

  in_allocator_hook = false;
}

VOID PosixMemalignBefore(ADDRINT memptr, ADDRINT size, ADDRINT ip)
{
  if (trace_limit_reached) return;
  if (in_allocator_hook) return;
  in_allocator_hook = true;

  pending_alloc_size = size;
  pending_alloc_type = 8; // 8: posix_memalign
  pending_alloc_memptr = memptr; // save for After callback
  pending_alloc_ip = ip;

  if (size < KnobMallocSizeThreshold.Value()) {
    accumulate_little(8, size);
  }
  // NOTE: in_allocator_hook is cleared in PosixMemalignAfter
}

VOID PosixMemalignAfter(ADDRINT ret, ADDRINT ip)
{
  if (pending_alloc_type != 8) {
    in_allocator_hook = false;
    return;
  }

  // For posix_memalign, the return value is the error code (0 on success)
  // The actual pointer is stored in *memptr
  if (ret == 0 && pending_alloc_memptr != 0) {
    // Read the allocated address from memptr
    ADDRINT allocated_addr = 0;
    PIN_SafeCopy(&allocated_addr, (VOID*)pending_alloc_memptr, sizeof(ADDRINT));

    if (allocated_addr != 0 && pending_alloc_size >= KnobMallocSizeThreshold.Value()) {
      write_malloc_instr(pending_alloc_ip, 8, pending_alloc_size, 0, allocated_addr);
      tracked_addresses.insert(allocated_addr);
    }
  }

  pending_alloc_size = 0;
  pending_alloc_type = 0;
  pending_alloc_memptr = 0;
  in_allocator_hook = false;
}

VOID MmapBefore(ADDRINT length, ADDRINT flags, ADDRINT ip)
{
  if (trace_limit_reached) return;
  if (in_allocator_hook) return;
  in_allocator_hook = true;

  // Only track anonymous mappings (MAP_ANONYMOUS)
  if (!(flags & MAP_ANONYMOUS)) {
    in_allocator_hook = false;
    return;
  }

  pending_alloc_size = length;
  pending_alloc_type = 3; // 3: mmap
  pending_alloc_ip = ip;

  if (length < KnobMallocSizeThreshold.Value()) {
    accumulate_little(3, length);
  }
  // NOTE: in_allocator_hook is cleared in MmapAfter
}

VOID MmapAfter(ADDRINT ret)
{
  if (pending_alloc_type != 3) return;

  if (ret != 0 && ret != (ADDRINT)-1 && pending_alloc_size >= KnobMallocSizeThreshold.Value()) {
    write_malloc_instr(pending_alloc_ip, 3, pending_alloc_size, 0, ret);
    tracked_addresses.insert(ret);
  }

  pending_alloc_size = 0;
  pending_alloc_type = 0;
  in_allocator_hook = false;
}

VOID MunmapBefore(ADDRINT addr, ADDRINT length, ADDRINT ip)
{
  if (addr == 0 || addr == (ADDRINT)-1) return;
  
  if (in_allocator_hook) return;
  in_allocator_hook = true;

  auto it = tracked_addresses.find(addr);
  if (it == tracked_addresses.end()) {
    in_allocator_hook = false;
    return;
  }

  write_malloc_instr((unsigned long long)ip, 4, (unsigned long long)addr, (unsigned long long)length, 0);
  tracked_addresses.erase(it);

  in_allocator_hook = false;
}

/* ===================================================================== */
// Instrumentation callbacks
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

VOID ImageLoad(IMG img, VOID* v)
{
  RTN rtn = RTN_FindByName(img, "malloc");
  if (!RTN_Valid(rtn)) {
    rtn = RTN_FindByName(img, "__libc_malloc");
  }
  if (RTN_Valid(rtn)) {
    RTN_Open(rtn);
    RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)MallocBefore, IARG_FUNCARG_ENTRYPOINT_VALUE, 0, IARG_RETURN_IP, IARG_END);
    RTN_InsertCall(rtn, IPOINT_AFTER, (AFUNPTR)MallocAfter, IARG_FUNCRET_EXITPOINT_VALUE, IARG_END);
    RTN_Close(rtn);
  }

  // Hook calloc for all images
  rtn = RTN_FindByName(img, "calloc");
  if (RTN_Valid(rtn)) {
    RTN_Open(rtn);
    RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)CallocBefore, IARG_FUNCARG_ENTRYPOINT_VALUE, 0, IARG_FUNCARG_ENTRYPOINT_VALUE, 1, IARG_RETURN_IP, IARG_END);
    RTN_InsertCall(rtn, IPOINT_AFTER, (AFUNPTR)MallocAfter, IARG_FUNCRET_EXITPOINT_VALUE, IARG_END);
    RTN_Close(rtn);
  }

  // Hook realloc for all images
  rtn = RTN_FindByName(img, "realloc");
  if (RTN_Valid(rtn)) {
    RTN_Open(rtn);
    RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)ReallocBefore, IARG_FUNCARG_ENTRYPOINT_VALUE, 0, IARG_FUNCARG_ENTRYPOINT_VALUE, 1, IARG_RETURN_IP, IARG_END);
    RTN_InsertCall(rtn, IPOINT_AFTER, (AFUNPTR)MallocAfter, IARG_FUNCRET_EXITPOINT_VALUE, IARG_END);
    RTN_Close(rtn);
  }

  // Hook aligned_alloc for all images (C11 standard)
  rtn = RTN_FindByName(img, "aligned_alloc");
  if (RTN_Valid(rtn)) {
    RTN_Open(rtn);
    RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)AlignedAllocBefore, IARG_FUNCARG_ENTRYPOINT_VALUE, 0, IARG_FUNCARG_ENTRYPOINT_VALUE, 1, IARG_RETURN_IP, IARG_END);
    RTN_InsertCall(rtn, IPOINT_AFTER, (AFUNPTR)MallocAfter, IARG_FUNCRET_EXITPOINT_VALUE, IARG_END);
    RTN_Close(rtn);
  }

  // Note: memalign() in current glibc is implemented as a wrapper around aligned_alloc(),
  // so we intentionally do NOT hook it. All memalign calls will be captured as aligned_alloc.

  // Hook posix_memalign for all images (POSIX standard)
  rtn = RTN_FindByName(img, "posix_memalign");
  if (RTN_Valid(rtn)) {
    RTN_Open(rtn);
    RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)PosixMemalignBefore, IARG_FUNCARG_ENTRYPOINT_VALUE, 0, IARG_FUNCARG_ENTRYPOINT_VALUE, 2, IARG_RETURN_IP, IARG_END);
    RTN_InsertCall(rtn, IPOINT_AFTER, (AFUNPTR)PosixMemalignAfter, IARG_FUNCRET_EXITPOINT_VALUE, IARG_RETURN_IP, IARG_END);
    RTN_Close(rtn);
  }

  // Hook free for all images
  rtn = RTN_FindByName(img, "free");
  if (!RTN_Valid(rtn)) {
    rtn = RTN_FindByName(img, "__libc_free");
  }
  if (RTN_Valid(rtn)) {
    RTN_Open(rtn);
    RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)FreeBefore, IARG_FUNCARG_ENTRYPOINT_VALUE, 0, IARG_RETURN_IP, IARG_END);
    RTN_Close(rtn);
  }

  // Hook mmap/mmap64/munmap for all images (not just main executable)
  // This allows tracking direct mmap calls from shared libraries
  rtn = RTN_FindByName(img, "mmap");
  if (RTN_Valid(rtn)) {
    RTN_Open(rtn);
    RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)MmapBefore, IARG_FUNCARG_ENTRYPOINT_VALUE, 1, IARG_FUNCARG_ENTRYPOINT_VALUE, 3, IARG_RETURN_IP, IARG_END);
    RTN_InsertCall(rtn, IPOINT_AFTER, (AFUNPTR)MmapAfter, IARG_FUNCRET_EXITPOINT_VALUE, IARG_END);
    RTN_Close(rtn);
  }

  rtn = RTN_FindByName(img, "mmap64");
  if (RTN_Valid(rtn)) {
    RTN_Open(rtn);
    RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)MmapBefore, IARG_FUNCARG_ENTRYPOINT_VALUE, 1, IARG_FUNCARG_ENTRYPOINT_VALUE, 3, IARG_RETURN_IP, IARG_END);
    RTN_InsertCall(rtn, IPOINT_AFTER, (AFUNPTR)MmapAfter, IARG_FUNCRET_EXITPOINT_VALUE, IARG_END);
    RTN_Close(rtn);
  }

  rtn = RTN_FindByName(img, "munmap");
  if (RTN_Valid(rtn)) {
    RTN_Open(rtn);
    RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)MunmapBefore, IARG_FUNCARG_ENTRYPOINT_VALUE, 0, IARG_FUNCARG_ENTRYPOINT_VALUE, 1, IARG_RETURN_IP, IARG_END);
    RTN_Close(rtn);
  }
}

/*!
 * Print out analysis results.
 * This function is called when the application exits.
 * @param[in]   code            exit code of the application
 * @param[in]   v               value specified by the tool in the
 *                              PIN_AddFiniFunction function call
 */
VOID Fini(INT32 code, VOID* v) { 
  if (outfile.is_open()) {
    outfile.close();
  }

  // Write header + little allocation stats as type=255/0 records embedded in malloc.bin
  // Written directly to bypass write_malloc_instr's trace_limit_reached check
  if (malloc_binfile.is_open()) {
    // Header record: type=255, arg1=k_threshold
    {
      malloc_instr rec;
      rec.ip = 0;
      rec.type = 255;
      rec.arg1 = KnobMallocSizeThreshold.Value();
      rec.arg2 = 0;
      rec.ret = 0;
      for (int i = 0; i < 7; i++) rec.reserved[i] = 0;
      typename decltype(malloc_binfile)::char_type buf[sizeof(malloc_instr)];
      std::memcpy(buf, &rec, sizeof(malloc_instr));
      malloc_binfile.write(buf, sizeof(malloc_instr));
    }

    // Type=0 records: per-type small alloc stats
    // ip=alloc_type, arg1=count, arg2=raw_total, ret=aligned_total
    if (!little_stats.empty()) {
      int type_order[] = {1, 3, 5, 6, 7, 8};
      for (int t : type_order) {
        auto it = little_stats.find(t);
        if (it != little_stats.end()) {
          malloc_instr rec;
          rec.ip = t;                       // original alloc_type
          rec.type = 0;                     // metadata marker
          rec.arg1 = it->second.count;      // number of small allocs
          rec.arg2 = it->second.raw_total;  // sum of original sizes
          rec.ret = it->second.aligned_total; // sum of next_power_of_2(sizes)
          for (int i = 0; i < 7; i++) rec.reserved[i] = 0;

          typename decltype(malloc_binfile)::char_type buf[sizeof(malloc_instr)];
          std::memcpy(buf, &rec, sizeof(malloc_instr));
          malloc_binfile.write(buf, sizeof(malloc_instr));
        }
      }
    }
  }

  malloc_binfile.close();
}

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

  trace_insts_left = KnobTraceLen.Value();
  fast_forward_insts_left = KnobFastForward.Value();

  // Only open instruction trace file if not in allocation-only mode
  if (!KnobAllocOnly.Value()) {
    outfile.open(KnobOutputFile.Value().c_str(), std::ios_base::binary | std::ios_base::trunc);
    if (!outfile) {
      std::cout << "Couldn't open output trace file. Exiting." << std::endl;
      exit(1);
    }
  }

  // Open binary malloc trace output
  malloc_binfile.open(KnobMallocOutputFile.Value().c_str(), std::ios_base::binary | std::ios_base::trunc);
  if (!malloc_binfile) {
    std::cout << "Couldn't open binary malloc trace file. Exiting." << std::endl;
    exit(1);
  }

  TRACE_AddInstrumentFunction(insert_instrumentation, 0);

  IMG_AddInstrumentFunction(ImageLoad, 0);

  // Register function to be called when the application exits
  PIN_AddFiniFunction(Fini, 0);

  // Start the program, never returns
  PIN_StartProgram();

  return 0;
}