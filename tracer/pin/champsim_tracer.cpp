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

std::ofstream malloc_outfile;
trace_instr_format_t event_instr;
std::unordered_set<ADDRINT> tracked_addresses;
ADDRINT pending_alloc_size = 0;
int pending_alloc_type = 0; // 0: none, 1: malloc, 3: mmap
bool trace_limit_reached = false;

// Malloc hook to prevent malloc/free reentrancy
bool in_allocator_hook = false;

// Prototype
VOID insert_analysis_functions(INS ins);

/* ===================================================================== */
// Command line switches
/* ===================================================================== */
KNOB<std::string> KnobOutputFile(KNOB_MODE_WRITEONCE, "pintool", "o", "champsim.trace", "specify file name for Champsim tracer output");

KNOB<UINT64> KnobFastForward(KNOB_MODE_WRITEONCE, "pintool", "s", "0", "How many instructions to fast-forward before tracing begins");

KNOB<UINT64> KnobTraceLen(KNOB_MODE_WRITEONCE, "pintool", "t", "0", "How many instructions to trace (0 for unlimited)");

KNOB<std::string> KnobMallocOutputFile(KNOB_MODE_WRITEONCE, "pintool", "m", "malloc.trace", "specify file name for malloc tracer output");

KNOB<UINT64> KnobMallocSizeThreshold(KNOB_MODE_WRITEONCE, "pintool", "k", "0", "Minimum allocation size to trace (bytes, 0 to trace all)");

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
            << "Specify the malloc text output file with -m" << std::endl
            << "Specify minimum allocation size to trace with -k (0 to trace all)" << std::endl
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
// Analysis routines
/* ===================================================================== */

void ResetCurrentInstruction(VOID* ip)
{
  curr_instr = {};
  curr_instr.ip = (unsigned long long int)ip;
}

void WriteCurrentInstruction()
{
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

void WriteEventInstruction()
{
  if (!trace_limit_reached && outfile.is_open()) {
    typename decltype(outfile)::char_type buf[sizeof(trace_instr_format_t)];
    std::memcpy(buf, &event_instr, sizeof(trace_instr_format_t));
    outfile.write(buf, sizeof(trace_instr_format_t));
  }
}

VOID MallocBefore(ADDRINT size, ADDRINT ip)
{
  if (trace_limit_reached) return;

  if (in_allocator_hook) return;
  in_allocator_hook = true;

  if (size < KnobMallocSizeThreshold.Value()) {
    pending_alloc_size = 0;
    pending_alloc_type = 0;
    in_allocator_hook = false;
    return;
  }

  pending_alloc_size = size;
  pending_alloc_type = 1; // 1: malloc

  event_instr = {};
  event_instr.ip = (unsigned long long int)ip;
  event_instr.is_malloc = 1;
}

VOID MallocAfter(ADDRINT ret)
{
  if (!in_allocator_hook || pending_alloc_type != 1) return;

  if (ret != 0 && !trace_limit_reached) {
    if (malloc_outfile.is_open()) {
      malloc_outfile << "malloc(" << std::dec << pending_alloc_size << ")=0x" << std::hex << ret << std::dec << std::endl;
    }

    event_instr.destination_memory[0] = ret;

    WriteEventInstruction();
    tracked_addresses.insert(ret);
  }

  pending_alloc_size = 0;
  pending_alloc_type = 0;
  in_allocator_hook = false;
}

VOID FreeBefore(ADDRINT ptr, ADDRINT ip)
{
  if (trace_limit_reached || ptr == 0) return;
  if (in_allocator_hook) return;
  in_allocator_hook = true;

  auto it = tracked_addresses.find(ptr);
  if (it == tracked_addresses.end()) {
    in_allocator_hook = false;
    return;
  }

  if (malloc_outfile.is_open()) {
    malloc_outfile << "free(0x" << std::hex << ptr << ")" << std::dec << std::endl;
  }

  event_instr = {};
  event_instr.ip = (unsigned long long int)ip;
  event_instr.is_malloc = 2; // 2: free
  event_instr.source_memory[0] = ptr;
  WriteEventInstruction();

  tracked_addresses.erase(it);
  in_allocator_hook = false;
}

VOID MmapBefore(ADDRINT length, ADDRINT flags, ADDRINT ip)
{
  if (trace_limit_reached) return;
  if (in_allocator_hook) return;
  in_allocator_hook = true;

  if (!(flags & MAP_ANONYMOUS) || length < KnobMallocSizeThreshold.Value()) {
    pending_alloc_size = 0;
    pending_alloc_type = 0;
    in_allocator_hook = false;
    return;
  }

  pending_alloc_size = length;
  pending_alloc_type = 3; // 3: mmap

  event_instr = {};
  event_instr.ip = (unsigned long long int)ip;
  event_instr.is_malloc = 3;
}

VOID MmapAfter(ADDRINT ret)
{
  if (!in_allocator_hook || pending_alloc_type != 3) return;

  if (ret != 0 && ret != (ADDRINT)-1 && !trace_limit_reached) {
    if (malloc_outfile.is_open()) {
      malloc_outfile << "app_mmap(" << std::dec << pending_alloc_size << ")=0x" << std::hex << ret << std::dec << std::endl;
    }

    event_instr.destination_memory[0] = ret;
//    event_instr.destination_memory[1] = ret + pending_alloc_size;

    WriteEventInstruction();
    tracked_addresses.insert(ret);
  }

  pending_alloc_size = 0;
  pending_alloc_type = 0;
  in_allocator_hook = false;
}

VOID MunmapBefore(ADDRINT addr, ADDRINT length, ADDRINT ip)
{
  if (trace_limit_reached || addr == 0 || addr == (ADDRINT)-1) return;
  if (in_allocator_hook) return;
  in_allocator_hook = true;

  auto it = tracked_addresses.find(addr);
  if (it == tracked_addresses.end()) {
    in_allocator_hook = false;
    return;
  }

  if (malloc_outfile.is_open()) {
    malloc_outfile << "app_munmap(0x" << std::hex << addr << ", " << std::dec << length << ")" << std::dec << std::endl;
  }

  event_instr = {};
  event_instr.ip = (unsigned long long int)ip;
  event_instr.is_malloc = 4; // 4: munmap
  event_instr.source_memory[0] = addr;
  event_instr.source_memory[1] = length;
  WriteEventInstruction();

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
  bool is_main_executable = IMG_IsMainExecutable(img);

  RTN rtn = RTN_FindByName(img, "malloc");
  if (!RTN_Valid(rtn)) {
    rtn = RTN_FindByName(img, "__libc_malloc");
  }
  if (RTN_Valid(rtn)) {
    RTN_Open(rtn);
    RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)MallocBefore, IARG_FUNCARG_ENTRYPOINT_VALUE, 0, IARG_INST_PTR, IARG_END);
    RTN_InsertCall(rtn, IPOINT_AFTER, (AFUNPTR)MallocAfter, IARG_FUNCRET_EXITPOINT_VALUE, IARG_END);
    RTN_Close(rtn);
  }

  rtn = RTN_FindByName(img, "free");
  if (!RTN_Valid(rtn)) {
    rtn = RTN_FindByName(img, "__libc_free");
  }
  if (RTN_Valid(rtn)) {
    RTN_Open(rtn);
    RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)FreeBefore, IARG_FUNCARG_ENTRYPOINT_VALUE, 0, IARG_INST_PTR, IARG_END);
    RTN_Close(rtn);
  }
  
  if (is_main_executable) {
    // If the main executable is statically linked, it might contain mmap/munmap implementations that we also want to hook.
    rtn = RTN_FindByName(img, "mmap");
    if (RTN_Valid(rtn)) {
      RTN_Open(rtn);
      RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)MmapBefore, IARG_FUNCARG_ENTRYPOINT_VALUE, 1, IARG_FUNCARG_ENTRYPOINT_VALUE, 3, IARG_INST_PTR, IARG_END);
      RTN_InsertCall(rtn, IPOINT_AFTER, (AFUNPTR)MmapAfter, IARG_FUNCRET_EXITPOINT_VALUE, IARG_END);
      RTN_Close(rtn);
    }

    rtn = RTN_FindByName(img, "mmap64");
    if (RTN_Valid(rtn)) {
      RTN_Open(rtn);
      RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)MmapBefore, IARG_FUNCARG_ENTRYPOINT_VALUE, 1, IARG_FUNCARG_ENTRYPOINT_VALUE, 3, IARG_INST_PTR, IARG_END);
      RTN_InsertCall(rtn, IPOINT_AFTER, (AFUNPTR)MmapAfter, IARG_FUNCRET_EXITPOINT_VALUE, IARG_END);
      RTN_Close(rtn);
    }

    rtn = RTN_FindByName(img, "munmap");
    if (RTN_Valid(rtn)) {
      RTN_Open(rtn);
      RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)MunmapBefore, IARG_FUNCARG_ENTRYPOINT_VALUE, 0, IARG_FUNCARG_ENTRYPOINT_VALUE, 1, IARG_INST_PTR, IARG_END);
      RTN_Close(rtn);
    }
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
  outfile.close();
  malloc_outfile.close();
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

  outfile.open(KnobOutputFile.Value().c_str(), std::ios_base::binary | std::ios_base::trunc);
  if (!outfile) {
    std::cout << "Couldn't open output trace file. Exiting." << std::endl;
    exit(1);
  }

  malloc_outfile.open(KnobMallocOutputFile.Value().c_str(), std::ios_base::out);
  if (!malloc_outfile) {
    std::cout << "Couldn't open malloc trace file. Exiting." << std::endl;
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
