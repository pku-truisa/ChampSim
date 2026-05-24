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
ADDRINT pending_alloc_memptr = 0; // for posix_memalign
int pending_alloc_type = 0; // 0: none, 1: malloc, 3: mmap, 5: calloc, 6: realloc, 7: aligned_alloc, 8: posix_memalign, 9: memalign
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
            << "Specify the malloc text output file with -m" << std::endl
            << "Specify minimum allocation size to trace with -k (0 to trace all)" << std::endl
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
  event_instr.source_memory[0] = size;  // size argument
}

VOID CallocBefore(ADDRINT nmemb, ADDRINT size, ADDRINT ip)
{
  if (trace_limit_reached) return;
  if (in_allocator_hook) return;
  in_allocator_hook = true;

  ADDRINT total_size = nmemb * size;
  if (total_size < KnobMallocSizeThreshold.Value()) {
    pending_alloc_size = 0;
    pending_alloc_type = 0;
    in_allocator_hook = false;
    return;
  }

  pending_alloc_size = total_size;
  pending_alloc_type = 5; // 5: calloc

  event_instr = {};
  event_instr.ip = (unsigned long long int)ip;
  event_instr.is_malloc = 5;
  event_instr.source_memory[0] = total_size;  // total size (nmemb * size)
}

VOID ReallocBefore(ADDRINT ptr, ADDRINT size, ADDRINT ip)
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
  pending_alloc_type = 6; // 6: realloc

  event_instr = {};
  event_instr.ip = (unsigned long long int)ip;
  event_instr.is_malloc = 6;
  event_instr.source_memory[0] = size;     // size argument (consistent with other alloc functions)
  event_instr.source_memory[1] = ptr;      // old pointer address
}

VOID AlignedAllocBefore(ADDRINT alignment, ADDRINT size, ADDRINT ip)
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
  pending_alloc_type = 7; // 7: aligned_alloc

  event_instr = {};
  event_instr.ip = (unsigned long long int)ip;
  event_instr.is_malloc = 7;
  event_instr.source_memory[0] = size;  // size argument
}

VOID MemalignBefore(ADDRINT alignment, ADDRINT size, ADDRINT ip)
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
  pending_alloc_type = 9; // 9: memalign

  event_instr = {};
  event_instr.ip = (unsigned long long int)ip;
  event_instr.is_malloc = 9;
  event_instr.source_memory[0] = size;  // size argument
}

VOID MallocAfter(ADDRINT ret)
{
  if (!in_allocator_hook) return;
  
  // Handle different allocation types that use MallocAfter as the After callback
  bool is_valid_type = (pending_alloc_type == 1 || pending_alloc_type == 5 || 
                        pending_alloc_type == 6 || pending_alloc_type == 7 ||
                        pending_alloc_type == 9);
  
  if (!is_valid_type) {
    in_allocator_hook = false;
    return;
  }

  if (!trace_limit_reached) {
    const char* alloc_type_str = "";
    switch (pending_alloc_type) {
      case 1: alloc_type_str = "malloc"; break;
      case 5: alloc_type_str = "calloc"; break;
      case 6: alloc_type_str = "realloc"; break;
      case 7: alloc_type_str = "aligned_alloc"; break;
      case 9: alloc_type_str = "memalign"; break;
    }
    
    if (malloc_outfile.is_open()) {
      if (pending_alloc_type == 6) {
        // For realloc, show both old and new pointers
        ADDRINT size = event_instr.source_memory[0];     // size argument
        ADDRINT old_ptr = event_instr.source_memory[1];  // old pointer address
        if (ret != 0) {
          malloc_outfile << "instrCount:" << std::dec << instrCount << " " << alloc_type_str << "(0x" << std::hex << old_ptr << ", " << std::dec << size << ")=0x" << std::hex << ret << std::dec;
          if (old_ptr == 0) {
            // realloc(NULL, size) behaves like malloc
            malloc_outfile << " [new]";
          } else if (old_ptr == ret) {
            malloc_outfile << " [in-place]";
          } else {
            malloc_outfile << " [moved]";
          }
        } else {
          // realloc failed, old pointer is still valid
          malloc_outfile << "instrCount:" << std::dec << instrCount << " " << alloc_type_str << "(0x" << std::hex << old_ptr << ", " << std::dec << size << ")=NULL [failed]";
        }
        malloc_outfile << std::dec << std::endl;
      } else {
        // For other allocation functions
        if (ret != 0) {
          malloc_outfile << "instrCount:" << std::dec << instrCount << " " << alloc_type_str << "(" << std::dec << pending_alloc_size << ")=0x" << std::hex << ret << std::dec << std::endl;
        } else {
          malloc_outfile << "instrCount:" << std::dec << instrCount << " " << alloc_type_str << "(" << std::dec << pending_alloc_size << ")=NULL [failed]" << std::endl;
        }
      }
    }

    // Only track successful allocations
    if (ret != 0) {
      event_instr.destination_memory[0] = ret;
      WriteEventInstruction();
      tracked_addresses.insert(ret);
      
      // For realloc with different pointers, remove old pointer from tracking
      if (pending_alloc_type == 6) {
        ADDRINT old_ptr = event_instr.source_memory[1];  // old pointer is now in source_memory[1]
        if (old_ptr != 0 && old_ptr != ret) {
          auto it = tracked_addresses.find(old_ptr);
          if (it != tracked_addresses.end()) {
            tracked_addresses.erase(it);
          }
        }
      }
    }
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
    malloc_outfile << "instrCount:" << std::dec << instrCount << " free(0x" << std::hex << ptr << ")" << std::dec << std::endl;
  }

  event_instr = {};
  event_instr.ip = (unsigned long long int)ip;
  event_instr.is_malloc = 2; // 2: free
  event_instr.source_memory[0] = ptr;
  WriteEventInstruction();

  tracked_addresses.erase(it);
  in_allocator_hook = false;
}

VOID PosixMemalignBefore(ADDRINT memptr, ADDRINT size, ADDRINT ip)
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
  pending_alloc_type = 8; // 8: posix_memalign
  pending_alloc_memptr = memptr; // save for After callback

  event_instr = {};
  event_instr.ip = (unsigned long long int)ip;
  event_instr.is_malloc = 8;
  event_instr.source_memory[0] = size;  // size argument
}

VOID PosixMemalignAfter(ADDRINT ret, ADDRINT ip)
{
  if (!in_allocator_hook || pending_alloc_type != 8) return;

  // For posix_memalign, the return value is the error code (0 on success)
  // The actual pointer is stored in *memptr
  if (ret == 0 && !trace_limit_reached && pending_alloc_memptr != 0) {
    // Read the allocated address from memptr
    ADDRINT allocated_addr = 0;
    PIN_SafeCopy(&allocated_addr, (VOID*)pending_alloc_memptr, sizeof(ADDRINT));

    if (allocated_addr != 0) {
      if (malloc_outfile.is_open()) {
        malloc_outfile << "instrCount:" << std::dec << instrCount << " posix_memalign(" << std::dec << pending_alloc_size << ")=0x" << std::hex << allocated_addr << std::dec << std::endl;
      }

      event_instr.destination_memory[0] = allocated_addr;
      WriteEventInstruction();
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
  event_instr.source_memory[0] = length;  // size argument (length for mmap)
}

VOID MmapAfter(ADDRINT ret)
{
  if (!in_allocator_hook || pending_alloc_type != 3) return;

  if (ret != 0 && ret != (ADDRINT)-1 && !trace_limit_reached) {
    if (malloc_outfile.is_open()) {
      malloc_outfile << "instrCount:" << std::dec << instrCount << " app_mmap(" << std::dec << pending_alloc_size << ")=0x" << std::hex << ret << std::dec << std::endl;
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
    malloc_outfile << "instrCount:" << std::dec << instrCount << " app_munmap(0x" << std::hex << addr << ", " << std::dec << length << ")" << std::dec << std::endl;
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

  // Hook calloc for all images
  rtn = RTN_FindByName(img, "calloc");
  if (RTN_Valid(rtn)) {
    RTN_Open(rtn);
    RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)CallocBefore, IARG_FUNCARG_ENTRYPOINT_VALUE, 0, IARG_FUNCARG_ENTRYPOINT_VALUE, 1, IARG_INST_PTR, IARG_END);
    RTN_InsertCall(rtn, IPOINT_AFTER, (AFUNPTR)MallocAfter, IARG_FUNCRET_EXITPOINT_VALUE, IARG_END);
    RTN_Close(rtn);
  }

  // Hook realloc for all images
  rtn = RTN_FindByName(img, "realloc");
  if (RTN_Valid(rtn)) {
    RTN_Open(rtn);
    RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)ReallocBefore, IARG_FUNCARG_ENTRYPOINT_VALUE, 0, IARG_FUNCARG_ENTRYPOINT_VALUE, 1, IARG_INST_PTR, IARG_END);
    RTN_InsertCall(rtn, IPOINT_AFTER, (AFUNPTR)MallocAfter, IARG_FUNCRET_EXITPOINT_VALUE, IARG_END);
    RTN_Close(rtn);
  }

  // Hook aligned_alloc for all images (C11 standard)
  rtn = RTN_FindByName(img, "aligned_alloc");
  if (RTN_Valid(rtn)) {
    RTN_Open(rtn);
    RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)AlignedAllocBefore, IARG_FUNCARG_ENTRYPOINT_VALUE, 0, IARG_FUNCARG_ENTRYPOINT_VALUE, 1, IARG_INST_PTR, IARG_END);
    RTN_InsertCall(rtn, IPOINT_AFTER, (AFUNPTR)MallocAfter, IARG_FUNCRET_EXITPOINT_VALUE, IARG_END);
    RTN_Close(rtn);
  }

  // Hook memalign for all images (traditional function)
  rtn = RTN_FindByName(img, "memalign");
  if (RTN_Valid(rtn)) {
    RTN_Open(rtn);
    RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)MemalignBefore, IARG_FUNCARG_ENTRYPOINT_VALUE, 0, IARG_FUNCARG_ENTRYPOINT_VALUE, 1, IARG_INST_PTR, IARG_END);
    RTN_InsertCall(rtn, IPOINT_AFTER, (AFUNPTR)MallocAfter, IARG_FUNCRET_EXITPOINT_VALUE, IARG_END);
    RTN_Close(rtn);
  }

  // Hook mmap/mmap64/munmap for all images (not just main executable)
  // This allows tracking direct mmap calls from shared libraries
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

  // Only open instruction trace file if not in allocation-only mode
  if (!KnobAllocOnly.Value()) {
    outfile.open(KnobOutputFile.Value().c_str(), std::ios_base::binary | std::ios_base::trunc);
    if (!outfile) {
      std::cout << "Couldn't open output trace file. Exiting." << std::endl;
      exit(1);
    }
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
