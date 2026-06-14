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

#ifndef TRACE_INSTRUCTION_H
#define TRACE_INSTRUCTION_H

#include <limits>

// special registers that help us identify branches
namespace champsim
{
constexpr char REG_STACK_POINTER = 6;
constexpr char REG_FLAGS = 25;
constexpr char REG_INSTRUCTION_POINTER = 26;
} // namespace champsim

// instruction format constants
constexpr std::size_t NUM_INSTR_DESTINATIONS_SPARC = 4; // SPARC has 4 destination register/memory slots
constexpr std::size_t NUM_INSTR_DESTINATIONS = 2;       // x86 has 2 destination slots
constexpr std::size_t NUM_INSTR_SOURCES = 4;            // Both use 4 source slots

// NOLINTBEGIN(cppcoreguidelines-avoid-c-arrays,modernize-avoid-c-arrays): These classes are deliberately trivial

// ==========================================================================
// input_instr — 64-byte fixed-size trace record (zero padding)
//
// Byte offsets:
//   [ 0.. 7]  ip                          — instruction pointer (PC)
//   [ 8]      instr_type                  — instruction type
//   [ 9]      instr_info                  — type-specific information
//   [10..11]  destination_registers[2]    — written register numbers
//   [12..15]  source_registers[4]         — read register numbers
//   [16..23]  destination_memory[0]       — first written memory address
//   [24..31]  destination_memory[1]       — second written memory address
//   [32..39]  source_memory[0]            — first read memory address
//   [40..47]  source_memory[1]            — second read memory address
//   [48..55]  source_memory[2]            — third read memory address
//   [56..63]  source_memory[3]            — fourth read memory address
//
// Total: 8 + 1 + 1 + 2 + 4 + 16 + 32 = 64 bytes
// ==========================================================================
//
// instr_type field:
//   0 = normal instruction (not a branch, not an allocation event)
//   1 = branch instruction
//   2 = memory allocation/deallocation event
//
// instr_info field (depends on instr_type):
//   When instr_type == 0 (normal):  unused (value 0)
//   When instr_type == 1 (branch):  0 = not taken, 1 = taken
//   When instr_type == 2 (alloc):   allocation type code:
//      1 = malloc/new    — source_memory[0]: size,
//                           destination_memory[0]: allocated addr,
//                           destination_memory[1]: caller IP
//      2 = free/delete   — source_memory[0]: pointer to free,
//                           destination_memory[1]: caller IP
//      3 = calloc        — source_memory[0]: total_size (nmemb x elem_size),
//                           destination_memory[0]: allocated addr,
//                           destination_memory[1]: caller IP
//      4 = realloc       — source_memory[0]: old_ptr,
//                           source_memory[1]: new_size,
//                           destination_memory[0]: new_ptr (or same ptr if in-place),
//                           destination_memory[1]: caller IP
//      5 = posix_memalign — source_memory[0]: size,
//                            source_memory[1]: alignment,
//                            destination_memory[0]: allocated addr,
//                            destination_memory[1]: caller IP
//      6 = mmap          — source_memory[0]: length,
//                           destination_memory[0]: mapped addr,
//                           destination_memory[1]: caller IP
//      7 = munmap        — source_memory[0]: addr,
//                           source_memory[1]: length,
//                           destination_memory[1]: caller IP
// ==========================================================================

struct input_instr {
  unsigned long long ip;                    // [0..7]

  // instruction classification (replaces is_branch / branch_taken / is_malloc)
  unsigned char instr_type;                 // [8]  0=normal, 1=branch, 2=alloc
  unsigned char instr_info;                 // [9]  branch_taken | alloc_type

  // register operands
  unsigned char destination_registers[NUM_INSTR_DESTINATIONS]; // [10..11]
  unsigned char source_registers[NUM_INSTR_SOURCES];           // [12..15]

  // memory addresses accessed by this instruction
  unsigned long long destination_memory[NUM_INSTR_DESTINATIONS]; // [16..31]
  unsigned long long source_memory[NUM_INSTR_SOURCES];           // [32..63]
};

static_assert(sizeof(input_instr) == 64, "input_instr must be exactly 64 bytes");

// ==========================================================================
// cloudsuite_instr — trace record for SPARC/Cloudsuite traces
//
// Byte offsets:
//   [ 0.. 7]  ip                          — instruction pointer (PC)
//   [ 8]      instr_type                  — instruction type
//   [ 9]      instr_info                  — type-specific information
//   [10..13]  destination_registers[4]    — SPARC: 4 written register numbers
//   [14..17]  source_registers[4]         — read register numbers
//   [18..23]  padding                     — implicit alignment to 8 bytes
//   [24..55]  destination_memory[4]       — SPARC: 4 written memory addresses
//   [56..87]  source_memory[4]            — read memory addresses
//   [88..89]  asid[2]                     — address space ID
//   [90..95]  padding                     — implicit alignment for struct size
// ==========================================================================

struct cloudsuite_instr {
  unsigned long long ip;                    // [0..7]

  // instruction classification (replaces is_branch / branch_taken / is_malloc)
  unsigned char instr_type;                 // [8]  0=normal, 1=branch, 2=alloc
  unsigned char instr_info;                 // [9]  branch_taken | alloc_type

  // register operands (SPARC has 4 destination register slots)
  unsigned char destination_registers[NUM_INSTR_DESTINATIONS_SPARC]; // [10..13]
  unsigned char source_registers[NUM_INSTR_SOURCES];                 // [14..17]
  // implicit 6-byte padding to align u64 members                     // [18..23]

  // memory addresses accessed by this instruction (SPARC has 4 destination slots)
  unsigned long long destination_memory[NUM_INSTR_DESTINATIONS_SPARC]; // [24..55]
  unsigned long long source_memory[NUM_INSTR_SOURCES];                 // [56..87]

  // address space identifier (at end to maintain u64 array layout)
  unsigned char asid[2];                    // [88..89]
  // implicit 6-byte trailing padding for struct alignment              // [90..95]
};

#endif