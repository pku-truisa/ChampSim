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

// instruction format
constexpr std::size_t NUM_INSTR_DESTINATIONS_SPARC = 4;
constexpr std::size_t NUM_INSTR_DESTINATIONS = 2;
constexpr std::size_t NUM_INSTR_SOURCES = 4;

// NOLINTBEGIN(cppcoreguidelines-avoid-c-arrays,modernize-avoid-c-arrays): These classes are deliberately trivial
struct input_instr {
  // instruction pointer or PC (Program Counter)
  unsigned long long ip;                    // 0..7

  // branch info
  unsigned char is_branch;                  // 8
  unsigned char branch_taken;               // 9

  // Memory allocation event type — placed early for fixed offset (10)
  // regardless of compiler alignment of the trailing arrays.
  unsigned char is_malloc;                  // 10
  //   0: normal instruction (not a memory allocation event)
  //   1: malloc   — source_memory[0]: size,        destination_memory[0]: allocated addr
  //   2: free     — source_memory[0]: pointer
  //   3: mmap     — source_memory[0]: length,      destination_memory[0]: mapped addr
  //   4: munmap   — source_memory[0]: addr,        source_memory[1]: length
  //   5: calloc   — source_memory[0]: total_size,  destination_memory[0]: allocated addr
  //   6: realloc  — source_memory[0]: old_ptr,     source_memory[1]: new_size,
  //                 destination_memory[0]: new_ptr
  //   8: posix_memalign — source_memory[0]: size,  source_memory[1]: alignment,
  //                       destination_memory[0]: allocated addr
  //  10: fortran_alloc  — source_memory[0]: size,  destination_memory[0]: allocated addr
  //  16: realloc_inplace — source_memory[0]: old_ptr (=new_ptr),
  //                         destination_memory[0]: same pointer

  unsigned char destination_registers[NUM_INSTR_DESTINATIONS]; // 11..12
  unsigned char source_registers[NUM_INSTR_SOURCES];           // 13..16

  // 7 bytes implicit padding to 8-byte alignment

  unsigned long long destination_memory[NUM_INSTR_DESTINATIONS]; // 24..39
  unsigned long long source_memory[NUM_INSTR_SOURCES];           // 40..71
};

struct cloudsuite_instr {
  // instruction pointer or PC (Program Counter)
  unsigned long long ip;

  // branch info
  unsigned char is_branch;
  unsigned char branch_taken;

  unsigned char destination_registers[NUM_INSTR_DESTINATIONS_SPARC]; // output registers
  unsigned char source_registers[NUM_INSTR_SOURCES];                 // input registers

  unsigned long long destination_memory[NUM_INSTR_DESTINATIONS_SPARC]; // output memory
  unsigned long long source_memory[NUM_INSTR_SOURCES];                 // input memory

  unsigned char asid[2];

  unsigned char is_malloc; // Memory allocation event type identifier:
};

#endif
