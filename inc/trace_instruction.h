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
  unsigned long long ip;

  // branch info
  unsigned char is_branch;
  unsigned char branch_taken;

  unsigned char destination_registers[NUM_INSTR_DESTINATIONS]; // output registers
  unsigned char source_registers[NUM_INSTR_SOURCES];           // input registers

  unsigned long long destination_memory[NUM_INSTR_DESTINATIONS]; // output memory
  unsigned long long source_memory[NUM_INSTR_SOURCES];           // input memory
  
  unsigned char is_malloc; // Memory allocation event type identifier:
                           //   0: normal instruction (not a memory allocation event)
                           //   1: malloc - standard memory allocation
                           //       - source_memory[0]: size
                           //       - destination_memory[0]: allocated address
                           //   2: free - memory deallocation
                           //       - source_memory[0]: pointer to free
                           //   3: mmap - memory mapping (anonymous mappings only)
                           //       - source_memory[0]: length
                           //       - destination_memory[0]: mapped address
                           //   4: munmap - unmap memory region
                           //       - source_memory[0]: addr
                           //       - source_memory[1]: length
                           //   5: calloc - allocate and zero-initialize array
                           //       - source_memory[0]: total_size (nmemb * elem_size)
                           //       - destination_memory[0]: allocated address
                           //   6: realloc - reallocate memory block
                           //       - source_memory[0]: old pointer
                           //       - source_memory[1]: new_size
                           //       - destination_memory[0]: new pointer (may be same or different)
                           //   8: posix_memalign - POSIX aligned allocation
                           //       - source_memory[0]: size
                           //       - source_memory[1]: alignment
                           //       - destination_memory[0]: allocated address
                           //   10: fortran_alloc - Fortran memory allocation
                           //       - source_memory[0]: size
                           //       - destination_memory[0]: allocated address
                           //   16: realloc_inplace - realloc that returned the same address
                           //       - source_memory[0]: old pointer (= new pointer)
                           //       - destination_memory[0]: same pointer
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
