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
                           //   2: free - memory deallocation
                           //   3: mmap - memory mapping (anonymous mappings only)
                           //   4: munmap - unmap memory region
                           //   5: calloc - allocate and zero-initialize array
                           //   6: realloc - reallocate memory block
                           //      - source_memory[0]: size argument
                           //      - source_memory[1]: old pointer address
                           //      - destination_memory[0]: new pointer address (may be same or different)
                           //   7: aligned_alloc - aligned memory allocation (C11)
                           //   8: posix_memalign - POSIX aligned allocation
                           //   9: memalign - traditional aligned allocation
                           //
                           // For allocation events (1, 3, 5, 6, 7, 8, 9):
                           //   - destination_memory[0]: allocated address (return value)
                           //   - source_memory[0]: size argument
                           //   - source_memory[1]: additional arguments if needed (e.g., old pointer for realloc)
                           //
                           // For deallocation events (2, 4):
                           //   - source_memory[0]: pointer/address to free/unmap
                           //   - source_memory[1]: length (for munmap only)
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

// compact binary malloc trace record (32 bytes)
// type: 1=malloc, 2=free, 3=mmap, 4=munmap, 5=calloc, 6=realloc,
//        7=aligned_alloc, 8=posix_memalign, 9=memalign
struct malloc_instr {
  unsigned long long arg1;     // parameter 1 (alloc=size, free/munmap=ptr, realloc=old_ptr)
  unsigned long long arg2;     // parameter 2 (realloc=size, munmap=length; 0 otherwise)
  unsigned long long ret;      // return value (allocated address, 0=failure)
  unsigned char type;          // allocation event type
  unsigned char reserved[7];   // alignment padding (total = 32 bytes)
};

// Binary layout: arg1(8) + arg2(8) + ret(8) + type(1) + reserved(7) = 32 bytes
static_assert(sizeof(malloc_instr) == 32, "malloc_instr must be exactly 32 bytes");
// NOLINTEND(cppcoreguidelines-avoid-c-arrays,modernize-avoid-c-arrays)

#endif
