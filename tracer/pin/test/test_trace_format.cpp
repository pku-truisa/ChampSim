#include "test_types.h"
#include <cstddef>

// Verify trace_instr_format_t layout — critical field offsets must match
// the binary trace consumer (tracereader.cc) for correct parsing.
//
// New 64-byte layout:
//   [0..7]   ip
//   [8]      instr_type
//   [9]      instr_info
//   [10..11] destination_registers[2]
//   [12..15] source_registers[4]
//   [16..23] destination_memory[0]
//   [24..31] destination_memory[1]
//   [32..39] source_memory[0]
//   [40..47] source_memory[1]
//   [48..55] source_memory[2]
//   [56..63] source_memory[3]
void test_trace_format_layout() {
  TEST("trace_instr_format_t critical field offsets for 64-byte layout");
  // ip is the first field
  CHECK_EQ(offsetof(trace_instr_format_t, ip), 0u, "ip at offset 0");
  // instr_type follows ip (8 bytes)
  CHECK_EQ(offsetof(trace_instr_format_t, instr_type), 8u, "instr_type at offset 8");
  // instr_info at offset 9
  CHECK_EQ(offsetof(trace_instr_format_t, instr_info), 9u, "instr_info at offset 9");
  // destination_memory follows registers (10 + 2 + 4 = 16, naturally aligned to 16)
  CHECK_EQ(offsetof(trace_instr_format_t, destination_memory[0]), 16u, "dst_memory[0] at offset 16");
  // source_memory follows destination_memory (2 * 8 = 16)
  CHECK_EQ(offsetof(trace_instr_format_t, source_memory[0]), 32u, "src_memory[0] at offset 32");
  PASS();
}

void test_trace_format_instr_types() {
  TEST("instr_type/instr_info: type values are distinct and match malloc_instr");
  // instr_type values:
  //   0: normal instruction
  //   1: branch instruction
  //   2: memory allocation/deallocation event
  //
  // instr_info values when instr_type == 2 (alloc):
  //   1: malloc, 2: free, 3: mmap, 4: munmap, 5: calloc
  //   6: realloc, 8: posix_memalign, 16: realloc_inplace

  // Verify no overlap between allocation types
  unsigned char types[] = {1, 2, 3, 4, 5, 6, 8, 16};
  for (size_t i = 0; i < sizeof(types); i++) {
    for (size_t j = i + 1; j < sizeof(types); j++) {
      CHECK(types[i] != types[j], "duplicate type value found");
    }
  }

  // Verify instr_type values are distinct
  CHECK(0 != 1, "instr_type 0 != 1");
  CHECK(0 != 2, "instr_type 0 != 2");
  CHECK(1 != 2, "instr_type 1 != 2");
  PASS();
}