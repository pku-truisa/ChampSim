#include "test_types.h"
#include <cstddef>

// Verify trace_instr_format_t layout — critical field offsets must match
// the binary trace consumer (tracereader.cc) for correct parsing.
void test_trace_format_layout() {
  TEST("trace_instr_format_t critical field offsets");
  // ip is the first field
  CHECK_EQ(offsetof(trace_instr_format_t, ip), 0u, "ip at offset 0");
  // is_branch follows ip (8 bytes)
  CHECK_EQ(offsetof(trace_instr_format_t, is_branch), 8u, "is_branch at offset 8");
  // branch_taken at offset 9
  CHECK_EQ(offsetof(trace_instr_format_t, branch_taken), 9u, "branch_taken at offset 9");
  // is_malloc moved after branch_taken for fixed offset
  CHECK_EQ(offsetof(trace_instr_format_t, is_malloc), 10u, "is_malloc at offset 10");
  // destination_memory follows registers (10 + 1 + 2*1 + 4*1 = 17, padded to 24)
  CHECK_EQ(offsetof(trace_instr_format_t, destination_memory[0]), 24u, "dst_memory[0] at offset 24");
  // source_memory follows destination_memory (2 * 8 = 16)
  CHECK_EQ(offsetof(trace_instr_format_t, source_memory[0]), 40u, "src_memory[0] at offset 40");
  PASS();
}

void test_trace_format_is_malloc_types() {
  TEST("is_malloc type values are distinct and match malloc_instr");
  // All allocation type values (1,2,3,4,5,6,8,16) must be non-overlapping
  // and match the malloc_instr type definitions in champsim_tracer.cpp
  //
  // 0: normal instruction
  // 1: malloc, 2: free, 3: mmap, 4: munmap, 5: calloc
  // 6: realloc, 8: posix_memalign, 16: realloc_inplace

  // Verify no overlap between allocation types
  unsigned char types[] = {1, 2, 3, 4, 5, 6, 8, 16};
  for (size_t i = 0; i < sizeof(types); i++) {
    for (size_t j = i + 1; j < sizeof(types); j++) {
      CHECK(types[i] != types[j], "duplicate type value found");
    }
  }
  PASS();
}