#ifndef CHAMPSIM_PIN_TEST_TYPES_H
#define CHAMPSIM_PIN_TEST_TYPES_H

// Mock PIN types and shared structures extracted from champsim_tracer.cpp
// No PIN SDK dependency — pure C++ logic testing.

#include <iostream>
#include <cstddef>
#include <cstring>
#include "../../../inc/trace_instruction.h"

// Alias from champsim_tracer.cpp line 59
using trace_instr_format_t = input_instr;

// Mock PIN types
typedef unsigned long long ADDRINT;
typedef unsigned int       UINT32;

// From champsim_tracer.cpp line 74-77
struct TrackedAlloc { ADDRINT size; unsigned char type; };

// Maximum nesting depth before saturation.
constexpr int MAX_DEPTH = 16;
constexpr int MAX_STUCK = 2;

// From champsim_tracer.cpp line 82-88
struct PendingAlloc {
  ADDRINT size          = 0;
  ADDRINT arg2          = 0;   // alignment (posix_memalign) or new_size (realloc)
  int     type          = 0;
  ADDRINT posix_memptr  = 0;
};

// From champsim_tracer.cpp line 90-101
struct ThreadState {
  PendingAlloc pending;
  int alloc_depth         = 0;
  int alloc_overflow      = 0;
  int alloc_stuck_counter = 0;

  ADDRINT mmap_pending_size  = 0;
  int     mmap_depth         = 0;
  int     mmap_overflow      = 0;
  int     mmap_stuck_counter = 0;
};

// From champsim_tracer.cpp — pending malloc event
struct PendingInstrMalloc {
  unsigned char type = 0;
  unsigned long long arg1 = 0;
  unsigned long long arg2 = 0;
  unsigned long long ret = 0;
};

// Mock PIN lock — no-op in single-threaded tests
inline void MockGetLock() {}
inline void MockReleaseLock() {}

// =====================================================================
// Test macros — shared across all test translation units
// =====================================================================

extern int total_tests;
extern int passed_tests;
extern int failed_tests;

#define TEST(name) do { \
  total_tests++; \
  std::cout << "  TEST " << name << "... "; \
} while(0)

#define PASS() do { \
  passed_tests++; \
  std::cout << "PASSED" << std::endl; \
} while(0)

#define FAIL(msg) do { \
  failed_tests++; \
  std::cout << "FAILED: " << msg << std::endl; \
} while(0)

#define CHECK(cond, msg) do { \
  if (!(cond)) { FAIL(msg); return; } \
} while(0)

#define CHECK_EQ(a, b, msg) do { \
  if ((a) != (b)) { FAIL(msg); return; } \
} while(0)

#endif // CHAMPSIM_PIN_TEST_TYPES_H
