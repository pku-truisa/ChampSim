// test_main.cpp — Minimal test runner for champsim_tracer logic.
// No external test framework required.
// Macros are defined in test_types.h for all translation units.

#include "test_types.h"
#include <iostream>

// Global test counters
int total_tests = 0;
int passed_tests = 0;
int failed_tests = 0;

// Test function declarations
void test_trace_format_layout();
void test_trace_format_is_malloc_types();
void test_depth_outermost();
void test_depth_nested();
void test_depth_saturation();
void test_depth_auto_reset();
void test_mmap_independent_depth();
void test_tracked_insert_malloc();
void test_tracked_insert_mmap();
void test_tracked_realloc_erase_insert();
void test_tracked_realloc_inplace();
void test_tracked_realloc_fail();
void test_free_only_tracked();
void test_free_ptr_zero();
void test_munmap_only_tracked();
void test_munmap_invalid_addr();
void test_fast_forward_skip_writes();
void test_fast_forward_baseline_dump();
void test_writetoset_normal();
void test_writetoset_dedup();
void test_writetoset_boundary();

int main() {
  std::cout << "=== champsim_tracer Unit Tests ===" << std::endl;
  std::cout << std::endl;

  std::cout << "--- Trace Format ---" << std::endl;
  test_trace_format_layout();
  test_trace_format_is_malloc_types();

  std::cout << std::endl << "--- Depth Counter ---" << std::endl;
  test_depth_outermost();
  test_depth_nested();
  test_depth_saturation();
  test_depth_auto_reset();

  std::cout << std::endl << "--- Mmap Independent Depth ---" << std::endl;
  test_mmap_independent_depth();

  std::cout << std::endl << "--- Tracked Allocations ---" << std::endl;
  test_tracked_insert_malloc();
  test_tracked_insert_mmap();
  test_tracked_realloc_erase_insert();
  test_tracked_realloc_inplace();
  test_tracked_realloc_fail();

  std::cout << std::endl << "--- Free/Munmap Filter ---" << std::endl;
  test_free_only_tracked();
  test_free_ptr_zero();
  test_munmap_only_tracked();
  test_munmap_invalid_addr();

  std::cout << std::endl << "--- Fast-Forward ---" << std::endl;
  test_fast_forward_skip_writes();
  test_fast_forward_baseline_dump();

  std::cout << std::endl << "--- WriteToSet ---" << std::endl;
  test_writetoset_normal();
  test_writetoset_dedup();
  test_writetoset_boundary();

  std::cout << std::endl << "================================" << std::endl;
  std::cout << "Total:  " << total_tests  << std::endl;
  std::cout << "Passed: " << passed_tests  << std::endl;
  std::cout << "Failed: " << failed_tests  << std::endl;
  std::cout << "================================" << std::endl;

  return failed_tests > 0 ? 1 : 0;
}