#include "test_types.h"
#include <algorithm>

// Test WriteToSet from champsim_tracer.cpp lines 246-252
// Template function extracted for testing

template <typename T>
void WriteToSet(T* begin, T* end, UINT32 r)
{
  auto set_end = std::find(begin, end, 0);
  auto found_reg = std::find(begin, set_end, r);
  *found_reg = r;
}

void test_writetoset_normal() {
  TEST("WriteToSet: inserts value into first available slot");
  unsigned char dest[4] = {0, 0, 0, 0};
  constexpr std::size_t N = sizeof(dest);

  WriteToSet<unsigned char>(dest, dest + N, 42);
  CHECK_EQ(dest[0], (unsigned char)42, "first slot filled with 42");

  WriteToSet<unsigned char>(dest, dest + N, 99);
  CHECK_EQ(dest[1], (unsigned char)99, "second slot filled with 99");
  PASS();
}

void test_writetoset_dedup() {
  TEST("WriteToSet: does not duplicate existing values");
  unsigned char src[4] = {0, 0, 0, 0};
  constexpr std::size_t N = sizeof(src);

  WriteToSet<unsigned char>(src, src + N, 10);
  WriteToSet<unsigned char>(src, src + N, 10);  // same value again
  WriteToSet<unsigned char>(src, src + N, 20);

  // 10 should only appear once, 20 in next slot
  CHECK_EQ(src[0], (unsigned char)10, "first occurrence of 10");
  CHECK_EQ(src[1], (unsigned char)20, "20 in next slot (10 was deduped)");
  CHECK_EQ(src[2], (unsigned char)0, "third slot still empty");
  PASS();
}

void test_writetoset_boundary() {
  TEST("WriteToSet: fills array to capacity");
  unsigned char arr[2] = {0, 0};
  constexpr std::size_t N = sizeof(arr);

  WriteToSet<unsigned char>(arr, arr + N, 1);
  WriteToSet<unsigned char>(arr, arr + N, 2);

  CHECK_EQ(arr[0], (unsigned char)1, "slot 0 = 1");
  CHECK_EQ(arr[1], (unsigned char)2, "slot 1 = 2");

  // Array is full (no zeros). PIN guarantees register count <= NUM_INSTR_SOURCES/NUM_INSTR_DESTINATIONS
  // on x86-64. This test verifies the array can be fully populated without issue.
  PASS();
}