#include "test_types.h"
#include <unordered_map>

// Test the tracked_allocations map logic extracted from champsim_tracer.cpp

void test_tracked_insert_malloc() {
  TEST("tracked_allocations: malloc insert stores size and type=1");
  std::unordered_map<ADDRINT, TrackedAlloc> tracked;
  ADDRINT addr = 0x1000;
  ADDRINT size = 1024;
  tracked[addr] = {size, 1};
  CHECK(tracked.find(addr) != tracked.end(), "addr should be tracked");
  CHECK_EQ(tracked[addr].size, 1024ull, "size should be 1024");
  CHECK_EQ(tracked[addr].type, (unsigned char)1, "type should be 1");
  PASS();
}

void test_tracked_insert_mmap() {
  TEST("tracked_allocations: mmap insert stores size and type=3");
  std::unordered_map<ADDRINT, TrackedAlloc> tracked;
  ADDRINT addr = 0x7000;
  ADDRINT size = 4096;
  tracked[addr] = {size, 3};
  CHECK(tracked.find(addr) != tracked.end(), "addr should be tracked");
  CHECK_EQ(tracked[addr].size, 4096ull, "mmap size");
  CHECK_EQ(tracked[addr].type, (unsigned char)3, "type=3 (mmap)");
  PASS();
}

void test_tracked_realloc_erase_insert() {
  TEST("tracked_allocations: realloc erases old, inserts new");
  std::unordered_map<ADDRINT, TrackedAlloc> tracked;
  ADDRINT old_ptr = 0x2000;
  ADDRINT new_ptr = 0x3000;
  ADDRINT new_size = 2048;

  // Initial malloc
  tracked[old_ptr] = {1024u, (unsigned char)1};

  // Realloc: erase old, insert new
  tracked.erase(old_ptr);
  tracked[new_ptr] = {new_size, (unsigned char)6};
  CHECK(tracked.find(old_ptr) == tracked.end(), "old ptr should be removed");
  CHECK_EQ(tracked[new_ptr].size, 2048ull, "new size=2048");
  CHECK_EQ(tracked[new_ptr].type, (unsigned char)6, "type=6 (realloc)");
  PASS();
}

void test_tracked_realloc_inplace() {
  TEST("tracked_allocations: realloc_inplace keeps same addr, type=16");
  std::unordered_map<ADDRINT, TrackedAlloc> tracked;
  ADDRINT addr = 0x4000;
  // Initial
  tracked[addr] = {512u, (unsigned char)1};

  // Realloc inplace: same address, type=16
  // Simulate AllocAfter logic: ret == old_ptr, so final_type = 16
  ADDRINT ret = addr;  // same address
  unsigned char final_type = (ret == addr && ret != 0) ? 16 : 6;

  tracked.erase(addr);  // erase old tracking info
  tracked[ret] = {1024u, final_type};  // insert with new size and type=16

  CHECK_EQ(tracked[addr].size, 1024ull, "inplace new size");
  CHECK_EQ(tracked[addr].type, (unsigned char)16, "type=16 (realloc_inplace)");
  PASS();
}

void test_tracked_realloc_fail() {
  TEST("tracked_allocations: realloc failure (ret=0) only erases");
  std::unordered_map<ADDRINT, TrackedAlloc> tracked;
  ADDRINT old_ptr = 0x5000;
  tracked[old_ptr] = {1024u, (unsigned char)1};

  // Realloc fails: ret=0, erase old but don't insert new
  ADDRINT ret = 0;
  tracked.erase(old_ptr);
  if (ret != 0 && ret != (ADDRINT)-1) {
    tracked[ret] = {2048u, (unsigned char)6};
  }
  CHECK(tracked.find(old_ptr) == tracked.end(), "old ptr removed");
  CHECK(tracked.find(ret) == tracked.end(), "no new entry for failed realloc");
  PASS();
}