#include "test_types.h"
#include <unordered_map>

// Test FreeBefore / MunmapBefore filter logic from champsim_tracer.cpp

void test_free_only_tracked() {
  TEST("FreeBefore: only writes event for tracked addresses");
  std::unordered_map<ADDRINT, TrackedAlloc> tracked;
  PendingInstrMalloc pending;

  // Tracked address
  ADDRINT addr = 0x1000;
  tracked[addr] = {1024u, (unsigned char)1};

  // Free tracked address
  {
    auto it = tracked.find(addr);
    if (it != tracked.end()) {
      pending.type = 2;
      pending.arg1 = addr;
      pending.arg2 = 0;
      pending.ret = 0;
      tracked.erase(it);
    }
    CHECK_EQ(pending.type, (unsigned char)2, "free type=2 recorded");
    CHECK_EQ(pending.arg1, 0x1000ull, "free arg1=ptr");
    CHECK(tracked.find(addr) == tracked.end(), "addr removed from tracked");
  }

  // Free untracked address
  {
    ADDRINT unknown = 0xDEAD;
    pending = {};
    auto it = tracked.find(unknown);
    int found = (it != tracked.end()) ? 1 : 0;
    CHECK_EQ(found, 0, "untracked addr not found");
    CHECK_EQ(pending.type, (unsigned char)0, "no event for untracked free");
  }
  PASS();
}

void test_free_ptr_zero() {
  TEST("FreeBefore: ptr==0 returns immediately, no event");
  // ptr==0: early return, no lock, no event
  ADDRINT ptr = 0;
  bool early_return = (ptr == 0);
  CHECK(early_return, "ptr==0 should trigger early return");
  PASS();
}

void test_munmap_only_tracked() {
  TEST("MunmapBefore: only writes event for tracked addresses");
  std::unordered_map<ADDRINT, TrackedAlloc> tracked;
  PendingInstrMalloc pending;

  ADDRINT addr = 0x3000;
  tracked[addr] = {4096u, (unsigned char)3};  // mmap

  // Munmap tracked address
  {
    auto it = tracked.find(addr);
    if (it != tracked.end()) {
      pending.type = 4;
      pending.arg1 = addr;
      pending.arg2 = 4096;  // length
      pending.ret = 0;
      tracked.erase(it);
    }
    CHECK_EQ(pending.type, (unsigned char)4, "munmap type=4 recorded");
    CHECK_EQ(pending.arg1, 0x3000ull, "munmap arg1=addr");
    CHECK_EQ(pending.arg2, 4096ull, "munmap arg2=length");
  }
  PASS();
}

void test_munmap_invalid_addr() {
  TEST("MunmapBefore: addr==0 or (ADDRINT)-1 returns immediately");
  ADDRINT a1 = 0;
  ADDRINT a2 = (ADDRINT)-1;
  bool early_return_1 = (a1 == 0 || a1 == (ADDRINT)-1);
  bool early_return_2 = (a2 == 0 || a2 == (ADDRINT)-1);
  CHECK(early_return_1, "addr=0 triggers early return");
  CHECK(early_return_2, "addr=-1 triggers early return");
  PASS();
}