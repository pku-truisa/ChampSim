#include "test_types.h"
#include <unordered_map>
#include <cstdint>

// =========================================================================
// Tests for malloc threshold (-k) logic extracted from champsim_tracer.cpp
//
// The threshold controls which allocation events are recorded in the trace.
// Only allocations with size >= threshold are written to pending_instr_malloc
// and tracked in tracked_allocations.
//
// Default threshold value = 4096 (from KnobMallocThreshold)
// =========================================================================

static constexpr ADDRINT DEFAULT_THRESHOLD = 4096;

// Helper: simulates the AllocAfter non-realloc branch (malloc/calloc/fortran)
static bool alloc_after_non_realloc_should_record(ADDRINT size, ADDRINT ret,
                                                   ADDRINT threshold)
{
  return ret != 0 && ret != (ADDRINT)-1 && size >= threshold;
}

// Helper: simulates the AllocAfter realloc branch
// Returns {should_erase_old, should_record_new}
struct ReallocDecision {
  bool should_erase_old;
  bool should_record_new;
};
static ReallocDecision alloc_after_realloc_should_record(
    ADDRINT old_ptr, ADDRINT new_size, ADDRINT ret, ADDRINT threshold)
{
  ReallocDecision d;
  d.should_erase_old = (old_ptr != 0);
  d.should_record_new =
      (new_size >= threshold && ret != 0 && ret != (ADDRINT)-1);
  return d;
}

// Helper: simulates the PosixMemalignAfter branch
static bool posix_memalign_after_should_record(ADDRINT size, ADDRINT real_addr,
                                                ADDRINT threshold)
{
  return real_addr != 0 && real_addr != (ADDRINT)-1 && size >= threshold;
}

// Helper: simulates the MmapAfter branch
static bool mmap_after_should_record(ADDRINT size, ADDRINT ret,
                                      ADDRINT threshold)
{
  return ret != 0 && ret != (ADDRINT)-1 && size >= threshold;
}

// =========================================================================
// Test: malloc size >= threshold  -> recorded
// =========================================================================
void test_threshold_malloc_above() {
  TEST("threshold: malloc size >= threshold (4096) is recorded");
  std::unordered_map<ADDRINT, TrackedAlloc> tracked;
  PendingInstrMalloc pending = {};

  ADDRINT size = 4096;
  ADDRINT ret = 0x1000;

  if (alloc_after_non_realloc_should_record(size, ret, DEFAULT_THRESHOLD)) {
    pending.type = 1;
    pending.arg1 = size;
    pending.ret = ret;
    tracked[ret] = {size, 1};
  }

  CHECK(pending.type != 0, "pending_instr_malloc should be set");
  CHECK_EQ(pending.arg1, size, "arg1 should be size");
  CHECK_EQ(pending.ret, ret, "ret should be allocated addr");
  CHECK(tracked.find(ret) != tracked.end(), "addr should be tracked");
  CHECK_EQ(tracked[ret].size, size, "tracked size should match");
  CHECK_EQ(tracked[ret].type, (unsigned char)1, "tracked type should be 1");
  PASS();
}

// =========================================================================
// Test: malloc size < threshold  -> NOT recorded
// =========================================================================
void test_threshold_malloc_below() {
  TEST("threshold: malloc size < threshold (1024 < 4096) is NOT recorded");
  std::unordered_map<ADDRINT, TrackedAlloc> tracked;
  PendingInstrMalloc pending = {};

  ADDRINT size = 1024;
  ADDRINT ret = 0x1000;

  if (alloc_after_non_realloc_should_record(size, ret, DEFAULT_THRESHOLD)) {
    pending.type = 1;
    pending.arg1 = size;
    pending.ret = ret;
    tracked[ret] = {size, 1};
  }

  CHECK(pending.type == 0, "pending_instr_malloc should NOT be set");
  CHECK(tracked.find(ret) == tracked.end(), "addr should NOT be tracked");
  PASS();
}

// =========================================================================
// Test: malloc with ret=0 (failure) never recorded, regardless of size
// =========================================================================
void test_threshold_malloc_failure() {
  TEST("threshold: malloc failure (ret=0) never recorded even if size>=threshold");
  std::unordered_map<ADDRINT, TrackedAlloc> tracked;
  PendingInstrMalloc pending = {};

  ADDRINT size = 8192;
  ADDRINT ret = 0;  // failure

  if (alloc_after_non_realloc_should_record(size, ret, DEFAULT_THRESHOLD)) {
    pending.type = 1;
    pending.arg1 = size;
    pending.ret = ret;
    tracked[ret] = {size, 1};
  }

  CHECK(pending.type == 0, "pending_instr_malloc should NOT be set on failure");
  CHECK(tracked.find(ret) == tracked.end(), "failed alloc should not be tracked");
  PASS();
}

// =========================================================================
// Test: realloc new_size >= threshold -> recorded, old always erased
// =========================================================================
void test_threshold_realloc_above() {
  TEST("threshold: realloc new_size >= threshold is recorded, old erased");
  std::unordered_map<ADDRINT, TrackedAlloc> tracked;
  PendingInstrMalloc pending = {};

  ADDRINT old_ptr = 0x2000;
  ADDRINT new_size = 4096;
  ADDRINT ret = 0x3000;
  // Simulate existing tracked allocation from a previous alloc
  tracked[old_ptr] = {1024, 1};

  auto dec = alloc_after_realloc_should_record(old_ptr, new_size, ret, DEFAULT_THRESHOLD);

  if (dec.should_erase_old) tracked.erase(old_ptr);
  if (dec.should_record_new) {
    unsigned char final_type = (ret == old_ptr && ret != 0) ? 16 : 6;
    pending.type = final_type;
    pending.arg1 = old_ptr;
    pending.arg2 = new_size;
    pending.ret = ret;
    tracked[ret] = {new_size, final_type};
  }

  CHECK(tracked.find(old_ptr) == tracked.end(), "old ptr should be erased");
  CHECK(pending.type != 0, "pending_instr_malloc should be set");
  CHECK_EQ(pending.type, (unsigned char)6, "type should be 6 (realloc)");
  CHECK_EQ(pending.arg2, new_size, "arg2 should be new_size");
  CHECK(tracked.find(ret) != tracked.end(), "new addr should be tracked");
  PASS();
}

// =========================================================================
// Test: realloc new_size < threshold -> old erased, new NOT tracked
// =========================================================================
void test_threshold_realloc_below() {
  TEST("threshold: realloc new_size < threshold, old erased, new NOT tracked");
  std::unordered_map<ADDRINT, TrackedAlloc> tracked;
  PendingInstrMalloc pending = {};

  ADDRINT old_ptr = 0x2000;
  ADDRINT new_size = 1024;
  ADDRINT ret = 0x3000;
  tracked[old_ptr] = {8192, 1};  // old was a large allocation

  auto dec = alloc_after_realloc_should_record(old_ptr, new_size, ret, DEFAULT_THRESHOLD);

  if (dec.should_erase_old) tracked.erase(old_ptr);
  if (dec.should_record_new) {
    unsigned char final_type = (ret == old_ptr && ret != 0) ? 16 : 6;
    pending.type = final_type;
    pending.arg1 = old_ptr;
    pending.arg2 = new_size;
    pending.ret = ret;
    tracked[ret] = {new_size, final_type};
  }

  CHECK(tracked.find(old_ptr) == tracked.end(), "old ptr should be erased");
  CHECK(pending.type == 0, "pending_instr_malloc should NOT be set");
  CHECK(tracked.find(ret) == tracked.end(), "new addr should NOT be tracked");
  PASS();
}

// =========================================================================
// Test: realloc inplace with new_size >= threshold -> type=16
// =========================================================================
void test_threshold_realloc_inplace_above() {
  TEST("threshold: realloc_inplace with new_size >= threshold, type=16");
  std::unordered_map<ADDRINT, TrackedAlloc> tracked;
  PendingInstrMalloc pending = {};

  ADDRINT addr = 0x4000;
  ADDRINT new_size = 8192;
  ADDRINT ret = addr;  // same address
  tracked[addr] = {4096, 1};  // previous malloc at threshold

  auto dec = alloc_after_realloc_should_record(addr, new_size, ret, DEFAULT_THRESHOLD);

  if (dec.should_erase_old) tracked.erase(addr);
  if (dec.should_record_new) {
    unsigned char final_type = (ret == addr && ret != 0) ? 16 : 6;
    pending.type = final_type;
    pending.arg1 = addr;
    pending.arg2 = new_size;
    pending.ret = ret;
    tracked[ret] = {new_size, final_type};
  }

  CHECK_EQ(pending.type, (unsigned char)16, "type should be 16 (realloc_inplace)");
  CHECK(tracked.find(addr) != tracked.end(), "addr should still be tracked");
  CHECK_EQ(tracked[addr].size, new_size, "tracked size should be new_size");
  CHECK_EQ(tracked[addr].type, (unsigned char)16, "tracked type should be 16");
  PASS();
}

// =========================================================================
// Test: posix_memalign size >= threshold -> recorded
// =========================================================================
void test_threshold_posix_memalign_above() {
  TEST("threshold: posix_memalign size >= threshold is recorded");
  std::unordered_map<ADDRINT, TrackedAlloc> tracked;
  PendingInstrMalloc pending = {};

  ADDRINT size = 4096;
  ADDRINT alignment = 64;
  ADDRINT real_addr = 0x5000;

  if (posix_memalign_after_should_record(size, real_addr, DEFAULT_THRESHOLD)) {
    pending.type = 8;
    pending.arg1 = size;
    pending.arg2 = alignment;
    pending.ret = real_addr;
    tracked[real_addr] = {size, 8};
  }

  CHECK(pending.type != 0, "pending_instr_malloc should be set");
  CHECK_EQ(pending.type, (unsigned char)8, "type should be 8");
  CHECK_EQ(pending.arg2, alignment, "arg2 should be alignment");
  CHECK(tracked.find(real_addr) != tracked.end(), "addr should be tracked");
  PASS();
}

// =========================================================================
// Test: posix_memalign size < threshold -> NOT recorded
// =========================================================================
void test_threshold_posix_memalign_below() {
  TEST("threshold: posix_memalign size < threshold is NOT recorded");
  std::unordered_map<ADDRINT, TrackedAlloc> tracked;
  PendingInstrMalloc pending = {};

  ADDRINT size = 256;
  ADDRINT alignment = 64;
  ADDRINT real_addr = 0x5000;

  if (posix_memalign_after_should_record(size, real_addr, DEFAULT_THRESHOLD)) {
    pending.type = 8;
    pending.arg1 = size;
    pending.arg2 = alignment;
    pending.ret = real_addr;
    tracked[real_addr] = {size, 8};
  }

  CHECK(pending.type == 0, "pending_instr_malloc should NOT be set");
  CHECK(tracked.find(real_addr) == tracked.end(), "addr should NOT be tracked");
  PASS();
}

// =========================================================================
// Test: mmap size >= threshold -> recorded
// =========================================================================
void test_threshold_mmap_above() {
  TEST("threshold: mmap size >= threshold is recorded");
  std::unordered_map<ADDRINT, TrackedAlloc> tracked;
  PendingInstrMalloc pending = {};

  ADDRINT size = 8192;
  ADDRINT ret = 0x6000;

  if (mmap_after_should_record(size, ret, DEFAULT_THRESHOLD)) {
    pending.type = 3;
    pending.arg1 = size;
    pending.ret = ret;
    tracked[ret] = {size, 3};
  }

  CHECK(pending.type != 0, "pending_instr_malloc should be set");
  CHECK_EQ(pending.type, (unsigned char)3, "type should be 3 (mmap)");
  CHECK(tracked.find(ret) != tracked.end(), "addr should be tracked");
  CHECK_EQ(tracked[ret].size, size, "tracked size should match");
  PASS();
}

// =========================================================================
// Test: mmap size < threshold -> NOT recorded
// =========================================================================
void test_threshold_mmap_below() {
  TEST("threshold: mmap size < threshold is NOT recorded");
  std::unordered_map<ADDRINT, TrackedAlloc> tracked;
  PendingInstrMalloc pending = {};

  ADDRINT size = 2048;
  ADDRINT ret = 0x6000;

  if (mmap_after_should_record(size, ret, DEFAULT_THRESHOLD)) {
    pending.type = 3;
    pending.arg1 = size;
    pending.ret = ret;
    tracked[ret] = {size, 3};
  }

  CHECK(pending.type == 0, "pending_instr_malloc should NOT be set");
  CHECK(tracked.find(ret) == tracked.end(), "addr should NOT be tracked");
  PASS();
}

// =========================================================================
// Test: size exactly at threshold boundary
// =========================================================================
void test_threshold_boundary_exact() {
  TEST("threshold: size == 4096 (exact boundary) is recorded");
  std::unordered_map<ADDRINT, TrackedAlloc> tracked;
  PendingInstrMalloc pending = {};

  ADDRINT size = 4096;
  ADDRINT ret = 0x7000;

  if (alloc_after_non_realloc_should_record(size, ret, DEFAULT_THRESHOLD)) {
    pending.type = 1;
    pending.arg1 = size;
    pending.ret = ret;
    tracked[ret] = {size, 1};
  }

  CHECK(pending.type != 0, "pending_instr_malloc should be set (>= threshold)");
  CHECK(tracked.find(ret) != tracked.end(), "addr should be tracked");
  PASS();
}

// =========================================================================
// Test: size exactly at threshold-1 boundary
// =========================================================================
void test_threshold_boundary_below() {
  TEST("threshold: size == 4095 (threshold-1) is NOT recorded");
  std::unordered_map<ADDRINT, TrackedAlloc> tracked;
  PendingInstrMalloc pending = {};

  ADDRINT size = 4095;
  ADDRINT ret = 0x7000;

  if (alloc_after_non_realloc_should_record(size, ret, DEFAULT_THRESHOLD)) {
    pending.type = 1;
    pending.arg1 = size;
    pending.ret = ret;
    tracked[ret] = {size, 1};
  }

  CHECK(pending.type == 0, "pending_instr_malloc should NOT be set (< threshold)");
  CHECK(tracked.find(ret) == tracked.end(), "addr should NOT be tracked");
  PASS();
}

// =========================================================================
// Test: custom threshold (not default 4096)
// =========================================================================
void test_threshold_custom_value() {
  TEST("threshold: custom threshold value (8192) is respected");
  std::unordered_map<ADDRINT, TrackedAlloc> tracked;
  PendingInstrMalloc pending = {};

  ADDRINT custom_threshold = 8192;
  ADDRINT size_below = 4096;
  ADDRINT size_above = 16384;
  ADDRINT ret = 0x8000;

  // Below custom threshold (but above default 4096) — should NOT record
  if (alloc_after_non_realloc_should_record(size_below, ret, custom_threshold)) {
    pending.type = 1;
    pending.arg1 = size_below;
    pending.ret = ret;
    tracked[ret] = {size_below, 1};
  }
  CHECK(pending.type == 0, "size 4096 should NOT pass custom threshold 8192");

  // Above custom threshold — should record
  ret = 0x9000;
  if (alloc_after_non_realloc_should_record(size_above, ret, custom_threshold)) {
    pending.type = 1;
    pending.arg1 = size_above;
    pending.ret = ret;
    tracked[ret] = {size_above, 1};
  }
  CHECK(pending.type != 0, "size 16384 should pass custom threshold 8192");
  CHECK(tracked.find(ret) != tracked.end(), "addr should be tracked");
  PASS();
}

// =========================================================================
// Test: free still works only for tracked allocations (threshold already
// filtered them, so free of small allocations is naturally suppressed)
// =========================================================================
void test_threshold_free_only_tracked() {
  TEST("threshold: free of small allocation (not tracked) produces no event");
  std::unordered_map<ADDRINT, TrackedAlloc> tracked;
  PendingInstrMalloc pending = {};

  // Simulate: a small malloc(1024) happened — not tracked due to threshold
  ADDRINT small_ptr = 0xA000;

  // Simulate FreeBefore: check tracked_allocations
  auto it = tracked.find(small_ptr);
  if (it != tracked.end()) {
    pending.type = 2;
    pending.arg1 = (unsigned long long)small_ptr;
    tracked.erase(it);
  }

  CHECK(pending.type == 0, "free of small untracked allocation should produce no event");
  PASS();
}

// =========================================================================
// Test: free of large allocation (tracked) still produces event
// =========================================================================
void test_threshold_free_large_tracked() {
  TEST("threshold: free of large allocation (tracked) produces event");
  std::unordered_map<ADDRINT, TrackedAlloc> tracked;
  PendingInstrMalloc pending = {};

  // Simulate: a large malloc(8192) happened and was tracked
  ADDRINT large_ptr = 0xB000;
  tracked[large_ptr] = {8192, 1};

  // Simulate FreeBefore
  auto it = tracked.find(large_ptr);
  if (it != tracked.end()) {
    pending.type = 2;
    pending.arg1 = (unsigned long long)large_ptr;
    tracked.erase(it);
  }

  CHECK(pending.type != 0, "free of large tracked allocation should produce event");
  CHECK_EQ(pending.type, (unsigned char)2, "type should be 2 (free)");
  CHECK(tracked.find(large_ptr) == tracked.end(), "addr should be removed from tracked");
  PASS();
}