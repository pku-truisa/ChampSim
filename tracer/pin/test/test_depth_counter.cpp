#include "test_types.h"

// Exact copies of the depth logic from champsim_tracer.cpp lines 264-337

static ThreadState* get_tls_static(ThreadState** ts_ptr) { return *ts_ptr; }
static ThreadState* get_mmap_tls_static(ThreadState** ts_ptr) { return *ts_ptr; }

static bool depth_outermost_before(ThreadState* ts, int alloc_type,
                                   ADDRINT size, ADDRINT arg2 = 0)
{
  if (ts->alloc_depth > 0) {
    if (ts->alloc_depth < MAX_DEPTH) {
      ts->alloc_depth++;
    } else {
      ts->alloc_overflow++;
    }
    return false;
  }
  ts->alloc_depth = 1;
  ts->pending = PendingAlloc{size, arg2, alloc_type, 0};
  return true;
}

static void try_auto_reset_depth(ThreadState* ts)
{
  if (ts->alloc_depth == 0) {
    ts->alloc_stuck_counter = 0;
    return;
  }
  ts->alloc_stuck_counter++;
  if (ts->alloc_stuck_counter >= MAX_STUCK) {
    ts->alloc_depth = 0;
    ts->alloc_overflow = 0;
    ts->alloc_stuck_counter = 0;
  }
}

void test_depth_outermost() {
  TEST("depth_outermost: first call stages parameters and sets depth=1");
  ThreadState ts;
  bool outermost = depth_outermost_before(&ts, 1, 1024);
  CHECK(outermost, "expected outermost=true");
  CHECK_EQ(ts.alloc_depth, 1, "depth should be 1");
  CHECK_EQ(ts.pending.size, 1024ull, "size should be 1024");
  CHECK_EQ(ts.pending.type, 1, "type should be 1");
  PASS();
}

void test_depth_nested() {
  TEST("depth_outermost: nested call increments depth, does not stage");
  ThreadState ts;
  depth_outermost_before(&ts, 1, 100);   // outermost, depth=1
  bool outer = depth_outermost_before(&ts, 1, 200);  // nested
  CHECK(!outer, "expected nested=false");
  CHECK_EQ(ts.alloc_depth, 2, "depth should be 2");
  CHECK_EQ(ts.pending.size, 100ull, "pending unchanged by nested call");
  PASS();
}

void test_depth_saturation() {
  TEST("depth_outermost: beyond MAX_DEPTH goes to overflow");
  ThreadState ts;
  for (int i = 0; i < MAX_DEPTH; i++) {
    depth_outermost_before(&ts, 1, 100 + i);
  }
  // depth now at MAX_DEPTH
  CHECK_EQ(ts.alloc_depth, MAX_DEPTH, "depth should be MAX_DEPTH");
  CHECK_EQ(ts.alloc_overflow, 0, "overflow should be 0");

  // Next call should overflow
  bool r = depth_outermost_before(&ts, 1, 999);
  CHECK(!r, "should not be outermost");
  CHECK_EQ(ts.alloc_overflow, 1, "overflow should be 1");
  PASS();
}

void test_depth_auto_reset() {
  TEST("try_auto_reset_depth: resets after MAX_STUCK stuck calls");
  ThreadState ts;
  depth_outermost_before(&ts, 1, 100);  // depth=1
  // Simulate stuck: no AFTER callback ever comes, yet BEFORE keeps firing
  // (depth > 0). try_auto_reset_depth bumps stuck counter each time.
  try_auto_reset_depth(&ts);
  CHECK_EQ(ts.alloc_stuck_counter, 1, "stuck_counter=1 after first stuck");
  CHECK_EQ(ts.alloc_depth, 1, "depth still 1");

  try_auto_reset_depth(&ts);
  // stuck_counter reached MAX_STUCK=2, should reset
  CHECK_EQ(ts.alloc_depth, 0, "depth should be reset to 0");
  CHECK_EQ(ts.alloc_overflow, 0, "overflow should be reset to 0");
  CHECK_EQ(ts.alloc_stuck_counter, 0, "stuck_counter should be reset to 0");
  PASS();
}

void test_mmap_independent_depth() {
  TEST("mmap_depth: independent of alloc_depth");
  // Simulate mmap depth tracking (from champsim_tracer.cpp MmapBefore/After)
  ThreadState ts;

  // Alloc depth active
  depth_outermost_before(&ts, 1, 100);
  CHECK_EQ(ts.alloc_depth, 1, "alloc depth=1");

  // Mmap depth separately
  CHECK_EQ(ts.mmap_depth, 0, "mmap depth=0 initially");
  // Simulate MmapBefore logic
  if (ts.mmap_depth > 0) {
    if (ts.mmap_depth < MAX_DEPTH) ts.mmap_depth++;
  } else {
    ts.mmap_depth = 1;
    ts.mmap_pending_size = 4096;
  }
  CHECK_EQ(ts.mmap_depth, 1, "mmap depth=1");
  CHECK_EQ(ts.alloc_depth, 1, "alloc depth still 1 (independent)");

  // Nested mmap
  if (ts.mmap_depth > 0) {
    if (ts.mmap_depth < MAX_DEPTH) ts.mmap_depth++;
  }
  CHECK_EQ(ts.mmap_depth, 2, "mmap depth=2 nested");
  CHECK_EQ(ts.alloc_depth, 1, "alloc depth unchanged");
  PASS();
}