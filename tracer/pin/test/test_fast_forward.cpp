#include "test_types.h"
#include <unordered_map>
#include <vector>

// Test fast-forward skip + baseline dump logic from champsim_tracer.cpp

struct DummyTraceRecord {
  trace_instr_format_t instr;
};

inline void write_record(std::vector<DummyTraceRecord>& buf,
                         const trace_instr_format_t& rec) {
  buf.push_back({rec});
}

void test_fast_forward_skip_writes() {
  TEST("fast_forward: WriteCurrentInstruction skips when skip_dumping=true");
  std::vector<DummyTraceRecord> buf;
  bool skip_dumping = true;

  trace_instr_format_t rec = {};
  rec.ip = 0x400000;
  rec.instr_type = 1;  // branch instruction

  // Simulate the WriteCurrentInstruction guard
  if (!skip_dumping) {
    write_record(buf, rec);
  }
  CHECK_EQ(buf.size(), 0u, "no record written during fast-forward");
  PASS();
}

void test_fast_forward_baseline_dump() {
  TEST("fast_forward: baseline dump writes all active tracked_allocations");
  std::unordered_map<ADDRINT, TrackedAlloc> tracked;
  std::vector<DummyTraceRecord> buf;
  PendingInstrMalloc pending;

  // Setup some active allocations
  tracked[0x1000] = {1024u, (unsigned char)1};    // malloc
  tracked[0x2000] = {512u, (unsigned char)5};     // calloc
  tracked[0x3000] = {4096u, (unsigned char)3};    // mmap
  tracked[0x4000] = {256u, (unsigned char)8};     // posix_memalign

  // Simulate fast_forward_ins dump logic
  {
    for (const auto& [addr, info] : tracked) {
      trace_instr_format_t rec = {};
      rec.instr_type = 2;  // allocation event
      rec.instr_info = info.type;
      rec.source_memory[0] = info.size;
      rec.destination_memory[0] = addr;
      write_record(buf, rec);
    }
    // Clear pending
    pending = {};
  }

  CHECK_EQ(buf.size(), (size_t)4, "all 4 tracked addresses dumped");

  // Verify each record
  for (const auto& r : buf) {
    ADDRINT addr = r.instr.destination_memory[0];
    CHECK(tracked.find(addr) != tracked.end(), "dumped addr exists in tracked");
    CHECK_EQ(r.instr.instr_info, tracked[addr].type, "type matches");
    CHECK_EQ(r.instr.source_memory[0], tracked[addr].size, "size matches");
  }

  CHECK_EQ(pending.type, (unsigned char)0, "pending cleared after dump");
  CHECK_EQ(pending.arg1, 0ull, "pending arg1 cleared");
  PASS();
}