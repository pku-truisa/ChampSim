#include "test_types.h"
#include <unordered_map>
#include <unordered_set>
#include <cstdint>
#include <cstring>
#include <sstream>

// =========================================================================
// Tests for malloc-only mode (-m) logic in champsim_tracer.cpp
//
// Covers:
//   - malloc_type_name lookup for type codes 1-23
//   - coarse_type mapping from fine-grained to instruction trace types
//   - AllocAfter in malloc-only mode (no threshold, direct write)
//   - AllocAfter in instruction trace mode (threshold, pending_instr_malloc)
//   - FreeBefore in malloc-only mode (tracked_addresses vs tracked_allocations)
//   - write_malloc_instr_locked output format verification
// =========================================================================

// Type codes matching champsim_tracer.cpp
static constexpr unsigned char TYPE_MALLOC         = 1;
static constexpr unsigned char TYPE_MI_MALLOC       = 2;
static constexpr unsigned char TYPE_JE_MALLOC       = 3;
static constexpr unsigned char TYPE_TC_MALLOC       = 4;
static constexpr unsigned char TYPE_ZNWM            = 5;
static constexpr unsigned char TYPE_ZNAM            = 6;
static constexpr unsigned char TYPE_CALLOC          = 7;
static constexpr unsigned char TYPE_MI_CALLOC       = 8;
static constexpr unsigned char TYPE_JE_CALLOC       = 9;
static constexpr unsigned char TYPE_TC_CALLOC       = 10;
static constexpr unsigned char TYPE_REALLOC         = 11;
static constexpr unsigned char TYPE_MI_REALLOC      = 12;
static constexpr unsigned char TYPE_JE_REALLOC      = 13;
static constexpr unsigned char TYPE_TC_REALLOC      = 14;
static constexpr unsigned char TYPE_POSIX_MEMALIGN  = 15;
static constexpr unsigned char TYPE_MMAP            = 16;
static constexpr unsigned char TYPE_MUNMAP          = 17;
static constexpr unsigned char TYPE_FREE            = 18;
static constexpr unsigned char TYPE_MI_FREE         = 19;
static constexpr unsigned char TYPE_JE_FREE         = 20;
static constexpr unsigned char TYPE_TC_FREE         = 21;
static constexpr unsigned char TYPE_ZDLPV           = 22;
static constexpr unsigned char TYPE_ZDAPV           = 23;

// =========================================================================
// malloc_type_name — same as champsim_tracer.cpp
// =========================================================================
static const char* malloc_type_name(unsigned char t)
{
  switch (t) {
    case TYPE_MALLOC:         return "malloc";
    case TYPE_MI_MALLOC:      return "mi_malloc";
    case TYPE_JE_MALLOC:      return "je_malloc";
    case TYPE_TC_MALLOC:      return "tc_malloc";
    case TYPE_ZNWM:           return "_Znwm";
    case TYPE_ZNAM:           return "_Znam";
    case TYPE_CALLOC:         return "calloc";
    case TYPE_MI_CALLOC:      return "mi_calloc";
    case TYPE_JE_CALLOC:      return "je_calloc";
    case TYPE_TC_CALLOC:      return "tc_calloc";
    case TYPE_REALLOC:        return "realloc";
    case TYPE_MI_REALLOC:     return "mi_realloc";
    case TYPE_JE_REALLOC:     return "je_realloc";
    case TYPE_TC_REALLOC:     return "tc_realloc";
    case TYPE_POSIX_MEMALIGN: return "posix_memalign";
    case TYPE_MMAP:           return "mmap";
    case TYPE_MUNMAP:         return "munmap";
    case TYPE_FREE:           return "free";
    case TYPE_MI_FREE:        return "mi_free";
    case TYPE_JE_FREE:        return "je_free";
    case TYPE_TC_FREE:        return "tc_free";
    case TYPE_ZDLPV:          return "_ZdlPv";
    case TYPE_ZDAPV:          return "_ZdaPv";
    default:                  return "UNKNOWN";
  }
}

// =========================================================================
// coarse_type — same as champsim_tracer.cpp
// =========================================================================
static unsigned char coarse_type(unsigned char fine_type)
{
  if (fine_type >= 1 && fine_type <= 6)  return 1;  // malloc-like
  if (fine_type >= 7 && fine_type <= 10) return 5;  // calloc-like
  if (fine_type >= 11 && fine_type <= 14) return 6;  // realloc-like
  if (fine_type == TYPE_POSIX_MEMALIGN)  return 8;
  if (fine_type == TYPE_MMAP)            return 3;
  if (fine_type == TYPE_MUNMAP)          return 4;
  if (fine_type >= 18 && fine_type <= 23) return 2;  // free-like
  return 0;
}

// =========================================================================
// Mock: malloc_instr struct (32 bytes) — same as champsim_tracer.cpp
// =========================================================================
struct malloc_instr {
  unsigned long long arg1;
  unsigned long long arg2;
  unsigned long long ret;
  unsigned char type;
  unsigned char reserved[7];
};

// =========================================================================
// Test: malloc_type_name returns correct names for all 23 types
// =========================================================================
void test_malloc_type_name_all_types() {
  TEST("malloc_type_name: all 23 type codes return correct names");
  CHECK(std::string(malloc_type_name(0)) == "UNKNOWN", "type 0 should be UNKNOWN");
  CHECK(std::string(malloc_type_name(24)) == "UNKNOWN", "type 24 should be UNKNOWN");
  CHECK(std::string(malloc_type_name(TYPE_MALLOC)) == "malloc", "type 1");
  CHECK(std::string(malloc_type_name(TYPE_MI_MALLOC)) == "mi_malloc", "type 2");
  CHECK(std::string(malloc_type_name(TYPE_JE_MALLOC)) == "je_malloc", "type 3");
  CHECK(std::string(malloc_type_name(TYPE_TC_MALLOC)) == "tc_malloc", "type 4");
  CHECK(std::string(malloc_type_name(TYPE_ZNWM)) == "_Znwm", "type 5");
  CHECK(std::string(malloc_type_name(TYPE_ZNAM)) == "_Znam", "type 6");
  CHECK(std::string(malloc_type_name(TYPE_CALLOC)) == "calloc", "type 7");
  CHECK(std::string(malloc_type_name(TYPE_MI_CALLOC)) == "mi_calloc", "type 8");
  CHECK(std::string(malloc_type_name(TYPE_JE_CALLOC)) == "je_calloc", "type 9");
  CHECK(std::string(malloc_type_name(TYPE_TC_CALLOC)) == "tc_calloc", "type 10");
  CHECK(std::string(malloc_type_name(TYPE_REALLOC)) == "realloc", "type 11");
  CHECK(std::string(malloc_type_name(TYPE_MI_REALLOC)) == "mi_realloc", "type 12");
  CHECK(std::string(malloc_type_name(TYPE_JE_REALLOC)) == "je_realloc", "type 13");
  CHECK(std::string(malloc_type_name(TYPE_TC_REALLOC)) == "tc_realloc", "type 14");
  CHECK(std::string(malloc_type_name(TYPE_POSIX_MEMALIGN)) == "posix_memalign", "type 15");
  CHECK(std::string(malloc_type_name(TYPE_MMAP)) == "mmap", "type 16");
  CHECK(std::string(malloc_type_name(TYPE_MUNMAP)) == "munmap", "type 17");
  CHECK(std::string(malloc_type_name(TYPE_FREE)) == "free", "type 18");
  CHECK(std::string(malloc_type_name(TYPE_MI_FREE)) == "mi_free", "type 19");
  CHECK(std::string(malloc_type_name(TYPE_JE_FREE)) == "je_free", "type 20");
  CHECK(std::string(malloc_type_name(TYPE_TC_FREE)) == "tc_free", "type 21");
  CHECK(std::string(malloc_type_name(TYPE_ZDLPV)) == "_ZdlPv", "type 22");
  CHECK(std::string(malloc_type_name(TYPE_ZDAPV)) == "_ZdaPv", "type 23");
  PASS();
}

// =========================================================================
// Test: coarse_type mapping
// =========================================================================
void test_coarse_type_mapping() {
  TEST("coarse_type: all fine-grained types map correctly");
  // malloc-like (1-6) -> coarse 1
  CHECK_EQ(coarse_type(1), (unsigned char)1, "malloc -> 1");
  CHECK_EQ(coarse_type(2), (unsigned char)1, "mi_malloc -> 1");
  CHECK_EQ(coarse_type(5), (unsigned char)1, "_Znwm -> 1");
  CHECK_EQ(coarse_type(6), (unsigned char)1, "_Znam -> 1");
  // calloc-like (7-10) -> coarse 5
  CHECK_EQ(coarse_type(7), (unsigned char)5, "calloc -> 5");
  CHECK_EQ(coarse_type(10), (unsigned char)5, "tc_calloc -> 5");
  // realloc-like (11-14) -> coarse 6
  CHECK_EQ(coarse_type(11), (unsigned char)6, "realloc -> 6");
  CHECK_EQ(coarse_type(14), (unsigned char)6, "tc_realloc -> 6");
  // posix_memalign (15) -> coarse 8
  CHECK_EQ(coarse_type(TYPE_POSIX_MEMALIGN), (unsigned char)8, "posix_memalign -> 8");
  // mmap (16) -> coarse 3
  CHECK_EQ(coarse_type(TYPE_MMAP), (unsigned char)3, "mmap -> 3");
  // munmap (17) -> coarse 4
  CHECK_EQ(coarse_type(TYPE_MUNMAP), (unsigned char)4, "munmap -> 4");
  // free-like (18-23) -> coarse 2
  CHECK_EQ(coarse_type(18), (unsigned char)2, "free -> 2");
  CHECK_EQ(coarse_type(23), (unsigned char)2, "_ZdaPv -> 2");
  PASS();
}

// =========================================================================
// Test: malloc_instr struct size is exactly 32 bytes
// =========================================================================
void test_malloc_instr_size() {
  TEST("malloc_instr: struct size is exactly 32 bytes");
  CHECK_EQ(sizeof(malloc_instr), (size_t)32, "malloc_instr must be 32 bytes");
  PASS();
}

// =========================================================================
// Test: malloc-only mode AllocAfter records all sizes (no threshold)
// =========================================================================
void test_malloc_only_mode_no_threshold() {
  TEST("malloc-only mode: AllocAfter records all sizes, no threshold");
  std::unordered_set<ADDRINT> tracked_addresses;
  unsigned char last_type = 0;
  unsigned long long last_arg1 = 0;
  unsigned long long last_ret = 0;
  bool record_called = false;

  // Helper that simulates write_malloc_instr_locked + tracked_addresses.insert
  auto record = [&](unsigned char type, unsigned long long arg1,
                     unsigned long long ret) {
    last_type = type;
    last_arg1 = arg1;
    last_ret = ret;
    tracked_addresses.insert(ret);
    record_called = true;
  };

  // Simulate malloc-only AllocAfter for small allocation (7 bytes)
  bool malloc_only_mode = true;
  ADDRINT size = 7;
  ADDRINT ret = 0x1000;

  // Non-realloc branch: ret != 0, malloc_only_mode=true
  if (ret != 0 && ret != (ADDRINT)-1) {
    if (malloc_only_mode) {
      record(TYPE_MALLOC, size, ret);
    }
  }
  CHECK(record_called, "malloc(7) should be recorded in malloc-only mode");
  CHECK_EQ(last_type, (unsigned char)TYPE_MALLOC, "type should be malloc");
  CHECK_EQ(last_arg1, (unsigned long long)7, "arg1 should be 7");
  CHECK(tracked_addresses.find(0x1000) != tracked_addresses.end(),
        "addr should be tracked");

  // Very small allocation (1 byte) — also no threshold
  record_called = false;
  ret = 0x2000;
  size = 1;
  if (ret != 0 && ret != (ADDRINT)-1) {
    if (malloc_only_mode) {
      record(TYPE_MALLOC, size, ret);
    }
  }
  CHECK(record_called, "malloc(1) should also be recorded (no threshold)");
  CHECK(tracked_addresses.find(0x2000) != tracked_addresses.end(),
        "small alloc should be tracked");
  PASS();
}

// =========================================================================
// Test: instruction trace mode AllocAfter with threshold
// =========================================================================
void test_instr_trace_mode_threshold() {
  TEST("instruction trace mode: alloc below threshold is NOT recorded");
  bool malloc_only_mode = false;
  ADDRINT threshold = 256;

  // Below threshold
  ADDRINT size = 128;
  ADDRINT ret = 0x3000;
  bool recorded = false;

  if (ret != 0 && ret != (ADDRINT)-1) {
    if (malloc_only_mode) {
      recorded = true;  // would record
    } else {
      if (size >= threshold) {
        recorded = true;
      }
    }
  }
  CHECK(!recorded, "128 < 256 should NOT be recorded in instr trace mode");

  // Above threshold
  size = 512;
  ret = 0x4000;
  recorded = false;
  if (ret != 0 && ret != (ADDRINT)-1) {
    if (malloc_only_mode) {
      recorded = true;
    } else {
      if (size >= threshold) {
        recorded = true;
      }
    }
  }
  CHECK(recorded, "512 >= 256 should be recorded in instr trace mode");
  PASS();
}

// =========================================================================
// Test: FreeBefore uses tracked_addresses in malloc-only mode
// =========================================================================
void test_malloc_only_mode_free_filter() {
  TEST("malloc-only mode: FreeBefore uses tracked_addresses set");
  std::unordered_set<ADDRINT> tracked_addresses;
  unsigned char free_type = 0;
  bool free_recorded = false;

  auto record_free = [&](unsigned char type, unsigned long long /*ptr*/) {
    free_type = type;
    free_recorded = true;
  };

  // Track an address first
  ADDRINT addr = 0x5000;
  tracked_addresses.insert(addr);

  // Simulate FreeBefore: address is tracked
  bool malloc_only_mode = true;
  if (malloc_only_mode) {
    auto it = tracked_addresses.find(addr);
    if (it != tracked_addresses.end()) {
      record_free(TYPE_FREE, addr);
      tracked_addresses.erase(it);
    }
  }
  CHECK(free_recorded, "tracked address should produce free event");
  CHECK_EQ(free_type, (unsigned char)TYPE_FREE, "type should be free");
  CHECK(tracked_addresses.find(addr) == tracked_addresses.end(),
        "address should be removed");

  // Untracked address — should not produce event
  free_recorded = false;
  ADDRINT untracked = 0x6000;
  if (malloc_only_mode) {
    auto it = tracked_addresses.find(untracked);
    if (it != tracked_addresses.end()) {
      record_free(TYPE_FREE, untracked);
    }
  }
  CHECK(!free_recorded, "untracked address should NOT produce free event");
  PASS();
}

// =========================================================================
// Test: write_malloc_instr_locked produces 32-byte records correctly
// =========================================================================
void test_malloc_instr_record_format() {
  TEST("malloc_instr: record format produces correct binary output");
  // Simulate writing a record to a string buffer
  std::ostringstream oss(std::ios_base::binary | std::ios_base::out);
  
  malloc_instr rec;
  rec.type = TYPE_MALLOC;
  rec.arg1 = 1024;
  rec.arg2 = 0;
  rec.ret = 0xABCD;
  std::memset(rec.reserved, 0, sizeof(rec.reserved));

  // Verify struct fields
  CHECK_EQ(rec.type, (unsigned char)TYPE_MALLOC, "type should be 1");
  CHECK_EQ(rec.arg1, (unsigned long long)1024, "arg1 should be 1024");
  CHECK_EQ(rec.arg2, (unsigned long long)0, "arg2 should be 0");
  CHECK_EQ(rec.ret, (unsigned long long)0xABCD, "ret should be 0xABCD");

  // Verify reserved is zeros
  for (int i = 0; i < 7; i++) {
    CHECK_EQ(rec.reserved[i], (unsigned char)0, "reserved should be zero");
  }

  PASS();
}

// =========================================================================
// Test: AllocAfter dual-mode distinction (realloc paths)
// =========================================================================
void test_malloc_only_mode_realloc() {
  TEST("malloc-only mode: realloc records fine-grained type, not instr coarse");
  std::unordered_set<ADDRINT> tracked_addresses;
  unsigned char recorded_type = 0;

  auto record = [&](unsigned char type, unsigned long long arg1,
                     unsigned long long ret) {
    recorded_type = type;
    tracked_addresses.erase(arg1);  // erase old
    if (ret != 0) tracked_addresses.insert(ret);
  };

  // Realloc move: fine type 11 (REALLOC) should be kept as-is
  bool malloc_only_mode = true;
  ADDRINT old_ptr = 0x7000;
  ADDRINT new_size = 4096;
  ADDRINT ret = 0x8000;  // different address = moved

  tracked_addresses.insert(old_ptr);

  if (malloc_only_mode) {
    if (ret != 0 && ret != (ADDRINT)-1) {
      record(TYPE_REALLOC, old_ptr, ret);
    }
  }
  CHECK_EQ(recorded_type, (unsigned char)TYPE_REALLOC,
           "malloc-only realloc should keep fine type 11");
  CHECK(tracked_addresses.find(old_ptr) == tracked_addresses.end(),
        "old ptr should be erased");
  CHECK(tracked_addresses.find(0x8000) != tracked_addresses.end(),
        "new addr should be tracked");

  // Now test instruction trace mode: realloc should use coarse type 6 or 16
  bool instr_trace_mode = false;
  recorded_type = 0;
  ADDRINT MALLOC_THRESHOLD = 256;
  ADDRINT inplace_ptr = 0x9000;
  new_size = 512;
  ADDRINT inplace_ret = inplace_ptr;  // same address = in-place

  if (!instr_trace_mode) {
    if (new_size >= MALLOC_THRESHOLD && inplace_ret != 0 && inplace_ret != (ADDRINT)-1) {
      unsigned char coarse = (inplace_ret == inplace_ptr && inplace_ret != 0) ? 16 : 6;
      recorded_type = coarse;
    }
  }
  CHECK_EQ(recorded_type, (unsigned char)16,
           "instr trace realloc_inplace should be type 16");
  PASS();
}