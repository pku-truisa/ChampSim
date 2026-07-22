/*
 * Memory Object Table - Tracks memory allocations and per-object statistics
 *
 * Maintains four internal structures:
 *   1. active_objects - currently allocated VA ranges (sorted by vaddr_start via map)
 *   2. ppage_to_allocid - reverse page table: physical page → alloc_id
 *   3. all_objects     - all historical allocations with per-object statistics
 *   4. allocid_to_record - fast index: alloc_id → ObjectRecord* (O(log n) lookup)
 *
 * tracereader → record_alloc() / record_free() → active_objects + all_objects
 * VirtualMemory::va_to_pa() → register_mapping() → ppage_to_allocid
 * Cache/DRAM → lookup_alloc_id_by_va() → find object → accumulate stats
 */

#ifndef MEMORY_OBJECT_TABLE_H
#define MEMORY_OBJECT_TABLE_H

#include <cstdint>
#include <map>
#include <string>
#include <unordered_map>
#include <vector>

#include "access_type.h"
#include "address.h"
#include "champsim.h"

// Memory allocation event types
// These values MUST match the instr_info encoding produced by
// champsim_object_tracer.cpp (tracer/pin-object/):
//   1= malloc,  2= calloc,  3= realloc,  4= free,
//   5= mmap,    6= mmap64,  7= mremap,   8= munmap,
//   9= main-begin,  10= posix_memalign,  11= aligned_alloc
enum class malloc_type : uint8_t {
  NORMAL = 0,
  MALLOC = 1,
  CALLOC = 2,
  REALLOC = 3,
  FREE = 4,
  MMAP = 5,
  MMAP64 = 6,
  MREMAP = 7,
  MUNMAP = 8,
  MAIN_BEGIN = 9,
  POSIX_MEMALIGN = 10,
  ALIGNED_ALLOC = 11,
};

inline const char* malloc_type_name(malloc_type t)
{
  switch (t) {
    case malloc_type::NORMAL: return "NORMAL";
    case malloc_type::MALLOC: return "MALLOC";
    case malloc_type::CALLOC: return "CALLOC";
    case malloc_type::REALLOC: return "REALLOC";
    case malloc_type::FREE: return "FREE";
    case malloc_type::MMAP: return "MMAP";
    case malloc_type::MMAP64: return "MMAP64";
    case malloc_type::MREMAP: return "MREMAP";
    case malloc_type::MUNMAP: return "MUNMAP";
    case malloc_type::MAIN_BEGIN: return "MAIN_BEGIN";
    case malloc_type::POSIX_MEMALIGN: return "POSIX_MEMALIGN";
    case malloc_type::ALIGNED_ALLOC: return "ALIGNED_ALLOC";
    default: return "UNKNOWN";
  }
}

// Per-cache-level statistics for a single object
struct PerCacheStats {
  // Access counts by access_type (indexed by to_underlying(access_type))
  uint64_t hits[5] = {};   // LOAD, RFO, PREFETCH, WRITE, TRANSLATION
  uint64_t misses[5] = {};
  uint64_t mshr_merge = 0;
  uint64_t mshr_return = 0;
  long total_miss_latency = 0;

  // Prefetch statistics
  uint64_t pf_requested = 0;
  uint64_t pf_issued = 0;
  uint64_t pf_useful = 0;
  uint64_t pf_useless = 0;
  uint64_t pf_fill = 0;
};

// Per-DRAM-channel statistics for a single object
struct PerDRAMStats {
  uint64_t rq_row_buffer_hit = 0;
  uint64_t rq_row_buffer_miss = 0;
  uint64_t wq_row_buffer_hit = 0;
  uint64_t wq_row_buffer_miss = 0;
  uint64_t wq_full = 0;
  long dbus_cycle_congested = 0;
  uint64_t dbus_count_congested = 0;
};

class MemoryObjectTable {
public:
  // An active allocation (currently allocated, not yet freed)
  struct ActiveObject {
    champsim::address vaddr_start;
    champsim::address vaddr_end; // exclusive
    uint8_t alloc_type;          // from input_instr.is_malloc
    uint64_t alloc_id;
    uint64_t size;
    uint64_t caller_ip = 0;      // return address from the allocator call site
  };

  // Historical record of all allocations with per-object statistics
  struct ObjectRecord {
    champsim::address vaddr_start;
    uint64_t size;
    uint8_t alloc_type;
    uint64_t alloc_id;
    uint64_t caller_ip = 0;      // return address from the allocator call site
    std::map<std::string, PerCacheStats> cache_stats;  // key: cache name (L1D, L1I, L2, LLC, PTW, ...)
    std::map<std::string, PerDRAMStats> dram_stats;    // key: DRAM channel name
  };

  // Called by tracereader when is_malloc > 0 (alloc event)
  uint64_t record_alloc(champsim::address vaddr, uint64_t size, uint8_t alloc_type, uint64_t caller_ip = 0);

  // Called by tracereader when is_malloc == 2 (free) or 4 (munmap)
  void record_free(champsim::address vaddr);

  // Called by VirtualMemory::va_to_pa() after translation
  void register_mapping(champsim::page_number vpage, champsim::page_number ppage);

  // Called by Cache/DRAM to find which object owns a physical page
  // Returns alloc_id (0 if no mapping found for this page)
  uint64_t lookup_alloc_id_by_pa(champsim::page_number ppage) const;

  // Called by Cache/DRAM to find which object owns a virtual address
  // Uses page-aligned address lookup in active_objects for O(log n) search
  uint64_t lookup_alloc_id_by_va(champsim::address vaddr) const;

  // Access the per-object stats by alloc_id
  PerCacheStats& get_cache_stats(uint64_t alloc_id, const std::string& cache_name);
  PerDRAMStats& get_dram_stats(uint64_t alloc_id, const std::string& dram_name);

  // Get all object records (for output)
  const std::vector<ObjectRecord>& get_all_objects() const { return all_objects; }


  // Register known cache/DRAM names (for output, ensures all-zero stats are also printed)
  void register_cache_name(const std::string& name) { known_cache_names.push_back(name); }
  void register_dram_name(const std::string& name) { known_dram_names.push_back(name); }
  const std::vector<std::string>& get_known_cache_names() const { return known_cache_names; }
  const std::vector<std::string>& get_known_dram_names() const { return known_dram_names; }

  // Trace prefix for output filenames (e.g. "bfs-3")
  void set_trace_prefix(const std::string& prefix) { trace_prefix = prefix; }
  const std::string& get_trace_prefix() const { return trace_prefix; }

private:
  // Structure 1: active VA ranges (sorted by vaddr_start, using map for O(log n) insert/erase)
  // Keyed by vaddr_start to enable efficient overlap queries and insertion.
  std::map<champsim::address, ActiveObject> active_objects;

  // Structure 2: direct PA page → alloc_id mapping (replaces old two-step ppage_to_vpage)
  std::map<champsim::page_number, uint64_t> ppage_to_allocid;

  // Structure 3: all historical allocations with stats
  std::vector<ObjectRecord> all_objects;

  // Structure 4: fast index for alloc_id → ObjectRecord lookup (O(1) instead of O(N))
  // Uses vector index (not pointer) to avoid invalidation from vector reallocation
  std::unordered_map<uint64_t, std::size_t> allocid_to_record;

  // Known cache/DRAM channel names for output (even if all stats are zero)
  std::vector<std::string> known_cache_names;
  std::vector<std::string> known_dram_names;

  // Trace prefix for output filenames
  std::string trace_prefix;

  // ID counter
  uint64_t next_alloc_id = 1;

  // Find active object by VA (binary search in active_objects)
  const ActiveObject* find_active_by_va(champsim::address vaddr) const;

  // Find alloc_id by VA page overlap (active objects only)
  uint64_t find_alloc_id_by_va(champsim::address vaddr) const;

  // Find ObjectRecord by alloc_id (uses fast index)
  ObjectRecord* find_record(uint64_t alloc_id);
};

// Global singleton instance
extern MemoryObjectTable mol_table;

// Output per-object statistics to a file (sorted by size descending)
void print_memory_object_stats(const std::string& filename);

#endif