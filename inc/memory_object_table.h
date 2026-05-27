/*
 * Memory Object Table - Tracks memory allocations and per-object statistics
 *
 * Maintains three internal structures:
 *   1. active_objects - currently allocated VA ranges (sorted by vaddr_start)
 *   2. ppage_to_vpage  - reverse page table: physical page → virtual page
 *   3. all_objects     - all historical allocations with per-object statistics
 *
 * tracereader → record_alloc() / record_free() → active_objects + all_objects
 * VirtualMemory::va_to_pa() → register_mapping() → ppage_to_vpage
 * Cache/DRAM → lookup_alloc_id_by_pa() → find object → accumulate stats
 */

#ifndef MEMORY_OBJECT_TABLE_H
#define MEMORY_OBJECT_TABLE_H

#include <cstdint>
#include <map>
#include <string>
#include <vector>

#include "access_type.h"
#include "address.h"
#include "champsim.h"

// Memory allocation event types (matching input_instr.is_malloc)
enum class malloc_type : uint8_t {
  NORMAL = 0,
  MALLOC = 1,
  FREE = 2,
  MMAP = 3,
  MUNMAP = 4,
  CALLOC = 5,
  REALLOC = 6,
  ALIGNED_ALLOC = 7,
  POSIX_MEMALIGN = 8,
  MEMALIGN = 9,
};

inline const char* malloc_type_name(malloc_type t)
{
  switch (t) {
    case malloc_type::NORMAL: return "NORMAL";
    case malloc_type::MALLOC: return "MALLOC";
    case malloc_type::FREE: return "FREE";
    case malloc_type::MMAP: return "MMAP";
    case malloc_type::MUNMAP: return "MUNMAP";
    case malloc_type::CALLOC: return "CALLOC";
    case malloc_type::REALLOC: return "REALLOC";
    case malloc_type::ALIGNED_ALLOC: return "ALIGNED_ALLOC";
    case malloc_type::POSIX_MEMALIGN: return "POSIX_MEMALIGN";
    case malloc_type::MEMALIGN: return "MEMALIGN";
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
  };

  // Historical record of all allocations with per-object statistics
  struct ObjectRecord {
    champsim::address vaddr_start;
    uint64_t size;
    uint8_t alloc_type;
    uint64_t alloc_id;
    std::map<std::string, PerCacheStats> cache_stats;  // key: cache name (L1D, L1I, L2, LLC, PTW, ...)
    std::map<std::string, PerDRAMStats> dram_stats;    // key: DRAM channel name
  };

  // Called by tracereader when is_malloc > 0 (alloc event)
  uint64_t record_alloc(champsim::address vaddr, uint64_t size, uint8_t alloc_type);

  // Called by tracereader when is_malloc == 2 (free) or 4 (munmap)
  void record_free(champsim::address vaddr);

  // Called by VirtualMemory::va_to_pa() after translation
  void register_mapping(champsim::page_number vpage, champsim::page_number ppage);

  // Called by Cache/DRAM to find which object owns a physical page
  // Returns alloc_id (0 if no active object found for this page)
  uint64_t lookup_alloc_id_by_pa(champsim::page_number ppage) const;

  // Access the per-object stats by alloc_id
  PerCacheStats& get_cache_stats(uint64_t alloc_id, const std::string& cache_name);
  PerDRAMStats& get_dram_stats(uint64_t alloc_id, const std::string& dram_name);

  // Get all object records (for output)
  const std::vector<ObjectRecord>& get_all_objects() const { return all_objects; }

private:
  // Structure 1: active VA ranges (sorted by vaddr_start)
  std::vector<ActiveObject> active_objects;

  // Structure 2: reverse page table (PA page → VA page)
  std::map<champsim::page_number, champsim::page_number> ppage_to_vpage;

  // Structure 3: all historical allocations with stats
  std::vector<ObjectRecord> all_objects;

  // ID counter
  uint64_t next_alloc_id = 1;

  // Find active object by VA (binary search in active_objects)
  const ActiveObject* find_active_by_va(champsim::address vaddr) const;

  // Find ObjectRecord by alloc_id
  ObjectRecord* find_record(uint64_t alloc_id);
};

// Global singleton instance
extern MemoryObjectTable mol_table;

// Output per-object statistics to a file (sorted by size descending)
void print_memory_object_stats(const std::string& filename);

#endif
