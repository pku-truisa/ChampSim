/*
 * Memory Object Statistics Printer
 * Outputs per-object cache/TLB/DRAM statistics sorted by object size (descending)
 */

#include <algorithm>
#include <fstream>
#include <vector>
#include <fmt/core.h>
#include <fmt/ostream.h>

#include "access_type.h"
#include "memory_object_table.h"
#include "util/to_underlying.h"

namespace {

// Helper: collect all cache names across all objects
std::vector<std::string> collect_cache_names(const std::vector<MemoryObjectTable::ObjectRecord>& objects)
{
  std::vector<std::string> names;
  for (const auto& obj : objects) {
    for (const auto& [name, stats] : obj.cache_stats) {
      if (std::find(names.begin(), names.end(), name) == names.end()) {
        names.push_back(name);
      }
    }
  }
  return names;
}

// Helper: collect all DRAM names across all objects
std::vector<std::string> collect_dram_names(const std::vector<MemoryObjectTable::ObjectRecord>& objects)
{
  std::vector<std::string> names;
  for (const auto& obj : objects) {
    for (const auto& [name, stats] : obj.dram_stats) {
      if (std::find(names.begin(), names.end(), name) == names.end()) {
        names.push_back(name);
      }
    }
  }
  return names;
}

void print_cache_stats(std::ostream& os, const PerCacheStats& st)
{
  // Per access_type hits and misses
  fmt::print(os, "    LOAD:     HIT={:>10}  MISS={:<10}\n", st.hits[champsim::to_underlying(access_type::LOAD)],
             st.misses[champsim::to_underlying(access_type::LOAD)]);
  fmt::print(os, "    RFO:      HIT={:>10}  MISS={:<10}\n", st.hits[champsim::to_underlying(access_type::RFO)],
             st.misses[champsim::to_underlying(access_type::RFO)]);
  fmt::print(os, "    PREFETCH: HIT={:>10}  MISS={:<10}\n", st.hits[champsim::to_underlying(access_type::PREFETCH)],
             st.misses[champsim::to_underlying(access_type::PREFETCH)]);
  fmt::print(os, "    WRITE:    HIT={:>10}  MISS={:<10}\n", st.hits[champsim::to_underlying(access_type::WRITE)],
             st.misses[champsim::to_underlying(access_type::WRITE)]);
  fmt::print(os, "    TRANS:    HIT={:>10}  MISS={:<10}\n", st.hits[champsim::to_underlying(access_type::TRANSLATION)],
             st.misses[champsim::to_underlying(access_type::TRANSLATION)]);

  // MSHR and latency
  fmt::print(os, "    MSHR_MERGE={:<10}  MSHR_RETURN={:<10}\n", st.mshr_merge, st.mshr_return);

  uint64_t total_misses = 0;
  for (int i = 0; i < 5; ++i)
    total_misses += st.misses[i];
  if (total_misses > 0) {
    fmt::print(os, "    AVG_MISS_LAT={:.2f}\n", static_cast<double>(st.total_miss_latency) / total_misses);
  } else {
    fmt::print(os, "    AVG_MISS_LAT=-\n");
  }

  // Prefetch stats
  fmt::print(os, "    PF_REQ={:<10}  PF_ISSUED={:<10}  PF_USEFUL={:<10}  PF_USELESS={:<10}  PF_FILL={:<10}\n", st.pf_requested, st.pf_issued, st.pf_useful,
             st.pf_useless, st.pf_fill);
}

void print_dram_stats(std::ostream& os, const PerDRAMStats& st)
{
  fmt::print(os, "    RQ_ROW_HIT={:<10}  RQ_ROW_MISS={:<10}\n", st.rq_row_buffer_hit, st.rq_row_buffer_miss);
  fmt::print(os, "    WQ_ROW_HIT={:<10}  WQ_ROW_MISS={:<10}\n", st.wq_row_buffer_hit, st.wq_row_buffer_miss);
  fmt::print(os, "    WQ_FULL={}\n", st.wq_full);
  if (st.dbus_count_congested > 0) {
    fmt::print(os, "    AVG_DBUS_CONGESTED={:.2f}\n",
               static_cast<double>(st.dbus_cycle_congested) / st.dbus_count_congested);
  } else {
    fmt::print(os, "    AVG_DBUS_CONGESTED=-\n");
  }
}

} // namespace

void print_memory_object_stats(const std::string& filename)
{
  std::ofstream out(filename);
  if (!out) {
    fmt::print(stderr, "[MOL] ERROR: Cannot open output file: {}\n", filename);
    return;
  }

  const auto& all_objects = mol_table.get_all_objects();

  if (all_objects.empty()) {
    fmt::print(out, "No memory objects recorded.\n");
    return;
  }

  // Make a copy and sort by size descending
  auto sorted = all_objects;
  std::sort(sorted.begin(), sorted.end(), [](const auto& a, const auto& b) { return a.size > b.size; });

  auto cache_names = collect_cache_names(all_objects);
  auto dram_names = collect_dram_names(all_objects);

  fmt::print(out, "=== Memory Object Statistics ({} objects, sorted by size descending) ===\n\n", sorted.size());

  for (const auto& obj : sorted) {
    fmt::print(out, "Object ID={}  Type={}  Size={}  VA_Start=0x{:x}\n", obj.alloc_id, malloc_type_name(static_cast<malloc_type>(obj.alloc_type)), obj.size,
               obj.vaddr_start.to<uint64_t>());
    fmt::print(out, "{:-<80}\n", "");

    // Cache/TLB stats
    for (const auto& cname : cache_names) {
      auto it = obj.cache_stats.find(cname);
      if (it != obj.cache_stats.end()) {
        fmt::print(out, "  [{}]\n", cname);
        print_cache_stats(out, it->second);
      }
    }

    // DRAM stats
    for (const auto& dname : dram_names) {
      auto it = obj.dram_stats.find(dname);
      if (it != obj.dram_stats.end()) {
        fmt::print(out, "  [{}]\n", dname);
        print_dram_stats(out, it->second);
      }
    }

    fmt::print(out, "\n");
  }

  fmt::print("[MOL] Memory object statistics written to: {}\n", filename);
}