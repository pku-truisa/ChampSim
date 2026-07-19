/*
 * Memory Object Statistics Printer
 * Outputs per-object cache/TLB/DRAM statistics sorted by object size (descending)
 * Objects or sections with no access data are omitted from output.
 *
 * Also outputs per-caller-IP aggregated statistics to a separate file.
 */

#include <algorithm>
#include <fstream>
#include <map>
#include <unordered_map>
#include <unordered_set>
#include <vector>
#include <fmt/core.h>
#include <fmt/ostream.h>

#include "access_type.h"
#include "memory_object_table.h"
#include "util/to_underlying.h"

namespace {

// Check if a PerCacheStats record has any non-zero data
inline bool has_any_data(const PerCacheStats& st)
{
  for (int i = 0; i < 5; ++i)
    if (st.hits[i] > 0 || st.misses[i] > 0)
      return true;
  if (st.mshr_merge > 0 || st.mshr_return > 0)
    return true;
  if (st.pf_requested > 0 || st.pf_issued > 0 || st.pf_useful > 0 || st.pf_useless > 0 || st.pf_fill > 0)
    return true;
  return false;
}

// Check if a PerDRAMStats record has any non-zero data
inline bool has_any_data(const PerDRAMStats& st)
{
  if (st.rq_row_buffer_hit > 0 || st.rq_row_buffer_miss > 0)
    return true;
  if (st.wq_row_buffer_hit > 0 || st.wq_row_buffer_miss > 0)
    return true;
  if (st.wq_full > 0)
    return true;
  if (st.dbus_cycle_congested > 0 || st.dbus_count_congested > 0)
    return true;
  return false;
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
    fmt::print(os, "    AVG_MISS_LAT={:.2f}\n", static_cast<double>(st.total_miss_latency) / static_cast<double>(total_misses));
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
               static_cast<double>(st.dbus_cycle_congested) / static_cast<double>(st.dbus_count_congested));
  } else {
    fmt::print(os, "    AVG_DBUS_CONGESTED=-\n");
  }
}

// ---------------------------------------------------------------------------
// Aggregated per-caller-IP statistics
// ---------------------------------------------------------------------------

// Data structure for one caller_ip group
struct GroupedCallerIPStats {
  uint64_t caller_ip = 0;
  uint64_t object_count = 0;
  uint64_t total_size = 0;
  std::map<std::string, PerCacheStats> cache_stats;  // aggregated per cache name
  std::map<std::string, PerDRAMStats> dram_stats;    // aggregated per DRAM name
};

// Add a single object's stats into the group
void add_object_to_group(GroupedCallerIPStats& grp, const MemoryObjectTable::ObjectRecord& obj)
{
  grp.object_count++;
  grp.total_size += obj.size;

  // Aggregate cache stats
  for (const auto& [cname, cstats] : obj.cache_stats) {
    auto& dst = grp.cache_stats[cname];
    for (int i = 0; i < 5; ++i) {
      dst.hits[i] += cstats.hits[i];
      dst.misses[i] += cstats.misses[i];
    }
    dst.mshr_merge += cstats.mshr_merge;
    dst.mshr_return += cstats.mshr_return;
    dst.total_miss_latency += cstats.total_miss_latency;
    dst.pf_requested += cstats.pf_requested;
    dst.pf_issued += cstats.pf_issued;
    dst.pf_useful += cstats.pf_useful;
    dst.pf_useless += cstats.pf_useless;
    dst.pf_fill += cstats.pf_fill;
  }

  // Aggregate DRAM stats
  for (const auto& [dname, dstats] : obj.dram_stats) {
    auto& dst = grp.dram_stats[dname];
    dst.rq_row_buffer_hit += dstats.rq_row_buffer_hit;
    dst.rq_row_buffer_miss += dstats.rq_row_buffer_miss;
    dst.wq_row_buffer_hit += dstats.wq_row_buffer_hit;
    dst.wq_row_buffer_miss += dstats.wq_row_buffer_miss;
    dst.wq_full += dstats.wq_full;
    dst.dbus_cycle_congested += dstats.dbus_cycle_congested;
    dst.dbus_count_congested += dstats.dbus_count_congested;
  }
}

void print_caller_ip_grouped_stats(const std::string& output_path)
{
  std::ofstream out(output_path);
  if (!out) {
    fmt::print(stderr, "[MOL] ERROR: Cannot open output file: {}\n", output_path);
    return;
  }

  const auto& all_objects = mol_table.get_all_objects();

  // Group objects by caller_ip
  std::unordered_map<uint64_t, GroupedCallerIPStats> groups_map;
  for (const auto& obj : all_objects) {
    uint64_t ip = obj.caller_ip;
    auto it = groups_map.find(ip);
    if (it == groups_map.end()) {
      GroupedCallerIPStats grp;
      grp.caller_ip = ip;
      add_object_to_group(grp, obj);
      groups_map[ip] = grp;
    } else {
      add_object_to_group(it->second, obj);
    }
  }

  if (groups_map.empty()) {
    fmt::print(out, "No memory objects recorded.\n");
    return;
  }

  // Move groups into a vector for sorting
  std::vector<GroupedCallerIPStats*> groups;
  groups.reserve(groups_map.size());
  for (auto& [ip, grp] : groups_map) {
    groups.push_back(&grp);
  }

  // Sort by total_size descending
  std::sort(groups.begin(), groups.end(), [](const GroupedCallerIPStats* a, const GroupedCallerIPStats* b) {
    return a->total_size > b->total_size;
  });

  // Collect sorted cache/dram names (preserve order of first appearance)
  std::vector<std::string> cache_names_sorted;
  std::vector<std::string> dram_names_sorted;
  {
    std::unordered_set<std::string> seen_cache, seen_dram;
    for (const auto* grp : groups) {
      for (const auto& [cname, _] : grp->cache_stats) {
        if (seen_cache.find(cname) == seen_cache.end()) {
          cache_names_sorted.push_back(cname);
          seen_cache.insert(cname);
        }
      }
      for (const auto& [dname, _] : grp->dram_stats) {
        if (seen_dram.find(dname) == seen_dram.end()) {
          dram_names_sorted.push_back(dname);
          seen_dram.insert(dname);
        }
      }
    }
  }

  fmt::print(out, "=== Aggregated Memory Object Statistics by Caller IP ({} unique IPs) ===\n\n",
             groups.size());

  for (const auto* grp : groups) {
    fmt::print(out, "Caller IP=0x{:x}  Objects={}  TotalSize={}\n", grp->caller_ip, grp->object_count, grp->total_size);
    fmt::print(out, "{:-<80}\n", "");

    // Cache/TLB stats
    for (const auto& cname : cache_names_sorted) {
      auto it = grp->cache_stats.find(cname);
      if (it != grp->cache_stats.end() && has_any_data(it->second)) {
        fmt::print(out, "  [{}]\n", cname);
        print_cache_stats(out, it->second);
      }
    }

    // DRAM stats
    for (const auto& dname : dram_names_sorted) {
      auto it = grp->dram_stats.find(dname);
      if (it != grp->dram_stats.end() && has_any_data(it->second)) {
        fmt::print(out, "  [{}]\n", dname);
        print_dram_stats(out, it->second);
      }
    }

    fmt::print(out, "\n");
  }

  fmt::print("[MOL] Aggregated caller-IP stats written to: {} ({} unique IPs)\n", output_path, groups.size());
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

  auto cache_names = mol_table.get_known_cache_names();
  auto dram_names = mol_table.get_known_dram_names();

  fmt::print(out, "=== Memory Object Statistics ({} objects, sorted by size descending) ===\n\n", sorted.size());

  uint64_t printed_count = 0;
  for (const auto& obj : sorted) {
    // Collect which cache levels actually have data for this object
    std::vector<std::string> active_cache_names;
    for (const auto& cname : cache_names) {
      auto it = obj.cache_stats.find(cname);
      if (it != obj.cache_stats.end() && has_any_data(it->second)) {
        active_cache_names.push_back(cname);
      }
    }

    // Collect which DRAM channels actually have data for this object
    std::vector<std::string> active_dram_names;
    for (const auto& dname : dram_names) {
      auto it = obj.dram_stats.find(dname);
      if (it != obj.dram_stats.end() && has_any_data(it->second)) {
        active_dram_names.push_back(dname);
      }
    }

    // Skip objects with no data at all
    if (active_cache_names.empty() && active_dram_names.empty()) {
      continue;
    }

    printed_count++;
    fmt::print(out, "Object ID={}  Type={}  Size={}  VA_Start=0x{:x}  Caller=0x{:x}\n", obj.alloc_id, malloc_type_name(static_cast<malloc_type>(obj.alloc_type)), obj.size,
               obj.vaddr_start.to<uint64_t>(), obj.caller_ip);
    fmt::print(out, "{:-<80}\n", "");

    // Cache/TLB stats (only if the object has data for this cache)
    for (const auto& cname : active_cache_names) {
      fmt::print(out, "  [{}]\n", cname);
      auto it = obj.cache_stats.find(cname);
      print_cache_stats(out, it->second);
    }

    // DRAM stats (only if the object has data for this DRAM channel)
    for (const auto& dname : active_dram_names) {
      fmt::print(out, "  [{}]\n", dname);
      auto it = obj.dram_stats.find(dname);
      print_dram_stats(out, it->second);
    }

    fmt::print(out, "\n");
  }

  fmt::print("[MOL] Memory object statistics written to: {} ({} objects with data)\n", filename, printed_count);

  // Also output aggregated per-caller-IP stats
  const auto& prefix = mol_table.get_trace_prefix();
  std::string caller_ip_file = prefix.empty() ? "caller_ip_status.txt" : prefix + "_caller_ip_status.txt";
  print_caller_ip_grouped_stats(caller_ip_file);
}