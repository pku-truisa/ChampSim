/*
 * Memory Object Statistics Printer
 * Outputs per-object cache statistics sorted by object size (descending)
 * Objects with no access data are omitted from output.
 *
 * Format matches the global stats output format from plain_printer.cc.
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

void print_cache_stats(std::ostream& os, const std::string& cache_name, const PerCacheStats& st)
{
  // Calculate totals across all access types
  uint64_t total_hits = 0, total_misses = 0;
  for (int i = 0; i < 5; ++i) {
    total_hits += st.hits[i];
    total_misses += st.misses[i];
  }
  uint64_t total_access = total_hits + total_misses;

  // TOTAL line
  fmt::print(os, "cpu0->{} {:<12s} ACCESS: {:10d} HIT: {:10d} MISS: {:10d} MSHR_MERGE: {:10d}\n",
             cache_name, "TOTAL", total_access, total_hits, total_misses, st.mshr_merge);

  // Per access_type lines (matching plain_printer.cc format)
  constexpr std::array types{access_type::LOAD, access_type::RFO, access_type::PREFETCH, access_type::WRITE, access_type::TRANSLATION};
  for (const auto type : types) {
    auto idx = champsim::to_underlying(type);
    uint64_t hits = st.hits[idx];
    uint64_t misses = st.misses[idx];
    uint64_t access = hits + misses;
    fmt::print(os, "cpu0->{} {:<12s} ACCESS: {:10d} HIT: {:10d} MISS: {:10d} MSHR_MERGE: {:10d}\n",
               cache_name, access_type_names.at(idx), access, hits, misses, st.mshr_merge);
  }

  // Prefetch stats line (matching plain_printer.cc: PREFETCH REQUESTED / ISSUED / USEFUL / USELESS)
  fmt::print(os, "cpu0->{} PREFETCH REQUESTED: {:10} ISSUED: {:10} USEFUL: {:10} USELESS: {:10}\n",
             cache_name, st.pf_requested, st.pf_issued, st.pf_useful, st.pf_useless);

  // Average miss latency line
  if (total_misses > 0) {
    double avg = static_cast<double>(st.total_miss_latency) / static_cast<double>(total_misses);
    fmt::print(os, "cpu0->{} AVERAGE MISS LATENCY: {:.2f} cycles\n", cache_name, avg);
  } else {
    fmt::print(os, "cpu0->{} AVERAGE MISS LATENCY: - cycles\n", cache_name);
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

  // Use fixed output order: L1D, L2C, LLC (substring match)
  const std::string patterns[] = {"L1D", "L2C", "LLC"};
  std::vector<std::string> cache_names_sorted;
  for (const auto& pat : patterns) {
    for (const auto& [cname, _] : groups.front()->cache_stats) {
      if (cname.find(pat) != std::string::npos) {
        cache_names_sorted.push_back(cname);
        break;
      }
    }
  }

  fmt::print(out, "=== Aggregated Memory Object Statistics by Caller IP ({} unique IPs) ===\n\n",
             groups.size());

  for (const auto* grp : groups) {
    fmt::print(out, "Caller IP=0x{:x}  Objects={}  TotalSize={}\n", grp->caller_ip, grp->object_count, grp->total_size);
    fmt::print(out, "{:-<80}\n", "");

    // Cache/TLB stats (flat format)
    for (const auto& cname : cache_names_sorted) {
      auto it = grp->cache_stats.find(cname);
      if (it != grp->cache_stats.end() && has_any_data(it->second)) {
        print_cache_stats(out, cname, it->second);
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

  fmt::print(out, "=== Memory Object Statistics ({} objects, sorted by size descending) ===\n\n", sorted.size());

  uint64_t printed_count = 0;
  for (const auto& obj : sorted) {
    // Collect which cache levels actually have data for this object
    // Output order: L1D, L2C, LLC only (substring match, e.g. "cpu0_L1D" matches "L1D")
    std::vector<std::string> active_cache_names;
    const std::string order[] = {"L1D", "L2C", "LLC"};
    for (const auto& pat : order) {
      for (const auto& [cname, cstats] : obj.cache_stats) {
        if (cname.find(pat) != std::string::npos && has_any_data(cstats)) {
          active_cache_names.push_back(cname);
          break;
        }
      }
    }

    // Skip objects with no cache data at all
    if (active_cache_names.empty()) {
      continue;
    }

    printed_count++;
    fmt::print(out, "Object ID={}  Type={}  Size={}  VA_Start=0x{:x}  Caller=0x{:x}\n", obj.alloc_id, malloc_type_name(static_cast<malloc_type>(obj.alloc_type)), obj.size,
               obj.vaddr_start.to<uint64_t>(), obj.caller_ip);
    fmt::print(out, "{:-<80}\n", "");

    // Cache/TLB stats in flat format matching plain_printer.cc
    for (const auto& cname : active_cache_names) {
      auto it = obj.cache_stats.find(cname);
      print_cache_stats(out, cname, it->second);
    }

    fmt::print(out, "\n");
  }

  fmt::print("[MOL] Memory object statistics written to: {} ({} objects with data)\n", filename, printed_count);

  // Output unmatched (no object mapping) access statistics
  {
    const auto& unmatched = mol_table.get_unmatched_record();
    std::vector<std::string> unmatched_cache_names;
    const std::string unmatched_order[] = {"L1D", "L2C", "LLC"};
    for (const auto& pat : unmatched_order) {
      for (const auto& [cname, cstats] : unmatched.cache_stats) {
        if (cname.find(pat) != std::string::npos && has_any_data(cstats)) {
          unmatched_cache_names.push_back(cname);
          break;
        }
      }
    }

    if (!unmatched_cache_names.empty()) {
      fmt::print(out, "Object ID=UNMATCHED  Type=-  Size=-  VA_Start=-  Caller=-\n");
      fmt::print(out, "{:-<80}\n", "");
      for (const auto& cname : unmatched_cache_names) {
        auto it = unmatched.cache_stats.find(cname);
        print_cache_stats(out, cname, it->second);
      }
      fmt::print(out, "\n");
    }
  }

  // Output TOTAL (all objects + unmatched) statistics
  {
    PerCacheStats total_l1d, total_l2c, total_llc;
    const std::string total_order[] = {"L1D", "L2C", "LLC"};

    // Aggregate from all objects
    for (const auto& obj : sorted) {
      for (const auto& [cname, cstats] : obj.cache_stats) {
        PerCacheStats* dst = nullptr;
        if (cname.find("L1D") != std::string::npos) dst = &total_l1d;
        else if (cname.find("L2C") != std::string::npos) dst = &total_l2c;
        else if (cname.find("LLC") != std::string::npos) dst = &total_llc;
        else continue;

        for (int i = 0; i < 5; ++i) {
          dst->hits[i] += cstats.hits[i];
          dst->misses[i] += cstats.misses[i];
        }
        dst->mshr_merge += cstats.mshr_merge;
        dst->mshr_return += cstats.mshr_return;
        dst->total_miss_latency += cstats.total_miss_latency;
        dst->pf_requested += cstats.pf_requested;
        dst->pf_issued += cstats.pf_issued;
        dst->pf_useful += cstats.pf_useful;
        dst->pf_useless += cstats.pf_useless;
        dst->pf_fill += cstats.pf_fill;
      }
    }

    // Aggregate from unmatched
    {
      const auto& unmatched = mol_table.get_unmatched_record();
      for (const auto& [cname, cstats] : unmatched.cache_stats) {
        PerCacheStats* dst = nullptr;
        if (cname.find("L1D") != std::string::npos) dst = &total_l1d;
        else if (cname.find("L2C") != std::string::npos) dst = &total_l2c;
        else if (cname.find("LLC") != std::string::npos) dst = &total_llc;
        else continue;

        for (int i = 0; i < 5; ++i) {
          dst->hits[i] += cstats.hits[i];
          dst->misses[i] += cstats.misses[i];
        }
        dst->mshr_merge += cstats.mshr_merge;
        dst->mshr_return += cstats.mshr_return;
        dst->total_miss_latency += cstats.total_miss_latency;
        dst->pf_requested += cstats.pf_requested;
        dst->pf_issued += cstats.pf_issued;
        dst->pf_useful += cstats.pf_useful;
        dst->pf_useless += cstats.pf_useless;
        dst->pf_fill += cstats.pf_fill;
      }
    }

    // Determine which cache names exist in total stats
    std::vector<std::pair<std::string, PerCacheStats*>> total_entries;
    const std::string total_cache_patterns[] = {"L1D", "L2C", "LLC"};
    PerCacheStats* total_stats[] = {&total_l1d, &total_l2c, &total_llc};
    for (int i = 0; i < 3; ++i) {
      if (has_any_data(*total_stats[i])) {
        // Find the actual cache name from any object or unmatched
        std::string actual_name;
        for (const auto& obj : sorted) {
          for (const auto& [cname, _] : obj.cache_stats) {
            if (cname.find(total_cache_patterns[i]) != std::string::npos) {
              actual_name = cname;
              break;
            }
          }
          if (!actual_name.empty()) break;
        }
        if (actual_name.empty()) {
          const auto& unmatched = mol_table.get_unmatched_record();
          for (const auto& [cname, _] : unmatched.cache_stats) {
            if (cname.find(total_cache_patterns[i]) != std::string::npos) {
              actual_name = cname;
              break;
            }
          }
        }
        if (!actual_name.empty()) {
          total_entries.emplace_back(actual_name, total_stats[i]);
        }
      }
    }

    if (!total_entries.empty()) {
      fmt::print(out, "Object ID=TOTAL  Type=-  Size=-  VA_Start=-  Caller=-\n");
      fmt::print(out, "{:-<80}\n", "");
      for (const auto& [cname, st] : total_entries) {
        print_cache_stats(out, cname, *st);
      }
      fmt::print(out, "\n");
    }
  }

  // Also output aggregated per-caller-IP stats
  const auto& prefix = mol_table.get_trace_prefix();
  std::string caller_ip_file = prefix.empty() ? "caller_ip_status.txt" : prefix + "_caller_ip_status.txt";
  print_caller_ip_grouped_stats(caller_ip_file);
}