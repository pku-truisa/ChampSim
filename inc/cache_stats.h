#ifndef CACHE_STATS_H
#define CACHE_STATS_H

#include <cstdint>
#include <string>
#include <type_traits>
#include <utility>

#include "address.h"
#include "channel.h"
#include "event_counter.h"

struct cache_stats {
  std::string name;
  // prefetch stats
  uint64_t pf_requested = 0;
  uint64_t pf_issued = 0;
  uint64_t pf_useful = 0;
  uint64_t pf_useless = 0;
  uint64_t pf_fill = 0;

  champsim::stats::event_counter<std::pair<access_type, std::remove_cv_t<decltype(NUM_CPUS)>>> hits = {};
  champsim::stats::event_counter<std::pair<access_type, std::remove_cv_t<decltype(NUM_CPUS)>>> misses = {};
  champsim::stats::event_counter<std::pair<access_type, std::remove_cv_t<decltype(NUM_CPUS)>>> mshr_merge = {};
  champsim::stats::event_counter<std::pair<access_type, std::remove_cv_t<decltype(NUM_CPUS)>>> mshr_return = {};

  long total_miss_latency_cycles{};

  // Extended recording methods that also update per-object stats via mol_table
  // Each method: (a) records the original stat, (b) if not warmup, looks up
  // the object from PA and accumulates per-object stats.
  void record_hit(access_type type, uint32_t cpu, champsim::address pa, bool warmup);
  void record_miss(access_type type, uint32_t cpu, champsim::address pa, bool warmup);
  void record_mshr_merge(access_type type, uint32_t cpu, champsim::address pa, bool warmup);
  void record_mshr_return(access_type type, uint32_t cpu, champsim::address pa, bool warmup);
  void record_miss_latency(champsim::address pa, long latency, bool warmup);
  void record_pf_requested(champsim::address pa, bool warmup);
  void record_pf_issued(champsim::address pa, bool warmup);
  void record_pf_useful(champsim::address pa, bool warmup);
  void record_pf_useless(champsim::address pa, bool warmup);
  void record_pf_fill(champsim::address pa, bool warmup);
};

cache_stats operator-(cache_stats lhs, cache_stats rhs);

#endif