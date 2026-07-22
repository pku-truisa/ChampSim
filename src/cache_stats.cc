#include "cache_stats.h"

#include "memory_object_table.h"
#include "util/to_underlying.h"

cache_stats operator-(cache_stats lhs, cache_stats rhs)
{
  cache_stats result;
  result.pf_requested = lhs.pf_requested - rhs.pf_requested;
  result.pf_issued = lhs.pf_issued - rhs.pf_issued;
  result.pf_useful = lhs.pf_useful - rhs.pf_useful;
  result.pf_useless = lhs.pf_useless - rhs.pf_useless;
  result.pf_fill = lhs.pf_fill - rhs.pf_fill;

  result.hits = lhs.hits - rhs.hits;
  result.misses = lhs.misses - rhs.misses;

  result.total_miss_latency_cycles = lhs.total_miss_latency_cycles - rhs.total_miss_latency_cycles;
  return result;
}

// Helper: get ppage and lookup alloc_id, then get per-object cache stats
// Uses VA first (preferred, avoids PA reuse issues), falls back to PA.
static PerCacheStats* mol_lookup_cache(champsim::address va, champsim::address pa, const std::string& cache_name)
{
  uint64_t alloc_id = 0;
  if (static_cast<uint64_t>(va.to<uint64_t>()) != 0) {
    // VA-based lookup: find which active object owns this virtual address
    alloc_id = mol_table.lookup_alloc_id_by_va(va);
  }
  if (alloc_id == 0) {
    // Fallback to PA-based lookup
    auto ppage_val = pa.to<uint64_t>() >> LOG2_PAGE_SIZE;
    champsim::page_number ppage{ppage_val};
    alloc_id = mol_table.lookup_alloc_id_by_pa(ppage);
  }
  if (alloc_id > 0) {
    return &mol_table.get_cache_stats(alloc_id, cache_name);
  }
  return nullptr;
}

void cache_stats::record_hit(access_type type, uint32_t cpu, champsim::address va, champsim::address pa, bool warmup)
{
  hits.increment(std::pair{type, cpu});
  if (!warmup) {
    auto* st = mol_lookup_cache(va, pa, name);
    if (st) {
      auto idx = champsim::to_underlying(type);
      if (idx < 5) {
        ++st->hits[idx];
      }
    }
  }
}

void cache_stats::record_miss(access_type type, uint32_t cpu, champsim::address va, champsim::address pa, bool warmup)
{
  misses.increment(std::pair{type, cpu});
  if (!warmup) {
    auto* st = mol_lookup_cache(va, pa, name);
    if (st) {
      auto idx = champsim::to_underlying(type);
      if (idx < 5) {
        ++st->misses[idx];
      }
    }
  }
}

void cache_stats::record_mshr_merge(access_type type, uint32_t cpu, champsim::address va, champsim::address pa, bool warmup)
{
  mshr_merge.increment(std::pair{type, cpu});
  if (!warmup) {
    auto* st = mol_lookup_cache(va, pa, name);
    if (st) {
      ++st->mshr_merge;
    }
  }
}

void cache_stats::record_mshr_return(access_type type, uint32_t cpu, champsim::address va, champsim::address pa, bool warmup)
{
  mshr_return.increment(std::pair{type, cpu});
  if (!warmup) {
    auto* st = mol_lookup_cache(va, pa, name);
    if (st) {
      ++st->mshr_return;
    }
  }
}

void cache_stats::record_miss_latency(champsim::address va, champsim::address pa, long latency, bool warmup)
{
  total_miss_latency_cycles += latency;
  if (!warmup) {
    auto* st = mol_lookup_cache(va, pa, name);
    if (st) {
      st->total_miss_latency += latency;
    }
  }
}

void cache_stats::record_pf_requested(champsim::address va, champsim::address pa, bool warmup)
{
  ++pf_requested;
  if (!warmup) {
    auto* st = mol_lookup_cache(va, pa, name);
    if (st) {
      ++st->pf_requested;
    }
  }
}

void cache_stats::record_pf_issued(champsim::address va, champsim::address pa, bool warmup)
{
  ++pf_issued;
  if (!warmup) {
    auto* st = mol_lookup_cache(va, pa, name);
    if (st) {
      ++st->pf_issued;
    }
  }
}

void cache_stats::record_pf_useful(champsim::address va, champsim::address pa, bool warmup)
{
  ++pf_useful;
  if (!warmup) {
    auto* st = mol_lookup_cache(va, pa, name);
    if (st) {
      ++st->pf_useful;
    }
  }
}

void cache_stats::record_pf_useless(champsim::address va, champsim::address pa, bool warmup)
{
  ++pf_useless;
  if (!warmup) {
    auto* st = mol_lookup_cache(va, pa, name);
    if (st) {
      ++st->pf_useless;
    }
  }
}

void cache_stats::record_pf_fill(champsim::address va, champsim::address pa, bool warmup)
{
  ++pf_fill;
  if (!warmup) {
    auto* st = mol_lookup_cache(va, pa, name);
    if (st) {
      ++st->pf_fill;
    }
  }
}