#include "dram_stats.h"

#include "memory_object_table.h"

dram_stats operator-(dram_stats lhs, dram_stats rhs)
{
  lhs.dbus_cycle_congested -= rhs.dbus_cycle_congested;
  lhs.dbus_count_congested -= rhs.dbus_count_congested;
  lhs.WQ_ROW_BUFFER_HIT -= rhs.WQ_ROW_BUFFER_HIT;
  lhs.WQ_ROW_BUFFER_MISS -= rhs.WQ_ROW_BUFFER_MISS;
  lhs.RQ_ROW_BUFFER_HIT -= rhs.RQ_ROW_BUFFER_HIT;
  lhs.RQ_ROW_BUFFER_MISS -= rhs.RQ_ROW_BUFFER_MISS;
  lhs.WQ_FULL -= rhs.WQ_FULL;
  return lhs;
}

// Helper: lookup per-object DRAM stats by PA
static PerDRAMStats* mol_lookup_dram(champsim::address pa, const std::string& dram_name)
{
  auto ppage_val = pa.to<uint64_t>() >> LOG2_PAGE_SIZE;
  champsim::page_number ppage{ppage_val};
  uint64_t alloc_id = mol_table.lookup_alloc_id_by_pa(ppage);
  if (alloc_id > 0) {
    return &mol_table.get_dram_stats(alloc_id, dram_name);
  }
  return nullptr;
}

void dram_stats::record_row_hit(champsim::address pa, bool is_write, bool warmup)
{
  if (is_write) {
    ++WQ_ROW_BUFFER_HIT;
  } else {
    ++RQ_ROW_BUFFER_HIT;
  }
  if (!warmup) {
    auto* st = mol_lookup_dram(pa, name);
    if (st) {
      if (is_write) {
        ++st->wq_row_buffer_hit;
      } else {
        ++st->rq_row_buffer_hit;
      }
    }
  }
}

void dram_stats::record_row_miss(champsim::address pa, bool is_write, bool warmup)
{
  if (is_write) {
    ++WQ_ROW_BUFFER_MISS;
  } else {
    ++RQ_ROW_BUFFER_MISS;
  }
  if (!warmup) {
    auto* st = mol_lookup_dram(pa, name);
    if (st) {
      if (is_write) {
        ++st->wq_row_buffer_miss;
      } else {
        ++st->rq_row_buffer_miss;
      }
    }
  }
}