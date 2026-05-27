#ifndef DRAM_STATS_H
#define DRAM_STATS_H

#include <cstdint>
#include <string>

#include "address.h"

struct dram_stats {
  std::string name{};
  long dbus_cycle_congested{};
  uint64_t dbus_count_congested = 0;
  uint64_t refresh_cycles = 0;
  unsigned WQ_ROW_BUFFER_HIT = 0, WQ_ROW_BUFFER_MISS = 0, RQ_ROW_BUFFER_HIT = 0, RQ_ROW_BUFFER_MISS = 0, WQ_FULL = 0;

  // Extended recording methods that also update per-object stats via mol_table
  void record_row_hit(champsim::address pa, bool is_write, bool warmup);
  void record_row_miss(champsim::address pa, bool is_write, bool warmup);
};

dram_stats operator-(dram_stats lhs, dram_stats rhs);

#endif