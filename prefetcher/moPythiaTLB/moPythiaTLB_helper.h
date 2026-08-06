//=======================================================================================//
// File             : moPythiaTLB/moPythiaTLB_helper.h
// Author           : Based on moPythia (Memory Object aware Pythia)
// Date             : 03/AUG/2026
// Description      : Implements helper functionalities for moPythiaTLB - Memory Object
//                    aware Pythia with an internal PrefetchTLB to reduce STLB pressure.
//=======================================================================================//

#ifndef __MO_PYTHIA_TLB_HELPER_H__
#define __MO_PYTHIA_TLB_HELPER_H__

#include <bitset>
#include <cstdint>
#include <deque>
#include <unordered_set>
#include <vector>

#include "moPythiaTLB_params.h"

#define Bitmap std::bitset<64UL>

namespace moptlb {

typedef enum {
  none = 0,
  incorrect,
  correct_untimely,
  correct_timely,
  out_of_bounds,

  num_rewards
} RewardType;

const char* getRewardTypeString(RewardType type);
inline bool isRewardCorrect(RewardType type) { return (type == correct_timely || type == correct_untimely); }
inline bool isRewardIncorrect(RewardType type) { return type == incorrect; }

//----------------------------------------------------//
// PrefetchTLB: an internal L1-like TLB used by the
// prefetcher to track which pages are known to have
// valid translations. Demand accesses and fills insert
// entries; prefetch predictions consult it to learn
// whether the destination page is already translated,
// which reduces pointless STLB lookups.
//----------------------------------------------------//
class PrefetchTLB
{
public:
  struct TLBEntry {
    uint64_t vpn;
    bool valid;
    uint32_t lru;
    TLBEntry() : vpn(0), valid(false), lru(0) {}
  };

private:
  uint32_t m_sets;
  uint32_t m_ways;
  std::vector<std::vector<TLBEntry>> m_entries;

  uint32_t get_set(uint64_t vpn) const { return vpn % m_sets; }

public:
  PrefetchTLB() : m_sets(MO_PYTHIA_TLB::prefetch_tlb_sets), m_ways(MO_PYTHIA_TLB::prefetch_tlb_ways)
  {
    m_entries.resize(m_sets, std::vector<TLBEntry>(m_ways));
  }

  ~PrefetchTLB() {}

  /* Returns true if the page is present in the PrefetchTLB.
   * On a hit, updates the LRU state of the set. */
  bool lookup(uint64_t vpn)
  {
    uint32_t set = get_set(vpn);
    for (uint32_t way = 0; way < m_ways; ++way) {
      if (m_entries[set][way].valid && m_entries[set][way].vpn == vpn) {
        m_entries[set][way].lru = 0;
        for (uint32_t w = 0; w < m_ways; ++w) {
          if (w != way && m_entries[set][w].valid) {
            m_entries[set][w].lru++;
          }
        }
        return true;
      }
    }
    return false;
  }

  /* Insert or refresh an entry for the given page. */
  void fill(uint64_t vpn)
  {
    uint32_t set = get_set(vpn);
    for (uint32_t way = 0; way < m_ways; ++way) {
      if (m_entries[set][way].valid && m_entries[set][way].vpn == vpn) {
        m_entries[set][way].lru = 0;
        for (uint32_t w = 0; w < m_ways; ++w) {
          if (w != way && m_entries[set][w].valid) {
            m_entries[set][w].lru++;
          }
        }
        return;
      }
    }

    /* Find an invalid way first, otherwise the LRU victim */
    uint32_t victim = 0;
    uint32_t max_lru = 0;
    for (uint32_t way = 0; way < m_ways; ++way) {
      if (!m_entries[set][way].valid) {
        victim = way;
        break;
      }
      if (m_entries[set][way].lru > max_lru) {
        max_lru = m_entries[set][way].lru;
        victim = way;
      }
    }

    m_entries[set][victim].vpn = vpn;
    m_entries[set][victim].valid = true;
    m_entries[set][victim].lru = 0;
    for (uint32_t way = 0; way < m_ways; ++way) {
      if (way != victim && m_entries[set][way].valid) {
        m_entries[set][way].lru++;
      }
    }
  }
};

class State
{
public:
  uint64_t pc;
  uint64_t address;
  uint64_t page;
  uint32_t offset;
  int32_t delta;
  uint32_t local_delta_sig2;
  uint32_t local_pc_sig;
  uint32_t local_offset_sig;
  bool is_high_bw;

  /* Memory object aware features */
  uint64_t alloc_id;
  uint64_t alloc_offset;
  uint32_t object_path_sig;

  /* PrefetchTLB aware feature: whether the destination page of the
   * predicted prefetch is already present in the internal PrefetchTLB */
  bool dest_page_in_prefetch_tlb;

  /* Add more states here */

  void reset()
  {
    pc = 0xdeadbeef;
    address = 0xdeadbeef;
    page = 0xdeadbeef;
    offset = 0;
    delta = 0;
    local_delta_sig2 = 0;
    local_pc_sig = 0;
    local_offset_sig = 0;
    is_high_bw = false;
    alloc_id = 0;
    alloc_offset = 0;
    object_path_sig = 0;
    dest_page_in_prefetch_tlb = false;
  }
  State() { reset(); }
  ~State() {}
  std::string to_string();
};

class ActionTracker
{
public:
  int32_t action;
  int32_t conf;
  ActionTracker(int32_t act, int32_t c) : action(act), conf(c) {}
  ~ActionTracker() {}
};

class Scooby_STEntry
{
public:
  uint64_t page;
  std::deque<uint64_t> pcs;
  std::deque<uint64_t> alloc_ids;
  std::deque<uint32_t> offsets;
  std::deque<int32_t> deltas;
  Bitmap bmp_pred;
  uint64_t trigger_pc;
  uint32_t trigger_offset;
  bool streaming;

  /* tracks last n actions on a page to determine degree */
  std::deque<ActionTracker*> action_tracker;
  std::unordered_set<int32_t> action_with_max_degree;
  std::unordered_set<int32_t> afterburning_actions;

  uint32_t total_prefetches;

public:
  Scooby_STEntry(uint64_t p, uint64_t pc, uint32_t offset) : page(p)
  {
    pcs.clear();
    alloc_ids.clear();
    offsets.clear();
    deltas.clear();
    bmp_pred.reset();
    trigger_pc = pc;
    trigger_offset = offset;
    streaming = false;

    pcs.push_back(pc);
    offsets.push_back(offset);
  }
  ~Scooby_STEntry() {}
  uint32_t get_delta_sig2();
  uint32_t get_pc_sig();
  uint32_t get_offset_sig();
  uint32_t get_object_sig();
  void update(uint64_t page, uint64_t pc, uint32_t offset, uint64_t address);
  void update_alloc_id(uint64_t page, uint64_t alloc_id, uint32_t offset, uint64_t address);
  void track_prefetch(uint32_t offset, int32_t pref_offset);
  void insert_action_tracker(int32_t pref_offset);
  bool search_action_tracker(int32_t action, int32_t& conf);
};

class Scooby_PTEntry
{
public:
  uint64_t address;
  State* state;
  uint32_t action_index;
  /* set when prefetched line is filled into cache
   * check during reward to measure timeliness */
  bool is_filled;
  /* set when prefetched line is alredy found in cache
   * donotes extreme untimely prefetch */
  bool pf_cache_hit;
  int32_t reward;
  RewardType reward_type;
  bool has_reward;
  std::vector<bool> consensus_vec; // only used in featurewise engine

  Scooby_PTEntry(uint64_t ad, State* st, uint32_t ac) : address(ad), state(st), action_index(ac)
  {
    is_filled = false;
    pf_cache_hit = false;
    reward = 0;
    reward_type = RewardType::none;
    has_reward = false;
  }
  ~Scooby_PTEntry() {}
};

typedef struct _stats {
  struct {
    uint64_t lookup;
    uint64_t hit;
    uint64_t evict;
    uint64_t insert;
    uint64_t streaming;
  } st;

  struct {
    uint64_t called;
    uint64_t out_of_bounds;
    uint64_t action_dist[MO_PYTHIA_TLB::max_actions];
    uint64_t issue_dist[MO_PYTHIA_TLB::max_actions];
    uint64_t pred_hit[MO_PYTHIA_TLB::max_actions];
    uint64_t out_of_bounds_dist[MO_PYTHIA_TLB::max_actions];
    uint64_t predicted;
    uint64_t multi_deg;
    uint64_t multi_deg_called;
    uint64_t multi_deg_histogram[MO_PYTHIA_TLB::max_degree + 1];
    uint64_t deg_histogram[MO_PYTHIA_TLB::max_degree + 1];
  } predict;

  struct {
    uint64_t called;
    uint64_t same_address;
    uint64_t evict;
  } track;

  struct {
    struct {
      uint64_t called;
      uint64_t pt_not_found;
      uint64_t pt_found;
      uint64_t pt_found_total;
      uint64_t has_reward;
    } demand;

    struct {
      uint64_t called;
    } train;

    struct {
      uint64_t called;
    } assign_reward;

    struct {
      uint64_t dist[MO_PYTHIA_TLB::max_rewards][2];
    } compute_reward;

    uint64_t correct_timely;
    uint64_t correct_untimely;
    uint64_t no_pref;
    uint64_t incorrect;
    uint64_t out_of_bounds;
    uint64_t tracker_hit;
    uint64_t dist[MO_PYTHIA_TLB::max_actions][MO_PYTHIA_TLB::max_rewards];
  } reward;

  struct {
    uint64_t called;
    uint64_t compute_reward;
  } train;

  struct {
    uint64_t called;
    uint64_t set;
    uint64_t set_total;
  } register_fill;

  struct {
    uint64_t called;
    uint64_t set;
    uint64_t set_total;
  } register_prefetch_hit;

  struct {
    uint64_t scooby;
  } pref_issue;

  struct {
    uint64_t epochs;
    uint64_t histogram[MO_PYTHIA_TLB::max_dram_bw_levels];
  } bandwidth;

  /* PrefetchTLB stats */
  struct {
    uint64_t lookup;
    uint64_t hit;
    uint64_t miss;
    uint64_t fill;
    uint64_t evict;
  } prefetch_tlb;
} PythiaStats;

} // namespace moptlb

#endif /* __MO_PYTHIA_TLB_HELPER_H__ */