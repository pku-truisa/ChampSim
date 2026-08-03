//=======================================================================================//
// File             : moPythia/moPythia.h
// Author           : Based on Pythia (Bera+, MICRO'21)
// Date             : 03/AUG/2026
// Description      : Implements moPythia - Memory Object aware Pythia prefetcher
//=======================================================================================//

#ifndef __MO_PYTHIA_H__
#define __MO_PYTHIA_H__

#include <deque>

#include "champsim.h"
#include "learning_engine_featurewise.h"
#include "modules.h"
#include "moPythia_helper.h"

struct moPythia : public champsim::modules::prefetcher {
private:
  std::deque<mop::Scooby_STEntry*> signature_table;
  mop::moLearningEngineFeaturewise* brain_featurewise;
  std::deque<mop::Scooby_PTEntry*> prefetch_tracker;
  mop::Scooby_PTEntry* last_evicted_tracker;

  /* Action array: basically a set of deltas to evaluate */
  std::vector<int32_t> Actions;

  /* for managing stats */
  mop::PythiaStats stats;

  // local functions
  void init_knobs();
  void update_global_state(uint64_t pc, uint64_t page, uint32_t offset, uint64_t address);
  mop::Scooby_STEntry* update_local_state(uint64_t pc, uint64_t page, uint32_t offset, uint64_t address);
  void update_local_state_alloc(uint64_t page, uint64_t alloc_id);
  uint32_t predict(uint64_t address, uint64_t page, uint32_t offset, mop::State* state, std::vector<uint64_t>& pref_addr, bool has_object_bounds,
                   uint64_t obj_start, uint64_t obj_end);
  bool track(uint64_t address, mop::State* state, uint32_t action_index, mop::Scooby_PTEntry** tracker);
  void reward(uint64_t address);
  void reward(mop::Scooby_PTEntry* ptentry);
  void assign_reward(mop::Scooby_PTEntry* ptentry, mop::RewardType type);
  int32_t compute_reward(mop::Scooby_PTEntry* ptentry, mop::RewardType type);
  void train(mop::Scooby_PTEntry* curr_evicted, mop::Scooby_PTEntry* last_evicted);
  void register_fill(uint64_t address);
  std::vector<mop::Scooby_PTEntry*> search_pt(uint64_t address, bool search_all = false);
  void track_in_st(uint64_t page, uint32_t pred_offset, int32_t pref_offset);
  void gen_multi_degree_pref(uint64_t page, uint32_t offset, int32_t action, uint32_t pref_degree, std::vector<uint64_t>& pref_addr,
                             bool has_object_bounds, uint64_t obj_start, uint64_t obj_end);
  uint32_t get_dyn_pref_degree(float max_to_avg_q_ratio, uint64_t page = 0xdeadbeef, int32_t action = 0); /* only implemented for CMAC engine 2.0 */
  int32_t getAction(uint32_t action_index);
  bool is_high_bw(uint8_t bw_level);

public:
  using champsim::modules::prefetcher::prefetcher;

  // interface to the rest of ChampSim
  void prefetcher_initialize();
  uint32_t prefetcher_cache_operate(champsim::address addr, champsim::address ip, uint8_t cache_hit, bool useful_prefetch, access_type type,
                                    uint32_t metadata_in);
  uint32_t prefetcher_cache_fill(champsim::address addr, long set, long way, uint8_t prefetch, champsim::address evicted_addr, uint32_t metadata_in);
  void prefetcher_cycle_operate();
  void prefetcher_final_stats();
};

#endif /* __MO_PYTHIA_H__ */