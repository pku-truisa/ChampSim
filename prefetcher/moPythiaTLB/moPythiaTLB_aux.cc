//=======================================================================================//
// File             : moPythiaTLB/moPythiaTLB_aux.cc
// Author           : Based on Pythia (Bera+, MICRO'21)
// Date             : 03/AUG/2026
// Description      : Implements auxiliary functions of moPythiaTLB - Memory Object aware Pythia
//=======================================================================================//

#include "moPythiaTLB.h"

#include <assert.h>
#include <strings.h>

#include <algorithm>

#include "dpc_api.h"
#include "util/util.h"
#include <cache.h>

#define CHECK_ACTION_SANITY(ai) (assert((ai) < Actions.size()))

void moPythiaTLB::init_knobs()
{
  Actions.clear();
  for (uint32_t index = 0; index < MO_PYTHIA_TLB::actions.size(); ++index) {
    Actions.push_back(MO_PYTHIA_TLB::actions[index]);
  }
  assert(Actions.size() == MO_PYTHIA_TLB::actions.size());
  assert(Actions.size() <= MO_PYTHIA_TLB::max_actions);
  assert(MO_PYTHIA_TLB::last_pref_offset_conf_thresholds.size() == MO_PYTHIA_TLB::dyn_degrees_type2.size() - 1);
  bzero(&stats, sizeof(stats));
}

void moPythiaTLB::update_global_state(uint64_t pc, uint64_t page, uint32_t offset, uint64_t address) {}

moptlb::Scooby_STEntry* moPythiaTLB::update_local_state(uint64_t pc, uint64_t page, uint32_t offset, uint64_t address)
{
  stats.st.lookup++;
  moptlb::Scooby_STEntry* stentry = NULL;
  auto st_index = find_if(signature_table.begin(), signature_table.end(), [page](moptlb::Scooby_STEntry* _stentry) { return _stentry->page == page; });
  if (st_index != signature_table.end()) {
    stats.st.hit++;
    stentry = (*st_index);
    stentry->update(page, pc, offset, address);
    signature_table.erase(st_index);
    signature_table.push_back(stentry);
    return stentry;
  } else {
    if (signature_table.size() >= MO_PYTHIA_TLB::st_size) {
      stats.st.evict++;
      stentry = signature_table.front();
      signature_table.pop_front();
      delete stentry;
    }

    stats.st.insert++;
    stentry = new moptlb::Scooby_STEntry(page, pc, offset);
    signature_table.push_back(stentry);
    return stentry;
  }
}

void moPythiaTLB::update_local_state_alloc(uint64_t page, uint64_t alloc_id)
{
  auto st_index = find_if(signature_table.begin(), signature_table.end(), [page](moptlb::Scooby_STEntry* _stentry) { return _stentry->page == page; });
  if (st_index != signature_table.end()) {
    (*st_index)->update_alloc_id(page, alloc_id, 0, 0);
  }
}

//----------------------------------------------------//
// Main predict function. Does four broader tasks:
// 1. Asks the RL engine to select an action
// 2. Decides on prefetch degree
// 3. Generates corresponding prefetch addresses and
//    inserts into the prefetch tracker (PT).
// 4. Assigns rewards to PT entry in special cases
//    (i.e., no prefetch, or out-of-bounds prefetch)
//----------------------------------------------------//
uint32_t moPythiaTLB::predict(uint64_t base_address, uint64_t page, uint32_t offset, moptlb::State* state, std::vector<uint64_t>& pref_addr,
                           bool has_object_bounds, uint64_t obj_start, uint64_t obj_end)
{
  stats.predict.called++;

  /* query learning engine to get the next prediction */
  uint32_t action_index = 0;
  uint32_t pref_degree = 1;
  std::vector<bool> consensus_vec; // only required for featurewise engine
  float max_to_avg_q_ratio = 1.0;

  // take an action
  action_index = brain_featurewise->chooseAction(state);
  CHECK_ACTION_SANITY(action_index);

  // select a prefetch degree
  if (MO_PYTHIA_TLB::enable_dyn_degree) {
    pref_degree = get_dyn_pref_degree(max_to_avg_q_ratio, page, Actions[action_index]);
  }

  uint64_t addr = 0xdeadbeef;
  moptlb::Scooby_PTEntry* ptentry = NULL;
  int32_t predicted_offset = 0;
  if (Actions[action_index] != 0) {
    predicted_offset = (int32_t)offset + Actions[action_index];

    /* check out of bounds: memory object bounds take priority when available,
     * otherwise fall back to page-bounded behavior (original Pythia) */
    bool is_out_of_bounds = false;
    if (has_object_bounds) {
      uint64_t generated_addr = base_address + (Actions[action_index] << LOG2_BLOCK_SIZE);
      is_out_of_bounds = (generated_addr < obj_start || generated_addr >= obj_end);
    } else {
      is_out_of_bounds = (predicted_offset < 0 || predicted_offset >= 64);
    }

    if (is_out_of_bounds) /* falls outside the allowed bounds */
    {
      stats.predict.out_of_bounds++;
      stats.predict.out_of_bounds_dist[action_index]++;
      if (MO_PYTHIA_TLB::enable_reward_out_of_bounds) {
        addr = 0xdeadbeef;
        track(addr, state, action_index, &ptentry);
        assert(ptentry);
        assign_reward(ptentry, moptlb::RewardType::out_of_bounds);
        ptentry->consensus_vec = consensus_vec;
      }
    } else {
      addr = (page << LOG2_PAGE_SIZE) + (predicted_offset << LOG2_BLOCK_SIZE);

      bool new_addr = track(addr, state, action_index, &ptentry); /* track prefetch */
      if (new_addr) {
        pref_addr.push_back(addr);
        track_in_st(page, predicted_offset, Actions[action_index]);
        stats.predict.issue_dist[action_index]++;
        if (pref_degree > 1) {
          gen_multi_degree_pref(page, offset, Actions[action_index], pref_degree, pref_addr, has_object_bounds, obj_start, obj_end);
        }
        stats.predict.deg_histogram[pref_degree]++;
        ptentry->consensus_vec = consensus_vec;
      } else {
        stats.predict.pred_hit[action_index]++;
      }
      stats.predict.action_dist[action_index]++;
    }
  } else {
    /* agent decided not to prefetch */
    addr = 0xdeadbeef;
    /* track no prefetch */
    track(addr, state, action_index, &ptentry);
    stats.predict.action_dist[action_index]++;
    ptentry->consensus_vec = consensus_vec;
  }

  stats.predict.predicted += pref_addr.size();
  return (uint32_t)pref_addr.size();
}

//----------------------------------------------------//
// Returns true if the address is
// not already present in prefetch_tracker.
// Otherwise, returns false.
//----------------------------------------------------//
bool moPythiaTLB::track(uint64_t address, moptlb::State* state, uint32_t action_index, moptlb::Scooby_PTEntry** tracker)
{
  stats.track.called++;

  bool new_addr = true;
  std::vector<moptlb::Scooby_PTEntry*> ptentries = search_pt(address, false);
  if (ptentries.empty()) {
    new_addr = true;
  } else {
    new_addr = false;
  }

  if (!new_addr && address != 0xdeadbeef) {
    stats.track.same_address++;
    tracker = NULL;
    return new_addr;
  }

  /* new prefetched address that hasn't been seen before */
  moptlb::Scooby_PTEntry* ptentry = NULL;

  if (prefetch_tracker.size() >= MO_PYTHIA_TLB::pt_size) {
    stats.track.evict++;
    ptentry = prefetch_tracker.front();
    prefetch_tracker.pop_front();
    if (last_evicted_tracker) {
      /* train the agent */
      train(ptentry, last_evicted_tracker);
      delete last_evicted_tracker->state;
      delete last_evicted_tracker;
    }
    last_evicted_tracker = ptentry;
  }

  ptentry = new moptlb::Scooby_PTEntry(address, state, action_index);
  prefetch_tracker.push_back(ptentry);
  assert(prefetch_tracker.size() <= MO_PYTHIA_TLB::pt_size);

  (*tracker) = ptentry;
  return new_addr;
}

//----------------------------------------------------//
// Computes the prefetch degree dynamically.
// Should be called when moPythiaTLB makes a prediction.
//----------------------------------------------------//
uint32_t moPythiaTLB::get_dyn_pref_degree(float max_to_avg_q_ratio, uint64_t page, int32_t action)
{
  uint32_t counted = false;
  uint32_t degree = 1;
  bool high_bw = is_high_bw(get_dram_bw());

  auto st_index = find_if(signature_table.begin(), signature_table.end(), [page](moptlb::Scooby_STEntry* stentry) { return stentry->page == page; });
  if (st_index != signature_table.end()) {
    int32_t conf = 0;
    bool found = (*st_index)->search_action_tracker(action, conf);
    std::vector<int32_t> conf_thresholds, deg_normal;

    conf_thresholds = high_bw ? MO_PYTHIA_TLB::last_pref_offset_conf_thresholds_hbw : MO_PYTHIA_TLB::last_pref_offset_conf_thresholds;
    deg_normal = high_bw ? MO_PYTHIA_TLB::dyn_degrees_type2_hbw : MO_PYTHIA_TLB::dyn_degrees_type2;

    if (found) {
      for (uint32_t index = 0; index < conf_thresholds.size(); ++index) {
        /* last_pref_offset_conf_thresholds is a sorted list in ascending order of values */
        if (conf <= conf_thresholds[index]) {
          degree = deg_normal[index];
          counted = true;
          break;
        }
      }
      if (!counted) {
        degree = deg_normal.back();
      }
    } else {
      degree = 1;
    }
  }

  return degree;
}

//----------------------------------------------------//
// Generates an array of prefetch candidates based on
// the given page, offset, and prefetch degree.
// Again, should be called from the predict function,
// after the prefetch degree has been decided.
//----------------------------------------------------//
void moPythiaTLB::gen_multi_degree_pref(uint64_t page, uint32_t offset, int32_t action, uint32_t pref_degree, std::vector<uint64_t>& pref_addr,
                                     bool has_object_bounds, uint64_t obj_start, uint64_t obj_end)
{
  stats.predict.multi_deg_called++;
  uint64_t addr = 0xdeadbeef;
  int32_t predicted_offset = 0;
  if (action != 0) {
    for (uint32_t degree = 2; degree <= pref_degree; ++degree) {
      predicted_offset = (int32_t)offset + degree * action;

      /* check out of bounds: memory object bounds take priority when available */
      bool is_out_of_bounds = false;
      if (has_object_bounds) {
        uint64_t generated_addr = (page << LOG2_PAGE_SIZE) + (predicted_offset << LOG2_BLOCK_SIZE);
        is_out_of_bounds = (generated_addr < obj_start || generated_addr >= obj_end);
      } else {
        is_out_of_bounds = (predicted_offset < 0 || predicted_offset >= 64);
      }

      if (is_out_of_bounds) {
        break;
      }

      addr = (page << LOG2_PAGE_SIZE) + (predicted_offset << LOG2_BLOCK_SIZE);
      if (std::find(pref_addr.begin(), pref_addr.end(), addr) == pref_addr.end()) {
        pref_addr.push_back(addr);
        stats.predict.multi_deg++;
        stats.predict.multi_deg_histogram[degree]++;
      }
    }
  }
}

//----------------------------------------------------//
// This reward function is called after seeing
// a demand access to the address.
//----------------------------------------------------//
void moPythiaTLB::reward(uint64_t address)
{
  stats.reward.demand.called++;
  std::vector<moptlb::Scooby_PTEntry*> ptentries = search_pt(address, MO_PYTHIA_TLB::enable_reward_all);

  if (ptentries.empty()) {
    stats.reward.demand.pt_not_found++;
    return;
  } else {
    stats.reward.demand.pt_found++;
  }

  for (uint32_t index = 0; index < ptentries.size(); ++index) {
    moptlb::Scooby_PTEntry* ptentry = ptentries[index];
    stats.reward.demand.pt_found_total++;

    /* Do not compute reward if already has a reward.
     * This can happen when a prefetch access sees multiple demand reuse */
    if (ptentry->has_reward) {
      stats.reward.demand.has_reward++;
      return;
    }

    if (ptentry->is_filled) /* timely */
    {
      assign_reward(ptentry, moptlb::RewardType::correct_timely);
    } else {
      assign_reward(ptentry, moptlb::RewardType::correct_untimely);
    }
    ptentry->has_reward = true;
  }
}

//----------------------------------------------------//
// This is another overloaded reward function.
// This variant is called during eviction from prefetch tracker.
//----------------------------------------------------//
void moPythiaTLB::reward(moptlb::Scooby_PTEntry* ptentry)
{
  stats.reward.train.called++;
  assert(!ptentry->has_reward);
  /* this is called during eviction from prefetch tracker
   * that means, this address doesn't see a demand reuse.
   * hence it either can be incorrect, or no prefetch */
  if (ptentry->address == 0xdeadbeef) /* no prefetch */
  {
    assign_reward(ptentry, moptlb::RewardType::none);
  } else /* incorrect prefetch */
  {
    assign_reward(ptentry, moptlb::RewardType::incorrect);
  }
  ptentry->has_reward = true;
}

//----------------------------------------------------//
// Asssigns reward to a given prefetch tracker entry.
// Can be called from one of the following four places:
// 1. prefetch goes out of bounds (inside predict())
// 2. no prefetch (inside predict())
// 3. PT entry sees a demand reuse (inside first variant of reward())
// 4. PT entry gets evicted without seeing a reuse (inside second variant of reward())
//----------------------------------------------------//
void moPythiaTLB::assign_reward(moptlb::Scooby_PTEntry* ptentry, moptlb::RewardType type)
{
  assert(!ptentry->has_reward);

  /* compute the reward */
  int32_t reward = compute_reward(ptentry, type);

  /* assign */
  ptentry->reward = reward;
  ptentry->reward_type = type;
  ptentry->has_reward = true;

  /* maintain stats */
  stats.reward.assign_reward.called++;
  switch (type) {
  case moptlb::RewardType::correct_timely:
    stats.reward.correct_timely++;
    break;
  case moptlb::RewardType::correct_untimely:
    stats.reward.correct_untimely++;
    break;
  case moptlb::RewardType::incorrect:
    stats.reward.incorrect++;
    break;
  case moptlb::RewardType::none:
    stats.reward.no_pref++;
    break;
  case moptlb::RewardType::out_of_bounds:
    stats.reward.out_of_bounds++;
    break;
  default:
    assert(false);
  }
  stats.reward.dist[ptentry->action_index][type]++;
}

//----------------------------------------------------//
// Computes the reward depending on the six cases:
// 1. accurate AND timely
// 2. accurate but NOT timely
// 3. inaccurate
// 4. no prefetch
// 5. out-of-bounds prefetch
// 6. regenerated a previously-predicted addr
//----------------------------------------------------//
int32_t moPythiaTLB::compute_reward(moptlb::Scooby_PTEntry* ptentry, moptlb::RewardType type)
{
  bool high_bw = (MO_PYTHIA_TLB::enable_hbw_reward && is_high_bw(get_dram_bw())) ? true : false;
  int32_t reward = 0;

  stats.reward.compute_reward.dist[type][high_bw]++;

  if (type == moptlb::RewardType::correct_timely) {
    reward = high_bw ? MO_PYTHIA_TLB::reward_hbw_correct_timely : MO_PYTHIA_TLB::reward_correct_timely;
  } else if (type == moptlb::RewardType::correct_untimely) {
    reward = high_bw ? MO_PYTHIA_TLB::reward_hbw_correct_untimely : MO_PYTHIA_TLB::reward_correct_untimely;
  } else if (type == moptlb::RewardType::incorrect) {
    reward = high_bw ? MO_PYTHIA_TLB::reward_hbw_incorrect : MO_PYTHIA_TLB::reward_incorrect;
  } else if (type == moptlb::RewardType::none) {
    reward = high_bw ? MO_PYTHIA_TLB::reward_hbw_none : MO_PYTHIA_TLB::reward_none;
  } else if (type == moptlb::RewardType::out_of_bounds) {
    reward = high_bw ? MO_PYTHIA_TLB::reward_hbw_out_of_bounds : MO_PYTHIA_TLB::reward_out_of_bounds;
  } else {
    assert(false);
  }

  return reward;
}

//----------------------------------------------------//
// Main training function.
// Invokes the RL engine training.
//----------------------------------------------------//
void moPythiaTLB::train(moptlb::Scooby_PTEntry* curr_evicted, moptlb::Scooby_PTEntry* last_evicted)
{
  stats.train.called++;
  if (!last_evicted->has_reward) {
    stats.train.compute_reward++;
    reward(last_evicted);
  }
  assert(last_evicted->has_reward);

  /* RL engine training */
  brain_featurewise->learn(last_evicted->state, last_evicted->action_index, last_evicted->reward, curr_evicted->state, curr_evicted->action_index,
                           last_evicted->reward_type);
}

//----------------------------------------------------//
// Called when a prefetch request gets filled into the cache.
// Necessary to identify timely prefetches.
//----------------------------------------------------//
void moPythiaTLB::register_fill(uint64_t address)
{
  stats.register_fill.called++;
  std::vector<moptlb::Scooby_PTEntry*> ptentries = search_pt(address, MO_PYTHIA_TLB::enable_reward_all);
  if (!ptentries.empty()) {
    stats.register_fill.set++;
    for (uint32_t index = 0; index < ptentries.size(); ++index) {
      stats.register_fill.set_total++;
      ptentries[index]->is_filled = true;
    }
  }
}

std::vector<moptlb::Scooby_PTEntry*> moPythiaTLB::search_pt(uint64_t address, bool search_all)
{
  std::vector<moptlb::Scooby_PTEntry*> entries;
  for (uint32_t index = 0; index < prefetch_tracker.size(); ++index) {
    if (prefetch_tracker[index]->address == address) {
      entries.push_back(prefetch_tracker[index]);
      if (!search_all)
        break;
    }
  }
  return entries;
}

void moPythiaTLB::track_in_st(uint64_t page, uint32_t pred_offset, int32_t pref_offset)
{
  auto st_index = find_if(signature_table.begin(), signature_table.end(), [page](moptlb::Scooby_STEntry* stentry) { return stentry->page == page; });
  if (st_index != signature_table.end()) {
    (*st_index)->track_prefetch(pred_offset, pref_offset);
  }
}

int32_t moPythiaTLB::getAction(uint32_t action_index)
{
  assert(action_index < Actions.size());
  return Actions[action_index];
}

bool moPythiaTLB::is_high_bw(uint8_t bw_level) { return bw_level >= MO_PYTHIA_TLB::high_bw_thresh ? true : false; }