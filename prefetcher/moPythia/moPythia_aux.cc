//=======================================================================================//
// File             : moPythia/moPythia_aux.cc
// Author           : Based on Pythia (Bera+, MICRO'21)
// Date             : 03/AUG/2026
// Description      : Implements auxiliary functions of moPythia - Memory Object aware Pythia
//=======================================================================================//

#include "moPythia.h"

#include <assert.h>
#include <strings.h>

#include "dpc_api.h"
#include "util/util.h"
#include <cache.h>

void moPythia::init_knobs()
{
  Actions.clear();
  for (uint32_t index = 0; index < MO_PYTHIA::actions.size(); ++index) {
    Actions.push_back(MO_PYTHIA::actions[index]);
  }
  bzero(&stats, sizeof(stats));
}

void moPythia::update_global_state(uint64_t pc, uint64_t page, uint32_t offset, uint64_t address) {}

mop::Scooby_STEntry* moPythia::update_local_state(uint64_t pc, uint64_t page, uint32_t offset, uint64_t address)
{
  mop::Scooby_STEntry* stentry = NULL;
  for (auto entry : signature_table) {
    if (entry->page == page) {
      stentry = entry;
      break;
    }
  }

  if (stentry == NULL) {
    if (signature_table.size() >= MO_PYTHIA::st_size)
      signature_table.pop_front();
    stentry = new mop::Scooby_STEntry(page, pc, offset);
    // stat
    stats.st.insert++;
    return stentry;
  }

  // stat
  stats.st.hit++;

  // state update
  stentry->update(page, pc, offset, address);
  return stentry;
}

void moPythia::update_local_state_alloc(uint64_t page, uint64_t alloc_id)
{
  for (auto entry : signature_table) {
    if (entry->page == page) {
      entry->update_alloc_id(page, alloc_id, 0, 0);
      break;
    }
  }
}

uint32_t moPythia::predict(uint64_t base_address, uint64_t page, uint32_t offset, mop::State* state, std::vector<uint64_t>& pref_addr,
                           bool has_object_bounds, uint64_t obj_start, uint64_t obj_end)
{
  stats.predict.called++;

  /* fallback: always evaluate action at index 0 */
  uint32_t action_index = 0;
  uint32_t pref_degree = 0;

  bool is_fallback = false;

  /* predict */
  action_index = brain_featurewise->chooseAction(state);

  /* statistics */
  stats.predict.action_dist[action_index]++;

  /* check limits of actions */
  assert(action_index < Actions.size());

  if (Actions[action_index] == 0) {
    MYLOG("action 0 -- %lu prefetches issued", pref_addr.size());
    return (uint32_t)pref_addr.size();
  }

  if (action_index > 0 && is_fallback) {
    // if fallback, only evaluate action at index 0
    return (uint32_t)pref_addr.size();
  }

  /* check out of bounds */
  uint64_t generated_addr = base_address + (Actions[action_index] << LOG2_BLOCK_SIZE);

  bool is_out_of_bounds = false;
  if (has_object_bounds) {
    /* object-bounded: prefetch must stay within [obj_start, obj_end) */
    is_out_of_bounds = (generated_addr < obj_start || generated_addr >= obj_end);
  } else {
    /* fallback: page-bounded (original Pythia behavior) */
    uint64_t predicted_offset = (uint64_t)((int64_t)offset + (int64_t)Actions[action_index]);
    if ((int64_t)predicted_offset < 0 || (predicted_offset >= ((1ull << (LOG2_PAGE_SIZE - LOG2_BLOCK_SIZE))))) {
      is_out_of_bounds = true;
    }
  }

  if (is_out_of_bounds) {
    stats.predict.out_of_bounds++;
    stats.predict.out_of_bounds_dist[action_index]++;
    return (uint32_t)pref_addr.size(); // do not prefetch
  }

  /* track issue and generate prefetch addresses */
  if (generated_addr != base_address) {
    uint64_t addr = generated_addr;
    bool new_addr = (std::find(pref_addr.begin(), pref_addr.end(), addr) == pref_addr.end());
    if (new_addr) {
      pref_addr.push_back(addr);
      track_in_st(page, offset + Actions[action_index], Actions[action_index]);
      if (pref_degree > 1) {
        gen_multi_degree_pref(page, offset, Actions[action_index], pref_degree, pref_addr, has_object_bounds, obj_start, obj_end);
      }
    }

    stats.predict.issue_dist[action_index]++;
  }

  stats.predict.predicted += pref_addr.size();
  MYLOG("end@%lx", base_address);
  return (uint32_t)pref_addr.size();
}

bool moPythia::track(uint64_t address, mop::State* state, uint32_t action_index, mop::Scooby_PTEntry** tracker)
{
  stats.track.called++;
  mop::Scooby_PTEntry* ptentry = NULL;

  std::vector<mop::Scooby_PTEntry*> same_address = search_pt(address);
  if (!same_address.empty()) {
    stats.track.same_address++;
    ptentry = same_address.at(0);
    if (ptentry->state->page != state->page) {
      return false;
    }
    ptentry->state = state;
    ptentry->action_index = action_index;
    *tracker = ptentry;
    return true;
  }

  if (prefetch_tracker.size() >= MO_PYTHIA::pt_size) {
    stats.track.evict++;
    last_evicted_tracker = prefetch_tracker.front();
    prefetch_tracker.pop_front();
  }

  ptentry = new mop::Scooby_PTEntry(address, state, action_index);
  prefetch_tracker.push_back(ptentry);
  *tracker = ptentry;

  return true;
}

void moPythia::reward(uint64_t address)
{
  stats.reward.demand.called++;
  std::vector<mop::Scooby_PTEntry*> ptentries = search_pt(address);
  if (ptentries.empty()) {
    stats.reward.demand.pt_not_found++;
    return;
  }

  stats.reward.demand.pt_found++;
  stats.reward.demand.pt_found_total += ptentries.size();

  for (auto ptentry : ptentries) {
    if (!ptentry->has_reward) {
      reward(ptentry);
      stats.reward.demand.has_reward++;
    }
  }
}

void moPythia::reward(mop::Scooby_PTEntry* ptentry)
{
  assign_reward(ptentry, mop::RewardType::none);

  if (ptentry->is_filled) {
    assign_reward(ptentry, mop::RewardType::correct_timely); // account for timeliness first
  } else {
    assign_reward(ptentry, mop::RewardType::incorrect);
  }

  // Account for reward out of bounds
  // Predict thinks this is out-of-bounds if offset has not changed. Use action_index as proxy
  // Since action itself can never be zero in out_of_bounds path
  if (MO_PYTHIA::enable_reward_out_of_bounds && ptentry->action_index == 0) {
    assign_reward(ptentry, mop::RewardType::out_of_bounds);
  }
}

void moPythia::assign_reward(mop::Scooby_PTEntry* ptentry, mop::RewardType type)
{
  stats.reward.assign_reward.called++;
  if (ptentry->has_reward)
    return;

  int32_t reward = compute_reward(ptentry, type);
  if (reward == 0) {
    return;
  }

  // Do the actual reward
  ptentry->reward = reward;
  ptentry->has_reward = true;
  ptentry->reward_type = type;

  MYLOG("<reward> %lx, action %d, reward %d", ptentry->address, ptentry->action_index, ptentry->reward);

  train(ptentry, last_evicted_tracker);
}

int32_t moPythia::compute_reward(mop::Scooby_PTEntry* ptentry, mop::RewardType type)
{
  stats.reward.compute_reward.dist[type][0]++;
  int32_t reward = 0;
  switch (type) {
    case mop::RewardType::none: {
      reward = 0;
      break;
    }
    case mop::RewardType::correct_timely: {
      reward = MO_PYTHIA::reward_correct_timely;
      if (ptentry->state->is_high_bw) {
        reward = MO_PYTHIA::reward_hbw_correct_timely;
        stats.reward.compute_reward.dist[type][1]++;
      }
      break;
    }
    case mop::RewardType::correct_untimely: {
      reward = MO_PYTHIA::reward_correct_untimely;
      if (ptentry->state->is_high_bw) {
        reward = MO_PYTHIA::reward_hbw_correct_untimely;
        stats.reward.compute_reward.dist[type][1]++;
      }
      break;
    }
    case mop::RewardType::incorrect: {
      reward = MO_PYTHIA::reward_incorrect;
      if (ptentry->state->is_high_bw) {
        reward = MO_PYTHIA::reward_hbw_incorrect;
        stats.reward.compute_reward.dist[type][1]++;
      }
      break;
    }
    case mop::RewardType::out_of_bounds: {
      reward = MO_PYTHIA::reward_out_of_bounds;
      if (ptentry->state->is_high_bw) {
        reward = MO_PYTHIA::reward_hbw_out_of_bounds;
        stats.reward.compute_reward.dist[type][1]++;
      }
      break;
    }
    default:
      break;
  }
  MYLOG("<reward> type %s reward %d", mop::getRewardTypeString(type), reward);
  return reward;
}

void moPythia::train(mop::Scooby_PTEntry* curr_evicted, mop::Scooby_PTEntry* last_evicted)
{
  stats.train.called++;
  if (curr_evicted && curr_evicted->has_reward) {
    if (last_evicted && last_evicted->has_reward) {
      brain_featurewise->learn(last_evicted->state, last_evicted->action_index, last_evicted->reward, curr_evicted->state,
                               curr_evicted->action_index, last_evicted->reward_type);
    }
  }
}

void moPythia::register_fill(uint64_t address)
{
  stats.register_fill.called++;
  std::vector<mop::Scooby_PTEntry*> ptentries = search_pt(address);
  if (ptentries.empty()) {
    return;
  }

  for (auto ptentry : ptentries) {
    if (ptentry->is_filled)
      continue;

    ptentry->is_filled = true;
    stats.register_fill.set++;
    stats.register_fill.set_total += ptentries.size();
  }
}

std::vector<mop::Scooby_PTEntry*> moPythia::search_pt(uint64_t address, bool search_all)
{
  std::vector<mop::Scooby_PTEntry*> entries;
  for (auto ptentry : prefetch_tracker) {
    if (ptentry->address == address) {
      entries.push_back(ptentry);
      if (!search_all)
        break;
    }
  }
  return entries;
}

void moPythia::track_in_st(uint64_t page, uint32_t pred_offset, int32_t pref_offset)
{
  MYLOG("page %lx pred_offset %lu pref_offset %d", page, pred_offset, pref_offset);
  for (auto entry : signature_table) {
    if (entry->page == page) {
      entry->track_prefetch(pred_offset, pref_offset);
      break;
    }
  }
}

void moPythia::gen_multi_degree_pref(uint64_t page, uint32_t offset, int32_t action, uint32_t pref_degree, std::vector<uint64_t>& pref_addr,
                                     bool has_object_bounds, uint64_t obj_start, uint64_t obj_end)
{
  for (uint32_t degree = 1; degree < pref_degree; ++degree) {
    uint64_t generated_addr = (page << LOG2_PAGE_SIZE) + ((offset + (degree + 1) * action) << LOG2_BLOCK_SIZE);

    if (has_object_bounds) {
      if (generated_addr < obj_start || generated_addr >= obj_end) {
        MYLOG("degree %u out of object bounds!", degree);
        break;
      }
    } else {
      uint64_t predicted_offset = (uint64_t)((int64_t)offset + (int64_t)((degree + 1) * action));
      if ((int64_t)predicted_offset < 0 || predicted_offset >= (1u << (LOG2_PAGE_SIZE - LOG2_BLOCK_SIZE))) {
        MYLOG("degree %u out of bounds! %lu", degree, predicted_offset);
        break;
      }
      generated_addr = (page << LOG2_PAGE_SIZE) + (predicted_offset << LOG2_BLOCK_SIZE);
    }

    if (std::find(pref_addr.begin(), pref_addr.end(), generated_addr) == pref_addr.end()) {
      pref_addr.push_back(generated_addr);
      MYLOG("degree %u pred_off %d pred_addr %lx", degree, offset + (degree + 1) * action, generated_addr);
    }
  }
}

uint32_t moPythia::get_dyn_pref_degree(float max_to_avg_q_ratio, uint64_t page, int32_t action)
{
  NOT_PORTED;
  return 0;
}

int32_t moPythia::getAction(uint32_t action_index)
{
  if (action_index >= Actions.size()) {
    assert(false);
    return 0;
  }
  return Actions[action_index];
}

bool moPythia::is_high_bw(uint8_t bw_level) { return (bw_level >= MO_PYTHIA::high_bw_thresh); }