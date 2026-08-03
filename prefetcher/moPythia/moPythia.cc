//=======================================================================================//
// File             : moPythia/moPythia.cc
// Author           : Based on Pythia (Bera+, MICRO'21)
// Date             : 03/AUG/2026
// Description      : Implements moPythia - Memory Object aware Pythia prefetcher
//=======================================================================================//

#include "moPythia.h"

#include <iostream>

#include "cache.h"
#include "dpc_api.h"
#include "memory_object_table.h"
#include "moPythia_params.h"

void moPythia::prefetcher_initialize()
{
  init_knobs();

  last_evicted_tracker = NULL;
  brain_featurewise = new mop::moLearningEngineFeaturewise(MO_PYTHIA::alpha, MO_PYTHIA::gamma, MO_PYTHIA::epsilon, (uint32_t)Actions.size(),
                                                           MO_PYTHIA::seed, MO_PYTHIA::policy, MO_PYTHIA::learning_type);

  std::cout << "moPythia Prefetcher (Memory Object aware Pythia)" << std::endl;
}

uint32_t moPythia::prefetcher_cache_operate(champsim::address addr, champsim::address ip, uint8_t cache_hit, bool useful_prefetch, access_type type,
                                            uint32_t metadata_in)
{
  uint64_t address = addr.to<uint64_t>();
  uint64_t pc = ip.to<uint64_t>();

  uint64_t page = address >> LOG2_PAGE_SIZE;
  uint32_t offset = (uint32_t)((address >> LOG2_BLOCK_SIZE) & ((1ull << (LOG2_PAGE_SIZE - LOG2_BLOCK_SIZE)) - 1));

  std::vector<uint64_t> pref_addr; // generated addresses to prefetch

  /* Memory object lookup */
  uint64_t alloc_id = mol_table.lookup_alloc_id_by_va(addr);
  auto [obj_start, obj_end] = mol_table.get_object_bounds(addr);
  uint64_t obj_start_addr = obj_start.to<uint64_t>();
  uint64_t obj_end_addr = obj_end.to<uint64_t>();
  bool has_object_bounds = (obj_start_addr != 0);

  /* compute reward on demand */
  reward(address);

  /* global state tracking */
  update_global_state(pc, page, offset, address);
  /* per page state tracking */
  mop::Scooby_STEntry* stentry = update_local_state(pc, page, offset, address);
  /* track alloc_id path in the STEntry */
  update_local_state_alloc(page, alloc_id);

  /* Measure state.
   * state can contain per page local information like delta signature, pc signature etc.
   */
  mop::State* state = new mop::State();
  state->pc = pc;
  state->address = address;
  state->page = page;
  state->offset = offset;
  state->delta = !stentry->deltas.empty() ? stentry->deltas.back() : 0;
  state->local_delta_sig2 = stentry->get_delta_sig2();
  state->local_pc_sig = stentry->get_pc_sig();
  state->local_offset_sig = stentry->get_offset_sig();
  state->is_high_bw = is_high_bw(get_dram_bw());

  /* Memory object aware features */
  state->alloc_id = alloc_id;
  state->alloc_offset = has_object_bounds ? (address - obj_start_addr) : 0;
  state->object_path_sig = stentry->get_object_sig();

  // generate prefetch predictions
  predict(address, page, offset, state, pref_addr, has_object_bounds, obj_start_addr, obj_end_addr);

  /* issue prefetches */
  for (uint32_t addr_index = 0; addr_index < pref_addr.size(); ++addr_index) {
    champsim::address pf_addr{pref_addr[addr_index]};
    intern_->prefetch_line(pf_addr, true, 0);
  }

  return 0;
}

uint32_t moPythia::prefetcher_cache_fill(champsim::address addr, long set, long way, uint8_t prefetch, champsim::address evicted_addr, uint32_t metadata_in)
{
  register_fill(addr.to<uint64_t>());
  return 0;
}

void moPythia::prefetcher_cycle_operate() {}

void moPythia::prefetcher_final_stats() {}