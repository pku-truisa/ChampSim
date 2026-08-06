//=======================================================================================//
// File             : moPythiaTLB/moPythiaTLB.cc
// Author           : Based on Pythia (Bera+, MICRO'21)
// Date             : 03/AUG/2026
// Description      : Implements moPythiaTLB - Memory Object aware Pythia prefetcher
//=======================================================================================//

#include "moPythiaTLB.h"

#include <iostream>

#include "cache.h"
#include "dpc_api.h"
#include "memory_object_table.h"
#include "moPythiaTLB_params.h"

void moPythiaTLB::prefetcher_initialize()
{
  init_knobs();

  last_evicted_tracker = NULL;
  brain_featurewise = new moptlb::moLearningEngineFeaturewise(MO_PYTHIA_TLB::alpha, MO_PYTHIA_TLB::gamma, MO_PYTHIA_TLB::epsilon, (uint32_t)Actions.size(),
                                                           MO_PYTHIA_TLB::seed, MO_PYTHIA_TLB::policy, MO_PYTHIA_TLB::learning_type);

  std::cout << "moPythiaTLB Prefetcher (Memory Object aware Pythia)" << std::endl;
}

uint32_t moPythiaTLB::prefetcher_cache_operate(champsim::address addr, champsim::address ip, uint8_t cache_hit, bool useful_prefetch, access_type type,
                                            uint32_t metadata_in)
{
  uint64_t address = addr.to<uint64_t>();
  uint64_t pc = ip.to<uint64_t>();

  uint64_t page = address >> LOG2_PAGE_SIZE;
  uint32_t offset = (uint32_t)((address >> LOG2_BLOCK_SIZE) & ((1ull << (LOG2_PAGE_SIZE - LOG2_BLOCK_SIZE)) - 1));

  std::vector<uint64_t> pref_addr; // generated addresses to prefetch

  /* Memory object lookup */
  uint64_t alloc_id = mol_table.lookup_alloc_id_by_va(addr);
  uint64_t caller_ip = mol_table.lookup_caller_ip_by_va(addr);
  auto [obj_start, obj_end] = mol_table.get_object_bounds(addr);
  uint64_t obj_start_addr = obj_start.to<uint64_t>();
  uint64_t obj_end_addr = obj_end.to<uint64_t>();
  uint64_t obj_size = obj_end_addr - obj_start_addr;
  bool has_object_bounds = intern_->virtual_prefetch && (obj_start_addr != 0) && (obj_size > 4096);

  /* Only prefetch for objects larger than 4KB.
   * Skip prefetch entirely for small objects (<=4KB) and unmatched accesses. */
  if (!has_object_bounds) {
    return 0;
  }

  /* compute reward on demand */
  reward(address);

  /* global state tracking */
  update_global_state(pc, page, offset, address);
  /* per page state tracking */
  moptlb::Scooby_STEntry* stentry = update_local_state(pc, page, offset, address);
  /* track alloc_id path in the STEntry */
  update_local_state_alloc(page, alloc_id);
  /* track caller_ip path in the STEntry */
  update_local_state_caller_ip(page, caller_ip);

  /* Measure state.
   * state can contain per page local information like delta signature, pc signature etc.
   */
  moptlb::State* state = new moptlb::State();
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
  state->caller_ip = caller_ip;
  state->caller_ip_path_sig = stentry->get_caller_ip_sig();

  // generate prefetch predictions
  predict(address, page, offset, state, pref_addr, has_object_bounds, obj_start_addr, obj_end_addr);

  /* issue prefetches */
  for (uint32_t addr_index = 0; addr_index < pref_addr.size(); ++addr_index) {
    champsim::address pf_addr{pref_addr[addr_index]};
    intern_->prefetch_line(pf_addr, true, 0);
  }

  return 0;
}

uint32_t moPythiaTLB::prefetcher_cache_fill(champsim::address addr, long set, long way, uint8_t prefetch, champsim::address evicted_addr, uint32_t metadata_in)
{
  register_fill(addr.to<uint64_t>());
  return 0;
}

void moPythiaTLB::prefetcher_cycle_operate() {}

void moPythiaTLB::prefetcher_final_stats() {}