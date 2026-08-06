//=======================================================================================//
// File             : moPythiaTLB/moPythiaTLB.cc
// Author           : Based on moPythia (Memory Object aware Pythia)
// Date             : 03/AUG/2026
// Description      : Implements moPythiaTLB - Memory Object aware Pythia with an internal
//                    PrefetchTLB to reduce STLB pressure.
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

  std::cout << "moPythiaTLB Prefetcher (Memory Object aware Pythia with PrefetchTLB)" << std::endl;
}

uint32_t moPythiaTLB::prefetcher_cache_operate(champsim::address addr, champsim::address ip, uint8_t cache_hit, bool useful_prefetch, access_type type,
                                               uint32_t metadata_in)
{
  uint64_t address = addr.to<uint64_t>();
  uint64_t pc = ip.to<uint64_t>();

  uint64_t page = address >> LOG2_PAGE_SIZE;
  uint32_t offset = (uint32_t)((address >> LOG2_BLOCK_SIZE) & ((1ull << (LOG2_PAGE_SIZE - LOG2_BLOCK_SIZE)) - 1));

  std::vector<uint64_t> pref_addr; // generated addresses to prefetch

  /* Update PrefetchTLB: a demand access means the translation for this page
   * is valid and present in the real TLB hierarchy. */
  prefetch_tlb.fill(page);
  stats.prefetch_tlb.fill++;

  /* Memory object lookup */
  uint64_t alloc_id = mol_table.lookup_alloc_id_by_va(addr);
  auto [obj_start, obj_end] = mol_table.get_object_bounds(addr);
  uint64_t obj_start_addr = obj_start.to<uint64_t>();
  uint64_t obj_end_addr = obj_end.to<uint64_t>();
  bool has_object_bounds = intern_->virtual_prefetch && (obj_start_addr != 0);

  /* compute reward on demand */
  reward(address);

  /* global state tracking */
  update_global_state(pc, page, offset, address);
  /* per page state tracking */
  moptlb::Scooby_STEntry* stentry = update_local_state(pc, page, offset, address);
  /* track alloc_id path in the STEntry */
  update_local_state_alloc(page, alloc_id);

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

  // generate prefetch predictions
  predict(address, page, offset, state, pref_addr, has_object_bounds, obj_start_addr, obj_end_addr);

  /* issue prefetches */
  for (uint32_t addr_index = 0; addr_index < pref_addr.size(); ++addr_index) {
    champsim::address pf_addr{pref_addr[addr_index]};
    intern_->prefetch_line(pf_addr, true, 0);
  }

  return 0;
}

uint32_t moPythiaTLB::prefetcher_cache_fill(champsim::address addr, long set, long way, uint8_t prefetch, champsim::address evicted_addr,
                                            uint32_t metadata_in)
{
  /* Update PrefetchTLB: a fill means the translation for this page has been
   * resolved and the page is now known to the TLB hierarchy. */
  uint64_t page = addr.to<uint64_t>() >> LOG2_PAGE_SIZE;
  prefetch_tlb.fill(page);
  stats.prefetch_tlb.fill++;

  register_fill(addr.to<uint64_t>());
  return 0;
}

void moPythiaTLB::prefetcher_cycle_operate() {}

void moPythiaTLB::prefetcher_final_stats()
{
  fprintf(stdout, "moPythiaTLB.prefetch_tlb.lookup %lu\n", stats.prefetch_tlb.lookup);
  fprintf(stdout, "moPythiaTLB.prefetch_tlb.hit %lu\n", stats.prefetch_tlb.hit);
  fprintf(stdout, "moPythiaTLB.prefetch_tlb.miss %lu\n", stats.prefetch_tlb.miss);
  fprintf(stdout, "moPythiaTLB.prefetch_tlb.fill %lu\n", stats.prefetch_tlb.fill);
  fprintf(stdout, "moPythiaTLB.prefetch_tlb.evict %lu\n", stats.prefetch_tlb.evict);
}