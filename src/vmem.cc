/*
 *    Copyright 2023 The ChampSim Contributors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "vmem.h"

#include <cassert>
#include <fmt/core.h>

#include "champsim.h"
#include "dram_controller.h"
#include "memory_object_table.h"
#include "util/bits.h"

using namespace champsim::data::data_literals;

VirtualMemory::VirtualMemory(champsim::data::bytes page_table_page_size, std::size_t page_table_levels, champsim::chrono::clock::duration minor_penalty,
                             MEMORY_CONTROLLER& dram_, std::optional<uint64_t> randomization_seed_)
    : randomization_seed(randomization_seed_), dram(dram_), minor_fault_penalty(minor_penalty), pt_levels(page_table_levels),
      pte_page_size(page_table_page_size),
      next_pte_page(
          champsim::dynamic_extent{champsim::data::bits{LOG2_PAGE_SIZE}, champsim::data::bits{champsim::lg2(champsim::data::bytes{pte_page_size}.count())}}, 0)
{
  assert(pte_page_size > 1_kiB);
  assert(champsim::is_power_of_2(pte_page_size.count()));

  champsim::page_number last_vpage{
      champsim::lowest_address_for_size(champsim::data::bytes{PAGE_SIZE + champsim::ipow(pte_page_size.count(), static_cast<unsigned>(pt_levels))})};
  champsim::data::bits required_bits{LOG2_PAGE_SIZE + champsim::lg2(last_vpage.to<uint64_t>())};
  if (required_bits > champsim::address::bits) {
    fmt::print("[VMEM] WARNING: virtual memory configuration would require {} bits of addressing.\n", required_bits); // LCOV_EXCL_LINE
  }
  if (required_bits > champsim::data::bits{champsim::lg2(dram.size().count())}) {
    fmt::print("[VMEM] WARNING: physical memory size is smaller than virtual memory size.\n"); // LCOV_EXCL_LINE
  }
  populate_pages();
  shuffle_pages();
  init_large_runs();
}

VirtualMemory::VirtualMemory(champsim::data::bytes page_table_page_size, std::size_t page_table_levels, champsim::chrono::clock::duration minor_penalty,
                             MEMORY_CONTROLLER& dram_)
    : VirtualMemory(page_table_page_size, page_table_levels, minor_penalty, dram_, {})
{
}

void VirtualMemory::populate_pages()
{
  assert(dram.size() > 1_MiB);
  const auto total_pages = ((dram.size() - 1_MiB) / PAGE_SIZE).count();
  const auto small_pages = static_cast<std::size_t>(static_cast<double>(total_pages) * (1.0 - LARGE_OBJECT_FRACTION));

  large_pool_pages = total_pages - small_pages;

  ppage_free_list.resize(small_pages);
  assert(ppage_free_list.size() != 0);
  champsim::page_number base_address{
      champsim::lowest_address_for_size(std::max<champsim::data::mebibytes>(champsim::data::bytes{PAGE_SIZE}, 1_MiB))};
  for (auto it = ppage_free_list.begin(); it != ppage_free_list.end(); it++) {
    *it = base_address;
    base_address++;
  }
  large_pool_start = base_address; // just past the small pool
}

void VirtualMemory::shuffle_pages()
{
  if (randomization_seed.has_value())
    std::shuffle(ppage_free_list.begin(), ppage_free_list.end(), std::mt19937_64{randomization_seed.value()});
}

void VirtualMemory::init_large_runs()
{
  large_free_runs.clear();
  large_free_runs[large_pool_start] = large_pool_pages;
}

champsim::dynamic_extent VirtualMemory::extent(std::size_t level) const
{
  const champsim::data::bits lower{LOG2_PAGE_SIZE + champsim::lg2(pte_page_size.count()) * (level - 1)};
  const auto size = static_cast<std::size_t>(champsim::lg2(pte_page_size.count()));
  return champsim::dynamic_extent{lower, size};
}

champsim::data::bits VirtualMemory::shamt(std::size_t level) const { return extent(level).lower; }

uint64_t VirtualMemory::get_offset(champsim::address vaddr, std::size_t level) const { return champsim::address_slice{extent(level), vaddr}.to<uint64_t>(); }

uint64_t VirtualMemory::get_offset(champsim::page_number vaddr, std::size_t level) const { return get_offset(champsim::address{vaddr}, level); }

champsim::page_number VirtualMemory::ppage_front() const
{
  assert(!ppage_free_list.empty());
  return ppage_free_list.front();
}

void VirtualMemory::ppage_pop()
{
  ppage_free_list.pop_front();
  if (ppage_free_list.empty()) {
    fmt::print("[VMEM] WARNING: Out of physical memory, freeing ppages\n");
    populate_pages();
    shuffle_pages();
  }
}

champsim::page_number VirtualMemory::allocate_contiguous(std::size_t num_pages)
{
  using diff = champsim::page_number::difference_type;
  for (auto it = large_free_runs.rbegin(); it != large_free_runs.rend(); ++it) {
    if (it->second < num_pages) {
      continue;
    }
    const champsim::page_number run_start = it->first;
    const std::size_t run_len = it->second;
    // Carve from the top of the highest run (high -> low).
    const champsim::page_number base = run_start + static_cast<diff>(run_len - num_pages);
    large_free_runs.erase(run_start);
    if (run_len > num_pages) {
      large_free_runs[run_start] = run_len - num_pages; // keep the lower remainder
    }
    return base;
  }
  // No run is large enough: recycle the large pool (infinite-memory semantics).
  init_large_runs();
  return allocate_contiguous(num_pages);
}

void VirtualMemory::free_pages(champsim::page_number start, std::size_t num_pages)
{
  using diff = champsim::page_number::difference_type;
  const champsim::page_number end = start + static_cast<diff>(num_pages);

  // Absorb a successor run that begins exactly at `end`.
  auto succ = large_free_runs.find(end);
  if (succ != large_free_runs.end()) {
    num_pages += succ->second;
    large_free_runs.erase(succ);
  }

  // Absorb a predecessor run that ends exactly at `start`.
  auto pred = large_free_runs.lower_bound(start);
  if (pred != large_free_runs.begin()) {
    --pred;
    if (pred->first + static_cast<diff>(pred->second) == start) {
      pred->second += num_pages;
      return;
    }
  }

  large_free_runs[start] = num_pages;
}

std::size_t VirtualMemory::available_ppages() const
{
  std::size_t total = ppage_free_list.size();
  for (auto& [run_start, run_len] : large_free_runs) {
    (void)run_start;
    total += run_len;
  }
  return total;
}

std::pair<champsim::page_number, champsim::chrono::clock::duration> VirtualMemory::va_to_pa(uint32_t cpu_num, champsim::page_number vaddr)
{
  const auto key = std::pair<uint32_t, champsim::page_number>{cpu_num, vaddr};
  auto hit = vpage_to_ppage_map.find(key);

  // Already translated: no minor fault, no new allocation.
  if (hit != vpage_to_ppage_map.end()) {
    return {hit->second, champsim::chrono::clock::duration::zero()};
  }

  // First touch of this virtual page: determine its physical page.
  champsim::page_number ppage{};
  auto* obj = (mol_table != nullptr) ? mol_table->find_large_contig(vaddr) : nullptr;
  if (obj != nullptr) {
    // The vpage lies in a large object's page-aligned contiguous middle segment.
    if (obj->contig_base_ppage.to<uint64_t>() == 0) {
      // First touch of the segment: allocate the whole contiguous block at once (high -> low).
      obj->contig_base_ppage = allocate_contiguous(static_cast<std::size_t>(obj->contig_num_pages));
      mol_table->register_mapping_range(obj->contig_base_ppage, static_cast<std::size_t>(obj->contig_num_pages), obj->alloc_id);
    }
    using diff = champsim::page_number::difference_type;
    ppage = obj->contig_base_ppage + static_cast<diff>(vaddr.to<uint64_t>() - obj->contig_start_page.to<uint64_t>());
  } else {
    // Small object, unaligned head/tail page, or PTE page: classic small-pool
    // single page (random/linear per the original allocator).
    ppage = ppage_front();
    ppage_pop();
    if (mol_table != nullptr) {
      mol_table->register_mapping(vaddr, ppage);
    }
  }

  vpage_to_ppage_map[key] = ppage;

  if constexpr (champsim::debug_print) {
    fmt::print("[VMEM] {} paddr: {} vpage: {} fault: 1\n", __func__, ppage, vaddr);
  }

  return {ppage, minor_fault_penalty};
}

std::pair<champsim::address, champsim::chrono::clock::duration> VirtualMemory::get_pte_pa(uint32_t cpu_num, champsim::page_number vaddr, std::size_t level)
{
  champsim::dynamic_extent pte_table_entry_extent{champsim::address::bits, shamt(level + 1)};
  auto [ppage, fault] =
      page_table.try_emplace({cpu_num, level, champsim::address_slice{pte_table_entry_extent, vaddr}}, champsim::splice(active_pte_page, next_pte_page));

  // this PTE doesn't yet have a mapping
  if (fault) {
    next_pte_page++;
    if (champsim::page_offset{next_pte_page} == champsim::page_offset{0}) {
      active_pte_page = ppage_front();
      ppage_pop();
    }
  }

  auto offset = get_offset(vaddr, level);
  champsim::address paddr{
      champsim::splice(ppage->second, champsim::address_slice{champsim::dynamic_extent{champsim::data::bits{champsim::lg2(pte_entry::byte_multiple)},
                                                                                       static_cast<std::size_t>(champsim::lg2(pte_page_size.count()))},
                                                              offset})};
  if constexpr (champsim::debug_print) {
    fmt::print("[VMEM] {} paddr: {} vaddr: {} pt_page_offset: {} translation_level: {} fault: {}\n", __func__, paddr, vaddr, offset, level, fault);
  }

  auto penalty = minor_fault_penalty;
  if (!fault) {
    penalty = champsim::chrono::clock::duration::zero();
  }

  return {paddr, penalty};
}
