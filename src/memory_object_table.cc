#include "memory_object_table.h"

#include <algorithm>
#include <stdexcept>

#include "util/bits.h"
#include "util/to_underlying.h"

// Global singleton instance
MemoryObjectTable mol_table;

uint64_t MemoryObjectTable::record_alloc(champsim::address vaddr, uint64_t size, uint8_t alloc_type)
{
  uint64_t id = next_alloc_id++;

  // Add to active_objects (keep sorted by vaddr_start)
  ActiveObject obj;
  obj.vaddr_start = vaddr;
  obj.vaddr_end = champsim::address{static_cast<uint64_t>(vaddr.to<uint64_t>() + size)};
  obj.alloc_type = alloc_type;
  obj.alloc_id = id;
  obj.size = size;

  auto pos = std::lower_bound(active_objects.begin(), active_objects.end(), obj,
                              [](const ActiveObject& a, const ActiveObject& b) { return a.vaddr_start < b.vaddr_start; });
  active_objects.insert(pos, obj);

  // Add to all_objects
  ObjectRecord record;
  record.vaddr_start = vaddr;
  record.size = size;
  record.alloc_type = alloc_type;
  record.alloc_id = id;
  all_objects.push_back(record);

  return id;
}

void MemoryObjectTable::record_free(champsim::address vaddr)
{
  // Find and remove from active_objects
  auto it =
      std::lower_bound(active_objects.begin(), active_objects.end(), vaddr,
                       [](const ActiveObject& obj, champsim::address va) { return obj.vaddr_start < va; });

  if (it != active_objects.end() && it->vaddr_start == vaddr) {
    active_objects.erase(it);
  }

  // Note: We do NOT remove from ppage_to_vpage here. Old mappings will be
  // overwritten when the same physical page is reused for a new allocation.
}

void MemoryObjectTable::register_mapping(champsim::page_number vpage, champsim::page_number ppage)
{
  // Check if this virtual page belongs to an active allocation
  champsim::address vaddr{vpage.to<uint64_t>() << champsim::lg2(PAGE_SIZE)};

  const ActiveObject* obj = find_active_by_va(vaddr);
  if (obj != nullptr) {
    // This physical page now maps to this virtual page (belonging to obj)
    ppage_to_vpage[ppage] = vpage;
  }
  // If the VA is not in any active allocation, we don't register the mapping.
  // Old mappings for freed objects remain until overwritten.
}

uint64_t MemoryObjectTable::lookup_alloc_id_by_pa(champsim::page_number ppage) const
{
  // Step 1: PA → VA via reverse page table
  auto it = ppage_to_vpage.find(ppage);
  if (it == ppage_to_vpage.end()) {
    return 0; // No known mapping
  }

  // Step 2: VA → active object lookup
  champsim::address vaddr{it->second.to<uint64_t>() << champsim::lg2(PAGE_SIZE)};
  const ActiveObject* obj = find_active_by_va(vaddr);
  if (obj != nullptr) {
    return obj->alloc_id;
  }

  return 0; // Object was freed, no longer active
}

PerCacheStats& MemoryObjectTable::get_cache_stats(uint64_t alloc_id, const std::string& cache_name)
{
  ObjectRecord* rec = find_record(alloc_id);
  if (rec == nullptr) {
    throw std::runtime_error("MemoryObjectTable::get_cache_stats: alloc_id " + std::to_string(alloc_id) + " not found");
  }
  return rec->cache_stats[cache_name];
}

PerDRAMStats& MemoryObjectTable::get_dram_stats(uint64_t alloc_id, const std::string& dram_name)
{
  ObjectRecord* rec = find_record(alloc_id);
  if (rec == nullptr) {
    throw std::runtime_error("MemoryObjectTable::get_dram_stats: alloc_id " + std::to_string(alloc_id) + " not found");
  }
  return rec->dram_stats[dram_name];
}

const MemoryObjectTable::ActiveObject* MemoryObjectTable::find_active_by_va(champsim::address vaddr) const
{
  // Binary search: find the active_range whose page [vaddr, vaddr+PAGE_SIZE) 
  // overlaps with the object's [vaddr_start, vaddr_end).
  // Because vaddr is page-aligned and object boundaries may not be page-aligned,
  // we use an overlap check rather than exact containment.
  auto it = std::upper_bound(active_objects.begin(), active_objects.end(), vaddr,
                             [](champsim::address va, const ActiveObject& obj) { return va < obj.vaddr_start; });

  if (it != active_objects.begin()) {
    --it;
    // Check page overlap: Page [vaddr, vaddr+PAGE_SIZE) overlaps [it->vaddr_start, it->vaddr_end)?
    champsim::address page_end{vaddr.to<uint64_t>() + PAGE_SIZE};
    if (vaddr < it->vaddr_end && page_end > it->vaddr_start) {
      return &(*it);
    }
  }

  return nullptr;
}

MemoryObjectTable::ObjectRecord* MemoryObjectTable::find_record(uint64_t alloc_id)
{
  auto it = std::find_if(all_objects.begin(), all_objects.end(),
                         [alloc_id](const ObjectRecord& r) { return r.alloc_id == alloc_id; });
  return (it != all_objects.end()) ? &(*it) : nullptr;
}