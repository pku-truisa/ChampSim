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

  // Add to active_objects (map keyed by vaddr_start, O(log n) insert)
  ActiveObject obj;
  obj.vaddr_start = vaddr;
  obj.vaddr_end = champsim::address{static_cast<uint64_t>(vaddr.to<uint64_t>() + size)};
  obj.alloc_type = alloc_type;
  obj.alloc_id = id;
  obj.size = size;

  active_objects.emplace(vaddr, obj);

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
  // Find and remove from active_objects (map, O(log n))
  auto it = active_objects.find(vaddr);
  if (it != active_objects.end()) {
    active_objects.erase(it);
  }

  // Note: We do NOT remove from ppage_to_allocid here. Old mappings will be
  // overwritten when the same physical page is reused for a new allocation.
}

void MemoryObjectTable::register_mapping(champsim::page_number vpage, champsim::page_number ppage)
{
  // Check if this virtual page belongs to an active or historical allocation
  champsim::address vaddr{vpage.to<uint64_t>() << champsim::lg2(PAGE_SIZE)};
  uint64_t alloc_id = find_alloc_id_by_va(vaddr);

  if (alloc_id > 0) {
    // Store the alloc_id directly for this physical page
    ppage_to_allocid[ppage] = alloc_id;
  }
}

uint64_t MemoryObjectTable::lookup_alloc_id_by_pa(champsim::page_number ppage) const
{
  // Direct lookup: PA → alloc_id
  auto it = ppage_to_allocid.find(ppage);
  if (it == ppage_to_allocid.end()) {
    return 0; // No known mapping
  }

  return it->second;
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
  // Uses map::upper_bound for O(log n) search on the sorted map.
  auto it = active_objects.upper_bound(vaddr);

  if (it != active_objects.begin()) {
    --it;
    // Check page overlap: Page [vaddr, vaddr+PAGE_SIZE) overlaps [it->vaddr_start, it->vaddr_end)?
    champsim::address page_end{vaddr.to<uint64_t>() + PAGE_SIZE};
    if (vaddr < it->second.vaddr_end && page_end > it->second.vaddr_start) {
      return &it->second;
    }
  }

  return nullptr;
}

// Search all_objects (both active and freed) for an alloc_id by VA page overlap
uint64_t MemoryObjectTable::find_alloc_id_by_va(champsim::address vaddr) const
{
  // Check active objects first
  const ActiveObject* active = find_active_by_va(vaddr);
  if (active != nullptr) {
    return active->alloc_id;
  }

  // Fall back to historical objects (freed allocations)
  champsim::address page_end{vaddr.to<uint64_t>() + PAGE_SIZE};
  for (const ObjectRecord& rec : all_objects) {
    champsim::address obj_end{rec.vaddr_start.to<uint64_t>() + rec.size};
    if (vaddr < obj_end && page_end > rec.vaddr_start) {
      return rec.alloc_id;
    }
  }

  return 0; // Not found
}

MemoryObjectTable::ObjectRecord* MemoryObjectTable::find_record(uint64_t alloc_id)
{
  auto it = std::find_if(all_objects.begin(), all_objects.end(),
                         [alloc_id](const ObjectRecord& r) { return r.alloc_id == alloc_id; });
  return (it != all_objects.end()) ? &(*it) : nullptr;
}