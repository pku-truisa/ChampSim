#include "memory_object_table.h"

#include <algorithm>
#include <stdexcept>

#include "util/bits.h"
#include "util/to_underlying.h"

// Global singleton instance
MemoryObjectTable mol_table;

uint64_t MemoryObjectTable::record_alloc(champsim::address vaddr, uint64_t size, uint8_t alloc_type, uint64_t caller_ip)
{
  uint64_t id = next_alloc_id++;

  // Add to active_objects (map keyed by vaddr_start, O(log n) insert)
  ActiveObject obj;
  obj.vaddr_start = vaddr;
  obj.vaddr_end = champsim::address{static_cast<uint64_t>(vaddr.to<uint64_t>() + size)};
  obj.alloc_type = alloc_type;
  obj.alloc_id = id;
  obj.size = size;

  obj.caller_ip = caller_ip;

  // Large-object segmentation: only the page-aligned middle is contiguous.
  obj.is_large = (size >= LARGE_OBJECT_THRESHOLD);
  if (obj.is_large) {
    const uint64_t s = vaddr.to<uint64_t>();
    const uint64_t e = s + size; // exclusive
    obj.contig_start_page = champsim::page_number{(s + PAGE_SIZE - 1) / PAGE_SIZE}; // ceil(start/PAGE_SIZE)
    obj.contig_num_pages =
        static_cast<int64_t>(e / PAGE_SIZE) - static_cast<int64_t>(obj.contig_start_page.to<uint64_t>());
  }

  active_objects.emplace(vaddr, obj);

  // Add to all_objects
  ObjectRecord record;
  record.vaddr_start = vaddr;
  record.size = size;
  record.alloc_type = alloc_type;
  record.alloc_id = id;
  record.caller_ip = caller_ip;
  all_objects.push_back(record);

  // Index the new record for O(1) lookup by alloc_id
  allocid_to_record[id] = all_objects.size() - 1;

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

uint64_t MemoryObjectTable::lookup_alloc_id_by_va(champsim::address vaddr) const
{
  // Use the page-aligned VA to find which active object owns this address
  return find_alloc_id_by_va(vaddr);
}

uint64_t MemoryObjectTable::lookup_caller_ip_by_va(champsim::address vaddr) const
{
  const ActiveObject* obj = find_active_by_va(vaddr);
  if (obj != nullptr) {
    return obj->caller_ip;
  }
  return 0;
}

std::pair<champsim::address, champsim::address> MemoryObjectTable::get_object_bounds(champsim::address vaddr) const
{
  const ActiveObject* obj = find_active_by_va(vaddr);
  if (obj == nullptr) {
    // vaddr does not belong to any active object
    return {champsim::address{0}, champsim::address{0}};
  }
  return {obj->vaddr_start, obj->vaddr_end};
}

void MemoryObjectTable::register_mapping_range(champsim::page_number ppage_start, std::size_t num_pages, uint64_t alloc_id)
{
  using diff = champsim::page_number::difference_type;
  for (std::size_t i = 0; i < num_pages; ++i) {
    ppage_to_allocid[ppage_start + static_cast<diff>(i)] = alloc_id;
  }
}

MemoryObjectTable::ActiveObject* MemoryObjectTable::find_large_contig(champsim::page_number vpage)
{
  // Reconstruct the page-aligned byte address and locate the owning active object.
  champsim::address vaddr{vpage.to<uint64_t>() << champsim::lg2(PAGE_SIZE)};
  auto it = active_objects.upper_bound(vaddr);
  if (it == active_objects.begin()) {
    return nullptr;
  }
  --it;
  auto& obj = it->second;

  if (!obj.is_large || obj.contig_num_pages <= 0) {
    return nullptr;
  }

  // Check the vpage falls within the page-aligned contiguous middle segment.
  const uint64_t vp = vpage.to<uint64_t>();
  const uint64_t cs = obj.contig_start_page.to<uint64_t>();
  if (vp < cs || vp >= cs + static_cast<uint64_t>(obj.contig_num_pages)) {
    return nullptr;
  }
  return &obj;
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
    // For alloc_id=0 (unmatched), use the sentinel; otherwise this is unexpected
    if (alloc_id != 0) {
      throw std::runtime_error("MemoryObjectTable::get_cache_stats: alloc_id " + std::to_string(alloc_id) + " not found");
    }
    rec = &unmatched_record;
    unmatched_record.alloc_id = 0;
  }
  return rec->cache_stats[cache_name];
}

PerDRAMStats& MemoryObjectTable::get_dram_stats(uint64_t alloc_id, const std::string& dram_name)
{
  ObjectRecord* rec = find_record(alloc_id);
  if (rec == nullptr) {
    if (alloc_id != 0) {
      throw std::runtime_error("MemoryObjectTable::get_dram_stats: alloc_id " + std::to_string(alloc_id) + " not found");
    }
    rec = &unmatched_record;
    unmatched_record.alloc_id = 0;
  }
  return rec->dram_stats[dram_name];
}

const MemoryObjectTable::ActiveObject* MemoryObjectTable::find_active_by_va(champsim::address vaddr) const
{
  // Find the active object whose page [vaddr, vaddr+PAGE_SIZE) overlaps the
  // object's [vaddr_start, vaddr_end). Because vaddr is page-aligned and object
  // boundaries may not be page-aligned, a page can overlap the HEAD of an object
  // (vaddr < vaddr_start) or its body, so we check both the predecessor and the
  // successor of the upper_bound position.
  auto it = active_objects.upper_bound(vaddr);

  if (it != active_objects.begin()) {
    auto prev = it;
    --prev;
    champsim::address page_end{vaddr.to<uint64_t>() + PAGE_SIZE};
    if (vaddr < prev->second.vaddr_end && page_end > prev->second.vaddr_start) {
      return &prev->second;
    }
  }

  if (it != active_objects.end()) {
    champsim::address page_end{vaddr.to<uint64_t>() + PAGE_SIZE};
    if (vaddr < it->second.vaddr_end && page_end > it->second.vaddr_start) {
      return &it->second;
    }
  }

  return nullptr;
}

// Search active objects for an alloc_id by VA page overlap.
// Only active (currently allocated) objects are valid targets.
// Freed objects are intentionally not searched — a freed object should
// not be associated with any new memory access.
uint64_t MemoryObjectTable::find_alloc_id_by_va(champsim::address vaddr) const
{
  const ActiveObject* active = find_active_by_va(vaddr);
  if (active != nullptr) {
    return active->alloc_id;
  }

  return 0; // Not found in active allocations
}

MemoryObjectTable::ObjectRecord* MemoryObjectTable::find_record(uint64_t alloc_id)
{
  auto it = allocid_to_record.find(alloc_id);
  if (it != allocid_to_record.end()) {
    return &all_objects[it->second];
  }
  return nullptr;
}
