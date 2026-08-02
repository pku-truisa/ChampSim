#include "vberti.h"

#include "cache.h"

/******************************************************************************/
/*                      Latency table functions                               */
/******************************************************************************/
uint8_t vberti::LatencyTable::add(uint64_t addr, uint64_t tag, bool pf, uint64_t cycle)
{
  /*
   * Save if possible the new miss into the pqmshr (latency) table
   *
   * Parameters:
   *  - addr: address without cache offset
   *  - tag: IP-Tag
   *  - pf: is the entry accessed by a demand miss
   *  - cycle: time to use in the latency table
   *
   * Return: pf
   */

  latency_table* free;
  free = nullptr;

  for (int i = 0; i < size; i++) {
    // Search if the addr already exists. If it exist we does not have
    // to do nothing more
    if (latencyt[i].addr == addr) {
      latencyt[i].time = cycle;
      latencyt[i].tag = tag;
      latencyt[i].pf = pf;
      return latencyt[i].pf;
    }

    // We discover a free space into the latency table, save it for later
    if (latencyt[i].tag == 0)
      free = &latencyt[i];
  }

  // No free space!! This cannot be truth
  if (free == nullptr)
    return 0;

  // We save the new entry into the latency table
  free->addr = addr;
  free->time = cycle;
  free->tag = tag;
  free->pf = pf;

  return free->pf;
}

uint64_t vberti::LatencyTable::del(uint64_t addr)
{
  /*
   * Remove the address from the latency table
   *
   * Parameters:
   *  - addr: address without cache offset
   *
   *  Return: the time where the line was enqueued
   */

  for (int i = 0; i < size; i++) {
    // Line already in the table
    if (latencyt[i].addr == addr) {
      uint64_t time = latencyt[i].time; // Save the enqueued time

      latencyt[i].addr = 0; // Free the entry
      latencyt[i].tag = 0;  // Free the entry
      latencyt[i].time = 0; // Free the entry
      latencyt[i].pf = 0;   // Free the entry

      // Return the enqueued time
      return time;
    }
  }

  // We should always track the misses
  return 0;
}

uint64_t vberti::LatencyTable::get(uint64_t addr)
{
  /*
   * Return time or 0 if the addr is or is not in the pqmshr (latency) table
   *
   * Parameters:
   *  - addr: address without cache offset
   *
   * Return: time if the line is in the latency table, otherwise 0
   */

  for (int i = 0; i < size; i++) {
    // Search if the addr already exists
    if (latencyt[i].addr == addr)
      return latencyt[i].time;
  }

  return 0;
}

uint64_t vberti::LatencyTable::get_tag(uint64_t addr)
{
  /*
   * Return IP-Tag or 0 if the addr is or is not in the pqmshr (latency) table
   *
   * Parameters:
   *  - addr: address without cache offset
   *
   * Return: ip-tag if the line is in the latency table, otherwise 0
   */

  for (int i = 0; i < size; i++) {
    if (latencyt[i].addr == addr && latencyt[i].tag) // This is the address
      return latencyt[i].tag;
  }

  return 0;
}

/******************************************************************************/
/*                       Shadow Cache functions                               */
/******************************************************************************/
bool vberti::ShadowCache::add(uint32_t set, uint32_t way, uint64_t addr, bool pf, uint64_t lat)
{
  /*
   * Add block to shadow cache
   *
   * Parameters:
   *      - set: cache set
   *      - way: cache way
   *      - addr: cache block v_addr
   *      - pf: the cache is access by a demand
   */

  scache[set][way].addr = addr;
  scache[set][way].pf = pf;
  scache[set][way].lat = lat;
  return scache[set][way].pf;
}

bool vberti::ShadowCache::get(uint64_t addr)
{
  /*
   * Parameters:
   *      - addr: cache block v_addr
   *
   * Return: true if the addr is in the l1d cache, false otherwise
   */

  for (int i = 0; i < sets; i++) {
    for (int ii = 0; ii < ways; ii++) {
      if (scache[i][ii].addr == addr)
        return true;
    }
  }

  return false;
}

void vberti::ShadowCache::set_pf(uint64_t addr, bool pf)
{
  /*
   * Parameters:
   *      - addr: cache block v_addr
   *
   * Return: change value of pf field
   */

  for (int i = 0; i < sets; i++) {
    for (int ii = 0; ii < ways; ii++) {
      if (scache[i][ii].addr == addr) {
        scache[i][ii].pf = pf;
        return;
      }
    }
  }

  // The address should always be in the cache
  // assert(0 && "Address is must be in shadow cache");
}

bool vberti::ShadowCache::is_pf(uint64_t addr)
{
  /*
   * Parameters:
   *      - addr: cache block v_addr
   *
   * Return: True if the saved one is a prefetch
   */

  for (int i = 0; i < sets; i++) {
    for (int ii = 0; ii < ways; ii++) {
      if (scache[i][ii].addr == addr)
        return scache[i][ii].pf;
    }
  }

  return false;
}

uint64_t vberti::ShadowCache::get_latency(uint64_t addr)
{
  /*
   * Parameters:
   *      - addr: cache block v_addr
   *
   * Return: the saved latency
   */

  for (int i = 0; i < sets; i++) {
    for (int ii = 0; ii < ways; ii++) {
      if (scache[i][ii].addr == addr)
        return scache[i][ii].lat;
    }
  }

  assert(0 && "Address is must be in shadow cache");
  return 0;
}

/******************************************************************************/
/*                       History Table functions                               */
/******************************************************************************/
void vberti::HistoryTable::add(uint64_t tag, uint64_t addr, uint64_t cycle)
{
  /*
   * Save the new information into the history table
   *
   * Parameters:
   *  - tag: PC tag
   *  - addr: ip addr access
   */
  uint16_t set = tag & TABLE_SET_MASK;
  addr &= ADDR_MASK;

  uint64_t time = cycle & TIME_MASK;

  // Save new element into the history table
  history_pointers[set]->tag = tag;
  history_pointers[set]->time = time;
  history_pointers[set]->addr = addr;

  if (history_pointers[set] == &historyt[set][ways - 1]) {
    history_pointers[set] = &historyt[set][0]; // End the cycle
  } else
    history_pointers[set]++; // Pointer to the next (oldest) entry
}

uint16_t vberti::HistoryTable::get_aux(uint32_t latency, uint64_t tag, uint64_t act_addr, uint64_t* tags, uint64_t* addr, uint64_t cycle)
{
  /*
   * Return an array (by parameter) with all the possible PC that can launch
   * an on-time and late prefetch
   *
   * Parameters:
   *  - tag: PC tag
   *  - latency: latency of the processor
   */

  uint16_t num_on_time = 0;
  uint16_t set = tag & TABLE_SET_MASK;

  // The IPs that is launch in this cycle will be able to launch this prefetch
  if (cycle < latency)
    return num_on_time;
  cycle -= latency;

  // Pointer to guide
  history_table* pointer = history_pointers[set];

  do {
    // Look for the IPs that can launch this prefetch
    if (pointer->tag == tag && pointer->time <= cycle) {
      // Test that addr is not duplicated
      if (pointer->addr == act_addr)
        return num_on_time;

      // This IP can launch the prefetch
      tags[num_on_time] = pointer->tag;
      addr[num_on_time] = pointer->addr;
      num_on_time++;
    }

    if (pointer == historyt[set]) {
      // We get at the end of the history, we start again
      pointer = &historyt[set][ways - 1];
    } else
      pointer--;
  } while (pointer != history_pointers[set]);

  return num_on_time;
}

uint16_t vberti::HistoryTable::get(uint32_t latency, uint64_t tag, uint64_t act_addr, uint64_t* tags, uint64_t* addr, uint64_t cycle)
{
  /*
   * Return an array (by parameter) with all the possible PC that can launch
   * an on-time and late prefetch
   *
   * Parameters:
   *  - tag: PC tag
   *  - latency: latency of the processor
   *  - tags (out): ips that can launch an on-time prefetch
   *  - addr (out): addr that can launch an on-time prefetch
   */

  act_addr &= ADDR_MASK;

  uint16_t num_on_time = get_aux(latency, tag, act_addr, tags, addr, cycle & TIME_MASK);

  // We found on-time prefetchs
  return num_on_time;
}

/******************************************************************************/
/*                        Berti table functions                               */
/******************************************************************************/
vberti::InnerBerti::InnerBerti(int latency_table_size, int sets, int ways)
{
  latencyt = new LatencyTable(latency_table_size);
  scache = new ShadowCache(sets, ways);
  historyt = new HistoryTable();
}

vberti::InnerBerti::~InnerBerti()
{
  for (auto& it : bertit) {
    delete it.second; // Free the entry
  }
  bertit.clear();

  delete latencyt; // Free the latency table
  delete scache;   // Free the shadow cache
  delete historyt; // Free the history table
}

void vberti::InnerBerti::increase_conf_tag(uint64_t tag)
{
  /*
   * Increase the global confidence of the stride associated to the tag
   *
   * Parameters:
   *  tag: tag to find
   */

  if (bertit.find(tag) == bertit.end())
    return;

  // Get the entries and the strides
  vberti_t* tmp = bertit[tag];
  stride_t* aux = tmp->stride.data();

  tmp->conf += CONFIDENCE_INC;

  if (tmp->conf == CONFIDENCE_MAX) {
    // Max confidence achieve
    for (int i = 0; i < BERTI_TABLE_STRIDE_SIZE; i++) {
      float temp = (float)aux[i].conf / (float)tmp->conf;
      uint64_t aux_conf = (uint64_t)(temp * 100);

      // Set bits
      if (aux_conf > CONFIDENCE_L1)
        aux[i].rpl = BERTI_L1;
      else if (aux_conf > CONFIDENCE_L2)
        aux[i].rpl = BERTI_L2;
      else if (aux_conf > CONFIDENCE_L2R)
        aux[i].rpl = BERTI_L2R;
      else
        aux[i].rpl = BERTI_R;

      aux[i].conf = 0; // Reset stride confidence
    }

    tmp->conf = 0; // Reset global confidence
  }
}

void vberti::InnerBerti::add(uint64_t tag, int64_t stride)
{
  /*
   * Save the new information into the berti table
   *
   * Parameters:
   *  - tag: PC tag
   *  - stride: actual stride
   */

  if (bertit.find(tag) == bertit.end()) {
    // We are not tracking this tag
    if (bertit_queue.size() > BERTI_TABLE_SIZE) {
      // FIFO replacement algorithm
      uint64_t key = bertit_queue.front();

      delete bertit[key]; // Free previous entry

      bertit.erase(bertit_queue.front());
      bertit_queue.pop();
    }
    assert((bertit.size() <= BERTI_TABLE_SIZE) && "Tracking too much tags");

    bertit_queue.push(tag); // Add new tag

    // Global confidence
    vberti_t* entry = new vberti_t;
    entry->conf = CONFIDENCE_INC;

    // Create new stride
    entry->stride[0].stride = stride;
    entry->stride[0].conf = CONFIDENCE_INIT;
    entry->stride[0].rpl = BERTI_R;

    // Save the new tag
    bertit.insert(std::make_pair(tag, entry));
    return;
  }

  // Get the strides
  vberti_t* tmp = bertit[tag];
  stride_t* aux = tmp->stride.data();

  // Increase IP confidence
  for (int i = 0; i < BERTI_TABLE_STRIDE_SIZE; i++) {
    if (aux[i].stride == stride) {
      // We already track the stride
      aux[i].conf += CONFIDENCE_INC;

      if (aux[i].conf > CONFIDENCE_MAX)
        aux[i].conf = CONFIDENCE_MAX;

      return;
    }
  }

  // We find a free (BERTI_R) entry with the lowest confidence
  uint8_t dx_conf = 100;
  int dx_remove = -1;
  for (int i = 0; i < BERTI_TABLE_STRIDE_SIZE; i++) {
    if (aux[i].rpl == BERTI_R && aux[i].conf < dx_conf) {
      dx_conf = aux[i].conf;
      dx_remove = i;
    }
  }

  if (dx_remove > -1) {
    tmp->stride[dx_remove].stride = stride;
    tmp->stride[dx_remove].conf = CONFIDENCE_INIT;
    tmp->stride[dx_remove].rpl = BERTI_R;
    return;
  }

  // We find a BERTI_L2R entry with the lowest confidence
  dx_conf = 100;
  dx_remove = -1;
  for (int i = 0; i < BERTI_TABLE_STRIDE_SIZE; i++) {
    if (aux[i].rpl == BERTI_L2R && aux[i].conf < dx_conf) {
      dx_conf = aux[i].conf;
      dx_remove = i;
    }
  }

  if (dx_remove > -1) {
    tmp->stride[dx_remove].stride = stride;
    tmp->stride[dx_remove].conf = CONFIDENCE_INIT;
    tmp->stride[dx_remove].rpl = BERTI_R;
    return;
  }
}

uint8_t vberti::InnerBerti::get(uint64_t tag, stride_t* res)
{
  /*
   * Save the new information into the berti table
   *
   * Parameters:
   *  - tag: PC tag
   *
   * Return: the stride to prefetch
   */

  if (!bertit.count(tag))
    return 0;

  // We found the tag
  vberti_t* tmp = bertit[tag];
  stride_t* aux = tmp->stride.data();
  uint16_t dx = 0;

  for (int i = 0; i < BERTI_TABLE_STRIDE_SIZE; i++) {
    if (aux[i].stride != 0 && aux[i].rpl) {
      // Substitute min confidence for the next one
      res[dx].stride = aux[i].stride;
      res[dx].rpl = aux[i].rpl;
      dx++;
    }
  }

  if (dx == 0 && tmp->conf >= LANZAR_INT) {
    // We do not find any stable stride, try to launch with small confidence
    for (int i = 0; i < BERTI_TABLE_STRIDE_SIZE; i++) {
      if (aux[i].stride != 0) {
        // Substitute min confidence for the next one
        res[dx].stride = aux[i].stride;
        float temp = (float)aux[i].conf / (float)tmp->conf;
        uint64_t aux_conf = (uint64_t)(temp * 100);
        res[dx].per = aux_conf;
        dx++;
      }
    }
    std::sort(res, res + MAX_PF, compare_per);

    for (int i = 0; i < MAX_PF; i++) {
      if (res[i].per > 80)
        res[i].rpl = BERTI_L1;
      else if (res[i].per > 35)
        res[i].rpl = BERTI_L2;
      else
        res[i].rpl = BERTI_R;
    }
    std::sort(res, res + MAX_PF, compare_rpl);
    return 1;
  }

  std::sort(res, res + MAX_PF, compare_rpl);

  return 1;
}

bool vberti::InnerBerti::compare_rpl(stride_t a, stride_t b)
{
  // Sort stride when the confidence is full
  if (a.rpl == BERTI_L1 && b.rpl != BERTI_L1)
    return 1;
  else if (a.rpl != BERTI_L1 && b.rpl == BERTI_L1)
    return 0;
  else {
    if (a.rpl == BERTI_L2 && b.rpl != BERTI_L2)
      return 1;
    else if (a.rpl != BERTI_L2 && b.rpl == BERTI_L2)
      return 0;
    else {
      if (a.rpl == BERTI_L2R && b.rpl != BERTI_L2R)
        return 1;
      if (a.rpl != BERTI_L2R && b.rpl == BERTI_L2R)
        return 0;
      else {
        if (std::abs(a.stride) < std::abs(b.stride))
          return 1;
        return 0;
      }
    }
  }
}

bool vberti::InnerBerti::compare_per(stride_t a, stride_t b)
{
  // Sort by percentage
  if (a.per > b.per)
    return 1;
  else {
    if (std::abs(a.stride) < std::abs(b.stride))
      return 1;
    return 0;
  }
}

void vberti::InnerBerti::find_and_update(uint64_t latency, uint64_t tag, uint64_t cycle, uint64_t line_addr)
{
  // We were tracking this miss
  uint64_t tags[HISTORY_TABLE_WAY];
  uint64_t addr[HISTORY_TABLE_WAY];
  uint16_t num_on_time = 0;

  // Get the IPs that can launch a prefetch
  num_on_time = historyt->get(latency, tag, line_addr, tags, addr, cycle);

  for (uint32_t i = 0; i < num_on_time; i++) {
    // Increase conf tag
    if (i == 0)
      increase_conf_tag(tag);

    // Max number of strides that we can find
    if (i >= MAX_HISTORY_IP)
      break;

    // Add information into berti table
    int64_t stride;
    line_addr &= ADDR_MASK;

    // Usually applications go from lower to higher memory position.
    // The operation order is important (mainly because we allow
    // negative strides)
    stride = (int64_t)(line_addr - addr[i]);

    if ((std::abs(stride) < (1 << STRIDE_MASK))) {
      // Only useful strides
      add(tags[i], stride);
    }
  }
}

/******************************************************************************/
/*                        Cache Functions                                     */
/******************************************************************************/
void vberti::prefetcher_initialize()
{
  // Calculate latency table size
  uint64_t latency_table_size = intern_->get_mshr_size();
  for (auto const& i : intern_->get_rq_size())
    latency_table_size += i;
  for (auto const& i : intern_->get_wq_size())
    latency_table_size += i;
  for (auto const& i : intern_->get_pq_size())
    latency_table_size += i;

  // New structures
  berti = new InnerBerti(latency_table_size, intern_->NUM_SET, intern_->NUM_WAY);

  std::cout << "L1D VBerti prefetcher" << std::endl;
  std::cout << "History Sets: " << HISTORY_TABLE_SET << std::endl;
  std::cout << "History Ways: " << HISTORY_TABLE_WAY << std::endl;
  std::cout << "BERTI Table Size: " << BERTI_TABLE_SIZE << std::endl;
  std::cout << "BERTI Stride Size: " << BERTI_TABLE_STRIDE_SIZE << std::endl;
}

uint32_t vberti::prefetcher_cache_operate(champsim::address address, champsim::address ip_addr, uint8_t cache_hit, bool useful_prefetch,
                                          access_type type, uint32_t metadata_in)
{
  uint64_t addr = address.to<uint64_t>();
  uint64_t ip = ip_addr.to<uint64_t>();

  // get current CPU cycle
  auto current_cycle = intern_->current_time.time_since_epoch() / intern_->clock_period;

  // We select the structures
  auto latencyt = berti->latencyt;
  auto scache = berti->scache;
  auto historyt = berti->historyt;

  uint64_t line_addr = (addr >> LOG2_BLOCK_SIZE); // Line addr

  // IP hash
  ip = ((ip >> 1) ^ (ip >> 4));
  ip = ip & IP_MASK;

  if (!cache_hit) {
    // This is a miss

    // Add @ to latency table
    latencyt->add(line_addr, ip, true, current_cycle);

    // Add to history table
    historyt->add(ip, line_addr, current_cycle);

  } else if (cache_hit && scache->is_pf(line_addr)) {
    // Cache line access
    scache->set_pf(line_addr, false);

    // Get latency
    uint64_t latency = scache->get_latency(line_addr);

    if (latency > LAT_MASK)
      latency = 0;

    berti->find_and_update(latency, ip, current_cycle & TIME_MASK, line_addr);

    historyt->add(ip, line_addr, current_cycle);
  } else {
    // Cache line access, no pf in hit
    scache->set_pf(line_addr, false);
  }

  // Get stride to prefetch
  stride_t stride[MAX_PF];
  for (int i = 0; i < MAX_PF; i++) {
    stride[i].conf = 0;
    stride[i].stride = 0;
    stride[i].rpl = BERTI_R;
  }

  if (!berti->get(ip, stride))
    return metadata_in;

  for (int i = 0; i < MAX_PF_LAUNCH; i++) {
    uint64_t p_addr = (line_addr + stride[i].stride) << LOG2_BLOCK_SIZE;

    // If the line is in the latency table, do not prefetch
    if (latencyt->get(p_addr))
      continue;

    // Level of prefetching depends on CONFIDENCE
    bool fill_this_level = false;
    float mshr_load = intern_->get_mshr_occupancy_ratio() * 100;

    if (stride[i].rpl == BERTI_L1 && mshr_load < MSHR_LIMIT) {
      fill_this_level = true;
    } else if (stride[i].rpl == BERTI_L1 || stride[i].rpl == BERTI_L2 || stride[i].rpl == BERTI_L2R) {
      fill_this_level = false;
    } else {
      return metadata_in;
    }

    if (prefetch_line(champsim::address{p_addr}, fill_this_level, 0)) {
    }
  }

  return metadata_in;
}

uint32_t vberti::prefetcher_cache_fill(champsim::address address, long set, long way, uint8_t prefetch, champsim::address evicted_addr,
                                       uint32_t metadata_in)
{
  uint64_t addr = address.to<uint64_t>();

  // get current CPU cycle
  auto current_cycle = intern_->current_time.time_since_epoch() / intern_->clock_period;

  // We select the structures
  auto latencyt = berti->latencyt;
  auto scache = berti->scache;

  uint64_t line_addr = (addr >> LOG2_BLOCK_SIZE); // Line addr

  // Remove @ from latency table
  uint64_t tag = latencyt->get_tag(line_addr);
  uint64_t cycle = latencyt->del(line_addr) & TIME_MASK;
  uint64_t latency = 0;

  if (cycle != 0 && ((current_cycle & TIME_MASK) > cycle))
    latency = (current_cycle & TIME_MASK) - cycle;

  if (latency > LAT_MASK)
    latency = 0;

  // Add to the shadow cache
  scache->add(set, way, line_addr, prefetch, latency);

  if (latency != 0 && !prefetch) {
    berti->find_and_update(latency, tag, cycle, line_addr);
  }

  return metadata_in;
}

void vberti::prefetcher_cycle_operate() {}

void vberti::prefetcher_final_stats() {}