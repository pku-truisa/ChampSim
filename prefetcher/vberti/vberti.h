#ifndef VBERTI_H_
#define VBERTI_H_

#include "vberti_size.h"

#include <algorithm>
#include <array>
#include <cassert>
#include <cmath>
#include <cstdint>
#include <iostream>
#include <map>
#include <queue>
#include <vector>

#include "champsim.h"
#include "modules.h"

// vBerti defines
#define MAX_HISTORY_IP (8)
#define MAX_PF (16)
#define MAX_PF_LAUNCH (12)
#define STRIDE_MASK (12)

// Mask
#define IP_MASK (0x3FF)
#define TIME_MASK (0xFFFF)
#define LAT_MASK (0xFFF)
#define ADDR_MASK (0xFFFFFF)

// Confidence
#define CONFIDENCE_MAX (16) // 6 bits
#define CONFIDENCE_INC (1)  // 6 bits
#define CONFIDENCE_INIT (1) // 6 bits
#define CONFIDENCE_L1 (65)  // 6 bits
#define CONFIDENCE_L2 (50)  // 6 bits
#define CONFIDENCE_L2R (35) // 6 bits
#define MSHR_LIMIT (70)
#define LANZAR_INT (8)

// Stride rpl
#define BERTI_R (0x0)
#define BERTI_L1 (0x1)
#define BERTI_L2 (0x2)
#define BERTI_L2R (0x3)

struct vberti : public champsim::modules::prefetcher {
  /*****************************************************************************
   *                      Berti structures                                     *
   *****************************************************************************/
  typedef struct Stride {
    uint64_t conf;
    int64_t stride;
    uint8_t rpl;
    float per;
    Stride() : conf(0), stride(0), rpl(BERTI_R), per(0) {}
  } stride_t;

  class LatencyTable {
    /* Latency table simulate the modified PQ and MSHR */
  private:
    struct latency_table {
      uint64_t addr = 0; // Addr
      uint64_t tag = 0;  // IP-Tag
      uint64_t time = 0; // Event cycle
      bool pf = false;   // Is the entry accessed by a demand miss
    };
    int size;

    latency_table* latencyt;

  public:
    LatencyTable(const int size) : size(size) { latencyt = new latency_table[size]; }
    ~LatencyTable() { delete[] latencyt; }

    uint8_t add(uint64_t addr, uint64_t tag, bool pf, uint64_t cycle);
    uint64_t get(uint64_t addr);
    uint64_t del(uint64_t addr);
    uint64_t get_tag(uint64_t addr);
  };

  class ShadowCache {
    /* Shadow cache simulate the modified L1D Cache */
  private:
    struct shadow_cache {
      uint64_t addr = 0; // Addr
      uint64_t lat = 0;  // Latency
      bool pf = false;   // Is a prefetch
    };                   // This struct is the vberti table

    int sets;
    int ways;
    shadow_cache** scache;

  public:
    ShadowCache(const int sets, const int ways)
    {
      scache = new shadow_cache*[sets];
      for (int i = 0; i < sets; i++)
        scache[i] = new shadow_cache[ways];

      this->sets = sets;
      this->ways = ways;
    }

    ~ShadowCache()
    {
      for (int i = 0; i < sets; i++)
        delete[] scache[i];
      delete[] scache;
    }

    bool add(uint32_t set, uint32_t way, uint64_t addr, bool pf, uint64_t lat);
    bool get(uint64_t addr);
    void set_pf(uint64_t addr, bool pf);
    bool is_pf(uint64_t addr);
    uint64_t get_latency(uint64_t addr);
  };

  class HistoryTable {
    /* History Table */
  private:
    struct history_table {
      uint64_t tag = 0;  // IP Tag
      uint64_t addr = 0; // IP @ accessed
      uint64_t time = 0; // Time where the line is accessed
    };                   // This struct is the history table

    const int sets = HISTORY_TABLE_SET;
    const int ways = HISTORY_TABLE_WAY;

    history_table** historyt;
    history_table** history_pointers;

    uint16_t get_aux(uint32_t latency, uint64_t tag, uint64_t act_addr, uint64_t* tags, uint64_t* addr, uint64_t cycle);

  public:
    HistoryTable()
    {
      history_pointers = new history_table*[sets];
      historyt = new history_table*[sets];

      for (int i = 0; i < sets; i++)
        historyt[i] = new history_table[ways];
      for (int i = 0; i < sets; i++)
        history_pointers[i] = historyt[i];
    }

    ~HistoryTable()
    {
      for (int i = 0; i < sets; i++)
        delete[] historyt[i];
      delete[] historyt;

      delete[] history_pointers;
    }

    void add(uint64_t tag, uint64_t addr, uint64_t cycle);
    uint16_t get(uint32_t latency, uint64_t tag, uint64_t act_addr, uint64_t* tags, uint64_t* addr, uint64_t cycle);
  };

  class InnerBerti {
    /* Berti Table */
  public:
    using stride_t = vberti::stride_t;

  private:
    typedef struct VBerti {
      std::array<stride_t, BERTI_TABLE_STRIDE_SIZE> stride;
      uint64_t conf = 0;
    } vberti_t;

    std::map<uint64_t, vberti_t*> bertit;
    std::queue<uint64_t> bertit_queue;

    void increase_conf_tag(uint64_t tag);
    void add(uint64_t tag, int64_t stride);
    static bool compare_rpl(stride_t a, stride_t b);
    static bool compare_per(stride_t a, stride_t b);

  public:
    LatencyTable* latencyt;
    ShadowCache* scache;
    HistoryTable* historyt;

    uint8_t get(uint64_t tag, stride_t* res);

    InnerBerti(int latency_table_size, int sets, int ways);
    ~InnerBerti();
    void find_and_update(uint64_t latency, uint64_t tag, uint64_t cycle, uint64_t line_addr);
  };

  InnerBerti* berti;

public:
  using prefetcher::prefetcher;

  // champsim interface prototypes
  void prefetcher_initialize();
  uint32_t prefetcher_cache_operate(champsim::address addr, champsim::address ip, uint8_t cache_hit, bool useful_prefetch, access_type type,
                                    uint32_t metadata_in);
  uint32_t prefetcher_cache_fill(champsim::address addr, long set, long way, uint8_t prefetch, champsim::address evicted_addr, uint32_t metadata_in);
  void prefetcher_cycle_operate();
  void prefetcher_final_stats();
};

#endif /* __VBERTI_H__ */