/* Profile heap and stack memory usage of running program.
   Copyright (C) 1998-2026 Free Software Foundation, Inc.
   This file is part of the GNU C Library.

   The GNU C Library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Lesser General Public
   License as published by the Free Software Foundation; either
   version 2.1 of the License, or (at your option) any later version.

   The GNU C Library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Lesser General Public License for more details.

   You should have received a copy of the GNU Lesser General Public
   License along with the GNU C Library; if not, see
   <https://www.gnu.org/licenses/>.  */

#include <assert.h>
#include <dlfcn.h>
#include <errno.h>
#include <error.h>
#include <fcntl.h>
#include <libintl.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/time.h>
#include <unistd.h>
#include <unistd_ext.h>

#include <hp-timing.h>
#include <machine-sp.h>
#include <stackinfo.h>  /* For _STACK_GROWS_UP  */

/* ChampSim malloc trace type codes */
enum {
  TYPE_MALLOC   = 1,
  TYPE_CALLOC   = 2,
  TYPE_REALLOC  = 3,
  TYPE_FREE     = 4,
  TYPE_MMAP     = 5,
  TYPE_MMAP64   = 6,
  TYPE_MREMAP   = 7,
  TYPE_MUNMAP   = 8,
  TYPE_MAIN_BEG = 9,
  TYPE_POSIX_MEMALIGN = 10,
  TYPE_ALIGNED_ALLOC  = 11,
};

/* ChampSim malloc trace record (40 bytes) */
struct malloc_instr {
  unsigned long long arg1;
  unsigned long long arg2;
  unsigned long long ret;
  unsigned long long caller_ip;
  unsigned char type;
  unsigned char reserved[7];
};

/* TLS: pending ChampSim trace info for update_data() */
static __thread unsigned char mtrace_type = 0;
static __thread unsigned long long mtrace_arg1 = 0;
static __thread unsigned long long mtrace_arg2 = 0;
static __thread unsigned long long mtrace_ret = 0;
static __thread unsigned long long mtrace_caller_ip = 0;

/* Pointer to the real functions.  These are determined used `dlsym'
   when really needed.  */
static void *(*mallocp)(size_t);
static void *(*reallocp) (void *, size_t);
static void *(*callocp) (size_t, size_t);
static void (*freep) (void *);

static void *(*mmapp) (void *, size_t, int, int, int, off_t);
static void *(*mmap64p) (void *, size_t, int, int, int, off64_t);
static int (*munmapp) (void *, size_t);
static void *(*mremapp) (void *, size_t, size_t, int, void *);

static int (*posix_memalignp) (void **, size_t, size_t);
static void *(*aligned_allocp) (size_t, size_t);

enum
{
  idx_malloc = 0,
  idx_realloc,
  idx_calloc,
  idx_free,
  idx_mmap_r,
  idx_mmap_w,
  idx_mmap_a,
  idx_mremap,
  idx_munmap,
  idx_posix_memalign,
  idx_aligned_alloc,
  idx_last
};


struct header
{
  size_t length;
  size_t magic;
  unsigned long long caller_ip;      /* caller IP at allocation time (for lifetime) */
  unsigned long long alloc_cycles;   /* HP_TIMING_NOW cycles at allocation time */
};

#define MAGIC 0xfeedbeaf


static _Atomic unsigned long int calls[idx_last];
static _Atomic unsigned long int failed[idx_last];
static _Atomic size_t total[idx_last];
static _Atomic size_t grand_total;
static _Atomic unsigned long int histogram[65536 / 16];
static _Atomic unsigned long int large;
static _Atomic unsigned long int calls_total;
static _Atomic unsigned long int inplace;
static _Atomic unsigned long int decreasing;
static _Atomic unsigned long int realloc_free;
static _Atomic unsigned long int inplace_mremap;
static _Atomic unsigned long int decreasing_mremap;
static _Atomic size_t current_heap;
static _Atomic size_t peak_use[3];
static __thread uintptr_t start_sp;

/* A few macros to make the source more readable.  */
#define peak_heap       peak_use[0]
#define peak_stack      peak_use[1]
#define peak_total      peak_use[2]

#define DEFAULT_BUFFER_SIZE     32768
static size_t buffer_size;

static int fd = -1;

static bool not_me;
static int initialized;
static bool trace_mmap;
extern const char *__progname;

/* ChampSim malloc trace support */
static int mtrace_fd = -1;

/* === New statistics tracking for three output tables === */
static FILE *summary_fp = NULL;
static FILE *mtrace_fp = NULL;            /* xz popen alternative to mtrace_fd */

/* Power-of-2 distribution: 48 buckets (2^0 .. 2^47) */
#define POW2_BUCKETS 48
static _Atomic unsigned long long pow2_objs[POW2_BUCKETS];
static _Atomic unsigned long long pow2_sizes[POW2_BUCKETS];

/* 13 size threshold intervals [16,32,64,128,256,512,1024,2048,4096,8192,16384,32768,65536] */
#define NUM_THRESHOLDS 13
static const size_t threshold_vals[NUM_THRESHOLDS] = {
  16, 32, 64, 128, 256, 512, 1024, 2048, 4096, 8192, 16384, 32768, 65536
};
/* Cumulative interval tracking (matching Python's bisect_right semantics)
   cum_aligned[i] = actual_{<=threshold[i]} + pow2_{>threshold[i]}
   cum_actual[i]  = actual_{<=threshold[i]}
   cum_objs[i]    = count_{<=threshold[i]}  */
static _Atomic unsigned long long cum_aligned[NUM_THRESHOLDS];
static _Atomic unsigned long long cum_actual[NUM_THRESHOLDS];
static _Atomic long long cum_objs[NUM_THRESHOLDS];
static unsigned long long peak_aligned[NUM_THRESHOLDS];
static unsigned long long peak_actual[NUM_THRESHOLDS];
static long long peak_objs[NUM_THRESHOLDS];
static _Atomic unsigned long long peak_heap_val;
static _Atomic unsigned long long peak_objs_val;
static _Atomic unsigned long long alive_objs;   /* current number of live objects */

/* Peak alive objects tracking (moment when alive_objs peaks) */
static _Atomic unsigned long long peak_objs_cnt_val;   /* peak of alive_objs */
static _Atomic unsigned long long peak_objs_cnt_heap;  /* current_heap at that moment */
static unsigned long long peak_objs_cnt_aligned[NUM_THRESHOLDS];
static unsigned long long peak_objs_cnt_actual[NUM_THRESHOLDS];
static long long peak_objs_cnt_objs[NUM_THRESHOLDS];

/* Caller IP hash table */
#define CALLER_HASH_SIZE 32768
struct caller_entry {
  _Atomic unsigned long long ip;
  _Atomic unsigned long long count;
  _Atomic unsigned long long tot_sz;
  _Atomic unsigned long long tot_lt;     /* total lifetime in cycles (freed objects) */
  _Atomic unsigned long long alloc_cycles_sum; /* sum of alloc_cycles for unfreed objects */
  _Atomic unsigned long long unfreed_cnt;      /* number of objects not yet freed */
  _Atomic unsigned int types[12];        /* frequency per type (indices 1-11) */
};
static struct caller_entry caller_tbl[CALLER_HASH_SIZE];
static _Atomic unsigned long long caller_entries;

struct entry
{
  uint64_t heap;
  uint64_t stack;
  uint32_t time_low;
  uint32_t time_high;
};

static struct entry buffer[2 * DEFAULT_BUFFER_SIZE];
static _Atomic uint32_t buffer_cnt;
static struct entry first;

static void
gettime (struct entry *e)
{
#if HP_TIMING_INLINE
  hp_timing_t now;
  HP_TIMING_NOW (now);
  e->time_low = now & 0xffffffff;
  e->time_high = now >> 32;
#else
  struct __timespec64 now;
  uint64_t usecs;
  __clock_gettime64 (CLOCK_REALTIME, &now);
  usecs = (uint64_t)now.tv_nsec / 1000 + (uint64_t)now.tv_sec * 1000000;
  e->time_low = usecs & 0xffffffff;
  e->time_high = usecs >> 32;
#endif
}

static inline void
peak_atomic_max (_Atomic size_t *peak, size_t val)
{
  size_t v;
  do
    {
      v = atomic_load_explicit (peak, memory_order_relaxed);
      if (v >= val)
	break;
    }
  while (! atomic_compare_exchange_weak (peak, &v, val));
}

/* Forward declarations for helper functions used in update_data.  */
static inline void stats_check_peak (void);
static inline void stats_check_peak_objs (void);
static inline unsigned long long get_cycles (void);

/* Update the global data after a successful function call.  */
static void
update_data (struct header *result, size_t len, size_t old_len)
{
  if (result != NULL)
    {
      /* Record the information we need and mark the block using a
         magic number.  */
      result->length = len;
      result->magic = MAGIC;
      /* Store caller IP and cycle count for lifetime tracking.  */
      result->caller_ip = mtrace_caller_ip;
      result->alloc_cycles = get_cycles ();
    }

  /* Compute current heap usage and compare it with the maximum value.
     Use a CAS loop to clamp current_heap at 0, preventing unsigned
     underflow when a free matches a pre-library or non-tracked alloc.  */
  size_t heap;
  if (len >= old_len) {
    /* alloc / expand / no-change: always safe.  */
    heap = atomic_fetch_add_explicit (&current_heap, len - old_len,
                                      memory_order_relaxed) + len - old_len;
  } else {
    /* shrink / free: guard against underflow.  */
    size_t dec = old_len - len;
    size_t old_val;
    do {
      old_val = atomic_load_explicit (&current_heap, memory_order_relaxed);
      if (old_val < dec) {
        /* Clamp result to 0.  */
        size_t expected = old_val;
        if (atomic_compare_exchange_weak (&current_heap, &expected, 0)) {
          heap = 0;
          break;
        }
        /* CAS failed, another thread changed current_heap — retry.  */
        continue;
      }
      heap = old_val - dec;
    } while (!atomic_compare_exchange_weak (&current_heap, &old_val, heap));
  }
  /* Only record peaks that pass a basic sanity filter.  */
  if (heap <= 1125899906842624ULL)  /* 1 PB sanity cap */
    peak_atomic_max (&peak_heap, heap);
  /* Check and snapshot peak-interval stats.  */
  /* stats_check_peak moved after stats_alloc/free */

  /* Compute current stack usage and compare it with the maximum
     value.  The base stack pointer might not be set if this is not
     the main thread and it is the first call to any of these
     functions.  */
  if (__glibc_unlikely (!start_sp))
    start_sp = __thread_stack_pointer ();

  uintptr_t sp = __thread_stack_pointer ();
#if _STACK_GROWS_UP
  /* This can happen in threads where we didn't catch the thread's
     stack early enough.  */
  if (__glibc_unlikely (sp < start_sp))
    start_sp = sp;
  size_t current_stack = sp - start_sp;
#else
  /* This can happen in threads where we didn't catch the thread's
     stack early enough.  */
  if (__glibc_unlikely (sp > start_sp))
    start_sp = sp;
  size_t current_stack = start_sp - sp;
#endif
  peak_atomic_max (&peak_stack, current_stack);

  /* Add up heap and stack usage and compare it with the maximum value.  */
  peak_atomic_max (&peak_total, heap + current_stack);

  /* Store the value only if we are writing to a file.  */
  if (fd != -1)
    {
      uint32_t idx = atomic_fetch_add_explicit (&buffer_cnt, 1,
						memory_order_relaxed);
      if (idx + 1 >= 2 * buffer_size)
        {
          /* We try to reset the counter to the correct range.  If
             this fails because of another thread increasing the
             counter it does not matter since that thread will take
             care of the correction.  */
          uint32_t reset = (idx + 1) % (2 * buffer_size);
	  uint32_t expected = idx + 1;
	  atomic_compare_exchange_weak (&buffer_cnt, &expected, reset);
          if (idx >= 2 * buffer_size)
            idx = reset - 1;
        }
      assert (idx < 2 * DEFAULT_BUFFER_SIZE);

      buffer[idx].heap = current_heap;
      buffer[idx].stack = current_stack;
      gettime (&buffer[idx]);

      /* Write out buffer if it is full.  */
      if (idx + 1 == buffer_size || idx + 1 == 2 * buffer_size)
        {
	  uint32_t write_size = buffer_size * sizeof (buffer[0]);
	  write_all (fd, &buffer[idx + 1 - buffer_size], write_size);
        }
    }

  /* ChampSim malloc trace: write pending record if mtrace is active.  */
  if (mtrace_type != 0)
    {
      struct malloc_instr rec;
      rec.type = mtrace_type;
      rec.arg1 = mtrace_arg1;
      rec.arg2 = mtrace_arg2;
      rec.ret = mtrace_ret;
      rec.caller_ip = mtrace_caller_ip;
      memset (rec.reserved, 0, sizeof (rec.reserved));
      if (mtrace_fp != NULL)
        {
          (void)fwrite (&rec, sizeof (rec), 1, mtrace_fp);
          fflush (mtrace_fp);
        }
      else if (mtrace_fd != -1)
        {
          (void)write (mtrace_fd, &rec, sizeof (rec));
        }
      mtrace_type = 0;  /* clear pending flag */
    }
}


/* ===== Helper functions for new statistics tables ===== */

static inline int
pow2_bucket (size_t sz)
{
  if (sz == 0) return 0;
  if (sz == 1) return 1;
  /* ceil(log2(sz)) = (64 - __builtin_clzll(sz - 1)) */
  return 64 - __builtin_clzll ((unsigned long long)(sz - 1));
}

/* bisect_right(thresholds, sz): returns count of thresholds <= sz */
static inline int
bisect_right (size_t sz)
{
  int i;
  for (i = 0; i < NUM_THRESHOLDS; i++)
    if (threshold_vals[i] > sz)
      return i;
  return NUM_THRESHOLDS;
}

static inline unsigned long long
next_power_of_2 (unsigned long long n)
{
  if (n == 0 || n == 1) return 1;
  if ((n & (n - 1)) == 0) return n;
  unsigned long long p = 1;
  while (p < n) p <<= 1;
  return p;
}

static inline unsigned long long
caller_hash (unsigned long long ip)
{
  return (ip ^ (ip >> 16) ^ (ip >> 32)) % CALLER_HASH_SIZE;
}

/* Record an allocation in cumulative interval + pow2 stats. */
static inline void
stats_alloc (size_t sz)
{
  int p2 = pow2_bucket (sz);
  if (p2 < POW2_BUCKETS)
    {
      atomic_fetch_add_explicit (&pow2_objs[p2], 1, memory_order_relaxed);
      atomic_fetch_add_explicit (&pow2_sizes[p2], sz, memory_order_relaxed);
    }
  /* Cumulative interval tracking (Python semantics) */
  int split = bisect_right (sz);  /* count of thresholds <= sz */
  unsigned long long pow2 = next_power_of_2 (sz);
  int i;
  for (i = 0; i < split; i++)
    atomic_fetch_add_explicit (&cum_aligned[i], sz, memory_order_relaxed);
  for (i = split; i < NUM_THRESHOLDS; i++)
    {
      atomic_fetch_add_explicit (&cum_aligned[i], pow2, memory_order_relaxed);
      atomic_fetch_add_explicit (&cum_actual[i], sz, memory_order_relaxed);
      atomic_fetch_add_explicit (&cum_objs[i], 1, memory_order_relaxed);
    }
  atomic_fetch_add_explicit (&alive_objs, 1, memory_order_relaxed);
}

/* Record a free in cumulative interval stats.
   Underflow-protected: uses CAS loops to prevent unsigned wrap-around
   that would produce 2^64-size garbage values in concurrent scenarios.  */
static inline void
stats_free (size_t sz)
{
  int split = bisect_right (sz);
  unsigned long long pow2 = next_power_of_2 (sz);
  int i;
  for (i = 0; i < split; i++)
    {
      unsigned long long val;
      do {
        val = atomic_load_explicit (&cum_aligned[i], memory_order_relaxed);
        if (val < sz) { val = sz; break; }  /* clamp so result >= 0 */
      } while (!atomic_compare_exchange_weak (&cum_aligned[i], &val, val - sz));
    }
  for (i = split; i < NUM_THRESHOLDS; i++)
    {
      /* cum_aligned[i] -= pow2, floor at 0 */
      {
        unsigned long long val;
        do {
          val = atomic_load_explicit (&cum_aligned[i], memory_order_relaxed);
          if (val < pow2) { val = pow2; break; }
        } while (!atomic_compare_exchange_weak (&cum_aligned[i], &val, val - pow2));
      }
      /* cum_actual[i] -= sz, floor at 0 */
      {
        unsigned long long val;
        do {
          val = atomic_load_explicit (&cum_actual[i], memory_order_relaxed);
          if (val < sz) { val = sz; break; }
        } while (!atomic_compare_exchange_weak (&cum_actual[i], &val, val - sz));
      }
      /* cum_objs[i] -= 1, floor at 0  (cum_objs is signed long long) */
      {
        long long val;
        do {
          val = atomic_load_explicit (&cum_objs[i], memory_order_relaxed);
          if (val <= 0) { val = 1; break; }
        } while (!atomic_compare_exchange_weak (&cum_objs[i], &val, val - 1));
      }
    }
  /* alive_objs -= 1, floor at 0 */
  {
    unsigned long long val;
    do {
      val = atomic_load_explicit (&alive_objs, memory_order_relaxed);
      if (val <= 0) { val = 1; break; }
    } while (!atomic_compare_exchange_weak (&alive_objs, &val, val - 1));
  }
}

/* Insert or update caller IP hash table entry.  cycles_delta is 0 on alloc,
   (cycles_now - alloc_cycles) on free. */
/* Insert or update caller IP hash table entry.
   For ALLOC events: sz is the allocated size, cycles_delta=0.
   For FREE events: sz is the freed size, cycles_delta = (cycles_now - alloc_cycles).
   Only the original allocator's IP gets the lifetime update. */
static inline void
stats_caller (unsigned long long ip, size_t sz,
              unsigned char type, unsigned long long cycles_delta)
{
  if (ip == 0 || ip <= 4096)
    return;
  unsigned long long h = caller_hash (ip);
  for (unsigned int i = 0; i < CALLER_HASH_SIZE; i++)
    {
      unsigned int idx = (h + i) % CALLER_HASH_SIZE;
      unsigned long long expected = 0;
      if (atomic_compare_exchange_weak (&caller_tbl[idx].ip,
                                         &expected, ip))
        {
          /* New entry inserted by this thread.  */
          atomic_store_explicit (&caller_tbl[idx].count, 1,
                                  memory_order_relaxed);
          atomic_store_explicit (&caller_tbl[idx].tot_sz, sz,
                                  memory_order_relaxed);
          atomic_store_explicit (&caller_tbl[idx].tot_lt, cycles_delta,
                                  memory_order_relaxed);
          atomic_store_explicit (&caller_tbl[idx].alloc_cycles_sum, 0,
                                  memory_order_relaxed);
          atomic_store_explicit (&caller_tbl[idx].unfreed_cnt, 0,
                                  memory_order_relaxed);
          /* Clear and increment type frequency */
          for (int t = 0; t < 12; t++)
            atomic_store_explicit (&caller_tbl[idx].types[t], 0,
                                    memory_order_relaxed);
          if (type < 12)
            atomic_fetch_add_explicit (&caller_tbl[idx].types[type], 1,
                                        memory_order_relaxed);
          if (type <= TYPE_REALLOC) /* alloc types */
            {
              atomic_store_explicit (&caller_tbl[idx].unfreed_cnt, 1,
                                      memory_order_relaxed);
              atomic_store_explicit (&caller_tbl[idx].alloc_cycles_sum,
                                      get_cycles (), memory_order_relaxed);
            }
          atomic_fetch_add_explicit (&caller_entries, 1,
                                      memory_order_relaxed);
          return;
        }
      if (atomic_load_explicit (&caller_tbl[idx].ip, memory_order_acquire) == ip)
        {
          atomic_fetch_add_explicit (&caller_tbl[idx].count, 1,
                                      memory_order_relaxed);
          atomic_fetch_add_explicit (&caller_tbl[idx].tot_sz, sz,
                                      memory_order_relaxed);
          atomic_fetch_add_explicit (&caller_tbl[idx].tot_lt, cycles_delta,
                                      memory_order_relaxed);
          if (type < 12)
            atomic_fetch_add_explicit (&caller_tbl[idx].types[type], 1,
                                        memory_order_relaxed);
          if (type <= TYPE_REALLOC) /* alloc types */
            {
              atomic_fetch_add_explicit (&caller_tbl[idx].unfreed_cnt, 1,
                                          memory_order_relaxed);
              atomic_fetch_add_explicit (&caller_tbl[idx].alloc_cycles_sum,
                                          get_cycles (), memory_order_relaxed);
            }
          return;
        }
    }
  /* Table full – silently drop */
}

/* Update lifetime only for an existing caller entry (matching Python: free events
   accumulate lifetime to the ORIGINAL allocator, not the free caller).
   Does NOT create a new entry if the IP is not found. */
static inline void
stats_caller_lifetime (unsigned long long ip, unsigned long long cycles_delta,
                       unsigned long long alloc_cycles)
{
  if (ip == 0 || ip <= 4096)
    return;
  unsigned long long h = caller_hash (ip);
  for (unsigned int i = 0; i < CALLER_HASH_SIZE; i++)
    {
      unsigned int idx = (h + i) % CALLER_HASH_SIZE;
      if (atomic_load_explicit (&caller_tbl[idx].ip, memory_order_acquire) == ip)
        {
          if (cycles_delta != 0)
            atomic_fetch_add_explicit (&caller_tbl[idx].tot_lt, cycles_delta,
                                        memory_order_relaxed);
          /* Decrement unfreed tracking */
          if (alloc_cycles != 0)
            {
              atomic_fetch_sub_explicit (&caller_tbl[idx].unfreed_cnt, 1,
                                          memory_order_relaxed);
              atomic_fetch_sub_explicit (&caller_tbl[idx].alloc_cycles_sum,
                                          alloc_cycles, memory_order_relaxed);
            }
          return;
        }
    }
}

/* Check whether current heap exceeds peak, and snapshot if so.
   Sanity filters prevent capturing transient dirty-state values caused
   by multi-threaded race between update_data (delta) and stats_alloc/free
   (full add/sub) — which can produce 2^64-sized underflow artifacts.  */
static inline void
stats_check_peak (void)
{
  unsigned long long heap_val = atomic_load_explicit (&current_heap,
                                                       memory_order_relaxed);
  /* Reject absurdly large heap values (>= 1 PB) caused by
     race-condition underflow before stats_alloc/free catches up.  */
  if (heap_val > 1125899906842624ULL)  /* 1 PB */
    return;

  unsigned long long peak_val = atomic_load_explicit (&peak_heap_val,
                                                       memory_order_relaxed);
  if (heap_val > peak_val)
    {
      unsigned long long old = peak_val;
      if (atomic_compare_exchange_weak (&peak_heap_val, &old, heap_val))
        {
          /* Quick dirty-check on cumulative counters before snapshotting.  */
          for (int i = 0; i < NUM_THRESHOLDS; i++)
            {
              unsigned long long ca = atomic_load_explicit (&cum_aligned[i],
                                                             memory_order_relaxed);
              if (ca > 1125899906842624ULL)  /* any interval > 1 PB → dirty */
                return;   /* abandon this snapshot, wait for a healthy cycle */
            }

          /* We won the race – take a snapshot.  */
          unsigned long long objs = atomic_load_explicit (&alive_objs,
                                                           memory_order_relaxed);
          atomic_store_explicit (&peak_objs_val, objs, memory_order_relaxed);
          for (int i = 0; i < NUM_THRESHOLDS; i++)
            {
              peak_objs[i] = atomic_load_explicit (&cum_objs[i],
                                                    memory_order_relaxed);
              peak_actual[i] = atomic_load_explicit (&cum_actual[i],
                                                      memory_order_relaxed);
              peak_aligned[i] = atomic_load_explicit (&cum_aligned[i],
                                                       memory_order_relaxed);
            }
        }
    }
}

/* Check whether current alive_objs count exceeds peak, and snapshot if so.  */
static inline void
stats_check_peak_objs (void)
{
  unsigned long long objs_val = atomic_load_explicit (&alive_objs,
                                                       memory_order_relaxed);
  unsigned long long peak_val = atomic_load_explicit (&peak_objs_cnt_val,
                                                       memory_order_relaxed);
  if (objs_val > peak_val)
    {
      unsigned long long old = peak_val;
      if (atomic_compare_exchange_weak (&peak_objs_cnt_val, &old, objs_val))
        {
          /* Quick dirty-check on cumulative counters before snapshotting.  */
          for (int i = 0; i < NUM_THRESHOLDS; i++)
            {
              unsigned long long ca = atomic_load_explicit (&cum_aligned[i],
                                                             memory_order_relaxed);
              if (ca > 1125899906842624ULL)  /* any interval > 1 PB → dirty */
                return;   /* abandon this snapshot, wait for a healthy cycle */
            }

          /* We won the race – take a snapshot.  */
          unsigned long long heap_val = atomic_load_explicit (&current_heap,
                                                               memory_order_relaxed);
          atomic_store_explicit (&peak_objs_cnt_heap, heap_val,
                                  memory_order_relaxed);
          for (int i = 0; i < NUM_THRESHOLDS; i++)
            {
              peak_objs_cnt_objs[i] = atomic_load_explicit (&cum_objs[i],
                                                             memory_order_relaxed);
              peak_objs_cnt_actual[i] = atomic_load_explicit (&cum_actual[i],
                                                               memory_order_relaxed);
              peak_objs_cnt_aligned[i] = atomic_load_explicit (&cum_aligned[i],
                                                                memory_order_relaxed);
            }
        }
    }
}

/* Get CPU cycle count via HP_TIMING_NOW, or fallback to 0. */
static inline unsigned long long
get_cycles (void)
{
#if HP_TIMING_INLINE
  hp_timing_t now;
  HP_TIMING_NOW (now);
  return (unsigned long long) now;
#else
  unsigned int lo, hi;
  __asm__ volatile ("rdtsc" : "=a" (lo), "=d" (hi));
  return ((unsigned long long)hi << 32) | lo;
#endif
}

/* Interrupt handler.  */
static void
int_handler (int signo)
{
  /* Nothing gets allocated.  Just record the stack pointer position.  */
  update_data (NULL, 0, 0);
}


/* Find out whether this is the program we are supposed to profile.
   For this the name in the variable `__progname' must match the one
   given in the environment variable MEMUSAGE_PROG_NAME.  If the variable
   is not present every program assumes it should be profiling.

   If this is the program open a file descriptor to the output file.
   We will write to it whenever the buffer overflows.  The name of the
   output file is determined by the environment variable MEMUSAGE_OUTPUT.

   If the environment variable MEMUSAGE_BUFFER_SIZE is set its numerical
   value determines the size of the internal buffer.  The number gives
   the number of elements in the buffer.  By setting the number to one
   one effectively selects unbuffered operation.

   If MEMUSAGE_NO_TIMER is not present an alarm handler is installed
   which at the highest possible frequency records the stack pointer.  */
static void
me (void)
{
  const char *env = getenv ("MEMUSAGE_PROG_NAME");
  size_t prog_len = strlen (__progname);

  initialized = -1;
  mallocp = (void *(*)(size_t))dlsym (RTLD_NEXT, "malloc");
  reallocp = (void *(*)(void *, size_t))dlsym (RTLD_NEXT, "realloc");
  callocp = (void *(*)(size_t, size_t))dlsym (RTLD_NEXT, "calloc");
  freep = (void (*)(void *))dlsym (RTLD_NEXT, "free");

  mmapp = (void *(*)(void *, size_t, int, int, int, off_t))dlsym (RTLD_NEXT,
                                                                  "mmap");
  mmap64p =
    (void *(*)(void *, size_t, int, int, int, off64_t))dlsym (RTLD_NEXT,
                                                              "mmap64");
  mremapp = (void *(*)(void *, size_t, size_t, int, void *))dlsym (RTLD_NEXT,
                                                                   "mremap");
  munmapp = (int (*)(void *, size_t))dlsym (RTLD_NEXT, "munmap");

  posix_memalignp = (int (*)(void **, size_t, size_t))dlsym (RTLD_NEXT, "posix_memalign");
  aligned_allocp = (void *(*)(size_t, size_t))dlsym (RTLD_NEXT, "aligned_alloc");

  initialized = 1;

  if (env != NULL)
    {
      /* Check for program name.  */
      size_t len = strlen (env);
      if (len > prog_len || strcmp (env, &__progname[prog_len - len]) != 0
          || (prog_len != len && __progname[prog_len - len - 1] != '/'))
        not_me = true;
    }

  /* Only open the file if it's really us.  */
  if (!not_me && fd == -1)
    {
      const char *outname;

      if (!start_sp)
        start_sp = __thread_stack_pointer ();

      outname = getenv ("MEMUSAGE_OUTPUT");
      if (outname != NULL && outname[0] != '\0'
          && (access (outname, R_OK | W_OK) == 0 || errno == ENOENT))
        {
          fd = creat64 (outname, 0666);

          if (fd == -1)
            /* Don't do anything in future calls if we cannot write to
               the output file.  */
            not_me = true;
          else
            {
              /* Write the first entry.  */
              first.heap = 0;
              first.stack = 0;
              gettime (&first);
              /* Write it two times since we need the starting and end time. */
	      write_all (fd, &first, sizeof (first));
	      write_all (fd, &first, sizeof (first));

              /* Determine the buffer size.  We use the default if the
                 environment variable is not present.  */
              buffer_size = DEFAULT_BUFFER_SIZE;
              const char *str_buffer_size = getenv ("MEMUSAGE_BUFFER_SIZE");
              if (str_buffer_size != NULL)
                {
                  buffer_size = atoi (str_buffer_size);
                  if (buffer_size == 0 || buffer_size > DEFAULT_BUFFER_SIZE)
                    buffer_size = DEFAULT_BUFFER_SIZE;
                }

              /* Possibly enable timer-based stack pointer retrieval.  */
              if (getenv ("MEMUSAGE_NO_TIMER") == NULL)
                {
                  struct sigaction act;

                  act.sa_handler = (sighandler_t) &int_handler;
                  act.sa_flags = SA_RESTART;
                  sigfillset (&act.sa_mask);

                  if (sigaction (SIGPROF, &act, NULL) >= 0)
                    {
                      struct itimerval timer;

                      timer.it_value.tv_sec = 0;
                      timer.it_value.tv_usec = 1;
                      timer.it_interval = timer.it_value;
                      setitimer (ITIMER_PROF, &timer, NULL);
                    }
                }
            }
        }

      if (!not_me && getenv ("MEMUSAGE_TRACE_MMAP") != NULL)
        trace_mmap = true;
    }

  /* Open ChampSim malloc trace file if requested.  */
  if (!not_me && mtrace_fd == -1 && mtrace_fp == NULL)
    {
      const char *mtrace_file = getenv ("MEMUSAGE_MTRACE_FILE");
      if (mtrace_file != NULL && mtrace_file[0] != '\0')
        {
          size_t mflen = strlen (mtrace_file);
          if (mflen > 3 && strcmp (mtrace_file + mflen - 3, ".xz") == 0)
            {
              /* For .xz files, pipe through xz compressor */
              char cmd[4096];
              snprintf (cmd, sizeof (cmd), "xz -c > %s", mtrace_file);
              mtrace_fp = popen (cmd, "w");
              mtrace_fd = -1; /* mark open via mtrace_fp */
            }
          else
            {
              mtrace_fd = creat64 (mtrace_file, 0666);
            }
        }
    }

  /* Read summary-only / summary-file environment variables.  */
  if (!not_me && summary_fp == NULL)
    {
      const char *summary_file = getenv ("MEMUSAGE_SUMMARY_FILE");
      if (summary_file != NULL && summary_file[0] != '\0')
        {
          summary_fp = fopen (summary_file, "w");
        }
    }
}


/* Record the initial stack position.  */
static void
__attribute__ ((constructor))
init (void)
{
  start_sp = __thread_stack_pointer ();
  if (!initialized)
    me ();

  /* Write main_begin marker (type=9) if mtrace is active.  */
  if (mtrace_fd != -1 || mtrace_fp != NULL)
    {
      struct malloc_instr rec;
      rec.type = TYPE_MAIN_BEG;
      rec.arg1 = 0; rec.arg2 = 0; rec.ret = 0; rec.caller_ip = 0;
      memset (rec.reserved, 0, sizeof (rec.reserved));
      if (mtrace_fp != NULL)
        { (void)fwrite (&rec, sizeof (rec), 1, mtrace_fp); fflush (mtrace_fp); }
      else
        { (void)write (mtrace_fd, &rec, sizeof (rec)); }
    }
}


/* `malloc' replacement.  We keep track of the memory usage if this is the
   correct program.  */
void *
malloc (size_t len)
{
  struct header *result = NULL;

  /* Determine real implementation if not already happened.  */
  if (__glibc_unlikely (initialized <= 0))
    {
      if (initialized == -1)
        return NULL;

      me ();
    }

  /* If this is not the correct program just use the normal function.  */
  if (not_me)
    return (*mallocp)(len);

  /* Keep track of number of calls.  */
  atomic_fetch_add_explicit (&calls[idx_malloc], 1, memory_order_relaxed);
  /* Keep track of total memory consumption for `malloc'.  */
  atomic_fetch_add_explicit (&total[idx_malloc], len, memory_order_relaxed);
  /* Keep track of total memory requirement.  */
  atomic_fetch_add_explicit (&grand_total, len, memory_order_relaxed);
  /* Remember the size of the request.  */
  if (len < 65536)
    atomic_fetch_add_explicit (&histogram[len / 16], 1, memory_order_relaxed);
  else
    atomic_fetch_add_explicit (&large, 1, memory_order_relaxed);
  /* Total number of calls of any of the functions.  */
  atomic_fetch_add_explicit (&calls_total, 1, memory_order_relaxed);

  /* Do the real work.  */
  result = (struct header *) (*mallocp)(len + sizeof (struct header));
  if (result == NULL)
    {
      atomic_fetch_add_explicit (&failed[idx_malloc], 1,
				 memory_order_relaxed);
      return NULL;
    }

  /* Set pending mtrace info for update_data().  */
  mtrace_type = TYPE_MALLOC;
  mtrace_arg1 = len;
  mtrace_arg2 = 0;
  mtrace_ret = (unsigned long long)(result + 1);
  mtrace_caller_ip = (unsigned long long)__builtin_return_address (0);

  /* Update the allocation data and write out the records if necessary.  */
  update_data (result, len, 0);

  /* Update new statistics tables.  */
  stats_alloc (len);
  stats_check_peak ();
  stats_check_peak_objs ();
  stats_caller (mtrace_caller_ip, len, TYPE_MALLOC, 0);

  /* Return the pointer to the user buffer.  */
  return (void *) (result + 1);
}


/* `realloc' replacement.  We keep track of the memory usage if this is the
   correct program.  */
void *
realloc (void *old, size_t len)
{
  struct header *result = NULL;
  struct header *real;
  size_t old_len;

  /* Determine real implementation if not already happened.  */
  if (__glibc_unlikely (initialized <= 0))
    {
      if (initialized == -1)
        return NULL;

      me ();
    }

  /* If this is not the correct program just use the normal function.  */
  if (not_me)
    {
      if (old != NULL)
        {
          struct header *real = ((struct header *) old) - 1;
          if (real->magic == MAGIC)
            {
              struct header *newh = (*reallocp)(real, len + sizeof (struct header));
              if (newh == NULL) return NULL;
              newh->length = len;
              return (void *) (newh + 1);
            }
        }
      return (*reallocp)(old, len);
    }

  if (old == NULL)
    {
      /* This is really a `malloc' call.  */
      real = NULL;
      old_len = 0;
    }
  else
    {
      real = ((struct header *) old) - 1;
      if (real->magic != MAGIC)
        /* This is no memory allocated here.  */
        return (*reallocp)(old, len);

      old_len = real->length;
    }

  /* Keep track of number of calls.  */
  atomic_fetch_add_explicit (&calls[idx_realloc], 1, memory_order_relaxed);
  if (len > old_len)
    {
      /* Keep track of total memory consumption for `realloc'.  */
      atomic_fetch_add_explicit (&total[idx_realloc], len - old_len,
				 memory_order_relaxed);
      /* Keep track of total memory requirement.  */
      atomic_fetch_add_explicit (&grand_total, len - old_len,
				 memory_order_relaxed);
    }
  /* Note: Shrinking realloc (len < old_len) does NOT decrement
     total[idx_realloc] or grand_total.  These are cumulative
     "bytes additionally consumed via realloc" counters, always
     non-negative per the original glibc memusage semantics.
     The freed bytes from shrinking are reflected in current_heap
     via update_data() and in total[idx_free] for the realloc(ptr,0)
     case only.  */

  if (len == 0 && old != NULL)
    {
      /* Special case: realloc(ptr, 0) = free(ptr).  */
      unsigned long long old_ptr = (unsigned long long)(real + 1);
      atomic_fetch_add_explicit (&realloc_free, 1, memory_order_relaxed);
      /* Keep track of total memory freed using `free'.  */
      atomic_fetch_add_explicit (&total[idx_free], real->length,
				 memory_order_relaxed);

      /* Set pending mtrace info for update_data().  */
      mtrace_type = TYPE_FREE;
      mtrace_arg1 = old_ptr;
      mtrace_arg2 = 0;
      mtrace_ret = 0;
      mtrace_caller_ip = (unsigned long long)__builtin_return_address (0);

      /* Update the allocation data and write out the records if necessary.  */
      update_data (NULL, 0, old_len);

      /* Update new statistics tables.  */
      stats_free (old_len);
  stats_check_peak ();
  stats_check_peak_objs ();
      /* Update lifetime for the original allocator (not the free caller) */
      stats_caller_lifetime (real->caller_ip, get_cycles () - real->alloc_cycles,
                               real->alloc_cycles);

      /* Do the real work.  */
      (*freep) (real);

      return NULL;
    }

  /* Remember the size of the request.  */
  if (len < 65536)
    atomic_fetch_add_explicit (&histogram[len / 16], 1, memory_order_relaxed);
  else
    atomic_fetch_add_explicit (&large, 1, memory_order_relaxed);
  /* Total number of calls of any of the functions.  */
  atomic_fetch_add_explicit (&calls_total, 1, memory_order_relaxed);


  /* Save old header info before reallocp may free the old block.  */
  unsigned long long old_caller_ip = (real != NULL) ? real->caller_ip : 0;
  unsigned long long old_alloc_cycles = (real != NULL) ? real->alloc_cycles : 0;

  /* Do the real work.  */
  result = (struct header *) (*reallocp)(real, len + sizeof (struct header));
  if (result == NULL)
    {
      atomic_fetch_add_explicit (&failed[idx_realloc], 1,
				 memory_order_relaxed);
      return NULL;
    }

  /* Record whether the reduction/increase happened in place.  */
  if (real == result)
    atomic_fetch_add_explicit (&inplace, 1, memory_order_relaxed);
  /* Was the buffer increased?  */
  if (old_len > len)
    atomic_fetch_add_explicit (&decreasing, 1, memory_order_relaxed);

  /* Set pending mtrace info for update_data().  */
  mtrace_type = TYPE_REALLOC;
  mtrace_arg1 = (unsigned long long)(real + 1);
  mtrace_arg2 = len;
  mtrace_ret = (unsigned long long)(result + 1);
  mtrace_caller_ip = (unsigned long long)__builtin_return_address (0);

  /* Update the allocation data and write out the records if necessary.  */
  update_data (result, len, old_len);

  /* Update new statistics tables.
     realloc semantics: free(old) + alloc(new).  */
  if (old_len > 0)
    {
      stats_free (old_len);
  stats_check_peak ();
  stats_check_peak_objs ();
      stats_caller_lifetime (old_caller_ip, get_cycles () - old_alloc_cycles,
                               old_alloc_cycles);
    }
  stats_alloc (len);
  stats_check_peak ();
  stats_check_peak_objs ();
  stats_caller (mtrace_caller_ip, len, TYPE_REALLOC, 0);

  /* Return the pointer to the user buffer.  */
  return (void *) (result + 1);
}


/* `calloc' replacement.  We keep track of the memory usage if this is the
   correct program.  */
void *
calloc (size_t n, size_t len)
{
  struct header *result;
  size_t size = n * len;

  /* Determine real implementation if not already happened.  */
  if (__glibc_unlikely (initialized <= 0))
    {
      if (initialized == -1)
        return NULL;

      me ();
    }

  /* If this is not the correct program just use the normal function.  */
  if (not_me)
    return (*callocp)(n, len);

  /* Keep track of number of calls.  */
  atomic_fetch_add_explicit (&calls[idx_calloc], 1, memory_order_relaxed);
  /* Keep track of total memory consumption for `calloc'.  */
  atomic_fetch_add_explicit (&total[idx_calloc], size, memory_order_relaxed);
  /* Keep track of total memory requirement.  */
  atomic_fetch_add_explicit (&grand_total, size, memory_order_relaxed);
  /* Remember the size of the request.  */
  if (size < 65536)
    atomic_fetch_add_explicit (&histogram[size / 16], 1,
			       memory_order_relaxed);
  else
    atomic_fetch_add_explicit (&large, 1, memory_order_relaxed);
  /* Total number of calls of any of the functions.  */
  ++calls_total;

  /* Do the real work.  */
  result = (struct header *) (*mallocp)(size + sizeof (struct header));
  if (result == NULL)
    {
      atomic_fetch_add_explicit (&failed[idx_calloc], 1,
				 memory_order_relaxed);
      return NULL;
    }

  /* Set pending mtrace info for update_data().  */
  mtrace_type = TYPE_CALLOC;
  mtrace_arg1 = size;
  mtrace_arg2 = 0;
  mtrace_ret = (unsigned long long)(result + 1);
  mtrace_caller_ip = (unsigned long long)__builtin_return_address (0);

  /* Update the allocation data and write out the records if necessary.  */
  update_data (result, size, 0);

  /* Update new statistics tables.  */
  stats_alloc (size);
  stats_check_peak ();
  stats_check_peak_objs ();
  stats_caller (mtrace_caller_ip, size, TYPE_CALLOC, 0);

  /* Do what `calloc' would have done and return the buffer to the caller.  */
  return memset (result + 1, '\0', size);
}


/* `free' replacement.  We keep track of the memory usage if this is the
   correct program.  */
void
free (void *ptr)
{
  struct header *real;

  /* Determine real implementation if not already happened.  */
  if (__glibc_unlikely (initialized <= 0))
    {
      if (initialized == -1)
        return;

      me ();
    }

  /* If this is not the correct program just use the normal function.  */
  if (not_me)
    {
      if (ptr != NULL)
        {
          struct header *real = ((struct header *) ptr) - 1;
          if (real->magic == MAGIC)
            (*freep) (real);
          else
            (*freep) (ptr);
        }
      return;
    }

  /* `free (NULL)' has no effect.  */
  if (ptr == NULL)
    return;

  /* Determine the pointer to the header.  */
  real = ((struct header *) ptr) - 1;
  if (real->magic != MAGIC)
    {
      /* This block wasn't allocated here.  */
      (*freep) (ptr);
      return;
    }

  /* Keep track of number of calls.  */
  atomic_fetch_add_explicit (&calls[idx_free], 1, memory_order_relaxed);
  /* Keep track of total memory freed using `free'.  */
  atomic_fetch_add_explicit (&total[idx_free], real->length,
			     memory_order_relaxed);

  /* Set pending mtrace info for update_data().  */
  mtrace_type = TYPE_FREE;
  mtrace_arg1 = (unsigned long long)ptr;
  mtrace_arg2 = 0;
  mtrace_ret = 0;
  mtrace_caller_ip = (unsigned long long)__builtin_return_address (0);

  /* Update the allocation data and write out the records if necessary.  */
  update_data (NULL, 0, real->length);

  /* Update new statistics tables.  */
  stats_free (real->length);
  stats_check_peak ();
  stats_check_peak_objs ();
  stats_caller_lifetime (real->caller_ip, get_cycles () - real->alloc_cycles,
                           real->alloc_cycles);

  /* Do the real work.  */
  (*freep) (real);
}


/* `posix_memalign' replacement.  We keep track of the memory usage if
   this is the correct program.  No header can be prepended due to
   alignment constraints, so tracking is similar to mmap (size-only).  */
int
posix_memalign (void **memptr, size_t alignment, size_t size)
{
  int result;

  /* Determine real implementation if not already happened.  */
  if (__glibc_unlikely (initialized <= 0))
    {
      if (initialized == -1)
        return ENOMEM;

      me ();
    }

  /* If this is not the correct program just use the normal function.  */
  if (not_me)
    return (*posix_memalignp)(memptr, alignment, size);

  /* Keep track of number of calls.  */
  atomic_fetch_add_explicit (&calls[idx_posix_memalign], 1, memory_order_relaxed);
  /* Keep track of total memory consumption for `posix_memalign'.  */
  atomic_fetch_add_explicit (&total[idx_posix_memalign], size, memory_order_relaxed);
  /* Keep track of total memory requirement.  */
  atomic_fetch_add_explicit (&grand_total, size, memory_order_relaxed);
  /* Remember the size of the request.  */
  if (size < 65536)
    atomic_fetch_add_explicit (&histogram[size / 16], 1, memory_order_relaxed);
  else
    atomic_fetch_add_explicit (&large, 1, memory_order_relaxed);
  /* Total number of calls of any of the functions.  */
  atomic_fetch_add_explicit (&calls_total, 1, memory_order_relaxed);

  /* Do the real work.  */
  result = (*posix_memalignp)(memptr, alignment, size);

  if (result != 0)
    {
      atomic_fetch_add_explicit (&failed[idx_posix_memalign], 1,
                                  memory_order_relaxed);
      return result;
    }

  /* Set pending mtrace info for update_data().  */
  mtrace_type = TYPE_POSIX_MEMALIGN;
  mtrace_arg1 = size;
  mtrace_arg2 = alignment;
  mtrace_ret = (unsigned long long)*memptr;
  mtrace_caller_ip = (unsigned long long)__builtin_return_address (0);

  /* Update the allocation data (no header, tracked like mmap).  */
  update_data (NULL, size, 0);

  /* Update new statistics tables.  */
  stats_alloc (size);
  stats_check_peak ();
  stats_check_peak_objs ();
  stats_caller (mtrace_caller_ip, size, TYPE_POSIX_MEMALIGN, 0);

  return 0;
}


/* `aligned_alloc' replacement.  We keep track of the memory usage if
   this is the correct program.  No header can be prepended due to
   alignment constraints, so tracking is similar to mmap (size-only).  */
void *
aligned_alloc (size_t alignment, size_t size)
{
  void *result = NULL;

  /* Determine real implementation if not already happened.  */
  if (__glibc_unlikely (initialized <= 0))
    {
      if (initialized == -1)
        return NULL;

      me ();
    }

  /* If this is not the correct program just use the normal function.  */
  if (not_me)
    return (*aligned_allocp)(alignment, size);

  /* Keep track of number of calls.  */
  atomic_fetch_add_explicit (&calls[idx_aligned_alloc], 1, memory_order_relaxed);
  /* Keep track of total memory consumption for `aligned_alloc'.  */
  atomic_fetch_add_explicit (&total[idx_aligned_alloc], size, memory_order_relaxed);
  /* Keep track of total memory requirement.  */
  atomic_fetch_add_explicit (&grand_total, size, memory_order_relaxed);
  /* Remember the size of the request.  */
  if (size < 65536)
    atomic_fetch_add_explicit (&histogram[size / 16], 1, memory_order_relaxed);
  else
    atomic_fetch_add_explicit (&large, 1, memory_order_relaxed);
  /* Total number of calls of any of the functions.  */
  atomic_fetch_add_explicit (&calls_total, 1, memory_order_relaxed);

  /* Do the real work.  */
  result = (*aligned_allocp)(alignment, size);

  if (result == NULL)
    {
      atomic_fetch_add_explicit (&failed[idx_aligned_alloc], 1,
                                  memory_order_relaxed);
      return NULL;
    }

  /* Set pending mtrace info for update_data().  */
  mtrace_type = TYPE_ALIGNED_ALLOC;
  mtrace_arg1 = size;
  mtrace_arg2 = alignment;
  mtrace_ret = (unsigned long long)result;
  mtrace_caller_ip = (unsigned long long)__builtin_return_address (0);

  /* Update the allocation data (no header, tracked like mmap).  */
  update_data (NULL, size, 0);

  /* Update new statistics tables.  */
  stats_alloc (size);
  stats_check_peak ();
  stats_check_peak_objs ();
  stats_caller (mtrace_caller_ip, size, TYPE_ALIGNED_ALLOC, 0);

  return result;
}


/* `mmap' replacement.  We do not have to keep track of the size since
   `munmap' will get it as a parameter.  */
void *
mmap (void *start, size_t len, int prot, int flags, int fd, off_t offset)
{
  void *result = NULL;

  /* Determine real implementation if not already happened.  */
  if (__glibc_unlikely (initialized <= 0))
    {
      if (initialized == -1)
        return NULL;

      me ();
    }

  /* Always get a block.  We don't need extra memory.  */
  result = (*mmapp)(start, len, prot, flags, fd, offset);

  if (!not_me && trace_mmap)
    {
      int idx = (flags & MAP_ANON
                 ? idx_mmap_a : prot & PROT_WRITE ? idx_mmap_w : idx_mmap_r);

      /* Keep track of number of calls.  */
      atomic_fetch_add_explicit (&calls[idx], 1, memory_order_relaxed);
      /* Keep track of total memory consumption for `malloc'.  */
      atomic_fetch_add_explicit (&total[idx], len, memory_order_relaxed);
      /* Keep track of total memory requirement.  */
      atomic_fetch_add_explicit (&grand_total, len, memory_order_relaxed);
      /* Remember the size of the request.  */
      if (len < 65536)
        atomic_fetch_add_explicit (&histogram[len / 16], 1,
				   memory_order_relaxed);
      else
        atomic_fetch_add_explicit (&large, 1, memory_order_relaxed);
      /* Total number of calls of any of the functions.  */
      atomic_fetch_add_explicit (&calls_total, 1, memory_order_relaxed);

      /* Check for failures.  */
      if (result == NULL)
        atomic_fetch_add_explicit (&failed[idx], 1, memory_order_relaxed);
      else if (idx == idx_mmap_w)
        {
          /* Set pending mtrace info before update_data().  */
          mtrace_type = TYPE_MMAP;
          mtrace_arg1 = len;
          mtrace_arg2 = 0;
          mtrace_ret = (unsigned long long)result;
          mtrace_caller_ip = (unsigned long long)__builtin_return_address (0);

          /* Update the allocation data and write out the records if
             necessary.  */
          update_data (NULL, len, 0);

          /* Update new statistics tables (mmap alloc).  */
          stats_alloc (len);
  stats_check_peak ();
  stats_check_peak_objs ();
          stats_caller (mtrace_caller_ip, len, TYPE_MMAP, 0);
        }
    }

  /* Return the pointer to the user buffer.  */
  return result;
}


/* `mmap64' replacement.  */
void *
mmap64 (void *start, size_t len, int prot, int flags, int fd, off64_t offset)
{
  void *result = NULL;

  /* Determine real implementation if not already happened.  */
  if (__glibc_unlikely (initialized <= 0))
    {
      if (initialized == -1)
        return NULL;

      me ();
    }

  /* Always get a block.  We don't need extra memory.  */
  result = (*mmap64p)(start, len, prot, flags, fd, offset);

  if (!not_me && trace_mmap)
    {
      int idx = (flags & MAP_ANON
                 ? idx_mmap_a : prot & PROT_WRITE ? idx_mmap_w : idx_mmap_r);

      /* Keep track of number of calls.  */
      atomic_fetch_add_explicit (&calls[idx], 1, memory_order_relaxed);
      /* Keep track of total memory consumption for `malloc'.  */
      atomic_fetch_add_explicit (&total[idx], len, memory_order_relaxed);
      /* Keep track of total memory requirement.  */
      atomic_fetch_add_explicit (&grand_total, len, memory_order_relaxed);
      /* Remember the size of the request.  */
      if (len < 65536)
        atomic_fetch_add_explicit (&histogram[len / 16], 1,
				   memory_order_relaxed);
      else
        atomic_fetch_add_explicit (&large, 1, memory_order_relaxed);
      /* Total number of calls of any of the functions.  */
      atomic_fetch_add_explicit (&calls_total, 1, memory_order_relaxed);

      /* Check for failures.  */
      if (result == NULL)
        atomic_fetch_add_explicit (&failed[idx], 1, memory_order_relaxed);
      else if (idx == idx_mmap_w)
        {
          /* Set pending mtrace info before update_data().  */
          mtrace_type = TYPE_MMAP64;
          mtrace_arg1 = len;
          mtrace_arg2 = 0;
          mtrace_ret = (unsigned long long)result;
          mtrace_caller_ip = (unsigned long long)__builtin_return_address (0);

          update_data (NULL, len, 0);

          /* Update new statistics tables (mmap64 alloc).  */
          stats_alloc (len);
  stats_check_peak ();
  stats_check_peak_objs ();
          stats_caller (mtrace_caller_ip, len, TYPE_MMAP64, 0);
        }
    }

  return result;
}


/* `mremap' replacement.  */
void *
mremap (void *start, size_t old_len, size_t len, int flags, ...)
{
  void *result = NULL;
  va_list ap;

  va_start (ap, flags);
  void *newaddr = (flags & MREMAP_FIXED) ? va_arg (ap, void *) : NULL;
  va_end (ap);

  /* Determine real implementation if not already happened.  */
  if (__glibc_unlikely (initialized <= 0))
    {
      if (initialized == -1)
        return NULL;

      me ();
    }

  /* Always get a block.  We don't need extra memory.  */
  result = (*mremapp)(start, old_len, len, flags, newaddr);

  if (!not_me && trace_mmap)
    {
      /* Keep track of number of calls.  */
      atomic_fetch_add_explicit (&calls[idx_mremap], 1, memory_order_relaxed);
      if (len > old_len)
        {
          /* Keep track of total memory consumption.  */
          atomic_fetch_add_explicit (&total[idx_mremap], len - old_len,
				     memory_order_relaxed);
          /* Keep track of total memory requirement.  */
          atomic_fetch_add_explicit (&grand_total, len - old_len,
				     memory_order_relaxed);
        }
      /* Remember the size of the request.  */
      if (len < 65536)
        atomic_fetch_add_explicit (&histogram[len / 16], 1,
				   memory_order_relaxed);
      else
        atomic_fetch_add_explicit (&large, 1, memory_order_relaxed);
      /* Total number of calls of any of the functions.  */
      atomic_fetch_add_explicit (&calls_total, 1, memory_order_relaxed);

      /* Check for failures.  */
      if (result == NULL)
        atomic_fetch_add_explicit (&failed[idx_mremap], 1,
				   memory_order_relaxed);
      else
        {
          /* Record whether the reduction/increase happened in place.  */
          if (start == result)
            atomic_fetch_add_explicit (&inplace_mremap, 1,
				       memory_order_relaxed);
          /* Was the buffer increased?  */
          if (old_len > len)
            atomic_fetch_add_explicit (&decreasing_mremap, 1,
				       memory_order_relaxed);

          /* Set pending mtrace info before update_data().  */
          mtrace_type = TYPE_MREMAP;
          mtrace_arg1 = (unsigned long long)start;
          mtrace_arg2 = old_len;
          mtrace_ret = (unsigned long long)result;
          mtrace_caller_ip = (unsigned long long)__builtin_return_address (0);

          /* Update the allocation data.  */
          update_data (NULL, len, old_len);

          /* Update new statistics tables (mremap: free old + alloc new).  */
          stats_free (old_len);
  stats_check_peak ();
  stats_check_peak_objs ();
          stats_alloc (len);
  stats_check_peak ();
  stats_check_peak_objs ();
          stats_caller (mtrace_caller_ip, len, TYPE_MREMAP, 0);
        }
    }

  /* Return the pointer to the user buffer.  */
  return result;
}


/* `munmap' replacement.  */
int
munmap (void *start, size_t len)
{
  int result;

  /* Determine real implementation if not already happened.  */
  if (__glibc_unlikely (initialized <= 0))
    {
      if (initialized == -1)
        return -1;

      me ();
    }

  /* Do the real work.  */
  result = (*munmapp)(start, len);

  if (!not_me && trace_mmap)
    {
      /* Keep track of number of calls.  */
      atomic_fetch_add_explicit (&calls[idx_munmap], 1, memory_order_relaxed);

      if (__glibc_likely (result == 0))
        {
          /* Keep track of total memory freed using `free'.  */
          atomic_fetch_add_explicit (&total[idx_munmap], len,
				     memory_order_relaxed);

          /* Set pending mtrace info before update_data().  */
          mtrace_type = TYPE_MUNMAP;
          mtrace_arg1 = (unsigned long long)start;
          mtrace_arg2 = len;
          mtrace_ret = 0;
          mtrace_caller_ip = (unsigned long long)__builtin_return_address (0);

          /* Update the allocation data.  */
          update_data (NULL, 0, len);

          /* Update new statistics tables (munmap free).  */
          stats_free (len);
  stats_check_peak ();
  stats_check_peak_objs ();
          stats_caller (mtrace_caller_ip, len, TYPE_MUNMAP, 0);
        }
      else
        atomic_fetch_add_explicit (&failed[idx_munmap], 1,
				   memory_order_relaxed);
    }

  return result;
}


/* ===== Output functions for the three new statistics tables ===== */

static const char *
fmt_range_val (unsigned long long v, char *buf, size_t bufsz)
{
  if (v >= (1024ULL * 1024 * 1024) && (v % (1024ULL * 1024 * 1024)) == 0)
    snprintf (buf, bufsz, "%lluG", v / (1024ULL * 1024 * 1024));
  else if (v >= (1024ULL * 1024) && (v % (1024ULL * 1024)) == 0)
    snprintf (buf, bufsz, "%lluM", v / (1024ULL * 1024));
  else if (v >= 1024 && (v % 1024) == 0)
    snprintf (buf, bufsz, "%lluK", v / 1024);
  else
    snprintf (buf, bufsz, "%llu", v);
  return buf;
}

static const char *
fmt_sz (unsigned long long v, char *buf, size_t bufsz)
{
  if (v >= (1024ULL * 1024 * 1024))
    snprintf (buf, bufsz, "%.3f G", (double)v / (1024.0 * 1024 * 1024));
  else if (v >= (1024ULL * 1024))
    snprintf (buf, bufsz, "%.3f M", (double)v / (1024.0 * 1024));
  else
    snprintf (buf, bufsz, "%.3f K", (double)v / 1024.0);
  return buf;
}

/* Table 1: Peak Memory Usage by Size Interval (matches Python cumulative logic) */
static void
output_table_peak (FILE *fp)
{
  int i;
  fprintf (fp, "\n=== Peak Memory Usage by Size Interval ===\n");

  /* Column headers: row names on left, interval columns */
  fprintf (fp, "%-14s %15s %7s %7s %15s %7s %7s %10s %7s %7s\n",
           "Range", "Aligned Inc", "Inc%%", "Cum%%",
           "Total Size", "Size%%", "Cum%%", "Obj Cnt", "Obj%%", "Cum%%");
  for (i = 0; i < 110; i++) fputc ('-', fp);
  fputc ('\n', fp);

  unsigned long long peak_heap_v = atomic_load_explicit (&peak_heap_val, memory_order_relaxed);
  unsigned long long peak_objs_v = atomic_load_explicit (&peak_objs_val, memory_order_relaxed);
  unsigned long long prev_aligned = 0, prev_actual = 0;
  long long prev_objs = 0;

  for (i = 0; i < NUM_THRESHOLDS; i++)
    {
      char rb[64], ib[32], sb[32];
      unsigned long long alc = peak_aligned[i];
      unsigned long long act = peak_actual[i];
      long long obj = peak_objs[i];

      /* Python: inc = peak_sizes[i] - (original_peak_size if i==0 else peak_sizes[i-1]) */
      unsigned long long base = (i == 0) ? peak_heap_v : prev_aligned;
      long long inc = (long long)(alc - base);

      /* Python: delta_sz = peak_actual_sizes[i] - (0 if i==0 else peak_actual_sizes[i-1]) */
      unsigned long long delta_sz = act - prev_actual;

      /* Python: delta_objs = peak_objs[i] - (0 if i==0 else peak_objs[i-1]) */
      long long delta_objs = obj - prev_objs;

      /* Python: total_aligned_inc = peak_sizes[i] - original_peak_size */
      long long total_inc = (long long)(alc - peak_heap_v);

      prev_aligned = alc;
      prev_actual = act;
      prev_objs = obj;

      char rlo[32], rhi[32];
      unsigned long long prev_t = (i == 0) ? 0 : (unsigned long long)threshold_vals[i - 1];
      snprintf (rb, sizeof (rb), "(%s,%s]",
                fmt_range_val (prev_t, rlo, sizeof (rlo)),
                fmt_range_val ((unsigned long long)threshold_vals[i], rhi, sizeof (rhi)));

      fprintf (fp, "%-14s %15s %6.2f%% %6.2f%% %15s %6.2f%% %6.2f%% %10lld %6.2f%% %6.2f%%\n",
               rb,
               fmt_sz (inc > 0 ? (unsigned long long)inc : 0, ib, sizeof (ib)),
               peak_heap_v ? 100.0 * inc / peak_heap_v : 0.0,
               peak_heap_v ? 100.0 * total_inc / peak_heap_v : 0.0,
               fmt_sz (delta_sz, sb, sizeof (sb)),
               peak_heap_v ? 100.0 * delta_sz / peak_heap_v : 0.0,
               peak_heap_v ? 100.0 * act / peak_heap_v : 0.0,
               (long long)delta_objs,
               peak_objs_v ? 100.0 * delta_objs / peak_objs_v : 0.0,
               peak_objs_v ? 100.0 * obj / peak_objs_v : 0.0);
    }

  /* Extra >65536 column (Python: objects above max threshold) */
  {
    char rb[64], ib[32], sb[32];
    unsigned long long extra_sz = (peak_heap_v > prev_actual) ? peak_heap_v - prev_actual : 0;
    long long extra_objs = (long long)((peak_objs_v > (unsigned long long)prev_objs) ? peak_objs_v - (unsigned long long)prev_objs : 0);
    char rhi[32];
    snprintf (rb, sizeof (rb), "(%s,+)", fmt_range_val ((unsigned long long)threshold_vals[NUM_THRESHOLDS - 1], rhi, sizeof (rhi)));
    fprintf (fp, "%-14s %15s %6.2f%% %6.2f%% %15s %6.2f%% %6.2f%% %10lld %6.2f%% %6.2f%%\n",
             rb, fmt_sz (0, ib, sizeof (ib)), 0.0,
             peak_heap_v ? 100.0 * 0 / peak_heap_v : 0.0,
             fmt_sz (extra_sz, sb, sizeof (sb)),
             peak_heap_v ? 100.0 * extra_sz / peak_heap_v : 0.0,
             100.0,
             (long long)extra_objs,
             peak_objs_v ? 100.0 * extra_objs / peak_objs_v : 0.0,
             100.0);
  }
}

/* Table 1b: Peak Alive Objects Memory Usage by Size Interval (matched format, different snapshot moment) */
static void
output_table_peak_objs (FILE *fp)
{
  int i;
  fprintf (fp, "\n=== Peak Alive Objects Memory Usage by Size Interval ===\n");

  /* Column headers: row names on left, interval columns */
  fprintf (fp, "%-14s %15s %7s %7s %15s %7s %7s %10s %7s %7s\n",
           "Range", "Aligned Inc", "Inc%%", "Cum%%",
           "Total Size", "Size%%", "Cum%%", "Obj Cnt", "Obj%%", "Cum%%");
  for (i = 0; i < 110; i++) fputc ('-', fp);
  fputc ('\n', fp);

  unsigned long long peak_heap_v = atomic_load_explicit (&peak_objs_cnt_heap, memory_order_relaxed);
  unsigned long long peak_objs_v = atomic_load_explicit (&peak_objs_cnt_val, memory_order_relaxed);
  unsigned long long prev_aligned = 0, prev_actual = 0;
  long long prev_objs = 0;

  for (i = 0; i < NUM_THRESHOLDS; i++)
    {
      char rb[64], ib[32], sb[32];
      unsigned long long alc = peak_objs_cnt_aligned[i];
      unsigned long long act = peak_objs_cnt_actual[i];
      long long obj = peak_objs_cnt_objs[i];

      /* Python: inc = peak_sizes[i] - (original_peak_size if i==0 else peak_sizes[i-1]) */
      unsigned long long base = (i == 0) ? peak_heap_v : prev_aligned;
      long long inc = (long long)(alc - base);

      /* Python: delta_sz = peak_actual_sizes[i] - (0 if i==0 else peak_actual_sizes[i-1]) */
      unsigned long long delta_sz = act - prev_actual;

      /* Python: delta_objs = peak_objs[i] - (0 if i==0 else peak_objs[i-1]) */
      long long delta_objs = obj - prev_objs;

      /* Python: total_aligned_inc = peak_sizes[i] - original_peak_size */
      long long total_inc = (long long)(alc - peak_heap_v);

      prev_aligned = alc;
      prev_actual = act;
      prev_objs = obj;

      char rlo[32], rhi[32];
      unsigned long long prev_t = (i == 0) ? 0 : (unsigned long long)threshold_vals[i - 1];
      snprintf (rb, sizeof (rb), "(%s,%s]",
                fmt_range_val (prev_t, rlo, sizeof (rlo)),
                fmt_range_val ((unsigned long long)threshold_vals[i], rhi, sizeof (rhi)));

      fprintf (fp, "%-14s %15s %6.2f%% %6.2f%% %15s %6.2f%% %6.2f%% %10lld %6.2f%% %6.2f%%\n",
               rb,
               fmt_sz (inc > 0 ? (unsigned long long)inc : 0, ib, sizeof (ib)),
               peak_heap_v ? 100.0 * inc / peak_heap_v : 0.0,
               peak_heap_v ? 100.0 * total_inc / peak_heap_v : 0.0,
               fmt_sz (delta_sz, sb, sizeof (sb)),
               peak_heap_v ? 100.0 * delta_sz / peak_heap_v : 0.0,
               peak_heap_v ? 100.0 * act / peak_heap_v : 0.0,
               (long long)delta_objs,
               peak_objs_v ? 100.0 * delta_objs / peak_objs_v : 0.0,
               peak_objs_v ? 100.0 * obj / peak_objs_v : 0.0);
    }

  /* Extra >65536 column (Python: objects above max threshold) */
  {
    char rb[64], ib[32], sb[32];
    unsigned long long extra_sz = (peak_heap_v > prev_actual) ? peak_heap_v - prev_actual : 0;
    long long extra_objs = (long long)((peak_objs_v > (unsigned long long)prev_objs) ? peak_objs_v - (unsigned long long)prev_objs : 0);
    char rhi[32];
    snprintf (rb, sizeof (rb), "(%s,+)", fmt_range_val ((unsigned long long)threshold_vals[NUM_THRESHOLDS - 1], rhi, sizeof (rhi)));
    fprintf (fp, "%-14s %15s %6.2f%% %6.2f%% %15s %6.2f%% %6.2f%% %10lld %6.2f%% %6.2f%%\n",
             rb, fmt_sz (0, ib, sizeof (ib)), 0.0,
             peak_heap_v ? 100.0 * 0 / peak_heap_v : 0.0,
             fmt_sz (extra_sz, sb, sizeof (sb)),
             peak_heap_v ? 100.0 * extra_sz / peak_heap_v : 0.0,
             100.0,
             (long long)extra_objs,
             peak_objs_v ? 100.0 * extra_objs / peak_objs_v : 0.0,
             100.0);
  }
}

/* Table 2: Top Caller IP Statistics (matches Python: type from frequency, sort by avg_size) */
static void
output_table_caller (FILE *fp)
{
  int i, ncallers = 0;
  for (i = 0; i < CALLER_HASH_SIZE; i++)
    if (caller_tbl[i].ip != 0) ncallers++;
  fprintf (fp, "\n=== Caller IP Statistics (sorted by average size) ===\n");
  if (ncallers == 0) { fprintf (fp, "  (no caller IP data collected)\n"); return; }
  int n = 0;
  int *sorted = (int *) (*mallocp) (ncallers * sizeof (int));
  if (sorted == NULL)
    { fprintf (fp, "  (malloc failed for sorting)\n"); return; }
  for (i = 0; i < CALLER_HASH_SIZE; i++)
    if (caller_tbl[i].ip != 0) sorted[n++] = i;
  /* Sort by avg_size descending (matching Python) */
  for (int a = 0; a < n - 1; a++)
    for (int b = 0; b < n - 1 - a; b++)
      {
        unsigned long long cnt_a = atomic_load_explicit (&caller_tbl[sorted[b]].count, memory_order_relaxed);
        unsigned long long cnt_b = atomic_load_explicit (&caller_tbl[sorted[b + 1]].count, memory_order_relaxed);
        unsigned long long sz_a = atomic_load_explicit (&caller_tbl[sorted[b]].tot_sz, memory_order_relaxed);
        unsigned long long sz_b = atomic_load_explicit (&caller_tbl[sorted[b + 1]].tot_sz, memory_order_relaxed);
        unsigned long long avg_a = cnt_a ? sz_a / cnt_a : 0;
        unsigned long long avg_b = cnt_b ? sz_b / cnt_b : 0;
        if (avg_a < avg_b)
          { int t = sorted[b]; sorted[b] = sorted[b + 1]; sorted[b + 1] = t; }
      }
  /* Python output: Caller IP, Type, Alloc Count, Avg Size, Total Size, Avg Lifetime */
  fprintf (fp, "  %18s %8s %12s %10s %15s %18s\n",
           "Caller IP", "Type", "Alloc Count", "Avg Size", "Total Size", "Avg Lifetime(cyc)");
  for (i = 0; i < 95; i++) fputc ('-', fp);
  fputc ('\n', fp);
  int limit = n;
  for (int ri = 0; ri < limit; ri++)
    {
      int idx = sorted[ri];
      unsigned long long ip = caller_tbl[idx].ip;
      unsigned long long cnt = atomic_load_explicit (&caller_tbl[idx].count, memory_order_relaxed);
      unsigned long long tot_sz = atomic_load_explicit (&caller_tbl[idx].tot_sz, memory_order_relaxed);
      unsigned long long tot_lt = atomic_load_explicit (&caller_tbl[idx].tot_lt, memory_order_relaxed);
      /* Determine primary type (most frequent) */
      unsigned int max_type = 0, max_cnt = 0;
      for (int ti = 1; ti < 12; ti++)
        {
          unsigned int c = atomic_load_explicit (&caller_tbl[idx].types[ti], memory_order_relaxed);
          if (c > max_cnt) { max_cnt = c; max_type = ti; }
        }
      const char *typestr = "?";
      switch (max_type) {
        case 1: typestr = "malloc"; break; case 2: typestr = "calloc"; break;
        case 3: typestr = "realloc"; break; case 4: typestr = "free"; break;
        case 5: typestr = "mmap"; break; case 6: typestr = "mmap64"; break;
        case 7: typestr = "mremap"; break; case 8: typestr = "munmap"; break;
        case 10: typestr = "posix_memalign"; break; case 11: typestr = "aligned_alloc"; break;
      }
      char sb[32];
      fprintf (fp, "  0x%016llx %8s %12llu %10llu %15s %18llu\n",
               ip, typestr, cnt,
               cnt ? tot_sz / cnt : 0ULL,
               fmt_sz (tot_sz, sb, sizeof (sb)),
               cnt ? tot_lt / cnt : 0ULL);

    }
  (*freep) (sorted);
}

/* Table 3: All Objects Size Distribution (by power-of-2 intervals) *//* Table 3: All Objects Size Distribution (by power-of-2 intervals) */
static void
output_table_pow2 (FILE *fp)
{
  int i;
  unsigned long long total_objs = 0, total_sz = 0;
  int first = -1, last = -1;
  for (i = 0; i < POW2_BUCKETS; i++)
    {
      total_objs += pow2_objs[i]; total_sz += pow2_sizes[i];
      if (pow2_objs[i] != 0) { if (first == -1) first = i; last = i; }
    }
  fprintf (fp, "\n=== All Objects Size Distribution (by power-of-2 intervals) ===\n");
  if (total_objs == 0) { fprintf (fp, "  (no allocation data collected)\n"); return; }
  fprintf (fp, "  %-14s %12s %8s %15s %8s %9s %9s\n",
           "Range", "Objects", "Obj%", "Total Size", "Size%", "Cum Obj%", "Cum Size%");
  for (i = 0; i < 80; i++) fputc ('-', fp);
  fputc ('\n', fp);
  unsigned long long cum_o = 0, cum_s = 0;
  for (i = first; i <= last; i++)
    {
      unsigned long long objs = pow2_objs[i], sz = pow2_sizes[i];
      cum_o += objs; cum_s += sz;
      char rb[64], sb[32], rlo[32], rhi[32];
      unsigned long long lo = (i == 0) ? 0 : (1ULL << (i - 1));
      unsigned long long hi = (1ULL << i);
      snprintf (rb, sizeof (rb), "(%s,%s]",
                fmt_range_val (lo, rlo, sizeof (rlo)),
                fmt_range_val (hi, rhi, sizeof (rhi)));
      fprintf (fp, "  %-14s %12llu %7.2f%% %15s %7.2f%% %8.2f%% %8.2f%%\n",
               rb, objs, total_objs ? 100.0 * objs / total_objs : 0.0,
               fmt_sz (sz, sb, sizeof (sb)),
               total_sz ? 100.0 * sz / total_sz : 0.0,
               total_objs ? 100.0 * cum_o / total_objs : 0.0,
               total_sz ? 100.0 * cum_s / total_sz : 0.0);
    }
}


/* Write some statistics to standard error.  */
static void
__attribute__ ((destructor))
dest (void)
{
  int percent, cnt;
  unsigned long int maxcalls;

  /* If we haven't done anything here just return.  */
  if (not_me)
    {
      /* Close mtrace fd/fp if open */
      if (mtrace_fp != NULL) { pclose (mtrace_fp); mtrace_fp = NULL; }
      if (mtrace_fd != -1) { close (mtrace_fd); mtrace_fd = -1; }
      return;
    }

  /* Close mtrace fp (popen) first if open */
  if (mtrace_fp != NULL)
    {
      pclose (mtrace_fp);
      mtrace_fp = NULL;
    }
  /* Close mtrace fd if open */
  if (mtrace_fd != -1)
    {
      close (mtrace_fd);
      mtrace_fd = -1;
    }

  /* If we should call any of the memory functions don't do any profiling.  */
  not_me = true;

  /* Finish the output file.  */
  if (fd != -1)
    {
      /* Write the partially filled buffer.  */
      struct entry *start = buffer;
      uint32_t write_cnt = buffer_cnt;

      if (buffer_cnt > buffer_size)
        {
          start = buffer + buffer_size;
          write_cnt = buffer_cnt - buffer_size;
        }

      write_all (fd, start, write_cnt * sizeof (buffer[0]));

      /* Go back to the beginning of the file.  We allocated two records
         here when we opened the file.  */
      lseek (fd, 0, SEEK_SET);
      /* Write out a record containing the total size.  */
      first.stack = peak_total;
      write_all (fd, &first, sizeof (first));
      /* Write out another record containing the maximum for heap and
         stack.  */
      first.heap = peak_heap;
      first.stack = peak_stack;
      gettime (&first);
      write_all (fd, &first, sizeof (first));

      /* Close the file.  */
      close (fd);
      fd = -1;
    }

  /* Write a colorful statistic.  */
  fprintf (stderr, "\n\
\e[01;32mMemory usage summary:\e[0;0m heap total: %llu, heap peak: %lu, stack peak: %lu\n\
\e[04;34m         total calls   total memory   failed calls\e[0m\n\
\e[00;34m%-16s\e[0m %10lu   %12llu   %s%12lu\e[00;00m\n\
\e[00;34m%-16s\e[0m %10lu   %12llu   %s%12lu\e[00;00m  (nomove:%ld, dec:%ld, free:%ld)\n\
\e[00;34m%-16s\e[0m %10lu   %12llu   %s%12lu\e[00;00m\n\
\e[00;34m%-16s\e[0m %10lu   %12llu\n\
\e[00;34m%-16s\e[0m %10lu   %12llu   %s%12lu\e[00;00m\n\
\e[00;34m%-16s\e[0m %10lu   %12llu   %s%12lu\e[00;00m\n",
           (unsigned long long int) grand_total, (unsigned long int) peak_heap,
           (unsigned long int) peak_stack,
           "malloc|",
           (unsigned long int) calls[idx_malloc],
           (unsigned long long int) total[idx_malloc],
           failed[idx_malloc] ? "\e[01;41m" : "",
           (unsigned long int) failed[idx_malloc],
           "realloc|",
           (unsigned long int) calls[idx_realloc],
           (unsigned long long int) total[idx_realloc],
           failed[idx_realloc] ? "\e[01;41m" : "",
           (unsigned long int) failed[idx_realloc],
           (unsigned long int) inplace,
           (unsigned long int) decreasing,
           (unsigned long int) realloc_free,
           "calloc|",
           (unsigned long int) calls[idx_calloc],
           (unsigned long long int) total[idx_calloc],
           failed[idx_calloc] ? "\e[01;41m" : "",
           (unsigned long int) failed[idx_calloc],
           "free|",
           (unsigned long int) calls[idx_free],
           (unsigned long long int) total[idx_free],
           "posix_memalign|",
           (unsigned long int) calls[idx_posix_memalign],
           (unsigned long long int) total[idx_posix_memalign],
           failed[idx_posix_memalign] ? "\e[01;41m" : "",
           (unsigned long int) failed[idx_posix_memalign],
           "aligned_alloc|",
           (unsigned long int) calls[idx_aligned_alloc],
           (unsigned long long int) total[idx_aligned_alloc],
           failed[idx_aligned_alloc] ? "\e[01;41m" : "",
           (unsigned long int) failed[idx_aligned_alloc]);

  if (trace_mmap)
    fprintf (stderr, "\
\e[00;34m%-16s\e[0m %10lu   %12llu   %s%12lu\e[00;00m\n\
\e[00;34m%-16s\e[0m %10lu   %12llu   %s%12lu\e[00;00m\n\
\e[00;34m%-16s\e[0m %10lu   %12llu   %s%12lu\e[00;00m\n\
\e[00;34m%-16s\e[0m %10lu   %12llu   %s%12lu\e[00;00m  (nomove: %ld, dec:%ld)\n\
\e[00;34m%-16s\e[0m %10lu   %12llu   %s%12lu\e[00;00m\n",
             "mmap(r)|",
             (unsigned long int) calls[idx_mmap_r],
             (unsigned long long int) total[idx_mmap_r],
             failed[idx_mmap_r] ? "\e[01;41m" : "",
             (unsigned long int) failed[idx_mmap_r],
             "mmap(w)|",
             (unsigned long int) calls[idx_mmap_w],
             (unsigned long long int) total[idx_mmap_w],
             failed[idx_mmap_w] ? "\e[01;41m" : "",
             (unsigned long int) failed[idx_mmap_w],
             "mmap(a)|",
             (unsigned long int) calls[idx_mmap_a],
             (unsigned long long int) total[idx_mmap_a],
             failed[idx_mmap_a] ? "\e[01;41m" : "",
             (unsigned long int) failed[idx_mmap_a],
             "mremap|",
             (unsigned long int) calls[idx_mremap],
             (unsigned long long int) total[idx_mremap],
             failed[idx_mremap] ? "\e[01;41m" : "",
             (unsigned long int) failed[idx_mremap],
             (unsigned long int) inplace_mremap,
             (unsigned long int) decreasing_mremap,
             "munmap|",
             (unsigned long int) calls[idx_munmap],
             (unsigned long long int) total[idx_munmap],
             failed[idx_munmap] ? "\e[01;41m" : "",
             (unsigned long int) failed[idx_munmap]);

  /* Final sweep: add lifetime for unfreed objects (treat program end as free time) */
  {
    unsigned long long end_cycles = get_cycles ();
    for (int i = 0; i < CALLER_HASH_SIZE; i++)
      {
        unsigned long long unfreed = atomic_load_explicit (&caller_tbl[i].unfreed_cnt, memory_order_relaxed);
        if (unfreed > 0)
          {
            unsigned long long sum_ac = atomic_load_explicit (&caller_tbl[i].alloc_cycles_sum, memory_order_relaxed);
            unsigned long long extra = end_cycles * unfreed - sum_ac;
            atomic_fetch_add_explicit (&caller_tbl[i].tot_lt, extra, memory_order_relaxed);
            /* Clear tracking to avoid double-counting */
            atomic_store_explicit (&caller_tbl[i].unfreed_cnt, 0, memory_order_relaxed);
            atomic_store_explicit (&caller_tbl[i].alloc_cycles_sum, 0, memory_order_relaxed);
          }
      }
  }

  if (summary_fp != NULL)
    {
      /* Three tables to summary_fp (file) */
      fprintf (summary_fp, "\nMemory usage summary: heap total: %llu, heap peak: %lu, stack peak: %lu\n",
               (unsigned long long int) grand_total, (unsigned long int) peak_heap,
               (unsigned long int) peak_stack);
      fprintf (summary_fp, "         total calls   total memory   failed calls\n");
      fprintf (summary_fp, "%-16s %10lu   %12llu   %12lu\n", "malloc|",
               (unsigned long int) calls[idx_malloc],
               (unsigned long long int) total[idx_malloc],
               (unsigned long int) failed[idx_malloc]);
      fprintf (summary_fp, "%-16s %10lu   %12llu   %12lu  (nomove:%ld, dec:%ld, free:%ld)\n", "realloc|",
               (unsigned long int) calls[idx_realloc],
               (unsigned long long int) total[idx_realloc],
               (unsigned long int) failed[idx_realloc],
               (unsigned long int) inplace,
               (unsigned long int) decreasing,
               (unsigned long int) realloc_free);
      fprintf (summary_fp, "%-16s %10lu   %12llu   %12lu\n", "calloc|",
               (unsigned long int) calls[idx_calloc],
               (unsigned long long int) total[idx_calloc],
               (unsigned long int) failed[idx_calloc]);
      fprintf (summary_fp, "%-16s %10lu   %12llu\n", "free|",
               (unsigned long int) calls[idx_free],
               (unsigned long long int) total[idx_free]);
      fprintf (summary_fp, "%-16s %10lu   %12llu   %12lu\n", "posix_memalign|",
               (unsigned long int) calls[idx_posix_memalign],
               (unsigned long long int) total[idx_posix_memalign],
               (unsigned long int) failed[idx_posix_memalign]);
      fprintf (summary_fp, "%-16s %10lu   %12llu   %12lu\n", "aligned_alloc|",
               (unsigned long int) calls[idx_aligned_alloc],
               (unsigned long long int) total[idx_aligned_alloc],
               (unsigned long int) failed[idx_aligned_alloc]);

      /* Output tables to summary_fp */
      output_table_peak (summary_fp);
      {
        unsigned long long peak_mem = atomic_load_explicit (&peak_heap_val, memory_order_relaxed);
        unsigned long long peak_obj = atomic_load_explicit (&peak_objs_val, memory_order_relaxed);
        char sz_buf[32];
        fprintf (summary_fp, "   %-33s %14s\n", "Peak Allocated Memory:", fmt_sz (peak_mem, sz_buf, sizeof (sz_buf)));
        fprintf (summary_fp, "   %-33s %14llu\n", "Peak Allocated Memory Objects:", peak_obj);
      }
      output_table_peak_objs (summary_fp);
      {
        unsigned long long peak_obj_cnt = atomic_load_explicit (&peak_objs_cnt_val, memory_order_relaxed);
        unsigned long long peak_obj_mem = atomic_load_explicit (&peak_objs_cnt_heap, memory_order_relaxed);
        char sz_buf[32];
        fprintf (summary_fp, "   %-33s %14llu\n", "Peak Active Objects:", peak_obj_cnt);
        fprintf (summary_fp, "   %-33s %14s\n", "Peak Active Objects Memory:", fmt_sz (peak_obj_mem, sz_buf, sizeof (sz_buf)));
      }
      {
        char sz_buf1[32];
        fprintf (summary_fp, "\n=== Total Objects Summary ===\n");
        fprintf (summary_fp, "   %-33s %14llu\n", "Total Alloc Objects:", (unsigned long long int) calls_total);
        fprintf (summary_fp, "   %-33s %14s\n", "Total Allocated Memory:", fmt_sz (grand_total, sz_buf1, sizeof (sz_buf1)));
      }
      output_table_caller (summary_fp);
      output_table_pow2 (summary_fp);

      /* Close summary file */
      fflush(summary_fp); fsync(fileno(summary_fp));
      fclose(summary_fp);
      summary_fp = NULL;

       /* Also output tables to stderr (screen) */
       output_table_peak (stderr);
       {
         unsigned long long peak_mem = atomic_load_explicit (&peak_heap_val, memory_order_relaxed);
         unsigned long long peak_obj = atomic_load_explicit (&peak_objs_val, memory_order_relaxed);
         char sz_buf[32];
         fprintf (stderr, "   %-33s %14s\n", "Peak Allocated Memory:", fmt_sz (peak_mem, sz_buf, sizeof (sz_buf)));
         fprintf (stderr, "   %-33s %14llu\n", "Peak Allocated Memory Objects:", peak_obj);
       }
       output_table_peak_objs (stderr);
       {
         unsigned long long peak_obj_cnt = atomic_load_explicit (&peak_objs_cnt_val, memory_order_relaxed);
         unsigned long long peak_obj_mem = atomic_load_explicit (&peak_objs_cnt_heap, memory_order_relaxed);
         char sz_buf[32];
         fprintf (stderr, "   %-33s %14llu\n", "Peak Active Objects:", peak_obj_cnt);
         fprintf (stderr, "   %-33s %14s\n", "Peak Active Objects Memory:", fmt_sz (peak_obj_mem, sz_buf, sizeof (sz_buf)));
       }
       {
         char sz_buf1[32];
         fprintf (stderr, "\n=== Total Objects Summary ===\n");
         fprintf (stderr, "   %-33s %14llu\n", "Total Alloc Objects:", (unsigned long long int) calls_total);
         fprintf (stderr, "   %-33s %14s\n", "Total Allocated Memory:", fmt_sz (grand_total, sz_buf1, sizeof (sz_buf1)));
       }
       output_table_caller (stderr);
       output_table_pow2 (stderr);
    }
  else
    {
      /* === Original histograms (skipped in summary_only mode) === */

      /* Write out a histogram of the sizes of the allocations.  */
      fprintf (stderr, "\e[01;32mHistogram for block sizes:\e[0;0m\n");

      /* Determine the maximum of all calls for each size range.  */
      maxcalls = large;
      for (cnt = 0; cnt < 65536; cnt += 16)
        if (histogram[cnt / 16] > maxcalls)
          maxcalls = histogram[cnt / 16];

      for (cnt = 0; cnt < 65536; cnt += 16)
        /* Only write out the nonzero entries.  */
        if (histogram[cnt / 16] != 0)
          {
            percent = (histogram[cnt / 16] * 100) / calls_total;
            fprintf (stderr, "%5d-%-5d%12lu ", cnt, cnt + 15,
                     (unsigned long int) histogram[cnt / 16]);
            if (percent == 0)
              fputs (" <1% \e[41;37m", stderr);
            else
              fprintf (stderr, "%3d%% \e[41;37m", percent);

            /* Draw a bar with a length corresponding to the current
               percentage.  */
            percent = (histogram[cnt / 16] * 50) / maxcalls;
            while (percent-- > 0)
              fputc ('=', stderr);
            fputs ("\e[0;0m\n", stderr);
          }

      if (large != 0)
        {
          percent = (large * 100) / calls_total;
          fprintf (stderr, "   large   %12lu ", (unsigned long int) large);
          if (percent == 0)
            fputs (" <1% \e[41;37m", stderr);
          else
            fprintf (stderr, "%3d%% \e[41;37m", percent);
          percent = (large * 50) / maxcalls;
          while (percent-- > 0)
            fputc ('=', stderr);
          fputs ("\e[0;0m\n", stderr);
        }

    }

  /* Any following malloc/free etc. calls should generate statistics again,
     because otherwise freeing something that has been malloced before
     this destructor (including struct header in front of it) wouldn't
     be properly freed.  */
  not_me = true;
}
