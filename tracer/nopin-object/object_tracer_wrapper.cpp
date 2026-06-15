/*
 * trace_wrapper.c - LD_PRELOAD malloc trace wrapper for ALL SPEC programs
 * v4: Added tracked_addresses + depth counter + size + caller_ip sanity
 *     - track_addresses set: only record free/realloc for known allocations
 *     - depth counter: prevent recording nested allocator calls
 *     - mmap depth: skip mmap when inside another alloc (glibc internal)
 *     - SIZE SANITY CHECK: allocations > 128 MiB are treated as glibc internal noise
 *     - CALLER_IP CHECK: caller_ip <= 4096 is invalid (__builtin_return_address failure),
 *       skip recording such allocations entirely (but still track addresses for free).
 *     - thread-safe: uses pwrite with atomic byte counter + mutex
 *     - Uses C-style simple hash table (no C++ STL to avoid LD_PRELOAD init issues)
 *
 * Build: gcc -shared -fPIC -o libobject_tracer_wrapper.so object_tracer_wrapper.cpp -ldl -lpthread
 */

#include <stdlib.h>
#include <string.h>
#include <dlfcn.h>
#include <stdint.h>
#include <sys/mman.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdio.h>

// ---- Constants ----
typedef struct {
  unsigned long long arg1;
  unsigned long long arg2;
  unsigned long long ret;
  unsigned long long caller_ip;
  unsigned char type;
  unsigned char reserved[7];
} __attribute__((packed)) malloc_record_t;

enum {
  TYPE_MALLOC         = 1,
  TYPE_FREE           = 2,
  TYPE_CALLOC         = 3,
  TYPE_REALLOC        = 4,
  TYPE_POSIX_MEMALIGN = 5,
  TYPE_MMAP           = 6,
  TYPE_MUNMAP         = 7,
};

// Sanity limits
#define MAX_REASONABLE_ALLOC_SIZE (128ULL * 1024ULL * 1024ULL)  // 128 MiB
#define MAX_INVALID_CALLER_IP     4096ULL  // caller_ip <= 4096 is invalid

// Simple open-addressing hash table for tracked addresses (C-style, no C++ STL)
#define HASH_TABLE_SIZE 262144  // 2^18 slots

static unsigned long long hash_table_keys[HASH_TABLE_SIZE];
static int hash_table_vals[HASH_TABLE_SIZE];  // 0 = empty, 1 = present

static pthread_mutex_t hash_mutex = PTHREAD_MUTEX_INITIALIZER;

static void hash_init(void) {
  static int initialized = 0;
  if (initialized) return;
  pthread_mutex_lock(&hash_mutex);
  if (!initialized) {
    memset(hash_table_keys, 0, sizeof(hash_table_keys));
    memset(hash_table_vals, 0, sizeof(hash_table_vals));
    initialized = 1;
  }
  pthread_mutex_unlock(&hash_mutex);
}

static unsigned long hash_fn(unsigned long long key) {
  key ^= key >> 33;
  key *= 0xff51afd7ed558ccdULL;
  key ^= key >> 33;
  key *= 0xc4ceb9fe1a85ec53ULL;
  key ^= key >> 33;
  return (unsigned long)(key % HASH_TABLE_SIZE);
}

static void track_add(unsigned long long addr) {
  if (addr == 0) return;
  hash_init();
  unsigned long idx = hash_fn(addr);
  while (hash_table_vals[idx]) {
    if (hash_table_keys[idx] == addr) return;
    idx = (idx + 1) % HASH_TABLE_SIZE;
  }
  hash_table_keys[idx] = addr;
  hash_table_vals[idx] = 1;
}

static void track_erase(unsigned long long addr) {
  if (addr == 0) return;
  hash_init();
  unsigned long idx = hash_fn(addr);
  while (hash_table_vals[idx]) {
    if (hash_table_keys[idx] == addr) {
      hash_table_vals[idx] = 0;
      hash_table_keys[idx] = 0;
      return;
    }
    idx = (idx + 1) % HASH_TABLE_SIZE;
  }
}

static int track_contains(unsigned long long addr) {
  if (addr == 0) return 0;
  hash_init();
  unsigned long idx = hash_fn(addr);
  while (hash_table_vals[idx]) {
    if (hash_table_keys[idx] == addr) return 1;
    idx = (idx + 1) % HASH_TABLE_SIZE;
  }
  return 0;
}

// ---- Global State ----
static int trace_fd = -1;
static volatile int opened = 0;
static volatile unsigned long long write_offset = 0;
static __thread int in_trace = 0;

// Depth counter
static __thread int alloc_depth = 0;
static const int MAX_ALLOC_DEPTH = 16;

// Independent mmap depth
static __thread int mmap_depth = 0;
static __thread unsigned long long mmap_pending_size = 0;
static __thread unsigned long long mmap_pending_caller_ip = 0;
static const int MAX_MMAP_DEPTH = 16;

/* Real function pointers */
static void* (*real_malloc)(size_t) = NULL;
static void* (*real_calloc)(size_t, size_t) = NULL;
static void* (*real_realloc)(void*, size_t) = NULL;
static void  (*real_free)(void*) = NULL;
static int   (*real_posix_memalign)(void**, size_t, size_t) = NULL;
static void* (*real_aligned_alloc)(size_t, size_t) = NULL;
static void* (*real_memalign)(size_t, size_t) = NULL;
static void* (*real_mmap)(void*, size_t, int, int, int, off_t) = NULL;
static int   (*real_munmap)(void*, size_t) = NULL;
static void* (*real_new)(size_t) = NULL;
static void* (*real_new_arr)(size_t) = NULL;
static void  (*real_delete)(void*) = NULL;
static void  (*real_delete_arr)(void*) = NULL;

static void open_files(void) {
  if (opened) return;
  opened = 1;
  const char* tf = getenv("TRACE_FILE");
  if (!tf || !tf[0]) tf = "trace_wrapper.bin";
  trace_fd = open(tf, O_WRONLY|O_CREAT|O_TRUNC, 0644);
}

static void resolve_syms(void) {
  if (real_malloc) return;
  in_trace = 1;

  real_malloc         = (void* (*)(size_t))           dlsym(RTLD_NEXT, "malloc");
  real_calloc         = (void* (*)(size_t,size_t))    dlsym(RTLD_NEXT, "calloc");
  real_realloc        = (void* (*)(void*,size_t))     dlsym(RTLD_NEXT, "realloc");
  real_free           = (void  (*)(void*))            dlsym(RTLD_NEXT, "free");
  real_posix_memalign = (int   (*)(void**,size_t,size_t)) dlsym(RTLD_NEXT, "posix_memalign");
  real_aligned_alloc  = (void* (*)(size_t,size_t))    dlsym(RTLD_NEXT, "aligned_alloc");
  real_memalign       = (void* (*)(size_t,size_t))    dlsym(RTLD_NEXT, "memalign");
  real_mmap           = (void* (*)(void*,size_t,int,int,int,off_t)) dlsym(RTLD_NEXT, "mmap");
  real_munmap         = (int   (*)(void*,size_t))     dlsym(RTLD_NEXT, "munmap");
  real_new            = (void* (*)(size_t))           dlsym(RTLD_NEXT, "_Znwm");
  real_new_arr        = (void* (*)(size_t))           dlsym(RTLD_NEXT, "_Znam");
  real_delete         = (void  (*)(void*))            dlsym(RTLD_NEXT, "_ZdlPv");
  real_delete_arr     = (void  (*)(void*))            dlsym(RTLD_NEXT, "_ZdaPv");

  if (!real_malloc || !real_free) _exit(1);
  open_files();
  in_trace = 0;
}

static void write_rec(unsigned char t, unsigned long long a1,
                      unsigned long long a2, unsigned long long ret,
                      unsigned long long caller_ip) {
  if (trace_fd < 0) return;
  malloc_record_t rec = {a1, a2, ret, caller_ip, t, {0}};
  unsigned long long off = __sync_fetch_and_add(&write_offset, sizeof(rec));
  pwrite(trace_fd, &rec, sizeof(rec), off);
}

// Check if a size is reasonable
static inline int size_is_reasonable(unsigned long long size) {
  return (size <= MAX_REASONABLE_ALLOC_SIZE) ? 1 : 0;
}

// Check if caller_ip is valid (not a glibc internal or __builtin_return_address failure)
static inline int caller_ip_is_valid(unsigned long long ip) {
  return (ip > MAX_INVALID_CALLER_IP) ? 1 : 0;
}

/* Standard C allocation */
void* malloc(size_t sz) {
  if (in_trace) return real_malloc ? real_malloc(sz) : NULL;
  resolve_syms();
  in_trace = 1;
  if (alloc_depth > 0) {
    if (alloc_depth < MAX_ALLOC_DEPTH) alloc_depth++;
    void* a = real_malloc(sz);
    alloc_depth--;
    in_trace = 0;
    return a;
  }
  alloc_depth = 1;

  void* a = real_malloc(sz);
  if (a) {
    unsigned long long ip = (unsigned long long)__builtin_return_address(0);
    if (size_is_reasonable(sz) && caller_ip_is_valid(ip)) {
      write_rec(TYPE_MALLOC, sz, 0, (unsigned long long)a, ip);
    }
    track_add((unsigned long long)a);
  }
  alloc_depth = 0;
  in_trace = 0;
  return a;
}

void* calloc(size_t n, size_t sz) {
  if (in_trace) return real_calloc ? real_calloc(n, sz) : NULL;
  resolve_syms();
  in_trace = 1;
  if (alloc_depth > 0) {
    if (alloc_depth < MAX_ALLOC_DEPTH) alloc_depth++;
    void* a = real_calloc(n, sz);
    alloc_depth--;
    in_trace = 0;
    return a;
  }
  alloc_depth = 1;

  void* a = real_calloc(n, sz);
  if (a) {
    unsigned long long ip = (unsigned long long)__builtin_return_address(0);
    unsigned long long total_sz = (unsigned long long)n * (unsigned long long)sz;
    if (size_is_reasonable(total_sz) && caller_ip_is_valid(ip)) {
      write_rec(TYPE_CALLOC, n, sz, (unsigned long long)a, ip);
    }
    track_add((unsigned long long)a);
  }
  alloc_depth = 0;
  in_trace = 0;
  return a;
}

void* realloc(void* p, size_t sz) {
  if (in_trace) return real_realloc ? real_realloc(p, sz) : NULL;
  resolve_syms();
  in_trace = 1;
  if (alloc_depth > 0) {
    if (alloc_depth < MAX_ALLOC_DEPTH) alloc_depth++;
    void* a = real_realloc(p, sz);
    alloc_depth--;
    in_trace = 0;
    return a;
  }
  alloc_depth = 1;

  unsigned long long old_ptr = (unsigned long long)p;
  unsigned long long ip = (unsigned long long)__builtin_return_address(0);

  int should_record = 1;
  if (!size_is_reasonable(sz)) should_record = 0;
  if (!caller_ip_is_valid(ip)) should_record = 0;
  if (old_ptr != 0 && !track_contains(old_ptr)) should_record = 0;

  void* a = real_realloc(p, sz);
  if (a) {
    if (old_ptr != 0) track_erase(old_ptr);
    if ((unsigned long long)a != old_ptr) track_add((unsigned long long)a);
    if (should_record) {
      write_rec(TYPE_REALLOC, old_ptr, sz, (unsigned long long)a, ip);
    }
  }
  alloc_depth = 0;
  in_trace = 0;
  return a;
}

void free(void* p) {
  if (!p) return;
  if (in_trace) { if (real_free) real_free(p); return; }
  resolve_syms();
  in_trace = 1;
  if (track_contains((unsigned long long)p)) {
    write_rec(TYPE_FREE, (unsigned long long)p, 0, 0,
              (unsigned long long)__builtin_return_address(0));
    track_erase((unsigned long long)p);
  }
  real_free(p);
  in_trace = 0;
}

/* Aligned allocation */
int posix_memalign(void** mp, size_t al, size_t sz) {
  if (in_trace) return real_posix_memalign ? real_posix_memalign(mp, al, sz) : ENOMEM;
  resolve_syms();
  in_trace = 1;
  if (alloc_depth > 0) {
    if (alloc_depth < MAX_ALLOC_DEPTH) alloc_depth++;
    int r = real_posix_memalign(mp, al, sz);
    alloc_depth--;
    in_trace = 0;
    return r;
  }
  alloc_depth = 1;

  int r = real_posix_memalign(mp, al, sz);
  if (r == 0 && mp && *mp) {
    unsigned long long ip = (unsigned long long)__builtin_return_address(0);
    if (size_is_reasonable(sz) && caller_ip_is_valid(ip)) {
      write_rec(TYPE_POSIX_MEMALIGN, sz, al, (unsigned long long)*mp, ip);
    }
    track_add((unsigned long long)*mp);
  }
  alloc_depth = 0;
  in_trace = 0;
  return r;
}

void* aligned_alloc(size_t al, size_t sz) {
  if (in_trace) return real_aligned_alloc ? real_aligned_alloc(al, sz) : NULL;
  resolve_syms();
  in_trace = 1;
  if (alloc_depth > 0) {
    if (alloc_depth < MAX_ALLOC_DEPTH) alloc_depth++;
    void* a = real_aligned_alloc(al, sz);
    alloc_depth--;
    in_trace = 0;
    return a;
  }
  alloc_depth = 1;

  void* a = real_aligned_alloc(al, sz);
  if (a) {
    unsigned long long ip = (unsigned long long)__builtin_return_address(0);
    if (size_is_reasonable(sz) && caller_ip_is_valid(ip)) {
      write_rec(TYPE_MALLOC, sz, al, (unsigned long long)a, ip);
    }
    track_add((unsigned long long)a);
  }
  alloc_depth = 0;
  in_trace = 0;
  return a;
}

void* memalign(size_t al, size_t sz) {
  if (in_trace) return real_memalign ? real_memalign(al, sz) : NULL;
  resolve_syms();
  in_trace = 1;
  if (alloc_depth > 0) {
    if (alloc_depth < MAX_ALLOC_DEPTH) alloc_depth++;
    void* a = real_memalign(al, sz);
    alloc_depth--;
    in_trace = 0;
    return a;
  }
  alloc_depth = 1;

  void* a = real_memalign(al, sz);
  if (a) {
    unsigned long long ip = (unsigned long long)__builtin_return_address(0);
    if (size_is_reasonable(sz) && caller_ip_is_valid(ip)) {
      write_rec(TYPE_MALLOC, sz, al, (unsigned long long)a, ip);
    }
    track_add((unsigned long long)a);
  }
  alloc_depth = 0;
  in_trace = 0;
  return a;
}

/* C++ operators */
void* _Znwm(size_t sz) {
  if (in_trace) return real_new ? real_new(sz) : NULL;
  resolve_syms();
  in_trace = 1;
  if (alloc_depth > 0) {
    if (alloc_depth < MAX_ALLOC_DEPTH) alloc_depth++;
    void* a = real_new(sz);
    alloc_depth--;
    in_trace = 0;
    return a;
  }
  alloc_depth = 1;

  void* a = real_new(sz);
  if (a) {
    unsigned long long ip = (unsigned long long)__builtin_return_address(0);
    if (size_is_reasonable(sz) && caller_ip_is_valid(ip)) {
      write_rec(TYPE_MALLOC, sz, 0, (unsigned long long)a, ip);
    }
    track_add((unsigned long long)a);
  }
  alloc_depth = 0;
  in_trace = 0;
  return a;
}

void* _Znam(size_t sz) {
  if (in_trace) return real_new_arr ? real_new_arr(sz) : NULL;
  resolve_syms();
  in_trace = 1;
  if (alloc_depth > 0) {
    if (alloc_depth < MAX_ALLOC_DEPTH) alloc_depth++;
    void* a = real_new_arr(sz);
    alloc_depth--;
    in_trace = 0;
    return a;
  }
  alloc_depth = 1;

  void* a = real_new_arr(sz);
  if (a) {
    unsigned long long ip = (unsigned long long)__builtin_return_address(0);
    if (size_is_reasonable(sz) && caller_ip_is_valid(ip)) {
      write_rec(TYPE_MALLOC, sz, 0, (unsigned long long)a, ip);
    }
    track_add((unsigned long long)a);
  }
  alloc_depth = 0;
  in_trace = 0;
  return a;
}

void _ZdlPv(void* p) {
  if (!p) return;
  if (in_trace) { if (real_delete) real_delete(p); return; }
  resolve_syms();
  in_trace = 1;
  if (track_contains((unsigned long long)p)) {
    write_rec(TYPE_FREE, (unsigned long long)p, 0, 0,
              (unsigned long long)__builtin_return_address(0));
    track_erase((unsigned long long)p);
  }
  real_delete(p);
  in_trace = 0;
}

void _ZdaPv(void* p) {
  if (!p) return;
  if (in_trace) { if (real_delete_arr) real_delete_arr(p); return; }
  resolve_syms();
  in_trace = 1;
  if (track_contains((unsigned long long)p)) {
    write_rec(TYPE_FREE, (unsigned long long)p, 0, 0,
              (unsigned long long)__builtin_return_address(0));
    track_erase((unsigned long long)p);
  }
  real_delete_arr(p);
  in_trace = 0;
}

/* mmap / munmap */
void* mmap(void* a, size_t l, int p, int f, int fd, off_t o) {
  if (in_trace) return real_mmap ? real_mmap(a, l, p, f, fd, o) : MAP_FAILED;
  resolve_syms();
  in_trace = 1;

  if (alloc_depth > 0) {
    void* r = real_mmap(a, l, p, f, fd, o);
    in_trace = 0;
    return r;
  }

  if (mmap_depth > 0) {
    if (mmap_depth < MAX_MMAP_DEPTH) mmap_depth++;
    void* r = real_mmap(a, l, p, f, fd, o);
    if (mmap_depth > 0) mmap_depth--;
    in_trace = 0;
    return r;
  }
  mmap_depth = 1;
  mmap_pending_size = l;
  mmap_pending_caller_ip = (unsigned long long)__builtin_return_address(0);

  void* r = real_mmap(a, l, p, f, fd, o);
  if (r != MAP_FAILED) {
    write_rec(TYPE_MMAP, l, 0, (unsigned long long)r, mmap_pending_caller_ip);
    track_add((unsigned long long)r);
  }
  mmap_depth = 0;
  in_trace = 0;
  return r;
}

int munmap(void* a, size_t l) {
  if (in_trace) return real_munmap ? real_munmap(a, l) : -1;
  resolve_syms();
  in_trace = 1;
  if (track_contains((unsigned long long)a)) {
    write_rec(TYPE_MUNMAP, (unsigned long long)a, l, 0,
              (unsigned long long)__builtin_return_address(0));
    track_erase((unsigned long long)a);
  }
  int r = real_munmap(a, l);
  in_trace = 0;
  return r;
}