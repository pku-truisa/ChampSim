/*
 * trace_wrapper.c - LD_PRELOAD malloc trace wrapper for ALL SPEC programs
 * v6: Aligned with champsim_tracer.cpp type encoding:
 *     1=malloc,2=calloc,3=realloc,4=free,5=mmap,6=mmap64,7=mremap,8=munmap,9=main_begin
 *     - Removed posix_memalign, aligned_alloc, memalign (thin wrappers)
 *     - Removed C++ new/delete operators (internal calls to malloc/free)
 *     - Added mmap64 and mremap intercepts
 *     - realloc(ptr,0) special handling (recorded as free)
 *     - mmap: no longer filters MAP_ANONYMOUS only (records all writable mmaps)
 *     - main_begin marker changed from type=8 to type=9
 *
 * Build: g++ -shared -fPIC -o libobject_tracer_wrapper.so object_tracer_wrapper.cpp -ldl -lpthread
 */

#include <cstdlib>
#include <cstring>
#include <dlfcn.h>
#include <cstdint>
#include <cstdarg>
#include <sys/mman.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <cstdio>
#include <unordered_set>
#include <mutex>
#include <new>

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
  TYPE_MALLOC  = 1,
  TYPE_CALLOC  = 2,
  TYPE_REALLOC = 3,
  TYPE_FREE    = 4,
  TYPE_MMAP    = 5,
  TYPE_MMAP64  = 6,
  TYPE_MREMAP  = 7,
  TYPE_MUNMAP  = 8,
};

// Sanity limits
#define MAX_REASONABLE_ALLOC_SIZE ((unsigned long long)-1)  // disabled: allow all sizes
#define MAX_INVALID_CALLER_IP     4096ULL  // caller_ip <= 4096 is invalid

// Tracked addresses: use pointer + placement new to avoid static init order issues
// with LD_PRELOAD (std::unordered_set constructor can crash before glibc is ready)
typedef std::unordered_set<unsigned long long> TrackedSet;
static char tracked_addrs_buf[sizeof(TrackedSet)];
static TrackedSet* tracked_addrs = nullptr;
static std::mutex tracked_mutex;

static void ensure_tracked_init() {
    if (__builtin_expect(tracked_addrs != nullptr, 1)) return;
    std::lock_guard<std::mutex> lock(tracked_mutex);
    if (tracked_addrs == nullptr) {
        // Placement new: construct unordered_set in pre-allocated buffer
        tracked_addrs = new (tracked_addrs_buf) TrackedSet();
    }
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
static __thread unsigned long long mmap_pending_old_addr = 0;
static __thread unsigned long long mmap_pending_old_len = 0;
static const int MAX_MMAP_DEPTH = 16;

/* Real function pointers */
static void* (*real_malloc)(size_t) = NULL;
static void* (*real_calloc)(size_t, size_t) = NULL;
static void* (*real_realloc)(void*, size_t) = NULL;
static void  (*real_free)(void*) = NULL;
static void* (*real_mmap)(void*, size_t, int, int, int, off_t) = NULL;
static void* (*real_mmap64)(void*, size_t, int, int, int, off64_t) = NULL;
static void* (*real_mremap)(void*, size_t, size_t, int, ...) = NULL;
static int   (*real_munmap)(void*, size_t) = NULL;
static int   (*real_libc_start_main)(int (*)(int,char**,char**), int, char**, void (*)(void), void (*)(void), void (*)(void), void*) = NULL;

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
  real_mmap           = (void* (*)(void*,size_t,int,int,int,off_t)) dlsym(RTLD_NEXT, "mmap");
  real_mmap64         = (void* (*)(void*,size_t,int,int,int,off64_t)) dlsym(RTLD_NEXT, "mmap64");
  real_mremap         = (void* (*)(void*,size_t,size_t,int,...))     dlsym(RTLD_NEXT, "mremap");
  real_munmap         = (int   (*)(void*,size_t))     dlsym(RTLD_NEXT, "munmap");
  real_libc_start_main = (int (*)(int (*)(int,char**,char**), int, char**, void (*)(void), void (*)(void), void (*)(void), void*)) dlsym(RTLD_NEXT, "__libc_start_main");

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

// Helper: check caller_ip validity
static inline int caller_ip_is_valid(unsigned long long ip) {
  return (ip > MAX_INVALID_CALLER_IP) ? 1 : 0;
}

// Helper: check size reasonableness
static inline int size_is_reasonable(unsigned long long size) {
  return (size <= MAX_REASONABLE_ALLOC_SIZE) ? 1 : 0;
}

// Tracked address helpers — using std::unordered_set
static void track_add(unsigned long long addr) {
  if (addr == 0) return;
  ensure_tracked_init();
  std::lock_guard<std::mutex> lock(tracked_mutex);
  tracked_addrs->insert(addr);
}

static void track_erase(unsigned long long addr) {
  if (addr == 0) return;
  ensure_tracked_init();
  std::lock_guard<std::mutex> lock(tracked_mutex);
  tracked_addrs->erase(addr);
}

static int track_contains(unsigned long long addr) {
  if (addr == 0) return 0;
  ensure_tracked_init();
  std::lock_guard<std::mutex> lock(tracked_mutex);
  return (tracked_addrs->find(addr) != tracked_addrs->end()) ? 1 : 0;
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

  // realloc(ptr, 0) = free(ptr): record as TYPE_FREE
  if (sz == 0 && p != NULL) {
    if (old_ptr != 0) track_erase(old_ptr);
    if (should_record) {
      write_rec(TYPE_FREE, old_ptr, 0, 0, ip);
    }
    alloc_depth = 0;
    in_trace = 0;
    return a;  // real_realloc returned NULL, caller must not use old_ptr
  }

  if (a) {
    if (old_ptr != 0) track_erase(old_ptr);
    track_add((unsigned long long)a);
    if (should_record) {
      write_rec(TYPE_REALLOC, old_ptr, sz, (unsigned long long)a, ip);
    }
  }
  // realloc failure: do nothing, old_ptr remains tracked
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

void* mmap64(void* a, size_t l, int p, int f, int fd, off64_t o) {
  if (in_trace) return real_mmap64 ? real_mmap64(a, l, p, f, fd, o) : MAP_FAILED;
  resolve_syms();
  in_trace = 1;

  if (alloc_depth > 0) {
    void* r = real_mmap64(a, l, p, f, fd, o);
    in_trace = 0;
    return r;
  }

  if (mmap_depth > 0) {
    if (mmap_depth < MAX_MMAP_DEPTH) mmap_depth++;
    void* r = real_mmap64(a, l, p, f, fd, o);
    if (mmap_depth > 0) mmap_depth--;
    in_trace = 0;
    return r;
  }
  mmap_depth = 1;
  mmap_pending_size = l;
  mmap_pending_caller_ip = (unsigned long long)__builtin_return_address(0);

  void* r = real_mmap64(a, l, p, f, fd, o);
  if (r != MAP_FAILED) {
    write_rec(TYPE_MMAP64, l, 0, (unsigned long long)r, mmap_pending_caller_ip);
    track_add((unsigned long long)r);
  }
  mmap_depth = 0;
  in_trace = 0;
  return r;
}

void* mremap(void* old_addr, size_t old_len, size_t new_len, int flags, ...) {
  if (in_trace) return real_mremap ? real_mremap(old_addr, old_len, new_len, flags) : MAP_FAILED;
  resolve_syms();
  in_trace = 1;

  va_list ap;
  va_start(ap, flags);
  void* new_addr = (flags & MREMAP_FIXED) ? va_arg(ap, void*) : NULL;
  va_end(ap);

  if (alloc_depth > 0) {
    void* r = real_mremap(old_addr, old_len, new_len, flags, new_addr);
    in_trace = 0;
    return r;
  }

  if (mmap_depth > 0) {
    if (mmap_depth < MAX_MMAP_DEPTH) mmap_depth++;
    void* r = real_mremap(old_addr, old_len, new_len, flags, new_addr);
    if (mmap_depth > 0) mmap_depth--;
    in_trace = 0;
    return r;
  }
  mmap_depth = 1;
  mmap_pending_size = new_len;
  mmap_pending_old_addr = (unsigned long long)old_addr;
  mmap_pending_old_len = old_len;
  mmap_pending_caller_ip = (unsigned long long)__builtin_return_address(0);

  void* r = real_mremap(old_addr, old_len, new_len, flags, new_addr);
  if (r != MAP_FAILED) {
    write_rec(TYPE_MREMAP, (unsigned long long)old_addr, old_len, (unsigned long long)r, mmap_pending_caller_ip);
    track_add((unsigned long long)r);
    if (mmap_pending_old_addr != 0) {
      track_erase(mmap_pending_old_addr);
    }
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

// --- __libc_start_main intercept ---
// Emit a main-begin marker (type=9) at the entry of main() itself,
// matching PIN tracer behavior (PIN instruments the main function).

// Store the original main pointer so main_wrapper can call it
static int (*g_real_main)(int, char**, char**) = NULL;

// Wrapper for main(): resets depth counters (like PIN ResetDepthOnMain),
// then writes type=9 marker, then calls real main()
static int main_wrapper(int argc, char** argv, char** envp)
{
  // Reset depth counters: glibc init may have left them non-zero
  alloc_depth = 0;
  mmap_depth = 0;

  // Emit type=9 marker: user's main() has started
  write_rec(9, 0, 0, 0, 0);

  // Call the real main (stored by __libc_start_main)
  return g_real_main(argc, argv, envp);
}

extern "C" int __libc_start_main(int (*main)(int,char**,char**), int argc, char **argv,
                                 void (*init)(void), void (*fini)(void),
                                 void (*rtld_fini)(void), void *stack_end)
{
  // Resolve symbols if not already done
  resolve_syms();

  // Store the real main pointer for main_wrapper
  g_real_main = main;

  // Call the real __libc_start_main with our wrapper instead of main
  // The wrapper will emit type=9 marker at main() entry
  return real_libc_start_main(main_wrapper, argc, argv, init, fini, rtld_fini, stack_end);
}