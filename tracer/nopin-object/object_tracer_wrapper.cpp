/*
 * trace_wrapper.c - LD_PRELOAD malloc trace wrapper for ALL SPEC programs
 * Build: gcc -shared -fPIC -o libtrace_wrapper.so trace_wrapper.cpp -ldl
 * Thread-safe: uses pwrite with atomic byte counter
 */

#include <stdlib.h>
#include <string.h>
#include <dlfcn.h>
#include <stdint.h>
#include <sys/mman.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>

typedef struct {
  unsigned long long arg1;
  unsigned long long arg2;
  unsigned long long ret;
  unsigned long long caller_ip;
  unsigned char type;
  unsigned char reserved[7];
} __attribute__((packed)) malloc_record_t;

enum {
  TYPE_MALLOC = 1, TYPE_CALLOC = 7, TYPE_REALLOC = 11,
  TYPE_POSIX_MEMALIGN = 15, TYPE_MMAP = 16, TYPE_MUNMAP = 17, TYPE_FREE = 18,
  TYPE_ZNWM = 1, TYPE_ZNAM = 1, TYPE_ZDLPV = 18, TYPE_ZDAPV = 18,
};

static int trace_fd = -1;
static volatile int opened = 0;
static volatile unsigned long long write_offset = 0;
static __thread int in_trace = 0;

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

/* Standard C allocation */
void* malloc(size_t sz) {
  if (in_trace) return real_malloc ? real_malloc(sz) : NULL;
  resolve_syms();
  in_trace = 1;
  void* a = real_malloc(sz);
  if (a) write_rec(TYPE_MALLOC, sz, 0, (unsigned long long)a, (unsigned long long)__builtin_return_address(0));
  in_trace = 0;
  return a;
}

void* calloc(size_t n, size_t sz) {
  if (in_trace) return real_calloc ? real_calloc(n, sz) : NULL;
  resolve_syms();
  in_trace = 1;
  void* a = real_calloc(n, sz);
  if (a) write_rec(TYPE_CALLOC, n, sz, (unsigned long long)a, (unsigned long long)__builtin_return_address(0));
  in_trace = 0;
  return a;
}

void* realloc(void* p, size_t sz) {
  if (in_trace) return real_realloc ? real_realloc(p, sz) : NULL;
  resolve_syms();
  in_trace = 1;
  void* a = real_realloc(p, sz);
  if (a) write_rec(TYPE_REALLOC, (unsigned long long)p, sz, (unsigned long long)a, (unsigned long long)__builtin_return_address(0));
  in_trace = 0;
  return a;
}

void free(void* p) {
  if (!p) return;
  if (in_trace) { if (real_free) real_free(p); return; }
  resolve_syms();
  in_trace = 1;
  write_rec(TYPE_FREE, (unsigned long long)p, 0, 0, (unsigned long long)__builtin_return_address(0));
  real_free(p);
  in_trace = 0;
}

/* Aligned allocation */
int posix_memalign(void** mp, size_t al, size_t sz) {
  if (in_trace) return real_posix_memalign ? real_posix_memalign(mp, al, sz) : ENOMEM;
  resolve_syms();
  in_trace = 1;
  int r = real_posix_memalign(mp, al, sz);
  if (r == 0 && mp && *mp) write_rec(TYPE_POSIX_MEMALIGN, sz, al, (unsigned long long)*mp, (unsigned long long)__builtin_return_address(0));
  in_trace = 0;
  return r;
}

void* aligned_alloc(size_t al, size_t sz) {
  if (in_trace) return real_aligned_alloc ? real_aligned_alloc(al, sz) : NULL;
  resolve_syms();
  in_trace = 1;
  void* a = real_aligned_alloc(al, sz);
  if (a) write_rec(TYPE_MALLOC, sz, al, (unsigned long long)a, (unsigned long long)__builtin_return_address(0));
  in_trace = 0;
  return a;
}

void* memalign(size_t al, size_t sz) {
  if (in_trace) return real_memalign ? real_memalign(al, sz) : NULL;
  resolve_syms();
  in_trace = 1;
  void* a = real_memalign(al, sz);
  if (a) write_rec(TYPE_MALLOC, sz, al, (unsigned long long)a, (unsigned long long)__builtin_return_address(0));
  in_trace = 0;
  return a;
}

/* C++ operators */
void* _Znwm(size_t sz) {
  if (in_trace) return real_new ? real_new(sz) : NULL;
  resolve_syms();
  in_trace = 1;
  void* a = real_new(sz);
  if (a) write_rec(TYPE_ZNWM, sz, 0, (unsigned long long)a, (unsigned long long)__builtin_return_address(0));
  in_trace = 0;
  return a;
}

void* _Znam(size_t sz) {
  if (in_trace) return real_new_arr ? real_new_arr(sz) : NULL;
  resolve_syms();
  in_trace = 1;
  void* a = real_new_arr(sz);
  if (a) write_rec(TYPE_ZNAM, sz, 0, (unsigned long long)a, (unsigned long long)__builtin_return_address(0));
  in_trace = 0;
  return a;
}

void _ZdlPv(void* p) {
  if (!p) return;
  if (in_trace) { if (real_delete) real_delete(p); return; }
  resolve_syms();
  in_trace = 1;
  write_rec(TYPE_ZDLPV, (unsigned long long)p, 0, 0, (unsigned long long)__builtin_return_address(0));
  real_delete(p);
  in_trace = 0;
}

void _ZdaPv(void* p) {
  if (!p) return;
  if (in_trace) { if (real_delete_arr) real_delete_arr(p); return; }
  resolve_syms();
  in_trace = 1;
  write_rec(TYPE_ZDAPV, (unsigned long long)p, 0, 0, (unsigned long long)__builtin_return_address(0));
  real_delete_arr(p);
  in_trace = 0;
}

/* mmap / munmap */
void* mmap(void* a, size_t l, int p, int f, int fd, off_t o) {
  if (in_trace) return real_mmap ? real_mmap(a, l, p, f, fd, o) : MAP_FAILED;
  resolve_syms();
  in_trace = 1;
  void* r = real_mmap(a, l, p, f, fd, o);
  if (r != MAP_FAILED) write_rec(TYPE_MMAP, l, 0, (unsigned long long)r, (unsigned long long)__builtin_return_address(0));
  in_trace = 0;
  return r;
}

int munmap(void* a, size_t l) {
  if (in_trace) return real_munmap ? real_munmap(a, l) : -1;
  resolve_syms();
  in_trace = 1;
  write_rec(TYPE_MUNMAP, (unsigned long long)a, l, 0, (unsigned long long)__builtin_return_address(0));
  int r = real_munmap(a, l);
  in_trace = 0;
  return r;
}
