/*
 * Comprehensive memory allocation test for Object Tracer v3
 *
 * Tests all supported allocation types:
 *   malloc(1), calloc(5), realloc(6), posix_memalign(8),
 *   mmap(MAP_ANONYMOUS)(3), munmap(4), free(2),
 *   realloc_inplace(16), aligned_alloc→malloc(1), memalign→malloc(1)
 *
 * Build:  g++ -o test_malloc test_malloc.cpp
 * Run:    pin -t object_tracer_gemini.so -m malloc.bin -- ./test_malloc
 * Check:  python3 -c "..." to see type counts
 */

#include <cstdlib>
#include <cstdio>
#include <cstring>
#include <sys/mman.h>
#include <malloc.h>
#include <unistd.h>
#include <new>

int main()
{
  printf("=== Tracer v3 Comprehensive Test ===\n\n");

  int allocs = 0, frees = 0;

  // ================================================================
  // Phase 1: Small malloc/calloc/realloc (< 64 bytes)
  // ================================================================
  printf("--- Phase 1: Small malloc/calloc/realloc ---\n");
  void* m1 = malloc(7);                                                            allocs++;  // type=1
  void* m2 = malloc(15);                                                           allocs++;  // type=1
  void* m3 = malloc(31);                                                           allocs++;  // type=1
  void* c1 = calloc(2, 15);                                                       allocs++;  // type=5
  void* c2 = calloc(4, 7);                                                        allocs++;  // type=5
  void* r1 = realloc(m3, 48);  // m3 freed, r1 new                                 allocs++;  // type=6 (moved)
  printf("  malloc(7,15,31) calloc(30,28) realloc(48) => %d allocs\n", allocs);

  // ================================================================
  // Phase 2: posix_memalign (type=8) — specialized hook with PIN_SafeCopy
  // ================================================================
  printf("--- Phase 2: posix_memalign (type=8) ---\n");
  void *p1=nullptr, *p2=nullptr, *p3=nullptr;
  posix_memalign(&p1, 16, 32);      allocs++;  // type=8, alignment=16
  posix_memalign(&p2, 64, 1024);    allocs++;  // type=8, alignment=64
  posix_memalign(&p3, 256, 4096);   allocs++;  // type=8, alignment=256
  printf("  posix_memalign(16/32, 64/1K, 256/4K) => %d allocs\n", allocs);

  // ================================================================
  // Phase 3: aligned_alloc / memalign — captured as type=1 via malloc hook
  // (v3 does NOT instrument these directly because they tail-call into
  //  __libc_memalign. The underlying malloc hook captures them correctly.)
  // ================================================================
  printf("--- Phase 3: aligned_alloc / memalign → type=1 via malloc ---\n");
  void* a1 = aligned_alloc(16, 32);    allocs++;  // type=1
  void* a2 = memalign(32, 64);          allocs++;  // type=1
  void* a3 = aligned_alloc(64, 1024);  allocs++;  // type=1
  void* a4 = memalign(128, 2048);       allocs++;  // type=1
  printf("  aligned(16/32,64/1K) memalign(32/64,128/2K) => %d allocs\n", allocs);

  // ================================================================
  // Phase 4: Big malloc/calloc/realloc (>= 64 bytes)
  // ================================================================
  printf("--- Phase 4: Big allocations ---\n");
  void* b1 = malloc(1024 * 1024);              allocs++;  // 1 MiB
  void* b2 = calloc(500, 4096);                 allocs++;  // ~2 MiB
  void* b3 = malloc(512);                        allocs++;  // 512B
  void* b4 = realloc(b3, 4096);                 allocs++;  // type=6 or 16
  void* b5 = realloc(nullptr, 8192);            allocs++;  // type=6 (realloc(NULL))
  printf("  malloc(1M) calloc(2M) malloc(512) realloc(4K,8K) => %d allocs\n", allocs);

  // ================================================================
  // Phase 5: mmap / munmap (independent mmap_depth)
  // ================================================================
  printf("--- Phase 5: mmap / munmap (type=3/4) ---\n");
  void* mm1 = mmap(nullptr, 1024*1024, PROT_READ|PROT_WRITE,
                   MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);    allocs++;  // type=3
  void* mm2 = mmap(nullptr, 4096, PROT_READ|PROT_WRITE,
                   MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);    allocs++;  // type=3
  printf("  mmap(1MiB, 4KiB) => %d allocs\n", allocs);

  // ================================================================
  // Phase 6: Mixed deallocations
  // ================================================================
  printf("--- Phase 6: Deallocations ---\n");
  free(m1);   frees++;  // type=2
  free(c1);   frees++;  // type=2
  free(p1);   frees++;  // type=2 (posix_memalign→tracked_addresses)
  free(a1);   frees++;  // type=2
  free(b4);   frees++;  // type=2 (realloc'd block)
  free(b5);   frees++;  // type=2
  munmap(mm2, 4096);    frees++;  // type=4
  printf("  free(6) + munmap(1) => %d frees\n", frees);

  // ================================================================
  // Phase 7: realloc in-place test
  // ================================================================
  printf("--- Phase 7: realloc in-place (type=16) vs move (type=6) ---\n");
  void* rr1 = malloc(1024);                   allocs++;
  void* rr2 = realloc(rr1, 2048);             allocs++;  // likely type=6 (moved)
  void* rr3 = realloc(rr2, 512);              allocs++;  // likely type=16 (in-place shrink)
  void* rr4 = realloc(rr3, 4096);             allocs++;  // likely type=6 (moved)
  free(rr4);                                   frees++;
  printf("  realloc chain: 1024→2048→512→4096 → 4 allocs + 1 free\n");

  // ================================================================
  // Phase 8: C++ operator new (type=1 via _Znwm hook)
  // ================================================================
  printf("--- Phase 8: C++ operator new → type=1 ---\n");
  int* np1 = new int(42);                     allocs++;  // type=1
  int* np2 = new int[10];                     allocs++;  // type=1 (_Znam)
  delete np1;                                  frees++;   // type=2
  delete[] np2;                                frees++;   // type=2
  printf("  new/delete => 2 allocs + 2 frees\n");

  // ================================================================
  // Summary
  // ================================================================
  printf("\n=== Test Complete ===\n");
  printf("User allocs: %d, frees: %d\n", allocs, frees);
  printf("Expected trace types:\n");
  printf("  malloc(10+), calloc(3), realloc(4+), posix(3)\n");
  printf("  mmap(2+libc_init), munmap(1+init), free(8+)\n");
  printf("  realloc_inplace(1+), type=0 should be ZERO\n");

  // Keep some objects alive
  (void)m2; (void)c2; (void)p2; (void)p3;
  (void)a2; (void)a3; (void)a4;
  (void)b1; (void)b2; (void)mm1;

  return 0;
}