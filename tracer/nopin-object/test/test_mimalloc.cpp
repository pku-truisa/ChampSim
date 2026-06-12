/*
 * Mimalloc malloc trace test
 * Calls mi_malloc/mi_calloc/mi_realloc/mi_free directly
 * to test object_tracer's mi_ symbol hooks (type 2, 8, 12, 19)
 *
 * Build: g++ -o test_mimalloc test_mimalloc.cpp -I/usr/local/include/mimalloc-2.3 -L/usr/local/lib -lmimalloc
 * Run:   LD_LIBRARY_PATH=/usr/local/lib pin -t object_tracer.so -m malloc.mimalloc.bin -- ./test_mimalloc
 */
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <mimalloc.h>

int main()
{
  printf("=== Mimalloc Direct API Test ===\n\n");
  int allocs = 0, frees = 0;

  // Phase 1: mi_malloc
  printf("--- Phase 1: mi_malloc ---\n");
  void* p1 = mi_malloc(100);
  allocs++;
  void* p2 = mi_malloc(1024);
  allocs++;
  void* p3 = mi_malloc(1024*1024);
  allocs++;
  printf("  mi_malloc(100, 1K, 1M) => %d allocs\n", allocs);

  // Phase 2: mi_calloc
  printf("--- Phase 2: mi_calloc ---\n");
  void* p4 = mi_calloc(10, 32);
  allocs++;
  void* p5 = mi_calloc(100, 1024);
  allocs++;
  printf("  mi_calloc(10*32, 100*1K) => %d allocs\n", allocs);

  // Phase 3: mi_realloc
  printf("--- Phase 3: mi_realloc ---\n");
  void* p6 = mi_realloc(p1, 200);
  allocs++;
  printf("  mi_realloc(100->200) => %d allocs\n", allocs);

  // Phase 4: mi_free
  printf("--- Phase 4: mi_free ---\n");
  mi_free(p2);   frees++;
  mi_free(p4);   frees++;
  printf("  mi_free(2) => %d frees\n", frees);

  // Phase 5: mmap (will appear as type=16 via libc mmap hook)
  printf("--- Phase 5: mmap ---\n");

  // Keep some alive
  (void)p3; (void)p5; (void)p6;

  printf("\n=== Test Complete ===\n");
  printf("Allocs: %d, Frees: %d\n", allocs, frees);

  // Force stats
  mi_stats_print(NULL);

  return 0;
}
