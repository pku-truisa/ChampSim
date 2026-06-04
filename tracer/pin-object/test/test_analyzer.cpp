/*
 * Peak memory & threshold analyzer stress test for Tracer v3
 *
 * Tests the analyzer's ability to:
 *  - Track peak memory with interleaved alloc/free patterns
 *  - Distinguish realloc(6) vs realloc_inplace(16)
 *  - Count threshold objects at multiple power-of-2 boundaries
 *  - Track posix_memalign aligned addresses through PIN_SafeCopy
 *
 * Build:  g++ -o test_analyzer test_analyzer.cpp
 * Run:    pin -t object_tracer_gemini.so -m malloc.bin -- ./test_analyzer
 * Check:  python3 little_object_analyzer.py -i malloc.bin
 */

#include <cstdlib>
#include <cstdio>
#include <cstring>
#include <sys/mman.h>
#include <malloc.h>
#include <unistd.h>

int main()
{
  printf("=== Analyzer Stress Test ===\n\n");

  void *s1, *s2, *s3, *s4;
  void *m1, *m2, *m3, *m4, *m5;
  void *b1, *b2, *b3;
  void *p1, *p2;

  // ================================================================
  // Phase 1: Small objects (< 64 bytes) for threshold bins 8/16/32
  // ================================================================
  printf("--- Phase 1: Threshold bin fill (8/16/32/64) ---\n");
  s1 = malloc(7);          // <8  → bin 8
  s2 = malloc(15);         // <16 → bin 16
  s3 = malloc(31);         // <32 → bin 32
  s4 = calloc(2, 15);      // <32 → bin 32
  printf("  Phase 1: 4 small allocs\n");

  // ================================================================
  // Phase 2: Medium objects (64-1024 bytes)
  // ================================================================
  printf("--- Phase 2: Medium allocations (64-1024) ---\n");
  m1 = malloc(512);         // <1024
  m2 = malloc(1023);        // <1024
  m3 = malloc(256);         // <512
  m4 = malloc(64);          // <128
  m5 = aligned_alloc(64, 256);  // → type=1 via malloc hook
  printf("  Phase 2: 5 medium allocs\n");

  // ================================================================
  // Phase 3: Big allocations + posix_memalign (peak build-up)
  // ================================================================
  printf("--- Phase 3: Big allocations (peak ~4.05 MiB) ---\n");
  b1 = malloc(1024 * 1024);                // 1 MiB
  b2 = calloc(500, 4096);                   // ~2 MiB
  posix_memalign(&p1, 64, 8192);           // 8 KiB, type=8
  posix_memalign(&p2, 256, 4096);          // 4 KiB, type=8
  b3 = mmap(nullptr, 1024*1024, PROT_READ|PROT_WRITE,
             MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);  // 1 MiB
  printf("  Phase 3: Peak memory ~4.05 MiB\n");

  // ================================================================
  // Phase 4: Free some — peak stays at Phase 3 level
  // ================================================================
  printf("--- Phase 4: Deallocations (peak unchanged) ---\n");
  free(s1);                  // 7B
  free(s4);                  // 30B
  free(m3);                  // 256B
  free(m4);                  // 64B
  free(b2);                  // ~2 MiB
  munmap(b3, 1024*1024);     // 1 MiB
  printf("  Phase 4: 6 deallocations\n");

  // ================================================================
  // Phase 5: realloc chain — tests type=6 vs type=16 discrimination
  // ================================================================
  printf("--- Phase 5: realloc move vs in-place ---\n");
  void* r1 = malloc(1024);
  void* r2 = realloc(r1, 2048);   // likely moved → type=6
  void* r3 = realloc(r2, 512);    // likely in-place → type=16
  void* r4 = realloc(r3, 4096);   // likely moved → type=6
  void* r5 = realloc(r4, 4096);   // same size, in-place → type=16
  free(r5);
  printf("  Phase 5: realloc chain complete\n");

  // ================================================================
  printf("=== Test Complete ===\n\n");
  printf("Expected analyzer output:\n");
  printf("  Peak ~4.05 MiB (Phase 3)\n");
  printf("  Objects < 8: 1, < 16: 2, < 32: 4, < 64: 4\n");

  return 0;
}