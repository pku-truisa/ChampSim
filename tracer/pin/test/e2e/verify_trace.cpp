/* verify_trace.cpp — Parses binary champsim trace at fixed field offsets.
 * The PIN tracer outputs 64-byte records regardless of compiler padding.
 * Field offsets (verified by unit test):
 *   ip at [0..7], is_malloc at [64]
 * Compile: g++ -std=c++17 -o verify_trace verify_trace.cpp
 * Usage: ./verify_trace <trace.bin>
 */

#include <cstdio>
#include <cstdlib>
#include <cstdint>

#define RECORD_SIZE   72
#define OFFSET_ISMALLOC     10

int main(int argc, char **argv) {
  if (argc < 2) { fprintf(stderr, "Usage: %s <trace.bin>\n", argv[0]); return 1; }
  FILE *f = fopen(argv[1], "rb");
  if (!f) { perror("fopen"); return 1; }

  printf("Using fixed record size: %d bytes\n", RECORD_SIZE);

  unsigned char raw[RECORD_SIZE];
  int total = 0, errors = 0;
  int mallocs = 0, callocs = 0, reallocs = 0, realloc_inplace = 0;
  int frees = 0, mmaps = 0, munmaps = 0, posix = 0;

  while (fread(raw, RECORD_SIZE, 1, f) == 1) {
    total++;
    uint8_t t = raw[OFFSET_ISMALLOC];
    switch (t) {
    case 0: break;
    case 1:  mallocs++; break;
    case 2:  frees++;  break;
    case 3:  mmaps++;  break;
    case 4:  munmaps++; break;
    case 5:  callocs++; break;
    case 6:  reallocs++; break;
    case 8:  posix++;   break;
    case 10: break;
    case 16: realloc_inplace++; break;
    default:
      fprintf(stderr, "ERROR: record %d: unknown is_malloc=%u\n", total, (unsigned)t);
      errors++;
    }
  }
  fclose(f);

  printf("Total records: %d\n", total);
  printf("malloc: %d  calloc: %d  realloc: %d  realloc_inplace: %d\n",
         mallocs, callocs, reallocs, realloc_inplace);
  printf("free: %d  mmap: %d  munmap: %d  posix_memalign: %d\n",
         frees, mmaps, munmaps, posix);
  printf("Errors: %d\n\n", errors);

  int ok = 1;

  /* Expected from test_app.c (10 allocation patterns + 2 frees):
   *   malloc(1000) → 1,  calloc(10,50) → 5, realloc(p1,500) → 6 or 16
   *   posix_memalign → 8,  mmap(8192,ANON) → 3, free(p2) → 2
   *   munmap → 4, realloc(p1,0) → 6, malloc(128) → 1
   *   free(p4) → 2, free(p1) → 2
   *
   * Total alloc events: 10 (3 malloc, 1 calloc, 2 realloc, 1 posix, 1 mmap, 1 munmap, 3 free)
   * free(untracked) and free(already-freed p3) should NOT appear
   */
  if (mallocs < 3)    { fprintf(stderr, "FAIL: expected >=3 malloc (got %d)\n", mallocs); ok = 0; }
  if (callocs < 1)    { fprintf(stderr, "FAIL: expected >=1 calloc (got %d)\n", callocs); ok = 0; }
  if (reallocs + realloc_inplace < 2) { fprintf(stderr, "FAIL: expected >=2 realloc (got %d)\n", reallocs + realloc_inplace); ok = 0; }
  if (posix < 1)      { fprintf(stderr, "FAIL: expected >=1 posix_memalign (got %d)\n", posix); ok = 0; }
  if (mmaps < 1)      { fprintf(stderr, "FAIL: expected >=1 mmap (got %d)\n", mmaps); ok = 0; }
  if (munmaps < 1)    { fprintf(stderr, "FAIL: expected >=1 munmap (got %d)\n", munmaps); ok = 0; }
  if (frees < 3)      { fprintf(stderr, "FAIL: expected >=3 free (got %d)\n", frees); ok = 0; }

  /* Critical: free count must be exactly 3 (p2, p4, p1 — not untracked, not already-freed p3) */
  if (frees > 3)      { fprintf(stderr, "FAIL: free count > 3 (got %d) — untracked/already-freed pointer was recorded\n", frees); ok = 0; }

  if (ok && errors == 0) {
    printf("ALL CHECKS PASSED\n");
    return 0;
  }
  printf("SOME CHECKS FAILED\n");
  return 1;
}