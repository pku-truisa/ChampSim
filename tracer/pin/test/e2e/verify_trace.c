/* verify_trace.c — Parses binary champsim trace and asserts expected alloc events.
 * Reads fixed 64-byte records (matching PIN's output layout).
 * Compile: gcc -std=c11 -o verify_trace verify_trace.c  (no C++ needed)
 * Usage: ./verify_trace <trace.bin>
 *
 * Record layout (64 bytes):
 *   [0..7]   ip (unsigned long long)
 *   [8]      is_branch
 *   [9]      branch_taken
 *   [10..11] destination_registers[2]
 *   [12..15] source_registers[4]
 *   [16..23] destination_memory[0]
 *   [24..31] destination_memory[1]
 *   [32..39] source_memory[0]
 *   [40..47] source_memory[1]
 *   [48..55] source_memory[2]
 *   [56..63] source_memory[3]
 *   [64]     is_malloc
 *   [65..71] reserved/padding
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#define RECORD_SIZE 72  /* sizeof(input_instr) on x86-64 with natural alignment */

int main(int argc, char **argv) {
  if (argc < 2) {
    fprintf(stderr, "Usage: %s <trace.bin>\n", argv[0]);
    return 1;
  }
  FILE *f = fopen(argv[1], "rb");
  if (!f) { perror("fopen"); return 1; }

  /* Auto-detect record size by reading first two records and checking ip spacing.
   * Fallback: try common sizes: 64, 72, 80 */
  unsigned char raw[256];
  size_t n = fread(raw, 1, sizeof(raw), f);
  if (n < 128) { fclose(f); fprintf(stderr, "Trace file too small\n"); return 1; }

  /* Find the record size: look for two consecutive non-zero ip values */
  int rec_size = 0;
  for (int s = 64; s <= 128; s++) {
    if (s >= (int)n - s) break;
    uint64_t ip0 = *(uint64_t*)(raw);
    uint64_t ip1 = *(uint64_t*)(raw + s);
    uint64_t ip2 = *(uint64_t*)(raw + 2*s);
    uint8_t m0  = raw[s - 8];  /* is_malloc at end of record */
    uint8_t m1  = raw[2*s - 8];
    if (ip0 != 0 && ip1 != 0 && ip2 != 0 && m0 <= 16 && m1 <= 16) {
      rec_size = s;
      break;
    }
  }
  if (rec_size == 0) {
    rec_size = 72; /* default */
    fprintf(stderr, "WARNING: could not auto-detect record size, using %d\n", rec_size);
  } else {
    printf("Detected record size: %d bytes\n", rec_size);
  }

  rewind(f);

  int total = 0, errors = 0;
  int mallocs = 0, callocs = 0, reallocs = 0, realloc_inplace = 0;
  int frees = 0, mmaps = 0, munmaps = 0, posix = 0;

  while (fread(raw, rec_size, 1, f) == 1) {
    total++;
    uint8_t t = raw[rec_size - 8];  /* is_malloc at end-8 of record */
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

  if (mallocs < 3) { fprintf(stderr, "FAIL: expected >=3 malloc (got %d)\n", mallocs); ok = 0; }
  if (callocs < 1) { fprintf(stderr, "FAIL: expected >=1 calloc (got %d)\n", callocs); ok = 0; }
  if (reallocs + realloc_inplace < 1) { fprintf(stderr, "FAIL: expected >=1 realloc (got %d)\n", reallocs + realloc_inplace); ok = 0; }
  if (posix < 1)    { fprintf(stderr, "FAIL: expected >=1 posix_memalign (got %d)\n", posix); ok = 0; }
  if (frees < 3)    { fprintf(stderr, "FAIL: expected >=3 free (got %d)\n", frees); ok = 0; }
  if (mmaps < 1)    { fprintf(stderr, "WARN: expected >=1 mmap (got %d)\n", mmaps); }
  if (munmaps < 1)  { fprintf(stderr, "WARN: expected >=1 munmap (got %d)\n", munmaps); }
  if (frees > 3)    { fprintf(stderr, "WARN: free count > 3 (got %d) — untracked free may have been recorded\n", frees); }

  if (ok && errors == 0) {
    printf("ALL CHECKS PASSED\n");
    return 0;
  }
  printf("SOME CHECKS FAILED\n");
  return 1;
}