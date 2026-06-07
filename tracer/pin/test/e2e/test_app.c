/* test_app.c — End-to-end test for champsim_tracer PIN tool.
 * Deterministic single-threaded allocation patterns.
 * Compile: gcc -o test_app test_app.c -lpthread  (pthread not strictly needed)
 *
 * Expected trace events (in order):
 *   1. malloc(1000)        → is_malloc=1, size=1000, ret=non-zero
 *   2. calloc(10, 50)      → is_malloc=5, size=500, ret=non-zero
 *   3. realloc(p1, 500)    → is_malloc=6 or 16, old_ptr=p1, new_size=500
 *   4. posix_memalign → is_malloc=8, size=256, alignment=64
 *   5. mmap(8192, ANON)    → is_malloc=3, size=8192
 *   6. free(p2)            → is_malloc=2, ptr=p2
 *   7. free(untracked)     → SHOULD NOT appear in trace
 *   8. munmap(maddr, 4096) → is_malloc=4, addr=maddr
 *   9. realloc(p3, 0)      → is_malloc=6, old_ptr=p3, new_size=0, ret=0
 *   10. malloc(128)        → is_malloc=1, size=128
 *   11. free(p4)           → is_malloc=2 (posix_memalign ptr)
 *   12. free(p3)           → no-op (already freed by realloc-to-0)
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>

#ifndef MAP_ANONYMOUS
#define MAP_ANONYMOUS 0x20
#endif

int main() {
    void *p1, *p2, *p3, *p4, *maddr;

    /* 1. malloc */
    p1 = malloc(1000);
    if (!p1) { fprintf(stderr, "malloc failed\n"); return 1; }

    /* 2. calloc */
    p2 = calloc(10, 50);
    if (!p2) { fprintf(stderr, "calloc failed\n"); return 1; }

    /* 3. realloc (shrink — may be inplace type=16 or move type=6) */
    p1 = realloc(p1, 500);
    if (!p1) { fprintf(stderr, "realloc failed\n"); return 1; }

    /* 4. posix_memalign */
    if (posix_memalign(&p4, 64, 256) != 0) {
        fprintf(stderr, "posix_memalign failed\n");
        /* p4 may be undefined on failure, but we don't use it if we abort */
        p4 = NULL;
    }

    /* 5. mmap */
    maddr = mmap(NULL, 8192, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (maddr == MAP_FAILED) {
        fprintf(stderr, "mmap failed\n");
        maddr = NULL;
    }

    /* 6. free p2 (calloc ptr) */
    free(p2);
    p2 = NULL;

    /* 7. free on an already-freed pointer (ptr was freed by realloc-to-0 above) —
     *    should NOT appear in trace since it's not in tracked_allocations */
    /* NOTE: The actual filtering is verified by unit tests (test_free_munmap_filter).
     *       We don't test with an invalid address here to avoid SIGSEGV. */

    /* 8. munmap half of mmap region */
    if (maddr) {
        munmap(maddr, 4096);
        /* maddr is now invalid; munmap(maddr+4096, 4096) would be a separate test */
        maddr = NULL;
    }

    /* 9. realloc(p1, 0) — equivalent to free(p1), returns NULL */
    p3 = p1;
    p1 = realloc(p1, 0);

    /* 10. another malloc */
    p1 = malloc(128);

    /* 11. free posix_memalign ptr */
    if (p4) free(p4);

    /* 12. free(p3) — p3 was the old ptr from realloc-to-0 above.
     *    It's already freed via realloc(p,0), and NOT in tracked_allocations.
     *    The filtering logic (no trace event for untracked ptr) is verified
     *    by the unit test test_free_munmap_filter.cpp.  We skip calling free()
     *    here to avoid a double-free abort from glibc. */
    p3 = NULL;

    /* cleanup remaining */
    free(p1);

    printf("Test program completed successfully.\n");
    return 0;
}