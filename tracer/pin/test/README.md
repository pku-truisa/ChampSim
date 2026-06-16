# champsim_tracer Unit Tests

Verifies the core logic of `tracer/pin/champsim_tracer.cpp` without requiring Intel PIN SDK.

## Coverage (44 tests)

| Test file | Tests | What it tests |
|-----------|:-----:|---------------|
| `test_trace_format.cpp` | 2 | `trace_instr_format_t` layout (64 bytes), `is_malloc` type values |
| `test_depth_counter.cpp` | 4 | Depth counter: outermost staging, nesting, MAX_DEPTH saturation, MAX_STUCK auto-reset |
| `test_tracked_allocations.cpp` | 5 | `tracked_allocations` map: malloc/mmap insert, realloc erase+insert, realloc_inplace (type=16), realloc failure |
| `test_free_munmap_filter.cpp` | 4 | FreeBefore/MunmapBefore: only tracked addresses trigger events, ptr==0/invalid-addr early return |
| `test_fast_forward.cpp` | 2 | WriteCurrentInstruction skip during fast-forward, baseline dump of all active allocations at transition |
| `test_writetoset.cpp` | 3 | WriteToSet normal insertion, dedup, array-at-capacity |
| `test_malloc_threshold.cpp` | 15 | Malloc threshold (-k): threshold filtering for malloc/calloc/realloc/posix_memalign/mmap, boundary and custom values |
| `test_malloc_only_mode.cpp` | **8** | Malloc-only mode (-m -a): `malloc_type_name` (7 types), type mapping, `malloc_instr` struct (40 bytes), no-threshold alloc, dual-mode realloc distinction, FreeBefore using `tracked_addresses` |

## Build & Run

```sh
make          # compile test_runner
make run      # run all tests (44 tests)
make clean    # remove binaries
```

Or simply:

```sh
make run
```

All tests are self-contained — no external dependencies beyond a C++17 compiler.

## Type 8 — main_begin Marker

The `ResetDepthOnMain()` callback (instrumented at `main`/`MAIN__`/`main_`) now emits a
`type=8` marker record when running in embedded-alloc or alloc-only mode. This allows
the analyzer to skip glibc initialization and achieve a perfect 1:1 alloc/free ledger.

## Malloc-Only Mode (-m) Tests

The `test_malloc_only_mode.cpp` test file (8 tests) covers the new -m functionality:

| Test | Description |
|------|-------------|
| `test_malloc_type_name_all_types` | Verifies `malloc_type_name()` returns correct names for type codes 0-24 |
| `test_coarse_type_mapping` | Verifies fine-grained type mapping |
| `test_malloc_instr_size` | Verifies `malloc_instr` struct is exactly 40 bytes |
| `test_malloc_only_mode_no_threshold` | Verifies all sizes (including 1 byte) are recorded in alloc-only mode |
| `test_instr_trace_mode_threshold` | Verifies allocs below threshold are filtered in instruction trace mode |
| `test_malloc_only_mode_free_filter` | Verifies FreeBefore uses `tracked_addresses` set in alloc-only mode |
| `test_malloc_instr_record_format` | Verifies `malloc_instr` binary record field correctness (40 bytes, includes caller_ip) |
| `test_malloc_only_mode_realloc` | Verifies realloc records fine-grained type in alloc-only mode vs coarse type in instr mode |
