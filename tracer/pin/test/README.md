# champsim_tracer Unit Tests

Verifies the core logic of `tracer/pin/champsim_tracer.cpp` without requiring Intel PIN SDK.

## Coverage

| Test file | What it tests |
|-----------|---------------|
| `test_trace_format.cpp` | `trace_instr_format_t` layout (64 bytes), `is_malloc` type values |
| `test_depth_counter.cpp` | Depth counter: outermost staging, nesting, MAX_DEPTH saturation, MAX_STUCK auto-reset; mmap independent depth |
| `test_tracked_allocations.cpp` | `tracked_allocations` map: malloc/mmap insert, realloc erase+insert, realloc_inplace (type=16), realloc failure |
| `test_free_munmap_filter.cpp` | FreeBefore/MunmapBefore: only tracked addresses trigger events, ptr==0/invalid-addr early return |
| `test_fast_forward.cpp` | WriteCurrentInstruction skip during fast-forward, baseline dump of all active allocations at transition |
| `test_writetoset.cpp` | WriteToSet normal insertion, dedup, array-at-capacity |

## Build & Run

```sh
make          # compile test_runner
make run      # run all tests
make clean    # remove binaries
```

Or simply:

```sh
make run
```

All tests are self-contained — no external dependencies beyond a C++17 compiler.