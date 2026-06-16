# Object Tracer Wrapper (LD_PRELOAD)

`libobject_tracer_wrapper.so` is a lightweight LD_PRELOAD interception library that extracts malloc traces from any program **without PIN**, generating binary trace files fully compatible with `little_object_analyzer.py`.

## Comparison with PIN + object_tracer

| Feature | PIN + object_tracer.so | LD_PRELOAD wrapper |
|---------|------------------------|--------------------|
| Requires PIN | ✅ PIN must be installed | ❌ Not required |
| Performance overhead | High (instruction-level instrumentation) | Minimal (intercepts allocation functions only) |
| Allocator replacement | ❌ Not supported (mimalloc/jemalloc/tcmalloc) | ✅ Fully supported |
| Thread safety | ✅ | ✅ `pwrite()` + atomic offset |
| new/delete interception | ✅ | ✅ |
| aligned_alloc/memalign | ✅ | ✅ |
| Compatible with existing analyzer | ✅ `malloc.bin` | ✅ Same format |
| Result consistency (dedup) | Peak 444.73 MiB, Active: 1 | ✅ **Identical** after alignment fixes |

## Recent Fixes (June 2026)

The nopin tracer has been extensively tested against the PIN `object_tracer.so` and
now produces **identical results**. Key fixes:

### 1. Type 8 — main_begin Marker

The tracer now intercepts `__libc_start_main` and replaces `main()` with a wrapper
that:
- Resets depth counters (`alloc_depth`, `mmap_depth`) — matching PIN's `ResetDepthOnMain()`
- Emits a `type=8` (main_begin) marker record before calling the real `main()`

This allows the analyzer to skip glibc initialization allocations and achieve a
perfect 1:1 alloc/free ledger.

### 2. MAP_ANONYMOUS mmap Filter (matching PIN)

Only anonymous mmap calls (`MAP_ANONYMOUS` flag set) are intercepted and recorded
as type=6. Non-anonymous (file-backed) mmap calls are forwarded directly without
recording, matching PIN's behavior in `MmapBefore`.

### 3. Realloc unconditional track_add

When realloc returns (whether in-place or moved), the new address is **always**
re-added to the tracked addresses set, matching PIN's unconditional `insert()`
in `AllocAfter`. Previously, nopin only inserted when the address changed,
which caused some in-place realloc addresses to "leak" from the tracking set.

### 4. Disabled 128 MiB Size Limit

The `MAX_REASONABLE_ALLOC_SIZE` sanity check was disabled (set to `(unsigned long long)-1`)
to prevent legitimate large allocations (e.g., dedup's 193 MiB input buffer) from being
silently filtered out.

## Build

```bash
gcc -shared -fPIC -o libobject_tracer_wrapper.so object_tracer_wrapper.cpp -ldl
```

## Usage

### 1. Basic usage (glibc default allocator)

```bash
TRACE_FILE=my_trace.bin LD_PRELOAD=./libobject_tracer_wrapper.so ./your_program
```

### 2. Using mimalloc

```bash
TRACE_FILE=my_trace.bin LD_PRELOAD=./libobject_tracer_wrapper.so:/usr/local/lib/libmimalloc.so ./your_program
```

### 3. Using jemalloc

```bash
TRACE_FILE=my_trace.bin LD_PRELOAD=./libobject_tracer_wrapper.so:/path/to/libjemalloc.so ./your_program
```

### 4. Using tcmalloc

```bash
TRACE_FILE=my_trace.bin LD_PRELOAD=./libobject_tracer_wrapper.so:/path/to/libtcmalloc.so ./your_program
```

### 5. Using default output filename

```bash
LD_PRELOAD=./libobject_tracer_wrapper.so ./your_program
# Output to trace_wrapper.bin
```

### 6. Analyze trace

```bash
python3 little_object_analyzer.py -i my_trace.bin -o my_trace.objects.log
```

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `TRACE_FILE` | `trace_wrapper.bin` | Binary trace output path |
| `TRACE_LOG` | `trace_wrapper.log` | Text log output path |

## Intercepted Allocation Types (7-type scheme)

All allocator-variant symbols (mi_malloc, je_malloc, tc_malloc, C++ new/delete) are mapped to their corresponding base type.

| Type Code | Symbols | Description |
|-----------|---------|-------------|
| 1 | `malloc`, `aligned_alloc`, `memalign`, `_Znwm`, `_Znam` | malloc / C++ new |
| 2 | `free`, `_ZdlPv`, `_ZdaPv` | free / C++ delete |
| 3 | `calloc` | Zero-initialized allocation |
| 4 | `realloc` | Reallocation |
| 5 | `posix_memalign` | Aligned allocation |
| 6 | `mmap` | Memory mapping |
| 7 | `munmap` | Unmap memory |

## Binary Trace Format

Each record is 40 bytes, compatible with `object_tracer.cpp` and analyzable by `little_object_analyzer.py` v10+:

```
struct malloc_record {
  unsigned long long arg1;      // size (alloc) / old ptr (realloc)
  unsigned long long arg2;      // 0 (alloc) / new size (realloc) / alignment (posix_memalign)
  unsigned long long ret;       // return address (allocated pointer)
  unsigned long long caller_ip; // caller instruction pointer
  unsigned char      type;      // type code (1-7)
  unsigned char      reserved[7];
};
```

## Test Results

### Comparison across 4 allocators

Results for the same `test/test_malloc` program (25 allocations + 10 frees) using glibc, tcmalloc, mimalloc, and jemalloc:

| Metric | glibc | tcmalloc | mimalloc | jemalloc |
|--------|-------|----------|----------|----------|
| Compatibility | ✅ | ✅ | ✅ | ✅ |
| Trace file size | 1,440 B | 1,480 B | 1,280 B | 1,280 B |
| Record count | 36 (26A+10F) | 38 (30A+8F) | 32 (24A+8F) | 32 (24A+8F) |
| Peak physical memory | 2.09 MiB | 2.09 MiB | 2.09 MiB | 2.09 MiB |
| Alignment overhead | 58,398 B (2.66%) | **58,838 B (2.68%)** | 58,398 B (2.66%) | 58,398 B (2.66%) |
| Real execution time | **0.001s** | 0.004s | 0.002s | 0.002s |
| malloc calls | 13 | **15** (+2 init) | 11 | 11 |
| realloc calls | 5 | **7** (+2 init) | 5 | 5 |

- **glibc**: Baseline, fastest, no extra overhead
- **tcmalloc**: Thread cache initialization adds minor internal malloc/realloc calls, slightly higher alignment overhead (+0.02%); significant advantage in high-concurrency scenarios
- **mimalloc** / **jemalloc**: Minimal initialization, overhead comparable to glibc, efficient memory alignment

### Quick Test Commands

```bash
# Build
make wrapper test

# glibc baseline test
TRACE_FILE=test/glibc.bin LD_PRELOAD=./libobject_tracer_wrapper.so ./test/test_malloc

# tcmalloc test (system installed)
TRACE_FILE=test/tcmalloc.bin LD_PRELOAD=./libobject_tracer_wrapper.so:/usr/lib/x86_64-linux-gnu/libtcmalloc.so ./test/test_malloc

# mimalloc test
TRACE_FILE=test/mimalloc.bin LD_PRELOAD=./libobject_tracer_wrapper.so:/usr/local/lib/libmimalloc.so ./test/test_malloc

# jemalloc test (system installed)
TRACE_FILE=test/jemalloc.bin LD_PRELOAD=./libobject_tracer_wrapper.so:/usr/lib/x86_64-linux-gnu/libjemalloc.so ./test/test_malloc

# Analyze trace
python3 little_object_analyzer.py -i test/glibc.bin
python3 little_object_analyzer.py -i test/tcmalloc.bin
python3 little_object_analyzer.py -i test/mimalloc.bin
python3 little_object_analyzer.py -i test/jemalloc.bin
```

### Verified Test Files

- `verify_new.bin` / `verify_new.result.log` — C++ test_malloc + glibc
- `verify_fortran.bin` / `verify_fortran.result.log` — Fortran test_fortran + mimalloc
- `fortran_glibc_fixed.bin` / `fortran_glibc_fixed.result.log` — Fortran + glibc
- `fortran_mimalloc_fixed.bin` / `fortran_mimalloc_fixed.result.log` — Fortran + mimalloc
- `trace_wrapper_glibc.*` — C++ test_malloc + glibc (v1)
- `trace_wrapper_mimalloc.*` — C++ test_malloc + mimalloc (v1)
- `glibc.bin/result.log` — test_malloc + glibc (full comparison)
- `tcmalloc.bin/result.log` — test_malloc + tcmalloc
- `mimalloc.bin/result.log` — test_malloc + mimalloc
- `jemalloc.bin/result.log` — test_malloc + jemalloc

## Notes

1. **Recursion protection**: The wrapper uses `__thread int in_trace` to prevent infinite recursion caused by `write()/pwrite()` internally triggering `malloc`
2. **Thread safety**: Multi-threaded writes use `pwrite()` + atomic `__sync_fetch_and_add` to ensure records are not corrupted
3. **Symbol resolution**: Uses `dlsym(RTLD_NEXT)` to locate the actual allocator functions, supporting various LD_PRELOAD chains