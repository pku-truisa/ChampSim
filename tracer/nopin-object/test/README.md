# Object Tracer Wrapper Test Suite

This directory contains test files for the LD_PRELOAD tracer (`object_tracer_wrapper.cpp`) and its analyzer (`little_object_analyzer.py`).

## Directory Structure

| File | Description |
|------|-------------|
| `test_malloc.cpp` | Comprehensive C/C++ memory allocation test — covers malloc/calloc/realloc/posix_memalign/mmap/C++ new and all other allocation types |
| `test_analyzer.cpp` | Peak memory and threshold statistics stress test |
| `test_fortran.f90` | Fortran ALLOCATE/DEALLOCATE test |
| `test_mimalloc.cpp` | mimalloc allocator integration test |
| `test_analyzer_synthetic.py` | **Standalone synthetic test** — no PIN/tracer required, generates synthetic binary trace and validates analyzer output |
| `verify.bin` / `verify.result.log` | Sample analyzer output from glibc test |
| `verify_mimalloc.bin` / `verify.result.log` | Sample analyzer output from mimalloc test |

## Building Test Programs

```bash
# Build all test programs from the nopin-object directory
make test

# Or build individually:
g++ -o test/test_malloc test/test_malloc.cpp
g++ -o test/test_analyzer test/test_analyzer.cpp
gfortran -o test/test_fortran test/test_fortran.f90
g++ -o test/test_mimalloc test/test_mimalloc.cpp -I/usr/local/include/mimalloc-2.3 -L/usr/local/lib -lmimalloc -Wl,-rpath,/usr/local/lib
```

## Running Tests

### Method 1: Full end-to-end test (requires no PIN, uses LD_PRELOAD)

```bash
# Build wrapper and test programs
cd tracer/nopin-object
make wrapper test

# 1. Run test_malloc to generate trace (glibc)
TRACE_FILE=test/verify.bin LD_PRELOAD=./libobject_tracer_wrapper.so ./test/test_malloc

# 2. Analyze trace with analyzer
python3 little_object_analyzer.py -i test/verify.bin

# 3. Check output file
cat test/verify.result.log

# 4. Run test_analyzer
TRACE_FILE=test/analyzer.bin LD_PRELOAD=./libobject_tracer_wrapper.so ./test/test_analyzer
python3 little_object_analyzer.py -i test/analyzer.bin

# 5. Run test_fortran
TRACE_FILE=test/fortran.bin LD_PRELOAD=./libobject_tracer_wrapper.so ./test/test_fortran
python3 little_object_analyzer.py -i test/fortran.bin

# 6. Run with mimalloc
TRACE_FILE=test/mimalloc.bin LD_PRELOAD=./libobject_tracer_wrapper.so:/usr/local/lib/libmimalloc.so ./test/test_malloc
python3 little_object_analyzer.py -i test/mimalloc.bin
```

### Method 2: Quick verification (one command)

```bash
cd tracer/nopin-object
make verify
```

This runs the test_malloc program with glibc, mimalloc, and fortran, then generates trace files in `test/`.

### Method 3: Standalone synthetic test (no tracer required)

```bash
# Run from any directory
python3 tracer/nopin-object/test/test_analyzer_synthetic.py
```

This test generates a synthetic binary trace containing all allocation types, runs the analyzer, and validates the output. All 13 tests are expected to pass.

### test_malloc.cpp Allocation Type Coverage (7-type scheme)

| Type Code | Type | Test Method |
|-----------|------|-------------|
| 1 | malloc / C++ new | Direct call + aligned_alloc/memalign + _Znwm, _Znam |
| 2 | free / C++ delete | Direct call + _ZdlPv, _ZdaPv |
| 3 | calloc | 2-parameter form |
| 4 | realloc | realloc (move or in-place) |
| 5 | posix_memalign | With alignment parameters |
| 6 | mmap | MAP_ANONYMOUS |
| 7 | munmap | Direct call |

## main_begin Marker (type=8)

The `test_analyzer_synthetic.py` test now begins generated traces with a `type=8` (main_begin)
marker to simulate the tracer behavior. The analyzer resets state when encountering this marker,
skipping any events that occurred before `main()` started.

The synthetic test expects 20 allocs + 9 frees from events after the type=8 marker.

## Workspace Files

| File | Description |
|------|-------------|
| `verify.bin` / `verify.result.log` | test_malloc + glibc trace |
| `verify_mimalloc.bin` / `verify.result.log` | test_malloc + mimalloc trace |
| `verify_fortran.bin` / `verify.result.log` | test_fortran + glibc trace |
| `verify_fortran_mimi.bin` / `verify.result.log` | test_fortran + mimalloc trace |