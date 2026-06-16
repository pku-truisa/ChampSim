# Object Tracer Test Suite

This directory contains test files for Object Tracer v3 (`object_tracer.cpp`) and its analyzer (`little_object_analyzer.py`).

## Directory Structure

| File | Description |
|------|-------------|
| `test_malloc.cpp` | Comprehensive C/C++ memory allocation test — covers malloc/calloc/realloc/posix_memalign/mmap/C++ new and all other allocation types |
| `test_analyzer.cpp` | Peak memory and threshold statistics stress test — validates analyzer peak tracking and threshold counting |
| `test_fortran.f90` | Fortran ALLOCATE/DEALLOCATE test — validates Fortran allocation tracking |
| `test_analyzer_synthetic.py` | **Standalone synthetic test** — no PIN required, generates synthetic binary trace and validates analyzer output |
| `pin.log` / `pintool.log` | PIN runtime logs |
| `debug.log` / `debug2.log` | Debug logs |
| `malloc.ips.log` / `malloc.result.log` | Sample analyzer output |

## Building Test Programs

```bash
# C/C++ tests
g++ -o test_malloc test_malloc.cpp
g++ -o test_analyzer test_analyzer.cpp

# Fortran test
gfortran -o test_fortran test_fortran.f90
```

## Running Tests

### Method 1: Full end-to-end test (requires PIN)

```bash
# Run from the tracer/pin-object directory

# 1. Run test_malloc to generate trace
pin -t obj-intel64/object_tracer.so -m test/malloc.bin -- test/test_malloc

# 2. Analyze trace with analyzer
python3 little_object_analyzer.py -i test/malloc.bin

# 3. Check output files
cat test/malloc.result.log
cat test/malloc.ips.log

# 4. Similarly test test_analyzer and test_fortran
pin -t obj-intel64/object_tracer.so -m test/analyzer.bin -- test/test_analyzer
python3 little_object_analyzer.py -i test/analyzer.bin

pin -t obj-intel64/object_tracer.so -m test/fortran.bin -- test/test_fortran
python3 little_object_analyzer.py -i test/fortran.bin
```

### Method 2: Standalone synthetic test (no PIN required)

```bash
# Run from ChampSim root directory
python3 tracer/pin-object/test/test_analyzer_synthetic.py
```

This test automatically generates a synthetic binary trace containing all allocation types (malloc/free/calloc/realloc/realloc_inplace/mmap/munmap/posix_memalign/fortran_alloc), runs the analyzer, and validates the output. All 13 tests are expected to pass.

### test_analyzer.cpp Expected Output

| Threshold | Objects < Thresh | Description |
|-----------|------------------|-------------|
| < 8  | 1               | malloc(7) |
| < 16 | 2               | Above + malloc(15) |
| < 32 | 4               | Above + malloc(31) + calloc(2,15) |
| < 64 | 4               | Above (no new allocations < 64) |

Peak memory is approximately 4.05 MiB (during the large allocation phase in Phase 3).

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
skipping any events that occurred before `main()` started. Both synthetic test scripts
(`nopin-object/test/test_analyzer_synthetic.py` and this one) have been updated to include
this marker.

The synthetic test expects 20 allocs + 9 frees from events after the type=8 marker.

## Known Issues

### Fixed Bugs (2026-06)

**`realloc_inplace` (type=16) memory double-counting**

- **Location**: `little_object_analyzer.py` line 109
- **Cause**: Only `etype == 6` was handled for old allocation cleanup, missing `etype == 16`
- **Fix**: Changed to `etype in (6, 16)`
- **Impact**: Any scenario using realloc with in-place expansion/shrinkage would have inflated peak memory statistics
- **Test coverage**: `test_analyzer_synthetic.py` Phase 5 includes dedicated type=16 validation
