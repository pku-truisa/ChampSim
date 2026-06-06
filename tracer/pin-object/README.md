# Object Tracer — Memory Allocation PIN Tool

The included PIN tool `object_tracer.cpp` records all memory allocation and deallocation events to a binary trace file (`malloc.bin`). It does **not** generate any instruction-level trace — it focuses solely on heap and anonymous mmap activity.

It has been tested with PIN 3.22 through PIN 3.31.

See [test/README.md](test/README.md) for the test suite documentation.

## Download and install PIN

Download the source of PIN from Intel's website, then build it in a location of your choice.

    wget https://software.intel.com/sites/landingpage/pintool/downloads/pin-3.22-98547-g7a303a835-gcc-linux.tar.gz
    tar zxf pin-3.22-98547-g7a303a835-gcc-linux.tar.gz
    cd pin-3.22-98547-g7a303a835-gcc-linux/source/tools
    make
    export PIN_ROOT=/your/path/to/pin

## Building the tracer

The provided makefile will generate `obj-intel64/object_tracer.so`.

    make
    $PIN_ROOT/pin -t obj-intel64/object_tracer.so -- <your program here>

## Command-line options

```
-m <filename>
Specify the output file for the binary malloc trace.
The default is malloc.bin.
```

## Usage Examples

### Trace malloc events for a program

    pin -t obj-intel64/object_tracer.so -- ./my_program

### Trace malloc events with a custom output file

    pin -t obj-intel64/object_tracer.so -m my_malloc.bin -- ./my_program

## Tracked Allocation Functions

The tracer hooks the following functions in all loaded shared libraries:

| Function                 | Type | Description                              |
|--------------------------|------|------------------------------------------|
| `malloc`                 | 1    | Standard memory allocation               |
| `free`                   | 2    | Memory deallocation                      |
| `mmap`                   | 3    | Anonymous memory mapping                 |
| `munmap`                 | 4    | Unmap memory region                      |
| `calloc`                 | 5    | Allocate and zero-initialize array       |
| `realloc` (搬迁)          | 6    | Reallocate to a new address              |
| `posix_memalign`         | 8    | POSIX aligned allocation                 |
| `fortran_alloc`          | 10   | Fortran ALLOCATE (gfortran)              |
| `realloc` (原地)          | 16   | Realloc expanding/shrinking in-place     |

> **Note:** `aligned_alloc` (C11), `memalign`, and `valloc` in glibc are thin wrappers that internally call `malloc` or `mmap`.  The tracer captures them correctly through the standard `malloc`/`mmap` hooks as **type=1** or **type=3**, rather than instrumenting them directly (to avoid tail-call deadlocks).  Similarly, C++ `operator new`/`operator new[]` and `operator delete`/`operator delete[]` are tracked through `_Znwm`/`_Znam` and `_ZdlPv`/`_ZdaPv` hooks, mapped to type=1 and type=2 respectively.

All events are recorded to a single binary file. Free/munmap events are only recorded for addresses that were previously tracked from an allocation/mmap call.

## Binary File Format

The output file consists of consecutive 40-byte records with the following C layout:

```c
struct malloc_instr {
  unsigned long long ip;       // caller's return address  (offset 0)
  unsigned long long arg1;     // parameter 1               (offset 8)
  unsigned long long arg2;     // parameter 2               (offset 16)
  unsigned long long ret;      // return value              (offset 24)
  unsigned char type;          // allocation event type     (offset 32)
  unsigned char reserved[7];   // alignment padding         (offset 33)
};  // total: 40 bytes
```

### Field semantics by event type

| Type | Event               | `arg1`                    | `arg2`                    | `ret`               |
|------|---------------------|---------------------------|---------------------------|---------------------|
| 1    | malloc              | size                      | 0                         | allocated address   |
| 2    | free                | pointer to free           | 0                         | 0                   |
| 3    | mmap                | length                    | 0                         | mapped address      |
| 4    | munmap              | address to unmap          | length                    | 0                   |
| 5    | calloc              | nmemb × size              | 0                         | allocated address   |
| 6    | realloc (搬迁)       | old pointer               | new size                  | new address         |
| 8    | posix_memalign      | size                      | alignment                 | aligned address     |
| 10   | fortran_alloc       | size                      | 0                         | allocated address   |
| 16   | realloc (原地)       | old pointer (= ret)       | new size                  | old address (same)  |

> **realloc 类型区分:** 当 `realloc` 返回的地址与旧指针不同时为 **type=6**（搬迁），相同时为 **type=16**（原地扩展/缩减）。两者均使用 `arg2` 存储新大小。

## Analyzing Memory Allocation Traces

The `little_object_analyzer.py` tool provides streaming, low-memory-footprint analysis of the binary malloc trace. It supports:

1. **Function call statistics** — count of each allocation and deallocation type
2. **Active memory tracking** — peak memory usage over time, both original and power-of-2-aligned
3. **Multi-threshold peak comparison** — compares aligned peaks at [8, 16, 32, 64, 128, 256, 512, 1024, 2048, 4096, 8192, 16384, 32768, 65536, 131072] byte thresholds
4. **Large object listing** (`*.objects.log`) — all allocated objects ≥32KB, sorted by size descending

### Usage

```bash
# Single file analysis (supports both .bin and .bin.xz input)
python3 little_object_analyzer.py -i malloc.bin

# Batch mode: process all *.malloc.bin.xz files in the current directory
python3 little_object_analyzer.py -i all
```

### Parameters

- `-i, --input`: Input binary malloc trace file (required). Supports `.xz` compressed files. Use `all` to batch-process every `*.malloc.bin.xz` in the current directory.

### Output Files

| File               | Description                                                              |
|--------------------|--------------------------------------------------------------------------|
| `*.result.log`     | Full analysis report including per-threshold peak comparison (console mirror) |
| `*.objects.log`    | All objects ≥32KB ever allocated, sorted by size descending              |

## Testing

The `test/` directory contains comprehensive test suites. See [test/README.md](test/README.md) for details.

### Quick synthetic test (no PIN required)

```bash
python3 test/test_analyzer_synthetic.py
```

### End-to-end tests (PIN required)

```bash
# Build test programs
cd test
g++ -o test_malloc test_malloc.cpp
g++ -o test_analyzer test_analyzer.cpp
gfortran -o test_fortran test_fortran.f90
cd ..

# Run each test
pin -t obj-intel64/object_tracer.so -m test/malloc.bin -- test/test_malloc
python3 little_object_analyzer.py -i test/malloc.bin
```

## Differences from champsim_tracer

`object_tracer` is a stripped-down, standalone version of the `-a` (alloc-only) mode from `champsim_tracer.cpp`:

- **No instruction trace** — no `-o`, `-s`, `-t` options
- **No size threshold (`-k`)** — all allocation events are recorded without filtering
- **No header/tail records** — the binary file consists purely of allocation/deallocation events
- **Self-contained** — the `malloc_instr` struct is defined directly in the source, no dependency on `inc/trace_instruction.h`
