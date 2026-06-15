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

The provided makefile uses the standard Pin kit build system. Set `PIN_ROOT` to your Pin or SDE kit's `pinkit` directory.

```bash
# Build with SDE kit (recommended)
make PIN_ROOT=$SDE_BUILD_KIT/pinkit

# Or build with standalone Pin kit
export PIN_ROOT=/path/to/pin
make
```

This generates `obj-intel64/object_tracer.so`.

> **Important for SDE users:** The compiled `.so` **must** be copied into the SDE kit's `intel64/` directory before use, as `sde64` resolves tool names relative to that path:
>
> ```bash
> cp obj-intel64/object_tracer.so $SDE_BUILD_KIT/intel64/
> ```

## Command-line options

```
-m <filename>
Specify the output file for the binary malloc trace.
The default is malloc.bin.
```

## SDE PinPlay Replay

The tool includes a built-in argument filter that strips PinPlay-injected internal options (`-work-dir`, `-pinplay:work-dir`, `-replay`, etc.), making it compatible with **both** standard `pin -t` and SDE PinPlay replay modes without any code changes.

### Whole Program replay

Replay a whole-program pinball with object tracing:

```bash
$SDE_BUILD_KIT/sde64 -skl -replay \
  -t object_tracer.so \
  -replay:basename whole_program.1/<program>.<pid>_<tid> \
  -replay:strace -replay:playout 0 -replay:deadlock_timeout 0 \
  -xyzzy \
  -- $SDE_BUILD_KIT/intel64/nullapp
```

`malloc.bin` is written to the current working directory.

### Region Pinball replay

Each region pinball can be replayed independently:

```bash
for rpb in test-malloc.1_6864.pp/*.address; do
  rpbname=$(basename "$rpb" .address)
  dir=$(dirname "$rpb")
  $SDE_BUILD_KIT/sde64 -skl -replay \
    -t object_tracer.so \
    -replay:basename "$dir/$rpbname" \
    -replay:strace -replay:playout 0 -replay:deadlock_timeout 0 \
    -xyzzy \
    -- $SDE_BUILD_KIT/intel64/nullapp
  mv malloc.bin "$dir/${rpbname}.malloc.bin"
done
```

## Usage Examples

### Standard Pin — trace a live program

```bash
pin -t obj-intel64/object_tracer.so -- ./my_program
pin -t obj-intel64/object_tracer.so -m my_malloc.bin -- ./my_program
```

### SDE — trace a live program

```bash
$SDE_BUILD_KIT/sde64 -skl -t object_tracer.so -m malloc.bin -- ./my_program
```

### SDE — replay a whole program pinball

```bash
$SDE_BUILD_KIT/sde64 -skl -replay \
  -t object_tracer.so \
  -replay:basename whole_program.1/test-malloc.1_6864 \
  -replay:strace -replay:playout 0 -replay:deadlock_timeout 0 \
  -xyzzy \
  -- $SDE_BUILD_KIT/intel64/nullapp
```

## Tracked Allocation Functions

The tracer hooks the following functions in all loaded shared libraries (7-type scheme):

| Function                 | Type | Description                              |
|--------------------------|------|------------------------------------------|
| `malloc`, `_Znwm`, `_Znam` | 1  | Standard memory allocation / C++ new     |
| `free`, `_ZdlPv`, `_ZdaPv` | 2  | Memory deallocation / C++ delete         |
| `calloc`                 | 3    | Allocate and zero-initialize array       |
| `realloc`                | 4    | Reallocation (move or in-place)          |
| `posix_memalign`         | 5    | POSIX aligned allocation                 |
| `mmap`                   | 6    | Anonymous memory mapping                 |
| `munmap`                 | 7    | Unmap memory region                      |

> **Note:** `aligned_alloc` (C11), `memalign`, and `valloc` in glibc are thin wrappers that internally call `malloc` or `mmap`. The tracer captures them correctly through the standard `malloc`/`mmap` hooks as **type=1** or **type=6**, rather than instrumenting them directly (to avoid tail-call deadlocks). Similarly, C++ `operator new`/`operator new[]` and `operator delete`/`operator delete[]` are tracked through `_Znwm`/`_Znam` and `_ZdlPv`/`_ZdaPv` hooks, mapped to type=1 and type=2 respectively.

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

All events use the 7-type scheme (1=malloc, 2=free, 3=calloc, 4=realloc, 5=posix_memalign, 6=mmap, 7=munmap). C++ `operator new`/`delete` and allocator-variant symbols (mi_malloc, je_malloc, etc.) are all mapped to their corresponding base type.

| Type | Event               | `arg1`                    | `arg2`                    | `ret`               |
|------|---------------------|---------------------------|---------------------------|---------------------|
| 1    | malloc / C++ new    | size                      | 0                         | allocated address   |
| 2    | free / C++ delete   | pointer to free           | 0                         | 0                   |
| 3    | calloc              | nmemb × size              | 0                         | allocated address   |
| 4    | realloc             | old pointer               | new size                  | new or same address |
| 5    | posix_memalign      | size                      | alignment                 | aligned address     |
| 6    | mmap                | length                    | 0                         | mapped address      |
| 7    | munmap              | address to unmap          | length                    | 0                   |

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
