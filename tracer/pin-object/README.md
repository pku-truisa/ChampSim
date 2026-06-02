# Object Tracer — Memory Allocation PIN Tool

The included PIN tool `object_tracer.cpp` records all memory allocation and deallocation events to a binary trace file (`malloc.bin`). It does **not** generate any instruction-level trace — it focuses solely on heap and anonymous mmap activity.

It has been tested (April 2022) using PIN 3.22.

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

| Function          | Type | Description                              |
|-------------------|------|------------------------------------------|
| `malloc`          | 1    | Standard memory allocation               |
| `free`            | 2    | Memory deallocation                      |
| `mmap`            | 3    | Anonymous memory mapping                 |
| `munmap`          | 4    | Unmap memory region                      |
| `calloc`          | 5    | Allocate and zero-initialize array       |
| `realloc`         | 6    | Reallocate memory block                  |
| `aligned_alloc`   | 7    | Aligned memory allocation (C11)          |
| `posix_memalign`  | 8    | POSIX aligned allocation                 |
| `memalign`        | 9    | Traditional aligned allocation           |

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

For **allocation** events (types 1, 3, 5, 6, 7, 8, 9):
- `arg1`: size (or old pointer for realloc)
- `arg2`: additional argument (new size for realloc; 0 otherwise)
- `ret`:  allocated address (0 on failure)

For **deallocation** events (types 2, 4):
- `arg1`: pointer/address to free/unmap
- `arg2`: length (for munmap only; 0 for free)
- `ret`:  0

## Analyzing Memory Allocation Traces

The `analyze_malloc.py` tool can be used to analyze the binary malloc trace. It provides:

1. **Function call statistics** — count and percentage of each allocation type
2. **Active memory tracking** — peak memory usage over time
3. **Multi-threshold peak comparison** — compares original vs. power-of-2-aligned sizes
4. **Per-IP allocation summary** (`ips.log`) — which call sites allocate the most
5. **Large-object lifecycle table** (`objects.log`) — lifetime and status of large objects

### Usage

```bash
# Basic analysis
python3 analyze_malloc.py -i malloc.bin

# Specify analysis threshold for power-of-2 alignment
python3 analyze_malloc.py -i malloc.bin -s 2048

# Verbose: dump all records in readable format
python3 analyze_malloc.py -i malloc.bin -v
```

### Parameters

- `-i, --input`: Input binary malloc trace file (required)
- `-s, --size`: Max size threshold for power-of-2 adjustment (default: 1024). Sizes smaller than this value are adjusted to the nearest power of 2 in peak memory calculations.
- `-v, --verbose`: Display all records in a human-readable table

### Output Files

| File               | Description                                           |
|--------------------|-------------------------------------------------------|
| `*.result.log`     | Full analysis report (console output mirror)          |
| `*.objects.log`    | Large object lifecycle table                          |
| `*.ips.log`        | Per-call-site (IP) allocation summary                 |

## Differences from champsim_tracer

`object_tracer` is a stripped-down, standalone version of the `-a` (alloc-only) mode from `champsim_tracer.cpp`:

- **No instruction trace** — no `-o`, `-s`, `-t` options
- **No size threshold (`-k`)** — all allocation events are recorded without filtering
- **No little-object tracking** — no separate summary for small allocations
- **No header/tail records** — the binary file consists purely of allocation/deallocation events
- **Self-contained** — the `malloc_instr` struct is defined directly in the source, no dependency on `inc/trace_instruction.h`
