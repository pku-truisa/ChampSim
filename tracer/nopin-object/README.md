# LD_PRELOAD nopin-object Tracer

This directory contains a memory allocation tracer that uses the `LD_PRELOAD`
mechanism to intercept dynamic memory allocation calls. Unlike the PIN-based
tracer in `pin-object/`, this tracer does **not** require the Intel PIN SDK
and works directly as a shared library preloaded into the target process.

## Files

- `malloc_memusage-champsim.c` — Main source file, adapted from glibc's memusage
- `Makefile` — Build system with two build modes
- `libmemusage-champsim.so` — Pre-built shared library (output)
- `little_object_analyzer.py` — Python script for streaming analysis of traces
- `memusage-champsim` — Placeholder target (kept for compatibility)

## Building

Two build modes are available:

### Standalone build (default)

    cd tracer/nopin-object
    make

This patches internal glibc headers to avoid external dependencies and disables
the SIGPROF timer. It is the recommended way to build on most systems.

### Build with glibc source

    cd tracer/nopin-object
    make USE_GLIBC_SRC=1

This requires the glibc source tree at `/usr/src/glibc/glibc-2.35`. It enables
the full set of glibc features including the SIGPROF profiling timer.

## Usage

Preload the library before running your program:

    LD_PRELOAD=./libmemusage-champsim.so ./my_program

The tracer will generate an allocation trace file in the current directory.
By default the output file is named `champsim.memtrace` (configurable via
the `MEMTRACE_OUTPUT` environment variable).

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `MEMTRACE_OUTPUT` | Output file path for the allocation trace | `champsim.memtrace` |
| `MEMUSAGE_NO_TIMER` | Set to disable SIGPROF timer (standalone mode always disables) | (unset) |

### Output Format

The tracer produces 40-byte `malloc_instr` records with the same format
as the PIN-based alloc-only mode. Each record contains:

| Offset | Field | Description |
|--------|-------|-------------|
| 0..7   | arg1  | Size (alloc) / old pointer (realloc) |
| 8..15  | arg2  | 0 (alloc) / new size (realloc) / alignment (posix_memalign) |
| 16..23 | ret   | Returned address (allocated/freed pointer) |
| 24..31 | caller_ip | Caller instruction pointer |
| 32     | type  | Allocation type code (see below) |
| 33..39 | reserved | Zero padding |

### Allocation Type Codes (9-type scheme)

The tracer records 9 distinct allocation event types:

| Code | Type | Meaning |
|------|------|---------|
| 1 | malloc | Dynamic memory allocation |
| 2 | calloc | Zero-initialized allocation |
| 3 | realloc | Resize existing allocation |
| 4 | free | Release allocated memory |
| 5 | mmap | Memory mapping |
| 6 | mmap64 | 64-bit memory mapping |
| 7 | mremap | Remap memory mapping |
| 8 | munmap | Unmap memory region |
| 9 | main_begin | Marker: `main()` function has started |

### main_begin Marker (type=9)

At the entry of the program's `main()` function, the tracer emits a `type=9`
marker record. The analyzer uses this marker to:

1. Skip all allocation events that occurred during glibc initialization (before `main()`)
2. Reset analysis state so only user-level allocations are counted
3. Achieve a clean alloc/free ledger (active objects ≈ 1 at program exit)

## Analyzer

The `little_object_analyzer.py` script provides streaming analysis of traces
produced by this tracer or the PIN-based alloc-only mode:

    python3 little_object_analyzer.py --input champsim.memtrace --stats

For full usage instructions, run:

    python3 little_object_analyzer.py --help

### Key features:
- **Function call statistics**: Counts of each allocation and deallocation type
- **Peak memory tracking**: Monitors active memory objects, original and power-of-2-aligned peak usage across multiple size thresholds
- **Per-call-site summary**: Identifies which IP addresses allocate the most memory
- **Top 64 largest objects**: Lists the largest allocated objects with lifetime and caller IP