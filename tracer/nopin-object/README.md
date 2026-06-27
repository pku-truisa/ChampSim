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
- `memusage-champsim` — Shell script wrapper (command-line front-end to the LD_PRELOAD library)

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

### Direct LD_PRELOAD

Preload the library before running your program:

    LD_PRELOAD=./libmemusage-champsim.so ./my_program

By default, the library prints a colorful memory usage summary and histograms to
stderr.

### Shell script wrapper

A command-line front-end is also available:

    ./memusage-champsim [OPTIONS] PROGRAM [ARGS...]

See `./memusage-champsim --help` for full option list.

### Summary file mode (three statistic tables)

The tracer can output three statistic tables to a plain-text file (no color
codes), suitable for scripting or automated analysis:

    LD_PRELOAD=./libmemusage-champsim.so \
      MEMUSAGE_SUMMARY_FILE=summary.log \
      MEMUSAGE_SUMMARY_ONLY=1 \
      ./my_program

Or using the shell wrapper:

    ./memusage-champsim --summary-file=summary.log --summary-only ./my_program

Short form (`-s` alone = `--summary-only`, `-s FILE` = `--summary-file=FILE`):

    ./memusage-champsim --summary-only ./my_program            # summary-only (use long form)
    ./memusage-champsim -s summary.log ./my_program            # save to file

The three tables are:

1. **Peak Memory Usage by Size Interval** — At peak heap moment, shows for each
   of the 13 size thresholds [16..65536] the contribution to peak memory:
   aligned increment, size, object count, and their cumulative percentages.

2. **Top 50 Caller IP Statistics** — Sorted by total allocated size (descending),
   shows for each calling instruction address: count, total size, average size,
   average lifetime in CPU cycles, and primary allocation type.

3. **All Objects Size Distribution (by power-of-2 intervals)** — 48 power-of-2
   buckets [2^0 .. 2^47] with object count, total size, and cumulative
   percentages.

### ChampSim trace output

To generate a 40-byte `malloc_instr` binary trace (compatible with
`little_object_analyzer.py`):

    LD_PRELOAD=./libmemusage-champsim.so \
      MEMUSAGE_MTRACE_FILE=my_trace.bin \
      ./my_program

If the file name ends with `.xz`, the output is automatically piped through
`xz -c` for on-the-fly compression:

    LD_PRELOAD=./libmemusage-champsim.so \
      MEMUSAGE_MTRACE_FILE=my_trace.bin.xz \
      ./my_program

Or using the shell wrapper:

    ./memusage-champsim --champsim-trace=my_trace.bin.xz ./my_program

### Combined usage

All features can be combined:

    LD_PRELOAD=./libmemusage-champsim.so \
      MEMUSAGE_MTRACE_FILE=trace.bin.xz \
      MEMUSAGE_SUMMARY_FILE=summary.log \
      MEMUSAGE_TRACE_MMAP=yes \
      ./my_program

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `MEMUSAGE_MTRACE_FILE` | Output file path for the ChampSim trace (`.xz` suffix enables compression) | (none) |
| `MEMUSAGE_SUMMARY_FILE` | Output three statistic tables to this file (plain text, no color codes) | (none) |
| `MEMUSAGE_SUMMARY_ONLY` | Set to 1 to suppress colorful stderr histogram; output tables only to summary file | (unset) |
| `MEMUSAGE_TRACE_MMAP` | Set to `yes` to also trace mmap/mmap64/mremap/munmap calls | (unset) |
| `MEMUSAGE_PROG_NAME` | Only profile program whose name matches this value | (all programs) |
| `MEMUSAGE_BUFFER_SIZE` | Number of internal buffer entries | `32768` |
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

## On-the-fly Summary vs Post-hoc Analyzer

The LD_PRELOAD library now includes three statistic tables directly in its
output (see "Summary file mode" above).  This means common profiling questions
can be answered **without** saving a trace file or running a separate analyzer.

The `little_object_analyzer.py` script remains useful for **post-hoc** analysis
of saved traces, especially when you need:

- Function call statistics (counts per allocation type)
- Processing after the program has exited
- Working with traces from the PIN-based tracer

To use the analyzer:

    python3 little_object_analyzer.py champsim.memtrace

For full usage instructions, run:

    python3 little_object_analyzer.py --help

### Comparison: Built-in tables vs Analyzer

| Feature | Built-in (C, at exit) | Python analyzer |
|---------|-----------------------|-----------------|
| **Peak memory interval table** | ✅ Yes (13 thresholds) | ✅ Yes |
| **Caller IP stats** | ✅ Top 50 (by total size) | ✅ All callers |
| **Pow2 size distribution** | ✅ Yes (48 buckets) | ✅ Yes |
| **Lifetime metric** | CPU cycles | Trace event count |
| **Top-N largest objects** | ❌ | ✅ (configurable) |
| **Requires trace file** | ❌ No (runs in-process) | ✅ Yes |
| **PIN-tracer compatible** | ❌ | ✅ |