This directory contains example tracing utilities that create ChampSim traces. It currently contains:

 - A tracer for use with Intel PIN (see `champsim_tracer.cpp` in `pin/`)
 - A memory-allocation-only PIN object tracer (see `object_tracer.cpp` in `pin-object/`)
 - An LD_PRELOAD memory allocation tracer (see `object_tracer_wrapper.cpp` in `nopin-object/`)
 - A conversion program for CVP traces (`cvp_converter/`)

For detailed instructions on each tracer, see their respective README files.

## Analyzer Tool

The `little_object_analyzer.py` script in `nopin-object/` provides streaming analysis of memory allocation traces. It supports:

- **Function call statistics**: Counts of each allocation and deallocation type
- **Peak memory tracking**: Monitors active memory objects, original and power-of-2-aligned peak usage across multiple size thresholds
- **Per-call-site summary**: Identifies which IP addresses allocate the most memory
- **Top 64 largest objects**: Lists the largest allocated objects with lifetime and caller IP
- **main_begin marker (type=8)**: Skips glibc initialization allocations before `main()` starts, resetting state at the type=8 marker embedded by tracers

For detailed usage instructions, see `nopin-object/README.md`.

## Recent Changes (June 2026)

### Type 8 — main_begin Marker

All three tracers now emit a `type=8` (main_begin) marker record at the entry of the program's `main()` function. This allows the analyzer to:
1. Skip all allocation events that occurred during glibc initialization (before `main()`)
2. Reset analysis state at the marker, ensuring only user-level allocations are counted
3. Achieve a perfect 1:1 Alloc/Free match (active objects = 1 at program exit)

### PIN champsim_tracer

The PIN instruction+alloc tracer (`pin/champsim_tracer.cpp`) writes the type=8 marker in embedded-alloc mode via `pending_instr_malloc` (embedded into the next instruction record) and in alloc-only mode via direct `write_alloc_record_locked(8,...)`.

### PIN object_tracer

The PIN alloc-only tracer (`pin-object/object_tracer.cpp`) calls `write_malloc_instr_locked(8, 0, 0, 0, 0)` in its `ResetDepthOnMain()` callback, which is triggered at `main()` entry via `RTN_FindByName`.

### LD_PRELOAD wrapper (nopin-object)

The nopin tracer (`nopin-object/object_tracer_wrapper.cpp`) uses a `main_wrapper` function to:
1. Reset depth counters (`alloc_depth`, `mmap_depth`) — matching PIN's `ResetDepthOnMain()`
2. Write the type=8 marker
3. Only intercept `MAP_ANONYMOUS` mmap calls (matching PIN's behavior)
4. Always re-track addresses on realloc (matching PIN's unconditional `track_add`)