# Intel PIN tracer

The included PIN tool `champsim_object_tracer.cpp` can be used to generate new traces.
It has been tested using PIN 3.22+.

## Download and install PIN

Download the source of PIN from Intel's website, then build it in a location of your choice.

    wget https://software.intel.com/sites/landingpage/pintool/downloads/pin-3.22-98547-g7a303a835-gcc-linux.tar.gz
    tar zxf pin-3.22-98547-g7a303a835-gcc-linux.tar.gz
    cd pin-3.22-98547-g7a303a835-gcc-linux/source/tools
    make
    export PIN_ROOT=/your/path/to/pin

## Building the tracer

The provided makefile will generate `obj-intel64/champsim_object_tracer.so`.

    cd tracer/pin-object
    make
    $PIN_ROOT/pin -t obj-intel64/champsim_object_tracer.so -- <your program here>

## Three Operation Modes

The tracer supports three mutually exclusive modes:

### 1. Compat mode (default, no `-m`)

Produces an instruction trace **without** allocation events. Compatible with the upstream
ChampSim trace format. Only normal instructions (instr_type=0) and branches (instr_type=1)
are recorded. Allocation events are completely ignored.

    $PIN_ROOT/pin -t obj-intel64/champsim_object_tracer.so -o trace.champsim -t 1000000 -- ./my_program

### 2. Embedded alloc mode (`-m`, no `-a`)

Produces an instruction trace **with** allocation events (instr_type=2) embedded between
normal instructions. Allocation events are mixed into the same output file as the instruction
records. This allows the simulator to reconstruct the dynamic memory allocation history.

    $PIN_ROOT/pin -t obj-intel64/champsim_object_tracer.so -o trace.champsim -t 1000000 -m -- ./my_program

### 3. Alloc-only mode (`-m -a <file>`)

Produces **only** allocation events (40-byte malloc_instr records compatible with
`little_object_analyzer.py`). No instruction trace is generated. This mode has no
threshold filtering — all allocation events are recorded regardless of size.

    $PIN_ROOT/pin -t obj-intel64/champsim_object_tracer.so -m -a alloc_trace.bin -- ./my_program

## Options

```
-o <filename>
Specify the output file for the instruction trace (compat and embedded alloc modes only).
The default is champsim.trace. Not used in alloc-only mode.

-s <number>
Specify the number of instructions to skip in the program before tracing begins.
This is useful for skipping initialization code that you don't want to include in
your instruction trace. The default value is 0 (start tracing from the beginning).

-t <number>
The number of instructions to trace, after -s instructions have been skipped.
The default value is 0, which means trace all instructions (unlimited).
If you specify a positive number N, the tracer will stop after tracing N instructions.

-k <number>
Minimum allocation size to record for allocation events embedded in the instruction
trace (embedded alloc mode only). The default value is 256 bytes.
Not used in compat or alloc-only modes.

-c <filename>
Specify a config file for multi-segment trace. Format: one line per segment,
each with -s N -t N -o filename.
Example: echo '-s 100000000 -t 50000000 -o trace_0.champsim' > cfg.txt

-m
Enable allocation event recording. Without -a, operates in embedded alloc mode:
allocation events are mixed into the instruction trace output.
With -a, operates in alloc-only mode. See "Three Operation Modes" above.

-a <filename>
(Requires -m) Alloc-only mode. Output only allocation events (40-byte malloc_instr
records compatible with little_object_analyzer.py) to the specified file.
No instruction trace is generated. All allocation events are recorded regardless
of size (-k is ignored).
```

## Usage Examples

### Compat mode (upstream ChampSim compatible)

    pin -t obj-intel64/champsim_object_tracer.so -o my_trace.champsim -s 1000000 -t 500000 -- ./my_program

### Embedded alloc mode

    pin -t obj-intel64/champsim_object_tracer.so -o trace_with_alloc.champsim -t 500000 -m -- ls

### Alloc-only mode

    pin -t obj-intel64/champsim_object_tracer.so -m -a alloc_events.bin -- ./my_program

### Multi-segment trace

    echo '-s 1000000 -t 500000 -o seg0.champsim' > cfg.txt
    echo '-s 2000000 -t 500000 -o seg1.champsim' >> cfg.txt
    pin -t obj-intel64/champsim_object_tracer.so -c cfg.txt -- ./my_program

## Output File Formats

### Instruction trace (compat and embedded alloc modes)

Output is a sequence of 64-byte `input_instr` records:

| Offset | Field | Description |
|--------|-------|-------------|
| 0..7   | ip    | Instruction pointer (PC) |
| 8      | instr_type | 0=normal, 1=branch, 2=alloc (embedded only) |
| 9      | instr_info | branch_taken or alloc type code |
| 10..11 | destination_registers[2] | Written register numbers |
| 12..15 | source_registers[4] | Read register numbers |
| 16..31 | destination_memory[2] | Written memory addresses |
| 32..63 | source_memory[4] | Read memory addresses |

### Alloc-only mode

Output is a sequence of 40-byte `malloc_instr` records, compatible with
`little_object_analyzer.py`:

| Offset | Field | Description |
|--------|-------|-------------|
| 0..7   | arg1  | Size (alloc) / old pointer (realloc) |
| 8..15  | arg2  | 0 (alloc) / new size (realloc) / alignment (posix_memalign) |
| 16..23 | ret   | Returned address (allocated/freed pointer) |
| 24..31 | caller_ip | Caller instruction pointer |
| 32     | type  | Allocation type code (see table below) |
| 33..39 | reserved | Zero padding |

### Allocation type codes (8-type scheme)

All allocator-variant symbols (mi_malloc, je_malloc, tc_malloc, C++ new/delete)
are mapped to their corresponding base type. Type 8 is a special marker
that indicates the start of the program's `main()` function.

| Code | Type | Meaning |
|------|------|---------|
| 1 | malloc / C++ new | malloc, mi/je/tc_malloc, _Znwm, _Znam |
| 2 | free / C++ delete | free, mi/je/tc_free, _ZdlPv, _ZdaPv |
| 3 | calloc | calloc, mi/je/tc_calloc |
| 4 | realloc | realloc, mi/je/tc_realloc |
| 5 | posix_memalign | POSIX aligned allocation |
| 6 | mmap | Anonymous memory mapping |
| 7 | munmap | Unmap memory region |
| 8 | main_begin | Marker: `main()` function has started |

### Type 8 — main_begin Marker

When running in embedded-alloc or alloc-only mode, the tracer automatically
emits a `type=8` record at the entry of `main()`. This is done via the
`ResetDepthOnMain()` callback, which is instrumented at `main`/`MAIN__`/`main_`
symbols found in each loaded image.

The marker allows the analyzer to:
- Skip glibc initialization allocations that occurred before `main()`
- Reset its internal state so only user-level allocations are counted
- Achieve a clean alloc/free ledger (active objects ≈ 1 at exit)

