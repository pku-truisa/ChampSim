# Intel PIN tracer

The included PIN tool `champsim_tracer.cpp` can be used to generate new traces.
It has been tested (April 2022) using PIN 3.22.

## Download and install PIN

Download the source of PIN from Intel's website, then build it in a location of your choice.

    wget https://software.intel.com/sites/landingpage/pintool/downloads/pin-3.22-98547-g7a303a835-gcc-linux.tar.gz
    tar zxf pin-3.22-98547-g7a303a835-gcc-linux.tar.gz
    cd pin-3.22-98547-g7a303a835-gcc-linux/source/tools
    make
    export PIN_ROOT=/your/path/to/pin

## Building the tracer

The provided makefile will generate `obj-intel64/champsim_tracer.so`.

    make
    $PIN_ROOT/pin -t obj-intel64/champsim_tracer.so -- <your program here>

The tracer has several options you can set:
```
-o <filename>
Specify the output file for your trace.
The default is champsim.trace.

-s <number>
Specify the number of instructions to skip in the program before tracing begins.
This is useful for skipping initialization code that you don't want to include in your trace.
The default value is 0 (start tracing from the beginning).

-t <number>
The number of instructions to trace, after -s instructions have been skipped.
The default value is 0, which means trace all instructions (unlimited).
If you specify a positive number N, the tracer will stop after tracing N instructions.

-m <filename>
Specify the output file for malloc/free event traces.
The default is malloc.trace.

-k <number>
Minimum allocation size to trace for malloc events (in bytes).
The default value is 0, which means trace all allocations regardless of size.

-a
Only generate memory allocation trace, skip instruction trace.
When this flag is set, the output file will contain only memory allocation events
(malloc/free/calloc/realloc/mmap/munmap/aligned_alloc/posix_memalign/memalign) and no regular instructions. This is useful for creating
smaller traces focused on memory allocation patterns.
```

## Usage Examples

### Trace entire program execution (default behavior)
Trace all instructions from start to finish:

    pin -t obj-intel64/champsim_tracer.so -- ./my_program

### Trace with fast-forward
Skip the first 1 million instructions, then trace the next 500,000 instructions:

    pin -t obj-intel64/champsim_tracer.so -o my_trace.champsim -s 1000000 -t 500000 -- ./my_program

### Trace specific portion of execution
Skip initialization (first 100K instructions), then trace everything after that:

    pin -t obj-intel64/champsim_tracer.so -o my_trace.champsim -s 100000 -t 0 -- ./my_program

### Trace with custom output file
Specify a custom output filename:

    pin -t obj-intel64/champsim_tracer.so -o traces/ls_trace.champsim -- ls

### Trace with malloc event logging
Enable malloc/free event tracing with minimum size threshold:

    pin -t obj-intel64/champsim_tracer.so -m malloc_events.trace -k 1024 -- ./my_program

The tracer now automatically hooks additional memory allocation functions:
- `malloc`, `free`, `calloc`, `realloc` - C standard library allocation functions
- `aligned_alloc` - C11 aligned allocation
- `posix_memalign` - POSIX aligned allocation  
- `memalign` - Traditional aligned allocation
- `mmap`/`munmap` - Memory mapping (from all shared libraries, not just main executable)

### Trace only memory allocation events
Generate a trace containing only memory allocation events, skipping all regular instructions:

    pin -t obj-intel64/champsim_tracer.so -o alloc_only.trace -a -- ./my_program

This creates a much smaller trace file that focuses solely on memory allocation patterns.

**Performance Optimization**: In allocation-only mode (`-a`), the tracer skips all instruction-level analysis (register tracking, memory operand analysis, etc.) and only maintains an instruction counter for the malloc trace. This significantly improves tracing speed compared to normal mode while still providing accurate `instrCount` values in the malloc trace output.

## Analyzing Memory Allocation Traces

The `analyze_malloc.py` tool can be used to analyze and modify memory allocation traces. It provides the following features:

1. **Size Adjustment**: Adjusts allocation sizes smaller than a threshold to the nearest power of 2
2. **Memory Tracking**: Tracks active memory objects and records peak memory usage
3. **Comparative Analysis**: Compares peak memory usage before and after size adjustments

### Supported Functions

The tool supports all memory allocation functions tracked by champsim_tracer. Each trace line includes an instruction count prefix (`instrCount:<count>`) to track memory object lifecycle:

- `instrCount:<count> malloc(size)=address`
- `instrCount:<count> calloc(size)=address`
- `instrCount:<count> realloc(old_ptr, size)=address [status]`
- `instrCount:<count> aligned_alloc(size)=address`
- `instrCount:<count> memalign(size)=address`
- `instrCount:<count> posix_memalign(size)=address`
- `instrCount:<count> app_mmap(length)=address`
- `instrCount:<count> free(address)`
- `instrCount:<count> app_munmap(address, length)`

The instruction count indicates the number of instructions executed when the allocation/deallocation occurred, which can be used to calculate memory object lifetime (destruction_instr - creation_instr).

### Usage

```bash
# Basic usage (default threshold: 1024 bytes)
python3 analyze_malloc.py -i malloc.trace

# Specify output file and custom threshold
python3 analyze_malloc.py -i malloc.trace -o modified.trace -s 2048
```

### Parameters

- `-i, --input`: Required input file path
- `-o, --output`: Optional output file path (default: input_file.modified)
- `-s, --size`: Size threshold in bytes (default: 1024). Sizes below this value will be adjusted to the next power of 2

### Example Output

The tool provides detailed statistics:

```
Processing complete!
Total 7 memory allocation calls found
Modified 7 size parameters

=== Peak Memory Usage Comparison ===
Original peak memory: 0.00 MB (2,700 bytes)
Modified peak memory: 0.00 MB (3,840 bytes)
Memory increase:      0.00 MB (1,140 bytes)
Increase percentage:  42.22%

=== Final State Statistics ===
Final active object count: 4
Final memory usage:    0.00 MB (2,560 bytes)
Output file saved to: modified.trace
```

### Use Cases

This tool is useful for:
- Studying the impact of memory alignment on peak memory usage
- Analyzing memory allocation patterns in applications
- Understanding how size adjustments affect overall memory consumption
- Preprocessing traces for cache simulation studies

Traces created with the champsim_tracer.so are approximately 64 bytes per instruction, but they generally compress down to less than a byte per instruction using xz compression.

