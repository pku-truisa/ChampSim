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

Traces created with the champsim_tracer.so are approximately 64 bytes per instruction, but they generally compress down to less than a byte per instruction using xz compression.

