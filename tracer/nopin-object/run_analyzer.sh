#!/bin/bash
# Run little_object_analyzer.py on .malloc.bin.xz files

ANALYZER="$CHAMPSIM_ROOT/tracer/nopin-object/little_object_analyzer.py"
DATA_DIR="."

if [ $# -ne 1 ]; then
    echo "Usage: $0 all|<filename>"
    echo "  all          - Process all .malloc.bin.xz files"
    echo "  <filename>   - Process a specific file (e.g., trace.malloc.bin.xz)"
    exit 1
fi

if [ "$1" = "all" ]; then
    for f in "$DATA_DIR"/*.malloc.bin.xz; do
        [ -f "$f" ] || continue
        echo "Processing: $(basename "$f")"
        python3 "$ANALYZER" "$f"
    done
else
    f="$DATA_DIR/$1"
    if [ -f "$f" ]; then
        echo "Processing: $1"
        python3 "$ANALYZER" "$f"
    else
        echo "Error: File not found: $f"
        exit 1
    fi
fi

echo "Done."