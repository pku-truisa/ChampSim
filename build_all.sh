#!/bin/bash

CONFIG_DIR="${1:-./dpc4}"

if [[ ! -d "$CONFIG_DIR" ]]; then
    echo "ERROR: Directory $TARGET_DIR does not exist."
    exit 1
fi

for file in "$CONFIG_DIR"/*.json; do
    if [[ ! -f "$file" ]]; then
        echo "No .json files found in $TARGET_DIR."
        exit 1
    fi

    echo "========================================="
    echo "Processing config file: $file"
    echo "========================================="

    ./config.sh "$file"
    if [[ $? -ne 0 ]]; then
        echo "ERROR: config.sh $file failed. Skipping build."
        continue
    fi

    # make clean
    make

    if [[ $? -eq 0 ]]; then
        echo "SUCCESS: $file configured and built."
    else
        echo "ERROR: Build failed for $file."
    fi

    echo ""
done

echo "All .json files processed."
