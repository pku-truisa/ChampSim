#!/bin/bash
#Copyright (C) 2022 Intel Corporation
#SPDX-License-Identifier: BSD-3-Clause
#
# sde-run.object_tracer.single-threaded.sh
# Automates whole-program record → object_tracer replay → malloc.bin.xz generation
# Based on sde-run.pinpoints.single-threaded.sh workflow
#

export OMP_NUM_THREADS=1
PROGRAM=test-malloc
INPUT=1
COMMAND="./test_malloc"
SDE_ARCH="-skl"

# --- PinPlay options ---
PCCOUNT="--pccount_regions"
GLOBAL=""

if [ -z $SDE_BUILD_KIT ]; then
  echo "Set SDE_BUILD_KIT to point to the latest SDE kit"
  exit 1
fi

SCRIPT_DIR="$(dirname "$(readlink -f "$0")")"
PINOBJECT_DIR="$SCRIPT_DIR"

# --- Build/install object_tracer.so ---
echo "=== Building object_tracer.so ==="
make -C "$PINOBJECT_DIR" PIN_ROOT="$SDE_BUILD_KIT/pinkit" 2>&1 | tail -1
if [ ! -e "$PINOBJECT_DIR/obj-intel64/object_tracer.so" ]; then
  echo "ERROR: Failed to build object_tracer.so"
  exit 1
fi
cp "$PINOBJECT_DIR/obj-intel64/object_tracer.so" "$SDE_BUILD_KIT/intel64/object_tracer.so"
echo "object_tracer.so installed to SDE kit"

# --- Check prerequisites ---
if [ ! -e "$SDE_BUILD_KIT/pinplay-scripts" ]; then
  echo "$SDE_BUILD_KIT/pinplay-scripts does not exist"
  cp -r ../../pinplay-scripts "$SDE_BUILD_KIT" 2>/dev/null || true
fi

if [ ! -e "$SDE_BUILD_KIT/intel64/nullapp" ]; then
  echo "ERROR: $SDE_BUILD_KIT/intel64/nullapp not found"
  exit 1
fi

# --- Step 1: Whole Program Recording ---
echo ""
echo "=== Step 1: Whole Program Recording ==="
$SDE_BUILD_KIT/pinplay-scripts/sde_pinpoints.py \
  --pin_options "$SDE_ARCH" $GLOBAL $PCCOUNT \
  --program_name=$PROGRAM --input_name=$INPUT \
  --command="$COMMAND" --delete --mode st \
  --log_options="-start_address main -log:fat -log:mp_mode 0 -log:mp_atomic 0" \
  --replay_options="-replay:strace" -l -r

# Determine whole_program pinball basename
WPB=$(ls whole_program.$INPUT/*.address 2>/dev/null | head -1 | sed '/.address/s///')
if [ -z "$WPB" ]; then
  echo "ERROR: Whole program pinball not found in whole_program.$INPUT/"
  exit 1
fi
echo "Whole program pinball: $WPB"

# --- Step 2: Replay whole program with object_tracer.so ---
echo ""
echo "=== Step 2: Replay with object_tracer.so ==="
$SDE_BUILD_KIT/sde64 $SDE_ARCH \
  -replay \
  -t object_tracer.so \
  -replay:basename "$WPB" \
  -replay:strace \
  -replay:playout 0 \
  -replay:deadlock_timeout 0 \
  -xyzzy \
  -- $SDE_BUILD_KIT/intel64/nullapp

# --- Step 3: Compress output ---
echo ""
echo "=== Step 3: Compress output ==="
if [ -e malloc.bin ]; then
  SIZE=$(stat -c%s malloc.bin 2>/dev/null)
  echo "Generated malloc.bin ($SIZE bytes)"
  OUTNAME="${WPB}.malloc.bin"
  mv malloc.bin "$OUTNAME"
  xz -kf "$OUTNAME"
  XZSIZE=$(stat -c%s "${OUTNAME}.xz" 2>/dev/null)
  echo "Compressed: ${OUTNAME}.xz ($XZSIZE bytes)"
else
  echo "WARNING: malloc.bin was not generated"
  exit 1
fi

echo ""
echo "=== Done ==="
echo "Output: ${OUTNAME}.xz"