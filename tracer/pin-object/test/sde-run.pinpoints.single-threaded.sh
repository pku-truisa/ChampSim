#!/bin/bash
#Copyright (C) 2022 Intel Corporation
#SPDX-License-Identifier: BSD-3-Clause
# uses $SDE_BUILD_KIT/pinkit/sde-example/example/pcregions_control.cpp
# First build 32-bit and 64-bit versions of the relevant tool and copy
# them to the SDE_BUILD_KIT tools directories where 'sde' expects them
# Build instructions:
# cd $SDE_BUILD_KIT/pinkit/sde-example/example
#  make TARGET=ia32 clean;  make TARGET=ia32
#  make TARGET=intel64 clean;  make TARGET=intel64
#  cp obj-ia32/pcregions_control.so $SDE_BUILD_KIT/ia32
#  cp obj-intel64/pcregions_control.so $SDE_BUILD_KIT/intel64
export OMP_NUM_THREADS=0
SLICESIZE=100
WARMUP_FACTOR=1
MAXK=4
PROGRAM=test-malloc
INPUT=1
COMMAND="./test_malloc"
SDE_ARCH="-skl" # AMX registers introduced in Sapphire Rapids (-spr) not handled by 'pinball2elf' yet.

PCCOUNT="--pccount_regions"
WARMUP="--warmup_factor $WARMUP_FACTOR" 
#GLOBAL="--global_regions"
GLOBAL=""
PAR=3 # how many regions to process in parallel. Should have PAR*OMP_NUM_THREADS
  # cores available on the test machine


if [ -z $SDE_BUILD_KIT ];
then
  echo "Set SDE_BUILD_KIT to point to the latest (internal)SDE kit"
  exit 1
fi

if [ ! -e $SDE_BUILD_KIT/pinplay-scripts ];
then
  echo "$SDE_BUILD_KIT/pinplay-scripts does not exist"
  cp -r ../../pinplay-scripts $SDE_BUILD_KIT
fi

if [ ! -e $SDE_BUILD_KIT/pinplay-scripts/PinPointsHome/Linux/bin/simpoint ];
then
  echo "$SDE_BUILD_KIT/pinplay-scripts//PinPointsHome/Linux/bin/simpoint does not exist"
  echo " Attempting to build it ..."
  pushd $SDE_BUILD_KIT/pinplay-scripts//PinPointsHome/Linux/bin/
  make clean; make
  popd
  if [ ! -e $SDE_BUILD_KIT/pinplay-scripts/PinPointsHome/Linux/bin/simpoint ];
  then
    echo "$SDE_BUILD_KIT/pinplay-scripts//PinPointsHome/Linux/bin/simpoint does not exist"
    echo "See $SDE_BUILD_KIT/pinplay-scripts/README.simpoint"
    exit 1
  fi
fi

if [ ! -e $SDE_BUILD_KIT/intel64/pcregions_control.so ];
then
  echo " $SDE_BUILD_KIT/intel64/pcregions_control.so is missing"
  echo "   See build instructions above"
  exit 1
fi

#Whole Program Logging and replay using the default sde tool
# We are recording starting at 'main'
$SDE_BUILD_KIT/pinplay-scripts/sde_pinpoints.py --pin_options "$SDE_ARCH" $GLOBAL $PCCOUNT --program_name=$PROGRAM --input_name=$INPUT --command="$COMMAND" --delete --mode st --log_options="-start_address main -log:fat -log:mp_mode 0 -log:mp_atomic 0" --replay_options="-replay:strace" -l -r 

#Profiling using regular profiler from the default sde tool
$SDE_BUILD_KIT/pinplay-scripts/sde_pinpoints.py --pin_options "$SDE_ARCH" $GLOBAL $PCCOUNT --program_name=$PROGRAM --input_name=$INPUT --command="$COMMAND" --mode st -S $SLICESIZE -b 

#Simpoint
$SDE_BUILD_KIT/pinplay-scripts/sde_pinpoints.py --pin_options "$SDE_ARCH" $GLOBAL $PCCOUNT  --program_name=$PROGRAM --input_name=$INPUT --command="$COMMAND" $PCCOUNT -S $SLICESIZE $WARMUP --maxk=$MAXK --append_status -s 
