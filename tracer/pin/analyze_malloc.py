#!/usr/bin/env python3
"""
Memory Allocation Trace File Analyzer

Features:
1. Parse malloc/calloc/realloc/aligned_alloc/memalign/posix_memalign/mmap calls, adjust size parameters smaller than threshold to the nearest power of 2
2. Track active memory objects and record peak memory usage
3. Compare and analyze peak memory usage differences before and after modifications

Supported trace functions:
- malloc(size)=address
- calloc(size)=address
- realloc(old_ptr, size)=address [status]
- aligned_alloc(size)=address
- memalign(size)=address
- posix_memalign(size)=address
- app_mmap(length)=address
- free(address)
- app_munmap(address, length)

Usage:
    python3 analyze_malloc.py -i <input_file> [-o <output_file>] [-s <threshold>]
    
Parameters:
    -i, --input     Required input file path
    -o, --output    Optional output file path, defaults to input_file.modified
    -s, --size      Optional size threshold in bytes, defaults to 1024
    
Examples:
    python3 analyze_malloc.py -i trace.malloc
    python3 analyze_malloc.py -i trace.malloc -o output.malloc
    python3 analyze_malloc.py -i trace.malloc -o output.malloc -s 2048
"""

import re
import sys
import argparse


def next_power_of_2(n):
    """Calculate the smallest power of 2 greater than or equal to n"""
    if n <= 0:
        return 1
    # Check if n is already a power of 2
    if (n & (n - 1)) == 0:
        return n
    # If not, calculate the smallest power of 2 greater than n
    power = 1
    while power < n:
        power <<= 1
    return power


class MemoryTracker:
    """Active memory object tracker"""
    
    def __init__(self):
        self.active_objects = {}  # {address: size} active object dictionary
        self.current_memory = 0   # current memory usage
        self.max_memory = 0       # peak memory usage
    
    def add_object(self, address, size):
        """Add a new memory object"""
        self.active_objects[address] = size
        self.current_memory += size
        # Update peak
        if self.current_memory > self.max_memory:
            self.max_memory = self.current_memory
    
    def remove_object(self, address):
        """Remove a memory object"""
        if address in self.active_objects:
            size = self.active_objects.pop(address)
            self.current_memory -= size
    
    def update_object(self, old_address, new_address, new_size):
        """Update a memory object (realloc)"""
        # First remove the old object
        self.remove_object(old_address)
        # Then add the new object
        self.add_object(new_address, new_size)
    
    def get_max_memory_mb(self):
        """Get peak memory (MB)"""
        return self.max_memory / (1024 * 1024)
    
    def get_current_memory_mb(self):
        """Get current memory (MB)"""
        return self.current_memory / (1024 * 1024)
    
    def get_active_count(self):
        """Get active object count"""
        return len(self.active_objects)


def process_malloc_file(input_file, output_file, threshold):
    """
    Process memory allocation trace file.
    Adjust size parameters of all malloc/calloc/realloc/aligned_alloc/memalign/posix_memalign/mmap calls (if smaller than threshold) to the nearest power of 2.
    Track active memory objects and peak memory usage, compare differences before and after modifications.
    
    Supported function types:
    - malloc/calloc: Standard C library allocation functions
    - realloc: Memory reallocation
    - aligned_alloc: C11 aligned allocation
    - memalign: Traditional aligned allocation
    - posix_memalign: POSIX aligned allocation
    - app_mmap: Anonymous memory mapping
    - free/app_munmap: Deallocation operations
    """
    # Regular expressions to match various memory allocation calls
    # malloc(size)=address
    malloc_pattern = re.compile(r'^(malloc)\((\d+)\)=(0x[0-9a-f]+)(?:\s+\[(new|failed)\])?$')
    
    # calloc(size)=address (same as malloc, only one size parameter)
    calloc_pattern = re.compile(r'^(calloc)\((\d+)\)=(0x[0-9a-f]+)(?:\s+\[(new|failed)\])?$')
    
    # realloc(old_ptr, size)=address [status]
    realloc_pattern = re.compile(r'^(realloc)\((0x[0-9a-f]+),\s*(\d+)\)=(0x[0-9a-f]+|NULL)(?:\s+\[(new|in-place|moved|failed)\])?$')
    
    # aligned_alloc(size)=address
    aligned_alloc_pattern = re.compile(r'^(aligned_alloc)\((\d+)\)=(0x[0-9a-f]+)(?:\s+\[(new|failed)\])?$')
    
    # memalign(size)=address
    memalign_pattern = re.compile(r'^(memalign)\((\d+)\)=(0x[0-9a-f]+)(?:\s+\[(new|failed)\])?$')
    
    # posix_memalign(size)=address
    posix_memalign_pattern = re.compile(r'^(posix_memalign)\((\d+)\)=(0x[0-9a-f]+)$')
    
    # app_mmap(length)=address
    mmap_pattern = re.compile(r'^(app_mmap)\((\d+)\)=(0x[0-9a-f]+)$')
    
    # free(address)
    free_pattern = re.compile(r'^free\((0x[0-9a-f]+)\)$')
    
    # app_munmap(address, length)
    munmap_pattern = re.compile(r'^app_munmap\((0x[0-9a-f]+),\s*(\d+)\)$')
    
    modified_count = 0
    total_count = 0
    
    # Create two trackers: one for original size, one for modified size
    tracker_original = MemoryTracker()
    tracker_modified = MemoryTracker()
    
    with open(input_file, 'r') as infile, open(output_file, 'w') as outfile:
        for line in infile:
            line = line.strip()
            
            # Process malloc call
            match = malloc_pattern.match(line)
            if match:
                total_count += 1
                func_name = match.group(1)
                original_size = int(match.group(2))
                address = match.group(3)
                
                # Adjust size to power of 2 (if smaller than threshold)
                modified_size = original_size
                if original_size < threshold:
                    new_size = next_power_of_2(original_size)
                    if new_size != original_size:
                        modified_count += 1
                        modified_size = new_size
                
                # Track original and modified memory objects separately
                tracker_original.add_object(address, original_size)
                tracker_modified.add_object(address, modified_size)
                
                # Write modified line
                if original_size != modified_size:
                    status = match.group(4)
                    if status:
                        outfile.write(f"{func_name}({modified_size})={address} [{status}]\n")
                    else:
                        outfile.write(f"{func_name}({modified_size})={address}\n")
                else:
                    outfile.write(line + '\n')
                continue
            
            # Process calloc call
            match = calloc_pattern.match(line)
            if match:
                total_count += 1
                func_name = match.group(1)
                original_size = int(match.group(2))
                address = match.group(3)
                
                # Adjust size to power of 2 (if smaller than threshold)
                modified_size = original_size
                if original_size < threshold:
                    new_size = next_power_of_2(original_size)
                    if new_size != original_size:
                        modified_count += 1
                        modified_size = new_size
                
                # Track original and modified memory objects separately
                tracker_original.add_object(address, original_size)
                tracker_modified.add_object(address, modified_size)
                
                # Write modified line
                if original_size != modified_size:
                    status = match.group(4)
                    if status:
                        outfile.write(f"{func_name}({modified_size})={address} [{status}]\n")
                    else:
                        outfile.write(f"{func_name}({modified_size})={address}\n")
                else:
                    outfile.write(line + '\n')
                continue
            
            # Process realloc call
            match = realloc_pattern.match(line)
            if match:
                total_count += 1
                func_name = match.group(1)
                address_old = match.group(2)
                original_size = int(match.group(3))
                address_new = match.group(4)
                
                # Adjust size to power of 2 (if smaller than threshold)
                modified_size = original_size
                if original_size < threshold:
                    new_size = next_power_of_2(original_size)
                    if new_size != original_size:
                        modified_count += 1
                        modified_size = new_size
                
                # Track original and modified memory objects separately
                if address_new != "NULL":
                    tracker_original.update_object(address_old, address_new, original_size)
                    tracker_modified.update_object(address_old, address_new, modified_size)
                
                # Write modified line
                if original_size != modified_size:
                    status = match.group(5)
                    if status:
                        outfile.write(f"{func_name}({address_old}, {modified_size})={address_new} [{status}]\n")
                    else:
                        outfile.write(f"{func_name}({address_old}, {modified_size})={address_new}\n")
                else:
                    outfile.write(line + '\n')
                continue
            
            # Process aligned_alloc call
            match = aligned_alloc_pattern.match(line)
            if match:
                total_count += 1
                func_name = match.group(1)
                original_size = int(match.group(2))
                address = match.group(3)
                
                # Adjust size to power of 2 (if smaller than threshold)
                modified_size = original_size
                if original_size < threshold:
                    new_size = next_power_of_2(original_size)
                    if new_size != original_size:
                        modified_count += 1
                        modified_size = new_size
                
                # Track original and modified memory objects separately
                tracker_original.add_object(address, original_size)
                tracker_modified.add_object(address, modified_size)
                
                # Write modified line
                if original_size != modified_size:
                    status = match.group(4)
                    if status:
                        outfile.write(f"{func_name}({modified_size})={address} [{status}]\n")
                    else:
                        outfile.write(f"{func_name}({modified_size})={address}\n")
                else:
                    outfile.write(line + '\n')
                continue
            
            # Process memalign call
            match = memalign_pattern.match(line)
            if match:
                total_count += 1
                func_name = match.group(1)
                original_size = int(match.group(2))
                address = match.group(3)
                
                # Adjust size to power of 2 (if smaller than threshold)
                modified_size = original_size
                if original_size < threshold:
                    new_size = next_power_of_2(original_size)
                    if new_size != original_size:
                        modified_count += 1
                        modified_size = new_size
                
                # Track original and modified memory objects separately
                tracker_original.add_object(address, original_size)
                tracker_modified.add_object(address, modified_size)
                
                # Write modified line
                if original_size != modified_size:
                    status = match.group(4)
                    if status:
                        outfile.write(f"{func_name}({modified_size})={address} [{status}]\n")
                    else:
                        outfile.write(f"{func_name}({modified_size})={address}\n")
                else:
                    outfile.write(line + '\n')
                continue
            
            # Process posix_memalign call
            match = posix_memalign_pattern.match(line)
            if match:
                total_count += 1
                func_name = match.group(1)
                original_size = int(match.group(2))
                address = match.group(3)
                
                # Adjust size to power of 2 (if smaller than threshold)
                modified_size = original_size
                if original_size < threshold:
                    new_size = next_power_of_2(original_size)
                    if new_size != original_size:
                        modified_count += 1
                        modified_size = new_size
                
                # Track original and modified memory objects separately
                tracker_original.add_object(address, original_size)
                tracker_modified.add_object(address, modified_size)
                
                # Write modified line
                if original_size != modified_size:
                    outfile.write(f"{func_name}({modified_size})={address}\n")
                else:
                    outfile.write(line + '\n')
                continue
            
            # Process app_mmap call
            match = mmap_pattern.match(line)
            if match:
                total_count += 1
                func_name = match.group(1)
                original_size = int(match.group(2))
                address = match.group(3)
                
                # Adjust size to power of 2 (if smaller than threshold)
                modified_size = original_size
                if original_size < threshold:
                    new_size = next_power_of_2(original_size)
                    if new_size != original_size:
                        modified_count += 1
                        modified_size = new_size
                
                # Track original and modified memory objects separately
                tracker_original.add_object(address, original_size)
                tracker_modified.add_object(address, modified_size)
                
                # Write modified line
                if original_size != modified_size:
                    outfile.write(f"{func_name}({modified_size})={address}\n")
                else:
                    outfile.write(line + '\n')
                continue
            
            # Process free call
            match = free_pattern.match(line)
            if match:
                address = match.group(1)
                # Remove object from both trackers
                tracker_original.remove_object(address)
                tracker_modified.remove_object(address)
                outfile.write(line + '\n')
                continue
            
            # Process app_munmap call
            match = munmap_pattern.match(line)
            if match:
                address = match.group(1)
                # Remove object from both trackers
                tracker_original.remove_object(address)
                tracker_modified.remove_object(address)
                outfile.write(line + '\n')
                continue
            
            # Write other lines as is
            outfile.write(line + '\n')
    
    # Calculate statistics
    original_peak = tracker_original.max_memory
    modified_peak = tracker_modified.max_memory
    memory_increase = modified_peak - original_peak
    increase_percentage = (memory_increase / original_peak * 100) if original_peak > 0 else 0
    
    print(f"Processing complete!")
    print(f"Total {total_count} memory allocation calls found")
    print(f"Modified {modified_count} size parameters")
    print(f"\n=== Peak Memory Usage Comparison ===")
    print(f"Original peak memory: {tracker_original.get_max_memory_mb():.2f} MB ({original_peak:,} bytes)")
    print(f"Modified peak memory: {tracker_modified.get_max_memory_mb():.2f} MB ({modified_peak:,} bytes)")
    print(f"Memory increase:      {memory_increase / (1024 * 1024):.2f} MB ({memory_increase:,} bytes)")
    print(f"Increase percentage:  {increase_percentage:.2f}%")
    print(f"\n=== Final State Statistics ===")
    print(f"Final active object count: {tracker_modified.get_active_count():,}")
    print(f"Final memory usage:    {tracker_modified.get_current_memory_mb():.2f} MB ({tracker_modified.current_memory:,} bytes)")
    print(f"Output file saved to: {output_file}")


if __name__ == "__main__":
    # Create command line argument parser
    parser = argparse.ArgumentParser(
        description='Memory allocation trace file analysis tool',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 analyze_malloc.py -i trace.malloc
  python3 analyze_malloc.py -i trace.malloc -o output.malloc
  python3 analyze_malloc.py -i trace.malloc -o output.malloc -s 2048
        """
    )
    
    # Add argument options
    parser.add_argument('-i', '--input', 
                        required=True,
                        help='Required input file path')
    
    parser.add_argument('-o', '--output',
                        default=None,
                        help='Optional output file path, defaults to input_file.modified')
    
    parser.add_argument('-s', '--size',
                        type=int,
                        default=1024,
                        help='size threshold (bytes), defaults to 1024. Sizes smaller than this will be adjusted to the nearest power of 2')
    
    # Parse arguments
    args = parser.parse_args()
    
    # Get input file path
    input_file = args.input
    
    # Determine output file path
    if args.output:
        output_file = args.output
    else:
        # If no output file is specified, default to input_file.modified
        output_file = input_file + ".modified"
    
    # Get threshold
    threshold = args.size
    
    print("Starting to process memory allocation trace file...")
    print(f"Input file: {input_file}")
    print(f"Output file: {output_file}")
    print(f"Size threshold: {threshold} bytes")
    print("-" * 50)
    
    process_malloc_file(input_file, output_file, threshold)
