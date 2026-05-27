#!/usr/bin/env python3
"""
Memory Allocation Trace File Analyzer

Features:
1. Parse malloc/calloc/realloc/aligned_alloc/memalign/posix_memalign/mmap calls, adjust size parameters smaller than threshold to the nearest power of 2
2. Track active memory objects and record peak memory usage
3. Compare and analyze peak memory usage differences before and after modifications

Supported trace functions (with instruction count prefix):
- instrCount:<count> malloc(size)=address
- instrCount:<count> calloc(size)=address
- instrCount:<count> realloc(old_ptr, size)=address [status]
- instrCount:<count> aligned_alloc(size)=address
- instrCount:<count> memalign(size)=address
- instrCount:<count> posix_memalign(size)=address
- instrCount:<count> app_mmap(length)=address
- instrCount:<count> free(address)
- instrCount:<count> app_munmap(address, length)

Usage:
    python3 analyze_malloc.py -i <input_file> [-s <threshold>]
    
Parameters:
    -i, --input     Required input file path
    -s, --size      Optional size threshold in bytes, defaults to 1024
    
Examples:
    python3 analyze_malloc.py -i trace.malloc
    python3 analyze_malloc.py -i trace.malloc -s 2048
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


def format_size(size):
    """Format byte size to human-readable string."""
    if size >= 1024 * 1024:
        return "{:.2f} MiB".format(size / (1024 * 1024))
    elif size >= 1024:
        return "{:.2f} KiB".format(size / 1024)
    else:
        return "{} B".format(size)


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
    
    def reduce_object(self, address, length):
        """Reduce a memory object by the given length (partial munmap).
        If length >= current size, the object is fully removed."""
        if address in self.active_objects:
            current_size = self.active_objects[address]
            if length >= current_size:
                self.remove_object(address)
            else:
                self.active_objects[address] = current_size - length
                self.current_memory -= length
    
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


def process_malloc_file(input_file, threshold):
    """
    Process memory allocation trace file.
    Adjust size parameters of all malloc/calloc/realloc/aligned_alloc/memalign/posix_memalign/mmap calls (if smaller than threshold) to the nearest power of 2.
    Track active memory objects and peak memory usage, compare differences before and after modifications.
    """

    # Regular expressions to match various memory allocation calls
    # Supports two formats:
    #   New: instrCount:<count> ip:0x<addr> function(args)=result [status]
    #   Old: function(args)=result  (no prefix)
    # Group indices (same for all alloc patterns):
    #   1: instrCount (optional, None if old format)
    #   2: ip address (optional, None if old format)
    #   3: function name
    #   4: size argument
    #   5: returned address
    # For realloc: 4=old_ptr, 5=size, 6=new_addr
    # For free/munmap: 1=instrCount(opt), 2=ip(opt), 3=address
    
    # malloc(size)=address
    malloc_pattern = re.compile(
        r'^(?:instrCount:(\d+)\s+ip:(0x[0-9a-f]+)\s+)?(malloc)\((\d+)\)=(0x[0-9a-f]+)(?:\s+\[(new|failed)\])?$')
    
    # calloc(size)=address
    calloc_pattern = re.compile(
        r'^(?:instrCount:(\d+)\s+ip:(0x[0-9a-f]+)\s+)?(calloc)\((\d+)\)=(0x[0-9a-f]+)(?:\s+\[(new|failed)\])?$')
    
    # realloc(old_ptr, size)=address [status]
    realloc_pattern = re.compile(
        r'^(?:instrCount:(\d+)\s+ip:(0x[0-9a-f]+)\s+)?(realloc)\((0x[0-9a-f]+),\s*(\d+)\)=(0x[0-9a-f]+|NULL)(?:\s+\[(new|in-place|moved|failed)\])?$')
    
    # aligned_alloc(size)=address
    aligned_alloc_pattern = re.compile(
        r'^(?:instrCount:(\d+)\s+ip:(0x[0-9a-f]+)\s+)?(aligned_alloc)\((\d+)\)=(0x[0-9a-f]+)(?:\s+\[(new|failed)\])?$')
    
    # memalign(size)=address
    memalign_pattern = re.compile(
        r'^(?:instrCount:(\d+)\s+ip:(0x[0-9a-f]+)\s+)?(memalign)\((\d+)\)=(0x[0-9a-f]+)(?:\s+\[(new|failed)\])?$')
    
    # posix_memalign(size)=address
    posix_memalign_pattern = re.compile(
        r'^(?:instrCount:(\d+)\s+ip:(0x[0-9a-f]+)\s+)?(posix_memalign)\((\d+)\)=(0x[0-9a-f]+)$')
    
    # app_mmap(length)=address
    mmap_pattern = re.compile(
        r'^(?:instrCount:(\d+)\s+ip:(0x[0-9a-f]+)\s+)?(app_mmap)\((\d+)\)=(0x[0-9a-f]+)$')
    
    # free(address)  -- group 3 = address
    free_pattern = re.compile(
        r'^(?:instrCount:(\d+)\s+ip:(0x[0-9a-f]+)\s+)?free\((0x[0-9a-f]+)\)$')
    
    # app_munmap(address, length)  -- group 3 = address, group 4 = length
    munmap_pattern = re.compile(
        r'^(?:instrCount:(\d+)\s+ip:(0x[0-9a-f]+)\s+)?app_munmap\((0x[0-9a-f]+),\s*(\d+)\)$')
    
    modified_count = 0
    total_count = 0
    
    # Per-IP allocation tracking: ip -> {'func': str, 'count': int, 'total_size': int}
    ip_info = {}
    
    def track_ip(ip, func, size):
        """Accumulate allocation info per IP."""
        if ip not in ip_info:
            ip_info[ip] = {'func': func, 'count': 0, 'total_size': 0}
        ip_info[ip]['count'] += 1
        ip_info[ip]['total_size'] += size
    
    # Statistics for each allocation function type
    func_stats = {
        'malloc': 0,
        'calloc': 0,
        'realloc': 0,
        'aligned_alloc': 0,
        'memalign': 0,
        'posix_memalign': 0,
        'app_mmap': 0,
        'free': 0,
        'app_munmap': 0
    }
    
    # Create two trackers: one for original size, one for modified size
    tracker_original = MemoryTracker()
    tracker_modified = MemoryTracker()
    
    # Store life cycle info for large objects
    # Key: address
    # Value: {
    #   'func': str,       # allocation function name
    #   'alloc_ip': str,    # IP at allocation ("0x0" if old format)
    #   'alloc_instr': int, # instrCount at allocation (0 if old format)
    #   'size': int,        # modified size
    #   'original_size': int,
    #   'free_instr': int or None,   # instrCount at free
    #   'free_ip': str or None,       # IP at free
    #   'trace_line': str,            # original trace line of allocation
    # }
    large_objects_info = {}
    
    with open(input_file, 'r') as infile:
        for line in infile:
            line = line.strip()
            
            # --- Allocation handlers ---
            
            # Process malloc call
            match = malloc_pattern.match(line)
            if match:
                total_count += 1
                func_stats['malloc'] += 1
                instr_cnt = int(match.group(1)) if match.group(1) else 0
                alloc_ip = match.group(2) if match.group(2) else "0x0"
                func_name = match.group(3)
                original_size = int(match.group(4))
                address = match.group(5)
                
                modified_size = original_size
                if original_size < threshold:
                    new_size = next_power_of_2(original_size)
                    if new_size != original_size:
                        modified_count += 1
                        modified_size = new_size
                
                track_ip(alloc_ip, func_name, original_size)
                
                tracker_original.add_object(address, original_size)
                tracker_modified.add_object(address, modified_size)
                
                if modified_size >= threshold:
                    large_objects_info[address] = {
                        'func': func_name,
                        'alloc_ip': alloc_ip,
                        'alloc_instr': instr_cnt,
                        'size': modified_size,
                        'original_size': original_size,
                        'free_instr': None,
                        'free_ip': None,
                        'trace_line': line
                    }
                continue
            
            # Process calloc call
            match = calloc_pattern.match(line)
            if match:
                total_count += 1
                func_stats['calloc'] += 1
                instr_cnt = int(match.group(1)) if match.group(1) else 0
                alloc_ip = match.group(2) if match.group(2) else "0x0"
                func_name = match.group(3)
                original_size = int(match.group(4))
                address = match.group(5)
                
                modified_size = original_size
                if original_size < threshold:
                    new_size = next_power_of_2(original_size)
                    if new_size != original_size:
                        modified_count += 1
                        modified_size = new_size
                
                tracker_original.add_object(address, original_size)
                tracker_modified.add_object(address, modified_size)
                
                if modified_size >= threshold:
                    large_objects_info[address] = {
                        'func': func_name,
                        'alloc_ip': alloc_ip,
                        'alloc_instr': instr_cnt,
                        'size': modified_size,
                        'original_size': original_size,
                        'free_instr': None,
                        'free_ip': None,
                        'trace_line': line
                    }
                
                track_ip(alloc_ip, func_name, original_size)
                continue
            
            # Process realloc call
            # Groups: 1=instrCount(opt), 2=ip(opt), 3=func, 4=old_ptr, 5=size, 6=new_addr
            match = realloc_pattern.match(line)
            if match:
                total_count += 1
                func_stats['realloc'] += 1
                instr_cnt = int(match.group(1)) if match.group(1) else 0
                alloc_ip = match.group(2) if match.group(2) else "0x0"
                func_name = match.group(3)
                address_old = match.group(4)
                original_size = int(match.group(5))
                address_new = match.group(6)
                
                modified_size = original_size
                if original_size < threshold:
                    new_size = next_power_of_2(original_size)
                    if new_size != original_size:
                        modified_count += 1
                        modified_size = new_size
                
                if address_new != "NULL":
                    tracker_original.update_object(address_old, address_new, original_size)
                    tracker_modified.update_object(address_old, address_new, modified_size)
                    track_ip(alloc_ip, func_name, original_size)
                    
                    # Carry over old object's alloc info if realloc was a move
                    old_info = large_objects_info.pop(address_old, {})
                    if modified_size >= threshold:
                        large_objects_info[address_new] = {
                            'func': func_name,
                            'alloc_ip': old_info.get('alloc_ip', alloc_ip),
                            'alloc_instr': old_info.get('alloc_instr', instr_cnt),
                            'size': modified_size,
                            'original_size': original_size,
                            'free_instr': None,
                            'free_ip': None,
                            'trace_line': line
                        }
                continue
            
            # Process aligned_alloc call
            match = aligned_alloc_pattern.match(line)
            if match:
                total_count += 1
                func_stats['aligned_alloc'] += 1
                instr_cnt = int(match.group(1)) if match.group(1) else 0
                alloc_ip = match.group(2) if match.group(2) else "0x0"
                func_name = match.group(3)
                original_size = int(match.group(4))
                address = match.group(5)
                
                modified_size = original_size
                if original_size < threshold:
                    new_size = next_power_of_2(original_size)
                    if new_size != original_size:
                        modified_count += 1
                        modified_size = new_size
                
                tracker_original.add_object(address, original_size)
                tracker_modified.add_object(address, modified_size)
                
                if modified_size >= threshold:
                    large_objects_info[address] = {
                        'func': func_name,
                        'alloc_ip': alloc_ip,
                        'alloc_instr': instr_cnt,
                        'size': modified_size,
                        'original_size': original_size,
                        'free_instr': None,
                        'free_ip': None,
                        'trace_line': line
                    }
                
                track_ip(alloc_ip, func_name, original_size)
                continue
            
            # Process memalign call
            match = memalign_pattern.match(line)
            if match:
                total_count += 1
                func_stats['memalign'] += 1
                instr_cnt = int(match.group(1)) if match.group(1) else 0
                alloc_ip = match.group(2) if match.group(2) else "0x0"
                func_name = match.group(3)
                original_size = int(match.group(4))
                address = match.group(5)
                
                modified_size = original_size
                if original_size < threshold:
                    new_size = next_power_of_2(original_size)
                    if new_size != original_size:
                        modified_count += 1
                        modified_size = new_size
                
                tracker_original.add_object(address, original_size)
                tracker_modified.add_object(address, modified_size)
                
                if modified_size >= threshold:
                    large_objects_info[address] = {
                        'func': func_name,
                        'alloc_ip': alloc_ip,
                        'alloc_instr': instr_cnt,
                        'size': modified_size,
                        'original_size': original_size,
                        'free_instr': None,
                        'free_ip': None,
                        'trace_line': line
                    }
                
                track_ip(alloc_ip, func_name, original_size)
                continue
            
            # Process posix_memalign call
            match = posix_memalign_pattern.match(line)
            if match:
                total_count += 1
                func_stats['posix_memalign'] += 1
                instr_cnt = int(match.group(1)) if match.group(1) else 0
                alloc_ip = match.group(2) if match.group(2) else "0x0"
                func_name = match.group(3)
                original_size = int(match.group(4))
                address = match.group(5)
                
                modified_size = original_size
                if original_size < threshold:
                    new_size = next_power_of_2(original_size)
                    if new_size != original_size:
                        modified_count += 1
                        modified_size = new_size
                
                tracker_original.add_object(address, original_size)
                tracker_modified.add_object(address, modified_size)
                
                if modified_size >= threshold:
                    large_objects_info[address] = {
                        'func': func_name,
                        'alloc_ip': alloc_ip,
                        'alloc_instr': instr_cnt,
                        'size': modified_size,
                        'original_size': original_size,
                        'free_instr': None,
                        'free_ip': None,
                        'trace_line': line
                    }
                
                track_ip(alloc_ip, func_name, original_size)
                continue
            
            # Process app_mmap call
            match = mmap_pattern.match(line)
            if match:
                total_count += 1
                func_stats['app_mmap'] += 1
                instr_cnt = int(match.group(1)) if match.group(1) else 0
                alloc_ip = match.group(2) if match.group(2) else "0x0"
                func_name = match.group(3)
                original_size = int(match.group(4))
                address = match.group(5)
                
                modified_size = original_size
                if original_size < threshold:
                    new_size = next_power_of_2(original_size)
                    if new_size != original_size:
                        modified_count += 1
                        modified_size = new_size
                
                tracker_original.add_object(address, original_size)
                tracker_modified.add_object(address, modified_size)
                
                if modified_size >= threshold:
                    large_objects_info[address] = {
                        'func': func_name,
                        'alloc_ip': alloc_ip,
                        'alloc_instr': instr_cnt,
                        'size': modified_size,
                        'original_size': original_size,
                        'free_instr': None,
                        'free_ip': None,
                        'trace_line': line
                    }
                
                track_ip(alloc_ip, func_name, original_size)
                continue
            
            # --- Deallocation handlers ---
            # Groups for free: 1=instrCount(opt), 2=ip(opt), 3=address
            # Groups for munmap: 1=instrCount(opt), 2=ip(opt), 3=address, 4=length
            
            # Process free call
            match = free_pattern.match(line)
            if match:
                func_stats['free'] += 1
                instr_cnt = int(match.group(1)) if match.group(1) else 0
                free_ip = match.group(2) if match.group(2) else "0x0"
                address = match.group(3)
                
                tracker_original.remove_object(address)
                tracker_modified.remove_object(address)
                
                if address in large_objects_info:
                    large_objects_info[address]['free_instr'] = instr_cnt
                    large_objects_info[address]['free_ip'] = free_ip
                continue
            
            # Process app_munmap call
            match = munmap_pattern.match(line)
            if match:
                func_stats['app_munmap'] += 1
                instr_cnt = int(match.group(1)) if match.group(1) else 0
                munmap_ip = match.group(2) if match.group(2) else "0x0"
                address = match.group(3)
                length = int(match.group(4))
                
                tracker_original.reduce_object(address, length)
                tracker_modified.reduce_object(address, length)
                
                if address in large_objects_info:
                    # If the object was fully removed, record free info
                    if address not in tracker_original.active_objects and address not in tracker_modified.active_objects:
                        large_objects_info[address]['free_instr'] = instr_cnt
                        large_objects_info[address]['free_ip'] = munmap_ip
                continue
    
    # Calculate statistics
    original_peak = tracker_original.max_memory
    modified_peak = tracker_modified.max_memory
    memory_increase = modified_peak - original_peak
    increase_percentage = (memory_increase / original_peak * 100) if original_peak > 0 else 0
    
    print(f"Processing complete!")
    print(f"Total {total_count} memory allocation calls found")
    print(f"Modified {modified_count} size parameters")
    print(f"\n=== Function Call Statistics ===")
    print(f"{'Function':<20} {'Count':>10} {'Percentage':>12}")
    print(f"{'-'*20} {'-'*10} {'-'*12}")
    
    # Allocation functions
    alloc_funcs = ['malloc', 'calloc', 'realloc', 'aligned_alloc', 'memalign', 'posix_memalign', 'app_mmap']
    alloc_total = sum(func_stats[func] for func in alloc_funcs)
    
    for func in alloc_funcs:
        count = func_stats[func]
        percentage = (count / total_count * 100) if total_count > 0 else 0
        print(f"{func:<20} {count:>10,} {percentage:>11.2f}%")
    
    print(f"{'-'*20} {'-'*10} {'-'*12}")
    print(f"{'Total Alloc':<20} {alloc_total:>10,} {(alloc_total/total_count*100) if total_count > 0 else 0:>11.2f}%")
    print()
    
    # Deallocation functions
    dealloc_funcs = ['free', 'app_munmap']
    dealloc_total = sum(func_stats[func] for func in dealloc_funcs)
    
    for func in dealloc_funcs:
        count = func_stats[func]
        percentage = (count / total_count * 100) if total_count > 0 else 0
        print(f"{func:<20} {count:>10,} {percentage:>11.2f}%")
    
    print(f"{'-'*20} {'-'*10} {'-'*12}")
    print(f"{'Total Dealloc':<20} {dealloc_total:>10,} {(dealloc_total/total_count*100) if total_count > 0 else 0:>11.2f}%")
    print()
    
    print(f"\n=== Peak Memory Usage Comparison ===")
    print(f"Original peak memory: {tracker_original.get_max_memory_mb():.2f} MB ({original_peak:,} bytes)")
    print(f"Modified peak memory: {tracker_modified.get_max_memory_mb():.2f} MB ({modified_peak:,} bytes)")
    print(f"Memory increase:      {memory_increase / (1024 * 1024):.2f} MB ({memory_increase:,} bytes)")
    print(f"Increase percentage:  {increase_percentage:.2f}%")
    print(f"\n=== Final State Statistics ===")
    print(f"Final active object count: {tracker_modified.get_active_count():,}")
    print(f"Final memory usage:    {tracker_modified.get_current_memory_mb():.2f} MB ({tracker_modified.current_memory:,} bytes)")
    
    # Write table-formatted objects log
    objects_log_file = input_file + ".objects.log"
    # Build list and sort by size descending
    large_objects_list = [(addr, info) for addr, info in large_objects_info.items()]
    large_objects_list.sort(key=lambda x: x[1]['size'], reverse=True)
    
    # Calculate column widths
    if large_objects_list:
        max_func_len = max(len(info['func']) for _, info in large_objects_list)
        max_addr_len = max(len(addr) for addr, _ in large_objects_list)
        max_ip_len = max(len(info['alloc_ip']) for _, info in large_objects_list)
        max_free_ip_len = max((len(info['free_ip']) if info['free_ip'] else 2) for _, info in large_objects_list)
        max_size_str_len = max(len(format_size(info['size'])) for _, info in large_objects_list)
        max_orig_size_str_len = max(len(format_size(info['original_size'])) for _, info in large_objects_list)
        
        # Compute max data widths for numeric columns
        max_alloc_instr_len = 0
        max_free_instr_len = 2   # "--" minimum
        max_life_str_len = 3     # "N/A" minimum
        for _, info in large_objects_list:
            alloc_str = "{:,}".format(info['alloc_instr'])
            max_alloc_instr_len = max(max_alloc_instr_len, len(alloc_str))
            if info['free_instr'] is not None:
                free_str = "{:,}".format(info['free_instr'])
                max_free_instr_len = max(max_free_instr_len, len(free_str))
                lifetime = info['free_instr'] - info['alloc_instr']
                life_str = "{:,}".format(lifetime)
                max_life_str_len = max(max_life_str_len, len(life_str))
            # else: free_instr_str = "--" (len 2), lifetime_str = "N/A" (len 3)
    else:
        max_func_len, max_addr_len, max_ip_len = 10, 12, 10
        max_free_ip_len = 8
        max_size_str_len, max_orig_size_str_len = 8, 12
        max_alloc_instr_len = 0
        max_free_instr_len = 2
        max_life_str_len = 3
    
    func_w = max(max_func_len, len("Function"))
    addr_w = max(max_addr_len, len("Address"))
    ip_w = max(max_ip_len, len("Alloc IP"))
    free_ip_w = max(max_free_ip_len, len("Free IP"))
    alloc_instr_w = max(max_alloc_instr_len, len("Alloc Instr"))
    free_instr_w = max(max_free_instr_len, len("Free Instr"))
    life_w = max(max_life_str_len, len("Lifetime"))
    size_w = max(max_size_str_len, len("Mod Size"))
    orig_size_w = max(max_orig_size_str_len, len("Orig Size"))
    status_w = max(8, len("Status"))
    
    header = (f"{'Function':>{func_w}}  {'Address':>{addr_w}}  {'Alloc IP':>{ip_w}}  "
              f"{'Alloc Instr':>{alloc_instr_w}}  {'Free IP':>{free_ip_w}}  "
              f"{'Free Instr':>{free_instr_w}}  {'Lifetime':>{life_w}}  "
              f"{'Orig Size':>{orig_size_w}}  {'Mod Size':>{size_w}}  {'Status':>{status_w}}")
    separator = "-" * len(header)
    
    total_lifetime = 0
    freed_count = 0
    
    with open(objects_log_file, 'w') as obj_file:
        obj_file.write(f"# Active/Large Memory Objects (modified size >= {threshold} bytes)\n")
        obj_file.write(f"# Total objects: {len(large_objects_list)}\n")
        obj_file.write(f"# Sorted by modified size (descending)\n")
        obj_file.write(f"#\n")
        obj_file.write(header + "\n")
        obj_file.write(separator + "\n")
        
        for addr, info in large_objects_list:
            func = info['func']
            alloc_ip = info['alloc_ip']
            alloc_instr = info['alloc_instr']
            mod_size = info['size']
            orig_size = info['original_size']
            free_instr = info['free_instr']
            free_ip = info['free_ip']
            
            # Determine lifetime and status
            if free_instr is not None:
                lifetime = free_instr - alloc_instr
                status = "FREED"
                total_lifetime += lifetime
                freed_count += 1
            else:
                lifetime = 0
                status = "ACTIVE"
                free_ip = "--"
                free_instr = 0
            
            # Format lifetime
            if info['free_instr'] is not None:
                lifetime_str = "{:,}".format(lifetime)
            else:
                lifetime_str = "N/A"
            
            free_ip_str = free_ip if free_ip else "--"
            free_instr_str = "{:,}".format(free_instr) if info['free_instr'] is not None else "--"
            
            line_out = (f"{func:>{func_w}}  {addr:>{addr_w}}  {alloc_ip:>{ip_w}}  "
                        f"{alloc_instr:>{alloc_instr_w},}  {free_ip_str:>{free_ip_w}}  "
                        f"{free_instr_str:>{free_instr_w}}  {lifetime_str:>{life_w}}  "
                        f"{format_size(orig_size):>{orig_size_w}}  {format_size(mod_size):>{size_w}}  {status:>{status_w}}")
            obj_file.write(line_out + "\n")
        
        obj_file.write(separator + "\n")
        if freed_count > 0:
            avg_lifetime = total_lifetime // freed_count
            obj_file.write(f"# Freed objects: {freed_count}, Average lifetime: {avg_lifetime:,} instructions\n")
        else:
            obj_file.write(f"# Freed objects: 0\n")
        active_count = len(large_objects_list) - freed_count
        obj_file.write(f"# Still active: {active_count}\n")
    
    print(f"\nLarge objects log saved to: {objects_log_file}")
    print(f"Total large objects (modified size >= {threshold} bytes): {len(large_objects_list):,}")
    
    # Write per-IP allocation summary
    ips_log_file = input_file + ".ips.log"
    if ip_info:
        ip_list = [(ip, info['func'], info['count'], info['total_size']) for ip, info in ip_info.items()]
        ip_list.sort(key=lambda x: x[3], reverse=True)
        
        ip_col_w = max(max(len(ip) for ip, _, _, _ in ip_list), len("IP"))
        func_w2 = max(max(len(func) for _, func, _, _ in ip_list), len("Function"))
        count_w2 = max(max(len("{:,}".format(cnt)) for _, _, cnt, _ in ip_list), len("Count"))
        total_w2 = max(max(len(format_size(total)) for _, _, _, total in ip_list), len("Total Size"))
        
        ips_header = (f"{'IP':>{ip_col_w}}  {'Function':>{func_w2}}  {'Count':>{count_w2}}  {'Total Size':>{total_w2}}")
        ips_sep = "-" * len(ips_header)
        
        with open(ips_log_file, 'w') as ips_file:
            ips_file.write(f"# Per-IP Allocation Summary\n")
            ips_file.write(f"# Total unique IPs: {len(ip_list)}\n")
            ips_file.write(f"# Sorted by total size (descending)\n")
            ips_file.write(f"#\n")
            ips_file.write(ips_header + "\n")
            ips_file.write(ips_sep + "\n")
            for ip, func, count, total in ip_list:
                ips_file.write(f"{ip:>{ip_col_w}}  {func:>{func_w2}}  {count:>{count_w2},}  {format_size(total):>{total_w2}}\n")
            ips_file.write(ips_sep + "\n")
    
    print(f"Per-IP allocation summary saved to: {ips_log_file}")


if __name__ == "__main__":
    # Create command line argument parser
    parser = argparse.ArgumentParser(
        description='Memory allocation trace file analysis tool',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 analyze_malloc.py -i trace.malloc
  python3 analyze_malloc.py -i trace.malloc -s 2048
        """
    )
    
    # Add argument options
    parser.add_argument('-i', '--input', 
                        required=True,
                        help='Required input file path')
    
    parser.add_argument('-s', '--size',
                        type=int,
                        default=1024,
                        help='Size threshold (bytes) for power-of-2 adjustment, defaults to 1024. Sizes smaller than this will be adjusted to the nearest power of 2')
    
    # Parse arguments
    args = parser.parse_args()
    
    # Get input file path
    input_file = args.input
    
    # Get threshold
    threshold = args.size
    
    print("Starting to process memory allocation trace file...")
    print(f"Input file: {input_file}")
    print(f"Size threshold: {threshold} bytes")
    print("-" * 50)
    
    process_malloc_file(input_file, threshold)