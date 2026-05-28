#!/usr/bin/env python3
"""
Memory Allocation Trace File Analyzer — streaming version for large files

Features:
1. Single-pass streaming: never stores all events, O(active_objects) memory
2. Multi-threshold peak memory comparison across all powers of 2 from 16 up to -s
3. Per-IP allocation summary (ips.log)
4. Large-object lifecycle table (objects.log)

Usage:
    python3 analyze_malloc.py -i <input_file> [-s <threshold>]
"""

import re
import sys
import argparse
import lzma


class Tee:
    """Write to multiple file objects simultaneously."""
    def __init__(self, *files):
        self.files = files
    def write(self, obj):
        for f in self.files:
            try:
                f.write(obj)
                f.flush()
            except ValueError:
                pass
    def flush(self):
        for f in self.files:
            try:
                f.flush()
            except ValueError:
                pass


def next_power_of_2(n):
    if n <= 0:
        return 1
    if (n & (n - 1)) == 0:
        return n
    power = 1
    while power < n:
        power <<= 1
    return power


def format_size(size):
    if size >= 1024 * 1024:
        return "{:.2f} MiB".format(size / (1024 * 1024))
    elif size >= 1024:
        return "{:.2f} KiB".format(size / 1024)
    else:
        return "{} B".format(size)


class MemoryTracker:
    """Tracks active memory objects and peak memory. O(active_objects) memory."""

    def __init__(self):
        self.active_objects = {}
        self.current_memory = 0
        self.max_memory = 0

    def add_object(self, address, size):
        self.active_objects[address] = size
        self.current_memory += size
        if self.current_memory > self.max_memory:
            self.max_memory = self.current_memory

    def remove_object(self, address):
        if address in self.active_objects:
            size = self.active_objects.pop(address)
            self.current_memory -= size

    def reduce_object(self, address, length):
        if address in self.active_objects:
            current_size = self.active_objects[address]
            if length >= current_size:
                self.remove_object(address)
            else:
                self.active_objects[address] = current_size - length
                self.current_memory -= length

    def update_object(self, old_address, new_address, new_size):
        self.remove_object(old_address)
        self.add_object(new_address, new_size)

    def get_active_count(self):
        return len(self.active_objects)

    def get_current_memory_mb(self):
        return self.current_memory / (1024 * 1024)


def process_malloc_file(input_file, threshold):
    """Single-pass streaming analysis."""

    malloc_pattern = re.compile(
        r'^(?:instrCount:(\d+)\s+ip:(0x[0-9a-f]+)\s+)?(malloc)\((\d+)\)=(0x[0-9a-f]+)(?:\s+\[(new|failed)\])?$')
    calloc_pattern = re.compile(
        r'^(?:instrCount:(\d+)\s+ip:(0x[0-9a-f]+)\s+)?(calloc)\((\d+)\)=(0x[0-9a-f]+)(?:\s+\[(new|failed)\])?$')
    realloc_pattern = re.compile(
        r'^(?:instrCount:(\d+)\s+ip:(0x[0-9a-f]+)\s+)?(realloc)\((0x[0-9a-f]+),\s*(\d+)\)=(0x[0-9a-f]+|NULL)(?:\s+\[(new|in-place|moved|failed)\])?$')
    aligned_alloc_pattern = re.compile(
        r'^(?:instrCount:(\d+)\s+ip:(0x[0-9a-f]+)\s+)?(aligned_alloc)\((\d+)\)=(0x[0-9a-f]+)(?:\s+\[(new|failed)\])?$')
    memalign_pattern = re.compile(
        r'^(?:instrCount:(\d+)\s+ip:(0x[0-9a-f]+)\s+)?(memalign)\((\d+)\)=(0x[0-9a-f]+)(?:\s+\[(new|failed)\])?$')
    posix_memalign_pattern = re.compile(
        r'^(?:instrCount:(\d+)\s+ip:(0x[0-9a-f]+)\s+)?(posix_memalign)\((\d+)\)=(0x[0-9a-f]+)$')
    mmap_pattern = re.compile(
        r'^(?:instrCount:(\d+)\s+ip:(0x[0-9a-f]+)\s+)?(app_mmap)\((\d+)\)=(0x[0-9a-f]+)$')
    free_pattern = re.compile(
        r'^(?:instrCount:(\d+)\s+ip:(0x[0-9a-f]+)\s+)?free\((0x[0-9a-f]+)\)$')
    munmap_pattern = re.compile(
        r'^(?:instrCount:(\d+)\s+ip:(0x[0-9a-f]+)\s+)?app_munmap\((0x[0-9a-f]+),\s*(\d+)\)$')

    total_count = 0
    modified_count = 0
    ip_info = {}

    def track_ip(ip, func, size):
        if ip not in ip_info:
            ip_info[ip] = {'func': func, 'count': 0, 'total_size': 0}
        ip_info[ip]['count'] += 1
        ip_info[ip]['total_size'] += size

    func_stats = {
        'malloc': 0, 'calloc': 0, 'realloc': 0, 'aligned_alloc': 0,
        'memalign': 0, 'posix_memalign': 0, 'app_mmap': 0, 'free': 0, 'app_munmap': 0
    }

    thresholds_list = []
    t = 16
    while t <= threshold:
        thresholds_list.append(t)
        t <<= 1

    tracker_original = MemoryTracker()
    threshold_trackers = {t: MemoryTracker() for t in thresholds_list}
    threshold_modified_counts = {t: 0 for t in thresholds_list}
    tracker_single = threshold_trackers[threshold] if threshold in threshold_trackers else MemoryTracker()
    # Remove threshold from thresholds_list to avoid double-counting (tracker_single handles it)
    if threshold in threshold_trackers:
        del thresholds_list[thresholds_list.index(threshold)]

    large_objects_info = {}

    # Detect .xz compression and open accordingly
    if input_file.endswith('.xz'):
        open_func = lzma.open
        base_name = input_file[:-3]  # strip .xz for log file names
    else:
        open_func = open
        base_name = input_file

    with open_func(input_file, 'rt') as infile:
        for line in infile:
            line = line.strip()

            # ---- malloc ----
            match = malloc_pattern.match(line)
            if match:
                total_count += 1
                func_stats['malloc'] += 1
                instr_cnt = int(match.group(1)) if match.group(1) else 0
                alloc_ip = match.group(2) if match.group(2) else "0x0"
                func_name = match.group(3)
                original_size = int(match.group(4))
                address = match.group(5)
                single_size = original_size
                if original_size < threshold:
                    new_sz = next_power_of_2(original_size)
                    if new_sz != original_size:
                        modified_count += 1
                        single_size = new_sz
                track_ip(alloc_ip, func_name, original_size)
                tracker_original.add_object(address, original_size)
                tracker_single.add_object(address, single_size)
                for t in thresholds_list:
                    if original_size < t:
                        new_sz = next_power_of_2(original_size)
                        threshold_trackers[t].add_object(address, new_sz)
                        if new_sz != original_size:
                            threshold_modified_counts[t] += 1
                    else:
                        threshold_trackers[t].add_object(address, original_size)
                if single_size >= threshold:
                    large_objects_info[address] = {
                        'func': func_name, 'alloc_ip': alloc_ip, 'alloc_instr': instr_cnt,
                        'size': single_size, 'original_size': original_size,
                        'free_instr': None, 'free_ip': None, 'trace_line': line}
                continue

            # ---- calloc ----
            match = calloc_pattern.match(line)
            if match:
                total_count += 1
                func_stats['calloc'] += 1
                instr_cnt = int(match.group(1)) if match.group(1) else 0
                alloc_ip = match.group(2) if match.group(2) else "0x0"
                func_name = match.group(3)
                original_size = int(match.group(4))
                address = match.group(5)
                single_size = original_size
                if original_size < threshold:
                    new_sz = next_power_of_2(original_size)
                    if new_sz != original_size:
                        modified_count += 1
                        single_size = new_sz
                track_ip(alloc_ip, func_name, original_size)
                tracker_original.add_object(address, original_size)
                tracker_single.add_object(address, single_size)
                for t in thresholds_list:
                    if original_size < t:
                        new_sz = next_power_of_2(original_size)
                        threshold_trackers[t].add_object(address, new_sz)
                        if new_sz != original_size:
                            threshold_modified_counts[t] += 1
                    else:
                        threshold_trackers[t].add_object(address, original_size)
                if single_size >= threshold:
                    large_objects_info[address] = {
                        'func': func_name, 'alloc_ip': alloc_ip, 'alloc_instr': instr_cnt,
                        'size': single_size, 'original_size': original_size,
                        'free_instr': None, 'free_ip': None, 'trace_line': line}
                continue

            # ---- realloc ----
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
                single_size = original_size
                if original_size < threshold:
                    new_sz = next_power_of_2(original_size)
                    if new_sz != original_size:
                        modified_count += 1
                        single_size = new_sz
                if address_new != "NULL":
                    track_ip(alloc_ip, func_name, original_size)
                    tracker_original.update_object(address_old, address_new, original_size)
                    tracker_single.update_object(address_old, address_new, single_size)
                    for t in thresholds_list:
                        if original_size < t:
                            new_sz = next_power_of_2(original_size)
                            threshold_trackers[t].update_object(address_old, address_new, new_sz)
                            if new_sz != original_size:
                                threshold_modified_counts[t] += 1
                        else:
                            threshold_trackers[t].update_object(address_old, address_new, original_size)
                    old_info = large_objects_info.pop(address_old, {})
                    if single_size >= threshold:
                        large_objects_info[address_new] = {
                            'func': func_name, 'alloc_ip': old_info.get('alloc_ip', alloc_ip),
                            'alloc_instr': old_info.get('alloc_instr', instr_cnt),
                            'size': single_size, 'original_size': original_size,
                            'free_instr': None, 'free_ip': None, 'trace_line': line}
                continue

            # ---- aligned_alloc ----
            match = aligned_alloc_pattern.match(line)
            if match:
                total_count += 1
                func_stats['aligned_alloc'] += 1
                instr_cnt = int(match.group(1)) if match.group(1) else 0
                alloc_ip = match.group(2) if match.group(2) else "0x0"
                func_name = match.group(3)
                original_size = int(match.group(4))
                address = match.group(5)
                single_size = original_size
                if original_size < threshold:
                    new_sz = next_power_of_2(original_size)
                    if new_sz != original_size:
                        modified_count += 1
                        single_size = new_sz
                track_ip(alloc_ip, func_name, original_size)
                tracker_original.add_object(address, original_size)
                tracker_single.add_object(address, single_size)
                for t in thresholds_list:
                    if original_size < t:
                        new_sz = next_power_of_2(original_size)
                        threshold_trackers[t].add_object(address, new_sz)
                        if new_sz != original_size:
                            threshold_modified_counts[t] += 1
                    else:
                        threshold_trackers[t].add_object(address, original_size)
                if single_size >= threshold:
                    large_objects_info[address] = {
                        'func': func_name, 'alloc_ip': alloc_ip, 'alloc_instr': instr_cnt,
                        'size': single_size, 'original_size': original_size,
                        'free_instr': None, 'free_ip': None, 'trace_line': line}
                continue

            # ---- memalign ----
            match = memalign_pattern.match(line)
            if match:
                total_count += 1
                func_stats['memalign'] += 1
                instr_cnt = int(match.group(1)) if match.group(1) else 0
                alloc_ip = match.group(2) if match.group(2) else "0x0"
                func_name = match.group(3)
                original_size = int(match.group(4))
                address = match.group(5)
                single_size = original_size
                if original_size < threshold:
                    new_sz = next_power_of_2(original_size)
                    if new_sz != original_size:
                        modified_count += 1
                        single_size = new_sz
                track_ip(alloc_ip, func_name, original_size)
                tracker_original.add_object(address, original_size)
                tracker_single.add_object(address, single_size)
                for t in thresholds_list:
                    if original_size < t:
                        new_sz = next_power_of_2(original_size)
                        threshold_trackers[t].add_object(address, new_sz)
                        if new_sz != original_size:
                            threshold_modified_counts[t] += 1
                    else:
                        threshold_trackers[t].add_object(address, original_size)
                if single_size >= threshold:
                    large_objects_info[address] = {
                        'func': func_name, 'alloc_ip': alloc_ip, 'alloc_instr': instr_cnt,
                        'size': single_size, 'original_size': original_size,
                        'free_instr': None, 'free_ip': None, 'trace_line': line}
                continue

            # ---- posix_memalign ----
            match = posix_memalign_pattern.match(line)
            if match:
                total_count += 1
                func_stats['posix_memalign'] += 1
                instr_cnt = int(match.group(1)) if match.group(1) else 0
                alloc_ip = match.group(2) if match.group(2) else "0x0"
                func_name = match.group(3)
                original_size = int(match.group(4))
                address = match.group(5)
                single_size = original_size
                if original_size < threshold:
                    new_sz = next_power_of_2(original_size)
                    if new_sz != original_size:
                        modified_count += 1
                        single_size = new_sz
                track_ip(alloc_ip, func_name, original_size)
                tracker_original.add_object(address, original_size)
                tracker_single.add_object(address, single_size)
                for t in thresholds_list:
                    if original_size < t:
                        new_sz = next_power_of_2(original_size)
                        threshold_trackers[t].add_object(address, new_sz)
                        if new_sz != original_size:
                            threshold_modified_counts[t] += 1
                    else:
                        threshold_trackers[t].add_object(address, original_size)
                continue

            # ---- app_mmap ----
            match = mmap_pattern.match(line)
            if match:
                total_count += 1
                func_stats['app_mmap'] += 1
                instr_cnt = int(match.group(1)) if match.group(1) else 0
                alloc_ip = match.group(2) if match.group(2) else "0x0"
                func_name = match.group(3)
                original_size = int(match.group(4))
                address = match.group(5)
                single_size = original_size
                if original_size < threshold:
                    new_sz = next_power_of_2(original_size)
                    if new_sz != original_size:
                        modified_count += 1
                        single_size = new_sz
                track_ip(alloc_ip, func_name, original_size)
                tracker_original.add_object(address, original_size)
                tracker_single.add_object(address, single_size)
                for t in thresholds_list:
                    if original_size < t:
                        new_sz = next_power_of_2(original_size)
                        threshold_trackers[t].add_object(address, new_sz)
                        if new_sz != original_size:
                            threshold_modified_counts[t] += 1
                    else:
                        threshold_trackers[t].add_object(address, original_size)
                if single_size >= threshold:
                    large_objects_info[address] = {
                        'func': func_name, 'alloc_ip': alloc_ip, 'alloc_instr': instr_cnt,
                        'size': single_size, 'original_size': original_size,
                        'free_instr': None, 'free_ip': None, 'trace_line': line}
                continue

            # ---- free ----
            match = free_pattern.match(line)
            if match:
                func_stats['free'] += 1
                instr_cnt = int(match.group(1)) if match.group(1) else 0
                free_ip = match.group(2) if match.group(2) else "0x0"
                address = match.group(3)
                tracker_original.remove_object(address)
                tracker_single.remove_object(address)
                for t in thresholds_list:
                    threshold_trackers[t].remove_object(address)
                if address in large_objects_info:
                    large_objects_info[address]['free_instr'] = instr_cnt
                    large_objects_info[address]['free_ip'] = free_ip
                continue

            # ---- app_munmap ----
            match = munmap_pattern.match(line)
            if match:
                func_stats['app_munmap'] += 1
                instr_cnt = int(match.group(1)) if match.group(1) else 0
                munmap_ip = match.group(2) if match.group(2) else "0x0"
                address = match.group(3)
                length = int(match.group(4))
                tracker_original.reduce_object(address, length)
                tracker_single.reduce_object(address, length)
                for t in thresholds_list:
                    threshold_trackers[t].reduce_object(address, length)
                if address in large_objects_info:
                    if address not in tracker_original.active_objects:
                        large_objects_info[address]['free_instr'] = instr_cnt
                        large_objects_info[address]['free_ip'] = munmap_ip
                continue

    # ---- Statistics ----
    original_peak = tracker_original.max_memory
    print(f"Processing complete!")
    print(f"Total {total_count:,} memory allocation calls found")
    print(f"Using threshold {threshold}: modified {modified_count} size parameters")
    print(f"\n=== Function Call Statistics ===")
    print(f"{'Function':<20} {'Count':>10} {'Percentage':>12}")
    print(f"{'-'*20} {'-'*10} {'-'*12}")
    alloc_funcs = ['malloc', 'calloc', 'realloc', 'aligned_alloc', 'memalign', 'posix_memalign', 'app_mmap']
    alloc_total = sum(func_stats[f] for f in alloc_funcs)
    for f in alloc_funcs:
        c = func_stats[f]
        pct = (c / total_count * 100) if total_count > 0 else 0
        print(f"{f:<20} {c:>10,} {pct:>11.2f}%")
    print(f"{'-'*20} {'-'*10} {'-'*12}")
    print(f"{'Total Alloc':<20} {alloc_total:>10,} {(alloc_total/total_count*100) if total_count > 0 else 0:>11.2f}%")
    print()
    dealloc_funcs = ['free', 'app_munmap']
    dealloc_total = sum(func_stats[f] for f in dealloc_funcs)
    for f in dealloc_funcs:
        c = func_stats[f]
        pct = (c / total_count * 100) if total_count > 0 else 0
        print(f"{f:<20} {c:>10,} {pct:>11.2f}%")
    print(f"{'-'*20} {'-'*10} {'-'*12}")
    print(f"{'Total Dealloc':<20} {dealloc_total:>10,} {(dealloc_total/total_count*100) if total_count > 0 else 0:>11.2f}%")
    print()

    # ---- Multi-threshold peak ----
    print(f"\n=== Multi-Threshold Peak Memory Comparison ===")
    print(f"Original peak: {format_size(original_peak)} ({original_peak:,} bytes)")
    print(f"Total alloc calls: {total_count:,}\n")
    hdr = f"{'Threshold':>10}  {'Modified Peak':>15}  {'Increase':>15}  {'Increase %':>11}  {'Mod Objects':>13}  {'Mod %':>8}"
    sep = f"{'-'*10}  {'-'*15}  {'-'*15}  {'-'*11}  {'-'*13}  {'-'*8}"
    print(hdr)
    print(sep)
    for t in thresholds_list:
        mod_peak = threshold_trackers[t].max_memory
        increase = mod_peak - original_peak
        pct = (increase / original_peak * 100) if original_peak > 0 else 0
        mod_cnt = threshold_modified_counts[t]
        mod_pct = (mod_cnt / total_count * 100) if total_count > 0 else 0
        print(f"{t:>10,}  {format_size(mod_peak):>15}  {format_size(increase):>15}  {pct:>10.2f}%  {mod_cnt:>13,}  {mod_pct:>7.2f}%")
    print(sep)
    single_peak = tracker_single.max_memory
    single_increase = single_peak - original_peak
    single_pct = (single_increase / original_peak * 100) if original_peak > 0 else 0
    print(f"\nUsing -s {threshold}:")
    print(f"  Original peak:  {format_size(original_peak)} ({original_peak:,} bytes)")
    print(f"  Modified peak:  {format_size(single_peak)} ({single_peak:,} bytes)")
    print(f"  Increase:       {format_size(single_increase)} ({single_increase:,} bytes, {single_pct:.2f}%)")
    print(f"\n=== Final State Statistics (using -s {threshold}) ===")
    print(f"Final active object count: {tracker_single.get_active_count():,}")
    print(f"Final memory usage:    {tracker_single.get_current_memory_mb():.2f} MB ({tracker_single.current_memory:,} bytes)")

    # ---- objects.log ----
    objects_log_file = base_name + ".objects.log"
    large_objects_list = [(a, i) for a, i in large_objects_info.items()]
    large_objects_list.sort(key=lambda x: x[1]['size'], reverse=True)
    if large_objects_list:
        max_func_len = max(len(i['func']) for _, i in large_objects_list)
        max_addr_len = max(len(a) for a, _ in large_objects_list)
        max_ip_len = max(len(i['alloc_ip']) for _, i in large_objects_list)
        max_free_ip_len = max((len(i['free_ip']) if i['free_ip'] else 2) for _, i in large_objects_list)
        max_size_str_len = max(len(format_size(i['size'])) for _, i in large_objects_list)
        max_orig_size_str_len = max(len(format_size(i['original_size'])) for _, i in large_objects_list)
        max_alloc_instr_len = 0
        max_free_instr_len = 2
        max_life_str_len = 3
        for _, i in large_objects_list:
            alloc_str = "{:,}".format(i['alloc_instr'])
            max_alloc_instr_len = max(max_alloc_instr_len, len(alloc_str))
            if i['free_instr'] is not None:
                free_str = "{:,}".format(i['free_instr'])
                max_free_instr_len = max(max_free_instr_len, len(free_str))
                lifetime = i['free_instr'] - i['alloc_instr']
                life_str = "{:,}".format(lifetime)
                max_life_str_len = max(max_life_str_len, len(life_str))
    else:
        max_func_len = max_addr_len = max_ip_len = 10
        max_free_ip_len = 8
        max_size_str_len = max_orig_size_str_len = 8
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
        obj_file.write(f"# Sorted by modified size (descending)\n#\n")
        obj_file.write(header + "\n" + separator + "\n")
        for addr, info in large_objects_list:
            f = info['func']; aip = info['alloc_ip']; ai = info['alloc_instr']
            ms = info['size']; os = info['original_size']; fi = info['free_instr']; fp = info['free_ip']
            if fi is not None:
                lifetime = fi - ai; status = "FREED"
                total_lifetime += lifetime; freed_count += 1
            else:
                lifetime = 0; status = "ACTIVE"; fp = "--"; fi = 0
            lifetime_str = "{:,}".format(lifetime) if info['free_instr'] is not None else "N/A"
            fp_str = fp if fp else "--"
            fi_str = "{:,}".format(fi) if info['free_instr'] is not None else "--"
            obj_file.write(
                f"{f:>{func_w}}  {addr:>{addr_w}}  {aip:>{ip_w}}  {ai:>{alloc_instr_w},}  "
                f"{fp_str:>{free_ip_w}}  {fi_str:>{free_instr_w}}  {lifetime_str:>{life_w}}  "
                f"{format_size(os):>{orig_size_w}}  {format_size(ms):>{size_w}}  {status:>{status_w}}\n")
        obj_file.write(separator + "\n")
        avg_lifetime = total_lifetime // freed_count if freed_count > 0 else 0
        obj_file.write(f"# Freed objects: {freed_count}, Average lifetime: {avg_lifetime:,} instructions\n")
        obj_file.write(f"# Still active: {len(large_objects_list) - freed_count}\n")
    print(f"\nLarge objects log saved to: {objects_log_file}")
    print(f"Total large objects (modified size >= {threshold} bytes): {len(large_objects_list):,}")

    # ---- ips.log ---
    ips_log_file = base_name + ".ips.log"
    if ip_info:
        ip_list = [(ip, i['func'], i['count'], i['total_size']) for ip, i in ip_info.items()]
        ip_list.sort(key=lambda x: x[3], reverse=True)
        ip_col_w = max(max(len(ip) for ip, _, _, _ in ip_list), len("IP"))
        func_w2 = max(max(len(func) for _, func, _, _ in ip_list), len("Function"))
        count_w2 = max(max(len("{:,}".format(cnt)) for _, _, cnt, _ in ip_list), len("Count"))
        total_w2 = max(max(len(format_size(total)) for _, _, _, total in ip_list), len("Total Size"))
        ips_header = f"{'IP':>{ip_col_w}}  {'Function':>{func_w2}}  {'Count':>{count_w2}}  {'Total Size':>{total_w2}}"
        ips_sep = "-" * len(ips_header)
        with open(ips_log_file, 'w') as ips_file:
            ips_file.write(f"# Per-IP Allocation Summary\n")
            ips_file.write(f"# Total unique IPs: {len(ip_list)}\n")
            ips_file.write(f"# Sorted by total size (descending)\n#\n")
            ips_file.write(ips_header + "\n" + ips_sep + "\n")
            for ip, func, count, total in ip_list:
                ips_file.write(f"{ip:>{ip_col_w}}  {func:>{func_w2}}  {count:>{count_w2},}  {format_size(total):>{total_w2}}\n")
            ips_file.write(ips_sep + "\n")
    print(f"Per-IP allocation summary saved to: {ips_log_file}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description='Memory allocation trace file analyzer — streaming version',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="Examples:\n  python3 analyze_malloc.py -i trace.malloc\n  python3 analyze_malloc.py -i trace.malloc -s 2048")
    parser.add_argument('-i', '--input', required=True, help='Input trace file')
    parser.add_argument('-s', '--size', type=int, default=1024,
                        help='Size threshold for power-of-2 adjustment (default: 1024)')
    args = parser.parse_args()
    
    # Determine base name for log files
    if args.input.endswith('.xz'):
        base_name = args.input[:-3]
    else:
        base_name = args.input
    
    result_log = open(base_name + ".result.log", "w")
    original_stdout = sys.stdout
    sys.stdout = Tee(original_stdout, result_log)
    
    print("Starting to process memory allocation trace file...")
    print(f"Input file: {args.input}")
    print(f"Size threshold: {args.size} bytes")
    print("-" * 50)
    process_malloc_file(args.input, args.size)
    
    result_log.close()
