#!/usr/bin/env python3
"""
Memory Allocation Trace File Analyzer — binary version

Reads the binary malloc.bin (40-byte malloc_instr records), then produces:

1. Single-pass streaming analysis of active memory with true dynamic peak
2. Multi-threshold peak memory comparison across powers of 2 (8, 16, 32, 64, 128, 256, 512, 1024)
3. Per-IP allocation summary (ips.log)
4. Large-object lifecycle table (objects.log)

Usage:
    python3 analyze_malloc.py -i <malloc.bin> [-s <threshold>] [-v]
"""

import struct
import sys
import os
import lzma
import argparse


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


# malloc_instr binary layout (40 bytes total):
#   uint64_t ip        (offset 0)
#   uint64_t arg1      (offset 8)
#   uint64_t arg2      (offset 16)
#   uint64_t ret       (offset 24)
#   uint8_t  type      (offset 32)
#   uint8_t  reserved[7](offset 33)
MALLOC_INSTR_FMT = '<QQQQBBBBBBBB'  # 4*uint64 + 8*uint8 = 32+8=40
MALLOC_INSTR_SIZE = 40

# type -> function name mapping
TYPE_MAP = {
    1: 'malloc',
    2: 'free',
    3: 'app_mmap',
    4: 'app_munmap',
    5: 'calloc',
    6: 'realloc',
    7: 'aligned_alloc',
    8: 'posix_memalign',
    9: 'memalign',
}


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
        """Partially or fully remove an object (used by munmap with length)."""
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


def read_malloc_binary(infile_path):
    """Generator that yields (seq_id, ip, type, arg1, arg2, ret) tuples from binary file.
       Supports .xz compressed files automatically."""
    seq_id = 0
    open_func = lzma.open if infile_path.endswith('.xz') else open
    with open_func(infile_path, 'rb') as f:
        while True:
            chunk = f.read(MALLOC_INSTR_SIZE)
            if len(chunk) < MALLOC_INSTR_SIZE:
                break
            fields = struct.unpack(MALLOC_INSTR_FMT, chunk)
            ip = fields[0]
            arg1 = fields[1]
            arg2 = fields[2]
            ret = fields[3]
            etype = fields[4]
            seq_id += 1
            yield seq_id, ip, etype, arg1, arg2, ret


def process_malloc_binary(input_file, threshold):
    """Streaming analysis of binary malloc trace."""

    # Determine base name for log files
    base_name = os.path.splitext(input_file)[0]  # strip .bin
    if base_name.endswith('.malloc'):
        base_name = base_name[:-7]

    func_stats = {
        'malloc': 0, 'calloc': 0, 'realloc': 0, 'aligned_alloc': 0,
        'memalign': 0, 'posix_memalign': 0, 'app_mmap': 0, 'free': 0, 'app_munmap': 0
    }

    total_big_count = 0
    ip_info = {}

    def track_ip(ip, func, size):
        s = hex(ip) if ip else "0x0"
        if s not in ip_info:
            ip_info[s] = {'func': func, 'count': 0, 'total_size': 0}
        ip_info[s]['count'] += 1
        ip_info[s]['total_size'] += size

    # Read all records (no header/tail in object_tracer format)
    normal_records = list(read_malloc_binary(input_file))

    thresholds_list = []
    t = next_power_of_2(16)
    while t <= threshold:
        thresholds_list.append(t)
        t <<= 1

    tracker_original = MemoryTracker()
    threshold_trackers = {t: MemoryTracker() for t in thresholds_list}
    threshold_modified_counts = {t: 0 for t in thresholds_list}
    tracker_single = threshold_trackers.get(threshold, MemoryTracker())

    # Dedicated tracker for the effective k threshold (8).
    # Objects < 8 are stored at aligned size, objects >= 8 at original size.
    k_threshold = 8
    tracker_k = MemoryTracker()

    # Per-object modification tracking: maps address -> set of thresholds
    # at which this object has already been counted as "modified".
    # FIX: prevents realloc from incrementing threshold_modified_counts
    # multiple times for the same object.
    object_modified_at = {}

    large_objects_info = {}

    # Process all records
    print("-" * 50)
    print("Processing binary malloc trace...")

    for seq_id, ip, etype, arg1, arg2, ret in normal_records:

        func_name = TYPE_MAP.get(etype, 'unknown')
        ip_str = hex(ip) if ip else "0x0"

        if etype in (1, 3, 5, 7, 8, 9):
            # Allocation types: arg1=size, ret=address
            total_big_count += 1
            func_stats[func_name] += 1
            original_size = arg1
            address = ret
            single_size = original_size

            if original_size < threshold:
                new_sz = next_power_of_2(original_size)
                single_size = new_sz

            track_ip(ip, func_name, original_size)
            tracker_original.add_object(address, original_size)
            tracker_single.add_object(address, single_size)

            # Initialize modification tracking for this object
            object_modified_at[address] = set()

            # k-threshold tracker: objects < k use aligned size, >= k use raw size
            if original_size < k_threshold:
                tracker_k.add_object(address, next_power_of_2(original_size))
            else:
                tracker_k.add_object(address, original_size)

            for t in thresholds_list:
                if t == threshold:
                    continue  # tracker_single already handles this threshold
                if original_size < t:
                    new_sz = next_power_of_2(original_size)
                    threshold_trackers[t].add_object(address, new_sz)
                    threshold_modified_counts[t] += 1
                    object_modified_at[address].add(t)
                else:
                    threshold_trackers[t].add_object(address, original_size)

            if single_size >= threshold:
                large_objects_info[address] = {
                    'func': func_name, 'alloc_ip': ip_str, 'alloc_instr': seq_id,
                    'size': single_size, 'original_size': original_size,
                    'free_instr': None, 'free_ip': None}

        elif etype == 6:
            # realloc: arg1=old_ptr, arg2=size, ret=new_ptr (0=fail)
            total_big_count += 1
            func_stats[func_name] += 1
            old_ptr = arg1
            original_size = arg2
            address_new = ret
            single_size = original_size

            if original_size < threshold:
                new_sz = next_power_of_2(original_size)
                single_size = new_sz

            if ret != 0:
                track_ip(ip, func_name, original_size)
                tracker_original.update_object(old_ptr, address_new, original_size)
                tracker_single.update_object(old_ptr, address_new, single_size)

                # k-threshold tracker: objects < k use aligned size, >= k use raw size
                if original_size < k_threshold:
                    tracker_k.update_object(old_ptr, address_new, next_power_of_2(original_size))
                else:
                    tracker_k.update_object(old_ptr, address_new, original_size)

                # Inherit old modification set, create new one for new address
                old_modified_set = object_modified_at.pop(old_ptr, set())
                object_modified_at[address_new] = set()

                for t in thresholds_list:
                    if t == threshold:
                        continue  # tracker_single already handled at line 261
                    if original_size < t:
                        new_sz = next_power_of_2(original_size)
                        threshold_trackers[t].update_object(old_ptr, address_new, new_sz)
                        # Only count if this object hasn't already been counted at this threshold
                        if t not in old_modified_set:
                            threshold_modified_counts[t] += 1
                            object_modified_at[address_new].add(t)
                        else:
                            object_modified_at[address_new].add(t)
                    else:
                        threshold_trackers[t].update_object(old_ptr, address_new, original_size)
                        # If the object grows above threshold, it's no longer "modified" at this t
                        # Keep the historical marks that still apply

                old_info = large_objects_info.pop(old_ptr, {})
                if single_size >= threshold:
                    large_objects_info[address_new] = {
                        'func': func_name, 'alloc_ip': old_info.get('alloc_ip', ip_str),
                        'alloc_instr': old_info.get('alloc_instr', seq_id),
                        'size': single_size, 'original_size': original_size,
                        'free_instr': None, 'free_ip': None}

        elif etype == 2:
            # free: arg1=ptr
            func_stats[func_name] += 1
            address = arg1
            tracker_original.remove_object(address)
            tracker_single.remove_object(address)
            tracker_k.remove_object(address)
            for t in thresholds_list:
                threshold_trackers[t].remove_object(address)
            if address in object_modified_at:
                del object_modified_at[address]
            if address in large_objects_info:
                large_objects_info[address]['free_instr'] = seq_id
                large_objects_info[address]['free_ip'] = ip_str

        elif etype == 4:
            # munmap: arg1=addr, arg2=length
            func_stats[func_name] += 1
            address = arg1
            length = arg2
            tracker_original.reduce_object(address, length)
            tracker_single.reduce_object(address, length)
            tracker_k.reduce_object(address, length)
            for t in thresholds_list:
                threshold_trackers[t].reduce_object(address, length)
            # Mark large object as freed only if it's completely removed from tracking
            if address in large_objects_info:
                if address not in tracker_original.active_objects:
                    large_objects_info[address]['free_instr'] = seq_id
                    large_objects_info[address]['free_ip'] = ip_str
                if address in object_modified_at and address not in tracker_original.active_objects:
                    del object_modified_at[address]

    total_count = total_big_count

    # ---- Statistics ----
    # Original peak: dynamic max from time-ordered tracking of all objects.
    # k-aligned peak: tracker_k handles alignment for objects < 128.
    original_peak = tracker_original.max_memory
    k_aligned_peak_raw = tracker_k.max_memory
    k_aligned_peak = k_aligned_peak_raw

    print(f"\nProcessing complete!")
    print(f"Total {total_count:,} allocation calls in trace")
    print(f"  Effective k-threshold: {k_threshold} bytes")
    print(f"Using threshold {threshold}: adjusted big objects < threshold to next power of 2")
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
    # FIX: All peaks computed purely from dynamic time-ordered tracking.
    # Each threshold tracker maintains its own active_objects with the appropriate
    # aligned or original sizes for objects crossing that threshold.
    print(f"\n=== Multi-Threshold Peak Memory Comparison ===")
    print(f"Original peak (all objects at raw size): {format_size(original_peak)} ({original_peak:,} bytes)")
    print(f"Total alloc calls: {total_count:,}\n")

    hdr = f"{'Threshold':>10}  {'Aligned Peak':>15}  {'Increase':>15}  {'Increase %':>11}  {'Mod Objects':>13}"
    sep = f"{'-'*10}  {'-'*15}  {'-'*15}  {'-'*11}  {'-'*13}"
    print(hdr)
    print(sep)

    # First row: k threshold (actual threshold from file header).
    # k_aligned_peak includes: large objects at aligned sizes (tracker_k) + little objects aligned total.
    k_increase = k_aligned_peak - original_peak
    k_pct = (k_increase / original_peak * 100) if original_peak > 0 else 0.0
    print(f"{k_threshold:>10,}  {format_size(k_aligned_peak):>15}  {format_size(k_increase):>15}  "
          f"{k_pct:>10.2f}%  N/A           ")

    # Subsequent rows: power-of-2 thresholds (2*k, 4*k, ...)
    for t in sorted(thresholds_list):
        mod_peak = threshold_trackers[t].max_memory
        increase = mod_peak - original_peak
        pct = (increase / original_peak * 100) if original_peak > 0 else 0
        mod_cnt = threshold_modified_counts[t]
        print(f"{t:>10,}  {format_size(mod_peak):>15}  {format_size(increase):>15}  {pct:>10.2f}%  {mod_cnt:>13,}")
    print(sep)

    single_peak = tracker_single.max_memory
    single_increase = single_peak - original_peak
    single_pct = (single_increase / original_peak * 100) if original_peak > 0 else 0
    print(f"\nUsing -s {threshold}:")
    print(f"  Original peak:  {format_size(original_peak)} ({original_peak:,} bytes)")
    print(f"  Aligned peak:   {format_size(single_peak)} ({single_peak:,} bytes)")
    print(f"  Increase:       {format_size(single_increase)} ({single_increase:,} bytes, {single_pct:.2f}%)")
    print(f"\n=== Final State Statistics (using -s {threshold}) ===")
    print(f"Final active object count: {tracker_single.get_active_count():,}")
    print(f"Final memory usage:        {tracker_single.get_current_memory_mb():.2f} MB ({tracker_single.current_memory:,} bytes)")

    # ---- objects.log ----
    objects_log_file = base_name + ".objects.log"
    large_objects_list = [(a, i) for a, i in large_objects_info.items()]
    large_objects_list.sort(key=lambda x: x[1]['size'], reverse=True)
    if large_objects_list:
        max_func_len = max(len(i['func']) for _, i in large_objects_list)
        max_addr_len = max(len(hex(a)) for a, _ in large_objects_list)
        max_ip_len = max(len(i['alloc_ip']) for _, i in large_objects_list)
        max_size_str_len = max(len(format_size(i['size'])) for _, i in large_objects_list)
        max_orig_size_str_len = max(len(format_size(i['original_size'])) for _, i in large_objects_list)
    else:
        max_func_len = max_addr_len = max_ip_len = 10
        max_size_str_len = max_orig_size_str_len = 8

    func_w = max(max_func_len, len("Function"))
    addr_w = max(max_addr_len, len("Address"))
    ip_w = max(max_ip_len, len("Alloc IP"))
    size_w = max(max_size_str_len, len("Mod Size"))
    orig_size_w = max(max_orig_size_str_len, len("Orig Size"))
    status_w = max(8, len("Status"))

    header = (f"{'Function':>{func_w}}  {'Address':>{addr_w}}  {'Alloc IP':>{ip_w}}  "
              f"{'Orig Size':>{orig_size_w}}  {'Mod Size':>{size_w}}  {'Status':>{status_w}}")
    separator = "-" * len(header)

    freed_count = 0
    with open(objects_log_file, 'w') as obj_file:
        obj_file.write(f"# Active/Large Memory Objects (modified size >= {threshold} bytes)\n")
        obj_file.write(f"# Total objects: {len(large_objects_list)}\n")
        obj_file.write(f"# Sorted by modified size (descending)\n#\n")
        obj_file.write(header + "\n" + separator + "\n")
        for addr, info in large_objects_list:
            f = info['func']; aip = info['alloc_ip']
            ms = info['size']; orig_sz = info['original_size']; fi = info['free_instr']
            addr_str = hex(addr)
            if fi is not None:
                status = "FREED"
                freed_count += 1
            else:
                status = "ACTIVE"
            obj_file.write(
                f"{f:>{func_w}}  {addr_str:>{addr_w}}  {aip:>{ip_w}}  "
                f"{format_size(orig_sz):>{orig_size_w}}  {format_size(ms):>{size_w}}  {status:>{status_w}}\n")
        obj_file.write(separator + "\n")
        obj_file.write(f"# Freed objects: {freed_count}, Still active: {len(large_objects_list) - freed_count}\n")
    print(f"\nLarge objects log saved to: {objects_log_file}")
    print(f"Total large objects (modified size >= {threshold} bytes): {len(large_objects_list):,}")

    # ---- ips.log ---
    ips_log_file = base_name + ".ips.log"
    if ip_info:
        ip_list = [(ip, i['func'], i['count'], i['total_size']) for ip, i in ip_info.items()]
        ip_list.sort(key=lambda x: x[2], reverse=True)  # sort by count descending
        ip_list_with_avg = [(ip, func, cnt, total, total // cnt if cnt > 0 else 0) for ip, func, cnt, total in ip_list]

        ip_col_w = max(max(len(ip) for ip, _, _, _, _ in ip_list_with_avg), len("IP"))
        func_w2 = max(max(len(func) for _, func, _, _, _ in ip_list_with_avg), len("Function"))
        count_w2 = max(max(len("{:,}".format(cnt)) for _, _, cnt, _, _ in ip_list_with_avg), len("Count"))
        total_w2 = max(max(len(format_size(total)) for _, _, _, total, _ in ip_list_with_avg), len("Total Size"))
        avg_w2 = max(max(len(format_size(avg)) for _, _, _, _, avg in ip_list_with_avg), len("Avg Size"))
        ips_header = f"{'IP':>{ip_col_w}}  {'Function':>{func_w2}}  {'Count':>{count_w2}}  {'Avg Size':>{avg_w2}}  {'Total Size':>{total_w2}}"
        ips_sep = "-" * len(ips_header)
        with open(ips_log_file, 'w') as ips_file:
            ips_file.write(f"# Per-IP Allocation Summary (all objects)\n")
            ips_file.write(f"# Total unique IPs: {len(ip_list)}\n")
            ips_file.write(f"# Sorted by count (descending)\n#\n")
            ips_file.write(ips_header + "\n" + ips_sep + "\n")
            for ip, func, count, total, avg in ip_list_with_avg:
                ips_file.write(f"{ip:>{ip_col_w}}  {func:>{func_w2}}  {count:>{count_w2},}  {format_size(avg):>{avg_w2}}  {format_size(total):>{total_w2}}\n")
            ips_file.write(ips_sep + "\n")
    print(f"Per-IP allocation summary saved to: {ips_log_file}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description='Memory allocation trace file analyzer — binary version',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="Examples:\n  python3 analyze_malloc.py -i malloc.bin\n"
               "  python3 analyze_malloc.py -i malloc.bin -s 1024\n"
               "  python3 analyze_malloc.py -i malloc.bin -v")
    parser.add_argument('-i', '--input', required=True, help='Input binary malloc trace file (malloc.bin)')
    parser.add_argument('-s', '--size', type=int, default=1024,
                        help='Max size threshold for power-of-2 adjustment (default: 1024)')
    parser.add_argument('-v', '--verbose', action='store_true',
                        help='Display the contents of the input file in a readable format')
    args = parser.parse_args()

    if args.verbose:
        print("Displaying file contents: {}".format(args.input))
        print("-" * 50)
        print("{:<8} {:<20} {:<6} {:<20} {:<20} {:<20}".format(
            "Seq", "IP", "Type", "arg1", "arg2", "ret"))
        print("-" * 50)
        for seq_id, ip, etype, arg1, arg2, ret in read_malloc_binary(args.input):
            func_name = TYPE_MAP.get(etype, 'unknown')
            print("{:<8} {:<20} {:<6}({:<14}) {:<20} {:<20} {:<20}".format(
                seq_id,
                hex(ip) if ip else "0x0",
                etype,
                func_name,
                hex(arg1) if arg1 else arg1,
                hex(arg2) if arg2 else arg2,
                hex(ret) if ret else ret))
        print("-" * 50)
        sys.exit(0)

    base_name = os.path.splitext(args.input)[0]
    if base_name.endswith('.malloc'):
        base_name = base_name[:-7]

    result_log = open(base_name + ".result.log", "w")
    original_stdout = sys.stdout
    sys.stdout = Tee(original_stdout, result_log)

    print("Starting to process binary memory allocation trace...")
    print(f"Input file: {args.input}")
    print(f"Size threshold: {args.size} bytes")
    print("-" * 50)
    process_malloc_binary(args.input, args.size)

    result_log.close()