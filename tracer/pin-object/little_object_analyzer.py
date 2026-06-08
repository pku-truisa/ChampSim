#!/usr/bin/env python3
"""
高性能低内存流式 Memory Allocation Trace File Analyzer — v5 39-type scheme.
"""

import struct
import sys
import os
import glob
import lzma
import argparse
import bisect

class Tee:
    def __init__(self, *files):
        self.files = files
    def write(self, obj):
        for f in self.files:
            try: f.write(obj); f.flush()
            except ValueError: pass
    def flush(self):
        for f in self.files:
            try: f.flush()
            except ValueError: pass

def next_power_of_2(n):
    if n <= 0: return 1
    if (n & (n - 1)) == 0: return n
    power = 1
    while power < n: power <<= 1
    return power

def format_size(size):
    if size >= 1024 * 1024 * 1024:
        return "{:.2f} GiB".format(size / (1024 * 1024 * 1024))
    if size >= 1024 * 1024:
        return "{:.2f} MiB".format(size / (1024 * 1024))
    if size >= 1024:
        return "{:.2f} KiB".format(size / 1024)
    return "{} B".format(size)

TYPE_MAP = {
    1: 'malloc', 2: 'mi_malloc', 3: 'je_malloc', 4: 'tc_malloc',
    5: '_Znwm', 6: '_Znam',
    7: 'calloc', 8: 'mi_calloc', 9: 'je_calloc', 10: 'tc_calloc',
    11: 'realloc', 12: 'mi_realloc', 13: 'je_realloc', 14: 'tc_realloc',
    15: 'posix_memalign',
    16: 'mmap', 17: 'munmap',
    18: 'free', 19: 'mi_free', 20: 'je_free', 21: 'tc_free',
    22: '_ZdlPv', 23: '_ZdaPv',
}

_ALLOC_TYPES = set(range(1, 17))  # 1-16
_FREE_TYPES = {17}.union(set(range(18, 24)))  # 17-23

_ALLOC_GROUPS = [
    ("malloc-like",   list(range(1, 7))),
    ("calloc",        list(range(7, 11))),
    ("realloc",       list(range(11, 15))),
    ("posix_memalign", [15]),
    ("mmap",          [16]),
]
_FREE_GROUPS = [
    ("munmap",        [17]),
    ("free/delete",   list(range(18, 24))),
]

def read_malloc_binary(filename):
    is_xz = filename.endswith('.xz')
    open_func = lzma.open if is_xz else open
    fmt = "<QQQB7s"
    struct_size = struct.calcsize(fmt)
    with open_func(filename, "rb") as f:
        chunk_size = 32 * 1024 * 64
        while True:
            chunk = f.read(chunk_size)
            if not chunk: break
            offset = 0
            while offset < len(chunk):
                record = chunk[offset:offset+struct_size]
                if len(record) < struct_size: break
                arg1, arg2, ret, etype, _ = struct.unpack(fmt, record)
                yield etype, arg1, arg2, ret
                offset += struct_size

def _update_sizes_on_alloc(current_sizes, peak_sizes, threshold_object_counts, ge_counts, n, size, pow2, split_idx):
    for i in range(split_idx):
        ge_counts[i] += 1
        current_sizes[i] += size
        if current_sizes[i] > peak_sizes[i]: peak_sizes[i] = current_sizes[i]
    for i in range(split_idx, n):
        threshold_object_counts[i] += 1
        current_sizes[i] += pow2
        if current_sizes[i] > peak_sizes[i]: peak_sizes[i] = current_sizes[i]

def _update_sizes_on_free(current_sizes, ge_counts, n, old_sz, pow2, split_idx):
    for i in range(split_idx):
        ge_counts[i] -= 1
        current_sizes[i] -= old_sz
    for i in range(split_idx, n):
        current_sizes[i] -= pow2

def process_malloc_binary(filename, objects_path=None):
    func_stats = {k: 0 for k in TYPE_MAP.values()}
    active_heap = {}

    thresholds = [8, 16, 32, 64, 128, 256, 512, 1024, 2048, 4096, 8192, 16384, 32768, 65536, 131072]
    n = len(thresholds)
    current_sizes = [0] * n
    peak_sizes = [0] * n
    peak_moment_sizes = [0] * n
    threshold_object_counts = [0] * n
    current_ge_counts = [0] * n
    peak_moment_ge_counts = [0] * n

    original_current_size = 0
    original_peak_size = 0
    all_large_objects = []

    print("Streaming processing data to minimize memory footprint...")

    for etype, arg1, arg2, ret in read_malloc_binary(filename):
        func_name = TYPE_MAP.get(etype, 'unknown')

        if etype in _ALLOC_TYPES:
            func_stats[func_name] += 1
            size = arg2 if 11 <= etype <= 14 else arg1

            if ret != 0:
                if 11 <= etype <= 14 and arg1 != 0 and arg1 in active_heap:
                    old_sz = active_heap.pop(arg1)
                    original_current_size -= old_sz
                    old_pow2 = next_power_of_2(old_sz)
                    old_idx = bisect.bisect_right(thresholds, old_sz)
                    _update_sizes_on_free(current_sizes, current_ge_counts, n, old_sz, old_pow2, old_idx)

                active_heap[ret] = size
                original_current_size += size
                if size >= 32768:
                    all_large_objects.append((ret, size, func_name))

                pow2 = next_power_of_2(size)
                split_idx = bisect.bisect_right(thresholds, size)
                _update_sizes_on_alloc(current_sizes, peak_sizes, threshold_object_counts, current_ge_counts,
                                       n, size, pow2, split_idx)

                if original_current_size > original_peak_size:
                    original_peak_size = original_current_size
                    peak_moment_sizes = current_sizes.copy()
                    peak_moment_ge_counts = current_ge_counts.copy()

        elif etype in _FREE_TYPES:
            func_stats[func_name] += 1
            ptr = arg1
            if ptr in active_heap:
                old_sz = active_heap.pop(ptr)
                original_current_size -= old_sz
                old_pow2 = next_power_of_2(old_sz)
                old_idx = bisect.bisect_right(thresholds, old_sz)
                _update_sizes_on_free(current_sizes, current_ge_counts, n, old_sz, old_pow2, old_idx)

    base_name = os.path.splitext(filename)[0]
    if base_name.endswith('.malloc'): base_name = base_name[:-7]

    with open(base_name + ".result.log", "w") as log_out:
        sys.stdout = Tee(sys.stdout, log_out)

        total_alloc = 0
        total_dealloc = 0
        for name, codes in _ALLOC_GROUPS:
            total_alloc += sum(func_stats.get(TYPE_MAP.get(c, 'unknown'), 0) for c in codes)
        for name, codes in _FREE_GROUPS:
            total_dealloc += sum(func_stats.get(TYPE_MAP.get(c, 'unknown'), 0) for c in codes)

        print("\n=== Function Call Statistics ===")
        print(f"Total Alloc calls: {total_alloc}")
        print(f"Total Free calls:  {total_dealloc}")
        print(f"Active objects remaining in memory: {len(active_heap)}")

        print("\n--- Breakdown by Type Group ---")
        print(f"{'Group':<18} {'Types':>12}  {'Count':>14}")
        print("-" * 48)
        for group_name, codes in _ALLOC_GROUPS + _FREE_GROUPS:
            group_total = 0
            for c in codes:
                name = TYPE_MAP.get(c, 'unknown')
                group_total += func_stats.get(name, 0)
            if group_total > 0:
                print(f"{group_name:<18} {len(codes):>12}  {group_total:>14,}")

        print("\n--- Breakdown by Symbol ---")
        print(f"{'Symbol':<30} {'Code':>4}  {'Count':>14}")
        print("-" * 52)
        for code in range(1, 24):
            name = TYPE_MAP.get(code, 'unknown')
            count = func_stats.get(name, 0)
            if count > 0:
                print(f"{name:<30} {code:>4}  {count:>14,}")

        print("\n=== Peak Memory Usage Summary ===")
        print(f"Original Physical Peak: {format_size(original_peak_size)}")
        print("\n Threshold   Aligned Increase               Increase %   Objects (interval)   % of Total Objs   Desc Overhead   Desc Overhead %")
        print("-" * 137)
        prev = 0
        for i in range(n):
            t = thresholds[i]
            increase = peak_moment_sizes[i] - original_peak_size
            inc_pct = (increase / original_peak_size * 100) if original_peak_size > 0 else 0
            delta = threshold_object_counts[i] - prev
            obj_pct = (threshold_object_counts[i] / total_alloc * 100) if total_alloc > 0 else 0
            desc_overhead = peak_moment_ge_counts[i] * 16
            desc_pct = (desc_overhead / original_peak_size * 100) if original_peak_size > 0 else 0
            print(f"{t:>9}  {increase:>27,}  {inc_pct:>9.2f}%  {delta:>16,}  {obj_pct:>15.2f}%  {desc_overhead:>13,}  {desc_pct:>15.2f}%")
            prev = threshold_object_counts[i]

        if objects_path is not None:
            if all_large_objects:
                sorted_large = sorted(all_large_objects, key=lambda x: x[1], reverse=True)
                with open(objects_path, "w") as obj_out:
                    obj_out.write(f"{'Address':>18}  {'Size':>12}  {'Type':<18}\n")
                    obj_out.write("-" * 52 + "\n")
                    for ptr, sz, atype in sorted_large:
                        obj_out.write(f"0x{ptr:016x}  {sz:>12,}  {atype:<18}\n")
                print(f"Large objects (>=32KB) report ({len(all_large_objects)} total) saved to: {objects_path}")
            else:
                with open(objects_path, "w") as obj_out:
                    obj_out.write("No objects >= 32KB found.\n")
                print(f"No objects >= 32KB found (empty report written to: {objects_path})")

        print(f"Analysis successfully done. Output logs saved to base: {base_name}")
        sys.stdout = sys.__stdout__

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='High Performance streaming Analyzer (v5 39-type)')
    parser.add_argument('-i', '--input', required=True, help='Path to malloc.bin or malloc.bin.xz, or "all"')
    parser.add_argument('-o', '--objects', default=None, help='Output path for large objects (>=32KB) report')
    args = parser.parse_args()

    if args.input.lower() == 'all':
        files = sorted(glob.glob('*.malloc.bin.xz'))
        if not files:
            print("No *.malloc.bin.xz files found in current directory.")
            sys.exit(1)
        print(f"Processing {len(files)} file(s):")
        for f in files:
            print(f"\n  --- {f} ---")
            objs = None
            if args.objects:
                base_name = os.path.splitext(os.path.basename(f))[0]
                if base_name.endswith('.malloc'): base_name = base_name[:-7]
                objs = base_name + ".objects.log"
            process_malloc_binary(f, objects_path=objs)
        print("\nAll files processed.")
    else:
        process_malloc_binary(args.input, objects_path=args.objects)