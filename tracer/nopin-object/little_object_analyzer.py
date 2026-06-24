#!/usr/bin/env python3
"""
High-performance low-memory streaming Memory Allocation Trace File Analyzer — v13
v6: Added top-64 largest memory objects tracking with lifetime (alloc/free event count).
v7: Added automatic legacy format detection + type code remapping for old PIN tracer traces.
v8: Added automatic 32-byte vs 40-byte record detection for compatibility.
v9: Removed 32-byte support entirely. Only 40-byte format is supported.
v10: Added per-caller_ip statistics (alloc count, avg size, total size, avg lifetime).
v11: Added defensive caller_ip filtering in display: caller_ip <= 4096 grouped as "unknown/invalid".
v12: Updated type codes to match champsim_tracer.cpp: 1=malloc,2=calloc,3=realloc,4=free,
     5=mmap,6=mmap64,7=mremap,8=munmap,9=main_begin.
     Format: <QQQQB7s> (arg1, arg2, ret, caller_ip, type, reserved[7])
v13: Removed top-64 largest objects tracking. Thresholds changed to [16..65536].
     Removed desc overhead stats. Added total/peak object/memory summary.
     Table transposed to interval-granularity by columns (range >prev <=current).
"""

import struct
import sys
import os
import glob
import lzma
import argparse
import bisect
from collections import defaultdict

INVALID_CALLER_IP_MAX = 4096  # caller_ip addresses at or below this are considered invalid

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

# ===== 9-type code scheme (aligned with champsim_tracer.cpp) =====
TYPE_MAP = {
    1: 'malloc',
    2: 'calloc',
    3: 'realloc',
    4: 'free',
    5: 'mmap',
    6: 'mmap64',
    7: 'mremap',
    8: 'munmap',
    9: 'main_begin',
}

_ALLOC_TYPES = {1, 2, 3, 5, 6, 7}
_FREE_TYPES = {4, 8}

_ALLOC_GROUPS = [
    ("malloc",        [1]),
    ("calloc",        [2]),
    ("realloc",       [3]),
    ("mmap",          [5]),
    ("mmap64",        [6]),
    ("mremap",        [7]),
]
_FREE_GROUPS = [
    ("free",          [4]),
    ("munmap",        [8]),
]

# 40-byte format: <QQQQB7s> (arg1, arg2, ret, caller_ip, type, reserved[7])
RECORD_FMT = "<QQQQB7s"
RECORD_SIZE = struct.calcsize(RECORD_FMT)  # = 40

def read_malloc_binary(filename):
    """Read binary malloc trace in 40-byte format. Yields (type, arg1, arg2, ret, caller_ip)."""
    is_xz = filename.endswith('.xz')
    open_func = lzma.open if is_xz else open

    with open_func(filename, "rb") as f:
        # IMPORTANT: chunk_size must be a multiple of RECORD_SIZE (40),
        # otherwise record boundaries get misaligned at chunk boundaries.
        # 2^21 / 40 = 52428.8, so we floor to nearest multiple of 40:
        chunk_raw_size = 32 * 1024 * 64  # 2,097,152 = 52428.8 records
        chunk_size = (chunk_raw_size // RECORD_SIZE) * RECORD_SIZE  # 2,097,120 = 52428 records exactly
        remainder = b''
        while True:
            data = f.read(chunk_size)
            if not data:
                if remainder:
                    # Process any remaining bytes that didn't form a full record
                    pass
                break
            frame = remainder + data
            offset = 0
            frame_len = len(frame)
            # Process whole records only
            while offset + RECORD_SIZE <= frame_len:
                record = frame[offset:offset+RECORD_SIZE]
                arg1, arg2, ret, caller_ip, etype, _ = struct.unpack(RECORD_FMT, record)
                yield etype, arg1, arg2, ret, caller_ip
                offset += RECORD_SIZE
            remainder = frame[offset:]

def _update_sizes_on_alloc(current_sizes, peak_sizes, threshold_object_counts, n, size, pow2, split_idx):
    for i in range(split_idx):
        current_sizes[i] += size
        if current_sizes[i] > peak_sizes[i]: peak_sizes[i] = current_sizes[i]
    for i in range(split_idx, n):
        threshold_object_counts[i] += 1
        current_sizes[i] += pow2
        if current_sizes[i] > peak_sizes[i]: peak_sizes[i] = current_sizes[i]

def _update_sizes_on_free(current_sizes, n, old_sz, pow2, split_idx):
    for i in range(split_idx):
        current_sizes[i] -= old_sz
    for i in range(split_idx, n):
        current_sizes[i] -= pow2

def process_malloc_binary(filename, objects_path=None, from_main=False):
    func_stats = {k: 0 for k in TYPE_MAP.values()}
    active_heap = {}

    thresholds = [16, 32, 64, 128, 256, 512, 1024, 2048, 4096, 8192, 16384, 32768, 65536]
    n = len(thresholds)
    current_sizes = [0] * n
    peak_sizes = [0] * n
    peak_moment_sizes = [0] * n
    threshold_object_counts = [0] * n

    original_current_size = 0
    original_peak_size = 0
    total_allocated_memory = 0
    peak_active_objects = 0
    all_large_objects = []

    event_counter = 0

    # Per-caller_ip statistics: { caller_ip -> {cnt, tot_sz, tot_lt, types: {type: count}} }
    caller_stats = {}
    invalid_caller_count = 0  # counter for caller_ip <= INVALID_CALLER_IP_MAX

    # main_begin marker handling: if from_main=True, skip events before type=9 marker
    in_main = not from_main
    saw_main_begin = False

    print("Streaming processing data to minimize memory footprint...")

    for etype, arg1, arg2, ret, caller_ip in read_malloc_binary(filename):
        event_counter += 1
        func_name = TYPE_MAP.get(etype, 'unknown')

        # Check for main_begin marker (type=9)
        if etype == 9:
            if from_main:
                # Reset all analysis state so we only count events after main()
                func_stats = {k: 0 for k in TYPE_MAP.values()}
                active_heap.clear()
                current_sizes = [0] * n
                peak_sizes = [0] * n
                peak_moment_sizes = [0] * n
                threshold_object_counts = [0] * n
                original_current_size = 0
                original_peak_size = 0
                total_allocated_memory = 0
                peak_active_objects = 0
                all_large_objects.clear()
                event_counter = 0
                caller_stats.clear()
                invalid_caller_count = 0
                in_main = True
                saw_main_begin = True
            # skip the marker itself (don't treat as alloc/free)
            continue

        # Before main() is reached, skip all events
        if not in_main:
            continue

        if etype in _ALLOC_TYPES:
            func_stats[func_name] += 1
            size = arg2 if etype == 3 else arg1  # realloc (type=3): size in arg2

            # Track per-caller_ip stats for allocations
            if caller_ip <= INVALID_CALLER_IP_MAX:
                invalid_caller_count += 1
            else:
                if caller_ip not in caller_stats:
                    caller_stats[caller_ip] = {"cnt": 0, "tot_sz": 0, "tot_lt": 0, "types": {}}
                caller_stats[caller_ip]["cnt"] += 1
                caller_stats[caller_ip]["tot_sz"] += size
                if etype not in caller_stats[caller_ip]["types"]:
                    caller_stats[caller_ip]["types"][etype] = 0
                caller_stats[caller_ip]["types"][etype] += 1

            if ret != 0:
                if etype == 3 and arg1 != 0 and arg1 in active_heap:
                    # realloc: remove old pointer before adding new
                    old_sz, old_alloc_ev, _, old_caller_ip = active_heap.pop(arg1)
                    original_current_size -= old_sz
                    # Accumulate lifetime to the original allocator's caller_ip
                    lifetime = event_counter - old_alloc_ev
                    if old_caller_ip > INVALID_CALLER_IP_MAX and old_caller_ip in caller_stats:
                        caller_stats[old_caller_ip]["tot_lt"] += lifetime
                    old_pow2 = next_power_of_2(old_sz)
                    old_idx = bisect.bisect_right(thresholds, old_sz)
                    _update_sizes_on_free(current_sizes, n, old_sz, old_pow2, old_idx)

                active_heap[ret] = (size, event_counter, func_name, caller_ip)
                original_current_size += size
                total_allocated_memory += size
                if size >= 32768:
                    all_large_objects.append((ret, size, func_name))

                pow2 = next_power_of_2(size)
                split_idx = bisect.bisect_right(thresholds, size)
                _update_sizes_on_alloc(current_sizes, peak_sizes, threshold_object_counts,
                                       n, size, pow2, split_idx)

                if original_current_size > original_peak_size:
                    original_peak_size = original_current_size
                    peak_active_objects = len(active_heap)
                    peak_moment_sizes = current_sizes.copy()

        elif etype in _FREE_TYPES:
            func_stats[func_name] += 1
            ptr = arg1
            if ptr in active_heap:
                old_sz, old_alloc_ev, _, old_caller_ip = active_heap.pop(ptr)
                original_current_size -= old_sz
                # Accumulate lifetime to the original allocator's caller_ip
                lifetime = event_counter - old_alloc_ev
                if old_caller_ip > INVALID_CALLER_IP_MAX and old_caller_ip in caller_stats:
                    caller_stats[old_caller_ip]["tot_lt"] += lifetime
                old_pow2 = next_power_of_2(old_sz)
                old_idx = bisect.bisect_right(thresholds, old_sz)
                _update_sizes_on_free(current_sizes, n, old_sz, old_pow2, old_idx)

    # Accumulate lifetime for objects still alive at end of trace
    for ptr, (old_sz, old_alloc_ev, _, old_caller_ip) in active_heap.items():
        lifetime = event_counter - old_alloc_ev
        if old_caller_ip > INVALID_CALLER_IP_MAX and old_caller_ip in caller_stats:
            caller_stats[old_caller_ip]["tot_lt"] += lifetime

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

        print(f"\nProcessing file: {base_name}")
        print("\n=== Function Call Statistics ===")
        print(f"Total Alloc calls: {total_alloc}")
        print(f"Total Free calls:  {total_dealloc}")
        print(f"Active objects remaining in memory: {len(active_heap)}")

        print("\n--- Breakdown by Type ---")
        print(f"{'Type':<30} {'Code':>4}  {'Count':>14}")
        print("-" * 52)
        for code in sorted(TYPE_MAP.keys()):
            name = TYPE_MAP.get(code, 'unknown')
            count = func_stats.get(name, 0)
            if count > 0:
                print(f"{name:<30} {code:>4}  {count:>14,}")

        # ===== Transposed Peak Memory Table (interval granularity) =====
        # Build column labels and interval values
        range_labels = []
        for i in range(n):
            lo = 0 if i == 0 else thresholds[i - 1]
            hi = thresholds[i]
            range_labels.append(f"({lo},{hi}]")
        # Extra column for >65536
        range_labels.append(f"({thresholds[-1]},+\u221e)")

        # Pre-compute interval metrics (excluding the extra >max column)
        interval_inc = []
        interval_inc_pct = []
        cum_inc_pct = []
        interval_objs = []
        interval_obj_pct = []
        cum_obj_pct = []

        prev_objs = 0
        for i in range(n):
            # Interval-object count (delta from cumulative)
            delta_objs = threshold_object_counts[i] - prev_objs
            prev_objs = threshold_object_counts[i]

            # Aligned increase contributed by this interval at peak moment
            #   peak_moment_sizes[i] = cumulative aligned total for objects <= threshold[i]
            #   subtract the baseline: for i==0, subtract original_peak_size;
            #   for i>0, subtract peak_moment_sizes[i-1] (aligned total of smaller objects at peak moment)
            base = original_peak_size if i == 0 else peak_moment_sizes[i - 1]
            inc = peak_moment_sizes[i] - base

            # Cumulative inc%: total aligned increase for all objects <= threshold[i]
            total_aligned_inc = peak_moment_sizes[i] - original_peak_size
            cum_pct = (total_aligned_inc / original_peak_size * 100) if original_peak_size > 0 else 0

            interval_inc.append(inc)
            interval_inc_pct.append((inc / original_peak_size * 100) if original_peak_size > 0 else 0)
            cum_inc_pct.append(cum_pct)
            interval_objs.append(delta_objs)
            interval_obj_pct.append((delta_objs / total_alloc * 100) if total_alloc > 0 else 0)
            cum_obj_pct.append((threshold_object_counts[i] / total_alloc * 100) if total_alloc > 0 else 0)

        # Extra column (>65536)
        extra_objs = total_alloc - threshold_object_counts[-1]
        interval_inc.append(0)
        interval_inc_pct.append(0.0)
        cum_inc_pct.append(cum_inc_pct[-1] if cum_inc_pct else 0.0)  # same as last cum value
        interval_objs.append(extra_objs)
        interval_obj_pct.append((extra_objs / total_alloc * 100) if total_alloc > 0 else 0)
        cum_obj_pct.append(cum_obj_pct[-1] if cum_obj_pct else 100.0)

        # Summary header with dynamic value alignment
        sum_labels = ['Total Alloc Objects:', 'Total Allocated Memory:', 'Peak Active Objects:', 'Peak Allocated Memory:']
        sum_vals = [f"{total_alloc:,}", format_size(total_allocated_memory), f"{peak_active_objects:,}", format_size(original_peak_size)]
        sum_label_width = max(len(l) for l in sum_labels)
        sum_val_width = max(len(v) for v in sum_vals)
        print("\n=== Peak Memory Usage Summary ===")
        for label, val in zip(sum_labels, sum_vals):
            print(f"{label:>{sum_label_width}}  {val:>{sum_val_width}}")
        print()

        # Data rows: (label, values, fmt_string)
        metrics = [
            ("Aligned Inc",   interval_inc,     "{:,}"),
            ("Inc%",          interval_inc_pct, "{:.2f}%"),
            ("Cum Inc%",      cum_inc_pct,      "{:.2f}%"),
            ("Obj Cnt",       interval_objs,    "{:,}"),
            ("Obj%",          interval_obj_pct, "{:.2f}%"),
            ("Cum Obj%",      cum_obj_pct,      "{:.2f}%"),
        ]

        # Compute dynamic column widths from actual formatted data
        first_col_width = max(len(label) for label, _, _ in metrics)
        col_strs = [[] for _ in range(len(range_labels))]
        for j in range(len(range_labels)):
            col_strs[j].append(range_labels[j])  # header
        for label, values, fmt in metrics:
            for j, v in enumerate(values):
                s = fmt.format(v)
                col_strs[j].append(s)
        col_widths = [max(len(s) for s in col_strs[j]) for j in range(len(range_labels))]

        # Build header: metrics row + range labels as columns
        header = f"{'Metric':>{first_col_width}}"
        for j, rl in enumerate(range_labels):
            header += f"  {rl:>{col_widths[j]}}"
        print(header)

        # Separator
        sep = "-" * first_col_width
        for j in range(len(range_labels)):
            sep += "  " + "-" * col_widths[j]
        print(sep)

        for label, values, fmt in metrics:
            row = f"{label:>{first_col_width}}"
            for j, v in enumerate(values):
                s = fmt.format(v)
                row += "  " + f"{s:>{col_widths[j]}}"
            print(row)

        # ===== Caller IP Statistics =====
        if caller_stats or invalid_caller_count > 0:
            # Build list of (avg_size, caller_ip, count, total_size, avg_lifetime, primary_type)
            raw_caller_rows = []

            # Aggregate invalid caller IPs into one row
            if invalid_caller_count > 0:
                # Re-scan to collect invalid stats more precisely.
                invalid_tot_sz = 0
                invalid_types = {}
                invalid_cnt = 0
                for etype, arg1, arg2, ret, caller_ip in read_malloc_binary(filename):
                    if caller_ip <= INVALID_CALLER_IP_MAX and etype in _ALLOC_TYPES:
                        size = arg2 if etype == 3 else arg1
                        invalid_cnt += 1
                        invalid_tot_sz += size
                        if etype not in invalid_types:
                            invalid_types[etype] = 0
                        invalid_types[etype] += 1
                if invalid_cnt > 0:
                    avg_sz = invalid_tot_sz / invalid_cnt if invalid_cnt > 0 else 0
                    primary_type = max(invalid_types, key=invalid_types.get) if invalid_types else 0
                    type_name = TYPE_MAP.get(primary_type, 'unknown')
                    raw_caller_rows.append((avg_sz, 0, invalid_cnt, invalid_tot_sz, 0.0, type_name))

            for ip, info in caller_stats.items():
                cnt = info["cnt"]
                tot_sz = info["tot_sz"]
                tot_lt = info["tot_lt"]
                avg_sz = tot_sz / cnt if cnt > 0 else 0
                avg_lt = tot_lt / cnt if cnt > 0 else 0
                # Determine primary type (most frequent)
                primary_type = max(info["types"], key=info["types"].get) if info["types"] else 0
                type_name = TYPE_MAP.get(primary_type, 'unknown')
                raw_caller_rows.append((avg_sz, ip, cnt, tot_sz, avg_lt, type_name))

            # Sort by avg size descending
            raw_caller_rows.sort(key=lambda x: -x[0])

            # Format all rows and compute dynamic column widths
            caller_headers = ['Caller IP', 'Type', 'Alloc Count', 'Avg Size', 'Total Size', 'Avg Lifetime']
            caller_formatted = []
            for avg_sz, ip, cnt, tot_sz, avg_lt, type_name in raw_caller_rows:
                if ip == 0:
                    ip_str = "unknown/invalid"
                else:
                    ip_str = f"0x{ip:016x}"
                cnt_str = f"{cnt:,}"
                avg_sz_str = f"{avg_sz:,.1f}"
                tot_sz_str = f"{tot_sz:,}"
                avg_lt_str = f"{avg_lt:,.1f}"
                caller_formatted.append((ip_str, type_name, cnt_str, avg_sz_str, tot_sz_str, avg_lt_str))

            # Column widths = max(width of header, max width of data)
            cw = []
            for ci in range(6):
                max_w = len(caller_headers[ci])
                for row in caller_formatted:
                    max_w = max(max_w, len(row[ci]))
                # Left-aligned columns (0, 1) need no extra; right-aligned columns need size
                cw.append(max_w)

            print("\n=== Caller IP Statistics (sorted by avg size) ===")
            # Build header with dynamic widths
            hdr = f"{caller_headers[0]:<{cw[0]}}  {caller_headers[1]:<{cw[1]}}"
            hdr += f"  {caller_headers[2]:>{cw[2]}}"
            hdr += f"  {caller_headers[3]:>{cw[3]}}"
            hdr += f"  {caller_headers[4]:>{cw[4]}}"
            hdr += f"  {caller_headers[5]:>{cw[5]}}"
            print(hdr)
            print("-" * len(hdr))

            for row in caller_formatted:
                line = f"{row[0]:<{cw[0]}}  {row[1]:<{cw[1]}}"
                line += f"  {row[2]:>{cw[2]}}"
                line += f"  {row[3]:>{cw[3]}}"
                line += f"  {row[4]:>{cw[4]}}"
                line += f"  {row[5]:>{cw[5]}}"
                print(line)

            print(f"\n(Total unique caller IPs: {len(raw_caller_rows) - (1 if invalid_caller_count > 0 else 0)})")
            if invalid_caller_count > 0:
                print(f"(Records with invalid caller_ip <= {INVALID_CALLER_IP_MAX}: {invalid_caller_count})")
        else:
            print("\n=== Caller IP Statistics ===")
            print("(No allocation events found)")

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
    parser = argparse.ArgumentParser(description='High Performance streaming Analyzer (v13, 40-byte, caller_ip stats, transposed interval peaks)')
    parser.add_argument('input', help='Path to malloc.bin or malloc.bin.xz, or "all"')
    parser.add_argument('-m', '--from-main', action='store_true', help='Only count events after the main_begin marker (type=9)')
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
            process_malloc_binary(f, objects_path=objs, from_main=args.from_main)
        print("\nAll files processed.")
    else:
        process_malloc_binary(args.input, objects_path=args.objects, from_main=args.from_main)