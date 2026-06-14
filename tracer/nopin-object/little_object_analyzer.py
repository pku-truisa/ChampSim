#!/usr/bin/env python3
"""
高性能低内存流式 Memory Allocation Trace File Analyzer — v7 39-type scheme.
v6: Added top-64 largest memory objects tracking with lifetime (alloc/free event count).
v7: Added automatic legacy format detection + type code remapping for old PIN tracer traces.
"""

import struct
import sys
import os
import glob
import lzma
import argparse
import bisect
import heapq

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

# ===== New 23-type code scheme (current) =====
TYPE_MAP = {
    1: 'malloc/new',
    2: 'free/delete',
    3: 'calloc',
    4: 'realloc',
    5: 'posix_memalign',
    6: 'mmap',
    7: 'munmap',
}

# Detect legacy type codes shown in old PIN object_tracer (pre-23-type).
# Old scheme: 1=malloc, 2=free, 3=mmap, 4=munmap, 5=calloc, 6=realloc,
#             8=posix_memalign, 16=realloc_inplace
# Mapping: old_type -> new_type (for automatic remapping)
_OLD_TYPE_REMAP = {
    2: 18,   # free -> free
    3: 16,   # mmap -> mmap
    4: 17,   # munmap -> munmap
    5: 7,    # calloc -> calloc
    6: 11,   # realloc -> realloc
    8: 15,   # posix_memalign -> posix_memalign
    16: 11,  # realloc_inplace -> realloc (treat as realloc)
}

_ALLOC_TYPES = {1, 3, 4, 5, 6}
_FREE_TYPES = {2, 7}

_ALLOC_GROUPS = [
    ("malloc/new",    [1]),
    ("calloc",        [3]),
    ("realloc",       [4]),
    ("posix_memalign", [5]),
    ("mmap",          [6]),
]
_FREE_GROUPS = [
    ("free/delete",   [2]),
    ("munmap",        [7]),
]

def detect_legacy_format(filename):
    """
    Read the first ~200 records from the binary trace to detect if it uses
    the OLD PIN object_tracer format (type 2=free, type 3=mmap, etc.)

    Detection heuristic: In old format, type 2 = free (arg1=ptr to user memory).
    In new format, type 2 = mi_malloc (arg1=size, usually small < 1MB).
    If type 2 records consistently have large arg1 values (> 1TB or >= 0x500000000000),
    it's legacy format.
    """
    is_xz = filename.endswith('.xz')
    open_func = lzma.open if is_xz else open
    fmt = "<QQQB7s"
    struct_size = struct.calcsize(fmt)

    sample_type2 = []
    total_records = 0

    try:
        with open_func(filename, "rb") as f:
            chunk = f.read(struct_size * 200)
            offset = 0
            while offset + struct_size <= len(chunk):
                arg1, arg2, ret, etype, _ = struct.unpack(fmt, chunk[offset:offset+struct_size])
                total_records += 1
                if etype == 2:
                    sample_type2.append(arg1)
                offset += struct_size
    except Exception:
        return False  # On any error, assume new format

    if not sample_type2 or total_records < 10:
        return False  # Not enough data to decide

    # Check: in legacy format, type 2 = free, arg1 is a pointer (high 16 bits non-zero)
    # In new format, type 2 = mi_malloc, arg1 is a size (usually < 2^48, but typically < a few MB)
    # A user-space pointer on x86_64 typically starts with 0x00005... or 0x00007...
    # But a size > 2^32 is extremely rare for allocation size.
    legacy_count = sum(1 for v in sample_type2 if v > 0x0000100000000000)  # > 28 TB
    new_count = sum(1 for v in sample_type2 if v <= 0x0000100000000000)

    # Also check if any type 2 arg1 is in valid pointer range (0x5555..., 0x7f7f..., 0xffff...)
    pointer_count = sum(1 for v in sample_type2 if (v >> 44) in (0x5, 0x7, 0xf))

    detected_legacy = (legacy_count > len(sample_type2) * 0.5) or (pointer_count > len(sample_type2) * 0.3)

    if detected_legacy:
        print(f"[Auto-detect] Detected OLD format trace ({len(sample_type2)} type-2 samples: "
              f"{legacy_count} huge, {pointer_count} pointer-looking). "
              f"Auto-remapping type codes to new scheme.")
    return detected_legacy

def remap_legacy_record(etype, arg1, arg2, ret):
    """
    Remap a record from old format to new format type codes.
    Returns (new_etype, new_arg1, new_arg2, new_ret).
    """
    if etype == 1:
        # malloc: unchanged
        return 1, arg1, arg2, ret
    elif etype == 2:
        # old free -> new free (type 18): arg1=ptr, arg2=0, ret=0
        return 18, arg1, 0, 0
    elif etype == 3:
        # old mmap -> new mmap (type 16): arg1=size, arg2=0, ret=addr
        return 16, arg1, 0, ret
    elif etype == 4:
        # old munmap -> new munmap (type 17): arg1=addr, arg2=0, ret=0
        return 17, arg1, 0, 0
    elif etype == 5:
        # old calloc -> new calloc (type 7): arg1=nmemb, arg2=elem_size, ret=addr
        return 7, arg1, arg2, ret
    elif etype == 6:
        # old realloc -> new realloc (type 11): arg1=old_ptr, arg2=new_size, ret=addr
        return 11, arg1, arg2, ret
    elif etype == 8:
        # old posix_memalign -> new posix_memalign (type 15): arg1=size, arg2=align, ret=addr
        return 15, arg1, arg2, ret
    elif etype == 16:
        # old realloc_inplace -> new realloc (type 11): arg1=ptr (old==new), arg2=0, ret=addr
        return 11, arg1, 0, ret
    else:
        # Unknown type - keep as-is
        return etype, arg1, arg2, ret

def read_malloc_binary(filename, legacy_mode=False):
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
                if legacy_mode:
                    etype, arg1, arg2, ret = remap_legacy_record(etype, arg1, arg2, ret)
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

def _maybe_add_candidate(candidate_heap, candidate_info, size, ptr, alloc_event, func_name):
    """Try to add object to top-64 candidate set. Returns False if not added."""
    # First, clean up stale entries at the top of the heap
    while candidate_heap and candidate_heap[0][1] not in candidate_info:
        heapq.heappop(candidate_heap)

    # If we have fewer than 64 candidates, always add
    if len(candidate_info) < 64:
        heapq.heappush(candidate_heap, (size, ptr))
        candidate_info[ptr] = {"size": size, "type": func_name, "alloc_event": alloc_event, "lifetime": None}
        return True

    # If heap is non-empty and this is larger than the smallest candidate
    if candidate_heap and size > candidate_heap[0][0]:
        # Remove the smallest
        min_size, min_ptr = heapq.heappop(candidate_heap)
        if min_ptr in candidate_info:
            del candidate_info[min_ptr]
        # Add the new one
        heapq.heappush(candidate_heap, (size, ptr))
        candidate_info[ptr] = {"size": size, "type": func_name, "alloc_event": alloc_event, "lifetime": None}
        return True
    elif candidate_heap and size == candidate_heap[0][0] and ptr < candidate_heap[0][1]:
        # Same size but smaller address; treat as larger (in case of ties)
        min_size, min_ptr = heapq.heappop(candidate_heap)
        if min_ptr in candidate_info:
            del candidate_info[min_ptr]
        heapq.heappush(candidate_heap, (size, ptr))
        candidate_info[ptr] = {"size": size, "type": func_name, "alloc_event": alloc_event, "lifetime": None}
        return True

    return False

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

    # Top-64 tracking
    event_counter = 0
    candidate_heap = []   # min-heap of (size, ptr)
    candidate_info = {}   # ptr -> {size, type, alloc_event, lifetime}

    # Detect legacy format automatically
    legacy_mode = detect_legacy_format(filename)
    if legacy_mode:
        print("[Auto-detect] Running in legacy mode with automatic type code remapping.")

    print("Streaming processing data to minimize memory footprint...")

    for etype, arg1, arg2, ret in read_malloc_binary(filename, legacy_mode=legacy_mode):
        event_counter += 1  # Each record (alloc or free) counts as one event
        func_name = TYPE_MAP.get(etype, 'unknown')

        if etype in _ALLOC_TYPES:
            func_stats[func_name] += 1
            size = arg2 if etype == 4 else arg1

            if ret != 0:
                # Handle realloc old pointer free (realloc is a single event)
                if etype == 4 and arg1 != 0 and arg1 in active_heap:
                    old_sz, old_alloc_ev, _ = active_heap.pop(arg1)
                    original_current_size -= old_sz
                    # Compute lifetime for old pointer freed by realloc
                    if arg1 in candidate_info:
                        candidate_info[arg1]["lifetime"] = event_counter - old_alloc_ev
                    old_pow2 = next_power_of_2(old_sz)
                    old_idx = bisect.bisect_right(thresholds, old_sz)
                    _update_sizes_on_free(current_sizes, current_ge_counts, n, old_sz, old_pow2, old_idx)

                # New alloc
                active_heap[ret] = (size, event_counter, func_name)
                original_current_size += size
                if size >= 32768:
                    all_large_objects.append((ret, size, func_name))

                # Try to add to top-64 candidates
                _maybe_add_candidate(candidate_heap, candidate_info, size, ret, event_counter, func_name)

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
                old_sz, old_alloc_ev, _ = active_heap.pop(ptr)
                original_current_size -= old_sz
                # Compute lifetime for freed object
                if ptr in candidate_info:
                    candidate_info[ptr]["lifetime"] = event_counter - old_alloc_ev
                old_pow2 = next_power_of_2(old_sz)
                old_idx = bisect.bisect_right(thresholds, old_sz)
                _update_sizes_on_free(current_sizes, current_ge_counts, n, old_sz, old_pow2, old_idx)

    # ===== End of trace: compute final lifetimes for still-active candidates =====
    for ptr in list(candidate_info.keys()):
        if candidate_info[ptr]["lifetime"] is None:
            alloc_ev = candidate_info[ptr]["alloc_event"]
            candidate_info[ptr]["lifetime"] = event_counter - alloc_ev

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

        print("\n--- Breakdown by Type ---")
        print(f"{'Type':<30} {'Code':>4}  {'Count':>14}")
        print("-" * 52)
        for code in sorted(TYPE_MAP.keys()):
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

        # ===== Top-64 Largest Memory Objects =====
        if candidate_info:
            # Sort by size descending, then by alloc_event as tiebreaker
            sorted_candidates = sorted(candidate_info.values(), key=lambda x: (-x["size"], x["alloc_event"]))

            print("\n=== Top 64 Largest Memory Objects ===")
            print(f"{'#':>4}  {'Size':>12}  {'Type':<18}  {'Lifetime':>10}")
            print("-" * 48)

            # Determine how many to print (64 + ties)
            print_count = min(64, len(sorted_candidates))
            for i in range(print_count):
                obj = sorted_candidates[i]
                print(f"{i+1:>4}  {obj['size']:>12,}  {obj['type']:<18}  {obj['lifetime']:>10,}")

            # Include ties at position 64
            if len(sorted_candidates) > 64:
                last_size = sorted_candidates[63]["size"]
                for j in range(64, len(sorted_candidates)):
                    if sorted_candidates[j]["size"] == last_size:
                        obj = sorted_candidates[j]
                        print(f"{j+1:>4}  {obj['size']:>12,}  {obj['type']:<18}  {obj['lifetime']:>10,}")
                    else:
                        break

            print(f"\n(Total unique candidate objects in top-64 set: {len(sorted_candidates)})")
        else:
            print("\n=== Top 64 Largest Memory Objects ===")
            print("(No alloc events found)")

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
    parser = argparse.ArgumentParser(description='High Performance streaming Analyzer (v7 39-type, top-64 objects, auto-format)')
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