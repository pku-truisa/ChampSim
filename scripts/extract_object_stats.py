#!/usr/bin/env python3
"""
Extract UNMATCHED object's L1D LOAD hit ratio from all <trace>_memory_object_stats.txt files.

ChampSim writes per-object stats to a file named "{trace_prefix}_memory_object_stats.txt"
(see src/main.cc: print_memory_object_stats). This script recursively finds all such
files under a directory and, for each, extracts the L1D LOAD hit/miss counters from the
"Object ID=UNMATCHED" block.

Usage: python extract_object_stats.py /path/to/dir [output.csv]
"""

import os
import csv
import glob
import sys
import re

# A cache stats line looks like (flat format, see src/memory_stats_printer.cc):
#   cpu0->cpu0_L1D LOAD  ACCESS: 123 HIT:  80 MISS:  43 MSHR_MERGE:  0
# Match any cache whose name contains "L1D" (avoids hard-coding "cpu0_L1D").
L1D_LOAD_RE = re.compile(
    r'cpu0->(?P<cache_name>\S+)\s+'
    r'LOAD\s+'
    r'ACCESS:\s*(?P<access>[0-9,]+)\s+'
    r'HIT:\s*(?P<hit>[0-9,]+)\s+'
    r'MISS:\s*(?P<miss>[0-9,]+)'
)


def parse_l1d_load_hit_miss(lines, start_idx):
    """
    Search from start_idx for the first L1D LOAD stats line that belongs to the
    current "Object ID=UNMATCHED" block.

    Scanning stops at the next "Object ID=" header (e.g. "Object ID=TOTAL") so that
    we never accidentally pick up stats from a later block (TOTAL aggregates all
    objects + unmatched).

    Returns (hit, miss) as integers, or (None, None) if not found.
    """
    for i in range(start_idx, len(lines)):
        line = lines[i]

        # Stop at the start of the next object block (TOTAL, or another object).
        if i > start_idx and line.lstrip().startswith('Object ID='):
            break

        m = L1D_LOAD_RE.search(line)
        if m and 'L1D' in m.group('cache_name'):
            hit = int(m.group('hit').replace(',', ''))
            miss = int(m.group('miss').replace(',', ''))
            return hit, miss

    return None, None


def process_file(filepath):
    with open(filepath, 'r', encoding='utf-8') as f:
        lines = f.readlines()

    # Find the line with "Object ID=UNMATCHED"
    unmatched_start = None
    for i, line in enumerate(lines):
        if 'Object ID=UNMATCHED' in line:
            unmatched_start = i
            break

    if unmatched_start is None:
        return None, None, None

    hit, miss = parse_l1d_load_hit_miss(lines, unmatched_start)
    if hit is None or miss is None:
        return None, None, None

    total = hit + miss
    # Treat "no accesses" as undefined (None -> 'NA') rather than 0%.
    hit_ratio = hit / total if total > 0 else None
    return hit, miss, hit_ratio


def main():
    if len(sys.argv) < 2:
        print("Usage: python extract_object_stats.py <directory> [output.csv]")
        sys.exit(1)

    search_dir = sys.argv[1]
    output_file = sys.argv[2] if len(sys.argv) > 2 else 'unmatched_l1d_hitratio.csv'

    pattern = os.path.join(search_dir, '**', '*_memory_object_stats.txt')
    files = glob.glob(pattern, recursive=True)

    if not files:
        print(f"No files matching pattern '{pattern}' found.")
        sys.exit(0)

    results = []
    for fpath in sorted(files):
        relpath = os.path.relpath(fpath, search_dir)
        hit, miss, ratio = process_file(fpath)
        results.append({
            'file': relpath,
            'L1D_LOAD_Hits': hit if hit is not None else 'NA',
            'L1D_LOAD_Misses': miss if miss is not None else 'NA',
            'L1D_LOAD_HitRatio': f'{ratio:.6f}' if ratio is not None else 'NA'
        })

    with open(output_file, 'w', newline='', encoding='utf-8') as csvfile:
        fieldnames = ['file', 'L1D_LOAD_Hits', 'L1D_LOAD_Misses', 'L1D_LOAD_HitRatio']
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        for row in results:
            writer.writerow(row)

    print(f"Done. Wrote {len(results)} entries to {output_file}")


if __name__ == '__main__':
    main()