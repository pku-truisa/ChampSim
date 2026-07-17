#!/usr/bin/env python3
"""
Aggregate memory_object_stats.txt by caller_ip.

Parses the per-object statistics output from ChampSim's MemoryObjectTable,
groups objects by their allocation call-site IP (caller_ip), and writes
consolidated statistics to caller_ip_status.txt.

Usage:
    python3 scripts/aggregate_by_caller_ip.py
    python3 scripts/aggregate_by_caller_ip.py path/to/memory_object_stats.txt
"""

import re
import sys
import os
from collections import defaultdict

# ---------------------------------------------------------------------------
# Regular expressions
# ---------------------------------------------------------------------------

# Object header:  Object ID=<num>  Type=<str>  Size=<num>  VA_Start=0x<hex>  [Caller=0x<hex>]
RE_OBJECT_HEADER = re.compile(
    r'Object\s+ID=(?P<alloc_id>\d+)\s+'
    r'Type=(?P<alloc_type>\S+)\s+'
    r'Size=(?P<size>\d+)\s+'
    r'VA_Start=0x(?P<va>[0-9a-fA-F]+)'
    r'(?:\s+Caller=0x(?P<caller_ip>[0-9a-fA-F]+))?'
)

# Cache section start:  [name]   e.g. [cpu0_STLB]  or  []
RE_CACHE_SECTION = re.compile(r'^\s*\[(?P<name>[^\]]*)\]\s*$')

# HIT/MISS line:  LOAD:     HIT=  123  MISS=456
RE_HIT_MISS = re.compile(
    r'^\s*(?P<type>LOAD|RFO|PREFETCH|WRITE|TRANS):\s*'
    r'HIT=\s*(?P<hit>\d+)\s+MISS=\s*(?P<miss>\d+)\s*$'
)

# MSHR line:  MSHR_MERGE=123  MSHR_RETURN=456
RE_MSHR = re.compile(
    r'^\s*MSHR_MERGE=\s*(?P<merge>\d+)\s+MSHR_RETURN=\s*(?P<ret>\d+)\s*$'
)

# AVG_MISS_LAT line:  AVG_MISS_LAT=123.45  or  AVG_MISS_LAT=-
RE_AVG_MISS_LAT = re.compile(
    r'^\s*AVG_MISS_LAT=\s*(?P<lat>[\d.]+|\-)\s*$'
)

# Prefetch stats line
RE_PREFETCH = re.compile(
    r'^\s*PF_REQ=\s*(?P<req>\d+)\s+'
    r'PF_ISSUED=\s*(?P<issued>\d+)\s+'
    r'PF_USEFUL=\s*(?P<useful>\d+)\s+'
    r'PF_USELESS=\s*(?P<useless>\d+)\s+'
    r'PF_FILL=\s*(?P<fill>\d+)\s*$'
)

# DRAM row hit/miss line
RE_RQ_ROW = re.compile(
    r'^\s*RQ_ROW_HIT=\s*(?P<rhit>\d+)\s+RQ_ROW_MISS=\s*(?P<rmiss>\d+)\s*$'
)
RE_WQ_ROW = re.compile(
    r'^\s*WQ_ROW_HIT=\s*(?P<whit>\d+)\s+WQ_ROW_MISS=\s*(?P<wmiss>\d+)\s*$'
)

RE_WQ_FULL = re.compile(
    r'^\s*WQ_FULL=\s*(?P<full>\d+)\s*$'
)

RE_AVG_DBUS = re.compile(
    r'^\s*AVG_DBUS_CONGESTED=\s*(?P<cong>[\d.]+|\-)\s*$'
)

# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------

class PerCacheAccum:
    """Accumulated cache/TLB stats for a group of objects."""
    __slots__ = ('hits', 'misses', 'mshr_merge', 'mshr_return',
                 'total_miss_latency', 'total_misses_for_lat',
                 'pf_requested', 'pf_issued', 'pf_useful', 'pf_useless', 'pf_fill')

    def __init__(self):
        self.hits = [0, 0, 0, 0, 0]       # LOAD, RFO, PREFETCH, WRITE, TRANS
        self.misses = [0, 0, 0, 0, 0]
        self.mshr_merge = 0
        self.mshr_return = 0
        self.total_miss_latency = 0        # summed cycles
        self.total_misses_for_lat = 0      # summed miss count that contributed
        self.pf_requested = 0
        self.pf_issued = 0
        self.pf_useful = 0
        self.pf_useless = 0
        self.pf_fill = 0

    def add(self, stats):
        for i in range(5):
            self.hits[i] += stats.hits[i]
            self.misses[i] += stats.misses[i]
        self.mshr_merge += stats.mshr_merge
        self.mshr_return += stats.mshr_return
        self.total_miss_latency += stats.total_miss_latency
        self.total_misses_for_lat += stats.total_misses_for_lat
        self.pf_requested += stats.pf_requested
        self.pf_issued += stats.pf_issued
        self.pf_useful += stats.pf_useful
        self.pf_useless += stats.pf_useless
        self.pf_fill += stats.pf_fill


class PerDRAMAccum:
    """Accumulated DRAM stats for a group of objects."""
    __slots__ = ('rq_row_hit', 'rq_row_miss', 'wq_row_hit', 'wq_row_miss',
                 'wq_full', 'dbus_cycle_congested', 'dbus_count_congested')

    def __init__(self):
        self.rq_row_hit = 0
        self.rq_row_miss = 0
        self.wq_row_hit = 0
        self.wq_row_miss = 0
        self.wq_full = 0
        self.dbus_cycle_congested = 0
        self.dbus_count_congested = 0

    def add(self, stats):
        self.rq_row_hit += stats.rq_row_hit
        self.rq_row_miss += stats.rq_row_miss
        self.wq_row_hit += stats.wq_row_hit
        self.wq_row_miss += stats.wq_row_miss
        self.wq_full += stats.wq_full
        self.dbus_cycle_congested += stats.dbus_cycle_congested
        self.dbus_count_congested += stats.dbus_count_congested


class GroupedStats:
    """Aggregated stats for one caller_ip across all its objects."""
    def __init__(self, caller_ip=0):
        self.caller_ip = caller_ip
        self.object_count = 0
        self.total_size = 0
        self.cache_stats = defaultdict(PerCacheAccum)   # cache_name -> PerCacheAccum
        self.dram_stats = defaultdict(PerDRAMAccum)      # dram_name -> PerDRAMAccum

    def add_object(self, obj):
        """Merge a single parsed object into this group."""
        self.object_count += 1
        self.total_size += obj['size']
        for cname, cstats in obj['cache_stats'].items():
            self.cache_stats[cname].add(cstats)
        for dname, dstats in obj['dram_stats'].items():
            self.dram_stats[dname].add(dstats)


# ---------------------------------------------------------------------------
# Parsing
# ---------------------------------------------------------------------------

def parse_file(filepath):
    """Parse memory_object_stats.txt and return a list of object dicts.

    Each object dict has keys:
        alloc_id, alloc_type, size, va_start, caller_ip (int or 0),
        cache_stats: {cache_name: PerCacheAccum},
        dram_stats:  {dram_name: PerDRAMAccum}
    """
    objects = []
    with open(filepath, 'r') as f:
        lines = f.readlines()

    i = 0
    n = len(lines)

    while i < n:
        line = lines[i]
        m = RE_OBJECT_HEADER.search(line)
        if not m:
            i += 1
            continue

        # Found an object header
        obj = {
            'alloc_id': int(m.group('alloc_id')),
            'alloc_type': m.group('alloc_type'),
            'size': int(m.group('size')),
            'va_start': int(m.group('va'), 16),
            'caller_ip': int(m.group('caller_ip'), 16) if m.group('caller_ip') else 0,
            'cache_stats': {},
            'dram_stats': {},
        }

        i += 1
        # Skip separator line
        if i < n and lines[i].startswith('---'):
            i += 1

        # Now parse sections until the next Object header or EOF
        current_cache = None
        current_dram = None
        # Temporary accumulators for the section being parsed
        cur_cache_acc = None
        cur_dram_acc = None

        while i < n:
            line = lines[i].rstrip()

            # Check if we hit the next object header
            if RE_OBJECT_HEADER.search(line):
                break

            # Check for section header
            sm = RE_CACHE_SECTION.match(line)
            if sm:
                # Save current accumulator
                if current_cache is not None and cur_cache_acc is not None:
                    obj['cache_stats'][current_cache] = cur_cache_acc
                if current_dram is not None and cur_dram_acc is not None:
                    obj['dram_stats'][current_dram] = cur_dram_acc

                # Reset for new section
                sec_name = sm.group('name')

                # Determine if cache or dram by checking if name is known from header
                # Heuristic: if name starts with "cpu" or is "LLC" -> cache
                # If name is empty -> DRAM
                if sec_name == '' or sec_name.startswith('dram') or sec_name.startswith('DRAM'):
                    current_cache = None
                    current_dram = sec_name if sec_name else 'DRAM'
                    cur_cache_acc = None
                    cur_dram_acc = PerDRAMAccum()
                else:
                    current_cache = sec_name
                    current_dram = None
                    cur_cache_acc = PerCacheAccum()
                    cur_dram_acc = None

                i += 1
                continue

            # Parse stats lines within a cache section
            if current_cache is not None and cur_cache_acc is not None:
                hm = RE_HIT_MISS.match(line)
                if hm:
                    atype = hm.group('type')
                    idx_map = {'LOAD': 0, 'RFO': 1, 'PREFETCH': 2, 'WRITE': 3, 'TRANS': 4}
                    idx = idx_map[atype]
                    cur_cache_acc.hits[idx] += int(hm.group('hit'))
                    cur_cache_acc.misses[idx] += int(hm.group('miss'))
                    i += 1
                    continue

                mshr_m = RE_MSHR.match(line)
                if mshr_m:
                    cur_cache_acc.mshr_merge += int(mshr_m.group('merge'))
                    cur_cache_acc.mshr_return += int(mshr_m.group('ret'))
                    i += 1
                    continue

                lat_m = RE_AVG_MISS_LAT.match(line)
                if lat_m:
                    lat_str = lat_m.group('lat')
                    if lat_str != '-':
                        # For aggregation, derive the miss count component from total_miss_latency
                        # But we only have average here, so we need to estimate from current misses
                        # Store the inverse: we accumulate total_miss_latency and total misses separately
                        # To reconstruct total_miss_latency, we'd need to know the number of misses.
                        # However, we can compute avg_miss_lat * misses to get the total latency contribution.
                        # We have the misses count for this section already (from the 5 types).
                        # But the total misses span all types? Typically AVG_MISS_LAT is across all miss types.
                        # Let's sum total misses across all access types for this section.
                        total_miss = sum(cur_cache_acc.misses)
                        if total_miss > 0:
                            cur_cache_acc.total_miss_latency += int(float(lat_str) * total_miss)
                            cur_cache_acc.total_misses_for_lat += total_miss
                    i += 1
                    continue

                pf_m = RE_PREFETCH.match(line)
                if pf_m:
                    cur_cache_acc.pf_requested += int(pf_m.group('req'))
                    cur_cache_acc.pf_issued += int(pf_m.group('issued'))
                    cur_cache_acc.pf_useful += int(pf_m.group('useful'))
                    cur_cache_acc.pf_useless += int(pf_m.group('useless'))
                    cur_cache_acc.pf_fill += int(pf_m.group('fill'))
                    i += 1
                    continue

            # Parse stats lines within a DRAM section
            if current_dram is not None and cur_dram_acc is not None:
                rq_m = RE_RQ_ROW.match(line)
                if rq_m:
                    cur_dram_acc.rq_row_hit += int(rq_m.group('rhit'))
                    cur_dram_acc.rq_row_miss += int(rq_m.group('rmiss'))
                    i += 1
                    continue

                wq_m = RE_WQ_ROW.match(line)
                if wq_m:
                    cur_dram_acc.wq_row_hit += int(wq_m.group('whit'))
                    cur_dram_acc.wq_row_miss += int(wq_m.group('wmiss'))
                    i += 1
                    continue

                wf_m = RE_WQ_FULL.match(line)
                if wf_m:
                    cur_dram_acc.wq_full += int(wf_m.group('full'))
                    i += 1
                    continue

                dbus_m = RE_AVG_DBUS.match(line)
                if dbus_m:
                    cong_str = dbus_m.group('cong')
                    if cong_str != '-':
                        # Similar to AVG_MISS_LAT, we need to estimate total cycles
                        # Use a proxy: just accumulate the average value multiplied by count
                        # Since we don't have dbus_count_congested from the line,
                        # we can set it to 1 for each line and sum cycles accordingly
                        cur_dram_acc.dbus_cycle_congested += int(float(cong_str))
                        cur_dram_acc.dbus_count_congested += 1
                    i += 1
                    continue

            i += 1

        # Save last section
        if current_cache is not None and cur_cache_acc is not None:
            obj['cache_stats'][current_cache] = cur_cache_acc
        if current_dram is not None and cur_dram_acc is not None:
            obj['dram_stats'][current_dram] = cur_dram_acc

        objects.append(obj)

    return objects


# ---------------------------------------------------------------------------
# Output formatting
# ---------------------------------------------------------------------------

ACCESS_TYPE_NAMES = ['LOAD', 'RFO', 'PREFETCH', 'WRITE', 'TRANS']


def format_avg_lat(total_latency, total_misses):
    if total_misses > 0:
        return f"{total_latency / total_misses:.2f}"
    return "-"


def format_avg_dbus(cycles, count):
    if count > 0:
        return f"{cycles / count:.2f}"
    return "-"


def write_grouped_stats(groups, output_path, cache_names_sorted, dram_names_sorted):
    """Write aggregated caller_ip stats to output_path."""
    with open(output_path, 'w') as f:
        f.write(f"=== Aggregated Memory Object Statistics by Caller IP ({len(groups)} unique IPs) ===\n\n")

        # Sort groups by total_size descending
        sorted_groups = sorted(groups, key=lambda g: g.total_size, reverse=True)

        for g in sorted_groups:
            f.write(f"Caller IP=0x{g.caller_ip:x}  Objects={g.object_count}  TotalSize={g.total_size}\n")
            f.write("-" * 80 + "\n")

            # Cache/TLB stats
            for cname in cache_names_sorted:
                if cname in g.cache_stats:
                    c = g.cache_stats[cname]
                    f.write(f"  [{cname}]\n")
                    for idx, atype in enumerate(ACCESS_TYPE_NAMES):
                        f.write(f"    {atype}:     HIT={c.hits[idx]:>10}  MISS={c.misses[idx]:<10}\n")
                    f.write(f"    MSHR_MERGE={c.mshr_merge:<10}  MSHR_RETURN={c.mshr_return:<10}\n")
                    f.write(f"    AVG_MISS_LAT={format_avg_lat(c.total_miss_latency, c.total_misses_for_lat)}\n")
                    f.write(f"    PF_REQ={c.pf_requested:<10}  PF_ISSUED={c.pf_issued:<10}  "
                            f"PF_USEFUL={c.pf_useful:<10}  PF_USELESS={c.pf_useless:<10}  PF_FILL={c.pf_fill:<10}\n")

            # DRAM stats
            for dname in dram_names_sorted:
                if dname in g.dram_stats:
                    d = g.dram_stats[dname]
                    f.write(f"  [{dname}]\n")
                    f.write(f"    RQ_ROW_HIT={d.rq_row_hit:<10}  RQ_ROW_MISS={d.rq_row_miss:<10}\n")
                    f.write(f"    WQ_ROW_HIT={d.wq_row_hit:<10}  WQ_ROW_MISS={d.wq_row_miss:<10}\n")
                    f.write(f"    WQ_FULL={d.wq_full}\n")
                    f.write(f"    AVG_DBUS_CONGESTED={format_avg_dbus(d.dbus_cycle_congested, d.dbus_count_congested)}\n")

            f.write("\n")

    print(f"[AGG] Aggregated stats written to: {output_path} ({len(groups)} unique caller IPs)")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    # Determine input file
    if len(sys.argv) >= 2:
        input_path = sys.argv[1]
    else:
        # Default: look for memory_object_stats.txt in the project root
        script_dir = os.path.dirname(os.path.abspath(__file__))
        input_path = os.path.join(os.path.dirname(script_dir), 'memory_object_stats.txt')

    if not os.path.isfile(input_path):
        print(f"[AGG] ERROR: Input file not found: {input_path}", file=sys.stderr)
        sys.exit(1)

    print(f"[AGG] Parsing: {input_path}")
    objects = parse_file(input_path)
    print(f"[AGG] Parsed {len(objects)} objects")

    if not objects:
        print("[AGG] No objects found, nothing to aggregate.")
        return

    # Group by caller_ip
    groups_map = {}
    for obj in objects:
        ip = obj['caller_ip']
        if ip not in groups_map:
            groups_map[ip] = GroupedStats(ip)
        groups_map[ip].add_object(obj)

    groups = list(groups_map.values())
    print(f"[AGG] Grouped into {len(groups)} unique caller IPs")

    # Collect known cache/dram names from the data (preserve order of appearance)
    cache_names_sorted = []
    dram_names_sorted = []
    seen_cache = set()
    seen_dram = set()
    for g in groups:
        for cname in g.cache_stats:
            if cname not in seen_cache:
                cache_names_sorted.append(cname)
                seen_cache.add(cname)
        for dname in g.dram_stats:
            if dname not in seen_dram:
                dram_names_sorted.append(dname)
                seen_dram.add(dname)

    # Output path (into the current working directory where the script is executed)
    output_path = os.path.join(os.getcwd(), 'caller_ip_status.txt')

    write_grouped_stats(groups, output_path, cache_names_sorted, dram_names_sorted)


if __name__ == '__main__':
    main()