#!/usr/bin/env python3
"""
Analyze ChampSim memory_object_stats.txt output.

Parses per-object statistics from the flat-format output (matching plain_printer.cc)
and writes a one-line-per-object summary:
  object_id  va_addr  size  caller_ip  L1D_access  L1D_miss_rate  L1D_pf_requested  L1D_pf_issued  L1D_pf_useful  L1D_pf_useless  L1D_pf_fill  L1D_pf_accuracy  ...

Sorted by L1D access descending.

Usage:
    python3 analyze_memory_object_stats.py [input_file] [-o output_file]

Default input:  memory_object_stats.txt
Default output: object_summary.txt
"""

import re
import sys
import argparse

# ---------------------------------------------------------------------------
# Regex patterns for parsing (new flat format matching plain_printer.cc)
# ---------------------------------------------------------------------------
# Object header line:
#   Object ID=123  Type=MALLOC  Size=4096  VA_Start=0x7f...  Caller=0x4a...
OBJ_HEADER_RE = re.compile(
    r'Object\s+ID=(?P<obj_id>\d+)\s+'
    r'Type=\S+\s+'
    r'Size=(?P<size>\d+)\s+'
    r'VA_Start=0x(?P<va>[0-9a-fA-F]+)\s+'
    r'Caller=0x(?P<caller_ip>[0-9a-fA-F]+)'
)

# Cache stats line (flat format, per-access-type lines only - skip TOTAL):
#   cpu0-><cache_name> LOAD         ACCESS:  129342986 HIT:   75380776 MISS:   53962210 MSHR_MERGE:   27947479
#   cpu0-><cache_name> RFO          ACCESS:          0 HIT:          0 MISS:          0 MSHR_MERGE:          0
CACHE_STATS_RE = re.compile(
    r'cpu0->(?P<cache_name>[^\s]+)\s+'
    r'(?:LOAD|RFO|PREFETCH|WRITE|TRANSLATION)\s+'
    r'ACCESS:\s*(?P<access>\d+)\s+'
    r'HIT:\s*(?P<hits>\d+)\s+'
    r'MISS:\s*(?P<misses>\d+)\s+'
    r'MSHR_MERGE:\s*(?P<mshr_merge>\d+)'
)

# Prefetch stats line:
#   cpu0-><cache_name> PREFETCH REQUESTED:          0 ISSUED:          0 USEFUL:          0 USELESS:          0 FILL:          0
PF_STATS_RE = re.compile(
    r'cpu0->(?P<cache_name>[^\s]+)\s+'
    r'PREFETCH REQUESTED:\s*(?P<pf_req>\d+)\s+'
    r'ISSUED:\s*(?P<pf_issued>\d+)\s+'
    r'USEFUL:\s*(?P<pf_useful>\d+)\s+'
    r'USELESS:\s*(?P<pf_useless>\d+)'
    r'(?:\s+FILL:\s*(?P<pf_fill>\d+))?'
)

# Cache name extractor for the header-less flat format.
# We detect cache sections by scanning for CACHE_STATS_RE matches,
# rather than relying on separate section headers.

# ---------------------------------------------------------------------------
# Data holder for one object
# ---------------------------------------------------------------------------
class ObjectInfo:
    __slots__ = ('obj_id', 'va', 'size', 'caller_ip', 'cache_stats', 'cache_prefetch')

    def __init__(self, obj_id: int, va: int, size: int, caller_ip: int):
        self.obj_id = obj_id
        self.va = va
        self.size = size
        self.caller_ip = caller_ip
        # cache_name -> (total_access, total_misses)
        self.cache_stats: dict[str, tuple[int, int]] = {}
        # cache_name -> (pf_req, pf_issued, pf_useful, pf_useless, pf_fill)
        self.cache_prefetch: dict[str, tuple[int, int, int, int, int]] = {}

    # Note: Access counts are aggregated per cache. TOTAL lines are used
    # for overall access counts (no need to sum across types unless needed).

    def total_access(self, cache_substr: str) -> int:
        """Sum hits+misses across all cache sections whose name contains 'cache_substr'."""
        total = 0
        for cname, (hits, misses) in self.cache_stats.items():
            if cache_substr in cname:
                total += hits + misses
        return total

    def total_misses(self, cache_substr: str) -> int:
        """Sum misses across all cache sections whose name contains 'cache_substr'."""
        total = 0
        for cname, (hits, misses) in self.cache_stats.items():
            if cache_substr in cname:
                total += misses
        return total

    def miss_rate(self, cache_substr: str) -> float:
        ta = self.total_access(cache_substr)
        if ta == 0:
            return 0.0
        return self.total_misses(cache_substr) / ta * 100.0

    def total_pf(self, cache_substr: str, field_idx: int) -> int:
        """Sum a specific prefetch field across matching cache sections.
        field_idx: 0=pf_req, 1=pf_issued, 2=pf_useful, 3=pf_useless, 4=pf_fill
        """
        total = 0
        for cname, vals in self.cache_prefetch.items():
            if cache_substr in cname:
                total += vals[field_idx]
        return total

    def pf_accuracy(self, cache_substr: str) -> float:
        issued = self.total_pf(cache_substr, 1)
        if issued == 0:
            return 0.0
        useful = self.total_pf(cache_substr, 2)
        return useful / issued * 100.0


# ---------------------------------------------------------------------------
# Parser
# ---------------------------------------------------------------------------
def parse_input(filepath: str) -> list[ObjectInfo]:
    """Return list of ObjectInfo parsed from the input file."""
    objects: list[ObjectInfo] = []
    current_obj: ObjectInfo | None = None

    with open(filepath, 'r') as f:
        for line in f:
            # --- Object header ---
            m = OBJ_HEADER_RE.search(line)
            if m:
                current_obj = ObjectInfo(
                    obj_id=int(m.group('obj_id')),
                    va=int(m.group('va'), 16),
                    size=int(m.group('size')),
                    caller_ip=int(m.group('caller_ip'), 16),
                )
                objects.append(current_obj)
                continue

            if current_obj is None:
                continue

            # --- Cache stats (flat format, per-type lines only) ---
            m = CACHE_STATS_RE.match(line)
            if m:
                cache_name = m.group('cache_name')
                hits = int(m.group('hits'))
                misses = int(m.group('misses'))
                # Aggregate across all access types for each cache
                prev_hits, prev_misses = current_obj.cache_stats.get(cache_name, (0, 0))
                current_obj.cache_stats[cache_name] = (
                    prev_hits + hits,
                    prev_misses + misses,
                )
                continue

            # --- Prefetch stats line ---
            m = PF_STATS_RE.match(line)
            if m:
                cache_name = m.group('cache_name')
                pf_req = int(m.group('pf_req'))
                pf_issued = int(m.group('pf_issued'))
                pf_useful = int(m.group('pf_useful'))
                pf_useless = int(m.group('pf_useless'))
                # FILL is now part of the flat format line; default to 0 for older logs that lack it
                pf_fill = int(m.group('pf_fill')) if m.group('pf_fill') else 0
                prev = current_obj.cache_prefetch.get(cache_name, (0, 0, 0, 0, 0))
                current_obj.cache_prefetch[cache_name] = (
                    prev[0] + pf_req,
                    prev[1] + pf_issued,
                    prev[2] + pf_useful,
                    prev[3] + pf_useless,
                    prev[4] + pf_fill,
                )

    return objects


# ---------------------------------------------------------------------------
# Output writer
# ---------------------------------------------------------------------------
def write_output(objects: list[ObjectInfo], output_path: str, caches: list[str]):
    """Write one line per object, sorted by L1D access descending."""
    # Sort by L1D access descending; if all zero, fall back to L2, then LLC
    def sort_key(o: ObjectInfo) -> tuple:
        return (-o.total_access(caches[0]),
                -o.total_access(caches[1]) if len(caches) > 1 else 0,
                -o.total_access(caches[2]) if len(caches) > 2 else 0)

    sorted_objs = sorted(objects, key=sort_key)

    COL_W = {
        'object_id': 12,
        'va_addr': 20,
        'size': 12,
        'caller_ip': 20,
        'access': 14,
        'miss_rate': 14,
        'pf_req': 14,
        'pf_issued': 14,
        'pf_useful': 14,
        'pf_useless': 14,
        'pf_fill': 14,
        'pf_accuracy': 14,
    }
    PF_COL_NAMES = ['pf_requested', 'pf_issued', 'pf_useful', 'pf_useless', 'pf_fill', 'pf_accuracy']

    # Build header list
    headers = ['object_id', 'va_addr', 'size', 'caller_ip']
    pf_col_keys = ['pf_req', 'pf_issued', 'pf_useful', 'pf_useless', 'pf_fill', 'pf_accuracy']
    for cname in caches:
        headers.append(f'{cname}_access')
        headers.append(f'{cname}_miss_rate')
        for col in PF_COL_NAMES:
            headers.append(f'{cname}_{col}')

    # Build format string
    fmt_parts = [
        f'{{:<{COL_W["object_id"]}}}',
        f'{{:<{COL_W["va_addr"]}}}',
        f'{{:<{COL_W["size"]}}}',
        f'{{:<{COL_W["caller_ip"]}}}',
    ]
    for _ in caches:
        fmt_parts.append(f'{{:>{COL_W["access"]}}}')
        fmt_parts.append(f'{{:>{COL_W["miss_rate"]}}}')
        for k in pf_col_keys:
            fmt_parts.append(f'{{:>{COL_W[k]}}}')
    fmt_str = '  '.join(fmt_parts)

    with open(output_path, 'w') as f:
        # Header line
        hdr_fmt_parts = [
            f'{{:<{COL_W["object_id"]}}}',
            f'{{:<{COL_W["va_addr"]}}}',
            f'{{:<{COL_W["size"]}}}',
            f'{{:<{COL_W["caller_ip"]}}}',
        ]
        for _ in caches:
            hdr_fmt_parts.append(f'{{:>{COL_W["access"]}}}')
            hdr_fmt_parts.append(f'{{:>{COL_W["miss_rate"]}}}')
            for k in pf_col_keys:
                hdr_fmt_parts.append(f'{{:>{COL_W[k]}}}')
        hdr_fmt = '  '.join(hdr_fmt_parts)
        print(hdr_fmt.format(*headers), file=f)

        # Data lines
        for obj in sorted_objs:
            row = [
                str(obj.obj_id),
                hex(obj.va),
                str(obj.size),
                hex(obj.caller_ip),
            ]
            for cname in caches:
                row.append(str(obj.total_access(cname)))
                row.append(f'{obj.miss_rate(cname):.2f}%')
                # Prefetch fields
                row.append(str(obj.total_pf(cname, 0)))  # pf_req
                row.append(str(obj.total_pf(cname, 1)))  # pf_issued
                row.append(str(obj.total_pf(cname, 2)))  # pf_useful
                row.append(str(obj.total_pf(cname, 3)))  # pf_useless
                row.append(str(obj.total_pf(cname, 4)))  # pf_fill
                row.append(f'{obj.pf_accuracy(cname):.2f}%')
            print(fmt_str.format(*row), file=f)

    print(f'Written {len(sorted_objs)} object(s) to {output_path}', file=sys.stderr)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main():
    parser = argparse.ArgumentParser(
        description='Analyze ChampSim memory_object_stats.txt into per-object summary.'
    )
    parser.add_argument(
        'input', nargs='?', default='memory_object_stats.txt',
        help='Path to input file (default: memory_object_stats.txt)',
    )
    parser.add_argument(
        '-o', '--output', default='object_summary.txt',
        help='Path to output file (default: object_summary.txt)',
    )
    parser.add_argument(
        '--caches', nargs='*', default=['L1D', 'L2', 'LLC'],
        help='Cache levels to include (default: L1D L2 LLC)',
    )
    args = parser.parse_args()

    objects = parse_input(args.input)
    if not objects:
        print(f'No objects found in {args.input}', file=sys.stderr)
        sys.exit(1)

    write_output(objects, args.output, args.caches)


if __name__ == '__main__':
    main()