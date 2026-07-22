#!/usr/bin/env python3
"""
Analyze ChampSim memory_object_stats.txt output.

Parses per-object statistics and writes a one-line-per-object summary:
  object_id  va_addr  size  caller_ip  L1D_access  L1D_miss_rate  L2_access  L2_miss_rate  LLC_access  LLC_miss_rate

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
# Regex patterns for parsing
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

# Cache section header:   [L1D]   or   [L2_Cache]  etc.
CACHE_SECTION_RE = re.compile(r'^\s+\[(?P<cache_name>[^\]]+)\]')

# Hit/Miss line per access type:
#     LOAD:     HIT=     12345  MISS=100
HIT_MISS_RE = re.compile(
    r'^\s+(?:LOAD|RFO|PREFETCH|WRITE|TRANS):\s+'
    r'HIT=\s*(?P<hits>\d+)\s+'
    r'MISS=\s*(?P<misses>\d+)'
)


# ---------------------------------------------------------------------------
# Data holder for one object
# ---------------------------------------------------------------------------
class ObjectInfo:
    __slots__ = ('obj_id', 'va', 'size', 'caller_ip', 'cache_stats')

    def __init__(self, obj_id: int, va: int, size: int, caller_ip: int):
        self.obj_id = obj_id
        self.va = va
        self.size = size
        self.caller_ip = caller_ip
        self.cache_stats: dict[str, tuple[int, int]] = {}  # cache_name -> (total_access, total_misses)

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


# ---------------------------------------------------------------------------
# Parser
# ---------------------------------------------------------------------------
def parse_input(filepath: str) -> list[ObjectInfo]:
    """Return list of ObjectInfo parsed from the input file."""
    objects: list[ObjectInfo] = []
    current_obj: ObjectInfo | None = None
    current_cache: str | None = None

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
                current_cache = None
                objects.append(current_obj)
                continue

            if current_obj is None:
                continue

            # --- Cache section header ---
            m = CACHE_SECTION_RE.match(line)
            if m:
                current_cache = m.group('cache_name')
                continue

            # --- Hit/Miss line ---
            if current_cache is not None:
                m = HIT_MISS_RE.match(line)
                if m:
                    hits = int(m.group('hits'))
                    misses = int(m.group('misses'))
                    prev_hits, prev_misses = current_obj.cache_stats.get(current_cache, (0, 0))
                    current_obj.cache_stats[current_cache] = (
                        prev_hits + hits,
                        prev_misses + misses,
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

    # Determine column widths for aligned output
    COL_W = {
        'object_id': 12,
        'va_addr': 20,
        'size': 12,
        'caller_ip': 20,
        'access': 14,
        'miss_rate': 14,
    }

    # Build header
    headers = ['object_id', 'va_addr', 'size', 'caller_ip']
    for cname in caches:
        headers.append(f'{cname}_access')
        headers.append(f'{cname}_miss_rate')

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
    fmt_str = '  '.join(fmt_parts)

    with open(output_path, 'w') as f:
        # Header line (right-align the numeric columns)
        hdr_fmt_parts = [
            f'{{:<{COL_W["object_id"]}}}',
            f'{{:<{COL_W["va_addr"]}}}',
            f'{{:<{COL_W["size"]}}}',
            f'{{:<{COL_W["caller_ip"]}}}',
        ]
        for _ in caches:
            hdr_fmt_parts.append(f'{{:>{COL_W["access"]}}}')
            hdr_fmt_parts.append(f'{{:>{COL_W["miss_rate"]}}}')
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