#!/usr/bin/env python3
"""
Trace Memory Object Access Analyzer
====================================
Analyzes a ChampSim 64-byte instruction trace (.xz or raw binary) to compute
per-object load/store counts.

The trace format is the 64-byte input_instr struct defined in inc/trace_instruction.h:
  - instr_type == 2 : memory allocation/deallocation event
      instr_info encodes the type (1=malloc,2=calloc,3=realloc,4=free,
                                    5=mmap,6=mmap64,7=mremap,8=munmap,
                                    9=main-begin,10=posix_memalign,11=aligned_alloc)
  - instr_type == 0/1 : normal/branch instruction
      source_memory[0..3] = load addresses
      destination_memory[0..1] = store addresses

The tool maintains a sorted list of currently-active memory objects (VA ranges),
and for each instruction's load/store addresses, it looks up the owning object
via binary search and increments the corresponding counter.

Usage:
    python trace_object_analyzer.py <trace.xz> [-o output.log] [-n topN]
    python trace_object_analyzer.py <trace.bin> [-o output.log] [-n topN]

Output:
    A tab-separated table sorted by total accesses (loads+stores) descending.
"""

import struct
import sys
import os
import bisect
import argparse
import lzma
from collections import defaultdict
import json

# =========================================================================
# 64-byte input_instr format (see inc/trace_instruction.h)
#   struct input_instr {
#       unsigned long long ip;                    # [0..7]       8B
#       unsigned char instr_type;                 # [8]          1B
#       unsigned char instr_info;                 # [9]          1B
#       unsigned char destination_registers[2];   # [10..11]     2B
#       unsigned char source_registers[4];        # [12..15]     4B
#       unsigned long long destination_memory[2]; # [16..31]    16B
#       unsigned long long source_memory[4];      # [32..63]    32B
#   };  // total = 64 bytes
# =========================================================================
INSTR_FMT = "<QBB2B4B2Q4Q"   # 8 + 1 + 1 + 2 + 4 + 16 + 32 = 64
INSTR_SIZE = struct.calcsize(INSTR_FMT)  # = 64

# =========================================================================
# Allocation type codes (matching inc/trace_instruction.h and inc/memory_object_table.h)
# =========================================================================
ALLOC_TYPE_NAMES = {
    0:  'NORMAL',
    1:  'MALLOC',
    2:  'CALLOC',
    3:  'REALLOC',
    4:  'FREE',
    5:  'MMAP',
    6:  'MMAP64',
    7:  'MREMAP',
    8:  'MUNMAP',
    9:  'MAIN_BEGIN',
    10: 'POSIX_MEMALIGN',
    11: 'ALIGNED_ALLOC',
}

# Alloc events that create a new allocation with a range [addr, addr+size)
_ALLOC_CREATE = {1, 2, 5, 6, 10, 11}
# Alloc events that create a new allocation AND free an old one
_ALLOC_REPLACE = {3, 7}
# Alloc events that free an allocation
_ALLOC_FREE = {4, 8}
# All types that represent allocation events (not real instructions)
_ALLOC_EVENTS = _ALLOC_CREATE | _ALLOC_REPLACE | _ALLOC_FREE | {9}


def open_trace(filename):
    """Open a trace file for binary reading. Supports .xz compression."""
    if filename.endswith('.xz'):
        return lzma.open(filename, 'rb')
    else:
        return open(filename, 'rb')


def read_records(filename):
    """Yield parsed (ip, instr_type, instr_info, dst_mem, src_mem) from a 64-byte trace file.

    Yields tuples: (ip, instr_type, instr_info, destination_memory[2], source_memory[4]).
    """
    # Use a chunk size that's a multiple of INSTR_SIZE (64) to keep alignment
    CHUNK_RAW = 2 * 1024 * 1024   # 2 MiB
    CHUNK_SIZE = (CHUNK_RAW // INSTR_SIZE) * INSTR_SIZE

    with open_trace(filename) as f:
        remainder = b''
        while True:
            data = f.read(CHUNK_SIZE)
            if not data:
                break
            frame = remainder + data
            offset = 0
            fsize = len(frame)
            while offset + INSTR_SIZE <= fsize:
                rec = frame[offset:offset + INSTR_SIZE]
                ip, itype, iinfo, \
                    dst_reg0, dst_reg1, \
                    src_reg0, src_reg1, src_reg2, src_reg3, \
                    dst_mem0, dst_mem1, \
                    src_mem0, src_mem1, src_mem2, src_mem3 = \
                    struct.unpack(INSTR_FMT, rec)
                dst_mem = [dst_mem0, dst_mem1]
                src_mem = [src_mem0, src_mem1, src_mem2, src_mem3]
                yield ip, itype, iinfo, dst_mem, src_mem
                offset += INSTR_SIZE
            remainder = frame[offset:]


class ActiveObjectTable:
    """Maintains a sorted list of active memory objects for fast VA→object lookup.

    Internally stores parallel arrays that stay sorted by vaddr_start.
    Uses bisect for O(log N) lookup.
    """

    def __init__(self):
        # Parallel arrays, sorted by vaddr_start
        self.starts = []    # vaddr_start of each active object
        self.ends = []      # vaddr_end (exclusive) of each active object
        self.ids = []       # alloc_id of each active object

    def insert(self, vaddr_start, vaddr_end, alloc_id):
        """Insert a new active object. Maintains sorted order by vaddr_start."""
        idx = bisect.bisect_left(self.starts, vaddr_start)
        self.starts.insert(idx, vaddr_start)
        self.ends.insert(idx, vaddr_end)
        self.ids.insert(idx, alloc_id)

    def remove(self, vaddr_start):
        """Remove the active object with the given vaddr_start. Returns its alloc_id."""
        idx = bisect.bisect_left(self.starts, vaddr_start)
        if idx < len(self.starts) and self.starts[idx] == vaddr_start:
            alloc_id = self.ids[idx]
            self.starts.pop(idx)
            self.ends.pop(idx)
            self.ids.pop(idx)
            return alloc_id
        return None

    def find(self, addr):
        """Find the alloc_id of the active object containing address `addr`.
        Returns None if no active object covers this address.
        """
        if not self.starts:
            return None
        # Find the rightmost object with vaddr_start <= addr
        idx = bisect.bisect_right(self.starts, addr) - 1
        if idx >= 0 and addr < self.ends[idx]:
            return self.ids[idx]
        return None


def process_trace(filename, top_n=None):
    """Main analysis: read trace file and compute per-object load/store counts.

    Returns (obj_stats, active_table, total_records, total_alloc_events, total_normal_instrs)
    where obj_stats is a dict: alloc_id -> {
        'loads': int, 'stores': int, 'size': int, 'alloc_type': int,
        'vaddr_start': int, 'vaddr_end': int
    }
    """
    active_table = ActiveObjectTable()

    # Per-object statistics: alloc_id -> stats dict
    # Note: we keep records for objects even after they're freed, to accumulate
    # their final stats. When an object is freed, we finalize its stats.
    obj_stats = {}

    # Tracks the next alloc_id
    next_alloc_id = 1

    total_records = 0
    total_alloc_events = 0
    total_normal_instrs = 0

    for ip, itype, iinfo, dst_mem, src_mem in read_records(filename):
        total_records += 1

        # ---- Handle allocation events (instr_type == 2) ----
        if itype == 2:
            total_alloc_events += 1
            atype = iinfo  # allocation type

            # Type=9 (main_begin) is a marker record; just skip it
            if atype == 9:
                continue

            if atype in _ALLOC_CREATE:
                # malloc, calloc, mmap, mmap64, posix_memalign, aligned_alloc
                #   src_mem[0] = size
                #   dst_mem[0] = allocated address
                size = src_mem[0]
                addr = dst_mem[0]
                if addr != 0 and size > 0:
                    alloc_id = next_alloc_id
                    next_alloc_id += 1
                    active_table.insert(addr, addr + size, alloc_id)
                    obj_stats[alloc_id] = {
                        'loads': 0,
                        'stores': 0,
                        'size': size,
                        'alloc_type': atype,
                        'vaddr_start': addr,
                        'vaddr_end': addr + size,
                    }

            elif atype in _ALLOC_REPLACE:
                # realloc (3):    src_mem[0]=old_ptr, src_mem[1]=new_size, dst_mem[0]=new_ptr
                # mremap (7):     src_mem[0]=old_addr, src_mem[1]=old_size, dst_mem[0]=new_addr
                old_ptr = src_mem[0]
                new_size = src_mem[1]
                new_addr = dst_mem[0]

                # Remove the old allocation
                if old_ptr != 0:
                    removed_id = active_table.remove(old_ptr)
                    if removed_id is not None and removed_id in obj_stats:
                        pass  # stats preserved for final report

                # Add the new allocation
                if new_addr != 0 and new_size > 0:
                    alloc_id = next_alloc_id
                    next_alloc_id += 1
                    active_table.insert(new_addr, new_addr + new_size, alloc_id)
                    obj_stats[alloc_id] = {
                        'loads': 0,
                        'stores': 0,
                        'size': new_size,
                        'alloc_type': atype,
                        'vaddr_start': new_addr,
                        'vaddr_end': new_addr + new_size,
                    }

            elif atype in _ALLOC_FREE:
                # free (4):   src_mem[0] = pointer
                # munmap (8): src_mem[0] = addr
                ptr = src_mem[0]
                if ptr != 0:
                    removed_id = active_table.remove(ptr)
                    if removed_id is not None and removed_id in obj_stats:
                        pass  # stats preserved

            # Skip the allocation event itself (not a real instruction)
            continue

        # ---- Handle normal instructions (instr_type == 0 or 1) ----
        total_normal_instrs += 1

        # Process load addresses (source_memory[0..3])
        for addr in src_mem[:4]:
            if addr != 0:
                obj_id = active_table.find(addr)
                if obj_id is not None and obj_id in obj_stats:
                    obj_stats[obj_id]['loads'] += 1

        # Process store addresses (destination_memory[0..1])
        for addr in dst_mem[:2]:
            if addr != 0:
                obj_id = active_table.find(addr)
                if obj_id is not None and obj_id in obj_stats:
                    obj_stats[obj_id]['stores'] += 1

    return obj_stats, active_table, total_records, total_alloc_events, total_normal_instrs


def simplify_size(n):
    """Convert size to human-readable string with K/M/G suffix."""
    if n >= 1024 * 1024 * 1024 and n % (1024 * 1024 * 1024) == 0:
        return f"{n // (1024 * 1024 * 1024)}G"
    if n >= 1024 * 1024 and n % (1024 * 1024) == 0:
        return f"{n // (1024 * 1024)}M"
    if n >= 1024 and n % 1024 == 0:
        return f"{n // 1024}K"
    return str(n)


def format_size(n):
    """Format size with appropriate unit."""
    if n >= 1024 * 1024 * 1024:
        return f"{n / (1024 * 1024 * 1024):.2f} GiB"
    if n >= 1024 * 1024:
        return f"{n / (1024 * 1024):.2f} MiB"
    if n >= 1024:
        return f"{n / 1024:.2f} KiB"
    return f"{n} B"


class Tee:
    """Duplicate output to multiple file objects."""
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


def output_results(obj_stats, active_table, total_records, total_alloc_events,
                   total_normal_instrs, filename, top_n=None, output_path=None):
    """Print analysis results as a formatted table.

    Results are sorted by total accesses (loads + stores) descending.
    """
    base_name = os.path.splitext(filename)[0]
    if base_name.endswith('.trace'):
        base_name = base_name[:-6]

    if output_path is None:
        output_path = base_name + '.objects.log'

    with open(output_path, 'w') as log_out:
        sys.stdout = Tee(sys.stdout, log_out)

        # ---- Summary ----
        print("=" * 70)
        print("  Memory Object Access Analysis")
        print("=" * 70)
        print(f"  Trace file:            {filename}")
        print(f"  Total records:         {total_records:,}")
        print(f"  Alloc/free events:     {total_alloc_events:,}")
        print(f"  Normal instructions:   {total_normal_instrs:,}")
        print(f"  Active objects (end):  {len(active_table.starts):,}")
        print(f"  Total unique objects:  {len(obj_stats):,}")
        print()

        # ---- Per-object statistics table ----
        if not obj_stats:
            print("  No allocation events found in the trace.")
            print("=" * 70)
            sys.stdout = sys.__stdout__
            return

        # Build rows sorted by total accesses descending
        rows = []
        for oid, stats in obj_stats.items():
            total_accesses = stats['loads'] + stats['stores']
            rows.append((
                total_accesses,
                stats['loads'],
                stats['stores'],
                stats['size'],
                stats['alloc_type'],
                stats['vaddr_start'],
                stats['vaddr_end'],
                oid,
            ))

        rows.sort(key=lambda r: -r[0])  # sort by total_accesses descending

        # Apply top-N limit
        if top_n is not None and top_n > 0:
            rows = rows[:top_n]

        # Determine column widths
        headers = ['Rank', 'Object ID', 'Start Address', 'End Address',
                   'Size', 'Sizefmt', 'Type', 'Loads', 'Stores', 'Total']
        col_widths = [len(h) for h in headers]

        formatted_rows = []
        for rank, (total_acc, loads, stores, size, atype, vaddr_start, vaddr_end, oid) in enumerate(rows, 1):
            rank_s = str(rank)
            oid_s = str(oid)
            start_s = f"0x{vaddr_start:016x}"
            end_s = f"0x{vaddr_end:016x}"
            size_s = f"{size:,}"
            sizefmt_s = format_size(size)
            type_s = ALLOC_TYPE_NAMES.get(atype, f"UNKNOWN({atype})")
            loads_s = f"{loads:,}"
            stores_s = f"{stores:,}"
            total_s = f"{total_acc:,}"

            formatted = (rank_s, oid_s, start_s, end_s, size_s, sizefmt_s,
                         type_s, loads_s, stores_s, total_s)
            formatted_rows.append(formatted)

            # Update max column widths
            for ci, val in enumerate(formatted):
                col_widths[ci] = max(col_widths[ci], len(val))

        # Fix column widths (minimum widths for readability)
        for ci in range(len(col_widths)):
            col_widths[ci] = max(col_widths[ci], len(headers[ci]))

        # Print table
        print(f"  Per-Object Statistics (sorted by total accesses, top {len(rows)} of {len(obj_stats)})")
        print(f"  {'-' * (sum(col_widths) + 3 * (len(col_widths) - 1))}")

        # Header
        header_line = ""
        for ci, h in enumerate(headers):
            if ci <= 3:  # left-aligned: Rank, Object ID, Start, End
                header_line += f"  {h:<{col_widths[ci]}}"
            elif ci == 5:  # skip Sizefmt in header
                continue
            else:
                header_line += f"  {h:>{col_widths[ci]}}"
        print(header_line)

        # Separator
        sep_line = ""
        for ci in range(len(col_widths)):
            if ci == 5:  # skip Sizefmt
                continue
            sep_line += "  " + "-" * col_widths[ci]
        print(sep_line)

        # Data rows
        for row in formatted_rows:
            line = ""
            for ci in range(len(col_widths)):
                if ci == 5:  # skip Sizefmt
                    continue
                val = row[ci]
                if ci <= 3:  # left-aligned
                    line += f"  {val:<{col_widths[ci]}}"
                else:
                    line += f"  {val:>{col_widths[ci]}}"
            print(line)

        # ---- Also print active objects summary ----
        print()
        print(f"  Objects still active at end of trace: {len(active_table.starts):,}")
        print(f"  Total objects ever allocated:         {len(obj_stats):,}")
        print("=" * 70)

        sys.stdout = sys.__stdout__

    # Also write a CSV version for easier analysis
    csv_path = output_path.rsplit('.', 1)[0] + '.objects.csv'
    with open(csv_path, 'w') as csv_out:
        csv_out.write("rank,object_id,vaddr_start,vaddr_end,size,size_fmt,alloc_type,loads,stores,total\n")
        for rank, (total_acc, loads, stores, size, atype, vaddr_start, vaddr_end, oid) in enumerate(rows, 1):
            type_s = ALLOC_TYPE_NAMES.get(atype, f"UNKNOWN({atype})")
            sizefmt_s = format_size(size)
            csv_out.write(f"{rank},{oid},0x{vaddr_start:016x},0x{vaddr_end:016x},{size},{sizefmt_s},{type_s},{loads},{stores},{total_acc}\n")

    print(f"  Analysis saved to: {output_path}")
    print(f"  CSV output saved to: {csv_path}")


def main():
    parser = argparse.ArgumentParser(
        description='Trace Memory Object Access Analyzer — '
                    'analyze a 64-byte ChampSim instruction trace (.xz or raw binary) '
                    'to compute per-object load/store counts.',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s champsim.trace.xz
  %(prog)s champsim.trace.xz -n 100 -o my_results.log
  %(prog)s champsim.trace
        """)
    parser.add_argument('input', help='Path to 64-byte trace file (.xz or raw binary)')
    parser.add_argument('-o', '--output', default=None,
                        help='Output log file path (default: <input>.objects.log)')
    parser.add_argument('-n', '--top', type=int, default=0,
                        help='Show only top N objects (default: all)')
    args = parser.parse_args()

    if not os.path.isfile(args.input):
        print(f"Error: file not found: {args.input}")
        sys.exit(1)

    top_n = args.top if args.top > 0 else None

    print(f"Processing trace file: {args.input}")
    print("Streaming analysis in progress...")

    obj_stats, active_table, total_records, total_alloc_events, total_normal_instrs = \
        process_trace(args.input, top_n=top_n)

    output_results(obj_stats, active_table, total_records, total_alloc_events,
                   total_normal_instrs, args.input, top_n=top_n,
                   output_path=args.output)

    print("\nDone.")


if __name__ == '__main__':
    main()