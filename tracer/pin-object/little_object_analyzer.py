#!/usr/bin/env python3
"""
高性能低内存流式 Memory Allocation Trace File Analyzer
"""

import struct
import sys
import os
import glob
import lzma
import argparse

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
    1: 'malloc', 2: 'free', 3: 'mmap', 4: 'munmap',
    5: 'calloc', 6: 'realloc', 7: 'aligned_alloc',
    8: 'posix_memalign', 9: 'memalign', 10: 'fortran_alloc',
    11: 'valloc', 12: '__libc_memalign', 16: 'realloc_inplace'
}

def read_malloc_binary(filename):
    """高效的分块流式读取，避免一次性载入"""
    is_xz = filename.endswith('.xz')
    open_func = lzma.open if is_xz else open
    
    # 32字节的固定的结构体格式 (ip removed from the binary record)
    fmt = "<QQQB7s"
    struct_size = struct.calcsize(fmt)
    
    with open_func(filename, "rb") as f:
        # 约 2.0MB 的读取缓冲区以加速 I/O (32 bytes * 64K records)
        chunk_size = 32 * 1024 * 64
        while True:
            chunk = f.read(chunk_size)
            if not chunk:
                break

            offset = 0
            while offset < len(chunk):
                record = chunk[offset:offset+struct_size]
                if len(record) < struct_size:
                    break

                arg1, arg2, ret, etype, _ = struct.unpack(fmt, record)
                yield etype, arg1, arg2, ret
                offset += struct_size

def process_malloc_binary(filename):
    # 基础统计，仅使用轻量标量
    func_stats = {k: 0 for k in TYPE_MAP.values()}
    
    # 核心精简状态账本：只保留 ACTIVE 对象。
    # 结构: ptr -> allocated_size
    # 释放后立刻 pop，内存中永远只保留当前的"活对象"
    active_heap = {}
    
    # 各阈值的水位线控制 (仅维护当前的整型大小，杜绝维护历史对象多级字典)
    thresholds = [8, 16, 32, 64, 128, 256, 512, 1024, 2048, 4096, 8192, 16384, 32768, 65536, 131072]
    current_sizes = {t: 0 for t in thresholds}
    peak_sizes = {t: 0 for t in thresholds}
    peak_moment_sizes = {t: 0 for t in thresholds}  # original_peak 时刻的 aligned size 快照
    threshold_object_counts = {t: 0 for t in thresholds}
    
    original_current_size = 0
    original_peak_size = 0

    # 记录所有 >=32KB 的大对象 (ptr -> (size, alloc_type))
    all_large_objects = []  # 所有曾分配过的大对象，每项 (ptr, size, alloc_type)
    # 峰值时刻的大对象快照
    peak_large_objects = {}
    
    print("Streaming processing data to minimize memory footprint...")
    
    record_gen = read_malloc_binary(filename)
    
    for etype, arg1, arg2, ret in record_gen:
        func_name = TYPE_MAP.get(etype, 'unknown')
        
        if etype in (1, 3, 5, 6, 7, 8, 9, 10, 11, 12, 16):  # 分配类行为
            func_stats[func_name] += 1
            
            size = arg2 if etype in (6, 16) else arg1 # realloc/realloc_inplace: size in arg2
                
            if ret != 0:
                # 发生 realloc 覆盖时，前置清理旧指针占用的内存
                if etype in (6, 16) and arg1 != 0 and arg1 in active_heap:
                    old_sz = active_heap.pop(arg1)
                    original_current_size -= old_sz
                    for t in thresholds:
                        old_aligned = next_power_of_2(old_sz) if old_sz < t else old_sz
                        current_sizes[t] -= old_aligned
                
                # 记录新对象
                active_heap[ret] = size
                original_current_size += size
                if size >= 32768:
                    all_large_objects.append((ret, size, func_name))

                for t in thresholds:
                    if size < t:
                        threshold_object_counts[t] += 1
                    aligned_sz = next_power_of_2(size) if size < t else size
                    current_sizes[t] += aligned_sz
                    if current_sizes[t] > peak_sizes[t]:
                        peak_sizes[t] = current_sizes[t]

                if original_current_size > original_peak_size:
                    original_peak_size = original_current_size
                    # 峰值时刻，保存 aligned sizes 和大对象快照
                    peak_moment_sizes = dict(current_sizes)
                    peak_large_objects = dict((p, (s, t)) for p, s, t in all_large_objects if p in active_heap)

        elif etype in (2, 4):  # 释放类行为 (free, munmap)
            func_stats[func_name] += 1
            
            ptr = arg1
            if ptr in active_heap:
                old_sz = active_heap.pop(ptr) # ★关键：立刻从内存哈希表中弹出销毁！
                original_current_size -= old_sz
                
                for t in thresholds:
                    old_aligned = next_power_of_2(old_sz) if old_sz < t else old_sz
                    current_sizes[t] -= old_aligned

    # 接下来把轻量化的汇总数据整理输出到最后的报告文件（控制台 + result.log）
    base_name = os.path.splitext(filename)[0]
    if base_name.endswith('.malloc'): base_name = base_name[:-7]
    
    with open(base_name + ".result.log", "w") as log_out:
        sys.stdout = Tee(sys.stdout, log_out)
        
        alloc_types = ['malloc', 'calloc', 'realloc', 'mmap', 'aligned_alloc', 'posix_memalign', 'memalign', 'fortran_alloc', 'valloc', '__libc_memalign', 'realloc_inplace']
        free_types = ['free', 'munmap']
        total_alloc = sum(func_stats[t] for t in alloc_types)
        total_dealloc = sum(func_stats[t] for t in free_types)
        print("\n=== Function Call Statistics ===")
        print(f"Total Alloc calls: {total_alloc}")
        print(f"Total Free calls:  {total_dealloc}")
        print(f"Active objects remaining in memory: {len(active_heap)}")

        print("\n--- Breakdown by Type ---")
        breakdown_order = [('malloc', 1), ('calloc', 5), ('realloc', 6), ('realloc_inplace', 16),
                           ('posix_memalign', 8), ('fortran_alloc', 10), ('mmap', 3),
                           ('free', 2), ('munmap', 4)]
        print(f"{'Type':<18} {'Code':>4}  {'Count':>14}")
        print("-" * 38)
        for name, code in breakdown_order:
            count = func_stats.get(name, 0)
            if count > 0 or name in ('malloc','free','mmap','munmap'):
                print(f"{name:<18} {code:>4}  {count:>14,}")

        print("\n=== Peak Memory Usage Summary ===")
        print(f"Original Physical Peak: {format_size(original_peak_size)}")
        print("\n Threshold   Aligned Increase               Increase %   Objects (interval)   % of Total Objs")
        print("-" * 100)
        prev = 0
        for t in thresholds:
            increase = peak_moment_sizes[t] - original_peak_size
            inc_pct = (increase / original_peak_size * 100) if original_peak_size > 0 else 0
            delta = threshold_object_counts[t] - prev
            obj_pct = (threshold_object_counts[t] / total_alloc * 100) if total_alloc > 0 else 0
            print(f"{t:>9}  {increase:>27,}  {inc_pct:>9.2f}%  {delta:>16,}  {obj_pct:>15.2f}%")
            prev = threshold_object_counts[t]

        # 输出所有 >=32KB 的大对象列表，按大小降序排列
        if all_large_objects:
            sorted_large = sorted(all_large_objects, key=lambda x: x[1], reverse=True)
            with open(base_name + ".objects.log", "w") as obj_out:
                obj_out.write(f"{'Address':>18}  {'Size':>12}  {'Type':<18}\n")
                obj_out.write("-" * 52 + "\n")
                for ptr, sz, atype in sorted_large:
                    obj_out.write(f"0x{ptr:016x}  {sz:>12,}  {atype:<18}\n")
            print(f"Large objects (>=32KB) report ({len(all_large_objects)} total) saved to: {base_name}.objects.log")
        else:
            with open(base_name + ".objects.log", "w") as obj_out:
                obj_out.write("No objects >= 32KB found.\n")
            print("No objects >= 32KB found.")

        print(f"Analysis successfully done. Output logs saved to base: {base_name}")

        # 恢复系统的标准输出流
        sys.stdout = sys.__stdout__

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='High Performance streaming Analyzer')
    parser.add_argument('-i', '--input', required=True, help='Path to malloc.bin or malloc.bin.xz, or "all" to process all *.malloc.bin.xz in current directory')
    args = parser.parse_args()

    if args.input.lower() == 'all':
        files = sorted(glob.glob('*.malloc.bin.xz'))
        if not files:
            print("No *.malloc.bin.xz files found in current directory.")
            sys.exit(1)
        print(f"Processing {len(files)} file(s):")
        for f in files:
            print(f"\n  --- {f} ---")
            process_malloc_binary(f)
        print("\nAll files processed.")
    else:
        process_malloc_binary(args.input)
