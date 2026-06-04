#!/usr/bin/env python3
"""
高性能低内存流式 Memory Allocation Trace File Analyzer
"""

import struct
import sys
import os
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
    
    # 40字节的固定的结构体格式
    fmt = "<QQQQB7s"
    struct_size = struct.calcsize(fmt)
    
    with open_func(filename, "rb") as f:
        # 约 2.5MB 的读取缓冲区以加速 I/O (40 bytes * 64K records)
        chunk_size = 40 * 1024 * 64
        while True:
            chunk = f.read(chunk_size)
            if not chunk:
                break

            offset = 0
            while offset < len(chunk):
                record = chunk[offset:offset+struct_size]
                if len(record) < struct_size:
                    break

                ip, arg1, arg2, ret, etype, _ = struct.unpack(fmt, record)
                yield ip, etype, arg1, arg2, ret
                offset += struct_size

def process_malloc_binary(filename):
    # 基础统计，仅使用轻量标量
    func_stats = {k: 0 for k in TYPE_MAP.values()}
    
    # 核心精简状态账本：只保留 ACTIVE 对象。
    # 结构: ptr -> (allocated_size, ip)
    # 释放后立刻 pop，内存中永远只保留当前的“活对象”
    active_heap = {}
    
    # 各阈值的水位线控制 (仅维护当前的整型大小，杜绝维护历史对象多级字典)
    thresholds = [8, 16, 32, 64, 128, 256, 512, 1024]
    current_sizes = {t: 0 for t in thresholds}
    peak_sizes = {t: 0 for t in thresholds}
    threshold_object_counts = {t: 0 for t in thresholds}
    
    original_current_size = 0
    original_peak_size = 0
    
    # 轻量化的 IP 汇总表 (由一亿减小到几千，安全无虞)
    ip_stats = {} 
    
    print("Streaming processing data to minimize memory footprint...")
    
    record_gen = read_malloc_binary(filename)
    
    for ip, etype, arg1, arg2, ret in record_gen:
        func_name = TYPE_MAP.get(etype, 'unknown')
        
        if etype in (1, 3, 5, 6, 7, 8, 9, 10, 11, 12, 16):  # 分配类行为
            func_stats[func_name] += 1
            
            size = arg2 if etype in (6, 16) else arg1 # realloc/realloc_inplace: size in arg2
                
            if ret != 0:
                # 发生 realloc 覆盖时，前置清理旧指针占用的内存
                if etype in (6, 16) and arg1 != 0 and arg1 in active_heap:
                    old_sz, _ = active_heap.pop(arg1)
                    original_current_size -= old_sz
                    for t in thresholds:
                        old_aligned = next_power_of_2(old_sz) if old_sz < t else old_sz
                        current_sizes[t] -= old_aligned
                
                # 记录新对象
                active_heap[ret] = (size, ip)
                original_current_size += size
                if original_current_size > original_peak_size:
                    original_peak_size = original_current_size
                    
                for t in thresholds:
                    if size < t:
                        threshold_object_counts[t] += 1
                    aligned_sz = next_power_of_2(size) if size < t else size
                    current_sizes[t] += aligned_sz
                    if current_sizes[t] > peak_sizes[t]:
                        peak_sizes[t] = current_sizes[t]
                        
                # 增量记录 IP
                if ip not in ip_stats:
                    ip_stats[ip] = {'count': 0, 'size': 0}
                ip_stats[ip]['count'] += 1
                ip_stats[ip]['size'] += size

        elif etype in (2, 4):  # 释放类行为 (free, munmap)
            func_stats[func_name] += 1
            
            ptr = arg1
            if ptr in active_heap:
                old_sz, _ = active_heap.pop(ptr) # ★关键：立刻从内存哈希表中弹出销毁！
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
        
        print("\n=== Peak Memory Usage Summary ===")
        print(f"Original Physical Peak: {format_size(original_peak_size)}")
        print("\n Threshold   Aligned Increase     Increase %   Objects < Thresh")
        print("-" * 75)
        for t in thresholds:
            increase = peak_sizes[t] - original_peak_size
            inc_pct = (increase / original_peak_size * 100) if original_peak_size > 0 else 0
            print(f"{t:>9}  {format_size(increase):>19}  {inc_pct:>9.2f}%  {threshold_object_counts[t]:>16,}")
            
    # 恢复系统的标准输出流
    sys.stdout = sys.__stdout__
    
    # 异步写入轻量级全局 ip 表
    with open(base_name + ".ips.log", "w") as ip_out:
        ip_out.write("IP,Count,Total_Allocated_Bytes\n")
        for ip, stats in sorted(ip_stats.items(), key=lambda x: x[1]['size'], reverse=True):
            ip_out.write(f"{hex(ip)},{stats['count']},{stats['size']}\n")
            
    print(f"Analysis successfully done. Output logs saved to base: {base_name}")

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='High Performance streaming Analyzer')
    parser.add_argument('-i', '--input', required=True, help='Path to malloc.bin or malloc.bin.xz')
    args = parser.parse_args()
    process_malloc_binary(args.input)
