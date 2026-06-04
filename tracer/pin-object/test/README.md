# Object Tracer Test Suite

本目录包含 Object Tracer v3 (`object_tracer.cpp`) 及其分析器 (`little_object_analyzer.py`) 的测试文件。

## 目录结构

| 文件 | 说明 |
|------|------|
| `test_malloc.cpp` | C/C++ 内存分配综合测试 — 覆盖 malloc/calloc/realloc/posix_memalign/mmap/C++ new 等所有分配类型 |
| `test_analyzer.cpp` | 峰值内存与阈值统计压力测试 — 验证分析器的 peak tracking 和 threshold 计数 |
| `test_fortran.f90` | Fortran ALLOCATE/DEALLOCATE 测试 — 验证 Fortran 分配追踪 |
| `test_analyzer_synthetic.py` | **独立合成测试** — 无需 PIN，生成合成二进制 trace 并验证分析器输出 |
| `pin.log` / `pintool.log` | PIN 运行时日志 |
| `debug.log` / `debug2.log` | 调试日志 |
| `malloc.ips.log` / `malloc.result.log` | 分析器输出示例 |

## 构建测试程序

```bash
# C/C++ 测试
g++ -o test_malloc test_malloc.cpp
g++ -o test_analyzer test_analyzer.cpp

# Fortran 测试
gfortran -o test_fortran test_fortran.f90
```

## 运行测试

### 方式一：完整端到端测试（需要 PIN）

```bash
# 在 tracer/pin-object 目录下执行

# 1. 运行 test_malloc，生成 trace
pin -t obj-intel64/object_tracer.so -m test/malloc.bin -- test/test_malloc

# 2. 用分析器分析 trace
python3 little_object_analyzer.py -i test/malloc.bin

# 3. 检查输出的 malloc.result.log 和 malloc.ips.log
cat test/malloc.result.log
cat test/malloc.ips.log

# 4. 同样方式测试 test_analyzer 和 test_fortran
pin -t obj-intel64/object_tracer.so -m test/analyzer.bin -- test/test_analyzer
python3 little_object_analyzer.py -i test/analyzer.bin

pin -t obj-intel64/object_tracer.so -m test/fortran.bin -- test/test_fortran
python3 little_object_analyzer.py -i test/fortran.bin
```

### 方式二：独立合成测试（无需 PIN）

```bash
# 在 ChampSim 根目录下执行
python3 tracer/pin-object/test/test_analyzer_synthetic.py
```

此测试自动生成包含所有分配类型（malloc/free/calloc/realloc/realloc_inplace/mmap/munmap/posix_memalign/fortran_alloc）的合成二进制 trace，运行分析器并验证结果。预计 11 项测试全部通过。

### test_analyzer.cpp 预期输出

| 阈值 | Objects < Thresh | 说明 |
|------|-----------------|------|
| < 8  | 1               | malloc(7) |
| < 16 | 2               | 以上 + malloc(15) |
| < 32 | 4               | 以上 + malloc(31) + calloc(2,15) |
| < 64 | 4               | 以上（无新增 < 64 的分配） |

峰值内存约为 4.05 MiB（Phase 3 中的大分配阶段）。

### test_malloc.cpp 覆盖的分配类型

| 类型码 | 类型 | 测试方式 |
|--------|------|---------|
| 1 | malloc | 直接调用 + aligned_alloc/memalign/C++ new |
| 2 | free | 直接调用 + delete |
| 3 | mmap | MAP_ANONYMOUS |
| 4 | munmap | - |
| 5 | calloc | 2 参数形式 |
| 6 | realloc (搬迁) | realloc 到更大内存 |
| 8 | posix_memalign | 带对齐参数 |
| 16 | realloc_inplace (原地) | realloc 到更小或同大小内存 |

## 已知问题

### 已修复 Bug（2026-06）

**`realloc_inplace` (type=16) 内存翻倍计算**

- **位置**: `little_object_analyzer.py` 第 109 行
- **原因**: 仅对 `etype == 6` 做旧分配清理，遗漏了 `etype == 16`
- **修复**: 改为 `etype in (6, 16)`
- **影响**: 任何使用 realloc 并发生原地扩展/缩减的场景，峰值内存统计会虚高
- **测试覆盖**: `test_analyzer_synthetic.py` Phase 5 包含专门的 type=16 验证