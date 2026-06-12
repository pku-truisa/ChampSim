# Object Tracer Wrapper (LD_PRELOAD)

`libobject_tracer_wrapper.so` 是一个轻量级的 LD_PRELOAD 拦截库，**无需 PIN** 即可提取任意程序的 malloc trace，生成与 `little_object_analyzer.py` 完全兼容的二进制 trace 文件。

## 与 PIN + object_tracer 方案对比

| 特性 | PIN + object_tracer.so | LD_PRELOAD wrapper |
|------|----------------------|-------------------|
| 需要 PIN 工具 | ✅ 需要安装 PIN | ❌ 不需要 |
| 性能开销 | 较大（指令级插桩） | 极小（仅拦截分配函数） |
| 替换分配器 | ❌ 不支持（mimalloc/jemalloc/tcmalloc） | ✅ 完全支持 |
| 多线程安全 | ✅ | ✅ `pwrite()` + 原子偏移 |
| new/delete 拦截 | ✅ | ✅ |
| aligned_alloc/memalign | ✅ | ✅ |
| 兼容已有分析器 | ✅ `malloc.bin` | ✅ 同一格式 |

## 编译

```bash
gcc -shared -fPIC -o libobject_tracer_wrapper.so object_tracer_wrapper.cpp -ldl
```

## 用法

### 1. 基本用法（glibc 默认分配器）

```bash
TRACE_FILE=my_trace.bin LD_PRELOAD=./libobject_tracer_wrapper.so ./your_program
```

### 2. 替换为 mimalloc

```bash
TRACE_FILE=my_trace.bin LD_PRELOAD=./libobject_tracer_wrapper.so:/usr/local/lib/libmimalloc.so ./your_program
```

### 3. 替换为 jemalloc

```bash
TRACE_FILE=my_trace.bin LD_PRELOAD=./libobject_tracer_wrapper.so:/path/to/libjemalloc.so ./your_program
```

### 4. 替换为 tcmalloc

```bash
TRACE_FILE=my_trace.bin LD_PRELOAD=./libobject_tracer_wrapper.so:/path/to/libtcmalloc.so ./your_program
```

### 5. 使用默认输出文件名

```bash
LD_PRELOAD=./libobject_tracer_wrapper.so ./your_program
# 输出到 trace_wrapper.bin
```

### 6. 分析 trace

```bash
python3 little_object_analyzer.py -i my_trace.bin -o my_trace.objects.log
```

## 环境变量

| 变量 | 默认值 | 说明 |
|------|--------|------|
| `TRACE_FILE` | `trace_wrapper.bin` | 二进制 trace 输出路径 |
| `TRACE_LOG` | `trace_wrapper.log` | 文本日志输出路径 |

## 拦截的分配类型

| 类型码 | 符号 | 说明 |
|--------|------|------|
| 1 | `malloc`, `aligned_alloc`, `memalign` | 标准/对齐 malloc |
| 5 | `_Znwm` | C++ `operator new` |
| 6 | `_Znam` | C++ `operator new[]` |
| 7 | `calloc` | 清零分配 |
| 11 | `realloc` | 重新分配 |
| 15 | `posix_memalign` | 对齐分配 |
| 16 | `mmap` | 内存映射 |
| 17 | `munmap` | 解除映射 |
| 18 | `free` | 标准释放 |
| 22 | `_ZdlPv` | C++ `operator delete` |
| 23 | `_ZdaPv` | C++ `operator delete[]` |

## 二进制 trace 格式

每条记录 32 字节，与 object_tracer v5 完全兼容：

```
struct malloc_record {
  unsigned long long arg1;   // 大小（alloc）/ 旧地址（realloc）
  unsigned long long arg2;   // 0（alloc）/ 新大小（realloc）/ 对齐（posix_memalign）
  unsigned long long ret;    // 返回地址
  unsigned char      type;   // 类型码（1-23）
  unsigned char      reserved[7];
};
```

## 测试验证

### 4 种分配器对比结果

对同一个 `test/test_malloc` 程序（25 次分配 + 10 次释放），分别使用 glibc、tcmalloc、mimalloc、jemalloc 运行，结果汇总如下：

| 指标 | glibc | tcmalloc | mimalloc | jemalloc |
|------|-------|----------|----------|----------|
| 兼容性 | ✅ | ✅ | ✅ | ✅ |
| Trace 文件大小 | 1,152 B | 1,216 B | 1,024 B | 1,024 B |
| 记录操作数 | 36 (26A+10F) | 38 (30A+8F) | 32 (24A+8F) | 32 (24A+8F) |
| 物理峰值内存 | 2.09 MiB | 2.09 MiB | 2.09 MiB | 2.09 MiB |
| 对齐开销 | 58,398 B (2.66%) | **58,838 B (2.68%)** | 58,398 B (2.66%) | 58,398 B (2.66%) |
| 执行时间（real） | **0.001s** | 0.004s | 0.002s | 0.002s |
| malloc 调用数 | 13 | **15**（+2 初始化） | 11 | 11 |
| realloc 调用数 | 5 | **7**（+2 初始化） | 5 | 5 |

- **glibc**：基线，最快，无额外开销
- **tcmalloc**：线程缓存初始化增加少量内部 malloc/realloc 调用，对齐开销略高 0.02%；对大并发场景优势明显
- **mimalloc** / **jemalloc**：初始化简洁，开销与 glibc 相当，内存对齐效率高

### 测试命令速查

```bash
# 编译
make wrapper test

# glibc 基线测试
TRACE_FILE=test/glibc.bin LD_PRELOAD=./libobject_tracer_wrapper.so ./test/test_malloc

# tcmalloc 测试（系统已安装）
TRACE_FILE=test/tcmalloc.bin LD_PRELOAD=./libobject_tracer_wrapper.so:/usr/lib/x86_64-linux-gnu/libtcmalloc.so ./test/test_malloc

# mimalloc 测试
TRACE_FILE=test/mimalloc.bin LD_PRELOAD=./libobject_tracer_wrapper.so:/usr/local/lib/libmimalloc.so ./test/test_malloc

# jemalloc 测试（系统已安装）
TRACE_FILE=test/jemalloc.bin LD_PRELOAD=./libobject_tracer_wrapper.so:/usr/lib/x86_64-linux-gnu/libjemalloc.so ./test/test_malloc

# 分析 trace
python3 little_object_analyzer.py -i test/glibc.bin
python3 little_object_analyzer.py -i test/tcmalloc.bin
python3 little_object_analyzer.py -i test/mimalloc.bin
python3 little_object_analyzer.py -i test/jemalloc.bin
```

### 已验证的测试文件

- `verify_new.bin` / `verify_new.result.log` — C++ test_malloc + glibc
- `verify_fortran.bin` / `verify_fortran.result.log` — Fortran test_fortran + mimalloc
- `fortran_glibc_fixed.bin` / `fortran_glibc_fixed.result.log` — Fortran + glibc
- `fortran_mimalloc_fixed.bin` / `fortran_mimalloc_fixed.result.log` — Fortran + mimalloc
- `trace_wrapper_glibc.*` — C++ test_malloc + glibc（第一版）
- `trace_wrapper_mimalloc.*` — C++ test_malloc + mimalloc（第一版）
- `glibc.bin/result.log` — test_malloc + glibc（完整对比版）
- `tcmalloc.bin/result.log` — test_malloc + tcmalloc
- `mimalloc.bin/result.log` — test_malloc + mimalloc
- `jemalloc.bin/result.log` — test_malloc + jemalloc

## 注意事项

1. **递归保护**：wrapper 使用 `__thread int in_trace` 防止 `write()/pwrite()` 内部触发 `malloc` 导致的无限递归
2. **线程安全**：多线程写入使用 `pwrite()` + 原子 `__sync_fetch_and_add`，确保记录不错位
3. **符号解析**：使用 `dlsym(RTLD_NEXT)` 找到实际的分配器函数，支持各种 LD_PRELOAD 链