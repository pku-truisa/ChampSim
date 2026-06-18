#include "pin.H"
#include <iostream>
#include <fstream>
#include <cstring>

using std::cerr;
using std::endl;
using std::hex;
using std::dec;
using std::string;

/* ===================================================================== */
/* 命令行参数定义 */
/* ===================================================================== */
KNOB<string> KnobOutputFile(KNOB_MODE_WRITEONCE, "pintool", "o", "malloctrace.out", "specify trace file name");

/* ===================================================================== */
/* 全局变量与真实分配器指针声明 */
/* ===================================================================== */
std::ofstream TraceFile;

static void* (*real_malloc)(size_t) = nullptr;
static void* (*real_calloc)(size_t, size_t) = nullptr;
static void* (*real_realloc)(void*, size_t) = nullptr;
static void  (*real_free)(void*) = nullptr;

/* ===================================================================== */
/* Replacement Analysis Routines (接管执行流的替换函数) */
/* ===================================================================== */

// 替换 Malloc
void* NewMalloc(size_t size, ADDRINT caller_ip)
{
    void* ret = real_malloc(size);

    // 一处现场，同时安全打印入参、返回值和调用起源 IP
    TraceFile << "[TRACE] Malloc  | Size: " << dec << size 
              << " | RetPtr: 0x" << hex << (ADDRINT)ret 
              << " | CallerIP: 0x" << caller_ip << "\n";

    return ret;
}

// 替换 Calloc
void* NewCalloc(size_t nmemb, size_t size, ADDRINT caller_ip)
{
    void* ret = real_calloc(nmemb, size);

    // 参数 100% 准确，彻底闭环别名符号下的寄存器丢失隐患
    TraceFile << "[TRACE] Calloc  | Items: " << dec << nmemb 
              << " | Size: " << size 
              << " | Total: " << (nmemb * size)
              << " | RetPtr: 0x" << hex << (ADDRINT)ret 
              << " | CallerIP: 0x" << caller_ip << "\n";

    return ret;
}

// 替换 Realloc
void* NewRealloc(void* ptr, size_t size, ADDRINT caller_ip)
{
    void* ret = real_realloc(ptr, size);

    TraceFile << "[TRACE] Realloc | OldPtr: 0x" << hex << (ADDRINT)ptr 
              << " | NewSize: " << dec << size 
              << " | NewPtr: 0x" << hex << (ADDRINT)ret 
              << " | CallerIP: 0x" << caller_ip << "\n";

    return ret;
}

// 替换 Free
void NewFree(void* ptr, ADDRINT caller_ip)
{
    real_free(ptr);

    if (ptr != nullptr) {
        TraceFile << "[TRACE] Free    | Ptr: 0x" << hex << (ADDRINT)ptr 
                  << " | CallerIP: 0x" << caller_ip << "\n";
    }
}

/* ===================================================================== */
/* Instrumentation Routine (镜像加载时的动态替换绑定 - 免Open安全版) */
/* ===================================================================== */
VOID Image(IMG img, VOID* v)
{
    if (!IMG_Valid(img)) return;

    // --- 1. 替换 MALLOC 环 ---
    for (const char* sym : {"malloc", "__libc_malloc"}) {
        if (real_malloc != nullptr) break; 

        RTN rtn = RTN_FindByName(img, sym);
        if (RTN_Valid(rtn)) {
            // 【核心修复】：彻底移除 RTN_Open(rtn);
            
            real_malloc = (void* (*)(size_t))RTN_Funptr(rtn);

            RTN_ReplaceSignature(rtn, (AFUNPTR)NewMalloc,
                                 IARG_FUNCARG_ENTRYPOINT_VALUE, 0,  // size
                                 IARG_RETURN_IP,
                                 IARG_END);
            
            // 【核心修复】：彻底移除 RTN_Close(rtn);
            break; // 成功替换后，立刻跳出循环，防止为别名符号二次插桩
        }
    }

    // --- 2. 替换 CALLOC 环 ---
    for (const char* sym : {"calloc", "__libc_calloc", "__calloc"}) {
        if (real_calloc != nullptr) break;

        RTN rtn = RTN_FindByName(img, sym);
        if (RTN_Valid(rtn)) {
            real_calloc = (void* (*)(size_t, size_t))RTN_Funptr(rtn);

            RTN_ReplaceSignature(rtn, (AFUNPTR)NewCalloc,
                                 IARG_FUNCARG_ENTRYPOINT_VALUE, 0,  // nmemb
                                 IARG_FUNCARG_ENTRYPOINT_VALUE, 1,  // size
                                 IARG_RETURN_IP,
                                 IARG_END);
            break;
        }
    }

    // --- 3. 替换 REALLOC 环 ---
    for (const char* sym : {"realloc", "__libc_realloc"}) {
        if (real_realloc != nullptr) break;

        RTN rtn = RTN_FindByName(img, sym);
        if (RTN_Valid(rtn)) {
            real_realloc = (void* (*)(void*, size_t))RTN_Funptr(rtn);

            RTN_ReplaceSignature(rtn, (AFUNPTR)NewRealloc,
                                 IARG_FUNCARG_ENTRYPOINT_VALUE, 0,  // old_ptr
                                 IARG_FUNCARG_ENTRYPOINT_VALUE, 1,  // size
                                 IARG_RETURN_IP,
                                 IARG_END);
            break;
        }
    }

    // --- 4. 替换 FREE 环 ---
    for (const char* sym : {"free", "__libc_free"}) {
        if (real_free != nullptr) break;

        RTN rtn = RTN_FindByName(img, sym);
        if (RTN_Valid(rtn)) {
            real_free = (void (*)(void*))RTN_Funptr(rtn);

            RTN_ReplaceSignature(rtn, (AFUNPTR)NewFree,
                                 IARG_FUNCARG_ENTRYPOINT_VALUE, 0,  // ptr
                                 IARG_RETURN_IP,
                                 IARG_END);
            break;
        }
    }
}

/* ===================================================================== */
/* 退出时的清理动作 */
/* ===================================================================== */
VOID Fini(INT32 code, VOID* v)
{
    TraceFile << "==== [Pin Replace Tracer] Tracing Successfully Finished ====\n";
    TraceFile.close();
}

INT32 Usage()
{
    cerr << "This tool produces a trace of calls to malloc / calloc / realloc / free using RTN_ReplaceSignature." << endl;
    cerr << endl << KNOB_BASE::StringKnobSummary() << endl;
    return -1;
}

/* ===================================================================== */
/* 主函数 */
/* ===================================================================== */
int main(int argc, char* argv[])
{
    PIN_InitSymbols();
    if (PIN_Init(argc, argv))
    {
        return Usage();
    }

    TraceFile.open(KnobOutputFile.Value().c_str());
    TraceFile << hex << std::showbase;

    IMG_AddInstrumentFunction(Image, 0);
    PIN_AddFiniFunction(Fini, 0);

    PIN_StartProgram();

    return 0;
}