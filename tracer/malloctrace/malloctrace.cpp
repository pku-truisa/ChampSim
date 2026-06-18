/*
 * Copyright (C) 2004-2021 Intel Corporation.
 * SPDX-License-Identifier: MIT
 *
 * Pin tool: memory allocation tracing using RTN_ReplaceSignature.
 * Output format: binary malloc_record_t (compatible with nopin-object tracer).
 *
 * Type encoding:
 *   1=malloc, 2=calloc, 3=realloc, 4=free,
 *   5=mmap, 6=mmap64, 7=mremap, 8=munmap, 9=main_begin
 */

#include "pin.H"
#include <iostream>
#include <fstream>
#include <cstring>
#include <unistd.h>
#include <fcntl.h>
#include <sys/mman.h>

using std::cerr;
using std::endl;
using std::hex;
using std::dec;
using std::string;

/* ===================================================================== */
/* Binary record format (compatible with nopin-object)                   */
/* ===================================================================== */
typedef struct {
  unsigned long long arg1;
  unsigned long long arg2;
  unsigned long long ret;
  unsigned long long caller_ip;
  unsigned char type;
  unsigned char reserved[7];
} __attribute__((packed)) malloc_record_t;

enum {
  TYPE_MALLOC  = 1,
  TYPE_CALLOC  = 2,
  TYPE_REALLOC = 3,
  TYPE_FREE    = 4,
  TYPE_MMAP    = 5,
  TYPE_MMAP64  = 6,
  TYPE_MREMAP  = 7,
  TYPE_MUNMAP  = 8,
  TYPE_MAIN_BEGIN = 9,
};

/* ===================================================================== */
/* Commandline Switches                                                  */
/* ===================================================================== */

KNOB<string> KnobOutputFile(KNOB_MODE_WRITEONCE, "pintool", "o", "malloctrace.out", "specify trace file name");

/* ===================================================================== */
/* Global State                                                          */
/* ===================================================================== */

static int trace_fd = -1;
static volatile unsigned long long write_offset = 0;

/* ===================================================================== */
/* Real function pointers                                                */
/* ===================================================================== */

static void* (*real_malloc)(size_t) = nullptr;
static void* (*real_calloc)(size_t, size_t) = nullptr;
static void* (*real_realloc)(void*, size_t) = nullptr;
static void  (*real_free)(void*) = nullptr;
static void* (*real_mmap)(void*, size_t, int, int, int, off_t) = nullptr;
static int   (*real_munmap)(void*, size_t) = nullptr;
static void* (*real_mremap)(void*, size_t, size_t, int, ...) = nullptr;

/* ===================================================================== */
/* Helper: write one record atomically                                   */
/* ===================================================================== */
static void write_rec(unsigned char t, unsigned long long a1,
                      unsigned long long a2, unsigned long long ret,
                      unsigned long long caller_ip)
{
    malloc_record_t rec;
    rec.arg1      = a1;
    rec.arg2      = a2;
    rec.ret       = ret;
    rec.caller_ip = caller_ip;
    rec.type      = t;
    memset(rec.reserved, 0, sizeof(rec.reserved));

    unsigned long long off = __sync_fetch_and_add(&write_offset, sizeof(rec));
    pwrite(trace_fd, &rec, sizeof(rec), off);
}

/* ===================================================================== */
/* Replacement Analysis Routines                                         */
/* ===================================================================== */

void* NewMalloc(size_t size, ADDRINT caller_ip)
{
    void* ret = real_malloc(size);
    write_rec(TYPE_MALLOC, size, 0, (unsigned long long)ret, (unsigned long long)caller_ip);
    return ret;
}

void* NewCalloc(size_t nmemb, size_t size, ADDRINT caller_ip)
{
    void* ret = real_calloc(nmemb, size);
    write_rec(TYPE_CALLOC, nmemb, size, (unsigned long long)ret, (unsigned long long)caller_ip);
    return ret;
}

void* NewRealloc(void* ptr, size_t size, ADDRINT caller_ip)
{
    void* ret = real_realloc(ptr, size);
    write_rec(TYPE_REALLOC, (unsigned long long)ptr, size,
              (unsigned long long)ret, (unsigned long long)caller_ip);
    return ret;
}

void NewFree(void* ptr, ADDRINT caller_ip)
{
    real_free(ptr);
    if (ptr != nullptr) {
        write_rec(TYPE_FREE, (unsigned long long)ptr, 0, 0, (unsigned long long)caller_ip);
    }
}

void* NewMmap(void* addr, size_t length, int prot, int flags, int fd, off_t offset, ADDRINT caller_ip)
{
    void* ret = real_mmap(addr, length, prot, flags, fd, offset);
    if (ret != MAP_FAILED) {
        write_rec(TYPE_MMAP, length, 0, (unsigned long long)ret, (unsigned long long)caller_ip);
    }
    return ret;
}

void* NewMremap(void* old_addr, size_t old_size, size_t new_size, int flags, void* new_addr, ADDRINT caller_ip)
{
    void* ret = real_mremap(old_addr, old_size, new_size, flags, new_addr);
    if (ret != MAP_FAILED) {
        write_rec(TYPE_MREMAP, (unsigned long long)old_addr, old_size,
                  (unsigned long long)ret, (unsigned long long)caller_ip);
    }
    return ret;
}

int NewMunmap(void* addr, size_t length, ADDRINT caller_ip)
{
    write_rec(TYPE_MUNMAP, (unsigned long long)addr, length, 0, (unsigned long long)caller_ip);
    return real_munmap(addr, length);
}

/* ===================================================================== */
/* Instrumentation Routine                                               */
/* ===================================================================== */

VOID Image(IMG img, VOID* v)
{
    if (!IMG_Valid(img)) return;

    // --- MALLOC ---
    for (const char* sym : {"malloc", "__libc_malloc"}) {
        if (real_malloc != nullptr) break;
        RTN rtn = RTN_FindByName(img, sym);
        if (RTN_Valid(rtn)) {
            real_malloc = (void* (*)(size_t))RTN_Funptr(rtn);
            RTN_ReplaceSignature(rtn, (AFUNPTR)NewMalloc,
                                 IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
                                 IARG_RETURN_IP,
                                 IARG_END);
            break;
        }
    }

    // --- CALLOC ---
    for (const char* sym : {"calloc", "__libc_calloc", "__calloc"}) {
        if (real_calloc != nullptr) break;
        RTN rtn = RTN_FindByName(img, sym);
        if (RTN_Valid(rtn)) {
            real_calloc = (void* (*)(size_t, size_t))RTN_Funptr(rtn);
            RTN_ReplaceSignature(rtn, (AFUNPTR)NewCalloc,
                                 IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
                                 IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
                                 IARG_RETURN_IP,
                                 IARG_END);
            break;
        }
    }

    // --- REALLOC ---
    for (const char* sym : {"realloc", "__libc_realloc"}) {
        if (real_realloc != nullptr) break;
        RTN rtn = RTN_FindByName(img, sym);
        if (RTN_Valid(rtn)) {
            real_realloc = (void* (*)(void*, size_t))RTN_Funptr(rtn);
            RTN_ReplaceSignature(rtn, (AFUNPTR)NewRealloc,
                                 IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
                                 IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
                                 IARG_RETURN_IP,
                                 IARG_END);
            break;
        }
    }

    // --- FREE ---
    for (const char* sym : {"free", "__libc_free"}) {
        if (real_free != nullptr) break;
        RTN rtn = RTN_FindByName(img, sym);
        if (RTN_Valid(rtn)) {
            real_free = (void (*)(void*))RTN_Funptr(rtn);
            RTN_ReplaceSignature(rtn, (AFUNPTR)NewFree,
                                 IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
                                 IARG_RETURN_IP,
                                 IARG_END);
            break;
        }
    }

    // --- MMAP ---
    for (const char* sym : {"mmap", "__libc_mmap"}) {
        if (real_mmap != nullptr) break;
        RTN rtn = RTN_FindByName(img, sym);
        if (RTN_Valid(rtn)) {
            real_mmap = (void* (*)(void*, size_t, int, int, int, off_t))RTN_Funptr(rtn);
            RTN_ReplaceSignature(rtn, (AFUNPTR)NewMmap,
                                 IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
                                 IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
                                 IARG_FUNCARG_ENTRYPOINT_VALUE, 2,
                                 IARG_FUNCARG_ENTRYPOINT_VALUE, 3,
                                 IARG_FUNCARG_ENTRYPOINT_VALUE, 4,
                                 IARG_FUNCARG_ENTRYPOINT_VALUE, 5,
                                 IARG_RETURN_IP,
                                 IARG_END);
            break;
        }
    }

    // --- MREMAP ---
    for (const char* sym : {"mremap", "__libc_mremap"}) {
        if (real_mremap != nullptr) break;
        RTN rtn = RTN_FindByName(img, sym);
        if (RTN_Valid(rtn)) {
            real_mremap = (void* (*)(void*, size_t, size_t, int, ...))RTN_Funptr(rtn);
            RTN_ReplaceSignature(rtn, (AFUNPTR)NewMremap,
                                 IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
                                 IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
                                 IARG_FUNCARG_ENTRYPOINT_VALUE, 2,
                                 IARG_FUNCARG_ENTRYPOINT_VALUE, 3,
                                 IARG_FUNCARG_ENTRYPOINT_VALUE, 4,
                                 IARG_RETURN_IP,
                                 IARG_END);
            break;
        }
    }

    // --- MUNMAP ---
    for (const char* sym : {"munmap", "__libc_munmap"}) {
        if (real_munmap != nullptr) break;
        RTN rtn = RTN_FindByName(img, sym);
        if (RTN_Valid(rtn)) {
            real_munmap = (int (*)(void*, size_t))RTN_Funptr(rtn);
            RTN_ReplaceSignature(rtn, (AFUNPTR)NewMunmap,
                                 IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
                                 IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
                                 IARG_RETURN_IP,
                                 IARG_END);
            break;
        }
    }
}

/* ===================================================================== */
/* Fini                                                                  */
/* ===================================================================== */

VOID Fini(INT32 code, VOID* v)
{
    if (trace_fd >= 0) close(trace_fd);
}

/* ===================================================================== */
/* Usage                                                                 */
/* ===================================================================== */

INT32 Usage()
{
    cerr << "This tool produces a binary trace of malloc/calloc/realloc/free/mmap* calls."
         << endl << endl << KNOB_BASE::StringKnobSummary() << endl;
    return -1;
}

/* ===================================================================== */
/* Main                                                                  */
/* ===================================================================== */

int main(int argc, char* argv[])
{
    PIN_InitSymbols();
    if (PIN_Init(argc, argv))
    {
        return Usage();
    }

    // Open trace file (binary)
    const string& fname = KnobOutputFile.Value();
    trace_fd = open(fname.c_str(), O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (trace_fd < 0) {
        cerr << "Could not open " << fname << endl;
        return -1;
    }

    IMG_AddInstrumentFunction(Image, 0);
    PIN_AddFiniFunction(Fini, 0);

    PIN_StartProgram();

    return 0;
}