/*
 * Copyright (C) 2004-2021 Intel Corporation.
 * SPDX-License-Identifier: MIT
 */

#include "pin.H"
#include <iostream>
#include <fstream>
#include <cstddef>
#include <cstring>
using std::cerr;
using std::endl;
using std::hex;
using std::ios;
using std::string;

/* ===================================================================== */
/* Global Variables */
/* ===================================================================== */

std::ofstream TraceFile;

/* ===================================================================== */
/* Commandline Switches */
/* ===================================================================== */

KNOB< string > KnobOutputFile(KNOB_MODE_WRITEONCE, "pintool", "o", "malloctrace.out", "specify trace file name");

/* ===================================================================== */

/* Pointers to the real functions */
static void* (*real_malloc)(size_t)           = nullptr;
static void* (*real_calloc)(size_t, size_t)   = nullptr;
static void* (*real_realloc)(void*, size_t)   = nullptr;

/* ===================================================================== */
/* Analysis / callback routines                                          */
/* ===================================================================== */

static VOID MallocBefore(ADDRINT size, ADDRINT ret_ip)
{
    TraceFile << "malloc before(size=" << size << ", ret_ip=" << ret_ip << ")" << endl;
}

static VOID CallocBefore(ADDRINT nmemb, ADDRINT size, ADDRINT ret_ip)
{
    TraceFile << "calloc before(nmemb=" << nmemb << ", size=" << size << ", ret_ip=" << ret_ip << ")" << endl;
}

static VOID ReallocBefore(ADDRINT ptr, ADDRINT size, ADDRINT ret_ip)
{
    TraceFile << "realloc before(ptr=" << ptr << ", size=" << size << ", ret_ip=" << ret_ip << ")" << endl;
}

static VOID AllocAfter(ADDRINT ret)
{
    TraceFile << "  after(" << ret << ")" << endl;
}

static VOID FreeBefore(ADDRINT ptr)
{
    TraceFile << "free before(ptr=" << ptr << ")" << endl;
}

/* ===================================================================== */
/* Instrumentation routines                                              */
/* ===================================================================== */

VOID Image(IMG img, VOID* v)
{
    // --- malloc ---
    {
        RTN rtn = RTN_FindByName(img, "malloc");
        if (RTN_Valid(rtn))
        {
            RTN_Open(rtn);
            real_malloc = (void* (*)(size_t))RTN_Funptr(rtn);

            RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)MallocBefore,
                           IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
                           IARG_RETURN_IP, IARG_END);
            RTN_InsertCall(rtn, IPOINT_AFTER, (AFUNPTR)AllocAfter,
                           IARG_FUNCRET_EXITPOINT_VALUE, IARG_END);

            RTN_Close(rtn);
        }
    }

    // --- calloc ---
    {
        RTN rtn = RTN_FindByName(img, "calloc");
        if (RTN_Valid(rtn))
        {
            RTN_Open(rtn);
            real_calloc = (void* (*)(size_t, size_t))RTN_Funptr(rtn);

            RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)CallocBefore,
                           IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
                           IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
                           IARG_RETURN_IP, IARG_END);
            RTN_InsertCall(rtn, IPOINT_AFTER, (AFUNPTR)AllocAfter,
                           IARG_FUNCRET_EXITPOINT_VALUE, IARG_END);

            RTN_Close(rtn);
        }
    }

    // --- realloc ---
    {
        RTN rtn = RTN_FindByName(img, "realloc");
        if (RTN_Valid(rtn))
        {
            RTN_Open(rtn);
            real_realloc = (void* (*)(void*, size_t))RTN_Funptr(rtn);

            RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)ReallocBefore,
                           IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
                           IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
                           IARG_RETURN_IP, IARG_END);
            RTN_InsertCall(rtn, IPOINT_AFTER, (AFUNPTR)AllocAfter,
                           IARG_FUNCRET_EXITPOINT_VALUE, IARG_END);

            RTN_Close(rtn);
        }
    }

    // --- free ---
    {
        RTN rtn = RTN_FindByName(img, "free");
        if (RTN_Valid(rtn))
        {
            RTN_Open(rtn);
            RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)FreeBefore,
                           IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
                           IARG_END);
            RTN_Close(rtn);
        }
    }
}

/* ===================================================================== */

VOID Fini(INT32 code, VOID* v) { TraceFile.close(); }

/* ===================================================================== */
/* Print Help Message                                                    */
/* ===================================================================== */

INT32 Usage()
{
    cerr << "This tool produces a trace of calls to malloc / calloc / realloc / free." << endl;
    cerr << endl << KNOB_BASE::StringKnobSummary() << endl;
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

    TraceFile.open(KnobOutputFile.Value().c_str());
    TraceFile << hex;
    TraceFile.setf(ios::showbase);

    IMG_AddInstrumentFunction(Image, 0);
    PIN_AddFiniFunction(Fini, 0);

    PIN_StartProgram();

    return 0;
}

/* ===================================================================== */
/* eof */
/* ===================================================================== */