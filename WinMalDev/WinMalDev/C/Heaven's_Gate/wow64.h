#pragma once
#include <Windows.h>

//
// Definitions used for running native x64 code from a wow64 process
// https://github.com/rapid7/meterpreter/blob/5e24206d510a48db284d5f399a6951cd1b4c754b/source/common/arch/win/i386/base_inject.h
//
typedef BOOL(WINAPI* X64FUNCTION)(
    DWORD dwParameter
    );

typedef DWORD(WINAPI* EXECUTEX64)(
    X64FUNCTION pFunction, 
    DWORD dwParameter
    );


//
// The context used for injection via migrate_via_remotethread_wow64
//
typedef struct _WOW64CONTEXT {
    union {
        HANDLE hProcess;
        BYTE bPadding2[8];
    } h;

    union {
        LPVOID lpStartAddress;
        BYTE bPadding1[8];
    } s;

    union {
        LPVOID lpParameter;
        BYTE bPadding2[8];
    } p;
    union {
        HANDLE hThread;
        BYTE bPadding2[8];
    } t;
} WOW64CONTEXT, * LPWOW64CONTEXT;