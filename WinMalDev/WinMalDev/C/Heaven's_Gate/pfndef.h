#pragma once
#include <Windows.h>
#include <TlHelp32.h>

typedef BOOL (WINAPI* pfnVirtualProtectEx)(
    IN HANDLE hProcess, 
    IN LPVOID lpAddress, 
    IN SIZE_T dwSize, 
    IN DWORD  flNewProtect, 
    OUT PDWORD lpflOldProtect
    );

typedef BOOL (WINAPI* pfnWriteProcessMemory)(
    IN  HANDLE  hProcess,
    IN  LPVOID  lpBaseAddress,
    IN  LPCVOID lpBuffer,
    IN  SIZE_T  nSize,
    OUT SIZE_T* lpNumberOfBytesWritten
    );

typedef LPVOID (WINAPI* pfnVirtualAllocEx)(
    IN           HANDLE hProcess,
    IN OPTIONAL  LPVOID lpAddress,
    IN           SIZE_T dwSize,
    IN           DWORD  flAllocationType,
    IN           DWORD  flProtect
    );

typedef LPVOID (WINAPI* pfnVirtualAlloc)(
    IN OPTIONAL  LPVOID lpAddress,
    IN           SIZE_T dwSize,
    IN           DWORD  flAllocationType,
    IN           DWORD  flProtect
);

typedef BOOL (WINAPI* pfnVirtualFree)(
    IN LPVOID lpAddress,
    IN SIZE_T dwSize,
    IN DWORD  dwFreeType
);

typedef HANDLE (WINAPI* pfnOpenProcess)(
    IN DWORD dwDesiredAccess,
    IN BOOL  bInheritHandle,
    IN DWORD dwProcessId
);

typedef HANDLE (WINAPI* pfnCreateRemoteThread)(
    IN  HANDLE                 hProcess,
    IN  LPSECURITY_ATTRIBUTES  lpThreadAttributes,
    IN  SIZE_T                 dwStackSize,
    IN  LPTHREAD_START_ROUTINE lpStartAddress,
    IN  LPVOID                 lpParameter,
    IN  DWORD                  dwCreationFlags,
    OUT LPDWORD                lpThreadId
);

typedef HANDLE (WINAPI* pfnCreateToolhelp32Snapshot)(
    IN DWORD dwFlags,
    IN DWORD th32ProcessID
);

typedef BOOL (WINAPI* pfnProcess32FirstW)(
    IN      HANDLE            hSnapshot,
    IN OUT  LPPROCESSENTRY32W lppe
);

typedef BOOL (WINAPI* pfnProcess32NextW)(
    IN  HANDLE            hSnapshot,
    OUT LPPROCESSENTRY32W lppe
);

typedef BOOL (WINAPI* pfnCloseHandle)(
    IN HANDLE hObject
    );

typedef DWORD (WINAPI* pfnResumeThread)(
    IN HANDLE hThread
);