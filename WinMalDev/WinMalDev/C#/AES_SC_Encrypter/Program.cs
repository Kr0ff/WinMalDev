using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;
// encryption/decryption shamelessly stolen from: https://github.com/shaddy43/AES_Shellcode_Encryptor

namespace AES_SC_Encrypter
{
    class Program
    {
        static string aes_key = "bbzCJMnU6h1W9xHrLpvXcyn3jydQQn1o";
        static string aes_iv = "UH33SE8jmJgkjxvA";
        static void Main(string[] args)
        {
            string hashed = ComputeSha256Hash(aes_key);
            string fixed_hash = hashed.Substring(0, 32);
            aes_key = fixed_hash;

            // Raw shellcode base64 encoded
            // msfvenom -p windows/x64/messagebox TEXT="Hello World" -f raw  | base64 -w 0
            string shellcode = "/EiB5PD////o0AAAAEFRQVBSUVZIMdJlSItSYD5Ii1IYPkiLUiA+SItyUD5ID7dKSk0xyUgxwKw8YXwCLCBBwckNQQHB4u1SQVE+SItSID6LQjxIAdA+i4CIAAAASIXAdG9IAdBQPotIGD5Ei0AgSQHQ41xI/8k+QYs0iEgB1k0xyUgxwKxBwckNQQHBOOB18T5MA0wkCEU50XXWWD5Ei0AkSQHQZj5BiwxIPkSLQBxJAdA+QYsEiEgB0EFYQVheWVpBWEFZQVpIg+wgQVL/4FhBWVo+SIsS6Un///9dScfBAAAAAD5IjZX+AAAAPkyNhQoBAABIMclBukWDVgf/1UgxyUG68LWiVv/VSGVsbG8gV29ybGQATWVzc2FnZUJveAA=";
            
            // Getting the size of the shellcode
            byte[] shellcodeBytes = Convert.FromBase64String(shellcode);
            int scSize = shellcodeBytes.Length;

            byte[] byte_encrypted = EncryptAES(Convert.ToBase64String(shellcodeBytes));
            string finalEncoded = Convert.ToBase64String(byte_encrypted);

            Console.WriteLine("Shellcode size: " + scSize);
            Console.WriteLine("Encrypted Bytes: \r\n\r\n" + finalEncoded);



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

        public static string ByteArrayToString(byte[] ba)
        {
            StringBuilder hex = new StringBuilder(ba.Length * 2);

            for (int i = 0; i < ba.Length - 1; i++)
            {
                hex.AppendFormat("0x" + "{0:x2}" + ", ", ba[i]);
            }

            hex.AppendFormat("0x" + "{0:x2}", ba[ba.Length - 1]);
            return hex.ToString();
        }

        public static byte[] EncryptAES(string plainText)
        {
            byte[] encrypted;

            using (AesCryptoServiceProvider aes = new AesCryptoServiceProvider())
            {
                aes.Key = Encoding.ASCII.GetBytes(aes_key);
                aes.IV = Encoding.ASCII.GetBytes(aes_iv);

                aes.Mode = CipherMode.CBC;
                aes.Padding = PaddingMode.PKCS7;

                ICryptoTransform enc = aes.CreateEncryptor(aes.Key, aes.IV);

                using (MemoryStream ms = new MemoryStream())
                {
                    using (CryptoStream cs = new CryptoStream(ms, enc, CryptoStreamMode.Write))
                    {
                        
                        using (StreamWriter sw = new StreamWriter(cs))
                        {
                            sw.Write(plainText);
                        }
                        

                        encrypted = ms.ToArray();
                    }
                }
            }

            return encrypted;
        }
    }
}
