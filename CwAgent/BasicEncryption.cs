using System;
using System.IO;
using System.Text;
using System.Security;
using System.Security.Cryptography;
using System.Runtime.InteropServices;

namespace DoubleAgent
{
    class BasicEncryption
    {
        public static SecureString Decrypt(string cipherText)
        {
            SecureString passphrase = new SecureString();
            passphrase.AppendChar('a');
            passphrase.AppendChar('l');
            passphrase.AppendChar('l');
            passphrase.AppendChar('t');
            passphrase.AppendChar('h');
            passphrase.AppendChar('e');
            passphrase.AppendChar('k');
            passphrase.AppendChar('i');
            passphrase.AppendChar('n');
            passphrase.AppendChar('g');
            passphrase.AppendChar('s');
            passphrase.AppendChar('h');
            passphrase.AppendChar('o');
            passphrase.AppendChar('r');
            passphrase.AppendChar('s');
            passphrase.AppendChar('e');
            passphrase.AppendChar('s');
            passphrase.AppendChar('a');
            passphrase.AppendChar('n');
            passphrase.AppendChar('d');
            passphrase.AppendChar('a');
            passphrase.AppendChar('l');
            passphrase.AppendChar('l');
            passphrase.AppendChar('t');
            passphrase.AppendChar('h');
            passphrase.AppendChar('e');
            passphrase.AppendChar('k');
            passphrase.AppendChar('i');
            passphrase.AppendChar('n');
            passphrase.AppendChar('g');
            passphrase.AppendChar('s');
            passphrase.AppendChar('m');
            passphrase.AppendChar('e');
            passphrase.AppendChar('n');
            passphrase.AppendChar('c');
            passphrase.AppendChar('o');
            passphrase.AppendChar('u');
            passphrase.AppendChar('l');
            passphrase.AppendChar('d');
            passphrase.AppendChar('n');
            passphrase.AppendChar('t');
            passphrase.AppendChar('p');
            passphrase.AppendChar('u');
            passphrase.AppendChar('t');
            passphrase.AppendChar('h');
            passphrase.AppendChar('u');
            passphrase.AppendChar('m');
            passphrase.AppendChar('p');
            passphrase.AppendChar('t');
            passphrase.AppendChar('y');
            passphrase.AppendChar('t');
            passphrase.AppendChar('o');
            passphrase.AppendChar('g');
            passphrase.AppendChar('e');
            passphrase.AppendChar('t');
            passphrase.AppendChar('h');
            passphrase.AppendChar('e');
            passphrase.AppendChar('r');
            passphrase.AppendChar('a');
            passphrase.AppendChar('g');
            passphrase.AppendChar('a');
            passphrase.AppendChar('i');
            passphrase.AppendChar('n');
            passphrase.AppendChar('!');
            passphrase.AppendChar('!');

            SecureString salt = new SecureString();
            salt.AppendChar('1');
            salt.AppendChar('q');
            salt.AppendChar('a');
            salt.AppendChar('z');
            salt.AppendChar('2');
            salt.AppendChar('w');
            salt.AppendChar('s');
            salt.AppendChar('x');
            salt.AppendChar('3');
            salt.AppendChar('e');
            salt.AppendChar('d');
            salt.AppendChar('c');
            salt.AppendChar('4');
            salt.AppendChar('r');
            salt.AppendChar('f');
            salt.AppendChar('v');
            salt.AppendChar('5');
            salt.AppendChar('t');
            salt.AppendChar('g');
            salt.AppendChar('b');
            salt.AppendChar('6');
            salt.AppendChar('y');
            salt.AppendChar('h');
            salt.AppendChar('n');
            salt.AppendChar('7');
            salt.AppendChar('u');
            salt.AppendChar('j');
            salt.AppendChar('m');
            salt.AppendChar('8');
            salt.AppendChar('i');
            salt.AppendChar('k');
            salt.AppendChar(',');
            salt.AppendChar('9');
            salt.AppendChar('o');
            salt.AppendChar('l');
            salt.AppendChar('.');
            salt.AppendChar('0');
            salt.AppendChar('p');
            salt.AppendChar(';');
            salt.AppendChar('/');

            SecureString iv = new SecureString();
            iv.AppendChar('1');
            iv.AppendChar('0');
            iv.AppendChar('!');
            iv.AppendChar(')');
            iv.AppendChar('2');
            iv.AppendChar('9');
            iv.AppendChar('@');
            iv.AppendChar('(');
            iv.AppendChar('3');
            iv.AppendChar('8');
            iv.AppendChar('#');
            iv.AppendChar('*');
            iv.AppendChar('4');
            iv.AppendChar('7');
            iv.AppendChar('$');
            iv.AppendChar('&');

            string hashAlgorithm = "SHA1";
            int passwordIterations = 2;
            int keySize = 256;

            //get pointers to the strings from secure string
            IntPtr iv_ = Marshal.SecureStringToBSTR(iv);
            IntPtr salt_ = Marshal.SecureStringToBSTR(salt); 

            // Convert strings defining encryption key characteristics into byte
            // arrays. Let us assume that strings only contain ASCII codes.
            byte[] initVectorBytes = Encoding.ASCII.GetBytes(Marshal.PtrToStringBSTR(iv_));
            byte[] saltValueBytes = Encoding.ASCII.GetBytes(Marshal.PtrToStringBSTR(salt_));

            //zero the pointers to secure strings
            Marshal.ZeroFreeBSTR(iv_);
            Marshal.ZeroFreeBSTR(salt_);

            // Convert our ciphertext into a byte array.
            byte[] cipherTextBytes = Convert.FromBase64String(cipherText);

            // First, we must create a password, from which the key will be 
            // derived. This password will be generated from the specified 
            // passphrase and salt value. The password will be created using
            // the specified hash algorithm. Password creation can be done in
            // several iterations.
            IntPtr passphrase_ = Marshal.SecureStringToBSTR(passphrase);
            PasswordDeriveBytes password = new PasswordDeriveBytes(Marshal.PtrToStringBSTR(passphrase_),saltValueBytes,hashAlgorithm,passwordIterations);
            Marshal.ZeroFreeBSTR(passphrase_);

            // Use the password to generate pseudo-random bytes for the encryption
            // key. Specify the size of the key in bytes (instead of bits).
            byte[] keyBytes = password.GetBytes(keySize / 8);

            // Create uninitialized Rijndael encryption object.
            RijndaelManaged symmetricKey = new RijndaelManaged();

            // It is reasonable to set encryption mode to Cipher Block Chaining
            // (CBC). Use default options for other symmetric key parameters.
            symmetricKey.Mode = CipherMode.CBC;
            symmetricKey.Padding = PaddingMode.Zeros;

            // Generate decryptor from the existing key bytes and initialization 
            // vector. Key size will be defined based on the number of the key 
            // bytes.
            ICryptoTransform decryptor = symmetricKey.CreateDecryptor(keyBytes,initVectorBytes);

            // Define memory stream which will be used to hold encrypted data.
            MemoryStream memoryStream = new MemoryStream(cipherTextBytes);

            // Define cryptographic stream (always use Read mode for encryption).
            CryptoStream cryptoStream = new CryptoStream(memoryStream,decryptor,CryptoStreamMode.Read);

            // Since at this point we don't know what the size of decrypted data
            // will be, allocate the buffer long enough to hold ciphertext;
            // plaintext is never longer than ciphertext
            byte[] plainTextBytes = new byte[cipherTextBytes.Length];

            // Start decrypting.
            int decryptedByteCount = cryptoStream.Read(plainTextBytes,0,plainTextBytes.Length);

            // Close both streams.
            memoryStream.Close();
            cryptoStream.Close();

            // Convert decrypted data into a string. 
            // Let us assume that the original plaintext string was UTF8-encoded.
            SecureString plainText = new SecureString();
            
            //loop through byte for byte and store that char in a safe string
            for (int i = 0; i < decryptedByteCount; i++)
            {
                char[] c = Encoding.UTF8.GetChars(plainTextBytes, i, 1);
                for (int j = 0; j < c.Length; j++)
                    plainText.AppendChar(c[j]);
            }

            // Return decrypted string as safe string   
            return plainText;
        }
    }
}
