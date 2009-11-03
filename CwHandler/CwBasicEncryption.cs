/*
 +---------------------------------------------------------------------+
 Copyright 2009, Aaron LeMasters and Michael Davis                                    
 
 This file is part of Codeword.
  
 Codeword is free software: you can redistribute it and/or modify
 it under the terms of the GNU General Public License as published by
 the Free Software Foundation, either version 3 of the License, or
 (at your option) any later version.

 Codeword is distributed in the hope that it will be useful,
 but WITHOUT ANY WARRANTY; without even the implied warranty of
 MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 GNU General Public License for more details.

 You should have received a copy of the GNU General Public License
 along with Codeword.  If not, see <http://www.gnu.org/licenses/>.
 +---------------------------------------------------------------------+
*/
using System;
using System.IO;
using System.Text;
using System.Security;
using System.Security.Cryptography;
using System.Runtime.InteropServices;

namespace CwHandler
{

    /*
     * //credit:  http://www.obviex.com/samples/Encryption.aspx
     *
    */
    public class CwBasicEncryption
    {
        //internal static SecureString passphrase = new SecureString();
        //internal static SecureString salt = new SecureString();
        //internal static SecureString iv = new SecureString();
        internal static string passphrase = "allthekingshorsesandallthekingsmencouldntputhumptytogetheragain!!";
        internal static string salt = "1qaz2wsx3edc4rfv5tgb6yhn7ujm8ik,9ol.0p;/";
        internal static string iv = "10!)29@(38#*47$&";
        internal static string hashAlgorithmName = "SHA1";
        internal static int keySize = 256;
        internal static int passwordIterations = 2;

        #region disabled securing string stuff
        /*internal static void InitializeCryptoVariables()
        {
            #region passphrase

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

            #endregion

            #region salt
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
 
            #endregion

            #region iv
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
            iv.AppendChar('&'); //16
            #endregion

        }*/
        #endregion

        public static string Encrypt(string plainText)
        {
            //InitializeCryptoVariables();

            // Convert strings into byte arrays.
            // Let us assume that strings only contain ASCII codes.
            // If strings include Unicode characters, use Unicode, UTF7, or UTF8 encoding.
            //byte[] initVectorBytes = Encoding.ASCII.GetBytes(GetStringFromSecureString(iv));
            //byte[] saltValueBytes = Encoding.ASCII.GetBytes(GetStringFromSecureString(salt));

            byte[] initVectorBytes = Encoding.ASCII.GetBytes(iv);
            byte[] saltValueBytes = Encoding.ASCII.GetBytes(salt);

            // Convert our plaintext into a byte array.
            // Let us assume that plaintext contains UTF8-encoded characters.
            byte[] plainTextBytes = Encoding.UTF8.GetBytes(plainText);

            // First, we must create a password, from which the key will be derived.
            // This password will be generated from the specified passphrase and 
            // salt value. The password will be created using the specified hash 
            // algorithm. Password creation can be done in several iterations.
            PasswordDeriveBytes password = new PasswordDeriveBytes(
                                                            passphrase,
                                                            saltValueBytes,
                                                            hashAlgorithmName,
                                                            passwordIterations);

            // Use the password to generate pseudo-random bytes for the encryption
            // key. Specify the size of the key in bytes (instead of bits).
            byte[] keyBytes = password.GetBytes(keySize / 8);

            // Create uninitialized Rijndael encryption object.
            RijndaelManaged symmetricKey = new RijndaelManaged();

            // It is reasonable to set encryption mode to Cipher Block Chaining
            // (CBC). Use default options for other symmetric key parameters.
            symmetricKey.Mode = CipherMode.CBC;
            symmetricKey.Key = keyBytes;
            symmetricKey.IV = initVectorBytes;

            // Generate encryptor from the existing key bytes and initialization 
            // vector. Key size will be defined based on the number of the key bytes.
            ICryptoTransform encryptor = symmetricKey.CreateEncryptor(keyBytes,initVectorBytes);

            // Define memory stream which will be used to hold encrypted data.
            MemoryStream memoryStream = new MemoryStream();

            // Define cryptographic stream (always use Write mode for encryption).
            CryptoStream cryptoStream = new CryptoStream(memoryStream,
                                                         encryptor,
                                                         CryptoStreamMode.Write);
            // Start encrypting.
            cryptoStream.Write(plainTextBytes, 0, plainTextBytes.Length);

            // Finish encrypting.
            cryptoStream.FlushFinalBlock();

            // Convert our encrypted data from a memory stream into a byte array.
            byte[] cipherTextBytes = memoryStream.ToArray();

            // Close both streams.
            memoryStream.Close();
            cryptoStream.Close();
            symmetricKey.Clear();

            // Convert encrypted data into a base64-encoded string.
            string cipherText = Convert.ToBase64String(cipherTextBytes);

            // Return encrypted string.
            return cipherText;
        }

        public static SecureString Decrypt(string cipherText)
        {
            //InitializeCryptoVariables();

            // Convert strings defining encryption key characteristics into byte
            // arrays. Let us assume that strings only contain ASCII codes.
            // If strings include Unicode characters, use Unicode, UTF7, or UTF8
            // encoding.
            //byte[] initVectorBytes = Encoding.ASCII.GetBytes(GetStringFromSecureString(iv));
            //byte[] saltValueBytes = Encoding.ASCII.GetBytes(GetStringFromSecureString(salt));
            byte[] initVectorBytes = Encoding.ASCII.GetBytes(iv);
            byte[] saltValueBytes = Encoding.ASCII.GetBytes(salt);

            // Convert our ciphertext into a byte array.
            byte[] cipherTextBytes = Convert.FromBase64String(cipherText);

            // First, we must create a password, from which the key will be 
            // derived. This password will be generated from the specified 
            // passphrase and salt value. The password will be created using
            // the specified hash algorithm. Password creation can be done in
            // several iterations.
            PasswordDeriveBytes password = new PasswordDeriveBytes(passphrase,saltValueBytes,hashAlgorithmName,passwordIterations);

            // Use the password to generate pseudo-random bytes for the encryption
            // key. Specify the size of the key in bytes (instead of bits).
            byte[] keyBytes = password.GetBytes(keySize / 8);

            // Create uninitialized Rijndael encryption object.
            RijndaelManaged symmetricKey = new RijndaelManaged();

            // It is reasonable to set encryption mode to Cipher Block Chaining
            // (CBC). Use default options for other symmetric key parameters.
            symmetricKey.Mode = CipherMode.CBC;

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
            // plaintext is never longer than ciphertext.
            byte[] plainTextBytes = new byte[cipherTextBytes.Length];

            // Start decrypting.
            int decryptedByteCount = cryptoStream.Read(plainTextBytes,0,plainTextBytes.Length);

            // Close both streams.
            memoryStream.Close();
            cryptoStream.Close();

            // Convert decrypted data into a string. 
            // Let us assume that the original plaintext string was UTF8-encoded.
            SecureString s = new SecureString();
            for (int i = 0; i < decryptedByteCount; i++)
                s.AppendChar(Encoding.UTF8.GetChars(plainTextBytes, i, 1)[0]);

            s.MakeReadOnly();

            // Return decrypted string as securestring   
            return s;
        }

        public static string GetStringFromSecureString(SecureString s)
        {
            IntPtr pBstr = Marshal.SecureStringToBSTR(s);
            string v= Marshal.PtrToStringUni(pBstr);
            Marshal.ZeroFreeBSTR(pBstr);
            return v;
        }
    }
}
