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
using System.Collections.Generic;
using System.Text;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.IO;

namespace CwHandler
{
    class CwCryptoHelper
    {
        /////////////////////////////////////////////////////
        //                                                 //
        // DestroyStore()                                  //
        //                                                 //
        /////////////////////////////////////////////////////
        //Description:  Clears the temporary store we created
        //              when PFX was imported.
        //
        //Returns:      true if successful
        /////////////////////////////////////////////////////
        internal static bool DestroyStore(string containerName, string providerName, uint providerType)
        {
            IntPtr hCryptProv = IntPtr.Zero;
            if (CwAgent.Win32Helper.CryptAcquireContext(ref hCryptProv, containerName, providerName, providerType, CwAgent.Win32Helper.CRYPT_DELETEKEYSET))
                return true;
            else
                return false;
        }

        /////////////////////////////////////////////////////
        //                                                 //
        // GetX509StoreHandleFromPFX()                     //
        //                                                 //
        /////////////////////////////////////////////////////
        //Description:  Uses unmanaged CAPI calls to import a
        //              PKCS-12/PFX crypto file and returns
        //              the embedded certificate.
        //
        //              Note:  this function throws an exception
        //              if the PFX file contains > 1 cert.
        //
        //Returns:      void
        /////////////////////////////////////////////////////
        internal static IntPtr GetX509StoreHandleFromPFX(string filename, string password)
        {
            IntPtr hMemStore = IntPtr.Zero;

            //get pfx from data in file
            CwAgent.Win32Helper.CRYPT_DATA_BLOB ppfx = new CwAgent.Win32Helper.CRYPT_DATA_BLOB();
            if (!LoadPFX(filename, ref ppfx))
                throw new Exception("Failed to load data from PFX file.");

            //try to import to memory store
            hMemStore = CwAgent.Win32Helper.PFXImportCertStore(ref ppfx, password, (uint)CwAgent.Win32Helper.CRYPT_USER_KEYSET);
            password = null; //mark for garbage collection

            if (hMemStore == IntPtr.Zero)
            {
                Marshal.FreeHGlobal(ppfx.pbData);
                throw new Exception("Failed to import PFX certificate store:  " + CwAgent.Win32Helper.GetLastError32());
            }

            Marshal.FreeHGlobal(ppfx.pbData);

            return hMemStore;
        }

        /////////////////////////////////////////////////////
        //                                                 //
        // IsValidPFX()                                    //
        //                                                 //
        /////////////////////////////////////////////////////
        //Description:  Uses unmanaged CAPI calls to validate
        //              a given file contains a valid PFX.
        //
        //Returns:      true if valid
        /////////////////////////////////////////////////////
        internal static bool IsValidPFX(string filename)
        {
            bool ret = false;
            CwAgent.Win32Helper.CRYPT_DATA_BLOB ppfx = new CwAgent.Win32Helper.CRYPT_DATA_BLOB();

            if (LoadPFX(filename, ref ppfx))
                if (CwAgent.Win32Helper.PFXIsPFXBlob(ref ppfx))
                    ret=true;

            if (ppfx.pbData != IntPtr.Zero)
                Marshal.FreeHGlobal(ppfx.pbData);

            return ret;
        }

        /////////////////////////////////////////////////////
        //                                                 //
        // IsValidPFXPassword()                            //
        //                                                 //
        /////////////////////////////////////////////////////
        //Description:  Uses unmanaged CAPI calls to validate
        //              a given password for the PFX file.
        //
        //Returns:      true if valid
        /////////////////////////////////////////////////////
        internal static bool IsValidPFXPassword(string filename, string pwd)
        {
            bool ret = false;
            CwAgent.Win32Helper.CRYPT_DATA_BLOB ppfx = new CwAgent.Win32Helper.CRYPT_DATA_BLOB();

            if (LoadPFX(filename, ref ppfx))
                if (CwAgent.Win32Helper.PFXVerifyPassword(ref ppfx,pwd,0))
                    ret = true;

            if (ppfx.pbData != IntPtr.Zero)
                Marshal.FreeHGlobal(ppfx.pbData);

            return ret;
        }

        /////////////////////////////////////////////////////
        //                                                 //
        // LoadPFX()                                       //
        //                                                 //
        /////////////////////////////////////////////////////
        //Description:  Uses unmanaged CAPI calls to load
        //              PFX data from a PFX file.
        //
        //Returns:      none
        /////////////////////////////////////////////////////
        internal static bool LoadPFX(string filename, ref CwAgent.Win32Helper.CRYPT_DATA_BLOB ppfx)
        {
            //load the bytes from this file and validate it is a PFX file
            Stream stream = null;
            byte[] pfxdata = null;

            try
            {
                stream = new FileStream(filename, FileMode.Open);
                int datalen = (int)stream.Length;
                pfxdata = new byte[datalen];
                stream.Seek(0, SeekOrigin.Begin);
                stream.Read(pfxdata, 0, datalen);
                stream.Close();
            }
            catch (Exception)
            {
                return false;
            }

            if (pfxdata == null || pfxdata.Length == 0)
                return false;

            //set data in pfx structure
            ppfx.cbData = pfxdata.Length;
            ppfx.pbData = Marshal.AllocHGlobal(pfxdata.Length);
            Marshal.Copy(pfxdata, 0, ppfx.pbData, pfxdata.Length);

            return true;
        }

        /////////////////////////////////////////////////////
        //                                                 //
        // CheckCAPIVersion()                              //
        //                                                 //
        /////////////////////////////////////////////////////
        //Description:  Uses unmanaged CAPI calls to determine
        //              if this system uses CAPI v1.0 or v2.0
        //              This is important because v1.0 does not
        //              support certain cipher suites we use.
        //Returns:      the version number as string.  either
        //              "0100" or "0200".
        /////////////////////////////////////////////////////
        internal static string CheckCAPIVersion()
        {
            IntPtr hCryptProv = IntPtr.Zero;
            string ppver = "?";

            //acquire cryptographic provider context
            //set provider type to 1 (RSA_FULL) and flags to 0 (CRYPT_VERIFY_CONTEXT)
            if (CwAgent.Win32Helper.CryptAcquireContext(ref hCryptProv, null, null, 1, 0))
            {
                byte[] pbData = new byte[4096];
                uint size = 4096;

                //get provider parameter - 5 for version
                if (CwAgent.Win32Helper.CryptGetProvParam(hCryptProv, 5, pbData, ref size, 0) && size > 0)
                {
                    ppver = "";
                    for (int i = 0; i < size; i++)
                        ppver += pbData[i].ToString();
                }
                else
                    throw new Exception("CryptGetProvParam:  " + CwAgent.Win32Helper.GetLastError32() + " (" + CwAgent.Win32Helper.GetLastError().ToString("x") + ")");

                //if no bytes were retrieved, throw exception
                if (size == 0)
                    throw new Exception("CryptGetProvParam:  0 bytes returned.");
            }
            else
            {
                throw new Exception("CryptAcquireContext:  " + CwAgent.Win32Helper.GetLastError32() + " (" + CwAgent.Win32Helper.GetLastError().ToString("x") + ")");
            }

            return ppver;
        }

        /////////////////////////////////////////////////////
        //                                                 //
        // InstallClientCertificateToKeystore()            //
        //                                                 //
        /////////////////////////////////////////////////////
        //Description:  Takes a public or private key file and
        //              adds it to the local user's key store
        //Returns:      the key data as a string
        /////////////////////////////////////////////////////
        internal static bool InstallClientCertificateToKeystore(X509Certificate2 certificate)
        {
            //try to open local machine's crypto store
            X509Store store;
            try
            {
                //open the user's certificate store
                store = new X509Store("MY", StoreLocation.CurrentUser);
                store.Open(OpenFlags.ReadWrite | OpenFlags.OpenExistingOnly);
            }
            catch (Exception ex)
            {
                throw new Exception("Failed to open MY store:  " + ex.Message);
            }

            //add the new X509 cert to the opened store
            store.Add(certificate);

            //close store
            store.Close();
            certificate.Reset();

            return true;
        }

        /////////////////////////////////////////////////////
        //                                                 //
        // UnInstallClientCertificateFromKeystore()        //
        //                                                 //
        /////////////////////////////////////////////////////
        //Description:  Uninstalls an x509 cert from the local
        //              keystore based on cert hash string 
        //Returns:      true if successful
        /////////////////////////////////////////////////////
        internal static bool UnInstallClientCertificateFromKeystore(string keyDataString)
        {
            try
            {
                X509Store store = new X509Store("MY", StoreLocation.CurrentUser);
                store.Open(OpenFlags.ReadWrite | OpenFlags.OpenExistingOnly);
                X509Certificate2Collection collection = (X509Certificate2Collection)store.Certificates;

                foreach (X509Certificate2 x509 in collection)
                {
                    if (x509.GetRawCertDataString() == keyDataString)
                    {
                        store.Remove(x509);
                        store.Close();
                        break;
                    }
                }

                if (store != null)
                    store.Close();
            }
            catch (Exception ex)
            {
                throw new Exception("Failed to read user's local key store:  " + ex.Message);
            }

            return true;
        }

        /////////////////////////////////////////////////////
        //                                                 //
        // GetX509Certificate2FromRawString()              //
        //                                                 //
        /////////////////////////////////////////////////////
        //Description:  Retrieves an x509 certificate from 
        //              the local user's keystore that maches
        //              the passed-in cert raw data (as string)
        //Returns:      X509 cert
        /////////////////////////////////////////////////////
        internal static X509Certificate2 GetX509Certificate2FromRawString(string certRawDataString)
        {
            try
            {
                X509Store store = new X509Store("MY", StoreLocation.CurrentUser);
                store.Open(OpenFlags.ReadOnly | OpenFlags.OpenExistingOnly);
                X509Certificate2Collection collection = (X509Certificate2Collection)store.Certificates;

                foreach (X509Certificate2 x509 in collection)
                {
                    if (x509.GetRawCertDataString() == certRawDataString)
                    {
                        store.Close();
                        return x509;
                    }
                }
                store.Close();
            }
            catch (Exception ex)
            {
                throw new Exception("Failed to read user's local key store:  " + ex.Message);
            }

            return null;
        }

        /////////////////////////////////////////////////////
        //                                                 //
        // GetX509CertificateCollectionFromLocalHostStore()//
        //                                                 //
        /////////////////////////////////////////////////////
        //Description:  Retrieves all x509 certificates from 
        //              the local user's keystore
        //Returns:      X509 cert collection
        /////////////////////////////////////////////////////
        internal static X509Certificate2Collection GetX509CertificateCollectionFromLocalHostStore()
        {
            try
            {
                X509Store store = new X509Store("MY", StoreLocation.CurrentUser);
                store.Open(OpenFlags.ReadOnly | OpenFlags.OpenExistingOnly);
                X509Certificate2Collection collection = (X509Certificate2Collection)store.Certificates;
                store.Close();
                return collection;
            }
            catch (Exception ex)
            {
                throw new Exception("Failed to read user's local key store:  " + ex.Message);
            }
        }

        /////////////////////////////////////////////////////
        //                                                 //
        // GetX509RawStringFromFile()                      //
        //                                                 //
        /////////////////////////////////////////////////////
        //Description:  Retrieves an x509 certificate by loading
        //              the key data from a file
        //Returns:      X509 cert
        /////////////////////////////////////////////////////
        internal static string GetX509RawStringFromFile(string filename)
        {
            byte[] rawData;

            //make sure file exists first!
            FileInfo finfo;
            try
            {
                finfo = new FileInfo(filename);
            }
            catch (Exception ex)
            {
                throw new Exception("ERROR:  Failed to query file '" + filename + "'.  " + ex.Message);
            }

            if (!finfo.Exists)
            {
                throw new Exception("ERROR:  Key file '" + filename + "' does not exist!");
            }

            //load binary data from key file
            try
            {
                FileStream f = new FileStream(filename, FileMode.Open, FileAccess.Read);
                int size = (int)f.Length;
                rawData = new byte[size];
                size = f.Read(rawData, 0, size);
                f.Close();
            }
            catch (Exception ex)
            {
                throw new Exception("Failed to read file stream from file '" + filename + "'.  " + ex.Message);
            }

            //dump binary data into an X509 certificate
            X509Certificate2 x509 = new X509Certificate2();
            try
            {
                x509.Import(rawData);
            }
            catch (Exception ex)
            {
                //delete the public key file we extracted, we dont need it anymore
                try
                {
                    File.Delete(filename);
                }
                catch { }

                throw new Exception("Failed to import raw data from certificate file '" + filename + "'.  " + ex.Message);
            }

            string rawString = x509.GetRawCertDataString();

            //delete the public key file we extracted, we dont need it anymore
            try
            {
                File.Delete(filename);
            }
            catch { }

            return rawString;
        }


        #region Encryption used for zip file

        internal static bool EncryptFile(string fileNameToEncrypt)
        {
            string encryptedFileName = fileNameToEncrypt + ".enc";

            //instantiate our RSA crypto service provider with parameters
            const int PROVIDER_RSA_FULL = 1;
            const string CONTAINER_NAME = "CodewordCryptoContainer";
            CspParameters cspParams;
            cspParams = new CspParameters(PROVIDER_RSA_FULL);
            cspParams.KeyContainerName = CONTAINER_NAME;
            cspParams.Flags = CspProviderFlags.UseMachineKeyStore;
            cspParams.ProviderName = "Microsoft Strong Cryptographic Provider";
            RSACryptoServiceProvider aSymmetricEncProvider = new RSACryptoServiceProvider(cspParams);
            TripleDESCryptoServiceProvider SymmetricEncProvider = new TripleDESCryptoServiceProvider();

            //open read-only file stream for our unencrypted file
            FileStream PlaintextFileDataStream = new FileStream(fileNameToEncrypt, System.IO.FileMode.Open, System.IO.FileAccess.Read);
            //create a writable filestream to write encrypted file out
            FileStream EncryptedFileDataStream = new FileStream(encryptedFileName, System.IO.FileMode.Create, System.IO.FileAccess.Write);
            //init a binaryWriter class to dump data to file
            BinaryWriter bw = new BinaryWriter(EncryptedFileDataStream);

            int fileLength = (int)PlaintextFileDataStream.Length;

            //if no data to encrypt, fail now
            if (fileLength == 0)
            {
                PlaintextFileDataStream.Close();
                EncryptedFileDataStream.Close();
                return false;
            }

            //read all data from file as binary data
            byte[] UnencryptedBinaryData = ReadByteArray(PlaintextFileDataStream);
            PlaintextFileDataStream.Close();

            //generate a new IV and sym key for encryption
            SymmetricEncProvider.GenerateIV();
            SymmetricEncProvider.GenerateKey();

            //use asymmetric encryption to encrpyt initialization vector (IV)
            byte[] EncryptedBinaryData = aSymmetricEncProvider.Encrypt(SymmetricEncProvider.IV, false);
            //then write it to the output stream (encrypted file)
            bw.Write(EncryptedBinaryData);
            //do the same for symmetric key
            EncryptedBinaryData = aSymmetricEncProvider.Encrypt(SymmetricEncProvider.Key, false);
            bw.Write(EncryptedBinaryData);

            //create our symmetric encryptor
            ICryptoTransform DES3Encrypt = SymmetricEncProvider.CreateEncryptor();

            //create a crypto stream to write our encrypted data by using:
            //      -target data stream (EncryptedFileDataStream), ie output file encrypted
            //      -transformation to user (3-DES)
            //      -mode (Write)
            //this will essentially pipe all our unencrypted data we read in from the file-to-encrypt
            //through our encrypted data stream using the 3-DES transformation
            CryptoStream cryptoStream = new CryptoStream(EncryptedFileDataStream, DES3Encrypt, CryptoStreamMode.Write);
            cryptoStream.Write(UnencryptedBinaryData, 0, UnencryptedBinaryData.Length);
            cryptoStream.Close();
            EncryptedFileDataStream.Close();
            PlaintextFileDataStream.Close();
            bw.Close();

            return true;
        }

        internal static bool DecryptFile(string fileNameToDecrypt)
        {
            //instantiate our RSA crypto service provider with parameters
            const int PROVIDER_RSA_FULL = 1;
            const string CONTAINER_NAME = "CodewordCryptoContainer";
            CspParameters cspParams;
            cspParams = new CspParameters(PROVIDER_RSA_FULL);
            cspParams.KeyContainerName = CONTAINER_NAME;
            cspParams.Flags = CspProviderFlags.UseMachineKeyStore;
            cspParams.ProviderName = "Microsoft Strong Cryptographic Provider";
            RSACryptoServiceProvider aSymmetricEncProvider = new RSACryptoServiceProvider(cspParams);
            TripleDESCryptoServiceProvider SymmetricEncProvider = new TripleDESCryptoServiceProvider();

            //just strip off the ".enc" and that should leave ".zip"
            string fileNameForPlaintext = fileNameToDecrypt.Replace(".enc", "");

            //open read-only file stream for input and output
            FileStream EncryptedStream = new FileStream(fileNameToDecrypt, System.IO.FileMode.Open, System.IO.FileAccess.Read);
            FileStream DecryptedStream = new FileStream(fileNameForPlaintext, System.IO.FileMode.Create, System.IO.FileAccess.Write);

            //decrypt IV and symmetric key - these are stored as first bytes of file
            byte[] cipheredIV = ReadByteArray(EncryptedStream);
            SymmetricEncProvider.IV = aSymmetricEncProvider.Decrypt(cipheredIV, false);
            byte[] cipheredKey = ReadByteArray(EncryptedStream);
            SymmetricEncProvider.Key = aSymmetricEncProvider.Decrypt(cipheredKey, false);
            int hdrLen = cipheredIV.Length + cipheredKey.Length + 8;
            int numRead = hdrLen, fileLength = (int)EncryptedStream.Length;

            if (fileLength - hdrLen == 0)
                return false;

            //read in all bytes of encrypted data from encrypted stream
            byte[] EncryptedData = ReadByteArray(EncryptedStream);
            EncryptedStream.Close();

            // create decryptor
            ICryptoTransform DES3Decrypt = SymmetricEncProvider.CreateDecryptor();
            CryptoStream cryptoStream = new CryptoStream(DecryptedStream, DES3Decrypt, CryptoStreamMode.Write);
            cryptoStream.Write(EncryptedData, 0, EncryptedData.Length);
            cryptoStream.Close();
            DecryptedStream.Close();

            return true;
        }

        internal static byte[] ReadByteArray(FileStream stream)
        {
            int offset = 0;
            byte[] data = new byte[stream.Length];
            int remaining = data.Length;
            while (remaining > 0)
            {
                int read = stream.Read(data, offset, remaining);
                if (read <= 0)
                    break;
                remaining -= read;
                offset += read;
            }

            return data;
        }
        #endregion

    }
}