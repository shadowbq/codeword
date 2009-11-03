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
using System.Collections;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Text;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography;
using System.IO;
using System.Xml;
using System.Xml.Serialization;

namespace CwHandler
{
    internal class SslTcpClient
    {  
        //private member data set by instantiator
        private TcpClient TcpClientConnection;
        private SslStream ClientSslStream;
        private string agentIP;
        private int agentPort;
        private bool IgnoreRemoteCertIgnoreChainErrors = false;
        private bool IgnoreRemoteCertIgnoreNameMismatchError = false;
        private string PFXfilename = "";
        private string PFXpassword = "";
        public SslPolicyErrors sslErrors = SslPolicyErrors.None;

        /////////////////////////////////////////////////////
        //                                                 //
        // SelectLocalClientCertificate()                  //
        //                                                 //
        /////////////////////////////////////////////////////
        //Description:  Selects the first valid x509 certificate
        //              in the admin console's PFX file that
        //              contains a private key.  It sends the
        //              corresponding public key to the remote
        //              server (ie, the agent) for authentication.
        //              This function is a callback
        //              which is called automatically by .net
        //              when an SSL session is being established.
        //
        //Returns:      void
        /////////////////////////////////////////////////////
        internal X509Certificate SelectLocalClientCertificate(object sender, string targetHost, X509CertificateCollection localCertificates, X509Certificate remoteCertificate, string[] acceptableIssuers)
        {
            if (acceptableIssuers != null && acceptableIssuers.Length > 0 && localCertificates != null && localCertificates.Count > 0)
            {
                // Use the first certificate that is from an acceptable issuer.
                foreach (X509Certificate certificate in localCertificates)
                {
                    string issuer = certificate.Issuer;
                    if (Array.IndexOf(acceptableIssuers, issuer) != -1)
                        return certificate;
                }
            }

            if (localCertificates != null && localCertificates.Count > 0)
                return localCertificates[0];

            return null;
        }

        /////////////////////////////////////////////////////
        //                                                 //
        // ValidateServerCertificate()                     //
        //                                                 //
        /////////////////////////////////////////////////////
        //Description:  Enforces validation rules on the remote
        //              server's certificate (ie, the agent).
        //              These rules are configurable in the
        //              admin console via the CwAdminCredentialsForm
        //              form window.  This function is a callback
        //              which is called automatically by .net
        //              when an SSL session is being established.
        //
        //Returns:      void
        /////////////////////////////////////////////////////
        // The following method is invoked by the RemoteCertificateValidationDelegate.
        internal bool ValidateServerCertificate(object sender, X509Certificate certificate, X509Chain chain, SslPolicyErrors sslPolicyErrors)
        {
            sslErrors = sslPolicyErrors;

           //yay, no errors.
           if (sslPolicyErrors == SslPolicyErrors.None)
                return true;

           //ignore name mismatch errors in certificate?
           if (sslPolicyErrors == SslPolicyErrors.RemoteCertificateNameMismatch)
               if (this.IgnoreRemoteCertIgnoreNameMismatchError)
                   return true;

           //ignore chain errors in certificate?
           if (sslPolicyErrors == SslPolicyErrors.RemoteCertificateChainErrors)
               if (this.IgnoreRemoteCertIgnoreChainErrors)
                   return true;

            //refuse communication
            return false;
        }

        /////////////////////////////////////////////////////
        //                                                 //
        // SetOptions()                                    //
        //                                                 //
        /////////////////////////////////////////////////////
        //Description:  Sets private member data fields.
        //
        //Returns:      void
        /////////////////////////////////////////////////////
        internal void SetOptions(string ip, int port, bool ignoreNameMismatchErr, bool ignoreCertChainErr, string pfxfilename, string pfxpassword)
        {
            this.agentIP = ip;
            this.agentPort = port;
            this.IgnoreRemoteCertIgnoreNameMismatchError = ignoreNameMismatchErr;
            this.IgnoreRemoteCertIgnoreChainErrors = ignoreCertChainErr;
            this.PFXfilename = pfxfilename;
            this.PFXpassword = pfxpassword;
        }

        /////////////////////////////////////////////////////
        //                                                 //
        // SetStreamTimeout()                              //
        //                                                 //
        /////////////////////////////////////////////////////
        //Description:  Sets the read/write timeouts for the
        //              active tcp/ssl stream.
        //
        //Returns:      void
        /////////////////////////////////////////////////////
        internal void SetStreamTimeout(string whichTimeout, int seconds)
        {
            if (whichTimeout == "read")
                ClientSslStream.ReadTimeout = seconds * 1000;
            else
                ClientSslStream.WriteTimeout = seconds * 1000;
        }

        /////////////////////////////////////////////////////
        //                                                 //
        // OpenConnection()                                //
        //                                                 //
        /////////////////////////////////////////////////////
        //Description:  Establishes a TCP/SSL connection to
        //              the specified agent ip:port.
        //
        //Returns:      null if successful; an err msg if not
        /////////////////////////////////////////////////////
        internal void OpenConnection()
        {
            //Create a TCP/IP client socket
            try
            {
                TcpClientConnection = new TcpClient(agentIP, agentPort);
                TcpClientConnection.ReceiveTimeout = 5000; //ms
                TcpClientConnection.SendTimeout = 5000;
            }
            catch (Exception ex)
            {
                if (TcpClientConnection != null)
                    TcpClientConnection.Close();

                throw new Exception("Error:  Error:  TCP connection failed.\n\n" + ex.Message);
            }

            //------------------------------------------
            //          LOAD PFX CERT STORE
            //------------------------------------------
            IntPtr hMemStore = IntPtr.Zero;

            try
            {
                hMemStore = CwCryptoHelper.GetX509StoreHandleFromPFX(PFXfilename, PFXpassword);
            }
            catch (Exception ex)
            {
                throw new Exception("Could not extract certificate store from PFX file:  " + ex.Message);
            }

            //establish an SSL stream
            try
            {
                //Create an SSL stream that will close the client's stream.
                ClientSslStream = new SslStream(TcpClientConnection.GetStream(), false, new RemoteCertificateValidationCallback(ValidateServerCertificate),new LocalCertificateSelectionCallback(SelectLocalClientCertificate));
                ClientSslStream.ReadTimeout = 5000; //ms
                ClientSslStream.WriteTimeout = 5000;
            }
            catch (Exception ex)
            {
                TcpClientConnection.Close();
                throw new Exception("Error:  Could not negotiate an SSL stream.\n\n" + ex.Message);
            }

            //instantiate a handle to the store we just created from the PFX file
            X509Store store = new X509Store(hMemStore);

            //authenticate using certs.
            try
            {
                ClientSslStream.AuthenticateAsClient("CwPublisher", store.Certificates, SslProtocols.Tls, false);
            }
            catch (AuthenticationException e)
            {
                ClientSslStream.Close();
                throw new Exception("Error:  Authentication failed:  " + e.Message);
            }
            catch (Exception ex)
            {
                ClientSslStream.Close();
                throw new Exception("Other authentication error:  " + ex.Message);
            }

            //cleanup
            if (store != null) store.Close();
            if (hMemStore != IntPtr.Zero) CwAgent.Win32Helper.CertCloseStore(hMemStore, 0);
            //CwCryptoHelper.DestroyStore(store.Name,store.Prov
        }

        /////////////////////////////////////////////////////
        //                                                 //
        // ReadResponse()                                  //
        //                                                 //
        /////////////////////////////////////////////////////
        //Description:  Attempt to read an incoming SSL msg.
        //
        //Throws:       Deserialization error
        //
        //Returns:      the response object
        /////////////////////////////////////////////////////
        internal CwXML.CodewordAgentResponse ReadResponse()
        {
            CwXML.CodewordAgentResponse r = new CwXML.CodewordAgentResponse();
            MemoryStream ms = new MemoryStream();
            Decoder UTF8Decoder = Encoding.UTF8.GetDecoder();
            int bytes = -1;
            byte[] buffer = new byte[2048];

            do
            {
                //read 2048 bytes from the network stream - store in our byte buffer
                //.Read() advances the stream's buffer, so dont worry about an offset.
                try
                {
                    bytes = ClientSslStream.Read(buffer, 0, 2048);
                }
                catch (IOException ex)
                {
                    throw new Exception("ReadResponse():  Caught IO Exception (read " + bytes.ToString() + " bytes):  " + ex.Message);
                }
                catch (Exception ex)
                {
                    throw new Exception("ReadResponse():  Caught other exception (read " + bytes.ToString() + " bytes):  " + ex.Message);
                }

                //decode the data to look for EOF
                StringBuilder messageData = new StringBuilder();
                char[] chars = new char[UTF8Decoder.GetCharCount(buffer, 0, bytes)];
                UTF8Decoder.GetChars(buffer, 0, bytes, chars, 0);
                messageData.Append(chars);

                //write the bytes from the byte buffer to our memory stream
                ms.Write(buffer, 0, bytes);

                //break if EOF.
                if (messageData.ToString().IndexOf("<EOF>") != -1)
                    break;
            }
            while (bytes != 0);

            //convert the memorystream to a string to replace the <EOF>
            //otherwise, xml parsing will fail.
            byte[] bData = ms.ToArray();
            char[] charArray = new char[UTF8Decoder.GetCharCount(bData, 0, bData.Length)];
            UTF8Decoder.GetChars(bData, 0, bData.Length, charArray, 0);
            string s = new string(charArray);
            s=s.Replace("<EOF>", "");
            ms = new MemoryStream(Encoding.UTF8.GetBytes(s));

            //try to deserialize the response data from the memory stream we filled            
            XmlSerializer serializer = new XmlSerializer(typeof(CwXML.CodewordAgentResponse));

            //restore the object's state with data from the XML document
            r = (CwXML.CodewordAgentResponse)serializer.Deserialize(ms);

            //DEBUG
            /*
            StreamWriter sw = new StreamWriter("ResponseRead.xml");
            sw.Write(new string(Encoding.UTF8.GetChars(ms.ToArray())));
            sw.Close();
            */

            if (r == null)
                throw new Exception("Response was retrieved, but the object was null.");
            
            return r;
        }

        /////////////////////////////////////////////////////
        //                                                 //
        // SendCommand()                                   //
        //                                                 //
        /////////////////////////////////////////////////////
        //Description:  Attempts to send a message over SSL.
        //
        //Throws:       Serialization error
        //
        //Returns:      true if successful
        /////////////////////////////////////////////////////
        internal bool SendCommand(int commandCode, string[] args, int timeout, bool responseRequired, CwXML.CodewordAgentAnomalyReport CollectOrMitigationTask)
        {
            CwXML.CodewordAgentCommand cmd = new CwXML.CodewordAgentCommand();
            cmd.CommandCode = commandCode;
            cmd.CommandParameters = args;
            cmd.CommandTimeout = timeout;
            cmd.ResponseRequired = responseRequired;
            cmd.CommandCollectOrMitigationTask = CollectOrMitigationTask;

            //create an XML serialization object to prepare the command
            XmlSerializer serializer = new XmlSerializer(typeof(CwXML.CodewordAgentCommand));

            //create a memory stream to which we will serialize our response object
            MemoryStream memStream = new MemoryStream();

            //store the object's state in XML format into the memory stream store
            serializer.Serialize(memStream, cmd);

            //tack on "<EOF>" to the message, so the server knows when to stop reading the socket
            char[] eofbuf = new char[] { '<', 'E', 'O', 'F', '>' };
            memStream.Write(Encoding.UTF8.GetBytes(eofbuf), 0, eofbuf.Length);

            //try to send the raw bytes in the memory stream to the remote socket
            try
            {
                //result of 5 hour debug session:  dont use memstream.getBuffer()
                //it returns all bytes in the buffer, not only the ones used..use ToArray() instead!!
                ClientSslStream.Write(memStream.ToArray());
                ClientSslStream.Flush();
            }
            catch (Exception ex)
            {
                throw new Exception("ClientSslStream.Write() error:  " + ex.Message);
            }

            //DEBUG
            /*
            StreamWriter sw = new StreamWriter("CommandSent.xml");
            sw.Write(new string(Encoding.UTF8.GetChars(memStream.ToArray())));
            sw.Close();*/

            memStream.Close();

            return true;
        }

        /////////////////////////////////////////////////////
        //                                                 //
        // SendFile()                                      //
        //                                                 //
        /////////////////////////////////////////////////////
        //Description:  Attempts to send a file over SSL.
        //
        //              NOTE:  This ONLY works for text files
        //              that need to be sent UTF-8 encoded!
        //
        //Throws:       write error
        //
        //Returns:      true if successful
        /////////////////////////////////////////////////////
        internal bool SendFile(string filename)
        {
            //slurp the file into memory - do not pass to constructor, b/c that will
            //make the stream immutable, and we must add <EOF> in a sec..
            MemoryStream ms = new MemoryStream();
            //get UTF-8 encoded bytes of the XML sig file
            byte[] filedata = Encoding.UTF8.GetBytes(File.ReadAllText(filename));
            //write it to the memory stream
            ms.Write(filedata, 0, filedata.Length);

            //tack on "<EOF>" to the message, so the server knows when to stop reading the socket
            char[] eofbuf = new char[] { '<', 'E', 'O', 'F', '>' };
            ms.Write(Encoding.UTF8.GetBytes(eofbuf), 0, eofbuf.Length);

            //try to send the raw bytes in the memory stream to the remote socket
            try
            {
                //result of 5 hour debug session:  dont use memstream.getBuffer()
                //it returns all bytes in the buffer, not only the ones used..use ToArray() instead!!
                ClientSslStream.Write(ms.ToArray());
                ClientSslStream.Flush();
            }
            catch (Exception ex)
            {
                throw new Exception("ClientSslStream.Write() error:  " + ex.Message);
            }

            ms.Close();

            return true;
        }

        /////////////////////////////////////////////////////
        //                                                 //
        // ReceiveFiles()                                  //
        //                                                 //
        /////////////////////////////////////////////////////
        //Description:  Receives as many files as the agent sends.
        //              Saves them to the specified folder.
        //
        //Throws:       read error
        //
        //Returns:      the binary data
        /////////////////////////////////////////////////////
        internal bool ReceiveFiles(string SaveToFolder, CwXML.FileSignatureMatch[] collectionTargets)
        {
            MemoryStream ms = new MemoryStream();
            Decoder UTF8Decoder = Encoding.UTF8.GetDecoder();
            int numBytesRead = -1;
            byte[] fileDataBuffer;

            //loop through all files in the collection target and download them
            foreach(CwXML.FileSignatureMatch fileMatch in collectionTargets)
            {
                string fileNameToCollect = fileMatch.FileName;
                string filePathToCollect = fileMatch.FullPath;
                long fileSizeToCollect = fileMatch.FileSize;
                string fileHashToCollect = fileMatch.FileHash;
                string fileHashTypeToCollect = fileMatch.FileHashType;

                //create a new buffer to store this file - size is the file's size
                fileDataBuffer = new byte[fileSizeToCollect];

                //====================================
                //DOWNLOAD FILE BYTES
                //====================================
                try
                {
                    //store a max of 2048 bytes starting at offset 0 in the buffer array
                    numBytesRead = ClientSslStream.Read(fileDataBuffer, 0, (int)fileSizeToCollect);
                }
                catch (IOException ex)
                {
                    throw new Exception("ReceiveFiles():  Caught IO Exception (read " + numBytesRead.ToString() + " bytes):  " + ex.Message);
                }
                catch (Exception ex)
                {
                    throw new Exception("ReceiveFiles():  Caught other exception (read " + numBytesRead.ToString() + " bytes):  " + ex.Message);
                }

                //throw an error if the file was corrupted
                if (numBytesRead != fileSizeToCollect)
                    throw new Exception("ReceiveFiles():  The downloaded file size (" + numBytesRead.ToString() + ") does not match the expected file size (" + fileSizeToCollect.ToString() + ")!");
                
                //do a binary write to save this file to the target folder
                string outputFullPath = SaveToFolder + "\\" + fileNameToCollect;
                StreamWriter sw = new StreamWriter(outputFullPath);
                BinaryWriter bw = new BinaryWriter(sw.BaseStream);
                bw.Write(fileDataBuffer);
                bw.Flush();
                bw.Close();

                //MATCH MD-5 HASH IF SPECIFIED
                if (fileHashTypeToCollect == "MD5" && fileHashToCollect != "")
                {
                    string thisMD5=GetMD5HashOfFile(outputFullPath);
                    if (thisMD5 != fileHashToCollect)
                        throw new Exception("ReceiveFiles():  The MD5 hash of the download evidence file (" + thisMD5.ToString() + ") does not match the expected MD5 hash (" + fileHashToCollect.ToString() + ")!");
                }
                //MATCH SHA-1 HASH IF SPECIFIED
                else if (fileHashTypeToCollect == "SHA1" && fileHashToCollect != "")
                {
                    string thisSHA1 = GetSHA1HashOfFile(outputFullPath);

                    if (thisSHA1 != fileHashToCollect)
                        throw new Exception("ReceiveFiles():  The SHA1 hash of the download evidence file (" + thisSHA1.ToString() + ") does not match the expected SHA1 hash (" + fileHashToCollect.ToString() + ")!");
                }
            }

            return true;
        }

        /////////////////////////////////////////////////////
        //                                                 //
        // CloseConnection()                               //
        //                                                 //
        /////////////////////////////////////////////////////
        //Description:  Closes the TCP/SSL connection.
        //
        //Returns:      true if successful
        /////////////////////////////////////////////////////
        internal bool CloseConnection()
        {
            if (TcpClientConnection != null)
                TcpClientConnection.Close();
            if (ClientSslStream != null)
                ClientSslStream.Close();

            return true;
        }

        /////////////////////////////////////////////////////
        //                                                 //
        // IsConnected()                                   //
        //                                                 //
        /////////////////////////////////////////////////////
        //Description:  Detects if the underlying TCP socket
        //              is still connected to the remote server.
        //
        //Returns:      true if currently connected.
        /////////////////////////////////////////////////////
        internal bool IsConnected()
        {
            if (TcpClientConnection != null)
                if (TcpClientConnection.Client != null)
                    if (TcpClientConnection.Client.Connected)
                        return true;
            return false;
        }

        /////////////////////////////////////////////////////
        //                                                 //
        // GetMD5HashOfFile()                              //
        //                                                 //
        /////////////////////////////////////////////////////
        //Description:  calculates an MD5 hash of a file by
        //              reading each byte from the stream
        //Returns:      string representation in upper case
        /////////////////////////////////////////////////////
        internal string GetMD5HashOfFile(string filename)
        {
            MD5 md5 = MD5.Create();
            StringBuilder sb = new StringBuilder();

            using (FileStream fs = File.Open(filename, FileMode.Open))
            {
                foreach (byte b in md5.ComputeHash(fs))
                    sb.Append(b.ToString("x2").ToUpper());
            }

            return sb.ToString();
        }

        /////////////////////////////////////////////////////
        //                                                 //
        // GetSHA1HashOfFile()                             //
        //                                                 //
        /////////////////////////////////////////////////////
        //Description:  Returns the sha-1 hash of a file
        //Returns:      string representation of hash
        /////////////////////////////////////////////////////
        internal string GetSHA1HashOfFile(string filename)
        {
            using (HashAlgorithm hashAlg = new SHA1Managed())
            {
                using (Stream file = new FileStream(filename, FileMode.Open, FileAccess.Read))
                {
                    byte[] hash = hashAlg.ComputeHash(file);

                    return (BitConverter.ToString(hash));
                }
            }
        }
    }
}
