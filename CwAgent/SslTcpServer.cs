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
using System.Collections.Generic;
using System.Net;
using System.Net.Sockets;
using System.Net.Security;
using System.Security.Authentication;
using System.Text;
using System.Security.Cryptography.X509Certificates;
using System.IO;
using System.Security;
using System.Security.Cryptography;
using System.Reflection;
using System.Xml;
using System.Xml.Serialization;
using System.Runtime.InteropServices;
using CwAgent; //needed for PKI and Crypto classes in CwAgent namespace

namespace CwHandler
{
    public class SslTcpServer
    {
        //data members populated during server startup/execution
        internal string EncryptedPassword = null;
        internal string PFXFileName = null;
        internal StringBuilder ServerLog = null;
        internal StringBuilder ConnectionLog = null;
        internal StringBuilder EnterpriseModeScanLog = null;

        //data members set at startup based on global agent settings
        internal bool AuthenticateServerToClient = false;
        internal bool AuthenticateClientToServer = false;
        internal int ServerPort = 1111;
        internal string RequiredIssuer = null;
        internal bool RequireStrongAuthentication = false;
        internal SslStream CurrentSslStream = null;
        
        public SslTcpServer() { }

        /////////////////////////////////////////////////////
        //                                                 //
        // ValidateRemoteClientCertificate()               //
        //                                                 //
        /////////////////////////////////////////////////////
        //Description:  enforces SSL certificate validation
        //              rules as chosen by user.
        //
        //Returns:      true if valid
        /////////////////////////////////////////////////////
        internal bool ValidateRemoteClientCertificate(object sender, X509Certificate certificate, X509Chain chain, SslPolicyErrors sslPolicyErrors)
        {
            //yay, no errors.
            if (sslPolicyErrors == SslPolicyErrors.None)
                return true;

            WriteConnectionLog("CONNECT:  Detected SSL policy errors:  " + sslPolicyErrors.ToString());

            //ignore name mismatch errors in certificate?
            if (sslPolicyErrors == SslPolicyErrors.RemoteCertificateNameMismatch)
                //if (this.IgnoreRemoteCertIgnoreNameMismatchError)
                    return true;

            //ignore chain errors in certificate?
            if (sslPolicyErrors == SslPolicyErrors.RemoteCertificateChainErrors)
                //if (this.IgnoreRemoteCertIgnoreChainErrors)
                    return true;

            //refuse communication
            return false;
        }

        /////////////////////////////////////////////////////
        //                                                 //
        // RunServer()                                     //
        //                                                 //
        /////////////////////////////////////////////////////
        //Description:  initiates listening loop for client
        //              connections.
        //
        //              Note:  the parameter ScanLog is the 
        //              output from an agent scan of the host
        //              which was initiated as a result of the
        //              agent's startup mode being set to Enterprise.
        //
        //Returns:      void
        /////////////////////////////////////////////////////
        internal void RunServer(StringBuilder ScanLog)
        {
            if (ScanLog != null)
                if (ScanLog.Length != 0)
                    this.EnterpriseModeScanLog = ScanLog;

            //********************************************
            //              IMPORTANT
            //********************************************
            //1) set global timeout for tcp connections; weird errors abound bc it reuses tcp conns:
            //  http://social.msdn.microsoft.com/forums/en-US/netfxnetcom/thread/212feb8f-cf96-4561-9953-40a21d21ea47/
            //2) disable TCP keep alive b/c of buggy MS implementation of the spec.
            ServicePointManager.MaxServicePointIdleTime = 10000;
            //only in .NET 3.5 or greater:  ServicePointManager.SetTcpKeepAlive(false, 0, 0);
            ServerLog = new StringBuilder();
            ConnectionLog = new StringBuilder();

            ServerLog.AppendLine("AGENT_SERVICE:  Starting TCP server...");

            // Create a TCP/IP (IPv4) socket and listen for incoming connections.
            TcpListener listener = new TcpListener(IPAddress.Any, this.ServerPort);

            try
            {
                listener.Start();
            }
            catch (Exception ex)
            {
                this.ServerLog.AppendLine("LISTEN:  Failed to bind to port " + this.ServerPort.ToString() + ":  " + ex.Message);
                return;
            }

            this.ServerLog.AppendLine("AGENT_SERVICE:  Bound to port " + this.ServerPort.ToString());
            this.ServerLog.AppendLine("AGENT_SERVICE:  Waiting for commands...");

            //---------------------------------------
            //          LISTEN FOR CONNECTIONS
            //---------------------------------------
            while (true)
            {
                //blocks while waiting for an incoming connection.
                TcpClient client = listener.AcceptTcpClient();
                bool success = true;

                //since we cant globally disable Keep Alive using ServicePointManager (only avail in .NET 3.5),
                //we must disable keep alive on a per-socket basis.
                client.Client.SetSocketOption(SocketOptionLevel.Tcp, SocketOptionName.KeepAlive, false);
                WriteConnectionLog("CONNECT:  Connected to remote host " + IPAddress.Parse(((IPEndPoint)client.Client.RemoteEndPoint).Address.ToString()) + " at " + DateTime.Now.ToString("MM/dd/yyyy HH:mm:ss"));

                //process this client:
                //  1) loop/wait for commands
                //  2) respond to the command; return when command AGENT_EXIT received
                try
                {
                    success=ProcessClient(client);
                }
                catch (Exception) { }
                
                //LOG THIS CONNECTION
                try
                {
                    StreamWriter sw = new StreamWriter("ConnectionLog.txt", true);
                    sw.WriteLine(ConnectionLog.ToString() + "--------------------------------------");
                    sw.Close();
                }
                catch (Exception) { }

                //break if told to.
                if (!success)
                    break;
            }
            
            this.ServerLog.AppendLine("AGENT_SERVICE:  Exiting TCP service...");
        }

        /////////////////////////////////////////////////////
        //                                                 //
        // ProcessClient()                                 //
        //                                                 //
        /////////////////////////////////////////////////////
        //Description:  Opens an SSL stream with the client,
        //              authenticating both the server to the
        //              client and vice-versa.  Processes
        //              commands sent in this stream.
        //
        //Returns:      false if told to quit the agent service
        //              or a failure occurs
        /////////////////////////////////////////////////////
        unsafe internal bool ProcessClient(TcpClient client)
        {
            IntPtr hMemStore = IntPtr.Zero;
            X509Store store = null;

            // A client has connected. Create the SslStream using the client's network stream.
            //note the TCP connection stream is automatically closed when this SSL stream object is disposed.
            try
            {
                CurrentSslStream = new SslStream(client.GetStream(), false, ValidateRemoteClientCertificate);
            }
            catch (Exception ex)
            {
                WriteConnectionLog("CONNECT:  Failed to create SSL stream:  " + ex.Message);
                return true;
            }

            // Authenticate the server to the client and vice-versa
            #region client/server authentication code
            try
            {
                WriteConnectionLog("CONNECT:  Authenticating client and server...");

                //------------------------------------------
                //          LOAD PFX CERT STORE
                //------------------------------------------
                //load the x509certificate2 from the PFX
                try
                {
                    //** get password via securestring **//
                    IntPtr pptr = IntPtr.Zero;
                    char[] str = EncryptedPassword.ToCharArray();
                    SecureString certPwd = null;

                    fixed (char* pChars = str)
                    {
                        certPwd = new SecureString(pChars, str.Length);
                    }

                    //decrypt our password in memory
                    pptr = Marshal.SecureStringToBSTR(certPwd);

                    //get x509 cert store from PFX file
                    hMemStore = CwCryptoHelper.GetX509StoreHandleFromPFX(PFXFileName, Marshal.PtrToStringBSTR(pptr));

                    //now use managed code to iterate over the store we just created from PFX
                    store = new X509Store(hMemStore);

                    //there should only be ONE certificate in this PFX store!
                    if (store.Certificates.Count != 1)
                    {
                        WriteConnectionLog("Error:  There are " + store.Certificates.Count.ToString() + " certificates in this store.  I don't know which one to extract, sorry.");

                        CwAgent.Win32Helper.CertCloseStore(hMemStore, 0);
                        //CwCryptoHelper.DestroyStore(store.Name,store.Prov
                        CurrentSslStream.Close();
                        return false;
                    }

                    //zero the password memory
                    Marshal.ZeroFreeBSTR(pptr);
                }
                catch (Exception ex)
                {
                    WriteConnectionLog("Could not extract certificate from PFX file:  " + ex.Message);
                    CurrentSslStream.Close();
                    return false;
                }

                //------------------------------------------
                //              AUTHENTICATE
                //------------------------------------------
                foreach(X509Certificate2 cert in store.Certificates)
                {
                    if (cert.HasPrivateKey)
                    {
                        CurrentSslStream.AuthenticateAsServer(cert, true, SslProtocols.Tls, false);
                        break;
                    }
                }
            }
            catch (AuthenticationException ex)
            {
                WriteConnectionLog("CONNECT:  Authentication error:  " + ex.Message);
                if (ex.InnerException != null)
                    WriteConnectionLog("CONNECT:  Additional error details:  " + ex.InnerException.Message);

                //cleanup
                if (store != null) store.Close();
                if (hMemStore != IntPtr.Zero) CwAgent.Win32Helper.CertCloseStore(hMemStore, 0);
                if (CurrentSslStream != null) CurrentSslStream.Close();
                //CwCryptoHelper.DestroyStore(store.Name,store.Prov

                return false;
            }
            catch (Exception ex)
            {
                WriteConnectionLog("CONNECT:  Caught exception:  " + ex.Message);

                //cleanup
                if (store != null) store.Close();
                if (hMemStore != IntPtr.Zero) CwAgent.Win32Helper.CertCloseStore(hMemStore, 0);
                if (CurrentSslStream != null) CurrentSslStream.Close();
                //CwCryptoHelper.DestroyStore(store.Name,store.Prov

                return false;
            }

            //require strong authentication?
            if (this.RequireStrongAuthentication)
            {
                if (!EnforceStrongAuthentication())
                {
                    WriteConnectionLog("Strong authentication failed.");
                    //cleanup
                    if (store != null) store.Close();
                    if (hMemStore != IntPtr.Zero) CwAgent.Win32Helper.CertCloseStore(hMemStore, 0);
                    if (CurrentSslStream != null) CurrentSslStream.Close();
                    //CwCryptoHelper.DestroyStore(store.Name,store.Prov
                    return false;
                }
            }
            //enforce required issuer 
            if (this.RequiredIssuer != "")
            {
                bool fail = false;
                if (CurrentSslStream.RemoteCertificate == null)
                {
                    fail = true;
                    WriteConnectionLog("Null client certificate not allowed, closing connection...");
                }
                else if (CurrentSslStream.RemoteCertificate.Issuer != this.RequiredIssuer)
                {
                    fail = true;
                    WriteConnectionLog("Client certificate issuer is invalid, closing connection...");
                }

                if (fail)
                {
                    //cleanup
                    if (store != null) store.Close();
                    if (hMemStore != IntPtr.Zero) CwAgent.Win32Helper.CertCloseStore(hMemStore, 0);
                    if (CurrentSslStream != null) CurrentSslStream.Close();
                    //CwCryptoHelper.DestroyStore(store.Name,store.Prov
                    return false;
                }
            }
            #endregion

            WriteConnectionLog("CONNECT:  Connection OK, awaiting commands...");

            //wait for commands and process them serially
            bool success=ProcessCommands();
            WriteConnectionLog("CONNECT:  Session complete, connection closed.");

            try
            {
                CurrentSslStream.Close();
                client.Close();
            }
            catch (Exception) { }

            if (store != null) store.Close();
            if (hMemStore != IntPtr.Zero) CwAgent.Win32Helper.CertCloseStore(hMemStore, 0);

            return success;
        }

        /////////////////////////////////////////////////////
        //                                                 //
        // ProcessCommands()                               //
        //                                                 //
        /////////////////////////////////////////////////////
        //Description:  Continually reads commands.
        //
        //Returns:      true if everything is OK; false if an error
        //              occurs or a command was received to quit.
        /////////////////////////////////////////////////////
        internal bool ProcessCommands()
        {
            bool success = true;

            //LOOP TO READ COMMANDS - normally we would do this in a separate
            //thread if we wanted to allow multiple simultaneous connections
            //to the agent - but we dont want that .
            while (true)
            {
                //**************************************
                //          GET COMMAND DATA
                //**************************************
                //this will block until command is received..
                CwXML.CodewordAgentCommand command = new CwXML.CodewordAgentCommand();
                try
                {
                    //deserialize the XML data in the SSL stream
                    command = ReadCommand();
                }
                //if we failed to interpret the command, create a dummy one to process.
                catch (Exception ex)
                {
                    WriteConnectionLog("CONNECT:  ProcessCommands():  " + ex.Message);

                    command = new CwXML.CodewordAgentCommand();
                    command.CommandCode = CwConstants.AGENTCMD_UNKNOWN;
                    command.CommandParameters = new string[] { "ERROR:  " + ex.Message };
                    command.CommandTimeout = 0;
                    command.ResponseRequired = false;
                }

                //**************************************
                //          PROCESS COMMAND/
                //         SEND RESPONSE DATA
                //**************************************
                //
                WriteConnectionLog("CONNECT:  Got command '" + command.CommandCode.ToString() + "' (setting stream timeouts to "+command.CommandTimeout.ToString()+"), executing...");

                //process the command and serialize our response in the response stream
                CwXML.CodewordAgentResponse response = ExecuteCommand(command);

                //send response
                try
                {
                    SendResponse(response);
                }
                catch (Exception ex)
                {
                    WriteConnectionLog("CONNECT:  ProcessCommands():  Failed to send response:  " + ex.Message);
                }
                
                WriteConnectionLog("CONNECT:  Response code '"+response.ResponseCode+"' sent successfully.");

                //we will stop listening for commands if we receive AGENT_EXIT or AGENT_NOMORECOMMANDS
                //from the remote client, or if we failed reading a command (AGENT_UNKNOWN)
                if (command.CommandCode == CwConstants.AGENTCMD_EXIT || command.CommandCode == CwConstants.AGENTCMD_NOMORECOMMANDS || command.CommandCode == CwConstants.AGENTCMD_UNKNOWN)
                {
                    //well, we were truly successful, but return false so the agent quits as requested.
                    success = false;
                    break;
                }
            }

            try
            {
                CurrentSslStream.Close();
            }
            catch (Exception) { }

            return success;
        }

        /////////////////////////////////////////////////////
        //                                                 //
        // ReadCommand()                                   //
        //                                                 //
        /////////////////////////////////////////////////////
        //Description:  Reads from the stream in 2048-byte chunks.
        //
        //Returns:      The message in UTF-8 decoded format.
        //              It should now be well-formed XML command.
        /////////////////////////////////////////////////////
        internal CwXML.CodewordAgentCommand ReadCommand()
        {
            CwXML.CodewordAgentCommand c = new CwXML.CodewordAgentCommand();
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
                    bytes = CurrentSslStream.Read(buffer, 0, 2048);
                }
                catch (ObjectDisposedException objEx)
                {
                    throw new Exception("ReadCommand():  Stream has been unexpectedly disposed:  "+objEx.Message);
                }
                catch (Exception ex)
                {
                    throw new Exception("ReadCommand():  Caught other exception (read " + bytes + " bytes):  " + ex.Message);
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
            XmlSerializer serializer = new XmlSerializer(typeof(CwXML.CodewordAgentCommand));

            //restore the object's state with data from the XML document
            c = (CwXML.CodewordAgentCommand)serializer.Deserialize(ms);
            ms.Close();

            if (c == null)
                throw new Exception("Command was retrieved, but the command object was null.  Terminating connection.");

            return c;
        }

        /////////////////////////////////////////////////////
        //                                                 //
        // ExecuteCommand()                                //
        //                                                 //
        /////////////////////////////////////////////////////
        //Description:  Executes the given command and returns
        //              a response object.
        //
        //Returns:      A response code, one of the following:
        //                  RESPONSE_EXITING - connection closing
        //                  RESPONSE_OK - command completed successfully
        //                  RESPONSE_FAIL = command failed
        /////////////////////////////////////////////////////
        internal CwXML.CodewordAgentResponse ExecuteCommand(CwXML.CodewordAgentCommand command)
        {
            CwXML.CodewordAgentResponse response = new CwXML.CodewordAgentResponse();
            response.CommandReceiveDate = DateTime.Now.ToString("MM/dd/yyyy HH:mm:ss");
            response.CommandProcessingStartDate = DateTime.Now.ToString("MM/dd/yyyy HH:mm:ss");
            response.ResponseCode = CwConstants.AGENTRESPONSE_OK;
            response.CommandCodeReceived = command.CommandCode;

            //-------------------------------------------------------------
            //                                                            
            //                  GET SYSTEM INFORMATION
            //
            //-------------------------------------------------------------
            #region GET SYSTEM INFORMATION
            if (command.CommandCode == CwConstants.AGENTCMD_GETSYSTEMINFO)
            {
                response.ResponseInfo = "System information retrieved.";
                CwXML.CodewordSystemInformation sysinfo = new CwXML.CodewordSystemInformation();
                sysinfo.HostInformation = new CwXML.HostInformation();
                sysinfo.AgentInformation = new CwXML.AgentInformation();
                //host info
                sysinfo.HostInformation.AgentCurrentDirectory = Environment.CurrentDirectory;
                sysinfo.HostInformation.MachineName = Environment.MachineName;
                sysinfo.HostInformation.NumProcessors = Environment.ProcessorCount.ToString();
                sysinfo.HostInformation.OSVersionShort = Environment.OSVersion.VersionString;
                sysinfo.HostInformation.LogicalDrives = string.Join(",", Environment.GetLogicalDrives());
                sysinfo.HostInformation.IPAddresses = string.Join(",", AgentScanner.EnvironmentHelper.GetIPAddresses());
                sysinfo.HostInformation.OSVersionLong = AgentScanner.EnvironmentHelper.GetOSName();
                sysinfo.HostInformation.UserDomainName = Environment.UserDomainName;
                sysinfo.HostInformation.UserName = Environment.UserName;
                sysinfo.HostInformation.WorkingSetSize = (Environment.WorkingSet / 1000000).ToString() + "MB";
                //agent info
                sysinfo.AgentInformation.Version = Assembly.GetExecutingAssembly().GetName().ToString();
                //use XML settings file in current directory - "CwAgentConfiguration.xml"
                //this will allow us to deserialize the XML data into class structures
                CwXML xml = new CwXML();
                CwXML.CodewordSettingsTemplate cst = new CwXML.CodewordSettingsTemplate();
                try
                {
                    cst = xml.LoadSettingsXML("CwAgentConfiguration.xml");
                }
                catch (Exception e)
                {
                    response.ResponseInfo = "There was an error retrieving the agent settings:  " + e.Message;
                }
                sysinfo.AgentInformation.AgentSettings = cst;
                //use XML signatures file in current directory - "CwAgentSignatures.xml"
                //this will allow us to deserialize the XML data into class structures
                xml = new CwXML();
                CwXML.CodewordSignatureTemplate sigs = new CwXML.CodewordSignatureTemplate();
                try
                {
                    sigs = xml.ImportSignatureTemplate("CwAgentSignatures.xml");
                }
                catch (Exception e)
                {
                    response.ResponseInfo = "There was an error retrieving the agent signatures:  " + e.Message;
                }
                sysinfo.AgentInformation.AgentSignatures = sigs;
                
                //assign sysinfo object to return response
                response.ResponseSystemInformation = sysinfo;
            }
            #endregion
            //-------------------------------------------------------------
            //                                                            
            //                  DOWNLOAD EVIDENCE FILES (COLLECT)
            //
            //-------------------------------------------------------------
            #region DOWNLOAD EVIDENCE FILES (COLLECT)
            else if (command.CommandCode == CwConstants.AGENTCMD_COLLECT)
            {
                //===================================================================
                //  SEND INTERMEDIATE RESPONSE TO TELL HOST TO START RECEIVING FILES
                //===================================================================
                //send a response then prepare to send
                WriteConnectionLog("CONNECT:  Got command to send evidence files...");

                CwXML.CodewordAgentResponse response2 = new CwXML.CodewordAgentResponse();
                response2.CommandReceiveDate = DateTime.Now.ToString("MM/dd/yyyy HH:mm:ss");
                response2.CommandProcessingStartDate = DateTime.Now.ToString("MM/dd/yyyy HH:mm:ss");
                response2.ResponseCode = CwConstants.AGENTRESPONSE_OK_RECVFILE;
                response2.CommandCodeReceived = command.CommandCode;

                WriteConnectionLog("CONNECT:  Sending response...");

                //send response
                try
                {
                    SendResponse(response2);
                }
                catch (Exception ex)
                {
                    WriteConnectionLog("Failed to send response in preparation for evidence collection:  " + ex.Message);
                    response.ResponseCode = CwConstants.AGENTRESPONSE_FAIL;
                    response.ResponseInfo = "Failed to send response in preparation for evidence collection:  " + ex.Message;
                    return response;
                }

                WriteConnectionLog("CONNECT:  Sending files..");

                //===================================================================
                //                      SEND EVIDENCE FILES
                //===================================================================
                //get list of files tos end
                CwXML.FileSignatureMatch[] fileSigsToSend = command.CommandCollectOrMitigationTask.SignatureMatches.FileSignatureMatches;
                int count = 0;

                //send the files
                foreach (CwXML.FileSignatureMatch match in fileSigsToSend)
                {
                    try
                    {
                        SendBinaryFile(match.FullPath);
                    }
                    catch (Exception ex)
                    {
                        response.ResponseCode = CwConstants.AGENTRESPONSE_FAIL;
                        response.ResponseInfo = "Failed to send binary file '" + match.FullPath + "':  " + ex.Message;
                        break;
                    }
                    count++;
                }

                if (response.ResponseCode == CwConstants.AGENTRESPONSE_OK)
                    response.ResponseInfo = "Successfully sent " + count + " evidence files.";
            }
            #endregion
            //-------------------------------------------------------------
            //                                                            
            //                  PERFORM MITIGATION TASK
            //
            //-------------------------------------------------------------
            #region PERFORM MITIGATION TASK
            else if (command.CommandCode == CwConstants.AGENTCMD_MITIGATE)
            {
                //the mitigation task is stored in the command object as an anomaly report
                CwXML.CodewordAgentAnomalyReport MitigationTask = command.CommandCollectOrMitigationTask;

                if (MitigationTask != null)
                {
                    CwXML.CodewordAgentSignatureMatches matches = MitigationTask.SignatureMatches;
                    //mitigate registry items
                    if (matches.RegistrySignatureMatches != null)
                    {
                        if (matches.RegistrySignatureMatches.Length > 0)
                        {
                            CwXML.RegistrySignatureMatch[] regMatches = matches.RegistrySignatureMatches;
                            AgentScanner.RegistryHelper RegistryScanner = new AgentScanner.RegistryHelper();
                            RegistryScanner.LoadNtUserDatFiles(false);
                            RegistryScanner.CleanRegistryFindings(ref regMatches, false);
                            RegistryScanner.LoadNtUserDatFiles(true);
                            response.ResponseLog = RegistryScanner.RegistryHelperLog.ToString();
                            //assign the matches back to our main object, so the ActionSuccessful variable gets sent back
                            matches.RegistrySignatureMatches = regMatches;
                        }
                    }
                    //mitigate file items
                    if (matches.FileSignatureMatches != null)
                    {
                        if (matches.FileSignatureMatches.Length > 0)
                        {
                            CwXML.FileSignatureMatch[] fileMatches = matches.FileSignatureMatches;
                            AgentScanner.FileHelper FileScanner = new AgentScanner.FileHelper();
                            FileScanner.CleanFileFindings(ref fileMatches);
                            response.ResponseLog = FileScanner.FileHelperLog.ToString();
                            //assign the matches back to our main object, so the ActionSuccessful variable gets sent back
                            matches.FileSignatureMatches = fileMatches;
                        }
                    }
                    //mitigate memory items
                    if (matches.MemorySignatureMatches != null)
                    {
                        if (matches.MemorySignatureMatches.Length > 0)
                        {
                            CwXML.MemorySignatureMatch[] memMatches = matches.MemorySignatureMatches;
                            AgentScanner.MemoryHelper MemoryScanner = new AgentScanner.MemoryHelper();
                            MemoryScanner.CleanMemoryFindings(ref memMatches);
                            response.ResponseLog = MemoryScanner.MemoryHelperLog.ToString();
                            //assign the matches back to our main object, so the ActionSuccessful variable gets sent back
                            matches.MemorySignatureMatches = memMatches;
                        }
                    }
                    //assign the main object to the response's anomaly report
                    response.ResponseAnomalyReport = new CwXML.CodewordAgentAnomalyReport();
                    response.ResponseAnomalyReport.SignatureMatches = matches;
                }
                else
                {
                    response.ResponseInfo = "Error completing mitigation task:  the mitigation object was null!";
                    response.ResponseCode = CwConstants.AGENTRESPONSE_FAIL;
                }
            }
            #endregion
            //-------------------------------------------------------------
            //                                                            
            //                  START A NEW SCAN
            //
            //-------------------------------------------------------------
            #region START A NEW SCAN
            else if (command.CommandCode == CwConstants.AGENTCMD_STARTSCAN)
            {
                //ENTERPRISE MODE CHECK:
                //make sure there isnt an already-completed scan from
                //starting up in enterprise mode.
                if (EnterpriseModeScanLog != null)
                {
                    response.ResponseLog = EnterpriseModeScanLog.ToString();
                    response.ResponseInfo = "These results are from a previous scan issued during agent startup.  To run a new scan, please re-issue the scan command.";
                    //clear the enterprise scan results 
                    EnterpriseModeScanLog = null;
                }
                //otherwise, issue a completely new scan task
                //warning:  this can be a lengthy operation (> 10 min)
                else
                {
                    CwXML.CodewordAgentAnomalyReport anomalyReport = new CwXML.CodewordAgentAnomalyReport();
                    AgentScanner scanner = new AgentScanner();
                    StringBuilder scannerLog = new StringBuilder();

                    try
                    {
                        scannerLog = scanner.StartScanTask(ref anomalyReport);
                    }
                    catch (Exception ex)
                    {
                        StreamWriter sw = new StreamWriter("AgentScanLog.txt", false);
                        sw.WriteLine(ex.Message);
                        sw.WriteLine("");
                        if (AgentScanner.AgentScanLog != null)
                            sw.WriteLine(AgentScanner.AgentScanLog.ToString());
                        sw.Close();
                    }

                    if (scannerLog != null && anomalyReport != null)
                    {
                        response.ResponseAnomalyReport = anomalyReport; //invalid xml chars replaced in AgentScanner.StartScanTask()
                        response.ResponseInfo = "Scan complete.";
                        response.ResponseLog = CwXML.ReplaceInvalidXmlChars(scannerLog.ToString());
                    }
                    else
                    {
                        response.ResponseCode = CwConstants.AGENTRESPONSE_FAIL;
                        response.ResponseInfo = "An unrecoverable error occured during the scan.";
                    }
                }
            }
            #endregion
            //-------------------------------------------------------------
            //                                                            
            //                  EXIT, NO MORE COMMANDS
            //
            //-------------------------------------------------------------
            #region EXIT
            else if (command.CommandCode == CwConstants.AGENTCMD_EXIT || command.CommandCode == CwConstants.AGENTCMD_NOMORECOMMANDS)
            {
                //
                //NO ACTION REQUIRED
                //
            }
            #endregion
            //-------------------------------------------------------------
            //                                                            
            //                  INVALID COMMAND
            //
            //-------------------------------------------------------------
            #region INVALID COMMAND
            else if (command.CommandCode == CwConstants.AGENTCMD_UNKNOWN)
            {
                response.ResponseCode = CwConstants.AGENTRESPONSE_FAIL;
                //the error is stored in this member of the fake command we created earlier
                response.ResponseInfo = string.Join(",", command.CommandParameters);
            }
            #endregion
            //-------------------------------------------------------------
            //                                                            
            //              RECEIVE NEW SIGNATURE UPDATE FILE
            //
            //-------------------------------------------------------------
            #region RECEIVE NEW SIGNATURE UPDATE FILE
            else if (command.CommandCode == CwConstants.AGENTCMD_UPDATESIG)
            {
                //send a response then prepare to receive
                WriteConnectionLog("CONNECT:  Got command to download new signature file...");

                CwXML.CodewordAgentResponse response2 = new CwXML.CodewordAgentResponse();
                response2.CommandReceiveDate = DateTime.Now.ToString("MM/dd/yyyy HH:mm:ss");
                response2.CommandProcessingStartDate = DateTime.Now.ToString("MM/dd/yyyy HH:mm:ss");
                response2.ResponseCode = CwConstants.AGENTRESPONSE_OK_SENDFILE;
                response2.CommandCodeReceived = command.CommandCode;

                WriteConnectionLog("CONNECT:  Sending response...");

                //send response
                try
                {
                    SendResponse(response2);
                }
                catch (Exception ex)
                {
                    WriteConnectionLog("Failed to send response in preparation for file retrieval:  " + ex.Message);
                    response.ResponseCode = CwConstants.AGENTRESPONSE_FAIL;
                    response.ResponseInfo = "Failed to send response in preparation for file retrieval:  " + ex.Message;
                    return response;
                }

                byte[] filedata;

                WriteConnectionLog("CONNECT:  Waiting for file...");

                //receive the file
                try
                {
                    filedata = ReceiveFile();
                }
                catch (Exception ex)
                {
                    WriteConnectionLog("Failed to receive file contents:  " + ex.Message);
                    response.ResponseCode = CwConstants.AGENTRESPONSE_FAIL;
                    response.ResponseInfo = "Failed to receive file contents:  " + ex.Message;
                    return response;
                }

                WriteConnectionLog("CONNECT:  File retrieved, saving locally...");

                //overwrite our current XML signature file
                try
                {
                    if (File.Exists("CwAgentSignatures.xml"))
                        File.Delete("CwAgentSignatures.xml");

                    AgentScanner.EnvironmentHelper.BinaryWrite("CwAgentSignatures.XML", filedata);
                }
                catch (Exception ex)
                {
                    WriteConnectionLog("Failed to write new signature file:  " + ex.Message);
                    response.ResponseCode = CwConstants.AGENTRESPONSE_FAIL;
                    response.ResponseInfo = "Failed to write new signature file:  " + ex.Message;
                    return response;
                }

                //success!
                response.ResponseInfo = "Successfully updated signatures file.";
            }
            #endregion

            response.CommandProcessingEndDate = DateTime.Now.ToString("MM/dd/yyyy HH:mm:ss");

            return response;
        }

        /////////////////////////////////////////////////////
        //                                                 //
        // SendResponse()                                  //
        //                                                 //
        /////////////////////////////////////////////////////
        //Description:  Attempts to send a message over SSL.
        //
        //Throws:       Serialization error
        //
        //Returns:      true if successful
        /////////////////////////////////////////////////////
        internal bool SendResponse(CwXML.CodewordAgentResponse response)
        {
            //create an XML serialization object to prepare the command
            XmlSerializer serializer = new XmlSerializer(typeof(CwXML.CodewordAgentResponse));

            //create a memory stream to which we will serialize our response object
            MemoryStream memStream = new MemoryStream();

            //store the object's state in XML format into the memory stream store
            serializer.Serialize(memStream, response);

            //tack on "<EOF>" to the message, so the server knows when to stop reading the socket
            char[] eofbuf = new char[] { '<', 'E', 'O', 'F', '>' };
            memStream.Write(Encoding.UTF8.GetBytes(eofbuf), 0, eofbuf.Length);

            //try to send the raw bytes in the memory stream to the remote socket
            try
            {
                //result of 5 hour debug session:  dont use memstream.getBuffer()
                //it returns all bytes in the buffer, not only the ones used..use ToArray() instead!!
                CurrentSslStream.Write(memStream.ToArray());
                CurrentSslStream.Flush();
            }
            catch (Exception ex)
            {
                throw new Exception("sslStream.Write() exception:  " + ex.Message);
            }

            //DEBUG
            /*
            StreamWriter sw = new StreamWriter("ResponseSent.xml");
            sw.Write(new string(Encoding.UTF8.GetChars(memStream.ToArray())));
            sw.Close();
            */
            try
            {
                memStream.Close();
            }
            catch (Exception) { }

            return true;
        }

        /////////////////////////////////////////////////////
        //                                                 //
        // SendFile()                                      //
        //                                                 //
        /////////////////////////////////////////////////////
        //Description:  Attempts to send a file over SSL.
        //
        //Throws:       write error
        //
        //Returns:      true if successful
        /////////////////////////////////////////////////////
        internal bool SendBinaryFile(string fullpath)
        {
            MemoryStream ms = new MemoryStream();

            //try to get file attributes
            FileInfo fi = new FileInfo(fullpath);

            //try to read the file directly
            try
            {
                using (FileStream fileStream = new FileStream(fullpath,FileMode.Open,FileAccess.Read,FileShare.ReadWrite))
                {
                    using (BinaryReader b = new BinaryReader(fileStream))
                    {
                        //slurp the file into memory
                        ms.Write(b.ReadBytes((int)fi.Length), 0, (int)fi.Length);
                    }
                }
            }
            catch (Exception)
            {
                /*
                //use win32 api CreateFile() to open in shared access mode.
                //this is in case the file is in use, such as a driver
                IntPtr hFile = Win32Helper.CreateFile(
                                                        fullpath,
                                                        Win32Helper.GENERIC_READ,
                                                        Win32Helper.FILE_SHARE_READ|Win32Helper.FILE_SHARE_WRITE,
                                                        IntPtr.Zero,
                                                        Win32Helper.OPEN_EXISTING,
                                                        Win32Helper.FILE_FLAG_BACKUP_SEMANTICS,
                                                        IntPtr.Zero
                                                        );
                //invalid handle?
                if (hFile == (IntPtr)(-1))
                {
                    throw new Exception("Failed to copy file; it most likely locked.");
                }

                byte[] buf=new byte[fi.Length];
                uint lpNumberOfBytesRead = 0;

                //use BackupRead() to make a "backup copy" of this file :)
                if (!Win32Helper.BackupRead(hFile, out buf, (uint)fi.Length, out lpNumberOfBytesRead, false, false, IntPtr.Zero))
                {


                }*/
            }

            //try to send the raw bytes in the memory stream to the remote socket
            try
            {
                //result of 5 hour debug session:  dont use memstream.getBuffer()
                //it returns all bytes in the buffer, not only the ones used..use ToArray() instead!!
                CurrentSslStream.Write(ms.ToArray());
                CurrentSslStream.Flush();
            }
            catch (Exception ex)
            {
                throw new Exception("ClientSslStream.Write() error on file '"+fullpath+"':  " + ex.Message);
            }

            ms.Close();

            return true;
        }

        /////////////////////////////////////////////////////
        //                                                 //
        // ReceiveFile()                                   //
        //                                                 //
        /////////////////////////////////////////////////////
        //Description:  Attempt to recv a file over SSL.
        //
        //Throws:       read error
        //
        //Returns:      the binary data
        /////////////////////////////////////////////////////
        internal byte[] ReceiveFile()
        {
            MemoryStream ms = new MemoryStream();
            Decoder UTF8Decoder = Encoding.UTF8.GetDecoder();
            int bytes = -1;
            byte[] buffer;

            do
            {
                buffer = new byte[2048];

                try
                {
                    //store a max of 2048 bytes starting at offset 0 in the buffer array
                    bytes = CurrentSslStream.Read(buffer, 0, 2048);
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
            byte[] bData = ms.ToArray();
            char[] charArray = new char[UTF8Decoder.GetCharCount(bData, 0, bData.Length)];
            UTF8Decoder.GetChars(bData, 0, bData.Length, charArray, 0);
            string s = new string(charArray);
            s = s.Replace("<EOF>", "");
            ms.Close();

            return Encoding.UTF8.GetBytes(s);
        }

        /////////////////////////////////////////////////////
        //                                                 //
        // EnforceStrongAuthentication()                   //
        //                                                 //
        /////////////////////////////////////////////////////
        //Description:  checks various attributes of the given
        //              SSL stream to make sure it stands up
        //              to strong auth standards (FIPS 140-2).
        //
        //Returns:      false if not strong.
        /////////////////////////////////////////////////////
        internal bool EnforceStrongAuthentication()
        {
            if (CurrentSslStream.CipherAlgorithm != CipherAlgorithmType.Aes256)
            {
                WriteConnectionLog("LISTEN:  Strong authentication failed:  Cipher algorithm is "+CurrentSslStream.CipherAlgorithm.ToString()+", not AES-256.");
                return false;
            }
            if (CurrentSslStream.CipherStrength < 128)
            {
                WriteConnectionLog("LISTEN:  Cipher strength less than 128-bit:  "+CurrentSslStream.CipherStrength.ToString());
                return false;
            }
            if (CurrentSslStream.HashAlgorithm != HashAlgorithmType.Sha1)
            {
                WriteConnectionLog("LISTEN:  Hash algorithm not SHA-1:  "+CurrentSslStream.HashAlgorithm.ToString());
                return false;
            }
            if (CurrentSslStream.HashStrength < 256)
            {
                WriteConnectionLog("LISTEN:  Hash strength less than 256:  "+CurrentSslStream.HashStrength.ToString());
                return false;
            }
            if (CurrentSslStream.KeyExchangeAlgorithm != ExchangeAlgorithmType.RsaKeyX)
            {
                WriteConnectionLog("LISTEN:  Key exchange algorithm is "+CurrentSslStream.KeyExchangeAlgorithm.ToString()+", not RsaKeyX.");
                return false;
            }
            if (CurrentSslStream.KeyExchangeStrength < 256)
            {
                WriteConnectionLog("LISTEN:  Key exchange strength is less than 256:  "+CurrentSslStream.KeyExchangeStrength.ToString());
                return false;
            }
            if (CurrentSslStream.SslProtocol != SslProtocols.Tls)
            {
                WriteConnectionLog("LISTEN:  SSL protocol is "+CurrentSslStream.SslProtocol.ToString()+", not TLS.");
                return false;
            }
            if (!CurrentSslStream.IsSigned)
            {
                WriteConnectionLog("LISTEN:  Stream is not signed.");
                return false;
            }
            if (!CurrentSslStream.IsEncrypted)
            {
                WriteConnectionLog("LISTEN:  Stream is not encrypted.");
                return false;
            }
            if (!CurrentSslStream.CheckCertRevocationStatus)
            {
                WriteConnectionLog("LISTEN:  Stream has disabled the ability to check certificate revocation status.");
                return false;
            }

            return true;
        }

        internal void WriteConnectionLog(string s)
        {
            //LOG THIS CONNECTION
            try
            {
                StreamWriter sw = new StreamWriter("ConnectionLog.txt", true);
                sw.WriteLine(s);
                sw.Close();
            }
            catch (Exception) { }
        }

        internal static void LogHit(int n)
        {
            StreamWriter sw = new StreamWriter("loghit.txt", true);
            sw.WriteLine(n.ToString());
            sw.Close();
        }
    }
}