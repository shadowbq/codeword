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
using System.Diagnostics;
using System.Management;
using System.Management.Instrumentation;
using System.Collections.Generic;
using System.Collections;
using System.Collections.Specialized;
using System.Text;
using System.IO;
using System.Reflection;
using System.ComponentModel;
using System.Threading;
using System.Security.Principal;
using System.Net;
using System.Net.Mail;
using System.Net.NetworkInformation;
using System.Net.Security;
using System.Net.Sockets;
using System.Text.RegularExpressions;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography;
using System.Security;
using System.Runtime.InteropServices;
using Ionic.Utils.Zip;
using Microsoft.Win32;
using CwHandler;

namespace CwAgent
{
    class Reporting
    {
        internal static string serverPublicKey = "";
        internal static bool authenticateClient = false;

        /////////////////////////////////////////////////////
        //                                                 //
        // SendResults()                                   //
        //                                                 //
        /////////////////////////////////////////////////////
        //Description:  attempts to send the ZIP file results
        //              via selected reporting method and also
        //              sends a summary email if requested.
        //Returns:      nothing
        /////////////////////////////////////////////////////
        unsafe public static void SendResults(Dictionary<string, string> settings, string zipfilename)
        {
            //if we have no live connection, bail since everything we need to do here requires it.
            if (!NetworkInterface.GetIsNetworkAvailable())
            {
                Console.WriteLine("WARNING:  There is no live network connection!  Remote reporting will not occur.");
                return;
            }

            Console.WriteLine("FINALIZE:  Network connection detected.");

            //*************************************
            //          CONFIGURE TLS
            //*************************************

            //determine if we are using TLS
            bool useTLS=false;
            string hostname = "";
            string port = "";

            //use TLS/SSL for transport-layer security?
            if (settings.ContainsKey("Reporting_Use_TLS"))
                if (settings["Reporting_Use_TLS"] == "True")
                    useTLS = true;

            //-------------------------------------
            //determine host name and port to use
            //-------------------------------------
            //if using TLS, get TLS port
            if (settings.ContainsKey("Reporting_TLS_Port"))
                port = settings["Reporting_TLS_Port"];

            // ** FTP SERVER ** //
            if (settings.ContainsKey("Reporting_Method_FTPServer"))
            {
                hostname=settings["Reporting_Method_FTPServer"];
                //if not using TLS port, use 21
                if (port == "")
                    port = "21";
            }
            // ** SMTP SERVER / EMAIL ** //
            else if (settings.ContainsKey("Reporting_Method_EmailAddress"))
            {
                hostname=settings["Reporting_SMTP_Server"];
                //if not using TLS port, use supplied SMTP port
                if (port=="")
                    port = settings["Reporting_SMTP_Port"];
            }
            // ** WEB SERVER/SSL ** //
            else if (settings.ContainsKey("Reporting_Method_WebServer_URI"))
            {
                hostname = settings["Reporting_Method_WebServer_URI"];
                //get the base domain name, e.g, mydomain.domain.com from URI
                hostname = hostname.Substring(0, hostname.IndexOf('/'));

                if (port == "")
                    port = settings["Reporting_WebServer_Port"];
            }

            //**************************************************
            //          TRANSPORT LAYER AUTHENTICATION
            //**************************************************
            if (useTLS)
            {
                string serverPubKeyFilename = "";

                //was server public key specified?
                if (settings.ContainsKey("Reporting_Auth_Server_PubKey"))
                {
                    serverPubKeyFilename = settings["Reporting_Auth_Server_PubKey"];
                    Console.WriteLine("FINALIZE:  Using server's public key stored in file '" + serverPubKeyFilename + "'...");
                    try
                    {
                        serverPublicKey = CwCryptoHelper.GetX509RawStringFromFile(serverPubKeyFilename);
                    }
                    catch (Exception ex)
                    {
                        Console.WriteLine("ERROR:  Failed to get raw certificate string from file.");
                        Console.WriteLine("ERROR:  " + ex.Message);
                        return;
                    }
                }

                //authenticate client?
                if (settings.ContainsKey("Reporting_AuthenticateClient"))
                    if (settings["Reporting_AuthenticateClient"] == "True")
                        authenticateClient = true;
            }

            //**************************************************
            //          APPLICATION LAYER AUTHENTICATION
            //**************************************************
            SecureString username = new SecureString();
            SecureString password = new SecureString();
            string authType = "";

            //use application-layer authentication (user name and password)?
            if (settings.ContainsKey("Reporting_Auth_UserName"))
            {
                fixed(char* ptr = settings["Reporting_Auth_UserName"].ToCharArray(), ptr2=settings["Reporting_Auth_Password"].ToCharArray())
                {
                    username = new SecureString(ptr, settings["Reporting_Auth_UserName"].ToCharArray().Length);
                    password = new SecureString(ptr2,settings["Reporting_Auth_Password"].ToCharArray().Length);
                }
            
                //authentication type is optional and only used for
                //web reporting - NTLM, Basic, Digest or Kerberos
                if (settings.ContainsKey("Reporting_Auth_Type"))
                    authType = settings["Reporting_Auth_Type"];
            }

            //**************************************************
            //                  * SEND *
            //**************************************************
            bool sendSuccessful = false;

            // ** NETWORK SHARE ** //
            if (settings.ContainsKey("Reporting_Method_NetworkShare"))
            {
                sendSuccessful = SendZipFileNetworkShare(
                                                            username,
                                                            password,
                                                            settings["Reporting_Method_NetworkShare"],
                                                            zipfilename
                                                            );
            }
            // ** FTP SERVER ** //
            else if (settings.ContainsKey("Reporting_Method_FTPServer"))
            {
                sendSuccessful = SendZipFileFTP(
                                                    username,
                                                    password,
                                                    settings["Reporting_Method_FTPServer"],
                                                    port,
                                                    zipfilename,
                                                    useTLS
                                                    );
            }
            // ** SMTP SERVER / EMAIL ** //
            else if (settings.ContainsKey("Reporting_Method_EmailAddress"))
            {
                sendSuccessful = SendZipFileSMTP(
                                                    username,
                                                    password,
                                                    settings["Reporting_SMTP_Server"],
                                                    port,
                                                    settings["Reporting_Method_EmailAddress"],
                                                    zipfilename,
                                                    useTLS
                                                    );
            }
            // ** WEB SERVER/SSL ** //
            else if (settings.ContainsKey("Reporting_Method_WebServer_URI"))
            {
                sendSuccessful = SendZipFileWeb(
                                                    username,
                                                    password,
                                                    settings["Reporting_Method_WebServer_URI"],
                                                    port,
                                                    zipfilename,
                                                    useTLS,
                                                    authType
                                                    );
            }

            //delete zip file if the send operation was successful.
            if (sendSuccessful)
            {
                Console.WriteLine("FINALIZE:  Deleting ZIP file...");
                try
                {
                    File.Delete(zipfilename);
                }
                catch { };
                Console.WriteLine("FINALIZE:  Success.");
            }
            else
            {
                Console.WriteLine("FINALIZE:  The send operation failed.");
            }
        }

        /////////////////////////////////////////////////////
        //                                                 //
        // SendZipFileNetworkShare()                       //
        //                                                 //
        /////////////////////////////////////////////////////
        //Description:  Maps a remote share name to a local drive
        //              letter and then copies the archive file 
        //              to that share, then disconnects share.
        //              Authentication is optional.
        //Returns:      true if successful
        /////////////////////////////////////////////////////
        public static bool SendZipFileNetworkShare(SecureString username, SecureString password, string networkshare, string zipfilename)
        {
            Console.WriteLine("FINALIZE:  Sending results via network share '" + networkshare + "'...");

            string nextDriveLetter = GetNextAvailableDriveLetter() + ":";

            Console.WriteLine("FINALIZE:  Creating mapped drive on '" + nextDriveLetter + "'...");

            //create a new Win32 NETRESOURCE struct in preparation for mapping the network drive
            Win32Helper.NETRESOURCE mappedDrive = new Win32Helper.NETRESOURCE();
            mappedDrive.dwScope = Win32Helper.RESOURCE_GLOBALNET;
            mappedDrive.dwScope = Win32Helper.RESOURCETYPE_DISK;
            mappedDrive.dwUsage = Win32Helper.RESOURCEUSAGE_CONNECTABLE;
            mappedDrive.lpRemoteName = networkshare;
            mappedDrive.lpLocalName = nextDriveLetter;
            mappedDrive.lpComment = "";
            mappedDrive.lpProvider = "";

            //Map the drive using authentication
            if (username.Length != 0)
            {
                Console.WriteLine("FINALIZE:  Using supplied credentials...");

                //map the remote network share to the next available local drive letter
                if (Win32Helper.WNetAddConnection2(ref mappedDrive, CwBasicEncryption.GetStringFromSecureString(password), CwBasicEncryption.GetStringFromSecureString(username), 0) != 0)
                {
                    Console.WriteLine("ERROR:  Could not map a drive to '" + nextDriveLetter + "'!");
                    Console.WriteLine("ERROR:  " + Win32Helper.GetLastError32());
                    return false;
                }
            }
            //map the drive using no credentials
            else
            {
                Console.WriteLine("FINALIZE:  Using anonymous login...");

                //map the remote network share to the next available local drive letter
                if (Win32Helper.WNetAddConnection2(ref mappedDrive, "", "", 0) != 0)
                {
                    Console.WriteLine("ERROR:  Could not map a drive to '" + nextDriveLetter + "'!");
                    Console.WriteLine("ERROR:  " + Win32Helper.GetLastError32());
                    return false;
                }
            }

            Console.WriteLine("FINALIZE:  Connection established.");
            Console.WriteLine("FINALIZE:  Sending results...");

            //we now have a mapped drive.  So just do a File.Copy()!
            try
            {
                File.Copy(zipfilename, nextDriveLetter + "\\" + zipfilename);
            }
            catch (Exception ex)
            {
                Console.WriteLine("ERROR:  Failed to copy archive from '" + zipfilename + "' to '" + nextDriveLetter + "\\" + zipfilename + "'.");
                Console.WriteLine("ERROR:  '" + ex.Message + "'");
                return false;
            }

            Console.WriteLine("FINALIZE:  Success!");
            Console.WriteLine("FINALIZE:  Disconnecting mapped drive '" + nextDriveLetter + "'...");

            //disconnect the network share
            if (Win32Helper.WNetCancelConnection2(nextDriveLetter, 0, 1) != 0)
            {
                Console.WriteLine("ERROR:  Could not disconnect mapped drive '" + nextDriveLetter + "'!");
                Console.WriteLine("ERROR:  " + Win32Helper.GetLastError32());
                return false;
            }

            return true;
        }

        /////////////////////////////////////////////////////
        //                                                 //
        // SendZipFileFTP()                                //
        //                                                 //
        /////////////////////////////////////////////////////
        //Description:  Connects to an FTP server using provided
        //              credentials.  TLS optional, authentication required.
        //Returns:      true if successful
        /////////////////////////////////////////////////////
        public static bool SendZipFileFTP(SecureString username, SecureString password, string server_name, string port, string zipfilename, bool useTLS)
        {
            Console.WriteLine("FINALIZE:  Sending results via FTP.");
            if (useTLS)
                Console.WriteLine("FINALIZE:  Using FTP over SSL/TLSv1.0 (FTP-S)...");

            IntPtr pUserName = Marshal.SecureStringToBSTR(username);
            IntPtr pPassword = Marshal.SecureStringToBSTR(password);
            
            //URL must have file name in it to upload
            string url = "ftp://" + server_name + "/" + zipfilename;
            Uri uri = new Uri(url);

            //create FTPwebrequest object
            FtpWebRequest ftp;
            try
            {
                ftp = (FtpWebRequest)FtpWebRequest.Create(uri);
            }
            catch (Exception ex)
            {
                Console.WriteLine("ERROR:  Failed to create FtpWebRequest object from URI '" + uri.ToString() + "':  " + ex.Message);
                Marshal.FreeBSTR(pUserName);
                Marshal.FreeBSTR(pPassword);
                return false;
            }

            //if requested, make the stream an SSL/TLS stream
            if (useTLS)
            {
                ftp.EnableSsl = true;
                ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls;

                //***********************************************
                //          AUTHENTICATE SERVER/CLIENT
                //***********************************************
                //if a server public key was specified, then we need to register a callback to validate the server's public key
                if (serverPublicKey != "")
                {
                    ServicePointManager.CheckCertificateRevocationList = true;

                    //specify a ServicePointManager callback to check for SSL errors and validate the server's public key
                    ServicePointManager.ServerCertificateValidationCallback += delegate(object sender, X509Certificate cert, X509Chain chain, SslPolicyErrors sslErrors)
                    {
                        Console.WriteLine("FINALIZE:  Validating server certificate...");
                        /*
                        Console.WriteLine("FINALIZE:  Checking for SSL errors...");

                        //HANDLE SSL ERRORS
                        if (sslErrors == SslPolicyErrors.RemoteCertificateChainErrors)
                        {
                            Console.WriteLine("ERROR:  There are errors in the server's certificate:  certificate chain is invalid:");

                            foreach (X509ChainStatus chainStat in chain.ChainStatus)
                            {
                                Console.WriteLine("\t\tStatus:  " + chainStat.Status.ToString());
                                Console.WriteLine("\t\tInformation:  " + chainStat.StatusInformation);
                            }
                                
                            return false;
                        }
                        else if (sslErrors == SslPolicyErrors.RemoteCertificateNameMismatch)
                        {
                            Console.WriteLine("ERROR:  There are errors in the server's certificate:  certificate name mismatch.");
                            return false;
                        }
                        else if (sslErrors == SslPolicyErrors.RemoteCertificateNotAvailable)
                        {
                            Console.WriteLine("ERROR:  There are errors in the server's certificate:  remote certificate not available.");
                            return false;
                        }
                        */
                        Console.WriteLine("FINALIZE:  Checking raw certificate data against known good...");

                        //validate the certificate raw data
                        if (cert.GetRawCertDataString() != serverPublicKey)
                        {
                            Console.WriteLine("ERROR:  The server's public key did not match a known good certificate.");
                            return false;
                        }

                        Console.WriteLine("FINALIZE:  Success!  Server certificate has been validated.");

                        return true;
                    };

                    //***********************************************
                    //          AUTHENTICATE CLIENT AS WELL
                    //***********************************************
                    //if additionally a client pub/priv key file was specified, we will validate the client also
                    if (authenticateClient)
                    {
                        Console.WriteLine("FINALIZE:  Using client certificates installed to local keystore.");

                        //set the client certificates for this web request
                        //see limitations:  http://msdn.microsoft.com/en-us/library/ms229719.aspx
                        try
                        {
                            ftp.ClientCertificates = CwCryptoHelper.GetX509CertificateCollectionFromLocalHostStore();
                        }
                        catch (Exception ex)
                        {
                            Console.WriteLine("ERROR:  " + ex.Message);
                            return false;
                        }
                    }
                }
                //***********************************************
                //          NO AUTHENTICATION!!
                //***********************************************
                //otherwise, no validation is done at all
                else
                {
                    Console.WriteLine("WARNING:  Trusting server without validation!");

                    //specify a ServicePointManager callback to just return true on server cert
                    ServicePointManager.ServerCertificateValidationCallback += delegate(object sender, X509Certificate cert, X509Chain chain, SslPolicyErrors sslErrors)
                    {
                        return true;
                    };
                }
            }

            ftp.Method = WebRequestMethods.Ftp.UploadFile;
            ftp.Credentials = new NetworkCredential(Marshal.PtrToStringBSTR(pUserName), Marshal.PtrToStringBSTR(pPassword));
            ftp.UsePassive = true;
            ftp.UseBinary = true;
            ftp.KeepAlive = true;

            //get archive file contents
            byte[] fileContents;
            try
            {
                StreamReader sourceStream = new StreamReader(zipfilename);
                fileContents = Encoding.UTF8.GetBytes(sourceStream.ReadToEnd());
                sourceStream.Close();
                ftp.ContentLength = fileContents.Length;
            }
            catch (Exception ex)
            {
                Console.WriteLine("ERROR:  Could not get archive contents:  " + ex.Message);
                Marshal.FreeBSTR(pUserName);
                Marshal.FreeBSTR(pPassword);
                return false;
            }

            Console.WriteLine("FINALIZE:  Connecting to '" + url + "'...");
            Console.WriteLine("FINALIZE:  Uploading file...");

            ftp.Timeout = 15000;  //wait 15 seconds before connect timeout
            ftp.ReadWriteTimeout = 20000;  //wait 20 seconds before stream timeout

            //send file contents to ftp server
            try
            {
                using (Stream writer = ftp.GetRequestStream())
                {
                    writer.Write(fileContents, 0, fileContents.Length);
                }
            }
            catch(Exception ex)
            {
                Console.WriteLine("ERROR:  Could not upload file:  "+ex.Message);
                Marshal.FreeBSTR(pUserName);
                Marshal.FreeBSTR(pPassword);
                return false;
            }

            //get server response
            FtpWebResponse ftpResponse;
            try
            {
                ftpResponse = (FtpWebResponse)ftp.GetResponse();
            }
            catch (Exception ex)
            {
                Console.WriteLine("ERROR:  Failed to get FTP response:  " + ex.Message);
                Marshal.FreeBSTR(pUserName);
                Marshal.FreeBSTR(pPassword);
                return false;
            }

            Console.WriteLine("FINALIZE:  Response from FTP server received...");
            Console.WriteLine("FINALIZE:  " + ftpResponse.StatusCode + ":  " + ftpResponse.StatusDescription);

            //cleanup
            ftpResponse.Close();
            Marshal.FreeBSTR(pUserName);
            Marshal.FreeBSTR(pPassword);

            return true;
        }

        /////////////////////////////////////////////////////
        //                                                 //
        // SendZipFileSMTP()                              //
        //                                                 //
        /////////////////////////////////////////////////////
        //Description:  Connects to an SMTP server with user
        //              supplied credentials and sends zip file
        //              as an attachment.  SSL optional, authentication required.
        //Returns:      true if successful
        /////////////////////////////////////////////////////
        public static bool SendZipFileSMTP(SecureString username, SecureString password, string server_name, string server_port, string address, string zipfilename, bool useTLS)
        {
            Console.WriteLine("FINALIZE:  Sending results via SMTP/Email.");
            if (useTLS)
                Console.WriteLine("FINALIZE:  Using SMTP over SSL/TLSv1.0...");

            //create the mail message
            MailMessage message = new MailMessage();
            message.From = new MailAddress("No-Reply@Codeword.NoDomain.Org");
            message.To.Add(new MailAddress(address));
            message.Subject = Environment.MachineName + " - Codeword Scan Results - " + DateTime.Now.ToShortDateString();
            message.Body = "Please see attached scan results for this host.";
            Attachment a = new Attachment(zipfilename);
            message.Attachments.Add(a);
            IntPtr pUserName = Marshal.SecureStringToBSTR(username);
            IntPtr pPassword = Marshal.SecureStringToBSTR(password);

            SmtpClient smtp = new SmtpClient();
            smtp.Host = server_name;
            smtp.Port = int.Parse(server_port);

            //set TLS/SSL options
            if (useTLS)
            {
                smtp.EnableSsl = true;
                ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls;

                //***********************************************
                //          AUTHENTICATE SERVER/CLIENT
                //***********************************************
                //if a server public key was specified, then we need to register a callback to validate the server's public key
                if (serverPublicKey != "")
                {
                    ServicePointManager.CheckCertificateRevocationList = true;

                    //specify a ServicePointManager callback to check for SSL errors and validate the server's public key
                    ServicePointManager.ServerCertificateValidationCallback += delegate(object sender, X509Certificate cert, X509Chain chain, SslPolicyErrors sslErrors)
                    {
                        Console.WriteLine("FINALIZE:  Validating server certificate...");
                        /*
                        Console.WriteLine("FINALIZE:  Checking for SSL errors...");

                        //HANDLE SSL ERRORS
                        if (sslErrors == SslPolicyErrors.RemoteCertificateChainErrors)
                        {
                            Console.WriteLine("ERROR:  There are errors in the server's certificate:  certificate chain is invalid:");

                            foreach (X509ChainStatus chainStat in chain.ChainStatus)
                            {
                                Console.WriteLine("\t\tStatus:  " + chainStat.Status.ToString());
                                Console.WriteLine("\t\tInformation:  " + chainStat.StatusInformation);
                            }
                                
                            return false;
                        }
                        else if (sslErrors == SslPolicyErrors.RemoteCertificateNameMismatch)
                        {
                            Console.WriteLine("ERROR:  There are errors in the server's certificate:  certificate name mismatch.");
                            return false;
                        }
                        else if (sslErrors == SslPolicyErrors.RemoteCertificateNotAvailable)
                        {
                            Console.WriteLine("ERROR:  There are errors in the server's certificate:  remote certificate not available.");
                            return false;
                        }
                        */
                        Console.WriteLine("FINALIZE:  Checking raw certificate data against known good...");

                        //validate the certificate raw data
                        if (cert.GetRawCertDataString() != serverPublicKey)
                        {
                            Console.WriteLine("ERROR:  The server's public key did not match a known good certificate.");
                            return false;
                        }

                        Console.WriteLine("FINALIZE:  Success!  Server certificate has been validated.");

                        return true;
                    };

                    //***********************************************
                    //          AUTHENTICATE CLIENT AS WELL
                    //***********************************************
                    //if additionally a client pub/priv key file was specified, we will validate the client also
                    /*
                     * 
                     * NOTE:  As of dotnet 3.5, smtp client certificate is only usable through
                     * "DefaultCredentials", which is populated based on smtp configuration file.
                     * 
                     * FMI, see:
                     * http://msdn.microsoft.com/en-us/library/system.net.mail.smtpclient.clientcertificates(VS.80).aspx
                     * 
                     * 
                    
                    if (clientKeypair != "")
                    {
                        Console.WriteLine("FINALIZE:  Using client certificates installed to local keystore.");

                        //set the client certificates for this web request
                        //see limitations:  http://msdn.microsoft.com/en-us/library/ms229719.aspx
                        try
                        {
                            smtp.ClientCertificates = PKI.GetX509CertificateCollectionFromLocalHostStore();
                        }
                        catch (Exception ex)
                        {
                            Console.WriteLine("ERROR:  " + ex.Message);
                            return false;
                        }
                    }
                    */
                }
                //***********************************************
                //          NO AUTHENTICATION!!
                //***********************************************
                //otherwise, no validation is done at all
                else
                {
                    Console.WriteLine("WARNING:  Trusting server without validation!");

                    //specify a ServicePointManager callback to just return true on server cert
                    ServicePointManager.ServerCertificateValidationCallback += delegate(object sender, X509Certificate cert, X509Chain chain, SslPolicyErrors sslErrors)
                    {
                        return true;
                    };
                }
            }

            smtp.UseDefaultCredentials = false;
            smtp.Credentials = new NetworkCredential(Marshal.PtrToStringBSTR(pUserName), Marshal.PtrToStringBSTR(pPassword));
            smtp.Timeout = 15000;  //timeout 15s

            Console.WriteLine("FINALIZE:  Connecting to " + server_name + ":" + server_port.ToString() + "...");

            //create connection to SMTP server
            try
            {
                smtp.Send(message);
            }
            catch (Exception ex)
            {
                Console.WriteLine("ERROR:  Failed to send message:  " + ex.Message);
                Marshal.FreeBSTR(pUserName);
                Marshal.FreeBSTR(pPassword);
            }

            Console.WriteLine("FINALIZE:  Success!  Email sent to " + address + ".");
           
            Marshal.FreeBSTR(pUserName);
            Marshal.FreeBSTR(pPassword);
            return true;
        }

        /////////////////////////////////////////////////////
        //                                                 //
        // SendZipFileWeb()                                //
        //                                                 //
        /////////////////////////////////////////////////////
        //Description:  Connects to a Web server to send
        //              our encrypted archive file.  It performs
        //              a POST to a listening web form.  SSL optional.
        //              Authentication optional.
        //Returns:      true if successful
        /////////////////////////////////////////////////////
        public static bool SendZipFileWeb(SecureString username, SecureString password, string url, string port, string zipfilename, bool useTLS, string authType)
        {
            IntPtr pUserName = IntPtr.Zero, pPassword = IntPtr.Zero;

            if (username.Length != 0)
            {
                pUserName = Marshal.SecureStringToBSTR(username);
                pPassword = Marshal.SecureStringToBSTR(password);
            }

            //if a non-standard port was given, we must insert the port num into the URL
            //we can assume the format of the passed-in URL is mydomain.com/folder/file.php
            //get first forward slash "/"
            if (port != "80")
                url=url.Insert(url.IndexOf('/'), ":" + port);
            if (useTLS)
                url = "https://" + url;
            else
                url = "http://" + url;
            Uri uri = new Uri(url);

            //print out summary information to console.
            Console.WriteLine("FINALIZE:  Sending results via Web server..");
            Console.WriteLine("FINALIZE:  Web server URI:  '" + url + "'..");
            if (useTLS)
            {
                Console.WriteLine("FINALIZE:  Using TLS/SSL...");
                ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls;
            }

            if (username.Length != 0)
            {
                Console.WriteLine("FINALIZE:  User name:  '" + Marshal.PtrToStringBSTR(pUserName) + "'..");
                Console.WriteLine("FINALIZE:  Password:  '" + Marshal.PtrToStringBSTR(pPassword) + "'..");
                if (authType != "")
                    Console.WriteLine("FINALIZE:  Authentication scheme is " + authType);
            }

            //*************************************************
            //          BUILD AND SEND SERVER REQUEST
            //*************************************************

            //try to form a Web Request object from this URI
            HttpWebRequest webrequest;
            try
            {
                webrequest = (HttpWebRequest)WebRequest.Create(uri);
            }
            catch (Exception ex)
            {
                Console.WriteLine("ERROR:  Failed to send archive via Web method.");
                Console.WriteLine("ERROR:  " + ex.Message);
                return false;
            }

            Console.WriteLine("FINALIZE:  Connected.");

            //if requested, make the stream an SSL/TLS stream
            if (useTLS)
            {
                //***********************************************
                //          AUTHENTICATE SERVER/CLIENT
                //***********************************************
                //if a server public key was specified, then we need to register a callback to validate the server's public key
                if (serverPublicKey != "")
                {
                    ServicePointManager.CheckCertificateRevocationList = true;

                    //specify a ServicePointManager callback to check for SSL errors and validate the server's public key
                    ServicePointManager.ServerCertificateValidationCallback += delegate(object sender, X509Certificate cert, X509Chain chain, SslPolicyErrors sslErrors)
                    {
                        Console.WriteLine("FINALIZE:  Validating server certificate...");
                        /*
                        Console.WriteLine("FINALIZE:  Checking for SSL errors...");

                        //HANDLE SSL ERRORS
                        if (sslErrors == SslPolicyErrors.RemoteCertificateChainErrors)
                        {
                            Console.WriteLine("ERROR:  There are errors in the server's certificate:  certificate chain is invalid:");

                            foreach (X509ChainStatus chainStat in chain.ChainStatus)
                            {
                                Console.WriteLine("\t\tStatus:  " + chainStat.Status.ToString());
                                Console.WriteLine("\t\tInformation:  " + chainStat.StatusInformation);
                            }
                                
                            return false;
                        }
                        else if (sslErrors == SslPolicyErrors.RemoteCertificateNameMismatch)
                        {
                            Console.WriteLine("ERROR:  There are errors in the server's certificate:  certificate name mismatch.");
                            return false;
                        }
                        else if (sslErrors == SslPolicyErrors.RemoteCertificateNotAvailable)
                        {
                            Console.WriteLine("ERROR:  There are errors in the server's certificate:  remote certificate not available.");
                            return false;
                        }
                        */
                        Console.WriteLine("FINALIZE:  Checking raw certificate data against known good...");

                        //validate the certificate raw data
                        if (cert.GetRawCertDataString() != serverPublicKey)
                        {
                            Console.WriteLine("ERROR:  The server's public key did not match a known good certificate.");
                            return false;
                        }

                        Console.WriteLine("FINALIZE:  Success!  Server certificate has been validated.");

                        return true;
                    };

                    //***********************************************
                    //          AUTHENTICATE CLIENT AS WELL
                    //***********************************************
                    //if additionally a client pub/priv key file was specified, we will validate the client also
                    if (authenticateClient)
                    {
                        Console.WriteLine("FINALIZE:  Using client certificates installed to local keystore.");

                        //set the client certificates for this web request
                        //see limitations:  http://msdn.microsoft.com/en-us/library/ms229719.aspx
                        try
                        {
                            webrequest.ClientCertificates = CwCryptoHelper.GetX509CertificateCollectionFromLocalHostStore();
                        }
                        catch (Exception ex)
                        {
                            Console.WriteLine("ERROR:  " + ex.Message);
                            return false;
                        }
                    }
                }
                //***********************************************
                //          NO AUTHENTICATION!!
                //***********************************************
                //otherwise, no validation is done at all
                else
                {
                    Console.WriteLine("WARNING:  Trusting server without validation!");

                    //specify a ServicePointManager callback to just return true on server cert
                    ServicePointManager.ServerCertificateValidationCallback += delegate(object sender, X509Certificate cert, X509Chain chain, SslPolicyErrors sslErrors)
                    {
                        return true;
                    };
                }
            }

            //apply authentication scheme and credentials if necessary
            if (username.Length != 0)
            {
                CredentialCache creds = new CredentialCache();
                creds.Add(uri, authType, new NetworkCredential(Marshal.PtrToStringBSTR(pUserName), Marshal.PtrToStringBSTR(pPassword), ""));
                webrequest.Credentials = creds;
            }

            //set content type and HTTP Method
            string boundary = "----------" + DateTime.Now.Ticks.ToString("x");
            webrequest.ContentType = "multipart/form-data; boundary=" + boundary;
            webrequest.Method = "POST";

            // Build up the post message header
            StringBuilder sb = new StringBuilder();
            sb.Append("--");
            sb.Append(boundary);
            sb.Append("\r\n");
            sb.Append("Content-Disposition: form-data; name=\"zipfilename\"; filename=\"" + (zipfilename) + "\"");
            sb.Append("\r\n");
            sb.Append("Content-Type:  application/octet-stream");
            sb.Append("\r\n");
            sb.Append("\r\n");

            string postHeader = sb.ToString();
            byte[] postHeaderBytes = Encoding.UTF8.GetBytes(postHeader);

            // Build the trailing boundary string as a byte array
            // ensuring the boundary appears on a line by itself
            byte[] boundaryBytes = Encoding.ASCII.GetBytes("\r\n--" + boundary + "\r\n");

            //try to create a filestream object from the zip file we want to send
            FileStream fileStream;
            try
            {
                fileStream = new FileStream(zipfilename, FileMode.Open, FileAccess.Read);
            }
            catch (Exception ex)
            {
                Console.WriteLine("ERROR:  Failed to open archive stream.");
                Console.WriteLine("ERROR:  " + ex.Message);
                webrequest.Abort();
                return false;
            }

            long length = postHeaderBytes.Length + fileStream.Length + boundaryBytes.Length;
            webrequest.ContentLength = length;

            //get request stream
            Stream requestStream;
            try
            {
                requestStream = webrequest.GetRequestStream();
            }
            catch (Exception ex)
            {
                Console.WriteLine("ERROR:  Failed to get request stream from Web Request.");
                Console.WriteLine("ERROR:  " + ex.Message);
                webrequest.Abort();
                fileStream.Close();
                return false;
            }

            // Write out our post header
            try
            {
                requestStream.Write(postHeaderBytes, 0, postHeaderBytes.Length);
            }
            catch (Exception ex)
            {
                Console.WriteLine("ERROR:  Failed to write headers to response stream in Web Response.");
                Console.WriteLine("ERROR:  " + ex.Message);
                requestStream.Close();
                webrequest.Abort();
                fileStream.Close();
                return false;
            }

            // Write out the file contents
            byte[] buffer = new Byte[checked((uint)Math.Min(4096,(int)fileStream.Length))];
            int bytesRead = 0;

            while ((bytesRead = fileStream.Read(buffer, 0, buffer.Length)) != 0)
            {
                try
                {
                    requestStream.Write(buffer, 0, bytesRead);
                }
                catch (Exception ex)
                {
                    Console.WriteLine("ERROR:  Failed to write archive file to Web Response stream.");
                    Console.WriteLine("ERROR:  " + ex.Message);
                    requestStream.Close();
                    webrequest.Abort();
                    fileStream.Close();
                    return false;
                }
            }

            fileStream.Close();  //done with zip file stream

            // Write out the trailing boundary
            try
            {
                requestStream.Write(boundaryBytes, 0, boundaryBytes.Length);
            }
            catch (Exception ex)
            {
                Console.WriteLine("ERROR:  Failed to write trailing boundary to Web Response stream.");
                Console.WriteLine("ERROR:  " + ex.Message);
                requestStream.Close();
                webrequest.Abort();
                return false;
            }

            requestStream.Close(); //done with request stream

            //*************************************************
            //          GET SERVER RESPONSE
            //*************************************************

            //get a WebResponse object from the request object
            WebResponse webresponse;
            try
            {
                webresponse = webrequest.GetResponse();
            }
            catch (Exception ex)
            {
                Console.WriteLine("ERROR:  Failed to get server response.");
                Console.WriteLine("ERROR:  " + ex.Message);
                webrequest.Abort();
                return false;
            }

            //get a response stream to read from
            Stream responseStream;
            try
            {
                responseStream = webresponse.GetResponseStream();
            }
            catch (Exception ex)
            {
                Console.WriteLine("ERROR:  Failed to get response stream.");
                Console.WriteLine("ERROR:  " + ex.Message);
                webresponse.Close();
                webrequest.Abort();
                return false;
            }

            //try to read the response
            StreamReader responseReader;
            try
            {
                responseReader = new StreamReader(responseStream, Encoding.GetEncoding("utf-8"));
            }
            catch (Exception ex)
            {
                Console.WriteLine("ERROR:  Failed to read the response stream.");
                Console.WriteLine("ERROR:  " + ex.Message);
                responseStream.Close();
                webresponse.Close();
                webrequest.Abort();
                return false;
            }

            string responseString = "";
            Console.WriteLine("FINALIZE:  Response stream received, reading...");
            char[] readBuf = new char[256];
            int responseBytes = 0;

            //build response string by reading 256 chars at a time and converting to text
            while (responseReader.Read(readBuf, 0, 256) != 0)
            {
                string thisPart = new string(readBuf, 0, readBuf.Length);
                responseString += thisPart;
                responseBytes += readBuf.Length;
            }

            if (responseString.Length == 0)
            {
                Console.WriteLine("ERROR:  0-length response received.");
                webresponse.Close();
                responseStream.Close();
                responseReader.Close();
                if (username.Length != 0)
                {
                    Marshal.FreeBSTR(pUserName);
                    Marshal.FreeBSTR(pPassword);
                }
                return false;
            }

            //quick cleanup
            if (username.Length != 0)
            {
                Marshal.FreeBSTR(pUserName);
                Marshal.FreeBSTR(pPassword);
            }

            webresponse.Close();
            responseStream.Close();
            responseReader.Close();

            Console.WriteLine("FINALIZE:  Read " + responseBytes.ToString() + " bytes.");

            //the response code is the first three characters returned by the script we just POST'd to
            //100 = success
            //200 = failure
            string responseCode = responseString.Trim().Substring(0, 3);

            if (responseCode == "100")
            {
                Console.WriteLine("FINALIZE:  Success!");
                return true;
            }
            else
            {
                Console.WriteLine("ERROR:  " + responseString.Trim());
                Console.WriteLine("FINALIZE:  Submission failed.");
                return false;
            }
        }

        /////////////////////////////////////////////////////
        //                                                 //
        // GetNextAvailableDriveLetter()                   //
        //                                                 //
        /////////////////////////////////////////////////////
        //Description:  Finds the next available drive letter
        //              on the current system.
        //Returns:      the drive letter w/o a colon
        /////////////////////////////////////////////////////
        public static string GetNextAvailableDriveLetter()
        {
            // build a string collection representing the alphabet
            StringCollection alphabet = new StringCollection();

            int lowerBound = Convert.ToInt16('g');
            int upperBound = Convert.ToInt16('z');
            for (int i = lowerBound; i < upperBound; i++)
            {
                char driveLetter = (char)i;
                alphabet.Add(driveLetter.ToString());
            }

            // get all current drives
            DriveInfo[] drives = DriveInfo.GetDrives();
            foreach (DriveInfo drive in drives)
            {
                alphabet.Remove(drive.Name.Substring(0, 1).ToLower());
            }

            //if there is one available, return it; else null
            if (alphabet.Count > 0)
                return alphabet[0];
            else
                return null;
        }
    }
}
