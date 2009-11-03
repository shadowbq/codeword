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
using System.Text;
using System.IO;
using System.Reflection;
using System.ComponentModel;
using System.Threading;
using System.Security.Principal;
using System.Security;
using System.Net;
using System.Net.NetworkInformation;
using System.Text.RegularExpressions;
using System.Security.Cryptography;
using System.Runtime.InteropServices;
using Ionic.Utils.Zip;
using Microsoft.Win32;
using CwHandler;

namespace CwAgent
{
    class AgentService
    {
        internal IntPtr globalHSvcHandle;
        internal static StringBuilder AgentServiceLog;
        internal static StringBuilder ScanResultsLog;
        internal Dictionary<string, string> AgentSettings;

        /////////////////////////////////////////////////////
        //                                                 //
        // ServiceMain()                                   //
        //                                                 //
        /////////////////////////////////////////////////////
        //Description:  Entry point for the agent service process.
        //              This function is called automatically
        //              by the Windows SCM if we are running
        //              as a service, or it's called manually
        //              in AgentMain if not a service.
        //
        //              This function's prototype is dictated
        //              by the Win32Helper.LPSERVICE_MAIN_FUNCTIONW
        //              delegate definition.
        //
        //Returns:      true if successful
        /////////////////////////////////////////////////////
        internal unsafe void ServiceMain(uint dwNumServicesArgs, ref IntPtr lpServiceArgVectors)
        {
            AgentSettings = new Dictionary<string, string>();
            AgentServiceLog = new StringBuilder();
            ScanResultsLog = new StringBuilder();

            //=============================================
            //              INITIALIZATION
            //=============================================
            //
            //1.  Load settings from XML file extracted to local dir from MSI
            //
            if (!LoadAgentSettings(ref AgentSettings))
                return;

            //=============================================
            //      SET SERVICE CONTROL HANDLER FUNCTION
            //=============================================
            //the function ServiceMain() is called either by:
            //      (1) the agent binary itself inside CwAgent.exe in "Fire and Forget" mode
            //      (2) the CwAgent service has been started by the SCM
            //
            //in #1, we dont need to do anything special, but in #2, we have to do a few items
            //to make sure the SCM is "in the know":
            //      http://msdn.microsoft.com/en-us/library/ms685984(VS.85).aspx
            //
            //we will distinguish between case #1 and case #2 by the number of args
            if (dwNumServicesArgs > 0)
            {
                //get a pointer to our callback delegate.
                Win32Helper.LPHANDLER_FUNCTION lpHandlerProc = new Win32Helper.LPHANDLER_FUNCTION(ServiceHandler);

                //call RegisterServiceCtrlHandler() with this ptr.  all SCM notifications will be handled by it.
                IntPtr svcStatusHandle = Win32Helper.RegisterServiceCtrlHandler(AgentSettings["AgentServiceName"], lpHandlerProc);

                if (svcStatusHandle == IntPtr.Zero)
                    return;

                //!!!!!!!!!!!!!!!!!!!!!!!!!!!
                //!!     MUI IMPORTANTE    !!
                //!!!!!!!!!!!!!!!!!!!!!!!!!!!
                //we must save this handle for later updates to SCM
                globalHSvcHandle = svcStatusHandle;
                bool success = false;

                //set service to the START_PENDING state
                try
                {
                    ServiceHelper.SetServiceStatus(globalHSvcHandle, Win32Helper.SERVICE_START_PENDING, ref success);
                }
                catch (Exception) { }
            }

            //=============================================
            //              ESCALATE PRIVILEGES
            //=============================================
            //we must have debug privs to succeed.
            if (!AgentScanner.EnvironmentHelper.EscalatePrivileges())
            {
                //set our service to the STOPPED state
                try
                {
                    bool success = false;
                    ServiceHelper.StopService(AgentSettings["AgentServiceName"]);
                    ServiceHelper.SetServiceStatus(globalHSvcHandle, Win32Helper.SERVICE_STOPPED, ref success);
                }
                catch (Exception) { }

                return;
            }

            AgentServiceLog.AppendLine("*********************************************");
            AgentServiceLog.AppendLine("Codeword Agent v" + Assembly.GetExecutingAssembly().GetName().Version);
            AgentServiceLog.AppendLine("*********************************************");
            AgentServiceLog.AppendLine("Copyright © 2009, Sippy Development International");
            AgentServiceLog.AppendLine("Author:  sippy");
            AgentServiceLog.AppendLine("Please contact sippy@sippysworld.org with questions.");
            AgentServiceLog.AppendLine("*********************************************");
            AgentServiceLog.AppendLine("");
            AgentServiceLog.AppendLine("*********************************************");
            AgentServiceLog.AppendLine("                 INITIALIZE                  ");
            AgentServiceLog.AppendLine("*********************************************");
            AgentServiceLog.AppendLine("");
            AgentServiceLog.AppendLine("INITIALIZE:  Codeword starting on " + DateTime.Now.ToString("MM/dd/yyyy HH:mm:ss"));
            AgentServiceLog.AppendLine("INITIALIZE:  Loading settings...");

            //=============================================
            //                  STARTUP
            //=============================================
            //
            //1.  determine our startup mode.
            //
            string[] possibleStartupModes = new string[] { "StartupFireAndForgetMode", "StartupRemoteControlMode", "StartupEnterpriseMode" };
            string AgentStartupMode = "";
            foreach (string s in possibleStartupModes)
                if (AgentSettings.ContainsKey(s))
                    if (AgentSettings[s] == "True")
                        AgentStartupMode = s;

            AgentServiceLog.AppendLine("INITIALIZE:  Agent startup mode set to " + AgentStartupMode);

            //
            //2.  start TCP server and listen for commands
            //
            if (AgentStartupMode == "StartupRemoteControlMode" || AgentStartupMode == "StartupEnterpriseMode")
            {
                SslTcpServer server = new SslTcpServer();
                string certfile = "", encPwd = "", issuer = "";
                bool authClientToServer = false;
                bool authServerToClient = false;
                bool strongAuth = false;
                int port = 1111;

                AgentServiceLog.AppendLine("STARTUP:  Initializing TCP/SSL server...");
                AgentServiceLog.AppendLine("STARTUP:  Using settings:");

                //------------------------------------
                //      LOAD TCP SERVER SETTINGS
                //------------------------------------
                //extract certificate from internal PKCS-12 file if provided
                if (AgentSettings.ContainsKey("AgentPFXFile"))
                    if (AgentSettings["AgentPFXFile"] != "")
                        certfile = Path.GetFileName(AgentSettings["AgentPFXFile"]);
                //get encrypted password for PFX keystore
                if (AgentSettings.ContainsKey("AgentPFXPassword"))
                    if (AgentSettings["AgentPFXPassword"] != "")
                        encPwd = AgentSettings["AgentPFXPassword"];
                //server port to listen on locally
                if (AgentSettings.ContainsKey("AgentListeningPort"))
                    if (AgentSettings["AgentListeningPort"] != "")
                        port = int.Parse(AgentSettings["AgentListeningPort"]);
                //authenticate client to server?
                if (AgentSettings.ContainsKey("AgentAuthenticateClientToServer"))
                    if (AgentSettings["AgentAuthenticateClientToServer"] == "True")
                        authClientToServer = true;
                //authenticate server to client?
                if (AgentSettings.ContainsKey("AgentAuthenticateServerToClient"))
                    if (AgentSettings["AgentAuthenticateServerToClient"] == "True")
                        authServerToClient = true;
                //required issuer of client certs
                if (AgentSettings.ContainsKey("AgentEnforceCertificateIssuer"))
                    if (AgentSettings["AgentEnforceCertificateIssuer"] != "")
                        issuer = AgentSettings["AgentEnforceCertificateIssuer"];
                //force strong authentication
                if (AgentSettings.ContainsKey("AgentEnforceStrongAuthentication"))
                    if (AgentSettings["AgentEnforceStrongAuthentication"] == "True")
                        strongAuth = true;

                AgentServiceLog.AppendLine("    PFX file name:  " + certfile);
                AgentServiceLog.AppendLine("    Listening on port:  " + port.ToString());
                AgentServiceLog.AppendLine("    Authenticate client to server:  " + authClientToServer.ToString());
                AgentServiceLog.AppendLine("    Authenticate server to client:  " + authServerToClient.ToString());
                AgentServiceLog.AppendLine("    Required issuer:  " + issuer);
                AgentServiceLog.AppendLine("    Strong authentication required:  " + strongAuth.ToString());

                //set server fields
                server.PFXFileName = certfile;
                server.EncryptedPassword = encPwd;
                server.ServerPort = port;
                server.AuthenticateClientToServer = authClientToServer;
                server.AuthenticateServerToClient = authServerToClient;
                server.RequiredIssuer = issuer;
                server.RequireStrongAuthentication = strongAuth;

                //insure the certificate file exists
                if (!File.Exists(certfile))
                {
                    AgentServiceLog.AppendLine("Error:  PFX certificate file '" + certfile + "' does not exist!");
                    return;
                }

                //------------------------------------
                //      RUN THE SCAN IF MODE IS
                //      StartupEnterpriseMode
                //------------------------------------
                if (AgentStartupMode == "StartupEnterpriseMode")
                {
                    //kick it off in a new thread so it doesnt stall the service
                    //and cause the SCM to barf.
                    Thread thr = new Thread(new ThreadStart(InitiateScanThread));
                    thr.Start();
                    
                    while (!thr.IsAlive) { }
                    Thread.Sleep(1);

                    //we will wait for it to complete, b/c we've already set the status of
                    //our service to RUNNING, so SCM is satisfied.
                    //Ideally, we would also kick the RunServer() below in a new thread 
                    //as well, and synchronize the three threads.
                    thr.Join();
                }
                
                //read the data back in from the file the child thread just wrote
                //ScanResultsLog = new StringBuilder(File.ReadAllText("xxzz1tmp1"));
                //promptly delete the file
                //File.Delete("xxzz1tmp1");

                //set our service to the RUNNING state
                try
                {
                    bool success = false;
                    ServiceHelper.SetServiceStatus(globalHSvcHandle, Win32Helper.SERVICE_RUNNING, ref success);
                }
                catch (Exception) { }

                //------------------------------------
                //      START THE TCP SERVER
                //------------------------------------
                //pass the results of an enterprise mode scan, if there is one
                //note:  ScanResultsLog is populated from the child thread above.
                try
                {
                    server.RunServer(ScanResultsLog);
                }
                catch (Exception ex)
                {
                    StreamWriter sw = new StreamWriter("SslServerError.txt", true);
                    sw.WriteLine(ex.Message);
                    sw.Close();
                }

                //set our service to the STOPPED state
                try
                {
                    bool success = false;
                    ServiceHelper.StopService(AgentSettings["AgentServiceName"]);
                    ServiceHelper.SetServiceStatus(globalHSvcHandle, Win32Helper.SERVICE_STOPPED, ref success);
                }
                catch (Exception) { }
            }
            //StartupFireAndForgetMode - do not start any server; just run the scan and report
            //note:  if we get here, we are not being called by SCM.
            else if (AgentStartupMode == "StartupFireAndForgetMode")
            {
                AgentScanner scanner = new AgentScanner();
                scanner.FireAndForget();
            }

            return;
        }

        /////////////////////////////////////////////////////
        //                                                 //
        // InitiateScanThread()                            //
        //                                                 //
        /////////////////////////////////////////////////////
        //Description:  Kicks of a scan of the host in a separate
        //              thread.  ServiceMain() will wait for
        //              this thread to complete.  This function
        //              is only called in Enterprise mode.
        //
        //Returns:      void
        //////////////////////////////////////////////////////
        internal void InitiateScanThread()
        {
            AgentScanner scanner = new AgentScanner();
            CwXML.CodewordAgentAnomalyReport anomalyReport = new CwXML.CodewordAgentAnomalyReport();
            //this wont modify our global variable "ScanResultsLog", so we have to write it to a file
            //in this child thread and then once back in the main thread, slurp it back up
            try
            {
                ScanResultsLog = scanner.StartScanTask(ref anomalyReport);
                StreamWriter sw = new StreamWriter("xxzz1tmp1");
                sw.Write(ScanResultsLog.ToString());
                sw.Close();
            }
            catch (Exception ex)
            {
                StreamWriter sw = new StreamWriter("errcw.txt");
                sw.WriteLine(ex.Message);
                if (ex.InnerException != null)
                    sw.WriteLine(ex.InnerException.Message);
                sw.Close();
            }

            return;
        }

        /////////////////////////////////////////////////////
        //                                                 //
        // ServiceHandler()                                //
        //                                                 //
        /////////////////////////////////////////////////////
        //Description:  A delegate function to handle service
        //              control messages from the SCM regarding
        //              our cwagent service.  all this function
        //              does is notify the SCM that our status
        //              has changed.  We are the ONLY process that
        //              can do this since we exclusively hold 
        //              the globalHSvcHandle.
        //
        //Returns:      void
        //////////////////////////////////////////////////////
        internal void ServiceHandler(uint dwCode)
        {
            bool success = false;

            switch (dwCode)
            {
                case Win32Helper.SERVICE_CONTROL_STOP:
                    try
                    {
                        ServiceHelper.StopService(AgentSettings["AgentServiceName"]);
                        ServiceHelper.SetServiceStatus(globalHSvcHandle, Win32Helper.SERVICE_STOPPED, ref success);
                    }
                    catch (Exception) { }
                    break;

                //start the service?  um, no..
                case Win32Helper.SERVICE_START:
                    break;

                case Win32Helper.SERVICE_PAUSE_CONTINUE:
                    break;

                default:
                    try
                    {
                        ServiceHelper.SetServiceStatus(globalHSvcHandle, dwCode, ref success);
                    }
                    catch (Exception) { }
                    break;
            }
        }

        /////////////////////////////////////////////////////
        //                                                 //
        // LoadAgentSettings()                             //
        //                                                 //
        /////////////////////////////////////////////////////
        //Description:  Loads settings from the agent config file.
        //
        //Returns:      true if successful
        //////////////////////////////////////////////////////
        private unsafe bool LoadAgentSettings(ref Dictionary<string, string> AgentSettings)
        {
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
                AgentServiceLog.AppendLine("ERROR:  " + e.Message);
                AgentServiceLog.AppendLine("ERROR:  Failed to load settings, terminating...");
                return false;
            }

            //copy the settings from the CST object to a more usable dictionary<> struct
            int count = 0;
            foreach (string s in cst.FormElementNames)
            {
                AgentSettings[s] = cst.FormElementValues[count];
                count++;
            }

            AgentServiceLog.AppendLine("INITIALIZE:  Success.");
            return true;
        }
    }
}
