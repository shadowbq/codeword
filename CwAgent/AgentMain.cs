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
    public static class AgentMain
    {
        //AgentMain() { }

        /////////////////////////////////////////////////////
        //                                                 //
        // Main()                                          //
        //                                                 //
        /////////////////////////////////////////////////////
        //Description:  This function is the equivalent of the
        //              C-style main() and is called when the
        //              program is executed.  In the case of
        //              this agent, this file is executed 
        //              after the agent MSI installer pkg is
        //              extracted.  If the settings require the
        //              agent run as a service, this function
        //              will create the service and exit, and
        //              the SCM will re-execute this file 
        //              automatically, passing the -skipinstall
        //              argument we gave to CreateService().
        //              Otherwise, this Main() simply
        //              calls the scanner to run once and exits.
        //
        //Returns:      void
        //////////////////////////////////////////////////////
        public static void Main(string[] args)
        {
            //++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
            //
            //                          WHO DARE CALLETH ME?
            //
            //++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
            //must IMMEDIATELY determine if we are being called by SCM or by Agent Installer
            //we do this by looking for the -skipinstall to our program, which would only be
            //passed by the SCM as a result of an SCM ServiceStart() call.
            if (args.Length > 0)
            {
                if (args[0].IndexOf("-skipinstall") >= 0)
                {
                    CodewordServicesStartup();
                    return;
                }
            }

            if (args.Length == 0)
                args = new string[] { "" };

            //otherwise this is the first time cwagent.exe has been executed, so execute
            //any install tasks (agent + driver) or a one-time run of the agent
            CodewordInstallation(args);
        }

        /////////////////////////////////////////////////////
        //                                                 //
        // CodewordInstallation()                          //
        //                                                 //
        /////////////////////////////////////////////////////
        //Description:  This function is executed by Main() 
        //              when the agent binary is being executed
        //              by the installer for the first time.
        //
        //Returns:      void
        //////////////////////////////////////////////////////
        private static void CodewordInstallation(string[] CmdLineInstallArgs)
        {
            //variables to hold signature and agent settings data
            Dictionary<string, string> AgentSettings = new Dictionary<string, string>();
            
            Console.WriteLine("Install args:  " + string.Join(",", CmdLineInstallArgs));
            Console.WriteLine("------------------");
            Console.WriteLine("Initialization");
            Console.WriteLine("------------------");

            Console.Write("Checking pre-requisites...");

            //=============================================
            //              PREREQUISITE CHECK
            //=============================================
            //bail if we dont have admin rights.
            if (!DoPreRequisiteCheck())
            {
                Console.Write("failed!");
                Console.WriteLine("");
                return;
            }

            Console.Write("OK.");
            Console.WriteLine("");

            //=============================================
            //              ESCALATE PRIVILEGES
            //=============================================
            //we must have debug privs to succeed.
            Console.Write("Escalating privileges...");
            if (!AgentScanner.EnvironmentHelper.EscalatePrivileges())
            {
                Console.Write("failed!");
                Console.WriteLine("");
                return;
            }

            Console.Write("OK.");
            Console.WriteLine("");

            //=============================================
            //              LOAD SETTINGS 
            //=============================================
            Console.Write("Loading settings...");
            if (!LoadAgentSettings(ref AgentSettings))
            {
                Console.Write("failed!");
                Console.WriteLine("");
                return;
            }

            Console.Write("OK.");
            Console.WriteLine("");

            //=============================================
            //              APPLY SETTINGS 
            //=============================================
            //load some initial settings
            bool DriverSuccessfullyLoaded = false;
            bool Stealth_LoadAndCallImage = false;
            bool InstallAgentService = false;
            string DriverFileName = CwConstants.DRIVER_BINARY_NAME;
            string DriverInstallPath = Environment.GetFolderPath(Environment.SpecialFolder.System) + "\\Drivers\\" + DriverFileName;
            string DriverImagePath = CwConstants.DRIVER_IMAGE_PATH_BASE + DriverFileName; //for registry entry for SCM
            string DriverServiceName = CwConstants.DRIVER_SERVICE_NAME;
            string AgentFileName = CwConstants.AGENT_BINARY_NAME;
            string AgentServiceName = CwConstants.AGENT_SERVICE_NAME;
            string AgentInstallPath = Environment.SystemDirectory + "\\"+AgentFileName;
            string AgentInstallPathWithArg = AgentInstallPath;
            string[] AgentServiceArguments = new string[]{"-skipinstall"};

            if (AgentSettings.ContainsKey("PersistenceInstallAsService"))
                if (AgentSettings["PersistenceInstallAsService"] == "True")
                    InstallAgentService = true;
            if (AgentSettings.ContainsKey("Stealth_LoadAndCallImage"))
                if (AgentSettings["Stealth_LoadAndCallImage"] == "True")
                    Stealth_LoadAndCallImage = true;
            if (AgentSettings.ContainsKey("AgentServiceName"))
                if (AgentSettings["AgentServiceName"] != "")
                    AgentServiceName = AgentSettings["AgentServiceName"];
            /*
            if (AgentSettings.ContainsKey("AgentInstallFolder"))
                if (AgentSettings["AgentInstallFolder"] != "")
                    GetAgentInstallPath(AgentSettings["AgentInstallFolder"], AgentFileName, ref AgentInstallPath);
            */

            //when passing this value to CreateService() API, it must be a fully-escaped string
            //note:  any parameters to the service are passed here!
            //  e.g.  \"C:\windows\system32\cwagent.exe -install\"
            //AgentInstallPathWithArg = "\\\"" + AgentInstallPath.Replace("\\", "\\\\") + " -skipinstall\\\"";
            //DriverInstallPathFullyQualified = "\\\"" + DriverInstallPath.Replace("\\", "\\\\") + "\\\"";
            AgentInstallPathWithArg = AgentInstallPath +" -skipinstall";

            //=============================================
            //             STEALTH [optional]
            //=============================================
            //
            //(1) Randomize agent process name [optional]
            //(2) Hide agent's process [optional]
            //(3) Load driver using LoadAndCallImage [optional]
            //
            //
            /*
            if (Stealth_LoadAndCallImage && !Win32Helper.Is64bit())
            {
                byte[] filedata = new byte[0];

                try
                {
                    bool success = false;
                    //extract driver binary data from our own assembly
                    AgentScanner.DriverHelper.ExtractDriver(DriverFileName, ref filedata);
                    //save it to C:\Windows\System32\Drivers\
                    AgentScanner.DriverHelper.SaveDriver(DriverInstallPath, filedata);
                    //load using load and call image
                    AgentScanner.DriverHelper.SysLoadAndCall(DriverInstallPath, ref success);
                    DriverSuccessfullyLoaded = success;
                }
                catch (Exception)
                {
                    DriverSuccessfullyLoaded = false;
                }
            }
            */

            //
            //=============================================
            //          STARTUP [required]
            //=============================================
            //
            //(1) Extract & Load driver [required] - if not already done stealthily
            Console.WriteLine("-------------------");
            Console.WriteLine("Driver Installation");
            Console.WriteLine("-------------------");

            #region DRIVER STARTUP/INSTALLATION
            //
            //NOTE:  do not quit on any errors when dealing with SCM.  It is unreliable and may report
            //the service installation/start/stop/etc failed when it really succeeeded!!!
            if (!DriverSuccessfullyLoaded && !Win32Helper.Is64bit())
            {
                Console.Write("Does the driver service exist?");
                bool InstallNecessary = true;
                byte[] filedata = new byte[0];

                //--------------------------------
                //     STOP EXISTING SERVICE
                //--------------------------------
                //first we have to stop the service if it is already running
                try
                {
                    if (ServiceHelper.ServiceExists(DriverServiceName))
                    {
                        Console.Write("  Yes.");
                        Console.WriteLine("");
                        Console.Write("   Is it running?");

                        InstallNecessary = false; //we dont need to re-install the service
                        long serviceStatus = 0;
                       
                        try
                        {
                            serviceStatus=ServiceHelper.GetServiceStatus(DriverServiceName);
                        }
                        catch(Exception ex)
                        {
                            Console.WriteLine("  Critical error:  could not determine the driver service's state:  " + ex.Message);
                            Console.WriteLine("");
                            return;
                        }

                        //STATUS IS RUNNING:  stop the service
                        if (serviceStatus == Win32Helper.SERVICE_RUNNING)
                        {
                            Console.Write("  Yes, stopping...");
                            try
                            {
                                if (!ServiceHelper.StopService(DriverServiceName))
                                {
                                    Console.WriteLine("  Critical error:  could not stop running driver service.");
                                    return;
                                }
                            }
                            catch (Exception ex)
                            {
                                Console.WriteLine("  Critical error:  could not stop running driver service:  " + ex.Message);
                                return;
                            }
                            Console.Write("OK.");
                            Console.WriteLine("");
                        }
                        //SOME OTHER STATUS, IGNORE.
                        else
                        {
                            if (serviceStatus == Win32Helper.SERVICE_STOPPED)
                                Console.Write("  No, it is STOPPED.");
                            else if (serviceStatus == Win32Helper.SERVICE_STOP_PENDING)
                                Console.Write("  No, it is STOP PENDING.");
                            else if (serviceStatus == Win32Helper.SERVICE_START_PENDING)
                                Console.Write("  No, it is START PENDING.");
                            else if (serviceStatus == Win32Helper.SERVICE_PAUSED)
                                Console.Write("  No, it is PAUSED.");
                            else if (serviceStatus == Win32Helper.SERVICE_PAUSE_PENDING)
                                Console.Write("  No, it is PAUSE PENDING.");
                            else if (serviceStatus == Win32Helper.SERVICE_CONTINUE_PENDING)
                                Console.Write("  No, it is CONTINUE PENDING.");
                            else
                                Console.Write("  No, it is UNKNOWN!");
                            Console.WriteLine("");
                        }
                    }
                    else
                    {
                        Console.Write("  No.");
                        Console.WriteLine("");
                    }
                }
                catch(Exception ex)
                {
                    Console.WriteLine("Critical error:  caught exception attempting to detect/stop driver service:  "+ex.Message);
                    Console.WriteLine("");
                    return;
                }

                //
                //SKIP EXTRACT/SAVE STEP IF INSTALL ARGS REQUEST
                //
                //this is useful for debugging the driver, so we dont have to worry about 
                //repackaging the .sys file with the agent installer
                //
                if (CmdLineInstallArgs[0].IndexOf("-skipExtract") == -1)
                {
                    Thread.Sleep(500); //sleep .5 second
                    Console.Write("Extracting driver...");

                    //--------------------------------
                    //     EXTRACT NEW DRIVER BINARY
                    //--------------------------------
                    //overwrite any previous version
                    bool ExtractSuccessful = false;
                    try
                    {
                        ExtractSuccessful = AgentScanner.DriverHelper.ExtractDriver(DriverFileName, ref filedata);
                    }
                    catch (Exception ex)
                    {
                        Console.WriteLine("Critical error:  caught exception attempting to extract driver binary:  " + ex.Message);
                        Console.WriteLine("");
                        return;
                    }

                    //FAILED.
                    if (!ExtractSuccessful)
                    {
                        Console.Write("failed:  " + Win32Helper.GetLastError32());
                        return;
                    }
                    else
                    {
                        Console.Write("OK.");
                        Console.WriteLine("");
                    }

                    Thread.Sleep(500); //sleep .5 second
                    Console.Write("Saving driver to disk...");

                    //save it to C:\Windows\System32\Drivers\
                    bool SaveSuccessful = false;
                    try
                    {
                        SaveSuccessful = AgentScanner.DriverHelper.SaveDriver(DriverInstallPath, filedata);
                    }
                    catch (Exception ex)
                    {
                        Console.WriteLine("Critical error:  caught exception attempting to save driver binary to disk:  " + ex.Message);
                        Console.WriteLine("");
                        return;
                    }

                    //FAILED.
                    if (!SaveSuccessful)
                    {
                        Console.Write("failed:  " + Win32Helper.GetLastError32());
                        return;
                    }
                    else
                    {
                        Console.Write("OK.");
                        Console.WriteLine("");
                        Console.WriteLine("Wrote " + filedata.Length.ToString() + " bytes to " + DriverInstallPath + ".");
                    }

                    Thread.Sleep(500); //sleep .5 second

                } //end save/extract driver binary

                Console.Write("Is driver installation necessary?  ");
                
                //--------------------------------
                //     CREATE NEW SERVICE
                //--------------------------------
                //install driver as a service if necessary
                if (InstallNecessary)
                {
                    Console.Write("Yes, installing from path:");
                    Console.WriteLine("");
                    Console.WriteLine("     " + DriverInstallPath);
                    Console.WriteLine("Creating new service:  ");
                    Console.WriteLine("     Service name:  " + DriverServiceName);
                    Console.WriteLine("     Display name:  " + DriverServiceName);
                    Console.WriteLine("     Service type:  " + Win32Helper.SERVICE_KERNEL_DRIVER);
                    Console.WriteLine("     Start type  :  " + Win32Helper.SERVICE_DEMAND_START);
                    Console.WriteLine("     Image path  :  " + DriverImagePath);
                    Console.Write("Installing service...");

                    bool CreateSuccessful = false;
                    try
                    {
                        CreateSuccessful=ServiceHelper.CreateService(DriverServiceName, DriverServiceName, Win32Helper.SERVICE_KERNEL_DRIVER, Win32Helper.SERVICE_DEMAND_START, DriverImagePath);
                    }
                    catch (Exception ex)
                    {
                        Console.Write("Caught exception trying to create service:  " + ex.Message);

                        //ignore ERROR_IO_PENDING
                        if (Win32Helper.GetLastError() == Win32Helper.ERROR_IO_PENDING)
                        {
                            Console.Write("...Ignoring.");
                        }
                        //bail..
                        else
                        {
                            Console.WriteLine("("+Win32Helper.GetLastError()+")");
                            return;
                        }
                    }

                    //FAILED.
                    if (!CreateSuccessful)
                    {
                        Console.Write("failed:  " + Win32Helper.GetLastError32());
                        return;
                    }
                    else
                    {
                        Console.Write("OK.");
                        Console.WriteLine("");
                    }
                }
                else
                {
                    Console.Write("No.");
                    Console.WriteLine("");
                }

                Thread.Sleep(500); //sleep .5 second
                Console.Write("Starting driver service...");

                //--------------------------------
                //     START  SERVICE
                //--------------------------------
                bool StartSuccessful = false;
                try
                {
                    StartSuccessful=ServiceHelper.StartService(DriverServiceName, null);
                }
                catch (Exception ex)
                {
                    Console.WriteLine("Caught exception trying to start service:  " + ex.Message);
                    return;
                }

                //FAILED.
                if (!StartSuccessful)
                {
                    Console.Write("failed:  " + Win32Helper.GetLastError32()+" ("+Win32Helper.GetLastError()+")");
                    return;
                }
                else
                {
                    Console.Write("OK.");
                    Console.WriteLine("");
                }
            }
            #endregion

            //(2) Any self-protection measures [optional]
            //      -run all kernel-mode heuristics to see if this system is hosed
            //      -if this option is set, the reporting mode is always set to Fire and forget
            //

            //(3) Install agent as a service [optional]
            //
            Console.WriteLine("------------------");
            Console.WriteLine("Agent Installation");
            Console.WriteLine("------------------");

            #region AGENT STARTUP/INSTALLATION

            //------------------------------------
            //          RUN ONCE
            //------------------------------------
            if (!InstallAgentService)
            {
                Console.WriteLine("Startup mode is Fire and Forget...");

                string args2 = "";
                IntPtr pArgs = Marshal.StringToHGlobalAuto(args2);

                AgentService service = new AgentService();
                service.ServiceMain(0, ref pArgs);

                if (pArgs != IntPtr.Zero)
                    Marshal.FreeHGlobal(pArgs);

                //the scan has completed -- terminate driver service
                //no need to leave it running b/c we didnt install agent as a service
                try
                {
                    ServiceHelper.StopService(DriverServiceName);
                    ServiceHelper.RemoveService(DriverServiceName);
                    File.Delete(DriverInstallPath);
                }
                catch (Exception) { }
                return;
            }
            //------------------------------------
            //          RUN AS SERVICE
            //------------------------------------
            else
            {
                //kill any other CwAgent.exe process in case the agent is already installed as a service
                TerminateAgents();
                bool InstallNecessary = true;

                Console.Write("Does the agent service exist?");

                //--------------------------------
                //     STOP EXISTING SERVICE
                //--------------------------------
                //first we have to stop the service if it is already running
                try
                {
                    if (ServiceHelper.ServiceExists(AgentServiceName))
                    {
                        Console.Write("  Yes.");
                        Console.WriteLine("");
                        Console.Write("   Is it running?");

                        InstallNecessary = false; //we dont need to re-install the service
                        long serviceStatus = 0;

                        try
                        {
                            serviceStatus = ServiceHelper.GetServiceStatus(AgentServiceName);
                        }
                        catch (Exception ex)
                        {
                            Console.WriteLine("  Critical error:  could not determine the agent service's state:  " + ex.Message);
                            Console.WriteLine("");
                            return;
                        }

                        //STATUS IS RUNNING:  stop the service
                        if (serviceStatus == Win32Helper.SERVICE_RUNNING)
                        {
                            Console.Write("  Yes, stopping...");
                            try
                            {
                                if (!ServiceHelper.StopService(AgentServiceName))
                                {
                                    Console.WriteLine("  Critical error:  could not stop running agent service.");
                                    return;
                                }
                            }
                            catch (Exception ex)
                            {
                                Console.WriteLine("  Critical error:  could not stop running agent service:  " + ex.Message);
                                return;
                            }
                            Console.Write("OK.");
                            Console.WriteLine("");
                        }
                        //SOME OTHER STATUS, IGNORE.
                        else
                        {
                            if (serviceStatus == Win32Helper.SERVICE_STOPPED)
                                Console.Write("  No, it is STOPPED.");
                            else if (serviceStatus == Win32Helper.SERVICE_STOP_PENDING)
                                Console.Write("  No, it is STOP PENDING.");
                            else if (serviceStatus == Win32Helper.SERVICE_START_PENDING)
                                Console.Write("  No, it is START PENDING.");
                            else if (serviceStatus == Win32Helper.SERVICE_PAUSED)
                                Console.Write("  No, it is PAUSED.");
                            else if (serviceStatus == Win32Helper.SERVICE_PAUSE_PENDING)
                                Console.Write("  No, it is PAUSE PENDING.");
                            else if (serviceStatus == Win32Helper.SERVICE_CONTINUE_PENDING)
                                Console.Write("  No, it is CONTINUE PENDING.");
                            else
                                Console.Write("  No, it is UNKNOWN!");
                            Console.WriteLine("");
                        }
                    }
                    else
                    {
                        Console.Write("  No.");
                        Console.WriteLine("");
                    }
                }
                catch (Exception ex)
                {
                    Console.WriteLine("Critical error:  caught exception attempting to detect/stop agent service:  " + ex.Message);
                    Console.WriteLine("");
                    return;
                }

                Thread.Sleep(500); //sleep .5 second
                Console.Write("Is agent service installation necessary?  ");

                //--------------------------------
                //     CREATE NEW SERVICE
                //--------------------------------
                //install driver as a service if necessary
                if (InstallNecessary)
                {
                    Console.Write("Yes, installing from path:");
                    Console.WriteLine("");
                    Console.WriteLine("     " + AgentInstallPathWithArg);
                    Console.WriteLine("Creating new service:  ");
                    Console.WriteLine("     Service name:  " + AgentServiceName);
                    Console.WriteLine("     Display name:  " + AgentServiceName);
                    Console.WriteLine("     Service type:  " + Win32Helper.SERVICE_WIN32_OWN_PROCESS);
                    Console.WriteLine("     Start type  :  " + Win32Helper.SERVICE_DEMAND_START);
                    Console.WriteLine("     Install folder:  " + AgentInstallPathWithArg);
                    Console.Write("Installing service...");

                    bool CreateSuccessful = false;
                    try
                    {
                        CreateSuccessful=ServiceHelper.CreateService(AgentServiceName, AgentServiceName, Win32Helper.SERVICE_WIN32_OWN_PROCESS, Win32Helper.SERVICE_DEMAND_START, AgentInstallPathWithArg);
                    }
                    catch (Exception ex)
                    {
                        Console.Write("Caught exception trying to create service:  " + ex.Message);

                        //ignore ERROR_IO_PENDING
                        if (Win32Helper.GetLastError() == Win32Helper.ERROR_IO_PENDING)
                        {
                            Console.Write("...Ignoring.");
                        }
                        //bail..
                        else
                        {
                            Console.WriteLine("");
                            return;
                        }
                    }

                    //FAILED.
                    if (!CreateSuccessful)
                    {
                        Console.Write("failed:  " + Win32Helper.GetLastError32());
                        return;
                    }
                    else
                    {
                        Console.Write("OK.");
                        Console.WriteLine("");
                    }
                }
                else
                {
                    Console.Write("No.");
                    Console.WriteLine("");
                }

                Thread.Sleep(500); //sleep .5 second
                Console.Write("Starting agent service...");

                //--------------------------------
                //     START  SERVICE
                //--------------------------------
                bool StartSuccessful = false;
                try
                {
                    StartSuccessful=ServiceHelper.StartService(AgentServiceName, null);
                }
                catch (Exception ex)
                {
                    Console.WriteLine("Caught exception trying to start service:  " + ex.Message);
                    return;
                }

                //FAILED.
                if (!StartSuccessful)
                {
                    Console.Write("failed:  " + Win32Helper.GetLastError32());
                    return;
                }
                else
                {
                    Console.Write("OK.");
                    Console.WriteLine("");
                }

                //TODO:
                //try to do some cleanup in user's app folder C:\Documents and Settings\<user>\Local Settings\Temp
                //

                return;
            }

            #endregion

        }

        /////////////////////////////////////////////////////
        //                                                 //
        // CodewordServicesStartup()                       //
        //                                                 //
        /////////////////////////////////////////////////////
        //Description:  called from Main() when this program is
        //              being executed by the SCM directly as a
        //              result of a service start request.  The
        //              sole job of CodewordServicesStartup() is to fire off
        //              StartServiceCtrlDispatcher(), the main
        //              win32 api for starting a windows svc.
        //
        //Returns:      void
        //////////////////////////////////////////////////////
        private static void CodewordServicesStartup()
        {
            //variables to hold signature and agent settings data
            Dictionary<string, string> AgentSettings = new Dictionary<string, string>();
            string DriverServiceName = "CwDriverSvc";

            //=============================================
            //              LOAD SETTINGS 
            //=============================================
            if (!LoadAgentSettings(ref AgentSettings))
                return;

            AgentService service = new AgentService();

            //define our delegate function as the entry point for the service
            Win32Helper.LPSERVICE_MAIN_FUNCTIONW sproc = new Win32Helper.LPSERVICE_MAIN_FUNCTIONW(service.ServiceMain);
            //create a new SERVICE_TABLE_ENTRY structure
            //note:  the last element in the structure must have its members set to NULL
            Win32Helper.SERVICE_TABLE_ENTRYW[] ServiceDispatchTableEntry = new Win32Helper.SERVICE_TABLE_ENTRYW[2];
            ServiceDispatchTableEntry[0] = new Win32Helper.SERVICE_TABLE_ENTRYW();
            ServiceDispatchTableEntry[0].lpServiceName = AgentSettings["AgentServiceName"];
            ServiceDispatchTableEntry[0].lpServiceProc = Marshal.GetFunctionPointerForDelegate(sproc).ToInt32();
            ServiceDispatchTableEntry[1] = new Win32Helper.SERVICE_TABLE_ENTRYW();
            ServiceDispatchTableEntry[1].lpServiceName = null;
            ServiceDispatchTableEntry[1].lpServiceProc = 0;
            //set the appropriate field of ServiceDispatchTable to point to this table
            Win32Helper.SERVICE_TABLE ServiceDispatchTable = new Win32Helper.SERVICE_TABLE();
            ServiceDispatchTable.lpServiceTable = ServiceDispatchTableEntry;
            //marshal a ptr to the SERVICE_TABLE struct
            IntPtr lpServiceDispatchTable = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(Win32Helper.SERVICE_TABLE)));
            Marshal.StructureToPtr(ServiceDispatchTable, lpServiceDispatchTable, true);

            //
            //KICK IT OFF!
            //this function returns when the service stops (system shutdown, admin stopping, etc)..
            //
            //pass it a ptr to an array of SERVICE_TABLE_ENTRY structures, the last one being null
            try
            {
                Win32Helper.StartServiceCtrlDispatcher(lpServiceDispatchTable);

                if (lpServiceDispatchTable != IntPtr.Zero)
                    Marshal.FreeHGlobal(lpServiceDispatchTable);
            }
            catch (Exception ex)
            {
                StreamWriter sw = new StreamWriter("StartServiceCtrlDispatcherError.txt", true);
                sw.WriteLine(ex.Message);
                if (ex.InnerException != null)
                    sw.WriteLine(ex.InnerException.Message);
                sw.Close();
            }

            //ok...if we got here, the AGENT service was stopped for some reason.
            //so, stop the driver service in parallel.  do NOT delete the driver file or service.
            try
            {
                ServiceHelper.StopService(DriverServiceName);
            }
            catch (Exception) { }

            return;
        }

        /////////////////////////////////////////////////////
        //                                                 //
        // TerminateAgents()                               //
        //                                                 //
        /////////////////////////////////////////////////////
        //Description:  kills any other process with the name
        //              CwAgent.exe, to insure any agent already
        //              installed as a service on this machine
        //              can be stopped via the SCM later.
        //
        //Returns:      void
        //////////////////////////////////////////////////////
        private static void TerminateAgents()
        {
            uint myPid = Win32Helper.GetCurrentProcessId();

            Process[] processlist = Process.GetProcesses();

            foreach (Process theprocess in processlist)
            {
                if (theprocess.ProcessName.ToLower() == "cwagent.exe" && theprocess.Id != (int)myPid)
                {
                    IntPtr hProcess = Win32Helper.OpenProcess(Win32Helper.PROCESS_TERMINATE, false, (uint)theprocess.Id);

                    if (hProcess != IntPtr.Zero)
                        Win32Helper.TerminateProcess(hProcess, 0);
                }
            }
        }

        /////////////////////////////////////////////////////
        //                                                 //
        // GetAgentInstallPath()                           //
        //                                                 //
        /////////////////////////////////////////////////////
        //Description:  parses the friendly folder name and
        //              returns a physical path.
        //
        //Returns:      full path to install agent to
        //////////////////////////////////////////////////////
        private static void GetAgentInstallPath(string folderFriendlyName, string agentBinaryName, ref string pathString)
        {
            string installLocation = "";
            if (folderFriendlyName == "System folder")
                installLocation = Environment.GetFolderPath(Environment.SpecialFolder.System);
            else if (folderFriendlyName == "Program Files\\Microsoft\\Networking")
                installLocation = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles) + "\\Microsoft\\";
            else if (folderFriendlyName == "Current directory")
                installLocation = Environment.CurrentDirectory;

            //create the fake folder if specified
            if (folderFriendlyName == "Program Files\\Microsoft\\Networking")
            {
                //does C:\Program Files\Microsoft exist?
                if (Directory.Exists(installLocation))
                {
                    //yes, then try C:\Program Files\Microsoft\Networking..
                    installLocation += "\\Networking";
                    if (!Directory.Exists(installLocation))
                    {
                        //ok, create it..
                        try
                        {
                            Directory.CreateDirectory(installLocation);
                        }
                        catch (Exception)
                        {
                            installLocation = Environment.GetFolderPath(Environment.SpecialFolder.System);
                        }
                    }
                }
                //create it..
                else
                {
                    //ok, create it..
                    try
                    {
                        Directory.CreateDirectory(installLocation);
                        installLocation += "\\Networking";
                        Directory.CreateDirectory(installLocation);
                    }
                    catch (Exception)
                    {
                        installLocation = Environment.GetFolderPath(Environment.SpecialFolder.System);
                    }
                }
            }

            //add the binary name to the install location
            installLocation += "\\" + agentBinaryName;

            pathString = installLocation;
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
        private static unsafe bool LoadAgentSettings(ref Dictionary<string,string> AgentSettings)
        {
            //use XML settings file in current directory - "CwAgentConfiguration.xml"
            //this will allow us to deserialize the XML data into class structures
            CwXML xml = new CwXML();
            CwXML.CodewordSettingsTemplate cst = new CwXML.CodewordSettingsTemplate();

            try
            {
                cst = xml.LoadSettingsXML("CwAgentConfiguration.xml");
            }
            catch (Exception)
            {
                return false;
            }

            //copy the settings from the CST object to a more usable dictionary<> struct
            int count = 0;
            foreach (string s in cst.FormElementNames)
            {
                AgentSettings[s] = cst.FormElementValues[count];
                count++;
            }

            return true;
        }

        /////////////////////////////////////////////////////
        //                                                 //
        // DoPreRequisiteCheck()                           //
        //                                                 //
        /////////////////////////////////////////////////////
        //Description:  Insures we are running as Admin.
        //
        //Returns:      true if successful
        //////////////////////////////////////////////////////
        private static bool DoPreRequisiteCheck()
        {
            //in order to run, Codeword must:
            //      -be run as administrator
            //      -be able to disable Vista UAC prompting for current account
            //      -have .NET installed (obviously this must be checked before this app can even run!!)
            WindowsIdentity wi = WindowsIdentity.GetCurrent();
            WindowsPrincipal wp = new WindowsPrincipal(wi);

            //1.  Make sure we are administrator
            if (!wp.IsInRole(WindowsBuiltInRole.Administrator))
                return false;
            return true;
        }
    }
}
