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
using System.Xml.Serialization;
using Ionic.Utils.Zip;
using Microsoft.Win32;
using CwHandler;

namespace CwAgent
{
    public partial class AgentScanner
    {
        //-----------------------------------------------
        //              GLOBAL VARIABLES
        //-----------------------------------------------
        //variable to hold results sent back to client
        internal CwXML.CodewordAgentHeuristicMatches AgentHeuristicMatches;
        internal CwXML.CodewordAgentSignatureMatches AgentSignatureMatches;
        internal string ZipFileName;
        internal SecureString ZipPassword;
        public static StringBuilder AgentScanLog;
        internal int TotalFindingsCount;
        
        //variables to hold signature and agent settings data
        internal Dictionary<string, string> AgentSettings;
        CwXML.RegistrySignature[] AgentRegistrySignatures;
        CwXML.RegistryGuidSignature[] AgentRegistryGuidSignatures;
        CwXML.FileSignature[] AgentFileSignatures;
        CwXML.MemorySignature[] AgentMemorySignatures;

        public AgentScanner()
        {
            AgentScanLog = new StringBuilder();
            AgentSettings = new Dictionary<string, string>();
            AgentHeuristicMatches = new CwXML.CodewordAgentHeuristicMatches();
            AgentHeuristicMatches.KernelModeMatches = new CwXML.KernelModeHeuristicMatches();
            AgentHeuristicMatches.UserModeMatches = new CwXML.UserModeHeuristicMatches();

            AgentSignatureMatches = new CwXML.CodewordAgentSignatureMatches();
            AgentSignatureMatches.RegistrySignatureMatches = new CwXML.RegistrySignatureMatch[0];
            AgentSignatureMatches.MemorySignatureMatches = new CwXML.MemorySignatureMatch[0];
            AgentSignatureMatches.FileSignatureMatches = new CwXML.FileSignatureMatch[0];
        }

        /////////////////////////////////////////////////////
        //                                                 //
        // FireAndForget()                                 //
        //                                                 //
        /////////////////////////////////////////////////////
        //Description:  This function is for the special case
        //              when the agent is running in 
        //              "Fire and Forget" mode, in which all
        //              of the various tasks (scan, collect, 
        //              mitigate, report) are done automatically.
        //
        //Returns:      void
        /////////////////////////////////////////////////////
        internal void FireAndForget()
        {
            //=============================================
            //              INITIALIZATION
            //=============================================
            //
            //1.  Load settings from XML file extracted to local dir from MSI
            //
            AgentScanLog.AppendLine("INITIALIZE:  Loading scan settings...");

            if (!LoadAgentSettings(ref AgentSettings))
                return;

            //
            //2.  log basic information about this system, along with information supplied in config file
            //
            LogSystemInformation(AgentSettings);
            LogAllSettings(AgentSettings);

            //
            //3.  Disable .NET security
            //
            EnvironmentHelper.ToggleDotnetSecurity("Off", "INITIALIZE");

            //=============================================
            //              EXECUTE TASKS
            //=============================================
            AgentScanLog.AppendLine("EXECUTE:  Tasks starting on " + DateTime.Now.ToString("MM/dd/yyyy HH:mm:ss"));
            DoSignatureScan();
            DoCollect();
            DoMitigate();
            DoPostScanTasks();
            AgentScanLog.AppendLine("FINALIZE:  Tasks finished on " + DateTime.Now.ToString("MM/dd/yyyy HH:mm:ss"));

            //generate runtime log from LogData
            StreamWriter RuntimeLog = new StreamWriter("AgentScanLog.txt");
            RuntimeLog.WriteLine(AgentScanLog.ToString());
            RuntimeLog.Close();

            //=============================================
            //           PREPARE REPORT PACKAGE
            //=============================================
            try
            {
                IntPtr pPwd = IntPtr.Zero;

                //decrypt our zip password in memory
                if (AgentSettings.ContainsKey("Reporting_Archive_Password"))
                    pPwd = Marshal.SecureStringToBSTR(ZipPassword);

                //re-open zip file we closed earlier and add final agent scan log
                using (ZipFile zip = ZipFile.Read(ZipFileName))
                {
                    if (pPwd != IntPtr.Zero)
                        zip.Password = Marshal.PtrToStringBSTR(pPwd);

                    //RUNTIME LOG FILE
                    Collect.AddToZip(zip, "AgentScanLog.txt");

                    zip.Save();
                }  //disposal is automatic here

                //zero the password memory
                if (pPwd != IntPtr.Zero)
                    Marshal.ZeroFreeBSTR(pPwd);
            }
            catch (Exception) { }

            //ENCRYPT THE PACKAGE AND DELETE OLD ONE
            if (CwCryptoHelper.EncryptFile(ZipFileName))
            {
                File.Delete(ZipFileName);
                ZipFileName += ".enc";
            }

            //=============================================
            //                SEND RESULTS
            //=============================================
            //send results to the site based on reporting method selected
            Reporting.SendResults(AgentSettings, ZipFileName);

            //re-enable dotnet security
            EnvironmentHelper.ToggleDotnetSecurity("on", "FINALIZE");
        }

        /////////////////////////////////////////////////////
        //                                                 //
        // StartScanTask()                                 //
        //                                                 //
        /////////////////////////////////////////////////////
        //Description:  This function only performs the setup
        //              necessary to perform a scan of registry,
        //              disk and memory, and to report those
        //              results back to the admin console.
        //
        //Returns:      a stringbuilder object containing log data.
        /////////////////////////////////////////////////////
        internal StringBuilder StartScanTask(ref CwXML.CodewordAgentAnomalyReport anomalyReport)
        {
            //clear any existing results
            anomalyReport = new CwXML.CodewordAgentAnomalyReport();
            AgentHeuristicMatches = new CwXML.CodewordAgentHeuristicMatches();
            AgentHeuristicMatches.KernelModeMatches = new CwXML.KernelModeHeuristicMatches();
            AgentHeuristicMatches.UserModeMatches = new CwXML.UserModeHeuristicMatches();
            AgentSignatureMatches = new CwXML.CodewordAgentSignatureMatches();
            AgentSignatureMatches.RegistrySignatureMatches = new CwXML.RegistrySignatureMatch[0];
            AgentSignatureMatches.MemorySignatureMatches = new CwXML.MemorySignatureMatch[0];
            AgentSignatureMatches.FileSignatureMatches = new CwXML.FileSignatureMatch[0];
            //
            //1.  Load settings from XML file extracted to local dir from MSI
            //
            AgentScanLog.AppendLine("INITIALIZE:  Loading scan settings...");

            if (!LoadAgentSettings(ref AgentSettings))
                return AgentScanLog;

            //
            //2.  Load signatures - this only needs to be done once here for the whole file
            //
            AgentScanLog.AppendLine("SCAN:  Loading signatures from XML file...");

            if (!LoadAgentSignatures())
                return AgentScanLog;

            //
            //3.  Disable .NET security
            //
            EnvironmentHelper.ToggleDotnetSecurity("Off", "INITIALIZE");
            
            //
            //4.  kick off scan
            //
            AgentScanLog.AppendLine("SCAN:  Scan starting on " + DateTime.Now.ToString("MM/dd/yyyy HH:mm:ss"));
            DoSignatureScan();
            //IMPORTANT:  pin the scan results object so the garbage collector doesn't mangle it...
            //GCHandle gchAgentSignatureMatches = GCHandle.Alloc(AgentSignatureMatches, GCHandleType.Pinned);

            //only auto-mitigate if option set.
            if (AgentSettings["Option_AutoMitigate"] == "True")
                DoMitigate();
            DoUserModeHeuristics();
            DoKernelModeHeuristics();
            AgentScanLog.AppendLine("SCAN:  Scan finished on " + DateTime.Now.ToString("MM/dd/yyyy HH:mm:ss"));
            //
            //5.  re-enable .NET security
            //
            EnvironmentHelper.ToggleDotnetSecurity("On", "FINALIZE");

            //
            //6.  return our results object byref
            //
            //sanitize the XML by escaping invalid characters first
            int count = 0;

            foreach (CwXML.RegistrySignatureMatch match in AgentSignatureMatches.RegistrySignatureMatches)
            {
                match.RegistryValueData = CwXML.ReplaceInvalidXmlChars(match.RegistryValueData);
                match.RegistryValueName = CwXML.ReplaceInvalidXmlChars(match.RegistryValueName);
                AgentSignatureMatches.RegistrySignatureMatches[count] = match;
                count++;
            }

            count = 0;

            foreach (CwXML.MemorySignatureMatch match in AgentSignatureMatches.MemorySignatureMatches)
            {
                //keywords are not required in memory search - could just be looking for presence of a process name
                if (match.Keywords != null)
                    match.Keywords = CwXML.ReplaceInvalidXmlChars(match.Keywords);
                match.MatchingBlock = CwXML.ReplaceInvalidXmlChars(match.MatchingBlock);
                AgentSignatureMatches.MemorySignatureMatches[count] = match;
                count++;
            }

            //assign the fields of the passed-in object byref
            anomalyReport.SignatureMatches = AgentSignatureMatches;
            anomalyReport.HeuristicMatches = AgentHeuristicMatches;

            //release our pinned handle to results
            //gchAgentSignatureMatches.Free();

            return AgentScanLog;
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
                AgentScanLog.AppendLine("ERROR:  " + e.Message);
                AgentScanLog.AppendLine("ERROR:  Failed to load settings, terminating...");
                return false;
            }

            //copy the settings from the CST object to a more usable dictionary<> struct
            int count = 0;
            foreach (string s in cst.FormElementNames)
            {
                AgentSettings[s] = cst.FormElementValues[count];
                count++;
            }

            AgentScanLog.AppendLine("INITIALIZE:  Success.");
            return true;
        }

        /////////////////////////////////////////////////////
        //                                                 //
        // LoadAgentSignatures()                           //
        //                                                 //
        /////////////////////////////////////////////////////
        //Description:  Loads signatures from the agent sig file.
        //
        //Returns:      true if successful
        //////////////////////////////////////////////////////
        private unsafe bool LoadAgentSignatures()
        {
            //use XML signature template file in current directory - "CwAgentSignatures.xml"
            //this will allow us to deserialize the XML data into class structures
            CwXML xml = new CwXML();
            CwXML.CodewordSignatureTemplate sigs = new CwXML.CodewordSignatureTemplate();
            try
            {
                sigs = xml.ImportSignatureTemplate("CwAgentSignatures.xml");
            }
            catch (Exception e)
            {
                AgentScanLog.AppendLine("ERROR:  " + e.Message);
                AgentScanLog.AppendLine("ERROR:  Failed to load signatures, terminating...");
                return false;
            }

            //save the values into global variables for all funcs to access
            AgentRegistrySignatures = sigs.RegistrySignatures;
            AgentRegistryGuidSignatures = sigs.RegistryGuidSignatures;
            AgentFileSignatures = sigs.FileSignatures;
            AgentMemorySignatures = sigs.MemorySignatures;

            return true;
        }

        /////////////////////////////////////////////////////
        //                                                 //
        // DoSignatureScan()                               //
        //                                                 //
        /////////////////////////////////////////////////////
        //Description:  Scans memory, disk and registry for 
        //              given signatures.  Stores results in
        //              class global results object.
        //
        //Returns:      true if successful
        //////////////////////////////////////////////////////
        private unsafe bool DoSignatureScan()
        {
            AgentScanLog.AppendLine("");
            AgentScanLog.AppendLine("*********************************************");
            AgentScanLog.AppendLine("               SIGNATURE SCAN                ");
            AgentScanLog.AppendLine("*********************************************");
            AgentScanLog.AppendLine("");

            //
            //=============================================
            //          SCAN FOR REGISTRY SIGNATURES
            //=============================================
            //
            RegistryHelper RegistryScanner = new RegistryHelper();

            //mount NTUSER.DAT files (so every user's SID is mounted in HKEY_USERS)
            RegistryScanner.LoadNtUserDatFiles(false);

            if (AgentRegistrySignatures.Length > 0)
            {
                AgentScanLog.AppendLine("SCAN:  Scanning registry for infections...");

                //optionally scan HKCR for potentially malicious GUIDs
                //nb:  if any found, auto added to malware_info.GUIDs container
                if (AgentSettings.ContainsKey("Option_Scan_GUIDs"))
                    if (AgentSettings["Option_Scan_GUIDs"] == "True")
                        RegistryScanner.ScanForMaliciousGUIDs();

                //create a static GUID in our AgentRegistryGuidSignatures for every dynamic GUID
                RegistryScanner.LoadDynamicGUIDs(ref AgentRegistryGuidSignatures);

                //
                //perform actual scan
                //
                //initialization here is irrelevant; it will be allocated in the function
                RegistryScanner.ScanForRegistrySignatures(AgentRegistrySignatures, AgentRegistryGuidSignatures, ref AgentSignatureMatches.RegistrySignatureMatches);

                //append scan log
                AgentScanLog.AppendLine(RegistryScanner.RegistryHelperLog.ToString());
                AgentScanLog.AppendLine("SCAN:  Registry scan complete.");
            }

            //
            //=============================================
            //          SCAN FOR FILE SIGNATURES
            //=============================================
            //
            FileHelper FileScanner = new FileHelper();

            if (AgentFileSignatures.Length > 0)
            {
                AgentScanLog.AppendLine("SCAN:  Scanning all attached disks for file signatures...");

                //perform scan
                FileScanner.ScanForFileSignatures(AgentFileSignatures, ref AgentSignatureMatches.FileSignatureMatches);

                //append the file scan log
                AgentScanLog.AppendLine(FileScanner.FileHelperLog.ToString());
                AgentScanLog.AppendLine("SCAN:  Disk scans complete.");
            }

            //
            //=============================================
            //          SCAN FOR MEMORY SIGNATURES
            //=============================================
            //
            MemoryHelper MemoryScanner = new MemoryHelper();

            if (AgentMemorySignatures.Length > 0)
            {
                AgentScanLog.AppendLine("SCAN:  Scanning active processes for memory signatures...");

                //setup a few scan parameters based on agent settings
                //
                //search cmd line parameters?
                bool SearchCmdLine = false;
                if (AgentSettings.ContainsKey("MemorySignatures_SearchCmdLine"))
                    if (AgentSettings["MemorySignatures_SearchCmdLine"] == "True")
                        SearchCmdLine = true;
                //search heap space?
                bool SearchHeap = false;
                if (AgentSettings.ContainsKey("MemorySignatures_SearchHeapSpace"))
                    if (AgentSettings["MemorySignatures_SearchHeapSpace"] == "True")
                        SearchHeap = true;
                //search loaded module list (dlls)?
                bool SearchLoadedModuleList = false;
                if (AgentSettings.ContainsKey("MemorySignatures_SearchLoadedModules"))
                    if (AgentSettings["MemorySignatures_SearchLoadedModules"] == "True")
                        SearchLoadedModuleList = true;
                //search registry findings in process?
                bool SearchForRegistryFindings = false;
                if (AgentSettings.ContainsKey("MemorySignatures_UseRegistryFindings"))
                    if (AgentSettings["MemorySignatures_UseRegistryFindings"] == "True")
                        SearchForRegistryFindings = true;

                //perform scan
                MemoryScanner.ScanForMemorySignatures(AgentSignatureMatches.RegistrySignatureMatches, AgentMemorySignatures, ref AgentSignatureMatches.MemorySignatureMatches, SearchCmdLine, SearchHeap, SearchLoadedModuleList, SearchForRegistryFindings);

                //append the memory scanner log
                AgentScanLog.AppendLine(MemoryScanner.MemoryHelperLog.ToString());
                AgentScanLog.AppendLine("SCAN:  Process scan complete.");
            }

            //calculate total # of findings
            TotalFindingsCount = 0;

            if (AgentSignatureMatches.RegistrySignatureMatches != null)
                TotalFindingsCount += AgentSignatureMatches.RegistrySignatureMatches.Length;
            if (AgentSignatureMatches.FileSignatureMatches != null)
                TotalFindingsCount += AgentSignatureMatches.FileSignatureMatches.Length;
            if (AgentSignatureMatches.MemorySignatureMatches != null)
                TotalFindingsCount += AgentSignatureMatches.MemorySignatureMatches.Length;

            //unload NTUSER.DAT files
            RegistryScanner.LoadNtUserDatFiles(true);
            
            /*
            StreamWriter sw = new StreamWriter("AgentScanLog.txt");
            sw.WriteLine(AgentScanLog.ToString());
            sw.Close();*/

            return true;
        }

        /////////////////////////////////////////////////////
        //                                                 //
        // DoKernelModeHeuristics()                        //
        //                                                 //
        /////////////////////////////////////////////////////
        //Description:  Communicates with kernel-mode driver
        //              to perform advanced heuristic analysis.
        //              (oooo...aaaahhh)
        //
        //Returns:      true if successful
        //////////////////////////////////////////////////////
        private unsafe bool DoKernelModeHeuristics()
        {
            AgentHeuristicMatches.KernelModeMatches = new CwXML.KernelModeHeuristicMatches();

            AgentScanLog.AppendLine("");
            AgentScanLog.AppendLine("*********************************************");
            AgentScanLog.AppendLine("          KERNEL-MODE HEURISTICS             ");
            AgentScanLog.AppendLine("*********************************************");
            AgentScanLog.AppendLine("");

            //----------------------------------------------
            //
            //                  SSDT HOOKS
            //
            //----------------------------------------------
            #region SSDT HOOKS

            if (AgentSettings["KernelHeuristics_SSDT_DetectHooks"] == "True")
            {
                AgentScanLog.AppendLine("------------------------");
                AgentScanLog.AppendLine("    SSDT HOOKS       ");
                AgentScanLog.AppendLine("------------------------");


                CwStructures.HOOKED_SSDT_TABLE HookTable = new CwStructures.HOOKED_SSDT_TABLE();

                try
                {
                    HookTable = HeuristicsKernelModeHelper.GetSSDTHooks();
                }
                catch (Exception ex)
                {
                    AgentScanLog.AppendLine("SCAN:  Error checking for SSDT hooks:  " + ex.Message);
                }

                //save the hook table to return object.
                AgentHeuristicMatches.KernelModeMatches.SSDTHookTable = HookTable;
            }
            else
            {
                AgentHeuristicMatches.KernelModeMatches.SSDTHookTable = new CwStructures.HOOKED_SSDT_TABLE();
            }
            #endregion

            //----------------------------------------------
            //
            //                  SSDT DETOURS
            //
            //----------------------------------------------
            #region SSDT DETOURS

            if (AgentSettings["KernelHeuristics_SSDT_DetectDetours"] == "True")
            {
                AgentScanLog.AppendLine("------------------------");
                AgentScanLog.AppendLine("    SSDT DETOURS       ");
                AgentScanLog.AppendLine("------------------------");


                CwStructures.DETOURED_SSDT_TABLE DetourTable = new CwStructures.DETOURED_SSDT_TABLE();

                try
                {
                    DetourTable = HeuristicsKernelModeHelper.GetSSDTDetours();
                }
                catch (Exception ex)
                {
                    AgentScanLog.AppendLine("SCAN:  Error checking for SSDT detours:  " + ex.Message);
                }

                //save the hook table to return object.
                AgentHeuristicMatches.KernelModeMatches.SSDTDetourTable = DetourTable;
            }
            else
            {
                AgentHeuristicMatches.KernelModeMatches.SSDTDetourTable = new CwStructures.DETOURED_SSDT_TABLE();
            }

            #endregion

            //----------------------------------------------
            //
            //                  WIN32 API DETOURS
            //
            //----------------------------------------------
            //
            //TODO:  this functionality is disabled until fixed.
            //
            #region WIN32 API DETOURS
            /*
            if (AgentSettings["KernelHeuristics_Win32Api_CheckExportsForDetours"] == "True")
            {
                AgentScanLog.AppendLine("------------------------");
                AgentScanLog.AppendLine("    WIN32 API DETOURS   ");
                AgentScanLog.AppendLine("------------------------");

                string[] DirtyDlls = new string[] { "ntdll.dll","kernel32.dll","user32.dll","advapi32.dll",
                                                       "gdi32.dll","comdlg32.dll","comctl32.dll","commctrl.dll",
                                                       "shell.dll","shlwapi.dll","mshtml.dll","urlmon.dll"}; //ntdll.dll??
            
                //initialize return object to 12 items
                AgentHeuristicMatches.KernelModeMatches.Win32DetourTable = new CwStructures.WIN32API_DETOUR_TABLE[12];

                //loop through DLLs we care about
                for (int i = 0; i < DirtyDlls.Length; i++)
                {
                    CwStructures.WIN32API_DETOUR_TABLE ModuleDetourTable = new CwStructures.WIN32API_DETOUR_TABLE();
                    string thisDLL = DirtyDlls[i];
                     
                    try
                    {
                        ModuleDetourTable = HeuristicsKernelModeHelper.GetModuleDetours(thisDLL);
                    }
                    catch (Exception ex)
                    {
                        AgentScanLog.AppendLine("SCAN:  Error checking for detours in module '" + thisDLL + "':  " + ex.Message);
                        continue;
                    }

                    //save the hook table to return object.
                    AgentHeuristicMatches.KernelModeMatches.Win32DetourTable[i] = ModuleDetourTable;
                }
            }
            else
            {
                AgentHeuristicMatches.KernelModeMatches.Win32DetourTable = new CwStructures.WIN32API_DETOUR_TABLE[0];
            }
            */
            #endregion

            //----------------------------------------------
            //
            //                  IRP HOOKS
            //
            //----------------------------------------------
            #region IRP HOOOKS

            if (AgentSettings["DriversHeuristics_DetectIRPHooks"] == "True" && AgentSettings.ContainsKey("AddDriverListview"))
            {
                //get the list of driver names and objects
                //it is stored in the settings variable "AddDriverListview"
                //as a comma-separated list:
                //      string[]=  {driver1,device1,driver2,device2,..}
                string drivers = AgentSettings["AddDriverListview"];

                if (drivers.IndexOf(",") != -1)
                {
                    //values were stored as comma-separated list
                    string[] items = drivers.Split(new char[] { ',' });
                    //get DRIVER_CHECK_INFO structs from the driver/device pairs
                    ArrayList driversToCheck = DriverHelper.GetDriverInfoStructs(items);

                    //bail completely
                    if (driversToCheck == null)
                    {
                        AgentHeuristicMatches.KernelModeMatches.DriverIrpHooksTable = new CwStructures.HOOKED_DISPATCH_FUNCTIONS_TABLE[0];
                        return false;
                    }
                    AgentScanLog.AppendLine("------------------------");
                    AgentScanLog.AppendLine("        IRP HOOKS       ");
                    AgentScanLog.AppendLine("------------------------");
                    AgentHeuristicMatches.KernelModeMatches.DriverIrpHooksTable = new CwStructures.HOOKED_DISPATCH_FUNCTIONS_TABLE[driversToCheck.Count];
                    int count = 0;

                    //loop through all drivers/device name combinations supplied by user and check for IRP hooks
                    foreach (CwStructures.DRIVER_CHECK_INFO thisDriver in (CwStructures.DRIVER_CHECK_INFO[])driversToCheck.ToArray(typeof(CwStructures.DRIVER_CHECK_INFO)))
                    {
                        CwStructures.HOOKED_DISPATCH_FUNCTIONS_TABLE DriverHookTable = new CwStructures.HOOKED_DISPATCH_FUNCTIONS_TABLE();

                        try
                        {
                            DriverHookTable = HeuristicsKernelModeHelper.GetHookedDispatchFunctionsInDriver(thisDriver);
                        }
                        catch (Exception ex)
                        {
                            AgentScanLog.AppendLine("SCAN:  Error checking for IRP hooks:  " + ex.Message);
                        }
                        AgentHeuristicMatches.KernelModeMatches.DriverIrpHooksTable[count] = DriverHookTable;
                        count++;
                    }
                }
                else
                {
                    AgentHeuristicMatches.KernelModeMatches.DriverIrpHooksTable = new CwStructures.HOOKED_DISPATCH_FUNCTIONS_TABLE[0];
                }
            }
            else
            {
                AgentHeuristicMatches.KernelModeMatches.DriverIrpHooksTable = new CwStructures.HOOKED_DISPATCH_FUNCTIONS_TABLE[0];
            }

            #endregion

            //----------------------------------------------
            //
            //                  IRP DETOURS
            //
            //----------------------------------------------
            #region IRP DETOURS

            if (AgentSettings["DriversHeuristics_CheckDispatchRoutinesForDetours"] == "True" && AgentSettings.ContainsKey("AddDriverListview"))
            {
                //get the list of driver names and objects
                //it is stored in the settings variable "AddDriverListview"
                //as a comma-separated list:
                //      string[]=  {driver1,device1,driver2,device2,..}
                string drivers = AgentSettings["AddDriverListview"];

                if (drivers.IndexOf(",") != -1)
                {
                    //values were stored as comma-separated list
                    string[] items = drivers.Split(new char[] { ',' });
                    //get DRIVER_CHECK_INFO structs from the driver/device pairs
                    ArrayList driversToCheck = DriverHelper.GetDriverInfoStructs(items);

                    //bail completely
                    if (driversToCheck == null)
                    {
                        AgentHeuristicMatches.KernelModeMatches.DriverIrpHooksTable = new CwStructures.HOOKED_DISPATCH_FUNCTIONS_TABLE[0];
                        return false;
                    }

                    AgentScanLog.AppendLine("------------------------");
                    AgentScanLog.AppendLine("      IRP DETOURS       ");
                    AgentScanLog.AppendLine("------------------------");

                    AgentHeuristicMatches.KernelModeMatches.DriverIrpDetoursTable = new CwStructures.DETOURED_DISPATCH_FUNCTIONS_TABLE[driversToCheck.Count];
                    int count = 0;

                    //loop through all drivers/device name combinations supplied by user and check for IRP hooks
                    foreach (CwStructures.DRIVER_CHECK_INFO thisDriver in (CwStructures.DRIVER_CHECK_INFO[])driversToCheck.ToArray(typeof(CwStructures.DRIVER_CHECK_INFO)))
                    {
                        CwStructures.DETOURED_DISPATCH_FUNCTIONS_TABLE DriverDetoursTable = new CwStructures.DETOURED_DISPATCH_FUNCTIONS_TABLE();

                        try
                        {
                            DriverDetoursTable = HeuristicsKernelModeHelper.GetDetouredDispatchFunctionsInDriver(thisDriver);
                        }
                        catch (Exception ex)
                        {
                            AgentScanLog.AppendLine("SCAN:  Error checking for IRP hooks:  " + ex.Message);
                        }

                        AgentHeuristicMatches.KernelModeMatches.DriverIrpDetoursTable[count] = DriverDetoursTable;
                        count++;
                    }
                }
                else
                {
                    AgentHeuristicMatches.KernelModeMatches.DriverIrpDetoursTable = new CwStructures.DETOURED_DISPATCH_FUNCTIONS_TABLE[0];
                }
            }
            else
            {
                AgentHeuristicMatches.KernelModeMatches.DriverIrpDetoursTable = new CwStructures.DETOURED_DISPATCH_FUNCTIONS_TABLE[0];
            }

            #endregion
            
            return true;
        }

        /////////////////////////////////////////////////////
        //                                                 //
        // DoUserModeHeuristics()                          //
        //                                                 //
        /////////////////////////////////////////////////////
        //Description:  Implements user mode heuristics to check
        //              for anomalies not identifiable in static
        //              signatures...aww, no ooooo/ahhhh?
        //
        //Returns:      true if successful
        //////////////////////////////////////////////////////
        private unsafe bool DoUserModeHeuristics()
        {
            AgentScanLog.AppendLine("");
            AgentScanLog.AppendLine("*********************************************");
            AgentScanLog.AppendLine("          USER-MODE HEURISTICS             ");
            AgentScanLog.AppendLine("*********************************************");
            AgentScanLog.AppendLine("");
            AgentScanLog.AppendLine("------------------------");
            AgentScanLog.AppendLine("    HIDDEN PROCESSES    ");
            AgentScanLog.AppendLine("------------------------");

            //-------------------------------------
            //      HIDDEN PROCESS DETECTION
            //-------------------------------------
            AgentHeuristicMatches.UserModeMatches.ProcessListing = HeuristicsUserModeHelper.CrossViewAnalysis();

            return true;
        }

        /////////////////////////////////////////////////////
        //                                                 //
        // DoCollect()                                     //
        //                                                 //
        /////////////////////////////////////////////////////
        //Description:  Collects all files identified in the scan
        //              as malicious and stuffs them into a
        //              password-protected, encrypted ZIP file.
        //
        //              NOTE:  depends on DoSignatureScan()
        //
        //
        //Returns:      true if successful
        //////////////////////////////////////////////////////
        private unsafe bool DoCollect()
        {
            AgentScanLog.AppendLine("");
            AgentScanLog.AppendLine("*********************************************");
            AgentScanLog.AppendLine("                  COLLECT                    ");
            AgentScanLog.AppendLine("*********************************************");
            AgentScanLog.AppendLine("");
            AgentScanLog.AppendLine("COLLECT:  Collecting evidence files...");

            //collect the following files to wrap up in archive file:
            //  1. all identified malware files
            //  2. infection log (Infection_Log.txt) which we create
            //  3. usb device list file (USB_Devices.txt) which we create
            //  4. .net installation log (if exists)
            //  

            //---------------------------------
            //          BUILD ZIP NAME
            //---------------------------------
            ZipFileName = Collect.BuildZipName(TotalFindingsCount);
            ZipFile zip = new ZipFile(ZipFileName);

            if (AgentSettings.ContainsKey("Reporting_Archive_Password"))
            {
                IntPtr pptr = IntPtr.Zero;
                //do this secure string thing if password specified
                char[] str = AgentSettings["Reporting_Archive_Password"].ToCharArray();

                fixed (char* pChars = str)
                {
                    ZipPassword = new SecureString(pChars, str.Length);
                }

                //decrypt our password in memory
                pptr = Marshal.SecureStringToBSTR(ZipPassword);
                zip.Password = Marshal.PtrToStringBSTR(pptr);

                //zero the password memory
                Marshal.ZeroFreeBSTR(pptr);
            }

            zip.TempFileFolder = ".";
            ArrayList CollectList = new ArrayList();
            int count = 0;

            AgentScanLog.AppendLine("COLLECT:  Searching file signature matches for files...");

            //loop through file signatures
            foreach (CwXML.FileSignatureMatch fileMatch in AgentSignatureMatches.FileSignatureMatches)
                if (Collect.AddToZip(zip, fileMatch.FullPath))
                    count++;

            AgentScanLog.AppendLine("COLLECT:  Added " + count + " files.");
            count = 0;
            AgentScanLog.AppendLine("COLLECT:  Searching registry signature matches for files...");

            //loop through registry signatures
            foreach (CwXML.RegistrySignatureMatch registryMatch in AgentSignatureMatches.RegistrySignatureMatches)
                if (registryMatch.IsFileOnDisk)
                    if (Collect.AddToZip(zip, registryMatch.RegistryValueData))
                        count++;

            AgentScanLog.AppendLine("COLLECT:  Added " + count + " files.");
            AgentScanLog.AppendLine("COLLECT:  Generating infection summary report...");

            //---------------------------------
            //          ADD INFECTION LOG
            //---------------------------------
            //2.  infection log (Infection_Log.txt) which we create
            StreamWriter infectionlog = new StreamWriter("InfectionLog.txt");
            StringBuilder InfectionSummaryReport = new StringBuilder();

            //print infection summary for each signature type
            RegistryHelper RegHelper = new RegistryHelper();
            FileHelper FileHelper = new FileHelper();
            MemoryHelper MemHelper = new MemoryHelper();
            RegHelper.PrintRegistryFindings(AgentSignatureMatches.RegistrySignatureMatches, ref InfectionSummaryReport);
            FileHelper.PrintFileFindings(AgentSignatureMatches.FileSignatureMatches, ref InfectionSummaryReport);
            MemHelper.PrintMemoryFindings(AgentSignatureMatches.MemorySignatureMatches, ref InfectionSummaryReport);
            infectionlog.WriteLine(InfectionSummaryReport.ToString());
            infectionlog.Close();
            zip.AddFile("InfectionLog.txt");

            AgentScanLog.AppendLine("COLLECT:  Enumerating USB Devices...");

            //---------------------------------
            //          ADD USB DEVICES LOG
            //---------------------------------
            //3.  usb device list file (USB_Devices.txt) which we create
            StreamWriter usblogfile = new StreamWriter("USB_Devices.txt");
            StringBuilder UsbDevicesReport = new StringBuilder();
            Collect.EnumerateUSBDevices(ref UsbDevicesReport);
            usblogfile.WriteLine(UsbDevicesReport.ToString());
            usblogfile.Close();
            zip.AddFile("USB_Devices.txt");

            //---------------------------------
            //          ADD .NET LOG
            //---------------------------------
            //4.  .net installation log (if exists)
            try
            {
                FileInfo dotnetfxLogfile = new FileInfo("dotnetfx_install_log.txt");
                if (dotnetfxLogfile.Exists)
                    zip.AddFile("dotnetfx_install_log.txt");
            }
            catch { } //no biggie..

            AgentScanLog.AppendLine("COLLECT:  All evidence collected.");
            AgentScanLog.AppendLine("COLLECT:  Saving zip to disk...");
            zip.Save();
            zip.Dispose();  //at this point zip is closed and written to disk

            return true;
        }

        /////////////////////////////////////////////////////
        //                                                 //
        // DoMitigate()                                    //
        //                                                 //
        /////////////////////////////////////////////////////
        //Description:  Performs various mitigation tasks, such
        //              as usb device disabling.
        //
        //              NOTE:  depends on DoSignatureScan()
        //
        //Returns:      true if successful
        //////////////////////////////////////////////////////
        private unsafe bool DoMitigate()
        {
            AgentScanLog.AppendLine("");
            AgentScanLog.AppendLine("*********************************************");
            AgentScanLog.AppendLine("            MITIGATE/CLEAN                   ");
            AgentScanLog.AppendLine("*********************************************");
            AgentScanLog.AppendLine("");

            //remove file references we found in registry from disk?
            bool removeReferences = false;
            if (AgentSettings.ContainsKey("Option_Delete_MalwareFoundInRegistry"))
                if (AgentSettings["Option_Delete_MalwareFoundInRegistry"] == "True")
                    removeReferences = true;

            //instantiate our helper classes
            RegistryHelper RegHelper = new RegistryHelper();
            FileHelper FileHelper = new FileHelper();
            MemoryHelper MemHelper = new MemoryHelper();

            if (AgentSignatureMatches.RegistrySignatureMatches != null)
                if (AgentSignatureMatches.RegistrySignatureMatches.Length > 0)
                    RegHelper.CleanRegistryFindings(ref AgentSignatureMatches.RegistrySignatureMatches, removeReferences);
            if (AgentSignatureMatches.FileSignatureMatches != null)
                if (AgentSignatureMatches.FileSignatureMatches.Length > 0)
                    FileHelper.CleanFileFindings(ref AgentSignatureMatches.FileSignatureMatches);
            if (AgentSignatureMatches.MemorySignatureMatches != null)
                if (AgentSignatureMatches.MemorySignatureMatches.Length > 0)
                    MemHelper.CleanMemoryFindings(ref AgentSignatureMatches.MemorySignatureMatches);

            //=============================================
            //          Disable/Disassociate autorun
            //=============================================
            if (AgentSettings["Option_Disable_Autorun"] == "True")
                Mitigate.DisableAndDisassociateAutorun();

            //=============================================
            //          Disable USB
            //=============================================
            if (AgentSettings["Option_Disable_USB"] == "True")
                Mitigate.DisableUseOfUSBDevices();

            AgentScanLog.AppendLine("MITIGATE:  Cleanup process complete.");
            AgentScanLog.AppendLine("MITIGATE:  Closing log file...");
            AgentScanLog.AppendLine("FINALIZE:  Codeword exiting on " + DateTime.Now.ToString("MM/dd/yyyy HH:mm:ss"));

            return true;
        }

        /////////////////////////////////////////////////////
        //                                                 //
        // DoPostScanTasks()                               //
        //                                                 //
        /////////////////////////////////////////////////////
        //Description:  Runs any 3rd party apps specified in
        //              agent configuration.
        //
        //Returns:      true if successful
        //////////////////////////////////////////////////////
        private unsafe bool DoPostScanTasks()
        {
            if (AgentSettings.ContainsKey("Advanced_3rdPartyApp_Filename"))
            {
                if (AgentSettings["Advanced_3rdPartyApp_Filename"] != "")
                {
                    string command = AgentSettings["Advanced_3rdPartyApp_Filename"];
                    string args = "";
                    bool extractSuccess = true;

                    //should we extract this app from our internal assembly or assume
                    //it exists on the local machine?
                    if (AgentSettings.ContainsKey("Advanced_3rdPartyApp_Distribute"))
                    {
                        if (AgentSettings["Advanced_3rdPartyApp_Distribute"] == "True")
                        {
                            if (!EnvironmentHelper.ExtractInternalResource(command, command))
                            {
                                AgentScanLog.AppendLine("ERROR:  Failed to extract 3rd party app '" + command + "'.");
                                extractSuccess = false;
                            }
                        }
                    }

                    //were any arguments supplied?
                    if (AgentSettings.ContainsKey("Advanced_3rdPartyApp_Arguments"))
                        args = AgentSettings["Advanced_3rdPartyApp_Arguments"];

                    //run the app
                    if (extractSuccess)
                    {
                        AgentScanLog.AppendLine("FINALIZE:  Executing third party app '" + command + "' with args '" + args + "'...");
                        if (!Mitigate.RunThirdPartyApp(command, args))
                            AgentScanLog.AppendLine("FINALIZE:  Failed to execute third party app.");
                    }
                }
            }

            return true;
        }

        /////////////////////////////////////////////////////
        //                                                 //
        // LogSystemInformation()                          //
        //                                                 //
        /////////////////////////////////////////////////////
        //Description:  Gathers key info about this system and
        //              adds it to the scanner log.  It also logs
        //              info included in the XML settings file
        //              about this agent installer.
        //
        //Returns:      void
        //////////////////////////////////////////////////////
        internal static void LogSystemInformation(Dictionary<string, string> settings)
        {
            AgentScanLog.AppendLine("****************** SITE INFORMATION *******************");
            foreach (KeyValuePair<string, string> keyValPair in settings)
                if (keyValPair.Key.Contains("Information_"))
                    AgentScanLog.AppendLine(keyValPair.Key + " = " + keyValPair.Value);
            AgentScanLog.AppendLine("******************************************************");

            //collect host information and log it
            string[] IPAddresses = EnvironmentHelper.GetIPAddresses();
            string[] Drives = Environment.GetLogicalDrives();
            AgentScanLog.AppendLine("****************** HOST INFORMATION *******************");
            AgentScanLog.AppendLine("Computer name:     " + Environment.MachineName);
            AgentScanLog.AppendLine("Domain name:       " + Environment.UserDomainName);
            AgentScanLog.AppendLine("IP Addresses:        " + string.Join(",",IPAddresses));
            AgentScanLog.AppendLine("User name:         " + Environment.UserName);
            AgentScanLog.AppendLine("OS:                " + Environment.OSVersion.ToString());
            AgentScanLog.AppendLine("Current Path:      " + Environment.CurrentDirectory.ToString());
            AgentScanLog.AppendLine("Logical Drives:    " + string.Join(",",Drives));
            AgentScanLog.AppendLine("Shutdown started:  " + Environment.HasShutdownStarted.ToString());
            AgentScanLog.AppendLine("Processor count:   " + Environment.ProcessorCount.ToString());
            AgentScanLog.AppendLine("Working set:       " + (Environment.WorkingSet / 1000000).ToString() + "MB");
            AgentScanLog.AppendLine("******************************************************");

            return;
        }

        /////////////////////////////////////////////////////
        //                                                 //
        // LogAllSettings()                                //
        //                                                 //
        /////////////////////////////////////////////////////
        //Description:  Simply dumps all XML file settings.
        //
        //Returns:      void
        //////////////////////////////////////////////////////
        internal static void LogAllSettings(Dictionary<string, string> settings)
        {
            AgentScanLog.AppendLine("****************** AGENT SETTINGS *******************");
            foreach (KeyValuePair<string, string> keyValPair in settings)
                AgentScanLog.AppendLine(keyValPair.Key + " = " + keyValPair.Value);
            AgentScanLog.AppendLine("******************************************************");
        }

        /////////////////////////////////////////////////////
        //                                                 //
        // BinaryWrite()                                   //
        //                                                 //
        /////////////////////////////////////////////////////
        //Description:  Writes binary data to given file
        //Returns:      true if successful
        /////////////////////////////////////////////////////
        internal static bool BinaryWrite(string filename, byte[] data)
        {
            FileStream outfile;
            BinaryWriter bw;

            //create the file on disk - auto overwrite if exists
            try
            {
                outfile = File.Create(filename);
            }
            catch (Exception e)
            {
                throw new Exception("Fatal error occurred.  Could not create file '" + filename + "':  " + e.Message);
            }

            //write to the file
            try
            {
                bw = new BinaryWriter(outfile);
                bw.Write(data);
                bw.Flush();
                bw.Close();
            }
            catch (Exception e)
            {
                outfile.Close();
                throw new Exception("Fatal error occurred.  Could not write to file '" + filename + "':  " + e.Message);
            }

            return true;
        }

        internal static void LogHit2(int n)
        {
            StreamWriter sw = new StreamWriter("loghit2.txt",true);
            sw.WriteLine(n.ToString());
            sw.Close();
        }
    }
}