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
    public partial class AgentScanner
    {
        public class HeuristicsUserModeHelper
        {
            /////////////////////////////////////////////////////
            //                                                 //
            // GetKernelModeProcessListingZwq()                //
            //                                                 //
            /////////////////////////////////////////////////////
            //Description:  Queries the cw driver to return a list
            //              of processes using ZwQuerySystemInformation().
            //
            //Returns:      a CWPROCESS_RECORD struct
            /////////////////////////////////////////////////////
            internal static CwStructures.PROCESS_LISTING_ZWQ GetKernelModeProcessListingZwq()
            {
                //-----------------------------
                //      SEND COMMAND
                //-----------------------------
                //build the IOCTL to send to driver
                uint ioctl = Win32Helper.GetIOCTL(CwConstants.CW_DRIVER_PROCESS_LISTING_ZWQ, Win32Helper.METHOD_OUT_DIRECT);

                //build our buffers
                int InBufSize = 0;
                int OutBufSize = Marshal.SizeOf(typeof(CwStructures.PROCESS_LISTING_ZWQ));
                IntPtr lpInBuf = IntPtr.Zero;
                IntPtr lpOutBuf = Marshal.AllocHGlobal(OutBufSize);
                int bytesReturned = 0;

                //send the IOCTL
                try
                {
                    bytesReturned = DriverHelper.SendDriverCommand(ioctl, lpInBuf, InBufSize, ref lpOutBuf, OutBufSize);
                }
                catch (Exception ex)
                {
                    throw new Exception("SendDriverCommand() failed:  " + ex.Message);
                }

                if (bytesReturned == 0)
                    throw new Exception("A 0-length buffer was returned from the driver.");

                //-----------------------------
                //      PROCESS RESULTS
                //-----------------------------
                CwStructures.PROCESS_LISTING_ZWQ processListing = new CwStructures.PROCESS_LISTING_ZWQ();

                //try to marshal the ptr
                try
                {
                    processListing = (CwStructures.PROCESS_LISTING_ZWQ)Marshal.PtrToStructure(lpOutBuf, typeof(CwStructures.PROCESS_LISTING_ZWQ));
                }
                catch (Exception ex)
                {
                    throw new Exception("Failed to marshal lpOutBuf pointer to processListing structure:  " + ex.Message);
                }

                Marshal.FreeHGlobal(lpOutBuf);

                return processListing;                
            }

            /////////////////////////////////////////////////////
            //                                                 //
            // GetUserModeProcessListingToolHelp32()           //
            //                                                 //
            /////////////////////////////////////////////////////
            //Description:  Uses toolhelp32 API to get a list of
            //              processes in user mode.  The code in
            //              this function is very similar to what
            //              is found in MemoryHelper class.
            //
            //Returns:      an ArrayList of PROCESSENTRY32 structs
            /////////////////////////////////////////////////////
            internal static ArrayList GetUserModeProcessListingToolHelp32()
            {
                //take a snapshot of all processes (0x00000002)
                IntPtr hSnapshot = Win32Helper.CreateToolhelp32Snapshot(0x00000002, 0);

                if (hSnapshot == (IntPtr)(-1))
                {
                    AgentScanLog.AppendLine("GetUserModeProcessListingToolHelp32():  Could not create process snapshot!");
                    return null;
                }

                //before we do anything, we have to set the size of the list structure
                Win32Helper.PROCESSENTRY32 procListHead = new Win32Helper.PROCESSENTRY32();
                procListHead.dwSize = (uint)Marshal.SizeOf(typeof(Win32Helper.PROCESSENTRY32));

                //retrieve a pointer to the first process in the list, so we can interate using that
                if (!Win32Helper.Process32First(hSnapshot, ref procListHead))
                {
                    AgentScanLog.AppendLine("GetUserModeProcessListingToolHelp32():  Could not obtain a pointer to the process list!");
                    AgentScanLog.AppendLine("GetUserModeProcessListingToolHelp32():  Error data = " + Win32Helper.GetLastError32());
                    Win32Helper.CloseHandle(hSnapshot);
                    return null;
                }

                ArrayList processes = new ArrayList();

                //search the process list for this process name
                do
                {
                    processes.Add(procListHead);
                }
                while (Win32Helper.Process32Next(hSnapshot, ref procListHead));

                Win32Helper.CloseHandle(hSnapshot); //close the handle to snapshot of the process list

                return processes;
            }

            /////////////////////////////////////////////////////
            //                                                 //
            // GetKernelModeProcessListingPspCidTable()        //
            //                                                 //
            /////////////////////////////////////////////////////
            //Description:  Uses PspCidTable to get a list of
            //              processes in kernel mode.  This is the
            //              basis for our trusted process listing.
            //
            //Returns:      an ArrayList of PIDs
            //References:
            // http://www.nirsoft.net/kernel_struct/vista/HANDLE_TABLE.html
            //      http://uninformed.org/index.cgi?v=3&a=7&p=6
            //      http://helios.miel-labs.com/downloads/process_scan.pdf
            //      http://forum.cheatengine.org/viewtopic.php?t=239616&view=previous&sid=b7123f7024b75849ab825a674c4de9f8
            /////////////////////////////////////////////////////
            internal static uint[] GetKernelModeProcessListingPspCidTable()
            {
                //-----------------------------
                //      SEND COMMAND
                //-----------------------------
                //build the IOCTL to send to driver
                uint ioctl = Win32Helper.GetIOCTL(CwConstants.CW_DRIVER_PROCESS_LISTING_PSP, Win32Helper.METHOD_OUT_DIRECT);

                //build our buffers
                int InBufSize = 0;
                int OutBufSize = Marshal.SizeOf(typeof(uint))*256; //int pids[256];
                IntPtr lpInBuf = IntPtr.Zero;
                IntPtr lpOutBuf = Marshal.AllocHGlobal(OutBufSize);
                int bytesReturned = 0;

                //send the IOCTL
                try
                {
                    bytesReturned = DriverHelper.SendDriverCommand(ioctl, lpInBuf, InBufSize, ref lpOutBuf, OutBufSize);
                }
                catch (Exception ex)
                {
                    throw new Exception("SendDriverCommand() failed:  " + ex.Message);
                }

                if (bytesReturned == 0)
                    throw new Exception("A 0-length buffer was returned from the driver.");

                //-----------------------------
                //      PROCESS RESULTS
                //-----------------------------
                uint[] pids = new uint[256];

                //try to marshal the ptr
                try
                {
                    pids = (uint[])Marshal.PtrToStructure(lpOutBuf, typeof(uint[]));
                }
                catch (Exception ex)
                {
                    throw new Exception("Failed to marshal lpOutBuf pointer to uint[] structure:  " + ex.Message);
                }

                Marshal.FreeHGlobal(lpOutBuf);

                return pids;
            }

            /////////////////////////////////////////////////////
            //                                                 //
            // CrossViewAnalysisWithTrustedProcessList()       //
            //                                                 //
            /////////////////////////////////////////////////////
            //Description:  This cross-view analysis approach uses
            //              a "trusted list" it obtains from PspCidTable
            //              and diffs that across the 3 user mode
            //              methods.
            //
            //Returns:      an array of CWPROCESS_RECORD structs
            /////////////////////////////////////////////////////
            /*internal static CwStructures.CWPROCESS_RECORD[] CrossViewAnalysisWithTrustedProcessList()
            {
                //
                //
                //  TODO:  THIS FUNCTION IS INCOMPLETE!
                //
                //
                //

                //1.  GET TRUSTED PROCESS LIST
                //
                //we will get a listing of processes from kernel mode using the PspCidTable
                uint[] trustedPidList = new uint[256];

                try
                {
                    trustedPidList = HeuristicsUserModeHelper.GetKernelModeProcessListingPspCidTable();
                }
                catch (Exception ex)
                {
                    AgentHeuristicMatches.UserModeMatches.ProcessListing = new CwStructures.CWPROCESS_RECORD[0];
                    AgentScanLog.AppendLine("Failed to get trusted process listing using PspCidTable:  " + ex.Message);
                    return false;
                }

                //build a CWPROCESS_RECORD array for storing hidden processes            
                CwStructures.CWPROCESS_RECORD[] hiddenProcesses = new CwStructures.CWPROCESS_RECORD[trustedPidList.Length];

                //take the "trusted" listing and create a process entry for each process
                //we will shortly enumerate processes from user mode in 3 ways and then fill
                //the boolean field of each process in this structure             
                for (int i = 0; i < trustedPidList.Length; i++)
                {
                    hiddenProcesses[i] = new CwStructures.CWPROCESS_RECORD();
                    hiddenProcesses[i].pid = trustedPidList[i];
                    hiddenProcesses[i].IsInUserModePsapiList = false;
                    hiddenProcesses[i].IsInUserModeToolhelp32List = false;
                    hiddenProcesses[i].IsInUserModeZwqList = false;
                }  
            }*/

            /////////////////////////////////////////////////////
            //                                                 //
            // CrossViewAnalysis()                             //
            //                                                 //
            /////////////////////////////////////////////////////
            //Description:  This cross-view analysis approach creates
            //              four different process listings using
            //              various process enumeration methods and then
            //              diffs all those lists to see if there are
            //              any discrepancies.
            //
            //Returns:      an array of CWPROCESS_RECORD structs
            /////////////////////////////////////////////////////
            internal static CwStructures.CWPROCESS_RECORD[] CrossViewAnalysis()
            {
                //*************************************
                //Cross-view analysis
                //*************************************
                //user mode enumeration methods:
                //  (1)PSAPI
                //  (2)Toolhelp32
                //  (3)ZwQuerySystemInformation
                //
                //kernel mode enumeration methods:
                //  (1)PspCidTable (TODO)
                //  (2)ZwQuerySystemInformation
                //
                //*************************************
                //           GET DATA POINTS
                //*************************************
                //1.  PSAPI
                Process[] PsapiList = Process.GetProcesses();
                //
                //2.  TOOLHELP32
                ArrayList Toolhelp32List = HeuristicsUserModeHelper.GetUserModeProcessListingToolHelp32();
                //3.  ZWQUERYSYSTEMINFORMATION (KERNEL MODE)
                CwStructures.PROCESS_LISTING_ZWQ ZwQueryKmList = new CwStructures.PROCESS_LISTING_ZWQ();
                try
                {
                    ZwQueryKmList = HeuristicsUserModeHelper.GetKernelModeProcessListingZwq();
                }
                catch (Exception ex)
                {
                    AgentScanLog.AppendLine("SCAN:  Failed to get process list using ZwQuerySystemInformation() from kernel mode:  " + ex.Message);
                }
                //4.  ZWQUERYSYSTEMINFORMATION (USER MODE)
                Win32Helper.SYSTEM_PROCESS_INFORMATION[] ZwQueryUmList = new Win32Helper.SYSTEM_PROCESS_INFORMATION[0];
                try
                {
                    ZwQueryUmList = Win32Helper.GetActiveProcessList();
                }
                catch (Exception ex)
                {
                    AgentScanLog.AppendLine("SCAN:  Failed to get process list using ZwQuerySystemInformation from user mode:  " + ex.Message);
                }

                //prepare return structure - initialize our list of processes to the obvious ones
                //in the psapi library (using .NET's Process class)
                ArrayList hiddenProcesses = new ArrayList();
                foreach (Process p in Process.GetProcesses())
                {
                    string pname = "";
                    try
                    {
                        pname = p.MainModule.ModuleName;
                    }
                    catch (Exception) { }

                    AddPidToList(ref hiddenProcesses, (uint)p.Id, GetPsapiParentProcessId(p.ProcessName), pname, "");
                }

                //*************************************
                //  DIFF EACH LIST AGAINST ALL LISTS
                //*************************************
                //
                //1.  PSAPI
                foreach (Process p in PsapiList)
                {
                    if (p.Id == 0)
                        continue;

                    string pname = "";
                    try
                    {
                        pname = p.MainModule.ModuleName;
                    }
                    catch (Exception) { }

                    if (Toolhelp32List != null)
                        if (!HeuristicsUserModeHelper.IsProcessPidInToolhelp32List((uint)p.Id))
                            AddPidToList(ref hiddenProcesses, (uint)p.Id, GetPsapiParentProcessId(p.ProcessName), pname, "Toolhelp32");
                    if (ZwQueryKmList.numProcesses > 0)
                        if (!HeuristicsUserModeHelper.IsProcessPidInZwqKMList((uint)p.Id))
                            AddPidToList(ref hiddenProcesses, (uint)p.Id, GetPsapiParentProcessId(p.ProcessName), pname, "ZwQueryUM");
                    if (ZwQueryUmList.Length > GetPsapiParentProcessId(p.ProcessName))
                        if (!HeuristicsUserModeHelper.IsProcessPidInZwqUMList((uint)p.Id))
                            AddPidToList(ref hiddenProcesses, (uint)p.Id, GetPsapiParentProcessId(p.ProcessName), pname, "ZwQueryKM");
                }
                //2.  Toolhelp32
                if (Toolhelp32List != null)
                {
                    foreach (Win32Helper.PROCESSENTRY32 process in (Win32Helper.PROCESSENTRY32[])Toolhelp32List.ToArray(typeof(Win32Helper.PROCESSENTRY32)))
                    {
                        if (process.th32ProcessID == 0)
                            continue;

                        if (PsapiList != null)
                            if (!HeuristicsUserModeHelper.IsProcessPidInPsapiList(process.th32ProcessID))
                                AddPidToList(ref hiddenProcesses, process.th32ProcessID, process.th32ParentProcessID, process.szExeFile, "Psapi");
                        if (ZwQueryKmList.numProcesses > 0)
                            if (!HeuristicsUserModeHelper.IsProcessPidInZwqKMList(process.th32ProcessID))
                                AddPidToList(ref hiddenProcesses, process.th32ProcessID, process.th32ParentProcessID, process.szExeFile, "ZwQueryUM");
                        if (ZwQueryUmList.Length > 0)
                            if (!HeuristicsUserModeHelper.IsProcessPidInZwqUMList(process.th32ProcessID))
                                AddPidToList(ref hiddenProcesses, process.th32ProcessID, process.th32ParentProcessID, process.szExeFile, "ZwQueryKM");
                    }
                }
                //3.  ZwQuerySystemInformation USER MODE
                if (ZwQueryUmList != null)
                {
                    foreach (Win32Helper.SYSTEM_PROCESS_INFORMATION process in ZwQueryUmList)
                    {
                        if (process.UniqueProcessId == 0)
                            continue;

                        if (PsapiList != null)
                            if (!HeuristicsUserModeHelper.IsProcessPidInPsapiList(process.UniqueProcessId))
                                AddPidToList(ref hiddenProcesses, process.UniqueProcessId, process.InheritedFromUniqueProcessId, process.ImageName.Buffer, "Psapi");
                        if (Toolhelp32List != null)
                            if (!HeuristicsUserModeHelper.IsProcessPidInToolhelp32List(process.UniqueProcessId))
                                AddPidToList(ref hiddenProcesses, process.UniqueProcessId, process.InheritedFromUniqueProcessId, process.ImageName.Buffer, "Toolhelp32");
                        if (ZwQueryKmList.numProcesses > 0)
                            if (!HeuristicsUserModeHelper.IsProcessPidInZwqKMList(process.UniqueProcessId))
                                AddPidToList(ref hiddenProcesses, process.UniqueProcessId, process.InheritedFromUniqueProcessId, process.ImageName.Buffer, "ZwQueryKM");
                    }
                }
                //4.  ZwQuerySystemInformation KERNEL MODE
                if (ZwQueryKmList.numProcesses > 0)
                {
                    for(int i=0;i<ZwQueryKmList.numProcesses;i++)
                    {
                        CwStructures.CW_PROCESS_ENTRY process = ZwQueryKmList.ProcessList[i];

                        if (process.UniqueProcessId == 0)
                            continue;

                        if (PsapiList != null)
                            if (!HeuristicsUserModeHelper.IsProcessPidInPsapiList(process.UniqueProcessId))
                                AddPidToList(ref hiddenProcesses, process.UniqueProcessId, process.InheritedFromUniqueProcessId, process.ImageName, "Psapi");
                        if (Toolhelp32List != null)
                            if (!HeuristicsUserModeHelper.IsProcessPidInToolhelp32List(process.UniqueProcessId))
                                AddPidToList(ref hiddenProcesses, process.UniqueProcessId, process.InheritedFromUniqueProcessId, process.ImageName, "Toolhelp32");
                        if (ZwQueryUmList != null && ZwQueryUmList.Length > 0)
                            if (!HeuristicsUserModeHelper.IsProcessPidInZwqUMList(process.UniqueProcessId))
                                AddPidToList(ref hiddenProcesses, process.UniqueProcessId, process.InheritedFromUniqueProcessId, process.ImageName, "ZwQueryUM");
                    }
                }

                return (CwStructures.CWPROCESS_RECORD[])hiddenProcesses.ToArray(typeof(CwStructures.CWPROCESS_RECORD));
            }

            /////////////////////////////////////////////////////
            //                                                 //
            // GetPsapiParentProcessId()                       //
            //                                                 //
            /////////////////////////////////////////////////////
            //Description:  Quick way to find parent pid.
            //
            //Returns:      void
            /////////////////////////////////////////////////////
            internal static uint GetPsapiParentProcessId(string pname)
            {
                try
                {
                    PerformanceCounter pc = new PerformanceCounter("Process", "Creating Process Id", pname);
                    return (uint)Process.GetProcessById((int)pc.RawValue).Id;
                }
                catch (Exception)
                {
                    return 0;
                }
            }

            /////////////////////////////////////////////////////
            //                                                 //
            // AddPidToList()                                  //
            //                                                 //
            /////////////////////////////////////////////////////
            //Description:  Adds the given PID to the running list
            //              of hidden processes, if that PID doesnt
            //              already exist in the list.
            //
            //Returns:      void
            /////////////////////////////////////////////////////
            internal static void AddPidToList(ref ArrayList list, uint pid, uint ppid, string processname, string notFoundInList)
            {
                foreach (CwStructures.CWPROCESS_RECORD rec in (CwStructures.CWPROCESS_RECORD[])list.ToArray(typeof(CwStructures.CWPROCESS_RECORD)))
                {
                    if (rec.pid == pid)
                        return;
                }

                CwStructures.CWPROCESS_RECORD newRec = new CwStructures.CWPROCESS_RECORD();
                newRec.pid = pid;
                if (notFoundInList != "")
                    newRec.NotInList[newRec.NotInList.Length] = notFoundInList;
                newRec.ppid = ppid;
                newRec.name = processname;
                newRec.modulePath = processname;

                list.Add(newRec);
            }

            /////////////////////////////////////////////////////
            //                                                 //
            // IsProcessPidInPsapiList()                       //
            //                                                 //
            /////////////////////////////////////////////////////
            //Description:  Determines whether or not the given pid
            //              exists in the process list obtained from
            //              the psapi win32 api.
            //
            //Returns:      true if it was found in the list
            /////////////////////////////////////////////////////
            internal static bool IsProcessPidInPsapiList(uint pid)
            {
                //skip the system process and any null process entries in the array
                if (pid == 0)
                    return true;
                foreach (Process p in Process.GetProcesses())
                    if (p.Id == pid)
                        return true;
                return false;
            }

            /////////////////////////////////////////////////////
            //                                                 //
            // IsProcessPidInToolhelp32List()                  //
            //                                                 //
            /////////////////////////////////////////////////////
            //Description:  Determines whether or not the given pid
            //              exists in the process list obtained from
            //              the toolhelp32 api.
            //
            //Returns:      true if it was found in the list
            /////////////////////////////////////////////////////
            internal static bool IsProcessPidInToolhelp32List(uint pid)
            {
                ArrayList umProcListToolhelp32 = HeuristicsUserModeHelper.GetUserModeProcessListingToolHelp32();

                if (umProcListToolhelp32 != null)
                {
                    Win32Helper.PROCESSENTRY32[] procs = (Win32Helper.PROCESSENTRY32[])umProcListToolhelp32.ToArray(typeof(Win32Helper.PROCESSENTRY32));

                    foreach (Win32Helper.PROCESSENTRY32 process in procs)
                        if (pid == process.th32ProcessID)
                            return true;
                }
                else
                {
                    AgentScanLog.AppendLine("SCAN:  Failed to get process list using Toolhelp32 library.");
                    return true;
                }

                return false;
            }

            /////////////////////////////////////////////////////
            //                                                 //
            // IsProcessPidInZwqUMList()                       //
            //                                                 //
            /////////////////////////////////////////////////////
            //Description:  Determines whether or not the given pid
            //              exists in the process list obtained from
            //              the ZwQuerySystemInformation() in user mode.
            //
            //Returns:      true if it was found in the list
            /////////////////////////////////////////////////////
            internal static bool IsProcessPidInZwqUMList(uint pid)
            {
                Win32Helper.SYSTEM_PROCESS_INFORMATION[] umProcListZwq = new Win32Helper.SYSTEM_PROCESS_INFORMATION[0];

                try
                {
                    umProcListZwq = Win32Helper.GetActiveProcessList();
                }
                catch (Exception ex)
                {
                    AgentScanLog.AppendLine("SCAN:  Failed to get process list using ZwQuerySystemInformation from user mode:  " + ex.Message);
                    return true;
                }

                foreach (Win32Helper.SYSTEM_PROCESS_INFORMATION process in umProcListZwq)
                    if (pid == process.UniqueProcessId)
                        return true;
                return false;
            }

            /////////////////////////////////////////////////////
            //                                                 //
            // IsProcessPidInZwqKMList()                       //
            //                                                 //
            /////////////////////////////////////////////////////
            //Description:  Determines whether or not the given pid
            //              exists in the process list obtained from
            //              the ZwQuerySystemInformation() in kernel mode.
            //
            //Returns:      true if it was found in the list
            /////////////////////////////////////////////////////
            internal static bool IsProcessPidInZwqKMList(uint pid)
            {
                CwStructures.PROCESS_LISTING_ZWQ ZwQueryKmList = new CwStructures.PROCESS_LISTING_ZWQ();
                try
                {
                    ZwQueryKmList = HeuristicsUserModeHelper.GetKernelModeProcessListingZwq();
                }
                catch (Exception ex)
                {
                    AgentScanLog.AppendLine("SCAN:  Failed to get process list using ZwQuerySystemInformation() from kernel mode:  " + ex.Message);
                }

                for (int i = 0; i < ZwQueryKmList.numProcesses; i++)
                {
                    CwStructures.CW_PROCESS_ENTRY process = ZwQueryKmList.ProcessList[i];
                    if (pid == process.UniqueProcessId)
                        return true;
                }
                return false;
            }
        }
    }
}
