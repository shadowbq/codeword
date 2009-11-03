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
        public class MemoryHelper
        {
            internal StringBuilder MemoryHelperLog;

            public MemoryHelper()
            {
                MemoryHelperLog = new StringBuilder();
            }
            ~MemoryHelper()
            {

            }

            /////////////////////////////////////////////////////
            //                                                 //
            // ScanForMemorySignatures()                       //
            //                                                 //
            /////////////////////////////////////////////////////
            //Description:  this function searches the heap space of
            //              process(es) of interest for supplied keyword(s)
            //Returns:      true if keyword found
            /////////////////////////////////////////////////////
            internal unsafe void ScanForMemorySignatures(CwXML.RegistrySignatureMatch[] RegistryFindings, CwXML.MemorySignature[] MemorySignatures, ref CwXML.MemorySignatureMatch[] matches, bool SearchCmdline, bool SearchHeap, bool searchModuleList, bool searchRegistryFindings)
            {
                //we will use this regex to validate whether a given keyword is a valid filename/path or not
                //this is used when we are walking the module list
                Regex filePathValidator = new Regex(@"^(([a-zA-Z]\:)|(\\))(\\{1}|((\\{1})[^\\]([^/:*?<>""|]*))+)$");
                ArrayList Findings=new ArrayList();

                //
                //loop through each memory signature and search 
                //
                foreach (CwXML.MemorySignature m in MemorySignatures)
                {
                    //is this process name for this signature in the list of active processes?
                    string ProcessName = m.ProcessName;
                    ArrayList ProcessInfo = GetActiveProcessInfo(ProcessName);
                    string action = m.Action;

                    //if not, skip it.
                    if (ProcessInfo == null)
                    {
                        MemoryHelperLog.AppendLine("SCAN:  The target process " + ProcessName + " is not running, skipping this signature...");
                        continue;
                    }
                    if (ProcessInfo.Count == 0)
                    {
                        MemoryHelperLog.AppendLine("SCAN:  The target process " + ProcessName + " did not return a full data set, skipping this signature...");
                        continue;
                    }

                    //* PROCESS OF INTEREST IS IN THE LIST OF RUNNING PROCESSES... *//
                    uint pid = (uint)ProcessInfo[0];
                    uint ppid = (uint)ProcessInfo[1];
                    uint threadCount = (uint)ProcessInfo[2];

                    //were any keywords given to search this process heap/cmdline/modlist?
                    string[] Keywords = m.Keywords.Split(new char[] { ',' }, StringSplitOptions.RemoveEmptyEntries);

                    //if no keywords were given, then we can conclude our task was only to identify that
                    //this process name was running on the system.  if that's the case, return a hit.
                    if (Keywords.Length == 0)
                    {
                        MemoryHelperLog.AppendLine("SCAN:  Match found for process name '" + ProcessName + "'!");
                        CwXML.MemorySignatureMatch matchRecord = new CwXML.MemorySignatureMatch();
                        matchRecord.MatchingBlock = ProcessName;
                        matchRecord.ProcessId = pid;
                        matchRecord.ParentProcessId = ppid;
                        matchRecord.ProcessName = ProcessName;
                        matchRecord.Keywords = "";
                        matchRecord.ChildThreadIds = GetChildThreadIds((uint)pid);
                        matchRecord.Action = action;

                        //note:  we are adding the match this way to be consistent with how
                        //we have to add them in SearchProcessCmdLine() and other funcs
                        ArrayList tmpMatches = new ArrayList();
                        tmpMatches.Add(matchRecord);

                        Findings.Add(tmpMatches);
                        continue;
                    }

                    //otherwise, we need to search either the process heap, cmd line, or module list
                    //for the given keywords in this memory signature.
                    ArrayList KeywordList = new ArrayList();
                    KeywordList.AddRange(Keywords);

                    //if the user wants to use registry findings in our keyword scan, add them now
                    if (searchRegistryFindings)
                        foreach (CwXML.RegistrySignatureMatch regMatch in RegistryFindings)
                            if (regMatch.RegistryValueData != null)
                                if (regMatch.RegistryValueData.Length < 300)
                                    KeywordList.Add(regMatch.RegistryValueData);

                    //*********************************
                    //      SCAN OPTIONS
                    //*********************************
                    //perform the following per-process scans, depending on user options:
                    // 1) use WMI to search the Cmdline for this process for keywords/indicators
                    // 2) use Win32 API to search the module list for keywords/indicators
                    // 3) use Win32 API to search the heap space for keywords/indicators

                    MemoryHelperLog.AppendLine("SCAN:  Searching target process " + ProcessName + " (PID=" + pid.ToString() + ")...");
                    MemoryHelperLog.AppendLine("SCAN:  Using keyword search list (" + KeywordList.Count + "):  '" + string.Join(",", ((string[])KeywordList.ToArray(typeof(string)))) + "'");

                    //*********************************
                    //      PERFORM SCANS
                    //*********************************
                    // 1) use WMI to search the Cmdline for this process for keywords/indicators
                    if (SearchCmdline)
                    {
                        ArrayList cmdlineFindings = new ArrayList();

                        MemoryHelperLog.Append("SCAN:  Searching command line ...");
                        if (!SearchProcessCmdline(pid, ppid, action, KeywordList, ref cmdlineFindings))
                            MemoryHelperLog.Append("nothing.");
                        else
                        {
                            MemoryHelperLog.Append(cmdlineFindings.Count + " matches!");
                            Findings.Add(cmdlineFindings);
                        }
                        MemoryHelperLog.AppendLine();
                    }
                    // 2) use Win32 API to search the module list for keywords/indicators
                    if (searchModuleList)
                    {
                        ArrayList modListFindings = new ArrayList();

                        MemoryHelperLog.Append("SCAN:  Searching loaded module list ...");
                        if (!SearchProcessLoadedModuleList(pid, ppid, ProcessName, action, KeywordList, ref modListFindings))
                            MemoryHelperLog.Append("nothing.");
                        else
                        {
                            MemoryHelperLog.Append(modListFindings.Count + " matches!");
                            Findings.Add(modListFindings);
                        }
                        MemoryHelperLog.AppendLine();
                    }
                    // 3) use Win32 API to search the heap space for keywords/indicators
                    if (SearchHeap)
                    {
                        ArrayList heapFindings = new ArrayList();

                        MemoryHelperLog.AppendLine("SCAN:  Searching heap space ...");
                        if (!SearchProcessHeap((uint)pid, ppid, ProcessName, action, KeywordList, ref heapFindings))
                            MemoryHelperLog.Append("SCAN:  Nothing.");
                        else
                        {
                            MemoryHelperLog.AppendLine("SCAN:  "+heapFindings.Count + " matches!");
                            Findings.Add(heapFindings);
                        }
                        MemoryHelperLog.AppendLine();
                    }
                }

                MemoryHelperLog.AppendLine("SCAN:  Done scanning processes, collating results...");

                //first find out how many findings we had
                if (Findings.Count > 0)
                {
                    MemoryHelperLog.AppendLine("SCAN:  There are " + Findings.Count + " memory finding set matches.");

                    int retBufSize = 0, i = 0;
                    foreach (ArrayList ar in Findings)
                        foreach (CwXML.MemorySignatureMatch m in ar)
                            retBufSize++;

                    matches = new CwXML.MemorySignatureMatch[retBufSize];

                    //loop through all matches and add them to findings
                    foreach (ArrayList ar in Findings)
                    {
                        foreach (CwXML.MemorySignatureMatch m in ar)
                        {
                            matches[i] = new CwXML.MemorySignatureMatch();
                            matches[i] = m;
                            i++;
                        }
                    }
                }
                else
                    matches = new CwXML.MemorySignatureMatch[0];
            }

            /////////////////////////////////////////////////////
            //                                                 //
            // CleanMemoryFindings()                           //
            //                                                 //
            /////////////////////////////////////////////////////
            //Description:  kills/suspends offending processes
            //Returns:      none
            /////////////////////////////////////////////////////
            internal void CleanMemoryFindings(ref CwXML.MemorySignatureMatch[] MemorySignatureMatches)
            {
                //the line below is added for compatibility when calling this function
                //over remote channels from the admin console
                if (MemoryHelperLog == null)
                    MemoryHelperLog = new StringBuilder();

                int count = 0;            

                //Possible actions:
                /*
                Terminate process if exists
                Terminate process if keyword found
                Suspend containing thread if keyword found
                */
                foreach (CwXML.MemorySignatureMatch match in MemorySignatureMatches)
                {
                    string action = match.Action;
                    IntPtr hProcess = Win32Helper.OpenProcess(Win32Helper.PROCESS_TERMINATE, false, match.ProcessId);

                    //try to obtain a handle to the process to kill/suspend
                    if(hProcess == IntPtr.Zero)
                    {
                        MemoryHelperLog.AppendLine("CLEAN:  Failed to open process PID " + match.ProcessId.ToString() + ":  " + Win32Helper.GetLastError32());
                        MemorySignatureMatches[count].ActionSuccessful = false;
                        count++;
                        continue;
                    }

                    // * TERMINATE PROCESS *
                    if (action == "Terminate process if exists" || action == "Terminate process if keyword found")
                    {
                        //note:  experience has shown you cant trust the return value of ZwTerminateProcess().
                        //dont even bother to validate it, assume success (we do have elevated privs!)
                        Win32Helper.ZwTerminateProcess(hProcess, Win32Helper.STATUS_SUCCESS);
                        Win32Helper.CloseHandle(hProcess);
                        MemorySignatureMatches[count].ActionSuccessful = true;
                    }
                    //* SUSPEND CONTAINING THREAD *
                    else if (action == "Suspend containing thread if keyword found")
                    {
                        //
                        //TODO
                        //
                        MemoryHelperLog.AppendLine("CLEAN:  Warning:  Suspending thread not implemented.");
                        MemorySignatureMatches[count].ActionSuccessful = false;
                    }

                    count++;
                }

                return;
            }

            /////////////////////////////////////////////////////
            //                                                 //
            // PrintMemoryFindings()                           //
            //                                                 //
            /////////////////////////////////////////////////////
            //Description:  outputs memory findings
            //Returns:      none
            /////////////////////////////////////////////////////
            internal void PrintMemoryFindings(CwXML.MemorySignatureMatch[] MemorySignatureMatches, ref StringBuilder output)
            {
                output.AppendLine("");
                output.AppendLine("REPORT:  ******************************");
                output.AppendLine("REPORT:  Memory Findings");
                output.AppendLine("REPORT:  ******************************");
                output.AppendLine("");
                output.AppendLine("Process\t\tPID (PPID)\t\tKeywords\t\tMatching Block\t\tChild ThreadIds\t\tMalicious Module(s)\t\tSuspicious Heap Blockp\t\tAction\t\tAction Successful\t");

                if (MemorySignatureMatches.Length == 0)
                {
                    output.AppendLine("REPORT:  No memory signatures were found.");
                }
                else
                {
                    //loop through all match records
                    foreach (CwXML.MemorySignatureMatch match in MemorySignatureMatches)
                    {
                        output.AppendLine("");
                        output.Append(match.ProcessName + "\t\t");
                        output.Append(match.ProcessId.ToString() + "("+match.ParentProcessId.ToString()+"\t\t");
                        output.Append(match.Keywords + "\t\t");
                        output.Append(match.MatchingBlock + "\t\t");
                        output.Append(match.ChildThreadIds + "\t\t");
                        output.Append(match.MaliciousLoadedModuleName + ","+match.MaliciousLoadedModuleSize+" bytes,"+match.MaliciousLoadedModuleBaseAddr+" base addr\t\t");
                        output.Append(match.SuspiciousHeapBlockRange + "\t\t");
                        output.Append(match.Action + "\t\t");
                        output.Append(match.ActionSuccessful.ToString() + "\t\t");
                    }
                }

                output.AppendLine("");
                output.AppendLine("REPORT:  ******************************");
                output.AppendLine("");
            }

            /////////////////////////////////////////////////////
            //                                                 //
            // GetActiveProcessInfo()                          //
            //                                                 //
            /////////////////////////////////////////////////////
            //Description:  searches the active process list for
            //              a process with the given name and then
            //              returns information about it.
            //Returns:      ArrayList (pid,ppid,threadcount)
            /////////////////////////////////////////////////////
            internal ArrayList GetActiveProcessInfo(string NameOfProcessToFind)
            {
                ArrayList returnArray = null;

                //take a snapshot of all processes (0x00000002)
                IntPtr hSnapshot = Win32Helper.CreateToolhelp32Snapshot(0x00000002, 0);

                if (hSnapshot == (IntPtr)(-1))
                {
                    MemoryHelperLog.AppendLine("ERROR:  Could not create process snapshot!");
                    return null;
                }

                //before we do anything, we have to set the size of the list structure
                Win32Helper.PROCESSENTRY32 procListHead = new Win32Helper.PROCESSENTRY32();
                procListHead.dwSize = (uint)Marshal.SizeOf(typeof(Win32Helper.PROCESSENTRY32));

                //retrieve a pointer to the first process in the list, so we can interate using that
                if (!Win32Helper.Process32First(hSnapshot, ref procListHead))
                {
                    MemoryHelperLog.AppendLine("ERROR:  Could not obtain a pointer to the process list!");
                    MemoryHelperLog.AppendLine("ERROR:  Error data = " + Win32Helper.GetLastError32());
                    Win32Helper.CloseHandle(hSnapshot);
                    return null;
                }

                MemoryHelperLog.AppendLine("SCAN:  Process listing:  ");

                //search the process list for this process name
                do
                {
                    string processName = procListHead.szExeFile.ToString();
                    
                    //log that we looked at this process name
                    MemoryHelperLog.Append(processName + ",");

                    if (processName.ToLower() == NameOfProcessToFind.ToLower())
                    {
                        uint pid = procListHead.th32ProcessID;
                        uint ppid = procListHead.th32ParentProcessID;
                        uint threadCount = procListHead.cntThreads;

                        returnArray = new ArrayList();
                        returnArray.Add(pid);
                        returnArray.Add(ppid);
                        returnArray.Add(threadCount);
                        break;
                    }

                }
                while (Win32Helper.Process32Next(hSnapshot, ref procListHead));

                MemoryHelperLog.AppendLine("");
                Win32Helper.CloseHandle(hSnapshot); //close the handle to snapshot of the process list

                return returnArray;
            }

            /////////////////////////////////////////////////////
            //                                                 //
            // SearchProcessCmdline()                          //
            //                                                 //
            /////////////////////////////////////////////////////
            //Description:  scans the command line argument for the
            //              given pid, searching the string for
            //              any keyword in the keywords list
            //Returns:      true if match found
            /////////////////////////////////////////////////////
            internal bool SearchProcessCmdline(uint pid, uint ppid, string action, ArrayList keywords, ref ArrayList matches)
            {
                //use WMI query
                SelectQuery sQuery = new SelectQuery("SELECT * FROM Win32_Process WHERE ProcessId=" + pid);
                ManagementObjectSearcher processSearcher = new ManagementObjectSearcher(sQuery);
                string cmdLine = "", processName="";

                //there will only be one result, but .net makes you loop over it..
                foreach (ManagementObject process in processSearcher.Get())
                {
                    cmdLine = process["CommandLine"].ToString();
                    processName = process["Name"].ToString();
                }

                //dont continue if there was no command line
                if (cmdLine == "")
                {
                    return false;
                }
                else
                {
                    //scan keyword list and see if this process's CMDLINE contains the keyword
                    foreach (string kw in keywords)
                    {
                        if (cmdLine.Contains(kw))
                        {
                            CwXML.MemorySignatureMatch matchRecord = new CwXML.MemorySignatureMatch();
                            matchRecord.MatchingBlock = cmdLine;
                            matchRecord.ProcessId = pid;
                            matchRecord.ParentProcessId=ppid;
                            matchRecord.ProcessName = processName;
                            matchRecord.Keywords = string.Join(",", ((string[])keywords.ToArray(typeof(string))));
                            matchRecord.ChildThreadIds = GetChildThreadIds((uint)pid);
                            matchRecord.Action = action;
                            matches.Add(matchRecord);
                        }
                    }
                }

                if (matches.Count > 0)
                    return true;
                return false;
            }

            /////////////////////////////////////////////////////
            //                                                 //
            // SearchProcessLoadedModuleList()                 //
            //                                                 //
            /////////////////////////////////////////////////////
            //Description:  scans all module entries for the given
            //              process using unamanged APIs.  simply
            //              checks the module's name against the
            //              known list of module names and also
            //              the module's command line startup.
            //Returns:      true if match found
            /////////////////////////////////////////////////////
            internal bool SearchProcessLoadedModuleList(uint pid, uint ppid, string procName, string action, ArrayList keywords, ref ArrayList matches)
            {
                //take a snapshot of the module list for this process
                IntPtr hSnapshotModules = Win32Helper.CreateToolhelp32Snapshot(0x00000008, (uint)pid);

                if (hSnapshotModules == (IntPtr)(-1))
                {
                    MemoryHelperLog.AppendLine("ERROR:  Could not create module snapshot, skipping this process (" + pid + ")...");
                    MemoryHelperLog.AppendLine("ERROR:  Error data = " + Win32Helper.GetLastError32());
                    return false;
                }

                //get a pointer to the module list for this process
                Win32Helper.MODULEENTRY32 procModuleList = new Win32Helper.MODULEENTRY32();
                procModuleList.dwSize = new IntPtr(Marshal.SizeOf(typeof(Win32Helper.MODULEENTRY32)));

                if (!Win32Helper.Module32First(hSnapshotModules, ref procModuleList))
                {
                    MemoryHelperLog.AppendLine("ERROR:  Could not obtain a pointer to the process module list, skipping this process (" + pid + ")...");
                    MemoryHelperLog.AppendLine("ERROR:  Error data = " + Win32Helper.GetLastError32());
                    return false;
                }

                //now loop over module list for this process
                do
                {
                    string moduleName = procModuleList.szModule.ToString();
                    string moduleBaseAddr = procModuleList.modBaseAddr.ToString();
                    string moduleEndAddr = (procModuleList.modBaseAddr.ToInt32() + procModuleList.modBaseSize).ToString();
                    string moduleSize = procModuleList.modBaseSize.ToString();
                    string modulePath = procModuleList.szExePath.ToString();

                    //loop through all keywords and search for this loaded module name in them
                    foreach (string kw in keywords)
                    {
                        if (moduleName.Contains(kw))
                        {
                            CwXML.MemorySignatureMatch matchRecord = new CwXML.MemorySignatureMatch();
                            matchRecord.Action = action;
                            matchRecord.MatchingBlock = moduleName;
                            matchRecord.ProcessId = pid;
                            matchRecord.ParentProcessId=ppid;
                            matchRecord.ProcessName = procName;
                            matchRecord.Keywords = string.Join(",", ((string[])keywords.ToArray(typeof(string))));
                            matchRecord.ChildThreadIds = GetChildThreadIds((uint)pid);
                            matchRecord.MaliciousLoadedModuleName = moduleName;
                            matchRecord.MaliciousLoadedModuleBaseAddr = moduleBaseAddr;
                            matchRecord.MaliciousLoadedModuleEndAddr = moduleEndAddr;
                            matchRecord.MaliciousLoadedModulePath = modulePath;
                            matchRecord.MaliciousLoadedModuleSize = moduleSize;
                            matches.Add(matchRecord);
                        }
                    }
                }
                while (Win32Helper.Module32Next(hSnapshotModules, ref procModuleList));

                Win32Helper.CloseHandle(hSnapshotModules); //close handle to snapshot of heap list

                if (matches.Count > 0)
                    return true;
                return false;
            }

            /////////////////////////////////////////////////////
            //                                                 //
            // SearchProcessHeap()                             //
            //                                                 //
            /////////////////////////////////////////////////////
            //Description:  scans all heap entries for the given
            //              process using unamanged APIs.  tries
            //              to Toolhelp32ReadProcessMemory() on
            //              each heap range and then search those
            //              bytes for keywords.
            //              If a memory page is protected, use
            //              VirtualProtectEx() to unprotect it.
            //Returns:      void
            /////////////////////////////////////////////////////
            internal bool SearchProcessHeap(uint pid, uint ppid, string procName, string action, ArrayList keywords, ref ArrayList matches)
            {
                //----------------------------------------
                //          CREATE HEAP SNAPSHOT
                //----------------------------------------
                IntPtr hSnapshotHeap = Win32Helper.CreateToolhelp32Snapshot(0x00000001, pid);

                if (hSnapshotHeap == (IntPtr)(-1))
                {
                    MemoryHelperLog.AppendLine("ERROR:  Could not create heap snapshot, skipping this process (" + pid + ")...");
                    MemoryHelperLog.AppendLine("ERROR:  Error data = " + Win32Helper.GetLastError32());
                    return false;
                }

                //----------------------------------------
                //       GET PTR TO FIRST HEAP BLOCK
                //----------------------------------------
                Win32Helper.HEAPLIST32 procHeapList = new Win32Helper.HEAPLIST32();
                procHeapList.dwSize = new IntPtr(Marshal.SizeOf(typeof(Win32Helper.HEAPLIST32)));

                if (!Win32Helper.Heap32ListFirst(hSnapshotHeap, ref procHeapList))
                {
                    MemoryHelperLog.AppendLine("ERROR:  Could not obtain a pointer to the process heap, skipping this process (" + pid + ")...");
                    MemoryHelperLog.AppendLine("ERROR:  Error data = " + Win32Helper.GetLastError32());
                    return false;
                }

                //----------------------------------------
                //          ITERATE OVER HEAP LIST
                //----------------------------------------
                do
                {
                    //----------------------------------------
                    //GET PTR TO FIRST LIST OF BLOCKS FOR THIS HEAP
                    //----------------------------------------
                    //get a pointer to the first block in the heap, so we can iterate over all blocks
                    Win32Helper.HEAPENTRY32 heapBlock = new Win32Helper.HEAPENTRY32();
                    heapBlock.dwSize = (uint)Marshal.SizeOf(typeof(Win32Helper.HEAPENTRY32));

                    //if we fail to get the first heap block, must skip this process..
                    if (!Win32Helper.Heap32First(ref heapBlock, procHeapList.th32ProcessID, procHeapList.th32HeapID))
                    {
                        MemoryHelperLog.AppendLine("ERROR:  Could not obtain a pointer to the first heap block, skipping this process (" + pid + ")...");
                        MemoryHelperLog.AppendLine("ERROR:  Error data = " + Win32Helper.GetLastError32());
                        break;
                    }

                    //----------------------------------------
                    //      ITERATE OVER HEAP BLOCK LIST
                    //----------------------------------------
                    do
                    {
                        MemoryHelperLog.AppendLine("SCAN:  Searching a " + heapBlock.dwBlockSize.ToString() + "-byte heap in " + pid + " from 0x" + heapBlock.dwAddress.ToString("x") + " - 0x" + (heapBlock.dwAddress + heapBlock.dwBlockSize).ToString("x"));

                        //YAY!!  WE finally have a ptr to the heap data...whew
                        IntPtr pBuffer = Marshal.AllocHGlobal((int)heapBlock.dwBlockSize);
                        IntPtr pBytesRead = Marshal.AllocHGlobal(4);

                        //
                        //----------------------------------------
                        //          UNPROTECT THE MEMORY 
                        //----------------------------------------
                        //
                        uint oldProtection = 0; //remember the old protection so we can restore it
                        bool needToRevertPageProtection = UnprotectMemoryRange(pid, (IntPtr)heapBlock.dwAddress, heapBlock.dwSize,ref oldProtection);

                        //----------------------------------------
                        //          READ THE HEAP BLOCK
                        //----------------------------------------
                        //but to actually obtain the data to search through it,
                        //we have to call Toolhelp32ReadProcessMemory() - if it fails, go to next heap
                        if (!Win32Helper.Toolhelp32ReadProcessMemory(pid, (IntPtr)heapBlock.dwAddress, pBuffer, heapBlock.dwBlockSize, pBytesRead))
                        {
                            MemoryHelperLog.AppendLine("ERROR:  Failed to read from the requested address range:  " + Win32Helper.GetLastError32() + ".  This may indicate this is an inaccessible private heap.");

                            //according to MSDN, if the error returned is ERROR_PARTIAL_COPY, this means the process is 64-bit
                            //however, i've seen this error occur on 32-bit OS running in a VM on a 64-bit host machine.
                            if (Win32Helper.GetLastError() == Win32Helper.ERROR_PARTIAL_COPY)
                                MemoryHelperLog.AppendLine("NOTE:  This error often indicates the process being searched is a 64-bit process, and we are running as a 32-bit process.");

                            //reinitialize size of this block in preparation for Heap32Next()
                            heapBlock.dwSize = (uint)Marshal.SizeOf(typeof(Win32Helper.HEAPENTRY32));

                            continue;
                        }

                        //----------------------------------------
                        //          RE-PROTECT THE MEMORY 
                        //----------------------------------------
                        //
                        if (needToRevertPageProtection)
                           ProtectMemoryRange(pid, (IntPtr)heapBlock.dwAddress, heapBlock.dwSize, oldProtection);

                        //----------------------------------------
                        //     COPY BUFFER AND DECODE
                        //----------------------------------------
                        byte[] buffer = new byte[unchecked((int)heapBlock.dwBlockSize)];
                        Marshal.Copy(pBuffer, buffer, 0, (int)heapBlock.dwBlockSize);
                        Marshal.FreeHGlobal(pBuffer);
                        Marshal.FreeHGlobal(pBytesRead);

                        StringBuilder ASCIIData = new StringBuilder();
                        StringBuilder UnicodeData = new StringBuilder();
                        string haystackASCII = "";
                        string haystackUnicode = "";

                        //ascii
                        try
                        {
                            char[] chars = new char[unchecked(Encoding.ASCII.GetCharCount(buffer, 0, buffer.Length))];
                            Encoding.ASCII.GetChars(buffer, 0, buffer.Length, chars, 0);
                            ASCIIData.Append(chars);
                            haystackASCII = ASCIIData.ToString();
                            ASCIIData.Remove(0, ASCIIData.Length);
                        }
                        catch (Exception) { }//swallow

                        //unicode
                        try
                        {
                            char[] chars = new char[unchecked(Encoding.Unicode.GetCharCount(buffer, 0, buffer.Length))];
                            Encoding.Unicode.GetChars(buffer, 0, buffer.Length, chars, 0);
                            UnicodeData.Append(chars);
                            haystackUnicode = UnicodeData.ToString();
                            UnicodeData.Remove(0, UnicodeData.Length);
                        }
                        catch (Exception) { }//swallow

                        //bail on this heap block if both decodings failed
                        if (haystackASCII == "" && haystackUnicode == "")
                        {
                            //reinitialize size of this block in preparation for Heap32Next()
                            heapBlock.dwSize = (uint)Marshal.SizeOf(typeof(Win32Helper.HEAPENTRY32));
                            continue;
                        }

                        //----------------------------------------
                        //     SEARCH LOCAL COPY OF HEAP BLOCK
                        //----------------------------------------
                        //loop through all keywords and search for it in heap data
                        foreach (string kw in keywords)
                        {
                            string containingBlob = "";

                            //ASCII
                            if (haystackASCII.Contains(kw))
                            {
                                int loc = haystackASCII.IndexOf(kw);
                                int start = loc - 25; //start 25 characters before match
                                int end = loc + 25; //end 25 characters after match

                                //make sure we are within bounds of the string
                                if (start < 0)
                                    start = 0;
                                if (end > haystackASCII.Length)
                                    end = haystackASCII.Length;

                                containingBlob = haystackASCII.Substring(start, end - start);
                            }
                            //Unicode
                            else if (haystackUnicode.Contains(kw))
                            {
                                int loc = haystackUnicode.IndexOf(kw);
                                int start = loc - 25; //start 25 characters before match
                                int end = loc + 25; //end 25 characters after match

                                //make sure we are within bounds of the string
                                if (start < 0)
                                    start = 0;
                                if (end > haystackUnicode.Length)
                                    end = haystackUnicode.Length;

                                containingBlob = haystackUnicode.Substring(start, end - start);
                            }

                            //continue if no matches.
                            if (containingBlob == "")
                                continue;

                            CwXML.MemorySignatureMatch matchRecord = new CwXML.MemorySignatureMatch();
                            matchRecord.Action = action;
                            matchRecord.MatchingBlock = containingBlob;
                            matchRecord.ProcessId = pid;
                            matchRecord.ProcessName = procName;
                            matchRecord.Keywords = string.Join(",", ((string[])keywords.ToArray(typeof(string))));
                            matchRecord.ChildThreadIds = GetChildThreadIds(pid);
                            matchRecord.SuspiciousHeapBlockRange = (heapBlock.dwAddress + heapBlock.dwBlockSize).ToString("x");
                            matches.Add(matchRecord);
                        }

                        haystackASCII = "";
                        haystackUnicode = "";

                        //reinitialize size of this block in preparation for Heap32Next()
                        heapBlock.dwSize = (uint)Marshal.SizeOf(typeof(Win32Helper.HEAPENTRY32));
                    }
                    while (Win32Helper.Heap32Next(out heapBlock));
                }
                while (Win32Helper.Heap32ListNext(hSnapshotHeap, ref procHeapList));

                Win32Helper.CloseHandle(hSnapshotHeap); //close handle to snapshot of heap list

                if (matches.Count > 0)
                    return true;
                return false;
            }

            /////////////////////////////////////////////////////
            //                                                 //
            // UnprotectMemoryRange()                          //
            //                                                 //
            /////////////////////////////////////////////////////
            //Description:  Uses Win32 API's to unprotect (add read access to)
            //              a range of memory pages.
            //
            //Returns:      true if successful; old protection level byref
            /////////////////////////////////////////////////////
            internal bool UnprotectMemoryRange(uint pid, IntPtr startAddress, uint size, ref uint oldProtection)
            {
                //first we must open an handle to the process with VM_PROTECT attributes
                //since we have SeDebugPrivilege, this is allowed.
                IntPtr hProcess = Win32Helper.OpenProcess(Win32Helper.PROCESS_QUERY_INFORMATION | Win32Helper.PROCESS_VM_OPERATION, false, pid);
                uint newPageProtection = 0;
                bool success = false;

                if (hProcess != IntPtr.Zero)
                {
                    Win32Helper.MEMORY_BASIC_INFORMATION minfo = new Win32Helper.MEMORY_BASIC_INFORMATION();
                    int dwLength = Marshal.SizeOf(typeof(Win32Helper.MEMORY_BASIC_INFORMATION));

                    //query the protection attributes for the memory pages of this heap range within the target process.
                    //if they are protected, attempt to unprotect them before ReadProcessMemory()
                    //NB:  VirtualQueryEx() returns the number of bytes in 'minfo'
                    if (0 < Win32Helper.VirtualQueryEx(hProcess, startAddress, out minfo, (uint)dwLength))
                    {
                        //these are the page protection values that, if present, will need to be changed to add read access.
                        int[] noReadAccessProtections = new int[]{
                                    Win32Helper.PAGE_EXECUTE,
                                    Win32Helper.PAGE_NOACCESS };
                        //but, we also need to tack on PAGE_GUARD and a few other modifier bits that could be present.
                        int[] pageProtectionModifierBits = new int[]{
                                    Win32Helper.PAGE_GUARD,
                                    Win32Helper.PAGE_NOCACHE,
                                    Win32Helper.PAGE_WRITECOMBINE};
                        //for more info on why these values work this way, see http://msdn.microsoft.com/en-us/library/aa366786(VS.85).aspx
                        int[] pageProtectionsToSearchFor = new int[8];
                        pageProtectionsToSearchFor[0] = noReadAccessProtections[0];
                        pageProtectionsToSearchFor[1] = noReadAccessProtections[1];
                        int i = 2;
                        foreach (int protect in noReadAccessProtections)
                        {
                            foreach (int modifierBit in pageProtectionModifierBits)
                            {
                                pageProtectionsToSearchFor[i] = protect | modifierBit;
                                i++;
                            }
                        }

                        //loop through all protections we care about and see if they match the page's protection level.
                        //if so, modify the protection attirbutes to allow read access.
                        foreach (int pprotect in pageProtectionsToSearchFor)
                        {
                            if (minfo.Protect == pprotect)
                            {
                                //determine what privileges we should add..dont want to add write or execute if not originally set.
                                //if we did, this would severely degrade security and stability of the process under evaluation.
                                //
                                //base access bits
                                if (minfo.Protect == Win32Helper.PAGE_NOACCESS)
                                    newPageProtection = Win32Helper.PAGE_READONLY;
                                else if (minfo.Protect == Win32Helper.PAGE_EXECUTE)
                                    newPageProtection = Win32Helper.PAGE_EXECUTE_READ;
                                //base access bits (PAGE_NOACCESS) | modifier bit
                                else if (minfo.Protect == (Win32Helper.PAGE_NOACCESS | Win32Helper.PAGE_GUARD))
                                    newPageProtection = Win32Helper.PAGE_READONLY | Win32Helper.PAGE_GUARD;
                                else if (minfo.Protect == (Win32Helper.PAGE_NOACCESS | Win32Helper.PAGE_NOCACHE))
                                    newPageProtection = Win32Helper.PAGE_READONLY | Win32Helper.PAGE_NOCACHE;
                                else if (minfo.Protect == (Win32Helper.PAGE_NOACCESS | Win32Helper.PAGE_WRITECOMBINE))
                                    newPageProtection = Win32Helper.PAGE_READONLY | Win32Helper.PAGE_WRITECOMBINE;
                                //base access bits (PAGE_EXECUTE) | modifier bit
                                else if (minfo.Protect == (Win32Helper.PAGE_EXECUTE | Win32Helper.PAGE_GUARD))
                                    newPageProtection = Win32Helper.PAGE_EXECUTE_READ | Win32Helper.PAGE_GUARD;
                                else if (minfo.Protect == (Win32Helper.PAGE_EXECUTE | Win32Helper.PAGE_NOCACHE))
                                    newPageProtection = Win32Helper.PAGE_EXECUTE_READ | Win32Helper.PAGE_NOCACHE;
                                else if (minfo.Protect == (Win32Helper.PAGE_EXECUTE | Win32Helper.PAGE_WRITECOMBINE))
                                    newPageProtection = Win32Helper.PAGE_EXECUTE_READ | Win32Helper.PAGE_WRITECOMBINE;

                                //modify the page protection attributes of the pages of this heap block
                                if (!Win32Helper.VirtualProtectEx(hProcess, startAddress, size, newPageProtection, out oldProtection))
                                {
                                    MemoryHelperLog.AppendLine("VirtualProtectEx() succeeded.  Changed protection attributes of this heap range from " + minfo.Protect.ToString() + " to " + newPageProtection.ToString() + ".");
                                    success = true;
                                    break;
                                }
                                else
                                {
                                    MemoryHelperLog.AppendLine("WARNING:  VirtualProtectEx() failed to change protection attributes of this heap range from " + minfo.Protect.ToString() + " to " + newPageProtection.ToString() + "!  ReadProcessMemory() will likely fail.");
                                }
                            }
                        } //end looping through page protections we care about                                 
                    } //end virtualqueryex()
                    else
                    {
                        MemoryHelperLog.AppendLine("WARNING:  VirtualQueryEx() failed:  " + Win32Helper.GetLastError32() + ".  Could not determine the page protection attributes of this heap range!");
                    }

                    //close process handle
                    Win32Helper.CloseHandle(hProcess);

                } //end check if 'hProcess' is 0
                else
                {
                    MemoryHelperLog.AppendLine("WARNING:  OpenProcess() failed:  " + Win32Helper.GetLastError32() + ".  Could not determine the page protection attributes of this heap range!");
                }

                return success;
            }

            /////////////////////////////////////////////////////
            //                                                 //
            // ProtectMemoryRange()                            //
            //                                                 //
            /////////////////////////////////////////////////////
            //Description:  Uses Win32 API's to protect a range of 
            //              memory pages by restoring the old protection
            //              level of the given range.
            //
            //Returns:      true if successful
            /////////////////////////////////////////////////////
            internal bool ProtectMemoryRange(uint pid, IntPtr startAddress, uint size, uint restoreProtectionValue)
            {
                //first we must open an handle to the process with VM_PROTECT attributes
                //since we have SeDebugPrivilege, this is allowed.
                IntPtr hProcess = Win32Helper.OpenProcess(Win32Helper.PROCESS_QUERY_INFORMATION | Win32Helper.PROCESS_VM_OPERATION, false, pid);
                uint originalPageProtection = 0;
                bool success = false;

                if (hProcess != IntPtr.Zero)
                {
                    //modify the page protection attributes of the pages of this heap block
                    if (!Win32Helper.VirtualProtectEx(hProcess, startAddress, size, restoreProtectionValue, out originalPageProtection))
                    {
                        MemoryHelperLog.AppendLine("VirtualProtectEx() succeeded.  Restored protection attributes of this heap range from " + originalPageProtection.ToString() + " to " + restoreProtectionValue.ToString() + ".");
                        success = true;
                    }
                    else
                    {
                        MemoryHelperLog.AppendLine("WARNING:  VirtualProtectEx() failed to change protection attributes of this heap range from " + originalPageProtection.ToString() + " to " + restoreProtectionValue.ToString() + "!  This may cause system instability!");
                    }            

                    //close process handle
                    Win32Helper.CloseHandle(hProcess);
                }
                else
                {
                    MemoryHelperLog.AppendLine("WARNING:  OpenProcess() failed:  " + Win32Helper.GetLastError32() + ".  Could not restore the page protection attributes of this heap range!");
                }

                return success;
            }

            /////////////////////////////////////////////////////
            //                                                 //
            // GetChildThreadId()                              //
            //                                                 //
            /////////////////////////////////////////////////////
            //Description:  retrieves the thread id by first using
            //              WMI to get a thread listing for the given
            //              process and then using unamanged api call
            //              to GetThreadId() b/c wmi for some reason
            //              doesn't return a thread id..?
            //Returns:      comma-separated list of thread id's for 
            //              the given process.
            /////////////////////////////////////////////////////
            internal string GetChildThreadIds(uint pid)
            {
                ArrayList threads = new ArrayList();

                //take a snapshot of the thread list for this process (actually this call gets all running threads in ANY process..)
                IntPtr hSnapshotThreads = Win32Helper.CreateToolhelp32Snapshot(0x00000004, pid);

                if (hSnapshotThreads == (IntPtr)(-1))
                {
                    MemoryHelperLog.AppendLine("ERROR:  Could not create thread list snapshot, cannot enumerate threads for process (" + pid + ")...");
                    MemoryHelperLog.AppendLine("ERROR:  Error data = " + Win32Helper.GetLastError32());
                    return "";
                }

                //get a pointer to the thread list
                Win32Helper.THREADENTRY32 threadList = new Win32Helper.THREADENTRY32();
                threadList.dwSize = new IntPtr(Marshal.SizeOf(typeof(Win32Helper.THREADENTRY32)));

                if (!Win32Helper.Thread32First(hSnapshotThreads, ref threadList))
                {
                    MemoryHelperLog.AppendLine("ERROR:  Could not obtain a pointer to the thread list, cannot enumerate threads for this process (" + pid + ")...");
                    MemoryHelperLog.AppendLine("ERROR:  Error data = " + Win32Helper.GetLastError32());
                    return "";
                }

                //now loop over module list for this process
                do
                {
                    uint parentProcessId = threadList.th32OwnerProcessID;

                    //if this thread doesnt belong to our process, skip
                    if (parentProcessId != pid)
                        continue;

                    string threadId = threadList.th32ThreadID.ToString();
                    threads.Add(threadId);
                }
                while (Win32Helper.Thread32Next(hSnapshotThreads, ref threadList));

                Win32Helper.CloseHandle(hSnapshotThreads); //close handle to snapshot of heap list

                return string.Join(",", ((string[])threads.ToArray(typeof(string))));
            }

            /////////////////////////////////////////////////////
            //                                                 //
            // PrintThreads()                                  //
            //                                                 //
            /////////////////////////////////////////////////////
            //Description:  this function loops through processes
            //              in the memory indicators list and output
            //              the thread list for each. originally this
            //              was going to be used to tie a specific thread
            //              to a heap address that contained an in-memory
            //              match for suspicious keyword, but thats not possible.
            //Returns:      void
            /////////////////////////////////////////////////////
            internal void PrintThreads(uint pid)
            {
                SelectQuery sQuery = new SelectQuery("Win32_Process WHERE ProcessId="+pid.ToString());
                ManagementObjectSearcher processSearcher = new ManagementObjectSearcher(sQuery);

                //loop through all processes returned by the above query
                foreach (ManagementObject process in processSearcher.Get())
                {
                    uint ppid = uint.Parse(process["ParentProcessId"].ToString());
                    string pName = process["Name"].ToString();
                    string desc = process["Description"].ToString();
                    string thisProcessHandle = process["Handle"].ToString();

                    MemoryHelperLog.AppendLine("");
                    MemoryHelperLog.AppendLine("Process name:  " + pName);
                    MemoryHelperLog.AppendLine("======================");

                    SelectQuery q2 = new SelectQuery("Win32_Thread", "ProcessHandle = '" + thisProcessHandle + "'");
                    ManagementObjectSearcher threadSearcher = new ManagementObjectSearcher(q2);

                    //loop through all threads for this process
                    foreach (ManagementObject thread in threadSearcher.Get())
                    {
                        MemoryHelperLog.AppendLine("---------------------------------");
                        MemoryHelperLog.AppendLine("Thread:");
                        foreach (PropertyData prop in thread.Properties)
                        {
                            if (prop.Value != null)
                            {
                                if (prop.Name == "ElapsedTime")
                                    MemoryHelperLog.AppendLine(prop.Name + "=" + (int.Parse(prop.Value.ToString()) / 1000).ToString() + " sec.");
                                else
                                    MemoryHelperLog.AppendLine(prop.Name + "=" + prop.Value);
                            }
                        }
                    }
                }

                MemoryHelperLog.AppendLine("");
                MemoryHelperLog.AppendLine("");
                MemoryHelperLog.AppendLine("");
            }
        }
    }
}
