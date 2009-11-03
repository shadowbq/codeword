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
        public class HeuristicsKernelModeHelper
        {
            /////////////////////////////////////////////////////
            //                                                 //
            // GetSSDTHooks()                                  //
            //                                                 //
            /////////////////////////////////////////////////////
            //Description:  Attempts to detect any SSDT hooks.
            //
            //Returns:      a HOOKED_SSDT_TABLE structure
            /////////////////////////////////////////////////////
            internal static CwStructures.HOOKED_SSDT_TABLE GetSSDTHooks()
            {
                //-----------------------------
                //      SEND COMMAND
                //-----------------------------
                //build the IOCTL to send to driver
                uint ioctl = Win32Helper.GetIOCTL(CwConstants.CW_DRIVER_SSDT_DETECT_HOOKS, Win32Helper.METHOD_OUT_DIRECT);

                //build our buffers
                int InBufSize = 0;
                int OutBufSize = Marshal.SizeOf(typeof(CwStructures.HOOKED_SSDT_TABLE));
                IntPtr lpInBuf = IntPtr.Zero; //nothing
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
                CwStructures.HOOKED_SSDT_TABLE HookTable = new CwStructures.HOOKED_SSDT_TABLE();

                //try to marshal the ptr
                try
                {
                    HookTable=(CwStructures.HOOKED_SSDT_TABLE)Marshal.PtrToStructure(lpOutBuf,typeof(CwStructures.HOOKED_SSDT_TABLE));
                }
                catch(Exception ex)
                {
                    throw new Exception("Failed to marshal lpOutBuf pointer to HookTable structure:  " + ex.Message);
                }

                Marshal.FreeHGlobal(lpOutBuf);
                    
                AgentScanLog.AppendLine("SCAN:  Detected "+HookTable.NumHookedEntries+" SSDT hooks.");

                //loop through hooks and print them out in our log
                for (int i = 0; i < HookTable.NumHookedEntries; i++)
                {
                    CwStructures.HOOKED_SSDT_ENTRY he = new CwStructures.HOOKED_SSDT_ENTRY();
                    he = HookTable.HookedEntries[i];
                    AgentScanLog.AppendLine("SCAN:       " + he.ServiceFunctionNameExpected + " hooked by function at address 0x" + he.ServiceFunctionAddress.ToString("x"));
                }

                return HookTable;
            }


            /////////////////////////////////////////////////////
            //                                                 //
            // GetSSDTDetours()                                  //
            //                                                 //
            /////////////////////////////////////////////////////
            //Description:  Attempts to detect any SSDT detours.
            //
            //Returns:      a DETOURED_SSDT_TABLE structure
            /////////////////////////////////////////////////////
            internal static CwStructures.DETOURED_SSDT_TABLE GetSSDTDetours()
            {
                //-----------------------------
                //      SEND COMMAND
                //-----------------------------
                //build the IOCTL to send to driver
                uint ioctl = Win32Helper.GetIOCTL(CwConstants.CW_DRIVER_SSDT_DETECT_DETOURS, Win32Helper.METHOD_OUT_DIRECT);

                //build our buffers
                int InBufSize = 0;
                int OutBufSize = Marshal.SizeOf(typeof(CwStructures.DETOURED_SSDT_TABLE));
                IntPtr lpInBuf = IntPtr.Zero; //nothing
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
                CwStructures.DETOURED_SSDT_TABLE DetourTable = new CwStructures.DETOURED_SSDT_TABLE();

                //try to marshal the ptr
                try
                {
                    DetourTable = (CwStructures.DETOURED_SSDT_TABLE)Marshal.PtrToStructure(lpOutBuf, typeof(CwStructures.DETOURED_SSDT_TABLE));
                }
                catch (Exception ex)
                {
                    throw new Exception("Failed to marshal lpOutBuf pointer to DetourTable structure:  " + ex.Message);
                }

                Marshal.FreeHGlobal(lpOutBuf);

                AgentScanLog.AppendLine("SCAN:  Detected " + DetourTable.NumDetouredEntries + " SSDT detours.");

                //loop through hooks and print them out in our log
                for (int i = 0; i < DetourTable.NumDetouredEntries; i++)
                {
                    CwStructures.DETOURED_SSDT_ENTRY de = new CwStructures.DETOURED_SSDT_ENTRY();
                    de = DetourTable.DetouredEntries[i];
                    AgentScanLog.AppendLine("SCAN:       " + de.ServiceFunctionNameExpected + "()'s prologue detoured to function at address 0x" + de.TargetAddress.ToString("x"));
                }

                return DetourTable;
            }

            /////////////////////////////////////////////////////
            //                                                 //
            // GetModuleDetours()                              //
            //                                                 //
            /////////////////////////////////////////////////////
            //Description:  Attempts to detect any detours in one
            //              of the "dirty dozen" system DLLs:
            //                  -ntdll.dll
            //                  -kernel32.dll
            //                  -user32.dll
            //                  -advapi32.dll
            //                  -gdi32.dll
            //                  -comdlg32.dll
            //                  -comctl32.dll
            //                  -commctrl.dll
            //                  -shell.dll
            //                  -shlwapi.dll
            //                  -mshtml.dll
            //                  -urlmon.dll
            //
            //Returns:      a WIN32API_DETOUR_TABLE structure
            /////////////////////////////////////////////////////
            internal unsafe static CwStructures.WIN32API_DETOUR_TABLE GetModuleDetours(string modname)
            {
                //-----------------------------
                //      SEND COMMAND
                //-----------------------------
                //build the IOCTL to send to driver
                uint ioctl = Win32Helper.GetIOCTL(CwConstants.CW_DRIVER_WIN32API_DETOUR_DETECTION, Win32Helper.METHOD_OUT_DIRECT);

                //build our buffers
                int InBufSize = Marshal.SystemDefaultCharSize * modname.Length;
                int OutBufSize = Marshal.SizeOf(typeof(CwStructures.WIN32API_DETOUR_TABLE));
                IntPtr lpInBuf = Marshal.StringToHGlobalAnsi(modname); //store our module name string for driver
                IntPtr lpOutBuf = Marshal.AllocHGlobal(OutBufSize);
                int bytesReturned = 0;

                //send the IOCTL
                try
                {
                    bytesReturned = DriverHelper.SendDriverCommand(ioctl, lpInBuf, InBufSize, ref lpOutBuf, OutBufSize);
                }
                catch (Exception ex)
                {
                    Marshal.FreeHGlobal(lpInBuf);
                    throw new Exception("SendDriverCommand() failed:  " + ex.Message);
                }

                Marshal.FreeHGlobal(lpInBuf);

                if (bytesReturned == 0)
                    throw new Exception("A 0-length buffer was returned from the driver.");

                //-----------------------------
                //      PROCESS RESULTS
                //-----------------------------
                CwStructures.WIN32API_DETOUR_TABLE moduleDetours = new CwStructures.WIN32API_DETOUR_TABLE();

                //try to marshal the ptr
                try
                {
                    moduleDetours = (CwStructures.WIN32API_DETOUR_TABLE)Marshal.PtrToStructure(lpOutBuf, typeof(CwStructures.WIN32API_DETOUR_TABLE));
                }
                catch (Exception ex)
                {
                    throw new Exception("Failed to marshal lpOutBuf pointer to Win32DetourTable structure:  " + ex.Message);
                }

                Marshal.FreeHGlobal(lpOutBuf);

                for (int j = 0; j < moduleDetours.NumDetours; j++)
                {
                    CwStructures.WIN32API_DETOUR_ENTRY de = new CwStructures.WIN32API_DETOUR_ENTRY();
                    de = moduleDetours.Win32Detours[j];
                    if (de.IsDetoured)
                        AgentScanLog.AppendLine("SCAN:       " + moduleDetours.ModuleName + "!" + de.ExportName + "()'s prologue detoured to function at address " + de.DetouringModule + "!0x" + de.ExportAddress.ToString("x"));
                    else if (de.IsUnknown)
                        AgentScanLog.AppendLine("SCAN:       Unable to check unnamed function at directory export table offset " + moduleDetours.ModuleName + "!0x" + de.ExportAddress.ToString("x"));
                }
                
                return moduleDetours;
            }

            /////////////////////////////////////////////////////
            //                                                 //
            // GetHookedDispatchFunctionsInDriver()            //
            //                                                 //
            /////////////////////////////////////////////////////
            //Description:  Attempts to detect any hooked dispatch functions in the
            //              given driver by examining its IRP table.
            //
            //Returns:      a HOOKED_DISPATCH_FUNCTIONS_TABLE structure
            /////////////////////////////////////////////////////
            internal static CwStructures.HOOKED_DISPATCH_FUNCTIONS_TABLE GetHookedDispatchFunctionsInDriver(CwStructures.DRIVER_CHECK_INFO driverInfoStruct)
            {
                //-----------------------------
                //      SEND COMMAND
                //-----------------------------
                //build the IOCTL to send to driver
                uint ioctl = Win32Helper.GetIOCTL(CwConstants.CW_DRIVER_IRP_HOOK_DETECTION, Win32Helper.METHOD_OUT_DIRECT);

                //build our buffers
                int InBufSize = Marshal.SizeOf(typeof(CwStructures.DRIVER_CHECK_INFO));
                int OutBufSize = Marshal.SizeOf(typeof(CwStructures.HOOKED_DISPATCH_FUNCTIONS_TABLE));
                IntPtr lpInBuf = Marshal.AllocHGlobal(InBufSize);
                try
                {
                    Marshal.StructureToPtr(driverInfoStruct, lpInBuf, true);
                }
                catch (Exception ex)
                {
                    throw new Exception("SendDriverCommand() failed:  " + ex.Message);
                }

                IntPtr lpOutBuf = Marshal.AllocHGlobal(OutBufSize);
                int bytesReturned = 0;

                //send the IOCTL
                try
                {
                    bytesReturned = DriverHelper.SendDriverCommand(ioctl, lpInBuf, InBufSize, ref lpOutBuf, OutBufSize);
                }
                catch (Exception ex)
                {
                    Marshal.FreeHGlobal(lpInBuf);
                    throw new Exception("SendDriverCommand() failed:  " + ex.Message);
                }

                Marshal.FreeHGlobal(lpInBuf);

                if (bytesReturned == 0)
                    throw new Exception("A 0-length buffer was returned from the driver.");

                //-----------------------------
                //      PROCESS RESULTS
                //-----------------------------
                CwStructures.HOOKED_DISPATCH_FUNCTIONS_TABLE DriverHookTable = new CwStructures.HOOKED_DISPATCH_FUNCTIONS_TABLE();

                //try to marshal the ptr
                try
                {
                    DriverHookTable = (CwStructures.HOOKED_DISPATCH_FUNCTIONS_TABLE)Marshal.PtrToStructure(lpOutBuf, typeof(CwStructures.HOOKED_DISPATCH_FUNCTIONS_TABLE));
                }
                catch (Exception ex)
                {
                    throw new Exception("Failed to marshal lpOutBuf pointer to DriverHookTable structure:  " + ex.Message);
                }

                Marshal.FreeHGlobal(lpOutBuf);

                AgentScanLog.AppendLine("SCAN:  Detected " + DriverHookTable.NumHookedEntries + " IRP hooks.");

                //loop through hooks and print them out in our log
                for (int i = 0; i < DriverHookTable.NumHookedEntries; i++)
                {
                    CwStructures.HOOKED_DISPATCH_FUNCTION_ENTRY de = new CwStructures.HOOKED_DISPATCH_FUNCTION_ENTRY();
                    de = DriverHookTable.HookedEntries[i];
                    AgentScanLog.AppendLine("SCAN:       " + de.DispatchFunctionName + "()'s major function code 0x"+de.IrpMajorFunctionHooked.ToString("x")+" is hooked to function at address 0x" + de.DispatchFunctionAddress.ToString("x"));
                }

                return DriverHookTable;
            }

            /////////////////////////////////////////////////////
            //                                                 //
            // GetDetouredDispatchFunctionsInDriver()          //
            //                                                 //
            /////////////////////////////////////////////////////
            //Description:  Attempts to detect any detoured dispatch functions in the
            //              given driver by examining those funcs' prologues.
            //
            //Returns:      a DETOURED_DISPATCH_FUNCTIONS_TABLE structure
            /////////////////////////////////////////////////////
            internal static CwStructures.DETOURED_DISPATCH_FUNCTIONS_TABLE GetDetouredDispatchFunctionsInDriver(CwStructures.DRIVER_CHECK_INFO driverInfoStruct)
            {
                //-----------------------------
                //      SEND COMMAND
                //-----------------------------
                //build the IOCTL to send to driver
                uint ioctl = Win32Helper.GetIOCTL(CwConstants.CW_DRIVER_IRP_DETOUR_DETECTION, Win32Helper.METHOD_OUT_DIRECT);

                //build our buffers
                int InBufSize = Marshal.SizeOf(typeof(CwStructures.DRIVER_CHECK_INFO));
                int OutBufSize = Marshal.SizeOf(typeof(CwStructures.DETOURED_DISPATCH_FUNCTIONS_TABLE));
                IntPtr lpInBuf = Marshal.AllocHGlobal(InBufSize);
                Marshal.StructureToPtr(driverInfoStruct, lpInBuf, true);
                IntPtr lpOutBuf = Marshal.AllocHGlobal(OutBufSize);
                int bytesReturned = 0;

                //send the IOCTL
                try
                {
                    bytesReturned = DriverHelper.SendDriverCommand(ioctl, lpInBuf, InBufSize, ref lpOutBuf, OutBufSize);
                }
                catch (Exception ex)
                {
                    Marshal.FreeHGlobal(lpInBuf);
                    throw new Exception("SendDriverCommand() failed:  " + ex.Message);
                }

                Marshal.FreeHGlobal(lpInBuf);

                if (bytesReturned == 0)
                    throw new Exception("A 0-length buffer was returned from the driver.");

                //-----------------------------
                //      PROCESS RESULTS
                //-----------------------------
                CwStructures.DETOURED_DISPATCH_FUNCTIONS_TABLE DriverDetourTable = new CwStructures.DETOURED_DISPATCH_FUNCTIONS_TABLE();

                //try to marshal the ptr
                try
                {
                    DriverDetourTable = (CwStructures.DETOURED_DISPATCH_FUNCTIONS_TABLE)Marshal.PtrToStructure(lpOutBuf, typeof(CwStructures.DETOURED_DISPATCH_FUNCTIONS_TABLE));
                }
                catch (Exception ex)
                {
                    throw new Exception("Failed to marshal lpOutBuf pointer to DriverDetourTable structure:  " + ex.Message);
                }

                Marshal.FreeHGlobal(lpOutBuf);

                AgentScanLog.AppendLine("SCAN:  Detected " + DriverDetourTable.NumDetours + " IRP detours.");

                //loop through hooks and print them out in our log
                for (int i = 0; i < DriverDetourTable.NumDetours; i++)
                {
                    CwStructures.DETOURED_DISPATCH_FUNCTION_ENTRY de = new CwStructures.DETOURED_DISPATCH_FUNCTION_ENTRY();
                    de = DriverDetourTable.DetouredEntries[i];
                    AgentScanLog.AppendLine("SCAN:       " + de.DispatchFunctionName + "()'s prologue is detoured to function at address 0x" + de.TargetAddress.ToString("x"));
                }

                return DriverDetourTable;
            }

        }
    }
}
