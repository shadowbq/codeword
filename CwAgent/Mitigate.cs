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
        class Mitigate
        {
            /////////////////////////////////////////////////////
            //                                                 //
            // RunThirdPartyApp()                              //
            //                                                 //
            /////////////////////////////////////////////////////
            //Description:  runs a 3rd party app at user discretion
            //Returns:      true if succeeds
            /////////////////////////////////////////////////////
            public static bool RunThirdPartyApp(string command, string args)
            {
                try
                {
                    FileInfo f = new FileInfo(command);

                    if (f.Exists)
                    {
                        AgentScanLog.AppendLine("FINALIZE:  Running third-party app '" + command + "' with args '" + args + "'...");

                        //kick off a new process for the patch to run
                        System.Diagnostics.Process p = System.Diagnostics.Process.Start(command, " " + args);

                        //wait for the process to finish
                        while (!p.HasExited) { }

                        AgentScanLog.AppendLine("FINALIZE:  Success!");
                    }
                    else
                    {
                        AgentScanLog.AppendLine("WARNING:  " + command + " could not be found.");
                    }
                }
                catch (Exception e)
                {
                    AgentScanLog.AppendLine("WARNING:  Caught exception '" + e.Message + "' trying to run 3rd party app '" + command + "'");
                }

                return true;
            }

            /////////////////////////////////////////////////////
            //                                                 //
            // DisableAndDisassociateAutorun()                 //
            //                                                 //
            /////////////////////////////////////////////////////
            //Description:  disables autorun according to:
            //      ref:  http://nick.brown.free.fr/blog/archive/2007_10_01_archive.html,
            //            http://support.microsoft.com/kb/953252)
            //      and disassociate autorun.inf
            //Returns:      true if succeeds
            /////////////////////////////////////////////////////
            public static unsafe bool DisableAndDisassociateAutorun()
            {
                //1.  disable autorun
                AgentScanLog.AppendLine("MITIGATE:  Disabling autorun capabilities...");
                RegistryKey autoRunKey = Registry.LocalMachine.OpenSubKey("Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer", true);

                if (autoRunKey != null)
                {
                    string currValue = (string)autoRunKey.GetValue("NoDriveTypeAutoRun");
                    if (currValue != null)
                        AgentScanLog.AppendLine("MITIGATE:  Changing NoDriveTypeAutoRun from '" + currValue + "' to 0xFF...");
                    else
                        AgentScanLog.AppendLine("MITIGATE:  Setting NoDriveTypeAutoRun to 0xFF...");

                    autoRunKey.SetValue("NoDriveTypeAutoRun", 0x000000FF, RegistryValueKind.DWord);
                    AgentScanLog.AppendLine("MITIGATE:  Success.");
                }
                else
                    AgentScanLog.AppendLine("MITIGATE:  'HKLM\\Software\\..\\Policies\\Explorer' doesn't exist, can't disable autorun.");

                //2. disassociate autorun.inf
                AgentScanLog.AppendLine("MITIGATE:  Disassociating autorun...");
                RegistryKey AutorunIniMapKey = Registry.LocalMachine.OpenSubKey("Software\\Microsoft\\WindowsNT\\CurrentVersion\\IniFileMapping", true);

                if (AutorunIniMapKey != null)
                {
                    string currValue = (string)AutorunIniMapKey.GetValue("Autorun.inf");
                    if (currValue != null)
                        AgentScanLog.AppendLine("MITIGATE:  Changing association of Autorun.inf from '" + currValue + "' to @=@SYS:DoesNotExist...");
                    else
                        AgentScanLog.AppendLine("MITIGATE:  Setting association of Autorun.inf to @=@SYS:DoesNotExist...");

                    AutorunIniMapKey.SetValue("Autorun.inf", "@=\"@SYS:DoesNotExist\"", RegistryValueKind.String);
                    AgentScanLog.AppendLine("MITIGATE:  Success.");
                }
                else
                    AgentScanLog.AppendLine("MITIGATE:  'HKLM\\Software\\..\\IniFileMapping' doesn't exist, can't disassociate autorun.");

                return true;
            }

            /////////////////////////////////////////////////////
            //                                                 //
            // DisableUseOfUSBDevices()                        //
            //                                                 //
            /////////////////////////////////////////////////////
            //Description:  disable usb devices completely, ref:
            //          (http://support.microsoft.com/kb/823732/)
            //Returns:      true if succeeds
            /////////////////////////////////////////////////////
            public static bool DisableUseOfUSBDevices()
            {
                RegistryKey UsbstorKey = Registry.LocalMachine.OpenSubKey("SYSTEM\\CurrentControlSet\\Services\\UsbStor", true);

                if (UsbstorKey != null)
                {
                    object currValue = UsbstorKey.GetValue("Start");
                    if (currValue != null)
                        AgentScanLog.AppendLine("MITIGATE:  Changing USBSTOR from '" + int.Parse(currValue.ToString()).ToString("x") + "' to 0x00000004...");
                    else
                        AgentScanLog.AppendLine("MITIGATE:  Setting USBSTOR to 0x00000004...");

                    UsbstorKey.SetValue("Start", 0x00000004, RegistryValueKind.DWord);
                    AgentScanLog.AppendLine("MITIGATE:  Success.");
                }
                else
                    AgentScanLog.AppendLine("MITIGATE:  'HKLM\\SYSTEM\\..\\USBSTOR' doesn't exist, can't disable USB devices.");

                return true;
            }
        }
    }
}
