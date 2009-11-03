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
        public class EnvironmentHelper
        {
            /////////////////////////////////////////////////////
            //                                                 //
            // GetIpAddresses()                                //
            //                                                 //
            /////////////////////////////////////////////////////
            //Description:  Utilizes WMI to get a list of all network
            //              adapters on the system, then iterates thru
            //              this list and grabs all assoc IP addresses
            //              IPv6, loopback, and 'down' addresses are
            //              not included.
            //Returns:      an array of strings of IP addresses
            /////////////////////////////////////////////////////
            public static string[] GetIPAddresses()
            {
                NetworkInterface[] interfaces = NetworkInterface.GetAllNetworkInterfaces();
                ArrayList addresses = new ArrayList();

                //loop through all interfaces on this machine and record potential IP address
                foreach (NetworkInterface iface in interfaces)
                {
                    //if the interface is down, we dont care about it
                    if (iface.OperationalStatus != OperationalStatus.Up)
                        continue;

                    IPInterfaceProperties p = iface.GetIPProperties();
                    UnicastIPAddressInformationCollection us = p.UnicastAddresses; //ip addresses
                    GatewayIPAddressInformationCollection gw = p.GatewayAddresses; //gateways

                    //if this interface isn't configured with a gateway, skip it
                    if (gw.Count == 0)
                        continue;

                    //loop through each unicast ip addr for this interface
                    //and if it has a non-private IP, we found the system ip
                    foreach (UnicastIPAddressInformation u in us)
                    {
                        //skip IPv6 addresses
                        if (u.Address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6)
                            continue;

                        //skip loopback addresses
                        if (IPAddress.IsLoopback(u.Address))
                            continue;

                        //it could be a private address..
                        addresses.Add(u.Address.ToString() + " (" + iface.Description + ")");
                    }
                }

                return (string[])addresses.ToArray(typeof(string));
            }

            /////////////////////////////////////////////////////
            //                                                 //
            // GetOsName()                                     //
            //                                                 //
            /////////////////////////////////////////////////////
            //Description:  uses some voodoo to find OS name
            //Returns:      the OS name like "Windows 95", etc
            /////////////////////////////////////////////////////
            public static string GetOSName()
            //credit:  http://www.codeproject.com/KB/system/osversion_producttype.aspx
            {
                OperatingSystem osInfo = Environment.OSVersion;
                string osName = "UNKNOWN";

                switch (osInfo.Platform)
                {
                    case PlatformID.Win32Windows:
                        {
                            switch (osInfo.Version.Minor)
                            {
                                case 0:
                                    {
                                        osName = "Windows 95";
                                        break;
                                    }

                                case 10:
                                    {
                                        if (osInfo.Version.Revision.ToString() == "2222A")
                                        {
                                            osName = "Windows 98 Second Edition";
                                        }
                                        else
                                        {
                                            osName = "Windows 98";
                                        }
                                        break;
                                    }

                                case 90:
                                    {
                                        osName = "Windows Me";
                                        break;
                                    }
                            }
                            break;
                        }

                    case PlatformID.Win32NT:
                        {
                            switch (osInfo.Version.Major)
                            {
                                case 3:
                                    {
                                        osName = "Windows NT 3.51";
                                        break;
                                    }

                                case 4:
                                    {
                                        osName = "Windows NT 4.0";
                                        break;
                                    }

                                case 5:
                                    {
                                        if (osInfo.Version.Minor == 0)
                                        {
                                            osName = "Windows 2000";
                                        }
                                        else if (osInfo.Version.Minor == 1)
                                        {
                                            osName = "Windows XP";
                                        }
                                        else if (osInfo.Version.Minor == 2)
                                        {
                                            osName = "Windows Server 2003";
                                        }
                                        break;
                                    }

                                case 6:
                                    {
                                        osName = "Windows Vista";
                                        break;
                                    }
                            }
                            break;
                        }
                }

                return osName;
            }

            /////////////////////////////////////////////////////
            //                                                 //
            // EscalatePrivileges()                            //
            //                                                 //
            /////////////////////////////////////////////////////
            //Description:  Escalates our process' privilege token
            //              to include debugging privileges.
            //
            //Returns:      true if successful
            //////////////////////////////////////////////////////
            public static bool EscalatePrivileges()
            {
                Win32Helper.TOKEN_PRIVILEGES TP = new Win32Helper.TOKEN_PRIVILEGES();
                Win32Helper.TOKEN_PRIVILEGES TP2 = new Win32Helper.TOKEN_PRIVILEGES();
                Win32Helper.LUID RestoreLuid = new Win32Helper.LUID();
                Win32Helper.LUID BackupLuid = new Win32Helper.LUID();
                int token = 0;

                //get a security token for the current process
                if (Win32Helper.OpenProcessToken(Win32Helper.GetCurrentProcess(), Win32Helper.TOKEN_ADJUST_PRIVILEGES | Win32Helper.TOKEN_QUERY, ref token) == 0)
                {
                    Console.WriteLine("ERROR:  Could not open current process security token:  " + Win32Helper.GetLastError32());
                    return false;
                }

                //get LUID (localy unique identifier) for RESTORE privilege 
                if (Win32Helper.LookupPrivilegeValue(null, Win32Helper.SE_RESTORE_NAME, ref RestoreLuid) == 0)
                {
                    Console.WriteLine("ERROR:  Could not get SeRestorePrivilege LUID of current process:  " + Win32Helper.GetLastError32());
                    return false;
                }

                //get LUID for BACKUP privilege
                if (Win32Helper.LookupPrivilegeValue(null, Win32Helper.SE_BACKUP_NAME, ref BackupLuid) == 0)
                {
                    Console.WriteLine("ERROR:  Could not get SeBackupPrivilege LUID of current process:  " + Win32Helper.GetLastError32());
                    return false;
                }

                //modify our security token to get both of these privileges
                TP.PrivilegeCount = 1;
                TP.Attributes = Win32Helper.SE_PRIVILEGE_ENABLED;
                TP.Luid = RestoreLuid;
                TP2.PrivilegeCount = 1;
                TP2.Attributes = Win32Helper.SE_PRIVILEGE_ENABLED;
                TP2.Luid = BackupLuid;

                //Adjust our process security token with new data structure with proper privileges
                if (Win32Helper.AdjustTokenPrivileges(token, 0, ref TP, 1024, 0, 0) == 0)
                {
                    Console.WriteLine("ERROR:  Could not adjust process security token:  " + Win32Helper.GetLastError32());
                    return false;
                }

                //Adjust our process security token with new data structure with proper privileges
                if (Win32Helper.AdjustTokenPrivileges(token, 0, ref TP2, 1024, 0, 0) == 0)
                {
                    Console.WriteLine("ERROR:  Could not adjust process security token:  " + Win32Helper.GetLastError32());
                    return false;
                }

                return true;
            }

            /////////////////////////////////////////////////////
            //                                                 //
            // ToggleUACPrompting()                            //
            //                                                 //
            /////////////////////////////////////////////////////
            //Description:  En/Disables UAC prompting on vista
            //Returns:      true if successful
            /////////////////////////////////////////////////////
            public static string ToggleUACPrompting(bool enable, string oldvalue)
            {
                //enable or disable UAC prompting?
                if (enable)
                    Console.WriteLine("Enabling UAC prompting...");
                else
                    Console.WriteLine("Disabling UAC prompting...");

                //write to reg key
                try
                {
                    RegistryKey policiesKey = Registry.LocalMachine.OpenSubKey("Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System", true);

                    //if we are re-enabling, just set it back to the saved value
                    if (enable)
                    {
                        try
                        {
                            policiesKey.SetValue("ConsentPromptBehaviorAdmin", oldvalue);
                        }
                        catch { }
                    }
                    //otherwise, we are disabling it, so save the old value 
                    //if it even exists, and then set it to 0 to turn off
                    else
                    {
                        if (policiesKey.GetValue("ConsentPromptBehaviorAdmin") != null)
                        {
                            oldvalue = policiesKey.GetValue("ConsentPromptBehaviorAdmin").ToString();
                            try
                            {
                                policiesKey.SetValue("ConsentPromptBehaviorAdmin", "2");
                            }
                            catch { }

                            Registry.LocalMachine.Flush(); //apply now
                        }
                        else
                            return "";
                    }
                }
                catch { return null; }

                return oldvalue;
            }

            /////////////////////////////////////////////////////
            //                                                 //
            // ToggleDotnetSecurity()                          //
            //                                                 //
            /////////////////////////////////////////////////////
            //Description:  Attempts to disable all .NET security
            //              settings with the caspol program.  To
            //              find this program, a full disk search
            //              is performed on any caspol for any .NET
            //              version, so all versions are rendered
            //              insecure.
            //Returns:      true if successful
            /////////////////////////////////////////////////////
            public static bool ToggleDotnetSecurity(string action, string mode)
            {
                ArrayList fileFolderCount = new ArrayList();
                fileFolderCount.Add(0);
                fileFolderCount.Add(0);
                FileHelper fh = new FileHelper();
                ArrayList caspols = fh.FileSearch("C:\\Windows\\Microsoft.NET\\Framework", "caspol.exe", "", "", "", "");

                //AgentScanLog.AppendLine(mode + ":  Found " + caspols.Count.ToString() + " caspol.exe programs.");

                if (caspols.Count == 0)
                {
                    AgentScanLog.AppendLine("WARNING:  Could not find caspol.exe.  .NET installation may be corrupt.  Continuing...");
                    return false;
                }
                else
                {
                    //call each caspol.exe for each version of .NET to disable them all
                    foreach (string caspol in caspols)
                    {
                        //AgentScanLog.AppendLine(mode + ":  Executing '" + caspol + "'...");

                        //kick off a new process for this caspol.exe execution - pass args to turn off security
                        System.Diagnostics.Process p = System.Diagnostics.Process.Start(caspol, "–polchgprompt off -security " + action + " -quiet");

                        //wait for the process to finish
                        while (!p.HasExited)
                        {
                        }

                        //AgentScanLog.AppendLine(mode + ":  Success.  File executed.");
                    }
                    AgentScanLog.AppendLine(mode + ":  Successfully turned " + action.ToUpper() + " .NET security.");
                    //AgentScanLog.AppendLine(mode + ":  Success.  All caspol's executed.");
                }

                return true;
            }

            /////////////////////////////////////////////////////
            //                                                 //
            // ExtractInternalResource()                       //
            //                                                 //
            /////////////////////////////////////////////////////
            //Description:  Uses the Assembly object model to extract
            //              an internally embedded assembly/resource.
            //Returns:      true if successful
            /////////////////////////////////////////////////////
            public static bool ExtractInternalResource(string resourceName, string outputFilename)
            {
                //extract internal assembly that holds config file
                //we will read in these settings and scope our action based on them
                Assembly a = Assembly.GetExecutingAssembly();

                Stream byteStream;

                try
                {
                    //get the file byte stream from the ASM manifest rsrc
                    //due to .NET naming convention, the name for the rsrc is:
                    //  "Codeword.Resources.CwAgentConfiguration.xml"
                    byteStream = a.GetManifestResourceStream(resourceName);
                }
                catch (System.IO.FileNotFoundException e)
                {
                    AgentScanLog.AppendLine("FileNotFoundException:  Unable to locate the embedded resource.  " + e.Message);
                    return false;
                }

                if (byteStream == null)
                {
                    AgentScanLog.AppendLine("The file extraction stream for the embedded resource '" + resourceName + "' was empty.");
                    AgentScanLog.AppendLine("Available assemblies:");
                    foreach (string Name in a.GetManifestResourceNames())
                        AgentScanLog.AppendLine("Name: " + Name);
                    return false;
                }

                //read the stream data and store in a Byte[] array
                byte[] buf = new byte[byteStream.Length];
                int bytesToRead = (int)byteStream.Length;
                int bytesRead = 0;

                while (bytesToRead > 0)
                {
                    int n = byteStream.Read(buf, bytesRead, bytesToRead);
                    if (n == 0)
                        break;
                    bytesRead += n;
                    bytesToRead -= n;
                }

                byteStream.Close();

                //save the file to disk using global file name
                try
                {
                    BinaryWrite(outputFilename, buf);
                }
                catch (Exception e)
                {
                    AgentScanLog.AppendLine(e.InnerException.Message);
                }

                return true;
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
        }
    }
}