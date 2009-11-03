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
        public class Collect
        {
            /////////////////////////////////////////////////////
            //                                                 //
            // BuildZipName()                                  //
            //                                                 //
            /////////////////////////////////////////////////////
            //Description:  creates zipfile name based on results
            //Returns:      string file name
            /////////////////////////////////////////////////////
            public static string BuildZipName(int numfindings)
            {
                //create zip file name in format:
                //  [I|C]_[YYYY-MM-DD_HHmmss]_[Hostname].zip
                //where I=infected and C=clean
                string zipfilename = "C";
                Random rand = new Random();
                int randNum = rand.Next(1000, 9999); //get 4 digit random number
                if (numfindings > 0)
                    zipfilename = "I";
                zipfilename += "_" + DateTime.Now.ToString("yyyy-MM-dd_HHmmss");
                zipfilename += "_" + Environment.MachineName;
                zipfilename += ".zip";

                return zipfilename;
            }

            /////////////////////////////////////////////////////
            //                                                 //
            // AddToZip()                                      //
            //                                                 //
            /////////////////////////////////////////////////////
            //Description:  Adds the given evidence to the zip file
            //Returns:      true if successful
            /////////////////////////////////////////////////////
            public static bool AddToZip(ZipFile zip, string filename)
            {
                FileInfo f = new FileInfo(filename);

                //if the file exists, try to add it to the archive
                if (f.Exists)
                {
                    try
                    {
                        //if this fails, it's most likely b/c the file is already in the archive
                        zip.AddFile(f.FullName);
                    }
                    catch (Exception ex)
                    {
                        AgentScanLog.AppendLine("WARNING:  Failed to add zip file '" + filename + "' to archive:  " + ex.Message);
                        return false;
                    }

                    AgentScanLog.AppendLine("      '" + filename + "'");
                }
                else
                {
                    AgentScanLog.AppendLine("WARNING:  A file in the collection queue does not exist: '" + filename + "'!  It will not be collected.");
                    return false;
                }

                return true;
            }

            /////////////////////////////////////////////////////
            //                                                 //
            // EnumerateUSBDevices()                           //
            //                                                 //
            /////////////////////////////////////////////////////
            //Description:  Uses .NET registry objects to dig in 
            //              the infamous USBSTOR key for past and
            //              present USB devices.
            //Returns:      true if successful
            //  NOTE:
            //      techniques used in this function are from 
            //      "Windows Forensic Analysis" by Harlan Carvey
            //
            /////////////////////////////////////////////////////
            public static bool EnumerateUSBDevices(ref StringBuilder usbdata)
            {
                RegistryKey USBSTOR;
                string current = "";

                //loop through 10 currentcontrolsets
                //sample structure:
                //      HKLM\System\CurrentControlSet003\Enum\USBSTOR\
                //          \Disk&Ven_ChipsBnk&Prod_Flash_Disk&Rev_2.00 --> USB DRIVE
                //              \3852u395823                            --> Instance ID
                //              \ag3490t24t940
                //          \Disk&Ven_SanDisk&Prod_Cruzer_Slide&Rev_4.05 --> USB DRIVE
                //          ....
                //
                for (int i = 0; i < 10; i++)
                {
                    current = "00" + i.ToString(); //001,002,003,etc
                    USBSTOR = Registry.LocalMachine.OpenSubKey("System\\ControlSet" + current + "\\Enum\\USBSTOR");

                    //if the key doesnt exist, we must continue b/c control set numbering isn't contiguous
                    if (USBSTOR == null)
                        continue;

                    string[] DeviceClassIds = USBSTOR.GetSubKeyNames();

                    //loop through all usb device class IDs beneath USBSTOR...
                    //get a list of subkeys which are named by instance IDs
                    foreach (string deviceName in DeviceClassIds)
                    {
                        //lots of info you can get from device name:
                        //Disk&Ven_###&Prod_###&Rev_### -- we want the ###
                        string[] driveInfo = deviceName.Split(new char[] { '&' });
                        string vendor = driveInfo[1].Replace("Ven_", "").Replace("_", " ");
                        string product = driveInfo[2].Replace("Prod_", "").Replace("_", " ");
                        string revision = driveInfo[3].Replace("Rev_", "").Replace("_", " ");
                        string serial = "";
                        ArrayList insertionDates = new ArrayList();

                        //get list of instances
                        string[] instances = USBSTOR.OpenSubKey(deviceName).GetSubKeyNames();
                        int count = 0;

                        //each unique instance represents a time the device was plugged in
                        //so collect information on each instance
                        foreach (string instanceId in instances)
                        {
                            //if the second character in the instanceId is '&', then we 
                            //know the id is made up by windows and manuf did not give one
                            if (instanceId[1] == '&')
                                serial = "None";
                            else
                                serial = instanceId;

                            string friendlyName = "[none]";
                            object friendlyNameValueObj = USBSTOR.OpenSubKey(deviceName + "\\" + instanceId).GetValue("FriendlyName");
                            if (friendlyNameValueObj != null)
                                friendlyName = (string)friendlyNameValueObj.ToString();

                            //see ntddstor.h - these are GUIDs for disk and volume device interfaces..
                            string key1 = "SYSTEM\\CurrentControlSet\\Control\\DeviceClasses\\{53f56307-b6bf-11d0-94f2-00a0c91efb8b}";
                            string key2 = "SYSTEM\\CurrentControlSet\\Control\\DeviceClasses\\{53f5630d-b6bf-11d0-94f2-00a0c91efb8b}";
                            RegistryKey diskGuid = Registry.LocalMachine.OpenSubKey(key1);
                            RegistryKey volDevGuid = Registry.LocalMachine.OpenSubKey(key2);
                            string[] DeviceClasses1 = diskGuid.GetSubKeyNames();
                            string[] DeviceClasses2 = volDevGuid.GetSubKeyNames();
                            //merge two sets of device classes into one
                            string[] allDeviceClasses = new string[DeviceClasses1.Length + DeviceClasses2.Length];
                            DeviceClasses1.CopyTo(allDeviceClasses, 0);
                            DeviceClasses2.CopyTo(allDeviceClasses, DeviceClasses1.Length);
                            IntPtr lastInsertionDatePtr = (IntPtr)0;
                            IntPtr keyHandle = (IntPtr)0;
                            IntPtr hKey = (IntPtr)0;
                            System.Runtime.InteropServices.ComTypes.FILETIME lastInsertionDate = new System.Runtime.InteropServices.ComTypes.FILETIME();

                            //get last write date/time
                            foreach (string devclass in allDeviceClasses)
                            {
                                if (devclass.Contains(instanceId))
                                {
                                    //open the registry key using unmanaged API call
                                    if (Win32Helper.RegOpenKeyExW(hKey, key1 + "\\" + devclass, 0, 0x00020019, ref keyHandle) == 0 && keyHandle != (IntPtr)(-1))
                                    {
                                        //pass 0 to all the vars we dont care about- we only want last write time
                                        Win32Helper.RegQueryInfoKeyW(keyHandle, null, (IntPtr)0, (IntPtr)0, (IntPtr)0, (IntPtr)0, (IntPtr)0, (IntPtr)0, (IntPtr)0, (IntPtr)0, (IntPtr)0, lastInsertionDatePtr);
                                        Marshal.PtrToStructure(lastInsertionDatePtr, lastInsertionDate);
                                        insertionDates.Add(lastInsertionDate.ToString());
                                    }
                                }
                            }

                            //print out summary info on first iteration of instances of this usb drive
                            if (count == 0)
                            {
                                usbdata.AppendLine("     Found USB Device '" + friendlyName + "'");
                                usbdata.AppendLine("        Serial Num      :  " + serial);
                                usbdata.AppendLine("        Vendor          :  " + vendor);
                                usbdata.AppendLine("        Product         :  " + product);
                                usbdata.AppendLine("        Revision        :  " + revision);
                                usbdata.AppendLine("        Instances       :  " + instances.Length);
                            }

                            usbdata.AppendLine("           Date:  " + lastInsertionDate.dwHighDateTime.ToString() + "/" + lastInsertionDate.dwLowDateTime.ToString());
                            count++;
                        }

                        //add how many other insertion dates there were
                        string[] dts = (string[])insertionDates.ToArray(typeof(string));
                        usbdata.AppendLine("        InsertionDates  :  " + string.Join(",", dts));
                    }
                }

                return true;
            }

            /////////////////////////////////////////////////////
            //                                                 //
            // EnumerateAllWMIdata()                           //
            //                                                 //
            /////////////////////////////////////////////////////
            //Description:  This crazy unused function can output
            //              ALL of the data in the WMI database
            //              when the massive array of WMI classes
            //              variable is uncommented below...
            //Returns:      ..use with caution...
            /////////////////////////////////////////////////////
            public static bool EnumerateAllWMIdata(string Win32Class)
            {
                //string[] Win32Classes ={ "Win32_1394Controller", "Win32_1394ControllerDevice", "Win32_Account", "Win32_AccountSID", "Win32_ACE", "Win32_ActionCheck", "Win32_ActiveRoute", "Win32_AllocatedResource", "Win32_ApplicationCommandLine", "Win32_ApplicationService", "Win32_AssociatedBattery", "Win32_AssociatedProcessorMemory", "Win32_AutochkSetting", "Win32_BaseBoard", "Win32_BaseService", "Win32_Battery", "Win32_Binary", "Win32_BindImageAction", "Win32_BIOS", "Win32_BootConfiguration", "Win32_Bus", "Win32_CacheMemory", "Win32_CDROMDrive", "Win32_CheckCheck", "Win32_CIMLogicalDeviceCIMDataFile", "Win32_ClassicCOMApplicationClasses", "Win32_ClassicCOMClass", "Win32_ClassicCOMClassSetting", "Win32_ClassicCOMClassSettings", "Win32_ClassInfoAction", "Win32_ClientApplicationSetting", "Win32_CodecFile", "Win32_CollectionStatistics", "Win32_COMApplication", "Win32_COMApplicationClasses", "Win32_COMApplicationSettings", "Win32_COMClass", "Win32_ComClassAutoEmulator", "Win32_ComClassEmulator", "Win32_CommandLineAccess", "Win32_ComponentCategory", "Win32_ComputerShutdownEvent", "Win32_ComputerSystem", "Win32_ComputerSystemEvent", "Win32_ComputerSystemProcessor", "Win32_ComputerSystemProduct", "Win32_ComputerSystemWindowsProductActivationSetting", "Win32_COMSetting", "Win32_Condition", "Win32_ConnectionShare", "Win32_ControllerHasHub", "Win32_CreateFolderAction", "Win32_CurrentProbe", "Win32_CurrentTime", "Win32_DCOMApplication", "Win32_DCOMApplicationAccessAllowedSetting", "Win32_DCOMApplicationLaunchAllowedSetting", "Win32_DCOMApplicationSetting", "Win32_DefragAnalysis", "Win32_DependentService", "Win32_Desktop", "Win32_DesktopMonitor", "Win32_DeviceBus", "Win32_DeviceChangeEvent", "Win32_DeviceMemoryAddress", "Win32_DeviceSettings", "Win32_DFSNode", "Win32_DFSNodeTarget", "Win32_DFSTarget", "Win32_Directory", "Win32_DirectorySpecification", "Win32_DiskDrive", "Win32_DiskDrivePhysicalMedia", "Win32_DiskDriveToDiskPartition", "Win32_DiskPartition", "Win32_DiskQuota", "Win32_DisplayConfiguration", "Win32_DisplayControllerConfiguration", "Win32_DMAChannel", "Win32_DriverForDevice", "Win32_DriverVXD", "Win32_DuplicateFileAction", "Win32_Environment", "Win32_EnvironmentSpecification", "Win32_ExtensionInfoAction", "Win32_Fan", "Win32_FileSpecification", "Win32_FloppyController", "Win32_FloppyDrive", "Win32_FontInfoAction", "Win32_Group", "Win32_GroupInDomain", "Win32_GroupUser", "Win32_HeatPipe", "Win32_IDEController", "Win32_IDEControllerDevice", "Win32_ImplementedCategory", "Win32_InfraredDevice", "Win32_IniFileSpecification", "Win32_InstalledSoftwareElement", "Win32_IP4PersistedRouteTable", "Win32_IP4RouteTable", "Win32_IP4RouteTableEvent", "Win32_IRQResource", "Win32_JobObjectStatus", "Win32_Keyboard", "Win32_LaunchCondition", "Win32_LoadOrderGroup", "Win32_LoadOrderGroupServiceDependencies", "Win32_LoadOrderGroupServiceMembers", "Win32_LocalTime", "Win32_LoggedOnUser", "Win32_LogicalDisk", "Win32_LogicalDiskRootDirectory", "Win32_LogicalDiskToPartition", "Win32_LogicalFileAccess", "Win32_LogicalFileAuditing", "Win32_LogicalFileGroup", "Win32_LogicalFileOwner", "Win32_LogicalFileSecuritySetting", "Win32_LogicalMemoryConfiguration", "Win32_LogicalProgramGroup", "Win32_LogicalProgramGroupDirectory", "Win32_LogicalProgramGroupItem", "Win32_LogicalProgramGroupItemDataFile", "Win32_LogicalShareAccess", "Win32_LogicalShareAuditing", "Win32_LogicalShareSecuritySetting", "Win32_LogonSession", "Win32_LogonSessionMappedDisk", "Win32_LUID", "Win32_LUIDandAttributes", "Win32_ManagedSystemElementResource", "Win32_MappedLogicalDisk", "Win32_MemoryArray", "Win32_MemoryArrayLocation", "Win32_MemoryDevice", "Win32_MemoryDeviceArray", "Win32_MemoryDeviceLocation", "Win32_MethodParameterClass", "Win32_MIMEInfoAction", "Win32_ModuleLoadTrace", "Win32_ModuleTrace", "Win32_MotherboardDevice", "Win32_MountPoint", "Win32_MoveFileAction", "Win32_MSIResource", "Win32_NamedJobObject", "Win32_NamedJobObjectActgInfo", "Win32_NamedJobObjectLimit", "Win32_NamedJobObjectLimitSetting", "Win32_NamedJobObjectProcess", "Win32_NamedJobObjectSecLimit", "Win32_NamedJobObjectSecLimitSetting", "Win32_NamedJobObjectStatistics", "Win32_NetworkAdapter", "Win32_NetworkAdapterConfiguration", "Win32_NetworkAdapterSetting", "Win32_NetworkClient", "Win32_NetworkConnection", "Win32_NetworkLoginProfile", "Win32_NetworkProtocol", "Win32_NTDomain", "Win32_NTEventlogFile", "Win32_NTLogEvent", "Win32_NTLogEventComputer", "Win32_NTLogEventLog", "Win32_NTLogEventUser", "Win32_ODBCAttribute", "Win32_ODBCDataSourceAttribute", "Win32_ODBCDataSourceSpecification", "Win32_ODBCDriverAttribute", "Win32_ODBCDriverSoftwareElement", "Win32_ODBCDriverSpecification", "Win32_ODBCSourceAttribute", "Win32_ODBCTranslatorSpecification", "Win32_OnBoardDevice", "Win32_OperatingSystem", "Win32_OperatingSystemAutochkSetting", "Win32_OperatingSystemQFE", "Win32_OSRecoveryConfiguration", "Win32_PageFile", "Win32_PageFileElementSetting", "Win32_PageFileSetting", "Win32_PageFileUsage", "Win32_ParallelPort", "Win32_Patch", "Win32_PatchFile", "Win32_PatchPackage", "Win32_PCMCIAController", "Win32_Perf", "Win32_PerfFormattedData", "Win32_PerfFormattedData_ASP_ActiveServerPages", "Win32_PerfFormattedData_ContentFilter_IndexingServiceFilter", "Win32_PerfFormattedData_ContentIndex_IndexingService", "Win32_PerfFormattedData_InetInfo_InternetInformationServicesGlobal", "Win32_PerfFormattedData_ISAPISearch_HttpIndexingService", "Win32_PerfFormattedData_MSDTC_DistributedTransactionCoordinator", "Win32_PerfFormattedData_NTFSDRV_SMTPNTFSStoreDriver", "Win32_PerfFormattedData_PerfDisk_LogicalDisk", "Win32_PerfFormattedData_PerfDisk_PhysicalDisk", "Win32_PerfFormattedData_PerfNet_Browser", "Win32_PerfFormattedData_PerfNet_Redirector", "Win32_PerfFormattedData_PerfNet_Server", "Win32_PerfFormattedData_PerfNet_ServerWorkQueues", "Win32_PerfFormattedData_PerfOS_Cache", "Win32_PerfFormattedData_PerfOS_Memory", "Win32_PerfFormattedData_PerfOS_Objects", "Win32_PerfFormattedData_PerfOS_PagingFile", "Win32_PerfFormattedData_PerfOS_Processor", "Win32_PerfFormattedData_PerfOS_System", "Win32_PerfFormattedData_PerfProc_FullImage_Costly", "Win32_PerfFormattedData_PerfProc_Image_Costly", "Win32_PerfFormattedData_PerfProc_JobObject", "Win32_PerfFormattedData_PerfProc_JobObjectDetails", "Win32_PerfFormattedData_PerfProc_Process", "Win32_PerfFormattedData_PerfProc_ProcessAddressSpace_Costly", "Win32_PerfFormattedData_PerfProc_Thread", "Win32_PerfFormattedData_PerfProc_ThreadDetails_Costly", "Win32_PerfFormattedData_PSched_PSchedFlow", "Win32_PerfFormattedData_PSched_PSchedPipe", "Win32_PerfFormattedData_RemoteAccess_RASPort", "Win32_PerfFormattedData_RemoteAccess_RASTotal", "Win32_PerfFormattedData_RSVP_ACSRSVPInterfaces", "Win32_PerfFormattedData_RSVP_ACSRSVPService", "Win32_PerfFormattedData_SMTPSVC_SMTPServer", "Win32_PerfFormattedData_Spooler_PrintQueue", "Win32_PerfFormattedData_TapiSrv_Telephony", "Win32_PerfFormattedData_Tcpip_ICMP", "Win32_PerfFormattedData_Tcpip_IP", "Win32_PerfFormattedData_Tcpip_NBTConnection", "Win32_PerfFormattedData_Tcpip_NetworkInterface", "Win32_PerfFormattedData_Tcpip_TCP", "Win32_PerfFormattedData_Tcpip_UDP", "Win32_PerfFormattedData_TermService_TerminalServices", "Win32_PerfFormattedData_TermService_TerminalServicesSession", "Win32_PerfFormattedData_W3SVC_WebService", "Win32_PerfRawData", "Win32_PerfRawData_ASP_ActiveServerPages", "Win32_PerfRawData_ContentFilter_IndexingServiceFilter", "Win32_PerfRawData_ContentIndex_IndexingService", "Win32_PerfRawData_InetInfo_InternetInformationServicesGlobal", "Win32_PerfRawData_ISAPISearch_HttpIndexingService", "Win32_PerfRawData_MSDTC_DistributedTransactionCoordinator", "Win32_PerfRawData_NTFSDRV_SMTPNTFSStoreDriver", "Win32_PerfRawData_PerfDisk_LogicalDisk", "Win32_PerfRawData_PerfDisk_PhysicalDisk", "Win32_PerfRawData_PerfNet_Browser", "Win32_PerfRawData_PerfNet_Redirector", "Win32_PerfRawData_PerfNet_Server", "Win32_PerfRawData_PerfNet_ServerWorkQueues", "Win32_PerfRawData_PerfOS_Cache", "Win32_PerfRawData_PerfOS_Memory", "Win32_PerfRawData_PerfOS_Objects", "Win32_PerfRawData_PerfOS_PagingFile", "Win32_PerfRawData_PerfOS_Processor", "Win32_PerfRawData_PerfOS_System", "Win32_PerfRawData_PerfProc_FullImage_Costly", "Win32_PerfRawData_PerfProc_Image_Costly", "Win32_PerfRawData_PerfProc_JobObject", "Win32_PerfRawData_PerfProc_JobObjectDetails", "Win32_PerfRawData_PerfProc_Process", "Win32_PerfRawData_PerfProc_ProcessAddressSpace_Costly", "Win32_PerfRawData_PerfProc_Thread", "Win32_PerfRawData_PerfProc_ThreadDetails_Costly", "Win32_PerfRawData_PSched_PSchedFlow", "Win32_PerfRawData_PSched_PSchedPipe", "Win32_PerfRawData_RemoteAccess_RASPort", "Win32_PerfRawData_RemoteAccess_RASTotal", "Win32_PerfRawData_RSVP_ACSRSVPInterfaces", "Win32_PerfRawData_RSVP_ACSRSVPService", "Win32_PerfRawData_SMTPSVC_SMTPServer", "Win32_PerfRawData_Spooler_PrintQueue", "Win32_PerfRawData_TapiSrv_Telephony", "Win32_PerfRawData_Tcpip_ICMP", "Win32_PerfRawData_Tcpip_IP", "Win32_PerfRawData_Tcpip_NBTConnection", "Win32_PerfRawData_Tcpip_NetworkInterface", "Win32_PerfRawData_Tcpip_TCP", "Win32_PerfRawData_Tcpip_UDP", "Win32_PerfRawData_TermService_TerminalServices", "Win32_PerfRawData_TermService_TerminalServicesSession", "Win32_PerfRawData_W3SVC_WebService", "Win32_PhysicalMedia", "Win32_PhysicalMemory", "Win32_PhysicalMemoryArray", "Win32_PhysicalMemoryLocation", "Win32_PingStatus", "Win32_PnPAllocatedResource", "Win32_PnPDevice", "Win32_PnPEntity", "Win32_PnPSignedDriver", "Win32_PnPSignedDriverCIMDataFile", "Win32_PointingDevice", "Win32_PortableBattery", "Win32_PortConnector", "Win32_PortResource", "Win32_POTSModem", "Win32_POTSModemToSerialPort", "Win32_PowerManagementEvent", "Win32_Printer", "Win32_PrinterConfiguration", "Win32_PrinterController", "Win32_PrinterDriver", "Win32_PrinterDriverDll", "Win32_PrinterSetting", "Win32_PrinterShare", "Win32_PrintJob", "Win32_PrivilegesStatus", "Win32_Process", "Win32_Processor", "Win32_ProcessStartTrace", "Win32_ProcessStartup", "Win32_ProcessStopTrace", "Win32_ProcessTrace", "Win32_Product", "Win32_ProductCheck", "Win32_ProductResource", "Win32_ProductSoftwareFeatures", "Win32_ProgIDSpecification", "Win32_ProgramGroup", "Win32_ProgramGroupContents", "Win32_ProgramGroupOrItem", "Win32_Property", "Win32_ProtocolBinding", "Win32_Proxy", "Win32_PublishComponentAction", "Win32_QuickFixEngineering", "Win32_QuotaSetting", "Win32_Refrigeration", "Win32_Registry", "Win32_RegistryAction", "Win32_RemoveFileAction", "Win32_RemoveIniAction", "Win32_ReserveCost", "Win32_ScheduledJob", "Win32_SCSIController", "Win32_SCSIControllerDevice", "Win32_SecurityDescriptor", "Win32_SecurityDescriptorHelper", "Win32_SecuritySetting", "Win32_SecuritySettingAccess", "Win32_SecuritySettingAuditing", "Win32_SecuritySettingGroup", "Win32_SecuritySettingOfLogicalFile", "Win32_SecuritySettingOfLogicalShare", "Win32_SecuritySettingOfObject", "Win32_SecuritySettingOwner", "Win32_SelfRegModuleAction", "Win32_SerialPort", "Win32_SerialPortConfiguration", "Win32_SerialPortSetting", "Win32_ServerConnection", "Win32_ServerFeature", "Win32_ServerSession", "Win32_Service", "Win32_ServiceControl", "Win32_ServiceSpecification", "Win32_ServiceSpecificationService", "Win32_Session", "Win32_SessionConnection", "Win32_SessionProcess", "Win32_SettingCheck", "Win32_ShadowBy", "Win32_ShadowContext", "Win32_ShadowCopy", "Win32_ShadowDiffVolumeSupport", "Win32_ShadowFor", "Win32_ShadowOn", "Win32_ShadowProvider", "Win32_ShadowStorage", "Win32_ShadowVolumeSupport", "Win32_Share", "Win32_ShareToDirectory", "Win32_ShortcutAction", "Win32_ShortcutFile", "Win32_ShortcutSAP", "Win32_SID", "Win32_SIDandAttributes", "Win32_SMBIOSMemory", "Win32_SoftwareElement", "Win32_SoftwareElementAction", "Win32_SoftwareElementCheck", "Win32_SoftwareElementCondition", "Win32_SoftwareElementResource", "Win32_SoftwareFeature", "Win32_SoftwareFeatureAction", "Win32_SoftwareFeatureCheck", "Win32_SoftwareFeatureParent", "Win32_SoftwareFeatureSoftwareElements", "Win32_SoundDevice", "Win32_StartupCommand", "Win32_SubDirectory", "Win32_SystemAccount", "Win32_SystemBIOS", "Win32_SystemBootConfiguration", "Win32_SystemConfigurationChangeEvent", "Win32_SystemDesktop", "Win32_SystemDevices", "Win32_SystemDriver", "Win32_SystemDriverPnPEntity", "Win32_SystemEnclosure", "Win32_SystemLoadOrderGroups", "Win32_SystemLogicalMemoryConfiguration", "Win32_SystemMemoryResource", "Win32_SystemNetworkConnections", "Win32_SystemOperatingSystem", "Win32_SystemPartitions", "Win32_SystemProcesses", "Win32_SystemProgramGroups", "Win32_SystemResources", "Win32_SystemServices", "Win32_SystemSetting", "Win32_SystemSlot", "Win32_SystemSystemDriver", "Win32_SystemTimeZone", "Win32_SystemTrace", "Win32_SystemUsers", "Win32_TapeDrive", "Win32_TCPIPPrinterPort", "Win32_TemperatureProbe", "Win32_Thread", "Win32_ThreadStartTrace", "Win32_ThreadStopTrace", "Win32_ThreadTrace", "Win32_TimeZone", "Win32_TokenGroups", "Win32_TokenPrivileges", "Win32_Trustee", "Win32_TypeLibraryAction", "Win32_UninterruptiblePowerSupply", "Win32_USBController", "Win32_USBControllerDevice", "Win32_USBHub", "Win32_UserAccount", "Win32_UserDesktop", "Win32_UserInDomain", "Win32_UTCTime", "Win32_VideoConfiguration", "Win32_VideoController", "Win32_VideoSettings", "Win32_VoltageProbe", "Win32_Volume", "Win32_VolumeChangeEvent", "Win32_VolumeQuota", "Win32_VolumeQuotaSetting", "Win32_VolumeUserQuota", "Win32_WindowsProductActivation", "Win32_WMIElementSetting", "Win32_WMISetting" };
                SelectQuery hwquery = new SelectQuery("SELECT * FROM " + Win32Class);
                ManagementObjectSearcher search = new ManagementObjectSearcher(hwquery);
                foreach (ManagementObject mObject in search.Get())
                    foreach (PropertyData prop in mObject.Properties)
                        AgentScanLog.AppendLine(prop.Name + "=" + prop.Value);
                return true;
            }
        }
    }
}
