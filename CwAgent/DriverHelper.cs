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
using System.Collections.Generic;
using System.Text;
using System.Security.Cryptography;
using System.IO;
using System.Collections;
using System.Runtime.InteropServices;
using System.Globalization;
using System.Reflection;
using System.ComponentModel;
using Microsoft.Win32.SafeHandles;
using CwHandler;

namespace CwAgent
{
    public partial class AgentScanner
    {
        public class DriverHelper
        {
            //------------------------------------------------------------------------
            //                        DRIVER LOADING ROUTINES
            //------------------------------------------------------------------------
            //      ExtractDriver() - writes driver from internal resource to internal variable
            //      SaveDriver() - calls ExtractDriver() and writes binary data from var to disk
            //      DeleteDriver() - deletes driver file from disk
            //      SysLoadAndCall() - loads driver into memory for execution using undoc method
            #region DRIVER LOADING ROUTINES

            /////////////////////////////////////////////////////
            //                                                 //
            // ExtractDriver()                                 //
            //                                                 //
            /////////////////////////////////////////////////////
            //Description:  Extract driver binary file from internal
            //              resource manifest.
            //
            //Returns:      true if successful
            //////////////////////////////////////////////////////
            public static bool ExtractDriver(string driverFilename, ref byte[] DriverBinaryData)
            {
                //extract the binary data which has been compiled in as a resource

                //Get executingAssembly to pass to driver, so it can extract
                //the driver sys file, which is embedded in the manifest asm
                Assembly a = Assembly.GetExecutingAssembly();
                Stream byteStream;

                try
                {
                    byteStream = a.GetManifestResourceStream("CwAgent.Resources." + driverFilename);
                }
                catch (Exception ex)
                {
                    throw new Exception("GetManifestResourceStream() failed:  " + ex.Message);
                }

                if (byteStream == null)
                    throw new Exception("Error:  The stream was empty.");
                
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

                byteStream.Flush();
                byteStream.Close();
                DriverBinaryData = buf;

                return true;
            }

            /////////////////////////////////////////////////////
            //                                                 //
            // SaveDriver()                                    //
            //                                                 //
            /////////////////////////////////////////////////////
            //Description:  Writes driver binary to disk.
            //
            //Returns:      true if successful
            //////////////////////////////////////////////////////
            public static bool SaveDriver(string drvFullPath, byte[] fileData)
            {
                FileInfo f;

                try
                {
                    f = new FileInfo(drvFullPath);
                }
                catch (Exception e)
                {
                    throw new Exception("SaveDriver() failed:  " + e.InnerException.Message);
                }

                FileStream outfile;
                BinaryWriter bw;

                //create the file on disk
                try
                {
                    outfile = File.Create(drvFullPath);
                }
                catch (Exception e)
                {
                    throw new Exception("File.Create():  " + e.Message);
                }

                //write driver binary data to it.
                try
                {
                    bw = new BinaryWriter(outfile);
                    bw.Write(fileData);
                    bw.Flush();
                    bw.Close();
                }
                catch (Exception e)
                {
                    throw new Exception("SaveDriver():  Failed writing binary data to file.\nError:  " + e.InnerException.Message);
                }

                return true;
            }


            /////////////////////////////////////////////////////
            //                                                 //
            // DeleteDriver()                                  //
            //                                                 //
            /////////////////////////////////////////////////////
            //Description:  Writes driver binary to disk.
            //
            //Returns:      Nothing
            //////////////////////////////////////////////////////
            public static void DeleteDriver(string drvFullPath, ref bool success)
            {
                FileInfo f = new FileInfo(drvFullPath);

                //if the driver exists on disk, remove it
                if (f.Exists)
                {
                    try
                    {
                        f.Delete();
                    }
                    catch (System.Security.SecurityException e)
                    {
                        throw new Exception("DeleteDriver():  " + e.Message);
                    }
                    catch (IOException e)
                    {
                        throw new Exception("DeleteDriver():  " + e.Message);
                    }
                    catch (UnauthorizedAccessException e)
                    {
                        throw new Exception("DeleteDriver():  " + e.Message);
                    }
                }
            }

            /////////////////////////////////////////////////////
            //                                                 //
            // SysLoadAndCall()                                //
            //                                                 //
            /////////////////////////////////////////////////////
            //Description:  Loads driver binary into memory using
            //              undocumented ZwSetSystemInformation().
            //
            //Returns:      Nothing
            //////////////////////////////////////////////////////
            internal unsafe static void SysLoadAndCall(string fullpath, ref bool success)
            {
                string drvFullPath = "\\\\??\\\\" + fullpath.Replace("\\", "\\\\");
                IntPtr pSystemLoadAndCallImage=IntPtr.Zero;
                Win32Helper.SYSTEM_LOAD_AND_CALL_IMAGE SystemLoadAndCallImage = new Win32Helper.SYSTEM_LOAD_AND_CALL_IMAGE();
                Win32Helper.UNICODE_STRING UnicodeString = new Win32Helper.UNICODE_STRING();

                //get pointers to the functions we need
                IntPtr RtlInitUnicodeString = Win32Helper.GetProcAddress(Win32Helper.GetModuleHandle("ntdll.dll"), "RtlInitUnicodeString");
                IntPtr ZwSetSystemInformation = Win32Helper.GetProcAddress(Win32Helper.GetModuleHandle("ntdll.dll"), "ZwSetSystemInformation");

                //marshal a delegate function from those pointers.
                if (RtlInitUnicodeString != IntPtr.Zero && ZwSetSystemInformation != IntPtr.Zero)
                {
                    //get delegate func for RtlInitUnicodeString()
                    Win32Helper.RtlInitUnicodeStringDelegate _RtlInitUnicodeString = (Win32Helper.RtlInitUnicodeStringDelegate)Marshal.GetDelegateForFunctionPointer(RtlInitUnicodeString, typeof(Win32Helper.RtlInitUnicodeStringDelegate));
                   
                    //get delegate func for ZwSetSystemInformation()
                    Win32Helper.ZwSetSystemInformationDelegate _ZwSetSystemInformation = (Win32Helper.ZwSetSystemInformationDelegate)Marshal.GetDelegateForFunctionPointer(ZwSetSystemInformation, typeof(Win32Helper.ZwSetSystemInformationDelegate));

                    //marshal a pointer to the unicode string field of the SystemLoadAndCall structure
                    //Marshal.StructureToPtr(SystemLoadAndCallImage.ModuleName, pUnicodeString, false);

                    //pass the pointer to the module name field of that structure to be initialized to the image path
                    _RtlInitUnicodeString(ref UnicodeString, drvFullPath);

                    SystemLoadAndCallImage.ModuleName = UnicodeString;

                    //get a pointer to our now-initialised LoadAndCallImage
                    Marshal.StructureToPtr(SystemLoadAndCallImage, pSystemLoadAndCallImage, false);

                    //pass that structure to ZwSetSystemInformation..and .. bam..
                    if (_ZwSetSystemInformation(38, pSystemLoadAndCallImage, (uint)Marshal.SizeOf(SystemLoadAndCallImage)))
                        success = true;
                }

                success = false;
            }

            #endregion
            
            #region DRIVER COMMUNICATION ROUTINES

            /////////////////////////////////////////////////////
            //                                                 //
            // SendDriverCommand()                             //
            //                                                 //
            /////////////////////////////////////////////////////
            //Description:  Sends the IOCTL to the driver.
            //
            //Throws:       Exception
            //
            //Returns:      num bytes written to lpOutBuf by driver.
            //              the driver writes data to lpOutBuf.
            //              Caller is responsible
            //              for setup/breakdown of in/out bufs.
            /////////////////////////////////////////////////////
            internal unsafe static int SendDriverCommand(uint ioctl, IntPtr lpInBuf, int InBufSize, ref IntPtr lpOutBuf, int OutBufSize)
            {
                //-----------------------------------
                //       OPEN HANDLE TO DRIVER
                //-----------------------------------
                //open a handle to our driver's device
                IntPtr hDevice = Win32Helper.CreateFile(
                                        "\\\\.\\" + CwConstants.DRIVER_SERVICE_NAME,
                                        Win32Helper.GENERIC_READ | Win32Helper.GENERIC_WRITE,
                                        Win32Helper.FILE_SHARE_READ | Win32Helper.FILE_SHARE_WRITE,
                                        IntPtr.Zero,
                                        Win32Helper.OPEN_EXISTING,
                                        Win32Helper.FILE_ATTRIBUTE_NORMAL,
                                        IntPtr.Zero);

                //if the handle is invalid (ie, -1), we failed to open the device.
                if (hDevice == (IntPtr)Win32Helper.ERROR_INVALID_HANDLE)  //(hDevice.IsInvalid)
                    throw new Exception("CreateFile():  Failed to open a handle to driver device object '"+CwConstants.DRIVER_SERVICE_NAME+"':  " + Win32Helper.GetLastError32()+" ("+Win32Helper.GetLastError().ToString()+")");

                //-----------------------------------
                //          SEND IOCTL
                //-----------------------------------
                int bytesReturned = 0;
                if (!Win32Helper.DeviceIoControl(hDevice, ioctl, lpInBuf, InBufSize, lpOutBuf, OutBufSize, ref bytesReturned, IntPtr.Zero))
                {
                    Win32Helper.CloseHandle(hDevice);
                    throw new Exception("DeviceIoControl():  Failed to send IOCTL 0x" + ioctl.ToString("x") + ":  " + Win32Helper.GetLastError32() + " (" + Win32Helper.GetLastError().ToString() + ")");
                }

                Win32Helper.CloseHandle(hDevice);

                return bytesReturned;
            }

            /////////////////////////////////////////////////////
            //                                                 //
            // GetDriverInfoStruct()                           //
            //                                                 //
            /////////////////////////////////////////////////////
            //Description:  Prepares a DRIVER_CHECK_INFO struct to
            //              pass to CwDriver.sys.
            //
            //Throws:       
            //
            //Returns:      true if successful
            /////////////////////////////////////////////////////
            internal unsafe static ArrayList GetDriverInfoStructs(string[] items)
            {
                ArrayList driversToCheck = new ArrayList();

                //----------------------
                //GET UNICODE STRINGS
                //----------------------
                IntPtr hNtdll = Win32Helper.GetModuleHandle("ntdll.dll");

                if (hNtdll == IntPtr.Zero)
                {
                    AgentScanLog.AppendLine("GetDriverInfoStructs() failed to get handle to ntdll.dll:  " + Win32Helper.GetLastError32());
                    return null;
                }

                //1. find the address of RtlInitUnicodeString
                IntPtr RtlInitUnicodeString = IntPtr.Zero;
                try
                {
                    RtlInitUnicodeString = Win32Helper.GetProcAddress(hNtdll, "RtlInitUnicodeString");
                }
                catch (Exception ex)
                {
                    Win32Helper.CloseHandle(hNtdll);
                    AgentScanLog.AppendLine("GetDriverInfoStructs() failed to get address of RtlInitUnicodeString:  " + ex.Message);
                    return null;
                }

                if (RtlInitUnicodeString == IntPtr.Zero)
                {
                    Win32Helper.CloseHandle(hNtdll);
                    AgentScanLog.AppendLine("GetDriverInfoStructs() returned a null address for RtlInitUnicodeString().");
                    return null;
                }

                //2.  marshal a delegate function from that pointer
                Win32Helper.RtlInitUnicodeStringDelegate _RtlInitUnicodeString;

                try
                {
                    _RtlInitUnicodeString = (Win32Helper.RtlInitUnicodeStringDelegate)Marshal.GetDelegateForFunctionPointer(RtlInitUnicodeString, typeof(Win32Helper.RtlInitUnicodeStringDelegate));
                }
                catch (Exception ex)
                {
                    Win32Helper.CloseHandle(hNtdll);
                    AgentScanLog.AppendLine("GetDriverInfoStructs() failed to retrieve delegate pointer:  " + ex.Message);
                    return null;
                }

                //loop over drivers/devices to process
                for (int i = 0; i < items.Length / 2; i += 2)
                {
                    CwStructures.DRIVER_CHECK_INFO aDriverToCheck = new CwStructures.DRIVER_CHECK_INFO();
                    //3.  call RtlInitUnicodeString to fill our unicode strings with the driver's name and device name
                    Win32Helper.UNICODE_STRING uDriverName = new Win32Helper.UNICODE_STRING();
                    Win32Helper.UNICODE_STRING uDeviceName = new Win32Helper.UNICODE_STRING();
                    _RtlInitUnicodeString(ref uDriverName, items[i]);
                    _RtlInitUnicodeString(ref uDeviceName, items[i + 1]);

                    //4.  store the resulting pointer in our object
                    aDriverToCheck.DriverName = uDriverName;
                    aDriverToCheck.DriverDeviceName = uDeviceName;
                    driversToCheck.Add(aDriverToCheck);
                }

                Win32Helper.CloseHandle(hNtdll);

                return driversToCheck;
            }

            #endregion
        }
    }
}