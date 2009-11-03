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
using Microsoft.Win32;
using System.ComponentModel;
using System.ServiceProcess;
using CwHandler;

namespace CwAgent
{
    public static class ServiceHelper
    {
        #region SERVICE CONTROL MANAGER ROUTINES

        /////////////////////////////////////////////////////
        //                                                 //
        // QueryService()                                  //
        //                                                 //
        /////////////////////////////////////////////////////
        //Description:  gets the status of a given service
        //Returns:      
        /////////////////////////////////////////////////////
        internal static long GetServiceStatus(string serviceName)
        {
            //open connection to SCM
            IntPtr hSCM = Win32Helper.OpenSCManager(null, null, Win32Helper.SC_MANAGER_ALL_ACCESS);

            if (hSCM == IntPtr.Zero)
                throw new Exception("OpenSCManager():  " + Win32Helper.GetLastError32());

            //open a handle to the service via SCM
            IntPtr hSvc = Win32Helper.OpenService(hSCM, serviceName, Win32Helper.SERVICE_ALL_ACCESS);

            if (hSvc == IntPtr.Zero)
            {
                Win32Helper.CloseServiceHandle(hSCM);
                throw new Exception("OpenService():  " + Win32Helper.GetLastError32());
            }

            uint pcbBytesNeeded = 0;

            //get the size of buffer we need for calling this API -- this call will always fail, and we want it to.
            if (!Win32Helper.QueryServiceStatusEx(hSvc, Win32Helper.SC_STATUS_PROCESS_INFO, IntPtr.Zero, 0, ref pcbBytesNeeded))
            {
                if (Win32Helper.GetLastError() == Win32Helper.ERROR_INSUFFICIENT_BUFFER)
                {
                    IntPtr lpServiceStatusProcess = Marshal.AllocHGlobal((int)pcbBytesNeeded);
                    uint dummy = 0;

                    //now query with that allocated buffer
                    if (Win32Helper.QueryServiceStatusEx(hSvc, Win32Helper.SC_STATUS_PROCESS_INFO, lpServiceStatusProcess, pcbBytesNeeded, ref dummy))
                    {
                        //success.  marshal the struct from unamanged mem
                        Win32Helper.SERVICE_STATUS_PROCESS ServiceStatusProcess = new Win32Helper.SERVICE_STATUS_PROCESS();
                        ServiceStatusProcess = (Win32Helper.SERVICE_STATUS_PROCESS)Marshal.PtrToStructure(lpServiceStatusProcess, typeof(Win32Helper.SERVICE_STATUS_PROCESS));
                        Win32Helper.CloseServiceHandle(hSvc);
                        Win32Helper.CloseServiceHandle(hSCM);
                        long ret = ServiceStatusProcess.dwCurrentState;
                        Marshal.FreeHGlobal(lpServiceStatusProcess);
                        return ret;
                    }
                    else
                    {
                        Marshal.FreeHGlobal(lpServiceStatusProcess);
                        Win32Helper.CloseServiceHandle(hSvc);
                        Win32Helper.CloseServiceHandle(hSCM);
                        throw new Exception("QueryServiceStatusEx():  " + Win32Helper.GetLastError32());
                    }
                }
                else
                {
                    Win32Helper.CloseServiceHandle(hSvc);
                    Win32Helper.CloseServiceHandle(hSCM);
                    throw new Exception("QueryServiceStatusEx() returned an unrecognized value:  " + Win32Helper.GetLastError32());
                }
            }

            return 0;
        }

        /////////////////////////////////////////////////////
        //                                                 //
        // StartService()                                  //
        //                                                 //
        /////////////////////////////////////////////////////
        //Description:  starts the given service using SCM
        //Returns:      
        /////////////////////////////////////////////////////
        //NB:  while debugging the SCM, a useful command for wiping the service:
        //      sc delete "<service name>" from cmd prompt
        internal static bool StartService(string serviceName, string[] parameters)
        {
            if (parameters == null)
                parameters = new string[] { "" };

            //open connection to SCM
            IntPtr hSCM = Win32Helper.OpenSCManager(null, null, Win32Helper.SC_MANAGER_ALL_ACCESS);

            if (hSCM == IntPtr.Zero)
                throw new Exception("OpenSCManager():  " + Win32Helper.GetLastError32());

            //open a handle to the service via SCM
            IntPtr hSvc = Win32Helper.OpenService(hSCM, serviceName, Win32Helper.SERVICE_ALL_ACCESS);

            if (hSvc == IntPtr.Zero)
            {
                Win32Helper.CloseServiceHandle(hSCM);
                throw new Exception("OpenService():  " + Win32Helper.GetLastError32());
            }

            //start the service given the above handle
            if (Win32Helper.StartService(hSvc, 0, null))
            {
                Win32Helper.CloseServiceHandle(hSvc);
                Win32Helper.CloseServiceHandle(hSCM);
                return true;
            }

            Win32Helper.CloseServiceHandle(hSvc);
            Win32Helper.CloseServiceHandle(hSCM);
            return false;
        }

        /////////////////////////////////////////////////////
        //                                                 //
        // ServiceExists()                                 //
        //                                                 //
        /////////////////////////////////////////////////////
        //Description:  queries SCM to see if given service name
        //              exists.
        //Returns:      
        /////////////////////////////////////////////////////
        //NB:  registry key location is:
        //  HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\<service name>
        internal static bool ServiceExists(string serviceName)
        {
            //open connection to SCM
            IntPtr hSCM = Win32Helper.OpenSCManager(null, null, Win32Helper.SC_MANAGER_ALL_ACCESS);

            if (hSCM == IntPtr.Zero)
                throw new Exception("OpenSCManager():  " + Win32Helper.GetLastError32());

            //try to open the service.
            IntPtr hSvc = Win32Helper.OpenService(hSCM, serviceName, Win32Helper.SERVICE_ALL_ACCESS);
            int errCode = -1;

            //if the handle returned is NULL, then the service either
            //doesn't exist or we don't have access or the name was invalid
            if (hSvc == IntPtr.Zero)
            {
                errCode = Marshal.GetLastWin32Error();

                //if any of these error conditions are true, we should
                //throw an exception and quit
                if (errCode == Win32Helper.ERROR_ACCESS_DENIED ||
                    errCode == Win32Helper.ERROR_INVALID_HANDLE ||
                    errCode == Win32Helper.ERROR_INVALID_NAME)
                {
                    Win32Helper.CloseServiceHandle(hSCM);
                    throw new Exception("OpenService():  " + Win32Helper.GetLastError32());
                }
                //however, if we get the error code that the service does not
                //exist, then this is what we wanted to know!
                else if (errCode == Win32Helper.ERROR_SERVICE_DOES_NOT_EXIST)
                {
                    Win32Helper.CloseServiceHandle(hSCM);
                    return false;
                }
                //otherwise, some other error...
                else
                {
                    Win32Helper.CloseServiceHandle(hSCM);
                    throw new Exception("Could not open service.  Error code:  " + errCode.ToString());
                }
            }

            //if we got to this point, the service was valid
            Win32Helper.CloseServiceHandle(hSCM);
            Win32Helper.CloseServiceHandle(hSvc);

            return true;
        }

        /////////////////////////////////////////////////////
        //                                                 //
        // CreateService()                                 //
        //                                                 //
        /////////////////////////////////////////////////////
        //Description:  queries SCM to create the service
        //Returns:      true if successful
        /////////////////////////////////////////////////////
        internal static bool CreateService(string serviceName, string serviceDisplayName, int serviceType, int serviceStartType, string exePathWithArguments)
        {
            //open connection to SCM
            IntPtr hSCM = IntPtr.Zero, hSc = IntPtr.Zero;
            int maxAttempts = 5, numAttempts = 0;

            //for some reason, CreateService() will crap out on the first try,
            //so always try multiple times.
            do
            {
                hSCM = Win32Helper.OpenSCManager(null, null, Win32Helper.SC_MANAGER_ALL_ACCESS);

                if (hSCM == IntPtr.Zero)
                    throw new Exception("OpenSCManager():  " + Win32Helper.GetLastError32());

                //register and install our service using SCM connection
                hSc = Win32Helper.CreateService(
                             hSCM,                                  //conn to SCM
                             serviceName,           	            //svc name
                             serviceDisplayName,    	            //display name
                             Win32Helper.SERVICE_ALL_ACCESS,	    //all access :) 
                             serviceType,                       	//service type
                             serviceStartType,              	    //start now by SCM 
                             Win32Helper.SERVICE_ERROR_NORMAL,	    //we are bug free!
                             exePathWithArguments,     	            //path 2 service binary + program args
                             null,		                            //we dont belong to a load ordering group 
                             0,		                                //no load order group, so no tag!
                             null,		                            //we dont depend on any other svc
                             null,		                            //LocalSystem account, please.
                             null);                                 //no password to access this service

                //quit unconditionally if null pointer received
                if (hSc == IntPtr.Zero)
                {
                    Win32Helper.CloseServiceHandle(hSCM);
                    throw new Exception("CreateService():  " + Win32Helper.GetLastError32());
                }
                //if it whines about SCM handle being bad, close it and open again
                else if (Win32Helper.GetLastError() == Win32Helper.ERROR_INVALID_HANDLE)
                {
                    Win32Helper.CloseServiceHandle(hSc);
                    Win32Helper.CloseServiceHandle(hSCM);
                    numAttempts++;
                    continue;
                }
                else
                {
                    break;
                }
            }
            while (Win32Helper.GetLastError() == Win32Helper.ERROR_INVALID_HANDLE && numAttempts < maxAttempts);

            Win32Helper.CloseServiceHandle(hSCM);
            Win32Helper.CloseServiceHandle(hSc);

            return true;
        }

        /////////////////////////////////////////////////////
        //                                                 //
        // StopService()                                   //
        //                                                 //
        /////////////////////////////////////////////////////
        //Description:  queries SCM to stop the service
        //Returns:      true if successful
        /////////////////////////////////////////////////////
        internal static bool StopService(string serviceName)
        {
            //open connection to SCM
            IntPtr hSCM = Win32Helper.OpenSCManager(null, null, Win32Helper.SC_MANAGER_ALL_ACCESS);

            if (hSCM == IntPtr.Zero)
                throw new Exception("OpenSCManager():  " + Win32Helper.GetLastError32());

            //open a handle to the service itself
            IntPtr hSvc = Win32Helper.OpenService(hSCM, serviceName, Win32Helper.SERVICE_ALL_ACCESS);

            //if the handle returned is NULL, then the service either
            //doesn't exist or we don't have access or the name was invalid
            if (hSvc == IntPtr.Zero)
            {
                Win32Helper.CloseServiceHandle(hSCM);
                throw new Exception("StopService():  failed to retrieve service handle.");
            }

            //create a SERVICE_STATUS structure to send with the stop code
            IntPtr lpServiceStatus = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(Win32Helper.SERVICE_STATUS)));

            //send it a STOP control code - according to MSDN, the SCM will ALWAYS wait for up to 30 seconds
            //for the target service to respond to our control code.
            if (!Win32Helper.ControlService(hSvc, Win32Helper.SERVICE_CONTROL_STOP, lpServiceStatus))
            {
                Win32Helper.CloseServiceHandle(hSCM);
                Win32Helper.CloseServiceHandle(hSvc);
                Marshal.FreeHGlobal(lpServiceStatus);
                throw new Exception("ControlService():  Failed to send STOP code:  " + Win32Helper.GetLastError32());
            }

            //
            //TODO:  if this fails due to access issues, modify the service's DACL as shown here:
            //http://msdn.microsoft.com/en-us/library/ms684215(VS.85).aspx
            //

            Win32Helper.CloseServiceHandle(hSCM);
            Win32Helper.CloseServiceHandle(hSvc);
            Marshal.FreeHGlobal(lpServiceStatus);

            return true;
        }

        /////////////////////////////////////////////////////
        //                                                 //
        // RemoveService()                                 //
        //                                                 //
        /////////////////////////////////////////////////////
        //Description:  queries SCM to remove the service
        //Returns:      true if successful
        /////////////////////////////////////////////////////
        internal static bool RemoveService(string serviceName)
        {
            //open connection to SCM
            IntPtr hSCM = Win32Helper.OpenSCManager(null, null, Win32Helper.SC_MANAGER_ALL_ACCESS);

            if (hSCM == IntPtr.Zero)
                throw new Exception("OpenSCManager():  " + Win32Helper.GetLastError32());

            //open a handle to the service itself
            IntPtr hSvc = Win32Helper.OpenService(hSCM, serviceName, Win32Helper.SERVICE_ALL_ACCESS);
            int errCode = -1;

            //if the handle returned is NULL, then the service either
            //doesn't exist or we don't have access or the name was invalid
            if (hSvc == IntPtr.Zero)
            {
                errCode = Marshal.GetLastWin32Error();

                //if any of these error conditions are true, we should
                //throw an exception and quit
                if (errCode == Win32Helper.ERROR_ACCESS_DENIED ||
                    errCode == Win32Helper.ERROR_INVALID_HANDLE ||
                    errCode == Win32Helper.ERROR_INVALID_NAME)
                {
                    Win32Helper.CloseServiceHandle(hSCM);
                    throw new Exception("OpenService():  " + Win32Helper.GetLastError32());
                }
                //service doesn't exist, just exit gracefully
                else if (errCode == Win32Helper.ERROR_SERVICE_DOES_NOT_EXIST)
                {
                    Console.WriteLine("Warning: SCM says the service '" + serviceName + "' doesn't exist!");
                    Win32Helper.CloseServiceHandle(hSCM);
                    return true;
                }
                //otherwise, some other error...
                else
                {
                    Win32Helper.CloseServiceHandle(hSCM);
                    throw new Exception("Could not open service.  Error code:  " + errCode.ToString());
                }
            }

            if (!Win32Helper.DeleteService(hSvc))
            {
                Win32Helper.CloseServiceHandle(hSCM);
                Win32Helper.CloseServiceHandle(hSvc);
                throw new Exception("DeleteService():  " + Win32Helper.GetLastError32());
            }

            Win32Helper.CloseServiceHandle(hSCM);
            Win32Helper.CloseServiceHandle(hSvc);

            return true;
        }

        /////////////////////////////////////////////////////
        //                                                 //
        // RemoveServiceRegistry()                         //
        //                                                 //
        /////////////////////////////////////////////////////
        //Description:  manually deletes the service's registry
        //              entries.  This is all the SCM does when
        //              you call the Win32 API DeleteService():
        //              http://msdn.microsoft.com/en-us/library/ms682562.aspx
        //
        //Returns:      true if successful
        /////////////////////////////////////////////////////
        internal static void RemoveServiceRegistry(string serviceName, ref bool success)
        {
            RegistryKey key = Registry.LocalMachine;
            string subkey1 = "SYSTEM\\ControlSet001\\Services\\" + serviceName;
            string subkey2 = "SYSTEM\\ControlSet002\\Services\\" + serviceName;
            string subkey3 = "SYSTEM\\CurrentControlSet\\Services\\" + serviceName;
            bool key1success = false, key2success = false, key3success = false;

            try
            {
                key.OpenSubKey(subkey1, true);
                key.DeleteSubKey(subkey1);
            }
            catch (Exception) { } //gulp
            try
            {
                key.OpenSubKey(subkey2, true);
                key.DeleteSubKey(subkey2);
            }
            catch (Exception) { } //gulp
            try
            {
                key.OpenSubKey(subkey3, true);
                key.DeleteSubKey(subkey3);
            }
            catch (Exception) { } //gulp

            if (key1success && key2success && key3success)
                success = true;
        }

        /////////////////////////////////////////////////////
        //                                                 //
        // SetServiceStatus()                              //
        //                                                 //
        /////////////////////////////////////////////////////
        //Description:  sets the status of our service; this
        //              function should ONLY be used for the
        //              agent service - not kernel driver.
        //
        //Returns:      void
        /////////////////////////////////////////////////////
        internal static void SetServiceStatus(IntPtr svcStatusHandle, uint code, ref bool success)
        {
            success = false;

            //marshal the ptr to the SERVICE_STATUS_HANDLE structure to pass to SetServiceStatus()
            Win32Helper.SERVICE_STATUS_HANDLE__ hStatus = (Win32Helper.SERVICE_STATUS_HANDLE__)Marshal.PtrToStructure(svcStatusHandle, typeof(Win32Helper.SERVICE_STATUS_HANDLE__));

            //build a SERVICE_STATUS structure to pass to SetServiceStatus()
            Win32Helper.SERVICE_STATUS status = new Win32Helper.SERVICE_STATUS();
            status.dwServiceType = Win32Helper.SERVICE_WIN32_OWN_PROCESS;
            status.dwCurrentState = code;
            status.dwControlsAccepted = Win32Helper.SERVICE_ACCEPT_STOP | Win32Helper.SERVICE_ACCEPT_PRESHUTDOWN | Win32Helper.SERVICE_ACCEPT_SHUTDOWN;

            //call SetServiceStatus() to notify the SCM we are up and running.
            if (Win32Helper.SetServiceStatus(ref hStatus, ref status))
                success = true;

        }

        #endregion
    }
}