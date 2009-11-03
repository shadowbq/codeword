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
using CwAgent;

namespace CwHandler
{
    #region CONSTANTS
    public static class CwConstants
    {
        internal const string AGENT_BINARY_NAME="CwAgent.exe";
        internal const string AGENT_SERVICE_NAME = "CwAgent";

        //---------------------------------------------------
        //              COMMUNICATION CONSTANTS
        //---------------------------------------------------
        //communication constants, in seconds.
        internal const int STREAM_DEFAULT_READ_TIMEOUT = 5;
        internal const int STREAM_DEFAULT_WRITE_TIMEOUT = 5;
        internal const int STREAM_SCAN_TASK_TIMEOUT = 600;
        internal const int STREAM_UPDATE_SIGNATURES_TIMEOUT = 30;
        internal const int STREAM_MITIGATE_TASK_TIMEOUT = 60;
        internal const int STREAM_GETSYSTEMINFO_TASK_TIMEOUT = 10;
        internal const int STREAM_COLLECT_TASK_TIMEOUT = 300;

        //---------------------------------------------------
        //     AGENT COMMANDS ISSUED BY ADMIN CONSOLE
        //---------------------------------------------------
        internal const int AGENTCMD_STARTSCAN = 1;
        internal const int AGENTCMD_NOMORECOMMANDS = 2;
        internal const int AGENTCMD_EXIT = 3;
        internal const int AGENTCMD_GETSYSTEMINFO = 4;
        internal const int AGENTCMD_UPDATESIG = 5;
        internal const int AGENTCMD_MITIGATE = 6;
        internal const int AGENTCMD_COLLECT = 7;
        //this command is never actually initiated by the admin console
        //it is created by the agent when it receives an invalid/corrupted command
        internal const int AGENTCMD_UNKNOWN = 99;
        //this command is never actually RECEIVED by the client.
        //it is used as an internal message to the worker thread to send an update file
        internal const int AGENTCMD_SENDUPDATEFILE = 1000;
        //this command is never actually RECEIVED by the client.
        //it is used as an internal message to the worker thread to receive an evidence file
        internal const int AGENTCMD_RECVEVIDENCEFILES = 1001;

        //---------------------------------------------------
        //              AGENT RESPONSE CONSTANTS
        //---------------------------------------------------
        internal const int AGENTRESPONSE_FAIL = 0;
        internal const int AGENTRESPONSE_OK = 1;
        internal const int AGENTRESPONSE_OK_SENDFILE = 2; //AC ----file----> Agent
        internal const int AGENTRESPONSE_OK_RECVFILE = 3; //AC <---file----> Agent

        //---------------------------------------------------
        //         ADMIN CONSOLE INTERNAL ERR CODES
        //---------------------------------------------------
        internal const int ADMINCONSOLE_ERROR_CMDFAILED = 0;
        internal const int ADMINCONSOLE_ERROR_RESPONSEFAILED = 1;

        //---------------------------------------------------
        //         DRIVER-RELATED CONSTANTS
        //---------------------------------------------------
        internal const string DRIVER_IMAGE_PATH_BASE = "System32\\DRIVERS\\";
        internal const string DRIVER_SERVICE_NAME = "CwSvc1";
        internal const string DRIVER_BINARY_NAME = "CwDriver.sys";
        internal const int DRIVER_DEVICE_TYPE = Win32Helper.FILE_DEVICE_UNKNOWN;
        internal const int DRIVER_ACCESS_TYPE = Win32Helper.FILE_ANY_ACCESS; 
        //IOCTLs
        internal const int CW_DRIVER_SSDT_DETECT_HOOKS = 0x801;
        internal const int CW_DRIVER_SSDT_DETECT_DETOURS = 0x802;
        internal const int CW_DRIVER_GDT_DETECT_SUSPICIOUS_SEGMENT_DESCRIPTORS = 0x803;
        internal const int CW_DRIVER_GDT_GET_CALL_GATES = 0x804;
        internal const int CW_DRIVER_IDT_DETECT_HOOKS = 0x805;
        internal const int CW_DRIVER_IDT_DETECT_DETOURS = 0x806;
        internal const int CW_DRIVER_WIN32API_DETOUR_DETECTION = 0x807;
        internal const int CW_DRIVER_IRP_HOOK_DETECTION = 0x808;
        internal const int CW_DRIVER_IRP_DETOUR_DETECTION = 0x809;
        internal const int CW_DRIVER_PROCESS_LISTING_ZWQ = 0x810; //use ZwQuerySystemInformation()
        internal const int CW_DRIVER_PROCESS_LISTING_PSP = 0x811; //use PspCidTable
        //Process listing request type codes
        internal const int CW_DRIVER_PROCLISTING_TYPE_ZWQ = 0x00;
        internal const int CW_DRIVER_PROCLISTING_TYPE_PSP = 0x01;
    }

    #endregion

    #region STRUCTUREs

    //NOTE:  THIS CLASS !!!MUST!!! BE NON-STATIC OR XML SERIALIZATION BREAKS
    public class CwStructures
    {
        #region MANAGED CODE STRUCTS

        [Serializable]
        public struct CWPROCESS_RECORD
        {
            public uint ppid;
            public uint pid;
            public string name;
            public string modulePath;
            public string[] NotInList;
        }

        [Serializable]
        public struct PROCESS_LISTING
        {
            public CWPROCESS_RECORD[] Processes;
        }

        [System.Runtime.InteropServices.StructLayoutAttribute(System.Runtime.InteropServices.LayoutKind.Sequential)]
        public struct DRIVER_CHECK_INFO
        {
            /// UNICODE_STRING->_UNICODE_STRING
            public Win32Helper.UNICODE_STRING DriverName;

            /// UNICODE_STRING->_UNICODE_STRING
            public Win32Helper.UNICODE_STRING DriverDeviceName;
        }

        #endregion

        #region P/Invoke CwDriver data structures

        [System.Runtime.InteropServices.StructLayoutAttribute(System.Runtime.InteropServices.LayoutKind.Sequential)]
        public struct HOOKED_SSDT_ENTRY
        {
            /// int
            public int ServiceIndex;

            /// ULONG->unsigned int
            public uint ServiceFunctionAddress;

            /// CHAR[256]
            [System.Runtime.InteropServices.MarshalAsAttribute(System.Runtime.InteropServices.UnmanagedType.ByValTStr, SizeConst = 256)]
            public string ServiceFunctionNameExpected;

            /// CHAR[256]
            [System.Runtime.InteropServices.MarshalAsAttribute(System.Runtime.InteropServices.UnmanagedType.ByValTStr, SizeConst = 256)]
            public string ServiceFunctionNameFound;

            /// CHAR[256]
            [System.Runtime.InteropServices.MarshalAsAttribute(System.Runtime.InteropServices.UnmanagedType.ByValTStr, SizeConst = 256)]
            public string ContainingModule;
        }

        [System.Runtime.InteropServices.StructLayoutAttribute(System.Runtime.InteropServices.LayoutKind.Sequential)]
        public struct HOOKED_SSDT_TABLE
        {
            /// int
            public int NumHookedEntries;

            /// HOOKED_SSDT_ENTRY[256]
            [System.Runtime.InteropServices.MarshalAsAttribute(System.Runtime.InteropServices.UnmanagedType.ByValArray, SizeConst = 256, ArraySubType = System.Runtime.InteropServices.UnmanagedType.Struct)]
            public HOOKED_SSDT_ENTRY[] HookedEntries;
        }

        [System.Runtime.InteropServices.StructLayoutAttribute(System.Runtime.InteropServices.LayoutKind.Sequential, CharSet = System.Runtime.InteropServices.CharSet.Ansi)]
        public struct DETOURED_SSDT_ENTRY
        {
            /// int
            public int ServiceIndex;

            /// ULONG->unsigned int
            public uint ServiceFunctionAddress;

            /// CHAR[256]
            [System.Runtime.InteropServices.MarshalAsAttribute(System.Runtime.InteropServices.UnmanagedType.ByValTStr, SizeConst = 256)]
            public string ServiceFunctionNameExpected;

            /// CHAR[256]
            [System.Runtime.InteropServices.MarshalAsAttribute(System.Runtime.InteropServices.UnmanagedType.ByValTStr, SizeConst = 256)]
            public string ServiceFunctionNameFound;

            /// ULONG->unsigned int
            public uint TargetAddress;

            /// CHAR[6400]
            [System.Runtime.InteropServices.MarshalAsAttribute(System.Runtime.InteropServices.UnmanagedType.ByValTStr, SizeConst = 6400)]
            public string Disassembly;

            /// CHAR[256]
            [System.Runtime.InteropServices.MarshalAsAttribute(System.Runtime.InteropServices.UnmanagedType.ByValTStr, SizeConst = 256)]
            public string ContainingModule;
        }

        [System.Runtime.InteropServices.StructLayoutAttribute(System.Runtime.InteropServices.LayoutKind.Sequential)]
        public struct DETOURED_SSDT_TABLE
        {
            /// int
            public int NumDetouredEntries;

            /// DETOURED_SSDT_ENTRY[256]
            [System.Runtime.InteropServices.MarshalAsAttribute(System.Runtime.InteropServices.UnmanagedType.ByValArray, SizeConst = 256, ArraySubType = System.Runtime.InteropServices.UnmanagedType.Struct)]
            public DETOURED_SSDT_ENTRY[] DetouredEntries;
        }

        [System.Runtime.InteropServices.StructLayoutAttribute(System.Runtime.InteropServices.LayoutKind.Sequential, CharSet = System.Runtime.InteropServices.CharSet.Ansi)]
        public struct WIN32API_DETOUR_ENTRY
        {
            /// ULONG->unsigned int
            public uint ExportAddress;

            /// CHAR[256]
            [System.Runtime.InteropServices.MarshalAsAttribute(System.Runtime.InteropServices.UnmanagedType.ByValTStr, SizeConst = 256)]
            public string ExportName;

            /// CHAR[6400]
            [System.Runtime.InteropServices.MarshalAsAttribute(System.Runtime.InteropServices.UnmanagedType.ByValTStr, SizeConst = 6400)]
            public string Disassembly;

            /// CHAR[256]
            [System.Runtime.InteropServices.MarshalAsAttribute(System.Runtime.InteropServices.UnmanagedType.ByValTStr, SizeConst = 256)]
            public string DetouringModule;

            /// ULONG->unsigned int
            public uint TargetAddress;

            /// BOOL->int
            [System.Runtime.InteropServices.MarshalAs(System.Runtime.InteropServices.UnmanagedType.Bool)]
            public bool IsDetoured;

            /// BOOL->int
            [System.Runtime.InteropServices.MarshalAs(System.Runtime.InteropServices.UnmanagedType.Bool)]
            public bool IsUnknown;
        }

        [System.Runtime.InteropServices.StructLayoutAttribute(System.Runtime.InteropServices.LayoutKind.Sequential, CharSet = System.Runtime.InteropServices.CharSet.Ansi)]
        public struct WIN32API_DETOUR_TABLE
        {
            /// int
            public int NumDetours;

            /// CHAR[256]
            [System.Runtime.InteropServices.MarshalAsAttribute(System.Runtime.InteropServices.UnmanagedType.ByValTStr, SizeConst = 256)]
            public string ModuleName;

            /// WIN32API_DETOUR_ENTRY[512]
            [System.Runtime.InteropServices.MarshalAsAttribute(System.Runtime.InteropServices.UnmanagedType.ByValArray, SizeConst = 512, ArraySubType = System.Runtime.InteropServices.UnmanagedType.Struct)]
            public WIN32API_DETOUR_ENTRY[] Win32Detours;
        }

        [System.Runtime.InteropServices.StructLayoutAttribute(System.Runtime.InteropServices.LayoutKind.Sequential, CharSet = System.Runtime.InteropServices.CharSet.Ansi)]
        public struct DETOURED_DISPATCH_FUNCTION_ENTRY
        {
            /// ULONG->unsigned int
            public uint DispatchFunctionAddress;

            /// CHAR[256]
            [System.Runtime.InteropServices.MarshalAsAttribute(System.Runtime.InteropServices.UnmanagedType.ByValTStr, SizeConst = 256)]
            public string DispatchFunctionName;

            /// CHAR[6400]
            [System.Runtime.InteropServices.MarshalAsAttribute(System.Runtime.InteropServices.UnmanagedType.ByValTStr, SizeConst = 6400)]
            public string Disassembly;

            /// CHAR[256]
            [System.Runtime.InteropServices.MarshalAsAttribute(System.Runtime.InteropServices.UnmanagedType.ByValTStr, SizeConst = 256)]
            public string DetouringModule;

            /// ULONG->unsigned int
            public uint TargetAddress;

            /// BOOL->int
            [System.Runtime.InteropServices.MarshalAsAttribute(System.Runtime.InteropServices.UnmanagedType.Bool)]
            public bool IsDetoured;

            /// BOOL->int
            [System.Runtime.InteropServices.MarshalAsAttribute(System.Runtime.InteropServices.UnmanagedType.Bool)]
            public bool IsUnknown;
        }

        [System.Runtime.InteropServices.StructLayoutAttribute(System.Runtime.InteropServices.LayoutKind.Sequential)]
        public struct DETOURED_DISPATCH_FUNCTIONS_TABLE
        {
            /// BOOL->int
            [System.Runtime.InteropServices.MarshalAsAttribute(System.Runtime.InteropServices.UnmanagedType.Bool)]
            public bool isDetoured;

            /// int
            public int NumDetours;

            /// UNICODE_STRING
            public Win32Helper.UNICODE_STRING DriverName;

            /// UNICODE_STRING
            public Win32Helper.UNICODE_STRING DriverDeviceName;

            /// DETOURED_DISPATCH_FUNCTION_ENTRY[512]
            [System.Runtime.InteropServices.MarshalAsAttribute(System.Runtime.InteropServices.UnmanagedType.ByValArray, SizeConst = 512, ArraySubType = System.Runtime.InteropServices.UnmanagedType.Struct)]
            public DETOURED_DISPATCH_FUNCTION_ENTRY[] DetouredEntries;
        }

        [System.Runtime.InteropServices.StructLayoutAttribute(System.Runtime.InteropServices.LayoutKind.Sequential, CharSet = System.Runtime.InteropServices.CharSet.Ansi)]
        public struct HOOKED_DISPATCH_FUNCTION_ENTRY
        {
            /// int
            public int IrpMajorFunctionHooked;

            /// ULONG->unsigned int
            public uint DispatchFunctionAddress;

            /// CHAR[256]
            [System.Runtime.InteropServices.MarshalAsAttribute(System.Runtime.InteropServices.UnmanagedType.ByValTStr, SizeConst = 256)]
            public string DispatchFunctionName;

            /// CHAR[256]
            [System.Runtime.InteropServices.MarshalAsAttribute(System.Runtime.InteropServices.UnmanagedType.ByValTStr, SizeConst = 256)]
            public string ContainingModule;
        }

        [System.Runtime.InteropServices.StructLayoutAttribute(System.Runtime.InteropServices.LayoutKind.Sequential)]
        public struct HOOKED_DISPATCH_FUNCTIONS_TABLE
        {
            /// int
            public int NumHookedEntries;

            /// BOOL->int
            [System.Runtime.InteropServices.MarshalAsAttribute(System.Runtime.InteropServices.UnmanagedType.Bool)]
            public bool isHooked;

            /// UNICODE_STRING
            public Win32Helper.UNICODE_STRING DriverName;

            /// UNICODE_STRING
            public Win32Helper.UNICODE_STRING DriverDeviceName;

            /// HOOKED_DISPATCH_FUNCTION_ENTRY[256]
            [System.Runtime.InteropServices.MarshalAsAttribute(System.Runtime.InteropServices.UnmanagedType.ByValArray, SizeConst = 256, ArraySubType = System.Runtime.InteropServices.UnmanagedType.Struct)]
            public HOOKED_DISPATCH_FUNCTION_ENTRY[] HookedEntries;
        }

        [System.Runtime.InteropServices.StructLayoutAttribute(System.Runtime.InteropServices.LayoutKind.Sequential, CharSet = System.Runtime.InteropServices.CharSet.Auto)]
        public struct CW_PROCESS_ENTRY
        {
            /// ULONG->unsigned int
            public uint NextEntryOffset;

            /// ULONG->unsigned int
            public uint NumberOfThreads;

            /// LARGE_INTEGER->_LARGE_INTEGER
            public Win32Helper.LARGE_INTEGER CreateTime;

            /// LARGE_INTEGER->_LARGE_INTEGER
            public Win32Helper.LARGE_INTEGER UserTime;

            /// LARGE_INTEGER->_LARGE_INTEGER
            public Win32Helper.LARGE_INTEGER KernelTime;

            /// WCHAR[256]
            [System.Runtime.InteropServices.MarshalAsAttribute(System.Runtime.InteropServices.UnmanagedType.ByValTStr, SizeConst = 256)]
            public string ImageName;

            /// KPRIORITY->LONG->int
            public int BasePriority;

            /// HANDLE->void*
            public uint UniqueProcessId;

            /// HANDLE->void*
            public uint InheritedFromUniqueProcessId;

            /// ULONG->unsigned int
            public uint HandleCount;

            /// ULONG->unsigned int
            public uint PrivatePageCount;

            /// SYSTEM_THREAD_INFORMATION[1]
            //[System.Runtime.InteropServices.MarshalAsAttribute(System.Runtime.InteropServices.UnmanagedType.ByValArray, SizeConst = 1, ArraySubType = System.Runtime.InteropServices.UnmanagedType.Struct)]
            // public Win32Helper.SYSTEM_THREAD_INFORMATION[] Threads;
        }

        [System.Runtime.InteropServices.StructLayoutAttribute(System.Runtime.InteropServices.LayoutKind.Sequential)]
        public struct PROCESS_LISTING_ZWQ
        {
            public int numProcesses;

            /// CW_PROCESS_ENTRY[256]
            [System.Runtime.InteropServices.MarshalAsAttribute(System.Runtime.InteropServices.UnmanagedType.ByValArray, SizeConst = 256, ArraySubType = System.Runtime.InteropServices.UnmanagedType.Struct)]
            public CW_PROCESS_ENTRY[] ProcessList;
        }

        #endregion
    }

    #endregion
}
