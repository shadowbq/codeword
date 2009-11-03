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
using System.Collections;
using System.Text;
using System.Runtime.InteropServices;
using System.Xml.Serialization;
using Microsoft.Win32.SafeHandles;
using CwHandler;

namespace CwAgent
{
    public class Win32Helper
    {
        /////////////////////////////////////////////////////
        //                                                 //
        // GetLoadedModuleList()                           //
        //                                                 //
        /////////////////////////////////////////////////////
        //Description:  returns a MODULE_LIST struct
        //              that contains a list of loaded modules on the system.
        //
        //Throws:       exception
        //
        //Returns:      void
        /////////////////////////////////////////////////////
        public static Win32Helper.MODULE_LIST GetLoadedModuleList()
        {
            MODULE_LIST moduleList = new MODULE_LIST();
            IntPtr pModuleList;
            pModuleList = Marshal.AllocHGlobal(1000);
            uint returnSize = 0;

            //must query once to get the size of buffer to alloc
            IntPtr ntstatus = Win32Helper.ZwQuerySystemInformation(Win32Helper.SYSTEM_INFORMATION_CLASS.SystemModuleInformation, pModuleList, (uint)1000, ref returnSize);
            long ntStatusCode = ntstatus.ToInt32();

            //alloc the right buffer size to recv the module list
            if (ntStatusCode == Win32Helper.STATUS_INFO_LENGTH_MISMATCH)
            {
                //re-allocate buffer and re-query
                Marshal.FreeHGlobal(pModuleList);
                try
                {
                    pModuleList = Marshal.AllocHGlobal((int)returnSize);
                }
                catch (Exception ex)
                {
                    throw new Exception("AllocHGlobal() part 2:  " + ex.Message);
                }

                ntstatus = Win32Helper.ZwQuerySystemInformation(Win32Helper.SYSTEM_INFORMATION_CLASS.SystemModuleInformation, pModuleList, returnSize, ref returnSize);
                ntStatusCode = ntstatus.ToInt32();

                if (ntStatusCode != (int)Win32Helper.STATUS_SUCCESS)
                    throw new Exception("ZwQuerySystemInformation() failed:  " + Win32Helper.GetLastError32());
            }

            try
            {
                moduleList=(MODULE_LIST)Marshal.PtrToStructure(pModuleList, typeof(MODULE_LIST));
            }
            catch (Exception ex)
            {
                throw new Exception("Failed to marshal pointer to loaded module list:  " + ex.Message);
            }

            Marshal.FreeHGlobal(pModuleList);

            return moduleList;
        }

        /////////////////////////////////////////////////////
        //                                                 //
        // GetActiveProcessList()                          //
        //                                                 //
        /////////////////////////////////////////////////////
        //Description:  returns an array of SYSTEM_PROCESS_INFORMATION structs
        //              that contains a list of active processes on the system.
        //
        //Throws:       exception
        //
        //Returns:      void
        /////////////////////////////////////////////////////
        public static SYSTEM_PROCESS_INFORMATION[] GetActiveProcessList()
        {
            IntPtr pProcessList=IntPtr.Zero,pProcessListHead=IntPtr.Zero;
            pProcessList = Marshal.AllocHGlobal(1000);
            uint returnSize = 0;
            int processCount = 0;

            //must query once to get the size of buffer to alloc
            IntPtr ntstatus = Win32Helper.ZwQuerySystemInformation(SYSTEM_INFORMATION_CLASS.SystemProcessInformation, pProcessList, (uint)1000, ref returnSize);
            long ntStatusCode = ntstatus.ToInt32();

            //alloc the right buffer size to recv the module list
            if (returnSize != 1000)
            {
                //re-allocate buffer and re-query
                Marshal.FreeHGlobal(pProcessList);
                pProcessList = Marshal.AllocHGlobal((int)returnSize);
                ntstatus = Win32Helper.ZwQuerySystemInformation(Win32Helper.SYSTEM_INFORMATION_CLASS.SystemProcessInformation, pProcessList, returnSize, ref returnSize);
                ntStatusCode = ntstatus.ToInt32();
                if (ntStatusCode != (int)Win32Helper.STATUS_SUCCESS)
                    throw new Exception("ZwQuerySystemInformation() failed:  " + Win32Helper.GetLastError32());
            }

            ArrayList processList = new ArrayList();

            pProcessListHead = pProcessList;

            //loop through linked list of processes
            while (true)
            {
                SYSTEM_PROCESS_INFORMATION thisProcessStruct = new SYSTEM_PROCESS_INFORMATION();

                try
                {
                    thisProcessStruct = (SYSTEM_PROCESS_INFORMATION)Marshal.PtrToStructure(pProcessListHead, typeof(SYSTEM_PROCESS_INFORMATION));
                }
                catch (Exception ex)
                {
                    Marshal.FreeHGlobal(pProcessList);
                    throw new Exception("Failed to marshal pointer to process #"+processCount+" in the list:  " + ex.Message);
                }

                //save it
                processList.Add(thisProcessStruct);

                //no more to process
                if (thisProcessStruct.NextEntryOffset == 0)
                    break;

                //increment processListHead
                pProcessListHead = (IntPtr)(pProcessListHead.ToInt32() + Int32.Parse(thisProcessStruct.NextEntryOffset.ToString()));
            }
            
            Marshal.FreeHGlobal(pProcessList);

            return (SYSTEM_PROCESS_INFORMATION[])processList.ToArray(typeof(SYSTEM_PROCESS_INFORMATION));
        }

        /////////////////////////////////////////////////////
        //                                                 //
        // Is64bit()                                       //
        //                                                 //
        /////////////////////////////////////////////////////
        //Description:  returns true if the current system
        //              is 64-bit or PAE-enabled
        //
        //Returns:      true if 64-bit system
        /////////////////////////////////////////////////////
        public static bool Is64bit()
        {
            if (IntPtr.Size == sizeof(Int64))
                return true;
            return false;
        }

        /////////////////////////////////////////////////////
        //                                                 //
        // GetLastError32()                                //
        //                                                 //
        /////////////////////////////////////////////////////
        //Description:  Uses unmanaged Win32 API functions
        //              GetLastError() and FormatMessage() to 
        //              retrieve the last error code and message
        //              from an unmanaged API call.
        //Returns:      string err message
        /////////////////////////////////////////////////////
        public static string GetLastError32()
        {
            uint errcode = Win32Helper.GetLastError();
            IntPtr lpBuffer = Marshal.AllocHGlobal(4096);
            Win32Helper.FormatMessage(0x00001000, (IntPtr)0, errcode, 0, lpBuffer, 1024, (IntPtr)0);
            string ret = Marshal.PtrToStringAnsi(lpBuffer);
            Marshal.FreeHGlobal(lpBuffer);
            return ret;
        }

        /////////////////////////////////////////////////////
        //                                                 //
        // GetIOCTL()                                      //
        //                                                 //
        /////////////////////////////////////////////////////
        //Description:  returns an IOCTL as built by the macro
        //              CTL_CODE(), defined in windows hdr file.
        //Returns:      uint
        /////////////////////////////////////////////////////
        public static uint GetIOCTL(uint code, uint method)
        {
            return CTL_CODE(CwConstants.DRIVER_DEVICE_TYPE,code,method,CwConstants.DRIVER_ACCESS_TYPE);
        }

        /////////////////////////////////////////////////////
        //                                                 //
        // GetIrpMjNameFromCode()                          //
        //                                                 //
        /////////////////////////////////////////////////////
        //Description:  Gets the name of the IRP Major Function
        //              code supplied.
        //Returns:      string name
        /////////////////////////////////////////////////////
        public static string GetIrpMjNameFromCode(int code)
        {
            if (code == 0)
                return "IRP_MJ_CREATE";
            else if (code == 1)
                return "IRP_MJ_CREATE_NAMED_PIPE";
            else if (code == 2)
                return "IRP_MJ_CLOSE";
            else if (code == 3)
                return "IRP_MJ_READ";
            else if (code == 4)
                return "IRP_MJ_WRITE";
            else if (code == 5)
                return "IRP_MJ_QUERY_INFORMATION";
            else if (code == 6)
                return "IRP_MJ_SET_INFORMATION";
            else if (code == 7)
                return "IRP_MJ_QUERY_EA";
            else if (code == 8)
                return "IRP_MJ_SET_EA";
            else if (code == 9)
                return "IRP_MJ_FLUSH_BUFFERS";
            else if (code == 10)
                return "IRP_MJ_QUERY_VOLUME_INFORMATION";
            else if (code == 11)
                return "IRP_MJ_SET_VOLUME_INFORMATION";
            else if (code == 12)
                return "IRP_MJ_DIRECTORY_CONTROL";
            else if (code == 13)
                return "IRP_MJ_FILE_SYSTEM_CONTROL";
            else if (code == 14)
                return "IRP_MJ_DEVICE_CONTROL";
            else if (code == 15)
                return "IRP_MJ_INTERNAL_DEVICE_CONTROL";
            else if (code == 16)
                return "IRP_MJ_SHUTDOWN";
            else if (code == 17)
                return "IRP_MJ_LOCK_CONTROL";
            else if (code == 18)
                return "IRP_MJ_CLEANUP";
            else if (code == 19)
                return "IRP_MJ_CREATE_MAILSLOT";
            else if (code == 20)
                return "IRP_MJ_QUERY_SECURITY";
            else if (code == 21)
                return "IRP_MJ_SET_SECURITY";
            else if (code == 22)
                return "IRP_MJ_POWER";
            else if (code == 23)
                return "IRP_MJ_SYSTEM_CONTROL";
            else if (code == 24)
                return "IRP_MJ_DEVICE_CHANGE";
            else if (code == 25)
                return "IRP_MJ_QUERY_QUOTA";
            else if (code == 26)
                return "IRP_MJ_SET_QUOTA";
            else if (code == 27)
                return "IRP_MJ_PNP";
            else
                return "[unknown]";
        }

        /////////////////////////////////////////////////////
        //                                                 //
        // -= UNMANAGED API PROTOTYPES =-                  //
        //                                                 //
        /////////////////////////////////////////////////////
        //Description:  The function prototypes below are for
        //Win32 API calls to the unmanaged API.  These are C
        //functions exported by the operating system for various
        //tasks.  They are interop'd into C# because sometimes
        //you just need to reach into unmanaged code........

        #region P/Invoke Delegate Prototypes

        public delegate void LPHANDLER_FUNCTION(uint dwControl);

        public delegate void LPSERVICE_MAIN_FUNCTIONW(uint dwNumServicesArgs, ref System.IntPtr lpServiceArgVectors);

        public delegate bool ZwSetSystemInformationDelegate(uint SystemInformationClass, System.IntPtr SystemInformation, uint SystemInformationLength);

        public delegate bool RtlInitUnicodeStringDelegate(ref UNICODE_STRING pUnicodeString, [System.Runtime.InteropServices.InAttribute()] [System.Runtime.InteropServices.MarshalAsAttribute(System.Runtime.InteropServices.UnmanagedType.LPTStr)] string SourceString);

        #endregion

        #region P/Invoke data structures

        //MASSIVE REGION OF STRUCTS FOR PROCESS ENUMERATION
        // disabled for now
        
        #region data structs for process enumeration
        /*
        [System.Runtime.InteropServices.StructLayoutAttribute(System.Runtime.InteropServices.LayoutKind.Sequential)]
        public struct PPM_PERF_STATE
        {

            /// ULONG->unsigned int
            public uint Frequency;

            /// ULONG->unsigned int
            public uint Power;

            /// UCHAR->unsigned char
            public byte PercentFrequency;

            /// UCHAR->unsigned char
            public byte IncreaseLevel;

            /// UCHAR->unsigned char
            public byte DecreaseLevel;

            /// UCHAR->unsigned char
            public byte Type;

            /// UINT64->unsigned __int64
            public ulong Control;

            /// UINT64->unsigned __int64
            public ulong Status;

            /// ULONG->unsigned int
            public uint TotalHitCount;

            /// ULONG->unsigned int
            public uint DesiredCount;
        }

        [System.Runtime.InteropServices.StructLayoutAttribute(System.Runtime.InteropServices.LayoutKind.Sequential)]
        public struct PPM_PERF_STATES
        {

            /// ULONG->unsigned int
            public uint Count;

            /// ULONG->unsigned int
            public uint MaxFrequency;

            /// ULONG->unsigned int
            public uint MaxPerfState;

            /// ULONG->unsigned int
            public uint MinPerfState;

            /// ULONG->unsigned int
            public uint LowestPState;

            /// ULONG->unsigned int
            public uint IncreaseTime;

            /// ULONG->unsigned int
            public uint DecreaseTime;

            /// UCHAR->unsigned char
            public byte BusyAdjThreshold;

            /// UCHAR->unsigned char
            public byte Reserved;

            /// UCHAR->unsigned char
            public byte ThrottleStatesOnly;

            /// UCHAR->unsigned char
            public byte PolicyType;

            /// ULONG->unsigned int
            public uint TimerInterval;

            /// ULONG->unsigned int
            public uint Flags;

            /// ULONG->unsigned int
            public uint TargetProcessors;

            /// LONG*
            public System.IntPtr PStateHandler;

            /// ULONG->unsigned int
            public uint PStateContext;

            /// LONG*
            public System.IntPtr TStateHandler;

            /// ULONG->unsigned int
            public uint TStateContext;

            /// ULONG*
            public System.IntPtr FeedbackHandler;

            /// PPM_PERF_STATE[1]
            [System.Runtime.InteropServices.MarshalAsAttribute(System.Runtime.InteropServices.UnmanagedType.ByValArray, SizeConst = 1, ArraySubType = System.Runtime.InteropServices.UnmanagedType.Struct)]
            public PPM_PERF_STATE[] State;
        }

        [System.Runtime.InteropServices.StructLayoutAttribute(System.Runtime.InteropServices.LayoutKind.Sequential)]
        public struct PPM_IDLE_STATE_ACCOUNTING
        {

            /// ULONG->unsigned int
            public uint IdleTransitions;

            /// ULONG->unsigned int
            public uint FailedTransitions;

            /// ULONG->unsigned int
            public uint InvalidBucketIndex;

            /// UINT64->unsigned __int64
            public ulong TotalTime;

            /// ULONG[6]
            [System.Runtime.InteropServices.MarshalAsAttribute(System.Runtime.InteropServices.UnmanagedType.ByValArray, SizeConst = 6, ArraySubType = System.Runtime.InteropServices.UnmanagedType.U4)]
            public uint[] IdleTimeBuckets;
        }

        [System.Runtime.InteropServices.StructLayoutAttribute(System.Runtime.InteropServices.LayoutKind.Sequential)]
        public struct PPM_IDLE_ACCOUNTING
        {

            /// ULONG->unsigned int
            public uint StateCount;

            /// ULONG->unsigned int
            public uint TotalTransitions;

            /// ULONG->unsigned int
            public uint ResetCount;

            /// UINT64->unsigned __int64
            public ulong StartTime;

            /// PPM_IDLE_STATE_ACCOUNTING[1]
            [System.Runtime.InteropServices.MarshalAsAttribute(System.Runtime.InteropServices.UnmanagedType.ByValArray, SizeConst = 1, ArraySubType = System.Runtime.InteropServices.UnmanagedType.Struct)]
            public PPM_IDLE_STATE_ACCOUNTING[] State;
        }

        [System.Runtime.InteropServices.StructLayoutAttribute(System.Runtime.InteropServices.LayoutKind.Sequential)]
        public struct PROCESSOR_IDLE_TIMES
        {

            /// UINT64->unsigned __int64
            public ulong StartTime;

            /// UINT64->unsigned __int64
            public ulong EndTime;

            /// ULONG[4]
            [System.Runtime.InteropServices.MarshalAsAttribute(System.Runtime.InteropServices.UnmanagedType.ByValArray, SizeConst = 4, ArraySubType = System.Runtime.InteropServices.UnmanagedType.U4)]
            public uint[] Reserved;
        }

        [System.Runtime.InteropServices.StructLayoutAttribute(System.Runtime.InteropServices.LayoutKind.Sequential)]
        public struct PPM_IDLE_STATE
        {

            /// LONG*
            public System.IntPtr IdleHandler;

            /// ULONG->unsigned int
            public uint Context;

            /// ULONG->unsigned int
            public uint Latency;

            /// ULONG->unsigned int
            public uint Power;

            /// ULONG->unsigned int
            public uint TimeCheck;

            /// ULONG->unsigned int
            public uint StateFlags;

            /// UCHAR->unsigned char
            public byte PromotePercent;

            /// UCHAR->unsigned char
            public byte DemotePercent;

            /// UCHAR->unsigned char
            public byte PromotePercentBase;

            /// UCHAR->unsigned char
            public byte DemotePercentBase;

            /// UCHAR->unsigned char
            public byte StateType;
        }

        [System.Runtime.InteropServices.StructLayoutAttribute(System.Runtime.InteropServices.LayoutKind.Sequential)]
        public struct PPM_IDLE_STATES
        {

            /// ULONG->unsigned int
            public uint Type;

            /// ULONG->unsigned int
            public uint Count;

            /// ULONG->unsigned int
            public uint Flags;

            /// ULONG->unsigned int
            public uint TargetState;

            /// ULONG->unsigned int
            public uint ActualState;

            /// ULONG->unsigned int
            public uint OldState;

            /// ULONG->unsigned int
            public uint TargetProcessors;

            /// PPM_IDLE_STATE[1]
            [System.Runtime.InteropServices.MarshalAsAttribute(System.Runtime.InteropServices.UnmanagedType.ByValArray, SizeConst = 1, ArraySubType = System.Runtime.InteropServices.UnmanagedType.Struct)]
            public PPM_IDLE_STATE[] State;
        }

        [System.Runtime.InteropServices.StructLayoutAttribute(System.Runtime.InteropServices.LayoutKind.Sequential)]
        public struct PROCESSOR_POWER_STATE
        {

            /// PVOID->void*
            public System.IntPtr IdleFunction;

            /// PPPM_IDLE_STATES->Anonymous_c17ed62b_08fb_4799_9f1f_ddd6c3232ecc*
            public System.IntPtr IdleStates;

            /// UINT64->unsigned __int64
            public ulong LastTimeCheck;

            /// UINT64->unsigned __int64
            public ulong LastIdleTime;

            /// PROCESSOR_IDLE_TIMES->Anonymous_26698327_6b4c_4753_8ec8_937442b1e5b7
            public PROCESSOR_IDLE_TIMES IdleTimes;

            /// PPPM_IDLE_ACCOUNTING->Anonymous_c47218c6_4247_4463_85d6_a9561ca82b05*
            public System.IntPtr IdleAccounting;

            /// PPPM_PERF_STATES->Anonymous_6905e89c_2925_4a46_a165_a3c33859577e*
            public System.IntPtr PerfStates;

            /// ULONG->unsigned int
            public uint LastKernelUserTime;

            /// ULONG->unsigned int
            public uint LastIdleThreadKTime;

            /// UINT64->unsigned __int64
            public ulong LastGlobalTimeHv;

            /// UINT64->unsigned __int64
            public ulong LastProcessorTimeHv;

            /// UCHAR->unsigned char
            public byte ThermalConstraint;

            /// UCHAR->unsigned char
            public byte LastBusyPercentage;

            /// BYTE[6]
            [System.Runtime.InteropServices.MarshalAsAttribute(System.Runtime.InteropServices.UnmanagedType.ByValArray, SizeConst = 6, ArraySubType = System.Runtime.InteropServices.UnmanagedType.I1)]
            public byte[] Flags;

            /// KTIMER->_KTIMER
            public KTIMER PerfTimer;

            /// KDPC->_KDPC
            public KDPC PerfDpc;

            /// ULONG->unsigned int
            public uint LastSysTime;

            /// PKPRCB->_KPRCB*
            public System.IntPtr PStateMaster;

            /// ULONG->unsigned int
            public uint PStateSet;

            /// ULONG->unsigned int
            public uint CurrentPState;

            /// ULONG->unsigned int
            public uint Reserved0;

            /// ULONG->unsigned int
            public uint DesiredPState;

            /// ULONG->unsigned int
            public uint Reserved1;

            /// ULONG->unsigned int
            public uint PStateIdleStartTime;

            /// ULONG->unsigned int
            public uint PStateIdleTime;

            /// ULONG->unsigned int
            public uint LastPStateIdleTime;

            /// ULONG->unsigned int
            public uint PStateStartTime;

            /// ULONG->unsigned int
            public uint WmiDispatchPtr;

            /// LONG->int
            public int WmiInterfaceEnabled;
        }

        [System.Runtime.InteropServices.StructLayoutAttribute(System.Runtime.InteropServices.LayoutKind.Explicit)]
        public struct Anonymous_aeea4489_d45c_4821_989d_50a7cbb87ef4
        {

            /// SLIST_HEADER->_SLIST_HEADER
            [System.Runtime.InteropServices.FieldOffsetAttribute(0)]
            public SLIST_HEADER ListHead;

            /// SINGLE_LIST_ENTRY->_SINGLE_LIST_ENTRY
            [System.Runtime.InteropServices.FieldOffsetAttribute(0)]
            public SINGLE_LIST_ENTRY SingleListHead;
        }

        [System.Runtime.InteropServices.StructLayoutAttribute(System.Runtime.InteropServices.LayoutKind.Explicit)]
        public struct Anonymous_4106a007_c52a_437e_b5d4_10c9e46786be
        {

            /// ULONG->unsigned int
            [System.Runtime.InteropServices.FieldOffsetAttribute(0)]
            public uint AllocateMisses;

            /// ULONG->unsigned int
            [System.Runtime.InteropServices.FieldOffsetAttribute(0)]
            public uint AllocateHits;
        }

        [System.Runtime.InteropServices.StructLayoutAttribute(System.Runtime.InteropServices.LayoutKind.Explicit)]
        public struct Anonymous_13270d3e_3717_43d3_9f1b_f7a95d97829c
        {

            /// ULONG->unsigned int
            [System.Runtime.InteropServices.FieldOffsetAttribute(0)]
            public uint FreeMisses;

            /// ULONG->unsigned int
            [System.Runtime.InteropServices.FieldOffsetAttribute(0)]
            public uint FreeHits;
        }

        [System.Runtime.InteropServices.StructLayoutAttribute(System.Runtime.InteropServices.LayoutKind.Explicit)]
        public struct Anonymous_5a55e2d6_417d_4a8c_9170_2b54aaf59b43
        {

            /// PVOID*
            [System.Runtime.InteropServices.FieldOffsetAttribute(0)]
            public System.IntPtr AllocateEx;

            /// PVOID*
            [System.Runtime.InteropServices.FieldOffsetAttribute(0)]
            public System.IntPtr Allocate;
        }

        [System.Runtime.InteropServices.StructLayoutAttribute(System.Runtime.InteropServices.LayoutKind.Explicit)]
        public struct Anonymous_a4f5a4c6_c73a_4b28_811b_d441479921b8
        {

            /// PVOID->void*
            [System.Runtime.InteropServices.FieldOffsetAttribute(0)]
            public System.IntPtr FreeEx;

            /// PVOID->void*
            [System.Runtime.InteropServices.FieldOffsetAttribute(0)]
            public System.IntPtr Free;
        }

        [System.Runtime.InteropServices.StructLayoutAttribute(System.Runtime.InteropServices.LayoutKind.Explicit)]
        public struct Anonymous_3d422d99_3788_4b27_bf27_b7882d4657df
        {

            /// ULONG->unsigned int
            [System.Runtime.InteropServices.FieldOffsetAttribute(0)]
            public uint LastAllocateMisses;

            /// ULONG->unsigned int
            [System.Runtime.InteropServices.FieldOffsetAttribute(0)]
            public uint LastAllocateHits;
        }

        [System.Runtime.InteropServices.StructLayoutAttribute(System.Runtime.InteropServices.LayoutKind.Sequential)]
        public struct GENERAL_LOOKASIDE_POOL
        {

            /// Anonymous_aeea4489_d45c_4821_989d_50a7cbb87ef4
            public Anonymous_aeea4489_d45c_4821_989d_50a7cbb87ef4 Union1;

            /// WORD->unsigned short
            public ushort Depth;

            /// WORD->unsigned short
            public ushort MaximumDepth;

            /// ULONG->unsigned int
            public uint TotalAllocates;

            /// Anonymous_4106a007_c52a_437e_b5d4_10c9e46786be
            public Anonymous_4106a007_c52a_437e_b5d4_10c9e46786be Union2;

            /// ULONG->unsigned int
            public uint TotalFrees;

            /// Anonymous_13270d3e_3717_43d3_9f1b_f7a95d97829c
            public Anonymous_13270d3e_3717_43d3_9f1b_f7a95d97829c Union3;

            /// POOL_TYPE->_POOL_TYPE
            public POOL_TYPE Type;

            /// ULONG->unsigned int
            public uint Tag;

            /// ULONG->unsigned int
            public uint Size;

            /// Anonymous_5a55e2d6_417d_4a8c_9170_2b54aaf59b43
            public Anonymous_5a55e2d6_417d_4a8c_9170_2b54aaf59b43 Union4;

            /// Anonymous_a4f5a4c6_c73a_4b28_811b_d441479921b8
            public Anonymous_a4f5a4c6_c73a_4b28_811b_d441479921b8 Union5;

            /// LIST_ENTRY->_LIST_ENTRY
            public LIST_ENTRY ListEntry;

            /// ULONG->unsigned int
            public uint LastTotalAllocates;

            /// Anonymous_3d422d99_3788_4b27_bf27_b7882d4657df
            public Anonymous_3d422d99_3788_4b27_bf27_b7882d4657df Union6;

            /// ULONG[2]
            [System.Runtime.InteropServices.MarshalAsAttribute(System.Runtime.InteropServices.UnmanagedType.ByValArray, SizeConst = 2, ArraySubType = System.Runtime.InteropServices.UnmanagedType.U4)]
            public uint[] Future;
        }

        [System.Runtime.InteropServices.StructLayoutAttribute(System.Runtime.InteropServices.LayoutKind.Sequential)]
        public struct KDPC_DATA
        {

            /// LIST_ENTRY->_LIST_ENTRY
            public LIST_ENTRY DpcListHead;

            /// ULONG->unsigned int
            public uint DpcLock;

            /// LONG->int
            public int DpcQueueDepth;

            /// ULONG->unsigned int
            public uint DpcCount;
        }

        [System.Runtime.InteropServices.StructLayoutAttribute(System.Runtime.InteropServices.LayoutKind.Sequential)]
        public struct HANDLE_TRACE_DB_ENTRY
        {

            /// CLIENT_ID->_CLIENT_ID
            public CLIENT_ID ClientId;

            /// PVOID->void*
            public System.IntPtr Handle;

            /// ULONG->unsigned int
            public uint Type;

            /// void*[16]
            [System.Runtime.InteropServices.MarshalAsAttribute(System.Runtime.InteropServices.UnmanagedType.ByValArray, SizeConst = 16, ArraySubType = System.Runtime.InteropServices.UnmanagedType.SysUInt)]
            public System.IntPtr[] StackTrace;
        }

        [System.Runtime.InteropServices.StructLayoutAttribute(System.Runtime.InteropServices.LayoutKind.Sequential)]
        public struct KSEMAPHORE
        {

            /// DISPATCHER_HEADER->_DISPATCHER_HEADER
            public DISPATCHER_HEADER Header;

            /// LONG->int
            public int Limit;
        }

        [System.Runtime.InteropServices.StructLayoutAttribute(System.Runtime.InteropServices.LayoutKind.Sequential)]
        public struct KAPC
        {

            /// UCHAR->unsigned char
            public byte Type;

            /// UCHAR->unsigned char
            public byte SpareByte0;

            /// UCHAR->unsigned char
            public byte Size;

            /// UCHAR->unsigned char
            public byte SpareByte1;

            /// ULONG->unsigned int
            public uint SpareLong0;

            /// PKTHREAD->_KTHREAD*
            public System.IntPtr Thread;

            /// LIST_ENTRY->_LIST_ENTRY
            public LIST_ENTRY ApcListEntry;

            /// PVOID->void*
            public System.IntPtr KernelRoutine;

            /// PVOID->void*
            public System.IntPtr RundownRoutine;

            /// PVOID->void*
            public System.IntPtr NormalRoutine;

            /// PVOID->void*
            public System.IntPtr NormalContext;

            /// PVOID->void*
            public System.IntPtr SystemArgument1;

            /// PVOID->void*
            public System.IntPtr SystemArgument2;

            /// CHAR->char
            public byte ApcStateIndex;

            /// CHAR->char
            public byte ApcMode;

            /// UCHAR->unsigned char
            public byte Inserted;
        }

        [System.Runtime.InteropServices.StructLayoutAttribute(System.Runtime.InteropServices.LayoutKind.Sequential)]
        public struct FX_SAVE_AREA
        {

            /// BYTE[520]
            [System.Runtime.InteropServices.MarshalAsAttribute(System.Runtime.InteropServices.UnmanagedType.ByValArray, SizeConst = 520, ArraySubType = System.Runtime.InteropServices.UnmanagedType.I1)]
            public byte[] U;

            /// ULONG->unsigned int
            public uint NpxSavedCpu;

            /// ULONG->unsigned int
            public uint Cr0NpxState;
        }

        [System.Runtime.InteropServices.StructLayoutAttribute(System.Runtime.InteropServices.LayoutKind.Sequential)]
        public struct KEVENT
        {

            /// DISPATCHER_HEADER->_DISPATCHER_HEADER
            public DISPATCHER_HEADER Header;
        }

        public enum POOL_TYPE
        {

            /// NonPagedPool -> 0
            NonPagedPool = 0,

            /// PagedPool -> 1
            PagedPool = 1,

            /// NonPagedPoolMustSucceed -> 2
            NonPagedPoolMustSucceed = 2,

            /// DontUseThisType -> 3
            DontUseThisType = 3,

            /// NonPagedPoolCacheAligned -> 4
            NonPagedPoolCacheAligned = 4,

            /// PagedPoolCacheAligned -> 5
            PagedPoolCacheAligned = 5,

            /// NonPagedPoolCacheAlignedMustS -> 6
            NonPagedPoolCacheAlignedMustS = 6,

            /// MaxPoolType -> 7
            MaxPoolType = 7,

            /// NonPagedPoolSession -> 32
            NonPagedPoolSession = 32,

            /// PagedPoolSession -> 33
            PagedPoolSession = 33,

            /// NonPagedPoolMustSucceedSession -> 34
            NonPagedPoolMustSucceedSession = 34,

            /// DontUseThisTypeSession -> 35
            DontUseThisTypeSession = 35,

            /// NonPagedPoolCacheAlignedSession -> 36
            NonPagedPoolCacheAlignedSession = 36,

            /// PagedPoolCacheAlignedSession -> 37
            PagedPoolCacheAlignedSession = 37,

            /// NonPagedPoolCacheAlignedMustSSession -> 38
            NonPagedPoolCacheAlignedMustSSession = 38,
        }

        [System.Runtime.InteropServices.StructLayoutAttribute(System.Runtime.InteropServices.LayoutKind.Explicit)]
        public struct Anonymous_5487b1c6_4f92_4157_8a01_701e119e018a
        {

            /// SLIST_HEADER->_SLIST_HEADER
            [System.Runtime.InteropServices.FieldOffsetAttribute(0)]
            public SLIST_HEADER ListHead;

            /// SINGLE_LIST_ENTRY->_SINGLE_LIST_ENTRY
            [System.Runtime.InteropServices.FieldOffsetAttribute(0)]
            public SINGLE_LIST_ENTRY SingleListHead;
        }

        [System.Runtime.InteropServices.StructLayoutAttribute(System.Runtime.InteropServices.LayoutKind.Explicit)]
        public struct Anonymous_4458ada0_eb57_4a4a_adfa_c214a0803918
        {

            /// ULONG->unsigned int
            [System.Runtime.InteropServices.FieldOffsetAttribute(0)]
            public uint AllocateMisses;

            /// ULONG->unsigned int
            [System.Runtime.InteropServices.FieldOffsetAttribute(0)]
            public uint AllocateHits;
        }

        [System.Runtime.InteropServices.StructLayoutAttribute(System.Runtime.InteropServices.LayoutKind.Explicit)]
        public struct Anonymous_c813d5c4_eeec_4aed_8a0c_517b237fb007
        {

            /// ULONG->unsigned int
            [System.Runtime.InteropServices.FieldOffsetAttribute(0)]
            public uint FreeMisses;

            /// ULONG->unsigned int
            [System.Runtime.InteropServices.FieldOffsetAttribute(0)]
            public uint FreeHits;
        }

        [System.Runtime.InteropServices.StructLayoutAttribute(System.Runtime.InteropServices.LayoutKind.Explicit)]
        public struct Anonymous_e48b4797_09c3_4892_8f99_b86e99f340b0
        {

            /// PVOID*
            [System.Runtime.InteropServices.FieldOffsetAttribute(0)]
            public System.IntPtr AllocateEx;

            /// PVOID*
            [System.Runtime.InteropServices.FieldOffsetAttribute(0)]
            public System.IntPtr Allocate;
        }

        [System.Runtime.InteropServices.StructLayoutAttribute(System.Runtime.InteropServices.LayoutKind.Explicit)]
        public struct Anonymous_5f9b3107_ebcf_460d_9e9c_a9065d5e67e5
        {

            /// PVOID->void*
            [System.Runtime.InteropServices.FieldOffsetAttribute(0)]
            public System.IntPtr FreeEx;

            /// PVOID->void*
            [System.Runtime.InteropServices.FieldOffsetAttribute(0)]
            public System.IntPtr Free;
        }

        [System.Runtime.InteropServices.StructLayoutAttribute(System.Runtime.InteropServices.LayoutKind.Explicit)]
        public struct Anonymous_655d7418_b6c2_43c7_95a0_3d4a007f54e8
        {

            /// ULONG->unsigned int
            [System.Runtime.InteropServices.FieldOffsetAttribute(0)]
            public uint LastAllocateMisses;

            /// ULONG->unsigned int
            [System.Runtime.InteropServices.FieldOffsetAttribute(0)]
            public uint LastAllocateHits;
        }

        [System.Runtime.InteropServices.StructLayoutAttribute(System.Runtime.InteropServices.LayoutKind.Sequential)]
        public struct GENERAL_LOOKASIDE
        {

            /// Anonymous_5487b1c6_4f92_4157_8a01_701e119e018a
            public Anonymous_5487b1c6_4f92_4157_8a01_701e119e018a Union1;

            /// WORD->unsigned short
            public ushort Depth;

            /// WORD->unsigned short
            public ushort MaximumDepth;

            /// ULONG->unsigned int
            public uint TotalAllocates;

            /// Anonymous_4458ada0_eb57_4a4a_adfa_c214a0803918
            public Anonymous_4458ada0_eb57_4a4a_adfa_c214a0803918 Union2;

            /// ULONG->unsigned int
            public uint TotalFrees;

            /// Anonymous_c813d5c4_eeec_4aed_8a0c_517b237fb007
            public Anonymous_c813d5c4_eeec_4aed_8a0c_517b237fb007 Union3;

            /// POOL_TYPE->_POOL_TYPE
            public POOL_TYPE Type;

            /// ULONG->unsigned int
            public uint Tag;

            /// ULONG->unsigned int
            public uint Size;

            /// Anonymous_e48b4797_09c3_4892_8f99_b86e99f340b0
            public Anonymous_e48b4797_09c3_4892_8f99_b86e99f340b0 Union4;

            /// Anonymous_5f9b3107_ebcf_460d_9e9c_a9065d5e67e5
            public Anonymous_5f9b3107_ebcf_460d_9e9c_a9065d5e67e5 Union5;

            /// LIST_ENTRY->_LIST_ENTRY
            public LIST_ENTRY ListEntry;

            /// ULONG->unsigned int
            public uint LastTotalAllocates;

            /// Anonymous_655d7418_b6c2_43c7_95a0_3d4a007f54e8
            public Anonymous_655d7418_b6c2_43c7_95a0_3d4a007f54e8 Union6;

            /// ULONG[2]
            [System.Runtime.InteropServices.MarshalAsAttribute(System.Runtime.InteropServices.UnmanagedType.ByValArray, SizeConst = 2, ArraySubType = System.Runtime.InteropServices.UnmanagedType.U4)]
            public uint[] Future;
        }

        [System.Runtime.InteropServices.StructLayoutAttribute(System.Runtime.InteropServices.LayoutKind.Sequential)]
        public struct PP_LOOKASIDE_LIST
        {

            /// PGENERAL_LOOKASIDE->_GENERAL_LOOKASIDE*
            public System.IntPtr P;

            /// PGENERAL_LOOKASIDE->_GENERAL_LOOKASIDE*
            public System.IntPtr L;
        }

        [System.Runtime.InteropServices.StructLayoutAttribute(System.Runtime.InteropServices.LayoutKind.Sequential)]
        public struct CACHED_KSTACK_LIST
        {

            /// SLIST_HEADER->_SLIST_HEADER
            public SLIST_HEADER SListHead;

            /// LONG->int
            public int MinimumFree;

            /// ULONG->unsigned int
            public uint Misses;

            /// ULONG->unsigned int
            public uint MissesLast;
        }

        [System.Runtime.InteropServices.StructLayoutAttribute(System.Runtime.InteropServices.LayoutKind.Sequential)]
        public struct KNODE
        {

            /// SLIST_HEADER->_SLIST_HEADER
            public SLIST_HEADER PagedPoolSListHead;

            /// SLIST_HEADER[3]
            [System.Runtime.InteropServices.MarshalAsAttribute(System.Runtime.InteropServices.UnmanagedType.ByValArray, SizeConst = 3, ArraySubType = System.Runtime.InteropServices.UnmanagedType.Struct)]
            public SLIST_HEADER[] NonPagedPoolSListHead;

            /// SLIST_HEADER->_SLIST_HEADER
            public SLIST_HEADER PfnDereferenceSListHead;

            /// ULONG->unsigned int
            public uint ProcessorMask;

            /// UCHAR->unsigned char
            public byte Color;

            /// UCHAR->unsigned char
            public byte Seed;

            /// UCHAR->unsigned char
            public byte NodeNumber;

            /// DWORD->unsigned int
            public uint Flags;

            /// ULONG->unsigned int
            public uint MmShiftedColor;

            /// ULONG[2]
            [System.Runtime.InteropServices.MarshalAsAttribute(System.Runtime.InteropServices.UnmanagedType.ByValArray, SizeConst = 2, ArraySubType = System.Runtime.InteropServices.UnmanagedType.U4)]
            public uint[] FreeCount;

            /// PSINGLE_LIST_ENTRY->_SINGLE_LIST_ENTRY*
            public System.IntPtr PfnDeferredList;

            /// CACHED_KSTACK_LIST->_CACHED_KSTACK_LIST
            public CACHED_KSTACK_LIST CachedKernelStacks;
        }

        [System.Runtime.InteropServices.StructLayoutAttribute(System.Runtime.InteropServices.LayoutKind.Sequential)]
        public struct KSPIN_LOCK_QUEUE
        {

            /// PKSPIN_LOCK_QUEUE->_KSPIN_LOCK_QUEUE*
            public System.IntPtr Next;

            /// ULONG*
            public System.IntPtr Lock;
        }

        [System.Runtime.InteropServices.StructLayoutAttribute(System.Runtime.InteropServices.LayoutKind.Sequential)]
        public struct DESCRIPTOR
        {

            /// WORD->unsigned short
            public ushort Pad;

            /// WORD->unsigned short
            public ushort Limit;

            /// ULONG->unsigned int
            public uint Base;
        }

        [System.Runtime.InteropServices.StructLayoutAttribute(System.Runtime.InteropServices.LayoutKind.Sequential)]
        public struct KSPECIAL_REGISTERS
        {

            /// ULONG->unsigned int
            public uint Cr0;

            /// ULONG->unsigned int
            public uint Cr2;

            /// ULONG->unsigned int
            public uint Cr3;

            /// ULONG->unsigned int
            public uint Cr4;

            /// ULONG->unsigned int
            public uint KernelDr0;

            /// ULONG->unsigned int
            public uint KernelDr1;

            /// ULONG->unsigned int
            public uint KernelDr2;

            /// ULONG->unsigned int
            public uint KernelDr3;

            /// ULONG->unsigned int
            public uint KernelDr6;

            /// ULONG->unsigned int
            public uint KernelDr7;

            /// DESCRIPTOR->_DESCRIPTOR
            public DESCRIPTOR Gdtr;

            /// DESCRIPTOR->_DESCRIPTOR
            public DESCRIPTOR Idtr;

            /// WORD->unsigned short
            public ushort Tr;

            /// WORD->unsigned short
            public ushort Ldtr;

            /// ULONG[6]
            [System.Runtime.InteropServices.MarshalAsAttribute(System.Runtime.InteropServices.UnmanagedType.ByValArray, SizeConst = 6, ArraySubType = System.Runtime.InteropServices.UnmanagedType.U4)]
            public uint[] Reserved;
        }

        [System.Runtime.InteropServices.StructLayoutAttribute(System.Runtime.InteropServices.LayoutKind.Sequential, CharSet = System.Runtime.InteropServices.CharSet.Ansi)]
        public struct FLOATING_SAVE_AREA
        {

            /// ULONG->unsigned int
            public uint ControlWord;

            /// ULONG->unsigned int
            public uint StatusWord;

            /// ULONG->unsigned int
            public uint TagWord;

            /// ULONG->unsigned int
            public uint ErrorOffset;

            /// ULONG->unsigned int
            public uint ErrorSelector;

            /// ULONG->unsigned int
            public uint DataOffset;

            /// ULONG->unsigned int
            public uint DataSelector;

            /// UCHAR[80]
            [System.Runtime.InteropServices.MarshalAsAttribute(System.Runtime.InteropServices.UnmanagedType.ByValTStr, SizeConst = 80)]
            public string RegisterArea;

            /// ULONG->unsigned int
            public uint Cr0NpxState;
        }

        [System.Runtime.InteropServices.StructLayoutAttribute(System.Runtime.InteropServices.LayoutKind.Sequential, CharSet = System.Runtime.InteropServices.CharSet.Ansi)]
        public struct CONTEXT
        {

            /// ULONG->unsigned int
            public uint ContextFlags;

            /// ULONG->unsigned int
            public uint Dr0;

            /// ULONG->unsigned int
            public uint Dr1;

            /// ULONG->unsigned int
            public uint Dr2;

            /// ULONG->unsigned int
            public uint Dr3;

            /// ULONG->unsigned int
            public uint Dr6;

            /// ULONG->unsigned int
            public uint Dr7;

            /// FLOATING_SAVE_AREA->_FLOATING_SAVE_AREA
            public FLOATING_SAVE_AREA FloatSave;

            /// ULONG->unsigned int
            public uint SegGs;

            /// ULONG->unsigned int
            public uint SegFs;

            /// ULONG->unsigned int
            public uint SegEs;

            /// ULONG->unsigned int
            public uint SegDs;

            /// ULONG->unsigned int
            public uint Edi;

            /// ULONG->unsigned int
            public uint Esi;

            /// ULONG->unsigned int
            public uint Ebx;

            /// ULONG->unsigned int
            public uint Edx;

            /// ULONG->unsigned int
            public uint Ecx;

            /// ULONG->unsigned int
            public uint Eax;

            /// ULONG->unsigned int
            public uint Ebp;

            /// ULONG->unsigned int
            public uint Eip;

            /// ULONG->unsigned int
            public uint SegCs;

            /// ULONG->unsigned int
            public uint EFlags;

            /// ULONG->unsigned int
            public uint Esp;

            /// ULONG->unsigned int
            public uint SegSs;

            /// UCHAR[512]
            [System.Runtime.InteropServices.MarshalAsAttribute(System.Runtime.InteropServices.UnmanagedType.ByValTStr, SizeConst = 512)]
            public string ExtendedRegisters;
        }

        [System.Runtime.InteropServices.StructLayoutAttribute(System.Runtime.InteropServices.LayoutKind.Sequential)]
        public struct KPROCESSOR_STATE
        {

            /// CONTEXT->_CONTEXT
            public CONTEXT ContextFrame;

            /// KSPECIAL_REGISTERS->_KSPECIAL_REGISTERS
            public KSPECIAL_REGISTERS SpecialRegisters;
        }

        [System.Runtime.InteropServices.StructLayoutAttribute(System.Runtime.InteropServices.LayoutKind.Sequential)]
        public struct Anonymous_422a3537_a4ba_4b54_968f_4e542e4f4962
        {

            /// UCHAR->unsigned char
            public byte CpuStepping;

            /// UCHAR->unsigned char
            public byte CpuModel;
        }

        [System.Runtime.InteropServices.StructLayoutAttribute(System.Runtime.InteropServices.LayoutKind.Explicit)]
        public struct Anonymous_a201b5a0_8375_44a6_9d58_f96a88972b80
        {

            /// WORD->unsigned short
            [System.Runtime.InteropServices.FieldOffsetAttribute(0)]
            public ushort CpuStep;

            /// Anonymous_422a3537_a4ba_4b54_968f_4e542e4f4962
            [System.Runtime.InteropServices.FieldOffsetAttribute(0)]
            public Anonymous_422a3537_a4ba_4b54_968f_4e542e4f4962 Struct1;
        }

        [System.Runtime.InteropServices.StructLayoutAttribute(System.Runtime.InteropServices.LayoutKind.Sequential, CharSet = System.Runtime.InteropServices.CharSet.Ansi)]
        public struct KPRCB
        {

            /// WORD->unsigned short
            public ushort MinorVersion;

            /// WORD->unsigned short
            public ushort MajorVersion;

            /// PKTHREAD->_KTHREAD*
            public System.IntPtr CurrentThread;

            /// PKTHREAD->_KTHREAD*
            public System.IntPtr NextThread;

            /// PKTHREAD->_KTHREAD*
            public System.IntPtr IdleThread;

            /// UCHAR->unsigned char
            public byte Number;

            /// UCHAR->unsigned char
            public byte NestingLevel;

            /// WORD->unsigned short
            public ushort BuildType;

            /// ULONG->unsigned int
            public uint SetMember;

            /// CHAR->char
            public byte CpuType;

            /// CHAR->char
            public byte CpuID;

            /// Anonymous_a201b5a0_8375_44a6_9d58_f96a88972b80
            public Anonymous_a201b5a0_8375_44a6_9d58_f96a88972b80 Union1;

            /// KPROCESSOR_STATE->_KPROCESSOR_STATE
            public KPROCESSOR_STATE ProcessorState;

            /// ULONG[16]
            [System.Runtime.InteropServices.MarshalAsAttribute(System.Runtime.InteropServices.UnmanagedType.ByValArray, SizeConst = 16, ArraySubType = System.Runtime.InteropServices.UnmanagedType.U4)]
            public uint[] KernelReserved;

            /// ULONG[16]
            [System.Runtime.InteropServices.MarshalAsAttribute(System.Runtime.InteropServices.UnmanagedType.ByValArray, SizeConst = 16, ArraySubType = System.Runtime.InteropServices.UnmanagedType.U4)]
            public uint[] HalReserved;

            /// ULONG->unsigned int
            public uint CFlushSize;

            /// UCHAR[88]
            [System.Runtime.InteropServices.MarshalAsAttribute(System.Runtime.InteropServices.UnmanagedType.ByValTStr, SizeConst = 88)]
            public string PrcbPad0;

            /// KSPIN_LOCK_QUEUE[33]
            [System.Runtime.InteropServices.MarshalAsAttribute(System.Runtime.InteropServices.UnmanagedType.ByValArray, SizeConst = 33, ArraySubType = System.Runtime.InteropServices.UnmanagedType.Struct)]
            public KSPIN_LOCK_QUEUE[] LockQueue;

            /// PKTHREAD->_KTHREAD*
            public System.IntPtr NpxThread;

            /// ULONG->unsigned int
            public uint InterruptCount;

            /// ULONG->unsigned int
            public uint KernelTime;

            /// ULONG->unsigned int
            public uint UserTime;

            /// ULONG->unsigned int
            public uint DpcTime;

            /// ULONG->unsigned int
            public uint DpcTimeCount;

            /// ULONG->unsigned int
            public uint InterruptTime;

            /// ULONG->unsigned int
            public uint AdjustDpcThreshold;

            /// ULONG->unsigned int
            public uint PageColor;

            /// UCHAR->unsigned char
            public byte SkipTick;

            /// UCHAR->unsigned char
            public byte DebuggerSavedIRQL;

            /// UCHAR->unsigned char
            public byte NodeColor;

            /// UCHAR->unsigned char
            public byte PollSlot;

            /// ULONG->unsigned int
            public uint NodeShiftedColor;

            /// PKNODE->_KNODE*
            public System.IntPtr ParentNode;

            /// ULONG->unsigned int
            public uint MultiThreadProcessorSet;

            /// PKPRCB->_KPRCB*
            public System.IntPtr MultiThreadSetMaster;

            /// ULONG->unsigned int
            public uint SecondaryColorMask;

            /// ULONG->unsigned int
            public uint DpcTimeLimit;

            /// ULONG->unsigned int
            public uint CcFastReadNoWait;

            /// ULONG->unsigned int
            public uint CcFastReadWait;

            /// ULONG->unsigned int
            public uint CcFastReadNotPossible;

            /// ULONG->unsigned int
            public uint CcCopyReadNoWait;

            /// ULONG->unsigned int
            public uint CcCopyReadWait;

            /// ULONG->unsigned int
            public uint CcCopyReadNoWaitMiss;

            /// LONG->int
            public int MmSpinLockOrdering;

            /// LONG->int
            public int IoReadOperationCount;

            /// LONG->int
            public int IoWriteOperationCount;

            /// LONG->int
            public int IoOtherOperationCount;

            /// LARGE_INTEGER->_LARGE_INTEGER
            public LARGE_INTEGER IoReadTransferCount;

            /// LARGE_INTEGER->_LARGE_INTEGER
            public LARGE_INTEGER IoWriteTransferCount;

            /// LARGE_INTEGER->_LARGE_INTEGER
            public LARGE_INTEGER IoOtherTransferCount;

            /// ULONG->unsigned int
            public uint CcFastMdlReadNoWait;

            /// ULONG->unsigned int
            public uint CcFastMdlReadWait;

            /// ULONG->unsigned int
            public uint CcFastMdlReadNotPossible;

            /// ULONG->unsigned int
            public uint CcMapDataNoWait;

            /// ULONG->unsigned int
            public uint CcMapDataWait;

            /// ULONG->unsigned int
            public uint CcPinMappedDataCount;

            /// ULONG->unsigned int
            public uint CcPinReadNoWait;

            /// ULONG->unsigned int
            public uint CcPinReadWait;

            /// ULONG->unsigned int
            public uint CcMdlReadNoWait;

            /// ULONG->unsigned int
            public uint CcMdlReadWait;

            /// ULONG->unsigned int
            public uint CcLazyWriteHotSpots;

            /// ULONG->unsigned int
            public uint CcLazyWriteIos;

            /// ULONG->unsigned int
            public uint CcLazyWritePages;

            /// ULONG->unsigned int
            public uint CcDataFlushes;

            /// ULONG->unsigned int
            public uint CcDataPages;

            /// ULONG->unsigned int
            public uint CcLostDelayedWrites;

            /// ULONG->unsigned int
            public uint CcFastReadResourceMiss;

            /// ULONG->unsigned int
            public uint CcCopyReadWaitMiss;

            /// ULONG->unsigned int
            public uint CcFastMdlReadResourceMiss;

            /// ULONG->unsigned int
            public uint CcMapDataNoWaitMiss;

            /// ULONG->unsigned int
            public uint CcMapDataWaitMiss;

            /// ULONG->unsigned int
            public uint CcPinReadNoWaitMiss;

            /// ULONG->unsigned int
            public uint CcPinReadWaitMiss;

            /// ULONG->unsigned int
            public uint CcMdlReadNoWaitMiss;

            /// ULONG->unsigned int
            public uint CcMdlReadWaitMiss;

            /// ULONG->unsigned int
            public uint CcReadAheadIos;

            /// ULONG->unsigned int
            public uint KeAlignmentFixupCount;

            /// ULONG->unsigned int
            public uint KeExceptionDispatchCount;

            /// ULONG->unsigned int
            public uint KeSystemCalls;

            /// ULONG[3]
            [System.Runtime.InteropServices.MarshalAsAttribute(System.Runtime.InteropServices.UnmanagedType.ByValArray, SizeConst = 3, ArraySubType = System.Runtime.InteropServices.UnmanagedType.U4)]
            public uint[] PrcbPad1;

            /// PP_LOOKASIDE_LIST[16]
            [System.Runtime.InteropServices.MarshalAsAttribute(System.Runtime.InteropServices.UnmanagedType.ByValArray, SizeConst = 16, ArraySubType = System.Runtime.InteropServices.UnmanagedType.Struct)]
            public PP_LOOKASIDE_LIST[] PPLookasideList;

            /// GENERAL_LOOKASIDE_POOL[32]
            [System.Runtime.InteropServices.MarshalAsAttribute(System.Runtime.InteropServices.UnmanagedType.ByValArray, SizeConst = 32, ArraySubType = System.Runtime.InteropServices.UnmanagedType.Struct)]
            public GENERAL_LOOKASIDE_POOL[] PPNPagedLookasideList;

            /// GENERAL_LOOKASIDE_POOL[32]
            [System.Runtime.InteropServices.MarshalAsAttribute(System.Runtime.InteropServices.UnmanagedType.ByValArray, SizeConst = 32, ArraySubType = System.Runtime.InteropServices.UnmanagedType.Struct)]
            public GENERAL_LOOKASIDE_POOL[] PPPagedLookasideList;

            /// ULONG->unsigned int
            public uint PacketBarrier;

            /// LONG->int
            public int ReverseStall;

            /// PVOID->void*
            public System.IntPtr IpiFrame;

            /// UCHAR[52]
            [System.Runtime.InteropServices.MarshalAsAttribute(System.Runtime.InteropServices.UnmanagedType.ByValTStr, SizeConst = 52)]
            public string PrcbPad2;

            /// void*[3]
            [System.Runtime.InteropServices.MarshalAsAttribute(System.Runtime.InteropServices.UnmanagedType.ByValArray, SizeConst = 3, ArraySubType = System.Runtime.InteropServices.UnmanagedType.SysUInt)]
            public System.IntPtr[] CurrentPacket;

            /// ULONG->unsigned int
            public uint TargetSet;

            /// PVOID->void*
            public System.IntPtr WorkerRoutine;

            /// ULONG->unsigned int
            public uint IpiFrozen;

            /// UCHAR[40]
            [System.Runtime.InteropServices.MarshalAsAttribute(System.Runtime.InteropServices.UnmanagedType.ByValTStr, SizeConst = 40)]
            public string PrcbPad3;

            /// ULONG->unsigned int
            public uint RequestSummary;

            /// PKPRCB->_KPRCB*
            public System.IntPtr SignalDone;

            /// UCHAR[56]
            [System.Runtime.InteropServices.MarshalAsAttribute(System.Runtime.InteropServices.UnmanagedType.ByValTStr, SizeConst = 56)]
            public string PrcbPad4;

            /// KDPC_DATA[2]
            [System.Runtime.InteropServices.MarshalAsAttribute(System.Runtime.InteropServices.UnmanagedType.ByValArray, SizeConst = 2, ArraySubType = System.Runtime.InteropServices.UnmanagedType.Struct)]
            public KDPC_DATA[] DpcData;

            /// PVOID->void*
            public System.IntPtr DpcStack;

            /// LONG->int
            public int MaximumDpcQueueDepth;

            /// ULONG->unsigned int
            public uint DpcRequestRate;

            /// ULONG->unsigned int
            public uint MinimumDpcRate;

            /// UCHAR->unsigned char
            public byte DpcInterruptRequested;

            /// UCHAR->unsigned char
            public byte DpcThreadRequested;

            /// UCHAR->unsigned char
            public byte DpcRoutineActive;

            /// UCHAR->unsigned char
            public byte DpcThreadActive;

            /// ULONG->unsigned int
            public uint PrcbLock;

            /// ULONG->unsigned int
            public uint DpcLastCount;

            /// ULONG->unsigned int
            public uint TimerHand;

            /// ULONG->unsigned int
            public uint TimerRequest;

            /// PVOID->void*
            public System.IntPtr PrcbPad41;

            /// KEVENT->_KEVENT
            public KEVENT DpcEvent;

            /// UCHAR->unsigned char
            public byte ThreadDpcEnable;

            /// UCHAR->unsigned char
            public byte QuantumEnd;

            /// UCHAR->unsigned char
            public byte PrcbPad50;

            /// UCHAR->unsigned char
            public byte IdleSchedule;

            /// LONG->int
            public int DpcSetEventRequest;

            /// LONG->int
            public int Sleeping;

            /// ULONG->unsigned int
            public uint PeriodicCount;

            /// ULONG->unsigned int
            public uint PeriodicBias;

            /// UCHAR[6]
            [System.Runtime.InteropServices.MarshalAsAttribute(System.Runtime.InteropServices.UnmanagedType.ByValTStr, SizeConst = 6)]
            public string PrcbPad5;

            /// LONG->int
            public int TickOffset;

            /// KDPC->_KDPC
            public KDPC CallDpc;

            /// LONG->int
            public int ClockKeepAlive;

            /// UCHAR->unsigned char
            public byte ClockCheckSlot;

            /// UCHAR->unsigned char
            public byte ClockPollCycle;

            /// UCHAR[2]
            [System.Runtime.InteropServices.MarshalAsAttribute(System.Runtime.InteropServices.UnmanagedType.ByValTStr, SizeConst = 2)]
            public string PrcbPad6;

            /// LONG->int
            public int DpcWatchdogPeriod;

            /// LONG->int
            public int DpcWatchdogCount;

            /// LONG->int
            public int ThreadWatchdogPeriod;

            /// LONG->int
            public int ThreadWatchdogCount;

            /// ULONG[2]
            [System.Runtime.InteropServices.MarshalAsAttribute(System.Runtime.InteropServices.UnmanagedType.ByValArray, SizeConst = 2, ArraySubType = System.Runtime.InteropServices.UnmanagedType.U4)]
            public uint[] PrcbPad70;

            /// LIST_ENTRY->_LIST_ENTRY
            public LIST_ENTRY WaitListHead;

            /// ULONG->unsigned int
            public uint WaitLock;

            /// ULONG->unsigned int
            public uint ReadySummary;

            /// ULONG->unsigned int
            public uint QueueIndex;

            /// SINGLE_LIST_ENTRY->_SINGLE_LIST_ENTRY
            public SINGLE_LIST_ENTRY DeferredReadyListHead;

            /// UINT64->unsigned __int64
            public ulong StartCycles;

            /// UINT64->unsigned __int64
            public ulong CycleTime;

            /// UINT64[3]
            [System.Runtime.InteropServices.MarshalAsAttribute(System.Runtime.InteropServices.UnmanagedType.ByValArray, SizeConst = 3, ArraySubType = System.Runtime.InteropServices.UnmanagedType.U8)]
            public ulong[] PrcbPad71;

            /// LIST_ENTRY[32]
            [System.Runtime.InteropServices.MarshalAsAttribute(System.Runtime.InteropServices.UnmanagedType.ByValArray, SizeConst = 32, ArraySubType = System.Runtime.InteropServices.UnmanagedType.Struct)]
            public LIST_ENTRY[] DispatcherReadyListHead;

            /// PVOID->void*
            public System.IntPtr ChainedInterruptList;

            /// LONG->int
            public int LookasideIrpFloat;

            /// LONG->int
            public int MmPageFaultCount;

            /// LONG->int
            public int MmCopyOnWriteCount;

            /// LONG->int
            public int MmTransitionCount;

            /// LONG->int
            public int MmCacheTransitionCount;

            /// LONG->int
            public int MmDemandZeroCount;

            /// LONG->int
            public int MmPageReadCount;

            /// LONG->int
            public int MmPageReadIoCount;

            /// LONG->int
            public int MmCacheReadCount;

            /// LONG->int
            public int MmCacheIoCount;

            /// LONG->int
            public int MmDirtyPagesWriteCount;

            /// LONG->int
            public int MmDirtyWriteIoCount;

            /// LONG->int
            public int MmMappedPagesWriteCount;

            /// LONG->int
            public int MmMappedWriteIoCount;

            /// ULONG->unsigned int
            public uint CachedCommit;

            /// ULONG->unsigned int
            public uint CachedResidentAvailable;

            /// PVOID->void*
            public System.IntPtr HyperPte;

            /// UCHAR->unsigned char
            public byte CpuVendor;

            /// UCHAR[3]
            [System.Runtime.InteropServices.MarshalAsAttribute(System.Runtime.InteropServices.UnmanagedType.ByValTStr, SizeConst = 3)]
            public string PrcbPad9;

            /// UCHAR[13]
            [System.Runtime.InteropServices.MarshalAsAttribute(System.Runtime.InteropServices.UnmanagedType.ByValTStr, SizeConst = 13)]
            public string VendorString;

            /// UCHAR->unsigned char
            public byte InitialApicId;

            /// UCHAR->unsigned char
            public byte CoresPerPhysicalProcessor;

            /// UCHAR->unsigned char
            public byte LogicalProcessorsPerPhysicalProcessor;

            /// ULONG->unsigned int
            public uint MHz;

            /// ULONG->unsigned int
            public uint FeatureBits;

            /// LARGE_INTEGER->_LARGE_INTEGER
            public LARGE_INTEGER UpdateSignature;

            /// UINT64->unsigned __int64
            public ulong IsrTime;

            /// UINT64->unsigned __int64
            public ulong SpareField1;

            /// FX_SAVE_AREA->_FX_SAVE_AREA
            public FX_SAVE_AREA NpxSaveArea;

            /// PROCESSOR_POWER_STATE->_PROCESSOR_POWER_STATE
            public PROCESSOR_POWER_STATE PowerState;

            /// KDPC->_KDPC
            public KDPC DpcWatchdogDpc;

            /// KTIMER->_KTIMER
            public KTIMER DpcWatchdogTimer;

            /// PVOID->void*
            public System.IntPtr WheaInfo;

            /// PVOID->void*
            public System.IntPtr EtwSupport;

            /// SLIST_HEADER->_SLIST_HEADER
            public SLIST_HEADER InterruptObjectPool;

            /// LARGE_INTEGER->_LARGE_INTEGER
            public LARGE_INTEGER HypercallPagePhysical;

            /// PVOID->void*
            public System.IntPtr HypercallPageVirtual;

            /// PVOID->void*
            public System.IntPtr RateControl;

            /// CACHE_DESCRIPTOR[5]
            [System.Runtime.InteropServices.MarshalAsAttribute(System.Runtime.InteropServices.UnmanagedType.ByValArray, SizeConst = 5, ArraySubType = System.Runtime.InteropServices.UnmanagedType.Struct)]
            public CACHE_DESCRIPTOR[] Cache;

            /// ULONG->unsigned int
            public uint CacheCount;

            /// ULONG[5]
            [System.Runtime.InteropServices.MarshalAsAttribute(System.Runtime.InteropServices.UnmanagedType.ByValArray, SizeConst = 5, ArraySubType = System.Runtime.InteropServices.UnmanagedType.U4)]
            public uint[] CacheProcessorMask;

            /// UCHAR->unsigned char
            public byte LogicalProcessorsPerCore;

            /// UCHAR[3]
            [System.Runtime.InteropServices.MarshalAsAttribute(System.Runtime.InteropServices.UnmanagedType.ByValTStr, SizeConst = 3)]
            public string PrcbPad8;

            /// ULONG->unsigned int
            public uint PackageProcessorSet;

            /// ULONG->unsigned int
            public uint CoreProcessorSet;
        }

        public enum EXCEPTION_DISPOSITION
        {

            /// ExceptionContinueExecution -> 0
            ExceptionContinueExecution = 0,

            /// ExceptionContinueSearch -> 1
            ExceptionContinueSearch = 1,

            /// ExceptionNestedException -> 2
            ExceptionNestedException = 2,

            /// ExceptionCollidedUnwind -> 3
            ExceptionCollidedUnwind = 3,
        }

        [System.Runtime.InteropServices.StructLayoutAttribute(System.Runtime.InteropServices.LayoutKind.Sequential)]
        public struct EXCEPTION_REGISTRATION_RECORD
        {

            /// PEXCEPTION_REGISTRATION_RECORD->_EXCEPTION_REGISTRATION_RECORD*
            public System.IntPtr Next;

            /// PEXCEPTION_DISPOSITION->_EXCEPTION_DISPOSITION*
            public System.IntPtr Handler;
        }

        [System.Runtime.InteropServices.StructLayoutAttribute(System.Runtime.InteropServices.LayoutKind.Sequential)]
        public struct KTRAP_FRAME
        {

            /// ULONG->unsigned int
            public uint DbgEbp;

            /// ULONG->unsigned int
            public uint DbgEip;

            /// ULONG->unsigned int
            public uint DbgArgMark;

            /// ULONG->unsigned int
            public uint DbgArgPointer;

            /// WORD->unsigned short
            public ushort TempSegCs;

            /// UCHAR->unsigned char
            public byte Logging;

            /// UCHAR->unsigned char
            public byte Reserved;

            /// ULONG->unsigned int
            public uint TempEsp;

            /// ULONG->unsigned int
            public uint Dr0;

            /// ULONG->unsigned int
            public uint Dr1;

            /// ULONG->unsigned int
            public uint Dr2;

            /// ULONG->unsigned int
            public uint Dr3;

            /// ULONG->unsigned int
            public uint Dr6;

            /// ULONG->unsigned int
            public uint Dr7;

            /// ULONG->unsigned int
            public uint SegGs;

            /// ULONG->unsigned int
            public uint SegEs;

            /// ULONG->unsigned int
            public uint SegDs;

            /// ULONG->unsigned int
            public uint Edx;

            /// ULONG->unsigned int
            public uint Ecx;

            /// ULONG->unsigned int
            public uint Eax;

            /// ULONG->unsigned int
            public uint PreviousPreviousMode;

            /// PEXCEPTION_REGISTRATION_RECORD->_EXCEPTION_REGISTRATION_RECORD*
            public System.IntPtr ExceptionList;

            /// ULONG->unsigned int
            public uint SegFs;

            /// ULONG->unsigned int
            public uint Edi;

            /// ULONG->unsigned int
            public uint Esi;

            /// ULONG->unsigned int
            public uint Ebx;

            /// ULONG->unsigned int
            public uint Ebp;

            /// ULONG->unsigned int
            public uint ErrCode;

            /// ULONG->unsigned int
            public uint Eip;

            /// ULONG->unsigned int
            public uint SegCs;

            /// ULONG->unsigned int
            public uint EFlags;

            /// ULONG->unsigned int
            public uint HardwareEsp;

            /// ULONG->unsigned int
            public uint HardwareSegSs;

            /// ULONG->unsigned int
            public uint V86Es;

            /// ULONG->unsigned int
            public uint V86Ds;

            /// ULONG->unsigned int
            public uint V86Fs;

            /// ULONG->unsigned int
            public uint V86Gs;
        }

        [System.Runtime.InteropServices.StructLayoutAttribute(System.Runtime.InteropServices.LayoutKind.Sequential)]
        public struct KDPC
        {

            /// UCHAR->unsigned char
            public byte Type;

            /// UCHAR->unsigned char
            public byte Importance;

            /// WORD->unsigned short
            public ushort Number;

            /// LIST_ENTRY->_LIST_ENTRY
            public LIST_ENTRY DpcListEntry;

            /// PVOID->void*
            public System.IntPtr DeferredRoutine;

            /// PVOID->void*
            public System.IntPtr DeferredContext;

            /// PVOID->void*
            public System.IntPtr SystemArgument1;

            /// PVOID->void*
            public System.IntPtr SystemArgument2;

            /// PVOID->void*
            public System.IntPtr DpcData;
        }

        [System.Runtime.InteropServices.StructLayoutAttribute(System.Runtime.InteropServices.LayoutKind.Sequential)]
        public struct KTIMER
        {

            /// DISPATCHER_HEADER->_DISPATCHER_HEADER
            public DISPATCHER_HEADER Header;

            /// ULARGE_INTEGER->_ULARGE_INTEGER
            public ULARGE_INTEGER DueTime;

            /// LIST_ENTRY->_LIST_ENTRY
            public LIST_ENTRY TimerListEntry;

            /// PKDPC->_KDPC*
            public System.IntPtr Dpc;

            /// LONG->int
            public int Period;
        }

        [System.Runtime.InteropServices.StructLayoutAttribute(System.Runtime.InteropServices.LayoutKind.Sequential)]
        public struct KQUEUE
        {

            /// DISPATCHER_HEADER->_DISPATCHER_HEADER
            public DISPATCHER_HEADER Header;

            /// LIST_ENTRY->_LIST_ENTRY
            public LIST_ENTRY EntryListHead;

            /// ULONG->unsigned int
            public uint CurrentCount;

            /// ULONG->unsigned int
            public uint MaximumCount;

            /// LIST_ENTRY->_LIST_ENTRY
            public LIST_ENTRY ThreadListHead;
        }

        [System.Runtime.InteropServices.StructLayoutAttribute(System.Runtime.InteropServices.LayoutKind.Sequential)]
        public struct KGATE
        {

            /// DISPATCHER_HEADER->_DISPATCHER_HEADER
            public DISPATCHER_HEADER Header;
        }

        [System.Runtime.InteropServices.StructLayoutAttribute(System.Runtime.InteropServices.LayoutKind.Sequential)]
        public struct KWAIT_BLOCK
        {

            /// LIST_ENTRY->_LIST_ENTRY
            public LIST_ENTRY WaitListEntry;

            /// PKTHREAD->_KTHREAD*
            public System.IntPtr Thread;

            /// PVOID->void*
            public System.IntPtr Object;

            /// PKWAIT_BLOCK->_KWAIT_BLOCK*
            public System.IntPtr NextWaitBlock;

            /// WORD->unsigned short
            public ushort WaitKey;

            /// UCHAR->unsigned char
            public byte WaitType;

            /// UCHAR->unsigned char
            public byte SpareByte;
        }

        [System.Runtime.InteropServices.StructLayoutAttribute(System.Runtime.InteropServices.LayoutKind.Sequential)]
        public struct KEXECUTE_OPTIONS
        {

            /// ExecuteDisable : 1
            ///ExecuteEnable : 1
            ///DisableThunkEmulation : 1
            ///Permanent : 1
            ///ExecuteDispatchEnable : 1
            ///ImageDispatchEnable : 1
            ///Spare : 2
            public uint bitvector1;

            public uint ExecuteDisable
            {
                get
                {
                    return ((uint)((this.bitvector1 & 1u)));
                }
                set
                {
                    this.bitvector1 = ((uint)((value | this.bitvector1)));
                }
            }

            public uint ExecuteEnable
            {
                get
                {
                    return ((uint)(((this.bitvector1 & 2u)
                                / 2)));
                }
                set
                {
                    this.bitvector1 = ((uint)(((value * 2)
                                | this.bitvector1)));
                }
            }

            public uint DisableThunkEmulation
            {
                get
                {
                    return ((uint)(((this.bitvector1 & 4u)
                                / 4)));
                }
                set
                {
                    this.bitvector1 = ((uint)(((value * 4)
                                | this.bitvector1)));
                }
            }

            public uint Permanent
            {
                get
                {
                    return ((uint)(((this.bitvector1 & 8u)
                                / 8)));
                }
                set
                {
                    this.bitvector1 = ((uint)(((value * 8)
                                | this.bitvector1)));
                }
            }

            public uint ExecuteDispatchEnable
            {
                get
                {
                    return ((uint)(((this.bitvector1 & 16u)
                                / 16)));
                }
                set
                {
                    this.bitvector1 = ((uint)(((value * 16)
                                | this.bitvector1)));
                }
            }

            public uint ImageDispatchEnable
            {
                get
                {
                    return ((uint)(((this.bitvector1 & 32u)
                                / 32)));
                }
                set
                {
                    this.bitvector1 = ((uint)(((value * 32)
                                | this.bitvector1)));
                }
            }

            public uint Spare
            {
                get
                {
                    return ((uint)(((this.bitvector1 & 192u)
                                / 64)));
                }
                set
                {
                    this.bitvector1 = ((uint)(((value * 64)
                                | this.bitvector1)));
                }
            }
        }

        [System.Runtime.InteropServices.StructLayoutAttribute(System.Runtime.InteropServices.LayoutKind.Sequential)]
        public struct KIDTENTRY
        {

            /// WORD->unsigned short
            public ushort Offset;

            /// WORD->unsigned short
            public ushort Selector;

            /// WORD->unsigned short
            public ushort Access;

            /// WORD->unsigned short
            public ushort ExtendedOffset;
        }

        [System.Runtime.InteropServices.StructLayoutAttribute(System.Runtime.InteropServices.LayoutKind.Sequential)]
        public struct KGDTENTRY
        {

            /// WORD->unsigned short
            public ushort LimitLow;

            /// WORD->unsigned short
            public ushort BaseLow;

            /// ULONG->unsigned int
            public uint HighWord;
        }

        [System.Runtime.InteropServices.StructLayoutAttribute(System.Runtime.InteropServices.LayoutKind.Explicit)]
        public struct Anonymous_c1a14938_a72f_465f_b212_9731e3df45f0
        {

            /// AutoAlignment : 1
            ///DisableBoost : 1
            ///DisableQuantum : 1
            ///ReservedFlags : 29
            [System.Runtime.InteropServices.FieldOffsetAttribute(0)]
            public uint bitvector1;

            /// LONG->int
            [System.Runtime.InteropServices.FieldOffsetAttribute(0)]
            public int ProcessFlags;

            public uint AutoAlignment
            {
                get
                {
                    return ((uint)((this.bitvector1 & 1u)));
                }
                set
                {
                    this.bitvector1 = ((uint)((value | this.bitvector1)));
                }
            }

            public uint DisableBoost
            {
                get
                {
                    return ((uint)(((this.bitvector1 & 2u)
                                / 2)));
                }
                set
                {
                    this.bitvector1 = ((uint)(((value * 2)
                                | this.bitvector1)));
                }
            }

            public uint DisableQuantum
            {
                get
                {
                    return ((uint)(((this.bitvector1 & 4u)
                                / 4)));
                }
                set
                {
                    this.bitvector1 = ((uint)(((value * 4)
                                | this.bitvector1)));
                }
            }

            public uint ReservedFlags
            {
                get
                {
                    return ((uint)(((this.bitvector1 & 4294967288u)
                                / 8)));
                }
                set
                {
                    this.bitvector1 = ((uint)(((value * 8)
                                | this.bitvector1)));
                }
            }
        }

        [System.Runtime.InteropServices.StructLayoutAttribute(System.Runtime.InteropServices.LayoutKind.Explicit)]
        public struct Anonymous_e4c013f2_4a3d_4e5f_8029_2f628fb44cfe
        {

            /// KEXECUTE_OPTIONS->_KEXECUTE_OPTIONS
            [System.Runtime.InteropServices.FieldOffsetAttribute(0)]
            public KEXECUTE_OPTIONS Flags;

            /// UCHAR->unsigned char
            [System.Runtime.InteropServices.FieldOffsetAttribute(0)]
            public byte ExecuteOptions;
        }

        [System.Runtime.InteropServices.StructLayoutAttribute(System.Runtime.InteropServices.LayoutKind.Sequential)]
        public struct KPROCESS
        {

            /// DISPATCHER_HEADER->_DISPATCHER_HEADER
            public DISPATCHER_HEADER Header;

            /// LIST_ENTRY->_LIST_ENTRY
            public LIST_ENTRY ProfileListHead;

            /// ULONG->unsigned int
            public uint DirectoryTableBase;

            /// ULONG->unsigned int
            public uint Unused0;

            /// KGDTENTRY->_KGDTENTRY
            public KGDTENTRY LdtDescriptor;

            /// KIDTENTRY->_KIDTENTRY
            public KIDTENTRY Int21Descriptor;

            /// WORD->unsigned short
            public ushort IopmOffset;

            /// UCHAR->unsigned char
            public byte Iopl;

            /// UCHAR->unsigned char
            public byte Unused;

            /// ULONG->unsigned int
            public uint ActiveProcessors;

            /// ULONG->unsigned int
            public uint KernelTime;

            /// ULONG->unsigned int
            public uint UserTime;

            /// LIST_ENTRY->_LIST_ENTRY
            public LIST_ENTRY ReadyListHead;

            /// SINGLE_LIST_ENTRY->_SINGLE_LIST_ENTRY
            public SINGLE_LIST_ENTRY SwapListEntry;

            /// PVOID->void*
            public System.IntPtr VdmTrapcHandler;

            /// LIST_ENTRY->_LIST_ENTRY
            public LIST_ENTRY ThreadListHead;

            /// ULONG->unsigned int
            public uint ProcessLock;

            /// ULONG->unsigned int
            public uint Affinity;

            /// Anonymous_c1a14938_a72f_465f_b212_9731e3df45f0
            public Anonymous_c1a14938_a72f_465f_b212_9731e3df45f0 Union1;

            /// CHAR->char
            public byte BasePriority;

            /// CHAR->char
            public byte QuantumReset;

            /// UCHAR->unsigned char
            public byte State;

            /// UCHAR->unsigned char
            public byte ThreadSeed;

            /// UCHAR->unsigned char
            public byte PowerState;

            /// UCHAR->unsigned char
            public byte IdealNode;

            /// UCHAR->unsigned char
            public byte Visited;

            /// Anonymous_e4c013f2_4a3d_4e5f_8029_2f628fb44cfe
            public Anonymous_e4c013f2_4a3d_4e5f_8029_2f628fb44cfe Union2;

            /// ULONG->unsigned int
            public uint StackCount;

            /// LIST_ENTRY->_LIST_ENTRY
            public LIST_ENTRY ProcessListEntry;

            /// UINT64->unsigned __int64
            public ulong CycleTime;
        }

        [System.Runtime.InteropServices.StructLayoutAttribute(System.Runtime.InteropServices.LayoutKind.Sequential)]
        public struct KAPC_STATE
        {

            /// LIST_ENTRY[2]
            [System.Runtime.InteropServices.MarshalAsAttribute(System.Runtime.InteropServices.UnmanagedType.ByValArray, SizeConst = 2, ArraySubType = System.Runtime.InteropServices.UnmanagedType.Struct)]
            public LIST_ENTRY[] ApcListHead;

            /// PKPROCESS->_KPROCESS*
            public System.IntPtr Process;

            /// UCHAR->unsigned char
            public byte KernelApcInProgress;

            /// UCHAR->unsigned char
            public byte KernelApcPending;

            /// UCHAR->unsigned char
            public byte UserApcPending;
        }

        [System.Runtime.InteropServices.StructLayoutAttribute(System.Runtime.InteropServices.LayoutKind.Explicit)]
        public struct Anonymous_54bb57f0_034b_4fed_bb68_e39537e900ae
        {

            /// UCHAR->unsigned char
            [System.Runtime.InteropServices.FieldOffsetAttribute(0)]
            public byte Abandoned;

            /// UCHAR->unsigned char
            [System.Runtime.InteropServices.FieldOffsetAttribute(0)]
            public byte Absolute;

            /// UCHAR->unsigned char
            [System.Runtime.InteropServices.FieldOffsetAttribute(0)]
            public byte NpxIrql;

            /// UCHAR->unsigned char
            [System.Runtime.InteropServices.FieldOffsetAttribute(0)]
            public byte Signalling;
        }

        [System.Runtime.InteropServices.StructLayoutAttribute(System.Runtime.InteropServices.LayoutKind.Explicit)]
        public struct Anonymous_9b171f12_800a_4c4b_b315_f6af0a8c574e
        {

            /// UCHAR->unsigned char
            [System.Runtime.InteropServices.FieldOffsetAttribute(0)]
            public byte Size;

            /// UCHAR->unsigned char
            [System.Runtime.InteropServices.FieldOffsetAttribute(0)]
            public byte Hand;
        }

        [System.Runtime.InteropServices.StructLayoutAttribute(System.Runtime.InteropServices.LayoutKind.Explicit)]
        public struct Anonymous_cc294b2b_e79e_4663_bc54_3b231a560c23
        {

            /// UCHAR->unsigned char
            [System.Runtime.InteropServices.FieldOffsetAttribute(0)]
            public byte Inserted;

            /// UCHAR->unsigned char
            [System.Runtime.InteropServices.FieldOffsetAttribute(0)]
            public byte DebugActive;

            /// UCHAR->unsigned char
            [System.Runtime.InteropServices.FieldOffsetAttribute(0)]
            public byte DpcActive;
        }

        [System.Runtime.InteropServices.StructLayoutAttribute(System.Runtime.InteropServices.LayoutKind.Sequential)]
        public struct Anonymous_994483f6_b670_4a06_9f87_32b09c5afd1b
        {

            /// UCHAR->unsigned char
            public byte Type;

            /// Anonymous_54bb57f0_034b_4fed_bb68_e39537e900ae
            public Anonymous_54bb57f0_034b_4fed_bb68_e39537e900ae Union1;

            /// Anonymous_9b171f12_800a_4c4b_b315_f6af0a8c574e
            public Anonymous_9b171f12_800a_4c4b_b315_f6af0a8c574e Union2;

            /// Anonymous_cc294b2b_e79e_4663_bc54_3b231a560c23
            public Anonymous_cc294b2b_e79e_4663_bc54_3b231a560c23 Union3;
        }

        [System.Runtime.InteropServices.StructLayoutAttribute(System.Runtime.InteropServices.LayoutKind.Explicit)]
        public struct Anonymous_2601f3a2_da6d_41a2_ad2b_69e38efc2f2c
        {

            /// Anonymous_994483f6_b670_4a06_9f87_32b09c5afd1b
            [System.Runtime.InteropServices.FieldOffsetAttribute(0)]
            public Anonymous_994483f6_b670_4a06_9f87_32b09c5afd1b Struct1;

            /// LONG->int
            [System.Runtime.InteropServices.FieldOffsetAttribute(0)]
            public int Lock;
        }

        [System.Runtime.InteropServices.StructLayoutAttribute(System.Runtime.InteropServices.LayoutKind.Sequential)]
        public struct DISPATCHER_HEADER
        {

            /// Anonymous_2601f3a2_da6d_41a2_ad2b_69e38efc2f2c
            public Anonymous_2601f3a2_da6d_41a2_ad2b_69e38efc2f2c Union1;

            /// LONG->int
            public int SignalState;

            /// LIST_ENTRY->_LIST_ENTRY
            public LIST_ENTRY WaitListHead;
        }

        [System.Runtime.InteropServices.StructLayoutAttribute(System.Runtime.InteropServices.LayoutKind.Explicit)]
        public struct Anonymous_a0a1d442_e8cc_43e8_9359_10a76cc415f5
        {

            /// KAPC_STATE->_KAPC_STATE
            [System.Runtime.InteropServices.FieldOffsetAttribute(0)]
            public KAPC_STATE ApcState;

            /// UCHAR[23]
            [System.Runtime.InteropServices.MarshalAsAttribute(System.Runtime.InteropServices.UnmanagedType.ByValArray, SizeConst = 23, ArraySubType = System.Runtime.InteropServices.UnmanagedType.I1)]
            [System.Runtime.InteropServices.FieldOffsetAttribute(0)]
            public byte[] ApcStateFill;
        }

        [System.Runtime.InteropServices.StructLayoutAttribute(System.Runtime.InteropServices.LayoutKind.Explicit)]
        public struct Anonymous_1edcaa8a_6e90_40d7_ad1c_2795998ecaac
        {

            /// PKWAIT_BLOCK->_KWAIT_BLOCK*
            [System.Runtime.InteropServices.FieldOffsetAttribute(0)]
            public System.IntPtr WaitBlockList;

            /// PKGATE->_KGATE*
            [System.Runtime.InteropServices.FieldOffsetAttribute(0)]
            public System.IntPtr GateObject;
        }

        [System.Runtime.InteropServices.StructLayoutAttribute(System.Runtime.InteropServices.LayoutKind.Explicit)]
        public struct Anonymous_09c75260_1c20_4ab2_b948_061a79a487cf
        {

            /// KernelStackResident : 1
            ///ReadyTransition : 1
            ///ProcessReadyQueue : 1
            ///WaitNext : 1
            ///SystemAffinityActive : 1
            ///Alertable : 1
            ///GdiFlushActive : 1
            ///Reserved : 25
            [System.Runtime.InteropServices.FieldOffsetAttribute(0)]
            public uint bitvector1;

            /// LONG->int
            [System.Runtime.InteropServices.FieldOffsetAttribute(0)]
            public int MiscFlags;

            public uint KernelStackResident
            {
                get
                {
                    return ((uint)((this.bitvector1 & 1u)));
                }
                set
                {
                    this.bitvector1 = ((uint)((value | this.bitvector1)));
                }
            }

            public uint ReadyTransition
            {
                get
                {
                    return ((uint)(((this.bitvector1 & 2u)
                                / 2)));
                }
                set
                {
                    this.bitvector1 = ((uint)(((value * 2)
                                | this.bitvector1)));
                }
            }

            public uint ProcessReadyQueue
            {
                get
                {
                    return ((uint)(((this.bitvector1 & 4u)
                                / 4)));
                }
                set
                {
                    this.bitvector1 = ((uint)(((value * 4)
                                | this.bitvector1)));
                }
            }

            public uint WaitNext
            {
                get
                {
                    return ((uint)(((this.bitvector1 & 8u)
                                / 8)));
                }
                set
                {
                    this.bitvector1 = ((uint)(((value * 8)
                                | this.bitvector1)));
                }
            }

            public uint SystemAffinityActive
            {
                get
                {
                    return ((uint)(((this.bitvector1 & 16u)
                                / 16)));
                }
                set
                {
                    this.bitvector1 = ((uint)(((value * 16)
                                | this.bitvector1)));
                }
            }

            public uint Alertable
            {
                get
                {
                    return ((uint)(((this.bitvector1 & 32u)
                                / 32)));
                }
                set
                {
                    this.bitvector1 = ((uint)(((value * 32)
                                | this.bitvector1)));
                }
            }

            public uint GdiFlushActive
            {
                get
                {
                    return ((uint)(((this.bitvector1 & 64u)
                                / 64)));
                }
                set
                {
                    this.bitvector1 = ((uint)(((value * 64)
                                | this.bitvector1)));
                }
            }

            public uint Reserved
            {
                get
                {
                    return ((uint)(((this.bitvector1 & 4294967168u)
                                / 128)));
                }
                set
                {
                    this.bitvector1 = ((uint)(((value * 128)
                                | this.bitvector1)));
                }
            }
        }

        [System.Runtime.InteropServices.StructLayoutAttribute(System.Runtime.InteropServices.LayoutKind.Explicit)]
        public struct Anonymous_40652056_2b6c_4667_955c_ef22022eca0f
        {

            /// LIST_ENTRY->_LIST_ENTRY
            [System.Runtime.InteropServices.FieldOffsetAttribute(0)]
            public LIST_ENTRY WaitListEntry;

            /// SINGLE_LIST_ENTRY->_SINGLE_LIST_ENTRY
            [System.Runtime.InteropServices.FieldOffsetAttribute(0)]
            public SINGLE_LIST_ENTRY SwapListEntry;
        }

        [System.Runtime.InteropServices.StructLayoutAttribute(System.Runtime.InteropServices.LayoutKind.Sequential)]
        public struct Anonymous_964d3714_c7b2_4e3d_9827_d668bdbc51a3
        {

            /// SHORT->short
            public short KernelApcDisable;

            /// SHORT->short
            public short SpecialApcDisable;
        }

        [System.Runtime.InteropServices.StructLayoutAttribute(System.Runtime.InteropServices.LayoutKind.Explicit)]
        public struct Anonymous_a7393dbf_0149_4f23_b9d3_b2a01ed988c4
        {

            /// Anonymous_964d3714_c7b2_4e3d_9827_d668bdbc51a3
            [System.Runtime.InteropServices.FieldOffsetAttribute(0)]
            public Anonymous_964d3714_c7b2_4e3d_9827_d668bdbc51a3 Struct1;

            /// ULONG->unsigned int
            [System.Runtime.InteropServices.FieldOffsetAttribute(0)]
            public uint CombinedApcDisable;
        }

        [System.Runtime.InteropServices.StructLayoutAttribute(System.Runtime.InteropServices.LayoutKind.Explicit)]
        public struct Anonymous_384954b7_a696_4d6d_8b08_1d4833eae197
        {

            /// KTIMER->_KTIMER
            [System.Runtime.InteropServices.FieldOffsetAttribute(0)]
            public KTIMER Timer;

            /// UCHAR[40]
            [System.Runtime.InteropServices.MarshalAsAttribute(System.Runtime.InteropServices.UnmanagedType.ByValArray, SizeConst = 40, ArraySubType = System.Runtime.InteropServices.UnmanagedType.I1)]
            [System.Runtime.InteropServices.FieldOffsetAttribute(0)]
            public byte[] TimerFill;
        }

        [System.Runtime.InteropServices.StructLayoutAttribute(System.Runtime.InteropServices.LayoutKind.Explicit)]
        public struct Anonymous_cf6b66d7_3e9d_49e3_b844_b6d2ee4da24c
        {

            /// AutoAlignment : 1
            ///DisableBoost : 1
            ///EtwStackTraceApc1Inserted : 1
            ///EtwStackTraceApc2Inserted : 1
            ///CycleChargePending : 1
            ///CalloutActive : 1
            ///ApcQueueable : 1
            ///EnableStackSwap : 1
            ///GuiThread : 1
            ///ReservedFlags : 23
            [System.Runtime.InteropServices.FieldOffsetAttribute(0)]
            public uint bitvector1;

            /// LONG->int
            [System.Runtime.InteropServices.FieldOffsetAttribute(0)]
            public int ThreadFlags;

            public uint AutoAlignment
            {
                get
                {
                    return ((uint)((this.bitvector1 & 1u)));
                }
                set
                {
                    this.bitvector1 = ((uint)((value | this.bitvector1)));
                }
            }

            public uint DisableBoost
            {
                get
                {
                    return ((uint)(((this.bitvector1 & 2u)
                                / 2)));
                }
                set
                {
                    this.bitvector1 = ((uint)(((value * 2)
                                | this.bitvector1)));
                }
            }

            public uint EtwStackTraceApc1Inserted
            {
                get
                {
                    return ((uint)(((this.bitvector1 & 4u)
                                / 4)));
                }
                set
                {
                    this.bitvector1 = ((uint)(((value * 4)
                                | this.bitvector1)));
                }
            }

            public uint EtwStackTraceApc2Inserted
            {
                get
                {
                    return ((uint)(((this.bitvector1 & 8u)
                                / 8)));
                }
                set
                {
                    this.bitvector1 = ((uint)(((value * 8)
                                | this.bitvector1)));
                }
            }

            public uint CycleChargePending
            {
                get
                {
                    return ((uint)(((this.bitvector1 & 16u)
                                / 16)));
                }
                set
                {
                    this.bitvector1 = ((uint)(((value * 16)
                                | this.bitvector1)));
                }
            }

            public uint CalloutActive
            {
                get
                {
                    return ((uint)(((this.bitvector1 & 32u)
                                / 32)));
                }
                set
                {
                    this.bitvector1 = ((uint)(((value * 32)
                                | this.bitvector1)));
                }
            }

            public uint ApcQueueable
            {
                get
                {
                    return ((uint)(((this.bitvector1 & 64u)
                                / 64)));
                }
                set
                {
                    this.bitvector1 = ((uint)(((value * 64)
                                | this.bitvector1)));
                }
            }

            public uint EnableStackSwap
            {
                get
                {
                    return ((uint)(((this.bitvector1 & 128u)
                                / 128)));
                }
                set
                {
                    this.bitvector1 = ((uint)(((value * 128)
                                | this.bitvector1)));
                }
            }

            public uint GuiThread
            {
                get
                {
                    return ((uint)(((this.bitvector1 & 256u)
                                / 256)));
                }
                set
                {
                    this.bitvector1 = ((uint)(((value * 256)
                                | this.bitvector1)));
                }
            }

            public uint ReservedFlags
            {
                get
                {
                    return ((uint)(((this.bitvector1 & 4294966784u)
                                / 512)));
                }
                set
                {
                    this.bitvector1 = ((uint)(((value * 512)
                                | this.bitvector1)));
                }
            }
        }

        [System.Runtime.InteropServices.StructLayoutAttribute(System.Runtime.InteropServices.LayoutKind.Sequential, CharSet = System.Runtime.InteropServices.CharSet.Ansi)]
        public struct Anonymous_e88fba0d_e84e_4a6e_8a4a_16c8f66fd552
        {

            /// UCHAR[23]
            [System.Runtime.InteropServices.MarshalAsAttribute(System.Runtime.InteropServices.UnmanagedType.ByValTStr, SizeConst = 23)]
            public string WaitBlockFill0;

            /// UCHAR->unsigned char
            public byte IdealProcessor;
        }

        [System.Runtime.InteropServices.StructLayoutAttribute(System.Runtime.InteropServices.LayoutKind.Sequential, CharSet = System.Runtime.InteropServices.CharSet.Ansi)]
        public struct Anonymous_c8b56258_9e0a_448c_8bd0_952a0ed77d0b
        {

            /// UCHAR[47]
            [System.Runtime.InteropServices.MarshalAsAttribute(System.Runtime.InteropServices.UnmanagedType.ByValTStr, SizeConst = 47)]
            public string WaitBlockFill1;

            /// CHAR->char
            public byte PreviousMode;
        }

        [System.Runtime.InteropServices.StructLayoutAttribute(System.Runtime.InteropServices.LayoutKind.Sequential, CharSet = System.Runtime.InteropServices.CharSet.Ansi)]
        public struct Anonymous_17c2fd77_9c60_4e66_bc82_44690bbbc6f6
        {

            /// UCHAR[71]
            [System.Runtime.InteropServices.MarshalAsAttribute(System.Runtime.InteropServices.UnmanagedType.ByValTStr, SizeConst = 71)]
            public string WaitBlockFill2;

            /// UCHAR->unsigned char
            public byte ResourceIndex;
        }

        [System.Runtime.InteropServices.StructLayoutAttribute(System.Runtime.InteropServices.LayoutKind.Explicit)]
        public struct Anonymous_640c844f_7a22_413f_aed8_9904d6cd398f
        {

            /// KWAIT_BLOCK[4]
            [System.Runtime.InteropServices.MarshalAsAttribute(System.Runtime.InteropServices.UnmanagedType.ByValArray, SizeConst = 4, ArraySubType = System.Runtime.InteropServices.UnmanagedType.Struct)]
            [System.Runtime.InteropServices.FieldOffsetAttribute(0)]
            public KWAIT_BLOCK[] WaitBlock;

            /// Anonymous_e88fba0d_e84e_4a6e_8a4a_16c8f66fd552
            [System.Runtime.InteropServices.FieldOffsetAttribute(0)]
            public Anonymous_e88fba0d_e84e_4a6e_8a4a_16c8f66fd552 Struct1;

            /// Anonymous_c8b56258_9e0a_448c_8bd0_952a0ed77d0b
            [System.Runtime.InteropServices.FieldOffsetAttribute(0)]
            public Anonymous_c8b56258_9e0a_448c_8bd0_952a0ed77d0b Struct2;

            /// Anonymous_17c2fd77_9c60_4e66_bc82_44690bbbc6f6
            [System.Runtime.InteropServices.FieldOffsetAttribute(0)]
            public Anonymous_17c2fd77_9c60_4e66_bc82_44690bbbc6f6 Struct3;

            /// UCHAR[95]
            [System.Runtime.InteropServices.MarshalAsAttribute(System.Runtime.InteropServices.UnmanagedType.ByValArray, SizeConst = 95, ArraySubType = System.Runtime.InteropServices.UnmanagedType.I1)]
            [System.Runtime.InteropServices.FieldOffsetAttribute(0)]
            public byte[] WaitBlockFill3;
        }

        [System.Runtime.InteropServices.StructLayoutAttribute(System.Runtime.InteropServices.LayoutKind.Explicit)]
        public struct Anonymous_8c3cbe6d_41f6_4b6c_9502_108e0d4bda93
        {

            /// PVOID->void*
            [System.Runtime.InteropServices.FieldOffsetAttribute(0)]
            public System.IntPtr CallbackStack;

            /// ULONG->unsigned int
            [System.Runtime.InteropServices.FieldOffsetAttribute(0)]
            public uint CallbackDepth;
        }

        [System.Runtime.InteropServices.StructLayoutAttribute(System.Runtime.InteropServices.LayoutKind.Explicit)]
        public struct Anonymous_8414609a_6a06_420b_837f_7e063f21a277
        {

            /// KAPC_STATE->_KAPC_STATE
            [System.Runtime.InteropServices.FieldOffsetAttribute(0)]
            public KAPC_STATE SavedApcState;

            /// UCHAR[23]
            [System.Runtime.InteropServices.MarshalAsAttribute(System.Runtime.InteropServices.UnmanagedType.ByValArray, SizeConst = 23, ArraySubType = System.Runtime.InteropServices.UnmanagedType.I1)]
            [System.Runtime.InteropServices.FieldOffsetAttribute(0)]
            public byte[] SavedApcStateFill;
        }

        [System.Runtime.InteropServices.StructLayoutAttribute(System.Runtime.InteropServices.LayoutKind.Sequential, CharSet = System.Runtime.InteropServices.CharSet.Ansi)]
        public struct Anonymous_e7ebae04_7ba9_470f_ba3f_9cb94460a1ae
        {

            /// UCHAR[1]
            [System.Runtime.InteropServices.MarshalAsAttribute(System.Runtime.InteropServices.UnmanagedType.ByValTStr, SizeConst = 1)]
            public string SuspendApcFill0;

            /// CHAR->char
            public byte Spare04;
        }

        [System.Runtime.InteropServices.StructLayoutAttribute(System.Runtime.InteropServices.LayoutKind.Sequential, CharSet = System.Runtime.InteropServices.CharSet.Ansi)]
        public struct Anonymous_b5580e4d_b0de_4af7_b5af_e233b171fbf8
        {

            /// UCHAR[3]
            [System.Runtime.InteropServices.MarshalAsAttribute(System.Runtime.InteropServices.UnmanagedType.ByValTStr, SizeConst = 3)]
            public string SuspendApcFill1;

            /// UCHAR->unsigned char
            public byte QuantumReset;
        }

        [System.Runtime.InteropServices.StructLayoutAttribute(System.Runtime.InteropServices.LayoutKind.Sequential, CharSet = System.Runtime.InteropServices.CharSet.Ansi)]
        public struct Anonymous_5d49ad2d_5e70_4bf5_836f_d90809c3f8fc
        {

            /// UCHAR[4]
            [System.Runtime.InteropServices.MarshalAsAttribute(System.Runtime.InteropServices.UnmanagedType.ByValTStr, SizeConst = 4)]
            public string SuspendApcFill2;

            /// ULONG->unsigned int
            public uint KernelTime;
        }

        [System.Runtime.InteropServices.StructLayoutAttribute(System.Runtime.InteropServices.LayoutKind.Sequential, CharSet = System.Runtime.InteropServices.CharSet.Ansi)]
        public struct Anonymous_52182e3e_009d_4b7e_8850_bd5fdbfc8bf5
        {

            /// UCHAR[36]
            [System.Runtime.InteropServices.MarshalAsAttribute(System.Runtime.InteropServices.UnmanagedType.ByValTStr, SizeConst = 36)]
            public string SuspendApcFill3;

            /// PKPRCB->_KPRCB*
            public System.IntPtr WaitPrcb;
        }

        [System.Runtime.InteropServices.StructLayoutAttribute(System.Runtime.InteropServices.LayoutKind.Sequential, CharSet = System.Runtime.InteropServices.CharSet.Ansi)]
        public struct Anonymous_0c6ceb9c_f28d_48ae_ae10_14faa40f06cd
        {

            /// UCHAR[40]
            [System.Runtime.InteropServices.MarshalAsAttribute(System.Runtime.InteropServices.UnmanagedType.ByValTStr, SizeConst = 40)]
            public string SuspendApcFill4;

            /// PVOID->void*
            public System.IntPtr LegoData;
        }

        [System.Runtime.InteropServices.StructLayoutAttribute(System.Runtime.InteropServices.LayoutKind.Explicit)]
        public struct Anonymous_a3d6b72e_c5f2_4456_bb50_3dd37f236761
        {

            /// KAPC->_KAPC
            [System.Runtime.InteropServices.FieldOffsetAttribute(0)]
            public KAPC SuspendApc;

            /// Anonymous_e7ebae04_7ba9_470f_ba3f_9cb94460a1ae
            [System.Runtime.InteropServices.FieldOffsetAttribute(0)]
            public Anonymous_e7ebae04_7ba9_470f_ba3f_9cb94460a1ae Struct1;

            /// Anonymous_b5580e4d_b0de_4af7_b5af_e233b171fbf8
            [System.Runtime.InteropServices.FieldOffsetAttribute(0)]
            public Anonymous_b5580e4d_b0de_4af7_b5af_e233b171fbf8 Struct2;

            /// Anonymous_5d49ad2d_5e70_4bf5_836f_d90809c3f8fc
            [System.Runtime.InteropServices.FieldOffsetAttribute(0)]
            public Anonymous_5d49ad2d_5e70_4bf5_836f_d90809c3f8fc Struct3;

            /// Anonymous_52182e3e_009d_4b7e_8850_bd5fdbfc8bf5
            [System.Runtime.InteropServices.FieldOffsetAttribute(0)]
            public Anonymous_52182e3e_009d_4b7e_8850_bd5fdbfc8bf5 Struct4;

            /// Anonymous_0c6ceb9c_f28d_48ae_ae10_14faa40f06cd
            [System.Runtime.InteropServices.FieldOffsetAttribute(0)]
            public Anonymous_0c6ceb9c_f28d_48ae_ae10_14faa40f06cd Struct5;

            /// UCHAR[47]
            [System.Runtime.InteropServices.MarshalAsAttribute(System.Runtime.InteropServices.UnmanagedType.ByValArray, SizeConst = 47, ArraySubType = System.Runtime.InteropServices.UnmanagedType.I1)]
            [System.Runtime.InteropServices.FieldOffsetAttribute(0)]
            public byte[] SuspendApcFill5;
        }

        [System.Runtime.InteropServices.StructLayoutAttribute(System.Runtime.InteropServices.LayoutKind.Explicit)]
        public struct Anonymous_0275bb8c_fcd6_4840_8694_68191265e690
        {

            /// KSEMAPHORE->_KSEMAPHORE
            [System.Runtime.InteropServices.FieldOffsetAttribute(0)]
            public KSEMAPHORE SuspendSemaphore;

            /// UCHAR[20]
            [System.Runtime.InteropServices.MarshalAsAttribute(System.Runtime.InteropServices.UnmanagedType.ByValArray, SizeConst = 20, ArraySubType = System.Runtime.InteropServices.UnmanagedType.I1)]
            [System.Runtime.InteropServices.FieldOffsetAttribute(0)]
            public byte[] SuspendSemaphorefill;
        }

        [System.Runtime.InteropServices.StructLayoutAttribute(System.Runtime.InteropServices.LayoutKind.Sequential, CharSet = System.Runtime.InteropServices.CharSet.Ansi)]
        public struct KTHREAD
        {

            /// DISPATCHER_HEADER->_DISPATCHER_HEADER
            public DISPATCHER_HEADER Header;

            /// UINT64->unsigned __int64
            public ulong CycleTime;

            /// ULONG->unsigned int
            public uint HighCycleTime;

            /// UINT64->unsigned __int64
            public ulong QuantumTarget;

            /// PVOID->void*
            public System.IntPtr InitialStack;

            /// PVOID->void*
            public System.IntPtr StackLimit;

            /// PVOID->void*
            public System.IntPtr KernelStack;

            /// ULONG->unsigned int
            public uint ThreadLock;

            /// Anonymous_a0a1d442_e8cc_43e8_9359_10a76cc415f5
            public Anonymous_a0a1d442_e8cc_43e8_9359_10a76cc415f5 Union1;

            /// CHAR->char
            public byte Priority;

            /// WORD->unsigned short
            public ushort NextProcessor;

            /// WORD->unsigned short
            public ushort DeferredProcessor;

            /// ULONG->unsigned int
            public uint ApcQueueLock;

            /// ULONG->unsigned int
            public uint ContextSwitches;

            /// UCHAR->unsigned char
            public byte State;

            /// UCHAR->unsigned char
            public byte NpxState;

            /// UCHAR->unsigned char
            public byte WaitIrql;

            /// CHAR->char
            public byte WaitMode;

            /// LONG->int
            public int WaitStatus;

            /// Anonymous_1edcaa8a_6e90_40d7_ad1c_2795998ecaac
            public Anonymous_1edcaa8a_6e90_40d7_ad1c_2795998ecaac Union2;

            /// Anonymous_09c75260_1c20_4ab2_b948_061a79a487cf
            public Anonymous_09c75260_1c20_4ab2_b948_061a79a487cf Union3;

            /// UCHAR->unsigned char
            public byte WaitReason;

            /// UCHAR->unsigned char
            public byte SwapBusy;

            /// UCHAR[2]
            [System.Runtime.InteropServices.MarshalAsAttribute(System.Runtime.InteropServices.UnmanagedType.ByValTStr, SizeConst = 2)]
            public string Alerted;

            /// Anonymous_40652056_2b6c_4667_955c_ef22022eca0f
            public Anonymous_40652056_2b6c_4667_955c_ef22022eca0f Union4;

            /// PKQUEUE->_KQUEUE*
            public System.IntPtr Queue;

            /// ULONG->unsigned int
            public uint WaitTime;

            /// Anonymous_a7393dbf_0149_4f23_b9d3_b2a01ed988c4
            public Anonymous_a7393dbf_0149_4f23_b9d3_b2a01ed988c4 Union5;

            /// PVOID->void*
            public System.IntPtr Teb;

            /// Anonymous_384954b7_a696_4d6d_8b08_1d4833eae197
            public Anonymous_384954b7_a696_4d6d_8b08_1d4833eae197 Union6;

            /// Anonymous_cf6b66d7_3e9d_49e3_b844_b6d2ee4da24c
            public Anonymous_cf6b66d7_3e9d_49e3_b844_b6d2ee4da24c Union7;

            /// Anonymous_640c844f_7a22_413f_aed8_9904d6cd398f
            public Anonymous_640c844f_7a22_413f_aed8_9904d6cd398f Union8;

            /// UCHAR->unsigned char
            public byte LargeStack;

            /// LIST_ENTRY->_LIST_ENTRY
            public LIST_ENTRY QueueListEntry;

            /// PKTRAP_FRAME->_KTRAP_FRAME*
            public System.IntPtr TrapFrame;

            /// PVOID->void*
            public System.IntPtr FirstArgument;

            /// Anonymous_8c3cbe6d_41f6_4b6c_9502_108e0d4bda93
            public Anonymous_8c3cbe6d_41f6_4b6c_9502_108e0d4bda93 Union9;

            /// PVOID->void*
            public System.IntPtr ServiceTable;

            /// UCHAR->unsigned char
            public byte ApcStateIndex;

            /// CHAR->char
            public byte BasePriority;

            /// CHAR->char
            public byte PriorityDecrement;

            /// UCHAR->unsigned char
            public byte Preempted;

            /// UCHAR->unsigned char
            public byte AdjustReason;

            /// CHAR->char
            public byte AdjustIncrement;

            /// UCHAR->unsigned char
            public byte Spare01;

            /// CHAR->char
            public byte Saturation;

            /// ULONG->unsigned int
            public uint SystemCallNumber;

            /// ULONG->unsigned int
            public uint Spare02;

            /// ULONG->unsigned int
            public uint UserAffinity;

            /// PKPROCESS->_KPROCESS*
            public System.IntPtr Process;

            /// ULONG->unsigned int
            public uint Affinity;

            /// PKAPC_STATE[2]
            [System.Runtime.InteropServices.MarshalAsAttribute(System.Runtime.InteropServices.UnmanagedType.ByValArray, SizeConst = 2, ArraySubType = System.Runtime.InteropServices.UnmanagedType.SysUInt)]
            public System.IntPtr[] ApcStatePointer;

            /// Anonymous_8414609a_6a06_420b_837f_7e063f21a277
            public Anonymous_8414609a_6a06_420b_837f_7e063f21a277 Union10;

            /// CHAR->char
            public byte FreezeCount;

            /// CHAR->char
            public byte SuspendCount;

            /// UCHAR->unsigned char
            public byte UserIdealProcessor;

            /// UCHAR->unsigned char
            public byte Spare03;

            /// UCHAR->unsigned char
            public byte Iopl;

            /// PVOID->void*
            public System.IntPtr Win32Thread;

            /// PVOID->void*
            public System.IntPtr StackBase;

            /// Anonymous_a3d6b72e_c5f2_4456_bb50_3dd37f236761
            public Anonymous_a3d6b72e_c5f2_4456_bb50_3dd37f236761 Union11;

            /// UCHAR->unsigned char
            public byte PowerState;

            /// ULONG->unsigned int
            public uint UserTime;

            /// Anonymous_0275bb8c_fcd6_4840_8694_68191265e690
            public Anonymous_0275bb8c_fcd6_4840_8694_68191265e690 Union12;

            /// ULONG->unsigned int
            public uint SListFaultCount;

            /// LIST_ENTRY->_LIST_ENTRY
            public LIST_ENTRY ThreadListEntry;

            /// LIST_ENTRY->_LIST_ENTRY
            public LIST_ENTRY MutantListHead;

            /// PVOID->void*
            public System.IntPtr SListFaultAddress;

            /// PVOID->void*
            public System.IntPtr MdlForLockedTeb;
        }

        [System.Runtime.InteropServices.StructLayoutAttribute(System.Runtime.InteropServices.LayoutKind.Sequential)]
        public struct FAST_MUTEX
        {

            /// LONG->int
            public int Count;

            /// PKTHREAD->_KTHREAD*
            public System.IntPtr Owner;

            /// ULONG->unsigned int
            public uint Contention;

            /// KEVENT->_KEVENT
            public KEVENT Gate;

            /// ULONG->unsigned int
            public uint OldIrql;
        }

        [System.Runtime.InteropServices.StructLayoutAttribute(System.Runtime.InteropServices.LayoutKind.Sequential)]
        public struct HANDLE_TRACE_DEBUG_INFO
        {

            /// LONG->int
            public int RefCount;

            /// ULONG->unsigned int
            public uint TableSize;

            /// ULONG->unsigned int
            public uint BitMaskFlags;

            /// FAST_MUTEX->_FAST_MUTEX
            public FAST_MUTEX CloseCompactionLock;

            /// ULONG->unsigned int
            public uint CurrentStackIndex;

            /// HANDLE_TRACE_DB_ENTRY[1]
            [System.Runtime.InteropServices.MarshalAsAttribute(System.Runtime.InteropServices.UnmanagedType.ByValArray, SizeConst = 1, ArraySubType = System.Runtime.InteropServices.UnmanagedType.Struct)]
            public HANDLE_TRACE_DB_ENTRY[] TraceDb;
        }

        [System.Runtime.InteropServices.StructLayoutAttribute(System.Runtime.InteropServices.LayoutKind.Explicit)]
        public struct Anonymous_98fda4c2_794f_4ccc_ac37_57b262ddfedd
        {

            /// Locked : 1
            ///Waiting : 1
            ///Waking : 1
            ///MultipleShared : 1
            ///Shared : 28
            [System.Runtime.InteropServices.FieldOffsetAttribute(0)]
            public uint bitvector1;

            /// ULONG->unsigned int
            [System.Runtime.InteropServices.FieldOffsetAttribute(0)]
            public uint Value;

            /// PVOID->void*
            [System.Runtime.InteropServices.FieldOffsetAttribute(0)]
            public System.IntPtr Ptr;

            public uint Locked
            {
                get
                {
                    return ((uint)((this.bitvector1 & 1u)));
                }
                set
                {
                    this.bitvector1 = ((uint)((value | this.bitvector1)));
                }
            }

            public uint Waiting
            {
                get
                {
                    return ((uint)(((this.bitvector1 & 2u)
                                / 2)));
                }
                set
                {
                    this.bitvector1 = ((uint)(((value * 2)
                                | this.bitvector1)));
                }
            }

            public uint Waking
            {
                get
                {
                    return ((uint)(((this.bitvector1 & 4u)
                                / 4)));
                }
                set
                {
                    this.bitvector1 = ((uint)(((value * 4)
                                | this.bitvector1)));
                }
            }

            public uint MultipleShared
            {
                get
                {
                    return ((uint)(((this.bitvector1 & 8u)
                                / 8)));
                }
                set
                {
                    this.bitvector1 = ((uint)(((value * 8)
                                | this.bitvector1)));
                }
            }

            public uint Shared
            {
                get
                {
                    return ((uint)(((this.bitvector1 & 4294967280u)
                                / 16)));
                }
                set
                {
                    this.bitvector1 = ((uint)(((value * 16)
                                | this.bitvector1)));
                }
            }
        }

        [System.Runtime.InteropServices.StructLayoutAttribute(System.Runtime.InteropServices.LayoutKind.Sequential)]
        public struct EX_PUSH_LOCK
        {

            /// Anonymous_98fda4c2_794f_4ccc_ac37_57b262ddfedd
            public Anonymous_98fda4c2_794f_4ccc_ac37_57b262ddfedd Union1;
        }

        [System.Runtime.InteropServices.StructLayoutAttribute(System.Runtime.InteropServices.LayoutKind.Sequential)]
        public struct CLIENT_ID
        {

            /// HANDLE->void*
            public System.IntPtr UniqueProcess;

            /// HANDLE->void*
            public System.IntPtr UniqueThread;
        }

        [System.Runtime.InteropServices.StructLayoutAttribute(System.Runtime.InteropServices.LayoutKind.Sequential)]
        public struct VM_COUNTERS
        {

            /// SIZE_T->ULONG_PTR->unsigned int
            public uint PeakVirtualSize;

            /// SIZE_T->ULONG_PTR->unsigned int
            public uint VirtualSize;

            /// ULONG->unsigned int
            public uint PageFaultCount;

            /// SIZE_T->ULONG_PTR->unsigned int
            public uint PeakWorkingSetSize;

            /// SIZE_T->ULONG_PTR->unsigned int
            public uint WorkingSetSize;

            /// SIZE_T->ULONG_PTR->unsigned int
            public uint QuotaPeakPagedPoolUsage;

            /// SIZE_T->ULONG_PTR->unsigned int
            public uint QuotaPagedPoolUsage;

            /// SIZE_T->ULONG_PTR->unsigned int
            public uint QuotaPeakNonPagedPoolUsage;

            /// SIZE_T->ULONG_PTR->unsigned int
            public uint QuotaNonPagedPoolUsage;

            /// SIZE_T->ULONG_PTR->unsigned int
            public uint PagefileUsage;

            /// SIZE_T->ULONG_PTR->unsigned int
            public uint PeakPagefileUsage;
        }

        [System.Runtime.InteropServices.StructLayoutAttribute(System.Runtime.InteropServices.LayoutKind.Sequential)]
        public struct UNICODE_STRING
        {

            /// USHORT->unsigned short
            public ushort Length;

            /// USHORT->unsigned short
            public ushort MaximumLength;

            /// USHORT*
            public System.IntPtr Buffer;
        }

        [System.Runtime.InteropServices.StructLayoutAttribute(System.Runtime.InteropServices.LayoutKind.Sequential)]
        public struct PSPCID_HANDLE_TABLE
        {

            /// PVOID->void*
            public System.IntPtr p_hTable;

            /// PEPROCESS->_EPROCESS*
            public System.IntPtr QuotaProcess;

            /// PVOID->void*
            public System.IntPtr UniqueProcessId;

            /// EX_PUSH_LOCK[4]
            [System.Runtime.InteropServices.MarshalAsAttribute(System.Runtime.InteropServices.UnmanagedType.ByValArray, SizeConst = 4, ArraySubType = System.Runtime.InteropServices.UnmanagedType.Struct)]
            public EX_PUSH_LOCK[] HandleTableLock;

            /// LIST_ENTRY->_LIST_ENTRY
            public LIST_ENTRY HandleTableList;

            /// EX_PUSH_LOCK->_EX_PUSH_LOCK
            public EX_PUSH_LOCK HandleContentionEvent;

            /// PHANDLE_TRACE_DEBUG_INFO->_HANDLE_TRACE_DEBUG_INFO*
            public System.IntPtr DebugInfo;

            /// DWORD->unsigned int
            public uint ExtraInfoPages;

            /// DWORD->unsigned int
            public uint FirstFree;

            /// DWORD->unsigned int
            public uint LastFree;

            /// DWORD->unsigned int
            public uint NextHandleNeedingPool;

            /// DWORD->unsigned int
            public uint HandleCount;

            /// DWORD->unsigned int
            public uint Flags;
        }

        [System.Runtime.InteropServices.StructLayoutAttribute(System.Runtime.InteropServices.LayoutKind.Sequential)]
        public struct SYSTEM_THREAD_INFORMATION
        {

            /// LARGE_INTEGER->_LARGE_INTEGER
            public LARGE_INTEGER KernelTime;

            /// LARGE_INTEGER->_LARGE_INTEGER
            public LARGE_INTEGER UserTime;

            /// LARGE_INTEGER->_LARGE_INTEGER
            public LARGE_INTEGER CreateTime;

            /// ULONG->unsigned int
            public uint WaitTime;

            /// PVOID->void*
            public System.IntPtr StartAddress;

            /// CLIENT_ID->_CLIENT_ID
            public CLIENT_ID ClientId;

            /// KPRIORITY->LONG->int
            public int Priority;

            /// KPRIORITY->LONG->int
            public int BasePriority;

            /// ULONG->unsigned int
            public uint ContextSwitchCount;

            /// LONG->int
            public int State;

            /// LONG->int
            public int WaitReason;
        }

        [System.Runtime.InteropServices.StructLayoutAttribute(System.Runtime.InteropServices.LayoutKind.Sequential)]
        public struct SYSTEM_PROCESS_INFORMATION
        {

            /// ULONG->unsigned int
            public uint NextEntryDelta;

            /// ULONG->unsigned int
            public uint ThreadCount;

            /// ULONG[6]
            [System.Runtime.InteropServices.MarshalAsAttribute(System.Runtime.InteropServices.UnmanagedType.ByValArray, SizeConst = 6, ArraySubType = System.Runtime.InteropServices.UnmanagedType.U4)]
            public uint[] Reserved1;

            /// LARGE_INTEGER->_LARGE_INTEGER
            public LARGE_INTEGER CreateTime;

            /// LARGE_INTEGER->_LARGE_INTEGER
            public LARGE_INTEGER UserTime;

            /// LARGE_INTEGER->_LARGE_INTEGER
            public LARGE_INTEGER KernelTime;

            /// UNICODE_STRING->_UNICODE_STRING
            public UNICODE_STRING ProcessName;

            /// KPRIORITY->LONG->int
            public int BasePriority;

            /// ULONG->unsigned int
            public uint ProcessId;

            /// ULONG->unsigned int
            public uint InheritedFromProcessId;

            /// ULONG->unsigned int
            public uint HandleCount;

            /// ULONG[2]
            [System.Runtime.InteropServices.MarshalAsAttribute(System.Runtime.InteropServices.UnmanagedType.ByValArray, SizeConst = 2, ArraySubType = System.Runtime.InteropServices.UnmanagedType.U4)]
            public uint[] Reserved2;

            /// VM_COUNTERS->_VM_COUNTERS
            public VM_COUNTERS VmCounters;

            /// IO_COUNTERS->_IO_COUNTERS
            public IO_COUNTERS IoCounters;

            /// SYSTEM_THREAD_INFORMATION[1]
            [System.Runtime.InteropServices.MarshalAsAttribute(System.Runtime.InteropServices.UnmanagedType.ByValArray, SizeConst = 1, ArraySubType = System.Runtime.InteropServices.UnmanagedType.Struct)]
            public SYSTEM_THREAD_INFORMATION[] Threads;
        }

        [System.Runtime.InteropServices.StructLayoutAttribute(System.Runtime.InteropServices.LayoutKind.Sequential)]
        public struct PROCESS_LISTING_REQUEST
        {

            /// UINT->unsigned int
            public uint pid;

            /// UINT->unsigned int
            public uint listingType;
        }

        [System.Runtime.InteropServices.StructLayoutAttribute(System.Runtime.InteropServices.LayoutKind.Sequential)]
        public struct PROCESS_LISTING_ZWQ
        {

            /// int
            public int numProcesses;

            /// SYSTEM_PROCESS_INFORMATION[256]
            [System.Runtime.InteropServices.MarshalAsAttribute(System.Runtime.InteropServices.UnmanagedType.ByValArray, SizeConst = 256, ArraySubType = System.Runtime.InteropServices.UnmanagedType.Struct)]
            public SYSTEM_PROCESS_INFORMATION[] ProcessList;
        }

        [System.Runtime.InteropServices.StructLayoutAttribute(System.Runtime.InteropServices.LayoutKind.Sequential)]
        public struct PROCESS_LISTING_PSP
        {

            /// int
            public int numProcesses;

            /// PSPCID_HANDLE_TABLE[256]
            [System.Runtime.InteropServices.MarshalAsAttribute(System.Runtime.InteropServices.UnmanagedType.ByValArray, SizeConst = 256, ArraySubType = System.Runtime.InteropServices.UnmanagedType.Struct)]
            public PSPCID_HANDLE_TABLE[] ProcessList;
        }

        [System.Runtime.InteropServices.StructLayoutAttribute(System.Runtime.InteropServices.LayoutKind.Explicit)]
        public struct SLIST_HEADER
        {

            /// ULONGLONG->unsigned __int64
            [System.Runtime.InteropServices.FieldOffsetAttribute(0)]
            public ulong Alignment;

            /// Anonymous_fd626461_7f3e_49a1_aabe_a2b90f0df936
            [System.Runtime.InteropServices.FieldOffsetAttribute(0)]
            public Anonymous_fd626461_7f3e_49a1_aabe_a2b90f0df936 Struct1;
        }

        [System.Runtime.InteropServices.StructLayoutAttribute(System.Runtime.InteropServices.LayoutKind.Sequential)]
        public struct SINGLE_LIST_ENTRY
        {

            /// _SINGLE_LIST_ENTRY*
            public System.IntPtr Next;
        }

        [System.Runtime.InteropServices.StructLayoutAttribute(System.Runtime.InteropServices.LayoutKind.Sequential)]
        public struct LIST_ENTRY
        {

            /// _LIST_ENTRY*
            public System.IntPtr Flink;

            /// _LIST_ENTRY*
            public System.IntPtr Blink;
        }

        [System.Runtime.InteropServices.StructLayoutAttribute(System.Runtime.InteropServices.LayoutKind.Explicit)]
        public struct LARGE_INTEGER
        {

            /// Anonymous_9320654f_2227_43bf_a385_74cc8c562686
            [System.Runtime.InteropServices.FieldOffsetAttribute(0)]
            public Anonymous_9320654f_2227_43bf_a385_74cc8c562686 Struct1;

            /// Anonymous_947eb392_1446_4e25_bbd4_10e98165f3a9
            [System.Runtime.InteropServices.FieldOffsetAttribute(0)]
            public Anonymous_947eb392_1446_4e25_bbd4_10e98165f3a9 u;

            /// LONGLONG->__int64
            [System.Runtime.InteropServices.FieldOffsetAttribute(0)]
            public long QuadPart;
        }

        [System.Runtime.InteropServices.StructLayoutAttribute(System.Runtime.InteropServices.LayoutKind.Explicit)]
        public struct ULARGE_INTEGER
        {

            /// Anonymous_652f900e_e9d5_4a81_ba95_5c3af2ba5157
            [System.Runtime.InteropServices.FieldOffsetAttribute(0)]
            public Anonymous_652f900e_e9d5_4a81_ba95_5c3af2ba5157 Struct1;

            /// Anonymous_da3d5bb2_d7f6_4b49_a86f_df044e26e59a
            [System.Runtime.InteropServices.FieldOffsetAttribute(0)]
            public Anonymous_da3d5bb2_d7f6_4b49_a86f_df044e26e59a u;

            /// ULONGLONG->unsigned __int64
            [System.Runtime.InteropServices.FieldOffsetAttribute(0)]
            public ulong QuadPart;
        }

        [System.Runtime.InteropServices.StructLayoutAttribute(System.Runtime.InteropServices.LayoutKind.Sequential)]
        public struct IO_COUNTERS
        {

            /// ULONGLONG->unsigned __int64
            public ulong ReadOperationCount;

            /// ULONGLONG->unsigned __int64
            public ulong WriteOperationCount;

            /// ULONGLONG->unsigned __int64
            public ulong OtherOperationCount;

            /// ULONGLONG->unsigned __int64
            public ulong ReadTransferCount;

            /// ULONGLONG->unsigned __int64
            public ulong WriteTransferCount;

            /// ULONGLONG->unsigned __int64
            public ulong OtherTransferCount;
        }

        [System.Runtime.InteropServices.StructLayoutAttribute(System.Runtime.InteropServices.LayoutKind.Sequential)]
        public struct CACHE_DESCRIPTOR
        {

            /// BYTE->unsigned char
            public byte Level;

            /// BYTE->unsigned char
            public byte Associativity;

            /// WORD->unsigned short
            public ushort LineSize;

            /// DWORD->unsigned int
            public uint Size;

            /// PROCESSOR_CACHE_TYPE->_PROCESSOR_CACHE_TYPE
            public PROCESSOR_CACHE_TYPE Type;
        }

        [System.Runtime.InteropServices.StructLayoutAttribute(System.Runtime.InteropServices.LayoutKind.Sequential)]
        public struct Anonymous_fd626461_7f3e_49a1_aabe_a2b90f0df936
        {

            /// SINGLE_LIST_ENTRY->_SINGLE_LIST_ENTRY
            public SINGLE_LIST_ENTRY Next;

            /// WORD->unsigned short
            public ushort Depth;

            /// WORD->unsigned short
            public ushort Sequence;
        }

        [System.Runtime.InteropServices.StructLayoutAttribute(System.Runtime.InteropServices.LayoutKind.Sequential)]
        public struct Anonymous_9320654f_2227_43bf_a385_74cc8c562686
        {

            /// DWORD->unsigned int
            public uint LowPart;

            /// LONG->int
            public int HighPart;
        }

        [System.Runtime.InteropServices.StructLayoutAttribute(System.Runtime.InteropServices.LayoutKind.Sequential)]
        public struct Anonymous_947eb392_1446_4e25_bbd4_10e98165f3a9
        {

            /// DWORD->unsigned int
            public uint LowPart;

            /// LONG->int
            public int HighPart;
        }

        [System.Runtime.InteropServices.StructLayoutAttribute(System.Runtime.InteropServices.LayoutKind.Sequential)]
        public struct Anonymous_652f900e_e9d5_4a81_ba95_5c3af2ba5157
        {

            /// DWORD->unsigned int
            public uint LowPart;

            /// DWORD->unsigned int
            public uint HighPart;
        }

        [System.Runtime.InteropServices.StructLayoutAttribute(System.Runtime.InteropServices.LayoutKind.Sequential)]
        public struct Anonymous_da3d5bb2_d7f6_4b49_a86f_df044e26e59a
        {

            /// DWORD->unsigned int
            public uint LowPart;

            /// DWORD->unsigned int
            public uint HighPart;
        }

        public enum PROCESSOR_CACHE_TYPE
        {

            CacheUnified,

            CacheInstruction,

            CacheData,

            CacheTrace,
        }
        */
        #endregion 

        //END MASSIVE REGION


        public enum KWAIT_REASON
        {
            Executive,
            FreePage,
            PageIn,
            PoolAllocation,
            DelayExecution,
            Suspended,
            UserRequest,
            WrExecutive,
            WrFreePage,
            WrPageIn,
            WrPoolAllocation,
            WrDelayExecution,
            WrSuspended,
            WrUserRequest,
            WrEventPair,
            WrQueue,
            WrLpcReceive,
            WrLpcReply,
            WrVirtualMemory,
            WrPageOut,
            WrRendezvous,
            Spare2,
            Spare3,
            Spare4,
            Spare5,
            WrCalloutStack,
            WrKernel,
            WrResource,
            WrPushLock,
            WrMutex,
            WrQuantumEnd,
            WrDispatchInt,
            WrPreempted,
            WrYieldExecution,
            WrFastMutex,
            WrGuardedMutex,
            WrRundown,
            MaximumWaitReason
        }

        [System.Runtime.InteropServices.StructLayoutAttribute(System.Runtime.InteropServices.LayoutKind.Sequential)]
        public struct CLIENT_ID
        {
            /// HANDLE->void*
            public UInt32 UniqueProcess;

            /// HANDLE->void*
            public UInt32 UniqueThread;
        }

        [System.Runtime.InteropServices.StructLayoutAttribute(System.Runtime.InteropServices.LayoutKind.Sequential)]
        public struct SYSTEM_THREAD_INFORMATION
        {

            /// LARGE_INTEGER->_LARGE_INTEGER
            public LARGE_INTEGER KernelTime;

            /// LARGE_INTEGER->_LARGE_INTEGER
            public LARGE_INTEGER UserTime;

            /// LARGE_INTEGER->_LARGE_INTEGER
            public LARGE_INTEGER CreateTime;

            /// ULONG->unsigned int
            public uint WaitTime;

            /// PVOID->void*
            public UInt32 StartAddress;

            /// CLIENT_ID->_CLIENT_ID
            public CLIENT_ID ClientId;

            /// KPRIORITY->LONG->int
            public int Priority;

            /// LONG->int
            public int BasePriority;

            /// ULONG->unsigned int
            public uint ContextSwitchCount;

            /// ULONG->unsigned int
            public uint State;

            /// KWAIT_REASON->_KWAIT_REASON
            public KWAIT_REASON WaitReason;
        }

        [System.Runtime.InteropServices.StructLayoutAttribute(System.Runtime.InteropServices.LayoutKind.Sequential)]
        public struct UNICODE_STRING
        {

            /// USHORT->unsigned short
            public ushort Length;

            /// USHORT->unsigned short
            public ushort MaximumLength;

            /// PWSTR->WCHAR*
            [System.Runtime.InteropServices.MarshalAsAttribute(System.Runtime.InteropServices.UnmanagedType.LPWStr)]
            public string Buffer;
        }

        [System.Runtime.InteropServices.StructLayoutAttribute(System.Runtime.InteropServices.LayoutKind.Sequential)]
        public struct VM_COUNTERS
        {

            /// SIZE_T->ULONG_PTR->unsigned int
            public uint PeakVirtualSize;

            /// SIZE_T->ULONG_PTR->unsigned int
            public uint VirtualSize;

            /// ULONG->unsigned int
            public uint PageFaultCount;

            /// SIZE_T->ULONG_PTR->unsigned int
            public uint PeakWorkingSetSize;

            /// SIZE_T->ULONG_PTR->unsigned int
            public uint WorkingSetSize;

            /// SIZE_T->ULONG_PTR->unsigned int
            public uint QuotaPeakPagedPoolUsage;

            /// SIZE_T->ULONG_PTR->unsigned int
            public uint QuotaPagedPoolUsage;

            /// SIZE_T->ULONG_PTR->unsigned int
            public uint QuotaPeakNonPagedPoolUsage;

            /// SIZE_T->ULONG_PTR->unsigned int
            public uint QuotaNonPagedPoolUsage;

            /// SIZE_T->ULONG_PTR->unsigned int
            public uint PagefileUsage;

            /// SIZE_T->ULONG_PTR->unsigned int
            public uint PeakPagefileUsage;
        }

        [System.Runtime.InteropServices.StructLayoutAttribute(System.Runtime.InteropServices.LayoutKind.Sequential)]
        public struct SYSTEM_PROCESS_INFORMATION
        {

            /// ULONG->unsigned int
            public UInt32 NextEntryOffset;

            /// ULONG->unsigned int
            public UInt32 NumberOfThreads;

            /// LARGE_INTEGER[3]
            [System.Runtime.InteropServices.MarshalAsAttribute(System.Runtime.InteropServices.UnmanagedType.ByValArray, SizeConst = 3, ArraySubType = System.Runtime.InteropServices.UnmanagedType.Struct)]
            public LARGE_INTEGER[] Reserved;

            /// LARGE_INTEGER->_LARGE_INTEGER
            public LARGE_INTEGER CreateTime;

            /// LARGE_INTEGER->_LARGE_INTEGER
            public LARGE_INTEGER UserTime;

            /// LARGE_INTEGER->_LARGE_INTEGER
            public LARGE_INTEGER KernelTime;

            /// UNICODE_STRING->_UNICODE_STRING
            public UNICODE_STRING ImageName;

            /// KPRIORITY->LONG->int
            public Int32 BasePriority;

            /// HANDLE->void*
            public uint UniqueProcessId;

            /// HANDLE->void*
            public uint InheritedFromUniqueProcessId;

            /// ULONG->unsigned int
            public UInt32 HandleCount;

            /// ULONG[2]
            [System.Runtime.InteropServices.MarshalAsAttribute(System.Runtime.InteropServices.UnmanagedType.ByValArray, SizeConst = 2, ArraySubType = System.Runtime.InteropServices.UnmanagedType.U4)]
            public UInt32[] Reserved2;

            /// ULONG->unsigned int
            public UInt32 PrivatePageCount;

            /// VM_COUNTERS->_VM_COUNTERS
            public VM_COUNTERS VirtualMemoryCounters;

            /// IO_COUNTERS->_IO_COUNTERS
            public IO_COUNTERS IoCounters;

            /// SYSTEM_THREAD_INFORMATION[1]
            [System.Runtime.InteropServices.MarshalAsAttribute(System.Runtime.InteropServices.UnmanagedType.ByValArray, SizeConst = 1, ArraySubType = System.Runtime.InteropServices.UnmanagedType.Struct)]
            public SYSTEM_THREAD_INFORMATION[] Threads;
        }

        [System.Runtime.InteropServices.StructLayoutAttribute(System.Runtime.InteropServices.LayoutKind.Explicit)]
        public struct LARGE_INTEGER
        {

            /// Anonymous_9320654f_2227_43bf_a385_74cc8c562686
            [System.Runtime.InteropServices.FieldOffsetAttribute(0)]
            public Anonymous_9320654f_2227_43bf_a385_74cc8c562686 Struct1;

            /// Anonymous_947eb392_1446_4e25_bbd4_10e98165f3a9
            [System.Runtime.InteropServices.FieldOffsetAttribute(0)]
            public Anonymous_947eb392_1446_4e25_bbd4_10e98165f3a9 u;

            /// LONGLONG->__int64
            [System.Runtime.InteropServices.FieldOffsetAttribute(0)]
            public long QuadPart;
        }

        [System.Runtime.InteropServices.StructLayoutAttribute(System.Runtime.InteropServices.LayoutKind.Sequential)]
        public struct IO_COUNTERS
        {

            /// ULONGLONG->unsigned __int64
            public ulong ReadOperationCount;

            /// ULONGLONG->unsigned __int64
            public ulong WriteOperationCount;

            /// ULONGLONG->unsigned __int64
            public ulong OtherOperationCount;

            /// ULONGLONG->unsigned __int64
            public ulong ReadTransferCount;

            /// ULONGLONG->unsigned __int64
            public ulong WriteTransferCount;

            /// ULONGLONG->unsigned __int64
            public ulong OtherTransferCount;
        }

        [System.Runtime.InteropServices.StructLayoutAttribute(System.Runtime.InteropServices.LayoutKind.Sequential)]
        public struct Anonymous_9320654f_2227_43bf_a385_74cc8c562686
        {

            /// DWORD->unsigned int
            public uint LowPart;

            /// LONG->int
            public int HighPart;
        }

        [System.Runtime.InteropServices.StructLayoutAttribute(System.Runtime.InteropServices.LayoutKind.Sequential)]
        public struct Anonymous_947eb392_1446_4e25_bbd4_10e98165f3a9
        {

            /// DWORD->unsigned int
            public uint LowPart;

            /// LONG->int
            public int HighPart;
        }


        public enum SC_STATUS_TYPE 
        {
            /// SC_STATUS_PROCESS_INFO -> 0
            SC_STATUS_PROCESS_INFO = 0,
        }

        [System.Runtime.InteropServices.StructLayoutAttribute(System.Runtime.InteropServices.LayoutKind.Sequential)]
        public struct MODULEINFO
        {

            /// LPVOID->void*
            public System.IntPtr lpBaseOfDll;

            /// DWORD->unsigned int
            public uint SizeOfImage;

            /// LPVOID->void*
            public System.IntPtr EntryPoint;
        }

        public enum MINIDUMP_TYPE
        {

            /// MiniDumpNormal -> 0x00000000
            MiniDumpNormal = 0,

            /// MiniDumpWithDataSegs -> 0x00000001
            MiniDumpWithDataSegs = 1,

            /// MiniDumpWithFullMemory -> 0x00000002
            MiniDumpWithFullMemory = 2,

            /// MiniDumpWithHandleData -> 0x00000004
            MiniDumpWithHandleData = 4,

            /// MiniDumpFilterMemory -> 0x00000008
            MiniDumpFilterMemory = 8,

            /// MiniDumpScanMemory -> 0x00000010
            MiniDumpScanMemory = 16,

            /// MiniDumpWithUnloadedModules -> 0x00000020
            MiniDumpWithUnloadedModules = 32,

            /// MiniDumpWithIndirectlyReferencedMemory -> 0x00000040
            MiniDumpWithIndirectlyReferencedMemory = 64,

            /// MiniDumpFilterModulePaths -> 0x00000080
            MiniDumpFilterModulePaths = 128,

            /// MiniDumpWithProcessThreadData -> 0x00000100
            MiniDumpWithProcessThreadData = 256,

            /// MiniDumpWithPrivateReadWriteMemory -> 0x00000200
            MiniDumpWithPrivateReadWriteMemory = 512,

            /// MiniDumpWithoutOptionalData -> 0x00000400
            MiniDumpWithoutOptionalData = 1024,

            /// MiniDumpWithFullMemoryInfo -> 0x00000800
            MiniDumpWithFullMemoryInfo = 2048,

            /// MiniDumpWithThreadInfo -> 0x00001000
            MiniDumpWithThreadInfo = 4096,

            /// MiniDumpWithCodeSegs -> 0x00002000
            MiniDumpWithCodeSegs = 8192,

            /// MiniDumpWithoutAuxiliaryState -> 0x00004000
            MiniDumpWithoutAuxiliaryState = 16384,

            /// MiniDumpWithFullAuxiliaryState -> 0x00008000
            MiniDumpWithFullAuxiliaryState = 32768,
        }

        [System.Runtime.InteropServices.StructLayoutAttribute(System.Runtime.InteropServices.LayoutKind.Sequential)]
        public struct MINIDUMP_EXCEPTION_INFORMATION
        {

            /// DWORD->unsigned int
            public uint ThreadId;

            /// PEXCEPTION_POINTERS->_EXCEPTION_POINTERS*
            public System.IntPtr ExceptionPointers;

            /// BOOL->int
            [System.Runtime.InteropServices.MarshalAsAttribute(System.Runtime.InteropServices.UnmanagedType.Bool)]
            public bool ClientPointers;
        }

        [System.Runtime.InteropServices.StructLayoutAttribute(System.Runtime.InteropServices.LayoutKind.Sequential)]
        public struct EXCEPTION_POINTERS
        {

            /// PEXCEPTION_RECORD->EXCEPTION_RECORD*
            public System.IntPtr ExceptionRecord;

            /// PCONTEXT->CONTEXT*
            public System.IntPtr ContextRecord;
        }

        [System.Runtime.InteropServices.StructLayoutAttribute(System.Runtime.InteropServices.LayoutKind.Sequential)]
        public struct EXCEPTION_RECORD
        {

            /// DWORD->unsigned int
            public uint ExceptionCode;

            /// DWORD->unsigned int
            public uint ExceptionFlags;

            /// _EXCEPTION_RECORD*
            public System.IntPtr ExceptionRecord;

            /// PVOID->void*
            public System.IntPtr ExceptionAddress;

            /// DWORD->unsigned int
            public uint NumberParameters;

            /// ULONG_PTR[15]
            [System.Runtime.InteropServices.MarshalAsAttribute(System.Runtime.InteropServices.UnmanagedType.ByValArray, SizeConst = 15, ArraySubType = System.Runtime.InteropServices.UnmanagedType.U4)]
            public uint[] ExceptionInformation;
        }

        [System.Runtime.InteropServices.StructLayoutAttribute(System.Runtime.InteropServices.LayoutKind.Sequential)]
        public struct CONTEXT
        {

            /// DWORD->unsigned int
            public uint ContextFlags;

            /// DWORD->unsigned int
            public uint Dr0;

            /// DWORD->unsigned int
            public uint Dr1;

            /// DWORD->unsigned int
            public uint Dr2;

            /// DWORD->unsigned int
            public uint Dr3;

            /// DWORD->unsigned int
            public uint Dr6;

            /// DWORD->unsigned int
            public uint Dr7;

            /// FLOATING_SAVE_AREA->_FLOATING_SAVE_AREA
            public FLOATING_SAVE_AREA FloatSave;

            /// DWORD->unsigned int
            public uint SegGs;

            /// DWORD->unsigned int
            public uint SegFs;

            /// DWORD->unsigned int
            public uint SegEs;

            /// DWORD->unsigned int
            public uint SegDs;

            /// DWORD->unsigned int
            public uint Edi;

            /// DWORD->unsigned int
            public uint Esi;

            /// DWORD->unsigned int
            public uint Ebx;

            /// DWORD->unsigned int
            public uint Edx;

            /// DWORD->unsigned int
            public uint Ecx;

            /// DWORD->unsigned int
            public uint Eax;

            /// DWORD->unsigned int
            public uint Ebp;

            /// DWORD->unsigned int
            public uint Eip;

            /// DWORD->unsigned int
            public uint SegCs;

            /// DWORD->unsigned int
            public uint EFlags;

            /// DWORD->unsigned int
            public uint Esp;

            /// DWORD->unsigned int
            public uint SegSs;

            /// BYTE[512]
            [System.Runtime.InteropServices.MarshalAsAttribute(System.Runtime.InteropServices.UnmanagedType.ByValArray, SizeConst = 512, ArraySubType = System.Runtime.InteropServices.UnmanagedType.I1)]
            public byte[] ExtendedRegisters;
        }

        [System.Runtime.InteropServices.StructLayoutAttribute(System.Runtime.InteropServices.LayoutKind.Sequential)]
        public struct FLOATING_SAVE_AREA
        {

            /// DWORD->unsigned int
            public uint ControlWord;

            /// DWORD->unsigned int
            public uint StatusWord;

            /// DWORD->unsigned int
            public uint TagWord;

            /// DWORD->unsigned int
            public uint ErrorOffset;

            /// DWORD->unsigned int
            public uint ErrorSelector;

            /// DWORD->unsigned int
            public uint DataOffset;

            /// DWORD->unsigned int
            public uint DataSelector;

            /// BYTE[80]
            [System.Runtime.InteropServices.MarshalAsAttribute(System.Runtime.InteropServices.UnmanagedType.ByValArray, SizeConst = 80, ArraySubType = System.Runtime.InteropServices.UnmanagedType.I1)]
            public byte[] RegisterArea;

            /// DWORD->unsigned int
            public uint Cr0NpxState;
        }

        [System.Runtime.InteropServices.StructLayoutAttribute(System.Runtime.InteropServices.LayoutKind.Sequential)]
        public struct OBJECT_ATTRIBUTES
        {

            /// ULONG->unsigned int
            public uint Length;

            /// HANDLE->void*
            public System.IntPtr RootDirectory;

            /// PUNICODE_STRING->UNICODE_STRING*
            public System.IntPtr ObjectName;

            /// ULONG->unsigned int
            public uint Attributes;

            /// PVOID->void*
            public System.IntPtr SecurityDescriptor;

            /// PVOID->void*
            public System.IntPtr SecurityQualityOfService;
        }

        [System.Runtime.InteropServices.StructLayoutAttribute(System.Runtime.InteropServices.LayoutKind.Sequential)]
        public struct SERVICE_STATUS_PROCESS
        {

            /// DWORD->unsigned int
            public uint dwServiceType;

            /// DWORD->unsigned int
            public uint dwCurrentState;

            /// DWORD->unsigned int
            public uint dwControlsAccepted;

            /// DWORD->unsigned int
            public uint dwWin32ExitCode;

            /// DWORD->unsigned int
            public uint dwServiceSpecificExitCode;

            /// DWORD->unsigned int
            public uint dwCheckPoint;

            /// DWORD->unsigned int
            public uint dwWaitHint;

            /// DWORD->unsigned int
            public uint dwProcessId;

            /// DWORD->unsigned int
            public uint dwServiceFlags;
        }

        [System.Runtime.InteropServices.StructLayoutAttribute(System.Runtime.InteropServices.LayoutKind.Sequential)]
        public struct HKEY__
        {
            public int unused;
        }

        [System.Runtime.InteropServices.StructLayoutAttribute(System.Runtime.InteropServices.LayoutKind.Sequential)]
        public struct FILETIME
        {
            /// DWORD->unsigned int
            public uint dwLowDateTime;

            /// DWORD->unsigned int
            public uint dwHighDateTime;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct OSVERSIONINFOEX
        {
            public int dwOSVersionInfoSize;
            public int dwMajorVersion;
            public int dwMinorVersion;
            public int dwBuildNumber;
            public int dwPlatformId;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 128)]
            public string szCSDVersion;
            public short wServicePackMajor;
            public short wServicePackMinor;
            public short wSuiteMask;
            public byte wProductType;
            public byte wReserved;
        }

        [System.Runtime.InteropServices.StructLayoutAttribute(System.Runtime.InteropServices.LayoutKind.Sequential)]
        public struct MEMORYSTATUSEX
        {
            /// DWORD->unsigned int
            public uint dwLength;
            /// DWORD->unsigned int
            public uint dwMemoryLoad;
            /// DWORDLONG->ULONGLONG->unsigned __int64
            public ulong ullTotalPhys;
            /// DWORDLONG->ULONGLONG->unsigned __int64
            public ulong ullAvailPhys;
            /// DWORDLONG->ULONGLONG->unsigned __int64
            public ulong ullTotalPageFile;
            /// DWORDLONG->ULONGLONG->unsigned __int64
            public ulong ullAvailPageFile;
            /// DWORDLONG->ULONGLONG->unsigned __int64
            public ulong ullTotalVirtual;
            /// DWORDLONG->ULONGLONG->unsigned __int64
            public ulong ullAvailVirtual;
            /// DWORDLONG->ULONGLONG->unsigned __int64
            public ulong ullAvailExtendedVirtual;
        }

        [StructLayoutAttribute(LayoutKind.Sequential)]
        public struct PROCESSENTRY32
        {
            /// DWORD->unsigned int
            public uint dwSize;
            /// DWORD->unsigned int
            public uint cntUsage;
            /// DWORD->unsigned int
            public uint th32ProcessID;
            /// ULONG_PTR->unsigned int
            public uint th32DefaultHeapID;
            /// DWORD->unsigned int
            public uint th32ModuleID;
            /// DWORD->unsigned int
            public uint cntThreads;
            /// DWORD->unsigned int
            public uint th32ParentProcessID;
            /// LONG->int
            public int pcPriClassBase;
            /// DWORD->unsigned int
            public uint dwFlags;
            /// TCHAR[260]
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)]
            public string szExeFile;
        }

        [StructLayoutAttribute(LayoutKind.Sequential)]
        public struct THREADENTRY32
        {
            /// DWORD->unsigned int
            public IntPtr dwSize;
            /// DWORD->unsigned int
            public uint cntUsage;
            /// DWORD->unsigned int
            public uint th32ThreadID;
            /// DWORD->unsigned int
            public uint th32OwnerProcessID;
            /// LONG->int
            public int tpBasePri;
            /// LONG->int
            public int tpDeltaPri;
            /// DWORD->unsigned int
            public uint dwFlags;
        }


        [System.Runtime.InteropServices.StructLayoutAttribute(System.Runtime.InteropServices.LayoutKind.Sequential)]
        public struct HEAPENTRY32
        {

            /// SIZE_T->ULONG_PTR->unsigned int
            public uint dwSize;

            /// HANDLE->void*
            public System.IntPtr hHandle;

            /// ULONG_PTR->unsigned int
            public uint dwAddress;

            /// SIZE_T->ULONG_PTR->unsigned int
            public uint dwBlockSize;

            /// DWORD->unsigned int
            public uint dwFlags;

            /// DWORD->unsigned int
            public uint dwLockCount;

            /// DWORD->unsigned int
            public uint dwResvd;

            /// DWORD->unsigned int
            public uint th32ProcessID;

            /// ULONG_PTR->unsigned int
            public uint th32HeapID;
        }

        [StructLayoutAttribute(LayoutKind.Sequential)]
        public struct HEAPLIST32
        {
            /// SIZE_T->ULONG_PTR->unsigned int
            public IntPtr dwSize;
            /// DWORD->unsigned int
            public uint th32ProcessID;
            /// ULONG_PTR->unsigned int
            public IntPtr th32HeapID;
            /// DWORD->unsigned int
            public uint dwFlags;
        }

        [StructLayoutAttribute(LayoutKind.Sequential)]
        public struct MODULEENTRY32
        {
            /// DWORD->unsigned int
            public IntPtr dwSize;
            /// DWORD->unsigned int
            public uint th32ModuleID;
            /// DWORD->unsigned int
            public uint th32ProcessID;
            /// DWORD->unsigned int
            public uint GlblcntUsage;
            /// DWORD->unsigned int
            public uint ProccntUsage;
            /// BYTE*
            public System.IntPtr modBaseAddr;
            /// DWORD->unsigned int
            public uint modBaseSize;
            /// HMODULE->HINSTANCE->HINSTANCE__*
            public System.IntPtr hModule;
            /// TCHAR[]
            [MarshalAsAttribute(UnmanagedType.ByValTStr, SizeConst = 256)]
            public string szModule;
            /// TCHAR[260]
            [MarshalAsAttribute(UnmanagedType.ByValTStr, SizeConst = 260)]
            public string szExePath;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct LUID
        {
            public int LowPart;
            public int HighPart;
        }
        [StructLayout(LayoutKind.Sequential)]
        public struct TOKEN_PRIVILEGES
        {
            public LUID Luid;
            public int Attributes;
            public int PrivilegeCount;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct NETRESOURCE
        {
            public int dwScope;
            public int dwType;
            public int dwDisplayType;
            public int dwUsage;
            public string lpLocalName;
            public string lpRemoteName;
            public string lpComment;
            public string lpProvider;
        }

        [Serializable]
        [System.Runtime.InteropServices.StructLayoutAttribute(System.Runtime.InteropServices.LayoutKind.Sequential)]
        public struct IMAGE_NT_HEADERS32
        {

            /// DWORD->unsigned int
            public uint Signature;

            /// IMAGE_FILE_HEADER->_IMAGE_FILE_HEADER
            public IMAGE_FILE_HEADER FileHeader;

            /// IMAGE_OPTIONAL_HEADER->IMAGE_OPTIONAL_HEADER32->_IMAGE_OPTIONAL_HEADER
            public IMAGE_OPTIONAL_HEADER32 OptionalHeader;
        }

        [Serializable]
        [System.Runtime.InteropServices.StructLayoutAttribute(System.Runtime.InteropServices.LayoutKind.Sequential)]
        public struct IMAGE_FILE_HEADER
        {

            /// WORD->unsigned short
            public ushort Machine;

            /// WORD->unsigned short
            public ushort NumberOfSections;

            /// DWORD->unsigned int
            public uint TimeDateStamp;

            /// DWORD->unsigned int
            public uint PointerToSymbolTable;

            /// DWORD->unsigned int
            public uint NumberOfSymbols;

            /// WORD->unsigned short
            public ushort SizeOfOptionalHeader;

            /// WORD->unsigned short
            public ushort Characteristics;
        }

        [Serializable]
        [System.Runtime.InteropServices.StructLayoutAttribute(System.Runtime.InteropServices.LayoutKind.Sequential)]
        public struct IMAGE_OPTIONAL_HEADER32
        {

            /// WORD->unsigned short
            public ushort Magic;

            /// BYTE->unsigned char
            public byte MajorLinkerVersion;

            /// BYTE->unsigned char
            public byte MinorLinkerVersion;

            /// DWORD->unsigned int
            public uint SizeOfCode;

            /// DWORD->unsigned int
            public uint SizeOfInitializedData;

            /// DWORD->unsigned int
            public uint SizeOfUninitializedData;

            /// DWORD->unsigned int
            public uint AddressOfEntryPoint;

            /// DWORD->unsigned int
            public uint BaseOfCode;

            /// DWORD->unsigned int
            public uint BaseOfData;

            /// DWORD->unsigned int
            public uint ImageBase;

            /// DWORD->unsigned int
            public uint SectionAlignment;

            /// DWORD->unsigned int
            public uint FileAlignment;

            /// WORD->unsigned short
            public ushort MajorOperatingSystemVersion;

            /// WORD->unsigned short
            public ushort MinorOperatingSystemVersion;

            /// WORD->unsigned short
            public ushort MajorImageVersion;

            /// WORD->unsigned short
            public ushort MinorImageVersion;

            /// WORD->unsigned short
            public ushort MajorSubsystemVersion;

            /// WORD->unsigned short
            public ushort MinorSubsystemVersion;

            /// DWORD->unsigned int
            public uint Win32VersionValue;

            /// DWORD->unsigned int
            public uint SizeOfImage;

            /// DWORD->unsigned int
            public uint SizeOfHeaders;

            /// DWORD->unsigned int
            public uint CheckSum;

            /// WORD->unsigned short
            public ushort Subsystem;

            /// WORD->unsigned short
            public ushort DllCharacteristics;

            /// DWORD->unsigned int
            public uint SizeOfStackReserve;

            /// DWORD->unsigned int
            public uint SizeOfStackCommit;

            /// DWORD->unsigned int
            public uint SizeOfHeapReserve;

            /// DWORD->unsigned int
            public uint SizeOfHeapCommit;

            /// DWORD->unsigned int
            public uint LoaderFlags;

            /// DWORD->unsigned int
            public uint NumberOfRvaAndSizes;

            /// IMAGE_DATA_DIRECTORY[16]
            [System.Runtime.InteropServices.MarshalAsAttribute(System.Runtime.InteropServices.UnmanagedType.ByValArray, SizeConst = 16, ArraySubType = System.Runtime.InteropServices.UnmanagedType.Struct)]
            public IMAGE_DATA_DIRECTORY[] DataDirectory;
        }

        [Serializable]
        [System.Runtime.InteropServices.StructLayoutAttribute(System.Runtime.InteropServices.LayoutKind.Sequential)]
        public struct IMAGE_DATA_DIRECTORY
        {

            /// DWORD->unsigned int
            public uint VirtualAddress;

            /// DWORD->unsigned int
            public uint Size;
        }

        [System.Runtime.InteropServices.StructLayoutAttribute(System.Runtime.InteropServices.LayoutKind.Sequential)]
        public struct SECURITY_ATTRIBUTES
        {

            /// DWORD->unsigned int
            public uint nLength;

            /// LPVOID->void*
            public System.IntPtr lpSecurityDescriptor;

            /// BOOL->int
            [System.Runtime.InteropServices.MarshalAsAttribute(System.Runtime.InteropServices.UnmanagedType.Bool)]
            public bool bInheritHandle;
        }


        [System.Runtime.InteropServices.StructLayoutAttribute(System.Runtime.InteropServices.LayoutKind.Sequential)]
        public struct IMAGE_SECTION_HEADER
        {

            /// BYTE[8]
            [System.Runtime.InteropServices.MarshalAsAttribute(System.Runtime.InteropServices.UnmanagedType.ByValArray, SizeConst = 8, ArraySubType = System.Runtime.InteropServices.UnmanagedType.I1)]
            public byte[] Name;

            /// MiscUnion
            public MiscUnion Misc;

            /// DWORD->unsigned int
            public uint VirtualAddress;

            /// DWORD->unsigned int
            public uint SizeOfRawData;

            /// DWORD->unsigned int
            public uint PointerToRawData;

            /// DWORD->unsigned int
            public uint PointerToRelocations;

            /// DWORD->unsigned int
            public uint PointerToLinenumbers;

            /// WORD->unsigned short
            public ushort NumberOfRelocations;

            /// WORD->unsigned short
            public ushort NumberOfLinenumbers;

            /// DWORD->unsigned int
            public uint Characteristics;
        }

        [System.Runtime.InteropServices.StructLayoutAttribute(System.Runtime.InteropServices.LayoutKind.Explicit)]
        public struct MiscUnion
        {

            /// DWORD->unsigned int
            [System.Runtime.InteropServices.FieldOffsetAttribute(0)]
            public uint PhysicalAddress;

            /// DWORD->unsigned int
            [System.Runtime.InteropServices.FieldOffsetAttribute(0)]
            public uint VirtualSize;
        }

        [System.Runtime.InteropServices.StructLayoutAttribute(System.Runtime.InteropServices.LayoutKind.Sequential)]
        public struct SERVICE_TABLE
        {
            [System.Runtime.InteropServices.MarshalAsAttribute(System.Runtime.InteropServices.UnmanagedType.ByValArray, SizeConst = 2, ArraySubType = System.Runtime.InteropServices.UnmanagedType.Struct)]
            public SERVICE_TABLE_ENTRYW[] lpServiceTable;
        }

        [System.Runtime.InteropServices.StructLayoutAttribute(System.Runtime.InteropServices.LayoutKind.Sequential)]
        public struct SERVICE_TABLE_ENTRYW
        {
            /// LPWSTR->WCHAR*
            [System.Runtime.InteropServices.MarshalAsAttribute(System.Runtime.InteropServices.UnmanagedType.LPWStr)]
            public string lpServiceName;

            /// LPSERVICE_MAIN_FUNCTIONW
            //public LPSERVICE_MAIN_FUNCTIONW lpServiceProc;
            public Int32 lpServiceProc;
        }

        [System.Runtime.InteropServices.StructLayoutAttribute(System.Runtime.InteropServices.LayoutKind.Sequential)]
        public struct SYSTEM_LOAD_AND_CALL_IMAGE {
                
                /// UNICODE_STRING->_UNICODE_STRING
                public UNICODE_STRING ModuleName;
        }

        /// Return Type: int
        public delegate int FARPROC();

        [System.Runtime.InteropServices.StructLayoutAttribute(System.Runtime.InteropServices.LayoutKind.Sequential)]
        public struct HINSTANCE__ {
            
            /// int
            public int unused;
        }

        [System.Runtime.InteropServices.StructLayoutAttribute(System.Runtime.InteropServices.LayoutKind.Sequential)]
        public struct SERVICE_STATUS_HANDLE__
        {
            /// int
            public int unused;
        }

        [System.Runtime.InteropServices.StructLayoutAttribute(System.Runtime.InteropServices.LayoutKind.Sequential)]
        public struct SERVICE_STATUS
        {

            /// DWORD->unsigned int
            public uint dwServiceType;

            /// DWORD->unsigned int
            public uint dwCurrentState;

            /// DWORD->unsigned int
            public uint dwControlsAccepted;

            /// DWORD->unsigned int
            public uint dwWin32ExitCode;

            /// DWORD->unsigned int
            public uint dwServiceSpecificExitCode;

            /// DWORD->unsigned int
            public uint dwCheckPoint;

            /// DWORD->unsigned int
            public uint dwWaitHint;
        }

         [StructLayout(LayoutKind.Sequential)]
         public struct CRYPT_DATA_BLOB
         {
                public int cbData;
                public IntPtr pbData;
         }

         [System.Runtime.InteropServices.StructLayoutAttribute(System.Runtime.InteropServices.LayoutKind.Sequential)]
         public struct MEMORY_BASIC_INFORMATION
         {

             /// PVOID->void*
             public System.IntPtr BaseAddress;

             /// PVOID->void*
             public System.IntPtr AllocationBase;

             /// DWORD->unsigned int
             public uint AllocationProtect;

             /// SIZE_T->ULONG_PTR->unsigned int
             public uint RegionSize;

             /// DWORD->unsigned int
             public uint State;

             /// DWORD->unsigned int
             public uint Protect;

             /// DWORD->unsigned int
             public uint Type;
         }

         [System.Runtime.InteropServices.StructLayoutAttribute(System.Runtime.InteropServices.LayoutKind.Sequential, CharSet = System.Runtime.InteropServices.CharSet.Ansi)]
         public struct SYSTEM_MODULE_INFORMATION
         {

             /// DWORD->unsigned int
             public uint reserved1;

             /// DWORD->unsigned int
             public uint reserved2;

             /// PVOID->void*
             public System.IntPtr Base;

             /// ULONG->unsigned int
             public uint Size;

             /// ULONG->unsigned int
             public uint Flags;

             /// USHORT->unsigned short
             public ushort Index;

             /// USHORT->unsigned short
             public ushort Unknown;

             /// USHORT->unsigned short
             public ushort LoadCount;

             /// USHORT->unsigned short
             public ushort ModuleNameOffset;

             /// CHAR[256]
             [System.Runtime.InteropServices.MarshalAsAttribute(System.Runtime.InteropServices.UnmanagedType.ByValTStr, SizeConst = 256)]
             public string ImageName;
         }

         [System.Runtime.InteropServices.StructLayoutAttribute(System.Runtime.InteropServices.LayoutKind.Sequential)]
         public struct MODULE_LIST
         {
             /// DWORD->unsigned int
             public uint ModuleCount;

             /// SYSTEM_MODULE_INFORMATION[]
             public SYSTEM_MODULE_INFORMATION[] Modules;
         }

        #endregion

        #region P/Invoke constants

        //Macros as defined in winioctl.h
        public static uint CTL_CODE(uint DeviceType, uint Function, uint Method, uint Access)
        {
            return (((DeviceType) << 16) | ((Access) << 14) | ((Function) << 2) | (Method));
        }

        //from Undocumented windows internals
        public enum SYSTEM_INFORMATION_CLASS
        {
            SystemBasicInformation,
            SystemProcessorInformation,
            SystemPerformanceInformation,
            SystemTimeOfDayInformation,
            SystemPathInformation,
            SystemProcessInformation,
            SystemCallCountInformation,
            SystemDeviceInformation,
            SystemProcessorPerformanceInformation,
            SystemFlagsInformation,
            SystemCallTimeInformation,
            SystemModuleInformation,
            SystemLocksInformation,
            SystemStackTraceInformation,
            SystemPagedPoolInformation,
            SystemNonPagedPoolInformation,
            SystemHandleInformation,
            SystemObjectInformation,
            SystemPageFileInformation,
            SystemVdmInstemulInformation,
            SystemVdmBopInformation,
            SystemFileCacheInformation,
            SystemPoolTagInformation,
            SystemInterruptInformation,
            SystemDpcBehaviorInformation,
            SystemFullMemoryInformation,
            SystemLoadGdiDriverInformation,
            SystemUnloadGdiDriverInformation,
            SystemTimeAdjustmentInformation,
            SystemSummaryMemoryInformation,
            SystemNextEventIdInformation,
            SystemEventIdsInformation,
            SystemCrashDumpInformation,
            SystemExceptionInformation,
            SystemCrashDumpStateInformation,
            SystemKernelDebuggerInformation,
            SystemContextSwitchInformation,
            SystemRegistryQuotaInformation,
            SystemExtendServiceTableInformation,
            SystemPrioritySeperation,
            SystemPlugPlayBusInformation,
            SystemDockInformation,
            SystemPowerInformation,
            SystemProcessorSpeedInformation,
            SystemCurrentTimeZoneInformation,
            SystemLookasideInformation,
        }

        //from cryptapi.dll
        public const int CRYPT_EXPORTABLE = 0x00000001;
        public const int CRYPT_USER_PROTECTED = 0x00000002;
        public const int CRYPT_MACHINE_KEYSET = 0x00000020;
        public const int CRYPT_USER_KEYSET = 0x00001000;
        public const int CERT_KEY_PROV_INFO_PROP_ID = 0x00000002;
        public const int X509_ASN_ENCODING = 0x00000001;
        public const int PKCS_7_ASN_ENCODING = 0x00010000;
        public const int RSA_CSP_PUBLICKEYBLOB = 19;
        public const int CRYPT_DELETEKEYSET = 0x00000010;

        //from winnetwk.h (drive mapping constants)
        public const int RESOURCE_CONNECTED = 0x00000001;
        public const int RESOURCE_GLOBALNET = 0x00000002;
        public const int RESOURCE_REMEMBERED = 0x00000003;
        public const int RESOURCEDISPLAYTYPE_SHARE = 0x00000003;
        public const int RESOURCETYPE_DISK = 0x00000001;
        public const int RESOURCEUSAGE_CONNECTABLE = 0x00000001;
        public const int CONNECT_INTERACTIVE = 0x00000008;
        public const int CONNECT_PROMPT = 0x00000010;
        public const int CONNECT_UPDATE_PROFILE = 0x00000001;
        public const int CONNECT_REDIRECT = 0x00000080;
        public const int CONNECT_COMMANDLINE = 0x00000800;
        public const int CONNECT_CMD_SAVECRED = 0x00001000;
        public const int GENERIC_READ = unchecked((int)0x80000000);
        public const int GENERIC_WRITE = unchecked((int)0x40000000);
        public const int FILE_MAP_READ = 0x00000004;

        public const int VER_NT_WORKSTATION = 1;
        public const int VER_NT_DOMAIN_CONTROLLER = 2;
        public const int VER_NT_SERVER = 3;
        public const int VER_SUITE_SMALLBUSINESS = 1;
        public const int VER_SUITE_ENTERPRISE = 2;
        public const int VER_SUITE_TERMINAL = 16;
        public const int VER_SUITE_DATACENTER = 128;
        public const int VER_SUITE_SINGLEUSERTS = 256;
        public const int VER_SUITE_PERSONAL = 512;
        public const int VER_SUITE_BLADE = 1024;
        public const int TOKEN_ADJUST_PRIVILEGES = 0x00000020;
        public const int TOKEN_QUERY = 0x00000008;
        public const int SE_PRIVILEGE_ENABLED = 0x00000002;
        public const string SE_RESTORE_NAME = "SeRestorePrivilege";
        public const string SE_BACKUP_NAME = "SeBackupPrivilege";
        public const Int32
            //SCM status acceptance codes
            SERVICE_ACCEPT_NETBINDCHANGE = 0x00000010,
            SERVICE_ACCEPT_PARAMCHANGE = 0x00000008,
            SERVICE_ACCEPT_PAUSE_CONTINUE=0x00000002,
            SERVICE_ACCEPT_PRESHUTDOWN=0x00000100,
            SERVICE_ACCEPT_SHUTDOWN=0x00000004,
            SERVICE_ACCEPT_STOP=0x00000001,
            //SCM status codes
            SC_MANAGER_CREATE_SERVICE = 0x0002,
            SC_MANAGER_ALL_ACCESS = 0xF003F,
            SC_MANAGER_ENUMERATE_SERVICE = 0x0004,
            SC_STATUS_PROCESS_INFO = 0,
            //Service query access rights
            STANDARD_RIGHTS_REQUIRED = 0x000F0000,
            SERVICE_QUERY_CONFIG = 0x0001,
            SERVICE_CHANGE_CONFIG = 0x0002,
            SERVICE_QUERY_STATUS = 0x0004,
            SERVICE_ENUMERATE_DEPENDENTS = 0x0008,
            SERVICE_START = 0x0010,
            SERVICE_STOP = 0x0020,
            SERVICE_PAUSE_CONTINUE = 0x0040,
            SERVICE_INTERROGATE = 0x0080,
            SERVICE_USER_DEFINED_CONTROL = 0x0100,
            SERVICE_ALL_ACCESS = (STANDARD_RIGHTS_REQUIRED |
                               SERVICE_QUERY_CONFIG |
                               SERVICE_CHANGE_CONFIG |
                               SERVICE_QUERY_STATUS |
                               SERVICE_ENUMERATE_DEPENDENTS |
                               SERVICE_START |
                               SERVICE_STOP |
                               SERVICE_PAUSE_CONTINUE |
                               SERVICE_INTERROGATE |
                               SERVICE_USER_DEFINED_CONTROL),
            //service types for SCM
            SERVICE_KERNEL_DRIVER = 0x00000001,
            SERVICE_FILE_SYSTEM_DRIVER = 0x00000002,
            SERVICE_WIN32_OWN_PROCESS = 0x00000010,
            SERVICE_WIN32_SHARE_PROCESS = 0x00000020,
            //service start types for SCM
            SERVICE_DEMAND_START = 0x00000003,
            SERVICE_AUTO_START = 0x00000002,
            SERVICE_BOOT_START = 0x00000000,
            SERVICE_SYSTEM_START = 0x00000001,
            //
            SERVICE_ERROR_IGNORE = 0x00000000,
            SERVICE_ERROR_NORMAL = 0x00000001,
            SERVICE_CONTROL_STOP = 0x00000001,
            SERVICE_CONTROL_PAUSE = 0x00000002,
            SERVICE_PAUSED = 0x00000007,
            SERVICE_STOPPED = 0x00000001,
            SERVICE_RUNNING = 0x00000004,
            SERVICE_PAUSE_PENDING = 0x00000006,
            SERVICE_START_PENDING = 0x00000002,
            SERVICE_STOP_PENDING = 0x00000003,
            SERVICE_CONTINUE_PENDING = 0x00000005,

            //SCM error codes (4-digit int)
            ERROR_SERVICE_DOES_NOT_EXIST = 1060,
            ERROR_INVALID_NAME = 123,
            ERROR_INVALID_HANDLE = 6,
            ERROR_ACCESS_DENIED = 5,
            ERROR_INSUFFICIENT_BUFFER = 122,

            //I/O constants
            ERROR_PARTIAL_COPY = 299,
            ERROR_IO_PENDING=997,
            ERROR_SUCCESS = 0,
            FILE_FLAG_BACKUP_SEMANTICS = 0x02000000,
            FILE_READ_DATA = 0x0001,
            FILE_SHARE_READ = 0x00000001,
            FILE_SHARE_WRITE = 0x00000002,
            OPEN_EXISTING = 3,
            FILE_ANY_ACCESS = 0,
            FILE_DEVICE_VIRTUAL_DISK = 0x00000024,
            FILE_DEVICE_UNKNOWN = 0x00000022,
            FILE_ATTRIBUTE_NORMAL = 0x80,
            METHOD_BUFFERED = 0,
            METHOD_IN_DIRECT = 1,
            METHOD_OUT_DIRECT = 2,
            METHOD_NEITHER = 3,

            //process access rights
            PROCESS_TERMINATE=0x0001,
            PROCESS_CREATE_PROCESS = 0x0080,
            PROCESS_CREATE_THREAD = 0x0002,
            PROCESS_DUP_HANDLE = 0x0040,
            PROCESS_QUERY_INFORMATION = 0x0400,
            PROCESS_SET_INFORMATION = 0x0200,
            PROCESS_SET_QUOTA = 0x0100,
            PROCESS_SUSPEND_RESUME = 0x0800,
            PROCESS_VM_OPERATION = 0x0008,
            PROCESS_VM_READ = 0x0010,
            PROCESS_VM_WRITE = 0x0020, 

            //memory page protection attributes
            PAGE_EXECUTE = 0x10,
            PAGE_EXECUTE_READ = 0x20,
            PAGE_EXECUTE_READWRITE = 0x40,
            PAGE_EXECUTE_WRITECOPY = 0x80,
            PAGE_NOACCESS = 0x01,
            PAGE_READONLY = 0x02,
            PAGE_READWRITE = 0x04,
            PAGE_WRITECOPY = 0x08,
            PAGE_GUARD = 0x100,
            PAGE_NOCACHE = 0x200,
            PAGE_WRITECOMBINE = 0x400,

            //status codes
            STATUS_SUCCESS=0x00000000,

            //error code format for FormatMessage() API
            FORMAT_MESSAGE_FROM_SYSTEM = 0x00001000,
            FORMAT_MESSAGE_ALLOCATE_BUFFER = 0x00000100,
            FORMAT_MESSAGE_IGNORE_INSERTS = 0x00000200;

        internal const uint STATUS_INFO_LENGTH_MISMATCH = 0xC0000004;
        #endregion

        #region P/Invoke API function prototypes

        //--------------------------------------------------------
        //------========= BackupRead() ========-----
        //--------------------------------------------------------
        /// Return Type: BOOL->int
        ///hFile: HANDLE->void*
        ///lpBuffer: LPBYTE->BYTE*
        ///nNumberOfBytesToRead: DWORD->unsigned int
        ///lpNumberOfBytesRead: LPDWORD->DWORD*
        ///bAbort: BOOL->int
        ///bProcessSecurity: BOOL->int
        ///lpContext: LPVOID*
        [System.Runtime.InteropServices.DllImportAttribute("kernel32.dll", EntryPoint = "BackupRead")]
        [return: System.Runtime.InteropServices.MarshalAsAttribute(System.Runtime.InteropServices.UnmanagedType.Bool)]
        public static extern bool BackupRead([System.Runtime.InteropServices.InAttribute()] System.IntPtr hFile, [System.Runtime.InteropServices.OutAttribute()] out byte lpBuffer, uint nNumberOfBytesToRead, [System.Runtime.InteropServices.OutAttribute()] out uint lpNumberOfBytesRead, [System.Runtime.InteropServices.MarshalAsAttribute(System.Runtime.InteropServices.UnmanagedType.Bool)] bool bAbort, [System.Runtime.InteropServices.MarshalAsAttribute(System.Runtime.InteropServices.UnmanagedType.Bool)] bool bProcessSecurity, ref System.IntPtr lpContext);

        //--------------------------------------------------------
        //------========= ZwQuerySystemInformation() ========-----
        //--------------------------------------------------------
        /// Return Type: BOOL->int
        ///SystemInformationClass: SYSTEM_INFORMATION_CLASS
        ///SystemInformation: PVOID->void*
        ///SystemInformationLength: ULONG->unsigned int
        ///ReturnLength: PULONG->ULONG*
        [System.Runtime.InteropServices.DllImportAttribute("ntdll.dll", EntryPoint = "ZwQuerySystemInformation")]
        public static extern IntPtr ZwQuerySystemInformation(SYSTEM_INFORMATION_CLASS SystemInformationClass, System.IntPtr SystemInformation, uint SystemInformationLength, ref uint ReturnLength);

        //--------------------------------------------------------
        //------========= GetModuleInformation() ========-----
        //--------------------------------------------------------
        /// Return Type: BOOL->int
        ///hProcess: HANDLE->void*
        ///hModule: HMODULE->HINSTANCE->HINSTANCE__*
        ///lpmodinfo: LPMODULEINFO->_MODULEINFO*
        ///cb: DWORD->unsigned int
        [System.Runtime.InteropServices.DllImportAttribute("<Unknown>", EntryPoint = "GetModuleInformation")]
        [return: System.Runtime.InteropServices.MarshalAsAttribute(System.Runtime.InteropServices.UnmanagedType.Bool)]
        public static extern bool GetModuleInformation(System.IntPtr hProcess, System.IntPtr hModule, ref MODULEINFO lpmodinfo, uint cb);

        //--------------------------------------------------------
        //------========= MiniDumpWriteDump() ========-----
        //--------------------------------------------------------
        /// Return Type: BOOL->int
        ///hProcess: HANDLE->void*
        ///ProcessId: DWORD->unsigned int
        ///hFile: HANDLE->void*
        ///DumpType: MINIDUMP_TYPE->_MINIDUMP_TYPE
        ///ExceptionParam: PMINIDUMP_EXCEPTION_INFORMATION->_MINIDUMP_EXCEPTION_INFORMATION*
        [System.Runtime.InteropServices.DllImportAttribute("<Unknown>", EntryPoint = "MiniDumpWriteDump")]
        [return: System.Runtime.InteropServices.MarshalAsAttribute(System.Runtime.InteropServices.UnmanagedType.Bool)]
        public static extern bool MiniDumpWriteDump([System.Runtime.InteropServices.InAttribute()] System.IntPtr hProcess, uint ProcessId, [System.Runtime.InteropServices.InAttribute()] System.IntPtr hFile, MINIDUMP_TYPE DumpType, [System.Runtime.InteropServices.InAttribute()] ref MINIDUMP_EXCEPTION_INFORMATION ExceptionParam);

        //--------------------------------------------------------
        //------========= VirtualProtectEx() ========-----
        //--------------------------------------------------------
        /// Return Type: BOOL->int
        ///hProcess: HANDLE->void*
        ///lpAddress: LPVOID->void*
        ///dwSize: SIZE_T->ULONG_PTR->unsigned int
        ///flNewProtect: DWORD->unsigned int
        ///lpflOldProtect: PDWORD->DWORD*
        [System.Runtime.InteropServices.DllImportAttribute("kernel32.dll", EntryPoint = "VirtualProtectEx")]
        [return: System.Runtime.InteropServices.MarshalAsAttribute(System.Runtime.InteropServices.UnmanagedType.Bool)]
        public static extern bool VirtualProtectEx([System.Runtime.InteropServices.InAttribute()] System.IntPtr hProcess, [System.Runtime.InteropServices.InAttribute()] System.IntPtr lpAddress, uint dwSize, uint flNewProtect, [System.Runtime.InteropServices.OutAttribute()] out uint lpflOldProtect);

        //--------------------------------------------------------
        //------========= VirtualQueryEx() ========-----
        //--------------------------------------------------------
        /// Return Type: SIZE_T->ULONG_PTR->unsigned int
        ///hProcess: HANDLE->void*
        ///lpAddress: LPCVOID->void*
        ///lpBuffer: PMEMORY_BASIC_INFORMATION->_MEMORY_BASIC_INFORMATION*
        ///dwLength: SIZE_T->ULONG_PTR->unsigned int
        [System.Runtime.InteropServices.DllImportAttribute("kernel32.dll", EntryPoint = "VirtualQueryEx")]
        public static extern uint VirtualQueryEx([System.Runtime.InteropServices.InAttribute()] System.IntPtr hProcess, [System.Runtime.InteropServices.InAttribute()] System.IntPtr lpAddress, [System.Runtime.InteropServices.OutAttribute()] out MEMORY_BASIC_INFORMATION lpBuffer, uint dwLength);
        
        //--------------------------------------------------------
        //------========= GetCurrentProcessId() ========-----
        //--------------------------------------------------------
        /// Return Type: DWORD->unsigned int
        [System.Runtime.InteropServices.DllImportAttribute("kernel32.dll", EntryPoint = "GetCurrentProcessId")]
        public static extern uint GetCurrentProcessId();

        //--------------------------------------------------------
        //------========= CertCloseStore() ========-----
        //--------------------------------------------------------
        /// Return Type: BOOL->int
        ///hCertStore: HCERTSTORE->void*
        ///dwFlags: DWORD->unsigned int
        [System.Runtime.InteropServices.DllImportAttribute("crypt32.dll", EntryPoint = "CertCloseStore")]
        [return: System.Runtime.InteropServices.MarshalAsAttribute(System.Runtime.InteropServices.UnmanagedType.Bool)]
        public static extern bool CertCloseStore([System.Runtime.InteropServices.InAttribute()] System.IntPtr hCertStore, uint dwFlags);

        //--------------------------------------------------------
        //------========= PFXVerifyPassword() ========-----
        //--------------------------------------------------------
        /// Return Type: BOOL->int
        ///pPFX: CRYPT_DATA_BLOB*
        ///szPassword: LPCWSTR->WCHAR*
        ///dwFlags: DWORD->unsigned int
        [System.Runtime.InteropServices.DllImportAttribute("crypt32.dll", EntryPoint = "PFXVerifyPassword")]
        [return: System.Runtime.InteropServices.MarshalAsAttribute(System.Runtime.InteropServices.UnmanagedType.Bool)]
        public static extern bool PFXVerifyPassword([System.Runtime.InteropServices.InAttribute()] ref CRYPT_DATA_BLOB pPFX, [System.Runtime.InteropServices.InAttribute()] [System.Runtime.InteropServices.MarshalAsAttribute(System.Runtime.InteropServices.UnmanagedType.LPWStr)] string szPassword, uint dwFlags);

        //--------------------------------------------------------
        //------========= PFXIsPFXBlob() ========-----
        //--------------------------------------------------------
        //source:  http://msdn.microsoft.com/en-us/library/ms867088.aspx
        /// Return Type: BOOL->int
        ///pPFX: CRYPT_DATA_BLOB*
        [System.Runtime.InteropServices.DllImportAttribute("crypt32.dll", EntryPoint = "PFXIsPFXBlob")]
        [return: System.Runtime.InteropServices.MarshalAsAttribute(System.Runtime.InteropServices.UnmanagedType.Bool)]
        public static extern bool PFXIsPFXBlob([System.Runtime.InteropServices.InAttribute()] ref CRYPT_DATA_BLOB pPFX);

        //--------------------------------------------------------
        //------========= PFXImportCertStore() ========-----
        //--------------------------------------------------------
        //source:  http://msdn.microsoft.com/en-us/library/ms867088.aspx
        //
        [DllImport("crypt32.dll", SetLastError=true)]   
        public static extern IntPtr PFXImportCertStore(ref CRYPT_DATA_BLOB pPfx,[MarshalAs(UnmanagedType.LPWStr)] String szPassword, uint dwFlags);

        /// Return Type: BOOL->int
        ///hStore: HCERTSTORE->void*
        ///pPFX: CRYPT_DATA_BLOB*
        ///szPassword: LPCWSTR->WCHAR*
        ///pvReserved: void*
        ///dwFlags: DWORD->unsigned int
        [System.Runtime.InteropServices.DllImportAttribute("crypt32.dll", EntryPoint = "PFXExportCertStoreEx")]
        [return: System.Runtime.InteropServices.MarshalAsAttribute(System.Runtime.InteropServices.UnmanagedType.Bool)]
        public static extern bool PFXExportCertStoreEx([System.Runtime.InteropServices.InAttribute()] System.IntPtr hStore, ref CRYPT_DATA_BLOB pPFX, [System.Runtime.InteropServices.InAttribute()] [System.Runtime.InteropServices.MarshalAsAttribute(System.Runtime.InteropServices.UnmanagedType.LPWStr)] string szPassword, System.IntPtr pvReserved, uint dwFlags);


        //--------------------------------------------------------
        //------========= GetModuleHandle() ========-----
        //--------------------------------------------------------
        /// Return Type: HMODULE->HINSTANCE->HINSTANCE__*
        ///lpModuleName: LPCTSTR->LPCWSTR->WCHAR*
        [System.Runtime.InteropServices.DllImportAttribute("kernel32.dll", EntryPoint="GetModuleHandleW")]
        public static extern  System.IntPtr GetModuleHandle([System.Runtime.InteropServices.InAttribute()] [System.Runtime.InteropServices.MarshalAsAttribute(System.Runtime.InteropServices.UnmanagedType.LPTStr)] string lpModuleName) ;

        //--------------------------------------------------------
        //------========= GetProcAddress() ========-----
        //--------------------------------------------------------
        /// Return Type: UIntPtr
        [DllImport("kernel32.dll", CharSet=CharSet.Ansi, ExactSpelling=true)]
        public static extern IntPtr GetProcAddress(IntPtr hModule, string procName);

        //--------------------------------------------------------
        //------========= SetServiceStatus() ========-----
        //--------------------------------------------------------
        /// Return Type: BOOL->int
        ///hServiceStatus: SERVICE_STATUS_HANDLE->SERVICE_STATUS_HANDLE__*
        ///lpServiceStatus: LPSERVICE_STATUS->_SERVICE_STATUS*
        [System.Runtime.InteropServices.DllImportAttribute("advapi32.dll", EntryPoint = "SetServiceStatus")]
        [return: System.Runtime.InteropServices.MarshalAsAttribute(System.Runtime.InteropServices.UnmanagedType.Bool)]
        public static extern bool SetServiceStatus([System.Runtime.InteropServices.InAttribute()] ref SERVICE_STATUS_HANDLE__ hServiceStatus, [System.Runtime.InteropServices.InAttribute()] ref SERVICE_STATUS lpServiceStatus);

        //--------------------------------------------------------
        //------========= RegisterServiceCtrlHandler() ========-----
        //--------------------------------------------------------
        /// Return Type: SERVICE_STATUS_HANDLE->SERVICE_STATUS_HANDLE__*
        ///lpServiceName: LPCTSTR->LPCWSTR->WCHAR*
        ///lpHandlerProc: LPHANDLER_FUNCTION
        [System.Runtime.InteropServices.DllImportAttribute("advapi32.dll", EntryPoint = "RegisterServiceCtrlHandlerW")]
        public static extern System.IntPtr RegisterServiceCtrlHandler([System.Runtime.InteropServices.InAttribute()] [System.Runtime.InteropServices.MarshalAsAttribute(System.Runtime.InteropServices.UnmanagedType.LPTStr)] string lpServiceName, LPHANDLER_FUNCTION lpHandlerProc);

        //--------------------------------------------------------
        //------========= StartServiceCtrlDispatcher() ========-----
        //--------------------------------------------------------
        /// Return Type: BOOL->int
        ///lpServiceTable: SERVICE_TABLE_ENTRY*
        [System.Runtime.InteropServices.DllImportAttribute("advapi32.dll", EntryPoint = "StartServiceCtrlDispatcherW")]
        [return: System.Runtime.InteropServices.MarshalAsAttribute(System.Runtime.InteropServices.UnmanagedType.Bool)]
        public static extern bool StartServiceCtrlDispatcher([System.Runtime.InteropServices.InAttribute()] IntPtr lpServiceTable);

        //--------------------------------------------------------
        //------========= DeviceIoControl() ========-------------
        //--------------------------------------------------------
        //allows us to send IOCTLs to our kernel driver.
        //Note:  overloaded for byte[] return data ONLY!
        //Marshal the in and out bufs to unmanaged code as LPArray type (like ptr to c-style array)
        //but treated like IntPtr's in managed code, so we can use built-in Marshaling to make sense of results
        [System.Runtime.InteropServices.DllImportAttribute("kernel32.dll", CharSet = CharSet.Auto, SetLastError = true, EntryPoint = "DeviceIoControl")]
        public static extern bool DeviceIoControl(IntPtr hDevice, uint dwIoControlCode, IntPtr lpInBuffer, int nInBufferSize, IntPtr lpOutBuffer, int nOutBufferSize, ref int lpBytesReturned, IntPtr lpOverlapped);

        //--------------------------------------------------------
        //------========= OpenSCManager() ========-------------
        //--------------------------------------------------------
        //creates a connection to the Service Control Manager
        [DllImport("advapi32.Dll", CharSet = CharSet.Auto, SetLastError = true)]public static extern IntPtr OpenSCManager(String lpMachineName,String lpDatabaseName,Int32 dwDesiredAccess);

        //--------------------------------------------------------
        //------========= OpenService() ========-------------
        //--------------------------------------------------------
        //opens an existing service
        [DllImport("advapi32.Dll", CharSet = CharSet.Auto, SetLastError = true)] public static extern IntPtr OpenService(IntPtr hSCManager, String lpServiceName,Int32 dwDesiredAccess);

        //--------------------------------------------------------
        //------========= CreateService() ========-------------
        //--------------------------------------------------------
        //installs and registers our driver's service
        [DllImport("advapi32.dll", CharSet = CharSet.Auto, SetLastError = true)] public static extern IntPtr CreateService(IntPtr hSCManager,String lpServiceName,String lpDisplayName,Int32 dwDesiredAccess,Int32 dwServiceType,Int32 dwStartType,Int32 dwErrorControl,String lpBinaryBathName, String lpLoadOrderGroup,Int32 lpdwTagId,String lpDependencies,String lpServiceStartName,String lpPassword);

        //--------------------------------------------------------
        //------========= StartService() ========-------------
        //--------------------------------------------------------
        //starts the service we registered earlier
        [DllImport("advapi32.dll", CharSet = CharSet.Auto, SetLastError = true)] public static extern bool StartService(IntPtr hService,Int32 dwNumServiceArgs,String[] lpServiceArgVectors);

        //--------------------------------------------------------
        //------========= ControlService() ========-------------
        //--------------------------------------------------------
        /// Return Type: BOOL->int
        ///hService: SC_HANDLE->SC_HANDLE__*
        ///dwControl: DWORD->unsigned int
        ///lpServiceStatus: LPSERVICE_STATUS->_SERVICE_STATUS*
        [System.Runtime.InteropServices.DllImportAttribute("advapi32.dll", EntryPoint = "ControlService")]
        [return: System.Runtime.InteropServices.MarshalAsAttribute(System.Runtime.InteropServices.UnmanagedType.Bool)]
        public static extern bool ControlService([System.Runtime.InteropServices.InAttribute()] IntPtr hService, uint dwControl, [System.Runtime.InteropServices.OutAttribute()] IntPtr lpServiceStatus);

        //--------------------------------------------------------
        //------========= QueryServiceStatusEx() ========-------------
        //--------------------------------------------------------
        /// Return Type: BOOL->int
        ///hService: SC_HANDLE->SC_HANDLE__*
        ///InfoLevel: SC_STATUS_TYPE->_SC_STATUS_TYPE
        ///lpBuffer: LPBYTE->BYTE*
        ///cbBufSize: DWORD->unsigned int
        ///pcbBytesNeeded: LPDWORD->DWORD*
        [System.Runtime.InteropServices.DllImportAttribute("advapi32.dll", EntryPoint = "QueryServiceStatusEx")]
        [return: System.Runtime.InteropServices.MarshalAsAttribute(System.Runtime.InteropServices.UnmanagedType.Bool)]
        public static extern bool QueryServiceStatusEx([System.Runtime.InteropServices.InAttribute()] IntPtr hService, SC_STATUS_TYPE InfoLevel, IntPtr lpBuffer, uint cbBufSize, ref uint pcbBytesNeeded);

        //--------------------------------------------------------
        //------========= DeleteService() ========-------------
        //--------------------------------------------------------
        //allows us to destroy the service we installed
        [DllImport("advapi32.dll", CharSet = CharSet.Auto, SetLastError = true)] public static extern bool DeleteService(IntPtr hService);

        //--------------------------------------------------------
        //------========= CloseServiceHandle() ========-------------
        //--------------------------------------------------------
        //declaration for CloseServiceHandle() API closes a handle we opened to our service
        [DllImport("advapi32.dll",CharSet = CharSet.Auto, SetLastError = true)] public static extern bool CloseServiceHandle(IntPtr hSCObject);

        //--------------------------------------------------------
        //------========= ZwOpenProcess() ========-------------
        //--------------------------------------------------------
        /// Return Type: BOOL->int
        ///ProcessHandle: PHANDLE->HANDLE*
        ///DesiredAccess: INT->int
        ///ObjectAttributes: int
        ///ClientId: INT->int
        [System.Runtime.InteropServices.DllImportAttribute("ntdll.dll", EntryPoint = "ZwOpenProcess")]
        [return: System.Runtime.InteropServices.MarshalAsAttribute(System.Runtime.InteropServices.UnmanagedType.Bool)]
        public static extern bool ZwOpenProcess(ref System.IntPtr ProcessHandle, IntPtr DesiredAccess, IntPtr ObjectAttributes, IntPtr ClientId);

        //--------------------------------------------------------
        //------========= ZwTerminateProcess() ========-------------
        //--------------------------------------------------------
        /// Return Type: BOOL->int
        ///ProcessHandle: HANDLE->void*
        ///ExitStatus: BOOL->int
        [System.Runtime.InteropServices.DllImportAttribute("ntdll.dll", EntryPoint = "ZwTerminateProcess")]
        [return: System.Runtime.InteropServices.MarshalAsAttribute(System.Runtime.InteropServices.UnmanagedType.Bool)]
        public static extern bool ZwTerminateProcess(System.IntPtr ProcessHandle, uint ExitStatus);

        //--------------------------------------------------------
        //------========= UnmapViewOfFile() ========-------------
        //--------------------------------------------------------
        /// Return Type: BOOL->int
        ///lpBaseAddress: LPCVOID->void*
        [System.Runtime.InteropServices.DllImportAttribute("kernel32.dll", EntryPoint = "UnmapViewOfFile")]
        [return: System.Runtime.InteropServices.MarshalAsAttribute(System.Runtime.InteropServices.UnmanagedType.Bool)]
        public static extern bool UnmapViewOfFile([System.Runtime.InteropServices.InAttribute()] System.IntPtr lpBaseAddress);

        //--------------------------------------------------------
        //------========= CreateFile() ========-------------
        //--------------------------------------------------------
        /// Return Type: HANDLE->void*
        ///lpFileName: LPCTSTR->LPCWSTR->WCHAR*
        ///dwDesiredAccess: DWORD->unsigned int
        ///dwShareMode: DWORD->unsigned int
        ///lpSecurityAttributes: LPSECURITY_ATTRIBUTES->_SECURITY_ATTRIBUTES*
        ///dwCreationDisposition: DWORD->unsigned int
        ///dwFlagsAndAttributes: DWORD->unsigned int
        ///hTemplateFile: HANDLE->void*
        [System.Runtime.InteropServices.DllImportAttribute("kernel32.dll", EntryPoint = "CreateFileW")]
        public static extern IntPtr CreateFile([System.Runtime.InteropServices.InAttribute()] [System.Runtime.InteropServices.MarshalAsAttribute(System.Runtime.InteropServices.UnmanagedType.LPTStr)] string lpFileName, int dwDesiredAccess, uint dwShareMode, [System.Runtime.InteropServices.InAttribute()] System.IntPtr lpSecurityAttributes, uint dwCreationDisposition, uint dwFlagsAndAttributes, [System.Runtime.InteropServices.InAttribute()] System.IntPtr hTemplateFile);
        //CreateFileSafeHandle() to return a safehandle for driver interaction
        [System.Runtime.InteropServices.DllImportAttribute("kernel32.dll", EntryPoint = "CreateFileW")]
        public static extern SafeFileHandle CreateFileSafeHandle([System.Runtime.InteropServices.InAttribute()] [System.Runtime.InteropServices.MarshalAsAttribute(System.Runtime.InteropServices.UnmanagedType.LPTStr)] string lpFileName, int dwDesiredAccess, uint dwShareMode, [System.Runtime.InteropServices.InAttribute()] System.IntPtr lpSecurityAttributes, uint dwCreationDisposition, uint dwFlagsAndAttributes, [System.Runtime.InteropServices.InAttribute()] System.IntPtr hTemplateFile);

        //--------------------------------------------------------
        //------========= CreateFileMapping() ========-------------
        //--------------------------------------------------------
        /// Return Type: HANDLE->void*
        ///hFile: HANDLE->void*
        ///lpAttributes: LPSECURITY_ATTRIBUTES->_SECURITY_ATTRIBUTES*
        ///flProtect: DWORD->unsigned int
        ///dwMaximumSizeHigh: DWORD->unsigned int
        ///dwMaximumSizeLow: DWORD->unsigned int
        ///lpName: LPCTSTR->LPCWSTR->WCHAR*
        [System.Runtime.InteropServices.DllImportAttribute("kernel32.dll", EntryPoint = "CreateFileMappingW")]
        public static extern System.IntPtr CreateFileMapping([System.Runtime.InteropServices.InAttribute()] System.IntPtr hFile, [System.Runtime.InteropServices.InAttribute()] System.IntPtr lpAttributes, uint flProtect, uint dwMaximumSizeHigh, uint dwMaximumSizeLow, [System.Runtime.InteropServices.InAttribute()] [System.Runtime.InteropServices.MarshalAsAttribute(System.Runtime.InteropServices.UnmanagedType.LPTStr)] string lpName);

        //--------------------------------------------------------
        //------========= ImageNtHeader() ========-------------
        //--------------------------------------------------------
        /// Return Type: PIMAGE_NT_HEADERS->PIMAGE_NT_HEADERS32->_IMAGE_NT_HEADERS*
        ///ImageBase: PVOID->void*
        [System.Runtime.InteropServices.DllImportAttribute("Dbghelp.dll", EntryPoint = "ImageNtHeader")]
        public static extern System.IntPtr ImageNtHeader([System.Runtime.InteropServices.InAttribute()] System.IntPtr ImageBase);

        //--------------------------------------------------------
        //------========= MapViewOfFile() ========-------------
        //--------------------------------------------------------
        /// Return Type: LPVOID->void*
        ///hFileMappingObject: HANDLE->void*
        ///dwDesiredAccess: DWORD->unsigned int
        ///dwFileOffsetHigh: DWORD->unsigned int
        ///dwFileOffsetLow: DWORD->unsigned int
        ///dwNumberOfBytesToMap: SIZE_T->ULONG_PTR->unsigned int
        [System.Runtime.InteropServices.DllImportAttribute("kernel32.dll", EntryPoint = "MapViewOfFile")]
        public static extern System.IntPtr MapViewOfFile([System.Runtime.InteropServices.InAttribute()] System.IntPtr hFileMappingObject, uint dwDesiredAccess, uint dwFileOffsetHigh, uint dwFileOffsetLow, uint dwNumberOfBytesToMap);

        //--------------------------------------------------------
        //------========= RegQueryInfoKeyW() ========-------------
        //--------------------------------------------------------
        [System.Runtime.InteropServices.DllImportAttribute("advapi32.dll", EntryPoint = "RegQueryInfoKeyW")]
        public static extern int RegQueryInfoKeyW(
            [System.Runtime.InteropServices.InAttribute()] IntPtr hKey,
            [System.Runtime.InteropServices.OutAttribute()] 
            [System.Runtime.InteropServices.MarshalAsAttribute(System.Runtime.InteropServices.UnmanagedType.LPTStr)] 
            System.Text.StringBuilder lpClass,
            IntPtr lpcClass,
            IntPtr lpReserved,
            IntPtr lpcSubKeys,
            IntPtr lpcMaxSubKeyLen,
            IntPtr lpcMaxClassLen,
            IntPtr lpcValues,
            IntPtr lpcMaxValueNameLen,
            IntPtr lpcMaxValueLen,
            IntPtr lpcbSecurityDescriptor,
            IntPtr lpftLastWriteTime);

        //--------------------------------------------------------
        //------========= RegOpenKeyExW() ========----------------
        //--------------------------------------------------------
        [System.Runtime.InteropServices.DllImportAttribute("advapi32.dll", EntryPoint = "RegOpenKeyExW")]
        public static extern int RegOpenKeyExW(
            [System.Runtime.InteropServices.InAttribute()] IntPtr hKey,
            [System.Runtime.InteropServices.InAttribute()] 
                [System.Runtime.InteropServices.MarshalAsAttribute(System.Runtime.InteropServices.UnmanagedType.LPTStr)] string lpSubKey,
                uint ulOptions,
                uint samDesired,
                ref IntPtr phkResult);

        //--------------------------------------------------------
        //------========= GetVersionEx() ========----------------
        //--------------------------------------------------------
        [DllImport("kernel32.dll")]
        private static extern bool GetVersionEx(ref OSVERSIONINFOEX osVersionInfo);

        //--------------------------------------------------------
        //------========= OpenProcess() ========----------------
        //--------------------------------------------------------
        [DllImport("kernel32.dll")]
        public static extern IntPtr OpenProcess(uint dwDesiredAccess, [MarshalAsAttribute(UnmanagedType.Bool)] bool bInheritHandle, uint dwProcessId);

        //--------------------------------------------------------
        //------========= ReadProcessMemory() ========------------
        //--------------------------------------------------------
        [DllImport("kernel32.dll")]
        public static extern Int32 ReadProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, [In, Out] byte[] buffer, UInt32 size, out IntPtr lpNumberOfBytesRead);

        //--------------------------------------------------------
        //------========= CloseHandle() ========----------------
        //--------------------------------------------------------
        [DllImport("kernel32.dll")]
        public static extern Int32 CloseHandle(IntPtr hObject);

        //--------------------------------------------------------
        //------========= GlobalMemoryStatusEx() ========---------
        //--------------------------------------------------------
        [return: MarshalAs(UnmanagedType.Bool)]
        [DllImport("kernel32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        static extern bool GlobalMemoryStatusEx([In, Out] MEMORYSTATUSEX lpBuffer);

        //--------------------------------------------------------
        //------========= TerminateThread() ========--------------
        //--------------------------------------------------------
        [System.Runtime.InteropServices.DllImportAttribute("kernel32.dll", EntryPoint = "TerminateThread")]
        [return: System.Runtime.InteropServices.MarshalAsAttribute(System.Runtime.InteropServices.UnmanagedType.Bool)]
        public static extern bool TerminateThread(System.IntPtr hThread, uint dwExitCode);

        //--------------------------------------------------------
        //------========= SuspendThread() ========----------------
        //--------------------------------------------------------
        [System.Runtime.InteropServices.DllImportAttribute("kernel32.dll", EntryPoint = "SuspendThread")]
        [return: System.Runtime.InteropServices.MarshalAsAttribute(System.Runtime.InteropServices.UnmanagedType.Bool)]
        public static extern bool SuspendThread([System.Runtime.InteropServices.InAttribute()] System.IntPtr hThread);

        //--------------------------------------------------------
        //------========= TerminateProcess() ========--------------
        //--------------------------------------------------------
        [System.Runtime.InteropServices.DllImportAttribute("kernel32.dll", EntryPoint = "TerminateProcess")]
        [return: System.Runtime.InteropServices.MarshalAsAttribute(System.Runtime.InteropServices.UnmanagedType.Bool)]
        public static extern bool TerminateProcess([System.Runtime.InteropServices.InAttribute()] System.IntPtr hProcess, uint uExitCode);

        //--------------------------------------------------------
        //------========= CreateToolhelp32Snapshot() ========----
        //--------------------------------------------------------
        [System.Runtime.InteropServices.DllImportAttribute("kernel32.dll", EntryPoint = "CreateToolhelp32Snapshot")]
        public static extern System.IntPtr CreateToolhelp32Snapshot(uint dwFlags, uint th32ProcessID);

        //--------------------------------------------------------
        //------========= Toolhelp32ReadProcessMemory() ========--
        //--------------------------------------------------------
        /// Return Type: BOOL->int
        ///th32ProcessID: DWORD->unsigned int
        ///lpBaseAddress: LPCVOID->void*
        ///lpBuffer: LPVOID->void*
        ///cbRead: SIZE_T->ULONG_PTR->unsigned int
        ///lpNumberOfBytesRead: SIZE_T->ULONG_PTR->unsigned int
        [System.Runtime.InteropServices.DllImportAttribute("kernel32.dll", EntryPoint = "Toolhelp32ReadProcessMemory")]
        [return: System.Runtime.InteropServices.MarshalAsAttribute(System.Runtime.InteropServices.UnmanagedType.Bool)]
        public static extern bool Toolhelp32ReadProcessMemory(uint th32ProcessID, [System.Runtime.InteropServices.InAttribute()] System.IntPtr lpBaseAddress, System.IntPtr lpBuffer, uint cbRead, IntPtr lpNumberOfBytesRead);

        //--------------------------------------------------------
        //------========= Process32First() ========---------------
        //--------------------------------------------------------
        [System.Runtime.InteropServices.DllImportAttribute("kernel32.dll", EntryPoint = "Process32First")]
        [return: System.Runtime.InteropServices.MarshalAsAttribute(System.Runtime.InteropServices.UnmanagedType.Bool)]
        public static extern bool Process32First([System.Runtime.InteropServices.InAttribute()] System.IntPtr hSnapshot, ref PROCESSENTRY32 lppe);

        //--------------------------------------------------------
        //------========= Process32Next() ========---------------
        //--------------------------------------------------------
        [System.Runtime.InteropServices.DllImportAttribute("kernel32.dll", EntryPoint = "Process32Next")]
        [return: System.Runtime.InteropServices.MarshalAsAttribute(System.Runtime.InteropServices.UnmanagedType.Bool)]
        public static extern bool Process32Next([System.Runtime.InteropServices.InAttribute()] System.IntPtr hSnapshot, ref PROCESSENTRY32 lppe);

        //--------------------------------------------------------
        //------========= Thread32First() ========----------------
        //--------------------------------------------------------
        [System.Runtime.InteropServices.DllImportAttribute("kernel32.dll", EntryPoint = "Thread32First")]
        [return: System.Runtime.InteropServices.MarshalAsAttribute(System.Runtime.InteropServices.UnmanagedType.Bool)]
        public static extern bool Thread32First([System.Runtime.InteropServices.InAttribute()] System.IntPtr hSnapshot, ref THREADENTRY32 lpte);

        //--------------------------------------------------------
        //------========= Thread32Next() ========----------------
        //--------------------------------------------------------
        [System.Runtime.InteropServices.DllImportAttribute("kernel32.dll", EntryPoint = "Thread32Next")]
        [return: System.Runtime.InteropServices.MarshalAsAttribute(System.Runtime.InteropServices.UnmanagedType.Bool)]
        public static extern bool Thread32Next([System.Runtime.InteropServices.InAttribute()] System.IntPtr hSnapshot, ref THREADENTRY32 lpte);

        //--------------------------------------------------------
        //------========= Heap32First() ========----------------
        //--------------------------------------------------------
        [System.Runtime.InteropServices.DllImportAttribute("kernel32.dll", EntryPoint = "Heap32First")]
        [return: System.Runtime.InteropServices.MarshalAsAttribute(System.Runtime.InteropServices.UnmanagedType.Bool)]
        public static extern bool Heap32First(ref HEAPENTRY32 lphe, uint th32ProcessID, IntPtr th32HeapID);

        //--------------------------------------------------------
        //------========= Heap32Next() ========----------------
        //--------------------------------------------------------
        [System.Runtime.InteropServices.DllImportAttribute("kernel32.dll", EntryPoint = "Heap32Next")]
        [return: System.Runtime.InteropServices.MarshalAsAttribute(System.Runtime.InteropServices.UnmanagedType.Bool)]
        public static extern bool Heap32Next([System.Runtime.InteropServices.OutAttribute()] out HEAPENTRY32 lphe);

        //--------------------------------------------------------
        //------========= Heap32ListFirst() ========----------------
        //--------------------------------------------------------
        [System.Runtime.InteropServices.DllImportAttribute("kernel32.dll", EntryPoint = "Heap32ListFirst")]
        [return: System.Runtime.InteropServices.MarshalAsAttribute(System.Runtime.InteropServices.UnmanagedType.Bool)]
        public static extern bool Heap32ListFirst([System.Runtime.InteropServices.InAttribute()] System.IntPtr hSnapshot, ref HEAPLIST32 lphl);

        //--------------------------------------------------------
        //------========= Heap32ListNext() ========----------------
        //--------------------------------------------------------
        [System.Runtime.InteropServices.DllImportAttribute("kernel32.dll", EntryPoint = "Heap32ListNext")]
        [return: System.Runtime.InteropServices.MarshalAsAttribute(System.Runtime.InteropServices.UnmanagedType.Bool)]
        public static extern bool Heap32ListNext([System.Runtime.InteropServices.InAttribute()] System.IntPtr hSnapshot, ref HEAPLIST32 lphl);

        //--------------------------------------------------------
        //------========= Module32First() ========----------------
        //--------------------------------------------------------
        [System.Runtime.InteropServices.DllImportAttribute("kernel32.dll", EntryPoint = "Module32First")]
        [return: System.Runtime.InteropServices.MarshalAsAttribute(System.Runtime.InteropServices.UnmanagedType.Bool)]
        public static extern bool Module32First([System.Runtime.InteropServices.InAttribute()] System.IntPtr hSnapshot, ref MODULEENTRY32 lpme);

        //--------------------------------------------------------
        //------========= Module32Next() ========----------------
        //--------------------------------------------------------
        [System.Runtime.InteropServices.DllImportAttribute("kernel32.dll", EntryPoint = "Module32Next")]
        [return: System.Runtime.InteropServices.MarshalAsAttribute(System.Runtime.InteropServices.UnmanagedType.Bool)]
        public static extern bool Module32Next([System.Runtime.InteropServices.InAttribute()] System.IntPtr hSnapshot, ref MODULEENTRY32 lpme);

        //--------------------------------------------------------
        //------========= GetLastError() ========----------------
        //--------------------------------------------------------
        [System.Runtime.InteropServices.DllImportAttribute("kernel32.dll", EntryPoint = "GetLastError")]
        public static extern uint GetLastError();

        //--------------------------------------------------------
        //------========= FormatMessage() ========----------------
        //--------------------------------------------------------
        [System.Runtime.InteropServices.DllImportAttribute("kernel32.dll", EntryPoint = "FormatMessage")]
        public static extern uint FormatMessage(uint dwFlags, [System.Runtime.InteropServices.InAttribute()] System.IntPtr lpSource, uint dwMessageId, uint dwLanguageId, [System.Runtime.InteropServices.OutAttribute()] IntPtr lpBuffer, uint nSize, System.IntPtr Arguments);

        //--------------------------------------------------------
        //------========= LogonUser() ========--------------------
        //--------------------------------------------------------
        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        public static extern bool LogonUser(String lpszUsername, String lpszDomain, String lpszPassword,
            int dwLogonType, int dwLogonProvider, ref IntPtr phToken);

        //--------------------------------------------------------
        //------========= DuplicateToken() ========---------------
        //--------------------------------------------------------
        [DllImport("advapi32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        public extern static bool DuplicateToken(IntPtr ExistingTokenHandle,
            int SECURITY_IMPERSONATION_LEVEL, ref IntPtr DuplicateTokenHandle);

        //--------------------------------------------------------
        //------========= RegLoadKey() ========-------------------
        //--------------------------------------------------------
        [DllImport("advapi32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        public static extern int RegLoadKey(uint hKey, string lpSubKey, string lpFile);

        //--------------------------------------------------------
        //------========= RegUnLoadKey() ========-----------------
        //--------------------------------------------------------
        [DllImport("advapi32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        public static extern int RegUnLoadKey(uint hKey, string lpSubKey);

        //--------------------------------------------------------
        //------========= OpenProcessToken() ========-----------------
        //--------------------------------------------------------
        [DllImport("advapi32.dll", CharSet = CharSet.Auto)]
        public static extern int OpenProcessToken(int ProcessHandle, int DesiredAccess,
        ref int tokenhandle);

        //--------------------------------------------------------
        //------========= GetCurrentProcess() ========-----------------
        //--------------------------------------------------------
        [DllImport("kernel32.dll", CharSet = CharSet.Auto)]
        public static extern int GetCurrentProcess();

        //--------------------------------------------------------
        //------========= LookupPrivilegeValue() ========-----------------
        //--------------------------------------------------------
        [DllImport("advapi32.dll", CharSet = CharSet.Auto)]
        public static extern int LookupPrivilegeValue(string lpsystemname, string lpname,
        [MarshalAs(UnmanagedType.Struct)] ref LUID lpLuid);

        //--------------------------------------------------------
        //------========= AdjustTokenPrivileges() ========-----------------
        //--------------------------------------------------------
        [DllImport("advapi32.dll", CharSet = CharSet.Auto)]
        public static extern int AdjustTokenPrivileges(int tokenhandle, int disableprivs,
        [MarshalAs(UnmanagedType.Struct)]ref TOKEN_PRIVILEGES Newstate, int bufferlength,
        int PreivousState, int Returnlength);

        //network drive mapping functions
        [DllImport("mpr.dll")]
        public static extern int WNetAddConnection2(ref NETRESOURCE pstNetRes, string psPassword, string psUsername, int piFlags);
        [DllImport("mpr.dll")]
        public static extern int WNetCancelConnection2(string psName, int piFlags, int pfForce);
        [DllImport("mpr.dll")]
        public static extern int WNetConnectionDialog(int phWnd, int piType);
        [DllImport("mpr.dll")]
        public static extern int WNetDisconnectDialog(int phWnd, int piType);
        [DllImport("mpr.dll")]
        public static extern int WNetRestoreConnectionW(int phWnd, string psLocalDrive);

        //MSFT Crypto API (CAPI) functions
        [DllImport("advapi32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool CryptAcquireContext(ref IntPtr hProv, string pszContainer,string pszProvider, uint dwProvType, uint dwFlags);

        //[DllImport("advapi32.dll", SetLastError = true)]
        //public static extern bool CryptGetProvParam(IntPtr hProv,uint dwParam,[MarshalAs(UnmanagedType.LPStr)] StringBuilder pbData,ref uint dwDataLen,uint dwFlags);

        [DllImport("advapi32.dll", SetLastError=true)]
        public static extern bool CryptGetProvParam(IntPtr hProv,uint dwParam,[In, Out] byte[] pbData,ref uint dwDataLen,uint dwFlags);

        #endregion

    }
}
