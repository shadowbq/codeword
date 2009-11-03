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
//////////////////////////////////////////////////////////////////////////////
// * main.h 
//
// * ChangeLog
// 
// * 7/3/2009 - AL - forked from kgsp project
// * 3/19/2009 - AL - first version.
//
//////////////////////////////////////////////////////////////////////////////

//set to 0 to convert ASSERT()s to NOOP's
#define CW_TAG 'rOwC'

//----------------------------------------------------------
//					TYPEDEFs
//----------------------------------------------------------
typedef unsigned int UINT;
typedef char * PCHAR;
typedef int BOOL;
typedef unsigned short WORD;
typedef unsigned long DWORD;
typedef unsigned char BYTE;
typedef BYTE* PBYTE;

//----------------------------------------------------------
//				FUNCTION PROTOTYPES
//----------------------------------------------------------
DRIVER_UNLOAD CwUnload;//(PDRIVER_OBJECT DriverObject);
DRIVER_INITIALIZE DriverEntry;//(PDRIVER_OBJECT pDriverObject, PUNICODE_STRING pRegistryPath);
DRIVER_DISPATCH CwDispatchHandlerIoControl;//(PDEVICE_OBJECT DeviceObject, PIRP Irp);
DRIVER_DISPATCH CwDispatchHandlerGeneric;//(PDEVICE_OBJECT DeviceObject, PIRP Irp);

//----------------------------------------------------------
//				CODE ALLOC DIRECTIVES
//----------------------------------------------------------
//put these functions in a pageable text section
#pragma alloc_text(PAGE, CwUnload)
//put DriverEntry in a discardable INIT section
#pragma alloc_text(INIT, DriverEntry)

//----------------------------------------------------------
//					DEFINES/CONSTANTS
//----------------------------------------------------------
//IOCTL command codes
//According to MSDN, function codes from 0x800 to 0xFFF are for customer use.
#define CW_DRIVER_SSDT_DETECT_HOOKS 0x801
#define CW_DRIVER_SSDT_DETECT_DETOURS 0x802
#define CW_DRIVER_GDT_DETECT_SUSPICIOUS_SEGMENT_DESCRIPTORS 0x803
#define CW_DRIVER_GDT_GET_CALL_GATES 0x804
#define CW_DRIVER_IDT_DETECT_HOOKS 0x805
#define CW_DRIVER_IDT_DETECT_DETOURS 0x806
#define CW_DRIVER_WIN32API_DETOUR_DETECTION 0x807
#define CW_DRIVER_IRP_HOOK_DETECTION 0x808
#define CW_DRIVER_IRP_DETOUR_DETECTION 0x809
#define CW_DRIVER_PROCESS_LISTING_ZWQ 0x810
#define CW_DRIVER_PROCESS_LISTING_PSP 0x811

//IOCTLs
#define IOCTL_SSDT_DETECT_HOOKS \
    CTL_CODE(FILE_DEVICE_UNKNOWN,CW_DRIVER_SSDT_DETECT_HOOKS,METHOD_OUT_DIRECT,FILE_ANY_ACCESS)
#define IOCTL_SSDT_DETECT_DETOURS \
    CTL_CODE(FILE_DEVICE_UNKNOWN,CW_DRIVER_SSDT_DETECT_DETOURS,METHOD_OUT_DIRECT,FILE_ANY_ACCESS)
#define IOCTL_WIN32API_DETOUR_DETECTION \
    CTL_CODE(FILE_DEVICE_UNKNOWN,CW_DRIVER_WIN32API_DETOUR_DETECTION,METHOD_OUT_DIRECT,FILE_ANY_ACCESS)
#define IOCTL_IRP_HOOK_DETECTION \
    CTL_CODE(FILE_DEVICE_UNKNOWN,CW_DRIVER_IRP_HOOK_DETECTION,METHOD_OUT_DIRECT,FILE_ANY_ACCESS)
#define IOCTL_IRP_DETOUR_DETECTION \
    CTL_CODE(FILE_DEVICE_UNKNOWN,CW_DRIVER_IRP_DETOUR_DETECTION,METHOD_OUT_DIRECT,FILE_ANY_ACCESS)
#define IOCTL_GET_PROCESS_LISTING_ZWQ \
    CTL_CODE(FILE_DEVICE_UNKNOWN,CW_DRIVER_PROCESS_LISTING_ZWQ,METHOD_OUT_DIRECT,FILE_ANY_ACCESS)
#define IOCTL_GET_PROCESS_LISTING_PSP \
    CTL_CODE(FILE_DEVICE_UNKNOWN,CW_DRIVER_PROCESS_LISTING_PSP,METHOD_OUT_DIRECT,FILE_ANY_ACCESS)
//not implemented yet:
#define IOCTL_GDT_DETECT_SUSPICIOUS_SEGMENT_DESCRIPTORS \
    CTL_CODE(FILE_DEVICE_UNKNOWN,CW_DRIVER_GDT_DETECT_SUSPICIOUS_SEGMENT_DESCRIPTORS,METHOD_OUT_DIRECT,FILE_ANY_ACCESS)
#define IOCTL_GDT_GET_CALL_GATES \
    CTL_CODE(FILE_DEVICE_UNKNOWN,CW_DRIVER_GDT_GET_CALL_GATES,METHOD_OUT_DIRECT,FILE_ANY_ACCESS)
#define IOCTL_IDT_DETECT_HOOKS \
    CTL_CODE(FILE_DEVICE_UNKNOWN,CW_DRIVER_IDT_DETECT_HOOKS,METHOD_OUT_DIRECT,FILE_ANY_ACCESS)
#define IOCTL_IDT_DETECT_DETOURS \
    CTL_CODE(FILE_DEVICE_UNKNOWN,CW_DRIVER_IDT_DETECT_DETOURS,METHOD_OUT_DIRECT,FILE_ANY_ACCESS)