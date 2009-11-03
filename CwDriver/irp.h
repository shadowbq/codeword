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
// * irp.h 
//
// * ChangeLog
// 
// * 7/3/2009 - AL - forked from kgsp project
// * 3/19/2009 - AL - first version.
//
//////////////////////////////////////////////////////////////////////////////
#ifndef __IRP_h__
#define __IRP_h__

//custom structure to hold info about MIGBOT detection
typedef struct _DETOURED_DISPATCH_FUNCTION_ENTRY
{
	ULONG DispatchFunctionAddress;
	CHAR DispatchFunctionName[256];
	CHAR Disassembly[25][256];
	CHAR DetouringModule[256];
	ULONG TargetAddress;
	BOOL IsDetoured;
	BOOL IsUnknown;
} DETOURED_DISPATCH_FUNCTION_ENTRY,*PDETOURED_DISPATCH_FUNCTION_ENTRY;

//table structure to hold a range of detour structures
typedef struct _DETOURED_DISPATCH_FUNCTIONS_TABLE
{
	BOOL isDetoured;
	int NumDetours;
	UNICODE_STRING DriverName;
	UNICODE_STRING DriverDeviceName;
	DETOURED_DISPATCH_FUNCTION_ENTRY DetouredEntries[512];
} DETOURED_DISPATCH_FUNCTIONS_TABLE,*PDETOURED_DISPATCH_FUNCTIONS_TABLE;

//custom structure to hold info about a hooked IRP handling dispatch routine
typedef struct _HOOKED_DISPATCH_FUNCTION_ENTRY
{
	int IrpMajorFunctionHooked;
	ULONG DispatchFunctionAddress;
	CHAR DispatchFunctionName[256];
	CHAR ContainingModule[256];
} HOOKED_DISPATCH_FUNCTION_ENTRY,*PHOOKED_DISPATCH_FUNCTION_ENTRY;

//custom structure to hold a copy of the hooked info
typedef struct _HOOKED_DISPATCH_FUNCTIONS_TABLE
{
	int NumHookedEntries;
	BOOL isHooked;
	UNICODE_STRING DriverName;
	UNICODE_STRING DriverDeviceName;
	HOOKED_DISPATCH_FUNCTION_ENTRY HookedEntries[256];
} HOOKED_DISPATCH_FUNCTIONS_TABLE,*PHOOKED_DISPATCH_FUNCTIONS_TABLE;

//structure that must be passed from user mode to CheckDriver()
typedef struct _DRIVER_CHECK_INFO
{
	UNICODE_STRING DriverName;
	UNICODE_STRING DriverDeviceName;
} DRIVER_CHECK_INFO, *PDRIVER_CHECK_INFO;

//function prototypes.
BOOL GetIrpTableHooksAndDetours(__in PUNICODE_STRING, 
								__in PUNICODE_STRING, 
								__in ULONG, 
								__in ULONG, 
								__inout PHOOKED_DISPATCH_FUNCTIONS_TABLE, 
								__inout PDETOURED_DISPATCH_FUNCTIONS_TABLE);

NTSTATUS CheckDriver(__in PUNICODE_STRING,
					 __in PUNICODE_STRING,
					 __inout PHOOKED_DISPATCH_FUNCTIONS_TABLE,
					 __inout PDETOURED_DISPATCH_FUNCTIONS_TABLE);

#endif