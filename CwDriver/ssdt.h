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
// * ssdt.h 
//
// * ChangeLog
// 
// * 7/3/2009 - AL - forked from kgsp project
// * 3/19/2009 - AL - first version.
//
//////////////////////////////////////////////////////////////////////////////

#ifndef __SSDT_h__
#define __SSDT_h__


//----------------------------------------------------------
//					TYPEDEFs
//----------------------------------------------------------
typedef struct __DescriptorEntry 
{
	void** KiServiceTable;			// Base address of the SSDT
	unsigned long ServiceCounterTableBase;		// counter base addr
	unsigned long NumberOfServices;			// Number of services described by ServiceTableBase
	unsigned char* ServiceParameterTableBase;	// Base address of the table containing the number of parameter bytes for each of the system services
} DescriptorEntry, *pDescriptorEntry;

//SSDT table structure
typedef struct __KeServiceDescriptorTable 
{
	DescriptorEntry ntoskrnl;	// Entry for ntoskrnl.exe
	DescriptorEntry win32k;		// Entry for win32k.sys
	DescriptorEntry unused1;		// Unused
	DescriptorEntry unused2;		// Unused
} _KeServiceDescriptorTable, *p_KeServiceDescriptorTable;

//custom structure to hold info about a hooked ssdt service routine
typedef struct _HOOKED_SSDT_ENTRY
{
	int ServiceIndex;
	ULONG ServiceFunctionAddress;
	CHAR ServiceFunctionNameExpected[256];
	CHAR ServiceFunctionNameFound[256];
	CHAR ContainingModule[256];
} HOOKED_SSDT_ENTRY,*PHOOKED_SSDT_ENTRY;

//custom structure to hold a copy of the SSDT table with hooked info
typedef struct _HOOKED_SSDT_TABLE
{
	int NumHookedEntries;
	HOOKED_SSDT_ENTRY HookedEntries[256];
} HOOKED_SSDT_TABLE,*PHOOKED_SSDT_TABLE;

//custom structure to hold info about a detoured ssdt service routine
typedef struct _DETOURED_SSDT_ENTRY
{
	int ServiceIndex;
	ULONG ServiceFunctionAddress;
	CHAR ServiceFunctionNameExpected[256];
	CHAR ServiceFunctionNameFound[256];
	ULONG TargetAddress;
	CHAR Disassembly[25][256];
	CHAR ContainingModule[256];
} DETOURED_SSDT_ENTRY,*PDETOURED_SSDT_ENTRY;

//custom structure to hold a copy of the SSDT table with detoured info
typedef struct _DETOURED_SSDT_TABLE
{
	int NumDetouredEntries;
	DETOURED_SSDT_ENTRY DetouredEntries[256];
} DETOURED_SSDT_TABLE,*PDETOURED_SSDT_TABLE;

//used to get SSDT address
__declspec(dllimport) _KeServiceDescriptorTable KeServiceDescriptorTable;

//----------------------------------------------------------
//					FUNCTION PROTOTYPES
//----------------------------------------------------------
NTSTATUS GetSSDTHooks(__inout PHOOKED_SSDT_TABLE pHookTable);
NTSTATUS GetSSDTDetours(__inout PDETOURED_SSDT_TABLE pDetourTable);
PCHAR GetKGServiceFunctionName(__in UINT);

#endif

