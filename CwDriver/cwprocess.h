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
// * cwprocess.h 
//
// * ChangeLog
// 
// * 7/18/2009 - AL - first version.
//
//////////////////////////////////////////////////////////////////////////////
#ifndef __CWPROCESS_h__
#define __CWPROCESS_h__

#include "ntundoc.h"

#define CW_DRIVER_PROCLISTING_TYPE_ZWQ 0x00
#define CW_DRIVER_PROCLISTING_TYPE_PSP 0x01

typedef struct _CW_PROCESS_ENTRY 
{
	ULONG NextEntryOffset; 
	ULONG NumberOfThreads; 
	LARGE_INTEGER CreateTime; 
	LARGE_INTEGER UserTime; 
	LARGE_INTEGER KernelTime; 
	WCHAR ImageName[256]; 
	KPRIORITY BasePriority; 
	HANDLE UniqueProcessId; 
	HANDLE InheritedFromUniqueProcessId; 
	ULONG HandleCount; 
	ULONG PrivatePageCount; 
	//SYSTEM_THREAD_INFORMATION Threads[1];
} CW_PROCESS_ENTRY, *PCW_PROCESS_ENTRY;

typedef struct _PROCESS_LISTING_ZWQ
{
	int numProcesses;
	CW_PROCESS_ENTRY ProcessList[256];
} PROCESS_LISTING_ZWQ, *PPROCESS_LISTING_ZWQ;

//function prototypes
unsigned long __fastcall SizeOfCode(void*, unsigned char**);
NTSTATUS GetProcessListingZwq(__inout PPROCESS_LISTING_ZWQ);
NTSTATUS GetProcessListByPspCidTable(__inout UINT*);
PHANDLE_TABLE GetPspCidTableByScanning();
PHANDLE_TABLE GetPspCidTableByOffsets();


#define OP_NONE           0x00
#define OP_MODRM          0x01
#define OP_DATA_I8        0x02
#define OP_DATA_I16       0x04
#define OP_DATA_I32       0x08
#define OP_DATA_PRE66_67  0x10
#define OP_WORD           0x20
#define OP_REL32          0x40
 

#endif
