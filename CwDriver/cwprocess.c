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
// * cwprocess.c 
//
// * ChangeLog
// 
// * 7/18/2009 - AL - first version.
//
//////////////////////////////////////////////////////////////////////////////
#include <stdio.h>
#include <string.h>
#include "ntddk.h"
#include "main.h"
#include "ntundoc.h"
#include "ssdt.h"
#include "x86.h"
#include "module.h"
#include "cwprocess.h"
#include <ntstrsafe.h>

/////////////////////////////////////////////////////
//                                                 //
// GetProcessListingZwq()                          //
//                                                 //
/////////////////////////////////////////////////////
//Description:  Gets a list of running processes on 
//				the system using ZwQuerySystemInformation().
//
//				Warning:  max 256 process entries allowed
//				in return array pProcessListing
//
//Returns:      BOOL
/////////////////////////////////////////////////////
NTSTATUS GetProcessListingZwq(__inout PPROCESS_LISTING_ZWQ pProcessListing)
{
	PSYSTEM_PROCESS_INFORMATION pProcessList;
	ULONG bufsize=0;
	PULONG returnLength=0;
	NTSTATUS nt;
	UNICODE_STRING UnknownName;
	int i=0,numProcs=0;

	RtlInitUnicodeString(&UnknownName,L"[unknown]");

	//0 buffer size is returned on failure
	bufsize=GetInformationClassSize(SystemProcessInformation);
	if (bufsize == 0)
		return STATUS_UNSUCCESSFUL;

	//loop through list of loaded drivers
	pProcessList=ExAllocatePoolWithTag(NonPagedPool,bufsize,CW_TAG);

	//oops, out of memory...
	if (pProcessList == NULL)
	{
		DbgPrint("GetProcessListing():  Out of memory.\n");
		return STATUS_UNSUCCESSFUL;
	}

	nt=ZwQuerySystemInformation(SystemProcessInformation,pProcessList,bufsize,returnLength);

	if (nt != STATUS_SUCCESS || pProcessList == NULL)
	{
		DbgPrint("GetProcessListing():  ZwQuerySystemInformation() failed.\n");
		if (pProcessList != NULL)
			ExFreePoolWithTag(pProcessList,CW_TAG);
		return STATUS_UNSUCCESSFUL;
	}

	DbgPrint("%s","GetProcessListingZwq():  Active processes:");

	//loop through the process list manually
	while(1)
	{			
		//copy the fields we care about into our custom CW_PROCESS_LISTING structure
		pProcessListing->ProcessList[numProcs].BasePriority = pProcessList->BasePriority;
		pProcessListing->ProcessList[numProcs].CreateTime = pProcessList->CreateTime;
		pProcessListing->ProcessList[numProcs].HandleCount = pProcessList->HandleCount;
		if (pProcessList->ImageName.Buffer == NULL)
			RtlStringCchCopyExW(pProcessListing->ProcessList[numProcs].ImageName,256,L"[unknown]",NULL,NULL,0);
		else
			RtlStringCchCopyExW(pProcessListing->ProcessList[numProcs].ImageName,256,pProcessList->ImageName.Buffer,NULL,NULL,0);
		pProcessListing->ProcessList[numProcs].InheritedFromUniqueProcessId = pProcessList->InheritedFromUniqueProcessId;
		pProcessListing->ProcessList[numProcs].KernelTime = pProcessList->KernelTime;
		pProcessListing->ProcessList[numProcs].NextEntryOffset = pProcessList->NextEntryOffset;
		pProcessListing->ProcessList[numProcs].NumberOfThreads = pProcessList->NumberOfThreads;
		pProcessListing->ProcessList[numProcs].PrivatePageCount = pProcessList->PrivatePageCount;
		//RtlCopyMemory(pProcessListing->ProcessList[numProcs].Threads,pProcessList->Threads,sizeof(SYSTEM_THREAD_INFORMATION));
		pProcessListing->ProcessList[numProcs].UniqueProcessId = pProcessList->UniqueProcessId;
		pProcessListing->ProcessList[numProcs].UserTime = pProcessList->UserTime;

		DbgPrint("   %i   %S",pProcessListing->ProcessList[numProcs].UniqueProcessId,pProcessListing->ProcessList[numProcs].ImageName);

		//there are no more processes in the list, break.
		if (pProcessListing->ProcessList[numProcs].NextEntryOffset == 0)
			break;
		//we have reached our static max of 256 processes (wow..)
		if (numProcs > 256)
			break;

		//advance to the next entry in the process list
		pProcessList = (PSYSTEM_PROCESS_INFORMATION)(((ULONG)pProcessList)+ pProcessList->NextEntryOffset);
		numProcs++;
	}

	pProcessListing->numProcesses=numProcs;

	return STATUS_SUCCESS;
}

/////////////////////////////////////////////////////
//                                                 //
// GetProcessListByPspCidTable()                   //
//                                                 //
/////////////////////////////////////////////////////
//Description:  Gets a list of running processes on 
//				the system using PspCidTable.
//
//				Warning:  max 256 process entries allowed
//				in return array "pids"
//
//Returns:      BOOL
//
//Reference:	http://uninformed.org/?v=3&a=7&t=txt
/////////////////////////////////////////////////////
NTSTATUS GetProcessListByPspCidTable(UINT* pids)
{
	PHANDLE_TABLE PspCidTable;
	PHANDLE_TABLE ptr;
	int i=0;

	__try
	{
		PspCidTable=GetPspCidTableByScanning();
	}
	__except(1)
	{
		DbgPrint("%s","GetProcessListByPspCidTable():  Caught exception trying to call GetPspCidTableByScanning().");
		return STATUS_UNSUCCESSFUL;
	}

	if (PspCidTable == NULL)
	{
		DbgPrint("%s","GetProcessListByPspCidTable():  GetPspCidTableByScanning() returned a NULL value for PspCidTable.");
		return STATUS_UNSUCCESSFUL;
	}

	DbgPrint("GetProcessListByPspCidTable():  PspCidTable = 0x%08x",PspCidTable);

	ptr=PspCidTable;

	//loop over PspCidTable
	while(ptr != NULL)
	{
		if (i>256)
			break;
		pids[i]=(UINT)ptr->UniqueProcessId;
		ptr=ptr->HandleTableList.Flink;
		i++;
	}

	return STATUS_SUCCESS;
}

/////////////////////////////////////////////////////
//                                                 //
// GetPspCidTableByScanning()                       //
//                                                 //
/////////////////////////////////////////////////////
//Description:  Finds PspCidTable by disassembling the
//				function prologue for PsLookupProcessbyProcessId
//
//Returns:      PHANDLE_TABLE
/////////////////////////////////////////////////////
PHANDLE_TABLE GetPspCidTableByScanning()
{
	PUCHAR cPtr, pOpcode;
	ULONG Length=0;
	PHANDLE_TABLE PspCidTable;

	DbgPrint("GetPspCidTableByScanning():  PsLookupProcessByProcessId = 0x%08x",(PULONG)PsLookupProcessByProcessId);

	//scan for PspCidTable CALL instruction in the prologue of PsLookupProcessByProcessId
	for (cPtr = (PUCHAR)PsLookupProcessByProcessId; 
	     cPtr < (PUCHAR)PsLookupProcessByProcessId + 4096; 
		 cPtr += Length)
	{
		Length = SizeOfCode(cPtr, &pOpcode);

		if (!Length) break;

		if (*(PUSHORT)cPtr == 0x35FF && *(pOpcode + 6) == 0xE8) 
		{
			DbgPrint("GetPspCidTableByScanning():  Found a JMP/CALL target at 0x%08x",pOpcode);
			PspCidTable = **(PVOID **)(pOpcode + 2);
			return PspCidTable;
		}
	}

	DbgPrint("%s","GetPspCidTableByScanning():  Failed to locate PspCidTable.");

	return NULL;
}

/////////////////////////////////////////////////////
//                                                 //
// GetPspCidTableByOffsets()                       //
//                                                 //
/////////////////////////////////////////////////////
//Description:  Finds PspCidTable using offsets as 
//				described in many documented sources.
//
//Returns:      PHANDLE_TABLE
/////////////////////////////////////////////////////
PHANDLE_TABLE GetPspCidTableByOffsets()
{
	ULONG pKPCR;
	PULONG pKdVersionBlock;
	ULONG DBGKD_GET_VERSION64;
	PLIST_ENTRY pKDDEBUGGER_DATA64;
	PULONG KDDEBUGGER_DATA64;
	PULONG pPspCidTable;
	PHANDLE_TABLE PspCidTable;
	PHANDLE_TABLE tableHead;
	int i=0;

	__try
	{
		pKPCR = (ULONG)0xffdff000;
		DbgPrint("GetProcessListByPspCidTable():  KPCR = 0x%08x",pKPCR);
		pKdVersionBlock = pKPCR+0x34;
		DbgPrint("GetProcessListByPspCidTable():  KdVersionBlock = 0x%08x",pKdVersionBlock);
		DBGKD_GET_VERSION64 = *pKdVersionBlock;
		DbgPrint("GetProcessListByPspCidTable():  DBGKD_GET_VERSION64 = 0x%08x",DBGKD_GET_VERSION64);
		pKDDEBUGGER_DATA64 = (PLIST_ENTRY)DBGKD_GET_VERSION64+0x20;
		DbgPrint("GetProcessListByPspCidTable():  pKDDEBUGGER_DATA64 = 0x%08x",pKDDEBUGGER_DATA64);
		KDDEBUGGER_DATA64 = pKDDEBUGGER_DATA64->Flink; //Flink & Blink contain the real address
		DbgPrint("GetProcessListByPspCidTable():  KDDEBUGGER_DATA64 = 0x%08x",KDDEBUGGER_DATA64);
		pPspCidTable = KDDEBUGGER_DATA64+0x58; //PspCidTable stored at offset 0x58
		PspCidTable = (PHANDLE_TABLE)(*pPspCidTable);
		DbgPrint("GetProcessListByPspCidTable():  PspCidTable = 0x%08x",PspCidTable);
		
		return PspCidTable;
	}
	__except(1)
	{
		return NULL;
	}
}



UCHAR OpcodeFlags[256] = 
{
	OP_MODRM,                      // 00
    OP_MODRM,                      // 01
    OP_MODRM,                      // 02
    OP_MODRM,                      // 03
    OP_DATA_I8,                    // 04
    OP_DATA_PRE66_67,              // 05
    OP_NONE,                       // 06
    OP_NONE,                       // 07
    OP_MODRM,                      // 08
    OP_MODRM,                      // 09
    OP_MODRM,                      // 0A
    OP_MODRM,                      // 0B
    OP_DATA_I8,                    // 0C
    OP_DATA_PRE66_67,              // 0D
    OP_NONE,                       // 0E
    OP_NONE,                       // 0F
    OP_MODRM,                      // 10
    OP_MODRM,                      // 11
    OP_MODRM,                      // 12
    OP_MODRM,                      // 13
    OP_DATA_I8,                    // 14
    OP_DATA_PRE66_67,              // 15
    OP_NONE,                       // 16
    OP_NONE,                       // 17
    OP_MODRM,                      // 18
    OP_MODRM,                      // 19
    OP_MODRM,                      // 1A
    OP_MODRM,                      // 1B
    OP_DATA_I8,                    // 1C
    OP_DATA_PRE66_67,              // 1D
    OP_NONE,                       // 1E
    OP_NONE,                       // 1F
    OP_MODRM,                      // 20
    OP_MODRM,                      // 21
    OP_MODRM,                      // 22
    OP_MODRM,                      // 23
    OP_DATA_I8,                    // 24
    OP_DATA_PRE66_67,              // 25
    OP_NONE,                       // 26
    OP_NONE,                       // 27
    OP_MODRM,                      // 28
    OP_MODRM,                      // 29
    OP_MODRM,                      // 2A
    OP_MODRM,                      // 2B
    OP_DATA_I8,                    // 2C
    OP_DATA_PRE66_67,              // 2D
    OP_NONE,                       // 2E
    OP_NONE,                       // 2F
    OP_MODRM,                      // 30
    OP_MODRM,                      // 31
    OP_MODRM,                      // 32
    OP_MODRM,                      // 33
    OP_DATA_I8,                    // 34
    OP_DATA_PRE66_67,              // 35
    OP_NONE,                       // 36
    OP_NONE,                       // 37
    OP_MODRM,                      // 38
    OP_MODRM,                      // 39
    OP_MODRM,                      // 3A
    OP_MODRM,                      // 3B
    OP_DATA_I8,                    // 3C
    OP_DATA_PRE66_67,              // 3D
    OP_NONE,                       // 3E
    OP_NONE,                       // 3F
    OP_NONE,                       // 40
    OP_NONE,                       // 41
    OP_NONE,                       // 42
    OP_NONE,                       // 43
    OP_NONE,                       // 44
    OP_NONE,                       // 45
    OP_NONE,                       // 46
    OP_NONE,                       // 47
    OP_NONE,                       // 48
    OP_NONE,                       // 49
    OP_NONE,                       // 4A
    OP_NONE,                       // 4B
    OP_NONE,                       // 4C
    OP_NONE,                       // 4D
    OP_NONE,                       // 4E
    OP_NONE,                       // 4F
    OP_NONE,                       // 50
    OP_NONE,                       // 51
    OP_NONE,                       // 52
    OP_NONE,                       // 53
    OP_NONE,                       // 54
    OP_NONE,                       // 55
    OP_NONE,                       // 56
    OP_NONE,                       // 57
    OP_NONE,                       // 58
    OP_NONE,                       // 59
    OP_NONE,                       // 5A
    OP_NONE,                       // 5B
    OP_NONE,                       // 5C
    OP_NONE,                       // 5D
    OP_NONE,                       // 5E
    OP_NONE,                       // 5F
    OP_NONE,                       // 60
    OP_NONE,                       // 61
    OP_MODRM,                      // 62
    OP_MODRM,                      // 63
    OP_NONE,                       // 64
    OP_NONE,                       // 65
    OP_NONE,                       // 66
    OP_NONE,                       // 67
    OP_DATA_PRE66_67,              // 68
    OP_MODRM | OP_DATA_PRE66_67,   // 69
    OP_DATA_I8,                    // 6A
    OP_MODRM | OP_DATA_I8,         // 6B
    OP_NONE,                       // 6C
    OP_NONE,                       // 6D
    OP_NONE,                       // 6E
    OP_NONE,                       // 6F
    OP_DATA_I8,                    // 70
    OP_DATA_I8,                    // 71
    OP_DATA_I8,                    // 72
    OP_DATA_I8,                    // 73
    OP_DATA_I8,                    // 74
    OP_DATA_I8,                    // 75
    OP_DATA_I8,                    // 76
    OP_DATA_I8,                    // 77
    OP_DATA_I8,                    // 78
    OP_DATA_I8,                    // 79
    OP_DATA_I8,                    // 7A
    OP_DATA_I8,                    // 7B
    OP_DATA_I8,                    // 7C
    OP_DATA_I8,                    // 7D
    OP_DATA_I8,                    // 7E
    OP_DATA_I8,                    // 7F
    OP_MODRM | OP_DATA_I8,         // 80
    OP_MODRM | OP_DATA_PRE66_67,   // 81
    OP_MODRM | OP_DATA_I8,         // 82
    OP_MODRM | OP_DATA_I8,         // 83
    OP_MODRM,                      // 84
    OP_MODRM,                      // 85
    OP_MODRM,                      // 86
    OP_MODRM,                      // 87
    OP_MODRM,                      // 88
    OP_MODRM,                      // 89
    OP_MODRM,                      // 8A
    OP_MODRM,                      // 8B
    OP_MODRM,                      // 8C
    OP_MODRM,                      // 8D
    OP_MODRM,                      // 8E
    OP_MODRM,                      // 8F
    OP_NONE,                       // 90
    OP_NONE,                       // 91
    OP_NONE,                       // 92
    OP_NONE,                       // 93
    OP_NONE,                       // 94
    OP_NONE,                       // 95
    OP_NONE,                       // 96
    OP_NONE,                       // 97
    OP_NONE,                       // 98
    OP_NONE,                       // 99
    OP_DATA_I16 | OP_DATA_PRE66_67,// 9A
    OP_NONE,                       // 9B
    OP_NONE,                       // 9C
    OP_NONE,                       // 9D
    OP_NONE,                       // 9E
    OP_NONE,                       // 9F
    OP_DATA_PRE66_67,              // A0
    OP_DATA_PRE66_67,              // A1
    OP_DATA_PRE66_67,              // A2
    OP_DATA_PRE66_67,              // A3
    OP_NONE,                       // A4
    OP_NONE,                       // A5
    OP_NONE,                       // A6
    OP_NONE,                       // A7
    OP_DATA_I8,                    // A8
    OP_DATA_PRE66_67,              // A9
    OP_NONE,                       // AA
    OP_NONE,                       // AB
    OP_NONE,                       // AC
    OP_NONE,                       // AD
    OP_NONE,                       // AE
    OP_NONE,                       // AF
    OP_DATA_I8,                    // B0
    OP_DATA_I8,                    // B1
    OP_DATA_I8,                    // B2
    OP_DATA_I8,                    // B3
    OP_DATA_I8,                    // B4
    OP_DATA_I8,                    // B5
    OP_DATA_I8,                    // B6
    OP_DATA_I8,                    // B7
    OP_DATA_PRE66_67,              // B8
    OP_DATA_PRE66_67,              // B9
    OP_DATA_PRE66_67,              // BA
    OP_DATA_PRE66_67,              // BB
    OP_DATA_PRE66_67,              // BC
    OP_DATA_PRE66_67,              // BD
    OP_DATA_PRE66_67,              // BE
    OP_DATA_PRE66_67,              // BF
    OP_MODRM | OP_DATA_I8,         // C0
    OP_MODRM | OP_DATA_I8,         // C1
    OP_DATA_I16,                   // C2
    OP_NONE,                       // C3
    OP_MODRM,                      // C4
    OP_MODRM,                      // C5
    OP_MODRM   | OP_DATA_I8,       // C6
    OP_MODRM   | OP_DATA_PRE66_67, // C7
    OP_DATA_I8 | OP_DATA_I16,      // C8
    OP_NONE,                       // C9
    OP_DATA_I16,                   // CA
    OP_NONE,                       // CB
    OP_NONE,                       // CC
    OP_DATA_I8,                    // CD
    OP_NONE,                       // CE
    OP_NONE,                       // CF
    OP_MODRM,                      // D0
    OP_MODRM,                      // D1
    OP_MODRM,                      // D2
    OP_MODRM,                      // D3
    OP_DATA_I8,                    // D4
    OP_DATA_I8,                    // D5
    OP_NONE,                       // D6
    OP_NONE,                       // D7
    OP_WORD,                       // D8
    OP_WORD,                       // D9
    OP_WORD,                       // DA
    OP_WORD,                       // DB
    OP_WORD,                       // DC
    OP_WORD,                       // DD
    OP_WORD,                       // DE
    OP_WORD,                       // DF
    OP_DATA_I8,                    // E0
    OP_DATA_I8,                    // E1
    OP_DATA_I8,                    // E2
    OP_DATA_I8,                    // E3
    OP_DATA_I8,                    // E4
    OP_DATA_I8,                    // E5
    OP_DATA_I8,                    // E6
    OP_DATA_I8,                    // E7
    OP_DATA_PRE66_67 | OP_REL32,   // E8
    OP_DATA_PRE66_67 | OP_REL32,   // E9
    OP_DATA_I16 | OP_DATA_PRE66_67,// EA
    OP_DATA_I8,                    // EB
    OP_NONE,                       // EC
    OP_NONE,                       // ED
    OP_NONE,                       // EE
    OP_NONE,                       // EF
    OP_NONE,                       // F0
    OP_NONE,                       // F1
    OP_NONE,                       // F2
    OP_NONE,                       // F3
    OP_NONE,                       // F4
    OP_NONE,                       // F5
    OP_MODRM,                      // F6
    OP_MODRM,                      // F7
    OP_NONE,                       // F8
    OP_NONE,                       // F9
    OP_NONE,                       // FA
    OP_NONE,                       // FB
    OP_NONE,                       // FC
    OP_NONE,                       // FD
    OP_MODRM,                      // FE
    OP_MODRM | OP_REL32            // FF
};

UCHAR OpcodeFlagsExt[256] =
{
    OP_MODRM,                      // 00
    OP_MODRM,                      // 01
    OP_MODRM,                      // 02
    OP_MODRM,                      // 03
    OP_NONE,                       // 04
    OP_NONE,                       // 05
    OP_NONE,                       // 06
    OP_NONE,                       // 07
    OP_NONE,                       // 08
    OP_NONE,                       // 09
    OP_NONE,                       // 0A
    OP_NONE,                       // 0B
    OP_NONE,                       // 0C
    OP_MODRM,                      // 0D
    OP_NONE,                       // 0E
    OP_MODRM | OP_DATA_I8,         // 0F
    OP_MODRM,                      // 10
    OP_MODRM,                      // 11
    OP_MODRM,                      // 12
    OP_MODRM,                      // 13
    OP_MODRM,                      // 14
    OP_MODRM,                      // 15
    OP_MODRM,                      // 16
    OP_MODRM,                      // 17
    OP_MODRM,                      // 18
    OP_NONE,                       // 19
    OP_NONE,                       // 1A
    OP_NONE,                       // 1B
    OP_NONE,                       // 1C
    OP_NONE,                       // 1D
    OP_NONE,                       // 1E
    OP_NONE,                       // 1F
    OP_MODRM,                      // 20
    OP_MODRM,                      // 21
    OP_MODRM,                      // 22
    OP_MODRM,                      // 23
    OP_MODRM,                      // 24
    OP_NONE,                       // 25
    OP_MODRM,                      // 26
    OP_NONE,                       // 27
    OP_MODRM,                      // 28
    OP_MODRM,                      // 29
    OP_MODRM,                      // 2A
    OP_MODRM,                      // 2B
    OP_MODRM,                      // 2C
    OP_MODRM,                      // 2D
    OP_MODRM,                      // 2E
    OP_MODRM,                      // 2F
    OP_NONE,                       // 30
    OP_NONE,                       // 31
    OP_NONE,                       // 32
    OP_NONE,                       // 33
    OP_NONE,                       // 34
    OP_NONE,                       // 35
    OP_NONE,                       // 36
    OP_NONE,                       // 37
    OP_NONE,                       // 38
    OP_NONE,                       // 39
    OP_NONE,                       // 3A
    OP_NONE,                       // 3B
    OP_NONE,                       // 3C
    OP_NONE,                       // 3D
    OP_NONE,                       // 3E
    OP_NONE,                       // 3F
    OP_MODRM,                      // 40
    OP_MODRM,                      // 41
    OP_MODRM,                      // 42
    OP_MODRM,                      // 43
    OP_MODRM,                      // 44
    OP_MODRM,                      // 45
    OP_MODRM,                      // 46
    OP_MODRM,                      // 47
    OP_MODRM,                      // 48
    OP_MODRM,                      // 49
    OP_MODRM,                      // 4A
    OP_MODRM,                      // 4B
    OP_MODRM,                      // 4C
    OP_MODRM,                      // 4D
    OP_MODRM,                      // 4E
    OP_MODRM,                      // 4F
    OP_MODRM,                      // 50
    OP_MODRM,                      // 51
    OP_MODRM,                      // 52
    OP_MODRM,                      // 53
    OP_MODRM,                      // 54
    OP_MODRM,                      // 55
    OP_MODRM,                      // 56
    OP_MODRM,                      // 57
    OP_MODRM,                      // 58
    OP_MODRM,                      // 59
    OP_MODRM,                      // 5A
    OP_MODRM,                      // 5B
    OP_MODRM,                      // 5C
    OP_MODRM,                      // 5D
    OP_MODRM,                      // 5E
    OP_MODRM,                      // 5F
    OP_MODRM,                      // 60
    OP_MODRM,                      // 61
    OP_MODRM,                      // 62
    OP_MODRM,                      // 63
    OP_MODRM,                      // 64
    OP_MODRM,                      // 65
    OP_MODRM,                      // 66
    OP_MODRM,                      // 67
    OP_MODRM,                      // 68
    OP_MODRM,                      // 69
    OP_MODRM,                      // 6A
    OP_MODRM,                      // 6B
    OP_MODRM,                      // 6C
    OP_MODRM,                      // 6D
    OP_MODRM,                      // 6E
    OP_MODRM,                      // 6F
    OP_MODRM | OP_DATA_I8,         // 70
    OP_MODRM | OP_DATA_I8,         // 71
    OP_MODRM | OP_DATA_I8,         // 72
    OP_MODRM | OP_DATA_I8,         // 73
    OP_MODRM,                      // 74
    OP_MODRM,                      // 75
    OP_MODRM,                      // 76
    OP_NONE,                       // 77
    OP_NONE,                       // 78
    OP_NONE,                       // 79
    OP_NONE,                       // 7A
    OP_NONE,                       // 7B
    OP_MODRM,                      // 7C
    OP_MODRM,                      // 7D
    OP_MODRM,                      // 7E
    OP_MODRM,                      // 7F
    OP_DATA_PRE66_67 | OP_REL32,   // 80
    OP_DATA_PRE66_67 | OP_REL32,   // 81
    OP_DATA_PRE66_67 | OP_REL32,   // 82
    OP_DATA_PRE66_67 | OP_REL32,   // 83
    OP_DATA_PRE66_67 | OP_REL32,   // 84
    OP_DATA_PRE66_67 | OP_REL32,   // 85
    OP_DATA_PRE66_67 | OP_REL32,   // 86
    OP_DATA_PRE66_67 | OP_REL32,   // 87
    OP_DATA_PRE66_67 | OP_REL32,   // 88
    OP_DATA_PRE66_67 | OP_REL32,   // 89
    OP_DATA_PRE66_67 | OP_REL32,   // 8A
    OP_DATA_PRE66_67 | OP_REL32,   // 8B
    OP_DATA_PRE66_67 | OP_REL32,   // 8C
    OP_DATA_PRE66_67 | OP_REL32,   // 8D
    OP_DATA_PRE66_67 | OP_REL32,   // 8E
    OP_DATA_PRE66_67 | OP_REL32,   // 8F
    OP_MODRM,                      // 90
    OP_MODRM,                      // 91
    OP_MODRM,                      // 92
    OP_MODRM,                      // 93
    OP_MODRM,                      // 94
    OP_MODRM,                      // 95
    OP_MODRM,                      // 96
    OP_MODRM,                      // 97
    OP_MODRM,                      // 98
    OP_MODRM,                      // 99
    OP_MODRM,                      // 9A
    OP_MODRM,                      // 9B
    OP_MODRM,                      // 9C
    OP_MODRM,                      // 9D
    OP_MODRM,                      // 9E
    OP_MODRM,                      // 9F
    OP_NONE,                       // A0
    OP_NONE,                       // A1
    OP_NONE,                       // A2
    OP_MODRM,                      // A3
    OP_MODRM | OP_DATA_I8,         // A4
    OP_MODRM,                      // A5
    OP_NONE,                       // A6
    OP_NONE,                       // A7
    OP_NONE,                       // A8
    OP_NONE,                       // A9
    OP_NONE,                       // AA
    OP_MODRM,                      // AB
    OP_MODRM | OP_DATA_I8,         // AC
    OP_MODRM,                      // AD
    OP_MODRM,                      // AE
    OP_MODRM,                      // AF
    OP_MODRM,                      // B0
    OP_MODRM,                      // B1
    OP_MODRM,                      // B2
    OP_MODRM,                      // B3
    OP_MODRM,                      // B4
    OP_MODRM,                      // B5
    OP_MODRM,                      // B6
    OP_MODRM,                      // B7
    OP_NONE,                       // B8
    OP_NONE,                       // B9
    OP_MODRM | OP_DATA_I8,         // BA
    OP_MODRM,                      // BB
    OP_MODRM,                      // BC
    OP_MODRM,                      // BD
    OP_MODRM,                      // BE
    OP_MODRM,                      // BF
    OP_MODRM,                      // C0
    OP_MODRM,                      // C1
    OP_MODRM | OP_DATA_I8,         // C2
    OP_MODRM,                      // C3
    OP_MODRM | OP_DATA_I8,         // C4
    OP_MODRM | OP_DATA_I8,         // C5
    OP_MODRM | OP_DATA_I8,         // C6 
    OP_MODRM,                      // C7
    OP_NONE,                       // C8
    OP_NONE,                       // C9
    OP_NONE,                       // CA
    OP_NONE,                       // CB
    OP_NONE,                       // CC
    OP_NONE,                       // CD
    OP_NONE,                       // CE
    OP_NONE,                       // CF
    OP_MODRM,                      // D0
    OP_MODRM,                      // D1
    OP_MODRM,                      // D2
    OP_MODRM,                      // D3
    OP_MODRM,                      // D4
    OP_MODRM,                      // D5
    OP_MODRM,                      // D6
    OP_MODRM,                      // D7
    OP_MODRM,                      // D8
    OP_MODRM,                      // D9
    OP_MODRM,                      // DA
    OP_MODRM,                      // DB
    OP_MODRM,                      // DC
    OP_MODRM,                      // DD
    OP_MODRM,                      // DE
    OP_MODRM,                      // DF
    OP_MODRM,                      // E0
    OP_MODRM,                      // E1
    OP_MODRM,                      // E2
    OP_MODRM,                      // E3
    OP_MODRM,                      // E4
    OP_MODRM,                      // E5
    OP_MODRM,                      // E6
    OP_MODRM,                      // E7
    OP_MODRM,                      // E8
    OP_MODRM,                      // E9
    OP_MODRM,                      // EA
    OP_MODRM,                      // EB
    OP_MODRM,                      // EC
    OP_MODRM,                      // ED
    OP_MODRM,                      // EE
    OP_MODRM,                      // EF
    OP_MODRM,                      // F0
    OP_MODRM,                      // F1
    OP_MODRM,                      // F2
    OP_MODRM,                      // F3
    OP_MODRM,                      // F4
    OP_MODRM,                      // F5
    OP_MODRM,                      // F6
    OP_MODRM,                      // F7 
    OP_MODRM,                      // F8
    OP_MODRM,                      // F9
    OP_MODRM,                      // FA
    OP_MODRM,                      // FB
    OP_MODRM,                      // FC
    OP_MODRM,                      // FD
    OP_MODRM,                      // FE
    OP_NONE                        // FF
};

unsigned long __fastcall SizeOfCode(void *Code, unsigned char **pOpcode)
{
	PUCHAR cPtr;
	UCHAR Flags;
	BOOLEAN PFX66, PFX67;
	BOOLEAN SibPresent;
	UCHAR iMod, iRM, iReg;
	UCHAR OffsetSize, Add;
	UCHAR Opcode;

	OffsetSize = 0;
	PFX66 = FALSE;
	PFX67 = FALSE;
	cPtr = (PUCHAR)Code;
	while ( (*cPtr == 0x2E) || (*cPtr == 0x3E) || (*cPtr == 0x36) ||
		    (*cPtr == 0x26) || (*cPtr == 0x64) || (*cPtr == 0x65) || 
			(*cPtr == 0xF0) || (*cPtr == 0xF2) || (*cPtr == 0xF3) ||
			(*cPtr == 0x66) || (*cPtr == 0x67) ) 
	{
		if (*cPtr == 0x66) PFX66 = TRUE;
		if (*cPtr == 0x67) PFX67 = TRUE;
		cPtr++;
		if (cPtr > (PUCHAR)Code + 16) return 0; 
	}
	Opcode = *cPtr;
	if (pOpcode) *pOpcode = cPtr; 
	if (*cPtr == 0x0F)
	{
		cPtr++;
		Flags = OpcodeFlagsExt[*cPtr];
	} else 
	{
		Flags = OpcodeFlags[Opcode];
		if (Opcode >= 0xA0 && Opcode <= 0xA3) PFX66 = PFX67;
	}
	cPtr++;
	if (Flags & OP_WORD) cPtr++;	
	if (Flags & OP_MODRM)
	{
		iMod = *cPtr >> 6;
		iReg = (*cPtr & 0x38) >> 3;  
		iRM  = *cPtr &  7;
		cPtr++;
		if ((Opcode == 0xF6) && !iReg) Flags |= OP_DATA_I8;    
		if ((Opcode == 0xF7) && !iReg) Flags |= OP_DATA_PRE66_67; 
		SibPresent = !PFX67 & (iRM == 4);
		switch (iMod)
		{
			case 0: 
			  if ( PFX67 && (iRM == 6)) OffsetSize = 2;
			  if (!PFX67 && (iRM == 5)) OffsetSize = 4; 
			 break;
			case 1: OffsetSize = 1;
			 break; 
			case 2: if (PFX67) OffsetSize = 2; else OffsetSize = 4;
			 break;
			case 3: SibPresent = FALSE;
		}
		if (SibPresent)
		{
			if (((*cPtr & 7) == 5) && ( (!iMod) || (iMod == 2) )) OffsetSize = 4;
			cPtr++;
		}
		cPtr = (PUCHAR)(ULONG)cPtr + OffsetSize;
	}
	if (Flags & OP_DATA_I8)  cPtr++;
	if (Flags & OP_DATA_I16) cPtr += 2;
	if (Flags & OP_DATA_I32) cPtr += 4;
	if (PFX66) Add = 2; else Add = 4;
	if (Flags & OP_DATA_PRE66_67) cPtr += Add;
	return (ULONG)cPtr - (ULONG)Code;
}