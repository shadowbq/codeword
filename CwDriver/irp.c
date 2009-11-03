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
// * irp.c 
//
// * ChangeLog
// 
// * 7/18/2009 - AL - finalized for release
// * 7/3/2009 - AL - forked from kgsp project
// * 3/19/2009 - AL - first version.
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
#include "irp.h"
#include <ntstrsafe.h>
#include <stdlib.h>

PCHAR IRP_MJ_CODES[28]=
{
	"IRP_MJ_CREATE",
	"IRP_MJ_CREATE_NAMED_PIPE",
	"IRP_MJ_CLOSE",
	"IRP_MJ_READ",
	"IRP_MJ_WRITE",
	"IRP_MJ_QUERY_INFORMATION",
	"IRP_MJ_SET_INFORMATION",
	"IRP_MJ_QUERY_EA",
	"IRP_MJ_SET_EA",
	"IRP_MJ_FLUSH_BUFFERS",
	"IRP_MJ_QUERY_VOLUME_INFORMATION",
	"IRP_MJ_SET_VOLUME_INFORMATION",
	"IRP_MJ_DIRECTORY_CONTROL",
	"IRP_MJ_FILE_SYSTEM_CONTROL",
	"IRP_MJ_DEVICE_CONTROL",
	"IRP_MJ_INTERNAL_DEVICE_CONTROL",
	"IRP_MJ_SHUTDOWN",
	"IRP_MJ_LOCK_CONTROL",
	"IRP_MJ_CLEANUP",
	"IRP_MJ_CREATE_MAILSLOT",
	"IRP_MJ_QUERY_SECURITY",
	"IRP_MJ_SET_SECURITY",
	"IRP_MJ_POWER",
	"IRP_MJ_SYSTEM_CONTROL",
	"IRP_MJ_DEVICE_CHANGE",
	"IRP_MJ_QUERY_QUOTA",
	"IRP_MJ_SET_QUOTA",
	"IRP_MJ_PNP"

};

/////////////////////////////////////////////////////
//                                                 //
// CheckDriver()                                   //
//                                                 //
/////////////////////////////////////////////////////
//Description:  Runs hook/detour detection routines
//				on the passed-in driver.
//
//				Note:  pHookTable and pDetourTable are
//				both optional, depending on which test
//				you wish to run.
//
//Returns:      void
/////////////////////////////////////////////////////
NTSTATUS CheckDriver(__in PUNICODE_STRING puDriverName, 
					 __in PUNICODE_STRING puDriverDeviceName, 
					 __inout_opt PHOOKED_DISPATCH_FUNCTIONS_TABLE pHookTable,
					 __inout_opt PDETOURED_DISPATCH_FUNCTIONS_TABLE pDetourTable)
{
	PMODULE_LIST pModuleList;
	ULONG bufsize=0;
	PULONG returnLength=0;
	ULONG modsize=0,modbase=0;
	CHAR ModuleName[256];
	WCHAR wModuleName[256];
	UNICODE_STRING uModuleName;
	ANSI_STRING aModuleName;
	PCHAR nameStart;
	NTSTATUS nt;
	int i;

	//0 buffer size is returned on failure
	bufsize=GetInformationClassSize(SystemModuleInformation);
	if (bufsize == 0)
		return STATUS_UNSUCCESSFUL;

	//loop through list of loaded drivers
	pModuleList=ExAllocatePoolWithTag(NonPagedPool,bufsize,CW_TAG);

	//oops, out of memory...
	if (pModuleList == NULL)
	{
		DbgPrint("CheckDriver():  Out of memory.\n");
		return STATUS_UNSUCCESSFUL;
	}

	nt=ZwQuerySystemInformation(SystemModuleInformation,pModuleList,bufsize,returnLength);

	if (nt != STATUS_SUCCESS)
	{
		DbgPrint("CheckDriver():  ZwQuerySystemInformation() failed.\n");
		if (pModuleList != NULL)
			ExFreePoolWithTag(pModuleList,CW_TAG);
		return STATUS_UNSUCCESSFUL;
	}

	//loop through the module list looking for the driver we are interested in;
	//retrieve it's load address and size.
	for(i=0;i<(long)pModuleList->ModuleCount;i++)
	{
		nameStart=pModuleList->Modules[i].ImageName+pModuleList->Modules[i].ModuleNameOffset;
		memcpy(ModuleName,nameStart,256-pModuleList->Modules[i].ModuleNameOffset);
		//since ZwQuerySystemInformation() returns a CHAR[256] and we need to compare it to a UNICODE_STRING, convert...
		RtlInitAnsiString(&aModuleName,ModuleName);
		RtlAnsiStringToUnicodeString(&uModuleName,&aModuleName,TRUE);

		//if we are on the driver we care about
		if (RtlCompareUnicodeString(&uModuleName,puDriverName,TRUE) == 0)
		{
			modsize=(ULONG)pModuleList->Modules[i].Size;
			modbase=(ULONG)pModuleList->Modules[i].Base;
			//free the tmp unicode string
			if (uModuleName.Buffer != NULL)
				RtlFreeUnicodeString(&uModuleName);
			break;
		}

		//free the tmp unicode string
		if (uModuleName.Buffer != NULL)
			RtlFreeUnicodeString(&uModuleName);
	}

	//bail if we didnt find the driver we were asked to look for.
	if (modsize == 0 || modbase == 0)
	{
		ExFreePoolWithTag(pModuleList,CW_TAG);
		DbgPrint("CheckDriver():  Failed to get this driver's size and base - maybe it's not loaded?\n");
		return STATUS_UNSUCCESSFUL;
	}

	DbgPrint("CheckDriver():  Found driver %wZ loaded at base address 0x%08x",puDriverName,modbase);

	//convert the driver device name to a PCWSTR
	//mbstowcs(uDriverDeviceName,driverDeviceName,256);

	//go ahead and save the driver name and device name in both tables
	if (pHookTable != NULL)
	{
		RtlInitUnicodeString(&pHookTable->DriverName,puDriverName->Buffer);
		RtlInitUnicodeString(&pHookTable->DriverDeviceName,puDriverDeviceName->Buffer);
	}
	if (pDetourTable != NULL)
	{
		//initialize the max length of the dest string
		RtlInitUnicodeString(&pDetourTable->DriverName,puDriverName->Buffer);
		RtlInitUnicodeString(&pDetourTable->DriverDeviceName,puDriverDeviceName->Buffer);
	}

	//----------------
	// ** IRP HOOKS **
	//----------------
	if (!GetIrpTableHooksAndDetours(puDriverName,puDriverDeviceName,modbase,modsize, pHookTable, pDetourTable))
	{
		ExFreePoolWithTag(pModuleList,CW_TAG);
		return STATUS_UNSUCCESSFUL;
	}

	if (pModuleList != NULL)
		ExFreePoolWithTag(pModuleList,CW_TAG);

	return STATUS_SUCCESS;
}

/////////////////////////////////////////////////////
//                                                 //
// GetIrpTableHooksAndDetours()                    //
//                                                 //
/////////////////////////////////////////////////////
//Description:  Scans the IRP table for the passed-in
//				driver and attempts to determine if a
//				dispatch routine is hooked.
//
//Returns:      void
/////////////////////////////////////////////////////
BOOL GetIrpTableHooksAndDetours(PUNICODE_STRING puDriverName, 
								PUNICODE_STRING puDeviceName, 
								ULONG DriverBaseAddress, 
								ULONG DriverSize, 
								PHOOKED_DISPATCH_FUNCTIONS_TABLE pHookTable,
								PDETOURED_DISPATCH_FUNCTIONS_TABLE pDetourTable)
{
	NTSTATUS nt;
	PDRIVER_DISPATCH* pDriverIrpTable;
	PDRIVER_DISPATCH dispatchFunctionAddress;
	CHAR dispatchFunctionName[256];
	PFILE_OBJECT fileObj;
	PDRIVER_OBJECT driverObj;
	PDEVICE_OBJECT deviceObj;
	PSYSTEM_MODULE_INFORMATION pModInfo;
	PCHAR pUnknownBuf="[unknown]";
	CHAR ContainingModule[256];
	BOOL IsHooked=FALSE,IsDetoured=FALSE;
	PDETOURINFO d;
	int i,j;

	//prep work
	pModInfo=ExAllocatePoolWithTag(NonPagedPool,sizeof(SYSTEM_MODULE_INFORMATION),CW_TAG);
	d=ExAllocatePoolWithTag(NonPagedPool,sizeof(DETOURINFO),CW_TAG);

	if (pModInfo == NULL || d == NULL)
	{
		DbgPrint("GetIrpTableHooksAndDetours():  ERROR:  pModInfo or d was NULL.");
		return FALSE;
	}

	//get a pointer to the driver's device object structure that represents this exposed device name
	//note: ACCESS_MASK of FILE_READ_DATA is important because it ensures
	//the file system is mounted on the storage device (if dealing with fs device)
	nt=IoGetDeviceObjectPointer(puDeviceName,FILE_READ_DATA,&fileObj,&deviceObj);
	if (!NT_SUCCESS(nt))
	{
		DbgPrint("GetIrpTableHooksAndDetours():  Error:  failed to obtain device pointer:  0x%08x",nt);
		return FALSE;
	}

	//get a pointer to the device's DRIVER_OBJECT structure
	driverObj=deviceObj->DriverObject;

	//from the driver object structure, get a pointer to the IRP table
	pDriverIrpTable=driverObj->MajorFunction;

	DbgPrint("GetIrpTableHooksAndDetours():  IRP table pointer obtained.");

	//iterate over all pointers in the IRP function handler table for this driver
	//note there are 28 IRP major function codes, and all drivers must specify
	//a routine for each one; the I/O manager fills entires in the IRP table
	//that the driver chose not to handle with a generic routine.
	for (i=0;i<IRP_MJ_MAXIMUM_FUNCTION+1;i++)
	{
		dispatchFunctionAddress=pDriverIrpTable[i];

		//---------------------------------------------
		//GET CONTAINING MODULE NAME AND FUNCTION NAME
		//---------------------------------------------
		//get the containing module of this  function by its address in memory
		if(GetModInfoByAddress((ULONG)dispatchFunctionAddress,pModInfo))
		{
			RtlStringCbCopyExA(ContainingModule,256,pModInfo->ImageName,NULL,NULL,0);

			//get the name of the function from the containing module's export table
			//or if not exported, store [unknown]
			if (!GetFunctionName(pModInfo->Base,(ULONG)dispatchFunctionAddress,dispatchFunctionName))
				RtlStringCbCopyExA(dispatchFunctionName,256,pUnknownBuf,NULL,NULL,0);
		}
		//if we cant find the containing module, there's a problem:
		//	(1) ZwQuerySystemInformation() is hooked.  we're screwed.
		//	(2) the module was not in the system's module list, so it injected somehow
		//in either case, the user should suspect something's up from this fact alone.
		else
		{
			RtlStringCbCopyExA(ContainingModule,256,pUnknownBuf,NULL,NULL,0);
			RtlStringCbCopyExA(dispatchFunctionName,256,pUnknownBuf,NULL,NULL,0);
		}

		////////////////////////////////////////
		//				HOOKED
		////////////////////////////////////////
		if (pHookTable != NULL)
		{
			pHookTable->HookedEntries[i].DispatchFunctionAddress=(ULONG)dispatchFunctionAddress;			
			RtlStringCbCopyExA(pHookTable->HookedEntries[i].ContainingModule,256,ContainingModule,NULL,NULL,0);
			RtlStringCbCopyExA(pHookTable->HookedEntries[i].DispatchFunctionName,256,dispatchFunctionName,NULL,NULL,0);

			if (!IsAddressWithinModule((ULONG)dispatchFunctionAddress,DriverBaseAddress,DriverSize))
			{
				pHookTable->HookedEntries[i].IrpMajorFunctionHooked=i;
				pHookTable->isHooked=TRUE;
			}
			else
			{
				pHookTable->isHooked=FALSE;
			}

			pHookTable->NumHookedEntries++;
		}

		////////////////////////////////////////
		//				DETOURED
		////////////////////////////////////////
		if (pDetourTable != NULL)
		{
			pDetourTable->DetouredEntries[i].DispatchFunctionAddress=(ULONG)dispatchFunctionAddress;
			RtlStringCbCopyExA(pDetourTable->DetouredEntries[i].DetouringModule,256,ContainingModule,NULL,NULL,0);
			RtlStringCbCopyExA(pDetourTable->DetouredEntries[i].DispatchFunctionName,256,dispatchFunctionName,NULL,NULL,0);

			if (IsFunctionPrologueDetoured((ULONG)dispatchFunctionAddress,DriverBaseAddress,DriverSize,d))
			{
				pDetourTable->isDetoured=TRUE;

				if (d->detouringModule != NULL)
					RtlStringCbCopyExA(pDetourTable->DetouredEntries[i].DetouringModule,256,d->detouringModule,NULL,NULL,0);

				pDetourTable->DetouredEntries[i].TargetAddress=d->TargetAddress;

				//loop through possible decoded instructions
				for (j = 0;j<d->numDisassembled; j++) 
				{
					RtlStringCchPrintfA(
						pDetourTable->DetouredEntries[i].Disassembly[j],
						256,
						"%08I64x (%02d) %s %s %s\n", 
						d->decodedInstructions[j].offset,
						d->decodedInstructions[j].size,
						(char*)d->decodedInstructions[j].instructionHex.p,
						(char*)d->decodedInstructions[j].mnemonic.p,
						(char*)d->decodedInstructions[j].operands.p
						);
				}
			}
			else
			{
				pDetourTable->isDetoured=FALSE;
			}

			pDetourTable->NumDetours++;
		}
	}

	//decrease reference count
	ObDereferenceObject(&fileObj);

	if (pModInfo != NULL)
		ExFreePoolWithTag(pModInfo,CW_TAG);
	if (d != NULL)
		ExFreePoolWithTag(d,CW_TAG);

	return TRUE;
}
