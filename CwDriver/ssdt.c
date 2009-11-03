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
// * ssdt.c
//
// * ChangeLog
// 
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
#include "lut.h"
#include <ntstrsafe.h>

/////////////////////////////////////////////////////
//                                                 //
// GetSSDTHooks()                                  //
//                                                 //
/////////////////////////////////////////////////////
//Description:  Attempts to detect hooks in the SSDT
//				system service functions by comparing
//				the address of the service function
//				pointer with ntoskrnl address space.
//
//Returns:      NTSTATUS
/////////////////////////////////////////////////////
NTSTATUS GetSSDTHooks(__inout PHOOKED_SSDT_TABLE pHookTable)
{
	NTSTATUS nt,ntstatus = STATUS_SUCCESS;
	PSYSTEM_MODULE_INFORMATION pThisModule=NULL;
	PHOOKED_SSDT_ENTRY pHookedEntry=NULL;
	PCHAR pUnknownBuf="[unknown]";
	DWORD ntoskrnl_base,ntoskrnl_size = 0;
	ULONG ServiceFunctionAddress,ServiceFunctionParameterBytes;
	CHAR ServiceFunctionNameExpected[256];
	CHAR ServiceFunctionNameFound[256];
	CHAR ContainingModule[256];
	UNICODE_STRING Disassembly;
	int i,j;
	int HookCount=0;

	pThisModule=ExAllocatePoolWithTag(NonPagedPool,sizeof(SYSTEM_MODULE_INFORMATION),CW_TAG);

	//oops, out of memory...
	if (pThisModule == NULL)
	{
		DbgPrint("GetSSDTHooks():  Could not allocate any memory.\n");
		return STATUS_UNSUCCESSFUL;
	}
	if (pHookTable == NULL)
	{
		DbgPrint("GetSSDTHooks():  I was passed a NULL pHookTable!!!\n");
		return STATUS_UNSUCCESSFUL;
	}

	//find kernel base address
	if(!GetModInfoByName(TEXT("ntoskrnl.exe"),pThisModule))  //normal kernel
	{
		if(!GetModInfoByName(TEXT("ntkrnlpa.exe"),pThisModule))  //pae-enabled kernel
		{
			if(!GetModInfoByName(TEXT("ntkrnlpa.exe"),pThisModule))  //multiprocessor kernel
			{
				DbgPrint("GetSSDTHooks():  Error:  Unable to locate ntoskrnl base address.\n\n");
				return STATUS_UNSUCCESSFUL;
			}
		}
	}

	//dereference the ptr we received
	ntoskrnl_base=(DWORD)pThisModule->Base;
	ntoskrnl_size=pThisModule->Size;

	//loop through SSDT entries
	for(i=0;i<(int)KeServiceDescriptorTable.ntoskrnl.NumberOfServices;i++)
	{
		///////////////////////////////////////////////////////////////////////////
		//																		 //
		//						COLLECT SSDT INFORMATION						 //
		//																		 //
		///////////////////////////////////////////////////////////////////////////
		//get the address of this service function and number of parameter bytes
		ServiceFunctionAddress=(ULONG)KeServiceDescriptorTable.ntoskrnl.KiServiceTable[i];
		ServiceFunctionParameterBytes=(ULONG)KeServiceDescriptorTable.ntoskrnl.ServiceParameterTableBase[i];
		//assign the "known good" service function name which is pulled from a lookup table
		//ie, what service address is normally stored at this index in the ssdt?
		RtlStringCbCopyExA(ServiceFunctionNameExpected,256,GetKGServiceFunctionName((UINT)i),NULL,NULL,0);
		//get the containing module of this service function by its address in memory
		if(GetModInfoByAddress(ServiceFunctionAddress,pThisModule))
		{
			RtlStringCbCopyExA(ContainingModule,256,pThisModule->ImageName,NULL,NULL,0);

			//get the name of the function from the containing module's export table
			//or if not exported, store [unknown]
			if (!GetFunctionName(pThisModule->Base,ServiceFunctionAddress,ServiceFunctionNameFound))
				RtlStringCbCopyExA(ServiceFunctionNameFound,256,pUnknownBuf,NULL,NULL,0);
		}
		//if we cant find the containing module, there's a problem:
		//	(1) ZwQuerySystemInformation() is hooked.  we're screwed.
		//	(2) the module was not in the system's module list, so it injected somehow
		//in either case, the user should suspect something's up from this fact alone.
		else
		{
			RtlStringCbCopyExA(ContainingModule,256,pUnknownBuf,NULL,NULL,0);
			RtlStringCbCopyExA(ServiceFunctionNameFound,256,pUnknownBuf,NULL,NULL,0);
		}

		//is the function hooked?
		if (!IsAddressWithinModule(ServiceFunctionAddress,(ULONG)ntoskrnl_base,(ULONG)ntoskrnl_size))
		{
			//create a HOOKED_SSDT_ENTRY struct and populate it with information
			pHookedEntry = ExAllocatePoolWithTag(NonPagedPool,sizeof(HOOKED_SSDT_ENTRY),CW_TAG);
			RtlStringCbCopyExA(pHookedEntry->ContainingModule,256,&ContainingModule,NULL,NULL,0);
			pHookedEntry->ServiceIndex=i;
			pHookedEntry->ServiceFunctionAddress=ServiceFunctionAddress;
			RtlStringCbCopyExA(pHookedEntry->ServiceFunctionNameExpected,256,&ServiceFunctionNameExpected,NULL,NULL,0);
			RtlStringCbCopyExA(pHookedEntry->ServiceFunctionNameFound,256,&ServiceFunctionNameFound,NULL,NULL,0);
			//copy the hooked entry object into the hook table 
			RtlCopyMemory(&(pHookTable->HookedEntries[HookCount]),pHookedEntry,sizeof(HOOKED_SSDT_ENTRY));
			//free the memory
			ExFreePoolWithTag(pHookedEntry,CW_TAG);
			HookCount++;
		}
	}

	pHookTable->NumHookedEntries=HookCount;

	//cleanup
	if (pThisModule != NULL)
		ExFreePoolWithTag(pThisModule,CW_TAG);

	return STATUS_SUCCESS;
}


/////////////////////////////////////////////////////
//                                                 //
// GetSSDTDetours()                                //
//                                                 //
/////////////////////////////////////////////////////
//Description:  Attempts to detect detours/patches in
//				system service functions listed in the
//				current SSDT.
//				
//				Note:  this function is nearly identical
//				to GetSSDTHooks() above.
//
//Returns:      NTSTATUS
/////////////////////////////////////////////////////
NTSTATUS GetSSDTDetours(__inout PDETOURED_SSDT_TABLE pDetourTable)
{
	NTSTATUS nt,ntstatus = STATUS_SUCCESS;
	PSYSTEM_MODULE_INFORMATION pThisModule=NULL;
	PDETOURED_SSDT_ENTRY pDetouredEntry=NULL;
	PCHAR pUnknownBuf="[unknown]";
	DWORD ntoskrnl_base,ntoskrnl_size = 0;
	ULONG ServiceFunctionAddress,ServiceFunctionParameterBytes;
	CHAR ServiceFunctionNameExpected[256];
	CHAR ServiceFunctionNameFound[256];
	CHAR ContainingModule[256];
	BOOL IsDetoured=FALSE;
	UNICODE_STRING Disassembly;
	PDETOURINFO d;
	int i,j;
	int DetourCount=0;

	pThisModule=ExAllocatePoolWithTag(NonPagedPool,sizeof(SYSTEM_MODULE_INFORMATION),CW_TAG);
	d=ExAllocatePoolWithTag(NonPagedPool,sizeof(DETOURINFO),CW_TAG);
	
	//oops, out of memory...
	if (pThisModule == NULL || d == NULL || pDetourTable == NULL)
	{
		DbgPrint("GetSSDTDetours():  A critical variable was NULL.\n");
		return STATUS_UNSUCCESSFUL;
	}

	//find kernel base address
	if(!GetModInfoByName(TEXT("ntoskrnl.exe"),pThisModule))  //normal kernel
	{
		if(!GetModInfoByName(TEXT("ntkrnlpa.exe"),pThisModule))  //pae-enabled kernel
		{
			if(!GetModInfoByName(TEXT("ntkrnlpa.exe"),pThisModule))  //multiprocessor kernel
			{
				DbgPrint("GetSSDTDetours():  Error:  Unable to locate ntoskrnl base address.\n\n");
				return STATUS_UNSUCCESSFUL;
			}
		}
	}

	//dereference the ptr we received
	ntoskrnl_base=(DWORD)pThisModule->Base;
	ntoskrnl_size=pThisModule->Size;

	//loop through SSDT entries
	for(i=0;i<(int)KeServiceDescriptorTable.ntoskrnl.NumberOfServices;i++)
	{
		///////////////////////////////////////////////////////////////////////////
		//																		 //
		//						COLLECT SSDT INFORMATION						 //
		//																		 //
		///////////////////////////////////////////////////////////////////////////
		//get the address of this service function and number of parameter bytes
		ServiceFunctionAddress=(ULONG)KeServiceDescriptorTable.ntoskrnl.KiServiceTable[i];
		ServiceFunctionParameterBytes=(ULONG)KeServiceDescriptorTable.ntoskrnl.ServiceParameterTableBase[i];
		//assign the "known good" service function name which is pulled from a lookup table
		//ie, what service address is normally stored at this index in the ssdt?
		RtlStringCbCopyExA(ServiceFunctionNameExpected,256,GetKGServiceFunctionName((UINT)i),NULL,NULL,0);
		//get the containing module of this service function by its address in memory
		if(GetModInfoByAddress(ServiceFunctionAddress,pThisModule))
		{
			RtlStringCbCopyExA(ContainingModule,256,pThisModule->ImageName,NULL,NULL,0);

			//get the name of the function from the containing module's export table
			//or if not exported, store [unknown]
			if (!GetFunctionName(pThisModule->Base,ServiceFunctionAddress,ServiceFunctionNameFound))
				RtlStringCbCopyExA(ServiceFunctionNameFound,256,pUnknownBuf,NULL,NULL,0);
		}
		//if we cant find the containing module, there's a problem:
		//	(1) ZwQuerySystemInformation() is hooked.  we're screwed.
		//	(2) the module was not in the system's module list, so it injected somehow
		//in either case, the user should suspect something's up from this fact alone.
		else
		{
			RtlStringCbCopyExA(ContainingModule,256,pUnknownBuf,NULL,NULL,0);
			RtlStringCbCopyExA(ServiceFunctionNameFound,256,pUnknownBuf,NULL,NULL,0);
		}

		//is the function detoured/patched?
		IsDetoured=IsFunctionPrologueDetoured(ServiceFunctionAddress,ntoskrnl_base,ntoskrnl_size,d);

		//if it is detoured, we may have found the containing module that way, so reassign here
		if (IsDetoured)
		{
			//save the name of the detouring module if it was found
			if (d->detouringModule != NULL)
				RtlStringCbCopyExA(ContainingModule,256,d->detouringModule,NULL,NULL,0);

			//create a HOOKED_SSDT_ENTRY struct and populate it with information
			pDetouredEntry = ExAllocatePoolWithTag(NonPagedPool,sizeof(DETOURED_SSDT_ENTRY),CW_TAG);
			pDetouredEntry->ServiceIndex=i;
			pDetouredEntry->ServiceFunctionAddress=ServiceFunctionAddress;
			RtlStringCbCopyExA(pDetouredEntry->ContainingModule,256,&ContainingModule,NULL,NULL,0);
			RtlStringCbCopyExA(pDetouredEntry->ServiceFunctionNameExpected,256,&ServiceFunctionNameExpected,NULL,NULL,0);
			RtlStringCbCopyExA(pDetouredEntry->ServiceFunctionNameFound,256,&ServiceFunctionNameFound,NULL,NULL,0);
			pDetouredEntry->TargetAddress=(ULONG)d->TargetAddress;

			//copy the disassembly into struct
			for (j = 0;j<d->numDisassembled; j++) 
			{
				RtlStringCchPrintfA(
					pDetouredEntry->Disassembly[j],
					256,
					"%08I64x (%02d) %s %s %s\n", 
					d->decodedInstructions[j].offset,
					d->decodedInstructions[j].size,
					(char*)d->decodedInstructions[j].instructionHex.p,
					(char*)d->decodedInstructions[j].mnemonic.p,
					(char*)d->decodedInstructions[j].operands.p
					);
			}			
			
			//copy the hooked entry object into the hook table 
			RtlCopyMemory(&(pDetourTable->DetouredEntries[DetourCount]),pDetouredEntry,sizeof(DETOURED_SSDT_ENTRY));
			//free the memory
			ExFreePoolWithTag(pDetouredEntry,CW_TAG);
			DetourCount++;
		}
	}

	pDetourTable->NumDetouredEntries=DetourCount;

	//cleanup
	if (pThisModule != NULL)
		ExFreePoolWithTag(pThisModule,CW_TAG);
	if (d != NULL)
		ExFreePoolWithTag(d,CW_TAG);

	return STATUS_SUCCESS;
}

/////////////////////////////////////////////////////
//                                                 //
// GetKGServiceFunctionName()                      //
//                                                 //
/////////////////////////////////////////////////////
//Description:  Retrieves the known-good SSDT service
//				function name at the given index by
//				loading and parsing a lookup table.
//
//Returns:      void
/////////////////////////////////////////////////////
PCHAR GetKGServiceFunctionName(__in UINT requestedIndex)
{
	extern BOOL LUT_INITIALIZED;
	extern PCHAR KnownGood_ServiceFunctionNames[LUT_NUM_ROWS];
	extern DWORD KnownGood_ServiceFunctionIndices[LUT_NUM_ROWS][LUT_NUM_COLS];
	int i;
	int OSIndex=0;
	PCHAR unknownName="[Unknown]";
	UNICODE_STRING u;
	NTSTATUS (*pRtlGetVersion) (PRTL_OSVERSIONINFOEXW);
	RTL_OSVERSIONINFOEXW versionInfoEx;
	
	//load the LUT if necessary
	if (!LUT_INITIALIZED)
		LoadLUT();
	LUT_INITIALIZED=TRUE;

	//get the OS version of this PC
	//see:  http://msdn.microsoft.com/en-us/library/ms724833(VS.85).aspx
	//
	//must first find the address of RtlGetVersion() since it is not exported on win2k
	RtlInitUnicodeString(&u,L"RtlGetVersion");
	pRtlGetVersion = MmGetSystemRoutineAddress(&u);

	if (pRtlGetVersion == NULL)
	{
		DbgPrint("GetKGServiceFunctionName():  Error:  RtlGetVersion() not found.\n");
		return unknownName;
	}

	//////////////////////////////////////////////
	//											//
	//				GET OS VERSION				//
	//											//
	//////////////////////////////////////////////
	versionInfoEx.dwOSVersionInfoSize = sizeof(versionInfoEx);
	pRtlGetVersion(&versionInfoEx);

	switch(versionInfoEx.dwMajorVersion)
	{
		//--------------------------------------
		//** VISTA AND GREATER (6.0 or 6.1) **//
		//we currently support only vista sp0
		//--------------------------------------
		case 6:

			switch(versionInfoEx.dwMinorVersion)
			{
				case 1:  //Windows 7 or WinServer 2008 R2 -- not supported
					OSIndex=-1;
					break;

				case 0:  //Vista or WinServer 2008
					switch (versionInfoEx.wServicePackMajor)
					{
						case 0:  //Vista SP0
							OSIndex=14;
							break;
						default: //unknown
							OSIndex=-1;
							break;
					}
					break;

				default:
					OSIndex=-1;
					break;
			}
			break;
			
		//------------------------------------------
		//** WIN2K AND GREATER (5.0,5.1 or 5.2) **//
		//all versions supported
		//------------------------------------------
		case 5:

			switch(versionInfoEx.dwMinorVersion)
			{
				case 2:  //WinServer 2003 sp1, win home server, winserver 2003, winxp pro 64
					switch (versionInfoEx.wServicePackMajor)
					{
						case 1:		//winserver 2003 sp1 or winxp pro 64 sp1
							OSIndex=13;
							break;
						case 0:		//winserver 2003 sp0 or winxp pro 64 sp0
							OSIndex=12;
							break;
						default:   //unsupported
							OSIndex=-1;
							break;
					}
					break;

				case 1:  //Win XP sp0,1,2 or 3
					switch (versionInfoEx.wServicePackMajor)
					{
						case 2:		//WinXP sp2
							OSIndex=11;
							break;
						case 1:		//WinXP sp1
							OSIndex=10;
							break;
						case 0:		//WinXP sp0
							OSIndex=9;
							break;
						default:   //unsupported
							OSIndex=-1;
							break;
					}
					break;

				case 0:  //win2k sp4,5,6,7 or8
					switch (versionInfoEx.wServicePackMajor)
					{
						case 4:		//win2k sp4
							OSIndex=8;
							break;
						case 3:		//win2k sp3
							OSIndex=7;
							break;
						case 2:		//win2k sp2
							OSIndex=6;
							break;
						case 1:		//win2k sp1
							OSIndex=5;
							break;
						case 0:		//win2k sp0
							OSIndex=4;
							break;
						default:   //unsupported
							OSIndex=-1;
							break;
					}
					break;

				default: //unknown
					OSIndex=-1;
					break;
			}
			break;

			
		//--------------------------------------
		//** LESS THAN WIN2K - WINNT 4.0 **//
		//--------------------------------------
		default:
			OSIndex=-1;
			break;
	}

	//if unsupported OS, return [unknown]
	if (OSIndex < 0)
	{
		DbgPrint("GetKGServiceFunctionName():  Error:  Unsupported operating system:\n");
		DbgPrint("            Major version      :  %d\n",versionInfoEx.dwMajorVersion);
		DbgPrint("            Minor version      :  %d\n",versionInfoEx.dwMinorVersion);
		DbgPrint("            Build Number       :  %d\n",versionInfoEx.dwBuildNumber);
		DbgPrint("            Platform Id        :  %d\n",versionInfoEx.dwPlatformId);
		DbgPrint("            Service Pack       :  %S\n",versionInfoEx.szCSDVersion);
		DbgPrint("            Product Type       :  %c\n",versionInfoEx.wProductType);
		DbgPrint("            Reserved           :  %c\n",versionInfoEx.wReserved);
		DbgPrint("            Major Service Pack :  %i\n",versionInfoEx.wServicePackMajor);
		DbgPrint("            Minor Service Pack :  %i\n",versionInfoEx.wServicePackMinor);
		DbgPrint("            Suite Mask         :  %i\n",versionInfoEx.wSuiteMask);
		return unknownName;
	}

	//otherwise, loop through the LUT and find the corresponding function name
	//for this SSDT entry based on operating system version
	for (i=0;i<LUT_NUM_ROWS;i++)
		if ((UINT)KnownGood_ServiceFunctionIndices[i][OSIndex] == requestedIndex)
			return KnownGood_ServiceFunctionNames[i];
	
	return unknownName;
}