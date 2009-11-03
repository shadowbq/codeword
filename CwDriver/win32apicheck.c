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
// * win32apicheck.c
//
// * ChangeLog
// 
// * 7/12/2009 - AL - first version.
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
#include "win32apicheck.h"
#include <ntstrsafe.h>
#include <stdlib.h>

/////////////////////////////////////////////////////
//                                                 //
// CheckModuleExportsForDetours()                  //
//                                                 //
/////////////////////////////////////////////////////
//Description:  Attempts to validate the function prologue
//				of all functions exported by the given module.
//				If any bytes are overwritten in Migbot-style
//				jumps/overwrites, they will be detected.
//
//				Migbot is our inspiration.
//
//				Note:  Disassembly must be a 25x256 char array
//
//Returns:      NTSTATUS
/////////////////////////////////////////////////////
NTSTATUS CheckModuleExportsForDetours(__in PCHAR modname, __inout PWIN32API_DETOUR_TABLE pWin32ApiDetourTable)
{
	DWORD mod_base,mod_size=0;
	PDETOURINFO d;
	PSYSTEM_MODULE_INFORMATION pMod;
	UNICODE_STRING u;
	UNICODE_STRING uModName;
	HANDLE hModule;
	ANSI_STRING aModName;
	WCHAR funcName[256];
	ULONG funcAddress,NumExports=0;
	PCHAR* exports[512];
	int k=0,x=0;
	ULONG j=0,offset=0,numDetours=0;
	BOOL initSuccess=FALSE;

	if (pWin32ApiDetourTable == NULL)
	{
		DbgPrint("%s","CheckModuleExportsForDetours():  passed-in table variable was NULL!");
		return STATUS_UNSUCCESSFUL;
	}

	//initialize to 0
	pWin32ApiDetourTable->NumDetours=0;

	d=ExAllocatePoolWithTag(NonPagedPool,sizeof(DETOURINFO),CW_TAG);
	pMod=ExAllocatePoolWithTag(NonPagedPool,sizeof(SYSTEM_MODULE_INFORMATION),CW_TAG);
	
	if (d == NULL || pMod == NULL)
	{
		DbgPrint("%s","CheckModuleExportsForDetours():  d or pMode was NULL.");
		return STATUS_UNSUCCESSFUL;
	}

	//
	//get module info - modname is one of:
	//	ntdll.dll, kernel32.dll, user32.dll, advapi32.dll, gdi32.dll, comdlg32.dll, comctl32.dll, commctrl.dll,
    //	shell.dll, shlwapi.dll, mshtml.dll, urlmon.dll.
	//
	//try the system load module list first
	if (!GetModInfoByName(modname,pMod))
	{
		DbgPrint("%s","CheckModuleExportsForDetours():  This module is not currently loaded.");
		return STATUS_UNSUCCESSFUL;

		/*
		TO DO:  Make the code below work... requires that we load the DLL using LdrLoadDll (in ntdll.lib) or 
		some other means .. 


		DbgPrint("%s","CheckModuleExportsForDetours():  The request module is not loaded - doing so now...");

		//if that failed, try to map the module into our address space using undoc LdrLoadDll()
		//0x00000001 = DONT_RESOLVE_DLL_REFERENCES
		RtlInitAnsiString(&aModName,modname);
		
		if (NT_SUCCESS(RtlAnsiStringToUnicodeString(&uModName,&aModName,TRUE)))
		{
			if (NT_SUCCESS(LdrLoadDll(NULL,0x00000001,&uModName,&hModule)))
			{
				//now try again...
				if (GetModInfoByName(modname,pMod))
					initSuccess=TRUE;
				else
					DbgPrint("%s","CheckModuleExportsForDetours():  Failed to retrieve module.");
				//free the handle LdrLoadDll() gave us
				if (hModule != NULL)
					ZwClose(hModule);
			}
			else
				DbgPrint("%s","CheckModuleExportsForDetours():  LdrLoadDll() failed.");
		}

		//all that crap failed
		if (!initSuccess)
		{
			DbgPrint("%s","CheckModuleExportsForDetours():  Failed to find or load the requested module.");
			if (d != NULL)
				ExFreePoolWithTag(d,CW_TAG);
			if (pMod != NULL)
				ExFreePoolWithTag(pMod,CW_TAG);
			//free the tmp unicode string
			if (uModName.Buffer != NULL)
				RtlFreeUnicodeString(&uModName);
			return STATUS_UNSUCCESSFUL;
		}
		*/
	}

	//store module location and size
	mod_base=(DWORD)pMod->Base;
	mod_size=(DWORD)pMod->Size;

	DbgPrint("CheckModuleExportsForDetours():  Target module base addr = 0x%08x, size = %i", mod_base, mod_size);

	//get a chunk of names of exported functions of thsi module
	//while we have the ability to get more than 512, memory quickly runs out b/c structures
	//are poorly defined in win32apicheck.h  (TODO)
	NumExports=GetModuleExportNames(mod_base,exports,offset,512);
	DbgPrint("CheckModuleExportsForDetours():  GetModuleExportNames() retrieved %i exports.", NumExports);
	
	//need to continue, because there still may be more functions in the export table with names.
	if (NumExports == 0)
	{
		DbgPrint("%s","CheckModuleExportsForDetours():  GetModuleExportNames() failed.");
		if (d != NULL)
			ExFreePoolWithTag(d,CW_TAG);
		if (pMod != NULL)
			ExFreePoolWithTag(pMod,CW_TAG);
		return STATUS_UNSUCCESSFUL;
	}

	DbgPrint("CheckModuleExportsForDetours():  Looping over %i exports...", NumExports);

	//loop through the names that were returned
	for (j=0;j<NumExports;j++)
	{
		//DbgPrint("\nCheckModuleExportsForDetours():  Examining export name %s...",exports[j]);

		//convert function name to wide string in prep for converting to UNICODE
		mbstowcs(funcName,exports[j],256);
		RtlInitUnicodeString(&u,funcName);

		//get the address of the function - always enclose a call to this unsupported API 
		//in try/except .. it will BSOD the system if the func doesnt exist
		__try
		{
			funcAddress = (ULONG)MmGetSystemRoutineAddress(&u);
		}
		__except(1)
		{
			RtlStringCbCopyExA(pWin32ApiDetourTable->Win32Detours[numDetours].DetouringModule,256,modname,NULL,NULL,0);
			pWin32ApiDetourTable->Win32Detours[numDetours].ExportAddress=0;
			pWin32ApiDetourTable->Win32Detours[numDetours].TargetAddress=0;
			pWin32ApiDetourTable->Win32Detours[numDetours].IsDetoured=FALSE;
			pWin32ApiDetourTable->Win32Detours[numDetours].IsUnknown=TRUE;
			numDetours++;
			continue;
		}

		//this function is likely not exported, so we should move on.
		if (funcAddress == 0 || funcAddress == NULL)
		{
			RtlStringCbCopyExA(pWin32ApiDetourTable->Win32Detours[numDetours].DetouringModule,256,modname,NULL,NULL,0);
			pWin32ApiDetourTable->Win32Detours[numDetours].ExportAddress=funcAddress;
			pWin32ApiDetourTable->Win32Detours[numDetours].TargetAddress=0;
			pWin32ApiDetourTable->Win32Detours[numDetours].IsDetoured=FALSE;
			pWin32ApiDetourTable->Win32Detours[numDetours].IsUnknown=FALSE;
			numDetours++;
			continue;
		}

		//ExportName (the function that is being examined)
		RtlStringCbCopyExA(pWin32ApiDetourTable->Win32Detours[numDetours].ExportName,256,exports[j],NULL,NULL,0);

		//if the function's address falls outside of the module's address space, we have a detour
		if (IsFunctionPrologueDetoured((DWORD)funcAddress,mod_base,mod_size,d))
		{			
			//DetouringModule (the bad guy)
			RtlStringCbCopyExA(pWin32ApiDetourTable->Win32Detours[numDetours].DetouringModule,256,d->detouringModule,NULL,NULL,0);
			pWin32ApiDetourTable->Win32Detours[numDetours].IsDetoured=TRUE;
			pWin32ApiDetourTable->Win32Detours[numDetours].IsUnknown=FALSE;	
			pWin32ApiDetourTable->Win32Detours[numDetours].TargetAddress=d->TargetAddress;

			//loop through possible decoded instructions
			for (k = 0;k<d->numDisassembled; k++) 
			{
				RtlStringCchPrintfA(
						pWin32ApiDetourTable->Win32Detours[numDetours].Disassembly[k],
						256,
						"%08I64x (%02d) %s %s %s\n", 
						d->decodedInstructions[k].offset,
						d->decodedInstructions[k].size,
						(char*)d->decodedInstructions[k].instructionHex.p,
						(char*)d->decodedInstructions[k].mnemonic.p,
						(char*)d->decodedInstructions[k].operands.p
						);
			}
		}
		//no detour - but report data anyway
		else
		{
			RtlStringCbCopyExA(pWin32ApiDetourTable->Win32Detours[numDetours].DetouringModule,256,modname,NULL,NULL,0);
			pWin32ApiDetourTable->Win32Detours[numDetours].ExportAddress=funcAddress;
			pWin32ApiDetourTable->Win32Detours[numDetours].TargetAddress=0;
			pWin32ApiDetourTable->Win32Detours[numDetours].IsDetoured=FALSE;
			pWin32ApiDetourTable->Win32Detours[numDetours].IsUnknown=FALSE;
		}

		numDetours++;
	}

	//populate the parameters for this module
	RtlStringCbCopyExA(pWin32ApiDetourTable->ModuleName,256,modname,NULL,NULL,0);
	pWin32ApiDetourTable->NumDetours=numDetours;

	if (d != NULL)
		ExFreePoolWithTag(d,CW_TAG);
	if (pMod != NULL)
		ExFreePoolWithTag(pMod,CW_TAG);

	return STATUS_SUCCESS;
}

/////////////////////////////////////////////////////
//                                                 //
// GetModuleExportNames()                          //
//                                                 //
/////////////////////////////////////////////////////
//Description:  Populates the CHAR[] array
//				with the list of names of all exports
//				for the given module by parsing the NtHeader.
//
//Returns:      BOOL
/////////////////////////////////////////////////////
ULONG GetModuleExportNames(DWORD ModBaseAddr, PCHAR* exports[], ULONG ordinalOffset, ULONG count)
{
	PIMAGE_EXPORT_DIRECTORY pExportDirectory;
    NTSTATUS ns = STATUS_INVALID_PARAMETER;
	PULONG AddressOfNames,AddressOfFunctions=0;
	PUSHORT AddressOfNameOrdinals;
	ULONG i,j=0;
	ULONG expCount=0;
	NTSTATUS nt=STATUS_SUCCESS;
	ULONG thisFuncAddr;
	PUSHORT thisOrdinal;
	PCHAR namePtr=NULL;
	CHAR funcNameBuffer[256];

	//get the base addr of export directory table for the module
	pExportDirectory=GetModuleExportDirectoryAddr((PVOID)ModBaseAddr);

    if (pExportDirectory != NULL)
	{
		AddressOfNames=(PULONG)((ULONG)ModBaseAddr+(ULONG)pExportDirectory->AddressOfNames);
		AddressOfNameOrdinals = (PUSHORT)((ULONG)ModBaseAddr+(ULONG)pExportDirectory->AddressOfNameOrdinals);
		AddressOfFunctions=(PULONG)((ULONG)ModBaseAddr+(ULONG)pExportDirectory->AddressOfFunctions);

		//loop through the table of function addresses and save the name
		//our starting point is the offset in the export directory table 
		for(i=ordinalOffset;i<count;i++)
		{
			if (i > (ULONG)pExportDirectory->NumberOfFunctions)
				break;

			//save function address of this export
			thisFuncAddr=(ULONG)((DWORD)ModBaseAddr+*AddressOfFunctions);

			//go ahead and increment for next time
			AddressOfFunctions++;

			//get ptr to nameordinals
			thisOrdinal=AddressOfNameOrdinals;
			
			//try to get this export's name.  this is a shot in the dark, because not all funcs
			//in the export directory will have a name.
			for(j=0;j<(ULONG)pExportDirectory->NumberOfFunctions;j++)
			{
				__try
				{	
					if ((ULONG)*thisOrdinal == i)
					{
						//add the module base to the address of the name dereferenced
						namePtr=(PCHAR)((DWORD)ModBaseAddr+(*(AddressOfNames+j)));
						//nt=RtlStringCbCopyExA(exports[expCount],256,namePtr,NULL,NULL,STRSAFE_NULL_ON_FAILURE);
						exports[expCount]=namePtr;
						expCount++;
						//DbgPrint("%s",exports[expCount-1]);
						break;
					}
				}
				__except(1) {} //DbgPrint("Exception.");}
				thisOrdinal++;
			}
		}
	}
	else
	{
		DbgPrint("%s","GetExportNames():  Could not find export directory table for this module.");
		return 0;
	}

	return expCount;
}