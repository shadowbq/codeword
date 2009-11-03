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
#include <stdio.h>
#include <string.h>
#include "ntddk.h"
#include "main.h"
#include "ntundoc.h"
#include "ssdt.h"
#include "gdt.h"
#include "x86.h"
#include "module.h"
#include <ntstrsafe.h>


//returns a pointer to the absolute linear address of the export section
//of the given module in memory using undocumented api
PIMAGE_EXPORT_DIRECTORY GetModuleExportDirectoryAddr(PVOID ModuleBaseAddr)
{
    PIMAGE_NT_HEADERS pHeader = NULL;
    PIMAGE_DATA_DIRECTORY pDataDirectory = NULL;
    NTSTATUS ns=STATUS_INVALID_PARAMETER;
    PIMAGE_EXPORT_DIRECTORY pExportDirectory=NULL; //this is what we return

	//returns a pointer to the linear address of the IMAGE_NT_HEADERS
	//structure in memory of the given module using undocumented API
	pHeader=RtlImageNtHeader(ModuleBaseAddr);

	//if the IMAGE_NT_HEADERS structure actually exists in the module's address space
    if (pHeader != NULL)
	{
		//the data directory is at a given offset from the optional_header
		pDataDirectory=pHeader->OptionalHeader.DataDirectory + IMAGE_DIRECTORY_ENTRY_EXPORT;

		//if the virtual address is NOT null and its size is within the export directory structure,
		//then we consider this a valid address and return the module base addr+this address
        if (pDataDirectory->VirtualAddress && (pDataDirectory->Size >= sizeof(IMAGE_EXPORT_DIRECTORY)))
			return (PVOID)((PBYTE)ModuleBaseAddr+(DWORD)pDataDirectory->VirtualAddress);
		else
			return NULL;
	}

	return NULL;
}

//finds a function name for the given function address from the export table of the given module, if it exists.
//if it exists, the function name is copied to the last parameter of this function, returning TRUE.
//if it doesnt exist, FALSE is returned.
//NB:  funcNameBuffer must be 256 bytes!
BOOL GetFunctionName(PVOID ModuleBaseAddr, ULONG FuncAddr, __inout PCHAR funcNameBuffer)
{
    PIMAGE_EXPORT_DIRECTORY pExportDirectory;
    NTSTATUS ns = STATUS_INVALID_PARAMETER;
	PULONG AddressOfNames,AddressOfFunctions=0;
	PUSHORT AddressOfNameOrdinals;
	ULONG i,j=0;
	NTSTATUS nt=STATUS_SUCCESS;
	ULONG thisFuncAddr;
	PUSHORT thisOrdinal;
	PCHAR namePtr;

	//get the base addr of export directory table
	pExportDirectory=GetModuleExportDirectoryAddr(ModuleBaseAddr);

    if (pExportDirectory != NULL)
	{
		//these three structures are the important fields from the export directory...
		//we will add their RVA (relative virtual address) to the base address of the module
		//to form a linear address that we can use to walk the tables each structure points to
		//for names and functions table, this is stored as a pointer to an unsigned long (PULONG)
		AddressOfNames=(PULONG)((ULONG)ModuleBaseAddr+(ULONG)pExportDirectory->AddressOfNames);
		AddressOfNameOrdinals = (PUSHORT)((ULONG)ModuleBaseAddr+(ULONG)pExportDirectory->AddressOfNameOrdinals);
		AddressOfFunctions=(PULONG)((ULONG)ModuleBaseAddr+(ULONG)pExportDirectory->AddressOfFunctions);

		/*
		DbgPrint("\nGetFunctionName():  [0] INFO:  Module base is 0x%08p\n",ModuleBaseAddr);
		DbgPrint("GetFunctionName():  [0] INFO:  Export dir table base is 0x%08p\n",pExportDirectory);
		DbgPrint("GetFunctionName():  [0] INFO:  AddressOfFunctions = 0x%08p\n",AddressOfFunctions);
		DbgPrint("GetFunctionName():  [0] INFO:  AddressOfNames = 0x%08p\n",AddressOfNames);
		DbgPrint("GetFunctionName():  [0] INFO:  AddressOfNameOrdinals is 0x%08p\n",AddressOfNameOrdinals);
		DbgPrint("GetFunctionName():  [0] INFO:  FuncAddr is 0x%08p\n",FuncAddr);
		DbgPrint("GetFunctionName():  [0] INFO:  Number of functions:  %i\n",pExportDirectory->NumberOfFunctions);
		DbgPrint("GetFunctionName():  [0] INFO:  Number of names:  %d\n",pExportDirectory->NumberOfNames);

		DbgPrint("\n\nExport table:");
		DbgPrint("\n--------------------------------------------------");
		DbgPrint("\nOrdinal		Function Address		Name		");
		DbgPrint("\n--------------------------------------------------");
		*/

		//loop through the table of function addresses to find the one we're interested in
		for(i=0;i<(ULONG)pExportDirectory->NumberOfFunctions;i++)
		{
			/*
			uncomment to print the export table..

			DbgPrint("\n%i		%08X		%s",i,*AddressOfFunctions,(PCHAR)((DWORD)ModuleBaseAddr+(*AddressOfNames)));
			AddressOfNames++;
			AddressOfFunctions++;
			AddressOfNameOrdinals++;
			}
			*/

			thisFuncAddr=(ULONG)((DWORD)ModuleBaseAddr+*AddressOfFunctions);
			
			//go ahead and increment for next time
			AddressOfFunctions++;

			//DbgPrint("\nThisFuncAddr: %08X / FuncAddr: %08x ",thisFuncAddr,FuncAddr);

			if(thisFuncAddr == FuncAddr)
			{
				//DbgPrint("\nGetFunctionName():  [0] Address match for %08X at index %d of %d (%08X = %08x)!",FuncAddr,i,pExportDirectory->NumberOfFunctions,thisFuncAddr,FuncAddr);

				//initialize counter ordinal to the first ordinal in the table
				thisOrdinal=AddressOfNameOrdinals;

				//we found the address.  at this point we know this module is the home for this
				//function (ie, it has an entry with that address in its export table)
				//we DONT know, however, if the function is exported by NAME or ORDINAL
				//
				//now we need to loop through ordinals table and if there
				//is a corresponding entry for this index, then there must be a name for the func
				//we can rely on this method b/c the name and ordinal table are always 1:1
				//
				//NB:  the loop condition points to the size of the FunctionNames table, not the
				//ordinal table, b/c the ordinal table has no static count...we must account for
				//this in the body of the loop using a __try/__except block
				for(j=0;j<(ULONG)pExportDirectory->NumberOfFunctions;j++)
				{
					__try
					{	
						//DbgPrint("\nLooking at ordinal %d..",*thisOrdinal);

						if ((ULONG)*thisOrdinal == i)
						{
							//DbgPrint("\nGetFunctionName():  [0] Function name found at ordinal %d",i);

							//add the module base to the address of the name dereferenced
							namePtr=(PCHAR)((DWORD)ModuleBaseAddr+(*(AddressOfNames+j)));

							//DbgPrint("\nGetFunctionName():  [0] Name is '%s'",namePtr);
							nt=RtlStringCbCopyExA(funcNameBuffer,256,namePtr,NULL,NULL,STRSAFE_NULL_ON_FAILURE);
							if (nt != STATUS_SUCCESS)
								DbgPrint("\nGetFunctionName():  [0] Error: RtlStringCbCopyExA() returned %X",nt);
							return TRUE;
						}

					}
					__except(1) {}
					thisOrdinal++;
				}
			}
		}
	}

	return FALSE;
}

//
//TODO..
//
PCHAR GetFunctionNameDbgHelp(ULONG FuncAddr, PCHAR FuncNameDbgHelp)
{
	return NULL;
}

//this function simply finds out how much buffer size we need for loading the module list
ULONG GetInformationClassSize(SYSTEM_INFORMATION_CLASS infoClass)
{
	PVOID sysInfoClassObj;
	NTSTATUS nt=STATUS_SUCCESS;
	ULONG bufsize=4096;
	PULONG returnLength=0;

	do
	{
		sysInfoClassObj=ExAllocatePoolWithTag(NonPagedPool,bufsize,CW_TAG);

		//oops, out of memory...
		if (sysInfoClassObj == NULL)
		{
			DbgPrint("GetInformationClassSize():  [0] Out of memory.\n");
			return 0;
		}

		nt=ZwQuerySystemInformation(infoClass,sysInfoClassObj,bufsize,returnLength);

		if(nt == STATUS_INFO_LENGTH_MISMATCH)
		{
			bufsize+=4096;
			if (sysInfoClassObj != NULL)
				ExFreePoolWithTag(sysInfoClassObj,CW_TAG);
		}
	}
	while(nt == STATUS_INFO_LENGTH_MISMATCH);

	if (nt != STATUS_SUCCESS)
	{
		DbgPrint("GetInformationClassSize():  [0] Error:  ZwQuerySystemInformation() failed.\n");
		return 0;
	}

	if (sysInfoClassObj != NULL)
		ExFreePoolWithTag(sysInfoClassObj,CW_TAG);

	return bufsize;
}

//this function searches the list of loaded modules for the one that owns the function passed in.
//a SYSTEM_MODULE_INFORMATION structure is modified and returned by reference
BOOL GetModInfoByAddress(ULONG FuncAddr, __inout PSYSTEM_MODULE_INFORMATION pEmptyModInfo)
{
	PMODULE_LIST pModuleList=NULL;
	ULONG modstart,modend=0;
	int i;
	ULONG bufsize=GetInformationClassSize(SystemModuleInformation);
	NTSTATUS nt=STATUS_SUCCESS;
	PULONG returnLength=0;

	//make sure pEmptyModInfo has been allocated
	if (pEmptyModInfo == NULL)
	{
		DbgPrint("GetModInfoByAddress():  [0] Error:  pEmptyModInfo must be initialized!\n");
		return FALSE;
	}

	//0 buffer size is returned on failure
	if (bufsize == 0)
		return FALSE;

	//get module list
	pModuleList=ExAllocatePoolWithTag(NonPagedPool,bufsize,CW_TAG);

	//oops, out of memory...
	if (pModuleList == NULL)
	{
		DbgPrint("GetModInfoByAddress():  [0] Out of memory.\n");
		return FALSE;
	}

	nt=ZwQuerySystemInformation(SystemModuleInformation,pModuleList,bufsize,returnLength);

	if (nt != STATUS_SUCCESS)
	{
		DbgPrint("GetModInfoByAddress():  [0] Error:  ZwQuerySystemInformation() failed.\n");
		return FALSE;
	}

	//loop through the module list and find owning module of this function address
	//a module owns it if the function address falls in the module's memory space
	for(i=0;i<(long)pModuleList->ModuleCount;i++)
	{
		//sometimes a module in the module list is null..?
		__try
		{
			if (pModuleList->Modules[i].Size == 0) {}
		}
		__except(1)
		{
			DbgPrint("GetModInfoByAddress():  [0] Warning:  Module #%d of %d has a 0-length size!.\n",i,(long)pModuleList->ModuleCount);
			continue;
		}
			
		modstart=(ULONG)pModuleList->Modules[i].Base;
		modend=modstart+pModuleList->Modules[i].Size;

		//we found the matching MODULE_INFO struct, so memcpy it and quit
		if (FuncAddr > modstart && FuncAddr < modend)
		{
			memcpy(pEmptyModInfo,&pModuleList->Modules[i],sizeof(SYSTEM_MODULE_INFORMATION));
			if (pModuleList != NULL)
				ExFreePoolWithTag(pModuleList,CW_TAG);
			return TRUE;
		}
	}

	if (pModuleList != NULL)
		ExFreePoolWithTag(pModuleList,CW_TAG);

	return FALSE;
}

//this function searches the list of loaded modules for the matching name.
//a SYSTEM_MODULE_INFORMATION structure is modified and returned by reference
//NB:  the passed-in ModuleName must be like "ntoskrnl.exe" or "kernel32.dll"
BOOL GetModInfoByName(PCHAR ModuleName, __inout PSYSTEM_MODULE_INFORMATION modinfo)
{
	PMODULE_LIST pModuleList=NULL;
	ULONG modstart,modend=0;
	int i;
	ULONG bufsize=GetInformationClassSize(SystemModuleInformation);
	NTSTATUS nt=STATUS_SUCCESS;
	PULONG returnLength=0;
	PCHAR nameStart;
	CHAR name[256];
	UINT length;

	//0 buffer size is returned on failure
	if (bufsize == 0)
		return FALSE;

	//get module list
	pModuleList=ExAllocatePoolWithTag(NonPagedPool,bufsize,CW_TAG);

	//oops, out of memory...
	if (pModuleList == NULL)
	{
		DbgPrint("GetModInfoByAddress():  [0] Out of memory.\n");
		return FALSE;
	}

	nt=ZwQuerySystemInformation(SystemModuleInformation,pModuleList,bufsize,returnLength);

	if (nt != STATUS_SUCCESS)
	{
		DbgPrint("GetModInfoByAddress():  [0] Error:  ZwQuerySystemInformation() failed.\n");
		if (pModuleList != NULL)
			ExFreePoolWithTag(pModuleList,CW_TAG);
		return FALSE;
	}

	//loop through the module list and find matching name
	for(i=0;i<(long)pModuleList->ModuleCount;i++)
	{
		//sometimes a module in the module list is null..?
		__try
		{
			if (pModuleList->Modules[i].Size == 0) {}
		}
		__except(1)
		{
			DbgPrint("GetModInfoByName():  [0] Warning:  Module #%d of %d is null!.\n",i,(long)pModuleList->ModuleCount);
			continue;
		}

		//to find the module base name from the module path, we will
		//start copying characters from the address of the base path string
		//plus the basename offset
		nameStart=pModuleList->Modules[i].ImageName+pModuleList->Modules[i].ModuleNameOffset;
		length=256-pModuleList->Modules[i].ModuleNameOffset;

		//now copy that many bytes into our 'name' variable
		memcpy(name,nameStart,length);

		//DbgPrint("GetModInfobyName():  Loaded system module:  %s",name);

		//we found the matching MODULE_INFO struct, so memcpy it and quit
		if (strcmp(ModuleName,name) == 0)
		{
			memcpy(modinfo,&pModuleList->Modules[i],sizeof(SYSTEM_MODULE_INFORMATION));
			if (pModuleList != NULL)
				ExFreePoolWithTag(pModuleList,CW_TAG);
			return TRUE;
		}
	}

	if (pModuleList != NULL)
		ExFreePoolWithTag(pModuleList,CW_TAG);

	return FALSE;
}

//returns TRUE if the given address falls within the module address's memory range
BOOL IsAddressWithinModule(ULONG FunctionAddress,ULONG ModuleBaseAddress,ULONG ModuleSize)
{
	if (FunctionAddress > ModuleBaseAddress && (FunctionAddress < (ModuleBaseAddress+ModuleSize)))
		return TRUE;
	return FALSE;
}

//returns true or false if the function's 5-byte prologue is patched with a 
//near or far JMP/CALL instruction, and iff the target of said instruction falls
//outside of the module's address range.  also modifies the supplied DETOURINFO structure
BOOL IsFunctionPrologueDetoured(DWORD FuncAddr, DWORD ModuleBaseAddr, DWORD ModuleSize, PDETOURINFO d)
{
	NTSTATUS nt;
	PSYSTEM_MODULE_INFORMATION pMod;
	BOOL DetourFound=FALSE;
	BOOL doSkipOperand=FALSE;
	PCHAR pUnknownBuf="[unknown detouring module]";
	ULONG addr=0;
	//UNICODE strings for comparison and conversion
	UNICODE_STRING uTargetAddress;
	UNICODE_STRING uMnemonic;
	UNICODE_STRING uJmpString;
	UNICODE_STRING uCallString;
	PCUNICODE_STRING addr2;
	wchar_t wstrTargetAddress[15];
	WCHAR wstrMnemonic[60];
	WCHAR wTargetAddress[15];
	CHAR SegmentSelector[15];
	CHAR Offset[31];
	int i,j,k;
	//distorm
	int numBytesToDisasm=25;
	int numDisassembled=0;
	_DecodedInst disassembly[MAX_INSTRUCTIONS];
	//end distorm

	//prep work
	RtlZeroMemory(d,sizeof(DETOURINFO));
	RtlInitUnicodeString(&uJmpString,L"JMP FAR");
	RtlInitUnicodeString(&uCallString,L"CALL FAR");

	//DbgPrint("\nIsFunctionPrologueDetoured():  Observing prologue of function at address 0x%08p\n",FuncAddr);

	///////////////////////////////////////////
	//										 //
	//			BEGIN DISASSEMBLY		     //
	//										 //
	///////////////////////////////////////////
	//
	//using diStorm open source diassembler, try to disassemble 25 bytes of prologue
	//starting from the start address of this function
	//credit:  http://ragestorm.net/distorm/
	//
	if (diStorm_Disasm(FuncAddr,numBytesToDisasm,disassembly,&numDisassembled))
	{
		for(i=0;i<numDisassembled;i++)
			d->decodedInstructions[i]=disassembly[i];
		d->numDisassembled=numDisassembled;
	}

	//DbgPrint("\nIsFunctionPrologueDetoured():  There are %i disassembled instructions.\n",d->numDisassembled);

	//loop through resulting 25-byte disassembly and parse any CALL or JMP's
	for(j=0;j<d->numDisassembled;j++)
	{
		doSkipOperand=FALSE;

		//convert the ASCII CHAR string to WCHAR then to unicode for comparison
		RtlStringCchPrintfW(wstrMnemonic,60,L"%S",d->decodedInstructions[j].mnemonic.p);
		RtlInitUnicodeString(&uMnemonic,(PCWSTR)wstrMnemonic);
		
		/*DbgPrint("\nIsFunctionPrologueDetoured():  Variables:\n");
		DbgPrint("      mnemonic:  %s\n",d->decodedInstructions[j].mnemonic.p);
		DbgPrint("      wstrMnemonic:  %S\n",wstrMnemonic);
		DbgPrint("      uMnemonic:  %wZ\n",&uMnemonic);
		DbgPrint("      uJmpString:  %wZ\n",&uJmpString);
		DbgPrint("      uCallString:  %wZ\n",&uCallString);
		*/

		//if it is a jmp or a call, do further processing
		if (RtlCompareUnicodeString(&uMnemonic,&uJmpString,TRUE) == 0 || RtlCompareUnicodeString(&uMnemonic,&uCallString,TRUE) == 0)
		{
			//DbgPrint("\nIsFunctionPrologueDetoured():  Match on %wZ!\n",&uMnemonic);

			//the .operands field is a comma-separated list of up to 3 operands
			//for jmp/call, we dont want any with commas, skip them
			for(k=0;k<(int)d->decodedInstructions[j].operands.length;k++)
			{
				if (d->decodedInstructions[j].operands.p[k] == ',')
				{
					//DbgPrint("\nIsFunctionPrologueDetoured():  Skipping instruction with multiple operands:  '%s'\n",d->decodedInstructions[j].operands.p);
					doSkipOperand=TRUE;
					break;
				}
			}

			//if multi-operand, skip
			if (doSkipOperand)
				continue;

			//first, try to parse a segment_selector:offset argument to the CALL/JMP
			//if this fails (ie, the argument has no colon), assume immediate address
			if (GetFarCallData(d->decodedInstructions[j].operands.p,d->decodedInstructions[j].operands.length,SegmentSelector,Offset))
			{
				//DbgPrint("\nIsFunctionPrologueDetoured():  Found FAR JMP or FAR CALL.");
				//convert the ASCII CHAR string to WCHAR then to unicode for comparison
				RtlStringCchPrintfW(wTargetAddress,15,L"%S",Offset);
			}
			//otherwise, fill the target address with the immediate operand
			else
			{
				//convert the ASCII CHAR string to WCHAR then to unicode for comparison
				RtlStringCchPrintfW(wTargetAddress,15,L"%S",d->decodedInstructions[j].operands.p);
			}
			
			//DbgPrint("      wTargetAddress:  %ws\n",&wTargetAddress);
			RtlInitUnicodeString(&uTargetAddress,(PCWSTR)wTargetAddress);
			//DbgPrint("      uTargetAddress:  %wZ\n",&uTargetAddress);
			//convert the unicode string to a 64-bit integer
			nt=RtlUnicodeStringToInteger(&uTargetAddress,0,&addr);
			if (nt==STATUS_SUCCESS) //if the conversion succeeded, dereference the converted ULONG
				d->TargetAddress=(DWORD)addr;
			else
				d->TargetAddress=0; //otherwise, bail.

			//DbgPrint("      Target Addr as integer:  %ul\n",d->TargetAddress);

			//find the module who owns this target address
			pMod=ExAllocatePoolWithTag(NonPagedPool,sizeof(SYSTEM_MODULE_INFORMATION),CW_TAG);
			if (pMod == NULL)
			{
				DbgPrint("%s","IsFunctionPrologueDetoured():  out of memory.");
				return FALSE;
			}

			GetModInfoByAddress(d->TargetAddress,pMod);

			if (pMod != NULL)
			{
				RtlStringCbCopyExA(d->detouringModule,256,pMod->ImageName,NULL,NULL,0);
				ExFreePoolWithTag(pMod,CW_TAG);
			}
			else
				RtlStringCbCopyExA(d->detouringModule,256,pUnknownBuf,NULL,NULL,0);

			//if the target of the CALL or JMP is not in this module's memory address range,
			//this is a highly suspicious execution flow alteration
			if (!IsAddressWithinModule(d->TargetAddress,ModuleBaseAddr,ModuleSize))
				DetourFound=TRUE;
				//DbgPrint("\nIsFunctionPrologueDetoured():  Detour found!  Target address 0x%08X is outside of range 0x%08X - 0x%08X\n",d->TargetAddress,ModuleBaseAddr,ModuleBaseAddr+ModuleSize);
			//else
				//DbgPrint("\nIsFunctionPrologueDetoured():  Target address 0x%08X is within range 0x%08X - 0x%08X\n",d->TargetAddress,ModuleBaseAddr,ModuleBaseAddr+ModuleSize);
		}
		//else
		//{
			//DbgPrint("\nIsFunctionPrologueDetoured():  %wZ is not a JMP/CALL...\n",&uMnemonic);
		//}
	}

	//ExFreePoolWithTag(pDisassembly,CW_TAG);

	/*

	//starting from the very first instruction (ie, the address of this function),
	//loop until we have read 5 instructions
	while (count < 5)
	{
		//get the opcode by dereferencing the pointer to the current location in memory
		InstructionOpcode = *((PBYTE)eip);

		//DbgPrint("\nLooking at opcode:  %03X",InstructionOpcode);

		//************
		//STORE STUFF
		//************
		p_x86=ExAllocatePoolWithTag(NonPagedPool,sizeof(x86ASM),CW_TAG);
		p_x86->InstructionOpcode=InstructionOpcode;
		p_x86->InstructionSize=1;	//we only support 1-byte instructions!
		//get the size of the operand of this instruction
		//if less than 0, it is an unsupported opcode
		opsize=Getx86OperandSize(InstructionOpcode);
		p_x86->OperandSize=opsize;
		//step over our current address and then dereference 32 bits
		//even if the operand is 8bit, it will be extended to 32-bit
		p_x86->OperandBytes=*((DWORD*)(eip+1));

		//************
		//ANALYZE STUFF
		//************

		if (!IsJmpOrCallOpcode(InstructionOpcode))
			continue;		
		
		//if the opcode is a CALL or JMP, analyze the target address of that instruction to see if it's being detoured.
		if (IsJmpOrCallOpcode(InstructionOpcode))
		{
			//relative short jmp (0xeb)
			//we dont care about this jmp b/c it can only go 255 bytes
			if (InstructionOpcode == 0xEB)
			{
				//the code below always copies 4 bytes
				TargetAddress=eip+1+p_x86->OperandBytes;
				p_x86->JmpCallType=0;
			}
			//relative near jmp (0xe9): 
			//-------------------------
			//	-target is relative to the address of the next instruction
			//	-formula to calculate target address:
			//		 Target=eip+1+relativeAddress
			//	-the operand size is always an 8-bit signed displacement
			else if (InstructionOpcode == 0xE9)
			{
				TargetAddress=eip+1+p_x86->OperandBytes;
				p_x86->JmpCallType=1;
			}
			//
			//relative near call (0xe8)
			//-------------------------
			//same as 0xe9, except 16 or 32 bit offset
			else if (InstructionOpcode  == 0xE8)
			{
				TargetAddress=eip+1+p_x86->OperandBytes;
				p_x86->JmpCallType=3;
			}
			//
			//far jump (0xEA) and far call (0x9A)
			//-----------------------------------
			//formula to calculate target address:
			//		BaseAddrOfSegmentInGDTorLDT+SegmentOffset
			//see gdt.c
			else if (InstructionOpcode == 0xEA || InstructionOpcode == 0x9A)
			{
				//for these opcodes, the argument to the JMP/CALL is of the format
				//XXXX:XXXX (ptr16:16) or XXXX:XXXXXXXX (ptr16:32)
				//
				//we find this argument 1 byte from the JMP instruction.
				//the operand size is at least 32 bits (16:16) and at most 48 bits (16:32).
				//but we know the seg selector is 16bit, so pass a ptr to that and the
				//rest will be determined from GDT/LDT later
				WORD* segmentSelector = (WORD*)(eip+1);

				//convert the logical address to a linear address.
				//this involves parsing the segment selector (left of colon) and
				//finding the corresponding descriptor entry in the gdt or ldt;
				//then extract the segment base address from that descriptor and add
				//it to the segment offset (to the right of the colon)
				TargetAddress=GetLinearAddressFromDescriptor(segmentSelector);

				if (InstructionOpcode == 0xEA)
					p_x86->JmpCallType=2;
				else
					p_x86->JmpCallType=4;
			}

			//now we have a target address for this JMP/CALL instruction
			//find the module who owns this function
			pMod=ExAllocatePoolWithTag(NonPagedPool,sizeof(SYSTEM_MODULE_INFORMATION),CW_TAG);
			GetModInfoByAddress((ULONG)TargetAddress,pMod);
			if (pMod != NULL)
				RtlStringCbCopyExA(d->detouringModule,256,pMod->ImageName,NULL,NULL,0);
			else
				RtlStringCbCopyExA(d->detouringModule,256,pUnknownBuf,NULL,NULL,0);
			ExFreePoolWithTag(pMod,CW_TAG);

			//check the range of the target address to see if it falls
			//in the address space of the specified module
			if(!IsAddressWithinModule((ULONG)TargetAddress,(ULONG)ModuleBaseAddr,(ULONG)ModuleSize))
				DetourFound=TRUE;
			else
				DbgPrint("\nTarget address 0x%08X is within range 0x%08X - 0x%08X\n",TargetAddress,ModuleBaseAddr,ModuleBaseAddr+ModuleSize);
		}

		d->x86[count]=*p_x86;

		//************
		//NEEEEEEEEXT
		//************
		//increment eip (instruction pointer) by 5
		eip+=5;
		//increment counter
		count++;
	}
	*/

	return DetourFound;
}

BOOL GetFarCallData(CHAR instruction[60],int length, PCHAR segmentSelector, PCHAR offset)
{
	int i,locColon=0;

	//format of instruction array:
	//	0x08:0xABCDEFGH
	
	//parse the segment selector (0x08)
	for(i=0;i<length;i++)
	{
		if (instruction[i] == ':')
		{
			if (locColon > 0)
			{
				RtlCopyMemory(segmentSelector,instruction,locColon);
				break;
			}
		}
		else
			locColon++;
	}

	//failed to get ss, bail...
	if (locColon <= 0 || locColon == length)
		return FALSE;

	//bounds check
	if (length-(locColon+1) > 60)
		return FALSE;

	//parse the offset (0xABCDEFGH)
	//copy the rest of the instruction string into the offset buffer
	RtlCopyMemory(offset,instruction+locColon+1,length-locColon);

	return TRUE;
}