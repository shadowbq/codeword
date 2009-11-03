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
// * module.h 
//
// * ChangeLog
// 
// * 7/3/2009 - AL - forked from kgsp project
// * 3/19/2009 - AL - first version.
//
//////////////////////////////////////////////////////////////////////////////
#ifndef __MODULE_h__
#define __MODULE_h__

//structure for view of detour data
typedef struct __DETOURINFO
{
	//data from diStorm disassembler
	_DecodedInst decodedInstructions[MAX_INSTRUCTIONS];
	int numDisassembled;		//how many instructions were successfully disassembled
	//data from analysis of assembler results
	BYTE InstructionOpcode;		//eg, JMP can be 0xE9
	UINT InstructionSize;		//eg 1 byte or 2 byte
	DWORD TargetAddress;		//if the inst is a jmp/call, record the target address
	int OperandSize;			//e.g., 1 byte, 2 byte, 4 byte
	int JmpCallType;			//0=short jmp
								//1=near jmp
								//2=far jmp
								//3=near call
								//4=far call
	CHAR detouringModule[256];	//the name of the module containing the detouring function

} DETOURINFO,*PDETOURINFO;

BOOL GetModInfoByName(PCHAR,PSYSTEM_MODULE_INFORMATION);
BOOL GetModInfoByAddress(ULONG,PSYSTEM_MODULE_INFORMATION);
BOOL IsAddressWithinModule(ULONG,ULONG,ULONG);
PIMAGE_EXPORT_DIRECTORY GetModuleExportDirectoryAddr(PVOID);
BOOL GetFunctionName(PVOID,ULONG,__inout PCHAR);
BOOL IsFunctionPrologueDetoured(__in DWORD, __in DWORD, __in DWORD, __inout PDETOURINFO);
PCHAR GetFunctionNameDbgHelp(ULONG, PCHAR);
ULONG GetInformationClassSize(SYSTEM_INFORMATION_CLASS);
BOOL GetFarCallData(CHAR [],int, PCHAR, PCHAR);

#endif
