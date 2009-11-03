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
#include "x86.h"

//this function returns a distorm x86 disasm structure
//credit:  http://www.ragestorm.net/distorm
//explanation of arguments:
//		StartAddress:  address of instructions to start disassembling from
//		Length:  number of bytes to decode starting at CodeOffset
//		disasm:  a structure to store the resulting disassembly
//		numDisassembled:  number of instructions successfully disassembled
//
//returns true or false based on disasm result.
//
BOOL diStorm_Disasm(ULONG StartAddress, int length, _DecodedInst disasm[], int* numDisassembled)
{
	// Holds the result code of the decoding:
	//		DECRES_SUCCESS - it worked.
	//		DECRES_INPUTERR - invalid decoding mode or opcode
	//		DECRES_MEMORYERR - result array is too small for diassembly
	_DecodeResult res;
	// Buffer to disassemble - initialize to start address
	unsigned char *buf=(PUCHAR)StartAddress;
	// next is used for instruction's offset synchronization.
	// decodedInstructionsCount holds the count of filled instructions' array by the decoder.
	unsigned int i, next;
	UINT len=length;
	// Default decoding mode is 32 bits, could be set by command line.
	_DecodeType dt = Decode32Bits;
	//since we are always starting at a function prologue, the offset is always
	//the same as the passed-in address
	_OffsetType offset = (_OffsetType)StartAddress;
	char* errch = NULL;

	while (1) 
	{
		//the first parameter, "offset", must be the linear address of the function
		//for our purposes, since we are always starting at the function prologue,
		//the first two parameters will always be the same.
		//that is being disassembled.  ie, MmGetSystemRoutineAddress()!
		res = distorm_decode(offset, (const unsigned char*)buf, len, dt, disasm, MAX_INSTRUCTIONS, numDisassembled);
		
		//There was a problem with the supplied buffer!
		if (res == DECRES_INPUTERR) 
		{
			//DbgPrint("\ndiStorm_Disasm():  Error:  Null buffer.\n");
			return FALSE;
		}
		//all's well...
		else if (res == DECRES_SUCCESS || *numDisassembled == 0) 
		{
			//DbgPrint("\ndiStorm_Disasm():  Successfully decoded %i instructions.\n",*numDisassembled);
			return TRUE;
		}
		else
		{
			//DbgPrint("\ndiStorm_Disasm():  Return code = %d.\n",res);
		}


		//Synchronize:  
		//get the offset of the last disassembled instruction
		//and add its size to form a pointer to the next instruction to look at
		//
		//this is essentially (disasm[numDisassembled-1].offset - offset)+disasm[numDisassembled-1].size
		//
		next = ((unsigned int)(*(disasm+(*numDisassembled-1))).offset - offset)+(unsigned int)(*(disasm+(*numDisassembled-1))).size;

		//DbgPrint("\ndiStorm_Disasm():  Next instruction located at %08X.\n",next);

		// Advance ptr and recalc offset.
		buf += next;
		len -= next;
		offset += next;
	}

	return TRUE;
}


BOOL IsJmpOrCallOpcode(BYTE opcode)
{
	if (opcode == 0xE8 || opcode == 0xE9 || opcode == 0xEA || opcode == 0x9A || opcode == 0xEB || opcode == 0x66)
		return TRUE;
	return FALSE;
}

int Getx86OperandSize(BYTE opcode)
{
	//SHORT JMP (intramodular)
	if (opcode == 0xEB)		//8 bit relative offset
		return 1;
	//NEAR JMP and NEAR CALL (intramodular)
	else if (opcode == 0xE9 || opcode == 0xE8)		//16 or 32 bit relative offset
		return 4;
	//FAR JMP and FAR CALL (different code segment)
	else if (opcode == 0xEA || opcode == 0x9A)		//16:16 or 16:32 ptr
		return 7;
	//default to 4 bytes
	else
		return 4;
}

PWCHAR Getx86Instruction(BYTE opcode)
{
	/*JMP*/
	if (opcode == 0xEB || opcode == 0xEA || opcode == 0xE9)
		return TEXT(L"JMP ");
	/*CALL*/
	else if (opcode == 0xE8 || opcode == 0x9A)
		return TEXT(L"CALL ");
	/*ADD*/
	else if (opcode == 0x00 ||  opcode == 0x01 ||  opcode == 0x02 || opcode == 0x03 ||
			opcode == 0x04 || opcode == 0x05)
			return TEXT(L"ADD ");
	/*SUB*/
	else if (opcode == 0x28 ||  opcode == 0x29 ||  opcode == 0x2A || opcode == 0x2B ||
			opcode == 0x2C || opcode == 0x2D)
		return TEXT(L"SUB ");
	/*MOV*/
	else if (opcode == 0x88 ||  opcode == 0x89 ||  opcode == 0x8A || opcode == 0x8B ||
			opcode == 0x8C || opcode == 0x8E || opcode == 0xA0 ||  opcode == 0xA1 ||  opcode == 0xA2 || opcode == 0xA3 ||
			opcode == 0xA4 || opcode == 0xA5 || (opcode >= 0xB0 && opcode <=0xBF))
		return TEXT(L"MOV ");
	/*PUSH*/
	else if (opcode == 0x06 ||  opcode == 0x16 || (opcode >= 0x50 && opcode <= 0x57) ||
			opcode == 0x60 || opcode == 0x0E || opcode == 0x1E ||  opcode == 0x68 ||  opcode == 0x6A || opcode == 0x9C)
		return TEXT(L"PUSH ");
	/*unsupported*/
	else
		return TEXT(L"??? ");
}