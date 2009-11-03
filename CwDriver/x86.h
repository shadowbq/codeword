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
// * x86.h 
//
// * ChangeLog
// 
// * 7/3/2009 - AL - forked from kgsp project
// * 3/19/2009 - AL - first version.
//
//////////////////////////////////////////////////////////////////////////////
#ifndef __x86_h__
#define __x86_h__

#include "distorm.h"

// diStorm disassembler #define:
// The number of the array of instructions the decoder function will use to return the disassembled instructions.
// Play with this value for performance...
#define MAX_INSTRUCTIONS 15

BOOL diStorm_Disasm(ULONG, int, _DecodedInst*, int*);
BOOL GetOpcode(ULONG, BYTE*);
int Getx86OperandSize(BYTE);
PWCHAR Getx86Instruction(BYTE);
BOOL IsJmpOrCallOpcode(BYTE);

#endif