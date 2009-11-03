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

//this function returns a 32-bit linear address that it calcualted
//by looking up the passed-in segment selector from the GDT or LDT
//NB:  even though the argument type is PWORD, the actual arg length
//can be 32 or 48 -bit depending on segment selector type; but we know
//the first 16-bits are the segment selector (XXXX:XXXX[XXXX])
DWORD GetLinearAddressFromDescriptor(WORD* SegmentSelector)
{
	int i;
	GDT gdt;
	LDT ldt;
	PSEGMENT_SELECTOR ss = ((PSEGMENT_SELECTOR)(*SegmentSelector));
	UCHAR table=ss->ti;
	DWORD address=0;

	//parse segment selector (ss) to see if we need to pull from GDT or LDT
	//0 = GDT
	//1 = LDT
	__asm
	{
		push ecx;
		mov cl,table;
		cmp cl,0;
		jz g;
		sldt ldt;
		jmp end;
		g:
			sgdt gdt;
		end:
			pop ecx;
	}

	if (table == 0)
		address=GetLinearAddressFromGDT(gdt,ss);
	else if (table == 1)
		address=GetLinearAddressFromLDT(ldt,ss);	

	return address;
}

DWORD GetLinearAddressFromGDT(GDT gdt, PSEGMENT_SELECTOR ss)
{
	DWORD SegmentOffset=0;
	int i;

	//get the address of the base of the table
	DWORD TableAddr = MAKELONG(gdt.BaseLow, gdt.BaseHigh);

	//initialize our first segment descriptor entry
	PSEGMENT_DESCRIPTOR thisTableEntry = (PSEGMENT_DESCRIPTOR)TableAddr;

	//note: we start iterating from 1, b/c 0 is never used according to intel
	for(i=1;i<=(int)gdt.BaseLimit;i++)
	{
		//are we at the index in the GDT that was specified in the index bits of the segment selector?
		//if so, shift in 29 zeros for high base address, add to 24-bit segment_base
		//shifted in 8 zeros, added to the provided segment offset
		if (i == (int)ss->index)
		{
			//if 1 , read 32 bits starting from 3 bytes forward 
			//		-->skip 2 bytes for segment selector and 1 for ":"
			if (thisTableEntry->db == 1)
				SegmentOffset=*((DWORD*)(ss+3));
			//if 0, read 16 bits, skipping 3 bytes -- extended to 32-bit:
			//		0xffff >> 16 = 0x0000ffff
			else
				SegmentOffset=*((WORD*)(ss+3));

			return ((thisTableEntry->base_high)<<24)+((thisTableEntry->base)>>24)+SegmentOffset;
		} 
	}

	return 0;
}

DWORD GetLinearAddressFromLDT(LDT ldt, PSEGMENT_SELECTOR ss)
{
	DWORD SegmentOffset=0;
	int i;

	//get the address of the base of the table
	DWORD TableAddr = MAKELONG(ldt.BaseLow, ldt.BaseHigh);

	//initialize our first segment descriptor entry
	PSEGMENT_DESCRIPTOR thisTableEntry = (PSEGMENT_DESCRIPTOR)TableAddr;

	//note: we start iterating from 1, b/c 0 is never used according to intel
	for(i=1;i<=(int)ldt.BaseLimit;i++)
	{
		//are we at the index in the GDT that was specified in the index bits of the segment selector?
		//if so, shift in 29 zeros for high base address, add to 24-bit segment_base
		//shifted in 8 zeros, added to the provided segment offset
		if (i == (int)ss->index)
		{
			//if 1 , read 32 bits starting from 3 bytes forward 
			//		-->skip 2 bytes for segment selector and 1 for ":"
			if (thisTableEntry->db == 1)
				SegmentOffset=*((DWORD*)(ss+3));
			//if 0, read 16 bits, skipping 3 bytes -- extended to 32-bit:
			//		0xffff >> 16 = 0x0000ffff
			else
				SegmentOffset=*((WORD*)(ss+3));

			return ((thisTableEntry->base_high)<<24)+((thisTableEntry->base)>>24)+SegmentOffset;
		}
	}

	return 0;
}