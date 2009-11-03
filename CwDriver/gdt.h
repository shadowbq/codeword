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
// * gdt.h 
//
// * ChangeLog
// 
// * 7/3/2009 - AL - forked from kgsp project
// * 3/19/2009 - AL - first version.
//
//////////////////////////////////////////////////////////////////////////////

//********************************************************************
//
//Note:  all structures below are built based on information from
//Intel's whitepaper "Overview of the Protected Mode Operation of 
//the Intel Architecture" by Steve Gorman, available via URL:
//		http://www.intel.com/design/intarch/papers/exc_ia.htm
//
//also:
//		http://www.intel.com/products/processor/manuals/index.htm
//
//********************************************************************

#ifndef __GDT_h__
#define __GDT_h__

/* reserved				0x00							*/
#define STYPE_TSS16A	0x01 /* 16-bit TSS (Available)	*/
#define STYPE_LDT		0x02 /* LDT						*/
#define STYPE_TSS16B	0x03 /* 16-bit TSS (Busy)		*/
#define STYPE_CALL16	0x04 /* 16-bit Call Gate		*/
#define STYPE_TASK		0x05 /* Task Gate				*/
#define STYPE_INT16		0x06 /* 16-bit Interrupt Gate	*/
#define STYPE_TRAP16	0x07 /* 16-bit Trap Gate		*/
/* reserved				0x08							*/
#define STYPE_TSS32A	0x09 /* 32-bit TSS (Available)	*/
/* reserved				0x0A							*/ 
#define STYPE_TSS32B	0x0B /* 32-bit TSS (Busy)		*/
#define STYPE_CALL32	0x0C /* 32-bit Call Gate		*/
/* reserved				0x0D							*/
#define STYPE_INT32		0x0E /* 32-bit Interrupt Gate	*/
#define STYPE_TRAP32	0x0F /* 32-bit Trap Gate		*/

//GDT definition
//struct as returned by x86 instruction for sgdt
//GDT is a 48-bit structure.  Max 8192 entries.
typedef struct
{
	unsigned short BaseLimit; //16-bit variable indicating # bytes in table
	unsigned short BaseLow;	//lower 16-bits of table's base address
	unsigned short BaseHigh;  //upper 16-bits of table's base address
} GDT,*PGDT;

//LDT definition
//struct as returned by x86 instruction for sldt
//LDT is a 64-bit structure.  max 8192 entries.
//LDT is a segment itself; ie, LDT has a descriptor entry in the GDT.
typedef struct
{
	unsigned short BaseLimit;			//16-bit variable indicating # bytes in table
	unsigned short BaseLow;			//lower 16-bits of table's base address
	unsigned short BaseHigh;			//upper 16-bits of table's base address
	unsigned short SegmentSelector;   //16-bit selector
} LDT,*PLDT;

//struct of a segment selector
typedef struct
{
	unsigned char rpl;			//bit 0 -> requested privilege level
	unsigned char ti;			//bit 1 -> table indicator; 0=GDT, 1=LDT
	unsigned char index[14];	//bits 2-15 -> index; indicates which descriptor to fetch in GDT/LDT

} SEGMENT_SELECTOR, *PSEGMENT_SELECTOR;

//struct of a segment descriptor (2x32-bit)
//all descriptors are 64 bits in size and reside in GDT/LDT
//types include:  call gate, task segment selector (tss), etc
typedef struct
{	
	/*
	
	Structure of a segment descriptor (not really 2 scale):

	63													  32
	______________________________________________________
	|		|	|	|	|	|S | |   | |    |	          |
	|  Base | G | DB| 0 |AVL|L |P|DPL|S|Type|	Base      |
	31----------------------------------------------------0
	|                          |                          |
	|		Base Address       |      Segment Limit       |
	|                          |                          |
	_______________________________________________________

	*/
	//
	//
	//first WORD (bits 0-15) 
	//
	unsigned short segment_limit;
	//
	//second WORD (bits 16-32)
	unsigned short base_address;
	//
	//third WORD (bits 32-48)
	//
	unsigned char base;				//bits 0-7
	unsigned char type[4];				//bits 8-11;
	unsigned char desc_type;			//bit 12; //descriptor type; 0=segment descriptor, 1=system descriptor
	unsigned char dpl;					//bits 13-14;
	unsigned char present;				//bit 15
	//
	//fourth WORD (bits 49-64)
	//
	unsigned char limit_middle[3];		//bits 0-3
	unsigned char available;			//bit 4; available bit; unused
	unsigned char zero;				//um...it's 0..?
	unsigned char db;					//D/B=default/big bit for code segments representing the default operand size (16 or 32 bit)
	unsigned char granularity;			//used to determine if the limit is checked on byte or 4KB page granularity
	unsigned char base_high;			//last 8 bits: base addr of segment

} SEGMENT_DESCRIPTOR, *PSEGMENT_DESCRIPTOR;

//further attributes of descriptor type
typedef struct subtype
{
	union
	{
		struct 
		{
			unsigned char		accessed;
			unsigned char		write_enable;
			unsigned char		expansion_direction;
			unsigned char		zero;
		} datatype;

		struct 
		{
			unsigned char		accessed;
			unsigned char		read_enable;
			unsigned char		conforming;
			unsigned char		one;
		} codetype;
		unsigned char	systemtype;
		unsigned char	databyte;
	} u;
	
} SUBTYPE, *PSUBTYPE;

DWORD GetLinearAddressFromDescriptor(WORD*);
DWORD GetLinearAddressFromGDT(GDT, PSEGMENT_SELECTOR);
DWORD GetLinearAddressFromLDT(LDT, PSEGMENT_SELECTOR);

#endif
