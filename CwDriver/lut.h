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
// * lut.h 
//
// * ChangeLog
// 
// * 7/3/2009 - AL - forked from kgsp project
// * 4/7/2009 - AL - table updated.
//
// * Notes
// *
// * About this table:
// * 
// * This lookup table (LUT) is built from the syscall table built by the metasploit project
// * which is located at the following URL:
// *		http://www.metasploit.com/users/opcode/syscalls.html
// * This LUT is built from manual referencing using WinDbg for known OS versions.
// *
// * How to build this table:
// *
// *	1.  run the php script GetLookupTable.php - it generates an HTML table in SyscallLookupTable.html
// *    2.  manually copy/paste the generated html table into excel.
// *    3.  export the spreadsheet to a CSV named LUT.csv (make sure empty cells get a comma!)
// *    4.  run GetCStructuresFromLUT.php to generate the code below.
// *	5.  change NUM_COLS and NUM_ROWS below to match spreadsheet dimensions.
// *    6.  paste the data from #4 in the specified location in lut.c
// *	7.  update the ChangeLog above.
// *
//////////////////////////////////////////////////////////////////////////////

//---------------------------------------------------------------
//
//	TABLE FORMAT
//
//---------------------------------------------------------------

//_____________________________________________________________________________
//|  Function Name	| WIN NT |    Win2k    |  WinXP  |  Win2k3Srv  |   Vista  |
//|-----------------|--------|-------------|---------|-------------|----------|
//|					|SP3->SP6|  SP0->SP4   | SP0-SP2 | SP0  |  SP1 |    SP0   |
//|_________________|________|_____________|_________|______|______|__________|
//| NtConnectPort   |0|0|0|0 |             |         |      |      |          |
//|_________________|________|_____________|_________|______|______|__________|
//| ...........
//| ............
//|____________________________________________________________________________
//---------------------------------------------------------------

#ifndef __LUT_h__
#define __LUT_h__
//
//update these variables to match the spreadsheet dimensions
//
#define LUT_NUM_COLS 15		//number of columns in spreadsheet (minus name column)
#define LUT_NUM_ROWS 410	//number of rows in spreadsheet

BOOL LUT_INITIALIZED;
PCHAR KnownGood_ServiceFunctionNames[LUT_NUM_ROWS];
DWORD KnownGood_ServiceFunctionIndices[LUT_NUM_ROWS][LUT_NUM_COLS];

VOID LoadLUT();
#endif