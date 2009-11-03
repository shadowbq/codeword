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
// * win32apicheck.h 
//
// * ChangeLog
// 
// * 7/12/2009 - AL - first version
//
//////////////////////////////////////////////////////////////////////////////

#ifndef __WIN32APICHECK_h__
#define __WIN32APICHECK_h__

//custom structure to hold info about detours
typedef struct _WIN32API_DETOUR_ENTRY
{
	ULONG ExportAddress;
	CHAR ExportName[256];
	CHAR Disassembly[25][256];
	CHAR DetouringModule[256];
	ULONG TargetAddress;
	BOOL IsDetoured;
	BOOL IsUnknown;
} WIN32API_DETOUR_ENTRY,*PWIN32API_DETOUR_ENTRY;

//table structure to hold a range of detour structures
typedef struct _WIN32API_DETOUR_TABLE
{
	int NumDetours;
	CHAR ModuleName[256];
	WIN32API_DETOUR_ENTRY Win32Detours[512];
} WIN32API_DETOUR_TABLE,*PWIN32API_DETOUR_TABLE;

NTSTATUS CheckModuleExportsForDetours(__in PCHAR, __inout PWIN32API_DETOUR_TABLE);
ULONG GetModuleExportNames(__in DWORD, __inout PCHAR*[],__in ULONG, __in ULONG);

#endif