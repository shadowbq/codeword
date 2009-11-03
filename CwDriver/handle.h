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
// * handle.h 
//
// * ChangeLog
// 
// * 7/3/2009 - AL - forked from kgsp project
// * 3/19/2009 - AL - first version.
//
//////////////////////////////////////////////////////////////////////////////
VOID FindPhysmemHandles();
UINT GetHandleListSize();
BOOL GetHandleInfo(ULONG,HANDLE,PUNICODE_STRING,int*,int*);
VOID GetProcessNameByPid(ULONG,PUNICODE_STRING);