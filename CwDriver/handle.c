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
#include "x86.h"
#include "module.h"
#include "handle.h"
#include <ntstrsafe.h>

VOID FindPhysmemHandles()
{
	PHANDLE_LIST pHandleList;
	ULONG bufsize=GetInformationClassSize(SystemHandleInformation);
	ULONG returnLength=0;
	int nameFail=0,otherFail=0,numFound=0;
	CHAR ModuleName[256];
	PCHAR nameStart;
	NTSTATUS nt;
	UNICODE_STRING ObjectName;
	UNICODE_STRING DevicePhysicalMemory;
	PVOID Object;
	int i;

	//front matter
	DWORD* buff=(DWORD*)ExAllocatePoolWithTag(NonPagedPool,4096,CW_TAG);
	RtlInitUnicodeString(&DevicePhysicalMemory,L"\\Device\\PhysicalMemory");

	//0 buffer size is returned on failure
	if (bufsize == 0)
		return;

	pHandleList=(PHANDLE_LIST)ExAllocatePoolWithTag(NonPagedPool,bufsize,CW_TAG);

	//oops, out of memory...
	if (pHandleList == NULL)
	{
		DbgPrint("\nFindPhysmemHandles():  [0] Out of memory.\n");
		return;
	}

	nt=ZwQuerySystemInformation(SystemHandleInformation,pHandleList,bufsize,&returnLength);

	if (nt != STATUS_SUCCESS)
	{
		DbgPrint("\nFindPhysmemHandles():  [0] Error:  ZwQuerySystemInformation() failed.\n");
		return;
	}

	DbgPrint("\nFindPhysmemHandles():  [0] Found %d handles.\n",pHandleList->HandleCount);

	//loop through the list of open handles across the system and match any that
	//have the name \\Device\\PhysicalMemory and then inspect the owner of that handle
	for(i=0;i<(long)pHandleList->HandleCount;i++)
	{
		if (GetHandleInfo(pHandleList->Handles[i].ProcessId,(HANDLE)pHandleList->Handles[i].Handle,&ObjectName,&nameFail,&otherFail))	
		{
			if (RtlCompareUnicodeString(&ObjectName,&DevicePhysicalMemory,FALSE) == 0)
			{
				DbgPrint("\nFindPhysmemHandles():  Process %d has a handle open to \\Device\\PhysicalMemory!!.\n",pHandleList->Handles[i].ProcessId);
				numFound++;
			}
		}
	}

	if (nameFail+otherFail > 0)
		DbgPrint("\nFindPhysmemHandles():  Warning:  %i name resolution failures and %i other failures.",nameFail,otherFail);

	DbgPrint("\nFindPhysmemHandles():  Found %i open handles to \\Device\\PhysicalMemory.",numFound);

	ExFreePoolWithTag(pHandleList,CW_TAG);
}

BOOL GetHandleInfo(ULONG pid, HANDLE hObject, PUNICODE_STRING ObjectName, int* nameFailCount, int* otherFailCount)
{
	CLIENT_ID c;
	OBJECT_ATTRIBUTES o;
	ULONG returnLength,returnLength2,size=0;
	HANDLE hProcess,hDuplicateObject=NULL;
	POBJECT_TYPE_INFORMATION oti;
	POBJECT_BASIC_INFORMATION obi;
	NTSTATUS nt;
	DWORD* nameBuff=NULL;
	UNICODE_STRING ProcessName;
	BOOL objNameResolutionFail;

	c.UniqueProcess = pid;
	c.UniqueThread = 0;

	o.Length=sizeof(OBJECT_ATTRIBUTES);
	InitializeObjectAttributes(&o,0,0,0,0);

	//open the process so we can duplicate its handle
	nt=ZwOpenProcess(&hProcess, PROCESS_DUP_HANDLE, &o, &c);
	
	if (nt != STATUS_SUCCESS) 
	{
		DbgPrint("\nGetHandleInfo():  Error:  ZwOpenProcess() failed on pid %d:  %08X",pid,nt);
		(*otherFailCount)++;
		return FALSE;
	}
					
	//now duplicate the handle we wish to examine further
	nt=ZwDuplicateObject(hProcess,hObject,(HANDLE)0xFFFFFFFF,&hDuplicateObject,0,0,DUPLICATE_SAME_ACCESS);

	if (nt != STATUS_SUCCESS || hDuplicateObject == NULL)
	{
		DbgPrint("\nGetHandleInfo():  Error:  ZwDuplicateObject() failed on pid %d:  %08X",pid,nt);
		ZwClose(hProcess);
		(*otherFailCount)++;
		return FALSE;
	}

	//////////////////////////////////////
	///	 get object basic information   //
	//////////////////////////////////////
	obi=(POBJECT_BASIC_INFORMATION)ExAllocatePoolWithTag(NonPagedPool,sizeof(OBJECT_BASIC_INFORMATION),CW_TAG);
	nt=ZwQueryObject(hDuplicateObject, ObjectBasicInformation,	obi, sizeof(OBJECT_BASIC_INFORMATION), &returnLength);

	if (nt != STATUS_SUCCESS)
	{
		DbgPrint("\nGetHandleInfo():  Error:  ZwQueryObject() failed to get object basic information:  %08X",nt);
		ZwClose(hDuplicateObject);
		ZwClose(hProcess);
		(*otherFailCount)++;
		return FALSE;
	}

	//////////////////////////////////////
	///	 get object type  information   //
	//////////////////////////////////////
	//try once with the type information we just retrieved from basic information query
	oti=(POBJECT_TYPE_INFORMATION)ExAllocatePoolWithTag(NonPagedPool,obi->TypeInformationLength,CW_TAG);
	nt=ZwQueryObject(hDuplicateObject, ObjectTypeInformation, oti, obi->TypeInformationLength, &returnLength);

	//if there was a size mismatch problem, the variable returnLength will have the required size
	if (nt == STATUS_INFO_LENGTH_MISMATCH)
	{
		//free the memory and re-allocate at correct size
		ExFreePoolWithTag(oti,CW_TAG);
		oti=(POBJECT_TYPE_INFORMATION)ExAllocatePoolWithTag(NonPagedPool,returnLength,CW_TAG);
		nt=ZwQueryObject(hDuplicateObject, ObjectTypeInformation, oti, returnLength, &returnLength2);
	}

	//failed again?  bail...
	if (nt != STATUS_SUCCESS)
	{			
		DbgPrint("\nGetHandleInfo():  Error:  ZwQueryObject() failed to get object type information:  %08X",nt);
		ExFreePoolWithTag(obi,CW_TAG);
		ExFreePoolWithTag(oti,CW_TAG);
		ZwClose(hDuplicateObject);
		ZwClose(hProcess);
		(*otherFailCount)++;
		return FALSE;
	}

	//////////////////////////////////////
	///	 get object NAME  information   //
	//////////////////////////////////////
	//PING!! how much memory should I allocate for you? (we make this call only to fill returnLength)
	nt=ZwQueryObject(hDuplicateObject, ObjectNameInformation, nameBuff, 0, &returnLength);

	//use the returnLength variable to reallocate an appropriately-sized buffer
	if (nt == STATUS_INFO_LENGTH_MISMATCH && returnLength)
	{
		//DbgPrint("\nGetHandleInfo():  Readjusting buffer size to %u",returnLength);
		//allocate our second buffer with the correct size
		nameBuff=ExAllocatePoolWithTag(NonPagedPool,returnLength,CW_TAG);
		nt=ZwQueryObject(hDuplicateObject, ObjectNameInformation, nameBuff, returnLength, &returnLength2);
		objNameResolutionFail=FALSE;
		//DbgPrint("\nGetHandleInfo():  returnLength2 %u",returnLength2);
	}
	//oftentimes we get a returnLength of 0 for some reason..
	else if (returnLength == 0)
	{
		objNameResolutionFail=TRUE;
		//DbgPrint("\nGetHandleInfo():  Warning:  ZwQueryObject() failed to get object name length:  Error code %08X, return length = %u",nt,returnLength2);
	}

	//try to get the associated process name
	//TODO:
	//GetProcessNameByPid(pid,&ProcessName);

	//if nameBuff is NULL, we failed to get name information above - return FALSE even though
	//technically a valid object exists here, we dont know its name though.
	if (objNameResolutionFail)
	{
		//Success - sort of..no name was resolved :(
		//DbgPrint("\nGetHandleInfo():  PID=%d:  '[empty]' (Type=%wZ)",pid,&(oti->Name));
		ExFreePoolWithTag(obi,CW_TAG);
		ExFreePoolWithTag(oti,CW_TAG);
		
		if (nt=ZwClose(hDuplicateObject) != STATUS_SUCCESS)
			DbgPrint("\nGetHandleInfo().ObjNameResolutionFail:  Warning:  Failed to free hDuplicateObject object!  Handle leaked, sorry...(%08X)",nt);
		if (nt=ZwClose(hProcess) != STATUS_SUCCESS)
			DbgPrint("\nGetHandleInfo().ObjNameResolutionFail:  Warning:  Failed to free hProcess object!  Handle leaked, sorry...(%08X)",nt);

		(*nameFailCount)++;
		return FALSE;
	}
	else
	{
		//SUCCESS!
		//DbgPrint("\nGetHandleInfo():  PID=%d:  '%wZ' (Type=%wZ)",pid,(PWCHAR)nameBuff,&(oti->Name));

		//initialize our unicode string with the result of the query
		RtlInitUnicodeString(ObjectName,(PWCHAR)nameBuff[1]);
	}

	ExFreePoolWithTag(obi,CW_TAG);
	ExFreePoolWithTag(oti,CW_TAG);
	ExFreePoolWithTag(nameBuff,CW_TAG);
	
	if (nt=ZwClose(hDuplicateObject) != STATUS_SUCCESS)
		DbgPrint("\nGetHandleInfo():  Warning:  Failed to free hDuplicateObject object!  Handle leaked, sorry...(%08X)",nt);
	if (nt=ZwClose(hProcess) != STATUS_SUCCESS)
		DbgPrint("\nGetHandleInfo():  Warning:  Failed to free hProcess object!  Handle leaked, sorry...(%08X)",nt);

	return TRUE;
}

//NOTE:  do not use function below without further testing.  it is buggy.
//i think the SYSTEM_PROCESS_INFORMATION structure is incorrect or has
//changed since it was documented online.  Using ZwQuerySystemInformation
//to get this structure is undocumented and could break at any release.
VOID GetProcessNameByPid(ULONG pid, PUNICODE_STRING ProcessName)
{
	ULONG size,returnLength;
	PSYSTEM_PROCESS_INFORMATION pFirstProcess,pThisProcess;
	NTSTATUS nt;
	ULONG NextEntryOffset;
	int i;

	//get the list of processes
	size=GetInformationClassSize(SystemProcessInformation);
	pFirstProcess=(PSYSTEM_PROCESS_INFORMATION)ExAllocatePoolWithTag(NonPagedPool,size,CW_TAG);
	nt=ZwQuerySystemInformation(SystemProcessInformation,pFirstProcess,size,&returnLength);

	if (nt != STATUS_SUCCESS)
	{
		DbgPrint("\nGetProcessNameByPid():  [0] Error:  ZwQuerySystemInformation() failed:  %X\n",nt);
		return;
	}

	pThisProcess=pFirstProcess;
	NextEntryOffset=pFirstProcess->NextEntryOffset;

	//loop through all processes in the process list
	while (NextEntryOffset)
	{
		DbgPrint("\nGetProcessNameByPid():  %08X (Offset %08X):  %wZ",(ULONG)pThisProcess,NextEntryOffset,pThisProcess->ImageName.Buffer);
		//if match on PID, return this process's name
		if ((ULONG)pThisProcess->UniqueProcessId == pid)
		{
			DbgPrint("\nGetProcessNameByPid():  Found match:  %wZ [%u]",pThisProcess->ImageName.Buffer,pThisProcess->UniqueProcessId);
			RtlInitUnicodeString(ProcessName,pThisProcess->ImageName.Buffer);
			break;
		}

		//advance to the next entry in the linked list
		NextEntryOffset=pThisProcess->NextEntryOffset;
		pThisProcess=(PSYSTEM_PROCESS_INFORMATION)((PULONG)pThisProcess+NextEntryOffset);
	}

	ExFreePoolWithTag(pFirstProcess,CW_TAG);

	if (ProcessName == NULL)
		RtlInitUnicodeString(ProcessName,L"[Unknown]");
}