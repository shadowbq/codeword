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
// * main.c 
//
// * ChangeLog
// 
// * 7/3/2009 - AL - forked from kgsp project
// * 3/19/2009 - AL - first version.
//
//////////////////////////////////////////////////////////////////////////////

//indicate our target architecture
#define _X86_ 1

//driver service name (device object name)
#define DRV_DEV_NAME L"\\Device\\CwSvc1"
#define DRV_DEV_DOS_NAME L"\\DosDevices\\CwSvc1"

#include <stdio.h>
#include <string.h>
#include "ntddk.h"
#include "main.h"
#include "ssdt.h"
#include "irp.h"
#include "handle.h"
#include "win32ApiCheck.h"
#include "cwprocess.h"

/////////////////////////////////////////////////////
//                                                 //
// DriverEntry()                                   //
//                                                 //
/////////////////////////////////////////////////////
//Description:  Entry point for this driver.  Called by
//				the I/O manager upon loading.
//
//Returns:      void
/////////////////////////////////////////////////////
NTSTATUS DriverEntry(PDRIVER_OBJECT pDriverObject, PUNICODE_STRING pRegistryPath)
{
    NTSTATUS NtStatus=STATUS_SUCCESS;
    UINT uiIndex=0;
    PDEVICE_OBJECT pDeviceObject=NULL;
    UNICODE_STRING driverName;
	UNICODE_STRING dosDeviceName;

	DbgPrint("%s","DriverEntry():  CwDriver initializing...");

    RtlInitUnicodeString(&driverName,DRV_DEV_NAME);
    RtlInitUnicodeString(&dosDeviceName,DRV_DEV_DOS_NAME); 

	//create our "device"
	//instead of FILE_DEVICE_UNKNOWN we could use any value from 32768 through 65535
	//perhaps that would aid in avoiding detection?  use rand num?
    NtStatus=IoCreateDevice(
							pDriverObject, 
							0,
                            &driverName, 
                            FILE_DEVICE_UNKNOWN,
                            FILE_DEVICE_SECURE_OPEN, 
                            FALSE,
							&pDeviceObject
							);

	if (!NT_SUCCESS(NtStatus))
	{
		DbgPrint("%s","IoCreateDevice() failed!  Driver not initialised.");
		if (NtStatus == STATUS_OBJECT_NAME_EXISTS)
			DbgPrint("%s","\t->the object name already exists.");
		else if (NtStatus == STATUS_OBJECT_NAME_COLLISION)
			DbgPrint("%s","\t->an object name collision occured.");
		else
			DbgPrint("%s","\tInsufficient resources.");
		return STATUS_UNSUCCESSFUL;
	}

	NtStatus=IoCreateSymbolicLink(&dosDeviceName, &driverName);

	//while creating a symbolic link is not necessary, we will do so
	//and must go no further if this fails, b/c usermode portion depends on it
	if (!NT_SUCCESS(NtStatus))
	{
		DbgPrint("%s","IoCreateSymbolicLink() failed!  Driver object will be deleted.");
		IoDeleteDevice(pDeviceObject);
		return STATUS_UNSUCCESSFUL;
	}
    
	//set REQUIRED IRP major functions we dont care about to generic pass-down dispatch handler
    pDriverObject->MajorFunction[IRP_MJ_CLOSE]=CwDispatchHandlerGeneric;
    pDriverObject->MajorFunction[IRP_MJ_CREATE]=CwDispatchHandlerGeneric;
	//catch major functions for IRPs we do care about
	pDriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL]=CwDispatchHandlerIoControl;
	pDriverObject->DriverUnload=CwUnload;

	//we shall use direct IO
	pDeviceObject->Flags|=DO_DIRECT_IO;


	/*
	//////////////////////////////////////////////////////////////////////////////
	//																			//
	//						DKOM DETECTION										//
	//																			//
	//////////////////////////////////////////////////////////////////////////////
	//
	//UNCOMMENT THIS TO LOOK FOR DKOM
	//
	*/
	//DbgPrint("DriverEntry():  [0] Looking for processes with a handle open to \\Device\\PhysicalMemory..");
	//FindPhysmemHandles();
	//DbgPrint("DriverEntry():  [0] Complete.");

	return STATUS_SUCCESS;
}


/////////////////////////////////////////////////////
//                                                 //
// LoadSilently()                                  //
//                                                 //
/////////////////////////////////////////////////////
//Description:  Loads the driver using system load
//				and call image rather than DriverEntry().
//
//Returns:      void
/////////////////////////////////////////////////////
/*
ref:  http://www.rootkit.com/newsread.php?newsid=208

VOID LoadSilently()
{
	----------------------------------------------
	SYSTEM_LOAD_IMAGE LoadImage;

	//const WCHAR DriverName[] = L"\\??\\C:\\SysDasm.sys";
	RtlInitUnicodeString(&LoadImage.ModuleName, driver_name);

	NTSTATUS Status;
	Status = ZwSetSystemInformation(
	SystemLoadImage,
	&LoadImage,
	sizeof(LoadImage));

	if (!NT_SUCCESS(Status)) {
	DbgPrint("SystemLoadImage failed with Error %x", Status);
	return 0; 
	}
	----------------------------------------------

	SYSTEM_UNLOAD_IMAGE UnloadImage;

	// Set ModuleSection value to that returned in LoadImage.ModuleSection
	UnloadImage.ModuleSection = LoadImage.ModuleSection;

	NTSTATUS Status;
	Status = ZwSetSystemInformation(
	SystemUnloadImage,
	&UnloadImage,
	sizeof(UnloadImage));
	----------------------------------------------
}
*/

/////////////////////////////////////////////////////
//                                                 //
// CwUnload()                                      //
//                                                 //
/////////////////////////////////////////////////////
//Description:  Unloads the driver.
//
//Returns:      void
/////////////////////////////////////////////////////
VOID CwUnload(PDRIVER_OBJECT DriverObject)
{   
    UNICODE_STRING dosDeviceName;

	//are we at correct IRQL for paging??
	PAGED_CODE();

    DbgPrint("%s","Unloading driver....");
    
    RtlInitUnicodeString(&dosDeviceName, DRV_DEV_DOS_NAME);
	
	//delete our symbolic link and device object
    if (!NT_SUCCESS(IoDeleteSymbolicLink(&dosDeviceName)))
		DbgPrint("%s","Warning:  IoDeleteSymbolicLink() failed!");
	else
		DbgPrint("%s","Successfully deleted symbolic link.");

	IoDeleteDevice(DriverObject->DeviceObject);

	DbgPrint("%s","Successfully deleted Device Object.");

	return;
}

/////////////////////////////////////////////////////
//                                                 //
// CwDispatchHandlerIoControl()                    //
//                                                 //
/////////////////////////////////////////////////////
//Description:  Handles I/O requests we care about.
//				We ONLY support DIRECT_IO!
//
//Returns:      void
/////////////////////////////////////////////////////
NTSTATUS CwDispatchHandlerIoControl(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
	PIO_STACK_LOCATION irpSp;
    NTSTATUS status,returnNtStatus;
    ULONG UserModeInputBufferLen, UserModeOutputBufferLen;
	PVOID UserModeOutputBuffer,UserModeInputBuffer;
	PVOID pReturnBuffer=NULL;
	ULONG RequiredOutputBufferSize=0;
	ULONG RequiredInputBufferSize=0;
	ULONG Ioctl;
	PDRIVER_CHECK_INFO dInfo=NULL;
	int i=0;
	BOOL ValidationFailed=FALSE;

	//are we at correct IRQL for paging??
	PAGED_CODE();

	//--------------------
	// GET IRP DATA
	//--------------------
	//our current IRP stack location
    irpSp = IoGetCurrentIrpStackLocation(Irp);
	//ioctl
	Ioctl=irpSp->Parameters.DeviceIoControl.IoControlCode;
	//length of user mode buffers (in/out)
    UserModeInputBufferLen = irpSp->Parameters.DeviceIoControl.InputBufferLength;
    UserModeOutputBufferLen = irpSp->Parameters.DeviceIoControl.OutputBufferLength;
	//get a nonpaged system-space virtual address for the user's output buffer
	UserModeOutputBuffer = MmGetSystemAddressForMdlSafe(Irp->MdlAddress, NormalPagePriority);
	//get the pointer to the system buffer the i/o manager allocated for us
	UserModeInputBuffer = Irp->AssociatedIrp.SystemBuffer;

	DbgPrint("CwDispatchHandlerIoControl():  User-mode output buffer at address 0x%08x, len %i bytes.",UserModeOutputBuffer, UserModeOutputBufferLen);
	DbgPrint("CwDispatchHandlerIoControl():  User-mode input buffer at address 0x%08x, len %i bytes.",UserModeInputBuffer, UserModeInputBufferLen);

	//--------------------
	// PRELIM VALIDATION
	//--------------------
	//determine required sizes for in/out bufs
	switch(Ioctl)
	{
		case IOCTL_SSDT_DETECT_HOOKS:
			RequiredOutputBufferSize = sizeof(HOOKED_SSDT_TABLE);
			RequiredInputBufferSize  = 0; //no input buf needed
			break;
		
		case IOCTL_SSDT_DETECT_DETOURS:
			RequiredOutputBufferSize = sizeof(DETOURED_SSDT_TABLE);
			RequiredInputBufferSize  = 0; //no input buf needed
			break;
			
		case IOCTL_WIN32API_DETOUR_DETECTION:
			RequiredOutputBufferSize = sizeof(WIN32API_DETOUR_TABLE);
			RequiredInputBufferSize  = 0; //input buf needed but not checked
			break;
			
		case IOCTL_IRP_HOOK_DETECTION:
			RequiredOutputBufferSize = sizeof(HOOKED_DISPATCH_FUNCTIONS_TABLE);
			RequiredInputBufferSize  = sizeof(DRIVER_CHECK_INFO);
			break;
			
		case IOCTL_IRP_DETOUR_DETECTION:
			RequiredOutputBufferSize = sizeof(DETOURED_DISPATCH_FUNCTIONS_TABLE);
			RequiredInputBufferSize  = sizeof(DRIVER_CHECK_INFO);
			break;
		
		case IOCTL_GET_PROCESS_LISTING_ZWQ:
			RequiredOutputBufferSize = sizeof(PROCESS_LISTING_ZWQ);
			RequiredInputBufferSize  = 0; //no inbuf needed
			break;
			
		case IOCTL_GET_PROCESS_LISTING_PSP:
			RequiredOutputBufferSize = sizeof(UINT)*256;
			RequiredInputBufferSize  = 0; //no inbuf needed
			break;
		
		default: //unrecognized IOCTL.  bail now.
			Irp->IoStatus.Status = STATUS_INVALID_DEVICE_REQUEST;
			Irp->IoStatus.Information = 0;
			DbgPrint("CwDispatchHandlerIoControl():  Received unrecognized IOCTL code 0x%08x",Ioctl);
			IoCompleteRequest(Irp,IO_NO_INCREMENT);
			return STATUS_INVALID_DEVICE_REQUEST;
	}

	//check out buffer size
    if (UserModeOutputBufferLen != RequiredOutputBufferSize)
    {
		DbgPrint("CwDispatchHandlerIoControl():  The supplied user output buffer is of incorrect size:  %i should be %i.",UserModeOutputBufferLen,RequiredOutputBufferSize);
		Irp->IoStatus.Information = 0;
		Irp->IoStatus.Status = STATUS_INVALID_PARAMETER;
        IoCompleteRequest(Irp,IO_NO_INCREMENT);
		return STATUS_INVALID_PARAMETER;
	}
	//check in buffer size if the required size is not 0
	if ((RequiredInputBufferSize !=  0) && (UserModeInputBufferLen != RequiredInputBufferSize))
    {
		DbgPrint("CwDispatchHandlerIoControl():  The supplied user input buffer is of incorrect size:  %i should be %i.",UserModeInputBufferLen,RequiredInputBufferSize);
		Irp->IoStatus.Information = 0;
		Irp->IoStatus.Status = STATUS_INVALID_PARAMETER;
        IoCompleteRequest(Irp,IO_NO_INCREMENT);
		return STATUS_INVALID_PARAMETER;
	}

	//------------------------
	// ALLOCATE RETURN BUFFER
	//------------------------
	pReturnBuffer = ExAllocatePoolWithTag(NonPagedPool,RequiredOutputBufferSize,CW_TAG);
	if (pReturnBuffer == NULL)
	{
		DbgPrint("CwDispatchHandlerIoControl():  ExAllocatePoolWithTag() failed to allocate %i bytes for return buffer.",RequiredOutputBufferSize);
		Irp->IoStatus.Information = 0;
		Irp->IoStatus.Status = STATUS_INSUFFICIENT_RESOURCES;
		IoCompleteRequest(Irp,IO_NO_INCREMENT);
		return STATUS_INSUFFICIENT_RESOURCES;
	}

	//dont leak kernel mode info that may be in this buffer
	RtlZeroMemory(pReturnBuffer,RequiredOutputBufferSize);

	//
	//////////////////////////////////////////////////////////////////////////////
	//																			//
	//						HANDLE SUPPLIED IOCTL								//
	//																			//
	//////////////////////////////////////////////////////////////////////////////
	//
    switch (Ioctl)
    {
		//
		//___________________________
		//		SSDT HOOKS
		//___________________________
		//
		//
		case IOCTL_SSDT_DETECT_HOOKS:

			DbgPrint("%s","CwDispatchHandlerIoControl():  Got IOCTL_SSDT_DETECT_HOOKS.");

			//Get hooks, bail if it failed.
			if (!NT_SUCCESS(GetSSDTHooks((PHOOKED_SSDT_TABLE)pReturnBuffer)))
			{
				DbgPrint("%s","CwDispatchHandlerIoControl():  There was a problem in GetSSDTHooks().");
				Irp->IoStatus.Information = 0;
				Irp->IoStatus.Status = STATUS_UNSUCCESSFUL;
				break;
			}
			//insure some data was returned
			if (pReturnBuffer == NULL)
			{
				DbgPrint("%s","CwDispatchHandlerIoControl():  GetSSDTHooks() returned a NULL structure.");
				Irp->IoStatus.Information = 0;
				Irp->IoStatus.Status = STATUS_UNSUCCESSFUL;
				break;
			}

			DbgPrint("CwDispatchHandlerIoControl():  Found %i hooks.",((PHOOKED_SSDT_TABLE)pReturnBuffer)->NumHookedEntries);

			//copy the buffer we just filled into the user's buffer
			RtlCopyMemory(UserModeOutputBuffer,((PHOOKED_SSDT_TABLE)pReturnBuffer),RequiredOutputBufferSize);
			Irp->IoStatus.Information = RequiredOutputBufferSize;
			Irp->IoStatus.Status = STATUS_SUCCESS;

			break;

		//
		//___________________________
		//		SSDT DETOURS
		//___________________________
		//
		//
		case IOCTL_SSDT_DETECT_DETOURS:

			DbgPrint("%s","CwDispatchHandlerIoControl():  Got IOCTL_SSDT_DETECT_DETOURS.");

			//Get hooks, bail if it failed.
			if (!NT_SUCCESS(GetSSDTDetours((PDETOURED_SSDT_TABLE)pReturnBuffer)))
			{
				DbgPrint("%s","CwDispatchHandlerIoControl():  There was a problem in GetSSDTDetours().");
				Irp->IoStatus.Information = 0;
				Irp->IoStatus.Status = STATUS_UNSUCCESSFUL;
				break;
			}
			//insure some data was returned
			if (pReturnBuffer == NULL)
			{
				DbgPrint("%s","CwDispatchHandlerIoControl():  GetSSDTDetours() returned a NULL structure.");
				Irp->IoStatus.Information = 0;
				Irp->IoStatus.Status = STATUS_UNSUCCESSFUL;
				break;
			}

			DbgPrint("CwDispatchHandlerIoControl():  Found %i detours.",((PDETOURED_SSDT_TABLE)pReturnBuffer)->NumDetouredEntries);

			//copy the buffer we just filled into the user's buffer
			RtlCopyMemory(UserModeOutputBuffer,((PDETOURED_SSDT_TABLE)pReturnBuffer),RequiredOutputBufferSize);
			Irp->IoStatus.Information = RequiredOutputBufferSize;
			Irp->IoStatus.Status = STATUS_SUCCESS;

			break;

		//
		//___________________________
		//  WIN32 API DETOUR DETECTION
		//___________________________
		//
		//
		case IOCTL_WIN32API_DETOUR_DETECTION:

			DbgPrint("%s","CwDispatchHandlerIoControl():  Got IOCTL_WIN32API_DETOUR_DETECTION.");

			DbgPrint("CwDispatchHandlerIoControl():  Checking module '%s'...",(PCHAR)UserModeInputBuffer);

			//find detours
			if (!NT_SUCCESS(CheckModuleExportsForDetours((PCHAR)UserModeInputBuffer, (PWIN32API_DETOUR_TABLE)pReturnBuffer)))
			{
				DbgPrint("CwDispatchHandlerIoControl():  CheckModuleExportsForDetours() failed.");
				Irp->IoStatus.Information = 0;
				Irp->IoStatus.Status = STATUS_UNSUCCESSFUL;
				break;
			}
			//insure some data was returned
			if (pReturnBuffer == NULL)
			{
				DbgPrint("%s","CwDispatchHandlerIoControl():  CheckModuleExportsForDetours() returned a NULL structure.");
				Irp->IoStatus.Information = 0;
				Irp->IoStatus.Status = STATUS_UNSUCCESSFUL;
				break;
			}

			DbgPrint("CwDispatchHandlerIoControl():  Found %i POSSIBLE detours in this module.",((PWIN32API_DETOUR_TABLE)pReturnBuffer)->NumDetours);

			//copy the buffer we just filled into the user's buffer
			RtlCopyMemory(UserModeOutputBuffer,((PWIN32API_DETOUR_TABLE)pReturnBuffer),RequiredOutputBufferSize);
			Irp->IoStatus.Information = RequiredOutputBufferSize;
			Irp->IoStatus.Status = STATUS_SUCCESS;

			break;

		//
		//___________________________
		//  IRP HOOK DETECTION
		//___________________________
		//
		//
		case IOCTL_IRP_HOOK_DETECTION:

			DbgPrint("%s","CwDispatchHandlerIoControl():  Got IOCTL_IRP_HOOK_DETECTION.");

			//marshal out the driver and device names from user struct
			dInfo=(PDRIVER_CHECK_INFO)UserModeInputBuffer;

			if (dInfo == NULL)
			{
				DbgPrint("CwDispatchHandlerIoControl():  User-supplied input buffer is NULL.");
				Irp->IoStatus.Information = 0;
				Irp->IoStatus.Status = STATUS_INVALID_PARAMETER;
				break;
			}

			DbgPrint("CwDispatchHandlerIoControl():  Checking driver '%wZ', device '%wZ'.",&dInfo->DriverName, &dInfo->DriverDeviceName);

			//find IRP hooks
			if (!NT_SUCCESS(CheckDriver(&(dInfo->DriverName), &(dInfo->DriverDeviceName), (PHOOKED_DISPATCH_FUNCTIONS_TABLE)pReturnBuffer, NULL)))
			{
				DbgPrint("%s","CwDispatchHandlerIoControl():  CheckDriver() failed.");
				Irp->IoStatus.Information = 0;
				Irp->IoStatus.Status = STATUS_UNSUCCESSFUL;
				break;
			}
			//insure some data was returned
			if (pReturnBuffer == NULL)
			{
				DbgPrint("%s","CwDispatchHandlerIoControl():  CheckDriver() returned a NULL structure.");
				Irp->IoStatus.Information = 0;
				Irp->IoStatus.Status = STATUS_UNSUCCESSFUL;
				break;
			}

			DbgPrint("CwDispatchHandlerIoControl():  Found %i POSSIBLE hooks.",((PHOOKED_DISPATCH_FUNCTIONS_TABLE)pReturnBuffer)->NumHookedEntries);

			//copy the buffer we just filled into the user's buffer
			RtlCopyMemory(UserModeOutputBuffer,((PHOOKED_DISPATCH_FUNCTIONS_TABLE)pReturnBuffer),RequiredOutputBufferSize);
			Irp->IoStatus.Information = RequiredOutputBufferSize;
			Irp->IoStatus.Status = STATUS_SUCCESS;

			break;

		//
		//___________________________
		//  IRP DETOUR DETECTION
		//___________________________
		//
		//
		case IOCTL_IRP_DETOUR_DETECTION:

			DbgPrint("%s","CwDispatchHandlerIoControl():  Got IOCTL_IRP_DETOUR_DETECTION.");

			//marshal out the driver and device names from user struct
			dInfo=(PDRIVER_CHECK_INFO)UserModeInputBuffer;

			if (dInfo == NULL)
			{
				DbgPrint("%s","CwDispatchHandlerIoControl():  User-supplied input buffer is NULL.");
				Irp->IoStatus.Information = 0;
				Irp->IoStatus.Status = STATUS_INVALID_PARAMETER;
				break;
			}

			//find IRP hooks
			if (!NT_SUCCESS(CheckDriver(&dInfo->DriverName, &dInfo->DriverDeviceName, NULL, (PDETOURED_DISPATCH_FUNCTIONS_TABLE)pReturnBuffer)))
			{
				DbgPrint("%s","CwDispatchHandlerIoControl():  CheckDriver() failed.");
				Irp->IoStatus.Information = 0;
				Irp->IoStatus.Status = STATUS_UNSUCCESSFUL;
				break;
			}
			//insure some data was returned
			if (pReturnBuffer == NULL)
			{
				DbgPrint("%s","CwDispatchHandlerIoControl():  CheckDriver() returned a NULL structure.");
				Irp->IoStatus.Information = 0;
				Irp->IoStatus.Status = STATUS_UNSUCCESSFUL;
				break;
			}

			DbgPrint("CwDispatchHandlerIoControl():  Found %i POSSIBLE detours.",((PDETOURED_DISPATCH_FUNCTIONS_TABLE)pReturnBuffer)->NumDetours);

			//copy the buffer we just filled into the user's buffer
			RtlCopyMemory(UserModeOutputBuffer,((PDETOURED_DISPATCH_FUNCTIONS_TABLE)pReturnBuffer),RequiredOutputBufferSize);
			Irp->IoStatus.Information = RequiredOutputBufferSize;
			Irp->IoStatus.Status = STATUS_SUCCESS;

			break;

		//
		//___________________________
		//  PROCESS LISTING REQUEST
		//  USE ZwQuerySystemInformation()
		//___________________________
		//
		//
		case IOCTL_GET_PROCESS_LISTING_ZWQ:

			DbgPrint("%s","CwDispatchHandlerIoControl():  Got IOCTL_GET_PROCESS_LISTING_ZWQ.");

			if (!NT_SUCCESS(GetProcessListingZwq((PPROCESS_LISTING_ZWQ)pReturnBuffer)))
			{
				DbgPrint("%s","CwDispatchHandlerIoControl():  GetProcessListingZwq() failed.");
				Irp->IoStatus.Information = 0;
				Irp->IoStatus.Status = STATUS_UNSUCCESSFUL;
				break;
			}
			//insure some data was returned
			if (pReturnBuffer == NULL)
			{
				DbgPrint("%s","CwDispatchHandlerIoControl():  GetProcessListingZwq() returned a NULL structure.");
				Irp->IoStatus.Information = 0;
				Irp->IoStatus.Status = STATUS_UNSUCCESSFUL;
				break;
			}

			DbgPrint("CwDispatchHandlerIoControl():  Found %i processes.",((PPROCESS_LISTING_ZWQ)pReturnBuffer)->numProcesses);

			//copy the buffer we just filled into the user's buffer
			RtlCopyMemory(UserModeOutputBuffer,((PPROCESS_LISTING_ZWQ)pReturnBuffer),RequiredOutputBufferSize);
			Irp->IoStatus.Information = RequiredOutputBufferSize;
			Irp->IoStatus.Status = STATUS_SUCCESS;
			
			//
		//___________________________
		//  PROCESS LISTING REQUEST
		//  USE PspCidTable
		//___________________________
		//
		//
		case IOCTL_GET_PROCESS_LISTING_PSP:

			DbgPrint("%s","CwDispatchHandlerIoControl():  Got IOCTL_GET_PROCESS_LISTING_PSP.");

			if (!NT_SUCCESS(GetProcessListByPspCidTable((UINT*)pReturnBuffer)))
			{
				DbgPrint("%s","CwDispatchHandlerIoControl():  GetProcessListByPspCidTable() failed.");
				Irp->IoStatus.Information = 0;
				Irp->IoStatus.Status = STATUS_UNSUCCESSFUL;
				break;
			}
			//insure some data was returned
			if (pReturnBuffer == NULL)
			{
				DbgPrint("%s","CwDispatchHandlerIoControl():  GetProcessListByPspCidTable() returned a NULL structure.");
				Irp->IoStatus.Information = 0;
				Irp->IoStatus.Status = STATUS_UNSUCCESSFUL;
				break;
			}

			//copy the buffer we just filled into the user's buffer
			RtlCopyMemory(UserModeOutputBuffer,((UINT*)pReturnBuffer),RequiredOutputBufferSize);
			Irp->IoStatus.Information = RequiredOutputBufferSize;
			Irp->IoStatus.Status = STATUS_SUCCESS;
			break;


	//
	//___________________________
	//		BASE CASE
	//___________________________
	//
	//
    //default:
	//	no need for default base case, since only known IRPs have made it this far
	}

	//free our PVOID return buffer
	if (pReturnBuffer != NULL)
		ExFreePoolWithTag(pReturnBuffer,CW_TAG);

	//save our return status before we complete the IRP!
	returnNtStatus=Irp->IoStatus.Status;

	//complete this IRP
	IoCompleteRequest(Irp,IO_NO_INCREMENT);

    return returnNtStatus;
}


/////////////////////////////////////////////////////
//                                                 //
// CwDispatchHandlerGeneric()                      //
//                                                 //
/////////////////////////////////////////////////////
//Description:  Handles I/O requests we DONT care about.
//
//Returns:      void
/////////////////////////////////////////////////////
NTSTATUS CwDispatchHandlerGeneric(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
	Irp->IoStatus.Status = STATUS_SUCCESS;
	Irp->IoStatus.Information = 0;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);

	return STATUS_SUCCESS;
}