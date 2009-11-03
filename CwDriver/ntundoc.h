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
// * ntundoc.h 
//
// * ChangeLog
// 
// * 7/3/2009 - AL - forked from kgsp project
// * 3/19/2009 - AL - first version.
//
//////////////////////////////////////////////////////////////////////////////

#ifndef __NTUNDOC_h__
#define __NTUNDOC_h__
//_____________________________________________________
//
//WINDOWS CONSTANTS
//
//_____________________________________________________
#define IMAGE_DIRECTORY_ENTRY_EXPORT             0
#define IMAGE_DIRECTORY_ENTRY_IMPORT             1
#define IMAGE_DIRECTORY_ENTRY_RESOURCE           2
#define IMAGE_DIRECTORY_ENTRY_EXCEPTION          3
#define IMAGE_DIRECTORY_ENTRY_SECURITY           4
#define IMAGE_DIRECTORY_ENTRY_BASERELOC          5
#define IMAGE_DIRECTORY_ENTRY_DEBUG6
#define IMAGE_DIRECTORY_ENTRY_COPYRIGHT          7
#define IMAGE_DIRECTORY_ENTRY_GLOBALPTR          8
#define IMAGE_DIRECTORY_ENTRY_TLS  9
#define IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG       10
#define IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT      11
#define IMAGE_DIRECTORY_ENTRY_IAT 12
#define IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT      13
#define IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR    14

#define IMAGE_NUMBEROF_DIRECTORY_ENTRIES        16

//_____________________________________________________
//
//WINDOWS STRUCTURES
//
//_____________________________________________________
typedef struct _HANDLE_TABLE_ENTRY_INFO
{
     ULONG AuditMask;
} HANDLE_TABLE_ENTRY_INFO, *PHANDLE_TABLE_ENTRY_INFO;
typedef struct _HANDLE_TABLE_ENTRY
{
     union
     {
          PVOID Object;
          ULONG ObAttributes;
          PHANDLE_TABLE_ENTRY_INFO InfoTable;
          ULONG Value;
     };
     union
     {
          ULONG GrantedAccess;
          struct
          {
               WORD GrantedAccessIndex;
               WORD CreatorBackTraceIndex;
          };
          LONG NextFreeTableEntry;
     };
} HANDLE_TABLE_ENTRY, *PHANDLE_TABLE_ENTRY;
typedef struct _HANDLE_TRACE_DB_ENTRY
{
     CLIENT_ID ClientId;
     PVOID Handle;
     ULONG Type;
     VOID * StackTrace[16];
} HANDLE_TRACE_DB_ENTRY, *PHANDLE_TRACE_DB_ENTRY;
typedef struct _HANDLE_TRACE_DEBUG_INFO
{
     LONG RefCount;
     ULONG TableSize;
     ULONG BitMaskFlags;
     FAST_MUTEX CloseCompactionLock;
     ULONG CurrentStackIndex;
     HANDLE_TRACE_DB_ENTRY TraceDb[1];
} HANDLE_TRACE_DEBUG_INFO, *PHANDLE_TRACE_DEBUG_INFO;
typedef struct _EX_PUSH_LOCK
{
     union
     {
          ULONG Locked: 1;
          ULONG Waiting: 1;
          ULONG Waking: 1;
          ULONG MultipleShared: 1;
          ULONG Shared: 28;
          ULONG Value;
          PVOID Ptr;
     };
} EX_PUSH_LOCK, *PEX_PUSH_LOCK;

typedef struct _HANDLE_TABLE
{
     ULONG TableCode;
     PEPROCESS QuotaProcess;
     PVOID UniqueProcessId;
     EX_PUSH_LOCK HandleLock;
     LIST_ENTRY HandleTableList;
     EX_PUSH_LOCK HandleContentionEvent;
     PHANDLE_TRACE_DEBUG_INFO DebugInfo;
     LONG ExtraInfoPages;
     ULONG Flags;
	 ULONG StrictFIFO:1;
     LONG FirstFreeHandle;
     PHANDLE_TABLE_ENTRY LastFreeHandleEntry;
     LONG HandleCount;
     ULONG NextHandleNeedingPool;
} HANDLE_TABLE, *PHANDLE_TABLE;

typedef struct _IMAGE_FILE_HEADER
{
    WORD Machine;
    WORD NumberOfSections;
    DWORD TimeDateStamp;
    DWORD PointerToSymbolTable;
    DWORD NumberOfSymbols;
    WORD SizeOfOptionalHeader;
    WORD Characteristics;
} IMAGE_FILE_HEADER, *PIMAGE_FILE_HEADER;

typedef struct _IMAGE_DATA_DIRECTORY
{
    DWORD VirtualAddress;
    DWORD Size;
} IMAGE_DATA_DIRECTORY, *PIMAGE_DATA_DIRECTORY;

typedef struct _IMAGE_OPTIONAL_HEADER
{
	WORD Magic;
	BYTE MajorLinkerVersion;
	BYTE MinorLinkerVersion;
	DWORD SizeOfCode;
	DWORD SizeOfInitializedData;
	DWORD SizeOfUninitializedData;
	DWORD AddressOfEntryPoint;
	DWORD BaseOfCode;
	DWORD BaseOfData;
	DWORD ImageBase;
	DWORD SectionAlignment;
	DWORD FileAlignment;
	WORD MajorOperatingSystemVersion;
	WORD MinorOperatingSystemVersion;
	WORD MajorImageVersion;
	WORD MinorImageVersion;
	WORD MajorSubsystemVersion;
	WORD MinorSubsystemVersion;
	DWORD Win32VersionValue;
	DWORD SizeOfImage;
	DWORD SizeOfHeaders;
	DWORD CheckSum;
	WORD Subsystem;
	WORD DllCharacteristics;
	DWORD SizeOfStackReserve;
	DWORD SizeOfStackCommit;
	DWORD SizeOfHeapReserve;
	DWORD SizeOfHeapCommit;
	DWORD LoaderFlags;
	DWORD NumberOfRvaAndSizes;
	IMAGE_DATA_DIRECTORY DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
} IMAGE_OPTIONAL_HEADER, *PIMAGE_OPTIONAL_HEADER;

typedef struct _IMAGE_NT_HEADERS
{
    DWORD Signature;
    IMAGE_FILE_HEADER FileHeader;
    IMAGE_OPTIONAL_HEADER OptionalHeader;
} IMAGE_NT_HEADERS, *PIMAGE_NT_HEADERS;

typedef struct _IMAGE_EXPORT_DIRECTORY
{
    DWORD Characteristics;
    DWORD TimeDateStamp;
    WORD MajorVersion;
    WORD MinorVersion;
    DWORD Name;
    DWORD Base;
    DWORD NumberOfFunctions;
    DWORD NumberOfNames;
    DWORD AddressOfFunctions;
    DWORD AddressOfNames;
    DWORD AddressOfNameOrdinals;
} IMAGE_EXPORT_DIRECTORY, *PIMAGE_EXPORT_DIRECTORY;

typedef enum _SYSTEM_INFORMATION_CLASS 
{
    SystemBasicInformation,
    SystemProcessorInformation,
    SystemPerformanceInformation,
    SystemTimeOfDayInformation,
    SystemPathInformation,
    SystemProcessInformation,
    SystemCallCountInformation,
    SystemDeviceInformation,
    SystemProcessorPerformanceInformation,
    SystemFlagsInformation,
    SystemCallTimeInformation,
    SystemModuleInformation,
    SystemLocksInformation,
    SystemStackTraceInformation,
    SystemPagedPoolInformation,
    SystemNonPagedPoolInformation,
    SystemHandleInformation,
    SystemObjectInformation,
    SystemPageFileInformation,
    SystemVdmInstemulInformation,
    SystemVdmBopInformation,
    SystemFileCacheInformation,
    SystemPoolTagInformation,
    SystemInterruptInformation,
    SystemDpcBehaviorInformation,
    SystemFullMemoryInformation,
    SystemLoadGdiDriverInformation,
    SystemUnloadGdiDriverInformation,
    SystemTimeAdjustmentInformation,
    SystemSummaryMemoryInformation,
    SystemUnused1,
    SystemPerformanceTraceInformation,
    SystemCrashDumpInformation,
    SystemExceptionInformation,
    SystemCrashDumpStateInformation,
    SystemKernelDebuggerInformation,
    SystemContextSwitchInformation,
    SystemRegistryQuotaInformation,
    SystemExtendServiceTableInformation,
    SystemPrioritySeperation,
    SystemUnused3,
    SystemUnused4,
    SystemUnused5,
    SystemUnused6,
    SystemCurrentTimeZoneInformation,
    SystemLookasideInformation,
    SystemTimeSlipNotification,
    SystemSessionCreate,
    SystemSessionDetach,
    SystemSessionInformation

} SYSTEM_INFORMATION_CLASS, *PSYSTEM_INFORMATION_CLASS;

typedef struct _SYSTEM_MODULE_INFORMATION 
{
	DWORD reserved1;
	DWORD reserved2;
	PVOID Base;
	ULONG Size;
	ULONG Flags;
	USHORT Index;
	USHORT Unknown;
	USHORT LoadCount;
	USHORT ModuleNameOffset;
	CHAR ImageName [256];
} SYSTEM_MODULE_INFORMATION,*PSYSTEM_MODULE_INFORMATION;

typedef struct _MODULE_LIST
{
	DWORD ModuleCount;
	SYSTEM_MODULE_INFORMATION Modules[];
} MODULE_LIST, *PMODULE_LIST;

typedef struct _SYSTEM_HANDLE_INFORMATION
{
	ULONG ProcessId;
	UCHAR ObjectTypeNumber;
	UCHAR Flags;
	USHORT Handle;
	PVOID Object;
	ACCESS_MASK	GrantedAccess;
} SYSTEM_HANDLE_INFORMATION,*PSYSTEM_HANDLE_INFORMATION;

typedef struct _HANDLE_LIST
{
	DWORD HandleCount;
	SYSTEM_HANDLE_INFORMATION Handles[];
} HANDLE_LIST, *PHANDLE_LIST;

typedef enum _OBJECT_INFORMATION_CLASS {
  ObjectBasicInformation=0,
  ObjectNameInformation=1, //this is undocumented!
  ObjectTypeInformation=2,
} OBJECT_INFORMATION_CLASS;


typedef struct _SYSTEM_OBJECT_TYPE_INFORMATION 
{ 
	ULONG NextEntryOffset; // absolute offset 
	ULONG ObjectCount; 
	ULONG HandleCount; 
	ULONG TypeIndex; // OB_TYPE_* (OB_TYPE_TYPE, etc.) 
	ULONG InvalidAttributes; // OBJ_* (OBJ_INHERIT, etc.) 
	GENERIC_MAPPING GenericMapping; 
	ACCESS_MASK ValidAccessMask; 
	POOL_TYPE PoolType; 
	BOOLEAN SecurityRequired; 
	BOOLEAN WaitableObject; 
	UNICODE_STRING TypeName; 
} SYSTEM_OBJECT_TYPE_INFORMATION, *PSYSTEM_OBJECT_TYPE_INFORMATION; 

typedef struct _SYSTEM_OBJECT_INFORMATION 
{ 
	ULONG NextEntryOffset; // absolute offset 
	PVOID Object; 
	ULONG CreatorProcessId; 
	USHORT CreatorBackTraceIndex; 
	USHORT Flags; // see "Native API Reference" page 24 
	LONG PointerCount; 
	LONG HandleCount; 
	ULONG PagedPoolCharge; 
	ULONG NonPagedPoolCharge; 
	ULONG ExclusiveProcessId; 
	PSECURITY_DESCRIPTOR SecurityDescriptor; 
	UNICODE_STRING ObjectName; 
} SYSTEM_OBJECT_INFORMATION, *PSYSTEM_OBJECT_INFORMATION;


typedef struct _OBJECT_BASIC_INFORMATION 
{ 
	ULONG Attributes; 
	ACCESS_MASK GrantedAccess; 
	ULONG HandleCount; 
	ULONG PointerCount; 
	ULONG PagedPoolUsage; 
	ULONG NonPagedPoolUsage; 
	ULONG Reserved[3]; 
	ULONG NameInformationLength; 
	ULONG TypeInformationLength; 
	ULONG SecurityDescriptorLength; 
	LARGE_INTEGER CreateTime; 
} OBJECT_BASIC_INFORMATION, *POBJECT_BASIC_INFORMATION; 

typedef struct _OBJECT_TYPE_INFORMATION 
{ 
	UNICODE_STRING Name; 
	ULONG ObjectCount;	
	ULONG HandleCount; 
	ULONG Reserved1[4]; 
	ULONG PeakObjectCount; 
	ULONG PeakHandleCount; 
	ULONG Reserved2[4]; 
	ULONG InvalidAttributes; 
	GENERIC_MAPPING GenericMapping; 
	ULONG ValidAccess; 
	UCHAR Unknown; 
	BOOLEAN MaintainHandleDatabase; 
	UCHAR Reserved3[2]; 
	POOL_TYPE PoolType; 
	ULONG PagedPoolUsage; 
	ULONG NonPagedPoolUsage; 
} OBJECT_TYPE_INFORMATION, *POBJECT_TYPE_INFORMATION; 


typedef struct _SYSTEM_THREAD_INFORMATION {
    LARGE_INTEGER   KernelTime;
    LARGE_INTEGER   UserTime;
    LARGE_INTEGER   CreateTime;
    ULONG			WaitTime;
    PVOID			StartAddress;
    CLIENT_ID	    ClientId;
    KPRIORITY	    Priority;
    LONG		    BasePriority;
    ULONG			ContextSwitchCount;
    ULONG			State;
    KWAIT_REASON	WaitReason;
} SYSTEM_THREAD_INFORMATION, *PSYSTEM_THREAD_INFORMATION;


typedef struct _SYSTEM_PROCESS_INFORMATION {

	ULONG NextEntryOffset; 
	ULONG NumberOfThreads; 
	LARGE_INTEGER Reserved[3]; 
	LARGE_INTEGER CreateTime; 
	LARGE_INTEGER UserTime; 
	LARGE_INTEGER KernelTime; 
	UNICODE_STRING ImageName; 
	KPRIORITY BasePriority; 
	HANDLE UniqueProcessId; 
	HANDLE InheritedFromUniqueProcessId; 
	ULONG HandleCount; 
	ULONG Reserved2[2]; 
	ULONG PrivatePageCount; 
	VM_COUNTERS VirtualMemoryCounters; 
	IO_COUNTERS IoCounters; 
	SYSTEM_THREAD_INFORMATION Threads[1];

} SYSTEM_PROCESS_INFORMATION, *PSYSTEM_PROCESS_INFORMATION;


//_____________________________________________________
//
//WINDOWS API's
//
//_____________________________________________________

NTSYSAPI NTSTATUS NTAPI LdrLoadDll(IN PWCHAR PathToFile OPTIONAL,
								   IN ULONG Flags OPTIONAL,
								   IN PUNICODE_STRING ModuleFileName,
								   OUT PHANDLE ModuleHandle );


NTSYSAPI NTSTATUS NTAPI ZwQuerySystemInformation (IN SYSTEM_INFORMATION_CLASS SystemInformationClass,
												  OUT PVOID SystemInformation,
												  IN ULONG SystemInformationLength,
												  OUT PULONG ReturnLength OPTIONAL);
PIMAGE_NT_HEADERS NTAPI RtlImageNtHeader(PVOID Base);

NTSYSAPI NTSTATUS ZwQueryObject(
    __in_opt HANDLE  Handle,
    __in OBJECT_INFORMATION_CLASS  ObjectInformationClass,
    __out_bcount_opt(ObjectInformationLength) PVOID  ObjectInformation,
    __in ULONG  ObjectInformationLength,
    __out_opt PULONG  ReturnLength
);

NTSYSAPI NTSTATUS ZwOpenProcess(__out PHANDLE ProcessHandle,
								__in ACCESS_MASK DesiredAccess,
								__in POBJECT_ATTRIBUTES ObjectAttributes,
								__in_opt PCLIENT_ID ClientId
								);

NTSYSAPI NTSTATUS ZwDuplicateObject(
									__in HANDLE hSrcProcess,
									__in PHANDLE hSrc,
									__in HANDLE hDstProcess,
									__out PHANDLE hDst,
									__in_opt ACCESS_MASK DesiredAccess,
									__in BOOL InheritHandle,
									__in LONG Options
									);

NTSTATUS PsLookupProcessByProcessId(IN HANDLE ProcessId,OUT PEPROCESS *Process);

#define MAKEWORD(a, b)      ((WORD)(((BYTE)((DWORD_PTR)(a) & 0xff)) | ((WORD)((BYTE)((DWORD_PTR)(b) & 0xff))) << 8))
#define MAKELONG(a, b)      ((LONG)(((WORD)((DWORD_PTR)(a) & 0xffff)) | ((DWORD)((WORD)((DWORD_PTR)(b) & 0xffff))) << 16))
#define LOWORD(l)           ((WORD)((DWORD_PTR)(l) & 0xffff))
#define HIWORD(l)           ((WORD)((DWORD_PTR)(l) >> 16))
#define LOBYTE(w)           ((BYTE)((DWORD_PTR)(w) & 0xff))
#define HIBYTE(w)           ((BYTE)((DWORD_PTR)(w) >> 8))

#define PTR_ADD(_base,_offset) \
        ((PVOID) ((PBYTE) (_base) + (DWORD) (_offset)))

#endif