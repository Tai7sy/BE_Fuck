#pragma once
#include "Includes.hpp"
#include "DbgLog.hpp"

#ifdef _WIN64

typedef struct _WPEB_LDR_DATA {
	ULONG			Length;
	UCHAR			Initialized;
	ULONG64			SsHandle;
	LIST_ENTRY64	InLoadOrderModuleList;
	LIST_ENTRY64	InMemoryOrderModuleList;
	LIST_ENTRY64	InInitializationOrderModuleList;
	PVOID64			EntryInProgress;
	UCHAR			ShutdownInProgress;
	PVOID64			ShutdownThreadId;
} WPEB_LDR_DATA, *WPPEB_LDR_DATA;

typedef struct _WPEB {
	UCHAR				InheritedAddressSpace;
	UCHAR				ReadImageFileExecOptions;
	UCHAR				BeingDebugged;
	BYTE				Reserved0;
	ULONG				Reserved1;
	ULONG64				Reserved3;
	ULONG64				ImageBaseAddress;
	_WPEB_LDR_DATA*     LoaderData;
	ULONG64				ProcessParameters;
}WPEB, *WPPEB;


typedef struct _WLDR_DATA_TABLE_ENTRY
{
	LIST_ENTRY	    	InLoadOrderModuleList;
	LIST_ENTRY	     	InMemoryOrderModuleList;
	LIST_ENTRY   		InInitializationOrderModuleList;
	ULONG64				BaseAddress;
	ULONG64				EntryPoint;
	ULONG				SizeOfImage;	
	UNICODE_STRING		FullDllName;
	UNICODE_STRING		BaseDllName;
	ULONG				Flags;
	USHORT				LoadCount;
} WLDR_DATA_TABLE_ENTRY, *WPLDR_DATA_TABLE_ENTRY;

#else

typedef struct _WPEB_LDR_DATA {
	DWORD					Length;
	UCHAR					Initialized;
	PVOID	                SsHandle;
	LIST_ENTRY              InLoadOrderModuleList;
	LIST_ENTRY				InMemoryOrderModuleList;
	LIST_ENTRY              InInitializationOrderModuleList;
	PVOID					EntryInProgress;
	UCHAR					ShutdownInProgress;
	PVOID					ShutdownThreadId;
} WPEB_LDR_DATA, *WPPEB_LDR_DATA;

typedef struct _WPEB {
	UCHAR InheritedAddressSpace;
	UCHAR ReadImageFileExecOptions;
	UCHAR BeingDebugged;
	BYTE Reserved2[9];
	WPPEB_LDR_DATA LoaderData;
	PRTL_USER_PROCESS_PARAMETERS ProcessParameters;
	BYTE Reserved3[448];
	ULONG SessionId;
}WPEB, *WPPEB;

typedef struct _WLDR_DATA_TABLE_ENTRY
{
	LIST_ENTRY            InLoadOrderModuleList;
	LIST_ENTRY            InMemoryOrderModuleList;
	LIST_ENTRY            InInitializationOrderModuleList;
	PVOID                 BaseAddress;
	PVOID                 EntryPoint;
	ULONG                 SizeOfImage;
	UNICODE_STRING        FullDllName;
	UNICODE_STRING        BaseDllName;
	ULONG                 Flags;
	USHORT				  LoadCount;
	USHORT                 TlsIndex;
	LIST_ENTRY            HashTableEntry;
	union
	{
		LIST_ENTRY HashLinks;
		struct
		{
			PVOID SectionPointer;
			ULONG CheckSum;
		};
	};
	union
	{
		ULONG TimeDateStamp;
		PVOID LoadedImports;
	};
	_ACTIVATION_CONTEXT *	EntryPointActivationContext;
	PVOID					PatchInformation;
	LIST_ENTRY				ForwarderLinks;
	LIST_ENTRY				ServiceTagLinks;
	LIST_ENTRY				StaticLinks;
	PVOID					ContextInformation;
	DWORD					OriginalBase;
	LARGE_INTEGER			LoadTime;
} WLDR_DATA_TABLE_ENTRY, *WPLDR_DATA_TABLE_ENTRY;
#endif

namespace Module
{
	static bool ModuleOnAttach(LPCSTR Modulename, HMODULE hDll)
	{
		_MEMORY_BASIC_INFORMATION mbi;
		DWORD Old = 0;
#ifdef _WIN64
		PLIST_ENTRY64 pListEntry = 0;
		_WLDR_DATA_TABLE_ENTRY* pModule = 0;
		_WPEB* pPEB = reinterpret_cast<_WPEB*>(__readgsqword(0x60));
#else
		PLIST_ENTRY pListEntry = 0;
		_WLDR_DATA_TABLE_ENTRY* pModule = 0;
		_WPEB* pPEB = reinterpret_cast<_WPEB*>(__readfsdword(0x30));
#endif
		
		
		ZeroMemory(&mbi, sizeof(mbi));
		
		if (!pPEB)
			return false;

#ifdef _WIN64
		pListEntry = reinterpret_cast<PLIST_ENTRY64>(pPEB->LoaderData->InLoadOrderModuleList.Flink);
#else
		pListEntry = reinterpret_cast<PLIST_ENTRY>(pPEB->LoaderData->InLoadOrderModuleList.Flink);
#endif
		while (pListEntry != &pPEB->LoaderData->InLoadOrderModuleList && pListEntry != NULL) {

			pModule = reinterpret_cast<_WLDR_DATA_TABLE_ENTRY*>(pListEntry->Flink);
#ifdef _WIN64
			if (pModule->BaseAddress == reinterpret_cast<ULONG64>(hDll))
			{
				pModule->InLoadOrderModuleList.Flink->Blink = pModule->InLoadOrderModuleList.Blink;
				pModule->InLoadOrderModuleList.Blink->Flink = pModule->InLoadOrderModuleList.Flink;

				pModule->InMemoryOrderModuleList.Flink->Blink = pModule->InMemoryOrderModuleList.Blink;
				pModule->InMemoryOrderModuleList.Blink->Flink = pModule->InMemoryOrderModuleList.Flink;

				pModule->InInitializationOrderModuleList.Flink->Blink = pModule->InInitializationOrderModuleList.Blink;
				pModule->InInitializationOrderModuleList.Blink->Flink = pModule->InInitializationOrderModuleList.Flink;

				break;
			}
			pListEntry = reinterpret_cast<PLIST_ENTRY64>(pListEntry->Flink);
#else
			if (pModule->BaseAddress == hDll)
			{
				pModule->InLoadOrderModuleList.Flink->Blink = pModule->InLoadOrderModuleList.Blink;
				pModule->InLoadOrderModuleList.Blink->Flink = pModule->InLoadOrderModuleList.Flink;

				pModule->InMemoryOrderModuleList.Flink->Blink = pModule->InMemoryOrderModuleList.Blink;
				pModule->InMemoryOrderModuleList.Blink->Flink = pModule->InMemoryOrderModuleList.Flink;

				pModule->InInitializationOrderModuleList.Flink->Blink = pModule->InInitializationOrderModuleList.Blink;
				pModule->InInitializationOrderModuleList.Blink->Flink = pModule->InInitializationOrderModuleList.Flink;

				break;
			}
			pListEntry = reinterpret_cast<PLIST_ENTRY>(pListEntry->Flink);
#endif

			
		}
		if (!VirtualQuery(hDll, &mbi, sizeof(mbi)))
			return false;
		if (!VirtualProtect(mbi.BaseAddress, mbi.RegionSize, PAGE_EXECUTE_READWRITE, &Old))
			return false;
		ZeroMemory(mbi.BaseAddress, mbi.RegionSize);
		if (!VirtualProtect(mbi.BaseAddress, mbi.RegionSize, Old, &Old))
			return false;
		return true;
	}
	static bool ModuleOnDetach(LPCSTR Modulename)
	{
		return true;
	}
}