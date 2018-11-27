#pragma once
#include "Includes.hpp"
#include "DbgLog.hpp"

namespace  BE
{
	namespace Kernelmode
	{
		class XDriver
		{
		public:
			XDriver();
			~XDriver();
			static XDriver* GetInstance();
			bool Init(), Uninit();
		private:
			bool detour_DriverConnection(bool Status);
			static NTSTATUS NTAPI NtCreateFile_Hook(PHANDLE FileHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PIO_STATUS_BLOCK IoStatusBlock, PLARGE_INTEGER AllocationSize, ULONG FileAttributes, ULONG ShareAccess, ULONG CreateDisposition, ULONG CreateOptions, PVOID EaBuffer, ULONG EaLength);
			static NTSTATUS NTAPI XDriver::ZwReadFile_Hook(HANDLE FileHandle, HANDLE Event, PIO_APC_ROUTINE  ApcRoutine, PVOID ApcContext, PIO_STATUS_BLOCK IoStatusBlock, PVOID Buffer, ULONG Length, PLARGE_INTEGER   ByteOffset, PULONG Key);
			static NTSTATUS NTAPI XDriver::ZwWriteFile_Hook(HANDLE FileHandle, HANDLE Event, PIO_APC_ROUTINE  ApcRoutine, PVOID ApcContext, PIO_STATUS_BLOCK IoStatusBlock, PVOID Buffer, ULONG Length, PLARGE_INTEGER   ByteOffset, PULONG Key);
		protected:
			typedef NTSTATUS(NTAPI*p_NtQueryInformationThread)(HANDLE ThreadHandle, THREADINFOCLASS ThreadInformationClass, PVOID ThreadInformation, ULONG ThreadInformationLength, PULONG ReturnLength);
			typedef NTSTATUS(NTAPI*p_NtCreateFile)(PHANDLE FileHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PIO_STATUS_BLOCK IoStatusBlock, PLARGE_INTEGER AllocationSize, ULONG FileAttributes, ULONG ShareAccess, ULONG CreateDisposition, ULONG CreateOptions, PVOID EaBuffer, ULONG EaLength);
			typedef NTSTATUS(NTAPI*p_ZwReadFile)(HANDLE FileHandle, HANDLE Event, PIO_APC_ROUTINE ApcRoutine, PVOID ApcContext, PIO_STATUS_BLOCK IoStatusBlock, PVOID Buffer, ULONG Length, PLARGE_INTEGER  ByteOffset, PULONG Key);
			typedef NTSTATUS(NTAPI*p_ZwWriteFile)(HANDLE FileHandle, HANDLE Event, PIO_APC_ROUTINE  ApcRoutine, PVOID ApcContext, PIO_STATUS_BLOCK IoStatusBlock, PVOID Buffer, ULONG Length, PLARGE_INTEGER ByteOffset, PULONG Key);
			typedef VOID(WINAPI*p_RtlInitUnicodeString)(PUNICODE_STRING Object, LPCWSTR String);
			static p_NtCreateFile o_NtCreateFile;
			static p_ZwReadFile o_ZwReadFile;
			static p_ZwWriteFile o_ZwWriteFile;
			static p_RtlInitUnicodeString o_RtlInitUnicodeString;
			static p_NtQueryInformationThread o_NtQueryInformationThread;

			static std::vector<HANDLE> fIOs;
			static std::map<HANDLE, HANDLE> hookedMap;
			static XDriver* Instance;
			static HANDLE hEvent, hService;
		};
	}
}