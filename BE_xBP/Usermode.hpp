#pragma once
#include "Includes.hpp"
#include "DbgLog.hpp"

namespace BE
{
    namespace Usermode
    {
        class Bypass
        {
        public:
            Bypass::Bypass();
            Bypass::~Bypass();
            static Bypass* GetInstance();
            bool Init(HMODULE hDll), Uninit();
        private:
            bool detour_Functions(bool Status);
        protected:
#pragma region Member
            static Bypass* Instance;
            static HANDLE hEvent, hProcessHandle, hThread;
            typedef NTSTATUS(NTAPI*p_NtCreateFile)(PHANDLE FileHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PIO_STATUS_BLOCK IoStatusBlock, PLARGE_INTEGER AllocationSize, ULONG FileAttributes, ULONG ShareAccess, ULONG CreateDisposition, ULONG CreateOptions, PVOID EaBuffer, ULONG EaLength);
            typedef NTSTATUS(NTAPI*p_NtQueryInformationThread)(HANDLE ThreadHandle, THREADINFOCLASS ThreadInformationClass, PVOID ThreadInformation, ULONG ThreadInformationLength, PULONG ReturnLength);
            typedef NTSTATUS(NTAPI*p_NtOpenProcess)(PHANDLE ProcessHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PVOID Inject_GameId);
            typedef DWORD(WINAPI*p_GetWindowThreadProcessId)(HWND hWnd, LPDWORD lpdwProcessId);
            typedef NTSTATUS(NTAPI*p_NtQuerySystemInformation)(SYSTEM_INFORMATION_CLASS SystemInformationClass, PVOID SystemInformation, ULONG SystemInformationLength, PULONG ReturnLength);
            typedef NTSTATUS(NTAPI*p_NtQueryVirtualMemory)(HANDLE ProcessHandle, PVOID BaseAddress, int MemoryInformationClass, PVOID MemoryInformation, SIZE_T MemoryInformationLength, PSIZE_T ReturnLength);
            typedef HANDLE(WINAPI*p_CreateSemaphoreW)(LPSECURITY_ATTRIBUTES lpSemaphoreAttributes, LONG lInitalCount, LONG lMaximumCount, LPCWSTR lpName);
            typedef NTSTATUS(NTAPI*p_NtReadVirtualMemory)(HANDLE ProcessHandle, PVOID BaseAddress, PVOID Buffer, ULONG NumberOfBytesToRead, PULONG NumberOfBytesReaded);
            typedef NTSTATUS(NTAPI*p_ZwQueryInformationProcess)(HANDLE ProcessHandle, PROCESSINFOCLASS ProcessInformationClass, PVOID ProcessInformation, ULONG ProcessInformationLength, PULONG ReturnLength);
            typedef NTSTATUS(NTAPI*p_NtWow64QueryVirtualMemory64)(HANDLE, PVOID64, int, PVOID, ULONGLONG, PULONGLONG);
            typedef NTSTATUS(NTAPI*p_NtGetContextThread)(HANDLE ThreadHandle, PCONTEXT pContext);
            typedef NTSTATUS(NTAPI*p_NtOpenThread)(PHANDLE ThreadHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PVOID Inject_GameId);
            typedef NTSTATUS(NTAPI*p_NtWow64ReadVirtualMemory64)(HANDLE, PVOID64, PVOID, ULONGLONG, PULONGLONG);
            typedef NTSTATUS(NTAPI*p_NtReadFile)(HANDLE FileHandle, HANDLE Event, PIO_APC_ROUTINE ApcRoutine, PVOID ApcContext, PIO_STATUS_BLOCK IoStatusBlock, PVOID Buffer, ULONG Length, PLARGE_INTEGER   ByteOffset, PULONG Key);
            typedef NTSTATUS(NTAPI*p_LdrLoadDll)(IN PWCHAR PathToFile OPTIONAL, IN ULONG Flags OPTIONAL, IN PUNICODE_STRING ModuleFileName, OUT PHANDLE ModuleHandle);
            typedef NTSTATUS(NTAPI*p_LdrGetProcedureAddressForCaller)(__in HMODULE ModuleHandle, __in_opt PANSI_STRING FunctionName, __in_opt WORD Oridinal, __out PVOID *FunctionAddress, __in BOOL bValue, __in PVOID *CallbackAddress);

            typedef VOID(WINAPI*p_RtlInitUnicodeString)(PUNICODE_STRING Object, LPCWSTR String);
            static p_NtQueryVirtualMemory o_NtQueryVirtualMemory;
            static p_NtOpenProcess o_NtOpenProcess;
            static p_GetWindowThreadProcessId o_GetWindowThreadProcessId;
            static p_NtQuerySystemInformation o_NtQuerySystemInformation;
            static p_NtQueryInformationThread o_NtQueryInformationThread;
            static p_NtReadVirtualMemory o_NtReadVirtualMemory;
            static p_ZwQueryInformationProcess o_ZwQueryInformationProcess;
            static p_ZwQueryInformationProcess o_NtWow64QueryInformationProcess64;
            static p_NtWow64QueryVirtualMemory64 o_NtWow64QueryVirtualMemory64;
            static p_NtGetContextThread o_NtGetContextThread;
            static p_NtOpenThread o_NtOpenThread;
            static p_NtWow64ReadVirtualMemory64 o_NtWow64ReadVirtualMemory64;
            static p_NtReadFile o_NtReadFile;
            static p_NtCreateFile o_NtCreateFile;
            static p_LdrLoadDll o_LdrLoadDll;
            static p_LdrGetProcedureAddressForCaller o_LdrGetProcedureAddressForCaller;
            static p_RtlInitUnicodeString o_RtlInitUnicodeString;
            static DWORD_PTR Module, PEBAddr;
            static std::vector<HANDLE> fThreads, fProcesses;
#pragma endregion Member		
#pragma region Hooks
            static NTSTATUS NTAPI NtQueryVirtualMemory_Hook(HANDLE ProcessHandle, PVOID BaseAddress, int MemoryInformationClass, PVOID MemoryInformation, SIZE_T MemoryInformationLength, PSIZE_T ReturnLength);
            static NTSTATUS NTAPI NtOpenProcess_Hook(PHANDLE ProcessHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PVOID Inject_GameId);
            static DWORD WINAPI GetWindowThreadProcessId_Hook(HWND hWnd, LPDWORD lpdwProcessId);
            static NTSTATUS NTAPI NtQuerySystemInformation_Hook(SYSTEM_INFORMATION_CLASS SystemInformationClass, PVOID SystemInformation, ULONG SystemInformationLength, PULONG ReturnLength);
            static NTSTATUS NTAPI NtReadVirtualMemory_Hook(HANDLE ProcessHandle, PVOID BaseAddress, PVOID Buffer, ULONG NumberOfBytesToRead, PULONG NumberOfBytesReaded);
            static NTSTATUS NTAPI NtWow64QueryVirtualMemory64_Hook(HANDLE ProcessHandle, PVOID64 BaseAddress, int MemoryInformationClass, PVOID MemoryInformation, ULONGLONG MemoryInformationLength, PULONGLONG ReturnLength);
            static NTSTATUS NTAPI NtGetContextThread_Hook(HANDLE ThreadHandle, PCONTEXT pContext);
            static NTSTATUS NTAPI NtOpenThread_Hook(PHANDLE ThreadHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PVOID Inject_GameId);
            static NTSTATUS NTAPI ZwReadFile_Hook(HANDLE FileHandle, HANDLE Event, PIO_APC_ROUTINE ApcRoutine, PVOID ApcContext, PIO_STATUS_BLOCK IoStatusBlock, PVOID Buffer, ULONG Length, PLARGE_INTEGER   ByteOffset, PULONG Key);
            static NTSTATUS NTAPI LdrLoadDll_Hook(IN PWCHAR PathToFile OPTIONAL, IN ULONG Flags OPTIONAL, IN PUNICODE_STRING ModuleFileName, OUT PHANDLE ModuleHandle);
            static NTSTATUS NTAPI LdrGetProcedureAddressForCaller_Hook(__in HMODULE ModuleHandle, __in_opt PANSI_STRING FunctionName, __in_opt WORD Oridinal, __out PVOID *FunctionAddress, __in BOOL bValue, __in PVOID *CallbackAddress);
            static NTSTATUS NTAPI Bypass::NtCreateFile_Hook(PHANDLE FileHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PIO_STATUS_BLOCK IoStatusBlock, PLARGE_INTEGER AllocationSize, ULONG FileAttributes, ULONG ShareAccess, ULONG CreateDisposition, ULONG CreateOptions, PVOID EaBuffer, ULONG EaLength);
#pragma endregion Hooks
        };
    }
}