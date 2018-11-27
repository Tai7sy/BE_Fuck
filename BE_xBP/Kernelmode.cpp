#include "Kernelmode.hpp"

namespace BE
{
    namespace Kernelmode
    {
        XDriver* XDriver::Instance;
        std::vector<HANDLE> XDriver::fIOs;
        std::map<HANDLE, HANDLE> XDriver::hookedMap;
        XDriver::p_NtCreateFile XDriver::o_NtCreateFile;
        XDriver::p_ZwReadFile XDriver::o_ZwReadFile;
        XDriver::p_ZwWriteFile XDriver::o_ZwWriteFile;
        XDriver::p_RtlInitUnicodeString XDriver::o_RtlInitUnicodeString;
        XDriver* XDriver::GetInstance()
        {
            if (!Instance)
                Instance = new XDriver;
            return Instance;
        }
        XDriver::XDriver()
        {
            o_NtCreateFile = 0;
            o_ZwReadFile = 0;
            o_ZwWriteFile = 0;
            o_RtlInitUnicodeString = 0;
            fIOs.clear();
            hookedMap.clear();
        }
        XDriver::~XDriver()
        {
            if (Instance)
                delete Instance;
        }
        bool XDriver::Init()
        {
            return detour_DriverConnection(true);
        }
        bool XDriver::Uninit()
        {
            return detour_DriverConnection(false);
        }

        bool XDriver::detour_DriverConnection(bool Status)
        {
            VirtualizerStart();
            BOOL Result = 1;
            o_NtCreateFile = o_NtCreateFile ? o_NtCreateFile : reinterpret_cast<p_NtCreateFile>(reinterpret_cast<DWORD_PTR>(GetProcAddress(GetModuleHandle("ntdll.dll"), "NtCreateFile")));
            if (!o_NtCreateFile)
                Result = 0;
            //o_ZwReadFile = o_ZwReadFile ? o_ZwReadFile : reinterpret_cast<p_ZwReadFile>(reinterpret_cast<DWORD_PTR>(GetProcAddress(GetModuleHandle("ntdll.dll"), "ZwReadFile")));
            //if (!o_ZwReadFile)
            //	Result = 0;
            //o_ZwWriteFile = o_ZwWriteFile ? o_ZwWriteFile : reinterpret_cast<p_ZwWriteFile>(reinterpret_cast<DWORD_PTR>(GetProcAddress(GetModuleHandle("ntdll.dll"), "ZwWriteFile")));
            //if (!o_ZwWriteFile)
            //	Result = 0;

            o_RtlInitUnicodeString = o_RtlInitUnicodeString ? o_RtlInitUnicodeString : reinterpret_cast<p_RtlInitUnicodeString>(reinterpret_cast<DWORD_PTR>(GetProcAddress(GetModuleHandle("ntdll.dll"), "RtlInitUnicodeString")));
            if (!o_RtlInitUnicodeString)
                Result = 0;
            if (DetourTransactionBegin() != NO_ERROR ||
                DetourUpdateThread(GetCurrentThread()) != NO_ERROR ||
                (Status ? DetourAttach : DetourDetach)(&(PVOID&)o_NtCreateFile, NtCreateFile_Hook) != NO_ERROR ||
                //(Status ? DetourAttach : DetourDetach)(&(PVOID&)o_ZwReadFile, ZwReadFile_Hook) != NO_ERROR ||
                //(Status ? DetourAttach : DetourDetach)(&(PVOID&)o_ZwWriteFile, ZwWriteFile_Hook) != NO_ERROR ||
                DetourTransactionCommit() != NO_ERROR)
                Result = 0;
            VirtualizerEnd();
            return Result;
        }


        NTSTATUS NTAPI XDriver::NtCreateFile_Hook(PHANDLE FileHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PIO_STATUS_BLOCK IoStatusBlock, PLARGE_INTEGER AllocationSize, ULONG FileAttributes, ULONG ShareAccess, ULONG CreateDisposition, ULONG CreateOptions, PVOID EaBuffer, ULONG EaLength)
        {
            VirtualizerStart();
            DWORD dwWritten = 0;
            NTSTATUS Status = -1;
            if (ObjectAttributes &&
                ObjectAttributes->ObjectName &&
                ObjectAttributes->ObjectName->Buffer &&
                wcsstr(ObjectAttributes->ObjectName->Buffer, L"BattlEye") &&
                wcsstr(ObjectAttributes->ObjectName->Buffer, L"pipe")) // the pipename is \\??\\pipe\\BattlEye 内核名字和应用层不一样
            {

                /*
                if (GetModuleHandleA(MAIN_GAME_NAME)) {
                    DbgLog::Log("Unturned.exe NtCreateFile_Hook:\n");
                    OutputDebugStringW(ObjectAttributes->ObjectName->Buffer);
                }
                if (GetModuleHandleA(GAME_NAME)) {
                    DbgLog::Log("Unturned_BE.exe NtCreateFile_Hook:\n");
                    OutputDebugStringW(ObjectAttributes->ObjectName->Buffer);
                }
                */

                // OutputDebugStringA("NtCreateFile_Hook: pipe hooked \n");
#if BYPASS_METHOD_INJECT_GAME
                // change the pipe name to our
                o_RtlInitUnicodeString(ObjectAttributes->ObjectName, SERVICE_PROXY_KERNEL);
#endif
                NTSTATUS Status = o_NtCreateFile(FileHandle, DesiredAccess, ObjectAttributes, IoStatusBlock, AllocationSize, FileAttributes, ShareAccess, CreateDisposition, CreateOptions, EaBuffer, EaLength);
                // o_RtlInitUnicodeString(ObjectAttributes->ObjectName, SERVICE_PIPE_KERNEL); doesn't work

                //if (NT_SUCCESS(Status)) {
                //	hookedMap[*FileHandle] = CreateFileA(SERVICE_PROXY, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, 0);
                //}

                return Status;
            }
            VirtualizerEnd();
            return o_NtCreateFile(FileHandle, DesiredAccess, ObjectAttributes, IoStatusBlock, AllocationSize, FileAttributes, ShareAccess, CreateDisposition, CreateOptions, EaBuffer, EaLength);

        };


        BOOL GetFileNameFromHandle(HANDLE hFile, std::string& fileName)
        {
            DWORD size = MAX_PATH * sizeof(WCHAR) + sizeof(DWORD);
            FILE_NAME_INFO* Path = (FILE_NAME_INFO*)malloc(size);
            memset(Path, 0, size);
            BOOL ret = GetFileInformationByHandleEx(hFile, FILE_INFO_BY_HANDLE_CLASS::FileNameInfo, Path, size);
            if (!ret) return false;
            std::wstring wstr = Path->FileName;
            fileName = std::string(wstr.begin(), wstr.end());
            free(Path);
            return true;
        }

        NTSTATUS NTAPI XDriver::ZwReadFile_Hook(HANDLE FileHandle, HANDLE Event, PIO_APC_ROUTINE  ApcRoutine, PVOID ApcContext, PIO_STATUS_BLOCK IoStatusBlock, PVOID Buffer, ULONG Length, PLARGE_INTEGER   ByteOffset, PULONG Key)
        {
            std::string fileName;
            if (GetFileNameFromHandle(FileHandle, fileName))
            {
                bool isBattlEye = fileName.compare("\\BattlEye") == 0;
                if (isBattlEye) {
                    auto search = hookedMap.find(FileHandle);
                    if (search != hookedMap.end()) {
                        FileHandle = search->second;
                    }
                    else {
                        OutputDebugStringA("[DLL_HOOK] Unturned_BE.exe ZwReadFile_Hook: Handle not found\n");
                    }
                }
            }
            return o_ZwReadFile(FileHandle, Event, ApcRoutine, ApcContext, IoStatusBlock, Buffer, Length, ByteOffset, Key);
        }

        NTSTATUS NTAPI XDriver::ZwWriteFile_Hook(HANDLE FileHandle, HANDLE Event, PIO_APC_ROUTINE  ApcRoutine, PVOID ApcContext, PIO_STATUS_BLOCK IoStatusBlock, PVOID Buffer, ULONG Length, PLARGE_INTEGER   ByteOffset, PULONG Key)
        {
            std::string fileName;
            if (GetFileNameFromHandle(FileHandle, fileName))
            {
                bool isBattlEye = fileName.compare("\\BattlEye") == 0;
                if (isBattlEye) {
                    auto search = hookedMap.find(FileHandle);
                    if (search != hookedMap.end()) {
                        FileHandle = search->second;
                    }
                    else {
                        OutputDebugStringA("[DLL_HOOK] Unturned_BE.exe ZwReadFile_Hook: Handle not found\n");
                    }
                }
            }
            return o_ZwWriteFile(FileHandle, Event, ApcRoutine, ApcContext, IoStatusBlock, Buffer, Length, ByteOffset, Key);
        }
    }
}