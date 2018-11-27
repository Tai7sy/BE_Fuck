#include "Listener.hpp"
#include <sstream>
#include <fstream>


std::ofstream LogFile;
// std::wofstream LogFileW;
std::ostringstream OutputBuffer;

void hex_dump(PVOID Buffer, size_t length, std::ostringstream& OutputBuffer) {
    OutputBuffer.str("");
    OutputBuffer.clear();
    OutputBuffer << "│ ";
    for (size_t i = 0; i < length; i++)
    {
        OutputBuffer.fill('0');
        OutputBuffer.width(2);
        OutputBuffer << std::hex << (int)(*((unsigned char *)Buffer + i));
        OutputBuffer << " ";
    }
    OutputBuffer << std::endl << "│ ";
    for (size_t i = 0; i < length; i++)
    {
        OutputBuffer << *((unsigned char *)Buffer + i);
    }
}

namespace BE
{
    namespace Listener
    {
        Listener* Listener::Instance;
        Listener::p_NtCreateFile Listener::o_NtCreateFile;
        Listener::p_ZwReadFile Listener::o_ZwReadFile;
        Listener::p_ZwWriteFile Listener::o_ZwWriteFile;
        Listener::p_NtQuerySystemInformation Listener::o_NtQuerySystemInformation;
        Listener::p_NtQueryObject Listener::o_NtQueryObject;
        Listener* Listener::GetInstance()
        {
            if (!Instance)
                Instance = new Listener;
            return Instance;
        }
        Listener::Listener()
        {
            o_NtCreateFile = 0;
            o_ZwReadFile = 0;
            o_ZwWriteFile = 0;
        }
        Listener::~Listener()
        {
            if (Instance)
                delete Instance;
        }
        bool Listener::Init()
        {
            LogFile = std::ofstream(BESERVICE_LISTENER_LOGPATH);
            // LogFileW = std::wofstream("D:\\MyProjects\\VSProjects\\BE_Fuck\\Log_BEService2.txt");
            if (detour_DriverConnection(true)) {
                LogFile << "[Dll_Hook] Listener hook successfully." << std::endl;
                return true;
            }
            else {
                LogFile << "[Dll_Hook] Failed to initialize BattlEye Listener (errorcode : " << GetLastError() << ")" << std::endl;
                return false;
            }
        }
        bool Listener::Uninit()
        {
            return detour_DriverConnection(false);
        }

        bool Listener::detour_DriverConnection(bool Status)
        {
            VirtualizerStart();
            BOOL Result = 1;
            o_NtCreateFile = o_NtCreateFile ? o_NtCreateFile : reinterpret_cast<p_NtCreateFile>(reinterpret_cast<DWORD_PTR>(GetProcAddress(GetModuleHandle("ntdll.dll"), "NtCreateFile")));
            if (!o_NtCreateFile)
                Result = 0;
            o_ZwReadFile = o_ZwReadFile ? o_ZwReadFile : reinterpret_cast<p_ZwReadFile>(reinterpret_cast<DWORD_PTR>(GetProcAddress(GetModuleHandle("ntdll.dll"), "ZwReadFile")));
            if (!o_ZwReadFile)
                Result = 0;
            o_ZwWriteFile = o_ZwWriteFile ? o_ZwWriteFile : reinterpret_cast<p_ZwWriteFile>(reinterpret_cast<DWORD_PTR>(GetProcAddress(GetModuleHandle("ntdll.dll"), "ZwWriteFile")));
            if (!o_ZwWriteFile)
                Result = 0;
            o_NtQuerySystemInformation = o_NtQuerySystemInformation ? o_NtQuerySystemInformation : reinterpret_cast<p_NtQuerySystemInformation>(GetProcAddress(GetModuleHandle("ntdll.dll"), "NtQuerySystemInformation"));
            if (!o_NtQuerySystemInformation)
                Result = 0;
            o_NtQueryObject = o_NtQueryObject ? o_NtQueryObject : reinterpret_cast<p_NtQueryObject>(GetProcAddress(GetModuleHandle("ntdll.dll"), "NtQueryObject"));
            if (!o_NtQueryObject)
                Result = 0;

            if (DetourTransactionBegin() != NO_ERROR ||
                DetourUpdateThread(GetCurrentThread()) != NO_ERROR ||
                (Status ? DetourAttach : DetourDetach)(&(PVOID&)o_NtCreateFile, NtCreateFile_Hook) != NO_ERROR ||
                (Status ? DetourAttach : DetourDetach)(&(PVOID&)o_ZwReadFile, ZwReadFile_Hook) != NO_ERROR ||
                (Status ? DetourAttach : DetourDetach)(&(PVOID&)o_ZwWriteFile, ZwWriteFile_Hook) != NO_ERROR ||
                DetourTransactionCommit() != NO_ERROR)
                Result = 0;

#if BESERVICE_LISTENER_MODE == 0
            static HANDLE hThread = NULL;
            if (Status) {
                hThread = CreateThread(0, 0, CloseOldPipe_Thread, 0, 0, 0);
                if (hThread > 0)
                    CloseHandle(hThread);
                else Result = 0;
            }
            else {
                TerminateThread(hThread, 0);
                hThread = 0;
            }
#endif
            VirtualizerEnd();
            return Result;
        }


        NTSTATUS NTAPI Listener::NtCreateFile_Hook(PHANDLE FileHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PIO_STATUS_BLOCK IoStatusBlock, PLARGE_INTEGER AllocationSize, ULONG FileAttributes, ULONG ShareAccess, ULONG CreateDisposition, ULONG CreateOptions, PVOID EaBuffer, ULONG EaLength)
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

                // 经测试根本不会到这里，BEService CreateFile 的速度太快了，这里根本Hook不上.....
                DbgLog::Log("[BEService] CreateFile NamedPipe: %ls", ObjectAttributes->ObjectName->Buffer);
#if BESERVICE_LISTENER_MODE
                LogFile << "[BEService] CreateFile NamedPipe!" << std::endl;
#else               
                memcpy(ObjectAttributes->ObjectName->Buffer, L"\\??\\pipe\\BattlEy2", (wcslen(L"\\??\\pipe\\BattlEy2")) * sizeof(wchar_t));
                DbgLog::Log("[BEService] CreateFile: %ls (Hooked)", ObjectAttributes->ObjectName->Buffer);
                LogFile << "[BEService] NamedPipe Created! Change to \\??\\pipe\\BattlEy2";
#endif
                LogFile.flush();
                return o_NtCreateFile(FileHandle, DesiredAccess, ObjectAttributes, IoStatusBlock, AllocationSize, FileAttributes, ShareAccess, CreateDisposition, CreateOptions, EaBuffer, EaLength);
            }
            VirtualizerEnd();
            return o_NtCreateFile(FileHandle, DesiredAccess, ObjectAttributes, IoStatusBlock, AllocationSize, FileAttributes, ShareAccess, CreateDisposition, CreateOptions, EaBuffer, EaLength);

        };

#if BESERVICE_LISTENER_MODE == 0
        typedef struct _SYSTEM_HANDLE
        {
            ULONG            ProcessId;    //进程ID
            UCHAR            ObjectTypeNumber;
            UCHAR            Flags;
            USHORT           Handle;    //句柄
            PVOID            Object;    //句柄 Object
            ACCESS_MASK      GrantedAccess;
        } SYSTEM_HANDLE, *PSYSTEM_HANDLE; /* 大小 0x18 最后4字节是补的*/
        typedef struct _SYSTEM_HANDLE_INFORMATION
        {
            ULONG NumberOfHandles;           //数组数量 +0
            SYSTEM_HANDLE Information[1];    //数组指针 +8 (上面对其补了4位)
        }SYSTEM_HANDLE_INFORMATION, *PSYSTEM_HANDLE_INFORMATION;

        typedef struct _OBJECT_NAME_INFORMATION {
            UNICODE_STRING Name;
        } OBJECT_NAME_INFORMATION, *POBJECT_NAME_INFORMATION;

#define STATUS_SUCCESS                   ((NTSTATUS)0x00000000L)
#define STATUS_UNSUCCESSFUL              ((NTSTATUS)0xC0000001L)
#define SystemHandleInformation          (SYSTEM_INFORMATION_CLASS)16
#define STATUS_INFO_LENGTH_MISMATCH      ((NTSTATUS)0xC0000004L)
#define ObjectNameInformation            (OBJECT_INFORMATION_CLASS)1


        BOOL GetFileNameFromHandle2(HANDLE hFile, WCHAR* fileName)
        {
            DWORD size = MAX_PATH * sizeof(WCHAR) + sizeof(DWORD);
            FILE_NAME_INFO* Path = (FILE_NAME_INFO*)malloc(size);
            memset(Path, 0, size);
            BOOL ret = GetFileInformationByHandleEx(hFile, FILE_INFO_BY_HANDLE_CLASS::FileNameInfo, Path, size);
            if (!ret) {
                return false;
            }
            memcpy(fileName, Path->FileName, Path->FileNameLength * sizeof(WCHAR));
            fileName[Path->FileNameLength] = 0;
            free(Path);
            return true;
        }

        DWORD WINAPI Listener::CloseOldPipe_Thread(LPVOID lpParam) {
            NTSTATUS Status = 0;
            ULONG dwReturnLength = 0;
            DWORD dwProcessId = GetCurrentProcessId();
            WCHAR szName[512] = { 0 };
            POBJECT_NAME_INFORMATION pNameInfo;
            DWORD dwBufferLength = 0;
            bool find = false;

            if (dwProcessId > 65535) {
                LogFile << "CurrentProcessId: " << dwProcessId << " > 65535, Please restart computer." << std::endl;
                exit;
            }
            while (1) {
                PVOID pInfo = malloc(sizeof(SYSTEM_HANDLE_INFORMATION));
                if (pInfo == NULL) return FALSE;
                Status = o_NtQuerySystemInformation(SystemHandleInformation, pInfo, sizeof(SYSTEM_HANDLE_INFORMATION), &dwReturnLength);  //得到要分配的内存大小
                free(pInfo);
                if (Status == STATUS_INFO_LENGTH_MISMATCH && dwReturnLength != 0) {
                    pInfo = malloc(dwReturnLength * 2);
                    if (pInfo != NULL) {
                        Status = o_NtQuerySystemInformation(SystemHandleInformation, pInfo, dwReturnLength * 2, &dwReturnLength);
                        if (STATUS_SUCCESS == Status) {
                            PSYSTEM_HANDLE_INFORMATION pHIContainer = (PSYSTEM_HANDLE_INFORMATION)pInfo;

                            // LogFileW << "CurrentProcessId: " << dwProcessId << std::endl;
                            // LogFileW << "Handles: " << pHIContainer->NumberOfHandles << std::endl;
                            // LogFileW.flush();
                            for (ULONG i = 0; i < pHIContainer->NumberOfHandles; i++)
                            {
                                SYSTEM_HANDLE pHI = pHIContainer->Information[i];


                                // LogFileW << "ProcessId: " << std::dec << pHI.ProcessId << ", Handle:" << std::hex << pHI.Handle;
                                // LogFileW.flush();
                                if (dwProcessId == pHI.ProcessId) {


                                    // Status = o_NtQueryObject((HANDLE)pHI.Handle, ObjectNameInformation, szName, 512, &dwBufferLength);

                                    if (GetFileNameFromHandle2((HANDLE)pHI.Handle, szName)) {
                                        // LogFileW << "GetFileNameFromHandle failed error: " << std::dec << GetLastError() << std::endl;
                                        // LogFileW.flush();
                                        CloseHandle((HANDLE)pHI.Handle);
                                        find = true;
                                        continue;
                                    }

                                    // LogFileW << ", Name:" << szName << std::endl;
                                    // LogFileW.flush();
                                    if (wcsstr(szName, L"\\\\.\\pipe\\BattlEye")) {
                                        CloseHandle((HANDLE)pHI.Handle);
                                        find = true;
                                    }


                                    /*
                                    pNameInfo = (POBJECT_NAME_INFORMATION)szName;
                                    LogFileW << ", Name:" << (wchar_t *)pNameInfo->Name.Buffer << std::endl;
                                    LogFileW.flush();
                                    if (wcsstr((wchar_t *)pNameInfo->Name.Buffer, L"\\\\.\\pipe\\BattlEye")) {
                                        CloseHandle((HANDLE)pHI.Handle);
                                        find = true;
                                    }*/
                                }

                                // LogFileW << std::endl;
                                // LogFileW.flush();
                            }
                            // LogFileW << std::endl << std::endl << std::endl;
                            // LogFileW.flush();
                            goto Exit;
                        }
                        else {
                            LogFile << "ZwQuerySystemInformation2, error: " << std::hex << Status << std::endl;
                        }
                        free(pInfo);
                    }
                }
                else {
                    LogFile << "ZwQuerySystemInformation1, error: " << std::hex << Status << std::endl;
                }
                Sleep(1000);
                if (find) goto Exit;
            }
        Exit:
            return NT_SUCCESS(Status);
        }
#endif


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

        NTSTATUS NTAPI Listener::ZwReadFile_Hook(HANDLE FileHandle, HANDLE Event, PIO_APC_ROUTINE  ApcRoutine, PVOID ApcContext, PIO_STATUS_BLOCK IoStatusBlock, PVOID Buffer, ULONG Length, PLARGE_INTEGER   ByteOffset, PULONG Key)
        {
            std::string fileName;
            if (!GetFileNameFromHandle(FileHandle, fileName))
            {
                fileName = "unknown";
            }

            NTSTATUS Status = o_ZwReadFile(FileHandle, Event, ApcRoutine, ApcContext, IoStatusBlock, Buffer, Length, ByteOffset, Key);

            bool isBattlEye = fileName.compare("\\BattlEye") == 0;
            if (isBattlEye) {
                if (NT_SUCCESS(Status)) {
                    DbgLog::Log("[BEService] ReadFile from:%s", fileName);
                    LogFile << "[BEService] ReadFile from: " << fileName << std::endl;
                    hex_dump(Buffer, Length, OutputBuffer);
                    LogFile << "│ [ID: " << (DWORD)reinterpret_cast<CHAR*>(Buffer)[0] << "][Recv] [" << Length << " bytes]\n" << OutputBuffer.str() << std::endl << std::endl;
                    LogFile.flush();
                }
                else {
                    DbgLog::Log("[BEService] ReadFile from:%ls error:%d", fileName, Status);
                    LogFile << "[BEService] ReadFile from: " << fileName << " error:" << Status << std::endl;
                }
            }
            return Status;
        }

        NTSTATUS NTAPI Listener::ZwWriteFile_Hook(HANDLE FileHandle, HANDLE Event, PIO_APC_ROUTINE  ApcRoutine, PVOID ApcContext, PIO_STATUS_BLOCK IoStatusBlock, PVOID Buffer, ULONG Length, PLARGE_INTEGER   ByteOffset, PULONG Key)
        {
            std::string fileName;
            if (!GetFileNameFromHandle(FileHandle, fileName))
            {
                fileName = "unknown";
            }

            NTSTATUS Status = o_ZwWriteFile(FileHandle, Event, ApcRoutine, ApcContext, IoStatusBlock, Buffer, Length, ByteOffset, Key);

            bool isBattlEye = fileName.compare("\\BattlEye") == 0;
            if (isBattlEye) {
                if (NT_SUCCESS(Status)) {
                    DbgLog::Log("[BEService] WriteFile from:%s", fileName);
                    LogFile << "[BEService] WriteFile from: " << fileName << std::endl;
                    hex_dump(Buffer, Length, OutputBuffer);
                    LogFile << "│ [ID: " << (DWORD)reinterpret_cast<CHAR*>(Buffer)[0] << "][Send] [" << Length << " bytes]\n" << OutputBuffer.str() << std::endl << std::endl;
                    LogFile.flush();

                }
                else {
                    DbgLog::Log("[BEService] WriteFile from:%ls error:%d", fileName, Status);
                    LogFile << "[BEService] WriteFile from: " << fileName << " error:" << Status << std::endl;
                }
            }
            return Status;
        }
    }
}