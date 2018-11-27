#include "cMain.hpp"
//=======================================================================================================================================================
void MyOutputDebugString(LPCSTR lpszFormat, ...)
{
    if (lpszFormat == NULL) return;
    va_list arglist;
    va_start(arglist, lpszFormat);
    char str[4095];
    vsprintf_s(str, lpszFormat, arglist);
    size_t len = strlen(str);
    if (str[len - 1] != '\n') {
        str[len] = '\n';
        str[len + 1] = 0;
    }
    OutputDebugStringA(str);
}


bool InjectBypass()
{
    VirtualizerStart();
    char Path[MAX_PATH];
    BOOL Status = true;
    HANDLE hProcess = INVALID_HANDLE_VALUE, hToken = 0, hThread = 0;
    DWORD gId = 0, lastId = 0, ReturnLength = 0, dwError = 0, TID = 0;
    BOOL bReturn = 0, isDebug = 0, Is64 = 0;
    LUID Luid;
    MODULEINFO Info;
    STARTUPINFOA si;
    PROCESS_INFORMATION pi;
    TOKEN_PRIVILEGES NewState, PreviousState;
    LPVOID lpLoadLibAddress = GetProcAddress(GetModuleHandleA("kernel32.dll"), "LoadLibraryA"), lpString = 0;

    PVOID pLoadLibAddress = GetProcAddress(GetModuleHandleA("Kernel32.dll"), "LoadLibraryA");
    PVOID pLoadLibArgument = 0;
    SIZE_T NumofBytes = 0;

    ZeroMemory(&Luid, sizeof(LUID));
    ZeroMemory(&NewState, sizeof(TOKEN_PRIVILEGES));
    ZeroMemory(&PreviousState, sizeof(TOKEN_PRIVILEGES));
    ZeroMemory(Path, MAX_PATH);
    ZeroMemory(&Info, sizeof(Info));
    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    ZeroMemory(&pi, sizeof(pi));

    auto GetProcessId = [](char* ProcessName)->DWORD
    {
        VirtualizerStart();
        PROCESSENTRY32 pe32;
        DWORD dwPid = 0;
        HANDLE hSnapshot = 0;
        BOOL Found = 0;
        hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (hSnapshot == INVALID_HANDLE_VALUE || hSnapshot == 0)
        {
            SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), FOREGROUND_INTENSITY | FOREGROUND_RED);
            std::cout << "[Inject_BE] [>>] [ERROR] : CreateToolhelp32Snapshot failed with errorcode " << GetLastError() << std::endl;
            SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
            return false;
        }
        pe32.dwSize = sizeof(PROCESSENTRY32);
        if (!Process32First(hSnapshot, &pe32))
        {
            SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), FOREGROUND_INTENSITY | FOREGROUND_RED);
            std::cout << "[Inject_BE] [>>] [ERROR] : Process32First failed with errorcode " << GetLastError() << std::endl;
            CloseHandle(hSnapshot);
            SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
            return false;
        }
        do
        {
            Found = false;
            for (auto pId : pProcessIds)
                if (pe32.th32ProcessID == pId) Found = true;
            if (!lstrcmpiA(pe32.szExeFile, ProcessName) &&
                !Found)
            {
                std::cout << "[Inject_BE] [>>] Process found! (ID : " << pe32.th32ProcessID << ")" << std::endl;
                pProcessIds.push_back(pe32.th32ProcessID);
                dwPid = pe32.th32ProcessID;
                break;
            }
        } while (Process32Next(hSnapshot, &pe32));
        CloseHandle(hSnapshot);
        VirtualizerEnd();
        return dwPid;
    };

    auto GetProcessBase = [](HANDLE hProcess)->MODULEINFO
    {
        VirtualizerStart();
        _MEMORY_BASIC_INFORMATION mbi;
        ULONG_PTR uCurrent = 0;
        MODULEINFO mod;
        BYTE PE[0x1000];
        ZeroMemory(&mbi, sizeof(mbi));
        ZeroMemory(&mod, sizeof(mod));
        do
        {
            ZeroMemory(&PE, 0x1000);
            if (uCurrent > 0 && ReadProcessMemory(hProcess, reinterpret_cast<PVOID>(uCurrent), &PE, 0x1000, 0) &&
                uCurrent != 0 && mbi.Type == MEM_IMAGE && mbi.Protect != PAGE_NOACCESS && mbi.Protect != 0 && PE[0] == 0x4D && PE[1] == 0x5A)
            {
                IMAGE_NT_HEADERS* ProcessHeader = reinterpret_cast<IMAGE_NT_HEADERS *>(reinterpret_cast<DWORD_PTR>(PE) + PIMAGE_DOS_HEADER(reinterpret_cast<DWORD_PTR>(PE))->e_lfanew);
                mod.EntryPoint = reinterpret_cast<PVOID>(ProcessHeader->OptionalHeader.AddressOfEntryPoint);
                mod.lpBaseOfDll = reinterpret_cast<PVOID>(uCurrent);
                mod.SizeOfImage = ProcessHeader->OptionalHeader.SizeOfImage;
                break;
            }
            uCurrent += mbi.RegionSize;
        } while (VirtualQueryEx(hProcess, reinterpret_cast<PVOID>(uCurrent), &mbi, sizeof(mbi)));
        VirtualizerEnd();
        return mod;
    };

    auto CheckThemida = [](HANDLE hProcess, MODULEINFO Info)->BOOL
    {
        VirtualizerStart();
        SIZE_T Size = 0;
        BYTE bByte = 0;
        BOOL fRet = false;
        if (ReadProcessMemory(hProcess, Info.lpBaseOfDll, &bByte, 1, &Size) && bByte == 0x4D)
        {
            fRet = true;
        }
        VirtualizerEnd();
        return fRet;
    };


    auto WaitForDll = [](DWORD dwPid, LPCSTR Dll)->BOOL
    {
        VirtualizerStart();
        HANDLE hModuleSnap = INVALID_HANDLE_VALUE;
        MODULEENTRY32 me32;
        BOOL fReturn = 0;

        hModuleSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, dwPid);
        if (hModuleSnap == INVALID_HANDLE_VALUE)
            fReturn = false;
        me32.dwSize = sizeof(MODULEENTRY32);
        if (!Module32First(hModuleSnap, &me32))
            fReturn = false;
        if (strstr(me32.szModule, Dll) ||
            !lstrcmpiA(me32.szModule, Dll))
        {
            CloseHandle(hModuleSnap);
            fReturn = true;
        }

        do
        {
            if (strstr(me32.szModule, Dll) ||
                !lstrcmpiA(me32.szModule, Dll))
            {
                CloseHandle(hModuleSnap);
                fReturn = true;
                break;
            }
        } while (Module32Next(hModuleSnap, &me32));
        CloseHandle(hModuleSnap);
        hModuleSnap = 0;
        VirtualizerEnd();
        return fReturn;
    };

    static auto xRtlCreateUserThread = [](HANDLE ProcessHandle, PSECURITY_DESCRIPTOR SecurityDescriptor, BOOLEAN CreateSuspended, ULONG StackZeroBits, PULONG StackReserved, PULONG StackCommit, PVOID StartAddress, PVOID StartParameter, PHANDLE ThreadHandle, PVOID Inject_GameID)->NTSTATUS
    {
        static FARPROC Function = 0;
        NTSTATUS Result = -1;
        if (!Function)
        {
            Function = GetProcAddress(GetModuleHandle("ntdll.dll"), "RtlCreateUserThread");
            if (!Function)
                return -1;
            *reinterpret_cast<DWORD_PTR*>(&Function) ^= 0x7777;
        }
        return reinterpret_cast<NTSTATUS(NTAPI*)(HANDLE, PSECURITY_DESCRIPTOR, BOOLEAN, ULONG, PULONG, PULONG, PVOID, PVOID, PHANDLE, PVOID)>(*reinterpret_cast<DWORD_PTR*>(&Function) ^ 0x7777)(ProcessHandle, SecurityDescriptor, CreateSuspended, StackZeroBits, StackReserved, StackCommit, StartAddress, StartParameter, ThreadHandle, Inject_GameID);
    };

    auto xCreateRemoteThread = [](HANDLE hProcess, LPSECURITY_ATTRIBUTES lpThreadAttributes, SIZE_T dwStackSize, LPTHREAD_START_ROUTINE lpStartAddress, LPVOID lpParameter, DWORD dwCreationFlags, LPDWORD lpThreadId)->HANDLE
    {
        ULONG Res = (dwStackSize == 0) ? 0x1000 : dwStackSize, Com = 0x1000;
        HANDLE ThreadHandle = 0;
        if (!xRtlCreateUserThread(hProcess, 0, (dwCreationFlags == CREATE_SUSPENDED) ? 1 : 0, 0, &Res, &Com, lpStartAddress, lpParameter, &ThreadHandle, 0))
            return ThreadHandle;
        return 0;
    };


    if (!IsElevated())
    {
        dwError = GetLastError();
        SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), FOREGROUND_INTENSITY | FOREGROUND_RED);
        std::cout << "[Inject_BE] [>>] [ERROR] : Administrative rights are needed for this bypass!" << std::endl;
        SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
        Status = false;
        goto END;
    }

    if (!GetFullPathNameA("BE_xBP.dll", MAX_PATH, Path, 0))
    {
        SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), FOREGROUND_INTENSITY | FOREGROUND_RED);
        std::cout << "[Inject_BE] [ERROR] : GetFullPathNameA failed with errorcode " << GetLastError() << std::endl;
        Status = false;
        goto END;
    }

    if (!dwCounts)
    {
        bReturn = OpenProcessToken(GetCurrentProcess(), TOKEN_ALL_ACCESS, &hToken);
        if (!bReturn)
        {
            SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), FOREGROUND_INTENSITY | FOREGROUND_RED);
            std::cout << "[Inject_BE] [ERROR] : OpenProcessToken failed with errorcode " << GetLastError() << std::endl;
            Status = false;
            goto END;
        }

        bReturn = LookupPrivilegeValueA(NULL, "SeDebugPrivilege", &Luid);
        if (!bReturn)
        {
            SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), FOREGROUND_INTENSITY | FOREGROUND_RED);
            std::cout << "[Inject_BE] [ERROR] : LookupPrivilegeValueA failed with errorcode " << GetLastError() << std::endl;
            Status = false;
            goto END;
        }

        NewState.PrivilegeCount = 1;
        NewState.Privileges[0].Luid = Luid;
        NewState.Privileges[0].Attributes = 2;
        bReturn = AdjustTokenPrivileges(hToken, FALSE, &NewState, 28, &PreviousState, &ReturnLength);

        if (!bReturn)
        {
            SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), FOREGROUND_INTENSITY | FOREGROUND_RED);
            std::cout << "[Inject_BE] [ERROR] : AdjustTokenPrivileges failed with errorcode " << GetLastError() << std::endl;
            Status = false;
            goto END;
        }
    }

    std::cout << "[Inject_BE] ================================================================" << std::endl;
    std::cout << "[Inject_BE] =================";
    SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), FOREGROUND_INTENSITY | FOREGROUND_RED | FOREGROUND_GREEN);
    std::cout << " [BattlEye Bypass] ";
    SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
    std::cout << "================" << std::endl;
    SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
    std::cout << "[Inject_BE] ================================================================" << std::endl;
    if (dwCounts == 1)
        std::cout << "[Inject_BE] [>>] Bypass has been injected in " << dwCounts << " process" << std::endl;
    if (dwCounts > 1)
        std::cout << "[Inject_BE] [>>] Bypass has been injected in " << dwCounts << " processes" << std::endl;
    std::cout << "[Inject_BE] [>>] Waiting for " << GAME_BE_EXE << std::endl;
    std::cout << "[Inject_BE] ================================================================" << std::endl;
    lastId = 0;
    while (!(lastId = GetProcessId(GAME_BE_EXE)))
        Sleep(50);
    gId = lastId;
    hProcess = INVALID_HANDLE_VALUE;
    hProcess = OpenProcess(PROCESS_ALL_ACCESS, false, lastId);
    if (hProcess == INVALID_HANDLE_VALUE || hProcess == 0)
        goto END;
    if (!CheckRemoteDebuggerPresent(hProcess, &isDebug) || isDebug)
    {
        dwError = GetLastError();
        SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), FOREGROUND_INTENSITY | FOREGROUND_RED);
        std::cout << "[Inject_BE] [>>] [ERROR] : CheckRemoteDebuggerPresent failed with errorcode (lpBaseOfDll) " << dwError << " or Debugger found " << isDebug << std::endl;
        SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
        Status = false;
        goto END;
    }
#if (IS_GAME_USE_THEMIDA == 1)
    Info = GetProcessBase(hProcess);
    if (!Info.lpBaseOfDll)
    {
        dwError = GetLastError();
        SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), FOREGROUND_INTENSITY | FOREGROUND_RED);
        std::cout << "[Inject_BE] [>>] [ERROR] : GetProcessBase failed with errorcode (lpBaseOfDll)" << 0 << std::endl;
        SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
        Status = false;
        goto END;
    }
    while (!CheckThemida(hProcess, Info))
    {
        if (!CheckIfExists(lastId))
            goto END;
    }
    while (!WaitForDll(lastId, "kernel32.dll"))
    {
        Sleep(10);
    }
#endif

    lpString = VirtualAllocEx(hProcess, 0, strlen(Path) + 1, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    if (!lpString)
    {
        SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), FOREGROUND_INTENSITY | FOREGROUND_RED);
        std::cout << "[Inject_BE] [ERROR] : VirtualAllocEx failed with errorcode " << GetLastError() << std::endl;
        CloseHandle(hProcess);
        goto END;
    }

    std::cout << "[Inject_BE] Hook: Path allocated at " << lpString << std::endl;

    if (!WriteProcessMemory(hProcess, lpString, Path, strlen(Path) + 1, 0))
    {
        SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), FOREGROUND_INTENSITY | FOREGROUND_RED);
        std::cout << "[Inject_BE] [ERROR] : WriteProcessMemory failed with errorcode " << GetLastError() << std::endl;
        VirtualFreeEx(hProcess, lpString, strlen(Path), MEM_DECOMMIT);
        CloseHandle(hProcess);
        goto END;
    }

    std::cout << "[Inject_BE] Hook: Path has been written " << Path << std::endl;

    hThread = CreateRemoteThread(hProcess, 0, 0, reinterpret_cast<LPTHREAD_START_ROUTINE>(lpLoadLibAddress), lpString, 0, &TID);
    if (!hThread)
    {
        SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), FOREGROUND_INTENSITY | FOREGROUND_RED);
        std::cout << "[Inject_BE] [ERROR] : CreateRemoteThread failed with errorcode " << GetLastError() << std::endl;
        VirtualFreeEx(hProcess, lpString, strlen(Path), MEM_DECOMMIT);
        CloseHandle(hProcess);
        goto END;
    }

    std::cout << "[Inject_BE] Hook: Thread has been created! (ID : " << TID << ", HANDLE : " << hThread << ")" << std::endl;

    WaitForSingleObject(hThread, INFINITE);

    if (VirtualFreeEx(hProcess, lpString, strlen(Path) + 1, MEM_DECOMMIT) &&
        CloseHandle(hProcess))
    {
        std::cout << "[Inject_BE] Hook: Path has been deallocated and the handle to the process has been closed." << std::endl;
        goto END;
    }

    dwCounts++;

END:
    if (hProcess)
        CloseHandle(hProcess);
    hProcess = INVALID_HANDLE_VALUE;

    std::cout << "[Inject_BE] Exit..." << std::endl;
#if _DEBUG
    getchar();
#else
    Sleep(2000);
#endif
    VirtualizerEnd();
    return Status;
}

//=======================================================================================================================================================

int main()
{
    VirtualizerStart();
    HANDLE hProcess = 0;
    pProcessIds.clear();
    dwCounts = 0;
    if (!SetConsoleTitleA("486373d32gh346634738s"))
    {
        SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), FOREGROUND_GREEN | FOREGROUND_RED | FOREGROUND_INTENSITY);
        std::cout << "[Inject_BE] [>>] [WARNING] : SetConsoleTitleA failed with errorcode " << GetLastError() << std::endl;
        SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
    }
    if (ControlDriver("BEService2.exe", FALSE))
        std::cout << "[Inject_BE] Stop service " << SERVICE2_NAME << " returned TRUE." << std::endl;
    else
        std::cout << "[Inject_BE] Stop service " << SERVICE2_NAME << " returned FALSE. (see DebugView for more information)" << std::endl;
    Sleep(220); // wait for delete service
    if (ControlDriver("BEService2.exe", TRUE))
        std::cout << "[Inject_BE] Start service " << SERVICE2_NAME << " returned TRUE." << std::endl;
    else
        std::cout << "[Inject_BE] Start service " << SERVICE2_NAME << " returned FALSE. (see DebugView for more information)" << std::endl;
    while (true)
    {
        Sleep(520);
        ClearScreen();
        if (InjectBypass() == false)
            break;
        Sleep(100);
        ExitProcess(9);
        for (auto it = pProcessIds.begin(); it != pProcessIds.end(); it++)
        {
            if (*it &&
                !CheckIfExists(*it))
            {
                pProcessIds.erase(it);
                break;
            }
        }
    }
    Sleep(3000);
    VirtualizerEnd();
    return true;
}

//=======================================================================================================================================================

void ClearScreen()
{
    std::cout << std::endl << std::endl;
    return;
    HANDLE                     hStdOut;
    CONSOLE_SCREEN_BUFFER_INFO csbi;
    DWORD                      count;
    DWORD                      cellCount;
    COORD                      homeCoords = { 0, 0 };

    hStdOut = GetStdHandle(STD_OUTPUT_HANDLE);
    if (hStdOut == INVALID_HANDLE_VALUE) return;

    if (!GetConsoleScreenBufferInfo(hStdOut, &csbi)) return;
    cellCount = csbi.dwSize.X *csbi.dwSize.Y;

    if (!FillConsoleOutputCharacter(hStdOut, ' ', cellCount, homeCoords, &count)) return;
    if (!FillConsoleOutputAttribute(hStdOut, csbi.wAttributes, cellCount, homeCoords, &count)) return;
    SetConsoleCursorPosition(hStdOut, homeCoords);
}

bool CheckIfExists(DWORD dwPid)
{
    HANDLE hProcess = OpenProcess(SYNCHRONIZE, FALSE, dwPid);
    DWORD dwReturn = WaitForSingleObject(hProcess, 0);
    if (hProcess)
        CloseHandle(hProcess);
    return dwReturn == WAIT_TIMEOUT;
};

bool IsElevated()
{
    BOOL fRet = FALSE;
    HANDLE hToken = NULL;
    TOKEN_ELEVATION Elevation;
    DWORD cbSize = sizeof(TOKEN_ELEVATION);
    ZeroMemory(&Elevation, sizeof(Elevation));
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken))
    {
        if (GetTokenInformation(hToken, TokenElevation, &Elevation, sizeof(Elevation), &cbSize))
            fRet = Elevation.TokenIsElevated;
    }
    if (hToken)
        CloseHandle(hToken);
    return fRet;
}

bool Is64Executable(HANDLE hProcess, PBOOL Is64)
{
    HANDLE hFile = INVALID_HANDLE_VALUE;
    LPVOID lpFile = 0;
    DWORD dwFileSize = 0, dwReaded = 0;
    PIMAGE_NT_HEADERS NtHeaders = 0;
    char Path[MAX_PATH];
    if (!GetModuleFileNameExA(hProcess, 0, Path, MAX_PATH))
        return false;
    hFile = CreateFileA(Path, GENERIC_READ, 0, 0, OPEN_EXISTING, 0, 0);
    if (!hFile || hFile == INVALID_HANDLE_VALUE)
        return false;
    dwFileSize = GetFileSize(hFile, 0);
    lpFile = VirtualAlloc(0, dwFileSize, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    if (!lpFile)
    {
        CloseHandle(hFile);
        return false;
    };
    if (!ReadFile(hFile, lpFile, dwFileSize, &dwReaded, 0))
    {
        CloseHandle(hFile);
        VirtualFree(lpFile, dwFileSize, MEM_DECOMMIT);
        return false;
    }
    NtHeaders = reinterpret_cast<PIMAGE_NT_HEADERS>((reinterpret_cast<DWORD_PTR>(lpFile) + PIMAGE_DOS_HEADER(lpFile)->e_lfanew));
    if (!NtHeaders ||
        NtHeaders->Signature != IMAGE_NT_SIGNATURE)
    {

        CloseHandle(hFile);
        VirtualFree(lpFile, dwFileSize, MEM_DECOMMIT);
        return false;
    }
    if (NtHeaders->FileHeader.Machine == IMAGE_FILE_MACHINE_AMD64 ||
        NtHeaders->FileHeader.Machine == IMAGE_FILE_MACHINE_IA64)
    {
        CloseHandle(hFile);
        VirtualFree(lpFile, dwFileSize, MEM_DECOMMIT);
        *Is64 = true;
        return true;
    }
    if (NtHeaders->FileHeader.Machine == IMAGE_FILE_MACHINE_I386)
    {
        CloseHandle(hFile);
        VirtualFree(lpFile, dwFileSize, MEM_DECOMMIT);
        *Is64 = false;
        return true;
    }
    CloseHandle(hFile);
    VirtualFree(lpFile, dwFileSize, MEM_DECOMMIT);
    return false;
}

BOOL WINAPI ControlDriver(LPCSTR lpFilename, BOOL Status)
{
    HANDLE g_DaisyHandle = NULL, Result = NULL;
    SC_HANDLE g_SCHandle = NULL;
    HKEY Key = 0;
    DWORD Value = 0;
    _SERVICE_STATUS ss;
    char Path[MAX_PATH];
    ZeroMemory(Path, MAX_PATH);
    ZeroMemory(&ss, sizeof(ss));

    g_SCHandle = OpenSCManagerA(0, 0, SC_MANAGER_ALL_ACCESS);
    if (!g_SCHandle)
        return FALSE;
    g_DaisyHandle = OpenServiceA(g_SCHandle, SERVICE2_NAME, SERVICE_ALL_ACCESS);
    if (Status == TRUE)
    {
        if (g_DaisyHandle && g_DaisyHandle != INVALID_HANDLE_VALUE)
        {
            ControlService(reinterpret_cast<SC_HANDLE>(g_DaisyHandle), SERVICE_CONTROL_STOP, &ss);
            WaitForSingleObject(g_DaisyHandle, INFINITE);
            if (!StartServiceA(reinterpret_cast<SC_HANDLE>(g_DaisyHandle), 0, 0))
            {
                MyOutputDebugString("[Inject_BE] Couldn't start the driver_1 %d", GetLastError());
                return FALSE;
            }
            CloseServiceHandle(reinterpret_cast<SC_HANDLE>(g_DaisyHandle));
            CloseServiceHandle(reinterpret_cast<SC_HANDLE>(g_SCHandle));
            return TRUE;
        }
        if (!GetFullPathNameA(lpFilename, MAX_PATH, Path, 0))
        {
            MyOutputDebugString("[Inject_BE] Couldn't find the driver_1 %d", GetLastError());
            return FALSE;
        }
        Result = CreateFileA(lpFilename, GENERIC_READ, 0, 0, OPEN_EXISTING, 0, 0);
        if (!Result || Result == INVALID_HANDLE_VALUE)
        {
            MyOutputDebugString("[Inject_BE] Couldn't find the driver_2 %d", GetLastError());
            return FALSE;
        }
        CloseHandle(Result);
        WaitForSingleObject(g_DaisyHandle, INFINITE);
        CloseServiceHandle(reinterpret_cast<SC_HANDLE>(g_DaisyHandle));
        g_DaisyHandle = 0;
        g_DaisyHandle = CreateServiceA(g_SCHandle, SERVICE2_NAME, SERVICE2_SHOW_NAME, 0x10034, SERVICE_WIN32_OWN_PROCESS, SERVICE_DEMAND_START, SERVICE_ERROR_NORMAL, Path, 0, 0, 0, 0, 0);
        if (!g_DaisyHandle || g_DaisyHandle == INVALID_HANDLE_VALUE)
        {
            MyOutputDebugString("[Inject_BE] Couldn't create the driver %d", GetLastError());
            CloseServiceHandle(reinterpret_cast<SC_HANDLE>(g_DaisyHandle));
            CloseServiceHandle(reinterpret_cast<SC_HANDLE>(g_SCHandle));
            return FALSE;
        }
        if (!StartServiceA(reinterpret_cast<SC_HANDLE>(g_DaisyHandle), 0, 0))
        {
            MyOutputDebugString("[Inject_BE] Couldn't start the driver_2 %d", GetLastError());
            CloseServiceHandle(reinterpret_cast<SC_HANDLE>(g_DaisyHandle));
            CloseServiceHandle(reinterpret_cast<SC_HANDLE>(g_SCHandle));
            return FALSE;
        }
        CloseServiceHandle(reinterpret_cast<SC_HANDLE>(g_DaisyHandle));
        CloseServiceHandle(reinterpret_cast<SC_HANDLE>(g_SCHandle));
        return TRUE;
    }
    if (!g_DaisyHandle || g_DaisyHandle == INVALID_HANDLE_VALUE)
    {
        DWORD errCode = GetLastError();
        CloseServiceHandle(reinterpret_cast<SC_HANDLE>(g_SCHandle));
        if (errCode == 1060) { // not install
            return TRUE;
        }
        MyOutputDebugString("[Inject_BE] Couldn't open the driver via openservice %d", GetLastError());
        return FALSE;
    }

    ControlService(reinterpret_cast<SC_HANDLE>(g_DaisyHandle), SERVICE_CONTROL_STOP, &ss);
    DeleteService(reinterpret_cast<SC_HANDLE>(g_DaisyHandle));
    CloseServiceHandle(reinterpret_cast<SC_HANDLE>(g_DaisyHandle));
    CloseServiceHandle(reinterpret_cast<SC_HANDLE>(g_SCHandle));
    return TRUE;
}
