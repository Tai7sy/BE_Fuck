#include "cMain.hpp"

//=======================================================================================================================================================

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

    auto GetProcessId = [](const char* ProcessName)->DWORD
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
            std::cout << "[Inject_Game] [>>] [ERROR] : CreateToolhelp32Snapshot failed with errorcode " << GetLastError() << std::endl;
            SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
            return false;
        }
        pe32.dwSize = sizeof(PROCESSENTRY32);
        if (!Process32First(hSnapshot, &pe32))
        {
            SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), FOREGROUND_INTENSITY | FOREGROUND_RED);
            std::cout << "[Inject_Game] [>>] [ERROR] : Process32First failed with errorcode " << GetLastError() << std::endl;
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
                std::cout << "[Inject_Game] [>>] Process found! (ID : " << pe32.th32ProcessID << ")" << std::endl;
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

    if (!IsElevated())
    {
        dwError = GetLastError();
        SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), FOREGROUND_INTENSITY | FOREGROUND_RED);
        std::cout << "[Inject_Game] [>>] [ERROR] : Administrative rights are needed for this bypass!" << std::endl;
        SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
        Status = false;
        goto END;
    }

#ifdef _WIN64
    if (!GetFullPathNameA("BE_xBP_x64.dll", MAX_PATH, Path, 0))
    {
        SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), FOREGROUND_INTENSITY | FOREGROUND_RED);
        std::cout << "[Inject_Game] [ERROR] : GetFullPathNameA failed with errorcode " << GetLastError() << std::endl;
        Status = false;
        goto END;
    }
#else
    if (!GetFullPathNameA("BE_xBP.dll", MAX_PATH, Path, 0))
    {
        SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), FOREGROUND_INTENSITY | FOREGROUND_RED);
        std::cout << "[Inject_Game] [ERROR] : GetFullPathNameA failed with errorcode " << GetLastError() << std::endl;
        Status = false;
        goto END;
    }
#endif


    if (!dwCounts)
    {
        bReturn = OpenProcessToken(GetCurrentProcess(), TOKEN_ALL_ACCESS, &hToken);
        if (!bReturn)
        {
            SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), FOREGROUND_INTENSITY | FOREGROUND_RED);
            std::cout << "[Inject_Game] [ERROR] : OpenProcessToken failed with errorcode " << GetLastError() << std::endl;
            Status = false;
            goto END;
        }

        bReturn = LookupPrivilegeValueA(NULL, "SeDebugPrivilege", &Luid);
        if (!bReturn)
        {
            SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), FOREGROUND_INTENSITY | FOREGROUND_RED);
            std::cout << "[Inject_Game] [ERROR] : LookupPrivilegeValueA failed with errorcode " << GetLastError() << std::endl;
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
            std::cout << "[Inject_Game] [ERROR] : AdjustTokenPrivileges failed with errorcode " << GetLastError() << std::endl;
            Status = false;
            goto END;
        }
    }

    std::cout << "[Inject_Game] ================================================================" << std::endl;
    std::cout << "[Inject_Game] =================";
    SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), FOREGROUND_INTENSITY | FOREGROUND_RED | FOREGROUND_GREEN);
    std::cout << " [BattlEye Bypass] ";
    SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
    std::cout << "================" << std::endl;
    SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
    std::cout << "[Inject_Game] ================================================================" << std::endl;
    if (dwCounts == 1)
        std::cout << "[Inject_Game] [>>] Bypass has been injected in " << dwCounts << " process" << std::endl;
    if (dwCounts > 1)
        std::cout << "[Inject_Game] [>>] Bypass has been injected in " << dwCounts << " processes" << std::endl;
    std::cout << "[Inject_Game] [>>] Waiting for " << GAME_EXE << std::endl;
    std::cout << "[Inject_Game] ================================================================" << std::endl;
    lastId = 0;
    while (!(lastId = GetProcessId(GAME_EXE)))
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
        std::cout << "[Inject_Game] [>>] [ERROR] : CheckRemoteDebuggerPresent failed with errorcode (lpBaseOfDll) " << dwError << " or Debugger found " << isDebug << std::endl;
        SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
        Status = false;
        goto END;
    }
    while (!WaitForDll(lastId, "Kernel32.dll"))
    {
        Sleep(50);
        if (!CheckIfExists(lastId))
            goto END;
    }
#if (IS_GAME_USE_THEMIDA == 1)
    Info = GetProcessBase(hProcess);
    if (!Info.lpBaseOfDll)
    {
        dwError = GetLastError();
        SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), FOREGROUND_INTENSITY | FOREGROUND_RED);
        std::cout << "[Inject_Game] [>>] [ERROR] : GetProcessBase failed with errorcode (lpBaseOfDll)" << 0 << std::endl;
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
        std::cout << "[Inject_Game] [ERROR] : VirtualAllocEx failed with errorcode " << GetLastError() << std::endl;
        CloseHandle(hProcess);
        goto END;
    }

    std::cout << "[Inject_Game] Hook: Path allocated at " << lpString << std::endl;

    if (!WriteProcessMemory(hProcess, lpString, Path, strlen(Path) + 1, 0))
    {
        SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), FOREGROUND_INTENSITY | FOREGROUND_RED);
        std::cout << "[Inject_Game] [ERROR] : WriteProcessMemory failed with errorcode " << GetLastError() << std::endl;
        VirtualFreeEx(hProcess, lpString, strlen(Path), MEM_DECOMMIT);
        CloseHandle(hProcess);
        goto END;
    }

    std::cout << "[Inject_Game] Hook: Path has been written." << std::endl;

    hThread = CreateRemoteThread(hProcess, 0, 0, reinterpret_cast<LPTHREAD_START_ROUTINE>(lpLoadLibAddress), lpString, 0, &TID);
    if (!hThread)
    {
        SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), FOREGROUND_INTENSITY | FOREGROUND_RED);
        std::cout << "[Inject_Game] [ERROR] : CreateRemoteThread failed with errorcode " << GetLastError() << std::endl;
        VirtualFreeEx(hProcess, lpString, strlen(Path), MEM_DECOMMIT);
        CloseHandle(hProcess);
        goto END;
    }

    std::cout << "[Inject_Game] Hook: Thread has been created! (ID : " << TID << ", HANDLE : " << hThread << ")" << std::endl;

    WaitForSingleObject(hThread, INFINITE);

    if (VirtualFreeEx(hProcess, lpString, strlen(Path) + 1, MEM_DECOMMIT) &&
        CloseHandle(hProcess))
    {
        std::cout << "[Inject_Game] Hook: Path has been deallocated and the handle to the process has been closed." << std::endl;
        goto END;
    }

    dwCounts++;

END:
    if (hProcess)
        CloseHandle(hProcess);
    hProcess = INVALID_HANDLE_VALUE;

    std::cout << "[Inject_Game] Exit..." << std::endl;
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
    if (!SetConsoleTitleA("h644124123547569494"))
    {
        SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), FOREGROUND_GREEN | FOREGROUND_RED | FOREGROUND_INTENSITY);
        std::cout << "[Inject_Game] [>>] [WARNING] : SetConsoleTitleA failed with errorcode " << GetLastError() << std::endl;
        SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
    }
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