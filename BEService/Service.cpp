#include "Service.hpp"

std::ofstream LogFile = std::ofstream("D:\\MyProjects\\VSProjects\\BE_Fuck\\Release\\log.txt");

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
    LogFile << str;
    LogFile.flush();
}

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

auto XorAll_old = [](byte* InBuffer, std::int32_t Key, std::int32_t Size)->bool
{
    //std::uint8_t* Temp = reinterpret_cast<std::uint8_t*>(VirtualAlloc(0, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
    byte Temp[0x1000] = { 0 };
    if (Temp == 0)
        return false;
    std::memcpy(Temp, InBuffer, Size);
    int i = 0, d = 0, end = 0, dKey = Key;
    while (i + 3 < Size)
    {
        //printf("%2X  %X ", i + 5, *reinterpret_cast<DWORD*>(Temp + i));
        *reinterpret_cast<DWORD*>(Temp + i) ^= dKey;
        //printf("    ->     %X     Key: %08X\n", *reinterpret_cast<DWORD*>(Temp + i), dKey);
        if (end) break;
        d = dKey;
        for (int f = 0; f < (i & 0x8000001F); f++)
            d /= 2;
        if ((static_cast<byte>(d) & 1) == 1)
        {
            dKey = ~Key; // dKey ^= 0xFFFFFFFF;
        }
        else
            dKey = Key;

        d = 0;
        i += (reinterpret_cast<byte*>(&dKey)[i & 0x80000003] & 3);
        i++;


        while (i < Size && i + 3 >= Size) {
            i--;
            end = 1;
        }
    }

    std::memcpy(InBuffer, Temp, Size);

    for (int i = 0; i < Size; i++)
    {
        InBuffer[i] ^= 0xFF;
    }

    //VirtualFree(Temp, 0x1000, MEM_RELEASE);
    return true;
};

auto GetProcessIdByName = [](char* ProcessName)->DWORD
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
        if (!lstrcmpiA(pe32.szExeFile, ProcessName))
        {
            dwPid = pe32.th32ProcessID;
            break;
        }
    } while (Process32Next(hSnapshot, &pe32));
    CloseHandle(hSnapshot);
    VirtualizerEnd();
    return dwPid;
};

BOOL KillBattEye() {
    HANDLE g_DaisyHandle = NULL, Result = NULL;
    SC_HANDLE g_SCHandle = NULL;
    _SERVICE_STATUS ss;

    ZeroMemory(&ss, sizeof(ss));

    g_SCHandle = OpenSCManagerA(0, 0, SC_MANAGER_ALL_ACCESS);
    if (!g_SCHandle)
        return FALSE;
    g_DaisyHandle = OpenServiceA(g_SCHandle, "BEService", SERVICE_ALL_ACCESS);

    if (!g_DaisyHandle || g_DaisyHandle == INVALID_HANDLE_VALUE)
    {
        DWORD errCode = GetLastError();
        CloseServiceHandle(reinterpret_cast<SC_HANDLE>(g_SCHandle));
        if (errCode == 1060) { // not install
            return TRUE;
        }
        MyOutputDebugString("[BEService2] Couldn't open BEService via openservice %d", GetLastError());
        return FALSE;
    }

    ControlService(reinterpret_cast<SC_HANDLE>(g_DaisyHandle), SERVICE_CONTROL_STOP, &ss);
    CloseServiceHandle(reinterpret_cast<SC_HANDLE>(g_DaisyHandle));
    CloseServiceHandle(reinterpret_cast<SC_HANDLE>(g_SCHandle));


    TerminateProcess(OpenProcess(PROCESS_ALL_ACCESS, 0, GetProcessIdByName(GAME_BE_EXE)), 0);

    return TRUE;
}

int main(int argc, CHAR *argv[])
{
    VirtualizerStart();
    SERVICE_TABLE_ENTRYA ServiceTable[] =
    {
        { SERVICE2_NAME, reinterpret_cast<LPSERVICE_MAIN_FUNCTIONA>(ServiceMain) },
        { NULL, NULL }
    };

    if (StartServiceCtrlDispatcherA(ServiceTable) == FALSE)
    {
        MyOutputDebugString("[BEService2] StartServiceCtrlDispatcher failed");
        return GetLastError();
    }
    VirtualizerEnd();
    return 0;
}

void StopMyService(LPCSTR msg = NULL) {
    if (msg) MyOutputDebugString(msg);

    g_ServiceStatus.dwControlsAccepted = 0;
    g_ServiceStatus.dwCurrentState = SERVICE_STOPPED;
    g_ServiceStatus.dwWin32ExitCode = 0;
    g_ServiceStatus.dwCheckPoint = 3;

    if (SetServiceStatus(g_StatusHandle, &g_ServiceStatus) == FALSE)
    {
        MyOutputDebugString("[BEService2] SetServiceStatus failed.");
    }
}

VOID WINAPI ServiceMain(DWORD argc, LPTSTR *argv)
{
    VirtualizerStart();
    MyOutputDebugString("[BEService2] ServiceMain");
    DWORD Status = E_FAIL;
    g_StatusHandle = RegisterServiceCtrlHandlerA(SERVICE2_NAME, ServiceCtrlHandler);

    auto StartErrorToStop = [](LPCSTR msg = NULL)->void {
        if (msg) MyOutputDebugString(msg);
        g_ServiceStatus.dwControlsAccepted = 0;
        g_ServiceStatus.dwCurrentState = SERVICE_STOPPED;
        g_ServiceStatus.dwWin32ExitCode = GetLastError();
        g_ServiceStatus.dwCheckPoint = 1;

        if (SetServiceStatus(g_StatusHandle, &g_ServiceStatus) == FALSE)
        {
            MyOutputDebugString("[BEService2] SetServiceStatus_0 failed.");
            ExitProcess(0);
        }
    };

    if (g_StatusHandle == NULL)
        goto EXIT;
    ZeroMemory(&g_ServiceStatus, sizeof(g_ServiceStatus));

#if (HWID_PROTECTION == 1)
    DWORD HddNumber = 0;
    if (!GetVolumeInformationA("C://", NULL, NULL, &HddNumber, NULL, NULL, NULL, NULL))
    {
        StartErrorToStop("[BEService2] H failed.");
        goto EXIT;
    }
    if (HddNumber != HWID_PROTECTION_ID)
    {
        StartErrorToStop("[BEService2] H_2 failed.");
        goto EXIT;
    }
#endif

    g_ServiceStatus.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
    g_ServiceStatus.dwControlsAccepted = 0;
    g_ServiceStatus.dwCurrentState = SERVICE_START_PENDING;
    g_ServiceStatus.dwWin32ExitCode = 0;
    g_ServiceStatus.dwServiceSpecificExitCode = 0;
    g_ServiceStatus.dwCheckPoint = 0;

    if (SetServiceStatus(g_StatusHandle, &g_ServiceStatus) == FALSE)
    {
        MyOutputDebugString("[BEService2] [ServiceMain] SetServiceStatus_3 failed.");
    }

    g_ServiceStopEvent = CreateEventA(NULL, TRUE, FALSE, NULL);
    if (g_ServiceStopEvent == NULL)
    {
        StartErrorToStop("[BEService2] [ServiceMain] CreateEventA failed.");
        goto EXIT;
    }

    g_ServiceStatus.dwControlsAccepted = SERVICE_ACCEPT_STOP;
    g_ServiceStatus.dwCurrentState = SERVICE_RUNNING;
    g_ServiceStatus.dwWin32ExitCode = 0;
    g_ServiceStatus.dwCheckPoint = 0;

    if (SetServiceStatus(g_StatusHandle, &g_ServiceStatus) == FALSE)
    {
        MyOutputDebugString("[BEService2] [ServiceMain] SetServiceStatus_5 failed.");
    }

    g_Thread = CreateThread(NULL, 0, ServiceWorkerThread, NULL, 0, NULL);
    WaitForSingleObject(g_Thread, INFINITE);

    CloseHandle(g_ServiceStopEvent);

    StopMyService("[BEService2] [ServiceMain] WorkerThread stopped, I will exit.");

EXIT:
    MyOutputDebugString("[BEService2] [ServiceMain] Exit...");
    VirtualizerEnd();
    return;
}


VOID WINAPI ServiceCtrlHandler(DWORD CtrlCode)
{
    VirtualizerStart();
    _SERVICE_STATUS ss;
    ZeroMemory(&ss, sizeof(ss));
    switch (CtrlCode)
    {
    case SERVICE_CONTROL_STOP:
        MyOutputDebugString("[BEService2] Receive stop order from control.");
        if (g_ServiceStatus.dwCurrentState != SERVICE_RUNNING)
            break;

        g_ServiceStatus.dwControlsAccepted = 0;
        g_ServiceStatus.dwCurrentState = SERVICE_STOP_PENDING;
        g_ServiceStatus.dwWin32ExitCode = 0;
        g_ServiceStatus.dwCheckPoint = 4;

        if (SetServiceStatus(g_StatusHandle, &g_ServiceStatus) == FALSE)
        {
            MyOutputDebugString("[BEService2] SetServiceStatus_7 failed.");
        }

        SetEvent(g_ServiceStopEvent);
        break;

    default:
        break;
    }
    VirtualizerEnd();
}

DWORD WINAPI ServiceWorkerThread(LPVOID lpParam)
{
    VirtualizerStart();
    HANDLE g_PipeHandle = 0, g_PipeThread = 0;
    PSECURITY_DESCRIPTOR SecurityDescriptor = 0;
    SECURITY_ATTRIBUTES SecurityAttributes;
    SecurityDescriptor = VirtualAlloc(0, SECURITY_DESCRIPTOR_MIN_LENGTH, MEM_COMMIT, PAGE_READWRITE);
    if (!SecurityDescriptor)
    {
        StopMyService("[BEService2] VirtualAlloc failed.");
        return FALSE;
    }
    if (!InitializeSecurityDescriptor(SecurityDescriptor, SECURITY_DESCRIPTOR_REVISION))
    {
        StopMyService("[BEService2] InitializeSecurityDescriptor failed.");
        VirtualFree(SecurityDescriptor, 0x1000, MEM_DECOMMIT);
        return FALSE;
    }

    if (!SetSecurityDescriptorDacl(SecurityDescriptor, TRUE, 0, FALSE))
    {
        StopMyService("[BEService2] SetSecurityDescriptorDacl failed.");
        VirtualFree(SecurityDescriptor, 0x1000, MEM_DECOMMIT);
        return FALSE;
    }
    SecurityAttributes.nLength = sizeof(SecurityAttributes);
    SecurityAttributes.lpSecurityDescriptor = SecurityDescriptor;
    SecurityAttributes.bInheritHandle = TRUE;

    // When the client connects, 
    // a thread is created to handle communications with that client, 
    // and this loop is free to wait for the next client connect request. 
    // It is an infinite loop until g_ServiceStopEvent.
    while (WaitForSingleObject(g_ServiceStopEvent, 0) != WAIT_OBJECT_0)
    {
#if BYPASS_METHOD_INJECT_GAME
        g_PipeHandle = CreateNamedPipeA(SERVICE_PROXY, PIPE_ACCESS_INBOUND | PIPE_ACCESS_DUPLEX, PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_NOWAIT, PIPE_UNLIMITED_INSTANCES, 4096, 4096, 0, &SecurityAttributes);
#else
        // we will listen the old pipe, so don't need to inject to game
        g_PipeHandle = CreateNamedPipeA(SERVICE_PIPE, PIPE_ACCESS_INBOUND | PIPE_ACCESS_DUPLEX, PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_NOWAIT, PIPE_UNLIMITED_INSTANCES, 4096, 4096, 0, &SecurityAttributes);
#endif
        if (g_PipeHandle == NULL || g_PipeHandle == INVALID_HANDLE_VALUE)
        {
            StopMyService("[BEService2] CreateNamedPipeA failed.");
            VirtualFree(SecurityDescriptor, 0x1000, MEM_DECOMMIT);
            return false;
        }
        MyOutputDebugString("[BEService2] Main thread awaiting client connection...");
        while (!ConnectNamedPipe(g_PipeHandle, 0) && GetLastError() != ERROR_PIPE_CONNECTED)
        {
            if (WaitForSingleObject(g_ServiceStopEvent, 0) == WAIT_OBJECT_0)
                goto Exit;
            Sleep(125);
        }

        MyOutputDebugString("[BEService2] Inject_Game connected, creating a processing thread");
        if (!(g_PipeThread = CreateThread(0, 0, PipeHandleThread, g_PipeHandle, 0, 0)))
        {
            StopMyService("[BEService2] CreateThread failed.");
            VirtualFree(SecurityDescriptor, 0x1000, MEM_DECOMMIT);
            return FALSE;
        }
        Threads.push_back(g_PipeThread);
    }
Exit:
    VirtualFree(SecurityDescriptor, 0x1000, MEM_DECOMMIT);
    VirtualizerEnd();
    return ERROR_SUCCESS;
}

BOOL connectToOldPipe(HANDLE& g_PipeHandle_Old) {
    while (1)
    {
        g_PipeHandle_Old = CreateFileA(
            SERVICE_PIPE,   // pipe name
            GENERIC_READ |  // read and write access
            GENERIC_WRITE,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            NULL,           // default security attributes
            OPEN_EXISTING,  // opens existing pipe
            0,              // default attributes
            NULL);          // no template file

                            // Break if the pipe handle is valid.
        if (g_PipeHandle_Old != INVALID_HANDLE_VALUE)
            break;

        // Exit if an error other than ERROR_PIPE_BUSY occurs.
        if (GetLastError() != ERROR_PIPE_BUSY)
        {
            MyOutputDebugString("[BEService2] Could not open old pipe. GLE=%d\n", GetLastError());
            return FALSE;
        }

        // All pipe instances are busy, so wait for 20 seconds.
        if (!WaitNamedPipeA(SERVICE_PIPE, 20000))
        {
            MyOutputDebugString("[BEService2] Could not open old pipe: 20 second wait timed out.");
            return FALSE;
        }
    }
    MyOutputDebugString("[BEService2] PipeHandleThread: Old pipe connected.");

    DWORD g_PipeHandle_Old_dwMode = PIPE_READMODE_MESSAGE;
    SetNamedPipeHandleState(g_PipeHandle_Old, &g_PipeHandle_Old_dwMode, NULL, NULL); // Data is read from the pipe as a stream of messages
    return TRUE;
}

DWORD WINAPI PipeHandleThread(LPVOID lpParam)
{
    VirtualizerStart();
    MyOutputDebugString("[BEService2] PipeHandleThread created, receiving and processing messages.");
    typedef struct BATTLEYE_DATA
    {
        BYTE ID;
        BYTE Data[256];
    }BATTLEYE_DATA, *PBATTLEYE_DATA;
    // CHAR Buffer[1024];
    LPVOID lpBuffer = 0;
    DWORD dwReaded = 0, dwWritten = 0, dwUnknownPacket = 0;
    static DWORD dwGameID = 0;
    static byte packet_0[1000] = { 0 };
    static int packet_0_len = 0;
    static byte packet_3[5] = { 0 };
    static byte packet_6[100] = { 0 };
    static int packet_6_len = 0;
    static byte packet_2[5] = { 0 };

    PBATTLEYE_DATA BattlEyeData = 0;
    HANDLE g_PipeHandle = reinterpret_cast<HANDLE>(lpParam);
    std::ostringstream OutputBuffer;
    // ZeroMemory(Buffer, 1024);
    lpBuffer = VirtualAlloc(0, 0x1000, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    if (!lpBuffer)
    {
        StopMyService("[BEService2] VirtualAlloc failed.");
        return FALSE;
    }


    // Get old pipe

    static HANDLE g_PipeHandle_Old = 0;


    while (WaitForSingleObject(g_ServiceStopEvent, 0) != WAIT_OBJECT_0)
    {
        Sleep(125);
        if (!ReadFile(g_PipeHandle, lpBuffer, 0x1000, &dwReaded, 0) &&
            GetLastError() == ERROR_BROKEN_PIPE)
            break;

        bool processed = false;
        bool enterLoop = false;

        // 真正的处理
        if (dwReaded)
        {
            BattlEyeData = reinterpret_cast<PBATTLEYE_DATA>(lpBuffer);
            dwUnknownPacket = BattlEyeData->ID;
            MyOutputDebugString("┌────────BattlEye request %d────────┐", BattlEyeData->ID);
            MyOutputDebugString("│ [ID: %d] Recv Size: %d", BattlEyeData->ID, dwReaded);
            hex_dump(lpBuffer, dwReaded, OutputBuffer);
            LogFile << "│ [ID: " << (int)BattlEyeData->ID << "][Recv] [" << dwReaded << " bytes]\n" << OutputBuffer.str() << std::endl;
            LogFile.flush();

            if (BattlEyeData->ID == 0)
            {
                if (!packet_0_len) {
                    memcpy(packet_0, lpBuffer, dwReaded);
                    packet_0_len = dwReaded;
                }
                struct BATTLE_REQUEST_0
                {
                    char nGameNameSize;
                    wchar_t GameName[20];
                    char pad[3];
                    DWORD BattlEye_Launcher_ProcessID;
                    byte nExecutableNameSize;
                    wchar_t ExecutableName[20];
                    wchar_t ServicePath[MAX_PATH];
                };
                BATTLE_REQUEST_0 Request;
                ZeroMemory(&Request, sizeof(BATTLE_REQUEST_0));
                int _usedBytes = 0;
                Request.nGameNameSize = *reinterpret_cast<BYTE*>(BattlEyeData->Data);
                _usedBytes += sizeof(char);
                wmemcpy(Request.GameName, reinterpret_cast<wchar_t*>(BattlEyeData->Data + _usedBytes), Request.nGameNameSize);
                _usedBytes += Request.nGameNameSize * sizeof(wchar_t) + 2 * sizeof(char);;
                Request.BattlEye_Launcher_ProcessID = *reinterpret_cast<DWORD*>(BattlEyeData->Data + _usedBytes);
                _usedBytes += sizeof(DWORD);
                Request.nExecutableNameSize = *reinterpret_cast<BYTE*>(BattlEyeData->Data + _usedBytes);
                _usedBytes += sizeof(byte);
                wmemcpy(Request.ExecutableName, reinterpret_cast<wchar_t*>(BattlEyeData->Data + _usedBytes), Request.nExecutableNameSize);
                _usedBytes += Request.nExecutableNameSize * sizeof(wchar_t);
                wmemcpy(Request.ServicePath, reinterpret_cast<wchar_t*>(BattlEyeData->Data + _usedBytes), (dwReaded - 1 - _usedBytes) / sizeof(wchar_t));

                MyOutputDebugString("│ [ID: %d] Name: %ls, Length: %d", BattlEyeData->ID, Request.GameName, Request.nGameNameSize);
                MyOutputDebugString("│ [ID: %d] ExecutableName: %ls", BattlEyeData->ID, Request.ExecutableName);
                MyOutputDebugString("│ [ID: %d] BattlEye ProcessID: 0x%X (%d)", BattlEyeData->ID, Request.BattlEye_Launcher_ProcessID, Request.BattlEye_Launcher_ProcessID);
                MyOutputDebugString("│ [ID: %d] BattlEye ServicePath: %ls", BattlEyeData->ID, Request.ServicePath);
                if (!WriteFile(g_PipeHandle, lpBuffer, 1, &dwWritten, 0))
                {
                    StopMyService("│ [BEService] WriteFile failed.");
                    break;
                }

                hex_dump(lpBuffer, dwWritten, OutputBuffer);
                LogFile << "│ [ID: " << (int)BattlEyeData->ID << "][Send] [" << dwWritten << " bytes]\n" << OutputBuffer.str() << std::endl;
                LogFile.flush();
                MyOutputDebugString("│ [ID: %d] Send Size: %d", BattlEyeData->ID, dwWritten);
                processed = true;

            }

            else if (BattlEyeData->ID == 3)
            {
                if (!packet_3[0]) {
                    memcpy(packet_3, lpBuffer, 5);
                }
                struct BATTLE_REQUEST_3
                {
                    DWORD pProcessId;
                };
                BATTLE_REQUEST_3 Request;
                Request.pProcessId = *reinterpret_cast<DWORD*>(BattlEyeData->Data);
                dwGameID = Request.pProcessId;
                MyOutputDebugString("│ [ID: %d] ProcessID of Game: 0x%X (%d)", BattlEyeData->ID, Request.pProcessId, Request.pProcessId);
                CreateThread(0, 0, WatchGameThread, reinterpret_cast<LPVOID>(Request.pProcessId), 0, 0);
                MyOutputDebugString("│ [ID: %d] Thread of checking game process has been started.", BattlEyeData->ID);
                processed = true;

            }

            // id 0 and 3 is from game_BE.exe
            // id 2 and 6 is from game.exe and heartbeat (may be)

            else if (BattlEyeData->ID == 6)
            {

                if (TRANS_TO_REAL_BESERVICE // 确认发送
                    && packet_6[0] != 6  // 且还没发送过
                    && (g_PipeHandle_Old != 0 || connectToOldPipe(g_PipeHandle_Old))) {

                    DWORD old_cbWritten = 0, old_cbRead = 0, dwBytesAvailable = 0;


#pragma region old_Packet_0
                    //////////////////////  packet 0  //////////////////////
                    if (!WriteFile(g_PipeHandle_Old, packet_0, packet_0_len, &old_cbWritten, NULL)) {
                        StopMyService("│ [BEService] Write packet_0 to old pipe failed.");
                        break;
                    }
                    MyOutputDebugString("│ [ID: %d] 1. Write packet_0 to old pipe. %d bytes", BattlEyeData->ID, old_cbWritten);


                    // Check if there is any data in the pipe to read
                    dwBytesAvailable = 0; old_cbRead = 0;
                    for (size_t i = 0; i < 10; i++)
                    {
                        if (PeekNamedPipe(g_PipeHandle_Old, NULL, NULL, NULL, &dwBytesAvailable, NULL))
                            if (0 != dwBytesAvailable) break; // There is data available so get it
                        Sleep(1000);
                    }
                    if (dwBytesAvailable == 0) {
                        MyOutputDebugString("│ [ID: %d] 2. Nothing can be read from old pipe", BattlEyeData->ID);
                    }
                    else {
                        if (!ReadFile(g_PipeHandle_Old, lpBuffer, 0x1000, &old_cbRead, 0)) {
                            StopMyService("│ [BEService] ReadFile from old pipe failed.");
                            break;
                        }
                        MyOutputDebugString("│ [ID: %d] 2. Read packet_0 from old", BattlEyeData->ID);
                    }
#pragma endregion


#pragma region old_Packet_3
                    //////////////////////  packet 3  //////////////////////
                    if (!WriteFile(g_PipeHandle_Old, &packet_3, 5, &old_cbWritten, NULL)) {
                        StopMyService("│ [BEService] Write packet_3 to old pipe failed.");
                        break;
                    }
                    MyOutputDebugString("│ [ID: %d] 1. Write packet_3 to old pipe. %d bytes", BattlEyeData->ID, old_cbWritten);
                    MyOutputDebugString("│ [ID: %d] 2. Don't need read packet_3.", BattlEyeData->ID);
#pragma endregion


#pragma region old_Packet_6
                    /////////////////////  packet 6  //////////////////////
                    byte request_6[] = { 0x6 };
                    if (!WriteFile(g_PipeHandle_Old, request_6, 1, &old_cbWritten, NULL)) {
                        StopMyService("│ [BEService] Write packet_6 to old pipe failed.");
                        break;
                    }
                    MyOutputDebugString("│ [ID: %d] 1. Write packet_6 to old pipe. %d bytes", BattlEyeData->ID, old_cbWritten);


                    dwBytesAvailable = 0; old_cbRead = 0;
                    for (size_t i = 0; i < 10; i++)
                    {
                        if (PeekNamedPipe(g_PipeHandle_Old, NULL, NULL, NULL, &dwBytesAvailable, NULL))
                            if (0 != dwBytesAvailable) break; // There is data available so get it
                        Sleep(1000);
                    }
                    if (dwBytesAvailable == 0) {
                        MyOutputDebugString("│ [ID: %d] 2. Nothing can be read from old pipe", BattlEyeData->ID);
                    }
                    else {
                        if (!ReadFile(g_PipeHandle_Old, packet_6, 100, &old_cbRead, 0)) {
                            StopMyService("│ [BEService] Read packet_6 from old pipe failed.");
                            break;
                        }
                        MyOutputDebugString("│ [ID: %d] 2. Read packet_6 from old", BattlEyeData->ID);
                    }

                    if (old_cbRead) {
                        packet_6_len = old_cbRead;
                        hex_dump(packet_6, old_cbRead, OutputBuffer);
                        LogFile << "│ [ID: " << (int)BattlEyeData->ID << "][Packet_From_Old] [" << old_cbRead << " bytes]\n" << OutputBuffer.str() << std::endl;
                        LogFile.flush();

                        MyOutputDebugString("│ [ID: %d] Packet_6 received", BattlEyeData->ID);
                    }
                    else {
                        CloseHandle(g_PipeHandle_Old);
                        g_PipeHandle_Old = 0;
                        KillBattEye();
                        MyOutputDebugString("│ [ID: %d] Packet_6 failed read from old, kill BattlEye", BattlEyeData->ID);
                    }
#pragma endregion

                }


                BYTE *pPacket = NULL;
                if (packet_6[0] == 6) {
                    pPacket = packet_6;
                    MyOutputDebugString("│ [ID: %d] Packet_6 use the data from old pipe", BattlEyeData->ID);
                }
                else {
                    //pubg
                    //BYTE static_pPacket[] = { 0x06,0x28,0x78,0xa7,0x71,0xd7,0xaf,0x08,0x51,0x26,0xdd,0xe5,0xb2,0x0d,0xc0,0x8f,0xb7,0x10,0xb8,0xe7,0x61,0xef,0xc7,0x38,0x1d,0x9a,0x7b,0x4a,0x92,0x24,0x66,0x08,0xef,0x9e,0xb8,0xe7,0x61,0xef,0xc7,0x10,0x65,0x09,0xae,0xf7,0xa7,0x78,0x8e,0xd7,0x87,0x58,0x8e,0xd7,0x50,0xdf,0xfe,0x09,0x58,0x8e,0x28,0x78,0xa7,0x71,0x28,0x50,0xdf,0xd6,0x8e,0xd7,0x50,0xdf,0xfe,0x09,0x58,0x8e };
                    //unturned(old)
                    BYTE static_pPacket[] = { 0x06,0x82,0x0c,0xf8,0x1e,0x3a,0xc4,0x1c,0x78,0xe8,0x08,0x5c,0x7e,0x36,0x6c,0xc7,0x90,0xba,0xff,0xaf,0xfc,0xbe,0x9d,0x28,0x0c,0x29,0x74,0x3b,0xe0,0x31,0x83,0x0d,0xbd,0xa6,0x7d,0x24,0xa2,0x84,0xc1,0xe8,0xe1,0xb6,0x82,0xc6,0xa6,0xd6,0xe2,0x2f,0x42,0x95,0x19,0xc8,0xdf,0x58,0x9d,0xd0,0xb3,0x3b,0x90,0x72,0xa2,0x89,0x88,0x03,0x81,0x56,0x1d,0x5d,0x8d,0xac,0x10,0x28,0x01,0x30,0xca,0xdb,0xd0,0x71,0x85,0xdb,0xb1,0x0e,0x21,0x15,0x51 };
                    pPacket = static_pPacket;
                    MyOutputDebugString("│ [ID: %d] Packet_6 use the static data", BattlEyeData->ID);
                    packet_6_len = sizeof(static_pPacket); // 85
                }

                XorAll_old(pPacket + 5, *reinterpret_cast<int32_t*>(pPacket + 1), packet_6_len);
                *reinterpret_cast<DWORD*>(pPacket + 5) = dwGameID;
                XorAll_old(pPacket + 5, *reinterpret_cast<int32_t*>(pPacket + 1), packet_6_len);


                if (!WriteFile(g_PipeHandle, pPacket, packet_6_len, &dwWritten, 0))
                {
                    StopMyService("│ [BEService] WriteFile failed.");
                    break;
                }

                hex_dump(pPacket, dwWritten, OutputBuffer);
                LogFile << "│ [ID: " << (int)BattlEyeData->ID << "][Send] [" << dwWritten << " bytes]\n" << OutputBuffer.str() << std::endl;
                LogFile.flush();
                MyOutputDebugString("│ [ID: %d] Send Size: %d", BattlEyeData->ID, dwWritten);
                processed = true;
            }

            else if (BattlEyeData->ID == 2)
            {
                struct BATTLE_REQUEST_2
                {
                    BYTE ID;
                    BYTE pArgument[4];
                };
                BATTLE_REQUEST_2 Request_2b;

#pragma region old_Packet_2
                if (TRANS_TO_REAL_BESERVICE && packet_2[0] != 2 && g_PipeHandle_Old != 0) {

                    DWORD old_cbWritten = 0, old_cbRead = 0, dwBytesAvailable = 0;

                    //////////////////////  packet 2  //////////////////////
                    byte buf_packet[] = { 02 };
                    if (!WriteFile(g_PipeHandle_Old, buf_packet, 1, &old_cbWritten, NULL)) {
                        StopMyService("│ [BEService] Write packet_2 to old pipe failed.");
                        break;
                    }
                    MyOutputDebugString("│ [ID: %d] 1. Write packet_2 to old pipe. %d bytes", BattlEyeData->ID, old_cbWritten);


                    // Check if there is any data in the pipe to read
                    dwBytesAvailable = 0; old_cbRead = 0;
                    for (size_t i = 0; i < 10; i++)
                    {
                        if (PeekNamedPipe(g_PipeHandle_Old, NULL, NULL, NULL, &dwBytesAvailable, NULL))
                            if (0 != dwBytesAvailable) break; // There is data available so get it
                        Sleep(1000);
                    }
                    if (dwBytesAvailable == 0) {
                        MyOutputDebugString("│ [ID: %d] 2. Nothing can be read from old pipe", BattlEyeData->ID);
                    }
                    else {
                        if (!ReadFile(g_PipeHandle_Old, packet_2, 5, &old_cbRead, 0)) {
                            StopMyService("│ [BEService] ReadFile from old pipe failed.");
                            break;
                        }
                        MyOutputDebugString("│ [ID: %d] 2. Read packet_2 from old", BattlEyeData->ID);

                        hex_dump(&packet_2, old_cbRead, OutputBuffer);
                        LogFile << "│ [ID: " << (int)BattlEyeData->ID << "][Packet_From_Old] [" << old_cbRead << " bytes]\n" << OutputBuffer.str() << std::endl;
                        LogFile.flush();

                    }

                    byte packet_2_b[5] = { 0 };
                    // Check if there is any data in the pipe to read
                    dwBytesAvailable = 0; old_cbRead = 0;
                    for (size_t i = 0; i < 10; i++)
                    {
                        if (PeekNamedPipe(g_PipeHandle_Old, NULL, NULL, NULL, &dwBytesAvailable, NULL))
                            if (0 != dwBytesAvailable) break; // There is data available so get it
                        Sleep(1000);
                    }

                    if (dwBytesAvailable == 0) {
                        MyOutputDebugString("│ [ID: %d] 3. Nothing can be read from old pipe", BattlEyeData->ID);
                    }
                    else {
                        if (!ReadFile(g_PipeHandle_Old, packet_2_b, 5, &old_cbRead, 0)) {
                            StopMyService("│ [BEService] ReadFile from old pipe failed.");
                            break;
                        }
                        MyOutputDebugString("│ [ID: %d] 4. Read packet_2 from old", BattlEyeData->ID);


                        hex_dump(&packet_2_b, old_cbRead, OutputBuffer);
                        LogFile << "│ [ID: " << (int)BattlEyeData->ID << "][Packet_From_Old] [" << old_cbRead << " bytes]\n" << OutputBuffer.str() << std::endl;
                        LogFile.flush();
                    }


                    //KillBattEye();
                    MyOutputDebugString("│ [ID: %d] Packet_2 reveived, kill BattlEye", BattlEyeData->ID);
                    MyOutputDebugString("│ [ID: %d] emmmm... don't kill it would be better", BattlEyeData->ID);
                    //CloseHandle(g_PipeHandle_Old);
                    //g_PipeHandle_Old = 0;
                }
#pragma endregion

                // be version
                if (packet_2[0] != 2) {
                    MyOutputDebugString("│ [ID: %d] packet_2 error, use static data", BattlEyeData->ID);
                    packet_2[0] = 2;
                    packet_2[1] = 0x75;
                    packet_2[2] = 0x92;
                    packet_2[3] = 0x20;
                    packet_2[4] = 0x5b;
                }

                if (!WriteFile(g_PipeHandle, &packet_2, 5, &dwWritten, 0))
                {
                    StopMyService("│ [BEService] WriteFile failed.");
                    break;
                }
                hex_dump(&packet_2, dwWritten, OutputBuffer);
                LogFile << "│ [ID: " << (int)BattlEyeData->ID << "][Send] [" << dwWritten << " bytes]\n" << OutputBuffer.str() << std::endl;
                LogFile.flush();
                MyOutputDebugString("│ [ID: %d] Send Size: %d", BattlEyeData->ID, dwWritten);

                Request_2b.ID = 2;
                *reinterpret_cast<DWORD*>(Request_2b.pArgument) = dwGameID;

                if (!WriteFile(g_PipeHandle, &Request_2b, 5, &dwWritten, 0))
                {
                    StopMyService("│ [BEService] WriteFile failed.");
                    break;
                }
                hex_dump(&Request_2b, dwWritten, OutputBuffer);
                LogFile << "│ [ID: " << (int)BattlEyeData->ID << "][Send] [" << dwWritten << " bytes]\n" << OutputBuffer.str() << std::endl;
                LogFile.flush();
                MyOutputDebugString("│ [ID: %d] Send Size: %d", BattlEyeData->ID, dwWritten);

                processed = true;
            }

            // 开始检查sigs的标记?
            else if (BattlEyeData->ID == 4 && dwReaded == 1)
            {
                processed = true;
            }

            // 需要反馈
            else if (BattlEyeData->ID == 4 && BattlEyeData->Data[0] == 0x05)
            {
                BYTE Request_5[1] = { 5 };

                if (!WriteFile(g_PipeHandle, &Request_5, 1, &dwWritten, 0))
                {
                    StopMyService("│ [BEService] WriteFile failed.");
                    break;
                }
                hex_dump(Request_5, dwWritten, OutputBuffer);
                LogFile << "│ [ID: " << (int)BattlEyeData->ID << "][Send] [" << dwWritten << " bytes]\n" << OutputBuffer.str() << std::endl;
                LogFile.flush();
                MyOutputDebugString("│ [ID: %d] Send Size: %d", BattlEyeData->ID, dwWritten);

                processed = true;
                // enterLoop = true;
            }

            // signs check  05 06/04/07 (XX 00 00 00) bodylen
            else if (BattlEyeData->Data[0] == 0x05 &&
                (BattlEyeData->Data[1] == 0x06 || BattlEyeData->Data[1] == 0x04 || BattlEyeData->Data[1] == 0x07))
            {
                // 16 05 06 80 00 00 00 xx xx (sigs)
                MyOutputDebugString("│ [ID: %d] Sigs check packet (Key: 0x66)", BattlEyeData->ID);

                /*
                byte *sigsBuffer = BattlEyeData->Data + 6;
                int sigsLen = *reinterpret_cast<DWORD*>(BattlEyeData->Data + 2);
                int dataLen = dwReaded - 6; // == sigsLen

                std::stringstream ss;
                bool needDivide = false;
                for (size_t i = 0; i < dataLen; i++)
                {
                    sigsBuffer[i] ^= 0x66;
                    if (sigsBuffer[i]) {
                        if (needDivide) ss << " - ";
                        ss << sigsBuffer[i];
                        needDivide = false;
                    }
                    else if (i + 1 < dataLen && !(sigsBuffer[i + 1] ^ 0x66)) {
                        needDivide = true;
                    }
                }

                LogFile << "│ [ID: " << (int)BattlEyeData->ID << "][Sigs: " << sigsLen << "bytes] " << ss.str() << std::endl;
                LogFile.flush();
                */
                processed = true;
            }

            // 0xe0 (224 226 227 235) maybe signs check
            else if (BattlEyeData->Data[0] == 0x04 && BattlEyeData->Data[1] == 0x01
                && BattlEyeData->Data[3] == 0x00 && BattlEyeData->Data[4] == 0x00 && BattlEyeData->Data[5] == 0x00)
            {
                //e0 04 01 24 00 00 00 16 a9 63 66 0f 66 15 66 46 66 04 66 07 66 05 66 0d 66 46 66 46 66 5c 66 4f 66 66 6d 14 66 03 66 08 66 03 66 
                MyOutputDebugString("│ [ID: %d] Sigs check packet (Key: 0x66)", BattlEyeData->ID);
                processed = true;
            }
            else {
                MyOutputDebugString("│ [ID: %d] Unknown request", BattlEyeData->ID);
            }

            MyOutputDebugString("└────────BattlEye request %d────────┘", BattlEyeData->ID);
            //dwUnknownPacket = 0;
            //dwReaded = 0;
        }


        if (enterLoop)
        {
            BYTE Request_5;
            Request_5 = 5;
            int sleepCount = 0;
            while (WriteFile(g_PipeHandle, &Request_5, 1, &dwWritten, 0)) {
                MyOutputDebugString("│ [ID: %d] send heart beat", 5);

                Sleep(100);
                sleepCount += 100;
                if (sleepCount >= 30000) {
                    sleepCount = 0;
                    MyOutputDebugString("┌────────BattlEye request %d────────┐", 2);
                    if (WriteFile(g_PipeHandle, &packet_2, 5, &dwWritten, 0)) {
                        MyOutputDebugString("│ [ID: %d] Send Size: %d", BattlEyeData->ID, dwWritten);
                    }
                    else {
                        MyOutputDebugString("│ [ID: %d] Failed to send packet_2", BattlEyeData->ID);
                    }
                    hex_dump(packet_2, dwWritten, OutputBuffer);
                    LogFile << "│ [ID: " << 2 << "][Send] [" << dwWritten << " bytes]\n" << OutputBuffer.str() << std::endl;
                    LogFile.flush();

                    byte packet_2b[5] = { 0 };
                    packet_2b[0] = 2;
                    *reinterpret_cast<DWORD*>(packet_2b + 1) = dwGameID;
                    if (WriteFile(g_PipeHandle, &packet_2b, 5, &dwWritten, 0)) {
                        MyOutputDebugString("│ [ID: %d] Send Size: %d", BattlEyeData->ID, dwWritten);
                    }
                    else {
                        MyOutputDebugString("│ [ID: %d] Failed to send packet_2b", BattlEyeData->ID);
                    }
                    hex_dump(packet_2b, dwWritten, OutputBuffer);
                    LogFile << "│ [ID: " << 2 << "][Send] [" << dwWritten << " bytes]\n" << OutputBuffer.str() << std::endl;
                    LogFile.flush();

                    MyOutputDebugString("└────────BattlEye request %d────────┘", 2);
                }
            }
            MyOutputDebugString("│ [ID: %d] failed to send heart beat", 5);
        }

        // only transfer data, for debug!
        if (false && dwReaded && !processed && (g_PipeHandle_Old != 0 || connectToOldPipe(g_PipeHandle_Old))) {
            BattlEyeData = reinterpret_cast<PBATTLEYE_DATA>(lpBuffer);
            dwUnknownPacket = BattlEyeData->ID;

            MyOutputDebugString("┌─────────Transfer BattlEye request %d────────┐", dwUnknownPacket);

            // id 3 process hack
            if (dwUnknownPacket == 3) {
                //BYTE request_3[5] = { 0 };
                //request_3[0] = 3;
                //DWORD hackId = GetCurrentProcessId();
                //*reinterpret_cast<DWORD*>(request_3 + 1) = hackId;
                //MyOutputDebugString("│ [ID: %d] ProcessId Hack: 0x%X (%d)", BattlEyeData->ID, hackId, hackId);
                DWORD old_cbWritten;
                if (!WriteFile(g_PipeHandle_Old, lpBuffer, 5, &old_cbWritten, NULL)) {
                    StopMyService("│ [BEService] WriteFile to old pipe failed.");
                    break;
                }
                MyOutputDebugString("│ [ID: %d] 1. WriteFile to old pipe ok", BattlEyeData->ID);
                MyOutputDebugString("│ [ID: %d] 2. Don't need ReadFile from old.", BattlEyeData->ID);

            }
            // 不需要返回包
            else if (dwUnknownPacket == 4 || dwUnknownPacket >= 22) {
                DWORD old_cbWritten;
                if (!WriteFile(g_PipeHandle_Old, lpBuffer, dwReaded, &old_cbWritten, NULL)) {
                    StopMyService("│ [BEService] WriteFile_dn to old pipe failed.");
                    break;
                }
                MyOutputDebugString("│ [ID: %d] 1. WriteFile to old pipe ok", BattlEyeData->ID);
                MyOutputDebugString("│ [ID: %d] 2. Don't need ReadFile from old.", BattlEyeData->ID);
            }
            // 返回包要发两次
            else if (dwUnknownPacket == 2) {
                DWORD old_cbWritten;
                // { 02 } 1 byte
                if (!WriteFile(g_PipeHandle_Old, lpBuffer, dwReaded, &old_cbWritten, NULL)) {
                    StopMyService("│ [BEService] WriteFile to old pipe failed.");
                    break;
                }
                MyOutputDebugString("│ [ID: %d] 1. WriteFile to old pipe ok", BattlEyeData->ID);

#pragma region read
                ZeroMemory(lpBuffer, 0x1000);
                DWORD old_cbRead;
                if (!ReadFile(g_PipeHandle_Old, lpBuffer, 0x1000, &old_cbRead, 0)) {
                    StopMyService("│ [BEService] ReadFile from old pipe failed.");
                    break;
                }
                MyOutputDebugString("│ [ID: %d] 2. ReadFile from old ok", BattlEyeData->ID);

                if (processed) {
                    MyOutputDebugString("│ [ID: %d] 3. WriteFile: already been sent", BattlEyeData->ID);
                }
                else {
                    if (!WriteFile(g_PipeHandle, lpBuffer, old_cbRead, &old_cbWritten, 0))
                    {
                        StopMyService("│ [BEService] WriteFile to new failed.");
                        break;
                    }
                    MyOutputDebugString("│ [ID: %d] 3. WriteFile to new ok", BattlEyeData->ID);

                    MyOutputDebugString("│ [ID: %d] Send Size: %d", BattlEyeData->ID, old_cbWritten);

                    hex_dump(lpBuffer, old_cbWritten, OutputBuffer);
                    LogFile << "│ [ID: " << (int)BattlEyeData->ID << "][Send] [" << old_cbWritten << " bytes]\n" << OutputBuffer.str() << std::endl;
                    LogFile.flush();
                }

#pragma endregion
                //这个包要读两次
#pragma region read_b
                ZeroMemory(lpBuffer, 0x1000);
                if (!ReadFile(g_PipeHandle_Old, lpBuffer, 0x1000, &old_cbRead, 0)) {
                    StopMyService("│ [BEService] ReadFile from old pipe failed.");
                    break;
                }
                MyOutputDebugString("│ [ID: %d] 4. ReadFile from old ok", BattlEyeData->ID);

                if (processed) {
                    MyOutputDebugString("│ [ID: %d] 5. WriteFile: already been sent", BattlEyeData->ID);
                }
                else {
                    if (!WriteFile(g_PipeHandle, lpBuffer, old_cbRead, &old_cbWritten, 0))
                    {
                        StopMyService("│ [BEService] WriteFile to new failed.");
                        break;
                    }
                    MyOutputDebugString("│ [ID: %d] 5. WriteFile to new ok", BattlEyeData->ID);
                    MyOutputDebugString("│ [ID: %d] Send Size: %d", BattlEyeData->ID, old_cbWritten);

                    hex_dump(lpBuffer, old_cbWritten, OutputBuffer);
                    LogFile << "│ [ID: " << (int)BattlEyeData->ID << "][Send] [" << old_cbWritten << " bytes]\n" << OutputBuffer.str() << std::endl;
                    LogFile.flush();
                }
#pragma endregion

            }
            // 普通的转发 id = 6 id = 4 
            else if (1) {
                DWORD old_cbWritten;
                if (!WriteFile(g_PipeHandle_Old, lpBuffer, dwReaded, &old_cbWritten, NULL)) {
                    StopMyService("│ [BEService] WriteFile to old pipe failed.");
                    break;
                }
                MyOutputDebugString("│ [ID: %d] 1. WriteFile to old pipe ok", BattlEyeData->ID);

                DWORD old_cbRead = 0;

                // Check if there is any data in the pipe to read
                DWORD dwBytesAvailable = 0;
                for (size_t i = 0; i < 10; i++)
                {
                    if (PeekNamedPipe(g_PipeHandle_Old, NULL, NULL, NULL, &dwBytesAvailable, NULL))
                        if (0 != dwBytesAvailable) break; // There is data available so get it
                    Sleep(1000);
                }
                if (dwBytesAvailable == 0) {
                    MyOutputDebugString("│ [ID: %d] 2. Nothing can be read from old pipe", BattlEyeData->ID);
                }
                else {
                    if (!ReadFile(g_PipeHandle_Old, lpBuffer, 0x1000, &old_cbRead, 0)) {
                        StopMyService("│ [BEService] ReadFile from old pipe failed.");
                        break;
                    }
                    MyOutputDebugString("│ [ID: %d] 2. ReadFile from old ok", BattlEyeData->ID);
                }
                if (old_cbRead) {
                    if (processed) {
                        MyOutputDebugString("│ [ID: %d] 3. WriteFile: already been sent", BattlEyeData->ID);
                    }
                    else {
                        if (!WriteFile(g_PipeHandle, lpBuffer, old_cbRead, &old_cbWritten, 0))
                        {
                            StopMyService("│ [BEService] WriteFile to new failed.");
                            break;
                        }
                        MyOutputDebugString("│ [ID: %d] 3. WriteFile to new ok", BattlEyeData->ID);
                        MyOutputDebugString("│ [ID: %d] Send Size: %d", BattlEyeData->ID, old_cbWritten);

                        hex_dump(lpBuffer, old_cbWritten, OutputBuffer);
                        LogFile << "│ [ID: " << (int)BattlEyeData->ID << "][Send] [" << old_cbWritten << " bytes]\n" << OutputBuffer.str() << std::endl;
                        LogFile.flush();
                    }
                }
            }

            MyOutputDebugString("└─────────Transfer BattlEye request %d────────┘", dwUnknownPacket);
        }
    }
    CloseHandle(g_PipeHandle);
    VirtualFree(lpBuffer, 0x1000, MEM_DECOMMIT);
    VirtualizerEnd();
    return TRUE;
}

// when game over, service exit
DWORD WINAPI WatchGameThread(LPVOID lpParam)
{
    VirtualizerStart();
    DWORD pProcessID = reinterpret_cast<DWORD>(lpParam);
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, false, pProcessID);
    WaitForSingleObject(hProcess, INFINITE);
    StopMyService("[BEService2] GameOver, I will exit...");
    SetEvent(g_ServiceStopEvent);
    CloseHandle(hProcess);
    VirtualizerEnd();
    return TRUE;
}