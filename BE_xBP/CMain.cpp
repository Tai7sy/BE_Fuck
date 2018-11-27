#include "Kernelmode.hpp"
#include "Usermode.hpp"
#include "Listener.hpp"
#include "Module.hpp"
#include "DbgLog.hpp"

namespace CMain
{
    static bool OnAttach(HMODULE hDll)
    {
        VirtualizerStart();
        PBOOL pCounter = 0;
        std::array<char, MAX_PATH> szError;
        bool Error = true;
#if (HWID_PROTECTION == 1)
        DWORD HddNumber = 0;
        if (!GetVolumeInformationA("C://", NULL, NULL, &HddNumber, NULL, NULL, NULL, NULL))
        {
            sprintf_s(szError.data(), szError.size(), "Failed to initialize HASH Reader (errorcode : %i)", GetLastError());
            MessageBoxA(0, szError.data(), "ERROR", MB_ICONERROR);
            ExitProcess(8);
            ExitThread(8);
        }
        if (HddNumber != HWID_PROTECTION_ID)
        {
            sprintf_s(szError.data(), szError.size(), "Failed to initialize BattlEye Bypass (errorcode : %i)", GetLastError());
            MessageBoxA(0, szError.data(), "ERROR", MB_ICONERROR);
            ExitProcess(8);
            ExitThread(8);
            *pCounter = 0;
        }
#endif
        if (GetModuleHandleA(GAME_EXE))
        {
            Error = BE::Usermode::Bypass::GetInstance()->Init(hDll);
            if (Error != true)
            {
                sprintf_s(szError.data(), szError.size(), "[Dll_Hook] Failed to initialize BattlEye Bypass_1 (errorcode : %i)\n", GetLastError());
                OutputDebugStringA(szError.data());
                MessageBoxA(0, szError.data(), "ERROR", MB_ICONERROR);
            }
            else {
                OutputDebugStringA("[Dll_Hook] Usermode hook successfully.\n");
            }
        }
        if (GetModuleHandleA(GAME_BE_EXE)) // BattlEye Launcher
        {
            Error = BE::Kernelmode::XDriver::GetInstance()->Init();
            if (Error != true)
            {
                sprintf_s(szError.data(), szError.size(), "[Dll_Hook] Failed to initialize BattlEye Bypass_2 (errorcode : %i)\n", GetLastError());
                OutputDebugStringA(szError.data());
                MessageBoxA(0, szError.data(), "ERROR", MB_ICONERROR);
            }
            else {
                OutputDebugStringA("[Dll_Hook] Kernelmode hook successfully.\n");
            }
        }

        if (GetModuleHandleA(SERVICE_EXE)) // BattlEye Service
        {
            Error = BE::Listener::Listener::GetInstance()->Init();
        }

#ifdef _WIN64
        Module::ModuleOnAttach("BE_xBP_x64.dll", hDll);
#else
        Module::ModuleOnAttach("BE_xBP.dll", hDll);
#endif

        VirtualizerEnd();
        return Error;
    }
    static bool OnDetach()
    {
        VirtualizerStart();
        std::array<char, MAX_PATH> szError;
        bool Error = true;

        if (GetModuleHandleA(GAME_EXE))
        {
            Error = BE::Usermode::Bypass::GetInstance()->Uninit();
            if (Error != true)
            {
                sprintf_s(szError.data(), szError.size(), "Failed to uninitialize BattlEye Bypass (errorcode : %i)\n", GetLastError());
                MessageBoxA(0, szError.data(), "ERROR", MB_ICONERROR);
            }
        }
        if (GetModuleHandleA(GAME_BE_EXE))
        {
            Error = BE::Kernelmode::XDriver::GetInstance()->Uninit();
            if (Error != true)
            {
                sprintf_s(szError.data(), szError.size(), "Failed to uninitialize BattlEye Bypass (errorcode : %i)\n", GetLastError());
                MessageBoxA(0, szError.data(), "ERROR", MB_ICONERROR);
            }
        }
        if (GetModuleHandleA(SERVICE_EXE))
        {
            Error = BE::Listener::Listener::GetInstance()->Uninit();
            if (Error != true)
            {
                sprintf_s(szError.data(), szError.size(), "Failed to uninitialize BattlEye Bypass (errorcode : %i)\n", GetLastError());
                MessageBoxA(0, szError.data(), "ERROR", MB_ICONERROR);
            }
        }

#ifdef _WIN64
        Module::ModuleOnDetach("BE_xBP_x64.dll");
#else
        Module::ModuleOnDetach("BE_xBP.dll");
#endif
        VirtualizerEnd();
        return Error;

    }
};


BOOL WINAPI DllMain(HMODULE hDll, DWORD dwReason, LPVOID lpReserved)
{
    if (dwReason == DLL_PROCESS_ATTACH)
    {
        OutputDebugString("\r\n");
#ifdef _WIN64
        OutputDebugString("[BE_xBP] Dll x64 Injected! \r\n");
#else
        OutputDebugString("[BE_xBP] Dll x86 Injected! \r\n");
#endif

        CMain::OnAttach(hDll);
    }
    if (dwReason == DLL_PROCESS_DETACH)
    {
        CMain::OnDetach();
    }
    return TRUE;
}