#pragma once
#include "../BE_Starter/Common.hpp"

#define USE_VMPROTECT 0

#define DISABLE_DLLDETECTION 1
#define DISABLE_THREADDETECTION 1
#define DISABLE_APIPROTECTION 1
#define DISABLE_PROCESSDETECTION 1
#define DISABLE_BECLIENT 1
#define HOOK_PIPE 1


#define LOG_STATE 0
#define LOG_CREATESEMPAPHORE 0
#define LOG_NTQUERYVIRTUALMEMORY 0
#define LOG_NTWOW64QUERYVIRTUALMEMORY64 0
#define LOG_NTOPENPROCESS 0
#define LOG_GETWINDOTHREADPROCESSID 0
#define LOG_NTQUERYSYSTEMINFORMATION 0
#define LOG_NTGETCONTEXTTHREAD 0
#define LOG_NTOPENTHREAD 0
#define LOG_ZWREADFILE 0
#define LOG_NTCREATEFILE 0

#define HWID_PROTECTION 0


#define TEST_HEARTBEAT 0
#define ONLY64 TEST_HEARTBEAT

#include <Windows.h>
#include <iostream>
#include <winternl.h>
#include <vector>
#include <map>
#include <array>
#include <fstream>
#include <cstdint>
#include <detours.h>
#include <TlHelp32.h>
#include <intrin.h>
#pragma comment(lib,"detours.lib")

#if(USE_VMPROTECT == 1)
#include <VirtualizerSDK.h>
#ifdef _WIN32 
#pragma comment(lib,"COFF\\VirtualizerSDK32")
#elif _WIN64
#pragma comment(lib,"COFF\\VirtualizerSDK64")
#endif
#else
static void VirtualizerStart() {}
static void VirtualizerEnd() {}
#endif
