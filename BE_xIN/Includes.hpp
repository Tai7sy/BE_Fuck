#pragma once
#include <Windows.h>
#include <iostream>
#include <TlHelp32.h>
#include <Psapi.h>
#include <vector>
#include "Options.hpp"
#pragma comment(lib,"psapi.lib")

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


