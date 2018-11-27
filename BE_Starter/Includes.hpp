#pragma once

#include <Windows.h>
#include "Options.hpp"
#include <iostream>

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

