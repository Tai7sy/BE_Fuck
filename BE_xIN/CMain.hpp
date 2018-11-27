#pragma once
#include "Includes.hpp"

std::vector<DWORD> pProcessIds;
DWORD dwCounts;

void ClearScreen();
bool CheckIfExists(DWORD dwPid);
bool IsElevated();
bool Is64Executable(HANDLE hProcess, PBOOL Is64);
BOOL WINAPI ControlDriver(LPCSTR lpFilename, BOOL Status);