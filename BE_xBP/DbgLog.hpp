#pragma once
#include "Includes.hpp"

namespace DbgLog
{
	static void Log(LPCTSTR lpszFormat, ...)
	{
		va_list args;
		TCHAR szBuffer[4096];
		int nBuf = 0;
		ZeroMemory(szBuffer, 4096);
		va_start(args, lpszFormat);
		nBuf = _vsnprintf_s(szBuffer, 4095, lpszFormat, args);
        size_t len = strlen(szBuffer);
        if (szBuffer[len - 1] != '\n') {
            szBuffer[len] = '\n';
            szBuffer[len + 1] = 0;
        }
		::OutputDebugStringA(szBuffer);
		va_end(args);
	}
	static void LogW(LPCWSTR lpszFormat, ...)
	{
		va_list args;
		WCHAR szBuffer[4096];
		int nBuf = 0;
		ZeroMemory(szBuffer, 4096);
		va_start(args, lpszFormat);
		nBuf = _vscwprintf(szBuffer, args);
		::OutputDebugStringW(szBuffer);
		va_end(args);
	}
}

