#include "Includes.hpp"

std::vector<HANDLE> Threads, Pipes;

SERVICE_STATUS        g_ServiceStatus = { 0 };
SERVICE_STATUS_HANDLE g_StatusHandle = NULL;
HANDLE                g_ServiceStopEvent = INVALID_HANDLE_VALUE, g_Thread = NULL;

VOID WINAPI ServiceMain(DWORD argc, LPTSTR *argv);
VOID WINAPI ServiceCtrlHandler(DWORD);
DWORD WINAPI ServiceWorkerThread(LPVOID lpParam);
DWORD WINAPI PipeHandleThread(LPVOID lpParam);
DWORD WINAPI WatchGameThread(LPVOID lpParam);
