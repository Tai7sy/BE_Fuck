#pragma once

#define SERVICE_PIPE	"\\\\.\\pipe\\BattlEye"
#define SERVICE_PROXY	"\\\\.\\pipe\\19060"
#define SERVICE_PIPE_KERNEL		L"\\??\\pipe\\BattlEye"
#define SERVICE_PROXY_KERNEL	L"\\??\\pipe\\19060"

#define SERVICE_EXE	    "BEService.exe"
#define GAME_EXE	    "Unturned.exe"
#define GAME_BE_EXE		"Unturned_BE.exe"

//#define MAIN_GAME_NAME	"TslGame.exe"
//#define GAME_NAME		"TslGame_BE.exe"

#define HWID_PROTECTION_ID 1824036797


// Inject GAME_EXE to change the pipe name, set to 1
// Kill BEService to use old pipe name, set to 0
// Use BE_Listener to capture the packets, set to 0
#define BYPASS_METHOD_INJECT_GAME   0
#define BESERVICE_LISTENER_MODE     BYPASS_METHOD_INJECT_GAME



#define BESERVICE_LISTENER_LOGPATH "D:\\MyProjects\\VSProjects\\BE_Fuck\\Log_BEService.txt"