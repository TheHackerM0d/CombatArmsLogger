#pragma once
#include <Windows.h>
#include <iostream>
#include <string>
#include <vector>
#include <utility>
#include <d3d9.h>
#include <d3dx9.h>
#include <sstream>
#include <fstream>
#include <filesystem>
#pragma comment(lib, "d3d9.lib")
#pragma comment(lib, "d3dx9.lib")
#include "PatternScanner.h"

std::ofstream ofile;
void __cdecl add_log(const char* fmt, ...)
{
	ofile.open("C:\\Classic.txt", std::ios::app); va_list va_alist;
	char logbuf[256] = { 0 };
	va_start(va_alist, fmt);
	vsnprintf(logbuf + strlen(logbuf), sizeof(logbuf) - strlen(logbuf), fmt, va_alist);
	va_end(va_alist);
	ofile << logbuf << std::endl;
	ofile.close();
}

std::wstring GetCurrentProcessName() { WCHAR fileName[MAX_PATH]; GetModuleFileNameW(NULL, fileName, MAX_PATH); return std::filesystem::path(fileName).filename().wstring(); }
std::wstring processName = GetCurrentProcessName();
void __stdcall Address_Logger()
{
	DeleteFileA("C:\\Classic.txt");
	MessageBox(NULL, "Press 'OK' once game is opened!", "Message from TheHacker/Mod", MB_OK | MB_ICONERROR);
#pragma region Engine
	if (processName == L"Engine.exe")
	{
		add_log("\n// \t Engine's Information\n");


		DWORD Get_DrawPrimitive = PatternScanAdder(1, "A1 ? ? ? ? C3 CC CC CC CC CC CC CC CC CC CC A1 ? ? ? ? C3 CC CC CC CC CC CC CC CC CC CC A1 ? ? ? ? C3 CC CC CC CC CC CC CC CC CC CC A1 ? ? ? ? C3 CC CC CC CC CC CC CC CC CC CC A1 ? ? ? ? C3 CC CC CC CC CC CC CC CC CC CC 8B 44 24 04 83 EC 0C ", false, 0x1);
		if (Get_DrawPrimitive != NULL) { add_log("#define ADDR_DrawPrimitive\t\t0x%X", Get_DrawPrimitive);  }
		else { add_log("//Failed to update DrawPrimitive"); }

	}
	if (processName == L"Engine2.exe")
	{
		add_log("\n// \t Engine2's Information\n");

		DWORD Get_DrawPrimitive = PatternScanAdder(2, "A1 ? ? ? ? C3 CC CC CC CC CC CC CC CC CC CC A1 ? ? ? ? C3 CC CC CC CC CC CC CC CC CC CC A1 ? ? ? ? C3 CC CC CC CC CC CC CC CC CC CC A1 ? ? ? ? C3 CC CC CC CC CC CC CC CC CC CC A1 ? ? ? ? C3 CC CC CC CC CC CC CC CC CC CC 8B 44 24 04 83 EC 0C ", false, 0x1);
		if (Get_DrawPrimitive != NULL) { add_log("#define ADDR_DrawPrimitive\t\t0x%X", Get_DrawPrimitive);  }
		else { add_log("//Failed to update DrawPrimitive"); }
	}
#pragma endregion
#pragma region CSHELL
	add_log("\n// \t CSHELL's Information\n");

	DWORD Get_GameStatus = PatternScan(0, "? 00 00 00 00 00 00 00 ? ? ? 37 00 00 00 00 FF FF FF FF", false);
	if (Get_GameStatus != NULL) { add_log("#define ADDR_GameStatus\t\t\t0x%X", Get_GameStatus);}
	else { add_log("//Failed to update ADDR_GameStatus");  }
#pragma endregion
	MessageBoxA(NULL, "Logging Complete", "Success!, Maybe?", MB_OK | MB_ICONEXCLAMATION);
	ExitProcess(1);
}
BOOL __stdcall DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved)
{
	if (ul_reason_for_call == DLL_PROCESS_ATTACH)
	{
		DisableThreadLibraryCalls(hModule); CreateThread(NULL, NULL, (LPTHREAD_START_ROUTINE)Address_Logger, NULL, NULL, NULL);
	}
	return TRUE;
}
