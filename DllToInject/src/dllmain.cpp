#define _CRT_SECURE_NO_WARNINGS
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>
#include <comdef.h>

BOOL WINAPI InjectedThread(HMODULE hModule)
{
	AllocConsole();
	FILE* f = nullptr;
	freopen_s(&f, "CONOUT$", "w", stdout);

	printf("dll injected at 0x%llX\n", (size_t)hModule);
	puts("press esc to terminate this thread (without closing the process)");
	while (1)
	{
		if (GetAsyncKeyState(VK_ESCAPE) & 0x01)
		{
			break;
		}
	}

	if (f) fclose(f);
	FreeConsole();
	FreeLibraryAndExitThread(hModule, 0);
	return 0;
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved)
{
	if (ul_reason_for_call == DLL_PROCESS_ATTACH)
	{
		HANDLE hThread = CreateThread(nullptr, 0, (LPTHREAD_START_ROUTINE)InjectedThread, hModule, 0, nullptr);
		if (hThread)
		{
			CloseHandle(hThread);
		}
		//MessageBoxA(NULL, "dll injected successfully!", "hello there", 0);
	}
	return TRUE;
}