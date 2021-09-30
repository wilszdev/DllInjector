#define _CRT_SECURE_NO_WARNINGS
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>
#include <comdef.h>

BOOL WINAPI InjectedThread(HMODULE hModule)
{
	BOOL createdConsole = FALSE;
	FILE* f = nullptr;
	if ((createdConsole = AllocConsole()) == TRUE)
	{
		freopen_s(&f, "CONOUT$", "w", stdout);
	}

	printf("dll injected at 0x%p\n", (void*)hModule);

#if _DEBUG
	puts("this is a debug build");
#else
	puts("this is a release build");
#endif

	puts("press esc to terminate this thread (without closing the process)");
	while (1)
	{
		if (GetAsyncKeyState(VK_ESCAPE) & 0x01)
		{
			break;
		}
	}

	if (f) fclose(f);
	if (createdConsole) FreeConsole();
	FreeLibraryAndExitThread(hModule, 0);
	return TRUE;
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
	}
	return TRUE;
}