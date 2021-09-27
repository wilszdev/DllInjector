#include "injection.h"

void LoadLibraryInject(const char* dllPath, DWORD pid)
{
	HANDLE hProc = 0, hThread = 0;
	DWORD exitCode = 0;

	// open the process
	printf("[*] opening process with pid %d...\n", pid);
	hProc = OpenProcess(PROCESS_ALL_ACCESS, 0, pid);
	if (!hProc || hProc == INVALID_HANDLE_VALUE)
	{
		PrintError("invalid process handle");
		return;
	}

	// allocate some memory
	printf("[*] allocating memory in process...\n");
	void* loc = VirtualAllocEx(hProc, 0, MAX_PATH, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (!loc)
	{
		PrintError("memory allocation failed");
		goto cleanup;
	}

	// write the dll path
	printf("[*] writing dll path into memory...\n");
	if (WriteProcessMemory(hProc, loc, dllPath, strlen(dllPath) + 1, 0) == 0)
	{
		PrintError("write failed");
		goto cleanup;
	}

	// create remote thread
	printf("[*] creating remote thread...\n");
	hThread = CreateRemoteThread(hProc, 0, 0, (LPTHREAD_START_ROUTINE)LoadLibraryA, loc, 0, 0);
	if (!hThread)
	{
		PrintError("failed to create remote thread");
		goto cleanup;
	}

	// wait for it to finish
	printf("[*] Loading DLL...\n");
	WaitForSingleObject(hThread, INFINITE);
	if (GetExitCodeThread(hThread, &exitCode) && exitCode == 0) {
		PrintError("failed to load dll");
	}
	else
	{
		PrintError("failed to get exit code of injection thread");
	}

cleanup:
	if (hProc)
	{
		CloseHandle(hProc);
	}
	if (hThread)
	{
		CloseHandle(hThread);
	}
}

void ManualMappingInject(const char* dllPath, DWORD pid)
{
	HANDLE process = OpenProcess(PROCESS_ALL_ACCESS, 0, pid);
	if (!process)
	{
		return;
	}
}