#define _CRT_SECURE_NO_WARNINGS
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <TlHelp32.h>
#include <cstdio>
#include <string>
#include <comdef.h>
#include <intrin.h>
#include <winternl.h>

#pragma region function definitions
void PrintError(const char* myMsg, DWORD err = -1);
DWORD SetPrivilege(HANDLE hToken, LPCTSTR lpszPrivilege, BOOL bEnablePrivilege);
void GetDebugPrivilege();
DWORD GetProcIdByName(const wchar_t* pName);
bool IsNumber(const std::string& s);
DWORD FindPid(const wchar_t* procName);
void SimpleInject(const char* dllPath, DWORD procId);

#pragma endregion

int main(int argc, char** argv) {
	// validate args
	if (argc < 3) {
		printf("usage: %s <dll path> <process name (or pid)>\n", argv[0]);
		return 0;
	}
	// expands a relative path
	DWORD size = GetFullPathNameA(argv[1], 0, nullptr, nullptr);
	char* dllPath = new char[size];
	DWORD res = GetFullPathNameA(argv[1], size, dllPath, nullptr);
	if (res == 0)
	{
		delete[] dllPath;
		return -1;
	}
	// find process
	std::string procArgStr(argv[2]);

	DWORD pid;
	if (IsNumber(procArgStr))
	{
		// gave us a target pid
		pid = std::stoul(procArgStr);
	}
	else
	{
		// gave us a target process name
		// convert to wide character string
		const char* cstr_ProcName = argv[2];
		const size_t sz = strlen(cstr_ProcName) + 1;
		std::wstring w_procName(sz, L'#');
		mbstowcs(&w_procName[0], cstr_ProcName, sz);
		const wchar_t* procName = w_procName.c_str();
		// find
		pid = FindPid(procName);
	}

	if (pid == -1) return -1; // unable to find process

	// do the stuff
	GetDebugPrivilege();
	SimpleInject(dllPath, pid);

	// free memory
	delete[] dllPath;

	return 0;
}

#pragma region implementation

void PrintError(const char* myMsg, DWORD err)
{
	if (err == -1)
	{
		//err = GetLastError();
		printf(" [-] %s.", myMsg);
		return;
	}
	wchar_t* msgBuf = nullptr;
	FormatMessage(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_IGNORE_INSERTS, NULL, err, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), (wchar_t*)&msgBuf, 0, NULL);
	_bstr_t b(msgBuf); const char* c = b;
	printf(" [-] %s. err: %d %s", myMsg, err, c);
	LocalFree(msgBuf);
}

DWORD SetPrivilege(HANDLE hToken, LPCTSTR lpszPrivilege, BOOL bEnablePrivilege)
{
	LUID luid;
	DWORD bRet = 0;

	if (LookupPrivilegeValueW(NULL, lpszPrivilege, &luid))
	{
		TOKEN_PRIVILEGES tp;
		memset(&tp, 0, sizeof(tp));
		tp.PrivilegeCount = 1;
		tp.Privileges[0].Luid = luid;
		tp.Privileges[0].Attributes = (bEnablePrivilege) ? SE_PRIVILEGE_ENABLED : 0;

		AdjustTokenPrivileges(hToken, FALSE, &tp, NULL, (PTOKEN_PRIVILEGES)NULL, (PDWORD)NULL);
	}
	bRet = GetLastError();
	return bRet;
}

void GetDebugPrivilege()
{
	HANDLE hProcess = GetCurrentProcess();
	HANDLE hToken;
	if (OpenProcessToken(hProcess, TOKEN_ADJUST_PRIVILEGES, &hToken))
	{
		printf("[*] obtaining debug privilege...\n");
		DWORD errCode = SetPrivilege(hToken, SE_DEBUG_NAME, TRUE);
		if (errCode != 0)
		{
			PrintError("failed to obtain debug privilege (method 1)", errCode);
		}
		else
		{
			printf(" [+] success!\n");
		}
		CloseHandle(hToken);
	}
}

DWORD GetProcIdByName(const wchar_t* pName)
{
	DWORD procId = 0;
	HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

	if (hSnap != INVALID_HANDLE_VALUE)
	{
		PROCESSENTRY32 procEntry;
		memset(&procEntry, 0, sizeof(procEntry));
		procEntry.dwSize = sizeof(procEntry);

		if (Process32First(hSnap, &procEntry))
		{
			do {
				if (!lstrcmpW(procEntry.szExeFile, pName))
				{
					procId = procEntry.th32ProcessID;
					break;
				}
			} while (Process32Next(hSnap, &procEntry));
		}
	}
	CloseHandle(hSnap);
	return procId;
}

bool IsNumber(const std::string& s)
{
	return !s.empty() && std::find_if(s.begin(),
		s.end(), [](unsigned char c) { return !std::isdigit(c); }) == s.end();
}

DWORD FindPid(const wchar_t* procName)
{
	DWORD procId = 0;
	wprintf(L"[*] searching for process '%s'...\n", procName);
	unsigned int ticks = 0;
	while (!procId)
	{
		if (ticks > 200)
		{
			// after approx 10 seconds
			printf(" [-] unable to find target process\n");
			return -1;
		}
		procId = GetProcIdByName(procName);
		++ticks;
		Sleep(50);
	}
	printf(" [+] found!\n");
	return procId;
}

void SimpleInject(const char* dllPath, DWORD procId)
{
	HANDLE hProc = 0, hThread = 0;
	DWORD exitCode = 0;

	// open the process
	printf("[*] opening process with pid %d...\n", procId);
	hProc = OpenProcess(PROCESS_ALL_ACCESS, 0, procId);
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
		char dest[MAX_PATH + 24 + 1] = "failed to load dll at: ";
		PrintError(strcat(dest, dllPath));
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

#pragma endregion