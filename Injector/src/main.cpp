#define _CRT_SECURE_NO_WARNINGS
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <TlHelp32.h>
#include <cstdio>
#include <string>
#include <comdef.h>
#include <intrin.h>
#include <winternl.h>

//#ifdef _M_IX86
//
//DWORD GetLastErrCode() {
//
//}
//DWORD GetTebAddr() {
//
//}
//
//#else
//
//extern "C" DWORD GetLastErrCode();
//extern "C" DWORD GetTebAddr();
//
//#endif


typedef struct _THREAD_BASIC_INFORMATION
{
	NTSTATUS ExitStatus;
	PTEB TebBaseAddress;
	CLIENT_ID ClientId;
	ULONG_PTR AffinityMask;
	KPRIORITY Priority;
	LONG BasePriority;
} THREAD_BASIC_INFORMATION, * PTHREAD_BASIC_INFORMATION;

unsigned long long int getThreadTeb(HANDLE hThread) {
	bool loadedManually = false;
	HMODULE module = GetModuleHandleA("ntdll.dll");
	if (!module)
	{
		module = LoadLibraryA("ntdll.dll");
		loadedManually = true;
	}
	NTSTATUS(__stdcall * NtQueryInformationThread)(HANDLE ThreadHandle, THREADINFOCLASS ThreadInformationClass, PVOID ThreadInformation, ULONG ThreadInformationLength, PULONG ReturnLength);
	NtQueryInformationThread = reinterpret_cast<decltype(NtQueryInformationThread)>(GetProcAddress(module, "NtQueryInformationThread"));
	THREAD_BASIC_INFORMATION tbi = { 0 };
	NTSTATUS status = NtQueryInformationThread(hThread, (THREADINFOCLASS)0, &tbi, sizeof(tbi), NULL);

	if (loadedManually)
	{
		FreeLibrary(module);
	}
	return (unsigned long long int)tbi.TebBaseAddress;
}

void PrintError(const char* myMsg, DWORD err = -1) {
	if (err == -1) {
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

DWORD SetPrivilege(HANDLE hToken, LPCTSTR lpszPrivilege, BOOL bEnablePrivilege) {
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

void getDebugPrivilege() {
	HANDLE hProcess = GetCurrentProcess();
	HANDLE hToken;
	if (OpenProcessToken(hProcess, TOKEN_ADJUST_PRIVILEGES, &hToken))
	{
		printf("[*] obtaining debug privilege...\n");
		DWORD errCode = SetPrivilege(hToken, SE_DEBUG_NAME, TRUE);
		if (errCode != 0) {
			PrintError("failed to obtain debug privilege (method 1)", errCode);
			// failed. try again, different method
			{
				printf(" [*] attempting method 2...\n");
				HMODULE ntdll = LoadLibraryA("ntdll");
				if (ntdll != NULL) {
					FARPROC RtlAdjustPrivilege = GetProcAddress(ntdll, "RtlAdjustPrivilege");
					FARPROC RtlNtStatusToDosError = GetProcAddress(ntdll, "RtlNtStatusToDosError");
					if (RtlAdjustPrivilege != NULL && RtlNtStatusToDosError != NULL) {
						BOOLEAN prev;
						// 20: SeDebugPrivilege
						LONG retval = ((LONG(*)(DWORD, DWORD, BOOLEAN, LPBYTE))RtlAdjustPrivilege)(20, 1, 0, &prev);
						// convert NTSTATUS (retval) to a DOS error code
						ULONG dosErr = ((ULONG(*)(LONG))RtlNtStatusToDosError)(retval);
						if (dosErr == 0) {
							printf(" [+] success! (method 2)\n");
						}
						else {
							PrintError("failed to obtain debug privilege (method 2)", dosErr);
						}
					}
				}
			}
		}
		else {
			printf(" [+] success!\n");
		}
		CloseHandle(hToken);
	}
}

DWORD GetProcIdByName(const wchar_t* pName) {
	DWORD procId = 0;
	HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

	if (hSnap != INVALID_HANDLE_VALUE) {
		PROCESSENTRY32 procEntry;
		memset(&procEntry, 0, sizeof(procEntry));
		procEntry.dwSize = sizeof(procEntry);

		if (Process32First(hSnap, &procEntry)) {
			do {
				if (!lstrcmpW(procEntry.szExeFile, pName)) {
					procId = procEntry.th32ProcessID;
					break;
				}
			} while (Process32Next(hSnap, &procEntry));
		}
	}
	CloseHandle(hSnap);
	return procId;
}

bool is_number(const std::string& s)
{
	return !s.empty() && std::find_if(s.begin(),
		s.end(), [](unsigned char c) { return !std::isdigit(c); }) == s.end();
}

DWORD FindPid(const wchar_t* procName) {
	DWORD procId = 0;
	wprintf(L"[*] searching for process '%s'...\n", procName);
	unsigned int ticks = 0;
	while (!procId) {
		if (ticks > 200) {
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

void simpleInject(const char* dllPath, DWORD procId) {
	printf("[*] opening process with pid %d...\n", procId);
	HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS, 0, procId);

	if (hProc && hProc != INVALID_HANDLE_VALUE) {
		printf(" [+] success!\n");
		printf("[*] allocating memory in process...\n");
		void* loc = VirtualAllocEx(hProc, 0, MAX_PATH, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

		if (loc == NULL) {
			PrintError("memory allocation failed");
		}
		else {
			printf(" [+] success!\n");
			printf("[*] writing dll path into memory...\n");
			if (WriteProcessMemory(hProc, loc, dllPath, strlen(dllPath) + 1, 0) == 0) {
				PrintError("write failed");
			}
			else {
				printf(" [+] success!\n");
				printf("[*] creating thread...\n");
				HANDLE hThread = CreateRemoteThread(hProc, 0, 0, (LPTHREAD_START_ROUTINE)LoadLibraryA, loc, 0, 0);

				if (hThread == NULL) {
					PrintError("failed to create thread");
				}
				else {
					printf(" [+] success!\n");
					printf("[*] Loading DLL...\n");

					WaitForSingleObject(hThread, INFINITE);

					DWORD exitCode = 0;
					if (GetExitCodeThread(hThread, &exitCode)) {
						if (exitCode != 0)
							printf(" [+] success!\n");
						else
						{
#pragma region get thread lasterror code. doesnt work

							//DWORD errCode = 69; SIZE_T dontcare = 69;
							////MEMORY_BASIC_INFORMATION meminfo = { 0 };
							////BOOL vq = VirtualQueryEx(hProc, (LPCVOID)errCode_address, &meminfo, sizeof(meminfo));

							//DWORD prevProtect;
							//{
							//	BOOL succ = VirtualProtectEx(hProc, (LPVOID)errCode_address, 4, PAGE_READONLY, &prevProtect);
							//	if (!succ) printError("VirtualProtectEx");
							//	BOOL success = ReadProcessMemory(hProc, (LPCVOID)(errCode_address), &errCode, sizeof(DWORD), &dontcare);
							//	if (!success) printError("ReadProcessMemory");
							//	BOOL _succ = VirtualProtectEx(hProc, (LPVOID)errCode_address, 4, prevProtect, &prevProtect);
							//	if (!_succ) printError("VirtualProtectEx");
							//}
							//{
							//	BOOL succ = VirtualProtectEx(GetCurrentProcess(), (LPVOID)errCode_address, 4, PAGE_READONLY, &prevProtect);
							//	if (!succ) printError("VirtualProtectEx");
							//	BOOL success = ReadProcessMemory(GetCurrentProcess(), (LPCVOID)(errCode_address), &errCode, sizeof(DWORD), &dontcare);
							//	if (!success) printError("ReadProcessMemory");
							//	BOOL _succ = VirtualProtectEx(GetCurrentProcess(), (LPVOID)errCode_address, 4, prevProtect, &prevProtect);
							//	if (!_succ) printError("VirtualProtectEx");
							//}
#pragma endregion
							char dest[MAX_PATH + 24 + 1] = "failed to load dll at: ";
							PrintError(strcat(dest, dllPath));
						}
					}
					else {
						PrintError("unable to get return value of injection thread");
					}
					CloseHandle(hThread);
				}
			}
		}
	}
	else {
		PrintError("invalid process handle");
	}

	if (hProc) {
		CloseHandle(hProc);
	}
}

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
	if (is_number(procArgStr)) 
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
	getDebugPrivilege();
	simpleInject(dllPath, pid);
	
	// free memory
	delete[] dllPath;

	return 0;
}
