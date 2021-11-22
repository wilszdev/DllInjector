#include "Win32Helpers.h"

std::string GetErrorCodeDescription(DWORD err)
{
	std::string result;

	char* buffer = nullptr;
	FormatMessageA(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_IGNORE_INSERTS,
		NULL, err, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), (char*)&buffer, 0, NULL);

	if (buffer)
	{
		// replace first CRLF with null terminator
		for (int i = 0; buffer && buffer[i]; ++i)
		{
			if (buffer[i] == '\r')
			{
				if (buffer[i + 1] == '\n')
				{
					buffer[i] = 0;
					break;
				}
			}
		}
		result = buffer;
		LocalFree(buffer);
	}
	else
	{
		result = "failed to get error code description";
	}

	return result;
}

DWORD SetPrivilege(HANDLE hToken, LPCTSTR lpszPrivilege, BOOL bEnablePrivilege)
{
	LUID luid;
	DWORD bRet = 0;

	if (LookupPrivilegeValue(NULL, lpszPrivilege, &luid))
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
		printf("[*] obtaining debug privilege\n");
		DWORD errCode = SetPrivilege(hToken, SE_DEBUG_NAME, TRUE);
		if (errCode != 0)
		{
			printf("\t[-] SetPrivilege failed: %s\n", GetLastErrorCodeDescriptionCstr());
		}
		else
		{
			puts("\t[+] success");
		}
		CloseHandle(hToken);
	}
}

DWORD GetProcIdByName(const char* pName)
{
	DWORD pid = 0;
	HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

	if (hSnap != INVALID_HANDLE_VALUE)
	{
		PROCESSENTRY32 procEntry = {};
		procEntry.dwSize = sizeof(procEntry);

		BOOL ret = Process32First(hSnap, &procEntry);
		while (ret)
		{
			if (!strcmp(pName, procEntry.szExeFile))
			{
				pid = procEntry.th32ProcessID;
				break;
			}
			ret = Process32Next(hSnap, &procEntry);
		}
	}
	CloseHandle(hSnap);
	return pid;
}

DWORD FindPid(const char* procName)
{
	DWORD pid = 0;
	printf("[*] searching for process '%s'...\n", procName);
	unsigned int ticks = 0;
	while (!pid)
	{
		if (ticks > 200)
		{
			// after approx 10 seconds
			printf("\t[-] unable to find target process\n");
			return -1;
		}
		pid = GetProcIdByName(procName);
		++ticks;
		Sleep(50);
	}
	printf("\t[+] found process. pid %d\n", pid);
	return pid;
}

int GetProcessBitness(HANDLE process)
{
	BOOL isWow64;
	if (!IsWow64Process(process, &isWow64))
	{
		printf("[-] IsWow64Process failed: %s\n", GetLastErrorCodeDescriptionCstr());
		return 0;
	}

	if (isWow64)
	{
		// 64-bit processor and 32-bit process
		return 32;
	}
	else
	{
		// process arch is same as processor arch
		SYSTEM_INFO sysInfo;
		GetNativeSystemInfo(&sysInfo);

		if (sysInfo.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_INTEL)
			return 32;
		else
			return 64;
	}

	return 0;
}
