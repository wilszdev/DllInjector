#pragma once
#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#include <TlHelp32.h>
#include <cstdio>

void PrintError(const char* myMsg, DWORD err);
DWORD SetPrivilege(HANDLE hToken, LPCTSTR lpszPrivilege, BOOL bEnablePrivilege);
void GetDebugPrivilege();
DWORD GetProcIdByName(const char* pName);
DWORD FindPid(const char* procName);


void PrintError(const char* myMsg, DWORD err = -1)
{
	if (err == -1)
	{
		//err = GetLastError();
		printf(" [-] %s.", myMsg);
		return;
	}
	char* msgBuf = nullptr;
	FormatMessage(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_IGNORE_INSERTS, NULL, err, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), (char*)&msgBuf, 0, NULL);
	printf(" [-] %s. err: %d %s", myMsg, err, msgBuf);
	LocalFree(msgBuf);
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

DWORD GetProcIdByName(const char* pName)
{
	DWORD procId = 0;
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
				procId = procEntry.th32ProcessID;
				break;
			}
			ret = Process32Next(hSnap, &procEntry);
		}
	}
	CloseHandle(hSnap);
	return procId;
}

DWORD FindPid(const char* procName)
{
	DWORD procId = 0;
	printf("[*] searching for process '%s'...\n", procName);
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
