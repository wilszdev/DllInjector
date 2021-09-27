#pragma once
#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#include <TlHelp32.h>

#include <cstdio>

void PrintError(const char* myMsg, DWORD err = -1);
DWORD SetPrivilege(HANDLE hToken, LPCTSTR lpszPrivilege, BOOL bEnablePrivilege);
void GetDebugPrivilege();
DWORD GetProcIdByName(const char* pName);
DWORD FindPid(const char* procName);

