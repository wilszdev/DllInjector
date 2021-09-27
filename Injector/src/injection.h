#pragma once
#include "Win32Helpers.h"

void LoadLibraryInject(const char* dllPath, DWORD procId);

void ManualMappingInject(const char* dllPath, DWORD pid);

using LoadLibraryASignature		= HINSTANCE(WINAPI*)(const char* filename);
using GetProcAddressSignature	= UINT_PTR(WINAPI*)(HINSTANCE module, const char* procName);
using DllEntryPointSignature	= BOOL(WINAPI*)(void* dll, DWORD reason, void* reserved);

struct ManualMappingInfo
{
	LoadLibraryASignature LoadLibraryA;
	GetProcAddressSignature GetProcAddress;
	HINSTANCE dllInstance;
};

void __stdcall Loader(ManualMappingInfo* info);