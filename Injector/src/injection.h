#pragma once
#define TARGET_SELF 0
#include "Win32Helpers.h"

void LoadLibraryInject(const char* dllPath, DWORD procId);

void ManualMappingInject(const char* dllPath, DWORD pid);

using LoadLibraryASignature = HINSTANCE(WINAPI*)(const char* filename);
using GetProcAddressSignature = UINT_PTR(WINAPI*)(HINSTANCE module, const char* procName);
using DllEntryPointSignature = BOOL(WINAPI*)(void* dll, DWORD reason, void* reserved);

struct ManualMappingInfo
{
	// passing LoadLibraryA and GetProcAddress
	// like this only works because these
	// functions are in Kernel32.dll, which is
	// imported once and shared system-wide
	// (so the ptrs will still be valid in the remote thread)
	LoadLibraryASignature LoadLibraryA;
	GetProcAddressSignature GetProcAddress;
	HINSTANCE dllInstance;
};

void __stdcall Loader(ManualMappingInfo* info);