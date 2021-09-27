#pragma once
#include "Win32Helpers.hpp"

void LoadLibraryInject(const char* dllPath, DWORD procId);

void ManualMappingInject(const char* dllPath, DWORD pid);
