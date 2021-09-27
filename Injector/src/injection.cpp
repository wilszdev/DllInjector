#include "injection.h"

#include <iostream>
#include <fstream>

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

	if (GetFileAttributesA(dllPath) == INVALID_FILE_ATTRIBUTES)
	{
		// file doesnt exist
		return;
	}

	HANDLE file = CreateFileA(dllPath, GENERIC_READ, 0, 0, OPEN_EXISTING, 0, 0);
	if (file == INVALID_HANDLE_VALUE)
	{
		return;
	}

	DWORD size = GetFileSize(file, 0);
	if (size < 0x1000)
	{
		CloseHandle(file);
		return;
	}

	BYTE* srcData = (BYTE*)VirtualAlloc(0, size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (!srcData)
	{
		return;
	}

	if (!ReadFile(file, srcData, size, 0, 0))
	{
		return;
	}

	CloseHandle(file);

	// validate image (check magic number)
	IMAGE_DOS_HEADER* dosHeader = reinterpret_cast<IMAGE_DOS_HEADER*>(srcData);
	if (dosHeader->e_magic != 0x5A4D)
	{
		VirtualFree(srcData, 0, MEM_RELEASE);
		return;
	}

	IMAGE_NT_HEADERS* ntHeader = reinterpret_cast<IMAGE_NT_HEADERS*>(srcData + dosHeader->e_lfanew);
	IMAGE_OPTIONAL_HEADER* optHeader = &ntHeader->OptionalHeader;
	IMAGE_FILE_HEADER* fileHeader = &ntHeader->FileHeader;

	// validate platform
	if (fileHeader->Machine !=
#ifdef _WIN64
		// should be x64 image
		IMAGE_FILE_MACHINE_AMD64)
#else
		// should be x86 image
		IMAGE_FILE_MACHINE_I386)
#endif
	{
		VirtualFree(srcData, 0, MEM_RELEASE);
		return;
	}

	// allocate memory in the target process
	// use the preferred base address of the image if possible
	BYTE* dstData = (BYTE*)VirtualAllocEx(process, (void*)optHeader->ImageBase, optHeader->SizeOfImage,
		MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if (!dstData)
	{
		// try again, not providing an image base
		dstData = (BYTE*)VirtualAllocEx(process, 0, optHeader->SizeOfImage,
			MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
		if (!dstData)
		{
			VirtualFree(srcData, 0, MEM_RELEASE);
			return;
		}
	}

	ManualMappingInfo mmi = {};
	mmi.LoadLibraryA = LoadLibraryA;
	mmi.GetProcAddress = reinterpret_cast<GetProcAddressSignature>(GetProcAddress);

	// map sections into memory
	IMAGE_SECTION_HEADER* sectionHeader = IMAGE_FIRST_SECTION(ntHeader);
	for (int i = 0; i < fileHeader->NumberOfSections; ++i, ++sectionHeader)
	{
		if (sectionHeader->SizeOfRawData)
		{
			if (!WriteProcessMemory(process, dstData + sectionHeader->VirtualAddress,
				srcData + sectionHeader->PointerToRawData, sectionHeader->SizeOfRawData, 0))
			{
				// failed
				VirtualFree(srcData, 0, MEM_RELEASE);
				VirtualFreeEx(process, dstData, 0, MEM_RELEASE);
				return;
			}
		}
	}

	// store the ManualMappingInfo in the header (since we wont need the header anymore)
	memcpy(srcData, &mmi, sizeof(mmi));

	// copy headers into target process memory
	if (!WriteProcessMemory(process, dstData, srcData, 0x1000, 0))
	{
		VirtualFreeEx(process, dstData, 0, MEM_RELEASE);
		return;
	}

	VirtualFree(srcData, 0, MEM_RELEASE);

	// allocate one page of memory for the shellcode
	void* shellcode = VirtualAllocEx(process, 0, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if (!shellcode)
	{
		VirtualFreeEx(process, dstData, 0, MEM_RELEASE);
		return;
	}

	// write Loader shellcode into process memory (plus some extra, probably)
	if (!WriteProcessMemory(process, shellcode, Loader, 0x1000, 0))
	{
		VirtualFreeEx(process, dstData, 0, MEM_RELEASE);
		VirtualFreeEx(process, shellcode, 0, MEM_RELEASE);
		return;
	}

	HANDLE remoteThread = CreateRemoteThread(process, 0, 0,
			// our loader technically has a different signature,
			// but this is just so we dont need to do a bunch
			// of casting. this way, the values are casted for us (in effect)
			reinterpret_cast<LPTHREAD_START_ROUTINE>(shellcode),
			dstData, 0, 0);
	if (!remoteThread || remoteThread == INVALID_HANDLE_VALUE)
	{
		PrintError("CreateRemoteThread failed", GetLastError());
		VirtualFreeEx(process, dstData, 0, MEM_RELEASE);
		VirtualFreeEx(process, shellcode, 0, MEM_RELEASE);
		return;
	}

	CloseHandle(remoteThread);

	// spinlock until the loader has finished
	HINSTANCE injectedThread = 0;
	while (!injectedThread)
	{
		ManualMappingInfo mmiCheck = {};
		ReadProcessMemory(process, dstData, &mmiCheck, sizeof(mmiCheck), 0);
		injectedThread = mmiCheck.dllInstance;
		Sleep(10);
	}

	// can free the shellcode now
	VirtualFreeEx(process, shellcode, 0, MEM_RELEASE);

	puts("[+] success");
}

/* Loader
* this will be written into the target process (i.e. as shellcode)
* it is responsible for:
*		- relocation
*		- resolving imports
*		- calling TLS callbacks
*		- calling DllMain
*/
void __stdcall Loader(ManualMappingInfo* info)
{
	if (!info) return;
	BYTE* imageBase = reinterpret_cast<BYTE*>(info); // because the info is stored at the image base

	// because we only overwrote the very beginning of the headers, should still be able to find the location of the optional header
	IMAGE_OPTIONAL_HEADER* optionalHeader = &reinterpret_cast<IMAGE_NT_HEADERS*>(
		imageBase + reinterpret_cast<IMAGE_DOS_HEADER*>(info)->e_lfanew)->OptionalHeader;

	auto dllMain = reinterpret_cast<DllEntryPointSignature>(imageBase + optionalHeader->AddressOfEntryPoint);

	// relocation
	BYTE* locationDelta = imageBase - optionalHeader->ImageBase;
	if (locationDelta)
	{
		if (!optionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size)
			return;
		IMAGE_BASE_RELOCATION* relocData = reinterpret_cast<IMAGE_BASE_RELOCATION*>(
			imageBase + optionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);
		while (relocData->VirtualAddress)
		{
			int numEntries = (relocData->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
			WORD* relativeInfo = reinterpret_cast<WORD*>(relocData + 1);

			// apply patches at all entries
			for (int i = 0; i < numEntries; ++i, ++relativeInfo)
			{
				// type is given by the high 4 bits
				BYTE relocationType = (*relativeInfo >> 12);
				if (relocationType ==
#ifdef _WIN64
					IMAGE_REL_BASED_DIR64
#else
					IMAGE_REL_BASED_HIGHLOW
#endif
					)
				{
					// offset is given by the low 12 bits
					int patchOffset = *relativeInfo & 0xFFF;
					UINT_PTR* patch = reinterpret_cast<UINT_PTR*>(imageBase +
						relocData->VirtualAddress + relocationType);
					*patch += reinterpret_cast<UINT_PTR>(locationDelta);
				}
			}

			// advance to next base relocation data block
			relocData = reinterpret_cast<IMAGE_BASE_RELOCATION*>(
				reinterpret_cast<BYTE*>(relocData) + relocData->SizeOfBlock);
		}
	}

	// resolve imports
	if (optionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size)
	{
		IMAGE_IMPORT_DESCRIPTOR* importDesc = reinterpret_cast<IMAGE_IMPORT_DESCRIPTOR*>(
			imageBase + optionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
		for (; importDesc->Name; ++importDesc)
		{
			char* importedModule = reinterpret_cast<char*>(imageBase + importDesc->Name);
			HINSTANCE module = info->LoadLibraryA(importedModule);

			ULONG_PTR* thunkRef = reinterpret_cast<ULONG_PTR*>(imageBase + importDesc->OriginalFirstThunk);
			ULONG_PTR* funcRef = reinterpret_cast<ULONG_PTR*>(imageBase + importDesc->FirstThunk);

			if (!thunkRef)
				thunkRef = funcRef;

			for (; *thunkRef; ++thunkRef, ++funcRef)
			{
				if (IMAGE_SNAP_BY_ORDINAL(*thunkRef))
				{
					*funcRef = info->GetProcAddress(module, reinterpret_cast<char*>(*thunkRef & 0xFFFF));
				}
				else
				{
					// import by name
					IMAGE_IMPORT_BY_NAME* import = reinterpret_cast<IMAGE_IMPORT_BY_NAME*>(imageBase + (*thunkRef));
					*funcRef = info->GetProcAddress(module, import->Name);
				}
			}
		}
	}

	// tls callbacks
	if (optionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].Size)
	{
		IMAGE_TLS_DIRECTORY* tls = reinterpret_cast<IMAGE_TLS_DIRECTORY*>(
			imageBase + optionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress);
		PIMAGE_TLS_CALLBACK* callback = reinterpret_cast<PIMAGE_TLS_CALLBACK*>(tls->AddressOfCallBacks);
		for (; callback && *callback; ++callback)
			(*callback)(imageBase, DLL_PROCESS_ATTACH, 0);
	}

	dllMain(imageBase, DLL_PROCESS_ATTACH, 0);

	info->dllInstance = reinterpret_cast<HINSTANCE>(imageBase);
}