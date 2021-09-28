#include "injection.h"
#include <cstdio>

void LoadLibraryInject(const char* dllPath, DWORD pid)
{
	HANDLE process = 0, thread = 0;
	DWORD exitCode = 0;

	// open the process
	printf("[*] opening process with pid %d...\n", pid);
	process = OpenProcess(PROCESS_ALL_ACCESS, 0, pid);
	if (!process || process == INVALID_HANDLE_VALUE)
	{
		printf("\t[-] OpenProcess failed: %s\n", GetLastErrorCodeDescriptionCstr());
		return;
	}

	// allocate some memory
	printf("[*] allocating memory in process...\n");
	void* loc = VirtualAllocEx(process, 0, MAX_PATH, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (!loc)
	{
		printf("\t[-] VirtualAllocEx failed: %s\n", GetLastErrorCodeDescriptionCstr());
		goto cleanup;
	}

	// write the dll path
	printf("[*] writing dll path into memory...\n");
	if (WriteProcessMemory(process, loc, dllPath, strlen(dllPath) + 1, 0) == 0)
	{
		printf("\t[-] WriteProcessMemory failed: %s\n", GetLastErrorCodeDescriptionCstr());
		goto cleanup;
	}

	// create remote thread
	printf("[*] creating remote thread...\n");
	thread = CreateRemoteThread(process, 0, 0, (LPTHREAD_START_ROUTINE)LoadLibraryA, loc, 0, 0);
	if (!thread)
	{
		printf("\t[-] CreateRemoteThread failed: %s\n", GetLastErrorCodeDescriptionCstr());
		goto cleanup;
	}

	// wait for it to finish
	printf("[*] Loading DLL...\n");
	WaitForSingleObject(thread, INFINITE);

	if (!GetExitCodeThread(thread, &exitCode))
	{
		puts("\t[-] failed to get exit code of injection thread");
	}

	// if LoadLibrary returns 0 (NULL), then it failed to load the module
	if (exitCode == 0)
	{
		puts("\t[-] failed :(");
	}
	else
	{
		puts("\t[+] success :)");
	}

cleanup:
	if (process)
	{
		CloseHandle(process);
	}
	if (thread)
	{
		CloseHandle(thread);
	}
}

#define SHARED_FILE_MAPPING_NAME "SomeRandomNameLolz"
void ManualMappingInject(const char* dllPath, DWORD pid)
{
	printf("[*] opening process with pid %d...\n", pid);
	HANDLE process = OpenProcess(PROCESS_ALL_ACCESS, 0, pid);
	if (!process)
	{
		printf("\t[-] OpenProcess failed: %s\n", GetLastErrorCodeDescriptionCstr());
		return;
	}

	puts("[*] loading dll from disk");
	if (GetFileAttributesA(dllPath) == INVALID_FILE_ATTRIBUTES)
	{
		printf("\t[-] GetFileAttributes failed: %s\n", GetLastErrorCodeDescriptionCstr());
		return;
	}

	HANDLE file = CreateFileA(dllPath, GENERIC_READ, 0, 0, OPEN_EXISTING, 0, 0);
	if (file == INVALID_HANDLE_VALUE)
	{
		printf("\t[-] CreateFile failed: %s\n", GetLastErrorCodeDescriptionCstr());
		return;
	}

	DWORD fileSize = GetFileSize(file, 0);
	// the file headers are on the first page
	// so if the file the file is smaller than one page,
	// it can't possibly be a valid PE file.
	if (fileSize < 0x1000)
	{
		puts("\t[-] invalid file: headers less than 4096 bytes");
		CloseHandle(file);
		return;
	}

	BYTE* srcData = (BYTE*)VirtualAlloc(0, fileSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (!srcData)
	{
		printf("\t[-] VirtualAlloc failed: %s\n", GetLastErrorCodeDescriptionCstr());
		return;
	}

	if (!ReadFile(file, srcData, fileSize, 0, 0))
	{
		printf("\t[-] ReadFile failed: %s\n", GetLastErrorCodeDescriptionCstr());
		return;
	}

	CloseHandle(file);

	// validate image (check magic number)
	IMAGE_DOS_HEADER* dosHeader = reinterpret_cast<IMAGE_DOS_HEADER*>(srcData);
	if (dosHeader->e_magic != 0x5A4D)
	{
		puts("\t[-] invalid PE header");
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
		puts("\t[-] invalid architecture");
		VirtualFree(srcData, 0, MEM_RELEASE);
		return;
	}

	puts("[*] mapping dll into target process");
	// allocate memory in the target process
	// use the preferred base address of the image if possible
	BYTE* dstData = (BYTE*)VirtualAllocEx(process, (void*)optHeader->ImageBase, optHeader->SizeOfImage,
		MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if (!dstData)
	{
		printf("\t[-] VirtualAllocEx (1) failed: %s\n", GetLastErrorCodeDescriptionCstr());
		// try again, not providing an image base
		dstData = (BYTE*)VirtualAllocEx(process, 0, optHeader->SizeOfImage,
			MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
		if (!dstData)
		{
			printf("\t[-] VirtualAllocEx (2) failed: %s\n", GetLastErrorCodeDescriptionCstr());
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
				printf("\t[-] WriteProcessMemory failed: %s\n", GetLastErrorCodeDescriptionCstr());
				VirtualFree(srcData, 0, MEM_RELEASE);
				VirtualFreeEx(process, dstData, 0, MEM_RELEASE);
				return;
			}
		}
	}

	// store the ManualMappingInfo in the header (since we wont need the header anymore)
	memcpy(srcData, &mmi, sizeof(mmi));

	// write headers into memory
	if (!WriteProcessMemory(process, dstData, srcData, 0x1000, 0))
	{
		printf("\t[-] WriteProcessMemory failed: %s\n", GetLastErrorCodeDescriptionCstr());
		VirtualFreeEx(process, dstData, 0, MEM_RELEASE);
		return;
	}

	VirtualFree(srcData, 0, MEM_RELEASE);

	puts("[*] writing loader shellcode into target process");
	// allocate one page of memory for the shellcode
	size_t shellcodeSize = 0x1000;
	void* shellcode = VirtualAllocEx(process, 0, shellcodeSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if (!shellcode)
	{
		printf("\t[-] VirtualAllocEx failed: %s\n", GetLastErrorCodeDescriptionCstr());
		VirtualFreeEx(process, dstData, 0, MEM_RELEASE);
		return;
	}

	// write Loader shellcode into process memory (plus some extra, probably)
	if (!WriteProcessMemory(process, shellcode, Loader, shellcodeSize, 0))
	{
		printf("\t[-] WriteProcessMemory failed: %s\n", GetLastErrorCodeDescriptionCstr());
		VirtualFreeEx(process, dstData, 0, MEM_RELEASE);
		VirtualFreeEx(process, shellcode, 0, MEM_RELEASE);
		return;
	}

	puts("[*] creating remote thread in target process");
	HANDLE remoteThread = CreateRemoteThread(process, 0, 0,
		// our loader technically has a different signature,
		// but this is just so we dont need to do a bunch
		// of casting. this way, the values are casted for us (in effect)
#if TARGET_SELF
		reinterpret_cast<LPTHREAD_START_ROUTINE>(Loader),
#else
		reinterpret_cast<LPTHREAD_START_ROUTINE>(shellcode),
#endif
		dstData, 0, 0);
	if (!remoteThread || remoteThread == INVALID_HANDLE_VALUE)
	{
		printf("\t[-] CreateRemoteThread failed: %s\n", GetLastErrorCodeDescriptionCstr());
		VirtualFreeEx(process, dstData, 0, MEM_RELEASE);
		VirtualFreeEx(process, shellcode, 0, MEM_RELEASE);
		return;
	}

	puts("[*] Loading DLL...");
	WaitForSingleObject(remoteThread, INFINITE);
	CloseHandle(remoteThread);

	ManualMappingInfo mmiCheck = {};
	ReadProcessMemory(process, dstData, &mmiCheck, sizeof(mmiCheck), 0);

	// can free the shellcode now
	VirtualFreeEx(process, shellcode, 0, MEM_RELEASE);

	if (mmiCheck.dllInstance)
	{
		puts("\t[+] success :)");
	}
	else
	{
		puts("\t[-] failed :(");
	}
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