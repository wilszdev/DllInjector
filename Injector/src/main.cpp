#include "Win32Helpers.h"
#include "injection.h"

#include <string>

bool IsNumber(const std::string& s);

int main(int argc, char** argv) {
	// validate args
	if (argc < 3) {
		printf("usage: %s <dll path> <process name (or pid)>\n", argv[0]);
		return 0;
	}

	// expands a relative path
	DWORD size = GetFullPathNameA(argv[1], 0, nullptr, nullptr);
	char* dllPath = new char[size];
	if (!GetFullPathNameA(argv[1], size, dllPath, nullptr))
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
		// find pid of target process
		pid = FindPid(procArgStr.c_str());
	}

	if (pid == -1) return -1; // unable to find process

	// do the stuff
	GetDebugPrivilege();
	//LoadLibraryInject(dllPath, pid);
	ManualMappingInject(dllPath, pid);

	// free memory
	delete[] dllPath;

	return 0;
}

bool IsNumber(const std::string& s)
{
	return !s.empty() && std::find_if(s.begin(),
		s.end(), [](unsigned char c) { return !std::isdigit(c); }) == s.end();
}