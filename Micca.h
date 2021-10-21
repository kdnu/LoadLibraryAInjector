#pragma once
#include <Windows.h>
#include <TlHelp32.h>

namespace Injector
{
	DWORD GetProcessID(const char* processName)
	{
		if (!processName)
			return 0;

		DWORD id = 0;
		HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

		if (hSnap)
		{
			PROCESSENTRY32 pe32 = { sizeof(PROCESSENTRY32) };
			if (Process32First(hSnap, &pe32))
			{
				while (Process32Next(hSnap, &pe32))
				{
					if (strcmp(processName, pe32.szExeFile) == 0)
					{
						id = pe32.th32ProcessID;
						break;
					}
				}
			}
		}CloseHandle(hSnap);
		return id;
	}


	bool Inject(const char* processName, const char* DllPath)
	{
		if (!processName || !DllPath)
			return false;

		DWORD processID = 0;
		do
			processID = GetProcessID(processName);
		while (processID == 0);

		HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, 0, processID);
		if (hProcess != INVALID_HANDLE_VALUE)
		{
			void* allocated = VirtualAllocEx(hProcess, 0, MAX_PATH, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
			if (!WriteProcessMemory(hProcess, allocated, DllPath, strlen(DllPath) + '\0', 0))
			{
				CloseHandle(hProcess);
				return false;
			}
			void* hThread = CreateRemoteThread(hProcess, 0, 0, (PTHREAD_START_ROUTINE)LoadLibraryA, allocated, 0, 0);

			if (hThread != 0)
				CloseHandle(hThread);
		}
		CloseHandle(hProcess);
		return true;
	}
}
