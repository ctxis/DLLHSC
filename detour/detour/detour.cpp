#include <windows.h>
#include <stdio.h>
#include "detours.h"
#include "utility.h"

#ifdef _WIN32
#pragma comment(lib, "lib.X86/detours.lib")
#endif

#ifdef _WIN64
#pragma comment(lib, "lib.X64/detours.lib")
#endif

#define DllExport __declspec(dllexport)

DllExport void CALLBACK DetourFinishHelperProcess() {}

HMODULE(WINAPI* True_LoadLibraryA)(LPCSTR) = LoadLibraryA;
HMODULE(WINAPI* True_LoadLibraryExA)(LPCSTR, HANDLE, DWORD) = LoadLibraryExA;
HMODULE(WINAPI* True_LoadLibraryW)(LPCWSTR) = LoadLibraryW;
HMODULE(WINAPI* True_LoadLibraryExW)(LPCWSTR, HANDLE, DWORD) = LoadLibraryExW;

HANDLE mutex = INVALID_HANDLE_VALUE;
HANDLE hFile = INVALID_HANDLE_VALUE;

int CreateRTLog(LPCSTR lpbuffer)
{
	if (hFile == INVALID_HANDLE_VALUE)
	{
		return 1;
	}

	DWORD dwMove = SetFilePointer(hFile, 1, NULL, FILE_END);
	if (dwMove == INVALID_SET_FILE_POINTER)
	{
		return 1;
	}

	CHAR* tmp = new CHAR[strlen(lpbuffer)+2];
	for (unsigned int i = 0; i < strlen(lpbuffer); i++)
	{
		tmp[i] = lpbuffer[i];
	}
	tmp[strlen(lpbuffer)] = '\n';
	tmp[strlen(lpbuffer)+1] = '\0';

	DWORD nCharWritten = 0;
	
	BOOL writestatus = WriteFile(hFile, tmp, strlen(tmp), &nCharWritten, NULL);
	if (writestatus)
	{
		return 1;
	}
	delete[]tmp;

	return 0;
}

int CreateRTLogW(LPCWSTR lpbuffer)
{
	if (hFile == INVALID_HANDLE_VALUE)
	{
		return 1;
	}

	DWORD dwMove = SetFilePointer(hFile, 1, NULL, FILE_END);
	if (dwMove == INVALID_SET_FILE_POINTER)
	{
		return 1;
	}

	DWORD pathlen = WideCharToMultiByte(CP_UTF8, 0, lpbuffer, -1, NULL, 0, NULL, NULL);
	CHAR* lpbufferA = new CHAR[pathlen];
	WideCharToMultiByte(CP_UTF8, 0, lpbuffer, -1, lpbufferA, pathlen, NULL, NULL);

	CHAR* tmp = new CHAR[pathlen + 1];
	unsigned int i = 0;
	while (lpbufferA[i] != '\0')
	{
		tmp[i] = lpbufferA[i];
		i++;
	}
	tmp[i] = '\n';
	tmp[i + 1] = '\0';

	DWORD nCharWritten = 0;
	BOOL writestatus = WriteFile(hFile, tmp, strlen(tmp), &nCharWritten, NULL);
	if (writestatus)
	{
		return 1;
	}
	delete[]tmp;

	return 0;
}

HMODULE WINAPI HookedLoadLibraryA(LPCSTR lpLibFileName)
{
	DWORD wait = WaitForSingleObject(mutex, INFINITE);
	if (wait == WAIT_OBJECT_0)
	{
		CreateRTLog(lpLibFileName);
		ReleaseMutex(mutex);
	}
	return True_LoadLibraryA(lpLibFileName);
}

HMODULE WINAPI HookedLoadLibraryExA(LPCSTR lpFileName, HANDLE hFile, DWORD dwFlags)
{
	DWORD wait = WaitForSingleObject(mutex, INFINITE);
	if ((wait == WAIT_OBJECT_0) && (dwFlags != 0x800))
	{
		CreateRTLog(lpFileName);
		ReleaseMutex(mutex);
	}
	return True_LoadLibraryExA(lpFileName, hFile, dwFlags);
}

HMODULE WINAPI HookedLoadLibraryW(LPCWSTR lpLibFileName)
{
	DWORD wait = WaitForSingleObject(mutex, INFINITE);
	if (wait == WAIT_OBJECT_0)
	{
		CreateRTLogW(lpLibFileName);
		ReleaseMutex(mutex);
	}
	return True_LoadLibraryW(lpLibFileName);
}

HMODULE WINAPI HookedLoadLibraryExW(LPCWSTR lpLibFileName, HANDLE hFile, DWORD dwFlags)
{
	DWORD wait = WaitForSingleObject(mutex, INFINITE);
	if ((wait == WAIT_OBJECT_0) && (dwFlags != 0x800))
	{
		CreateRTLogW(lpLibFileName);
		ReleaseMutex(mutex);
	}
	return True_LoadLibraryExW(lpLibFileName, hFile, dwFlags);
}

BOOL WINAPI DllMain(HINSTANCE hInstance, DWORD dwReason, LPVOID p)
{
	switch (dwReason)
	{
		case DLL_PROCESS_ATTACH:
		{
			CHAR logfilename[] = "DLLHSCRTLOG.tmp";
			mutex = CreateMutexW(NULL, false, L"SecWrite1234");
			hFile = CreateFileA(PopulatePoCPath(logfilename), FILE_APPEND_DATA, 0x1, NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);

			DetourRestoreAfterWith();
			DetourTransactionBegin();
			DetourUpdateThread(GetCurrentThread());
			DetourAttach(&(PVOID&)True_LoadLibraryA, HookedLoadLibraryA);
			DetourAttach(&(PVOID&)True_LoadLibraryExA, HookedLoadLibraryExA);
			DetourAttach(&(PVOID&)True_LoadLibraryW, HookedLoadLibraryW);
			DetourAttach(&(PVOID&)True_LoadLibraryExW, HookedLoadLibraryExW);

			LONG lError = DetourTransactionCommit();
			if (lError != NO_ERROR)
			{
				return FALSE;
			}
		}
		break;
		case DLL_PROCESS_DETACH:
		{
			DetourRestoreAfterWith();
			DetourTransactionBegin();
			DetourUpdateThread(GetCurrentThread());
			DetourAttach(&(PVOID&)True_LoadLibraryA, HookedLoadLibraryA);
			DetourAttach(&(PVOID&)True_LoadLibraryExA, HookedLoadLibraryExA);
			DetourAttach(&(PVOID&)True_LoadLibraryW, HookedLoadLibraryW);
			DetourAttach(&(PVOID&)True_LoadLibraryExW, HookedLoadLibraryExW);

			LONG lError = DetourTransactionCommit();
			if (lError != NO_ERROR)
			{
				return FALSE;
			}
			CloseHandle(hFile);
		}
		break;
	}
	return TRUE;
}