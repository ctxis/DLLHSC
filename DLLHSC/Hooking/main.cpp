#pragma once
#include <windows.h>
#include <stdio.h>
#include "..\DLLHSC\detours.h"
#include "..\DLLHSC\utility.h"

#ifdef _WIN32
#pragma comment(lib, "..\\DLLHSC\\lib.X86\\detours.lib")
#endif

#ifdef _WIN64
#pragma comment(lib, "..\\DLLHSC\\lib.X64\\detours.lib")
#endif

__declspec(dllexport) VOID CALLBACK DetourFinishHelperProcess() {}

HMODULE(WINAPI* LoadLibraryADelegate)(LPCSTR) = LoadLibraryA;
HMODULE(WINAPI* LoadLibraryExADelegate)(LPCSTR, HANDLE, DWORD) = LoadLibraryExA;
HMODULE(WINAPI* LoadLibraryWDelegate)(LPCWSTR) = LoadLibraryW;
HMODULE(WINAPI* LoadLibraryExWDelegate)(LPCWSTR, HANDLE, DWORD) = LoadLibraryExW;

HANDLE g_hMutex = INVALID_HANDLE_VALUE;
HANDLE g_hFile = INVALID_HANDLE_VALUE;

BOOL CreateRTLog(LPCSTR lpBuffer)
{
	if (g_hFile == INVALID_HANDLE_VALUE)
		return FALSE;

	DWORD dwMove = ::SetFilePointer(g_hFile, 1, NULL, FILE_END);
	if (dwMove == INVALID_SET_FILE_POINTER)
		return FALSE;

	PCHAR tmp = new CHAR[strlen(lpBuffer) + 2];
	::strcpy_s(tmp, strlen(lpBuffer) + 2, lpBuffer);
	::strcat_s(tmp, strlen(lpBuffer) + 2, "\n\0");

	DWORD dwCharWritten = 0;
	BOOL writestatus = ::WriteFile(g_hFile, tmp, (DWORD)strlen(tmp), &dwCharWritten, NULL);
	
	delete[] tmp;
	return writestatus;
}

BOOL CreateRTLogW(LPCWSTR lpBuffer)
{
	DWORD dwPathLen = ::WideCharToMultiByte(CP_UTF8, 0, lpBuffer, -1, NULL, 0, NULL, NULL);
	PCHAR lpBufferA = new CHAR[dwPathLen];
	WideCharToMultiByte(CP_UTF8, 0, lpBuffer, -1, lpBufferA, dwPathLen, NULL, NULL);

	return CreateRTLog(lpBufferA);
}

HMODULE WINAPI HookedLoadLibraryA(LPCSTR lpLibFileName)
{
	DWORD dwWait = ::WaitForSingleObject(g_hMutex, INFINITE);
	if (dwWait == WAIT_OBJECT_0)
	{
		CreateRTLog(lpLibFileName);
		::ReleaseMutex(g_hMutex);
	}
	return LoadLibraryADelegate(lpLibFileName);
}

HMODULE WINAPI HookedLoadLibraryExA(LPCSTR lpFileName, HANDLE hFile, DWORD dwFlags)
{
	DWORD dwWait = ::WaitForSingleObject(g_hMutex, INFINITE);
	if ((dwWait == WAIT_OBJECT_0) && (dwFlags != 0x800))
	{
		CreateRTLog(lpFileName);
		::ReleaseMutex(g_hMutex);
	}
	return LoadLibraryExADelegate(lpFileName, hFile, dwFlags);
}

HMODULE WINAPI HookedLoadLibraryW(LPCWSTR lpLibFileName)
{
	DWORD dwWait = ::WaitForSingleObject(g_hMutex, INFINITE);
	if (dwWait == WAIT_OBJECT_0)
	{
		CreateRTLogW(lpLibFileName);
		::ReleaseMutex(g_hMutex);
	}
	return LoadLibraryWDelegate(lpLibFileName);
}

HMODULE WINAPI HookedLoadLibraryExW(LPCWSTR lpLibFileName, HANDLE hFile, DWORD dwFlags)
{
	DWORD dwWait = ::WaitForSingleObject(g_hMutex, INFINITE);
	if ((dwWait == WAIT_OBJECT_0) && (dwFlags != 0x800))
	{
		CreateRTLogW(lpLibFileName);
		::ReleaseMutex(g_hMutex);
	}
	return LoadLibraryExWDelegate(lpLibFileName, hFile, dwFlags);
}

BOOL WINAPI DllMain(HINSTANCE hInstance, DWORD dwReason, LPVOID p)
{
	UNREFERENCED_PARAMETER(hInstance);
	UNREFERENCED_PARAMETER(p);

	switch (dwReason)
	{
	case DLL_PROCESS_ATTACH:
	{
		CHAR logfilename[] = "DLLHSCRTLOG.tmp";
		g_hMutex = ::CreateMutexW(NULL, false, L"SecWrite1234");
		g_hFile = ::CreateFileA(PopulatePoCPath(logfilename), FILE_APPEND_DATA, 0x1, NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);

		::DetourRestoreAfterWith();
		::DetourTransactionBegin();
		::DetourUpdateThread(GetCurrentThread());
		::DetourAttach(&(PVOID&)LoadLibraryADelegate, HookedLoadLibraryA);
		::DetourAttach(&(PVOID&)LoadLibraryExADelegate, HookedLoadLibraryExA);
		::DetourAttach(&(PVOID&)LoadLibraryWDelegate, HookedLoadLibraryW);
		::DetourAttach(&(PVOID&)LoadLibraryExWDelegate, HookedLoadLibraryExW);

		LONG lError = ::DetourTransactionCommit();
		if (lError != NO_ERROR)
			return FALSE;
		break;
	}
	case DLL_PROCESS_DETACH:
	{
		::DetourRestoreAfterWith();
		::DetourTransactionBegin();
		::DetourUpdateThread(GetCurrentThread());
		::DetourAttach(&(PVOID&)LoadLibraryADelegate, HookedLoadLibraryA);
		::DetourAttach(&(PVOID&)LoadLibraryExADelegate, HookedLoadLibraryExA);
		::DetourAttach(&(PVOID&)LoadLibraryWDelegate, HookedLoadLibraryW);
		::DetourAttach(&(PVOID&)LoadLibraryExWDelegate, HookedLoadLibraryExW);

		LONG lError = ::DetourTransactionCommit();
		if (lError != NO_ERROR)
			return FALSE;
		::CloseHandle(g_hFile);
		break;
	}
	}
	return TRUE;
}