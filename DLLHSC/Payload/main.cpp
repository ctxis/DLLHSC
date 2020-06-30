#include <windows.h>
#include <stdio.h>

__declspec(dllexport) BOOL __stdcall poc_write()
{
	// create a logfile in user's temp
	// this file will be used as a proof of payload execution

	PCHAR lpBuffer = new CHAR[MAX_PATH];
	if (::GetTempPathA(MAX_PATH, lpBuffer) != 0)
		return FALSE;

	CHAR szLogFilename[11] = "DLLHSC.tmp";
	SIZE_T numberofelements = ::strlen(lpBuffer) + ::strlen(szLogFilename) + 1;
	PCHAR szLogFilePath = new CHAR[numberofelements];
	::strcpy_s(szLogFilePath, numberofelements, lpBuffer);
	::strcat_s(szLogFilePath, numberofelements, szLogFilename);

	HANDLE hFile = ::CreateFileA(
		szLogFilePath,
		GENERIC_ALL,
		FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
		NULL,
		CREATE_NEW,
		FILE_ATTRIBUTE_NORMAL,
		NULL
	);

	if (hFile == INVALID_HANDLE_VALUE)
		return FALSE;

	::CloseHandle(hFile);
	return TRUE;
}

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpReserved)
{
	UNREFERENCED_PARAMETER(hinstDLL);
	UNREFERENCED_PARAMETER(lpReserved);

	switch (fdwReason)
	{
	case DLL_PROCESS_ATTACH:
		poc_write();
		break;
	case DLL_THREAD_ATTACH:
	case DLL_PROCESS_DETACH:
	case DLL_THREAD_DETACH:
		break;
	}

	return TRUE;
}
