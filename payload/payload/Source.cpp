#include <windows.h>
#include <stdio.h>

#define DllExport __declspec(dllexport)

DllExport int __stdcall poc_write()
{
	// create a logfile in user's temp
	// this file will be used as a proof of payload execution

	CHAR* lpBuffer = new CHAR[MAX_PATH];
	lpBuffer[MAX_PATH - 1] = '\0';

	DWORD len = GetTempPathA(MAX_PATH, lpBuffer);
	if (!len)
	{
		//printf("[-] GetTempPathA has failed: %d\n", GetLastError());
		exit(1);
	}

	CHAR logfilename[11] = "DLLHSC.tmp";
	size_t numberofelements = strlen(lpBuffer) + strlen(logfilename) + 1;
	CHAR* logfilepath = new CHAR[numberofelements];
	strcpy_s(logfilepath, numberofelements, lpBuffer);
	strcat_s(logfilepath, numberofelements, logfilename);

	HANDLE hFile = CreateFileA(
		logfilepath,
		GENERIC_ALL,
		FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
		NULL,
		CREATE_NEW,
		FILE_ATTRIBUTE_NORMAL,
		NULL
	);

	if (hFile == INVALID_HANDLE_VALUE)
	{
		//printf("[-] CreateFileA has failed: %d\n", GetLastError());
		//if (GetLastError() == ERROR_FILE_EXISTS){}
		exit(1);
	}

	CloseHandle(hFile);

	return 0;
}

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpReserved)
{
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
