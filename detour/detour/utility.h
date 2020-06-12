#pragma once

CHAR* ConcatString(CHAR* path, CHAR* filename)
{
	size_t len1 = strlen(path);
	size_t len2 = strlen(filename);
	size_t outputlen = len1 + len2 + 1;

	CHAR* output = new CHAR[outputlen];
	strcpy_s(output, outputlen, path);
	strcat_s(output, outputlen, filename);

	return output;
}

CHAR* PopulatePoCPath(CHAR* fname)
{
	// populates and returns the path C:\Users\%USERNAME%\AppData\Local\Temp\DLLHSC.tmp
	CHAR* lpBuffer = new CHAR[MAX_PATH];
	DWORD len = GetTempPathA(MAX_PATH, lpBuffer);

	if (!len)
	{
		printf("[-] GetTempPathA has failed: %d\n", GetLastError());
		exit(1);
	}

	return ConcatString(lpBuffer, fname);
}