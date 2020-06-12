#include <windows.h>
#include <shlwapi.h>
#include <stdio.h>
#include <string>
#include <strsafe.h>
#include <tchar.h>
#include <stringapiset.h>
#include <Winuser.h>
#include <psapi.h>
#include "detours.h"
#include "utility.h"

#pragma comment(lib, "shlwapi.lib")
#ifdef _WIN32
#pragma comment(lib, "lib.X86/detours.lib")
#endif
#ifdef _WIN64
#pragma comment(lib, "lib.X64/detours.lib")
#endif

struct KnownDLLs {
	BYTE** list;
	DWORD size;
};
struct ImportedModules {
	CHAR** modulenames;
	DWORD count;
};
struct Manifest {
	CHAR* location;
	DWORD size;
};

void menu()
{
	// prints this menu and exits
	printf("NAME\n");
	printf("\tdllhsc - DLL Hijack SCanner\n\n");
	printf("SYNOPSIS\n");
	printf("\tdllhsc.exe -h\n\n");
	printf("\tdllhsc.exe -e <executable image path> (-l|-lm|-rt)\n\n");
	printf("DESCRIPTION\n");
	printf("\tDLLHSC scans a given executable image for DLL Hijacking and reports the results\n\n");
	printf("\tIt requires elevated privileges\n\n");
	printf("OPTIONS\n");
	printf("\t-h, --help\n");
	printf("\t\tdisplay this help menu and exit\n\n");
	printf("\t-e, --executable-image\n");
	printf("\t\texecutable image to scan\n\n");
	printf("\t-l, --lightweight\n");
	printf("\t\tparse the import table, attempt to launch a payload and report the results\n\n");
	printf("\t-lm, --list-modules\n");
	printf("\t\tlist loaded modules that do not exist in the application's directory\n\n");
	printf("\t-rt, --runtime-load\n");
	printf("\t\tdisplay modules loaded in run-time by hooking LoadLibrary and LoadLibraryEx APIs\n");
}

CHAR* FindFirstOccurence(CHAR* input, CHAR* keyword)
{
	// returns a pointer to the beginning of the substring(keyword) or 0 if the substring is not found
	CHAR* offsetaddr = 0;
	
	// if keyword is smaller than the input, exit
	if ( strlen(keyword) > strlen(input))
	{
		return offsetaddr;
	}

	CHAR* slidingwindow = new CHAR[strlen(keyword) + 1];
	size_t limit = strlen(input) - strlen(keyword) + 1;
	for (size_t i = 0; i < limit; i++)
	{
		strncpy_s(slidingwindow, strlen(keyword) + 1, input, strlen(keyword));
		if (!(_stricmp(slidingwindow, keyword)))
		{
			offsetaddr = input;
			break;
		}
		input++;
	}
	return offsetaddr;
}

CHAR* helper(CHAR* input, CHAR* output)
{
	// parses double quote terminated string into null terminated string
	int i = 0;
	if (input == NULL)
	{
		output[i] = '*';
		output[i + 1] = '\0';
		return output;
	}

	while (input[i] != '\"')
	{
		output[i] = input[i];
		i++;
	}
	output[i] = '\0';

	return output;
}

BOOL CheckElevatePrivilege()
{
	BOOL result = FALSE;
	HANDLE TokenHandle = NULL;

	if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &TokenHandle))
	{
		TOKEN_ELEVATION TokenInformation;
		DWORD ReturnLength = sizeof(TOKEN_ELEVATION);
		if (GetTokenInformation(TokenHandle, TokenElevation, &TokenInformation, ReturnLength, &ReturnLength))
		{
			result = TokenInformation.TokenIsElevated;
		}
	}
	if (TokenHandle) CloseHandle(TokenHandle);

	return result;
}

KnownDLLs RegReadKnownDLLs()
{
	// lpValueName = module/DLL name
	HKEY hKey;
	LPCSTR lpSubKey = "SYSTEM\\CurrentControlSet\\Control\\Session Manager\\KnownDLLs";

	KnownDLLs knowndlls = { 0 };

	// get a handle to the registry key
	DWORD regstat = RegOpenKeyExA(HKEY_LOCAL_MACHINE, lpSubKey, 0, KEY_READ, &hKey);
	if (regstat)
	{
		printf("[-] RegOpenKeyExA: %d\n", GetLastError());
		return knowndlls;
	}

	// get number of Values, MaxValueNameLen and MaxValueLen the key has
	DWORD lpcbMaxValueNameLen, lpcbMaxValueLen;
	if (RegQueryInfoKeyA(hKey, NULL, NULL, NULL, NULL, NULL, NULL, &knowndlls.size, &lpcbMaxValueNameLen, &lpcbMaxValueLen, NULL, NULL))
	{
		printf("[-] RegQueryInfoKeyA: %d\n", GetLastError());
		return knowndlls;
	}
		
	CHAR* lpValueName = new CHAR[lpcbMaxValueNameLen + 1];
	knowndlls.list = new BYTE*[knowndlls.size];
	for (unsigned int dwIndex = 0; dwIndex < knowndlls.size; dwIndex++)
	{
		knowndlls.list[dwIndex] = new BYTE[lpcbMaxValueLen];
		DWORD lpcchValueName = lpcbMaxValueNameLen + 1;
		DWORD lpcbData = lpcbMaxValueLen;
		DWORD lpType;
		RegEnumValueA(hKey, dwIndex, lpValueName, &lpcchValueName, NULL, &lpType, knowndlls.list[dwIndex], &lpcbData);
	}
	delete []lpValueName;

	return knowndlls;
}

CHAR* LoadFileMemory(CHAR* exepath)
{
	// loads a file into memory and returns a pointer to the buffer

	// get file handle
	HANDLE hFile = 0;
	hFile = CreateFileA(exepath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hFile == INVALID_HANDLE_VALUE)
	{
		//printf("[-] in LoadFileMemory CreateFileA has failed: %d\n", GetLastError());
		if (GetLastError() == ERROR_FILE_NOT_FOUND)
		{
			//printf("[-] in load memory The file you specified doesn't exist\n");
		}
		return 0;
	}

	// get file size
	DWORD nNumberOfBytesToRead = GetFileSize(hFile, NULL);

	// read file bytes
	CHAR* lpBuffer = 0;
	lpBuffer = new CHAR[nNumberOfBytesToRead+1];
	if (!ReadFile(hFile, lpBuffer, nNumberOfBytesToRead, NULL, NULL))
	{
		printf("[-] FileRead has failed: %d\n", GetLastError());
		return 0;
	}
	lpBuffer[nNumberOfBytesToRead] = '\0';

	CloseHandle(hFile);

	return lpBuffer;
}

DWORD RVAtoOffset(DWORD RVA, DWORD NumberOfSections, IMAGE_SECTION_HEADER* hdrSection)
{
	IMAGE_SECTION_HEADER* tmphdrSection;
	tmphdrSection = hdrSection;

	if (RVA == 0)
	{
		return RVA;
	}

	for (unsigned int i = 0; i < NumberOfSections; i++)
	{
		if (RVA >= tmphdrSection->VirtualAddress && RVA < tmphdrSection->VirtualAddress + tmphdrSection->Misc.VirtualSize)
		{
			break;
		}
		tmphdrSection++;
	}

	return (RVA - tmphdrSection->VirtualAddress + tmphdrSection->PointerToRawData);
}

template <typename T>
ImportedModules ParseImportedModules(CHAR* lpBuffer, T* hdrNT)
{
	// parses the Imported modules
	// returns a struct that contains the names and the number of imported modules for 32bit arch
	IMAGE_SECTION_HEADER* hdrSection = IMAGE_FIRST_SECTION(hdrNT);
	IMAGE_IMPORT_DESCRIPTOR* ImgImportDescriptor;

	ImportedModules imodules = { 0 };

	if (hdrNT->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size != 0)
	{
		ImgImportDescriptor = (IMAGE_IMPORT_DESCRIPTOR*)(lpBuffer + RVAtoOffset(hdrNT->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress, hdrNT->FileHeader.NumberOfSections, hdrSection));

		IMAGE_IMPORT_DESCRIPTOR* tmpImgImportDescriptor = ImgImportDescriptor;
		while (tmpImgImportDescriptor->Name != NULL)
		{
			// number of imported modules
			imodules.count++;
			tmpImgImportDescriptor++;
		}

		imodules.modulenames = new CHAR * [imodules.count];
		for (unsigned int i = 0; i < imodules.count; i++)
		{
			imodules.modulenames[i] = new CHAR[40];
			imodules.modulenames[i] = (CHAR*)(lpBuffer + RVAtoOffset(ImgImportDescriptor->Name, hdrNT->FileHeader.NumberOfSections, hdrSection));
			ImgImportDescriptor++;
		}

		// return number of modules parsed
		return imodules;
	}
	else
	{
		// 0 modules parsed, return 0
		return imodules;
	}
}

template <typename T>
Manifest GetPointerToManifest(CHAR* lpBuffer, T* hdrNT)
{
	// returns a pointer to Manifest file
	IMAGE_SECTION_HEADER* hdrSection = IMAGE_FIRST_SECTION(hdrNT);
	IMAGE_RESOURCE_DIRECTORY* ImgResourceDir, * ImgResourceDirSecond, * ImgResourceDirThird;

	Manifest manifest = { 0 };

	ImgResourceDir = (IMAGE_RESOURCE_DIRECTORY*)(lpBuffer + RVAtoOffset(hdrNT->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE].VirtualAddress, hdrNT->FileHeader.NumberOfSections, hdrSection));

	IMAGE_RESOURCE_DIRECTORY_ENTRY* ImgResourceDirEntry = (IMAGE_RESOURCE_DIRECTORY_ENTRY*)(ImgResourceDir + 1);
	DWORD counter = ImgResourceDir->NumberOfNamedEntries;

	while (counter > 0)
	{
		ImgResourceDirEntry++;
		counter--;
	}

	for (unsigned int i = 0; i < ImgResourceDir->NumberOfIdEntries; i++)
	{
		// ImgResourceDirEntry->Name = 24 -> Configuration Files
		if (ImgResourceDirEntry->Name == 24)
		{
			ImgResourceDirSecond = (IMAGE_RESOURCE_DIRECTORY*)((ULONGLONG)ImgResourceDir + (0x0fffffff & ImgResourceDirEntry->OffsetToData));
			ImgResourceDirEntry = (IMAGE_RESOURCE_DIRECTORY_ENTRY*)(ImgResourceDirSecond + 1);

			ImgResourceDirThird = (IMAGE_RESOURCE_DIRECTORY*)((ULONGLONG)ImgResourceDir + (0x0fffffff & ImgResourceDirEntry->OffsetToData));
			ImgResourceDirEntry = (IMAGE_RESOURCE_DIRECTORY_ENTRY*)(ImgResourceDirThird + 1);

			IMAGE_RESOURCE_DATA_ENTRY* ImgResourceDataEntry = (IMAGE_RESOURCE_DATA_ENTRY*)((ULONGLONG)ImgResourceDir + (0x0fffffff & ImgResourceDirEntry->OffsetToData));

			manifest.location = lpBuffer + RVAtoOffset(ImgResourceDataEntry->OffsetToData, hdrNT->FileHeader.NumberOfSections, hdrSection);
			manifest.size = ImgResourceDataEntry->Size;
		}
		ImgResourceDirEntry++;
	}

	return manifest;
}

CHAR* newRemoveFileSpec(CHAR* inputpath)
{
	// function that removes the filename from the provided path
	// functionality similar to PathCchRemoveFileSpec API
	size_t i = strlen(inputpath);

	do
	{
		i--;
	} while (inputpath[i] != '\\');

	CHAR* apppath = new CHAR[i + 2];
	for (size_t j = 0; j < i + 1; j++)
	{
		apppath[j] = inputpath[j];
	}
	apppath[i + 1] = '\0';

	// return the new path (ends with \)
	return apppath;
}

BOOL inKnownDLLs(CHAR* modulename, KnownDLLs knowndlls)
{
	// checks if the provided module exists in KnownDLLs
	unsigned int j = 0;

	do 
	{
		if (!_stricmp(modulename, (CHAR *)knowndlls.list[j]))
		{
			return TRUE;
		}
		j++;
	} while (j < knowndlls.size);
	
	return FALSE;
}

CHAR* ManifestToWinSxSPath(CHAR* manifestbuffer, size_t arch)
{
	// returns the WinSxS directory wildcard
	// schemas-microsoft-com:asm.v1

	CHAR dependentAssemblykeyword[] = "<dependentAssembly>";
	CHAR dependentAssemblyEnd[] = "</dependentAssembly>";
	CHAR assemblyidkeyword[] = "<assemblyIdentity";
	const CHAR* attributes[6] = { "processorArchitecture=\"", "name=\"", "publicKeyToken=\"", "version=\"", "language=\"", "type=\"" };

	CHAR* path = 0;
	if (manifestbuffer == 0)
	{
		return path;
	}

	CHAR* startaddress = 0;
	startaddress = FindFirstOccurence(manifestbuffer, dependentAssemblykeyword);
	if (startaddress == 0)
	{
		return path;
	}

	CHAR* upperlimit;
	CHAR* offset = startaddress;
	CHAR** attributesvalues = new CHAR * [6];
	while (offset < manifestbuffer + strlen(manifestbuffer) - strlen(dependentAssemblykeyword))
	{
		upperlimit = 0;
		if (startaddress != 0)
		{
			upperlimit = FindFirstOccurence(startaddress + strlen(dependentAssemblykeyword), dependentAssemblyEnd);
			CHAR* tmp = new CHAR[upperlimit - startaddress];
			strncpy_s(tmp, upperlimit - startaddress, startaddress + strlen(dependentAssemblykeyword), upperlimit - startaddress - strlen(dependentAssemblykeyword));
			for (int j = 0; j < 6; j++)
			{
				attributesvalues[j] = new CHAR[50];
				CHAR* matched = FindFirstOccurence(tmp, (CHAR*)attributes[j]);
				if (matched != 0) helper(matched + strlen(attributes[j]), attributesvalues[j]);
				else helper(matched, attributesvalues[j]);
			}
		}
		offset = offset + strlen(dependentAssemblykeyword);
		startaddress = FindFirstOccurence(offset, dependentAssemblykeyword);
	}

	// path structure: processorArchitecture_name_publicKeyToken_version_language_<unknown>\modulename.dll
	// <unknown>: star
	// version: star
	// language: star

	CHAR* tmp = new CHAR[MAX_PATH];
	tmp[0] = '\0';
	char underscore[] = "_";
	char star[] = "*";

	if (strncmp(attributesvalues[0], star, 1) && (arch == 32))
	{
		CHAR archSxS[] = "x86";
		tmp = ConcatString(tmp, archSxS);
	}
	else if (strncmp(attributesvalues[0], star, 1) && (arch == 64))
	{
		CHAR archSxS[] = "amd64";
		tmp = ConcatString(tmp, archSxS);
	}
	else
	{
		tmp = ConcatString(tmp, star);
	}
	tmp = ConcatString(tmp, underscore);

	for (int i = 1; i < 3; i++)
	{
		tmp = ConcatString(tmp, attributesvalues[i]);
		tmp = ConcatString(tmp, underscore);
	}
	tmp = ConcatString(tmp, star);
	tmp = ConcatString(tmp, underscore);
	tmp = ConcatString(tmp, attributesvalues[4]);
	tmp = ConcatString(tmp, underscore);
	tmp = ConcatString(tmp, star);

	CHAR base[] = "C:\\Windows\\WinSxs\\";
	path = ConcatString(base, tmp);

	return path;
}

BOOL CheckWinSxSDependency(CHAR* path, CHAR* modulename)
{
	CHAR base[] = "C:\\Windows\\WinSxS\\";
	
	WIN32_FIND_DATAA lpFindFileData = { 0 };
	HANDLE hFileListing = FindFirstFileA(path, &lpFindFileData);
	if (hFileListing == INVALID_HANDLE_VALUE)
	{
		printf("[-] FindFirstFileA has failed: %d. Exiting...\n", GetLastError());
		exit(1);
	}

	if (lpFindFileData.cFileName)
	{
		CHAR backslash[] = "\\";
		CHAR* filepath = ConcatString(base, lpFindFileData.cFileName);
		filepath = ConcatString(filepath, backslash);
		filepath = ConcatString(filepath, modulename);

		return PathFileExistsA(filepath);
	}

	/*
	while (FindNextFileA(hFileListing, &lpFindFileData) != 0)
	{
		//printf("--> %s\n", lpFindFileData.cFileName);
		//dependency = TRUE;
	}
	*/

	return FALSE;
}

CHAR* SourcePayloadPath(CHAR* filename)
{
	// returns the path of the running process

	CHAR* lpFilename = new CHAR[MAX_PATH];
	if (!GetModuleFileNameA(NULL, lpFilename, MAX_PATH))
	{
		return 0;
	}
	lpFilename = newRemoveFileSpec(lpFilename);

	return ConcatString(lpFilename, filename);
}

BOOL ColoredText(CHAR* intext, WORD color)
{
	// save current attributes
	HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
	CONSOLE_SCREEN_BUFFER_INFO consoleInfo;
	GetConsoleScreenBufferInfo(hConsole, &consoleInfo);
	WORD saved_attributes;
	saved_attributes = consoleInfo.wAttributes;

	SetConsoleTextAttribute(hConsole, color);
	printf("%s", intext);

	// restore original attributes
	SetConsoleTextAttribute(hConsole, saved_attributes);

	return TRUE;
}

int ListModules(CHAR* exeimgpath, KnownDLLs knowndlls)
{
	STARTUPINFOA lpStartupInfo = { 0 };
	lpStartupInfo.cb = sizeof(STARTUPINFOA);
	// do not show window
	lpStartupInfo.dwFlags = STARTF_USESHOWWINDOW;
	lpStartupInfo.wShowWindow = SW_HIDE;
	
	BOOL status = FALSE;
	PROCESS_INFORMATION lpProcessInformation = { 0 };
	status = CreateProcessA(exeimgpath, NULL, NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL, NULL, &lpStartupInfo, &lpProcessInformation);
	if (!status)
	{
		printf("[-] CreateProcessA has failed: %d\n", GetLastError());
		return 1;
	}

	Sleep(1000);
	//DWORD synchro = WaitForSingleObject(lpProcessInformation.hThread, INFINITE);

	status = FALSE;
	HMODULE hModule[1024];
	DWORD cbNeeded;
	status = EnumProcessModules(lpProcessInformation.hProcess, hModule, sizeof(hModule), &cbNeeded);
	if (!status)
	{
		printf("[-] EnumProcessModules has failed with error code: %d\n", GetLastError());
		printf("\t This may indicate that the process has crashed before listing the modules.\n");
		return 1;
	}

	printf("[+] Loaded Modules mapped in the process address space that don't exist in KnownDLLs:\n");
	for (unsigned int i = 0; i < cbNeeded / sizeof(HMODULE); i++)
	{
		CHAR lpFilename[256];
		DWORD statusModule = 0;
		statusModule = GetModuleFileNameExA(lpProcessInformation.hProcess, hModule[i], lpFilename, MAX_PATH);
		if (!status)
		{
			printf("[-] GetModuleFileNameExA has failed: %d\n", GetLastError());
			return 1;
		}

		if (strncmp(exeimgpath, lpFilename, strlen(exeimgpath)) && strncmp("c:\\windows\\winsxs\\", CharLowerA(lpFilename), 18))
		{
			// only print modules that do not exists in the KnownDLLs list
			if (!inKnownDLLs(lpFilename+20, knowndlls))
			{
				// potential hijack candidates
				printf("\t%s\n", lpFilename);
			}
		}
	}

	TerminateProcess(lpProcessInformation.hProcess, 0);

	CloseHandle(lpProcessInformation.hProcess);
	CloseHandle(lpProcessInformation.hThread);

	return 0;
}

void HijackHunt(CHAR* lpBuffer, CHAR* exeimgpath, KnownDLLs knowndlls, CHAR* current)
{
	IMAGE_DOS_HEADER* hdrDOS = (IMAGE_DOS_HEADER*)lpBuffer;
	IMAGE_NT_HEADERS* hdrNT = (IMAGE_NT_HEADERS*)(lpBuffer + hdrDOS->e_lfanew);

	ImportedModules imodules = { 0 };
	Manifest manifest = { 0 };

	size_t arch = 0;
	// parse imported modules based on the architecture and get a pointer to manifest
	if (hdrNT->FileHeader.Machine == IMAGE_FILE_MACHINE_AMD64)
	{
		arch = 64;
		IMAGE_NT_HEADERS64* hdrNT = (IMAGE_NT_HEADERS64*)(lpBuffer + hdrDOS->e_lfanew);

		imodules = ParseImportedModules(lpBuffer, hdrNT);

		// check if the image contains a manifest file
		if (hdrNT->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE].Size != 0)
		{
			// get a pointer to the manifest
			manifest = GetPointerToManifest(lpBuffer, hdrNT);
		}
	}
	else if (hdrNT->FileHeader.Machine == IMAGE_FILE_MACHINE_I386)
	{
		arch = 32;
		IMAGE_NT_HEADERS32* hdrNT = (IMAGE_NT_HEADERS32*)(lpBuffer + hdrDOS->e_lfanew);

		imodules = ParseImportedModules(lpBuffer, hdrNT);

		if (hdrNT->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE].Size != 0)
		{
			// get pointer to manifest file
			manifest = GetPointerToManifest(lpBuffer, hdrNT);
		}
	}
	else
	{
		printf("[-] Unrecognized PE format. Exiting...\n");
		exit(1);
	}

	// if no import modules identified exit
	if (!imodules.count)
	{
		printf("[+] No imported modules identified. Exiting...\n");
		exit(1);
	}

	CHAR* apppath = newRemoveFileSpec(exeimgpath);

	BOOL finding = FALSE;
	for (unsigned int i = 0; i < imodules.count; i++)
	{
		// check if the imported DLL is in the KnownDLLs registry key for each of the imported modules
		if (!inKnownDLLs(imodules.modulenames[i], knowndlls))
		{
			CHAR* candidateDLLfilepath = 0;
			candidateDLLfilepath = ConcatString(apppath, imodules.modulenames[i]);
			
			// check WinSxS dependency
			CHAR* pathWinSxS = ManifestToWinSxSPath(manifest.location, arch);
			if ((pathWinSxS) && CheckWinSxSDependency(pathWinSxS, imodules.modulenames[i]))
			{
				continue;
			}

			// failsafe
			if (PathFileExistsA(candidateDLLfilepath))
			{
				printf("[!] DLL %s exists probably from a previous test. Make sure to remove it\n", candidateDLLfilepath);
				continue;
			}

			if (!PathFileExistsA(candidateDLLfilepath))
			{
				// if it doesn't exist, rename the payload DLL to the imported DLL and check if it's launched
				// make a 64 and a 32 bit payload, that once gets loaded will write a file in the C:\Uers\%USERNAME%\AppData\Local\Temp
				// copy the payload to the directory from which the application was launched
				// assuming the payload32.dll and payload64 are both located in the same directory
				if (arch == 32)
				{
					CHAR payloaddll[14] = "payload32.dll";
					if (!CopyFileA(SourcePayloadPath(payloaddll), ConcatString(apppath, imodules.modulenames[i]), TRUE))
					{
						printf("[-] CopyFileA for 32bit architecture has failed: %d\n", GetLastError());
					}
				}
				else if (arch == 64)
				{
					CHAR payloaddll[14] = "payload64.dll";
					if (!CopyFileA(SourcePayloadPath(payloaddll), ConcatString(apppath, imodules.modulenames[i]), TRUE))
					{
						printf("[-] CopyFileA for 64bit architecture has failed: %d\n", GetLastError());
					}
				}
				else printf("[-] Error in Switch. ARCH is zero.\n");

				STARTUPINFOA lpStartupInfo = { 0 };
				lpStartupInfo.cb = sizeof(STARTUPINFOA);
				// do not show window
				lpStartupInfo.dwFlags = STARTF_USESHOWWINDOW;
				lpStartupInfo.wShowWindow = SW_HIDE;
				PROCESS_INFORMATION lpProcessInformation;

				if (!CreateProcessA(exeimgpath, NULL, NULL, NULL, FALSE, NORMAL_PRIORITY_CLASS, NULL, apppath, &lpStartupInfo, &lpProcessInformation))
				{
					printf("[-] The launch of the tested process has failed: %d. Exiting...\n", GetLastError());
					exit(1);
				}
				Sleep(300);

				// terminate the process
				if (!TerminateProcess(lpProcessInformation.hProcess, 0))
				{
					printf("[-] Termination of the tested process has failed: %d. Exiting...\n", GetLastError());
					exit(1);
				}
				
				CHAR ordinal[] = " - Ordinal Not Found";
				CHAR entrypoint[] = " - Entry Point Not Found";
				CHAR* first = PathFindFileNameA(exeimgpath);

				CHAR* lpWindowName1 = ConcatString(first, ordinal);
				CHAR* lpWindowName2 = ConcatString(first, entrypoint);
				HWND WndOrdinal = 0;
				HWND WndEntryPoint = 0;
				BOOL msgboxpopup = FALSE;

				WndOrdinal = FindWindowA(NULL, lpWindowName1);
				WndEntryPoint = FindWindowA(NULL, lpWindowName2);
				
				CHAR* textt = new CHAR[512];
				while (WndOrdinal != 0)
				{
					SendMessage(WndOrdinal, WM_CLOSE, NULL, NULL);
					msgboxpopup = TRUE;
					WndOrdinal = FindWindowA(NULL, lpWindowName1);
				}
				
				while (WndEntryPoint != 0)
				{
					SendMessage(WndEntryPoint, WM_CLOSE, NULL, NULL);
					msgboxpopup = TRUE;
					WndEntryPoint = FindWindowA(NULL, lpWindowName2);
				}

				// delete the copied DLL
				Sleep(400);
				if (!DeleteFileA(candidateDLLfilepath))
				{
					printf("[-] Delete renamed payload DLL has failed: %d. Exiting...\n", GetLastError());
					exit(1);
				}

				// chech if the payload was executed successfully (if the PoC file was created)
				CHAR what[] = "report";
				CHAR logfilename[11] = "DLLHSC.tmp";
				if (PathFileExistsA(PopulatePoCPath(logfilename)))
				{
					// critical finding
					printf("\t[");
					ColoredText(what, FOREGROUND_RED);
					printf("] PoC file was found.This indicates that if %s is replaced with a payload DLL, the payload gets executed immediately\n", candidateDLLfilepath);
					finding = TRUE;

					// delete the PoC file that was in C:\Users\%USERNAME%\AppData\Local\Temp\DLLHSC.tmp
					if (!DeleteFileA(PopulatePoCPath(logfilename)))
					{
						printf("[-] PoC file delete has failed: %d\n", GetLastError());
						exit(1);
					}
				}
				else if (msgboxpopup)
				{
					// medium finding
				 	printf("\t[");
					ColoredText(what, FOREGROUND_GREEN | FOREGROUND_RED);
					printf("] Message box was poped up, indicating the DLL %s may be replaced and execute the payload upon dependencies are met.\n", candidateDLLfilepath);
					finding = TRUE;
				}
				else
				{
					// not exploitable
					printf("\t[");
					ColoredText(what, FOREGROUND_GREEN);
					printf("] The %s is NOT exploitable.\n", candidateDLLfilepath);
					finding = TRUE;
				}
			}
		}
	}

	if (finding == FALSE)
	{
		printf("[+] No DLL that could be placed in the application directory was found\n");
	}
}

int HookLoadLibrary(CHAR* exeimgpath)
{
	// string ASCII to Unicode
	DWORD pathlen = MultiByteToWideChar(CP_UTF8, 0, exeimgpath, -1, NULL, 0);
	WCHAR* exeimgpathW = new WCHAR[pathlen];
	MultiByteToWideChar(CP_UTF8, 0, exeimgpath, -1, exeimgpathW, pathlen);

	DWORD nBufferLength = GetCurrentDirectory(0, NULL);
	WCHAR detourDLLfilename[] = L"\\detour.dll";

	WCHAR* detourDLLPathW = new WCHAR[nBufferLength + wcslen(detourDLLfilename)];
	
	GetCurrentDirectory(nBufferLength + wcslen(detourDLLfilename) + 1, detourDLLPathW);

	StringCchCatW(detourDLLPathW, nBufferLength + wcslen(detourDLLfilename), detourDLLfilename);

	pathlen = WideCharToMultiByte(CP_UTF8, 0, detourDLLPathW, -1, NULL, 0, NULL, NULL);
	CHAR* detourDLLPathA = new CHAR[pathlen];
	WideCharToMultiByte(CP_UTF8, 0, detourDLLPathW, -1, detourDLLPathA, pathlen, NULL, NULL);
	
	STARTUPINFOW lpStartupInfo = { 0 };
	lpStartupInfo.cb = sizeof(STARTUPINFOW);
	// do not show window
	lpStartupInfo.dwFlags = STARTF_USESHOWWINDOW;
	lpStartupInfo.wShowWindow = SW_HIDE;
	PROCESS_INFORMATION lpProcessInformation = { 0 };
	DetourCreateProcessWithDllEx(exeimgpathW, NULL, NULL, NULL, FALSE, CREATE_DEFAULT_ERROR_MODE, NULL, NULL, &lpStartupInfo, &lpProcessInformation, detourDLLPathA, NULL);

	Sleep(1000);
	TerminateProcess(lpProcessInformation.hProcess, 0);
	// wait for the process to terminate
	WaitForSingleObject(lpProcessInformation.hProcess, INFINITE);

	// print Run-Time loaded modules
	CHAR* pBuffer = 0;
	CHAR logfilename[] = "DLLHSCRTLOG.tmp";
	pBuffer = LoadFileMemory(PopulatePoCPath(logfilename));

	printf("[+] The application is loading in run-time the following modules:\n\n");
	printf("%s", pBuffer);

	// delete the DLLHSCRTLOG.tmp
	if (!DeleteFileA(PopulatePoCPath(logfilename)))
	{
		printf("[-] Delete DLLHSCRTLOG.tmp has failed: %d. Exiting...\n", GetLastError());
		return 1;
	}

	return 0;
}

// main
int main(int argc, char **argv)
{
	// elevation error message
	if (!CheckElevatePrivilege())
	{
		printf("[!] Process has to be started elevated. Exiting...\n");
		return 1;
	}

	printf("[+] Application has started\n");

	// parse flags
	CHAR* exeimgpath = NULL;
	BOOL EXEset = FALSE;
	BOOL listmodules = FALSE;
	BOOL lightweight = FALSE;
	BOOL runtime = FALSE;
	for (int i = 1; i < argc; i++)
	{
		std::string input = argv[i];

		if (!input.compare("-h") || !input.compare("--help"))
		{
			menu();
			return 0;
		}

		if ( !input.compare("-e") || !input.compare("--executable-image") )
		{
			exeimgpath = argv[i + 1];
			EXEset = TRUE;
			if (!PathFileExistsA(argv[i + 1]))
			{
				printf("[-] The provided image does not exist. Please provide an image that exists\n");
				return 1;
			}
		}

		if ( !input.compare("-l") || !input.compare("--lightweight") )
		{
			lightweight = TRUE;
		}

		if ( !input.compare("-lm") || !input.compare("--list-modules") )
		{
			listmodules = TRUE;
		}

		if ( !input.compare("-rt") || !input.compare("--runtime-load") )
		{
			runtime = TRUE;
		}
	}

	if (!EXEset)
	{
		printf("[-] Executable image flag hasn't been specified. Exiting...\n");
		return 1;
	}
	else if (EXEset)
	{
		CHAR* lpBuffer = LoadFileMemory(exeimgpath);
		if (lpBuffer == 0)
		{
			printf("[-] Executable image was not loaded in memory. Exiting...\n");
			return 1;
		}

		KnownDLLs knowndlls = RegReadKnownDLLs();

		if (lightweight)
		{
			HijackHunt(lpBuffer, exeimgpath, knowndlls, exeimgpath);
		}
		if (listmodules)
		{
			ListModules(exeimgpath, knowndlls);
		}
		if (runtime)
		{
			HookLoadLibrary(exeimgpath);
		}
	}

	printf("[+] Scan has ended");

	return 0;
}
