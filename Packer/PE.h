#pragma once
#include "windows.h"
#include "stdio.h"

typedef struct _BASE_RELOCATION_ENTRY {
	WORD Offset : 12;
	WORD Type : 4;
} BASE_RELOCATION_ENTRY, * PBASE_RELOCATION_ENTRY;

PIMAGE_NT_HEADERS32 getNTHeaders32(PVOID fileBuffer);
PIMAGE_DATA_DIRECTORY getDataDirectories32(PVOID fileBuffer, DWORD dwDirectoryID);

BOOL mapPEVirtualLocal(PVOID fileBuffer, SIZE_T bufferSize, LPVOID baseAddress);

BOOL hasRelocDirectory(PVOID fileBuffer);

BOOL applyRelocateBlock32(PBASE_RELOCATION_ENTRY pRelocEntry, DWORD dwNumberOfEntries, DWORD dwPage, DWORDLONG dwlOldBaseAddress, DWORDLONG dwlNewBaseAddress, PVOID pModule);

BOOL applyRelocation(DWORDLONG dwlOldBaseAddress, DWORDLONG dwlNewBaseAddress, PVOID pModule);