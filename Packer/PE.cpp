#include "PE.h"
#include <iostream>
#include <string>
using namespace std;
PIMAGE_NT_HEADERS32 getNTHeaders32(PVOID fileBuffer) {
	if (!fileBuffer) {
		return NULL;
	}

	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)fileBuffer;
	if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
		return NULL;
	}
	PIMAGE_NT_HEADERS32 pNTHeaders32 = (PIMAGE_NT_HEADERS32)((DWORDLONG)fileBuffer + pDosHeader->e_lfanew);
	return pNTHeaders32;
}
PIMAGE_DATA_DIRECTORY getDataDirectories32(PVOID fileBuffer, DWORD dwDirectoryID) {
	if (dwDirectoryID >= IMAGE_NUMBEROF_DIRECTORY_ENTRIES || !fileBuffer) {
		return NULL;
	}

	PIMAGE_NT_HEADERS32 pNTHeaders32 = getNTHeaders32(fileBuffer);
	if (!pNTHeaders32) {
		return NULL;
	}

	PIMAGE_DATA_DIRECTORY pDataDirEntry = (PIMAGE_DATA_DIRECTORY) & (pNTHeaders32->OptionalHeader.DataDirectory[dwDirectoryID]);
	if (!pDataDirEntry) {
		return NULL;
	}
	return pDataDirEntry;
}

BOOL mapPEVirtualLocal(PVOID fileBuffer, SIZE_T bufferSize, LPVOID baseAddress) {
	if (!fileBuffer) {
		printf("File buffer is null\n");
		return FALSE;
	}

	PIMAGE_NT_HEADERS32 pNtHeaders32 = getNTHeaders32(fileBuffer);
	if (!pNtHeaders32) {
		printf("Not valid PE file\n");
		return FALSE;
	}

	// Copy all the headers into baseAddress
	memcpy(baseAddress, fileBuffer, (size_t)pNtHeaders32->OptionalHeader.SizeOfHeaders);

	PIMAGE_SECTION_HEADER pSectionHeader = (PIMAGE_SECTION_HEADER)((DWORDLONG)(&pNtHeaders32->OptionalHeader) + pNtHeaders32->FileHeader.SizeOfOptionalHeader);
	PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)fileBuffer;
	// iterate through all the sections and copy them
	DWORD dwNumSections = pNtHeaders32->FileHeader.NumberOfSections;

	for (DWORD i = 0; i < dwNumSections; i++) {
		LPVOID sectionBaseAddress = (BYTE*)baseAddress + pSectionHeader->VirtualAddress;
		memcpy(
			sectionBaseAddress,
			(BYTE*)fileBuffer + pSectionHeader->PointerToRawData,
			pSectionHeader->SizeOfRawData
		);
		printf("[*] Copying section %s to %p\n", pSectionHeader->Name, sectionBaseAddress);
		pSectionHeader++;
	}
	return TRUE;
}
//https://stackoverflow.com/questions/17436668/how-are-pe-base-relocations-build-up
BOOL hasRelocDirectory(PVOID fileBuffer) {
	return getDataDirectories32(fileBuffer, IMAGE_DIRECTORY_ENTRY_BASERELOC) != NULL;
}

BOOL applyRelocateBlock32(PBASE_RELOCATION_ENTRY pRelocEntry, DWORD dwNumberOfEntries, DWORD dwPage, DWORDLONG dwlOldBaseAddress, DWORDLONG dwlNewBaseAddress, PVOID pBuffer) {
	PBASE_RELOCATION_ENTRY tempEntry = pRelocEntry;
	DWORD i;
	for (i = 0; i < dwNumberOfEntries; i++) {
		if (!tempEntry)
			break;
		DWORD dwOffset = tempEntry->Offset;
		DWORD dwType = tempEntry->Type;
		if (dwType == 0)
			break;

		if (dwType != 3) {
			printf("Not supported relocations format %d\n", dwType);
			return FALSE;
		}

		PDWORD pdwRelocateAddr = (PDWORD)((ULONG_PTR)pBuffer + dwPage + dwOffset);
		(*pdwRelocateAddr) = static_cast<DWORD>((*pdwRelocateAddr) - (ULONG_PTR)dwlOldBaseAddress) + dwlNewBaseAddress;
		tempEntry = (PBASE_RELOCATION_ENTRY)((ULONG_PTR)tempEntry + sizeof(WORD));
	}
	printf("[+] Applied %d relocations\n", static_cast<int>(i));
	return TRUE;
}

BOOL applyRelocation(DWORDLONG dwlOldBaseAddress, DWORDLONG dwlNewBaseAddress, PVOID pBuffer) {
	PIMAGE_DATA_DIRECTORY pDataDirReloc = getDataDirectories32(pBuffer, IMAGE_DIRECTORY_ENTRY_BASERELOC);

	if (!pDataDirReloc) {
		printf("Executable does not have relocation table\n");
		return FALSE;
	}

	DWORD dwRelocSize = pDataDirReloc->Size;
	DWORD dwRelocVA = pDataDirReloc->VirtualAddress;

	PIMAGE_BASE_RELOCATION pBaseReloc = NULL;
	DWORD dwParsedSize = 0;
	while (dwParsedSize < dwRelocSize) {
		pBaseReloc = (PIMAGE_BASE_RELOCATION)(dwRelocVA + dwParsedSize + (ULONG_PTR)pBuffer);
		dwParsedSize += pBaseReloc->SizeOfBlock;
		if (pBaseReloc->SizeOfBlock == 0 || pBaseReloc->VirtualAddress == NULL) {
			pBaseReloc++;
			continue;
		}

		printf("Relocation block: 0x%x 0x%x\n", pBaseReloc->VirtualAddress, pBaseReloc->SizeOfBlock);

		DWORD dwNumberOfEntries = (pBaseReloc->SizeOfBlock - 2 * sizeof(DWORD)) / sizeof(WORD);
		printf("	Num entries: 0x%x\n", dwNumberOfEntries);
		PBASE_RELOCATION_ENTRY pRelocEntry = (PBASE_RELOCATION_ENTRY)((ULONG_PTR)pBaseReloc + sizeof(DWORD) + sizeof(DWORD));
		if (applyRelocateBlock32(
			pRelocEntry,
			dwNumberOfEntries,
			pBaseReloc->VirtualAddress,
			dwlOldBaseAddress,
			dwlNewBaseAddress,
			pBuffer
		) == FALSE) {
			return FALSE;
		}
	}
	return TRUE;
}