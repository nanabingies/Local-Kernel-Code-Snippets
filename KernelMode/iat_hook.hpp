#pragma once
#include "Header.hpp"

namespace IATHook {

	using uint64_t = UINT64;
	using uint32_t = UINT32;
	using BYTE = unsigned char;
	

	auto GetDriverBase(_In_ LPCSTR)->PVOID;

	auto IATHook(_In_ PVOID, _In_ LPCSTR, _In_ PVOID) -> void;

	auto Fn_MmGetSystemRoutineAddress(_In_ PUNICODE_STRING)->PVOID;

	auto NotifyRoutine(_In_opt_ PUNICODE_STRING, HANDLE, PIMAGE_INFO) -> void;

	auto gh_ZwAllocateVirtualMemory(_In_ HANDLE, _Inout_ PVOID*, _In_    ULONG_PTR, _Inout_ PSIZE_T, _In_ ULONG, _In_ ULONG)->NTSTATUS;

	auto gh_MmIsAddressValid(PVOID)->BOOLEAN;

	auto gh_IoCreateDevice(PDRIVER_OBJECT, ULONG, PUNICODE_STRING, DEVICE_TYPE, ULONG, BOOLEAN, PDEVICE_OBJECT*)->NTSTATUS;

	auto gh_MmGetPhysicalAddress(PVOID)->PHYSICAL_ADDRESS;

	auto gh_MmMapIoSpace(PHYSICAL_ADDRESS, SIZE_T, MEMORY_CACHING_TYPE)->PVOID;

	auto gh_ZwOpenFile(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PIO_STATUS_BLOCK, ULONG, ULONG)->NTSTATUS;

	auto gh_KeStackAttachProcess(PRKPROCESS, PRKAPC_STATE)->VOID;

	auto gh_DbgPrint()->ULONG;

	auto gh_ZwClose(_In_ HANDLE)->NTSTATUS;

	auto gh_ZwMapViewOfSection(_In_ HANDLE, _In_ HANDLE, _Inout_ PVOID*, _In_ ULONG_PTR, _In_ SIZE_T, _Inout_opt_ PLARGE_INTEGER,
		_Inout_ PSIZE_T, _In_ SECTION_INHERIT, _In_ ULONG, _In_ ULONG)->NTSTATUS;

	auto gh_ZwCreateSection()->PVOID;
}