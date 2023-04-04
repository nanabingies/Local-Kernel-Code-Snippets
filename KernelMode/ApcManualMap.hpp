#pragma once
#include "Header.hpp"

// Kernel Mode Manual Mapping through APCs

#define APC_MAP_TAG ' cpA'

namespace ApcManualMap {
	// open the file for reading and return handle
	NTSTATUS Fn_Read(_Out_ PHANDLE, _In_ PWSTR);

	// read contents of file to buffer
	NTSTATUS Fn_ReadBuffer(_In_ HANDLE, _Out_ PVOID*);

	NTSTATUS ApcInitialize(KAPC*);

	NTSTATUS ManualMap();
}