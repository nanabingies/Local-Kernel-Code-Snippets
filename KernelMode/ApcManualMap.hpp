#pragma once
#include "Header.hpp"

// Kernel Mode Manual Mapping through APCs

#define APC_MAP_TAG ' cpA'

namespace ApcManualMap {
	// open the file for reading and return handle
	NTSTATUS Fn_Read(_Out_ PHANDLE, _In_ PWSTR);

	// read contents of file to buffer
	NTSTATUS Fn_ReadBuffer(_In_ HANDLE, _Out_ PVOID*);

	NTSTATUS ApcInitialize();

	NTSTATUS ManualMap(_In_ PVOID);

	VOID ApcKernelRoutine(_In_ PKAPC Apc, _Inout_ PKNORMAL_ROUTINE* NormalRoutine,
		_Inout_ PVOID* NormalContext, _Inout_ PVOID* SystemArgument1, _Inout_ PVOID* SystemArgument2);
}