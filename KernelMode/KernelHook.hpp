#pragma once
#include "Header.hpp"

namespace KernelHook {
	
	using pZwReadFile = NTSYSAPI NTSTATUS (NTAPI*)(
		_In_ HANDLE           FileHandle,
		_In_opt_ HANDLE           Event,
		_In_opt_ PIO_APC_ROUTINE  ApcRoutine,
		_In_opt_ PVOID            ApcContext,
		_Out_ PIO_STATUS_BLOCK IoStatusBlock,
		_Out_ PVOID            Buffer,
		_In_ ULONG            Length,
		_In_opt_ PLARGE_INTEGER   ByteOffset,
		_In_opt_ PULONG           Key
	);

	NTSTATUS HookZwReadFile(_In_ HANDLE, _In_opt_ HANDLE, _In_opt_ PIO_APC_ROUTINE, _In_opt_ PVOID, _Out_ PIO_STATUS_BLOCK,
		_Out_ PVOID, _In_ ULONG, _In_opt_ PLARGE_INTEGER, _In_opt_ PULONG);
	
	template <typename T>
	NTSTATUS PrepareMdl(_In_ T, _Out_ PMDL*);

	template <typename T>
	NTSTATUS SetupHook(_In_ T, _In_ PMDL, _Out_ T*);

	template <typename T>
	NTSTATUS PrepareAddress(_In_ PWSTR, _Out_ T*);

	NTSTATUS RestoreAddress(_In_ PVOID);
}