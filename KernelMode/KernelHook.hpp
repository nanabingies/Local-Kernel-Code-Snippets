#pragma once
#include "Header.hpp"

namespace KernelHook {
	
	using pNtReadFile = NTSYSAPI NTSTATUS(NTAPI*)(
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

	NTSTATUS HookNtReadFile(_In_ HANDLE, _In_opt_ HANDLE, _In_opt_ PIO_APC_ROUTINE, _In_opt_ PVOID, _Out_ PIO_STATUS_BLOCK,
		_Out_ PVOID, _In_ ULONG, _In_opt_ PLARGE_INTEGER, _In_opt_ PULONG);
	
	//template <typename T>
	NTSTATUS PrepareMdl(_In_ PVOID, _Out_ PMDL*);

	//template <typename T>
	NTSTATUS SetupHook(_In_ PVOID, _In_ PMDL);

	//template <typename T>
	NTSTATUS PrepareAddress(_In_ PWSTR, _Out_ PVOID*);

	VOID RestoreAddress(_In_ PVOID);

	VOID RestoreHook();

	// InterlockedExchangePointer
	NTSTATUS InterLockedHook(/* NtCreateFile */);

}