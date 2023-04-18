#pragma once
#include "Header.hpp"

/// Get PID of process & attach to it
/// Get Base Address
/// Create a section and map it to process address space
/// Map same section to kernel address space
/// Write Shellcode to kernel address space (will automatically be written to process address space)
/// Perform APC Injection
/// Wait on thread.
/// Done !!!!



namespace CodeInjection {
	
	auto Injection(_In_ ULONG)->NTSTATUS;

	auto PerformInjection(_In_ ULONG)->NTSTATUS;

	auto CreateSection(_Out_ HANDLE*)->NTSTATUS;

	auto MapSection(_In_ HANDLE, _In_ HANDLE, _Out_ PVOID*, _In_ BOOLEAN)->NTSTATUS;

	auto OpenProcess(_In_ ULONG, _Out_ HANDLE*)->NTSTATUS;

	auto PerformApcInjection(_In_ PETHREAD, _In_ PVOID)->NTSTATUS;

	auto ApcKernelRoutine(_In_ PKAPC, _Inout_ PKNORMAL_ROUTINE*, _Inout_ PVOID*, _Inout_ PVOID*, _Inout_ PVOID*) -> void;
}