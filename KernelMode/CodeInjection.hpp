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
	
	auto Injection(ULONG Pid)->NTSTATUS;

	auto CreateSection(HANDLE*)->NTSTATUS;

	auto MapSection(HANDLE*, HANDLE)->NTSTATUS;
}