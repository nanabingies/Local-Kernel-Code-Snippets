#pragma once
#include "Header.hpp"

// Kernel Mode Manual Mapping using System Worker Threads

#define MAP_TAG 'gaT_'
using PBYTE = BYTE*;

namespace DriverManualMap {
	// open the file for reading and return handle
	NTSTATUS Fn_Read(_Out_ HANDLE*, _In_ UNICODE_STRING);

	// read contents of file to buffer
	NTSTATUS Fn_ReadBuffer(_In_ HANDLE, _Out_ PBYTE*);

	//KDEFERRED_ROUTINE ManualMap;
	//PIO_WORKITEM_ROUTINE_EX ManualMap;
	VOID ManualMap(_In_ PVOID, _In_opt_ PVOID, _In_ PIO_WORKITEM);

	NTSTATUS Fn_WorkItem(_In_ PDEVICE_OBJECT);
}