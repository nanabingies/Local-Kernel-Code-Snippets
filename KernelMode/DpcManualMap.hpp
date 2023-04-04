#pragma once
#include "Header.hpp"

// Kernel Mode Manual Mapping through DPCs

#define DPC_MAP_TAG ' cpD'

namespace DPCManualMap {
	// open the file for reading and return handle
	NTSTATUS Fn_Read(_Out_ HANDLE*, _In_ UNICODE_STRING);

	// read contents of file to buffer
	NTSTATUS Fn_ReadBuffer(_In_ HANDLE, _Out_ PVOID*);

	//KDEFERRED_ROUTINE ManualMap;
	VOID ManualMap();

	NTSTATUS Fn_WorkItem(_In_ PDEVICE_OBJECT);
}