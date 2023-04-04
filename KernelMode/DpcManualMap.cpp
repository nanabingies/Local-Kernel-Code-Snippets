#include "DpcManualMap.hpp"

namespace DPCManualMap {

	NTSTATUS Fn_Read(_Out_ PHANDLE fileHandle, _In_ PWSTR fileName) {
		*fileHandle = NULL;

		IO_STATUS_BLOCK ioBlock{};
		OBJECT_ATTRIBUTES oa{};
		UNICODE_STRING usString{};
		RtlInitUnicodeString(&usString, fileName);

		InitializeObjectAttributes(&oa, &usString, OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE,
			nullptr, nullptr);
		auto ns = ZwOpenFile(fileHandle, FILE_READ_ACCESS, &oa, &ioBlock,
			FILE_SHARE_READ, FILE_SYNCHRONOUS_IO_NONALERT);
		if (!NT_SUCCESS(ns)) {
			DbgPrint("Failed to open file %wZ for reading.\n", &usString);
			DbgPrint("Exiting with error code %X\n", ns);
			return ns;
		}

		PVOID fileObject;
		ns = ObReferenceObjectByHandle(fileHandle, FILE_READ_ACCESS, nullptr, KernelMode,
			&fileObject, nullptr);
		
		return ns;
	}


	NTSTATUS Fn_ReadBuffer(_In_ HANDLE fileHandle, _Out_ PVOID* fileBuffer) {
		*fileBuffer = nullptr;

		if (fileHandle == nullptr)	return STATUS_INVALID_PARAMETER_1;

		IO_STATUS_BLOCK ioBlock{};
		auto fileInfo = reinterpret_cast<FILE_STANDARD_INFORMATION*>
			(ExAllocatePoolWithTag(NonPagedPoolNx, sizeof(FILE_STANDARD_INFORMATION), APC_MAP_TAG));
		if (fileInfo == nullptr) {
			DbgPrint("[-] Failed to allocate memory for querying file information.\n");
			return STATUS_INSUFFICIENT_RESOURCES;
		}
		auto ns = ZwQueryInformationFile(fileHandle, &ioBlock, fileInfo, 
			sizeof(FILE_STANDARD_INFORMATION), FileStandardInformation);
		if (!NT_SUCCESS(ns)) {
			DbgPrint("ZwQueryInformationFile failed. Exiting with error %X\n", ns);
			return ns;
		}

		auto fileSize = fileInfo->EndOfFile.QuadPart;
		DbgPrint("File Size : %llX\n", fileSize);

		auto buffer = ExAllocatePoolWithTag(NonPagedPoolNx, fileSize, APC_MAP_TAG);
		if (buffer == nullptr) {
			DbgPrint("Failed to allocate memory for storing file contents.\n");
			return STATUS_INSUFFICIENT_RESOURCES;
		}

		ns = ZwReadFile(fileHandle, nullptr, nullptr, nullptr, &ioBlock, buffer, fileSize,
			nullptr, nullptr);
		if (!NT_SUCCESS(ns)) {
			DbgPrint("ZwReadFile failed with error status : %X\n", ns);
			return ns;
		}

		*fileBuffer = buffer;
		DbgPrint("File Buffer is at 0x%p\n", buffer);

		ExFreePoolWithTag(fileInfo, APC_MAP_TAG);
		return ns;
	}

	
	VOID ManualMap(_In_ struct _KDPC* Dpc, _In_opt_ PVOID DeferredContext,
			_In_opt_ PVOID SystemArgument1, _In_opt_ PVOID SystemArgument2) {

		DbgPrint("[%s] => \n", __FUNCTION__);


	}
}