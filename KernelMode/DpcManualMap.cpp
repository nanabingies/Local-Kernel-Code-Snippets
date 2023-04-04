#include "DpcManualMap.hpp"
#pragma warning(disable : 4100)

namespace DPCManualMap {

	NTSTATUS Fn_Read(_Out_ HANDLE* fileHandle, _In_ UNICODE_STRING fileName) {
		HANDLE hFile;
		IO_STATUS_BLOCK ioBlock{};
		OBJECT_ATTRIBUTES oa{};

		InitializeObjectAttributes(&oa, &fileName, OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE,
			nullptr, nullptr);
		auto ns = ZwCreateFile(&hFile, FILE_READ_ATTRIBUTES, &oa, &ioBlock, nullptr,
			FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ, FILE_OPEN, FILE_SYNCHRONOUS_IO_NONALERT,
			nullptr, 0);
		if (!NT_SUCCESS(ns)) {
			DbgPrint("Failed to open file %wZ for reading.\n", &fileName);
			DbgPrint("Exiting with error code %X\n", ns);
			return ns;
		}
		DbgPrint("--");

		PVOID fileObject;
		ns = ObReferenceObjectByHandle(hFile, FILE_READ_ACCESS, nullptr, KernelMode,
			&fileObject, nullptr);
		DbgPrint("FileHandle : %p | fileObject : %p\n", hFile, fileObject);

		*fileHandle = hFile;
		
		return ns;
	}


	NTSTATUS Fn_ReadBuffer(_In_ HANDLE fileHandle, _Out_ PVOID* fileBuffer) {
		*fileBuffer = nullptr;

		if (fileHandle == nullptr)	return STATUS_INVALID_PARAMETER_1;

		IO_STATUS_BLOCK ioBlock{};
		auto fileInfo = reinterpret_cast<FILE_STANDARD_INFORMATION*>
			(ExAllocatePoolWithTag(NonPagedPoolNx, sizeof(FILE_STANDARD_INFORMATION), DPC_MAP_TAG));
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

		auto buffer = ExAllocatePoolWithTag(NonPagedPoolNx, fileSize, DPC_MAP_TAG);
		if (buffer == nullptr) {
			DbgPrint("Failed to allocate memory for storing file contents.\n");
			return STATUS_INSUFFICIENT_RESOURCES;
		}

		ns = ZwReadFile(fileHandle, nullptr, nullptr, nullptr, &ioBlock, buffer, (ULONG)fileSize,
			nullptr, nullptr);
		if (!NT_SUCCESS(ns)) {
			DbgPrint("ZwReadFile failed with error status : %X\n", ns);
			return ns;
		}

		*fileBuffer = buffer;
		DbgPrint("File Buffer is at 0x%p\n", buffer);

		ExFreePoolWithTag(fileInfo, DPC_MAP_TAG);
		return ns;
	}

	
	VOID ManualMap(/*_In_ struct _KDPC* Dpc, _In_opt_ PVOID DeferredContext,
			_In_opt_ PVOID SystemArgument1, _In_opt_ PVOID SystemArgument2*/) {

		DbgPrint("[%s] => \n", __FUNCTION__);

		HANDLE fileHandle{};
		UNICODE_STRING fileName{};
		RtlInitUnicodeString(&fileName, L"\\DosDevices\\C:\\Users\\nana\\Desktop\\TestDriver.sys");
		if (!NT_SUCCESS(Fn_Read(&fileHandle, fileName)))	return;

		PVOID fileBuffer;
		if (!NT_SUCCESS(Fn_ReadBuffer(fileHandle, &fileBuffer)))	return;

		// copy contents
		auto dos_header = reinterpret_cast<IMAGE_DOS_HEADER*>
			((uintptr_t)fileBuffer);
		if (dos_header->e_magic != IMAGE_DOS_SIGNATURE) {
			DbgPrint("Invalid DOS header.\n");
			return;
		}

		auto nt_headers = reinterpret_cast<IMAGE_NT_HEADERS*>
			((uintptr_t)fileBuffer + dos_header->e_lfanew);
		if (nt_headers->Signature != IMAGE_NT_SIGNATURE) {
			DbgPrint("Invalid NT signature.\n");
			return;
		}

		DbgPrint("Passed all checks\n");
		ExFreePoolWithTag(fileBuffer, DPC_MAP_TAG);

		return;
	}


	NTSTATUS Fn_WorkItem(_In_ PDEVICE_OBJECT DeviceObject) {
		auto workItem = reinterpret_cast

		return STATUS_SUCCESS;
	}
}