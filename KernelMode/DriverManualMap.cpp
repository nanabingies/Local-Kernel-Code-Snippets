#include "DriverManualMap.hpp"
#pragma warning(disable : 4100)

namespace DriverManualMap {

	
	VOID ManualMap(_In_ PVOID IoObject, _In_opt_ PVOID Context, _In_ PIO_WORKITEM IoWorkItem) {

		DbgPrint("[%s] => \n", __FUNCTION__);

		HANDLE fileHandle{};
		UNICODE_STRING fileName{};
		IO_STATUS_BLOCK ioBlock{};
		OBJECT_ATTRIBUTES oa{};
		LARGE_INTEGER byteOffset = { 0 };

		RtlInitUnicodeString(&fileName, L"\\DosDevices\\C:\\Users\\nana\\Desktop\\TestDriver.sys");
		InitializeObjectAttributes(&oa, &fileName, OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, nullptr, nullptr);
		auto ns = ZwCreateFile(&fileHandle, FILE_READ_ATTRIBUTES, &oa, &ioBlock, nullptr,
			FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ, FILE_OPEN, FILE_SYNCHRONOUS_IO_NONALERT, nullptr, 0);
		if (!NT_SUCCESS(ns)) {
			DbgPrint("Failed to open file %wZ for reading.\n", &fileName);
			DbgPrint("Exiting with error code %X\n", ns);
			return;
		}

		PVOID fileObject;
		ns = ObReferenceObjectByHandle(fileHandle, FILE_READ_ACCESS, nullptr, KernelMode, &fileObject, nullptr);
		DbgPrint("FileHandle : %p | fileObject : %p\n", fileHandle, fileObject);
		

		auto fileInfo = reinterpret_cast<FILE_STANDARD_INFORMATION*>
			(ExAllocatePoolWithTag(NonPagedPoolNx, sizeof(FILE_STANDARD_INFORMATION), MAP_TAG));
		if (fileInfo == nullptr) {
			DbgPrint("[-] Failed to allocate memory for querying file information.\n");
			return;
		}
		ns = ZwQueryInformationFile(fileHandle, &ioBlock, fileInfo, sizeof(FILE_STANDARD_INFORMATION), FileStandardInformation);
		if (!NT_SUCCESS(ns)) {
			DbgPrint("ZwQueryInformationFile failed. Exiting with error %X\n", ns);
			return;
		}

		auto fileSize = fileInfo->EndOfFile.QuadPart * sizeof(PVOID);

		auto fileBuffer = reinterpret_cast<BYTE*>
			(ExAllocatePoolWithTag(NonPagedPool, fileSize, MAP_TAG));
		if (fileBuffer == nullptr) {
			DbgPrint("Failed to allocate memory for storing file contents.\n");
			return;
		}

		ns = ZwReadFile(fileHandle, nullptr, nullptr, nullptr, &ioBlock, fileBuffer, (ULONG)fileSize, &byteOffset, nullptr);
		if (!NT_SUCCESS(ns)) {
			DbgPrint("ZwReadFile failed with error status : %X\n", ns);
			return;
		}
		DbgPrint("File Buffer is at 0x%p with size : %llX\n", fileBuffer, fileSize);

		ExFreePoolWithTag(fileInfo, MAP_TAG);

		// validate PE headers
		auto dos_header = reinterpret_cast<IMAGE_DOS_HEADER*>((uintptr_t)fileBuffer);
		if (dos_header->e_magic != IMAGE_DOS_SIGNATURE) {
			DbgPrint("Invalid DOS header.\n");
			return;
		}

		auto nt_headers = reinterpret_cast<IMAGE_NT_HEADERS*>((uintptr_t)fileBuffer + dos_header->e_lfanew);
		if (nt_headers->Signature != IMAGE_NT_SIGNATURE) {
			DbgPrint("Invalid NT signature.\n");
			return;
		}

		const auto aligned_image_size = (nt_headers->OptionalHeader.SizeOfImage & ~(0x1000 - 0x1)) + 0x1000;
		
		// allocate memory to map file contents
		auto remoteMemory = reinterpret_cast<BYTE*>
			(ExAllocatePoolWithTag(NonPagedPool, aligned_image_size, MAP_TAG));
		if (remoteMemory == nullptr) return;
		RtlZeroMemory(remoteMemory, aligned_image_size);

		// copy image headers to remote memory
		RtlCopyMemory(remoteMemory, fileBuffer, nt_headers->OptionalHeader.SizeOfHeaders);
		DbgPrint("Copied image headers to remote base.\n");

		// copy section headers
		auto sections = IMAGE_FIRST_SECTION(nt_headers);
		for (auto idx = 0; idx < nt_headers->FileHeader.NumberOfSections; ++idx) {
			if (sections->SizeOfRawData > 0) {
				auto section_base = remoteMemory + sections->VirtualAddress;
				auto section_addr = fileBuffer + sections->PointerToRawData;
				RtlCopyMemory(section_base, section_addr, sections->SizeOfRawData);
				
			}
			sections++;
		}
		DbgPrint("Copied section headers to remote base.\n");

		// copy import functions to remote memory
		auto importsRVA = nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
		auto imports = reinterpret_cast<IMAGE_IMPORT_DESCRIPTOR*>(remoteMemory + importsRVA);
		for (; imports->Name != NULL; imports++) {
			auto name = reinterpret_cast<char*>(remoteMemory + imports->Name);
			auto nameAddress = GetModuleBaseAddress(name);

			PIMAGE_THUNK_DATA firstThunk = (PIMAGE_THUNK_DATA)(remoteMemory + imports->FirstThunk);
			PIMAGE_THUNK_DATA originalFirstThunk = (PIMAGE_THUNK_DATA)(remoteMemory + imports->OriginalFirstThunk);

			for (; firstThunk->u1.AddressOfData; ++firstThunk, ++originalFirstThunk) {
				auto importName = reinterpret_cast<CHAR*>(((PIMAGE_IMPORT_BY_NAME)
					(remoteMemory + originalFirstThunk->u1.AddressOfData))->Name);
				ULONG64 import = GetExport((PBYTE)nameAddress, importName);
				if (!import) {
					DbgPrint("Failed to find export %s in module %s\n", importName, nameAddress);
					return;
				}

				firstThunk->u1.Function = import;
			}
		}
		DbgPrint("Done imports relocations.\n");

		auto baseRelocDir = reinterpret_cast<IMAGE_DATA_DIRECTORY*>(&nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC]);
		if (baseRelocDir->VirtualAddress) {
			PIMAGE_BASE_RELOCATION reloc = (PIMAGE_BASE_RELOCATION)(remoteMemory + baseRelocDir->VirtualAddress);

			for (UINT32 currentSize = 0; currentSize < baseRelocDir->Size; ) {
				ULONG relocCount = (reloc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(USHORT);
				PUSHORT relocData = (PUSHORT)((PBYTE)reloc + sizeof(IMAGE_BASE_RELOCATION));
				PBYTE relocBase = remoteMemory + reloc->VirtualAddress;

				for (UINT32 i = 0; i < relocCount; ++i, ++relocData) {
					USHORT data = *relocData;
					USHORT type = data >> 12;
					USHORT offset = data & 0xFFF;

					switch (type) {
					case IMAGE_REL_BASED_ABSOLUTE:
						break;
					case IMAGE_REL_BASED_DIR64: {
						PULONG64 rva = (PULONG64)(relocBase + offset);
						*rva = (ULONG64)(remoteMemory + (*rva - nt_headers->OptionalHeader.ImageBase));
						break;
					}
					default:
						return;
					}
				}

				currentSize += reloc->SizeOfBlock;
				reloc = (PIMAGE_BASE_RELOCATION)relocData;
			}
		}
		DbgPrint("Done base relocations.\n");

		auto driver_entry = remoteMemory + nt_headers->OptionalHeader.AddressOfEntryPoint;
		((PDRIVER_INITIALIZE)(driver_entry))(reinterpret_cast<PDRIVER_OBJECT>(remoteMemory), nullptr);


		DbgPrint("Passed all checks\n");
		ExFreePoolWithTag(fileBuffer, MAP_TAG);
		DbgPrint("[%s] <= \n", __FUNCTION__);

		return;
	}


	NTSTATUS Fn_WorkItem(_In_ PDEVICE_OBJECT DeviceObject) {
		DbgPrint("[%s] => \n", __FUNCTION__);
		auto workItem = IoAllocateWorkItem(DeviceObject);
		if (workItem == nullptr) {
			DbgPrint("IoAllocateWorkItem failed.\n");
			return STATUS_INSUFFICIENT_RESOURCES;
		}

		IoQueueWorkItemEx(workItem, ManualMap, DelayedWorkQueue, nullptr);

		LARGE_INTEGER interval{};
		interval.QuadPart = -1000 * 100;
		KeDelayExecutionThread(KernelMode, FALSE, &interval);
		IoFreeWorkItem(workItem);
		DbgPrint("[%s] <= \n", __FUNCTION__);

		return STATUS_SUCCESS;
	}


	PVOID GetModuleBaseAddress(PCHAR name) {
		PVOID addr = 0;

		ULONG size = 0;
		NTSTATUS status = ZwQuerySystemInformation(SystemModuleInformation, 0, 0, &size);
		if (status != STATUS_INFO_LENGTH_MISMATCH) {
			DbgPrint("ZwQuerySystemInformation for size failed: %x\n", status);
			return addr;
		}

		PSYSTEM_MODULE_INFORMATION modules = (PSYSTEM_MODULE_INFORMATION)ExAllocatePool(NonPagedPool, size);
		if (!modules) {
			DbgPrint("Failed to allocate %d bytes for modules\n", size);
			return addr;
		}

		if (!NT_SUCCESS(status = ZwQuerySystemInformation(SystemModuleInformation, modules, size, 0))) {
			DbgPrint("ZwQuerySystemInformation failed: %x\n", status);
			ExFreePool(modules);
			return addr;
		}

		for (ULONG i = 0; i < modules->NumberOfModules; ++i) {
			SYSTEM_MODULE m = modules->Modules[i];
			if (strstr((PCHAR)m.FullPathName, name)) {
				addr = m.ImageBase;
				break;
			}
		}

		ExFreePool(modules);
		return addr;
	}


	using PWORD = WORD*;
	ULONG64 GetExport(PBYTE base, PCHAR exportName) {
		PIMAGE_DOS_HEADER dosHeaders = (PIMAGE_DOS_HEADER)base;
		if (dosHeaders->e_magic != IMAGE_DOS_SIGNATURE) {
			return 0;
		}

		PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)(base + dosHeaders->e_lfanew);

		ULONG exportsRva = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
		if (!exportsRva)
			return 0;

		PIMAGE_EXPORT_DIRECTORY exports = (PIMAGE_EXPORT_DIRECTORY)(base + exportsRva);
		PULONG nameRva = (PULONG)(base + exports->AddressOfNames);

		for (ULONG i = 0; i < exports->NumberOfNames; ++i) {
			PCHAR func = (PCHAR)(base + nameRva[i]);
			if (strcmp(func, (PCHAR)exportName) == 0) {
				PULONG funcRva = (PULONG)(base + exports->AddressOfFunctions);
				PWORD ordinalRva = (PWORD)(base + exports->AddressOfNameOrdinals);

				return (ULONG64)(base + funcRva[ordinalRva[i]]);
			}
		}

		return 0;
	}
}