#include "iat_hook.hpp"

namespace IATHook {

	auto GetDriverBase(_In_ LPCSTR drv_name) -> PVOID {
		if (strlen(drv_name) == 0)	return nullptr;

		PVOID drv_base = 0;
		ULONG ReturnLength = 0;
		auto ns = ZwQuerySystemInformation(SystemModuleInformation, nullptr, 0, &ReturnLength);
		if (ns == STATUS_INFO_LENGTH_MISMATCH) {
			auto pBuf = reinterpret_cast<SYSTEM_MODULE_INFORMATION*>
				(ExAllocatePoolWithTag(NonPagedPoolNx, ReturnLength, 0x41414141));
			if (pBuf == nullptr)	return nullptr;

			ns = ZwQuerySystemInformation(SystemModuleInformation, pBuf, ReturnLength, &ReturnLength);
			if (!NT_SUCCESS(ns))	return nullptr;

			for (ULONG idx = 0; idx < pBuf->NumberOfModules; idx++) {
				if (strcmp(reinterpret_cast<const char*>(pBuf->Modules[idx].FullPathName + pBuf->Modules[idx].OffsetToFileName),
					drv_name) == 0) {
					drv_base = pBuf->Modules[idx].ImageBase;
					break;
				}
			}

			ExFreePoolWithTag(pBuf, 0x41414141);
			return drv_base;
		}

		return nullptr;
	}

	auto IATHook(_In_ PVOID ImageBase, _In_ LPCSTR FuncName, _In_ PVOID HookFunction) -> void {
		if (ImageBase == nullptr)	return;

		auto base = reinterpret_cast<uint64_t>(ImageBase);

		auto dos_header = reinterpret_cast<IMAGE_DOS_HEADER*>(base);
		if (dos_header->e_magic != IMAGE_DOS_SIGNATURE) {
			DbgPrint("[%s] Image verification failed.\n", __FUNCTION__);
			return;
		}

		auto nt_headers = reinterpret_cast<IMAGE_NT_HEADERS*>(base + dos_header->e_lfanew);
		if (nt_headers->Signature != IMAGE_NT_SIGNATURE) {
			DbgPrint("[%s] NT verification failed.\n", __FUNCTION__);
			return;
		}

		auto export_offset = nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
		auto exports = reinterpret_cast<IMAGE_EXPORT_DIRECTORY*>(base + export_offset);
		
		auto names = reinterpret_cast<uint32_t*>(base + exports->AddressOfNames);
		auto functions = reinterpret_cast<uint32_t*>(base + exports->AddressOfFunctions);
		auto ordinals = reinterpret_cast<uint32_t*>(base + exports->AddressOfNameOrdinals);

		for (auto idx = 0; idx < exports->NumberOfNames; idx++) {
			auto export_name = reinterpret_cast<char*>(base + names[idx]);
			if (strcmp(export_name, FuncName) == 0) {

			}
		}
	}
}