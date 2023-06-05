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
					drv_name)) {
					drv_base = pBuf->Modules[idx].ImageBase;
					break;
				}
			}

			ExFreePoolWithTag(pBuf, 0x41414141);
			return drv_base;
		}

		return nullptr;
	}
}