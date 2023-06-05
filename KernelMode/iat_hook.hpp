#pragma once
#include "Header.hpp"

namespace IATHook {

	using uint64_t = UINT64;
	using uint32_t = UINT32;
	using BYTE = unsigned char;

	inline wchar_t drvName[] = L"Test.sys";

	auto NotifyRoutine(_In_opt_ PUNICODE_STRING FullImageName, HANDLE ProcessId, PIMAGE_INFO ImageInfo) -> void {
		if (FullImageName && wcsstr(FullImageName->Buffer, drvName)) {
			DbgPrint(">==================== Driver %wZ ===================<\n", FullImageName);
			IATHook(ImageInfo->ImageBase)
		}
	}

	auto GetDriverBase(_In_ CHAR*)->PVOID;

	auto IATHook(_In_ PVOID, _In_ uint64_t) -> void;

	auto Fn_MmGetSystemRoutineAddress(_In_ PUNICODE_STRING)->PVOID;
}