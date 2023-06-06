#include "iat_hook.hpp" 
#pragma warning(disable : 6387)

namespace IATHook {

	UNICODE_STRING dbg = RTL_CONSTANT_STRING(L"[IATHook] ");

	wchar_t drvName[] = L"x64KMDFDriver.sys";

	auto WPOff() -> void {
		auto cr0 = __readcr0();
		cr0 &= 0xfffffffffffeffff;
		__writecr0(cr0);
		_disable();
	}

	auto WPOn() -> void {
		auto cr0 = __readcr0();
		cr0 |= 0x10000;
		_enable();
		__writecr0(cr0);
	}

	auto NotifyRoutine(_In_opt_ PUNICODE_STRING FullImageName, HANDLE ProcessId, PIMAGE_INFO ImageInfo) -> void {
		UNREFERENCED_PARAMETER(ProcessId);

		if (FullImageName && wcsstr(FullImageName->Buffer, drvName)) {
			DbgPrint(">==================== Driver %wZ ===================<\n", FullImageName);
			IATHook(ImageInfo->ImageBase, "MmGetSystemRoutineAddress", &Fn_MmGetSystemRoutineAddress);
		}
	}

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

		auto import_offset = nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
		auto imports = reinterpret_cast<IMAGE_IMPORT_DESCRIPTOR*>(base + import_offset);
		if (imports == nullptr)	return;

		for (auto idx = 0; imports->Name != NULL64; idx++, imports++) {
			auto libraryName = reinterpret_cast<char*>(base + imports->Name);
			DbgPrint("[*] libraryName : %s\n", libraryName);
			if (GetDriverBase(libraryName)) {
				auto firstThunk = reinterpret_cast<IMAGE_THUNK_DATA*>(base + imports->FirstThunk);
				auto originalFirstThunk = reinterpret_cast<IMAGE_THUNK_DATA*>(base + imports->OriginalFirstThunk);

				while (originalFirstThunk->u1.AddressOfData != NULL64) {
					auto funcName = reinterpret_cast<IMAGE_IMPORT_BY_NAME*>(base + originalFirstThunk->u1.AddressOfData);
					if (strcmp(funcName->Name, FuncName) == 0) {
						DbgPrint("\t[>] funcName : %s\n", funcName->Name);
						DbgPrint("[*] Found it!!!!!\n");
						// Disable Write Protection
						WPOff();

						firstThunk->u1.Function = reinterpret_cast<uint64_t>(HookFunction);

						// Enable Write Protection
						WPOn();
						break;
					}
					++firstThunk;
					++originalFirstThunk;
				}
			}
		}
	}

	auto Fn_MmGetSystemRoutineAddress(_In_ PUNICODE_STRING RoutineName) -> PVOID {
		DbgPrint("%wZ RoutineName : %wZ\n", &dbg, RoutineName);

		if (wcsstr(RoutineName->Buffer, L"ZwAllocateVirtualMemory")) {
			DbgPrint("[%s] Hooked ZwAllocateVirtualMemory\n", __FUNCTION__);
			return &gh_ZwAllocateVirtualMemory;
		}

		if (wcsstr(RoutineName->Buffer, L"MmIsAddressValid")) {
			DbgPrint("[%s] Hooked MmIsAddressValid\n", __FUNCTION__);
			return &gh_MmIsAddressValid;
		}

		if (wcsstr(RoutineName->Buffer, L"IoCreateDevice")) {
			DbgPrint("[%s] Hooked IoCreateDevice\n", __FUNCTION__);
			return &gh_IoCreateDevice;
		}

		if (wcsstr(RoutineName->Buffer, L"MmGetPhysicalAddress")) {
			DbgPrint("[%s] Hooked MmGetPhysicalAddress\n", __FUNCTION__);
			return &gh_MmGetPhysicalAddress;
		}

		if (wcsstr(RoutineName->Buffer, L"MmMapIoSpace")) {
			DbgPrint("[%s] Hooked MmMapIoSpace\n", __FUNCTION__);
			return &gh_MmMapIoSpace;
		}

		if (wcsstr(RoutineName->Buffer, L"ZwOpenFile")) {
			DbgPrint("[%s] Hooked ZwOpenFile\n", __FUNCTION__);
			return &gh_ZwOpenFile;
		}

		if (wcsstr(RoutineName->Buffer, L"KeStackAttachProcess")) {
			DbgPrint("[%s] Hooked ObReferenceObjectByHandle\n", __FUNCTION__);
			return &gh_KeStackAttachProcess;
		}

		if (wcsstr(RoutineName->Buffer, L"DbgPrint")) {
			DbgPrint("[%s] Hooked DbgPrint\n", __FUNCTION__);
			return &gh_DbgPrint;
		}

		if (wcsstr(RoutineName->Buffer, L"ZwMapViewOfSection")) {
			DbgPrint("[%s] Hooked ZwMapViewOfSection\n", __FUNCTION__);
			return &gh_ZwMapViewOfSection;
		}

		if (wcsstr(RoutineName->Buffer, L"ZwCreateSection")) {
			DbgPrint("[%s] Hooked ZwCreateSection\n", __FUNCTION__);
			return &gh_ZwCreateSection;
		}

		return MmGetSystemRoutineAddress(RoutineName);
	}

	auto gh_ZwAllocateVirtualMemory(_In_    HANDLE    ProcessHandle,
		_Inout_ PVOID* BaseAddress,
		_In_    ULONG_PTR ZeroBits,
		_Inout_ PSIZE_T   RegionSize,
		_In_    ULONG     AllocationType,
		_In_    ULONG     Protect) -> NTSTATUS {

		DbgPrint("[>] %s => \n", __FUNCTION__);

		DbgPrint("\t[*] ProcessHandle : %p\n", ProcessHandle);
		DbgPrint("\t[*] BaseAddress : %p\n", *BaseAddress);
		DbgPrint("\t[*] RegionSize : 0x%p\n", RegionSize);
		DbgPrint("\t[*] AllocationType : %lx\n", AllocationType);
		DbgPrint("\t[*] Protect : %lx\n", Protect);

		DbgPrint("[>] %s <= \n", __FUNCTION__);

		return ZwAllocateVirtualMemory(ProcessHandle, BaseAddress, ZeroBits, RegionSize, AllocationType, Protect);
	}

	auto gh_MmIsAddressValid(PVOID VirtualAddress) -> BOOLEAN {
		DbgPrint("[>] %s => \n", __FUNCTION__);

		DbgPrint("\t[*] VirtualAddress : %p\n", VirtualAddress);

		DbgPrint("[>] %s <= \n", __FUNCTION__);

		return MmIsAddressValid(VirtualAddress);
	}

	auto gh_IoCreateDevice(PDRIVER_OBJECT  DriverObject,
		ULONG           DeviceExtensionSize,
		PUNICODE_STRING DeviceName,
		DEVICE_TYPE     DeviceType,
		ULONG           DeviceCharacteristics,
		BOOLEAN         Exclusive,
		PDEVICE_OBJECT* DeviceObject) -> NTSTATUS {

		DbgPrint("[>] %s => \n", __FUNCTION__);

		DbgPrint("\t[*] DriverObject : %llx\n", reinterpret_cast<uint64_t>(DriverObject));
		DbgPrint("\t[*] DeviceName : %wZ\n", DeviceName);
		DbgPrint("\t[*] DeviceObject : %llx\n", reinterpret_cast<uint64_t>(DeviceObject));

		DbgPrint("[>] %s <= \n", __FUNCTION__);

		return IoCreateDevice(DriverObject, DeviceExtensionSize, DeviceName, DeviceType, DeviceCharacteristics, Exclusive, DeviceObject);
	}

	auto gh_MmGetPhysicalAddress(PVOID BaseAddress) -> PHYSICAL_ADDRESS {
		DbgPrint("[>] %s => \n", __FUNCTION__);

		DbgPrint("\t[*] BaseAddress : %p\n", BaseAddress);

		DbgPrint("[>] %s <= \n", __FUNCTION__);

		return MmGetPhysicalAddress(BaseAddress);
	}

	auto gh_MmMapIoSpace(PHYSICAL_ADDRESS    PhysicalAddress,
		SIZE_T              NumberOfBytes,
		MEMORY_CACHING_TYPE CacheType) -> PVOID {

		DbgPrint("[>] %s => \n", __FUNCTION__);

		DbgPrint("\t[*] PhysicalAddress : %llx\n", PhysicalAddress.QuadPart);
		DbgPrint("\t[*] NumberOfBytes : %llx\n", NumberOfBytes);
		DbgPrint("\t[*] CacheType : %lx\n", CacheType);

		DbgPrint("[>] %s <= \n", __FUNCTION__);

		return MmMapIoSpace(PhysicalAddress, NumberOfBytes, CacheType);
	}

	auto gh_ZwOpenFile(PHANDLE            FileHandle,
		ACCESS_MASK        DesiredAccess,
		POBJECT_ATTRIBUTES ObjectAttributes,
		PIO_STATUS_BLOCK   IoStatusBlock,
		ULONG              ShareAccess,
		ULONG              OpenOptions) -> NTSTATUS {

		DbgPrint("[>] %s => \n", __FUNCTION__);

		DbgPrint("\t[*] FileHandle : %p\n", FileHandle);
		DbgPrint("\t[*] ObjectName : %wZ\n", ObjectAttributes->ObjectName);

		DbgPrint("[>] %s <= \n", __FUNCTION__);

		return ZwOpenFile(FileHandle, DesiredAccess, ObjectAttributes, IoStatusBlock, ShareAccess, OpenOptions);
	}

	auto gh_KeStackAttachProcess(PRKPROCESS   PROCESS,
		PRKAPC_STATE ApcState) -> VOID {
		DbgPrint("[>] %s => \n", __FUNCTION__);

		DbgPrint("\t[*] PROCESS : %llx\n", reinterpret_cast<uint64_t>(PROCESS));
		DbgPrint("\t[*] ApcState : %p\n", ApcState);

		DbgPrint("[>] %s <= \n", __FUNCTION__);

		return KeStackAttachProcess(PROCESS, ApcState);
	}

	auto gh_DbgPrint() -> ULONG {

	}
}