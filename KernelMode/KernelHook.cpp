#include "KernelHook.hpp"

namespace KernelHook {

	pZwReadFile OriginalZwReadFile{};
	unsigned char OrigAddress[0x10] = { 0 };

	CHAR shell_code[] = {
		// push rcx
		0x51,

		// movabs rcx, 0xOurFuncAddress (push into register as 64-bit value)
		0x48, 0xB9,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,

		// xchg QWORD PTR [rsp], rcx (transpose operand)
		0x48, 0x87, 0x0C, 0x24,

		// ret
		0xC3
	};

	NTSTATUS HookZwReadFile(_In_ HANDLE           FileHandle,
		_In_opt_ HANDLE           Event,
		_In_opt_ PIO_APC_ROUTINE  ApcRoutine,
		_In_opt_ PVOID            ApcContext,
		_Out_ PIO_STATUS_BLOCK IoStatusBlock,
		_Out_ PVOID            Buffer,
		_In_ ULONG            Length,
		_In_opt_ PLARGE_INTEGER   ByteOffset,
		_In_opt_ PULONG           Key) {
		DbgPrint("[%s] ==> \n", __FUNCTION__);

		DbgPrint("\t[>] FileHandle : %p\n", FileHandle);
		DbgPrint("\t[>] Event : %p\n", Event);
		DbgPrint("\t[>] ApcRoutine : %p\n", ApcRoutine);
		DbgPrint("\t[>] ApcContext : %p\n", ApcContext);

		DbgPrint("[%s] <== \n", __FUNCTION__);

		//return OriginalZwReadFile(FileHandle, Event, ApcRoutine, ApcContext, IoStatusBlock, Buffer, Length, ByteOffset, Key);
		return STATUS_SUCCESS;
	}

	template <typename T>
	NTSTATUS PrepareMdl(_In_ T RoutineAddress, _Out_ PMDL* Mdl) {
		*Mdl = { 0 };

		*Mdl = IoAllocateMdl(RoutineAddress, sizeof(T), FALSE, FALSE, NULL);
		if (*Mdl == __nullptr) {
			DbgPrint("[-] IoAllocateMdl failed\n");
			return STATUS_UNSUCCESSFUL;
		}

		MmBuildMdlForNonPagedPool(*Mdl);

		// Lock pages in memory
		MmProbeAndLockPages(*Mdl, KernelMode, IoModifyAccess);
		return STATUS_SUCCESS;
	}

	template <typename T>
	NTSTATUS SetupHook(_In_ T RoutineAddress, _In_ PMDL Mdl, _Out_ T* VirtualAddress) {

		*VirtualAddress = MmMapLockedPagesSpecifyCache(Mdl, KernelMode, MmNonCached, NULL, 0, NormalPagePriority);
		if (*VirtualAddress == __nullptr) {
			DbgPrint("[-] MmMapLockedPagesSpecifyCache failed.\n");
			return STATUS_INSUFFICIENT_RESOURCES;
		}

		MmProtectMdlSystemAddress(Mdl, PAGE_EXECUTE_READWRITE);

		uintptr_t HookAddress = &HookZwReadFile;
		RtlCopyMemory(&shell_code[0x3], &HookAddress, sizeof(uintptr_t));

		__try {
			// try and change address
			RtlCopyMemory(&(*VirtualAddress), &shell_code, sizeof(shell_code));
		}
		__except (EXCEPTION_EXECUTE_HANDLER) {
			DbgPrint("[-] Failed to write shellcode to memory\n");
			return STATUS_UNSUCCESSFUL;
		}

		return STATUS_SUCCESS;
	}

	template <typename T>
	NTSTATUS PrepareAddress(_In_ PWSTR RoutineName, _Out_ T* RoutineAddress) {
		UNICODE_STRING usRoutineName{};
		RtlInitUnicodeString(&usRoutineName, RoutineName);

		*RoutineAddress = 0;
		*RoutineAddress = MmGetSystemRoutineAddress(&usRoutineName);
		if (*RoutineAddress == __nullptr) {
			DbgPrint("[-] MmGetSystemRoutineAddress failed.\n");
			return STATUS_NOT_FOUND;
		}

		/*SIZE_T NumberOfBytesTransferred = 0;
		MM_COPY_ADDRESS CopyAddress{};
		CopyAddress.VirtualAddress = *RoutineAddress;
		auto ns = MmCopyMemory(&OrigAddress, CopyAddress, sizeof(OrigAddress), MM_COPY_MEMORY_VIRTUAL, &NumberOfBytesTransferred);
		if (!NT_SUCCESS(ns) || NumberOfBytesTransferred != sizeof(OrigAddress)) {
			DbgPrint("[-] MmCopyMemory failed.\n");
			return ns;
		}*/
		RtlCopyMemory(&OrigAddress, *RoutineAddress, sizeof(OrigAddress));

		return STATUS_SUCCESS;
	}

	NTSTATUS RestoreAddress(_In_ PVOID RoutineAddress) {
		RtlCopyMemory(RoutineAddress, OrigAddress, sizeof(OrigAddress));
		return STATUS_SUCCESS;
	}
}