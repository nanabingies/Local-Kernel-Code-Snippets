#include "KernelHook.hpp"

namespace KernelHook {

	pZwReadFile OriginalZwReadFile{};

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

		return OriginalZwReadFile(FileHandle, Event, ApcRoutine, ApcContext, IoStatusBlock, Buffer, Length, ByteOffset, Key);
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

	}
}