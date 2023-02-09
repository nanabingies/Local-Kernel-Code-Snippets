#include "Header.hpp"
#include "Pool.hpp"

namespace Pool {

	//
	//  Return a buffer pointing to the pooltaginfo
	//
	NTSTATUS GetPoolTagInfo(PSYSTEM_POOLTAG_INFORMATION* pPoolTagInfo) {

		ULONG ReturnLength = 0;
		ZwQuerySystemInformation(SystemPoolTagInformation, NULL, 0, &ReturnLength);
		auto Buffer = ExAllocatePoolWithTag(NonPagedPoolNx, ReturnLength, POOLTAGINFO);
		if (Buffer == __nullptr) {
			DbgPrint("[%s] ExAllocatePoolWithTag failed\n", __FUNCTION__);
			return STATUS_INSUFFICIENT_RESOURCES;
		}

		ZwQuerySystemInformation(SystemPoolTagInformation, Buffer, ReturnLength, &ReturnLength);
		*pPoolTagInfo = reinterpret_cast<SYSTEM_POOLTAG_INFORMATION*>(Buffer);

		return STATUS_SUCCESS;
	}

	//
	// Given a buffer pointing to a list of pooltaginfo structures,
	// print them all out with aditional information.
	//
	NTSTATUS PrintPoolInfo(SYSTEM_POOLTAG_INFORMATION* pPoolTagInfo) {

		auto Ptr = pPoolTagInfo;
		auto count = pPoolTagInfo->Count;
		ULONG i = 0;

		do {
			auto PoolTag = Ptr->TagInfo[i].Tag;
			DbgPrint("\t[+] Tag : %s\n", PoolTag);
			++i;
			--count;
		} while (i < count);

		return STATUS_SUCCESS;
	}
};