#include "Header.hpp"
#include "Pool.hpp"
#pragma warning(disable : 6387)

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

		ExFreePoolWithTag(Buffer, POOLTAGINFO);
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

	//
	// Return a buffer containing BigPool Information
	//
	NTSTATUS GetBigPoolInfo(PSYSTEM_BIGPOOL_INFORMATION* pBigPool) {
		ULONG ReturnLength = 0;
		ZwQuerySystemInformation(SystemBigPoolInformation, NULL, 0, &ReturnLength);
		auto Buffer = ExAllocatePoolWithTag(NonPagedPoolNx, ReturnLength, POOLTAGINFO);
		if (Buffer == __nullptr) {
			DbgPrint("[%s] ExAllocatePoolWithTag failed\n", __FUNCTION__);
			return STATUS_INSUFFICIENT_RESOURCES;
		}

		ZwQuerySystemInformation(SystemBigPoolInformation, Buffer, ReturnLength, &ReturnLength);
		*pBigPool = reinterpret_cast<SYSTEM_BIGPOOL_INFORMATION*>(Buffer);

		ExFreePoolWithTag(Buffer, POOLTAGINFO);
		return STATUS_SUCCESS;
	}

	NTSTATUS PrintBigPoolInfo(SYSTEM_BIGPOOL_INFORMATION* BigPool) {
		
		auto Ptr = BigPool;
		auto count = BigPool->Count;
		ULONG i = 0;

		do {
			auto Tag = Ptr->AllocatedInfo[i].Tag;
			auto TagUlong = Ptr->AllocatedInfo[i].TagUlong;
			auto SizeInBytes = Ptr->AllocatedInfo[i].SizeInBytes;
			auto VirtualAddress = Ptr->AllocatedInfo[i].VirtualAddress;

			DbgPrint("\t[+] VirtualAddress : %p ; SizeInBytes : %llX Tag : %s ; TagUlong : %X\n",
				VirtualAddress, SizeInBytes, Tag, TagUlong);
			++i;
			--count;
		} while (i < count);

		return STATUS_SUCCESS;
	}
};