#pragma once
#include "Header.hpp"

namespace Pool {

#define IOCTL_POOL CTL_CODE(FILE_DEVICE_UNKNOWN, 0x900, METHOD_BUFFERED, FILE_READ_ACCESS | FILE_WRITE_ACCESS)

	typedef struct _SYSTEM_POOLTAG {
		union {
			UCHAR Tag[4];
			ULONG TagUlong;
		};
		ULONG PagedAllocs;
		ULONG PagedFrees;
		ULONG_PTR PagedUsed;
		ULONG NonPagedAllocs;
		ULONG NonPagedFrees;
		ULONG_PTR NonPagedUsed;
	} SYSTEM_POOLTAG, *PSYSTEM_POOLTAG;

	typedef struct _SYSTEM_POOLTAG_INFORMATION {
		ULONG Count;
		SYSTEM_POOLTAG TagInfo[ANYSIZE_ARRAY];
	} SYSTEM_POOLTAG_INFORMATION, *PSYSTEM_POOLTAG_INFORMATION;

	typedef struct _SYSTEM_BIGPOOL_ENTRY {
		union {
			PVOID VirtualAddress;
			ULONG_PTR NonPaged : 1;
		};
		ULONG_PTR SizeInBytes;
		union {
			UCHAR Tag[4];
			ULONG TagUlong;
		};
	} SYSTEM_BIGPOOL_ENTRY, PSYSTEM_BIGPOOL_ENTRY;

	typedef struct _SYSTEM_BIGPOOL_INFORMATION {
		ULONG Count;
		SYSTEM_BIGPOOL_ENTRY AllocatedInfo[ANYSIZE_ARRAY];
	} SYSTEM_BIGPOOL_INFORMATION, *PSYSTEM_BIGPOOL_INFORMATION;

	NTSTATUS GetPoolTagInfo(PSYSTEM_POOLTAG_INFORMATION*);
	NTSTATUS PrintPoolInfo(SYSTEM_POOLTAG_INFORMATION*);

	NTSTATUS GetBigPoolInfo(PSYSTEM_BIGPOOL_INFORMATION*);
	NTSTATUS PrintBigPoolInfo(SYSTEM_BIGPOOL_INFORMATION*);
};