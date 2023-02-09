#pragma once
#include "Header.hpp"

namespace Pool {

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

	NTSTATUS GetPoolTagInfo(PSYSTEM_POOLTAG_INFORMATION*);
	NTSTATUS PrintPoolInfo(SYSTEM_POOLTAG_INFORMATION*);
};