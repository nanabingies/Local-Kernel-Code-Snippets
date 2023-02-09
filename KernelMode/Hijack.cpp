#include "Hijack.hpp"

namespace Hijack {

	NTSTATUS DriverHijack::DriverInitialization(_In_ PCWSTR DriverName) {

		RtlInitUnicodeString(&_DriverName, DriverName);
		auto ns = IoGetDeviceObjectPointer(&_DriverName, FILE_ALL_ACCESS, FileObject, &_DeviceObject);
		if (!NT_SUCCESS(ns)) {
			DbgPrint("[%s] Constructor failed with error code : %X\n", __FUNCTION__, ns);
			return ns;
		}

		_DriverObject = _DeviceObject->DriverObject;
	}
}