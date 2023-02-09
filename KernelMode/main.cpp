#include "Header.hpp"
#include "Pool.hpp"
#include "Hijack.hpp"
#pragma warning(disable : 4100)

EXTERN_C NTSTATUS DriverEntry(_In_ PDRIVER_OBJECT DriverObject, _In_ PUNICODE_STRING RegistryPath) {

	UNICODE_STRING DosDeviceName = RTL_CONSTANT_STRING(DOSDEVICE_NAME);
	UNICODE_STRING DriverName = RTL_CONSTANT_STRING(DRIVER_NAME);

	PDEVICE_OBJECT DeviceObject{};

	auto ns = IoCreateDevice(DriverObject, 0, &DriverName, FILE_DEVICE_UNKNOWN, FILE_DEVICE_SECURE_OPEN,
		FALSE, (PDEVICE_OBJECT*)&DeviceObject);
	if (!NT_SUCCESS(ns)) {
		DbgPrint("[-] IoCreateDevice failed.\n");
		return STATUS_FAILED_DRIVER_ENTRY;
	}

	ns = IoCreateSymbolicLink(&DosDeviceName, &DriverName);
	if (!NT_SUCCESS(ns)) {
		DbgPrint("[-] IoCreateSymbolicLink failed.\n");
		IoDeleteDevice(DeviceObject);
		return STATUS_FAILED_DRIVER_ENTRY;
	}

	for (auto idx = 0; idx < IRP_MJ_MAXIMUM_FUNCTION; ++idx) {
		DriverObject->MajorFunction[idx] = DefaultDispatch;
	}
	DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = IoctlDispatch;
	DriverObject->DriverUnload = DriverUnload;

	DriverObject->Flags &= ~DO_DEVICE_INITIALIZING;
	DriverObject->Flags |= DO_BUFFERED_IO;

	auto hijack = Hijack::DriverHijack{};
	hijack.DriverInitialization(L"\\Device\\GIO");
	hijack.HijackDriver();

	return STATUS_SUCCESS;
}

EXTERN_C VOID DriverUnload(_In_ PDRIVER_OBJECT DriverObject) {
	UNICODE_STRING dosName{};
	RtlInitUnicodeString(&dosName, DOSDEVICE_NAME);
	IoDeleteSymbolicLink(&dosName);
	IoDeleteDevice(DriverObject->DeviceObject);
}

_Function_class_(DRIVER_DISPATCH)
_IRQL_requires_max_(DISPATCH_LEVEL)
_IRQL_requires_same_
EXTERN_C NTSTATUS DefaultDispatch(_In_ PDEVICE_OBJECT DeviceObject, _In_ PIRP Irp) {
	Irp->IoStatus.Status = STATUS_SUCCESS;
	Irp->IoStatus.Information = 0;

	IoCompleteRequest(Irp, IO_NO_INCREMENT);
	return STATUS_SUCCESS;
}

_Function_class_(DRIVER_DISPATCH)
_IRQL_requires_max_(DISPATCH_LEVEL)
_IRQL_requires_same_
EXTERN_C NTSTATUS IoctlDispatch(_In_ PDEVICE_OBJECT DeviceObject, _In_ PIRP Irp) {

	auto ioStackLocation = IoGetCurrentIrpStackLocation(Irp);
	auto ctlcode = ioStackLocation->Parameters.DeviceIoControl.IoControlCode;
	NTSTATUS ns = STATUS_SUCCESS;

	switch (ctlcode) {
	case IOCTL_POOL: {
		DbgPrint("[+] In IOCTL_POOL\n");
		Pool::SYSTEM_BIGPOOL_INFORMATION* BigPoolInfo;
		if (NT_SUCCESS(Pool::GetBigPoolInfo(&BigPoolInfo))) {
			Pool::PrintBigPoolInfo(BigPoolInfo);
		}
		break;
	}
	default:
		break;
	}

	Irp->IoStatus.Status = ns;
	Irp->IoStatus.Information = 0;
	
	IoCompleteRequest(Irp, IO_NO_INCREMENT);
	return ns;
}