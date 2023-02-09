#include "Hijack.hpp"

namespace Hijack {

	PDRIVER_DISPATCH g_OriginalCreate = 0;
	PFILE_OBJECT FileObject;

	EXTERN_C NTSTATUS HookCreate(_In_ PDEVICE_OBJECT DeviceObject, _In_ PIRP Irp) {
		DbgPrint("[%s] DeviceObject : 0x%p\n", __FUNCTION__, DeviceObject);
		DbgPrint("[%s] Irp : 0x%p\n", __FUNCTION__, Irp);

		if (!g_OriginalCreate) {
			DbgPrint("g_OriginalCreate not set. Crashing.......\n");
			return STATUS_UNSUCCESSFUL;
		}

		auto create = reinterpret_cast<DRIVER_DISPATCH*>(g_OriginalCreate);
		return create(DeviceObject, Irp);
	}

	NTSTATUS DriverHijack::DriverInitialization(_In_ PCWSTR drvName) {

		RtlInitUnicodeString(&_DriverName, drvName);
		if (_DriverName.Buffer == nullptr || _DriverName.Length <= 0) {
			DbgPrint("[-] DriverName parameter cannot be empty\n");
			return STATUS_INVALID_PARAMETER;
		}

		auto ns = IoGetDeviceObjectPointer(&_DriverName, FILE_ALL_ACCESS, &FileObject, &_DeviceObject);
		if (!NT_SUCCESS(ns)) {
			DbgPrint("[%s] Constructor failed with error code : %X\n", __FUNCTION__, ns);
			return ns;
		}

		_DriverObject = _DeviceObject->DriverObject;

		DbgPrint("[+] DeviceName : %wZ\n", &_DriverName);
		DbgPrint("[+] DeviceObject : 0x%p\n", _DeviceObject);
		DbgPrint("[+] DriverObject : 0x%p\n", _DriverObject);

		return STATUS_SUCCESS;
	}

	NTSTATUS DriverHijack::HijackDriver() {

		// Resolving irp handlers
		auto IrpCreate = _DriverObject->MajorFunction[IRP_MJ_CREATE];
		auto IrpClose = _DriverObject->MajorFunction[IRP_MJ_CLOSE];
		auto IrpDevCtl = _DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL];
		g_OriginalCreate = IrpCreate;
		DbgPrint("[+] IrpCreate : 0x%p\n", (void*)IrpCreate);
		DbgPrint("[+] IrpClose : 0x%p\n", (void*)IrpClose);
		DbgPrint("[+] IrpDevCtl : 0x%p\n", (void*)IrpDevCtl);

		_DriverObject->MajorFunction[IRP_MJ_CREATE] = &HookCreate;

		return STATUS_SUCCESS;
	}

	NTSTATUS DriverHijack::RestoreDriver() {

		_DriverObject->MajorFunction[IRP_MJ_CREATE] = g_OriginalCreate;

		return STATUS_SUCCESS;
	}
}