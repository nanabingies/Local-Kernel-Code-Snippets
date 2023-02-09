#pragma once
#include "Header.hpp"

namespace Hijack {
	//
	// Hook IRP_MJ_CREATE, IRP_MJ_CLOSE, IRP_MJ_DEVICE_CONTROL
	//

	PFILE_OBJECT* FileObject;
	
	class DriverHijack {
	public:
		NTSTATUS DriverInitialization(_In_ PCWSTR);
		NTSTATUS HijackDriver();

	private:
		PDEVICE_OBJECT _DeviceObject;
		PDRIVER_OBJECT _DriverObject;
		UNICODE_STRING _DriverName;
	};

}