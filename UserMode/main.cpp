#include <iostream>
#include <Windows.h>
#include <assert.h>

#define DRIVER_NAME		L"\\\\.\\KernelMode"
#define IOCTL_POOL CTL_CODE(FILE_DEVICE_UNKNOWN, 0x900, METHOD_BUFFERED, FILE_READ_ACCESS | FILE_WRITE_ACCESS)

int main(int argc, char* argv[]) {

	const auto hHandle = ::CreateFile(DRIVER_NAME, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE,
		__nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hHandle == INVALID_HANDLE_VALUE) {
		printf("[-] CreateFile failed.\n");
		return -1;
	}

	DWORD lpBytesReturned = 0;
	::DeviceIoControl(hHandle, IOCTL_POOL, __nullptr, 0, __nullptr, 0, &lpBytesReturned, __nullptr);

	return 0;
}