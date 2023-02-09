#include <iostream>
#include <Windows.h>
#include <assert.h>

#define DRIVER_NAME		L"\\\\.\\KernelMode"
#define IOCTL_POOL CTL_CODE(FILE_DEVICE_UNKNOWN, 0x900, METHOD_BUFFERED, FILE_READ_ACCESS | FILE_WRITE_ACCESS)

int main(int argc, char* argv[]) {

	const auto hHandle = ::CreateFile(DRIVER_NAME, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE,
		__nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	assert(hHandle != INVALID_HANDLE_VALUE, "CreateFile failed.\n");

	DWORD lpBytesReturned = 0;
	::DeviceIoControl(hHandle, IOCTL_POOL, __nullptr, 0, __nullptr, 0, &lpBytesReturned, __nullptr);
	::CloseHandle(hHandle);

	return 0;
}