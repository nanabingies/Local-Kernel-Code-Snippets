#include <iostream>
#include <Windows.h>
#include <assert.h>
#include <TlHelp32.h>

#define DRIVER_NAME		L"\\\\.\\KernelMode"
#define IOCTL_POOL CTL_CODE(FILE_DEVICE_UNKNOWN, 0x900, METHOD_BUFFERED, FILE_READ_ACCESS | FILE_WRITE_ACCESS)

auto getPid() -> DWORD {
	wchar_t fileName[] = L"notepad.exe";
	auto handle = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
	DWORD procID = NULL;
	if (handle == INVALID_HANDLE_VALUE)		return procID;

	PROCESSENTRY32W entry = { 0 };
	entry.dwSize = sizeof(PROCESSENTRY32W);

	if (Process32FirstW(handle, &entry)) {
		if (!_wcsicmp(fileName, entry.szExeFile)) {
			procID = entry.th32ProcessID;
		}
		else while (Process32NextW(handle, &entry)) {
			if (!_wcsicmp(fileName, entry.szExeFile)) {
				procID = entry.th32ProcessID;
			}
		}
	}

	CloseHandle(handle);
	return procID;
}

/*int main(int argc, char* argv[]) {

	const auto hHandle = ::CreateFile(DRIVER_NAME, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE,
		__nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	assert(hHandle != INVALID_HANDLE_VALUE);

	DWORD lpBytesReturned = 0;
	auto pid = getPid();
	printf("Pid : %x\n", pid);
	::DeviceIoControl(hHandle, IOCTL_POOL, reinterpret_cast<LPVOID>(pid), sizeof(LPVOID), __nullptr, 0, &lpBytesReturned, __nullptr);
	::CloseHandle(hHandle);

	return 0;
}*/