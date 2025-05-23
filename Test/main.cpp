#include <phnt/phnt_windows.h>
#include <phnt/phnt.h>

#include "../zDriver/zdrv_ctl.hpp"

// Returns process ID by process name using Toolhelp32 API
#include <windows.h>
#include <tlhelp32.h>
#include <string>

DWORD GetProcessIdByName(const std::wstring& processName) {
    DWORD processId = 0;
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE)
        return 0;

    PROCESSENTRY32W pe;
    pe.dwSize = sizeof(PROCESSENTRY32W);

    if (Process32FirstW(hSnapshot, &pe)) {
        do {
            if (processName == pe.szExeFile) {
                processId = pe.th32ProcessID;
                break;
            }
        } while (Process32NextW(hSnapshot, &pe));
    }
    CloseHandle(hSnapshot);
    return processId;
}

int main() {
    _CrtSetDbgFlag(_CRTDBG_ALLOC_MEM_DF | _CRTDBG_LEAK_CHECK_DF);
    auto drv = ZDriver::GetInstance();

    if (!drv->Initialize()) {
        system("pause");
        return 1;
    }

    DWORD pid{};
    while (!(pid = GetProcessIdByName(L"notepad.exe")))
		Sleep(1000);

    drv->SuspendProcess(pid);
    printf("Suspend!\n");
    system("pause");
    drv->ResumeProcess(pid);
    printf("Resume!\n");
    system("pause");
	return 0;
}