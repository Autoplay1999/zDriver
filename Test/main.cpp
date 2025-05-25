#include <phnt/phnt_windows.h>
#include <phnt/phnt.h>

#include <windows.h>
#include <tlhelp32.h>
#include <string>

#include "../zDriver/zdrv_ctl.hpp"

DWORD GetProcessIdByName(const std::wstring& processName);

int main() {
    _CrtSetDbgFlag(_CRTDBG_ALLOC_MEM_DF | _CRTDBG_LEAK_CHECK_DF);
    auto drv = ZDriver::GetInstance();

    if (!drv->Initialize()) {
		printf(">>> Initialize failed!\n");
        system("pause");
        return 1;
    }

    DWORD pid{};
    while (!(pid = GetProcessIdByName(L"notepad.exe")))
		Sleep(1000);

    drv->AttachProcess(pid);

    auto processBase = drv->GetProcessBase();
    printf(">>> ProcessBase: %p\n", (void*)processBase);

    auto processPEB = drv->GetProcessPEB();
    printf(">>> processPEB: %p\n", (void*)processPEB);

    char peHeader[0x1000];
    if (!drv->ReadProcessMemory(processBase, peHeader, 0x1000)) {
		printf(">>> ReadProcessMemory failed!\n");
        system("pause");
		return 2;
    }

    printf(">>> PEHeader: %p\n", (void*)*(uintptr_t*)peHeader);

    if (!drv->SuspendProcess()) {
		printf(">>> SuspendProcess failed!\n");
        system("pause");
		return 3;
    }

    printf(">>> Suspend!\n");

    if (!drv->ResumeProcess()) {
		printf(">>> ResumeProcess failed!\n");
        system("pause");
		return 4;
    }

    printf(">>> Resume!\n");
    system("pause");
	return 0;
}

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