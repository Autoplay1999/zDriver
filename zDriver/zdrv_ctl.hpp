#pragma once
#ifndef __ZDRV_CTL_H__
#define __ZDRV_CTL_H__

#pragma comment(lib, "ntdll.lib")

#include <phnt/phnt_windows.h>
#include <phnt/phnt.h>

#include <vmp/VMProtectSDK.h>

#include <cstdint>
#include <cassert>
#include <memory>
#include <vector>
#include <string>
#include <array>

#include "zdrv.hpp"

#if defined(_ZDRV_VERBOSE) || defined(_DEBUG)
#   define ZDRV_TRACE(fmt, ...) printf("[ZDriver.Client] " fmt "\n",__VA_ARGS__)
#   define ZDRV_TRACE_FUNC_ENTER(funcName) printf_s("[ZDriver.Client] Entering [%s]\n", funcName)
#   define ZDRV_TRACE_FUNC_LEAVE(funcName) printf_s("[ZDriver.Client] Leaving [%s]\n", funcName)
#endif

class ZDriver {
    ZDriver(const ZDriver&) = delete;
    ZDriver& operator=(const ZDriver&) = delete;
    ZDriver(ZDriver&&) = delete;
    ZDriver& operator=(ZDriver&&) = delete;

public:
    static std::shared_ptr<ZDriver> GetInstance() {
        ZDRV_TRACE_FUNC_ENTER(__FUNCTION__);
        static std::shared_ptr<ZDriver> instance;
        
        if (!instance && !(instance = std::make_shared<ZDriver>())) {
            ZDRV_TRACE("Failed to create ZDriver instance");
            return {};
        }

        ZDRV_TRACE("ZDriver instance created (%p)", instance.get());
        ZDRV_TRACE_FUNC_LEAVE(__FUNCTION__);
        return instance;
    }

    template<typename IP = INPUT_BASE_IOCTL_CALL, typename OP = OUTPUT_BASE_IOCTL_CALL>
    bool SendIoctl(uint32_t code, IP& input, OP& output) {
        assert(mInitCalled && mInitOK);
        VMP_BEGIN_MUTATION("aLBHh5m10Hr52CFcxT4W2e3kMyUUp6Y32Bm8WLg84Gwb2bEa8655l5w566g66p47");
        ZDRV_TRACE_FUNC_ENTER(__FUNCTION__);

        input.Filter      = ZDRV_FILTER_CODE;
        input.ControlCode = code;

        NTSTATUS status;
        IO_STATUS_BLOCK isb{};

        status = ::ZwDeviceIoControlFile(
            mDriverHandle, NULL, NULL, NULL, 
            &isb, IOCTL_DISK_UPDATE_PROPERTIES, 
            &input, sizeof(input),
            &output, sizeof(output));

        if (!NT_SUCCESS(status)) {
			ZDRV_TRACE("Driver Not Running (%08X)", status);
            ZDRV_TRACE_FUNC_LEAVE(__FUNCTION__);
            return false;
        }

        if (isb.Information != sizeof(output)) {
			ZDRV_TRACE("Invalid Output Buffer Size (%08X != %08X)", isb.Information, sizeof(output));
            ZDRV_TRACE_FUNC_LEAVE(__FUNCTION__);
            return false;
        }

        mLastDrvAPIError.QuadPart = isb.Status;
        mLastDrvError = output.DrvError;
		ZDRV_TRACE("SendIoctl Success", mLastDrvAPIError.LowPart, mLastDrvError);
        ZDRV_TRACE_FUNC_LEAVE(__FUNCTION__);
        VMP_END();
        return true;
    }

    bool Verify() {
        assert(mInitCalled && !mConnected);
        VMP_BEGIN_ULTRA("tawGQ1aCYRPkuaUhvpD0G5ThOSR9vHeIY9WQHfnjnF8QUGOIjJLe5NTJsX8GfuLa");
        ZDRV_TRACE_FUNC_ENTER(__FUNCTION__);
        OUTPUT_VERIFY_IOCTL_CALL ouput{};
        INPUT_VERIFY_IOCTL_CALL input{ .UserSignature = ZDRV_VERIFY_CLIENT_SIGNATURE };

        if (!SendIoctl(ZDRV_IOCTL_VERIFY, input, ouput)) {
            ZDRV_TRACE_FUNC_LEAVE(__FUNCTION__);
            return false;
        }

        if (ouput.DrvSignature != ZDRV_VERIFY_DRIVER_SIGNATURE) {
			ZDRV_TRACE("Invalid Driver Signature (%08X)", ouput.DrvSignature);
            ZDRV_TRACE_FUNC_LEAVE(__FUNCTION__);
            return false;
        }

        mConnected = true;
        ZDRV_TRACE("Verify Success");
        ZDRV_TRACE_FUNC_LEAVE(__FUNCTION__);
        VMP_END();
        return true;
    }

public:
    bool Initialize() {
        assert(!mInitCalled);
        VMP_BEGIN_ULTRA("677642STS0InOjYE46UtTR0wE0UtA01VpNxf40RWbutXxUkL0H10oer0563ert6R");
        ZDRV_TRACE_FUNC_ENTER(__FUNCTION__);

        if (mInitCalled)
            return false;

        mInitCalled = true;

        IO_STATUS_BLOCK isb;
        OBJECT_ATTRIBUTES objectAttributes;
        UNICODE_STRING fileName;

#if (PHNT_VERSION >= PHNT_WIN7)
        if (!NT_SUCCESS(::RtlDosPathNameToNtPathName_U_WithStatus(VMP_STRW(L"\\\\.\\ACPI_ROOT_OBJECT"), &fileName, NULL, NULL))) {
            ZDRV_TRACE("Failed to open driver");
            ZDRV_TRACE_FUNC_LEAVE(__FUNCTION__);
            return false;
        }
#else
        if (!::RtlDosPathNameToNtPathName_U(VMP_STRW(L"\\\\.\\ACPI_ROOT_OBJECT"), &fileName, NULL, NULL)) {
            ZDRV_TRACE("Failed to open driver");
            ZDRV_TRACE_FUNC_LEAVE(__FUNCTION__);
            return false;
        }
#endif

        InitializeObjectAttributes(&objectAttributes, &fileName, OBJ_CASE_INSENSITIVE, NULL, NULL);

        if (!NT_SUCCESS(::NtCreateFile(&mDriverHandle, FILE_READ_ATTRIBUTES | GENERIC_READ | GENERIC_WRITE | SYNCHRONIZE, &objectAttributes, &isb, nullptr, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ | FILE_SHARE_WRITE, OPEN_EXISTING, 0, nullptr, 0))) {
            ::RtlFreeUnicodeString(&fileName);
            ZDRV_TRACE("Failed to open driver (%08X)", isb.Status);
            ZDRV_TRACE_FUNC_LEAVE(__FUNCTION__);
            return false;
        }

        ::RtlFreeUnicodeString(&fileName);
        mInitOK = true;

        if (!Verify()) {
            ZDRV_TRACE_FUNC_LEAVE(__FUNCTION__);
            return false;
        }

        VMP_END();
        ZDRV_TRACE_FUNC_LEAVE(__FUNCTION__);
        return true;
    }
    bool SuspendProcess(uintptr_t pid) {
        VMP_BEGIN_MUTATION("pOvx9GjnpD1OuN3AKapMyGbnx0mkHfCOJTVU5SYsH91xym2ZuPtZ2Lrx0wy27OiC");
        ZDRV_TRACE_FUNC_ENTER(__FUNCTION__);
        OUTPUT_BASE_IOCTL_CALL output{};
        INPUT_PROCESS_IOCTL_CALL input{ .ProcessId = pid };
        ZDRV_TRACE("Suspend Process (%08X)", pid);

        if (!SendIoctl(ZDRV_IOCTL_SUSPEND_PROCESS, input, output)) {
            ZDRV_TRACE("Failed to Suspend Process");
            ZDRV_TRACE_FUNC_LEAVE(__FUNCTION__);
            return false;
        }

        ZDRV_TRACE("SuspendProcess Success");
        ZDRV_TRACE_FUNC_LEAVE(__FUNCTION__);
        VMP_END();
        return true;
    }
    bool ResumeProcess(uintptr_t pid) {
        VMP_BEGIN_MUTATION("pOvx9GjnpD1OuN3AKapMyGbnx0mkHfCOJTVU5SYsH91xym2ZuPtZ2Lrx0wy27OiC");
        ZDRV_TRACE_FUNC_ENTER(__FUNCTION__);
		OUTPUT_BASE_IOCTL_CALL output{};
        INPUT_PROCESS_IOCTL_CALL input{ .ProcessId = pid };
        ZDRV_TRACE("Resume Process (%08X)", pid);

        if (!SendIoctl(ZDRV_IOCTL_RESUME_PROCESS, input, output)) {
			ZDRV_TRACE("Failed to Resume Process");
            ZDRV_TRACE_FUNC_LEAVE(__FUNCTION__);
            return false;
        }

		ZDRV_TRACE("ResumeProcess Success");
        ZDRV_TRACE_FUNC_LEAVE(__FUNCTION__);
        VMP_END();
        return true;
    }

public:
    ZDriver() : mInitCalled(), mInitOK(), mConnected(),
        mLastDrvAPIError(), mLastDrvError(), mLastError(),
        mDriverHandle() {}
    ~ZDriver() {}

private:
    bool mInitCalled, mInitOK, mConnected;
    HANDLE mDriverHandle;
    LARGE_INTEGER mLastError, mLastDrvAPIError;
    ZDRV_ERROR mLastDrvError;
};

#endif