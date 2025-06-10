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
        static std::shared_ptr<ZDriver> instance;
        
        if (!instance && !(instance = std::make_shared<ZDriver>())) {
            return {};
        }

        ZDRV_TRACE("ZDriver instance created (%p)", instance.get());
        return instance;
    }

    template<typename IP = INPUT_BASE_IOCTL_CALL, typename OP = OUTPUT_BASE_IOCTL_CALL>
    bool SendIoctl(uint32_t code, IP& input, OP& output) {
        assert(mInitCalled && mInitOK);
        VMP_BEGIN_MUTATION("aLBHh5m10Hr52CFcxT4W2e3kMyUUp6Y32Bm8WLg84Gwb2bEa8655l5w566g66p47");

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
            return false;
        }

        if (isb.Information != sizeof(output)) {
			ZDRV_TRACE("Invalid Output Buffer Size (%p != %p)", (void*)isb.Information, (void*)sizeof(output));
            return false;
        }

        mLastDrvAPIError.QuadPart = isb.Status;
        mLastDrvError = output.DrvError;
        VMP_END();
        return true;
    }

    bool Verify() {
        assert(mInitCalled && !mConnected);
        VMP_BEGIN_ULTRA("tawGQ1aCYRPkuaUhvpD0G5ThOSR9vHeIY9WQHfnjnF8QUGOIjJLe5NTJsX8GfuLa");
        OUTPUT_VERIFY_IOCTL_CALL ouput{};
        INPUT_VERIFY_IOCTL_CALL input{ .UserSignature = ZDRV_VERIFY_CLIENT_SIGNATURE };

        if (!SendIoctl(ZDRV_IOCTL_VERIFY, input, ouput)) {
            return false;
        }

        if (ouput.DrvSignature != ZDRV_VERIFY_DRIVER_SIGNATURE) {
			ZDRV_TRACE("Invalid Driver Signature (%p)", (void*)ouput.DrvSignature);
            return false;
        }

        mConnected = true;
        ZDRV_TRACE("Verify Success");
        VMP_END();
        return true;
    }

public:
    uintptr_t GetProcessPEB() {
        assert(mInitCalled && mInitOK && mProcessID);
        VMP_BEGIN_MUTATION("UQomHTOMG14iYuv91yId88nSla3jvKCneDa7ccZXgSxB95aU6wjrSYzENc3s4qTN");
        OUTPUT_POINTER_IOCTL_CALL output{};
        INPUT_PROCESS_IOCTL_CALL input{ .ProcessId = mProcessID };

        if (!SendIoctl(ZDRV_IOCTL_GET_PROCESS_PEB, input, output)) {
            ZDRV_TRACE("Failed to Get Process PEB");
            return 0;
        }

        ZDRV_TRACE("GetProcessPEB Success");
        VMP_END();
        return output.Pointer;
    }
    uintptr_t GetProcessBase() {
        assert(mInitCalled && mInitOK && mProcessID);
        VMP_BEGIN_MUTATION("WPYt3o5ikRol1nA1mSy7BdZ2VUW99uMCf1eof8JwfKQ9GbjjSKBfSvr74s8u29FZ");
        OUTPUT_POINTER_IOCTL_CALL output{};
        INPUT_PROCESS_IOCTL_CALL input{ .ProcessId = mProcessID };

        if (!SendIoctl(ZDRV_IOCTL_GET_PROCESS_BASE, input, output)) {
            ZDRV_TRACE("Failed to Get Process Base");
            return 0;
        }

        ZDRV_TRACE("GetProcessBase Success");
        VMP_END();
        return output.Pointer;
    }
    bool ReadProcessMemory(uint64_t address, void* buffer, size_t size) {
        assert(mInitCalled && mInitOK && mProcessID);
        VMP_BEGIN_MUTATION("aEGo0iDWdC3Xf1uecwdNfAnJtZCMsigeFYGaz1PcfWVWyPOy93yhbJf9tH2OqEyG");
        OUTPUT_READWRITE_IOCTL_CALL output{};
        INPUT_READWRITE_IOCTL_CALL input{};
        input.ProcessId = mProcessID;
        input.Address = address;
        input.Buffer = (uint64_t)buffer;
        input.Size = size;

        if (!SendIoctl(ZDRV_IOCTL_READ_MEMORY, input, output)) {
            ZDRV_TRACE("Failed to Read Process Memory");
            return false;
        }

        if (output.rwBytes != size) {
			ZDRV_TRACE("Failed to Read Process Memory");
			return false;
        }

        ZDRV_TRACE("ReadProcessMemory Success");
        VMP_END();
        return true;
    }
    bool WriteProcessMemory(uint64_t address, void* buffer, size_t size) {
        assert(mInitCalled && mInitOK && mProcessID);
        VMP_BEGIN_MUTATION("44JHWrbK233n3AuHr9dKqlfj9MXKfHWVOwQymNPVurkBBMgViW4jVyYKkfHKgfzD");
        OUTPUT_READWRITE_IOCTL_CALL output{};
        INPUT_READWRITE_IOCTL_CALL input{};
        input.ProcessId = mProcessID;
        input.Address = address;
        input.Buffer = (uint64_t)buffer;
        input.Size = size;

        if (!SendIoctl(ZDRV_IOCTL_WRITE_MEMORY, input, output)) {
            ZDRV_TRACE("Failed to Write Process Memory");
            return false;
        }

        if (output.rwBytes != size) {
            ZDRV_TRACE("Failed to Write Process Memory");
            return false;
        }

        ZDRV_TRACE("WriteProcessMemory Success");
        VMP_END();
        return true;
    }
    bool ProtectVirtualMemory(uint64_t& address, size_t& size, uint64_t protection, uint64_t& oldProtection) {
        assert(mInitCalled && mInitOK && mProcessID);
        VMP_BEGIN_MUTATION("mTbXsoJ5iPu3RhqVhRauVYZm0zmOgJlJXVE5psdQPeBTvVsEWFlR2wVFRKO7IiO8");
        OUTPUT_PROTECT_MEMORY_IOCTL_CALL output{};
        INPUT_PROTECT_MEMORY_IOCTL_CALL input{};
        input.ProcessId = mProcessID;
        input.Address = address;
        input.Size = size;
        input.NewProtection = protection;
        
        if (!SendIoctl(ZDRV_IOCTL_PROTECT_MEMORY, input, output)) {
            ZDRV_TRACE("Failed to Protect Virtual Memory");
            return false;
        }

		address = output.BaseAddress;
		size = output.Size;
		oldProtection = output.OldProtection;
        ZDRV_TRACE("ProtectVirtualMemory Success");
        VMP_END();
        return true;
    }
    bool SuspendProcess() {
        assert(mInitCalled && mInitOK && mProcessID);
        VMP_BEGIN_MUTATION("ZlT730KL5Sb3VdYicklfj5Td5TZTkR19eYz7laHRgbgp6UUwhDH19oqAKusbdK7J");
        OUTPUT_BASE_IOCTL_CALL output{};
        INPUT_PROCESS_IOCTL_CALL input{ .ProcessId = mProcessID };

        if (!SendIoctl(ZDRV_IOCTL_SUSPEND_PROCESS, input, output)) {
            ZDRV_TRACE("Failed to Suspend Process");
            return false;
        }

        ZDRV_TRACE("SuspendProcess Success");
        VMP_END();
        return true;
    }
    bool ResumeProcess() {
        assert(mInitCalled && mInitOK && mProcessID);
        VMP_BEGIN_MUTATION("zL8yZAmvPpqCm1lPKmbc0tebhEgKibAqTvMeslljGs6pIMBy1fqFIa8gy7N243hj");
		OUTPUT_BASE_IOCTL_CALL output{};
        INPUT_PROCESS_IOCTL_CALL input{ .ProcessId = mProcessID };

        if (!SendIoctl(ZDRV_IOCTL_RESUME_PROCESS, input, output)) {
			ZDRV_TRACE("Failed to Resume Process");
            return false;
        }

		ZDRV_TRACE("ResumeProcess Success");
        VMP_END();
        return true;
    }
    inline void AttachProcess(uint64_t processId) {
        mProcessID = processId;
    }

    bool Initialize() {
        assert(!mInitCalled);
        VMP_BEGIN_ULTRA("677642STS0InOjYE46UtTR0wE0UtA01VpNxf40RWbutXxUkL0H10oer0563ert6R");

        if (mInitCalled)
            return false;

        mInitCalled = true;

        IO_STATUS_BLOCK isb;
        OBJECT_ATTRIBUTES objectAttributes;
        UNICODE_STRING fileName;

#if (PHNT_VERSION >= PHNT_WIN7)
        if (!NT_SUCCESS(::RtlDosPathNameToNtPathName_U_WithStatus(VMP_STRW(L"\\\\.\\ACPI_ROOT_OBJECT"), &fileName, NULL, NULL))) {
            ZDRV_TRACE("Failed to open driver");
            return false;
        }
#else
        if (!::RtlDosPathNameToNtPathName_U(VMP_STRW(L"\\\\.\\ACPI_ROOT_OBJECT"), &fileName, NULL, NULL)) {
            ZDRV_TRACE("Failed to open driver");
            return false;
        }
#endif

        InitializeObjectAttributes(&objectAttributes, &fileName, OBJ_CASE_INSENSITIVE, NULL, NULL);

        if (!NT_SUCCESS(::NtCreateFile(&mDriverHandle, FILE_READ_ATTRIBUTES | GENERIC_READ | GENERIC_WRITE | SYNCHRONIZE, &objectAttributes, &isb, nullptr, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ | FILE_SHARE_WRITE, OPEN_EXISTING, 0, nullptr, 0))) {
            ::RtlFreeUnicodeString(&fileName);
            ZDRV_TRACE("Failed to open driver (%08X)", isb.Status);
            return false;
        }

        ::RtlFreeUnicodeString(&fileName);
        mInitOK = true;

        if (!Verify()) {
            return false;
        }

        VMP_END();
        return true;
    }

public:
    ZDriver() : mInitCalled(), mInitOK(), mConnected(),
        mLastDrvAPIError(), mLastDrvError(), mLastError(),
        mDriverHandle(), mProcessID() {}
    ~ZDriver() {}

private:
    bool mInitCalled, mInitOK, mConnected;
    uint64_t mProcessID;
    HANDLE mDriverHandle;
    LARGE_INTEGER mLastError, mLastDrvAPIError;
    ZDRV_ERROR mLastDrvError;
};

#endif