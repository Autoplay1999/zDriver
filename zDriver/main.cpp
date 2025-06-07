#include "main.h"
#include "zdrv.hpp"

DRIVER_INITIALIZE DriverEntry;
#pragma alloc_text(INIT, DriverEntry)
extern "C" void DispatchHook();

PDRIVER_DISPATCH ACPIOriginalDispatch = 0;

NTSTATUS CustomDispatch(PDEVICE_OBJECT device, PIRP irp) {
    PIO_STACK_LOCATION		irpSp;
    NTSTATUS				status = STATUS_SUCCESS;
    ULONG					inBufLength, outBufLength, bytesIO{};
    INPUT_BASE_IOCTL_CALL*  inBaseBuffer;

    irpSp        = IoGetCurrentIrpStackLocation(irp);
    inBufLength  = irpSp->Parameters.DeviceIoControl.InputBufferLength;
    outBufLength = irpSp->Parameters.DeviceIoControl.OutputBufferLength;
    inBaseBuffer = (INPUT_BASE_IOCTL_CALL*)irp->AssociatedIrp.SystemBuffer;

    if (irpSp->Parameters.DeviceIoControl.IoControlCode != IOCTL_DISK_UPDATE_PROPERTIES)
        return ACPIOriginalDispatch(device, irp);

    if (inBaseBuffer->Filter != ZDRV_FILTER_CODE)
        return ACPIOriginalDispatch(device, irp);

    switch (inBaseBuffer->ControlCode) {
    case ZDRV_IOCTL_VERIFY: {
        TRACE_BEGIN("ZDRV_IOCTL_VERIFY");
        auto inUserBuffer = (INPUT_VERIFY_IOCTL_CALL*)irp->AssociatedIrp.SystemBuffer;
        auto outUserBuffer = (OUTPUT_VERIFY_IOCTL_CALL*)irp->AssociatedIrp.SystemBuffer;
        outUserBuffer->DrvSignature = ZDRV_VERIFY_DRIVER_SIGNATURE;
        bytesIO = sizeof(OUTPUT_VERIFY_IOCTL_CALL);
        TRACE_END();
        break;
    }
    case ZDRV_IOCTL_GET_PROCESS_PEB: {
        TRACE_BEGIN("ZDRV_IOCTL_GET_PROCESS_PEB");
        auto inUserBuffer = (INPUT_PROCESS_IOCTL_CALL*)irp->AssociatedIrp.SystemBuffer;
        auto outUserBuffer = (OUTPUT_POINTER_IOCTL_CALL*)irp->AssociatedIrp.SystemBuffer;

        DEBUG("ProcessId: %p", inUserBuffer->ProcessId);

        PEPROCESS targetProcess = 0;
        status = PsLookupProcessByProcessId((HANDLE)inUserBuffer->ProcessId, &targetProcess);

        if (NT_SUCCESS(status)) {
            outUserBuffer->Pointer = (uint64_t)PsGetProcessPeb(targetProcess);

            if (!outUserBuffer->Pointer) {
                outUserBuffer->DrvError = ZDRV_ERROR::PsGetProcessPeb_Failed;
            }

            DEBUG("PsGetProcessPeb: %p", outUserBuffer->Pointer);
            ObfDereferenceObject(targetProcess);
        }
        else {
            TRACE("PsLookupProcessByProcessId Failed");
            outUserBuffer->DrvError = ZDRV_ERROR::PsLookupProcessByProcessId_Failed;
        }

        bytesIO = sizeof(OUTPUT_POINTER_IOCTL_CALL);
        TRACE_END();
        break;
    }
    case ZDRV_IOCTL_GET_PROCESS_BASE: {
        TRACE_BEGIN("ZDRV_IOCTL_GET_PROCESS_BASE");
        auto inUserBuffer = (INPUT_PROCESS_IOCTL_CALL*)irp->AssociatedIrp.SystemBuffer;
        auto outUserBuffer = (OUTPUT_POINTER_IOCTL_CALL*)irp->AssociatedIrp.SystemBuffer;

        DEBUG("ProcessId: %p", inUserBuffer->ProcessId);

        PEPROCESS targetProcess = 0;
        status = PsLookupProcessByProcessId((HANDLE)inUserBuffer->ProcessId, &targetProcess);

        if (NT_SUCCESS(status)) {
            outUserBuffer->Pointer = (uint64_t)PsGetProcessSectionBaseAddress(targetProcess);

            if (!outUserBuffer->Pointer) {
                outUserBuffer->DrvError = ZDRV_ERROR::PsGetProcessBase_Failed;
            }

            DEBUG("PsGetProcessSectionBaseAddress: %p", outUserBuffer->Pointer);
            ObfDereferenceObject(targetProcess);
        }
        else {
            TRACE("PsLookupProcessByProcessId Failed");
            outUserBuffer->DrvError = ZDRV_ERROR::PsLookupProcessByProcessId_Failed;
        }

        bytesIO = sizeof(OUTPUT_POINTER_IOCTL_CALL);
        TRACE_END();
        break;
    }
    case ZDRV_IOCTL_READ_MEMORY: {
        TRACE_BEGIN("ZDRV_IOCTL_READ_MEMORY");
        auto inUserBuffer = (INPUT_READWRITE_IOCTL_CALL*)irp->AssociatedIrp.SystemBuffer;
        auto outUserBuffer = (OUTPUT_READWRITE_IOCTL_CALL*)irp->AssociatedIrp.SystemBuffer;

        DEBUG("ProcessId: %p", inUserBuffer->ProcessId);
        DEBUG("Address  : %p", inUserBuffer->Address);
        DEBUG("Size     : %p", inUserBuffer->Size);
        DEBUG("Buffer   : %p", inUserBuffer->Buffer);

        PEPROCESS targetProcess = 0;
        status = PsLookupProcessByProcessId((HANDLE)inUserBuffer->ProcessId, &targetProcess);

        if (NT_SUCCESS(status)) {
            uint64_t rwSize = inUserBuffer->Size;
            status = KeReadProcessMemory(targetProcess, (PVOID)inUserBuffer->Address, (PVOID)inUserBuffer->Buffer, &rwSize);

            if (!NT_SUCCESS(status)) {
                outUserBuffer->DrvError = ZDRV_ERROR::KeReadProcessMemory_Failed;
            }

            outUserBuffer->rwBytes = rwSize;
            DEBUG("KeReadProcessMemory: %p, rwSize: %p", status, rwSize);
            ObfDereferenceObject(targetProcess);
        }
        else {
            TRACE("PsLookupProcessByProcessId Failed");
            outUserBuffer->DrvError = ZDRV_ERROR::PsLookupProcessByProcessId_Failed;
        }

        bytesIO = sizeof(OUTPUT_READWRITE_IOCTL_CALL);
        TRACE_END();
        break;
    }
    case ZDRV_IOCTL_WRITE_MEMORY: {
        TRACE_BEGIN("ZDRV_IOCTL_WRITE_MEMORY");
        auto inUserBuffer = (INPUT_READWRITE_IOCTL_CALL*)irp->AssociatedIrp.SystemBuffer;
        auto outUserBuffer = (OUTPUT_READWRITE_IOCTL_CALL*)irp->AssociatedIrp.SystemBuffer;

        DEBUG("ProcessId: %p", inUserBuffer->ProcessId);
        DEBUG("Address  : %p", inUserBuffer->Address);
        DEBUG("Size     : %p", inUserBuffer->Size);
        DEBUG("Buffer   : %p", inUserBuffer->Buffer);

        PEPROCESS targetProcess = 0;
        status = PsLookupProcessByProcessId((HANDLE)inUserBuffer->ProcessId, &targetProcess);

        if (NT_SUCCESS(status)) {
            uint64_t rwSize = inUserBuffer->Size;
            status = KeWriteProcessMemory(targetProcess, (PVOID)inUserBuffer->Address, (PVOID)inUserBuffer->Buffer, &rwSize);

            if (!NT_SUCCESS(status)) {
                outUserBuffer->DrvError = ZDRV_ERROR::KeWriteProcessMemory_Failed;
            }

            outUserBuffer->rwBytes = rwSize;
            DEBUG("KeWriteProcessMemory: %p, rwSize: %p", status, rwSize);
            ObfDereferenceObject(targetProcess);
        }
        else {
            TRACE("PsLookupProcessByProcessId Failed");
            outUserBuffer->DrvError = ZDRV_ERROR::PsLookupProcessByProcessId_Failed;
        }

        bytesIO = sizeof(OUTPUT_READWRITE_IOCTL_CALL);
        TRACE_END();
        break;
    }
    case ZDRV_IOCTL_SUSPEND_PROCESS: {
        TRACE_BEGIN("ZDRV_IOCTL_SUSPEND_PROCESS");
        auto inUserBuffer = (INPUT_PROCESS_IOCTL_CALL*)irp->AssociatedIrp.SystemBuffer;
        auto outUserBuffer = (OUTPUT_BASE_IOCTL_CALL*)irp->AssociatedIrp.SystemBuffer;

        DEBUG("ProcessId: %p", inUserBuffer->ProcessId);

        PEPROCESS targetProcess = 0;
        status = PsLookupProcessByProcessId((HANDLE)inUserBuffer->ProcessId, &targetProcess);

        if (NT_SUCCESS(status)) {
            status = PsSuspendProcess(targetProcess);
            
            if (!NT_SUCCESS(status)) {
                outUserBuffer->DrvError = ZDRV_ERROR::PsSuspendProcess_Failed;
            }

            DEBUG("PsSuspendProcess: %p", status);
            ObfDereferenceObject(targetProcess);
        }
        else {
            TRACE("PsLookupProcessByProcessId Failed");
            outUserBuffer->DrvError = ZDRV_ERROR::PsLookupProcessByProcessId_Failed;
        }

        bytesIO = sizeof(OUTPUT_BASE_IOCTL_CALL);
        TRACE_END();
        break;
    }
    case ZDRV_IOCTL_RESUME_PROCESS: {
        TRACE_BEGIN("ZDRV_IOCTL_RESUME_PROCESS");
        auto inUserBuffer = (INPUT_PROCESS_IOCTL_CALL*)irp->AssociatedIrp.SystemBuffer;
        auto outUserBuffer = (OUTPUT_BASE_IOCTL_CALL*)irp->AssociatedIrp.SystemBuffer;

        DEBUG("ProcessId: %p", inUserBuffer->ProcessId);

        PEPROCESS targetProcess = 0;
        status = PsLookupProcessByProcessId((HANDLE)inUserBuffer->ProcessId, &targetProcess);

        if (NT_SUCCESS(status)) {
            status = PsResumeProcess(targetProcess);

            if (!NT_SUCCESS(status)) {
                outUserBuffer->DrvError = ZDRV_ERROR::PsResumeProcess_Failed;
            }

            DEBUG("PsResumeProcess: %p", status);
            ObfDereferenceObject(targetProcess);
        }
        else {
            TRACE("PsLookupProcessByProcessId Failed");
            outUserBuffer->DrvError = ZDRV_ERROR::PsLookupProcessByProcessId_Failed;
        }

        bytesIO = sizeof(OUTPUT_BASE_IOCTL_CALL);
        TRACE_END();
        break;
    }
    default:
        TRACE_BEGIN("IOCTL_ZDRV_INVALID");
        bytesIO = 0;
        status = STATUS_INVALID_DEVICE_REQUEST;
        TRACE_END();
        break;
    }

    irp->IoStatus.Status = status;
    irp->IoStatus.Information = bytesIO;
    IofCompleteRequest(irp, IO_NO_INCREMENT);
    return status;
}

NTSTATUS DriverEntry(_In_  struct _DRIVER_OBJECT* DriverObject, _In_  PUNICODE_STRING RegistryPath) {
    TRACE_BEGIN(__FUNCTION__);
    //RetrieveMmUnloadedDriversData();
    //ClearPiDDBCacheTable();
    //UNICODE_STRING iqvw64e = RTL_CONSTANT_STRING(L"iqvw64e.sys");
    //ClearMmUnloadedDrivers(&iqvw64e, true);

    PDRIVER_OBJECT ACPIDriverObject = nullptr;
    UNICODE_STRING DriverObjectName = RTL_CONSTANT_STRING(L"\\Driver\\ACPI");
    auto status = ObReferenceObjectByName(&DriverObjectName, OBJ_CASE_INSENSITIVE, 0, 0, *IoDriverObjectType, KernelMode, 0, (PVOID*)&ACPIDriverObject);

    if (NT_SUCCESS(status) && ACPIDriverObject) {
        ACPIOriginalDispatch = ACPIDriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL];
        uintptr_t DispatchHookAddr = (uintptr_t)DispatchHook;
        *(uintptr_t*)(DispatchHookAddr + 0x6) = (uintptr_t)CustomDispatch;
        //uintptr_t TraceMessageHookInst = FindPatternInKernelSection(".TEXT", (uintptr_t)ACPIDriverObject->DriverStart, (BYTE*)"\x48\x8D\x45\x4F\x4C\x89\x00\x24\x28\x48\x89\x00\x24\x20", "xxxxxx?xxxx?xx"); // 48 8D 45 4F 4C 89 ?? 24 28 48 89 ?? 24 20
        auto TraceMessageHookInst = FindPatternInKernelSection(".TEXT", (uintptr_t)ACPIDriverObject->DriverStart, (BYTE*)"\x48\x8B\x05\x00\x00\x00\x00\xFF\x15\x00\x00\x00\x00\x41\xB9\x05\x00\x00\x00", "xxx????xx????xxxxxx");    // 48 8B 05 ?? ?? ?? ?? FF 15 ?? ?? ?? ?? 41 B9 05 00 00 00

        if (!TraceMessageHookInst) {
            TraceMessageHookInst = FindPatternInKernelSection(".TEXT", (uintptr_t)ACPIDriverObject->DriverStart, (BYTE*)"\x48\x8B\x05\x00\x00\x00\x00\xE8\x00\x00\x00\x00\x90\x41\xB9\x05\x00\x00\x00", "xxx????x????xxxxxxx");     // 48 8B 05 ?? ?? ?? ?? E8 ?? ?? ?? ?? 90 41 B9 05 00 00 00
        }

        if (!TraceMessageHookInst) {
            TraceMessageHookInst = FindPatternInKernelSection(".TEXT", (uintptr_t)ACPIDriverObject->DriverStart, (BYTE*)"\x48\x8B\x05\x00\x00\x00\x00\xFF\x15\x00\x00\x00\x00\xB9\x05\x00\x00\x00", "xxx????xx????xxxxx");          // 48 8B 05 ?? ?? ?? ?? FF 15 ?? ?? ?? ?? B9 05 00 00 00 (Win11 23H2 22631.5335)
        }

        if (!TraceMessageHookInst) {
            TraceMessageHookInst = FindPatternInKernelSection(".TEXT", (uintptr_t)ACPIDriverObject->DriverStart, (BYTE*)"\x48\x8B\x05\x00\x00\x00\x00\xE8\x00\x00\x00\x00\x90\xB9\x05\x00\x00\x00", "xxx????x????xxxxxx");          // 48 8B 05 ?? ?? ?? ?? E8 ?? ?? ?? ?? 90 B9 05 00 00 00 (Win11 23H2 22631.5335)
        }

        if (TraceMessageHookInst) {
            //TraceMessageHookInst += 0xE;
            uintptr_t pfnWppTraceMessagePtr = (uintptr_t)ResolveRelativeAddress((PVOID)TraceMessageHookInst, 3, 7);

            if (pfnWppTraceMessagePtr) {
                TRACE("pfnWppTraceMessagePtr: %p", pfnWppTraceMessagePtr);
                *(uintptr_t*)(pfnWppTraceMessagePtr) = DispatchHookAddr;
                ACPIDriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = (PDRIVER_DISPATCH)TraceMessageHookInst;
            }
        } else
            TRACE("Failed to find WPP TraceMessage hook instruction.");

        ObfDereferenceObject(ACPIDriverObject);
    }
    else {
        TRACE("Failed to reference ACPI driver object.");
    }

    TRACE_END();
    return 0;
}




