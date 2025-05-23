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
	INPUT_BASE_IOCTL_CALL* inBaseBuffer;

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
	case ZDRV_IOCTL_SUSPEND_PROCESS: {
		TRACE_BEGIN("ZDRV_IOCTL_SUSPEND_PROCESS");
		auto inUserBuffer = (INPUT_PROCESS_IOCTL_CALL*)irp->AssociatedIrp.SystemBuffer;
		auto outUserBuffer = (OUTPUT_BASE_IOCTL_CALL*)irp->AssociatedIrp.SystemBuffer;

		TRACE("ProcessId: %08lX", inUserBuffer->ProcessId);

		PEPROCESS targetProcess = 0;
		status = PsLookupProcessByProcessId((HANDLE)inUserBuffer->ProcessId, &targetProcess);

		if (NT_SUCCESS(status)) {
			status = PsSuspendProcess(targetProcess);
			
			if (!NT_SUCCESS(status)) {
				outUserBuffer->DrvError = ZDRV_ERROR::PsSuspendProcess_Failed;
			}

			TRACE("PsSuspendProcess: %08lX", status);
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

		TRACE("ProcessId: %08lX", inUserBuffer->ProcessId);

		PEPROCESS targetProcess = 0;
		status = PsLookupProcessByProcessId((HANDLE)inUserBuffer->ProcessId, &targetProcess);

		if (NT_SUCCESS(status)) {
			status = PsResumeProcess(targetProcess);

			if (!NT_SUCCESS(status)) {
				outUserBuffer->DrvError = ZDRV_ERROR::PsResumeProcess_Failed;
			}

			TRACE("PsResumeProcess: %08lX", status);
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
	//RetrieveMmUnloadedDriversData();
	//ClearPiDDBCacheTable();
	//UNICODE_STRING iqvw64e = RTL_CONSTANT_STRING(L"iqvw64e.sys");
	//ClearMmUnloadedDrivers(&iqvw64e, true);

	PDRIVER_OBJECT ACPIDriverObject = nullptr;
	UNICODE_STRING DriverObjectName = RTL_CONSTANT_STRING(L"\\Driver\\ACPI");
	ObReferenceObjectByName(&DriverObjectName, OBJ_CASE_INSENSITIVE, 0, 0, *IoDriverObjectType, KernelMode, 0, (PVOID*)&ACPIDriverObject);

	if (ACPIDriverObject) {
		ACPIOriginalDispatch = ACPIDriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL];
		uintptr_t DispatchHookAddr = (uintptr_t)DispatchHook;
		*(uintptr_t*)(DispatchHookAddr + 0x6) = (uintptr_t)CustomDispatch;
		uintptr_t TraceMessageHookInst = FindPattern((uintptr_t)ACPIDriverObject->DriverStart, ACPIDriverObject->DriverSize, (BYTE*)"\x48\x8D\x45\x4F\x4C\x89\x00\x24\x28\x48\x89\x00\x24\x20\x48", "xxxxxx?xxxx?xxx");

		if (TraceMessageHookInst) {
			TraceMessageHookInst += 0xE;
			uintptr_t pfnWppTraceMessagePtr = (uintptr_t)ResolveRelativeAddress((PVOID)TraceMessageHookInst, 3, 7);

			if (pfnWppTraceMessagePtr) {
				*(uintptr_t*)(pfnWppTraceMessagePtr) = DispatchHookAddr;
				ACPIDriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = (PDRIVER_DISPATCH)TraceMessageHookInst;
			}
		}
	}

	return 0;
}




