#include "main.h"

#define MM_UNLOADED_DRIVERS_SIZE 50

static PMM_UNLOADED_DRIVER gMmUnloadedDrivers;
static PULONG gMmLastUnloadedDriver;
static uintptr_t gNtoskrnlBase, gNtoskrnlSize;
static ERESOURCE gPsLoadedModuleResource;

NTSTATUS KeReadProcessMemory(PEPROCESS Process, PVOID Address, PVOID BufferAddress, SIZE_T* Size) {
	return MmCopyVirtualMemory(Process, Address, PsGetCurrentProcess(), BufferAddress, *Size, UserMode, Size);
}

NTSTATUS KeWriteProcessMemory(PEPROCESS Process, PVOID Address, PVOID BufferAddress, SIZE_T* Size) {
	return MmCopyVirtualMemory(PsGetCurrentProcess(), BufferAddress, Process, Address, *Size, UserMode, Size);
}

uintptr_t FindPatternInKernelSection(PCCH sectionName, uintptr_t modulePtr, BYTE* bMask, PCCH szMask) {
	auto section = FindKernelSection(sectionName, modulePtr);

	if (!section) {
		TRACE("Failed to find section %s", sectionName);
		return {};
	}

	return FindPattern(modulePtr + section->VirtualAddress, section->Misc.VirtualSize, bMask, szMask);
}

PIMAGE_SECTION_HEADER FindKernelSection(PCCH sectionName, uintptr_t imageBase) {
	auto out_section = (PIMAGE_SECTION_HEADER)nullptr;
	auto hdr = RtlImageNtHeader((void*)imageBase);

	if (!hdr)
		return out_section;

	auto firstSection = IMAGE_FIRST_SECTION(hdr);

	for (auto section = firstSection; section < firstSection + hdr->FileHeader.NumberOfSections; section++) {
		if (_stricmp(sectionName, (PCCH)section->Name) == 0) {
			out_section = section;
			break;
		}
	}

	return out_section;
}

LONG ClearPiDDBCacheTable() {
	uintptr_t PiDDBLockPtr{}, PiDTablePtr{};
	PERESOURCE PiDDBLock{};
	PRTL_AVL_TABLE PiDDBCacheTable{};

	PiDDBLockPtr = FindPatternInKernelSection("PAGE", gNtoskrnlBase, (BYTE*)"\x65\x48\x8B\x04\x25\x00\x00\x00\x00\x66\xFF\x88\x00\x00\x00\x00\xB2\x01\x48\x8D\x0D\x00\x00\x00\x00\xE8\x00\x00\x00\x00\x4C\x8B\x8C", "xxxxx????xxx????xxxxx????x????xxx"); // 65 48 8B 04 25 ?? ?? ?? ?? 66 FF 88 ?? ?? ?? ?? B2 01 48 8D 0D ?? ?? ?? ?? E8 ?? ?? ?? ?? 4C 8B 8C

	if (!PiDDBLockPtr) {
		TRACE("Failed to find PiDDBLockPtr");
		return 1;
	}

	PiDDBLock = (PERESOURCE)ResolveRelativeAddress((PVOID)PiDDBLockPtr, 21, 25);
	PiDTablePtr = FindPatternInKernelSection("PAGE", gNtoskrnlBase, (BYTE*)"\x66\x03\xD2\x48\x8D\x0D", "xxxxxx"); // 66 03 D2 48 8D 0D

	if (!PiDTablePtr) {
		TRACE("Failed to find PiDTablePtr");
		return 2;
	}

	PiDDBCacheTable = (PRTL_AVL_TABLE)ResolveRelativeAddress((PVOID)PiDTablePtr, 6, 10);

	TRACE("PiDDBCacheTable: %p", PiDDBCacheTable);
	TRACE("PiDDBLock      : %p", PiDDBLock);

	PIDCacheobj iqvw64e;
	iqvw64e.DriverName = RTL_CONSTANT_STRING(L"iqvw64e.sys");
	iqvw64e.TimeDateStamp = 0x5284EAC3; // 0x5284F8FA

	ExAcquireResourceExclusiveLite(PiDDBLock, TRUE);
	PIDCacheobj* pFoundEntry = (PIDCacheobj*)RtlLookupElementGenericTableAvl(PiDDBCacheTable, &iqvw64e);

	if (pFoundEntry == NULL) {
		ExReleaseResourceLite(PiDDBLock);
		return 3;
	}

	RemoveEntryList(&pFoundEntry->List);
	RtlDeleteElementGenericTableAvl(PiDDBCacheTable, pFoundEntry);
	PiDDBCacheTable->DeleteCount = 0;
	ExReleaseResourceLite(PiDDBLock);
	return 0;
}

static BOOLEAN IsUnloadedDriverEntryEmpty(PMM_UNLOADED_DRIVER Entry) {
	if (Entry->Name.MaximumLength == 0 || Entry->Name.Length == 0 || Entry->Name.Buffer == NULL)
		return TRUE;
	else
		return FALSE;
}

static BOOLEAN IsMmUnloadedDriversFilled() {
	for (ULONG Index = 0; Index < MM_UNLOADED_DRIVERS_SIZE; ++Index) {
		PMM_UNLOADED_DRIVER Entry = &gMmUnloadedDrivers[Index];

		if (IsUnloadedDriverEntryEmpty(Entry))
			return FALSE;
	}

	return TRUE;
}

LONG ClearMmUnloadedDrivers(PUNICODE_STRING DriverName, BOOLEAN AccquireResource) {
	if (AccquireResource)
		ExAcquireResourceExclusiveLite(&gPsLoadedModuleResource, TRUE);

	BOOLEAN Modified = FALSE;
	BOOLEAN Filled = IsMmUnloadedDriversFilled();

	for (ULONG Index = 0; Index < MM_UNLOADED_DRIVERS_SIZE; ++Index) {
		PMM_UNLOADED_DRIVER Entry = &gMmUnloadedDrivers[Index];

		if (Modified) {
			PMM_UNLOADED_DRIVER PrevEntry = &gMmUnloadedDrivers[Index - 1];
			RtlCopyMemory(PrevEntry, Entry, sizeof(MM_UNLOADED_DRIVER));

			if (Index == MM_UNLOADED_DRIVERS_SIZE - 1)
				RtlFillMemory(Entry, sizeof(MM_UNLOADED_DRIVER), 0);
		}
		else if (RtlEqualUnicodeString(DriverName, &Entry->Name, TRUE)) {
			PVOID BufferPool = Entry->Name.Buffer;
			RtlFillMemory(Entry, sizeof(MM_UNLOADED_DRIVER), 0);
			ExFreePoolWithTag(BufferPool, TAG);
			*gMmLastUnloadedDriver = (Filled ? MM_UNLOADED_DRIVERS_SIZE : *gMmLastUnloadedDriver) - 1;
			Modified = TRUE;
		}
	}

	if (Modified) {
		ULONG64 PreviousTime = 0;

		for (LONG Index = MM_UNLOADED_DRIVERS_SIZE - 2; Index >= 0; --Index) {
			PMM_UNLOADED_DRIVER Entry = &gMmUnloadedDrivers[Index];

			if (IsUnloadedDriverEntryEmpty(Entry))
				continue;

			if (PreviousTime != 0 && Entry->UnloadTime > PreviousTime)
				Entry->UnloadTime = PreviousTime - 48;

			PreviousTime = Entry->UnloadTime;
		}

		ClearMmUnloadedDrivers(DriverName, FALSE);
	}

	if (AccquireResource)
		ExReleaseResourceLite(&gPsLoadedModuleResource);

	return Modified ? 0 : 1;
}

NTSTATUS EnumKernelModules(PRTL_PROCESS_MODULES* Modules) {
	static ULONG initialBufferSize = 0x1000;
	NTSTATUS status;
	PRTL_PROCESS_MODULES buffer;
	ULONG bufferSize;

	bufferSize = initialBufferSize;
	buffer = (PRTL_PROCESS_MODULES)ExAllocatePoolWithTag(NonPagedPool, bufferSize, TAG);

	if (!buffer)
		return STATUS_INSUFFICIENT_RESOURCES;

	status = ZwQuerySystemInformation(
		SystemModuleInformation,
		buffer,
		bufferSize,
		&bufferSize
	);

	if (status == STATUS_INFO_LENGTH_MISMATCH) {
		ExFreePoolWithTag(buffer, TAG);
		buffer = (PRTL_PROCESS_MODULES)ExAllocatePoolWithTag(NonPagedPool, bufferSize, TAG);

		if (!buffer)
			return STATUS_INSUFFICIENT_RESOURCES;

		status = ZwQuerySystemInformation(
			SystemModuleInformation,
			buffer,
			bufferSize,
			&bufferSize
		);
	}

	if (!NT_SUCCESS(status))
		return status;

	if (bufferSize <= 0x100000) initialBufferSize = bufferSize;
	*Modules = buffer;

	return status;
}

LONG RetrieveMmUnloadedDriversData() {
	PRTL_PROCESS_MODULES modules{};

	if (!NT_SUCCESS(EnumKernelModules(&modules))) {
		TRACE("Failed to enumerate kernel modules");
		return 1;
	}

	PRTL_PROCESS_MODULE_INFORMATION module = modules->Modules;

	if (!module) {
		TRACE("Failed to retrieve module information");
		return 2;
	}

	for (ULONG i = 0; i < modules->NumberOfModules; i++) {
		if (strstr((char*)module[i].FullPathName, "ntoskrnl.exe")) {
			gNtoskrnlBase = (UINT64)module[i].ImageBase;
			gNtoskrnlSize = (UINT64)module[i].ImageSize;
			break;
		}
	}

	if (modules)
		ExFreePoolWithTag(modules, TAG);

	UINT64 MmLocateUnloadedDriver = FindPattern((UINT64)gNtoskrnlBase, (UINT64)gNtoskrnlSize, (BYTE*)"\xCC\x4C\x8B\x00\x00\x00\x00\x00\x4C\x8B\x00\x4D\x85\x00\x74", "xxx?????xx?xx?x"); // CC 4C 8B ?? ?? ?? ?? ?? 4C 8B ?? 4D 85 ?? 74

	if (MmLocateUnloadedDriver == NULL) {
		TRACE("Failed to find MmLocateUnloadedDriver");
		return 3;
	}

	gMmUnloadedDrivers = *(PMM_UNLOADED_DRIVER*)ResolveRelativeAddress((PVOID)MmLocateUnloadedDriver, 4, 8);

	if (*(PBYTE)(MmLocateUnloadedDriver + 0x10) == 0x8B)
		gMmLastUnloadedDriver = (PULONG)ResolveRelativeAddress((PVOID)MmLocateUnloadedDriver, 18, 22);
	else if (*(PBYTE)(MmLocateUnloadedDriver + 0x10) == 0x44)
		gMmLastUnloadedDriver = (PULONG)ResolveRelativeAddress((PVOID)MmLocateUnloadedDriver, 19, 23);

	TRACE("ntoskrnl.MmUnloadedDrivers   : %p", gMmUnloadedDrivers);
	TRACE("ntoskrnl.MmLastUnloadedDriver: %p", gMmLastUnloadedDriver);
	return 0;
}

BOOLEAN bDataCompare(const BYTE* pData, const BYTE* bMask, PCCH szMask) {
	for (; *szMask; ++szMask, ++pData, ++bMask)
		if (*szMask == 'x' && *pData != *bMask)
			return 0;

	return (*szMask) == 0;
}

uintptr_t FindPattern(uintptr_t dwAddress, uintptr_t dwLen, BYTE* bMask, PCCH szMask) {
	for (uintptr_t i = 0; i < dwLen; i++)
		if (bDataCompare((BYTE*)(dwAddress + i), bMask, szMask))
			return (uintptr_t)(dwAddress + i);

	return 0;
}

uintptr_t GetKernelProcAddress(PCWCH SystemRoutineName) {
	UNICODE_STRING Name;
	RtlInitUnicodeString(&Name, SystemRoutineName);
	return (uintptr_t)MmGetSystemRoutineAddress(&Name);
}

uintptr_t GetKernelModuleAddress(PCCH moduleName) {
	uintptr_t moduleBase{};
	PRTL_PROCESS_MODULES modules{};

	if (!NT_SUCCESS(EnumKernelModules(&modules))) {
		TRACE("Failed to enumerate kernel modules\n");
		return 0;
	}

	PRTL_PROCESS_MODULE_INFORMATION module = modules->Modules;

	if (!module) {
		TRACE("Failed to retrieve module information\n");
		return 0;
	}

	for (ULONG i = 0; i < modules->NumberOfModules; i++) {
		if (strstr((char*)module[i].FullPathName, moduleName)) {
			moduleBase = (UINT64)module[i].ImageBase;
			break;
		}
	}

	if (modules)
		ExFreePoolWithTag(modules, TAG);

	return moduleBase;

}

PVOID ResolveRelativeAddress(PVOID Instruction, ULONG OffsetOffset, ULONG InstructionSize) {
	ULONG_PTR Instr = (ULONG_PTR)Instruction;
	LONG RipOffset = *(PLONG)(Instr + OffsetOffset);
	PVOID ResolvedAddr = (PVOID)(Instr + InstructionSize + RipOffset);
	return ResolvedAddr;
}
