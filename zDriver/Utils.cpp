#include "main.h"

static PMM_UNLOADED_DRIVER gMmUnloadedDrivers;
static PULONG gMmLastUnloadedDriver;
static UINT64 gNtoskrnlBase, gNtoskrnlSize;

//LONG RetrieveMmUnloadedDriversData()  {
//	ULONG bytes = 0;
//
//	NTSTATUS status = ZwQuerySystemInformation(SystemModuleInformation, 0, bytes, &bytes);
//	if (!bytes) return 1;
//	PRTL_PROCESS_MODULES modules = (PRTL_PROCESS_MODULES)ExAllocatePoolWithTag(NonPagedPool, bytes, 0x504D5448);
//	status = ZwQuerySystemInformation(SystemModuleInformation, modules, bytes, &bytes);
//	if (!NT_SUCCESS(status)) return 2;
//	PRTL_PROCESS_MODULE_INFORMATION module = modules->Modules;
//
//	for (ULONG i = 0; i < modules->NumberOfModules; i++) {
//		if (strstr((char*)module[i].FullPathName, "ntoskrnl.exe")) {
//			gNtoskrnlBase = (UINT64)module[i].ImageBase;
//			gNtoskrnlSize = (UINT64)module[i].ImageSize;
//			break;
//		}
//	}
//	if (modules) ExFreePoolWithTag(modules, 0);
//
//	UINT64 MmUnloadedDriversInstr = FindPattern((UINT64)gNtoskrnlBase, (UINT64)gNtoskrnlSize, (BYTE*)"\x4C\x8B\x00\x00\x00\x00\x00\x4C\x8B\xC9\x4D\x85\x00\x74", "xx?????xxxxx?x");
//	if (MmUnloadedDriversInstr == NULL) return 3;
//
//	UINT64 MmLastUnloadedDriverInstr = FindPattern((UINT64)gNtoskrnlBase, (UINT64)gNtoskrnlSize, (BYTE*)"\x8B\x05\x00\x00\x00\x00\x83\xF8\x32", "xx????xxx");
//	if (MmLastUnloadedDriverInstr == NULL) return 4;
//
//	gMmUnloadedDrivers = *(PMM_UNLOADED_DRIVER*)ResolveRelativeAddress((PVOID)MmUnloadedDriversInstr, 3, 7);
//	gMmLastUnloadedDriver = (PULONG)ResolveRelativeAddress((PVOID)MmLastUnloadedDriverInstr, 2, 6);
//
//	return 0;
//}

BOOLEAN bDataCompare(const BYTE* pData, const BYTE* bMask, const char* szMask)
{
	for (; *szMask; ++szMask, ++pData, ++bMask)
		if (*szMask == 'x' && *pData != *bMask)
			return 0;

	return (*szMask) == 0;
}

UINT64 FindPattern(UINT64 dwAddress, UINT64 dwLen, BYTE* bMask, const char* szMask)
{
	for (UINT64 i = 0; i < dwLen; i++)
		if (bDataCompare((BYTE*)(dwAddress + i), bMask, szMask))
			return (UINT64)(dwAddress + i);

	return 0;
}

PVOID NTAPI GetKernelProcAddress(LPCWSTR SystemRoutineName)
{
	UNICODE_STRING Name;
	RtlInitUnicodeString(&Name, SystemRoutineName);
	return MmGetSystemRoutineAddress(&Name);
}

ULONG64 GeModuleBase(const char* Findmodule)
{
	ULONG modulesSize = 0;
	NTSTATUS ReturnCode = ZwQuerySystemInformation(SystemModuleInformation, 0, modulesSize, &modulesSize);

	if (!modulesSize)
		return 0;

	PRTL_PROCESS_MODULES ModuleList = (PRTL_PROCESS_MODULES)ExAllocatePoolWithTag(NonPagedPool, modulesSize, 'ENON'); // 'ENON'

	ReturnCode = ZwQuerySystemInformation(SystemModuleInformation, ModuleList, modulesSize, &modulesSize);

	if (!NT_SUCCESS(ReturnCode))
		return 0;

	PRTL_PROCESS_MODULE_INFORMATION module = ModuleList->Modules;

	for (ULONG i = 0; i < ModuleList->NumberOfModules; i++)
	{
		if (strstr((char*)module[i].FullPathName, Findmodule))
		{
			if (ModuleList)
				ExFreePoolWithTag(ModuleList, 'ENON');

			return (UINT64)module[i].ImageBase;
		}
	}

	if (ModuleList)
		ExFreePoolWithTag(ModuleList, 'ENON');

	return 0;

}

PVOID ResolveRelativeAddress(PVOID Instruction, ULONG OffsetOffset, ULONG InstructionSize)
{
	ULONG_PTR Instr = (ULONG_PTR)Instruction;
	LONG RipOffset = *(PLONG)(Instr + OffsetOffset);
	PVOID ResolvedAddr = (PVOID)(Instr + InstructionSize + RipOffset);
	return ResolvedAddr;
}
