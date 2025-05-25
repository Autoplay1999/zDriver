#pragma once
#ifndef __ZDRV_HPP__
#define __ZDRV_HPP__

#include <cstdint>

#ifndef IOCTL_DISK_BASE
#	define IOCTL_DISK_BASE                  FILE_DEVICE_DISK
#	define IOCTL_DISK_UPDATE_PROPERTIES     CTL_CODE(IOCTL_DISK_BASE, 0x0050, METHOD_BUFFERED, FILE_ANY_ACCESS)
#endif

#define ZDRV_IOCTL_VERIFY			        CTL_CODE(FILE_DEVICE_UNKNOWN, 0x1101, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)
#define ZDRV_IOCTL_SUSPEND_PROCESS	        CTL_CODE(FILE_DEVICE_UNKNOWN, 0x1102, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)
#define ZDRV_IOCTL_RESUME_PROCESS	        CTL_CODE(FILE_DEVICE_UNKNOWN, 0x1103, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)
#define ZDRV_IOCTL_READ_MEMORY	            CTL_CODE(FILE_DEVICE_UNKNOWN, 0x1104, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)
#define ZDRV_IOCTL_WRITE_MEMORY	            CTL_CODE(FILE_DEVICE_UNKNOWN, 0x1105, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)
#define ZDRV_IOCTL_GET_PROCESS_PEB			CTL_CODE(FILE_DEVICE_UNKNOWN, 0x1106, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)
#define ZDRV_IOCTL_GET_PROCESS_BASE			CTL_CODE(FILE_DEVICE_UNKNOWN, 0x1107, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)

#define ZDRV_FILTER_CODE              0xC16F31A2ED659EFB
#define ZDRV_VERIFY_CLIENT_SIGNATURE  0xD9BDF4632FB7EACE
#define ZDRV_VERIFY_DRIVER_SIGNATURE  0xAC5D4AF0E31D7BDB

enum class ZDRV_ERROR {
	Success,
	PsLookupProcessByProcessId_Failed,
	PsSuspendProcess_Failed,
	PsResumeProcess_Failed,
	KeReadProcessMemory_Failed,
	KeWriteProcessMemory_Failed,
	PsGetProcessPeb_Failed,
	PsGetProcessBase_Failed
};

//----------------------------------------------------------------//
// INPUT
//----------------------------------------------------------------//

struct INPUT_BASE_IOCTL_CALL {
	uint64_t Filter;
	uint64_t ControlCode;
};

struct INPUT_VERIFY_IOCTL_CALL: INPUT_BASE_IOCTL_CALL {
	uint64_t UserSignature;
};

struct INPUT_PROCESS_IOCTL_CALL: INPUT_BASE_IOCTL_CALL {
	uint64_t ProcessId;
};

struct INPUT_MEMORY_IOCTL_CALL: INPUT_PROCESS_IOCTL_CALL {
	uint64_t Address;
	uint64_t Size;
};

struct INPUT_READWRITE_IOCTL_CALL: INPUT_MEMORY_IOCTL_CALL {
	uint64_t Buffer;
};

//----------------------------------------------------------------//
// OUTPUT
//----------------------------------------------------------------//

struct OUTPUT_BASE_IOCTL_CALL {
	ZDRV_ERROR DrvError;
};

struct OUTPUT_VERIFY_IOCTL_CALL: OUTPUT_BASE_IOCTL_CALL {
	uint64_t DrvSignature;
};

struct OUTPUT_READWRITE_IOCTL_CALL: OUTPUT_BASE_IOCTL_CALL {
	uint64_t rwBytes;
};

struct OUTPUT_POINTER_IOCTL_CALL: OUTPUT_BASE_IOCTL_CALL {
	uint64_t Pointer;
};

//----------------------------------------------------------------//

inline void lazy_encode(void* data, size_t size) {
	for (int i = 0; i < size; i++)
		static_cast<uint8_t*>(data)[i] = static_cast<uint8_t>(255 - static_cast<int>(static_cast<uint8_t*>(data)[i]));
}

#endif