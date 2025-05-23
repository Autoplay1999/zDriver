#pragma once
#pragma warning( disable : 4099 )

#include <ntdef.h>
#include <ntifs.h>

#include <ntifs.h>
#include <ntddk.h>
#include <windef.h>
#include <wdf.h>
#include <ntdef.h>
#include <ntimage.h>
#include <ntifs.h>
#include <intrin.h>

#include <ntdef.h>
#include <ntifs.h>
#include <ntifs.h>
#include <ntddk.h>
#include <windef.h>
#include <wdf.h>
#include <ntdef.h>

#include <ntimage.h>
#include <ntifs.h>
#include <intrin.h>

#include "Utils.h"

DRIVER_INITIALIZE DriverInitialize;
extern "C" DRIVER_INITIALIZE DriverEntry;
extern "C" NTSTATUS PsSuspendProcess(PEPROCESS Process);
extern "C" NTSTATUS PsResumeProcess(PEPROCESS Process);

#define TRACE(fmt, ...)	DbgPrintEx( DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[ZDriver.Driver] " fmt "\n", __VA_ARGS__ )
#define TRACE_BEGIN(name) TRACE("[ " name " ]")
#define TRACE_END() TRACE("[ END ]")

#define BLOCK_BEGIN() while (true) {
#define BLOCK_BEGIN_(x) while (x) {
#define BLOCK_END() break;}
#define BLOCK_EXIT() break
#define BLOCK_NEXT() continue