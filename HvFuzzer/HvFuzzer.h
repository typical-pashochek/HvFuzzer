#pragma once

// #include <wdm.h>
#include <ntddk.h>
#include <windef.h>
#include "../common/types.h"

#define DEVICE_NAME L"\\Device\\HvFuzzer"
#define SYMLINK_NAME L"\\DosDevices\\HvFuzzer"

#define DBG_PRINT(...) DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, __VA_ARGS__)

#define INPUT_BUF_SIZE 0x1000

NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath);
VOID UnloadDriver(PDRIVER_OBJECT DriverObject);
NTSTATUS CreateCloseHandler(PDEVICE_OBJECT DeviceObject, PIRP Irp);
NTSTATUS IoControlHandler(PDEVICE_OBJECT DeviceObject, PIRP Irp);
