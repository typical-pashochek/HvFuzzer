#include "HvFuzzer.h"

#pragma optimize("", off)
__declspec(noinline)
HV_STATUS
__fastcall
Hypercall
//(char opType, short sscn, int zero, char* callData);
(
    IN  PCPU_REG_64 regsIn,
    OUT PCPU_REG_64 regsOut
);

#pragma optimize("", on) 

HV_X64_HYPERCALL_OUTPUT HvlInvokeHypercall(HV_X64_HYPERCALL_INPUT InputValue, ULONGLONG InputPa, ULONGLONG OutputPa);

typedef HV_X64_HYPERCALL_OUTPUT(*VslpEnterIumSecureMode)(char opType, short sscn, int zero, PCHAR callData);

NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath) 
{
    PDEVICE_OBJECT deviceObject = NULL;
    UNICODE_STRING deviceName;
    UNICODE_STRING symLinkName;
    NTSTATUS status;


    UNREFERENCED_PARAMETER(RegistryPath);
    
    RtlInitUnicodeString(&deviceName, DEVICE_NAME);
    
    status = IoCreateDevice(DriverObject, 0, &deviceName, HV_FUZZER_DEVICE, 0, FALSE, &deviceObject);

    if (!NT_SUCCESS(status)) 
    {
        DBG_PRINT("[-] Can't create device\n");
        return status;
    }

    RtlInitUnicodeString(&symLinkName, SYMLINK_NAME);
    status = IoCreateSymbolicLink(&symLinkName, &deviceName);

    if (!NT_SUCCESS(status)) 
    {
        DBG_PRINT("[-] Can't create symlink\n");
        IoDeleteDevice(deviceObject);
        return status;
    }

    DriverObject->DriverUnload = UnloadDriver;

    DriverObject->MajorFunction[IRP_MJ_CREATE] = CreateCloseHandler;
    DriverObject->MajorFunction[IRP_MJ_CLOSE] = CreateCloseHandler;
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = IoControlHandler;

    DBG_PRINT("[+] HvFuzzer loaded\n");

    return STATUS_SUCCESS;
}


VOID UnloadDriver(PDRIVER_OBJECT DriverObject) 
{
    UNICODE_STRING symLinkName;

    RtlInitUnicodeString(&symLinkName, SYMLINK_NAME);
    IoDeleteSymbolicLink(&symLinkName);

    IoDeleteDevice(DriverObject->DeviceObject);

    DBG_PRINT("[+] HvFuzzer unloaded\n");
}


NTSTATUS CreateCloseHandler(PDEVICE_OBJECT DeviceObject, PIRP Irp) 
{
    UNREFERENCED_PARAMETER(DeviceObject);

    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;

    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}


VOID FillPage(IN OUT PCHAR pInBuf, IN INT bSize, IN UINT64 content8B)
{
    for (int i = 0; i < bSize / 8; i++)
    {
        *((PUINT64)pInBuf + i) = content8B;
    }

}


NTSTATUS
MapUserBufferToMdl(
    _In_ PVOID UserBuffer,
    _In_ ULONG BufferSize,
    _In_ BOOLEAN IsInput,
    _Out_ PULONGLONG MappedPa,
    _Out_ PMDL* MdlToFree
)
{
    PMDL hvMdl;
    PHYSICAL_ADDRESS low, high;
    PVOID mapBuffer;
    ULONG pageCount;
    ULONG idealNode;
    ULONG flags;
    NTSTATUS status;
    //
    // Allocate an MDL for the number of pages needed, in the
    // current NUMA node, and allow the processor to cache them.
    // In case more than a page of data is needed, make sure to
    // require contiguous pages, as the hypervisor only receives
    // the starting PFN, not an array. We also allow the memory
    // manager to look at other non local nodes if the current
    // one is unavailable, and we speed it up by not requesting
    // zeroed memory.
    //
    * MdlToFree = NULL;
    *MappedPa = 0;
    low.QuadPart = 0;
    high.QuadPart = ~0ULL;
    pageCount = ROUND_TO_PAGES(BufferSize);
    idealNode = KeGetCurrentNodeNumber();
    flags = MM_ALLOCATE_REQUIRE_CONTIGUOUS_CHUNKS |
        MM_ALLOCATE_FULLY_REQUIRED |
        MM_DONT_ZERO_ALLOCATION;
    //
    // Use the very latest 1809 API which also allows us to
    // pass in the Memory Partition from which to grab the
    // pages from -- in our case we pass NULL meaning use the
    // System Partition (0).
    //
    hvMdl = MmAllocatePartitionNodePagesForMdlEx(low,
        high,
        low,
        pageCount,
        MmCached,
        idealNode,
        flags,
        NULL);
    if (hvMdl == NULL)
    {
        //
        // There is not enough free contiguous physical memory,
        // bail out
        //
        DbgPrintEx(DPFLTR_IHVDRIVER_ID,
            DPFLTR_ERROR_LEVEL,
            "Failed to allocate MDL\n");
        status = STATUS_INSUFFICIENT_RESOURCES;
        goto Cleanup;
    }
    //
    // Map the MDL pages in kernel-mode, with RWNX permissions
    //
    mapBuffer = MmGetSystemAddressForMdlSafe(hvMdl,
        MdlMappingNoExecute);
    if (mapBuffer == NULL)
    {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID,
            DPFLTR_ERROR_LEVEL,
            "Failed to map buffer\n");
        status = STATUS_INSUFFICIENT_RESOURCES;
        goto Cleanup;
    }
    //
    // Use SEH in case the user-mode buffer is invalid
    //
    __try
    {
        if (IsInput != FALSE)
        {
            //
            // Make sure the input buffer is aligned user-mode
            // memory, then copy it into the mapped kernel buffer
            //
            /*ProbeForRead(UserBuffer,
                BufferSize,
                __alignof(UCHAR));*/
            RtlCopyMemory(mapBuffer,
                UserBuffer,
                BufferSize);
        }
        else
        {
            //
            // Make sure the output buffer is aligned user-mode
            // memory and that it is writeable. The copy will be
            // done after the hypercall completes.
            //
            /*ProbeForWrite(UserBuffer,
                BufferSize,
                __alignof(UCHAR));*/
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        //
        // An exception was raised, bail out
        //
        status = GetExceptionCode();
        DbgPrintEx(DPFLTR_IHVDRIVER_ID,
            DPFLTR_ERROR_LEVEL,
            "Exception copying buffer : %lx\n",
            status);
        goto Cleanup;
    }
    //
    // Hyper-V will want to know the starting physical address
    // for the buffer, so grab it
    //
    *MappedPa = *MmGetMdlPfnArray(hvMdl) << PAGE_SHIFT;
    *MdlToFree = hvMdl;
    status = STATUS_SUCCESS;
Cleanup:
    //
    // On failure, clean up the MDL if one was created/mapped
    //
    if (!(NT_SUCCESS(status)) && (hvMdl != NULL))
    {
        //
        // This also cleans up the mapping buffer if one exists
        //
        MmFreePagesFromMdlEx(hvMdl, 0);
        ExFreePool(hvMdl);
    }
    return status;
}


NTSTATUS IoControlHandler(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    UNREFERENCED_PARAMETER(DeviceObject);

    ULONG bytesRet = 0;
    PIO_STACK_LOCATION ioStackLocation = IoGetCurrentIrpStackLocation(Irp);
    NTSTATUS status = STATUS_SUCCESS;
    ULONG inputBufferLength = ioStackLocation->Parameters.DeviceIoControl.InputBufferLength;


    switch (ioStackLocation->Parameters.DeviceIoControl.IoControlCode)
    {
    case IOCTL_SEND_MESSAGE:
        if (inputBufferLength > 0) 
            DBG_PRINT("[+] Message: %s\n", (char*)Irp->AssociatedIrp.SystemBuffer);
        else 
            DBG_PRINT("[+] Message: empty\n");

        break;
    case IOCTL_MSR_READ:
    {
        ULONG msr = *(PULONG)(Irp->AssociatedIrp.SystemBuffer);
        *(PULONG)(Irp->AssociatedIrp.SystemBuffer) = (ULONG)__readmsr(msr);

        bytesRet = 4;
        status = STATUS_SUCCESS;

        DBG_PRINT("[+] MSR_READ: done\n");
        break;
    }
    case IOCTL_CPUID:
    {
        INT cpuid = *(PULONG)(Irp->AssociatedIrp.SystemBuffer);
        PCPU_REG_32 pOutRegs = Irp->AssociatedIrp.SystemBuffer;

        __cpuid((INT*)pOutRegs, cpuid);

        bytesRet = sizeof(CPU_REG_32);
        status = STATUS_SUCCESS;

        DBG_PRINT("[+] CPUID: done\n");
        break;
    }
    case IOCTL_HYPERCALL:
    {            
        HV_X64_HYPERCALL_OUTPUT hvResult = { 0 };
        CPU_REG_64 inReg = { 0 };
        CPU_REG_64 outReg = { 0 };
        HYPERCALL_DATA hypercallData;

        RtlCopyMemory(&hypercallData, Irp->AssociatedIrp.SystemBuffer, sizeof(HYPERCALL_DATA));

        PCHAR pInBuf = ExAllocatePoolWithTag(NonPagedPool, INPUT_BUF_SIZE, 'fuzz');
        if (!pInBuf)
        {
            DBG_PRINT("[-] Can't allocate pool\n");
            status = STATUS_INTERNAL_ERROR;
            break;
        }

        RtlZeroMemory(pInBuf, INPUT_BUF_SIZE);
        RtlCopyMemory(pInBuf, (PCHAR)hypercallData.inputParameter, INPUT_BUF_SIZE);

        //PHYSICAL_ADDRESS realAddr = MmGetPhysicalAddress(pInBuf);
        //inReg.rdx = realAddr.QuadPart;    

        inReg.rcx = hypercallData.hypercallInput.AsUINT64;      
        inReg.rdx = (UINT64)pInBuf;

        //hvResult.CallStatus = Hypercall(&inReg, &outReg);

        VslpEnterIumSecureMode vslpEnterIumSecureMode = (VslpEnterIumSecureMode)0xfffff80369342a90;

        UNICODE_STRING functionName;
        RtlInitUnicodeString(&functionName, L"FsRtlGetNextBaseMcbEntry");
        PVOID functionAddress = MmGetSystemRoutineAddress(&functionName);

        //Windows 11 23H2
        vslpEnterIumSecureMode = (VslpEnterIumSecureMode)((UINT64)functionAddress + 0x1040);

        /*DBG_PRINT("[+] Hypercall %llx\n", vslpEnterIumSecureMode);
        outReg.rax = (UINT64)vslpEnterIumSecureMode;*/

        //DbgBreakPoint();

        if (hypercallData.hypercallInput.callCode == 0x11)
        {
            short sscn = ((SHORT*)pInBuf)[1];
            DBG_PRINT("[+] Secure service %hx\n", sscn);
            hvResult = vslpEnterIumSecureMode(2, sscn, 0, pInBuf);
        }
        else
        {
            DBG_PRINT("[+] Hypercall %llx\n", hypercallData.hypercallInput.AsUINT64);

            ULONGLONG inputPa;
            PMDL inputMdl;

            status = MapUserBufferToMdl(pInBuf, INPUT_BUF_SIZE, TRUE, &inputPa, &inputMdl);

            if (!NT_SUCCESS(status))
            {
                DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "Failed to create input MDL: %lx\n", status);
                return 0;
            }

            hvResult = HvlInvokeHypercall(hypercallData.hypercallInput, inputPa, 0);
        }


        RtlCopyMemory(Irp->AssociatedIrp.SystemBuffer, &outReg, sizeof(CPU_REG_64));
        bytesRet = sizeof(CPU_REG_64);
        status = STATUS_SUCCESS;

        ExFreePoolWithTag(pInBuf, 'fuzz');
        break;
    }
    default:
        status = STATUS_INVALID_DEVICE_REQUEST;
        break;
    }

    Irp->IoStatus.Information = bytesRet;
    Irp->IoStatus.Status = status;

    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return status;
}

