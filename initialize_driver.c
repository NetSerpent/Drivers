#include "common.h"
#include "wfp.h"
#include "filter.h"
#include "globals.h"
#include "packet_queue.h"
#include <ntstrsafe.h> // For RtlStringCchPrintfA

//---------------------------------------------------------------------
// Function called when driver is being unloaded
//---------------------------------------------------------------------
VOID DriverUnload(PDRIVER_OBJECT DriverObject)
{
    UNICODE_STRING symLinkName = RTL_CONSTANT_STRING(L"\\DosDevices\\NetSerpent");
    UnInitWfp();
    IoDeleteSymbolicLink(&symLinkName);
    IoDeleteDevice(DeviceObject);
    DebugMessage("NetSerpent: Unloaded Driver ");
}


// ----------------------------------------
//  I/O service opening and closing
// ----------------------------------------
// initialize_driver.c (modify DeviceIoControlHandler)
NTSTATUS DeviceIoControlHandler(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    PIO_STACK_LOCATION irpSp = IoGetCurrentIrpStackLocation(Irp);
    ULONG controlCode = irpSp->Parameters.DeviceIoControl.IoControlCode;
    NTSTATUS status = STATUS_INVALID_DEVICE_REQUEST;
    ULONG_PTR information = 0;
    PVOID outBuffer = Irp->AssociatedIrp.SystemBuffer;
    ULONG outBufferLength = irpSp->Parameters.DeviceIoControl.OutputBufferLength;

    switch (controlCode) {
    case IOCTL_GET_PCAP_PACKET:
    {
        ULONG bytesCopied = 0;
        status = DequeuePcapPacket(outBuffer, outBufferLength, &bytesCopied);
        information = bytesCopied;
        break;
    }
    case IOCTL_GET_ERROR_MESSAGE:
    {
        size_t messageLength = strlen(g_ErrorMessage) + 1;
        if (outBufferLength < messageLength) {
            status = STATUS_BUFFER_TOO_SMALL;
        }
        else {
            RtlCopyMemory(outBuffer, g_ErrorMessage, messageLength);
            status = STATUS_SUCCESS;
            information = (ULONG_PTR)messageLength;
        }
        break;
    }
    default:
        break;
    }

    Irp->IoStatus.Status = status;
    Irp->IoStatus.Information = information;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return status;
}


NTSTATUS DriverCreate(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{

    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}

NTSTATUS DriverClose(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{

    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}



NTSTATUS CommunicationServiceStartup(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{
    NTSTATUS status;
    UNICODE_STRING deviceName = RTL_CONSTANT_STRING(L"\\Device\\NetSerpent"); // TODO: Perhaps we store this in a constants file?
    UNICODE_STRING symLinkName = RTL_CONSTANT_STRING(L"\\DosDevices\\NetSerpent");

    // Create the device
    status = IoCreateDevice(
        DriverObject,
        0,
        &deviceName,
        FILE_DEVICE_UNKNOWN,
        0,
        FALSE,
        &DeviceObject);
    if (!NT_SUCCESS(status)) {
        DebugMessage("NetSerpent: Failed to create device\n");
        RtlStringCchPrintfA(g_ErrorMessage, sizeof(g_ErrorMessage),
            "NetSerpent Error: Failed to create device (0x%08X)", status);
        return status;
    }

    // Create a symbolic link for user mode.
    status = IoCreateSymbolicLink(&symLinkName, &deviceName);
    if (!NT_SUCCESS(status)) {
        IoDeleteDevice(DeviceObject);
        DebugMessage("NetSerpent: Failed to create symbolic link\n");
        RtlStringCchPrintfA(g_ErrorMessage, sizeof(g_ErrorMessage),
            "NetSerpent Error: Failed to create symbolic link (0x%08X)", status);
        return status;
    }

    return status;
}

NTSTATUS FilterServiceStartup(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{
    NTSTATUS status;

    // Register IRP dispatch routines
    DriverObject->MajorFunction[IRP_MJ_CREATE] = DriverCreate;
    DriverObject->MajorFunction[IRP_MJ_CLOSE] = DriverClose;
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DeviceIoControlHandler;
    DriverObject->DriverUnload = DriverUnload;

    // Initialize the packet queue and WFP components
    PacketQueueInitialize();

    status = InitializeWfp();
    if (!NT_SUCCESS(status)) {
        RtlStringCchPrintfA(g_ErrorMessage, sizeof(g_ErrorMessage),
            "NetSerpent Error: Failed to initialize WFP (0x%08X)", status);
        IoDeleteDevice(DeviceObject);
        DebugMessage("%s\n", g_ErrorMessage);
        return status;
    }

    return STATUS_SUCCESS;
}

