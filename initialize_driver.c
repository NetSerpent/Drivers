#include "constants.h"
#include "common.h"
#include "wfp.h"
#include "filter.h"
#include "globals.h"
#include "packet_queue.h"
#include <ntstrsafe.h> // For RtlStringCchPrintfA
#include "network_info.h"
#include "netserpent_packet.h"
#include "async_classify.h"
#include "initialize_driver.h"


// kernel drivers generally don't support float operations ...
int _fltused = 0;

// Forward declarations
NTSTATUS DriverCreate(PDEVICE_OBJECT DeviceObject, PIRP Irp);
NTSTATUS DriverClose(PDEVICE_OBJECT DeviceObject, PIRP Irp);
NTSTATUS DeviceIoControlHandler(PDEVICE_OBJECT DeviceObject, PIRP Irp);
VOID   DriverUnload(PDRIVER_OBJECT DriverObject);

/*---------------------------------------------------------------------
  Function called when driver is being unloaded
---------------------------------------------------------------------*/
VOID DriverUnload(PDRIVER_OBJECT DriverObject)
{
    UNICODE_STRING symLinkName = RTL_CONSTANT_STRING(NETSERPENT_SYMLINK_NAME);
    UnInitWfp();  // tear down WFP
    IoDeleteSymbolicLink(&symLinkName);
    IoDeleteDevice(DeviceObject);
    DebugMessage("NetSerpent: Unloaded Driver\n");
}

/*---------------------------------------------------------------------
  CommunicationServiceStartup:
    Creates the device & symbolic link, and crucially, sets up IRP
    dispatch routines so that user-mode can open \\.\NetSerpent now.
---------------------------------------------------------------------*/
NTSTATUS CommunicationServiceStartup(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{
    NTSTATUS status;
    UNICODE_STRING deviceName = RTL_CONSTANT_STRING(NETSERPENT_DEVICE_NAME);
    UNICODE_STRING symLinkName = RTL_CONSTANT_STRING(NETSERPENT_SYMLINK_NAME);

    // Create the device
    status = IoCreateDevice(
        DriverObject,
        0,
        &deviceName,
        FILE_DEVICE_UNKNOWN,
        0,
        FALSE,
        &DeviceObject
    );
    if (!NT_SUCCESS(status)) {
        DebugMessage("NetSerpent: Failed to create device\n");
        RtlStringCchPrintfA(g_ErrorMessage, sizeof(g_ErrorMessage),
            "NetSerpent Error: Failed to create device (0x%08X)", status);
        return status;
    }
    DebugMessage("NetSerpent: Created Io Device.\n");

    //
    // *** REGISTER IRP DISPATCH ROUTINES HERE ***
    //
    DriverObject->MajorFunction[IRP_MJ_CREATE] = DriverCreate;
    DriverObject->MajorFunction[IRP_MJ_CLOSE] = DriverClose;
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DeviceIoControlHandler;
    DriverObject->DriverUnload = DriverUnload;

    // Create a symbolic link for user mode:  \\.\NetSerpent => \Device\NetSerpent
    status = IoCreateSymbolicLink(&symLinkName, &deviceName);
    if (!NT_SUCCESS(status)) {
        IoDeleteDevice(DeviceObject);
        DebugMessage("NetSerpent: Failed to create symbolic link\n");
        RtlStringCchPrintfA(g_ErrorMessage, sizeof(g_ErrorMessage),
            "NetSerpent Error: Failed to create symbolic link (0x%08X)", status);
        return status;
    }
    DebugMessage("NetSerpent: Created Io Link.\n");

    // Initialize our admin connection event (non-signaled)
    KeInitializeEvent(&AdminConnectionEvent, NotificationEvent, FALSE);

    // Initialize security approval event
    KeInitializeEvent(&SecurityApprovalEvent, NotificationEvent, FALSE);

    DebugMessage("NetSerpent: Communication service startup complete.\n");
    return status;
}

/*---------------------------------------------------------------------
  FilterServiceStartup:
    Called when we want to actually start the WFP filter. Note we no
    longer set IRP dispatch routines here, because we did that above.
---------------------------------------------------------------------*/
NTSTATUS FilterServiceStartup(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{
    NTSTATUS status;

    // Set up your packet queue as before
    PacketQueueInitialize();

    // NEW: Initialize injection handle for out-of-band injection
    status = InitializeInjectionHandle();
    if (!NT_SUCCESS(status))
    {
        DebugMessage("Failed to create injection handle: 0x%08X\n", status);
        return status;
    }

    // Now do the normal WFP initialization
    status = InitializeWfp();
    if (!NT_SUCCESS(status))
    {
        CleanupInjectionHandle();
        RtlStringCchPrintfA(g_ErrorMessage, sizeof(g_ErrorMessage),
            "NetSerpent Error: Failed to initialize WFP (0x%08X)", status);
        IoDeleteDevice(DeviceObject);
        DebugMessage("%s\n", g_ErrorMessage);
        return status;
    }

    DebugMessage("NetSerpent: Filter service startup complete.\n");
    return STATUS_SUCCESS;
}


/*---------------------------------------------------------------------
  DriverCreate & DriverClose
---------------------------------------------------------------------*/
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

/*---------------------------------------------------------------------
  DeviceIoControlHandler
---------------------------------------------------------------------*/
NTSTATUS DeviceIoControlHandler(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    PIO_STACK_LOCATION irpSp = IoGetCurrentIrpStackLocation(Irp);
    ULONG controlCode = irpSp->Parameters.DeviceIoControl.IoControlCode;
    NTSTATUS status = STATUS_INVALID_DEVICE_REQUEST;
    ULONG_PTR information = 0;
    PVOID outBuffer = Irp->AssociatedIrp.SystemBuffer;
    ULONG inBufferLength = irpSp->Parameters.DeviceIoControl.InputBufferLength;
    ULONG outBufferLength = irpSp->Parameters.DeviceIoControl.OutputBufferLength;

    DebugMessage("NetSerpent: DeviceIoControlHandler triggered.\n");

    switch (controlCode)
    {
    case IOCTL_GET_PCAP_PACKET:
    {
        DebugMessage("IOCTL_GET_PCAP_PACKET");
        // BUG FIX: Program crashes when we receive this command in specific at the start
        /*ULONG bytesCopied = 0;
        status = DequeuePcapPacket(outBuffer, outBufferLength, &bytesCopied);
        information = bytesCopied;*/
        break;
    }
    case IOCTL_GET_ERROR_MESSAGE:
    {
        DebugMessage("IOCTL_GET_ERROR_MESSAGE");
        g_ErrorMessage[sizeof(g_ErrorMessage) - 1] = '\0';
        size_t messageLength = strlen(g_ErrorMessage) + 1;
        if (messageLength == 1) {
            const char defaultMsg[] = "No error.";
            RtlCopyMemory(g_ErrorMessage, defaultMsg, sizeof(defaultMsg));
            messageLength = sizeof(defaultMsg);
        }
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
    case IOCTL_SET_NETWORK_INFO:
    {
        DebugMessage("IOCTL_SET_NETWORK_INFO");
        if (inBufferLength < sizeof(GUID)) {
            status = STATUS_BUFFER_TOO_SMALL;
            break;
        }
        GUID* newGuid = (GUID*)Irp->AssociatedIrp.SystemBuffer;
        NTSTATUS saveStatus = SaveNetworkInfo(newGuid);
        if (NT_SUCCESS(saveStatus)) {
            KeSetEvent(&AdminConnectionEvent, IO_NO_INCREMENT, FALSE);
        }
        status = saveStatus;
        information = sizeof(GUID);
        
        break;
    }
    case IOCTL_SEND_NETSERPENT_COMMAND:
    {
        DebugMessage("IOCTL_SEND_NETSERPENT_COMMAND");
        if (inBufferLength < 1) {
            status = STATUS_INVALID_PARAMETER;
            break;
        }
        UCHAR* cmdBuffer = (UCHAR*)Irp->AssociatedIrp.SystemBuffer;
        UCHAR command = cmdBuffer[0];
        switch (command) {
        case 0x03: // Security status response
            ProcessSecurityStatusCommand(cmdBuffer + 1, inBufferLength - 1);
            status = STATUS_SUCCESS;
            information = inBufferLength;
            break;
        default:
            status = STATUS_INVALID_DEVICE_REQUEST;
            break;
        }
        
        break;
    }
    case IOCTL_INFORM_NETWORK_CONNECTED:
    {
        g_ClientConnected = TRUE;
        // Now start the filtering services.
        status = FilterServiceStartup(g_DriverObject, &g_RegistryPath);
        if (!NT_SUCCESS(status)) {
            DebugMessage("NetSerpent: Failed to start filter services: 0x%08X\n", status);
        }
        else {
            DebugMessage("NetSerpent: Filter services started.\n");
        }
        //information = 0;
        DebugMessage("IOCTL_INFORM_NETWORK_CONNECTED");
        break;
    }
    default:
        // no-op
        break;
    }

    Irp->IoStatus.Status = status;
    Irp->IoStatus.Information = information;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return status;
}
