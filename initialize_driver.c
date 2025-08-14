#include "constants.h"
#include "common.h"
#include "wfp.h"
#include "filter.h"
#include "globals.h"
#include "packet_queue.h"
#include <ntstrsafe.h> // For RtlStringCchPrintfA

#include "initialize_driver.h"

// For I/O and networking
#include "network_info.h"
#include "netserpent_packet.h"
#include "async_classify.h"
#include "driver_to_client.h"


// kernel drivers generally don't support float operations ...
int _fltused = 0;

// Forward declarations
NTSTATUS DriverCreate(PDEVICE_OBJECT DeviceObject, PIRP Irp);
NTSTATUS DriverClose(PDEVICE_OBJECT DeviceObject, PIRP Irp);
NTSTATUS DeviceIoControlHandler(PDEVICE_OBJECT DeviceObject, PIRP Irp);
VOID   DriverUnload(PDRIVER_OBJECT DriverObject);


/*
    HELPER FUNCTIONS
*/
/// HELPER FUNCTIONS -------------------------------------------
const char* IoctlCodeToString(ULONG controlCode)
{
    switch (controlCode)
    {
    case IOCTL_GET_CLIENT_COMMAND_HANDLE:
        return "IOCTL_GET_CLIENT_COMMAND_HANDLE";
    case IOCTL_SET_STREAMING_SERVER_IP:
        return "IOCTL_SET_STREAMING_SERVER_IP";
    case IOCTL_PROCESS_SECURITY_RESPONSE:
        return "IOCTL_PROCESS_SECURITY_RESPONSE";
    case IOCTL_INFORM_NETWORK_CONNECTED:
        return "IOCTL_INFORM_NETWORK_CONNECTED";
    case IOCTL_PING:
        return "IOCTL_PING";
    default:
        return "Unknown IOCTL";
    }
}

/// SERVICE STARTUP FUNCTIONS -------------------------------------------

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

    // Initialize our admin connection event (non-signaled)
    KeInitializeEvent(&AdminConnectionEvent, NotificationEvent, FALSE);

    // Initialize security approval event
    KeInitializeEvent(&SecurityApprovalEvent, NotificationEvent, FALSE);

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

    // Mark that the filter service is now started.
    g_FilterServiceStarted = TRUE;

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


/// IO MANAGEMENT FUNCTIONS -------------------------------------------


//NTSTATUS DriverToClientControl(PDEVICE_OBJECT DeviceObject, PIRP Irp)
//{
//    PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(Irp);
//    NTSTATUS status = STATUS_INVALID_DEVICE_REQUEST;
//    ULONG ioControlCode = stack->Parameters.DeviceIoControl.IoControlCode;
//
//    switch (ioControlCode) {
//    case IOCTL_GET_CLIENT_COMMAND_HANDLE:
//        status = HandleRegisterCommandListener(DeviceObject, Irp);
//        break;
//        // Add cases for other IOCTLs (e.g., IOCTL_GET_ERROR_MESSAGE, etc.)
//    default:
//        status = STATUS_INVALID_DEVICE_REQUEST;
//        Irp->IoStatus.Status = status;
//        Irp->IoStatus.Information = 0;
//        IoCompleteRequest(Irp, IO_NO_INCREMENT);
//        break;
//    }
//    return status;
//}

// TODO: Is this the right place to put this function?
// The file here is about service initialization
NTSTATUS DeviceIoControlHandler(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    PIO_STACK_LOCATION irpSp = IoGetCurrentIrpStackLocation(Irp);
    ULONG controlCode = irpSp->Parameters.DeviceIoControl.IoControlCode;
    NTSTATUS status = STATUS_INVALID_DEVICE_REQUEST;
    ULONG_PTR information = 0;
    PVOID outBuffer = Irp->AssociatedIrp.SystemBuffer;
    ULONG inBufferLength = irpSp->Parameters.DeviceIoControl.InputBufferLength;
    ULONG outBufferLength = irpSp->Parameters.DeviceIoControl.OutputBufferLength;

    #if VERBOSE
        DebugMessage("DeviceIoControlHandler: Received IOCTL: %s (0x%08X)\n", IoctlCodeToString(controlCode), controlCode);
    #endif

    switch (controlCode)
    {
    case IOCTL_PING:
    {
        // Let’s assume our ping response is a 32-bit magic number.
        if (outBufferLength < sizeof(ULONG)) {
            status = STATUS_BUFFER_TOO_SMALL;
        }
        else {
            *((PULONG)outBuffer) = 0xCAFEBABE;  // arbitrary magic number for “pong”
            status = STATUS_SUCCESS;
            information = sizeof(ULONG);
        }
        break;
    }


    // TODO: Make this a Push change for the client to handle
    /*case IOCTL_SET_STREAMING_SERVER_IP:
    {
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
    }*/

    // TODO: Replace this with returning a handle of our last entry in the linked list
    case IOCTL_GET_CLIENT_COMMAND_HANDLE:
    {
        // Get the output buffer length from the IRP.
        PIO_STACK_LOCATION irpSp = IoGetCurrentIrpStackLocation(Irp);
        ULONG outBufferLength = irpSp->Parameters.DeviceIoControl.OutputBufferLength;

        // If the buffer is too small, return an error without removing an entry.
        if (outBufferLength < sizeof(ClientCommandLinkedListEntry)) {
            status = STATUS_BUFFER_TOO_SMALL;
            break;
        }

        // Now dequeue the head (FIFO) of the command queue.
        ClientCommandLinkedListEntry* head = DequeueClientCommand();
        if (head == NULL) {
            status = STATUS_NOT_FOUND;
            break;
        }

        // Copy the command structure into the user-provided output buffer.
        RtlCopyMemory(Irp->AssociatedIrp.SystemBuffer, head, sizeof(ClientCommandLinkedListEntry));
        status = STATUS_SUCCESS;
        information = sizeof(ClientCommandLinkedListEntry);

        // Free the memory for the dequeued node.
        ExFreePool(head);
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

        
        break;
    }


    case IOCTL_SET_STREAMING_SERVER_IP:
    {
        PIO_STACK_LOCATION irpSp = IoGetCurrentIrpStackLocation(Irp);
        ULONG inBufferLength = irpSp->Parameters.DeviceIoControl.InputBufferLength;
        CHAR* ipString = (CHAR*)Irp->AssociatedIrp.SystemBuffer;

        status = AddStreamingServerIp(ipString, inBufferLength);
        if (NT_SUCCESS(status)) {
            information = 0;  // No data returned to user
        }
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