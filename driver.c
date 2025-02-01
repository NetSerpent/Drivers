
#include "common.h"
#include "wfp.h"
#include "filter.h"
#include "globals.h"

// Forward declaration of our new IOCTL dispatch routine.
NTSTATUS DeviceIoControlHandler(PDEVICE_OBJECT DeviceObject, PIRP Irp);


VOID DriverUnload(PDRIVER_OBJECT DriverObject)
{
    UnInitWfp();
    IoDeleteDevice(DeviceObject);
    DebugMessage("NetSerpent: Unloaded Driver ");
}

NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{
    NTSTATUS status;
    DebugMessage("NetSerpent: Driver Entry running");

    DriverObject->DriverUnload = DriverUnload;

    // Add the IOCTL dispatch handler.
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DeviceIoControlHandler;

    status = IoCreateDevice(DriverObject, 0, NULL, FILE_DEVICE_UNKNOWN, 0, FALSE, &DeviceObject);
    if (!NT_SUCCESS(status)) {
        DebugMessage("NetSerpent: Failed to create device");
        return status;
    }

    status = InitializeWfp();
    if (!NT_SUCCESS(status)) {
        DebugMessage("NetSerpent: Failed to initialize WFP");
        return status;
    }

    DebugMessage("NetSerpent: Successful Driver Entry");
    return status;
}


//---------------------------------------------------------------------
// IOCTL Dispatch Routine
//---------------------------------------------------------------------
NTSTATUS DeviceIoControlHandler(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    PIO_STACK_LOCATION irpSp = IoGetCurrentIrpStackLocation(Irp);
    ULONG controlCode = irpSp->Parameters.DeviceIoControl.IoControlCode;
    NTSTATUS status = STATUS_INVALID_DEVICE_REQUEST;
    ULONG_PTR information = 0;

    if (controlCode == IOCTL_GET_PCAP_PACKET) {
        // For METHOD_BUFFERED, input and output share the same SystemBuffer.
        PVOID inBuffer = Irp->AssociatedIrp.SystemBuffer;
        PVOID outBuffer = Irp->AssociatedIrp.SystemBuffer;
        ULONG inBufferLength = irpSp->Parameters.DeviceIoControl.InputBufferLength;
        ULONG outBufferLength = irpSp->Parameters.DeviceIoControl.OutputBufferLength;

        // Define sizes for the PCAP headers:
        const ULONG globalHeaderSize = 24;   // PCAP Global Header size
        const ULONG packetHeaderSize = 16;     // PCAP Per-Packet Header size

        // We'll use the input buffer as the payload.
        ULONG payloadSize = inBufferLength;
        ULONG totalSize = globalHeaderSize + packetHeaderSize + payloadSize;

        if (outBufferLength < totalSize) {
            status = STATUS_BUFFER_TOO_SMALL;
            // Inform the caller how many bytes are required.
            information = totalSize;
        }
        else {
            PUCHAR pOut = (PUCHAR)outBuffer;

            // --- PCAP Global Header (24 bytes) ---
            // Magic number (0xa1b2c3d4), version major (2), version minor (4)
            *((ULONG*)(pOut)) = 0xa1b2c3d4;   // magic number
            *((USHORT*)(pOut + 4)) = 2;             // version major
            *((USHORT*)(pOut + 6)) = 4;             // version minor
            *((ULONG*)(pOut + 8)) = 0;             // thiszone (GMT to local correction)
            *((ULONG*)(pOut + 12)) = 0;             // sigfigs (timestamp accuracy)
            *((ULONG*)(pOut + 16)) = 65535;         // snaplen (max packet length)
            *((ULONG*)(pOut + 20)) = 1;             // network (LINKTYPE_ETHERNET)

            // --- PCAP Packet Header (16 bytes) ---
            PUCHAR pPacket = pOut + globalHeaderSize;
            *((ULONG*)(pPacket)) = 0;            // ts_sec (timestamp seconds; use 0 or a real timestamp)
            *((ULONG*)(pPacket + 4)) = 0;            // ts_usec (timestamp microseconds)
            *((ULONG*)(pPacket + 8)) = payloadSize;  // incl_len (number of bytes saved)
            *((ULONG*)(pPacket + 12)) = payloadSize;  // orig_len (actual packet length)

            // --- Copy payload ---
            // Place the content of the input buffer immediately after the packet header.
            RtlCopyMemory(pPacket + packetHeaderSize, inBuffer, payloadSize);

            status = STATUS_SUCCESS;
            information = totalSize;
        }
    }

    Irp->IoStatus.Status = status;
    Irp->IoStatus.Information = information;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return status;
}

/*
// Author: William Stobaugh
// Starting date: Jan 27th, 2025
// The base of the code was followed with a tutorial found at https://www.youtube.com/watch?v=6LmJHMU7R7Y&ab_channel=ProgrammingLoL

// Continue from https://www.youtube.com/watch?v=BWm_w-otyjw&ab_channel=ProgrammingLoL
// 4:44


// --------------------------------------------------------------------
// Headers
// --------------------------------------------------------------------

#define NDIS630 1                 // or NDIS650, etc., depending on your target

#pragma warning(disable:4201)
#include <ntddk.h>   // or <wdm.h> / <ntifs.h>
#include <ndis.h>    // for NET_BUFFER_LIST, NDIS types
#include <fwpsk.h>
#include <fwpmk.h>
#define INITGUID
#include <guiddef.h>
#include <fwpmu.h>




// --------------------------------------------------------------------
// Debug macro
// --------------------------------------------------------------------
#define DebugMessage(msg, ...) DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, msg, __VA_ARGS__)


// --------------------------------------------------------------------
// Define GUIDs
// --------------------------------------------------------------------

//c80739ac-0d54-4343-81c3-c813e398c4e4
DEFINE_GUID(WFP_SAMPLE_ESTABLISHED_CALLOUT_V4_GUID, 0xc80739ac, 0x0d54, 0x4343, 0x81, 0xc3, 0xc8, 0x13, 0xe3, 0x98, 0xc4, 0xe4);
//09535fdf - 6b10 - 4765 - b6f6 - a84797e9fdec
DEFINE_GUID(WFP_SAMPLE_SUB_LAYER_GUID, 0x09535fdf, 0x6b10, 0x4765, 0xb6, 0xf6, 0xa8, 0x47, 0x97, 0xe9, 0xfd, 0xec);



// --------------------------------------------------------------------
// Device Object & Other globals
// --------------------------------------------------------------------
PDEVICE_OBJECT DeviceObject = NULL;
HANDLE EngineHandle = NULL;
UINT32 RegCalloutId = 0, AddCalloutId;
UINT64 filterid = 0;


// --------------------------------------------------------------------
// Driver Unload
// --------------------------------------------------------------------
VOID UnInitWfp()
{
    if (EngineHandle != NULL)
    {
        if (filterid != 0)
        {
            FwpmFilterDeleteById(EngineHandle, filterid);
            FwpmSubLayerDeleteByKey(EngineHandle, &WFP_SAMPLE_SUB_LAYER_GUID);
        }

        if (AddCalloutId != 0)
        {
            FwpmCalloutDeleteById(EngineHandle, AddCalloutId);
        }

        if (RegCalloutId != 0)
        {
            FwpsCalloutUnregisterById(RegCalloutId);
        }

        FwpmEngineClose(EngineHandle);
    }
}

VOID DriverUnload(PDRIVER_OBJECT DriverObject)
{
    UnInitWfp();
    IoDeleteDevice(DeviceObject);
    DebugMessage("NetSerpent: Unloaded Driver ");
}



// --------------------------------------------------------------------
// Callbacks
// --------------------------------------------------------------------

NTSTATUS NotifyCallback(FWPS_CALLOUT_NOTIFY_TYPE type, const GUID* filterkey, const FWPS_FILTER* filter)
{
    return STATUS_SUCCESS;
}

VOID FlowDeleteCallback(UINT16 layerid, UINT32 calloutid, UINT64 flowcontext)
{

}

// FILTER CALLBACK - THIS DOES THE FILTERING!! - MOST IMPORTANT CALLBACK
VOID FilterCallback(const FWPS_INCOMING_VALUES0* Values, const FWPS_INCOMING_METADATA_VALUES0* MetaData,  void* layerdata, const void* context, const FWPS_FILTER3* filter, UINT64 flowcontext, FWPS_CLASSIFY_OUT0* classifyout)
{
    FWPS_STREAM_CALLOUT_IO_PACKET* packet; 
    DebugMessage("Netserpent: Data is here\r\n");

    packet = (FWPS_STREAM_CALLOUT_IO_PACKET*)layerdata;

    RtlZeroMemory(classifyout, sizeof(FWPS_CLASSIFY_OUT));

    packet->streamAction = FWPS_STREAM_ACTION_NONE; // None does not drop the packet, but we could drop it with this if we wanted with 'drop_connection'
    classifyout->actionType = FWP_ACTION_PERMIT;
    
    if (filter->flags & FWPS_FILTER_FLAG_CLEAR_ACTION_RIGHT)
    {
        classifyout->rights &= ~FWPS_RIGHT_ACTION_WRITE; // ~ is a bitwise first complement
        //classifyout->actionType &= FWPS_RIGHT_ACTION_WRITE;
        
    }
    
}

// --------------------------------------------------------------------
// Helper functions to get a handle on WFP
// --------------------------------------------------------------------


NTSTATUS WfpOpenEngine()
{
    return FwpmEngineOpen(NULL, RPC_C_AUTHN_WINNT, NULL, NULL, &EngineHandle);
}

NTSTATUS WfpRegisterCallout()
{
    FWPS_CALLOUT Callout = { 0 };

    Callout.calloutKey = WFP_SAMPLE_ESTABLISHED_CALLOUT_V4_GUID;
    Callout.flags = 0;
    Callout.classifyFn = FilterCallback;
    Callout.notifyFn = NotifyCallback;
    Callout.flowDeleteFn = FlowDeleteCallback;
    return FwpsCalloutRegister(DeviceObject, &Callout, &RegCalloutId);
}


NTSTATUS WfpAddCallout()
{
    FWPM_CALLOUT callout = { 0 };
    callout.flags = 0;
    callout.displayData.name = L"EstablishedCalloutName";
    callout.displayData.description = L"EstablishedCalloutName";
    callout.calloutKey = WFP_SAMPLE_ESTABLISHED_CALLOUT_V4_GUID;
    callout.applicableLayer = FWPM_LAYER_STREAM_V4;  // This is the layer that our callout lives on, do we want this to be on the tcp/ip layer?

    return FwpmCalloutAdd(EngineHandle, &callout, NULL, &AddCalloutId);
}

NTSTATUS WfpAddSublayer()
{
    FWPM_SUBLAYER sublayer = { 0 };

    sublayer.displayData.name = L"EstablishedSublayerName";
    sublayer.displayData.description = L"EstablishedSublayerName";
    sublayer.subLayerKey = WFP_SAMPLE_SUB_LAYER_GUID;
    sublayer.weight = 65500; //The higher the weight, the higher the priv of the driver

    return FwpmSubLayerAdd(EngineHandle, &sublayer, NULL);
}

NTSTATUS WfpAddFilter()
{
    FWPM_FILTER filter = { 0 };
    FWPM_FILTER_CONDITION condition[1] = {0}; // We only have one condition so one member is needed

    filter.displayData.name = L"EstablishedFilterName";
    filter.displayData.description = L"EstablishedFilterName";
    filter.layerKey = FWPM_LAYER_STREAM_V4; // This is the layer that our callout lives on, do we want this to be on the tcp/ip layer?
    filter.weight.type = FWP_EMPTY;
    filter.numFilterConditions = 1;
    filter.filterCondition = condition;
    filter.action.type = FWP_ACTION_CALLOUT_TERMINATING;
    filter.action.calloutKey = WFP_SAMPLE_ESTABLISHED_CALLOUT_V4_GUID;

    condition[0].fieldKey = FWPM_CONDITION_IP_LOCAL_PORT;
    condition[0].matchType = FWP_MATCH_LESS_OR_EQUAL;
    condition[0].conditionValue.type = FWP_UINT16;
    condition[0].conditionValue.uint16 = 65000; // In most cases the random port number will be less than or equal to this number so we will intercept most packets

    return FwpmFilterAdd(EngineHandle, &filter, NULL, &filterid);
}


// --------------------------------------------------------------------
// Here we use all of the helper functions to get access to the wfp
// --------------------------------------------------------------------
NTSTATUS InitializeWfp()
{
    // Open the engine
    if (!NT_SUCCESS(WfpOpenEngine()))
    {
        DebugMessage("NetSerpent: Failed to open engine");
        goto end;
    }

    // Register our callout
    if (!NT_SUCCESS(WfpRegisterCallout()))
    {
        DebugMessage("NetSerpent: Failed to register callout");
        goto end;
    }

    // Add our callout
    if (!NT_SUCCESS(WfpAddCallout()))
    {
        DebugMessage("NetSerpent: Failed to add callout");
        goto end;
    }

    // Add the sublayer
    if (!NT_SUCCESS(WfpAddSublayer()))
    {
        DebugMessage("NetSerpent: Failed to add sublayer");
        goto end;
    }

    // Add the filter
    if (!NT_SUCCESS(WfpAddFilter()))
    {
        DebugMessage("NetSerpent: Failed to add filter");
        goto end;
    }

    return STATUS_SUCCESS;
   
// If the status has failed then we should unload the driver
end: 
    UnInitWfp();
    return STATUS_UNSUCCESSFUL;
}


// --------------------------------------------------------------------
// Driver Entry
// --------------------------------------------------------------------
NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{
    DebugMessage("NetSerpent: Driver Entry running");
    
    NTSTATUS status;

    DriverObject->DriverUnload = DriverUnload;

    status = IoCreateDevice(DriverObject, 0, NULL, FILE_DEVICE_UNKNOWN, 0, FALSE, &DeviceObject);

    if (!NT_SUCCESS(status)) {
        DebugMessage("NetSerpent: Failed to create IoCreateDevice");
        return status;
    }

    status = InitializeWfp();

    if (!NT_SUCCESS(status)) {
        DebugMessage("NetSerpent: Failed to Initialize Wfp");
        return status;
    }

    DebugMessage("NetSerpent: Successful Driver Entry");
    return status;
}
*/