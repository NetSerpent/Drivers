// async_classify.c
#include "globals.h"
#include "packet_approval.h"
#include "driver_to_client.h"  // for PushCommandPacket
#include "packet_extractor.h"

HANDLE g_InjectionHandle = NULL;

typedef struct _ASYNC_INSPECT_CONTEXT {
    NET_BUFFER_LIST* ClonedNbl;
    UINT32            InterfaceIndex;
    UINT32            SubInterfaceIndex;
    UINT16            LayerId;
} ASYNC_INSPECT_CONTEXT, * PASYNC_INSPECT_CONTEXT;


typedef struct _ASYNC_WORK_ITEM_CONTEXT {
    PIO_WORKITEM WorkItem;
    ASYNC_INSPECT_CONTEXT InspectCtx;
} ASYNC_WORK_ITEM_CONTEXT, * PASYNC_WORK_ITEM_CONTEXT;


NTSTATUS InitializeInjectionHandle()
{
    return FwpsInjectionHandleCreate(
        AF_INET,
        FWPS_INJECTION_TYPE_NETWORK,
        &g_InjectionHandle
    );
}


VOID CleanupInjectionHandle()
{
    if (g_InjectionHandle)
    {
        FwpsInjectionHandleDestroy(g_InjectionHandle);
        g_InjectionHandle = NULL;
    }
}


// Forward declarations for our new helper functions.
ULONG BuildPcapPacket(NET_BUFFER_LIST* nbl, UCHAR* buffer, ULONG bufferSize);

static VOID NTAPI AsyncInspectionWorker(_In_ PVOID StartContext);
static VOID NTAPI InjectionCompletionFn(
    _In_ VOID* context,
    _Inout_ NET_BUFFER_LIST* netBufferList,
    _In_ BOOLEAN dispatchLevel
);


static VOID NTAPI AsyncInspectionWorker(_In_ PVOID StartContext);
static VOID NTAPI InjectionCompletionFn(
    _In_ VOID* context,
    _Inout_ NET_BUFFER_LIST* netBufferList,
    _In_ BOOLEAN dispatchLevel
);


VOID AsyncBlockAndQueuePacket(
    const FWPS_INCOMING_VALUES0* inFixedValues,
    const FWPS_INCOMING_METADATA_VALUES0* inMetaValues,
    const FWPS_FILTER3* filter,
    NET_BUFFER_LIST* nbl
)
{
    NTSTATUS status;
    NET_BUFFER_LIST* clonedNbl = NULL;

    status = FwpsAllocateCloneNetBufferList0(
        nbl,
        NULL,
        NULL,
        0,
        &clonedNbl
    );
    if (!NT_SUCCESS(status) || (clonedNbl == NULL)) {
        DebugMessage("AsyncBlockAndQueuePacket: FwpsCloneNetBufferList failed: 0x%08X\n", status);
        return;
    }

    UINT32 ifIndex = 0, subIfIndex = 0;
    if (inFixedValues->layerId == FWPS_LAYER_INBOUND_IPPACKET_V4) {
        ifIndex = inFixedValues->incomingValue[FWPS_FIELD_INBOUND_IPPACKET_V4_INTERFACE_INDEX].value.uint32;
        subIfIndex = inFixedValues->incomingValue[FWPS_FIELD_INBOUND_IPPACKET_V4_SUB_INTERFACE_INDEX].value.uint32;
    }

    PASYNC_WORK_ITEM_CONTEXT ctx = ExAllocatePoolZero(NonPagedPoolNx, sizeof(*ctx), 'wCtx');
    if (!ctx) {
        DebugMessage("Failed to allocate combined work item context\n");
        FwpsFreeCloneNetBufferList(clonedNbl, 0);
        return;
    }

    ctx->WorkItem = IoAllocateWorkItem(DeviceObject);
    if (!ctx->WorkItem) {
        DebugMessage("Failed to allocate work item\n");
        ExFreePool(ctx);
        FwpsFreeCloneNetBufferList(clonedNbl, 0);
        return;
    }

    ctx->InspectCtx.ClonedNbl = clonedNbl;
    ctx->InspectCtx.InterfaceIndex = ifIndex;
    ctx->InspectCtx.SubInterfaceIndex = subIfIndex;
    ctx->InspectCtx.LayerId = inFixedValues->layerId;

    IoQueueWorkItem(ctx->WorkItem, (PIO_WORKITEM_ROUTINE)AsyncInspectionWorker, DelayedWorkQueue, ctx);
}


static VOID NTAPI AsyncInspectionWorker(_In_ PVOID StartContext)
{
    PASYNC_WORK_ITEM_CONTEXT ctx = (PASYNC_WORK_ITEM_CONTEXT)StartContext;
    NTSTATUS approvalStatus = WaitForPacketApproval();

    if (NT_SUCCESS(approvalStatus)) {
        // Format the PCAP packet here (build a PCAP header, etc.)
        UCHAR pcapPacket[1024] = { 0 };
        // TODO : You would implement this to format the NET_BUFFER_LIST into a proper PCAP packet.
        ULONG pcapSize = BuildPcapPacket(ctx->InspectCtx.ClonedNbl, pcapPacket, sizeof(pcapPacket));

        // Write the packet to the ring buffer (implement WriteToRingBuffer to handle wrapping, etc.)
        // TODO: This function writes data into the ring buffer while handling wrap-around. It should return a status code indicating success or failure.
        NTSTATUS writeStatus = WriteToRingBuffer(g_PcapRingBuffer, g_RingBufferSize, pcapPacket, pcapSize);
        if (NT_SUCCESS(writeStatus)) {
            // Signal the event to notify the user-mode client
            KeSetEvent(&g_PcapDataAvailableEvent, IO_NO_INCREMENT, FALSE);
            DebugMessage("AsyncInspectionWorker: PCAP packet written and event signaled.\n");
        }
        else {
            DebugMessage("AsyncInspectionWorker: Failed to write PCAP packet to ring buffer.\n");
        }
    }
    else {
        DebugMessage("AsyncInspectionWorker: Packet blocked (approval status: 0x%08X)\n", approvalStatus);
    }

    // Clean up
    FwpsFreeCloneNetBufferList(ctx->InspectCtx.ClonedNbl, 0);
    IoFreeWorkItem(ctx->WorkItem);
    ExFreePool(ctx);
}


static VOID NTAPI InjectionCompletionFn(
    _In_ VOID* context,
    _Inout_ NET_BUFFER_LIST* netBufferList,
    _In_ BOOLEAN dispatchLevel
)
{
    PASYNC_WORK_ITEM_CONTEXT ctx = (PASYNC_WORK_ITEM_CONTEXT)context;
    FwpsFreeCloneNetBufferList(netBufferList, 0);
    IoFreeWorkItem(ctx->WorkItem);
    ExFreePool(ctx);
}



// BuildPcapPacket
// Converts the NET_BUFFER_LIST to a PCAP record (header + packet data)
//------------------------------------------------------------------------------
ULONG BuildPcapPacket(NET_BUFFER_LIST * nbl, UCHAR * buffer, ULONG bufferSize)
{
    // Define the PCAP record header structure.
    typedef struct _pcaprec_hdr_t {
        ULONG ts_sec;    // Timestamp seconds
        ULONG ts_usec;   // Timestamp microseconds
        ULONG incl_len;  // Number of octets saved in file
        ULONG orig_len;  // Actual length of packet
    } pcaprec_hdr_t;

    PUCHAR packetData = NULL;
    ULONG packetDataLength = 0;
    NTSTATUS status = ExtractPacketFromNbl(nbl, &packetData, &packetDataLength);
    if (!NT_SUCCESS(status) || packetDataLength == 0) {
        return 0;
    }

    ULONG requiredSize = sizeof(pcaprec_hdr_t) + packetDataLength;
    if (requiredSize > bufferSize) {
        ExFreePool(packetData);
        return 0;
    }

    // Get system time for timestamp.
    LARGE_INTEGER systemTime;
    KeQuerySystemTime(&systemTime);
    ULONG ts_sec = (ULONG)(systemTime.QuadPart / 10000000ULL);
    ULONG ts_usec = (ULONG)((systemTime.QuadPart % 10000000ULL) / 10ULL);

    pcaprec_hdr_t* header = (pcaprec_hdr_t*)buffer;
    header->ts_sec = ts_sec;
    header->ts_usec = ts_usec;
    header->incl_len = packetDataLength;
    header->orig_len = packetDataLength;

    // Copy the packet data immediately following the header.
    RtlCopyMemory(buffer + sizeof(pcaprec_hdr_t), packetData, packetDataLength);
    ExFreePool(packetData);
    return requiredSize;
}


