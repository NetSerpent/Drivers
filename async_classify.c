// async_classify.c
#include "globals.h"
#include "packet_approval.h"

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

    if (approvalStatus == STATUS_SUCCESS) {
        NTSTATUS injectStatus = FwpsInjectNetworkReceiveAsync0(
            g_InjectionHandle,
            NULL,
            0,
            ctx->InspectCtx.LayerId,
            ctx->InspectCtx.InterfaceIndex,
            ctx->InspectCtx.SubInterfaceIndex,
            ctx->InspectCtx.ClonedNbl,
            InjectionCompletionFn,
            ctx   // Pass the entire context to the callback.
        );
        if (NT_SUCCESS(injectStatus)) {
            // On success the injection callback will clean up.
            return;
        }
        else {
            DebugMessage("AsyncInspectionWorker: Injection failed: 0x%08X\n", injectStatus);
            FwpsFreeCloneNetBufferList(ctx->InspectCtx.ClonedNbl, 0);
        }
    }
    else {
        DebugMessage("AsyncInspectionWorker: Packet blocked.\n");
        FwpsFreeCloneNetBufferList(ctx->InspectCtx.ClonedNbl, 0);
    }

    // Cleanup for injection failure or blocked packet:
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
