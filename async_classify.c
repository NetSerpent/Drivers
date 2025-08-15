/*======================================================================
  async_classify.c – Off-path packet inspection & re-injection worker
  ----------------------------------------------------------------------
  Flow
    FilterCallback -> AsyncBlockAndQueuePacket()
                   -> clones NBL, queues IoWorkItem
                   -> AsyncInspectionWorker()
                        · WaitForPacketApproval()
                        · Builds mini-PCAP
                        · SendClientCommand(SECURITY_CHECK,…)
                        · (future) Inject back via FwpsInjectNetBufferList2

  Major helpers
    - InitializeInjectionHandle() / CleanupInjectionHandle()
    - BuildPcapPacket() – local static; converts NBL -> PCAP record

   Contributing
    - Wire InjectionCompletionFn once re-injection path is enabled.
    - Consider using ExInitializeNPagedLookasideList for ctx objects if
      allocation churn becomes measurable.
======================================================================*/

#include "globals.h"
#include "packet_approval.h"
#include "driver_to_client.h"  // now used for SendClientCommand
#include "packet_extractor.h"

HANDLE g_InjectionHandle = NULL;

//typedef struct _ASYNC_INSPECT_CONTEXT {
//    NET_BUFFER_LIST* ClonedNbl;
//    UINT32            InterfaceIndex;
//    UINT32            SubInterfaceIndex;
//    UINT16            LayerId;
//} ASYNC_INSPECT_CONTEXT, * PASYNC_INSPECT_CONTEXT;
//
//typedef struct _ASYNC_WORK_ITEM_CONTEXT {
//    PIO_WORKITEM WorkItem;
//    ASYNC_INSPECT_CONTEXT InspectCtx;
//} ASYNC_WORK_ITEM_CONTEXT, * PASYNC_WORK_ITEM_CONTEXT;
//
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
//
//// Forward declaration for our helper function.
//ULONG BuildPcapPacket(
//    const FWPS_INCOMING_VALUES0* inValues,
//    NET_BUFFER_LIST* nbl,
//    UCHAR* outBuf,
//    ULONG outCap);
//
//static VOID NTAPI AsyncInspectionWorker(_In_ PVOID StartContext);
//static VOID NTAPI InjectionCompletionFn(
//    _In_ VOID* context,
//    _Inout_ NET_BUFFER_LIST* netBufferList,
//    _In_ BOOLEAN dispatchLevel
//);
//
////
//// New version of AsyncBlockAndQueuePacket that uses the linked-list client command system
////
//VOID AsyncBlockAndQueuePacket(
//    const FWPS_INCOMING_VALUES0* inFixedValues,
//    const FWPS_INCOMING_METADATA_VALUES0* inMetaValues,
//    const FWPS_FILTER3* filter,
//    NET_BUFFER_LIST* nbl
//)
//{
//    NTSTATUS status;
//    NET_BUFFER_LIST* clonedNbl = NULL;
//
//    // Clone the NET_BUFFER_LIST so we can hold onto the packet data
//    status = FwpsAllocateCloneNetBufferList0(
//        nbl,
//        NULL,
//        NULL,
//        0,
//        &clonedNbl
//    );
//    if (!NT_SUCCESS(status) || (clonedNbl == NULL)) {
//        DebugMessage("AsyncBlockAndQueuePacket: FwpsCloneNetBufferList failed: 0x%08X\n", status);
//        return;
//    }
//
//    UINT32 ifIndex = 0, subIfIndex = 0;
//    if (inFixedValues->layerId == FWPS_LAYER_INBOUND_IPPACKET_V4) {
//        ifIndex = inFixedValues->incomingValue[FWPS_FIELD_INBOUND_IPPACKET_V4_INTERFACE_INDEX].value.uint32;
//        subIfIndex = inFixedValues->incomingValue[FWPS_FIELD_INBOUND_IPPACKET_V4_SUB_INTERFACE_INDEX].value.uint32;
//    }
//
//    // Allocate context for the asynchronous work item.
//    PASYNC_WORK_ITEM_CONTEXT ctx = ExAllocatePoolZero(NonPagedPoolNx, sizeof(*ctx), 'wCtx');
//    if (!ctx) {
//        DebugMessage("AsyncBlockAndQueuePacket: Failed to allocate work item context\n");
//        FwpsFreeCloneNetBufferList(clonedNbl, 0);
//        return;
//    }
//
//    ctx->WorkItem = IoAllocateWorkItem(DeviceObject);
//    if (!ctx->WorkItem) {
//        DebugMessage("AsyncBlockAndQueuePacket: Failed to allocate work item\n");
//        ExFreePool(ctx);
//        FwpsFreeCloneNetBufferList(clonedNbl, 0);
//        return;
//    }
//
//    // Save the cloned NET_BUFFER_LIST and interface indexes into the context.
//    ctx->InspectCtx.ClonedNbl = clonedNbl;
//    ctx->InspectCtx.InterfaceIndex = ifIndex;
//    ctx->InspectCtx.SubInterfaceIndex = subIfIndex;
//    ctx->InspectCtx.LayerId = inFixedValues->layerId;
//
//    // Queue the work item.
//    IoQueueWorkItem(ctx->WorkItem, (PIO_WORKITEM_ROUTINE)AsyncInspectionWorker, DelayedWorkQueue, ctx);
//}
//
//static VOID NTAPI AsyncInspectionWorker(_In_ PVOID StartContext)
//{
//    PASYNC_WORK_ITEM_CONTEXT ctx = (PASYNC_WORK_ITEM_CONTEXT)StartContext;
//    NTSTATUS approvalStatus = WaitForPacketApproval();
//
//    if (NT_SUCCESS(approvalStatus)) {
//        // Format the packet into a PCAP record.
//        UCHAR pcapPacket[1024] = { 0 };
//        ULONG pcapSize = BuildPcapPacket(ctx->InspectCtx.ClonedNbl, pcapPacket, sizeof(pcapPacket));
//
//        // Send command to client to send packet to our servers
//        NTSTATUS sendStatus = SendClientCommand(RUST_PACKET_SECURITY_CHECK_CODE, pcapPacket, pcapSize);
//        if (!NT_SUCCESS(sendStatus)) {
//            DebugMessage("AsyncInspectionWorker: Failed to send client command, status: 0x%08X\n", sendStatus);
//        }
//    }
//    else {
//        DebugMessage("AsyncInspectionWorker: Packet blocked (approval status: 0x%08X)\n", approvalStatus);
//    }
//
//    // Clean up
//    FwpsFreeCloneNetBufferList(ctx->InspectCtx.ClonedNbl, 0);
//    IoFreeWorkItem(ctx->WorkItem);
//    ExFreePool(ctx);
//}
//
//static VOID NTAPI InjectionCompletionFn(
//    _In_ VOID* context,
//    _Inout_ NET_BUFFER_LIST* netBufferList,
//    _In_ BOOLEAN dispatchLevel
//)
//{
//    PASYNC_WORK_ITEM_CONTEXT ctx = (PASYNC_WORK_ITEM_CONTEXT)context;
//    FwpsFreeCloneNetBufferList(netBufferList, 0);
//    IoFreeWorkItem(ctx->WorkItem);
//    ExFreePool(ctx);
//}



// BuildPcapPacket
// Converts the NET_BUFFER_LIST to a PCAP record (header + packet data)
//------------------------------------------------------------------------------
#pragma pack(push, 1)
typedef struct {
    UINT32 magic;        // 0xa1b2c3d4 (LE)
    UINT16 ver_major;    // 2
    UINT16 ver_minor;    // 4
    INT32  thiszone;     // 0
    UINT32 sigfigs;      // 0
    UINT32 snaplen;      // 65535
    UINT32 network;      // 1 (LINKTYPE_ETHERNET)
} pcap_hdr_t;

typedef struct {
    UINT32 ts_sec, ts_usec;
    UINT32 incl_len, orig_len;
} pcaprec_hdr_t;

typedef struct {
    UCHAR  dst[6];
    UCHAR  src[6];
    USHORT ethertype;     // htons(0x0800) for IPv4
} eth_hdr_t;

typedef struct {
    UCHAR  ver_ihl; UCHAR tos;
    USHORT tot_len; USHORT id;
    USHORT frag_off; UCHAR ttl;
    UCHAR  proto;   USHORT check;
    UINT32 saddr;   UINT32 daddr;
} ip4_hdr_t;

typedef struct {
    USHORT sport, dport, len, check;
} udp_hdr_t;
#pragma pack(pop)

static __forceinline USHORT hton16(USHORT x) { return RtlUshortByteSwap(x); }
static __forceinline UINT32 hton32(UINT32 x) { return RtlUlongByteSwap(x); }

ULONG BuildPcapPacket(
    const FWPS_INCOMING_VALUES0* v,
    NET_BUFFER_LIST* nbl,
    UCHAR* out,
    ULONG cap)
{
    if (!nbl || !out || cap < sizeof(pcap_hdr_t) + sizeof(pcaprec_hdr_t))
        return 0;

    // 1) Get the UDP payload bytes from the NBL (what you already did before)
    PUCHAR payload = NULL;
    ULONG  paylen = 0;
    if (!NT_SUCCESS(ExtractPacketFromNbl(nbl, &payload, &paylen)) || paylen == 0)
        return 0;

    // 2) Pull ports + IPs from metadata
    UINT8  proto = 17; // UDP
    UINT16 lportN = 0, rportN = 0;
    UINT32 saddrN = 0, daddrN = 0;

    // Try both V4 and V6 (only V4 shown here; extend for V6 if needed)
    if (v->layerId == FWPS_LAYER_DATAGRAM_DATA_V4 ||
        v->layerId == FWPS_LAYER_OUTBOUND_TRANSPORT_V4 ||
        v->layerId == FWPS_LAYER_INBOUND_TRANSPORT_V4) {

        proto = v->incomingValue[FWPS_FIELD_DATAGRAM_DATA_V4_IP_PROTOCOL].value.uint8;
        lportN = v->incomingValue[FWPS_FIELD_DATAGRAM_DATA_V4_IP_LOCAL_PORT].value.uint16;
        rportN = v->incomingValue[FWPS_FIELD_DATAGRAM_DATA_V4_IP_REMOTE_PORT].value.uint16;
        saddrN = v->incomingValue[FWPS_FIELD_DATAGRAM_DATA_V4_IP_LOCAL_ADDRESS].value.uint32;
        daddrN = v->incomingValue[FWPS_FIELD_DATAGRAM_DATA_V4_IP_REMOTE_ADDRESS].value.uint32;
    }

    // 3) Synthesize Ethernet + IPv4 + UDP headers
    eth_hdr_t eth = { 0 };
    eth.ethertype = hton16(0x0800);

    ip4_hdr_t ip = { 0 };
    ip.ver_ihl = 0x45;
    ip.ttl = 64;
    ip.proto = 17; // UDP
    ip.tot_len = hton16((USHORT)(20 + 8 + paylen));
    ip.saddr = saddrN;
    ip.daddr = daddrN;
    // ip.check  = 0; // fine for our parser

    udp_hdr_t udp = { 0 };
    udp.sport = lportN;
    udp.dport = rportN;
    udp.len = hton16((USHORT)(8 + paylen));
    // udp.check = 0; // optional

    UINT32 frame_len = sizeof(eth) + sizeof(ip) + sizeof(udp) + paylen;
    UINT32 need = sizeof(pcap_hdr_t) + sizeof(pcaprec_hdr_t) + frame_len;
    if (cap < need) return 0;

    // 4) Global header
    pcap_hdr_t gh = {
        .magic = 0xa1b2c3d4,  // LE (writer is little-endian)
        .ver_major = 2,
        .ver_minor = 4,
        .thiszone = 0,
        .sigfigs = 0,
        .snaplen = 65535,
        .network = 1           // Ethernet
    };

    // 5) Record header
    LARGE_INTEGER now; KeQuerySystemTime(&now);
    pcaprec_hdr_t rh = {
        .ts_sec = (UINT32)(now.QuadPart / 10000000ULL - 11644473600ULL), // FILETIME->UNIX
        .ts_usec = (UINT32)((now.QuadPart / 10ULL) % 1000000ULL),
        .incl_len = frame_len,
        .orig_len = frame_len,
    };

    // 6) Serialize
    UCHAR* p = out;
    RtlCopyMemory(p, &gh, sizeof(gh)); p += sizeof(gh);
    RtlCopyMemory(p, &rh, sizeof(rh)); p += sizeof(rh);
    RtlCopyMemory(p, &eth, sizeof(eth)); p += sizeof(eth);
    RtlCopyMemory(p, &ip, sizeof(ip));  p += sizeof(ip);
    RtlCopyMemory(p, &udp, sizeof(udp)); p += sizeof(udp);
    RtlCopyMemory(p, payload, paylen);   p += paylen;

    // free temp from ExtractPacketFromNbl if it allocated
    ExFreePool(payload); // if ExtractPacketFromNbl allocated; otherwise remove this

    return (ULONG)(p - out);
}