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
#include "driver_to_client.h"  // now used for SendClientCommand
#include "packet_extractor.h"

HANDLE g_InjectionHandle = NULL;

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
static __forceinline USHORT ntoh16(USHORT x) { return RtlUshortByteSwap(x); }
static __forceinline UINT32 ntoh32(UINT32 x) { return RtlUlongByteSwap(x); }

static __forceinline BOOLEAN GetV4Meta(
    const FWPS_INCOMING_VALUES0* v,
    UINT8* outProto,
    UINT16* outLportN,
    UINT16* outRportN,
    UINT32* outSaddrN,
    UINT32* outDaddrN)
{
    switch (v->layerId)
    {
    case FWPS_LAYER_DATAGRAM_DATA_V4:
        *outProto = v->incomingValue[FWPS_FIELD_DATAGRAM_DATA_V4_IP_PROTOCOL].value.uint8;
        *outLportN = v->incomingValue[FWPS_FIELD_DATAGRAM_DATA_V4_IP_LOCAL_PORT].value.uint16;
        *outRportN = v->incomingValue[FWPS_FIELD_DATAGRAM_DATA_V4_IP_REMOTE_PORT].value.uint16;
        *outSaddrN = v->incomingValue[FWPS_FIELD_DATAGRAM_DATA_V4_IP_LOCAL_ADDRESS].value.uint32;
        *outDaddrN = v->incomingValue[FWPS_FIELD_DATAGRAM_DATA_V4_IP_REMOTE_ADDRESS].value.uint32;
        return TRUE;

    case FWPS_LAYER_OUTBOUND_TRANSPORT_V4:
        *outProto = v->incomingValue[FWPS_FIELD_OUTBOUND_TRANSPORT_V4_IP_PROTOCOL].value.uint8;
        *outLportN = v->incomingValue[FWPS_FIELD_OUTBOUND_TRANSPORT_V4_IP_LOCAL_PORT].value.uint16;
        *outRportN = v->incomingValue[FWPS_FIELD_OUTBOUND_TRANSPORT_V4_IP_REMOTE_PORT].value.uint16;
        *outSaddrN = v->incomingValue[FWPS_FIELD_OUTBOUND_TRANSPORT_V4_IP_LOCAL_ADDRESS].value.uint32;
        *outDaddrN = v->incomingValue[FWPS_FIELD_OUTBOUND_TRANSPORT_V4_IP_REMOTE_ADDRESS].value.uint32;
        return TRUE;

    case FWPS_LAYER_INBOUND_TRANSPORT_V4:
        *outProto = v->incomingValue[FWPS_FIELD_INBOUND_TRANSPORT_V4_IP_PROTOCOL].value.uint8;
        *outLportN = v->incomingValue[FWPS_FIELD_INBOUND_TRANSPORT_V4_IP_LOCAL_PORT].value.uint16;
        *outRportN = v->incomingValue[FWPS_FIELD_INBOUND_TRANSPORT_V4_IP_REMOTE_PORT].value.uint16;
        *outSaddrN = v->incomingValue[FWPS_FIELD_INBOUND_TRANSPORT_V4_IP_LOCAL_ADDRESS].value.uint32;
        *outDaddrN = v->incomingValue[FWPS_FIELD_INBOUND_TRANSPORT_V4_IP_REMOTE_ADDRESS].value.uint32;
        return TRUE;

    default:
        return FALSE;
    }
}


// Simple IPv4 header checksum (header must have check=0 when called)
static __forceinline USHORT ipv4_hdr_checksum(const ip4_hdr_t* ip)
{
    ULONG sum = 0;
    const USHORT* w = (const USHORT*)ip;
    // 20 bytes header because we set IHL=5 (no options)
    #pragma warning(suppress:6386)
    for (int i = 0; i < 10; ++i) sum += w[i];
    // fold 32→16
    while (sum >> 16) sum = (sum & 0xFFFF) + (sum >> 16);
    return (USHORT)(~sum);
}

ULONG BuildPcapPacket(
    const FWPS_INCOMING_VALUES0* v,
    NET_BUFFER_LIST* nbl,
    UCHAR* out,
    ULONG cap)
{
    if (!nbl || !out || cap < sizeof(pcap_hdr_t) + sizeof(pcaprec_hdr_t))
        return 0;

    // 1) Extract contiguous bytes from the NBL
    PUCHAR payload_base = NULL;             // FIX: keep base pointer we must free
    ULONG  payload_len  = 0;
    if (!NT_SUCCESS(ExtractPacketFromNbl(nbl, &payload_base, &payload_len)) || payload_len == 0)
        return 0;

    // 2) Read 5-tuple from WFP metadata
    UINT8  proto = 17; // default UDP
    UINT16 lportN = 0, rportN = 0;          // network-order ports as returned by GetV4Meta
    UINT32 saddrN = 0, daddrN = 0;          // network-order IPv4 addresses
    if (!GetV4Meta(v, &proto, &lportN, &rportN, &saddrN, &daddrN) || proto != IPPROTO_UDP) {
        ExFreePool(payload_base);
        return 0;
    }

    // 3) View into the payload we will serialize (may skip 8 bytes)
    PUCHAR payload_view = payload_base;     // FIX: use a view pointer
    ULONG  view_len     = payload_len;

    // Some WFP layers hand us UDP+payload; others only payload.
    // If the first 8 bytes look exactly like the expected UDP header, strip them once.
    if (view_len >= sizeof(udp_hdr_t)) {
        const UCHAR* p = payload_view;
        USHORT sport_be = (USHORT)((payload_view[0] << 8) | payload_view[1]);
        USHORT dport_be = (USHORT)((payload_view[2] << 8) | payload_view[3]);
        USHORT ulen_be = (USHORT)((payload_view[4] << 8) | payload_view[5]);

        // expected ports in network order (metadata ports are host order)
        USHORT lport_be = hton16(lportN);
        USHORT rport_be = hton16(rportN);

        // accept either direction (inbound/outbound)
        BOOLEAN ports_match =
            (sport_be == lport_be && dport_be == rport_be) ||
            (sport_be == rport_be && dport_be == lport_be);


        // ulen_be includes UDP header; require plausibility vs. captured bytes
        BOOLEAN len_ok = (ulen_be >= sizeof(udp_hdr_t)) && (ulen_be <= view_len);

        if (ports_match && len_ok) {
            // strip the leading UDP header exactly once
            payload_view += sizeof(udp_hdr_t);
            view_len -= sizeof(udp_hdr_t);
        }
    }

    // 4) Build Ethernet + IPv4 + UDP headers
    eth_hdr_t eth = { 0 };
    eth.ethertype = hton16(0x0800);              // IPv4
    // (Optional) Populate MACs if you want nicer-looking frames:
    // RtlFillMemory(eth.dst, 6, 0x22);
    // RtlFillMemory(eth.src, 6, 0x11);

    ip4_hdr_t ip = { 0 };
    ip.ver_ihl  = 0x45;                          // v4, IHL=5 (20 bytes)
    ip.tos      = 0;
    ip.id       = 0;
    ip.frag_off = 0;
    ip.ttl      = 64;
    ip.proto    = IPPROTO_UDP;
    ip.tot_len  = hton16((USHORT)(sizeof(ip4_hdr_t) + sizeof(udp_hdr_t) + view_len));
    ip.check    = 0;                              // FIX: compute after fields set
    ip.saddr = hton32(saddrN);                         // already network-order
    ip.daddr = hton32(daddrN);                         // already network-order

    udp_hdr_t udp = { 0 };
    udp.sport = hton16(lportN);
    udp.dport = hton16(rportN);
    udp.len   = hton16((USHORT)(sizeof(udp_hdr_t) + view_len));
    udp.check = 0;                                // 0 is allowed for IPv4 UDP

    // Now that IP is finalized, compute checksum.
    ip.check = ipv4_hdr_checksum(&ip);            // FIX: set checksum

    const UINT32 frame_len = (UINT32)(sizeof(eth_hdr_t) + sizeof(ip4_hdr_t) + sizeof(udp_hdr_t) + view_len);
    const UINT32 need      = (UINT32)(sizeof(pcap_hdr_t) + sizeof(pcaprec_hdr_t)) + frame_len;

    if (cap < need) {
        ExFreePool(payload_base);
        return 0;
    }

    // 5) PCAP global header (DLT_EN10MB = 1)
    pcap_hdr_t gh = {
        .magic    = 0xa1b2c3d4,                  // will appear as d4 c3 b2 a1 on little-endian
        .ver_major= 2,
        .ver_minor= 4,
        .thiszone = 0,
        .sigfigs  = 0,
        .snaplen  = 65535,
        .network  = 1
    };

    // 6) PCAP record header (timestamps in seconds/useconds)
    LARGE_INTEGER now; 
    KeQuerySystemTime(&now);
    const UINT64 unix100ns = (UINT64)now.QuadPart - 116444736000000000ULL;
    pcaprec_hdr_t rh = {
        .ts_sec   = (UINT32)(unix100ns / 10000000ULL),
        .ts_usec  = (UINT32)((unix100ns / 10ULL) % 1000000ULL),
        .incl_len = frame_len,                    // FIX: exact number of bytes we will write
        .orig_len = frame_len,
    };

    // 7) Serialize (exactly incl_len bytes of frame after record header)
    UCHAR* p = out;
    RtlCopyMemory(p, &gh, sizeof(gh));                 p += sizeof(gh);
    RtlCopyMemory(p, &rh, sizeof(rh));                 p += sizeof(rh);
    RtlCopyMemory(p, &eth, sizeof(eth));               p += sizeof(eth);
    RtlCopyMemory(p, &ip,  sizeof(ip));                p += sizeof(ip);
    RtlCopyMemory(p, &udp, sizeof(udp));               p += sizeof(udp);
    RtlCopyMemory(p, payload_view, view_len);          p += view_len;

    ExFreePool(payload_base);                          // FIX: free the original allocation exactly once
    return (ULONG)(p - out);                           // total bytes written (global + record + frame)
}
