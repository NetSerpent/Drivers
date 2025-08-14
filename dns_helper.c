#include "dns_helper.h"

static __forceinline UINT16 ntoh16(UINT16 x) { return RtlUshortByteSwap(x); }

static __forceinline BOOLEAN is_dns_proto_port(UINT8 proto, UINT16 lportN, UINT16 rportN)
{
    if (proto != IPPROTO_UDP && proto != IPPROTO_TCP) return FALSE;
    const UINT16 lport = ntoh16(lportN);
    const UINT16 rport = ntoh16(rportN);
    return (lport == 53 || rport == 53);
}

static BOOLEAN get_tuple_for_layer(
    UINT16 layerId,
    const FWPS_INCOMING_VALUES0* v,
    UINT8* outProto,
    UINT16* outLportN,
    UINT16* outRportN)
{
    switch (layerId)
    {
        // -------- IPv4 transport --------
    case FWPS_LAYER_OUTBOUND_TRANSPORT_V4:
        *outProto = v->incomingValue[FWPS_FIELD_OUTBOUND_TRANSPORT_V4_IP_PROTOCOL].value.uint8;
        *outLportN = v->incomingValue[FWPS_FIELD_OUTBOUND_TRANSPORT_V4_IP_LOCAL_PORT].value.uint16;
        *outRportN = v->incomingValue[FWPS_FIELD_OUTBOUND_TRANSPORT_V4_IP_REMOTE_PORT].value.uint16;
        return TRUE;

    case FWPS_LAYER_INBOUND_TRANSPORT_V4:
        *outProto = v->incomingValue[FWPS_FIELD_INBOUND_TRANSPORT_V4_IP_PROTOCOL].value.uint8;
        *outLportN = v->incomingValue[FWPS_FIELD_INBOUND_TRANSPORT_V4_IP_LOCAL_PORT].value.uint16;
        *outRportN = v->incomingValue[FWPS_FIELD_INBOUND_TRANSPORT_V4_IP_REMOTE_PORT].value.uint16;
        return TRUE;

        // -------- IPv6 transport --------
    case FWPS_LAYER_OUTBOUND_TRANSPORT_V6:
        *outProto = v->incomingValue[FWPS_FIELD_OUTBOUND_TRANSPORT_V6_IP_PROTOCOL].value.uint8;
        *outLportN = v->incomingValue[FWPS_FIELD_OUTBOUND_TRANSPORT_V6_IP_LOCAL_PORT].value.uint16;
        *outRportN = v->incomingValue[FWPS_FIELD_OUTBOUND_TRANSPORT_V6_IP_REMOTE_PORT].value.uint16;
        return TRUE;

    case FWPS_LAYER_INBOUND_TRANSPORT_V6:
        *outProto = v->incomingValue[FWPS_FIELD_INBOUND_TRANSPORT_V6_IP_PROTOCOL].value.uint8;
        *outLportN = v->incomingValue[FWPS_FIELD_INBOUND_TRANSPORT_V6_IP_LOCAL_PORT].value.uint16;
        *outRportN = v->incomingValue[FWPS_FIELD_INBOUND_TRANSPORT_V6_IP_REMOTE_PORT].value.uint16;
        return TRUE;

        // -------- Datagram Data (great for UDP DNS) --------
    case FWPS_LAYER_DATAGRAM_DATA_V4:
        *outProto = v->incomingValue[FWPS_FIELD_DATAGRAM_DATA_V4_IP_PROTOCOL].value.uint8;
        *outLportN = v->incomingValue[FWPS_FIELD_DATAGRAM_DATA_V4_IP_LOCAL_PORT].value.uint16;
        *outRportN = v->incomingValue[FWPS_FIELD_DATAGRAM_DATA_V4_IP_REMOTE_PORT].value.uint16;
        return TRUE;

    case FWPS_LAYER_DATAGRAM_DATA_V6:
        *outProto = v->incomingValue[FWPS_FIELD_DATAGRAM_DATA_V6_IP_PROTOCOL].value.uint8;
        *outLportN = v->incomingValue[FWPS_FIELD_DATAGRAM_DATA_V6_IP_LOCAL_PORT].value.uint16;
        *outRportN = v->incomingValue[FWPS_FIELD_DATAGRAM_DATA_V6_IP_REMOTE_PORT].value.uint16;
        return TRUE;

        // -------- ALE (connect/recv-accept) --------
    case FWPS_LAYER_ALE_AUTH_CONNECT_V4:
        *outProto = v->incomingValue[FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_PROTOCOL].value.uint8;
        *outLportN = v->incomingValue[FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_LOCAL_PORT].value.uint16;
        *outRportN = v->incomingValue[FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_REMOTE_PORT].value.uint16;
        return TRUE;

    case FWPS_LAYER_ALE_AUTH_RECV_ACCEPT_V4:
        *outProto = v->incomingValue[FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V4_IP_PROTOCOL].value.uint8;
        *outLportN = v->incomingValue[FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V4_IP_LOCAL_PORT].value.uint16;
        *outRportN = v->incomingValue[FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V4_IP_REMOTE_PORT].value.uint16;
        return TRUE;

    case FWPS_LAYER_ALE_AUTH_CONNECT_V6:
        *outProto = v->incomingValue[FWPS_FIELD_ALE_AUTH_CONNECT_V6_IP_PROTOCOL].value.uint8;
        *outLportN = v->incomingValue[FWPS_FIELD_ALE_AUTH_CONNECT_V6_IP_LOCAL_PORT].value.uint16;
        *outRportN = v->incomingValue[FWPS_FIELD_ALE_AUTH_CONNECT_V6_IP_REMOTE_PORT].value.uint16;
        return TRUE;

    case FWPS_LAYER_ALE_AUTH_RECV_ACCEPT_V6:
        *outProto = v->incomingValue[FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V6_IP_PROTOCOL].value.uint8;
        *outLportN = v->incomingValue[FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V6_IP_LOCAL_PORT].value.uint16;
        *outRportN = v->incomingValue[FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V6_IP_REMOTE_PORT].value.uint16;
        return TRUE;

    default:
        return FALSE;
    }
}

BOOLEAN IsDnsByMetadata(const FWPS_INCOMING_VALUES0* v, const FWPS_FILTER3* f)
{
    UNREFERENCED_PARAMETER(f); // FWPS_FILTER3 does not expose layerId

    const UINT16 lid = v ? v->layerId : 0;

    UINT8  proto = 0;
    UINT16 lportN = 0, rportN = 0;

    if (!lid || !get_tuple_for_layer(lid, v, &proto, &lportN, &rportN)) {
        DebugMessage("IsDnsByMetadata: Unsupported/unknown layer (values->layerId=%u, valueCount=%u)\n",
            (unsigned)lid,
            v ? (unsigned)v->valueCount : 0u);
        return FALSE;
    }

    const BOOLEAN isDns = is_dns_proto_port(proto, lportN, rportN);
    DebugMessage("IsDnsByMetadata: layer=%u proto=%u lport=%u rport=%u => %s\n",
        (unsigned)lid,
        (unsigned)proto,
        (unsigned)ntoh16(lportN),
        (unsigned)ntoh16(rportN),
        isDns ? "DNS" : "not DNS");
    return isDns;
}
