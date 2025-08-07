/*======================================================================
  dns_helper.c – Fast DNS-classifier for NET_BUFFER_LISTs
  ----------------------------------------------------------------------
    BOOLEAN IsDnsPacket(NBL*)
         Returns TRUE for UDP/TCP packets on port 53
         (works directly on NDIS NBL without flattening).

   Contributing
    - Extend the protocol structs (IP_HEADER, UDP_HEADER, …) only if
      you need extra fields – they are *wire* formats, so keep them
      packed (pragma pack push/pop).
    - Add IPv6 support by cloning IsDnsPacket() with the v6 header
      layout and checking FWPS_LAYER_INBOUND_IPPACKET_V6.
======================================================================*/

#include "dns_helper.h"

// Include ntddndis.h to bring in the proper definitions for NDIS routines.
#include <ntddndis.h>

#pragma pack(push, 1)
typedef struct _IP_HEADER {
    UCHAR  VersionAndHeaderLength; // Version (4 bits) and Header Length (4 bits)
    UCHAR  TypeOfService;
    USHORT TotalLength;
    USHORT Identification;
    USHORT FlagsAndFragmentOffset;
    UCHAR  TimeToLive;
    UCHAR  Protocol;
    USHORT HeaderChecksum;
    ULONG  SourceAddress;
    ULONG  DestinationAddress;
} IP_HEADER, * PIP_HEADER;

typedef struct _UDP_HEADER {
    USHORT SourcePort;
    USHORT DestinationPort;
    USHORT Length;
    USHORT Checksum;
} UDP_HEADER, * PUDP_HEADER;

typedef struct _TCP_HEADER {
    USHORT SourcePort;
    USHORT DestinationPort;
    ULONG SequenceNumber;
    ULONG AcknowledgmentNumber;
    UCHAR DataOffsetAndReserved; // Upper 4 bits = data offset
    UCHAR Flags;
    USHORT Window;
    USHORT Checksum;
    USHORT UrgentPointer;
} TCP_HEADER, * PTCP_HEADER;
#pragma pack(pop)

#ifndef IPPROTO_UDP
#define IPPROTO_UDP 17
#endif

#ifndef IPPROTO_TCP
#define IPPROTO_TCP 6
#endif

// IsDnsPacket parses the IP header (and UDP/TCP header) from the NET_BUFFER_LIST.
// If the packet uses UDP or TCP and either the source or destination port is 53, it returns TRUE.
BOOLEAN IsDnsPacket(NET_BUFFER_LIST* nbl)
{
    if (!nbl)
        return FALSE;

    NET_BUFFER* nb = NET_BUFFER_LIST_FIRST_NB(nbl);
    if (!nb)
        return FALSE;

    // Get a contiguous buffer for the IP header (minimum 20 bytes).
    UCHAR* buffer = NdisGetDataBuffer(nb, 20, NULL, 1, 0);
    if (!buffer)
        return FALSE;

    PIP_HEADER ipHeader = (PIP_HEADER)buffer;
    UCHAR ipHeaderLength = (ipHeader->VersionAndHeaderLength & 0x0F) * 4;
    if (ipHeaderLength < 20)
        return FALSE;

    // Check for UDP DNS packets.
    if (ipHeader->Protocol == IPPROTO_UDP)
    {
        if (nb->DataLength < ipHeaderLength + sizeof(UDP_HEADER))
            return FALSE;
        PUDP_HEADER udpHeader = (PUDP_HEADER)(buffer + ipHeaderLength);
        USHORT srcPort = RtlUshortByteSwap(udpHeader->SourcePort);
        USHORT dstPort = RtlUshortByteSwap(udpHeader->DestinationPort);
        if (srcPort == 53 || dstPort == 53)
            return TRUE;
    }
    // Check for TCP DNS packets.
    else if (ipHeader->Protocol == IPPROTO_TCP)
    {
        if (nb->DataLength < ipHeaderLength + sizeof(TCP_HEADER))
            return FALSE;
        PTCP_HEADER tcpHeader = (PTCP_HEADER)(buffer + ipHeaderLength);
        USHORT srcPort = RtlUshortByteSwap(tcpHeader->SourcePort);
        USHORT dstPort = RtlUshortByteSwap(tcpHeader->DestinationPort);
        if (srcPort == 53 || dstPort == 53)
            return TRUE;
    }

    return FALSE;
}
