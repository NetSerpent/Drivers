#include "netserpent_packet.h"
#include "globals.h"      // For access to g_NetSerpentServerIP and DebugMessage
#include "common.h"
#include <ntddndis.h>
#include <ndis/nblaccessors.h>
#include <ndis/nblapi.h>

// Helper: Extracts the source IP address from the first NET_BUFFER in the NET_BUFFER_LIST.
static ULONG GetSourceIPAddress(NET_BUFFER_LIST* nbl)
{
    if (!nbl)
        return 0;

    NET_BUFFER* nb = NET_BUFFER_LIST_FIRST_NB(nbl);
    if (!nb)
        return 0;

    // Try to get a contiguous pointer for the IP header (assume minimum 20 bytes).
    UCHAR* buffer = NdisGetDataBuffer(nb, 20, NULL, 1, 0);
    if (!buffer)
        return 0;

    // Minimal IP header structure
    typedef struct _IP_HEADER {
        UCHAR  VersionAndHeaderLength;
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

    PIP_HEADER ipHeader = (PIP_HEADER)buffer;
    return ipHeader->SourceAddress;
}

BOOLEAN IsNetSerpentPacket(NET_BUFFER_LIST* nbl)
{
    ULONG srcIP = GetSourceIPAddress(nbl);
    // Compare the source IP against our trusted server IP.
    // TODO: Instead of looking at a single IP, we likely will have a list of trusted IPs, more places than here will need to reflect this change
    if (srcIP == g_NetSerpentServerIP)
        return TRUE;
    return FALSE;
}

VOID ProcessNetSerpentPacket(NET_BUFFER_LIST* nbl)
{
    // For now, simply log that a NetSerpent packet was received.
    DebugMessage("NetSerpent: Received packet from trusted service.\n");

    // TODO: Implement further processing:
    // - For an IP/DNS update packet, update trusted IPs.
    // - For a security status response, decide whether to permit or block related packets.
}
