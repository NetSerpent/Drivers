/*======================================================================
  netserpent_packet.c – Parsing & executing NetSerpent control packets
  ----------------------------------------------------------------------
  •  IsNetSerpentPacket()               – quick src-IP whitelist check
  •  ProcessNetSerpentPacket()          – main demux; first byte = cmd id

  Command handlers
    0x01  ProcessAddTrustedIPCommand()      (add server IP)
    0x02  ProcessRemoveTrustedIPCommand()   (remove server IP)
    0x03  ProcessSecurityStatusCommand()    (update g_SecurityScore)

  Command table is initialised lazily in InitializeNetserpentCommandHandlers().

   Contributing
    - To add a new on-wire command, reserve an ID, implement handler,
      register in the handler table.
    - If payloads grow, switch from fixed [cmd | raw bytes] to TLV.
======================================================================*/


#include "netserpent_packet.h"
#include "globals.h"          // For g_TrustedServerIPs, g_TrustedServerIPCount, g_SecurityScore, and SecurityApprovalEvent
#include "common.h"
#include "packet_extractor.h"
#include <ntddndis.h>
//#include <ndis/nblaccessors.h>
//#include <ndis/nblapi.h>

/// HELPER FUNCTIONS -----------------------------------------------

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
    // Iterate through the list of trusted server IPs.
    for (ULONG i = 0; i < g_TrustedServerIPCount; i++) {
        if (srcIP == g_TrustedServerIPs[i]) {
            return TRUE;
        }
    }
    return FALSE;
}




/// FUNCTIONS FOR PROCESSING PACKETS THAT COME FROM NETSERPENT SERVERS -----------------------------------------------

// Command 0x01: Add trusted IP.
VOID ProcessAddTrustedIPCommand(PUCHAR payload, ULONG payloadSize)
{
    if (payloadSize < sizeof(ULONG)) {
        DebugMessage("ProcessAddTrustedIPCommand: payload too small\n");
        return;
    }
    ULONG newIP;
    RtlCopyMemory(&newIP, payload, sizeof(ULONG));
    BOOLEAN exists = FALSE;
    for (ULONG i = 0; i < g_TrustedServerIPCount; i++) {
        if (g_TrustedServerIPs[i] == newIP) {
            exists = TRUE;
            break;
        }
    }
    if (!exists) {
        if (g_TrustedServerIPCount < MAX_TRUSTED_IPS) {
            g_TrustedServerIPs[g_TrustedServerIPCount++] = newIP;
            DebugMessage("NetSerpent: Added trusted IP: 0x%08X\n", newIP);
        }
        else {
            DebugMessage("NetSerpent: Trusted IP list full, cannot add 0x%08X\n", newIP);
        }
    }
    else {
        DebugMessage("NetSerpent: Trusted IP 0x%08X already exists\n", newIP);
    }
}


// Command 0x02: Remove trusted IP.
VOID ProcessRemoveTrustedIPCommand(PUCHAR payload, ULONG payloadSize)
{
    if (payloadSize < sizeof(ULONG)) {
        DebugMessage("ProcessRemoveTrustedIPCommand: payload too small\n");
        return;
    }
    ULONG removeIP;
    RtlCopyMemory(&removeIP, payload, sizeof(ULONG));
    BOOLEAN found = FALSE;
    for (ULONG i = 0; i < g_TrustedServerIPCount; i++) {
        if (g_TrustedServerIPs[i] == removeIP) {
            for (ULONG j = i; j < g_TrustedServerIPCount - 1; j++) {
                g_TrustedServerIPs[j] = g_TrustedServerIPs[j + 1];
            }
            g_TrustedServerIPCount--;
            found = TRUE;
            DebugMessage("NetSerpent: Removed trusted IP: 0x%08X\n", removeIP);
            break;
        }
    }
    if (!found) {
        DebugMessage("NetSerpent: Trusted IP 0x%08X not found for removal\n", removeIP);
    }
}


// Command 0x03: Process security status response.
// TODO: Make this process the score, then reinject the traffic if it passes
VOID ProcessSecurityStatusCommand(PUCHAR payload, ULONG payloadSize)
{
    if (payloadSize < sizeof(ULONG)) {
        DebugMessage("ProcessSecurityStatusCommand: payload too small\n");
        return;
        
    }
    ULONG score;
    RtlCopyMemory(&score, payload, sizeof(ULONG));
    g_SecurityScore = score;
    DebugMessage("NetSerpent: Received security score: %u\n", g_SecurityScore);
}



/// CLIENT TO DRIVER INITIALIZATION -----------------------------------------------

typedef VOID(*NETSERPENT_CMD_HANDLER)(PUCHAR payload, ULONG payloadSize);
static NETSERPENT_CMD_HANDLER netserpentCommandHandlers[256] = { 0 };
static BOOLEAN netserpentCommandHandlersInitialized = FALSE;


static VOID InitializeNetserpentCommandHandlers(void)
{
    if (!netserpentCommandHandlersInitialized) {
        netserpentCommandHandlers[0x01] = ProcessAddTrustedIPCommand;
        netserpentCommandHandlers[0x02] = ProcessRemoveTrustedIPCommand;
        netserpentCommandHandlers[0x03] = ProcessSecurityStatusCommand;
        netserpentCommandHandlersInitialized = TRUE;
    }
}


VOID ProcessNetSerpentPacket(NET_BUFFER_LIST* nbl)
{
    DebugMessage("NetSerpent: Received packet from trusted service.\n");

    PUCHAR packetBuffer = NULL;
    ULONG packetSize = 0;
    NTSTATUS status = ExtractPacketFromNbl(nbl, &packetBuffer, &packetSize);
    if (!NT_SUCCESS(status) || packetSize < 1) {
        DebugMessage("NetSerpent: Failed to extract payload or payload empty, status: 0x%08X\n", status);
        return;
    }

    // The first byte is the command ID.
    UCHAR command = packetBuffer[0];
    InitializeNetserpentCommandHandlers();

    if (netserpentCommandHandlers[command] != NULL) {
        netserpentCommandHandlers[command](packetBuffer + 1, packetSize - 1);
    }
    else {
        DebugMessage("NetSerpent: Unknown command 0x%02X in trusted packet\n", command);
    }

    ExFreePool(packetBuffer);
}
