#include "filter.h"
#include "packet_queue.h"
#include "packet_extractor.h"
#include "dns_helper.h"  // Added for DNS whitelisting
#include "netserpent_packet.h"
#include "packet_approval.h"

NTSTATUS NotifyCallback(FWPS_CALLOUT_NOTIFY_TYPE type, const GUID* filterkey, const FWPS_FILTER* filter)
{
    return STATUS_SUCCESS;
}

VOID FlowDeleteCallback(UINT16 layerid, UINT32 calloutid, UINT64 flowcontext)
{
    // Optional implementation
}


// This is what is ran every time a new packet enters the computer
VOID FilterCallback(const FWPS_INCOMING_VALUES0* Values,
    const FWPS_INCOMING_METADATA_VALUES0* MetaData,
    void* layerdata,
    const void* context,
    const FWPS_FILTER3* filter,
    UINT64 flowcontext,
    FWPS_CLASSIFY_OUT0* classifyout)
{
    // For FWPM_LAYER_INBOUND_IPPACKET_V4, layerdata is a pointer to a NET_BUFFER_LIST.
    NET_BUFFER_LIST* nbl = (NET_BUFFER_LIST*)layerdata;

    // Whitelist DNS packets: if this is a DNS packet, immediately permit it.
    if (IsDnsPacket(nbl)) {
        RtlZeroMemory(classifyout, sizeof(FWPS_CLASSIFY_OUT0));
        classifyout->actionType = FWP_ACTION_PERMIT;
        return;
    }

    // Check if the packet is from our NetSerpent service.
    if (IsNetSerpentPacket(nbl)) {
        ProcessNetSerpentPacket(nbl);
        RtlZeroMemory(classifyout, sizeof(FWPS_CLASSIFY_OUT0));
        classifyout->actionType = FWP_ACTION_PERMIT;
        return;
    }

    // For non-DNS and non-NetSerpent packets, perform our usual processing.
    if (nbl) {
        PUCHAR packetBuffer = NULL;
        ULONG packetSize = 0;
        NTSTATUS status = ExtractPacketFromNbl(nbl, &packetBuffer, &packetSize);
        if (NT_SUCCESS(status)) {
            // Queue the packet (which will prepend the PCAP headers)
            NTSTATUS qStatus = QueuePcapPacket(packetBuffer, packetSize);
            if (NT_SUCCESS(qStatus)) {
                // NEW: Wait for the NetSerpent server to approve this third-party packet.
                NTSTATUS approvalStatus = WaitForPacketApproval();
                if (!NT_SUCCESS(approvalStatus)) {
                    DebugMessage("Packet not approved: 0x%X\n", approvalStatus);
                    // Optionally, change the action to block the packet.
                    RtlZeroMemory(classifyout, sizeof(FWPS_CLASSIFY_OUT0));
                    classifyout->actionType = FWP_ACTION_BLOCK;
                    ExFreePool(packetBuffer);
                    return;
                }
            }
            else {
                DebugMessage("Failed to queue PCAP packet: 0x%X", qStatus);
            }
            ExFreePool(packetBuffer);
        }
        else {
            DebugMessage("Failed to extract packet: 0x%X", status);
        }
    }

    // Permit the packet to pass.
    RtlZeroMemory(classifyout, sizeof(FWPS_CLASSIFY_OUT0));
    classifyout->actionType = FWP_ACTION_PERMIT;
    if (filter->flags & FWPS_FILTER_FLAG_CLEAR_ACTION_RIGHT) {
        classifyout->rights &= ~FWPS_RIGHT_ACTION_WRITE;
    }
}
