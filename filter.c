#include "filter.h"
#include "packet_queue.h"
#include "packet_extractor.h"
#include "dns_helper.h"  // Added for DNS whitelisting

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


    // TODO: Is the packet from our services? This will be checked by comparing the IP of the sender to the saved IPs we have -> if so automatically let the packet pass

    /*
    * TODO Psuedocode
    if (IsNetSerpentPacket(nbl))
    {
        // If the packet is a IP update / DNS update, then edit trusted IPs to be ours

        // If the packet is the security status of an existing oncoming packet, then we need to either let the 3rd party packet through or not depending on the response
        // In other words, this packet basically tells us if a previous packet (one not from our services) is safe or not.
    }
    */


    // Whitelist DNS packets: if this is a DNS packet, immediately permit it
    if (IsDnsPacket(nbl)) {
        RtlZeroMemory(classifyout, sizeof(FWPS_CLASSIFY_OUT0));
        classifyout->actionType = FWP_ACTION_PERMIT;
        return;
    }

    // For non-DNS packets, perform our usual processing.
    if (nbl) {
        PUCHAR packetBuffer = NULL;
        ULONG packetSize = 0;
        NTSTATUS status = ExtractPacketFromNbl(nbl, &packetBuffer, &packetSize);
        if (NT_SUCCESS(status)) {
            // Queue the packet (which will prepend the PCAP headers)
            NTSTATUS qStatus = QueuePcapPacket(packetBuffer, packetSize);
            if (NT_SUCCESS(qStatus)) {
                // TODO: At this point the packet should NOT be ours and NOT DNS, so we need a way to wait for when our NetSerpent server says that this 3rd party packet is "okay" or not "okay"
                // Another thought is that we might be doing some of this in the code already, and a lot of it we are not, overall it seems quite a bit of code change (not just here) will be needed to add this.
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

    if (filter->flags & FWPS_FILTER_FLAG_CLEAR_ACTION_RIGHT)
    {
        classifyout->rights &= ~FWPS_RIGHT_ACTION_WRITE;
    }
}
