#include "filter.h"
#include "packet_queue.h"
#include "packet_extractor.h"

NTSTATUS NotifyCallback(FWPS_CALLOUT_NOTIFY_TYPE type, const GUID* filterkey, const FWPS_FILTER* filter)
{
    return STATUS_SUCCESS;
}

VOID FlowDeleteCallback(UINT16 layerid, UINT32 calloutid, UINT64 flowcontext)
{
    // Optional implementation
}

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
    if (nbl) {
        PUCHAR packetBuffer = NULL;
        ULONG packetSize = 0;
        NTSTATUS status = ExtractPacketFromNbl(nbl, &packetBuffer, &packetSize);
        if (NT_SUCCESS(status)) {
            // Queue the packet (which will prepend the PCAP headers)
            NTSTATUS qStatus = QueuePcapPacket(packetBuffer, packetSize);
            if (NT_SUCCESS(qStatus)) {
                // Print out the queued PCAP packet in hex
                PrintPcapPacket();
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

    // Let the packet pass through.
    FWPS_STREAM_CALLOUT_IO_PACKET* dummyPacket = (FWPS_STREAM_CALLOUT_IO_PACKET*)layerdata;
    RtlZeroMemory(classifyout, sizeof(FWPS_CLASSIFY_OUT0));
    // Note: In an IP packet layer callout, you typically use NET_BUFFER_LIST handling.
    // Here we simply permit the packet.
    classifyout->actionType = FWP_ACTION_PERMIT;

    if (filter->flags & FWPS_FILTER_FLAG_CLEAR_ACTION_RIGHT)
    {
        classifyout->rights &= ~FWPS_RIGHT_ACTION_WRITE;
    }
}
