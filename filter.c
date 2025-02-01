#include "filter.h"
#include "packet_queue.h" 

NTSTATUS NotifyCallback(FWPS_CALLOUT_NOTIFY_TYPE type, const GUID* filterkey, const FWPS_FILTER* filter)
{
    return STATUS_SUCCESS;
}

VOID FlowDeleteCallback(UINT16 layerid, UINT32 calloutid, UINT64 flowcontext)
{
    
}

VOID FilterCallback(const FWPS_INCOMING_VALUES0* Values,
    const FWPS_INCOMING_METADATA_VALUES0* MetaData,
    void* layerdata,
    const void* context,
    const FWPS_FILTER3* filter,
    UINT64 flowcontext,
    FWPS_CLASSIFY_OUT0* classifyout)
{
    FWPS_STREAM_CALLOUT_IO_PACKET* packet;
    packet = (FWPS_STREAM_CALLOUT_IO_PACKET*)layerdata;

    // (For demonstration, we simulate extracting a payload.)
    UCHAR simulatedPayload[] = { 0x11, 0x22, 0x33, 0x44 };
    // Queue the packet in PCAP format.
    QueuePcapPacket(simulatedPayload, sizeof(simulatedPayload));

    RtlZeroMemory(classifyout, sizeof(FWPS_CLASSIFY_OUT0));
    packet->streamAction = FWPS_STREAM_ACTION_NONE;
    classifyout->actionType = FWP_ACTION_PERMIT;

    if (filter->flags & FWPS_FILTER_FLAG_CLEAR_ACTION_RIGHT)
    {
        classifyout->rights &= ~FWPS_RIGHT_ACTION_WRITE;
    }
}