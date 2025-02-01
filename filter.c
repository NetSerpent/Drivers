#include "filter.h"

NTSTATUS NotifyCallback(FWPS_CALLOUT_NOTIFY_TYPE type, const GUID* filterkey, const FWPS_FILTER* filter)
{
    return STATUS_SUCCESS;
}

VOID FlowDeleteCallback(UINT16 layerid, UINT32 calloutid, UINT64 flowcontext)
{
    // Implementation (if needed)
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
    DebugMessage("Netserpent: Data is here\r\n");

    packet = (FWPS_STREAM_CALLOUT_IO_PACKET*)layerdata;

    RtlZeroMemory(classifyout, sizeof(FWPS_CLASSIFY_OUT0));

    packet->streamAction = FWPS_STREAM_ACTION_NONE;
    classifyout->actionType = FWP_ACTION_PERMIT;

    if (filter->flags & FWPS_FILTER_FLAG_CLEAR_ACTION_RIGHT)
    {
        classifyout->rights &= ~FWPS_RIGHT_ACTION_WRITE;
    }
}
