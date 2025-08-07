/*======================================================================
  filter.c - WFP call-out classify routine
  ----------------------------------------------------------------------
  • NotifyCallback() / FlowDeleteCallback() – boiler-plate, mostly NOP
  • FilterCallback(...) – central packet decision path
        → Permit immediately for DNS or NetSerpent control traffic
        → While client disconnected, default-permit
        → Otherwise build PCAP snapshot + queue security check command

   Contributing
    - Plug the commented “AsyncBlockAndQueuePacket” section back in when
      out-of-band blocking/re-injection is ready.
    - Add layer-specific fast-paths *before* the expensive PCAP build.
    - Keep this file *pure WFP*: heavy analysis moves to async_classify.c
======================================================================*/

#include "filter.h"
#include "globals.h"
#include "packet_queue.h"
#include "packet_extractor.h"
#include "dns_helper.h"
#include "netserpent_packet.h"
#include "async_classify.h"
#include "driver_to_client.h"
// #include "packet_approval.h"  // no direct calls in the classify callback

NTSTATUS NotifyCallback(FWPS_CALLOUT_NOTIFY_TYPE type, const GUID* filterkey, const FWPS_FILTER* filter)
{
    return STATUS_SUCCESS;
}

VOID FlowDeleteCallback(UINT16 layerid, UINT32 calloutid, UINT64 flowcontext)
{
    // Optional
}

VOID FilterCallback(
    const FWPS_INCOMING_VALUES0* Values,
    const FWPS_INCOMING_METADATA_VALUES0* MetaData,
    void* layerdata,
    const void* context,
    const FWPS_FILTER3* filter,
    UINT64 flowcontext,
    FWPS_CLASSIFY_OUT0* classifyout)
{
    RtlZeroMemory(classifyout, sizeof(*classifyout));

    NET_BUFFER_LIST* nbl = (NET_BUFFER_LIST*)layerdata;
    if (!nbl)
    {
        classifyout->actionType = FWP_ACTION_PERMIT;
        return;
    }

    // Immediately permit DNS
    if (IsDnsPacket(nbl))
    {
        classifyout->actionType = FWP_ACTION_PERMIT;
        return;
    }

    // Immediately permit NetSerpent control packets
    if (IsNetSerpentPacket(nbl))
    {
        ProcessNetSerpentPacket(nbl);
        classifyout->actionType = FWP_ACTION_PERMIT;
        return;
    }

    // If not connected, just permit or block. 
    // For example, let's allow the packet if the client isn't ready:
    if (!g_ClientConnected)
    {
        DebugMessage("FilterCallback: g_ClientConnected == FALSE, permitting.\n");
        classifyout->actionType = FWP_ACTION_PERMIT;
        return;
    }

    /*
    // Otherwise, we do out-of-band inspection:
    // 1) Block the packet now
    classifyout->actionType = FWP_ACTION_BLOCK;
    classifyout->flags |= FWPS_CLASSIFY_OUT_FLAG_ABSORB;

    // 2) Clone + queue for user-mode scanning & re-injection
    AsyncBlockAndQueuePacket(Values, MetaData, filter, nbl);
    */


    

    // Build a PCAP packet header.
    UCHAR pcapPacket[1024] = { 0 };
    ULONG pcapSize = BuildPcapPacket(nbl, pcapPacket, sizeof(pcapPacket));
    if (pcapSize > 0)
    {
        NTSTATUS sendStatus = SendClientCommand(RUST_PACKET_SECURITY_CHECK_CODE, pcapPacket, pcapSize);
        if (NT_SUCCESS(sendStatus)) {
            DebugMessage("FilterCallback: Enqueued security check command successfully.\n");
        }
        else {
            DebugMessage("FilterCallback: Failed to enqueue security check command, status: 0x%08X\n", sendStatus);
        }
    }

    // For the time being lets just have the packets pass for testing out the security command
    classifyout->actionType = FWP_ACTION_PERMIT;
}
