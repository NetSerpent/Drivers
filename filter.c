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

NTSTATUS NotifyCallback(FWPS_CALLOUT_NOTIFY_TYPE type, const GUID* filterkey, const FWPS_FILTER* filter)
{
    return STATUS_SUCCESS;
}

VOID FlowDeleteCallback(UINT16 layerid, UINT32 calloutid, UINT64 flowcontext)
{
    // Optional
}

/*
THIS IS THE FUNCTION THAT TAKES IN PACKET DATA AND MAKES A DECISION ON SAFETY VALUE
*/
VOID FilterCallback(
    const FWPS_INCOMING_VALUES0* Values,
    const FWPS_INCOMING_METADATA_VALUES0* MetaData,
    void* layerdata,
    const void* context,
    const FWPS_FILTER3* filter,
    UINT64 flowcontext,
    FWPS_CLASSIFY_OUT0* classifyout)
{

    // CONTEXT: THIS FUNCTION IS CALLED FOR EVERY PORT 53 PACKET

    // IMPORTANT: Only rely on NBL if your layer guarantees it’s present.
    // Use metadata for DNS detection:
    //if (!IsDnsByMetadata(Values, filter)) {
    //    classifyout->actionType = FWP_ACTION_PERMIT;
    //    return;
    //}

    NET_BUFFER_LIST* nbl = (NET_BUFFER_LIST*)layerdata;
    if (!nbl) {
        // Some layers don't supply NBLs → we can't build PCAP, just permit (or handle differently).
        return;
    }

    //DebugMessage("FilterCallback: Processing DNS packet \n");

    UCHAR pcapPacket[2048] = { 0 };
    ULONG pcapSize = BuildPcapPacket(Values, nbl, pcapPacket, sizeof(pcapPacket));
    if (pcapSize > 0) {
        SendClientCommand(RUST_PACKET_SECURITY_CHECK_CODE, pcapPacket, pcapSize);
    }
}