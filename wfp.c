
/*======================================================================
  wfp.c – Windows Filtering Platform boiler-plate
  ----------------------------------------------------------------------
  Opens WFP engine, registers our call-out on
  FWPM_LAYER_INBOUND_IPPACKET_V4, and wires it to FilterCallback().

  Public helpers
    • NTSTATUS InitializeWfp(void)      – one-stop bring-up
    • VOID     UnInitWfp(void)          – symmetrical cleanup

  Key globals (in globals.h)
    EngineHandle, RegCalloutId, AddCalloutId, filterid

   Contributing
    - Add IPv6 by cloning GUIDs / layers (IPPACKET_V6).
    - Insert condition objects inside WfpAddFilter() when you need to
      limit interception to specific interfaces or protocols.
======================================================================*/

#include "wfp.h"
#include "filter.h"
#include "globals.h"

// Use the inbound IPv4 packet layer instead of the stream layer.
DEFINE_GUID(WFP_SAMPLE_ESTABLISHED_CALLOUT_V4_GUID,
    0xc80739ac, 0x0d54, 0x4343, 0x81, 0xc3, 0xc8, 0x13, 0xe3, 0x98, 0xc4, 0xe4);
DEFINE_GUID(WFP_SAMPLE_SUB_LAYER_GUID,
    0x09535fdf, 0x6b10, 0x4765, 0xb6, 0xf6, 0xa8, 0x47, 0x97, 0xe9, 0xfd, 0xec);

NTSTATUS WfpOpenEngine(void)
{
    return FwpmEngineOpen(NULL, RPC_C_AUTHN_WINNT, NULL, NULL, &EngineHandle);
}

NTSTATUS WfpRegisterCallout(void)
{
    FWPS_CALLOUT Callout = { 0 };

    Callout.calloutKey = WFP_SAMPLE_ESTABLISHED_CALLOUT_V4_GUID;
    Callout.flags = 0;
    Callout.classifyFn = FilterCallback;  // See updated filter callback below
    Callout.notifyFn = NotifyCallback;
    Callout.flowDeleteFn = FlowDeleteCallback;
    // Change the applicable layer to capture entire IPv4 packets.
    return FwpsCalloutRegister(DeviceObject, &Callout, &RegCalloutId);
}

NTSTATUS WfpAddCallout(void)
{
    FWPM_CALLOUT callout = { 0 };
    callout.flags = 0;
    callout.displayData.name = L"EstablishedCalloutName";
    callout.displayData.description = L"EstablishedCalloutName";
    callout.calloutKey = WFP_SAMPLE_ESTABLISHED_CALLOUT_V4_GUID;
    // Use the inbound IPv4 packet layer
    callout.applicableLayer = FWPM_LAYER_INBOUND_IPPACKET_V4;
    return FwpmCalloutAdd(EngineHandle, &callout, NULL, &AddCalloutId);
}

NTSTATUS WfpAddSublayer()
{
    FWPM_SUBLAYER sublayer = { 0 };

    sublayer.displayData.name = L"EstablishedSublayerName";
    sublayer.displayData.description = L"EstablishedSublayerName";
    sublayer.subLayerKey = WFP_SAMPLE_SUB_LAYER_GUID;
    sublayer.weight = 65500; // Higher weight = higher priority

    NTSTATUS status = FwpmSubLayerAdd(EngineHandle, &sublayer, NULL);
    if (status == STATUS_FWP_ALREADY_EXISTS)
    {
        DebugMessage("NetSerpent: Sublayer already exists, using existing one.\n");
        status = STATUS_SUCCESS;
    }
    return status;
}


NTSTATUS WfpAddFilter()
{
    FWPM_FILTER filter = { 0 };

    filter.displayData.name = L"EstablishedFilterName";
    filter.displayData.description = L"EstablishedFilterName";
    // Use the inbound IPv4 packet layer to capture full packets.
    filter.layerKey = FWPM_LAYER_INBOUND_IPPACKET_V4;
    filter.subLayerKey = WFP_SAMPLE_SUB_LAYER_GUID; // Associate with your sublayer
    filter.weight.type = FWP_EMPTY;
    filter.numFilterConditions = 0; // No conditions needed for full packet capture.
    filter.action.type = FWP_ACTION_CALLOUT_TERMINATING;
    filter.action.calloutKey = WFP_SAMPLE_ESTABLISHED_CALLOUT_V4_GUID;

    return FwpmFilterAdd(EngineHandle, &filter, NULL, &filterid);
}



NTSTATUS InitializeWfp(void)
{
    NTSTATUS status = WfpOpenEngine();
    if (!NT_SUCCESS(status)) {
        DebugStatus("NetSerpent: Failed to open engine", status);
        goto end;
    }

    status = WfpRegisterCallout();
    if (!NT_SUCCESS(status)) {
        DebugStatus("NetSerpent: Failed to register callout", status);
        goto end;
    }

    status = WfpAddCallout();
    if (!NT_SUCCESS(status)) {
        DebugStatus("NetSerpent: Failed to add callout", status);
        goto end;
    }

    status = WfpAddSublayer();
    if (!NT_SUCCESS(status)) {
        DebugStatus("NetSerpent: Failed to add sublayer", status);
        goto end;
    }

    status = WfpAddFilter();
    if (!NT_SUCCESS(status)) {
        DebugStatus("NetSerpent: Failed to add filter", status);
        goto end;
    }

    return STATUS_SUCCESS;

end:
    UnInitWfp();
    return STATUS_UNSUCCESSFUL;
}

VOID UnInitWfp(void)
{
    if (EngineHandle != NULL) {
        if (filterid != 0) {
            FwpmFilterDeleteById(EngineHandle, filterid);
            FwpmSubLayerDeleteByKey(EngineHandle, &WFP_SAMPLE_SUB_LAYER_GUID);
        }
        if (AddCalloutId != 0) {
            FwpmCalloutDeleteById(EngineHandle, AddCalloutId);
        }
        if (RegCalloutId != 0) {
            FwpsCalloutUnregisterById(RegCalloutId);
        }
        FwpmEngineClose(EngineHandle);
    }
}
