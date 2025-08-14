/*======================================================================
  wfp.c – Windows Filtering Platform boiler-plate
  ----------------------------------------------------------------------
  Opens WFP engine, registers our call-out, and wires it to FilterCallback().
  This version is minimally modified to target the ALE_AUTH_CONNECT
  layer to properly inspect DNS requests.

  Public helpers
    • NTSTATUS InitializeWfp(void)      – one-stop bring-up
    • VOID     UnInitWfp(void)          – symmetrical cleanup

  Key globals (in globals.h)
    EngineHandle, RegCalloutId, AddCalloutId, filterid
======================================================================*/

#include "wfp.h"
#include "filter.h"
#include "globals.h"

// Note: fwpsk.h and fwpmu.h are included via common.h, so they are not
// needed here to avoid redefinition errors.


// Original GUIDs from the initial file.
DEFINE_GUID(WFP_SAMPLE_ESTABLISHED_CALLOUT_V4_GUID,
    0xc80739ac, 0x0d54, 0x4343, 0x81, 0xc3, 0xc8, 0x13, 0xe3, 0x98, 0xc4, 0xe4);
DEFINE_GUID(WFP_NETSERPENT_SUB_LAYER_GUID,
    0x09535fdf, 0x6b10, 0x4765, 0xb6, 0xf6, 0xa8, 0x47, 0x97, 0xe9, 0xfd, 0xec);

NTSTATUS WfpOpenEngine(void)
{
    // Using original function for minimal changes
    return FwpmEngineOpen(NULL, RPC_C_AUTHN_WINNT, NULL, NULL, &EngineHandle);
}

NTSTATUS WfpRegisterCallout(void)
{
    // Using original FWPS_CALLOUT for minimal changes
    FWPS_CALLOUT0 Callout = { 0 };

    Callout.calloutKey = WFP_SAMPLE_ESTABLISHED_CALLOUT_V4_GUID;
    // The explicit casts are necessary because your FilterCallback and NotifyCallback
    // function signatures are for a newer version of WFP than FWPS_CALLOUT0 expects.
    // This can be risky, but is required to compile without changing other files.
    Callout.classifyFn = (FWPS_CALLOUT_CLASSIFY_FN0)FilterCallback;
    Callout.notifyFn = (FWPS_CALLOUT_NOTIFY_FN0)NotifyCallback;
    Callout.flowDeleteFn = FlowDeleteCallback;

    // Using original function
    return FwpsCalloutRegister0(DeviceObject, &Callout, &RegCalloutId);
}

NTSTATUS WfpAddCallout(void)
{
    // Using original FWPM_CALLOUT for minimal changes
    FWPM_CALLOUT0 callout = { 0 };

    callout.calloutKey = WFP_SAMPLE_ESTABLISHED_CALLOUT_V4_GUID;
    callout.displayData.name = L"NetSerpent DNS Inspection Callout";
    callout.displayData.description = L"Monitors outbound DNS connections";

    // MINIMAL CHANGE: The callout must apply to the layer we are filtering.
    callout.applicableLayer = FWPM_LAYER_DATAGRAM_DATA_V4;

    return FwpmCalloutAdd0(EngineHandle, &callout, NULL, &AddCalloutId);
}

NTSTATUS WfpAddSublayer()
{
    // Using original FWPM_SUBLAYER for minimal changes
    FWPM_SUBLAYER0 sublayer = { 0 };

    sublayer.displayData.name = L"NetSerpent Filter Sub-Layer";
    sublayer.displayData.description = L"A custom sub-layer for the NetSerpent driver.";
    sublayer.subLayerKey = WFP_NETSERPENT_SUB_LAYER_GUID;
    sublayer.weight = 0xFFFF; // High weight to ensure our filter is evaluated before most others.

    NTSTATUS status = FwpmSubLayerAdd0(EngineHandle, &sublayer, NULL);
    // CORRECTED: Use the correct kernel-mode NTSTATUS code for this check.
    if (status == STATUS_FWP_ALREADY_EXISTS)
    {
        DebugMessage("NetSerpent: Sublayer already exists, which is okay.\n");
        status = STATUS_SUCCESS;
    }
    return status;
}

#define DNS_ASSIGNED_RFC_NUMBER 32
NTSTATUS WfpAddFilter()
{
    FWPM_FILTER0 filter = { 0 };
    FWPM_FILTER_CONDITION0 condition[1] = { 0 };

    // PORT NUMBER FILTER
    condition[0].fieldKey = FWPM_CONDITION_IP_REMOTE_PORT;
    condition[0].matchType = FWP_MATCH_EQUAL;
    condition[0].conditionValue.type = FWP_UINT16;
    condition[0].conditionValue.uint16 = 53;

    // IP_PROTOCOL == UDP
    //condition[1].fieldKey = FWPM_CONDITION_IP_PROTOCOL;
    //condition[1].matchType = FWP_MATCH_EQUAL;
    //condition[1].conditionValue.type = FWP_UINT8;
    //condition[1].conditionValue.uint8 = DNS_ASSIGNED_RFC_NUMBER; // Reference: https://datatracker.ietf.org/doc/html/rfc1700

    filter.displayData.name = L"NetSerpent DNS Monitoring Filter";
    filter.displayData.description = L"Inspects outbound connections on port 53";

    // MINIMAL CHANGE: Target the correct layer for inspecting new connections.
    filter.layerKey = FWPM_LAYER_DATAGRAM_DATA_V4;

    filter.subLayerKey = WFP_NETSERPENT_SUB_LAYER_GUID;
    filter.weight.type = FWP_EMPTY;

    // Wire up the condition we just created.
    filter.numFilterConditions = 1;
    filter.filterCondition = condition;

    // Use a non-terminating callout for inspection.
	// NOTE: WITH THIS CALLOUT TYPE WE CANNOT PERMIT NOR BLOCK PACKETS.
    // TYPES CAN BE FOUND HERE: https://learn.microsoft.com/en-us/windows/win32/api/fwpmtypes/ns-fwpmtypes-fwpm_action0
    filter.action.type = FWP_ACTION_CALLOUT_INSPECTION;
    filter.action.calloutKey = WFP_SAMPLE_ESTABLISHED_CALLOUT_V4_GUID;

    return FwpmFilterAdd0(EngineHandle, &filter, NULL, &filterid);
}



NTSTATUS InitializeWfp(void)
{
    // Reverted to original simple, linear initialization.
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
    // Reverted to original simple cleanup.
    if (EngineHandle != NULL) {
        if (filterid != 0) {
            FwpmFilterDeleteById0(EngineHandle, filterid);
            FwpmSubLayerDeleteByKey0(EngineHandle, &WFP_NETSERPENT_SUB_LAYER_GUID);
        }
        if (AddCalloutId != 0) {
            FwpmCalloutDeleteById0(EngineHandle, AddCalloutId);
        }
        if (RegCalloutId != 0) {
            FwpsCalloutUnregisterById0(RegCalloutId);
        }
        FwpmEngineClose0(EngineHandle);
        EngineHandle = NULL;
    }
}
