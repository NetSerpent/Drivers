#include "wfp.h"
#include "filter.h"
#include "globals.h"


//c80739ac-0d54-4343-81c3-c813e398c4e4
DEFINE_GUID(WFP_SAMPLE_ESTABLISHED_CALLOUT_V4_GUID, 0xc80739ac, 0x0d54, 0x4343, 0x81, 0xc3, 0xc8, 0x13, 0xe3, 0x98, 0xc4, 0xe4);
//09535fdf - 6b10 - 4765 - b6f6 - a84797e9fdec
DEFINE_GUID(WFP_SAMPLE_SUB_LAYER_GUID, 0x09535fdf, 0x6b10, 0x4765, 0xb6, 0xf6, 0xa8, 0x47, 0x97, 0xe9, 0xfd, 0xec);


// Function implementations
NTSTATUS WfpOpenEngine()
{
    return FwpmEngineOpen(NULL, RPC_C_AUTHN_WINNT, NULL, NULL, &EngineHandle);
}

NTSTATUS WfpRegisterCallout()
{
    FWPS_CALLOUT Callout = { 0 };
    Callout.calloutKey = WFP_SAMPLE_ESTABLISHED_CALLOUT_V4_GUID;
    Callout.flags = 0;
    Callout.classifyFn = FilterCallback;  // declared in your filter module
    Callout.notifyFn = NotifyCallback;      // declared in your filter module
    Callout.flowDeleteFn = FlowDeleteCallback; // declared in your filter module
    return FwpsCalloutRegister(DeviceObject, &Callout, &RegCalloutId);
}

NTSTATUS WfpAddCallout()
{
    FWPM_CALLOUT callout = { 0 };
    callout.flags = 0;
    callout.displayData.name = L"EstablishedCalloutName";
    callout.displayData.description = L"EstablishedCalloutName";
    callout.calloutKey = WFP_SAMPLE_ESTABLISHED_CALLOUT_V4_GUID;
    callout.applicableLayer = FWPM_LAYER_STREAM_V4;
    return FwpmCalloutAdd(EngineHandle, &callout, NULL, &AddCalloutId);
}

NTSTATUS WfpAddSublayer()
{
    FWPM_SUBLAYER sublayer = { 0 };
    sublayer.displayData.name = L"EstablishedSublayerName";
    sublayer.displayData.description = L"EstablishedSublayerName";
    sublayer.subLayerKey = WFP_SAMPLE_SUB_LAYER_GUID;
    sublayer.weight = 65500;
    return FwpmSubLayerAdd(EngineHandle, &sublayer, NULL);
}

NTSTATUS WfpAddFilter()
{
    FWPM_FILTER filter = { 0 };
    FWPM_FILTER_CONDITION condition[1] = { 0 };

    filter.displayData.name = L"EstablishedFilterName";
    filter.displayData.description = L"EstablishedFilterName";
    filter.layerKey = FWPM_LAYER_STREAM_V4;
    filter.weight.type = FWP_EMPTY;
    filter.numFilterConditions = 1;
    filter.filterCondition = condition;
    filter.action.type = FWP_ACTION_CALLOUT_TERMINATING;
    filter.action.calloutKey = WFP_SAMPLE_ESTABLISHED_CALLOUT_V4_GUID;

    condition[0].fieldKey = FWPM_CONDITION_IP_LOCAL_PORT;
    condition[0].matchType = FWP_MATCH_LESS_OR_EQUAL;
    condition[0].conditionValue.type = FWP_UINT16;
    condition[0].conditionValue.uint16 = 65000;

    return FwpmFilterAdd(EngineHandle, &filter, NULL, &filterid);
}

NTSTATUS InitializeWfp()
{
    if (!NT_SUCCESS(WfpOpenEngine()))
    {
        DebugMessage("NetSerpent: Failed to open engine");
        goto end;
    }
    if (!NT_SUCCESS(WfpRegisterCallout()))
    {
        DebugMessage("NetSerpent: Failed to register callout");
        goto end;
    }
    if (!NT_SUCCESS(WfpAddCallout()))
    {
        DebugMessage("NetSerpent: Failed to add callout");
        goto end;
    }
    if (!NT_SUCCESS(WfpAddSublayer()))
    {
        DebugMessage("NetSerpent: Failed to add sublayer");
        goto end;
    }
    if (!NT_SUCCESS(WfpAddFilter()))
    {
        DebugMessage("NetSerpent: Failed to add filter");
        goto end;
    }
    return STATUS_SUCCESS;

end:
    UnInitWfp();
    return STATUS_UNSUCCESSFUL;
}

VOID UnInitWfp()
{
    if (EngineHandle != NULL)
    {
        if (filterid != 0)
        {
            FwpmFilterDeleteById(EngineHandle, filterid);
            FwpmSubLayerDeleteByKey(EngineHandle, &WFP_SAMPLE_SUB_LAYER_GUID);
        }
        if (AddCalloutId != 0)
        {
            FwpmCalloutDeleteById(EngineHandle, AddCalloutId);
        }
        if (RegCalloutId != 0)
        {
            FwpsCalloutUnregisterById(RegCalloutId);
        }
        FwpmEngineClose(EngineHandle);
    }
}
