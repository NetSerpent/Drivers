#pragma once
#ifndef FILTER_H
#define FILTER_H

#include "common.h"

// Declarations for filter callbacks and related functions
NTSTATUS NotifyCallback(FWPS_CALLOUT_NOTIFY_TYPE type, const GUID* filterkey, const FWPS_FILTER* filter);
VOID FlowDeleteCallback(UINT16 layerid, UINT32 calloutid, UINT64 flowcontext);
VOID FilterCallback(const FWPS_INCOMING_VALUES0* Values,
    const FWPS_INCOMING_METADATA_VALUES0* MetaData,
    void* layerdata,
    const void* context,
    const FWPS_FILTER3* filter,
    UINT64 flowcontext,
    FWPS_CLASSIFY_OUT0* classifyout);

#endif // FILTER_H
