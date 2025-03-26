#pragma once
#ifndef ASYNC_CLASSIFY_H
#define ASYNC_CLASSIFY_H

#include <ntddk.h>
#include <fwpsk.h>
#include <ndis/nbl.h>

// Called from FilterCallback to block & queue a packet for user-mode scanning.
VOID AsyncBlockAndQueuePacket(
    const FWPS_INCOMING_VALUES0* inFixedValues,
    const FWPS_INCOMING_METADATA_VALUES0* inMetaValues,
    const FWPS_FILTER3* filter,
    NET_BUFFER_LIST* nbl
);

NTSTATUS InitializeInjectionHandle();
VOID CleanupInjectionHandle();
ULONG BuildPcapPacket(NET_BUFFER_LIST* nbl, UCHAR* buffer, ULONG bufferSize);

#endif // ASYNC_CLASSIFY_H
