#pragma once
#ifndef PACKET_EXTRACTOR_H
#define PACKET_EXTRACTOR_H

#include "common.h"
#include <ndis.h>

// Extracts the entire packet from the given NET_BUFFER_LIST.
// Allocates a contiguous buffer from NonPagedPoolNx and returns it via pPacketBuffer and pPacketSize.
// The caller is responsible for freeing the buffer with ExFreePool.
NTSTATUS ExtractPacketFromNbl(
    NET_BUFFER_LIST* nbl,
    PUCHAR* pPacketBuffer,
    ULONG* pPacketSize
);

#endif // PACKET_EXTRACTOR_H
