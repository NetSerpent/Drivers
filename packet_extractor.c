#include "packet_extractor.h"

// Helper function that copies 'length' bytes from the NET_BUFFER starting at its current offset
// into the caller's 'target' buffer.
NTSTATUS CopyFromNetBufferToBuffer(NET_BUFFER* nb, ULONG length, PUCHAR target)
{
    // Try to get a contiguous pointer for the requested data.
    PUCHAR contiguous = NdisGetDataBuffer(nb, length, NULL, 1, 0);
    if (contiguous != NULL) {
        // The data is already contiguous; just copy.
        RtlCopyMemory(target, contiguous, length);
        return STATUS_SUCCESS;
    }

    // If data is not contiguous, we copy manually by iterating through the MDL chain.
    PMDL mdl = NET_BUFFER_FIRST_MDL(nb);
    ULONG mdlOffset = NET_BUFFER_CURRENT_MDL_OFFSET(nb);
    ULONG bytesCopied = 0;

    while (mdl && bytesCopied < length)
    {
        // Map the MDL into system space (for read access).
        PUCHAR mdlAddr = (PUCHAR)MmGetSystemAddressForMdlSafe(mdl, NormalPagePriority);
        if (mdlAddr == NULL) {
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        // Get the number of bytes available in this MDL starting at mdlOffset.
        ULONG mdlBytes = MmGetMdlByteCount(mdl);
        if (mdlOffset >= mdlBytes) {
            // This MDL has no more data at or after mdlOffset.
            mdl = mdl->Next;
            mdlOffset = 0;
            continue;
        }

        mdlBytes -= mdlOffset; // Adjust for offset into the MDL.
        ULONG bytesToCopy = (mdlBytes < (length - bytesCopied))
            ? mdlBytes
            : (length - bytesCopied);

        // Copy from the MDL into the target buffer.
        RtlCopyMemory(target + bytesCopied, mdlAddr + mdlOffset, bytesToCopy);

        bytesCopied += bytesToCopy;
        mdlOffset += bytesToCopy;
    }

    return (bytesCopied == length) ? STATUS_SUCCESS : STATUS_UNSUCCESSFUL;
}

NTSTATUS ExtractPacketFromNbl(
    NET_BUFFER_LIST* nbl,
    PUCHAR* pPacketBuffer,
    ULONG* pPacketSize
)
{
    if (!nbl || !pPacketBuffer || !pPacketSize) {
        return STATUS_INVALID_PARAMETER;
    }

    // Calculate total size of all NET_BUFFERs in the NET_BUFFER_LIST.
    ULONG totalSize = 0;
    NET_BUFFER* nb = NET_BUFFER_LIST_FIRST_NB(nbl);
    while (nb) {
        totalSize += NET_BUFFER_DATA_LENGTH(nb);
        nb = NET_BUFFER_NEXT_NB(nb);
    }

    *pPacketSize = totalSize;

    // Allocate a contiguous buffer for the entire packet.
    *pPacketBuffer = (PUCHAR)ExAllocatePoolWithTag(NonPagedPoolNx, totalSize, 'pktE');
    if (*pPacketBuffer == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    // Copy each NET_BUFFER into the allocated buffer.
    nb = NET_BUFFER_LIST_FIRST_NB(nbl);
    ULONG offset = 0;

    while (nb) {
        ULONG nbLength = NET_BUFFER_DATA_LENGTH(nb);
        NTSTATUS status = CopyFromNetBufferToBuffer(nb, nbLength, *pPacketBuffer + offset);
        if (!NT_SUCCESS(status)) {
            ExFreePool(*pPacketBuffer);
            *pPacketBuffer = NULL;
            *pPacketSize = 0;
            return status;
        }
        offset += nbLength;
        nb = NET_BUFFER_NEXT_NB(nb);
    }

    return STATUS_SUCCESS;
}
