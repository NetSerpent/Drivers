#include "packet_queue.h"
#include <stdio.h>  // for sprintf; note that kernel mode has limited stack so be cautious

// Global (static) storage for our single–slot packet.
static UCHAR gPcapPacketBuffer[MAX_PCAP_PACKET_SIZE] = { 0 };
static ULONG gPcapPacketSize = 0;
static FAST_MUTEX gPacketMutex;

VOID PacketQueueInitialize(void)
{
    ExInitializeFastMutex(&gPacketMutex);
}

NTSTATUS QueuePcapPacket(PUCHAR payload, ULONG payloadSize)
{
    const ULONG globalHeaderSize = 24;   // PCAP Global Header size
    const ULONG packetHeaderSize = 16;     // PCAP Packet Header size
    ULONG totalSize = globalHeaderSize + packetHeaderSize + payloadSize;
    if (totalSize > MAX_PCAP_PACKET_SIZE) {
        return STATUS_BUFFER_OVERFLOW;
    }

    ExAcquireFastMutex(&gPacketMutex);

    PUCHAR pBuf = gPcapPacketBuffer;
    // --- PCAP Global Header (24 bytes) ---
    *((ULONG*)(pBuf)) = 0xa1b2c3d4;          // magic number
    *((USHORT*)(pBuf + 4)) = 2;                // version major
    *((USHORT*)(pBuf + 6)) = 4;                // version minor
    *((ULONG*)(pBuf + 8)) = 0;                 // thiszone
    *((ULONG*)(pBuf + 12)) = 0;                // sigfigs
    *((ULONG*)(pBuf + 16)) = 65535;            // snaplen
    *((ULONG*)(pBuf + 20)) = 1;                // network (Ethernet)

    // --- PCAP Packet Header (16 bytes) ---
    PUCHAR pPacket = pBuf + globalHeaderSize;
    // For a simple timestamp, we use KeQuerySystemTime.
    LARGE_INTEGER systemTime;
    KeQuerySystemTime(&systemTime);
    ULONG ts_sec = (ULONG)(systemTime.QuadPart / 10000000);
    ULONG ts_usec = (ULONG)((systemTime.QuadPart % 10000000) / 10);
    *((ULONG*)(pPacket)) = ts_sec;
    *((ULONG*)(pPacket + 4)) = ts_usec;
    *((ULONG*)(pPacket + 8)) = payloadSize;    // incl_len
    *((ULONG*)(pPacket + 12)) = payloadSize;   // orig_len

    // --- Copy payload ---
    RtlCopyMemory(pPacket + packetHeaderSize, payload, payloadSize);

    gPcapPacketSize = totalSize;

    ExReleaseFastMutex(&gPacketMutex);
    return STATUS_SUCCESS;
}

NTSTATUS DequeuePcapPacket(PUCHAR outBuffer, ULONG outBufferLength, PULONG bytesCopied)
{
    NTSTATUS status = STATUS_SUCCESS;
    ExAcquireFastMutex(&gPacketMutex);

    if (gPcapPacketSize == 0) {
        status = STATUS_NO_DATA_DETECTED;
        *bytesCopied = 0;
    }
    else if (outBufferLength < gPcapPacketSize) {
        status = STATUS_BUFFER_TOO_SMALL;
        *bytesCopied = gPcapPacketSize;
    }
    else {
        RtlCopyMemory(outBuffer, gPcapPacketBuffer, gPcapPacketSize);
        *bytesCopied = gPcapPacketSize;
        // Clear the packet to simulate dequeue.
        gPcapPacketSize = 0;
    }

    ExReleaseFastMutex(&gPacketMutex);
    return status;
}

VOID PrintPcapPacket(VOID)
{
    ULONG i;
    ExAcquireFastMutex(&gPacketMutex);
    if (gPcapPacketSize > 0) {
        DebugMessage("PCAP Packet (%u bytes):", gPcapPacketSize);
        for (i = 0; i < gPcapPacketSize; i += 16) {
            char line[80] = { 0 };
            int offset = 0;
            offset += sprintf(line + offset, "   %04X: ", i);
            for (ULONG j = i; j < i + 16 && j < gPcapPacketSize; j++) {
                offset += sprintf(line + offset, "%02X ", gPcapPacketBuffer[j]);
            }
            DebugMessage("%s", line);
        }
    }
    else {
        DebugMessage("No PCAP packet in queue.");
    }
    ExReleaseFastMutex(&gPacketMutex);
}
