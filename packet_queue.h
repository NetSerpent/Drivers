#pragma once
#ifndef PACKET_QUEUE_H
#define PACKET_QUEUE_H

#include "common.h"

// Maximum size for a single PCAP–formatted packet.
#define MAX_PCAP_PACKET_SIZE 2048

// Initialize the packet queue (e.g. initialize the mutex).
VOID PacketQueueInitialize(void);

// Queue a packet (format the captured payload into PCAP format and store it).
NTSTATUS QueuePcapPacket(PUCHAR payload, ULONG payloadSize);

// Dequeue a packet from the queue (copy it to the caller’s buffer).
NTSTATUS DequeuePcapPacket(PUCHAR outBuffer, ULONG outBufferLength, PULONG bytesCopied);

// Print the queued PCAP packet (dump its contents in hex).
VOID PrintPcapPacket(VOID);

#endif // PACKET_QUEUE_H
