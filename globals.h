#pragma once
#ifndef GLOBALS_H
#define GLOBALS_H

#include "common.h" // or any header that defines PDEVICE_OBJECT, etc.

extern PDRIVER_OBJECT g_DriverObject;
extern PDEVICE_OBJECT DeviceObject;
extern HANDLE EngineHandle;
extern UINT32 RegCalloutId;
extern UINT32 AddCalloutId;
extern UINT64 filterid;

extern CHAR g_ErrorMessage[256];

extern KEVENT AdminConnectionEvent;


// Maximum number of trusted IPs
#define MAX_TRUSTED_IPS 10
extern ULONG g_TrustedServerIPs[MAX_TRUSTED_IPS];
extern ULONG g_TrustedServerIPCount;

// Event and variables for security approval
extern KEVENT SecurityApprovalEvent;
extern ULONG g_SecurityScore;
extern ULONG g_SecurityThreshold;

// Flag indicating that the client & server connection is active.
extern BOOLEAN g_ClientConnected;

// Global copy of the registry path (used when starting the filter services later).
extern UNICODE_STRING g_RegistryPath;

// Flag indicating that the filter service and packet queue are started.
extern BOOLEAN g_FilterServiceStarted;

#include <wdm.h>  // for LIST_ENTRY, KSPIN_LOCK

extern LIST_ENTRY g_PushIrpQueue;
extern KSPIN_LOCK g_PushIrpQueueLock;

extern PVOID g_PcapRingBuffer;             // Circular buffer for PCAP packets.
extern ULONG g_RingBufferSize;             // Total size of the ring buffer.
extern KEVENT g_PcapDataAvailableEvent;    // Event to signal data availability.
extern ULONG g_RingBufferWriteIndex;       // Write index into the ring buffer.
extern ULONG g_RingBufferReadIndex;        // Read index (for user-mode consumption).
extern KSPIN_LOCK g_RingBufferLock;        // Lock for ring buffer access.

extern PVOID g_CommandRingBuffer;             // Ring buffer for command packets.
extern ULONG g_CommandRingBufferSize;         // Total size of the command ring buffer.
extern ULONG g_CommandRingBufferWriteIndex;   // Write index for the command ring buffer.
extern ULONG g_CommandRingBufferReadIndex;    // Read index (for user-mode consumption).
extern KSPIN_LOCK g_CommandRingBufferLock;      // Lock for command ring buffer access.
extern KEVENT g_CommandDataAvailableEvent;      // Event to signal that a new command is available.



#endif // GLOBALS_H