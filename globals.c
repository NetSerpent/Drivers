#include "globals.h"


PDRIVER_OBJECT g_DriverObject = NULL;
PDEVICE_OBJECT DeviceObject = NULL;
HANDLE EngineHandle = NULL;
UINT32 RegCalloutId = 0;
UINT32 AddCalloutId = 0;
UINT64 filterid = 0;


// Initialize error message to empty
CHAR g_ErrorMessage[256] = { 0 };

// A notification event that is initially not signaled.
KEVENT AdminConnectionEvent;


ULONG g_TrustedServerIPs[MAX_TRUSTED_IPS] = { 0 };
ULONG g_TrustedServerIPCount = 0;

// NEW: Initialize the security approval event and variables.
KEVENT SecurityApprovalEvent;
ULONG g_SecurityScore = 0;        // Default to “good”
ULONG g_SecurityThreshold = 0;      // Default threshold for approval

// TODO (Make sure to initialize SecurityApprovalEvent during driver startup.)

BOOLEAN g_ClientConnected = FALSE; // Initially not connected to the client

UNICODE_STRING g_RegistryPath = RTL_CONSTANT_STRING(L"");

BOOLEAN g_FilterServiceStarted = FALSE;

LIST_ENTRY g_PushIrpQueue = { 0 };
KSPIN_LOCK g_PushIrpQueueLock = { 0 }; 

PVOID g_PcapRingBuffer = NULL;      // Circular buffer for PCAP packets.
ULONG g_RingBufferSize = 1024;         // Total size of the ring buffer.
KEVENT g_PcapDataAvailableEvent;    // Event to signal data availability.
ULONG g_RingBufferWriteIndex;       // Write index into the ring buffer.
KSPIN_LOCK g_RingBufferLock;        // Lock for ring buffer access.

PVOID g_CommandRingBuffer;             // Ring buffer for command packets.
ULONG g_CommandRingBufferSize = 1024;         // Total size of the command ring buffer.
ULONG g_CommandRingBufferWriteIndex;   // Write index for the command ring buffer.
ULONG g_CommandRingBufferReadIndex;    // Read index (for user-mode consumption).
KSPIN_LOCK g_CommandRingBufferLock;      // Lock for command ring buffer access.
KEVENT g_CommandDataAvailableEvent;      // Event to signal that a new command is available.