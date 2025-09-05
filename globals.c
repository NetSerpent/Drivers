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

KSPIN_LOCK g_ClientCommandLock;    // Spin lock for client command list

UNICODE_STRING g_RegistryPath = RTL_CONSTANT_STRING(L"");

BOOLEAN g_FilterServiceStarted = FALSE;