#include "globals.h"

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
FLOAT g_SecurityScore = 1.0f;        // Default to “good”
FLOAT g_SecurityThreshold = 0.5f;      // Default threshold for approval

// (Make sure to initialize SecurityApprovalEvent during driver startup.)