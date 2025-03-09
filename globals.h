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




#endif // GLOBALS_H