#pragma once
#ifndef GLOBALS_H
#define GLOBALS_H

#include "common.h" // or any header that defines PDEVICE_OBJECT, etc.

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

// NEW: Event and variables for security approval
extern KEVENT SecurityApprovalEvent;
extern FLOAT g_SecurityScore;
extern FLOAT g_SecurityThreshold;

#endif // GLOBALS_H