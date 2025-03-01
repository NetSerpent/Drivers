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