#pragma once
#ifndef GLOBALS_H
#define GLOBALS_H

#include "common.h" // or any header that defines PDEVICE_OBJECT, etc.

// Declare globals with extern so they are not redefined.
extern PDEVICE_OBJECT DeviceObject;
extern HANDLE EngineHandle;
extern UINT32 RegCalloutId;
extern UINT32 AddCalloutId;
extern UINT64 filterid;

#endif // GLOBALS_H
