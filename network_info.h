#pragma once
#ifndef NETWORK_INFO_H
#define NETWORK_INFO_H

#include <ntddk.h>
#include <ntstrsafe.h>
#include <guiddef.h>

// Loads the locally stored network UUID (and possibly other network data) from disk.
// Returns STATUS_SUCCESS if successful or an error status otherwise.
NTSTATUS LoadNetworkInfo(GUID* pNetworkGuid);

// Saves the given network UUID to local storage.
NTSTATUS SaveNetworkInfo(GUID* pNetworkGuid);

#endif // NETWORK_INFO_H
