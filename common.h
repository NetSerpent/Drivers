#pragma once
#ifndef COMMON_H
#define COMMON_H

#define NDIS630 1  // or NDIS650, etc., depending on your target

#pragma warning(disable:4201)
#include <ntddk.h>
#include <ndis.h>
//#include <ndis/nbl.h>
#include <fwpsk.h>
#include <fwpmk.h>
#define INITGUID
#include <guiddef.h>
#include <fwpmu.h>


// Debug macro definition
#define DebugMessage(msg, ...) DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, msg, __VA_ARGS__)
VOID DebugStatus(PCSTR msg, NTSTATUS status);

// NEW: Define our custom IOCTL for getting a PCAP-formatted packet.
// (FILE_DEVICE_UNKNOWN is used here; adjust the code and function number as needed.)
#define IOCTL_GET_PCAP_PACKET CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_GET_ERROR_MESSAGE CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_SET_NETWORK_INFO CTL_CODE(FILE_DEVICE_UNKNOWN, 0x802, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_SEND_NETSERPENT_COMMAND CTL_CODE(FILE_DEVICE_UNKNOWN, 0x803, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_INFORM_NETWORK_CONNECTED CTL_CODE(FILE_DEVICE_UNKNOWN, 0x804, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_PING CTL_CODE(FILE_DEVICE_UNKNOWN, 0x805, METHOD_BUFFERED, FILE_ANY_ACCESS)


#endif // COMMON_H
