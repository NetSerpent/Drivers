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

// IOCTL CODES (SENT TO THE DRIVER)
#define IOCTL_REGISTER_COMMAND_LISTENER CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_OUT_DIRECT, FILE_ANY_ACCESS)
#define IOCTL_SET_NETWORK_INFO CTL_CODE(FILE_DEVICE_UNKNOWN, 0x802, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_PROCESS_SECURITY_RESPONSE CTL_CODE(FILE_DEVICE_UNKNOWN, 0x803, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_INFORM_NETWORK_CONNECTED CTL_CODE(FILE_DEVICE_UNKNOWN, 0x804, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_PING CTL_CODE(FILE_DEVICE_UNKNOWN, 0x805, METHOD_BUFFERED, FILE_ANY_ACCESS)


// RUST CLIENT COMMANDS (SENT TO THE CLIENT)
#define RUST_PACKET_SECURITY_CHECK_CODE 0x3
#define RUST_PACKET_ERROR_CODE            0x4
#define RUST_PACKET_TEST_CODE             0x5  // New test command code


#endif // COMMON_H
