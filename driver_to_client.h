#pragma once
#include "common.h"
NTSTATUS HandleRegisterCommandListener(PDEVICE_OBJECT DeviceObject, PIRP Irp);
NTSTATUS PushCommandPacket(UCHAR* packet, ULONG packetSize);
NTSTATUS SendClientCommand(UCHAR commandCode, UCHAR* payload, ULONG payloadSize);
NTSTATUS WriteToRingBuffer(PVOID ringBuffer, ULONG ringBufferSize, UCHAR* data, ULONG dataSize);