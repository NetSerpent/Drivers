#include "driver_to_client.h"
#include "globals.h"
#include <wdm.h>


/// GENERAL FUNCTIONS FOR PACKET SENDING TO CLIENT -----------------------

//------------------------------------------------------------------------------
// WriteToRingBuffer
// Writes the provided data into the circular ring buffer while handling wrap-around.
//------------------------------------------------------------------------------
NTSTATUS WriteToRingBuffer(PVOID ringBuffer, ULONG ringBufferSize, UCHAR* data, ULONG dataSize)
{
    if (dataSize > ringBufferSize) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    KIRQL oldIrql;
    KeAcquireSpinLock(&g_RingBufferLock, &oldIrql);
    ULONG writeIndex = g_RingBufferWriteIndex;

    if (writeIndex + dataSize <= ringBufferSize) {
        RtlCopyMemory((PUCHAR)ringBuffer + writeIndex, data, dataSize);
        g_RingBufferWriteIndex = (writeIndex + dataSize) % ringBufferSize;
    }
    else {
        ULONG firstPart = ringBufferSize - writeIndex;
        RtlCopyMemory((PUCHAR)ringBuffer + writeIndex, data, firstPart);
        RtlCopyMemory((PUCHAR)ringBuffer, data + firstPart, dataSize - firstPart);
        g_RingBufferWriteIndex = dataSize - firstPart;
    }
    KeReleaseSpinLock(&g_RingBufferLock, oldIrql);
    return STATUS_SUCCESS;
}

/// New centralized command sending function.
/// This builds a packet with the first byte as the command code, followed by any payload,
/// then calls PushCommandPacket() to deliver it to the user-mode client.
NTSTATUS SendClientCommand(UCHAR commandCode, UCHAR* payload, ULONG payloadSize)
{
    DebugMessage("Sending command to the client via ring buffer!\n");

    // Calculate the total size of our command packet.
    // (For simplicity, we use a 1-byte command code followed by the payload.)
    ULONG packetSize = 1 + payloadSize;

    // Allocate temporary storage for the command packet.
    UCHAR* commandPacket = ExAllocatePoolWithTag(NonPagedPoolNx, packetSize, 'cmdP');
    if (!commandPacket) {
        DebugMessage("SendClientCommand: Failed to allocate memory for command packet.\n");
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    // Set the command code.
    commandPacket[0] = commandCode;

    // Copy payload if provided.
    if (payloadSize > 0 && payload) {
        RtlCopyMemory(commandPacket + 1, payload, payloadSize);
    }

    // Write the command packet into the command ring buffer.
    NTSTATUS status = WriteToRingBuffer(g_CommandRingBuffer, g_CommandRingBufferSize, commandPacket, packetSize);
    if (NT_SUCCESS(status)) {
        // Signal the event to notify the user-mode client that a command is available.
        KeSetEvent(&g_CommandDataAvailableEvent, IO_NO_INCREMENT, FALSE);
        DebugMessage("SendClientCommand: Successfully queued command 0x%02X via ring buffer.\n", commandCode);
    }
    else {
        DebugMessage("SendClientCommand: Failed to write command packet to ring buffer, status: 0x%08X\n", status);
    }

    ExFreePool(commandPacket);
    return status;
}




/// FUNCTIONS FOR SENDING INDIVIDUAL COMMANDS TO THE RUST CLIENT ------------------------

// This function is now used to register a push IRP.
NTSTATUS HandleRegisterCommandListener(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    // Mark the IRP pending.
    IoMarkIrpPending(Irp);

    // Insert the IRP into the global push queue.
    KIRQL oldIrql;
    KeAcquireSpinLock(&g_PushIrpQueueLock, &oldIrql);
    InsertTailList(&g_PushIrpQueue, &Irp->Tail.Overlay.ListEntry);
    KeReleaseSpinLock(&g_PushIrpQueueLock, oldIrql);

    // Do not complete it now. It will be completed when a push event occurs.
    return STATUS_PENDING;
}

