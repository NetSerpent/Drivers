#include "packet_approval.h"
#include "globals.h"

// This function waits for a security approval signal from our NetSerpent server.
// It waits on SecurityApprovalEvent (with a timeout) and then compares g_SecurityScore against g_SecurityThreshold.
NTSTATUS WaitForPacketApproval()
{
    LARGE_INTEGER timeout;
    // Wait up to 50 milliseconds for approval (50 ms in 100-nanosecond intervals, negative for relative time)
    timeout.QuadPart = -50 * 1000 * 10LL;

    NTSTATUS status = KeWaitForSingleObject(&SecurityApprovalEvent, Executive, KernelMode, FALSE, &timeout);
    if (status == STATUS_TIMEOUT) {
        DebugMessage("Packet approval timed out.\n");
        return STATUS_TIMEOUT;
    }

    // Reset the event for next use.
    KeResetEvent(&SecurityApprovalEvent);

    // If the received security score is at or above the threshold, approve.
    if (g_SecurityScore >= g_SecurityThreshold) {
        DebugMessage("Packet approved with score: %u\n", g_SecurityScore);
        return STATUS_SUCCESS;
    }
    else {
        DebugMessage("Packet disapproved with score: %u\n", g_SecurityScore);
        return STATUS_ACCESS_DENIED;
    }
}