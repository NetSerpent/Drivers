/*======================================================================
  packet_approval.c – Tiny synchronisation gate for packet re-injection
  ----------------------------------------------------------------------
  • NTSTATUS WaitForPacketApproval()
        Waits up to 50 ms for SecurityApprovalEvent then compares the
        latest g_SecurityScore vs g_SecurityThreshold.

  Return codes
        STATUS_SUCCESS        – approve and continue processing
        STATUS_ACCESS_DENIED  – block / drop
        STATUS_TIMEOUT        – fall-back decision (currently “block”)

   Contributing
    - Adjust timeout or make it dynamic based on packet priority.
    - Surface richer verdicts (e.g. “quarantine”, “reroute”) via enum.
======================================================================*/


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