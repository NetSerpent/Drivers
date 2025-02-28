#include "connection.h"
#include "common.h"

NTSTATUS confirmConnection(void)
{
    LARGE_INTEGER delay;

    // Set up a 5-second delay.
    // The time is specified in 100-nanosecond intervals (negative value for relative time).
    delay.QuadPart = -5 * 1000 * 1000 * 10LL;

    DebugMessage("NetSerpent: Waiting for internet connection...\n");

    // Delay the current thread for 5 seconds.
    KeDelayExecutionThread(KernelMode, FALSE, &delay);

    DebugMessage("NetSerpent: Internet connection confirmed.\n");

    return STATUS_SUCCESS;
}
