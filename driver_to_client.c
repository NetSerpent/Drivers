/*======================================================================
  driver_to_client.c – Kernel → User-mode command queue
  ----------------------------------------------------------------------
  Core idea: the kernel builds small command objects (up to 64 B payload)
  and enqueues them in a lock-free doubly-linked list.  The Rust client
  polls / waits on this list to process work.

  • AddClientCommand()          – O(1) tail insert with backlog guard
  • DequeueClientCommand()      – O(n) (walk back to head) FIFO pop
  • SendClientCommand(code,buf) – Public façade to build & enqueue
  • AddStreamingServerIp()      – Example command-specific helper

  Globals
    g_LastCommandEntry          – tail pointer
    g_ClientCommandCount        – atomic depth counter

   Contributing
    - Increase MAX_CLIENT_COMMAND_COUNT or auto-scale when near full.
    - Extend command set: create new helper, encode payload, call
      SendClientCommand().
    - Consider replacing the O(n) dequeue with a head pointer +
      interlocked list ops if throughput becomes an issue.
======================================================================*/

#include "driver_to_client.h"
#include "globals.h"
#include <wdm.h>

#define MAX_CLIENT_COMMAND_COUNT 1024

// Diagnostic: disable queue entirely to rule out list corruption / memory growth
#define NS_DIAG_DISABLE_CLIENT_QUEUE 0  // <—— set to 0 to re-enable

volatile LONG g_ClientCommandCount = 0;

// Global tail pointer for doubly-linked list.
ClientCommandLinkedListEntry* g_LastCommandEntry = NULL;

static __forceinline VOID FreeEntry(_In_ ClientCommandLinkedListEntry* e)
{
    if (e) ExFreePool(e);
}

#if !NS_DIAG_DISABLE_CLIENT_QUEUE
// --------------------------------------------------------------------
// Adds a new entry to the tail of the doubly-linked list. (UNLOCKED)
// NOTE: In high PPS, concurrent callers can corrupt the list. Use
//       a spin lock if you re-enable this in production.
// --------------------------------------------------------------------
VOID AddClientCommand(ClientCommandLinkedListEntry* newEntry)
{
    if (InterlockedCompareExchange(&g_ClientCommandCount, 0, 0) >= MAX_CLIENT_COMMAND_COUNT) {
        DebugMessage("AddClientCommand: Queue is full, dropping command.\n");
        ExFreePool(newEntry);
        return;
    }

    if (g_LastCommandEntry == NULL)
    {
        g_LastCommandEntry = newEntry;
        newEntry->before = NULL;
        newEntry->next = NULL;
    }
    else
    {
        g_LastCommandEntry->next   = newEntry;
        newEntry->before           = g_LastCommandEntry;
        newEntry->next             = NULL;
        g_LastCommandEntry         = newEntry;
    }
    InterlockedIncrement(&g_ClientCommandCount);
}
#else
// Diagnostic stub: pretend we enqueued, but just free it.
static VOID AddClientCommand(ClientCommandLinkedListEntry* newEntry)
{
    UNREFERENCED_PARAMETER(newEntry);
    // No queueing in diagnostics
}
#endif

#if !NS_DIAG_DISABLE_CLIENT_QUEUE
// FIFO dequeue by walking back to head (O(n)). Caller frees returned node.
ClientCommandLinkedListEntry* DequeueClientCommand(void)
{
    if (g_LastCommandEntry == NULL)
        return NULL;

    ClientCommandLinkedListEntry* head = g_LastCommandEntry;
    while (head->before != NULL)
        head = head->before;

    if (head->next != NULL)
        head->next->before = NULL;
    else
        g_LastCommandEntry = NULL;

    head->next = NULL;
    head->before = NULL;
    InterlockedDecrement(&g_ClientCommandCount);
    return head;
}
#else
ClientCommandLinkedListEntry* DequeueClientCommand(void)
{
    // Diagnostics: nothing ever queued.
    return NULL;
}
#endif

NTSTATUS SendClientCommand(UCHAR commandCode, UCHAR* payload, ULONG payloadSize)
{
    // Allocate a new command node
    ClientCommandLinkedListEntry* newEntry =
        (ClientCommandLinkedListEntry*)ExAllocatePoolZero(
            NonPagedPoolNx,
            sizeof(ClientCommandLinkedListEntry),
            'cmdP'
        );
    if (!newEntry)
    {
        DebugMessage("SendClientCommand: Failed to allocate newEntry.\n");
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    newEntry->commandCode = commandCode;
    newEntry->workState   = 0; // untouched

    ULONG copyLength = (payload && payloadSize > 0)
        ? ((payloadSize > sizeof(newEntry->data)) ? sizeof(newEntry->data) : payloadSize)
        : 0;

    if (copyLength > 0)
        RtlCopyMemory(newEntry->data, payload, copyLength);

#if NS_DIAG_DISABLE_CLIENT_QUEUE
    // ===================== DIAGNOSTIC BEHAVIOR ======================
    // Drop immediately to avoid:
    //  • NonPagedPool growth,
    //  • lock-free list pointer races,
    //  • user-mode dequeue lag causing backlog.
    // ================================================================
    FreeEntry(newEntry);
    return STATUS_SUCCESS;
#else
    AddClientCommand(newEntry);
    return STATUS_SUCCESS;
#endif
}

/* Optional utility that might be called elsewhere */
#include <ip2string.h>
#include <inaddr.h>
NTSTATUS AddStreamingServerIp(CHAR* ipString, ULONG ipStringLength)
{
    if (ipStringLength == 0 || ipStringLength >= 64)
        return STATUS_INVALID_PARAMETER;

    CHAR localBuffer[64] = {0};
    RtlCopyMemory(localBuffer, ipString, ipStringLength);

    ULONG ipv4Addr = 0;
    ANSI_STRING ansiStr;
    RtlInitAnsiString(&ansiStr, localBuffer);

    PCSZ terminator = NULL;
    NTSTATUS status = RtlIpv4StringToAddressA(ansiStr.Buffer, TRUE, &terminator, (PIN_ADDR)&ipv4Addr);
    if (!NT_SUCCESS(status))
        return status;

    for (ULONG i = 0; i < g_TrustedServerIPCount; i++)
        if (g_TrustedServerIPs[i] == ipv4Addr)
            return STATUS_SUCCESS;

    if (g_TrustedServerIPCount >= MAX_TRUSTED_IPS)
        return STATUS_INSUFFICIENT_RESOURCES;

    g_TrustedServerIPs[g_TrustedServerIPCount++] = ipv4Addr;
    return STATUS_SUCCESS;
}