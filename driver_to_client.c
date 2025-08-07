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
#include "driver_to_client.h"
#include <wdm.h>


// Max number of commands in our stack allowed
#define MAX_CLIENT_COMMAND_COUNT 1024
volatile LONG g_ClientCommandCount = 0;


/// GENERAL FUNCTIONS FOR PACKET SENDING TO CLIENT -----------------------

// --------------------------------------------------------------------
// Global pointer to the last entry in our doubly-linked command list.
// If NULL, the list is empty. 
// --------------------------------------------------------------------
ClientCommandLinkedListEntry* g_LastCommandEntry = NULL;

// --------------------------------------------------------------------
// Adds a new entry to the tail of the doubly-linked list. 
// If the list is empty, the new entry becomes the first/only element.
// --------------------------------------------------------------------
VOID AddClientCommand(ClientCommandLinkedListEntry* newEntry)
{
    // TODO: Probably in the future we will want to ask the client to increase the number of workers if we get close to being full
    // Check if we have reached the maximum allowed queue size.
    if (InterlockedCompareExchange(&g_ClientCommandCount, 0, 0) >= MAX_CLIENT_COMMAND_COUNT) {
        DebugMessage("AddClientCommand: Queue is full, dropping command.\n");
        ExFreePool(newEntry);
        return;
    }


    // If there's no tail yet, the list is empty
    if (g_LastCommandEntry == NULL)
    {
        // This is the first entry
        g_LastCommandEntry = newEntry;
        newEntry->before = NULL;
        newEntry->next = NULL;
    }
    else
    {
        // Link the new entry after the old tail
        g_LastCommandEntry->next = newEntry;
        newEntry->before = g_LastCommandEntry;
        newEntry->next = NULL;

        // Update the "last" pointer
        g_LastCommandEntry = newEntry;
    }
    InterlockedIncrement(&g_ClientCommandCount);
}

// DequeueClientCommand: removes and returns the head (FIFO).
// Returns NULL if the list is empty.
ClientCommandLinkedListEntry* DequeueClientCommand(void)
{
    if (g_LastCommandEntry == NULL)
        return NULL;

    // Walk backward to find the head (node with before == NULL)
    ClientCommandLinkedListEntry* head = g_LastCommandEntry;
    while (head->before != NULL)
    {
        head = head->before;
    }

    // Remove head from the list:
    if (head->next != NULL)
    {
        head->next->before = NULL;
    }
    else
    {
        // Only one node was in the list.
        g_LastCommandEntry = NULL;
    }
    // Detach the node from the list.
    head->next = NULL;
    head->before = NULL;
    InterlockedDecrement(&g_ClientCommandCount);
    return head;
}


NTSTATUS SendClientCommand(UCHAR commandCode, UCHAR* payload, ULONG payloadSize)
{

    // Allocate a new doubly-linked command node
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

    // Initialize the fields
    newEntry->commandCode = commandCode;
    newEntry->workState = 0; // Untouched

    // Copy up to 64 bytes of the payload
    // TODO: How should we handle this edge case other than clipping?
    ULONG copyLength = (payloadSize > sizeof(newEntry->data))
        ? sizeof(newEntry->data)
        : payloadSize;
    if (payload && copyLength > 0)
    {
        RtlCopyMemory(newEntry->data, payload, copyLength);
    }

    // Insert the new node at the end of our list
    AddClientCommand(newEntry);
    // In a real driver, you might signal an event here 
    // so the client side knows a new command is ready.

    return STATUS_SUCCESS;
}


/// INDIVIDUAL COMMAND FUNCTIONS -----------------------


#include <ip2string.h> // for RtlIpv4StringToAddressA
#include <inaddr.h> // for in_addr structure
NTSTATUS AddStreamingServerIp(CHAR* ipString, ULONG ipStringLength)
{
    // 1) Validate the input length.
    if (ipStringLength == 0 || ipStringLength >= 64) {
        return STATUS_INVALID_PARAMETER;
    }

    // 2) Copy into a local buffer to ensure null-termination.
    CHAR localBuffer[64];
    RtlZeroMemory(localBuffer, sizeof(localBuffer));
    RtlCopyMemory(localBuffer, ipString, ipStringLength);

    // 3) Parse the IP string into a 32-bit IPv4 address using RtlIpv4StringToAddressA.
    ULONG ipv4Addr = 0;
    ANSI_STRING ansiStr;
    RtlInitAnsiString(&ansiStr, localBuffer);

    PCSZ terminator = NULL;
    NTSTATUS status = RtlIpv4StringToAddressA(ansiStr.Buffer,TRUE,&terminator,(PIN_ADDR)&ipv4Addr);
    if (!NT_SUCCESS(status)) {
        DebugMessage("AddStreamingServerIp: Failed to parse IP string, status=0x%08X\n", status);
        return status;
    }

    // 4) Check if we already have the IP or if there's room in g_TrustedServerIPs.
    for (ULONG i = 0; i < g_TrustedServerIPCount; i++) {
        if (g_TrustedServerIPs[i] == ipv4Addr) {
            return STATUS_SUCCESS;
        }
    }

    // Check to be sure we are not going over the IP limit
    if (g_TrustedServerIPCount >= MAX_TRUSTED_IPS) {
        DebugMessage("AddStreamingServerIp: IP list full.\n");
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    g_TrustedServerIPs[g_TrustedServerIPCount++] = ipv4Addr;
    DebugMessage("AddStreamingServerIp: Added or kept existing IP=0x%08X, total count=%lu\n",
        ipv4Addr, g_TrustedServerIPCount);

    return STATUS_SUCCESS;
}
