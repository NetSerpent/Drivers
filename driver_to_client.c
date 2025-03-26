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
