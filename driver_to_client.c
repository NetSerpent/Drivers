#include "driver_to_client.h"
#include "globals.h"
#include "driver_to_client.h"
#include <wdm.h>


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
    return head;
}


NTSTATUS SendClientCommand(UCHAR commandCode, UCHAR* payload, ULONG payloadSize)
{
    DebugMessage("SendClientCommand: Creating a new command entry.\n");

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

    DebugMessage(
        "SendClientCommand: Appended command 0x%02X to the list. (WorkState=%u)\n",
        commandCode,
        newEntry->workState
    );

    // In a real driver, you might signal an event here 
    // so the client side knows a new command is ready.

    return STATUS_SUCCESS;
}



/// FUNCTIONS FOR SENDING INDIVIDUAL COMMANDS TO THE RUST CLIENT ------------------------

// This function is now used to register a push IRP.
ClientCommandLinkedListEntry* GetClientCommandListHandle()
{
    return g_LastCommandEntry;
}

