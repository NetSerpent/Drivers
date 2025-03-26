#pragma once
#include "common.h"

typedef struct ClientCommandLinkedListEntry {
    // Command code
    UCHAR commandCode;

    // Work state (0x0 : untouched) (0x1 : touched) (0x2 for finished not needed since we will just free the memory)
    UCHAR workState;

    // Buffer for data
    UCHAR data[64];

    // Pointer to the next command in the list
    struct ClientCommandLinkedListEntry* next;

    // Pointer to the previous command in the list
    struct ClientCommandLinkedListEntry* before;

} ClientCommandLinkedListEntry;

ClientCommandLinkedListEntry* GetClientCommandListHandle();
NTSTATUS SendClientCommand(UCHAR commandCode, UCHAR* payload, ULONG payloadSize);
ClientCommandLinkedListEntry* DequeueClientCommand(void);