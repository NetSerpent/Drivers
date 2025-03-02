#pragma once
#ifndef NETSERPENT_PACKET_H
#define NETSERPENT_PACKET_H

#include <ntddk.h>
#include <ndis/nbl.h>

// Returns TRUE if the given NET_BUFFER_LIST comes from our NetSerpent service.
BOOLEAN IsNetSerpentPacket(NET_BUFFER_LIST* nbl);

// Processes a NetSerpent packet (for example, updating trusted IPs or handling status responses).
VOID ProcessNetSerpentPacket(NET_BUFFER_LIST* nbl);

#endif // NETSERPENT_PACKET_H
