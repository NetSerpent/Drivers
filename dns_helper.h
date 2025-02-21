#pragma once
#ifndef DNS_HELPER_H
#define DNS_HELPER_H

#include <ntddk.h>
#include <ndis.h>
#include <ndis/nbl.h> // Ensure that you have the proper path for NDIS NBL definitions
#include <ndis/nblaccessors.h>
#include <ndis/nblapi.h>

#ifdef __cplusplus
extern "C" {
#endif

	// Returns TRUE if the NET_BUFFER_LIST contains a DNS packet.
	BOOLEAN IsDnsPacket(NET_BUFFER_LIST* nbl);

#ifdef __cplusplus
}
#endif

#endif // DNS_HELPER_H
