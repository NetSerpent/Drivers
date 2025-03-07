// Author: William Stobaugh
// Starting date: Jan 27th, 2025
// Reference https://www.canva.com/design/DAGffSOUc7I/oboaEWY13sDACMWfbimHgw/edit?referrer=diagrams-landing-page

#include "common.h"
#include "globals.h"
#include "initialize_driver.h"
#include "network_info.h"
#include "connection.h"


// TODO FOR NEXT SESSIONL: FIX BUG FOUND IN initalize_driver.c IN IOCTL_GET_PCAP_PACKET IO HANDLING

NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{
    DebugMessage("NetSerpent: Starting\n");
    // Store the driver object globally.
    g_DriverObject = DriverObject;


    // Open Kernel to client communication
    NTSTATUS status = CommunicationServiceStartup(DriverObject, RegistryPath);
    if (!NT_SUCCESS(status)) return status;

    // TODO: Implement this to actually check for an active internet connection
    /*status = confirmConnection();
    if (!NT_SUCCESS(status)) return status;*/

    // Does the user have existing network information stored? (For testing we are going to comment this out for now)
    //status = WaitForNetworkConnectionInformation();
    //if (!NT_SUCCESS(status)) return status;

    DebugMessage("NetSerpent: Successful Driver Entry\n");
    return status;
}
