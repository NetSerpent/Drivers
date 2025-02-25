// Author: William Stobaugh
// Starting date: Jan 27th, 2025
// Reference https://www.canva.com/design/DAGffSOUc7I/oboaEWY13sDACMWfbimHgw/edit?referrer=diagrams-landing-page

#include "common.h"
#include "globals.h"
#include "initialize_driver.h"
#include "network_info.h"


NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{

    // Open Kernel to client communication
    NTSTATUS status = CommunicationServiceStartup(DriverObject, RegistryPath);

    // TODO: Before we send out any packets, we need to confirm that we have access to the internet
    /*
    status = confirmConnection()
    if (!NT_SUCCESS(status))
    {
        DebugMessage("NetSerpent: Failed to connect to NetSerpent servers\n");
        RtlStringCchPrintfA(g_ErrorMessage, sizeof(g_ErrorMessage),
            "NetSerpent Error: Failed to connect to NetSerpent servers (0x%08X)", status);
    }
    */

    // Starts the Filter Driver service
    status = FilterServiceStartup(DriverObject, RegistryPath);
    if (!NT_SUCCESS(status))
    {
        return status;
    }





    return status;
}
