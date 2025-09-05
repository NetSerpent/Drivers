/*======================================================================
  driver.c – NetSerpent kernel driver’s entry-point (DriverEntry)
  ----------------------------------------------------------------------

  // Reference https://www.canva.com/design/DAGffSOUc7I/oboaEWY13sDACMWfbimHgw/edit?referrer=diagrams-landing-page

  Responsibilities
    1. Emit startup banner and stash DriverObject globally
    2. Boot the kernel <-> client IPC layer via CommunicationServiceStartup()
    3. (Future) Validate network connectivity & cached network-info
    4. Defer to other subsystems (WFP, filter, etc.)

   Contributing
    - **Never** add heavy-weight logic directly inside DriverEntry; keep
      it quick and defer via work-items if needed.
    - TODO marks where idempotence checks and reconnection handling will
      be added once multiple client reconnects are supported.
======================================================================*/



#include "common.h"
#include "globals.h"
#include "driver_init.h"


// TODO FOR NEXT SESSION: Clean up this code, each function and file should have
// more specific responsibilities. Everything should be well documented.



NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{
    DebugMessage("NetSerpent: Starting\n");
    // Store the driver object globally.
    g_DriverObject = DriverObject;
    
    // Open Kernel to client communication
    NTSTATUS status = CommunicationServiceStartup(DriverObject, RegistryPath);
    if (!NT_SUCCESS(status)) return status;

    // TODO: Check for an active internet connection (At least to our server??)



    DebugMessage("NetSerpent: Successful Driver Entry\n");
    //return status;
	return STATUS_SUCCESS;
}
