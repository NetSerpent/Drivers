// Author: William Stobaugh
// Starting date: Jan 27th, 2025

#include "common.h"
#include "globals.h"
#include "initialize_driver.h"


NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{

    // Does the user have existing network information stored? 
    // Check if file path exist

    // If not, await command to connect to an admin network
    // Then save network information locally

    // Start up driver services
    NTSTATUS status = ServiceStartup(DriverObject, RegistryPath);
    return status;
}
