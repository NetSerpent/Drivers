#include "network_info.h"
#include "globals.h"

// Define the file path for our network information.
// Note: In kernel mode, paths typically use the "\\??\\" prefix.
#define NETWORK_INFO_PATH L"\\??\\C:\\NetSerpent\\network.info"

NTSTATUS LoadNetworkInfo(GUID* pNetworkGuid)
{
    if (!pNetworkGuid) {
        return STATUS_INVALID_PARAMETER;
    }

    UNICODE_STRING filePath;
    RtlInitUnicodeString(&filePath, NETWORK_INFO_PATH);

    OBJECT_ATTRIBUTES objAttr;
    InitializeObjectAttributes(&objAttr, &filePath, OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, NULL, NULL);

    HANDLE fileHandle;
    IO_STATUS_BLOCK ioStatusBlock;
    NTSTATUS status = ZwCreateFile(&fileHandle,
        GENERIC_READ,
        &objAttr,
        &ioStatusBlock,
        NULL,
        FILE_ATTRIBUTE_NORMAL,
        0,
        FILE_OPEN,
        FILE_SYNCHRONOUS_IO_NONALERT,
        NULL,
        0);
    if (!NT_SUCCESS(status)) {
        // File does not exist or cannot be opened.
        return status;
    }

    // Read the file; we expect the file to contain a GUID.
    GUID guid = { 0 };
    status = ZwReadFile(fileHandle,
        NULL,
        NULL,
        NULL,
        &ioStatusBlock,
        &guid,
        sizeof(GUID),
        NULL,
        NULL);
    ZwClose(fileHandle);
    if (NT_SUCCESS(status) && ioStatusBlock.Information == sizeof(GUID)) {
        *pNetworkGuid = guid;
        return STATUS_SUCCESS;
    }
    return STATUS_UNSUCCESSFUL;
}

NTSTATUS SaveNetworkInfo(GUID* pNetworkGuid)
{
    if (!pNetworkGuid) {
        return STATUS_INVALID_PARAMETER;
    }

    UNICODE_STRING filePath;
    RtlInitUnicodeString(&filePath, NETWORK_INFO_PATH);

    OBJECT_ATTRIBUTES objAttr;
    InitializeObjectAttributes(&objAttr, &filePath, OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, NULL, NULL);

    HANDLE fileHandle;
    IO_STATUS_BLOCK ioStatusBlock;
    NTSTATUS status = ZwCreateFile(&fileHandle,
        GENERIC_WRITE,
        &objAttr,
        &ioStatusBlock,
        NULL,
        FILE_ATTRIBUTE_NORMAL,
        0,
        FILE_OVERWRITE_IF,
        FILE_SYNCHRONOUS_IO_NONALERT,
        NULL,
        0);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    status = ZwWriteFile(fileHandle,
        NULL,
        NULL,
        NULL,
        &ioStatusBlock,
        pNetworkGuid,
        sizeof(GUID),
        NULL,
        NULL);
    ZwClose(fileHandle);
    return status;
}

NTSTATUS WaitForNetworkConnectionInformation()
{
    // Check if the user has existing network information stored.
    GUID networkGuid = { 0 };
    NTSTATUS netInfoStatus = LoadNetworkInfo(&networkGuid);
    if (NT_SUCCESS(netInfoStatus)) {
        DebugMessage("NetSerpent: Loaded network info successfully.\n", netInfoStatus);
        return netInfoStatus;
    }
    else {
        DebugMessage("NetSerpent: No existing network info found. Awaiting admin network connection command.\n", netInfoStatus);
        
        // TODO: Wait until we make an admin connection, client must send us a message that a connection is formed...

        // For simulation purposes, we immediately generate a new network GUID.
        NTSTATUS guidStatus = ExUuidCreate(&networkGuid);  // TODO: In reality we would save whatever information the client sends us.
        if (NT_SUCCESS(guidStatus)) {
            DebugMessage("NetSerpent: Generated new network GUID.\n", guidStatus);
            NTSTATUS saveStatus = SaveNetworkInfo(&networkGuid);
            if (!NT_SUCCESS(saveStatus)) {
                DebugMessage("NetSerpent: Failed to save network info: 0x%08X\n", saveStatus);
            }
            return saveStatus;
        }
        else {
            DebugMessage("NetSerpent: Failed to generate new GUID: 0x%08X\n", guidStatus);
            return guidStatus;
        }
    }
}
