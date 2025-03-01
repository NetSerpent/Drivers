#include "network_info.h"
#include "globals.h"

// Define the directory and file paths.
#define NETWORK_DIR      L"\\??\\C:\\NetSerpent"
#define NETWORK_INFO_PATH L"\\??\\C:\\NetSerpent\\network.info"

// Helper function to ensure the directory exists.
static NTSTATUS EnsureNetworkDirectoryExists()
{
    UNICODE_STRING directoryPath;
    RtlInitUnicodeString(&directoryPath, NETWORK_DIR);
    OBJECT_ATTRIBUTES objAttr;
    InitializeObjectAttributes(&objAttr, &directoryPath, OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, NULL, NULL);

    HANDLE dirHandle;
    IO_STATUS_BLOCK ioStatusBlock;
    NTSTATUS status = ZwCreateFile(
        &dirHandle,
        FILE_GENERIC_WRITE | SYNCHRONIZE,
        &objAttr,
        &ioStatusBlock,
        NULL,
        FILE_ATTRIBUTE_DIRECTORY,
        0,
        FILE_OPEN_IF, // Open if exists; create if not.
        FILE_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT,
        NULL,
        0
    );
    if (NT_SUCCESS(status))
    {
        ZwClose(dirHandle);
    }
    return status;
}




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

    // Ensure that the directory exists.
    NTSTATUS dirStatus = EnsureNetworkDirectoryExists();
    if (!NT_SUCCESS(dirStatus)) {
        DebugMessage("NetSerpent: Failed to create network directory: 0x%08X\n", dirStatus);
        return dirStatus;
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
    // First, try to load any existing network info.
    GUID networkGuid = { 0 };
    NTSTATUS netInfoStatus = LoadNetworkInfo(&networkGuid);
    if (NT_SUCCESS(netInfoStatus)) {
        DebugMessage("NetSerpent: Loaded network info successfully.\n", netInfoStatus);
        return STATUS_SUCCESS;
    }

    DebugMessage("NetSerpent: No existing network info found. Awaiting admin network connection command.\n", netInfoStatus);

    // Wait for the admin to set the network info (for example, wait up to 30 seconds).
    LARGE_INTEGER timeout;
    timeout.QuadPart = -30 * 1000 * 1000 * 10LL; // 30 seconds in 100-nanosecond intervals
    NTSTATUS waitStatus = KeWaitForSingleObject(&AdminConnectionEvent, Executive, KernelMode, FALSE, &timeout);
    if (waitStatus == STATUS_TIMEOUT) {
        DebugMessage("NetSerpent: Timeout waiting for admin network connection.\n");
        return STATUS_TIMEOUT;
    }

    // After the event is signaled, try loading the network info again.
    netInfoStatus = LoadNetworkInfo(&networkGuid);
    if (NT_SUCCESS(netInfoStatus)) {
        DebugMessage("NetSerpent: Loaded network info successfully after admin connection.\n", netInfoStatus);
        return STATUS_SUCCESS;
    }

    return STATUS_UNSUCCESSFUL;
}

