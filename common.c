#include "common.h"

VOID DebugStatus(PCSTR msg, NTSTATUS status)
{
    DebugMessage("%s: 0x%08X\n", msg, status);
}
