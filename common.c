/*======================================================================
  common.c – Tiny utility helpers shared across the kernel components
  ----------------------------------------------------------------------
   DebugStatus(...)   – Single-line wrapper that prints an NTSTATUS in
                          hex.  Use anywhere you need “msg: 0xXXXXXXXX”.
   DebugMessage(...)  – (declared in common.h) macro that funnels all
                          debug output through DbgPrintEx.

  Contributing
    - Add *stateless* debugging helpers or generally useful one-liners
      that do **not** belong to a specific subsystem.
======================================================================*/

#include "common.h"

VOID DebugStatus(PCSTR msg, NTSTATUS status)
{
    DebugMessage("%s: 0x%08X\n", msg, status);
}