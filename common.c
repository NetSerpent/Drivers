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
    - TODO inside shows the planned “log-to-file” upgrade: look up the
      shared folder constant in *constants.h*, create / append the text
      file, then cache the file handle in a global for speed.
======================================================================*/

#include "common.h"

VOID DebugStatus(PCSTR msg, NTSTATUS status)
{
    DebugMessage("%s: 0x%08X\n", msg, status);
}

/*
Function Pseudocode
1. DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, msg, __VA_ARGS__);
2. Look for a text file in the shared directory (make this a constant somewhere) -> This uses a folder search
3. If no file, make it???
4. If there is now a file, Append the message to this text file
    - We now have the file, define a global variable that references this file. 



*/