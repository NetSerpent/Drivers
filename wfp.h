#pragma once
#ifndef WFP_H
#define WFP_H

#include "common.h"

// Function declarations related to WFP and driver initialization
NTSTATUS WfpOpenEngine(void);
NTSTATUS WfpRegisterCallout(void);
NTSTATUS WfpAddCallout(void);
NTSTATUS WfpAddSublayer(void);
NTSTATUS WfpAddFilter(void);
NTSTATUS InitializeWfp(void);
VOID UnInitWfp(void);

#endif // WFP_H
