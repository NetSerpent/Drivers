// dns_helper.h
#pragma once
#include "common.h"

#ifdef __cplusplus
extern "C" {
#endif

BOOLEAN IsDnsByMetadata(
    const FWPS_INCOMING_VALUES0* Values,
    const FWPS_FILTER3*          Filter // kept for future use
);

#ifdef __cplusplus
}
#endif
