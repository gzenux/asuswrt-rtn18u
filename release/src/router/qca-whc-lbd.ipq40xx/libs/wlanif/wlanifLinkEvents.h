// vim: set et sw=4 sts=4 cindent:
/*
 * @File: wlanifLinkEvents.h
 *
 * @Abstract: Load balancing daemon band link events interface (for
 *            association/disassociation)
 *
 * @Notes: This header should not be included directly by other components
 *         within the load balancing daemon. It should be considered
 *         private to the wlanif module.
 *
 * @@-COPYRIGHT-START-@@
 *
 * Copyright (c) 2014 Qualcomm Atheros, Inc.
 * All Rights Reserved.
 * Qualcomm Atheros Confidential and Proprietary.
 *
 * @@-COPYRIGHT-END-@@
 */

#ifndef wlanifLinkEvents__h
#define wlanifLinkEvents__h

#include "lbd_types.h"  // for LBD_STATUS
#include "wlanifBSteerControl.h"

#if defined(__cplusplus)
extern "C" {
#endif

// Out of package forward decls.
struct dbgModule;

/* package API */

struct wlanifLinkEventsPriv_t;  // opaque forward declaration
typedef struct wlanifLinkEventsPriv_t * wlanifLinkEventsHandle_t;

/**
 * @brief Initialize the link events interface (for
 *        association/disassociation).
 *
 * @param [in] dbgModule  the handle to use for logging
 * @param [in] controlHandle  the handle containing system index information
 *
 * @return a handle to the state for this instance, or NULL if it could
 *         not be created
 */
wlanifLinkEventsHandle_t wlanifLinkEventsCreate(struct dbgModule *dbgModule,
                                                wlanifBSteerControlHandle_t controlHandle);

/**
 * @brief Destroy the band steering event interface.
 *
 * When this completes, no further events will be generated.
 *
 * @param [in] handle  the handle returned from wlanifLinkEventsCreate() to
 *                     destroy
 *
 * @return LBD_OK if it was successfully destroyed; otherwise LBD_NOK
 */
LBD_STATUS wlanifLinkEventsDestroy(wlanifLinkEventsHandle_t handle);

#if defined(__cplusplus)
}
#endif

#endif  // wlanifLinkEvents__h
