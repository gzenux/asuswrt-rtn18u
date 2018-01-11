// vim: set et sw=4 sts=4 cindent:
/*
 * @File: wlanifLinkEventsCmn.h
 *
 * @Abstract: Header for utility functions for handling RTM_NEWLINK events
 *
 * @Notes:
 *
 * @@-COPYRIGHT-START-@@
 *
 * Copyright (c) 2015 Qualcomm Atheros, Inc.
 * All Rights Reserved.
 * Qualcomm Atheros Confidential and Proprietary.
 *
 * @@-COPYRIGHT-END-@@
 *
 */

#ifndef wlanifLinkEventsCmn__h
#define wlanifLinkEventsCmn__h

#include "wlanif.h"
#include "wlanifLinkEvents.h"

#include <dbg.h>

// ====================================================================
// Protected members (for use within the common functions and any
// "derived" functions that may be using this component).
// ====================================================================

struct wlanifLinkEventsPriv_t {
    struct dbgModule *dbgModule;
    // Control handle used to resolve system index
    wlanifBSteerControlHandle_t bsteerControlHandle;
};

// ====================================================================
// Protected functions
// ====================================================================

/**
 * @brief React to a netlink message being received, converting it to any
 *        events as appropriate.
 *
 * @param [in] state  the internal state for this instance
 * @param [in] msg  the message received (including the netlink header)
 * @param [in] numBytes  the total number of bytes in the message (including
 *                       the netlink header)
 */
void wlanifLinkEventsCmnMsgRx(wlanifLinkEventsHandle_t state,
                              const u_int8_t *msg, u_int32_t numBytes);

/**
 * @brief React to a link event indicating the channel has 
 *        changed, propagating as necessary
 * 
 * @param [in] sysIndex  system index for the interface on which 
 *                       the channel has changed
 * @param [in] channel  new channel on the interface
 */
void wlanifLinkEventsProcessChannelChange(int sysIndex, u_int8_t channel);

#endif  /* wlanifLinkEventsCmn__h */
