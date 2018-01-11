// vim: set et sw=4 sts=4 cindent:
/*
 * @File: wlanifLinkEventsBSA.c
 *
 * @Abstract: Load balancing daemon link events
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


#include "wlanifLinkEvents.h"
#include "wlanifLinkEventsCmn.h"

#include "wlanif.h"
#include "wlanifPrivate.h"
#include "lb_common.h"
#include "lb_assert.h"
#include "module.h"

#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <linux/wireless.h>
#include <string.h>

#include <ieee80211_external.h>

#include <dbg.h>
#include <bufrd.h>

// ====================================================================
// Internal types
// ====================================================================

/**
 * @brief Private data for handling link events for the single AP BSS
 *        steering algorithm.
 */
struct wlanifLinkEventsBSAPriv_t {
    // "Base class" members for all common functionality
    struct wlanifLinkEventsPriv_t common;

    int netlinkSocket;
    struct bufrd readBuf;
};

typedef struct wlanifLinkEventsBSAPriv_t *wlanifLinkEventsBSAHandle_t;

// This appears to be just sufficient for the events that are currently being
// sent. It may be necessary to tweak this in the future if the kernel starts
// including more attributes for specific events (such as an interface being
// brought down).
#define RECEIVE_BUFFER_SIZE 1024

// forward decls
static void wlanifLinkEventsBSARegister(struct dbgModule *dbgModule,
                                        wlanifLinkEventsBSAHandle_t state);
static LBD_STATUS wlanifLinkEventsBSAUnregister(wlanifLinkEventsBSAHandle_t handle);
static void wlanifLinkEventsBSABufRdCB(void *cookie);

// ====================================================================
// Package level functions
// ====================================================================

wlanifLinkEventsHandle_t wlanifLinkEventsCreate(struct dbgModule *dbgModule,
                                                wlanifBSteerControlHandle_t controlHandle) {
    struct wlanifLinkEventsBSAPriv_t *state =
        calloc(1, sizeof(struct wlanifLinkEventsBSAPriv_t));
    if (!state) {
        dbgf(dbgModule, DBGERR, "%s: Failed to allocate state structure",
             __func__);
        return NULL;
    }

    wlanifLinkEventsBSARegister(dbgModule, state);
    state->common.dbgModule = dbgModule;
    state->common.bsteerControlHandle = controlHandle;

    if (-1 == state->netlinkSocket) {
        free(state);
        return NULL;
    }

    // We return a handle to the base type and convert that back to the
    // derived type when appropriate.
    return &state->common;
}

LBD_STATUS wlanifLinkEventsDestroy(wlanifLinkEventsHandle_t state) {
    LBD_STATUS result = LBD_OK;
    if (state) {
        result = wlanifLinkEventsBSAUnregister((struct wlanifLinkEventsBSAPriv_t *) state);
        free(state);
    }

    return result;
}

// ====================================================================
// Private helper functions
// ====================================================================

/**
 * @brief Create and bind the netlink socket for new link events.
 *
 * @param [in] dbgModule  the handle to use for logging
 * @param [inout] state  the internal state for this instance; upon success,
 *                       the socket and debug module members will be
 *                       initialized
 */
static void wlanifLinkEventsBSARegister(struct dbgModule *dbgModule,
                                        wlanifLinkEventsBSAHandle_t state) {
    state->netlinkSocket = socket(PF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
    if (-1 == state->netlinkSocket) {
        dbgf(dbgModule, DBGERR, "%s: Netlink socket creation failed",
             __func__);
        return;
    }

    struct sockaddr_nl addr;
    memset(&addr, 0, sizeof(addr));
    addr.nl_family = AF_NETLINK;
    addr.nl_pid = getpid();
    addr.nl_groups = RTMGRP_LINK;

    if (-1 == bind(state->netlinkSocket, (const struct sockaddr *) &addr,
                   sizeof(addr))) {
        dbgf(dbgModule, DBGERR, "%s: Failed to bind netlink socket",
             __func__);
        close(state->netlinkSocket);
        state->netlinkSocket = -1;
        return;
    }

    state->common.dbgModule = dbgModule;
    bufrdCreate(&state->readBuf, "wlanifLinkEvents-rd",
                state->netlinkSocket, RECEIVE_BUFFER_SIZE,
                wlanifLinkEventsBSABufRdCB, state);
}

/**
 * @brief Clean up the netlink socket and its registration.
 *
 * @param [in] state  the internal state for which the cleanup should occur
 *
 * @return LBD_OK if the socket was closed successfully and unregistered from
 *         the event loop; otherwise LBD_NOK
 */
static LBD_STATUS wlanifLinkEventsBSAUnregister(
        wlanifLinkEventsBSAHandle_t state) {
    LBD_STATUS result = LBD_OK;
    if (close(state->netlinkSocket) != 0) {
        dbgf(state->common.dbgModule, DBGERR, "%s: Socket close failed",
             __func__);
        result = LBD_NOK;
    }

    state->netlinkSocket = -1;

    // We will always have registered the socket if the state is valid.
    bufrdDestroy(&state->readBuf);
    return result;
}

/**
 * @brief React to the indication that the netlink socket is readable.
 *
 * @param [in] cookie  the "this" pointer provided during registration
 */
static void wlanifLinkEventsBSABufRdCB(void *cookie) {
    u_int32_t numBytes;
    const u_int8_t *msg;

    wlanifLinkEventsBSAHandle_t state = (wlanifLinkEventsBSAHandle_t) cookie;

    numBytes = bufrdNBytesGet(&state->readBuf);
    msg = bufrdBufGet(&state->readBuf);

    if (bufrdErrorGet(&state->readBuf)) {
        dbgf(state->common.dbgModule, DBGERR, "%s: Read error! # bytes=%u",
             __func__, numBytes);

        wlanifLinkEventsBSAUnregister(state);
        wlanifLinkEventsBSARegister(state->common.dbgModule, state);

        if (-1 == state->netlinkSocket) {
            dbgf(state->common.dbgModule, DBGERR,
                 "%s: Failed to recover from fatal error", __func__);
            exit(1);
        }

        return;
    }

    // bufrd will keep calling us back until no more progress is made.
    // This includes when there is no more data to be read, so we need
    // to bail out here to avoid the error below.
    if (!numBytes) {
        return;
    }

    wlanifLinkEventsCmnMsgRx(&state->common, msg, numBytes);

    bufrdConsume(&state->readBuf, numBytes);
}

void wlanifLinkEventsProcessChannelChange(
        int sysIndex, u_int8_t channel) {
}
