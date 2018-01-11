// vim: set et sw=4 sts=4 cindent:
/*
 * @File: wlanifBSteerEvents.c
 *
 * @Abstract: Load balancing daemon band steering events
 *
 * @Notes:
 *
 * @@-COPYRIGHT-START-@@
 *
 * Copyright (c) 2014 Qualcomm Atheros, Inc.
 * All Rights Reserved.
 * Qualcomm Atheros Confidential and Proprietary.
 *
 * @@-COPYRIGHT-END-@@
 *
 */


#include "wlanifBSteerEvents.h"

#include "wlanif.h"
#include "wlanifPrivate.h"
#include "lb_common.h"
#include "module.h"
#include "lb_assert.h"

#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <linux/netlink.h>
#include <string.h>

#include <dbg.h>
#include <bufrd.h>

#include <diaglog.h>

#include <ieee80211_band_steering_api.h>

// forward decls
static void wlanifBSteerEventsRegister(struct dbgModule *dbgModule,
                                       wlanifBSteerEventsHandle_t state);
static LBD_STATUS wlanifBSteerEventsUnregister(
        wlanifBSteerEventsHandle_t handle);
static void wlanifBSteerEventsBufRdCB(void *cookie);

// ====================================================================
// Internal types
// ====================================================================

struct wlanifBSteerEventsPriv_t {
    int netlinkSocket;
    int eventsEnabled;
    struct bufrd readBuf;

    /// This debug module is for all events other than probe requests
    /// (which happen too frequently to be lumped together).
    struct dbgModule *dbgModule;

    /// This debug module is only for probe requests, which happen
    /// quite frequently and that we want to suppress in many cases.
    struct dbgModule *probeDbgModule;

    /// Control handle to callback with RSSI measurement
    wlanifBSteerControlHandle_t bsteerControlHandle;

    /// STA stats callback related information
    /// Should only be used by estimator
    wlanif_staStatsObserverCB staStatsCallback;
    void *staStatsCookie;
};

// ====================================================================
// Package level functions
// ====================================================================

wlanifBSteerEventsHandle_t wlanifBSteerEventsCreate(struct dbgModule *dbgModule,
                                                    wlanifBSteerControlHandle_t controlHandle) {
    struct wlanifBSteerEventsPriv_t *state =
        calloc(1, sizeof(struct wlanifBSteerEventsPriv_t));
    if (!state) {
        dbgf(dbgModule, DBGERR, "%s: Failed to allocate state structure",
             __func__);
        return NULL;
    }

    state->bsteerControlHandle = controlHandle;
    wlanifBSteerEventsRegister(dbgModule, state);

    if (-1 == state->netlinkSocket) {
        free(state);
        state = NULL;
    } else {
        state->probeDbgModule = dbgModuleFind("probe");
    }

    return state;
}

LBD_STATUS wlanifBSteerEventsEnable(wlanifBSteerEventsHandle_t state, u_int32_t sysIndex) {
    struct sockaddr_nl destAddr;
    memset(&destAddr, 0, sizeof(destAddr));
    destAddr.nl_family = AF_NETLINK;
    destAddr.nl_pid = 0;
    destAddr.nl_groups = 0;

    struct nlmsghdr hdr;
    hdr.nlmsg_len = NLMSG_SPACE(0);
    hdr.nlmsg_flags = sysIndex;
    hdr.nlmsg_type = 0;
    hdr.nlmsg_pid = getpid();

    if (sendto(state->netlinkSocket, &hdr, hdr.nlmsg_len, 0,
               (const struct sockaddr *) &destAddr, sizeof(destAddr)) < 0) {
        dbgf(state->dbgModule, DBGERR, "%s: Failed to send netlink trigger",
             __func__);
        return LBD_NOK;
    }

    // Remember that eventing was enabled in case we need to reenable it
    // after a fatal socket error.
    state->eventsEnabled = 1;
    return LBD_OK;
}

LBD_STATUS wlanifBSteerEventsDestroy(wlanifBSteerEventsHandle_t state) {
    LBD_STATUS result = LBD_OK;
    if (state) {
        result = wlanifBSteerEventsUnregister(state);
        free(state);
    }

    return result;
}

LBD_STATUS wlanifBSteerEventsRegisterSTAStatsObserver(
    wlanifBSteerEventsHandle_t state, wlanif_staStatsObserverCB callback,
    void *cookie) {

    if (!state || !callback) {
        return LBD_NOK;
    }

    if (state->staStatsCallback) {
        // Don't allow more than one callback to be installed
        dbgf(state->dbgModule, DBGERR, "%s: STA stats callback already installed "
             "(func %p, cookie %p)",
             __func__, state->staStatsCallback, state->staStatsCookie);
        return LBD_NOK;
    }

    state->staStatsCallback = callback;
    state->staStatsCookie = cookie;
    return LBD_OK;
}

LBD_STATUS wlanifBSteerEventsUnregisterSTAStatsObserver(
    wlanifBSteerEventsHandle_t state, wlanif_staStatsObserverCB callback,
    void *cookie) {
    if (!state || !callback) {
        return LBD_NOK;
    }

    if (state->staStatsCallback != callback ||
        state->staStatsCookie != cookie) {
        // Trying to unregister a different callback
        return LBD_NOK;
    }

    state->staStatsCallback = NULL;
    state->staStatsCookie = NULL;

    // Unregister successful
    return LBD_OK;
}

// ====================================================================
// Private helper functions
// ====================================================================

/**
 * @brief Create and bind the netlink socket for band steering events.
 *
 * @param [in] dbgModule  the handle to use for logging
 * @param [inout] state  the internal state for this instance; upon success,
 *                       the socket and debug module members will be
 *                       initialized
 */
static void wlanifBSteerEventsRegister(struct dbgModule *dbgModule,
                                       wlanifBSteerEventsHandle_t state) {
    state->netlinkSocket = socket(PF_NETLINK, SOCK_RAW,
                                  NETLINK_BAND_STEERING_EVENT);
    if (-1 == state->netlinkSocket) {
        dbgf(dbgModule, DBGERR, "%s: Netlink socket creation failed",
             __func__);
        return;
    }

    struct sockaddr_nl addr;
    memset(&addr, 0, sizeof(addr));
    addr.nl_family = AF_NETLINK;
    addr.nl_pid = getpid();
    addr.nl_groups = 0;  // using unicast for now

    if (-1 == bind(state->netlinkSocket, (const struct sockaddr *) &addr,
                   sizeof(addr))) {
        dbgf(dbgModule, DBGERR, "%s: Failed to bind netlink socket",
             __func__);
        close(state->netlinkSocket);
        state->netlinkSocket = -1;
        return;
    }

    state->dbgModule = dbgModule;

    u_int32_t bufferSize = NLMSG_SPACE(sizeof(struct nlmsghdr) +
                                       sizeof(struct ath_netlink_bsteering_event));

    bufrdCreate(&state->readBuf, "wlanifBSteerEvents-rd",
                state->netlinkSocket, bufferSize,
                wlanifBSteerEventsBufRdCB, state);
}

/**
 * @brief Clean up the netlink socket and its registration.
 *
 * @param [in] state  the internal state for which the cleanup should occur
 *
 * @return LBD_OK if the socket was closed successfully and unregistered from
 *         the event loop; otherwise LBD_NOK
 */
static LBD_STATUS wlanifBSteerEventsUnregister(
        wlanifBSteerEventsHandle_t state) {
    LBD_STATUS result = LBD_OK;
    if (close(state->netlinkSocket) != 0) {
        dbgf(state->dbgModule, DBGERR, "%s: Socket close failed",
             __func__);
        result = LBD_NOK;
    }

    state->netlinkSocket = -1;
    state->eventsEnabled = 0;

    // We will always have registered the socket if the state is valid.
    bufrdDestroy(&state->readBuf);
    return result;
}

/**
 * @brief React to an indication from the driver that a probe request was
 *        received from a specific client.
 *
 * @param [in] state  the "this" pointer
 * @param [in] event  the data sent from the kernel
 * @param [in] bss BSS the event was received from
 */
static void wlanifBSteerEventsHandleProbeReqInd(
        wlanifBSteerEventsHandle_t state,
        const ath_netlink_bsteering_event_t *event,
        const lbd_bssInfo_t *bss) {
    wlanif_probeReqEvent_t probeEvent;

    dbgf(state->probeDbgModule, DBGDUMP,
         "%s: Probe request from " lbMACAddFmt(":")
         ": RSSI %2u " lbBSSInfoAddFmt(),
         __func__, lbMACAddData(event->data.bs_probe.sender_addr),
         event->data.bs_probe.rssi, lbBSSInfoAddData(bss));

    lbCopyMACAddr(event->data.bs_probe.sender_addr,
                  probeEvent.sta_addr.ether_addr_octet);

    lbCopyBSSInfo(bss, &probeEvent.bss);

    probeEvent.rssi = event->data.bs_probe.rssi;

    mdCreateEvent(mdModuleID_WlanIF, mdEventPriority_High,
                  wlanif_event_probereq, &probeEvent, sizeof(probeEvent));
}

/**
 * @brief React to an indication from the driver that a specific client was
 *        associated on the provided band.
 *
 * @param [in] state  the "this" pointer
 * @param [in] event  the data sent from the kernel
 * @param [in] bss BSS the event was received from
 */
static void wlanifBSteerEventsHandleNodeAssociatedInd(
        wlanifBSteerEventsHandle_t state,
        const ath_netlink_bsteering_event_t *event,
        const lbd_bssInfo_t *bss) {
    wlanif_assocEvent_t assocEvent;

    dbgf(state->dbgModule, DBGINFO,
         "%s: Node " lbMACAddFmt(":") " associated on " lbBSSInfoAddFmt() ", Capabilities: %s %s %s %s, "
         "Max bandwidth: %u, Num of spatial streams: %u, PHY mode: %u, Max MCS: %u. Max TX power: %u",
         __func__, lbMACAddData(event->data.bs_node_associated.client_addr),
         lbBSSInfoAddData(bss),
         event->data.bs_node_associated.isBTMSupported ? "BTM" : "",
         event->data.bs_node_associated.isRRMSupported ? "RRM" : "",
         event->data.bs_node_associated.datarate_info.is_mu_mimo_supported ? "MU" : "",
         event->data.bs_node_associated.datarate_info.is_static_smps ? "SMPS" : "",
         event->data.bs_node_associated.datarate_info.max_chwidth,
         event->data.bs_node_associated.datarate_info.num_streams,
         event->data.bs_node_associated.datarate_info.phymode,
         event->data.bs_node_associated.datarate_info.max_MCS,
         event->data.bs_node_associated.datarate_info.max_txpower);

    lbCopyBSSInfo(bss, &assocEvent.bss);

    lbCopyMACAddr(event->data.bs_node_associated.client_addr,
                  assocEvent.sta_addr.ether_addr_octet);
    assocEvent.btmStatus =
        event->data.bs_node_associated.isBTMSupported ? wlanif_cap_enabled :
                                                        wlanif_cap_disabled;
    assocEvent.rrmStatus =
        event->data.bs_node_associated.isRRMSupported ? wlanif_cap_enabled :
                                                        wlanif_cap_disabled;
    assocEvent.isMUMIMOSupported =
        (LBD_BOOL)(event->data.bs_node_associated.datarate_info.is_mu_mimo_supported);

    assocEvent.isStaticSMPS =
        (LBD_BOOL)(event->data.bs_node_associated.datarate_info.is_static_smps);
    assocEvent.phyCapInfo.valid = LBD_TRUE;
    assocEvent.phyCapInfo.maxChWidth =
        wlanifMapToBandwidth(state->dbgModule,
                             event->data.bs_node_associated.datarate_info.max_chwidth);
    assocEvent.phyCapInfo.numStreams = event->data.bs_node_associated.datarate_info.num_streams;
    assocEvent.phyCapInfo.phyMode =
        wlanifMapToPhyMode(state->dbgModule,
                           event->data.bs_node_associated.datarate_info.phymode);
    assocEvent.phyCapInfo.maxMCS = event->data.bs_node_associated.datarate_info.max_MCS;
    assocEvent.phyCapInfo.maxTxPower = event->data.bs_node_associated.datarate_info.max_txpower;

    mdCreateEvent(mdModuleID_WlanIF, mdEventPriority_Low,
                  wlanif_event_assoc, &assocEvent, sizeof(assocEvent));
}

/**
 * @brief React to an indication from the driver that it sent an
 *        authentication message with a failure code due to an ACL match.
 *
 * @param [in] state  the "this" pointer
 * @param [in] event  the data sent from the kernel
 * @param [in] bss BSS the event was received from
 */
static void wlanifBSteerEventsHandleTxAuthFailInd(
        wlanifBSteerEventsHandle_t state,
        const ath_netlink_bsteering_event_t *event,
        const lbd_bssInfo_t *bss) {
    dbgf(state->dbgModule, DBGDEBUG,
         "%s: Tx'ed Auth reject to " lbMACAddFmt(":")
         ": RSSI %2u " lbBSSInfoAddFmt(),
         __func__, lbMACAddData(event->data.bs_auth.client_addr),
         event->data.bs_auth.rssi, lbBSSInfoAddData(bss));

    wlanif_authRejEvent_t authEvent;

    lbCopyBSSInfo(bss, &authEvent.bss);
    lbCopyMACAddr(event->data.bs_auth.client_addr,
                  authEvent.sta_addr.ether_addr_octet);

    authEvent.rssi = event->data.bs_auth.rssi;

    mdCreateEvent(mdModuleID_WlanIF, mdEventPriority_High,
                  wlanif_event_authrej, &authEvent, sizeof(authEvent));
}

/**
 * @brief React to an indication from the driver that it sent an
 *        authentication allow message due to an Auth_allow flag set.
 *
 * @param [in] state  the "this" pointer
 * @param [in] event  the data sent from the kernel
 * @param [in] bss BSS the event was received from
 */
static void wlanifBSteerEventsHandleTxAuthAllowInd(
        wlanifBSteerEventsHandle_t state,
        const ath_netlink_bsteering_event_t *event,
        const lbd_bssInfo_t *bss) {
    dbgf(state->dbgModule, DBGDEBUG,
            "%s: Tx Auth allowed due to authentication allow flag set " lbMACAddFmt(":")
            ": RSSI %2u " lbBSSInfoAddFmt(),
            __func__, lbMACAddData(event->data.bs_auth.client_addr),
            event->data.bs_auth.rssi, lbBSSInfoAddData(bss));
}

/**
 * @brief React to an indication from the driver that a specific client's
 *        activity status has changed.
 *
 * @param [in] state  the "this" pointer
 * @param [in] event  the data sent from the kernel
 * @param [in] bss BSS the event was received from
 */
static void wlanifBSteerEventsHandleActivityChange(
        wlanifBSteerEventsHandle_t state,
        const ath_netlink_bsteering_event_t *event,
        const lbd_bssInfo_t *bss) {
    dbgf(state->dbgModule, DBGDEBUG,
         "%s: " lbMACAddFmt(":") " activity status changes to %s " lbBSSInfoAddFmt(),
         __func__, lbMACAddData(event->data.bs_activity_change.client_addr),
         event->data.bs_activity_change.activity ? "ACTIVE" : "INACTIVE",
         lbBSSInfoAddData(bss));

    wlanif_actChangeEvent_t actChangeEvent;
    lbCopyMACAddr(event->data.bs_activity_change.client_addr,
                  actChangeEvent.sta_addr.ether_addr_octet);

    lbCopyBSSInfo(bss, &actChangeEvent.bss);
    actChangeEvent.active = event->data.bs_activity_change.activity ? LBD_TRUE : LBD_FALSE;

    // Transition to active is high priority event since we would want to cancel
    // any steering that is in process. Transition to inactive is not high priority.
    mdCreateEvent(mdModuleID_WlanIF,
                  actChangeEvent.active ? mdEventPriority_High : mdEventPriority_Low,
                  wlanif_event_act_change, &actChangeEvent, sizeof(actChangeEvent));
}

/**
 * @brief React to an indication from the driver that a specific client's
 *        RSSI measurement has crossed threshold(s).
 *
 * @param [in] state  the "this" pointer
 * @param [in] event  the data sent from the kernel
 * @param [in] bss BSS the event was received from
 */
static void wlanifBSteerEventsHandleRSSIXingInd(
        wlanifBSteerEventsHandle_t state,
        const ath_netlink_bsteering_event_t *event,
        const lbd_bssInfo_t *bss) {
    dbgf(state->dbgModule, DBGDEBUG,
         "%s: " lbMACAddFmt(":") " RSSI measurement %u on " lbBSSInfoAddFmt() "; "
         "Inactivity threshold xing: %u; Low threshold xing: %u; Rate threshold xing: %u; "
         "AP steering threshold xing: %u",
         __func__, lbMACAddData(event->data.bs_rssi_xing.client_addr),
         event->data.bs_rssi_xing.rssi, lbBSSInfoAddData(bss),
         event->data.bs_rssi_xing.inact_rssi_xing,
         event->data.bs_rssi_xing.low_rssi_xing,
         event->data.bs_rssi_xing.rate_rssi_xing,
         event->data.bs_rssi_xing.ap_rssi_xing);

    wlanif_rssiXingEvent_t rssiXingEvent;
    lbCopyMACAddr(event->data.bs_rssi_xing.client_addr,
                  rssiXingEvent.sta_addr.ether_addr_octet);

    lbCopyBSSInfo(bss, &rssiXingEvent.bss);

    rssiXingEvent.rssi = event->data.bs_rssi_xing.rssi;
    rssiXingEvent.inactRSSIXing = wlanifMapToXingDirection(state->dbgModule, event->data.bs_rssi_xing.inact_rssi_xing);
    rssiXingEvent.lowRSSIXing = wlanifMapToXingDirection(state->dbgModule, event->data.bs_rssi_xing.low_rssi_xing);
    rssiXingEvent.rateRSSIXing = wlanifMapToXingDirection(state->dbgModule, event->data.bs_rssi_xing.rate_rssi_xing);
    rssiXingEvent.apRSSIXing = wlanifMapToXingDirection(state->dbgModule, event->data.bs_rssi_xing.ap_rssi_xing);

    mdCreateEvent(mdModuleID_WlanIF, mdEventPriority_Low,
                  wlanif_event_rssi_xing, &rssiXingEvent, sizeof(rssiXingEvent));
}

/**
 * @brief React to an indication from the driver that a specific
 *        client's Tx rate has crossed a threshold.
 *
 * @param [in] state  the "this" pointer
 * @param [in] event  the data sent from the kernel
 * @param [in] bss BSS the event was received from
 */
static void wlanifBSteerEventsHandleTxRateXingInd(
        wlanifBSteerEventsHandle_t state,
        const ath_netlink_bsteering_event_t *event,
        const lbd_bssInfo_t *bss) {
    dbgf(state->dbgModule, DBGDEBUG,
         "%s: " lbMACAddFmt(":") " Tx rate measurement %u on " lbBSSInfoAddFmt() "; "
         "Xing direction: %u",
         __func__, lbMACAddData(event->data.bs_tx_rate_xing.client_addr),
         event->data.bs_tx_rate_xing.tx_rate,
         lbBSSInfoAddData(bss),
         event->data.bs_tx_rate_xing.xing);

    wlanif_txRateXingEvent_t txRateXingEvent;
    lbCopyMACAddr(event->data.bs_tx_rate_xing.client_addr,
                  txRateXingEvent.sta_addr.ether_addr_octet);

    lbCopyBSSInfo(bss, &txRateXingEvent.bss);

    txRateXingEvent.tx_rate = event->data.bs_tx_rate_xing.tx_rate;
    txRateXingEvent.xing = wlanifMapToXingDirection(state->dbgModule,
                                                    event->data.bs_tx_rate_xing.xing);

    mdCreateEvent(mdModuleID_WlanIF, mdEventPriority_Low,
                  wlanif_event_tx_rate_xing, &txRateXingEvent, sizeof(txRateXingEvent));
}

/**
 * @brief React to an indication from the driver that a VAP has
 *        stopped (this is treated the same as when a VAP is
 *        brought down).
 *
 * @param [in] state  the "this" pointer
 * @param [in] event  the data sent from the kernel
 * @param [in] bss BSS the event was received from
 */
static void wlanifBSteerEventsHandleVAPStop(
        wlanifBSteerEventsHandle_t state,
        const ath_netlink_bsteering_event_t *event,
        const lbd_bssInfo_t *bss) {

    LBD_BOOL changed = LBD_FALSE;
    wlanifBSteerControlUpdateLinkState(state->bsteerControlHandle,
                                       event->sys_index,
                                       LBD_FALSE /* ifaceUp */, &changed);
    if (changed) {
        dbgf(state->dbgModule, DBGINFO,
             "%s: Interface " lbBSSInfoAddFmt() " stopped",
             __func__, lbBSSInfoAddData(bss));

        if (wlanifBSteerControlRestartChannelUtilizationMonitoring(
            state->bsteerControlHandle) != LBD_OK) {
            dbgf(state->dbgModule, DBGERR,
                 "%s: Failed to restart utilization monitoring; "
                 "measurements may be out of sync", __func__);
            exit(1);
        }

        wlanif_band_e band = wlanif_resolveBandFromChannelNumber(bss->channelId);
        lbDbgAssertExit(state->dbgModule, band != wlanif_band_invalid);

        wlanif_vapRestartEvent_t vapRestartEvent;
        vapRestartEvent.band = band;

        mdCreateEvent(mdModuleID_WlanIF, mdEventPriority_High,
                      wlanif_event_vap_restart,
                      &vapRestartEvent, sizeof(vapRestartEvent));
    }
}

/**
 * @brief React to an indication from the driver that a specific client's
 *        requested RSSI measurement is available.
 *
 * @param [in] state  the "this" pointer
 * @param [in] event  the data sent from the kernel
 * @param [in] bss BSS the event was received from
 * @param [in] isRawMeasurement  LBD_TRUE if the measurement is a raw one
 *                               (only suited for logging); otherwise LBD_FALSE
 */
static void wlanifBSteerEventsHandleRSSIMeasurementInd(
        wlanifBSteerEventsHandle_t state,
        const ath_netlink_bsteering_event_t *event,
        const lbd_bssInfo_t *bss,
        LBD_BOOL isRawMeasurement) {
    dbgf(state->dbgModule, isRawMeasurement ? DBGDUMP : DBGDEBUG,
         "%s: " lbMACAddFmt(":") " RSSI measurement %u on " lbBSSInfoAddFmt(),
         __func__, lbMACAddData(event->data.bs_rssi_measurement.client_addr),
         event->data.bs_rssi_measurement.rssi, lbBSSInfoAddData(bss));

    wlanif_rssiMeasurementEvent_t rssiMeasurementEvent;
    lbCopyBSSInfo(bss, &rssiMeasurementEvent.bss);
    lbCopyMACAddr(event->data.bs_rssi_measurement.client_addr,
                  rssiMeasurementEvent.sta_addr.ether_addr_octet);
    rssiMeasurementEvent.rssi = wlanifMapToRSSIMeasurement(event->data.bs_rssi_measurement.rssi);

    if (isRawMeasurement) {
        if (diaglog_startEntry(mdModuleID_WlanIF, wlanif_msgId_rawRSSI,
                               diaglog_level_debug)) {
            diaglog_writeMAC(&rssiMeasurementEvent.sta_addr);
            diaglog_writeBSSInfo(&rssiMeasurementEvent.bss);
            diaglog_write8(rssiMeasurementEvent.rssi);
            diaglog_finishEntry();
        }
        return;
    }

    wlanifBSteerControlHandleRSSIMeasurement(
            state->bsteerControlHandle,
            bss, &rssiMeasurementEvent.sta_addr);

    mdCreateEvent(mdModuleID_WlanIF, mdEventPriority_High,
                  wlanif_event_rssi_measurement, &rssiMeasurementEvent,
                  sizeof(rssiMeasurementEvent));

}

/**
 * @brief React to an indication from the driver that the Tx
 *        rate to a client has changed.
 *
 * @param [in] state  the "this" pointer
 * @param [in] event  the data sent from the kernel
 * @param [in] bss BSS the event was received from
 */
static void wlanifBSteerEventsHandleTxRateMeasurementInd(
        wlanifBSteerEventsHandle_t state,
        const ath_netlink_bsteering_event_t *event,
        const lbd_bssInfo_t *bss) {
    dbgf(state->dbgModule, DBGDUMP,
         "%s: " lbMACAddFmt(":") " TxRate measurement %u on " lbBSSInfoAddFmt(),
         __func__, lbMACAddData(event->data.bs_rssi_measurement.client_addr),
         event->data.bs_tx_rate_measurement.tx_rate, lbBSSInfoAddData(bss));
}

/**
 * @brief React to an indication from the driver that the channel utilization
 *        has been measured.
 *
 * @param [in] state  the "this" pointer
 * @param [in] event  the data sent from the kernel
 * @param [in] bss BSS the event was received from
 * @param [in] isRawMeasurement  LBD_TRUE if the measurement is a raw one
 *                               (only suited for logging); otherwise LBD_FALSE
 */
static void wlanifBSteerEventsHandleChanUtilInd(
        wlanifBSteerEventsHandle_t state,
        const ath_netlink_bsteering_event_t *event,
        const lbd_bssInfo_t *bss,
        LBD_BOOL isRawMeasurement) {
    enum dbgLevel level = isRawMeasurement ? DBGDUMP : DBGDEBUG;
    dbgf(state->dbgModule, level, "%s: Channel utilization %2u%% on " lbBSSInfoAddFmt(),
         __func__, event->data.bs_chan_util.utilization, lbBSSInfoAddData(bss));

    wlanif_chanUtilEvent_t chanUtilEvent;
    lbCopyBSSInfo(bss, &chanUtilEvent.bss);
    chanUtilEvent.utilization = event->data.bs_chan_util.utilization;

    if (!isRawMeasurement) {
        // For now we leave the utilization as a low priority event, as at most
        // it will trigger a switch to overload mode and institute
        // pre-association steering. Since it takes many minutes before we get
        // the utilization measurements (using the default settings), it does
        // not matter if it takes a bit longer.
        mdCreateEvent(mdModuleID_WlanIF, mdEventPriority_Low,
                      wlanif_event_chan_util, &chanUtilEvent,
                      sizeof(chanUtilEvent));
    }

    if (isRawMeasurement &&
        diaglog_startEntry(mdModuleID_WlanIF, wlanif_msgId_rawChanUtilization,
                           diaglog_level_debug)) {
        diaglog_write8(bss->channelId);
        diaglog_write8(chanUtilEvent.utilization);
        diaglog_finishEntry();
    }
}

/**
 * @brief Handle the 802.11k beacon report received from driver
 *
 * @param [in] state  the "this" pointer
 * @param [in] receivingBss  the BSS from which the report is
 *                           received
 * @param [in] report  the beacon report received
 */
static void wlanifBSteerEventsHandleBeaconReport(
        wlanifBSteerEventsHandle_t state,
        const lbd_bssInfo_t *receivingBss,
        const struct bs_rrm_report_ind *report) {
    wlanif_beaconReportEvent_t bcnrptEvent = {0};
    LBD_BOOL generateEvent = LBD_FALSE;
    LBD_BOOL foundInvalidBSSID = LBD_FALSE;

    lbCopyMACAddr(report->macaddr, bcnrptEvent.sta_addr.ether_addr_octet);
    if (report->measrpt_mode != IEEE80211_RRM_MEASRPT_MODE_SUCCESS) {
        bcnrptEvent.valid = LBD_FALSE;
        generateEvent = LBD_TRUE;
    } else {
        int i = 0;
        bcnrptEvent.valid = LBD_TRUE;
        while (i < IEEE80211_BSTEERING_RRM_NUM_BCNRPT_MAX) {
            const ieee80211_bcnrpt_t *bcnrpt = &report->data.bcnrpt[i];
            lbd_bssInfo_t reportedBss = {0};
            // Get the BSS info for the report
            if (wlanifBSteerControlGetBSSInfoFromBSSID(
                        state->bsteerControlHandle,
                        receivingBss->essId, bcnrpt->bssid,
                        &reportedBss) == LBD_OK) {
                // Check the ESSID and channel number match
                // However, a mismatch is considered a soft error (some STAs send an
                // incorrect channel number), so print a warning, but treat the
                // response as valid anyway
                if (reportedBss.essId != receivingBss->essId) {
                    dbgf(state->dbgModule, DBGINFO,
                         "%s: Warning: beacon report event reports a BSS " lbBSSInfoAddFmt()
                         " not on the serving ESS (%d)", __func__,
                         lbBSSInfoAddData(&reportedBss),
                         receivingBss->essId);
                }
                if (reportedBss.channelId != bcnrpt->chnum) {
                    dbgf(state->dbgModule, DBGINFO,
                         "%s: Warning: beacon report event channel number %d"
                         " does not match BSS " lbBSSInfoAddFmt()
                         " identified by BSSID " lbMACAddFmt(":"),
                         __func__, bcnrpt->chnum,
                         lbBSSInfoAddData(&reportedBss),
                         lbMACAddData(bcnrpt->bssid));
                }

                dbgf(state->dbgModule, DBGINFO, "%s: Beacon report from " lbMACAddFmt(":")
                     ": " lbBSSInfoAddFmt() " rcpi: %d", __func__,
                     lbMACAddData(bcnrptEvent.sta_addr.ether_addr_octet),
                     lbBSSInfoAddData(&reportedBss), (int8_t)bcnrpt->rcpi);

                if (diaglog_startEntry(mdModuleID_WlanIF, wlanif_msgId_beaconReport,
                                       diaglog_level_demo)) {
                    diaglog_writeMAC(&bcnrptEvent.sta_addr);
                    diaglog_writeBSSInfo(&reportedBss);
                    diaglog_write8(bcnrpt->rcpi);
                    diaglog_finishEntry();
                }

                bcnrptEvent.reportedBcnrptInfo[bcnrptEvent.numBcnrpt].rcpi = bcnrpt->rcpi;
                lbCopyBSSInfo(&reportedBss,
                              &bcnrptEvent.reportedBcnrptInfo[bcnrptEvent.numBcnrpt].reportedBss);
                ++bcnrptEvent.numBcnrpt;
                generateEvent = LBD_TRUE;
            } else {
                // If no valid beacon report is found (that matches any of
                // the local BSSes), still report that
                // there was an invalid report received.
                dbgf(state->dbgModule, DBGINFO,
                     "%s: Beacon report BSSID " lbMACAddFmt(":")
                     " doesn't match any BSS",
                     __func__, lbMACAddData(bcnrpt->bssid));
                foundInvalidBSSID = LBD_TRUE;
            }
            if (!bcnrpt->more) {
                break;
            }
            ++i;
        }
    }

    if (!generateEvent && foundInvalidBSSID) {
        // No valid report found, still notify anyone waiting for this event.
        bcnrptEvent.valid = LBD_FALSE;
        generateEvent = LBD_TRUE;
    }
    if (generateEvent) {
        mdCreateEvent(mdModuleID_WlanIF, mdEventPriority_Low,
                      wlanif_event_beacon_report, &bcnrptEvent,
                      sizeof(bcnrptEvent));
    }
}

/**
 * @brief React to an indication from the driver that an 802.11k radio
 *        resource measurement report has been received.
 *
 * @param [in] state  the "this" pointer
 * @param [in] event  the data sent from the kernel
 * @param [in] bss BSS the event was received from
 */
static void wlanifBSteerEventsHandleRRMReportInd(
        wlanifBSteerEventsHandle_t state,
        const ath_netlink_bsteering_event_t *event,
        const lbd_bssInfo_t *bss) {
    const struct bs_rrm_report_ind *report = &event->data.rrm_report;
    switch (report->rrm_type) {
        case BSTEERING_RRM_TYPE_BCNRPT:
            wlanifBSteerEventsHandleBeaconReport(state, bss, report);
            break;
        default:
            dbgf(state->dbgModule, DBGINFO, "%s: Unhandled RRM msg: type %u",
                 __func__, report->rrm_type);
            return;
    }
}

/**
 * @brief React to an indication from the driver that it
 *        received a WNM event.
 *
 * @param [in] state  the "this" pointer
 * @param [in] event  the data sent from the kernel
 * @param [in] bss BSS the event was received from
 */
static void wlanifBSteerEventsHandleWNMEvent(
        wlanifBSteerEventsHandle_t state,
        const ath_netlink_bsteering_event_t *event,
        const lbd_bssInfo_t *bss) {

    switch (event->data.wnm_event.wnm_type) {
        case BSTEERING_WNM_TYPE_BSTM_RESPONSE:
            dbgf(state->dbgModule, DBGDEBUG,
                 "%s: Received BTM Response from " lbMACAddFmt(":")
                 ": Dialog Token: %u, Status: %u, BSS termination delay: %u, Target BSSID " lbMACAddFmt(":"),
                 __func__, lbMACAddData(event->data.wnm_event.macaddr),
                 event->data.wnm_event.dialog_token,
                 event->data.wnm_event.data.bstm_resp.status,
                 event->data.wnm_event.data.bstm_resp.termination_delay,
                 lbMACAddData(event->data.wnm_event.data.bstm_resp.target_bssid));

            wlanif_btmResponseEvent_t resp;
            resp.dialog_token = event->data.wnm_event.dialog_token;
            lbCopyMACAddr(event->data.wnm_event.macaddr,
                          resp.sta_addr.ether_addr_octet);
            resp.status = event->data.wnm_event.data.bstm_resp.status;
            resp.termination_delay = event->data.wnm_event.data.bstm_resp.termination_delay;
            lbCopyMACAddr(event->data.wnm_event.data.bstm_resp.target_bssid,
                          resp.target_bssid.ether_addr_octet);

            mdCreateEvent(mdModuleID_WlanIF, mdEventPriority_High,
                          wlanif_event_btm_response, &resp, sizeof(resp));
            break;
        default:
            dbgf(state->dbgModule, DBGINFO, "%s: Unhandled WNM msg from " lbMACAddFmt(":")
                 ": type %u, Dialog Token %u",
                 __func__, lbMACAddData(event->data.wnm_event.macaddr),
                 event->data.wnm_event.wnm_type, event->data.wnm_event.dialog_token);
            break;
    }
}

/**
 * @brief React to an indication from the driver that Tx power
 *        changes on the VAP
 *
 * @param [in] state  the "this" pointer
 * @param [in] event  the data sent from the kernel
 * @param [in] bss  BSS the event was received from
 */
static void wlanifBSteerEventsHandleTxPowerChangeInd(
        wlanifBSteerEventsHandle_t state,
        const ath_netlink_bsteering_event_t *event,
        const lbd_bssInfo_t *bss) {
    wlanifBSteerControlUpdateMaxTxPower(state->bsteerControlHandle, bss,
                                        event->data.bs_tx_power_change.tx_power);
}

/**
 * @brief React to an indication from the driver that new STA
 *        stats are ready
 *
 * @param [in] state  the "this" pointer
 * @param [in] event  the data sent from the kernel
 * @param [in] bss  BSS the event was received from
 */
static void wlanifBSteerEventsHandleSTAStatsInd(
    wlanifBSteerEventsHandle_t state,
    const ath_netlink_bsteering_event_t *event,
    const lbd_bssInfo_t *bss) {
    size_t i;
    struct bs_sta_stats_ind *stats = (struct bs_sta_stats_ind *)&event->data.bs_sta_stats;

    if (!stats->peer_count || stats->peer_count > BSTEERING_MAX_PEERS_PER_EVENT) {
        dbgf(state->dbgModule, DBGERR, "%s: Invalid peer count %u in STA stats event "
             "from BSS " lbBSSInfoAddFmt(),
             __func__, stats->peer_count, lbBSSInfoAddData(bss));
        return;
    }

    for (i = 0; i < stats->peer_count; i++) {
        struct bs_sta_stats_per_peer *peer = &stats->peer_stats[i];

        dbgf(state->dbgModule, DBGDUMP, "%s: Updated stats for STA " lbMACAddFmt(":")
             " on " lbBSSInfoAddFmt() " Tx bytes: %llu, Rx bytes: %llu, Tx packets: %u, "
             "Rx packets: %u, Tx rate: %u, RSSI: %u, PER: %u",
             __func__, lbMACAddData(peer->client_addr),
             lbBSSInfoAddData(bss), peer->tx_byte_count,
             peer->rx_byte_count, peer->tx_packet_count, peer->rx_packet_count,
             peer->tx_rate, peer->rssi, peer->per);

        if (state->staStatsCallback) {
            wlanif_staStats_t stats;
            stats.txByteCount = peer->tx_byte_count;
            stats.rxByteCount = peer->rx_byte_count;
            stats.txPacketCount = peer->tx_packet_count;
            stats.rxPacketCount = peer->rx_packet_count;
            // Convert from Kbps to Mbps to be used within LBD
            // Divide by 1000 to be consistent with 'wlanconfig' behavior,
            // which is used to collect the data for training purposes.
            stats.txRate = peer->tx_rate / 1000;
            stats.rssi = peer->rssi;
            stats.per = peer->per;

            struct ether_addr addr;
            lbCopyMACAddr(peer->client_addr, addr.ether_addr_octet);

            state->staStatsCallback(&addr, bss, &stats,
                                    state->staStatsCookie);
        }
    }
}

/**
 * @brief React to an indication from the driver that SM Power Save mode
 *        updated for a given STA
 *
 * @param [in] state  the "this" pointer
 * @param [in] event  the data sent from the kernel
 * @param [in] bss  BSS the event was received from
 */
static void wlanifBSteerEventsHandleSMPSUpdateInd(
    wlanifBSteerEventsHandle_t state,
    const ath_netlink_bsteering_event_t *event,
    const lbd_bssInfo_t *bss) {
    struct bs_node_smps_update_ind *update =
        (struct bs_node_smps_update_ind *)&event->data.smps_update;

    dbgf(state->dbgModule, DBGINFO,
         "%s: SM Power Save mode received from " lbMACAddFmt(":") " on "
         lbBSSInfoAddFmt() ": %sSTATIC", __func__,
         lbMACAddData(update->client_addr), lbBSSInfoAddData(bss),
         update->is_static ? "" : "NOT ");

    wlanif_smpsUpdateEvent_t smpsEvent;
    lbCopyMACAddr(update->client_addr, smpsEvent.sta_addr.ether_addr_octet);
    lbCopyBSSInfo(bss, &smpsEvent.bss);
    smpsEvent.isStatic = update->is_static ? LBD_TRUE : LBD_FALSE;

    mdCreateEvent(mdModuleID_WlanIF, mdEventPriority_High,
                  wlanif_event_smps_update, &smpsEvent, sizeof(smpsEvent));
    return;
}

/**
 * @brief React to an indication from the driver that Operating Mode Notification
 *        received from a given STA
 *
 * @param [in] state  the "this" pointer
 * @param [in] event  the data sent from the kernel
 * @param [in] bss  BSS the event was received from
 */
static void wlanifBSteerEventsHandleOpModeUpdateInd(
    wlanifBSteerEventsHandle_t state,
    const ath_netlink_bsteering_event_t *event,
    const lbd_bssInfo_t *bss) {
    struct bs_node_opmode_update_ind *update =
        (struct bs_node_opmode_update_ind *)&event->data.opmode_update;
    dbgf(state->dbgModule, DBGINFO,
         "%s: Operating Mode Notification received from " lbMACAddFmt(":")
         " on " lbBSSInfoAddFmt() ", Max bandwidth: %u, Num of spatial streams: %u",
         __func__, lbMACAddData(update->client_addr), lbBSSInfoAddData(bss),
         update->datarate_info.max_chwidth, update->datarate_info.num_streams);

    wlanif_opmodeUpdateEvent_t opModeEvent;
    lbCopyMACAddr(update->client_addr, opModeEvent.sta_addr.ether_addr_octet);
    lbCopyBSSInfo(bss, &opModeEvent.bss);
    opModeEvent.maxChWidth = wlanifMapToBandwidth(state->dbgModule,
                                                  update->datarate_info.max_chwidth);
    opModeEvent.numStreams = update->datarate_info.num_streams;

    mdCreateEvent(mdModuleID_WlanIF, mdEventPriority_High,
                  wlanif_event_opmode_update, &opModeEvent, sizeof(opModeEvent));
    return;
}

/**
 * @brief Handle a band steering event received from the kernel.
 *
 * @param [in] state  the "this" pointer
 * @param [in] event  the message to handle
 */
static void wlanifBSteerEventsMsgRx(wlanifBSteerEventsHandle_t state,
                                    const ath_netlink_bsteering_event_t *event) {
    lbd_bssInfo_t bss;
    if (wlanifBSteerControlGetBSSInfo(state->bsteerControlHandle,
                                      event->sys_index, &bss) != LBD_OK) {
        dbgf(state->dbgModule, DBGDUMP,
             "%s: Received msg from unknown BSS: type %u index %u",
             __func__, event->type, event->sys_index);
        return;
    }

    switch (event->type) {
        case ATH_EVENT_BSTEERING_CHAN_UTIL:
            wlanifBSteerEventsHandleChanUtilInd(
                    state, event, &bss, LBD_FALSE /* isRawMeasurement */);
            break;
        case ATH_EVENT_BSTEERING_PROBE_REQ:
            wlanifBSteerEventsHandleProbeReqInd(state, event, &bss);
            break;

        case ATH_EVENT_BSTEERING_NODE_ASSOCIATED:
            wlanifBSteerEventsHandleNodeAssociatedInd(state, event, &bss);
            break;

        case ATH_EVENT_BSTEERING_CLIENT_ACTIVITY_CHANGE:
            wlanifBSteerEventsHandleActivityChange(state, event, &bss);
            break;

        case ATH_EVENT_BSTEERING_TX_AUTH_FAIL:
            wlanifBSteerEventsHandleTxAuthFailInd(state, event, &bss);
            break;

        case ATH_EVENT_BSTEERING_DBG_CHAN_UTIL:
            wlanifBSteerEventsHandleChanUtilInd(
                    state, event, &bss, LBD_TRUE /* isRawMeasurement */);
            break;

        case ATH_EVENT_BSTEERING_CLIENT_RSSI_CROSSING:
            wlanifBSteerEventsHandleRSSIXingInd(state, event, &bss);
            break;

        case ATH_EVENT_BSTEERING_CLIENT_RSSI_MEASUREMENT:
            wlanifBSteerEventsHandleRSSIMeasurementInd(
                    state, event, &bss, LBD_FALSE /* isRawMeasurement*/);
            break;

        case ATH_EVENT_BSTEERING_DBG_RSSI:
            wlanifBSteerEventsHandleRSSIMeasurementInd(
                    state, event, &bss, LBD_TRUE /* isRawMeasurement*/);
            break;

        case ATH_EVENT_BSTEERING_WNM_EVENT:
            wlanifBSteerEventsHandleWNMEvent(state, event, &bss);
            break;

        case ATH_EVENT_BSTEERING_RRM_REPORT:
            wlanifBSteerEventsHandleRRMReportInd(state, event, &bss);
            break;

        case ATH_EVENT_BSTEERING_CLIENT_TX_RATE_CROSSING:
            wlanifBSteerEventsHandleTxRateXingInd(state, event, &bss);
            break;

        case ATH_EVENT_BSTEERING_VAP_STOP:
            wlanifBSteerEventsHandleVAPStop(state, event, &bss);
            break;

        case ATH_EVENT_BSTEERING_DBG_TX_RATE:
            wlanifBSteerEventsHandleTxRateMeasurementInd(
                    state, event, &bss);
            break;

        case ATH_EVENT_BSTEERING_TX_POWER_CHANGE:
            wlanifBSteerEventsHandleTxPowerChangeInd(state, event, &bss);
            break;

        case ATH_EVENT_BSTEERING_STA_STATS:
            wlanifBSteerEventsHandleSTAStatsInd(state, event, &bss);
            break;

        case ATH_EVENT_BSTEERING_SMPS_UPDATE:
            wlanifBSteerEventsHandleSMPSUpdateInd(state, event, &bss);
            break;

        case ATH_EVENT_BSTEERING_OPMODE_UPDATE:
            wlanifBSteerEventsHandleOpModeUpdateInd(state, event, &bss);
            break;

        case ATH_EVENT_BSTEERING_DBG_TX_AUTH_ALLOW:
            wlanifBSteerEventsHandleTxAuthAllowInd(state, event, &bss);
            break;

        default:
            dbgf(state->dbgModule, DBGINFO, "%s: Unhandled msg: type %u index %u",
                 __func__, event->type, event->sys_index);
            break;
    }
}

/**
 * @brief React to the indication that the netlink socket is readable.
 *
 * @param [in] cookie  the "this" pointer provided during registration
 */
static void wlanifBSteerEventsBufRdCB(void *cookie) {
    u_int32_t numBytes;
    const u_int8_t *msg;

    wlanifBSteerEventsHandle_t state = (wlanifBSteerEventsHandle_t) cookie;

    numBytes = bufrdNBytesGet(&state->readBuf);
    msg = bufrdBufGet(&state->readBuf);

    do {
        if (bufrdErrorGet(&state->readBuf)) {
            dbgf(state->dbgModule, DBGERR, "%s: Read error! # bytes=%u",
                 __func__, numBytes);

            int eventsEnabled = state->eventsEnabled;
            wlanifBSteerEventsUnregister(state);
            wlanifBSteerEventsRegister(state->dbgModule, state);

            if (-1 == state->netlinkSocket ||
                (eventsEnabled &&
                 wlanifBSteerControlEventsEnable(state->bsteerControlHandle, state) == LBD_NOK)) {
                dbgf(state->dbgModule, DBGERR,
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

        const struct nlmsghdr *hdr = (const struct nlmsghdr *) msg;
        if (numBytes < sizeof(struct nlmsghdr) +
                       sizeof(ath_netlink_bsteering_event_t) ||
            hdr->nlmsg_len < sizeof(ath_netlink_bsteering_event_t)) {
            dbgf(state->dbgModule, DBGERR, "%s: Invalid message len: %u bytes",
                 __func__, numBytes);
            break;
        }

        const ath_netlink_bsteering_event_t *event = NLMSG_DATA(hdr);
        wlanifBSteerEventsMsgRx(state, event);
    } while (0);

    bufrdConsume(&state->readBuf, numBytes);
}
