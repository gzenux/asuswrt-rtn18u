// vim: set et sw=4 sts=4 cindent:
/*
 * @File: wlanifLinkEventsCmn.c
 *
 * @Abstract: Utility functions for handling RTM_NEWLINK events
 *
 * @Notes:
 *
 * @@-COPYRIGHT-START-@@
 *
 * Copyright (c) 2014-2015 Qualcomm Atheros, Inc.
 * All Rights Reserved.
 * Qualcomm Atheros Confidential and Proprietary.
 *
 * @@-COPYRIGHT-END-@@
 *
 */


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

static void wlanifLinkEventsCmnRestartUtilization(
        wlanifLinkEventsHandle_t state, wlanif_band_e band);

// ====================================================================
// Private helper functions
// ====================================================================

/**
 * @brief React to an indication from the driver that the channel changed
 *        on one of our VAPs.
 *
 * @param [in] state  the internal state for this instance
 * @param [in] event  the event that the driver generated
 * @param [in] band  the band on which the channel change occurred
 */
static void wlanifLinkEventsCmnProcessChannelChange(
        wlanifLinkEventsHandle_t state, const struct iw_event *event,
        wlanif_band_e band, int sysIndex) {
    dbgf(state->dbgModule, DBGINFO,
         "%s: Channel change to %u", __func__, event->u.freq.m);

    // If the band has actually changed on the VAP, we do not support
    // that so we will exit and let the process monitoring framework
    // restart us.
    wlanif_band_e newBand = wlanifMapFreqToBand(event->u.freq.m);
    if (newBand != band) {
        dbgf(state->dbgModule, DBGERR,
             "%s: Change of band not supported in lbd; restarting",
             __func__);
        exit(1);
    }

    // Update the frequency in the BSteerControl record
    if (wlanifBSteerControlUpdateChannel(state->bsteerControlHandle,
                                         band,
                                         sysIndex,
                                         event->u.freq.m) != LBD_OK) {
         dbgf(state->dbgModule, DBGERR,
              "%s: Could not update channel in lbd; restarting",
              __func__);
         exit(1);
    }

    // Otherwise, we need to inform other modules of the channel change,
    // but first force the disable and re-enable of the band steering
    // feature to ensure the channel monitoring on both bands is in
    // sync (as the driver only restarts the one band).
    //
    // Note that if this fails, we have to pull the plug since band
    // steering may no longer be enabled on both bands. It generally
    // should not fail though.
    wlanifLinkEventsCmnRestartUtilization(state, band);
}

/**
 * @brief Restart the channel utilization monitoring and generate an event
 *        indicating a VAP restart.
 *
 * @param [in] state  the internal state for this instance
 * @param [in] band  the band on which the VAP restart happened
 */
static void wlanifLinkEventsCmnRestartUtilization(
        wlanifLinkEventsHandle_t state, wlanif_band_e band) {
    if (wlanifBSteerControlRestartChannelUtilizationMonitoring(
                state->bsteerControlHandle) != LBD_OK) {
        dbgf(state->dbgModule, DBGERR,
             "%s: Failed to restart utilization monitoring; "
             "measurements may be out of sync", __func__);
        exit(1);
    }

    wlanif_vapRestartEvent_t vapRestartEvent;
    vapRestartEvent.band = band;

    mdCreateEvent(mdModuleID_WlanIF, mdEventPriority_High,
                  wlanif_event_vap_restart,
                  &vapRestartEvent, sizeof(vapRestartEvent));
}

/**
 * @brief Generate the event for a client that disassociated
 *        using the data contained in the iw_event structure
 *
 * @param [in] state  the internal state for this instance
 * @param [in] event  the event that the driver generated
 * @param [in] sysIndex  the OS-specific identifier for the
 *                       interface on which the disassociation
 *                       happened
 */
static void wlanifLinkEventsCmnGenerateDisassocEvent(
        wlanifLinkEventsHandle_t state, const struct iw_event *event,
        int sysIndex) {
    wlanif_assocEvent_t assocEvent;
    lbCopyMACAddr(event->u.addr.sa_data, assocEvent.sta_addr.ether_addr_octet);

    // We already have resolved the system index previously to a band, so this
    // should never fail.
    lbDbgAssertExit(state->dbgModule,
                    wlanifBSteerControlGetBSSInfo(
                        state->bsteerControlHandle,
                        sysIndex, &assocEvent.bss) != LBD_NOK);

    dbgf(state->dbgModule, DBGINFO, "%s: Client " lbMACAddFmt(":")
                                     " disassociated on "lbBSSInfoAddFmt(),
         __func__, lbMACAddData(event->u.addr.sa_data),
         lbBSSInfoAddData((&assocEvent.bss)));

    // don't change capabilities status during disassociation
    assocEvent.btmStatus = wlanif_cap_unchanged;
    assocEvent.rrmStatus = wlanif_cap_unchanged;
    assocEvent.phyCapInfo.valid = LBD_FALSE;

    mdCreateEvent(mdModuleID_WlanIF, mdEventPriority_Low,
                  wlanif_event_disassoc,
                  &assocEvent, sizeof(assocEvent));
}

/**
 * @brief Parse out all of the iw_event structures inside of the
 *        IFLA_WIRELESS attribute, generating events for them if necessary.
 *
 * @param [in] state  the internal state for this instance
 * @param [in] data  the start of the iw_events
 * @param [in] dataLen  the amount of remaining data in the IFLA_WIRELESS
 *                      attribute in which the iw_events can be found
 * @param [in] band  the band on which the event occurred
 * @param [in] sysIndex  the OS-specific identifier for the
 *                       interface on which the event was
 *                       generated
 */
static void wlanifLinkEventsCmnHandleIWEvent(wlanifLinkEventsHandle_t state,
                                             const u_int8_t *data,
                                             u_int32_t dataLen,
                                             wlanif_band_e band,
                                             int sysIndex) {
    struct iw_event event;
    const u_int8_t *dataEnd = data + dataLen;

    // There could be multiple events in the data, so keep going while
    // there is at least enough space for the event type and length.
    while (data + IW_EV_LCP_LEN <= dataEnd) {
        memcpy(&event, data, IW_EV_LCP_LEN);  // copy in to ensure alignment

        if (event.len <= IW_EV_LCP_LEN || data + event.len > dataEnd) {
            dbgf(state->dbgModule, DBGERR, "%s: Malformed event length %u "
                                           "(available %u)",
                 __func__, event.len, dataEnd - data);
            break;
        }

        switch (event.cmd) {
            case SIOCSIWFREQ:
            case IWEVREGISTERED:
                // Ignore this as we rely on a custom event for channel
                // changes (as only the custom event is generated for
                // driver-initiated channel changes).
                // Similarly, custom event for association, in order to communicate
                // 802.11v status, and so we have a single event for both open and secured
                // association
                break;

            case IWEVEXPIRED:
            {
                if (event.len == IW_EV_LCP_LEN + sizeof(event.u)) {
                    memcpy(&event.u, data + IW_EV_LCP_LEN, sizeof(event.u));
                    wlanifLinkEventsCmnGenerateDisassocEvent(
                            state, &event, sysIndex);
                } else {
                    dbgf(state->dbgModule, DBGERR,
                         "%s: Invalid event length %u (expected %u)",
                         __func__, event.len, IW_EV_LCP_LEN + sizeof(event.u));
                }
                break;
            }

            case IWEVASSOCREQIE:
                // Ignore this. It comes normally when the network is secured,
                // but it is consumed by hostapd and is irrelevant for load
                // balancing.
                break;


            case IWEVCUSTOM:
            {
                // Most of these events are not relevant, except for the
                // channel change. This is the only one we are handling here.
                if (event.len >= IW_EV_POINT_LEN) {
                    memcpy(&event.u.data.length, data + IW_EV_LCP_LEN,
                           sizeof(struct iw_event) -
                           (((char *) &event.u.data.length) -
                           ((char *) &event)));

                    if (event.u.data.flags == IEEE80211_EV_CHAN_CHANGE) {
                        if (event.u.data.length == sizeof(u_int8_t) &&
                            data + IW_EV_POINT_LEN + event.u.data.length <= dataEnd) {
                            u_int8_t chan;
                            memcpy(&chan, data + IW_EV_POINT_LEN, event.u.data.length);
                            event.u.freq.m = chan;
                            wlanifLinkEventsCmnProcessChannelChange(
                                    state, &event, band, sysIndex);
                            wlanifLinkEventsProcessChannelChange(
                                    sysIndex, chan);
                        } else {
                            dbgf(state->dbgModule, DBGERR,
                                 "%s: Invalid channel change event (len=%u, "
                                 "remaining=%u)", __func__, event.u.data.length,
                                 dataEnd - (data + IW_EV_POINT_LEN));
                        }
                    }
                }
                break;
            }

            default:
            {
                // We do not need to handle any other events.
                dbgf(state->dbgModule, DBGERR, "%s: Unhandled event %u len %u",
                     __func__, event.cmd, event.len);

                break;
            }
        }

        data += event.len;
    }
}

/**
 * @brief React to a change in the operational status of an interface.
 *
 * This is primarily used for detecting an interface that has been made
 * administratively down. When the interface is brought back up, state
 * is updated locally here but additional checks are needed before the
 * interface can be considered usable.
 *
 * @param [in] state  the internal state for this instance
 * @param [in] data  the start of the operstate data
 * @param [in] dataLen  the amount of remaining data in the IFLA_OPERSTATE
 *                      attribute
 * @param [in] band  the band on which the operating state changed
 * @param [in] sysIndex  the index of the interface on which the event occurred
 */
static void wlanifLinkEventsCmnHandleOperState(wlanifLinkEventsHandle_t state,
                                               const u_int8_t *data,
                                               u_int32_t dataLen,
                                               wlanif_band_e band,
                                               int sysIndex) {
    u_int8_t operstate;
    if (dataLen == sizeof(operstate)) {
        operstate = *data;

        // From testing, it appears we only ever see IF_OPER_UNKNOWN when
        // the interface is brought up. No transition to IF_OPER_UP is seen.
        // However, we allow for it here just in case this changes in the
        // future.
        LBD_BOOL ifaceUp = (operstate == IF_OPER_UNKNOWN ||
                            operstate == IF_OPER_UP) ? LBD_TRUE : LBD_FALSE;
        LBD_BOOL changed = LBD_FALSE;
        wlanifBSteerControlUpdateLinkState(state->bsteerControlHandle,
                                           sysIndex, ifaceUp, &changed);
        if (changed) {
            dbgf(state->dbgModule, DBGINFO,
                 "%s: Interface on band %u changed state to %u",
                 __func__, band, ifaceUp);

            wlanifLinkEventsCmnRestartUtilization(state, band);
        }
    } else {
        dbgf(state->dbgModule, DBGERR,
             "%s: Invalid length for operstate change: %u",
             __func__, dataLen);
    }
}


/**
 * @brief Handle an RTM_NEWLINK message from the driver, generating the
 *        appropriate events from it.
 *
 * @param [in] state  the internal state for this instance
 * @param [in] hdr  the netlink message header; the length field has
 *                  already been validated
 * @param [in] payloadLen  the length of the payload (not including the
 *                         netlink header)
 */
static void wlanifLinkEventsCmnHandleNewLink(wlanifLinkEventsHandle_t state,
                                             const struct nlmsghdr *hdr,
                                             u_int32_t payloadLen) {
    const struct ifinfomsg *ifaceInfo = NLMSG_DATA(hdr);

    size_t ifaceLen = NLMSG_ALIGN(sizeof(*ifaceInfo));
    if (payloadLen < ifaceLen) {
        dbgf(state->dbgModule, DBGERR, "%s: Malformed netlink payload "
                                       "length %u", __func__, payloadLen);
        return;
    }

    wlanif_band_e band =
        wlanifBSteerControlResolveBandFromSystemIndex(state->bsteerControlHandle,
                                                      ifaceInfo->ifi_index);
    if (wlanif_band_invalid == band) {
        dbgf(state->dbgModule, DBGDUMP,
             "%s: Received message from ifindex %u not managed by lbd",
             __func__, ifaceInfo->ifi_index);
        return;
    }

    const struct rtattr *attr = IFLA_RTA(ifaceInfo);
    const size_t RTATTR_LEN = RTA_ALIGN(sizeof(*attr));

    // This will keep track of the amount of data remaining in the payload
    // for the RT attributes.
    size_t attrLen = payloadLen - ifaceLen;

    // Iterate over all of the RT attributes, looking for a wireless one
    // and then dispatch to a separate function to parse the event.
    while (RTA_OK(attr, attrLen)) {
        const u_int8_t *data =
            ((const u_int8_t *) attr) + RTATTR_LEN;
        switch (attr->rta_type) {
            case IFLA_WIRELESS:
            {
                wlanifLinkEventsCmnHandleIWEvent(state, data,
                                                 attr->rta_len - RTATTR_LEN,
                                                 band, ifaceInfo->ifi_index);
                break;
            }

            case IFLA_OPERSTATE:
            {
                wlanifLinkEventsCmnHandleOperState(state, data,
                                                attr->rta_len - RTATTR_LEN,
                                                band, ifaceInfo->ifi_index);
                break;
            }

            default:
            {
                // Nop
                break;
            }
        }

        attr = RTA_NEXT(attr, attrLen);
    }

    if (attrLen != 0) {
        dbgf(state->dbgModule, DBGERR, "%s: Did not consume all attributes: %u bytes left",
             __func__, attrLen);
    }
}

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
                              const u_int8_t *msg, u_int32_t numBytes) {
    const struct nlmsghdr *hdr = (const struct nlmsghdr *) msg;
    u_int32_t msgLen, payloadLen;

    while (numBytes >= sizeof(*hdr)) {
        msgLen = NLMSG_ALIGN(hdr->nlmsg_len);
        if (hdr->nlmsg_len < sizeof(*hdr) || msgLen > numBytes) {
            dbgf(state->dbgModule, DBGERR, "%s: Malformed netlink message "
                                           "length %u (should be %u)",
                 __func__, numBytes, msgLen);
            break;
        }

        payloadLen = msgLen - sizeof(*hdr);
        switch (hdr->nlmsg_type) {
            case RTM_NEWLINK:
                wlanifLinkEventsCmnHandleNewLink(state, hdr, payloadLen);
                break;

            default:
                // Nop
                break;
        }

        numBytes -= msgLen;
        hdr = (const struct nlmsghdr *) (((const u_int8_t *) hdr) + msgLen);
    }

    if (numBytes != 0) {
        dbgf(state->dbgModule, DBGERR, "%s: Did not consume all bytes: %u bytes left",
             __func__, numBytes);
    }
}
