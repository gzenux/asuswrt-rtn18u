// vim: set et sw=4 sts=4 cindent:
/*
 * @File: steeralgBSA.c
 *
 * @Abstract: Implementation of single AP steering algorithm
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

#include "lb_common.h"
#include "lb_assert.h"
#include "bandmon.h"

#include "steeralgCmn.h"


// ====================================================================
// Private functions
// ====================================================================

// ====================================================================
// Package level functions
// ====================================================================

/**
 * The following rules are used to compute metric:
 * bit 31: Set if BSS is on a different band from serving band
 * bit 30: Set if BSS has reserved airtime for the client
 * bit 29: Set if the utilization is below its safety threshold
 * bit 28: set if a channel with higher Tx power for 11ac clients
 *         or if a channel with lower Tx power for non-11ac clients
 * bit 20-27: set with medium utilization measured on this channel
 */
u_int32_t steeralgSelect11kChannelCallback(stadbEntry_handle_t entry,
                                           stadbEntry_bssStatsHandle_t bssHandle,
                                           void *cookie) {
#define METRIC_OFFSET_BAND 31
#define METRIC_OFFSET_RESERVED_AIRTIME (METRIC_OFFSET_BAND - 1)
#define METRIC_OFFSET_SAFETY (METRIC_OFFSET_RESERVED_AIRTIME - 1)
#define METRIC_OFFSET_PHY_CAP (METRIC_OFFSET_SAFETY - 1)
#define METRIC_OFFSET_UTIL (METRIC_OFFSET_PHY_CAP - sizeof(lbd_airtime_t) * 8)
    steeralgCmnServingBSSInfo_t *servingBSS = (steeralgCmnServingBSSInfo_t *)cookie;
    const lbd_bssInfo_t *bssInfo = stadbEntry_resolveBSSInfo(bssHandle);
    lbDbgAssertExit(steeralgState.dbgModule, bssInfo);
    if (servingBSS->bssInfo->channelId == bssInfo->channelId) {
        // Ignore current channel
        return 0;
    }

    LBD_BOOL polluted = LBD_FALSE;
    if (stadbEntry_getPolluted(entry, bssHandle, &polluted, NULL) == LBD_NOK ||
        polluted) {
        // Ignore polluted channel
        return 0;
    }

    // If trigger is upgrade/downgrade, prefer the other band. Else prefer 5 GHz.
    wlanif_band_e preferred11kReqBand;
    if (steeralgCmnIsActiveUpgradeDowngrade(servingBSS->trigger)) {
        preferred11kReqBand = servingBSS->band == wlanif_band_24g ?
            wlanif_band_5g : wlanif_band_24g;

        // For upgrade/downgrade, we ignore any BSSes that are not on the
        // preferred band as there is no sense in measuring them.
        if (wlanif_resolveBandFromChannelNumber(bssInfo->channelId) !=
                preferred11kReqBand) {
            return 0;
        }
    } else {
        preferred11kReqBand = wlanif_band_5g;
    }

    // If active steering, ignoring a channel above the safety threshold since
    // there is no way the traffic will fit.
    if (steeralgCmnIsActiveSteer(servingBSS->trigger) &&
        bandmon_canSupportClient(bssInfo->channelId,
                                 0 /* airtime */) == LBD_INVALID_AIRTIME) {
        return 0;
    }

    u_int32_t metric = steeralgCmnComputeBSSMetric(entry, bssHandle,
                                                   preferred11kReqBand,
                                                   servingBSS->bestPHYMode,
                                                   METRIC_OFFSET_BAND,
                                                   METRIC_OFFSET_PHY_CAP,
                                                   METRIC_OFFSET_RESERVED_AIRTIME,
                                                   METRIC_OFFSET_SAFETY,
                                                   METRIC_OFFSET_UTIL);

    const struct ether_addr *staAddr = stadbEntry_getAddr(entry);
    lbDbgAssertExit(steeralgState.dbgModule, staAddr);
    dbgf(steeralgState.dbgModule, DBGDEBUG,
         "%s: " lbBSSInfoAddFmt() "is selected as 11k candidate with metric 0x%x "
         "for " lbMACAddFmt(":"),
         __func__, lbBSSInfoAddData(bssInfo), metric, lbMACAddData(staAddr->ether_addr_octet));

    return metric;
#undef METRIC_OFFSET_RESERVED_AIRTIME
#undef METRIC_OFFSET_SAFETY
#undef METRIC_OFFSET_BAND
#undef METRIC_OFFSET_PHY_CAP
#undef METRIC_OFFSET_UTIL
}

LBD_STATUS steeralgHandleSTAMetricsForActiveClient(
        stadbEntry_handle_t entry,
        const estimator_staDataMetricsCompleteEvent_t *metricEvent) {
    if (metricEvent->result != LBD_OK) {
        // Metric collection was not successful
        return LBD_NOK;
    }

    return steeralgCmnSteerActiveClient(entry, &metricEvent->addr);
}

/**
 * For single AP, data metrics estimation should not be triggered for
 * idle client. It may only be possible if the offloading process takes
 * too long that the STA becomes idle during this process, which should
 * be handled by idle steering logic. So this function does nothing here
 */
void steeralgHandleSTAMetricsForIdleClient(
        stadbEntry_handle_t entry,
        const estimator_staDataMetricsCompleteEvent_t *event) {
}
