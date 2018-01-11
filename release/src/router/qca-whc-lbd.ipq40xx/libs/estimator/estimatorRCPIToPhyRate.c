// vim: set et sw=4 sts=4 cindent:
/*
 * @File: estimatorSNRToPhyRate.c
 *
 * @Abstract: Private helper for conversion from an SNR to a PHY rate.
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

#include <dbg.h>

#include "lb_common.h"
#include "lb_assert.h"
#include "estimatorCmn.h"
#include "estimatorRCPIToPhyRate.h"
#include "estimatorSNRToPhyRateTable.h"

// Constants

/**
 * @brief The expected total noise value (noise floor plus noise figure)
 *        based on the channel width.
 */
static const int8_t NOISE_OFFSET_BY_CH_WIDTH[wlanif_chwidth_invalid] = {
    -94,  // 20 MHz
    -91,  // 40 MHz
    -88,  // 80 MHz
    -85,  // 160 MHz
};

// Forward decls
static lbd_snr_t estimatorRCPIToPhyRateEstimateSNR(struct dbgModule *dbgModule,
                                                   int8_t rcpi,
                                                   wlanif_chwidth_e chwidth);

// ====================================================================
// Package level APIs
// ====================================================================
lbd_linkCapacity_t estimatorEstimateFullCapacityFromRCPI(
        struct dbgModule *dbgModule, stadbEntry_handle_t entry,
        const lbd_bssInfo_t *targetBSSInfo, const wlanif_phyCapInfo_t *bssCap,
        stadbEntry_bssStatsHandle_t measuredBSS, lbd_rcpi_t rcpi,
        u_int8_t measuredBSSTxPower, lbd_rcpi_t *estimatedRCPI) {
    // Adjust RCPI value based on relative powers on the measured and target BSSes
    // if both are valid.
    if (measuredBSSTxPower) {
        rcpi += bssCap->maxTxPower - measuredBSSTxPower;
    }
    *estimatedRCPI = rcpi;

    const struct ether_addr *addr = stadbEntry_getAddr(entry);
    lbDbgAssertExit(dbgModule, addr);

    wlanif_phyCapInfo_t minPhyCap;
    if (estimatorCmnResolveMinPhyCap(entry, addr, measuredBSS, targetBSSInfo,
                                     bssCap, &minPhyCap) == LBD_NOK) {
        return LBD_INVALID_LINK_CAP;
    }

    lbd_snr_t snr = estimatorRCPIToPhyRateEstimateSNR(dbgModule, rcpi,
                                                      minPhyCap.maxChWidth);

    lbd_linkCapacity_t capacity =
        estimatorSNRToPhyRateTablePerformLookup(dbgModule, minPhyCap.phyMode,
                                                minPhyCap.maxChWidth,
                                                minPhyCap.numStreams,
                                                minPhyCap.maxMCS,
                                                snr);

    if (LBD_INVALID_LINK_CAP == capacity) {
        dbgf(dbgModule, DBGERR,
             "%s: No supported PHY rate for " lbMACAddFmt(":") " on "
             lbBSSInfoAddFmt() " using PhyMode [%u] ChWidth [%u] "
             "NumStreams [%u] MaxMCS [%u] SNR [%u]",
             __func__, lbMACAddData(addr->ether_addr_octet),
             lbBSSInfoAddData(targetBSSInfo),
             minPhyCap.phyMode, minPhyCap.maxChWidth, minPhyCap.numStreams,
             minPhyCap.maxMCS, snr);
    } else {
        dbgf(dbgModule, DBGDUMP,
             "%s: Estimated capacity for STA " lbMACAddFmt(":") " on "
             lbBSSInfoAddFmt() " of %u Mbps using PhyMode [%u] ChWidth [%u] "
             "NumStreams [%u] MaxMCS [%u] SNR [%u]",
             __func__, lbMACAddData(addr->ether_addr_octet),
             lbBSSInfoAddData(targetBSSInfo), capacity,
             minPhyCap.phyMode, minPhyCap.maxChWidth, minPhyCap.numStreams,
             minPhyCap.maxMCS, snr);
    }
    return capacity;
}

// ====================================================================
// Private helper functions
// ====================================================================

/**
 * @brief Estimate the SNR from an RCPI value and the channel width.
 *
 * @param [in] dbgModule  the module to use for logging errors
 * @param [in] rcpi  the value reported by the STA
 * @param [in] chwidth  the channel width for which to estimate the SNR
 *
 * @return the estimated SNR
 */
static lbd_snr_t estimatorRCPIToPhyRateEstimateSNR(struct dbgModule *dbgModule,
                                                   int8_t rcpi,
                                                   wlanif_chwidth_e chwidth) {
    lbDbgAssertExit(dbgModule, chwidth < wlanif_chwidth_invalid);
    return rcpi - NOISE_OFFSET_BY_CH_WIDTH[chwidth];
}
