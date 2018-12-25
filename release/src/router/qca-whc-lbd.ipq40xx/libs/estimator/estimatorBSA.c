// vim: set et sw=4 sts=4 cindent:
/*
 * @File: estimatorBSA.c
 *
 * @Abstract: Implementation of single AP estimator
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

#include "estimatorCmn.h"

// ====================================================================
// Private functions
// ====================================================================

// ====================================================================
// Package level functions
// ====================================================================

LBD_STATUS estimatorHandleValidBeaconReport(stadbEntry_handle_t entry,
                                            const wlanif_beaconReportEvent_t *bcnrptEvent,
                                            wlanif_band_e measuredBand,
                                            const lbd_bssInfo_t **reportedLocalBss) {
    estimatorNonServingRateAirtimeParams_t params;
    params.staAddr = &bcnrptEvent->sta_addr;
    params.measuredBand = measuredBand;
    params.result = LBD_OK;

    size_t i = 0;
    for (i = 0; i < bcnrptEvent->numBcnrpt; ++i) {
        // First find the reported local BSS
        if (bcnrptEvent->reportedBcnrptInfo[i].reportedBss.apId ==
                LBD_APID_SELF) {
            *reportedLocalBss = &bcnrptEvent->reportedBcnrptInfo[i].reportedBss;
            params.measuredBss = *reportedLocalBss;
            params.rcpi = bcnrptEvent->reportedBcnrptInfo[i].rcpi;
        }
        if (LBD_NOK == stadbEntry_setRCPIByBSSInfo(
                           entry,
                           &bcnrptEvent->reportedBcnrptInfo[i].reportedBss,
                           bcnrptEvent->reportedBcnrptInfo[i].rcpi)) {
            dbgf(estimatorState.dbgModule, DBGERR,
                 "%s: Failed to record downlink RSSI for " lbMACAddFmt(":")
                 " on " lbBSSInfoAddFmt(), __func__,
                 lbMACAddData(bcnrptEvent->sta_addr.ether_addr_octet),
                 lbBSSInfoAddData(&bcnrptEvent->reportedBcnrptInfo[i].reportedBss));
            // Still try to record on other BSSes if any
        }
    }

    if (!*reportedLocalBss) {
        dbgf(estimatorState.dbgModule, DBGERR,
             "%s: No local BSS reported in beacon report from " lbMACAddFmt(":"),
             __func__, lbMACAddData(bcnrptEvent->sta_addr.ether_addr_octet));
        return LBD_NOK;
    }

    estimatorCmnHandleLocalBeaconReport(entry, &bcnrptEvent->sta_addr,
                                        *reportedLocalBss, &params);

    return params.result;
}

void estimatorSubInit(void) {
   // No BSA specific initialization needs to be done.
}
