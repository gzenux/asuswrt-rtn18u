// vim: set et sw=4 sts=4 cindent:
/*
 * @File: estimatorSNRToPhyRate.h
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
 */

#ifndef estimatorSNRToPhyRate__h
#define estimatorSNRToPhyRate__h

#include "lbd_types.h"  // for LBD_STATUS and other type defs
#include "stadb.h"

// Forward decls
struct dbgModule;

#if defined(__cplusplus)
extern "C" {
#endif

/**
 * @brief Determine the full link capacity supportable on the downlink for
 *        the provided client on the given BSS.
 *
 * The capacity is estimated based on the SNR and the client capabilities.
 *
 * @param [in] dbgModule  the module to use for any debug logs
 * @param [in] entry  the STA for which to estimate the capacity
 * @param [in] targetBSSInfo  the BSS on which to estimate the capacity
 * @param [in] targetPHYCap  the PHY capability on the target BSS
 * @param [in] measuredBSS  the BSS on which the SNR was obtained
 * @param [in] rcpi  the measured receive channel power indicator
 * @param [in] measuredBSSTxPower  the maximum Tx power on the measured
 *                                 BSS, used to adjust RCPI value; or 0
 *                                 if no PHY capability available on the
 *                                 measured BSS
 * @param [out] estimatedRCPI  the estimated RCPI on the given BSS
 *
 * @return the capacity in Mbps, or LBD_INVALID_LINK_CAP if it cannot be
 *         obtained
 */
lbd_linkCapacity_t estimatorEstimateFullCapacityFromRCPI(
        struct dbgModule *dbgModule, stadbEntry_handle_t entry,
        const lbd_bssInfo_t *targetBSSInfo, const wlanif_phyCapInfo_t *targetPHYCap,
        stadbEntry_bssStatsHandle_t measuredBSS, lbd_rcpi_t rcpi,
        u_int8_t measuredBSSTxPower, lbd_rcpi_t *estimatedRCPI);

#if defined(__cplusplus)
}
#endif

#endif // estimatorSNRToPhyRate__h

