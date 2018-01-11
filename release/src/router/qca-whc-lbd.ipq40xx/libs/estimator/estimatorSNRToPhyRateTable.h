// vim: set et sw=4 sts=4 cindent:
/*
 * @File: estimatorSNRToPhyRateTable.h
 *
 * @Abstract: The representation of the SNR to PHY rate table.
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

#ifndef estimatorSNRToPhyRateTable__h
#define estimatorSNRToPhyRateTable__h

#include "lbd_types.h"
#include "wlanif.h"

#if defined(__cplusplus)
extern "C" {
#endif

// Forward decls
struct dbgModule;

/**
 * @brief Definition for a single entry in the table that maps from SNR to
 *        PHY rate.
 */
typedef struct estimatorSNRToPhyRateEntry_t {
    /// The signal to noise ratio.
    lbd_snr_t snr;

    /// The estimated PHY rate, in Mbps.
    lbd_linkCapacity_t phyRate;
} estimatorSNRToPhyRateEntry_t;

// These constants define the dimensions in our table, specifying the most
// capabilities for which we have predicted rate information.
#define ESTIMATOR_MAX_NSS    4
#define ESTIMATOR_MIN_NSS    1
#define ESTIMATOR_MAX_RATES  10

/**
 * @brief The SNR to PHY rate table.
 *
 * Entries are at the leaves. The entry to use for a given SNR and capability
 * set is the one whose SNR is less than the given SNR but the next entry is
 * greater than the given SNR.
 */
extern const estimatorSNRToPhyRateEntry_t
    estimatorSNRToPhyRateTable[wlanif_phymode_invalid]
                              [wlanif_chwidth_invalid]
                              [ESTIMATOR_MAX_NSS]
                              [ESTIMATOR_MAX_RATES];


/**
 * @brief Determine the estimated full capacity for a STA with the provided
 *        SNR based on its PHY capabilities.
 *
 * Note that this is somewhat of an upper bound as it assumes the AP and
 * STA will be able to operate at the provided channel width and number of
 * spatial streams (when in reality rate control may step down from these).
 *
 * @param [in] dbgModule  handle to the module to use for error reporting
 * @param [in] phyMode  the expected mode of operation
 * @param [in] chwidth  the maximum channel width of operation
 * @param [in] numSpatialStreams  the maximum number of spatial streams that
 *                                can be used
 * @param [in] maxMCSIndex  the index of the maximum MCS supported
 * @param [in] snr  the estimated SNR of the client
 *
 * @return the capacity in Mbps, or LBD_INVALID_LINK_CAP if the parameters
 *         cannot be resolved to an expected rate (eg. SNR is too weak)
 */
lbd_linkCapacity_t estimatorSNRToPhyRateTablePerformLookup(
        struct dbgModule *dbgModule,
        wlanif_phymode_e phyMode, wlanif_chwidth_e chwidth,
        u_int8_t numSpatialStreams, u_int8_t maxMCSIndex, lbd_snr_t snr);

/**
 * @brief Determine estimated SNR for a STA with the provided
 *        full link capacity based on its PHY capabilities.
 *
 * @param [in] dbgModule  handle to the module to use for error reporting
 * @param [in] phyMode  the expected mode of operation
 * @param [in] chwidth  the maximum channel width of operation
 * @param [in] numSpatialStreams  the maximum number of spatial streams that
 *                                can be used
 * @param [in] maxMCSIndex  the index of the maximum MCS supported
 * @param [in] phyRate  the measured link capacity of the client
 *
 * @return the estimated SNR, or LBD_MAX_SNR if the parameters
 *         cannot be resolved to an expected SNR (eg. rate is too low)
 */
lbd_snr_t estimatorSNRToPhyRateTablePerformReverseLookup(
        struct dbgModule *dbgModule, wlanif_phymode_e phyMode,
        wlanif_chwidth_e chwidth, u_int8_t numSpatialStreams,
        u_int8_t maxMCSIndex, lbd_linkCapacity_t linkCAP);

#if defined(__cplusplus)
}
#endif

#endif // estimatorSNRToPhyRateTable__h
