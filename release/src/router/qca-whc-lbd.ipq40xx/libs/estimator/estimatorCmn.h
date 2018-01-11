// vim: set et sw=4 sts=4 cindent:
/*
 * @File: estimatorCmn.h
 *
 * @Abstract: Functions shared by estimatorBSA and estimatorMBSA
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

#ifndef estimatorCmn__h
#define estimatorCmn__h

#include <dbg.h>
#include <evloop.h>

#include "lbd_types.h"

#include "estimator.h"
#include "estimatorPollutionAccumulator.h"

#if defined(__cplusplus)
extern "C" {
#endif

// ====================================================================
// Protected members (for use within the common functions and any
// "derived" functions that may be using this component).
// ====================================================================

// Currently only stamon needs to know when clients are eligible again
// to have their metrics measured. However, we allow up to two observers
// in case steeralg needs this in the future.
#define MAX_STA_DATA_METRICS_ALLOWED_OBSERVERS 2

/**
 * @brief Internal state for the rate estimator module.
 */
struct estimatorPriv_t {
    struct dbgModule *dbgModule;

    /// Special logging area for the raw byte count statistics and estimated
    /// throughput / rate for continuous throughput sampling mode.
    /// This is used to make it easier to suppress the logs that would
    /// otherwise fill up the console.
    struct dbgModule *statsDbgModule;

    /// Configuration data obtained at init time
    struct {
        /// Maximum age (in seconds) before some measurement is considered too
        /// old and thus must be re-measured.
        u_int32_t ageLimit;

        /// RSSI difference when estimating RSSI on 5 GHz from
        /// the one measured on 2.4 GHz
        int rssiDiffEstimate5gFrom24g;

        /// RSSI difference when estimating RSSI on 2.4 GHz from
        /// the one measured on 5 GHz
        int rssiDiffEstimate24gFrom5g;

        /// Number of probes required when non-associted band RSSI is valid
        u_int8_t probeCountThreshold;

        /// How frequently to sample the statistics for a node.
        unsigned statsSampleInterval;

        /// Maximum amount of time (in seconds) to allow for a client to
        /// respond to an 802.11k Beacon Report Request before giving up
        /// and declaring a failure.
        u_int8_t max11kResponseTime;

        /// Minimum amount of time (in seconds) between two consecutive 802.11k
        /// requests for a given STA if the first one failed.
        unsigned dot11kProhibitTimeShort;

        /// Minimum amount of time (in seconds) between two consecutive 802.11k
        /// requests for a given STA if the first one succeeded.
        unsigned dot11kProhibitTimeLong;

        /// Percentage factor to apply the PHY rate before deriving the
        /// airtime from the rate and throughput information.
        u_int8_t phyRateScalingForAirtime;

        /// Whether to enable the continous throughput sampling mode
        /// (primarily for demo purposes) or not.
        LBD_BOOL enableContinuousThroughput;

        /// The maximum length of time (in seconds) that a BSS can remain
        /// marked as polluted without any further updates to the pollution
        /// state.
        unsigned maxPollutionTime;

        /// Configuration parameters related to pollution accumulator
        estimatorPollutionAccumulatorParams_t accumulator;

        /// IAS should not be triggered if RSSI is below this threshold
        lbd_rssi_t iasLowRSSIThreshold;

        /// The amount the maximum PHY rate should be scaled by in creating
        /// a cap beyond which the detector curve is not used.
        u_int8_t iasMaxRateFactor;

        /// IAS should not be triggered if byte count increase is below this threshold
        u_int64_t iasMinDeltaBytes;

        /// IAS should not be triggered if packet count increase is below this threshold
        u_int32_t iasMinDeltaPackets;

        /// Whether interference detection should be done on single band
        /// devices or not.
        LBD_BOOL iasEnableSingleBandDetect;
    } config;

    /// Tracking information for an invocation of
    /// estimator_estimatePerSTAAirtimeOnChannel.
    struct estimatorAirtimeOnChannelState {
        /// The channel on which a measurement is being done, or
        /// LBD_CHANNEL_INVALID if one is not in progress.
        lbd_channelId_t channelId;

        /// The number of STAs for which an estimate is still pending.
        size_t numSTAsRemaining;

        /// The number of STAs for which airtime was successfully measured.
        size_t numSTAsSuccess;

        /// The number of STAs for which airtime could not be successfully
        /// measured. This is only for logging/debugging purposes.
        size_t numSTAsFailure;
    } airtimeOnChannelState;

    /// Observer for when a STA becomes eligible to have its data metrics
    /// measured again.
    struct estimatorSTADataMetricsAllowedObserver {
        LBD_BOOL isValid;
        estimator_staDataMetricsAllowedObserverCB callback;
        void *cookie;
    } staDataMetricsAllowedObservers[MAX_STA_DATA_METRICS_ALLOWED_OBSERVERS];

    /// Timer used to periodically sample the byte counter stats for STAs.
    struct evloopTimeout statsSampleTimer;

    /// Timer used to check for STAs that have not responded to an 802.11k
    /// request.
    struct evloopTimeout dot11kTimer;

    /// The time (in seconds) at which to next expire the 802.11k timer.
    struct timespec nextDot11kExpiry;

    /// The number of entries for which an 802.11k timer is running.
    size_t numDot11kTimers;

    /// Whether the debug mode for interference detection is enabled or not.
    LBD_BOOL debugModeEnabled;
};

/**
 * @brief Parameters that are needed when iterating over the BSSes when
 *        writing back the estimated rates and airtime based on an 802.11k
 *        measurement.
 */
typedef struct estimatorNonServingRateAirtimeParams_t {
    /// Whether to consider it a result overall or not.
    LBD_STATUS result;

    /// MAC address of the STA
    const struct ether_addr *staAddr;

    /// Measured BSS information
    const lbd_bssInfo_t *measuredBss;

    /// RCPI reported in 802.11k beacon report
    lbd_rcpi_t rcpi;

    /// Handle to the BSS that was measured.
    stadbEntry_bssStatsHandle_t measuredBSSStats;

    /// Value for the band that was measured (just to avoid re-resolving
    /// the band each time).
    wlanif_band_e measuredBand;

    /// Tx power on the BSS that was measured
    u_int8_t txPower;
} estimatorNonServingRateAirtimeParams_t;

extern struct estimatorPriv_t estimatorState;

// ====================================================================
// Protected functions
// ====================================================================

/**
 * @brief Perform BSA/MBSA specific initialization
 */
void estimatorSubInit(void);

/**
 * @brief Handle 802.11k beacon report and start data rate estimation
 *
 * @pre the beacon report is valid
 *
 * @param [in] handle  the handle of the STA sending the beacon report
 * @param [in] bcnrptEvent  the event containing valid beacon reports
 * @param [in] measuredBand  the band where 802.11k beacon report is measured
 * @param [out] reportedLocalBss  the local BSS reported in the beacon report if any
 *
 * @return LBD_OK if the data rate estimator succeeds; otherwise return LBD_NOK
 */
LBD_STATUS estimatorHandleValidBeaconReport(stadbEntry_handle_t handle,
                                            const wlanif_beaconReportEvent_t *bcnrptEvent,
                                            wlanif_band_e measuredBand,
                                            const lbd_bssInfo_t **reportedLocalBss);

// ====================================================================
// Functions internally shared by BSA and MBSA
// ====================================================================

/**
 * @brief Resolve the minimum PHY capabilities between STA and AP on a given BSS
 *
 * @param [in] handle  the handle to the STA
 * @param [in] addr  the MAC address of the STA
 * @param [in] bssStats  the handle to the BSS
 * @param [in] bssInfo  basic information of the given BSS
 * @param [in] bssCap  PHY capabilities of the AP on the given BSS
 * @param [out] minPhyCap  on success, return the minimum PHY capabilities
 *
 * @return LBD_NOK if no valid capabilities for the STA, otherwise return LBD_OK
 */
LBD_STATUS estimatorCmnResolveMinPhyCap(
        stadbEntry_handle_t handle, const struct ether_addr *addr,
        stadbEntry_bssStatsHandle_t bssStats, const lbd_bssInfo_t *bssInfo,
        const wlanif_phyCapInfo_t *bssCap, wlanif_phyCapInfo_t *minPhyCap);

/**
 * @brief Estimate and store rate and airtime on non-serving BSS
 *
 * @param [in] handle  the handle to the STA
 * @param [in] staAddr  the MAC address of the STA
 * @param [in] measuredBSSStats  the BSS on which the beacon report measurement is done
 * @param [in] nonServingBSSStats  the BSS to estimate rate and airtime
 * @param [in] targetBSSInfo  the info of target BSS
 * @param [in] targetPHYCap  the PHY capability on target BSS
 * @param [in] measuredRCPI  the RCPI valid reported in beacon report
 * @param [in] measuredBSSTxPower  the Tx power on BSS where beacon report
 *                                 measurement is done
 *
 * @return LBD_OK if the estimation and store succeeds, otherwise return LBD_NOK
 */
LBD_STATUS estimatorCmnEstimateNonServingRateAirtime(
        stadbEntry_handle_t handle, const struct ether_addr *staAddr,
        stadbEntry_bssStatsHandle_t measuredBSSStats,
        stadbEntry_bssStatsHandle_t nonServingBSSStats,
        const lbd_bssInfo_t *targetBSSInfo,
        const wlanif_phyCapInfo_t *targetPHYCap,
        lbd_rcpi_t measuredRCPI, u_int8_t measuredBSSTxPower);

/**
 * @brief Handle a beacon report containing info of local BSS
 *
 * @param [in] handle  the handle to the STA
 * @param [in] staAddr  the MAC address of the STA
 * @param [in] reportedLocalBss  the BSS reported in beacon report
 * @param [inout] params  @see estimatorNonServingRateAirtimeParams_t for details
 */
void estimatorCmnHandleLocalBeaconReport(
        stadbEntry_handle_t entry, const struct ether_addr *staAddr,
        const lbd_bssInfo_t *reportedLocalBss,
        estimatorNonServingRateAirtimeParams_t *params);

/**
 * @brief Send the log indicating that a BSS's polluted state changed
 *        for a given STA.
 *
 * @param [in] addr  the MAC address of the STA
 * @param [in] bssInfo  the BSS that pollution state changed
 * @param [in] polluted  new pollution state
 * @param [in] reasonCode  the reason why pollution state changed
 */
void estimatorCmnDiaglogSTAPollutionChanged(
        const struct ether_addr *addr, const lbd_bssInfo_t *bssInfo,
        LBD_BOOL polluted, estimatorPollutionChangedReason_e reasonCode);


/**
 * @brief Start the pollution timer running if it is not running, or reschedule
 *        it if it currently running but scheduled to expire after the given
 *        time.
 *
 * @param [in] staAddr  the STA for which the timer is being started
 * @param [in] entry  the handle for this entry
 * @param [in] timerSecs  the duration of the timer (in seconds)
 */
void estimatorCmnStartPollutionTimer(
        const struct ether_addr *staAddr, stadbEntry_handle_t entry,
        unsigned timerSecs);

/**
 * @brief Generate an event indicating pollution state being cleared on the given STA
 *
 * @param [in] staAddr  MAC address of the given STA
 */
void estimatorCmnGeneratePollutionClearEvent(const struct ether_addr *staAddr);

#if defined(__cplusplus)
}
#endif

#endif // estimatorCmn__h
