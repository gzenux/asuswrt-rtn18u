// vim: set et sw=4 sts=4 cindent:
/*
 * @File: steeralgCmn.h
 *
 * @Abstract: Functions shared by steeralgBSA and steeralgMBSA
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

#ifndef steeralgCmn__h
#define steeralgCmn__h

#include <dbg.h>

#include "steeralg.h"
#include "stadbEntry.h"
#include "estimator.h"
#include "steerexec.h"

#if defined(__cplusplus)
extern "C" {
#endif

// ====================================================================
// Protected members (for use within the common functions and any
// "derived" functions that may be using this component).
// ====================================================================

/**
 * @brief Internal structure for offloading candidate
 */
typedef struct steeralgCmnOffloadingCandidateEntry_t {
    /// The handle to the candidate STA
    stadbEntry_handle_t entry;

    /// The metric of this candidate, used for sorting
    /// Bit 15:  Set if prefered to be offloaded
    /// Bit 0-7: The estimated airtime of this STA
    u_int16_t metric;
#define STEERALG_OFFLOADING_CANDIDATE_PREFER_BIT 15
#define STEERALG_OFFLOADING_CANDIDATE_AIRTIME_MASK 0xFF
} steeralgCmnOffloadingCandidateEntry_t;

/**
 * @brief Internal state for the BSS steeralg module.
 */
typedef struct steeralgPriv_t {
    struct dbgModule *dbgModule;

    /// Configuration data obtained at init time
    struct {
        /// RSSI threshold when inactive
        lbd_rssi_t inactRSSIXingThreshold[wlanif_band_invalid];

        /// Low Tx rate threshold on 5 GHz (Mbps)
        lbd_linkCapacity_t lowTxRateThreshold;

        /// High Tx rate threshold on 2.4 GHz (Mbps)
        lbd_linkCapacity_t highTxRateThreshold;

        /// Minimum rate improvement over the lowTxRateThreshold
        /// when steering from 2.4GHz to 5GHz
        lbd_linkCapacity_t minTxRateIncreaseThreshold;

        /// The lower-bound RSSI value below which a client on 5GHz
        /// is eligible for downgrade to 2.4GHz.
        u_int8_t lowRateRSSIXingThreshold;

        /// When evaluating a STA for upgrade from 2.4GHz to 5GHz, the RSSI must
        /// also exceed this value.
        u_int8_t highRateRSSIXingThreshold;

        /// Number of seconds allowed for a measurement to
        /// be considered as recent
        u_int8_t freshnessLimit;

        /// Whether to consider PHY capability when sorting BSSes or clients
        /// for idle steering, offloading or selecting 11k channel
        LBD_BOOL phyBasedPrioritization;

        /// The RSSI threshold serving channel RSSI must be above to consider
        /// 2.4 GHz BSS as idle offloading candidate
        u_int8_t rssiSafetyThreshold;

        /// The minimum difference of upstream AP's downlink RSSI must be above the
        /// one of serving AP to be considered as an AP steering candidate
        lbd_rcpi_t apSteerToRootMinRSSIIncreaseThreshold;

        /// The minimum difference of downstream AP's downlink RSSI must be above the
        /// one of serving AP to be considered as an AP steering candidate
        lbd_rcpi_t apSteerToLeafMinRSSIIncreaseThreshold;

        /// The minimum difference of peer AP's downlink RSSI must be above the
        /// one of serving AP to be considered as an AP steering candidate
        lbd_rcpi_t apSteerToPeerMinRSSIIncreaseThreshold;

        /// The RSSI threshold downlink RSSI must be above to consider steering
        /// to 5 GHz channel
        lbd_rcpi_t dlRSSIThresholdW5;

        /// Maximum number of candidate BSSes allowed when steering a client.
        u_int8_t maxSteeringTargetCount;
    } config;

    /// A queue holding overloaded channels that have been offloaded
    struct {
        /// Channel ID, LBD_CHANNEL_INVALID if this entry is invalid
        lbd_channelId_t channelId;

        /// the time when it was served
        time_t lastServingTime;
    } servedChannels[WLANIF_MAX_RADIOS];

    /// Offloading overloaded channel related info
    struct {
        /// Whether there is an airtime estimate pending
        LBD_BOOL airtimeEstimatePending : 1;

        /// Whether offloading by steering clients away is in progress.
        /// This should happen after airtime estimation completes.
        LBD_BOOL inProgress : 1;

        /// The channel being offloaded
        lbd_channelId_t channelId;

        /// A list of clients that can be offloaded;
        /// it should be sorted based on the occupied airtime.
        steeralgCmnOffloadingCandidateEntry_t *candidateList;

        /// Number of clients in candidateList
        size_t numCandidates;

        /// Index of the client in candidateList that has an 802.11k
        /// measuremnt pending; candidates before the index should have
        /// been processed.
        size_t headIdx;

        /// Total airtime that has been offloaded from
        /// the overloaded channel.
        lbd_airtime_t totalAirtimeOffloaded;
    } offloadState;

    /// Number of channels that are active on this device
    u_int8_t numActiveChannels;
} steeralgPriv_t;

extern steeralgPriv_t steeralgState;

/**
 * @brief Parameters used when iterating over STA BSS stats to determine
 *        the target BSS for a given STA
 */
typedef struct steeralgCmnServingBSSInfo_t {
    stadbEntry_bssStatsHandle_t stats;
    const lbd_bssInfo_t *bssInfo;
    wlanif_band_e band;
    lbd_linkCapacity_t dlRate;
    LBD_BOOL isOverloaded;
    steeralg_rateSteerEligibility_e rateSteerEligibility;
    wlanif_phymode_e bestPHYMode;
    LBD_BOOL isOnStrongest5G;
    steerexec_reason_e trigger;
    LBD_BOOL isPolluted;
} steeralgCmnServingBSSInfo_t;

// ====================================================================
// Functions internally shared by BSA and MBSA
// ====================================================================

/**
 * @brief Determine if the steering reason reflects an active steer or not.
 *
 * @param [in] reason  the type of steering being performed
 *
 * @return LBD_TRUE if it is an active steer; otherwise LBD_FALSE
 */
LBD_BOOL steeralgCmnIsActiveSteer(steerexec_reason_e reason);

/**
 * @brief Determine if the steering reason reflects an active
 *        upgrade/downgrade or not.
 *
 * @param [in] reason  the type of steering being performed
 *
 * @return LBD_TRUE if it is an active upgrade/downgrade; otherwise LBD_FALSE
 */
LBD_BOOL steeralgCmnIsActiveUpgradeDowngrade(steerexec_reason_e reason);

/**
 * @brief Compute a metric for a given BSS based on its band, Tx power,
 *        reserved airtime and utilization info.
 *
 * This is currently used for determining 11k and idle steer candidate.
 * The weigh of each factor is based on the offset given.
 *
 * @param [in] entry  the client to compute this metric for
 * @param [in] bssHandle  the given BSS
 * @param [in] preferedBand  set the band bit in metric to 1 if the BSS
 *                           is operating on this prefered band
 * @param [in] bestPHYMode  the best PHY mode supported by the client
 * @param [in] offsetBand  offset in the metric for band
 * @param [in] offsetPHYCap  offset in the metric for PHY capability
 * @param [in] offsetReservedAirtime  offset in the metric for reserved airtime
 * @param [in] offsetSafety  offset in the metric for MU below safety threshold
 * @param [in] offsetUtil  offset in the metric for measured MU
 */
u_int32_t steeralgCmnComputeBSSMetric(
        stadbEntry_handle_t entry, stadbEntry_bssStatsHandle_t bssHandle,
        wlanif_band_e preferedBand, wlanif_phymode_e bestPHYMode,
        u_int32_t offsetBand, u_int32_t offsetPHYCap, u_int32_t offsetReservedAirtime,
        u_int32_t offsetSafety, u_int32_t offsetUtil);

/**
 * @brief Perform the steering operation
 *
 * @pre There is at least one candidate BSS.
 *
 * @param [in] entry  the STA that needs to be steered
 * @param [in] numBSS  number of candidate BSSes
 * @param [in] bssCandidates  candidate BSSes
 * @param [in] reason  reason for the steer
 *
 * @return LBD_OK if the STA has been successfully steered;
 *         otherwise return LBD_NOK
 */
LBD_STATUS steeralgCmnDoSteering(stadbEntry_handle_t entry, size_t numBSS,
                                 const lbd_bssInfo_t *bssCandidates,
                                 steerexec_reason_e trigger);

/**
 * @brief Finish offloading process
 *
 * Free allocated candidate list and clear offloading state. If not triggered
 * by fini, it will request one shot medium utilization event to get informed
 * of new measurement.
 *
 * @param [in] requestOneShotUtil  whether to request one shot
 *                                 medium utilization event
 */
void steeralgCmnFinishOffloading(LBD_BOOL requestOneShotUtil);

/**
 * @brief Try to steer an active client across band
 *
 * @param [in] handle  the handle to the active client
 * @param [in] staAddr  the MAC address of the active client
 *
 * @return LBD_OK if the client is being steered successfully; otherwise return LBD_NOK
 */
LBD_STATUS steeralgCmnSteerActiveClient(stadbEntry_handle_t handle,
                                        const struct ether_addr *staAddr);

// ====================================================================
// Protected functions
// ====================================================================

/**
 * @brief Callback function to check if we want to measure the downlink RSSI by sending
 *        802.11k beacon report request on a BSS
 *
 * If a BSS is a candidate, it must return a non-zero metric.
 *
 * @pre the STA entry is associated
 *
 * @param [in] entry  the STA entry
 * @param [in] bssHandle  the BSS handle to check
 * @param [in] cookie  currently not used
 *
 * @return the non-zero metric if the BSS is an 802.11k candidate;
 *         otherwise return 0
 */
u_int32_t steeralgSelect11kChannelCallback(stadbEntry_handle_t entry,
                                           stadbEntry_bssStatsHandle_t bssHandle,
                                           void *cookie);

/**
 * @brief React to the event indicating metric collection is complete for an active client
 *
 * @param [in] handle  the handle to the client
 * @param [in] event  the event containing metric collection result and trigger
 *
 * @return LBD_OK if the client has been successfully steered; otherwise return LBD_NOK
 */
LBD_STATUS steeralgHandleSTAMetricsForActiveClient(
        stadbEntry_handle_t handle, const estimator_staDataMetricsCompleteEvent_t *event);

/**
 * @brief React to the event indicating metric collection is complete for an active client
 *
 * @param [in] handle  the handle to the client
 * @param [in] event  the event containing metric collection result and trigger
 */
void steeralgHandleSTAMetricsForIdleClient(
        stadbEntry_handle_t handle, const estimator_staDataMetricsCompleteEvent_t *event);

/**
 * @brief Check if a BSS can be the target to steer the STA
 *
 * It will check:
 * 1. Channel overload condition
 * 2. After adding the STA, the BSS is still below safety threshold
 *
 * @param [in] entry  the handle to the STA
 * @param [in] bssHandle  the handle to the BSS
 * @param [in] bss  BSS information
 * @param [in] isActive  whether the STA is active
 * @param [out] availableAirtime  if the BSS can support the STA, available
 *                                airtime left on this BSS; otherwise, set to
 *                                LBD_INVALID_AIRTIME
 *
 * @return LBD_TRUE if the BSS can be a steer target; otherwise return LBD_FALSE
 */
LBD_BOOL steeralgCmnCanBSSSupportClient(stadbEntry_handle_t entry,
                                        stadbEntry_bssStatsHandle_t bssHandle,
                                        const lbd_bssInfo_t *bss, LBD_BOOL isActive,
                                        lbd_airtime_t *availableAirtime);

#if defined(__cplusplus)
}
#endif

#endif // steeralgCmn__h
