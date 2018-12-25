// vim: set et sw=4 sts=4 cindent:
/*
 * @File: stamonCmn.c
 *
 * @Abstract: Implementation of station monitor public APIs
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

#include <stdint.h>
#include <stdlib.h>
#include <time.h>

#ifdef LBD_DBG_MENU
#include <cmd.h>
#endif

#include "lb_common.h"
#include "lb_assert.h"
#include "module.h"
#include "profile.h"
#include "stadb.h"
#include "steerexec.h"
#include "bandmon.h"
#include "steeralg.h"
#include "estimator.h"

#include "stamon.h"
#include "stamonCmn.h"

struct stamonPriv_t stamonState;

// Forward decls
static void stamonCmnActivityObserver(stadbEntry_handle_t entry, void *cookie);
static void stamonCmnSteeringObserver(stadbEntry_handle_t entry, void *cookie);
static void stamonCmnEstimatorObserver(stadbEntry_handle_t entry, void *cookie);
static void stamonCmnRSSIObserver(stadbEntry_handle_t entry,
                                  stadb_rssiUpdateReason_e reason, void *cookie);
static void stamonCmnHandleSTABecomeActive(stadbEntry_handle_t entry);
static void stamonCmnHandleSTABecomeIdle(stadbEntry_handle_t entry);
static void stamonCmnHandleUtilizationChange(struct mdEventNode *event);
static void stamonCmnHandleOverloadChange(struct mdEventNode *event);
static void stamonCmnHandleTxRateXing(struct mdEventNode *event);
static void stamonCmnHandleInterferenceDetected(struct mdEventNode *event);
static void stamonCmnHandlePollutionCleared(struct mdEventNode *event);
static void stamonCmnStaDBIterateCB(stadbEntry_handle_t entry, void *cookie);
static void stamonCmnStaDBIterateUtilizationCB(stadbEntry_handle_t entry, void *cookie);
static steerexec_steerEligibility_e stamonCmnDetermineSteerEligibility(stadbEntry_handle_t entry);
static LBD_BOOL stamonCmnIsSteerCandidate(stadbEntry_handle_t handle, LBD_BOOL *isActive);
static void stamonCmnMakeSteerDecisionActive(stadbEntry_handle_t entry);

/**
 * @brief Default configuration values.
 *
 * These are used if the config file does not specify them.
 */
static struct profileElement stamonCmnElementDefaultTable[] = {
    { STAMON_RSSI_MEASUREMENT_NUM_SAMPLES_W2_KEY, "5" },
    { STAMON_RSSI_MEASUREMENT_NUM_SAMPLES_W5_KEY, "5" },
    { STAMON_AGE_LIMIT_KEY,                       "5" },
    // From wlanifBSteerControl
    { STAMON_HIGH_TX_RATE_XING_THRESHOLD,         "50000"},
    { STAMON_LOW_TX_RATE_XING_THRESHOLD,          "6000"},
    { STAMON_LOW_RATE_RSSI_XING_THRESHOLD,        "0"},
    { STAMON_HIGH_RATE_RSSI_XING_THRESHOLD,       "40"},
    // Only necessary for multi-AP setup. By default they
    // are all invalid and must be explicitly specified when
    // running in multi-AP mode.
    { STAMON_INACT_RSSI_DG_THRESHOLD,                    "0"},
    { STAMON_LOW_AP_STEER_RSSI_XING_THRESHOLD_W2_KEY,    "0"},
    { STAMON_LOW_AP_STEER_RSSI_XING_THRESHOLD_W5_KEY,    "0"},
    { NULL, NULL }
};


// ====================================================================
// Public API
// ====================================================================

LBD_STATUS stamon_init(void) {
    stamonState.dbgModule = dbgModuleFind("stamon");
    stamonState.dbgModule->Level = DBGINFO;

    if (stadb_registerActivityObserver(stamonCmnActivityObserver, &stamonState) != LBD_OK ||
        stadb_registerRSSIObserver(stamonCmnRSSIObserver, &stamonState) != LBD_OK ||
        steerexec_registerSteeringAllowedObserver(stamonCmnSteeringObserver,
                                                  &stamonState) != LBD_OK ||
        estimator_registerSTADataMetricsAllowedObserver(stamonCmnEstimatorObserver,
                                                        &stamonState) != LBD_OK) {
        return LBD_NOK;
    }

    stamonState.config.instRSSINumSamples[wlanif_band_24g] =
        profileGetOptsInt(mdModuleID_StaMon,
                          STAMON_RSSI_MEASUREMENT_NUM_SAMPLES_W2_KEY,
                          stamonCmnElementDefaultTable);
    stamonState.config.instRSSINumSamples[wlanif_band_5g] =
        profileGetOptsInt(mdModuleID_StaMon,
                          STAMON_RSSI_MEASUREMENT_NUM_SAMPLES_W5_KEY,
                          stamonCmnElementDefaultTable);
    stamonState.config.freshnessLimit =
        profileGetOptsInt(mdModuleID_StaMon,
                          STAMON_AGE_LIMIT_KEY,
                          stamonCmnElementDefaultTable);

    u_int32_t rate =
        profileGetOptsInt(mdModuleID_StaMon,
                          STAMON_LOW_TX_RATE_XING_THRESHOLD,
                          stamonCmnElementDefaultTable);

    // Convert from the Kbps config value to Mbps
    stamonState.config.lowTxRateCrossingThreshold = rate / 1000;

    rate = profileGetOptsInt(mdModuleID_StaMon,
                             STAMON_HIGH_TX_RATE_XING_THRESHOLD,
                             stamonCmnElementDefaultTable);

    // Convert from the Kbps config value to Mbps
    stamonState.config.highTxRateCrossingThreshold = rate / 1000;

    // Don't do any checking of the wlanif variables here - wlanif will
    // restart lbd if necessary.

    stamonState.config.lowRateRSSIXingThreshold =
        profileGetOptsInt(mdModuleID_StaMon,
                          STAMON_LOW_RATE_RSSI_XING_THRESHOLD,
                          stamonCmnElementDefaultTable);

    stamonState.config.highRateRSSIXingThreshold =
        profileGetOptsInt(mdModuleID_StaMon,
                          STAMON_HIGH_RATE_RSSI_XING_THRESHOLD,
                          stamonCmnElementDefaultTable);

    stamonState.config.inactRSSIXingThreshold_DG =
        profileGetOptsInt(mdModuleID_StaMon,
                          STAMON_INACT_RSSI_DG_THRESHOLD,
                          stamonCmnElementDefaultTable);

    stamonState.config.apSteerLowRSSIXingThresholds[wlanif_band_24g] =
        profileGetOptsInt(mdModuleID_StaMon,
                          STAMON_LOW_AP_STEER_RSSI_XING_THRESHOLD_W2_KEY,
                          stamonCmnElementDefaultTable);
    stamonState.config.apSteerLowRSSIXingThresholds[wlanif_band_5g] =
        profileGetOptsInt(mdModuleID_StaMon,
                          STAMON_LOW_AP_STEER_RSSI_XING_THRESHOLD_W5_KEY,
                          stamonCmnElementDefaultTable);

    mdListenTableRegister(mdModuleID_BandMon, bandmon_event_overload_change,
                          stamonCmnHandleOverloadChange);

    mdListenTableRegister(mdModuleID_BandMon, bandmon_event_utilization_update,
                          stamonCmnHandleUtilizationChange);

    mdListenTableRegister(mdModuleID_WlanIF, wlanif_event_tx_rate_xing,
                          stamonCmnHandleTxRateXing);

    mdListenTableRegister(mdModuleID_Estimator, estimator_event_staInterferenceDetected,
                          stamonCmnHandleInterferenceDetected);

    mdListenTableRegister(mdModuleID_Estimator, estimator_event_staPollutionCleared,
                          stamonCmnHandlePollutionCleared);

    return LBD_OK;
}

LBD_STATUS stamon_fini(void) {
    LBD_STATUS status = LBD_OK;
    status |=
        stadb_unregisterActivityObserver(stamonCmnActivityObserver, &stamonState);
    status |=
        stadb_unregisterRSSIObserver(stamonCmnRSSIObserver, &stamonState);
    status |=
        steerexec_unregisterSteeringAllowedObserver(stamonCmnSteeringObserver,
                                                    &stamonState);
    status |=
        estimator_unregisterSTADataMetricsAllowedObserver(stamonCmnEstimatorObserver,
                                                          &stamonState);
    return status;
}

// ====================================================================
// Private helper functions
// ====================================================================

/**
 * @brief Handle the activity status update about a STA become active
 *
 * @param [in] entry  the STA that becomes active
 */
static void stamonCmnHandleSTABecomeActive(stadbEntry_handle_t entry) {
    // Determine if this steer should be aborted.
    if (steerexec_shouldAbortSteerForActive(entry)) {
        steerexec_abort(entry, NULL);
        return;
    }

    // If the device can be steered while active, there is nothing
    // further to do.
}

/**
 * @brief Handle the activity status update about a STA become idle
 *
 * @param [in] entry  the STA that becomes idle
 */
static void stamonCmnHandleSTABecomeIdle(stadbEntry_handle_t entry) {
    stamonMakeSteerDecisionIdle(entry);
}


/**
 * @brief Either an activity change or steering allowed event
 *        has occurred for a STA.
 *
 * @param [in] entry STA to evaluate
 * @param [in] activityUpdate LBD_TRUE if the triggering event was an
 *                            activity change (transition to active or
 *                            inactive)
 */
static void stamonCmnTriggerActivityOrSteering(stadbEntry_handle_t entry,
                                               LBD_BOOL activityUpdate) {
    LBD_BOOL isActive;
    if (!stamonCmnIsSteerCandidate(entry, &isActive)) {
        return;
    }

    steerexec_steerEligibility_e eligibility = steerexec_steerEligibility_none;
    if (!isActive || !activityUpdate) {
        eligibility = steerexec_determineSteeringEligibility(entry);
    }

    if (isActive) {
        if (!activityUpdate) {
            // Triggered by STA becoming steerable or became eligible for
            // its data metrics to be measured again.
            if (eligibility == steerexec_steerEligibility_active) {
                stamonCmnMakeSteerDecisionActive(entry);
            }
        } else {
            // Triggered by STA becoming active.
            stamonCmnHandleSTABecomeActive(entry);
        }
    } else {
        if (eligibility != steerexec_steerEligibility_none) {
            // Action is the same for Idle STAs, regardless of the trigger.
            stamonCmnHandleSTABecomeIdle(entry);
        }
    }
}

/**
 * @brief Callback function invoked by the station database module when
 *        the activity status for a specific STA has been
 *        updated.
 *
 * @param [in] entry  the entry that was updated
 * @param [in] cookie  the pointer to our internal state
 */
static void stamonCmnActivityObserver(stadbEntry_handle_t entry, void *cookie) {
    stamonCmnTriggerActivityOrSteering(entry,
                                       LBD_TRUE /* activityUpdate */);
}

/**
 * @brief Callback function invoked by the steering executor module when
 *        a specific STA has become eligible to be steered.
 *
 * @param [in] entry  the entry that was updated
 * @param [in] cookie  the pointer to our internal state
 */
static void stamonCmnSteeringObserver(stadbEntry_handle_t entry, void *cookie) {
    stamonCmnTriggerActivityOrSteering(entry,
                                       LBD_FALSE /* activityUpdate */);
}

/**
 * @brief Callback function invoked by the estimator module when
 *        a specific STA has become eligible to have its data metrics measured
 *        again.
 *
 * @param [in] entry  the entry that was updated
 * @param [in] cookie  the pointer to our internal state
 */
static void stamonCmnEstimatorObserver(stadbEntry_handle_t entry, void *cookie) {
    stamonCmnTriggerActivityOrSteering(entry,
                                       LBD_FALSE /* activityUpdate */);
}

/**
 * @brief Callback function invoked by the station database module when
 *        the RSSI for a specific STA has been updated.
 *
 * For a dual-band and idle STA, estimate RSSI value on the other band
 * based on the RSSI measurement received, and make the steering decision
 * based on the estimated RSSI value.
 *
 * @param [in] entry  the entry that was updated
 * @param [in] reason  the reason for the updated RSSI measurement
 * @param [in] cookie  the pointer to our internal state
 */
static void stamonCmnRSSIObserver(stadbEntry_handle_t entry,
                                  stadb_rssiUpdateReason_e reason, void *cookie) {
    steerexec_steerEligibility_e eligibility = stamonCmnDetermineSteerEligibility(entry);
    if (eligibility == steerexec_steerEligibility_idle) {
        stamonMakeSteerDecisionIdle(entry);
    } else if (eligibility == steerexec_steerEligibility_active) {
        stamonCmnMakeSteerDecisionActive(entry);
    }
}

/**
 * @brief React to an event providing the updated overload status information
 */
static void stamonCmnHandleOverloadChange(struct mdEventNode *event) {
    if (stadb_iterate(stamonCmnStaDBIterateCB, NULL) != LBD_OK) {
        dbgf(stamonState.dbgModule, DBGERR,
             "%s: Failed to iterate over STA DB; will wait for RSSI "
             "or inactivity updates", __func__);
        return;
    }
}

/**
 * @brief React to an event indicating utilization is updated
 */
static void stamonCmnHandleUtilizationChange(struct mdEventNode *event) {
    const bandmon_utilizationUpdateEvent_t *util =
        (const bandmon_utilizationUpdateEvent_t *)event->Data;

    if (!util) {
        return;
    }

    lbd_channelId_t channels[WLANIF_MAX_RADIOS];

    // Get the set of channels from wlanif.
    u_int8_t channelCount = wlanif_getChannelList(&channels[0], NULL /* chwidthList */,
                                                  WLANIF_MAX_RADIOS);

    if (util->numOverloadedChannels >= channelCount) {
        // All channels are overloaded, so can't do anything now.
        // Request notification for the next utilization update.
        bandmon_enableOneShotUtilizationEvent();

        return;
    }

    if (stadb_iterate(stamonCmnStaDBIterateUtilizationCB, NULL) != LBD_OK) {
        dbgf(stamonState.dbgModule, DBGERR,
             "%s: Failed to iterate over STA DB (triggered by utilization update)", __func__);
        return;
    }
}

/**
 * @brief A rate crossing event has occurred. General evaluation
 *        to determine if we should now steer the STA.
 *
 * @param [in] staAddr MAC address of the STA that generated the
 *                     event
 * @param [in] bss  BSS the STA is associated on
 * @param [in] band  band the STA is associated on
 * @param [in] tx_rate  last Tx rate used to the STA (0 if
 *                      unknown)
 * @param [in] xing  crossing direction
 */
static void stamonCmnActiveSteerRateXing(const struct ether_addr *staAddr,
                                         const lbd_bssInfo_t *bss,
                                         wlanif_band_e band, u_int32_t txRate,
                                         wlanif_xingDirection_e xing) {
    // Get the stadb entry for the event
    stadbEntry_handle_t entry = stadb_find(staAddr);
    steerexec_reason_e trigger = steerexec_reason_invalid;
    if (!entry) {
        // Unknown MAC address
        dbgf(stamonState.dbgModule, DBGERR,
             "%s: Received Tx rate crossing event from unknown MAC address: "
             lbMACAddFmt(":") " on BSS " lbBSSInfoAddFmt(),
             __func__, lbMACAddData(staAddr),
             lbBSSInfoAddData(bss));
        return;
    }

    if (steerexec_steerEligibility_active !=
            stamonCmnDetermineSteerEligibility(entry)) {
        // This device can not be steered while active, return.
        // If it can be steered later, we will revisit this STA then.
        return;
    }

    lbd_rssi_t rssi = LBD_INVALID_RSSI;
    if (xing == wlanif_xing_down) {
        dbgf(stamonState.dbgModule, DBGINFO,
             "%s: Device " lbMACAddFmt(":") " eligible for downgrade at rate %u",
             __func__, lbMACAddData(staAddr->ether_addr_octet), txRate);
        trigger = steerexec_reason_activeDowngradeRate;
    } else if (stamonCmnGetUplinkRSSI(entry, &rssi) == LBD_OK &&
               stamonCmnIsEligibleForActiveUpgrade(staAddr, band, txRate, rssi)) {
        trigger = steerexec_reason_activeUpgrade;
    }

    if (trigger != steerexec_reason_invalid) {
        stamonCmnTriggerActiveSteering(entry, staAddr, trigger);
    }
}

/**
 * @brief React to an event indicating Tx rate has crossed a
 *        threshold.
 */
static void stamonCmnHandleTxRateXing(struct mdEventNode *event) {
    const wlanif_txRateXingEvent_t *xing =
        (const wlanif_txRateXingEvent_t *)event->Data;

    if (!xing) {
        return;
    }

    // Check this is an event we need to act on.
    if ((xing->xing != wlanif_xing_up) && (xing->xing != wlanif_xing_down)) {
        // Invalid crossing.
        return;
    }

    // Get the band this event occurred on.
    wlanif_band_e band = wlanif_resolveBandFromChannelNumber(xing->bss.channelId);
    if (band >= wlanif_band_invalid) {
        // Invalid band.
        return;
    }

    // Shouldn't ever get a Tx rate crossing event with a rate of 0
    if (!xing->tx_rate) {
        dbgf(stamonState.dbgModule, DBGERR,
             "%s: Received Tx rate crossing in direction %d on band %d"
             " from MAC address " lbMACAddFmt(":") " on BSS " lbBSSInfoAddFmt()
             " with a Tx rate of 0, ignoring",
             __func__, xing->xing, band, lbMACAddData(xing->sta_addr.ether_addr_octet),
             lbBSSInfoAddData(&xing->bss));
        return;
    }

    // Check the direction of the crossing corresponds to the band it occured on.
    if (((band == wlanif_band_5g) && (xing->xing != wlanif_xing_down)) ||
        ((band == wlanif_band_24g) && (xing->xing != wlanif_xing_up))) {
        // Will only attempt to upgrade 2.4GHz clients and downgrade 5GHz clients.
        dbgf(stamonState.dbgModule, DBGERR,
             "%s: Received unexpected Tx rate crossing in direction %d on band %d"
             " from MAC address " lbMACAddFmt(":") " on BSS " lbBSSInfoAddFmt(),
             __func__, xing->xing, band, lbMACAddData(xing->sta_addr.ether_addr_octet),
             lbBSSInfoAddData(&xing->bss));
        return;
    }

    stamonCmnActiveSteerRateXing(&xing->sta_addr, &xing->bss, band,
                                 xing->tx_rate, xing->xing);
}

/**
 * @brief Handler for each entry in the station database.
 *
 * @param [in] entry  the current entry being examined
 * @param [in] cookie  the parameter provided in the stadb_iterate call
 */
static void stamonCmnStaDBIterateCB(stadbEntry_handle_t entry, void *cookie) {
    steerexec_steerEligibility_e eligibility = stamonCmnDetermineSteerEligibility(entry);
    if (eligibility == steerexec_steerEligibility_idle) {
        stamonMakeSteerDecisionIdle(entry);
    }
}

/**
 * @brief Handler for each entry in the station database.
 *        Triggered by utilization update.
 *
 * @param [in] entry  the current entry being examined
 * @param [in] cookie  the parameter provided in the stadb_iterate call
 */
static void stamonCmnStaDBIterateUtilizationCB(stadbEntry_handle_t entry, void *cookie) {
    steerexec_steerEligibility_e eligibility = stamonCmnDetermineSteerEligibility(entry);
    if (eligibility == steerexec_steerEligibility_active) {
        stamonCmnMakeSteerDecisionActive(entry);
    }
}

/**
 * @brief Check if a given STA can be a steering candidate
 *
 * @param [in] entry  the handle of the given STA
 *
 * @return Eligibility for steering based on the activity.  If
 *         the client can be steered while active or idle and is
 *         currently idle, will return
 *         steerexec_steerEligibility_idle.  If the client can
 *         be steered while active and is currently active, will
 *         return steerexec_steerEligibility_active.  If the
 *         client can't be steered, will return
 *         steerexec_steerEligibility_none.
 */
static steerexec_steerEligibility_e
stamonCmnDetermineSteerEligibility(stadbEntry_handle_t entry) {
    LBD_BOOL isActive;
    if (!stamonCmnIsSteerCandidate(entry, &isActive)) {
        return steerexec_steerEligibility_none;
    }

    steerexec_steerEligibility_e eligibility =
        steerexec_determineSteeringEligibility(entry);
    if (((eligibility == steerexec_steerEligibility_idle) && isActive) ||
        (eligibility == steerexec_steerEligibility_none)) {
        return steerexec_steerEligibility_none;
    }

    // We can steer this device, return eligibility based on activity
    if (isActive) {
        return steerexec_steerEligibility_active;
    }
    return steerexec_steerEligibility_idle;
}

/**
 * @brief Check if a client can be steered
 *
 * @param [in] entry  the handle to the client to check
 * @param [out] isActive  whether the client is active or not
 *
 * return LBD_TRUE if the client is associated, dual band capable
 *                 with valid activity status and does not have
 *                 reserved airtime on serving BSS; otherwise, return
 *                 LBD_FALSE
 */
static LBD_BOOL stamonCmnIsSteerCandidate(stadbEntry_handle_t entry,
                                          LBD_BOOL *isActive) {
    stadbEntry_bssStatsHandle_t servingBSS = stadbEntry_getServingBSS(entry, NULL);
    return servingBSS && stadbEntry_isDualBand(entry) &&
           LBD_OK == stadbEntry_getActStatus(entry, isActive, NULL) &&
           LBD_INVALID_AIRTIME == stadbEntry_getReservedAirtime(entry, servingBSS);
}

/**
 * @brief React to an event indicating interference is detected for a STA
 */
static void stamonCmnHandleInterferenceDetected(struct mdEventNode *event) {
    const estimator_staInterferenceDetectedEvent_t *info =
        (const estimator_staInterferenceDetectedEvent_t *)event->Data;

    stadbEntry_handle_t entry = stadb_find(&info->addr);
    if (!entry) {
        dbgf(stamonState.dbgModule, DBGERR,
             "%s: Received interference detected event from unknown MAC address: "
             lbMACAddFmt(":"),
             __func__, lbMACAddData(info->addr.ether_addr_octet));
        return;
    }

    steerexec_steerEligibility_e eligibility = stamonCmnDetermineSteerEligibility(entry);
    if (steerexec_steerEligibility_active == eligibility) {
        dbgf(stamonState.dbgModule, DBGINFO,
             "%s: Device " lbMACAddFmt(":") " eligible for active interference avoidance steering",
             __func__, lbMACAddData(info->addr.ether_addr_octet));
        stamonCmnTriggerActiveSteering(entry, &info->addr,
                                       steerexec_reason_interferenceAvoidance);
    } else if (steerexec_steerEligibility_idle == eligibility) {
        dbgf(stamonState.dbgModule, DBGINFO,
             "%s: Device " lbMACAddFmt(":") " eligible for idle interference avoidance steering",
             __func__, lbMACAddData(info->addr.ether_addr_octet));
        stamonMakeSteerDecisionIdle(entry);
    }
}

/**
 * @brief React to an event indicating at least one BSS for a STA is no longer
 *        polluted.
 */
static void stamonCmnHandlePollutionCleared(struct mdEventNode *event) {
    const estimator_staPollutionClearedEvent_t *info =
        (const estimator_staPollutionClearedEvent_t *)event->Data;

    stadbEntry_handle_t entry = stadb_find(&info->addr);
    if (!entry) {
        dbgf(stamonState.dbgModule, DBGERR,
             "%s: Received pollution cleared event from unknown MAC address: "
             lbMACAddFmt(":"),
             __func__, lbMACAddData(info->addr.ether_addr_octet));
        return;
    }

    stamonCmnTriggerActivityOrSteering(entry,
                                       LBD_FALSE /* activityUpdate */);
}

static void stamonCmnMakeSteerDecisionActive(stadbEntry_handle_t entry) {
    const struct ether_addr *staAddr = stadbEntry_getAddr(entry);
    lbDbgAssertExit(stamonState.dbgModule, staAddr);
    stadbEntry_bssStatsHandle_t servingBSS = stadbEntry_getServingBSS(entry, NULL);
    const lbd_bssInfo_t *bss = stadbEntry_resolveBSSInfo(servingBSS);
    lbDbgAssertExit(stamonState.dbgModule, bss);
    wlanif_band_e band = wlanif_resolveBandFromChannelNumber(bss->channelId);
    lbDbgAssertExit(stamonState.dbgModule, band != wlanif_band_invalid);

    steerexec_reason_e trigger = steerexec_reason_invalid;

    do {
        // First check if it qualifies for IAS
        LBD_BOOL polluted = LBD_FALSE;
        if (LBD_OK == stadbEntry_getPolluted(entry, servingBSS, &polluted, NULL) &&
            polluted) {
            dbgf(stamonState.dbgModule, DBGINFO,
                 "%s: Device " lbMACAddFmt(":") " eligible for interference avoidance "
                 "steering", __func__, lbMACAddData(staAddr->ether_addr_octet));
            trigger = steerexec_reason_interferenceAvoidance;
            break;
        }

        // Check the Tx rate - is this device eligible for upgrade or downgrade?
        wlanif_staStatsSnapshot_t staStats;
        if (wlanif_sampleSTAStats(bss, staAddr, LBD_TRUE /* rateOnly */,
                                  &staStats) != LBD_OK) {
            dbgf(stamonState.dbgModule, DBGERR,
                 "%s: Failed to get Tx rate information for " lbMACAddFmt(":")
                 " on " lbBSSInfoAddFmt(),
                 __func__, lbMACAddData(staAddr->ether_addr_octet),
                 lbBSSInfoAddData(bss));
            break;
        }

        // Make active steer decision based on rate and RSSI
        steeralg_rateSteerEligibility_e rateEligibility =
            steeralg_determineRateSteerEligibility(staStats.lastTxRate, band);
        trigger = stamonMakeSteerDecisionActive(entry, staAddr, band, &staStats,
                                                rateEligibility);
    } while (0);

    if (trigger != steerexec_reason_invalid) {
        stamonCmnTriggerActiveSteering(entry, staAddr, trigger);
    }
}

// ====================================================================
// Package level functions
// ====================================================================
LBD_STATUS stamonCmnGetUplinkRSSI(stadbEntry_handle_t entry,
                                      lbd_rssi_t *rssiOut) {
    const struct ether_addr *staAddr = stadbEntry_getAddr(entry);
    lbDbgAssertExit(stamonState.dbgModule, staAddr);
    stadbEntry_bssStatsHandle_t servingBSS = stadbEntry_getServingBSS(entry, NULL);
    const lbd_bssInfo_t *bss = stadbEntry_resolveBSSInfo(servingBSS);
    lbDbgAssertExit(stamonState.dbgModule, bss);

    time_t ageSecs = 0xFFFFFFFF;
    u_int8_t probeCount = 0;
    lbd_rssi_t rssi = stadbEntry_getUplinkRSSI(entry, servingBSS, &ageSecs, &probeCount);
    if (rssi == LBD_INVALID_RSSI ||
        ageSecs > stamonState.config.freshnessLimit ||
        probeCount) {
        // RSSI is either too old or invalid, need to re-measure
        // Since probe RSSI will be ignored on serving BSS, it is very unlikely
        // to have a recent valid probe RSSI. So probe RSSI will be ignored here
        wlanif_band_e associatedBand = wlanif_resolveBandFromChannelNumber(bss->channelId);
        if (LBD_NOK == wlanif_requestStaRSSI(bss, staAddr,
                                             stamonState.config.instRSSINumSamples[associatedBand])) {
            dbgf(stamonState.dbgModule, DBGERR,
                 "%s: Failed to request RSSI measurement for " lbMACAddFmt(":")
                 " on " lbBSSInfoAddFmt(),
                  __func__, lbMACAddData(staAddr->ether_addr_octet),
                  lbBSSInfoAddData(bss));
        }
        return LBD_NOK;
    }

    if (rssiOut) {
        *rssiOut = rssi;
        return LBD_OK;
    }

    if (LBD_NOK == estimator_estimateNonServingUplinkRSSI(entry)) {
        dbgf(stamonState.dbgModule, DBGERR,
             "%s: Failed to estimate non-serving RSSI for "lbMACAddFmt(":"),
             __func__, lbMACAddData(staAddr->ether_addr_octet));
        return LBD_NOK;
    }

    return LBD_OK;
}

LBD_BOOL stamonCmnIsEligibleForActiveUpgrade(const struct ether_addr *staAddr,
                                             wlanif_band_e band, u_int32_t tx_rate,
                                             lbd_rssi_t rssi) {
    // When upgrading a STA, the RSSI has to exceed the HighRateRSSIXingThreshold
    if (rssi <= stamonState.config.highRateRSSIXingThreshold) {
        dbgf(stamonState.dbgModule, DBGDEBUG,
             "%s: " lbMACAddFmt(":") " eligible for upgrade at rate %u, "
             "but RSSI %u does not exceed the high crossing threshold %u",
             __func__, lbMACAddData(staAddr->ether_addr_octet),
             tx_rate, rssi, stamonState.config.highRateRSSIXingThreshold);
        return LBD_FALSE;
    }

    // Check if there is at least one channel this STA can be directed to.
    if (!bandmon_canOffloadClientFromBand(band)) {
        dbgf(stamonState.dbgModule, DBGDEBUG,
             "%s: " lbMACAddFmt(":") " eligible for active steering due to rate, "
             " but all potential destination channels exceed safety threshold",
             __func__, lbMACAddData(staAddr->ether_addr_octet));

        // Request notification for utilization update.
        bandmon_enableOneShotUtilizationEvent();
        return LBD_FALSE;
    }

    if (bandmon_isInSteeringBlackout()) {
        // During steering blackout, can only downgrade 5GHz clients.
        dbgf(stamonState.dbgModule, DBGDEBUG,
             "%s: " lbMACAddFmt(":") " eligible for upgrade to 5GHz band, "
             " but postponed due to steering blackout",
             __func__, lbMACAddData(staAddr->ether_addr_octet));

        // Request notification for utilization update.
        bandmon_enableOneShotUtilizationEvent();
        return LBD_FALSE;
    }

    dbgf(stamonState.dbgModule, DBGINFO,
         "%s: " lbMACAddFmt(":") " eligible for upgrade at rate %u rssi %u",
         __func__, lbMACAddData(staAddr->ether_addr_octet),
         tx_rate, rssi);

    return LBD_TRUE;
}

void stamonCmnTriggerActiveSteering(stadbEntry_handle_t entry,
                                    const struct ether_addr *staAddr,
                                    steerexec_reason_e trigger) {
    if (LBD_NOK == estimator_estimateSTADataMetrics(entry, trigger)) {
        dbgf(stamonState.dbgModule, DBGINFO,
             "%s: Failed to collecting metrics for " lbMACAddFmt(":"),
             __func__, lbMACAddData(staAddr->ether_addr_octet));
    }
}
