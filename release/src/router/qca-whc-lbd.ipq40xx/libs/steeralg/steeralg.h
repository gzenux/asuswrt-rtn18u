// vim: set et sw=4 sts=4 cindent:
/*
 * @File: steeralg.h
 *
 * @Abstract: Public interface for BSS steeralg
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

#ifndef steeralg__h
#define steeralg__h

#include "lbd_types.h"
#include "wlanif.h"
#include "stadb.h"
#include "steerexec.h"

#if defined(__cplusplus)
extern "C" {
#endif

/**
 * @brief Enum types denote whether a client is eligible for 
 *        upgrade or downgrade (while active).
 */
typedef enum {
    /// Not eligible for upgrade or downgrade.
    steeralg_rateSteer_none = 0,

    /// Eligible for upgrade.
    steeralg_rateSteer_upgrade = 1,

    /// Eligible for downgrade.
    steeralg_rateSteer_downgrade = 2,

    /// Eligible for downgrade based on RSSI.
    steeralg_rateSteer_downgradeRSSI = 3,

    steeralg_rateSteer_invalid
} steeralg_rateSteerEligibility_e;

/**
 * @brief Initialize the BSS steeralg module.
 *
 * @return LBD_OK on success; otherwise LBD_NOK
 */
LBD_STATUS steeralg_init(void);

/**
 * @brief Deinitialize the BSS steeralg module
 *
 * @return LBD_OK on success; otherwise LBD_NOK
 */
LBD_STATUS steeralg_fini(void);

/**
 * @brief Steer an idle client
 *
 * @pre not all channels are overloaded; the client is an idle steering candidate
 *
 * @param [in] handle  the handle to the idle client
 *
 * return LBD_OK if the client is being steered successfully; otherwise return LBD_NOK
 */
LBD_STATUS steeralg_steerIdleClient(stadbEntry_handle_t handle);

/**
 * @brief Select the best channel to send 802.11k beacon report request.
 *
 * @param [in] handle  the handle to the client
 * @param [in] trigger  the trigger to this 802.11k request
 *
 * @return the channel ID, or LBD_CHANNEL_INVALID if no channel is selected
 */
lbd_channelId_t steeralg_select11kChannel(stadbEntry_handle_t handle,
                                          steerexec_reason_e trigger);

/**
 * @brief Determine if a STA is eligible for rate based 
 *        steering.
 * 
 * @param [in] txRate current Tx rate (Mbps)
 * @param [in] band band STA is operating on
 * 
 * @return enum code indicating if STA is eligible for upgrade, 
 *         downgrade, or none.
 */
steeralg_rateSteerEligibility_e steeralg_determineRateSteerEligibility(
    lbd_linkCapacity_t txRate,
    wlanif_band_e band);

// ====================================================================
// Constants needed by test cases
// ====================================================================
#define STEERALG_INACT_RSSI_THRESHOLD_W2_KEY "InactRSSIXingThreshold_W2"
#define STEERALG_INACT_RSSI_THRESHOLD_W5_KEY "InactRSSIXingThreshold_W5"
#define STEERALG_HIGH_TX_RATE_XING_THRESHOLD "HighTxRateXingThreshold"
#define STEERALG_LOW_TX_RATE_XING_THRESHOLD "LowTxRateXingThreshold"
#define STEERALG_MIN_TXRATE_INCREASE_THRESHOLD_KEY "MinTxRateIncreaseThreshold"
#define STEERALG_LOW_RATE_RSSI_XING_THRESHOLD "LowRateRSSIXingThreshold"
#define STEERALG_HIGH_RATE_RSSI_XING_THRESHOLD "HighRateRSSIXingThreshold"
#define STEERALG_AGE_LIMIT_KEY "AgeLimit"
#define STEERALG_PHY_BASED_PRIORITIZATION "PHYBasedPrioritization"
#define STEERALG_RSSI_SAFETY_THRESHOLD_KEY "RSSISafetyThreshold"
#define STEERALG_MAX_STEERING_TARGET_COUNT_KEY "MaxSteeringTargetCount"
#define STEERALG_AP_STEER_TO_ROOT_MIN_RSSI_INC_KEY "APSteerToRootMinRSSIIncThreshold"
#define STEERALG_AP_STEER_TO_LEAF_MIN_RSSI_INC_KEY "APSteerToLeafMinRSSIIncThreshold"
#define STEERALG_AP_STEER_TO_PEER_MIN_RSSI_INC_KEY "APSteerToPeerMinRSSIIncThreshold"
#define STEERALG_DL_RSSI_THRESHOLD_W5_KEY "DownlinkRSSIThreshold_W5"

#if defined(LBD_DBG_MENU) && defined(GMOCK_UNIT_TESTS)
struct cmdContext;

/**
 * @brief Print the status of the steering algorithm module.
 *
 * @param [in] context  the output context
 * @param [in] cmd  the command in the debug CLI
 */
void steeralgMenuStatusHandler(struct cmdContext *context, const char *cmd);

#endif /* LBD_DBG_MENU */

#if defined(__cplusplus)
}
#endif

#endif // steeralg__h
