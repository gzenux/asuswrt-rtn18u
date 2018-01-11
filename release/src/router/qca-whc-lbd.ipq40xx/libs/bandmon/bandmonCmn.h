// vim: set et sw=4 sts=4 cindent:
/*
 * @File: bandmonCmn.h
 *
 * @Abstract: Functions shared by bandmonBSA and bandmonMBSA
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

#ifndef bandmonCmn__h
#define bandmonCmn__h

#include <dbg.h>

#include "bandmon.h"

#if defined(__cplusplus)
extern "C" {
#endif

// ====================================================================
// Protected members (for use within the common functions and any
// "derived" functions that may be using this component).
// ====================================================================

// Forward decl
struct bandmonChannelUtilizationInfoExt_t;

/// State information on a per active channel basis.
struct bandmonChannelUtilizationInfo_t {
    /// The index of the bit in the utilizationsState value for this
    /// entry.
    size_t bitIndex;

    /// The channel index.
    lbd_channelId_t channelId;

    /// The last measured utilization (the percentage of time the channel
    /// was busy, between 0 and 100) during a period in which no active
    /// upgrade steering and no idle upgrade steerings were allowed.
    u_int8_t measuredUtilization;

    /// The amount the utilization (percentage of time the channel is
    /// busy) on this channel is projected to increase based on the active
    //steering attempts done since the last measurement.
    u_int8_t projectedUtilizationIncrease;

    /// Whether the overload value has changed since last reported.
    LBD_BOOL overloadChanged : 1;

    /// Whether the channel is currently considered overloaded (based on
    /// measured utilization only) or not.
    LBD_BOOL isOverloaded : 1;

    /// Whether on the last assessment, the channel was considered
    /// overloaded.
    LBD_BOOL wasOverloaded : 1;

    /// Maximum channel width supported on this channel
    wlanif_chwidth_e maxChWidth;

    /// Extra information specific to BSA/MBSA
    struct bandmonChannelUtilizationInfoExt_t *extInfo;
};

/**
 * @brief Internal state for the band monitor module.
 */
struct bandmonPriv_t {
    struct dbgModule *dbgModule;

    /// When debug mode is enabled, all utilization events are ignored and
    /// changes have to come via the debug CLI.
    /// TODO: This currently is not protected by LBD_DBG_MENU since HYD does
    ///       not have this defined when compiling. Need better way to handle this
    LBD_BOOL debugModeEnabled;

    /// Configuration data obtained at init time.
    struct {
        /// The per-band medium utilization overload thresholds for the
        /// overload condition.
        u_int8_t overloadThresholds[wlanif_band_invalid];

        /// The per-band medium utilization safety thresholds for active
        /// steering.
        u_int8_t safetyThresholds[wlanif_band_invalid];

        /// The maximum age an RSSI measurements can be before it is
        /// considered to old to be used when making a steering decision.
        time_t rssiMaxAge;

        /// The RSSI value above which pre-association steering to a
        /// non-overloaded channel may be done.
        u_int8_t rssiSafetyThreshold;

        /// Number of probes required when non-associted band RSSI is valid
        u_int8_t probeCountThreshold;

        /// Parameters only necessary for multi-AP setup

        /// Interval between two requests to collect medium utilizations from all
        /// APs in the network. Only necessary for CAP
        time_t utilReportPeriod;

        /// Maximum time an AP is allowed to perform active/idle upgrade after
        /// being assigned the slot by CAP
        time_t lbAllowedPeriod;
    } config;

    /// Maximum number of channels supported.
    u_int8_t maxNumChannels;

    /// The number of currently active channels.
    u_int8_t numActiveChannels;

    /// Bitmask that is used to keep track of the updates for each band.
    /// The updates are complete on all channels when the bitmask is either
    /// all 0's or all 1's (up to the bit index for the number of active
    /// channels).
    u_int8_t utilizationsState;

    /// State capturing whether we are in a steering blackout window or
    /// one is coming up at the next utilization update.
    enum bandmon_blackoutState_e {
        /// No steering blackout is in effect.
        bandmon_blackoutState_idle,

        /// Next utilization update will be a steering blackout.
        bandmon_blackoutState_pending,

        /// Next utilization update should re-enter the steering blackout.
        /// This is used when there are projected utilization changes
        /// while already in a steering blackout (eg. due to downgrade
        /// steering).
        bandmon_blackoutState_activeWithPending,

        /// Currently in a steering blackout.
        bandmon_blackoutState_active
    } blackoutState;

    /// Whether a one shot event for utilization update was requested.
    LBD_BOOL oneShotUtilizationRequested;

    struct bandmonChannelUtilizationInfo_t *channelUtilizations;
};

/**
 * Handle to band monitor top level state
 */
extern struct bandmonPriv_t *bandmonCmnStateHandle;

// ====================================================================
// Protected functions
// ====================================================================

/**
 * @brief Initialize extra channel information
 *
 * @param [in] chanInfo  the channel information where extra info is appended
 *
 * @return LBD_OK if extra info is initialized successfully;
 *         otherwise return LBD_NOK
 */
LBD_STATUS bandmonInitializeChannelExtInfo(
        struct bandmonChannelUtilizationInfo_t *chanInfo);

/**
 * @brief Finalize extra channel information
 *
 * @param [in] chanInfo  the channel information where extra info is appended
 */
void bandmonFinalizeChannelExtInfo(struct bandmonChannelUtilizationInfo_t *chanInfo);

/**
 * @brief React to when active steering happened
 */
void bandmonHandleActiveSteered(void);

/**
 * @brief Initialize BSA/MBSA specific functionalities
 */
void bandmonSubInit(void);

/**
 * @brief Handle a VAP restart
 */
void bandmonHandleVAPRestart();

// ====================================================================
// Functions internally shared by BSA and MBSA
// ====================================================================

/**
 * @brief Update the overload state for all channels if all measurements are
 *        available.
 *
 * @return the number of channels which had their overload state change
 */
u_int8_t bandmonCmnDetermineOperatingRegion(void);

/**
 * @brief Generate a diagnostic log (if enabled) indicating the change in
 *        the blackout state.
 *
 * @param [in] isBlackoutStart  whether this is the starting point or ending
 *                              point for a steering blackout
 */
void bandmonCmnDiaglogBlackoutChange(LBD_BOOL isBlackoutStart);

/**
 * @brief Generate bandmon_msgId_utilization diaglog
 *
 * @param [in] channel  the channel ID where utilization is measured
 * @param [in] util  the measured utilization
 */
void bandmonCmnDiaglogUtil(lbd_channelId_t channel, u_int8_t util);

/**
 * @brief Find the matching entry for the channel utilization by the channel
 *        number.
 *
 * @param [in] channelId  the channel number
 *
 * @return the handle to the entry, or NULL if no match was found
 */
struct bandmonChannelUtilizationInfo_t *
    bandmonCmnGetChannelUtilizationInfo(lbd_channelId_t channelId);

/**
 * @brief React to a utilization measurement on the provided band.
 *
 * @param [in] channel  the channel on which the utilization was measured
 * @param [in] utilization   the utilization value (0-100)
 */
void bandmonCmnHandleChanUtil(lbd_channelId_t channelId, u_int8_t utilization);

/**
 * @brief Initialize channel information for a given channel
 *
 * @param [in] bitIndex  the index of the bit in the utilizationsState value for this entry.
 * @param [in] channelId  the channel number for this entry
 * @param [in] maxChWidth  maximum channel width supported on this channel
 *
 * @return the channel info struct if it is initialized successfully;
 *         otherwise return NULL
 */
struct bandmonChannelUtilizationInfo_t *
bandmonCmnInitializeChanInfo(size_t bitIndex, lbd_channelId_t channelId,
                             wlanif_chwidth_e maxChWidth);

/**
 * @brief Check whether the operating region has changed and if it has,
 *        do the necessary ACL operations.
 *
 * @param [in] overloadState  the current overload condition
 */
void bandmonCmnProcessOperatingRegion(void);

/**
 * @brief Move the blackout state to the next state.
 *
 * @param [in] keepActive  if true, will not exit active blackout period
 */
void bandmonCmnTransitionBlackoutState(LBD_BOOL keepActive);

#if defined(__cplusplus)
}
#endif

#endif // bandmonCmn__h
