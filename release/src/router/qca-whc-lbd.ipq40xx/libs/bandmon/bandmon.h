// vim: set et sw=4 sts=4 cindent:
/*
 * @File: bandmon.h
 *
 * @Abstract: Public interface for the band monitor
 *
 * @Notes:
 *
 * @@-COPYRIGHT-START-@@
 *
 * Copyright (c) 2014 Qualcomm Atheros, Inc.
 * All Rights Reserved.
 * Qualcomm Atheros Confidential and Proprietary.
 *
 * @@-COPYRIGHT-END-@@
 */

#ifndef bandmon__h
#define bandmon__h

#include "lbd_types.h"  // for LBD_STATUS and other types
#include "wlanif.h"  // for wlanif_band_e and WLANIF_MAX_RADIOS

#if defined(__cplusplus)
extern "C" {
#endif

// ====================================================================
// Common types exported to other modules
// ====================================================================

/**
 * @brief IDs of events that are generated from this module.
 */
typedef enum bandmon_event_e {
    bandmon_event_overload_change,    ///< Overload status change
    bandmon_event_utilization_update, ///< New utilization values have been
                                      ///< recorded for all channels

    bandmon_event_maxnum
} bandmon_event_e;

/**
 * @brief The format of the bandmon_event_overload_change event.
 */
typedef struct bandmon_overloadChangeEvent_t {
    /// The number of channels that are overloaded.
    u_int8_t numOverloadedChannels;
} bandmon_overloadChangeEvent_t;

/**
 * @brief The format of the bandmon_event_utilization_update event.
 */
typedef struct bandmon_utilizationUpdateEvent_t {
    /// The number of channels that are overloaded.
    u_int8_t numOverloadedChannels;
} bandmon_utilizationUpdateEvent_t;

// ====================================================================
// Public API
// ====================================================================

/**
 * @brief Initialize the band monitor module.
 *
 * @pre stadb must have been initialized first
 *
 * @return LBD_OK on success; otherwise LBD_NOK
 */
LBD_STATUS bandmon_init(void);

/**
 * @brief Query whether all channels are overloaded.
 *
 * @return LBD_TRUE if all channels are overloaded; otherwise LBD_FALSE
 */
LBD_BOOL bandmon_areAllChannelsOverloaded(void);

/**
 * @brief Query whether the channel is overloaded or not.
 *
 * @param [in] channel  the channel for which to check for overload
 * @param [out] isOverloaded  whether the channel is overloaded or not;
 *                            this is only valid on LBD_OK being returned
 *
 * @return LBD_OK if the overload information for the channel was obtained;
 *         otherwise LBD_NOK
 */
LBD_STATUS bandmon_isChannelOverloaded(lbd_channelId_t channelId,
                                       LBD_BOOL *isOverloaded);

/**
 * @brief Determine the channel that is the least loaded on the provided band.
 *
 * @return the channel id, or LBD_CHANNEL_INVALID if the band is invalid (or
 *         no match is found which should generally not happen)
 */
lbd_channelId_t bandmon_getLeastLoadedChannel(wlanif_band_e band);

/**
 * @brief Obtain the current measured utilization on the channel.
 *
 * @return the utilization, or LBD_INVALID_AIRTIME if the channel is not
 *         known
 */
lbd_airtime_t bandmon_getMeasuredUtilization(lbd_channelId_t channelId);

/**
 * @brief Check whether we are in a blackout period to allow for updated
 *        measured utilization.
 *
 * @return LBD_TRUE if we are in a blackout period; otherwise LBD_FALSE
 */
LBD_BOOL bandmon_isInSteeringBlackout(void);

/**
 * @brief Query whether the channel can support the addition of an active
 *        client based on its estimated airtime.
 *
 * @param [in] channel  the channel for which to check for headroom
 * @param [in] airtime  the estimated airtime for the client on the channel
 *
 * @return LBD_INVALID_AIRTIME if airtime can not fit on the 
 *         given channel without causing it to go above the
 *         safety threshold.  Otherwise return the difference
 *         between the safety threshold and the (measured +
 *         projected) utilization (amount of headroom
 *         available).  Note the projected utilization does not
 *         include the airtime passed in.
 */
lbd_airtime_t bandmon_canSupportClient(lbd_channelId_t channelId,
                                       lbd_airtime_t airtime);

/**
 * @brief Query whether there is any channel that has any 
 *        headroom when attempting to offload from band.
 *
 * @param [in] band  the band to attempt to remove the client 
 *                   from
 *
 * @return LBD_TRUE if there exists a channel not on band that 
 *         has some available headroom, LBD_FALSE otherwise.
 */
LBD_BOOL bandmon_canOffloadClientFromBand(wlanif_band_e band);

/**
 * @brief Add the airtime for a client that is being steered to the channel
 *        to its projected airtime.
 *
 * @param [in] channel  the channel to which to add the projected airtime
 * @param [in] airtime  the projected airtime to add
 * @param [in] allowAboveSafety  whether to allow total airtime above safety
 *                               threshold after adding this projected one
 *
 * @return LBD_OK on success; otherwise LBD_NOK
 */
LBD_STATUS bandmon_addProjectedAirtime(lbd_channelId_t channelId,
                                       lbd_airtime_t airtime,
                                       LBD_BOOL allowAboveSafety);

/**
 * @brief Check if after offloading some airtime, the expected utilization
 *        on the channel will go below safety threshold
 *
 * @param [in] channelId  the channel being offloaded
 * @param [in] totalOffloadedAirtime  total airtime offloaded
 * @param [out] isBelow  on success, set to LBD_TRUE if the expected utilization
 *                       will go below the threshold; otherwise, set to LBD_FALSE
 *
 * @return LBD_OK if the airtime has been checked succussfully; otherwise,
 *                return LBD_NOK
 */
LBD_STATUS bandmon_isExpectedBelowSafety(lbd_channelId_t channelId,
                                         lbd_airtime_t totalOffloadedAirtime,
                                         LBD_BOOL *isBelow);

/**
 * @brief Request that a utilization event be generated at the next
 *        utilization update that is not the start of a blackout
 *        period.
 */
void bandmon_enableOneShotUtilizationEvent(void);

/**
 * @brief Terminate the band monitor module.
 *
 * @pre stadb must still be initialized
 *
 * @return LBD_OK on success; otherwise LBD_NOK
 */
LBD_STATUS bandmon_fini(void);

// ====================================================================
// Constants needed by test cases
// ====================================================================

// These need not be exposed but it is useful to do so for unit tests to
// avoid duplicating the strings.

#define BANDMON_MU_OVERLOAD_THRESHOLD_W2_KEY "MUOverloadThreshold_W2"
#define BANDMON_MU_OVERLOAD_THRESHOLD_W5_KEY "MUOverloadThreshold_W5"
#define BANDMON_MU_SAFETY_THRESHOLD_W2_KEY   "MUSafetyThreshold_W2"
#define BANDMON_MU_SAFETY_THRESHOLD_W5_KEY   "MUSafetyThreshold_W5"
#define BANDMON_MU_RESERVE_W5_KEY            "MUReserve_W5"
#define BANDMON_RSSI_SAFETY_THRESHOLD_KEY    "RSSISafetyThreshold"
#define BANDMON_RSSI_MAX_AGE_KEY             "RSSIMaxAge"
#define BANDMON_PROBE_COUNT_THRESHOLD_KEY    "ProbeCountThreshold"
#define BANDMON_MU_REPORT_PERIOD_KEY         "MUReportPeriod"
#define BANDMON_LB_ALLOWED_MAX_PERIOD_KEY    "LoadBalancingAllowedMaxPeriod"
#define BANDMON_MAX_REMOTE_CHANNELS_KEY      "NumRemoteChannels"

#if defined(LBD_DBG_MENU) && defined(GMOCK_UNIT_TESTS)
struct cmdContext;

/**
 * @brief Print the status of the band monitor module.
 *
 * @param [in] context  the output context
 * @param [in] cmd  the command in the debug CLI
 */
void bandmonMenuStatusHandler(struct cmdContext *context, const char *cmd);

/**
 * @brief Enable/disable the debug mode from the debug CLI.
 *
 * @param [in] context  the output context
 * @param [in] cmd  the command in the debug CLI
 */
void bandmonMenuDebugHandler(struct cmdContext *context, const char *cmd);

/**
 * @brief Inject a utilization measurement from the debug CLI.
 *
 * @param [in] context  the output context
 * @param [in] cmd  the command in the debug CLI
 */
void bandmonMenuUtilHandler(struct cmdContext *context, const char *cmd);

#endif /* LBD_DBG_MENU */

#if defined(__cplusplus)
}
#endif

#endif
