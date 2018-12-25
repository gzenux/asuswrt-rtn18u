// vim: set et sw=4 sts=4 cindent:
/*
 * @File: steerexec.h
 *
 * @Abstract: Public interface for the steering executor
 *
 * @Notes:
 *
 * @@-COPYRIGHT-START-@@
 *
 * Copyright (c) 2014-2016 Qualcomm Atheros, Inc.
 * All Rights Reserved.
 * Qualcomm Atheros Confidential and Proprietary.
 *
 * @@-COPYRIGHT-END-@@
 */

#ifndef steerexec__h
#define steerexec__h

#include "lbd_types.h"  // for LBD_STATUS

#include "stadbEntry.h"
#include "wlanif.h"

#if defined(__cplusplus)
extern "C" {
#endif

/**
 * Maximum number of candidates that can be provided in a call
 * to steerexec_steer
 */
#define STEEREXEC_MAX_CANDIDATES 2

/**
 * Maximum number of channels that can be provided in a call
 * to steerexec_allowAssoc
 */
#define STEEREXEC_MAX_ALLOW_ASSOC (WLANIF_MAX_RADIOS - 1)

/**
 * @brief Used to indicate the conditions under which a STA can
 *        be steered.
 */
typedef enum steerexec_steerEligibility_e {
    // Can't be steered
    steerexec_steerEligibility_none,

    // Can be steered while idle
    steerexec_steerEligibility_idle,

    // Can be steered while active or idle
    steerexec_steerEligibility_active,

    steerexec_steerEligibility_invalid
} steerexec_steerEligibility_e;

/**
 * @brief Used to indicate the reason why a steer is initiated
 */
typedef enum steerexec_reason_e {
    // Steered from the command line by the user
    steerexec_reason_user,

    // Upgrade while active (due to good rate and RSSI on 2.4GHz)
    steerexec_reason_activeUpgrade,

    // Downgrade while active due to poor rate
    steerexec_reason_activeDowngradeRate,

    // Downgrade while active due to poor RSSI
    steerexec_reason_activeDowngradeRSSI,

    // Upgrade while idle (due to RSSI)
    steerexec_reason_idleUpgrade,

    // Downgrade while idle (due to RSSI)
    steerexec_reason_idleDowngrade,

    // Steer due to offloading overloaded channel (while STA is active)
    steerexec_reason_activeOffload,

    // Steer due to offloading overloaded channel (while STA is idle)
    steerexec_reason_idleOffload,

    // AP steering while active
    steerexec_reason_activeAPSteering,

    // AP steering while idle
    steerexec_reason_idleAPSteering,

    // Request from another AP in the network
    steerexec_reason_APrequest,

    // Interference avoidance
    steerexec_reason_interferenceAvoidance,

    steerexec_reason_invalid
} steerexec_reason_e;

/**
 * @brief Function callback type that other modules can register to be
 *        informed when steering becomes allowed for a given entry.
 *
 * The callback occurs after the entry has been updated.
 *
 * @param [in] handle  the entry that was updated
 * @param [in] cookie  the value provided by the caller when the observer
 *                     callback function was registered
 */
typedef void (*steerexec_steeringAllowedObserverCB)(stadbEntry_handle_t handle,
                                                    void *cookie);

/**
 * @brief Initialize the steering executor module.
 *
 * This should be called prior to intializing the station database so that
 * the steering executor can be notified of associated stations.
 *
 * @return LBD_OK on success; otherwise LBD_NOK
 */
LBD_STATUS steerexec_init(void);

/**
 * @brief Allows the STA to associate on any channels in
 *        channelList (used for pre-association steering).
 *        The STA will be prohibited from associating on any
 *        channel not on channelList
 *
 * @param [in] handle the handle to the STA to allow
 * @param [in] channelCount count of channels in channelList
 * @param [in] channelList list of channels to allow the STA
 *                         to associate on
 * @param [out] ignored  if the request was ignored by the executor, this
 *                       will be set to LBD_TRUE; otherwise it will be set
 *                       to LBD_FALSE indicating it was acted upon by the
 *                       executor; this parameter may be NULL if the caller
 *                       does not care to distinguish between ignored and
 *                       non-ignored requests
 *
 * @return LBD_STATUS LBD_OK on success, LBD_NOK otherwse
 */
LBD_STATUS steerexec_allowAssoc(stadbEntry_handle_t handle,
                                u_int8_t channelCount,
                                const lbd_channelId_t *channelList,
                                LBD_BOOL *ignored);

/**
 * @brief Abort any pre-association steering operation which may
 *        be in progress for the STA.
 *
 * @param [in] handle  the handle to the STA for which to abort
 * @param [out] ignored  if the request was ignored by the executor, this
 *                       will be set to LBD_TRUE; otherwise it will be set
 *                       to LBD_FALSE indicating it was acted upon by the
 *                       executor; this parameter may be NULL if the caller
 *                       does not care to distinguish between ignored and
 *                       non-ignored requests
 *
 * @return LBD_OK on success; otherwise LBD_NOK
 */
LBD_STATUS steerexec_abortAllowAssoc(stadbEntry_handle_t handle,
                                     LBD_BOOL *ignored);

/**
 * @brief Steer the STA to any of the BSSes listed in
 *        candidateList (used for post-association steering).
 *
 * @param [in] handle STA to be steered
 * @param [in] candidateCount count of BSSes in candidateList
 * @param [in] candidateList list of potential targets for
 *                           steering
 * @param [in] reason  reason for the steer
 * @param [out] ignored  if the request was ignored by the executor, this
 *                       will be set to LBD_TRUE; otherwise it will be set
 *                       to LBD_FALSE indicating it was acted upon by the
 *                       executor; this parameter may be NULL if the caller
 *                       does not care to distinguish between ignored and
 *                       non-ignored requests
 *
 * @return LBD_STATUS LBD_OK on success; otherwise LBD_NOK
 */
LBD_STATUS steerexec_steer(stadbEntry_handle_t handle,
                           u_int8_t candidateCount,
                           const lbd_bssInfo_t *candidateList,
                           steerexec_reason_e reason,
                           LBD_BOOL *ignored);

/**
 * @brief Abort any steering operation which may be in progress for the STA.
 *
 * @param [in] handle  the handle to the STA for which to abort
 * @param [out] ignored  if the request was ignored by the executor, this
 *                       will be set to LBD_TRUE; otherwise it will be set
 *                       to LBD_FALSE indicating it was acted upon by the
 *                       executor; this parameter may be NULL if the caller
 *                       does not care to distinguish between ignored and
 *                       non-ignored requests
 *
 * @return LBD_OK on success; otherwise LBD_NOK
 */
LBD_STATUS steerexec_abort(stadbEntry_handle_t handle,
                           LBD_BOOL *ignored);


/**
 * @brief Returns the conditions under which handle can be
 *        steered at this time.
 *
 * @pre Should only be called for associated STAs
 *
 * @param [in] handle STA to determine steering eligibility for
 *
 * @return Eligibility for handle to be steered
 */
steerexec_steerEligibility_e steerexec_determineSteeringEligibility(
    stadbEntry_handle_t handle);

/**
 * @brief Determines if a steer should be aborted if the STA
 *        becomes active.
 *
 * @param [in] handle STA to determine if the steer should be
 *                    aborted
 *
 * @return LBD_TRUE if steer should be aborted, LBD_FALSE
 *         otherwise
 */
LBD_BOOL steerexec_shouldAbortSteerForActive(stadbEntry_handle_t handle);

/**
 * @brief Register a function to get called back when an entry can be
 *        steered again (after previously not being allowed).
 *
 * @param [in] observer  the callback function to invoke
 * @param [in] cookie  the parameter to pass to the callback function
 *
 * @return LBD_OK on success; otherwise LBD_NOK
 */
LBD_STATUS steerexec_registerSteeringAllowedObserver(
        steerexec_steeringAllowedObserverCB observer,
        void *cookie);

/**
 * @brief Unregister the observer callback function.
 *
 * @param [in] observer  the callback function to unregister
 * @param [in] cookie  the registered parameter to pass to the callback
 *                     function
 *
 * @return LBD_OK on success; otherwise LBD_NOK
 */
LBD_STATUS steerexec_unregisterSteeringAllowedObserver(
        steerexec_steeringAllowedObserverCB observer,
        void *cookie);

/**
 * @brief Tear down the steering executor module.
 *
 * @return LBD_OK on success; otherwise LBD_NOK
 */
LBD_STATUS steerexec_fini(void);

/**
 * @brief Generate JSON for a station's steering state
 *
 * @param [in] entry  the station handle
 * @return jansson object on success, NULL on failure
 */
json_t *steerexec_jsonize(stadbEntry_handle_t entry);

/**
 * @brief Restore a station's steering state from JSON
 *
 * @param [in] entry  the station handle
 * @param [in] json the json object
 */
void steerexec_restore(stadbEntry_handle_t entry, json_t *json);

// ====================================================================
// Constants needed by test cases
// ====================================================================

// These need not be exposed but it is useful to do so for unit tests to
// avoid duplicating the strings.

#define STEEREXEC_STEERING_PROHIBIT_TIME_KEY   "SteeringProhibitTime"
#define STEEREXEC_T_STEERING_KEY               "TSteering"
#define STEEREXEC_INITIAL_AUTH_REJ_COALESCE_TIME_KEY "InitialAuthRejCoalesceTime"
#define STEEREXEC_AUTH_REJ_MAX_KEY             "AuthRejMax"
#define STEEREXEC_STEERING_UNFRIENDLY_TIME_KEY "SteeringUnfriendlyTime"
#define STEEREXEC_MAX_STEERING_UNFRIENDLY "MaxSteeringUnfriendly"
#define STEEREXEC_LOW_RSSI_THRESHOLD_W2_KEY "LowRSSIXingThreshold_W2"
#define STEEREXEC_LOW_RSSI_THRESHOLD_W5_KEY "LowRSSIXingThreshold_W5"
#define STEEREXEC_TARGET_LOW_RSSI_THRESHOLD_W2_KEY "TargetLowRSSIThreshold_W2"
#define STEEREXEC_TARGET_LOW_RSSI_THRESHOLD_W5_KEY "TargetLowRSSIThreshold_W5"
#define STEEREXEC_BLACKLIST_TIME_KEY "BlacklistTime"
#define STEEREXEC_BTM_RESPONSE_TIME_KEY "BTMResponseTime"
#define STEEREXEC_BTM_ASSOCIATION_TIME_KEY "BTMAssociationTime"
#define STEEREXEC_BTM_ALSO_BLACKLIST "BTMAlsoBlacklist"
#define STEEREXEC_BTM_UNFRIENDLY_TIME_KEY "BTMUnfriendlyTime"
#define STEEREXEC_BTM_STEERING_PROHIBIT_SHORT_TIME_KEY "BTMSteeringProhibitShortTime"
#define STEEREXEC_MAX_BTM_UNFRIENDLY "MaxBTMUnfriendly"
#define STEEREXEC_MAX_BTM_ACTIVE_UNFRIENDLY "MaxBTMActiveUnfriendly"
#define STEEREXEC_AGE_LIMIT_KEY "AgeLimit"
#define STEEREXEC_BTM_MIN_RSSI_BE "MinRSSIBestEffort"
#define STEEREXEC_IAS_USE_BE "IASUseBestEffort"
#define STEEREXEC_START_IN_BTM_ACTIVE_STATE_KEY "StartInBTMActiveState"
#define STEEREXEC_MAX_CONSECUTIVE_BTM_FAILURES_AS_ACTIVE_KEY "MaxConsecutiveBTMFailuresAsActive"

#if defined(LBD_DBG_MENU) && defined(GMOCK_UNIT_TESTS)
struct cmdContext;

/**
 * @brief Print the status of the steering executor module.
 *
 * @param [in] context  the output context
 * @param [in] cmd  the command in the debug CLI
 */
void steerexecMenuStatusHandler(struct cmdContext *context,
                                const char *cmd);

/**
 * @brief Steer a specific STA to a specified band.
 *
 * @param [in] context  the output context
 * @param [in] cmd  the command in the debug CLI
 */
void steerexecMenuSteerHandler(struct cmdContext *context,
                               const char *cmd);

/**
 * @brief Abort the steering for a specific STA.
 *
 * @param [in] context  the output context
 * @param [in] cmd  the command in the debug CLI
 */
void steerexecMenuAbortHandler(struct cmdContext *context,
                               const char *cmd);

/**
 * @brief Allow association on a set of channels for a
 *        specific STA (pre-association steering)
 *
 * @param [in] context  the output context
 * @param [in] cmd  the command in the debug CLI
 */
void steerexecMenuAllowAssocHandler(struct cmdContext *context,
                                    const char *cmd);

/**
 * @brief Trigger diaglog from the debug CLI
 *
 * @param [in] context  the output context
 * @param [in] cmd  the command in the debug CLI
 */
void steerexecMenuDiaglogHandler(struct cmdContext *context,
                                 const char *cmd);

#endif /* LBD_DBG_MENU && GMOCK_UNIT_TESTS */

#if defined(__cplusplus)
}
#endif

#endif
