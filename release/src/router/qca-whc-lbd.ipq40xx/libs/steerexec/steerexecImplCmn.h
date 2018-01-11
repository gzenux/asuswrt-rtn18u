// vim: set et sw=4 sts=4 cindent:
/*
 * @File: steerexecImplCmnCmn.h
 *
 * @Abstract: Package level interface to the steering implementation
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

#ifndef steerexecImplCmn__h
#define steerexecImplCmn__h

#include "lbd_types.h"  // for LBD_STATUS

#include "steerexec.h"
#include "stadbEntry.h"
#include "wlanif.h"

#if defined(__cplusplus)
extern "C" {
#endif

// Out of package forward decls.
struct dbgModule;

/**
 * @brief Config parameters used for legacy stations, and BTM
 *        compliant stations if config parameter
 *        BTMAlsoBlacklist = 1
 */
typedef struct steerexecImplCmnLegacyConfig_t {
    /// Amount of time between successive steerings for the legacy
    /// steering mechanism.
    u_int32_t steeringProhibitTime;

    /// How long to allow for the STA to associate on the target band
    /// before aborting the steering.
    u_int32_t tSteering;

    /// The window during which repeated authentication rejects are counted
    /// as only a single one.
    u_int32_t initialAuthRejCoalesceTime;

    /// The point at which repeated authentications result in the blacklist
    /// being cleared and steering aborted.
    u_int32_t authRejMax;

    /// The base amount of time a device should be considered as steering
    /// unfriendly before being attempted again (s).
    u_int32_t steeringUnfriendlyTime;

    /// The maximum timeout used for backoff for steering unfriendly STAs.
    /// Total amount of backoff is calculated as
    /// min(maxSteeringUnfriendly, SteeringUnfriendlyTime * 2 ^ CountConsecutiveFailures)
    u_int32_t maxSteeringUnfriendly;

    /// The amount of time a device should be blacklisted on one band
    /// before being removed.
    u_int32_t blacklistTime;
} steerexecImplCmnLegacyConfig_t;

/**
 * @brief Config parameters used for BTM compliant stations
 */
typedef struct steerexecImplCmnBTMConfig_t {
    /// How long to wait for a BTM response after sending a BTM request.
    /// If no response is received in that time,
    /// mark the BTM transition as a failure
    u_int32_t responseTime;

    /// How long to wait for an association on the target band after receiving a BTM response.
    /// If no association is received in that time, mark the BTM transition as a failure
    u_int32_t associationTime;

    /// If set to 0, just attempt to move the client via 802.11v BTM, otherwise also blacklist
    /// when steering the client
    u_int32_t alsoBlacklist;

    /// The base time to mark a STA as BTM-unfriendly after failing to respond correctly
    /// to a BTM request (s)
    u_int32_t btmUnfriendlyTime;

    /// The maximum timeout used for backoff for BTM unfriendly STAs.
    /// Total amount of backoff is calculated as
    /// min(maxBTMUnfriendly, btmUnfriendlyTime * 2 ^ CountConsecutiveFailures)
    u_int32_t maxBTMUnfriendly;

    /// The maximum timeout used for backoff for active steering unfriendly STAs.
    /// Total amount of backoff is calculated as
    /// min(maxBTMActiveUnfriendly, btmUnfriendlyTime * 2 ^ CountConsecutiveFailuresActive)
    u_int32_t maxBTMActiveUnfriendly;

    /// Amount of time between successive steerings for the BTM
    /// steering mechanism unless there is an auth reject (in which
    /// case the long prohibit time is used).
    u_int32_t steeringProhibitShortTime;

    /// Number of seconds allowed for a RSSI measurement to
    /// be considered as recent
    u_int8_t freshnessLimit;

    /// Minimum RSSI allowed before STA will be steered as best-effort
    lbd_rssi_t minRSSIBestEffort;

    /// If LBD_TRUE, BTM capable STAs will begin in the BTM active
    /// steering friendly state.  If LBD_FALSE, BTM capable STAs
    /// will begin in the Idle steering state
    LBD_BOOL startInBTMActiveState;

    /// Maximum number of consecutive failures while active allowed before marking a STA
    /// as active steering unfriendly
    u_int8_t maxConsecutiveBTMFailuresAsActive;
} steerexecImplCmnBTMConfig_t;

typedef struct steerexecImplCmnConfig_t {
    /// Config parameters for legacy steering
    steerexecImplCmnLegacyConfig_t legacy;

    /// Config parameters for 802.11v BTM steering
    steerexecImplCmnBTMConfig_t btm;

    /// RSSI threshold indicating poor signal strength
    u_int8_t lowRSSIXingThreshold[wlanif_band_invalid];

    /// RSSI threshold indicating the target band is not strong enough
    /// for association
    u_int8_t targetLowRSSIThreshold[wlanif_band_invalid];

    /// Whether to use best-effort steering for IAS
    u_int8_t IASUseBestEffort;
} steerexecImplCmnConfig_t;

struct steerexecImplCmnPriv_t;
typedef struct steerexecImplCmnPriv_t *steerexecImplCmnHandle_t;

/**
 * @brief Type of steering currently in progress for the STA
 */
typedef enum steerexecImplCmnSteeringType_e {
    /// No steering in progress
    steerexecImplCmnSteeringType_none,

    /// Legacy steering
    steerexecImplCmnSteeringType_legacy,

    /// BTM steering with a blacklist
    steerexecImplCmnSteeringType_btm_and_blacklist,

    /// BTM steering only (no blacklist)
    steerexecImplCmnSteeringType_btm,

    /// BTM steering while active with a blacklist
    steerexecImplCmnSteeringType_btm_and_blacklist_active,

    /// BTM steering only (no blacklist) while active
    steerexecImplCmnSteeringType_btm_active,

    /// Pre-association
    steerexecImplCmnSteeringType_preassociation,

    /// Best-effort BTM steering (no blacklist, failures do not mark
    /// STA as unfriendly / increase exponential backoff)
    steerexecImplCmnSteeringType_btm_be,

    /// Best-effort BTM steering (no blacklist, failures do not mark
    /// STA as unfriendly / increase exponential backoff) while active
    steerexecImplCmnSteeringType_btm_be_active,

    /// Best-effort BTM steering with blacklist (failures do not mark
    /// STA as unfriendly / increase exponential backoff)
    steerexecImplCmnSteeringType_btm_blacklist_be,

    /// Best-effort BTM steering with blacklist (failures do not mark
    /// STA as unfriendly / increase exponential backoff) while active
    steerexecImplCmnSteeringType_btm_blacklist_be_active,

    /// Best-effort Legacy steering (failures do not mark
    /// STA as unfriendly / increase exponential backoff)
    steerexecImplCmnSteeringType_legacy_be,

    /// Invalid state
    steerexecImplCmnSteeringType_invalid
} steerexecImplCmnSteeringType_e;

/**
 * @brief Type that denotes the current state of BTM compliance
 */
typedef enum steerexecImplCmn_btmComplianceState_e {
    /// Will attempt to steer via BTM request, but only while idle
    steerexecImplCmn_btmComplianceState_idle,

    /// Will attempt to steer via BTM request, but only while idle
    /// and will not promote to active steering until the timer expires
    /// (STA has failed a BTM transition while in the active state)
    steerexecImplCmn_btmComplianceState_activeUnfriendly,

    /// Will attempt to steer via BTM request while idle or active
    steerexecImplCmn_btmComplianceState_active,

    /// Invalid state
    steerexecImplCmn_btmComplianceState_invalid,
} steerexecImplCmn_btmComplianceState_e;

/**
 * @brief Type of steering prohibition for the STA
 */
typedef enum steerexecImplCmnSteeringProhibitType_e {
    /// No steering prohibition
    steerexecImplCmnSteeringProhibitType_none,

    /// Short steering prohibition (used for clean BTM steering)
    steerexecImplCmnSteeringProhibitType_short,

    /// Long steering prohibition (used for legacy and non-clean
    /// BTM steering)
    steerexecImplCmnSteeringProhibitType_long,

    /// Special steering prohibit timer set by another device in the network
    steerexecImplCmnSteeringProhibitType_remote,

    /// Invalid steering prohibition
    steerexecImplCmnSteeringProhibitType_invalid
} steerexecImplCmnSteeringProhibitType_e;

/**
 * @brief Status of attempted steer when complete
 */
typedef enum steerexecImplCmnSteeringStatusType_e {
    /// Success.
    steerexecImplCmnSteeringStatusType_success,

    /// Steer was aborted due to excessive auth rejects.
    steerexecImplCmnSteeringStatusType_abort_auth_reject,

    /// Steer was aborted because target RSSI is too low
    steerexecImplCmnSteeringStatusType_abort_low_rssi,

    /// Steer was aborted because steering was started to
    /// a different target
    steerexecImplCmnSteeringStatusType_abort_change_target,

    /// Steer was aborted by user.
    steerexecImplCmnSteeringStatusType_abort_user,

    /// BTM reject response.
    steerexecImplCmnSteeringStatusType_btm_reject,

    /// BTM response timeout.
    steerexecImplCmnSteeringStatusType_btm_response_timeout,

    /// Association timeout.
    steerexecImplCmnSteeringStatusType_assoc_timeout,

    /// Steer was aborted due to channel change
    steerexecImplCmnSteeringStatusType_channel_change,

    /// Steer was aborted since preparation failed
    steerexecImplCmnSteeringStatusType_prepare_fail,

    /// Steer was aborted since association occurred on an unexpected BSS
    steerexecImplCmnSteeringStatusType_unexpected_bss,

    /// Invalid status.
    steerexecImplCmnSteeringStatusType_invalid
} steerexecImplCmnSteeringStatusType_e;

/**
 * @brief Reason codes why a steer may be accepted / rejected.
 *
 * Note: should be kept in sync with the OTA values provided in
 * steermsg_steerStatus_e.
 */
typedef enum steerexecImplCmnSteeringAcceptType_e {
    steerexecImplCmnSteeringAcceptType_success,

    // The STA is currently associated to the rejecting node.
    steerexecImplCmnSteeringAcceptType_rejectAssociated,

    // The rejecting node believes the STA is still prohibited.
    steerexecImplCmnSteeringAcceptType_rejectProhibited,

    // The rejecting node believes the STA is unfriendly.
    steerexecImplCmnSteeringAcceptType_rejectUnfriendly,

    // The rejecting node believes the STA is ineligible for the type of
    // steering requested.
    steerexecImplCmnSteeringAcceptType_rejectIneligible,

    // The rejecting node has an internal failure, and is unable to steer.
    steerexecImplCmnSteeringAcceptType_rejectUnable,
} steerexecImplCmnSteeringAcceptType_e;

/**
 * @brief Create the steering executor.
 *
 * @param [in] config  the configuration parameters needed
 * @param [in] dbgModule  the area to use for log messages
 *
 * @return a handle to the executor instance, or NULL if creation failed
 */
steerexecImplCmnHandle_t steerexecImplCmnCreate(const steerexecImplCmnConfig_t *config,
                                          struct dbgModule *dbgModule);

/**
 * @brief Abort any steering operation which may be in progress
 *        for the STA.
 *
 * Note that with BTM based steering only the blacklisting can be
 * aborted (if used). The BTM request will remain in progress and
 * can only be undone via sending another BTM request in the future.
 *
 * If the abort reason is channel change, will remove all blacklist
 * even if no steering is in progress.
 *
 * @param [in] exec  the executor instance to use
 * @param [in] entry  the handle to the STA for which to abort
 * @param [in] status reason for the abort
 * @param [out] ignored  if the request was ignored by the executor, this
 *                       will be set to LBD_TRUE; otherwise it will be set
 *                       to LBD_FALSE indicating it was acted upon by the
 *                       executor; this parameter may be NULL if the caller
 *                       does not care to distinguish between ignored and
 *                       non-ignored requests
 *
 * @return LBD_OK on success; otherwise LBD_NOK
 */
LBD_STATUS steerexecImplCmnAbort(steerexecImplCmnHandle_t exec,
                              stadbEntry_handle_t entry,
                              steerexecImplCmnSteeringStatusType_e status,
                              LBD_BOOL *ignored);

/**
 * @brief Abort any pre-association steering operation which may
 *        be in progress for the STA.
 *
 * @param [in] exec  the executor instance to use
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
LBD_STATUS steerexecImplCmnAbortAllowAssoc(steerexecImplCmnHandle_t exec,
                                        stadbEntry_handle_t handle,
                                        LBD_BOOL *ignored);

/**
 * @brief Allows the STA to associate on any channels in
 *        channelList (used for pre-association steering).
 *        The STA will be prohibited from associating on any
 *        channel not on channelList
 *
 * @param [in] exec  the executor instance to use
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
LBD_STATUS steerexecImplCmnAllowAssoc(
    steerexecImplCmnHandle_t exec,
    stadbEntry_handle_t entry,
    u_int8_t channelCount,
    const lbd_channelId_t *channelList,
    LBD_BOOL *ignored);

/**
 * @brief Steer the STA to any of the BSSes listed in
 *        candidateList (used for post-association steering).
 *
 * @param [in] exec  the executor instance to use
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
LBD_STATUS steerexecImplCmnSteer(steerexecImplCmnHandle_t exec,
                              stadbEntry_handle_t entry,
                              u_int8_t candidateCount,
                              const lbd_bssInfo_t *candidateList,
                              steerexec_reason_e reason,
                              LBD_BOOL *ignored);

/**
 * @brief Inform the steering executor of an update on the
 *        association for a given STA.
 *
 * @param [in] exec  the executor instance to use
 * @param [in] entry  the handle to the STA which was updated
 * @param [in] lastAssocBSS  the BSS the STA was associated before this update
 */
void steerexecImplCmnHandleAssocUpdate(steerexecImplCmnHandle_t exec,
                                       stadbEntry_handle_t entry,
                                       const lbd_bssInfo_t *lastAssocBSS);

/**
 * @brief Returns the conditions under which entry can be
 *        steered at this time.
 *
 * @pre Should only be called for associated STAs
 *
 * @param [in] exec  the executor instance to use
 * @param [in] entry STA to determine steering eligibility for
 * @param [in] reportReasonNotEligible  whether to report the
 *                                      reason why the STA is
 *                                      not eligible for
 *                                      steering
 *
 * @return Eligibility for handle to be steered
 */
steerexec_steerEligibility_e steerexecImplCmnDetermineSteeringEligibility(
    steerexecImplCmnHandle_t exec,
    stadbEntry_handle_t entry,
    LBD_BOOL reportReasonNotEligible);

/**
 * @brief Determines if a steer should be aborted if the STA
 *        becomes active.
 *
 * @param [in] exec  the executor instance to use
 * @param [in] handle STA to determine if the steer should be
 *                    aborted
 *
 * @return LBD_TRUE if steer should be aborted, LBD_FALSE
 *         otherwise
 */
LBD_BOOL steerexecImplCmnShouldAbortSteerForActive(steerexecImplCmnHandle_t exec,
                                                stadbEntry_handle_t handle);

/**
 * @brief Register a function to get called back when an entry can be
 *        steered again (after previously not being allowed).
 *
 * @param [in] exec  the executor instance to use
 * @param [in] callback  the callback function to invoke
 * @param [in] cookie  the parameter to pass to the callback function
 *
 * @return LBD_OK on success; otherwise LBD_NOK
 */
LBD_STATUS steerexecImplCmnRegisterSteeringAllowedObserver(
        steerexecImplCmnHandle_t exec,
        steerexec_steeringAllowedObserverCB callback,
        void *cookie);

/**
 * @brief Unregister the observer callback function.
 *
 * @param [in] exec  the executor instance to use
 * @param [in] callback  the callback function to unregister
 * @param [in] cookie  the registered parameter to pass to the callback
 *                     function
 *
 * @return LBD_OK on success; otherwise LBD_NOK
 */
LBD_STATUS steerexecImplCmnUnregisterSteeringAllowedObserver(
        steerexecImplCmnHandle_t exec,
        steerexec_steeringAllowedObserverCB callback,
        void *cookie);

/**
 * @brief Destroy the steering executor.
 *
 * @param [in] exec  the steering executor instance to destroy
 *
 * @return LBD_OK on success; otherwise LBD_NOK
 */
void steerexecImplCmnDestroy(steerexecImplCmnHandle_t exec);

/**
 * @brief Start a steer that has already been prepared
 *
 * @param [in] exec  handle to the executor instance
 * @param [in] entry  stadb entry
 * @param [in] staAddr  MAC address of STA
 * @param [out] shouldIgnore  if starting the steer fails, but
 *                            the failure should be ignored (ie.
 *                            don't clean up the current steer)
 *
 * @return LBD_OK if the steer was started successfully, LBD_NOK
 *         otherwise
 */
LBD_STATUS steerexecImplCmnStartPreparedSteer(steerexecImplCmnHandle_t exec,
                                              stadbEntry_handle_t entry,
                                              const struct ether_addr *staAddr,
                                              LBD_BOOL *shouldIgnore);

/**
 * @brief Check if it's OK to start a steer of the specified
 *        type
 *
 * @param [in] exec  handle to the executor instance
 * @param [in] handle  stadb handle
 * @param [in] staAddr  MAC address of STA
 * @param [in] steerType  steer type requested
 * @param [in] isSteerInProgress  set to LBD_TRUE if a steer is
 *                                currently in progress (and
 *                                should be updated); LBD_FALSE
 *                                if this is a new steer
 *
 * @return code indicating if the steer can be accepted, or
 *         reason code why not
 */
steerexecImplCmnSteeringAcceptType_e steerexecImplCmnSteerOK(
    void *exec,
    stadbEntry_handle_t handle,
    const struct ether_addr *staAddr,
    steerexecImplCmnSteeringType_e steerType,
    LBD_BOOL isSteerInProgress);

/**
 * @brief Prepare for a steer based on a request
 *
 * @param [in] handle  stadb handle
 * @param [in] staAddr  MAC address of STA
 * @param [in] steerType  steer type requested
 * @param [in] numUnresolvedCandidates  number of candidates
 *        that couldn't be resolved
 * @param [in] candidateCount  count of resolved candidates
 * @param [in] candidateList  list of resolved candidates
 * @param [in] blacklistAutoClear  set to LBD_TRUE if blacklist
 *                                 should be cleared on
 *                                 completion of steer,
 *                                 LBD_FALSE otherwise
 * @param [in] blacklistMaxTime  maximum time the blacklist
 *                               should remain installed on
 *                               completion of steer if
 *                               blacklistAutoClear is LBD_FALSE
 * @param [in] msgTransaction  the messaging transaction ID for
 *                             the steer to begin
 * @param [in] isSteerInProgress  set to LBD_TRUE if a steer is
 *                                currently in progress (and
 *                                should be updated); LBD_FALSE
 *                                if this is a new steer
 *
 * @return LBD_OK if steer could be prepared, LBD_NOK otherwise
 */
LBD_STATUS steerexecImplCmnPrepareForSteeringReq(
    stadbEntry_handle_t handle,
    const struct ether_addr *staAddr,
    steerexecImplCmnSteeringType_e steerType,
    u_int8_t numUnresolvedCandidates,
    u_int8_t candidateCount,
    const lbd_bssInfo_t *candidateList,
    LBD_BOOL blacklistAutoClear,
    u_int32_t blacklistMaxTime,
    u_int8_t msgTransaction,
    LBD_BOOL isSteerInProgress);

/**
 * @brief Cleanup a prepared steer without starting it
 *
 * @param [in] entry  stadb entry
 * @param [in] staAddr  MAC address of STA
 *
 * @return LBD_OK if steer could be cleaned up, LBD_NOK
 *         otherwise
 */
LBD_STATUS steerexecImplCmnClearPreparedSteer(
    stadbEntry_handle_t entry,
    const struct ether_addr *staAddr);

/**
 * @brief Get the time since a STA has last been steered
 *
 * @param [in] handle  stadb handle
 *
 * @return Time since handle has last been steered, UINT_MAX if
 *         it has never been steered
 */
u_int32_t steerexecImplCmnGetTimeSinceLastSteered(stadbEntry_handle_t handle);

/**
 * @brief Set the common steering state to a set of initial
 *        conditions
 *
 * @param [in] handle  stadb handle
 * @param [in] staAddr  MAC address of STA
 * @param [in] secsSinceSteered  seconds since this STA was last
 *                               steered
 * @param [in] prohibitRemainingSecs  time remaining on the
 *                                    prohibit timer
 * @param [in] consecFailures  number of consecutive legacy
 *                             steering failures
 * @param [in] unfriendlyTimerRemainingSecs  time remaining on
 *                                           the unfriendly
 *                                           timer
 */
void steerexecImplCmnSetState(stadbEntry_handle_t entry,
                              const struct ether_addr *staAddr,
                              u_int32_t secsSinceSteered,
                              u_int32_t prohibitRemainingSecs,
                              u_int32_t consecFailures,
                              u_int32_t unfriendlyTimerRemainingSecs);

/**
 * @brief Set the BTM steering state to a set of initial
 *        conditions
 *
 * @param [in] entry  stadb handle
 * @param [in] staAddr  MAC address of STA
 * @param [in] btmCompliance  BTM compliance state
 * @param [in] btmIdleConsecFail  number of consecutive BTM idle
 *                                failures
 * @param [in] btmActiveConsecFail  number of consecutive BTM
 *                                  active failures
 * @param [in] btmUnfriendlyRemainingSecs  time remaining on the
 *                                         BTM unfriendly timer
 * @param [in] btmActiveUnfriendlyRemainingSecs  time remaining
 *                                               on the BTM
 *                                               active
 *                                               unfriendly
 *                                               timer
 */
void steerexecImplCmnSetBTMState(stadbEntry_handle_t entry,
                                 const struct ether_addr *staAddr,
                                 steerexecImplCmn_btmComplianceState_e btmCompliance,
                                 u_int32_t btmIdleConsecFail,
                                 u_int32_t btmActiveConsecFail,
                                 u_int32_t btmUnfriendlyRemainingSecs,
                                 u_int32_t btmActiveUnfriendlyRemainingSecs);

/**
 * @brief Fetch the current common state
 *
 * @param [in] entry  stadb handle
 * @param [out] secsSinceSteered  seconds since this STA was
 *                               last steered
 * @param [out] prohibitRemainingSecs  time remaining on the
 *                                    prohibit timer
 * @param [out] consecFailures  number of consecutive legacy
 *                             steering failures
 * @param [out] unfriendlyTimerRemainingSecs  time remaining on
 *                                           the unfriendly
 *                                           timer
 */
void steerexecImplCmnGetState(stadbEntry_handle_t entry,
                              u_int32_t *secsSinceSteered,
                              u_int32_t *prohibitRemainingSecs,
                              u_int8_t *consecFailures,
                              u_int32_t *unfriendlyTimerRemainingSecs);

/**
 * @brief Get the current BTM steering state
 *
 * @param [in] entry  stadb handle
 * @param [out] btmCompliance  BTM compliance state
 * @param [out] btmIdleConsecFail  number of consecutive BTM
 *                                 idle failures
 * @param [out] btmActiveConsecFail  number of consecutive BTM
 *                                   active failures
 * @param [out] btmUnfriendlyRemainingSecs  time remaining on
 *                                          the BTM unfriendly
 *                                          timer
 * @param [out] btmActiveUnfriendlyRemainingSecs  time remaining
 *                                                on the BTM
 *                                                active
 *                                                unfriendly
 *                                                timer
 */
void steerexecImplCmnGetBTMState(stadbEntry_handle_t entry,
                                 steerexecImplCmn_btmComplianceState_e *btmCompliance,
                                 u_int8_t *btmIdleConsecFail,
                                 u_int8_t *btmActiveConsecFail,
                                 u_int32_t *btmUnfriendlyRemainingSecs,
                                 u_int32_t *btmActiveUnfriendlyRemainingSecs);

/**
 * @brief Handle completion of a steer to a remote BSS
 *
 * @param [in] exec  handle to the executor instance
 * @param [in] entry  stadb handle
 * @param [in] staAddr  MAC address of STA
 * @param [in] assocBSS  BSS STA has associated on
 *
 * @return LBD_TRUE if steer is successfully completed,
 *         LBD_FALSE otherwise
 */
LBD_BOOL steerexecImplCmnHandleRemoteSteerComplete(
    steerexecImplCmnHandle_t exec,
    stadbEntry_handle_t entry,
    const struct ether_addr *staAddr,
    const lbd_bssInfo_t *assocBSS);

/**
 * @brief Abort the current steer as requested by another device
 *        in the network
 *
 * @param [in] staAddr  MAC address of STA
 * @param [in] reason  reason for the abort
 * @param [in] msgTransaction  transaction ID on the steer to
 *                             abort
 *
 * @return LBD_OK on success, LBD_NOK on failure
 */
LBD_STATUS steerexecImplCmnRemoteAbort(const struct ether_addr *staAddr,
                                       steerexecImplCmnSteeringStatusType_e reason,
                                       u_int8_t msgTransaction);

/**
 * @brief Return if the STA is being steered via BTM (either
 *        with or without blacklists)
 *
 * @param [in] steerType  steering type to check
 *
 * @return LBD_TRUE if this is a BTM steer type, LBD_FALSE
 *         otherwise
 */
LBD_BOOL steerexecImplCmnIsBTMSteer(steerexecImplCmnSteeringType_e steerType);

/**
 * @brief Return if the STA is being steered while active
 *
 * @param [in] steerType  steering type to check
 *
 * @return LBD_TRUE if this is an active steer type, LBD_FALSE
 *         otherwise
 */
LBD_BOOL steerexecImplCmnIsActiveSteer(steerexecImplCmnSteeringType_e steerType);

/**
 * @brief React to an authentication rejection that was sent, aborting
 *        steering if necessary.
 *
 * Also start the T-Steering timer if the STA has a steering in progress
 * and the timer has not started.
 *
 * If this is a BTM client, mark as steering prohibited now
 * (since this message indicates the client is attempting to
 * associate somewhere it wasn't steered to).
 *
 * @param [in] exec  the executor instance to use
 * @param [in] entry  the entry for which an auth reject was sent
 * @param [in] state  the internal state used by the executor
 *
 * @return LBD_TRUE if the steering was aborted; otherwise LBD_FALSE
 */
LBD_BOOL steerexecImplCmnHandleAuthRej(
        struct steerexecImplCmnPriv_t *exec, stadbEntry_handle_t entry,
        void *state, u_int8_t numAuthRejects);

/**
 * @brief Determine if the state should be updated (on request
 *        from remote node)
 *
 * @param [in] exec  the executor instance to use
 * @param [in] entry  the entry for which an auth reject was sent
 * @param [in] staAddr  MAC address of STA
 * @param [in] isBTMSupported  set to LBD_TRUE if STA supports
 *                             BTM
 * @param [in] secsSinceSteered  time since the STA was steered
 *                               in the state
 *
 * @return LBD_TRUE if the state should be updated, LBD_FALSE
 *         otherwise
 */
LBD_BOOL steerexecImplCmnShouldUpdateState(
    struct steerexecImplCmnPriv_t *exec, stadbEntry_handle_t entry,
    const struct ether_addr *staAddr, LBD_BOOL isBTMSupported,
    u_int32_t secsSinceSteered);

/**
 * @brief Check if a steer is currently in progress
 *
 * @param [in] entry  stadb entry for the STA to check
 *
 * @return LBD_TRUE if a steer for entry is in progress,
 *         LBD_FALSE otherwise
 */
LBD_BOOL steerexecImplCmnIsSteerInProgress(stadbEntry_handle_t entry);

/**
 * @brief Check if a steer is being started (in the Prepare
 *        state)
 *
 * @param [in] entry  stadb entry for the STA to check
 *
 * @return LBD_TRUE if a steer for entry is in the prepare
 *         state, LBD_FALSE otherwise
 */
LBD_BOOL steerexecImplCmnIsStartingNewSteer(stadbEntry_handle_t entry);

/**
 * @brief Check if a time difference is 'close enough' to 0
 *
 * @param [in] timeDiff  time difference between the expiry
 *                       time and now (will be 0 if the expiry
 *                       time is in the past)
 *
 * @return LBD_TRUE if the timer is either already expired, or
 *         close enough to be considered expired, LBD_FALSE
 *         otherwise
 */
LBD_BOOL steerexecImplCmnTimeDiffLessThanErrorTime(time_t timeDiff);

// ====================================================================
// Protected functions
// ====================================================================

/**
 * @brief Create the steering implementation specific to network configuration.
 *
 * @param [in] exec  handle to the executor instance
 * @param [in] dbgModule  the area to use for log messages
 */
void steerexecImplCreate(steerexecImplCmnHandle_t exec, struct dbgModule *dbgModule);

/**
 * @brief Network configuration specific preparation
 *
 * @param [in] entry  stadb entry
 * @param [in] staAddr  MAC address of STA
 * @param [in] candidateCount  number of steering candidates
 * @param [in] candidateList  list of steering candidates
 * @param [in] steerType  type of steer
 * @param [in] blacklistAutoClear  set to LBD_TRUE if blacklist
 *                                 should be cleared on
 *                                 completion of steer,
 *                                 LBD_FALSE otherwise
 * @param [in] blacklistMaxTime  maximum time the blacklist
 *                               should remain installed on
 *                               completion of steer if
 *                               blacklistAutoClear is LBD_FALSE
 * @param [in] resetProhibitTime  set to LBD_TRUE if the
 *                                prohibit time in the CSBC
 *                                state should be reset (due to
 *                                starting a new steer)
 * @param [out] preparationComplete  set to LBD_TRUE if
 *                                   preparation is complete,
 *                                   LBD_FALSE if need to wait
 *                                   to steer
 * @param [out] msgTransaction  the messaging transaction ID for
 *                              the steer to begin
 *
 * @return LBD_OK if preparation was successful, LBD_NOK if it
 *         failed
 */
LBD_STATUS steerexecImplPrepareForSteering(
    stadbEntry_handle_t entry,
    const struct ether_addr *staAddr,
    u_int8_t candidateCount,
    const lbd_bssInfo_t *candidateList,
    steerexecImplCmnSteeringType_e steerType,
    LBD_BOOL blacklistAutoClear,
    u_int32_t blacklistMaxTime,
    LBD_BOOL resetProhibitTime,
    LBD_BOOL *preparationComplete,
    u_int8_t *msgTransaction);

/**
 * @brief Network configuration specific handling of a steer
 *        abort
 *
 * @param [in] transId  network specific transaction handle
 * @param [in] addr  MAC address of STA for which steering was
 *                   aborted
 * @param [in] status  status code for the steer abort
 *
 * @return LBD_OK if the abort handling was successful, LBD_NOK
 *         otherwise
 */
LBD_STATUS steerexecImplAbort(u_int8_t transId,
                              const struct ether_addr *addr,
                              steerexecImplCmnSteeringStatusType_e status);

/**
 * @brief Network configuration specific handling of a local
 *        association
 *
 * @param [in] staAddr  MAC address of STA that associated
 * @param [in] steeringComplete  set to LBD_TRUE if the
 *                               association also ended a steer
 *                               successfully, LBD_FALSE
 *                               otherwise
 */
void steerexecImplHandleAssocUpdate(const struct ether_addr *staAddr,
                                    LBD_BOOL steeringComplete);

/**
 * @brief Network configuration specific handling of an auth
 *        reject being sent
 *
 * @param [in] staAddr  MAC address of STA to which the auth
 *                      reject was sent
 * @param [in] numConsecRejects  number of consecutive auth
 *                               rejects sent to that STA
 */
void steerexecImplHandleAuthReject(const struct ether_addr *staAddr,
                                   u_int8_t numConsecRejects);

/**
 * @brief Network configuration specific checking that a
 *        candidate list is valid
 *
 * @param [in] candidateCount  number of steering candidates
 * @param [in] candidateList  list of steering candidates
 *
 * @return LBD_TRUE if the candidate list is valid, LBD_FALSE
 *         otherwise
 */
LBD_BOOL steerexecImplCandidateListValid(u_int8_t candidateCount,
                                         const lbd_bssInfo_t *candidateList);

#ifdef GMOCK_UNIT_TESTS
/**
 * @brief Check if a device is steering unfriendly
 */
LBD_BOOL steerexecImplCmnIsSTASteeringUnfriendly(stadbEntry_handle_t entry);
#endif

#ifdef LBD_DBG_MENU
struct cmdContext;

/**
 * @brief Dump the overall executor information along with the
 *        header for the individual entries.  Information
 *        relevant to legacy devices and BTM devices steered via
 *        legacy mechanisms only.
 *
 * @param [in] context  the output context
 * @param [in] exec  the executor instance to use
 */
void steerexecImplCmnDumpLegacyHeader(struct cmdContext *context,
                                   steerexecImplCmnHandle_t exec);

/**
 * @brief Dump the overall executor information along with the
 *        header for the individual entries.  802.11v BSS
 *        Transition Management compatible devices only.
 *
 * @param [in] context  the output context
 * @param [in] exec  the executor instance to use
 */
void steerexecImplCmnDumpBTMHeader(struct cmdContext *context,
                                steerexecImplCmnHandle_t exec);

/**
 * @brief Dump the header for BTM-related statistics (per STA).
 *
 * @param [in] context  the output context
 * @param [in] exec  the executor instance to use
 */
void steerexecImplCmnDumpBTMStatisticsHeader(struct cmdContext *context,
                                          steerexecImplCmnHandle_t exec);

/**
 * @brief Dump the steering state for a single entry.
 *
 * @param [in] context  the output context
 * @param [in] exec  the executor instance to use
 * @param [in] entry  the entry to dump
 * @param [in] inProgressOnly  flag indicating whether to only dump entries
 *                             that are currently being steered
 * @param [in] dumpBTMClients set to LBD_TRUE if dumping
 *                            information relevant to BTM
 *                            stations
 * @param [in] dumpStatistics set to LBD_TRUE if dumping
 *                            BTM statistics
 */
void steerexecImplCmnDumpEntryState(struct cmdContext *context,
                                 steerexecImplCmnHandle_t exec,
                                 stadbEntry_handle_t entry,
                                 LBD_BOOL inProgressOnly,
                                 LBD_BOOL dumpBTMClients,
                                 LBD_BOOL dumpStatistics);

/**
 * @brief Generate requested diagnostic logs for a given STA
 *
 * @param [in] exec  the executor instance to use
 * @param [in] handle  the handle to the given STA
 * @param [in] prohibit  whether to generate diaglog for prohibit
 * @param [in] unfriendly  whether to generate diaglog for unfiendly
 * @param [in] compliance  whether to generate diaglog for BTM compliance
 */
void steerexecImplCmnGenerateDiaglog(steerexecImplCmnHandle_t exec,
                                     stadbEntry_handle_t handle,
                                     LBD_BOOL prohibit,
                                     LBD_BOOL unfriendly,
                                     LBD_BOOL compliance);

/**
 * @brief Generate JSON for steering state
 *
 * @param [in] exec  the executor instance to use
 * @param [in] handle  the handle to the STA
 */
json_t *steerexecImplCmnJsonize(steerexecImplCmnHandle_t exec,
                                stadbEntry_handle_t entry);

/**
 * @brief Restore steering state from JSON
 *
 * @param [in] exec  the executor instance to use
 * @param [in] handle  the handle to the STA
 * @param [in] json  the steerexec json object
 */
void steerexecImplCmnRestore(steerexecImplCmnHandle_t exec,
				stadbEntry_handle_t entry,
                                json_t *json);
#endif /* LBD_DBG_MENU */

#if defined(__cplusplus)
}
#endif

#endif
