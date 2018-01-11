// vim: set et sw=4 sts=4 cindent:
/*
 * @File: steerexecImplCmn.c
 *
 * @Abstract: Package-level implementation of the steering executor for
 *            802.11v BSS Transition Management compliant clients and
 *            legacy clients
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
 *
 */

#include <stdlib.h>
#include <time.h>
#include <limits.h>
#include <math.h>

#include <dbg.h>
#include <evloop.h>
#include <jansson.h>

#ifdef LBD_DBG_MENU
#include <cmd.h>
#endif

#include "lb_common.h"
#include "lb_assert.h"
#include "lbd_assert.h"
#include "module.h"
#include "profile.h"

#include "steerexecImplCmn.h"
#include "steerexecDiaglogDefs.h"
#include "stadb.h"
#include "bandmon.h"
#include "diaglog.h"

// For now, we are only permitting 2 observers, as it is likely that the
// following will need to observe steering allowed changes:
//
// 1. Pre-association steering decision maker
// 2. Post-association steering decision maker
#define MAX_STEERING_ALLOWED_OBSERVERS 2

/**
 * @brief Structure used to define a steerexec common timer
 *        (shared between all STAs)
 */
typedef struct steerexecImplCmnTimerStruct_t {
    /// Timer implementation.
    struct evloopTimeout timer;

    /// Count of entries waiting for timeout.
    size_t countEntries;

    /// Next expiry time.
    time_t nextExpiry;
} steerexecImplCmnTimerStruct_t;

/**
 * @brief Internal state for the steering executor used for
 *        legacy steering.
 */
struct steerexecImplCmnLegacyPriv_t {
    /// Timer used to age out devices marked as steering unfriendly.
    steerexecImplCmnTimerStruct_t steeringUnfriendly;

    /// Timer used to age out devices blacklisted.
    steerexecImplCmnTimerStruct_t blacklistTimer;
};

/**
 * @brief Internal state for the steering executor used for
 *        802.11v BTM steering.
 */
struct steerexecImplCmnBTMPriv_t {
    /// Dialog token to send with the next BTM request
    u_int8_t dialogToken;

    /// Timer used to age out devices marked as BTM-steering unfriendly.
    steerexecImplCmnTimerStruct_t unfriendlyTimer;

    /// Timer used to age out devices marked as Active-steering unfriendly.
    steerexecImplCmnTimerStruct_t activeUnfriendlyTimer;
};

/**
 * @brief Internal state for the steering executor.
 */
struct steerexecImplCmnPriv_t {
    steerexecImplCmnConfig_t config;

    /// Observer for all changes in the steering allowed status.
    struct steerexecImplCmnSteeringAllowedObserver {
        LBD_BOOL isValid;
        steerexec_steeringAllowedObserverCB callback;
        void *cookie;
    } steeringAllowedObservers[MAX_STEERING_ALLOWED_OBSERVERS];

    /// Transaction ID of the next steer attempt.
    u_int8_t transaction;

    /// Timer used to age out steering prohibitions.
    steerexecImplCmnTimerStruct_t prohibitTimer;

    /// Internal state used for legacy steering
    struct steerexecImplCmnLegacyPriv_t legacy;

    /// Internal state used for 802.11v BTM steering
    struct steerexecImplCmnBTMPriv_t btm;

    struct dbgModule *dbgModule;
};

/**
 * @brief Legacy steering state information stored with each STA
 *        that has been steered.
 */
typedef struct steerexecImplCmnSteeringStateLegacy_t {
    /// The time the last steering was attempted or completed (whichever is
    /// more recent).
    time_t lastSteeringTime;

    /// The time when the prohibit timer expires.
    time_t prohibitExpiryTime;

    /// The number of consecutive authentication rejects seen so far
    /// for the current attempt at steering.
    u_int32_t numAuthRejects;

    /// Flag indicating if this device is steering unfriendly
    LBD_BOOL steeringUnfriendly;

    /// The time when the steering unfriendly timer expires.
    time_t unfriendlyExpiryTime;

    /// Consecutive failure count of legacy steering
    u_int32_t countConsecutiveFailure;

    /// Timer used to track T-steering period
    struct evloopTimeout tSteerTimer;

    /// Count of disabled channels (used for pre-association steering)
    u_int8_t disabledChannelCount;

    /// Set of disabled channels (used for pre-association steering)
    lbd_channelId_t disabledChannelList[WLANIF_MAX_RADIOS-1];
} steerexecImplCmnSteeringStateLegacy_t;

/**
 * @brief Type that denotes current state of steering.
 */
typedef enum steerexecImplCmn_steerState_e {
    /// No steer in progress
    steerexecImplCmn_state_idle,

    /// Preparing to steer
    steerexecImplCmn_state_prepare,

    /// BTM request sent, waiting on BTM response
    steerexecImplCmn_state_waiting_response,

    /// Waiting on association
    steerexecImplCmn_state_waiting_association,

    /// Steer was aborted
    steerexecImplCmn_state_aborted,

    /// Failure during steering
    steerexecImplCmn_state_failed,

    /// Invalid state
    steerexecImplCmn_state_invalid,
} steerexecImplCmn_steerState_e;

static const char *steerexecImplCmn_stateString[] = {
    "Idle",
    "Prepare",
    "WaitResp",
    "WaitAssoc",
    "Aborted",
    "Invalid"
};

static const char *steerexecImplCmn_btmComplianceString[] = {
    "Idle",
    "ActiveUnfriendly",
    "Active",
    "Invalid"
};

/**
 * @brief 802.11v BSS Transition Management steering state
 *        information stored with each STA that has been
 *        steered.
 */
typedef struct steerexecImplCmnSteeringStateBTM_t {
    /// Timer used to track when a BTM response or association should be received
    /// (which is expected depends on the state)
    struct evloopTimeout timer;

    /// The time when the BTM unfriendly timer expires.
    time_t unfriendlyExpiryTime;

    /// The time when the BTM active steering unfriendly timer expires.
    time_t activeUnfriendlyExpiryTime;

    /// Flag indicating if this device is BTM unfriendly
    LBD_BOOL btmUnfriendly;

    /// State tracking how we should attempt to steer this client
    steerexecImplCmn_btmComplianceState_e complianceState;

    /// Dialog token sent with most recent request
    u_int8_t dialogToken;

    /// Record the BSSID the STA has indicated it will transition to
    struct ether_addr bssid;

    /// BSS STA was associated on at the start of the steer
    lbd_bssInfo_t initialAssoc;

    /// Count how many times transition has failed due to no response received
    u_int32_t countNoResponseFailure;

    /// Count how many times transition has failed due to reject code received
    u_int32_t countRejectFailure;

    /// Count how many times transition has failed due to no / incorrect association received
    u_int32_t countAssociationFailure;

    /// Count how many times transition has succeeded
    u_int32_t countSuccess;

    /// Consecutive failure count as active (since the last success as active)
    u_int32_t countConsecutiveFailureActive;

    /// Consecutive failure count (since the last BTM success)
    /// This is used in the idle state, or after transitioning to the active state
    /// (since steerexecImplCmn_maxConsecutiveBTMFailuresAsActive consecutive failures
    /// are required before the active consecutive failure count is incremented)
    u_int32_t countConsecutiveFailure;

    /// Count how many times a BTM response is received with a different BSSID
    /// than the target BSS(es)
    u_int32_t countBSSIDMismatch;
} steerexecImplCmnSteeringStateBTM_t;

static const char *steerexecImplCmn_SteeringTypeString[] = {
    "None",
    "Legacy",
    "BTM and Blacklist",
    "BTM",
    "BTM and Blacklist (Active)",
    "BTM (Active)",
    "Pre-Association",
    "BTM BE",
    "BTM BE (Active)",
    "BTM and Blacklist BE",
    "BTM and Blacklist BE (Active)",
    "Legacy BE",
    "Invalid"
};

static const char *steerexecImplCmn_SteeringProhibitTypeString[] = {
    "None",
    "Short",
    "Long",
    "Remote",
    "Invalid"
};

/**
 * @brief Type of blacklist that is active for the STA
 */
typedef enum steerexecImplCmnBlacklistType_e {
    /// Nothing is blacklisted.
    steerexecImplCmnBlacklist_none,

    /// Channel(s) are blacklisted.
    steerexecImplCmnBlacklist_channel,

    /// Candidate(s) are blacklisted.
    steerexecImplCmnBlacklist_candidate,

    /// Invalid.
    steerexecImplCmnBlacklist_invalid
} steerexecImplCmnBlacklistType_e;


static const char *steerexecImplCmn_SteeringBlacklistTypeString[] = {
    "None",
    "Channel",
    "Candidate",
    "Invalid"
};

/**
 * @brief State information that the steering executor stores
 *        with each STA that has been steered.
 */
typedef struct steerexecImplCmnSteeringState_t {
    /// Steering context.
    steerexecImplCmnHandle_t context;

    /// The type of blacklisting for this STA.
    steerexecImplCmnBlacklistType_e blacklistType;

    /// Whether to clear the blacklist when steering completes
    LBD_BOOL blacklistAutoClear;

    // The amount of time to leave the blacklist installed if auto-clearing
    // is disabled.
    u_int32_t blacklistMaxTime;

    /// Reason for the steer
    steerexec_reason_e reason;

    /// Unresolved candidates.
    u_int8_t numUnresolvedCandidates;

    /// Candidate count.
    u_int8_t candidateCount;

    /// Candidate list.
    lbd_bssInfo_t candidateList[STEEREXEC_MAX_CANDIDATES];

    /// Type of steering used.
    steerexecImplCmnSteeringType_e steerType;

    /// State tracking what is the next steer event expected
    steerexecImplCmn_steerState_e state;

    /// Transaction ID of the most recent steer attempt.
    u_int8_t transaction;

    /// Messaging transaction.  This ID is provided when beginning a steer
    /// with a messaging component, and must be provided for any future abort
    /// related messaging.
    u_int8_t msgTransaction;

    /// Whether steering for this device is currently prohibited, and
    /// the length of the prohibition.
    steerexecImplCmnSteeringProhibitType_e steeringProhibited;

    /// Legacy state information.
    steerexecImplCmnSteeringStateLegacy_t legacy;

    /// BTM state information.
    /// Only allocated for STAs that indicate they support BTM.
    steerexecImplCmnSteeringStateBTM_t *btm;
} steerexecImplCmnSteeringState_t;

/**
 * @brief Structure used when iterating through channels to make
 *        sure there is at least one enabled channel with an OK
 *        RSSI.
 */
typedef struct steerexecImplCmnCheckChannelRSSI_t {
    /// Current time
    struct timespec ts;

    /// Steering executor pointer
    struct steerexecImplCmnPriv_t *exec;

    /// Steering state for STA
    steerexecImplCmnSteeringState_t *state;

    /// Count of currently enabled channels
    u_int8_t enabledChannelCount;

    /// List of currently enabled channels
    lbd_channelId_t enabledChannelList[WLANIF_MAX_RADIOS];

    /// Set to LBD_TRUE if there exists a channel that is currently enabled
    /// with an OK RSSI
    LBD_BOOL isChannelRSSIOK;
} steerexecImplCmnCheckChannelRSSI_t;

static const char *steerexec_SteeringReasonString[] = {
    "UserRequest",
    "ActiveUpgrade",
    "ActiveDowngradeRate",
    "ActiveDowngradeRSSI",
    "IdleUpgrade",
    "IdleDowngrade",
    "ActiveOffload",
    "IdleOffload",
    "ActiveAPSteering",
    "IdleAPSteering",
    "APRequest",
    "InterferenceAvoidance",
    "Invalid"
};

static const char *steerexec_SteerEligibilityString[] = {
    "None",
    "Idle",
    "Active",
    "Invalid"
};

static const char *steerexec_SteerStatusString[] = {
    "Success",
    "AuthReject",
    "LowRSSI",
    "ChangeTarget",
    "AbortUser",
    "BTMReject",
    "BTMResponseTimeout",
    "AssocTimeout",
    "ChannelChange",
    "PrepareFail",
    "Unexpected BSS",
    "Invalid"
};

// As long as less time than this is remaining on a timer (prohibit, unfriendly),
// and a PFS request is received, treat the request as valid, and allow the
// steer to proceed
static const u_int32_t steerexecImplCmn_timerErrorValue = 1;

// ====================================================================
// Forward decls for internal "private" functions
// ====================================================================

static steerexecImplCmnSteeringState_t *steerexecImplCmnGetOrCreateSteeringState(
        steerexecImplCmnHandle_t exec, stadbEntry_handle_t entry);

static void steerexecImplCmnManageSteeringStateLifecycleCB(
        stadbEntry_handle_t handle, void *state);

static steerexecImplCmnSteeringType_e steerexecImplCmnDetermineSteeringType(
    steerexecImplCmnSteeringState_t *state,
    steerexecImplCmnHandle_t exec,
    stadbEntry_handle_t entry,
    const struct ether_addr *staAddr,
    stadbEntry_bssStatsHandle_t stats,
    LBD_BOOL eligibilityOnly,
    LBD_BOOL reportReasonNotEligible,
    LBD_BOOL isBestEffort);

static u_int32_t steerexecImplCmnGetSteeringProhibitTime(
    steerexecImplCmnHandle_t exec,
    steerexecImplCmnSteeringProhibitType_e prohibit);

static void steerexecImplCmnStartTimer(struct dbgModule *dbgModule,
                                       steerexecImplCmnTimerStruct_t *timer,
                                       time_t expiryTime,
                                       time_t incTime);

static LBD_BOOL steerexecImplCmnIsInSteeringQuietPeriod(
        steerexecImplCmnHandle_t exec,
        stadbEntry_handle_t entry,
        steerexecImplCmnSteeringState_t *state);
static void steerexecImplCmnStartSteeringProhibit(
        steerexecImplCmnHandle_t exec, steerexecImplCmnSteeringState_t *state,
        const struct ether_addr *staAddr,
        steerexecImplCmnSteeringProhibitType_e prohibit,
        u_int32_t prohibitTime);
static void steerexecImplCmnStartSteeringProhibitLocal(
    steerexecImplCmnHandle_t exec,
    steerexecImplCmnSteeringState_t *state,
    const struct ether_addr *staAddr,
    steerexecImplCmnSteeringProhibitType_e prohibit,
    stadbEntry_handle_t entry);

static void steerexecImplCmnProhibitTimeoutHandler(void *cookie);
static void steerexecImplCmnProhibitIterateCB(stadbEntry_handle_t entry,
                                             void *cookie);

static void steerexecImplCmnStartSteeringUnfriendly(
        steerexecImplCmnHandle_t exec, steerexecImplCmnSteeringState_t *state,
        const struct ether_addr *staAddr);
static void steerexecImplCmnUpdateTimer(
    struct dbgModule *dbgModule,
    steerexecImplCmnTimerStruct_t *timer,
    time_t currentTime,
    u_int32_t remainingSecs,
    time_t *currentExpiryTime);

static void steerexecImplCmnUpdateSteeringUnfriendly(
    LBD_BOOL isUnfriendly,
    steerexecImplCmnSteeringState_t *state,
    const struct ether_addr *staAddr);

static void steerexecImplCmnUpdateBTMComplianceState(
    LBD_BOOL isUnfriendly, steerexecImplCmn_btmComplianceState_e btmCompliance,
    steerexecImplCmnSteeringState_t *state, const struct ether_addr *staAddr);

static void steerexecImplCmnStartBTMUnfriendly(
        steerexecImplCmnHandle_t exec,
        steerexecImplCmnSteeringState_t *state,
        const struct ether_addr *staAddr,
        steerexecImplCmnTimerStruct_t *timer,
        u_int32_t exponent,
        u_int32_t maxBackoff,
        time_t *expiryTime);

static void steerexecImplCmnUpdateBTMCompliance(
    stadbEntry_handle_t entry,
    steerexecImplCmnSteeringState_t *state,
    const struct ether_addr *staAddr,
    LBD_BOOL success);

static void steerexecImplCmnUnfriendlyTimeoutHandler(void *cookie);
static void steerexecImplCmnBTMUnfriendlyTimeoutHandler(void *cookie);
static void steerexecImplCmnBTMActiveUnfriendlyTimeoutHandler(void *cookie);
static void steerexecImplCmnUnfriendlyIterateCB(stadbEntry_handle_t entry,
                                             void *cookie);
static void steerexecImplCmnBTMUnfriendlyIterateCB(stadbEntry_handle_t entry,
                                                void *cookie);

static void steerexecImplCmnBlacklistTimeoutHandler(void *cookie);
static void steerexecImplCmnBlacklistIterateCB(stadbEntry_handle_t entry,
                                              void *cookie);
static void steerexecImplCmnCleanupBlacklistBTM(steerexecImplCmnSteeringState_t *state,
                                             stadbEntry_handle_t entry,
                                             const struct ether_addr *staAddr,
                                             steerexecImplCmnSteeringStatusType_e status);

static void steerexecImplCmnNotifySteeringAllowedObservers(
        steerexecImplCmnHandle_t exec, stadbEntry_handle_t entry);

static LBD_STATUS steerexecImplCmnAbortSteerImpl(
        steerexecImplCmnHandle_t exec, stadbEntry_handle_t entry,
        steerexecImplCmnSteeringState_t *state,
        steerexecImplCmnSteeringStatusType_e status,
        LBD_BOOL isLocalAbort);

static void steerexecImplCmnLowRSSIObserver(stadbEntry_handle_t entry, void *cookie);

static void steerexecImplCmnTSteeringTimeoutHandler(void *cookie);

static void steerexecImplCmnBTMTimeoutHandler(void *cookie);

static void steerexecImplCmnRSSIObserver(stadbEntry_handle_t entry,
                                      stadb_rssiUpdateReason_e reason,
                                      void *cookie);

static void steerexecImplCmnMarkBlacklist(
    steerexecImplCmnHandle_t exec,
    steerexecImplCmnSteeringState_t *state,
    steerexecImplCmnBlacklistType_e blacklistType);

static void steerexecImplCmnUpdateTransactionID(steerexecImplCmnHandle_t exec,
                                             steerexecImplCmnSteeringState_t *state);

static void steerexecImplCmnDiagLogSteeringUnfriendly(
        const struct ether_addr *staAddr, LBD_BOOL isUnfriendly,
        u_int32_t consecutiveFailures);
static void steerexecImplCmnDiagLogSteeringProhibited(
        const struct ether_addr *staAddr,
        steerexecImplCmnSteeringProhibitType_e prohibit);
static void steerexecImplCmnDiagLogBTMCompliance(
        const struct ether_addr *staAddr,
        LBD_BOOL btmUnfriendly,
        steerexecImplCmn_btmComplianceState_e complianceState,
        u_int32_t consecutiveFailures,
        u_int32_t consecutiveFailuresActive);
static void steerexecImplCmnDiagLogSteerEnd(
        const struct ether_addr *staAddr,
        u_int8_t transaction,
        steerexecImplCmnSteeringType_e steerType,
        steerexecImplCmnSteeringStatusType_e status);

static LBD_STATUS steerexecImplCmnPrepareForSteering(
    steerexecImplCmnSteeringState_t *state,
    steerexecImplCmnHandle_t exec,
    stadbEntry_handle_t entry,
    u_int8_t candidateCount,
    const lbd_bssInfo_t *candidateList,
    LBD_BOOL *ignored,
    stadbEntry_bssStatsHandle_t stats,
    const lbd_bssInfo_t *bss,
    LBD_BOOL isBestEffort,
    LBD_BOOL *okToSteer);

static LBD_STATUS steerexecImplCmnHandleSteerInProgress(
    steerexecImplCmnSteeringState_t *state,
    steerexecImplCmnHandle_t exec,
    stadbEntry_handle_t entry,
    const struct ether_addr *staAddr,
    steerexecImplCmnSteeringType_e steerType,
    u_int8_t candidateCount,
    const lbd_bssInfo_t *candidateList,
    LBD_BOOL *willSteer);

static LBD_STATUS steerexecImplCmnStartSteer(
    steerexecImplCmnSteeringState_t *state,
    steerexecImplCmnHandle_t exec,
    stadbEntry_handle_t entry,
    const struct ether_addr *staAddr,
    const lbd_bssInfo_t *assocBSS);

static void steerexecImplCmnSaveSteerParams(
    steerexecImplCmnSteeringState_t *state,
    u_int8_t numUnresolvedCandidates,
    u_int8_t candidateCount,
    const lbd_bssInfo_t *candidateList,
    steerexec_reason_e reason,
    LBD_BOOL blacklistAutoClear,
    u_int32_t blacklistMaxTime,
    LBD_BOOL isSteerInProgress);

static LBD_STATUS steerexecImplCmnSteerBTM(
    steerexecImplCmnSteeringState_t *state,
    steerexecImplCmnHandle_t exec,
    stadbEntry_handle_t entry,
    const struct ether_addr *staAddr,
    const lbd_bssInfo_t *assocBSS);

static LBD_STATUS steerexecImplCmnSteerLegacy(
    steerexecImplCmnSteeringState_t *state,
    steerexecImplCmnHandle_t exec,
    stadbEntry_handle_t entry,
    const struct ether_addr *staAddr,
    const lbd_bssInfo_t *assocBSS);

static LBD_STATUS steerexecImplCmnAbortInProgress(
    steerexecImplCmnHandle_t exec,
    steerexecImplCmnSteeringState_t *state,
    stadbEntry_handle_t entry,
    const struct ether_addr *addr,
    steerexecImplCmnSteeringStatusType_e abortReason,
    LBD_BOOL isLocalAbort,
    LBD_BOOL *ignored);

static LBD_STATUS steerexecImplCmnAbortBTM(
        steerexecImplCmnHandle_t exec, steerexecImplCmnSteeringState_t *state,
        stadbEntry_handle_t entry, const struct ether_addr *addr);

static LBD_BOOL steerexecImplCmnHandleAssocUpdateBTM(
    steerexecImplCmnHandle_t exec,
    stadbEntry_handle_t entry,
    steerexecImplCmnSteeringState_t *state,
    const lbd_bssInfo_t *assocBSS,
    const struct ether_addr *staAddr);

static LBD_BOOL steerexecImplCmnHandleAssocUpdateLegacy(
    steerexecImplCmnHandle_t exec,
    stadbEntry_handle_t entry,
    steerexecImplCmnSteeringState_t *state,
    const lbd_bssInfo_t *assocBSS,
    const struct ether_addr *staAddr);

static void steerexecImplCmnHandleAssocPreAssoc(
    steerexecImplCmnHandle_t exec,
    stadbEntry_handle_t entry,
    steerexecImplCmnSteeringState_t *state,
    const lbd_bssInfo_t *assocBSS);

static LBD_BOOL steerexecImplCmnHandleAuthRejLocal(
    struct steerexecImplCmnPriv_t *exec, stadbEntry_handle_t entry,
    const struct ether_addr *staAddr,
    steerexecImplCmnSteeringState_t *state);
static LBD_BOOL steerexecImplCmnHandleAuthRejRemote(
    struct steerexecImplCmnPriv_t *exec, stadbEntry_handle_t entry,
    const struct ether_addr *staAddr,
    steerexecImplCmnSteeringState_t *state,
    u_int8_t numAuthRejects);

static void steerexecImplCmnAssocBlacklistClear(steerexecImplCmnHandle_t exec,
                                             stadbEntry_handle_t entry,
                                             steerexecImplCmnSteeringState_t *state,
                                             const lbd_bssInfo_t *assocBSS);

static void steerexecImplCmnHandleBTMResponseEvent(struct mdEventNode *event);

static void steerexecImplCmnSteerEnd(steerexecImplCmnSteeringState_t *state,
                                     const struct ether_addr *staAddr,
                                     steerexecImplCmnSteeringStatusType_e status,
                                     LBD_BOOL isLocalAbort,
                                     stadbEntry_handle_t entry);
static void steerexecImplCmnSteerEndBTMFailure(
    stadbEntry_handle_t entry,
    steerexecImplCmnSteeringState_t *state,
    const struct ether_addr *staAddr,
    steerexecImplCmnSteeringStatusType_e status);

static LBD_STATUS steerexecImplCmnGetAndValidateRadioChannelList(
    steerexecImplCmnSteeringState_t *state,
    u_int8_t *channelCount,
    lbd_channelId_t *channelList);

static LBD_STATUS steerexecImplCmnChannelDelta(
    steerexecImplCmnSteeringState_t *state,
    u_int8_t channelCount,
    const lbd_channelId_t *channelList,
    u_int8_t *enabledChannelCount,
    lbd_channelId_t *enabledChannelList,
    u_int8_t *disabledChannelCount,
    lbd_channelId_t *disabledChannelList);

static u_int8_t steerexecImplCmnCopyAllNotOnList(
    u_int8_t count1,
    const lbd_channelId_t *list1,
    u_int8_t count2,
    const lbd_channelId_t *list2,
     lbd_channelId_t *outList);

static void steerexecImplCmnUpdateChannelSet(
    steerexecImplCmnSteeringState_t *state,
    u_int8_t enabledChannelCount,
    const lbd_channelId_t *enabledChannelList,
    u_int8_t disabledChannelCount,
    const lbd_channelId_t *disabledChannelList);

static LBD_STATUS steerexecImplCmnEnableAllDisabledChannels(
    steerexecImplCmnSteeringState_t *state,
    const struct ether_addr *staAddr);

static LBD_STATUS steerexecImplCmnEnableAllDisabledCandidates(
    steerexecImplCmnSteeringState_t *state,
    u_int8_t candidateCount,
    const struct lbd_bssInfo_t *candidateList,
    const struct ether_addr *staAddr);

static LBD_BOOL steerexecImplCmnIsOnCandidateList(steerexecImplCmnSteeringState_t *state,
                                               u_int8_t candidateCount,
                                               const lbd_bssInfo_t *candidateList,
                                               const lbd_bssInfo_t *bss);

static LBD_BOOL steerexecImplCmnIsOnChannelList(u_int8_t channelCount,
                                             const lbd_channelId_t *channelList,
                                             lbd_channelId_t channel);

static LBD_BOOL steerexecImplCmnCleanupSteerDifferentType(
    steerexecImplCmnSteeringState_t *state,
    steerexecImplCmnHandle_t exec,
    stadbEntry_handle_t entry,
    const struct ether_addr *staAddr,
    steerexecImplCmnSteeringType_e steerType);
static LBD_STATUS steerexecImplCmnReconcileSteerCandidate(
    steerexecImplCmnSteeringState_t *state,
    steerexecImplCmnHandle_t exec,
    stadbEntry_handle_t entry,
    const struct ether_addr *staAddr,
    steerexecImplCmnSteeringType_e steerType,
    u_int8_t candidateCount,
    const lbd_bssInfo_t *candidateList);
static LBD_STATUS steerexecImplCmnReconcileSteerChannel(
    steerexecImplCmnSteeringState_t *state,
    steerexecImplCmnHandle_t exec,
    stadbEntry_handle_t entry,
    const struct ether_addr *staAddr,
    steerexecImplCmnSteeringType_e steerType,
    u_int8_t channelCount,
    const lbd_channelId_t *channelList,
    LBD_BOOL *willSteer);

static LBD_STATUS steerexecImplCmnRemoveAllBlacklists(
    steerexecImplCmnSteeringState_t *state,
    const struct ether_addr *staAddr);
static void steerexecImplCmnMarkAsNotBlacklisted(steerexecImplCmnSteeringState_t *state);
static void steerexecImplCmnMarkAsNotProhibited(steerexecImplCmnSteeringState_t *state,
                                                const struct ether_addr *staAddr);

static LBD_BOOL steerexecImplCmnIsBTMOnlySteer(steerexecImplCmnSteeringType_e steerType);
static void steerexecImplCmnChanChangeObserver(lbd_vapHandle_t vap,
                                            lbd_channelId_t channelId,
                                            void *cookie);

static LBD_STATUS steerexecImplCmnUpdateBTMCapability(
    steerexecImplCmnSteeringState_t *state,
    stadbEntry_handle_t entry,
    const struct ether_addr *staAddr,
    LBD_BOOL isBTMSupported);

static LBD_STATUS steerexecImplCmnSetupBTMState(steerexecImplCmnSteeringState_t *state,
                                             stadbEntry_handle_t entry);

static void steerexecImplCmnSetLastSteeringTime(
    steerexecImplCmnSteeringState_t *state);

static u_int8_t steerexecImplCmnLimitToUint8(u_int32_t val);

static LBD_BOOL steerexecImplCmnHandleSteerComplete(
    steerexecImplCmnSteeringState_t *state,
    stadbEntry_handle_t entry,
    const struct ether_addr *staAddr,
    const lbd_bssInfo_t *assocBSS);

static void steerexecImplCmnMoveToWaitAssocState(
    steerexecImplCmnSteeringState_t *state,
    u_int32_t expiryTime);
static LBD_STATUS steerexecImplCmnFetchEntryAndState(const struct ether_addr *addr,
                                                     stadbEntry_handle_t *entry,
                                                     steerexecImplCmnSteeringState_t **state);

static LBD_BOOL steerexecImplCmnIsWithinErrorTime(time_t expiryTime,
                                                  time_t timeNow);

static void steerexecImplCmnSetNonDecreasing(u_int32_t newValue,
                                             u_int32_t *outValue);
static LBD_BOOL steerexecImplCmnIsLegacySteer(steerexecImplCmnSteeringType_e steerType);

// ====================================================================
// Public API
// ====================================================================

steerexecImplCmnHandle_t steerexecImplCmnCreate(const steerexecImplCmnConfig_t *config,
                                          struct dbgModule *dbgModule) {
    steerexecImplCmnHandle_t exec =
        calloc(1, sizeof(struct steerexecImplCmnPriv_t));
    if (exec) {
        memcpy(&exec->config, config, sizeof(*config));

        exec->dbgModule = dbgModule;

        if (stadb_registerLowRSSIObserver(steerexecImplCmnLowRSSIObserver, exec) != LBD_OK ||
            stadb_registerRSSIObserver(steerexecImplCmnRSSIObserver, exec) != LBD_OK ||
            wlanif_registerChanChangeObserver(steerexecImplCmnChanChangeObserver, exec) != LBD_OK) {
            free(exec);
            return NULL;
        }

        evloopTimeoutCreate(&exec->prohibitTimer.timer,
                            "steerexecImplCmnProhibitTimeout",
                            steerexecImplCmnProhibitTimeoutHandler,
                            exec);

        evloopTimeoutCreate(&exec->legacy.steeringUnfriendly.timer,
                            "steerexecImplCmnUnfriendlyTimeout",
                            steerexecImplCmnUnfriendlyTimeoutHandler,
                            exec);

        evloopTimeoutCreate(&exec->legacy.blacklistTimer.timer,
                            "steerexecImplCmnClearBlacklistTimeout",
                            steerexecImplCmnBlacklistTimeoutHandler,
                            exec);

        evloopTimeoutCreate(&exec->btm.unfriendlyTimer.timer,
                            "steerexecImplCmnBTMUnfriendlyTimeout",
                            steerexecImplCmnBTMUnfriendlyTimeoutHandler,
                            exec);

        evloopTimeoutCreate(&exec->btm.activeUnfriendlyTimer.timer,
                            "steerexecImplCmnBTMActiveUnfriendlyTimeout",
                            steerexecImplCmnBTMActiveUnfriendlyTimeoutHandler,
                            exec);

        mdListenTableRegister(mdModuleID_WlanIF, wlanif_event_btm_response,
                              steerexecImplCmnHandleBTMResponseEvent);

        steerexecImplCreate(exec, dbgModule);
    }

    return exec;
}

LBD_STATUS steerexecImplCmnAbort(steerexecImplCmnHandle_t exec,
                                 stadbEntry_handle_t entry,
                                 steerexecImplCmnSteeringStatusType_e abortReason,
                                 LBD_BOOL *ignored) {
    if (!exec || !entry) {
        return LBD_NOK;
    }

    if (ignored) {
        *ignored = LBD_TRUE;
    }

    steerexecImplCmnSteeringState_t *state = stadbEntry_getSteeringState(entry);
    if (!state) {
        // There must not be any steering operation in progress, so silently
        // succeed.
        return LBD_OK;
    }

    const struct ether_addr *addr = stadbEntry_getAddr(entry);
    lbDbgAssertExit(exec->dbgModule, addr);

    if (state->steerType == steerexecImplCmnSteeringType_none) {
        // No Steering in progress.
        if (abortReason == steerexecImplCmnSteeringStatusType_channel_change) {
            // When there is channel change, clear all blacklist
            return steerexecImplCmnRemoveAllBlacklists(state, addr);
        } else {
            return LBD_NOK;
        }
    }

    return steerexecImplCmnAbortInProgress(exec, state, entry, addr,
                                           abortReason, LBD_TRUE /* isLocalAbort */,
                                           ignored);
}

LBD_STATUS steerexecImplCmnAbortAllowAssoc(steerexecImplCmnHandle_t exec,
                                           stadbEntry_handle_t entry,
                                           LBD_BOOL *ignored) {
    if (!exec || !entry) {
        return LBD_NOK;
    }

    if (ignored) {
        *ignored = LBD_TRUE;
    }

    steerexecImplCmnSteeringState_t *state = stadbEntry_getSteeringState(entry);
    if (!state) {
        // There must not be any steering operation in progress, so silently
        // succeed.
        return LBD_OK;
    }

    if (state->steerType != steerexecImplCmnSteeringType_preassociation) {
        // No preassociation steering in progress.
        return LBD_NOK;
    }

    if (ignored) {
        *ignored = LBD_FALSE;
    }

    // Do blacklist related abort
    return steerexecImplCmnAbortSteerImpl(exec, entry, state,
                                          steerexecImplCmnSteeringStatusType_abort_user,
                                          LBD_TRUE /* isLocalAbort */);
}


LBD_STATUS steerexecImplCmnAllowAssoc(
    steerexecImplCmnHandle_t exec,
    stadbEntry_handle_t entry,
    u_int8_t channelCount,
    const lbd_channelId_t *channelList,
    LBD_BOOL *ignored) {

    if (!exec || !entry) {
        return LBD_NOK;
    }

    if (channelCount > STEEREXEC_MAX_ALLOW_ASSOC || !channelCount || !channelList) {
        return LBD_NOK;
    }

    steerexecImplCmnSteeringState_t *state =
        steerexecImplCmnGetOrCreateSteeringState(exec, entry);
    if (!state) {
        return LBD_NOK;
    }

    const struct ether_addr *staAddr = stadbEntry_getAddr(entry);
    lbDbgAssertExit(exec->dbgModule, staAddr);

    stadbEntry_bssStatsHandle_t stats = stadbEntry_getServingBSS(entry, NULL);

    if (steerexecImplCmnDetermineSteeringType(state, exec, entry, staAddr,
                                              stats, LBD_TRUE /* eligibiltyOnly */,
                                              LBD_TRUE /* reportReasonNotEligible */,
                                              LBD_FALSE /* isBestEffort */) !=
        steerexecImplCmnSteeringType_preassociation) {
        return LBD_NOK;
    }

    // Update the blacklists / set of disabled VAPs based upon the new steer request
    LBD_BOOL willSteer;
    if (steerexecImplCmnReconcileSteerChannel(
        state, exec, entry, staAddr, steerexecImplCmnSteeringType_preassociation,
        channelCount, channelList, &willSteer) != LBD_OK) {
        return LBD_NOK;
    }

    // No error, but no action to take.
    if (!willSteer) {
        if (ignored) {
            *ignored = LBD_TRUE;
        }
        return LBD_OK;
    }

    state->steerType = steerexecImplCmnSteeringType_preassociation;
    if (ignored) {
        *ignored = LBD_FALSE;
    }

    steerexecImplCmnSetLastSteeringTime(state);

    // Update the transaction ID
    steerexecImplCmnUpdateTransactionID(exec, state);

    dbgf(exec->dbgModule, DBGINFO,
         "%s: Starting new steer for " lbMACAddFmt(":") " of type %s (transaction %d)",
         __func__, lbMACAddData(staAddr->ether_addr_octet),
         steerexecImplCmn_SteeringTypeString[state->steerType], state->transaction);

    if (diaglog_startEntry(mdModuleID_SteerExec,
                           steerexec_msgId_preAssocSteerStart,
                           diaglog_level_demo)) {
        diaglog_writeMAC(staAddr);
        diaglog_write8(state->transaction);
        // Log the number of channels.
        diaglog_write8(channelCount);
        size_t i;
        // Log the channels.
        for (i = 0; i < channelCount; i++) {
            diaglog_write8(channelList[i]);
        }
        diaglog_finishEntry();
    }

    return LBD_OK;
}

LBD_STATUS steerexecImplCmnSteer(steerexecImplCmnHandle_t exec,
                              stadbEntry_handle_t entry,
                              u_int8_t candidateCount,
                              const lbd_bssInfo_t *candidateList,
                              steerexec_reason_e reason,
                              LBD_BOOL *ignored) {
    if (!exec || !entry || !candidateList ||
        (candidateCount == 0) || (candidateCount > STEEREXEC_MAX_CANDIDATES)) {
        return LBD_NOK;
    }

    // Make sure the candidate list is valid
    if (!steerexecImplCandidateListValid(candidateCount, candidateList)) {
        return LBD_NOK;
    }

    // This function can only be used for locally associated STAs.
    // However, don't return here - this could be a call to change the target BSS.
    stadbEntry_bssStatsHandle_t stats = stadbEntry_getServingBSS(entry, NULL);

    // Get the BSS this STA is associated to
    const lbd_bssInfo_t *assocBSS = stadbEntry_resolveBSSInfo(stats);
    steerexecImplCmnSteeringState_t *state =
        steerexecImplCmnGetOrCreateSteeringState(exec, entry);
    if (!state) {
        return LBD_NOK;
    }

    // Common preparation
    // Any steer done for reason of interference avoidance will be best effort
    LBD_BOOL okToSteer;
    LBD_BOOL isBestEffort = (reason == steerexec_reason_interferenceAvoidance) &&
        exec->config.IASUseBestEffort;
    if (steerexecImplCmnPrepareForSteering(
        state, exec, entry, candidateCount, candidateList, ignored, stats, assocBSS,
        isBestEffort, &okToSteer) != LBD_OK) {
        return LBD_NOK;
    }

    if (!okToSteer) {
        // No errors occurred, but can't steer the STA now, return
        return LBD_OK;
    }

    // Acting on the steer request, it's not ignored at this point
    if (ignored) {
        *ignored = LBD_FALSE;
    }

    const struct ether_addr *staAddr = stadbEntry_getAddr(entry);
    lbDbgAssertExit(exec->dbgModule, staAddr);

    // Special preparation (depending on MBSA or BSA mode)
    LBD_BOOL preparationComplete;
    LBD_BOOL blacklistAutoClear =
        wlanif_resolveBandFromChannelNumber(candidateList[0].channelId) == wlanif_band_5g ?
        LBD_TRUE : LBD_FALSE;
    if (steerexecImplPrepareForSteering(entry, staAddr, candidateCount,
                                        candidateList, state->steerType,
                                        blacklistAutoClear,
                                        exec->config.legacy.blacklistTime,
                                        LBD_TRUE /* resetProhibitTime */,
                                        &preparationComplete,
                                        &state->msgTransaction) == LBD_NOK) {
        // Failed to prepare for steering
        // Enable any disabled BSSes
        steerexecImplCmnEnableAllDisabledCandidates(state,
                                                    candidateCount,
                                                    candidateList,
                                                    staAddr);
        state->steerType = steerexecImplCmnSteeringType_none;
        return LBD_NOK;
    }

    // Save steering parameters
    steerexecImplCmnSaveSteerParams(state, 0 /* numUnresolvedCandidates */,
                                    candidateCount, candidateList, reason,
                                    blacklistAutoClear, exec->config.legacy.blacklistTime,
                                    LBD_FALSE /* isSteerInProgress */);

    if (preparationComplete) {
        // All preparation is done, start the steer now
        return steerexecImplCmnStartSteer(state, exec, entry, staAddr, assocBSS);
    }

    // Preparation still pending, return OK, but we don't steer yet
    state->state = steerexecImplCmn_state_prepare;
    return LBD_OK;
}

LBD_STATUS steerexecImplCmnStartPreparedSteer(steerexecImplCmnHandle_t exec,
                                              stadbEntry_handle_t entry,
                                              const struct ether_addr *staAddr,
                                              LBD_BOOL *shouldIgnore) {
    if (!staAddr || !entry || !shouldIgnore) {
        return LBD_NOK;
    }

    *shouldIgnore = LBD_FALSE;

    steerexecImplCmnSteeringState_t *state = stadbEntry_getSteeringState(entry);
    if (!state) {
        return LBD_NOK;
    }

    if (state->state != steerexecImplCmn_state_prepare) {
        dbgf(exec->dbgModule, DBGERR,
             "%s: Unable to start prepared steer for STA " lbMACAddFmt(":")
             " in state %s, not state %s",
             __func__, lbMACAddData(staAddr->ether_addr_octet),
             state->state <= steerexecImplCmn_state_invalid ?
             steerexecImplCmn_stateString[state->state] :
             steerexecImplCmn_stateString[steerexecImplCmn_state_invalid],
             steerexecImplCmn_stateString[steerexecImplCmn_state_prepare]);

        // Don't want to cancel previous (valid) steer, so ignore this response
        // and don't cancel the existing steer.
        *shouldIgnore = LBD_TRUE;
        return LBD_NOK;
    }

    // This function can only be used for locally associated STAs.
    stadbEntry_bssStatsHandle_t stats = stadbEntry_getServingBSS(entry, NULL);
    if (!stats) {
        // STA is no longer associated to us - can't steer
        dbgf(exec->dbgModule, DBGERR,
             "%s: Unable to start prepared steer for disassociated STA " lbMACAddFmt(":"),
             __func__, lbMACAddData(staAddr->ether_addr_octet));

        return LBD_NOK;
    }

    // Get the BSS this STA is associated to
    const lbd_bssInfo_t *assocBSS = stadbEntry_resolveBSSInfo(stats);
    lbDbgAssertExit(exec->dbgModule, assocBSS);

    return steerexecImplCmnStartSteer(state, exec, entry, staAddr, assocBSS);
}

static LBD_BOOL steerexecImplCmnHandleSteerComplete(
    steerexecImplCmnSteeringState_t *state,
    stadbEntry_handle_t entry,
    const struct ether_addr *staAddr,
    const lbd_bssInfo_t *assocBSS) {

    // What to do on association is determined by whether or not the device supports
    // 802.11v BTM
    LBD_BOOL steeringComplete = LBD_FALSE;
    if (steerexecImplCmnIsBTMSteer(state->steerType)) {
        steeringComplete = steerexecImplCmnHandleAssocUpdateBTM(
            state->context, entry, state, assocBSS, staAddr);
    } else if (steerexecImplCmnIsLegacySteer(state->steerType)) {
        steeringComplete = steerexecImplCmnHandleAssocUpdateLegacy(
            state->context, entry, state, assocBSS, staAddr);
    } else {
        // No steer in progress, cancel T-Steering timer (in case it was started)
        evloopTimeoutUnregister(&state->legacy.tSteerTimer);
        // If there was an aborted BTM steer in progress, return to the idle state now
        if (state->btm && state->state == steerexecImplCmn_state_aborted) {
            state->state = steerexecImplCmn_state_idle;
            evloopTimeoutUnregister(&state->btm->timer);
        }
    }

    // Do blacklist related cleanup if needed
    if (steeringComplete) {
        steerexecImplCmnAssocBlacklistClear(state->context, entry, state, assocBSS);
    }

    return steeringComplete;
}

void steerexecImplCmnHandleAssocUpdate(steerexecImplCmnHandle_t exec,
                                       stadbEntry_handle_t entry,
                                       const lbd_bssInfo_t *lastAssocBSS) {
    if (!exec || !entry) {
        return;
    }

    const struct ether_addr *staAddr = stadbEntry_getAddr(entry);
    lbDbgAssertExit(exec->dbgModule, staAddr);

    // Check if the STA is actually associated
    stadbEntry_bssStatsHandle_t stats = stadbEntry_getServingBSS(entry, NULL);
    if (!stats) {
        // Not actually associated
        return;
    }

    const lbd_bssInfo_t *assocBSS = stadbEntry_resolveBSSInfo(stats);
    lbDbgAssertExit(exec->dbgModule, assocBSS);

    // Disassociate on the old interface if it was associated locally regardless of
    // whether it was steered or not, to remove stale association information from
    // driver in case the STA does not disassociate cleanly. But this is a potential
    // race condition when a STA disassociates from the new BSS and associates back
    // to the old one immediately after this update. It may need better handle if
    // proven to be a problem.
    if (lbIsBSSLocal(lastAssocBSS) && !lbAreBSSesSame(assocBSS, lastAssocBSS) &&
        wlanif_disassociateSTA(lastAssocBSS, staAddr, LBD_TRUE /* local */) != LBD_OK) {
        dbgf(exec->dbgModule, DBGDEBUG,
             "%s: " lbMACAddFmt(":") " no longer associated on original "
             "BSS " lbBSSInfoAddFmt(),
             __func__, lbMACAddData(staAddr->ether_addr_octet),
             lbBSSInfoAddData(lastAssocBSS));
    }

    // If there is no steering state this must be an association from a device
    // we haven't tried to steer before.
    steerexecImplCmnSteeringState_t *state = stadbEntry_getSteeringState(entry);
    if (!state) {
        steerexecImplHandleAssocUpdate(staAddr, LBD_FALSE /* steeringComplete */);
        return;
    }

    // We have a steering state and the STA is associated.  Check if the BTM
    // capabilities have changed.
    LBD_BOOL isBTMSupported = stadbEntry_isBTMSupported(entry);
    if (steerexecImplCmnUpdateBTMCapability(state, entry,
                                            staAddr, isBTMSupported) != LBD_OK) {
        // Error occurred - can't change BTM capabilities, return here
        steerexecImplHandleAssocUpdate(staAddr, LBD_FALSE /* steeringComplete */);
        return;
    }

    if (state->steerType == steerexecImplCmnSteeringType_preassociation) {
        steerexecImplCmnHandleAssocPreAssoc(state->context, entry, state, assocBSS);
        return;
    }

    LBD_BOOL steeringComplete = steerexecImplCmnHandleSteerComplete(
        state, entry, staAddr, assocBSS);

    steerexecImplHandleAssocUpdate(staAddr, steeringComplete);
}

LBD_BOOL steerexecImplCmnHandleRemoteSteerComplete(
    steerexecImplCmnHandle_t exec,
    stadbEntry_handle_t entry,
    const struct ether_addr *staAddr,
    const lbd_bssInfo_t *assocBSS) {
    steerexecImplCmnSteeringState_t *state =
        steerexecImplCmnGetOrCreateSteeringState(exec, entry);
    if (!state) {
        return LBD_FALSE;
    }

    return steerexecImplCmnHandleSteerComplete(
        state, entry, staAddr, assocBSS);
}

LBD_STATUS steerexecImplCmnRemoteAbort(const struct ether_addr *staAddr,
                                       steerexecImplCmnSteeringStatusType_e reason,
                                       u_int8_t msgTransaction) {

    stadbEntry_handle_t entry;
    steerexecImplCmnSteeringState_t *state;
    if (steerexecImplCmnFetchEntryAndState(staAddr, &entry, &state) == LBD_NOK) {
        return LBD_NOK;
    }

    if (state->steerType == steerexecImplCmnSteeringType_none) {
        dbgf(state->context->dbgModule, DBGERR,
             "%s: No steer in progress for STA " lbMACAddFmt(":")
             ", can not abort",
             __func__, lbMACAddData(staAddr->ether_addr_octet));
        return LBD_NOK;
    }

    if (state->msgTransaction != msgTransaction) {
        dbgf(state->context->dbgModule, DBGERR,
             "%s: Transaction of in progress steer for STA " lbMACAddFmt(":")
             " (%u) does not match requested transaction (%u), will not abort",
             __func__, lbMACAddData(staAddr->ether_addr_octet),
             state->msgTransaction, msgTransaction);
        return LBD_NOK;
    }

    switch (reason) {
        case steerexecImplCmnSteeringStatusType_abort_auth_reject:
            // If the reason for the abort is auth rejects - mark as steering unfriendly
            steerexecImplCmnStartSteeringUnfriendly(state->context, state,
                                                    staAddr);
            break;
        case steerexecImplCmnSteeringStatusType_btm_reject:
        case steerexecImplCmnSteeringStatusType_btm_response_timeout:
            if (reason == steerexecImplCmnSteeringStatusType_btm_response_timeout) {
                state->btm->countNoResponseFailure++;
            } else {
                state->btm->countRejectFailure++;
            }
            // If the reason for the abort is a BTM failure - mark as BTM unfriendly
            steerexecImplCmnUpdateBTMCompliance(entry, state, staAddr,
                                                LBD_FALSE /* success */);
            break;
        default:
            // Other failure types don't need special handling, since they don't
            // result in the STA being marked as unfriendly.
            break;
    }

    // The request is valid, abort the steer
    return steerexecImplCmnAbortInProgress(state->context, state, entry, staAddr,
                                           reason, LBD_FALSE /* isLocalAbort */,
                                           NULL /* ignored */);
}

steerexec_steerEligibility_e steerexecImplCmnDetermineSteeringEligibility(
    steerexecImplCmnHandle_t exec,
    stadbEntry_handle_t entry,
    LBD_BOOL reportReasonNotEligible) {
    if (!exec || !entry) {
        return steerexec_steerEligibility_none;
    }

    // Check if the STA is actually associated
    stadbEntry_bssStatsHandle_t stats = stadbEntry_getServingBSS(entry, NULL);
    if (!stats) {
        // Not actually associated
        return steerexec_steerEligibility_none;
    }

    steerexecImplCmnSteeringState_t *state = stadbEntry_getSteeringState(entry);
    if (!state) {
        // If there is no steering state, this STA hasn't been steered before,
        // therefore it can't be prohibited from steering.
        if (exec->config.btm.startInBTMActiveState &&
            stadbEntry_isBTMSupported(entry) &&
            stadbEntry_isRRMSupported(entry)) {
            // As long as the STA supports BTM and RRM, it can be steered while active.
            return steerexec_steerEligibility_active;
        } else {
            // It can only be steered while idle.
            return steerexec_steerEligibility_idle;
        }
    }

    const struct ether_addr *staAddr = stadbEntry_getAddr(entry);
    lbDbgAssertExit(exec->dbgModule, staAddr);

    steerexecImplCmnSteeringType_e steerType = steerexecImplCmnDetermineSteeringType(
        state, exec, entry, staAddr, stats,
        LBD_TRUE /* eligibilityOnly */,
        reportReasonNotEligible,
        LBD_FALSE /* isBestEffort */);

    if (steerexecImplCmnIsLegacySteer(steerType)) {
        // Legacy STAs can only be steered while idle
        return steerexec_steerEligibility_idle;
    } else if (!steerexecImplCmnIsBTMSteer(steerType)) {
        return steerexec_steerEligibility_none;
    } else {
        // For BTM STAs, determine if it can be steered while active or not.
        lbDbgAssertExit(exec->dbgModule, state->btm);

        if (state->btm->complianceState == steerexecImplCmn_btmComplianceState_active) {
            // Determine if the STA reports it supports RRM
            if (stadbEntry_isRRMSupported(entry)) {
                return steerexec_steerEligibility_active;
            } else {
                // Even though the STA could be steered while active according
                // to steerexec, it doesn't support RRM, so we can't get stats
                // on the non-serving channel.  Only attempt to steer while idle.
                return steerexec_steerEligibility_idle;
            }
        } else {
            return steerexec_steerEligibility_idle;
        }
    }
}

steerexecImplCmnSteeringAcceptType_e steerexecImplCmnSteerOK(
    void *execPtr,
    stadbEntry_handle_t entry,
    const struct ether_addr *staAddr,
    steerexecImplCmnSteeringType_e steerType,
    LBD_BOOL isSteerInProgress) {

    steerexecImplCmnHandle_t exec = (steerexecImplCmnHandle_t)execPtr;

    LBD_BOOL isBTMSupported = stadbEntry_isBTMSupported(entry);
    if (!isBTMSupported && steerexecImplCmnIsBTMSteer(steerType)) {
        // STA doesn't support BTM - note we don't reject the steer here
        // since it's possible the originator has more up-to-date information
        // about the STA capabilities than us.  Update our own information
        // to indicate the STA supports BTM.
        dbgf(exec->dbgModule, DBGINFO,
             "%s: Warning BTM steering requested for STA " lbMACAddFmt(":")
             " even though it is not known to support BTM, updating stadb state",
             __func__, lbMACAddData(staAddr->ether_addr_octet));

        LBD_BOOL changed;
        if (stadbEntry_updateIsBTMSupported(entry, LBD_TRUE /* isBTMSupported */,
                                            &changed) != LBD_OK) {
            dbgf(exec->dbgModule, DBGERR,
                 "%s: BTM steering requested for STA " lbMACAddFmt(":")
                 " and failed to update stadb state, can not steer",
                 __func__, lbMACAddData(staAddr->ether_addr_octet));
            return steerexecImplCmnSteeringAcceptType_rejectIneligible;
        }

        isBTMSupported = LBD_TRUE;
    }

    steerexecImplCmnSteeringState_t *state =
        steerexecImplCmnGetOrCreateSteeringState(exec, entry);
    if (!state) {
        // No steering state, and unable to create
        dbgf(exec->dbgModule, DBGERR,
             "%s: Unable to steer STA " lbMACAddFmt(":")
             " because can't create steering state",
             __func__, lbMACAddData(staAddr->ether_addr_octet));
        return steerexecImplCmnSteeringAcceptType_rejectUnable;
    }

    struct timespec ts;
    lbGetTimestamp(&ts);

    if (!isSteerInProgress && (state->steeringProhibited != steerexecImplCmnSteeringProhibitType_none &&
                               !steerexecImplCmnIsWithinErrorTime(state->legacy.prohibitExpiryTime,
                                                                  ts.tv_sec))) {

        dbgf(exec->dbgModule, DBGERR,
             "%s: Unable to steer STA " lbMACAddFmt(":")
             " because currently prohibited from steering",
             __func__, lbMACAddData(staAddr->ether_addr_octet));
        return steerexecImplCmnSteeringAcceptType_rejectProhibited;
    }

    //if STA steering flag is set to true, then cannot to be steered this STA.
    if (stadbEntry_isSteeringDisallowed(entry)){
        return steerexecImplCmnSteeringAcceptType_rejectProhibited;
    }
    if (steerexecImplCmnIsLegacySteer(steerType)) {
        // For legacy steering - just make sure not marked as unfriendly
        if (state->legacy.steeringUnfriendly &&
            !steerexecImplCmnIsWithinErrorTime(state->legacy.unfriendlyExpiryTime,
                                               ts.tv_sec)) {
            dbgf(exec->dbgModule, DBGERR,
                 "%s: Unable to steer STA " lbMACAddFmt(":")
                 " because marked legacy steering unfriendly",
                 __func__, lbMACAddData(staAddr->ether_addr_octet));
            return steerexecImplCmnSteeringAcceptType_rejectUnfriendly;
        } else {
            return steerexecImplCmnSteeringAcceptType_success;
        }
    }

    // BTM steer requested - update the BTM capabilities if needed
    if (steerexecImplCmnUpdateBTMCapability(state, entry, staAddr, isBTMSupported) == LBD_NOK) {
        // Not able to update the BTM steering state
        return steerexecImplCmnSteeringAcceptType_rejectUnable;
    }

    if (state->btm->btmUnfriendly &&
        !steerexecImplCmnIsWithinErrorTime(state->btm->unfriendlyExpiryTime, ts.tv_sec)) {
        dbgf(exec->dbgModule, DBGERR,
             "%s: Unable to steer STA " lbMACAddFmt(":")
             " because marked BTM steering unfriendly",
             __func__, lbMACAddData(staAddr->ether_addr_octet));
        return steerexecImplCmnSteeringAcceptType_rejectUnfriendly;
    }

    if (steerexecImplCmnIsActiveSteer(steerType)) {
        if (state->btm->complianceState == steerexecImplCmn_btmComplianceState_idle) {
            // STA doesn't support active steering, update state to reflect request
            // by originator (assuming they as the owner of the STA have more
            // up-to-date information than us).
            dbgf(exec->dbgModule, DBGERR,
                 "%s: Warning active steering requested for STA " lbMACAddFmt(":")
                 " because current compliance state is %s, updating state",
                 __func__, lbMACAddData(staAddr->ether_addr_octet),
                 steerexecImplCmn_btmComplianceString[state->btm->complianceState]);

            steerexecImplCmnUpdateBTMComplianceState(
                state->btm->btmUnfriendly, steerexecImplCmn_btmComplianceState_active,
                state, staAddr);
        } else if (state->btm->complianceState ==
                   steerexecImplCmn_btmComplianceState_activeUnfriendly) {
            dbgf(exec->dbgModule, DBGERR,
                 "%s: Unable to steer STA " lbMACAddFmt(":")
                 " because marked BTM active steering unfriendly",
                 __func__, lbMACAddData(staAddr->ether_addr_octet));
            return steerexecImplCmnSteeringAcceptType_rejectUnfriendly;
        }
    }

    // OK to steer
    return steerexecImplCmnSteeringAcceptType_success;
}

LBD_STATUS steerexecImplCmnPrepareForSteeringReq(
    stadbEntry_handle_t entry,
    const struct ether_addr *staAddr,
    steerexecImplCmnSteeringType_e steerType,
    u_int8_t numUnresolvedCandidates,
    u_int8_t candidateCount,
    const lbd_bssInfo_t *candidateList,
    LBD_BOOL blacklistAutoClear,
    u_int32_t blacklistMaxTime,
    u_int8_t msgTransaction,
    LBD_BOOL isSteerInProgress) {

    steerexecImplCmnSteeringState_t *state = stadbEntry_getSteeringState(entry);
    if (!state) {
        // Should not be here without a valid steering state
        return LBD_NOK;
    }

    // Update blacklists
    if (steerexecImplCmnReconcileSteerCandidate(
        state, state->context, entry, staAddr, steerType, candidateCount,
        candidateList) != LBD_OK) {
        return LBD_NOK;
    }

    // Save steering parameters
    state->steerType = steerType;
    state->msgTransaction = msgTransaction;
    steerexecImplCmnSaveSteerParams(state, numUnresolvedCandidates, candidateCount,
                                    candidateList,
                                    steerexec_reason_APrequest,
                                    blacklistAutoClear,
                                    blacklistMaxTime,
                                    isSteerInProgress);

    // Clear the initalAssoc - since this STA is not associated to us, will not attempt
    // to disassociate at steer completion
    if (state->btm) {
        memset(&state->btm->initialAssoc, 0, sizeof(lbd_bssInfo_t));
    }

    if (!isSteerInProgress) {
        dbgf(state->context->dbgModule, DBGINFO,
             "%s: Starting new steer of type %s (msgTransaction %d, transaction %d)",
             __func__, steerexecImplCmn_SteeringTypeString[state->steerType],
             state->msgTransaction, state->transaction);

        // Start the prohibit timer
        steerexecImplCmnStartSteeringProhibitLocal(
            state->context, state, staAddr,
            steerexecImplCmnIsBTMSteer(steerType) ? steerexecImplCmnSteeringProhibitType_short :
            steerexecImplCmnSteeringProhibitType_long, entry);

        // Waiting for association - we will wait the BTM response time + the association time
        // since we don't expect to get a BTM response to reset the timer
        steerexecImplCmnMoveToWaitAssocState(
            state, state->context->config.btm.associationTime +
            state->context->config.btm.responseTime);
    } else {
        dbgf(state->context->dbgModule, DBGINFO,
             "%s: Updated steer of type %s (msgTransaction %d, transaction %d)",
             __func__, steerexecImplCmn_SteeringTypeString[state->steerType],
             state->msgTransaction, state->transaction);
    }

    return LBD_OK;
}

LBD_BOOL steerexecImplCmnHandleAuthRej(
        struct steerexecImplCmnPriv_t *exec, stadbEntry_handle_t entry,
        void *statePtr, u_int8_t numAuthRejects) {

    steerexecImplCmnSteeringState_t *state = (steerexecImplCmnSteeringState_t *)statePtr;

    // We shouldn't receive an auth reject message under these circumstances.
    // Just print an error here, since it may indicate network state is out of sync.
    if (steerexecImplCmnIsBTMOnlySteer(state->steerType)) {
        dbgf(exec->dbgModule, DBGINFO,
             "%s: Received auth reject while STA is steered without blacklists",
             __func__);
        return LBD_FALSE;
    }

    const struct ether_addr *staAddr = stadbEntry_getAddr(entry);
    lbDbgAssertExit(exec->dbgModule, staAddr);

    // If this is a BTM compliant station, and not marked as steering prohibited,
    // mark it now.  If the STA attempts to associate on a
    // blacklisted band, we will delay our next attempt to steer in case it
    // has temporarily blacklisted us.
    if (stadbEntry_isBTMSupported(entry)) {
        if (state->steeringProhibited != steerexecImplCmnSteeringProhibitType_long) {
            steerexecImplCmnStartSteeringProhibitLocal(exec, state, staAddr,
                                                       steerexecImplCmnSteeringProhibitType_long, entry);
        }
    }

    if (numAuthRejects) {
        return steerexecImplCmnHandleAuthRejRemote(exec, entry, staAddr,
                                                   state, numAuthRejects);
    } else {
        return steerexecImplCmnHandleAuthRejLocal(exec, entry, staAddr, state);
    }
}

LBD_BOOL steerexecImplCmnShouldUpdateState(
    struct steerexecImplCmnPriv_t *exec, stadbEntry_handle_t entry,
    const struct ether_addr *staAddr, LBD_BOOL isBTMSupported,
    u_int32_t secsSinceSteered) {

    // Does the state already exist?
    steerexecImplCmnSteeringState_t *state = stadbEntry_getSteeringState(entry);
    if (!state) {
        // Update the BTM state if needed
        LBD_BOOL changed;
        if (stadbEntry_updateIsBTMSupported(entry, isBTMSupported,
                                            &changed) != LBD_OK) {
            dbgf(exec->dbgModule, DBGERR,
                 "%s: Unable to update BTM state for STA " lbMACAddFmt(":"),
                 __func__, lbMACAddData(&staAddr->ether_addr_octet));
            return LBD_FALSE;
        }

        // Create the steering state
        state = steerexecImplCmnGetOrCreateSteeringState(exec, entry);
        if (!state) {
            dbgf(exec->dbgModule, DBGERR,
                 "%s: Couldn't create steering state for STA " lbMACAddFmt(":")
                 ", will not update state",
                 __func__, lbMACAddData(&staAddr->ether_addr_octet));
            return LBD_FALSE;
        }

        // No steering state, so this must be the first state update,
        // and it is automatically valid
        return LBD_TRUE;
    }

    struct timespec ts;
    lbGetTimestamp(&ts);

    LBD_BOOL newerUpdate =
        (secsSinceSteered < (ts.tv_sec - state->legacy.lastSteeringTime));

    // Only downgrade the BTM state for a newer update.
    // However, we allow the actual state to be updated even if the
    // lastSteeringTime is older.  If we are fetching state as the result
    // of a PFS request failure, the rejecting node will by definition have
    // an older lastSteeringTime than the local node (since lastSteering time
    // is set when the steer starts, but is not updated on the remote node).
    // When updating the timers, we take the most pesimistic value, which
    // may not be the most recent one.
    if ((newerUpdate && !isBTMSupported) || isBTMSupported) {

        // Should update

        // Update BTM state if needed
        LBD_BOOL changed;
        if (stadbEntry_updateIsBTMSupported(entry, isBTMSupported,
                                            &changed) != LBD_OK) {
            dbgf(exec->dbgModule, DBGERR,
                 "%s: Unable to update BTM state for STA " lbMACAddFmt(":"),
                 __func__, lbMACAddData(&staAddr->ether_addr_octet));
            return LBD_FALSE;
        }

        if (isBTMSupported && changed) {
            // Now BTM is supported - need to update steerexec state too
            if (steerexecImplCmnUpdateBTMCapability(state, entry, staAddr,
                                                    isBTMSupported) == LBD_NOK) {
                // Not able to update the BTM steering state
                return LBD_FALSE;
            }
        }
    }

    return LBD_TRUE;
}

LBD_STATUS steerexecImplCmnClearPreparedSteer(
    stadbEntry_handle_t entry, const struct ether_addr *staAddr) {

    steerexecImplCmnSteeringState_t *state = stadbEntry_getSteeringState(entry);
    if (!state) {
        return LBD_NOK;
    }

    LBD_STATUS status = steerexecImplCmnRemoveAllBlacklists(state, staAddr);

    // Return to idle state
    steerexecImplCmnSteerEnd(state, staAddr,
                             steerexecImplCmnSteeringStatusType_prepare_fail,
                             LBD_TRUE /* isLocalAbort */, entry);

    return status;
}

u_int32_t steerexecImplCmnGetTimeSinceLastSteered(stadbEntry_handle_t entry) {
    if (!entry) {
        // Never been steered before, set to the max
        return UINT_MAX;
    }

    steerexecImplCmnSteeringState_t *state = stadbEntry_getSteeringState(entry);
    if (!state) {
        // Never been steered before, set to the max
        return UINT_MAX;
    }

    struct timespec ts;
    lbGetTimestamp(&ts);

    if (!state->legacy.lastSteeringTime) {
        // Never been steered before, set to the max
        return UINT_MAX;
    } else {
        return ts.tv_sec - state->legacy.lastSteeringTime;
    }
}

void steerexecImplCmnSetState(stadbEntry_handle_t entry,
                              const struct ether_addr *staAddr,
                              u_int32_t secsSinceSteered,
                              u_int32_t prohibitRemainingSecs,
                              u_int32_t consecFailures,
                              u_int32_t unfriendlyTimerRemainingSecs) {
    steerexecImplCmnSteeringState_t *state = stadbEntry_getSteeringState(entry);
    if (!state) {
        // Should not be here without a valid steering state
        return;
    }

    struct timespec ts;
    lbGetTimestamp(&ts);

    dbgf(state->context->dbgModule, DBGINFO,
         "%s: Updating common state for device " lbMACAddFmt(":")
         ": original state (new state): secsSinceSteered %lu (%d), "
         "prohibitRemainingSecs %lu (%d), consecFailures %d (%d), "
         "unfriendlyTimerRemainingSecs %lu (%d)",
         __func__, lbMACAddData(staAddr->ether_addr_octet),
         ts.tv_sec - state->legacy.lastSteeringTime, secsSinceSteered,
         state->legacy.prohibitExpiryTime > ts.tv_sec ?
         state->legacy.prohibitExpiryTime - ts.tv_sec : 0, prohibitRemainingSecs,
         state->legacy.countConsecutiveFailure, consecFailures,
         state->legacy.unfriendlyExpiryTime > ts.tv_sec ?
         state->legacy.unfriendlyExpiryTime - ts.tv_sec : 0,
         unfriendlyTimerRemainingSecs);

    // Update the state
    state->legacy.lastSteeringTime = ts.tv_sec - secsSinceSteered;
    steerexecImplCmnSetNonDecreasing(consecFailures,
                                     &state->legacy.countConsecutiveFailure);

    // Update the timers
    if (prohibitRemainingSecs) {
        // Update prohibit time if the time is increased
        if (state->legacy.prohibitExpiryTime < ts.tv_sec + prohibitRemainingSecs) {
            state->legacy.prohibitExpiryTime = ts.tv_sec + prohibitRemainingSecs;
            steerexecImplCmnStartSteeringProhibit(
                state->context, state, staAddr,
                steerexecImplCmnSteeringProhibitType_remote,
                prohibitRemainingSecs);
        }
    } else if (state->steeringProhibited != steerexecImplCmnSteeringProhibitType_none) {
        // Cancel the prohibit timer if within the error time
        if (steerexecImplCmnIsWithinErrorTime(state->legacy.prohibitExpiryTime,
                                              ts.tv_sec)) {
            steerexecImplCmnMarkAsNotProhibited(state, staAddr);
        }
    }

    steerexecImplCmnUpdateTimer(state->context->dbgModule,
                                &state->context->legacy.steeringUnfriendly,
                                ts.tv_sec, unfriendlyTimerRemainingSecs,
                                &state->legacy.unfriendlyExpiryTime);

    steerexecImplCmnUpdateSteeringUnfriendly(state->legacy.unfriendlyExpiryTime > 0,
                                             state, staAddr);

    stadb_setDirty();
}

void steerexecImplCmnSetBTMState(stadbEntry_handle_t entry,
                                 const struct ether_addr *staAddr,
                                 steerexecImplCmn_btmComplianceState_e btmCompliance,
                                 u_int32_t btmIdleConsecFail,
                                 u_int32_t btmActiveConsecFail,
                                 u_int32_t btmUnfriendlyRemainingSecs,
                                 u_int32_t btmActiveUnfriendlyRemainingSecs) {
    steerexecImplCmnSteeringState_t *state = stadbEntry_getSteeringState(entry);
    if (!state) {
        // Should not be here without a valid steering state
        return;
    }

    if (!state->btm) {
        // Should not be here without a valid BTM steering state
        return;
    }

    struct timespec ts;
    lbGetTimestamp(&ts);

    dbgf(state->context->dbgModule, DBGINFO,
         "%s: Updating BTM state for device " lbMACAddFmt(":")
         ": original state (new state): "
         "btmCompliance %d (%d), btmIdleConsecFail %d (%d), "
         "btmActiveConsecFail %d (%d), "
         "btmUnfriendlyRemainingSecs %lu (%d), "
         "btmActiveUnfriendlyRemainingSecs %lu (%d)",
         __func__, lbMACAddData(staAddr->ether_addr_octet),
         state->btm->complianceState, btmCompliance,
         state->btm->countConsecutiveFailure, btmIdleConsecFail,
         state->btm->countConsecutiveFailureActive, btmActiveConsecFail,
         state->btm->unfriendlyExpiryTime > ts.tv_sec ?
         state->btm->unfriendlyExpiryTime - ts.tv_sec : 0,
         btmUnfriendlyRemainingSecs,
         state->btm->activeUnfriendlyExpiryTime > ts.tv_sec ?
         state->btm->activeUnfriendlyExpiryTime - ts.tv_sec : 0,
         btmActiveUnfriendlyRemainingSecs);

    // Update the state
    steerexecImplCmnSetNonDecreasing(btmIdleConsecFail,
                                     &state->btm->countConsecutiveFailure);
    steerexecImplCmnSetNonDecreasing(btmActiveConsecFail,
                                     &state->btm->countConsecutiveFailureActive);

    // Update the timers
    steerexecImplCmnUpdateTimer(state->context->dbgModule,
                                &state->context->btm.activeUnfriendlyTimer,
                                ts.tv_sec, btmActiveUnfriendlyRemainingSecs,
                                &state->btm->activeUnfriendlyExpiryTime);

    steerexecImplCmnUpdateTimer(state->context->dbgModule,
                                &state->context->btm.unfriendlyTimer,
                                ts.tv_sec, btmUnfriendlyRemainingSecs,
                                &state->btm->unfriendlyExpiryTime);

    // Don't clear the active unfriendly state here, if the timer is still running.
    // However, we allow the remote node to change the state from idle to active.
    if (state->btm->activeUnfriendlyExpiryTime) {
        btmCompliance = steerexecImplCmn_btmComplianceState_activeUnfriendly;
    }
    steerexecImplCmnUpdateBTMComplianceState(state->btm->unfriendlyExpiryTime > 0, btmCompliance,
                                             state, staAddr);
}

void steerexecImplCmnGetState(stadbEntry_handle_t entry,
                              u_int32_t *secsSinceSteered,
                              u_int32_t *prohibitRemainingSecs,
                              u_int8_t *consecFailures,
                              u_int32_t *unfriendlyTimerRemainingSecs) {
    steerexecImplCmnSteeringState_t *state = stadbEntry_getSteeringState(entry);
    if (!state) {
        // Should not be here without a valid steering state
        return;
    }

    struct timespec ts;
    lbGetTimestamp(&ts);

    if (!state->legacy.lastSteeringTime) {
        // Never been steered before, set to the max
        *secsSinceSteered = UINT_MAX;
    } else {
        *secsSinceSteered = ts.tv_sec - state->legacy.lastSteeringTime;
    }
    if (!state->legacy.prohibitExpiryTime ||
        state->steeringProhibited == steerexecImplCmnSteeringProhibitType_none) {
        // Not prohibited
        *prohibitRemainingSecs = 0;
    } else {
        *prohibitRemainingSecs = (state->legacy.prohibitExpiryTime > ts.tv_sec ?
            state->legacy.prohibitExpiryTime - ts.tv_sec : 0);
    }

    *consecFailures = steerexecImplCmnLimitToUint8(state->legacy.countConsecutiveFailure);
    if (!state->legacy.unfriendlyExpiryTime) {
        // Never been unfriendly before
        *unfriendlyTimerRemainingSecs = 0;
    } else {
        *unfriendlyTimerRemainingSecs = state->legacy.unfriendlyExpiryTime > ts.tv_sec ?
            state->legacy.unfriendlyExpiryTime - ts.tv_sec : 0;
    }
}

void steerexecImplCmnGetBTMState(stadbEntry_handle_t entry,
                                 steerexecImplCmn_btmComplianceState_e *btmCompliance,
                                 u_int8_t *btmIdleConsecFail,
                                 u_int8_t *btmActiveConsecFail,
                                 u_int32_t *btmUnfriendlyRemainingSecs,
                                 u_int32_t *btmActiveUnfriendlyRemainingSecs) {
    steerexecImplCmnSteeringState_t *state = stadbEntry_getSteeringState(entry);
    if (!state) {
        // Should not be here without a valid steering state
        return;
    }

    if (!state->btm) {
        // Should not be here without a valid BTM steering state
        return;
    }

    struct timespec ts;
    lbGetTimestamp(&ts);

    *btmCompliance = state->btm->complianceState;
    *btmIdleConsecFail =
        steerexecImplCmnLimitToUint8(state->btm->countConsecutiveFailure);
    *btmActiveConsecFail =
        steerexecImplCmnLimitToUint8(state->btm->countConsecutiveFailureActive);
    *btmUnfriendlyRemainingSecs =
        state->btm->unfriendlyExpiryTime > ts.tv_sec ?
        state->btm->unfriendlyExpiryTime - ts.tv_sec : 0;
    *btmActiveUnfriendlyRemainingSecs =
        state->btm->activeUnfriendlyExpiryTime > ts.tv_sec ?
        state->btm->activeUnfriendlyExpiryTime - ts.tv_sec : 0;
}

LBD_BOOL steerexecImplCmnShouldAbortSteerForActive(steerexecImplCmnHandle_t exec,
                                          stadbEntry_handle_t entry) {
    if (!exec || !entry) {
        return LBD_FALSE;
    }

    steerexecImplCmnSteeringState_t *state = stadbEntry_getSteeringState(entry);
    if (!state) {
        // If there is no steering state, this STA hasn't been steered before,
        // therefore there is nothing to abort.
        return LBD_FALSE;
    }

    // If there is no steer in progresss, nothing to abort
    if (state->steerType == steerexecImplCmnSteeringType_none) {
        return LBD_FALSE;
    }

    if (!stadbEntry_isBTMSupported(entry)) {
        // STA does not report it supports BSS Transition Management,
        // therefore should abort any steer if active.
        return LBD_TRUE;
    } else {
        // For BTM STAs, determine if it can be steered while active or not.
        lbDbgAssertExit(exec->dbgModule, state->btm);

        if (state->btm->complianceState == steerexecImplCmn_btmComplianceState_active) {
            return LBD_FALSE;
        } else {
            return LBD_TRUE;
        }
    }
}

LBD_BOOL steerexecImplCmnIsSteerInProgress(stadbEntry_handle_t entry) {
    if (!entry) {
        return LBD_FALSE;
    }

    steerexecImplCmnSteeringState_t *state = stadbEntry_getSteeringState(entry);
    if (!state) {
        // If there is no steering state, this STA hasn't been steered before,
        // therefore can not be in progress.
        return LBD_FALSE;
    }

    if (state->state == steerexecImplCmn_state_idle) {
        // No steer in progress
        return LBD_FALSE;
    } else {
        // Steer in progress
        return LBD_TRUE;
    }
}

LBD_BOOL steerexecImplCmnIsStartingNewSteer(stadbEntry_handle_t entry) {
    if (!entry) {
        return LBD_TRUE;
    }

    steerexecImplCmnSteeringState_t *state = stadbEntry_getSteeringState(entry);
    if (!state) {
        // If there is no steering state, this STA hasn't been steered before,
        // therefore must be a new steer.
        return LBD_TRUE;
    }

    if (state->state == steerexecImplCmn_state_prepare) {
        // New steer
        return LBD_TRUE;
    } else {
        // Not a new steer
        return LBD_FALSE;
    }
}

LBD_STATUS steerexecImplCmnRegisterSteeringAllowedObserver(
        steerexecImplCmnHandle_t exec,
        steerexec_steeringAllowedObserverCB callback,
        void *cookie) {
    if (!exec || !callback) {
        return LBD_NOK;
    }

    struct steerexecImplCmnSteeringAllowedObserver *freeSlot = NULL;
    size_t i;
    for (i = 0; i < MAX_STEERING_ALLOWED_OBSERVERS; ++i) {
        struct steerexecImplCmnSteeringAllowedObserver *curSlot =
            &exec->steeringAllowedObservers[i];
        if (curSlot->isValid && curSlot->callback == callback &&
            curSlot->cookie == cookie) {
            dbgf(exec->dbgModule, DBGERR, "%s: Duplicate registration "
                                          "(func %p, cookie %p)",
                 __func__, callback, cookie);
           return LBD_NOK;
        }

        if (!freeSlot && !curSlot->isValid) {
            freeSlot = curSlot;
        }

    }

    if (freeSlot) {
        freeSlot->isValid = LBD_TRUE;
        freeSlot->callback = callback;
        freeSlot->cookie = cookie;
        return LBD_OK;
    }

    // No free entries found.
    return LBD_NOK;
}

LBD_STATUS steerexecImplCmnUnregisterSteeringAllowedObserver(
        steerexecImplCmnHandle_t exec,
        steerexec_steeringAllowedObserverCB callback,
        void *cookie) {
    if (!exec || !callback) {
        return LBD_NOK;
    }

    size_t i;
    for (i = 0; i < MAX_STEERING_ALLOWED_OBSERVERS; ++i) {
        struct steerexecImplCmnSteeringAllowedObserver *curSlot =
            &exec->steeringAllowedObservers[i];
        if (curSlot->isValid && curSlot->callback == callback &&
            curSlot->cookie == cookie) {
            curSlot->isValid = LBD_FALSE;
            curSlot->callback = NULL;
            curSlot->cookie = NULL;
            return LBD_OK;
        }
    }

    // No match found
    return LBD_NOK;
}

void steerexecImplCmnDestroy(steerexecImplCmnHandle_t exec) {
    if (exec) {
        stadb_unregisterLowRSSIObserver(steerexecImplCmnLowRSSIObserver, exec);
        stadb_unregisterRSSIObserver(steerexecImplCmnRSSIObserver, exec);
        wlanif_unregisterChanChangeObserver(steerexecImplCmnChanChangeObserver, exec);
        evloopTimeoutUnregister(&exec->prohibitTimer.timer);
        evloopTimeoutUnregister(&exec->legacy.steeringUnfriendly.timer);
        evloopTimeoutUnregister(&exec->legacy.blacklistTimer.timer);
        evloopTimeoutUnregister(&exec->btm.unfriendlyTimer.timer);
        evloopTimeoutUnregister(&exec->btm.activeUnfriendlyTimer.timer);
        free(exec);
    }
}

LBD_BOOL steerexecImplCmnIsBTMSteer(steerexecImplCmnSteeringType_e steerType) {
    if ((steerType == steerexecImplCmnSteeringType_btm) ||
        (steerType == steerexecImplCmnSteeringType_btm_and_blacklist) ||
        (steerType == steerexecImplCmnSteeringType_btm_active) ||
        (steerType == steerexecImplCmnSteeringType_btm_and_blacklist_active) ||
        (steerType == steerexecImplCmnSteeringType_btm_be) ||
        (steerType == steerexecImplCmnSteeringType_btm_be_active) ||
        (steerType == steerexecImplCmnSteeringType_btm_blacklist_be) ||
        (steerType == steerexecImplCmnSteeringType_btm_blacklist_be_active)) {
        return LBD_TRUE;
    }

    return LBD_FALSE;
}

LBD_BOOL steerexecImplCmnIsActiveSteer(steerexecImplCmnSteeringType_e steerType) {
    if ((steerType == steerexecImplCmnSteeringType_btm_active)||
        (steerType == steerexecImplCmnSteeringType_btm_and_blacklist_active) ||
        (steerType == steerexecImplCmnSteeringType_btm_be_active) ||
        (steerType == steerexecImplCmnSteeringType_btm_blacklist_be_active)) {
        return LBD_TRUE;
    }

    return LBD_FALSE;
}

LBD_BOOL steerexecImplCmnTimeDiffLessThanErrorTime(time_t timeDiff) {
    if (timeDiff <= steerexecImplCmn_timerErrorValue) {
        return LBD_TRUE;
    }
    return LBD_FALSE;
}

// ====================================================================
// Private helper functions
// ====================================================================

/**
 * @brief Check if an expiry time is 'close enough' to the
 *        current time
 *
 * @param [in] expiryTime  timer expiry time
 * @param [in] timeNow  current time
 *
 * @return LBD_TRUE if the timer is either already expired, or
 *         close enough to be considered expired, LBD_FALSE
 *         otherwise
 */
static LBD_BOOL steerexecImplCmnIsWithinErrorTime(time_t expiryTime,
                                                  time_t timeNow) {
    if (expiryTime <= timeNow ||
        steerexecImplCmnTimeDiffLessThanErrorTime(expiryTime - timeNow)) {
        // Expired, or close enough
        return LBD_TRUE;
    }

    return LBD_FALSE;
}

/**
 * @brief Set a variable to a new value, only if the new value
 *        is larger
 *
 * @param [in] newValue  new value to set
 * @param [inout] outValue  old value, updated to newValue if
 *                          newValue is greater than the
 *                          original value of outValue
 */
static void steerexecImplCmnSetNonDecreasing(u_int32_t newValue,
                                             u_int32_t *outValue) {
    if (newValue > *outValue) {
        *outValue = newValue;
    }

}

/**
 * @brief Return if the STA is being steered via BTM without
 *        blacklists
 *
 * @param [in] steerType  steering type to check
 *
 * @return LBD_TRUE if this is a BTM only (no blacklist) steer
 *         type, LBD_FALSE otherwise
 */
static LBD_BOOL steerexecImplCmnIsBTMOnlySteer(steerexecImplCmnSteeringType_e steerType) {
    if ((steerType == steerexecImplCmnSteeringType_btm) ||
        (steerType == steerexecImplCmnSteeringType_btm_active) ||
        (steerType == steerexecImplCmnSteeringType_btm_be) ||
        (steerType == steerexecImplCmnSteeringType_btm_be_active)) {
        return LBD_TRUE;
    }

    return LBD_FALSE;
}

/**
 * @brief Return if the STA is being steered with blacklists
 *
 * @param [in] steerType  steering type to check
 *
 * @return LBD_TRUE if this is a blacklist steer type, LBD_FALSE
 *         otherwise
 */
static LBD_BOOL steerexecImplCmnIsBlacklistSteer(steerexecImplCmnSteeringType_e steerType) {
    if ((steerType == steerexecImplCmnSteeringType_legacy) ||
        (steerType == steerexecImplCmnSteeringType_legacy_be) ||
        (steerType == steerexecImplCmnSteeringType_btm_and_blacklist) ||
        (steerType == steerexecImplCmnSteeringType_btm_and_blacklist_active) ||
        (steerType == steerexecImplCmnSteeringType_btm_blacklist_be) ||
        (steerType == steerexecImplCmnSteeringType_btm_blacklist_be_active)) {
        return LBD_TRUE;
    }

    return LBD_FALSE;
}

/**
 * @brief Return if the the steer is best effort
 *
 * @param [in] steerType  steering type to check
 *
 * @return LBD_TRUE if this is a best effort steer type,
 *         LBD_FALSE otherwise
 */
static LBD_BOOL steerexecImplCmnIsBestEffortSteer(steerexecImplCmnSteeringType_e steerType) {
    if ((steerType == steerexecImplCmnSteeringType_legacy_be) ||
        (steerType == steerexecImplCmnSteeringType_btm_be) ||
        (steerType == steerexecImplCmnSteeringType_btm_be_active) ||
        (steerType == steerexecImplCmnSteeringType_btm_blacklist_be) ||
        (steerType == steerexecImplCmnSteeringType_btm_blacklist_be_active)) {
        return LBD_TRUE;
    }

    return LBD_FALSE;
}

/**
 * @brief Return if the the steer is a legacy steer
 *
 * @param [in] steerType  steering type to check
 *
 * @return LBD_TRUE if this is a best effort steer type,
 *         LBD_FALSE otherwise
 */
static LBD_BOOL steerexecImplCmnIsLegacySteer(steerexecImplCmnSteeringType_e steerType) {
    if ((steerType == steerexecImplCmnSteeringType_legacy) ||
        (steerType == steerexecImplCmnSteeringType_legacy_be)) {
        return LBD_TRUE;
    }

    return LBD_FALSE;
}

/**
 * @brief Decrease the number of entries waiting on a timer
 *        expiry, clearing the timer if there are no entries
 *        remaining
 *
 * @param [inout] timer  to adjust entry count for
 */
static void steerexecImplCmnRemoveTimerEntry(steerexecImplCmnTimerStruct_t *timer) {
    timer->countEntries--;
    if (!timer->countEntries) {
        // Clear the timer
        evloopTimeoutUnregister(&timer->timer);
    }
}

/**
 * @brief Mark a STA entry as no longer blacklisted.  Will
 *        unregister the blacklist timer if no other STAs are
 *        still blacklisted.
 *
 * @param [in] state  steering state for the STA
 */
static void steerexecImplCmnMarkAsNotBlacklisted(steerexecImplCmnSteeringState_t *state) {
    if (state->blacklistType != steerexecImplCmnBlacklist_none) {
        state->blacklistType = steerexecImplCmnBlacklist_none;
        steerexecImplCmnRemoveTimerEntry(&state->context->legacy.blacklistTimer);
    }
}

/**
 * @brief Mark a STA entry as no longer prohibited from
 *        steering. Will unregister the prohibit timer if no
 *        other STAs are still prohibited.
 *
 * @pre Should only call for a STA that is currently prohibited
 *
 * @param [in] state  steering state for the STA
 */
static void steerexecImplCmnMarkAsNotProhibited(steerexecImplCmnSteeringState_t *state,
                                                const struct ether_addr *staAddr) {
    state->steeringProhibited = steerexecImplCmnSteeringProhibitType_none;
    steerexecImplCmnDiagLogSteeringProhibited(
        staAddr, state->steeringProhibited);
    steerexecImplCmnRemoveTimerEntry(&state->context->prohibitTimer);
    state->legacy.prohibitExpiryTime = 0;
}

/**
 * @brief Check if the STA is reporting a different BTM
 *        capability than previous association
 *
 * @param [in] state  steering state for the STA
 * @param [in] entry  stadb entry for the STA
 * @param [in] staAddr  MAC address of the STA
 *
 * @return LBD_OK if the state was updated successfully; LBD_NOK
 *         otherwise
 */
static LBD_STATUS steerexecImplCmnUpdateBTMCapability(
    steerexecImplCmnSteeringState_t *state,
    stadbEntry_handle_t entry,
    const struct ether_addr *staAddr,
    LBD_BOOL isBTMSupported) {
    if (!state->btm && isBTMSupported) {
        dbgf(state->context->dbgModule, DBGINFO,
             "%s: Device " lbMACAddFmt(":") " previously marked as not BTM "
             "capable, now supports BTM", __func__,
             lbMACAddData(staAddr->ether_addr_octet));

        if (steerexecImplCmnSetupBTMState(state, entry) != LBD_OK) {
            dbgf(state->context->dbgModule, DBGERR,
             "%s: Unable to upgrade device " lbMACAddFmt(":") " from non-BTM "
             "capable, to BTM capable, deleted steering entry", __func__,
             lbMACAddData(staAddr->ether_addr_octet));

            // Destroy the steering state
            steerexecImplCmnManageSteeringStateLifecycleCB(NULL, state);

            // Clear the stadb record
            stadbEntry_setSteeringState(entry, NULL, NULL);
            return LBD_NOK;
        }
    } else if (state->btm && !isBTMSupported) {
        // If device no longer reports it supports BTM just print
        // an informational mesage, no action to take
        dbgf(state->context->dbgModule, DBGINFO,
             "%s: Device " lbMACAddFmt(":") " previously marked as BTM "
             "capable, no longer supports BTM", __func__,
             lbMACAddData(staAddr->ether_addr_octet));
    }

    return LBD_OK;
}

/**
 * @brief Debug log the fact that a timer was created for a given stadbEntry.
 *
 * @param [in] exec  the handle to the overall steerexec instance
 * @param [in] timerDesc  the type of timer being created
 * @param [in] entry  the entry for which a timer is being created
 */
static void steerexecImplCmnLogTimerCreate(steerexecImplCmnHandle_t exec,
                                           const char *timerDesc,
                                           stadbEntry_handle_t entry) {
    const struct ether_addr *addr = stadbEntry_getAddr(entry);
    lbDbgAssertExit(exec->dbgModule, addr);

    dbgf(exec->dbgModule, DBGINFO,
         "%s: %s timer registered for " lbMACAddFmt(":") " using handle %p",
         __func__, timerDesc, lbMACAddData(addr->ether_addr_octet), entry);
}

/**
 * @brief Create the T_Steering timer for a specific STA.
 *
 * @param [in] state  steering state for the STA
 * @param [in] entry  stadb entry for the STA
 */
static void steerexecImplCmnCreateTSteerTimer(
        steerexecImplCmnSteeringState_t *state, stadbEntry_handle_t entry) {
    evloopTimeoutCreate(&state->legacy.tSteerTimer,
                        "steerexecImplCmnTSteeringTimeout",
                        steerexecImplCmnTSteeringTimeoutHandler,
                        entry);
}

/**
 * @brief Create the BTM timer for a specific STA.
 *
 * @param [in] state  steering state for the STA
 * @param [in] entry  stadb entry for the STA
 */
static void steerexecImplCmnCreateBTMTimer(
        steerexecImplCmnSteeringState_t *state, stadbEntry_handle_t entry) {
    evloopTimeoutCreate(&state->btm->timer,
                        "steerexecImplCmnBTMTimer",
                        steerexecImplCmnBTMTimeoutHandler,
                        entry);
}

/**
 * @brief Setup the BTM state in the steering state
 *
 * @param [in] state steering state for the STA
 * @param [in] entry stadb entry for the STA
 *
 * @return LBD_OK if the state was updated successfully; LBD_NOK
 *         otherwise
 */
static LBD_STATUS steerexecImplCmnSetupBTMState(steerexecImplCmnSteeringState_t *state,
                                                stadbEntry_handle_t entry) {
    state->btm = calloc(1, sizeof(steerexecImplCmnSteeringStateBTM_t));
    if (!state->btm) {
        return LBD_NOK;
    }

    state->state = steerexecImplCmn_state_idle;

    if (state->context->config.btm.startInBTMActiveState) {
        // Allow active steering from the beginning
        state->btm->complianceState = steerexecImplCmn_btmComplianceState_active;
    } else {
        // Initially only attempt to use BTM steering while idle
        state->btm->complianceState = steerexecImplCmn_btmComplianceState_idle;
    }

    evloopTimeoutCreate(&state->btm->timer,
                        "steerexecImplCmnBTMTimer",
                        steerexecImplCmnBTMTimeoutHandler,
                        entry);

    steerexecImplCmnLogTimerCreate(state->context, "BTM", entry);
    return LBD_OK;
}

/**
 * @brief Obtain the steering state entry for the STA, creating it if it does
 *        not exist.
 *
 * @param [in] exec  the executor instance to use
 * @param [in] entry  the handle to the STA for which to get the state
 *
 * @return the state entry, or NULL if one could not be created
 */
static steerexecImplCmnSteeringState_t *steerexecImplCmnGetOrCreateSteeringState(
        steerexecImplCmnHandle_t exec, stadbEntry_handle_t entry) {
    steerexecImplCmnSteeringState_t *state = stadbEntry_getSteeringState(entry);
    if (!state) {
        state = calloc(1, sizeof(steerexecImplCmnSteeringState_t));
        if (!state) {
            return NULL;
        }

        state->context = exec;
        steerexecImplCmnCreateTSteerTimer(state, entry);

        steerexecImplCmnLogTimerCreate(exec, "T_Steering", entry);

        LBD_BOOL isBTMSupported = stadbEntry_isBTMSupported(entry);
        if (isBTMSupported) {
            if (steerexecImplCmnSetupBTMState(state, entry) != LBD_OK) {
                steerexecImplCmnManageSteeringStateLifecycleCB(NULL, state);
                return NULL;
            }
        }

        stadbEntry_setSteeringState(entry, state,
                                    steerexecImplCmnManageSteeringStateLifecycleCB);
    }

    return state;
}

/**
 * @brief Lifecycle management function used to perform maintenance when the
 *        STA entry is being destroyed or reallocated.
 *
 * @param [in] handle  the entry being managed
 * @param [in] state  the steerexec state object registered
 */
static void steerexecImplCmnManageSteeringStateLifecycleCB(
        stadbEntry_handle_t handle, void *state) {
    steerexecImplCmnSteeringState_t *statePtr = (steerexecImplCmnSteeringState_t *)state;

    unsigned tSteerSecs, tSteerUsecs, btmSecs, btmUsecs;
    if (handle) {  // record the remaining time
        evloopTimeoutRemaining(&statePtr->legacy.tSteerTimer,
                               &tSteerSecs, &tSteerUsecs);
        if (statePtr->btm) {
            evloopTimeoutRemaining(&statePtr->btm->timer,
                                   &btmSecs, &btmUsecs);
        }
    }

    // Cancel any timers that may be running.
    evloopTimeoutUnregister(&statePtr->legacy.tSteerTimer);
    if (statePtr->btm) {
        evloopTimeoutUnregister(&statePtr->btm->timer);
    }

    if (!handle) {  // destroy
        if (statePtr->btm) {
            free(statePtr->btm);
        }
        free(state);
    } else {  // realloc
        steerexecImplCmnCreateTSteerTimer(state, handle);
        if (tSteerSecs || tSteerUsecs) {
            evloopTimeoutRegister(&statePtr->legacy.tSteerTimer,
                                  tSteerSecs, tSteerUsecs);
        }

        if (statePtr->btm) {
            steerexecImplCmnCreateBTMTimer(state, handle);
            if (btmSecs || btmUsecs) {
                evloopTimeoutRegister(&statePtr->btm->timer,
                                      btmSecs, btmUsecs);
            }
        }
    }
}

/**
 * @brief Determine the BTM steering type to use depending on if
 *        the STA is active, and whether blacklists are required
 *
 * @param [in] exec  the executor instance to use
 * @param [in] entry  the stadb entry to steer
 * @param [in] stats  BSS stats handle for the STA
 * @param [in] active LBD_TRUE if STA is active, LBD_FALSE
 *                    otherwise
 * @param [in] useBlacklist  LBD_TRUE if blacklists should be
 *                           used, LBD_FALSE otherwise
 * @param [in] isBestEffort  LBD_TRUE if best-effort steering as
 *                           requested by caller (eg. used for
 *                           interference avoidance steering)
 *
 * @return Steering type to use
 */
static steerexecImplCmnSteeringType_e steerexecImplCmnDetermineBTMSteeringType(
    steerexecImplCmnHandle_t exec,
    stadbEntry_handle_t entry,
    stadbEntry_bssStatsHandle_t stats,
    LBD_BOOL active,
    LBD_BOOL useBlacklist,
    LBD_BOOL isBestEffort) {

    LBD_BOOL useBestEffortRSSI = LBD_FALSE;

    // Even if we usually use a blacklist for BTM steering, if the RSSI
    // is sufficiently low, we can't be confident the transaction will
    // succeed due to poor channel conditions.  If we try and steer, it
    // is best effort (no blacklist, no marking as unfriendly on failure)
    lbd_rssi_t rssi = stadbEntry_getUplinkRSSI(entry, stats,
                                               NULL, NULL);

    if ((rssi == LBD_INVALID_RSSI) ||
        (rssi < exec->config.btm.minRSSIBestEffort)) {
        // Generally the RSSI should be both valid and recent here.  However, if
        // we can't get a valid RSSI, use best-effort steering.  Also use
        // best-effort steering if the RSSI indicates channel conditions are poor
        // (even if that RSSI is not recent).
        useBestEffortRSSI = LBD_TRUE;
    }

    if (active) {
        if (useBestEffortRSSI ||
            (!useBlacklist && isBestEffort)) {
            return steerexecImplCmnSteeringType_btm_be_active;
        }
        if (useBlacklist) {
            if (isBestEffort) {
                return steerexecImplCmnSteeringType_btm_blacklist_be_active;
            } else {
                return steerexecImplCmnSteeringType_btm_and_blacklist_active;
            }
        } else {
            return steerexecImplCmnSteeringType_btm_active;
        }
    } else {
        if (useBestEffortRSSI ||
            (!useBlacklist && isBestEffort)) {
            return steerexecImplCmnSteeringType_btm_be;
        }
        if (useBlacklist) {
            if (isBestEffort) {
                return steerexecImplCmnSteeringType_btm_blacklist_be;
            } else {
                return steerexecImplCmnSteeringType_btm_and_blacklist;
            }
        } else {
            return steerexecImplCmnSteeringType_btm;
        }
    }
}

/**
 * @brief Determine the legacy steering type to use
 *
 * @param [in] isBestEffort  LBD_TRUE if best-effort steering as
 *                           requested by caller (eg. used for
 *                           interference avoidance steering)
 *
 * @return Steering type to use
 */
static steerexecImplCmnSteeringType_e steerexecImplCmnDetermineLegacySteeringType(
    LBD_BOOL isBestEffort) {
    if (isBestEffort) {
        return steerexecImplCmnSteeringType_legacy_be;
    } else {
        return steerexecImplCmnSteeringType_legacy;
    }
}

/**
 * @brief Determine the type of steering to use for this STA
 *
 * @param [in] state steering state for the STA
 * @param [in] exec steering executor instance
 * @param [in] entry staDB entry for the STA
 * @param [in] staAddr MAC address of the STA
 * @param [in] stats  BSS stats handle for the STA
 * @param [in] eligibilityOnly LBD_TRUE if just checking whether
 *                             the STA is eligible to be steered
 *                             via BTM, LBD_FALSE if the type of
 *                             BTM steering also needs to be
 *                             determined
 * @param [in] reportReasonNotEligible  whether to report the
 *                                      reason why the STA is
 *                                      not eligible for
 *                                      steering
 * @param [in] isBestEffort  LBD_TRUE if best-effort steering as
 *                           requested by caller (eg. used for
 *                           interference avoidance steering)
 *
 * @return Steering type to use
 */
static steerexecImplCmnSteeringType_e steerexecImplCmnDetermineSteeringType(
    steerexecImplCmnSteeringState_t *state,
    steerexecImplCmnHandle_t exec,
    stadbEntry_handle_t entry,
    const struct ether_addr *staAddr,
    stadbEntry_bssStatsHandle_t stats,
    LBD_BOOL eligibilityOnly,
    LBD_BOOL reportReasonNotEligible,
    LBD_BOOL isBestEffort) {

    steerexecImplCmnSteeringType_e steerType;

    //if STA steering flag is set to true, then cannot to be steered this STA.
    if (stadbEntry_isSteeringDisallowed(entry)){
        return steerexecImplCmnSteeringType_none;
    }
    // Steering unfriendly devices cannot be steered until a timer expires
    // that lets us try steering them again.
    if (state->legacy.steeringUnfriendly) {
        if (reportReasonNotEligible) {
            dbgf(exec->dbgModule, DBGDEBUG,
                 "%s: Cannot steer " lbMACAddFmt(":") " due "
                 "to being marked as steering unfriendly", __func__,
                 lbMACAddData(staAddr->ether_addr_octet));
        }
        return steerexecImplCmnSteeringType_none;
    }

    // If the device was steered too recently, return.
    if (state->steeringProhibited != steerexecImplCmnSteeringProhibitType_none) {
        if (reportReasonNotEligible) {
            dbgf(exec->dbgModule, DBGDEBUG,
                 "%s: Cannot steer "  lbMACAddFmt(":") " due "
                 "to quiet period", __func__,
                 lbMACAddData(staAddr->ether_addr_octet));
        }
        return steerexecImplCmnSteeringType_none;
    }

    if (!stats) {
        steerType = steerexecImplCmnSteeringType_preassociation;
    } else if (!stadbEntry_isBTMSupported(entry)) {
        // STA does not report it supports BSS Transition Management,
        // only use legacy steering
        steerType = steerexecImplCmnDetermineLegacySteeringType(isBestEffort);
    } else {
        if (eligibilityOnly) {
            // Just checking steering eligibility, enough to say
            // it supports BTM
            return steerexecImplCmnSteeringType_btm;
        }

        // STA reports it does support BTM, but is it eligible to use it?
        if (state->btm->btmUnfriendly) {
            // Using legacy steering
            steerType = steerexecImplCmnDetermineLegacySteeringType(isBestEffort);
        } else if (state->btm->complianceState != steerexecImplCmn_btmComplianceState_active) {
            // Must be idle, can only be steered while idle
            steerType = steerexecImplCmnDetermineBTMSteeringType(
                exec, entry, stats, LBD_FALSE /* isActive */,
                exec->config.btm.alsoBlacklist, isBestEffort);
        } else {
            // This STA can be steered while active - check if it actually is active
            LBD_BOOL active = LBD_FALSE;
            if (stadbEntry_getActStatus(entry, &active, NULL) != LBD_OK) {
                dbgf(state->context->dbgModule, DBGERR,
                 "%s: BTM STA can be steered while active, but could not get activity status, "
                 "will assume is idle",
                 __func__);
            }

            steerType = steerexecImplCmnDetermineBTMSteeringType(
                exec, entry, stats, active,
                exec->config.btm.alsoBlacklist, isBestEffort);
        }
    }

    return steerType;
}

/**
 * @brief Get the length of time (in seconds) to prohibit
 *        steering
 *
 * @param [in] exec steering executor instance
 * @param [in] prohibit type of steering prohibition
 *
 * @return u_int32_t length of time (in seconds) to prohibit
 *        steering
 */
static u_int32_t steerexecImplCmnGetSteeringProhibitTime(
    steerexecImplCmnHandle_t exec,
    steerexecImplCmnSteeringProhibitType_e prohibit) {
    if (prohibit == steerexecImplCmnSteeringProhibitType_short) {
        return exec->config.btm.steeringProhibitShortTime;
    } else if (prohibit == steerexecImplCmnSteeringProhibitType_long) {
        return exec->config.legacy.steeringProhibitTime;
    } else if (prohibit == steerexecImplCmnSteeringProhibitType_none) {
        return 0;
    } else {
        // Remote prohibit time - return the shortProhibitTime,
        // since the only way we can be updating the prohibit timer when
        // it was set remotely is if we were doing a BTM no blacklist steer.
        return exec->config.btm.steeringProhibitShortTime;
    }
}

/**
 * @brief Start the time period during which steering is
 *        prohibited for this entry (starting from the current
 *        time).
 *
 * @param [in] exec  the executor instance to use
 * @param [in] state  the object that captures the steering state
 * @param [in] staAddr  the address of the STA that is having its prohibited
 *                      time started/updated
 * @param [in] prohibit type of steering prohibition
 * @param [in] entry  stadb entry
 */
static void steerexecImplCmnStartSteeringProhibitLocal(
    steerexecImplCmnHandle_t exec,
    steerexecImplCmnSteeringState_t *state,
    const struct ether_addr *staAddr,
    steerexecImplCmnSteeringProhibitType_e prohibit,
    stadbEntry_handle_t entry) {

    // Get the correct time to prohibit steering for.
    u_int32_t prohibitTime =
        steerexecImplCmnGetSteeringProhibitTime(exec, prohibit) + 1;

    u_int32_t lastSteeredTime = UINT_MAX;
    // Special case: if the prohibit time is 0, don't set a timer here
    // (STA is never prohibited from steering)
    if (prohibitTime == 1) {
        steerexecImplCmnSetLastSteeringTime(state);
        return;
    }

    lastSteeredTime = steerexecImplCmnGetTimeSinceLastSteered(entry);

    if (lastSteeredTime != UINT_MAX) {
        if (state->state == steerexecImplCmn_state_failed) {
            prohibitTime += state->context->config.btm.responseTime +
                            state->context->config.btm.associationTime -
                            lastSteeredTime;
        }
    }

    steerexecImplCmnSetLastSteeringTime(state);

    state->legacy.prohibitExpiryTime = state->legacy.lastSteeringTime + prohibitTime;

    steerexecImplCmnStartSteeringProhibit(exec, state, staAddr, prohibit, prohibitTime);
}

/**
 * @brief Start the time period during which steering is prohibited for this
 *        entry.
 *
 * @param [in] exec  the executor instance to use
 * @param [in] state  the object that captures the steering state
 * @param [in] staAddr  the address of the STA that is having its prohibited
 *                      time started/updated
 * @param [in] prohibit type of steering prohibition
 */
static void steerexecImplCmnStartSteeringProhibit(
    steerexecImplCmnHandle_t exec,
    steerexecImplCmnSteeringState_t *state,
    const struct ether_addr *staAddr,
    steerexecImplCmnSteeringProhibitType_e prohibit,
    u_int32_t prohibitTime) {

    LBD_BOOL generateLog = LBD_FALSE;
    if (state->steeringProhibited != prohibit ||
        prohibit == steerexecImplCmnSteeringProhibitType_remote) {
        // Log if the prohibit time is changed.
        generateLog = LBD_TRUE;
        if (state->steeringProhibited == steerexecImplCmnSteeringProhibitType_none) {
            // New entry being prohibited.
            exec->prohibitTimer.countEntries++;
        }
    }

    state->steeringProhibited = prohibit;

    // Determine if we need to set a new timer.  This will occur if this is
    // the first timer set, or if this new expiry is for an earlier time than the previous
    // earliest expiry.  This can occur if a short timer is started while
    // a long timer is the current next expiry.
    steerexecImplCmnStartTimer(exec->dbgModule, &exec->prohibitTimer,
                               state->legacy.prohibitExpiryTime, prohibitTime);

    if (generateLog) {
        steerexecImplCmnDiagLogSteeringProhibited(staAddr,
                                                  prohibit);
    }
    stadb_setDirty();
}

/**
 * @brief Calculate the exponential backoff time
 *        min(maxBackoff, (baseTime * 2 ^ exponent))
 *
 * @param [in] baseTime  base time for the calculation
 * @param [in] exponent  exponent for the calculation
 * @param [in] maxBackoff   maximum value for the backoff
 *
 * @return Exponential backoff time
 */
static u_int32_t steerexecImplCmnGetExpBackoffTime(u_int32_t baseTime,
                                                u_int32_t exponent,
                                                u_int32_t maxBackoff) {
    // We are limited to a 32-bit backoff time (around 68 years)
    if (exponent >= 31) {
        return maxBackoff;
    }
    // Handle rollover
    u_int32_t exponentialFactor = (1 << exponent);
    if (maxBackoff / baseTime <= exponentialFactor) {
        return maxBackoff;
    }
    return baseTime * exponentialFactor;
}

/**
 * @brief Start a timer (only actually started if the timer is
 *        not already running, or needs to expire sooner)
 *
 * @param [in] timer  timer to start
 * @param [in] expiryTime  expiry time requested
 * @param [in] incTime  expiry time requested (as an increment
 *                      from the current time)
 */
static void steerexecImplCmnStartTimer(struct dbgModule *dbgModule,
                                       steerexecImplCmnTimerStruct_t *timer,
                                       time_t expiryTime,
                                       time_t incTime) {
    if ((timer->countEntries == 1) || (timer->nextExpiry > expiryTime)) {
        timer->nextExpiry = expiryTime;

        dbgf(dbgModule, DBGDEBUG,
             "%s: Starting timer to expire at time %lu (in %lu seconds)",
             __func__, timer->nextExpiry, incTime);

        evloopTimeoutRegister(&timer->timer, incTime, 0);
    }
}

/**
 * @brief Start an exponential backoff for a STA.  Will start
 *        the timer running if this is the first STA using this
 *        timer, or the expiry time for this STA is less than
 *        the old timer expiry.
 *
 * @param [in] timer  timer structure to use
 * @param [in] baseTime  base time for the backoff
 * @param [in] exponent  exponent for the backoff
 * @param [in] maxBackoff   maximum value for the backoff
 */
static void steerexecImplCmnStartExpBackoff(struct dbgModule *dbgModule,
                                            steerexecImplCmnTimerStruct_t *timer,
                                            u_int32_t baseTime,
                                            time_t *expiryTime,
                                            u_int32_t exponent,
                                            u_int32_t maxBackoff) {
    if (!baseTime) {
        return;
    }

    timer->countEntries++;

    struct timespec ts;
    lbGetTimestamp(&ts);

    time_t incTime =
        steerexecImplCmnGetExpBackoffTime(baseTime, exponent, maxBackoff) + 1;
    *expiryTime = ts.tv_sec + incTime;
    steerexecImplCmnStartTimer(dbgModule, timer, *expiryTime, incTime);
}

/**
 * @brief Start the time period during which this entry is marked as
 *        steering unfriendly.
 *
 * @param [in] exec  the executor instance to use
 * @param [in] state  the object that captures the steering state
 * @param [in] staAddr address of the STA marked steering
 *                     unfriendly
 */
static void steerexecImplCmnStartSteeringUnfriendly(
        steerexecImplCmnHandle_t exec,
        steerexecImplCmnSteeringState_t *state,
        const struct ether_addr *staAddr) {
    lbDbgAssertExit(exec->dbgModule, !state->legacy.steeringUnfriendly);

    steerexecImplCmnStartExpBackoff(exec->dbgModule,
                                    &exec->legacy.steeringUnfriendly,
                                    exec->config.legacy.steeringUnfriendlyTime,
                                    &state->legacy.unfriendlyExpiryTime,
                                    state->legacy.countConsecutiveFailure,
                                    exec->config.legacy.maxSteeringUnfriendly);

    state->legacy.countConsecutiveFailure++;

    steerexecImplCmnUpdateSteeringUnfriendly(
        LBD_TRUE /* isUnfriendly */, state,  staAddr);
}

/**
 * @brief Update the timer based on the expiry time being
 *        manually set from another device in the network
 *
 * @param [in] timer  timer to update
 * @param [in] currentTime  time now
 * @param [in] remainingSecs  expiry time as an increment from
 *                            the current time
 * @param [inout] currentExpiryTime  current expiry time for the
 *                                   timer, updated with the
 *                                   expiryTime
 */
static void steerexecImplCmnUpdateTimer(
    struct dbgModule *dbgModule,
    steerexecImplCmnTimerStruct_t *timer,
    time_t currentTime,
    u_int32_t remainingSecs,
    time_t *currentExpiryTime) {

    if (remainingSecs) {
        if (!*currentExpiryTime) {
            // Start a new timer
            timer->countEntries++;
        }

        // Only start the timer if the expiry time is increased
        if (*currentExpiryTime < currentTime + remainingSecs) {
            steerexecImplCmnStartTimer(dbgModule, timer,
                                       currentTime + remainingSecs, remainingSecs);
            *currentExpiryTime = currentTime + remainingSecs;
        }
    } else if (*currentExpiryTime) {
        // Previously was a timer running, cancel it only if there is less than the error
        // time remaining
        if (steerexecImplCmnIsWithinErrorTime(*currentExpiryTime, currentTime)) {
            steerexecImplCmnRemoveTimerEntry(timer);
            *currentExpiryTime = 0;
        }
    }
}

/**
 * @brief Update the steering unfriendliness state, and log if
 *        changed
 *
 * @param [in] isUnfriendly  new unfriendliness state
 * @param [in] state  STA state
 * @param [in] staAddr  STA MAC address
 */
static void steerexecImplCmnUpdateSteeringUnfriendly(
    LBD_BOOL isUnfriendly,
    steerexecImplCmnSteeringState_t *state,
    const struct ether_addr *staAddr) {

    if (state->legacy.steeringUnfriendly == isUnfriendly) {
        // No change, return
        return;
    }

    state->legacy.steeringUnfriendly = isUnfriendly;

    steerexecImplCmnDiagLogSteeringUnfriendly(staAddr, isUnfriendly,
                                              state->legacy.countConsecutiveFailure);
    stadb_setDirty();
}

/**
 * @brief Update the BTM compliance / unfriendliness state, and
 *        log if changed
 *
 * @param [in] isUnfriendly  new unfriendliness state
 * @param [in] btmCompliance  new compliance state
 * @param [in] state  STA state
 * @param [in] staAddr  STA MAC address
 */
static void steerexecImplCmnUpdateBTMComplianceState(
    LBD_BOOL isUnfriendly, steerexecImplCmn_btmComplianceState_e btmCompliance,
    steerexecImplCmnSteeringState_t *state, const struct ether_addr *staAddr) {

    if ((state->btm->btmUnfriendly == isUnfriendly) &&
        (state->btm->complianceState == btmCompliance)) {
        // No change, return
        return;
    }

    state->btm->btmUnfriendly = isUnfriendly;
    state->btm->complianceState = btmCompliance;

    steerexecImplCmnDiagLogBTMCompliance(staAddr, state->btm->btmUnfriendly,
                                         state->btm->complianceState,
                                         state->btm->countConsecutiveFailure,
                                         state->btm->countConsecutiveFailureActive);
}

/**
 * @brief Start the time period during which this entry is
 *        marked as BTM steering unfriendly (can be either
 *        active steering unfriendly, or unfriendly for any kind
 *        of BTM steering).
 *
 * @param [in] exec  the executor instance to use
 * @param [in] state  the object that captures the steering state
 * @param [in] staAddr address of the STA marked BTM steering
 *                     unfriendly
 * @param [in] timer  timer to start
 * @param [in] exponent  exponent for backoff
 * @param [in] maxBackoff   maximum value for backoff
 * @param [out] expiryTime  filled in with the new expiry time
 */
static void steerexecImplCmnStartBTMUnfriendly(
        steerexecImplCmnHandle_t exec,
        steerexecImplCmnSteeringState_t *state,
        const struct ether_addr *staAddr,
        steerexecImplCmnTimerStruct_t *timer,
        u_int32_t exponent,
        u_int32_t maxBackoff,
        time_t *expiryTime) {
    // BTM unfriendly time of 0 means this station will always always
    // be treated as BTM friendly.
    if (!exec->config.btm.btmUnfriendlyTime) {
        return;
    }

    if (state->btm->complianceState == steerexecImplCmn_btmComplianceState_active) {
        // Was using active steering, mark as active unfriendly
        state->btm->complianceState =
            steerexecImplCmn_btmComplianceState_activeUnfriendly;
        state->btm->countConsecutiveFailureActive++;
        // Reset the count of consecutive failures (to use for idle steering)
        state->btm->countConsecutiveFailure = 0;
    } else {
        // Was using idle steering, mark as BTM unfriendly
        state->btm->btmUnfriendly = LBD_TRUE;
        state->btm->countConsecutiveFailure++;
    }

    steerexecImplCmnStartExpBackoff(exec->dbgModule,
                                    timer,
                                    exec->config.btm.btmUnfriendlyTime,
                                    expiryTime,
                                    exponent, maxBackoff);

    steerexecImplCmnDiagLogBTMCompliance(staAddr, state->btm->btmUnfriendly,
                                      state->btm->complianceState,
                                      state->btm->countConsecutiveFailure,
                                      state->btm->countConsecutiveFailureActive);
}

/**
 * @brief Update the BTM compliance state, based on the success
 *        or failure of the previous transaction.
 *
 * @param [in] entry  stadb entry
 * @param [in] state  steering state
 * @param [in] staAddr  MAC address of STA
 * @param [in] success  set to LBD_TRUE if the previous
 *                      transaction was a success, LBD_FALSE on
 *                      failure
 */
static void steerexecImplCmnUpdateBTMCompliance(
    stadbEntry_handle_t entry,
    steerexecImplCmnSteeringState_t *state,
    const struct ether_addr *staAddr,
    LBD_BOOL success) {

    if (success) {
        // Any successful BTM steer will reset the consecutive failure count.
        state->btm->countConsecutiveFailure = 0;

        if (state->btm->complianceState ==
            steerexecImplCmn_btmComplianceState_idle) {
            // Since the STA successfully obeyed the BTM request, allow it to
            // be steered while active
            state->btm->complianceState = steerexecImplCmn_btmComplianceState_active;
            steerexecImplCmnDiagLogBTMCompliance(staAddr, state->btm->btmUnfriendly,
                                              state->btm->complianceState,
                                              state->btm->countConsecutiveFailure,
                                              state->btm->countConsecutiveFailureActive);
        } else if (state->btm->complianceState ==
                   steerexecImplCmn_btmComplianceState_active) {
            if (steerexecImplCmnIsActiveSteer(state->steerType)) {
                // Only reset the consecutive failure while active count
                // if the STA was actually active at the time of the steer.
                state->btm->countConsecutiveFailureActive = 0;
            }
        }
    } else {
        if (steerexecImplCmnIsBestEffortSteer(state->steerType)) {
            // Failures are OK in best-effort state, return
            return;
        }

        // While in the active allowed state, will not move to the active unfriendly
        // state until there are either steerexecImplCmn_maxConsecutiveBTMFailuresAsActive
        // consecutive failures while active, or the STA fails to transition while
        // idle.
        if (state->btm->complianceState == steerexecImplCmn_btmComplianceState_active) {
            if ((state->btm->countConsecutiveFailure ==
                 state->context->config.btm.maxConsecutiveBTMFailuresAsActive - 1) ||
                (!steerexecImplCmnIsActiveSteer(state->steerType))) {
                steerexecImplCmnStartBTMUnfriendly(
                    state->context, state, staAddr,
                    &state->context->btm.activeUnfriendlyTimer,
                    state->btm->countConsecutiveFailureActive,
                    state->context->config.btm.maxBTMActiveUnfriendly,
                    &state->btm->activeUnfriendlyExpiryTime);
                return;
            }
        } else {
            steerexecImplCmnStartBTMUnfriendly(state->context, state, staAddr,
                                               &state->context->btm.unfriendlyTimer,
                                               state->btm->countConsecutiveFailure,
                                               state->context->config.btm.maxBTMUnfriendly,
                                               &state->btm->unfriendlyExpiryTime);
            return;
        }
        state->btm->countConsecutiveFailure++;
    }
}

/**
 * @brief Store the transaction ID with the per-STA steering
 *        information, and increment the global transaction ID,
 *        handling overflow if needed.
 *
 * @param [in] exec  the executor instance to use
 * @param [in] state  the object that captures the steering
 *                    state
 */
static void steerexecImplCmnUpdateTransactionID(steerexecImplCmnHandle_t exec,
                                             steerexecImplCmnSteeringState_t *state) {
    state->transaction = exec->transaction;
    exec->transaction++;
}

/**
 * @brief Generate a diagnostic log indicating that the steering unfriendly
 *        state for a given client changed.
 *
 * @param [in] staAddr  the MAC address of the STA whose state changed
 * @param [in] isUnfriendly  flag indicating whether the STA is currently
 *                           considered steering unfriendly
 * @param [in] consecutiveFailures  number of consecutive legacy
 *                                  steering failures
 */
static void steerexecImplCmnDiagLogSteeringUnfriendly(
        const struct ether_addr *staAddr, LBD_BOOL isUnfriendly,
        u_int32_t consecutiveFailures) {
    if (diaglog_startEntry(mdModuleID_SteerExec,
                           steerexec_msgId_steeringUnfriendly,
                           diaglog_level_info)) {
        diaglog_writeMAC(staAddr);
        diaglog_write8(isUnfriendly);
        diaglog_write32(consecutiveFailures);
        diaglog_finishEntry();
    }
}

/**
 * @brief Generate a diagnostic log indicating that the BTM
 *        compliance state for a given client changed.
 *
 * @param [in] staAddr  the MAC address of the STA whose state changed
 * @param [in] btmUnfriendly  flag indicating whether the STA is
 *                            currently considered BTM
 *                            unfriendly
 * @param [in] complianceState  current BTM compliance state
 * @param [in] consecutiveFailures  count of BTM failures since
 *                                  the last successful BTM
 *                                  transition
 * @param [in] consecutiveFailuresActive count of BTM failures
 *                                       in the active allowed
 *                                       state since the last
 *                                       successful BTM
 *                                       transition while active
 */
static void steerexecImplCmnDiagLogBTMCompliance(
        const struct ether_addr *staAddr,
        LBD_BOOL btmUnfriendly,
        steerexecImplCmn_btmComplianceState_e complianceState,
        u_int32_t consecutiveFailures,
        u_int32_t consecutiveFailuresActive) {
    if (diaglog_startEntry(mdModuleID_SteerExec,
                           steerexec_msgId_btmCompliance,
                           diaglog_level_info)) {
        diaglog_writeMAC(staAddr);
        diaglog_write8(btmUnfriendly);
        diaglog_write8(complianceState);
        diaglog_write32(consecutiveFailures);
        diaglog_write32(consecutiveFailuresActive);
        diaglog_finishEntry();
    }
}

/**
 * @brief Generate a diagnostic log indicating that a steer
 *        attempt has ended.
 *
 * @param [in] staAddr  the MAC address of the STA whose state changed
 * @param [in] transaction completed transaction ID
 * @param [in] steerType  type of steer that was underway
 * @param [in] status  status of steer that has ended
 */
static void steerexecImplCmnDiagLogSteerEnd(
        const struct ether_addr *staAddr,
        u_int8_t transaction,
        steerexecImplCmnSteeringType_e steerType,
        steerexecImplCmnSteeringStatusType_e status) {

    if (diaglog_startEntry(mdModuleID_SteerExec,
                           steerexec_msgId_steerEnd,
                           diaglog_level_info)) {

        diaglog_writeMAC(staAddr);
        diaglog_write8(transaction);
        diaglog_write8(steerType);
        diaglog_write8(status);
        diaglog_finishEntry();
    }
}

/**
 * @brief Generate a diagnostic log indicating that the steering prohibited
 *        state for a given client changed.
 *
 * @param [in] staAddr  the MAC address of the STA whose state changed
 * @param [in] prohibit type of steering prohibition
 */
static void steerexecImplCmnDiagLogSteeringProhibited(
        const struct ether_addr *staAddr,
        steerexecImplCmnSteeringProhibitType_e prohibit) {
    if (diaglog_startEntry(mdModuleID_SteerExec,
                           steerexec_msgId_steeringProhibited,
                           diaglog_level_info)) {
        diaglog_writeMAC(staAddr);
        diaglog_write8(prohibit);
        diaglog_finishEntry();
    }
}

/**
 * @brief Check if a steer was aborted
 *
 * @param [in] status  status code for the reason the steer
 *                     ended
 *
 * @return LBD_TRUE if the steer was aborted, LBD_FALSE if it
 *         was terminated for another reason
 */
static LBD_BOOL steerExecImplCmnIsSteerAborted(steerexecImplCmnSteeringStatusType_e status) {
    switch (status) {
        case steerexecImplCmnSteeringStatusType_abort_auth_reject:
        case steerexecImplCmnSteeringStatusType_abort_low_rssi:
        case steerexecImplCmnSteeringStatusType_abort_change_target:
        case steerexecImplCmnSteeringStatusType_abort_user:
        case steerexecImplCmnSteeringStatusType_channel_change:
            return LBD_TRUE;
        default:
            return LBD_FALSE;
    }
}

/**
 * @brief Cleanup after a steer attempt has ended
 *
 * @param [in] state steering state
 * @param [in] staAddr the MAC address of the STA whose steer
 *                     attempt has ended
 * @param [in] status status of the steer attempt
 * @param [in] isLocalAbort  set to LBD_TRUE if the steer has
 *                           ended because of an abort on the
 *                           local device, LBD_FALSE if it is
 *                           the result of a request from
 *                           another device in the network
 */
static void steerexecImplCmnSteerEnd(steerexecImplCmnSteeringState_t *state,
                                     const struct ether_addr *staAddr,
                                     steerexecImplCmnSteeringStatusType_e status,
                                     LBD_BOOL isLocalAbort,
                                     stadbEntry_handle_t entry) {
    // Log if enabled
    steerexecImplCmnDiagLogSteerEnd(staAddr, state->transaction,
                                    state->steerType, status);

    // Start the prohibit timer
    steerexecImplCmnStartSteeringProhibitLocal(state->context, state, staAddr,
                                               state->steeringProhibited, entry);

    // Need to tell other nodes in the network if the steer was unsuccessful
    // Note: Also don't send the abort if the STA just fails to associate.  Each
    // device will maintain this timer independently, so if each reported it,
    // there would be a flood of abort messages.  The abort should only be used
    // to communicate an issue that only one STA could be aware of.
    // Also don't send an abort message if this steer end is itself the result of
    // a network abort request.
    if (isLocalAbort && (status != steerexecImplCmnSteeringStatusType_success) &&
        (status != steerexecImplCmnSteeringStatusType_assoc_timeout)) {
        steerexecImplAbort(state->msgTransaction, staAddr, status);
    }

    // Unset steering flag for BTM steering
    if (steerexecImplCmnIsBTMSteer(state->steerType) &&
        lbIsBSSLocal(&state->btm->initialAssoc)) {
        wlanif_updateSteeringStatus(staAddr, &state->btm->initialAssoc,
                                    LBD_FALSE /* steeringInProgress */);
    }

    // No steer in progress
    state->steerType = steerexecImplCmnSteeringType_none;
    if (state->btm && steerExecImplCmnIsSteerAborted(status)) {
        // Special case: if the steer was aborted,
        // want to make sure that any error messages are suppressed
        // due to the potentially ongoing BTM transition.
        state->state = steerexecImplCmn_state_aborted;
    } else {
        state->state = steerexecImplCmn_state_idle;
    }

    // Reset count of unresolved candidates
    state->numUnresolvedCandidates = 0;
}

/**
 * @brief Common operations after a BTM steering failure
 *
 * @param [in] entry  stadb entry
 * @param [in] state  steering state
 * @param [in] staAddr  MAC address of STA
 * @param [in] status  status code for the failure
 */
static void steerexecImplCmnSteerEndBTMFailure(
    stadbEntry_handle_t entry,
    steerexecImplCmnSteeringState_t *state,
    const struct ether_addr *staAddr,
    steerexecImplCmnSteeringStatusType_e status) {
    switch (status) {
        case steerexecImplCmnSteeringStatusType_btm_response_timeout:
            dbgf(state->context->dbgModule, DBGINFO,
                 "%s: "lbMACAddFmt(":")" timeout waiting for BTM response (transaction %d)",
                 __func__, lbMACAddData(staAddr->ether_addr_octet), state->transaction);
            // Increment failure count
            state->btm->countNoResponseFailure++;
            break;
        case steerexecImplCmnSteeringStatusType_assoc_timeout:
            dbgf(state->context->dbgModule, DBGINFO,
                 "%s: "lbMACAddFmt(":")" timeout waiting for association after BTM response "
                 "(transaction %d)",
                 __func__, lbMACAddData(staAddr->ether_addr_octet), state->transaction);
            // Increment failure count
            state->btm->countAssociationFailure++;
            break;
        case steerexecImplCmnSteeringStatusType_btm_reject:
            // Report the failure in the calling function to avoid having to pass in
            // the reject code.
            // Increment failure count
            state->btm->countRejectFailure++;
            break;
        default:
            dbgf(state->context->dbgModule, DBGINFO,
                 "%s: "lbMACAddFmt(":")" invalid steering status %u",
                 __func__, lbMACAddData(staAddr->ether_addr_octet),
                 status);
    }

    steerexecImplCmnUpdateBTMCompliance(entry, state, staAddr,
                                     LBD_FALSE /* success */);

    // Clear the blacklist, if one exists
    steerexecImplCmnCleanupBlacklistBTM(state, entry, staAddr, status);
}

/**
 * @brief Mark the STA being blacklisted.
 *
 * Start the blacklist timer when the first STA is blacklisted.
 *
 * @param [in] exec  the executor instance to use
 * @param [in] state  the object that captures the steering state
 * @param [in] blacklistType  the type of blacklisting to
 *                            perform
 */
static void steerexecImplCmnMarkBlacklist(steerexecImplCmnHandle_t exec,
                                       steerexecImplCmnSteeringState_t *state,
                                       steerexecImplCmnBlacklistType_e blacklistType) {
    struct timespec ts;
    lbGetTimestamp(&ts);

    lbDbgAssertExit(exec->dbgModule, state->blacklistType == steerexecImplCmnBlacklist_none);

    exec->legacy.blacklistTimer.countEntries++;
    state->blacklistType = blacklistType;

    if (exec->config.legacy.blacklistTime > 0 &&
        exec->legacy.blacklistTimer.countEntries == 1) {
        exec->legacy.blacklistTimer.nextExpiry =
            ts.tv_sec + exec->config.legacy.blacklistTime + 1;

        // Initial timer expiry we let be for the max time. It'll get
        // rescheduled based on the earliest expiry time (if necessary).
        evloopTimeoutRegister(&exec->legacy.blacklistTimer.timer,
                              exec->config.legacy.blacklistTime + 1, 0);
    }
}

/**
 * @brief Examine a single entry to see if its steering prohibition period
 *        has elapsed.
 *
 * @param [in] entry  the entry to examine
 * @param [in] cookie  the executor handle
 */
static void steerexecImplCmnProhibitIterateCB(stadbEntry_handle_t entry,
                                             void *cookie) {
    if (!stadbEntry_isInNetwork(entry)) {
        return;
    }

    steerexecImplCmnHandle_t exec = (steerexecImplCmnHandle_t) cookie;
    steerexecImplCmnSteeringState_t *state = stadbEntry_getSteeringState(entry);
    if (state &&
        steerexecImplCmnIsInSteeringQuietPeriod(exec, entry, state)) {
        // Determine if the next expiry time is sooner than the one currently
        // set. If so, update the time so that it is used when the timer is
        // next scheduled.
        if (!exec->prohibitTimer.nextExpiry ||
            state->legacy.prohibitExpiryTime < exec->prohibitTimer.nextExpiry) {
            exec->prohibitTimer.nextExpiry = state->legacy.prohibitExpiryTime;
            dbgf(exec->dbgModule, DBGDEBUG,
                 "%s: Setting next prohibit expiry time to %lu",
                 __func__, state->legacy.prohibitExpiryTime);
        } else {
            dbgf(exec->dbgModule, DBGDEBUG,
                 "%s: Not adjusting next prohibit expiry time (%lu < %lu)",
                 __func__, exec->prohibitTimer.nextExpiry,
                 state->legacy.prohibitExpiryTime);
        }
    }
}

/**
 * @brief Check if an timer has expired for
 *        a STA. If it has, decrement the number of entries
 *        pending expiry and return LBD_TRUE.  If not, check if
 *        this timer is the next to expire and update the next
 *        expiry if so, and return LBD_FALSE.
 *
 * @param [in] exec steering executor
 * @param [in] entry STA entry to check for expiry
 * @param [in] timer timer to check for expiry
 * @param [in] expiryTime  time this entry will expire
 *
 * @return LBD_TRUE if this timer has expired, LBD_FALSE
 *         otherwise
 */
static LBD_BOOL steerexecImplCmnTimerExpiryCheck(
    steerexecImplCmnHandle_t exec,
    steerexecImplCmnTimerStruct_t *timer,
    time_t expiryTime) {

    struct timespec ts;
    lbGetTimestamp(&ts);

    if (ts.tv_sec >= expiryTime) {
        timer->countEntries--;

        return LBD_TRUE;
    } else {
        if (!timer->nextExpiry || (expiryTime < timer->nextExpiry)) {
            timer->nextExpiry = expiryTime;
        }

        return LBD_FALSE;
    }
}

/**
 * @brief Examine a single entry to see if its steering unfriendly period
 *        has elapsed.
 *
 * @param [in] entry  the entry to examine
 * @param [in] cookie  the executor handle
 */
static void steerexecImplCmnUnfriendlyIterateCB(stadbEntry_handle_t entry,
                                             void *cookie) {
    if (!stadbEntry_isInNetwork(entry)) {
        return;
    }

    steerexecImplCmnHandle_t exec = (steerexecImplCmnHandle_t) cookie;
    steerexecImplCmnSteeringState_t *state = stadbEntry_getSteeringState(entry);
    if (state && state->legacy.steeringUnfriendly) {
        if (steerexecImplCmnTimerExpiryCheck(exec,
                                             &exec->legacy.steeringUnfriendly,
                                             state->legacy.unfriendlyExpiryTime)) {
            const struct ether_addr *addr = stadbEntry_getAddr(entry);
            lbDbgAssertExit(exec->dbgModule, addr);

            dbgf(exec->dbgModule, DBGINFO,
                 "%s: Cleared steering unfriendly flag for " lbMACAddFmt(":"),
                 __func__, lbMACAddData(addr->ether_addr_octet));

            state->legacy.unfriendlyExpiryTime = 0;

            steerexecImplCmnUpdateSteeringUnfriendly(
                LBD_FALSE /* isUnfriendly */, state,  addr);

            steerexecImplCmnNotifySteeringAllowedObservers(exec, entry);
            stadb_setDirty();
        }
    }
}

/**
 * @brief Common function to start iterating through stadb
 *        entries, checking for timer expiry.
 *
 * @param [in] exec  steering executor
 * @param [in] timer  timer to check for expiry
 * @param [in] callback  callback function for iteration
 * @param [in] baseTime  basetime for timer expiry
 */
static void steerexecImplCmnTimerStartIterate(steerexecImplCmnHandle_t exec,
                                           steerexecImplCmnTimerStruct_t *timer,
                                           stadb_iterFunc_t callback,
                                           u_int32_t baseTime) {
    struct timespec ts;
    lbGetTimestamp(&ts);

    timer->nextExpiry = 0;

    if (stadb_iterate(callback, exec) != LBD_OK) {
        dbgf(exec->dbgModule, DBGERR,
             "%s: Failed to iterate over station database", __func__);

        // For now we are falling through to reschedule the timer.
    }

    if (timer->countEntries != 0) {
        if (!timer->nextExpiry) {
            dbgf(exec->dbgModule, DBGERR,
                 "%s: There is at least 1 outstanding STA, but no nextExpiry", __func__);
            timer->nextExpiry = ts.tv_sec + baseTime + 1;
        }
        evloopTimeoutRegister(&timer->timer,
                              timer->nextExpiry - ts.tv_sec, 0);
    }
}

/**
 * @brief Handle the periodic timer that signals we should check how many
 *        entries are still waiting for steering prohibition to complete.
 *
 * @param [in] cookie  the executor handle
 */
static void steerexecImplCmnProhibitTimeoutHandler(void *cookie) {
    steerexecImplCmnHandle_t exec = (steerexecImplCmnHandle_t) cookie;

    steerexecImplCmnTimerStartIterate(exec, &exec->prohibitTimer,
                                      steerexecImplCmnProhibitIterateCB,
                                      exec->config.legacy.steeringProhibitTime);
}

/**
 * @brief Handle the periodic timer that signals we should check how many
 *        entries are still waiting to have their steering unfriendly
 *        flag cleared.
 *
 * @param [in] cookie  the executor handle
 */
static void steerexecImplCmnUnfriendlyTimeoutHandler(void *cookie) {
    steerexecImplCmnHandle_t exec = (steerexecImplCmnHandle_t) cookie;

    steerexecImplCmnTimerStartIterate(exec, &exec->legacy.steeringUnfriendly,
                                   steerexecImplCmnUnfriendlyIterateCB,
                                   exec->config.legacy.steeringUnfriendlyTime);
}

/**
 * @brief Examine a single entry to see if its BTM unfriendly
 *        period has elapsed.
 *
 * @param [in] entry  the entry to examine
 * @param [in] cookie  the executor handle
 */
static void steerexecImplCmnBTMUnfriendlyIterateCB(stadbEntry_handle_t entry,
                                                void *cookie) {
    if (!stadbEntry_isInNetwork(entry)) {
        return;
    }

    steerexecImplCmnHandle_t exec = (steerexecImplCmnHandle_t) cookie;
    steerexecImplCmnSteeringState_t *state = stadbEntry_getSteeringState(entry);
    if (state && state->btm &&
        ((state->btm->btmUnfriendly))) {
        if (steerexecImplCmnTimerExpiryCheck(exec,
                                             &exec->btm.unfriendlyTimer,
                                             state->btm->unfriendlyExpiryTime)) {

            const struct ether_addr *addr = stadbEntry_getAddr(entry);
            lbDbgAssertExit(exec->dbgModule, addr);

            dbgf(exec->dbgModule, DBGINFO,
                 "%s: Cleared BTM unfriendly flag for " lbMACAddFmt(":"),
                 __func__, lbMACAddData(addr->ether_addr_octet));

            state->btm->btmUnfriendly = LBD_FALSE;
            state->btm->unfriendlyExpiryTime = 0;

            steerexecImplCmnDiagLogBTMCompliance(
                addr, state->btm->btmUnfriendly, state->btm->complianceState,
                state->btm->countConsecutiveFailure,
                state->btm->countConsecutiveFailureActive);
            stadb_setDirty();

        }
    }
}

/**
 * @brief Examine a single entry to see if its BTM active
 *        unfriendly period has elapsed.
 *
 * @param [in] entry  the entry to examine
 * @param [in] cookie  the executor handle
 */
static void steerexecImplCmnBTMActiveUnfriendlyIterateCB(stadbEntry_handle_t entry,
                                                      void *cookie) {
    if (!stadbEntry_isInNetwork(entry)) {
        return;
    }

    steerexecImplCmnHandle_t exec = (steerexecImplCmnHandle_t) cookie;
    steerexecImplCmnSteeringState_t *state = stadbEntry_getSteeringState(entry);
    if (state && state->btm &&
        (state->btm->complianceState == steerexecImplCmn_btmComplianceState_activeUnfriendly)) {
        if (steerexecImplCmnTimerExpiryCheck(exec,
                                             &exec->btm.activeUnfriendlyTimer,
                                             state->btm->activeUnfriendlyExpiryTime)) {

            const struct ether_addr *addr = stadbEntry_getAddr(entry);
            lbDbgAssertExit(exec->dbgModule, addr);

            dbgf(exec->dbgModule, DBGINFO,
                 "%s: Cleared BTM active unfriendly flag for " lbMACAddFmt(":"),
                 __func__, lbMACAddData(addr->ether_addr_octet));

            // Move to the next state
            state->btm->complianceState = steerexecImplCmn_btmComplianceState_idle;
            state->btm->activeUnfriendlyExpiryTime = 0;

            steerexecImplCmnDiagLogBTMCompliance(
                addr, state->btm->btmUnfriendly,
                state->btm->complianceState,
                state->btm->countConsecutiveFailure,
                state->btm->countConsecutiveFailureActive);

        }
    }
}

/**
 * @brief Handle the periodic timer that signals we should check how many
 *        entries are still waiting to have their BTM unfriendly
 *        flag cleared.
 *
 * @param [in] cookie  the executor handle
 */
static void steerexecImplCmnBTMUnfriendlyTimeoutHandler(void *cookie) {
    steerexecImplCmnHandle_t exec = (steerexecImplCmnHandle_t) cookie;

    steerexecImplCmnTimerStartIterate(exec, &exec->btm.unfriendlyTimer,
                                   steerexecImplCmnBTMUnfriendlyIterateCB,
                                   exec->config.btm.btmUnfriendlyTime);
}

/**
 * @brief Handle the periodic timer that signals we should check how many
 *        entries are still waiting to have their BTM unfriendly
 *        flag cleared.
 *
 * @param [in] cookie  the executor handle
 */
static void steerexecImplCmnBTMActiveUnfriendlyTimeoutHandler(void *cookie) {
    steerexecImplCmnHandle_t exec = (steerexecImplCmnHandle_t) cookie;

    steerexecImplCmnTimerStartIterate(exec, &exec->btm.activeUnfriendlyTimer,
                                   steerexecImplCmnBTMActiveUnfriendlyIterateCB,
                                   exec->config.btm.btmUnfriendlyTime);
}

/**
 * @brief Handle timing out a set of blacklisted channels.  Will
 *        enable all channels that aren't overloaded, and update
 *        the disabledChannelCount and disabledChannelList.
 *
 * @param [in] exec  steering executor
 * @param [in] state  steering state
 * @param [in] staAddr  MAC address of the STA to manipulate
 *                      blacklist for
 *
 * @return LBD_OK if there were no errors; otherwise LBD_NOK
 */
static LBD_STATUS steerexecImplCmnTimeoutBlacklistChannel(
    steerexecImplCmnHandle_t exec,
    steerexecImplCmnSteeringState_t *state,
    const struct ether_addr *staAddr) {
    // Check none of the channels are overloaded
    size_t channelsToChange = state->legacy.disabledChannelCount;
    int i;
    for (i = channelsToChange - 1; i >= 0 ; i--) {
        LBD_BOOL isOverloaded;
        if (bandmon_isChannelOverloaded(state->legacy.disabledChannelList[i],
                                        &isOverloaded) != LBD_OK) {
            dbgf(exec->dbgModule, DBGERR,
                 "%s: Could not determine if channel %d is overloaded, "
                 "will remove entire blacklist for " lbMACAddFmt(":"),
                 __func__, state->legacy.disabledChannelList[i],
                 lbMACAddData(staAddr->ether_addr_octet));

            return LBD_NOK;
        }

        if (isOverloaded) {
            dbgf(exec->dbgModule, DBGDEBUG,
                 "%s: Will not remove blacklist for " lbMACAddFmt(":")
                 " on channel %d because it is overloaded",
                 __func__, lbMACAddData(staAddr->ether_addr_octet),
                 state->legacy.disabledChannelList[i]);
            continue;
        }

        if (wlanif_setChannelStateForSTA(1,
                                         &state->legacy.disabledChannelList[i],
                                         staAddr,
                                         LBD_TRUE /* enable */) != LBD_OK) {
            dbgf(state->context->dbgModule, DBGERR,
                 "%s: Failed to re-enable disabled channel %d, "
                 "will remove entire blacklist for " lbMACAddFmt(":"),
                 __func__, state->legacy.disabledChannelList[i],
                 lbMACAddData(staAddr->ether_addr_octet));
            return LBD_NOK;
        }

        dbgf(state->context->dbgModule, DBGDEBUG,
             "%s: Enable disabled channel %d for " lbMACAddFmt(":"),
             __func__, state->legacy.disabledChannelList[i],
             lbMACAddData(staAddr->ether_addr_octet));

        // Successfully disabled channel
        state->legacy.disabledChannelCount--;
        if (i != state->legacy.disabledChannelCount) {
            // Not the last element in the list, move other elements along
            memmove(&state->legacy.disabledChannelList[i],
                    &state->legacy.disabledChannelList[i+1],
                    (state->legacy.disabledChannelCount - i) *
                    sizeof(state->legacy.disabledChannelList[0]));
        }
    }

    return LBD_OK;
}

/**
 * @brief Handle timing out a set of blacklisted candidates.
 *
 *        Will enable all candidate that are not on overloaded
 *        channels, and update the candidateList and
 *        candidateCount.  Note that since candidateList and
 *        candidateCount reference the candidate BSSes that the
 *        STA is allowed to associate on, the number of
 *        candidates may increase in this function call.
 *        candidateCount will be reset to 0 and the blacklist
 *        removed if all blacklisted candidates can be enabled.
 *
 * @param [in] exec  steering executor
 * @param [in] state  steering state
 * @param [in] staAddr  MAC address of the STA to manipulate
 *                      blacklist for
 * @param [in] blacklistCount  count of candidates currently
 *                             blacklisted
 * @param [in] blacklist  list of candidates currently
 *                        blacklisted
 *
 * @return LBD_OK if there were no errors; otherwise LBD_NOK
 */
LBD_STATUS steerexecImplCmnTimeoutBlacklistCandidate(
    steerexecImplCmnHandle_t exec,
    steerexecImplCmnSteeringState_t *state,
    const struct ether_addr *staAddr,
    u_int8_t blacklistCount,
    const lbd_bssInfo_t *blacklist) {
    size_t i;
    LBD_BOOL candidateStillBlacklisted = LBD_FALSE;
    for (i = 0; i < blacklistCount; i++) {
        LBD_BOOL isOverloaded;
        if (bandmon_isChannelOverloaded(blacklist[i].channelId,
                                        &isOverloaded) != LBD_OK) {
            dbgf(exec->dbgModule, DBGERR,
                 "%s: Could not determine if channel %d is overloaded, "
                 "will remove entire blacklist for " lbMACAddFmt(":"),
                 __func__, state->legacy.disabledChannelList[i],
                 lbMACAddData(staAddr->ether_addr_octet));

            return LBD_NOK;
        }

        if (isOverloaded) {
            dbgf(exec->dbgModule, DBGDEBUG,
                 "%s: Will not remove blacklist on BSS " lbBSSInfoAddFmt()
                 " for " lbMACAddFmt(":") " because it is on an overloaded channel",
                 __func__, lbBSSInfoAddData(&blacklist[i]),
                 lbMACAddData(staAddr->ether_addr_octet));
            candidateStillBlacklisted = LBD_TRUE;
            continue;
        }

        // Channel is not overloaded, remove from blacklist
        if (wlanif_setCandidateStateForSTA(1,
                                           &blacklist[i],
                                           staAddr,
                                           LBD_TRUE /* enable */) != LBD_OK) {
            dbgf(state->context->dbgModule, DBGERR,
                 "%s: Failed to remove blacklist on BSS " lbBSSInfoAddFmt()
                 " for " lbMACAddFmt(":") " will remove entire blacklist",
                 __func__, lbBSSInfoAddData(&blacklist[i]),
                 lbMACAddData(staAddr->ether_addr_octet));
            return LBD_NOK;
        }

        dbgf(state->context->dbgModule, DBGDEBUG,
             "%s: Removed blacklist on BSS " lbBSSInfoAddFmt() " for "
             lbMACAddFmt(":"),
             __func__, lbBSSInfoAddData(&blacklist[i]),
             lbMACAddData(staAddr->ether_addr_octet));

        // Successfully removed the blacklist
        // Add this BSS to the list that the STA can associate on
        // if there is still room.  If there isn't room, it means that all
        // candidates must have been enabled
        if (state->candidateCount == STEEREXEC_MAX_CANDIDATES) {
            // All channels enabled, mark as not blacklisted
            steerexecImplCmnMarkAsNotBlacklisted(state);
            state->candidateCount = 0;
            return LBD_OK;
        } else {
            lbCopyBSSInfo(&blacklist[i],
                          &state->candidateList[state->candidateCount]);
            state->candidateCount++;
        }
    }

    if (!candidateStillBlacklisted) {
        // No candidates still blacklisted
        steerexecImplCmnMarkAsNotBlacklisted(state);
        state->candidateCount = 0;
    }

    return LBD_OK;
}

/**
 * @brief Handle timing out either a candidate or channel based
 *        blacklist.  Will take appropriate action depending on
 *        the type of blacklist present.
 *
 * @param [in] exec  steering executor
 * @param [in] state  steering state
 * @param [in] staAddr  MAC address of the STA to manipulate
 *                      blacklist for
 *
 * @return LBD_OK if there were no errors; otherwise LBD_NOK
 */
static LBD_STATUS steerexecImplCmnTimeoutBlacklist(
    steerexecImplCmnHandle_t exec,
    steerexecImplCmnSteeringState_t *state,
    const struct ether_addr *addr) {
    if (state->blacklistType == steerexecImplCmnBlacklist_channel) {
        if (steerexecImplCmnTimeoutBlacklistChannel(exec, state, addr) != LBD_OK) {
            return LBD_NOK;
        }

        if (!state->legacy.disabledChannelCount) {
            // All channels enabled, mark as not blacklisted
            steerexecImplCmnMarkAsNotBlacklisted(state);
        }

        return LBD_OK;
    } else {
        // Candidate blacklist
        lbd_bssInfo_t candidateList[STEEREXEC_MAX_CANDIDATES];
        u_int8_t candidateCount;
        // Get the set of candidates not currently blacklisted
        if (state->candidateCount > (sizeof(state->candidateList)/sizeof(state->candidateList[0]))){
            return LBD_NOK;
        }
        candidateCount = wlanif_getNonCandidateStateForSTA(
            state->candidateCount,
            &state->candidateList[0],
            STEEREXEC_MAX_CANDIDATES,
            &candidateList[0]);
        if (!candidateCount) {
            dbgf(exec->dbgModule, DBGERR,
                 "%s: Could not find any non-candidate VAPs, "
                 "will remove entire blacklist for " lbMACAddFmt(":"),
                 __func__, lbMACAddData(addr->ether_addr_octet));

            return LBD_NOK;
        }

        if (candidateCount + state->candidateCount > WLANIF_MAX_RADIOS) {
            dbgf(exec->dbgModule, DBGERR,
                 "%s: Total number of allowed candidates (%d) and "
                 "blacklisted candidates (%d) exceeds number of radios (%d), "
                 "will remove entire blacklist for " lbMACAddFmt(":"),
                 __func__, state->candidateCount, candidateCount,
                 WLANIF_MAX_RADIOS, lbMACAddData(addr->ether_addr_octet));

            return LBD_NOK;
        }

        return steerexecImplCmnTimeoutBlacklistCandidate(exec, state, addr, candidateCount,
                                                      &candidateList[0]);
    }
}

/**
 * @brief Examine a single entry to see if its blacklist period
 *        has elapsed.
 *
 * @param [in] entry  the entry to examine
 * @param [in] cookie  the executor handle
 */
void steerexecImplCmnBlacklistIterateCB(stadbEntry_handle_t entry,
                                     void *cookie) {

    steerexecImplCmnHandle_t exec = (steerexecImplCmnHandle_t) cookie;
    steerexecImplCmnSteeringState_t *state = stadbEntry_getSteeringState(entry);
    if (state && state->blacklistType != steerexecImplCmnBlacklist_none) {
        struct timespec ts;
        lbGetTimestamp(&ts);

        if (ts.tv_sec - state->legacy.lastSteeringTime >
            exec->config.legacy.blacklistTime) {
            const struct ether_addr *addr = stadbEntry_getAddr(entry);
            lbDbgAssertExit(exec->dbgModule, addr);

            // Store for logging purposes.
            steerexecImplCmnBlacklistType_e blacklistType = state->blacklistType;
            LBD_STATUS status = steerexecImplCmnTimeoutBlacklist(exec, state, addr);
            if (status != LBD_OK) {
                // Selective blacklist didn't work, try disabling the
                // whole blacklist
                status = steerexecImplCmnRemoveAllBlacklists(state, addr);
            }

            if ((LBD_OK == status) &&
                (state->blacklistType == steerexecImplCmnBlacklist_none)) {
                dbgf(exec->dbgModule, DBGINFO,
                     "%s: Cleared blacklist of type %s for "lbMACAddFmt(":")" due to aging",
                     __func__, steerexecImplCmn_SteeringBlacklistTypeString[blacklistType],
                     lbMACAddData(addr->ether_addr_octet));
            }

            // If enable error, timer will be rescheduled and it will be retried
            // when timer expires next time.
        } else {
            time_t expiryTime = state->legacy.lastSteeringTime +
                exec->config.legacy.blacklistTime + 1;
            if (expiryTime < exec->legacy.blacklistTimer.nextExpiry) {
                exec->legacy.blacklistTimer.nextExpiry = expiryTime;
            }
        }
    }
}

/**
 * @brief Handle the periodic timer that signals we should check how many
 *        entries are still waiting to be removed from blacklist
 *
 * @param [in] cookie  the executor handle
 */
static void steerexecImplCmnBlacklistTimeoutHandler(void *cookie) {
    steerexecImplCmnHandle_t exec = (steerexecImplCmnHandle_t) cookie;

    struct timespec ts;
    lbGetTimestamp(&ts);

    // This is the worst case. The iteration will adjust this based on the
    // actual devices that are still under prohibition.
    exec->legacy.blacklistTimer.nextExpiry =
        ts.tv_sec + exec->config.legacy.blacklistTime + 1;

    if (stadb_iterate(steerexecImplCmnBlacklistIterateCB, exec) != LBD_OK) {
        dbgf(exec->dbgModule, DBGERR,
             "%s: Failed to iterate over station database", __func__);

        // For now we are falling through to reschedule the timer.
    }

    if (exec->legacy.blacklistTimer.countEntries != 0) {
        evloopTimeoutRegister(&exec->legacy.blacklistTimer.timer,
                              exec->legacy.blacklistTimer.nextExpiry - ts.tv_sec, 0);
    }
}

/**
 * @brief Notify all registered oberservers that the provided entry can
 *        now be steered.
 *
 * @param [in] entry  the entry that was updated
 */
static void steerexecImplCmnNotifySteeringAllowedObservers(
        steerexecImplCmnHandle_t exec, stadbEntry_handle_t entry) {
    size_t i;
    for (i = 0; i < MAX_STEERING_ALLOWED_OBSERVERS; ++i) {
        struct steerexecImplCmnSteeringAllowedObserver *curSlot =
            &exec->steeringAllowedObservers[i];
        if (curSlot->isValid) {
            curSlot->callback(entry, curSlot->cookie);
        }
    }
}

/**
 * @brief Determine if the state indicates the entry is eligible for steering
 *        or not.
 *
 * @param [in] exec  the executor instance to use
 * @param [in] entry  the entry of the STA being examined
 * @param [in] state  the object to check for steering or not
 *
 * @return LBD_TRUE if the entry is still not allowed to be steered (due to its
 *         last steering being too recently); LBD_FALSE if it is eligible to be
 *         steered
 */
static LBD_BOOL steerexecImplCmnIsInSteeringQuietPeriod(
        steerexecImplCmnHandle_t exec,
        stadbEntry_handle_t entry,
        steerexecImplCmnSteeringState_t *state) {
    if (state->steeringProhibited != steerexecImplCmnSteeringProhibitType_none) {
        // Check if enough time has elapsed and if so, clear the flag.
        struct timespec ts;
        const struct ether_addr *addr = stadbEntry_getAddr(entry);
        lbDbgAssertExit(exec->dbgModule, addr);

        lbGetTimestamp(&ts);

        if (ts.tv_sec >= state->legacy.prohibitExpiryTime) {
            dbgf(exec->dbgModule, DBGINFO,
                 "%s: " lbMACAddFmt(":") " became eligible for steering",
                 __func__, lbMACAddData(addr->ether_addr_octet));

            state->steeringProhibited = steerexecImplCmnSteeringProhibitType_none;
            exec->prohibitTimer.countEntries--;
            state->legacy.prohibitExpiryTime = 0;

            if (!state->legacy.steeringUnfriendly) {
                steerexecImplCmnNotifySteeringAllowedObservers(exec, entry);
            }

            steerexecImplCmnDiagLogSteeringProhibited(
                    addr, steerexecImplCmnSteeringProhibitType_none);
            stadb_setDirty();
        } else {
            dbgf(exec->dbgModule, DBGDEBUG,
                 "%s: " lbMACAddFmt(":") " will become eligible for steering"
                 " at time %lu (in %lu seconds)",
                 __func__, lbMACAddData(addr->ether_addr_octet),
                 state->legacy.prohibitExpiryTime,
                 state->legacy.prohibitExpiryTime - ts.tv_sec);
        }
    }

    return (state->steeringProhibited != steerexecImplCmnSteeringProhibitType_none);
}

/**
 * @brief Enable all channels that have been disabled as part of
 *        pre-association steering.  If attempting to enable the
 *        specific set of channels fails, it will attempt to
 *        enable all channels (to avoid the case where the
 *        channel may have changed while the steer is in
 *        progress).
 *
 * @param [in] state steering state for STA
 * @param [in] staAddr MAC address of STA to enable
 *
 * @return LBD_STATUS LBD_OK if the channels could be enabled,
 *                    LBD_NOK otherwise
 */
static LBD_STATUS steerexecImplCmnEnableAllDisabledChannels(
    steerexecImplCmnSteeringState_t *state,
    const struct ether_addr *staAddr) {
    if (wlanif_setChannelStateForSTA(state->legacy.disabledChannelCount,
                                     &state->legacy.disabledChannelList[0],
                                     staAddr,
                                     LBD_TRUE /* enable */) != LBD_OK) {
        dbgf(state->context->dbgModule, DBGERR,
             "%s: Failed to re-enable disabled channel list for " lbMACAddFmt(":")
             ", will attempt to enable all channels",
             __func__, lbMACAddData(staAddr->ether_addr_octet));

        // This could be caused by a channel we had disabled having changed.
        // Try and enable on all channels.
        lbd_channelId_t newChannelList[WLANIF_MAX_RADIOS];
        u_int8_t newChannelCount = wlanif_getChannelList(&newChannelList[0],
                                                         NULL, // chwidthList
                                                         WLANIF_MAX_RADIOS);
        if (wlanif_setChannelStateForSTA(newChannelCount,
                                         &newChannelList[0],
                                         staAddr,
                                         LBD_TRUE /* enable */) != LBD_OK) {
            dbgf(state->context->dbgModule, DBGERR,
                 "%s: Failed to enable entire radio channel list for " lbMACAddFmt(":"),
                 __func__, lbMACAddData(staAddr->ether_addr_octet));

            // Some sort of more serious error, but there's nothing we can do
            return LBD_NOK;
        }
    }

    // All channels should now be enabled
    state->legacy.disabledChannelCount = 0;

    return LBD_OK;
}


/**
 * @brief Enable all candidates that have been disabled as part
 *        of post-association steering.
 *
 * @param [in] state steering state for STA
 * @param [in] staAddr MAC address of STA to enable
 *
 * @return LBD_STATUS LBD_OK if the candidates could be enabled,
 *                    LBD_NOK otherwise
 */
static LBD_STATUS steerexecImplCmnEnableAllDisabledCandidates(
    steerexecImplCmnSteeringState_t *state,
    u_int8_t candidateCount,
    const struct lbd_bssInfo_t *candidateList,
    const struct ether_addr *staAddr) {

    if (!steerexecImplCmnIsBTMOnlySteer(state->steerType)) {
        if (wlanif_setNonCandidateStateForSTA(
            candidateCount,
            candidateList,
            staAddr,
            LBD_TRUE /* enable */,
            LBD_FALSE /* probeOnly */) != LBD_OK) {
            dbgf(state->context->dbgModule, DBGERR,
                 "%s: Failed to re-enable disabled candidate list for " lbMACAddFmt(":"),
                 __func__, lbMACAddData(staAddr->ether_addr_octet));

            return LBD_NOK;
        }
    }

    // All candidates should now be enabled
    state->candidateCount = 0;

    return LBD_OK;
}

/**
 * @brief Enable all disabled candidates / channels, and remove
 *        blacklists (if installed).
 *
 * @param [in] state steering state for STA
 * @param [in] staAddr MAC address of STA to remove blacklists
 *                     for
 *
 * @return LBD_OK if successfully removed
 */
static LBD_STATUS steerexecImplCmnRemoveAllBlacklists(
    steerexecImplCmnSteeringState_t *state,
    const struct ether_addr *staAddr) {

    LBD_STATUS status;

    if (state->legacy.disabledChannelCount) {
        // Re-enable all disabled channels
        status = steerexecImplCmnEnableAllDisabledChannels(state, staAddr);
    } else if (state->candidateCount ||
               state->blacklistType == steerexecImplCmnBlacklist_candidate ||
               steerexecImplCmnIsBlacklistSteer(state->steerType)) {
        // Note: It's possible to have blacklisted BSSes even with a 0-length
        // candidate list - if we received a prepare for steering request
        // and not all the BSSes (which must be remote) could be resolved.
        // In this case, all BSSes on ESS 0 will be blacklisted, and need
        // to be cleaned up here.  Check for all the conditions under which
        // a BSS could be blacklisted.

        // Re-enable all disabled candidates
        if (state->candidateCount > (sizeof(state->candidateList)/sizeof(state->candidateList[0]))){
            return LBD_NOK;
        }
        status = steerexecImplCmnEnableAllDisabledCandidates(state,
                                                             state->candidateCount,
                                                             &state->candidateList[0],
                                                             staAddr);
    } else {
        // No blacklist, return
        return LBD_OK;
    }

    if (status == LBD_OK) {
        steerexecImplCmnMarkAsNotBlacklisted(state);
    }

    return status;
}

/**
 * @brief The core implementation of the package level
 *        steerexecImplCmnAbortSteer() function.
 *
 * This allows the client to associate on the non-target band (where it was
 * previously disallowed).
 *
 * @pre exec, entry, and state are all valid
 *
 * @param [in] exec  the executor instance to use
 * @param [in] entry  the handle to the STA for which to abort
 * @param [in] state  the internal state used by the executor
 * @param [in] status reason for the abort
 * @param [in] isLocalAbort  set to LBD_TRUE if the steer has
 *                           ended because of an abort on the
 *                           local device, LBD_FALSE if it is
 *                           the result of a request from
 *                           another device in the network
 *
 * @return LBD_OK on success; otherwise LBD_NOK
 */
static LBD_STATUS steerexecImplCmnAbortSteerImpl(
        steerexecImplCmnHandle_t exec, stadbEntry_handle_t entry,
        steerexecImplCmnSteeringState_t *state,
        steerexecImplCmnSteeringStatusType_e status,
        LBD_BOOL isLocalAbort) {
    LBD_STATUS result = LBD_OK;
    const struct ether_addr *staAddr = stadbEntry_getAddr(entry);
    lbDbgAssertExit(state->context->dbgModule, staAddr);

    dbgf(exec->dbgModule, DBGINFO,
         "%s: Aborting steer request for " lbMACAddFmt(":")
         " due to %s (transaction %d)",
         __func__, lbMACAddData(staAddr->ether_addr_octet),
         steerexec_SteerStatusString[status],
         state->transaction);

    result = steerexecImplCmnRemoveAllBlacklists(state,staAddr);
    if (result == LBD_NOK) {
        dbgf(exec->dbgModule, DBGERR,
             "%s: Error clearing blacklist for " lbMACAddFmt(":")
             " (transaction %d).",
             __func__, lbMACAddData(staAddr->ether_addr_octet),
             state->transaction);
    }

    evloopTimeoutUnregister(&state->legacy.tSteerTimer);
    steerexecImplCmnSteerEnd(state, staAddr, status, isLocalAbort, entry);

    return result;
}

/**
 * @brief Callback function invoked by the station database module when
 *        the RSSI for a specific STA went below the low RSSI threshold
 *
 * Any blacklist installed will be removed.
 *
 * @param [in] entry  the entry that was updated
 * @param [in] cookie  the pointer to our internal state
 */
static void steerexecImplCmnLowRSSIObserver(stadbEntry_handle_t entry, void *cookie) {
    const struct steerexecImplCmnPriv_t *exec =
        (const struct steerexecImplCmnPriv_t *) cookie;
    lbDbgAssertExit(NULL, exec);

    steerexecImplCmnSteeringState_t *state = stadbEntry_getSteeringState(entry);
    if (!state) {
        // There must not be any steering operation in progress,
        // so no blacklist to remove.
        return;
    }

    stadbEntry_bssStatsHandle_t stats = stadbEntry_getServingBSS(entry, NULL);
    if (!stats) {
        // If not associated, nothing to do
        return;
    }

    wlanif_band_e band = stadbEntry_getAssociatedBand(entry, NULL);
    if (band == wlanif_band_invalid) {
        // Invalid band
        return;
    }

    // Be conservative here by double checking RSSI is below the low threshold
    u_int8_t rssi = stadbEntry_getUplinkRSSI(entry, stats, NULL, NULL);
    if (rssi != LBD_INVALID_RSSI &&
        rssi < exec->config.lowRSSIXingThreshold[band]) {
        const struct ether_addr *staAddr = stadbEntry_getAddr(entry);
        lbDbgAssertExit(exec->dbgModule, staAddr);

        if (LBD_OK == steerexecImplCmnRemoveAllBlacklists(state,
                                                       staAddr)) {
            dbgf(exec->dbgModule, DBGINFO,
                 "%s: Blacklist is cleared for "lbMACAddFmt(":")
                 " due to RSSI going below the low threshold (transaction %d).",
                 __func__, lbMACAddData(staAddr->ether_addr_octet),
                 state->transaction);
        }
    }
}

/**
 * @brief Timeout handler for T-Steering timer
 *
 * It will abort current steering and mark the device as steering unfriendly
 *
 * @param [in] cookie  the steering state
 */
static void steerexecImplCmnTSteeringTimeoutHandler(void *cookie) {
    stadbEntry_handle_t entry = (stadbEntry_handle_t) cookie;
    lbDbgAssertExit(NULL, entry);

    steerexecImplCmnSteeringState_t *state = stadbEntry_getSteeringState(entry);
    const struct ether_addr *staAddr = stadbEntry_getAddr(entry);
    steerexecImplCmnSteeringType_e steerType;

    // @todo Remove these when satisfied that there are no more lurking
    //       issues with spurious timer expiries.
    if (!state && staAddr) {
        dbgf(NULL, DBGERR,
             "%s: Unexpected NULL state for " lbMACAddFmt(":") " (entry=%p)",
             __func__, lbMACAddData(staAddr->ether_addr_octet), entry);
    } else if (!state && !staAddr) {
        dbgf(NULL, DBGERR,
             "%s: Unexpected NULL state and addr for entry=%p",
             __func__, entry);
    }

    lbDbgAssertExit(NULL, state);
    lbDbgAssertExit(state->context->dbgModule, staAddr);

    steerType = state->steerType;
    if (steerexecImplCmnIsBTMSteer(state->steerType) ||
        (state->steerType == steerexecImplCmnSteeringType_none)) {
        // Take no action for BTM steering - separate timer used to evaluate.
        // If there is no steering in progress, also ignore.
        return;
    }

    steerexecImplCmnAbortSteerImpl(state->context, entry, state,
                                   steerexecImplCmnSteeringStatusType_assoc_timeout,
                                   LBD_TRUE /* isLocalAbort */);

    // Steer type is reset in the state during abort
    if (steerexecImplCmnIsBestEffortSteer(steerType)) {
        dbgf(state->context->dbgModule, DBGINFO,
             "%s: "lbMACAddFmt(":")" not associated within %u seconds; "
             "steer is best-effort, not marking the device as steering unfriendly "
             "(transaction %d).",
             __func__, lbMACAddData(staAddr->ether_addr_octet),
             state->context->config.legacy.tSteering,
             state->transaction);
    } else {
        dbgf(state->context->dbgModule, DBGINFO,
             "%s: "lbMACAddFmt(":")" not associated within %u seconds; "
             "mark the device as steering unfriendly (transaction %d).",
             __func__, lbMACAddData(staAddr->ether_addr_octet),
             state->context->config.legacy.tSteering,
             state->transaction);

        steerexecImplCmnStartSteeringUnfriendly(state->context, state,
                                                staAddr);
    }
}

/**
 * @brief Clear a blacklist (if one exists) and unregister the
 *        T_Steer timer (should be used for BTM clients only)
 *
 * @param state steering state
 * @param entry STA entry to clear blacklist for
 * @param staAddr STA address to clear blacklist for
 */
static void steerexecImplCmnCleanupBlacklistBTM(steerexecImplCmnSteeringState_t *state,
                                                stadbEntry_handle_t entry,
                                                const struct ether_addr *staAddr,
                                                steerexecImplCmnSteeringStatusType_e status) {

    // Nothing to do for pure 802.11v based transitions
    if (steerexecImplCmnIsBTMOnlySteer(state->steerType)) {
        // All candidates should now be enabled
        state->candidateCount = 0;

        steerexecImplCmnSteerEnd(state, staAddr, status, LBD_TRUE /* isLocalAbort */, entry);
        return;
    }

    steerexecImplCmnRemoveAllBlacklists(state, staAddr);

    // Clear the T_Steer timer
    evloopTimeoutUnregister(&state->legacy.tSteerTimer);

    steerexecImplCmnSteerEnd(state, staAddr, status, LBD_TRUE /* isLocalAbort */, entry);
}

/**
 * @brief Timeout handler for BSS Transition Management timeouts
 *
 * Increments counters indicating cause of failure, and resets
 * BTM state.
 *
 * TBD: Add logic evaluating if this device is not BTM friendly
 *
 * @param cookie the steering state
 */
static void steerexecImplCmnBTMTimeoutHandler(void *cookie) {
    stadbEntry_handle_t entry = (stadbEntry_handle_t) cookie;
    lbDbgAssertExit(NULL, entry);

    steerexecImplCmnSteeringState_t *state = stadbEntry_getSteeringState(entry);
    const struct ether_addr *staAddr = stadbEntry_getAddr(entry);

    // @todo Remove these when satisfied that there are no more lurking
    //       issues with spurious timer expiries.
    if (!state && staAddr) {
        dbgf(NULL, DBGERR,
             "%s: Unexpected NULL state for " lbMACAddFmt(":") " (entry=%p)",
             __func__, lbMACAddData(staAddr->ether_addr_octet), entry);
    } else if (!state && !staAddr) {
        dbgf(NULL, DBGERR,
             "%s: Unexpected NULL state and addr for entry=%p",
             __func__, entry);
    }

    lbDbgAssertExit(NULL, state);
    lbDbgAssertExit(state->context->dbgModule, staAddr);

    // Get the current BTM state
    switch (state->state) {
        case steerexecImplCmn_state_aborted:
            // The transition was already aborted, so ignore this timeout,
            // and reset back to the idle state
            state->state = steerexecImplCmn_state_idle;
            break;
        case steerexecImplCmn_state_idle:
            dbgf(state->context->dbgModule, DBGINFO,
             "%s: "lbMACAddFmt(":")" timeout during BTM transition, but no BTM transition in progress",
             __func__, lbMACAddData(staAddr->ether_addr_octet));
            break;
        case steerexecImplCmn_state_waiting_response:
            state->state = steerexecImplCmn_state_failed;
            steerexecImplCmnSteerEndBTMFailure(
                entry, state, staAddr,
                steerexecImplCmnSteeringStatusType_btm_response_timeout);
            break;
        case steerexecImplCmn_state_waiting_association:
            state->state = steerexecImplCmn_state_failed;
            steerexecImplCmnSteerEndBTMFailure(
                entry, state, staAddr,
                steerexecImplCmnSteeringStatusType_assoc_timeout);
            break;
        default:
            dbgf(state->context->dbgModule, DBGERR,
                 "%s: "lbMACAddFmt(":")" received timeout during BTM transition, but invalid BTM state %d",
                 __func__, lbMACAddData(staAddr->ether_addr_octet), state->state);
            break;
    }
}

/**
 * @brief Handle an auth reject being generated locally
 *
 * @param [in] exec  the executor instance to use
 * @param [in] entry  the entry for which an auth reject was sent
 * @param [in] staAddr  MAC address of the STA to which the auth
 *                      reject was sent
 * @param [in] state  the internal state used by the executor
 *
 * @return LBD_TRUE if the steer is aborted, LBD_FALSE otherwise
 */
static LBD_BOOL steerexecImplCmnHandleAuthRejLocal(
    struct steerexecImplCmnPriv_t *exec, stadbEntry_handle_t entry,
    const struct ether_addr *staAddr,
    steerexecImplCmnSteeringState_t *state) {

    unsigned secsRemaining, usecsRemaining;

    LBD_BOOL shouldAbort = LBD_FALSE;
    LBD_BOOL shouldNotifyAuthReject = LBD_FALSE;
    if(evloopTimeoutRemaining(&state->legacy.tSteerTimer, &secsRemaining,
                              &usecsRemaining)) {
        evloopTimeoutRegister(&state->legacy.tSteerTimer, exec->config.legacy.tSteering,
                              0 /* USec */);
        state->legacy.numAuthRejects = 1;
        shouldNotifyAuthReject = LBD_TRUE;
    } else {
        // Update the authentication reject count, but only if enough time
        // has elapsed from the first one.
        if (exec->config.legacy.tSteering - secsRemaining >
                exec->config.legacy.initialAuthRejCoalesceTime) {
            state->legacy.numAuthRejects++;
            shouldNotifyAuthReject = LBD_TRUE;
        }

        // If there have been too many auth rejects, abort the steering.
        if (state->legacy.numAuthRejects == exec->config.legacy.authRejMax) {
            steerexecImplCmnAbortSteerImpl(
                exec, entry, state, steerexecImplCmnSteeringStatusType_abort_auth_reject,
                LBD_TRUE /* isLocalAbort */);

            steerexecImplCmnStartSteeringUnfriendly(state->context, state,
                                                    staAddr);

            shouldAbort = LBD_TRUE;
        }

        // Have not hit the limit yet.
    }

    // Notify remote nodes of the auth reject (if required)
    // Note will only send the notification of authentication reject if the number
    // of auth rejects changes (either because this is the first auth reject of
    // the steer, or we are outside of the coalesce time).
    if (shouldNotifyAuthReject) {
        steerexecImplHandleAuthReject(staAddr, state->legacy.numAuthRejects);
    }

    return shouldAbort;
}

/**
 * @brief Handle the report of an auth reject being generated on
 *        a remote node
 *
 * @param [in] exec  the executor instance to use
 * @param [in] entry  the entry for which an auth reject was sent
 * @param [in] staAddr  MAC address of the STA to which the auth
 *                      reject was sent
 * @param [in] state  the internal state used by the executor
 * @param [in] numAuthRejects  number of auth rejects sent to
 *                             the STA during this steering
 *                             attempt
 *
 * @return LBD_TRUE if the steer is aborted, LBD_FALSE otherwise
 */
static LBD_BOOL steerexecImplCmnHandleAuthRejRemote(
    struct steerexecImplCmnPriv_t *exec, stadbEntry_handle_t entry,
    const struct ether_addr *staAddr,
    steerexecImplCmnSteeringState_t *state,
    u_int8_t numAuthRejects) {

    unsigned secsRemaining, usecsRemaining;

    int isTSteerTimerIdle =
        evloopTimeoutRemaining(&state->legacy.tSteerTimer, &secsRemaining,
                               &usecsRemaining);

    u_int8_t originalNumAuthRejects = state->legacy.numAuthRejects;
    if (isTSteerTimerIdle) {
        // Timer not yet started - reset number of auth rejects
        // Set the count to the value sent by the other device
        originalNumAuthRejects = 0;
        state->legacy.numAuthRejects = numAuthRejects;
    } else {
        // Timer already started, so there have been local and remote auth
        // rejects.  There is a potential for race conditions / errors due
        // to lost messages, so this is a 'best-effort' update.
        if (numAuthRejects > state->legacy.numAuthRejects) {
            // Assume auth rejects are in sync
            state->legacy.numAuthRejects = numAuthRejects;
        } else {
            // We are possibly out of sync - increment by 1
            state->legacy.numAuthRejects++;
        }
    }

    dbgf(exec->dbgModule, DBGDEBUG,
         "%s: Update auth reject count from remote notification. "
         "Original local count: %u, Remote count: %u, New local count %u",
         __func__, originalNumAuthRejects, numAuthRejects, state->legacy.numAuthRejects);

    // If there have been too many auth rejects, abort the steering.
    if (state->legacy.numAuthRejects >= exec->config.legacy.authRejMax) {

        // Steer is still in progress, but hit the maximum number of auth rejects
        // Note this is not the normal order - usually steer should be aborted first.
        // However, this can happen if the abort message is lost OTA.
        if (state->state != steerexecImplCmn_state_idle &&
            state->state != steerexecImplCmn_state_aborted) {
            dbgf(exec->dbgModule, DBGINFO,
                 "%s: Received max number of remote auth rejects (%d), but steer was "
                 "not aborted remotely.  Either abort message was lost OTA, out of order, "
                 "or max number of auth rejects is different in the network",
                 __func__, state->legacy.numAuthRejects);

            steerexecImplCmnAbortSteerImpl(
                exec, entry, state, steerexecImplCmnSteeringStatusType_abort_auth_reject,
                LBD_FALSE /* isLocalAbort */);

            steerexecImplCmnStartSteeringUnfriendly(state->context, state,
                                                    staAddr);
        }

        return LBD_TRUE;
    } else if (isTSteerTimerIdle) {
        // Not aborting the steer.
        // Start the T-Steering timer if it's not already started
        evloopTimeoutRegister(&state->legacy.tSteerTimer, exec->config.legacy.tSteering,
                              0 /* USec */);
    }

    return LBD_FALSE;
}

/**
 * @brief Check if a channel has an RSSI below the low threshold
 *        for a STA
 *
 * @param [in] ts  current time
 * @param [in] exec  steering executor
 * @param [in] state  steering state for STA
 * @param [in] entry  staDB entry for STA
 * @param [in] stats  BSS stats handle to check RSSI for
 * @param [in] channel  channel to check RSSI for
 *
 * @return LBD_FALSE if the RSSI is too low; otherwise LBD_TRUE
 */
static LBD_BOOL steerexecImplCmnIsTargetChannelRSSIOK(
    const struct timespec *ts,
    struct steerexecImplCmnPriv_t *exec,
    steerexecImplCmnSteeringState_t *state,
    stadbEntry_handle_t entry,
    stadbEntry_bssStatsHandle_t stats,
    lbd_channelId_t channel) {

    wlanif_band_e targetBand =
        wlanif_resolveBandFromChannelNumber(channel);
    lbDbgAssertExit(exec->dbgModule, targetBand != wlanif_band_invalid);

    time_t rssiAgeSecs = 0xFF;
    lbd_rssi_t rssi = stadbEntry_getUplinkRSSI(entry, stats,
                                               &rssiAgeSecs, NULL);

    // Note RSSI value is only checked if it is valid and has been updated
    // since the steer began.  This function is basically checking if conditions
    // have changed since the decision was made to begin steering.
    if (rssi == LBD_INVALID_RSSI ||
        rssiAgeSecs > (ts->tv_sec - state->legacy.lastSteeringTime) ||
        rssi >= exec->config.targetLowRSSIThreshold[targetBand]) {
        // Target RSSI is OK, or has not changed since the steer began
        return LBD_TRUE;
    }

    // Target RSSI is too low
    dbgf(exec->dbgModule, DBGDEBUG,
         "%s: RSSI (%u) on candidate channel %u is below threshold (%u)",
         __func__, rssi, channel, exec->config.targetLowRSSIThreshold[targetBand]);
    return LBD_FALSE;
}

/**
 * @brief Check if all candidate BSSes have a RSSI below the low
 *        threshold for a STA (post-association steering)
 *
 * @param [in] exec  steering executor
 * @param [in] state  steering state for STA
 * @param [in] entry  staDB entry for STA
 *
 * @return LBD_FALSE if all candidates have an RSSI below the
 *         low threshold; LBD_TRUE otherwise
 */
static LBD_BOOL steerexecImplCmnIsTargetRSSIOKCandidate(
    struct steerexecImplCmnPriv_t *exec,
    steerexecImplCmnSteeringState_t *state,
    stadbEntry_handle_t entry) {

    struct timespec ts;
    lbGetTimestamp(&ts);

    size_t i;
    LBD_BOOL retval = LBD_TRUE ;

    if (state->numUnresolvedCandidates) {
        // Not all candidates are resolved, so won't abort steer
        return LBD_TRUE;
    }

    for (i = 0; i < state->candidateCount; i++) {
        if (!lbIsBSSLocal(&state->candidateList[i])) {
            // At least one BSS is remote, so we can't know the target RSSI, don't abort steer
            return LBD_TRUE;
        }

        stadbEntry_bssStatsHandle_t stats =
            stadbEntry_findMatchBSSStats(entry,
                                         &state->candidateList[i]);
        if (!stats) {
            // No stats for this target BSS
            continue;
        }

        if (steerexecImplCmnIsTargetChannelRSSIOK(&ts, exec, state, entry, stats,
                                               state->candidateList[i].channelId)) {
            return LBD_TRUE;
        } else {
            retval = LBD_FALSE;
        }
    }

    // No candidate has an OK target RSSI
    return retval;
}

/**
 * @brief Callback function used to check if a BSS has a RSSI
 *        below the low threshold for a STA (used for
 *        pre-association steering)
 *
 * @param [in] entry  staDB entry for STA
 * @param [in] bssHandle  BSS stats handle
 * @param [inout] cookie  contains
 *                        steerexecImplCmnCheckChannelRSSI_t
 *                        pointer
 *
 * @return LBD_FALSE if the RSSI is below the low threshold;
 *         LBD_TRUE otherwise
 */
static LBD_BOOL steerexecImplCmnIsTargetRSSIOKChannelCallback(
    stadbEntry_handle_t entry, stadbEntry_bssStatsHandle_t bssHandle,
    void *cookie) {
    steerexecImplCmnCheckChannelRSSI_t *params =
        (steerexecImplCmnCheckChannelRSSI_t *) cookie;

    const lbd_bssInfo_t *bssInfo = stadbEntry_resolveBSSInfo(bssHandle);
    lbDbgAssertExit(params->exec->dbgModule, bssInfo); // should never happen in practice

    // Is this BSS on one of the enabled channels?
    if (!steerexecImplCmnIsOnChannelList(params->enabledChannelCount,
                                      params->enabledChannelList,
                                      bssInfo->channelId)) {
        return LBD_FALSE;
    }

    // Is the RSSI for this BSS OK?
    if (steerexecImplCmnIsTargetChannelRSSIOK(&params->ts, params->exec, params->state,
                                           entry, bssHandle,
                                           bssInfo->channelId)) {
        params->isChannelRSSIOK = LBD_TRUE;
        return LBD_TRUE;
    }

    // RSSI is insufficient
    return LBD_FALSE;
}

/**
 * @brief Check if all enabled channels have a RSSI below the
 *        low threshold for a STA (pre-association steering)
 *
 * @param [in] exec  steering executor
 * @param [in] state  steering state for STA
 * @param [in] entry  staDB entry for STA
 *
 * @return LBD_FALSE if all channels have a RSSI below the low
 *         threshold; LBD_TRUE otherwise
 */
static LBD_BOOL steerexecImplCmnIsTargetRSSIOKChannel(
    struct steerexecImplCmnPriv_t *exec,
    steerexecImplCmnSteeringState_t *state,
    stadbEntry_handle_t entry) {

    u_int8_t wlanifChannelCount;
    lbd_channelId_t wlanifChannelList[WLANIF_MAX_RADIOS];

    // Get the set of channels from the radio
    if (steerexecImplCmnGetAndValidateRadioChannelList(state, &wlanifChannelCount,
                                                    &wlanifChannelList[0]) != LBD_OK) {
        return LBD_FALSE;
    }

    // Get the set of enabled channels
    steerexecImplCmnCheckChannelRSSI_t params;
    lbGetTimestamp(&params.ts);
    params.exec = exec;
    params.state = state;
    params.isChannelRSSIOK = LBD_FALSE;
    params.enabledChannelCount = steerexecImplCmnCopyAllNotOnList(
        wlanifChannelCount,
        &wlanifChannelList[0],
        state->legacy.disabledChannelCount,
        &state->legacy.disabledChannelList[0],
        &params.enabledChannelList[0]);

    // Determine if there are any BSSes that have an adequate RSSI
    if (stadbEntry_iterateBSSStats(entry,
                                   steerexecImplCmnIsTargetRSSIOKChannelCallback,
                                   &params, NULL, NULL) != LBD_OK) {
        const struct ether_addr *addr = stadbEntry_getAddr(entry);
        lbDbgAssertExit(exec->dbgModule, addr);
        dbgf(exec->dbgModule, DBGERR,
             "%s: Failed to iterate over BSS stats for " lbMACAddFmt(":"),
             __func__, lbMACAddData(addr->ether_addr_octet));

        return LBD_FALSE;
    }

    return params.isChannelRSSIOK;
}

/**
 * @brief Callback function invoked by the station database module when
 *        the RSSI for a specific STA got updates
 *
 * If a STA is in steering progress and the target band RSSI goes below
 * the threshold, the steering will be cancelled.
 *
 * In addition, the T_Steering timer will be started on the first auth
 * reject.
 *
 * @param [in] entry  the entry that was updated
 * @param [in] reason  the reason the RSSI value was updated
 * @param [in] cookie  the pointer to our internal state
 */
static void steerexecImplCmnRSSIObserver(stadbEntry_handle_t entry,
                                         stadb_rssiUpdateReason_e reason,
                                         void *cookie) {
    struct steerexecImplCmnPriv_t *exec =
        (struct steerexecImplCmnPriv_t *) cookie;
    lbDbgAssertExit(NULL, exec);
    steerexecImplCmnSteeringState_t *state = stadbEntry_getSteeringState(entry);
    if (!state) {
        return;
    }
    // Ignore entry that is not currently blacklisted, or being steered via 802.11v without
    // also requiring a blacklist to be installed.
    if (steerexecImplCmnIsBTMOnlySteer(state->steerType) ||
        ((state->steerType == steerexecImplCmnSteeringType_none) &&
         (state->blacklistType == steerexecImplCmnBlacklist_none))) {
        return;
    }

    // If the auth reject handling indicates the abort already happened, we
    // do not even need to examine the RSSI.
    if (reason == stadb_rssiUpdateReason_authrej &&
        steerexecImplCmnHandleAuthRej(exec, entry, state, 0)) {
        return;
    }

    // If steering is still in progress, we need to check the RSSI to make
    // sure the target is not too low.  As long as at least one candidate
    // has an OK RSSI, we will continue steering.
    LBD_BOOL rssiSafe = LBD_FALSE;
    if (state->steerType == steerexecImplCmnSteeringType_none) {
        return;
    } else if (state->steerType == steerexecImplCmnSteeringType_preassociation) {
        rssiSafe = steerexecImplCmnIsTargetRSSIOKChannel(exec, state, entry);
    } else {
        rssiSafe = steerexecImplCmnIsTargetRSSIOKCandidate(exec, state, entry);
    }

    if (!rssiSafe) {
        steerexecImplCmnAbortSteerImpl(exec, entry, state,
                                       steerexecImplCmnSteeringStatusType_abort_low_rssi,
                                       LBD_TRUE /* isLocalAbort */);
    }
}

/**
 * @brief Check if a candidate list matches the currently active
 *        steer
 *
 * @param [in] state steering state for the STA
 * @param [in] candidateCount number of candidates
 * @param [in] candidateList list of candidates
 *
 * @return LBD_TRUE if steer is to the same target BSS set
 */
LBD_BOOL steerexecImplCmnIsSameTarget(steerexecImplCmnSteeringState_t *state,
                                   u_int8_t candidateCount,
                                   const lbd_bssInfo_t *candidateList) {
    if ((state->candidateCount == candidateCount) &&
        (memcmp(&state->candidateList, candidateList,
                sizeof(lbd_bssInfo_t) * candidateCount) == 0)) {
        return LBD_TRUE;
    } else {
        return LBD_FALSE;
    }
}

/**
 * @brief Determine the change in blacklist due to a new
 *        candidate based steer
 *
 * @param [in] state  steering state
 * @param [in] staAddr  MAC address of STA
 * @param [in] candidateCount  number of candidates for steer
 * @param [in] candidateList  list of candidates for steer
 * @param [out] enableCount  count of candidate BSSes to enable
 * @param [out] enableList  list of candidate BSSes to enable
 * @param [out] disableCount  count of candidate BSSes to
 *                            disable
 * @param [out] disableList  list of candidate BSSes to disable
 *
 */
static void steerexecImplCmnUpdateCandidateBlacklist(
    steerexecImplCmnSteeringState_t *state,
    const struct ether_addr *staAddr,
    u_int8_t candidateCount,
    const lbd_bssInfo_t *candidateList,
    u_int8_t *enableCount,
    lbd_bssInfo_t *enableList,
    u_int8_t *disableCount,
    lbd_bssInfo_t *disableList) {

    // Get the set of candidates to enable - any candidate on the new candidate list
    // that is not on the old candidate list.
    size_t i, j;
    *enableCount = 0;
    *disableCount = 0;
    for (i = 0; i < candidateCount; i++) {
        LBD_BOOL match = LBD_FALSE;
        // Only copy local BSSes
        if (!lbIsBSSLocal(&candidateList[i])) {
            continue;
        }

        for (j = 0; j < state->candidateCount; j++) {
            if (lbAreBSSesSame(&candidateList[i], &state->candidateList[j])) {
                match = LBD_TRUE;
                break;
            }
        }

        if (!match) {
            lbCopyBSSInfo(&candidateList[i], &enableList[*enableCount]);
            (*enableCount)++;
        }
    }

    // Get the set of candidates to disable - any candidate on the old candidate list
    // that is not on the new candidate list.
    for (i = 0; i < state->candidateCount; i++) {
        LBD_BOOL match = LBD_FALSE;
        // Only copy local BSSes
        if (!lbIsBSSLocal(&state->candidateList[i])) {
            continue;
        }

        for (j = 0; j < candidateCount; j++) {
            if (lbAreBSSesSame(&candidateList[j], &state->candidateList[i])) {
                match = LBD_TRUE;
                break;
            }
        }

        if (!match) {
            lbCopyBSSInfo(&state->candidateList[i], &disableList[*disableCount]);
            (*disableCount)++;
        }
    }
}

/**
 * @brief Set the lastSteeringTime (and the BTM last steering
 *        time if needed) to the current time
 *
 * @param [in] state  steering state
 */
static void steerexecImplCmnSetLastSteeringTime(
    steerexecImplCmnSteeringState_t *state) {
    struct timespec ts;
    lbGetTimestamp(&ts);

    state->legacy.lastSteeringTime = ts.tv_sec;
    stadb_setDirty();
}

/**
 * @brief Perform common pre-steering preparation (regardless of
 *        steering mechanism) and install blacklist if required
 *        (legacy clients and BTM clients when BTMAlsoBlacklist
 *        config parameter is set)
 *
 * @param [in] state the internal state used by the executor for
 *                   the entry
 * @param [in] exec steering executor
 * @param [in] entry staDB entry to prepare for steering
 * @param [in] candidateCount number of candidates for steer
 * @param [in] candidateList list of candidates for steer
 * @param [out] ignored set to LBD_TRUE if this request is
 *                      ignored
 * @param [in] bss BSS the STA is currently associated to
 * @param [out] okToSteer set to LBD_TRUE if preparation was
 *                        successful and STA can be steered to
 *                        targetBand
 *
 * @return LBD_STATUS LBD_OK on success, LBD_NOK otherwise
 */
static LBD_STATUS steerexecImplCmnPrepareForSteering(
    steerexecImplCmnSteeringState_t *state,
    steerexecImplCmnHandle_t exec,
    stadbEntry_handle_t entry,
    u_int8_t candidateCount,
    const lbd_bssInfo_t *candidateList,
    LBD_BOOL *ignored,
    stadbEntry_bssStatsHandle_t stats,
    const lbd_bssInfo_t *bss,
    LBD_BOOL isBestEffort,
    LBD_BOOL *okToSteer) {

    *okToSteer = LBD_FALSE;
    if (ignored) {
        *ignored = LBD_TRUE;
    }

    const struct ether_addr *staAddr = stadbEntry_getAddr(entry);
    lbDbgAssertExit(exec->dbgModule, staAddr);

    // Determine what sort of steering to use
    steerexecImplCmnSteeringType_e steerType =
        steerexecImplCmnDetermineSteeringType(state, exec, entry, staAddr,
                                              stats,
                                              LBD_FALSE /* eligibilityOnly */,
                                              LBD_TRUE /* reportReasonNotEligible */,
                                              isBestEffort);

    // Should only be here for post-association steering
    if ((steerType == steerexecImplCmnSteeringType_none) ||
        (steerType == steerexecImplCmnSteeringType_preassociation)) {
        return LBD_OK;
    }

    // Make sure we're not getting steered to the currently associated BSS
    if (steerexecImplCmnIsOnCandidateList(state, candidateCount, candidateList, bss)) {
        lbDbgAssertExit(exec->dbgModule, bss);
        dbgf(exec->dbgModule, DBGERR,
             "%s: Requested steer for " lbMACAddFmt(":")
             " to currently associated BSS " lbBSSInfoAddFmt() ", will not steer",
             __func__,
             lbMACAddData(staAddr->ether_addr_octet),
             lbBSSInfoAddData(bss));
        return LBD_NOK;
    }

    // Special handling if there is already a steer in progress.
    if (steerexecImplCmnHandleSteerInProgress(
        state, exec, entry, staAddr, steerType,
        candidateCount, candidateList, okToSteer) != LBD_OK) {
        return LBD_NOK;
    }

    if (!(*okToSteer)) {
        return LBD_OK;
    }

    // Update blacklists
    if (steerexecImplCmnReconcileSteerCandidate(
        state, state->context, entry, staAddr, steerType, candidateCount,
        candidateList) != LBD_OK) {
        // Error setting blacklists
        return LBD_NOK;
    }

    // Mark this entry as not allowing steering for the configured time.
    steerexecImplCmnStartSteeringProhibitLocal(
        exec, state, staAddr, steerexecImplCmnIsBTMSteer(steerType) ?
        steerexecImplCmnSteeringProhibitType_short :
        steerexecImplCmnSteeringProhibitType_long, entry);

    state->steerType = steerType;

    // Blacklisting process was OK, can continue on to steer the STA now
    if (ignored) {
        *ignored = LBD_FALSE;
    }
    *okToSteer = LBD_TRUE;

    return LBD_OK;
}

/**
 * @brief Save steering parameters
 *
 * @param [in] state  steering state
 * @param [in] numUnresolvedCandidates  number of unresolved
 *        candidates
 * @param [in] candidateCount  number of resolved candidates
 * @param [in] candidateList  list of candidates
 * @param [in] reason  reason for the steer
 * @param [in] blacklistAutoClear  set to LBD_TRUE if the
 *                                 blacklist should be cleared
 *                                 on steer completion
 * @param [in] blacklistMaxTime  max time blacklist will be kept
 *                               after steer completion if
 *                               blacklistAutoClear == LB_FALSE
 * @param [in] isSteerInProgress  set to LBD_TRUE if the steer
 *                                is in progress (being
 *                                updated); set to LBD_FALSE if
 *                                this is a new steer
 */
static void steerexecImplCmnSaveSteerParams(
    steerexecImplCmnSteeringState_t *state,
    u_int8_t numUnresolvedCandidates,
    u_int8_t candidateCount,
    const lbd_bssInfo_t *candidateList,
    steerexec_reason_e reason,
    LBD_BOOL blacklistAutoClear,
    u_int32_t blacklistMaxTime,
    LBD_BOOL isSteerInProgress) {
    // Copy over the candidates
    state->numUnresolvedCandidates = numUnresolvedCandidates;
    state->candidateCount = candidateCount;
    memcpy(&state->candidateList[0], candidateList,
           candidateCount * sizeof(lbd_bssInfo_t));

    state->reason = reason;
    state->blacklistAutoClear = blacklistAutoClear;
    state->blacklistMaxTime = blacklistMaxTime;

    if (!isSteerInProgress) {
        // Update the transaction ID
        steerexecImplCmnUpdateTransactionID(state->context, state);
    }
}

/**
 * @brief Start a steer
 *
 * @param [in] state  steering state
 * @param [in] exec  steering executor
 * @param [in] entry  stadb entry for STA
 * @param [in] staAddr  MAC address of STA
 * @param [in] assocBSS  BSS STA is currently associated on
 *
 * @return LBD_OK if steer was started, LBD_NOK otherwise
 */
static LBD_STATUS steerexecImplCmnStartSteer(
    steerexecImplCmnSteeringState_t *state,
    steerexecImplCmnHandle_t exec,
    stadbEntry_handle_t entry,
    const struct ether_addr *staAddr,
    const lbd_bssInfo_t *assocBSS) {

    // How the device is steered is determined by whether or not the device supports
    // 802.11v BTM
    LBD_STATUS status;
    lbDbgAssertExit(exec->dbgModule, assocBSS);
    if (steerexecImplCmnIsLegacySteer(state->steerType)) {
        status = steerexecImplCmnSteerLegacy(state, exec, entry,
                                             staAddr, assocBSS);
    } else {
        status = steerexecImplCmnSteerBTM(state, exec, entry,
                                          staAddr, assocBSS);
    }

    if (status == LBD_OK) {
        // Steering was successful, log

        // Make sure the reason code is not out of bounds
        if (state->reason > steerexec_reason_invalid) {
            state->reason = steerexec_reason_invalid;
        }
        dbgf(exec->dbgModule, DBGINFO,
             "%s: Starting new steer for " lbMACAddFmt(":") " of type %s "
             " for reason %s (transaction %d)",
             __func__, lbMACAddData(staAddr->ether_addr_octet),
             steerexecImplCmn_SteeringTypeString[state->steerType],
             steerexec_SteeringReasonString[state->reason],
             state->transaction);

        if (diaglog_startEntry(mdModuleID_SteerExec,
                               steerexec_msgId_postAssocSteerStart,
                               diaglog_level_demo)) {
            diaglog_writeMAC(staAddr);
            diaglog_write8(state->transaction);
            diaglog_write8(state->steerType);
            diaglog_write8(state->reason);
            // Log the currently associated BSS
            diaglog_writeBSSInfo(assocBSS);
            // Log the number of candidates
            diaglog_write8(state->candidateCount);
            // Log the candidates
            size_t i;
            for (i = 0; i < state->candidateCount; i++) {
                diaglog_writeBSSInfo(&state->candidateList[i]);
            }
            diaglog_finishEntry();
        }
    } else {
         /*== handle steer fail */
        steerexecImplCmnAbortInProgress(exec, state, entry, staAddr,
                steerexecImplCmnSteeringStatusType_prepare_fail, LBD_TRUE /*isLocalAbort*/, NULL);
        state->candidateCount = 0;
        state->steerType = steerexecImplCmnSteeringType_none;
        state->state = steerexecImplCmn_state_idle;
    }

    return status;
}

/**
 * @brief Perform steering via BSS Transition Management request
 *        frame
 *
 * @param [in] state the internal state used by the executor for
 *                   the entry
 * @param [in] exec steering executor
 * @param [in] entry staDB entry to steer
 * @param [in] staAddr MAC address of STA to steer
 * @param [in] assocBSS BSS STA is currently associated on
 *
 * @return LBD_STATUS LBD_OK if steering was started
 *         successfully, LBD_NOK otherwise
 */
static LBD_STATUS steerexecImplCmnSteerBTM(
    steerexecImplCmnSteeringState_t *state,
    steerexecImplCmnHandle_t exec,
    stadbEntry_handle_t entry,
    const struct ether_addr *staAddr,
    const lbd_bssInfo_t *assocBSS) {

    // Store the current association
    lbCopyBSSInfo(assocBSS, &state->btm->initialAssoc);

    // Set steering flag in driver to avoid unnecessary deauth.
    // Based on current testing, even if this operation fails, steering
    // can still succeed, so only print a warning for failure
    if (LBD_NOK == wlanif_updateSteeringStatus(
                       staAddr, assocBSS, LBD_TRUE /* steeringInProgress */)) {
        dbgf(exec->dbgModule, DBGERR,
             "%s: Failed to set steering flag for " lbMACAddFmt(":")
             " on " lbBSSInfoAddFmt() ", but BTM steering can continue.",
             __func__, lbMACAddData(staAddr->ether_addr_octet),
             lbBSSInfoAddData(assocBSS));
    }

    if (wlanif_sendBTMRequest(assocBSS,
                              staAddr,
                              exec->btm.dialogToken,
                              state->candidateCount,
                              state->candidateList) != LBD_OK) {
        // Failed to send BTM request
        dbgf(exec->dbgModule, DBGERR,
             "%s: Can't steer for " lbMACAddFmt(":")
             " sendBTMRequest failed (transaction %d)",
             __func__,
             lbMACAddData(staAddr->ether_addr_octet),
             state->transaction);

        wlanif_updateSteeringStatus(staAddr, assocBSS,
                                    LBD_FALSE /* steeringInProgress */);
        return LBD_NOK;
    }

    // Increment dialogToken for the next BTM to send, and store current dialogToken
    // with the STA record
    state->btm->dialogToken = exec->btm.dialogToken;
    exec->btm.dialogToken++;

    // Steering is now in progress to the target band, waiting for a BTM response
    state->state = steerexecImplCmn_state_waiting_response;

    // Start timer for BTM response timeout
    evloopTimeoutRegister(&state->btm->timer, exec->config.btm.responseTime,
                          0 /* USec */);

    return LBD_OK;
}

/**
 * @brief Perform steering via disassociation
 *
 * @param [in] state the internal state used by the executor for
 *                   the entry
 * @param [in] exec steering executor
 * @param [in] entry staDB entry to steer
 * @param [in] staAddr MAC address of STA to steer
 * @param [in] assocBSS BSS STA is currently associated on
 *
 * @return LBD_STATUS LBD_OK if steering was started
 *         successfully, LBD_NOK otherwise
 */
static LBD_STATUS steerexecImplCmnSteerLegacy(
    steerexecImplCmnSteeringState_t *state,
    steerexecImplCmnHandle_t exec,
    stadbEntry_handle_t entry,
    const struct ether_addr *staAddr,
    const lbd_bssInfo_t *assocBSS) {

    // If the device is currently associated on the other band (the one being
    // disallowed), kick it out. If it is already associated on the target
    // band, we do not disassociate as this may be an attempt to lock the
    // client to the band.
    if (wlanif_disassociateSTA(assocBSS, staAddr, LBD_FALSE /* local */) != LBD_OK) {
        dbgf(exec->dbgModule, DBGERR,
             "%s: Failed to force " lbMACAddFmt(":") " to disassociate "
             "on BSS " lbBSSInfoAddFmt() " (transaction %d)", __func__,
             lbMACAddData(staAddr->ether_addr_octet),
             lbBSSInfoAddData(assocBSS), state->transaction);

        // Should we remove the blacklist we installed above? For now,
        // we do not as the hope is if the client does disassociate, it
        // should go to the target band as desired.
        return LBD_NOK;
    }

    // Steering is now in progress to the target, waiting for association
    state->state = steerexecImplCmn_state_waiting_association;

    return LBD_OK;
}

/**
 * @brief Abort the currently in progress steer
 *
 * @param [in] exec steering executor
 * @param [in] state the internal state used by the executor for
 *                   the entry
 * @param [in] entry staDB entry for STA
 * @param [in] addr MAC address of STA
 * @param [in] abortReason  reason the steer is aborted
 * @param [in] isLocalAbort  set to LBD_TRUE if the steer has
 *                           ended because of an abort on the
 *                           local device, LBD_FALSE if it is
 *                           the result of a request from
 *                           another device in the network
 * @param [out] ignored  set to LBD_TRUE if nothing can be
 *                       aborted (BTM only steer), LBD_FALSE
 *                       otherwise
 *
 * @return LBD_OK on success, LBD_NOK on failure
 */
static LBD_STATUS steerexecImplCmnAbortInProgress(
    steerexecImplCmnHandle_t exec,
    steerexecImplCmnSteeringState_t *state,
    stadbEntry_handle_t entry,
    const struct ether_addr *addr,
    steerexecImplCmnSteeringStatusType_e abortReason,
    LBD_BOOL isLocalAbort,
    LBD_BOOL *ignored) {

    LBD_STATUS status;

    if (steerexecImplCmnIsBTMSteer(state->steerType)) {
        status = steerexecImplCmnAbortBTM(exec, state, entry, addr);

        // Do we have blacklists installed too?
        if (steerexecImplCmnIsBTMOnlySteer(state->steerType)) {
            steerexecImplCmnSteerEnd(state, addr, abortReason, isLocalAbort, entry);
            return status;
        }
    }

    if (ignored) {
        *ignored = LBD_FALSE;
    }

    // Do blacklist related abort
    return steerexecImplCmnAbortSteerImpl(exec, entry, state,
                                          abortReason, isLocalAbort);
}

/**
 * @brief Abort a steering attempt for a STA being steered via
 *        BTM.  Note this is currently a NOP since a BTM
 *        transition can not be cancelled.
 *
 * @param [in] exec steering executor
 * @param [in] state  steering state
 * @param [in] entry staDB entry to steer
 * @param [in] addr  MAC address of STA
 *
 * @return LBD_STATUS always returns LBD_OK
 */
static LBD_STATUS steerexecImplCmnAbortBTM(steerexecImplCmnHandle_t exec,
                                        steerexecImplCmnSteeringState_t *state,
                                        stadbEntry_handle_t entry,
                                        const struct ether_addr *addr) {
    // Can't cancel an 802.11v BTM request.  No need to return an error, just log
    // that nothing was done.
    dbgf(exec->dbgModule, DBGDEBUG,
         "%s: Steer request to " lbMACAddFmt(":")
         " aborted, but it was steered via BTM, so transition may continue (transaction %d)",
         __func__, lbMACAddData(addr->ether_addr_octet),
         state->transaction);

    return LBD_OK;
}

/**
 * @brief Check if a BSS is on a candidate list
 *
 * @param [in] state steering state
 * @param [in] candidateCount number of candidates for steer
 * @param [in] candidateList list of candidates for steer
 * @param [in] bss BSS to check for
 *
 * @return LBD_TRUE if found, LBD_FALSE otherwise
 */
static LBD_BOOL steerexecImplCmnIsOnCandidateList(steerexecImplCmnSteeringState_t *state,
                                               u_int8_t candidateCount,
                                               const lbd_bssInfo_t *candidateList,
                                               const lbd_bssInfo_t *bss) {
    size_t i;

    for (i = 0; i < candidateCount; i++) {
        if (lbAreBSSesSame(bss, &candidateList[i])) {
            return LBD_TRUE;
        }
    }

    // Not found in list
    return LBD_FALSE;
}

/**
 * @brief Check if a channel is on a channel list
 *
 * @param [in] channelCount  count of channels to check
 * @param [in] channelList  list of channels to check
 * @param [in] channel  channel to search for
 *
 * @return LBD_TRUE if channel is found; LBD_FALSE otherwise
 */
static LBD_BOOL steerexecImplCmnIsOnChannelList(u_int8_t channelCount,
                                             const lbd_channelId_t *channelList,
                                             lbd_channelId_t channel) {
    if (!channelList) {
        return LBD_FALSE;
    }
    size_t i;
    for (i = 0; i < channelCount; i++) {
        if (channelList[i] == channel) {
            return LBD_TRUE;
        }
    }

    return LBD_FALSE;
}

/**
 * @brief Check if an association occurred in an expected
 *        location
 *
 * @param [in] state  steering state
 * @param [in] entry  staDB entry for the STA
 * @param [in] assocBSS  BSS STA associated on
 * @param [in] staAddr  MAC address of STA
 * @param [in] abort  set to LBD_TRUE if steer should be aborted if the
 *                    association is not on a steer candidate
 *
 * @return LBD_TRUE if association is valid (and completes a
 *         steer), else LBD_FALSE
 */
static LBD_BOOL steerexecImplCmnIsAssociationOnCandidate(
    steerexecImplCmnSteeringState_t *state,
    stadbEntry_handle_t entry,
    const lbd_bssInfo_t *assocBSS,
    const struct ether_addr *staAddr,
    LBD_BOOL abort) {

    if (steerexecImplCmnIsOnCandidateList(state, state->candidateCount,
                                          &state->candidateList[0], assocBSS)) {
        dbgf(state->context->dbgModule, DBGDEBUG,
             "%s: STA " lbMACAddFmt(":") " associated on BSS " lbBSSInfoAddFmt()
             " matching entry in candidate list (transaction %d)",
             __func__, lbMACAddData(staAddr->ether_addr_octet),
             lbBSSInfoAddData(assocBSS), state->transaction);

        return LBD_TRUE;
    }

    // Not on candidate list - were there unresolved BSSes and is the association
    // on a remote BSS?  Give the STA the benefit of the doubt, and assume
    // this was a legitimate steer success
    if (state->numUnresolvedCandidates && !lbIsBSSLocal(assocBSS)) {
        dbgf(state->context->dbgModule, DBGDEBUG,
             "%s: STA " lbMACAddFmt(":") " associated on BSS " lbBSSInfoAddFmt()
             " that doesn't match any entry in candidate list, but there were %d"
             " unresolved BSSes, so will treat as successful steer (transaction %d)",
             __func__, lbMACAddData(staAddr->ether_addr_octet),
             lbBSSInfoAddData(assocBSS), state->numUnresolvedCandidates,
             state->transaction);

        return LBD_TRUE;
    }

    // Doesn't match any location we would expect this STA to be steered to
    // Do we now need to abort this steer?
    if (abort) {
        dbgf(state->context->dbgModule, DBGINFO,
             "%s: Requested a blacklist steer (%s) for " lbMACAddFmt(":")
             " but associated on an unexpected BSS " lbBSSInfoAddFmt()
             " due to autonomous roaming before blacklists set,"
             " aborting steer (transaction %d)",
             __func__, steerexecImplCmn_SteeringTypeString[state->steerType],
             lbMACAddData(staAddr->ether_addr_octet),
             lbBSSInfoAddData(assocBSS),
             state->transaction);

        steerexecImplCmnAbortSteerImpl(
            state->context, entry,
            state, steerexecImplCmnSteeringStatusType_unexpected_bss,
            LBD_TRUE /* isLocalAbort */);
    }
    return LBD_FALSE;
}

/**
 * @brief Received an association update message for a STA which
 *        is being steered via BTM
 *
 * @param [in] exec steering executor
 * @param [in] entry staDB entry for the STA whose association
 *                   status is updated
 * @param [in] state steering state for STA
 * @param [in] assocBSS BSS STA is associated on
 * @param [in] staAddr MAC address of STA
 *
 * @return LBD_BOOL LBD_TRUE if steering is completed
 *                  successfully, LBD_FALSE otherwise
 */
static LBD_BOOL steerexecImplCmnHandleAssocUpdateBTM(
    steerexecImplCmnHandle_t exec,
    stadbEntry_handle_t entry,
    steerexecImplCmnSteeringState_t *state,
    const lbd_bssInfo_t *assocBSS,
    const struct ether_addr *staAddr) {

    if (state->state == steerexecImplCmn_state_waiting_response) {
        // It's possible we didn't receive the BTM response for some reason, so continue, just print a warning
        dbgf(exec->dbgModule, DBGDEBUG,
             "%s: Received association update from " lbMACAddFmt(":")
             ", but no BTM response received yet (transaction %d)",
             __func__, lbMACAddData(staAddr->ether_addr_octet),
             state->transaction);
    }

    // STA has associated somewhere valid - was it where we expected?
    // Only abort the steer if we are doing a blacklist steer
    LBD_BOOL abort = steerexecImplCmnIsBlacklistSteer(state->steerType);
    if (steerexecImplCmnIsAssociationOnCandidate(state, entry, assocBSS, staAddr,
                                                 abort)) {
        // Success case
        dbgf(exec->dbgModule, DBGINFO,
             "%s: BTM steering " lbMACAddFmt(":") " is complete (transaction %d)",
             __func__, lbMACAddData(staAddr->ether_addr_octet),
             state->transaction);

        // Unregister the timeout
        evloopTimeoutUnregister(&state->btm->timer);
        state->btm->countSuccess++;

        steerexecImplCmnUpdateBTMCompliance(entry, state, staAddr,
                                            LBD_TRUE /* success */);
        return LBD_TRUE;
    } else {
        if (!abort) {
            dbgf(exec->dbgModule, DBGINFO,
                 "%s: Requested BTM steering " lbMACAddFmt(":")
                 " but associated on an unexpected BSS " lbBSSInfoAddFmt()
                 ", waiting on correct association (transaction %d)",
                 __func__, lbMACAddData(staAddr->ether_addr_octet),
                 lbBSSInfoAddData(assocBSS),
                 state->transaction);
        }

        // Don't cancel the timeout or change the state, just keep waiting

        return LBD_FALSE;
    }
}

/**
 * @brief Received an association update message for a STA which
 *        is being steered via legacy mechanics
 *
 * @param [in] exec steering executor
 * @param [in] entry staDB entry for the STA whose association
 *                   status is updated
 * @param [in] state steering state for STA
 * @param [in] assocBSS BSS STA is associated on
 * @param [in] staAddr MAC address of STA
 *
 * @return LBD_BOOL LBD_TRUE if steering is completed
 *                  successfully, LBD_FALSE otherwise
 */
static LBD_BOOL steerexecImplCmnHandleAssocUpdateLegacy(
    steerexecImplCmnHandle_t exec,
    stadbEntry_handle_t entry,
    steerexecImplCmnSteeringState_t *state,
    const lbd_bssInfo_t *assocBSS,
    const struct ether_addr *staAddr) {

    // STA has associated somewhere valid - was it where we expected?
    // If not, abort the steer, since it should not be possible to
    // associate unless blacklists are removed, or the STA associated
    // before blacklists were in place.
    if (steerexecImplCmnIsAssociationOnCandidate(state, entry, assocBSS, staAddr,
                                                 LBD_TRUE /* abort */)) {
        // Steering completed.
        state->legacy.countConsecutiveFailure = 0;

        dbgf(exec->dbgModule, DBGINFO,
             "%s: Steering " lbMACAddFmt(":") " is complete (transaction %d)",
             __func__, lbMACAddData(staAddr->ether_addr_octet),
             state->transaction);

        return LBD_TRUE;
    }

    return LBD_FALSE;
}

/**
 * @brief Received an association event for a STA which is being
 *        pre-association steered
 *
 * @param [in] exec steering executor
 * @param [in] entry staDB entry for the STA whose association
 *                   status is updated
 * @param [in] state steering state for STA
 * @param [in] assocBSS BSS STA is associated on
 *
 */
static void steerexecImplCmnHandleAssocPreAssoc(
    steerexecImplCmnHandle_t exec,
    stadbEntry_handle_t entry,
    steerexecImplCmnSteeringState_t *state,
    const lbd_bssInfo_t *assocBSS) {

    // Check there was a valid association
    wlanif_band_e assocBand = wlanif_resolveBandFromChannelNumber(assocBSS->channelId);
    if (assocBand == wlanif_band_invalid) {
        // Not associated, nothing to do
        return;
    }

    // If we had started T_Steering due to an auth reject and now the
    // STA has associated, we want to stop the timer.
    evloopTimeoutUnregister(&state->legacy.tSteerTimer);

    const struct ether_addr *staAddr = stadbEntry_getAddr(entry);
    lbDbgAssertExit(exec->dbgModule, staAddr);

    lbd_channelId_t channelList[WLANIF_MAX_RADIOS];
    u_int8_t channelCount = wlanif_getChannelList(&channelList[0],
                                                     NULL, // chwidthList
                                                     WLANIF_MAX_RADIOS);

    /* Reset probe responses in 2.4G band after steer completion */
    if (wlanif_setChannelProbeStateForSTA(
        channelCount,
        &channelList[0],
        staAddr,
        LBD_FALSE /* enable */) != LBD_OK) {

        // Failed to update the set of channels
        return;
    }

    // Special case for 5 GHz. We need to clear the blacklist immediately
    // as we want to make sure the client can associate to 2.4 GHz if
    // it wanders out of 5 GHz range (and we cannot react fast enough).
    if (assocBand == wlanif_band_5g) {
        if (steerexecImplCmnEnableAllDisabledChannels(state, staAddr) != LBD_OK) {
            return;
        }

        state->legacy.disabledChannelCount = 0;
    } else {
        // Record this entry as blacklisted on the disabled channel set,
        // and keep it for the configured time
        steerexecImplCmnMarkBlacklist(exec, state, steerexecImplCmnBlacklist_channel);
    }

    steerexecImplCmnSteerEnd(state, staAddr,
                             steerexecImplCmnSteeringStatusType_success,
                             LBD_TRUE /* isLocalAbort */, entry);
}

/**
 * @brief Set blacklist based on a candidate list at the
 *        completion of a steer
 *
 * Will delete all non-local candidates (since these are no
 * longer needed if steer is complete), and enable probe
 * responses.
 *
 * @param [in] state  steering state
 * @param [in] staAddr  MAC address of STA
 */
static void steerexecImplCmnBlacklistCandidates(
    steerexecImplCmnSteeringState_t *state,
    const struct ether_addr *staAddr) {

    // Mark as blacklisted
    steerexecImplCmnMarkBlacklist(state->context, state,
                                  steerexecImplCmnBlacklist_candidate);

    // To avoid confusing the user (if s/he happens to be looking
    // at a screen that might be affected by seeing beacons but not
    // probe responses, re-enable probe resposnes here. If the client
    // happens to try the 5 GHz band again, it will still get rejected.
    if (wlanif_setNonCandidateStateForSTA(state->candidateCount,
                                          &state->candidateList[0],
                                          staAddr,
                                          LBD_TRUE /* enable */,
                                          LBD_TRUE /* probeOnly */) != LBD_OK) {
        // This should not happen unless the blacklist entry was
        // removed out from under us, so we just log an error.
        dbgf(state->context->dbgModule, DBGERR,
             "%s: Failed to enable probe responses for "
             lbMACAddFmt(":"), __func__,
             lbMACAddData(staAddr->ether_addr_octet));
    } else {
        dbgf(state->context->dbgModule, DBGDEBUG,
             "%s: Probe responses are enabled for "
             lbMACAddFmt(":"), __func__,
             lbMACAddData(staAddr->ether_addr_octet));
    }
}

/**
 * @brief Update the blacklist when a steer completes.
 *
 * Always remove the blacklist on a 2.4GHz BSS.  Also if the STA associated on
 * a remote device, remove the 5GHz blacklist on the same channel (if any), as
 * long as it is not overloaded
 *
 * @param [in] state  steering state
 * @param [in] assocBSS  BSS the STA associated on
 * @param [in] staAddr  MAC address of STA
 */
static void steerexecImplCmnUpdateBlacklistOnSteerCompletion(
    steerexecImplCmnSteeringState_t *state,
    const lbd_bssInfo_t *assocBSS,
    const struct ether_addr *staAddr) {

    wlanif_band_e assocBand = wlanif_resolveBandFromChannelNumber(assocBSS->channelId);

    // On association, always remove any 2.4GHz blacklists, and always enable probe
    // responses on any still blacklisted 5GHz BSSes.
    // In multi-AP steering, where the STA has associated on another device on 5GHz,
    // we also remove our blacklist on that channel, as long as it is not over-loaded
    lbd_channelId_t channelToEnable = LBD_CHANNEL_INVALID;

    if (assocBand == wlanif_band_5g && !lbIsBSSLocal(assocBSS)) {
        // Associated on a remote 5GHz BSS - if we have a BSS on the same channel,
        // remove its blacklist if it's not overloaded
        LBD_BOOL isOverloaded;
        if (bandmon_isChannelOverloaded(assocBSS->channelId,
                                        &isOverloaded) != LBD_OK) {
            // Don't print an error here, since we can't determine
            // if this channel is overloaded if we don't have a BSS on that channel.
        } else if (!isOverloaded) {
            channelToEnable = assocBSS->channelId;
        } else {
            dbgf(state->context->dbgModule, DBGDEBUG,
                 "%s: Will not remove blacklist for " lbMACAddFmt(":")
                 " on channel %d because it is overloaded",
                 __func__, lbMACAddData(staAddr->ether_addr_octet),
                 assocBSS->channelId);
        }
    }

    // Reset all 2.4G candidates on the candidate list for delayed probe responses.
    if ((state->candidateCount != 0) && (state->candidateCount <= STEEREXEC_MAX_CANDIDATES)) {
        if (wlanif_setCandidateProbeStateForSTA(state->candidateCount,
                    &state->candidateList[0],
                    staAddr, LBD_FALSE /* enable */) != LBD_OK) {
            dbgf(state->context->dbgModule, DBGERR,
                    "%s: Failed to reset(probe responses) candidate(s) for "
                    lbMACAddFmt(":") ", will not steer", __func__,
                    lbMACAddData(staAddr->ether_addr_octet));
        }
    }

    // Get the set of blacklisted BSSes
    lbd_bssInfo_t blacklist[STEEREXEC_MAX_CANDIDATES];
    u_int8_t blacklistCount;
    blacklistCount = wlanif_getNonCandidateStateForSTA(
        state->candidateCount,
        &state->candidateList[0],
        STEEREXEC_MAX_CANDIDATES,
        &blacklist[0]);
    if (!blacklistCount) {
        dbgf(state->context->dbgModule, DBGDEBUG,
             "%s: No VAPs blacklisted for " lbMACAddFmt(":"),
             __func__, lbMACAddData(staAddr->ether_addr_octet));

        state->candidateCount = 0;
        return;
    }

    // Check which of these BSSes should be enabled
    int i;
    u_int8_t enableCount = 0;
    lbd_bssInfo_t enableList[STEEREXEC_MAX_CANDIDATES];
    for (i = 0; i < blacklistCount; i++) {
        if (blacklist[i].channelId == channelToEnable ||
            wlanif_resolveBandFromChannelNumber(blacklist[i].channelId) == wlanif_band_24g) {
            // This candidate should be enabled
            lbCopyBSSInfo(&blacklist[i], &enableList[enableCount]);
            enableCount++;
        }
    }

    // Enable all candidates on the enable list
    if (enableCount) {
        if (wlanif_setCandidateStateForSTA(enableCount, &enableList[0],
                                           staAddr, LBD_TRUE /* enable */) != LBD_OK) {
            dbgf(state->context->dbgModule, DBGERR,
                 "%s: Failed to enable candidate(s) for " lbMACAddFmt(":"),
                 __func__, lbMACAddData(staAddr->ether_addr_octet));
        }
    }

    if (enableCount == blacklistCount) {
        // Everything is enabled, nothing blacklisted
        state->candidateCount = 0;
        return;
    }

    // Remove all remote candidates - at this point we only need to know
    // the (local) locations where the STA can associate.  When timing
    // out the blacklist, we need to keep this limited to local BSSes, and will reduce
    // the number of candidates we need to iterate through and ignore
    // in future processing.
    // Start with the last entry and iterate backwards, to try and reduce the shifting
    // needed.
    for (i = state->candidateCount - 1; (i >= 0 && state->candidateCount); i--) {
        if (!lbIsBSSLocal(&state->candidateList[i])) {
            // Remove remote candidates
            if (i != (state->candidateCount - 1)) {

                // Not the last candidate - shift and decrease the count
                memmove(&state->candidateList[i], &state->candidateList[i+1],
                        sizeof(lbd_bssInfo_t) * (state->candidateCount - i - 1));

            }
            state->candidateCount--;
        }
    }

    // Copy everything on the enable list into the candidate list (marking the local
    // locations where the STA can associate)
    if (state->candidateCount + enableCount > STEEREXEC_MAX_CANDIDATES) {
        dbgf(state->context->dbgModule, DBGERR,
             "%s: state->candidateCount (%d) +  enableCount (%d) for " lbMACAddFmt(":")
             " should be less than STEEREXEC_MAX_CANDIDATES",
             __func__, state->candidateCount, enableCount,
             lbMACAddData(staAddr->ether_addr_octet));
        return;
    }

    memcpy(&state->candidateList[state->candidateCount], &enableList,
           sizeof(lbd_bssInfo_t) * enableCount);
    state->candidateCount+=enableCount;

    // Enable probe responses on anything not on the candidate list, and
    // start the blacklist timer
    steerexecImplCmnBlacklistCandidates(state, staAddr);
}

/**
 * @brief Clear blacklists / probe withholding for a STA steered
 *        via legacy mechanics
 *
 * @param [in] exec steering executor
 * @param [in] entry staDB entry for the STA whose association
 *                   status is updated
 * @param [in] state steering state for STA
 * @param [in] assocBSS BSS STA is associated on
 *  */
static void steerexecImplCmnAssocBlacklistClear(steerexecImplCmnHandle_t exec,
                                             stadbEntry_handle_t entry,
                                             steerexecImplCmnSteeringState_t *state,
                                             const lbd_bssInfo_t *assocBSS) {

    const struct ether_addr *staAddr = stadbEntry_getAddr(entry);
    lbDbgAssertExit(exec->dbgModule, staAddr);

    if (steerexecImplCmnIsBTMOnlySteer(state->steerType)) {
        // Pure 802.11v BTM steering, nothing to do here
        steerexecImplCmnSteerEnd(state, staAddr,
                                 steerexecImplCmnSteeringStatusType_success,
                                 LBD_TRUE /* isLocalAbort */, entry);
        state->candidateCount = 0;
        return;
    }

    evloopTimeoutUnregister(&state->legacy.tSteerTimer);

    steerexecImplCmnUpdateBlacklistOnSteerCompletion(state, assocBSS, staAddr);

    steerexecImplCmnSteerEnd(state, staAddr,
                             steerexecImplCmnSteeringStatusType_success,
                             LBD_TRUE /* isLocalAbort */, entry);
}

/**
 * @brief Change the currently in progress steer to a best
 *        effort steer (will keep the status indicating if this
 *        is an active steer or a blacklist steer the same)
 *
 * @param [in] state  steering state for STA
 * @param [in] entry  stadb entry
 * @param [in] staAddr  MAC address of STA
 * @param [in] bssid  BSSID that the STA indicated it prefers to
 *                    transition to
 */
static void steerexecImplCmnUpdateSteerTypeBE(
    steerexecImplCmnSteeringState_t *state,
    stadbEntry_handle_t entry,
    const struct ether_addr *staAddr,
    const struct ether_addr *bssid) {

    dbgf(state->context->dbgModule, DBGINFO,
         "%s: Received successful BTM response from " lbMACAddFmt(":")
         " but BSSID " lbMACAddFmt(":") " does not match any of the requested"
         " targets, steer type is %s (transaction %d)",
         __func__, lbMACAddData(staAddr->ether_addr_octet),
         lbMACAddData(bssid->ether_addr_octet),
         steerexecImplCmn_SteeringTypeString[state->steerType],
         state->transaction);

    // Increment count of the mismatch
    state->btm->countBSSIDMismatch++;

    // If this is already a BE steer - do nothing
    if (steerexecImplCmnIsBestEffortSteer(state->steerType)) {
        return;
    }

    // Determine if the current steer has a blacklist and is active
    LBD_BOOL isActive = steerexecImplCmnIsActiveSteer(state->steerType);
    LBD_BOOL isBTMOnly = steerexecImplCmnIsBTMOnlySteer(state->steerType);

    if (isActive) {
        if (isBTMOnly) {
            state->steerType = steerexecImplCmnSteeringType_btm_be_active;
        } else {
            state->steerType = steerexecImplCmnSteeringType_btm_blacklist_be_active;
        }
    } else {
        if (isBTMOnly) {
            state->steerType = steerexecImplCmnSteeringType_btm_be;
        } else {
            state->steerType = steerexecImplCmnSteeringType_btm_blacklist_be;
        }
    }

    // Notify other devices in the network (if any) of the changed steer type
    LBD_BOOL preparationComplete;
    if (steerexecImplPrepareForSteering(entry, staAddr, state->candidateCount,
                                        state->candidateList, state->steerType,
                                        state->blacklistAutoClear,
                                        state->context->config.legacy.blacklistTime,
                                        LBD_FALSE /* resetProhibitTime */,
                                        &preparationComplete,
                                        &state->msgTransaction) == LBD_NOK) {
        // No action can be taken if sending PFS fails, just print a warning
        dbgf(state->context->dbgModule, DBGERR,
             "%s: Failed to change steer type for " lbMACAddFmt(":") " to %s, "
             "may result in state mismatch across network if steer fails (transaction %d)",
             __func__, lbMACAddData(staAddr->ether_addr_octet),
             steerexecImplCmn_SteeringTypeString[state->steerType],
             state->transaction);
    } else {
        dbgf(state->context->dbgModule, DBGINFO,
             "%s: Successfully changed steer type for " lbMACAddFmt(":")
             " to %s (transaction %d)",
             __func__, lbMACAddData(staAddr->ether_addr_octet),
             steerexecImplCmn_SteeringTypeString[state->steerType],
             state->transaction);
    }
}


/**
 * @brief Check if the BTM response BSSID matches one of the
 *        target BSSes
 *
 * @param [in] state  steering state for STA
 * @param [in] entry  stadb entry
 * @param [in] staAddr  MAC address for STA
 * @param [in] bssid  BSSID from BTM response
 */
static void steerexecImplCmnHandleResponseBSSID(
    steerexecImplCmnSteeringState_t *state,
    stadbEntry_handle_t entry,
    const struct ether_addr *staAddr,
    const struct ether_addr *bssid) {

    // Check if the BSSID in the response matches any of the target BSSIDs
    // requested.
    if (wlanif_isBSSIDInList(state->candidateCount, &state->candidateList[0],
                             bssid)) {
        // Response BSSID matches one of the requested target BSSIDs
        dbgf(state->context->dbgModule, DBGINFO,
             "%s: Received successful BTM response from " lbMACAddFmt(":")
             " BSSID " lbMACAddFmt(":") " (transaction %d)",
             __func__, lbMACAddData(staAddr->ether_addr_octet),
             lbMACAddData(bssid->ether_addr_octet),
             state->transaction);
    } else {
        // Response BSSID doesn't match one of the target BSSIDs
        // Update the type of the steer to be best-effort
        steerexecImplCmnUpdateSteerTypeBE(state, entry, staAddr, bssid);
    }

    // Store the BSSID
    lbCopyMACAddr(bssid->ether_addr_octet, state->btm->bssid.ether_addr_octet);
}

/**
 * @brief Move a STA to the Wait For Association state
 *
 * @param [inout] state  steering state
 * @param [in] expiryTime  expiry time to set the timer to
 */
static void steerexecImplCmnMoveToWaitAssocState(
    steerexecImplCmnSteeringState_t *state,
    u_int32_t expiryTime) {
    state->state = steerexecImplCmn_state_waiting_association;

    if (steerexecImplCmnIsBTMSteer(state->steerType)) {
        // Start timer for association
        evloopTimeoutRegister(&state->btm->timer, expiryTime,
                              0 /* USec */);
    }
}

/**
 * @brief Fetch the stadb entry and steering state from a STA
 *        MAC address
 *
 * @param [in] addr  MAC address to find
 * @param [out] entry  filled in with the stadb entry on success
 * @param [out] state  filled in with the steerexec steering
 *                     state on success
 *
 * @return LBD_OK if both entry and state can be found, else
 *         LBD_NOK
 */
static LBD_STATUS steerexecImplCmnFetchEntryAndState(const struct ether_addr *addr,
                                                     stadbEntry_handle_t *entry,
                                                     steerexecImplCmnSteeringState_t **state) {
    *entry = stadb_find(addr);
    if (!*entry) {
        // No stadb entry for this address
        return LBD_NOK;
    }

    *state = stadbEntry_getSteeringState(*entry);
    if (!*state) {
        // No steering state
        return LBD_NOK;
    }

    // Both lookups successful
    return LBD_OK;
}

/**
 * @brief React to an event that a BTM response was received.
 *
 * @param [in] event event received
 */
static void steerexecImplCmnHandleBTMResponseEvent(struct mdEventNode *event) {
    const wlanif_btmResponseEvent_t *resp =
        (const wlanif_btmResponseEvent_t *)event->Data;

    lbDbgAssertExit(NULL, resp);

    stadbEntry_handle_t staHandle;
    steerexecImplCmnSteeringState_t *state;
    if (steerexecImplCmnFetchEntryAndState(&resp->sta_addr,
                                           &staHandle, &state) == LBD_NOK) {
        return;
    }

    // Were we expecting this response?
    if (state->state == steerexecImplCmn_state_aborted) {
        // The steer was already cancelled, so ignore this response
        evloopTimeoutUnregister(&state->btm->timer);
        state->state = steerexecImplCmn_state_idle;
        return;
    } else if (state->state != steerexecImplCmn_state_waiting_response) {
        // This is not necessarily an error - BTM response could have been received due to a
        // request sent from the console, or just very delayed
        dbgf(state->context->dbgModule, DBGINFO,
             "%s: Received unexpected BTM response from " lbMACAddFmt(":")
             " (last transaction was %d)",
             __func__, lbMACAddData(resp->sta_addr.ether_addr_octet),
             state->transaction);
        return;
    }

    // Response was expected, cancel the timeout
    evloopTimeoutUnregister(&state->btm->timer);

    // Does the dialog token match?
    if (state->btm->dialogToken != resp->dialog_token) {
        // Some devices may not update the dialog token, so don't treat this as an error,
        // just print a warning
        dbgf(state->context->dbgModule, DBGINFO,
             "%s: Received BTM response from " lbMACAddFmt(":")
             " with unexpected dialog token (%d), expected (%d)",
             __func__, lbMACAddData(resp->sta_addr.ether_addr_octet), resp->dialog_token,
             state->btm->dialogToken);
    }

    // Is the BTM response a success?
    if (resp->status != IEEE80211_WNM_BSTM_RESP_SUCCESS) {
        dbgf(state->context->dbgModule, DBGINFO,
             "%s: Received BTM response from " lbMACAddFmt(":")
             " with non-success code (%d) (transaction %d)",
             __func__, lbMACAddData(resp->sta_addr.ether_addr_octet), resp->status,
             state->transaction);
        steerexecImplCmnSteerEndBTMFailure(staHandle, state, &resp->sta_addr,
                                           steerexecImplCmnSteeringStatusType_btm_reject);
        return;
    }

    // Does the BSSID match?
    steerexecImplCmnHandleResponseBSSID(state, staHandle, &resp->sta_addr, &resp->target_bssid);

    // STA indicated it would transition, update state
    steerexecImplCmnMoveToWaitAssocState(state, state->context->config.btm.associationTime);
}

/**
 * @brief Get and check the set of channels provided from the
 *        radio are valid
 *
 * @param [in] state steering state
 * @param [out] channelCount number of channels provided from
 *                           the radio
 * @param [out] channelList list of channels provided from the
 *                          radio
 *
 * @return LBD_STATUS LBD_OK if the set of channels is valid,
 *                    LBD_NOK otherwise
 */
static LBD_STATUS steerexecImplCmnGetAndValidateRadioChannelList(
    steerexecImplCmnSteeringState_t *state,
    u_int8_t *channelCount,
    lbd_channelId_t *channelList) {

    // Get the set of active channels from wlanif
    *channelCount = wlanif_getChannelList(channelList, NULL /* chwidthList */,
                                          WLANIF_MAX_RADIOS);

    // There must be at least 2 channels enabled (one per band), and not
    // more than 3 channels (max number of radios)
    if ((*channelCount < 2) ||
        (*channelCount > WLANIF_MAX_RADIOS)) {
        dbgf(state->context->dbgModule, DBGERR,
             "%s: Invalid number of channels: %d, should be in range 2 to %d",
             __func__, *channelCount, WLANIF_MAX_RADIOS);

        return LBD_NOK;
    }

    return LBD_OK;
}

/**
 * @brief Check the set of input channels (channels to enable
 *        STA association on) are valid.  The set of input
 *        channels is fixed if possible by removing invalid
 *        channels.  If there are no valid channels, an error is
 *        returned.
 *
 * @param [in] state steering state
 * @param [in] radioChannelCount count of channels provided by
 *                               the radio
 * @param [in] radioChannelList set of channels provided by the
 *                              radio
 * @param [inout] inChannelCount count of input channels
 *                               provided by the caller
 * @param [inout] inChannelList set of input channels provided
 *                              by the caller
 *
 * @return LBD_STATUS LBD_OK if inChannelList contains any valid
 *                    channels, LBD_NOK otherwise
 */
static LBD_STATUS steerexecImplCmnValidateInChannelList(
    steerexecImplCmnSteeringState_t *state,
    u_int8_t radioChannelCount,
    const lbd_channelId_t *radioChannelList,
    u_int8_t *inChannelCount,
    lbd_channelId_t *inChannelList) {

    size_t i, j;
    u_int8_t updatedChannelCount = 0;
    lbd_channelId_t updatedChannelList[WLANIF_MAX_RADIOS];
    if (radioChannelCount >= WLANIF_MAX_RADIOS){
        return LBD_NOK;
    }
    // Check at least one channel on the input list is present on a radio.
    for (i = 0; i < *inChannelCount; i++) {
        LBD_BOOL match = LBD_FALSE;
        for (j = 0; j < radioChannelCount; j++) {
            if (inChannelList[i] == radioChannelList[j]) {
                match = LBD_TRUE;

                // Copy this to the updated list
                updatedChannelList[updatedChannelCount] = inChannelList[i];
                updatedChannelCount++;
                break;
            }
        }

        if (!match) {
            dbgf(state->context->dbgModule, DBGINFO,
             "%s: Requested pre-association steering to channel %d, "
             "but it isn't present on any radio",
             __func__, inChannelList[i]);
        }
    }

    if (!updatedChannelCount) {
        dbgf(state->context->dbgModule, DBGERR,
             "%s: No requested pre-association channels are present on any radio, will not steer",
             __func__);
        return LBD_NOK;
    }

    // Copy over the new channel set
    *inChannelCount = updatedChannelCount;
    memcpy(inChannelList, &updatedChannelList[0],
           updatedChannelCount * sizeof(lbd_channelId_t));

    return LBD_OK;
}

/**
 * @brief Check the set of currently disabled channels is
 *        consistent with the set of channels provided by the
 *        radio.
 *
 * @param [in] state steering state
 * @param [in] radioChannelCount count of channels provided by
 *                               the radio
 * @param [in] radioChannelList set of channels provided by the
 *                              radio
 *
 * @return LBD_STATUS LBD_OK if the set of disabled channels is
 *                    consistent with the set of channels
 *                    provided by the radio, LBD_NOK otherwise.
 */
static LBD_STATUS steerexecImplCmnValidateDisabledChannelList(
    steerexecImplCmnSteeringState_t *state,
    u_int8_t radioChannelCount,
    const lbd_channelId_t *radioChannelList) {

    size_t j;

    for (j = 0; j < state->legacy.disabledChannelCount; j++) {
        if (!steerexecImplCmnIsOnChannelList(radioChannelCount,
                                          &radioChannelList[0],
                                          state->legacy.disabledChannelList[j])) {
            // Not found - there must have been a channel change event since
            // this steering attempt started.
            // Reset the state - enable all channels on the updatedChannelList, and
            // disable all channels not on that list
            dbgf(state->context->dbgModule, DBGERR,
                 "%s: Pre-association steer in progress, but disabled channel %d"
                 " is no longer active, will reset steer",
                 __func__, state->legacy.disabledChannelList[j]);

            return LBD_NOK;
        }
    }

    return LBD_OK;
}

/**
 * @brief Copy all channels present in list1 and not list2 to
 *        outList
 *
 * @param [in] count1 count of channels present on list1
 * @param [in] list1 set of channels in the first list
 * @param [in] count2 count of channels present on list2
 * @param [in] list2 set of channels in the second list
 * @param [out] outList set of channels present in list1 and not
 *                      list2
 *
 * @return u_int8_t number of channels copied to outList
 */
static u_int8_t steerexecImplCmnCopyAllNotOnList(
    u_int8_t count1,
    const lbd_channelId_t *list1,
    u_int8_t count2,
    const lbd_channelId_t *list2,
     lbd_channelId_t *outList) {
    size_t i;
    u_int8_t outCount = 0;

    for (i = 0; i < count1; i++) {
        if (!steerexecImplCmnIsOnChannelList(count2, list2, list1[i])) {
            // No match, so copy
            outList[outCount] = list1[i];
            outCount++;
        }
    }

    return outCount;
}

/**
 * @brief Copy all channels present in list1 and list2 to
 *        outList
 *
 * @param [in] count1 count of channels present on list1
 * @param [in] list1 set of channels in the first list
 * @param [in] count2 count of channels present on list2
 * @param [in] list2 set of channels in the second list
 * @param [out] outList set of channels present in list1 and
 *                      list2
 *
 * @return u_int8_t number of channels copied to outList
 */
static u_int8_t steerexecImplCmnCopyAllOnList(
    u_int8_t count1,
    const lbd_channelId_t *list1,
    u_int8_t count2,
    const lbd_channelId_t *list2,
     lbd_channelId_t *outList) {
    size_t i, j;
    u_int8_t outCount = 0;

    for (i = 0; i < count1; i++) {
        for (j = 0; j < count2; j++) {
            if (list2[j] == list1[i]) {
                // Match, so copy
                outList[outCount] = list1[i];
                outCount++;

                break;
            }
        }
    }

    return outCount;
}

/**
 * @brief Reset the set of enabled and disabled channels to be
 *        consistent with the set of channels provided by the
 *        radio and the enabled channel set requested by the
 *        caller.
 *
 * @param [in] state steering state
 * @param [in] radioChannelCount count of channels provided by
 *                               the radio
 * @param [in] radioChannelList set of channels provided by the
 *                              radio
 * @param [in] updatedChannelCount count of channels provided by
 *                                 the caller
 * @param [in] updatedChannelList set of channels provided by
 *                                the caller
 * @param [out] enabledChannelCount count of channels to enable
 * @param [out] enabledChannelList set of channels to enable
 * @param [out] disabledChannelCount count of channels to
 *                                   disable
 * @param [out] disabledChannelList set of channels to disable
 */
static void steerexecImplCmnResetChannelList(
    steerexecImplCmnSteeringState_t *state,
    u_int8_t radioChannelCount,
    const lbd_channelId_t *radioChannelList,
    u_int8_t updatedChannelCount,
    const lbd_channelId_t *updatedChannelList,
    u_int8_t *enabledChannelCount,
    lbd_channelId_t *enabledChannelList,
    u_int8_t *disabledChannelCount,
    lbd_channelId_t *disabledChannelList) {

    state->legacy.disabledChannelCount = 0;

    // Enabled channels are all those on the list requested by the caller
    *enabledChannelCount = updatedChannelCount;
    memcpy(enabledChannelList, &updatedChannelList[0],
           updatedChannelCount * sizeof(lbd_channelId_t));

    // Disabled channels are all those on the radio channel list, and not on the
    // list requested by the caller
    *disabledChannelCount =
        steerexecImplCmnCopyAllNotOnList(radioChannelCount, radioChannelList,
                                      updatedChannelCount, updatedChannelList,
                                      disabledChannelList);
}

/**
 * @brief Update the blacklist state / set of disabled VAPs
 *        based upon a new post-association (candidate
 *        based) steer request. Will:
 *            - Cancel existing steer if there is one in
 *              progress
 *            - Enable any VAPs disabled by channel
 *            - Update the set of VAPs disabled / enabled by
 *              candidate
 *            - Mark the entry as not blacklisted
 *
 * @param [in] state  steering state
 * @param [in] exec  steering executor
 * @param [in] entry  stadb entry
 * @param [in] staAddr  STA MAC address
 * @param [in] steerType type of steer requested
 * @param [in] candidateCount  count of steer candidates
 * @param [in] candidateList  list of steer candidates
 * @param [out] willSteer  fill in with LBD_TRUE if a new steer
 *                         should be started, LBD_FALSE
 *                         otherwise
 *
 * @return LBD_OK on success, LBD_NOK otherwise.
 */
static LBD_STATUS steerexecImplCmnHandleSteerInProgress(
    steerexecImplCmnSteeringState_t *state,
    steerexecImplCmnHandle_t exec,
    stadbEntry_handle_t entry,
    const struct ether_addr *staAddr,
    steerexecImplCmnSteeringType_e steerType,
    u_int8_t candidateCount,
    const lbd_bssInfo_t *candidateList,
    LBD_BOOL *willSteer) {

    // If there is any steering in progress, we need to handle that specially.
    if (state->steerType != steerexecImplCmnSteeringType_none) {
        *willSteer = LBD_FALSE;
        if (steerexecImplCmnIsSameTarget(state, candidateCount, candidateList)) {
            // Nop. Already being steered to the target.
            return LBD_OK;
        } else {
            return steerexecImplCmnAbortSteerImpl(
                exec, entry, state,
                steerexecImplCmnSteeringStatusType_abort_change_target,
                LBD_TRUE /* isLocalAbort */);
        }
    }

    *willSteer = LBD_TRUE;

    return LBD_OK;
}

/**
 * @brief Update the blacklist state / set of disabled VAPs
 *        based upon a new post-association (candidate
 *        based) steer request. Will:
 *            - Cancel existing steer if there is one in
 *              progress
 *            - Enable any VAPs disabled by channel
 *            - Update the set of VAPs disabled / enabled by
 *              candidate
 *            - Mark the entry as not blacklisted
 *
 * @param [in] state  steering state
 * @param [in] exec  steering executor
 * @param [in] entry  stadb entry
 * @param [in] staAddr  STA MAC address
 * @param [in] steerType type of steer requested
 * @param [in] candidateCount  count of steer candidates
 * @param [in] candidateList  list of steer candidates
 *
 * @return LBD_OK on success, LBD_NOK otherwise.
 */
static LBD_STATUS steerexecImplCmnReconcileSteerCandidate(
    steerexecImplCmnSteeringState_t *state,
    steerexecImplCmnHandle_t exec,
    stadbEntry_handle_t entry,
    const struct ether_addr *staAddr,
    steerexecImplCmnSteeringType_e steerType,
    u_int8_t candidateCount,
    const lbd_bssInfo_t *candidateList) {

    LBD_BOOL updatedState = steerexecImplCmnCleanupSteerDifferentType(
        state, exec, entry, staAddr, steerType);
    if (!steerexecImplCmnIsBTMOnlySteer(steerType)) {
        if (updatedState) {
            // No previous blacklisted candidates - disable all VAPs that don't match
            // the candidate list
            if (wlanif_setNonCandidateStateForSTA(candidateCount, candidateList,
                                               staAddr, LBD_FALSE /* enable */,
                                               LBD_FALSE /* probeOnly */) != LBD_OK) {
                dbgf(exec->dbgModule, DBGERR,
                     "%s: Failed to update candidate based blacklists for "
                     lbMACAddFmt(":") ", will not steer", __func__,
                     lbMACAddData(staAddr->ether_addr_octet));
                return LBD_NOK;
            }
         } else {
             // Update the blacklist.
             u_int8_t enableCount, disableCount;
             lbd_bssInfo_t enableList[STEEREXEC_MAX_CANDIDATES], disableList[STEEREXEC_MAX_CANDIDATES];

             // Enable all 2.4G candidates on the list for probe responses.
             if ((candidateCount != 0) && (candidateCount <= STEEREXEC_MAX_CANDIDATES)) {
                 if (wlanif_setCandidateProbeStateForSTA(candidateCount, candidateList,
                             staAddr, LBD_TRUE /* enable */) != LBD_OK) {
                     dbgf(exec->dbgModule, DBGERR,
                             "%s: Failed to enable(probe responses) candidate(s) for "
                             lbMACAddFmt(":") ", will not steer", __func__,
                             lbMACAddData(staAddr->ether_addr_octet));
                     return LBD_NOK;
                 }
             }
             steerexecImplCmnUpdateCandidateBlacklist(state, staAddr, candidateCount, candidateList,
                                                   &enableCount, &enableList[0],
                                                   &disableCount, &disableList[0]);

             // Update the blacklists + probe response witholding in wlanif
             // There were previously blacklisted candidates - enable and disable specific VAPs

             if (enableCount) {
                 // Enable all candidates on the enable list
                 if (wlanif_setCandidateStateForSTA(enableCount, &enableList[0],
                                                    staAddr, LBD_TRUE /* enable */) != LBD_OK) {
                     dbgf(exec->dbgModule, DBGERR,
                          "%s: Failed to enable candidate(s) for "
                          lbMACAddFmt(":") ", will not steer", __func__,
                          lbMACAddData(staAddr->ether_addr_octet));
                     return LBD_NOK;
                 }
             }

             if (disableCount) {
                 // Disable all candidates on the disable list
                 if (wlanif_setCandidateStateForSTA(disableCount, &disableList[0],
                                                    staAddr, LBD_FALSE /* enable */) != LBD_OK) {
                     dbgf(exec->dbgModule, DBGERR,
                          "%s: Failed to disable candidate(s) for "
                          lbMACAddFmt(":") ", will not steer", __func__,
                          lbMACAddData(staAddr->ether_addr_octet));
                     return LBD_NOK;
                 }
             }
         }
    }

    // No longer blacklisted
    steerexecImplCmnMarkAsNotBlacklisted(state);

    return LBD_OK;
}


/**
 * @brief Update the blacklist state / set of disabled VAPs
 *        based upon a new pre-association (channel based)
 *        steer request. Will:
 *            - Cancel a post-association steer if there is one
 *              in progress
 *            - Enable any VAPs disabled by candidate
 *            - Update the set of VAPs disabled / enabled by
 *              channel
 *            - Mark the entry as not blacklisted
 *
 * @param [in] state  steering state
 * @param [in] exec  steering executor
 * @param [in] entry  stadb entry
 * @param [in] staAddr  STA MAC address
 * @param [in] steerType type of steer requested
 * @param [in] channelCount  count of channels
 * @param [in] channelList  list of channels
 * @param [out] willSteer  fill in with LBD_TRUE if a new steer
 *                         should be started, LBD_FALSE
 *                         otherwise
 *
 * @return LBD_OK on success, LBD_NOK otherwise.
 */
static LBD_STATUS steerexecImplCmnReconcileSteerChannel(
    steerexecImplCmnSteeringState_t *state,
    steerexecImplCmnHandle_t exec,
    stadbEntry_handle_t entry,
    const struct ether_addr *staAddr,
    steerexecImplCmnSteeringType_e steerType,
    u_int8_t channelCount,
    const lbd_channelId_t *channelList,
    LBD_BOOL *willSteer) {

    *willSteer = LBD_FALSE;
    LBD_BOOL cleanupComplete = LBD_FALSE;

    if (state->steerType != steerexecImplCmnSteeringType_none) {
        // There is a steer in progress - is it a pre-association steer?
        if (state->steerType == steerexecImplCmnSteeringType_preassociation) {
            // Same type - will need to update the blacklist state.
            cleanupComplete = LBD_FALSE;
        } else {
            // The new steer is of a different type, abort the previous steer.
            steerexecImplCmnAbortSteerImpl(exec, entry, state,
                                           steerexecImplCmnSteeringStatusType_abort_change_target,
                                           LBD_TRUE /* isLocalAbort */);

            // Fresh state for steering.
            cleanupComplete =  LBD_TRUE;
        }
    } else {
        // Do cleanup if there is no steer in progress
        cleanupComplete = steerexecImplCmnCleanupSteerDifferentType(
            state, exec, entry, staAddr,
            steerexecImplCmnSteeringType_preassociation);
    }

    // Check if set of enabled channels has changed
    u_int8_t countEnable, countDisable;
    lbd_channelId_t listEnable[WLANIF_MAX_RADIOS], listDisable[WLANIF_MAX_RADIOS];

    if (steerexecImplCmnChannelDelta(state, channelCount, channelList,
                                  &countEnable, &listEnable[0],
                                  &countDisable, &listDisable[0]) == LBD_NOK) {
        // Error occurred.
        return LBD_NOK;
    } else if (!countEnable && !countDisable) {
        // Nothing to do, set of channels has not changed
        return LBD_OK;
    }

    if (!cleanupComplete) {
        dbgf(exec->dbgModule, DBGINFO,
             "%s: Pre-association steer for " lbMACAddFmt(":")
             " aborted due to changed channel set (transaction %d)",
             __func__,
             lbMACAddData(staAddr->ether_addr_octet),
             state->transaction);
    }

    /* Allow probe responses in 2.4G band before starting steering */
    if (wlanif_setChannelProbeStateForSTA(
        channelCount,
        channelList,
        staAddr,
        LBD_TRUE /* enable */) != LBD_OK) {

        // Failed to update the set of enabled channels
        return LBD_NOK;
    }

    if (countEnable) {
        if(countEnable > WLANIF_MAX_RADIOS){
            return LBD_NOK;
        }
        // Change set of enabled channels via wlanif
        if (wlanif_setChannelStateForSTA(
            countEnable,
            &listEnable[0],
            staAddr,
            LBD_TRUE /* enable */) != LBD_OK) {

            // Failed to update the set of enabled channels
            return LBD_NOK;
        }
    }

    if (countDisable) {
        if(countDisable > WLANIF_MAX_RADIOS){
            return LBD_NOK;
        }
        // Change set of disabled channels via wlanif
        if (wlanif_setChannelStateForSTA(
            countDisable,
            &listDisable[0],
            staAddr,
            LBD_FALSE /* enable */) != LBD_OK) {

            // Failed to update the set of disabled channels
            return LBD_NOK;
        }
    }

    // Set of enabled channels changed, update storage
    steerexecImplCmnUpdateChannelSet(state,
                                  countEnable, &listEnable[0],
                                  countDisable, &listDisable[0]);

    *willSteer = LBD_TRUE;
    return LBD_OK;
}

/**
 * @brief Helper function to determine if the entire blacklist
 *        should be removed (as opposed to selective update)
 *
 * @param [in] state steering state
 * @param [in] steerType steer type
 *
 * @return LBD_TRUE if the entire blacklist should be removed,
 *         LBD_FALSE otherwise
 */
static LBD_BOOL steerexecImplCmnShouldRemoveBlacklist(
    steerexecImplCmnSteeringState_t *state,
    steerexecImplCmnSteeringType_e steerType) {

    if (steerexecImplCmnIsBTMOnlySteer(steerType)) {
        // Starting a BTM steer, and there was any kind of blacklist
        return LBD_TRUE;
    } else if ((state->blacklistType == steerexecImplCmnBlacklist_candidate) &&
               (steerType == steerexecImplCmnSteeringType_preassociation)) {
        // Had a candidate blacklist, and starting a channel steer
        return LBD_TRUE;
    } else if ((state->blacklistType == steerexecImplCmnBlacklist_channel) &&
               (steerType != steerexecImplCmnSteeringType_preassociation)) {
        // Had a channel blacklist, and starting a candidate steer
        return LBD_TRUE;
    }

    return LBD_FALSE;
}

/**
 * @brief Cleanup old state when starting a new steer of a
 *        different type.
 *
 * @param [in] state  steering state
 * @param [in] exec  steering executor
 * @param [in] entry  stadb entry
 * @param [in] staAddr  STA MAC address
 * @param [in] steerType type of steer requested
 *
 * @return LBD_TRUE if all cleanup could be done here (due to
 *         the steer type changing), LBD_FALSE if the steer type
 *         has not changed, meaning cleanup could not be done
 *         here.
 */
static LBD_BOOL steerexecImplCmnCleanupSteerDifferentType(
    steerexecImplCmnSteeringState_t *state,
    steerexecImplCmnHandle_t exec,
    stadbEntry_handle_t entry,
    const struct ether_addr *staAddr,
    steerexecImplCmnSteeringType_e steerType) {

    if (state->blacklistType == steerexecImplCmnBlacklist_none) {
        // No blacklist, fresh state.
        return LBD_TRUE;
    }
    // No steer in progress - is there a blacklist of the opposite type
    // still around?
    if (steerexecImplCmnShouldRemoveBlacklist(state, steerType)) {
        // Blacklist type doesn't match current steer.
        // Re-enable everything that is disabled
        steerexecImplCmnRemoveAllBlacklists(state, staAddr);
        return LBD_TRUE;
    }

    // There is already a blacklist of the same type as the new steer,
    // will need to selectively update the blacklist state.
    return LBD_FALSE;
}

/**
 * @brief Check the set of requested channels for validity, and
 *        get the set of channels to enable and disable.
 *
 * @pre Set of input channels should contain unique channelIds
 *      (ie. no repeating channels)
 * @pre All channel sets are non-NULL
 *
 * @param [in] state steering state
 * @param [in] channelCount count of channels requested by
 *                          caller
 * @param [in] channelList set of channels requested by caller
 * @param [out] enabledChannelCount count of channels to enable
 * @param [out] enabledChannelList set of channels to enable
 * @param [out] disabledChannelCount count of channels to
 *                                   disable
 * @param [out] disabledChannelList set of channels to disable
 *
 * @return LBD_STATUS LBD_OK if the channels are valid, LBD_NOK
 *                    otherwise
 */
static LBD_STATUS steerexecImplCmnChannelDelta(
    steerexecImplCmnSteeringState_t *state,
    u_int8_t channelCount,
    const lbd_channelId_t *channelList,
    u_int8_t *enabledChannelCount,
    lbd_channelId_t *enabledChannelList,
    u_int8_t *disabledChannelCount,
    lbd_channelId_t *disabledChannelList) {

    size_t i, j;

    *enabledChannelCount = 0;
    *disabledChannelCount = 0;

    u_int8_t wlanifChannelCount;
    lbd_channelId_t wlanifChannelList[WLANIF_MAX_RADIOS];

    if (channelCount >= WLANIF_MAX_RADIOS) {
       return LBD_NOK;
    }
    // Get the set of channels from the radio
    if (steerexecImplCmnGetAndValidateRadioChannelList(state, &wlanifChannelCount,
                                                    &wlanifChannelList[0]) != LBD_OK) {
        return LBD_NOK;
    }

    // Validate the input set of channels
    u_int8_t updatedChannelCount = channelCount;
    lbd_channelId_t updatedChannelList[WLANIF_MAX_RADIOS];
    memcpy(&updatedChannelList[0], channelList,
           channelCount * sizeof(lbd_channelId_t));

    if (steerexecImplCmnValidateInChannelList(state,
                                           wlanifChannelCount,
                                           &wlanifChannelList[0],
                                           &updatedChannelCount,
                                           &updatedChannelList[0]) != LBD_OK) {
        return LBD_NOK;
    }

    // Make sure all the currently disabled channels match ones on the wlanif list
    // Note: We don't track the enabled channels, if an enabled channel has changed, we don't care
    if (steerexecImplCmnValidateDisabledChannelList(state, wlanifChannelCount,
                                                 &wlanifChannelList[0]) != LBD_OK) {
        // If the disabled channel list is no longer valid, we will still attempt to steer
        // This steer will bring the channel set back in sync with what is reported from wlanif
        steerexecImplCmnResetChannelList(state,
                                      wlanifChannelCount,
                                      &wlanifChannelList[0],
                                      updatedChannelCount,
                                      &updatedChannelList[0],
                                      enabledChannelCount,
                                      enabledChannelList,
                                      disabledChannelCount,
                                      disabledChannelList);
        return LBD_OK;
    }

    // No channel state has changed, continue

    // Get the set of disabled channels
    // The disabled list will be all channels in the wlanif list that aren't in
    // the updated list or the disable list.
    for (i = 0; i < wlanifChannelCount; i++) {
        LBD_BOOL match = LBD_FALSE;
        for (j = 0; j < updatedChannelCount; j++) {
            if (updatedChannelList[j] == wlanifChannelList[i]) {
                match = LBD_TRUE;

                break;
            }
        }

        if (!match) {
            // Channel to disable - check if it's already disabled
            for (j = 0; j < state->legacy.disabledChannelCount; j++) {
                if (wlanifChannelList[i] == state->legacy.disabledChannelList[j]) {
                    // already disabled, nothing to do
                    match = LBD_TRUE;
                    break;
                }
            }

            if (!match) {
                // Not present on disabled, list, add it
                disabledChannelList[*disabledChannelCount] = wlanifChannelList[i];
                (*disabledChannelCount)++;
            }
        }
    }

    // Get the set of enabled channels
    // The enabled list will be all channels in the updated list that are currently disabled.
    *enabledChannelCount =
        steerexecImplCmnCopyAllOnList(updatedChannelCount, &updatedChannelList[0],
                                   state->legacy.disabledChannelCount,
                                   &state->legacy.disabledChannelList[0],
                                   enabledChannelList);
    return LBD_OK;
}

/**
 * @brief Update the set of disabled channels to store with the
 *        STA
 *
 * @param [in] state steering state
 * @param [in] enabledChannelCount count of channels enabled
 * @param [in] enabledChannelList set of channels enabled
 * @param [in] disabledChannelCount count of channels disabled
 * @param [in] disabledChannelList set of channels disabled
 */
static void steerexecImplCmnUpdateChannelSet(
    steerexecImplCmnSteeringState_t *state,
    u_int8_t enabledChannelCount,
    const lbd_channelId_t *enabledChannelList,
    u_int8_t disabledChannelCount,
    const lbd_channelId_t *disabledChannelList) {

    // Copy over disabled channels
    lbd_channelId_t temp[WLANIF_MAX_RADIOS-1];
    // Still disabled channels are all those on the old disabled channel list, and not on the
    // new enabled list
    u_int8_t countDisabled =
        steerexecImplCmnCopyAllNotOnList(state->legacy.disabledChannelCount,
                                      &state->legacy.disabledChannelList[0],
                                      enabledChannelCount,
                                      &enabledChannelList[0],
                                      &temp[0]);

    // Copy over the still disabled channels
    memcpy(&state->legacy.disabledChannelList, &temp,
           countDisabled * sizeof(lbd_channelId_t));

    // Copy over the newly disabled channels
    memcpy(&state->legacy.disabledChannelList[countDisabled], disabledChannelList,
           disabledChannelCount * sizeof(lbd_channelId_t));
    state->legacy.disabledChannelCount = countDisabled + disabledChannelCount;

    // Mark this entry as no longer blacklisted.
    steerexecImplCmnMarkAsNotBlacklisted(state);
}

/**
 * @brief Callback function used to cancel active steering of a client, and
 *        clear blacklist if any
 *
 * @see stadb_iterFunc_t
 */
static void steerexecImplCmnHandleChanChangeCB(stadbEntry_handle_t entry,
                                               void *cookie) {
    struct steerexecImplCmnPriv_t *exec =
        (struct steerexecImplCmnPriv_t *) cookie;
    lbDbgAssertExit(NULL, exec);

    steerexecImplCmnAbort(exec, entry,
                          steerexecImplCmnSteeringStatusType_channel_change,
                          NULL /* ignored */);
}

/**
 * @brief Callback function invoked by wlanif when channel change happens
 *
 * It will cancel any ongoing steering and clear blacklist if any
 *
 * @see wlanif_chanChangeObserverCB
 */
static void steerexecImplCmnChanChangeObserver(lbd_vapHandle_t vap,
                                            lbd_channelId_t channelId,
                                            void *cookie) {
    struct steerexecImplCmnPriv_t *exec =
        (struct steerexecImplCmnPriv_t *) cookie;
    lbDbgAssertExit(NULL, exec);

    if (LBD_NOK == stadb_iterate(steerexecImplCmnHandleChanChangeCB, exec)) {
        dbgf(exec->dbgModule, DBGERR,
             "%s: Failed to iterate station database for aborting steering",
             __func__);
    }
}

/**
 * @brief Limit a u_int32_t value to a u_int8_t
 *
 * @param [in] val  value to limit
 *
 * @return Value capped to a maximum value of 255
 */
static u_int8_t steerexecImplCmnLimitToUint8(u_int32_t val) {
    if (val > UCHAR_MAX) {
        return UCHAR_MAX;
    }

    return (u_int8_t)val;
}

#ifdef GMOCK_UNIT_TESTS
LBD_BOOL steerexecImplCmnIsSTASteeringUnfriendly(stadbEntry_handle_t entry) {
    steerexecImplCmnSteeringState_t *state = stadbEntry_getSteeringState(entry);
    if (!state) {
        return LBD_FALSE;
    }

    return state->legacy.steeringUnfriendly;
}
#endif

#ifdef LBD_DBG_MENU

void steerexecImplCmnDumpLegacyHeader(struct cmdContext *context,
                                   steerexecImplCmnHandle_t exec) {
    struct timespec ts;
    lbGetTimestamp(&ts);

    cmdf(context, "Legacy overall state:\n");
    cmdf(context, "  Current # STAs prohibited from steering: %u\n",
         exec->prohibitTimer.countEntries);

    if (exec->prohibitTimer.countEntries > 0) {
        cmdf(context, "    Next prohibit update: %u seconds\n",
             exec->prohibitTimer.nextExpiry - ts.tv_sec);
    }

    cmdf(context, "  Current # STAs marked as steering unfriendly: %u\n",
         exec->legacy.steeringUnfriendly.countEntries);

    if (exec->legacy.steeringUnfriendly.countEntries &&
        exec->config.legacy.steeringUnfriendlyTime > 0) {
        cmdf(context, "    Next unfriendly update: %u seconds\n",
             exec->legacy.steeringUnfriendly.nextExpiry - ts.tv_sec);
    }

    cmdf(context, "  Current # STAs blacklisted: %u\n",
         exec->legacy.blacklistTimer.countEntries);

    if (exec->legacy.blacklistTimer.countEntries > 0 && exec->config.legacy.blacklistTime > 0) {
        cmdf(context, "    Next blacklist update: %u seconds\n",
             exec->legacy.blacklistTimer.nextExpiry - ts.tv_sec);
    }

    cmdf(context, "\nLegacy per STA information:\n");
    cmdf(context, "%-18s%-12s%-17s%-10s%-11s%-11s%-11s%-8s%-10s%-21s\n",
         "MAC", "Transaction", "Secs since steer", "State", "# Auth Rej",
         "Prohibited", "Unfriendly", "T_Steer", "Blacklist", "Consecutive Failures");
}

void steerexecImplCmnDumpBTMHeader(struct cmdContext *context,
                                steerexecImplCmnHandle_t exec) {
    struct timespec ts;
    lbGetTimestamp(&ts);

    cmdf(context, "BTM overall state:\n");
    cmdf(context, "  If no state is set, BTM clients can %s\n",
         exec->config.btm.startInBTMActiveState ? "be steered while Active" :
         "only be steered while Idle");

    cmdf(context, "  Current # STAs marked as BTM unfriendly: %u\n",
         exec->btm.unfriendlyTimer.countEntries);

    if (exec->btm.unfriendlyTimer.countEntries > 0) {
        cmdf(context, "    Next BTM unfriendly update: %u seconds\n",
             exec->btm.unfriendlyTimer.nextExpiry - ts.tv_sec);
    }

    cmdf(context, "  Current # STAs marked as BTM active unfriendly: %u\n",
         exec->btm.activeUnfriendlyTimer.countEntries);

    if (exec->btm.activeUnfriendlyTimer.countEntries > 0) {
        cmdf(context, "    Next BTM active unfriendly update: %u seconds\n",
             exec->btm.activeUnfriendlyTimer.nextExpiry - ts.tv_sec);
    }

    cmdf(context, "\n802.11v BTM Compliant per STA information:\n");
    cmdf(context, "%-18s%-12s%-16s%-17s%-11s%-17s%-12s%-6s%-15s\n",
         "MAC", "Transaction", "Secs since steer", "(active failure)",
         "Unfriendly", "Compliance", "Eligibility",
         "Token", "Timer");
}

void steerexecImplCmnDumpBTMStatisticsHeader(struct cmdContext *context,
                                          steerexecImplCmnHandle_t exec) {
    cmdf(context, "\n802.11v BTM Compliant per STA statistics:\n");
    cmdf(context, "%-18s%-7s%-7s%-8s%-8s%-21s%-9s%-14s\n",
         "MAC", "NoResp", "Reject", "NoAssoc", "Success", "Consecutive Failures",
         "(active)", "BSSIDMismatch");
}

static void steerexecImplCmnDumpBTMEntryState(struct cmdContext *context,
                                           stadbEntry_handle_t entry,
                                           steerexecImplCmnSteeringState_t *state) {
    const struct ether_addr *staAddr = stadbEntry_getAddr(entry);
    lbDbgAssertExit(state->context->dbgModule, staAddr);

    cmdf(context, lbMACAddFmt(":") " ",
         lbMACAddData(staAddr->ether_addr_octet));

    cmdf(context, "%-12d", state->transaction);

    struct timespec ts;
    lbGetTimestamp(&ts);
    cmdf(context, "%-16d(%-14d) ",
         state->btm->unfriendlyExpiryTime > ts.tv_sec ?
         state->btm->unfriendlyExpiryTime - ts.tv_sec : 0,
         state->btm->activeUnfriendlyExpiryTime > ts.tv_sec ?
         state->btm->activeUnfriendlyExpiryTime - ts.tv_sec : 0);

    cmdf(context, "%-11s", state->btm->btmUnfriendly ? "yes" : "no");

    cmdf(context, "%-17s",
         state->btm->complianceState <= steerexecImplCmn_btmComplianceState_invalid ?
         steerexecImplCmn_btmComplianceString[state->btm->complianceState] :
         steerexecImplCmn_btmComplianceString[steerexecImplCmn_btmComplianceState_invalid]);

    steerexec_steerEligibility_e eligibility =
        steerexecImplCmnDetermineSteeringEligibility(
            state->context, entry,
            LBD_FALSE /* reportReasonNotEligible */);
    cmdf(context, "%-12s",
         steerexec_SteerEligibilityString[eligibility]);

    cmdf(context, "%-6d", state->btm->dialogToken);

    unsigned timeoutRemaining;
    if (evloopTimeoutRemaining(&state->btm->timer, &timeoutRemaining,
                               NULL) == 0) {
        cmdf(context, "%-15u", timeoutRemaining);
    } else {
        cmdf(context, "%-15c", ' ');
    }

    cmdf(context, "\n");
}

static void steerexecImplCmnDumpBTMEntryStatistics(
    struct cmdContext *context,
    stadbEntry_handle_t entry,
    steerexecImplCmnSteeringState_t *state) {
    const struct ether_addr *staAddr = stadbEntry_getAddr(entry);
    lbDbgAssertExit(state->context->dbgModule, staAddr);

    cmdf(context, lbMACAddFmt(":") " ",
         lbMACAddData(staAddr->ether_addr_octet));

    cmdf(context, "%-7d", state->btm->countNoResponseFailure);
    cmdf(context, "%-7d", state->btm->countRejectFailure);
    cmdf(context, "%-8d", state->btm->countAssociationFailure);
    cmdf(context, "%-8d", state->btm->countSuccess);
    cmdf(context, "%-21d", state->btm->countConsecutiveFailure);
    cmdf(context, "(%-6d) ", state->btm->countConsecutiveFailureActive);
    cmdf(context, "%-14d", state->btm->countBSSIDMismatch);

    cmdf(context, "\n");
}

static void steerexecImplCmnDumpLegacyEntryState(struct cmdContext *context,
                                              stadbEntry_handle_t entry,
                                              steerexecImplCmnSteeringState_t *state) {
    const struct ether_addr *staAddr = stadbEntry_getAddr(entry);
    lbDbgAssertExit(state->context->dbgModule, staAddr);

    cmdf(context, lbMACAddFmt(":") " ",
         lbMACAddData(staAddr->ether_addr_octet));

    cmdf(context, "%-12d", state->transaction);

    struct timespec ts;
    lbGetTimestamp(&ts);
    cmdf(context, "%-17d", ts.tv_sec - state->legacy.lastSteeringTime);

    cmdf(context, "%-10s", state->state <= steerexecImplCmn_state_invalid ?
         steerexecImplCmn_stateString[state->state] :
         steerexecImplCmn_stateString[steerexecImplCmn_state_invalid]);

    cmdf(context, "%-11u", state->legacy.numAuthRejects);

    cmdf(context, "%-11s%-11s",
         (state->steeringProhibited <= steerexecImplCmnSteeringProhibitType_invalid ?
          steerexecImplCmn_SteeringProhibitTypeString[state->steeringProhibited] :
          steerexecImplCmn_SteeringProhibitTypeString[steerexecImplCmnSteeringProhibitType_invalid]),
         state->legacy.steeringUnfriendly ? "yes" : "no");

    unsigned tSteeringRemaining;
    if (evloopTimeoutRemaining(&state->legacy.tSteerTimer, &tSteeringRemaining,
                               NULL) == 0) {
        cmdf(context, "%-8u", tSteeringRemaining);
    } else {
        cmdf(context, "%-8c", ' ');
    }

    cmdf(context, "%-10s", state->blacklistType <= steerexecImplCmnBlacklist_invalid ?
         steerexecImplCmn_SteeringBlacklistTypeString[state->blacklistType] :
         steerexecImplCmn_SteeringBlacklistTypeString[steerexecImplCmnBlacklist_invalid]);

    cmdf(context, "%-21d", state->legacy.countConsecutiveFailure);

    cmdf(context, "\n");
}

void steerexecImplCmnDumpEntryState(struct cmdContext *context,
                                 steerexecImplCmnHandle_t exec,
                                 stadbEntry_handle_t entry,
                                 LBD_BOOL inProgressOnly,
                                 LBD_BOOL dumpBTMClients,
                                 LBD_BOOL dumpStatistics) {
    steerexecImplCmnSteeringState_t *state = stadbEntry_getSteeringState(entry);
    if (state &&
        (!inProgressOnly || state->steerType != steerexecImplCmnSteeringType_none)) {

        if (dumpBTMClients && stadbEntry_isBTMSupported(entry)) {
            if (dumpStatistics) {
                steerexecImplCmnDumpBTMEntryStatistics(context, entry, state);
            } else {
                steerexecImplCmnDumpBTMEntryState(context, entry, state);
            }
        } else if (!dumpBTMClients) {
            // Need to dump legacy status for BTM clients as well since these
            // can be steered via legacy if they fail BTM transitions
            steerexecImplCmnDumpLegacyEntryState(context, entry, state);
        }
    }
}

void steerexecImplCmnGenerateDiaglog(steerexecImplCmnHandle_t exec,
                                     stadbEntry_handle_t entry, LBD_BOOL prohibit,
                                     LBD_BOOL unfriendly, LBD_BOOL compliance) {
    if (!exec || !entry) { return; }

    steerexecImplCmnSteeringState_t *state = stadbEntry_getSteeringState(entry);
    if (!state) { return; }

    const struct ether_addr *staAddr = stadbEntry_getAddr(entry);
    lbDbgAssertExit(exec->dbgModule, staAddr);

    if (prohibit) {
        steerexecImplCmnDiagLogSteeringProhibited(staAddr, state->steeringProhibited);
    }

    if (unfriendly) {
        steerexecImplCmnDiagLogSteeringUnfriendly(
                staAddr, state->legacy.steeringUnfriendly,
                state->legacy.countConsecutiveFailure);
    }

    if (compliance && state->btm) {
        steerexecImplCmnDiagLogBTMCompliance(
                staAddr, state->btm->btmUnfriendly, state->btm->complianceState,
                state->btm->countConsecutiveFailure,
                state->btm->countConsecutiveFailureActive);
    }
}

/**
 * @brief Compute the difference between monotonic and realtime clocks
 *
 * @return the number of seconds of difference
 */
static time_t steerexecTimeDelta(void) {
    struct timespec mono = {0};
    struct timespec real = {0};
    time_t delta = 0;
    int res1, res2;

    res1 = clock_gettime(CLOCK_MONOTONIC, &mono);
    res2 = clock_gettime(CLOCK_REALTIME, &real);
    if (!res1 && !res2) {
        /* We assume that the difference between realtime and monotonic stays
         * constant.  This is true if the realtime clock has not been changed
         * between the timestamp and now.  If it has been changed, we cannot
         * compute the realtime from monotonic and vice versa. */
        delta = real.tv_sec - mono.tv_sec;
    }

    return delta;
}

/**
 * @brief convert a relative timestamp to absolute timestamp
 *
 * @param [in] time relative timestamp
 * @return absolute timestamp
 */
static time_t steerexecToAbsoluteTime(time_t time) {
    return time + steerexecTimeDelta();
}

/**
 * @brief convert an absolute timestamp to relative timestamp
 *
 * @param [in] time absolute timestamp
 * @return relative timestamp
 */
static time_t steerexecToRelativeTime(time_t time) {
    return time - steerexecTimeDelta();
}

static json_t *
steerexecImplCmnBtmJsonize(steerexecImplCmnHandle_t exec,
                           steerexecImplCmnSteeringState_t *state) {
    json_t *btm_j;

    if (state->btm == NULL) {
        /* btm is optional */
        return json_null();
    }

    btm_j = json_pack(
        "{s:i, s:i, s:i, s:i, s:i}",
        "unfriendlyExpiryTime",
            steerexecToAbsoluteTime(state->btm->unfriendlyExpiryTime),
        "activeUnfriendlyTimer",
            steerexecToAbsoluteTime(state->btm->activeUnfriendlyExpiryTime),
        "complianceState", state->btm->complianceState,
        "countConsecutiveFailureActive",
            state->btm->countConsecutiveFailureActive,
        "countConsecutiveFailure",
            state->btm->countConsecutiveFailure);

    return btm_j;
}

json_t *steerexecImplCmnJsonize(steerexecImplCmnHandle_t exec,
                                stadbEntry_handle_t entry) {
    steerexecImplCmnSteeringState_t *state;
    json_t *ret, *btm_j;

    if (!exec || !entry) {
        return NULL;
    }

    state = stadbEntry_getSteeringState(entry);
    if (state == NULL) {
        return NULL;
    }

    btm_j = steerexecImplCmnBtmJsonize(exec, state);
    if (btm_j == NULL) {
        dbgf(exec->dbgModule, DBGERR, "%s: Failed to jsonize btm.", __func__);
        return NULL;
    }

    ret = json_pack(
            "{s:i, s:{"
            "s:i, s:i, s:i, s:b, s:i, s:i"
            "}, s:o}",
            "steeringProhibited", state->steeringProhibited,
            "legacy",
                "lastSteeringTime",
                    steerexecToAbsoluteTime(state->legacy.lastSteeringTime),
                "prohibitExpiryTime",
                    steerexecToAbsoluteTime(state->legacy.prohibitExpiryTime),
                "numAuthRejects",
                    state->legacy.numAuthRejects,
                "steeringUnfriendly", state->legacy.steeringUnfriendly,
                "unfriendlyExpiryTime",
                    steerexecToAbsoluteTime(state->legacy.unfriendlyExpiryTime),
                "countConsecutiveFailure",
                    state->legacy.countConsecutiveFailure,
                "btm", btm_j);

    if (ret == NULL) {
        dbgf(exec->dbgModule, DBGERR, "%s: Failed to jsonize steerExec state.",
             __func__);
        json_decref(btm_j);
        return NULL;
    }

    if (json_is_null(btm_j)) {
        json_object_del(ret, "btm");
    }

    return ret;
}

static void steerexecImplCmnRestoreBtm(steerexecImplCmnHandle_t exec,
                                       steerexecImplCmnSteeringState_t *state,
                                       json_t *btm_j) {
    int res;

    if (state->btm == NULL) {
        /* Should have been set up if BTM is supported */
        return;
    }

    res = json_unpack(btm_j,
        "{s?:i, s?:i, s?:i, s?:i, s?:i}",
        "unfriendlyExpiryTime",
            &(state->btm->unfriendlyExpiryTime),
        "activeUnfriendlyTimer",
            &(state->btm->activeUnfriendlyExpiryTime),
        "complianceState", &(state->btm->complianceState),
        "countConsecutiveFailureActive",
            &(state->btm->countConsecutiveFailureActive),
        "countConsecutiveFailure",
            &(state->btm->countConsecutiveFailure));

    if (res) {
        dbgf(exec->dbgModule, DBGERR, "%s: Failed to restore btm state.",
             __func__);
        return;
    }

    /* Fixup time values if present */
    if (json_object_get(btm_j, "unfriendlyExpiryTime") != NULL) {
        state->btm->unfriendlyExpiryTime =
            steerexecToRelativeTime(state->btm->unfriendlyExpiryTime);
    }
    if (json_object_get(btm_j, "activeUnfriendlyExpiryTime") != NULL) {
        state->btm->activeUnfriendlyExpiryTime =
            steerexecToRelativeTime(state->btm->activeUnfriendlyExpiryTime);
    }
}

void steerexecImplCmnRestore(steerexecImplCmnHandle_t exec,
                             stadbEntry_handle_t entry, json_t *json) {
    int res;
    json_t *btm_j, *legacy_j;

    steerexecImplCmnSteeringState_t *state =
        steerexecImplCmnGetOrCreateSteeringState(exec, entry);

    if (state == NULL) {
        dbgf(exec->dbgModule, DBGERR, "%s: Failed to alloc steerExec state.",
             __func__);
        return;
    }

    res = json_unpack(json,
            "{s?:i, s?:{"
            "s?:i, s?:i, s?:i, s?:b, s?:i, s?:i"
            "}}",
            "steeringProhibited", &(state->steeringProhibited),
            "legacy",
                "lastSteeringTime", &(state->legacy.lastSteeringTime),
                "prohibitExpiryTime", &(state->legacy.prohibitExpiryTime),
                "numAuthRejects", &(state->legacy.numAuthRejects),
                "steeringUnfriendly", &(state->legacy.steeringUnfriendly),
                "unfriendlyExpiryTime", &(state->legacy.unfriendlyExpiryTime),
                "countConsecutiveFailure",
                                    &(state->legacy.countConsecutiveFailure)
                );

    if (res != 0) {
        dbgf(exec->dbgModule, DBGERR, "Failed to restore steerExec");
        return;
    }

    /* Fixup time values if present */
    if ((legacy_j = json_object_get(json, "legacy")) != NULL) {
        if (json_object_get(legacy_j, "lastSteeringTime") != NULL) {
            state->legacy.lastSteeringTime =
                steerexecToRelativeTime(state->legacy.lastSteeringTime);
        }
        if (json_object_get(legacy_j, "prohibitExpiryTime") != NULL) {
            state->legacy.prohibitExpiryTime =
                steerexecToRelativeTime(state->legacy.prohibitExpiryTime);
        }
        if (json_object_get(legacy_j, "unfriendlyExpiryTime") != NULL) {
            state->legacy.unfriendlyExpiryTime =
                steerexecToRelativeTime(state->legacy.unfriendlyExpiryTime);
        }
    }

    btm_j = json_object_get(json, "btm");
    if (btm_j != NULL) {
        steerexecImplCmnRestoreBtm(exec, state, btm_j);
    }
}
#endif /* LBD_DBG_MENU */
