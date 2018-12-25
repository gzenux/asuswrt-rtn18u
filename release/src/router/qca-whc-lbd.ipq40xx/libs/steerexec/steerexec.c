// vim: set et sw=4 sts=4 cindent:
/*
 * @File: steerexec.c
 *
 * @Abstract: Top-level implementation of top-level steering executor.
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
#include <netinet/ether.h>
#include <limits.h>

#include <dbg.h>

#ifdef LBD_DBG_MENU
#include <cmd.h>
#endif

#include "lb_common.h"
#include "module.h"
#include "profile.h"

#include "steerexec.h"
#include "steerexecImplCmn.h"
#include "stadb.h"


static struct {
    /// The steering executor to use for clients.
    steerexecImplCmnHandle_t steerexecImplCmn;

    struct dbgModule *dbgModule;
} steerexecState;

/**
 * @brief Default configuration values.
 *
 * These are used if the config file does not specify them.
 */
static struct profileElement steerexecElementDefaultTable[] = {
    { STEEREXEC_STEERING_PROHIBIT_TIME_KEY,          "300" },
    { STEEREXEC_T_STEERING_KEY,                      "15" },
    { STEEREXEC_INITIAL_AUTH_REJ_COALESCE_TIME_KEY,  "2" },
    { STEEREXEC_AUTH_REJ_MAX_KEY,                    "3" },
    { STEEREXEC_STEERING_UNFRIENDLY_TIME_KEY,        "600" },
    // There are 604800 seconds in a week
    { STEEREXEC_MAX_STEERING_UNFRIENDLY              "604800" },
    { STEEREXEC_LOW_RSSI_THRESHOLD_W2_KEY,           "10" },
    { STEEREXEC_LOW_RSSI_THRESHOLD_W5_KEY,           "10" },
    { STEEREXEC_TARGET_LOW_RSSI_THRESHOLD_W2_KEY,    "5" },
    { STEEREXEC_TARGET_LOW_RSSI_THRESHOLD_W5_KEY,    "15" },
    // 15 minutes
    { STEEREXEC_BLACKLIST_TIME_KEY,                  "900" },
    { STEEREXEC_BTM_RESPONSE_TIME_KEY,               "10" },
    { STEEREXEC_BTM_ASSOCIATION_TIME_KEY,            "6" },
    { STEEREXEC_BTM_ALSO_BLACKLIST,                  "1" },
    { STEEREXEC_BTM_UNFRIENDLY_TIME_KEY,             "600" },
    { STEEREXEC_BTM_STEERING_PROHIBIT_SHORT_TIME_KEY,"30" },
    // There are 86400 seconds in a day.
    { STEEREXEC_MAX_BTM_UNFRIENDLY,                  "86400" },
    { STEEREXEC_MAX_BTM_ACTIVE_UNFRIENDLY,           "604800" },
    { STEEREXEC_AGE_LIMIT_KEY,                       "5" },
    { STEEREXEC_BTM_MIN_RSSI_BE,                     "12" },
    { STEEREXEC_IAS_USE_BE,                          "0" },
    { STEEREXEC_START_IN_BTM_ACTIVE_STATE_KEY,       "0" },
    { STEEREXEC_MAX_CONSECUTIVE_BTM_FAILURES_AS_ACTIVE_KEY, "4" },
    { NULL, NULL }
};

// Forward decls
static LBD_STATUS steerexecReadConfig(steerexecImplCmnConfig_t *config,
                                      struct dbgModule *dbgModule);

static void steerexecAssocObserverCB(stadbEntry_handle_t handle,
                                     const lbd_bssInfo_t *lastAssocBSS,
                                     void *cookie);

static void steerexecMenuInit(void);

// ====================================================================
// Public API
// ====================================================================

LBD_STATUS steerexec_init(void) {
    steerexecState.dbgModule = dbgModuleFind("steerexec");
    steerexecState.dbgModule->Level = DBGINFO;

    steerexecImplCmnConfig_t config;
    if (steerexecReadConfig(&config, steerexecState.dbgModule) != LBD_OK) {
        return LBD_NOK;
    }

    if (stadb_registerAssocObserver(steerexecAssocObserverCB,
                                    NULL) != LBD_OK) {
        return LBD_NOK;
    }

    steerexecState.steerexecImplCmn =
        steerexecImplCmnCreate(&config, steerexecState.dbgModule);
    if (!steerexecState.steerexecImplCmn) {
        return LBD_NOK;
    }

    steerexecMenuInit();
    return LBD_OK;
}

LBD_STATUS steerexec_abort(stadbEntry_handle_t entry,
                           LBD_BOOL *ignored) {
    // Underlying steering orchestrator must check the entry itself.
    if (!steerexecState.steerexecImplCmn) {
        return LBD_NOK;
    }

    return steerexecImplCmnAbort(steerexecState.steerexecImplCmn, entry,
                                 steerexecImplCmnSteeringStatusType_abort_user,
                                 ignored);
}

LBD_STATUS steerexec_allowAssoc(stadbEntry_handle_t entry,
                                u_int8_t channelCount,
                                const lbd_channelId_t *channelList,
                                LBD_BOOL *ignored) {
    // Underlying steering orchestrator must check parameters itself.
    if (!steerexecState.steerexecImplCmn) {
        return LBD_NOK;
    }

    return steerexecImplCmnAllowAssoc(steerexecState.steerexecImplCmn,
                                   entry, channelCount, channelList, ignored);
}

LBD_STATUS steerexec_abortAllowAssoc(stadbEntry_handle_t entry,
                                     LBD_BOOL *ignored) {
    // Underlying steering orchestrator must check parameters itself.
    if (!steerexecState.steerexecImplCmn) {
        return LBD_NOK;
    }

    return steerexecImplCmnAbortAllowAssoc(steerexecState.steerexecImplCmn,
                                        entry, ignored);
}

LBD_STATUS steerexec_steer(stadbEntry_handle_t entry,
                           u_int8_t candidateCount,
                           const lbd_bssInfo_t *candidateList,
                           steerexec_reason_e reason,
                           LBD_BOOL *ignored) {
    // Underlying steering orchestrator must check parameters itself.
    if (!steerexecState.steerexecImplCmn) {
        return LBD_NOK;
    }

    return steerexecImplCmnSteer(steerexecState.steerexecImplCmn,
                              entry, candidateCount, candidateList,
                              reason, ignored);
}

steerexec_steerEligibility_e steerexec_determineSteeringEligibility(
    stadbEntry_handle_t entry) {
    // Underlying steering orchestrator must check parameters itself.
    if (!steerexecState.steerexecImplCmn) {
        return steerexec_steerEligibility_none;
    }

    return steerexecImplCmnDetermineSteeringEligibility(
        steerexecState.steerexecImplCmn, entry,
        LBD_TRUE /* reportReasonNotEligible */);
}


LBD_BOOL steerexec_shouldAbortSteerForActive(stadbEntry_handle_t entry) {
    // Underlying steering orchestrator must check parameters itself.
    if (!steerexecState.steerexecImplCmn) {
        return LBD_FALSE;
    }

    return steerexecImplCmnShouldAbortSteerForActive(
        steerexecState.steerexecImplCmn, entry);
}

LBD_STATUS steerexec_registerSteeringAllowedObserver(
        steerexec_steeringAllowedObserverCB observer,
        void *cookie) {
    if (!steerexecState.steerexecImplCmn) {
        return LBD_NOK;
    }

    return steerexecImplCmnRegisterSteeringAllowedObserver(
            steerexecState.steerexecImplCmn, observer, cookie);
}

LBD_STATUS steerexec_unregisterSteeringAllowedObserver(
        steerexec_steeringAllowedObserverCB observer,
        void *cookie) {
    if (!steerexecState.steerexecImplCmn) {
        return LBD_NOK;
    }

    return steerexecImplCmnUnregisterSteeringAllowedObserver(
            steerexecState.steerexecImplCmn, observer, cookie);
}

LBD_STATUS steerexec_fini(void) {
    stadb_unregisterAssocObserver(steerexecAssocObserverCB, NULL);
    steerexecImplCmnDestroy(steerexecState.steerexecImplCmn);
    steerexecState.steerexecImplCmn = NULL;
    return LBD_OK;
}

json_t *steerexec_jsonize(stadbEntry_handle_t entry) {
    if (!steerexecState.steerexecImplCmn) {
        return NULL;
    }

    return steerexecImplCmnJsonize(steerexecState.steerexecImplCmn, entry);
}

void steerexec_restore(stadbEntry_handle_t entry, json_t *json) {
    if (!steerexecState.steerexecImplCmn) {
        return;
    }

    steerexecImplCmnRestore(steerexecState.steerexecImplCmn, entry,
            json);
}


// ====================================================================
// Private helper functions
// ====================================================================

/**
 * @brief Read all of the configuration data from the file into the internal
 *        state.
 *
 * @param [out] config  the location to store the config data
 * @param [in] dbgModule  used for debug output
 *
 * @return LBD_STATUS LBD_OK if configuration is valid
 */
static LBD_STATUS steerexecReadConfig(steerexecImplCmnConfig_t *config,
                                      struct dbgModule *dbgModule) {
    config->legacy.steeringProhibitTime =
        profileGetOptsInt(mdModuleID_SteerExec,
                          STEEREXEC_STEERING_PROHIBIT_TIME_KEY,
                          steerexecElementDefaultTable);

    config->legacy.tSteering =
        profileGetOptsInt(mdModuleID_SteerExec,
                          STEEREXEC_T_STEERING_KEY,
                          steerexecElementDefaultTable);

    config->legacy.initialAuthRejCoalesceTime =
        profileGetOptsInt(mdModuleID_SteerExec,
                          STEEREXEC_INITIAL_AUTH_REJ_COALESCE_TIME_KEY,
                          steerexecElementDefaultTable);

    config->legacy.authRejMax =
        profileGetOptsInt(mdModuleID_SteerExec,
                          STEEREXEC_AUTH_REJ_MAX_KEY,
                          steerexecElementDefaultTable);

    config->legacy.steeringUnfriendlyTime =
        profileGetOptsInt(mdModuleID_SteerExec,
                          STEEREXEC_STEERING_UNFRIENDLY_TIME_KEY,
                          steerexecElementDefaultTable);

    config->legacy.maxSteeringUnfriendly =
        profileGetOptsInt(mdModuleID_SteerExec,
                          STEEREXEC_MAX_STEERING_UNFRIENDLY,
                          steerexecElementDefaultTable);

    config->lowRSSIXingThreshold[wlanif_band_24g] =
        profileGetOptsInt(mdModuleID_SteerExec,
                          STEEREXEC_LOW_RSSI_THRESHOLD_W2_KEY,
                          steerexecElementDefaultTable);

    config->lowRSSIXingThreshold[wlanif_band_5g] =
        profileGetOptsInt(mdModuleID_SteerExec,
                          STEEREXEC_LOW_RSSI_THRESHOLD_W5_KEY,
                          steerexecElementDefaultTable);

    config->targetLowRSSIThreshold[wlanif_band_24g] =
        profileGetOptsInt(mdModuleID_SteerExec,
                          STEEREXEC_TARGET_LOW_RSSI_THRESHOLD_W2_KEY,
                          steerexecElementDefaultTable);

    config->targetLowRSSIThreshold[wlanif_band_5g] =
        profileGetOptsInt(mdModuleID_SteerExec,
                          STEEREXEC_TARGET_LOW_RSSI_THRESHOLD_W5_KEY,
                          steerexecElementDefaultTable);

    config->legacy.blacklistTime =
        profileGetOptsInt(mdModuleID_SteerExec,
                          STEEREXEC_BLACKLIST_TIME_KEY,
                          steerexecElementDefaultTable);

    config->btm.responseTime =
        profileGetOptsInt(mdModuleID_SteerExec,
                          STEEREXEC_BTM_RESPONSE_TIME_KEY,
                          steerexecElementDefaultTable);

    config->btm.associationTime =
        profileGetOptsInt(mdModuleID_SteerExec,
                          STEEREXEC_BTM_ASSOCIATION_TIME_KEY,
                          steerexecElementDefaultTable);

    config->btm.alsoBlacklist =
        profileGetOptsInt(mdModuleID_SteerExec,
                          STEEREXEC_BTM_ALSO_BLACKLIST,
                          steerexecElementDefaultTable);

    config->btm.btmUnfriendlyTime =
        profileGetOptsInt(mdModuleID_SteerExec,
                          STEEREXEC_BTM_UNFRIENDLY_TIME_KEY,
                          steerexecElementDefaultTable);

    config->btm.maxBTMUnfriendly =
        profileGetOptsInt(mdModuleID_SteerExec,
                          STEEREXEC_MAX_BTM_UNFRIENDLY,
                          steerexecElementDefaultTable);

    config->btm.maxBTMActiveUnfriendly =
        profileGetOptsInt(mdModuleID_SteerExec,
                          STEEREXEC_MAX_BTM_ACTIVE_UNFRIENDLY,
                          steerexecElementDefaultTable);

    config->btm.steeringProhibitShortTime =
        profileGetOptsInt(mdModuleID_SteerExec,
                          STEEREXEC_BTM_STEERING_PROHIBIT_SHORT_TIME_KEY,
                          steerexecElementDefaultTable);

    config->btm.freshnessLimit =
        profileGetOptsInt(mdModuleID_SteerExec,
                          STEEREXEC_AGE_LIMIT_KEY,
                          steerexecElementDefaultTable);

    config->btm.minRSSIBestEffort =
        profileGetOptsInt(mdModuleID_SteerExec,
                          STEEREXEC_BTM_MIN_RSSI_BE,
                          steerexecElementDefaultTable);

    config->IASUseBestEffort =
        profileGetOptsInt(mdModuleID_SteerExec,
                          STEEREXEC_IAS_USE_BE,
                          steerexecElementDefaultTable);

    config->btm.startInBTMActiveState =
        profileGetOptsInt(mdModuleID_SteerExec,
                          STEEREXEC_START_IN_BTM_ACTIVE_STATE_KEY,
                          steerexecElementDefaultTable);

    config->btm.maxConsecutiveBTMFailuresAsActive =
        profileGetOptsInt(mdModuleID_SteerExec,
                          STEEREXEC_MAX_CONSECUTIVE_BTM_FAILURES_AS_ACTIVE_KEY,
                          steerexecElementDefaultTable);

    if (config->btm.steeringProhibitShortTime >=
        config->legacy.steeringProhibitTime) {
        dbgf(dbgModule, DBGERR,
             "%s: Invalid configuration, "
             "STEEREXEC_BTM_STEERING_PROHIBIT_SHORT_TIME_KEY (%u) "
             "must be less than STEEREXEC_STEERING_PROHIBIT_TIME_KEY (%u)",
             __func__, config->btm.steeringProhibitShortTime,
             config->legacy.steeringProhibitTime);
        return LBD_NOK;
    }

    if (!config->btm.maxConsecutiveBTMFailuresAsActive) {
        // Must allow at least 1 failure before marking as active unfriendly
        dbgf(dbgModule, DBGERR,
             "%s: There must be at least 1 active failure allowed before "
             "marking a STA as active steering unfriendly, setting to default value",
             __func__);
        const char *maxFailures = profileElementDefault(
            STEEREXEC_MAX_CONSECUTIVE_BTM_FAILURES_AS_ACTIVE_KEY,
            steerexecElementDefaultTable);

        if (!maxFailures) {
            dbgf(dbgModule, DBGERR,
                 "%s: Max consecutive steering failures as active value is NULL",
                 __func__);
            return LBD_NOK;
        } else {
            config->btm.maxConsecutiveBTMFailuresAsActive =
                atoi(maxFailures);
        }
    }

    return LBD_OK;
}

/**
 * @brief Observer callback for changes in the association state for STAs in
 *        the database.
 *
 * @param [in] entry  the STA that was updated
 * @param [in] lastAssocBSS  the BSS the STA was associated before this update
 * @param [in] cookie  the parameter provided in the registration (unused)
 */
static void steerexecAssocObserverCB(stadbEntry_handle_t entry,
                                     const lbd_bssInfo_t *lastAssocBSS,
                                     void *cookie) {
    if (steerexecState.steerexecImplCmn) {
        steerexecImplCmnHandleAssocUpdate(steerexecState.steerexecImplCmn,
                                          entry, lastAssocBSS);
    }
}

#ifdef LBD_DBG_MENU

struct steerexecStatusCmdContext {
    struct cmdContext *context;
    LBD_BOOL inProgressOnly;
    LBD_BOOL dumpBTMClients;
    LBD_BOOL dumpStatistics;
};

static void steerexecStatusIterateCB(stadbEntry_handle_t entry,
                                           void *cookie) {
    struct steerexecStatusCmdContext *statusContext =
        (struct steerexecStatusCmdContext *) cookie;

    steerexecImplCmnDumpEntryState(statusContext->context,
                                steerexecState.steerexecImplCmn,
                                entry, statusContext->inProgressOnly,
                                statusContext->dumpBTMClients,
                                statusContext->dumpStatistics);
}

static const char *steerexecMenuStatusHelp[] = {
    "s -- print steering executor status",
    "Usage:",
    "\ts: display all nodes",
    "\ts in: display only steering in progress nodes",
    NULL
};

#ifndef GMOCK_UNIT_TESTS
static
#endif
void steerexecMenuStatusHandler(struct cmdContext *context,
                                const char *cmd) {
    LBD_BOOL inProgressOnly = LBD_FALSE;
    const char *arg = cmdWordFirst(cmd);

    if (arg && strncmp("in", arg, 2) == 0) {
        inProgressOnly = LBD_TRUE;
    }

    // Iterate twice, once for Legacy STAs, then again for 802.11v BTM STAs

    steerexecImplCmnDumpLegacyHeader(context, steerexecState.steerexecImplCmn);

    struct steerexecStatusCmdContext statusContext = {
        context, inProgressOnly, LBD_FALSE /* dumpBTMClients */
    };
    if (stadb_iterate(steerexecStatusIterateCB,
                      &statusContext) != LBD_OK) {
        cmdf(context, "Iteration over station database for Legacy STAs failed\n");
    }

    steerexecImplCmnDumpBTMHeader(context, steerexecState.steerexecImplCmn);

    statusContext.dumpBTMClients = LBD_TRUE;
    statusContext.dumpStatistics = LBD_FALSE;

    if (stadb_iterate(steerexecStatusIterateCB,
                      &statusContext) != LBD_OK) {
        cmdf(context, "Iteration over station database for BTM compatible STAs failed\n");
    }

    steerexecImplCmnDumpBTMStatisticsHeader(context, steerexecState.steerexecImplCmn);

    statusContext.dumpStatistics = LBD_TRUE;

    if (stadb_iterate(steerexecStatusIterateCB,
                      &statusContext) != LBD_OK) {
        cmdf(context, "Iteration over station database for BTM compatible STAs (statistics) failed\n");
    }
}

static const char *steerexecMenuSteerHelp[] = {
    "steer -- post-association steer of a STA",
    "Usage:",
    "\tsteer <mac> <ap> <channel> <ess> [<ap> <channel> <ess>]: steer the MAC address to the given candidate(s)."
    "  Second candidate is optional.",
    NULL
};

/**
 * @brief Extract and store a command line argument as a
 *        u_int8_t
 *
 * @param [in] context the output context
 * @param [in] arg argument to parse
 * @param [out] val store the value from parsing argument here
 *
 * @return LBD_STATUS returns LBD_OK on success, LBD_NOK
 *         otherwise
 */
static LBD_STATUS steerexecMenuAssignUint8(struct cmdContext *context,
                                           const char *arg,
                                           u_int8_t *val) {
    if (!cmdWordDigits(arg)) {
        // Don't print an error here, could just be out of arguments
        return LBD_NOK;
    }

    int tempInt = atoi(arg);
    if (tempInt < 0 || tempInt > UCHAR_MAX) {
        cmdf(context, "steerexec command argument out of range, should be < 0xFF: '%d'\n",
             tempInt);
        return LBD_NOK;
    }
    *val = tempInt;

    return LBD_OK;
}

/**
 * @brief Extract the BSS info from the command line argument
 *
 * @param [in] context the output context
 * @param [inout] arg next argument to parse
 * @param [out] outBSS structure to populate with BSS
 *                     information
 * @param [in] entry the stadb entry to lookup the BSS for
 *                   (needed to lookup the VAP pointer)
 *
 * @return LBD_STATUS return LBD_OK on success, LBD_NOK
 *         otherwise
 */
static LBD_STATUS steerexecMenuGetBSSInfo(struct cmdContext *context,
                                          const char **arg,
                                          lbd_bssInfo_t *outBSS,
                                          stadbEntry_handle_t entry) {
    // Unknown VAP at this point
    outBSS->vap = LBD_VAP_INVALID;

    *arg = cmdWordNext(*arg);
    if (steerexecMenuAssignUint8(context, *arg, &outBSS->apId) != LBD_OK) {
        return LBD_NOK;
    }

    *arg = cmdWordNext(*arg);
    if (steerexecMenuAssignUint8(context, *arg, &outBSS->channelId) != LBD_OK) {
        return LBD_NOK;
    }

    *arg = cmdWordNext(*arg);
    if (steerexecMenuAssignUint8(context, *arg, &outBSS->essId) != LBD_OK) {
        return LBD_NOK;
    }

    if (!lbIsBSSLocal(outBSS)) {
        // For a non-local BSS, can't collect VAP info, however, should make
        // sure that we can get the BSSID
        if (!wlanif_getBSSIDForBSSInfo(outBSS)) {
            cmdf(context, "Can't fetch BSSID for remote BSS " lbBSSInfoAddFmt() "\n",
                 lbBSSInfoAddData(outBSS));
            return LBD_NOK;
        }

        return LBD_OK;
    }

    // Get the BSS stats from this bss
    stadbEntry_bssStatsHandle_t stats = stadbEntry_findMatchBSSStats(entry, outBSS);
    if (!stats) {
        cmdf(context, "No known BSS match\n");
        return LBD_NOK;
    }

    // Now get the bss info (should have the VAP filled in)
    const lbd_bssInfo_t *candidatePtr;
    candidatePtr = stadbEntry_resolveBSSInfo(stats);
    if (!candidatePtr) {
        cmdf(context, "Couldn't resolve BSS from stats\n");
        return LBD_NOK;
    }

    // Copy over the VAP information
    outBSS->vap = candidatePtr->vap;

    return LBD_OK;
}

#ifndef GMOCK_UNIT_TESTS
static
#endif
void steerexecMenuSteerHandler(struct cmdContext *context,
                                const char *cmd) {
    const char *arg = cmdWordFirst(cmd);
    if (!arg) {
        return;
    }

    const struct ether_addr *staAddr = ether_aton(arg);
    if (!staAddr) {
        cmdf(context, "steerexec 'steer' command invalid MAC address: %s\n",
             arg);
        return;
    }

    stadbEntry_handle_t entry = stadb_find(staAddr);
    if (!entry) {
        cmdf(context, "steerexec 'steer' unknown MAC address: "
                      lbMACAddFmt(":") "\n",
             lbMACAddData(staAddr->ether_addr_octet));
        return;
    }

    lbd_bssInfo_t candidateList[STEEREXEC_MAX_CANDIDATES];
    size_t i;
    for (i = 0; i < STEEREXEC_MAX_CANDIDATES; i++) {
        if (steerexecMenuGetBSSInfo(context, &arg, &candidateList[i], entry) != LBD_OK) {
            break;
        }
    }

    if (!i) {
        cmdf(context, "steerexec 'steer' command needs at least 1 candidate. "
             "Candidate should be specified as <ap> <channel> <ess>\n",
             arg);
        return;
    }

    LBD_BOOL ignored;
    if (steerexec_steer(entry, i, &candidateList[0], steerexec_reason_user,
                        &ignored) != LBD_OK) {
        cmdf(context, "steerexec 'steer' " lbMACAddFmt(":")
                      " failed\n",
             lbMACAddData(staAddr->ether_addr_octet));
    } else if (ignored) {
        cmdf(context, "steerexec 'steer' " lbMACAddFmt(":")
                      " ignored by executor\n",
             lbMACAddData(staAddr->ether_addr_octet));
    }

}

static const char *steerexecMenuAllowAssocHelp[] = {
    "allow_assoc -- pre-association steer of a STA",
    "Usage:",
    "\tallow_assoc <mac> <channel> [<channel>]: allow the MAC address to associate "
    "on the given channel(s).  Second channel is optional.",
    NULL
};

#ifndef GMOCK_UNIT_TESTS
static
#endif
void steerexecMenuAllowAssocHandler(struct cmdContext *context,
                                    const char *cmd) {
    const char *arg = cmdWordFirst(cmd);
    if (!arg) {
        return;
    }

    const struct ether_addr *staAddr = ether_aton(arg);
    if (!staAddr) {
        cmdf(context, "steerexec 'allow_assoc' command invalid MAC address: %s\n",
             arg);
        return;
    }

    stadbEntry_handle_t entry = stadb_find(staAddr);
    if (!entry) {
        cmdf(context, "steerexec 'allow_assoc' unknown MAC address: "
                      lbMACAddFmt(":") "\n",
             lbMACAddData(staAddr->ether_addr_octet));
        return;
    }

    lbd_channelId_t channels[STEEREXEC_MAX_ALLOW_ASSOC];
    size_t channelCount;

    for (channelCount = 0; channelCount < STEEREXEC_MAX_ALLOW_ASSOC; channelCount++) {
        arg = cmdWordNext(arg);
        if (steerexecMenuAssignUint8(context,arg, &channels[channelCount]) == LBD_NOK) {
            break;
        }
    }

    if (!channelCount) {
        cmdf(context, "steerexec 'allow_assoc' command needs at least 1 channel\n",
             arg);
        return;
    }

    LBD_BOOL ignored;
    if (steerexec_allowAssoc(entry, channelCount, &channels[0], &ignored) != LBD_OK) {
        cmdf(context, "steerexec 'allowAssoc' " lbMACAddFmt(":")
                      " failed\n",
             lbMACAddData(staAddr->ether_addr_octet));
    } else if (ignored) {
        cmdf(context, "steerexec 'allowAssoc' " lbMACAddFmt(":")
                      " ignored by executor\n",
             lbMACAddData(staAddr->ether_addr_octet));
    }
}

static const char *steerexecMenuAbortHelp[] = {
    "abort -- abort steering a STA",
    "Usage:",
    "\tabort <mac>: abort steer of the MAC address",
    NULL
};

#ifndef GMOCK_UNIT_TESTS
static
#endif
void steerexecMenuAbortHandler(struct cmdContext *context,
                               const char *cmd) {
    const char *arg = cmdWordFirst(cmd);
    if (!arg) {
        return;
    }

    const struct ether_addr *staAddr = ether_aton(arg);
    if (!staAddr) {
        cmdf(context, "steerexec 'abort' command invalid MAC address: %s\n",
             arg);
        return;
    }

    stadbEntry_handle_t entry = stadb_find(staAddr);
    if (!entry) {
        cmdf(context, "steerexec 'abort' unknown MAC address: "
                      lbMACAddFmt(":") "\n",
             lbMACAddData(staAddr->ether_addr_octet));
        return;
    }

    LBD_BOOL ignored;
    if (steerexec_abort(entry, &ignored) != LBD_OK) {
        cmdf(context, "steerexec 'abort' " lbMACAddFmt(":")
                      " failed\n",
             lbMACAddData(staAddr->ether_addr_octet));
    } else if (ignored) {
        cmdf(context, "steerexec 'abort' " lbMACAddFmt(":")
                      " ignored by executor\n",
             lbMACAddData(staAddr->ether_addr_octet));
    }
}

static const char *steerexecMenuDiaglogHelp[] = {
    "diaglog -- generate diaglog messages",
    "Usage:",
    "\tdiaglog all: generate logs for steering unfriendly, BTM compliance and prohibit type "
        "for all STAs",
    NULL
};

/**
 * @brief Callback function to generate diaglogs for the given STA
 *
 * @param [in] entry  the entry to generate diaglog
 * @param [in] cookie  not used
 */
static void steerexecDiaglogAllCB(stadbEntry_handle_t entry, void *cookie) {
    steerexecImplCmnGenerateDiaglog(steerexecState.steerexecImplCmn,
                                    entry, LBD_TRUE /* prohibit */,
                                    LBD_TRUE /* unfriendly */,
                                    LBD_TRUE /* compliance */);
}

#ifndef GMOCK_UNIT_TESTS
static
#endif
void steerexecMenuDiaglogHandler(struct cmdContext *context,
                                 const char *cmd) {
    const char *arg = cmdWordFirst(cmd);
#define DIAGLOG_ALL "all"
    if (!steerexecState.steerexecImplCmn) {
        cmdf(context, "steerexec 'diaglog' command is ignored before init\n");
        return;
    }

    if (!arg) {
        cmdf(context, "steerexec 'diaglog' command requires one argument\n");
        return;
    }

    if (strncmp(DIAGLOG_ALL, arg, strlen(DIAGLOG_ALL)) == 0) {
        if (stadb_iterate(steerexecDiaglogAllCB, NULL) == LBD_NOK) {
            cmdf(context, "'diaglog %s': Failed to iterate steerexec\n", arg);
        }
    } else {
        cmdf(context, "steerexec 'diaglog' unknown command: %s\n", arg);
    }
#undef DIAGLOG_ALL
}

// Sub-menus for the steering executor debug CLI.
static const struct cmdMenuItem steerexecMenu[] = {
    CMD_MENU_STANDARD_STUFF(),
    { "s", steerexecMenuStatusHandler, NULL, steerexecMenuStatusHelp },
    { "steer", steerexecMenuSteerHandler, NULL, steerexecMenuSteerHelp },
    { "allow_assoc", steerexecMenuAllowAssocHandler, NULL, steerexecMenuAllowAssocHelp },
    { "abort", steerexecMenuAbortHandler, NULL, steerexecMenuAbortHelp },
    { "diaglog", steerexecMenuDiaglogHandler, NULL, steerexecMenuDiaglogHelp },
    CMD_MENU_END()
};

static const char *steerexecMenuHelp[] = {
    "steerexec -- Steering Executor",
    NULL
};

// Top-level steering executor menu.
static const struct cmdMenuItem steerexecMenuItem = {
    "steerexec",
    cmdMenu,
    (struct cmdMenuItem *) steerexecMenu,
    steerexecMenuHelp
};

#endif /* LBD_DBG_MENU */

/**
 * @brief Initialize the debug CLI hooks for this module (if necesary).
 */
static void steerexecMenuInit(void) {
#ifdef LBD_DBG_MENU
    cmdMainMenuAdd(&steerexecMenuItem);
#endif /* LBD_DBG_MENU */
}
