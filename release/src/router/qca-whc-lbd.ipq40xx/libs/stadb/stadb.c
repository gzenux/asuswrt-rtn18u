// vim: set et sw=4 sts=4 cindent:
/*
 * @File: stadb.c
 *
 * @Abstract: Implementation of station database public APIs
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
#include <evloop.h>

#ifdef LBD_DBG_MENU
#include <cmd.h>
#endif

#include "lb_assert.h"
#include "lb_common.h"
#include "module.h"
#include "profile.h"
#include "wlanif.h"

#include "stadb.h"
#include "stadbHashTable.h"
#include "stadbEntryPrivate.h"

// For now, we are only permitting 3 observers, as it is likely that the
// following will need to observe RSSI updates:
//
// 1. Pre-association steering decision maker
// 2. Post-association steering decision maker
// 3. Steering safety mechanism
#define MAX_RSSI_OBSERVERS 3
#define STADB_PERSIST_VERSION 1

/**
 * @brief Internal type used for station database iteration, tying the user
 *        requested cookie and function together with this files iteration
 *        function.
 */
typedef struct stadbIterateParams_t {
    /// The caller-provided callback function to invoke for each entry.
    stadb_iterFunc_t callback;

    /// The caller-provided cookie to provide in each invocation.
    void *cookie;
} stadbIterateParams_t;

static struct {
    struct {
        /// Whether out of network devices should be included in the station
        /// database or not.
        u_int32_t includeOutOfNetwork;

        /// Number of entries in the database that triggers aging.
        u_int32_t agingSizeThreshold;

        /// How often to perform aging, in seconds.
        u_int32_t agingFrequency;

        /// The maximum age of an out of network STA after which it should be
        /// removed during aging.
        u_int32_t outOfNetworkMaxAge;

        /// The maximum age of an out of network STA after which it should be
        /// removed during aging.
        u_int32_t inNetworkMaxAge;

        /// Number of seconds of the interval when two consecutive probe requests
        /// should be grouped
        u_int32_t probeMaxInterval;

        /// Whether to mark 11k/v capable clients as dual band capable
        u_int32_t markAdvClientAsDualBand;

        /// Whether to populate PHY capability info on non-serving band for 11k/v client
        u_int32_t populateNonServingPHY;
    } config;

    stadbHashTableHandle_t db;

    /// Observer for all RSSI updates to entries in the database.
    struct stadbRSSIObserver {
        LBD_BOOL isValid;
        stadb_rssiObserverCB callback;
        void *cookie;
    } rssiObservers[MAX_RSSI_OBSERVERS];

    /// Observer for all association updates to entries in the database.
    struct stadbAssocObserver {
        LBD_BOOL isValid;
        stadb_assocObserverCB callback;
        void *cookie;
    } assocObserver;

    /// Observer for all activity status updates to entries in the database.
    struct stadbActivityObserver {
        LBD_BOOL isValid;
        stadb_activityObserverCB callback;
        void *cookie;
    } activityObserver;

    /// Observer for all entries in the database whose RSSI crossing low threshold
    struct stadbLowRSSIObserver {
        LBD_BOOL isValid;
        stadb_lowRSSIObserverCB callback;
        void *cookie;
    } lowRSSIObserver;

    /// Timer used to conduct periodic aging of the database.
    struct evloopTimeout agingTimeout;

    struct dbgModule *dbgModule;

    /// Number of radios local AP supports, which determines number
    /// of BSS entries should be created for each in-network STA.
    size_t numRadiosLocal;

    /// Number of BSS entries remote AP(s) supports, which determines the
    /// additional number of BSSes should be created for each in-network STA
    /// that supports 11k.
    size_t numRemoteBSSStats;

#ifdef LBD_DBG_MENU
    /// When debug mode is enabled, the actChangeEvent/rssiXingEvent/rssiMeasurementEvent
    /// will be ignored and not override RSSI and activity status, and changes have to
    /// come via the debug CLI. But other events can still go through and potentially
    /// overwrite the RSSI value injected via the debug CLI.
    LBD_BOOL debugModeEnabled;
#endif /* LBD_DBG_MENU */

    LBD_BOOL isDirty;
} stadbState;

/**
 * @brief Check whether stadb is currently running in a multi-AP setup
 *
 * It checks the number of BSS entries remote AP(s) supports. If it is
 * 0, then it is in single-AP setup; otherwise, it is for multi-AP.
 */
static inline LBD_BOOL stadbIsMultiAP(void) {
    return stadbState.numRemoteBSSStats;
}

/**
 * @brief Default configuration values.
 *
 * These are used if the config file does not specify them.
 */
static struct profileElement stadbElementDefaultTable[] = {
    { STADB_INCLUDE_OUT_OF_NETWORK_KEY, "1" },
    { STADB_AGING_SIZE_THRESHOLD_KEY,   "100" },
    { STADB_AGING_FREQUENCY_KEY,        "60" },
    { STADB_OUT_OF_NETWORK_MAX_AGE,     "300" },      // 5 minutes
    { STADB_IN_NETWORK_MAX_AGE,         "2592000" },  // 30 days
    { STADB_PROBE_MAX_INTERVAL,         "5" },        // 5 seconds
    { STADB_MARK_ADV_CLIENT_DUAL_BAND,  "0" },
    { STADB_POPULATE_NON_SERVING_PHY,   "1" },
    // Only necessary for multi-AP setup. By default they
    // are all invalid and must be explicitly specified when
    // running in multi-AP mode.
    { STADB_MAX_REMOTE_BSSES,           "0" },
    { NULL, NULL }
};

// Forward decls
static void stadbReadConfig(void);
static stadbEntry_handle_t stadbFindOrInsertEntry(
        const struct ether_addr *addr, LBD_BOOL outOfNetwork,
        wlanif_capStateUpdate_e rrmStatus);

static stadbEntry_handle_t stadbUpdateBandAndRSSI(
        const struct ether_addr *addr,
        const lbd_bssInfo_t *bss, u_int8_t rssi,
        stadb_rssiUpdateReason_e reason, LBD_BOOL markAssociated,
        LBD_BOOL outOfNetwork);
static void stadbUpdateAssoc(const struct ether_addr *addr,
                             const lbd_bssInfo_t *bss,
                             wlanif_capStateUpdate_e btmStatus,
                             wlanif_capStateUpdate_e rrmStatus,
                             LBD_BOOL isMUMIMOSupported,
                             LBD_BOOL isStaticSMPS,
                             const wlanif_phyCapInfo_t *phyCapInfo,
                             LBD_BOOL isAssoc);
static void stadbNotifyRSSIObservers(stadbEntry_handle_t entry,
                                     stadb_rssiUpdateReason_e reason);
static void stadbNotifyAssocObserver(stadbEntry_handle_t entry,
                                     const lbd_bssInfo_t *lastAssocBSS);
static void stadbNotifyActivityObservers(stadbEntry_handle_t entry);
static void stadbNotifyLowRSSIObservers(stadbEntry_handle_t entry);

static void stadbHandleProbeReq(struct mdEventNode *event);
static void stadbHandleAuthRej(struct mdEventNode *event);
static void stadbHandleAssoc(struct mdEventNode *event);
static void stadbHandleActChangeEvent(struct mdEventNode *event);
static void stadbHandleActChange(const struct ether_addr *staAddr,
                                 const lbd_bssInfo_t *bss,
                                 LBD_BOOL active);
static void stadbHandleSteerChange(const struct ether_addr *staAddr,
                                 LBD_BOOL active);
static void stadbHandleRSSIXingEvent(struct mdEventNode *event);
static void stadbHandleRSSIXing(const struct ether_addr *staAddr,
                                const lbd_bssInfo_t *bss,
                                u_int8_t rssi,
                                wlanif_xingDirection_e lowXing);
static void stadbHandleRSSIMeasurementEvent(struct mdEventNode *event);
static void stadbHandleRSSIMeasurement(const struct ether_addr *staAddr,
                                       const lbd_bssInfo_t *bss,
                                       u_int8_t rssi);

static void stadbIterateResetAssoc(stadbEntry_handle_t entry, void *cookie);
static void stadbHandleBandSteeringStateEvent(struct mdEventNode *event);
static void stadbAgingTimeoutHandler(void *cookie);
static void stadbDumpAssociatedSTAsCB(const struct ether_addr *addr,
                                      const lbd_bssInfo_t *bss,
                                      LBD_BOOL isBTMSupported,
                                      LBD_BOOL isRRMSupported,
                                      LBD_BOOL isMUMIMOSupported,
                                      LBD_BOOL isStaticSMPS,
                                      const wlanif_phyCapInfo_t *phyCapInfo,
                                      void *cookie);
static LBD_BOOL stadbIterateCB(stadbHashTableHandle_t table,
                               stadbEntry_handle_t entry,
                               void *cookie);
static void stadbMenuInit(void);
static void stadbDumpReservedAirtimeCB(const struct ether_addr *addr,
                                       const lbd_bssInfo_t *bss,
                                       lbd_airtime_t airtime,
                                       void *cookie);
static void stadbChanChangeObserverCB(lbd_vapHandle_t vap,
                                      lbd_channelId_t channelId,
                                      void *cookie);
static LBD_BOOL stadbUpdateEntryForChannelChange(stadbHashTableHandle_t handle,
                                    stadbEntry_handle_t entry,
                                    void *cookie);
static void stadbHandleSMPSUpdateEvent(struct mdEventNode *event);
static void stadbHandleOpModeUpdateEvent(struct mdEventNode *event);

#ifdef LBD_DBG_MENU
static LBD_STATUS convertCmdToRSSIXingDirection(struct cmdContext *context,
                                                const char* arg,
                                                wlanif_xingDirection_e *direction);
#endif

struct stadbJsonizeEntryCB_cookie {
    json_t *devices_j;
    stadbEntry_jsonizeSteerExecCB_t jseCB;
};
static void stadbJsonizeEntryCB(stadbEntry_handle_t entry, void *cookie);
static void stadbCreateEntryFromJson(json_t *device_j,
                   stadb_restoreSteerExecCB_t rseCB);

// ====================================================================
// Public API
// ====================================================================

LBD_STATUS stadb_init(void) {
    stadbState.dbgModule = dbgModuleFind("stadb");
    stadbState.dbgModule->Level = DBGINFO;

    stadbState.numRadiosLocal = WLANIF_MAX_RADIOS;

    stadbReadConfig();

    stadbState.db = stadbHashTableCreate();
    if (!stadbState.db) {
        return LBD_NOK;
    }

    if (wlanif_dumpAssociatedSTAs(stadbDumpAssociatedSTAsCB,
                                  &stadbState) != LBD_OK ||
        wlanif_dumpATFTable(stadbDumpReservedAirtimeCB,
                            &stadbState) != LBD_OK) {
        return LBD_NOK;
    }

    if (LBD_NOK == wlanif_registerChanChangeObserver(
                       stadbChanChangeObserverCB, &stadbState)) {
        dbgf(stadbState.dbgModule, DBGERR,
             "%s: Failed to register channel change observer",
             __func__);
        return LBD_NOK;
    }

    mdListenTableRegister(mdModuleID_WlanIF, wlanif_event_probereq,
                          stadbHandleProbeReq);

    mdListenTableRegister(mdModuleID_WlanIF, wlanif_event_authrej,
                          stadbHandleAuthRej);

    mdListenTableRegister(mdModuleID_WlanIF, wlanif_event_assoc,
                          stadbHandleAssoc);

    mdListenTableRegister(mdModuleID_WlanIF, wlanif_event_disassoc,
                          stadbHandleAssoc);

    mdListenTableRegister(mdModuleID_WlanIF, wlanif_event_act_change,
                          stadbHandleActChangeEvent);

    mdListenTableRegister(mdModuleID_WlanIF, wlanif_event_rssi_xing,
                          stadbHandleRSSIXingEvent);

    mdListenTableRegister(mdModuleID_WlanIF, wlanif_event_rssi_measurement,
                          stadbHandleRSSIMeasurementEvent);

    mdListenTableRegister(mdModuleID_WlanIF, wlanif_event_band_steering_state,
                          stadbHandleBandSteeringStateEvent);

    mdListenTableRegister(mdModuleID_WlanIF, wlanif_event_smps_update,
                          stadbHandleSMPSUpdateEvent);

    mdListenTableRegister(mdModuleID_WlanIF, wlanif_event_opmode_update,
                          stadbHandleOpModeUpdateEvent);

    evloopTimeoutCreate(&stadbState.agingTimeout, "stadbAgingTimeout",
                        stadbAgingTimeoutHandler, NULL);

    stadbMenuInit();

    stadbState.isDirty = LBD_FALSE;

    return LBD_OK;
}

LBD_STATUS stadb_registerRSSIObserver(stadb_rssiObserverCB callback,
                                      void *cookie) {
    if (!callback) {
        return LBD_NOK;
    }

    struct stadbRSSIObserver *freeSlot = NULL;
    size_t i;
    for (i = 0; i < MAX_RSSI_OBSERVERS; ++i) {
        struct stadbRSSIObserver *curSlot = &stadbState.rssiObservers[i];
        if (curSlot->isValid && curSlot->callback == callback &&
            curSlot->cookie == cookie) {
            dbgf(stadbState.dbgModule, DBGERR, "%s: Duplicate registration "
                                               "(func %p, cookie %p)",
                 __func__, callback, cookie);
           return LBD_NOK;
        }

        if (!freeSlot && !curSlot->isValid) {
            freeSlot = &stadbState.rssiObservers[i];
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

LBD_STATUS stadb_registerActivityObserver(stadb_activityObserverCB callback,
                                          void *cookie) {
    if (!callback || stadbState.activityObserver.isValid) {
        return LBD_NOK;
    }

    stadbState.activityObserver.isValid = LBD_TRUE;
    stadbState.activityObserver.callback = callback;
    stadbState.activityObserver.cookie = cookie;

    return LBD_OK;
}

LBD_STATUS stadb_unregisterRSSIObserver(stadb_rssiObserverCB callback,
                                        void *cookie) {
    if (!callback) {
        return LBD_NOK;
    }

    size_t i;
    for (i = 0; i < MAX_RSSI_OBSERVERS; ++i) {
        if (stadbState.rssiObservers[i].isValid &&
            stadbState.rssiObservers[i].callback == callback &&
            stadbState.rssiObservers[i].cookie == cookie) {
            stadbState.rssiObservers[i].isValid = LBD_FALSE;
            stadbState.rssiObservers[i].callback = NULL;
            stadbState.rssiObservers[i].cookie = NULL;
            return LBD_OK;
        }
    }

    // No match found
    return LBD_NOK;
}

LBD_STATUS stadb_unregisterActivityObserver(stadb_activityObserverCB callback,
                                            void *cookie) {
    if (!callback || !stadbState.activityObserver.isValid ||
        stadbState.activityObserver.callback != callback ||
        stadbState.activityObserver.cookie != cookie) {
        return LBD_NOK;
    }

    stadbState.activityObserver.isValid = LBD_FALSE;
    stadbState.activityObserver.callback = NULL;
    stadbState.activityObserver.cookie = NULL;

    return LBD_OK;
}

stadbEntry_handle_t stadb_find(const struct ether_addr *addr) {
    if (addr) {
        return stadbHashTableFind(stadbState.db, addr);
    }

    // Address must be valid.
    return NULL;
}

stadbEntry_handle_t stadb_findOrCreate(const struct ether_addr *addr,
                                       LBD_BOOL outOfNetwork,
                                       wlanif_capStateUpdate_e rrmStatus) {
    if (addr) {
        return stadbFindOrInsertEntry(addr, outOfNetwork, rrmStatus);
    }

    // Address must be valid.
    return NULL;
}

LBD_STATUS stadb_registerAssocObserver(stadb_assocObserverCB callback,
                                       void *cookie) {
    if (!callback || stadbState.assocObserver.isValid) {
        return LBD_NOK;
    }

    stadbState.assocObserver.isValid = LBD_TRUE;
    stadbState.assocObserver.callback = callback;
    stadbState.assocObserver.cookie = cookie;

    return LBD_OK;
}

LBD_STATUS stadb_unregisterAssocObserver(stadb_assocObserverCB callback,
                                         void *cookie) {
    if (!callback || !stadbState.assocObserver.isValid ||
        stadbState.assocObserver.callback != callback ||
        stadbState.assocObserver.cookie != cookie) {
        return LBD_NOK;
    }

    stadbState.assocObserver.isValid = LBD_FALSE;
    stadbState.assocObserver.callback = NULL;
    stadbState.assocObserver.cookie = NULL;

    return LBD_OK;
}

LBD_STATUS stadb_registerLowRSSIObserver(stadb_lowRSSIObserverCB callback,
                                         void *cookie) {
    if (!callback || stadbState.lowRSSIObserver.isValid) {
        return LBD_NOK;
    }

    stadbState.lowRSSIObserver.isValid = LBD_TRUE;
    stadbState.lowRSSIObserver.callback = callback;
    stadbState.lowRSSIObserver.cookie = cookie;

    return LBD_OK;
}

LBD_STATUS stadb_unregisterLowRSSIObserver(stadb_lowRSSIObserverCB callback,
                                           void *cookie) {
    if (!callback || !stadbState.lowRSSIObserver.isValid ||
        stadbState.lowRSSIObserver.callback != callback ||
        stadbState.lowRSSIObserver.cookie != cookie) {
        return LBD_NOK;
    }

    stadbState.lowRSSIObserver.isValid = LBD_FALSE;
    stadbState.lowRSSIObserver.callback = NULL;
    stadbState.lowRSSIObserver.cookie = NULL;

    return LBD_OK;
}

LBD_STATUS stadb_iterate(stadb_iterFunc_t callback, void *cookie) {
    if (!callback) {
        return LBD_NOK;
    }

    stadbIterateParams_t params = { callback, cookie };
    return stadbHashTableIterate(stadbState.db, stadbIterateCB, &params);
}

LBD_STATUS stadb_fini(void) {
    wlanif_unregisterChanChangeObserver(stadbChanChangeObserverCB,
                                        &stadbState);
    stadbHashTableDestroy(stadbState.db);
    stadbState.db = NULL;

    return LBD_OK;
}

void stadb_persist(const char *filename,
                   stadbEntry_jsonizeSteerExecCB_t jseCB) {
    json_t *root_j;
    json_t *devices_j;
    struct stadbJsonizeEntryCB_cookie cookie;

    root_j =
        json_pack("{s:i, s:[]}", "version", STADB_PERSIST_VERSION, "devices");

    if (root_j == NULL) {
        dbgf(stadbState.dbgModule, DBGERR,
             "%s: Failed to allocate device root.", __func__);
        return;
    }

    devices_j = json_object_get(root_j, "devices");
    if (devices_j == NULL || !json_is_array(devices_j)) {
        dbgf(stadbState.dbgModule, DBGERR,
             "%s: Failed to allocate devices array.", __func__);
        json_decref(root_j);
        return;
    }

    cookie.devices_j = devices_j;
    cookie.jseCB = jseCB;
    stadb_iterate(stadbJsonizeEntryCB, &cookie);

    if (json_dump_file(root_j, filename, JSON_INDENT(4) | JSON_SORT_KEYS) !=
            0) {
        dbgf(stadbState.dbgModule, DBGERR, "%s: Failed to write file %s",
             __func__, filename);
    }
    json_decref(root_j);

    stadbState.isDirty = LBD_FALSE;
}

void stadb_restore(const char *filename,
                   stadb_restoreSteerExecCB_t rseCB) {
    json_t *root_j, *devices_j, *device_j;
    json_error_t err;
    size_t index;

    root_j = json_load_file(filename, 0, &err);
    if (root_j == NULL) {
        dbgf(stadbState.dbgModule, DBGERR,
             "%s: Didn't get valid json from %s: %s", __func__, filename,
             err.text);
        /* return without decref */
        return;
    }

    if (!json_is_object(root_j)) {
        dbgf(stadbState.dbgModule, DBGERR,
             "%s: Invalid root object while restoring stadb.", __func__);
        return;
    }

    devices_j = json_object_get(root_j, "devices");
    if (devices_j == NULL || !json_is_array(devices_j)) {
        dbgf(stadbState.dbgModule, DBGERR,
             "%s: Invalid devices array while restoring stadb.", __func__);
        goto errout;
    }

    for (index = 0; index < json_array_size(devices_j) &&
                        (device_j = json_array_get(devices_j, index));
         index++) {
        if (device_j != NULL && json_is_object(device_j)) {
            stadbCreateEntryFromJson(device_j, rseCB);
        }
    }

errout:
    json_decref(root_j);
}

void stadb_setDirty(void) {
    stadbState.isDirty = LBD_TRUE;
}

LBD_BOOL stadb_isDirty(void) {
    return stadbState.isDirty;
}

// ====================================================================
// Private helper functions
// ====================================================================

/**
 * @brief Read all of the configuration data from the file into the internal
 *        state.
 */
static void stadbReadConfig(void) {
    stadbState.config.includeOutOfNetwork =
        profileGetOptsInt(mdModuleID_StaDB, STADB_INCLUDE_OUT_OF_NETWORK_KEY,
                          stadbElementDefaultTable);

    stadbState.config.agingSizeThreshold =
        profileGetOptsInt(mdModuleID_StaDB, STADB_AGING_SIZE_THRESHOLD_KEY,
                          stadbElementDefaultTable);

    stadbState.config.agingFrequency =
        profileGetOptsInt(mdModuleID_StaDB, STADB_AGING_FREQUENCY_KEY,
                          stadbElementDefaultTable);

    stadbState.config.outOfNetworkMaxAge =
        profileGetOptsInt(mdModuleID_StaDB, STADB_OUT_OF_NETWORK_MAX_AGE,
                          stadbElementDefaultTable);

    stadbState.config.inNetworkMaxAge =
        profileGetOptsInt(mdModuleID_StaDB, STADB_IN_NETWORK_MAX_AGE,
                          stadbElementDefaultTable);

    stadbState.config.probeMaxInterval =
        profileGetOptsInt(mdModuleID_StaDB, STADB_PROBE_MAX_INTERVAL,
                          stadbElementDefaultTable);

    stadbState.config.markAdvClientAsDualBand =
        profileGetOptsInt(mdModuleID_StaDB, STADB_MARK_ADV_CLIENT_DUAL_BAND,
                          stadbElementDefaultTable);

    stadbState.config.populateNonServingPHY =
        profileGetOptsInt(mdModuleID_StaDB, STADB_POPULATE_NON_SERVING_PHY,
                          stadbElementDefaultTable);

    stadbState.numRemoteBSSStats =
        profileGetOptsInt(mdModuleID_StaDB, STADB_MAX_REMOTE_BSSES,
                          stadbElementDefaultTable);
}

/**
 * @brief Find the entry in the database with the matching MAC address,
 *        or allocate and insert a new entry if not found.
 *
 * @param [in] addr  the MAC address of the entry to find
 * @param [in] outOfNetwork  flag indicating whether the STA should be
 *                           considered out of network for this update;
 *                           if it is considered out of network, an entry
 *                           will only be created if storage of out of
 *                           network devices in the database is enabled
 * @param [in] rrmStatus  whether 802.11 Radio Resource Management is supported,
 *                        disabled, or unchanged from the current state.
 *                        If it becomes supported, will allocate BSS entries for
 *                        both local radios and remote radios; otherwise, will
 *                        only allocate BSS entries for local BSSes
 *
 * @return the handle to the entry, or NULL if the entry did not exist and
 *         one could not be created
 */
static stadbEntry_handle_t stadbFindOrInsertEntry(
        const struct ether_addr *addr, LBD_BOOL outOfNetwork,
        wlanif_capStateUpdate_e rrmStatus) {
    stadbEntry_handle_t entry =
        stadbHashTableFind(stadbState.db, addr);
    if (!entry && (!outOfNetwork || stadbState.config.includeOutOfNetwork)) {
        // Create a new STA entry
        entry = stadbEntryCreate(addr, !outOfNetwork, rrmStatus,
                                 stadbState.numRadiosLocal, stadbState.numRadiosLocal);
        if (!entry) {
            dbgf(stadbState.dbgModule, DBGERR, "%s: Failed to allocate "
                                               "new entry; dropping",
                 __func__);
            return NULL;
        }

        stadbHashTableInsert(stadbState.db, entry);

        // If the size is now at the limit where aging is required, start up
        // the timer.
        if (stadbHashTableGetSize(stadbState.db) ==
                stadbState.config.agingSizeThreshold) {
            evloopTimeoutRegister(&stadbState.agingTimeout,
                                  stadbState.config.agingFrequency,
                                  0 /* us */);
        }
    } else if ((!outOfNetwork && !stadbEntry_isInNetwork(entry)) ||
               (stadbIsMultiAP() && rrmStatus == wlanif_cap_enabled &&
                !stadbEntry_isRRMSupported(entry))) {
        stadbEntry_handle_t oldEntry = entry;

        // For an existing STA, if it becomes in-network or when it turns to support
        // 11k, need to update its entry type. Before doing so, delete the entry from
        // database, it will be added back if the new type entry is created successfully.
        stadbHashTableDelete(stadbState.db, entry);
        entry = stadbEntryChangeEntryType(entry, rrmStatus,
                                          stadbState.numRadiosLocal,
                                          stadbState.numRemoteBSSStats);
        if (!entry) {
            dbgf(stadbState.dbgModule, DBGERR,
                 "%s: Failed to convert " lbMACAddFmt(":") " to in-network STA",
                 __func__, lbMACAddData(addr->ether_addr_octet));
            return NULL;
        } else {
            dbgf(stadbState.dbgModule, DBGDEBUG,
                 "%s: Converted entry for " lbMACAddFmt(":")
                 " to in-network STA (old=%p, new=%p, rrm=%u)",
                 __func__, lbMACAddData(addr->ether_addr_octet),
                 oldEntry, entry, rrmStatus);
        }

        stadbHashTableInsert(stadbState.db, entry);
    }

    stadbEntrySetDirtyIfInNetwork(entry);
    return entry;
}

/**
 * @brief Record in the database the band and RSSI on which a STA was active .
 *
 * @param [in] addr  the MAC address of the STA
 * @param [in] band  the band on which the STA sent a packet
 * @param [in] rssi  the signal strength of the received packet
 * @param [in] reason  the reason for the RSSI update
 * @param [in] markAssociated  flag indicating if this update implies that the STA
 *                             is associated on the given band
 * @param [in] outOfNetwork  whether this update should be considered as for
 *                           a potentially out of network device; note that
 *                           this only is relevant if storage of out of network
 *                           devices in the database is disabled
 *
 * @return the handle for the STA entry
 */
static stadbEntry_handle_t stadbUpdateBandAndRSSI(const struct ether_addr *addr,
                                                  const lbd_bssInfo_t *bss,
                                                  u_int8_t rssi,
                                                  stadb_rssiUpdateReason_e reason,
                                                  LBD_BOOL markAssociated,
                                                  LBD_BOOL outOfNetwork) {
    // If the entry does not exist in the DB, create and add it (unless
    // storage of out of network devices is disabled).
    stadbEntry_handle_t entry =
        stadbFindOrInsertEntry(addr, outOfNetwork,
                               wlanif_cap_unchanged /* rrmStatus */);
    if (entry) {
        if (markAssociated) {
            // Not update activity status based on RSSI report
            stadbEntryMarkAssociated(entry, bss, LBD_TRUE, /* isAssociated */
                                     LBD_FALSE /* updateAct */,
                                     LBD_TRUE /* verifyAssociation */,
                                     NULL /* assocChanged */);
        }
        LBD_STATUS result = LBD_NOK;
        if (reason == stadb_rssiUpdateReason_probe) {
            result = stadbEntryRecordProbeRSSI(
                        entry, bss, rssi, stadbState.config.probeMaxInterval);
        } else {
            result = stadbEntryRecordRSSI(entry, bss, rssi);
        }
        if (LBD_OK == result) {
            stadbNotifyRSSIObservers(entry, reason);
        }
    }

    return entry;
}

/**
 * @brief Record in the database that the STA associated or disassociated on
 *        the specified band.
 *
 * @param [in] addr  the MAC address of the STA
 * @param [in] bss  the BSS on which the STA associated/disassociated
 * @param [in] btmStatus whether BTM support is enabled,
 *                       disabled, or unchanged from the current
 *                       state
 * @param [in] rrmStatus whether 802.11 Radio Resource Management is supported,
 *                       disabled, or unchanged from the current state
 * @param [in] isMUMIMOSupported  set to LBD_TRUE if MU-MIMO is
 *                                supported by the STA,
 *                                LBD_FALSE otherwise
 * @param [in] isStaticSMPS  whether the STA is operating in static SMPS mode
 * @param [in] phyCapInfo  PHY capability supported by the STA
 * @param [in] isAssoc  LBD_TRUE if it was an association; otherwise LBD_FALSE
 */
static void stadbUpdateAssoc(const struct ether_addr *addr,
                             const lbd_bssInfo_t *bss,
                             wlanif_capStateUpdate_e btmStatus,
                             wlanif_capStateUpdate_e rrmStatus,
                             LBD_BOOL isMUMIMOSupported,
                             LBD_BOOL isStaticSMPS,
                             const wlanif_phyCapInfo_t *phyCapInfo,
                             LBD_BOOL isAssoc) {
    // Association events always result in the device being considered in
    // network. It is possible this will not be the case as we do not
    // necessarily know that the device successfully completed the security
    // handshake, but this is our best guess.
    stadbEntry_handle_t entry =
        stadbFindOrInsertEntry(addr, LBD_FALSE /* outOfNetwork */,
                               rrmStatus);
    if (entry) {
        LBD_BOOL btmChanged = LBD_FALSE;
        // set whether or not BSS Transition Management is supported
        if (btmStatus != wlanif_cap_unchanged) {
            if (btmStatus == wlanif_cap_enabled) {
                stadbEntry_updateIsBTMSupported(entry, LBD_TRUE, &btmChanged);
            }
            else {
                stadbEntry_updateIsBTMSupported(entry, LBD_FALSE, &btmChanged);
            }
        }
        // set whether or not 11k Radio Resource Management is supported
        if (rrmStatus != wlanif_cap_unchanged) {
            if (rrmStatus == wlanif_cap_enabled) {
                stadbEntryUpdateIsRRMSupported(entry, LBD_TRUE);
            }
            else {
                stadbEntryUpdateIsRRMSupported(entry, LBD_FALSE);
            }
        }

        if (stadbState.config.markAdvClientAsDualBand &&
            stadbEntry_isBTMSupported(entry) &&
            stadbEntry_isRRMSupported(entry)) {
            // Mark 11k/v client as dual band
            stadbEntryMarkDualBandSupported(entry);
        }

        // Update activity status when asociation status changes
        stadbEntry_bssStatsHandle_t oldServingBSS =
            stadbEntry_getServingBSS(entry, NULL);
        const lbd_bssInfo_t *lastAssocBSS =
            stadbEntry_resolveBSSInfo(oldServingBSS);
        LBD_BOOL assocChanged;
        stadbEntryMarkAssociated(entry, bss, isAssoc,
                                 LBD_TRUE /* updateAct */,
                                 LBD_FALSE /* verifyAssociation */,
                                 &assocChanged);

        if (isAssoc) {
            // Update MU-MIMO mode
            stadbEntryUpdateMUMIMOMode(entry, isMUMIMOSupported);
        }

        // Update SMPS mode, PHY capability info and populate BSSes from
        // same ESS on association
        if (isAssoc && assocChanged) {
            stadbEntry_bssStatsHandle_t bssHandle =
                stadbEntry_getServingBSS(entry, NULL);
            stadbEntrySetPHYCapInfo(entry, bssHandle, phyCapInfo);
            wlanif_band_e requestedBand = wlanif_band_invalid;
            if (!stadbEntry_isDualBand(entry)) {
                // If not dual band capable, only request BSSes on the serving band
                requestedBand = wlanif_resolveBandFromChannelNumber(bss->channelId);
            }
            stadbEntryPopulateBSSesFromSameESS(entry, bss, requestedBand);

            // Update SMPS mode
            stadbEntryUpdateSMPSMode(entry, bss, isStaticSMPS);

            if (stadbState.config.populateNonServingPHY &&
                stadbEntry_isBTMSupported(entry) &&
                stadbEntry_isRRMSupported(entry)) {
                // Populate PHY info on non-serving band for 11k/v client
                stadbEntryPopulateNonServingPHYInfo(entry, bss, phyCapInfo);
            }
        }

        // Notify observers if BTM or association status changed
        if (assocChanged || btmChanged) {
            if (!assocChanged) {
                // Emit a diag log if only the BTM status updated
                // (if association status updated, log will already be
                // generated)
                stadbEntryAssocDiagLog(entry, bss);
            }

            stadbNotifyAssocObserver(entry, lastAssocBSS);
        }
    }
}

/**
 * @brief Notify all registered oberservers that the provided entry was
 *        updated.
 *
 * @param [in] entry  the entry that was updated
 * @param [in] reason  the reason for the RSSI update
 */
static void stadbNotifyRSSIObservers(stadbEntry_handle_t entry,
                                     stadb_rssiUpdateReason_e reason) {
    size_t i;
    for (i = 0; i < MAX_RSSI_OBSERVERS; ++i) {
        if (stadbState.rssiObservers[i].isValid) {
            stadbState.rssiObservers[i].callback(
                    entry, reason, stadbState.rssiObservers[i].cookie);
        }
    }
}

/**
 * @brief Notify all registered oberservers that the provided entry's
 *        association information was updated.
 *
 * @param [in] entry  the entry that was updated
 */
static void stadbNotifyAssocObserver(stadbEntry_handle_t entry,
                                     const lbd_bssInfo_t *lastAssocBSS) {
    if (stadbState.assocObserver.isValid) {
        stadbState.assocObserver.callback(
            entry, lastAssocBSS, stadbState.assocObserver.cookie);
    }
}

/**
 * @brief Notify all registered oberservers that the activity status of
 *        the provided entry was updated.
 *
 * @param [in] entry  the entry that was updated
 */
static void stadbNotifyActivityObservers(stadbEntry_handle_t entry) {
    if (stadbState.activityObserver.isValid) {
        stadbState.activityObserver.callback(
            entry, stadbState.activityObserver.cookie);
    }
}

/**
 * @brief Notify all registered oberservers that the RSSI of the provided entry
 *        crossed the low threshold.
 *
 * @param [in] entry  the entry that was updated
 */
static void stadbNotifyLowRSSIObservers(stadbEntry_handle_t entry) {
    if (stadbState.lowRSSIObserver.isValid) {
        stadbState.lowRSSIObserver.callback(
            entry, stadbState.lowRSSIObserver.cookie);
    }
}

/**
 * @brief React to an event indicating that a probe request was received.
 *
 * @param [in] event  the event received
 */
static void stadbHandleProbeReq(struct mdEventNode *event) {
    const wlanif_probeReqEvent_t *probeEvent =
        (const wlanif_probeReqEvent_t *) event->Data;

    stadbUpdateBandAndRSSI(&probeEvent->sta_addr,
                           &probeEvent->bss,
                           probeEvent->rssi, stadb_rssiUpdateReason_probe,
                           LBD_FALSE /* markAssociated */,
                           LBD_TRUE /* outOfNetwork */);
}

/**
 * @brief React to an event indicating than an authentication reject message
 *        was sent to a STA that tried to authenticate on a blacklisted
 *        band.
 *
 * @param [in] event  the event received
 */
static void stadbHandleAuthRej(struct mdEventNode *event) {
    const wlanif_authRejEvent_t *authEvent =
        (const wlanif_authRejEvent_t *) event->Data;

    // An auth reject should indicate the device was considered in network
    // at some point, as otherwise its MAC address would not have been in
    // the ACLs.
    stadbUpdateBandAndRSSI(&authEvent->sta_addr,
                           &authEvent->bss,
                           authEvent->rssi, stadb_rssiUpdateReason_authrej,
                           LBD_FALSE /* markAssociated */,
                           LBD_FALSE /* outOfNetwork */);
}

/**
 * @brief React to an event indicating a station associated or disassociated
 *        on a given band.
 *
 * @param [in] event  the event received
 */
static void stadbHandleAssoc(struct mdEventNode *event) {
    const wlanif_assocEvent_t *assocEvent =
        (const wlanif_assocEvent_t *) event->Data;

    stadbUpdateAssoc(&assocEvent->sta_addr,
                     &assocEvent->bss,
                     assocEvent->btmStatus, assocEvent->rrmStatus,
                     assocEvent->isMUMIMOSupported,
                     assocEvent->isStaticSMPS, &assocEvent->phyCapInfo,
                     event->EventID == wlanif_event_assoc);
}

/**
 * @brief React to an event indicating a station's activity status changed
 *        on a given band
 *
 * @param [in] event  the event received
 */
static void stadbHandleActChangeEvent(struct mdEventNode *event) {
    const wlanif_actChangeEvent_t *actChangeEvent =
        (const wlanif_actChangeEvent_t *) event->Data;

#ifdef LBD_DBG_MENU
    if (!stadbState.debugModeEnabled)
#endif
    {
        stadbHandleActChange(&actChangeEvent->sta_addr,
                             &actChangeEvent->bss,
                             actChangeEvent->active);
    }
}

/**
 * @brief Handle the activity status reported from activity change event
 *
 * @param [in] staAddr  the MAC address of the STA
 * @param [in] band  the band on which this event is received
 * @param [in] active  flag indicating the STA is active or not
 */
static void stadbHandleActChange(const struct ether_addr *staAddr,
                                 const lbd_bssInfo_t *bss,
                                 LBD_BOOL active) {
    stadbEntry_handle_t entry =
        stadbFindOrInsertEntry(staAddr, LBD_FALSE /* outOfNetwork */,
                               wlanif_cap_unchanged /* rrmStatus */);
    if (entry) {
        stadbEntryMarkActive(entry, bss, active);

        // Only notify the observers if the activity event occurred for
        // the currently associated band (which may have just been updated).
        stadbEntry_bssStatsHandle_t servingBSS = stadbEntry_getServingBSS(entry, NULL);
        if (servingBSS &&
            lbAreBSSesSame(stadbEntry_resolveBSSInfo(servingBSS), bss)) {
            stadbNotifyActivityObservers(entry);
        }
    }
}

/**
 * @brief Handle the sta disallow/allow steering  from stadb nosteer command
 *
 * @param [in] staAddr  the MAC address of the STA
 * @param [in] active  flag indicating whether steering is disallowed/allow
 *             for this STA
 */
static void stadbHandleSteerChange(const struct ether_addr *staAddr,
                                 LBD_BOOL active) {
    stadbEntry_handle_t entry =
        stadbFindOrInsertEntry(staAddr, LBD_TRUE /* outOfNetwork */,
                               wlanif_cap_unchanged /* rrmStatus */);
    if (entry) {
        if (active != entry->isSteeringDisallowed) {
            stadbEntrySetDirtyIfInNetwork(entry);
        }

        if (active) {
            entry->isSteeringDisallowed = LBD_TRUE;
        }
        else {
            entry->isSteeringDisallowed = LBD_FALSE;
        }
    }
}


/**
 * @brief React to an event indicating the requested RSSI measurement is available
 *
 * @param [in] event  the event received
 */
static void stadbHandleRSSIMeasurementEvent(struct mdEventNode *event) {
    const wlanif_rssiMeasurementEvent_t *rssiMeasurementEvent =
        (const wlanif_rssiMeasurementEvent_t *) event->Data;

#ifdef LBD_DBG_MENU
    if (!stadbState.debugModeEnabled)
#endif
    {
        stadbHandleRSSIMeasurement(&rssiMeasurementEvent->sta_addr,
                                   &rssiMeasurementEvent->bss,
                                   rssiMeasurementEvent->rssi);
    }
}

/**
 * @brief Handle requested RSSI measurement result
 *
 * For valid RSSI measurement, update RSSI and band info.
 *
 * @param [in] staAddr  the MAC address of the STA
 * @param [in] band  the band on which this measurement is taken
 * @param [in] rssi  the RSSI measurement
 */
static void stadbHandleRSSIMeasurement(const struct ether_addr *staAddr,
                                       const lbd_bssInfo_t *bss,
                                       u_int8_t rssi) {

    if (rssi == LBD_INVALID_RSSI) {
        // Observers are not informed about INVALID_RSSI, as they are expected to
        // rely on other RSSI updates, e.g RSSI crossing event, probe request
        dbgf(stadbState.dbgModule, DBGERR,
             "%s: Invalid RSSI measurement for "lbMACAddFmt(":"),
             __func__, lbMACAddData(staAddr->ether_addr_octet));
        return;
    } else {
        stadbUpdateBandAndRSSI(staAddr, bss, rssi,
                               stadb_rssiUpdateReason_measurement,
                               LBD_TRUE /* markAssociated */,
                               LBD_FALSE /* outOfNetwork */);
    }
}

/**
 * @brief React to an event indicating the RSSI measurement crossed thresholds
 *
 * @param [in] event  the event received
 */
static void stadbHandleRSSIXingEvent(struct mdEventNode *event) {
    const wlanif_rssiXingEvent_t *rssiXingEvent =
        (const wlanif_rssiXingEvent_t *) event->Data;

#ifdef LBD_DBG_MENU
    if (!stadbState.debugModeEnabled)
#endif
    {
        stadbHandleRSSIXing(&rssiXingEvent->sta_addr,
                            &rssiXingEvent->bss,
                            rssiXingEvent->rssi,
                            rssiXingEvent->lowRSSIXing);
    }
}

/**
 * @brief Handle the RSSI information from RSSI crossing event
 *
 * @param [in] staAddr  the MAC address of the STA
 * @param [in] band  the band on which this event is received
 * @param [in] rssi  the RSSI measurement
 */
static void stadbHandleRSSIXing(const struct ether_addr *staAddr,
                                const lbd_bssInfo_t *bss,
                                u_int8_t rssi,
                                wlanif_xingDirection_e lowXing) {
    stadbEntry_handle_t entry =
        stadbUpdateBandAndRSSI(staAddr, bss, rssi,
                               stadb_rssiUpdateReason_crossing,
                               LBD_TRUE /* markAssociated */,
                               LBD_FALSE /* outOfNetwork */);

    if (entry && lowXing == wlanif_xing_down) {
        stadbNotifyLowRSSIObservers(entry);
    }
}

/**
 * @brief Reset the association information for the entry in the database.
 *
 * If the entry is not associated, this does nothing.
 *
 * @param [in] entry  the entry to reset
 * @param [in] cookie  unused
 */
static void stadbIterateResetAssoc(stadbEntry_handle_t entry, void *cookie) {
    stadbEntry_bssStatsHandle_t bssHandle = stadbEntry_getServingBSS(entry, NULL);
    if (bssHandle) {
        stadbEntryMarkAssociated(entry,
                                 stadbEntry_resolveBSSInfo(bssHandle),
                                 LBD_FALSE /* isAssociated */,
                                 LBD_FALSE /* updateActive */,
                                 LBD_FALSE /* verifyAssociation */,
                                 NULL /* assocChanged */);
    }
}

/**
 * @brief React to a change in the band steering state.
 *
 * @param [in] event  the event carrying the band steering state
 */
static void stadbHandleBandSteeringStateEvent(struct mdEventNode *event) {
    const wlanif_bandSteeringStateEvent_t *stateEvent =
        (const wlanif_bandSteeringStateEvent_t *) event->Data;

    if (!stateEvent->enabled) {
        // For now we do not do anything on a disable (and in fact wlanif
        // does not even generate a disabled event).
        return;
    }

    // Iterate over hash table and mark all STAs as no longer
    // associated. Then dump the information to start afresh.
    if (stadb_iterate(stadbIterateResetAssoc, NULL) == LBD_NOK ||
        wlanif_dumpAssociatedSTAs(stadbDumpAssociatedSTAsCB,
                                  &stadbState) != LBD_OK) {
        dbgf(stadbState.dbgModule, DBGERR,
             "%s: Failed to re-populate stadb association info",
             __func__);
    } else {
        dbgf(stadbState.dbgModule, DBGINFO,
             "%s: stadb populated with currently associated STAs",
             __func__);
    }
}

/**
 * @brief React to an event indicating SM Power Save mode update received
 *
 * @param [in] event  the event received
 */
static void stadbHandleSMPSUpdateEvent(struct mdEventNode *event) {
    const wlanif_smpsUpdateEvent_t *smpsUpdate =
        (const wlanif_smpsUpdateEvent_t *) event->Data;

    // If the entry does not exist in the DB, create and add it (unless
    // storage of out of network devices is disabled).
    stadbEntry_handle_t entry =
        stadbFindOrInsertEntry(&smpsUpdate->sta_addr, LBD_TRUE /* outOfNetwork */,
                               wlanif_cap_unchanged /* rrmStatus */);
    if (entry) {
        if (LBD_NOK == stadbEntryUpdateSMPSMode(entry, &smpsUpdate->bss,
                                                smpsUpdate->isStatic)) {
            dbgf(stadbState.dbgModule, DBGERR,
                 "%s: Failed to update SM Power Saving Mode for " lbMACAddFmt(":"),
                 __func__, lbMACAddData(smpsUpdate->sta_addr.ether_addr_octet));
        }
    }
}

/**
 * @brief React to an event indicating Operating Mode update received
 *
 * @param [in] event  the event received
 */
static void stadbHandleOpModeUpdateEvent(struct mdEventNode *event) {
    const wlanif_opmodeUpdateEvent_t *opmodeUpdate =
        (const wlanif_opmodeUpdateEvent_t *) event->Data;

    stadbEntry_handle_t entry = stadb_find(&opmodeUpdate->sta_addr);
    if (LBD_NOK == stadbEntryUpdateOpMode(entry, &opmodeUpdate->bss,
                                          opmodeUpdate->maxChWidth,
                                          opmodeUpdate->numStreams)) {
        dbgf(stadbState.dbgModule, DBGERR,
             "%s: Failed to update Operating Mode for " lbMACAddFmt(":")
             " on " lbBSSInfoAddFmt(),
             __func__, lbMACAddData(opmodeUpdate->sta_addr.ether_addr_octet),
             lbBSSInfoAddData(&opmodeUpdate->bss));
    }
}

/**
 * @brief Process a single associated STA entry in the dump of all currently
 *        associated STAs.
 *
 * @param [in] addr  the MAC address of the STA
 * @param [in] bss  the BSS on which the STA is associated
 * @param [in] isBTMSupported set to LBD_TRUE if BTM is enabled,
 *                            LBD_FALSE otherwise
 * @param [in] isRRMSupported set to LBD_TRUE if RRM is enabled,
 *                            LBD_FALSE otherwise
 * @param [in] isMUMIMOSupported  set to LBD_TRUE if MU-MIMO is
 *                                supported by the STA,
 *                                LBD_FALSE otherwise
 * @param [in] isStaticSMPS  set to LBD_TRUE if STA is operating in static SMPS mode
 * @param [in] phyCapInfo  PHY capabilities supported by this STA
 * @param [in] cookie  the stadb state provided when request the STAs dump,
 *                     currently not used
 */
static void stadbDumpAssociatedSTAsCB(const struct ether_addr *addr,
                                      const lbd_bssInfo_t *bss,
                                      LBD_BOOL isBTMSupported,
                                      LBD_BOOL isRRMSupported,
                                      LBD_BOOL isMUMIMOSupported,
                                      LBD_BOOL isStaticSMPS,
                                      const wlanif_phyCapInfo_t *phyCapInfo,
                                      void *cookie) {
    stadbUpdateAssoc(addr, bss,
                     isBTMSupported ? wlanif_cap_enabled : wlanif_cap_disabled,
                     isRRMSupported ? wlanif_cap_enabled : wlanif_cap_disabled,
                     isMUMIMOSupported,
                     isStaticSMPS, phyCapInfo, LBD_TRUE /* isAssoc */);
}

/**
 * @brief Process each STA entry in the database, checking if it should be
 *        aged out.
 *
 * @param [in] handle  the handle to the complete station database
 * @param [in] entry  the STA entry to examine
 * @param [in] cookie  the cookie provided for iteration (not used)
 *
 * @return LBD_TRUE if the entry should be deleted; otherwise LBD_FALSE
 */
static LBD_BOOL stadbCheckEntryAge(stadbHashTableHandle_t handle,
                                   stadbEntry_handle_t entry,
                                   void *cookie) {
    // This should never fail, but we are being defensive here.
    time_t ageSecs;
    if (stadbEntry_getAge(entry, &ageSecs) != LBD_OK) {
        return LBD_FALSE;
    }

    const char *deviceType;
    enum dbgLevel level;
    LBD_BOOL doRemove = LBD_FALSE;

    //if STA steering flag is set to true, do not remove this entry.
    //As customer cannot reset it again.
    if (stadbEntry_isSteeringDisallowed(entry)){
        return doRemove;
    }

    // For out-of-network entries, the only condition for removal is that
    // their age exceeds the threshold.
    //
    // In-network entries must not be currently associated (in addition to
    // their age exceeding the threshold).
    if (!stadbEntry_isInNetwork(entry) &&
        ageSecs >= stadbState.config.outOfNetworkMaxAge) {
        deviceType = "out-of-network";
        level = DBGDEBUG;
        doRemove = LBD_TRUE;
    } else if (stadbEntry_isInNetwork(entry) &&
               stadbEntry_getAssociatedBand(entry, NULL) ==
               wlanif_band_invalid &&
               ageSecs >= stadbState.config.inNetworkMaxAge) {
        deviceType = "in-network";
        level = DBGINFO;
        doRemove = LBD_TRUE;
    }

    if (doRemove) {
        const struct ether_addr *addr = stadbEntry_getAddr(entry);

        dbgf(stadbState.dbgModule, level,
             "%s: Removing %s device " lbMACAddFmt(":")
             " due to age", __func__, deviceType,
             lbMACAddData(addr->ether_addr_octet));
    }

    return doRemove;
}

/**
 * @brief React to the aging timeout by sweeping over the database, looking
 *        for STAs that should be aged out.
 *
 * @param [in] cookie  the cookie provided when the timeout was created
 */
static void stadbAgingTimeoutHandler(void *cookie) {
    stadbHashTableIterate(stadbState.db, stadbCheckEntryAge, cookie);

    if (stadbHashTableGetSize(stadbState.db) >=
            stadbState.config.agingSizeThreshold) {
        evloopTimeoutRegister(&stadbState.agingTimeout,
                              stadbState.config.agingFrequency,
                              0 /* us */);
    }
}

/**
 * @brief Process one entry in the database during iteration.
 *
 * @param [in] table  the table over which the iteration is happening
 * @param [in] cookie  the wrapped parameters from the stadb_iterate()
 *                     invocation
 *
 * @return LBD_FALSE always (to signal no entry should be deleted)
 */
static LBD_BOOL stadbIterateCB(stadbHashTableHandle_t table,
                               stadbEntry_handle_t entry,
                               void *cookie) {
    stadbIterateParams_t *iterateParams = (stadbIterateParams_t *) cookie;
    iterateParams->callback(entry, iterateParams->cookie);
    return LBD_FALSE;  // no deletes allowed through this function
}

/**
 * @brief Process a single reserved airtime entry in the dump of ATF table.
 *
 * @param [in] addr  the MAC address of the STA
 * @param [in] bss  the BSS on which the airtime is reserved for this STA
 * @param [in] airtime  the reserved airtime for this STA
 * @param [in] cookie  the stadb state provided when request the ATF dump,
 *                     currently not used
 */
static void stadbDumpReservedAirtimeCB(const struct ether_addr *addr,
                                       const lbd_bssInfo_t *bss,
                                       lbd_airtime_t airtime,
                                       void *cookie) {
    lbDbgAssertExit(stadbState.dbgModule,
                    addr && bss && airtime != LBD_INVALID_AIRTIME);

    dbgf(stadbState.dbgModule, DBGINFO,
         "%s: " lbMACAddFmt(":") " with reserved airtime %u on " lbBSSInfoAddFmt(),
         __func__, lbMACAddData(addr->ether_addr_octet), airtime, lbBSSInfoAddData(bss));

    stadbEntry_handle_t entry =
        stadbFindOrInsertEntry(addr, LBD_FALSE /* outOfNetwork */,
                               wlanif_cap_unchanged /* rrmStatus */);
    if (entry) {
        stadbEntryAddReservedAirtime(entry, bss, airtime);
    }
}

/**
 * @brief Parameters used for iterating station database to handle
 *        channel change
 */
typedef struct stadbChannelChangeParams_t {
    /// The handle to the VAP on which channel change occurs
    lbd_vapHandle_t vap;
    /// The new channel ID
    lbd_channelId_t channelId;
} stadbChannelChangeParams_t;

/**
 * @brief Process each STA entry in the database, handling channel change
 *
 * @param [in] handle  the handle to the complete station database
 * @param [in] entry  the STA entry to examine
 * @param [in] cookie  the cookie provided for iteration
 *
 * @return LBD_FALSE since the entry should not be deleted
 */
static LBD_BOOL stadbUpdateEntryForChannelChange(stadbHashTableHandle_t handle,
                                                 stadbEntry_handle_t entry,
                                                 void *cookie) {
    const stadbChannelChangeParams_t *params =
        (const stadbChannelChangeParams_t *)cookie;
    stadbEntryHandleChannelChange(entry, params->vap, params->channelId);
    return LBD_FALSE;
}

/**
 * @brief Callback function to handle channel change notification
 *
 * @see wlanif_chanChangeObserverCB
 */
static void stadbChanChangeObserverCB(lbd_vapHandle_t vap,
                                      lbd_channelId_t channelId,
                                      void *cookie) {
    if (!vap || channelId == LBD_CHANNEL_INVALID) {
        dbgf(stadbState.dbgModule, DBGERR,
             "%s: Invalid information provided in channel change callback "
             "function: vap %p; channel %u", __func__, vap, channelId);
        return;
    }
    stadbChannelChangeParams_t params = {
        vap, channelId
    };
    stadbHashTableIterate(stadbState.db, stadbUpdateEntryForChannelChange, &params);
}

#ifdef LBD_DBG_MENU

static const char *stadbMenuStatusHelp[] = {
    "s -- print station database contents",
    "Usage:",
    "\ts: display only in-network nodes",
    "\ts out: display only out-of-network nodes",
    "\ts bss: display BSSes supported, with RSSI and reserved airtime info",
    "\ts phy: display PHY capabilities for in-network nodes",
    "\ts rate: display measured and estimated rates for in-network nodes",
    "\ts <mac>: display all information for the provided MAC address",
    NULL
};

/**
 * @brief String representation of different types of detailed info of a STA
 */
static const char *stadbDBGInfoStr[] = {
    "phy",
    "bss",
    "measured rate",
    "estimated rate",

    "" // Invalid
};

/**
 * @brief Resolve the STA entry based on the MAC address provided in the command
 *
 * @param [in] context  the context to print error message if any
 * @param [in] cmd  the command string containing MAC address
 * @param [in] subCmd  the caller sub-command, i.e 'phy', 'rssi'
 * @param [out] notFound  this is set to LBD_TRUE if a valid MAC address is provided
 *                        in the command but cannot find the STA entry from database
 *
 * @return the handle to the resolved STA, or NULL if no valid MAC address is
 *         provided in the command or no STA entry found
 */
static stadbEntry_handle_t stadbResolveEntryFromCmd(struct cmdContext *context,
                                                    const char *cmd,
                                                    stadbEntryDBGInfoType_e infoType,
                                                    LBD_BOOL *notFound) {
    const char *arg = cmdWordNext(cmd);
    stadbEntry_handle_t entry = NULL;
    if (arg == NULL) {
        return entry;
    }
    const struct ether_addr *staAddr = ether_aton(arg);
    *notFound = LBD_FALSE;
    if (staAddr) {
        entry = stadb_find(staAddr);
        if (!entry) {
            cmdf(context, "'stadb s %s' unknown MAC address: "
                          lbMACAddFmt(":") "\n",
                 stadbDBGInfoStr[infoType],
                 lbMACAddData(staAddr->ether_addr_octet));
            *notFound = LBD_TRUE;
        }
    }
    // If the argument is not a valid MAC address, print all entries
    return entry;
}

/**
 * @brief Print detailed info of stadb status
 *
 * @pre the type of detailed info is valid
 *
 * @param [in] context  the output stream to print
 * @param [in] cmd  the command string
 * @param [in] infoType  the type of detailed info
 */
static void stadbPrintStatusDetail(struct cmdContext *context, const char *cmd,
                                   stadbEntryDBGInfoType_e infoType) {
    LBD_BOOL notFound = LBD_TRUE;
    stadbEntry_handle_t entry = stadbResolveEntryFromCmd(context, cmd, infoType, &notFound);
    if (entry) {
        stadbEntryPrintDetailHeader(context, infoType, LBD_FALSE /* listAddr */);
        stadbEntryPrintDetail(context, entry, infoType, LBD_FALSE /* listAddr */);
    } else if (!notFound) {
        stadbHashTablePrintDetail(stadbState.db, context, infoType);
    }
}

#ifndef GMOCK_UNIT_TESTS
static
#endif
void stadbMenuStatusHandler(struct cmdContext *context,
                            const char *cmd) {
    stadbEntryDBGInfoType_e infoType = stadbEntryDBGInfoType_invalid,
                            extraRateInfoType = stadbEntryDBGInfoType_invalid;
    const char *arg = cmdWordFirst(cmd);

    if (!arg) {
        return;
    }
    if (!strlen(arg)) {
        stadbHashTablePrintSummary(stadbState.db, context, LBD_TRUE /* inNetworkOnly */);
    } else if (strncmp("out", arg, 3) == 0) {
        stadbHashTablePrintSummary(stadbState.db, context, LBD_FALSE /* inNetworkOnly */);
    } else if (strncmp("phy", arg, 3) == 0) {
        infoType = stadbEntryDBGInfoType_phy;
    } else if (strncmp("bss", arg, 3) == 0) {
        infoType = stadbEntryDBGInfoType_bss;
    } else if (strncmp("rate", arg, 4) == 0) {
        infoType = stadbEntryDBGInfoType_rate_measured;
        extraRateInfoType = stadbEntryDBGInfoType_rate_estimated;
    } else {
        const struct ether_addr *staAddr = ether_aton(arg);
        stadbEntry_handle_t entry = stadb_find(staAddr);
        if (entry) {
            // Print all detailed info
            stadbEntryDBGInfoType_e infoType;
            for (infoType = 0; infoType < stadbEntryDBGInfoType_invalid; ++infoType) {
                cmdf(context, "\n%s\n", stadbDBGInfoStr[infoType]);
                stadbEntryPrintDetailHeader(context, infoType, LBD_FALSE /* listAddr */);
                stadbEntryPrintDetail(context, entry, infoType, LBD_FALSE /* listAddr */);
            }
        } else {
            cmdf(context, "'stadb s' invalid parameter: %s\n", arg);
        }
        return;
    }

    if (infoType < stadbEntryDBGInfoType_invalid) {
        stadbPrintStatusDetail(context, cmd, infoType);
    }
    if (extraRateInfoType < stadbEntryDBGInfoType_invalid) {
        cmdf(context, "\nEstimated rate info:\n");
        stadbPrintStatusDetail(context, cmd, extraRateInfoType);
    }
}

static const char *stadbMenuDebugHelp[] = {
    "d -- enable/disable station database debug mode",
    "Usage:",
    "\td on: enable debug mode (ignore RSSI/Activity status update)",
    "\td off: disable debug mode (handling RSSI/Activity status update)",
    NULL
};

#ifndef GMOCK_UNIT_TESTS
static
#endif
void stadbMenuDebugHandler(struct cmdContext *context, const char *cmd) {
    LBD_BOOL isOn = LBD_FALSE;
    const char *arg = cmdWordFirst(cmd);

    if (!arg) {
        cmdf(context, "stadb 'd' command requires on/off argument\n");
        return;
    }

    if (cmdWordEq(arg, "on")) {
        isOn = LBD_TRUE;
    } else if (cmdWordEq(arg, "off")) {
        isOn = LBD_FALSE;
    } else {
        cmdf(context, "stadb 'd' command: invalid arg '%s'\n", arg);
        return;
    }

    dbgf(stadbState.dbgModule, DBGINFO, "%s: Setting debug mode to %u",
         __func__, isOn);
    stadbState.debugModeEnabled = isOn;
}

static const char *stadbMenuRSSIHelp[] = {
    "rssi -- inject an RSSI measurement",
    "Usage:",
    "\trssi <mac_addr> <value> [low-xing <direction>]: inject RSSI <value> for the <mac_addr> station on the associated channel\n"
    "\t                                                Optionally inject RSSI crossing low threshold event",
    NULL
};

/**
 * @brief Get the lbd_bssInfo_t for the serving BSS for this STA
 *
 * @param context 'this' pointer
 * @param staAddr STA address to retrieve serving BSS info for
 *
 * @return lbd_bssInfo_t* serving BSS info if associated, NULL
 *                        otherwise
 */
static const lbd_bssInfo_t *stadbMenuGetServingBSS(struct cmdContext *context,
                                                   const struct ether_addr *staAddr) {
    // Lookup the STA
    stadbEntry_handle_t handle  = stadb_find(staAddr);
    if (!handle) {
        cmdf(context, "Error, STA not found\n");
        return NULL;
    }

    // Get the association
    stadbEntry_bssStatsHandle_t servingBSS =
        stadbEntry_getServingBSS(handle, NULL);
    if (!servingBSS) {
        cmdf(context, "Error, command requires STA to be associated\n");
        return NULL;
    }

    return stadbEntry_resolveBSSInfo(servingBSS);
}

#ifndef GMOCK_UNIT_TESTS
static
#endif
void stadbMenuRSSIHandler(struct cmdContext *context, const char *cmd) {
    const char *arg = cmdWordFirst(cmd);

    if (!stadbState.debugModeEnabled) {
        cmdf(context, "stadb 'rssi' command not allowed unless debug mode "
                      "is enabled\n");
        return;
    }

    if (!arg) {
        cmdf(context, "stadb 'rssi' command missing MAC address");
        return;
    }

    const struct ether_addr *staAddr = ether_aton(arg);
    if (!staAddr) {
        cmdf(context, "stadb 'rssi' command invalid MAC address: %s\n", arg);
        return;
    }

    arg = cmdWordNext(arg);
    if (!cmdWordDigits(arg)) {
        cmdf(context, "stadb 'rssi' command invalid rssi: '%s'\n",
             arg);
        return;
    }

    int rssi = atoi(arg);
    const int STADB_DBG_MAX_RSSI = 95;
    if (rssi > STADB_DBG_MAX_RSSI) {
        cmdf(context, "stadb 'rssi' command RSSI value must be "
                      "between %d and %d\n",
             LBD_INVALID_RSSI, STADB_DBG_MAX_RSSI);
        return;
    }

    // Get the BSS this STA is associated to
    const lbd_bssInfo_t *bss = stadbMenuGetServingBSS(context, staAddr);
    if (!bss) {
        return;
    }

    arg = cmdWordNext(arg);
    if (!cmdWordEq(arg, "low-xing")) {
        // RSSI measurement event
        dbgf(stadbState.dbgModule, DBGINFO,
             "%s: Spoofing RSSI measurement: %s", __func__, cmd);
        stadbHandleRSSIMeasurement(staAddr, bss, rssi);
    } else {
        // RSSI Xing event
        wlanif_xingDirection_e low;
        arg = cmdWordNext(arg);
        if (LBD_NOK == convertCmdToRSSIXingDirection(context, arg, &low)) {
            return;
        }

        dbgf(stadbState.dbgModule, DBGINFO,
             "%s: Spoofing RSSI crossing: %s", __func__, cmd);
        stadbHandleRSSIXing(staAddr, bss, rssi, low);
    }
}

/**
 * @brief Resolve RSSI xing direction from command
 *
 * @param [in] context  the output context
 * @param [in] cmd  the command in the debug CLI containing RSSI xing direction
 * @param [out] direction  the resolved direction
 *
 * @return LBD_OK if the direction is resolve properly; otherwise LBD_NOK
 */
static LBD_STATUS convertCmdToRSSIXingDirection(struct cmdContext *context,
                                                const char* arg,
                                                wlanif_xingDirection_e *direction) {
    if(cmdWordLen(arg) != 1) {
        cmdf(context, "stadb 'rssi' command invalid xing direction: '%s': "
                      "expect 0 (unchanged) | 1 (up) | 2 (down)\n",
             arg);
            return LBD_NOK;
    }

    switch (arg[0]) {
        case '0':
            *direction = wlanif_xing_unchanged;
            break;
        case '1':
            *direction = wlanif_xing_up;
            break;
        case '2':
            *direction = wlanif_xing_down;
            break;
        default:
            cmdf(context, "stadb 'rssi' command invalid xing direction: '%c': "
                          "expect 0 (unchanged) | 1 (up) | 2 (down)",
                 arg[0]);
            return LBD_NOK;
    }

    return LBD_OK;
}

static const char *stadbMenuNoSteerHelp[] = {
    "nosteer -- control whether steering is disallowed for a STA",
    "Usage:",
    "\tnosteer <mac_addr> <1|0>: disallow/allow steering (respectively) for <mac_addr>",
    NULL
};


static const char *stadbMenuActivityHelp[] = {
    "act -- inject an activity status",
    "Usage:",
    "\tact <mac_addr> <1|0>: inject activity status for the <mac_addr> station on the associated channel",
    NULL
};

#ifndef GMOCK_UNIT_TESTS
static
#endif
void stadbMenuNoSteerHandler(struct cmdContext *context, const char *cmd) {
    const char *arg = cmdWordFirst(cmd);


    if (!arg) {
        cmdf(context, "stadb 'nosteer' command missing MAC address");
        return;
    }

    const struct ether_addr *staAddr = ether_aton(arg);
    if (!staAddr) {
        cmdf(context, "stadb 'nosteer' command invalid MAC address: %s\n", arg);
        return;
    }

    arg = cmdWordNext(arg);
    if (cmdWordLen(arg) != 1) {
        cmdf(context, "stadb 'nosteer' command invalid activity status - "
                      "expected '1|0'\n");
        return;
    }

    char actChar = arg[0];
    LBD_BOOL active;
    switch (actChar) {
        case '1':
            active = LBD_TRUE;
            break;

        case '0':
            active = LBD_FALSE;
            break;

        default:
            cmdf(context, "stadb 'nosteer' command invalid activity status '%c'\n",
                actChar);
            return;
    }

    dbgf(stadbState.dbgModule, DBGINFO,
         "%s: STA nosteering change: %s %s for STA"lbMACAddFmt(":")"\r\n", __func__,
          cmd,active?"Disallow steering":"Allow steering",
          lbMACAddData(staAddr->ether_addr_octet));
    stadbHandleSteerChange(staAddr, active);
}


#ifndef GMOCK_UNIT_TESTS
static
#endif
void stadbMenuActivityHandler(struct cmdContext *context, const char *cmd) {
    const char *arg = cmdWordFirst(cmd);

    if (!stadbState.debugModeEnabled) {
        cmdf(context, "stadb 'act' command not allowed unless debug mode "
                      "is enabled\n");
        return;
    }

    if (!arg) {
        cmdf(context, "stadb 'act' command missing MAC address");
        return;
    }

    const struct ether_addr *staAddr = ether_aton(arg);
    if (!staAddr) {
        cmdf(context, "stadb 'act' command invalid MAC address: %s\n", arg);
        return;
    }

    arg = cmdWordNext(arg);
    if (cmdWordLen(arg) != 1) {
        cmdf(context, "stadb 'act' command invalid activity status - "
                      "expected '1|0'\n");
        return;
    }

    char actChar = arg[0];
    LBD_BOOL active;
    switch (actChar) {
        case '1':
            active = LBD_TRUE;
            break;

        case '0':
            active = LBD_FALSE;
            break;

        default:
            cmdf(context, "stadb 'act' command invalid activity status '%c'\n",
                actChar);
            return;
    }

    // Get the BSS this STA is associated to
    const lbd_bssInfo_t *bss = stadbMenuGetServingBSS(context, staAddr);
    if (!bss) {
        return;
    }

    dbgf(stadbState.dbgModule, DBGINFO,
         "%s: Spoofing inactivity change: %s", __func__, cmd);
    stadbHandleActChange(staAddr, bss, active);
}

static const char *stadbMenuDiaglogHelp[] = {
    "diaglog -- generate diaglog message",
    "Usage:",
    "\tdiaglog assoc: generate association update log for all associated STAs",
    NULL
};

/**
 * @brief Callback function to generate association diaglog for all associated STAs
 *
 * @param [in] entry  the entry to generate diaglog if associated
 * @param [in] cookie  not used
 */
static void stadbDiaglogAssocCallback(stadbEntry_handle_t entry, void *cookie) {
    stadbEntry_bssStatsHandle_t servingBSS =
        stadbEntry_getServingBSS(entry, NULL);
    if (!servingBSS) { return; }

    const lbd_bssInfo_t *bssInfo = stadbEntry_resolveBSSInfo(servingBSS);
    lbDbgAssertExit(stadbState.dbgModule, bssInfo);
    stadbEntryAssocDiagLog(entry, bssInfo);
}

#ifndef GMOCK_UNIT_TESTS
static
#endif
void stadbMenuDiaglogHandler(struct cmdContext *context, const char *cmd) {
    const char *arg = cmdWordFirst(cmd);
#define DIAGLOG_ASSOC "assoc"
    if (!arg) {
        cmdf(context, "stadb 'diaglog' command requires one argument\n");
        return;
    }
    if (strncmp(DIAGLOG_ASSOC, arg, strlen(DIAGLOG_ASSOC)) == 0) {
        if (stadb_iterate(stadbDiaglogAssocCallback, NULL) == LBD_NOK) {
            cmdf(context, "'diaglog %s': Failed to iterate stadb\n", arg);
        }
    } else {
        cmdf(context, "stadb 'diaglog' unknown command: %s\n", arg);
    }
#undef DIAGLOG_ASSOC
}

static const struct cmdMenuItem stadbMenu[] = {
    CMD_MENU_STANDARD_STUFF(),
    { "s", stadbMenuStatusHandler, NULL, stadbMenuStatusHelp },
    { "d", stadbMenuDebugHandler, NULL, stadbMenuDebugHelp },
    { "rssi", stadbMenuRSSIHandler, NULL, stadbMenuRSSIHelp },
    { "act", stadbMenuActivityHandler, NULL, stadbMenuActivityHelp },
    { "nosteer", stadbMenuNoSteerHandler, NULL, stadbMenuNoSteerHelp },
    { "diaglog", stadbMenuDiaglogHandler, NULL, stadbMenuDiaglogHelp },
    CMD_MENU_END()
};

static const char *stadbMenuHelp[] = {
    "stadb -- Station Database",
    NULL
};

static const struct cmdMenuItem stadbMenuItem = {
    "stadb",
    cmdMenu,
    (struct cmdMenuItem *) stadbMenu,
    stadbMenuHelp
};

#endif /* LBD_DBG_MENU */

static void stadbMenuInit(void) {
#ifdef LBD_DBG_MENU
    cmdMainMenuAdd(&stadbMenuItem);
#endif /* LBD_DBG_MENU */
}

static void stadbJsonizeEntryCB(stadbEntry_handle_t entry, void *cookie) {
    struct stadbJsonizeEntryCB_cookie *jc = cookie;
    json_t *entry_j;
    json_t *devices_j = jc->devices_j;

    if (entry == NULL) {
        dbgf(stadbState.dbgModule, DBGERR,
             "%s: bad device arg to stadbJsonizeEntryCB", __func__);
        return;
    }

    if (!stadbEntry_isInNetwork(entry)) {
        /* Only serialize in-network entries */
        return;
    }

    if (devices_j == NULL) {
        dbgf(stadbState.dbgModule, DBGERR,
             "%s: stadbJsonizeEntryCB: no devices object", __func__);
        return;
    }

    if (!json_is_array(devices_j)) {
        dbgf(stadbState.dbgModule, DBGERR,
             "%s: stadbJsonizeEntryCB: invalid devices object", __func__);
        return;
    }

    entry_j = stadbEntryJsonize(entry, jc->jseCB);
    if (entry_j != NULL) {
        if (json_array_append_new(devices_j, entry_j)) {
            dbgf(stadbState.dbgModule, DBGERR, "%s: couldn't append device",
                 __func__);
        }
    } else {
        dbgf(stadbState.dbgModule, DBGERR, "%s: failed to jsonize device",
             __func__);
    }
}

static void stadbRestorePhyCapInfo(const stadbEntry_handle_t entry,
                                   json_t *phyCapInfo_j) {
    int res;
    size_t i, size;
    json_t *pci_j;
    wlanif_phyCapInfo_t *pci;
    LBD_BOOL valid = LBD_FALSE;
    wlanif_chwidth_e maxChWidth = 0;
    u_int8_t numStreams = 0;
    wlanif_phymode_e phyMode = 0;

    if (json_typeof(phyCapInfo_j) != JSON_ARRAY) {
        dbgf(stadbState.dbgModule, DBGERR, "%s: invalid type for phyCapInfo",
             __func__);
        return;
    }

    size = json_array_size(phyCapInfo_j);
    for (i = 0; i < size && i < wlanif_band_invalid; i++) {
        pci = &(entry->inNetworkInfo->phyCapInfo[i]);
        pci_j = json_array_get(phyCapInfo_j, i);
        if (pci_j != NULL) {
            res = json_unpack(pci_j, "{s?:b, s?:i, s?:i, s?:i, s?:i, s?:i}",
                "valid", &(valid),
                "maxChWidth", &(maxChWidth),
                "numStreams", &(numStreams),
                "phyMode", &(phyMode),
                "maxMCS", &(pci->maxMCS),
                "maxTxPower", &(pci->maxTxPower));

            if (res) {
                dbgf(stadbState.dbgModule, DBGERR,
                     "%s: failed to restore a phyCapInfo entry", __func__);
            }

            pci->valid = valid;
            pci->maxChWidth = maxChWidth;
            pci->numStreams = numStreams;
            pci->phyMode = phyMode;
        }
    }
}

/**
 * @brief create a new stadb entry from a json object
 *
 * @param device_j must be a valid json object
 *
 */
static void stadbCreateEntryFromJson(json_t *device_j,
                   stadb_restoreSteerExecCB_t rseCB) {
    struct ether_addr *addr;
    const char *ether_a;
    int res;
    json_t *phyCapInfo_j = NULL, *steerExec_j = NULL;
    stadbEntry_handle_t entry;
    stadbEntryType_e entryType;
    u_int8_t operatingBands = 0, isBTMSupported = 0, isRRMSupported = 0;
    LBD_BOOL isMUMIMOSupported = LBD_FALSE, isSteeringDisallowed = LBD_FALSE;

    res = json_unpack(device_j, "{s:s, s:i}", "addr", &ether_a, "entryType",
                      &entryType);
    if (res != 0) {
        dbgf(stadbState.dbgModule, DBGERR, "%s: failed to read device addr",
             __func__);
        return;
    }

    addr = ether_aton(ether_a);
    if (addr == NULL) {
        dbgf(stadbState.dbgModule, DBGERR, "%s: failed to parse device addr",
             __func__);
        return;
    }

    dbgf(stadbState.dbgModule, DBGINFO, "%s: Restoring %s", __func__, ether_a);
    entry = stadbFindOrInsertEntry(addr,
                    entryType == stadbEntryType_outOfNetwork,
                    wlanif_cap_unchanged);
    if (entry == NULL) {
        dbgf(stadbState.dbgModule, DBGERR, "%s: Failed to create entry %s",
             __func__, ether_a);
        return;
    }

    res = json_unpack(device_j,
            "{s?:i, s?:b, s?:b, s?:b, s?:b, s?:{s?:o}}",
            "operatingBands", &operatingBands,
            "isBTMSupported", &isBTMSupported,
            "isRRMSupported", &isRRMSupported,
            "isMUMIMOSupported", &isMUMIMOSupported,
            "isSteeringDisallowed", &isSteeringDisallowed,
            "inNetworkInfo",
                "phyCapInfo", &phyCapInfo_j,
            "steerExec", &steerExec_j
    );

    if (res != 0) {
        dbgf(stadbState.dbgModule, DBGERR, "%s: failed to restore %s", __func__,
             ether_a);
        return;
    }

    /* Fill bitfields, these can't be handled by json_unpack */
    entry->operatingBands = operatingBands;
    entry->isBTMSupported = isBTMSupported;
    entry->isRRMSupported = isRRMSupported;
    entry->isMUMIMOSupported = isMUMIMOSupported;
    entry->isSteeringDisallowed = isSteeringDisallowed;

    if (phyCapInfo_j != NULL) {
        stadbRestorePhyCapInfo(entry, phyCapInfo_j);
    }

    if (steerExec_j != NULL) {
        rseCB(entry, steerExec_j);
    }
}
