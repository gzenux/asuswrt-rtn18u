// vim: set et sw=4 sts=4 cindent:
/*
 * @File: stadb.h
 *
 * @Abstract: Public interface for the station database
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

#ifndef stadb__h
#define stadb__h

#include "lbd_types.h"  // for LBD_STATUS

#include "stadbEntry.h"

#if defined(__cplusplus)
extern "C" {
#endif

// Flag indicating the reason for the RSSI update when an obeserver is
// invoked.
typedef enum stadb_rssiUpdateReason_e {
    // probe request was received from the STA
    stadb_rssiUpdateReason_probe,

    // STA attempted to authenticate on a blacklisted band and was rejected
    stadb_rssiUpdateReason_authrej,

    // STA RSSI was measured via null data packets (as requested)
    stadb_rssiUpdateReason_measurement,

    // STA RSSI crossed one of the configured thresholds
    stadb_rssiUpdateReason_crossing,

    // 802.11k beacon report was received from the STA
    stadb_rssiUpdateReason_bcnrpt,
} stadb_rssiUpdateReason_e;

/**
 * @brief Function callback type that other modules can register to observe
 *        updates to the RSSI of stations in the database.
 *
 * The callback occurs after the entry has been updated.
 *
 * @param [in] handle  the entry that was updated
 * @param [in] reason  the reason for the RSSI update
 * @param [in] cookie  the value provided by the caller when the observer
 *                     callback function was registered
 */
typedef void (*stadb_rssiObserverCB)(stadbEntry_handle_t handle,
                                     stadb_rssiUpdateReason_e reason,
                                     void *cookie);

/**
 * @brief Function callback type that other modules can register to observe
 *        updates to the association of stations in the database.
 *
 * The callback occurs after the entry has been updated.
 *
 * @param [in] handle  the entry that was updated
 * @param [in] lastAssocBSS  the BSS the entry was associated before the new
 *                           association. Set to NULL or invalid BSS if the
 *                           entry was disassociated
 * @param [in] cookie  the value provided by the caller when the observer
 *                     callback function was registered
 */
typedef void (*stadb_assocObserverCB)(stadbEntry_handle_t handle,
                                      const lbd_bssInfo_t *lastAssocBSS,
                                      void *cookie);

/**
 * @brief Function callback type that other modules can register to observe
 *        updates to the activity status of stations in the database
 *
 * The callback occurs after the entry has been updated.
 *
 * @param [in] handle  the entry that was updated
 * @param [in] cookie  the value provided by the caller when the observer
 *                     callback function was registered
 */
typedef void (*stadb_activityObserverCB)(stadbEntry_handle_t handle,
                                         void *cookie);

/**
 * @brief Function callback type that other modules can register to observe
 *        updates when RSSI crossed low threshold
 *
 * The callback occurs after the entry has been updated.
 *
 * @param [in] handle  the entry that was updated
 * @param [in] cookie  the value provided by the caller when the observer
 *                     callback function was registered
 */
typedef void (*stadb_lowRSSIObserverCB)(stadbEntry_handle_t handle,
                                        void *cookie);

/**
 * @brief Callback function type for station database iteration.
 *
 * @param [in] entry  a station entry in the table
 * @param [in] cookie  the argument provided to stadb_iterate
 */
typedef void (*stadb_iterFunc_t)(stadbEntry_handle_t entry, void *cookie);

/**
 * @brief Initialize the station database module.
 *
 * This will pre-populate the database with the list of currently associated
 * STAs.
 *
 * @pre wlanif must have been initialized first
 *
 * @return LBD_OK on success; otherwise LBD_NOK
 */
LBD_STATUS stadb_init(void);

/**
 * @brief Register a callback function to observe RSSI updates.
 *
 * Note that the pair of the callback and cookie must be unique.
 *
 * @param [in] callback  the function to invoke for RSSI updates
 * @param [in] cookie  the parameter to pass to the callback function
 *
 * @return LBD_OK if the observer was successfully registered; otherwise
 *         LBD_NOK (either due to no free slots or a duplicate registration)
 */
LBD_STATUS stadb_registerRSSIObserver(stadb_rssiObserverCB callback,
                                      void *cookie);
/**
 * @brief Register a callback function to observe activity updates.
 *
 * Note that the pair of the callback and cookie must be unique.
 *
 * @param [in] callback  the function to invoke for activity updates
 * @param [in] cookie  the parameter to pass to the callback function
 *
 * @return LBD_OK if the observer was successfully registered; otherwise
 *         LBD_NOK (either due to no free slots or a duplicate registration)
 */
LBD_STATUS stadb_registerActivityObserver(stadb_activityObserverCB callback,
                                          void *cookie);

/**
 * @brief Unregister a callback function so that it no longer will receive
 *        RSSI updates.
 *
 * The parameters provided must match those given in the original
 * stadb_registerRSSIObserver() call.
 *
 * @param [in] callback  the function that was previously registered for
 *                       RSSI updates
 * @param [in] cookie  the parameter that was provided when the function was
 *                     registered
 *
 * @return LBD_OK if the observer was successfully unregistered; otherwise
 *         LBD_NOK
 */
LBD_STATUS stadb_unregisterRSSIObserver(stadb_rssiObserverCB callback,
                                        void *cookie);

/**
 * @brief Register a callback function to observe association updates.
 *
 * Note that the pair of the callback and cookie must be unique.
 *
 * @param [in] callback  the function to invoke for association updates
 * @param [in] cookie  the parameter to pass to the callback function
 *
 * @return LBD_OK if the observer was successfully registered; otherwise
 *         LBD_NOK (either due to no free slots or a duplicate registration)
 */
LBD_STATUS stadb_registerAssocObserver(stadb_assocObserverCB callback,
                                       void *cookie);

/**
 * @brief Unregister a callback function so that it not longer will receive
 *        association updates.
 *
 * The parameters provided must match those given in the original
 * stadb_registerAssocObserver() call.
 *
 * @param [in] callback  the function that was previously registered for
 *                       association updates
 * @param [in] cookie  the parameter that was provided when the function was
 *                     registered
 *
 * @return LBD_OK if the observer was successfully unregistered; otherwise
 *         LBD_NOK
 */
LBD_STATUS stadb_unregisterAssocObserver(stadb_assocObserverCB callback,
                                         void *cookie);

/**
 * @brief Unregister a callback function so that it no longer will receive
 *        activity updates.
 *
 * The parameters provided must match those given in the original
 * stadb_registerActivityObserver() call.
 *
 * @param [in] callback  the function that was previously registered for
 *                       activity updates
 * @param [in] cookie  the parameter that was provided when the function was
 *                     registered
 *
 * @return LBD_OK if the observer was successfully unregistered; otherwise
 *         LBD_NOK
 */
LBD_STATUS stadb_unregisterActivityObserver(stadb_activityObserverCB callback,
                                            void *cookie);

/**
 * @brief Register a callback function to observe updates when RSSI crossing low threshold.
 *
 * Note that the pair of the callback and cookie must be unique.
 *
 * @param [in] callback  the function to invoke for low RSSI updates
 * @param [in] cookie  the parameter to pass to the callback function
 *
 * @return LBD_OK if the observer was successfully registered; otherwise
 *         LBD_NOK (either due to no free slots or a duplicate registration)
 */
LBD_STATUS stadb_registerLowRSSIObserver(stadb_lowRSSIObserverCB callback,
                                         void *cookie);

/**
 * @brief Unregister a callback function so that it no longer will receive
 *        RSSI crossing low threshold updates.
 *
 * The parameters provided must match those given in the original
 * stadb_registerLowRSSIObserver() call.
 *
 * @param [in] callback  the function that was previously registered for
 *                       low RSSI updates
 * @param [in] cookie  the parameter that was provided when the function was
 *                     registered
 *
 * @return LBD_OK if the observer was successfully unregistered; otherwise
 *         LBD_NOK
 */
LBD_STATUS stadb_unregisterLowRSSIObserver(stadb_lowRSSIObserverCB callback,
                                           void *cookie);

/**
 * @brief Find an entry in the station database with the matching MAC address.
 *
 * Note that caller should not hang onto one entry instance, as it may be
 * invalidated when the STA entry type changes.
 *
 * @param [in] addr  the address to find
 *
 * @return the handle to the found entry, or NULL if not found
 */
stadbEntry_handle_t stadb_find(const struct ether_addr *addr);

/**
 * @brief Find or create an entry in the station database with
 *        the matching MAC address
 *
 * @param [in] addr  the address to find
 * @param [in] outOfNetwork  set to LBD_TRUE if the STA is
 *                           out-of-network
 * @param [in] rrmStatus  RRM status of the STA
 *
 * @return the handle to the found or created entry, or NULL if
 *         it can't be created
 */
stadbEntry_handle_t stadb_findOrCreate(const struct ether_addr *addr,
                                       LBD_BOOL outOfNetwork,
                                       wlanif_capStateUpdate_e rrmStatus);

/**
 * @brief Iterate over all entries in the station database, invoking func
 *        for each one.
 *
 * @param [in] callback  the callback function
 * @param [in] cookie  opaque parameter to provide in the callbacks
 *
 * @return LBD_OK if the iteration was successful; otherwise LBD_NOK
 */
LBD_STATUS stadb_iterate(stadb_iterFunc_t callback, void *cookie);

/**
 * @brief Tear down the station database module.
 *
 * @return LBD_OK on success; otherwise LBD_NOK
 */
LBD_STATUS stadb_fini(void);

/**
 * @brief Persist stadb to file
 *
 * @param [in] filename the persistence file name
 */
void stadb_persist(const char *filename, stadbEntry_jsonizeSteerExecCB_t jseCB);

/**
 * @brief Function to invoke to restore steerExec state
 *
 * @param [in] handle  the entry being jsonized
 * @return a pointer to a json object that represents the steerExec state
 */
typedef void (*stadb_restoreSteerExecCB_t)(stadbEntry_handle_t entry, json_t *json);

/**
 * @brief Restore stadb from file
 *
 * @param [in] filename the persistence file name
 */
void stadb_restore(const char *filename, stadb_restoreSteerExecCB_t rseCB);

/**
 * @brief Set dirty flag on stadb
 */
void stadb_setDirty(void);

/**
 * @brief Read dirty flag on stadb
 */
LBD_BOOL stadb_isDirty(void);

// ====================================================================
// Constants needed by test cases
// ====================================================================

// These need not be exposed but it is useful to do so for unit tests to
// avoid duplicating the strings.

#define STADB_INCLUDE_OUT_OF_NETWORK_KEY "IncludeOutOfNetwork"
#define STADB_AGING_SIZE_THRESHOLD_KEY   "AgingSizeThreshold"
#define STADB_AGING_FREQUENCY_KEY        "AgingFrequency"
#define STADB_OUT_OF_NETWORK_MAX_AGE     "OutOfNetworkMaxAge"
#define STADB_IN_NETWORK_MAX_AGE         "InNetworkMaxAge"
#define STADB_PROBE_MAX_INTERVAL         "ProbeMaxInterval"
#define STADB_MAX_REMOTE_BSSES           "NumRemoteBSSes"
#define STADB_MARK_ADV_CLIENT_DUAL_BAND  "MarkAdvClientAsDualBand"
#define STADB_POPULATE_NON_SERVING_PHY   "PopulateNonServingPHYInfo"

#if defined(LBD_DBG_MENU) && defined(GMOCK_UNIT_TESTS)
struct cmdContext;

/**
 * @brief Print the status of the station database module.
 *
 * @param [in] context  the output context
 * @param [in] cmd  the command in the debug CLI
 */
void stadbMenuStatusHandler(struct cmdContext *context,
                            const char *cmd);

/**
 * @brief Enable/disable the debug mode from the debug CLI
 *
 * @param [in] context  the output context
 * @param [in] cmd  the command in the debug CLI
 */
void stadbMenuDebugHandler(struct cmdContext *context, const char *cmd);

/**
 * @brief STA allow/disallow AP/BAND steering from the debug CLI
 *
 * @param [in] context  the output context
 * @param [in] cmd  the command in the debug CLI
 */
void stadbMenuNoSteerHandler(struct cmdContext *context, const char *cmd);

/**
 * @brief Inject an activity status from the debug CLI
 *
 * @param [in] context  the output context
 * @param [in] cmd  the command in the debug CLI
 */
void stadbMenuActivityHandler(struct cmdContext *context, const char *cmd);

/**
 * @brief Inject an RSSI measurement from the debug CLI
 *
 * @param [in] context  the output context
 * @param [in] cmd  the command in the debug CLI
 */
void stadbMenuRSSIHandler(struct cmdContext *context, const char *cmd);

/**
 * @brief Trigger diaglog from the debug CLI
 *
 * @param [in] context  the output context
 * @param [in] cmd  the command in the debug CLI
 */
void stadbMenuDiaglogHandler(struct cmdContext *context, const char *cmd);

#endif /* LBD_DBG_MENU && GMOCK_UNIT_TESTS */

#if defined(__cplusplus)
}
#endif

#endif
