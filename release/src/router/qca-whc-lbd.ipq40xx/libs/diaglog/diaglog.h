// vim: set et sw=4 sts=4 cindent:
/*
 * @File: diaglog.h
 *
 * @Abstract: Load balancing daemon diagnostic logging
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

#ifndef diaglog__h
#define diaglog__h

#include "lbd_types.h"
#include "module.h"

#if defined(__cplusplus)
extern "C" {
#endif

/**
 * @brief Diagnostic logging levels which can be used by each module to emit
 *        different verbosity of logs.
 */
typedef enum diaglog_level_e {
    diaglog_level_debug,   ///< full logging (including raw measurements)
    diaglog_level_info,    ///< general logging (no raw measurements)
    diaglog_level_demo,    ///< limited logging (only enough for external demos)
    diaglog_level_none,    ///< no logging at all
    diaglog_level_invalid, ///< only used internally to signal an invalid level
} diaglog_level_e;


/**
 * @brief Message identifiers defined by this module.
 */
typedef enum diaglog_msgId_e {
    // A single string (not null terminated).
    diaglog_msgId_message
} diaglog_msgId_e;

/**
 * @brief Initialize the diagnostic logging module, including obtaining the
 *        default configuration.
 */
LBD_STATUS diaglog_init(void);

/**
 * @brief Write an arbitrary buffer into the log message currently being
 *        constructed.
 *
 * @pre diaglogStartEntry must have been called first (with diaglogFinishEntry
 *      not yet having been called)
 *
 * @param [in] buffer  the data to log
 * @param [in] buflen  the number of bytes to log
 */
void diaglog_write(const void *buffer, size_t buflen);

/**
 * @brief Include a MAC address in the log message currently being constructed.
 *
 * @pre diaglogStartEntry must have been called first (with diaglogFinishEntry
 *      not yet having been called)
 *
 * @param [in] mac  the MAC address to log
 */
void diaglog_writeMAC(const struct ether_addr *mac);

/**
 * @brief Include a BSS info in the log message currently being constructed.
 *
 * @pre diaglogStartEntry must have been called first (with diaglogFinishEntry
 *      not yet having been called)
 *
 * @param [in] bssInfo  the BSS info to log
 */
void diaglog_writeBSSInfo(const lbd_bssInfo_t *bssInfo);

/**
 * @brief Include an 8-bit value in the log message currently being
 *        constructed.
 *
 * @pre diaglogStartEntry must have been called first (with diaglogFinishEntry
 *      not yet having been called)
 *
 * @param [in] value  the value to log
 */
void diaglog_write8(u_int8_t value);

/**
 * @brief Include an 16-bit value in the log message currently being
 *        constructed.
 *
 * @pre diaglogStartEntry must have been called first (with diaglogFinishEntry
 *      not yet having been called)
 *
 * @param [in] value  the value to log
 */
void diaglog_write16(u_int16_t value);

/**
 * @brief Include an 32-bit value in the log message currently being
 *        constructed.
 *
 * @pre diaglogStartEntry must have been called first (with diaglogFinishEntry
 *      not yet having been called)
 *
 * @param [in] value  the value to log
 */
void diaglog_write32(u_int32_t value);

/**
 * @brief Include an 64-bit value in the log message currently being
 *        constructed.
 *
 * @pre diaglogStartEntry must have been called first (with diaglogFinishEntry
 *      not yet having been called)
 *
 * @param [in] value  the value to log
 */
void diaglog_write64(u_int64_t value);

/**
 * @brief Start the log entry, filling out the header (including a timestamp).
 *
 * @param [in] moduleId  the module that is generating the log
 * @param [in] msgId  the identifier (scoped to the module) for the log
 * @param [in] level  the diag logging level of the message being generated
 *
 * @return LBD_TRUE if the entry was started; LBD_FALSE if the message is
 *         disabled (by the logging levels)
 */
LBD_BOOL diaglog_startEntry(enum mdModuleID_e moduleId, u_int16_t msgId,
                            diaglog_level_e level);

/**
 * @brief Complete the in progress log entry, sending it over the network.
 */
void diaglog_finishEntry(void);

/**
 * @brief Cleanly shut down the diagnostic logging infrastructuer.
 */
LBD_STATUS diaglog_fini(void);

// ====================================================================
// Constants needed by test cases
// ====================================================================

// These need not be exposed but it is useful to do so for unit tests to
// avoid duplicating the strings.

#define DIAGLOG_ENABLE_LOG_KEY           "EnableLog"
#define DIAGLOG_LOG_SERVER_IP_KEY        "LogServerIP"
#define DIAGLOG_LOG_SERVER_PORT_KEY      "LogServerPort"
#define DIAGLOG_LOG_LEVEL_WLANIF_KEY     "LogLevelWlanIF"
#define DIAGLOG_LOG_LEVEL_BANDMON_KEY    "LogLevelBandMon"
#define DIAGLOG_LOG_LEVEL_STADB_KEY      "LogLevelStaDB"
#define DIAGLOG_LOG_LEVEL_STEEREXEC_KEY  "LogLevelSteerExec"
#define DIAGLOG_LOG_LEVEL_STAMON_KEY     "LogLevelStaMon"
#define DIAGLOG_LOG_LEVEL_DIAGLOG_KEY    "LogLevelDiagLog"
#define DIAGLOG_LOG_LEVEL_ESTIMATOR_KEY  "LogLevelEstimator"

#if defined(LBD_DBG_MENU) && defined(GMOCK_UNIT_TESTS)
struct cmdContext;

/**
 * @brief Debug CLI handler for the status operation.
 *
 * @param [in] context  the output context
 * @param [in] cmd  the command in the debug CLI
 */
void diaglogMenuStatusHandler(struct cmdContext *context, const char *cmd);

/**
 * @brief Debug CLI handler for the parameters operation.
 *
 * @param [in] context  the output context
 * @param [in] cmd  the command in the debug CLI
 */
void diaglogMenuParametersHandler(struct cmdContext *context, const char *cmd);

/**
 * @brief Debug CLI handler for the message operation.
 *
 * @param [in] context  the output context
 * @param [in] cmd  the command in the debug CLI
 */
void diaglogMenuMessageHandler(struct cmdContext *context, const char *cmd);

#endif /* LBD_DBG_MENU && GMOCK_UNIT_TESTS */

#if defined(__cplusplus)
}
#endif

#endif
