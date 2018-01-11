// vim: set et sw=4 sts=4 cindent:
/*
 * @File: diaglog.c
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
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <arpa/inet.h>

#ifdef GMOCK_UNIT_TESTS
#include "strlcpy.h"
#endif

#include <dbg.h>
#include <module.h>
#include <profile.h>
#include "lb_assert.h"
#include "diaglog.h"

#define LOG_BUFFER_SIZE 1024

struct diaglogConfig {
    LBD_BOOL enableLog;
    char logServerIP[32];
    u_int32_t logServerPort;
};

struct diaglogState {
    struct diaglogConfig config;
    LBD_BOOL bigEndian;

    diaglog_level_e logLevels[mdModuleID_MaxNum];

    int socketFd;
    int lastErrno;
    struct sockaddr_in serverAddr;

    u_int8_t seqNum;
    u_int8_t msgBuf[LOG_BUFFER_SIZE];
    size_t msgBufOffset;

    struct dbgModule *dbgModule;
} diaglogState;

struct profileElement diaglogElementDefaultTable[ ] = {
        { DIAGLOG_ENABLE_LOG_KEY,      "0" },
        { DIAGLOG_LOG_SERVER_IP_KEY,   "192.168.1.10" },
        { DIAGLOG_LOG_SERVER_PORT_KEY, "7788" },

        // Each area defaults to demo-level logging only.
        { DIAGLOG_LOG_LEVEL_WLANIF_KEY,    "2" },
        { DIAGLOG_LOG_LEVEL_BANDMON_KEY,   "2" },
        { DIAGLOG_LOG_LEVEL_STADB_KEY,     "2" },
        { DIAGLOG_LOG_LEVEL_STEEREXEC_KEY, "2" },
        { DIAGLOG_LOG_LEVEL_STAMON_KEY,    "2" },
        { DIAGLOG_LOG_LEVEL_DIAGLOG_KEY,   "2" },
        { DIAGLOG_LOG_LEVEL_ESTIMATOR_KEY, "2" },
        { NULL, NULL },
};

#define DIAGLOG_VERSION 2
#define DIAGLOG_VERSION_SHIFT 4
#define DIAGLOG_BIG_ENDIAN_SHIFT 0

// Forward decls of private functions
static void diaglogReadConfig(void);
static void diaglogReadConfigLevel(enum mdModuleID_e moduleId);

static void diaglogDetectEndianness(void);

static LBD_STATUS diaglogOpenSocket(void);
static LBD_STATUS diaglogInitServerAddr(struct sockaddr_in *serverAddr);
static void diaglogWriteVersionAndFlags(void);
static void diaglogResetBuffer(void);
static void diaglogCloseSocket(void);
static void diaglogMenuInit(void);

// ====================================================================
// Public API
// ====================================================================

LBD_STATUS diaglog_init(void) {
    diaglogState.dbgModule = dbgModuleFind("diaglog");
    diaglogState.seqNum = 0;
    diaglogState.socketFd = -1;
    diaglogState.lastErrno = 0;
    diaglogState.msgBufOffset = 0;

    diaglogReadConfig();
    diaglogDetectEndianness();

    diaglogMenuInit();

    if (diaglogState.config.enableLog) {
        return diaglogOpenSocket();
    }

    return LBD_OK;
}

void diaglog_write(const void* buffer, size_t buflen) {
    if (diaglogState.config.enableLog) {
        if (diaglogState.msgBufOffset + buflen >= LOG_BUFFER_SIZE) {
            dbgf(diaglogState.dbgModule, DBGERR,
                 "%s: Buffer size exceeded - dropping", __func__);
            diaglogResetBuffer();
            return;
        }

        memcpy(diaglogState.msgBuf + diaglogState.msgBufOffset, buffer, buflen);
        diaglogState.msgBufOffset += buflen;
    }
}

void diaglog_writeMAC(const struct ether_addr *mac) {
    diaglog_write(mac->ether_addr_octet, ETH_ALEN);
}

void diaglog_writeBSSInfo(const lbd_bssInfo_t *bssInfo) {
    diaglog_write8(bssInfo->apId);
    diaglog_write8(bssInfo->channelId);
    diaglog_write8(bssInfo->essId);
}

void diaglog_write8(u_int8_t val) {
    diaglog_write(&val, sizeof(u_int8_t));
}

void diaglog_write16(u_int16_t val) {
    // Written in native byte ordering as flags in the header indicate to
    // the server whether byte swapping is required.
    diaglog_write(&val, sizeof(u_int16_t));
}

void diaglog_write32(u_int32_t val) {
    // Written in native byte ordering as flags in the header indicate to
    // the server whether byte swapping is required.
    diaglog_write(&val, sizeof(u_int32_t));
}

void diaglog_write64(u_int64_t val) {
    // Written in native byte ordering as flags in the header indicate to
    // the server whether byte swapping is required.
    diaglog_write(&val, sizeof(u_int64_t));
}

LBD_BOOL diaglog_startEntry(enum mdModuleID_e moduleId, u_int16_t msgId,
                            diaglog_level_e level) {
    if (!diaglogState.config.enableLog || moduleId >= mdModuleID_MaxNum ||
        diaglogState.logLevels[moduleId] > level) {
        return LBD_FALSE;
    }

    struct timeval tv = {0};
    gettimeofday(&tv, NULL);

    if (diaglogState.msgBufOffset) {
        dbgf(diaglogState.dbgModule, DBGERR,
             "%s: Called before finishing (transmitting) the last entry using "
             "'diaglog_finishEntry()'.", __func__);
        diaglogResetBuffer();
    }

    diaglogWriteVersionAndFlags();
    diaglog_write8(diaglogState.seqNum);
    diaglog_write32(tv.tv_sec);
    diaglog_write32(tv.tv_usec);
    diaglog_write8(moduleId);
    diaglog_write8(msgId);

    return LBD_TRUE;  // message is enabled
}

void diaglog_finishEntry(void) {
    if (diaglogState.config.enableLog) {
        if (diaglogState.msgBufOffset == 0) {
            dbgf(diaglogState.dbgModule, DBGERR,
                 "%s: Trying to finish an empty entry; ignored",
                 __func__);
            return;
        }

        if (diaglogState.socketFd < 0) {
            dbgf(diaglogState.dbgModule, DBGERR,
                 "%s: Trying to write data but the log service is not "
                 "initialized!", __func__);
            return;
        }

        if (sendto(diaglogState.socketFd, diaglogState.msgBuf,
                   diaglogState.msgBufOffset, MSG_DONTWAIT,
                   (const struct sockaddr *) &diaglogState.serverAddr,
                   sizeof(diaglogState.serverAddr)) < 0) {
            if (errno != diaglogState.lastErrno) {
                dbgf(diaglogState.dbgModule, DBGERR,
                     "%s: Failed to send mesage with length %u (errno=%d)",
                     __func__, diaglogState.msgBufOffset, errno);
                diaglogState.lastErrno = errno;
            }
        }

        diaglogResetBuffer();
        diaglogState.seqNum++;
    }
}

LBD_STATUS diaglog_fini() {
    diaglogCloseSocket();
    return LBD_OK;
}

// ====================================================================
// Private API
// ====================================================================

/**
 * @brief Read the configuration values from the file into our internal
 *        state.
 */
static void diaglogReadConfig(void) {
    diaglogState.config.enableLog = profileGetOptsInt(
            mdModuleID_DiagLog, DIAGLOG_ENABLE_LOG_KEY,
            diaglogElementDefaultTable) ? LBD_TRUE : LBD_FALSE;

    const char *serverIpStr = profileGetOpts(mdModuleID_DiagLog,
                                             DIAGLOG_LOG_SERVER_IP_KEY,
                                             diaglogElementDefaultTable);
    lbDbgAssertExit(diaglogState.dbgModule, serverIpStr);

    strlcpy(diaglogState.config.logServerIP, serverIpStr,
            sizeof(diaglogState.config.logServerIP));
    free((char *) serverIpStr);
    diaglogState.config.logServerPort = profileGetOptsInt(
            mdModuleID_DiagLog, DIAGLOG_LOG_SERVER_PORT_KEY,
            diaglogElementDefaultTable);

    size_t i;
    for (i = 0; i < mdModuleID_MaxNum; ++i) {
        diaglogReadConfigLevel((enum mdModuleID_e) i);
    }
}

/**
 * @brief Read the configuration file to determine the diag log level for
 *        the provided module.
 *
 * @param [in] moduleId  the module for which to get the level
 */
static void diaglogReadConfigLevel(enum mdModuleID_e moduleId) {
    const char *key = NULL;
    switch (moduleId) {
        case mdModuleID_WlanIF:
            key = DIAGLOG_LOG_LEVEL_WLANIF_KEY;
            break;

        case mdModuleID_BandMon:
            key = DIAGLOG_LOG_LEVEL_BANDMON_KEY;
            break;

        case mdModuleID_StaDB:
            key = DIAGLOG_LOG_LEVEL_STADB_KEY;
            break;

        case mdModuleID_SteerExec:
            key = DIAGLOG_LOG_LEVEL_STEEREXEC_KEY;
            break;

        case mdModuleID_StaMon:
            key = DIAGLOG_LOG_LEVEL_STAMON_KEY;
            break;

        case mdModuleID_DiagLog:
            key = DIAGLOG_LOG_LEVEL_DIAGLOG_KEY;
            break;

        case mdModuleID_Estimator:
            key = DIAGLOG_LOG_LEVEL_ESTIMATOR_KEY;
            break;

        default:
            // Nothing to do for these areas.
            break;
    }

    if (key) {
        diaglogState.logLevels[moduleId] = profileGetOptsInt(
            mdModuleID_DiagLog, key, diaglogElementDefaultTable);
    } else {
        diaglogState.logLevels[moduleId] = diaglog_level_none;
    }
}

/**
 * @brief Determine whether the machine is big or little endian and
 *        record this in the diag logging state.
 */
static void diaglogDetectEndianness(void) {
    const u_int32_t val32 = 0x12345678;
    const u_int8_t *byte = (const u_int8_t *) &val32;
    diaglogState.bigEndian = (*byte == 0x12);
}

/**
 * @brief Open the socket that will be used to send diagnostic logging
 *        records.
 */
static LBD_STATUS diaglogOpenSocket(void) {
    dbgf(diaglogState.dbgModule, DBGDEBUG, "%s: Starting diag logging", __func__);

    struct sockaddr_in serverAddr;
    if (diaglogInitServerAddr(&serverAddr) == LBD_NOK) {
        return LBD_NOK;
    }
    diaglogState.serverAddr = serverAddr;

    diaglogState.socketFd = socket(AF_INET, SOCK_DGRAM, 0);
    if (diaglogState.socketFd == -1) {
        dbgf(diaglogState.dbgModule, DBGERR, "%s: socket(...) failed: %s",
             __func__, strerror(errno));
        return LBD_NOK;
    }

    return LBD_OK;
}

/**
 * @brief Initialize the address to use as the destination for diagnostic
 *        logging messages.
 *
 * @pre the logServerIP and logServerPort members of the configuration have
 *      already been populated
 *
 * @return LBD_OK if the address was resolved successfully; otherwise LBD_NOK
 */
static LBD_STATUS diaglogInitServerAddr(struct sockaddr_in *serverAddr) {
    memset(serverAddr, 0, sizeof(*serverAddr));
    if (inet_aton(diaglogState.config.logServerIP,
                  &serverAddr->sin_addr) == 0) {
        dbgf(diaglogState.dbgModule, DBGERR, "%s: Invalid LogServerIP %s",
             __func__, diaglogState.config.logServerIP);
        return LBD_NOK;
    }
    serverAddr->sin_family = AF_INET;
    serverAddr->sin_port = htons(diaglogState.config.logServerPort);

    return LBD_OK;
}

/**
 * @brief Write the portion of the header that contains the version number
 *        and flags.
 */
static void diaglogWriteVersionAndFlags(void) {
    diaglog_write8(DIAGLOG_VERSION << DIAGLOG_VERSION_SHIFT |
                   diaglogState.bigEndian << DIAGLOG_BIG_ENDIAN_SHIFT);
}

/**
 * @brief Reset the internal buffer to prepare it for the next log.
 */
static void diaglogResetBuffer(void) {
    diaglogState.msgBufOffset = 0;
}

/**
 * @brief Close the socket that was being used for diagnostic logging.
 */
static void diaglogCloseSocket(void) {
    if (diaglogState.socketFd < 0) {
        // nothing to do as socket is invalid
        return;
    }

    dbgf(diaglogState.dbgModule, DBGDEBUG, "%s: Stopping diag logging",
         __func__);
    close(diaglogState.socketFd);
    diaglogState.socketFd = -1;
}

// ====================================================================
// Debug CLI functions
// ====================================================================

#ifdef LBD_DBG_MENU /* entire debug menu section */
#include <cmd.h>

/* ------------------- s = status -------------------------------- */
const char *diaglogMenuStatusHelp[] = {
    "s -- print diaglog module status",
    NULL
};

#ifndef GMOCK_UNIT_TESTS
static
#endif
void diaglogMenuStatusHandler(struct cmdContext *context, const char *cmd) {
    cmdf(context, "diaglog status: %s\n",
         diaglogState.config.enableLog ? "enabled" : "disabled");
}

/* ------------------- p = parameters -------------------------------- */
static const struct {
    const char *paramName;
    enum mdModuleID_e moduleId;
} diaglogNameToModuleIDMap[] = {
    { "WlanIFLevel", mdModuleID_WlanIF },
    { "BandMonLevel", mdModuleID_BandMon },
    { "StaDBLevel", mdModuleID_StaDB },
    { "SteerExecLevel", mdModuleID_SteerExec },
    { "StaMonLevel", mdModuleID_StaMon },
    { "DiagLogLevel", mdModuleID_DiagLog },
    { "EstimatorLevel", mdModuleID_Estimator },
};

/**
 * @brief Determine the module identifier from the parameter name.
 *
 * @param [in] paramName  the name of the parameter being set or retrieved
 *
 * @return the matching module ID, or mdModuleID_MaxNum on no match
 */
static enum mdModuleID_e diaglogGetMatchingModuleId(const char *paramName) {
    size_t i = 0;
    for (i = 0; i < sizeof(diaglogNameToModuleIDMap) /
                    sizeof(diaglogNameToModuleIDMap[0]); ++i) {
        if (strcmp(diaglogNameToModuleIDMap[i].paramName, paramName) == 0) {
            return diaglogNameToModuleIDMap[i].moduleId;
        }
    }

    return mdModuleID_MaxNum;
}

static const char *diaglogLevelStrings[] = {
    "debug",
    "info",
    "demo",
    "none"
};

/**
 * @brief Determine the numeric log level based on the provided string.
 *
 * @param [in] paramValue  the log level to map to a numeric value
 *
 * @return the numeric value, or diaglog_level_invalid if there is no mapping
 *         for the string
 */
static diaglog_level_e diaglogGetLogLevelFromString(const char *paramValue) {
    size_t i = 0;
    for (i = 0; i < sizeof(diaglogLevelStrings) /
                    sizeof(diaglogLevelStrings[0]); ++i) {
        if (strcmp(diaglogLevelStrings[i], paramValue) == 0) {
            return (diaglog_level_e) i;
        }
    }

    return diaglog_level_invalid;
}

const char *diaglogMenuParametersHelp[] = {
    "p -- Parameter access command (set & display)",
    "Usage:",
    "\tp: print all parameters",
    "\tp <parameter>: print specific parameter value",
    "\tp <parameter> <value>: set parameter to value",
    NULL
};

#ifndef GMOCK_UNIT_TESTS
static
#endif
void diaglogMenuParametersHandler(struct cmdContext *context, const char *cmd) {
    const char* arg = cmdWordFirst(cmd);
    if (!arg || !arg[0]) { // no arguments: print all parameters
        cmdf(context, "diaglog configuration parameters:\n");

        cmdf(context, "\tEnableLog = %s\n", diaglogState.config.enableLog ? "ENABLED" : "DISABLED");
        cmdf(context, "\tLogServerIP = %s\n", diaglogState.config.logServerIP);
        cmdf(context, "\tLogServerPort = %d\n", diaglogState.config.logServerPort);

        cmdf(context, "\n\tLog levels\n");
        cmdf(context, "\t---------------------------------------\n");
        size_t i;
        for (i = 0; i < sizeof(diaglogNameToModuleIDMap) /
                        sizeof(diaglogNameToModuleIDMap[0]); ++i) {
            enum mdModuleID_e moduleId = diaglogNameToModuleIDMap[i].moduleId;
            cmdf(context, "\t%s = %s\n", diaglogNameToModuleIDMap[i].paramName,
                 diaglogLevelStrings[diaglogState.logLevels[moduleId]]);
        }

        return;
    }

    char *paramName = cmdWordDup(arg);
    if (!paramName) {
        cmdf(context, "Memory allocation failed; cannot process command\n");
        return;
    }

    const char *paramValue = cmdWordNext(arg);
    if (paramValue && !paramValue[0]) {
        paramValue = NULL;
    }

    do {
        enum mdModuleID_e moduleId;
        if ((moduleId = diaglogGetMatchingModuleId(paramName)) !=
            mdModuleID_MaxNum) {
            if (paramValue) {
                char *levelStr = cmdWordDup(paramValue);
                if (!levelStr) {
                    cmdf(context, "Memory allocation failed; cannot process command\n");
                    break;
                }

                diaglog_level_e level = diaglogGetLogLevelFromString(levelStr);
                free(levelStr);
                if (level == diaglog_level_invalid) {
                    cmdf(context, "Invalid log level '%s'\n", paramValue);
                    break;
                }

                diaglogState.logLevels[moduleId] = level;
            }
            cmdf(context, "%s = %s\n", paramName,
                 diaglogLevelStrings[diaglogState.logLevels[moduleId]]);
        } else if (!strcmp(paramName, "LogServerIP")) {
            if (paramValue) {
                u_int32_t maxLen = sizeof(diaglogState.config.logServerIP);
                strncpy(diaglogState.config.logServerIP, paramValue, maxLen);
                diaglogState.config.logServerIP[maxLen - 1] = '\0';

                struct sockaddr_in serverAddr;
                if (diaglogInitServerAddr(&serverAddr) != LBD_OK) {
                    cmdf(context, "Invalid LogServerIP = %s and/or "
                                  "LogServerPort = %u\n",
                         diaglogState.config.logServerIP,
                         diaglogState.config.logServerPort);
                    break;
                }
                diaglogState.serverAddr = serverAddr;
            }

            cmdf(context, "LogServerIP = %s\n", diaglogState.config.logServerIP);
        } else {
            u_int32_t value = 0;

            if (paramValue) {
                value = atoi(paramValue);
            }

            if (!strcmp(paramName, "EnableLog")) {
                if (paramValue) {
                    if (value && !diaglogState.config.enableLog) {
                        if (diaglogOpenSocket() != LBD_OK) {
                            cmdf(context, "Failed to open socket for logging\n");
                            break;
                        }
                    } else if (!value && diaglogState.config.enableLog) {
                        diaglogCloseSocket();
                    }

                    diaglogState.config.enableLog = value ? LBD_TRUE : LBD_FALSE;
                }

                cmdf(context, "EnableLog = %s\n", diaglogState.config.enableLog ?
                                                  "ENABLED" : "DISABLED");
            } else if (!strcmp(paramName, "LogServerPort")) {
                if (paramValue) {
                    diaglogState.config.logServerPort = value;

                    struct sockaddr_in serverAddr;
                    if (diaglogInitServerAddr(&serverAddr) != LBD_OK) {
                        cmdf(context, "Invalid LogServerIP = %s and/or "
                                      "LogServerPort = %u\n",
                             diaglogState.config.logServerIP,
                             diaglogState.config.logServerPort);
                        break;
                    }
                    diaglogState.serverAddr = serverAddr;
                }

                cmdf(context, "LogServerPort = %d\n", diaglogState.config.logServerPort);
            } else {
                cmdf(context, "Unknown parameter specified -- '%s'\n", paramName);
            }
        }
    } while (0);

    free(paramName);
}

/* ------------------- m = message -------------------------------- */
const char *diaglogMenuMessageHelp[] = {
    "m -- print message into log stream",
    "Usage:",
    "\tm: print standard 'LOG_ALERT' message log stream",
    "\tm <message>: print specified message into log stream",
    NULL
};

#ifndef GMOCK_UNIT_TESTS
static
#endif
void diaglogMenuMessageHandler(struct cmdContext *context, const char *cmd) {
    const char* arg;
    u_int16_t len;

    arg = cmdWordFirst(cmd);
    if (!arg || !arg[0]) {
        arg = "LOG_ALERT";
    }

    char *copyArg = strdup(arg);
    if (copyArg) {
        len = strlen(copyArg);

        // Need to strip any carriage return that may have been inserted
        if (copyArg[len - 1] == '\r') {
            copyArg[len - 1] = '\0';
            len--;
        }

        diaglog_startEntry(mdModuleID_DiagLog, diaglog_msgId_message,
                           diaglog_level_info);
        diaglog_write(copyArg, len);
        diaglog_finishEntry();

        cmdf(context, "Message printed to log stream: '%s' (%d length)\n", copyArg, len);

        free(copyArg);
    }
}


/* ------------ diaglog menu (added to main menu) ----------*/

struct cmdMenuItem diaglogMenu[] = {
    CMD_MENU_STANDARD_STUFF(),
    { "s", diaglogMenuStatusHandler, NULL, diaglogMenuStatusHelp },
    { "p", diaglogMenuParametersHandler, NULL, diaglogMenuParametersHelp },
    { "m", diaglogMenuMessageHandler, NULL, diaglogMenuMessageHelp },
    /* you can add more menu items here */
    CMD_MENU_END()
};

const char *diaglogMenuHelp[] = {
    "dlog (diaglog) -- log data to host at regular intervals",
    NULL
};

const struct cmdMenuItem diaglogMenuItem = {
    "dlog",
    cmdMenu,
    diaglogMenu,
    diaglogMenuHelp
};

#endif  /* LBD_DBG_MENU  -- entire section*/

/**
 * @brief Initialize the CLI interface for this module (if enabled in the
 *        build).
 */
static void diaglogMenuInit(void) {
    #ifdef LBD_DBG_MENU
    cmdMainMenuAdd(&diaglogMenuItem);
    #endif
}
