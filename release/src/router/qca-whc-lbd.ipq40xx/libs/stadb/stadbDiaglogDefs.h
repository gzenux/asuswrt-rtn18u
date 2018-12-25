// vim: set et sw=4 sts=4 cindent:
/*
 * @File: stadbDiaglogDefs.h
 *
 * @Abstract: Diagnostic logging definitions for station database
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

#ifndef stadbDiaglogDefs__h
#define stadbDiaglogDefs__h

#if defined(__cplusplus)
extern "C" {
#endif

/**
 * @brief Diagnostic logging message identifiers for the stadb module.
 */
typedef enum stadb_msgId_e {
    /// The associated band for a STA has changed
    stadb_msgId_associationUpdate,

    /// RSSI value has been updated on a band
    stadb_msgId_rssiUpdate,

    /// Activity of a given STA has been updated
    stadb_msgId_activityUpdate,

    /// Whether a STA is dual band capable has been updated
    stadb_msgId_dualBandUpdate,
} stadb_msgId_e;

#if defined(__cplusplus)
}
#endif

#endif
