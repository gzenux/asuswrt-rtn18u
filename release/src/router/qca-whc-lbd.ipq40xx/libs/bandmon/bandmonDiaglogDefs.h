// vim: set et sw=4 sts=4 cindent:
/*
 * @File: bandmonDiaglogDefs.h
 *
 * @Abstract: Diagnostic logging definitions for band monitor
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

#ifndef bandmonDiaglogDefs__h
#define bandmonDiaglogDefs__h

#if defined(__cplusplus)
extern "C" {
#endif

/**
 * @brief Diagnostic logging message identifiers for the bandmon module.
 */
typedef enum bandmon_msgId_e {
    /// A change in the overload status occurred
    bandmon_msgId_overloadChange,

    /// An average utilization measurement for a single band
    bandmon_msgId_utilization,

    /// Whether steering is disallowed or not has changed.
    bandmon_msgId_blackoutChange,
} bandmon_msgId_e;

#if defined(__cplusplus)
}
#endif

#endif
