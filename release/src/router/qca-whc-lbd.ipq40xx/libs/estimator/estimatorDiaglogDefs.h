// vim: set et sw=4 sts=4 cindent:
/*
 * @File: estmiatorDiaglogDefs.h
 *
 * @Abstract: Diagnostic logging definitions for estimator
 *
 * @Notes:
 *
 * @@-COPYRIGHT-START-@@
 *
 * Copyright (c) 2015 Qualcomm Atheros, Inc.
 * All Rights Reserved.
 * Qualcomm Atheros Confidential and Proprietary.
 *
 * @@-COPYRIGHT-END-@@
 */

#ifndef estimatorDiaglogDefs__h
#define estimatorDiaglogDefs__h

#if defined(__cplusplus)
extern "C" {
#endif

/**
 * @brief Diagnostic logging message identifiers for the estimator module.
 */
typedef enum estimator_msgId_e {
    /// Measurement for serving BSS throughput, full capacity, and airtime
    estimator_msgId_servingDataMetrics,

    /// Estimate for non-serving full capacity and airtime
    estimator_msgId_nonServingDataMetrics,

    /// Interference detection state for a given STA on its serving channel
    /// changed.
    estimator_msgId_staInterferenceDetected,

    /// Pollution state change for a given STA on a given BSS.
    estimator_msgId_staPollutionChanged,

    /// STA statistics used for interference detection
    estimator_msgId_iasSTAStats
} estimator_msgId_e;

#if defined(__cplusplus)
}
#endif

#endif
