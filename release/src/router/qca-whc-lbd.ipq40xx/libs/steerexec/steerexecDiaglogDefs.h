// vim: set et sw=4 sts=4 cindent:
/*
 * @File: steerexecDiaglogDefs.h
 *
 * @Abstract: Diagnostic logging definitions for steering executor
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

#ifndef steerexecDiaglogDefs__h
#define steerexecDiaglogDefs__h

#if defined(__cplusplus)
extern "C" {
#endif

/**
 * @brief Diagnostic logging message identifiers for the steerexec module.
 */
typedef enum steerexec_msgId_e {
    /// Pre-association steering of a specific STA began.
    steerexec_msgId_preAssocSteerStart,

    /// Steering of a specific STA finished 
    /// (can be pre- or post-association steering).
    steerexec_msgId_steerEnd,

    /// The steering unfriendly status for a STA changed.
    steerexec_msgId_steeringUnfriendly,

    /// The steering prohibited flag for a STA changed.
    steerexec_msgId_steeringProhibited,

    /// The BTM compliance status for a STA changed.
    steerexec_msgId_btmCompliance,

    /// Post-association steering of a specific STA began.
    steerexec_msgId_postAssocSteerStart
} steerexec_msgId_e;

#if defined(__cplusplus)
}
#endif

#endif
