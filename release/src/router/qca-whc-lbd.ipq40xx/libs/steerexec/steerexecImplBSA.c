// vim: set et sw=4 sts=4 cindent:
/*
 * @File: steerexecImplCmnBSA.c
 *
 * @Abstract: Single AP steering implementation
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
 *
 */

#include "lb_common.h"
#include "lb_assert.h"

#include "steerexecImplCmn.h"

/**
 * @brief Internal state for the single-AP steering
 *        implementation.
 */
static struct {
    /// Pointer to the steering executor
    steerexecImplCmnHandle_t exec;

    /// Pointer to the debug module
    struct dbgModule *dbgModule;
} steerexecImplBSAState;

// ====================================================================
// Private functions
// ====================================================================


// ====================================================================
// Package level functions
// ====================================================================

void steerexecImplCreate(steerexecImplCmnHandle_t exec, struct dbgModule *dbgModule) {
    steerexecImplBSAState.exec = exec;
    steerexecImplBSAState.dbgModule = dbgModule;
}

LBD_STATUS steerexecImplPrepareForSteering(
    stadbEntry_handle_t entry,
    const struct ether_addr *staAddr,
    u_int8_t candidateCount,
    const lbd_bssInfo_t *candidateList,
    steerexecImplCmnSteeringType_e steerType,
    LBD_BOOL blacklistAutoClear,
    u_int32_t blacklistMaxTime,
    LBD_BOOL resetProhibitTime,
    LBD_BOOL *preparationComplete,
    u_int8_t *msgTransaction) {

    // For BSA there is no preparation needed, start the steer right away
    *preparationComplete = LBD_TRUE;
    return LBD_OK;
}

LBD_STATUS steerexecImplAbort(u_int8_t transId,
                              const struct ether_addr *addr,
                              steerexecImplCmnSteeringStatusType_e reason) {
    return LBD_OK;
}

void steerexecImplHandleAssocUpdate(const struct ether_addr *staAddr,
                                    LBD_BOOL steeringComplete) {
}

void steerexecImplHandleAuthReject(const struct ether_addr *staAddr,
                                   u_int8_t numConsecRejects) {
}

LBD_BOOL steerexecImplCandidateListValid(u_int8_t candidateCount,
                                         const lbd_bssInfo_t *candidateList) {
    // For BSA steering, all candidates should be local
    size_t i;
    for (i = 0; i < candidateCount; i++) {
        if (!lbIsBSSLocal(&candidateList[i])) {
            dbgf(steerexecImplBSAState.dbgModule, DBGERR,
                 "%s: Candidate list contains remote BSS " lbBSSInfoAddFmt()
                 ".  Will not steer.",
                 __func__, lbBSSInfoAddData(&candidateList[i]));
            return LBD_FALSE;
        }

        // Should be a VAP pointer for each local BSS
        if (!candidateList[i].vap) {
            dbgf(steerexecImplBSAState.dbgModule, DBGERR,
                 "%s: Candidate list contains local BSS " lbBSSInfoAddFmt()
                 " with invalid VAP pointer.  Will not steer.",
                 __func__, lbBSSInfoAddData(&candidateList[i]));
            return LBD_FALSE;
        }
    }

    // All candidates OK.
    return LBD_TRUE;
}
