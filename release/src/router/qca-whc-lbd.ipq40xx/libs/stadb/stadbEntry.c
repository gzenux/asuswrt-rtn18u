// vim: set et sw=4 sts=4 cindent:
/*
 * @File: stadbEntry.c
 *
 * @Abstract: Implementation of accessors and mutators for stadbEntry
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
#include <time.h>

#ifdef LBD_DBG_MENU
#include <cmd.h>
#endif

#include "stadbEntry.h"
#include "stadbEntryPrivate.h"
#include "stadbDiaglogDefs.h"
#include "stadb.h"

#include "lb_common.h"
#include "lb_assert.h"
#include "diaglog.h"

// Forward decls
static void stadbEntryMarkBandSupported(stadbEntry_handle_t handle,
                                        const lbd_bssInfo_t *bss);

static time_t stadbEntryGetTimestamp(void);
static void stadbEntryUpdateTimestamp(stadbEntry_handle_t entry);
static void stadbEntryBSSStatsUpdateTimestamp(stadbEntry_bssStatsHandle_t bssHandle);
static void stadbEntryResetBSSStatsEntry(stadbEntry_bssStatsHandle_t bssHandle,
                                         const lbd_bssInfo_t *newBSS);
static void stadbEntryFindBestPHYMode(stadbEntry_handle_t entry);
static LBD_BOOL stadbEntryIsValidAssociation(const struct timespec *ts,
                                             const lbd_bssInfo_t *bss,
                                             stadbEntry_handle_t entry,
                                             LBD_BOOL checkAssociation);
static LBD_BOOL stadbEntryUpdateBandPHYCapInfo(stadbEntry_handle_t handle,
                                               wlanif_band_e band,
                                               const wlanif_phyCapInfo_t *newPHYCap);

static size_t stadbEntryDetermineEntrySizeAndType(
        LBD_BOOL inNetwork, wlanif_capStateUpdate_e rrmStatus,
        size_t numRadiosLocal, size_t numRemoteBSSStats, size_t *numBSSStats,
        stadbEntryType_e *type);
static void stadbEntryRealloc(stadbEntry_handle_t entry);

static stadbEntry_bssStatsHandle_t stadbEntryFindSlotForBSSStats(
        stadbEntry_handle_t entry, const lbd_bssInfo_t *bss, LBD_BOOL localLRU);
static LBD_BOOL stadbEntryIsBSSOlder(stadbEntry_bssStatsHandle_t bssStat1,
                                     stadbEntry_bssStatsHandle_t bssStat2);
static void stadbEntrySetSupportedBand(stadbEntry_handle_t entry,
                                       wlanif_band_e band);


// Minimum time since association occurred when disassociation message
// is received.  If disassociation is received before this time, verify
// if the STA is really disassociated.  500 ms.
static const struct timespec STADB_ENTRY_MIN_TIME_ASSOCIATION = {0, 500000000};

const struct ether_addr *stadbEntry_getAddr(const stadbEntry_handle_t handle) {
    if (handle) {
        return &handle->addr;
    }

    return NULL;
}

LBD_BOOL stadbEntry_isMatchingAddr(const stadbEntry_handle_t entry,
                                   const struct ether_addr *addr) {
    if (!entry || !addr) {
        return LBD_FALSE;
    }

    return lbAreEqualMACAddrs(entry->addr.ether_addr_octet,
                              addr->ether_addr_octet);
}

LBD_BOOL stadbEntry_isBandSupported(const stadbEntry_handle_t entry,
                                    wlanif_band_e band) {
    if (!entry || band >= wlanif_band_invalid) {
        return LBD_FALSE;
    }

    return (entry->operatingBands & 1 << band) != 0;
}

LBD_BOOL stadbEntry_isSteeringDisallowed(const stadbEntry_handle_t entry){
    if (!entry) {
        return LBD_FALSE;
    }

    return entry->isSteeringDisallowed;
}

LBD_STATUS stadbEntry_setBandSupported(const stadbEntry_handle_t entry,
                                       wlanif_band_e band) {
    if (!entry || band >= wlanif_band_invalid) {
        return LBD_NOK;
    }

    if ((entry->operatingBands & (1 << band)) == 0) {
        stadbEntrySetDirtyIfInNetwork(entry);
    }

    entry->operatingBands |= 1 << band;
    return LBD_OK;
}

LBD_STATUS stadbEntry_setRemoteBandSupported(const stadbEntry_handle_t entry,
                                             wlanif_band_e band) {
    if (stadbEntry_setBandSupported(entry, band) == LBD_NOK) {
        return LBD_NOK;
    }

    stadbEntry_bssStatsHandle_t servingBSS = stadbEntry_getServingBSS(entry, NULL);
    const lbd_bssInfo_t *bssInfo = stadbEntry_resolveBSSInfo(servingBSS);

    stadbEntryPopulateBSSesFromSameESS(entry, bssInfo, band);

    return LBD_OK;
}

LBD_BOOL stadbEntry_isDualBand(const stadbEntry_handle_t entry) {
    if (!entry) {
        return LBD_FALSE;
    }

    u_int8_t mask = (1 << wlanif_band_24g | 1 << wlanif_band_5g);
    return (entry->operatingBands & mask) == mask;
}

wlanif_band_e stadbEntry_getAssociatedBand(const stadbEntry_handle_t entry,
                                           time_t *deltaSecs) {
    if (!stadbEntry_isInNetwork(entry)) {
        return wlanif_band_invalid;
    }

    if (!entry->inNetworkInfo->assoc.bssHandle) {
        return wlanif_band_invalid;
    }

    if (deltaSecs) {
        time_t curTime = stadbEntryGetTimestamp();
        *deltaSecs = curTime - entry->inNetworkInfo->assoc.lastAssoc.tv_sec;
    }

    return stadbEntry_resolveBandFromBSSStats(entry->inNetworkInfo->assoc.bssHandle);
}

LBD_BOOL stadbEntry_isInNetwork(const stadbEntry_handle_t entry) {
    if (!entry) {
        return LBD_FALSE;
    }

    return entry->entryType == stadbEntryType_inNetworkLocal ||
           entry->entryType == stadbEntryType_inNetworkLocalRemote;
}

LBD_STATUS stadbEntry_getAge(const stadbEntry_handle_t entry, time_t *ageSecs) {
    if (!entry || !ageSecs) {
        return LBD_NOK;
    }

    *ageSecs = stadbEntryGetTimestamp() - entry->lastUpdateSecs;
    return LBD_OK;
}

void *stadbEntry_getSteeringState(stadbEntry_handle_t entry) {
    if (stadbEntry_isInNetwork(entry)) {
        return entry->inNetworkInfo->steeringState;
    }

    return NULL;
}

LBD_STATUS stadbEntry_setSteeringState(
        stadbEntry_handle_t entry, void *state,
        stadbEntry_stateLifecycleCB_t callback) {
    if ((state && !callback) || !stadbEntry_isInNetwork(entry)) {
        return LBD_NOK;
    }

    entry->inNetworkInfo->steeringState = state;
    entry->inNetworkInfo->steeringStateLifecycleCB = callback;
    return LBD_OK;
}

void *stadbEntry_getEstimatorState(stadbEntry_handle_t entry) {
    if (stadbEntry_isInNetwork(entry)) {
        return entry->inNetworkInfo->estimatorState;
    }

    return NULL;
}

LBD_STATUS stadbEntry_setEstimatorState(
        stadbEntry_handle_t entry, void *state,
        stadbEntry_stateLifecycleCB_t callback) {
    if ((state && !callback) || !stadbEntry_isInNetwork(entry)) {
        return LBD_NOK;
    }

    entry->inNetworkInfo->estimatorState = state;
    entry->inNetworkInfo->estimatorStateLifecycleCB = callback;
    return LBD_OK;
}

void *stadbEntry_getSteerMsgState(stadbEntry_handle_t entry) {
    if (stadbEntry_isInNetwork(entry)) {
        return entry->inNetworkInfo->steermsgState;
    }

    return NULL;
}

LBD_STATUS stadbEntry_setSteerMsgState(
        stadbEntry_handle_t entry, void *state,
        stadbEntry_stateLifecycleCB_t callback) {
    if ((state && !callback) || !stadbEntry_isInNetwork(entry)) {
        return LBD_NOK;
    }

    entry->inNetworkInfo->steermsgState = state;
    entry->inNetworkInfo->steermsgStateLifecycleCB = callback;
    return LBD_OK;
}

LBD_STATUS stadbEntry_getActStatus(const stadbEntry_handle_t entry, LBD_BOOL *active, time_t *deltaSecs) {
    if (!entry || !active) {
        return LBD_NOK;
    }

    if (!stadbEntry_getServingBSS(entry, NULL)) {
        // If an entry is not associated, there is no activity status
        return LBD_NOK;
    }

    if (deltaSecs) {
        time_t curTime = stadbEntryGetTimestamp();
        *deltaSecs = curTime - entry->inNetworkInfo->lastActUpdate;
    }

    *active = entry->isAct;

    return LBD_OK;
}

// ====================================================================
// "Package" and private helper functions
// ====================================================================

stadbEntry_handle_t stadbEntryCreate(const struct ether_addr *addr, LBD_BOOL inNetwork,
                                     wlanif_capStateUpdate_e rrmStatus,
                                     size_t numRadiosLocal, size_t numRemoteBSSStats) {
    if (!addr) {
        return NULL;
    }

    size_t numBSSStats = 0;
    stadbEntryType_e entryType = stadbEntryType_invalid;
    size_t entrySize =
        stadbEntryDetermineEntrySizeAndType(inNetwork, rrmStatus, numRadiosLocal,
                                            numRemoteBSSStats, &numBSSStats, &entryType);

    stadbEntry_handle_t entry = calloc(1, entrySize);
    if (entry) {
        lbCopyMACAddr(addr->ether_addr_octet, entry->addr.ether_addr_octet);
        entry->entryType = entryType;
        stadbEntryUpdateTimestamp(entry);
        if (entryType != stadbEntryType_outOfNetwork) {
            entry->inNetworkInfo->assoc.channel = LBD_CHANNEL_INVALID;
            entry->inNetworkInfo->assoc.lastServingESS = LBD_ESSID_INVALID;

            entry->inNetworkInfo->numBSSStats = numBSSStats;
            // All BSS stats entries should be invalid at this point. Before using a new
            // BSS stats entry, need to make sure it is reset so that all fields have invalid
            // values. (Currently done in stadbEntryFindBSSStats)
        }
    }

    return entry;
}

stadbEntry_handle_t stadbEntryChangeEntryType(
        stadbEntry_handle_t entry, wlanif_capStateUpdate_e rrmStatus,
        size_t numRadiosLocal, size_t numRemoteBSSStats) {
    lbDbgAssertExit(NULL, entry && numRadiosLocal);

    size_t numBSSStats = 0;
    stadbEntryType_e newEntryType = stadbEntryType_invalid;
    size_t entrySize =
        stadbEntryDetermineEntrySizeAndType(LBD_TRUE /* inNetwork */, rrmStatus, numRadiosLocal,
                                            numRemoteBSSStats, &numBSSStats, &newEntryType);

    if (entry->entryType == newEntryType) {
        return entry;
    }

    stadbEntry_handle_t newEntry = realloc(entry, entrySize);
    if (newEntry) {
        if (newEntry->entryType == stadbEntryType_outOfNetwork) {
            memset(newEntry->inNetworkInfo, 0, sizeof(stadbEntryPriv_inNetworkInfo_t));
            memset(newEntry->inNetworkInfo->bssStats, 0,
                   sizeof(stadbEntryPriv_bssStats_t) * numBSSStats);
            newEntry->inNetworkInfo->assoc.channel = LBD_CHANNEL_INVALID;
            newEntry->inNetworkInfo->assoc.lastServingESS = LBD_ESSID_INVALID;
        } else {
            // From in-network local to in-network local and remote
            memset(&newEntry->inNetworkInfo->bssStats[numRadiosLocal], 0,
                   sizeof(stadbEntryPriv_bssStats_t) * numRemoteBSSStats);
        }
        newEntry->inNetworkInfo->numBSSStats = numBSSStats;
        newEntry->entryType = newEntryType;

        // All new allocated BSS stats entries should be invalid at this point. If an entry
        // was out-of-network, then all BSS entries are invalid; if it was in-network local
        // only entries, then all remote BSS entries are invalid, and local ones will remain
        // unchanged. Before using a new BSS stats entry, need to make sure it is reset so that
        // all fields have invalid values. (Currently done in stadbEntryFindBSSStats)

        // Let the lifecycle callbacks react to the fact that the entry was reallocated.
        stadbEntryRealloc(newEntry);
        stadbEntrySetDirtyIfInNetwork(newEntry);
    } else {  // realloc failed
        // In this case, we want to clean up the old memory block, since the
        // caller will interpret a non-NULL value as success.
        stadbEntryDestroy(entry);
    }

    return newEntry;
}

LBD_STATUS stadbEntryRecordRSSI(stadbEntry_handle_t entry,
                                const lbd_bssInfo_t *bss,
                                lbd_rssi_t rssi) {
    if (!entry || !bss) { return LBD_NOK; }

    stadbEntryMarkBandSupported(entry, bss);

    if (!stadbEntry_isInNetwork(entry)) {
        // No RSSI update for out-of-network STA
        return LBD_NOK;
    }

    time_t curTime = stadbEntryGetTimestamp();

    stadbEntry_bssStatsHandle_t bssHandle =
        stadbEntryFindBSSStats(entry, bss, LBD_FALSE /* matchOnly */);

    bssHandle->uplinkInfo.rssi = rssi;
    bssHandle->uplinkInfo.lastUpdateSecs = curTime;
    bssHandle->uplinkInfo.probeCount = 0;
    bssHandle->uplinkInfo.estimate = LBD_FALSE;

    bssHandle->lastUpdateSecs = curTime;

    if (diaglog_startEntry(mdModuleID_StaDB,
                           stadb_msgId_rssiUpdate,
                           diaglog_level_demo)) {
        diaglog_writeMAC(&entry->addr);
        diaglog_writeBSSInfo(bss);
        diaglog_write8(rssi);
        diaglog_finishEntry();
    }

    return LBD_OK;
}

LBD_STATUS stadbEntryRecordProbeRSSI(stadbEntry_handle_t entry,
                                     const lbd_bssInfo_t *bss,
                                     lbd_rssi_t rssi, time_t maxInterval) {
    if (!entry || !bss) { return LBD_NOK; }

    stadbEntryMarkBandSupported(entry, bss);

    if (!stadbEntry_isInNetwork(entry)) {
        // No RSSI update for out-of-network STA
        return LBD_NOK;
    }

    if (entry->inNetworkInfo->assoc.bssHandle &&
        lbAreBSSesSame(bss, &entry->inNetworkInfo->assoc.bssHandle->bss)) {
        // Ignore probes on the associated band since they present an
        // instantaneous measurement and may not be as accurate as our
        // average RSSI report or triggered RSSI measurement which are
        // both taken over a series of measurements.
        return LBD_NOK;
    }

    lbd_essId_t lastServingESS = stadbEntryGetLastServingESS(entry);
    if (lastServingESS != LBD_ESSID_INVALID &&
        bss->essId != lastServingESS) {
        // Only handle probes when the STA has never associated or if STA
        // probes on the same ESS as last association
        return LBD_NOK;
    }

    time_t curTime = stadbEntryGetTimestamp();

    stadbEntry_bssStatsHandle_t bssHandle =
        stadbEntryFindBSSStats(entry, bss, LBD_FALSE /* matchOnly */);
    bssHandle->lastUpdateSecs = curTime;

    if (!bssHandle->uplinkInfo.probeCount ||
        (curTime - bssHandle->uplinkInfo.lastUpdateSecs) > maxInterval) {
        // Reset probe RSSI averaging
        bssHandle->uplinkInfo.rssi = rssi;
        bssHandle->uplinkInfo.lastUpdateSecs = curTime;
        bssHandle->uplinkInfo.probeCount = 1;
        bssHandle->uplinkInfo.estimate = LBD_FALSE;
    } else {
        // Average this one with previous measurements
        bssHandle->uplinkInfo.rssi =
            (bssHandle->uplinkInfo.rssi * bssHandle->uplinkInfo.probeCount + rssi) /
            (bssHandle->uplinkInfo.probeCount + 1);
        bssHandle->uplinkInfo.lastUpdateSecs = curTime;
        ++bssHandle->uplinkInfo.probeCount;
    }

    if (diaglog_startEntry(mdModuleID_StaDB,
                           stadb_msgId_rssiUpdate,
                           diaglog_level_demo)) {
        diaglog_writeMAC(&entry->addr);
        diaglog_writeBSSInfo(bss);
        // Report averaged probe RSSI
        diaglog_write8(bssHandle->uplinkInfo.rssi);
        diaglog_finishEntry();
    }

    return LBD_OK;
}

/**
 * @brief Check if a given STA is associated on a given BSS
 *
 * @param [in] entry  the handle to the STA entry
 * @param [in] bss  the given BSS
 *
 * @pre the STA must be in-network and BSS is valid
 *
 * @return LBD_TRUE if the STA is associated on the given BSS; otherwise
 *         return LBD_FALSE
 */
static inline LBD_BOOL stadbEntryIsAssociatedOnBSS(stadbEntry_handle_t entry,
                                                   const lbd_bssInfo_t *bss) {
    return entry->inNetworkInfo->assoc.bssHandle &&
           lbAreBSSesSame(&entry->inNetworkInfo->assoc.bssHandle->bss, bss);
}

LBD_STATUS stadbEntryMarkAssociated(stadbEntry_handle_t entry,
                                    const lbd_bssInfo_t *bss,
                                    LBD_BOOL isAssociated,
                                    LBD_BOOL updateActive,
                                    LBD_BOOL verifyAssociation,
                                    LBD_BOOL *assocChanged) {
    if (assocChanged) {
        *assocChanged = LBD_FALSE;
    }
    if (!bss || !stadbEntry_isInNetwork(entry)) {
        return LBD_NOK;
    }

    // Did the association status change?
    LBD_BOOL assocSame = entry->inNetworkInfo->assoc.bssHandle &&
                         lbAreBSSesSame(&entry->inNetworkInfo->assoc.bssHandle->bss, bss);
    lbd_channelId_t oldAssocChannel = entry->inNetworkInfo->assoc.channel;
    lbd_essId_t oldServingESS = entry->inNetworkInfo->assoc.lastServingESS;

    struct timespec ts = {0};
    lbGetTimestamp(&ts);
    stadbEntryMarkBandSupported(entry, bss);

    if (isAssociated) {
        if (verifyAssociation) {
            if (oldAssocChannel == LBD_CHANNEL_INVALID) {
                // This check should always return LBD_TRUE under normal
                // circumstances.  It is added to be overly cautious and ensure
                // that we only receive notifications on an interface
                // the STA is associated on.
                if (!stadbEntryIsValidAssociation(&ts, bss, entry,
                                                  LBD_TRUE /* checkAssociation */)) {
                    // STA is not actually associated even though we got an
                    // update, ignore.
                    return LBD_OK;
                }
            } else {
                // If we are verifying the association, ignore association
                // updates when we are already associated.  In this case
                // we can't disambiguate the associations (it's caused by
                // an unclean disassociation / spurious messages from firmware),
                // so ignore until one of the entries times out.
                return LBD_OK;
            }
        }

        // Only update the last association time if the VAP on which we
        // previously thought the STA was associated is out of date/wrong.
        if (!assocSame) {
            entry->inNetworkInfo->assoc.lastAssoc = ts;
        }

        stadbEntry_bssStatsHandle_t bssHandle =
            stadbEntryFindBSSStats(entry, bss, LBD_FALSE /* matchOnly */);
        entry->inNetworkInfo->assoc.bssHandle = bssHandle;
        entry->inNetworkInfo->assoc.channel = bss->channelId;
        entry->inNetworkInfo->assoc.lastServingESS = bss->essId;
        if (updateActive) {
            // Also mark entry as active
            entry->isAct = LBD_TRUE;
            entry->inNetworkInfo->lastActUpdate = ts.tv_sec;
        }
    } else if ((assocSame &&
                stadbEntryIsValidAssociation(&ts, bss, entry,
                                             LBD_FALSE /* checkAssociation */)) ||
               !entry->inNetworkInfo->assoc.bssHandle) {
        entry->inNetworkInfo->assoc.bssHandle = NULL;
        entry->inNetworkInfo->assoc.channel = LBD_CHANNEL_INVALID;

        // Also mark entry as inactive
        entry->isAct = LBD_FALSE;
        entry->inNetworkInfo->lastActUpdate = ts.tv_sec;
        stadbEntrySetDirtyIfInNetwork(entry);
    }

    if (oldAssocChannel != entry->inNetworkInfo->assoc.channel ||
        oldServingESS != entry->inNetworkInfo->assoc.lastServingESS) {
        // Association status changed, including ESS change
        if (assocChanged) {
            *assocChanged = LBD_TRUE;
        }

        stadbEntryAssocDiagLog(entry, bss);
    }

    return LBD_OK;
}

LBD_STATUS stadbEntry_updateIsBTMSupported(stadbEntry_handle_t entry,
                                           LBD_BOOL isBTMSupported,
                                           LBD_BOOL *changed) {
    if (!entry) {
        return LBD_NOK;
    }

    if (changed) {
        if (entry->isBTMSupported == isBTMSupported) {
            *changed = LBD_FALSE;
        } else {
            *changed = LBD_TRUE;
            stadbEntrySetDirtyIfInNetwork(entry);
        }
    }

    // update if BTM is supported
    entry->isBTMSupported = isBTMSupported;

    return LBD_OK;
}

LBD_STATUS stadbEntryUpdateIsRRMSupported(stadbEntry_handle_t entry,
                                          LBD_BOOL isRRMSupported) {
    if (!entry) {
        return LBD_NOK;
    }

    if (entry->isRRMSupported != isRRMSupported) {
        stadbEntrySetDirtyIfInNetwork(entry);
    }

    // update if RRM is supported
    entry->isRRMSupported = isRRMSupported;

    return LBD_OK;
}

LBD_STATUS stadbEntryUpdateMUMIMOMode(stadbEntry_handle_t entry,
                                      LBD_BOOL isMUMIMOSupported) {
    if (!entry) {
        return LBD_NOK;
    }

    if (entry->isMUMIMOSupported != isMUMIMOSupported) {
        stadbEntrySetDirtyIfInNetwork(entry);
    }

    // update if MU-MIMO is supported
    entry->isMUMIMOSupported = isMUMIMOSupported;

    return LBD_OK;
}

/**
 * @brief React to an entry that has been reallocated by informing the
 *        registered state objects.
 *
 * @param [in] entry  the entry that was reallocated
 */
static void stadbEntryRealloc(stadbEntry_handle_t entry) {
    lbDbgAssertExit(NULL, stadbEntry_isInNetwork(entry));
    if (entry->inNetworkInfo->steeringState) {
        lbDbgAssertExit(NULL, entry->inNetworkInfo->steeringStateLifecycleCB);
        entry->inNetworkInfo->steeringStateLifecycleCB(
                entry, entry->inNetworkInfo->steeringState);
    }
    if (entry->inNetworkInfo->estimatorState) {
        lbDbgAssertExit(NULL, entry->inNetworkInfo->estimatorStateLifecycleCB);
        entry->inNetworkInfo->estimatorStateLifecycleCB(
                entry, entry->inNetworkInfo->estimatorState);
    }

    if (entry->inNetworkInfo->steermsgState) {
        lbDbgAssertExit(NULL, entry->inNetworkInfo->steermsgStateLifecycleCB);
        entry->inNetworkInfo->steermsgStateLifecycleCB(
                entry, entry->inNetworkInfo->steermsgState);
    }
}

void stadbEntryDestroy(stadbEntry_handle_t entry) {
    if (stadbEntry_isInNetwork(entry)) {
        if (entry->inNetworkInfo->steeringState) {
            lbDbgAssertExit(NULL, entry->inNetworkInfo->steeringStateLifecycleCB);
            entry->inNetworkInfo->steeringStateLifecycleCB(
                    NULL, entry->inNetworkInfo->steeringState);
        }
        if (entry->inNetworkInfo->estimatorState) {
            lbDbgAssertExit(NULL, entry->inNetworkInfo->estimatorStateLifecycleCB);
            entry->inNetworkInfo->estimatorStateLifecycleCB(
                    NULL, entry->inNetworkInfo->estimatorState);
        }

        if (entry->inNetworkInfo->steermsgState) {
            lbDbgAssertExit(NULL, entry->inNetworkInfo->steermsgStateLifecycleCB);
            entry->inNetworkInfo->steermsgStateLifecycleCB(
                    NULL, entry->inNetworkInfo->steermsgState);
        }
    }

    free(entry);
}

LBD_STATUS stadbEntryMarkActive(stadbEntry_handle_t entry,
                                const lbd_bssInfo_t *bss,
                                LBD_BOOL active) {
    if (!bss || !stadbEntry_isInNetwork(entry)) {
        return LBD_NOK;
    }

    // Only mark the entry as associated if it is being reported as active.
    // If we did it always, we might change the associated band due to the
    // STA having moved from one band to another without cleanly
    // disassociating.
    //
    // For example, if the STA is on 5 GHz and then moves to 2.4 GHz without
    // cleanly disassociating, the driver will still have an activity timer
    // running on 5 GHz. When that expires, if we mark it as associated, we
    // will clobber our current association state (of 2.4 GHz) with this 5 GHz
    // one. This will cause RSSI measurements and steering to be done with the
    // wrong band.
    //
    // Note that we do not update activity status, as it will be done
    // immediately below. We cannot let it mark the activity status as it
    // always sets the status to active for an associated device and inactive
    // for an unassociated device.
    if (active) {
        stadbEntryMarkAssociated(entry, bss, LBD_TRUE, /* isAssociated */
                                 LBD_FALSE /* updateActive */,
                                 LBD_TRUE /* verifyAssociation */,
                                 NULL /* assocChanged */);
    }

    // Only update the activity if the device is associated, as if it is not,
    // we do not know for sure that it is really a legitimate association
    // (see the note above for reasons).
    if (stadbEntryIsAssociatedOnBSS(entry, bss)) {
        entry->isAct = active;
        entry->inNetworkInfo->lastActUpdate = stadbEntryGetTimestamp();

        if (diaglog_startEntry(mdModuleID_StaDB, stadb_msgId_activityUpdate,
                               diaglog_level_demo)) {
            diaglog_writeMAC(&entry->addr);
            diaglog_writeBSSInfo(bss);
            diaglog_write8(entry->isAct);
            diaglog_finishEntry();
        }
    }

    return LBD_OK;
}

/**
 * @brief Mark the provided band as being supported by this entry.
 *
 * @param [in] handle  the handle to the entry to modify
 * @param [in] band  the band to enable for the entry
 *
 * @return LBD_OK on success; otherwise LBD_NOK
 */
static void stadbEntryMarkBandSupported(stadbEntry_handle_t entry,
                                        const lbd_bssInfo_t *bss) {
    lbDbgAssertExit(NULL, entry && bss);
    wlanif_band_e band = wlanif_resolveBandFromChannelNumber(bss->channelId);
    stadbEntrySetSupportedBand(entry, band);
    stadbEntryUpdateTimestamp(entry);
}

/**
 * @brief Set the provided band as being supported by this entry
 *
 * A dual band diaglog will be generated when the entry is marked as
 * dual band for the first time.
 *
 * @param [in] entry  the STA entry to set supported band
 * @param [in] band  the band to set
 */
static void stadbEntrySetSupportedBand(stadbEntry_handle_t entry,
                                       wlanif_band_e band) {
    LBD_BOOL wasDualBand = stadbEntry_isDualBand(entry);

    if ((entry->operatingBands & (1 << band)) == 0) {
        stadbEntrySetDirtyIfInNetwork(entry);
    }

    entry->operatingBands |= 1 << band;

    if (stadbEntry_isInNetwork(entry) &&
        !wasDualBand && stadbEntry_isDualBand(entry) &&
        diaglog_startEntry(mdModuleID_StaDB,
                           stadb_msgId_dualBandUpdate,
                           diaglog_level_demo)) {
        diaglog_writeMAC(&entry->addr);
        diaglog_write8(LBD_TRUE);
        diaglog_finishEntry();
    }
}

/**
 * @brief Determine if an association or disassociation is
 *        valid.
 *
 * On disassociation: Treated as valid if the association is
 * older than STADB_ENTRY_MIN_TIME_ASSOCIATION or the STA is
 * verified as disassociated via wlanif
 *
 * On association: Treated as valid if the STA is verified as
 * associated on bss via wlanif
 *
 * @param [in] ts  current time
 * @param [in] bss BSS to check for association on
 * @param [in] entry  stadb entry to check for association
 * @param [in] checkAssociation  if LBD_TRUE check if STA is
 *                               associated on bss; if LBD_FALSE
 *                               check if STA is disassociated
 *                               on bss
 *
 * @return LBD_TRUE if the association is valid; LBD_FALSE
 *         otherwise
 */
static LBD_BOOL stadbEntryIsValidAssociation(const struct timespec *ts,
                                             const lbd_bssInfo_t *bss,
                                             stadbEntry_handle_t entry,
                                             LBD_BOOL checkAssociation) {
    if (!checkAssociation) {
        // If this is disassociation, check the time relative to the last
        // association.
        struct timespec diff;
        lbTimeDiff(ts, &entry->inNetworkInfo->assoc.lastAssoc, &diff);
        if (lbIsTimeAfter(&diff, &STADB_ENTRY_MIN_TIME_ASSOCIATION)) {
            // The association happened more than the min time ago, treat it as valid
            return LBD_TRUE;
        }
    }

    // Check if the STA is really associated
    LBD_BOOL isAssociation = wlanif_isSTAAssociated(bss, &entry->addr);

    // Check if the association state matches what we were checking for.
    return (isAssociation == checkAssociation);
}

LBD_BOOL stadbEntry_isBTMSupported(const stadbEntry_handle_t entry) {
    lbDbgAssertExit(NULL, entry);

    return entry->isBTMSupported;
}

LBD_BOOL stadbEntry_isRRMSupported(const stadbEntry_handle_t entry) {
    lbDbgAssertExit(NULL, entry);

    return entry->isRRMSupported;
}

LBD_BOOL stadbEntry_isMUMIMOSupported(const stadbEntry_handle_t entry) {
    lbDbgAssertExit(NULL, entry);

    return entry->isMUMIMOSupported;
}

/**
 * @brief Get a timestamp in seconds for use in delta computations.
 *
 * @return the current time in seconds
 */
static time_t stadbEntryGetTimestamp(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);

    return ts.tv_sec;
}

/**
 * @brief Update the timestamp in the entry that stores the last time it was
 *        updated.
 *
 * @param [in] entry   the handle to the entry to update
 */
static void stadbEntryUpdateTimestamp(stadbEntry_handle_t entry) {
    lbDbgAssertExit(NULL, entry);
    entry->lastUpdateSecs = stadbEntryGetTimestamp();
}

u_int8_t stadbEntryComputeHashCode(const struct ether_addr *addr) {
    return lbMACAddHash(addr->ether_addr_octet);
}

#ifdef LBD_DBG_MENU
static const char *stadbEntryChWidthString[] = {
    "20MHz",
    "40MHz",
    "80MHz",
    "160MHz",
    "NA"
};

static const char *stadbEntryPHYModeString[] = {
    "BASIC",
    "HT",
    "VHT",
    "NA"
};

// Definitions used to help format debug output,
#define MAC_ADDR_STR_LEN 25
#define BSS_INFO_STR_LEN 30
#define ASSOC_STR_LEN (BSS_INFO_STR_LEN + 10) // BSS (age)
#define ACTIVITY_STR_LEN 20
#define PHY_FIELD_LEN 15
#define RSSI_STR_LEN 25 // RSSI (age) (flag)
#define RATE_INFO_FIELD_LEN 15
#define RESERVED_AIRTIME_LEN 20
#define BAND_STR_LEN 10
#define POLLUTION_FLAG_LEN 25 // Polluted (expiry secs)

void stadbEntryPrintSummaryHeader(struct cmdContext *context, LBD_BOOL inNetwork) {
    cmdf(context, "%-*s%-10s%-10s", MAC_ADDR_STR_LEN, "MAC Address", "Age", "Bands");
    if (inNetwork) {
        cmdf(context, "%-*s%-*s%-10s\n",
             ASSOC_STR_LEN, "Assoc? (age)", ACTIVITY_STR_LEN, "Active? (age)", "Flags");
    } else {
        cmdf(context, "\n");
    }
}

void stadbEntryPrintSummary(const stadbEntry_handle_t entry,
                            struct cmdContext *context,
                            LBD_BOOL inNetwork) {
    if (!entry) {
        return;
    } else if (stadbEntry_isInNetwork(entry) ^ inNetwork) {
        return;
    }

    time_t curTime = stadbEntryGetTimestamp();
    cmdf(context, lbMACAddFmt(":") "        %-10u%c%c        ",
         lbMACAddData(entry->addr.ether_addr_octet),
         curTime - entry->lastUpdateSecs,
         stadbEntry_isBandSupported(entry, wlanif_band_24g) ? '2' : ' ',
         stadbEntry_isBandSupported(entry, wlanif_band_5g) ? '5' : ' ');

    if (!inNetwork) {
        cmdf(context, " %s  \n",entry->isSteeringDisallowed?"Steer Disallowed":"Steer Allowed");
        return;
    }

    char assocStr[ASSOC_STR_LEN + 1]; // Add one for null terminator
    if (!entry->inNetworkInfo->assoc.bssHandle) {
        snprintf(assocStr, sizeof(assocStr), "       (%u)",
                 (unsigned int)(curTime - entry->inNetworkInfo->assoc.lastAssoc.tv_sec));
    } else {
        snprintf(assocStr, sizeof(assocStr), lbBSSInfoAddFmt() " (%u)",
                 lbBSSInfoAddData(&entry->inNetworkInfo->assoc.bssHandle->bss),
                 (unsigned int)(curTime - entry->inNetworkInfo->assoc.lastAssoc.tv_sec));
    }
    cmdf(context, "%-*s", ASSOC_STR_LEN, assocStr);

    if (entry->inNetworkInfo->assoc.bssHandle) {
        char activityStr[ACTIVITY_STR_LEN + 1]; // Add one for null terminator
        snprintf(activityStr, sizeof(activityStr), "%-3s (%u)",
                 entry->isAct ? "yes" : "no",
                 (unsigned int)(curTime - entry->inNetworkInfo->lastActUpdate));
        cmdf(context, "%-*s", ACTIVITY_STR_LEN, activityStr);
    } else {
        cmdf(context, "%-*s", ACTIVITY_STR_LEN, " ");
    }

    cmdf(context, "%s%s%s%s%s%s",
         entry->isBTMSupported ? "BTM " : "",
         entry->isRRMSupported ? "RRM " : "",
         entry->hasReservedAirtime ? "RA " : "",
         entry->isMUMIMOSupported ? "MU " : "",
         entry->isStaticSMPS ? "PS" : "",
         entry->isSteeringDisallowed ? "  Steer Disallowed":"  Steer Allowed");

    cmdf(context, "\n");
}

void stadbEntryPrintDetailHeader(struct cmdContext *context,
                                 stadbEntryDBGInfoType_e infoType,
                                 LBD_BOOL listAddr) {
    if (listAddr) {
        cmdf(context, "%-*s", MAC_ADDR_STR_LEN, "MAC Address");
    }
    switch (infoType) {
        case stadbEntryDBGInfoType_phy:
            cmdf(context, "%-*s%-*s%-*s%-*s%-*s%-*s",
                 BAND_STR_LEN, "Band",
                 PHY_FIELD_LEN, "MaxChWidth",
                 PHY_FIELD_LEN, "NumStreams",
                 PHY_FIELD_LEN, "PHYMode",
                 PHY_FIELD_LEN, "MaxMCS",
                 PHY_FIELD_LEN, "MaxTxPower");
            break;
        case stadbEntryDBGInfoType_bss:
            cmdf(context, "%-*s", BSS_INFO_STR_LEN, "BSS Info");
            cmdf(context, "%-*s%-*s%-*s",
                 RSSI_STR_LEN, "RSSI (age) (flags)",
                 RESERVED_AIRTIME_LEN, "Reserved Airtime",
                 POLLUTION_FLAG_LEN, "Polluted (expiry secs)");
            break;
        case stadbEntryDBGInfoType_rate_measured:
            cmdf(context, "%-*s", BSS_INFO_STR_LEN, "BSS Info");
            cmdf(context, "%-*s%-*s%-*s",
                 RATE_INFO_FIELD_LEN, "DLRate (Mbps)",
                 RATE_INFO_FIELD_LEN, "ULRate (Mbps)",
                 RATE_INFO_FIELD_LEN, "Age (seconds)");
            break;
        case stadbEntryDBGInfoType_rate_estimated:
            cmdf(context, "%-*s", BSS_INFO_STR_LEN, "BSS Info");
            cmdf(context, "%-*s%-*s%-*s",
                 RATE_INFO_FIELD_LEN, "fullCap (Mbps)",
                 RATE_INFO_FIELD_LEN, "airtime (%)",
                 RATE_INFO_FIELD_LEN, "Age (seconds)");
            break;
        default:
            break;
    }

    cmdf(context, "\n");
}

/**
 * @brief Parameters used when iterating BSS stats to print
 *        detailed information
 */
typedef struct stadbEntryPrintDetailCBParams_t {
    /// The context to print details
    struct cmdContext *context;
    /// The type of the detailed info to print
    stadbEntryDBGInfoType_e infoType;
    /// Whether to print MAC address
    LBD_BOOL listAddr;
} stadbEntryPrintDetailCBParams_t;

/**
 * @brief Print common information for each detailed info entry of a given STA
 *
 * @param [in] entry  the handle to the STA
 * @param [in] bssHandle  the handle to the BSS stats
 * @param [in] context  the output stream to print
 * @param [in] listAddr  whether to print MAC address
 */
static void stadbEntryPrintDetailCommonInfo(stadbEntry_handle_t entry,
                                            stadbEntry_bssStatsHandle_t bssHandle,
                                            struct cmdContext *context,
                                            LBD_BOOL listAddr) {
    if (listAddr) {
        char macStr[MAC_ADDR_STR_LEN + 1];
        snprintf(macStr, sizeof(macStr), lbMACAddFmt(":"), lbMACAddData(entry->addr.ether_addr_octet));
        cmdf(context, "%-*s", MAC_ADDR_STR_LEN, macStr);
    }

    char bssStr[BSS_INFO_STR_LEN + 1];
    snprintf(bssStr, sizeof(bssStr), lbBSSInfoAddFmt(), lbBSSInfoAddData(&bssHandle->bss));
    cmdf(context, "%-*s", BSS_INFO_STR_LEN, bssStr);
}

/**
 * @brief Callback function to print details of requested information on a BSS of a given STA
 *
 * @param [in] entry  the handle to the STA
 * @param [in] bssHandle  the handle to the BSS
 * @param [in] cookie  the parameters provided to the iteration
 *
 * @return LBD_FALSE (not used)
 */
static LBD_BOOL stadbEntryPrintDetailCB(stadbEntry_handle_t entry,
                                        stadbEntry_bssStatsHandle_t bssHandle,
                                        void *cookie) {
    stadbEntryPrintDetailCBParams_t *params = (stadbEntryPrintDetailCBParams_t *) cookie;

    switch (params->infoType) {
        case stadbEntryDBGInfoType_bss:
            // Always show BSS entry regardless of whether RSSI is valid or not
            stadbEntryPrintDetailCommonInfo(entry, bssHandle, params->context, params->listAddr);
            time_t curTime = stadbEntryGetTimestamp();
            if (bssHandle->uplinkInfo.rssi != LBD_INVALID_RSSI) {
                char rssiStr[RSSI_STR_LEN + 1];
                snprintf(rssiStr, sizeof(rssiStr), "%u (%lu) (%c%c)",
                         bssHandle->uplinkInfo.rssi,
                         curTime - bssHandle->uplinkInfo.lastUpdateSecs,
                         bssHandle->uplinkInfo.probeCount ? 'P' : ' ',
                         bssHandle->uplinkInfo.estimate ? 'E' : ' ');
                cmdf(params->context, "%-*s", RSSI_STR_LEN, rssiStr);
            } else {
                cmdf(params->context, "%-*s", RSSI_STR_LEN, " ");
            }

            if (bssHandle->reservedAirtime != LBD_INVALID_AIRTIME) {
                char airtimeStr[RESERVED_AIRTIME_LEN + 1];
                snprintf(airtimeStr, sizeof(airtimeStr), "%u%%",
                         bssHandle->reservedAirtime);
                cmdf(params->context, "%-*s", RESERVED_AIRTIME_LEN, airtimeStr);
            } else {
                cmdf(params->context, "%-*s", RESERVED_AIRTIME_LEN, " ");
            }

            char pollutionFlagStr[POLLUTION_FLAG_LEN + 1];
            snprintf(pollutionFlagStr, sizeof(pollutionFlagStr),
                     "%s (%lu)", bssHandle->polluted ? "yes" : "no",
                     bssHandle->polluted && bssHandle->pollutionExpirySecs > curTime ?
                         bssHandle->pollutionExpirySecs - curTime : 0);
            cmdf(params->context, "%-*s", POLLUTION_FLAG_LEN, pollutionFlagStr);

            cmdf(params->context, "\n");
            break;
        case stadbEntryDBGInfoType_rate_estimated:
            if (bssHandle->downlinkInfo.fullCapacity != LBD_INVALID_LINK_CAP) {
                stadbEntryPrintDetailCommonInfo(entry, bssHandle, params->context, params->listAddr);
                time_t curTime = stadbEntryGetTimestamp();
                cmdf(params->context, "%-*u%-*u%-*lu\n",
                     RATE_INFO_FIELD_LEN, bssHandle->downlinkInfo.fullCapacity,
                     RATE_INFO_FIELD_LEN, bssHandle->downlinkInfo.airtime,
                     RATE_INFO_FIELD_LEN, curTime - bssHandle->downlinkInfo.lastUpdateSecs);
            }
            break;
        default:
            break;
    }

    return LBD_FALSE;
}

/**
 * @brief Print the measured rate info of a given STA
 *
 * @param [in] context  the output stream to print
 * @param [in] entry  the handle to the STA
 * @param [in] listAddr  whether to print MAC address
 */
static void stadbEntryPrintMeasuredRate(struct cmdContext *context,
                                        const stadbEntry_handle_t entry,
                                        LBD_BOOL listAddr) {
    if (!entry->inNetworkInfo->assoc.bssHandle || !entry->validDataRate) {
        // Ignore not associated STA or STA without measured rate
        return;
    }

    stadbEntryPrintDetailCommonInfo(entry, entry->inNetworkInfo->assoc.bssHandle, context, listAddr);
    time_t curTime = stadbEntryGetTimestamp();
    cmdf(context, "%-*u%-*u%-*lu\n",
         RATE_INFO_FIELD_LEN, entry->inNetworkInfo->dataRateInfo.downlinkRate,
         RATE_INFO_FIELD_LEN, entry->inNetworkInfo->dataRateInfo.uplinkRate,
         RATE_INFO_FIELD_LEN, curTime - entry->inNetworkInfo->dataRateInfo.lastUpdateSecs);

    cmdf(context, "\n");
}

/**
 * @brief Print PHY capability information for a given STA
 *
 * @param [in] context  the output stream to print
 * @param [in] entry  the handle to the STA
 * @param [in] listAddr  whether to print MAC address
 */
static void stadbEntryPrintPHYCapInfo(struct cmdContext *context,
                                      const stadbEntry_handle_t entry,
                                      LBD_BOOL listAddr) {
    wlanif_band_e band;
    for (band = wlanif_band_24g; band < wlanif_band_invalid; ++band) {
        const wlanif_phyCapInfo_t *phyCapInfo = &entry->inNetworkInfo->phyCapInfo[band];
        if (!phyCapInfo->valid) {
            continue;
        }
        if (listAddr) {
            char macStr[MAC_ADDR_STR_LEN + 1];
            snprintf(macStr, sizeof(macStr), lbMACAddFmt(":"),
                     lbMACAddData(entry->addr.ether_addr_octet));
            cmdf(context, "%-*s", MAC_ADDR_STR_LEN, macStr);
        }
        cmdf(context, "%-*c%-*s%-*u%-*s%-*u%-*u\n",
             BAND_STR_LEN, band == wlanif_band_24g ? '2' : '5',
             PHY_FIELD_LEN, stadbEntryChWidthString[phyCapInfo->maxChWidth],
             PHY_FIELD_LEN, phyCapInfo->numStreams,
             PHY_FIELD_LEN, stadbEntryPHYModeString[phyCapInfo->phyMode],
             PHY_FIELD_LEN, phyCapInfo->maxMCS,
             PHY_FIELD_LEN, phyCapInfo->maxTxPower);
    }
}

void stadbEntryPrintDetail(struct cmdContext *context,
                           const stadbEntry_handle_t entry,
                           stadbEntryDBGInfoType_e infoType,
                           LBD_BOOL listAddr) {
    if (infoType == stadbEntryDBGInfoType_rate_measured) {
        // Only have one measured rate info per STA
        stadbEntryPrintMeasuredRate(context, entry, listAddr);
    } else if (infoType == stadbEntryDBGInfoType_phy) {
        // One PHY capability info per band
        stadbEntryPrintPHYCapInfo(context, entry, listAddr);
    } else {
        // Other info will be one per BSS entry
        stadbEntryPrintDetailCBParams_t params = {
            context, infoType, listAddr
        };
        stadbEntry_iterateBSSStats(entry, stadbEntryPrintDetailCB, &params, NULL, NULL);
    }
}

#undef POLLUTION_FLAG_LEN
#undef BAND_STR_LEN
#undef RESERVED_AIRTIME_LEN
#undef MAC_ADDR_STR_LEN
#undef BSS_INFO_STR_LEN
#undef ASSOC_STR_LEN
#undef ACTIVITY_STR_LEN
#undef PHY_FIELD_LEN
#undef RSSI_STR_LEN
#undef RATE_INFO_FIELD_LEN

#endif /* LBD_DBG_MENU */

/*****************************************************
 *  New APIs
 ****************************************************/
/**
 * @brief Add BSS that meets requirement to the selected list
 *
 * The list is sorted, and this BSS will be inserted before the entries that
 * have a lower metric than it, or to the end if none. If there are already
 * enough better BSSes selected, do nothing
 *
 * @pre sortedMetrics must be initialized to all 0
 *
 * @param [inout] selectedBSSList  the list to insert BSS
 * @param [inout] sortedMetrics  the list to insert metric, the order must be
 *                               the same as selectedBSSList
 * @param [in] bssStats  the handle to the BSS
 * @param [in] metric  the metric returned from callback function for this BSS
 * @param [in] maxNumBSS  maximum number of BSS requested
 * @param [inout] numBSSSelected  number of BSS being added to the list
 */
static void stadbEntryAddBSSToSelectedList(lbd_bssInfo_t *selectedBSSList,
                                           u_int32_t *sortedMetrics,
                                           stadbEntryPriv_bssStats_t *bssStats,
                                           u_int32_t metric, size_t maxNumBSS,
                                           size_t *numBSSSelected) {
    size_t i;
    for (i = 0; i < maxNumBSS; ++i) {
        if (metric > sortedMetrics[i]) {
            // Need to move all entries from i to right by 1, last one will be discarded
            size_t numEntriesToMove = maxNumBSS - i - 1;
            if (numEntriesToMove) {
                memmove(&selectedBSSList[i + 1], &selectedBSSList[i],
                        sizeof(lbd_bssInfo_t) * numEntriesToMove);
                memmove(&sortedMetrics[i + 1], &sortedMetrics[i],
                        sizeof(u_int32_t) * numEntriesToMove);
            }
            lbCopyBSSInfo(&bssStats->bss, &selectedBSSList[i]);
            sortedMetrics[i] = metric;
            if (*numBSSSelected < maxNumBSS) {
                ++*numBSSSelected;
            }
            return;
        }
    }
}

LBD_STATUS stadbEntry_iterateBSSStats(stadbEntry_handle_t entry, stadbEntry_iterBSSFunc_t callback,
                                      void *cookie, size_t *maxNumBSS, lbd_bssInfo_t *bss) {
    // Sanity check
    if (!callback || (maxNumBSS && !bss) || ((!maxNumBSS || !(*maxNumBSS)) && bss) ||
        !stadbEntry_isInNetwork(entry)) {
        //No BSS iteration should be done for out-of-network
        return LBD_NOK;
    }

    size_t i, numBSSSelected = 0;
    stadbEntryPriv_bssStats_t *bssStats = NULL;
    u_int32_t metric = 0;
    u_int32_t *sortedMetrics = calloc(entry->inNetworkInfo->numBSSStats,
                                      sizeof(u_int32_t));
    if (!sortedMetrics) { return LBD_NOK; }

    for (i = 0; i < entry->inNetworkInfo->numBSSStats; ++i) {
        bssStats = &entry->inNetworkInfo->bssStats[i];
        if (bssStats->valid &&
            (entry->inNetworkInfo->assoc.lastServingESS == LBD_ESSID_INVALID ||
             bssStats->bss.essId == entry->inNetworkInfo->assoc.lastServingESS)) {
            metric = callback(entry, bssStats, cookie);
            if (bss && metric) {
                stadbEntryAddBSSToSelectedList(bss, sortedMetrics, bssStats,
                                               metric, *maxNumBSS, &numBSSSelected);
            }
        }
    }

    if (maxNumBSS) {
        *maxNumBSS = numBSSSelected;
    }

    free(sortedMetrics);
    return LBD_OK;
}

LBD_STATUS stadbEntry_getPHYCapInfo(const stadbEntry_handle_t entry,
                                    const stadbEntry_bssStatsHandle_t bssHandle,
                                    wlanif_phyCapInfo_t *phyCapInfo) {
    if (!entry || !bssHandle || !phyCapInfo) {
        return LBD_NOK;
    }
    lbDbgAssertExit(NULL, bssHandle->valid);

    wlanif_band_e band = stadbEntry_resolveBandFromBSSStats(bssHandle);
    lbDbgAssertExit(NULL, band != wlanif_band_invalid);

    return stadbEntry_getPHYCapInfoByBand(entry, band, phyCapInfo);
}

LBD_STATUS stadbEntry_getPHYCapInfoByBand(const stadbEntry_handle_t entry,
                                          wlanif_band_e band,
                                          wlanif_phyCapInfo_t *phyCapInfo) {
    if (!stadbEntry_isInNetwork(entry) || band >= wlanif_band_invalid ||
            !phyCapInfo) {
        return LBD_NOK;
    }

    if (!entry->inNetworkInfo->phyCapInfo[band].valid) {
        return LBD_NOK;
    }

    *phyCapInfo = entry->inNetworkInfo->phyCapInfo[band];
    if (entry->isStaticSMPS) {
        // When STA is operating in Static SMPS mode, NSS is forced to 1
        phyCapInfo->numStreams = 1;
    }

    return LBD_OK;
}

LBD_STATUS stadbEntry_setPHYCapInfoByBand(
        stadbEntry_handle_t entry, wlanif_band_e band,
        const wlanif_phyCapInfo_t *phyCapInfo) {
    if (!entry || band >= wlanif_band_invalid ||
            !phyCapInfo || !phyCapInfo->valid ||
            !stadbEntry_isInNetwork(entry)) {
        return LBD_NOK;
    }

    if (stadbEntryUpdateBandPHYCapInfo(entry, band, phyCapInfo)) {
        stadbEntryFindBestPHYMode(entry);
    }

    return LBD_OK;
}

lbd_linkCapacity_t stadbEntry_getFullCapacity(const stadbEntry_handle_t entry,
                                              const stadbEntry_bssStatsHandle_t bssHandle,
                                              time_t *deltaSecs) {
    if (!entry || !bssHandle) {
        return LBD_INVALID_LINK_CAP;
    }
    lbDbgAssertExit(NULL, bssHandle->valid);

    if (deltaSecs) {
        time_t curTime = stadbEntryGetTimestamp();
        *deltaSecs = curTime - bssHandle->downlinkInfo.lastUpdateSecs;
    }

    return bssHandle->downlinkInfo.fullCapacity;
}

LBD_STATUS stadbEntry_setFullCapacity(stadbEntry_handle_t entry,
                                      stadbEntry_bssStatsHandle_t bssHandle,
                                      lbd_linkCapacity_t capacity) {
    if (!entry || !bssHandle) {
        return LBD_NOK;
    }
    lbDbgAssertExit(NULL, bssHandle->valid);

    bssHandle->downlinkInfo.fullCapacity = capacity;
    time_t curTime = stadbEntryGetTimestamp();
    bssHandle->downlinkInfo.lastUpdateSecs = curTime;

    return LBD_OK;
}

LBD_STATUS stadbEntry_setFullCapacityByBSSInfo(stadbEntry_handle_t entry,
                                               const lbd_bssInfo_t *bss,
                                               lbd_linkCapacity_t capacity) {
    if (!bss || !stadbEntry_isInNetwork(entry)) {
        return LBD_NOK;
    }

    stadbEntry_bssStatsHandle_t bssHandle =
        stadbEntryFindBSSStats(entry, bss, LBD_FALSE /* matchOnly */);
    bssHandle->downlinkInfo.fullCapacity = capacity;
    time_t curTime = stadbEntryGetTimestamp();
    bssHandle->downlinkInfo.lastUpdateSecs = curTime;

    bssHandle->lastUpdateSecs = curTime;
    return LBD_OK;
}

lbd_rcpi_t stadbEntry_getRCPI(const stadbEntry_handle_t entry,
                              const stadbEntry_bssStatsHandle_t bssHandle,
                              time_t *deltaSecs) {
    if (!entry || !bssHandle) {
        return LBD_INVALID_LINK_CAP;
    }
    lbDbgAssertExit(NULL, bssHandle->valid);

    if (deltaSecs) {
        time_t curTime = stadbEntryGetTimestamp();
        *deltaSecs = curTime - bssHandle->downlinkInfo.lastUpdateSecs;
    }

    return bssHandle->downlinkInfo.rcpi;
}

LBD_STATUS stadbEntry_setRCPI(stadbEntry_handle_t entry,
                              stadbEntry_bssStatsHandle_t bssHandle,
                              lbd_rcpi_t rcpi) {
    if (!entry || !bssHandle) {
        return LBD_NOK;
    }
    lbDbgAssertExit(NULL, bssHandle->valid);

    bssHandle->downlinkInfo.rcpi = rcpi;
    time_t curTime = stadbEntryGetTimestamp();
    bssHandle->downlinkInfo.lastUpdateSecs = curTime;

    return LBD_OK;
}

LBD_STATUS stadbEntry_setRCPIByBSSInfo(stadbEntry_handle_t entry,
                                       const lbd_bssInfo_t *bss,
                                       lbd_rcpi_t rcpi) {
    if (!bss || !stadbEntry_isInNetwork(entry)) {
        return LBD_NOK;
    }

    stadbEntry_bssStatsHandle_t bssHandle =
        stadbEntryFindBSSStats(entry, bss, LBD_FALSE /* matchOnly */);
    bssHandle->downlinkInfo.rcpi = rcpi;
    time_t curTime = stadbEntryGetTimestamp();
    bssHandle->downlinkInfo.lastUpdateSecs = curTime;

    bssHandle->lastUpdateSecs = curTime;

    return LBD_OK;
}

lbd_rssi_t stadbEntry_getUplinkRSSI(const stadbEntry_handle_t entry,
                                    const stadbEntry_bssStatsHandle_t bssHandle,
                                    time_t *ageSecs, u_int8_t *probeCount) {
    if (!entry || !bssHandle) {
        return LBD_INVALID_RSSI;
    }
    lbDbgAssertExit(NULL, bssHandle->valid);

    if (ageSecs) {
        time_t curTime = stadbEntryGetTimestamp();
        *ageSecs = curTime - bssHandle->uplinkInfo.lastUpdateSecs;
    }

    if (probeCount) {
        *probeCount = bssHandle->uplinkInfo.probeCount;
    }

    return bssHandle->uplinkInfo.rssi;
}

LBD_STATUS stadbEntry_setUplinkRSSI(stadbEntry_handle_t entry,
                                    stadbEntry_bssStatsHandle_t bssHandle,
                                    lbd_rssi_t rssi, LBD_BOOL estimated) {
    if (!entry || !bssHandle) {
        return LBD_NOK;
    }
    lbDbgAssertExit(NULL, bssHandle->valid);

    bssHandle->uplinkInfo.rssi = rssi;
    bssHandle->uplinkInfo.estimate = estimated;
    bssHandle->uplinkInfo.probeCount = 0;

    time_t curTime = stadbEntryGetTimestamp();
    bssHandle->uplinkInfo.lastUpdateSecs = curTime;

    if (!estimated) {
        bssHandle->lastUpdateSecs = curTime;
    }
    return LBD_OK;
}

lbd_airtime_t stadbEntry_getAirtime(const stadbEntry_handle_t entry,
                                    const stadbEntry_bssStatsHandle_t bssHandle,
                                    time_t *deltaSecs) {
    if (!entry || !bssHandle) {
        return LBD_INVALID_AIRTIME;
    }
    lbDbgAssertExit(NULL, bssHandle->valid);

    if (deltaSecs) {
        time_t curTime = stadbEntryGetTimestamp();
        *deltaSecs = curTime - bssHandle->downlinkInfo.lastUpdateSecs;
    }

    return bssHandle->downlinkInfo.airtime;
}

LBD_STATUS stadbEntry_setAirtime(stadbEntry_handle_t entry,
                                 stadbEntry_bssStatsHandle_t bssHandle,
                                 lbd_airtime_t airtime) {
    if (!entry || !bssHandle) {
        return LBD_NOK;
    }
    lbDbgAssertExit(NULL, bssHandle->valid);

    bssHandle->downlinkInfo.airtime = airtime;

    return LBD_OK;
}

LBD_STATUS stadbEntry_setAirtimeByBSSInfo(stadbEntry_handle_t entry,
                                          const lbd_bssInfo_t *bss,
                                          lbd_airtime_t airtime) {
    if (!bss || !stadbEntry_isInNetwork(entry)) {
        return LBD_NOK;
    }

    stadbEntry_bssStatsHandle_t bssHandle =
        stadbEntryFindBSSStats(entry, bss, LBD_FALSE /* matchOnly */);
    bssHandle->downlinkInfo.airtime = airtime;

    stadbEntryBSSStatsUpdateTimestamp(bssHandle);
    return LBD_OK;
}

LBD_STATUS stadbEntry_getLastDataRate(const stadbEntry_handle_t entry,
                                      lbd_linkCapacity_t *dlRate,
                                      lbd_linkCapacity_t *ulRate,
                                      time_t *deltaSecs) {
    if (!dlRate || !ulRate || !stadbEntry_isInNetwork(entry) ||
        !entry->validDataRate) {
        return LBD_NOK;
    }

    *dlRate = entry->inNetworkInfo->dataRateInfo.downlinkRate;
    *ulRate = entry->inNetworkInfo->dataRateInfo.uplinkRate;

    if (deltaSecs) {
        time_t curTime = stadbEntryGetTimestamp();
        *deltaSecs = curTime - entry->inNetworkInfo->dataRateInfo.lastUpdateSecs;
    }

    return LBD_OK;
}

LBD_STATUS stadbEntry_setLastDataRate(stadbEntry_handle_t entry,
                                      lbd_linkCapacity_t dlRate,
                                      lbd_linkCapacity_t ulRate) {
    if (!stadbEntry_isInNetwork(entry)) {
        return LBD_NOK;
    }

    entry->validDataRate = LBD_TRUE;
    entry->inNetworkInfo->dataRateInfo.downlinkRate = dlRate;
    entry->inNetworkInfo->dataRateInfo.uplinkRate = ulRate;
    entry->inNetworkInfo->dataRateInfo.lastUpdateSecs = stadbEntryGetTimestamp();

    stadbEntryUpdateTimestamp(entry);
    return LBD_OK;
}

LBD_BOOL stadbEntry_isChannelSupported(const stadbEntry_handle_t entry,
                                       lbd_channelId_t channel) {
    if (!stadbEntry_isInNetwork(entry)) {
        return LBD_FALSE;
    }

    size_t i = 0;
    for (i = 0; i < entry->inNetworkInfo->numBSSStats; ++i) {
        if (entry->inNetworkInfo->bssStats[i].valid &&
            entry->inNetworkInfo->bssStats[i].bss.channelId == channel) {
            return LBD_TRUE;
        }
    }

    return LBD_FALSE;
}

stadbEntry_bssStatsHandle_t stadbEntry_getServingBSS(
        const stadbEntry_handle_t entry, time_t *deltaSecs) {
    if (!stadbEntry_isInNetwork(entry) ||
        !entry->inNetworkInfo->assoc.bssHandle) {
        return NULL;
    }

    if (deltaSecs) {
        time_t curTime = stadbEntryGetTimestamp();
        *deltaSecs = curTime - entry->inNetworkInfo->assoc.lastAssoc.tv_sec;
    }
    return entry->inNetworkInfo->assoc.bssHandle;
}

const lbd_bssInfo_t *stadbEntry_resolveBSSInfo(const stadbEntry_bssStatsHandle_t bssHandle) {
    if (!bssHandle) {
        return NULL;
    }

    return &bssHandle->bss;
}

stadbEntry_bssStatsHandle_t stadbEntry_findMatchBSSStats(stadbEntry_handle_t entry,
                                                         const lbd_bssInfo_t *bss) {
    return stadbEntryFindBSSStats(entry, bss, LBD_TRUE /* matchOnly */);
}

stadbEntry_bssStatsHandle_t stadbEntry_findMatchRemoteBSSStats(stadbEntry_handle_t entry,
                                                               const lbd_bssInfo_t *bss) {
    if (!bss || bss->apId == LBD_APID_SELF) {
        return NULL;
    }

    return stadbEntryFindBSSStats(entry, bss, LBD_FALSE /* matchOnly */);
}

stadbEntry_bssStatsHandle_t stadbEntryFindBSSStats(stadbEntry_handle_t entry,
                                                   const lbd_bssInfo_t *bss,
                                                   LBD_BOOL matchOnly) {
    if (!bss || !stadbEntry_isInNetwork(entry)) {
        return NULL;
    }

    size_t i;
    for (i = 0; i < entry->inNetworkInfo->numBSSStats; ++i) {
        if (entry->inNetworkInfo->bssStats[i].valid) {
            if (lbAreBSSesSame(bss, &entry->inNetworkInfo->bssStats[i].bss)) {
                // When there is a match, return
                return &entry->inNetworkInfo->bssStats[i];
            } else if (!matchOnly &&
                       lbAreBSSesOnSameRadio(bss, &entry->inNetworkInfo->bssStats[i].bss)) {
                // This will happen when ESS changes. Update BSS info and keep other stats
                lbCopyBSSInfo(bss, &entry->inNetworkInfo->bssStats[i].bss);
                return &entry->inNetworkInfo->bssStats[i];
            }
        }
    }

    if (matchOnly) { return NULL; }

    // For a new BSS
    stadbEntry_bssStatsHandle_t newBSSStats = NULL;
    if (lbIsBSSLocal(bss)) {
        if (entry->inNetworkInfo->numLocalBSSStats < WLANIF_MAX_RADIOS) {
            // For local BSS, if number of local BSS stats is still smaller than
            // the radios supported, find it an empty slot or replace the LRU remote BSS
            newBSSStats = stadbEntryFindSlotForBSSStats(entry, bss, LBD_FALSE /* localLRU */);
            entry->inNetworkInfo->numLocalBSSStats += 1;
        } else {
            // If we already have enough local BSSes, for the new local BSS
            // (very unlikely to happen in real case since we already handle
            // channel change and ESS change, handle here to be conservative),
            // replace the LRU local BSS
            newBSSStats = stadbEntryFindSlotForBSSStats(entry, bss, LBD_TRUE /* localLRU */);
        }
    } else if (entry->inNetworkInfo->numLocalBSSStats < entry->inNetworkInfo->numBSSStats){
        // For a new remote BSS, find it an empty slot or replace the LRU remote BSS
        newBSSStats = stadbEntryFindSlotForBSSStats(entry, bss, LBD_FALSE /* localLRU */);
    }
    // Else, all slots have been filled with local BSS entries, no slot available for remote BSS,
    // should not happen on target

    if (newBSSStats) {
        stadbEntryResetBSSStatsEntry(newBSSStats, bss);
        newBSSStats->valid = LBD_TRUE;
    }

    return newBSSStats;
}

LBD_STATUS stadbEntrySetPHYCapInfo(stadbEntry_handle_t entry,
                                   stadbEntry_bssStatsHandle_t bssHandle,
                                   const wlanif_phyCapInfo_t *phyCapInfo) {
    if (!entry || !bssHandle || !phyCapInfo || !phyCapInfo->valid) {
        return LBD_NOK;
    }

    stadbEntryBSSStatsUpdateTimestamp(bssHandle);

    wlanif_band_e band = stadbEntry_resolveBandFromBSSStats(bssHandle);
    lbDbgAssertExit(NULL, band != wlanif_band_invalid);

    if (stadbEntryUpdateBandPHYCapInfo(entry, band, phyCapInfo)) {
        stadbEntryFindBestPHYMode(entry);
    }

    return LBD_OK;
}

/**
 * @brief Compare two PHY capability info entry to determine if the new PHY
 *        info is better than the old one
 *
 * Current only compares PHY mode, i.e. 11ac is better than 11n.
 *
 * @pre both PHY capability info are valid
 *
 * @param [in] newPHYCap  the new PHY info
 * @param [in] oldPHYCap  the PHY info to compare against
 *
 * @return LBD_TRUE if the new PHY info is better than the old one based
 *         on the rule(s) defined above
 */
static LBD_BOOL stadbEntryIsBetterPHYCapInfo(const wlanif_phyCapInfo_t *newPHYCap,
                                             const wlanif_phyCapInfo_t *oldPHYCap) {
    // Assume if PHY mode is better, then other PHY capabilities should also be better
    return newPHYCap->phyMode != wlanif_phymode_invalid &&
           (oldPHYCap->phyMode == wlanif_phymode_invalid ||
            newPHYCap->phyMode > oldPHYCap->phyMode);
}

/**
 * @brief Update PHY capability info on a given band with the new PHY info
 *
 * Only record the best PHY capability on a given band.
 *
 * @pre new PHY capability information is valid
 *
 * @param [in] entry  the handle to the STA
 * @param [in] band  the band on which PHY capability may update
 * @param [in] newPHYCap  new PHY capability information
 *
 * @return LBD_TRUE if the PHY capability on the band is updated; otherwise return
 *         LBD_FALSE if the new capability is not better than the original one
 */
static LBD_BOOL stadbEntryUpdateBandPHYCapInfo(stadbEntry_handle_t entry,
                                               wlanif_band_e band,
                                               const wlanif_phyCapInfo_t *newPHYCap) {
    LBD_BOOL updated = LBD_FALSE;
    const wlanif_phyCapInfo_t *oldPHYCap = &entry->inNetworkInfo->phyCapInfo[band];
    // Currently we only record the best PHY capabilities on the band,
    // and do not handle any downgrade
    if (!oldPHYCap->valid ||
        stadbEntryIsBetterPHYCapInfo(newPHYCap, oldPHYCap)) {
        memcpy(&entry->inNetworkInfo->phyCapInfo[band], newPHYCap,
               sizeof(wlanif_phyCapInfo_t));
        updated = LBD_TRUE;
    }

    return updated;
}

/**
 * @brief Find the best PHY mode supported by a STA across all bands
 *
 * @param [in] entry  the handle to the STA entry
 */
static void stadbEntryFindBestPHYMode(stadbEntry_handle_t entry) {
    entry->bestPHYMode = wlanif_phymode_basic;

    wlanif_band_e band;
    for (band = wlanif_band_24g; band < wlanif_band_invalid; ++band) {
        const wlanif_phyCapInfo_t *phyCapInfo = &entry->inNetworkInfo->phyCapInfo[band];
        if (phyCapInfo->valid && phyCapInfo->phyMode != wlanif_phymode_invalid &&
            phyCapInfo->phyMode > entry->bestPHYMode) {
                entry->bestPHYMode = phyCapInfo->phyMode;
        }
    }
}

/**
 * @brief Update the timestamp of a BSS stats entry
 *
 * The caller should confirm the entry is valid
 *
 * @param [in] bssHandle  the handle to the BSS entry to be updated
 */
static void stadbEntryBSSStatsUpdateTimestamp(stadbEntry_bssStatsHandle_t bssHandle) {
    lbDbgAssertExit(NULL, bssHandle && bssHandle->valid);
    bssHandle->lastUpdateSecs = stadbEntryGetTimestamp();
}

LBD_STATUS stadbEntryAddReservedAirtime(stadbEntry_handle_t entry,
                                        const lbd_bssInfo_t *bss,
                                        lbd_airtime_t airtime) {
    if (!entry || !bss || airtime == LBD_INVALID_AIRTIME) {
        return LBD_NOK;
    }

    if (entry->entryType == stadbEntryType_outOfNetwork) {
        // This should not happen on target, add a check to be conservative
        return LBD_NOK;
    }

    stadbEntry_bssStatsHandle_t bssHandle =
        stadbEntryFindBSSStats(entry, bss, LBD_FALSE /* matchOnly */);
    lbDbgAssertExit(NULL, bssHandle);

    bssHandle->reservedAirtime = airtime;
    stadbEntryBSSStatsUpdateTimestamp(bssHandle);

    entry->hasReservedAirtime = LBD_TRUE;
    // Mark band as supported
    stadbEntryMarkBandSupported(entry, bss);

    return LBD_OK;
}

LBD_BOOL stadbEntry_hasReservedAirtime(stadbEntry_handle_t handle) {
    if (!handle) { return LBD_FALSE; }

    return handle->hasReservedAirtime;
}

lbd_airtime_t stadbEntry_getReservedAirtime(stadbEntry_handle_t handle,
                                            stadbEntry_bssStatsHandle_t bssHandle) {
    if (!handle || !bssHandle) {
        return LBD_INVALID_AIRTIME;
    }
    lbDbgAssertExit(NULL, bssHandle->valid);

    return bssHandle->reservedAirtime;
}


wlanif_phymode_e stadbEntry_getBestPHYMode(stadbEntry_handle_t entry) {
    if (!entry) { return wlanif_phymode_invalid; }

    // If there is no PHY cap info for this client yet, it will return
    // wlanif_phymode_basic since this field is 0 initialized at entry
    // creation time.
    return entry->bestPHYMode;
}

void stadbEntryHandleChannelChange(stadbEntry_handle_t entry,
                                   lbd_vapHandle_t vap,
                                   lbd_channelId_t channelId) {
    if (!stadbEntry_isInNetwork(entry)) { return; }

    size_t i = 0;
    for (i = 0; i < entry->inNetworkInfo->numBSSStats; ++i) {
        stadbEntryPriv_bssStats_t *bssStats = &entry->inNetworkInfo->bssStats[i];
        if (bssStats->valid && bssStats->bss.vap == vap) {
            bssStats->bss.channelId = channelId;
            if (stadbEntry_clearPolluted(entry, bssStats) != LBD_OK) {
                dbgf(NULL, DBGERR,
                        "%s: Failed to clear polluted state ",__func__);
            }
            // The new channel may have a different TX power, so nuke RSSI
            // here to allow a new one filled in.
            memset(&bssStats->uplinkInfo, 0, sizeof(bssStats->uplinkInfo));
            bssStats->uplinkInfo.rssi = LBD_INVALID_RSSI;
            break;
        }
    }
}

void stadbEntryAssocDiagLog(stadbEntry_handle_t entry,
                            const lbd_bssInfo_t *bss) {
    if (diaglog_startEntry(mdModuleID_StaDB,
                           stadb_msgId_associationUpdate,
                           diaglog_level_demo)) {
        diaglog_writeMAC(&entry->addr);
        diaglog_writeBSSInfo(bss);
        diaglog_write8(entry->inNetworkInfo->assoc.bssHandle != NULL);
        diaglog_write8(entry->isAct);
        diaglog_write8(stadbEntry_isDualBand(entry));
        diaglog_write8(entry->isBTMSupported);
        diaglog_write8(entry->isRRMSupported);
        diaglog_finishEntry();
    }
}

void stadbEntryPopulateBSSesFromSameESS(stadbEntry_handle_t entry,
                                        const lbd_bssInfo_t *servingBSS,
                                        wlanif_band_e band) {
    if (!stadbEntry_isInNetwork(entry)) {
        return;
    }

    lbd_essId_t lastServingESS = stadbEntryGetLastServingESS(entry);
    if (lastServingESS == LBD_ESSID_INVALID) {
        // The client must have never associated with us before, pick ESS ID 0.
        // We will re-populate this on real association
        lbDbgAssertExit(NULL, !servingBSS);
        lastServingESS = 0;
    }

    size_t maxNumBSSes = entry->inNetworkInfo->numBSSStats - 1; // exclude serving BSS
    lbd_bssInfo_t bss[maxNumBSSes];

    if (LBD_NOK == wlanif_getBSSesSameESS(servingBSS, lastServingESS,
                                          band, &maxNumBSSes, bss) ||
        !maxNumBSSes) {
        // No other BSSes on the serving ESS
        return;
    }

    size_t i;
    for (i = 0; i < maxNumBSSes; ++i) {
        // Create a BSS entry for all same ESS BSSes if they do not exist
        stadbEntry_bssStatsHandle_t bssHandle =
            stadbEntryFindBSSStats(entry, &bss[i], LBD_FALSE /* matchOnly */);
        if (!bssHandle) {
            dbgf(NULL, DBGERR,
                 "%s: Failed to create BSS stats entry for " lbBSSInfoAddFmt(),
                 __func__, lbBSSInfoAddData(&bss[i]));
        }
    }
}

lbd_essId_t stadbEntryGetLastServingESS(stadbEntry_handle_t entry) {
    if (!stadbEntry_isInNetwork(entry)) {
        return LBD_ESSID_INVALID;
    }

    return entry->inNetworkInfo->assoc.lastServingESS;
}

wlanif_band_e stadbEntry_resolveBandFromBSSStats(
        const stadbEntry_bssStatsHandle_t bssHandle) {
    if (!bssHandle) {
        return wlanif_band_invalid;
    }

    return wlanif_resolveBandFromChannelNumber(bssHandle->bss.channelId);
}

/**
 * @brief Decide the entry size and type for a given STA entry
 *
 * @param [in] inNetwork  whether the STA is in-network or not
 * @param [in] rrmStatus  whether 802.11 Radio Resource Management is supported,
 *                        disabled, or unchanged from the current state.
 * @param [in] numRadiosLocal  number of BSSes supported on local AP
 * @param [in] numRemoteBSSStats  number of BSSes supported on remote
 *                                AP(s) if running in multi-AP setup
 * @param [out] numBSSStats  number of BSSes entries should be allocated
 * @param [out] type  the stadb entry type determined based on given information
 *
 * @return the memory size should be allocated for ths STA entry
 */
static size_t stadbEntryDetermineEntrySizeAndType(
        LBD_BOOL inNetwork, wlanif_capStateUpdate_e rrmStatus,
        size_t numRadiosLocal, size_t numRemoteBSSStats, size_t *numBSSStats,
        stadbEntryType_e *type) {
    size_t entrySize = sizeof(stadbEntryPriv_t);
    *numBSSStats = 0;
    *type = stadbEntryType_outOfNetwork;
    if (inNetwork) {
        entrySize += (sizeof(stadbEntryPriv_inNetworkInfo_t) +
                      sizeof(stadbEntryPriv_bssStats_t) * numRadiosLocal);
        *numBSSStats += numRadiosLocal;
        *type = stadbEntryType_inNetworkLocal;

        if (rrmStatus == wlanif_cap_enabled && numRemoteBSSStats) {
           entrySize += numRemoteBSSStats * sizeof(stadbEntryPriv_bssStats_t);
           *numBSSStats += numRemoteBSSStats;
           *type = stadbEntryType_inNetworkLocalRemote;
        }
    }
    return entrySize;
}

/**
 * @brief Reset a BSS stats entry with new BSS info
 *
 * All other fields should be set to invalid values.
 *
 * @param [in] bssStats  the entry to be reset
 * @param [in] newBSS  the new BSS info to be assigned to the entry
 */
static void stadbEntryResetBSSStatsEntry(stadbEntry_bssStatsHandle_t bssStats,
                                         const lbd_bssInfo_t *newBSS) {
    memset(bssStats, 0, sizeof(*bssStats));
    bssStats->reservedAirtime = LBD_INVALID_AIRTIME;
    lbCopyBSSInfo(newBSS, &bssStats->bss);
}

/**
 * @brief Compare two BSS entries to determine if BSS1 is older than BSS2
 *
 * BSS1 is older than BSS2 if the last update time of BSS1 is before that of BSS2
 *
 * @param [in] bssStat1  the given BSS stat entry to compare
 * @param [in] bssStat2  the given BSS stat entry to compare with
 *
 * @return LBD_TRUE if BSS1 is older, otherwise return LBD_FALSE
 */
static LBD_BOOL stadbEntryIsBSSOlder(stadbEntry_bssStatsHandle_t bssStat1,
                                     stadbEntry_bssStatsHandle_t bssStat2) {
    lbDbgAssertExit(NULL, bssStat1);
    if (!bssStat2) { return LBD_TRUE; }

    return bssStat1->lastUpdateSecs < bssStat2->lastUpdateSecs;
}

/**
 * @brief Find a slot to hold BSS stats for the given BSS.
 *
 * The following rules are used to pick a slot:
 * 1. Try to find an empty slot;
 * 2. If no empty slot, look for a Least Recently Used (LRU) BSS stats slot.
 *    When looking for LRU BSS slot, need to consider whether to look for slot for
 *    local BSS or remote BSS.
 *    # For local LRU, try to find a LRU same band entry first, if none, pick
 *      the LRU one among all local slots
 *    # For remote LRU, always pick LRU one among all remote slots
 *
 * @param [in] entry  the STA entry to look for BSS stats slot
 * @param [in] bss  the new BSS to be added
 * @param [in] localLRU  flag indicating whether to look for LRU local BSS stats
 *                       or LRU remote BSS stats
 *
 * @return the handle to the BSS stats slot found
 */
static stadbEntry_bssStatsHandle_t stadbEntryFindSlotForBSSStats(
        stadbEntry_handle_t entry, const lbd_bssInfo_t *bss, LBD_BOOL localLRU) {
    stadbEntry_bssStatsHandle_t oldestEntry = NULL, oldestSameBandEntry = NULL;

    wlanif_band_e band = wlanif_resolveBandFromChannelNumber(bss->channelId);

    size_t i;
    for (i = 0; i < entry->inNetworkInfo->numBSSStats; ++i) {
        if (!entry->inNetworkInfo->bssStats[i].valid) {
            // Found an empty slot, use it
            return &entry->inNetworkInfo->bssStats[i];
        } else if (!(lbIsBSSLocal(&entry->inNetworkInfo->bssStats[i].bss) ^ localLRU)) {
            if (localLRU &&
                wlanif_resolveBandFromChannelNumber(
                    entry->inNetworkInfo->bssStats[i].bss.channelId) == band &&
                stadbEntryIsBSSOlder(&entry->inNetworkInfo->bssStats[i],
                                     oldestSameBandEntry)) {
                // Only look for same band LRU slot for local BSS
                oldestSameBandEntry = &entry->inNetworkInfo->bssStats[i];
            } else if (stadbEntryIsBSSOlder(&entry->inNetworkInfo->bssStats[i],
                                            oldestEntry)) {
                oldestEntry = &entry->inNetworkInfo->bssStats[i];
            }
        }
    }

    if (oldestSameBandEntry) {
        stadbEntryResetBSSStatsEntry(oldestSameBandEntry, bss);
        return oldestSameBandEntry;
    } else {
        lbDbgAssertExit(NULL, oldestEntry);
        stadbEntryResetBSSStatsEntry(oldestEntry, bss);
        return oldestEntry;
    }
}

LBD_STATUS stadbEntry_setPolluted(stadbEntry_handle_t entry,
                                  stadbEntry_bssStatsHandle_t bssStats,
                                  time_t expirySecs) {
    if (!stadbEntry_isInNetwork(entry) || !bssStats) {
        return LBD_NOK;
    }

    if (!bssStats->polluted) {
        bssStats->polluted = LBD_TRUE;
        entry->inNetworkInfo->numPollutedBSS++;
    }

    bssStats->pollutionExpirySecs = stadbEntryGetTimestamp() + expirySecs;

    return LBD_OK;
}

LBD_STATUS stadbEntry_clearPolluted(stadbEntry_handle_t entry,
                                    stadbEntry_bssStatsHandle_t bssStats) {
    if (!stadbEntry_isInNetwork(entry) || !bssStats) {
        return LBD_NOK;
    }

    if (bssStats->polluted) {
        lbDbgAssertExit(NULL, entry->inNetworkInfo->numPollutedBSS);
        bssStats->polluted = LBD_FALSE;
        entry->inNetworkInfo->numPollutedBSS--;
    }

    bssStats->pollutionExpirySecs = 0;

    return LBD_OK;
}

LBD_STATUS stadbEntry_getPolluted(stadbEntry_handle_t entry,
                                  stadbEntry_bssStatsHandle_t bssStats,
                                  LBD_BOOL *polluted, time_t *expirySecs) {
    if (!stadbEntry_isInNetwork(entry) || !bssStats || !polluted) {
        return LBD_NOK;
    }

    *polluted = bssStats->polluted;

    if (expirySecs) {
        time_t curTime = stadbEntryGetTimestamp();
        *expirySecs = *polluted && bssStats->pollutionExpirySecs > curTime ?
                          bssStats->pollutionExpirySecs - curTime : 0;
    }

    return LBD_OK;
}

LBD_STATUS stadbEntry_isChannelPollutionFree(stadbEntry_handle_t entry,
                                             lbd_channelId_t channel,
                                             LBD_BOOL *pollutionFree) {
    if (!stadbEntry_isInNetwork(entry) || !pollutionFree) {
        return LBD_NOK;
    }

    // If no polluted BSS, return directly
    if (!entry->inNetworkInfo->numPollutedBSS) {
        *pollutionFree = LBD_TRUE;
        return LBD_OK;
    }

    LBD_BOOL channelMatch = LBD_FALSE;
    size_t i = 0;
    for (i = 0; i < entry->inNetworkInfo->numBSSStats; ++i) {
        if (entry->inNetworkInfo->bssStats[i].valid &&
            entry->inNetworkInfo->bssStats[i].bss.channelId == channel) {
            channelMatch = LBD_TRUE;
            if (entry->inNetworkInfo->bssStats[i].polluted) {
                *pollutionFree = LBD_FALSE;
                return LBD_OK;
            }
        }
    }

    if (channelMatch) {
        *pollutionFree = LBD_TRUE;
        return LBD_OK;
    }

    return LBD_NOK;
}

LBD_STATUS stadbEntryUpdateSMPSMode(stadbEntry_handle_t entry,
                                    const lbd_bssInfo_t *bss,
                                    LBD_BOOL isStatic) {
    if (!entry || !bss) { return LBD_NOK; }

    entry->isStaticSMPS = isStatic;
    stadbEntryMarkBandSupported(entry, bss);
    return LBD_OK;
}

LBD_STATUS stadbEntryUpdateOpMode(stadbEntry_handle_t entry,
                                  const lbd_bssInfo_t *bss,
                                  wlanif_chwidth_e maxChWidth,
                                  u_int8_t numStreams) {
    if (!stadbEntry_isInNetwork(entry) || !bss ||
        maxChWidth >= wlanif_chwidth_invalid || !numStreams) {
        return LBD_NOK;
    }

    // Operating Mode notification should only happen on the serving BSS
    stadbEntry_bssStatsHandle_t servingBSS = stadbEntry_getServingBSS(entry, NULL);
    const lbd_bssInfo_t *servingBSSInfo = stadbEntry_resolveBSSInfo(servingBSS);

    if (!lbAreBSSesSame(bss, servingBSSInfo)) {
        return LBD_NOK;
    }

    wlanif_band_e band = wlanif_resolveBandFromChannelNumber(servingBSSInfo->channelId);
    lbDbgAssertExit(NULL, band < wlanif_band_invalid);

    entry->inNetworkInfo->phyCapInfo[band].maxChWidth = maxChWidth;
    entry->inNetworkInfo->phyCapInfo[band].numStreams = numStreams;

    stadbEntryUpdateTimestamp(entry);

    return LBD_OK;
}

LBD_STATUS stadbEntryMarkDualBandSupported(stadbEntry_handle_t entry) {
    if (!entry) { return LBD_NOK; }

    stadbEntrySetSupportedBand(entry, wlanif_band_24g);
    stadbEntrySetSupportedBand(entry, wlanif_band_5g);
    stadbEntryUpdateTimestamp(entry);

    return LBD_OK;
}

LBD_STATUS stadbEntryPopulateNonServingPHYInfo(stadbEntry_handle_t entry,
                                               const lbd_bssInfo_t *servingBSS,
                                               const wlanif_phyCapInfo_t *servingPHY) {
    wlanif_band_e servingBand, nonServingBand;
    wlanif_phyCapInfo_t phyInfo = { LBD_FALSE };

    if (!stadbEntry_isInNetwork(entry) ||
        !servingBSS || !servingPHY || !servingPHY->valid) {
        return LBD_NOK;
    }

    servingBand = wlanif_resolveBandFromChannelNumber(servingBSS->channelId);
    if (servingBand == wlanif_band_invalid) {
        return LBD_NOK;
    }

    nonServingBand = (servingBand == wlanif_band_24g) ? wlanif_band_5g :
                                                        wlanif_band_24g;

    if (LBD_OK == stadbEntry_getPHYCapInfoByBand(entry, nonServingBand,
                                                 &phyInfo) &&
        phyInfo.valid) {
        // Already have valid PHY info on non-serving band, do nothing
        return LBD_OK;
    }

    if (nonServingBand == wlanif_band_5g) {
        // Assume what STA is capable of on 2.4 GHz will be capable on 5 GHz
        return stadbEntry_setPHYCapInfoByBand(entry, nonServingBand, servingPHY);
    } else { // non-serving band is 2.4 GHz
        // Currently assume max capability on 2.4 GHz is 11n/40MHz/MCS7,
        // and number of streams and Tx power will be the same as ones on 5 GHz
        const wlanif_phyCapInfo_t BEST_24G_PHY = {
            LBD_TRUE /* valid */, wlanif_chwidth_40, WLANIF_MAX_NUM_STREAMS,
            wlanif_phymode_ht, WLANIF_MAX_MCS_HT, WLANIF_MAX_TX_POWER
        };
        wlanif_resolveMinPhyCap(servingPHY, &BEST_24G_PHY, &phyInfo);
        if (phyInfo.phyMode == wlanif_phymode_basic) {
            // Correct MCS if running in 11a mode
            phyInfo.maxMCS = servingPHY->maxMCS;
        }

        return stadbEntry_setPHYCapInfoByBand(entry, nonServingBand, &phyInfo);
    }
}

static json_t *stadbEntryPhyCapInfoJsonize(const stadbEntry_handle_t entry) {
    json_t *phyCapInfo_j, *pci_j;
    wlanif_phyCapInfo_t *pci;
    int i;

    phyCapInfo_j = json_array();
    for (i = 0; i < wlanif_band_invalid; i++) {
        pci = &(entry->inNetworkInfo->phyCapInfo[i]);
        pci_j = json_pack("{s:b, s:i, s:i, s:i, s:i, s:i}",
                "valid", pci->valid,
                "maxChWidth", pci->maxChWidth,
                "numStreams", pci->numStreams,
                "phyMode", pci->phyMode,
                "maxMCS", pci->maxMCS,
                "maxTxPower", pci->maxTxPower);

        if (pci_j == NULL) {
            dbgf(NULL, DBGERR, "%s: Failed to jsonize a phyCapInfo", __func__);
            json_decref(phyCapInfo_j);
            phyCapInfo_j = NULL;
            break;
        }

        if (json_array_append_new(phyCapInfo_j, pci_j) != 0) {
            dbgf(NULL, DBGERR, "%s: Failed to append a phyCapInfo", __func__);
            json_decref(pci_j);
            json_decref(phyCapInfo_j);
            phyCapInfo_j = NULL;
            break;
        }
    }

    return phyCapInfo_j;
}

json_t *stadbEntryJsonize(const stadbEntry_handle_t entry,
                          stadbEntry_jsonizeSteerExecCB_t jseCB) {
    json_t *ret, *phyCapInfo_j, *steerExec_j;
    char *ether_a;

    /* stringify addr */
    ether_a = ether_ntoa(&entry->addr);
    if (ether_a == NULL) {
        dbgf(NULL, DBGERR, "%s: Failed to convert ether addr to string.",
             __func__);
        return NULL;
    }

    phyCapInfo_j = stadbEntryPhyCapInfoJsonize(entry);
    if (phyCapInfo_j == NULL) {
        dbgf(NULL, DBGERR, "%s: Failed to jsonize phyCapInfo.", __func__);
        return NULL;
    }

    ret = json_pack("{s:s, s:i, s:i, s:b, s:b, s:b, s:b, s:{s:o}}",
            "addr", ether_a,
            "entryType", entry->entryType,
            "operatingBands", entry->operatingBands,
            "isBTMSupported", entry->isBTMSupported,
            "isRRMSupported", entry->isRRMSupported,
            "isMUMIMOSupported", entry->isMUMIMOSupported,
            "isSteeringDisallowed", entry->isSteeringDisallowed,
            "inNetworkInfo",
                "phyCapInfo", phyCapInfo_j
    );

    if (ret == NULL) {
        dbgf(NULL, DBGERR, "%s: Failed to jsonize stadb entry", __func__);
        return NULL;
    }

    /* steerExec (optional) */
    steerExec_j = jseCB(entry);
    if (steerExec_j != NULL) {
        if (json_object_set_new(ret, "steerExec", steerExec_j) != 0) {
            dbgf(NULL, DBGERR, "%s: Failed to set steerExec", __func__);
            json_decref(ret);
            json_decref(steerExec_j);
            ret = NULL;
        }
    }

    return ret;
}

void stadbEntrySetDirtyIfInNetwork(stadbEntry_handle_t entry) {
    if (stadbEntry_isInNetwork(entry)) {
        stadb_setDirty();
    }
}
