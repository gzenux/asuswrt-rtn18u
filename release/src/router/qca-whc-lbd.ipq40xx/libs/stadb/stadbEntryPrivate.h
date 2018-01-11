// vim: set et sw=4 sts=4 cindent:
/*
 * @File: stadbEntryPrivate.h
 *
 * @Abstract: Definition for the STA database entry type. This file should not
 *            be used outside of the stadb module.
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

#ifndef stadbEntryPrivate__h
#define stadbEntryPrivate__h

#include <net/ethernet.h>

#include "list.h"
#include "lbd_types.h"

#if defined(__cplusplus)
extern "C" {
#endif

/**
 * @brief Enumeration for different entry types
 */
typedef enum stadbEntryType_e {
    /// Out of network entries
    stadbEntryType_outOfNetwork,
    /// In-network entries that only store local information
    stadbEntryType_inNetworkLocal,
    /// In-network entries that store both local and remote information
    stadbEntryType_inNetworkLocalRemote,

    stadbEntryType_invalid
} stadbEntryType_e;

/**
 * @brief All of the stats that are stored for a BSS
 */
typedef struct stadbEntryPriv_bssStats_t {
    struct {
        /// The time value corresponding to the last point at which the RSSI
        /// was updated.
        time_t lastUpdateSecs;

        /// if this RSSI value is estimated or measured
        /// This should only be used for debugging purpose.
        LBD_BOOL estimate : 1;

        /// The last uplink RSSI value, or LBD_INVALID_RSSI if nothing was
        /// obtained yet.
        lbd_rssi_t rssi;

        /// For a probe RSSI, we want to do RSSI averaging and this field will
        /// be set to the number of probes being averaged; for other RSSI update,
        /// set this field to 0.
        u_int8_t probeCount;
    } uplinkInfo;

    struct {
        /// The time value corresponding to the last point at which the data rate
        /// was updated.
        time_t lastUpdateSecs;

        /// The estimated downlink full capacity on this channel,
        /// or LBD_INVALID_LINK_CAP if not estimated yet
        lbd_linkCapacity_t fullCapacity;

        /// The estimated airtime on this channel, LBD_INVALID_AIRTIME if not estimated yet
        lbd_airtime_t airtime;

        /// The estimated or measured downlink RCPI value
        lbd_rcpi_t rcpi;
    } downlinkInfo;

    /// Basic information of this BSS
    lbd_bssInfo_t bss;

    /// last time this entry was updated
    time_t lastUpdateSecs;

    /// The time when the pollution info expires
    time_t pollutionExpirySecs;

    /// The reserved airtime if any
    lbd_airtime_t reservedAirtime;

    /// if this stat entry is valid or not
    LBD_BOOL valid : 1;

    /// Whether interference pollution has been detected on this BSS
    LBD_BOOL polluted : 1;
} stadbEntryPriv_bssStats_t;

/**
 * @brief Structure to record detailed information of an in-network STAs
 *
 * These information can be obtained from local (driver) notifications or
 * notifications from remote APs.
 */
typedef struct stadbEntryPriv_inNetworkInfo_t {
    // Association state.
    struct {
        /// The time of the last association.
        struct timespec lastAssoc;

        /// The pointer to the associated BSS stats. It should be NULL
        /// when not associated
        stadbEntry_bssStatsHandle_t bssHandle;

        /// The channel on which the device is currently associated (if any).
        lbd_channelId_t channel;

        /// Last ESS the STA is associated on
        lbd_essId_t lastServingESS;
    } assoc;

    struct {
        /// The time value corresponding to the last point at which the data rate
        /// information was updated.
        time_t lastUpdateSecs;

        /// The measured downlink data rate for this station
        lbd_linkCapacity_t downlinkRate;

        /// The measured uplink data rate for this station
        lbd_linkCapacity_t uplinkRate;
    } dataRateInfo;

    /// The best PHY capabilities reported by this STA on a given band
    wlanif_phyCapInfo_t phyCapInfo[wlanif_band_invalid];

    /// The time of last time activity status change
    time_t lastActUpdate;

    /// State information related to steering. This should be considered
    /// opaque to all but the steering executor.
    void *steeringState;

    /// Function to invoke to destroy the steering state prior to destroying
    /// the overall entry.
    stadbEntry_stateLifecycleCB_t steeringStateLifecycleCB;

    /// State information related to estimating STA data rates and airtimes.
    /// This should be considered opaque to all but the estimator.
    void *estimatorState;

    /// Function to invoke to destroy the estimator state prior to
    /// destroying the overall entry.
    stadbEntry_stateLifecycleCB_t estimatorStateLifecycleCB;

    /// State information related to steering coordination between nodes.
    /// This should be considered opaque to all but the steering messaging
    /// module.
    void *steermsgState;

    /// Function to invoke to destroy the steering messaging state prior to
    /// destroying the overall entry.
    stadbEntry_stateLifecycleCB_t steermsgStateLifecycleCB;

    /// Number of BSS entries being marked as polluted for this STA
    u_int8_t numPollutedBSS;

    /// Number of BSS entries allocated for this STA
    size_t numBSSStats : 6;

    /// Number of BSS stats entries taken by local BSS
    /// Once it reaches WLANIF_MAX_RADIOS, it will not increment
    size_t numLocalBSSStats : 2;

    /// Entries for BSS related information
    /// Warning: BSS stats entry must be accessed via finding APIs.
    stadbEntryPriv_bssStats_t bssStats[0];
} stadbEntryPriv_inNetworkInfo_t;

/**
 * @brief All of the data that is stored for a specific station.
 *
 * For an out-of-network STA
 *   1. What we are interested in is only the MAC address and if it is dual band capable
 *   2. the entry size should be 20 bytes
 *
 * For an in-network STA:
 *   1. STA can be marked as in-network either directly from association, or from topology messages.
 *   2. Once being marked as in-network, a stadbEntryPriv_inNetworkInfo_t will be allocated
 *   3. entry size should be 20 + sizeof(inNetworkInfo) + sizeof(BSS) * numBSSEntries:
 *       In single AP three radios case or for STA does not support 11k: 172 bytes;
 *       For STA supports 11k and in multi-AP setup: 172 + 32 * numRemoteBSSStats bytes.
 */
typedef struct stadbEntryPriv_t {
    /// Doubly-linked list for use in a given hash table bucket.
    list_head_t hashChain;

    /// The MAC address of the station
    struct ether_addr addr;

    /// Note: total memory cost of bitfields below should not exceed 2 bytes
    /// Type specifier for this entry
    stadbEntryType_e entryType : 4;

    /// The bands on which the STA has been known to operate.
    u_int8_t operatingBands : 2;

    /// 802.11v BSS Transition Management support (as reported via Association Request)
    u_int8_t isBTMSupported : 1;

    /// 802.11k Radio Resource Management support (as reported via Association Request)
    u_int8_t isRRMSupported : 1;

    /// Whether it has Reserved airtime on any BSS
    LBD_BOOL hasReservedAirtime : 1;

    /// The best PHY mode supported across all bands (VHT, HT or basic)
    wlanif_phymode_e bestPHYMode : 2;

    /// Whether the data rate info is valid
    LBD_BOOL validDataRate : 1;

    /// Whether the device is active or not
    LBD_BOOL isAct : 1;

    /// Whether the device is operating in static SMPS mode
    LBD_BOOL isStaticSMPS : 1;

    /// Whether the device supports MU-MIMO
    LBD_BOOL isMUMIMOSupported : 1;

    /// whether there is a global prohibition against steering for this client
    LBD_BOOL isSteeringDisallowed : 1;

    /// Timestamp of the last time the entry was updated.
    time_t lastUpdateSecs;

    /// Additional information for in-network clients
    stadbEntryPriv_inNetworkInfo_t inNetworkInfo[0];
} stadbEntryPriv_t;

/**
 * @brief Create a new station entry with the provided MAC address.
 *
 * @param [in] addr  the MAC address for the new entry
 * @param [in] inNetwork  flag indicating whether the STA is in-network or not
 * @param [in] rrmStatus  whether 802.11 Radio Resource Management is supported,
 *                        disabled, or unchanged from the current state.
 * @param [in] numRadiosLocal  number of BSSes supported on local AP
 * @param [in] numRemoteBSSStats  number of BSSes supported on remote
 *                                AP(s) if running in multi-AP setup
 *
 * @return  the handle to the new entry, or NULL if it could not be created
 */
stadbEntry_handle_t stadbEntryCreate(
        const struct ether_addr *addr, LBD_BOOL inNetwork,
        wlanif_capStateUpdate_e rrmStatus, size_t numRadiosLocal,
        size_t numRemoteBSSStats);

/**
 * @brief Change the type of a given STA entry
 *
 *  Note that the handle of the given STA entry returned from this function
 *  may or may not be the same as the handle passed in. And the handle passed
 *  in may be freed in this function. Caller should handle it properly.
 *
 * @param [in] handle  the handle to the STA entry
 * @param [in] rrmStatus  whether 802.11 Radio Resource Management is supported,
 *                        disabled, or unchanged from the current state.
 * @param [in] numRadiosLocal  number of BSSes supported on local AP
 * @param [in] numRemoteBSSStats  number of BSSes supported on remote
 *                                AP(s) if running in multi-AP setup
 *
 * @return the handle of STA entry with the new type
 */
stadbEntry_handle_t stadbEntryChangeEntryType(
        stadbEntry_handle_t handle, wlanif_capStateUpdate_e rrmStatus,
        size_t numRadiosLocal, size_t numRemoteBSSStats);

/**
 * @brief Mark whether the STA of the provided entry is associated on the
 *        provided band or not.
 *
 * Also mark this device as being an in network device. If it is disassociated,
 * also mark it as inactive.
 *
 * Note that if the call is for a disassociation and the band does not
 * match what is currently thought to be the associated band, no update
 * is made to the currently associated band.
 *
 * If a disassociation occurs shortly after an association
 * (currently within 500ms), the association status is verified
 * in the driver (to make sure we haven't received the updates
 * in the wrong order).
 *
 * If the verifyAssociation parameter is set to LBD_TRUE, the
 * association status is only updated if the STA is currently
 * not marked as associated, and the association status is
 * verified from the driver.  This flag is used for when the
 * association status is inferred due to receiving a RSSI or
 * activity update.  It is possible to receive spurious events,
 * so we don't want to incorrectly update the association in
 * these cases.
 *
 * @param [in] handle  the handle of the entry to update
 * @param [in] bss  the bss on which the assoc/disassoc
 *                  occurred
 * @param [in] isAssociated  LBD_TRUE if the device is now associated;
 *                           LBD_FALSE if the device is now disassociated
 * @param [in] updateActive  flag indicating if the device should be
 *                           marked as active when it is associated
 * @param [in] verifyAssociation  set to LBD_TRUE if the
 *                                association needs to be
 *                                verified
 * @param [out] assocChanged set to LBD_TRUE if the association
 *                           state of the entry changed.  Will
 *                           be ignored if NULL
 *
 * @return LBD_OK on success; otherwise LBD_NOK
 */
LBD_STATUS stadbEntryMarkAssociated(stadbEntry_handle_t handle,
                                    const lbd_bssInfo_t *bss,
                                    LBD_BOOL isAssociated,
                                    LBD_BOOL updateActive,
                                    LBD_BOOL verifyAssociation,
                                    LBD_BOOL *assocChanged);


/**
 * @brief Update whether the STA of the provided entry supports
 *        802.11k Radio Resource Management (RRM). Called after
 *        receiving an association request
 *
 * @param [in] entry  the handle of the entry to update
 * @param [in] isRRMSupported  LBD_TRUE if RRM is supported
 *
 * @return LBD_OK on success; otherwise LBD_NOK
 */
LBD_STATUS stadbEntryUpdateIsRRMSupported(stadbEntry_handle_t entry,
                                          LBD_BOOL isRRMSupported);

/**
 * @brief Update whether the STA of the provided entry supports
 *        MU-MIMO. Called after
 *        receiving an association request
 *
 * @param [in] entry  the handle of the entry to update
 * @param [in] isRRMSupported  LBD_TRUE if MU-MIMO is supported
 *
 * @return LBD_OK on success; otherwise LBD_NOK
 */
LBD_STATUS stadbEntryUpdateMUMIMOMode(stadbEntry_handle_t entry,
                                      LBD_BOOL isMUMIMOSupported);

/**
 * @brief Mark whether the STA is active or not
 *
 * If it is active, also mark the associated band.
 *
 * @param [in] handle  the handle of the entry to update
 * @param [in] bss  the bss on which the activity status change
 *                  occurred
 * @param [in] active  flag indicating if the STA is active or not
 *
 * @return LBD_OK on success; otherwise LBD_NOK
 */
LBD_STATUS stadbEntryMarkActive(stadbEntry_handle_t handle,
                                const lbd_bssInfo_t *bss,
                                LBD_BOOL active);

/**
 * @brief Record the latest RSSI value on the given BSS in the database
 *        entry.
 *
 * @param [in] handle  the handle to the entry to modify
 * @param [in] bss  the BSS on which the RSSI measurement occurred
 * @param [in] rssi  the RSSI measurement
 *
 * @return LBD_OK on success; otherwise LBD_NOK
 */
LBD_STATUS stadbEntryRecordRSSI(stadbEntry_handle_t entry,
                                const lbd_bssInfo_t *bss,
                                lbd_rssi_t rssi);
/**
 * @brief Record the latest probe request RSSI value on the given BSS
 *        in the database entry.
 *
 * @param [in] handle  the handle to the entry to modify
 * @param [in] bss  the BSS on which the RSSI measurement occurred
 * @param [in] rssi  the RSSI measurement
 * @param [in] maxInterval  the number of seconds allowed for this measurement
 *                          to be averaged with previous ones if any
 *
 * @return LBD_OK on success; otherwise LBD_NOK
 */
LBD_STATUS stadbEntryRecordProbeRSSI(stadbEntry_handle_t entry,
                                     const lbd_bssInfo_t *bss,
                                     lbd_rssi_t rssi, time_t maxInterval);

/**
 * @brief Destroy the provided entry.
 *
 * @param [in] handle  the handle to the entry to destroy
 */
void stadbEntryDestroy(stadbEntry_handle_t handle);

/**
 * @brief Compute the hash code for the entry.
 *
 * The hash code is derived from the STA's MAC address.
 *
 * @pre addr is valid
 *
 * @param [in] addr  the address for which to compute the hash code
 *
 * @return  the computed hash code
 */
u_int8_t stadbEntryComputeHashCode(const struct ether_addr *addr);

/**
 * @brief Update PHY capabilities information of a STA on a given BSS
 *
 * This will store the new capabilities in BSS stats entry if
 * the capability entry is valid; otherwise, do nothing.
 *
 * @param [in] entry  the handle of the entry to update
 * @param [in] bssHandle  the handle of BSS stats entry to store PHY capability info
 * @param [in] phyCapInfo  the new PHY capabilities
 *
 * @return LBD_OK on success; otherwise LBD_NOK
 */
LBD_STATUS stadbEntrySetPHYCapInfo(stadbEntry_handle_t entry,
                                   stadbEntry_bssStatsHandle_t bssHandle,
                                   const wlanif_phyCapInfo_t *phyCapInfo);

/**
 * @brief Find the BSS stats entry for the given BSS info
 *
 * If there is a matching BSS stats entry, return it;
 * otherwise, if not require matching BSS only, return
 * 1. an empty slot if any;
 * 2. oldest entry on the same band to overwrite if any
 * 3. oldest entry to overwrite
 *
 * @param [in] handle  the handle to the entry to find BSS stats
 * @param [in] bss  the BSS information to look for an entry
 * @param [in] matchOnly  if true, only find BSS stats entry that matching
 *                        the given BSS info
 *
 * @return the BSS stats handle found, or NULL on failure
 */
stadbEntry_bssStatsHandle_t stadbEntryFindBSSStats(stadbEntry_handle_t handle,
                                                   const lbd_bssInfo_t *bss,
                                                   LBD_BOOL matchOnly);

/**
 * @brief Add reserved airtime on a given BSS to the STA
 *
 * It will mark the BSS/band as supported and set top level
 * hasReservedAirtime flag.
 *
 * @param [in] handle  the handle to the entry to add reserved airtime
 * @param [in] bss  the BSS on which airtime is reserved
 * @param [in] airtime  the reserved airtime
 *
 * @return LBD_OK if the airtime
 */
LBD_STATUS stadbEntryAddReservedAirtime(stadbEntry_handle_t handle,
                                        const lbd_bssInfo_t *bss,
                                        lbd_airtime_t airtime);

/**
 * @brief Handle channel change on a specific VAP
 *
 * If the STA supports that VAP, the channel ID will be updated;
 * otherwise do nothing.
 *
 * @pre entry handle, VAP handle and channel ID are valid
 *
 * @param [in] handle  the handle to the entry
 * @param [in] vap  the VAP on which channel change occurs
 * @param [in] channel  new channel ID
 */
void stadbEntryHandleChannelChange(stadbEntry_handle_t handle,
                                   lbd_vapHandle_t vap,
                                   lbd_channelId_t channel);

/**
 * @brief Emit an association dialog log
 *
 * @param [in] handle  stadb entry to generate log for
 * @param [in] bss  associated BSS to generate log for
 */
void stadbEntryAssocDiagLog(stadbEntry_handle_t handle,
                            const lbd_bssInfo_t *bss);

/**
 * @brief Create BSS entries for BSSes on the same ESS as the
 *        serving BSS if they do not exist.
 *
 * @pre This should only happen for associated client
 *
 * @param [in] handle  the handle to the entry
 * @param [in] servingBSS  the BSS the client entry associates on
 * @param [in] band  if set to wlanif_band_invalid, will create
 *                   BSS entries for both bands; otherwise, will
 *                   create BSS entries on the given band
 */
void stadbEntryPopulateBSSesFromSameESS(stadbEntry_handle_t handle,
                                        const lbd_bssInfo_t *servingBSS,
                                        wlanif_band_e band);

/**
 * @brief Get the ESS ID the STA last associates on
 *
 * @param [in] handle  the handle to the STA entry
 *
 * @return the last associated ESS ID, or LBD_ESSID_INVALID if the STA has
 *         never associated before
 */
lbd_essId_t stadbEntryGetLastServingESS(stadbEntry_handle_t handle);

/**
 * @brief Update SM Power Save mode for a given STA
 *
 * @param [in] handle  the handle to the STA entry
 * @param [in] bss  the BSS on which SMPS mode is reported
 * @param [in] isStatic  whether the STA is operating in static SMPS mode
 *
 * @return LBD_OK on success, otherwise return LBD_NOK
 */
LBD_STATUS stadbEntryUpdateSMPSMode(stadbEntry_handle_t handle,
                                    const lbd_bssInfo_t *bss,
                                    LBD_BOOL isStatic);

/**
 * @brief Update PHY capabilities based on info from Operating Mode IE
 *
 */
LBD_STATUS stadbEntryUpdateOpMode(stadbEntry_handle_t entry,
                                  const lbd_bssInfo_t *bss,
                                  wlanif_chwidth_e maxChWidth,
                                  u_int8_t numStreams);

/**
 * @brief Mark the given entry as dual band supported
 *
 * @param [in] handle  the handle to the STA entry
 *
 * @return LBD_OK on success, otherwise return LBD_NOK
 */
LBD_STATUS stadbEntryMarkDualBandSupported(stadbEntry_handle_t handle);

/**
 * @brief Populate estimated PHY capabilities info on the non-serving band if no
 *        valid PHY info is available on that band
 *
 * @param [in] handle  the handle to the STA entry
 * @param [in] servingBSS  the info of the serving BSS
 * @param [in] servingPHY  STA PHY capabilities on the serving BSS
 */
LBD_STATUS stadbEntryPopulateNonServingPHYInfo(
        stadbEntry_handle_t handle, const lbd_bssInfo_t *servingBSS,
        const wlanif_phyCapInfo_t *servingPHY);

// --------------------------------------------------------------------
// Debug menu dump routines
// --------------------------------------------------------------------

// Optionally include functions for dumping out individual entries in the
// database.
#ifdef LBD_DBG_MENU
struct cmdContext;

/**
 * @brief Enumeration for different types of detailed information of a STA
 */
typedef enum stadbEntryDBGInfoType_e {
    stadbEntryDBGInfoType_phy,
    stadbEntryDBGInfoType_bss,

    stadbEntryDBGInfoType_rate_measured,
    stadbEntryDBGInfoType_rate_estimated,

    stadbEntryDBGInfoType_invalid,
} stadbEntryDBGInfoType_e;

/**
 * @brief Print the header corresponding to the entry summary information that
 *        will be included.
 *
 * @param [in] context  the output context
 * @param [in] inNetwork  flag indicating if the header is for in-network STAs
 */
void stadbEntryPrintSummaryHeader(struct cmdContext *context, LBD_BOOL inNetwork);

/**
 * @brief Print the summary information for this entry.
 *
 * @param [in] handle  the handle to the STA entry
 * @param [in] context  the output stream
 * @param [in] inNetwork  if set to LBD_TRUE, it should only print in-network entry;
 *                        otherwise, print only out-of-network entry
 */
void stadbEntryPrintSummary(const stadbEntry_handle_t handle,
                            struct cmdContext *context,
                            LBD_BOOL inNetwork);

/**
 * @brief Print the detailed information for this entry
 *
 * @param [in] context  the output stream
 * @param [in] handle  the handle to the STA entry
 * @param [in] infoType  the type of detailed info to print
 * @param [in] listAddr  whether to include MAC address in the output
 */
void stadbEntryPrintDetail(struct cmdContext *context,
                           const stadbEntry_handle_t handle,
                           stadbEntryDBGInfoType_e infoType,
                           LBD_BOOL listAddr);

/**
 * @brief Print the header corresponding to the entry detailed information that
 *        will be included.
 *
 * @param [in] context  the output stream
 * @param [in] infoType  the type of detailed info to print
 * @param [in] listAddr  whether to include MAC address in the output
 */
void stadbEntryPrintDetailHeader(struct cmdContext *context,
                                 stadbEntryDBGInfoType_e infoType,
                                 LBD_BOOL listAddr);
#endif /* LBD_DBG_MENU */


#if defined(__cplusplus)
}
#endif

#endif
