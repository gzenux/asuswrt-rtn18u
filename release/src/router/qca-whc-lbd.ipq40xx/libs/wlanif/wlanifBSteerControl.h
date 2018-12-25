// vim: set et sw=4 sts=4 cindent:
/*
 * @File: wlanifBSteerControl.h
 *
 * @Abstract: Load balancing daemon band steering control interface
 *
 * @Notes: This header should not be included directly by other components
 *         within the load balancing daemon. It should be considered
 *         private to the wlanif module.
 *
 * @@-COPYRIGHT-START-@@
 *
 * Copyright (c) 2014 Qualcomm Atheros, Inc.
 * All Rights Reserved.
 * Qualcomm Atheros Confidential and Proprietary.
 *
 * @@-COPYRIGHT-END-@@
 */

#ifndef wlanifBSteerControl__h
#define wlanifBSteerControl__h

#include "lbd_types.h"
#include "wlanif.h" //wlanif_band_e

#if defined(__cplusplus)
extern "C" {
#endif

// Out of package forward decls.
struct dbgModule;

/* package API */

struct wlanifBSteerControlPriv_t;  // opaque forward declaration
typedef struct wlanifBSteerControlPriv_t * wlanifBSteerControlHandle_t;

struct wlanifBSteerEventsPriv_t;  // opaque forward declaration
typedef struct wlanifBSteerEventsPriv_t * wlanifBSteerEventsHandle_t;

/**
 * @brief Initialize the band steering request interface, by resolving
 *        wlan interfaces and parsing the configuration file
 *
 * @param [in] dbgModule  the handle to use for logging
 *
 * @return a handle to the state for this instance, or NULL if it
 *         could not be created
 */
wlanifBSteerControlHandle_t wlanifBSteerControlCreate(struct dbgModule *dbgModule);

/**
 * @brief Enable the band steering feature, but only if both bands indicate
 *        that the VAPs are not active in doing a scan or DFS wait.
 *
 * @param [in] handle  the handle returned from wlanifBSteerControlCreate()
 *                     to use to enable the band steering feature
 * @param [out] enabled  whether band steering was enabled
 *
 * @return LBD_OK if band steering was enabled or a timer was started to
 *         enable it later; otherwise LBD_NOK
 */
LBD_STATUS wlanifBSteerControlEnableWhenReady(
        wlanifBSteerControlHandle_t state, LBD_BOOL *enabled);

/**
 * @brief Disable band steering feature on all bands.
 *
 * @param [in] handle  the handle returned from wlanifBSteerControlCreate()
 *                     to use to disable band steering feature
 *
 * @return LBD_OK on successfully enable/disable; otherwise LBD_NOK
 */
LBD_STATUS wlanifBSteerControlDisable(wlanifBSteerControlHandle_t handle);

/**
 * @brief Destroy the band steering control interface
 *
 * @param [in] handle  the handle returned from wlanifBSteerControlCreate()
 *                     to destroy
 *
 * @return LBD_OK if it was successfully destroyed; otherwise LBD_NOK
 */
LBD_STATUS wlanifBSteerControlDestroy(wlanifBSteerControlHandle_t handle);

 /**
 * @brief Set overload status on a band
 *
 * @param [in] handle  the handle returned from wlanifBSteerControlCreate()
 *                     to use to set overload status
 * @param [in] channelId  the channel on which to set overload status
 * @param [in] overload  LBD_TRUE for overload, LBD_FALSE for not overload
 *
 * @return LBD_OK on successfully set overload; otherwise LBD_NOK
 */
LBD_STATUS wlanifBSteerControlSetOverload(wlanifBSteerControlHandle_t handle,
                                          lbd_channelId_t channel,
                                          LBD_BOOL overload);

/**
 * @brief Convert the system index from the driver into a band.
 *
 * @param [in] handle  the handle returned from wlanifBSteerControlCreate()
 *                     to use to resolve band from system index
 * @param [in] index  the system interface index
 *
 * @return  the resolved band, or wlanif_band_invalid
 */
wlanif_band_e wlanifBSteerControlResolveBandFromSystemIndex(wlanifBSteerControlHandle_t handle,
                                                            int index);

/**
 * @brief Update the link status for the provided interface and indicate
 *        whether it has changed.
 *
 * @pre changed is a valid pointer.
 * @pre The sysIndex parameter corresponds to a VAP being managed by this.
 *      If it does not, this will be a nop.
 *
 * @param [in] handle  the handle returned from wlanifBSteerControlCreate()
 *                     to use to update the internal state
 * @param [in] sysIndex  the system interface index
 * @param [in] ifaceUp  whether the interface is currently considered up
 * @param [out] changed  whether the link state was changed or not
 */
void wlanifBSteerControlUpdateLinkState(wlanifBSteerControlHandle_t handle,
                                        int sysIndex, LBD_BOOL ifaceUp,
                                        LBD_BOOL *changed);

/**
 * @brief For each of the VAPs, dump the associated STAs and invoke the
 *        callback with each STA MAC address and the band on which it
 *        is associated.
 *
 * @param [in] handle  the handle returned from wlanifBSteerControlCreate()
 *                     to use to dump the associated STAs
 * @param [in] callback  the callback to invoke with the associated STA
 *                       information
 * @param [in] cookie  the parameter to provide in the callback (in addition
 *                     to the STA information) for use by the caller of this
 *                     function
 *
 *
 * @return LBD_OK on success; otherwise LBD_NOK
 */
LBD_STATUS wlanifBSteerControlDumpAssociatedSTAs(wlanifBSteerControlHandle_t handle,
                                                 wlanif_associatedSTAsCB callback,
                                                 void *cookie);

/**
 * @brief Request real-time RSSI measurement of a specific station
 *
 * The RSSI measurement will be reported back in wlanif_event_rssi_measurement.
 *
 * @param [in] handle  the handle returned from wlanifBSteerControlCreate()
 *                     to use to request RSSI measurement
 * @param [in] bss  the BSS that the client is associated with
 * @param [in] staAddr  the MAC address of the specific station
 * @param [in] numSamples  number of RSSI samples to average before reporting RSSI back
 *
 * @return  LBD_OK if the request is sent successfully; otherwise LBD_NOK
 */
LBD_STATUS wlanifBSteerControlRequestStaRSSI(wlanifBSteerControlHandle_t handle,
                                             const lbd_bssInfo_t *bss,
                                             const struct ether_addr * staAddr,
                                             u_int8_t numSamples);

/**
 * @brief Enable/disable probe response withholding for a specific STA.
 *
 * @pre The band must have been disabled for the STA first before this is
 *      called.
 *
 * @param [in] handle  the handle returned from wlanifBSteerControlCreate()
 *                     to use to request RSSI measurement
 * @param [in] band  the band on which to withhold probe responses
 * @param [in] staAddr  the MAC address of the specific station
 * @param [in] withholdProbes  the flag for whether to withhold probe
 *                             responses or not
 *
 * @return  LBD_OK if the request is sent successfully; otherwise LBD_NOK
 */
LBD_STATUS wlanifBSteerControlSetProbeRespWHForSTA(
        wlanifBSteerControlHandle_t handle, wlanif_band_e band,
        const struct ether_addr * staAddr, LBD_BOOL withholdProbes);

/**
 * @brief Either enable or disable all VAPs on a channel in
 *        channelList for a STA.
 *
 * @param [in] handle  the handle returned from wlanifBSteerControlCreate()
 * @param [in] channelCount number of channels in channelList
 * @param [in] channelList set of channels to enable or disable
 * @param [in] staAddr the MAC address of the STA
 * @param [in] enable set to LBD_TRUE to enable for all
 *                    channels, LBD_FALSE to disable
 *
 * @return LBD_STATUS LBD_OK if the state could be set, LBD_NOK
 *                    otherwise
 */
LBD_STATUS wlanifBSteerControlSetChannelStateForSTA(
    wlanifBSteerControlHandle_t handle,
    u_int8_t channelCount,
    const lbd_channelId_t *channelList,
    const struct ether_addr *staAddr,
    LBD_BOOL enable);

/**
 * @brief Either enable or disable all 2.4G VAPs on a channel in
 *        channelList for a STA.
 *
 * @param [in] handle  the handle returned from wlanifBSteerControlCreate()
 * @param [in] channelCount number of channels in channelList
 * @param [in] channelList set of channels to enable or disable
 * @param [in] staAddr the MAC address of the STA
 * @param [in] enable set to LBD_TRUE to enable for all
 *                    channels, LBD_FALSE to disable
 *
 * @return LBD_STATUS LBD_OK if the state could be set, LBD_NOK
 *                    otherwise
 */
LBD_STATUS wlanifBSteerControlSetChannelProbeStateForSTA(
    wlanifBSteerControlHandle_t handle,
    u_int8_t channelCount,
    const lbd_channelId_t *channelList,
    const struct ether_addr *staAddr,
    LBD_BOOL enable);

/**
 * @brief Will set the state of all VAPs on the same ESS not
 *        matching the candidate list.
 *
 * @param [in] handle  the handle returned from
 *                     wlanifBSteerControlCreate()
 * @param [in] candidateCount number of candidates in
 *                            candidateList
 * @param [in] candidateList set of candidate BSSes
 * @param [in] staAddr the MAC address of the STA
 * @param [in] enable if LBD_TRUE, will enable all VAPs not on
 *                    the candidate list
 * @param [in] probeOnly if LBD_TRUE, will set the probe
 *                       response witholding state only
 *
 * @return LBD_STATUS LBD_OK if the state could be set, LBD_NOK
 *                    otherwise
 */
LBD_STATUS wlanifBSteerControlSetNonCandidateStateForSTA(
    wlanifBSteerControlHandle_t handle,
    u_int8_t candidateCount,
    const lbd_bssInfo_t *candidateList,
    const struct ether_addr *staAddr,
    LBD_BOOL enable,
    LBD_BOOL probeOnly);

/**
 * @brief Get the set of VAPs on the same ESS but not matching
 *        the candidate list.
 *
 * @param [in] handle  the handle returned from
 *                     wlanifBSteerControlCreate()
 * @param [in] candidateCount number of candidates in
 *                            candidateList
 * @param [in] candidateList set of candidate BSSes
 * @param [in] maxCandidateCount  maximum number of candidates
 *                                that can be added to
 *                                outCandidateList
 * @param [out] outCandidateList filled in with VAP information
 *
 * @return Number of candidates added to outCandidateList
 */
u_int8_t wlanifBSteerControlGetNonCandidateStateForSTA(
    wlanifBSteerControlHandle_t handle,
    u_int8_t candidateCount,
    const lbd_bssInfo_t *candidateList,
    u_int8_t maxCandidateCount,
    lbd_bssInfo_t *outCandidateList);

/**
 * @brief Will update the state for all VAPs on the candidate
 *        list.
 *
 * @param [in] handle  the handle returned from
 *                     wlanifBSteerControlCreate()
 * @param [in] candidateCount number of candidates in
 *                            candidateList
 * @param [in] candidateList set of candidate BSSes
 * @param [in] staAddr the MAC address of the STA
 * @param [in] enable if LBD_TRUE, will enable all VAPs on
 *                    the candidate list
 *
 * @return LBD_STATUS LBD_OK if the state could be set, LBD_NOK
 *                    otherwise
 */
LBD_STATUS wlanifBSteerControlSetCandidateStateForSTA(
    wlanifBSteerControlHandle_t handle,
    u_int8_t candidateCount,
    const lbd_bssInfo_t *candidateList,
    const struct ether_addr *staAddr,
    LBD_BOOL enable);

/**
 * @brief Will update the probe response state for all 2.4G VAPs on
 *  the candidate list.
 *
 * @param [in] handle  the handle returned from
 *                     wlanifBSteerControlCreate()
 * @param [in] candidateCount number of candidates in
 *                            candidateList
 * @param [in] candidateList set of candidate BSSes
 * @param [in] staAddr the MAC address of the STA
 * @param [in] enable if LBD_TRUE, will enable all VAPs on
 *                    the candidate list
 *
 * @return LBD_STATUS LBD_OK if the state could be set, LBD_NOK
 *                    otherwise
 */
LBD_STATUS wlanifBSteerControlSetCandidateProbeStateForSTA(
    wlanifBSteerControlHandle_t handle,
    u_int8_t candidateCount,
    const lbd_bssInfo_t *candidateList,
    const struct ether_addr *staAddr,
    LBD_BOOL enable);

/**
 * @brief Determine if a BSSID identifies one of the candidates
 *        in a list.
 *
 * @param [in] handle  the handle returned from
 *                     wlanifBSteerControlCreate()
 * @param [in] candidateCount number of candidates in
 *                            candidateList
 * @param [in] candidateList set of candidate BSSes
 * @param [in] bssid  BSSID to search for
 *
 * @return LBD_TRUE if match is found; LBD_FALSE otherwise
 */
LBD_BOOL wlanifBSteerControlIsBSSIDInList(
    wlanifBSteerControlHandle_t handle,
    u_int8_t candidateCount,
    const lbd_bssInfo_t *candidateList,
    const struct ether_addr *bssid);

/**
 * @brief Resolve the BSSID for a given set of BSS info parameters.
 *
 * @param [in] handle  the handle returned from
 *                     wlanifBSteerControlCreate()
 * @param [in] bssInfo  the parameters to look up
 *
 * @return the BSSID, or NULL if it cannot be resolved
 */
const struct ether_addr *wlanifBSteerControlGetBSSIDForBSSInfo(
        wlanifBSteerControlHandle_t handle,
        const lbd_bssInfo_t *bssInfo);

/**
 * @brief Get the set of channels that are active on this device
 *
 * @param [in] handle  the handle returned from wlanifBSteerControlCreate()
 * @param [out] channelList  set of active channels
 * @param [out] chwidthList  set of channel width of all active channels
 * @param [in] maxSize  maximum number of channels that will be
 *                      returned
 *
 * @return count of active channels
 */
u_int8_t wlanifBSteerControlGetChannelList(wlanifBSteerControlHandle_t handle,
                                           lbd_channelId_t *channelList,
                                           wlanif_chwidth_e *chwidthList,
                                           u_int8_t maxSize);

/**
 * @brief Kick the STA out of the provided band, forcing disassociation.
 *
 * @param [in] handle  the handle returned from wlanifBSteerControlCreate()
 *                     to use for this operation
 * @param [in] assocBSS  the BSS on which the STA should be
 *                       disassociated
 * @param [in] staAddr the MAC address of the STA to disassociate 
 * @param [in] local  set to LBD_TRUE if doing just a local
 *                    disassociation (no disassociation frame
 *                    sent OTA, only state cleaned up),
 *                    otherwise LBD_FALSE for a true
 *                    disassociation (sending disassociation
 *                    frame OTA) 
 *
 * @return LBD_OK if the request to disassociate was successfully handled;
 *         otherwise LBD_NOK
 */
LBD_STATUS wlanifBSteerControlDisassociateSTA(
        wlanifBSteerControlHandle_t handle, const lbd_bssInfo_t *assocBSS,
        const struct ether_addr *staAddr,
        LBD_BOOL local);

/**
 * @brief Restart the process in the driver that monitors the channel
 *        utilization on each band.
 *
 * @param [in] handle  the handle returned from wlanifBSteerControlCreate()
 *                     to use for this operation
 *
 * @return LBD_OK if the overall restart was successful; otherwise LBD_NOK
 */
LBD_STATUS wlanifBSteerControlRestartChannelUtilizationMonitoring(
        wlanifBSteerControlHandle_t state);

/**
 * @brief Handle RSSI measurement update.
 *
 * If it is for the pending STA, the STA will be removed from pending
 * list and the next queued STA can send the request. Otherwise, it
 * will be ignored.
 *
 * @param [in] handle  the handle returned from wlanifBSteerControlCreate()
 *                     to use for this operation
 * @param [in] bss  the BSS on which the RSSI measurement is received
 * @param [in] staAddr  the MAC address of the STA
 */
void wlanifBSteerControlHandleRSSIMeasurement(
        wlanifBSteerControlHandle_t handle,
        const lbd_bssInfo_t *bss,
        const struct ether_addr *staAddr);

/**
 * @brief Send a BSS Transition Management request frame to
 *        staAddr on all VAPs operating on band
 *
 * @param [in] handle  the handle returned from wlanifBSteerControlCreate()
 *                     to use for this operation
 * @param [in] assocBSS  the BSS on which to send this request
 * @param [in] staAddr  the MAC address of the STA
 * @param [in] dialogToken dialog token to send with the request
 * @param [in] candidateCount count of candidates for the
 *                            request
 * @param [in] candidates candidate list for the request
 *
 * @return LBD_STATUS LBD_OK if sent successfully, LBD_NOK
 *                    otherwise. Note will only return LBD_NOK
 *                    if there is a problem with the input
 *                    parameters, since we don't know which VAP
 *                    the STA is operating on, failure to send
 *                    is considered a soft error.
 */
LBD_STATUS wlanifBSteerControlSendBTMRequest(wlanifBSteerControlHandle_t handle,
                                             const lbd_bssInfo_t *assocBSS,
                                             const struct ether_addr *staAddr,
                                             u_int8_t dialogToken,
                                             u_int8_t candidateCount,
                                             const lbd_bssInfo_t *candidateList);

/**
 * @brief Request the real-time downlink RSSI measurement of a specific
 *        client. This could be the RSSI seen by client from beacon or probe
 *        response
 *
 * The RSSI measurement will be reported back in wlanif_event_rssi_measurement.
 *
 * @param [in] handle  the handle returned from wlanifBSteerControlCreate()
 *                     to use to request RSSI measurement
 * @param [in] bss  the BSS that the client is associated with
 * @param [in] staAddr  the MAC address of the specific station
 * @param [in] rrmCapable  flag indicating if the STA implements 802.11k feature
 * @param [in] numChannels  number of channels in channelList
 * @param [in] channelList  set of channels to measure downlink RSSI
 *
 * @return  LBD_OK if the request is sent successfully; otherwise LBD_NOK
 */
LBD_STATUS wlanifBSteerControlRequestDownlinkRSSI(
        wlanifBSteerControlHandle_t handle, const lbd_bssInfo_t *bss,
        const struct ether_addr *staAddr, LBD_BOOL rrmCapable,
        size_t numChannels, const lbd_channelId_t *channelList);

/**
 * @brief Fill in a lbd_bssInfo_t for the VAP that matches
 *        sysIndex
 *
 * @param [in] state the handle returned from
 *                   wlanifBSteerControlCreate()
 * @param [in] sysIndex OS-specific identifier for the interface
 * @param [out] bss structure to be filled in with BSS info
 *
 * @return LBD_STATUS LBD_OK if the BSS was found, LBD_NOK
 *                    otherwise
 */
LBD_STATUS wlanifBSteerControlGetBSSInfo(wlanifBSteerControlHandle_t state,
                                         u_int32_t sysIndex, lbd_bssInfo_t *bss);

/**
 * @brief Fill in a lbd_bssInfo_t for the VAP that matches
 *        the BSSID
 *
 * @param [in] state the handle returned from
 *                   wlanifBSteerControlCreate()
 * @param [in] essid  the ESS ID on which the BSSID is seen
 * @param [in] bssid BSSID for this VAP
 * @param [out] bss structure to be filled in with BSS info
 *
 * @return LBD_STATUS LBD_OK if the BSS was found, LBD_NOK
 *                    otherwise
 */
LBD_STATUS wlanifBSteerControlGetBSSInfoFromBSSID(
    wlanifBSteerControlHandle_t state, lbd_essId_t essid,
    const u_int8_t *bssid, lbd_bssInfo_t *bss);

/**
 * @brief Enable the collection of byte and MCS statistics on the provided
 *        BSS.
 *
 * @param [in] handle  the handle returned from wlanifBSteerControlCreate()
 *                     to use for enabling the stats
 * @param [in] bss  the BSS on which to enable the stats; this must be a
 *                  local BSS
 *
 * @return LBD_OK on success; otherwise LBD_NOK
 */
LBD_STATUS wlanifBSteerControlEnableSTAStats(
        wlanifBSteerControlHandle_t handle,
        const lbd_bssInfo_t *bss);

/**
 * @brief Take a snapshot of the STA statistics.
 *
 * @param [in] handle  the handle returned from wlanifBSteerControlCreate()
 *                     to use to snapshot the stats
 * @param [in] bss  the BSS that is serving the STA
 * @param [in] staAddr  the MAC address of the STA
 * @param [in] rateOnly will return only the rate data.  Does
 *                      not require stats to be enabled.
 * @param [out] staStats  the snapshot of the stats; only populated on success
 *
 * @return LBD_OK on success; otherwise LBD_NOK
 */
LBD_STATUS wlanifBSteerControlSampleSTAStats(
        wlanifBSteerControlHandle_t handle,
        const lbd_bssInfo_t *bss, const struct ether_addr *staAddr,
        LBD_BOOL rateOnly,
        wlanif_staStatsSnapshot_t *staStats);

/**
 * @brief Disable the collection of byte and MCS statistics on the provided
 *        BSS.
 *
 * @param [in] handle  the handle returned from wlanifBSteerControlCreate()
 *                     to use for disabling the stats
 * @param [in] bss  the BSS on which to disable the stats; this must be a
 *                  local BSS
 *
 * @return LBD_OK on success; otherwise LBD_NOK
 */
LBD_STATUS wlanifBSteerControlDisableSTAStats(
        wlanifBSteerControlHandle_t handle,
        const lbd_bssInfo_t *bss);

/**
 * @brief Obtain a copy of the PHY capabilities of a specific BSS.
 *
 * @param [in] handle  the handle returned from wlanifBSteerControlCreate()
 *                     to use for obtaining the capabilties
 * @param [in] bss  the BSS for which to obtain the capabilities
 * @param [out] phyCap  on success, the PHY capabilities
 *
 * @return LBD_OK on success; otherwise LBD_NOK
 */
LBD_STATUS wlanifBSteerControlGetBSSPHYCapInfo(wlanifBSteerControlHandle_t handle,
                                               const lbd_bssInfo_t *bss,
                                               wlanif_phyCapInfo_t *phyCap);

/**
 * @brief Update the channel and regulatory class stored for a
 *        radio (after a channel change event)
 *
 * @param [in] handle  the handle returned from
 *                     wlanifBSteerControlCreate()
 * @param [in] band band the event occurred on
 * @param [in] sysIndex sysIndex the event occurred on
 * @param [in] frequency new frequency for the radio
 *
 * @return LBD_STATUS LBD_OK if channel / regulatory class could
 *                    be updated, LBD_NOK otherwise
 */
LBD_STATUS wlanifBSteerControlUpdateChannel(
     wlanifBSteerControlHandle_t handle,
     wlanif_band_e band,
     u_int32_t sysIndex,
     u_int32_t frequency);

/**
 * @brief For each of the VAPs, dump the Airtime Fainess (ATF) table and
 *        invoke the callback with each STA MAC address and the reserved
 *        airtime listed
 *
 * @param [in] handle  the handle returned from wlanifBSteerControlCreate()
 *                     to use to dump the reserved airtime info
 * @param [in] callback  the callback to invoke with the reserved airtime
 *                       information
 * @param [in] cookie  the parameter to provide in the callback (in addition
 *                     to the airtime information) for use by the caller of this
 *                     function
 *
 * @return LBD_OK on success; otherwise LBD_NOK
 */
LBD_STATUS wlanifBSteerControlDumpATFTable(wlanifBSteerControlHandle_t handle,
                                           wlanif_reservedAirtimeCB callback,
                                           void *cookie);

/**
 * @brief Determine if STA is associated on a BSS
 *
 * @param [in] handle  the handle returned from
 *                     wlanifBSteerControlCreate()
 * @param [in] bss  BSS to check for STA association
 * @param [in] staAddr  MAC address of STA to check for
 *                      association
 *
 * @return LBD_TRUE if STA is associated on BSS; LBD_FALSE
 *         otherwise
 */
LBD_BOOL wlanifBSteerControlIsSTAAssociated(wlanifBSteerControlHandle_t handle,
                                            const lbd_bssInfo_t *bss,
                                            const struct ether_addr *staAddr);

/**
 * @brief Register a callback function to observe channel changes
 *
 * Note that the pair of the callback and cookie must be unique.
 *
 * @param [in] handle  the handle returned from wlanifBSteerControlCreate()
 * @param [in] callback  the function to invoke for channel changes
 * @param [in] cookie  the parameter to pass to the callback function
 *
 * @return LBD_OK if the observer was successfully registered; otherwise
 *         LBD_NOK (either due to no free slots or a duplicate registration)
 */
LBD_STATUS wlanifBSteerControlRegisterChanChangeObserver(
        wlanifBSteerControlHandle_t handle, wlanif_chanChangeObserverCB callback,
        void *cookie);

/**
 * @brief Unregister a callback function so that it no longer will receive
 *        channel change notification.
 *
 * The parameters provided must match those given in the original
 * wlanif_registerChanChangeObserver() call.
 *
 * @param [in] handle  the handle returned from wlanifBSteerControlCreate()
 * @param [in] callback  the function that was previously registered
 * @param [in] cookie  the parameter that was provided when the function was
 *                     registered
 *
 * @return LBD_OK if the observer was successfully unregistered; otherwise
 *         LBD_NOK
 */
LBD_STATUS wlanifBSteerControlUnregisterChanChangeObserver(
        wlanifBSteerControlHandle_t handle, wlanif_chanChangeObserverCB callback,
        void *cookie);

/**
 * @brief Update the max Tx power on a BSS
 *
 * @param [in] handle  the handle returned from wlanifBSteerControlCreate()
 * @param [in] bss  the BSS on which max Tx power changes
 * @param [in] maxTxPower  new max Tx power
 */
void wlanifBSteerControlUpdateMaxTxPower(wlanifBSteerControlHandle_t handle,
                                         const lbd_bssInfo_t *bss,
                                         u_int16_t maxTxPower);

/**
 * @brief Check if a given channel has stronger Tx power on its band
 *
 * @param [in] handle  the handle returned from wlanifBSteerControlCreate()
 * @param [in] channelId  the given channel
 * @param [out] isStrongest  set to LBD_TRUE if the channel has the highest Tx
 *                           power on its band on success
 *
 * @return LBD_OK on success; otherwise return LBD_NOK
 */
LBD_STATUS wlanifBSteerControlIsStrongestChannel(
        wlanifBSteerControlHandle_t handle, lbd_channelId_t channelId,
        LBD_BOOL *isStrongest);

/**
 * @brief Check if a given BSS is on the channel with the strongest Tx power
 *        on its band
 *
 * @param [in] handle  the handle returned from wlanifBSteerControlCreate()
 * @param [in] bss  the given BSS
 * @param [out] isStrongest  set to LBD_TRUE if the channel has the highest Tx
 *                           power on its band on success
 *
 * @return LBD_OK on success; otherwise return LBD_NOK
 */
LBD_STATUS wlanifBSteerControlIsBSSOnStrongestChannel(
        wlanifBSteerControlHandle_t handle, const lbd_bssInfo_t *bss,
        LBD_BOOL *isStrongest);

/**
 * @brief Find BSSes that are on the same ESS with the given BSS (except the given one),
 *        or all BSSes on the given ESS
 *
 * @param [in] handle  the handle returned from wlanifBSteerControlCreate()
 * @param [in] bss  the given BSS
 * @param [in] lastServingESS  if no given BSS, will find BSSes on this ESS
 * @param [in] band  if set to wlanif_band_invalid, find BSSes from both bands;
 *                   otherwise, find BSSes from the given band
 * @param [inout] maxNumBSSes  on input, it is the maximum number of BSSes expected;
 *                             on output, return number of entries in the bssList
 * @param [out] bssList  the list of BSSes that are on the same ESS with given BSS
 *
 * @return LBD_OK on success, otherwise return LBD_NOK
 */
LBD_STATUS wlanifBSteerControlGetBSSesSameESS(
        wlanifBSteerControlHandle_t handle, const lbd_bssInfo_t *bss,
        lbd_essId_t lastServingESS, wlanif_band_e band,
        size_t* maxNumBSSes, lbd_bssInfo_t *bssList);

/**
 * @brief Notify driver if a given STA is being steered or not
 *
 * @param [in] handle  the handle returned from wlanifBSteerControlCreate()
 * @param [in] addr  the MAC address of the given STA
 * @param [in] bss  the BSS where the given STA is associated
 * @param [in] steeringInProgress  whether the STA is being steered
 *
 * @return LBD_OK if the steering status of the driver has been updated
 *         successfully; otherwise return LBD_NOK
 */
LBD_STATUS wlanifBSteerControlUpdateSteeringStatus(
        wlanifBSteerControlHandle_t handle, const struct ether_addr *addr,
        const lbd_bssInfo_t *bss, LBD_BOOL steeringInProgress);

/**
 * @brief Enable socket based event generation from driver.
 *
 * This should be called after all interested entities have registered for the
 * events so that they do not miss any of them.
 *
 * @param [in] state, handle returned from wlanifBSteerControlCreate()
 * @param [in] handle, opaque handle returned from wlanifBSteerEventsCreate()
 *
 * @return LBD_OK if communciation to driver is successfull; otherwise return LBD_NOK
 */
LBD_STATUS wlanifBSteerControlEventsEnable(
          wlanifBSteerControlHandle_t state,
          wlanifBSteerEventsHandle_t handle);

/*========================================================================*/
/*============ Constants needed by test cases ============================*/
/*========================================================================*/

// Note that these are #define's instead of global constants, as the latter
// cannot be used in the initializer list for the profileElement array that
// specifies default values.
#define WLANIFBSTEERCONTROL_WLAN_INTERFACES "WlanInterfaces"
#define WLANIFBSTEERCONTROL_INACT_IDLE_THRESHOLD "InactIdleThreshold"
#define WLANIFBSTEERCONTROL_INACT_OVERLOAD_THRESHOLD "InactOverloadThreshold"
#define WLANIFBSTEERCONTROL_INACT_CHECK_INTERVAL "InactCheckInterval"
#define WLANIFBSTEERCONTROL_INACT_RSSI_XING_HIGH_THRESHOLD "InactRSSIXingHighThreshold"
#define WLANIFBSTEERCONTROL_INACT_RSSI_XING_LOW_THRESHOLD "InactRSSIXingLowThreshold"
#define WLANIFBSTEERCONTROL_LOW_RSSI_XING_THRESHOLD "LowRSSIXingThreshold"
#define WLANIFBSTEERCONTROL_MU_AVG_PERIOD "MUAvgPeriod"
#define WLANIFBSTEERCONTROL_MU_CHECK_INTERVAL "MUCheckInterval"
#define WLANIFBSTEERCONTROL_BCNRPT_ACTIVE_DURATION "BcnrptActiveDuration"
#define WLANIFBSTEERCONTROL_BCNRPT_PASSIVE_DURATION "BcnrptPassiveDuration"
#define WLANIFBSTEERCONTROL_LOW_TX_RATE_XING_THRESHOLD "LowTxRateXingThreshold"
#define WLANIFBSTEERCONTROL_HIGH_TX_RATE_XING_THRESHOLD "HighTxRateXingThreshold"
#define WLANIFBSTEERCONTROL_LOW_RATE_RSSI_XING_THRESHOLD "LowRateRSSIXingThreshold"
#define WLANIFBSTEERCONTROL_HIGH_RATE_RSSI_XING_THRESHOLD "HighRateRSSIXingThreshold"
#define WLANIFBSTEERCONTROL_AP_STEER_LOW_XING_THRESHOLD "LowRSSIAPSteeringThreshold"
#define WLANIFBSTEERCONTROL_INTERFERENCE_DETECTION_ENABLE "InterferenceDetectionEnable"
#define WLANIFBSTEERCONTROL_AUTH_ALLOW "AuthAllow"
#define WLANIFBSTEERCONTROL_DELAY_24G_PROBE_RSSI_THRESHOLD "Delay24GProbeRSSIThreshold"
#define WLANIFBSTEERCONTROL_DELAY_24G_PROBE_TIME_WINDOW "Delay24GProbeTimeWindow"
#define WLANIFBSTEERCONTROL_DELAY_24G_PROBE_MIN_REQ_COUNT "Delay24GProbeMinReqCount"

// When VAPs are not ready upon first check, how frequently (in seconds) to
// check them for becoming ready.
#define VAP_READY_CHECK_PERIOD 10

#if defined(__cplusplus)
}
#endif

#endif  // wlanifBSteerControl__h
