// vim: set et sw=4 sts=4 cindent:
/*
 * @File: wlanifBSteerControlCmn.h
 *
 * @Abstract: Header for load balancing daemon band steering control interface
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

#ifndef wlanifBSteerControlCmn__h
#define wlanifBSteerControlCmn__h

#include <stdlib.h>

#include <dbg.h>
#include <evloop.h>

#include "list.h"
#include "wlanifBSteerControl.h"

#if defined(__cplusplus)
extern "C" {
#endif

// ====================================================================
// Internal constants and types shared by BSA and MBSA
// ====================================================================

// Maximum number of VAPs on a single band
#define MAX_VAP_PER_BAND 16

/**
 * @brief Structure used to define an ESS
 */
typedef struct wlanifBSteerControlEssInfo_t {
    // SSID length
    u_int8_t ssidLen;

    // SSID string
    u_int8_t ssidStr[IEEE80211_NWID_LEN+1];
} wlanifBSteerControlEssInfo_t;

/**
 * @brief Internal structure for the radios in the system.
 *
 * VAPs are enabled on a specific radio. This type is used to represent
 * characteristics and state of the radio that are shared across all
 * VAPs on the radio.
 */
struct wlanifBSteerControlRadioInfo {
    /// Flag indicating whether the entry is valid.
    LBD_BOOL valid : 1;

    /// Flag indicating if the radio has the highest Tx power on its band.
    /// For single radio, it is always LBD_TRUE
    LBD_BOOL strongestRadio : 1;

    /// Interface name, +1 to ensure it is null-terminated.
    char ifname[IFNAMSIZ + 1];

    /// The value for the private ioctl that sets whether the SON mode
    /// is enabled or not.
    int sonIoctl;

    /// The resolved number for the enable_ol_stats ioctl.
    int enableOLStatsIoctl;

    /// The resolved number for the Nodebug for direct attach hardware.
    int enableNoDebug;

    /// The number of calls to enable the stats that need to be disabled.
    size_t numEnableStats;

    /// Channel on which this radio is operating.
    lbd_channelId_t channel;

    /// Regulatory class in which this radio is operating.
    u_int8_t regClass;

    /// Maximum Tx power on this radio
    u_int8_t maxTxPower;

    /// Maximum channel width supported on this radio
    wlanif_chwidth_e maxChWidth;

    // a list of STAs whose RSSI measurement is requested
    list_head_t rssiWaitingList;
};

/**
 * @brief internal structure for VAP information
 */
struct wlanifBSteerControlVapInfo {
    // flag indicating if this VAP is valid
    LBD_BOOL valid;

    // interface name, +1 to ensure it is null-terminated
    char ifname[IFNAMSIZ + 1];

    /// Reference to the radio that "owns" this VAP.
    struct wlanifBSteerControlRadioInfo *radio;

    // system index
    int sysIndex;

    // Whether the interface is considered up or not
    LBD_BOOL ifaceUp;

    // MAC address of this VAP
    struct ether_addr macaddr;

    // PHY capabilities information
    wlanif_phyCapInfo_t phyCapInfo;

    // ID corresponding to the ESS
    lbd_essId_t essId;
};

/**
 * @brief internal structure for band information
 */
struct wlanifBSteerControlBandInfo {
    // All VAPs on this band
    struct wlanifBSteerControlVapInfo vaps[MAX_VAP_PER_BAND];

    // config parameters
    ieee80211_bsteering_param_t configParams;

    // flag indicating if band steering is enabled on this band
    LBD_BOOL enabled;

    // duration for 802.11k beacon report
    u_int32_t bcnrptDurations[IEEE80211_RRM_BCNRPT_MEASMODE_RESERVED];
};

struct wlanifBSteerControlPriv_t {
    struct dbgModule *dbgModule;

    struct wlanifBSteerControlRadioInfo radioInfo[WLANIF_MAX_RADIOS];

    struct wlanifBSteerControlBandInfo bandInfo[wlanif_band_invalid];

    // Socket used to send control request down to driver
    int controlSock;

    /// Timer used to periodically check whether ACS and CAC have completed
    struct evloopTimeout vapReadyTimeout;

    /// Flag indicating whether band steering is currently enabled.
    LBD_BOOL bandSteeringEnabled;

    /// Number of ESSes supported on this device
    u_int8_t essCount;

    /// Variable used to set or clear the Authentication allow feature
     u_int8_t auth;

     /// Structure used to map ESS string to an ID (for
    /// simpler comparisons.  Each VAP on a radio must have a
    /// unique ESSID.  Index into this array will be the
    /// essId.
    wlanifBSteerControlEssInfo_t essInfo[MAX_VAP_PER_BAND];

// For now, we are only permitting two observers, as it is likely that the
// following will need to observe channel change
//
// 1. Station database
// 2. Steering executor
#define MAX_CHAN_CHANGE_OBSERVERS 2
    /// Observer for channel change
    struct wlanifBSteerControlChanChangeObserver {
        LBD_BOOL isValid;
        wlanif_chanChangeObserverCB callback;
        void *cookie;
    } chanChangeObserver[MAX_CHAN_CHANGE_OBSERVERS];
};

// ====================================================================
// Functions shared internally by BSA and MBSA
// ====================================================================

/**
 * @brief Fill in a local lbd_bssInfo_t for the VAP that matches
 *        the BSSID
 *
 * @param [in] state  the handle returned from wlanifBSteerControlCreate()
 * @param [in] bssid  BSSID for this VAP
 * @param [out] bss  structure to be filled in with BSS info
 *
 * @return LBD_STATUS LBD_OK if the BSS was found, LBD_NOK
 *                    otherwise
 */
LBD_STATUS wlanifBSteerControlCmnGetLocalBSSInfoFromBSSID(
    wlanifBSteerControlHandle_t state, const u_int8_t *bssid,
    lbd_bssInfo_t *bss);

/**
 * @brief Resolve the BSSID for a given set of BSS info parameters.
 *
 * @param [in] bssInfo  the parameters to look up; this must be for the self
 *                      AP ID
 *
 * @return the BSSID, or NULL if it cannot be resolved
 */
const struct ether_addr *wlanifBSteerControlCmnGetBSSIDForLocalBSSInfo(
        const lbd_bssInfo_t *bssInfo);

/**
 * @brief Obtain a copy of the PHY capabilities of a given local BSS.
 *
 * @param [in] handle  the handle returned from wlanifBSteerControlCreate()
 *                     to use for obtaining the capabilties
 * @param [in] bss  the BSS for which to obtain the capabilities
 * @param [out] phyCap  on success, the PHY capabilities
 *
 * @return LBD_OK on success; otherwise LBD_NOK
 */
LBD_STATUS wlanifBSteerControlCmnGetLocalBSSPHYCapInfo(
        wlanifBSteerControlHandle_t state, const lbd_bssInfo_t *bss,
        wlanif_phyCapInfo_t *phyCap);

// ====================================================================
// Protected functions
// ====================================================================

/**
 * @brief Notify other modules after PHY capabilities have been resolved
 *        on all VAPs successfully
 *
 * @param [in] state  the handle returned from wlanifBSteerControlCreate()
 */
void wlanifBSteerControlNotifyPHYCapabilities(wlanifBSteerControlHandle_t state);

/**
 * @brief Determine whether the driver should be told that SON mode is
 *        enabled.
 *
 * SON mode is the mode reserved for the fully coordinated multi-AP steering.
 *
 * @param [in] state  the handle returned from wlanifBSteerControlCreate()
 *
 * @return LBD_TRUE if SON mode should be set in the driver;
 *         otherwise LBD_FALSE
 */
LBD_BOOL wlanifBSteerControlGetSONInitVal(wlanifBSteerControlHandle_t state);

#if defined(__cplusplus)
}
#endif

#endif  // wlanifBSteerControlCmn__h
