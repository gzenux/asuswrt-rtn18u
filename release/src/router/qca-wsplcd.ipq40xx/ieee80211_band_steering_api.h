/*
 * @@-COPYRIGHT-START-@@
 *
 * Copyright (c) 2014 Qualcomm Atheros, Inc.
 * All Rights Reserved.
 * Qualcomm Atheros Confidential and Proprietary.
 *
 * @@-COPYRIGHT-END-@@
 */

#ifndef _ATH_BAND_STEERING_API__
#define _ATH_BAND_STEERING_API__
#include <ieee80211_rrm.h>
#define NETLINK_BAND_STEERING_EVENT 21
#define BSTEERING_INVALID_RSSI 0
#define IEEE80211_ADDR_LEN 6
/* Note this is dependent on firmware - currently can only have 3 per event */
#define BSTEERING_MAX_PEERS_PER_EVENT 3

/**
 * Metadata about a probe request received from a client that is useful
 * for making band steering decisions.
 */
struct bs_probe_req_ind {
    /* The MAC address of the client that sent the probe request.*/
    u_int8_t sender_addr[IEEE80211_ADDR_LEN];
    /*  The RSSI of the received probe request.*/
    u_int8_t rssi;
};

/**
 * Metadata about an authentication message that was sent with a failure
 * code due to the client being prohibited by the ACL.
 */
struct bs_auth_reject_ind {
    /* The MAC address of the client to which the authentication message
        was sent with a failure code.*/
    u_int8_t client_addr[IEEE80211_ADDR_LEN];
    /* The RSSI of the received authentication message (the one that
       triggered the rejection).*/
    u_int8_t rssi;
};

/**
 * Data rated related information contained in ATH_EVENT_BSTEERING_NODE_ASSOCIATED
 * and IEEE80211_DBGREQ_BSTEERING_GET_DATARATE_INFO response
 */
typedef struct ieee80211_bsteering_datarate_info_t {
    /* Maximum bandwidth the client supports, valid values are enumerated
     * in enum ieee80211_cwm_width in _ieee80211.h. But the header file cannot
     * be included here because of potential circular dependency. Caller should
     * make sure that only valid values can be written/read. */
    u_int8_t max_chwidth;
    /* Number of spatial streams the client supports */
    u_int8_t num_streams;
    /* PHY mode the client supports. Same as max_chwidth field, only valid values
     * enumerated in enum ieee80211_phymode can be used here. */
    u_int8_t phymode;
    /* Maximum MCS the client supports */
    u_int8_t max_MCS;
    /* Maximum TX power the client supports */
    u_int8_t max_txpower;
    /* Set to 1 if this client is operating in Static SM Power Save mode */
    u_int8_t is_static_smps : 1;
    /* Set to 1 if this client supports MU-MIMO */
    u_int8_t is_mu_mimo_supported : 1;
} ieee80211_bsteering_datarate_info_t;

/**
 * Metadata about a STA that has associated
 */
struct bs_node_associated_ind {
    /* The MAC address of the client that is associated.*/
    u_int8_t client_addr[IEEE80211_ADDR_LEN];
    /* Set to 1 if this client supports BSS Transition Management */
    u_int8_t isBTMSupported : 1;
    /* Set to 1 if this client implements Radio Resource Manangement */
    u_int8_t isRRMSupported : 1;
    /* Data rate related information supported by this client */
    ieee80211_bsteering_datarate_info_t datarate_info;
};

/**
 * Metadata about a client activity status change.
 */
struct bs_activity_change_ind {
    /* The MAC address of the client that activity status changes */
    u_int8_t client_addr[IEEE80211_ADDR_LEN];
    /* Activity status*/
    u_int8_t activity;
};

/**
 * Data for a channel utilization measurement.
 */
struct bs_chan_utilization_ind {
    /* The current utilization on the band, expressed as a percentage.*/
    u_int8_t utilization;
};

/**
 * Enumeration to mark crossing direction
 */
typedef enum {
    /* Threshold not crossed */
    BSTEERING_XING_UNCHANGED = 0,
    /* Threshold crossed in the up direction */
    BSTEERING_XING_UP = 1,
    /* Threshold crossed in the down direction */
    BSTEERING_XING_DOWN = 2
} BSTEERING_XING_DIRECTION;

/**
 * Metadata about a client RSSI measurement crossed threshold.
 */
struct bs_rssi_xing_threshold_ind {
    /* The MAC address of the client */
    u_int8_t client_addr[IEEE80211_ADDR_LEN];
    /* The measured RSSI */
    u_int8_t rssi;
    /* Flag indicating if it crossed inactivity RSSI threshold */
    BSTEERING_XING_DIRECTION inact_rssi_xing;
    /* Flag indicating if it crossed low RSSI threshold */
    BSTEERING_XING_DIRECTION low_rssi_xing;
    /* Flag indicating if it crossed the rate RSSI threshold */
    BSTEERING_XING_DIRECTION rate_rssi_xing;
    /* Flag indicating if it crossed the AP steering RSSI threshold */
    BSTEERING_XING_DIRECTION ap_rssi_xing;
};

/**
 * Metadata about a client requested RSSI measurement
 */
struct bs_rssi_measurement_ind {
    /* The MAC address of the client */
    u_int8_t client_addr[IEEE80211_ADDR_LEN];
    /* The measured RSSI */
    u_int8_t rssi;
};

/**
 * Metadata about a Tx rate measurement
 * NOTE: Debug event only, use bs_tx_rate_xing_threshold_ind for
 * rate crossing information.
 */
struct bs_tx_rate_measurement_ind {
    /* The MAC address of the client */
    u_int8_t client_addr[IEEE80211_ADDR_LEN];
    /* The measured Tx rate */
    u_int32_t tx_rate;
};

/**
 * Radio Resource Managmenet report types
 *
 * Note that these types are only used between user space and driver, and
 * not in sync with the OTA types defined in 802.11k spec.
 */
typedef enum {
    /* Indication of a beacon report. */
    BSTEERING_RRM_TYPE_BCNRPT,

    BSTEERING_RRM_TYPE_INVALID
} BSTEERING_RRM_TYPE;

/**
 * Number of RRM beacon reports in a single OTA message can be conveyed in
 * in single event up to user space. Multiple events will be sent if more
 * than this number of reports is included in a single OTA message.
 */
#define IEEE80211_BSTEERING_RRM_NUM_BCNRPT_MAX 4

/**
 * Metadata and report contents about a Radio Resource Measurement report
 */
struct bs_rrm_report_ind {
    /* The type of the rrm event: One of BSTEERING_RRM_TYPE.*/
    u_int32_t rrm_type;
    /* The token corresponding to the measurement request.*/
    u_int8_t dialog_token;
    /* MAC address of the reporter station.*/
    u_int8_t macaddr[IEEE80211_ADDR_LEN];
    /* The result bitmap, as defined in IEEE80211_RRM_MEASRPT_MODE.*/
    u_int8_t measrpt_mode;
    /* The report data. Which member is valid is based on the
       rrm_type field.*/
    union {
        ieee80211_bcnrpt_t bcnrpt[IEEE80211_BSTEERING_RRM_NUM_BCNRPT_MAX];
    } data;
};

/**
 * Wireless Network Management (WNM) report types
 */
typedef enum {
    /* Indication of reception of a BSS Transition Management response frame */
    BSTEERING_WNM_TYPE_BSTM_RESPONSE,

    BSTEERING_WNM_TYPE_INVALID
} BSTEERING_WNM_TYPE;

/* BSS Transition Management Response information that can be returned via netlink message */
struct bs_wnm_bstm_resp {
    /* status of the response to the request frame */
    u_int8_t status;
    /* number of minutes that the STA requests the BSS to delay termination */
    u_int8_t termination_delay;
    /* BSSID of the BSS that the STA transitions to */
    u_int8_t target_bssid[IEEE80211_ADDR_LEN];
} ;

/**
 * Metadata and report contents about a Wireless Network
 * Management event
 */
struct bs_wnm_event_ind {
    /* The type of the wnm event: One of BSTEERING_WNM_TYPE.*/
    u_int32_t wnm_type;
    /* The token corresponding to the message.*/
    u_int8_t dialog_token;
    /* MAC address of the sending station.*/
    u_int8_t macaddr[IEEE80211_ADDR_LEN];
    /* The event data. Which member is valid is based on the
       wnm_type field.*/
    union {
        struct bs_wnm_bstm_resp bstm_resp;
    } data;
};

/**
 * Metadata about a client Tx rate threshold crossing event.
 */
struct bs_tx_rate_xing_threshold_ind {
    /* The MAC address of the client */
    u_int8_t client_addr[IEEE80211_ADDR_LEN];
    /* The Tx rate (in Kbps) */
    u_int32_t tx_rate;
    /* Flag indicating crossing direction */
    BSTEERING_XING_DIRECTION xing;
};

/**
 * Metadata about Tx power change on a VAP
 */
struct bs_tx_power_change_ind {
    /* The new Tx power */
    u_int16_t tx_power;
};

/**
 * STA stats per peer
 */
struct bs_sta_stats_per_peer {
    /* The MAC address of the client */
    u_int8_t client_addr[IEEE80211_ADDR_LEN];
    /* Uplink RSSI */
    u_int8_t rssi;
    /* PER */
    u_int8_t per;
    /* The Tx byte count */
    u_int64_t tx_byte_count;
    /* The Rx byte count */
    u_int64_t rx_byte_count;
    /* The Tx packet count */
    u_int32_t tx_packet_count;
    /* The Rx packet count */
    u_int32_t rx_packet_count;
    /* The last Tx rate (in Kbps) */
    u_int32_t tx_rate;
};

/**
 * Metadata for STA stats
 */
struct bs_sta_stats_ind {
    /* Number of peers for which stats are provided */
    u_int8_t peer_count;
    /* Stats per peer */
    struct bs_sta_stats_per_peer peer_stats[BSTEERING_MAX_PEERS_PER_EVENT];
};

/**
 * Metadate for STA SM Power Save mode update
 */
struct bs_node_smps_update_ind {
    /* The MAC address of the client */
    u_int8_t client_addr[IEEE80211_ADDR_LEN];
    /* Whether the client is operating in Static SMPS mode */
    u_int8_t is_static;
};

/**
 * Metadata for STA OP_MODE update
 */
struct bs_node_opmode_update_ind {
    /* The MAC address of the client */
    u_int8_t client_addr[IEEE80211_ADDR_LEN];
    /* Data rate related information supported by this client */
    ieee80211_bsteering_datarate_info_t datarate_info;
};

/**
 * Common event structure for all Netlink indications to userspace.
 */
typedef struct ath_netlink_bsteering_event {
    /* The type of the event: One of ATH_BSTEERING_EVENT.*/
    u_int32_t type;
    /* The OS-specific index of the VAP on which the event occurred.*/
    u_int32_t sys_index;
    /* The data for the event. Which member is valid is based on the
       type field.*/
    union {
        struct bs_probe_req_ind bs_probe;
        struct bs_node_associated_ind bs_node_associated;
        struct bs_activity_change_ind bs_activity_change;
        struct bs_auth_reject_ind bs_auth;
        struct bs_chan_utilization_ind bs_chan_util;
        struct bs_rssi_xing_threshold_ind bs_rssi_xing;
        struct bs_rssi_measurement_ind bs_rssi_measurement;
        struct bs_rrm_report_ind rrm_report;
        struct bs_wnm_event_ind wnm_event;
        struct bs_tx_rate_xing_threshold_ind bs_tx_rate_xing;
        struct bs_tx_rate_measurement_ind bs_tx_rate_measurement;
        struct bs_tx_power_change_ind bs_tx_power_change;
        struct bs_sta_stats_ind bs_sta_stats;
        struct bs_node_smps_update_ind smps_update;
        struct bs_node_opmode_update_ind opmode_update;
    } data;
} ath_netlink_bsteering_event_t;

/**
 * Parameters that can be configured by userspace to control the band
 * steering events.
 */
typedef struct ieee80211_bsteering_param_t {
    /* Amount of time a client has to be idle under normal (no overload)
       conditions before it becomes a candidate for steering.*/
    u_int32_t inactivity_timeout_normal;
    /*  Amount of time a client has to be idle under overload conditions
        before it becomes a candidate for steering.*/
    u_int32_t inactivity_timeout_overload;
    /* Frequency (in seconds) at which the client inactivity staus should
       be checked. */
    u_int32_t inactivity_check_period;
    /* Frequency (in seconds) at which the medium utilization should be
       measured. */
    u_int32_t utilization_sample_period;
    /* The number of samples over which the medium utilization should be
       averaged before being reported.*/
    u_int32_t utilization_average_num_samples;
    /* Two RSSI values for which to generate threshold crossing events for
       an idle client. Such events are generated when the thresholds are
       crossed in either direction.*/
    u_int32_t inactive_rssi_xing_high_threshold;
    u_int32_t inactive_rssi_xing_low_threshold;
    /* The RSSI value for which to generate threshold crossing events for
        both active and idle clients. This value should generally be less
        than inactive_rssi_xing_low_threshold.*/
    u_int32_t low_rssi_crossing_threshold;
    /* The lower-bound Tx rate value (Kbps) for which to generate threshold crossing events
       if the Tx rate for a client decreases below this value.*/
    u_int32_t low_tx_rate_crossing_threshold;
    /* The upper-bound Tx rate (Kbps) value for which to generate threshold crossing events
       if the Tx rate for a client increases above this value.*/
    u_int32_t high_tx_rate_crossing_threshold;
    /* The RSSI value for which to generate threshold crossing events for
        active clients. Used in conjunction with the rate crossing events
        to determine if STAs should be downgraded. */
    u_int32_t low_rate_rssi_crossing_threshold;
    /* The RSSI value for which to generate threshold crossing events for
        active clients. Used in conjunction with the rate crossing events
        to determine if STAs should be upgraded. */
    u_int32_t high_rate_rssi_crossing_threshold;
    /* The RSSI value for which to generate threshold crossing events for
       a client. Used to determine if STAs should be steered to another AP. */
    u_int32_t ap_steer_rssi_xing_low_threshold;
    /* If set, enable interference detection */
    u_int8_t interference_detection_enable;
    /* Delay sending probe responses, if 2.4G RSSI of a STA is
     * above this threshold */
    u_int32_t delay_24g_probe_rssi_threshold;
    /* Delay sending probe responses till this time window and probe request
     * count is less than or equal to 'delay_24g_probe_min_req_count' */
    u_int32_t delay_24g_probe_time_window;
    /* Deny sending probe responses for this many times in
     * 'delay_24g_probe_time_window' time window */
    u_int32_t delay_24g_probe_min_req_count;
} ieee80211_bsteering_param_t;

/**
 * Parameters that are used to configure lmac part band steering logic.
 * Currently it contains inactivity related parameters.
 */
typedef struct ieee80211_bsteering_lmac_param_t {
    /* Frequency (in seconds) at which the client inactivity staus should
       be checked. */
    u_int32_t inactivity_check_period;

    /* Number of check periods a client has to be idle under normal (no overload)
       conditions before it becomes a candidate for steering. */
    u_int32_t inactivity_threshold_normal;

    /* Number of check periods a client has to be idle under overload conditions
       before it becomes a candidate for steering. */
    u_int32_t inactivity_threshold_overload;
} ieee80211_bsteering_lmac_param_t;

/**
 * Parameters that must be specified to trigger an RSSI measurement by
 * sending QoS Null Data Packets and examining the RSSI from the ACK.
 */
typedef struct ieee80211_bsteering_rssi_req_t {
    /* The address of the client to measure.*/
    u_int8_t sender_addr[IEEE80211_ADDR_LEN];
    /* The number of consecutive measurements to make. This must be
       at least 1.*/
    u_int16_t num_measurements;
} ieee80211_bsteering_rssi_req_t;

/**
 * Parameters that can be configured by userspace to enable logging of
 * intermediate results via events to userspace.
 */
typedef struct ieee80211_bsteering_dbg_param_t {
    /* Whether logging of the raw channel utilization data is enabled.*/
    u_int8_t  raw_chan_util_log_enable:1;
    /* Whether logging of the raw RSSI measurement is enabled.*/
    u_int8_t  raw_rssi_log_enable:1;
    /* Whether logging of the raw Tx rate measurement is enabled.*/
    u_int8_t  raw_tx_rate_log_enable:1;
} ieee80211_bsteering_dbg_param_t;

/**
 * Event types that are asynchronously generated by the band steering
 * module.
 */
typedef enum {
    /* Indication of utilization of the channel.*/
    ATH_EVENT_BSTEERING_CHAN_UTIL = 1,
    /* Indication that a probe request was received from a client.*/
    ATH_EVENT_BSTEERING_PROBE_REQ = 2,
    /* Indicated that a STA associated.*/
    ATH_EVENT_BSTEERING_NODE_ASSOCIATED = 3,
    /* Indication that an authentication frame was sent with a failure
        status code.*/
    ATH_EVENT_BSTEERING_TX_AUTH_FAIL = 4,
    /* Indication that a client changes from active to inactive or
       vice versa.*/
    ATH_EVENT_BSTEERING_CLIENT_ACTIVITY_CHANGE = 5,
    /* Indication when the client RSSI crosses above or below the
       configured threshold.*/
    ATH_EVENT_BSTEERING_CLIENT_RSSI_CROSSING = 6,
    /* Indication when a requested RSSI measurement for a specific
       client is available.*/
    ATH_EVENT_BSTEERING_CLIENT_RSSI_MEASUREMENT = 7,
    /* Indication when a 802.11k radio resource management report
       is received from a client.*/
    ATH_EVENT_BSTEERING_RRM_REPORT = 8,
    /* Indication when a 802.11v wireless network management (WNM) message
       is received from a client.*/
    ATH_EVENT_BSTEERING_WNM_EVENT = 9,
    /* Indication when the client Tx rate crosses above or below the
       configured threshold. */
    ATH_EVENT_BSTEERING_CLIENT_TX_RATE_CROSSING = 10,
    /* Indication when a VAP has stopped.
       Note: This is not the same as a VAP being brought down.  This will be seen
       in RE mode when the uplink STA interface disassociates. */
    ATH_EVENT_BSTEERING_VAP_STOP = 11,
    /* Indication when Tx power changes on a VAP. */
    ATH_EVENT_BSTEERING_TX_POWER_CHANGE = 12,
    /* Indication of new STA stats from firmware. */
    ATH_EVENT_BSTEERING_STA_STATS = 13,
    /* Indication of SM Power Save mode update for a client. */
    ATH_EVENT_BSTEERING_SMPS_UPDATE = 14,
    /* Indication of OP_MODE IE received from a client */
    ATH_EVENT_BSTEERING_OPMODE_UPDATE = 15,

    /*  Events generated solely for debugging purposes. These are not
        intended for direct consumption by any algorithm components but are
        here to facilitate logging the raw data.*/
    ATH_EVENT_BSTEERING_DBG_CHAN_UTIL = 32,
    /* Raw RSSI measurement event used to facilitate logging.*/
    ATH_EVENT_BSTEERING_DBG_RSSI = 33,
    /* Raw Tx rate measurement event used to facilitate logging.*/
    ATH_EVENT_BSTEERING_DBG_TX_RATE = 34,
    /* Indication that an authentication is allowed due to Auth Allow flag
       set.*/
    ATH_EVENT_BSTEERING_DBG_TX_AUTH_ALLOW = 35,
} ATH_BSTEERING_EVENT;

typedef struct ieee80211_bsteering_probe_resp_wh_entry {
    u_int32_t prb_resp_wh_count;
    unsigned long initial_prb_req_jiffies;
    u_int8_t mac_addr[IEEE80211_ADDR_LEN];
    u_int8_t valid;
} ieee80211_bsteering_probe_resp_wh_entry_t;

typedef struct ieee80211_bsteering_probe_resp_allow_entry {
    unsigned long create_time_jiffies;
    u_int8_t mac_addr[IEEE80211_ADDR_LEN];
    u_int8_t valid;
} ieee80211_bsteering_probe_resp_allow_entry_t;

#undef IEEE80211_ADDR_LEN
#endif /* _ATH_BAND_STEERING_API__ */
