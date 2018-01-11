/*
 * @File: ieee1905_vendor.h
 *
 * @Abstract: IEEE 1905.1 vendor specific header file.
 *
 * @Notes:
 *
 * Copyright (c) 2011 Qualcomm Atheros, Inc.
 * All rights reserved.
 *
 */

#ifndef ieee1905_vendor__h /*once only*/
#define ieee1905_vendor__h

#include "ieee1905_vendor_consts.h"

#define IEEE1905_QCA_OUI        "\x00\x03\x7f"

/*
 * QCA IEEE1905.1 Vendor Specific TLV
 */
typedef enum ieee1905QCAVendorSpecificType_e
{
    IEEE1905_QCA_TYPE_NULL,                 /* Null message. Used for PLC packet spoofing */
    IEEE1905_QCA_TYPE_INTERFACE_BITMAP,     /* Device's interface bitmap */
    IEEE1905_QCA_TYPE_TX_INTERFACE,         /* The interface used to transmit this message */
    IEEE1905_QCA_TYPE_DEVICE_FLAGS,         /* Device flags: HR, HC, can be further extended */
    IEEE1905_QCA_TYPE_BRIDGED_INTERFACES,   /* Bridged interfaces */
    IEEE1905_QCA_TYPE_EXT_LINK_METRICS,     /* Extended link metrics data */
    IEEE1905_QCA_TYPE_LOCAL_FLOWS,          /* List of local flows with rate above threshold */
    IEEE1905_QCA_TYPE_LOCAL_FLOW_RESPONSE,  /* Local flow response */
    IEEE1905_QCA_TYPE_RESPOND_NOW,          /* Ask remote devices to respond, used when hyd restarts/system reboots */
    IEEE1905_QCA_TYPE_WLAN_STA_ASSOC,       /* WLAN Station association */
    IEEE1905_QCA_TYPE_REMOTE_INTERFACE_DOWN,/* Remote interface down acceleration */
    IEEE1905_QCA_TYPE_IPV4_ADDRESS,         /* IPv4 address of the device */
    IEEE1905_QCA_TYPE_WLAN_INFO,            /* Wlan info */
    IEEE1905_QCA_TYPE_ASSOCIATED_STATIONS,  /* List of associated STAs on an AP */

    IEEE1905_QCA_TYPE_SYSTEM_INFO_REQ = 64,      /* Request the system parameters for steering */
    IEEE1905_QCA_TYPE_SYSTEM_INFO_RSP,           /* Overall system parameters */
    IEEE1905_QCA_TYPE_CSBC_CONFIG_PARAMS,        /* Client steering behavior classification
                                                    configuration */
    IEEE1905_QCA_TYPE_AVG_UTIL_REQ,              /* Request a local utilization report */
    IEEE1905_QCA_TYPE_AVG_UTIL_REPORT,           /* Local or aggregate utilization report */
    IEEE1905_QCA_TYPE_LOAD_BALANCING_ALLOWED,    /* Node is allowed to steer */
    IEEE1905_QCA_TYPE_LOAD_BALANCING_COMPLETE,   /* All steering has been attemped */
    IEEE1905_QCA_TYPE_STA_BAND_CAPABILITY,       /* Update to which bands a STA can use */
    IEEE1905_QCA_TYPE_STADB_DUMP_REQ,            /* Request dump of all STAs */
    IEEE1905_QCA_TYPE_STADB_DUMP_RSP,            /* List of all known STAs */
    IEEE1905_QCA_TYPE_STADB_AGING,               /* One or more STAs aged out */
    IEEE1905_QCA_TYPE_STA_INFO_REQ,              /* Request complete info for a STA */
    IEEE1905_QCA_TYPE_STA_INFO_RSP,              /* Share the complete info for a STA */
    IEEE1905_QCA_TYPE_STA_CSBC_STATE,            /* Client steering behavior classification
                                                    state for a single STA */
    IEEE1905_QCA_TYPE_PREPARE_FOR_STEERING_REQ,  /* Request blacklist installation */
    IEEE1905_QCA_TYPE_PREPARE_FOR_STEERING_RSP,  /* Indicate blacklist installation complete */
    IEEE1905_QCA_TYPE_AUTH_REJ_SENT,             /* Auth reject sent by this node */
    IEEE1905_QCA_TYPE_STEERING_ABORT_REQ,        /* Request steering be aborted */
    IEEE1905_QCA_TYPE_STEERING_ABORT_RSP,        /* Acknowledge steering was aborted */
    IEEE1905_QCA_TYPE_STA_POLLUTION_STATE,       /* Which channels are polluted */

    IEEE1905_QCA_TYPE_ATF_SSID_CFG,              /* ATF SSID configuration */
    IEEE1905_QCA_TYPE_ATF_PEER_CFG,              /* ATF PEER configuration */
    IEEE1905_QCA_TYPE_ATF_GROUP_CFG,             /* ATF GROUP configuration */
    IEEE1905_QCA_TYPE_ATF_RADIOPARAM_CFG,        /* ATF Radio params */

    IEEE1905_QCA_TYPE_CFG_ACK ,                  /* Ack to config receive */
    IEEE1905_QCA_TYPE_CFG_APPLY,                 /* Apply config and restart */

    IEEE1905_QCA_TYPE_RESERVED /* Must be the last */

} ieee1905QCAVendorSpecificType_e;

typedef struct ieee1905QCAMessage_t
{
    u_int8_t oui[ IEEE1905_OUI_LENGTH ];
    u_int8_t type;

    u_int8_t content[ 0 ];

} __attribute__((packed)) ieee1905QCAMessage_t;

typedef struct ieee1905QCAInterfaceBitmaps_t
{
    u_int32_t interfaceConnected;                           /* Interface connection bitmap */
    u_int8_t  interfaceTypes[ IEEE1905_QCA_VENDOR_MAX_INTERFACE ]; /* Interface types */

} __attribute__((packed)) ieee1905QCAInterfaceBitmaps_t;


typedef struct ieee1905QCABridgedInterfaces_t
{
    u_int8_t numBridgedDAs;     /* Number of addresses in this message */
    u_int8_t updated;           /* Marks if fdb has been updated or not */

    u_int8_t bridgedDA[ 0 ];  /* Place holder for addresses, size should be 6*numBridgedDAs */

} __attribute__((packed)) ieee1905QCABridgedInterfaces_t;

typedef struct ieee1905QCAExtLinkMetrics_t
{
    struct ether_addr addr;

    u_int32_t TCPFullLinkCapacity;
    u_int32_t UDPFullLinkCapacity;
    u_int32_t TCPAvailableLinkCapacity;
    u_int32_t UDPAvailableLinkCapacity;

    u_int32_t reserved[ 4 ];                /* For future use, I have a feeling we will need it */

} __attribute__((packed)) ieee1905QCAExtLinkMetrics_t;

typedef struct ieee1905QCALocalFlowsInfo_t
{
    u_int8_t hash;
    u_int8_t ifaceType;
    struct ether_addr sa;
    struct ether_addr da;
    u_int32_t rate;

} __attribute__((packed)) ieee1905QCALocalFlowsInfo_t;

enum
{
    IEEE1905_QCA_LOCAL_FLOW_ACTION_CLEAR,
    IEEE1905_QCA_LOCAL_FLOW_ACTION_SET,

    IEEE1905_QCA_LOCAL_FLOW_ACTION_RESERVED
};

typedef struct ieee1905QCALocalFlowReponse_t
{
    u_int8_t hash;
    u_int8_t action;
    struct ether_addr sa;
    struct ether_addr da;

} __attribute__((packed)) ieee1905QCALocalFlowReponse_t;

/**
 * @brief Notification that a WLAN STA has associated on an 
 *        interface
 */
typedef struct ieee1905QCAWLANSTAAssoc_t
{
    /// STA that associated
    struct ether_addr staAddr;     

    /// MAC address of interface it associated on
    struct ether_addr ifaceAddr;
} __attribute__((packed)) ieee1905QCAWLANSTAAssoc_t;

/*
 * @brief PHY capabilities on the WLAN interface, to be sent
 *        in IEEE1905_QCA_TYPE_WLAN_INFO TLV
 */
typedef struct ieee1905QCAWLANInfoPHYCap_t {
    /* Maximum bandwidth the client supports, valid values are enumerated
     * in enum ieee80211_cwm_width in _ieee80211.h. */
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
} __attribute__((packed)) ieee1905QCAWLANInfoPHYCap_t;

/**
 * @brief Extra WiFi info sent per interface (currently just the
 *        primary channel for each interface).
 */
typedef struct ieee1905QCAWLANInfoPerIntf_t
{
    /// The interface layer MAC address
    struct ether_addr interfaceMAC;

    /// Primary channel for that interface.
    u_int8_t primaryChannel;

    /// Flag indicating if this entry contains valid PHY capabilities
    u_int8_t validPHY;

    /// PHY capabilities on this WLAN interface
    ieee1905QCAWLANInfoPHYCap_t phyCapabilities[ 0 ];
} __attribute__((packed)) ieee1905QCAWLANInfoPerIntf_t;

/**
 * @brief Vendor specific TLV conveying extra WiFi info
 *        (currently just the primary channel for each
 *        interface).
 */
typedef struct ieee1905QCAWLANInfo_t
{
    /// Number of WiFi interfaces
    u_int8_t numWlanIntf;

    /// Information per interface.
    ieee1905QCAWLANInfoPerIntf_t intfInfo[ 0 ];
} __attribute__((packed)) ieee1905QCAWLANInfo_t;

/**
 * @brief Vendor specific TLV conveying the list of associated STA MAC
 *        addresses for a single AP interface on the sending device.
 */
typedef struct ieee1905QCAAssociatedStations_t
{
    /// The interface layer MAC address of the AP interface to which all
    /// of the below stations are associated.
    struct ether_addr interfaceMAC;

    /// List of associated stations on this AP interface.
    struct ether_addr stationMACs[ 0 ];
} __attribute__((packed)) ieee1905QCAAssociatedStations_t;

#define IEEE1905_QCA_TLV_MIN_LEN    IEEE1905_TLV_LEN( sizeof(ieee1905QCAMessage_t) )

/* For versioned QCA TLV, add 1 byte for the version number */
#define IEEE1905_VERSION_QCA_TLV_MIN_LEN IEEE1905_TLV_LEN( sizeof(ieee1905QCAMessage_t) + sizeof(u_int8_t) )

/*
 * API
 */
#define ieee1905QCAIsQCAOUI( _oui ) \
    ( memcmp( _oui, IEEE1905_QCA_OUI, IEEE1905_OUI_LENGTH ) == 0 )

#define ieee1905QCAOUIAndTypeSet( _qcaMessage, _type, _total ) \
    do{ memcpy( (_qcaMessage)->oui, IEEE1905_QCA_OUI, IEEE1905_OUI_LENGTH ); (_qcaMessage)->type = _type; _total += IEEE1905_OUI_LENGTH + sizeof( u_int8_t ); } while(0)

#define ieee1905QCATypeGet( _qcaMessage ) \
    ( (_qcaMessage)->type )

#define ieee1905QCATypeSet( _qcaMessage, _type ) \
    ( (_qcaMessage)->type = _type )

#define ieee1905QCALenGet( _TLV ) \
    ( htons( (_TLV)->length ) - IEEE1905_OUI_LENGTH - sizeof( u_int8_t ) )

#define ieee1905QCAValGet( _qcaMessage ) \
    ( (_qcaMessage)->content )

#define ieee1905QCAValSet( _qcaMessage, _val, _len, _total ) \
    do{ memcpy((_qcaMessage)->content, (_val), (_len) ); _total += (_len ); } while(0)

#endif /* ieee1905_vendor__h */
