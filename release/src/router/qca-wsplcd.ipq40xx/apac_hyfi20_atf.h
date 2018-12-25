/*
 * @@-COPYRIGHT-START-@@
 *
 * Copyright (c) 2016 Qualcomm Atheros, Inc.
 * All Rights Reserved.
 * Qualcomm Atheros Confidential and Proprietary.
 *
 * @@-COPYRIGHT-END-@@
 */

#include "wsplcd.h"
#include <linux/wireless.h>
#include <ieee80211_external.h>
#include "ieee1905_defs.h"
#include "ieee1905_vendor.h"

#define ATF_MAX_PEERS           8
#define ATF_MAX_VAPS            8
#define ATF_MAX_REPEATERS       8
#define ATF_IDENT_MAX_LEN       8
#define ATF_CMD_MAX_LEN         16
#define ATF_SUBCMD_MAX_LEN      16
#define ATF_INTERFACE_MAX_LEN   8
#define ATF_MAX_GROUPS          2
#define ATF_MAX_SSID_GROUP      4
#define ATF_NUM_WIFI_INTERFACE  3
#define ATF_IDENT_STR "ATF.RE\0"

#define streq(a,b)  ((strlen(a) == strlen(b)) && (strncasecmp(a,b,sizeof(b)-1) == 0))

#define ATF_ETH_ADDR_ALL "\xFF\xFF\xFF\xFF\xFF\xFF"

/* ATF Major versions supported */
typedef enum atfmsgMajorVersion_e {
    atfmsgMajorVersion1 = 1
} atfmsgMajorVersion_e;

/* ATF Minor versions supported */
typedef enum atfmsgMinorVersion_e {
    atfmsgMinorVersion0 = 0,
} atfmsgMinorVersion_e;

typedef enum {
    APAC_ATF_GROUP_ENABLE = 1,
    APAC_ATF_GROUP_DISABLE = 2,
} apacHyfi20atfGroupStatus;

typedef enum {
    APAC_ATF_SCHED_POLICY_STRICT = 1,
    APAC_ATF_SCHED_POLICY_FAIR,
    APAC_ATF_OBSS_ENABLE,
    APAC_ATF_OBSS_DISABLE,
    APAC_ATF_GROUP_SCHED_STRICT,
    APAC_ATF_GROUP_SCHED_FAIR,
} apacHyfi20atfschedparams;

#define ATFMSG_VERSION_MAJOR_SHIFT 4
#define ATFMSG_VERSION_MINOR_SHIFT 0
#define ATFMSG_VERSION_COMPONENT_MASK 0xFF

// Pack the major/minor version numbers into a single value.
#define atfmsgPackVersionNum(major, minor) \
    (((major & ATFMSG_VERSION_COMPONENT_MASK) \
        << ATFMSG_VERSION_MAJOR_SHIFT) | \
     ((minor & ATFMSG_VERSION_COMPONENT_MASK) \
        << ATFMSG_VERSION_MINOR_SHIFT))

// Extract the major and minor version numbers from the packed value.
#define atfmsgExtractMajorVersionNum(version) \
    ((version >> ATFMSG_VERSION_MAJOR_SHIFT) \
        & ATFMSG_VERSION_COMPONENT_MASK)
#define atfmsgExtractMinorVersionNum(version) \
    (version & ATFMSG_VERSION_COMPONENT_MASK)

/* ATF configurations as read from config file */
typedef struct _atf_config {
    char cmd[ATF_CMD_MAX_LEN];
    char subcmd[ATF_SUBCMD_MAX_LEN];
    char ident[ATF_IDENT_MAX_LEN];
    char cmd_index[ATF_IDENT_MAX_LEN];
    char *value;
}ATF_CONFIG;

/* PER Repeater ATF configurations */
typedef struct apac_atf_repeater_config {
    u8 remac[ETH_ALEN];
    char identifier[ATF_IDENT_MAX_LEN]; //10
    u16 mid;    // Message identifier
    u32 retrycnt; // Retry count
    struct peer_config {
        char cmd[ATF_CMD_MAX_LEN];
        char interface[ATF_INTERFACE_MAX_LEN];
        u8 sta_mac[ETH_ALEN];
        int val; //34 * 8 = 256
    }__attribute__((packed)) peer[ATF_MAX_PEERS];
    struct ssid_config {
        char cmd[ATF_CMD_MAX_LEN];
        char interface[ATF_INTERFACE_MAX_LEN];
        char ssid[IEEE80211_NWID_LEN + 1];
        int val; // 61 * 8 = 488
    }__attribute__((packed)) vap[ATF_MAX_VAPS];
    struct group_config {
        char cmd[ATF_CMD_MAX_LEN];
        char interface[ATF_INTERFACE_MAX_LEN];
        char grpname[ IEEE80211_NWID_LEN + 1 ]; //group name
        char grp_ssid[ATF_MAX_SSID_GROUP][ IEEE80211_NWID_LEN + 1 ]; // List of SSIDs in the group
        u32 grp_num_ssid; //Number of ssids added in this group
        int val;
        int grpenable;
    }__attribute__((packed)) group[ATF_MAX_GROUPS];
    struct radio_config {
        char interface[ATF_INTERFACE_MAX_LEN];
        u8  sched_policy;
        u8  obss_enable;
        u8  group_sched_policy;
    }__attribute__((packed)) radioparams[ATF_NUM_WIFI_INTERFACE];
    int vap_num_cfg;
    int peer_num_cfg;
    int group_num_cfg;
    int radio_num_cfg;
}__attribute__((packed)) ATF_REP_CONFIG;

/* ATF SSID Config command */
struct addssid_val{
    uint16_t    id_type;
    uint8_t     ssid[IEEE80211_NWID_LEN+1];
    uint32_t    value;
};

/* ATF Peer Config command */
struct addsta_val{
    uint16_t    id_type;
    uint8_t     sta_mac[IEEE80211_ADDR_LEN];
    uint32_t    value;
};

struct addgroup_val{
    uint16_t    id_type;
    u_int8_t    name[32];
    uint8_t     ssid[IEEE80211_NWID_LEN+1];
    uint32_t    value;
};

/* Parse ATF config file */
int apac_atf_config_parse_file(void *pData, const char *fname);

/* Seperate out ATF command params */
int apac_atf_config_line_lex(char *buf, ATF_CONFIG *atf_cfg);

/* Read an ATF param */
int apac_atf_config_line_getparam(char *buf, char delim, char *out);

/* Fill ATF config struct */
int apac_atf_config_apply_line(void* pData, ATF_CONFIG *atfcfg);

/* Update RE MAC in Per Repeater ATF config struct */
int apac_atf_re_mac_update(void* pData, ATF_CONFIG *atfcfg, int index );

/* Update SSID configuration in Per Repeater ATF config struct */
int apac_atf_ssid_config_update(void* pData, ATF_CONFIG *atfcfg, int index );

/* Update STA configuration in Per Repeater ATF config struct */
int apac_atf_sta_config_update( void* pData, ATF_CONFIG *atfcfg, int index );

/* Update SSID GROUP configuration in Per Repeater ATF config struct */
int apac_atf_group_config_update( void* pData, ATF_CONFIG *atfcfg, int index );

/* Dump ATF configurations Read */
void apacHyfi20AtfConfigDump(void *pData);

/* Send ATF configurations */
int apacHyfi20SendAtfConfig(void *pData, int rep_index);

/* Receive ATF configurations */
int apacHyfi20ReceiveAtfConfig(u8 *msg, u32 msgLen);

/* Extract ATF TLV */
const ieee1905QCAMessage_t *atfmsgExtractAtfTLV( const ieee1905TLV_t *tlv);

/* Configure ATF */
int apacHyfi20ConfigureAtf(ATF_REP_CONFIG *apAtfConfig);

/* Issue command to add SSID based ATF */
int apacHyfi20ConfigAtf_addssid(const char *ifname, char *ssid, u_int32_t val);

/* Issue command to delete SSID based ATF */
int apacHyfi20ConfigAtf_delssid(const char *ifname, char *ssid);

/* Issue command to add Peer based ATF */
int apacHyfi20ConfigAtf_addsta(const char *ifname, u8 *macaddr, u_int32_t val);

/* Issue command to del Peer based ATF */
int apacHyfi20ConfigAtf_delsta(const char *ifname, u8 *macaddr);

/* Issue command to add ATF Group */
int apacHyfi20ConfigAtf_addgroup( char *ifname, char *grpname, char *grpssid );

/* Issue command to delete ATF Group */
int apacHyfi20ConfigAtf_delgroup(const char *ifname, char *grp_name);

/* Issue command to configure airtime to an ATF Group */
int apacHyfi20ConfigAtf_configgroup(const char *ifname, char *grpname, u_int32_t val);

/* Issue command to enabled ATF */
int apacHyfi20atfCommit( const char *iface, int val);

/* Issue command to Enable/Disable ATF SSID grouping */
int apacHyfi20atfGroupEnable( const char *iface, int val);

/* Issue command to configure ATF radio params */
int apacHyfi20ConfigAtf_radioparams( char *iface, u_int32_t param, u_int32_t val);
