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
#include "eloop.h"
#include <sys/socket.h>
#include <sys/file.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <linux/wireless.h>
#include <ieee80211_external.h>

#include "apac_priv.h"
#include "ieee1905_vendor.h"

const char *print_macaddr(const uint8_t mac[6]) {
    static char buf[32];

    snprintf(buf, sizeof(buf), "%02x:%02x:%02x:%02x:%02x:%02x",
            mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    return buf;
}

int apac_atf_config_line_getparam(char *buf, char delim, char *out) {
    int len;
    char *newpos;

    newpos = strchr(buf, delim);
    if(newpos == NULL) {
        return -1;
    }
    len = (newpos - buf);
    os_memcpy(out, buf, len);
    out[len] = 0;
    return len;
}

int apac_atf_config_line_lex(char *buf, ATF_CONFIG *atf_cfg) {
    char *pos;
    int len;

    /* Trim leading whitespace, including comment lines */
    for (pos = buf; ; pos++) {
       if (*pos == 0) {
           return 1;
       }
       if (*pos == '\n' || *pos == '\r' || *pos == '#') {
          *pos = 0;
          return 1;
       }
       buf = pos;
       if (isgraph(*pos)) break;
    }
    while (isgraph(*pos) && *pos != '=') pos++;
    if (*pos == '=') {
        *pos++ = 0;     /* null terminate the tag */
        atf_cfg->value = pos;
    } else {
        return -1;
    }

    /* Trim trailing whitepace.paces inside of a value are allowed,
     * as are other arbitrary non-white text, thus no comments on
     * end of lines.
     */
    for (pos += strlen(pos); --pos >= atf_cfg->value; ) {
        if (isgraph(*pos)) break;
        *pos = 0;
    }

    /* get RE identifier */
    pos = buf;
    len = apac_atf_config_line_getparam(pos, '_', atf_cfg->ident);
    if ((len == -1) || strncmp(atf_cfg->ident, ATF_IDENT_STR, strlen(ATF_IDENT_STR))) {
        return 1;
    }

    /* get Command */
    pos += len + 1;
    len = apac_atf_config_line_getparam(pos, '_', atf_cfg->cmd);
    if (len == -1) {
        dprintf(MSG_ERROR, "Command not found\n");
        return -1;
    }

    /* get Sub-command */
    pos += len + 1;
    len = apac_atf_config_line_getparam(pos, '_', atf_cfg->subcmd);
    if (len == -1) {
        return 0;
    }

    /* Get sub-Command index */
    pos += len + 1;
    len = apac_atf_config_line_getparam(pos, '\0', atf_cfg->cmd_index);
    if(len == -1) {
        dprintf(MSG_ERROR, "Sub-command not found\n");
        return -1;
    }

    return 0;
}

int apac_atf_re_mac_update(void *ptrData, ATF_CONFIG *atfcfg, int index ) {
    apacHyfi20Data_t* pData = (apacHyfi20Data_t*)ptrData;
    apacHyfi20Config_t *pConfig = &pData->config;
    int num_repeaters = pConfig->apac_atf_num_repeaters;

    hwaddr_aton(atfcfg->value, pConfig->atfConf[num_repeaters].remac);
    strncpy(pConfig->atfConf[num_repeaters].identifier, atfcfg->ident, strlen(atfcfg->ident));

    pConfig->apac_atf_num_repeaters++;
    dprintf(MSG_MSGDUMP, "%s num_repeater : %d \n", __func__, pConfig->apac_atf_num_repeaters);
    return 0;
}

int apac_atf_radio_params_update(void* ptrData, ATF_CONFIG *atfcfg, int index ) {
    apacHyfi20Data_t* pData = (apacHyfi20Data_t*)ptrData;
    apacHyfi20Config_t *pConfig = &pData->config;
    int num_repeaters = pConfig->apac_atf_num_repeaters;
    int rep_index = 0;
    int cmd_index = 0;

    if(index == ATF_MAX_REPEATERS) {
        rep_index = (num_repeaters - 1);
    } else {
        rep_index = index;
    }

    cmd_index = (atoi(atfcfg->cmd_index) - 1);
    if(cmd_index >= ATF_NUM_WIFI_INTERFACE)
    {
        dprintf(MSG_ERROR, "Cannot have mode than %d radio entries\n", APAC_NUM_WIFI_FREQ);
        return 1;
    }

    dprintf(MSG_MSGDUMP, "%s index : %d subcmd : %s \n", __func__, cmd_index, atfcfg->subcmd);
    if(streq(atfcfg->subcmd, "name")) {
        if(strlen(atfcfg->value) <= ATF_INTERFACE_MAX_LEN ) {
            strncpy(pConfig->atfConf[rep_index].radioparams[cmd_index].interface, atfcfg->value, strlen(atfcfg->value));
        } else {
            dprintf(MSG_ERROR, "%s Radio name cannot be more than %d\n",__func__, ATF_INTERFACE_MAX_LEN);
            return 1;
        }
    } else if(streq(atfcfg->subcmd, "sched")) {
        if(streq(atfcfg->value, "STRICT")) {
            pConfig->atfConf[rep_index].radioparams[cmd_index].sched_policy = APAC_ATF_SCHED_POLICY_STRICT;
        } else if(streq(atfcfg->value, "FAIR")) {
            pConfig->atfConf[rep_index].radioparams[cmd_index].sched_policy = APAC_ATF_SCHED_POLICY_FAIR;
        } else {
            dprintf(MSG_ERROR, "Unknown ATF scheduling policy %s\n", atfcfg->value);
            return 1;
        }
    } else if(streq(atfcfg->subcmd, "obss")) {
        if(atoi(atfcfg->value)) {
            pConfig->atfConf[rep_index].radioparams[cmd_index].obss_enable = APAC_ATF_OBSS_ENABLE;
        } else {
            pConfig->atfConf[rep_index].radioparams[cmd_index].obss_enable = APAC_ATF_OBSS_DISABLE;
        }
    } else if(streq(atfcfg->subcmd, "grouppolicy")) {
        if(streq(atfcfg->value, "STRICT")) {
            pConfig->atfConf[rep_index].radioparams[cmd_index].group_sched_policy = APAC_ATF_GROUP_SCHED_STRICT;
        } else if(streq(atfcfg->value, "FAIR")) {
            pConfig->atfConf[rep_index].radioparams[cmd_index].group_sched_policy = APAC_ATF_GROUP_SCHED_FAIR;
        } else {
            dprintf(MSG_ERROR, "Unknown Inter group scheduling policy %s\n", atfcfg->value);
            return 1;
        }
    } else {
        dprintf(MSG_ERROR, "Invalid Subcommand %s\n", atfcfg->subcmd);
        return 1;
    }

    if( ( pConfig->atfConf[rep_index].radio_num_cfg == 0 ) ||
        ( pConfig->atfConf[rep_index].radio_num_cfg - 1) < cmd_index) {
        pConfig->atfConf[rep_index].radio_num_cfg++;
    }
    dprintf(MSG_MSGDUMP, "%s radio_num : %d \n", __func__, pConfig->atfConf[rep_index].radio_num_cfg);

    return 0;
}

int apac_atf_ssid_config_update(void* ptrData, ATF_CONFIG *atfcfg, int index ) {
    apacHyfi20Data_t* pData = (apacHyfi20Data_t*)ptrData;
    int rep_index = 0;
    int cmd_index = 0;
    apacHyfi20Config_t *pConfig = &pData->config;
    int num_repeaters = pConfig->apac_atf_num_repeaters;

    if(index == ATF_MAX_REPEATERS) {
        rep_index = (num_repeaters - 1);
    } else {
        rep_index = index;
    }

    cmd_index = (atoi(atfcfg->cmd_index) - 1);
    if(cmd_index >= ATF_MAX_VAPS)
    {
        dprintf(MSG_ERROR, "Cannot add more than %d ATF SSID configurations\n", ATF_MAX_VAPS);
        return 1;
    }

    dprintf(MSG_MSGDUMP, "%s index : %d subcmd : %s \n", __func__, cmd_index, atfcfg->subcmd);
    if(streq(atfcfg->subcmd, "entry")) {
        if(strlen(atfcfg->value) <= IEEE80211_NWID_LEN ) {
            strncpy(pConfig->atfConf[rep_index].vap[cmd_index].ssid, atfcfg->value, strlen(atfcfg->value));
        } else {
            dprintf(MSG_ERROR, "%s ssidlen cannot be more than %d\n",__func__, IEEE80211_NWID_LEN);
            return 1;
        }
    } else if(streq(atfcfg->subcmd, "wifidev")) {
        if(strlen(atfcfg->value) <= ATF_INTERFACE_MAX_LEN ) {
            strncpy(pConfig->atfConf[rep_index].vap[cmd_index].interface, atfcfg->value, strlen(atfcfg->value));
        } else {
            dprintf(MSG_ERROR, "%s Interface len cannot be more than %d\n",__func__, ATF_INTERFACE_MAX_LEN);
            return 1;
        }
    } else if(streq(atfcfg->subcmd, "cmd")) {
        if(strlen(atfcfg->value) <= ATF_CMD_MAX_LEN ) {
            strncpy(pConfig->atfConf[rep_index].vap[cmd_index].cmd, atfcfg->value, strlen(atfcfg->value));
        } else {
            dprintf(MSG_ERROR, "%s Command len cannot be more than %d\n",__func__, ATF_CMD_MAX_LEN);
            return 1;
        }
    } else if(streq(atfcfg->subcmd, "val")) {
        pConfig->atfConf[rep_index].vap[cmd_index].val = atoi(atfcfg->value);
        pConfig->atfConf[rep_index].vap_num_cfg++;
    }
    dprintf(MSG_MSGDUMP, "%s vap_num : %d \n", __func__, pConfig->atfConf[rep_index].vap_num_cfg);

    return 0;
}

int apac_atf_sta_config_update( void* ptrData, ATF_CONFIG *atfcfg, int index ) {
    apacHyfi20Data_t* pData = (apacHyfi20Data_t*)ptrData;
    int rep_index = 0;
    int cmd_index = 0;
    apacHyfi20Config_t *pConfig = &pData->config;
    int num_repeaters = pConfig->apac_atf_num_repeaters;

    if(index == ATF_MAX_REPEATERS) {
        rep_index = (num_repeaters - 1);
    } else {
        rep_index = index;
    }

    cmd_index = (atoi(atfcfg->cmd_index) - 1);
    if(cmd_index >= ATF_MAX_PEERS)
    {
        dprintf(MSG_ERROR, "Cannot add more than %d ATF Peer configurations\n", ATF_MAX_PEERS);
        return 1;
    }

    dprintf(MSG_MSGDUMP, "%s index : %d subcmd : %s \n", __func__, cmd_index, atfcfg->subcmd);
    if(streq(atfcfg->subcmd, "entry")) {
        hwaddr_aton(atfcfg->value, pConfig->atfConf[rep_index].peer[cmd_index].sta_mac);
    } else if(streq(atfcfg->subcmd, "wifidev")) {
        if(strlen(atfcfg->value) <= ATF_INTERFACE_MAX_LEN ) {
            strncpy(pConfig->atfConf[rep_index].peer[cmd_index].interface, atfcfg->value, strlen(atfcfg->value));
        } else {
            dprintf(MSG_ERROR, "%s Interface len cannot be more than %d\n",__func__, ATF_INTERFACE_MAX_LEN);
            return 1;
        }
    } else if(streq(atfcfg->subcmd, "cmd")) {
        if(strlen(atfcfg->value) <= ATF_CMD_MAX_LEN ) {
            strncpy(pConfig->atfConf[rep_index].peer[cmd_index].cmd, atfcfg->value, strlen(atfcfg->value));
        } else {
            dprintf(MSG_ERROR, "%s Command len cannot be more than %d\n",__func__, ATF_CMD_MAX_LEN );
            return 1;
        }
    } else if(streq(atfcfg->subcmd, "val")) {
        pConfig->atfConf[rep_index].peer[cmd_index].val = atoi(atfcfg->value);
        pConfig->atfConf[rep_index].peer_num_cfg++;
    }
    dprintf(MSG_MSGDUMP, "%s peer_num : %d \n", __func__, pConfig->atfConf[rep_index].peer_num_cfg);
    return 0;
}

int apac_atf_group_config_update(void* ptrData, ATF_CONFIG *atfcfg, int index ) {
    apacHyfi20Data_t* pData = (apacHyfi20Data_t*)ptrData;
    int rep_index = 0;
    int cmd_index = 0;
    int grp_index = 0;
    apacHyfi20Config_t *pConfig = &pData->config;
    int num_repeaters = pConfig->apac_atf_num_repeaters;

    if(index == ATF_MAX_REPEATERS) {
        rep_index = (num_repeaters - 1);
    } else {
        rep_index = index;
    }

    cmd_index = (atoi(atfcfg->cmd_index) - 1);
    if(cmd_index >= ATF_MAX_GROUPS)
    {
        dprintf(MSG_ERROR, "Cannot add more than %d ATF Groups\n", ATF_MAX_GROUPS);
        return 1;
    }

    dprintf(MSG_MSGDUMP, "%s index : %d subcmd : %s \n", __func__, cmd_index, atfcfg->subcmd);
    if(streq(atfcfg->subcmd, "entry")) {
        if(strlen(atfcfg->value) <= IEEE80211_NWID_LEN ) {
            strncpy(pConfig->atfConf[rep_index].group[cmd_index].grpname, atfcfg->value, strlen(atfcfg->value));
        } else {
            dprintf(MSG_ERROR, "%s Group Name cannot be more than %d\n",__func__, IEEE80211_NWID_LEN);
            return 1;
        }
    } else if(streq(atfcfg->subcmd, "wifidev")) {
        if(strlen(atfcfg->value) <= ATF_INTERFACE_MAX_LEN ) {
            strncpy(pConfig->atfConf[rep_index].group[cmd_index].interface, atfcfg->value, strlen(atfcfg->value));
        } else {
            dprintf(MSG_ERROR, "%s Interface len cannot be more than %d\n",__func__, ATF_INTERFACE_MAX_LEN);
            return 1;
        }
    } else if(streq(atfcfg->subcmd, "cmd")) {
        if(strlen(atfcfg->value) <= ATF_CMD_MAX_LEN ) {
            strncpy(pConfig->atfConf[rep_index].group[cmd_index].cmd, atfcfg->value, strlen(atfcfg->value));
        } else {
            dprintf(MSG_ERROR, "%s Command len cannot be more than %d\n",__func__, ATF_CMD_MAX_LEN);
            return 1;
        }
    } else if(streq(atfcfg->subcmd, "ssid")) {
        grp_index = pConfig->atfConf[rep_index].group[cmd_index].grp_num_ssid;
        if( (grp_index < ATF_MAX_SSID_GROUP ) &&
            (strlen(atfcfg->value) <= IEEE80211_NWID_LEN) ) {
            strncpy(pConfig->atfConf[rep_index].group[cmd_index].grp_ssid[grp_index], atfcfg->value, strlen(atfcfg->value));
            pConfig->atfConf[rep_index].group[cmd_index].grp_num_ssid++;
        } else {
            dprintf(MSG_ERROR, "%s Num of SSIDs in group(%d) should be less than %d & ssid len(%d) should be less than %d\n",
                    __func__,grp_index, ATF_MAX_SSID_GROUP, strlen(atfcfg->value),  IEEE80211_NWID_LEN );
            return 1;
        }
    } else if(streq(atfcfg->subcmd, "enable")) {
        if(atoi(atfcfg->value)) {
            pConfig->atfConf[rep_index].group[cmd_index].grpenable = APAC_ATF_GROUP_ENABLE;
        } else {
            pConfig->atfConf[rep_index].group[cmd_index].grpenable = APAC_ATF_GROUP_DISABLE;
        }
    } else if(streq(atfcfg->subcmd, "val")) {
        pConfig->atfConf[rep_index].group[cmd_index].val = atoi(atfcfg->value);
    }
    dprintf(MSG_MSGDUMP, "%s group_num : %d group_num_ssid : %d \n",
            __func__, pConfig->atfConf[rep_index].group_num_cfg,
            pConfig->atfConf[rep_index].group[cmd_index].grp_num_ssid);

    if( ( pConfig->atfConf[rep_index].group_num_cfg == 0 ) ||
        ( pConfig->atfConf[rep_index].group_num_cfg - 1) < cmd_index) {
        pConfig->atfConf[rep_index].group_num_cfg++;
    }
    return 0;
}
int apac_atf_config_apply_line(void* ptrData, ATF_CONFIG *atfcfg) {
    apacHyfi20Data_t* pData = (apacHyfi20Data_t*)ptrData;
    apacHyfi20Config_t *pConfig = &pData->config;
    int index = 0;

    //Search for RE entry (identifier)
    for( index = 0; index < ATF_MAX_REPEATERS; index++) {
        if(atfcfg->ident != NULL) {
            if(streq(atfcfg->ident, pConfig->atfConf[index].identifier)) {
                break;
            }
        }
    }

    //max num repeaters reached. Return error
    if( (index >= ATF_MAX_REPEATERS) && (pConfig->apac_atf_num_repeaters >= ATF_MAX_REPEATERS) ) {
        dprintf(MSG_ERROR, "Cannot add repeater. Max entry limit\n");
        return 1;
    }

    dprintf(MSG_MSGDUMP, "%s cmd : %s \n", __func__, atfcfg->cmd);
    if(streq(atfcfg->cmd, "REmac")) {
        apac_atf_re_mac_update(pData, atfcfg, index);
    } else if(streq(atfcfg->cmd, "ssid")) {
        apac_atf_ssid_config_update(pData, atfcfg, index);
    } else if(streq(atfcfg->cmd, "sta")) {
        apac_atf_sta_config_update(pData, atfcfg, index);
    } else if(streq(atfcfg->cmd, "group")) {
        apac_atf_group_config_update(pData, atfcfg, index);
    } else if(streq(atfcfg->cmd, "radio")) {
        apac_atf_radio_params_update(pData, atfcfg, index);
    } else {
        dprintf(MSG_ERROR, "%s (len : %d) Invalid Command received\n", atfcfg->cmd, strlen(atfcfg->cmd));
    }

    return 0;
}

void apacHyfi20AtfConfigDump(void *ptrData) {
    int i = 0, j = 0, k =0;
    apacHyfi20Data_t *pData = (apacHyfi20Data_t *)ptrData;
    apacHyfi20Config_t *pConfig = &pData->config;
    int num_repeaters = pConfig->apac_atf_num_repeaters;

    if( pConfig->atf_config_enabled ) {
        dprintf(MSG_INFO, "ATF Configuration dump begin\n");

        dprintf(MSG_INFO, "Num repeater entries : %d\n", num_repeaters);

        for(i = 0; i < num_repeaters; i++) {
            dprintf(MSG_INFO, "RE MAC : %s Identifier : %s vap_num_cfg : %d sta_num_cfg : %d group_num_cfg : %d radio_num_cfg : %d\n",
                    print_macaddr(pConfig->atfConf[i].remac), pConfig->atfConf[i].identifier,
                    pConfig->atfConf[i].vap_num_cfg, pConfig->atfConf[i].peer_num_cfg,
                    pConfig->atfConf[i].group_num_cfg, pConfig->atfConf[i].radio_num_cfg);

            /* ATF SSID configurations */
            for(j = 0; j < pConfig->atfConf[i].vap_num_cfg; j++) {
                dprintf(MSG_INFO, "cmd : %s, intf : %s ssid : %s val : %d\n",
                        pConfig->atfConf[i].vap[j].cmd, pConfig->atfConf[i].vap[j].interface,
                        pConfig->atfConf[i].vap[j].ssid, pConfig->atfConf[i].vap[j].val);
            }

            /* ATF Peer configurations */
            for(k = 0; k < pConfig->atfConf[i].peer_num_cfg; k++) {
                dprintf(MSG_INFO, "cmd : %s, intf : %s sta_mac : %s val : %d\n",
                        pConfig->atfConf[i].peer[k].cmd, pConfig->atfConf[i].peer[k].interface,
                        print_macaddr(pConfig->atfConf[i].peer[k].sta_mac), pConfig->atfConf[i].peer[k].val);
            }

            /* ATF Group Configurations */
            for(k = 0; k < pConfig->atfConf[i].group_num_cfg; k++) {
                dprintf(MSG_INFO, "cmd : %s, intf : %s val : %d grpname : %s SSIDs : ",
                        pConfig->atfConf[i].group[k].cmd, pConfig->atfConf[i].group[k].interface,
                        pConfig->atfConf[i].group[k].val, pConfig->atfConf[i].group[k].grpname);

                for(j=0; j < pConfig->atfConf[i].group[k].grp_num_ssid; j++)
                    dprintf(MSG_INFO, "%s   ", pConfig->atfConf[i].group[k].grp_ssid[j]);

                dprintf(MSG_INFO,"\n");
            }

            /* ATF Radio Params */
            for(k = 0; k < pConfig->atfConf[i].radio_num_cfg; k++) {
                dprintf(MSG_INFO, "Interface : %s sched_policy : %d obss : %d group_sched: %d\n",
                        pConfig->atfConf[i].radioparams[k].interface,
                        pConfig->atfConf[i].radioparams[k].sched_policy,
                        pConfig->atfConf[i].radioparams[k].obss_enable,
                        pConfig->atfConf[i].radioparams[k].group_sched_policy);
            }

        }
        dprintf(MSG_INFO, "ATF Configuration dump end\n");
    }
}

int apac_atf_config_parse_file(void *ptrData, const char *fname) {
    apacHyfi20Data_t *pData = (apacHyfi20Data_t *)ptrData;
    FILE *f;
    char buf[256];
    int line = 0;
    int errors = 0;
    int ret = 0;
    ATF_CONFIG atf_cfg_line;
    int lock_fd = open(APAC_LOCK_FILE_PATH, O_RDONLY);

    if (lock_fd < 0) {
        dprintf(MSG_ERROR, "Failed to open lock file %s\n", APAC_LOCK_FILE_PATH);
        return -1;
    }
    if (flock(lock_fd, LOCK_EX) == -1) {
        dprintf(MSG_ERROR, "Failed to flock lock file %s\n", APAC_LOCK_FILE_PATH);
        close(lock_fd);
        return -1;
    }

    dprintf(MSG_DEBUG, "Reading wsplcd 2.0 ATF configuration file %s ...\n", fname);

    f = fopen(fname, "r");
    if (f == NULL) {
        dprintf(MSG_ERROR,
            "Could not open configuration file '%s' for reading.\n",
            fname);
        return -1;
    }

    while (fgets(buf, sizeof(buf), f) != NULL) {
        line++;
        ret = apac_atf_config_line_lex(buf, &atf_cfg_line);
        if (ret == -1) {
            errors++;
            continue;
        }
        if (ret == 1)
            continue;        /* empty line */

        if (apac_atf_config_apply_line(pData, &atf_cfg_line)) {
            dprintf(MSG_ERROR, "line %d error in configure file\n", line);
            errors++;
        }
    }

    if (flock(lock_fd, LOCK_UN) == 1) {
        dprintf(MSG_ERROR, "Failed to unlock file %s\n", APAC_LOCK_FILE_PATH);
        errors++;
    }
    close(lock_fd);
    fclose(f);

    if (errors) {
        dprintf(MSG_ERROR,
            "%d errors found in configuration file '%s'\n",
            errors, fname);
    }

    return (errors != 0);
}

/* Add the vendor specifc TLV header, including the ATF version info */
static u_int8_t *atfmsgGenerateVendorSpecificAtfMsgTLVHeader(
        ieee1905TLV_t *tlv, ieee1905QCAVendorSpecificType_e type,
        u_int32_t *bufferLen) {
    ieee1905QCAMessage_t *qcaMessage =
        (ieee1905QCAMessage_t *)ieee1905TLVValGet(tlv);

    *bufferLen = 0;  // new TLV, start from scratch
    ieee1905TLVTypeSet(tlv, IEEE1905_TLV_TYPE_VENDOR_SPECIFIC);
    ieee1905QCAOUIAndTypeSet(qcaMessage, type, *bufferLen);
    *qcaMessage->content = atfmsgPackVersionNum(atfmsgMajorVersion1,
                                                  atfmsgMinorVersion0);
    (*bufferLen)++;

    return qcaMessage->content + 1;
}

const ieee1905QCAMessage_t *atfmsgExtractAtfTLV( const ieee1905TLV_t *tlv) {
    ieee1905TlvType_e tlvType = ieee1905TLVTypeGet(tlv);

    if (tlvType == IEEE1905_TLV_TYPE_VENDOR_SPECIFIC) {
        const ieee1905QCAMessage_t *qcaMessage =
            (const ieee1905QCAMessage_t *)ieee1905TLVValGet(tlv);

        // The TLVs we care about have a type field followed by a version
        // field, so ignore any that are of insufficient length.
        if (ieee1905TLVLenGet(tlv) >= IEEE1905_OUI_LENGTH + 2 &&
            ieee1905QCAIsQCAOUI(qcaMessage->oui) &&
            qcaMessage->type >= IEEE1905_QCA_TYPE_SYSTEM_INFO_REQ) {
            const u_int8_t version = qcaMessage->content[0];
            if (atfmsgExtractMajorVersionNum(version) ==
                    atfmsgMajorVersion1) {
                return qcaMessage;
            }
        }
    }

    // Not a TLV we will handle.
    return NULL;
}

int apacHyfi20SendAtfConfig(void *ptrData, int rep_index) {
    apacHyfi20Data_t *pData = (apacHyfi20Data_t *)ptrData;
    apacHyfi20IF_t *pIF = pData->hyif;
    apacHyfi20Config_t *pConfig = &pData->config;
    ATF_REP_CONFIG *ap_rep_config = &pConfig->atfConf[rep_index];
    u8 *frame = apacHyfi20GetXmitBuf();
    ieee1905TLV_t *tlv = (ieee1905TLV_t *)((ieee1905Message_t *)frame)->content;
    u16 mid = apacHyfi20GetMid();
    u8 dest[ETH_ALEN];
    size_t frameLen = IEEE1905_FRAME_MIN_LEN;
    u32 i = 0;
    size_t maxAtfMsgLen = IEEE1905_CONTENT_MAXLEN;
    size_t atfMsgLen = 0;
    u_int32_t bufferLen = 0;

    if (!ap_rep_config->remac) {
        dprintf(MSG_ERROR, "Repeater MAC address is null!\n");
        return -1;
    }

    if (os_memcmp(ap_rep_config->remac, ATF_ETH_ADDR_ALL, ETH_ALEN) == 0) {
        os_memcpy(dest, APAC_MULTICAST_ADDR, ETH_ALEN);
        dprintf(MSG_INFO, "%s, One-shot config to all Repeaters (dest %s)", __func__, print_macaddr(dest));
    } else {
        os_memcpy(dest, ap_rep_config->remac, ETH_ALEN);
        dprintf(MSG_INFO, "%s, Per Repeater config (dest %s)", __func__, print_macaddr(dest));
    }

    /* OverHead : ATF TLVs (depending on the number of SSID & Peer Based config) + EndTLV */
    atfMsgLen = ( (ap_rep_config->vap_num_cfg * (sizeof(struct ssid_config) + IEEE1905_VERSION_QCA_TLV_MIN_LEN)) +
                  (ap_rep_config->peer_num_cfg * (sizeof(struct peer_config) + IEEE1905_VERSION_QCA_TLV_MIN_LEN)) +
                  (ap_rep_config->group_num_cfg * (sizeof(struct group_config) + IEEE1905_VERSION_QCA_TLV_MIN_LEN)) +
                  (ap_rep_config->radio_num_cfg * (sizeof(struct radio_config) + IEEE1905_VERSION_QCA_TLV_MIN_LEN)) +
                  IEEE1905_TLV_MIN_LEN );

    if(atfMsgLen > maxAtfMsgLen)
    {
        dprintf(MSG_ERROR, "atfMsgLen (%u) >  maxAtfMsgLen(%u)\n", atfMsgLen, maxAtfMsgLen);
        return -1;
    }

    dprintf(MSG_MSGDUMP, "%s atfMsgLen : %d maxAtfMsgLen : %d \n", __func__, atfMsgLen, maxAtfMsgLen);
    apacHyfi20SetPktHeader(frame, IEEE1905_MSG_TYPE_VENDOR_SPECIFIC,
        mid, 0, IEEE1905_HEADER_FLAG_LAST_FRAGMENT | IEEE1905_HEADER_FLAG_RELAY,
        pData->alid, dest);

    /* ATF - SID Based Configuration */
    dprintf(MSG_INFO, "Sending ATF config for rep %s vap_num : %d peer_num : %d group_num : %d radio_num : %d\n",
            print_macaddr(ap_rep_config->remac), ap_rep_config->vap_num_cfg, ap_rep_config->peer_num_cfg,
            ap_rep_config->group_num_cfg, ap_rep_config->radio_num_cfg);

    for(i = 0; i < ap_rep_config->vap_num_cfg; i++) {
        dprintf(MSG_INFO, "SSID config %d\n", i);

        struct ssid_config *payload_ssid  = (struct ssid_config *)atfmsgGenerateVendorSpecificAtfMsgTLVHeader(
                tlv, IEEE1905_QCA_TYPE_ATF_SSID_CFG, &bufferLen);

        os_memcpy(payload_ssid, &ap_rep_config->vap[i], sizeof(struct ssid_config));
        bufferLen += sizeof(struct ssid_config);
        ieee1905TLVLenSet(tlv, bufferLen, frameLen);

        tlv = ieee1905TLVGetNext(tlv);
        dprintf(MSG_INFO, "FrameLen %d\n", frameLen);
    }

    for(i = 0; i < ap_rep_config->peer_num_cfg; i++) {
        dprintf(MSG_INFO, "ATF Peer config %d\n", i);
        struct peer_config *payload_peer  = (struct peer_config *)atfmsgGenerateVendorSpecificAtfMsgTLVHeader(
                tlv, IEEE1905_QCA_TYPE_ATF_PEER_CFG, &bufferLen);

        os_memcpy(payload_peer, &ap_rep_config->peer[i], sizeof(struct peer_config));
        bufferLen += sizeof(struct peer_config);
        ieee1905TLVLenSet(tlv, bufferLen, frameLen);

        tlv = ieee1905TLVGetNext(tlv);
        dprintf(MSG_INFO, "FrameLen %d\n", frameLen);
    }

    for(i = 0; i < ap_rep_config->group_num_cfg; i++) {
        dprintf(MSG_INFO, "ATF Group config %d group_name : %s val : %d\n",
                i, ap_rep_config->group[i].grpname, ap_rep_config->group[i].val);
        struct group_config *payload_group  = (struct group_config *)atfmsgGenerateVendorSpecificAtfMsgTLVHeader(
                tlv, IEEE1905_QCA_TYPE_ATF_GROUP_CFG, &bufferLen);

        os_memcpy(payload_group, &ap_rep_config->group[i], sizeof(struct group_config));
        bufferLen += sizeof(struct group_config);
        ieee1905TLVLenSet(tlv, bufferLen, frameLen);

        tlv = ieee1905TLVGetNext(tlv);
        dprintf(MSG_INFO, "FrameLen %d\n", frameLen);
    }

    for(i = 0; i < ap_rep_config->radio_num_cfg; i++) {
        dprintf(MSG_INFO, "index : %d Radio : %s sched_policy : %d obss : %d group_sched : %d \n",
                i, ap_rep_config->radioparams[i].interface, ap_rep_config->radioparams[i].sched_policy,
                ap_rep_config->radioparams[i].obss_enable, ap_rep_config->radioparams[i].group_sched_policy);

        struct radio_config *payload_radio  = (struct radio_config *)atfmsgGenerateVendorSpecificAtfMsgTLVHeader(
                tlv, IEEE1905_QCA_TYPE_ATF_RADIOPARAM_CFG, &bufferLen);

        os_memcpy(payload_radio, &ap_rep_config->radioparams[i], sizeof(struct radio_config));
        bufferLen += sizeof(struct radio_config);
        ieee1905TLVLenSet(tlv, bufferLen, frameLen);

        tlv = ieee1905TLVGetNext(tlv);
        dprintf(MSG_INFO, "FrameLen %d\n", frameLen);
    }

    /* Add EndOfTlv */
    ieee1905EndOfTLVSet(tlv);

    /* Send the packet out */
    if (pData->config.sendOnAllIFs == APAC_FALSE) {
        if (send(pData->bridge.sock, frame, frameLen, 0) < 0) {
            perror("apacHyfi20SendResponseR");
            return -1;
        }
    } else {
        for (i = 0; i < APAC_MAXNUM_HYIF; i++) {
           if (apacHyfi20SendL2Packet(&pIF[i], frame, frameLen) < 0) {
                perror("apacHyfi20SendAtfConfig");
                return -1;
            }
            dprintf(MSG_INFO, "%s sent msg mid: %d on %s\n", __func__, mid, pIF[i].ifName);
        }
    }

    return 0;
}

int apacHyfi20ReceiveAtfConfig(u8 *message, u32 msgLen) {
    ieee1905Message_t *frame = (ieee1905Message_t *)message;
    ieee1905TLV_t *TLV =  (ieee1905TLV_t *)frame->content;
    ieee1905TlvType_e tlvType;
    ieee1905QCAVendorSpecificType_e qcaType;
    ATF_REP_CONFIG ap_rep_rcv_config;
    u32 num_vaps = 0, num_peers = 0, num_groups = 0, num_radio = 0;
    u32 processedLen  = IEEE1905_FRAME_MIN_LEN;

    os_memset(&ap_rep_rcv_config, 0, sizeof(ATF_REP_CONFIG));

    while (processedLen <= msgLen) {

        tlvType = ieee1905TLVTypeGet(TLV);

        if (tlvType == IEEE1905_TLV_TYPE_END_OF_MESSAGE) {
            dprintf(MSG_MSGDUMP, "end of message received\n");
            break;
        } else if( tlvType == IEEE1905_TLV_TYPE_VENDOR_SPECIFIC ) {
            const ieee1905QCAMessage_t *qcaMsg = atfmsgExtractAtfTLV(TLV);
            if(qcaMsg) {
                const u_int8_t *payload = &qcaMsg->content[1];
                qcaType = ieee1905QCATypeGet(qcaMsg);

                if (qcaType == IEEE1905_QCA_TYPE_ATF_SSID_CFG) {
                    num_vaps = ap_rep_rcv_config.vap_num_cfg;
                    os_memcpy(&ap_rep_rcv_config.vap[num_vaps], payload, sizeof(ap_rep_rcv_config.vap[num_vaps]));
                    ap_rep_rcv_config.vap_num_cfg++;
                } else if (qcaType == IEEE1905_QCA_TYPE_ATF_PEER_CFG) {
                    num_peers = ap_rep_rcv_config.peer_num_cfg;
                    os_memcpy(&ap_rep_rcv_config.peer[num_peers], payload, sizeof(ap_rep_rcv_config.peer[num_peers]));
                    ap_rep_rcv_config.peer_num_cfg++;
                } else if (qcaType == IEEE1905_QCA_TYPE_ATF_GROUP_CFG) {
                    num_groups = ap_rep_rcv_config.group_num_cfg;
                    os_memcpy(&ap_rep_rcv_config.group[num_groups], payload, sizeof(ap_rep_rcv_config.group[num_groups]));
                    ap_rep_rcv_config.group_num_cfg++;
                } else if (qcaType == IEEE1905_QCA_TYPE_ATF_RADIOPARAM_CFG) {
                    num_radio = ap_rep_rcv_config.radio_num_cfg;
                    os_memcpy(&ap_rep_rcv_config.radioparams[num_radio], payload, sizeof(ap_rep_rcv_config.radioparams[num_radio]));
                    ap_rep_rcv_config.radio_num_cfg++;
                } else {
                    dprintf(MSG_MSGDUMP, "%s ATF type not found in QCA Message\n",__func__);
                    break;
                }
                processedLen += ieee1905TLVLenGet(TLV) + IEEE1905_OUI_LENGTH;

                TLV = ieee1905TLVGetNext(TLV);
                dprintf(MSG_MSGDUMP,"%s processedLen: %d\n", __func__, processedLen);
            } else {
                dprintf(MSG_ERROR, "%s Invalid ATF TLV header\n", __func__);
                break;
            }
        } else {
            dprintf(MSG_ERROR, "Invalid TLV\n");
            break;
        }
    }

    dprintf(MSG_INFO, "Received ATF Config - numvaps : %d numpeers : %d numgroups : %d\n",
            ap_rep_rcv_config.vap_num_cfg, ap_rep_rcv_config.peer_num_cfg, ap_rep_rcv_config.group_num_cfg);
    if(ap_rep_rcv_config.vap_num_cfg || ap_rep_rcv_config.peer_num_cfg ||
       ap_rep_rcv_config.group_num_cfg || ap_rep_rcv_config.radio_num_cfg) {
        apacHyfi20ConfigureAtf(&ap_rep_rcv_config);
    }
    return 0;
}

int apacHyfi20ConfigureAtf(ATF_REP_CONFIG *apAtfConfig) {
    int j = 0, k =0;
    int ret = 0;

    for(j = 0; j < apAtfConfig->vap_num_cfg; j++) {
        dprintf(MSG_INFO, "cmd : %s, intf : %s ssid : %s val : %d\n",
                apAtfConfig->vap[j].cmd, apAtfConfig->vap[j].interface, apAtfConfig->vap[j].ssid, apAtfConfig->vap[j].val);

        if(streq (apAtfConfig->vap[j].cmd, "addssid")) {
            ret = apacHyfi20ConfigAtf_addssid(apAtfConfig->vap[j].interface, apAtfConfig->vap[j].ssid, apAtfConfig->vap[j].val);
        } else if(streq (apAtfConfig->vap[j].cmd, "delssid")) {
            ret = apacHyfi20ConfigAtf_delssid(apAtfConfig->vap[j].interface, apAtfConfig->vap[j].ssid);
        } else {
            dprintf(MSG_ERROR,"%s invalid command received\n",__func__);
            ret = 1;
        }

        if(!ret) {
            apacHyfi20atfCommit( apAtfConfig->vap[j].interface, 1);
        }
    }

    for(k = 0; k < apAtfConfig->peer_num_cfg; k++) {
        dprintf(MSG_INFO, "cmd : %s, intf : %s sta_mac : %s val : %d\n",
                apAtfConfig->peer[k].cmd, apAtfConfig->peer[k].interface, print_macaddr(apAtfConfig->peer[k].sta_mac), apAtfConfig->peer[k].val);
        if(streq (apAtfConfig->peer[k].cmd, "addsta")) {
            ret = apacHyfi20ConfigAtf_addsta(apAtfConfig->peer[k].interface, apAtfConfig->peer[k].sta_mac, apAtfConfig->peer[k].val);
        } else if(streq (apAtfConfig->peer[k].cmd, "delsta")) {
            ret = apacHyfi20ConfigAtf_delsta(apAtfConfig->peer[k].interface, apAtfConfig->peer[k].sta_mac);
        } else {
            dprintf(MSG_ERROR,"%s invalid command received\n",__func__);
            ret = 1;
        }
        if(!ret) {
            apacHyfi20atfCommit( apAtfConfig->peer[k].interface, 1);
        }
    }

    /* Enable ATF SSID grouping feature before configuring */
    for(k = 0; k < apAtfConfig->group_num_cfg; k++) {
        if( apAtfConfig->group[k].grpenable == APAC_ATF_GROUP_ENABLE) {
            dprintf(MSG_INFO, "Enabling Grouping\n");
            ret = apacHyfi20atfGroupEnable( apAtfConfig->group[k].interface, 1);
        }
    }

    for(k = 0; k < apAtfConfig->group_num_cfg; k++) {
        int grp_ssid_idx = 0;
        dprintf(MSG_INFO, "cmd : %s, intf : %s group_name : %s val : %d\n",
                apAtfConfig->group[k].cmd, apAtfConfig->group[k].interface, apAtfConfig->group[k].grpname, apAtfConfig->group[k].val);
        if(streq (apAtfConfig->group[k].cmd, "addgroup")) {
            /* Create ATF group & add ssids to the group */
            for( grp_ssid_idx = 0; grp_ssid_idx < apAtfConfig->group[k].grp_num_ssid; grp_ssid_idx++ ) {
                ret = apacHyfi20ConfigAtf_addgroup( apAtfConfig->group[k].interface, apAtfConfig->group[k].grpname,  \
                                                    apAtfConfig->group[k].grp_ssid[grp_ssid_idx] );
            }
            /*Configure Airtime to the group */
            ret = apacHyfi20ConfigAtf_configgroup( apAtfConfig->group[k].interface, apAtfConfig->group[k].grpname,  \
                                                   apAtfConfig->group[k].val );
        } else if(streq (apAtfConfig->group[k].cmd, "delgroup")) {
            ret = apacHyfi20ConfigAtf_delgroup(apAtfConfig->group[k].interface, apAtfConfig->group[k].grpname);
        } else {
            dprintf(MSG_ERROR,"%s invalid command received\n",__func__);
            ret = 1;
        }
        if(!ret) {
            apacHyfi20atfCommit( apAtfConfig->group[k].interface, 1);
        }
    }

    /* Disable ATF grouping after group delete */
    for(k = 0; k < apAtfConfig->group_num_cfg; k++) {
        if( apAtfConfig->group[k].grpenable == APAC_ATF_GROUP_DISABLE) {
            dprintf(MSG_INFO, "Disabling Grouping\n");
            ret = apacHyfi20atfGroupEnable( apAtfConfig->group[k].interface, 0);
        }
    }

    for(k = 0; k < apAtfConfig->radio_num_cfg; k++) {

        if( apAtfConfig->radioparams[k].sched_policy == APAC_ATF_SCHED_POLICY_STRICT) {
            dprintf(MSG_INFO,"Setting sched policy to strict\n");
            ret = apacHyfi20ConfigAtf_radioparams(apAtfConfig->radioparams[k].interface, ATH_PARAM_ATF_STRICT_SCHED, 1);
        } else if ( apAtfConfig->radioparams[k].sched_policy == APAC_ATF_SCHED_POLICY_FAIR) {
            dprintf(MSG_INFO,"Setting sched policy to Fair\n");
            ret = apacHyfi20ConfigAtf_radioparams(apAtfConfig->radioparams[k].interface, ATH_PARAM_ATF_STRICT_SCHED, 0);
        }

        if( apAtfConfig->radioparams[k].obss_enable == APAC_ATF_OBSS_ENABLE) {
            dprintf(MSG_INFO,"Enabling OBSS\n");
            ret = apacHyfi20ConfigAtf_radioparams(apAtfConfig->radioparams[k].interface, ATH_PARAM_ATF_OBSS_SCHED, 1);
        } else if ( apAtfConfig->radioparams[k].obss_enable == APAC_ATF_OBSS_DISABLE) {
            dprintf(MSG_INFO,"Disabling OBSS\n");
            ret = apacHyfi20ConfigAtf_radioparams(apAtfConfig->radioparams[k].interface, ATH_PARAM_ATF_OBSS_SCHED, 0);
        }

        if( apAtfConfig->radioparams[k].group_sched_policy == APAC_ATF_GROUP_SCHED_STRICT) {
            dprintf(MSG_INFO, "Setting group sched policy to strict\n");
            ret = apacHyfi20ConfigAtf_radioparams(apAtfConfig->radioparams[k].interface, ATH_PARAM_ATF_GROUP_SCHED_POLICY, 1);
        } else if ( apAtfConfig->radioparams[k].group_sched_policy == APAC_ATF_GROUP_SCHED_FAIR) {
            dprintf(MSG_INFO, "Setting group sched policy to fair\n");
            ret = apacHyfi20ConfigAtf_radioparams(apAtfConfig->radioparams[k].interface, ATH_PARAM_ATF_GROUP_SCHED_POLICY, 0);
        }
    }
    return 0;
}

int apacHyfi20ConfigAtf_radioparams( char *iface, u_int32_t param, u_int32_t val) {

    int32_t Sock;
    struct iwreq Wrq;

    if (!iface) {
        dprintf(MSG_ERROR, "%s: Invalid arguments\n", __func__);
        goto out;
    }

    if ((Sock = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
        dprintf(MSG_ERROR, "%s Failed to open socket\n",__func__);
        goto out;
    }

    if (fcntl(Sock, F_SETFL, fcntl(Sock, F_GETFL) | O_NONBLOCK)) {
        dprintf(MSG_ERROR, "%s: fcntl() failed\n", __func__);
        goto err;
    }

    strncpy(Wrq.ifr_name, iface, IFNAMSIZ);
    Wrq.u.mode = param | ATH_PARAM_SHIFT;;
    os_memcpy(Wrq.u.name + sizeof(__u32), &val, sizeof(val));

    if (ioctl(Sock, IEEE80211_IOCTL_SETPARAM, &Wrq) < 0) {
        dprintf(MSG_ERROR, "%s: ioctl() failed, ifName: %s\n", __func__, iface);
        goto err;
    }

    close(Sock);
    return 0;
err:
    close(Sock);
out:
    return -1;
}

int apacHyfi20ConfigAtf_addgroup( char *ifname, char *grpname, char *grpssid ) {
    int s;
    uint8_t *buf;
    struct iwreq iwr;
    struct addgroup_val set_group;

    s = socket(AF_INET, SOCK_DGRAM, 0);
    if (s < 0){
        dprintf(MSG_ERROR, "%s - Failed to open Socket\n", __func__);
        return -1;
    }

    (void)memset(&set_group, 0, sizeof(set_group) );
    os_memcpy( &set_group.name[0], grpname, strlen(grpname) );
    os_memcpy( &set_group.ssid[0], grpssid, strlen(grpssid) );
    set_group.id_type = IEEE80211_IOCTL_ATF_ADDGROUP;

    buf = ((uint8_t *)&set_group);
    (void) memset(&iwr, 0, sizeof(iwr));
    (void) strncpy(iwr.ifr_name, ifname, sizeof(iwr.ifr_name));
    iwr.u.data.pointer = (void *) buf;
    iwr.u.data.length = sizeof(set_group);

    if (ioctl(s,IEEE80211_IOCTL_CONFIG_GENERIC, &iwr) < 0) {
        dprintf(MSG_ERROR, "Unable to add ATF group\n");
        close(s);
        return -1;
    }
    close(s);
    return 0;
}

int apacHyfi20ConfigAtf_delgroup(const char *ifname, char *grpname) {
    int32_t s;
    uint8_t *buf;
    struct iwreq iwr;
    struct addgroup_val del_group;

    s = socket(AF_INET, SOCK_DGRAM, 0);
    if (s < 0){
        dprintf(MSG_ERROR, "%s - Failed to open Socket\n", __func__);
        return -1;
    }

    (void) memset(&del_group, 0, sizeof(del_group));

    os_memcpy(&del_group.name[0], grpname, strlen(grpname));
    del_group.id_type = IEEE80211_IOCTL_ATF_DELGROUP;

    buf = ((uint8_t *) &del_group);
    (void) memset(&iwr, 0, sizeof(iwr));
    (void) strncpy(iwr.ifr_name, ifname, sizeof(iwr.ifr_name));
    iwr.u.data.pointer = (void *) buf;
    iwr.u.data.length = sizeof(del_group);

    if (ioctl(s,IEEE80211_IOCTL_CONFIG_GENERIC, &iwr) < 0){
        dprintf(MSG_ERROR, "Unable to delete ATF group\n");
        close(s);
        return -1;
    }
    close(s);
    return 0;
}

int apacHyfi20ConfigAtf_configgroup(const char *ifname, char *grpname, u_int32_t val) {
    int32_t s;
    uint8_t *buf;
    struct iwreq iwr;
    struct addgroup_val config_group;

    s = socket(AF_INET, SOCK_DGRAM, 0);
    if (s < 0){
        dprintf(MSG_ERROR, "%s - Failed to open Socket\n", __func__);
        return -1;
    }

    if( val <= 0 || val > 100) {
        dprintf(MSG_ERROR, "Invalid Group Airtime\n");
        close(s);
        return -1;
    }

    (void) memset(&config_group, 0, sizeof(config_group));
    os_memcpy(&config_group.name[0], grpname, strlen(grpname));

    config_group.id_type = IEEE80211_IOCTL_ATF_CONFIGGROUP;
    config_group.value = val;

    config_group.value = config_group.value * 10;
    buf = ((uint8_t *) &config_group);
    (void) memset(&iwr, 0, sizeof(iwr));
    (void) strncpy(iwr.ifr_name, ifname, sizeof(iwr.ifr_name));
    iwr.u.data.pointer = (void *) buf;
    iwr.u.data.length = sizeof(config_group);

    if (ioctl(s,IEEE80211_IOCTL_CONFIG_GENERIC, &iwr) < 0){
        dprintf(MSG_ERROR, "Unable to configure airtime to ATF group\n");
        close(s);
        return -1;
    }
    close(s);
    return 0;
}

int apacHyfi20ConfigAtf_addssid(const char *ifname, char *ssid, u_int32_t val) {
    int s;
    uint8_t *buf;
    struct iwreq iwr;
    struct addssid_val  set_atp;
    int ret = 0;

    s = socket(AF_INET, SOCK_DGRAM, 0);
    if (s < 0){
        dprintf(MSG_ERROR, "%s Failed on open socket\n",__func__);
        return -1;
    }

    (void) memset(&set_atp, 0, sizeof(set_atp));
    os_memcpy(&(set_atp.ssid[0]),ssid,strlen(ssid));
    set_atp.id_type = IEEE80211_IOCTL_ATF_ADDSSID;
    set_atp.value = val;

    if(set_atp.value > 100) {
        dprintf(MSG_ERROR," %s Input percentage value is over 100!!\n", __func__);
        close(s);
        return -1;
    }

    set_atp.value = set_atp.value*10;
    buf = ((uint8_t *) &set_atp);
    (void) memset(&iwr, 0, sizeof(iwr));
    (void) strncpy(iwr.ifr_name, ifname, sizeof(iwr.ifr_name));
    iwr.u.data.pointer = (void *) buf;
    iwr.u.data.length = sizeof(set_atp);

    if (ioctl(s,IEEE80211_IOCTL_CONFIG_GENERIC, &iwr) < 0) {
        dprintf(MSG_ERROR, "Unable to configureSID based ATF\n");
        ret = -1;
    }

    close(s);
    return ret;
}

int apacHyfi20ConfigAtf_delssid(const char *ifname, char *ssid) {
    int s;
    uint8_t *buf;
    struct iwreq iwr;
    struct addssid_val  set_atp;
    int ret = 0;

    s = socket(AF_INET, SOCK_DGRAM, 0);
    if (s < 0) {
        dprintf(MSG_ERROR, "%s Failed on open socket\n",__func__);
        return -1;
    }

    (void) memset(&set_atp, 0, sizeof(set_atp));
    os_memcpy(&(set_atp.ssid[0]),ssid,strlen(ssid));
    set_atp.id_type = IEEE80211_IOCTL_ATF_DELSSID;
    buf = ((uint8_t *) &set_atp);

    (void) memset(&iwr, 0, sizeof(iwr));
    (void) strncpy(iwr.ifr_name, ifname, sizeof(iwr.ifr_name));
    iwr.u.data.pointer = (void *) buf;
    iwr.u.data.length = sizeof(set_atp);
    if (ioctl(s,IEEE80211_IOCTL_CONFIG_GENERIC, &iwr) < 0) {
        dprintf(MSG_ERROR, "unable to delete ATFSID entry\n");
        ret = -1;
    }
    close(s);
    return ret;
}

int apacHyfi20ConfigAtf_addsta(const char *ifname, u8 *macaddr, u_int32_t val) {
    int s;
    uint8_t *buf;
    struct iwreq iwr;
    struct addsta_val  set_sta;
    int ret = 0;

    s = socket(AF_INET, SOCK_DGRAM, 0);
    if (s < 0) {
        dprintf(MSG_ERROR, "%s - socket cannot be created\n", __func__);
        return -1;
    }

    (void) memset(&set_sta, 0, sizeof(set_sta));
    os_memcpy(&set_sta.sta_mac, macaddr, IEEE80211_ADDR_LEN);
    set_sta.value = val;
    if(set_sta.value > 100) {
        dprintf(MSG_ERROR, "Input percentage value is over 100!!\n");
        close(s);
        return -1;
    }
    set_sta.value = set_sta.value * ATF_AIRTIME_CONVERSION_FACTOR;
    set_sta.id_type = IEEE80211_IOCTL_ATF_ADDSTA;
    buf = ((uint8_t *) &set_sta);

    (void) memset(&iwr, 0, sizeof(iwr));
    (void) strncpy(iwr.ifr_name, ifname, sizeof(iwr.ifr_name));
    iwr.u.data.pointer = (void *) buf;
    iwr.u.data.length = sizeof(set_sta);
    if (ioctl(s,IEEE80211_IOCTL_CONFIG_GENERIC, &iwr) < 0) {
        dprintf(MSG_ERROR, "unable to configure STA based ATF\n");
        ret = -1;
    }

    close(s);
    return ret;
}

int apacHyfi20ConfigAtf_delsta(const char *ifname, u8 *macaddr) {
    int s;
    uint8_t *buf;
    struct iwreq iwr;
    struct addsta_val  set_sta;
    int ret = 0;

    s = socket(AF_INET, SOCK_DGRAM, 0);
    if (s < 0) {
        dprintf(MSG_ERROR, "%s Failed to open socket\n",__func__);
        return -1;
    }

    (void) memset(&set_sta, 0, sizeof(set_sta));
    os_memcpy(set_sta.sta_mac, macaddr, IEEE80211_ADDR_LEN);

    set_sta.id_type = IEEE80211_IOCTL_ATF_DELSTA;
    buf = ((uint8_t *) &set_sta);

    (void) memset(&iwr, 0, sizeof(iwr));
    (void) strncpy(iwr.ifr_name, ifname, sizeof(iwr.ifr_name));
    iwr.u.data.pointer = (void *) buf;
    iwr.u.data.length = sizeof(set_sta);
    if (ioctl(s,IEEE80211_IOCTL_CONFIG_GENERIC, &iwr) < 0){
        dprintf(MSG_ERROR, "unable to delete ATFTA entry\n");
        ret = -1;
    }

    close(s);
    return ret;
}

int apacHyfi20atfGroupEnable( const char *iface, int val) {
    int32_t Sock;
    struct iwreq Wrq;

    if (!iface) {
        dprintf(MSG_ERROR, "%s: Invalid arguments\n", __func__);
        goto out;
    }

    if ((Sock = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
        dprintf(MSG_ERROR, "%s Failed to open socket\n",__func__);
        goto out;
    }

    if (fcntl(Sock, F_SETFL, fcntl(Sock, F_GETFL) | O_NONBLOCK)) {
        dprintf(MSG_ERROR, "%s: fcntl() failed\n", __func__);
        goto err;
    }

    strncpy(Wrq.ifr_name, iface, IFNAMSIZ);
    Wrq.u.mode = IEEE80211_PARAM_ATF_SSID_GROUP;
    os_memcpy(Wrq.u.name + sizeof(__u32), &val, sizeof(val));
    if (ioctl(Sock, IEEE80211_IOCTL_SETPARAM, &Wrq) < 0) {
        dprintf(MSG_ERROR, "%s: ioctl() failed, ifName: %s\n", __func__, iface);
        goto err;
    }

    close(Sock);
    return 0;
err:
    close(Sock);
out:
    return -1;
}

int apacHyfi20atfCommit( const char *iface, int val) {
    int32_t Sock;
    struct iwreq Wrq;

    if (!iface) {
        dprintf(MSG_ERROR, "%s: Invalid arguments\n", __func__);
        goto out;
    }

    if ((Sock = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
        dprintf(MSG_ERROR, "%s Failed to open socket\n",__func__);
        goto out;
    }

    if (fcntl(Sock, F_SETFL, fcntl(Sock, F_GETFL) | O_NONBLOCK)) {
        dprintf(MSG_ERROR, "%s: fcntl() failed\n", __func__);
        goto err;
    }

    strncpy(Wrq.ifr_name, iface, IFNAMSIZ);
    Wrq.u.mode = IEEE80211_PARAM_ATF_OPT;
    os_memcpy(Wrq.u.name + sizeof(__u32), &val, sizeof(val));
    if (ioctl(Sock, IEEE80211_IOCTL_SETPARAM, &Wrq) < 0) {
        dprintf(MSG_ERROR, "%s: ioctl() failed, ifName: %s\n", __func__, iface);
        goto err;
    }

    close(Sock);
    return 0;
err:
    close(Sock);
out:
    return -1;
}
