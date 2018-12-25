/* apac_hyfi20_init.c 
 * @Notes:
 *
 * Copyright (c) 2011-2012 Qualcomm Atheros, Inc.
 * Qualcomm Atheros Confidential and Proprietary. 
 * All rights reserved.
 *
 */

#include "wsplcd.h"
#include "eloop.h"
#include <sys/socket.h>
#include <sys/file.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <linux/wireless.h>
#include <ieee80211_external.h>

#include "apac_hyfi20_ctrl.h"
#include "apac_hyfi20_mib.h"
#include "apac_priv.h"

#include "wps_config.h"
#include "wps_parser.h"
#include "split.h"

#define MAXCHANONESTRLEN    8
#define MAXCHANLISTSTRLEN   1024
#define WMODE_NAMESIZE  16
#define WSPLCD_PLC_SOCKET_SERVER "/var/run/wsplcd_plc_socket_server"

extern int get_2g;
extern int get_5g;
extern int qca_cfg_changed;
extern int qca_role;
extern int debug_level; 
extern apacHyfi20GlobalState_t apacS;
extern apacLogFileMode_e logFileMode;;
extern u16 apac_cfg_apply_interval;
extern u16 apac_cfg_restart_short_interval;
extern u16 apac_cfg_restart_long_interval;

/**
 * Mapping from "iwpriv athx get_mode" output to the format required
 * by "Standard" TLV in QCA extension
 */
static const struct {
    char *phy_mode;
    char *apac_std;
} phy_to_std_mappings[] = {
    { "11NGHT20",      "ng20" },
    { "11NGHT40MINUS", "ng40minus" },
    { "11NGHT40PLUS", "ng40plus" },
    { "11NGHT40", "ng40" },
    { "11NAHT20", "na20" },
    { "11NAHT40MINUS", "na40minus" },
    { "11NAHT40PLUS", "na40plus" },
    { "11NAHT40", "na40" },
    { "11ACVHT20", "acvht20" },
    { "11ACVHT40MINUS", "acvht40minus" },
    { "11ACVHT40PLUS", "acvht40plus" },
    { "11ACVHT40", "acvht40" },
    { "11ACVHT80", "acvht80" },
    { "11ACVHT160", "acvht160" },
    { "11ACVHT80_80", "acvht80_80" },
    { NULL, NULL }
};

// "auto" APAC standard used when no matching PHY mode is found
#define APAC_STD_AUTO "auto"


/**************************************************************
 * Hyfi2.0 / IEEE1905 AP Auto-Configuration 
 **************************************************************/
int apacHyfi20GetDeviceMode(apacHyfi20IF_t *pIF) {
    int32_t Sock;
    struct iwreq Wrq;
    char *ifName = pIF->ifName;

    if (!ifName) {
        dprintf(MSG_ERROR, "%s - Invalid arguments: ifName is NULL", __func__);
        goto out;
    }

    if ((Sock = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
        dprintf(MSG_ERROR, "%s: Create ioctl socket failed!", __func__);
        goto out;
    }

    if (fcntl(Sock, F_SETFL, fcntl(Sock, F_GETFL) | O_NONBLOCK)) {
        dprintf(MSG_ERROR, "%s: fcntl() failed", __func__);
        goto err;
    }

    strncpy(Wrq.ifr_name, ifName, IFNAMSIZ);
    if (ioctl(Sock, SIOCGIWMODE, &Wrq) < 0) {
        dprintf(MSG_ERROR, "%s: ioctl() failed, ifName: %s.\n", __func__, ifName);
        goto err;
    }

    if (Wrq.u.mode == IW_MODE_MASTER) {
        pIF->wlanDeviceMode = APAC_WLAN_AP;
    }
    else {
        pIF->wlanDeviceMode = APAC_WLAN_STA;
    }

    close(Sock);
    return 0;
err:
    close(Sock);
out:
    return -1;

}

int apacHyfi20GetVAPIndex(apacHyfi20IF_t *pIF) {
    int vapIndex;

    vapIndex = apac_mib_get_vapindex(pIF->ifName);

    if (vapIndex < 0) {
        dprintf(MSG_ERROR, "%s, can't get VAP INDEX for %s! vapIndex: %d\n", __func__, pIF->ifName, vapIndex);
        return -1;
    }

    pIF->vapIndex = vapIndex;

    return 0;
}

/**
 * @brief Check if the given interface is marked as wsplcd unmanaged
 *
 * @param [in] pIF  the interface to check
 *
 * @return negative value if error reading config data;
 *         0 if it is not unmanaged;
 *         positive value if the interface is marked as unmanaged
 */
static int apacHyfi20IsWsplcdUnmanaged(apacHyfi20IF_t *pIF) {
    return apac_mib_get_wsplcdUnmanaged_by_vapindex(pIF->vapIndex);
}

int apacHyfi20GetBandFromMib(int vap_index, apacHyfi20WifiFreq_e *freq) {
    char standard[1024];
    int i;

    struct wlanBand_t
    {
        const char* name;
        apacHyfi20WifiFreq_e freq;

    } wlanBands[] =
        {
            { "ng", APAC_WIFI_FREQ_2},
            { "na", APAC_WIFI_FREQ_5},
            { "acvht", APAC_WIFI_FREQ_5},
            { "a", APAC_WIFI_FREQ_5},
            { "b", APAC_WIFI_FREQ_2},
            { "g", APAC_WIFI_FREQ_2},
        };

    if (apac_mib_get_wlan_standard_by_vapindex(vap_index, standard) < 0) {
        dprintf(MSG_ERROR, "%s, get wlan standard from mib error\n", __func__);
        return -1;
    }

    for(i = 0; i < sizeof(wlanBands)/sizeof(wlanBands[0]); i++)
    {
        /* Return correct type by string match */
        if( strstr( standard, wlanBands[ i ].name ) )
        {
            dprintf(MSG_DEBUG, "%s: WiFi name: %s\n", __func__, standard);
            *freq = wlanBands[i].freq;
            return 0;
        }
    }

    dprintf(MSG_ERROR, "%s, Can't find match. vap: %u, standard: %s\n", __func__, vap_index, standard);
    return -1;
}

int apacHyfi20GetFreq(apacHyfi20IF_t *pIF) {
    int32_t Sock;
    struct iwreq Wrq;

    if (!pIF->ifName) {
        dprintf(MSG_ERROR, "%s - Invalid arguments: ifName is NULL", __func__);
        goto out;
    }

    if ((Sock = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
        dprintf(MSG_ERROR, "%s: Create ioctl socket failed!", __func__);
        goto out;
    }

    if (fcntl(Sock, F_SETFL, fcntl(Sock, F_GETFL) | O_NONBLOCK)) {
        dprintf(MSG_ERROR, "%s: fcntl() failed", __func__);
        goto err;
    }

    strncpy(Wrq.ifr_name, pIF->ifName, IFNAMSIZ);
    if (ioctl(Sock, SIOCGIWFREQ, &Wrq) < 0) {
        dprintf(MSG_ERROR, "%s: ioctl() failed, ifName: %s.\n", __func__, pIF->ifName);
        goto err;
    }

    if (Wrq.u.freq.m / 100000000 >= 60)
        pIF->wifiFreq = APAC_WIFI_FREQ_60;
    else if (Wrq.u.freq.m / 100000000 >= 5)
        pIF->wifiFreq = APAC_WIFI_FREQ_5;
    else
        pIF->wifiFreq = APAC_WIFI_FREQ_2;

    dprintf(MSG_MSGDUMP, "%s - Interface %s, frequency %uHz\n", __func__, pIF->ifName, Wrq.u.freq.m);

    close(Sock);
    return 0;
err:
    close(Sock);
out:
    return -1;
}


static uint32_t ieee80211_mhz2ieee(uint32_t freq)
{
#define IS_CHAN_IN_PUBLIC_SAFETY_BAND(_c) ((_c) > 4940 && (_c) < 4990)
    if (freq < 2412)
        return 0;
    if (freq == 2484)
        return 14;
    if (freq < 2484)
        return (freq - 2407) / 5;
    if (freq < 5000) {
        if (IS_CHAN_IN_PUBLIC_SAFETY_BAND(freq)) {
            return ((freq * 10) +
                (((freq % 5) == 2) ? 5 : 0) - 49400)/5;
        } else if (freq > 4900) {
            return (freq - 4000) / 5;
        } else {
            return 15 + ((freq - 2512) / 20);
        }
    }
    return (freq - 5000) / 5;
}


int apacHyfi20GetChannel(apacHyfi20AP_t *pAP) {
    int32_t Sock;
    struct iwreq Wrq;

    if (!pAP->ifName) {
        dprintf(MSG_ERROR, "%s - Invalid arguments: ifName is NULL", __func__);
        goto out;
    }

    if ((Sock = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
        dprintf(MSG_ERROR, "%s: Create ioctl socket failed!", __func__);
        goto out;
    }

    if (fcntl(Sock, F_SETFL, fcntl(Sock, F_GETFL) | O_NONBLOCK)) {
        dprintf(MSG_ERROR, "%s: fcntl() failed", __func__);
        goto err;
    }

    strncpy(Wrq.ifr_name, pAP->ifName, IFNAMSIZ);
    if (ioctl(Sock, SIOCGIWFREQ, &Wrq) < 0) {
        dprintf(MSG_ERROR, "%s: ioctl() failed, ifName: %s.\n", __func__, pAP->ifName);
        goto err;
    }
    
    pAP->channel = ieee80211_mhz2ieee(Wrq.u.freq.m/100000);

    dprintf(MSG_MSGDUMP, "%s - Interface %s, channel %d\n", __func__, pAP->ifName, pAP->channel);

    close(Sock);
    return 0;
err:
    close(Sock);
out:
    return -1;
}

/**
 * @brief Resolve Wlan Standard string from the mode returned from driver
 *
 * @param [in] mode  the mode string returned from driver
 * @param [in] chanInfo  channel information containing the actual OTA bandwidth
 *                       and channel offset
 * @param [out] std  the standard string resolved
 * @param [out] std_len  the length of the standard string
 */
static void apacHyfi20ResolveWlanStd(const char *mode, const apacHyfi20ChanInfo_t *chanInfo,
                                     char *std, u_int8_t *std_len) {
    size_t i, max_len;
    char *actual_std;
    for (i = 0; phy_to_std_mappings[i].phy_mode; ++i) {
        if (!strcmp(phy_to_std_mappings[i].phy_mode, mode)) {
            strlcpy(std, phy_to_std_mappings[i].apac_std, APAC_STD_MAX_LEN);
#define VHT_STD "acvht"
#define NGHT_STD "ng"
#define NAHT_STD "na"
            // Workaround to resolve actual OTA mode for HT/VHT
            if (strncmp(std, VHT_STD, strlen(VHT_STD)) == 0) {
                actual_std = std + strlen(VHT_STD);
                max_len = APAC_STD_MAX_LEN - strlen(VHT_STD);
            } else if (strncmp(std, NGHT_STD, strlen(NGHT_STD)) == 0) {
                actual_std = std + strlen(NGHT_STD);
                max_len = APAC_STD_MAX_LEN - strlen(NGHT_STD);
            } else if (strncmp(std, NAHT_STD, strlen(NAHT_STD)) == 0) {
                actual_std = std + strlen(NAHT_STD);
                max_len = APAC_STD_MAX_LEN - strlen(NAHT_STD);
            } else { // Non HT/VHT mode, do nothing
                break;
            }

            switch (chanInfo->width) {
                case IEEE80211_CWM_WIDTH20:
                    strlcpy(actual_std, "20", max_len);
                    break;
                case IEEE80211_CWM_WIDTH40:
                    strlcpy(actual_std, "40", max_len);
                    if (chanInfo->offset == 1) {
                        strlcpy(actual_std + 2, "plus", max_len - 2);
                    } else if (chanInfo->offset == -1) {
                        strlcpy(actual_std + 2, "minus", max_len - 2);
                    }
                    break;
                case IEEE80211_CWM_WIDTH80:
                    strlcpy(actual_std, "80", max_len);
                    break;
                case IEEE80211_CWM_WIDTH160:
                    if (chanInfo->ifreq2) {
                        strlcpy(actual_std, "80_80", max_len);
                    } else {
                        strlcpy(actual_std, "160", max_len);
                    }
                    break;
                default:
                    break;
            }
            break;
        }
    }

    if (!phy_to_std_mappings[i].phy_mode) {
        // If no matching mode, use "auto"
        strlcpy(std, APAC_STD_AUTO, APAC_STD_MAX_LEN);
    }

    *std_len = strlen(std);
}

int apacHyfi20GetAPMode(apacHyfi20AP_t *pAP) {
    int32_t Sock;
    struct iwreq Wrq;
    char mode[100];
    apacHyfi20ChanInfo_t chanInfo = {0};

    if (!pAP->ifName) {
        dprintf(MSG_ERROR, "%s - Invalid arguments: ifName is NULL", __func__);
        goto out;
    }

    if ((Sock = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
        dprintf(MSG_ERROR, "%s: Create ioctl socket failed!", __func__);
        goto out;
    }

    if (fcntl(Sock, F_SETFL, fcntl(Sock, F_GETFL) | O_NONBLOCK)) {
        dprintf(MSG_ERROR, "%s: fcntl() failed", __func__);
        goto err;
    }

    strncpy(Wrq.ifr_name, pAP->ifName, IFNAMSIZ);
    Wrq.u.data.pointer = mode;
    Wrq.u.data.length = sizeof(mode);
    if (ioctl(Sock, IEEE80211_IOCTL_GETMODE, &Wrq) < 0) {
        dprintf(MSG_ERROR, "%s: ioctl() failed, ifName: %s.\n", __func__, pAP->ifName);
        goto err;
    }
    mode[Wrq.u.data.length] = '\0';

    if (apacHyfi20GetAPChannelInfo(pAP->ifName, &chanInfo) != 0) {
        dprintf(MSG_ERROR, "%s: Failed to get channel info, ifName: %s.\n",
                __func__, pAP->ifName);
        goto err;
    }
    apacHyfi20ResolveWlanStd(mode, &chanInfo, pAP->standard, &pAP->standard_len);
    dprintf(MSG_MSGDUMP, "%s - Interface %s, standard %s\n",
            __func__, pAP->ifName, pAP->standard);

    close(Sock);
    return 0;
err:
    close(Sock);
out:
    return -1;

}

static int get80211ChannelInfo(const char *ifName, struct ieee80211req_chaninfo *chans) {
    int32_t Sock;
    struct iwreq Wrq;
    size_t len = sizeof(*chans);

    if (!ifName) {
        dprintf(MSG_ERROR, "%s - Invalid arguments: ifName is NULL\n", __func__);
        goto out;
    }

    if ((Sock = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
        dprintf(MSG_ERROR, "%s: Create ioctl socket failed!\n", __func__);
        goto out;
    }

    if (fcntl(Sock, F_SETFL, fcntl(Sock, F_GETFL) | O_NONBLOCK)) {
        dprintf(MSG_ERROR, "%s: fcntl() failed", __func__);
        goto err;
    }

    os_memset(&Wrq, 0, sizeof(Wrq));
    strlcpy(Wrq.ifr_name, ifName, IFNAMSIZ);
    
    Wrq.u.data.pointer = chans;
    Wrq.u.data.length = len;    
    
    if (ioctl(Sock, IEEE80211_IOCTL_GETCHANINFO, &Wrq, len) < 0) {
        dprintf(MSG_ERROR, "%s: ioctl() failed, ifName: %s.\n", __func__, ifName);
        goto err;
    }

    if (Wrq.u.data.length < 0) {
        dprintf(MSG_ERROR, "%s, Wrq.u.data.length: %d!\n", __func__, Wrq.u.data.length);
        goto err;
    }
    
    close(Sock);
    return 0;
err:
    close(Sock);
out:
    return -1;
}

int apacHyfi20GetWlanBandCapacity(const char *ifName, char *chanlist, apacBool_e *hasW2, apacBool_e *hasW5) {
    struct ieee80211req_chaninfo *chans;
    int i;
    int ret = -1;
    char chanone[MAXCHANONESTRLEN + 1];

    /*size coped to user space: 
     (sizeof(struct ieee80211req_chaninfo)/sizeof(__u32)) + 1)
     */
    chans = malloc((sizeof(struct ieee80211req_chaninfo)/sizeof(unsigned int) + 1) * sizeof(unsigned int));
    if (!chans)
    {
        dprintf(MSG_ERROR, "ERR to malloc chaninfo buffer\n");
        return -1;
    }

    if (get80211ChannelInfo(ifName, chans) < 0) {
        dprintf(MSG_ERROR, "ERR, get80211ChannelInfo\n");
        goto err;
    }

    chanlist[0]='\0';   /*flush out the list*/
    *hasW2 = APAC_FALSE;
    *hasW5 = APAC_FALSE;

    for (i = 0; i < chans->ic_nchans; i ++) {
        snprintf(chanone, MAXCHANONESTRLEN, "%u, ", chans->ic_chans[i].ic_freq);
        strncat(chanlist, chanone, sizeof(chanone));

        if ( (chans->ic_chans[i].ic_freq / 1000) == 2 ) {
            *hasW2 = APAC_TRUE;
        }
        else if ( (chans->ic_chans[i].ic_freq / 1000) == 5 ) {
            *hasW5 = APAC_TRUE;
        }
        else {
            dprintf(MSG_ERROR, "%s, invalid freq read: %u\n", __func__, chans->ic_chans[i].ic_freq);
            goto err;
        }
    }
    dprintf(MSG_MSGDUMP, "%s, channel info: %s\n", __func__, chanlist);
    ret = 0;

err:
    if (chans) {
        free(chans);
    }

    return ret;
}

int apacHyfi20GetWlanHWCapability(const int rindex, char *hwcaps)
{
    FILE *f;
    char fname[256];

    if (!hwcaps)
        return -1;

    snprintf(fname, sizeof(fname), "/sys/class/net/wifi%d/hwcaps", rindex -1);
    dprintf(MSG_DEBUG, "Reading HW Capacity from %s\n", fname);


    f = fopen(fname, "r");
    if (f == NULL) {
        dprintf(MSG_ERROR,
            "Could not open hwcaps file '%s' for reading.\n", fname);
        return -1;
    }

    if (fgets(hwcaps, 256, f) == NULL) {
        dprintf(MSG_ERROR,
            "Could not read hwcaps file '%s'.\n", fname);
        fclose(f);
        return -1;
    }

    fclose(f);
    return 0;
}

/**
 * @brief Get the maximum channel width the radio is capable of
 *
 * @param [in] rindex  the radio index
 * @param [in] is2G  whether the radio is 2G or not (5G)
 * @param [out] maxChWidth  the maximum channel width capability
 *
 * @return 0 on success; otherwise return -1
 */
static int apacHyfi20GetWlanMaxChwidth(const int rindex, int is2G,
                                       enum ieee80211_cwm_width *maxChWidth) {
    FILE *f;
    char fname[256];
    int ret = 0;

    if (!maxChWidth) { return -1; }

    if (is2G) {
        snprintf(fname, sizeof(fname), "/sys/class/net/wifi%d/2g_maxchwidth", rindex -1);
    } else {
        snprintf(fname, sizeof(fname), "/sys/class/net/wifi%d/5g_maxchwidth", rindex -1);
    }
    dprintf(MSG_DEBUG, "Reading max channel width supported from %s\n", fname);

    f = fopen(fname, "r");
    if (f == NULL) {
        dprintf(MSG_ERROR,
            "Could not open maxchwidth file '%s' for reading.\n", fname);
        return -1;
    } else {
        char chwidthStr[256];
        if (fgets(chwidthStr, sizeof(chwidthStr), f) == NULL) {
            dprintf(MSG_ERROR, "Could not read maxchwidth file '%s'.\n", fname);
            ret = -1;
        } else {
            if (strcmp(chwidthStr, "20") == 0) {
                *maxChWidth = IEEE80211_CWM_WIDTH20;
            } else if (strcmp(chwidthStr, "40") == 0) {
                *maxChWidth = IEEE80211_CWM_WIDTH40;
            } else if (strcmp(chwidthStr, "80") == 0) {
                *maxChWidth = IEEE80211_CWM_WIDTH80;
            } else if (strcmp(chwidthStr, "160") == 0) {
                *maxChWidth = IEEE80211_CWM_WIDTH160;
            } else {
                dprintf(MSG_ERROR, "Invalid maxchwidth read: %s\n", chwidthStr);
                ret = -1;
            }
        }
    }

    fclose(f);
    return ret;
}

/* 
GetWlanBestStandard
     Get a compatible standard according to current HW capacity
In:
    rindex: radio index
    chan:   channel
    regStd: registrar's standard
Return: 
    -1: errors
     0: success, the compatible standard is stored in "bestStd"
*/
int apacHyfi20GetWlanBestStandard(const int rindex, int chan, char* regStd, char **bestStd/*out*/)
{
    char hwcaps[256];
    int  is2G;
    enum ieee80211_cwm_width maxChWidth = IEEE80211_CWM_WIDTHINVALID;
    static struct best11naMode{
        int channel;
        char *bestmode;
    } modes[] = {
        {36, "na40plus"},   
        {40, "na40minus"}, 
        {44, "na40plus"},   
        {48, "na40minus"},    
        {52, "na40plus"},   
        {56, "na40minus"},
        {60, "na40plus"},      
        {64, "na40minus"},  
        {100, "na40plus"},    
        {104, "na40minus"},   
        {108, "na40plus"},   
        {112, "na40minus"},    
        {116, "na40plus"},    
        {120, "na40minus"}, 
        {124, "na40plus"},  
        {128, "na40minus"},
        {132, "na40plus"},  
        {136, "na40minus"},  
        {140, "na20"},
        {149, "na40plus"},   
        {153, "na40minus"}, 
        {157, "na40plus"},  
        {161, "na40minus"}, 
        {165, "na20"},
        {0  , NULL} 
    };

    if (!bestStd)
        return -1;
    *bestStd = NULL;

    /*QCA 2.4G implementation for 11ac*/
    if (chan > 0 && chan <= 14)
        is2G = 1;
    else
        is2G = 0;

    if (apacHyfi20GetWlanHWCapability(rindex, hwcaps) < 0)
        return -1;

    /*If peer is 11AC, but we don't support it.
      11AC         -->     11NA
      acvht20              na20
      acvht40plus          na40plus
      acvht40minus         na40minus
      acvht40/80           select best mode from table

      11AC         -->     11NG
      acvht20              ng20
      acvht40plus          ng40plus
      acvht40minus         ng40minus
      1-4                  ng40plus
      5-9/10-14            ng40minus  //world safe
    */
    if (!strstr(regStd, "acvht")
        ||strstr(hwcaps, "ac"))
    {
        if (strcmp(regStd, "acvht160") == 0 ||
            strcmp(regStd, "acvht80_80") == 0) {
            // Currently only check max channel width supported when receives
            // 160 MHz mode from CAP, since there may not be strong needs for
            // other cases given the platform this code will be running on.
            if (apacHyfi20GetWlanMaxChwidth(rindex, is2G, &maxChWidth) < 0) {
                return -1;
            }

            if (maxChWidth < IEEE80211_CWM_WIDTH160) {
                *bestStd = (char *)calloc(APAC_STD_MAX_LEN, sizeof(char));
                if (!*bestStd) {
                    dprintf(MSG_ERROR, "%s: calloc failed\n", __func__);
                    return -1;
                }
                snprintf(*bestStd, APAC_STD_MAX_LEN, "acvht%d0", 2 << maxChWidth);
                goto out;
            }
        }
        *bestStd = strdup(regStd);
        goto out;
    }

    if (is2G) {
        if (strcmp(regStd, "acvht20") == 0)
            *bestStd = strdup("ng20");
        else if (strcmp(regStd, "acvht40plus") == 0)
            *bestStd = strdup("ng40plus");
        else if (strcmp(regStd, "acvht40minus") == 0)
            *bestStd = strdup("ng40minus");
        else if (chan <= 4)
            *bestStd = strdup("ng40plus");
        else
            *bestStd = strdup("ng40minus");;
    } else {
        if (strcmp(regStd, "acvht20") == 0)
            *bestStd = strdup("na20");
        else if (strcmp(regStd, "acvht40plus") == 0)
            *bestStd = strdup("na40plus");
        else if (strcmp(regStd, "acvht40minus") == 0)
            *bestStd = strdup("na40minus");
        else /*acvht40, acvht80 or others*/
        {
            struct best11naMode *pMode;
            for(pMode = modes; pMode->channel; pMode++)
            {
                 if (pMode->channel == chan)
                 {
                     *bestStd = strdup(pMode->bestmode);
                     break;
                 }
            }
            if (!pMode->channel)
            {
                /*For auto channel, registrar should notify its channel soon*/
                if (chan == 0)
                    *bestStd = strdup("na20");
                else
                {
                    dprintf(MSG_ERROR, "%s: can't find the channel %d\n", __func__, chan);
                    return -1;
                }
            }
        }
    }

out:
    if (!*bestStd)
    {
        dprintf(MSG_ERROR, "%s: string allocation failed\n", __func__);
        return -1;
    }

    return 0;
}

int apacHyfi20GetAPChannelInfo( const char *iface, apacHyfi20ChanInfo_t *chaninfo)
{
    int32_t Sock;
    struct iwreq Wrq;
    u_int8_t     channel;
    int          iwparam;
    int          chwidth, choffset, offset;
    uint32_t     cfreq2;

    if (!iface) {
        dprintf(MSG_ERROR, "%s: Invalid arguments", __func__);
        goto out;
    }

    if ((Sock = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
        dprintf(MSG_ERROR, "%s: Create ioctl socket failed!", __func__);
        goto out;
    }

    if (fcntl(Sock, F_SETFL, fcntl(Sock, F_GETFL) | O_NONBLOCK)) {
        dprintf(MSG_ERROR, "%s: fcntl() failed", __func__);
        goto err;
    }

    strncpy(Wrq.ifr_name, iface, IFNAMSIZ);
    if (ioctl(Sock, SIOCGIWFREQ, &Wrq) < 0) {
        dprintf(MSG_ERROR, "%s: ioctl() failed, ifName: %s.\n", __func__, iface);
        goto err;
    }

    channel = ieee80211_mhz2ieee(Wrq.u.freq.m / 100000);
    dprintf(MSG_MSGDUMP, "%s: Interface %s, frequency %uHz channel %d\n", __func__, iface, Wrq.u.freq.m, channel);


    memset(&Wrq, 0, sizeof(struct iwreq));
    strncpy(Wrq.ifr_name, iface, IFNAMSIZ);
    iwparam = IEEE80211_PARAM_CHWIDTH;
    memcpy(Wrq.u.name, &iwparam, sizeof(iwparam));
    if (ioctl(Sock, IEEE80211_IOCTL_GETPARAM, &Wrq) < 0) {
        dprintf(MSG_ERROR, "%s: ioctl() failed, ifName: %s.\n", __func__, iface);
        goto err;
    }
    memcpy(&chwidth, Wrq.u.name, sizeof(chwidth));
    dprintf(MSG_MSGDUMP, "%s: Interface %s, channel width %d\n", __func__, iface, chwidth);

    memset(&Wrq, 0, sizeof(struct iwreq));
    strncpy(Wrq.ifr_name, iface, IFNAMSIZ);
    iwparam = IEEE80211_PARAM_CHEXTOFFSET;
    memcpy(Wrq.u.name, &iwparam, sizeof(iwparam));
    if (ioctl(Sock, IEEE80211_IOCTL_GETPARAM, &Wrq) < 0) {
        dprintf(MSG_ERROR, "%s: ioctl() failed, ifName: %s.\n", __func__, iface);
        goto err;
    }
    memcpy(&choffset, Wrq.u.name, sizeof(choffset));
    dprintf(MSG_MSGDUMP, "%s: Interface %s, channel offset %d", __func__, iface, choffset);

    switch( chwidth )
    {
    case IEEE80211_CWM_WIDTH20:
        chaninfo->ifreq1 = channel;
        chaninfo->ifreq2 = 0;
        chaninfo->offset = 0;
        break;

    case IEEE80211_CWM_WIDTH40:
        chaninfo->ifreq2 = 0;
        if (choffset == 1)
            chaninfo->ifreq1 = channel + 2;
        else if (choffset == -1)
            chaninfo->ifreq1 = channel - 2;
        else {
            dprintf(MSG_ERROR, "%s: Invalid channel offset for interface: %s\n", __func__, iface);
            goto err;
        }
        chaninfo->offset = choffset;
        break;

    case IEEE80211_CWM_WIDTH80:
        chaninfo->ifreq2 = 0;
        if (choffset == 1)
            chaninfo->ifreq1 = channel + 4;
        else if (choffset == -1)
            chaninfo->ifreq1 = channel - 4;
        else {
            dprintf(MSG_ERROR, "%s: Invalid channel offset for interface: %s\n", __func__, iface);
            goto err;
        }
        chaninfo->offset = choffset;
        break;

    case IEEE80211_CWM_WIDTH160: //160MHz or 80p80MHz
        memset(&Wrq, 0, sizeof(struct iwreq));
        strncpy(Wrq.ifr_name, iface, IFNAMSIZ);
        iwparam = IEEE80211_PARAM_SECOND_CENTER_FREQ;
        memcpy(Wrq.u.name, &iwparam, sizeof(iwparam));
        if (ioctl(Sock, IEEE80211_IOCTL_GETPARAM, &Wrq) < 0) {
            dprintf(MSG_ERROR, "%s: ioctl(IEEE80211_PARAM_SECOND_CENTER_FREQ) failed, "
                    "ifName: %s.\n", __func__, iface);
            goto err;
        }
        memcpy(&cfreq2, Wrq.u.name, sizeof(cfreq2));
        chaninfo->ifreq2 = ieee80211_mhz2ieee(cfreq2);
        dprintf(MSG_MSGDUMP, "%s: Interface %s, 2nd center freq %d\n",
                __func__, iface, chaninfo->ifreq2);

        if (chaninfo->ifreq2) { // 80p80 MHz
            offset = 4;
        } else { // 160 MHz
            offset = 8;
        }
        if (choffset == 1)
            chaninfo->ifreq1 = channel + offset;
        else if (choffset == -1)
            chaninfo->ifreq1 = channel - offset;
        else {
            dprintf(MSG_ERROR, "%s: Invalid channel offset for interface: %s", __func__, iface);
            goto err;
        }
        chaninfo->offset = choffset;
    	break;

    default:
    	dprintf(MSG_ERROR, "%s: Invalid channel width for interface: %s", __func__, iface);
        goto err;
    }
    chaninfo->width = chwidth;
    
    close(Sock);
    return 0;
err:
    close(Sock);
out:
    return -1;
}

int apacHyfi20Set80211Channel(const char *ifName, apacHyfi20WifiFreq_e freq) {
    /* Choose ng20 for 2G, and na40plus for 5G */
    const char WMODE_5G[] = "11NAHT40PLUS";
    const char WMODE_2G[] = "11NGHT20";
    char wmode[WMODE_NAMESIZE];
     
    int32_t Sock;
    struct iwreq Wrq;
    struct ieee80211req_chaninfo *chans;
    int i;
    apacBool_e found = APAC_FALSE;

    /*size coped to user space: 
     (sizeof(struct ieee80211req_chaninfo)/sizeof(__u32)) + 1)
     */
    chans = malloc((sizeof(struct ieee80211req_chaninfo)/sizeof(unsigned int) + 1) * sizeof(unsigned int));
    if (!chans)
    {
        dprintf(MSG_ERROR, "ERR to malloc chaninfo buffer\n");
        return -1;
    }

    /* read available channel information */
    if (get80211ChannelInfo(ifName, chans) < 0) {
        dprintf(MSG_ERROR, "%s, getWlanBandCapacity error\n", __func__);
        goto out;
    }

    if (!ifName) {
        dprintf(MSG_ERROR, "%s - Invalid arguments: ifName is NULL\n", __func__);
        goto out;
    }

    if ((Sock = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
        dprintf(MSG_ERROR, "%s: Create ioctl socket failed!\n", __func__);
        goto out;
    }

    if (fcntl(Sock, F_SETFL, fcntl(Sock, F_GETFL) | O_NONBLOCK)) {
        dprintf(MSG_ERROR, "%s: fcntl() failed", __func__);
        goto err;
    }

    os_memset(&Wrq, 0, sizeof(Wrq));
    strlcpy(Wrq.ifr_name, ifName, IFNAMSIZ);

    /* alway set channel to 0 */
    Wrq.u.freq.m = 0;
    Wrq.u.freq.e = 0;
    Wrq.u.freq.flags = IW_FREQ_AUTO;

    if (ioctl(Sock, SIOCSIWFREQ, &Wrq) < 0) {
        dprintf(MSG_ERROR, "%s: Set channel to 0 for %s failed", __func__, ifName);
        goto err;
    }

    /* set vap standard */
    for (i = 0; i < chans->ic_nchans; i ++) {
        
        if ( (chans->ic_chans[i].ic_freq / 1000) == 2 && freq == APAC_WIFI_FREQ_2 ) {
            strlcpy(wmode, WMODE_2G, sizeof(wmode));
            found = APAC_TRUE;
            break;
        }
        else if ( (chans->ic_chans[i].ic_freq / 1000) == 5 && freq == APAC_WIFI_FREQ_5 ) {
            strlcpy(wmode, WMODE_5G, sizeof(wmode));
            found = APAC_TRUE;
            break;
        }
    }

    if (!found) {
        dprintf(MSG_ERROR, "%s, couldn't set freq %u!\n", __func__, freq);
        goto err;
    }

    Wrq.u.data.pointer = (void *)wmode;
    Wrq.u.data.length = sizeof(wmode);    

    if (ioctl(Sock, IEEE80211_IOCTL_SETMODE, &Wrq) < 0) {
        dprintf(MSG_ERROR, "%s, ioctl setmode for '%s' failed: mode '%s'\n", __func__, wmode, ifName);
        goto err;
    }
    dprintf(MSG_DEBUG, "%s, ioctl setmode to '%s' for IF '%s' successful\n", __func__, wmode, ifName);

    free(chans);
    close(Sock);
    return 0;
err:
    free(chans);
    close(Sock);
out:
    return -1;
}

int apacHyfi20SetMediaTypeFromStr(char *str, apacHyfi20Data_t *pData, int index) {
    apacHyfi20IF_t *hyif = &(pData->hyif[index]);
    apacHyfi20AP_t *pAP = pData->ap;

    if (strcmp(str, "WLAN") == 0) {
        apacHyfi20WifiFreq_e freq;

        hyif->mediaType = APAC_MEDIATYPE_WIFI;
        hyif->nonPBC = APAC_FALSE;  /* PBC enabled by default */
        if (apacHyfi20GetDeviceMode(hyif) < 0
            || apacHyfi20GetVAPIndex(hyif) < 0
            || apacHyfi20GetBandFromMib(hyif->vapIndex, &(hyif->wifiFreq)) < 0 )
        {
            return -1;
        }

        if (hyif->wlanDeviceMode != APAC_WLAN_AP) {
            return 0;   /* done with STA */
        }

        int unmanaged = apacHyfi20IsWsplcdUnmanaged(hyif);
        if (unmanaged < 0) {
            dprintf(MSG_ERROR, "%s: Failed to resolve wsplcd unmanaged flag on %s\n",
                    __func__, hyif->ifName);
            return -1;
        } else if (unmanaged) {
            dprintf(MSG_DEBUG, "%s: %s is marked as WSPLCD unmanaged\n",
                    __func__, hyif->ifName);
            return 0;
        }

        /* lei: Currently only one 1905 AP per band is supported. If there is more than 
         * one AP per band found, information of the previous AP will be overwritten in pData->ap
         * (only remember the recent vap_index), but not pData->hyif
         */
        freq = hyif->wifiFreq;
        if (pAP[freq].valid) {
            dprintf(MSG_ERROR, "%s - Configuration Error: Freq %d has more than one 1905 AP, previous\
            information will be overwritten!\n", __func__, freq);
            //return -1;
        }

        pAP[freq].freq = freq;
        pAP[freq].vap_index = hyif->vapIndex;
        pAP[freq].ifName = hyif->ifName;
        pAP[freq].valid = APAC_TRUE;
        apacHyfi20GetChannel(&pAP[freq]);
        apacHyfi20GetAPMode(&pAP[freq]);
    }
    else if (strcmp(str, "PLC") == 0) {
        hyif->mediaType = APAC_MEDIATYPE_PLC;
        hyif->nonPBC = APAC_FALSE;  /* PBC enabled by default */
    }
    else if (strcmp(str, "ETHER") == 0) {
        hyif->mediaType = APAC_MEDIATYPE_ETH;
        hyif->nonPBC = APAC_TRUE;
    }
    else if (strcmp(str, "ESWITCH") == 0) {
        hyif->mediaType = APAC_MEDIATYPE_ETH;
        hyif->nonPBC = APAC_TRUE;
    }
    else if (strcmp(str, "MOCA") == 0) {
        hyif->mediaType = APAC_MEDIATYPE_MOCA;
        hyif->nonPBC = APAC_TRUE;
    }
    else if (strcmp(str, "WLAN_VLAN") == 0) {
        hyif->mediaType = APAC_MEDIATYPE_WIFI_VLAN;
        hyif->nonPBC = APAC_TRUE;
    }
    else {
        dprintf(MSG_ERROR, "Invalid Media type: %s!\n", str);
        return -1;
    }

    return 0;
}

#define WPA_GET_BE16(a) ((u16) (((a)[0] << 8) | (a)[1]))
#define WPA_PUT_BE16(a, val)            \
    do {                    \
            (a)[0] = ((u16) (val)) >> 8;    \
            (a)[1] = ((u16) (val)) & 0xff;  \
       } while (0)

int wps_dev_type_str2bin(const char *str, u8 dev_type[SIZE_8_BYTES])
{
	const char *pos;

	/* <categ>-<OUI>-<subcateg> */
	WPA_PUT_BE16(dev_type, atoi(str));
	pos = os_strchr(str, '-');
	if (pos == NULL)
		return -1;
	pos++;
	if (hexstr2bin(pos, &dev_type[2], 4))
		return -1;
	pos = os_strchr(pos, '-');
	if (pos == NULL)
		return -1;
	pos++;
	WPA_PUT_BE16(&dev_type[6], atoi(pos));

	return 0;
}

char * wps_dev_type_bin2str(const u8 dev_type[SIZE_8_BYTES], char *buf,
			    size_t buf_len)
{
	int ret;

	ret = os_snprintf(buf, buf_len, "%u-%08X-%u",
			  WPA_GET_BE16(dev_type), WPA_GET_BE32(&dev_type[2]),
			  WPA_GET_BE16(&dev_type[6]));
	if (ret < 0 || (unsigned int) ret >= buf_len)
		return NULL;

	return buf;
}

/* 
 * Read interface names and types and store them
 * Sample string: ath0:WLAN,ath1:WLAN
 * return 0 for sucess, else for error
 */
static int apac_config_interfaces(char *buf, /* input */ 
        apacBool_e is1905Interface, /* input */
        apacHyfi20Data_t *pData/* output */ ) 
{
    const int TOKEN_LEN = IFNAMSIZ + 8;
    char *token;
    char ifList[APAC_MAXNUM_HYIF][TOKEN_LEN];
    int i, j;
    int num_if = splitByToken(buf, APAC_MAXNUM_HYIF, TOKEN_LEN, (char *)ifList, ',');
    apacHyfi20IF_t *pIF = pData->hyif;
    char *typeStr; 

    for (j = 0; j < APAC_MAXNUM_HYIF; j++) {
        if (!pIF[j].valid) {
            break;
        }
    }

    for (i = 0; i < num_if; i++) {
        dprintf(MSG_MSGDUMP, "read: %s\n", ifList[i]);

        if (j >= APAC_MAXNUM_HYIF) {
            dprintf(MSG_ERROR, "%s - Can't set interface(%s): out of range! j: %d \n", __func__, ifList[i], j); 
            return -1;
        }

        token = strchr(ifList[i], ':');
        if (!token) {
            dprintf(MSG_ERROR, "split token error! string: %s, token: %s\n", ifList[i], token);
            return -1;
        }

        os_memcpy(pIF[j].ifName, ifList[i], (token - ifList[i]));
        typeStr = token + 1;
        
        dprintf(MSG_MSGDUMP, "write ifname: %s\n", pIF[j].ifName);
        if (apacHyfi20SetMediaTypeFromStr(typeStr, pData, j) < 0) {
            return -1;
        }
        pIF[j].is1905Interface = is1905Interface; 
        pIF[j].valid = APAC_TRUE;

        j++;
    } 

    return 0;
}

/**
 * @brief Handle the interfaces that are marked as not push button
 *        configuration enabled, marking them as such so that PBC
 *        is skipped for them when activating it.
 *
 * @param [in] buf  the list of comma separated interfaces
 * @param [out] pData  the structure being populated
 *
 * @return 0 on success; non-zero on failure
 */
static int apac_config_nonpbc(char *buf, /* input */
        apacHyfi20Data_t *pData/* output */ )
{
    const int TOKEN_LEN = IFNAMSIZ + 1;
    char ifList[APAC_MAXNUM_HYIF][TOKEN_LEN];
    int i, j, numValidIfaces;
    int num_if = splitByToken(buf, APAC_MAXNUM_HYIF, TOKEN_LEN, (char *)ifList, ',');
    apacHyfi20IF_t *pIF = pData->hyif;
    apacBool_e found;

    for (numValidIfaces = 0; numValidIfaces < APAC_MAXNUM_HYIF; numValidIfaces++) {
        if (!pIF[numValidIfaces].valid) {
            break;
        }
    }

    for (i = 0; i < num_if; i++) {
        dprintf(MSG_MSGDUMP, "Recording %s as non-PBC\n", ifList[i]);

        // Find the matching interface (if any) and mark it as non-PBC.
        found = APAC_FALSE;
        for (j = 0; j < numValidIfaces; ++j) {
            if (strncmp(pIF[j].ifName, ifList[i], IFNAMSIZ) == 0) {
                pIF[j].nonPBC = APAC_TRUE;
                found = APAC_TRUE;
                break;
            }
        }

        if (!found) {
            dprintf(MSG_ERROR, "%s: Failed to find interface: %s\n",
                    __func__, ifList[i]);
            return -1;
        }
    }

    return 0;
}


/* breaks up a configuration input line:
 *      -- empty lines, or with only a #... comment result in no error
 *              but result in return of empty string.
 *      -- lines of form tag=value are broken up; whitespace before
 *              and after tag and before and after value is discarded,
 *              but otherwise retained inside of value.
 *      -- other lines result in NULL return.
 *
 *      The tag pointer is the return value.
 */
char * apac_config_line_lex(
        char *buf,      /* input: modified as storage for results */
        char **value_out        /* output: pointer to value (null term) */
        )
{
        char *pos;
        char *value;

        /* Trim leading whitespace, including comment lines */
        for (pos = buf; ; pos++) {
                if (*pos == 0)  {
                        *value_out = pos;
                        return pos;
                }
                if (*pos == '\n' || *pos == '\r' || *pos == '#') {
                        *pos = 0;
                        *value_out = pos;
                        return pos;
                }
                buf = pos;
                if (isgraph(*pos)) break;
        }
        while (isgraph(*pos) && *pos != '=') pos++;
        if (*pos == '=') {
                *pos++ = 0;     /* null terminate the tag */
                *value_out = value = pos;
        } else {
                return NULL;
        }
        /* Trim trailing whitepace. Spaces inside of a value are allowed,
         * as are other arbitrary non-white text, thus no comments on
         * end of lines.
         */
        for (pos += strlen(pos); --pos >= value; ) {
                if (isgraph(*pos)) break;
                *pos = 0;
        }
        return buf;
}

/* apply a configuration line: for wsplcd.conf
 */
static int apac_config_apply_line(
        apacHyfi20Data_t* pData, 
        char *tag,
        char *value,
        int line       /* for diagnostics */
        )
{
    apacHyfi20Config_t *pConfig = &pData->config;		
    struct wps_config *pWpsConfig = pConfig->wpsConf;
    /*HyFi 1.0 compatability*/
    WSPLCD_CONFIG *hyfi10Config = &HYFI20ToHYFI10(pData)->wsplcConfig;

    dprintf(MSG_MSGDUMP, "%s, tag: %s, value: %s\n", __func__, tag, value);

    if (strcmp(tag, "role") == 0) {
        apacHyfi20Role_e role;		
        role = atoi(value);
	    pConfig->role = role;
	    qca_role=role;
    }
    else if (strcmp (tag, "designated_pb_ap") == 0) {
        pConfig->designated_pb_ap_enabled = (atoi(value) == 0 ? APAC_FALSE : APAC_TRUE);
    }
    else if (strcmp(tag, "debug_level") == 0) {
        pConfig->debug_level = atoi(value);
        debug_level = pConfig->debug_level;
    } else if (strcmp(tag, "bridge") == 0) {
        strncpy((pData->bridge).ifName, value, IFNAMSIZ);
    } else if (strcmp(tag, "cfg_changed") == 0) {
        pConfig->cfg_changed = atoi(value);
	qca_cfg_changed=atoi(value);
    } else if (strcmp(tag, "cfg_apply_timeout") == 0) {
        pConfig->cfg_apply_timeout = atoi(value);
        apac_cfg_apply_interval = pConfig->cfg_apply_timeout;
    } else if (strcmp(tag, "cfg_restart_long_timeout") == 0) {
        pConfig->cfg_restart_long_timeout = atoi(value);
        apac_cfg_restart_long_interval = pConfig->cfg_restart_long_timeout;
    } else if (strcmp(tag, "cfg_restart_short_timeout") == 0) {
        pConfig->cfg_restart_short_timeout = atoi(value);
        apac_cfg_restart_short_interval = pConfig->cfg_restart_short_timeout;
    }
    else if (strncmp(tag, "1905Interfaces", 14) == 0) {
        dprintf(MSG_MSGDUMP, "tag: %s,\tvalue: %s\n", tag, value);
        if (apac_config_interfaces(value, APAC_TRUE, pData) < 0) {
            goto failure;
        }
    }
    else if (strcmp(tag, "Non1905InterfacesWlan") == 0) {
        dprintf(MSG_MSGDUMP, "tag: %s,\tvalue: %s\n", tag, value);
        if (apac_config_interfaces(value, APAC_FALSE, pData) < 0) {
            goto failure;
        }
    } 
    else if (strcmp(tag, "NonPBCInterfaces") == 0) {
        dprintf(MSG_MSGDUMP, "tag: %s,\tvalue: %s\n", tag, value);
        if (apac_config_nonpbc(value, pData) < 0) {
            goto failure;
        }
    }
    else if (strcmp(tag, "WPS_method") == 0) {
        if (strncmp(value, "M2", 2) == 0) {
            pConfig->wps_method = APAC_WPS_M2;
        }
        else {
            pConfig->wps_method = APAC_WPS_M8;
        }
    }
    else if (strcmp(tag, "config_station") == 0) {
        if (strncmp(value, "yes", 3) == 0) {
            pConfig->config_sta = APAC_TRUE;
        }
        else {
            pConfig->config_sta = APAC_FALSE;
        }
    }
    else if (strcmp(tag, "ssid_suffix") == 0) {
        strcpy(pConfig->ssid_suffix, value);
    }
    else if (strcmp(tag, "1905Nwkey") == 0) {
        strncpy(pConfig->ucpk, value, 64);
    }
    else if (strcmp(tag, "ucpk_salt") == 0) {
        strncpy(pConfig->salt, value, 64);
    }
    else if (strcmp(tag, "wpa_passphrase_type") == 0) {
        pConfig->wpa_passphrase_type = atoi(value);
    }
    else if (strcmp(tag, "APCloning") == 0) {
        pConfig->hyfi10_compatible = atoi(value);
    }
    else if (strcmp(tag, "search_timeout") == 0) {
        pConfig->search_to = atoi(value);
    }
    else if (strcmp(tag, "WPS_session_timeout") == 0) {
        pConfig->wps_session_to = atoi(value);
    }
    else if (strcmp(tag, "WPS_retransmission_timeout") == 0) {
        pConfig->wps_retransmit_to = atoi(value);
    }
    else if (strcmp(tag, "WPS_per_message_timeout") == 0) {
        pConfig->wps_per_msg_to = atoi(value);
    }
    else if (strcmp(tag, "band_sel_enable") == 0) {
        pConfig->band_sel_enabled = atoi(value);
    }
    else if (strcmp(tag, "band_choice") == 0) {
        if (strncmp(value, "5G", 2) == 0) {
            pConfig->band_choice = APAC_WIFI_FREQ_5;
        }
        else if (strncmp(value, "2G", 2) == 0) {
            pConfig->band_choice = APAC_WIFI_FREQ_2;
        }
    }
    else if (strcmp(tag, "rm_collect_timeout") == 0) {
        pConfig->rm_collect_to = atoi(value);
    }
    else if (strcmp(tag, "deep_clone_enable") == 0) {
        pConfig->deep_clone_enabled = atoi(value);
    }
    else if (strcmp(tag, "deep_clone_no_bssid") == 0) {
        pConfig->deep_clone_no_bssid = atoi(value);
    }
    else if (strcmp(tag, "manage_vap_ind") == 0) {
        pConfig->manage_vap_ind = atoi(value);
    }
    else if (strcmp(tag, "wait_wifi_config_secs_other") == 0) {
        pConfig->wait_wifi_config_secs_other = atoi(value);
    }
    else if (strcmp(tag, "wait_wifi_config_secs_first") == 0) {
        pConfig->wait_wifi_config_secs_first = atoi(value);
    }
    /* attributes for wps_config */
    else if (strcmp(tag, "version") == 0) {
            pWpsConfig->version = strtoul(value, NULL, 16);
    } else if (strcmp(tag, "uuid") == 0) {
        struct wps_config *wps = pWpsConfig;
        if (hexstr2bin(value, wps->uuid, SIZE_16_BYTES) ||
            value[SIZE_16_BYTES * 2] != '\0') {
            dprintf(MSG_ERROR, "Line %d: Invalid UUID '%s'.", line, value);
                goto failure;
        }
        wps->uuid_set = 1;
    }
    else if (strcmp(tag, "config_methods") == 0) {
        //printf("strtoul: %lu\n", strtoul(value, NULL, 16));

        //FIXME pWpsConfig->config_methods = 0; //strtoul(value, NULL, 16);
    }
    else if (strcmp(tag, "manufacturer") == 0) {
        free(pWpsConfig->manufacturer);
        #if WPS_HACK_PADDING() /* a work around */
        pWpsConfig->manufacturer_len = 64;        /* wps spec */
        if (((pWpsConfig->manufacturer = os_zalloc(64+1))) == NULL)
                goto failure;
        strncpy(pWpsConfig->manufacturer, value, 64);
        #else   /* original */
        if ((pWpsConfig->manufacturer = strdup(value)) == NULL) 
                goto failure;
        pWpsConfig->manufacturer_len = strlen(pWpsConfig->manufacturer);
        #endif  /* WPS_HACK_PADDING */
    } else if (strcmp(tag, "model_name") == 0) {
        free(pWpsConfig->model_name);
        #if WPS_HACK_PADDING() /* a work around */
        pWpsConfig->model_name_len = 32;  /* wps spec */
        if ((pWpsConfig->model_name = os_zalloc(32+1)) == NULL) 
                goto failure;
        strncpy(pWpsConfig->model_name, value, 32);
        #else   /* original */
        if ((pWpsConfig->model_name = strdup(value)) == NULL) 
                goto failure;
        pWpsConfig->model_name_len = strlen(pWpsConfig->model_name);
        #endif  /* WPS_HACK_PADDING */
    } else if (strcmp(tag, "model_number") == 0) {
        free(pWpsConfig->model_number);
        #if WPS_HACK_PADDING() /* a work around */
        pWpsConfig->model_number_len = 32;        /* wps spec */
        if ((pWpsConfig->model_number = os_zalloc(32+1)) == NULL) 
                goto failure;
        strncpy(pWpsConfig->model_number, value, 32);
        #else   /* original */
        if ((pWpsConfig->model_number = strdup(value)) == NULL) 
                goto failure;
        pWpsConfig->model_number_len = strlen(pWpsConfig->model_number);
        #endif  /* WPS_HACK_PADDING */
    } else if (strcmp(tag, "serial_number") == 0) {
        free(pWpsConfig->serial_number);
        #if WPS_HACK_PADDING() /* a work around */
        pWpsConfig->serial_number_len = 32;       /* wps spec */
        if ((pWpsConfig->serial_number = os_zalloc(32+1)) == NULL) 
                goto failure;
        strncpy(pWpsConfig->serial_number, value, 32);
        #else   /* original */
        if ((pWpsConfig->serial_number = strdup(value)) == NULL) 
                goto failure;
        pWpsConfig->serial_number_len = strlen(pWpsConfig->serial_number);
        #endif  /* WPS_HACK_PADDING */
	} else if (strcmp(tag, "device_type") == 0) {
        if (wps_dev_type_str2bin(value, pWpsConfig->prim_dev_type))
            goto failure;
    } else if (strcmp(tag, "device_name") == 0) {
        free(pWpsConfig->dev_name);
        #if WPS_HACK_PADDING() /* a work around */
        pWpsConfig->dev_name_len = 32;
        if ((pWpsConfig->dev_name = os_zalloc(32+1)) == NULL) 
                goto failure;
        strncpy(pWpsConfig->dev_name, value, 32);
        #else   /* original */
        if ((pWpsConfig->dev_name = strdup(value)) == NULL) 
                goto failure;
        pWpsConfig->dev_name_len = strlen(pWpsConfig->dev_name);
        #endif  /* WPS_HACK_PADDING */
    } else if (strcmp(tag, "os_version") == 0) {
        //pWpsConfig->os_version = strtoul(value, NULL, 16);
        //printf("osv: %lu\n", strtoul(value, NULL, 16)); //pWpsConfig->os_version);
    }
    /*HyFi 1.0 compatability*/
    else if (strcmp(tag, "clone_timeout") == 0) {
        hyfi10Config->clone_timeout = atoi(value);
    }
    else if (strcmp(tag, "walk_timeout") == 0) {
        hyfi10Config->walk_timeout = atoi(value);
    } 
    else if (strcmp(tag, "repeat_timeout") == 0) {
        hyfi10Config->repeat_timeout = atoi(value);
    }
    else if (strcmp(tag, "internal_timeout") == 0) {
        hyfi10Config->internal_timeout = atoi(value);
    }
    else if (strcmp(tag, "button_mode") == 0) {
        int mode;		
        mode = atoi(value);
        if (mode != WSPLC_ONE_BUTTON && mode != WSPLC_TWO_BUTTON)
        {
            dprintf(MSG_ERROR,"INVALID button mode (%s)specified, exiting\n", value);
            goto failure;
        }
        hyfi10Config->button_mode = mode;
    }
    else if (strcmp(tag, "atf_config_en") == 0) {
        pConfig->atf_config_enabled = (atoi(value) == 0 ? APAC_FALSE : APAC_TRUE);
        dprintf(MSG_INFO,"atf_config set to %d \n", pConfig->atf_config_enabled);
    }
    /*End of HyFi 1.0*/
    
    return 0;

 failure:
    dprintf(MSG_ERROR, "Config parse failure, line %d\n", line);
    return -1;
}


int apac_config_parse_file(apacHyfi20Data_t *pData, const char *fname)
{
    FILE *f;
    char buf[256];
    int line = 0;
    int errors = 0;

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

    dprintf(MSG_DEBUG, "Reading wsplcd 2.0 configuration file %s ...\n", fname);

    f = fopen(fname, "r");
    if (f == NULL) {
        dprintf(MSG_ERROR,
            "Could not open configuration file '%s' for reading.\n",
            fname);
        return -1;
    }

    while (fgets(buf, sizeof(buf), f) != NULL) {
        char *tag;
        char *value;
    
        line++;
        tag = apac_config_line_lex(buf, &value);
        if (tag == NULL) {
            //errors++;
            continue;
        }
        if (*tag == 0) 
            continue;        /* empty line */
        if (apac_config_apply_line(pData, tag, value, line)) {
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

void apacHyfi20ConfigInit(apacHyfi20Data_t *ptrData)
{
    apacHyfi20Config_t *ptrConfig = &ptrData->config;
    apacHyfi20IF_t *ptrIF = ptrData->hyif;
    apacHyfi20AP_t *pAP;
    int i, index;
    int num_radio;

    apacHyfi20TRACE();

    ptrConfig->wpsConf = os_malloc(sizeof(struct wps_config));

    /* Init MID */
    messageId_init();

    /* Init apacS */
    memset(&apacS, 0, sizeof(apacS));
    for (i = 0; i < APAC_NUM_WIFI_FREQ; i++) {
        ptrData->ap[i].freq = i; 
        apacS.searchMidSent[i].freq = i;
    }
    apacS.pApacData = ptrData;

    /* Set configuration parameters */
    ptrConfig->role = APAC_REGISTRAR;  
    ptrConfig->search_to = APAC_SEARCH_TIMEOUT;
    ptrConfig->pushbutton_to  = APAC_PUSHBUTTON_TIMEOUT;
    ptrConfig->pb_search_to = APAC_PB_SEARCH_TIMEOUT;
    ptrConfig->config_sta = APAC_CONFIG_STA;
    ptrConfig->wps_method = APAC_WPS_METHOD;
    ptrConfig->wps_session_to = APAC_WPS_SESSION_TIMEOUT;
    ptrConfig->wps_retransmit_to = APAC_WPS_RETRANSMISSION_TIMEOUT;
    ptrConfig->wps_per_msg_to = APAC_WPS_MSG_PROCESSING_TIMEOUT;
    ptrConfig->debug_level = MSG_INFO; 
    ptrConfig->pbmode_enabled = APAC_FALSE;
    ptrConfig->hyfi10_compatible = APAC_FALSE;	
    ptrConfig->band_sel_enabled = APAC_TRUE;
    ptrConfig->band_choice = APAC_WIFI_FREQ_5;
    ptrConfig->rm_collect_to = APAC_RM_COLLECT_TIMEOUT;
    ptrConfig->deep_clone_enabled = APAC_TRUE;
    ptrConfig->deep_clone_no_bssid = APAC_TRUE;
    ptrConfig->manage_vap_ind = APAC_TRUE;
    ptrConfig->designated_pb_ap_enabled = APAC_FALSE;
    ptrConfig->wait_wifi_config_secs_first = APAC_WAIT_WIFI_CONFIG_SECS_FIRST;
    ptrConfig->wait_wifi_config_secs_other = APAC_WAIT_WIFI_CONFIG_SECS_OTHER;
    ptrConfig->atf_config_enabled = APAC_FALSE;
    ptrConfig->atfConf = NULL;
    get_2g=0;
    get_5g=0;

    for (i = 0; i < APAC_MAXNUM_HYIF; i++) {
        ptrIF[i].ifIndex = -1;
        ptrIF[i].ifName[0] = '\0';
    }

    /* get configurable paramters, interface and other info from masterd */
    if (apac_config_parse_file(ptrData, g_cfg_file) < 0) {
        dprintf(MSG_ERROR, "parse config file (%s) error!\n", g_cfg_file);
        return;
    }

    if(ptrConfig->atf_config_enabled == APAC_TRUE)
    {
        dprintf(MSG_INFO, "ATF Configuration Enabled! Parsing ATF configuration File \n\r");
        ptrConfig->atfConf = os_malloc( (sizeof(ATF_REP_CONFIG) * ATF_MAX_REPEATERS) );

        if(ptrConfig->atfConf != NULL)
        {

            if (apac_atf_config_parse_file(ptrData, g_cfg_file) < 0) {
                dprintf(MSG_ERROR, "parse ATF config file (%s) error!\n", g_cfg_file);
                return;
            }
        } else {
            dprintf(MSG_ERROR, "Mem alloc for ATF Config structure failed!!\n\r");
            return;
        }
    }

    /* Now check config_sta: run APAC even if there is only STA (no AP) for a given band */
    if (ptrConfig->config_sta) {
        for (i = 0; i < APAC_MAXNUM_HYIF; i++) {

            /* for 1905 STA */
            if (ptrIF[i].valid && 
                ptrIF[i].is1905Interface && 
                ptrIF[i].mediaType == APAC_MEDIATYPE_WIFI &&
                ptrIF[i].wlanDeviceMode == APAC_WLAN_STA) 
            {  
                /* check if AP is there */
                apacHyfi20WifiFreq_e freq = ptrIF[i].wifiFreq;
                if (freq == APAC_WIFI_FREQ_INVALID)
                    continue;

                pAP = &(ptrData->ap[freq]);
                
                if (pAP->valid == APAC_FALSE) {
                    dprintf(MSG_INFO, "%s, Band %u has 1905 Station, but not 1905 AP. Enable APAC\n",
                            __func__, freq);
                    pAP->freq = freq;
                    pAP->isAutoConfigured = APAC_FALSE;
                    pAP->vap_index = ptrIF[i].vapIndex;
                    pAP->isStaOnly = APAC_TRUE;
                    pAP->valid = APAC_TRUE;
                }
            }

        }
    }

    /* Check DB band adaptation */
    num_radio = 0;
    index = -1;
    pAP = ptrData->ap;
    for (i = 0; i < APAC_NUM_WIFI_FREQ; i++) {
        if (pAP[i].valid) {
            num_radio++;

            if (num_radio == 1) 
                index = i;
        }
    }
    
    if (num_radio < 0 || num_radio > 2) {
        dprintf(MSG_ERROR, "%s, number of radio is %u, invalid\n", __func__, num_radio);
        return;
    }
    
    /* For single radio, check if it is SB or DB */
    if (num_radio == 1) {
        char liststr[MAXCHANLISTSTRLEN];
        apacBool_e hasWlan2G = APAC_FALSE;
        apacBool_e hasWlan5G = APAC_FALSE;

        if (index == -1) {
            dprintf(MSG_ERROR, "%s, index is not assigned value!\n", __func__);
            return;
        }

        if (pAP[index].isStaOnly == APAC_FALSE) {
            if (apacHyfi20GetWlanBandCapacity(pAP[index].ifName, liststr, &hasWlan2G, &hasWlan5G) < 0) {
                dprintf(MSG_ERROR, "%s, Failed to get Channel Info for %s\n", __func__, pAP[index].ifName);
                return;
            }
        }
        else {  /* Can't find ifName from pAP if band has only STA */
            int j;
            apacBool_e found = APAC_FALSE;

            for (j = 0; j < APAC_MAXNUM_HYIF; j++) {
                if (ptrIF[j].wifiFreq == pAP[index].freq) {
                    found = APAC_TRUE;
                    break;
                }
            }

            if (!found) {
                dprintf(MSG_ERROR, "%s, Can't find IF on Freq %u!\n", __func__, pAP[index].freq);
                return;
            }
            
            if (apacHyfi20GetWlanBandCapacity(ptrIF[j].ifName, liststr, &hasWlan2G, &hasWlan5G) < 0) {
                dprintf(MSG_ERROR, "%s, Can't get Channel Info for %s\n", __func__, ptrIF[j].ifName);
                return;
            }
        }
        
        if (hasWlan2G && hasWlan5G) {
            pAP[index].isDualBand = APAC_TRUE;
            ptrConfig->wlan_chip_cap = APAC_DB;
            dprintf(MSG_DEBUG, "%s, IF %s is dual band\n", __func__, pAP[index].ifName);
        }
        else if (hasWlan2G || hasWlan5G) {
            ptrConfig->wlan_chip_cap = APAC_SB;
        }
        else {
            dprintf(MSG_ERROR, "%s, can't get channel capacity info for AP %s!\n", __func__, pAP[index].ifName);
            return;
        }
    }
    else if (num_radio == 2) {
        ptrConfig->wlan_chip_cap = APAC_DBDC;
    }
}

void apacHyfi20ConfigDump(apacHyfi20Data_t *ptrData)
{
    apacHyfi20Config_t *ptrConfig = &ptrData->config;
    apacHyfi20AP_t *ptrAP = ptrData->ap;
    apacHyfi20IF_t *ptrIF = ptrData->hyif;
    //struct wps_config *pWpsConfig = ptrConfig->wpsConf;
    int dumpLevel = MSG_INFO;

    int i;

    dprintf(dumpLevel, "Configuration dump begin\n");
    if (ptrConfig->role == APAC_ENROLLEE) {
        dprintf(dumpLevel, "Device is Enrollee\n");
    }
    else if(ptrConfig->role == APAC_REGISTRAR) {
        dprintf(dumpLevel, "Device is Registrar\n");
    }
    else {
        dprintf(dumpLevel, "Device is neither Registrar nor Enrollee\n");
    }

    dprintf(dumpLevel, "Debug Level: %d\n", ptrConfig->debug_level);
    dprintf(dumpLevel, "WPS method: %s\n", (ptrConfig->wps_method == APAC_WPS_M2 ? "M2" : "M8"));
    dprintf(dumpLevel, "Config Station: %s\n", (ptrConfig->config_sta == APAC_TRUE ? "YES" : "NO"));
    dprintf(dumpLevel, "SSID Suffix: '%s'\n", ptrConfig->ssid_suffix);
    dprintf(dumpLevel, "Search Timeout: %d\n", ptrConfig->search_to);
    dprintf(dumpLevel, "WPS Session Timeout: %d\n", ptrConfig->wps_session_to);
    dprintf(dumpLevel, "WPS Retransmission Timeout: %d\n", ptrConfig->wps_retransmit_to);
    dprintf(dumpLevel, "WPS Per-Message Timeout: %d\n", ptrConfig->wps_per_msg_to);
    dprintf(dumpLevel, "DB Band Adaptation: %s\n", (ptrConfig->band_sel_enabled == APAC_TRUE ? "YES" : "NO"));
    if (ptrConfig->band_sel_enabled) {
        dprintf(dumpLevel, "Preferred Band Choice: %s\n", (ptrConfig->band_choice == APAC_WIFI_FREQ_2 ? "2G" : "5G"));
        dprintf(dumpLevel, "Waiting Response Msg Interval: %u\n", ptrConfig->rm_collect_to);
    }
    dprintf(dumpLevel, "Deep Cloning: %s\n", (ptrConfig->deep_clone_enabled == APAC_TRUE ? "YES" : "NO"));
    dprintf(dumpLevel, "Deep Cloning Without BSSID: %s\n", (ptrConfig->deep_clone_no_bssid == APAC_TRUE ? "YES" : "NO"));
    dprintf(dumpLevel, "Manage VAP Independent: %s\n", (ptrConfig->manage_vap_ind == APAC_TRUE ? "YES" : "NO"));
    
    dprintf(dumpLevel, "1905.1 UCPK: %s\n", ptrConfig->ucpk);
    dprintf(dumpLevel, "1905.1 SALT: %s\n", ptrConfig->salt);
    dprintf(dumpLevel, "Compatiable with Hyfi1.0: %c\n", (ptrConfig->hyfi10_compatible == APAC_TRUE ? 'y':'n'));

#if 0
    dprintf(dumpLevel, "WPS info:\n");
    dprintf(dumpLevel, "version: %x\n", pWpsConfig->version); 
    dprintf(dumpLevel, "config_methods: %u\n", pWpsConfig->config_methods);
    dprintf(dumpLevel, "manufacturer: %s\n", pWpsConfig->manufacturer);
    dprintf(dumpLevel, "model_name: %s\n", pWpsConfig->model_name);
    dprintf(dumpLevel, "model_number: %s\n", pWpsConfig->model_number);
    dprintf(dumpLevel, "serial_number: %s\n", pWpsConfig->serial_number);
    dprintf(dumpLevel, "dev_name: %s\n", pWpsConfig->dev_name);
    dprintf(dumpLevel, "os_version: %s\n", pWpsConfig->os_version);
#endif

    dprintf(dumpLevel, "1905 AP info:\n");
    for (i = 0; i < APAC_NUM_WIFI_FREQ; i++) {
        if (!ptrAP[i].valid)
            continue;

        dprintf(dumpLevel, "AP%d freq: %d, vap_index: %u\n", i, ptrAP[i].freq, ptrAP[i].vap_index);

        if (ptrConfig->role == APAC_ENROLLEE) {
            continue;
        }
    }
    for (i = 0; i < APAC_MAXNUM_HYIF; i++) {
        if (!ptrIF[i].valid)
            continue;

        dprintf(dumpLevel, "Interface%d name: %s, 1905IF: %c \tmediatype: %u",
                            i, ptrIF[i].ifName, (ptrIF[i].is1905Interface ? 'y' : 'n'), 
                            ptrIF[i].mediaType);
        if (strncmp(ptrIF[i].ifName, "ath", 3) == 0) {
            dprintf(dumpLevel, "\n\t\tWLAN device mode: %u \tfreq: %u \tvapIndex: %u\n", 
                                ptrIF[i].wlanDeviceMode, ptrIF[i].wifiFreq, ptrIF[i].vapIndex); 
        }
        else {
            dprintf(dumpLevel, "\n");
        }
    }

    dprintf(dumpLevel, "Configuration dump end\n");	
}

void apacHyfi20CmdLogFileMode(int argc, char **argv)
{
    int c;

    for (;;) {
        c = getopt(argc, argv, "f:r:l:o:c:wa");
        if (c < 0)
            break;
        switch (c) {
        case 'w':
            /* Write debug log to file */
            printf("Write debug log to file: %s\n", APAC_LOG_FILE_PATH);
            logFileMode = APAC_LOG_FILE_TRUNCATE;
            break;
        case 'a':
            /* Append debug log to file */
            printf("Append debug log to file: %s\n", APAC_LOG_FILE_PATH);
            logFileMode = APAC_LOG_FILE_APPEND;
            break;
        default:
            /* Handled separately in apacHyfi20CmdConfig */
            break;
        }
    }
}


void apacHyfi20CmdConfig(apacHyfi20Data_t *pData, int argc, char **argv)
{
    apacHyfi20Config_t *pConfig = &(pData->config);
    char* val = NULL;
    int dlevel;
    int c;
    int custom_cfg_file = 0;

    /* command line debug */
    for (;;) {
        c = getopt(argc, argv, "f:r:l:o:c:wa");
        if (c < 0)
            break;
        switch (c) {

        /* send unicast packets from ALL Interfaces. Debug only! */
        case 'f': 
            printf("\n\nForward Unicast (Response/WPS) packets from ALL interfaces\n");
            pConfig->sendOnAllIFs = APAC_TRUE;
            break;

        case 'r':
            val = optarg;
            if (strncmp(val, "r", 1) == 0) {
                pConfig->role = APAC_REGISTRAR;
            }
            else if (strncmp(val, "e", 1) == 0) {
                pConfig->role = APAC_ENROLLEE;
            }
            else
            {
                printf("INVALID role (%s)specified, exiting\n", val);
                exit(1);
            }
            break;

        case 'l': 
            dlevel = atoi(optarg);
            printf("debug level: %d\n", dlevel);
            
            if (dlevel < 0 || dlevel > 3) {
                printf("Invalid debug level: %d\n", dlevel);
                debug_level = pConfig->debug_level;
            }
            else {
                printf("change debug level from %d to %d\n", debug_level, dlevel);
                debug_level = dlevel;
            }
            break;

        case 'o':
            val = optarg;
            printf("option: %s\n", val);

            /* Virtually activate Push Button */
            if (strncmp(val, "p", 1) == 0) {
                printf("\n\nEnable Push Button function for wsplcd .... \n");
                                              
                pbcHyfi20EventPushButtonActivated(pData);
            }
            else if (strncmp(val, "v", 1) == 0) { 
                /* print version */
                printf("wsplcd-2.0 IEEE1905 AP Auto-Configuration.\n");
                printf("Copyright (c) 2011-2012 Qualcomm Atheros, Inc.\n");
                printf("Qualcomm Atheros Confidential and Proprietary.\n");
                printf("All rights reserved.\n");
                printf("Additional copyright information:\n");
                printf("Copyright (c) 2006-2007 Sony Corporation. All Rights Reserved.\n");
                printf("Copyright (c) 2002-2007 Jouni Malinen <j@w1.fi> and contributors. All Rights Reserved.\n\n");
            }
            else {
                printf("invalid option: %s\n", val);
            }
            break;
        case 'c':
            /*configuration file path*/
            custom_cfg_file = 1;
            strlcpy(g_cfg_file, optarg, APAC_CONF_FILE_NAME_MAX_LEN);
            break;    
        case 'w':
        case 'a':
            /* Handled separately in apacHyfi20CmdLogFileMode */
            break;
        default:
            printf("Invalid argument: %c\n", c);
            break;
        }
    }

    if (custom_cfg_file == 0) {
        /* use default config file if not specified by -c option */
        strlcpy(g_cfg_file, APAC_CONF_FILE_PATH, APAC_CONF_FILE_NAME_MAX_LEN);
    }


    if (optind != argc)
        return;

}

int apacHyfi20Init(apacHyfi20Data_t *pData) {
    s32 i;
    apacHyfi20IF_t *pIF = pData->hyif;
    
    apacHyfi20TRACE();

    if (apacHyfi20InitDeviceInfo(pData) < 0) {
        perror("InitDeviceInfo");
        return -1;
    }

    /* bridge */
    memcpy(pData->alid, pData->bridge.mac_addr, ETH_ALEN);
   
    pData->nlSock = apacHyfi20InitNLSock(pData);
    if (pData->nlSock < 0) {
        perror("InitNLSock");
        return -1;
    }
    dprintf(MSG_MSGDUMP, "nl sock: %d\n", pData->nlSock);

    eloop_register_read_sock(pData->nlSock, pbcHyfi20GetNLMsgCB, pData, NULL);
    
    pData->pipeFd = apacHyfi20InitPipeFd();
    if (pData->pipeFd < 0) {
        perror("InitPipe");
        return -1;          
    }   
    dprintf(MSG_MSGDUMP, "pipe FD: %d\n", pData->pipeFd);
    eloop_register_read_sock(pData->pipeFd, pbcHyfi20GetPipeMsgCB, pData, NULL);

#ifdef ENABLE_PLC
    pData->unPlcSock = apacHyfi20InitPlcUnixSock(pData);
    if (pData->unPlcSock < 0) {
        perror("Init Unix Sock for PLC");
        return -1;
    }
    dprintf(MSG_MSGDUMP, "Unix Sock for PLC: %d\n", pData->unPlcSock);
    eloop_register_read_sock(pData->unPlcSock, pbcHyfi20GetUnixSockPlcMsgCB, pData, NULL);
#endif

    pData->bridge.sock = apacHyfi20InitIEEE1905Sock(pData->bridge.ifName);
    if (pData->bridge.sock < 0) {
        perror("InitIEEE1905Sock for bridge");
        return -1;
    }
    dprintf(MSG_MSGDUMP, "bridge(hy0) sock: %d\n", pData->bridge.sock);
    eloop_register_read_sock(pData->bridge.sock, apacHyfi20GetIEEE1905PktCB, pData, NULL);

    /* 1905 interfaces */
    for (i = 0; i < APAC_MAXNUM_HYIF; i++) {
        if (!pIF[i].valid || !pIF[i].is1905Interface) {
            continue;
        }

        pIF[i].sock = apacHyfi20InitIEEE1905Sock(pIF[i].ifName);
        if (pIF[i].sock < 0) {
            perror("InitIEEE1905Sock for tx");
            return -1; 
        }
        dprintf(MSG_MSGDUMP, "if: %s, ifIndex: %d, sock: %d\n", pIF[i].ifName, pIF[i].ifIndex, pIF[i].sock);
    }

    if (apac_ctrl_init(pData) < 0)
    {
        dprintf(MSG_ERROR, "CTRL sock failed\n");
        return -1;
    }

    /* init sess data */
    pData->sess_list = NULL;
    pData->wpas = NULL; 

    /* init WPS config*/
    if (!pData->config.wpsConf->uuid_set)
    {
        /*generate a uuid in rough compliance with rfc4122 based on mac address*/
        struct wps_config *wps = pData->config.wpsConf;
        memset(wps->uuid, 0, sizeof(wps->uuid));
        wps->uuid[6] = (1<<4);
        memcpy(wps->uuid+SIZE_UUID-6, pData->alid, 6);
        wps->uuid_set = 1;
    }

    /* init mib handle */
    pData->wifiConfigHandle = apac_mib_get_wifi_config_handle();
    pData->wifiConfigWaitSecs = 0;
    if (!pData->wifiConfigHandle)
    {
        dprintf(MSG_ERROR, "Get mib storage handle failed\n");
        return -1;
    }

    return 0; 
}


int apacHyfi20InitDeviceInfo(apacHyfi20Data_t *ptrData) {
    s32 i;    
    struct ifreq ifr;
    int sock = -1;
    apacHyfi20IF_t* ptrIF = ptrData->hyif; 
    
    apacHyfi20TRACE();
    
    for (i = 0; i < APAC_MAXNUM_HYIF; i++) {
        if (!ptrIF[i].is1905Interface) {
            ptrIF[i].ifIndex = -1;
            continue;
        }

        dprintf(MSG_MSGDUMP, "IF%d: %s\n", i, ptrIF[i].ifName);

        /* Get interface mac address */ 
        sock = socket(PF_INET, SOCK_DGRAM, 0);
        if (sock < 0) {
            perror("socket[PF_INET,SOCK_DGRAM]");
            return -1;
        }
        
        memset(&ifr, 0, sizeof(ifr));
        memcpy(ifr.ifr_name, ptrIF[i].ifName, sizeof(ptrIF[i].ifName));

        if (ioctl(sock, SIOCGIFHWADDR, &ifr) < 0) {
            perror("ioctl[SIOCGIFHWADDR]");
            close(sock);
            return -1;
        }

        memcpy(ptrIF[i].mac_addr, ifr.ifr_hwaddr.sa_data, ETH_ALEN);
        dprintf(MSG_MSGDUMP, "TxIF mac: ");
        printMac(MSG_MSGDUMP, ptrIF[i].mac_addr);
    
        /* get interface index */
        memset(&ifr, 0, sizeof(ifr));
        memcpy(ifr.ifr_name, ptrIF[i].ifName, sizeof(ptrIF[i].ifName));
        if (ioctl(sock, SIOCGIFINDEX, &ifr) != 0) {
            perror("ioctl(SIOCGIFINDEX)");
            close (sock);
            return -1;
        }
        ptrIF[i].ifIndex = ifr.ifr_ifindex;
        dprintf(MSG_MSGDUMP,"TX ifname %s, ifindex %d\n", ptrIF[i].ifName, ptrIF[i].ifIndex);
    
        close (sock);
    }

    /* Get ALID (hy0)  and related info */
    sock = socket(PF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        perror("socket[PF_INET,SOCK_DGRAM]");
        return -1;
    }
    
    memset(&ifr, 0, sizeof(ifr));
    memcpy(ifr.ifr_name, ptrData->bridge.ifName, sizeof(ptrData->bridge.ifName));

    if (ioctl(sock, SIOCGIFHWADDR, &ifr) < 0) {
        perror("ioctl[SIOCGIFHWADDR]");
        close(sock);
        return -1;
    }

    memcpy(ptrData->bridge.mac_addr, ifr.ifr_hwaddr.sa_data, ETH_ALEN);
    dprintf(MSG_MSGDUMP, "BridgeIF mac: ");
    printMac(MSG_MSGDUMP, ptrData->bridge.mac_addr);
    
    /* get interface index */
    memset(&ifr, 0, sizeof(ifr));
    memcpy(ifr.ifr_name, ptrData->bridge.ifName, sizeof(ptrData->bridge.ifName));
    if (ioctl(sock, SIOCGIFINDEX, &ifr) != 0) {
        perror("ioctl(SIOCGIFINDEX)");
        close (sock);
        return -1;
    }
    ptrData->bridge.ifIndex = ifr.ifr_ifindex;
    dprintf(MSG_MSGDUMP,"TX ifname %s, ifindex %d\n", ptrData->bridge.ifName, ptrData->bridge.ifIndex);

    close (sock);

    return 0;
}

int apacHyfi20InitPlcUnixSock() {
    int plcsock_len;
    struct sockaddr_un sockaddr_un = {    
        AF_UNIX,
        WSPLCD_PLC_SOCKET_SERVER
    };
    signed Fd = -1;

    if ((Fd = socket (AF_UNIX, SOCK_DGRAM, 0)) == -1) {    
        perror("Socket Creation of Unix Socket Failed");
        return (-2);
    }
    memset(&sockaddr_un, 0, sizeof(sockaddr_un));
    sockaddr_un.sun_family = AF_UNIX;
    strncpy(sockaddr_un.sun_path, WSPLCD_PLC_SOCKET_SERVER, sizeof(WSPLCD_PLC_SOCKET_SERVER));
    plcsock_len = strlen(WSPLCD_PLC_SOCKET_SERVER);
    sockaddr_un.sun_path[plcsock_len] = '\0';
    if (unlink (sockaddr_un.sun_path)) {
        if (errno != ENOENT) {
            perror("Unlink of Unix Socket File Failed");
            return (-1);
        }
    }
    if (bind (Fd, (struct sockaddr *)(&sockaddr_un), sizeof (sockaddr_un)) == -1) {    
        perror("Bind on Unix Socket Failed");
        return (-3);
    }
    if (chmod (sockaddr_un.sun_path, 0666) == -1) {    
        perror("chmod on Unix Socket File Failed");
        return (-4);
    }
    return (Fd);
}

int apacHyfi20InitNLSock() {
    struct sockaddr_nl local;
    s32 sock;
    
    /* Initialize netlink socket */
    sock = socket(PF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
    if (sock < 0) {
        perror("socket(PF_NETLINK, SOCK_RAW, NETLINK_ROUTE");
        return -1;
    }

    memset(&local, 0, sizeof(local));
    local.nl_family = AF_NETLINK;
    local.nl_groups = RTMGRP_LINK;

    if (bind(sock, (struct sockaddr *)&local, sizeof(local)) < 0) {
        perror("bind(netlink)");
        close(sock);
        return -1;
    }

    return sock;
}

int apacHyfi20InitPipeFd() {
    int err; 
    int fd;

    unlink(APAC_PIPE_PATH);
    err = mkfifo(APAC_PIPE_PATH, 0666);
    if ((err == -1) && (errno != EEXIST)) {
        return -1;
    }

    fd = open(APAC_PIPE_PATH, O_RDWR);
    if (fd == -1) {
        perror("open(pipe)");
        return -1;
    }

    return fd;
}

/* Initialize receiving/transmission socket */
int apacHyfi20InitIEEE1905Sock(char *ifname) {
    struct ifreq ifr;
    struct sockaddr_ll ll;
    struct packet_mreq mreq;
    s32 sock;
    u8 multicast_addr[ETH_ALEN] = APAC_MULTICAST_ADDR;

    sock = socket(PF_PACKET, SOCK_RAW, htons(APAC_ETH_P_IEEE1905));
    if (sock < 0) {
        perror("socket(PF_ACKET)");
        return -1;
    } 

    memset(&ifr, 0,sizeof(struct ifreq));
    memcpy(ifr.ifr_name, ifname, IFNAMSIZ);
    if (ioctl(sock, SIOCGIFINDEX, &ifr) < 0) {
        perror("ioctl[SIOCGIFINDEX]");
        close(sock);
        return -1;
    }

    memset(&ll, 0, sizeof(ll));
    ll.sll_family = PF_PACKET;
    ll.sll_ifindex = ifr.ifr_ifindex;
    ll.sll_protocol = htons(APAC_ETH_P_IEEE1905);
    if (bind(sock, (struct sockaddr *)&ll, sizeof(ll)) < 0) {
        perror("bind[PF_PACKET]");
        close(sock);
        return -1;
    }

    memset(&mreq, 0, sizeof(mreq));
    mreq.mr_ifindex = ifr.ifr_ifindex;
    mreq.mr_type = PACKET_MR_MULTICAST;
    mreq.mr_alen = ETH_ALEN;
    memcpy(mreq.mr_address, multicast_addr, mreq.mr_alen);

    if (setsockopt(sock, SOL_PACKET, PACKET_ADD_MEMBERSHIP, &mreq, sizeof(mreq)) < 0 )
    {
        perror("setsockopt[SOL_SOCKET, PACKET_ADD_MEMBERSHIP]");
        close(sock);
        return -1;
    }

    dprintf(MSG_MSGDUMP, "ifname: %s, ifIndex: %d, sock: %d\n", ifname, ifr.ifr_ifindex, sock);

    return sock;
}

int apacHyfi20ResetIeee1905TXSock(apacHyfi20IF_t *pIF)
{

    dprintf(MSG_ERROR, "Interface[%s] changed, reset ieee1905.1 socket \n", pIF->ifName);

    if (!pIF->valid || !pIF->is1905Interface) {
        return -1;
    }

    if (pIF->sock > 0 )
        close(pIF->sock);

    pIF->sock = apacHyfi20InitIEEE1905Sock(pIF->ifName);
    if (pIF->sock < 0) {
        perror("InitIEEE1905Sock for tx");
        return -1;
    }
    dprintf(MSG_MSGDUMP, "if: %s, ifIndex: %d, sock: %d\n", pIF->ifName, pIF->ifIndex, pIF->sock);
 
    return 0;
}

static void apacHyfi20Ieee1905RXSockTimeout(void *eloop_ctx, void *timeout_ctx)
{
    apacHyfi20Data_t *pData = (apacHyfi20Data_t *)eloop_ctx;
    apacHyfi20ResetIeee1905RXSock(pData);
}

int apacHyfi20ResetIeee1905RXSock(apacHyfi20Data_t *pData)
{
    if (pData->bridge.sock > 0 )
    {
        eloop_unregister_read_sock(pData->bridge.sock);
        close (pData->bridge.sock);
        pData->bridge.sock = -1;
    }

    pData->bridge.sock = apacHyfi20InitIEEE1905Sock(pData->bridge.ifName);
    if (pData->bridge.sock < 0) {
        perror("InitIEEE1905Sock for bridge");

        /*RX socket broken due to linux bridge changing, retry it later*/
        eloop_register_timeout(1, 0, apacHyfi20Ieee1905RXSockTimeout, pData, NULL);
        return -1;
    }

    eloop_register_read_sock(pData->bridge.sock, apacHyfi20GetIEEE1905PktCB, pData, NULL);
    return 0;
}

int apacHyfi20ResetPipeFd(apacHyfi20Data_t *pData)
{
    if (pData->pipeFd > 0 )
    {
        eloop_unregister_read_sock(pData->pipeFd);
        close (pData->pipeFd);
    }

    pData->pipeFd = apacHyfi20InitPipeFd();
    if (pData->pipeFd < 0) {
        perror("InitPipe");
        return -1;          
    }   
    dprintf(MSG_INFO, "Reset pipe FD: %d\n", pData->pipeFd);
    eloop_register_read_sock(pData->pipeFd, pbcHyfi20GetPipeMsgCB, pData, NULL);

    return 0;
}

/* destroy sockets */
void apacHyfi20DeinitSock(apacHyfi20Data_t *ptrData) {
    s32 i;
    apacHyfi20IF_t *pIF = ptrData->hyif;
    apacHyfi20Config_t *pConfig = &ptrData->config;

    for (i = 0; i < APAC_MAXNUM_HYIF; i++) {
        if (pIF[i].sock > 0)
            close (pIF[i].sock);
    }

    if (ptrData->bridge.sock > 0)
        close(ptrData->bridge.sock);

    if (ptrData->nlSock > 0)
        close(ptrData->nlSock );

    if (ptrData->pipeFd > 0)
        close(ptrData->pipeFd);

    if (ptrData->unPlcSock > 0)
        close(ptrData->unPlcSock);

    if (pConfig->wpsConf) {
        os_free(pConfig->wpsConf);
    }

    if (pConfig->atfConf) {
        os_free(pConfig->atfConf);
    }

    if (ptrData->wifiConfigHandle) {
        apac_mib_apply_wifi_configuration(ptrData->wifiConfigHandle, APAC_FALSE);
    }

    apac_ctrl_deinit(ptrData);
}

