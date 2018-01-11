// vim: set et sw=4 sts=4 cindent:
/*
 * @File: wlanif.c
 *
 * @Abstract: Private helpers for load balancing daemon WLAN interface
 *
 * @Notes:
 *
 * @@-COPYRIGHT-START-@@
 *
 * Copyright (c) 2014 Qualcomm Atheros, Inc.
 * All Rights Reserved.
 * Qualcomm Atheros Confidential and Proprietary.
 *
 * @@-COPYRIGHT-END-@@
 *
 */


#include "wlanifPrivate.h"

#include <dbg.h>

wlanif_xingDirection_e wlanifMapToXingDirection(struct dbgModule *dbgModule,
                                                BSTEERING_XING_DIRECTION direction) {
    switch (direction) {
        case BSTEERING_XING_UNCHANGED:
            return wlanif_xing_unchanged;

        case BSTEERING_XING_UP:
            return wlanif_xing_up;

        case BSTEERING_XING_DOWN:
            return wlanif_xing_down;

        default:
            // Fall through for the error case
            break;
    }

    dbgf(dbgModule, DBGERR, "%s: Invalid crossing direction from driver: %u",
         __func__, direction);
    return wlanif_xing_invalid;
}

u_int8_t wlanifMapToRSSIMeasurement(u_int8_t rssi) {
    if (rssi == BSTEERING_INVALID_RSSI) {
        return LBD_INVALID_RSSI;
    }
    return rssi;
}

LBD_STATUS wlanifResolveRegclassAndChannum(u_int32_t freq, u_int8_t *channel,
                                           u_int8_t *regClass) {
    if (!channel || !regClass) {
        return LBD_NOK;
    }
    *channel = 0;
    *regClass = IEEE80211_RRM_REGCLASS_RESERVED;

    freq /= 100000; // Convert to MHz
    if ((freq >= 2412) && (freq <= 2472)) {
        if (((freq - 2407) % 5) != 0) {
            /* error: freq not exact */
            return LBD_NOK;
        }
        *regClass = IEEE80211_RRM_REGCLASS_81; /* 2.407 GHz, channels 1..13 */
        *channel = (freq - 2407) / 5;
        return LBD_OK;
    }

    if (freq == 2484) {
        *regClass = IEEE80211_RRM_REGCLASS_82; /* channel 14 */
        *channel = 14;
        return LBD_OK;
    }

#define IS_CHAN_IN_PUBLIC_SAFETY_BAND(_c) ((_c) > 4940 && (_c) < 4990)
    if (freq >= 2512 && freq < 5000) {
        if (IS_CHAN_IN_PUBLIC_SAFETY_BAND(freq)) {
             *channel = ((freq * 10) +
                         (((freq % 5) == 2) ? 5 : 0) - 49400)/5;
        } else if ( freq > 4900 ) {
             *channel = (freq - 4000) / 5;
        } else {
             *channel = 15 + ((freq - 2512) / 20);
        }
        // Since our chipset does not support bands other than 2.4 Ghz or 5 GHz,
        // indicate failure here with channel resolved but regulatory class cannot
        // be resolved.
        return LBD_NOK;
    }

#define FREQ_5G_CH(_chan_num)   (5000 + (5 * _chan_num))

#define CASE_5G_FREQ(_chan_num)         \
    case FREQ_5G_CH(_chan_num):         \
        *channel = _chan_num;           \
        break;

    if ((freq >= FREQ_5G_CH(36)) && (freq <= FREQ_5G_CH(48))) {
        switch(freq) {
            CASE_5G_FREQ(36);
            CASE_5G_FREQ(40);
            CASE_5G_FREQ(44);
            CASE_5G_FREQ(48);
            default:
                /* No valid frequency in this range */
                return LBD_NOK;
        }
        *regClass = IEEE80211_RRM_REGCLASS_115; /* 5 GHz, channels 36..48 */
        return LBD_OK;
    }

    if ((freq >= FREQ_5G_CH(149)) && (freq <= FREQ_5G_CH(169))) {
        switch(freq) {
            CASE_5G_FREQ(149);
            CASE_5G_FREQ(153);
            CASE_5G_FREQ(157);
            CASE_5G_FREQ(161);
            CASE_5G_FREQ(165);
            CASE_5G_FREQ(169);
            default:
                /* No valid frequency in this range */
                return LBD_NOK;
        }
        *regClass = IEEE80211_RRM_REGCLASS_125; /* 5 GHz, channels 149..169 */
        return LBD_OK;
    }

    if ((freq >= FREQ_5G_CH(8)) && (freq <= FREQ_5G_CH(16))) {
        switch(freq) {
            CASE_5G_FREQ(8);
            CASE_5G_FREQ(12);
            CASE_5G_FREQ(16);
            default:
                /* No valid frequency in this range */
                return LBD_NOK;
        }
        *regClass = IEEE80211_RRM_REGCLASS_112; /* 5 GHz, channels 8, 12, 16 */
        return LBD_OK;
    }

    if ((freq >= FREQ_5G_CH(52)) && (freq <= FREQ_5G_CH(64))) {
        switch(freq) {
            CASE_5G_FREQ(52);
            CASE_5G_FREQ(56);
            CASE_5G_FREQ(60);
            CASE_5G_FREQ(64);
            default:
                /* No valid frequency in this range */
                return LBD_NOK;
        }
        *regClass = IEEE80211_RRM_REGCLASS_118; /* 5 GHz, channels 52, 56, 60, 64 */
        return LBD_OK;
    }

    if ((freq >= FREQ_5G_CH(100)) && (freq <= FREQ_5G_CH(140))) {
        switch(freq) {
            CASE_5G_FREQ(100);
            CASE_5G_FREQ(104);
            CASE_5G_FREQ(108);
            CASE_5G_FREQ(112);
            CASE_5G_FREQ(116);
            CASE_5G_FREQ(120);
            CASE_5G_FREQ(124);
            CASE_5G_FREQ(128);
            CASE_5G_FREQ(132);
            CASE_5G_FREQ(136);
            CASE_5G_FREQ(140);
            default:
                /* No valid frequency in this range */
                return LBD_NOK;
        }
        *regClass = IEEE80211_RRM_REGCLASS_121; /* 5 GHz, channels 100, 104, 108, 112,
                           * 116, 120, 124, 128, 132, 136, 140 */
        return LBD_OK;
    }

    return LBD_NOK;

#undef IS_CHAN_IN_PUBLIC_SAFETY_BAND
#undef CASE_5G_FREQ
#undef FREQ_5G_CH
}

LBD_STATUS wlanifResolveRegclass(u_int8_t channel,
                                 u_int8_t *regClass) {
    if (!regClass) {
        return LBD_NOK;
    }

    *regClass = IEEE80211_RRM_REGCLASS_RESERVED;

    if ((channel >= 1) && (channel <= 13)) {
        *regClass = IEEE80211_RRM_REGCLASS_81; /* 2.407 GHz, channels 1..13 */
        return LBD_OK;
    } else if (channel == 14) {
        *regClass = IEEE80211_RRM_REGCLASS_82; /* channel 14 */
        return LBD_OK;
    } else if ((channel >= 36) && (channel <= 48)) {
        *regClass = IEEE80211_RRM_REGCLASS_115; /* 5 GHz, channels 36..48 */
        return LBD_OK;
    } else if ((channel >= 149) && (channel <= 169)) {
        *regClass = IEEE80211_RRM_REGCLASS_125; /* 5 GHz, channels 149..169 */
        return LBD_OK;
    } else if (channel == 16) {
        // @todo: Is there a way to disambiguate the channels 8 and 12
        // from the 2.4GHz channels?
        *regClass = IEEE80211_RRM_REGCLASS_112; /* 5 GHz, channels 8, 12, 16 */
        return LBD_OK;
    } else if ((channel == 52) || (channel == 56) ||
               (channel == 60) || (channel == 64)) {
        *regClass = IEEE80211_RRM_REGCLASS_118; /* 5 GHz, channels 52, 56, 60, 64 */
        return LBD_OK;
    } else if ((channel == 100) || (channel == 104) ||
               (channel == 108) || (channel == 112) ||
               (channel == 116) || (channel == 120) ||
               (channel == 124) || (channel == 128) ||
               (channel == 132) || (channel == 136) ||
               (channel == 140)) {
        *regClass = IEEE80211_RRM_REGCLASS_121; /* 5 GHz, channels 100, 104, 108, 112,
                           * 116, 120, 124, 128, 132, 136, 140 */
        return LBD_OK;
    }

    return LBD_NOK;
}

wlanif_chwidth_e wlanifMapToBandwidth(struct dbgModule *dbgModule,
                                      enum ieee80211_cwm_width chwidth) {
    switch (chwidth) {
        case IEEE80211_CWM_WIDTH20:
            return wlanif_chwidth_20;

        case IEEE80211_CWM_WIDTH40:
            return wlanif_chwidth_40;

        case IEEE80211_CWM_WIDTH80:
            return wlanif_chwidth_80;

#ifdef LBD_SUPPORT_VHT160
        case IEEE80211_CWM_WIDTH160:
            return wlanif_chwidth_160;
#endif // LBD_SUPPORT_VHT160

        default:
            // Fall through for the error case
            break;
    }

    dbgf(dbgModule, DBGERR, "%s: Invalid bandwidth from driver: %u",
         __func__, chwidth);
    return wlanif_chwidth_invalid;
}

wlanif_phymode_e wlanifMapToPhyMode(struct dbgModule *dbgModule,
                                    enum ieee80211_phymode phymode) {
    switch (phymode) {
        case IEEE80211_MODE_11A:
        case IEEE80211_MODE_11B:
        case IEEE80211_MODE_11G:
        case IEEE80211_MODE_FH:
        case IEEE80211_MODE_TURBO_A:
        case IEEE80211_MODE_TURBO_G:
            return wlanif_phymode_basic;

        case IEEE80211_MODE_11NA_HT20:
        case IEEE80211_MODE_11NG_HT20:
        case IEEE80211_MODE_11NA_HT40PLUS:
        case IEEE80211_MODE_11NA_HT40MINUS:
        case IEEE80211_MODE_11NG_HT40PLUS:
        case IEEE80211_MODE_11NG_HT40MINUS:
        case IEEE80211_MODE_11NG_HT40:
        case IEEE80211_MODE_11NA_HT40:
            return wlanif_phymode_ht;

        case IEEE80211_MODE_11AC_VHT20:
        case IEEE80211_MODE_11AC_VHT40PLUS:
        case IEEE80211_MODE_11AC_VHT40MINUS:
        case IEEE80211_MODE_11AC_VHT40:
        case IEEE80211_MODE_11AC_VHT80:
#ifdef LBD_SUPPORT_VHT160
        case IEEE80211_MODE_11AC_VHT160:
        case IEEE80211_MODE_11AC_VHT80_80:
#endif // LBD_SUPPORT_VHT160
            return wlanif_phymode_vht;

        default:
            // Fall through for the error case
            break;
    }

    dbgf(dbgModule, DBGERR, "%s: Invalid PHY mode from driver: %u",
         __func__, phymode);
    return wlanif_phymode_invalid;
}

u_int8_t wlanifConvertToSingleStreamMCSIndex(struct dbgModule *dbgModule,
                                             enum ieee80211_phymode phymode,
                                             u_int8_t driverMCS) {
#define WLANIF_MAX_11N_MCS_INDEX 7
    switch (phymode) {
        case IEEE80211_MODE_11B:
        case IEEE80211_MODE_FH:
            // Assumes it can only use the first two data rates. In
            // practice it may be even more limited, but hopefully these
            // clients are not seen in the real world any more.
            //
            // Note that the driver reports in Mbps, so we're just picking
            // an MCS index for 802.11g that roughly corresponds to the
            // maximum rate for 802.11b.
            return 1;

        case IEEE80211_MODE_11A:
        case IEEE80211_MODE_11G:
        case IEEE80211_MODE_TURBO_A:
        case IEEE80211_MODE_TURBO_G:
            // 802.11g and 802.11n should share the same max index for a
            // single spatial stream (although 802.11n brings higher
            // efficiency).
            //
            // Note that the driver reports the rate as Mbps. Here we are
            // assuming that all clients will support up to MCS 7.
            return WLANIF_MAX_11N_MCS_INDEX;

        case IEEE80211_MODE_11NA_HT20:
        case IEEE80211_MODE_11NG_HT20:
        case IEEE80211_MODE_11NA_HT40PLUS:
        case IEEE80211_MODE_11NA_HT40MINUS:
        case IEEE80211_MODE_11NG_HT40PLUS:
        case IEEE80211_MODE_11NG_HT40MINUS:
        case IEEE80211_MODE_11NG_HT40:
        case IEEE80211_MODE_11NA_HT40:
            // 802.11n uses MCS indices that incorporate the number of
            // spatial streams. We are capturing that separately, so
            // remove the spatial stream component of the value.
            return driverMCS % (WLANIF_MAX_11N_MCS_INDEX + 1);

        case IEEE80211_MODE_11AC_VHT20:
        case IEEE80211_MODE_11AC_VHT40PLUS:
        case IEEE80211_MODE_11AC_VHT40MINUS:
        case IEEE80211_MODE_11AC_VHT40:
        case IEEE80211_MODE_11AC_VHT80:
#ifdef LBD_SUPPORT_VHT160
        case IEEE80211_MODE_11AC_VHT160:
        case IEEE80211_MODE_11AC_VHT80_80:
#endif // LBD_SUPPORT_VHT160
            // 802.11ac just reports the MCS index itself independent of
            // the number of spatial streams.
            return driverMCS;

        default:
            // Fall through for the error case
            break;
    }

    dbgf(dbgModule, DBGERR, "%s: Invalid PHY mode from driver: %u",
         __func__, phymode);
    return 0;
#undef WLANIF_MAX_11N_MCS_INDEX
}

lbd_airtime_t wlanifMapToAirtime(struct dbgModule *dbgModule,
                                 u_int32_t cfg_value) {
    if (!cfg_value) {
        // No reserved airtime
        return LBD_INVALID_AIRTIME;
    } else if (cfg_value > 100 * ATF_AIRTIME_CONVERSION_FACTOR ||
               cfg_value < 1 * ATF_AIRTIME_CONVERSION_FACTOR) {
        dbgf(dbgModule, DBGERR, "%s: Invalid airtime from driver: %u",
             __func__, cfg_value);
        return LBD_INVALID_AIRTIME;
    }

    return cfg_value / ATF_AIRTIME_CONVERSION_FACTOR;
}

enum ieee80211_phytype_mode wlanifMapToPhyType(wlanif_phymode_e phyMode) {
    switch (phyMode) {
        case wlanif_phymode_basic:
            return IEEE80211_PHY_TYPE_OFDM;
        case wlanif_phymode_ht:
            return IEEE80211_PHY_TYPE_HT;
        case wlanif_phymode_vht:
            return IEEE80211_PHY_TYPE_VHT;
        default:
            return IEEE80211_PHY_TYPE_UNKNOWN;
    }
}
