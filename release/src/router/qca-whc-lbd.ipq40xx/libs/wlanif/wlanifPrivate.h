// vim: set et sw=4 sts=4 cindent:
/*
 * @File: wlanifPrivate.h
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
 */

#ifndef wlanifPrivate__h
#define wlanifPrivate__h

#include "wlanif.h"

#include <ieee80211_band_steering_api.h>

// Forward decls
struct dbgModule;

// ====================================================================
// Helper functions private to this wlanif module
// ====================================================================

/**
 * @brief Map a frequency value (as defined by the kernel) to a band.
 *
 * @param [in] freq  the frequency value given by the kernel
 */
wlanif_band_e wlanifMapFreqToBand(int32_t freq);

/**
 * @brief Convert the crossing direction received from driver into
 *        the enum valus used within LBD
 *
 * @param [in] dbgModule  the handle to use when logging errors
 * @param [in] direction  the crossing direction as indicated by the driver
 *
 * @return  the mapped crossing direction
 */
wlanif_xingDirection_e wlanifMapToXingDirection(struct dbgModule *dbgModule,
                                                BSTEERING_XING_DIRECTION direction);

/**
 * @brief Convert the RSSI measurement from driver into values used in LBD
 *
 * @param [in] rssi  the RSSI measurement received from driver
 *
 * @return the mapped RSSI value
 */
u_int8_t wlanifMapToRSSIMeasurement(u_int8_t rssi);

/**
 * @brief Resolve 802.11 regulatory class and channel
 *        number from Wi-Fi frequency
 *
 * @param [in] freq  the Wi-Fi frequency
 * @param [out] channel  the resolved channel number if success
 * @param [out] regClass  the resolved regulatory class if success
 *
 * @return LBD_OK if channel and regulatory class are resolved
 *         successfully; otherwise return LBD_NOK
 */
LBD_STATUS wlanifResolveRegclassAndChannum(u_int32_t freq, u_int8_t *channel,
                                           u_int8_t *regClass);


/**
 * @brief Resolve 802.11 regulatory class from Wi-Fi channel
 *        number
 *
 * @param [in] channel  the channel number
 * @param [out] regClass  the resolved regulatory class if success
 *
 * @return LBD_OK if regulatory class is resolved
 *         successfully; otherwise return LBD_NOK
 */
LBD_STATUS wlanifResolveRegclass(u_int8_t channel,
                                 u_int8_t *regClass);

/**
 * @brief Convert the bandwidth received from the driver into the enum
 *        value used within LBD.
 *
 * @param [in] dbgModule  the handle to use when logging errors
 * @param [in] chwidth  the bandwidth by the driver
 *
 * @return  the mapped bandwidth used in LBD
 */
wlanif_chwidth_e wlanifMapToBandwidth(struct dbgModule *dbgModule,
                                      enum ieee80211_cwm_width chwidth);

/**
 * @brief Convert the PHY mode received from the driver into the enum
 *        value used within LBD
 *
 * @param [in] dbgModule  the handle to use when logging errors
 * @param [in] phymode  the PHY mode by the driver
 *
 * @return  the mapped PHY mode used in LBD
 */
wlanif_phymode_e wlanifMapToPhyMode(struct dbgModule *dbgModule,
                                    enum ieee80211_phymode phymode);

/**
 * @brief Convert the MCS information received from the driver to a single
 *        stream MCS index.
 *
 * @param [in] dbgModule  the handle to use when logging errors
 * @param [in] phymode  the PHY mode provided by the driver
 * @param [in] driverMCS  the maximum MCS reported by the driver
 *
 * @return  the corresponding single stream MCS index
 */
u_int8_t wlanifConvertToSingleStreamMCSIndex(struct dbgModule *dbgModule,
                                             enum ieee80211_phymode phymode,
                                             u_int8_t driverMCS);

/**
 * @brief Convert the airtime information received from the driver to
 *        the airtime used within LBD
 *
 * @param [in] dbgModule  the handle to use when logging errors
 * @param [in] airtime  the airtime received from driver
 *
 * @return the corresponding airtime to use within LBD
 */
lbd_airtime_t wlanifMapToAirtime(struct dbgModule *dbgModule,
                                 u_int32_t cfg_value);

/**
 * @brief Convert PHY mode stored within LBD to PHY type as per 802.11mc spec anex C
 *
 * Currently we lose information about 11a/b/g are treated same within LBD, so all
 * wlanif_phymode_basic is converted to IEEE80211_PHY_TYPE_OFDM. This should not be
 * a problem since no 11b AP can support RRM/BTM in theory.
 *
 * @param [in] phyMode  PHY mode stored within LBD
 *
 * @return the corresponding PHY type used in driver and OTA
 */
enum ieee80211_phytype_mode wlanifMapToPhyType(wlanif_phymode_e phyMode);

#endif
