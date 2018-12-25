// vim: set et sw=4 sts=4 cindent:
/*
 * @File: stamon.h
 *
 * @Abstract: Public interface for the station monitor
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

#ifndef stamon__h
#define stamon__h

#include "lbd_types.h"  // for LBD_STATUS
#include "wlanif.h"  // for wlanif_band_e

#if defined(__cplusplus)
extern "C" {
#endif

/**
 * @brief Initialize the station monitor module.
 *
 * @pre stadb must have been initialized first
 *
 * @return LBD_OK on success; otherwise LBD_NOK
 */
LBD_STATUS stamon_init(void);

/**
 * @brief Deinitialize the station monitor module
 *
 * @return LBD_OK on success; otherwise LBD_NOK
 */
LBD_STATUS stamon_fini(void);

// ====================================================================
// Constants needed by test cases
// ====================================================================

// These need not be exposed but it is useful to do so for unit tests to
// avoid duplicating the strings.

#define STAMON_RSSI_MEASUREMENT_NUM_SAMPLES_W2_KEY "RSSIMeasureSamples_W2"
#define STAMON_RSSI_MEASUREMENT_NUM_SAMPLES_W5_KEY "RSSIMeasureSamples_W5"
#define STAMON_AGE_LIMIT_KEY "AgeLimit"
#define STAMON_HIGH_TX_RATE_XING_THRESHOLD "HighTxRateXingThreshold"
#define STAMON_LOW_TX_RATE_XING_THRESHOLD "LowTxRateXingThreshold"
#define STAMON_LOW_RATE_RSSI_XING_THRESHOLD "LowRateRSSIXingThreshold"
#define STAMON_HIGH_RATE_RSSI_XING_THRESHOLD "HighRateRSSIXingThreshold"
#define STAMON_LOW_AP_STEER_RSSI_XING_THRESHOLD_W2_KEY "LowRSSIAPSteeringThreshold_W2"
#define STAMON_LOW_AP_STEER_RSSI_XING_THRESHOLD_W5_KEY "LowRSSIAPSteeringThreshold_W5"
#define STAMON_INACT_RSSI_DG_THRESHOLD "RSSISteeringPoint_DG"

#if defined(__cplusplus)
}
#endif

#endif // stamon__h

