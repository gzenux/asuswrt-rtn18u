// vim: set et sw=4 sts=4 cindent:
/*
 * @File: estimatorSNRToPhyRateTable.c
 *
 * @Abstract: The actual SNR to PHY rate table.
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

#include "lb_assert.h"

#include "estimatorSNRToPhyRateTable.h"

const estimatorSNRToPhyRateEntry_t
    estimatorSNRToPhyRateTable[wlanif_phymode_invalid]
                              [wlanif_chwidth_invalid]
                              [ESTIMATOR_MAX_NSS]
                              [ESTIMATOR_MAX_RATES] =
{
    // Data is extracted from SNR_table_WHC_v01.xlsx, using the SNR and Rates
    // worksheets. When dealing with fractional values, the ceiling is used
    // for the SNR and the floor is used for the rate (to be conservative).

    // 802.11g/a mode - derived from 11n with 51% efficiency (due to
    //                  no AMPDU)
    // ================================================================
    {
        // 20 MHz
        {
            // 1 spatial stream
            {
                { 7  /* snr */,    3  /* rate */ },
                { 10 /* snr */,    6  /* rate */ },
                { 13 /* snr */,    9  /* rate */ },
                { 14 /* snr */,    13 /* rate */ },
                { 18 /* snr */,    19 /* rate */ },
                { 22 /* snr */,    26 /* rate */ },
                { 23 /* snr */,    29 /* rate */ },
                { 25 /* snr */,    33 /* rate */ },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
            },

            // 2 spatial streams (invalid for this mode)
            {
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
            },

            // 3 spatial streams (invalid for this mode)
            {
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
            },

            // 4 spatial streams (invalid for this mode)
            {
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
            },
        },
        // 40 MHz - not valid for this mode
        {
            // 1 spatial stream
            {
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
            },

            // 2 spatial streams (invalid for this mode)
            {
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
            },

            // 3 spatial streams (invalid for this mode)
            {
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
            },

            // 4 spatial streams (invalid for this mode)
            {
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
            },
        },
        // 80 MHz - not valid for this mode
        {
            // 1 spatial stream
            {
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
            },

            // 2 spatial streams (invalid for this mode)
            {
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
            },

            // 3 spatial streams (invalid for this mode)
            {
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
            },

            // 4 spatial streams (invalid for this mode)
            {
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
            },
        },
        // 160 MHz - not valid for this mode
        {
            // 1 spatial stream
            {
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
            },

            // 2 spatial streams (invalid for this mode)
            {
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
            },

            // 3 spatial streams (invalid for this mode)
            {
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
            },

            // 4 spatial streams (invalid for this mode)
            {
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
            },
        },
    },

    // 802.11n mode - note that MCS8 and 9 are always invalid
    // ================================================================
    {
        // 20 MHz
        {
            // 1 spatial stream
            {
                { 7 /* snr */,     6  /* rate */ },
                { 10 /* snr */,    13 /* rate */ },
                { 13 /* snr */,    19 /* rate */ },
                { 14 /* snr */,    26 /* rate */ },
                { 18 /* snr */,    39 /* rate */ },
                { 22 /* snr */,    52 /* rate */ },
                { 23 /* snr */,    58 /* rate */ },
                { 25 /* snr */,    65 /* rate */ },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
            },

            // 2 spatial streams
            {
                { 7 /* snr */,     13  /* rate */ },
                { 11 /* snr */,    26  /* rate */ },
                { 14 /* snr */,    39  /* rate */ },
                { 18 /* snr */,    52  /* rate */ },
                { 21 /* snr */,    78  /* rate */ },
                { 26 /* snr */,    104 /* rate */ },
                { 28 /* snr */,    117 /* rate */ },
                { 31 /* snr */,    130 /* rate */ },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
            },

            // 3 spatial streams - assumed to be the same as 2 NSS due to no
            // data available at this time
            {
                { 7 /* snr */,     13  /* rate */ },
                { 11 /* snr */,    26  /* rate */ },
                { 14 /* snr */,    39  /* rate */ },
                { 18 /* snr */,    52  /* rate */ },
                { 21 /* snr */,    78  /* rate */ },
                { 26 /* snr */,    104 /* rate */ },
                { 28 /* snr */,    117 /* rate */ },
                { 31 /* snr */,    130 /* rate */ },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
            },

            // 4 spatial streams - assumed to be the same as 2 NSS due to no
            // data available at this time
            {
                { 7 /* snr */,     13  /* rate */ },
                { 11 /* snr */,    26  /* rate */ },
                { 14 /* snr */,    39  /* rate */ },
                { 18 /* snr */,    52  /* rate */ },
                { 21 /* snr */,    78  /* rate */ },
                { 26 /* snr */,    104 /* rate */ },
                { 28 /* snr */,    117 /* rate */ },
                { 31 /* snr */,    130 /* rate */ },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
            },
        },

        // 40 MHz
        {
            // 1 spatial stream
            {
                { 6 /* snr */,     13  /* rate */ },
                { 9 /* snr */,     27  /* rate */ },
                { 12 /* snr */,    40  /* rate */ },
                { 13 /* snr */,    54  /* rate */ },
                { 17 /* snr */,    81  /* rate */ },
                { 21 /* snr */,    108 /* rate */ },
                { 22 /* snr */,    121 /* rate */ },
                { 24 /* snr */,    135 /* rate */ },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
            },

            // 2 spatial streams
            {
                { 6 /* snr */,     27  /* rate */ },
                { 10 /* snr */,    54  /* rate */ },
                { 13 /* snr */,    81  /* rate */ },
                { 17 /* snr */,    108 /* rate */ },
                { 21 /* snr */,    162 /* rate */ },
                { 25 /* snr */,    216 /* rate */ },
                { 27 /* snr */,    243 /* rate */ },
                { 30 /* snr */,    270 /* rate */ },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
            },

            // 3 spatial streams - assumed to be the same as 2 NSS due to no
            // data available at this time
            {
                { 6 /* snr */,     27  /* rate */ },
                { 10 /* snr */,    54  /* rate */ },
                { 13 /* snr */,    81  /* rate */ },
                { 17 /* snr */,    108 /* rate */ },
                { 21 /* snr */,    162 /* rate */ },
                { 25 /* snr */,    216 /* rate */ },
                { 27 /* snr */,    243 /* rate */ },
                { 30 /* snr */,    270 /* rate */ },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
            },

            // 4 spatial streams - assumed to be the same as 2 NSS due to no
            // data available at this time
            {
                { 6 /* snr */,     27  /* rate */ },
                { 10 /* snr */,    54  /* rate */ },
                { 13 /* snr */,    81  /* rate */ },
                { 17 /* snr */,    108 /* rate */ },
                { 21 /* snr */,    162 /* rate */ },
                { 25 /* snr */,    216 /* rate */ },
                { 27 /* snr */,    243 /* rate */ },
                { 30 /* snr */,    270 /* rate */ },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
            },
        },

        // 80 MHz - not valid for 802.11n
        {
            // 1 spatial stream
            {
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
            },

            // 2 spatial streams
            {
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
            },

            // 3 spatial streams
            {
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
            },

            // 4 spatial streams
            {
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
            },
        },

        // 160 MHz - not valid for 802.11n
        {
            // 1 spatial stream
            {
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
            },

            // 2 spatial streams
            {
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
            },

            // 3 spatial streams
            {
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
            },

            // 4 spatial streams
            {
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
                { LBD_MAX_SNR,     LBD_INVALID_LINK_CAP },
            },
        },
    },

    // 802.11ac mode - identical to 802.11n but with MCS8 and 9 populated
    // ================================================================
    {
        // 20 MHz
        {
            // 1 spatial stream
            {
                { 7 /* snr */,     6  /* rate */ },
                { 10 /* snr */,    13 /* rate */ },
                { 13 /* snr */,    19 /* rate */ },
                { 14 /* snr */,    26 /* rate */ },
                { 18 /* snr */,    39 /* rate */ },
                { 22 /* snr */,    52 /* rate */ },
                { 23 /* snr */,    58 /* rate */ },
                { 25 /* snr */,    65 /* rate */ },
                { 31 /* snr */,    78 /* rate */ },
                { 32 /* snr */,    78 /* rate */ },
            },

            // 2 spatial streams
            {
                { 7 /* snr */,     13  /* rate */ },
                { 11 /* snr */,    26  /* rate */ },
                { 14 /* snr */,    39  /* rate */ },
                { 18 /* snr */,    52  /* rate */ },
                { 21 /* snr */,    78  /* rate */ },
                { 26 /* snr */,    104 /* rate */ },
                { 28 /* snr */,    117 /* rate */ },
                { 31 /* snr */,    130 /* rate */ },
                { 35 /* snr */,    156 /* rate */ },
                { 37 /* snr */,    156 /* rate */ },
            },

            // 3 spatial streams - assumed to be the same as 2 NSS due to no
            // data available at this time
            {
                { 7 /* snr */,     13  /* rate */ },
                { 11 /* snr */,    26  /* rate */ },
                { 14 /* snr */,    39  /* rate */ },
                { 18 /* snr */,    52  /* rate */ },
                { 21 /* snr */,    78  /* rate */ },
                { 26 /* snr */,    104 /* rate */ },
                { 28 /* snr */,    117 /* rate */ },
                { 31 /* snr */,    130 /* rate */ },
                { 35 /* snr */,    156 /* rate */ },
                { 37 /* snr */,    156 /* rate */ },
            },

            // 4 spatial streams - assumed to be the same as 2 NSS due to no
            // data available at this time
            {
                { 7 /* snr */,     13  /* rate */ },
                { 11 /* snr */,    26  /* rate */ },
                { 14 /* snr */,    39  /* rate */ },
                { 18 /* snr */,    52  /* rate */ },
                { 21 /* snr */,    78  /* rate */ },
                { 26 /* snr */,    104 /* rate */ },
                { 28 /* snr */,    117 /* rate */ },
                { 31 /* snr */,    130 /* rate */ },
                { 35 /* snr */,    156 /* rate */ },
                { 37 /* snr */,    156 /* rate */ },
            },
        },

        // 40 MHz
        {
            // 1 spatial stream
            {
                { 6 /* snr */,     13  /* rate */ },
                { 9 /* snr */,     27  /* rate */ },
                { 12 /* snr */,    40  /* rate */ },
                { 13 /* snr */,    54  /* rate */ },
                { 17 /* snr */,    81  /* rate */ },
                { 21 /* snr */,    108 /* rate */ },
                { 22 /* snr */,    121 /* rate */ },
                { 24 /* snr */,    135 /* rate */ },
                { 30 /* snr */,    162 /* rate */ },
                { 31 /* snr */,    180 /* rate */ },
            },

            // 2 spatial streams
            {
                { 6 /* snr */,     27  /* rate */ },
                { 10 /* snr */,    54  /* rate */ },
                { 13 /* snr */,    81  /* rate */ },
                { 17 /* snr */,    108 /* rate */ },
                { 21 /* snr */,    162 /* rate */ },
                { 25 /* snr */,    216 /* rate */ },
                { 27 /* snr */,    243 /* rate */ },
                { 30 /* snr */,    270 /* rate */ },
                { 34 /* snr */,    324 /* rate */ },
                { 36 /* snr */,    360 /* rate */ },
            },

            // 3 spatial streams - assumed to be the same as 2 NSS due to no
            // data available at this time
            {
                { 6 /* snr */,     27  /* rate */ },
                { 10 /* snr */,    54  /* rate */ },
                { 13 /* snr */,    81  /* rate */ },
                { 17 /* snr */,    108 /* rate */ },
                { 21 /* snr */,    162 /* rate */ },
                { 25 /* snr */,    216 /* rate */ },
                { 27 /* snr */,    243 /* rate */ },
                { 30 /* snr */,    270 /* rate */ },
                { 34 /* snr */,    324 /* rate */ },
                { 36 /* snr */,    360 /* rate */ },
            },

            // 4 spatial streams - assumed to be the same as 2 NSS due to no
            // data available at this time
            {
                { 6 /* snr */,     27  /* rate */ },
                { 10 /* snr */,    54  /* rate */ },
                { 13 /* snr */,    81  /* rate */ },
                { 17 /* snr */,    108 /* rate */ },
                { 21 /* snr */,    162 /* rate */ },
                { 25 /* snr */,    216 /* rate */ },
                { 27 /* snr */,    243 /* rate */ },
                { 30 /* snr */,    270 /* rate */ },
                { 34 /* snr */,    324 /* rate */ },
                { 36 /* snr */,    360 /* rate */ },
            },
        },

        // 80 MHz
        {
            // 1 spatial stream
            {
                { 5 /* snr */,     29  /* rate */ },
                { 8 /* snr */,     58  /* rate */ },
                { 11 /* snr */,    87  /* rate */ },
                { 12 /* snr */,    117 /* rate */ },
                { 16 /* snr */,    175 /* rate */ },
                { 20 /* snr */,    234 /* rate */ },
                { 21 /* snr */,    263 /* rate */ },
                { 23 /* snr */,    292 /* rate */ },
                { 29 /* snr */,    351 /* rate */ },
                { 30 /* snr */,    390 /* rate */ },
            },

            // 2 spatial streams
            {
                { 5 /* snr */,     58  /* rate */ },
                { 9 /* snr */,     117 /* rate */ },
                { 12 /* snr */,    175 /* rate */ },
                { 16 /* snr */,    234 /* rate */ },
                { 20 /* snr */,    351 /* rate */ },
                { 24 /* snr */,    468 /* rate */ },
                { 26 /* snr */,    526 /* rate */ },
                { 29 /* snr */,    585 /* rate */ },
                { 33 /* snr */,    702 /* rate */ },
                { 35 /* snr */,    780 /* rate */ },
            },

            // 3 spatial streams - assumed to be the same as 2 NSS due to no
            // data available at this time
            {
                { 5 /* snr */,     58  /* rate */ },
                { 9 /* snr */,     117 /* rate */ },
                { 12 /* snr */,    175 /* rate */ },
                { 16 /* snr */,    234 /* rate */ },
                { 20 /* snr */,    351 /* rate */ },
                { 24 /* snr */,    468 /* rate */ },
                { 26 /* snr */,    526 /* rate */ },
                { 29 /* snr */,    585 /* rate */ },
                { 33 /* snr */,    702 /* rate */ },
                { 35 /* snr */,    780 /* rate */ },
            },

            // 4 spatial streams - assumed to be the same as 2 NSS due to no
            // data available at this time
            {
                { 5 /* snr */,     58  /* rate */ },
                { 9 /* snr */,     117 /* rate */ },
                { 12 /* snr */,    175 /* rate */ },
                { 16 /* snr */,    234 /* rate */ },
                { 20 /* snr */,    351 /* rate */ },
                { 24 /* snr */,    468 /* rate */ },
                { 26 /* snr */,    526 /* rate */ },
                { 29 /* snr */,    585 /* rate */ },
                { 33 /* snr */,    702 /* rate */ },
                { 35 /* snr */,    780 /* rate */ },
            },
        },

        // 160 MHz - assumed to double the data rate of 80 MHz
        {
            // 1 spatial stream
            {
                { 5 /* snr */,     58  /* rate */ },
                { 8 /* snr */,     116 /* rate */ },
                { 11 /* snr */,    174 /* rate */ },
                { 12 /* snr */,    234 /* rate */ },
                { 16 /* snr */,    350 /* rate */ },
                { 20 /* snr */,    468 /* rate */ },
                { 21 /* snr */,    526 /* rate */ },
                { 23 /* snr */,    584 /* rate */ },
                { 29 /* snr */,    702 /* rate */ },
                { 30 /* snr */,    780 /* rate */ },
            },

            // 2 spatial streams
            {
                { 5 /* snr */,     116  /* rate */ },
                { 9 /* snr */,     234  /* rate */ },
                { 12 /* snr */,    350  /* rate */ },
                { 16 /* snr */,    468  /* rate */ },
                { 20 /* snr */,    702  /* rate */ },
                { 24 /* snr */,    936  /* rate */ },
                { 26 /* snr */,    1052 /* rate */ },
                { 29 /* snr */,    1170 /* rate */ },
                { 33 /* snr */,    1404 /* rate */ },
                { 35 /* snr */,    1560 /* rate */ },
            },

            // 3 spatial streams - assumed to be the same as 2 NSS due to no
            // data available at this time
            {
                { 5 /* snr */,     116  /* rate */ },
                { 9 /* snr */,     234  /* rate */ },
                { 12 /* snr */,    350  /* rate */ },
                { 16 /* snr */,    468  /* rate */ },
                { 20 /* snr */,    702  /* rate */ },
                { 24 /* snr */,    936  /* rate */ },
                { 26 /* snr */,    1052 /* rate */ },
                { 29 /* snr */,    1170 /* rate */ },
                { 33 /* snr */,    1404 /* rate */ },
                { 35 /* snr */,    1560 /* rate */ },
            },

            // 4 spatial streams - assumed to be the same as 2 NSS due to no
            // data available at this time
            {
                { 5 /* snr */,     116  /* rate */ },
                { 9 /* snr */,     234  /* rate */ },
                { 12 /* snr */,    350  /* rate */ },
                { 16 /* snr */,    468  /* rate */ },
                { 20 /* snr */,    702  /* rate */ },
                { 24 /* snr */,    936  /* rate */ },
                { 26 /* snr */,    1052 /* rate */ },
                { 29 /* snr */,    1170 /* rate */ },
                { 33 /* snr */,    1404 /* rate */ },
                { 35 /* snr */,    1560 /* rate */ },
            },
        },

    }
};

lbd_linkCapacity_t estimatorSNRToPhyRateTablePerformLookup(
        struct dbgModule *dbgModule,
        wlanif_phymode_e phyMode, wlanif_chwidth_e chwidth,
        u_int8_t numSpatialStreams, u_int8_t maxMCSIndex, lbd_snr_t snr) {
    // These are preconditions that should have already been ensured
    // by the rest of lbd.
    lbDbgAssertExit(dbgModule, phyMode < wlanif_phymode_invalid);
    lbDbgAssertExit(dbgModule, chwidth < wlanif_chwidth_invalid);
    lbDbgAssertExit(dbgModule, numSpatialStreams <= ESTIMATOR_MAX_NSS);
    lbDbgAssertExit(dbgModule, numSpatialStreams >= ESTIMATOR_MIN_NSS);

    const estimatorSNRToPhyRateEntry_t *entries =
        estimatorSNRToPhyRateTable[phyMode][chwidth][numSpatialStreams - 1];

    // Although this could be done with a binary search, for the small
    // size of this array, it is not likely worth the complexity. Thus,
    // we search through the array until we find an entry whose SNR is
    // larger than the client one. The entry right before this is the
    // one to use.
    size_t i;
    for (i = 0; i < ESTIMATOR_MAX_RATES && i <= maxMCSIndex; ++i) {
        if (snr < entries[i].snr) {
            break;
        }
    }

    if (0 == i) {
        return LBD_INVALID_LINK_CAP;
    } else {
        return entries[i - 1].phyRate;
    }
}

lbd_snr_t estimatorSNRToPhyRateTablePerformReverseLookup(
        struct dbgModule *dbgModule, wlanif_phymode_e phyMode,
        wlanif_chwidth_e chwidth, u_int8_t numSpatialStreams,
        u_int8_t maxMCSIndex, lbd_linkCapacity_t phyRate) {
    // These are preconditions that should have already been ensured
    // by the rest of lbd.
    lbDbgAssertExit(dbgModule, phyMode < wlanif_phymode_invalid);
    lbDbgAssertExit(dbgModule, chwidth < wlanif_chwidth_invalid);
    lbDbgAssertExit(dbgModule, numSpatialStreams <= ESTIMATOR_MAX_NSS);

    const estimatorSNRToPhyRateEntry_t *entries =
        estimatorSNRToPhyRateTable[phyMode][chwidth][numSpatialStreams - 1];

    size_t i;
    for (i = 0; i < ESTIMATOR_MAX_RATES && i <= maxMCSIndex; ++i) {
        if (entries[i].phyRate == LBD_INVALID_LINK_CAP ||
            phyRate < entries[i].phyRate) {
            break;
        }
    }

    if (0 == i) {
        return LBD_INVALID_SNR;
    } else {
        return entries[i - 1].snr;
    }
}
