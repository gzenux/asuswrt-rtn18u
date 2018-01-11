// vim: set et sw=4 sts=4 cindent:
/*
 * @File: estimatorInterferenceDetectionCurve.c
 *
 * @Abstract: Implementation of a single curve that is used to declare
 *            interference or no-interference for a given set of client
 *            capabilities.
 *
 * @Notes:
 *
 * @@-COPYRIGHT-START-@@
 *
 * Copyright (c) 2016 Qualcomm Atheros, Inc.
 * All Rights Reserved.
 * Qualcomm Atheros Confidential and Proprietary.
 *
 * @@-COPYRIGHT-END-@@
 */

#include "estimatorInterferenceDetectionCurve.h"

LBD_STATUS estimatorInterferenceDetectionCurveInit(
        estimatorInterferenceDetectionCurve_t *curve,
        estimatorInterferenceDetectionCurveCoefficient_t degree0,
        estimatorInterferenceDetectionCurveCoefficient_t rssiDegree1,
        estimatorInterferenceDetectionCurveCoefficient_t mcsDegree1,
        estimatorInterferenceDetectionCurveCoefficient_t rssiDegree2,
        estimatorInterferenceDetectionCurveCoefficient_t rssiMCSDegree1,
        estimatorInterferenceDetectionCurveCoefficient_t mcsDegree2) {
    if (!curve) {
        return LBD_NOK;
    }

    curve->degree0 = degree0;
    curve->rssiDegree1 = rssiDegree1;
    curve->mcsDegree1 = mcsDegree1;
    curve->rssiDegree2 = rssiDegree2;
    curve->rssiMCSDegree1 = rssiMCSDegree1;
    curve->mcsDegree2 = mcsDegree2;

    return LBD_OK;
}

LBD_STATUS estimatorInterferenceDetectionCurveEvaluate(
        const estimatorInterferenceDetectionCurve_t *curve,
        lbd_linkCapacity_t capacity, lbd_rssi_t rssi,
        lbd_linkCapacity_t maxRate, LBD_BOOL *result) {
    if (!curve || capacity == LBD_INVALID_LINK_CAP ||
        rssi == LBD_INVALID_RSSI || !result) {
        return LBD_NOK;
    }

    if (capacity < maxRate) {
        // The coefficients are for the following equation (where x = RSSI
        // and y = MCS):
        //
        // degree0 + rssiDegree1 * x + mcsDegree1 * y + rssiDegree2 * x^2 +
        // rssiMCSDegree1 * x * y + mcsDegree2 * y^2
        //
        // When this evaluates to a positive number, interference is declared.
        // Otherwise, no interference.
        estimatorInterferenceDetectionCurveCoefficient_t curveVal =
            curve->degree0 +
            curve->rssiDegree1 * rssi +
            curve->mcsDegree1 * capacity +
            curve->rssiDegree2 * rssi * rssi +
            curve->rssiMCSDegree1 * rssi * capacity +
            curve->mcsDegree2 * capacity * capacity;

        *result = (curveVal > 0);
    } else {
        // No interference if the capacity is high for the client's
        // capabilities.
        *result = LBD_FALSE;
    }
    return LBD_OK;
}
