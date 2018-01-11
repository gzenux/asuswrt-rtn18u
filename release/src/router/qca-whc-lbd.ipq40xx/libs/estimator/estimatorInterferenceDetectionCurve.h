// vim: set et sw=4 sts=4 cindent:
/*
 * @File: estimatorInterferenceDetectionCurve.h
 *
 * @Abstract: Representation of a single curve that is used to declare
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

#ifndef estimatorInterferenceDetectionCurve__h
#define estimatorInterferenceDetectionCurve__h

#include "lbd_types.h"

#if defined(__cplusplus)
extern "C" {
#endif

/**
 * Type used for the coefficients of the curve. This is assumed to be a
 * floating point type for now.
 */
typedef float estimatorInterferenceDetectionCurveCoefficient_t;

/**
 * @brief The set of coefficients that will be used in the equation
 *        for evaluating interference.
 *
 * The curve is a quadratic equation in two variables: uplink RSSI (x)
 * and downlink MCS (y).
 *
 * All of these fields should be treated as private and should be set
 * via the estimatorInterferenceDetectionCurveInit() function.
 */
typedef struct estimatorInterferenceDetectionCurve_t {
    // The x^0*y^0 term
    estimatorInterferenceDetectionCurveCoefficient_t degree0;

    // The x^1 term
    estimatorInterferenceDetectionCurveCoefficient_t rssiDegree1;

    // The y^1 term
    estimatorInterferenceDetectionCurveCoefficient_t mcsDegree1;

    // The x^2 term
    estimatorInterferenceDetectionCurveCoefficient_t rssiDegree2;

    // The x^1*y^1 term
    estimatorInterferenceDetectionCurveCoefficient_t rssiMCSDegree1;

    // The y^2 term
    estimatorInterferenceDetectionCurveCoefficient_t mcsDegree2;
} estimatorInterferenceDetectionCurve_t;

/**
 * @brief Initialize the set of coefficients for a curve based on the
 *        values obtained from the config file.
 *
 * @param [in] degree0  the coefficient for the constant term
 * @param [in] rssiDegree1  the coefficient for the RSSI term
 * @param [in] mcsDegree1  the coefficient for the MCS term
 * @param [in] rssiDegree2  the coefficient for the RSSI*RSSI term
 * @param [in] rssiMCSDegree1  the coefficient for the RSSI*MCS term
 * @param [in] mcsDegree2  the coefficient for the MCS*MCS term
 *
 * @return LBD_OK on success; LBD_NOK if the curve is invalid
 */
LBD_STATUS estimatorInterferenceDetectionCurveInit(
        estimatorInterferenceDetectionCurve_t *curve,
        estimatorInterferenceDetectionCurveCoefficient_t degree0,
        estimatorInterferenceDetectionCurveCoefficient_t rssiDegree1,
        estimatorInterferenceDetectionCurveCoefficient_t mcsDegree1,
        estimatorInterferenceDetectionCurveCoefficient_t rssiDegree2,
        estimatorInterferenceDetectionCurveCoefficient_t rssiMcsDegree1,
        estimatorInterferenceDetectionCurveCoefficient_t mcsDegree2);

/**
 * @brief Evaluate whether the curve for the given MCS and RSSI parameters to
 *        determine whether interference is detected or not.
 *
 * @param [in] curve  the curve's coefficients
 * @param [in] mcs  the downlink MCS value
 * @param [in] rssi  the uplink RSSI value
 * @param [in] maxRate  the maximum rate beyond which interference should
 *                      never be declared
 * @param [out] result  LBD_TRUE if the curve indicates interference
 *                      detection; LBD_FALSE if it indicates no interference
 *
 * @return LBD_NOK if any of the parameters are invalid
 */
LBD_STATUS estimatorInterferenceDetectionCurveEvaluate(
        const estimatorInterferenceDetectionCurve_t *curve,
        lbd_linkCapacity_t capacity, lbd_rssi_t rssi,
        lbd_linkCapacity_t maxRate, LBD_BOOL *result);

#if defined(__cplusplus)
}
#endif

#endif // estimatorInterferenceDetectionCurve__h
