// vim: set et sw=4 sts=4 cindent:
/*
 * @File: estimatorPollutionAccumulator.c
 *
 * @Abstract: Helper class to accumulator interference samples and make pollution decision
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

#include "dbg.h"

#include "estimatorPollutionAccumulator.h"

LBD_BOOL estimatorPollutionAccumulatorAreValidParams(
        struct dbgModule *dbgModule, estimatorPollutionAccumulatorParams_t *params) {
    if (!params) { return LBD_FALSE; }

    if (!params->fastPollutionDetectBufSize ||
        (params->normalPollutionDetectBufSize <
             params->fastPollutionDetectBufSize)) {
        dbgf(dbgModule, DBGERR,
             "%s: Interference samples (fast: %u/normal: %u) must be positive, "
             "and fast detection buffer size cannot be greater than the normal one.",
             __func__, params->fastPollutionDetectBufSize,
             params->normalPollutionDetectBufSize);
        return LBD_FALSE;
    }

    if (params->pollutionDetectThreshold > 100 ||
        (params->pollutionDetectThreshold <=
             params->pollutionClearThreshold)) {
        dbgf(dbgModule, DBGERR,
             "%s: Pollution thresholds (detect: %u%%/clear %u%%) must be "
             "0 <= clear_threshold < detect_threshold <= 100 to eliminate ambiguity.",
             __func__, params->pollutionDetectThreshold,
             params->pollutionClearThreshold);
        return LBD_FALSE;
    }

    return LBD_TRUE;
}

LBD_STATUS estimatorPollutionAccumulatorAccumulate(
        estimatorCircularBufferHandle_t pollutionAccumulator, LBD_BOOL detected,
        LBD_BOOL prevPolluted, estimatorPollutionAccumulatorParams_t *params,
        estimatorPollutionAccumulatorObserverCB callback, void *cookie) {
    estimatorPollutionState_e pollutionState = estimatorPollutionState_unknown;
    size_t newBufferSize = 0;
    size_t numDetected, numTotal;

    if (!params || !callback) {
        // Require callback funcion since it is the only way to inform caller
        // about pollution change
        return LBD_NOK;
    }

    if (LBD_NOK == estimatorCircularBufferInsert(pollutionAccumulator,
                                                 detected, &numDetected,
                                                 &numTotal)) {
        return LBD_NOK;
    }

    if (!prevPolluted) {
        if (numTotal >= params->fastPollutionDetectBufSize &&
            numDetected * 100 >= (params->pollutionDetectThreshold * numTotal)) {
            // Enough detected samples, set pollution state
            pollutionState = estimatorPollutionState_detected;
            newBufferSize = params->normalPollutionDetectBufSize;
        }
    } else if (numTotal >= params->normalPollutionDetectBufSize) {
        if (numDetected * 100 >= (params->pollutionDetectThreshold * numTotal)) {
            // Detect pollution again, flush buffer
            pollutionState = estimatorPollutionState_detected;
            newBufferSize = params->normalPollutionDetectBufSize;
        } else if (numDetected * 100 <= (params->pollutionClearThreshold * numTotal)) {
            // Enough non-detected samples, clear pollution state
            pollutionState = estimatorPollutionState_cleared;
            newBufferSize = params->fastPollutionDetectBufSize;
        }
    }

    if (LBD_OK == callback(pollutionState, cookie) && newBufferSize) {
        return estimatorCircularBufferReset(pollutionAccumulator,
                                            newBufferSize);
    }

    return LBD_OK;
}

LBD_STATUS estimatorPollutionAccumulatorReset(
        estimatorCircularBufferHandle_t pollutionAccumulator,
        LBD_BOOL prevPolluted, estimatorPollutionAccumulatorParams_t *params) {
    if (!params) { return LBD_NOK; }

    size_t newBufferSize = prevPolluted ? params->normalPollutionDetectBufSize :
                                          params->fastPollutionDetectBufSize;
    return estimatorCircularBufferReset(pollutionAccumulator,
                                        newBufferSize);
}
