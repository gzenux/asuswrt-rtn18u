// vim: set et sw=4 sts=4 cindent:
/*
 * @File: estimatorPollutionAccumulator.h
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

#ifndef estimatorPollutionAccumulator__h
#define estimatorPollutionAccumulator__h

#include "lbd_types.h"
#include "estimatorCircularBuffer.h"

#if defined(__cplusplus)
extern "C" {
#endif

/**
 * @brief Enumeration type to denote whether pollution state changes
 */
typedef enum estimatorPollutionState_e {
    /// Pollution was detected
    estimatorPollutionState_detected,

    /// Pollution was cleared
    estimatorPollutionState_cleared,

    /// Pollution state unknown, probably due to lack of samples
    estimatorPollutionState_unknown
} estimatorPollutionState_e;

/**
 * @brief Configuration parameters related to pollution accumulator
 */
typedef struct estimatorPollutionAccumulatorParams_t {
    /// The minimum number of samples required to detect pollution
    u_int8_t fastPollutionDetectBufSize;

    /// The minimum number of samples required to clear pollution
    /// or extend pollution
    u_int8_t normalPollutionDetectBufSize;

    /// The minimum percentage of interference detected samples
    /// required to detect pollution
    u_int8_t pollutionDetectThreshold;

    /// The maximum percentage of interference detected samples
    /// allowed to clear pollution
    u_int8_t pollutionClearThreshold;

    /// Maximum number of seconds elapsed allowed for a valid
    /// interference detection sample
    u_int32_t interferenceAgeLimit;
} estimatorPollutionAccumulatorParams_t;

/**
 * @brief Function callback type that estimator main logic can register
 *        to observe and react to pollution state change
 *
 * @param [in] pollutionState  the pollution state change
 * @param [in] cookie  the value provided by the caller
 *
 * @return LBD_OK if the observer has done its work reacting to the change;
 *         otherwise return LBD_NOK
 */
typedef LBD_STATUS (*estimatorPollutionAccumulatorObserverCB)(
        estimatorPollutionState_e pollutionState,
        void *cookie);

/**
 * @brief Check whether given pollution accumulator related parameters are valid
 *
 * @param [in] dbgModule  handle to the module to use for error reporting
 * @param [in] params  the accumulator parameters
 *
 * @return LBD_TRUE if the parameters are valid; otherwise return LBD_FALSE
 */
LBD_BOOL estimatorPollutionAccumulatorAreValidParams(
        struct dbgModule *dbgModule, estimatorPollutionAccumulatorParams_t *params);

/**
 * @brief Accumulate interference detection sample and make pollution decision
 *
 * The accumulator buffer will be reset on pollution state change and the observer
 * has successfully reacted to it.
 *
 * @param [in] pollutionAccumulator  the buffer to accumulate interference samples
 * @param [in] detected  whether interference is detected or not
 * @param [in] prevPolluted  whether it is polluted before current sample
 * @param [in] params  pollution accumulator related parameters
 * @param [in] callback  the callback function to be notified of pollution state change
 * @param [in] cookie  the value as callback function parameter
 *
 * @return LBD_NOK if failed to accumulate the sample or reset buffer;
 *         otherwise return LBD_OK
 */
LBD_STATUS estimatorPollutionAccumulatorAccumulate(
        estimatorCircularBufferHandle_t pollutionAccumulator,
        LBD_BOOL detected, LBD_BOOL prevPolluted,
        estimatorPollutionAccumulatorParams_t *params,
        estimatorPollutionAccumulatorObserverCB callback, void *cookie);

/**
 * @brief Reset accumulator based on pollution state
 *
 * @param [in] pollutionAccumulator  the accumulator to reset
 * @param [in] prevPolluted  whether the STA is marked polluted or not
 * @param [in] params  pollution accumulator related parameters
 *
 * @return LBD_OK if the accumulator was reset successfully; otherwise
 *         return LBD_NOK
 */
LBD_STATUS estimatorPollutionAccumulatorReset(
        estimatorCircularBufferHandle_t pollutionAccumulator,
        LBD_BOOL prevPolluted, estimatorPollutionAccumulatorParams_t *params);

#if defined(__cplusplus)
}
#endif

#endif // estimatorPollutionAccumulator__h
