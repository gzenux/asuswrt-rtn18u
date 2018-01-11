// vim: set et sw=4 sts=4 cindent:
/*
 * @File: estimatorCircularBuffer.h
 *
 * @Abstract: Circular buffer to store interference detection result
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

#ifndef estimatorCircularBuffer__h
#define estimatorCircularBuffer__h

#include <time.h>

#include "lbd_types.h"

#if defined(__cplusplus)
extern "C" {
#endif

struct estimatorCircularBufferPriv_t; // opaque forward declaration
typedef struct estimatorCircularBufferPriv_t *estimatorCircularBufferHandle_t;

/**
 * @brief Create a circular buffer
 *
 * @param [in] initSize  the initial capacity to allocte for the buffer
 * @param [in] maxSize  maximum capacity it can grow to
 * @param [in] ageLimitPerEntry  the base age threshold to remove old
 *                               entries, while the total age threshold
 *                               equals to (ageLimit * bufferSize)
 *
 * @return a handle to the circular buffer, or NULL if it cannot be created
 */
estimatorCircularBufferHandle_t
estimatorCircularBufferCreate(size_t initSize, size_t maxSize, time_t ageLimitPerEntry);

/**
 * @brief Destroy a circular buffer instance, including all entries stored
 *
 * @param [in] handle  the handle returned from estimatorCircularBufferInit
 */
void estimatorCircularBufferDestroy(estimatorCircularBufferHandle_t handle);

/**
 * @brief Reset the circular buffer with the given size
 *
 * The buffer will be wiped so all stored data will be lost.
 *
 * @pre the given buffer size cannot be larger than the maxSize given at init time.
 *
 * @param [in] handle  the handle returned from estimatorCircularBufferInit
 * @param [in] bufferSize  new buffer size
 *
 * @return LBD_NOK if the new buffer size is invalid; otherwise return LBD_OK
 */
LBD_STATUS estimatorCircularBufferReset(estimatorCircularBufferHandle_t handle,
                                        size_t bufferSize);

/**
 * @brief Insert an entry into the buffer
 *
 * It will also remove from the end of the circular buffer any entries that do not
 * meet the minimum age requirement.
 *
 * @param [in] handle  the handle returned from estimatorCircularBufferInit
 * @param [in] detected  the detection result to be inserted
 * @param [out] numDetected  on success, return the number of detected entries stored
 * @param [out] numTotal  on success, return the total number of entries stored
 *
 * @return LBD_NOK if the entry is NULL; otherwise return LBD_OK
 */
LBD_STATUS estimatorCircularBufferInsert(estimatorCircularBufferHandle_t handle,
                                         LBD_BOOL detected, size_t *numDetected,
                                         size_t *numTotal);

#if defined(__cplusplus)
}
#endif

#endif // estimatorCircularBuffer__h
