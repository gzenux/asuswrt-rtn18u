// vim: set et sw=4 sts=4 cindent:
/*
 * @File: estimatorCircularBuffer.c
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

#include <stdlib.h>

#include "lb_assert.h"
#include "lb_common.h"

#include "estimatorCircularBuffer.h"

/**
 * @brief Entry stored in circular buffer
 */
typedef struct estimatorCircularBufferEntry_t {
    /// Whether the entry represents a detected interference or not
    LBD_BOOL detected;

    /// The time at which the entry was inserted
    time_t insertTime;
} estimatorCircularBufferEntry_t;

typedef struct estimatorCircularBufferPriv_t {
    /// Maximum number of entries the buffer can store
    size_t maxBufferSize : 8;

    /// Current buffer size
    size_t bufferSize : 8;

    /// Number of entries inserted into the buffer
    size_t numEntries : 8;

    /// Number of entries inserted being marked as detected
    size_t numDetected : 8;

    /// Index pointed to the oldest entry, i.e to be read next
    size_t readPointer : 8;

    /// Index pointed to the slot that will be written to next
    size_t writePointer : 8;

    /// The base age threshold to remove old entries
    time_t ageLimitPerEntry;

    /// List of entries, size equals to maxBufferSize
    estimatorCircularBufferEntry_t entries[0];
} estimatorCircularBufferPriv_t;


// Forward declarations
static void estimatorCircularBufferRemoveOldest(
        estimatorCircularBufferPriv_t *buffer,
        estimatorCircularBufferEntry_t *readPointer);
static LBD_BOOL estimatorCircularBufferIsEntryOld(
        const estimatorCircularBufferPriv_t *buffer,
        const estimatorCircularBufferEntry_t *entry,
        const struct timespec *curTime);


estimatorCircularBufferHandle_t
estimatorCircularBufferCreate(size_t initSize, size_t maxSize, time_t ageLimitPerEntry) {
    if (!initSize || initSize > maxSize || !ageLimitPerEntry) { return NULL; }

    estimatorCircularBufferHandle_t buffer =
        calloc(1, sizeof(estimatorCircularBufferPriv_t) +
                      maxSize * sizeof(estimatorCircularBufferEntry_t));

    if (!buffer) { return NULL; }

    buffer->maxBufferSize = maxSize;
    buffer->bufferSize = initSize;
    buffer->ageLimitPerEntry = ageLimitPerEntry;

    return buffer;
}

void estimatorCircularBufferDestroy(estimatorCircularBufferHandle_t buffer) {
    if (buffer) {
        free(buffer);
    }
}

LBD_STATUS estimatorCircularBufferReset(estimatorCircularBufferHandle_t buffer,
                                        size_t bufferSize) {
    if (!buffer || !bufferSize || bufferSize > buffer->maxBufferSize) {
        return LBD_NOK;
    }

    buffer->numEntries = 0;
    buffer->numDetected = 0;
    buffer->readPointer = 0;
    buffer->writePointer = 0;
    buffer->bufferSize = bufferSize;

    return LBD_OK;
}

LBD_STATUS estimatorCircularBufferInsert(estimatorCircularBufferHandle_t buffer,
                                         LBD_BOOL detected, size_t *numDetected,
                                         size_t *numTotal) {
    if (!buffer || !numDetected || !numTotal) { return LBD_NOK; }

    struct timespec curTime = {0};
    lbGetTimestamp(&curTime);

    // First remove old entries
    size_t i;
    for (i = buffer->readPointer; i < (buffer->readPointer + buffer->numEntries); ++i) {
        estimatorCircularBufferEntry_t *entry = &buffer->entries[i % buffer->bufferSize];
        if (estimatorCircularBufferIsEntryOld(buffer, entry, &curTime)) {
            estimatorCircularBufferRemoveOldest(buffer, entry);
        } else {
            // All entries after this should be recent enough
            break;
        }
    }

    // Kickout the oldest entry if the buffer is full
    if (buffer->writePointer == buffer->readPointer && buffer->numEntries) {
        estimatorCircularBufferRemoveOldest(
                buffer, &buffer->entries[buffer->readPointer]);
    }

    // Insert the new entry
    buffer->entries[buffer->writePointer].detected = detected;
    buffer->entries[buffer->writePointer].insertTime = curTime.tv_sec;
    ++buffer->numEntries;
    buffer->writePointer = (buffer->writePointer + 1) % buffer->bufferSize;
    if (detected) { ++buffer->numDetected; }

    *numDetected = buffer->numDetected;
    *numTotal = buffer->numEntries;

    return LBD_OK;
}

/**
 * @brief Remove the oldest entry from the given circular buffer
 *
 * @param [in] buffer  the given circular buffer
 * @param [in] oldestEntry  the entry to be removed
 */
static void estimatorCircularBufferRemoveOldest(
        estimatorCircularBufferPriv_t *buffer,
        estimatorCircularBufferEntry_t *oldestEntry) {
    if (oldestEntry->detected) {
        --buffer->numDetected;
    }
    --buffer->numEntries;
    buffer->readPointer = (buffer->readPointer + 1) % buffer->bufferSize;
}

/**
 * @brief Check if an entry is old enough to be removed
 *
 * @param [in] buffer  the circular buffer
 * @param [in] entry  the entry stored
 * @param [in] curTime  current time
 *
 * @return LBD_TRUE if the entry is old enough; otherwise return LBD_FALSE
 */
static LBD_BOOL estimatorCircularBufferIsEntryOld(
        const estimatorCircularBufferPriv_t *buffer,
        const estimatorCircularBufferEntry_t *entry,
        const struct timespec *curTime) {
    // Plus one to make sure it has truly past age limit
    return (curTime->tv_sec - entry->insertTime) >=
               (buffer->ageLimitPerEntry * buffer->bufferSize + 1);
}
