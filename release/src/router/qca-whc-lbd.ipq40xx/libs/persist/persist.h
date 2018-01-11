// vim: set et sw=4 sts=4 cindent:
/*
 * @File: persist.h
 *
 * @Abstract: stadb persistence
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
 *
 */

#ifndef persist__h
#define persist__h

#include "lbd_types.h"

#if defined(__cplusplus)
extern "C" {
#endif

// ====================================================================
// Types for use within this module's APIs
// ====================================================================

// ====================================================================
// Lifecyle functions
// ====================================================================

/**
 * @brief Initialize the persist library.
 *
 * This will start the timer to persist stadb.
 */
LBD_STATUS persist_init(void);

/**
 * @brief Perform a clean shutdown of the persist functionality,
 *        terminating all of underlying components.
 */
void persist_fini(void);

#define PERSIST_FILE_KEY "PersistFile"
#define PERSIST_PERIOD_KEY "PersistPeriod"

#if defined(__cplusplus)
}
#endif

#endif /* persist__h */
