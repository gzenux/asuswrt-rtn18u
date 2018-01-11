/*
 * @File: lb_assert.h
 *
 * @Abstract: Assertion support for Load Balancing (aka. steering) logic.
 *
 * @Notes: See below
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

#ifndef lb_assert__h
#define lb_assert__h

#include "lb_common.h"

// ====================================================================
// Traditional asserts (like the standard library one but logs to the
// debug stream). Also will attempt to do a proper shutdown.
// ====================================================================

#define lbDbgAssertExit(module, expression) \
    ((expression) ? \
     (void) (0) : \
     __lbDbgAssertExit(module, __STRING(expression), __FILE__, __LINE__, \
                       __func__))

#endif /* lb_assert__h */
