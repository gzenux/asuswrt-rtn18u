/*
 * @File: lb_common.c
 *
 * @Abstract: Load balancing common helper functions.
 *
 * @Notes: Macros and functions used by the load balancing daemon
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

#include <time.h>
#include <assert.h>

#include <dbg.h>

#include "lb_common.h"

static const time_t NUM_NSEC_IN_SEC = 1000000000;

void lbGetTimestamp(struct timespec *ts) {
    clock_gettime(CLOCK_MONOTONIC, ts);
}

LBD_BOOL lbIsTimeBefore(const struct timespec *time1,
                        const struct timespec *time2) {
    assert(time1);
    assert(time2);

    return time1->tv_sec < time2->tv_sec ||
           (time1->tv_sec == time2->tv_sec &&
            time1->tv_nsec < time2->tv_nsec);
}

void lbTimeDiff(const struct timespec *time1,
                const struct timespec *time2,
                struct timespec *diff) {
    assert(time1);
    assert(time2);
    assert(diff);
    assert(!lbIsTimeAfter(time2, time1));

    time_t sec = time1->tv_sec;
    if (time1->tv_nsec >= time2->tv_nsec) {
        diff->tv_nsec = time1->tv_nsec - time2->tv_nsec;
    } else {
        sec--;
        diff->tv_nsec = NUM_NSEC_IN_SEC -
            (time2->tv_nsec - time1->tv_nsec);
    }

    diff->tv_sec = sec - time2->tv_sec;
}

void __lbDbgAssertExit(struct dbgModule *dbg, const char *assertion,
                       const char *filename, unsigned int line,
                       const char *function) {
    dbgf(dbg, DBGERR, "%s (%s:%u): Assertion '%s' failed",
         function, filename, line, assertion);

    lbFatalShutdown();
}
