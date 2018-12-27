/**
   @copyright
   Copyright (c) 2008 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   Cavium Octeon Simple Executive fastpath for QuickSec.
   This file includes tunable defines for SE fastpath and
   accelerated fastpath.
*/

#ifndef OCTEON_SE_FASTPATH_PARAMS_H
#define OCTEON_SE_FASTPATH_PARAMS_H 1

/** Defines for enabling general features on SE fastpath */

/** Define to enable flow and transform statistics collection on SE fastpath.
    This must be defined if kilobyte based IPsec SA lifetimes are used. */
/* #define OCTEON_SE_FASTPATH_STATISTICS */

/** Define to enable packet fragmentation on SE fastpath. */
/* #define OCTEON_SE_FASTPATH_FRAGMENTATION */

/** Define to enable AH transform on SE fastpath. */
/* #define OCTEON_SE_FASTPATH_TRANSFORM_AH */

/** Define to enable transport mode on SE fastpath. */
/* #define OCTEON_SE_FASTPATH_TRANSFORM_TRANSPORT_MODE */

/** Define to enable SHA-256 support on SE fastpath */
/* #define OCTEON_SE_FASTPATH_TRANSFORM_SHA_256 */

/** Define to enable SHA-384 and SHA-512 support on SE fastpath */
/* #define OCTEON_SE_FASTPATH_TRANSFORM_SHA_512 */

/** Define to enable AES-GCM support on SE fastpath*/
/* #define OCTEON_SE_FASTPATH_TRANSFORM_AES_GCM */

/** Define to enable UDP NAT-T encapsulation on SE fastpath. */
/* #define OCTEON_SE_FASTPATH_TRANSFORM_NATT */

/** Define to enable ESN on SE fastpath. */
/* #define OCTEON_SE_FASTPATH_TRANSFORM_LONGSEQ */

/** Undefine to disable optional ESP padding format verification. */
#define OCTEON_SE_FASTPATH_TRANSFORM_ESP_PADDING_FORMAT_VERIFICATION

/** Define to enable forwarding of passby IPsec packets on SE fastpath. */
/* #define OCTEON_SE_FASTPATH_FORWARD_IPSEC_PASSBY */

/** Define to enable passing corrupted packets to slowpath. */
#define OCTEON_SE_FASTPATH_AUDIT_CORRUPT

/** Define the maximum number of Octeon cpus on the system. These defines are
    used for preallocating tables on the SE fastpath. */
#define OCTEON_SE_FASTPATH_MAX_NUM_CPUS 1

/** Undefine to disable rate limiting of packets from SE fastpath to
    slowpath. */
#define OCTEON_SE_FASTPATH_SLOWPATH_RATE_LIMITING

/** Define the ratio of cores running SE fastpath to cores running slowpath.
    This is used for estimating the slowpath rate limiting variables in
    octeon_se_fastpath_internal.h. By default the rate limiting variables are
    optimized for Cavium EBT-5800 with CN-5860 running at 700MHz. You may need
    to fine tune the rate limiting variables to match your Octeon setup and
    core clock frequency. */
#define OCTEON_SE_FASTPATH_SLOWPATH_RATIO 15

/** Defines for enabling debug features on SE fastpath */

/** Define to enable cpu cycle counting on SE fastpath. This should only be
    used for debugging while tuning the performance of the SE fastpath. */
/* #define OCTEON_SE_FASTPATH_COUNT_CYCLES */

/** Define to enable per core statistics counters on SE fastpath. This should
    only be used to debug problems in work scheduling or slowpath interaction.
*/
/* #define OCTEON_SE_FASTPATH_COLLECT_CORE_STATS */

/** Define to enable debug statements and assertions */
/* #define OCTEON_SE_FASTPATH_DEBUG */

/** Define what debug statements are compiled in. Debug levels are following:
    0 none, 3 errors, 5 slowpath, 7 dumps for dropped packets, 9 everything. */
#define OCTEON_SE_FASTPATH_DEBUG_LEVEL 3

#endif /* OCTEON_SE_FASTPATH_PARAMS_H */
