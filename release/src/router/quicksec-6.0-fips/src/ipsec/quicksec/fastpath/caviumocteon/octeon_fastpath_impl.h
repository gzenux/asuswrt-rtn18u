/**
   @copyright
   Copyright (c) 2007 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   Implementations of the macros described in fastpath_accel.h
*/

#ifndef OCTEON_FASTPATH_IMPL_H
#define OCTEON_FASTPATH_IMPL_H 1

#include "fastpath_accel.h"

/** Cavium Octeon reserves an exclusive IPv4 ID range for engine and software
    fastpath. */
#define FASTPATH_ENGINE_IP_ID_MIN 0xf000
#define FASTPATH_ENGINE_IP_ID_MAX 0xffff

/** Cavium Octeon reserves an exclusive IPv6 frag ID range for engine and
    software fastpath. */
#define FASTPATH_ENGINE_IPV6_FRAG_ID_MIN 0xf0000000
#define FASTPATH_ENGINE_IPV6_FRAG_ID_MAX 0xffffffff

/** Cavium Octeon implements per object locking. */

#endif /* OCTEON_FASTPATH_IMPL_H */
