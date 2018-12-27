/**
   @copyright
   Copyright (c) 2004 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   Implementations of the macros described in engine_fastpath.h.
   This header file includes the fastpath specific header file that
   implements the required macros.

*/

#ifndef FASTPATH_IMPL_H
#define FASTPATH_IMPL_H 1

#ifdef FASTPATH_IS_SCP51X0
#include "scp51x0_fastpath_impl.h"
#endif /* FASTPATH_IS_SCP51X0 */

#ifdef SSHDIST_IPSEC_HWACCEL_OCTEON
#ifdef FASTPATH_IS_OCTEON
#include "octeon_fastpath_impl.h"
#endif /* FASTPATH_IS_OCTEON */
#endif /* SSHDIST_IPSEC_HWACCEL_OCTEON */

#ifdef FASTPATH_IS_TILEGX
#include "tilegx_fastpath_impl.h"
#endif /* FASTPATH_IS_TILEGX */

/* Include the software fastpath */
#include "engine_fastpath_impl.h"

#endif /* FASTPATH_IMPL_H */
