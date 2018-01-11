/*
 * @File: internal.h
 *
 * @Abstract: internal header file.
 *
 * @Notes: Macros and functions used internally
 *
 * Copyright (c) 2011, 2015 Qualcomm Atheros, Inc.
 * All Rights Reserved.
 * Qualcomm Atheros Confidential and Proprietary.
 *
 */

#ifndef internal__h		/*once only */
#define internal__h

#include <string.h>
#include <stddef.h>
#include <sys/types.h>		/* Primitive types: u_int32_t, u_int8_t... */
#include <net/ethernet.h>	/* Ethernet structures */

/*
 * MCS_STATUS - function return values
 */
typedef enum {
	MCS_OK = 0,
	MCS_NOK = -1
} MCS_STATUS;

/*
 * MCS_BOOL - boolean values
 */
typedef enum {
	MCS_FALSE = 0,
	MCS_TRUE = !MCS_FALSE
} MCS_BOOL;

#define ETH_ADDR_LEN             ETH_ALEN

/*
 * MACAddrCopy - Copy MAC address variable
 */
#define MACAddrCopy(src, dst) memcpy( dst, src, ETH_ADDR_LEN )

/*
 * MACAddrEqual - Compare two MAC addresses (returns 1 if equal)
 */
#define MACAddrEqual(arg1, arg2) (!memcmp(arg1, arg2, ETH_ADDR_LEN))

/*
 * MACAddrHash - Create a Hash out of a MAC address
 */
#define MACAddrHash(_arg) (__byteof(_arg, 0) ^ __byteof(_arg, 1) ^ __byteof(_arg, 2) \
		^ __byteof(_arg, 3) ^ __byteof(_arg, 4) ^ __byteof(_arg, 5))	/* convert to use the ETH_ADDR_LEN constant */

/*
 * MACAddrFmt - Format a MAC address (use with (s)printf)
 */
#define MACAddrFmt(_sep) "%02X" _sep "%02X" _sep "%02X" _sep "%02X" _sep "%02X" _sep "%02X"

/*
 * MACAddrData - MAC Address data octets
 */
#define MACAddrData(_arg) __byteof(_arg, 0), __byteof(_arg, 1), __byteof(_arg, 2), __byteof(_arg, 3), __byteof(_arg, 4), __byteof(_arg, 5)

#define __byteof(_arg, _i) (((u_int8_t *)_arg)[_i])


#endif
