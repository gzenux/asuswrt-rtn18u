/*
 * Tracing utility.
 *
 * Copyright (C) 2015, Broadcom Corporation
 * All Rights Reserved.
 * 
 * This is UNPUBLISHED PROPRIETARY SOURCE CODE of Broadcom Corporation;
 * the contents of this file may not be disclosed to third parties, copied
 * or duplicated in any form, in whole or in part, without the prior
 * written permission of Broadcom Corporation.
 *
 * $Id:$
 */

#ifndef _TRACE_H_
#define _TRACE_H_

#include <stdio.h>
#include <ctype.h>
#include "typedefs.h"
#include "proto/ethernet.h"
#ifdef BCMDRIVER
#include <wl_dbg.h>
#include <wlioctl.h>
#include <bcmutils.h>
#endif

/* --------------------------------------------------------------- */

typedef enum {
	TRACE_NONE		= 0x0000,
	TRACE_ERROR		= 0x0001,
	TRACE_DEBUG		= 0x0002,
	TRACE_EVENT		= 0x0004,
	TRACE_PACKET	= 0x0008,
	TRACE_VERBOSE	= 0x0010,
	TRACE_ALL		= 0xffff,
	TRACE_PRINTF	= 0x10000	/* output same as printf */
} traceLevelE;

extern traceLevelE gTraceLevel;

#define TRACE_LEVEL_SET(level) 	gTraceLevel = level;

#if defined(BCMDBG)

#define TRACE(level, args...)	\
	trace(__FILE__, __LINE__, __FUNCTION__, level, args)

#define TRACE_MAC_ADDR(level, str, mac)	\
	traceMacAddr(__FILE__, __LINE__, __FUNCTION__, level, str, mac)

#define TRACE_HEX_DUMP(level, str, len, buf)	\
	traceHexDump(__FILE__, __LINE__, __FUNCTION__, level, str, len, buf)

#else

#define TRACE(level, args...)

#define TRACE_MAC_ADDR(level, str, mac)

#define TRACE_HEX_DUMP(level, str, len, buf)

#endif	/* BCMDBG */

void trace(const char *file, int line, const char *function,
	traceLevelE level, const char *format, ...);

void traceMacAddr(const char *file, int line, const char *function,
	traceLevelE level, const char *str, struct ether_addr *mac);

void traceHexDump(const char *file, int line, const char *function,
	traceLevelE level, const char *str, int len, uint8 *buf);


/* Compatibility with wl_dbg.h */

#if !defined(BCMDRIVER)

#define WL_ERROR(args)		WL_ERROR_ args
#define WL_ERROR_(args...)	TRACE(TRACE_ERROR, args)

#define WL_TRACE(args)		WL_TRACE_ args
#define WL_TRACE_(args...)	TRACE(TRACE_VERBOSE, args)

#define WL_PRINT(args)		printf args

#define TRACE_P2PO			(TRACE_PACKET)
#define WL_P2PO(args)		WL_P2PO_ args
#define WL_P2PO_(args...)	TRACE(TRACE_P2PO, args)

#define WL_PRPKT(m, b, n)	TRACE_HEX_DUMP(TRACE_PACKET, m, n, b)

#define WL_PRUSR(m, b, n)	TRACE_HEX_DUMP(TRACE_PRINTF, m, n, b)

#define WL_PRMAC(m, mac)	TRACE_MAC_ADDR(TRACE_DEBUG, m, mac)

#if defined(BCMDBG)
#define WL_P2PO_ON()		(gTraceLevel & TRACE_PACKET)
#else
#define WL_P2PO_ON()		(0)
#endif

#else

#if defined(BCMDBG)
#define WL_PRMAC(m, mac)							\
	do {											\
		char eabuf[ETHER_ADDR_STR_LEN];				\
		(void)eabuf;								\
		WL_ERROR(("%s = %s\n", m,					\
			bcm_ether_ntoa((struct ether_addr*)mac,	\
			eabuf)));								\
	} while (0);
#else
#define WL_PRMAC(m, mac)
#endif

#endif /* BCMDRIVER */

#define PRINT_MAC_ADDR(str, mac)	\
	traceMacAddr(__FILE__, __LINE__, __FUNCTION__, TRACE_PRINTF, str, mac)

#define PRINT_HEX_DUMP(str, len, buf)	\
	traceHexDump(__FILE__, __LINE__, __FUNCTION__, TRACE_PRINTF, str, len, buf)

#endif /* _TRACE_H_ */
