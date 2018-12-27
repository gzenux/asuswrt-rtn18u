/*
 * EVENTD shared include file
 *
 * Copyright (C) 2015, Broadcom Corporation
 * All Rights Reserved.
 * 
 * This is UNPUBLISHED PROPRIETARY SOURCE CODE of Broadcom Corporation;
 * the contents of this file may not be disclosed to third parties, copied
 * or duplicated in any form, in whole or in part, without the prior
 * written permission of Broadcom Corporation.
 *
 * $Id: eventd.h 506825 2014-10-07 13:05:36Z $
 */

#ifndef _eventd_h_
#define _eventd_h_

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>

#include <assert.h>
#include <typedefs.h>
#include <bcmnvram.h>
#include <bcmutils.h>
#include <bcmtimer.h>
#include <bcmendian.h>

#include <shutils.h>
#include <bcmendian.h>
#include <bcmwifi_channels.h>
#include <wlioctl.h>
#include <wlutils.h>

#include <security_ipc.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <net/if.h>
#include <arpa/inet.h>


extern bool eventd_swap;
#define htod32(i) (eventd_swap?bcmswap32(i):(uint32)(i))
#define htod16(i) (eventd_swap?bcmswap16(i):(uint16)(i))
#define dtoh32(i) (eventd_swap?bcmswap32(i):(uint32)(i))
#define dtoh16(i) (eventd_swap?bcmswap16(i):(uint16)(i))
#define htodchanspec(i) (eventd_swap?htod16(i):i)
#define dtohchanspec(i) (eventd_swap?dtoh16(i):i)
#define htodenum(i) (eventd_swap?((sizeof(i) == 4) ? \
			htod32(i) : ((sizeof(i) == 2) ? htod16(i) : i)):i)
#define dtohenum(i) (eventd_swap?((sizeof(i) == 4) ? \
			dtoh32(i) : ((sizeof(i) == 2) ? htod16(i) : i)):i)


extern int eventd_debug_level;

#define EVENTD_DEBUG_ERROR	0x0001
#define EVENTD_DEBUG_WARNING	0x0002
#define EVENTD_DEBUG_INFO		0x0004
#define EVENTD_DEBUG_DETAIL	0x0008


#define EVENTD_ERROR(fmt, arg...) \
		do { if (eventd_debug_level & EVENTD_DEBUG_ERROR) \
			printf("EVENTD >>%s(%d): "fmt, __FUNCTION__, __LINE__, ##arg); } while (0)

#define EVENTD_WARNING(fmt, arg...) \
		do { if (eventd_debug_level & EVENTD_DEBUG_WARNING) \
			printf("EVENTD >>%s(%d): "fmt, __FUNCTION__, __LINE__, ##arg); } while (0)

#define EVENTD_INFO(fmt, arg...) \
		do { if (eventd_debug_level & EVENTD_DEBUG_INFO) \
			printf("EVENTD >>%s(%d): "fmt, __FUNCTION__, __LINE__, ##arg); } while (0)

#define EVENTD_DEBUG(fmt, arg...) \
		do { if (eventd_debug_level & EVENTD_DEBUG_DETAIL) \
			printf("EVENTD >>%s(%d): "fmt, __FUNCTION__, __LINE__, ##arg); } while (0)

#define EVENTD_BUFSIZE_4K	4096

#define EVENTD_OK	0
#define EVENTD_FAIL -1

#define EVENTD_IFNAME_SIZE		16
#define EVENTD_MAX_INTERFACES		3
#define EVENT_MAX_IF_NUM EVENTD_MAX_INTERFACES

#define EVENTD_DFLT_POLL_INTERVAL 1  /* default polling interval */

#endif /*  _eventd_h_ */
