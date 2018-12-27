/*
 * wlssev.h
 * Wireless events
 *
 * Copyright (C) 2014, Broadcom Corporation
 * All Rights Reserved.
 * 
 * This is UNPUBLISHED PROPRIETARY SOURCE CODE of Broadcom Corporation;
 * the contents of this file may not be disclosed to third parties, copied
 * or duplicated in any form, in whole or in part, without the prior
 * written permission of Broadcom Corporation.
 *
 * $Id: wlssev.h,v 1.1 2010-05-05 21:02:58 $
*/

#ifndef _wlssev_h_
#define _wlssev_h_

#define SECLIB_BCM_EVENT_FLAGS(p) \
	(((struct seclib_ev *)(p))->event->flags)

#define SECLIB_BCM_EVENT_TYPE(p) \
	(((struct seclib_ev *)(p))->event->event_type)

#define SECLIB_BCM_EVENT_STATUS(p) \
	((struct seclib_ev *)(p))->event->status)
	
#define SECLIB_BCM_EVENT_REASON(p) \
	(((struct seclib_ev *)(p))->event->reason)

#define SECLIB_BCM_EVENT_DATALEN(p) \
	(((struct seclib_ev *)(p))->event->datalen)

#define SECLIB_BCM_EVENT_ADDR(p) \
	(&((struct seclib_ev *)(p))->event->addr)

#define SECLIB_BCM_EVENT_DATA(p) \
	(((struct seclib_ev *)(p))->data)

#define SECLIB_BCM_EVENT_ADDR_SIZE(p) \
	(sizeof(((struct seclib_ev *)(p))->event->addr))

#define SECLIB_BCM_EVENT_FLAG_LINK_UP(p) \
	(ntoh16(SECLIB_BCM_EVENT_FLAGS(p)) & WLC_EVENT_MSG_LINK)

#define SECLIB_BCM_EVENT_FLAG_GRP_MIC_ERR(p) \
	(SECLIB_BCM_EVENT_FLAGS(p) & WLC_EVENT_MSG_GROUP)

/* This struct is private and subject to change.
 * Use the macros that are defined above!
*/
struct seclib_ev {
	wl_event_msg_t *event;	/* unaligned */
	void *data;	/* unaligned */
};

#endif /* _wlssev_h_ */
