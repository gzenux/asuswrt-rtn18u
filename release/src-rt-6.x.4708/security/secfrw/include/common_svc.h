/*****************************************************************************
 * common service
 * common_svc.h
 * Header file for common svc funs
 * Copyright (C) 2014, Broadcom Corporation
 * All Rights Reserved.
 * 
 * This is UNPUBLISHED PROPRIETARY SOURCE CODE of Broadcom Corporation;
 * the contents of this file may not be disclosed to third parties, copied
 * or duplicated in any form, in whole or in part, without the prior
 * written permission of Broadcom Corporation.
 * $Id: common_svc.h,v 1.1 2010-03-08 22:38:35 $
 *****************************************************************************
*/


#if !defined(__COMMON_SVC_H__)
#define __COMMON_SVC_H__

struct wpa {
	/* adaptation layer */
	int (*cfg)(struct wpa_dat *);
	int (*cleanup)(struct wpa_dat *);
};

struct wpa_al {
	/* adaptation layer */
	int (*cfg)(struct wpa_dat *);
	int (*cleanup)(struct wpa_dat *);

	/* rx frame handler */
	int (*frame_rx_handler)(void *, void *, int);

	/* event handler */
	int (*event_rx_handler)(void *, void *, int);

	/* which eapol transport protocol */
	int proto_index;

	void (*events)(void *, void *);

};

extern int
common_svc_init(struct cfg_ctx *ctx, const struct wpa_al *wpa);


extern int
common_svc_deinit(struct cfg_ctx *ctx, const struct wpa_al *wpa);


#endif /* __COMMON_SVC_H__ */
