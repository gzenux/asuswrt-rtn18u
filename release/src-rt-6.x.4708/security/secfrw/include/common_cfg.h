/*
 * common_cfg.h
 * Platform independent config routines
 *
 * Copyright (C) 2014, Broadcom Corporation
 * All Rights Reserved.
 * 
 * This is UNPUBLISHED PROPRIETARY SOURCE CODE of Broadcom Corporation;
 * the contents of this file may not be disclosed to third parties, copied
 * or duplicated in any form, in whole or in part, without the prior
 * written permission of Broadcom Corporation.
 *
 * $Id: common_cfg.h,v 1.1 2010-03-08 22:38:35 $
*/

#ifndef _common_cfg_h_
#define _common_cfg_h_

struct ctx;
struct cfg_ctx;
struct cfg_ctx_set_cfg;
struct wpa_dat;
struct bind_sk;

extern void
common_sk_init(struct wpa_dat *dat, struct bind_sk **eapol,
			  int (*eapol_fun)(void *, void *, int),
			  struct bind_sk **wlss,
			  int (*evt_fun)(void *, void *, int));

extern void
common_sk_deinit(struct wpa_dat *dat, struct bind_sk **eapol,
		struct bind_sk **wlss);

#endif /* _common_cfg_h_ */
