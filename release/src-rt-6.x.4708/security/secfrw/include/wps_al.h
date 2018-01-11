/*****************************************************************************
 * WPS adaptation layer
 * Header file for WPS adaptation layer
 * Copyright (C) 2014, Broadcom Corporation
 * All Rights Reserved.
 * 
 * This is UNPUBLISHED PROPRIETARY SOURCE CODE of Broadcom Corporation;
 * the contents of this file may not be disclosed to third parties, copied
 * or duplicated in any form, in whole or in part, without the prior
 * written permission of Broadcom Corporation.
 * $Id: wps_al.h,v 1.1 2010-08-09 19:28:58 $
 *****************************************************************************
*/


#if !defined(__WPS_AL_H__)
#define __WPS_AL_H__

struct wps_dat;
struct cfg_ctx;
struct cfg_ctx_set_cfg;
struct bcmseclib_ev_wps;

struct wps_cbs {
	void (*result)(struct cfg_ctx *, const struct bcmseclib_ev_wps *);
};

/* sup/enrollee */

extern int
wps_sup_enr_cfg(struct wps_dat *);

extern int
wps_sup_enr_cleanup(struct wps_dat *);

extern int
wps_sup_eapol_hdlr(void *arg, void *frame, int len);

extern int
wps_sup_handle_event(void *arg, void *event, int len);

extern int
wps_sup_unpack(struct cfg_ctx *, struct wps_dat *,
			   const struct cfg_ctx_set_cfg *);

/* auth/registrar */

extern int
wps_auth_cfg(struct wps_dat *dat);

extern int
wps_auth_cleanup(struct wps_dat *dat);

extern int
wps_auth_eapol_hdlr(void *arg, void *pkt, int len);

extern int
wps_auth_handle_event(void *arg, void *pevt, int len);

extern int
wps_auth_unpack(struct cfg_ctx *, struct wps_dat *,
				const struct cfg_ctx_set_cfg *);

/* common */

extern void
wps_cbs(struct wps_dat *, const struct wps_cbs *);

extern void
wps_set_eapol_tx(struct wps_dat *, void *);

extern void
wps_events(void *ctx, void *priv);

extern struct cfg_ctx *
wps_get_ctx(struct wps_dat *);

extern void
wps_set_ctx(struct wps_dat *, struct cfg_ctx *);

#if defined(WPS_CFG_PRIVATE)

/*
 * wps private
*/

struct wps_dat {

	/* al dat */
	uchar is_started : 1;
	uchar is_session : 1;
	struct bcmseclib_timer *timer;

	/* svc */
	const struct wps_cbs *cb;

	/* cfg */
	char pin[9];
	uint8 ssid[DOT11_MAX_SSID_LEN];
	int ssid_len;
	char nw_key[64+1];
	unsigned auth_type;
	unsigned encr_type;
	uint16 wep_index;
	uint8 peer_mac_addr[6];

	/* svc wiring */
	struct cfg_ctx *ctx; /* back pointer */
	struct bind_sk eapol, wlss;
	void *eapol_tx;

}; /* struct wps_dat */

#endif /* defined(WPS_CFG_PRIVATE) */

#endif /* __WPS_AL_H__ */
