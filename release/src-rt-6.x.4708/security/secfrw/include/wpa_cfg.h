/*
 * wpa_cfg.h
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
 * $Id: wpa_cfg.h,v 1.2 2010-03-08 22:49:21 $
*/

#ifndef _wpa_cfg_h_
#define _wpa_cfg_h_

struct ctx;
struct cfg_ctx;
struct cfg_ctx_set_cfg;
struct wpa_dat;
struct bind_sk;

/*
 * wpa supplicant
*/

/* Top level supplicant init: called when library is starting up */
void wpa_sup_init();

/* Top level supplicant de-init: called when library is shutting down */
int wpa_sup_deinit();

/* Config a supplicant instance */
int wpa_sup_cfg(struct wpa_dat *);

/* De-init a supplicant instance */
int wpa_sup_cleanup(struct wpa_dat *);

/*
 * wpa authenticator
*/

/* Config an auth instance */
int wpa_auth_cfg(struct wpa_dat *);

/* Top level auth init: called when library is starting up */
int wpa_auth_init();

/* De-init an auth instance */
int wpa_auth_cleanup(struct wpa_dat *);

/*
 * wpa common
*/

/* EAPOL traffic handler */
extern int
wpa_handle_8021x(void *arg, void *frame, int len);

/* state indication handler */
extern int
wpa_handle_event(void *arg, void *event, int len);

/* device events */
extern void
wpa_events(void *ctx, void *priv);

/* get ctx pointer */
extern struct cfg_ctx *
wpa_get_ctx(struct wpa_dat *);

/* set ctx pointer */
extern void
wpa_set_ctx(struct wpa_dat *, struct cfg_ctx *);

/* set eapol tx context */
extern void
wpa_set_eapol_tx(struct wpa_dat *, void *tx);

/* init stacks */
extern void
wpa_sk_init(struct wpa_dat *, struct bind_sk **eapol_sk,
			struct bind_sk **wlss_sk);

/* deinit stacks */
extern void
wpa_sk_deinit(struct wpa_dat *, struct bind_sk **eapol_sk,
			  struct bind_sk **wlss_sk);

/* unpack a WPA configuration */
extern int
wpa_cfg(struct cfg_ctx *, struct wpa_dat *, const struct cfg_ctx_set_cfg *);


#if defined(WPA_CFG_PRIVATE)

/*
 * wpa private
*/


struct wpa_dat {
	/*
	 * configuration
	*/
	
	int WPA_auth;	/* WPA authentication mode bitvec, wlioctl.h */
	int auth_type;	/* AUTH_WPAPSK or AUTH_UNUSED, wpa_auth.h */
	int wsec;	/* wireless security bitvec, wlioctl.h */
	int btamp_enabled;	/* this cfg for a btamp link */

	/* the end product of hashing the passphrase */
	uint8 pmk[PMK_LEN];
	int pmk_len;			/* uselses: always PMK_LEN? */

	/* code will be TRUE (AUTHORIZED) or FALSE (DEAUTHENTICATED, for a reason)
	 * reason is only valid for DEAUTHENTICATED code
	 * AUTHORIZED means successful handshake & keys plumbed
	 */
	void (*result)(void *, unsigned char code, unsigned char reason);

	int role;

	/*
	 * adaptation layer data
	*/
	
	struct cfg_ctx *ctx; /* back pointer */
	struct ctx *svc_ctx;		/* contains ctx handle returned by supp/auth */
	struct bind_sk eapol, wlss;
	void *eapol_tx;
	struct ether_addr cur_etheraddr;
	struct ether_addr BSSID;

}; /* struct wpa_dat */

#endif /* defined(WPA_CFG_PRIVATE) */

#endif /* _wpa_cfg_h_ */
