/*
 * Exposed interfaces of wlc_auth.c
 *
 * Copyright (C) 2014, Broadcom Corporation
 * All Rights Reserved.
 * 
 * This is UNPUBLISHED PROPRIETARY SOURCE CODE of Broadcom Corporation;
 * the contents of this file may not be disclosed to third parties, copied
 * or duplicated in any form, in whole or in part, without the prior
 * written permission of Broadcom Corporation.
 *
 * $Id: wlc_auth.h,v 1.1.1.1 2010-02-04 00:44:37 $
 */

#ifndef _wlc_auth_h_
#define _wlc_auth_h_

/* Values for type parameter of wlc_set_auth() */
#define AUTH_UNUSED	0	/* Authenticator unused */
#define AUTH_WPAPSK	1	/* Used for WPA-PSK */


/* Install WPA PSK material in authenticator */
extern int wlc_auth_set_pmk(authenticator_t *auth, wsec_pmk_t *psk);
extern bool wlc_set_auth(authenticator_t *auth, int type, uint8 *sup_ies, uint sup_ies_len,
                         uint8 *auth_ies, uint auth_ies_len, sta_parms_t *scb);

extern bool wlc_auth_eapol(authenticator_t *auth, eapol_header_t *eapol_hdr,
                           bool encrypted, sta_parms_t *scb);

extern void wlc_auth_retry_timer(void *arg);

extern void wlc_auth_initialize_gkc(authenticator_t *auth);

#endif	/* _wlc_auth_h_ */
