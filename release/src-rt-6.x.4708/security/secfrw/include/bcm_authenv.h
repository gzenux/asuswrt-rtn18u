/*
 * bcm_authenv.h -- platform dependent environment stuff
 *
 * Copyright (C) 2014, Broadcom Corporation
 * All Rights Reserved.
 * 
 * This is UNPUBLISHED PROPRIETARY SOURCE CODE of Broadcom Corporation;
 * the contents of this file may not be disclosed to third parties, copied
 * or duplicated in any form, in whole or in part, without the prior
 * written permission of Broadcom Corporation.
 *
 * $Id: bcm_authenv.h,v 1.1.1.1 2010-02-04 00:44:36 $
 */

#ifndef _bcm_authenv_h_
#define _bcm_authenv_h_


#define AUTH_WPA2_RETRY		3	/* number of retry attempts */
#define AUTH_WPA2_RETRY_TIMEOUT	1000	/* 1 sec retry timeout */

/* PRF() expects to write its result sloppily. */
#define PRF_RESULT_LEN	80

#define GMK_LEN			32
#define KEY_COUNTER_LEN		32

#define AUTH_FLAG_GTK_PLUMBED	0x1		/* GTK has been plumbed into h/w */
#define AUTH_FLAG_PMK_PRESENT	0x2		/* auth->psk contains pmk */

/* GTK plumbing index values */
#define GTK_INDEX_1	1
#define GTK_INDEX_2	2

/* Toggle GTK index.  Indices 1 - 3 are usable; spec recommends 1 and 2. */
#define GTK_NEXT_INDEX(auth)	((auth)->gtk_index == GTK_INDEX_1 ? GTK_INDEX_2 : GTK_INDEX_1)

#define MAX_STA_COUNT	16

typedef
struct sta_parms {
	struct sta_parms *next;			/* ll next: MUST be first element */
	struct auth_info *auth;			/* back ptr to auth structure */
	struct ether_addr sta_ea;	/* This sta's ether address */
	wpapsk_t wpa;						/* volatile wpa state info */
	wpapsk_info_t wpa_info;			/* non volatile wpa info */
	bool have_keys;						/* authorized (TRUE), not (FALSE) */
	bcmseclib_timer_t *tlist;		/* timers owned by this sta */
} sta_parms_t;

typedef
struct auth_info {
	struct ctx ctx;			/* back pointer to cfg */
	int sup_wpa2_eapver;	/* placeholder: set to zero */
	int sup;				/* placeholder: set to NULL */
	struct ether_addr auth_ea;	/* authenticator's ea */
	struct sta_parms *sta_list;	/* ll of sta's */

	/* following grabbed from struct authenticator in wlc_auth.c */
	uint16 flags;			/* operation flags */

	/* mixed-mode WPA/WPA2 is not supported */
	int auth_type;			/* authenticator discriminator */
	int WPA_auth;			/* in lieu of bsscfg->WPA_auth */
	int btamp_enabled;		/* zero: no, non-zero yes */
	int wsec;				/* wsec bit vector */

	/* global passphrases used for cobbling pairwise keys */
	ushort psk_len;			/* len of pre-shared key */
	uchar  psk[WSEC_MAX_PSK_LEN];	/* saved pre-shared key */

	/* group key stuff */
	uint8 gtk[TKIP_KEY_SIZE];		/* group transient key */
	uint8 gtk_index;
	ushort gtk_len;		/* Group (mcast) key length */
	uint8 global_key_counter[KEY_COUNTER_LEN];	/* global key counter */
	uint8 initial_gkc[KEY_COUNTER_LEN];		/* initial GKC value */
	uint8 gnonce[EAPOL_WPA_KEY_NONCE_LEN];	/* AP's group key nonce */
	uint8 gmk[GMK_LEN];			/* group master key */
	uint8 gtk_rsc[8];
}auth_info_t;

/* To avoid all of those name changes in wlc_auth.c */
typedef struct auth_info authenticator_t;


/* Platform dependent macros */
#define EAPOL_PKT_GET(auth, supp_info, len)	bcm_authenv_pktget(supp_info, len)

#define CLEANUP_WPA(osh, wpa)	bcm_authenv_cleanup_wpa(osh, wpa)

#define WLC_OSH_PTR		NULL
#define AUTH_WLC_OSH_PTR		NULL


/* deauth sta and cleanup associated data structures */
#define CLEANUP_STA(sta_info)	wpaif_auth_cleanup_sta(sta_info)

#define DEAUTHENTICATE_STA(sta_info, reason) \
	wpaif_auth_deauth_sta(sta_info, reason)

#define AUTH_PLUMB_PTK(sta_info, pkey, keylen, cipher) \
	wpaif_auth_plumb_ptk(sta_info, pkey, keylen, cipher)
	

#define AUTH_PLUMB_GTK(sta_info, pkey, keylen, keyindex, cipher, rsc, primary_key) \
		wpaif_auth_plumb_gtk(sta_info, pkey, keylen, keyindex, cipher, rsc, primary_key)


#define AUTHORIZE_STA(sta_info)  wpaif_auth_authorize_sta(sta_info)

#define GET_KEY_SEQ(sta_info, p, len) \
		wpaif_auth_get_key_seq(sta_info, p, len)


#define WLC_GETRAND(nonce, len)  wlc_getrand(NULL, nonce, len)

#define AUTH_SEND_PKT(sta_info, p)  wpaif_auth_tx_frame(sta_info, p)

void *
bcm_authenv_pktget(struct sta_parms *suppctx, int len);

void
bcm_authenv_cleanup_wpa(osl_t *osh, wpapsk_t *wpa);

#endif /* _bcm_authenv_h_ */
