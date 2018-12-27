/*
 * wpaif_auth.h -- interface to wpa authenticator library
 *
 * Copyright (C) 2014, Broadcom Corporation
 * All Rights Reserved.
 * 
 * This is UNPUBLISHED PROPRIETARY SOURCE CODE of Broadcom Corporation;
 * the contents of this file may not be disclosed to third parties, copied
 * or duplicated in any form, in whole or in part, without the prior
 * written permission of Broadcom Corporation.
 *
 * $Id: wpaif_auth.h,v 1.1.1.1 2010-02-04 00:44:37 $
 */

#ifndef _WPAIF_AUTH_H_
#define _WPAIF_AUTH_H_


struct auth_cbs {

   /* WLC_SCB_AUTHORIZE, WLC_SCB_DEAUTHENTICATE_FOR_REASON, wlc_mac_event */
   void (*result)(clientdata_t *, unsigned char success, struct ether_addr *ea, unsigned char reason);
	/* wlc_wpa_plumb_tk */
   void (*plumb_ptk)(clientdata_t *, uint8 *key, uint32 keylen, uint32 algo,
		   struct ether_addr *ea);
   
   /* wlc_wpa_plumb_gtk */
   void (*plumb_gtk)(clientdata_t *, uint8 *key, uint32 keylen, uint32 index,
		   uint32 algo, uint16 rsc_lo, uint32 rsc_hi, bool primary);

   /* wlc_sendpkt */
   void (*tx_frame)(clientdata_t *, void *p, int len);


   /* Get key sequence */
   void (*get_key_seq)(clientdata_t *, void *buf, int buflen);

};


/* general (de)initialization */
void wpaif_auth_init(struct auth_cbs*);
void wpaif_auth_cleanup(void);


/* context (de)initialization */
struct ctx* wpaif_auth_ctx_init(clientdata_t *, int WPA_auth, int btamp_en,
		int wsec, uint8 *pmk, int pmk_len, struct ether_addr *auth_ea);
void wpaif_auth_ctx_cleanup(struct ctx*);


/* dispatch EAPOL frame: entry point for incoming eapol frames
 * - receipt of EAP-REQUEST/IDENTITY for non-PSK auth_type is equivalent to
 *   ctx_set_pmk(ctx, NULL, 0)
 * - non EAPOL-KEY frames are ignored save EAP-REQUEST/IDENTITY
*/
void wpaif_auth_ctx_dispatch(struct ctx*, unsigned char *, int);

/* Handle inputs from WLC_E_ASSOC_IND */
/* Remember translate auth_type to AUTH_WPAPSK for wlc_set_auth */
void wpaif_auth_ctx_set_sta(struct ctx *, uint8 *sup_ies,
		uint sup_ies_len, uint8 *auth_ies, uint auth_ies_len,
		struct ether_addr *ea, unsigned char *key, int key_len);

void
wpaif_auth_plumb_ptk(sta_parms_t *sta_info, uint8 *pkey, int keylen, ushort cipher);

void
wpaif_auth_plumb_gtk(sta_parms_t *sta_info, uint8 *gtk, uint32 gtk_len,
	uint32 key_index, uint32 cipher, uint8 *rsc, bool primary_key);

void
wpaif_auth_cleanup_sta(struct sta_parms *sta_info);

void
wpaif_auth_deauth_sta(sta_parms_t *sta_info, int reason);

void
wpaif_auth_authorize_sta(sta_parms_t *sta_info);

void
wpaif_auth_get_key_seq(sta_parms_t *sta_info, void *buf, int buflen);

void
wpaif_auth_tx_frame(sta_parms_t *sta_info, void *p);

void
wpaif_auth_cleanup_ea(struct ctx* ctx, struct ether_addr *ea);

#endif /* _WPAIF_AUTH_H_ */
