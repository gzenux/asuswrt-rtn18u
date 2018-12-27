/*
 * Broadcom 802.11 device interface header
 *
 * Copyright (C) 2014, Broadcom Corporation
 * All Rights Reserved.
 * 
 * This is UNPUBLISHED PROPRIETARY SOURCE CODE of Broadcom Corporation;
 * the contents of this file may not be disclosed to third parties, copied
 * or duplicated in any form, in whole or in part, without the prior
 * written permission of Broadcom Corporation.
 *
 * $Id: hal.h,v 1.4 2010-08-09 19:20:31 $
 */

#ifndef _hal_h_
#define _hal_h_

struct ether_addr;

extern int
hal_get_event_mask(char *ifname, int bsscfg_index, unsigned char *buf,
	int length);
extern int
hal_set_event_mask(char *ifname, int bsscfg_index, unsigned char *buf,
	int length);

extern int hal_get_key_seq(char *ifname, void *buf, int buflen);

extern int hal_authorize(char *ifname, int bsscfg_index, struct ether_addr *ea);

extern int hal_deauthorize(char *ifname, int bsscfg_index, struct ether_addr *ea);

extern int hal_deauthenticate(char *ifname, int bsscfg_index,
	struct ether_addr *ea, int reason);

extern int hal_get_group_rsc(char *ifname, uint8 *buf, int index);

extern int hal_plumb_ptk(char *ifname, int bsscfg_index, struct ether_addr *ea,
	uint8 *tk, int tk_len, int cipher);

extern void hal_plumb_gtk(char *ifname, int bsscfg_index, uint8 *gtk,
	uint32 gtk_len, uint32 key_index, uint32 cipher,
	uint16 rsc_lo, uint32 rsc_hi, bool primary_key);

extern int hal_wl_tkip_countermeasures(char *ifname, int enable);

extern int hal_set_ssid(char *ifname, char *ssid);

extern int hal_disassoc(char *ifname);

extern int hal_get_wpacap(char *ifname, uint8 *cap);
/* get STA info */
extern int hal_get_stainfo(char *ifname, char *macaddr, int len, char *ret_buf, int ret_buf_len);

extern int hal_send_frame(char *ifname, int bsscfg_index, void *pkt, int len);

extern int hal_get_bssid(char *ifname, int bsscfg_index, char *ret_buf,
	int ret_buf_len);

extern int hal_get_assoc_info(char *ifnmae, int bsscfg_index,
	unsigned char *buf, int length);

extern int hal_get_assoc_req_ies(char *ifname, int bsscfg_index,
	unsigned char *buf, int length);

extern int hal_get_cur_etheraddr(char *ifname, int bsscfg_index,
	uint8 *ret_buf, int ret_buf_len);

extern int
hal_get_wpaie(char *ifname, int bsscfg_index, uint8 *ret_buf, int ret_buf_len,
		struct ether_addr *ea);

extern int
hal_get_btampkey(char *ifname, struct ether_addr *ea, char *ret_buf,
		int ret_buf_len);

extern int
hal_add_wpsie(char *ifname, int bsscfg_index, void *ie, int ie_len,
			  unsigned type);

extern int
hal_del_wpsie(char *ifname, int bsscfg_index, unsigned type);


#endif /* _hal_h_ */
