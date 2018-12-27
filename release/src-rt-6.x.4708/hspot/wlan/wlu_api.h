/*
 * WLAN iovar functions.
 *
 * Copyright (C) 2015, Broadcom Corporation
 * All Rights Reserved.
 * 
 * This is UNPUBLISHED PROPRIETARY SOURCE CODE of Broadcom Corporation;
 * the contents of this file may not be disclosed to third parties, copied
 * or duplicated in any form, in whole or in part, without the prior
 * written permission of Broadcom Corporation.
 *
 * $Id:$
 */

#ifndef _WLU_API_H_
#define _WLU_API_H_

#include "typedefs.h"
#include "wlioctl.h"

#define DEFAULT_BSSCFG_INDEX	(-1)

#define MAX_WLIF_NUM	8

void *wl(void);
void *wlif(int index);
void *wl_getifbyname(char *ifname);
void wlFree(void);

int wl_open(void **wl);
void wl_close(void);
char *wl_ifname(void *wl);

int wlu_get(void *wl, int cmd, void *buf, int len);
int wlu_set(void *wl, int cmd, void *buf, int len);

int wlu_iovar_get(void *wl, const char *iovar, void *outbuf, int len);
int wlu_iovar_set(void *wl, const char *iovar, void *param, int paramlen);

int wlu_iovar_getint(void *wl, const char *iovar, int *pval);
int wlu_iovar_setint(void *wl, const char *iovar, int val);

int wlu_iovar_setbuf(void* wl, const char *iovar,
	void *param, int paramlen, void *bufptr, int buflen);

int wlu_var_getbuf(void *wl, const char *iovar, void *param, int param_len, void **bufptr);
int wlu_var_setbuf(void *wl, const char *iovar, void *param, int param_len);

int wlu_bssiovar_setbuf(void* wl, const char *iovar, int bssidx,
	void *param, int paramlen, void *bufptr, int buflen);

int wlu_bssiovar_get(void *wl, const char *iovar, int bssidx, void *outbuf, int len);

int wl_cur_etheraddr(void *wl, int bsscfg_idx, struct ether_addr *ea);

int wl_format_ssid(char* ssid_buf, uint8* ssid, int ssid_len);
void dump_bss_info(wl_bss_info_t *bi);
char *wl_ether_etoa(const struct ether_addr *n);

int wl_escan(void *wl, uint16 sync_id, int isActive,
	int numProbes, int activeDwellTime, int passiveDwellTime,
	int num_channels, uint16 *channels);
int wl_escan_abort(void *wl, uint16 sync_id);

int wl_scan_abort(void *wl);

int wl_actframe(void *wl, int bsscfg_idx, uint32 packet_id,
	uint32 channel, int32 dwell_time,
	struct ether_addr *BSSID, struct ether_addr *da,
	uint16 len, uint8 *data);

int wl_wifiaction(void *wl, uint32 packet_id,
	struct ether_addr *da, uint16 len, uint8 *data);

int wl_enable_event_msg(void *wl, int event);
int wl_disable_event_msg(void *wl, int event);

int wl_add_vndr_ie(void *wl, int bsscfg_idx, uint32 pktflag, int len, uchar *data);
int wl_del_vndr_ie(void *wl, int bsscfg_idx, uint32 pktflag, int len, uchar *data);

int wl_ie(void *wl, uchar id, uchar len, uchar *data);

int wl_get_channels(void *wl, int max, int *len, uint16 *channels);
int wl_is_dfs(void *wl, uint16 channel);

int wl_disassoc(void *wl);
int wl_pmf_disassoc(void *wl);

int wl_wnm_bsstrans_query(void *wl);
int wl_wnm_bsstrans_req(void *wl, uint8 reqmode, uint16 tbtt, uint16 dur, uint8 unicast);

int wl_tdls_enable(void *wl, int enable);
int wl_tdls_endpoint(void *wl, char *cmd, struct ether_addr *ea);

int wl_status(void *wl, int *isAssociated, int biBufferSize, wl_bss_info_t *biBuffer);

int wl_grat_arp(void *wl, int enable);
int wl_bssload(void *wl, int enable);
int wl_dls(void *wl, int enable);
int wl_wnm(void *wl, int mask);
int wl_wnm_get(void *wl, int *mask);
int wl_wnm_parp_discard(void *wl, int enable);
int wl_interworking(void *wl, int enable);
int wl_probresp_sw(void *wl, int enable);
int wl_block_ping(void *wl, int enable);
int wl_block_sta(void *wl, int enable);
int wl_ap_isolate(void *wl, int enable);
int wl_proxy_arp(void *wl, int enable);
int wl_block_tdls(void *wl, int enable);
int wl_dls_reject(void *wl, int enable);
int wl_dhcp_unicast(void *wl, int enable);
int wl_block_multicast(void *wl, int enable);
int wl_gtk_per_sta(void *wl, int enable);
int wl_wnm_url(void *wl, uchar datalen, uchar *url_data);
int wl_pmf(void *wl, int mode);
int wl_mac(void *wl, int count, struct ether_addr *bssid);
int wl_macmode(void *wl, int mode);

int wl_p2p_disc(void *wl, int enable);
int wl_p2p_state(void *wl, uint8 state, chanspec_t chspec, uint16 dwell);
int wl_p2p_scan(void *wl, uint16 sync_id, int isActive,
	int numProbes, int activeDwellTime, int passiveDwellTime,
	int num_channels, uint16 *channels);
int wl_p2p_if(void *wl, struct ether_addr *ea, int *bsscfgIndex);
int wl_p2p_dev(void *wl, int *bsscfgIndex);

#endif /* _WLU_API_H_ */
