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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include "wlioctl.h"
#include "bcmutils.h"
#include "bcmendian.h"
#include "wlu.h"
#include "wlu_api.h"

#define WL_SCAN_PARAMS_SSID_MAX 10

/* The below macros handle endian mis-matches between wl utility and wl driver. */
static bool g_swap = FALSE;
#define htod32(i) (g_swap?bcmswap32(i):(uint32)(i))
#define htod16(i) (g_swap?bcmswap16(i):(uint16)(i))
#define dtoh32(i) (g_swap?bcmswap32(i):(uint32)(i))
#define dtoh16(i) (g_swap?bcmswap16(i):(uint16)(i))
#define htodchanspec(i) (g_swap?htod16(i):i)
#define dtohchanspec(i) (g_swap?dtoh16(i):i)
#define htodenum(i) (g_swap?((sizeof(i) == 4) ? htod32(i) : ((sizeof(i) == 2) ? htod16(i) : i)):i)
#define dtohenum(i) (g_swap?((sizeof(i) == 4) ? dtoh32(i) : ((sizeof(i) == 2) ? htod16(i) : i)):i)

/* dword align allocation */
static union {
	char bufdata[WLC_IOCTL_MAXLEN];
	uint32 alignme;
} bufstruct_wlu;
static char *buf = (char*) &bufstruct_wlu.bufdata;

int wl_cur_etheraddr(void *wl, int bsscfg_idx, struct ether_addr *ea)
{
	if (bsscfg_idx == DEFAULT_BSSCFG_INDEX)
	return wlu_iovar_get(wl, "cur_etheraddr", ea, ETHER_ADDR_LEN);
	else
		return wlu_bssiovar_get(wl, "cur_etheraddr", bsscfg_idx, ea, ETHER_ADDR_LEN);
}

static int escan(void *wl, uint16 action, uint16 sync_id, int isActive,
	int numProbes, int activeDwellTime, int passiveDwellTime,
	int num_channels, uint16 *channels)
{
	int params_size = (WL_SCAN_PARAMS_FIXED_SIZE + OFFSETOF(wl_escan_params_t, params)) +
	    (WL_NUMCHANNELS * sizeof(uint16));
	wl_escan_params_t *params;
	int nssid = 0;
	int err;

	params_size += WL_SCAN_PARAMS_SSID_MAX * sizeof(wlc_ssid_t);
	params = (wl_escan_params_t*)malloc(params_size);
	if (params == NULL) {
		return -1;
	}
	memset(params, 0, params_size);

	memcpy(&params->params.bssid, &ether_bcast, ETHER_ADDR_LEN);
	params->params.bss_type = DOT11_BSSTYPE_ANY;
	params->params.scan_type = isActive ? 0 : WL_SCANFLAGS_PASSIVE;
	params->params.nprobes = htod32(numProbes);
	params->params.active_time = htod32(activeDwellTime);
	params->params.passive_time = htod32(passiveDwellTime);
	params->params.home_time = htod32(-1);
	params->params.channel_num = 0;
	params_size = sizeof(*params);

	params->version = htod32(ESCAN_REQ_VERSION);
	params->action = htod16(action);
	params->sync_id = htod16(sync_id);

	memcpy(params->params.channel_list, channels, num_channels * sizeof(uint16));

	params->params.channel_num = htod32((nssid << WL_SCAN_PARAMS_NSSID_SHIFT) |
		(num_channels & WL_SCAN_PARAMS_COUNT_MASK));

	params_size = (WL_SCAN_PARAMS_FIXED_SIZE + OFFSETOF(wl_escan_params_t, params)) +
	    (num_channels * sizeof(uint16)) + (nssid * sizeof(wlc_ssid_t));

	err = wlu_iovar_setbuf(wl, "escan", params, params_size, buf, WLC_IOCTL_MAXLEN);

	free(params);
	return err;
}

int wl_escan(void *wl, uint16 sync_id, int isActive,
	int numProbes, int activeDwellTime, int passiveDwellTime,
	int num_channels, uint16 *channels)
{
	return escan(wl, WL_SCAN_ACTION_START, sync_id, isActive, numProbes,
		activeDwellTime, passiveDwellTime, num_channels, channels);
}

int wl_escan_abort(void *wl, uint16 sync_id)
{
	return escan(wl, WL_SCAN_ACTION_ABORT, sync_id, FALSE, 0, 0, 0, 0, 0);
}

int wl_scan_abort(void *wl)
{
	return wlu_var_setbuf(wl, "scanabort", NULL, 0);
}

int wl_actframe(void *wl, int bsscfg_idx, uint32 packet_id,
	uint32 channel, int32 dwell_time,
	struct ether_addr *BSSID, struct ether_addr *da,
	uint16 len, uint8 *data)
{
	wl_action_frame_t * action_frame;
	wl_af_params_t * af_params;
	struct ether_addr *bssid;
	int err = 0;

	if (len > ACTION_FRAME_SIZE)
		return -1;

	if ((af_params = (wl_af_params_t *) malloc(WL_WIFI_AF_PARAMS_SIZE)) == NULL) {
		return -1;
	}
	action_frame = &af_params->action_frame;

	/* Add the packet Id */
	action_frame->packetId = packet_id;

	memcpy(&action_frame->da, (char*)da, ETHER_ADDR_LEN);

	/* set default BSSID */
	bssid = da;
	if (BSSID != 0)
		bssid = BSSID;
	memcpy(&af_params->BSSID, (char*)bssid, ETHER_ADDR_LEN);

	action_frame->len = htod16(len);
	af_params->channel = htod32(channel);
	af_params->dwell_time = htod32(dwell_time);
	memcpy(action_frame->data, data, len);

	if (bsscfg_idx == DEFAULT_BSSCFG_INDEX)
	err = wlu_var_setbuf(wl, "actframe", af_params, WL_WIFI_AF_PARAMS_SIZE);
	else
		err = wlu_bssiovar_setbuf(wl, "actframe", bsscfg_idx,
			af_params, WL_WIFI_AF_PARAMS_SIZE, buf, WLC_IOCTL_MAXLEN);

	free(af_params);
	return (err);
}

int wl_wifiaction(void *wl, uint32 packet_id,
	struct ether_addr *da, uint16 len, uint8 *data)
{
	wl_action_frame_t * action_frame;
	int err = 0;

	if (len > ACTION_FRAME_SIZE)
		return -1;

	if ((action_frame = (wl_action_frame_t *) malloc(WL_WIFI_ACTION_FRAME_SIZE)) == NULL) {
		return -1;
	}

	/* Add the packet Id */
	action_frame->packetId = packet_id;

	memcpy(&action_frame->da, (char*)da, ETHER_ADDR_LEN);

	action_frame->len = htod16(len);
	memcpy(action_frame->data, data, len);

	err = wlu_var_setbuf(wl, "wifiaction", action_frame, WL_WIFI_ACTION_FRAME_SIZE);

	free(action_frame);

	return (err);
}

int wl_enable_event_msg(void *wl, int event)
{
	uint8 event_inds_mask[WL_EVENTING_MASK_LEN];	/* 128-bit mask */
	void *ptr;

	if ((event / 8) > WL_EVENTING_MASK_LEN)
		return -1;

	/* get current setting */
	memset(buf, '\0', WLC_IOCTL_MAXLEN);
	if (wlu_var_getbuf(wl, "event_msgs", NULL, 0, &ptr))
		return -1;

	/* OR new event */
	memcpy(event_inds_mask, ptr, WL_EVENTING_MASK_LEN);
	event_inds_mask[event / 8] |= 1 << (event % 8);

	if (wlu_iovar_set(wl, "event_msgs", &event_inds_mask, WL_EVENTING_MASK_LEN))
		return -1;

	return 0;
}

int wl_disable_event_msg(void *wl, int event)
{
	uint8 event_inds_mask[WL_EVENTING_MASK_LEN];	/* 128-bit mask */
	void *ptr;

	if ((event / 8) > WL_EVENTING_MASK_LEN)
		return -1;

	/* get current setting */
	memset(buf, '\0', WLC_IOCTL_MAXLEN);
	if (wlu_var_getbuf(wl, "event_msgs", NULL, 0, &ptr))
		return -1;

	/* AND mask event */
	memcpy(event_inds_mask, ptr, WL_EVENTING_MASK_LEN);
	event_inds_mask[event / 8] &= ~(1 << (event % 8));

	if (wlu_iovar_set(wl, "event_msgs", &event_inds_mask, WL_EVENTING_MASK_LEN))
		return -1;

	return 0;
}

static int
wl_vndr_ie(void *wl, int bsscfg_idx, const char *command, uint32 pktflag, int len, uchar *data)
{
	vndr_ie_setbuf_t *ie_setbuf;
	int buflen, iecount;
	int err = 0;

	/* OUI is included in first 3 bytes of len and data */

	if ((pktflag &
	    ~(VNDR_IE_BEACON_FLAG |
	      VNDR_IE_PRBRSP_FLAG |
	      VNDR_IE_ASSOCRSP_FLAG |
	      VNDR_IE_AUTHRSP_FLAG |
	      VNDR_IE_PRBREQ_FLAG |
	      VNDR_IE_ASSOCREQ_FLAG))) {
		fprintf(stderr, "Invalid packet flag 0x%x (%d)\n", pktflag, pktflag);
		return -1;
	}

	if (len < VNDR_IE_MIN_LEN || VNDR_IE_MAX_LEN < len) {
		fprintf(stderr, "Invalid length %d\n", len);
		return -1;
	}

	/* struct includes OUI + 1 byte */
	buflen = sizeof(vndr_ie_setbuf_t) - VNDR_IE_MIN_LEN - 1 + len;

	ie_setbuf = (vndr_ie_setbuf_t *) malloc(buflen);

	if (ie_setbuf == NULL) {
		fprintf(stderr, "memory alloc failure\n");
		return -1;
	}

	/* Copy the vndr_ie SET command ("add"/"del") to the buffer */
	strncpy(ie_setbuf->cmd, command, VNDR_IE_CMD_LEN - 1);
	ie_setbuf->cmd[VNDR_IE_CMD_LEN - 1] = '\0';


	/* Buffer contains only 1 IE */
	iecount = htod32(1);
	memcpy((void *)&ie_setbuf->vndr_ie_buffer.iecount, &iecount, sizeof(int));

	/*
	 * The packet flag bit field indicates the packets that will
	 * contain this IE
	 */
	pktflag = htod32(pktflag);
	memcpy((void *)&ie_setbuf->vndr_ie_buffer.vndr_ie_list[0].pktflag,
	       &pktflag, sizeof(uint32));

	/* Now, add the IE to the buffer */
	ie_setbuf->vndr_ie_buffer.vndr_ie_list[0].vndr_ie_data.len = (uchar)len;

	/* copy OUI */
	memcpy(&ie_setbuf->vndr_ie_buffer.vndr_ie_list[0].vndr_ie_data.oui[0],
		data, VNDR_IE_MIN_LEN);

	/* copy IE data */
	if (len - VNDR_IE_MIN_LEN > 0) {
		memcpy(&ie_setbuf->vndr_ie_buffer.vndr_ie_list[0].vndr_ie_data.data[0],
			&data[VNDR_IE_MIN_LEN], len - VNDR_IE_MIN_LEN);
	}

	if (bsscfg_idx == DEFAULT_BSSCFG_INDEX)
	err = wlu_var_setbuf(wl, "vndr_ie", ie_setbuf, buflen);
	else
		err = wlu_bssiovar_setbuf(wl, "vndr_ie", bsscfg_idx,
			ie_setbuf, buflen, buf, WLC_IOCTL_MAXLEN);

	free(ie_setbuf);

	return (err);
}

int
wl_add_vndr_ie(void *wl, int bsscfg_idx, uint32 pktflag, int len, uchar *data)
{
	return (wl_vndr_ie(wl, bsscfg_idx, "add", pktflag, len, data));
}

int
wl_del_vndr_ie(void *wl, int bsscfg_idx, uint32 pktflag, int len, uchar *data)
{
	return (wl_vndr_ie(wl, bsscfg_idx, "del", pktflag, len, data));
}

int wl_ie(void *wl, uchar id, uchar len, uchar *data)
{
	int err;
	uchar *buf;
	uint32 pktflag;
	int iecount;
	ie_setbuf_t *ie_setbuf;
	uchar count;

	/* use VNDR_IE_CUSTOM_FLAG flags for none vendor IE */
	pktflag = htod32(VNDR_IE_CUSTOM_FLAG);

	count = sizeof(ie_setbuf_t) + len - 1;
	buf = malloc(count);
	if (buf == NULL) {
		fprintf(stderr, "memory alloc failure\n");
		return -1;
	}

	ie_setbuf = (ie_setbuf_t *) buf;
	/* Copy the ie SET command ("add") to the buffer */
	strncpy(ie_setbuf->cmd, "add", VNDR_IE_CMD_LEN - 1);
	ie_setbuf->cmd[VNDR_IE_CMD_LEN - 1] = '\0';

	/* Buffer contains only 1 IE */
	iecount = htod32(1);
	memcpy((void *)&ie_setbuf->ie_buffer.iecount, &iecount, sizeof(int));

	memcpy((void *)&ie_setbuf->ie_buffer.ie_list[0].pktflag, &pktflag, sizeof(uint32));

	/* Now, add the IE to the buffer */
	ie_setbuf->ie_buffer.ie_list[0].ie_data.id = id;
	ie_setbuf->ie_buffer.ie_list[0].ie_data.len = len;

	memcpy((uchar *)&ie_setbuf->ie_buffer.ie_list[0].ie_data.data[0], data, len);

	err = wlu_var_setbuf(wl, "ie", buf, count);

	free(buf);
	return (err);
}

int
wl_get_channels(void *wl, int max, int *len, uint16 *channels)
{
	uint32 chan_buf[WL_NUMCHANNELS + 1];
	wl_uint32_list_t *list;
	int ret;
	uint i;
	int count;

	list = (wl_uint32_list_t *)(void *)chan_buf;
	list->count = htod32(WL_NUMCHANNELS);
	ret = wlu_get(wl, WLC_GET_VALID_CHANNELS, chan_buf, sizeof(chan_buf));
	if (ret < 0)
		return ret;

	count = 0;
	for (i = 0; i < dtoh32(list->count); i++) {
		if (count >= max)
			break;
		channels[count++] = dtoh32(list->element[i]);
	}

	*len = count;
	return ret;
}

int wl_is_dfs(void *wl, uint16 channel)
{
	(void)wl;

	if (channel >= 52 && channel <= 64)			/* class 2 */
		return TRUE;
	else if (channel >= 100 && channel <= 140)	/* class 4 */
		return TRUE;
	else
		return FALSE;
}

int wl_disassoc(void *wl)
{
	return wlu_set(wl, WLC_DISASSOC, NULL, 0);
}

int wl_pmf_disassoc(void *wl)
{
	const char *cmdname = "mfp_disassoc";
	int	flag;
	char varbuf[256];

	memset(varbuf, 0, 256);

	/* add the action */
	flag = 1;		/* flag1 */
	*(int *)varbuf = htod32(flag);
	flag = 0;		/* flag2 */
	*(int *)(varbuf + sizeof(flag)) = htod32(flag);

	if (wlu_var_setbuf(wl, cmdname, varbuf, 256))
		return -1;

	return 0;
}

int wl_wnm_bsstrans_query(void *wl)
{
	char *cmd = "wnm_bsstrans_query";
	int buflen = strlen(cmd) + 1;

	strcpy(buf, cmd);
	return wlu_set(wl, WLC_SET_VAR, buf, buflen);
}

int wl_wnm_bsstrans_req(void *wl, uint8 reqmode, uint16 tbtt, uint16 dur, uint8 unicast)
{
	char *cmd = "wnm_bsstrans_req";

/* some branches do not support this iovar */
#ifndef WNM_BSSTRANS_SUPPORT
	(void)wl;
	(void)reqmode;
	(void)tbtt;
	(void)dur;
	(void)unicast;
	printf("iovar not supported: %s\n", cmd);
	return -1;
#else
	wl_bsstrans_req_t bsstrans_req;

	memset(&bsstrans_req, 0, sizeof(bsstrans_req));

	bsstrans_req.tbtt = tbtt;
	bsstrans_req.dur = dur;
	bsstrans_req.reqmode = reqmode;
	bsstrans_req.unicast = unicast;

	return wlu_var_setbuf(wl, cmd, &bsstrans_req, sizeof(bsstrans_req));
#endif	/* WNM_BSSTRANS_SUPPORT */
}

int wl_tdls_enable(void *wl, int enable)
{
	return wlu_iovar_setint(wl, "tdls_enable", enable);
}

int wl_tdls_endpoint(void *wl, char *cmd, struct ether_addr *ea)
{
	const char *cmdname_tdls = "tdls_endpoint";
	tdls_iovar_t info;

	memset(&info, 0, sizeof(tdls_iovar_t));

	if (!strcmp("create", cmd))
		info.mode = TDLS_MANUAL_EP_CREATE;
	else if (!strcmp("modify", cmd))
		info.mode = TDLS_MANUAL_EP_MODIFY;
	else if (!strcmp("delete", cmd))
		info.mode = TDLS_MANUAL_EP_DELETE;
	else if (!strcmp("PM", cmd))
		info.mode = TDLS_MANUAL_EP_PM;
	else if (!strcmp("wake", cmd))
		info.mode = TDLS_MANUAL_EP_WAKE;
	else if (!strcmp("disc", cmd))
		info.mode = TDLS_MANUAL_EP_DISCOVERY;
	else if (!strcmp("cw", cmd)) {
		info.mode = TDLS_MANUAL_EP_CHSW;
	}
	else {
		printf("error: invalid mode string\n");
		return USAGE_ERROR;
	}

	memcpy(&info.ea, ea, sizeof(info.ea));

	return wlu_var_setbuf(wl, cmdname_tdls, &info, sizeof(info));
}

int wl_status(void *wl, int *isAssociated, int biBufferSize, wl_bss_info_t *biBuffer)
{
	int ret;
	struct ether_addr bssid;
	wl_bss_info_t *bi;

	*isAssociated = FALSE;

	if ((ret = wlu_get(wl, WLC_GET_BSSID, &bssid, ETHER_ADDR_LEN)) == 0) {
		/* The adapter is associated. */
		*(uint32*)buf = htod32(WLC_IOCTL_MAXLEN);
		if ((ret = wlu_get(wl, WLC_GET_BSS_INFO, buf, WLC_IOCTL_MAXLEN)) < 0)
			return ret;

		bi = (wl_bss_info_t*)(buf + 4);
		if (dtoh32(bi->version) == WL_BSS_INFO_VERSION ||
		    dtoh32(bi->version) == LEGACY2_WL_BSS_INFO_VERSION ||
		    dtoh32(bi->version) == LEGACY_WL_BSS_INFO_VERSION) {

		    *isAssociated = TRUE;
		    if (bi->length <= (uint32)biBufferSize) {
				memcpy(biBuffer, bi, bi->length);
			}
		    else {
				fprintf(stderr, "buffer too small %d > %d\n",
					bi->length, biBufferSize);
			}
		}
		else
			fprintf(stderr, "Sorry, your driver has bss_info_version %d "
				"but this program supports only version %d.\n",
				bi->version, WL_BSS_INFO_VERSION);
	}

	return 0;
}

int wl_grat_arp(void *wl, int enable)
{
	return wlu_iovar_setint(wl, "grat_arp", enable);
}

int wl_bssload(void *wl, int enable)
{
	return wlu_iovar_setint(wl, "bssload", enable);
}

int wl_dls(void *wl, int enable)
{
	return wlu_iovar_setint(wl, "dls", enable);
}

int wl_wnm(void *wl, int mask)
{
	return wlu_iovar_setint(wl, "wnm", mask);
}

int wl_wnm_get(void *wl, int *mask)
{
	return wlu_iovar_getint(wl, "wnm", mask);
}

int wl_wnm_parp_discard(void *wl, int enable)
{
	return wlu_iovar_setint(wl, "wnm_parp_discard", enable);
}

int wl_interworking(void *wl, int enable)
{
	return wlu_iovar_setint(wl, "interworking", enable);
}

int wl_probresp_sw(void *wl, int enable)
{
	return wlu_iovar_setint(wl, "probresp_sw", enable);
}

int wl_block_ping(void *wl, int enable)
{
	return wlu_iovar_setint(wl, "block_ping", enable);
}

int wl_block_sta(void *wl, int enable)
{
	return wlu_iovar_setint(wl, "block_sta", enable);
}

int wl_ap_isolate(void *wl, int enable)
{
	return wlu_iovar_setint(wl, "ap_isolate", enable);
}

int wl_proxy_arp(void *wl, int enable)
{
	return wlu_iovar_setint(wl, "proxy_arp", enable);
}

int wl_block_tdls(void *wl, int enable)
{
	return wlu_iovar_setint(wl, "block_tdls", enable);
}

int wl_dls_reject(void *wl, int enable)
{
	return wlu_iovar_setint(wl, "dls_reject", enable);
}

int wl_dhcp_unicast(void *wl, int enable)
{
	return wlu_iovar_setint(wl, "dhcp_unicast", enable);
}

int wl_block_multicast(void *wl, int enable)
{
	return wlu_iovar_setint(wl, "block_multicast", enable);
}

int wl_gtk_per_sta(void *wl, int enable)
{
	return wlu_iovar_setint(wl, "gtk_per_sta", enable);
}

int wl_wnm_url(void *wl, uchar datalen, uchar *url_data)
{
	wnm_url_t *url;
	int err;
	uchar *data;
	uchar count;
	count = sizeof(wnm_url_t) + datalen - 1;
	data = malloc(count);
	if (data == NULL) {
		fprintf(stderr, "memory alloc failure\n");
		return -1;
	}

	url = (wnm_url_t *) data;
	url->len = datalen;
	if (datalen > 0) {
		memcpy(url->data, url_data, datalen);
	}

	err = wlu_var_setbuf(wl, "wnm_url", data, count);
	free(data);

	return (err);
}

int wl_pmf(void *wl, int mode)
{
	return wlu_iovar_setint(wl, "mfp", mode);
}

int wl_mac(void *wl, int count, struct ether_addr *bssid)
{
	int len;
	struct maclist *maclist;

	len = OFFSETOF(struct maclist, ea) + count * sizeof(*bssid);
	maclist = malloc(len);
	if (maclist == 0) {
		fprintf(stderr, "memory alloc failure\n");
		return -1;
	}

	maclist->count = count;
	memcpy(maclist->ea, bssid, count * sizeof(*bssid));

	maclist->count = htod32(maclist->count);
	return wlu_set(wl, WLC_SET_MACLIST, maclist, len);
}

int wl_macmode(void *wl, int mode)
{
	return wlu_set(wl, WLC_SET_MACMODE, &mode, sizeof(mode));
}

int wl_p2p_disc(void *wl, int enable)
{
	return wlu_iovar_setint(wl, "p2p_disc", enable);
}

int wl_p2p_state(void *wl, uint8 state, chanspec_t chspec, uint16 dwell)
{
	wl_p2p_disc_st_t st;

	st.state = state;
	st.chspec = chspec;
	st.dwell = dwell;

	return wlu_var_setbuf(wl, "p2p_state", &st, sizeof(st));
}

int wl_p2p_scan(void *wl, uint16 sync_id, int isActive,
	int numProbes, int activeDwellTime, int passiveDwellTime,
	int num_channels, uint16 *channels)
{
	wl_p2p_scan_t *params = NULL;
	int params_size = 0;
	int malloc_size = 0;
	int nssid = 0;
	int err = 0;
	wl_escan_params_t *eparams;

	malloc_size = sizeof(wl_p2p_scan_t);
	malloc_size += OFFSETOF(wl_escan_params_t, params) +
		WL_SCAN_PARAMS_FIXED_SIZE + WL_NUMCHANNELS * sizeof(uint16);
	malloc_size += WL_SCAN_PARAMS_SSID_MAX * sizeof(wlc_ssid_t);
	params = (wl_p2p_scan_t *)malloc(malloc_size);
	if (params == NULL) {
		fprintf(stderr, "Error allocating %d bytes for scan params\n", malloc_size);
		return -1;
	}
	memset(params, 0, malloc_size);

	eparams = (wl_escan_params_t *)(params+1);

	params->type = 'E';

	eparams->version = htod32(ESCAN_REQ_VERSION);
	eparams->action = htod16(WL_SCAN_ACTION_START);
	eparams->sync_id = sync_id;

	memcpy(&eparams->params.bssid, &ether_bcast, ETHER_ADDR_LEN);
	eparams->params.bss_type = DOT11_BSSTYPE_ANY;
	eparams->params.scan_type = isActive ? 0 : WL_SCANFLAGS_PASSIVE;
	eparams->params.nprobes = htod32(numProbes);
	eparams->params.active_time = htod32(activeDwellTime);
	eparams->params.passive_time = htod32(passiveDwellTime);
	eparams->params.home_time = htod32(-1);
	eparams->params.channel_num = 0;

	memcpy(eparams->params.channel_list, channels, num_channels * sizeof(uint16));

	eparams->params.channel_num = htod32((nssid << WL_SCAN_PARAMS_NSSID_SHIFT) |
		(num_channels & WL_SCAN_PARAMS_COUNT_MASK));

	params_size = sizeof(wl_p2p_scan_t) + sizeof(wl_escan_params_t) + WL_SCAN_PARAMS_FIXED_SIZE+
	    (num_channels * sizeof(uint16)) + (nssid * sizeof(wlc_ssid_t));

	err = wlu_iovar_setbuf(wl, "p2p_scan", params, params_size, buf, WLC_IOCTL_MAXLEN);

	free(params);
	return err;
}

int wl_p2p_if(void *wl, struct ether_addr *ea, int *bsscfgIndex)
{
	wl_p2p_ifq_t *ptr;
	int err;

	err = wlu_var_getbuf(wl, "p2p_if", ea, sizeof(*ea), (void*)&ptr);
	if (err >= 0)
		*bsscfgIndex = dtoh32(ptr->bsscfgidx);

	return err;
}

int wl_p2p_dev(void *wl, int *bsscfgIndex)
{
	int *ptr;
	int err;

	err = wlu_var_getbuf(wl, "p2p_dev", NULL, 0, (void*)&ptr);
	if (err >= 0)
		*bsscfgIndex = dtoh32(*ptr);

	return err;
}
