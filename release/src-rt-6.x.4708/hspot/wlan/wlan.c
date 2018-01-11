/*
 * WLAN functions.
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

#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "proto/802.11.h"
#include "trace.h"
#include "dsp.h"
#include "wlu_api.h"
#include "wlan.h"

struct wlanStruct {
	/* ether addr */
	struct ether_addr etherAddr;

	/* escan parameters */
	uint16 syncId;
	int numNonDfsChannels;
	uint16 nonDfsChannels[WL_NUMCHANNELS];
};

static struct {
	void (*fn)(void *context, uint32 eventType,
		wl_event_msg_t *wlEvent, uint8 *data, uint32 length);
	void *context;
} gEventCallback;

typedef struct wlanReq wlanReqT;

/* request handler */
typedef void (*requestHandlerT)(wlanT *wlan,
	int reqLength, wlanReqT *req, void *rspData);

typedef struct {
	wlanT *wlan;
} wlanCreateRspT;

typedef struct {
	int event;
} wlanEventMsgReqT;

typedef struct {
	uint32 pktflag;
	int len;
	uchar data[VNDR_IE_MAX_LEN];
} wlanVendorIeReqT;

typedef struct {
	uint8 id;
	uint8 len;
	uchar data[VNDR_IE_MAX_LEN];
} wlanIeReqT;

typedef struct {
	int isActive;
	int numProbes;			/* num probes per channel */
	int activeDwellTime;	/* dwell time per channel for active scanning */
	int passiveDwellTime;	/* dwell time per channel for passive scanning */
} wlanStartEscanReqT;

typedef struct {
	uint32 packetId;
	uint32 channel;
	int32 dwellTime;
	struct ether_addr bssid;
	struct ether_addr da;
	uint16 len;
	uint8 data[ACTION_FRAME_SIZE];
} wlanActionFrameReqT;

typedef struct {
	int *isAssociated;
	int biBufferSize;
	wl_bss_info_t *biBuffer;
} wlanAssociationStatusRspT;

typedef struct {
	struct ether_addr ea;
} wlanTdlsReqT;

typedef struct {
	int enable;
} wlanDropGratuitousArpT;

typedef struct {
	int mask;
} wlanWnmT;

typedef struct {
	uint8 reqmode;
	uint16 disassocTimer;
	char url[256 + 1];	/* null terminated */
} wlanWnmBssTransReqEssDisassocImminentT;

typedef struct {
	int mode;
} wlanPmfT;

typedef struct {
	int mode;
	int count;
	struct ether_addr addr[1];	/* variable length */
} wlanMacT;

struct wlanReq {
	requestHandlerT handler;
	union {
		wlanEventMsgReqT eventMsg;		/* enable/disable */
		wlanVendorIeReqT vendorIe;		/* add/delete vendor IE */
		wlanIeReqT ie;					/* add/delete IE */
		wlanStartEscanReqT startEscan;
		wlanActionFrameReqT actionFrame;
		wlanTdlsReqT tdls;
		wlanDropGratuitousArpT dropGratuitousArp;
		wlanWnmT wnm;
		wlanWnmBssTransReqEssDisassocImminentT wnmBssTransReqEssDisassocImminent;
		wlanPmfT pmf;
		wlanMacT mac;
	};
};

/* dispatch handler */
static void wlanProcessWlanEvent(void *context, uint32 eventType,
	wl_event_msg_t *wlEvent, uint8 *data, uint32 length);

/* ----------------------------------------------------------- */

/* initialize wlan */
int wlanInitialize(void)
{
	return dspSubscribe(dsp(), 0, wlanProcessWlanEvent);
}

/* deinitialize wlan */
int wlanDeinitialize(void)
{
	return dspUnsubscribe(dsp(), wlanProcessWlanEvent);
}

/* ----------------------------------------------------------- */

static void wlanCreateHandler(wlanT *wlanNull,
	int reqLength, wlanReqT *req, wlanCreateRspT *rsp)
{
	wlanT *wlan;
	uint16 channels[WL_NUMCHANNELS];
	int numChannels = 0;
	int i;

	(void)wlanNull;
	if (reqLength != sizeof(wlanReqT) || req == 0 || rsp == 0) {
		TRACE(TRACE_ERROR, "invalid parameter\n");
		return;
	}

	TRACE(TRACE_VERBOSE, "wlanCreateHandler\n");

	rsp->wlan = 0;
	wlan = malloc(sizeof(*wlan));
	if (wlan == 0)
		return;
	memset(wlan, 0, sizeof(*wlan));

	/* get the ethernet address */
	if (wl_cur_etheraddr(wl(), DEFAULT_BSSCFG_INDEX, &wlan->etherAddr) != 0) {
		TRACE(TRACE_ERROR, "wl_cur_etheraddr failed\n");
	}

	/* get the supported channels */
	if (wl_get_channels(wl(), WL_NUMCHANNELS, &numChannels, channels) != 0) {
		TRACE(TRACE_ERROR, "wl_get_channels failed\n");
	}

	/* remove DFS channels */
	wlan->numNonDfsChannels = 0;
	for (i = 0; i < numChannels; i++) {
		if (!wl_is_dfs(wl(), channels[i]))
			wlan->nonDfsChannels[wlan->numNonDfsChannels++] = channels[i];
	}

	/* enable event */
	if (wl_enable_event_msg(wl(), WLC_E_ESCAN_RESULT) < 0) {
		TRACE(TRACE_ERROR, "failed to enable escan event\n");
	}
	if (wl_enable_event_msg(wl(), WLC_E_DISASSOC) < 0) {
		TRACE(TRACE_ERROR, "failed to enable disassoc event\n");
	}
	if (wl_enable_event_msg(wl(), WLC_E_LINK) < 0) {
		TRACE(TRACE_ERROR, "failed to enable link event\n");
	}
	if (wl_enable_event_msg(wl(), WLC_E_SET_SSID) < 0) {
		TRACE(TRACE_ERROR, "failed to enable set ssid event\n");
	}

	/* return created instance */
	rsp->wlan = wlan;
}

/* create wlan instance */
wlanT *wlanCreate(void)
{
	wlanReqT req;
	wlanCreateRspT rsp;

	TRACE(TRACE_VERBOSE, "wlanCreate\n");

	req.handler = (requestHandlerT)wlanCreateHandler;
	if (!dspRequestSynch(dsp(), 0, sizeof(req), (uint8 *)&req, (uint8 *)&rsp))
	{
		return 0;
	}

	return rsp.wlan;
}

/* ----------------------------------------------------------- */

static void wlanDestroyHandler(wlanT *wlan,
	int reqLength, wlanReqT *req, void *rspNull)
{
	(void)rspNull;
	if (wlan == 0 || reqLength != sizeof(wlanReqT) || req == 0) {
		TRACE(TRACE_ERROR, "invalid parameter\n");
		return;
	}

	TRACE(TRACE_VERBOSE, "wlanDestroyHandler\n");
	free(wlan);
}

/* destroy wlan instance */
int wlanDestroy(wlanT *wlan)
{
	wlanReqT req;

	TRACE(TRACE_VERBOSE, "wlanDestroy\n");

	req.handler = wlanDestroyHandler;
	return dspRequest(dsp(), wlan, sizeof(req), (uint8 *)&req);
}

/* ----------------------------------------------------------- */

/* get WLAN interface name */
char *wlanIfName(wlanT *wlan)
{
	(void)wlan;
	return wl_ifname(wl());
}

/* ----------------------------------------------------------- */

/* get WLAN ethernet address */
int wlanEtherAddr(wlanT *wlan, struct ether_addr *addr)
{
	memcpy(addr, &wlan->etherAddr, sizeof(*addr));
	return TRUE;
}

/* ----------------------------------------------------------- */

static void wlanEnableEventMsgHandler(wlanT *wlan,
	int reqLength, wlanReqT *req, void *rspNull)
{
	(void)rspNull;
	if (wlan == 0 || reqLength != sizeof(wlanReqT) || req == 0) {
		TRACE(TRACE_ERROR, "invalid parameter\n");
		return;
	}

	TRACE(TRACE_VERBOSE, "wlanEnableEventMsgHandler\n");

	if (wl_enable_event_msg(wl(), req->eventMsg.event) < 0) {
		TRACE(TRACE_ERROR, "failed to enable event msg %d\n",
			req->eventMsg.event);
	}
}

/* enable event msg */
int wlanEnableEventMsg(wlanT *wlan, int event)
{
	wlanReqT req;

	TRACE(TRACE_VERBOSE, "wlanEnableEventMsg\n");

	req.handler = wlanEnableEventMsgHandler;
	req.eventMsg.event = event;
	return dspRequest(dsp(), wlan, sizeof(req), (uint8 *)&req);
}

/* ----------------------------------------------------------- */

static void wlanDisableEventMsgHandler(wlanT *wlan,
	int reqLength, wlanReqT *req, void *rspNull)
{
	(void)rspNull;
	if (wlan == 0 || reqLength != sizeof(wlanReqT) || req == 0) {
		TRACE(TRACE_ERROR, "invalid parameter\n");
		return;
	}

	TRACE(TRACE_VERBOSE, "wlanDisableEventMsgHandler\n");

	if (wl_disable_event_msg(wl(), req->eventMsg.event) < 0) {
		TRACE(TRACE_ERROR, "failed to disable event msg %d\n",
			req->eventMsg.event);
	}
}

/* disable event msg */
int wlanDisableEventMsg(wlanT *wlan, int event)
{
	wlanReqT req;

	TRACE(TRACE_VERBOSE, "wlanDisableEventMsg\n");

	req.handler = wlanDisableEventMsgHandler;
	req.eventMsg.event = event;
	return dspRequest(dsp(), wlan, sizeof(req), (uint8 *)&req);
}

/* ----------------------------------------------------------- */

static void wlanAddVendorIeHandler(wlanT *wlan,
	int reqLength, wlanReqT *req, void *rspNull)
{
	(void)rspNull;
	if (wlan == 0 || reqLength != sizeof(wlanReqT) || req == 0) {
		TRACE(TRACE_ERROR, "invalid parameter\n");
		return;
	}

	TRACE(TRACE_VERBOSE, "wlanAddVendorIeHandler\n");

	if (wl_add_vndr_ie(wl(), DEFAULT_BSSCFG_INDEX,
		req->vendorIe.pktflag, req->vendorIe.len, req->vendorIe.data) < 0) {
		TRACE(TRACE_ERROR, "failed to add vendor IE\n");
	}
}

/* add vendor IEs */
int wlanAddVendorIe(wlanT *wlan, uint32 pktflag, int len, uchar *data)
{
	wlanReqT req;

	TRACE(TRACE_VERBOSE, "wlanAddVendorIe\n");

	req.handler = wlanAddVendorIeHandler;
	req.vendorIe.pktflag = pktflag;
	req.vendorIe.len = len;
	memcpy(req.vendorIe.data, data, req.vendorIe.len);
	return dspRequest(dsp(), wlan, sizeof(req), (uint8 *)&req);
}

/* ----------------------------------------------------------- */

static void wlanDeleteVendorIeHandler(wlanT *wlan,
	int reqLength, wlanReqT *req, void *rspNull)
{
	(void)rspNull;
	if (wlan == 0 || reqLength != sizeof(wlanReqT) || req == 0) {
		TRACE(TRACE_ERROR, "invalid parameter\n");
		return;
	}

	TRACE(TRACE_VERBOSE, "wlanDeleteVendorIeHandler\n");

	/* may return fail but just means IE has been deleted already */
	wl_del_vndr_ie(wl(), DEFAULT_BSSCFG_INDEX,
		req->vendorIe.pktflag, req->vendorIe.len, req->vendorIe.data);
}

/* delete vendor IEs */
int wlanDeleteVendorIe(wlanT *wlan, uint32 pktflag, int len, uchar *data)
{
	wlanReqT req;

	TRACE(TRACE_VERBOSE, "wlanDeleteVendorIe\n");

	req.handler = wlanDeleteVendorIeHandler;
	req.vendorIe.pktflag = pktflag;
	req.vendorIe.len = len;
	memcpy(req.vendorIe.data, data, req.vendorIe.len);
	return dspRequest(dsp(), wlan, sizeof(req), (uint8 *)&req);
}

/* ----------------------------------------------------------- */

static void wlanIeHandler(wlanT *wlan,
	int reqLength, wlanReqT *req, void *rspNull)
{
	(void)rspNull;
	if (wlan == 0 || reqLength != sizeof(wlanReqT) || req == 0) {
		TRACE(TRACE_ERROR, "invalid parameter\n");
		return;
	}

	TRACE(TRACE_VERBOSE, "wlanIeHandler\n");

	if (wl_ie(wl(), req->ie.id, req->ie.len, req->ie.data) < 0) {
		TRACE(TRACE_ERROR, "failed IE %d\n", req->ie.id);
	}
}

/* add/del IE */
int wlanIe(wlanT *wlan, uint8 id, uint8 len, uchar *data)
{
	wlanReqT req;

	TRACE(TRACE_VERBOSE, "wlanIe\n");

	req.handler = wlanIeHandler;
	req.ie.id = id;
	req.ie.len = len;
	memcpy(req.ie.data, data, req.ie.len);
	return dspRequest(dsp(), wlan, sizeof(req), (uint8 *)&req);
}

/* ----------------------------------------------------------- */

static void wlanStartEscanHandler(wlanT *wlan,
	int reqLength, wlanReqT *req, void *rspNull)
{
	int numChannels = 0;
	uint16 *channels = 0;

	(void)rspNull;
	if (wlan == 0 || reqLength != sizeof(wlanReqT) || req == 0) {
		TRACE(TRACE_ERROR, "invalid parameter\n");
		return;
	}

	TRACE(TRACE_VERBOSE, "wlanStartEscanHandler isActive=%d numProbes=%d "
		"activeDwellTime=%d passiveDwellTime=%d\n",
		req->startEscan.isActive, req->startEscan.numProbes,
		req->startEscan.activeDwellTime, req->startEscan.passiveDwellTime);


	/* use scan abort to abort all escan, actframe, etc. */
	if (wl_scan_abort(wl()) != 0) {
		TRACE(TRACE_ERROR, "wl_scan_abort failed\n");
	}
	if (wl_escan(wl(), ++wlan->syncId, req->startEscan.isActive,
		req->startEscan.numProbes, req->startEscan.activeDwellTime,
		req->startEscan.passiveDwellTime,
		numChannels, channels) != 0) {
		TRACE(TRACE_ERROR, "wl_escan failed\n");
	}
}

/* start escan */
int wlanStartEscan(wlanT *wlan, int isActive, int numProbes,
	int activeDwellTime, int passiveDwellTime)
{
	wlanReqT req;

	TRACE(TRACE_VERBOSE, "wlanStartEscan isActive=%d\n", isActive);

	req.handler = wlanStartEscanHandler;
	req.startEscan.isActive = isActive;
	req.startEscan.numProbes = numProbes;
	req.startEscan.activeDwellTime = activeDwellTime;
	req.startEscan.passiveDwellTime = passiveDwellTime;
	return dspRequest(dsp(), wlan, sizeof(req), (uint8 *)&req);
}

/* ----------------------------------------------------------- */

static void wlanStopScanHandler(wlanT *wlan,
	int reqLength, wlanReqT *req, void *rspNull)
{
	(void)rspNull;
	if (wlan == 0 || reqLength != sizeof(wlanReqT) || req == 0) {
		TRACE(TRACE_ERROR, "invalid parameter\n");
		return;
	}

	TRACE(TRACE_VERBOSE, "wlanStopScanHandler\n");
	/* use scan abort to abort all escan, actframe, etc. */
	if (wl_scan_abort(wl()) != 0) {
		TRACE(TRACE_ERROR, "wl_scan_abort failed\n");
	}
}

/* stop scan engine (scan, escan, action frame, etc.) */
int wlanStopScan(wlanT *wlan)
{
	wlanReqT req;

	TRACE(TRACE_VERBOSE, "wlanStopScan\n");

	req.handler = wlanStopScanHandler;
	return dspRequest(dsp(), wlan, sizeof(req), (uint8 *)&req);
}

/* ----------------------------------------------------------- */

static void wlanDisassociateHandler(wlanT *wlan,
	int reqLength, wlanReqT *req, void *rspNull)
{
	(void)rspNull;
	if (wlan == 0 || reqLength != sizeof(wlanReqT) || req == 0) {
		TRACE(TRACE_ERROR, "invalid parameter\n");
		return;
	}

	TRACE(TRACE_VERBOSE, "wlanDisassociateHandler\n");

	if (wl_disassoc(wl()) < 0) {
		TRACE(TRACE_ERROR, "wl_disassoc failed\n");
	}
}

/* disassociate */
int wlanDisassociate(wlanT *wlan)
{
	wlanReqT req;

	TRACE(TRACE_VERBOSE, "wlanDisassociate\n");

	req.handler = wlanDisassociateHandler;
	return dspRequest(dsp(), wlan, sizeof(req), (uint8 *)&req);
}

/* ----------------------------------------------------------- */

static void wlanPmfDisassociateHandler(wlanT *wlan,
	int reqLength, wlanReqT *req, void *rspNull)
{
	(void)rspNull;
	if (wlan == 0 || reqLength != sizeof(wlanReqT) || req == 0) {
		TRACE(TRACE_ERROR, "invalid parameter\n");
		return;
	}

	TRACE(TRACE_VERBOSE, "wlanPmfDisassociateHandler\n");

	if (wl_pmf_disassoc(wl()) < 0) {
		TRACE(TRACE_ERROR, "wl_pmf_disassoc failed\n");
	}
}

/* PMF disassociate */
int wlanPmfDisassociate(wlanT *wlan)
{
	wlanReqT req;

	TRACE(TRACE_VERBOSE, "wlanPmfDisassociate\n");

	req.handler = wlanPmfDisassociateHandler;
	return dspRequest(dsp(), wlan, sizeof(req), (uint8 *)&req);
}

/* ----------------------------------------------------------- */

static void wlanBssTransitionQueryHandler(wlanT *wlan,
	int reqLength, wlanReqT *req, void *rspNull)
{
	(void)rspNull;
	if (wlan == 0 || reqLength != sizeof(wlanReqT) || req == 0) {
		TRACE(TRACE_ERROR, "invalid parameter\n");
		return;
	}

	TRACE(TRACE_VERBOSE, "wlanBssTransitionQueryHandler\n");

	if (wl_wnm_bsstrans_query(wl()) < 0) {
		TRACE(TRACE_ERROR, "wl_wnm_bsstrans_query failed\n");
	}
}

/* send BSS transition query */
int wlanBssTransitionQuery(wlanT *wlan)
{
	wlanReqT req;

	TRACE(TRACE_VERBOSE, "wlanBssTransitionQuery\n");

	req.handler = wlanBssTransitionQueryHandler;
	return dspRequest(dsp(), wlan, sizeof(req), (uint8 *)&req);
}

/* ----------------------------------------------------------- */

static void wlanBssTransReqEssDisassocImminentHandler(wlanT *wlan,
	int reqLength, wlanReqT *req, void *rspNull)
{
	(void)rspNull;
	if (wlan == 0 || reqLength != sizeof(wlanReqT) || req == 0) {
		TRACE(TRACE_ERROR, "invalid parameter\n");
		return;
	}

	TRACE(TRACE_VERBOSE, "wlanBssTransReqEssDisassocImminentHandler\n");

	if (wl_wnm_url(wl(), strlen(req->wnmBssTransReqEssDisassocImminent.url),
		(uchar *)req->wnmBssTransReqEssDisassocImminent.url) < 0) {
		TRACE(TRACE_ERROR, "wl_wnm_url failed\n");
		return;
	}

	if (wl_wnm_bsstrans_req(wl(),
		DOT11_BSSTRANS_REQMODE_PREF_LIST_INCL |
		DOT11_BSSTRANS_REQMODE_DISASSOC_IMMINENT |
		DOT11_BSSTRANS_REQMODE_ESS_DISASSOC_IMNT,
		req->wnmBssTransReqEssDisassocImminent.disassocTimer,
		0, TRUE) < 0) {
		TRACE(TRACE_ERROR, "wl_wnm_bsstrans_req failed\n");
	}
}

/* send BSS transition request - ESS disassociation imminent */
int wlanBssTransReqEssDisassocImminent(wlanT *wlan,
	uint16 disassocTimer, char *url)
{
	wlanReqT req;

	TRACE(TRACE_VERBOSE, "wlanBssTransReqEssDisassocImminent\n");

	req.handler = wlanBssTransReqEssDisassocImminentHandler;
	req.wnmBssTransReqEssDisassocImminent.disassocTimer = disassocTimer;
	strncpy(req.wnmBssTransReqEssDisassocImminent.url, url,
		sizeof(req.wnmBssTransReqEssDisassocImminent.url) - 1);
	req.wnmBssTransReqEssDisassocImminent.url[
		sizeof(req.wnmBssTransReqEssDisassocImminent.url) - 1] = 0;

	return dspRequest(dsp(), wlan, sizeof(req), (uint8 *)&req);
}

/* ----------------------------------------------------------- */

static void wlanActionFrameHandler(wlanT *wlan,
	int reqLength, wlanReqT *req, void *rspNull)
{
	(void)rspNull;
	if (wlan == 0 || reqLength != sizeof(wlanReqT) || req == 0) {
		TRACE(TRACE_ERROR, "invalid parameter\n");
		return;
	}

	TRACE(TRACE_VERBOSE, "wlanActionFrameHandler\n");

	if (wl_actframe(wl(), DEFAULT_BSSCFG_INDEX,
		req->actionFrame.packetId, req->actionFrame.channel,
		req->actionFrame.dwellTime, &req->actionFrame.bssid, &req->actionFrame.da,
		req->actionFrame.len, req->actionFrame.data) < 0) {
		TRACE(TRACE_ERROR, "wl_actframe failed\n");
	}
}

/* send action frame */
int wlanActionFrame(wlanT *wlan, uint32 packetId, uint32 channel, int32 dwellTime,
	struct ether_addr *bssid, struct ether_addr *da, uint16 len, uint8 *data)
{
	wlanReqT req;

	TRACE(TRACE_VERBOSE, "wlanActionFrame\n");

	if (len > ACTION_FRAME_SIZE)
		return 0;

	req.handler = wlanActionFrameHandler;
	req.actionFrame.packetId = packetId;
	req.actionFrame.channel = channel;
	req.actionFrame.dwellTime = dwellTime;
	memcpy(&req.actionFrame.bssid, bssid, sizeof(req.actionFrame.bssid));
	memcpy(&req.actionFrame.da, da, sizeof(req.actionFrame.da));
	req.actionFrame.len = len;
	memcpy(req.actionFrame.data, data, req.actionFrame.len);

	return dspRequest(dsp(), wlan, sizeof(req), (uint8 *)&req);
}

/* ----------------------------------------------------------- */

static void wlanAssociationStatusHandler(wlanT *wlan,
	int reqLength, wlanReqT *req, wlanAssociationStatusRspT *rsp)
{
	if (wlan == 0 || reqLength != sizeof(wlanReqT) || req == 0 || rsp == 0) {
		TRACE(TRACE_ERROR, "invalid parameter\n");
		return;
	}

	TRACE(TRACE_VERBOSE, "wlanAssociationStatusHandler\n");

	/* get the ethernet address */
	if (wl_status(wl(), rsp->isAssociated, rsp->biBufferSize, rsp->biBuffer) != 0) {
		TRACE(TRACE_ERROR, "wl_status failed\n");
	}
}

/* wlan association status */
int wlanAssociationStatus(wlanT *wlan, int *isAssociated,
	int biBufferSize, wl_bss_info_t *biBuffer)
{
	wlanReqT req;
	wlanAssociationStatusRspT rsp;

	TRACE(TRACE_VERBOSE, "wlanAssociationStatus\n");

	req.handler = (requestHandlerT)wlanAssociationStatusHandler;
	rsp.isAssociated = isAssociated;
	rsp.biBufferSize = biBufferSize;
	rsp.biBuffer = biBuffer;

	return dspRequestSynch(dsp(), wlan, sizeof(req), (uint8 *)&req,
		(uint8 *)&rsp);
}

/* ----------------------------------------------------------- */

static void wlanTdlsDiscoveryRequestHandler(wlanT *wlan,
	int reqLength, wlanReqT *req, void *rspNull)
{
	(void)rspNull;
	if (wlan == 0 || reqLength != sizeof(wlanReqT) || req == 0) {
		TRACE(TRACE_ERROR, "invalid parameter\n");
		return;
	}

	TRACE(TRACE_VERBOSE, "wlanTdlsDiscoveryRequestHandler\n");

	/* enable TDLS */
	if (wl_tdls_enable(wl(), 1) < 0) {
		TRACE(TRACE_ERROR, "wl_tdls_enable failed\n");
	}

	/* discovery request */
	if (wl_tdls_endpoint(wl(), "disc", &req->tdls.ea) < 0) {
		TRACE(TRACE_ERROR, "wl_tdls_enable failed\n");
	}

	/* disable TDLS */
	if (wl_tdls_enable(wl(), 0) < 0) {
		TRACE(TRACE_ERROR, "wl_tdls_enable failed\n");
	}
}

/* send TDLS discovery request */
int wlanTdlsDiscoveryRequest(wlanT *wlan, struct ether_addr *ea)
{
	wlanReqT req;

	TRACE(TRACE_VERBOSE, "wlanTdlsDiscoveryRequest\n");

	req.handler = wlanTdlsDiscoveryRequestHandler;
	memcpy(&req.tdls.ea, ea, sizeof(req.tdls.ea));

	return dspRequest(dsp(), wlan, sizeof(req), (uint8 *)&req);
}

/* ----------------------------------------------------------- */

static void wlanTdlsSetupRequestHandler(wlanT *wlan,
	int reqLength, wlanReqT *req, void *rspNull)
{
	(void)rspNull;
	if (wlan == 0 || reqLength != sizeof(wlanReqT) || req == 0) {
		TRACE(TRACE_ERROR, "invalid parameter\n");
		return;
	}

	TRACE(TRACE_VERBOSE, "wlanTdlsSetupRequestHandler\n");

	/* enable TDLS */
	if (wl_tdls_enable(wl(), 1) < 0) {
		TRACE(TRACE_ERROR, "wl_tdls_enable failed\n");
	}

	/* setup request */
	if (wl_tdls_endpoint(wl(), "create", &req->tdls.ea) < 0) {
		TRACE(TRACE_ERROR, "wl_tdls_endpoint failed\n");
	}

	/* disable TDLS */
	if (wl_tdls_enable(wl(), 0) < 0) {
		TRACE(TRACE_ERROR, "wl_tdls_enable failed\n");
	}
}

/* send TDLS setup request */
int wlanTdlsSetupRequest(wlanT *wlan, struct ether_addr *ea)
{
	wlanReqT req;

	TRACE(TRACE_VERBOSE, "wlanTdlsSetupRequest\n");

	req.handler = wlanTdlsSetupRequestHandler;
	memcpy(&req.tdls.ea, ea, sizeof(req.tdls.ea));

	return dspRequest(dsp(), wlan, sizeof(req), (uint8 *)&req);
}

/* ----------------------------------------------------------- */

static void wlanDropGratuitousArpHandler(wlanT *wlan,
	int reqLength, wlanReqT *req, void *rspNull)
{
	(void)rspNull;
	if (wlan == 0 || reqLength != sizeof(wlanReqT) || req == 0) {
		TRACE(TRACE_ERROR, "invalid parameter\n");
		return;
	}

	TRACE(TRACE_VERBOSE, "wlanDropGratuitousArpHandler\n");

	if (wl_grat_arp(wl(), req->dropGratuitousArp.enable) < 0) {
		TRACE(TRACE_ERROR, "wl_grat_arp failed\n");
	}
}

/* drop gratuitous ARP */
int wlanDropGratuitousArp(wlanT *wlan, int enable)
{
	wlanReqT req;

	TRACE(TRACE_VERBOSE, "wlanDropGratuitousArp\n");

	req.handler = wlanDropGratuitousArpHandler;
	req.dropGratuitousArp.enable = enable;

	return dspRequest(dsp(), wlan, sizeof(req), (uint8 *)&req);
}

/* ----------------------------------------------------------- */

static void wlanWnmHandler(wlanT *wlan,
	int reqLength, wlanReqT *req, void *rspNull)
{
	(void)rspNull;
	if (wlan == 0 || reqLength != sizeof(wlanReqT) || req == 0) {
		TRACE(TRACE_ERROR, "invalid parameter\n");
		return;
	}

	TRACE(TRACE_VERBOSE, "wlanWnmHandler\n");

	if (wl_wnm(wl(), req->wnm.mask) < 0) {
		TRACE(TRACE_ERROR, "wl_wnm failed\n");
	}
}

/* WNM configuration enable */
int wlanWnm(wlanT *wlan, int mask)
{
	wlanReqT req;

	TRACE(TRACE_VERBOSE, "wlanWnm\n");

	req.handler = wlanWnmHandler;
	req.wnm.mask = mask;

	return dspRequest(dsp(), wlan, sizeof(req), (uint8 *)&req);
}

/* ----------------------------------------------------------- */

static void wlanWnmGetHandler(wlanT *wlan,
	int reqLength, wlanReqT *req, void *rsp)
{
	if (wlan == 0 || reqLength != sizeof(wlanReqT) || req == 0 || rsp == 0) {
		TRACE(TRACE_ERROR, "invalid parameter\n");
		return;
	}

	TRACE(TRACE_VERBOSE, "wlanWnmGetHandler\n");

	if (wl_wnm_get(wl(), rsp) < 0) {
		TRACE(TRACE_ERROR, "wl_wnm_get failed\n");
	}
}

/* WNM configuration get */
int wlanWnmGet(wlanT *wlan, int *mask)
{
	wlanReqT req;

	TRACE(TRACE_VERBOSE, "wlanWnmGet\n");

	req.handler = wlanWnmGetHandler;

	return dspRequestSynch(dsp(), wlan, sizeof(req), (uint8 *)&req,
		(uint8 *)mask);
}


/* ----------------------------------------------------------- */

static void wlanPmfHandler(wlanT *wlan,
	int reqLength, wlanReqT *req, void *rspNull)
{
	(void)rspNull;
	if (wlan == 0 || reqLength != sizeof(wlanReqT) || req == 0) {
		TRACE(TRACE_ERROR, "invalid parameter\n");
		return;
	}

	TRACE(TRACE_VERBOSE, "wlanPmfHandler\n");

	if (wl_pmf(wl(), req->pmf.mode) < 0) {
		TRACE(TRACE_ERROR, "wl_pmf failed\n");
	}
}

/* PMF mode (0=disable, 1=capable, 2=required) */
int wlanPmf(wlanT *wlan, int mode)
{
	wlanReqT req;

	TRACE(TRACE_VERBOSE, "wlanPmf\n");

	req.handler = wlanPmfHandler;
	req.pmf.mode = mode;

	return dspRequest(dsp(), wlan, sizeof(req), (uint8 *)&req);
}

/* ----------------------------------------------------------- */

static void wlanMacHandler(wlanT *wlan,
	int reqLength, wlanReqT *req, void *rspNull)
{
	(void)rspNull;
	if (wlan == 0 || reqLength == 0 || req == 0) {
		TRACE(TRACE_ERROR, "invalid parameter\n");
		return;
	}

	TRACE(TRACE_VERBOSE, "wlanMacHandler\n");

	if (wl_mac(wl(), req->mac.count, req->mac.addr) < 0) {
		TRACE(TRACE_ERROR, "wl_mac failed\n");
	}
	if (wl_macmode(wl(), req->mac.mode) < 0) {
		TRACE(TRACE_ERROR, "wl_macmode failed\n");
	}
}

/* set MAC mode and list */
int wlanMac(wlanT *wlan, int mode, int count, struct ether_addr *addr)
{
	int ret;
	int len;
	wlanReqT *req;

	TRACE(TRACE_VERBOSE, "wlanMac\n");

	len = sizeof(wlanReqT) - sizeof(*addr) + count * sizeof(*addr);
	req = malloc(len);
	if (req == 0)
		return 0;
	req->handler = wlanMacHandler;
	req->mac.mode = mode;
	req->mac.count = count;
	memcpy(req->mac.addr, addr, count * sizeof(*addr));

	ret = dspRequest(dsp(), wlan, len, (uint8 *)req);
	free(req);
	return ret;
}

/* ----------------------------------------------------------- */

static void wlanProcessWlanEvent(void *context, uint32 eventType,
	wl_event_msg_t *wlEvent, uint8 *data, uint32 length)
{
	(void)context;
#ifdef BCMDBG
	int i;
	char *event_name = "UNKNOWN";

	for (i = 0; i < bcmevent_names_size; i++) {
		if (bcmevent_names[i].event == eventType)
			event_name = (char *)bcmevent_names[i].name;
	}
	TRACE(TRACE_EVENT, "WLAN event %s (%d) status=%d reason=%d\n",
		event_name, eventType, wlEvent->status, wlEvent->reason);
#endif	/* BCMDBG */

	if (gEventCallback.fn != 0) {
		gEventCallback.fn(gEventCallback.context,
			eventType, wlEvent, data, length);
	}
}

/* subscribe for event notification callback */
int wlanSubscribeEvent(void *context, void (*fn)(void *context, uint32 eventType,
	wl_event_msg_t *wlEvent, uint8 *data, uint32 length))
{
	gEventCallback.fn = fn;
	gEventCallback.context = context;
	return TRUE;
}

/* unsubscribe for event notification callback */
int wlanUnsubscribeEvent(void (*fn)(void *context, uint32 eventType,
	wl_event_msg_t *wlEvent, uint8 *data, uint32 length))
{
	(void)fn;
	memset(&gEventCallback, 0, sizeof(gEventCallback));
	return TRUE;
}
