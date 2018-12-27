/*
 * Common OS-independent driver header for open-loop power calibration engine.
 *
 * Copyright (C) 2015, Broadcom Corporation
 * All Rights Reserved.
 * 
 * This is UNPUBLISHED PROPRIETARY SOURCE CODE of Broadcom Corporation;
 * the contents of this file may not be disclosed to third parties, copied
 * or duplicated in any form, in whole or in part, without the prior
 * written permission of Broadcom Corporation.
 *
 * $Id: wlc_olpc_engine.h,v 1.70 2012/01/28 04:59:00 Exp $
 */
#ifndef _wlc_olpc_engine_h_
#define _wlc_olpc_engine_h_

#ifdef WLOLPC
/* get open loop pwr ctl rate limit for current channel */
#define WLC_OLPC_NO_LIMIT	0
#define WLC_OLPC_SISO_LIMIT	1

/* return current rate limit state */
extern int wlc_olpc_eng_rate_limit_get(wlc_info_t *wlc, uint16 frame_type);

/* kick-off open loop phy cal */
extern int wlc_olpc_eng_hdl_chan_update(wlc_info_t *wlc);

/* call from stf when txchain increases */
extern int wlc_olpc_eng_hdl_txchain_update(wlc_info_t *wlc);

/* kick off new open loop phy cal */
extern int wlc_olpc_eng_recal(wlc_info_t *wlc, uint8 npkts);

/* module attach */
extern wlc_olpc_eng_info_t * wlc_olpc_eng_attach(wlc_info_t *wlc);

/* module detach, up, down */
extern void wlc_olpc_eng_detach(struct wlc_olpc_eng_info_t *olpc_info);

extern int wlc_olpc_eng_up(void *hdl);
extern int wlc_olpc_eng_down(void *hdl);

/* txstatus callback */
extern void wlc_olpc_pkt_complete(wlc_info_t *wlc, void *pkt,
	wlc_txh_info_t* tx_info, uint txs);

/* return TRUE iff olpc sent the pkt */
extern bool wlc_olpc_sent_pkt(wlc_info_t *wlc, void *pkt, wlc_txh_info_t* tx_info);

/* return next core/antenna to use for sending mgmt/ctl frame (0, 1, ...) */
extern uint8
wlc_olpc_get_next_antenna_mask(struct wlc_olpc_eng_info_t *olpc, ratespec_t rspec);

extern bool
wlc_olpc_chan_has_active_cal(wlc_info_t *wlc);

#endif /* WLOLPC */
#endif /* _wlc_olpc_engine_h_ */
