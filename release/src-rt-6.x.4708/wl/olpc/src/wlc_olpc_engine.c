/*
 * Open Loop phy calibration SW module for
 * Broadcom 802.11bang Networking Device Driver
 *
 * Copyright (C) 2015, Broadcom Corporation
 * All Rights Reserved.
 * 
 * This is UNPUBLISHED PROPRIETARY SOURCE CODE of Broadcom Corporation;
 * the contents of this file may not be disclosed to third parties, copied
 * or duplicated in any form, in whole or in part, without the prior
 * written permission of Broadcom Corporation.
 *
 * $Id: wlc_olpc_engine.c 377976 2013-01-23 20:57:10Z $
 */

#include <wlc_cfg.h>
#ifdef WLOLPC
#include <typedefs.h>
#include <osl.h>
#include <bcmutils.h>
#include <bcmdevs.h>
#include <pcicfg.h>
#include <pcie_core.h>
#include <siutils.h>
#include <bcmendian.h>
#include <nicpci.h>
#include <wlioctl.h>
#include <pcie_core.h>
#include <sbhnddma.h>
#include <hnddma.h>
#include <d11.h>
#include <wlc_rate.h>
#include <wlc_key.h>
#include <wlc_pub.h>
#include <wlc_bsscfg.h>
#include <wlc.h>
#include <wlc_hw.h>
#include <wlc_bmac.h>
#include <wlc_scb.h>
#include <wl_export.h>
#include <wl_dbg.h>
#include <wlc_olpc_engine.h>
#include <wlc_channel.h>
#include <wlc_ppr.h>
#include <wlc_stf.h>
#include <wlc_scan.h>
#include <wlc_rm.h>

#define WL_OLPC_DEF_NPKTS 16
#define WL_OLPC_PKT_LEN (sizeof(struct dot11_header)+1)
#define WL_OLPC(args) WL_INFORM(args)
#define WL_OLPC_DBG(args) WL_INFORM(args)

/* assume one bit per antenna, so ant 3 is 4 */
#define WL_OLPC_MAX_NUM_CORES 3
#define WL_OLPC_MAX_CORE 4
#define WL_OLPC_ANT_TO_CIDX(core) ((core == WL_OLPC_MAX_CORE) ? \
	(WL_OLPC_MAX_NUM_CORES-1) : (core - 1))
/* Need to shave 1.5 (6 coz units are .25 dBm) off ppr power to comp TSSI pwr */
#define WL_OLPC_PPR_TO_TSSI_PWR(pwr) (pwr - 6)
/* below value in dBm -- 802.11d POWER at/below which olpc kicks in */
#define WL_OLPC_MAX_POWER_THRESH 14
#define WLC_OLPC_INVALID_CHAN 0
#define WLC_OLPC_INVALID_TXCHAIN 0xff

#ifdef NOT_YET
enum {
	IOV_OLPC,
	IOV_OLPC_NPKTS,
	IOV_OLPC_TIMEOUT,
	IOV_OLPC_LAST
};
#endif /* NOT_YET */

static const bcm_iovar_t olpc_iovars[] = {
#ifdef NOT_YET
	{"olpc", IOV_OLPC, IOVF_SET_DOWN, IOVT_BOOL, 0},
	{"npkts", IOV_OLPC_NPKTS, IOVF_SET_UP, IOVT_UINT8, 0},
	{"timeout", IOV_OLPC_TIMEOUT, IOVF_SET_DOWN, IOVT_INT16, 0},
#endif /* NOT_YET */
	{NULL, 0, 0, 0, 0}
};

typedef struct wlc_olpc_eng_chan_t {
	struct wlc_olpc_eng_chan_t *next;
	chanspec_t cspec; /* chanspec, containing chan number the struct refers to */
	uint8 pkts_sent[WL_OLPC_MAX_NUM_CORES];
	bool limit_rate; /* should driver limit rates */
	bool past_cal; /* has there ever been a successful cal ? */
	uint8 cores_cal; /* which cores have been calibrated */
	uint8 cores_cal_active; /* which cores have active cal */
} wlc_olpc_eng_chan;

struct wlc_olpc_eng_info_t {
	wlc_info_t *wlc;
	/* status info */
	wlc_olpc_eng_chan *chan_list;
	chanspec_t last_chan_chk;
	bool last_chan_olpc_state;
	bool last_chan_olpc; /* track whether last channel was olpc one */
	bool up;
	/* configuration */
	uint8 npkts;	/* number of pkts to send for calibration */
	uint8 next_ant;	/* next antenna to use for mgmt/ctl packet */
	uint8 num_hw_cores;

	/* txchain and txcore mgmt */
	bool restore_perrate_stf_state;

	wlc_stf_txchain_st stf_saved_perrate;

	/* needs olpc cache */
	uint8 last_txchain_chk;

	/* track our current channel - detect channel changes */
	chanspec_t cur_cspec;
};

/* static functions and internal defines */
#define WLC_TO_CHANSPEC(wlc) (wlc->chanspec)
#define WLC_TO_NPKTS4CAL(wlc) \
	(wlc->olpc_info ? wlc->olpc_info->npkts : WL_OLPC_DEF_NPKTS)

/* use own mac addr for src and dest */
#define WLC_MACADDR(wlc) (char*)(wlc->bsscfg[0]->cur_etheraddr.octet)

static int
wlc_olpc_schedule_recal(wlc_info_t *wlc, struct wlc_olpc_eng_chan_t* chan, uint8 npkts);

static bool wlc_olpc_chan_needs_cal(wlc_olpc_eng_info_t *olpc, struct wlc_olpc_eng_chan_t* chan);

static int
wlc_olpc_send_dummy_pkts(wlc_info_t *wlc,
	struct wlc_olpc_eng_chan_t* chan, uint8 npkts);

static int
wlc_olpc_eng_recal_ex(wlc_info_t *wlc, uint8 npkts, bool force);

static int
wlc_olpc_stf_override(wlc_info_t *wlc);

int BCMFASTPATH
wlc_olpc_eng_rate_limit_get(wlc_info_t *wlc, uint16 type);

static struct wlc_olpc_eng_chan_t*
wlc_olpc_get_chan(wlc_info_t *wlc, chanspec_t cspec, int *err);

static struct wlc_olpc_eng_chan_t*
wlc_olpc_get_chan_ex(wlc_info_t *wlc, chanspec_t cspec, int *err, bool create);

static INLINE bool
wlc_olpc_chan_needs_olpc(wlc_olpc_eng_info_t *olpc, chanspec_t cspec);

void
wlc_olpc_stf_perrate_changed(wlc_info_t *wlc);

static void wlc_olpc_chan_terminate_active_cal(wlc_info_t *wlc, chanspec_t cspec);
static bool wlc_olpc_chan_active_cal(wlc_olpc_eng_info_t *olpc, struct wlc_olpc_eng_chan_t* chan);
static int wlc_olpc_stf_override_revert(wlc_info_t *wlc);


static void
wlc_olpc_chan_terminate_active_cal(wlc_info_t *wlc, chanspec_t cspec)
{
	int err;
	struct wlc_olpc_eng_chan_t* cur_chan = wlc_olpc_get_chan_ex(wlc, cspec, &err, FALSE);
	if (cur_chan && wlc_olpc_chan_active_cal(wlc->olpc_info, cur_chan)) {
		wlc_olpc_stf_override_revert(wlc);
		bzero(cur_chan->pkts_sent, sizeof(cur_chan->pkts_sent));
		cur_chan->cores_cal_active = 0;
	}
}

/* return TRUE iff txchain has cores that need calibrating */
static bool
wlc_olpc_chan_needs_cal(wlc_olpc_eng_info_t *olpc, struct wlc_olpc_eng_chan_t* chan)
{
	/* if cores not calibrated nor calibrating (~(chan->cores_cal | chan->cores_cal_active)) */
	/* that are in txchain (& olpc->wlc->stf->txchain), then we need some calibration */
	return (~(chan->cores_cal | chan->cores_cal_active) & olpc->wlc->stf->txchain) != 0;
}

static bool
wlc_olpc_chan_active_cal(wlc_olpc_eng_info_t *olpc, struct wlc_olpc_eng_chan_t* chan)
{
	return ((chan->cores_cal_active) != 0);
}

void
wlc_olpc_stf_perrate_changed(wlc_info_t *wlc)
{
	if (wlc->olpc_info) {
		WL_OLPC_DBG(("prerrate chged not restore\n"));
		wlc->olpc_info->restore_perrate_stf_state = FALSE;
	}
}

bool
wlc_olpc_chan_has_active_cal(wlc_info_t *wlc)
{
	wlc_olpc_eng_info_t *olpc = wlc->olpc_info;
	bool found_active = FALSE;
	struct wlc_olpc_eng_chan_t* cur_chan = NULL;

	if (!olpc || !olpc->up) {
		return found_active;
	}

	cur_chan = olpc->chan_list;
	while (cur_chan) {
		if (wlc_olpc_chan_active_cal(olpc, cur_chan)) {
			found_active = TRUE;
			break;
		}
		cur_chan = cur_chan->next;
	}
	return found_active;
}

static int
wlc_olpc_stf_override(wlc_info_t *wlc)
{
	int err = BCME_OK;
	uint8 tgt_chains = wlc->stf->txchain;

	if ((wlc->stf->txcore_override[OFDM_IDX] == tgt_chains &&
		wlc->stf->txcore_override[CCK_IDX] == tgt_chains)) {
		/* NO-OP */
		return err;
	}
	if (!wlc->olpc_info->restore_perrate_stf_state) {
		wlc_stf_txchain_get_perrate_state(wlc, &(wlc->olpc_info->stf_saved_perrate),
			wlc_olpc_stf_perrate_changed);
	}

	wlc->olpc_info->restore_perrate_stf_state = TRUE;

	/* set value to have all cores on */
	/* we may use OFDM or CCK for cal pkts */
	wlc->stf->txcore_override[OFDM_IDX] = tgt_chains;
	wlc->stf->txcore_override[CCK_IDX] = tgt_chains;

	wlc_stf_spatial_policy_set(wlc, wlc->stf->spatialpolicy);

	return err;
}

/* called when calibration is done */
static int
wlc_olpc_stf_override_perrate_revert(wlc_info_t *wlc)
{
	if (wlc->olpc_info->restore_perrate_stf_state) {
		wlc->olpc_info->restore_perrate_stf_state = FALSE;
		wlc_stf_txchain_restore_perrate_state(wlc, &(wlc->olpc_info->stf_saved_perrate));
	}
	return BCME_OK;
}

/* called when calibration is done - if stf saved state still valid, restore it */
static int
wlc_olpc_stf_override_revert(wlc_info_t *wlc)
{
	/* restore override on txcore */
	wlc_olpc_stf_override_perrate_revert(wlc);
	/* txchain is not changed */
	return BCME_OK;
}

/* get open loop pwr ctl rate limit for current channel */
int BCMFASTPATH
wlc_olpc_eng_rate_limit_get(wlc_info_t *wlc, uint16 type)
{
	int err;
	struct wlc_olpc_eng_chan_t *olpc_chan = NULL;
	if (!wlc->pub->up) {
		WL_OLPC_DBG(("wl%d:%s: not up!\n", wlc->pub->unit, __FUNCTION__));
		/* assume no limit - can't prove otherwise */
		return WLC_OLPC_NO_LIMIT;
	}

	if (!wlc_olpc_chan_needs_olpc(wlc->olpc_info, wlc->chanspec)) {
		return WLC_OLPC_NO_LIMIT;
	}

	/* if pkt is mgmt or ctl frame, then always restrict on low power channel */
	if (type == FC_TYPE_MNG || type == FC_TYPE_CTL) {
		return WLC_OLPC_SISO_LIMIT;
	}

	olpc_chan = wlc_olpc_get_chan(wlc, wlc->chanspec, &err);

	if (err != BCME_OK) {
		WL_RATE(("wl%d:%s: limit rate due to error getting olpc chan info\n",
			wlc->pub->unit, __FUNCTION__));
		return WLC_OLPC_SISO_LIMIT;
	}
	if (!olpc_chan || !olpc_chan->limit_rate) {
		return WLC_OLPC_NO_LIMIT;
	}
	return WLC_OLPC_SISO_LIMIT;
}

/* use ppr to find min tgt power in .25dBm units */
static int
wlc_olpc_get_min_tgt_pwr(wlc_olpc_eng_info_t *olpc, chanspec_t channel)
{
	wlc_info_t* wlc = olpc->wlc;
	int cur_min = 0xFFFF;
	wlc_phy_t *pi = wlc->band->pi;
	ppr_t *txpwr;
	ppr_t *srommax;
	int8 min_srom;
	if ((txpwr = ppr_create(wlc->pub->osh, PPR_CHSPEC_BW(channel))) == NULL) {
		return WL_RATE_DISABLED;
	}
	if ((srommax = ppr_create(wlc->pub->osh, PPR_CHSPEC_BW(channel))) == NULL) {
		ppr_delete(wlc->pub->osh, txpwr);
		return WL_RATE_DISABLED;
	}
	/* use the control channel to get the regulatory limits and srom max/min */
	wlc_channel_reg_limits(wlc->cmi, channel, txpwr);

	wlc_phy_txpower_sromlimit(pi, channel, (uint8*)&min_srom, srommax, 0);
	/* bound the regulatory limit by srom min/max */
	ppr_apply_vector_ceiling(txpwr, srommax);
	ppr_apply_min(txpwr, min_srom);
	WL_NONE(("min_srom %d\n", min_srom));

	cur_min = ppr_get_min(txpwr, min_srom);

	ppr_delete(wlc->pub->osh, srommax);
	ppr_delete(wlc->pub->osh, txpwr);

	return (int)(cur_min);
}

/* is channel one that needs open loop phy cal? */
static INLINE bool
wlc_olpc_chan_needs_olpc(wlc_olpc_eng_info_t *olpc, chanspec_t chan)
{
	int pwr, tssi_thresh;

	if (olpc && olpc->wlc->band && olpc->wlc->band->pi) {
		if (olpc->last_chan_chk != chan ||
			olpc->last_txchain_chk != olpc->wlc->stf->txchain) {
			pwr = wlc_olpc_get_min_tgt_pwr(olpc, chan);

			if (pwr == WL_RATE_DISABLED) {
				/* assume not need olpc */
				WL_ERROR(("%s: min pwr lookup failed -- assume not olpc\n",
					__FUNCTION__));
				olpc->last_chan_olpc_state = FALSE;
			} else {
				/* adjust by -1.5dBm to reconcile ppr and tssi */
				pwr = WL_OLPC_PPR_TO_TSSI_PWR(pwr);
				tssi_thresh = wlc_phy_tssivisible_thresh(olpc->wlc->band->pi);
				WL_NONE(("chan=%d mintgtpwr=%d tssithresh=%d\n",
					CHSPEC_CHANNEL(chan), pwr, tssi_thresh));
				/* this channel needs open loop pwr cal iff the below is true */
				olpc->last_chan_olpc_state = (pwr < tssi_thresh);
			}
			olpc->last_chan_chk = chan;
			olpc->last_txchain_chk = olpc->wlc->stf->txchain;
		}
		return olpc->last_chan_olpc_state;
	} else {
		WL_REGULATORY(("%s: needs olpc FALSE/skip due to null phy info\n",
			__FUNCTION__));
	}
	return FALSE;
}

static void
wlc_olpc_chan_init(struct wlc_olpc_eng_chan_t* chan, chanspec_t cspec)
{
	chan->limit_rate = TRUE;
	chan->past_cal = FALSE;
	chan->pkts_sent[0] = 0;
	chan->pkts_sent[1] = 0;
	chan->pkts_sent[2] = 0;

	/* chanspec, containing chan number the struct refers to */
	chan->cspec = CHSPEC_CHANNEL(cspec);
	chan->next = NULL;
	chan->cores_cal = 0;
	chan->cores_cal_active = 0;
}

/*
* cspec - chanspec to search for
* err - to return error values
* create - TRUE to create if not found; FALSE otherwise
* return pointer to channel info structure; NULL if not found/not created
*/
static struct wlc_olpc_eng_chan_t*
wlc_olpc_get_chan_ex(wlc_info_t *wlc, chanspec_t cspec, int *err, bool create)
{
	struct wlc_olpc_eng_chan_t* chan = NULL;
	*err = BCME_OK;

	chan = wlc->olpc_info->chan_list;
	/* find cspec in list */
	while (chan) {
		/* get chan struct through which comparison? */
		if (chan->cspec == CHSPEC_CHANNEL(cspec)) {
			return chan;
		}
		chan = chan->next;
	}
	if (!create) {
		return NULL;
	}
	/* create new channel on demand */
	chan = MALLOC(wlc->osh, sizeof(struct wlc_olpc_eng_chan_t));
	if (chan) {
		/* init and insert into list */
		wlc_olpc_chan_init(chan, cspec);
		chan->next = wlc->olpc_info->chan_list;
		wlc->olpc_info->chan_list = chan;
	} else {
		*err = BCME_NOMEM;
	}

	return chan;
}

/* get olpc chan from list - create it if not there */
static struct wlc_olpc_eng_chan_t*
wlc_olpc_get_chan(wlc_info_t *wlc, chanspec_t cspec, int *err)
{
	return wlc_olpc_get_chan_ex(wlc, cspec, err, TRUE);
}

static void
wlc_olpc_set_rate_limit(struct wlc_olpc_eng_chan_t* chan_info, bool lim)
{
	if (chan_info) {
		chan_info->limit_rate = lim;
	} else {
		return;
	}
}

static void
wlc_olpc_rt_change(wlc_info_t *wlc, struct wlc_olpc_eng_info_t* olpc_info)
{
	uint entry_ptr;
	uint offset_pos;
	uint16 txphyctl;
	wlc_hwrs_iterator hwrs_walker;
	WL_OLPC_DBG(("wl%d:%s\n", wlc->pub->unit, __FUNCTION__));
	/* read ratetable */
	/* init d11 core dependent rate table offset */
	if (D11REV_LT(olpc_info->wlc->pub->corerev, 40)) {
		offset_pos = M_RT_TXPWROFF_POS;
	} else {
		offset_pos = M_REV40_RT_TXPWROFF_POS;
	}

	/* walk rateset and for each rate, ensure we use only tx pwr offset 0 for ucode pkts */
	wlc_hwrs_iterator_init(wlc, &hwrs_walker);
	while (!wlc_hwrs_iterator_finished(&hwrs_walker)) {
		entry_ptr = wlc_rate_shm_offset(olpc_info->wlc,
			wlc_hwrs_iterator_next(&hwrs_walker));

		txphyctl = wlc_read_shm(olpc_info->wlc, (entry_ptr + offset_pos));

		WL_OLPC_DBG(("wl%d:%s: before-%x\n", wlc->pub->unit, __FUNCTION__, txphyctl));
		txphyctl &= ~D11AC_PHY_TXC_TXPWR_OFFSET_MASK;
		WL_OLPC_DBG(("wl%d:%s: after-%x\n", wlc->pub->unit, __FUNCTION__, txphyctl));

		/* set pwr offset to 0 */
		wlc_write_shm(olpc_info->wlc, (entry_ptr + offset_pos), txphyctl);
	}
}

static void
wlc_olpc_rt_revert(wlc_info_t *wlc, struct wlc_olpc_eng_info_t* olpc_info)
{
	/* this appears to be a no-op for now */
}

int
wlc_olpc_eng_hdl_txchain_update(wlc_info_t *wlc)
{
	if (wlc->olpc_info->restore_perrate_stf_state &&
		!wlc_stf_saved_state_is_consistent(wlc, &wlc->olpc_info->stf_saved_perrate))
	{
		/* our saved txcore_override may no longer be valid, so don't restore */
		/* logic in stf prevents txchain and txcore_override from colliding */
		/* if saved state is 0 then restore unless txcore_override changes */
		wlc->olpc_info->restore_perrate_stf_state = FALSE;
	}
	return wlc_olpc_eng_hdl_chan_update(wlc);
}

/* kick-off open loop phy cal */
int wlc_olpc_eng_hdl_chan_update(wlc_info_t *wlc)
{
	int err = BCME_OK;
	chanspec_t cspec = WLC_TO_CHANSPEC(wlc);
	bool olpc_chan = FALSE;
	struct wlc_olpc_eng_chan_t* chan_info = NULL;
	struct wlc_olpc_eng_info_t* olpc_info = wlc->olpc_info;

	if (!olpc_info || !olpc_info->up) {
		WL_OLPC_DBG(("wl%d:%s: olpc module not up\n", wlc->pub->unit, __FUNCTION__));
		return BCME_ERROR;
	}
	if (olpc_info->cur_cspec != cspec && olpc_info->last_chan_olpc) {
		wlc_olpc_chan_terminate_active_cal(wlc, olpc_info->cur_cspec);
	}
	olpc_info->cur_cspec = cspec;

	olpc_chan = wlc_olpc_chan_needs_olpc(olpc_info, cspec);
	WL_OLPC_DBG(("%s: chan=%x home=%x olpc_chan=%d\n", __FUNCTION__, wlc->chanspec,
		wlc->home_chanspec, olpc_chan));

	if (olpc_chan) {
		/* phytx ctl word power offset needs to be set */
		if (!olpc_info->last_chan_olpc) {
			wlc_olpc_rt_change(wlc, olpc_info);
			olpc_info->last_chan_olpc = TRUE;
		}
		chan_info = wlc_olpc_get_chan(wlc, cspec, &err);
		/* if null here, there was an out of mem condition */
		if (!chan_info) {
			err = BCME_NOMEM;
			WL_OLPC(("%s: chan info not found\n", __FUNCTION__));

			goto exit;
		} else if (wlc_olpc_chan_active_cal(olpc_info, chan_info) &&
			!wlc_olpc_chan_needs_cal(olpc_info, chan_info)) {
			/* calibration active - do nothing */
			WL_OLPC_DBG(("calibration active at chan update notify\n"));
			goto exit;
		} else if (!wlc_olpc_chan_needs_cal(olpc_info, chan_info)) {
			/* no cal needed */
			wlc_olpc_set_rate_limit(chan_info, FALSE);
			WL_OLPC_DBG(("%s: calibration not needed\n", __FUNCTION__));
			goto exit;
		} else {
			/* cal needed -- limit all rates for now */
			wlc_olpc_set_rate_limit(chan_info, TRUE);
			WL_OLPC_DBG(("%s: calibration needed, limiting rate\n", __FUNCTION__));
		}
		/* now kick off cal/recal */
		WL_OLPC_DBG(("%s: calibration needed chan=%d, starting\n", __FUNCTION__,
			chan_info->cspec));
		err = wlc_olpc_eng_recal_ex(wlc, WLC_TO_NPKTS4CAL(wlc), !chan_info->past_cal);
	} else {
		if (olpc_info->last_chan_olpc) {
			wlc_olpc_rt_revert(wlc, olpc_info);
			wlc_olpc_stf_override_revert(wlc);
			olpc_info->last_chan_olpc = FALSE;
		}
	}
exit:
	return err;
}

static int
wlc_olpc_eng_recal_ex(wlc_info_t *wlc, uint8 npkts, bool force)
{
	int err = BCME_OK;
	struct wlc_olpc_eng_chan_t* chan_info = NULL;

	WL_OLPC_DBG(("%s\n", __FUNCTION__));
	if (!wlc_olpc_chan_needs_olpc(wlc->olpc_info, WLC_TO_CHANSPEC(wlc))) {
		return BCME_OK;
	}

	chan_info = wlc_olpc_get_chan(wlc, WLC_TO_CHANSPEC(wlc), &err);

	if ((SCAN_IN_PROGRESS(wlc->scan) || WLC_RM_IN_PROGRESS(wlc))) {
		if (force || (chan_info && wlc_olpc_chan_needs_cal(wlc->olpc_info, chan_info))) {
			WL_OLPC_DBG(("%s - in excursion\n", __FUNCTION__));
			err = wlc_olpc_schedule_recal(wlc, chan_info, npkts);
		} else {
			WL_OLPC_DBG(("olpc in excursion - no-op\n"));
		}
	} else {
		WL_OLPC(("%s - send dummies\n", __FUNCTION__));
		err = wlc_olpc_send_dummy_pkts(wlc, chan_info, npkts);
	}
	WL_OLPC_DBG(("%s - end\n", __FUNCTION__));

	return err;
}

/* kick off new open loop phy cal */
int
wlc_olpc_eng_recal(wlc_info_t *wlc, uint8 npkts)
{
	return wlc_olpc_eng_recal_ex(wlc, npkts, TRUE);
}

/* implement lazy scheduling - wait til next time we're on channel, then kick off */
static int
wlc_olpc_schedule_recal(wlc_info_t *wlc, struct wlc_olpc_eng_chan_t* chan, uint8 npkts)
{
	if (!chan) {
		return BCME_NOMEM;
	}
	if (wlc->olpc_info) {
		wlc->olpc_info->npkts = npkts;
	} else {
		return BCME_NOTUP;
	}
	chan->cores_cal = 0;
	chan->limit_rate = !(chan->past_cal);
	return BCME_OK;
}

static void
wlc_olpc_modify_pkt(wlc_info_t *wlc, void* p, uint8 core_idx)
{
	/* no ACK */
	wlc_pkt_set_ack(wlc, p, FALSE);

	/* Which core? */
	wlc_pkt_set_core(wlc, p, core_idx);

	/* pwr offset 0 */
	wlc_pkt_set_txpwr_offset(wlc, p, 0);
}

/* totally bogus -- d11 hdr only + tx hdrs */
static void *
wlc_olpc_get_pkt(wlc_info_t *wlc, uint ac, uint* fifo)
{
	int buflen = 1024;
	void* p = NULL;
	osl_t *osh = wlc->osh;
	const char* macaddr = NULL;
	struct dot11_header *hdr = NULL;

	if ((p = PKTGET(osh, buflen, TRUE)) == NULL) {
		WL_ERROR(("wl%d: %s: pktget error for len %d \n",
			wlc->pub->unit, __FUNCTION__, buflen));
		goto fatal;
	}
	macaddr = WLC_MACADDR(wlc);

	WL_OLPC_DBG(("pkt manip\n"));
	/* reserve TXOFF bytes of headroom */
	PKTPULL(osh, p, TXOFF);
	PKTSETLEN(osh, p, WL_OLPC_PKT_LEN);

	WL_OLPC_DBG(("d11_hdr\n"));
	hdr = (struct dot11_header*)PKTDATA(osh, p);
	bzero((char*)hdr, WL_OLPC_PKT_LEN);
	hdr->fc = htol16(FC_DATA);
	hdr->durid = 0;
	bcopy((const char*)macaddr, (char*)&(hdr->a1.octet), ETHER_ADDR_LEN);
	bcopy((const char*)macaddr, (char*)&(hdr->a2.octet), ETHER_ADDR_LEN);
	bcopy((const char*)macaddr, (char*)&(hdr->a3.octet), ETHER_ADDR_LEN);
	hdr->seq = 0;
	WL_OLPC_DBG(("prep raw 80211\n"));

	/* frameid returned here -- ignore for now -- may speed up using this */
	(void)wlc_prep80211_raw(wlc, NULL, ac, TRUE, p, fifo);
	return p;
fatal:
	return (NULL);
}

bool BCMFASTPATH
wlc_olpc_sent_pkt(wlc_info_t *wlc, void *pkt, wlc_txh_info_t* tx_info)
{
	struct dot11_header *hdr;
	const char* macaddr;
	d11actxh_t* vhtHdr;
	chanspec_t chanspec;
	int err;
	struct wlc_olpc_eng_chan_t* olpc_chan;
	wlc_olpc_eng_info_t *olpc_info = wlc->olpc_info;

	/* check if olpc channel */
	if (olpc_info->chan_list) {
		vhtHdr = (d11actxh_t*)(tx_info->hdrPtr);
		chanspec = ltoh16(vhtHdr->PktInfo.Chanspec);

		if (!wlc_olpc_chan_needs_olpc(olpc_info, chanspec)) {
			WL_OLPC_DBG(("%s: skipping unowned pkt\n", __FUNCTION__));
			return FALSE;
		}
	} else {
		return FALSE;
	}

	hdr = (struct dot11_header *)tx_info->d11HdrPtr;
	macaddr = (const char*)WLC_MACADDR(wlc);

	/* ensure a1-a3 macaddress are all ours */
	if (bcmp(macaddr, (char*)&(hdr->a1.octet), ETHER_ADDR_LEN) == 0 &&
		bcmp(macaddr, (char*)&(hdr->a3.octet), ETHER_ADDR_LEN) == 0 &&
		bcmp(macaddr, (char*)&(hdr->a2.octet), ETHER_ADDR_LEN) == 0) {
		olpc_chan = wlc_olpc_get_chan_ex(wlc, chanspec, &err, FALSE);
		return (olpc_chan != NULL);
	}
	return FALSE;
}

/* process one pkt send complete */
void
wlc_olpc_pkt_complete(wlc_info_t *wlc, void *pkt, wlc_txh_info_t* tx_info, uint txs)
{
	chanspec_t chanspec;

	struct wlc_olpc_eng_chan_t* olpc_chan = NULL;
	int err;
	uint8 coreMask;
	uint8 cidx = 0;
	/* one calibration packet was finished */
	/* look at packet header to find - channel, antenna, etc. */
	chanspec = wlc_txh_get_chanspec(wlc, tx_info);
	olpc_chan = wlc_olpc_get_chan_ex(wlc, chanspec, &err, FALSE);
	if (!olpc_chan || err != BCME_OK || olpc_chan->cores_cal_active == 0) {
		WL_OLPC_DBG(("%s: entry NO-OP chanspec=%x\n", __FUNCTION__, chanspec));
		return;
	}
	WL_OLPC_DBG(("%s: entry status=%d\n", __FUNCTION__, txs));

	/* get core number */
	coreMask = (tx_info->PhyTxControlWord0 & D11AC_PHY_TXC_CORE_MASK) >>
		(D11AC_PHY_TXC_CORE_SHIFT);
	cidx = WL_OLPC_ANT_TO_CIDX(coreMask);

	WL_OLPC_DBG(("%s: coreNum=%x\n", __FUNCTION__, coreMask));

	/* decrement counters */
	if (olpc_chan->pkts_sent[cidx]) {
		olpc_chan->pkts_sent[cidx]--;
	} else {
		WL_OLPC_DBG(("wl%d: %s: tried decrementing counter of 0, idx=%d\n",
			wlc->pub->unit, __FUNCTION__, WL_OLPC_ANT_TO_CIDX(coreMask)));
	}
	/* if done, lift rate restrictions and update info */
	if (olpc_chan->pkts_sent[cidx] == 0) {
		olpc_chan->cores_cal_active &= ~coreMask;
		olpc_chan->cores_cal |= coreMask;
		WL_OLPC(("%s: exit: open loop phy CAL done mask=%x!\n", __FUNCTION__, coreMask));
		WL_OLPC(("%s: exit: open loop phy CAL done done=%x active=%x!\n", __FUNCTION__,
			olpc_chan->cores_cal, olpc_chan->cores_cal_active));
	}
	if (olpc_chan->cores_cal == wlc->stf->hw_txchain) {
		olpc_chan->past_cal = TRUE;
		WL_OLPC(("%s: exit: open loop phy CAL done for all chains!\n", __FUNCTION__));
	}
	if (olpc_chan->cores_cal_active == 0) {
		/* execute these for now, coz cal is over */
		wlc_olpc_set_rate_limit(olpc_chan, FALSE);
		wlc_olpc_stf_override_revert(wlc);
	}
}

/* return BCME_OK if all npkts * num_cores get sent out */
static int
wlc_olpc_send_dummy_pkts(wlc_info_t *wlc, struct wlc_olpc_eng_chan_t* chan, uint8 npkts)
{
	int err = BCME_OK;
	void *pkt = NULL;
	uint8 cores, core_idx = 0;
	uint8 pktnum;
	uint ac = AC_VI;
	wlc_txh_info_t tx_info;
	uint fifo = 0;
	ASSERT(wlc->stf);
	cores = wlc->olpc_info->num_hw_cores;
	if (!chan) {
		WL_ERROR(("wl%d: %s: null channel - not sending\n", wlc->pub->unit, __FUNCTION__));
		return BCME_NOMEM;
	}

	if ((err = wlc_olpc_stf_override(wlc)) != BCME_OK) {
		WL_ERROR(("%s: abort olpc cal; err=%d\n", __FUNCTION__, err));
		return err;
	}

	for (; core_idx < cores; core_idx++) {
		/* if chain is off or calibration done/in progress then skip */
		if ((wlc->stf->txchain & (1 << core_idx)) == 0 ||
			((chan->cores_cal | chan->cores_cal_active) & (1 << core_idx)) != 0) {
			/* skip this one - already calibrated/calibrating or txchain not on */
			WL_OLPC(("%s: skip core %d for calibrating. txchain=%x\n",
				__FUNCTION__, core_idx, wlc->stf->txchain));
			continue;
		}

		for (pktnum = 0; pktnum < npkts; pktnum++) {
			WL_OLPC_DBG(("%s: getting test frame\n", __FUNCTION__));

			pkt = wlc_olpc_get_pkt(wlc, ac, &fifo);
			if (pkt == NULL) {
				WL_ERROR(("wl%d: %s: null pkt - not sending\n", wlc->pub->unit,
					__FUNCTION__));
				err = BCME_NOMEM;
				break;
			}
			/* modify tx headers, make sure it is no ack and on the right antenna */
			WL_OLPC_DBG(("%s: modify pkt\n", __FUNCTION__));
			wlc_olpc_modify_pkt(wlc, pkt, core_idx);
			WL_OLPC_DBG(("%s: send pkt\n", __FUNCTION__));

			/* avoid get_txh_info if can reuse */
			if (pktnum == 0) {
				wlc_get_txh_info(wlc, pkt, &tx_info);
			} else {
				int tsoHdrSize;
				d11actxh_t* vhtHdr = NULL;
				tsoHdrSize = wlc_pkt_get_vht_hdr(wlc, pkt, &vhtHdr);
				tx_info.tsoHdrSize = tsoHdrSize;
				tx_info.tsoHdrPtr = (void*)((tsoHdrSize != 0) ?
				PKTDATA(wlc->osh, pkt) : NULL);
				tx_info.hdrPtr = (wlc_txd_t *)(PKTDATA(wlc->osh, pkt) + tsoHdrSize);
				tx_info.hdrSize = D11AC_TXH_LEN;
				tx_info.d11HdrPtr = ((uint8 *)tx_info.hdrPtr) + D11AC_TXH_LEN;
				tx_info.TxFrameID = vhtHdr->PktInfo.TxFrameID;
				tx_info.MacTxControlLow = vhtHdr->PktInfo.MacTxControlLow;
				tx_info.MacTxControlHigh = vhtHdr->PktInfo.MacTxControlHigh;
				tx_info.plcpPtr = (vhtHdr->RateInfo[0].plcp);
			}
			chan->pkts_sent[core_idx]++;
			WL_OLPC_DBG(("olpc fifo=%d prio=%d\n", fifo, PKTPRIO(pkt)));
			wlc_txfifo(wlc, fifo, pkt, &tx_info, TRUE, 1);
		}
		/* successful here, so modify cal_active variable */
		chan->cores_cal_active |= (1 << core_idx);
	}
	if (err != BCME_OK) {
		WL_ERROR(("wl%d: %s: err - cal not done\n",
			wlc->pub->unit, __FUNCTION__));
		if (pkt) {
			PKTFREE(wlc->osh, pkt, TRUE);
		}
		chan->limit_rate = !(chan->past_cal);
	}
	return err;
}

static int
wlc_olpc_doiovar(void *context, const bcm_iovar_t *vi, uint32 actionid, const char *name,
	void *p, uint plen, void *a, int alen, int vsize, struct wlc_if *wlcif)
{
	/* todo handle iovars */
	WL_ERROR(("TODO\n"));

	return BCME_OK;
}

/* module attach */
wlc_olpc_eng_info_t* wlc_olpc_eng_attach(wlc_info_t *wlc)
{
	wlc_olpc_eng_info_t *olpc_info = NULL;
	WL_OLPC_DBG(("%s\n", __FUNCTION__));
	if (!wlc) {
		WL_ERROR(("%s - null wlc\n", __FUNCTION__));
		goto fail;
	}
	if ((olpc_info = (wlc_olpc_eng_info_t *)MALLOC(wlc->osh, sizeof(wlc_olpc_eng_info_t)))
		== NULL) {
		WL_ERROR(("wl%d: %s: out of mem, malloced %d bytes\n",
		          wlc->pub->unit, __FUNCTION__, MALLOCED(wlc->osh)));
		goto fail;
	}
	bzero(olpc_info, sizeof(wlc_olpc_eng_info_t));
	olpc_info->wlc = wlc;
	olpc_info->chan_list = NULL;
	olpc_info->npkts = WL_OLPC_DEF_NPKTS;
	olpc_info->last_chan_olpc = FALSE;
	olpc_info->up = FALSE;
	olpc_info->last_chan_olpc_state = FALSE;
	olpc_info->last_chan_chk = WLC_OLPC_INVALID_CHAN;
	olpc_info->next_ant = 0;
	/* register module up/down, watchdog, and iovar callbacks */
	if (wlc_module_register(wlc->pub, olpc_iovars, "olpc", olpc_info, wlc_olpc_doiovar,
	                        NULL, NULL, wlc_olpc_eng_down)) {
		WL_ERROR(("wl%d: %s: wlc_module_register() failed\n",
		          wlc->pub->unit, __FUNCTION__));
		goto fail;
	}
	WL_OLPC_DBG(("%s - end\n", __FUNCTION__));

	return olpc_info;
fail:
	wlc_olpc_eng_detach(olpc_info);
	return NULL;
}

/* go through and free all chan info */
static void
wlc_olpc_free_chans(struct wlc_olpc_eng_info_t *olpc_info)
{
	struct wlc_olpc_eng_chan_t* cur_chan = olpc_info->chan_list;
	wlc_info_t *wlc = olpc_info->wlc;

	while (cur_chan) {
		cur_chan = cur_chan->next;
		MFREE(wlc->osh, olpc_info->chan_list, sizeof(struct wlc_olpc_eng_chan_t));
		olpc_info->chan_list = cur_chan;
	}
}

/* module detach, up, down */
void wlc_olpc_eng_detach(struct wlc_olpc_eng_info_t *olpc_info)
{
	wlc_info_t *wlc;

	if (olpc_info == NULL) {
		return;
	}
	wlc = olpc_info->wlc;
	wlc_olpc_free_chans(olpc_info);
	wlc_module_unregister(wlc->pub, "olpc", olpc_info);

	MFREE(wlc->osh, olpc_info, sizeof(struct wlc_olpc_eng_info_t));
}

int wlc_olpc_eng_up(void *hdl)
{
	struct wlc_olpc_eng_info_t *olpc_info;
	olpc_info = (struct wlc_olpc_eng_info_t *)hdl;
	if (olpc_info->up) {
		return BCME_OK;
	}
	olpc_info->num_hw_cores = (uint8)WLC_BITSCNT(olpc_info->wlc->stf->hw_txchain);

	olpc_info->up = TRUE;
	wlc_olpc_eng_hdl_chan_update(olpc_info->wlc);

	return BCME_OK;
}

int wlc_olpc_eng_down(void *hdl)
{
	struct wlc_olpc_eng_info_t *olpc_info;
	olpc_info = (struct wlc_olpc_eng_info_t *)hdl;
	if (!olpc_info->up) {
		return BCME_OK;
	}
	olpc_info->up = FALSE;
	olpc_info->last_chan_olpc_state = FALSE;
	olpc_info->last_chan_chk = WLC_OLPC_INVALID_CHAN;
	olpc_info->last_txchain_chk = WLC_OLPC_INVALID_TXCHAIN;

	olpc_info->restore_perrate_stf_state = FALSE;
	olpc_info->cur_cspec = WLC_OLPC_INVALID_CHAN;

	/* clear cal info */
	wlc_olpc_free_chans(olpc_info);
	return BCME_OK;
}

/* return antenna # to use next */
uint8
wlc_olpc_get_next_antenna_mask(struct wlc_olpc_eng_info_t *olpc, ratespec_t rspec)
{
	uint8 ant;
	uint8 txchain_avail = wlc_stf_get_core_mask(olpc->wlc, rspec);
	ASSERT(txchain_avail);
	do {
		olpc->next_ant++;
		olpc->next_ant %= olpc->num_hw_cores;
		ant = (1 << olpc->next_ant);
	} while (!(txchain_avail & ant));
	return ant;
}
#endif /* WLOLPC */
