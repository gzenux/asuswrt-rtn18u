/*
 * bsd deamon (Linux)
 *
 * Copyright (C) 2014, Broadcom Corporation
 * All Rights Reserved.
 * 
 * This is UNPUBLISHED PROPRIETARY SOURCE CODE of Broadcom Corporation;
 * the contents of this file may not be disclosed to third parties, copied
 * or duplicated in any form, in whole or in part, without the prior
 * written permission of Broadcom Corporation.
 *
 * $Id: bsd.c $
 */

#include "bsd.h"

bsd_policy_t predefined_policy[] = {
/* idle_rate rssi wprio wrssi wphy_rate wtx_failures wtx_rate wrx_rate */
/* 0: low rssi rssi BSD_POLICY_LOW_RSSI */
{0,	0,	0,	1,	0,	0,	0,	0},
/* 1: high rssi rssi BSD_POLICY_HIGH_RSSI */
{0,	0,	0,	-1,	0,	0,	0,	0},
/* 2: low phyrate BSD_POLICY_LOW_PHYRATE */
{0,	0,	0,	0,	1,	0,	0,	0},
/* 3: high phyrate rssi BSD_POLICY_HIGH_PHYRATE */
{0,	-75,	0,	0,	-1,	0,	0,	0},
/* 4: tx_failures */
{0,	0,	0,	0,	0,	1,	0,	0},
/* 5: tx/rx rate */
{0,	0,	0,	0,	0,	0,	1,	1},
/* End */
{0,	0,	0,	0,	0,	0,	0}
};

typedef bsd_sta_info_t * (*bsd_algo_t)(bsd_info_t *info);

static bsd_sta_info_t *bsd_default_algo(bsd_info_t *info);

bsd_algo_t predefined_algo[] = {
	bsd_default_algo,
	NULL
};

typedef void (*bsd_scheme_t)(bsd_info_t *info);

static void bsd_steer_scheme_5g(bsd_info_t *info);
static void bsd_steer_scheme_balance(bsd_info_t *info);

bsd_scheme_t predefined_scheme[] = {
	bsd_steer_scheme_5g,
	bsd_steer_scheme_balance,
	NULL
};

#define BSD_MAX_POLICY (sizeof(predefined_policy)/sizeof(bsd_policy_t) - 1)
#define BSD_MAX_ALGO (sizeof(predefined_algo)/sizeof(bsd_algo_t) - 1)
#define BSD_MAX_SCHEME (sizeof(predefined_scheme)/sizeof(bsd_scheme_t) - 1)

char ioctl_buf[BSD_IOCTL_MAXLEN];
char ret_buf[BSD_IOCTL_MAXLEN];
char cmd_buf[BSD_IOCTL_MAXLEN];
char maclist_buf[BSD_IOCTL_MAXLEN];

static int bsd_aclist_steerable(bsd_bssinfo_t *bssinfo, struct ether_addr *addr);

int bsd_get_max_policy(bsd_info_t *info)
{
	UNUSED_PARAMETER(info);
	return BSD_MAX_POLICY;
}

int bsd_get_max_algo(bsd_info_t *info)
{
	UNUSED_PARAMETER(info);
	return BSD_MAX_ALGO;
}

int bsd_get_max_scheme(bsd_info_t *info)
{
	UNUSED_PARAMETER(info);
	return BSD_MAX_SCHEME;
}

bsd_policy_t *bsd_get_policy_params(bsd_bssinfo_t *bssinfo)
{
	return &predefined_policy[bssinfo->policy];
}

/* Default victim STA seelction algo */
static bsd_sta_info_t *bsd_default_algo(bsd_info_t *info)
{
	bsd_intf_info_t *intf_info;
	bsd_bssinfo_t *bssinfo, *steer_bssinfo;
	int idx, bssidx;
	bsd_sta_info_t *sta = NULL, *victim = NULL;
	uint score = (uint)(-1);
	int score_idx = -1, score_bssidx = -1;
	time_t now = time(NULL);
	bool idle = FALSE;

	BSD_ENTER();

	UNUSED_PARAMETER(idle);

	if(info->over == BSD_CHAN_BUSY) { /* 5G over */
		score_idx = info->ifidx;
		score_bssidx = info->bssidx;

		for (idx = 0; idx < BSD_MAX_INTF; idx++) {
			BSD_STEER("idx[%d]\n", idx);
			intf_info = &(info->intf_info[idx]);
			for (bssidx = 0; bssidx < WL_MAXBSSCFG; bssidx++) {
				bssinfo = &(intf_info->bsd_bssinfo[bssidx]);
				if (!(bssinfo->valid))
					continue;

				idle |= bssinfo->video_idle;
				BSD_STEER("ifnames[%s] [%d[%d] idle=%d\n",
					bssinfo->ifnames, idx, bssidx, idle);
			}
		}
	}
	else { /* 5G under */
		intf_info = &(info->intf_info[info->ifidx]);
		bssinfo = &(intf_info->bsd_bssinfo[info->bssidx]);
		bssinfo = bssinfo->steer_bssinfo;
		score_idx = bssinfo->intf_info->idx;
		score_bssidx = bssinfo->idx;
	}

	BSD_STEER("over=%d score_idx=%d score_bssidx=%d\n", info->over, score_idx, score_bssidx);

	for (idx = 0; idx < BSD_MAX_INTF; idx++) {
		BSD_INFO("idx[%d]\n", idx);
		intf_info = &(info->intf_info[idx]);
		for (bssidx = 0; bssidx < WL_MAXBSSCFG; bssidx++) {
			bssinfo = &(intf_info->bsd_bssinfo[bssidx]);
			if (!(bssinfo->valid))
				continue;

			if ((idx != score_idx) || (bssidx != score_bssidx)) {
				BSD_INFO("skip bssinfo[%s] [%d]{%d]\n",
					bssinfo->ifnames, idx, bssidx);
				continue;
			}

			BSD_STEER("intf:%d bssidx[%d] ifname:%s\n", idx, bssidx, bssinfo->ifnames);

			/* assoclist */
			sta = bssinfo->assoclist;
			BSD_INFO("sta[%p]\n", sta);
			while (sta) {
				/* skipped single band STA */
				if (!bsd_is_sta_dualband(info, &sta->addr)) {
					BSD_STEER("sta[%p]:"MACF" is not dualand. Skipped.\n",
						sta, ETHERP_TO_MACF(&sta->addr));
					goto next;
				}

				/* skipped non-staeerable STA */
				if (sta->steerflag & BSD_BSSCFG_NOTSTEER) {
					BSD_STEER("sta[%p]:"MACF" is not steerable. Skipped.\n",
						sta, ETHERP_TO_MACF(&sta->addr));
					goto next;
				}

				/* Skiiped macmode mismatch STA */
				steer_bssinfo = bssinfo->steer_bssinfo;
				if (bsd_aclist_steerable(steer_bssinfo, &sta->addr) == BSD_FAIL) {
					BSD_STEER("sta[%p]:"MACF" not steerable match "
						"w/ static maclist. Skipped.\n",
						sta, ETHERP_TO_MACF(&sta->addr));
					goto next;
				}

				/* Skipped idle STA */
				if (bssinfo->policy_params.idle_rate != 0) {
					uint32 rate = sta->tx_bps + sta->rx_bps;
					if (rate <= bssinfo->policy_params.idle_rate) {
						BSD_STEER("Skip idle STA:"MACF" idle_rate[%d]"
							"tx+rx_rate[%d: %d+%d]\n",
							ETHERP_TO_MACF(&sta->addr),
							bssinfo->policy_params.idle_rate,
							sta->tx_bps+sta->rx_bps,
							sta->tx_bps, sta->rx_bps);
						goto next;
					}
				}

				/* Skipped low rssi STA */
				if (bssinfo->policy_params.rssi != 0) {
					int32 est_rssi = sta->rssi;
					est_rssi += DIV_QUO(steer_bssinfo->txpwr.txpwr[0], 4);
					est_rssi -= DIV_QUO(bssinfo->txpwr.txpwr[0], 4);

					if (est_rssi < bssinfo->policy_params.rssi) {
						BSD_STEER("Skip low rssi STA:"MACF" sta_rssi"
							"[%d (%d-(%d-%d))] <  thld[%d]\n",
							ETHERP_TO_MACF(&sta->addr),
							est_rssi, sta->rssi,
							DIV_QUO(bssinfo->txpwr.txpwr[0], 4),
							DIV_QUO(steer_bssinfo->txpwr.txpwr[0], 4),
							bssinfo->policy_params.rssi);
						goto next;
					}
				}

				sta->score = sta->prio * bssinfo->policy_params.wprio +
					sta->rssi * bssinfo->policy_params.wrssi+
					sta->phyrate * bssinfo->policy_params.wphy_rate +
					sta->tx_failures * bssinfo->policy_params.wtx_failures +
					sta->tx_rate * bssinfo->policy_params.wtx_rate +
					sta->rx_rate * bssinfo->policy_params.wrx_rate;

				BSD_STEER("sta[%p]:"MACF"Score[%d] prio[%d], rssi[%d] "
					"phyrate[%d] tx_failures[%d] tx_rate[%d] rx_rate[%d]\n",
					sta, ETHERP_TO_MACF(&sta->addr), sta->score,
					sta->prio, sta->rssi, sta->phyrate,
					sta->tx_failures, sta->tx_bps, sta->rx_bps);

				if (sta->score < score) {
					/* timestamp check to avoid flip'n'flop ? */
					BSD_STEER("found victim:"MACF" now[%lu]- timestamp[%lu]"
						"= %lu timeout[%d] \n",
						ETHERP_TO_MACF(&sta->addr), now,
						sta->timestamp, now - sta->timestamp,
						info->steer_timeout);

					if (now - sta->timestamp > info->steer_timeout)	{
						BSD_STEER("found victim:"MACF"\n",
							ETHERP_TO_MACF(&sta->addr));
						victim = sta;
						score = sta->score;
					}
				}
next:
				BSD_INFO("next[%p]\n", sta->next);
				sta = sta->next;
			}
		}
	}

	if (victim) {
		BSD_STEER("Victim sta[%p]:"MACF"Score[%d]\n",
			victim, ETHERP_TO_MACF(&victim->addr), victim->score);
	}

	if (idle) {
		BSD_STEER("idle=%d no victim\n", idle);
		return NULL;
	}


	BSD_EXIT();
	return victim;
}


/* Default victim STA seelction algo */
void bsd_sort_sta(bsd_info_t *info)
{
	bsd_intf_info_t *intf_info;
	bsd_bssinfo_t *bssinfo;
	int idx, bssidx;
	bsd_sta_info_t *sta = NULL;
	bsd_sta_info_t *scorelist = NULL, *snext, *sprev;
	bsd_sta_info_t *dlist;

	BSD_ENTER();

	for (idx = 0; idx < BSD_MAX_INTF; idx++) {
		intf_info = &(info->intf_info[idx]);
		BSD_STEER("idx[%d]\n", idx);
		for (bssidx = 0; bssidx < WL_MAXBSSCFG; bssidx++) {
			bssinfo = &(intf_info->bsd_bssinfo[bssidx]);
			if (!(bssinfo->valid))
				continue;
			scorelist = NULL;

			BSD_STEER("bssidx=%d\n", bssidx);

			/* assoclist */
			sta = bssinfo->assoclist;

			while (sta) {
				BSD_STEER("sta[%p]\n", sta);
				if (sta->steerflag & BSD_BSSCFG_NOTSTEER) {
					sta = sta->next;
					continue;
				}

				if (scorelist == NULL) {
					BSD_STEER("first: sta[%p]\n", sta);
					scorelist = sta;
					sta->snext = NULL;
					sta->sprev = NULL;
					sta = sta->next;
					continue;
				}

				snext = scorelist;
				while (snext) {
					BSD_STEER("sta->score[%d] snext[%p]->score[%d]"
						"snext->snext[%p]\n",
						sta->score, snext, snext->score, snext->snext);

					if (sta->score < snext->score) {
						BSD_STEER("Mid: snext[%p] sta[%p]\n", snext, sta);

						sprev = snext->sprev;

						sta->snext = snext;
						sta->sprev = sprev;
						snext->sprev = sta;

						if (sprev)
							sprev->snext = sta;
						else
							scorelist = sta;
						break;
					}
					if (snext->snext == NULL) {
						BSD_STEER("head: snext[%p] sta[%p]\n", snext, sta);
						snext->snext = sta;
						sta->sprev = snext;
						sta->snext = NULL;
						break;
					}
					snext = snext->snext;

				}

				sta = sta->next;

				/* Dump list */
				dlist = scorelist;
				BSD_STEER("dlist[%p]:\n", dlist);
				while (dlist) {
					BSD_STEER(MACF"\n", ETHER_TO_MACF(dlist->addr));
					dlist = dlist->snext;
				}
				BSD_STEER("-----------------------\n");
			}
			bssinfo->scorelist = scorelist;
		}
	}

	BSD_EXIT();
	return;
}

/* select victim STA */
static bsd_sta_info_t *bsd_select_sta(bsd_info_t *info)
{
	bsd_sta_info_t *sta = NULL;
	bsd_bssinfo_t *bssinfo;
	bsd_intf_info_t *intf_info;

	BSD_ENTER();

	if (info->over) {
		intf_info = &(info->intf_info[info->ifidx]);
		bssinfo = &(intf_info->bsd_bssinfo[info->bssidx]);
		if (info->over == BSD_CHAN_BUSY) { /* 5G over */
			BSD_INFO("Steer from %s: [%d][%d]\n",
				bssinfo->ifnames, info->ifidx, info->bssidx);
		}
		else { 	/* 5G under */
			bssinfo = bssinfo->steer_bssinfo;
			BSD_INFO("Steer from %s: [%d][%d]\n", bssinfo->ifnames,
				(bssinfo->intf_info)->idx, bssinfo->idx);
		}

		sta = (predefined_algo[bssinfo->algo])(info);
		/* 	bsd_sort_sta(info); */
	}

	BSD_EXIT();
	return sta;
}

/* add addr to maclist */
void bsd_addto_maclist(bsd_bssinfo_t *bssinfo, struct ether_addr *addr)
{
	bsd_maclist_t *ptr;

	BSD_ENTER();
	BSD_STEER("Add mac:"MACF" to %s: macmode: %d\n",
		ETHERP_TO_MACF(addr), bssinfo->ifnames, bssinfo->macmode);

	/* adding to maclist */
	ptr = bssinfo->maclist;
	while (ptr) {
		BSD_STEER("Sta:"MACF"\n", ETHER_TO_MACF(ptr->addr));
		if (eacmp(&(ptr->addr), addr) == 0) {
			break;
		}
		ptr = ptr->next;
	}

	if (!ptr) {
		/* add sta to maclist */
		ptr = malloc(sizeof(bsd_maclist_t));
		if (!ptr) {
			BSD_STEER("Err: Exiting %s@%d malloc failure\n", __FUNCTION__, __LINE__);
			return;
		}
		memset(ptr, 0, sizeof(bsd_maclist_t));
		memcpy(&ptr->addr, addr, sizeof(struct ether_addr));
		ptr->next = bssinfo->maclist;
		bssinfo->maclist = ptr;
	}

	ptr->timestamp = time(NULL);

	bssinfo->macmode = WLC_MACMODE_DENY;

	if (BSD_DUMP_ENAB) {
		BSD_PRINT("prting bssinfo macmode:%d Maclist: \n", bssinfo->macmode);
		ptr = bssinfo->maclist;
		while (ptr) {
			BSD_PRINT("Sta:"MACF"\n", ETHER_TO_MACF(ptr->addr));
			ptr = ptr->next;
		}
	}

	BSD_EXIT();
	return;
}

/* remove addr from maclist */
void bsd_remove_maclist(bsd_bssinfo_t *bssinfo, struct ether_addr *addr)
{
	bsd_maclist_t *ptr, *prev;

	BSD_ENTER();

	/* removing from steer-ed intf maclist */
	BSD_STEER("Remove mac:"MACF"from %s: macmode: %d\n",
		ETHERP_TO_MACF(addr), bssinfo->ifnames, bssinfo->macmode);

	ptr = bssinfo->maclist;
	if (!ptr) {
		BSD_STEER("%s Steer-ed maclist empty. Exiting....\n", __FUNCTION__);
		return;
	}

	if (eacmp(&(ptr->addr), addr) == 0) {
		BSD_STEER("foudn/free maclist: "MACF"\n", ETHER_TO_MACF(ptr->addr));
		bssinfo->maclist = ptr->next;
		free(ptr);
	} else {
		prev = ptr;
		ptr = ptr->next;

		while (ptr) {
			BSD_STEER("checking maclist"MACF"\n", ETHER_TO_MACF(ptr->addr));
			if (eacmp(&(ptr->addr), addr) == 0) {
				BSD_STEER("found/free maclist: "MACF"\n", ETHER_TO_MACF(ptr->addr));
				prev->next = ptr->next;
				free(ptr);
				break;
			}
			prev = ptr;
			ptr = ptr->next;
		}
	}

	BSD_STEER("prting steer-ed bssinfo macmode:%d Maclist: \n", bssinfo->macmode);
	ptr = bssinfo->maclist;
	while (ptr) {
		BSD_STEER("Sta:"MACF"\n", ETHER_TO_MACF(ptr->addr));
		ptr = ptr->next;
	}

	BSD_EXIT();
	return;
}

/* update tstamp */
void bsd_stamp_maclist(bsd_info_t *info, bsd_bssinfo_t *bssinfo, struct ether_addr *addr)
{
	bsd_maclist_t *ptr;

	BSD_ENTER();

	ptr = bssinfo->maclist;
	if (!ptr) {
		BSD_STEER("%s [%s] maclist empty. Exiting....\n", __FUNCTION__, bssinfo->ifnames);
		return;
	}

	while (ptr) {
		BSD_STEER("checking maclist"MACF"\n", ETHER_TO_MACF(ptr->addr));
		if (eacmp(&(ptr->addr), addr) == 0) {
			BSD_INFO("found maclist: "MACF"\n", ETHER_TO_MACF(ptr->addr));
			if (info->maclist_timeout >= 5)
				ptr->timestamp = info->maclist_timeout - 5;
			break;
		}
		ptr = ptr->next;
	}

	BSD_EXIT();
	return;
}

/* find maclist */
bsd_maclist_t *bsd_maclist_by_addr(bsd_bssinfo_t *bssinfo, struct ether_addr *addr)
{
	bsd_maclist_t *ptr;

	BSD_ENTER();

	ptr = bssinfo->maclist;
	if (!ptr) {
		BSD_STEER("%s [%s] maclist empty. Exiting....\n", __FUNCTION__, bssinfo->ifnames);
		return NULL;
	}

	while (ptr) {
		BSD_STEER("checking maclist"MACF"\n", ETHER_TO_MACF(ptr->addr));
		if (eacmp(&(ptr->addr), addr) == 0) {
			BSD_INFO("found maclist: "MACF"\n", ETHER_TO_MACF(ptr->addr));
			break;
		}
		ptr = ptr->next;
	}

	BSD_EXIT();
	return ptr;
}

/* find maclist */
static int bsd_static_maclist_by_addr(bsd_bssinfo_t *bssinfo, struct ether_addr *addr)
{
	struct maclist *static_maclist = bssinfo->static_maclist;
	int cnt;
	int ret = BSD_FAIL;

	BSD_ENTER();

	BSD_STEER("Check static_maclist with "MACF"\n", ETHERP_TO_MACF(addr));

	if (static_maclist) {
		BSD_STEER("static_mac: macmode[%d] cnt[%d]\n",
			bssinfo->static_macmode, static_maclist->count);
		for (cnt = 0; cnt < static_maclist->count; cnt++) {
			BSD_INFO("cnt[%d] mac:"MACF"\n", cnt,
				ETHER_TO_MACF(static_maclist->ea[cnt]));
			if (eacmp(&(static_maclist->ea[cnt]), addr) == 0) {
				BSD_INFO("found mac: "MACF"\n", ETHERP_TO_MACF(addr));
				ret = BSD_OK;
				break;
			}
		}
	}

	BSD_EXIT();
	return ret;
}

/* set iovar maclist */
void bsd_set_maclist(bsd_bssinfo_t *bssinfo)
{
	int ret, val;
	struct ether_addr *ea;
	struct maclist *maclist = (struct maclist *)maclist_buf;
	bsd_maclist_t *ptr;

	struct maclist *static_maclist = bssinfo->static_maclist;
	int static_macmode = bssinfo->static_macmode;
	int cnt;

	BSD_ENTER();

	BSD_STEER("Iovar maclist to %s, static_macmode:%d\n",
		bssinfo->ifnames, static_macmode);

	if (static_macmode == WLC_MACMODE_DENY || static_macmode == WLC_MACMODE_DISABLED) {
		val = WLC_MACMODE_DENY;
	}
	else {
		val = WLC_MACMODE_ALLOW;
	}

	BSD_RPC("---RPC name:%s cmd: %d(WLC_SET_MACMODE) to mode:%d\n",
		bssinfo->ifnames, WLC_SET_MACMODE, val);
	ret = bsd_wl_ioctl(bssinfo, WLC_SET_MACMODE, &val, sizeof(val));
	if (ret < 0) {
		BSD_ERROR("Err: ifnams[%s] set macmode\n", bssinfo->ifnames);
		goto done;
	}

	memset(maclist_buf, 0, sizeof(maclist_buf));

	if (static_macmode == WLC_MACMODE_DENY || static_macmode == WLC_MACMODE_DISABLED) {
		if (static_maclist && static_macmode == WLC_MACMODE_DENY) {
			BSD_STEER("Deny mode: Adding static maclist\n");
			maclist->count = static_maclist->count;
			memcpy(maclist_buf, static_maclist,
				sizeof(uint) + ETHER_ADDR_LEN * (maclist->count));
		}

		ptr = bssinfo->maclist;
		ea = &(maclist->ea[maclist->count]);
		while (ptr) {
			memcpy(ea, &(ptr->addr), sizeof(struct ether_addr));
			maclist->count++;
			BSD_STEER("Deny mode: cnt[%d] mac:"MACF"\n",
				maclist->count, ETHERP_TO_MACF(ea));
			ea++;
			ptr = ptr->next;
		}
	}
	else {
		ea = &(maclist->ea[0]);

		if (!static_maclist) {
			BSD_ERROR("SERR: %s macmode:%d static_list is NULL\n",
				bssinfo->ifnames, static_macmode);
			goto done;
		}

		for (cnt = 0; cnt < static_maclist->count; cnt++) {
			BSD_STEER("Allow mode: static mac[%d] addr:"MACF"\n", cnt,
				ETHER_TO_MACF(static_maclist->ea[cnt]));
			if (bsd_maclist_by_addr(bssinfo, &(static_maclist->ea[cnt])) == NULL) {
				memcpy(ea, &(static_maclist->ea[cnt]), sizeof(struct ether_addr));
				maclist->count++;
				BSD_STEER("Adding to Allow list: cnt[%d] addr:"MACF"\n",
					maclist->count, ETHERP_TO_MACF(ea));
				ea++;
			}
		}
	}

	BSD_STEER("maclist count[%d] \n", maclist->count);
	for (cnt = 0; cnt < maclist->count; cnt++) {
		BSD_STEER("maclist: "MACF"\n",
			ETHER_TO_MACF(maclist->ea[cnt]));
	}

	BSD_RPC("---RPC name:%s cmd: %d(WLC_SET_MACLIST)\n", bssinfo->ifnames, WLC_SET_MACLIST);
	ret = bsd_wl_ioctl(bssinfo, WLC_SET_MACLIST, maclist,
		sizeof(maclist_buf) - BSD_RPC_HEADER_LEN);
	if (ret < 0) {
		BSD_ERROR("Err: [%s] set maclist...\n", bssinfo->ifnames);
	}

done:
	BSD_EXIT();
	return;
}

/* check if STA is deny in steerable intf */
static int bsd_aclist_steerable(bsd_bssinfo_t *bssinfo, struct ether_addr *addr)
{
	int ret = BSD_OK;

	BSD_ENTER();

	switch (bssinfo->static_macmode) {
		case WLC_MACMODE_DENY:
			if (bsd_static_maclist_by_addr(bssinfo, addr) == BSD_OK) {
				BSD_STEER("Deny: skiiped STA:"MACF"\n", ETHERP_TO_MACF(addr));
				ret = BSD_FAIL;
			}
			break;
		case WLC_MACMODE_ALLOW:
			if (bsd_static_maclist_by_addr(bssinfo, addr) != BSD_OK) {
				BSD_STEER("Allow: skiiped STA:"MACF"\n", ETHERP_TO_MACF(addr));
				ret = BSD_FAIL;
			}
			break;
		default:
			break;
	}

	BSD_EXIT();
	return ret;
}

static void bsd_send_transreq(bsd_sta_info_t *sta)
{
	bsd_bssinfo_t *bssinfo = sta->bssinfo;
	bsd_bssinfo_t *steer_bssinfo = bssinfo->steer_bssinfo;
	int ret;
	char *param;
	int buflen;

	dot11_bsstrans_req_t *transreq;
	dot11_neighbor_rep_ie_t *nbr_ie;

	wl_af_params_t *af_params;
	wl_action_frame_t *action_frame;


	BSD_ENTER();

	memset(ioctl_buf, 0, sizeof(ioctl_buf));
	strcpy(ioctl_buf, "actframe");
	buflen = strlen(ioctl_buf) + 1;
	param = (char *)(ioctl_buf + buflen);

	af_params = (wl_af_params_t *)param;
	action_frame = &af_params->action_frame;

	af_params->channel = 0;
	af_params->dwell_time = -1;

	memcpy(&action_frame->da, (char *)&(sta->addr), ETHER_ADDR_LEN);
	action_frame->packetId = (uint32)(uintptr)action_frame;
	action_frame->len = DOT11_NEIGHBOR_REP_IE_FIXED_LEN + TLV_HDR_LEN + DOT11_BSSTRANS_REQ_LEN;

	transreq = (dot11_bsstrans_req_t *)&action_frame->data[0];
	transreq->category = DOT11_ACTION_CAT_WNM;
	transreq->action = DOT11_WNM_ACTION_BSSTRANS_REQ;
	transreq->token = 0xa5;
	transreq->reqmode = DOT11_BSSTRANS_REQMODE_PREF_LIST_INCL;
	transreq->reqmode |= DOT11_BSSTRANS_REQMODE_DISASSOC_IMMINENT;
	transreq->disassoc_tmr = 0x0000;
	transreq->validity_intrvl = 0x00;

	nbr_ie = (dot11_neighbor_rep_ie_t *)&transreq->data[0];
	nbr_ie->id = DOT11_MNG_NEIGHBOR_REP_ID;
	nbr_ie->len = DOT11_NEIGHBOR_REP_IE_FIXED_LEN;
	memcpy(&nbr_ie->bssid, &steer_bssinfo->bssid, ETHER_ADDR_LEN);
	nbr_ie->bssid_info = 0x00000000;
	nbr_ie->reg = steer_bssinfo->rclass;
	nbr_ie->channel = wf_chspec_ctlchan(steer_bssinfo->chanspec);
	nbr_ie->phytype = 0x00;


	BSD_AT("actframe @%s chanspec:0x%x rclass:0x%x to STA"MACF"\n",
		bssinfo->ifnames, steer_bssinfo->chanspec, steer_bssinfo->rclass,
		ETHER_TO_MACF(steer_bssinfo->bssid));
	BSD_RPC("RPC name:%s cmd: %d(WLC_SET_VAR: actframe)\n",
		bssinfo->ifnames, WLC_SET_VAR);
	bsd_rpc_dump(ioctl_buf, 64, BSD_STEER_ENAB);

	if (!nvram_match("bsd_actframe", "0")) {
		BSD_STEER("*** Sending act Frame\n");
		ret = bsd_wl_ioctl(bssinfo, WLC_SET_VAR,
			ioctl_buf, WL_WIFI_AF_PARAMS_SIZE);

		if (ret < 0) {
			BSD_ERROR("Err: intf:%s actframe\n", bssinfo->ifnames);
		}

		usleep(1000*100);
	}

	BSD_EXIT();
}

/* Steer STA */
void bsd_steer_sta(bsd_info_t *info, bsd_sta_info_t *sta)
{
	bsd_bssinfo_t *bssinfo = sta->bssinfo;
	bsd_intf_info_t *intf_info = bssinfo->intf_info;

	bsd_bssinfo_t *steer_bssinfo;
	int ret;

	steer_bssinfo = bssinfo->steer_bssinfo;

	BSD_ENTER();

	/* adding STA to maclist and set mode to deny */
	/* deauth STA */
	BSD_STEER("Steering sta:"MACF" from %s[%d][%d]["MACF"[ to %s[%d][%d]["MACF"]\n",
		ETHER_TO_MACF(sta->addr), bssinfo->prefix, intf_info->idx, bssinfo->idx,
		ETHER_TO_MACF(bssinfo->bssid),
		bssinfo->steer_prefix, (steer_bssinfo->intf_info)->idx, steer_bssinfo->idx,
		ETHER_TO_MACF(steer_bssinfo->bssid));

	/* adding to maclist */
	bsd_addto_maclist(bssinfo, &(sta->addr));
	bsd_set_maclist(bssinfo);

	/* removing from steer-ed intf maclist */
	bsd_remove_maclist(steer_bssinfo, &(sta->addr));
	bsd_set_maclist(steer_bssinfo);

	bsd_send_transreq(sta);

	/* iovar to deaut and set maclist */
	BSD_RPC("---RPC name:%s cmd: %d(WLC_SCB_DEAUTHENTICATE)\n",
		bssinfo->ifnames, WLC_SCB_DEAUTHENTICATE);
	ret = bsd_wl_ioctl(bssinfo, WLC_SCB_DEAUTHENTICATE, &sta->addr, ETHER_ADDR_LEN);
	if (ret < 0) {
		BSD_ERROR("Err: ifnams[%s] send deauthenticate\n", bssinfo->ifnames);
	}

	BSD_STEER("deauth STA:"MACF" from %s\n", ETHER_TO_MACF(sta->addr), bssinfo->ifnames);

	BSD_EXIT();
	return;
}

/* chan busy detection: may need to be a generic algo */
static bsd_chan_state_t bsd_detect_chan_busy(bsd_info_t *info)
{
	bsd_intf_info_t *intf_info;
	bsd_bssinfo_t *bssinfo;
	uint8 idx, cnt, num;

	bsd_chan_util_info_t *chan_util_info;
	bsd_chanim_stats_t *rec;
	chanim_stats_t *stats;
	int min, max;
	uint8 over, under;

	BSD_CCAENTER();

	intf_info = &(info->intf_info[info->ifidx]);
	bssinfo = &(intf_info->bsd_bssinfo[info->bssidx]);
	chan_util_info = &intf_info->chan_util_info;
	cnt = chan_util_info->cnt;
	min = chan_util_info->chan_busy_min;
	max = chan_util_info->chan_busy_max;

	intf_info->chan_util_info.state = BSD_CHAN_BUSY_UNKNOWN;

	if (!min || !max || !cnt) {
		BSD_CCAEXIT();
		return intf_info->chan_util_info.state;
	}

	idx = MODSUB(chan_util_info->idx, cnt, BSD_CHANIM_STATS_MAX);

	/* detect over/under */
	over = under = 0;
	for (num = 0; num < cnt; num++) {
		rec = &(intf_info->chan_util_info.rec[idx]);
		stats = &rec->stats;
		BSD_CCA("cca idx[%d] idle:%d[v:%d]\n",
			idx, stats->ccastats[CCASTATS_TXOP], rec->valid);
		if (rec->valid && (stats->ccastats[CCASTATS_TXOP] < min))
			over++;

		if (rec->valid && (stats->ccastats[CCASTATS_TXOP] > max))
			under++;

		idx = MODINC(idx, BSD_CHANIM_STATS_MAX);
	}

	BSD_CCA("ifname:%s[remote:%d] over:%d under:%d min:%d max:%d cnt:%d\n",
		bssinfo->ifnames, intf_info->remote, over, under, min, max, cnt);

	if (over >= cnt)
		intf_info->chan_util_info.state = BSD_CHAN_BUSY;

	if (under >= cnt)
		intf_info->chan_util_info.state = BSD_CHAN_IDLE;

/*
	if (over >= cnt || under >= cnt) {
		idx = MODDEC(chan_util_info->idx, BSD_CHANIM_STATS_MAX);
		BSD_CCA("invalid ccs rec[%d] for %d\n", idx, cnt);
		for (num = 0; num < cnt; num++) {
			rec = &(intf_info->chan_util_info.rec[idx]);
			stats = &rec->stats;
			rec->valid = 0;
			BSD_CCA("invalid: rec[%d] idle[%d]\n", idx, stats->chan_idle);
			idx = MODINC(idx, BSD_CHANIM_STATS_MAX);
		}
	}
*/
	BSD_CCA("chan_util state:%d\n", intf_info->chan_util_info.state);

	BSD_CCAEXIT();
	return intf_info->chan_util_info.state;
}


static bool bsd_check_oversub(bsd_info_t *info)
{
	bool ret = FALSE;

	bsd_intf_info_t *intf_info;
	bsd_bssinfo_t *bssinfo;
	int idx, bssidx;
	bsd_sta_info_t *sta = NULL;


	uint8 at_ratio = 0, at_ratio_lowest_phyrate = 0, at_ratio_highest_phyrate = 0;
	uint32 min_phyrate = (uint32) -1, max_phyrate = 0, delta_phyrate = 0;
	uint8	assoc = 0;

	BSD_ATENTER();

	for (idx = 0; idx < BSD_MAX_INTF; idx++) {
		intf_info = &(info->intf_info[idx]);
		BSD_AT("idx=%d, band=%d\n", idx, intf_info->band);

		if (!(intf_info->band & BSD_BAND_5G))
			continue;

		for (bssidx = 0; bssidx < WL_MAXBSSCFG; bssidx++) {
			bssinfo = &(intf_info->bsd_bssinfo[bssidx]);
			if (!(bssinfo->valid))
				continue;

			BSD_AT("bssidx=%d intf:%s\n", bssidx, bssinfo->ifnames);

			sta = bssinfo->assoclist;

			while (sta) {
				BSD_AT("sta[%p]:"MACF" steer_flag=%d at_ratio=%d phyrate=%d\n",
					sta, ETHER_TO_MACF(sta->addr),
					sta->steerflag, sta->at_ratio, sta->phyrate);
				if (sta->steerflag & BSD_BSSCFG_NOTSTEER) {
					at_ratio += sta->at_ratio;
				}
				else {
					assoc++;
					/* calc data STA phyrate and at_ratio */
					if ((sta->phyrate < min_phyrate) &&
						(sta->at_ratio > info->slowest_at_ratio)) {
						min_phyrate = sta->phyrate;
						at_ratio_lowest_phyrate = sta->at_ratio;

						BSD_AT("lowest[phyrate:%d at_ratio:%d]\n",
							min_phyrate, at_ratio_lowest_phyrate);
					}

					if (sta->phyrate > max_phyrate) {
						max_phyrate = sta->phyrate;
						at_ratio_highest_phyrate = sta->at_ratio;

						BSD_AT("highest[phyrate:%d at_ratio:%d]\n",
							max_phyrate, at_ratio_highest_phyrate);
					}
				}

				sta = sta->next;
			}
			BSD_AT("ifnaems:%s Video at_ratio=%d\n", bssinfo->ifnames, at_ratio);
			BSD_AT("lowest[phyrate:%d at_ratio:%d] highest[phyrate:%d"
				"at_ratio:%d]\n", min_phyrate, at_ratio_lowest_phyrate,
				max_phyrate, at_ratio_highest_phyrate);
		}
	}

	/* algo 1: This algo is to check when Video takes most of airtime.
	 * v/(v+d) threshold. video_at_ratio[n] is threshold for n+1 data-stas
	 * n data-sta actively assoc, v/(v+d) > video_at_ratio[n]. steer
	 */
	if (assoc >= BSD_MAX_AT_SCB)
		assoc = BSD_MAX_AT_SCB - 1;

	if (assoc < 1) {
		BSD_AT("No data sta. No steer\n");
		BSD_ATEXIT();
		return FALSE;
	}

	assoc--;

	if (at_ratio > info->video_at_ratio[assoc])
		ret = TRUE;

	/* Algo 2: This algo is to check for all data sta case
	 * for all data-STA, if delta(phyrate) > phyrate_delat
	 * && at_time(lowest phyrate sta) > at_rati: steer
	 * slowest data-sta airtime ratio
	 */
	delta_phyrate = 0;
	if (min_phyrate < max_phyrate) {
		delta_phyrate = max_phyrate - min_phyrate;
		BSD_AT("delta_phyrate[%d\n", delta_phyrate);
	}
	if ((delta_phyrate > info->phyrate_delta) &&
		at_ratio_lowest_phyrate > info->slowest_at_ratio)
		ret = TRUE;

	BSD_AT("ret:%d assoc:%d at_ratio:%d[%d] delta_phyrate:%d[%d] "
		"at_ratio_slowest_phyrate:%d[%d]\n",
		ret, assoc, at_ratio, info->video_at_ratio[assoc],
		delta_phyrate, info->phyrate_delta,
		at_ratio_lowest_phyrate, info->slowest_at_ratio);

	BSD_ATEXIT();
	return ret;
}

/* retrieve chann busy state */
bsd_chan_state_t bsd_get_chan_busy_state(bsd_info_t *info)
{
	bsd_intf_info_t *intf_info;

	BSD_CCAENTER();
	intf_info = &(info->intf_info[info->ifidx]);

	BSD_CCA("state:%d\n", intf_info->chan_util_info.state);

	BSD_CCAEXIT();
	return intf_info->chan_util_info.state;
}


/* Steer scheme: Ony based on 5G channel utilization */
void bsd_steer_scheme_5g(bsd_info_t *info)
{
	bsd_sta_info_t *sta;
	bsd_intf_info_t *intf_info;
	bsd_bssinfo_t *bssinfo;
	char tmp[100], *str, *endptr = NULL;
	bool flag = FALSE;

	BSD_ENTER();

	if (BSD_DUMP_ENAB) {
		BSD_PRINT("\nBefore steer Check: dump dbg info========= \n");
		bsd_dump_info(info);
		BSD_PRINT("\n============================= \n");
	}

	intf_info = &(info->intf_info[info->ifidx]);
	bssinfo = &(intf_info->bsd_bssinfo[info->bssidx]);

	info->over = (uint8)bsd_detect_chan_busy(info);

	str = nvram_get(strcat_r(bssinfo->prefix, "bsd_over", tmp));
	if (str) {
		info->over = (uint8)strtoul(str, &endptr, 0);
		nvram_unset(strcat_r(bssinfo->prefix, "bsd_over", tmp));
	}

	BSD_STEER("======over[0x%x:%d]=========\n",
		info->over, info->over&(~(BSD_CHAN_STEER_MASK)));

	flag = bsd_check_oversub(info);

	BSD_STEER("bsd_check_oversub return %d\n", flag);
	BSD_STEER("bsd mode:%d. actframe:%d \n", info->mode, !nvram_match("bsd_actframe", "0"));

	if (info->mode == BSD_MODE_STEER) {
		if ((info->over == BSD_CHAN_IDLE) ||
			((info->over == BSD_CHAN_BUSY) && flag) ||
			(info->over & BSD_CHAN_STEER_MASK)) {
			info->over &= ~(BSD_CHAN_STEER_MASK);
			sta = bsd_select_sta(info);
			if (sta) {
				bssinfo = sta->bssinfo;
				bsd_steer_sta(info, sta);
				bsd_remove_sta_reason(info, bssinfo->ifnames,
					bssinfo->intf_info->remote,	&(sta->addr),
					BSD_STA_STEERED);
			}
			else
				BSD_STEER("No data STA steer to/from [%s]\n", bssinfo->ifnames);

			/* reset cca stats */
			bsd_reset_chan_busy(info);
		}
	}

	if (BSD_DUMP_ENAB) {
		BSD_PRINT("\nAfter Steer Check: dump dbg info========= \n");
		bsd_dump_info(info);
		BSD_PRINT("\n============================= \n");
	}
	BSD_EXIT();
	return;
}

/* Steer scheme: Balance 5G and 2.4G channel load */
void bsd_steer_scheme_balance(bsd_info_t *info)
{
	BSD_PRINT("***** Not implemented yet\n");
}

void bsd_check_steer(bsd_info_t *info)
{
	(predefined_scheme[info->scheme])(info);
	return;
}
