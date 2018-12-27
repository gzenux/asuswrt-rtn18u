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
 * $Id: bsd_util.c $
 */

#include "bsd.h"

bsd_sta_info_t *bsd_sta_by_addr(bsd_info_t *info, bsd_bssinfo_t *bssinfo,
	struct ether_addr *addr, bool enable);

bsd_sta_histo_t *bsd_set_stahisto_by_addr(bsd_info_t *info,
	bsd_bssinfo_t *bssinfo, struct ether_addr *addr,	bool add, bsd_sta_state_t state);

bsd_maclist_t *bsd_prbsta_by_addr(bsd_info_t *info,
	struct ether_addr *addr, bool enable);

bsd_sta_histo_t *bsd_stahisto_by_addr(bsd_info_t *info, struct ether_addr *addr);


static char *sta_state_str[] = {
	"BSD_STA_INVALID",
	"BSD_STA_ASSOCLIST",
	"BSD_STA_AUTH",
	"BSD_STA_ASSOC",
	"BSD_STA_STEERED",
	"BSD_STA_DEAUTH",
	"BSD_STA_DISASSOC"
};

extern bsd_info_t *bsd_info;

void bsd_rpc_dump(char *ptr, int len, int enab)
{
	int i;
	char ch;

	if (!enab)
		return;

	for (i = 0; i < len; i++) {
		ch = ptr[i];
		BSD_PRINT_PLAIN("%02x[%c] ", ch, isprint((int)(ch & 0xff))? ch : ' ');
		if ((i+1)%16 == 0)
			BSD_PRINT_PLAIN("\n");
	}
	return;
}

/* coverity[ -tainted_data_argument : arg-2 ] */
int bsd_rpc_send(bsd_rpc_pkt_t *rpc_pkt, int len, bsd_rpc_pkt_t *resp)
{
	int	sockfd;
	int ret;
	struct sockaddr_in	servaddr;
	struct timeval tv;
	char tcmd[BSD_IOCTL_MAXLEN];

	BSD_ENTER();
	BSD_INFO("bsd_info=%p\n", bsd_info);
	if (len <= 0)
		return BSD_FAIL;

	BSD_RPC("raw Send buff[sock:%d]: id:%d cmd:%d name:%s len:%d\n",
		bsd_info->rpc_ioctlfd, rpc_pkt->id, rpc_pkt->cmd.cmd,
		rpc_pkt->cmd.name, rpc_pkt->cmd.len);
	bsd_rpc_dump((char *)rpc_pkt, 64, BSD_RPC_ENAB);

	if (bsd_info->rpc_ioctlfd == BSD_DFLT_FD) {
		sockfd = socket(AF_INET, SOCK_STREAM, 0);
		if (sockfd < 0) {
			BSD_ERROR("Socket failes.\n");
			return BSD_FAIL;
		}

		tv.tv_sec = 5;
		tv.tv_usec = 0;
		if (setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO,
			(char *)&tv, sizeof(struct timeval)) < 0) {
			BSD_ERROR("SetSockoption failes.\n");
			close(sockfd);
			return BSD_FAIL;
		}

		bzero(&servaddr, sizeof(servaddr));
		servaddr.sin_family = AF_INET;
		servaddr.sin_port = htons(bsd_info->hport);

		servaddr.sin_addr.s_addr = inet_addr(bsd_info->helper_addr);

		if (connect(sockfd, (const struct sockaddr *)&servaddr, sizeof(servaddr)) < 0) {
			BSD_ERROR("Connect to help failes: Peer: %s[%d]\n",
				bsd_info->helper_addr, bsd_info->hport);
			close(sockfd);
			return BSD_FAIL;
		}
		bsd_info->rpc_ioctlfd = sockfd;
		BSD_RPCD("ioctl new sockfd:%d is created\n", sockfd);
	}

	ret = write(bsd_info->rpc_ioctlfd, (void *)rpc_pkt, len);
	BSD_RPC("Sending:%d sent:%d\n", len, ret);
	if (ret != len) {
		/* tcp conn broken */
		BSD_RPCD("Err: Socket: tcp sock[%d] broken. sending:%d, sent:%d. Close to reopen\n",
			bsd_info->rpc_ioctlfd, len, ret);

		close(bsd_info->rpc_ioctlfd);
		bsd_info->rpc_ioctlfd = BSD_DFLT_FD;
		return BSD_FAIL;
	}

	memset(tcmd, 0, BSD_IOCTL_MAXLEN);
	ret = read(bsd_info->rpc_ioctlfd, tcmd, sizeof(tcmd));

	if (ret <= 0) {
		/* tcp conn broken */
		BSD_RPCD("Err: Socket: sock[%d] broken. Reading ret:%d."
			"Close to reopen, errno:%d\n",
			bsd_info->rpc_ioctlfd, ret, errno);

		close(bsd_info->rpc_ioctlfd);
		bsd_info->rpc_ioctlfd = BSD_DFLT_FD;
		return BSD_FAIL;
	}

	if ((ret > 0) && (ret < BSD_IOCTL_MAXLEN)) {
		int delta = BSD_IOCTL_MAXLEN - ret;
		int pos = ret;
		BSD_ERROR("ERR++: ioctl len=%d, remaining:%d, pos:%d\n", ret, delta, pos);

		while (delta > 0) {
			ret = read(bsd_info->rpc_ioctlfd, (void *)(tcmd + pos), delta);
			if ((ret > 0) && (ret <= delta)) {
				delta = delta - ret;
				pos += ret;
				BSD_RPCD("Assemble:ioctl len=%d, remaining:%d, pos:%d\n",
					ret, delta, pos);
			}
			else {
				BSD_RPCD("Err: Socket: sock[%d] broken. Reading frag ret:%d."
					"Close to reopen, errno:%d\n",
					bsd_info->rpc_ioctlfd, ret, errno);

				close(bsd_info->rpc_ioctlfd);
				bsd_info->rpc_ioctlfd = BSD_DFLT_FD;
				return BSD_FAIL;
			}
		}
	}
	memcpy((char *)resp, tcmd, len);

	BSD_RPC("Raw recv buff[sock:%d] ret=%d: cmd:%d name:%s len:%d\n",
		bsd_info->rpc_ioctlfd, ret, resp->cmd.cmd, resp->cmd.name, resp->cmd.len);

	if ((resp->cmd.cmd != rpc_pkt->cmd.cmd) ||
		(resp->id != rpc_pkt->id) ||
		strcmp(resp->cmd.name, rpc_pkt->cmd.name)) {

		BSD_RPCD("+++++++++ERR: rpc_pkt:id[%d] cmd[%d] name[%s] "
			"resp:id[%d] cmd[%d] name[%s] ",
			rpc_pkt->id, rpc_pkt->cmd.cmd, rpc_pkt->cmd.name,
			resp->id, resp->cmd.cmd, resp->cmd.name);

		BSD_RPCD("Err: Socket: tcp sock[%d] broken. Close to reopen\n",
			bsd_info->rpc_ioctlfd);

		close(bsd_info->rpc_ioctlfd);
		bsd_info->rpc_ioctlfd = BSD_DFLT_FD;

		return BSD_FAIL;
	}

	BSD_EXIT();
	return BSD_OK;
}


char *bsd_nvram_get(bool rpc, const char *name, int *status)
{
	bsd_rpc_pkt_t *pkt = (bsd_rpc_pkt_t *)cmd_buf;
	bsd_rpc_pkt_t *resp = (bsd_rpc_pkt_t *)ret_buf;
	char *ptr;
	char *str = NULL;
	int ret = BSD_OK;
#define BSD_COMM_RETRY_LIMIT	10
	int cnt;

	BSD_ENTER();
	BSD_INFO("rpc[%d] nvram[%s]\n", rpc, name);

	if (!rpc) {
		str = nvram_get(name);
	}
	else {
		/* call rpc nvram */
		cnt = 0;
		BSD_RPC("\n\n\n nvram[%s]\n", name);

		while (cnt++ < BSD_COMM_RETRY_LIMIT) {
			memset(cmd_buf, 0, sizeof(cmd_buf));
			memset(ret_buf, 0, sizeof(ret_buf));

			pkt->id = BSD_RPC_ID_NVRAM;
			pkt->cmd.len = strlen(name) + 4;
			strcpy(pkt->cmd.name, "bsd");
			ptr = (char *)(pkt + 1);
			BSDSTRNCPY(ptr, name, 128);

			ret = bsd_rpc_send(pkt, pkt->cmd.len + sizeof(bsd_rpc_pkt_t), resp);
			bsd_rpc_dump((char *)resp, 64, BSD_RPC_ENAB);
			if (ret == BSD_OK)
				break;

			BSD_RPC("++retry cnt=%d\n", cnt);
		}
		if (ret == BSD_OK) {
			str = (char *)(resp + 1);
			BSD_RPCD("nvram:%s=%s\n", name, str);
		}
	}
	if (status)
		*status = ret;
	BSD_EXIT();
	return str;
}

static INLINE char *bsd_nvram_safe_get(bool rpc, const char *name, int *status)
{
	char *p = bsd_nvram_get(rpc, name, status);
	if (status && *status != BSD_OK)
		return "";
	else
		return p ? p : "";
}

static INLINE int bsd_nvram_match(bool rpc, const char *name, const char *match)
{
	int status;
	const char *value = bsd_nvram_get(rpc, name, &status);
	if (status == BSD_OK)
		return (value && !strcmp(value, match));
	else
		return 0;
}

int bsd_wl_ioctl(bsd_bssinfo_t *bssinfo, int cmd, void *buf, int len)
{
	int ret = -1;
	bsd_rpc_pkt_t *pkt = (bsd_rpc_pkt_t *)cmd_buf;
	char *ptr;
	bsd_rpc_pkt_t *resp = (bsd_rpc_pkt_t *)ret_buf;

	BSD_ENTER();

	BSD_RPC("\n\n\n ifname:%s idx:%d: Remote:%d  cmd:%d len:%d\n",
		bssinfo->ifnames, bssinfo->idx, bssinfo->intf_info->remote, cmd, len);

	if (bssinfo->intf_info->remote) {
		memset(cmd_buf, 0, sizeof(cmd_buf));
		memset(ret_buf, 0, sizeof(ret_buf));
		pkt->id = BSD_RPC_ID_IOCTL;
		pkt->cmd.cmd = cmd;
		BSDSTRNCPY(pkt->cmd.name, bssinfo->ifnames, sizeof(pkt->cmd.name) - 1);
		pkt->cmd.len = len;
		ptr = (char *)(pkt + 1);
		memcpy(ptr, buf, len);
		BSD_RPCD("ioctl: cmd:%d len:%d name:%s\n", cmd, len, bssinfo->ifnames);

		ret = bsd_rpc_send(pkt, pkt->cmd.len + sizeof(bsd_rpc_pkt_t), resp);
		bsd_rpc_dump((char *)resp, 64, BSD_RPC_ENAB);

		if (ret == BSD_OK) {
			ret = resp->cmd.ret;
			BSD_RPCD("ret: %d ioctl: cmd:%d len:%d name:%s\n",
				ret, resp->cmd.cmd, resp->cmd.len, bssinfo->ifnames);
			memcpy(buf, (char *)(resp + 1), len);
		}
	}
	else {
		ret = wl_ioctl(bssinfo->ifnames, cmd, buf, len);
	}
	BSD_EXIT();
	return ret;
}

/* remove disassoc STA from list */
bsd_bssinfo_t *bsd_bssinfo_by_ifname(bsd_info_t *info, char *ifname, uint8 remote)
{
	bsd_intf_info_t *intf_info;
	bsd_bssinfo_t *bssinfo = NULL;
	bool found = FALSE;
	int idx, bssidx;

	BSD_ENTER();

	for (idx = 0; (!found) && (idx < BSD_MAX_INTF); idx++) {
		intf_info = &(info->intf_info[idx]);
		if (intf_info->remote != remote) {
			BSD_INFO("intf_info:[%d] remote[%d] != %d\n",
				idx, intf_info->remote, remote);
			continue;
		}
		for (bssidx = 0; bssidx < WL_MAXBSSCFG; bssidx++) {
			bssinfo = &(intf_info->bsd_bssinfo[bssidx]);
			if (!(bssinfo->valid))
				continue;

			BSD_ALL("idx=%d bssidx=%d ifname=[%s][%s]\n",
				idx, bssidx, ifname, bssinfo->ifnames);
			if (!strcmp(ifname, bssinfo->ifnames)) {
				found = TRUE;
				BSD_ALL("idx=%d bssidx=%d\n", idx, bssidx);
				break;
			}
		}
	}

	BSD_EXIT();
	if (found)
		return bssinfo;
	else
		return NULL;
}

/*
 * config info->staprio list
 * sta_config format: xx:xx:xx:xx:xx:xx,prio[,steerflag]".
 */

void bsd_retrieve_staprio_config(bsd_info_t *info)
{
	struct ether_addr ea;
	char var[80], *next, *tmp;
	char *addr, *p, *s;
	bsd_staprio_config_t *ptr;
	char *endptr = NULL;

	BSD_ENTER();
	foreach(var, nvram_safe_get("sta_config"), next) {
		if (strlen(var) < 21) {
			BSD_ERROR("bsd_stprio format error: %s\n", var);
			break;
		}
		tmp = var;

		BSD_INFO("var:%s\n", tmp);
		addr = strsep(&tmp, ",");
		p = strsep(&tmp, ",");
		s = tmp;

		BSD_INFO("addr:%s p:%s s:%s\n", addr, p, s);
		if (ether_atoe(addr, (unsigned char *)(&(ea.octet)))) {
			ptr = malloc(sizeof(bsd_staprio_config_t));
			if (!ptr) {
				BSD_ERROR("Malloc Err:%s\n", __FUNCTION__);
				break;
			}
			memset(ptr, 0, sizeof(bsd_staprio_config_t));
			memcpy(&ptr->addr, &ea, sizeof(struct ether_addr));
			ptr->prio = p ? (uint8)strtol(p, &endptr, 0) : 0;
			ptr->steerflag = s ? (uint8)strtol(s, &endptr, 0) : 1;
			ptr->next = info->staprio;
			info->staprio = ptr;
			BSD_INFO("Mac:"MACF" prio:%d steerflag:%d \n",
				ETHER_TO_MACF(ptr->addr), ptr->prio, ptr->steerflag);
		}
	}
	BSD_EXIT();
	return;
}

/* config info->video_at_ratio */
void bsd_retrieve_video_at_ratio_config(bsd_info_t *info)
{
	char var[80], *next;
	char *endptr = NULL;
	int cnt;

	BSD_ENTER();
	for (cnt = 0; cnt < BSD_MAX_AT_SCB; cnt++)
		info->video_at_ratio[cnt] = 100 - BSD_VIDEO_AT_RATIO_BASE * (cnt + 1);

	cnt = 0;

	foreach(var, nvram_safe_get("bsd_video_at_ratio"), next) {
		info->video_at_ratio[cnt] = strtol(var, &endptr, 0);
		if (++cnt > (BSD_MAX_AT_SCB - 1))
			break;
	}

	for (cnt = 0; cnt < BSD_MAX_AT_SCB; cnt++) {
		BSD_INFO("video_at_ratio[%d]:%d\n", cnt, info->video_at_ratio[cnt]);
	}

	BSD_EXIT();
	return;
}

/* config info->staprio list */
int bsd_retrieve_static_maclist(bsd_bssinfo_t *bssinfo)
{

	int ret = BSD_OK, size;
	struct maclist *maclist = (struct maclist *) maclist_buf;

	BSD_ENTER();

	BSD_INFO("bssinfo[%p] prefix[%s], idx[%d]\n", bssinfo, bssinfo->prefix, bssinfo->idx);

	BSD_RPC("RPC name:%s cmd: %d(WLC_GET_MACMODE)\n", bssinfo->ifnames, WLC_GET_MACMODE);
	ret = bsd_wl_ioctl(bssinfo, WLC_GET_MACMODE,
		&(bssinfo->static_macmode), sizeof(bssinfo->static_macmode));

	if (ret < 0) {
		bssinfo->static_macmode = WLC_MACMODE_DISABLED;
		BSD_ERROR("Err: get macmode fails\n");
		ret = BSD_FAIL;
		goto done;
	}

	BSD_INFO("macmode=%d\n", bssinfo->static_macmode);

	BSD_RPC("RPC name:%s cmd: %d(WLC_GET_MACLIST)\n", bssinfo->ifnames, WLC_GET_MACLIST);
	if (bsd_wl_ioctl(bssinfo, WLC_GET_MACLIST, (void *)maclist,
		sizeof(maclist_buf)-BSD_RPC_HEADER_LEN) < 0) {
		BSD_ERROR("Err: get %s maclist fails\n", bssinfo->ifnames);
		ret = BSD_FAIL;
		goto done;
	}

	if (maclist->count > 0 && maclist->count < 128) {
		size = sizeof(uint) + sizeof(struct ether_addr) * (maclist->count + 1);

		BSD_INFO("count[%d] size[%d]\n", maclist->count, size);

		bssinfo->static_maclist = (struct maclist *)malloc(size);
		if (!(bssinfo->static_maclist)) {
			BSD_ERROR("%s malloc {%d] failure... \n", __FUNCTION__, size);
			ret = BSD_FAIL;
			goto done;
		}
		memcpy(bssinfo->static_maclist, maclist, size);
		maclist = bssinfo->static_maclist;
		if (BSD_DUMP_ENAB) {
			for (size = 0; size < maclist->count; size++) {
				BSD_PRINT("[%d]mac:"MACF"\n",
					size, ETHER_TO_MACF(maclist->ea[size]));
			}
		}
	}
	else {
		BSD_ERROR("Err: %s maclist cnt [%d] too large\n",
			bssinfo->ifnames, maclist->count);
		ret = BSD_FAIL;
		goto done;
	}

done:
	BSD_EXIT();
	return ret;
}


/* Retrieve nvram setting */
void bsd_retrieve_config(bsd_info_t *info)
{
	char *str, *endptr = NULL;

	BSD_ENTER();

	if ((str = nvram_get("bsd_mode"))) {
		info->mode = (uint8)strtol(str, &endptr, 0);
		if (info->mode >= BSD_MODE_MAX)
			info->mode = BSD_MODE_DISABLE;
	}

	info->prefer_5g = BSD_BAND_5G;
	if ((str = nvram_get("bsd_prefer_5g"))) {
		info->prefer_5g = (uint8)strtol(str, &endptr, 0);
	}

	if ((str = nvram_get("bsd_status_poll"))) {
		info->status_poll = (uint8)strtol(str, &endptr, 0);
		if (info->status_poll == 0)
			info->status_poll = BSD_STATUS_POLL_INTV;
	}

	info->counter_poll = BSD_COUNTER_POLL_INTV;
	if ((str = nvram_get("bsd_counter_poll"))) {
		info->counter_poll = (uint8)strtol(str, &endptr, 0);
		if (info->counter_poll == 0)
			info->counter_poll = BSD_COUNTER_POLL_INTV;
	}

	info->idle_rate = 10;
	if ((str = nvram_get("bsd_idle_rate"))) {
		info->idle_rate = (uint8)strtol(str, &endptr, 0);
		if (info->idle_rate == 0)
			info->idle_rate = 10;
	}

	info->slowest_at_ratio = BSD_SLOWEST_AT_RATIO;
	if ((str = nvram_get("bsd_slowest_at_ratio"))) {
		info->slowest_at_ratio = (uint8)strtol(str, &endptr, 0);
		if (info->slowest_at_ratio == 0)
			info->slowest_at_ratio = BSD_SLOWEST_AT_RATIO;
	}

	info->phyrate_delta = BSD_PHYRATE_DELTA;
	if ((str = nvram_get("bsd_phyrate_delta"))) {
		info->phyrate_delta = (uint8)strtol(str, &endptr, 0);
		if (info->phyrate_delta == 0)
			info->phyrate_delta = BSD_PHYRATE_DELTA;
	}
	bsd_retrieve_video_at_ratio_config(info);

	if ((str = nvram_get("bsd_poll_interval")))
		info->poll_interval = strtol(str, &endptr, 0);

	info->probe_timeout = BSD_PROBE_TIMEOUT;
	if ((str = nvram_get("bsd_probe_timeout")))
		info->probe_timeout = strtol(str, &endptr, 0);

	info->probe_gap = BSD_PROBE_GAP;
	if ((str = nvram_get("bsd_probe_gap")))
		info->probe_gap = strtol(str, &endptr, 0);

	info->maclist_timeout = BSD_MACLIST_TIMEOUT;
	if ((str = nvram_get("bsd_aclist_timeout")))
		info->maclist_timeout = strtol(str, &endptr, 0);

	info->steer_timeout = BSD_STEER_TIMEOUT;
	if ((str = nvram_get("bsd_steer_timeout")))
		info->steer_timeout = strtol(str, &endptr, 0);

	info->sta_timeout = BSD_STA_TIMEOUT;
	if ((str = nvram_get("bsd_sta_timeout")))
		info->sta_timeout = strtol(str, &endptr, 0);

	info->stahisto_timeout = BSD_STA_HISTO_TIMEOUT;
	if ((str = nvram_get("bsd_sta_histo_timeout")))
		info->stahisto_timeout = strtol(str, &endptr, 0);

	bsd_retrieve_staprio_config(info);

	if (BSD_DUMP_ENAB)
		bsd_dump_info(info);
	BSD_EXIT();
}

/* Dump bsd DB */
void bsd_dump_info(bsd_info_t *info)
{

	bsd_intf_info_t *intf_info;
	bsd_bssinfo_t *bssinfo;
	int idx, bssidx, cnt;
	bsd_sta_info_t *assoclist;
	bsd_maclist_t *maclist, *prbsta;
	struct maclist *static_maclist;

	bsd_staprio_config_t *staprio;
	bsd_sta_histo_t *stahisto;
	time_t now = time(NULL);

	BSD_ENTER();

	BSD_PRINT("-------------------------\n");
	BSD_PRINT("mode:%d role:%d now:%lu \n", info->mode, info->role, (unsigned long)now);
	BSD_PRINT("helper:%s[%d] primary:%s[%d]\n",
		info->helper_addr, info->hport,
		info->primary_addr, info->pport);
	BSD_PRINT("status_poll: %d\n", info->status_poll);
	BSD_PRINT("counter_poll: %d idle_rate:%d\n", info->counter_poll, info->idle_rate);
	BSD_PRINT("prefer_5g: %d\n", info->prefer_5g);
	BSD_PRINT("scheme:%d[%d]\n", info->scheme, bsd_get_max_scheme(info));
	BSD_PRINT("stahisto_timeout: %d\n", info->stahisto_timeout);
	BSD_PRINT("steer_timeout: %d\n", info->steer_timeout);
	BSD_PRINT("sta_timeout: %d\n", info->sta_timeout);
	BSD_PRINT("maclist_timeout: %d\n", info->maclist_timeout);
	BSD_PRINT("probe_timeout: %d\n", info->probe_timeout);
	BSD_PRINT("probe_gap: %d\n", info->probe_gap);
	BSD_PRINT("poll_interval: %d\n", info->poll_interval);
	BSD_PRINT("slowest_at_ratio: %d\n", info->slowest_at_ratio);
	BSD_PRINT("phyrate_delta: %d\n", info->phyrate_delta);

	BSD_PRINT_PLAIN("video_at_ratio:\n");
	for (cnt = 0; cnt < BSD_MAX_AT_SCB; cnt++) {
		BSD_PRINT_PLAIN("[%d]:%d\t", cnt, info->video_at_ratio[cnt]);
	}
	BSD_PRINT("\n");

	BSD_PRINT("ifidx=%d bssidx=%d\n", info->ifidx, info->bssidx);

	BSD_PRINT("staPrio List:\n");
	staprio = info->staprio;
	while (staprio) {
		BSD_PRINT("staPrio:"MACF" Prio:%d Steerflag:%d\n",
			ETHER_TO_MACF(staprio->addr), staprio->prio, staprio->steerflag);
		staprio = staprio->next;
	}

	BSD_PRINT("-------------------------\n");
	BSD_PRINT("Probe STA List:\n");
	for (idx = 0; idx < BSD_PROBE_STA_HASH; idx++) {
		prbsta = info->prbsta[idx];
		while (prbsta) {
			BSD_PRINT("sta[%p]:"MACF" timestamp[%lu] band[%d]\n",
				prbsta, ETHER_TO_MACF(prbsta->addr),
				(unsigned long)(prbsta->timestamp), prbsta->band);
			prbsta = prbsta->next;
		}
	}

	BSD_PRINT("-------------------------\n");
	BSD_PRINT("STA Histo List:\n");
	for (idx = 0; idx < BSD_PROBE_STA_HASH; idx++) {
		stahisto = info->stahisto[idx];
		while (stahisto) {
			BSD_PRINT("sta[%p]:"MACF" band[%d] idx[%d]\n",
				stahisto, ETHER_TO_MACF(stahisto->addr), stahisto->band, idx);

			for (cnt = 0; cnt < BSD_MAX_STA_HISTO; cnt++) {
				if ((stahisto->status[cnt].state > BSD_STA_INVALID) &&
					(stahisto->status[cnt].state < BSD_STA_MAX)) {
					BSD_PRINT("[%d] timestamp[%lu] state[%s][%d] ifname:%s\n",
						cnt,
						(unsigned long)(stahisto->status[cnt].timestamp),
						sta_state_str[stahisto->status[cnt].state],
						stahisto->status[cnt].state,
						(stahisto->status[cnt].bssinfo)->ifnames);
				}
			}
			stahisto = stahisto->next;
		}
	}


	BSD_PRINT("-------------------------\n");
	BSD_PRINT("intf_info:\n");
	for (idx = 0; idx < BSD_MAX_INTF; idx++) {
		intf_info = &(info->intf_info[idx]);

		BSD_PRINT("band:%d idx:%d remote[%d] enabled[%d]\n",
			intf_info->band, intf_info->idx,
			intf_info->remote, intf_info->enabled);

		for (bssidx = 0; bssidx < WL_MAXBSSCFG; bssidx++) {
			bssinfo = &(intf_info->bsd_bssinfo[bssidx]);
			if (bssinfo->valid) {
				BSD_PRINT("ifnames:%s valid:%d prefix:%s ssid:%s idx:0x%x "
					"bssid:"MACF" rclass:0x%x chanspec:0x%x"
					"prio:0x%x video_idle:%d\n",
					bssinfo->ifnames, bssinfo->valid, bssinfo->prefix,
					bssinfo->ssid, bssinfo->idx, ETHER_TO_MACF(bssinfo->bssid),
					bssinfo->rclass, bssinfo->chanspec,
					bssinfo->prio, bssinfo->video_idle);
				BSD_PRINT("steerflag:0x%x assoc_cnt:%d \n",
					bssinfo->steerflag, bssinfo->assoc_cnt);

				if (bssinfo->steer_bssinfo) {
					BSD_PRINT("steer_prefix:%s [%d][%d]\n",
						bssinfo->steer_prefix,
						((bssinfo->steer_bssinfo)->intf_info)->idx,
						(bssinfo->steer_bssinfo)->idx);
				}

				BSD_PRINT("policy:%d[%d]\n",
					bssinfo->policy, bsd_get_max_policy(info));
				BSD_PRINT("algo:%d[%d]\n", bssinfo->algo, bsd_get_max_algo(info));
				BSD_PRINT("Policy: idle_rate=%d rssi=%d prio=%d rssi=%d"
					"phy_rate=%d tx_failures=%d tx_rate=%d rx_rate=%d\n",
					bssinfo->policy_params.idle_rate,
					bssinfo->policy_params.rssi,
					bssinfo->policy_params.wprio,
					bssinfo->policy_params.wrssi,
					bssinfo->policy_params.wphy_rate,
					bssinfo->policy_params.wtx_failures,
					bssinfo->policy_params.wtx_rate,
					bssinfo->policy_params.wrx_rate);

				/* assoclist */
				assoclist = bssinfo->assoclist;
				BSD_PRINT("assoclist[%p]:\n", assoclist);
				while (assoclist) {
					BSD_PRINT("STA[%p]:"MACF" paddr:"MACF"\n",
						assoclist,
						ETHER_TO_MACF(assoclist->addr),
						ETHER_TO_MACF(assoclist->paddr));
					BSD_PRINT("prio: 0x%x\n", assoclist->prio);
					BSD_PRINT("steerflag: 0x%x\n", assoclist->steerflag);
					BSD_PRINT("rssi: %d\n", assoclist->rssi);
					BSD_PRINT("phy_rate: %d\n", assoclist->phy_rate);

					BSD_PRINT("tx_rate:%d, rx_rate:%d\n",
						assoclist->tx_rate, assoclist->rx_rate);

					BSD_PRINT("tx_bps:%d, rx_bps:%d\n",
						assoclist->tx_bps, assoclist->rx_bps);

					BSD_PRINT("timestamp: %lu(%ld)\n",
						(unsigned long)(assoclist->timestamp),
						(unsigned long)(assoclist->active));

					BSD_PRINT("at_ratio:%d, phyrate:%d\n",
						assoclist->at_ratio, assoclist->phyrate);
					assoclist = assoclist->next;
				}

				/* maclist */
				BSD_PRINT("macmode: %d\n", bssinfo->macmode);
				maclist = bssinfo->maclist;
				while (maclist) {
					BSD_PRINT("maclist: "MACF"\n",
						ETHER_TO_MACF(maclist->addr));
					maclist = maclist->next;
				}

				if (bssinfo->static_maclist) {
					static_maclist = bssinfo->static_maclist;
					BSD_PRINT("static_mac: macmode[%d] cnt[%d]\n",
						bssinfo->static_macmode, static_maclist->count);
					for (cnt = 0; cnt < static_maclist->count; cnt++) {
						BSD_INFO("[%d] mac:"MACF"\n", cnt,
							ETHER_TO_MACF(static_maclist->ea[cnt]));
					}
				}
			}
		}
		{
			chanim_stats_t *stats;
			bsd_chan_util_info_t * chan_util_info = &intf_info->chan_util_info;
			uint8 idx, num;
			bsd_chanim_stats_t *rec = &(chan_util_info->rec[0]);

			BSD_PRINT("-------------------------\n");
			BSD_PRINT("chamin histo:\n");
			BSD_PRINT("idx[%d] min[%d] max[%d] period[%d] cnt[%d] state[%d]\n",
				chan_util_info->idx, chan_util_info->chan_busy_min,
				chan_util_info->chan_busy_max, chan_util_info->period,
				chan_util_info->cnt, chan_util_info->state);

			BSD_PRINT_PLAIN("chanspec    tx   inbss   obss   nocat   nopkt   "
				"doze     txop     goodtx  badtx   glitch   badplcp  "
				"knoise  timestamp     idle\n");

			for (num = 0; num < BSD_CHANIM_STATS_MAX; num++) {
				if (!(rec[num].valid))
					continue;

				stats = &(rec[num].stats);

				BSD_PRINT_PLAIN("[%d]0x%4x\t",
					num, stats->chanspec);

				for (idx = 0; idx < CCASTATS_MAX; idx++)
					BSD_PRINT_PLAIN("%d\t", stats->ccastats[idx]);
				BSD_PRINT_PLAIN("%d\t%d\t%d\t%d\t%d\n",
					stats->glitchcnt, stats->badplcp,
					stats->bgnoise, stats->timestamp,
					stats->chan_idle);
			}
		}
		BSD_PRINT("-------------------------\n");
	}
	BSD_EXIT();
}

/* Cleanup bsd DB */
void bsd_bssinfo_cleanup(bsd_info_t *info)
{
	bsd_intf_info_t *intf_info;
	bsd_bssinfo_t *bssinfo;
	int idx, bssidx;
	bsd_sta_info_t *assoclist, *next;
	bsd_maclist_t *maclist, *next_mac;
	bsd_staprio_config_t *staprio, *next_staprio;
	bsd_sta_histo_t *stahisto, *next_stahisto;

	BSD_ENTER();

	for (idx = 0; idx < BSD_MAX_INTF; idx++) {
		intf_info = &(info->intf_info[idx]);

		for (bssidx = 0; bssidx < WL_MAXBSSCFG; bssidx++) {
			bssinfo = &(intf_info->bsd_bssinfo[bssidx]);

			BSD_INFO("free assoclist/maclist[bssidx:%d]...\n", bssidx);
			/* assoclist */
			assoclist = bssinfo->assoclist;
			while (assoclist) {
				next = assoclist->next;
				BSD_INFO("sta[%p]:"MACF"\n",
					assoclist, ETHER_TO_MACF(assoclist->addr));
				free(assoclist);
				assoclist = next;
			}

			/* maclist */
			maclist = bssinfo->maclist;
			while (maclist) {
				BSD_INFO("maclist"MACF"\n", ETHER_TO_MACF(maclist->addr));
				next_mac = maclist->next;
				free(maclist);
				maclist = next_mac;
			}

			if (bssinfo->static_maclist)
				free(bssinfo->static_maclist);
		}
	}

	for (idx = 0; idx < BSD_PROBE_STA_HASH; idx++) {
		/* cleanup prbsta list */
		maclist = info->prbsta[idx];
		while (maclist) {
			BSD_INFO("prbsta: "MACF"\n", ETHER_TO_MACF(maclist->addr));
			next_mac = maclist->next;
			free(maclist);
			maclist = next_mac;
		}

		/* cleanup stahisto list */
		stahisto = info->stahisto[idx];
		while (stahisto) {
			BSD_INFO("stahisto: "MACF"\n", ETHER_TO_MACF(stahisto->addr));
			next_stahisto = stahisto->next;
			free(stahisto);
			stahisto = next_stahisto;
		}

	}

	/* cleanup staprio list */
	staprio = info->staprio;
	while (staprio) {
		BSD_INFO("staprio: "MACF"\n", ETHER_TO_MACF(staprio->addr));
		next_staprio = staprio->next;
		free(staprio);
		staprio = next_staprio;
	}

	BSD_EXIT();
}

/* initialize bsd info DB */
int bsd_info_init(bsd_info_t *info)
{
	char name[BSD_IFNAME_SIZE], var_intf[BSD_IFNAME_SIZE], prefix[BSD_IFNAME_SIZE];
	char *next_intf;

	int idx_intf = 0;
	int ret, unit;
	int band;
	wlc_ssid_t ssid = { 0, {0} };
	struct ether_addr ea;

	int idx;
	char var[80];
	char tmp[100];
	char *next;
	char *str;
	char *endptr = NULL;
	uint8 tmpu8;

	bsd_intf_info_t *intf_info;
	bsd_bssinfo_t *bssinfo;
	int num;
	bsd_policy_t policy;
	int err = BSD_FAIL;
	char acs_ifnames[64];
	char vifs[128];
	bool rpc = FALSE;

	BSD_ENTER();

	if (info->role == BSD_ROLE_HELPER) {
		BSD_INFO("No need to do init for helper\n");
		BSD_EXIT();
		return BSD_OK;
	}

	BSDSTRNCPY(acs_ifnames, nvram_safe_get("acs_ifnames"), sizeof(acs_ifnames) - 1);

	BSD_INFO("acs_ifnames=%s\n", acs_ifnames);

	if (info->role == BSD_ROLE_PRIMARY) {
		do {
			str = bsd_nvram_safe_get(1, "acs_ifnames", &ret);
			if (ret == BSD_OK) {
				BSDSTRNCPY(tmp, str, sizeof(tmp) - 1);
				break;
			}
			sleep(5);
			BSD_RPCD("Waiting for Helper...\n");
		} while (TRUE);

		if (strlen(tmp)) {
			strcat(acs_ifnames, " rpc ");
			strcat(acs_ifnames, tmp);
		}
		BSD_RPCD("RPC acs_ifnames=%s\n", tmp);
	}

	idx_intf = 0;
	BSD_INFO("acs_ifnames=%s\n", acs_ifnames);

	foreach(var_intf, acs_ifnames, next_intf) {
		BSD_INFO("-------var_intf[%s: %d]-----------------\n", var_intf, idx_intf);
		if (!strncmp(var_intf, "rpc", 3)) {
			rpc = TRUE;
			continue;
		}

		idx = 0;
		BSDSTRNCPY(name, var_intf, sizeof(name) - 1);

		intf_info = &(info->intf_info[idx_intf]);
		intf_info->idx = idx_intf;
		intf_info->remote = (rpc)?1:0;

		bssinfo = &(intf_info->bsd_bssinfo[idx]);
		bssinfo->intf_info = intf_info;

		BSDSTRNCPY(bssinfo->ifnames, name, BSD_IFNAME_SIZE);

		BSD_RPC("RPC name:%s cmd: %d(WLC_GET_INSTANCE)\n",
			bssinfo->ifnames, WLC_GET_INSTANCE);
		ret = bsd_wl_ioctl(bssinfo, WLC_GET_INSTANCE, &unit, sizeof(unit));
		if (ret < 0) {
			BSD_ERROR("Err: get instance %s error\n", name);
			continue;
		}

		snprintf(prefix, sizeof(prefix), "wl%d_", unit);
		BSDSTRNCPY(bssinfo->prefix, prefix, sizeof(bssinfo->prefix) - 1);
		bssinfo->idx = 0;

		BSD_INFO("nvram %s=%s\n",
			strcat_r(prefix, "radio", tmp),
			bsd_nvram_safe_get(rpc, strcat_r(prefix, "radio", tmp), NULL));

		intf_info->enabled = TRUE;
		if (bsd_nvram_match(rpc, strcat_r(prefix, "radio", tmp), "0")) {
			BSD_INFO("Skipp intf:%s.  radio is off\n", name);
			memset(intf_info, 0, sizeof(bsd_intf_info_t));
			continue;
		}

		BSD_INFO("nvram %s=%s\n",
			strcat_r(prefix, "bss_enabled", tmp),
			bsd_nvram_safe_get(rpc, strcat_r(prefix, "bss_enabled", tmp), NULL));

		if (bsd_nvram_match(rpc, strcat_r(prefix, "bss_enabled", tmp), "1")) {
			bssinfo->valid = TRUE;
			BSD_INFO("Valid intf:%s\n", name);
		}

		BSD_INFO("nvram %s=%s\n",
			strcat_r(prefix, "bss_prio", tmp),
			nvram_safe_get(strcat_r(prefix, "bss_prio", tmp)));

		str = nvram_get(strcat_r(prefix, "bss_prio", tmp));
		tmpu8 = BSD_BSS_PRIO_DISABLE;
		if (str) {
			tmpu8 = (uint8)strtol(str, &endptr, 0);
			if (tmpu8 >= BSD_MAX_PRIO) {
				BSD_INFO("Err prio:%s=0x%x\n",
					strcat_r(prefix, "bss_prio", tmp), tmpu8);
				tmpu8 = BSD_BSS_PRIO_DISABLE;
			}
		}
		bssinfo->prio = tmpu8;

		BSD_RPC("RPC name:%s cmd: %d(WLC_GET_BAND)\n", bssinfo->ifnames, WLC_GET_BAND);
		ret = bsd_wl_ioctl(bssinfo, WLC_GET_BAND, &band, sizeof(band));
		if (ret < 0) {
			BSD_ERROR("Err: get %s band error\n", name);
			continue;
		}

		intf_info->band = band;

		BSD_RPC("RPC name:%s cmd: %d(WLC_GET_SSID)\n", bssinfo->ifnames, WLC_GET_SSID);
		if (bsd_wl_ioctl(bssinfo, WLC_GET_SSID, &ssid, sizeof(ssid)) < 0) {
			BSD_ERROR("Err: ifnams[%s] get ssid failure\n", name);
			continue;
		}
		ssid.SSID[ssid.SSID_len] = '\0';
		BSDSTRNCPY(bssinfo->ssid, (char *)(ssid.SSID), sizeof(bssinfo->ssid) - 1);
		BSD_INFO("ifnams[%s] ssid[%s]\n", name, ssid.SSID);

		BSD_RPC("RPC name:%s cmd: %d(WLC_GET_BSSID)\n", bssinfo->ifnames, WLC_GET_BSSID);
		if (bsd_wl_ioctl(bssinfo, WLC_GET_BSSID, &ea, ETHER_ADDR_LEN) < 0) {
			BSD_ERROR("Err: ifnams[%s] get bssid failure\n", name);
			continue;
		}
		memcpy(&bssinfo->bssid, &ea, ETHER_ADDR_LEN);
		BSD_INFO("bssid:"MACF"\n", ETHER_TO_MACF(bssinfo->bssid));


		BSD_INFO("ifname=%s idx_intf=%d prefix=%s idx=%d"
			"ssid=%s bssid:"MACF" "
			"band=%d prio=%d steerflag=0x%x, steer_prefix=%s\n",
			var_intf, idx_intf, prefix, idx,
			bssinfo->ssid, ETHER_TO_MACF(bssinfo->bssid),
			intf_info->band,
			bssinfo->prio, bssinfo->steerflag, bssinfo->steer_prefix);

		bssinfo->steerflag = BSD_BSSCFG_NOTSTEER;
		str = nvram_get(strcat_r(prefix, "bsd_steer_prefix", tmp));
		if (str) {
			BSDSTRNCPY(bssinfo->steer_prefix, str,
				sizeof(bssinfo->steer_prefix) - 1);
			bssinfo->steerflag = 0;
			if (intf_info->band == BSD_BAND_5G) {
				info->ifidx = idx_intf;
				info->bssidx = idx;
				BSD_INFO("Monitor intf[%s] [%d][%d]\n",
					bssinfo->ifnames, idx_intf, idx);
				err = BSD_OK;
			}
		}

		if ((str = nvram_get(strcat_r(prefix, "bsd_algo", tmp)))) {
			bssinfo->algo = (uint8)strtol(str, &endptr, 0);
			if (bssinfo->algo >= bsd_get_max_algo(info))
				bssinfo->algo = 0;
		}

		if ((str = nvram_get(strcat_r(prefix, "bsd_policy", tmp)))) {
			bssinfo->policy = (uint8)strtol(str, &endptr, 0);
			if (bssinfo->policy >= bsd_get_max_policy(info))
				bssinfo->policy = 0;
		} else {
			if (intf_info->band == BSD_BAND_5G)
				bssinfo->policy = BSD_POLICY_LOW_PHYRATE;
			else
				bssinfo->policy = BSD_POLICY_HIGH_PHYRATE;
		}

		memcpy(&bssinfo->policy_params, bsd_get_policy_params(bssinfo),
			sizeof(bsd_policy_t));

		if ((str = nvram_get(strcat_r(prefix, "bsd_policy_params", tmp)))) {
			num = sscanf(str, "%d %d %d %d %d %d %d %d",
				&policy.idle_rate, &policy.rssi, &policy.wprio,
				&policy.wrssi, &policy.wphy_rate,
				&policy.wtx_failures, &policy.wtx_rate, &policy.wrx_rate);
			if (num == 8) {
				memcpy(&bssinfo->policy_params, &policy, sizeof(bsd_policy_t));
			}
			else {
				BSD_ERROR("intf[%s] bsd_policy_params[%s] format error\n",
					bssinfo->ifnames, str);
			}
		}

		BSD_INFO("Algo[%d] policy[%d]: idle_rate=%d rssi=%d wprio=%d"
			"wrssi=%d wphy_rate=%d wtx_failures=%d wtx_rate=%d wrx_rate=%d\n",
			bssinfo->algo, bssinfo->policy,
			bssinfo->policy_params.idle_rate,
			bssinfo->policy_params.rssi,
			bssinfo->policy_params.wprio,
			bssinfo->policy_params.wrssi,
			bssinfo->policy_params.wphy_rate,
			bssinfo->policy_params.wtx_failures,
			bssinfo->policy_params.wtx_rate,
			bssinfo->policy_params.wrx_rate);

		bsd_retrieve_static_maclist(bssinfo);

		{
			bsd_chan_util_info_t *chan_util_info = &intf_info->chan_util_info;
			num = 0;

			if ((str = nvram_get(strcat_r(prefix, "bsd_chan_params", tmp)))) {
				num = sscanf(str, "%d %d %d %d",
					&chan_util_info->chan_busy_min,
					&chan_util_info->chan_busy_max,
					&chan_util_info->period,
					&chan_util_info->cnt);
			}
			if (!str || (num != 4)) {
				chan_util_info->chan_busy_min = BSD_CHAN_BUSY_MIN;
				chan_util_info->chan_busy_max = BSD_CHAN_BUSY_MAX;
				chan_util_info->period = BSD_CHAN_BUSY_PERIOD;
				chan_util_info->cnt = BSD_CHAN_BUSY_CNT;
			}

			BSD_INFO("idx[%d] min[%d] max[%d] period[%d] cnt[%d] state[%d]\n",
				chan_util_info->idx, chan_util_info->chan_busy_min,
				chan_util_info->chan_busy_max, chan_util_info->period,
				chan_util_info->cnt, chan_util_info->state);
		}


		/* additional virtual BSS Configs from wlX_vifs */
		BSD_INFO("%s = %s\n", strcat_r(prefix, "vifs", tmp),
			bsd_nvram_safe_get(rpc, strcat_r(prefix, "vifs", tmp), NULL));

		BSDSTRNCPY(vifs, bsd_nvram_safe_get(rpc, strcat_r(prefix, "vifs", tmp), NULL),
			sizeof(vifs) - 1);

		foreach(var, vifs, next) {
			if ((get_ifname_unit(var, NULL, &idx) != 0) || (idx >= WL_MAXBSSCFG)) {
				BSD_INFO("Unable to parse unit.subunit in interface[%s]\n", var);
				continue;
			}

			snprintf(prefix, BSD_IFNAME_SIZE, "%s_", var);
			str = bsd_nvram_safe_get(rpc, strcat_r(prefix, "bss_enabled", tmp), NULL);

			BSD_INFO("idx:%d %s=%s\n", idx,
				strcat_r(prefix, "bss_enabled", tmp), str);

			if (bsd_nvram_match(rpc, strcat_r(prefix, "bss_enabled", tmp), "1")) {

				bssinfo = &(intf_info->bsd_bssinfo[idx]);

				bssinfo->valid = TRUE;
				bssinfo->idx = idx;
				bssinfo->intf_info = intf_info;

				BSDSTRNCPY(bssinfo->ifnames, var, BSD_IFNAME_SIZE);
				BSDSTRNCPY(bssinfo->prefix, prefix, sizeof(bssinfo->prefix) - 1);

				BSD_RPC("RPC name:%s cmd: %d(WLC_GET_SSID)\n",
					bssinfo->ifnames, WLC_GET_SSID);
				if (bsd_wl_ioctl(bssinfo, WLC_GET_SSID, &ssid, sizeof(ssid)) < 0) {
					BSD_ERROR("Err: ifnams[%s] get ssid failure\n",
						bssinfo->ifnames);
					continue;
				}

				ssid.SSID[ssid.SSID_len] = '\0';
				BSDSTRNCPY(bssinfo->ssid, (char *)(ssid.SSID),
					sizeof(bssinfo->ssid) - 1);
				BSD_INFO("ifnams[%s] ssid[%s]\n", var, ssid.SSID);

				BSD_RPC("RPC name:%s cmd: %d(WLC_GET_BSSID)\n",
					bssinfo->ifnames, WLC_GET_BSSID);
				if (bsd_wl_ioctl(bssinfo, WLC_GET_BSSID, &ea, ETHER_ADDR_LEN) < 0) {
					BSD_ERROR("Err: ifnams[%s] get bssid failure\n", name);
					continue;
				}
				memcpy(&bssinfo->bssid, &ea, ETHER_ADDR_LEN);
				BSD_INFO("bssid:"MACF"\n", ETHER_TO_MACF(bssinfo->bssid));

				str = nvram_get(strcat_r(prefix, "bss_prio", tmp));
				tmpu8 = BSD_BSS_PRIO_DISABLE;
				if (str) {
					tmpu8 = (uint8)strtol(str, &endptr, 0);
					if (tmpu8 > BSD_MAX_PRIO) {
						BSD_INFO("error prio: %s= 0x%x\n",
							strcat_r(prefix, "bss_prio", tmp), tmpu8);
						tmpu8 = BSD_BSS_PRIO_DISABLE;
					}
				}
				bssinfo->prio = tmpu8;

				bssinfo->steerflag = BSD_BSSCFG_NOTSTEER;
				str = nvram_get(strcat_r(prefix, "bsd_steer_prefix", tmp));
				if (str) {
					BSDSTRNCPY(bssinfo->steer_prefix, str,
						sizeof(bssinfo->steer_prefix));
					bssinfo->steerflag = 0;
					if (intf_info->band == BSD_BAND_5G) {
						info->ifidx = idx_intf;
						info->bssidx = idx;
						BSD_INFO("Monitor intf[%s] [%d][%d]\n",
							bssinfo->ifnames, idx_intf, idx);
						err = BSD_OK;
					}
				}

				BSD_INFO("ifname=%s prefix=%s idx=%d prio=%d"
					"ssid=%s bssid:"MACF" "
					"steerflag=0x%x steer_prefix=%s\n",
					var, prefix, idx, bssinfo->prio,
					bssinfo->ssid, ETHER_TO_MACF(bssinfo->bssid),
					bssinfo->steerflag, bssinfo->steer_prefix);

				if ((str = nvram_get(strcat_r(prefix, "bsd_algo", tmp)))) {
					bssinfo->algo = (uint8)strtol(str, &endptr, 0);
					if (bssinfo->algo >= bsd_get_max_algo(info))
						bssinfo->algo = 0;
				}

				if ((str = nvram_get(strcat_r(prefix, "bsd_policy", tmp)))) {
					bssinfo->policy = (uint8)strtol(str, &endptr, 0);
					if (bssinfo->policy >= bsd_get_max_policy(info))
						bssinfo->policy = 0;
				}

				memcpy(&bssinfo->policy_params, bsd_get_policy_params(bssinfo),
					sizeof(bsd_policy_t));

				if ((str = nvram_get(strcat_r(prefix, "bsd_policy_params", tmp)))) {
					num = sscanf(str, "%d %d %d %d %d %d %d",
						&policy.idle_rate, &policy.wprio,
						&policy.wrssi, &policy.wphy_rate,
						&policy.wtx_failures,
						&policy.wtx_rate, &policy.wrx_rate);

					if (num == 7)
						memcpy(&bssinfo->policy_params, &policy,
							sizeof(bsd_policy_t));
				}

				BSD_INFO("Algo[%d] policy[%d]: idle_rate=%d prio=%d rssi=%d"
					"phy_rate=%d tx_failures=%d tx_rate=%d rx_rate=%d\n",
					bssinfo->algo, bssinfo->policy,
					bssinfo->policy_params.idle_rate,
					bssinfo->policy_params.wprio,
					bssinfo->policy_params.wrssi,
					bssinfo->policy_params.wphy_rate,
					bssinfo->policy_params.wtx_failures,
					bssinfo->policy_params.wtx_rate,
					bssinfo->policy_params.wrx_rate);

				bsd_retrieve_static_maclist(bssinfo);
			}
		}

		idx_intf++;
		if (idx_intf >= BSD_MAX_INTF) {
			BSD_ERROR("too much intf...\n");
			break;
		}
	}

	BSD_INFO("-----------------------------------\n");

	/* update steer_prefix idx */
	for (idx_intf = 0; idx_intf < BSD_MAX_INTF; idx_intf++) {
		intf_info = &(info->intf_info[idx_intf]);
		for (idx = 0; idx < WL_MAXBSSCFG; idx++) {
			bssinfo = &(intf_info->bsd_bssinfo[idx]);
			if (bssinfo->valid) {
				int tifidx, tmp_idx;
				bsd_intf_info_t *tifinfo;
				bsd_bssinfo_t *tbssinfo;
				bool found = FALSE;
				char *prefix, *steer_prefix;

				BSD_INFO("bssinfo->steer_prefix:%s[%s] [%d][%d]\n",
					bssinfo->steer_prefix, bssinfo->ssid, idx_intf, idx);
				for (tifidx = 0; !found && (tifidx < BSD_MAX_INTF); tifidx++) {
					/* skip same band */
					if (idx_intf == tifidx)
						continue;
					tifinfo = &(info->intf_info[tifidx]);
					for (tmp_idx = 0; tmp_idx < WL_MAXBSSCFG; tmp_idx++) {
						tbssinfo = &(tifinfo->bsd_bssinfo[tmp_idx]);
						BSD_INFO("tbssinfo->prefix[%s] ssid[%s]"
							"[%d][%d][v:%d]\n",
							tbssinfo->prefix, tbssinfo->ssid,
							tifidx, tmp_idx, tbssinfo->valid);

						if (!(tbssinfo->valid))
							continue;
						prefix = tbssinfo->prefix;
						steer_prefix = bssinfo->steer_prefix;
						if (!strcmp(tbssinfo->ssid, bssinfo->ssid) ||
							!strcmp(prefix, steer_prefix))
						{
							bssinfo->steer_bssinfo = tbssinfo;

							BSDSTRNCPY(bssinfo->steer_prefix,
								tbssinfo->prefix,
								sizeof(bssinfo->steer_prefix) - 1);
							bssinfo->steerflag = 0;
							if (intf_info->band == BSD_BAND_5G) {
								info->ifidx = idx_intf;
								info->bssidx = idx;
								BSD_INFO("Mon intf[%s] [%d][%d]\n",
									bssinfo->ifnames,
									idx_intf, idx);
							}

							found = TRUE;
							err = BSD_OK;
							break;
						}
					}
				}

				if (!found) {
					BSD_INFO("[%d][%d] %s [%s] cannot found steering match\n",
						idx_intf, idx, bssinfo->steer_prefix,
						bssinfo->ssid);
					bssinfo->steerflag = BSD_BSSCFG_NOTSTEER;
					BSD_INFO("Err: Set %s[%d][%d] to nosteer [%x] \n",
						bssinfo->prefix, idx_intf, idx, bssinfo->steerflag);
				}
				else {
					BSD_INFO("[%d][%d]:%s [%s] found steering match"
						"[%d][%d]:%s[%s]\n",
						idx_intf, idx, bssinfo->steer_prefix, bssinfo->ssid,
						tbssinfo->intf_info->idx, tbssinfo->idx,
						tbssinfo->prefix, tbssinfo->ssid);
				}

			}

		}
	}

	BSD_INFO("-----------------------------------\n");
	BSD_EXIT();
	return err;
}


bsd_sta_info_t *bsd_add_assoclist(bsd_bssinfo_t *bssinfo, struct ether_addr *addr, bool enable)
{
	bsd_sta_info_t *sta, *head;

	BSD_ENTER();

	sta = bssinfo->assoclist;

	BSD_INFO("sta[%p]:"MACF"\n", sta, ETHERP_TO_MACF(addr));
	while (sta) {
		BSD_INFO("cmp: sta[%p]:"MACF"\n", sta, ETHER_TO_MACF(sta->addr));
		if (eacmp(&(sta->addr), addr) == 0) {
			break;
		}
		sta = sta->next;
	}

	if (enable && !sta) {
		sta = malloc(sizeof(bsd_sta_info_t));
		if (!sta) {
			BSD_INFO("%s@%d: Malloc failure\n", __FUNCTION__, __LINE__);
			return NULL;
		}

		memset(sta, 0, sizeof(bsd_sta_info_t));
		memcpy(&sta->addr, addr, sizeof(struct ether_addr));

		sta->timestamp = time(NULL);
		sta->active = time(NULL);
		sta->bssinfo = bssinfo;

		sta->prio = bssinfo->prio;
		sta->steerflag = bssinfo->steerflag;

		head = bssinfo->assoclist;
		if (head)
			head->prev = sta;

		sta->next = head;
		sta->prev = (struct bsd_sta_info *)&(bssinfo->assoclist);
		bssinfo->assoclist = sta;

		BSD_INFO("head[%p] sta[%p]:"MACF" prio:0x%x steerflag:0x%x\n",
			head, sta, ETHERP_TO_MACF(addr), sta->prio, sta->steerflag);

	}

	BSD_INFO("sta[%p]\n", sta);

	BSD_EXIT();
	return sta;
}

void bsd_clear_assoclist_bs_data(bsd_bssinfo_t *bssinfo)
{
	bsd_sta_info_t *sta;

	BSD_ENTER();

	sta = bssinfo->assoclist;

	while (sta) {
		BSD_AT("cmp: sta[%p]:"MACF"\n", sta, ETHER_TO_MACF(sta->addr));
		sta->at_ratio = 0;
		sta->phyrate = 0;
		sta = sta->next;
	}

	BSD_EXIT();
}

void bsd_remove_assoclist(bsd_bssinfo_t *bssinfo, struct ether_addr *addr)
{
	bool found = FALSE;
	bsd_sta_info_t *assoclist = NULL, *prev, *head;

	BSD_ENTER();

	assoclist = bssinfo->assoclist;

	if (assoclist == NULL) {
		BSD_INFO("%s: ifname:%s empty assoclist \n",
			__FUNCTION__, bssinfo->ifnames);
		BSD_INFO("%s Exiting....\n", __FUNCTION__);
		return;
	}

	BSD_INFO("sta[%p]:"MACF"[cmp]"MACF"\n",
		assoclist,
		ETHERP_TO_MACF(&assoclist->addr), ETHERP_TO_MACF(addr));

	if (eacmp(&(assoclist->addr), addr) == 0) {
		head = assoclist->next;
		bssinfo->assoclist = head;
		if (head)
			head->prev = (struct bsd_sta_info *)&(bssinfo->assoclist);
		found = TRUE;
	}
	else {
		prev = assoclist;
		assoclist = prev->next;

		while (assoclist) {
			BSD_INFO("sta[%p]:"MACF"[cmp]"MACF"\n",
				assoclist, ETHERP_TO_MACF(&assoclist->addr),
				ETHERP_TO_MACF(addr));

			if (eacmp(&(assoclist->addr), addr) == 0) {
				head = assoclist->next;
				prev->next = head;
				if (head)
					head->prev = prev;

				found = TRUE;
				break;
			}

			prev = assoclist;
			assoclist = prev->next;
		}
	}

	if (found) {
		BSD_INFO("remove sta[%p]:"MACF"\n", assoclist, ETHERP_TO_MACF(addr));
		free(assoclist);
	}
	else {
		BSD_INFO("doesn't find sta:"MACF"\n", ETHERP_TO_MACF(addr));
	}

	BSD_EXIT();
	return;
}


/* remove disassoc STA from list */
void bsd_remove_sta_reason(bsd_info_t *info, char *ifname, uint8 remote, struct ether_addr *addr,
	bsd_sta_state_t reason)
{
	bsd_bssinfo_t *bssinfo;

	BSD_ENTER();

	bssinfo = bsd_bssinfo_by_ifname(info, ifname, remote);

/*	if (!bssinfo || (bssinfo->steerflag & BSD_BSSCFG_NOTSTEER) ||
		(bssinfo->steer_bssinfo == NULL)) {
*/
	if (!bssinfo) {
		BSD_INFO("%s: not found steerable ifname:%s\n", __FUNCTION__, ifname);
		BSD_EXIT();
		return;
	}

	bsd_set_stahisto_by_addr(info, bssinfo, addr, TRUE, reason);

	bsd_remove_assoclist(bssinfo, addr);

	BSD_EXIT();
}


/* Find STA from list */
bsd_sta_info_t *bsd_sta_by_addr(bsd_info_t *info, bsd_bssinfo_t *bssinfo,
struct ether_addr *addr, bool enable)
{
	bsd_sta_info_t *sta;
	bsd_staprio_config_t *ptr;

	BSD_ENTER();

	sta = bsd_add_assoclist(bssinfo, addr, enable);
	if (sta) {
		/* update staprio from staprio list */
		ptr = info->staprio;
		while (ptr) {
			if (eacmp(&(ptr->addr), addr) == 0) {
				sta->prio = ptr->prio;
				sta->steerflag = ptr->steerflag;
				break;
			}
			ptr = ptr->next;
		}
	}

	BSD_EXIT();
	return sta;
}

/* add assoc STA from list */
void bsd_assoc_sta(bsd_info_t *info, char *ifname, uint8 remote, struct ether_addr *addr)
{
	bsd_intf_info_t *intf_info;
	bsd_bssinfo_t *bssinfo;
	bsd_sta_info_t *sta;
	bsd_maclist_t *mac;

	BSD_ENTER();

	/* add to list */
	bssinfo = bsd_bssinfo_by_ifname(info, ifname, remote);
/*
	if (!bssinfo || (bssinfo->steerflag & BSD_BSSCFG_NOTSTEER) ||
		(bssinfo->steer_bssinfo == NULL)) {
*/
	if (!bssinfo) {
		BSD_INFO("Not found steerable ifname:%s\n", ifname);
		return;
	}

	sta = bsd_sta_by_addr(info, bssinfo, addr, TRUE);
	if (!sta || !(sta->bssinfo->steer_bssinfo)) {
		if (sta) {
			BSD_ERROR("sta[%p] is not in steer bssinfo[%s][%d]\n",
				sta, sta->bssinfo->ifnames, sta->bssinfo->idx);
		}
		return;
	}

	bsd_set_stahisto_by_addr(info, bssinfo, addr, TRUE, BSD_STA_ASSOC);

	intf_info = bssinfo->intf_info;

	if ((intf_info->band == BSD_BAND_2G && info->prefer_5g == BSD_BAND_5G)) {
		/* (intf_info->band == BSD_BAND_5G && info->prefer_5g == BSD_BAND_2G) */

		mac = bssinfo->steer_bssinfo->maclist;
		while (mac) {
			BSD_STEER("checking maclist"MACF"\n", ETHER_TO_MACF(mac->addr));
			if (eacmp(&(mac->addr), &(sta->addr)) == 0) {
				BSD_INFO("found maclist: "MACF"\n", ETHER_TO_MACF(mac->addr));
				break;
			}
			mac = mac->next;
		}

		if (!mac) {
			/* not just steered */
			mac = bsd_prbsta_by_addr(info, addr, FALSE);

			if (mac && ((mac->band & BSD_BAND_5G) == BSD_BAND_5G)) {
				/* && 	((now - mac->timestamp) < info->probe_gap)){ */
				BSD_STEER("prb 5g found STA:"MACF"\n", ETHER_TO_MACF(*addr));
				bsd_steer_sta(info, sta);
				bsd_set_stahisto_by_addr(info, bssinfo,
					addr, TRUE, BSD_STA_STEERED);
			}
		}
	}

	/* update steered intf acl maclist */
	bsd_stamp_maclist(info, bssinfo->steer_bssinfo, addr);

	BSD_INFO("sta[%p]:"MACF" prio:0x%x steerflag:0x%x\n",
		sta, ETHERP_TO_MACF(addr), sta->prio, sta->steerflag);

	if (BSD_DUMP_ENAB)
		bsd_dump_info(info);

	BSD_EXIT();
}

bool bsd_is_sta_dualband(bsd_info_t *info, struct ether_addr *addr)
{
	bsd_maclist_t *mac;

	mac = bsd_prbsta_by_addr(info, addr, FALSE);

	if (mac && ((mac->band & BSD_BAND_ALL) == BSD_BAND_ALL)) {
		return TRUE;
	}
	return FALSE;
}

void bsd_auth_sta(bsd_info_t *info, char *ifname, uint8 remote, struct ether_addr *addr)
{
	bsd_bssinfo_t *bssinfo;

	BSD_ENTER();

	/* add to list */
	bssinfo = bsd_bssinfo_by_ifname(info, ifname, remote);

	if (!bssinfo) {
/*	if (!bssinfo || (bssinfo->steerflag & BSD_BSSCFG_NOTSTEER) ||
		(bssinfo->steer_bssinfo == NULL)) {
*/
		BSD_INFO("Not found steerable ifname:%s\n", ifname);
		return;
	}

	bsd_set_stahisto_by_addr(info, bssinfo, addr, TRUE, BSD_STA_AUTH);

	if (BSD_DUMP_ENAB)
		bsd_dump_info(info);

	BSD_EXIT();
}

void bsd_deauth_sta(bsd_info_t *info, char *ifname, uint8 remote, struct ether_addr *addr)
{
	BSD_ENTER();

	bsd_remove_sta_reason(info, ifname, remote,
		(struct ether_addr *)addr, BSD_STA_DEAUTH);
	if (BSD_DUMP_ENAB)
		bsd_dump_info(info);

	BSD_EXIT();
}

void bsd_disassoc_sta(bsd_info_t *info, char *ifname, uint8 remote, struct ether_addr *addr)
{
	BSD_ENTER();

	bsd_remove_sta_reason(info, ifname, remote,
		(struct ether_addr *)addr, BSD_STA_DISASSOC);
	if (BSD_DUMP_ENAB)
		bsd_dump_info(info);

	BSD_EXIT();
}

void bsd_update_psta(bsd_info_t *info, char *ifname, uint8 remote,
	struct ether_addr *addr, struct ether_addr *paddr)
{
	bsd_bssinfo_t *bssinfo;
	bsd_sta_info_t *sta, *psta;

	BSD_ENTER();

	bssinfo = bsd_bssinfo_by_ifname(info, ifname, remote);

	if (!bssinfo) {
/*
	if (!bssinfo || (bssinfo->steerflag & BSD_BSSCFG_NOTSTEER)) {
*/
		BSD_INFO("%s: not found ifname:%s\n", __FUNCTION__, ifname);
		return;
	}

	sta = bsd_sta_by_addr(info, bssinfo, addr, FALSE);
	psta = bsd_sta_by_addr(info, bssinfo, paddr, FALSE);

	if (!sta) {
		BSD_ERROR("Not found sta:"MACF" @ [%s]\n", ETHERP_TO_MACF(addr), ifname);
		BSD_EXIT();
		return;
	}

	if (!psta) {
		BSD_ERROR("Not found psta:"MACF" @ [%s]\n", ETHERP_TO_MACF(paddr), ifname);
		BSD_EXIT();
		return;
	}

	memcpy(&sta->paddr, paddr, sizeof(struct ether_addr));
	sta->steerflag = psta->steerflag;
	sta->timestamp = time(NULL);

	BSD_INFO("sta: "MACF " steerflag=%d\n", ETHERP_TO_MACF(addr), sta->steerflag);
	BSD_EXIT();
}

void bsd_retrieve_bs_data(bsd_bssinfo_t *bssinfo)
{
	iov_bs_data_struct_t *data = (iov_bs_data_struct_t *)ioctl_buf;
	int argn;
	int ret;
	bsd_sta_info_t *sta = NULL;
	iov_bs_data_record_t *rec;
	iov_bs_data_counters_t *ctr;
	float datarate;
	float phyrate;
	float air, rtr;

	BSD_ATENTER();

	memset(ioctl_buf, 0, sizeof(ioctl_buf));
	strcpy(ioctl_buf, "bs_data");
	BSD_RPC("RPC name:%s cmd: %d(WLC_GET_VAR: bs_data)\n", bssinfo->ifnames, WLC_GET_VAR);
	ret = bsd_wl_ioctl(bssinfo, WLC_GET_VAR, ioctl_buf, sizeof(ioctl_buf) - BSD_RPC_HEADER_LEN);

	if (ret < 0) {
		BSD_ERROR("Err to read bs_data: %s\n", bssinfo->ifnames);
		BSD_ATEXIT();
		return;
	}

	BSD_AT("ifnames=%s[remote:%d] data->structure_count=%d\n",
		bssinfo->ifnames, bssinfo->intf_info->remote, data->structure_count);

	for (argn = 0; argn < data->structure_count; ++argn) {
		rec = &data->structure_record[argn];
		ctr = &rec->station_counters;

		if (ctr->acked == 0) continue;

		BSD_AT("STA:"MACF"\t", ETHER_TO_MACF(rec->station_address));

		/* Calculate PHY rate */
		phyrate = (float)ctr->txrate_succ * 0.5 / (float)ctr->acked;

		/* Calculate Data rate */
		datarate = (ctr->time_delta) ?
			(float)ctr->throughput * 8.0 / (float)ctr->time_delta : 0.0;

		/* Calculate % airtime */
		air = (ctr->time_delta) ? ((float)ctr->airtime * 100.0 /
			(float) ctr->time_delta) : 0.0;
		if (air > 100)
			air = 100;

		/* Calculate retry percentage */
		rtr = (float)ctr->retry / (float)ctr->acked * 100;
		if (rtr > 100)
			rtr = 100;

		BSD_AT("phyrate[%10.1f] [datarate]%10.1f [air]%9.1f%% [retry]%9.1f%%\n",
			phyrate, datarate, air, rtr);
		sta = bsd_add_assoclist(bssinfo, &(rec->station_address), FALSE);
		if (sta) {
			BSD_AT("sta[%p] Mac:"MACF"\n", sta, ETHER_TO_MACF(sta->addr));
			sta->at_ratio = air;
			sta->phyrate = phyrate;
			sta->datarate = datarate;
		}
	}
	BSD_ATEXIT();
}


/* Update sta_info */
void bsd_update_stainfo(bsd_info_t *info)
{
	bsd_intf_info_t *intf_info;
	bsd_bssinfo_t *bssinfo;
	uint8 bssprio = BSD_BSS_PRIO_DISABLE;
	int idx, bssidx, cnt;
	bsd_sta_info_t *sta = NULL;
	struct ether_addr ea;

	struct maclist *maclist = (struct maclist *) maclist_buf;
	int count = 0;
	char *param;
	int buflen;
	int ret;
	time_t now = time(NULL);
	uint32 tx_tot_pkts = 0, rx_tot_pkts = 0;
	uint32	delta_txframe, delta_rxframe;
	txpwr_target_max_t *txpwr;
	int i;

	BSD_ENTER();

	for (idx = 0; idx < BSD_MAX_INTF; idx++) {
		intf_info = &(info->intf_info[idx]);
		BSD_INFO("idx=%d\n", idx);
		for (bssidx = 0; bssidx < WL_MAXBSSCFG; bssidx++) {
			bssinfo = &(intf_info->bsd_bssinfo[bssidx]);
			if (!(bssinfo->valid))
				continue;
/*			if (bssinfo->steerflag & BSD_BSSCFG_NOTSTEER)
				continue;
*/
			bssprio = bssinfo->prio;
			BSD_INFO("bssidx=%d intf:%s\n", bssidx, bssinfo->ifnames);

			memset(ioctl_buf, 0, sizeof(ioctl_buf));
			strcpy(ioctl_buf, "chanspec");
			BSD_RPC("RPC name:%s cmd: %d(WLC_GET_VAR: chanspec)\n",
				bssinfo->ifnames, WLC_GET_VAR);
			ret = bsd_wl_ioctl(bssinfo, WLC_GET_VAR, (void *)ioctl_buf,
				sizeof(ioctl_buf) - BSD_RPC_HEADER_LEN);

			if (ret < 0) {
				BSD_ERROR("Err to read chanspec: %s\n", bssinfo->ifnames);
				continue;
			}
			bssinfo->chanspec = (chanspec_t)(*((uint32 *)ioctl_buf));
			BSD_INFO("chanspec: 0x%x\n", bssinfo->chanspec);

			memset(ioctl_buf, 0, sizeof(ioctl_buf));
			strcpy(ioctl_buf, "rclass");
			buflen = strlen(ioctl_buf) + 1;
			param = (char *)(ioctl_buf + buflen);
			memcpy(param, &bssinfo->chanspec, sizeof(chanspec_t));

			BSD_RPC("RPC name:%s cmd: %d(WLC_GET_VAR: rclass)\n",
				bssinfo->ifnames, WLC_GET_VAR);
			ret = bsd_wl_ioctl(bssinfo, WLC_GET_VAR, (void *)ioctl_buf,
				sizeof(ioctl_buf) - BSD_RPC_HEADER_LEN);

			if (ret < 0) {
				BSD_ERROR("Err to read rclass. ifname:%s chanspec:0x%x\n",
					bssinfo->ifnames, bssinfo->chanspec);
				continue;
			}
			bssinfo->rclass = (uint8)(*((uint32 *)ioctl_buf));
			BSD_INFO("rclass:0x%x\n", bssinfo->rclass);

			BSD_RPC("RPC name:%s cmd: %d(WLC_GET_BSSID)\n",
				bssinfo->ifnames, WLC_GET_BSSID);
			if (bsd_wl_ioctl(bssinfo, WLC_GET_BSSID, &ea, ETHER_ADDR_LEN) < 0) {
				BSD_ERROR("Err: ifnams[%s] get bssid failure\n", bssinfo->ifnames);
				continue;
			}
			memcpy(&bssinfo->bssid, &ea, ETHER_ADDR_LEN);
			BSD_INFO("bssid:"MACF"\n", ETHER_TO_MACF(bssinfo->bssid));


			memset(ioctl_buf, 0, sizeof(ioctl_buf));
			strcpy(ioctl_buf, "txpwr_target_max");

			BSD_RPC("RPC name:%s cmd: %d(WLC_GET_VAR: txpwr_target)\n",
				bssinfo->ifnames, WLC_GET_VAR);
			ret = bsd_wl_ioctl(bssinfo, WLC_GET_VAR, ioctl_buf,
				sizeof(ioctl_buf) - BSD_RPC_HEADER_LEN);

			if (ret < 0) {
				BSD_ERROR("Err to read txpwr_target. ifname:%s chanspec:0x%x\n",
					bssinfo->ifnames, bssinfo->chanspec);
				continue;
			}
			txpwr = (txpwr_target_max_t *)ioctl_buf;

			BSD_INFO("Maximum Tx Power Target (chanspec:0x%x):\t", txpwr->chanspec);
			for (i = 0; i < txpwr->rf_cores; i++)
				BSD_INFO("%2d.%02d  ",
				       DIV_QUO(txpwr->txpwr[i], 4),
				       DIV_REM(txpwr->txpwr[i], 4));
			BSD_INFO("\n");
			memcpy(&bssinfo->txpwr, txpwr, sizeof(bssinfo->txpwr));

			bsd_clear_assoclist_bs_data(bssinfo);
			bsd_retrieve_bs_data(bssinfo);

			/* read assoclist */
			memset(maclist_buf, 0, sizeof(maclist_buf));
			maclist->count = ((sizeof(maclist_buf)- 300 - sizeof(int))/ETHER_ADDR_LEN);
			BSD_RPC("RPC name:%s cmd: %d(WLC_GET_ASSOCLIST)\n",
				bssinfo->ifnames, WLC_GET_ASSOCLIST);
			ret = bsd_wl_ioctl(bssinfo,  WLC_GET_ASSOCLIST,
				(void *)maclist,  sizeof(maclist_buf)-BSD_RPC_HEADER_LEN);

			if (ret < 0) {
				BSD_ERROR("Err: ifnams[%s] get assoclist\n", bssinfo->ifnames);
				continue;
			}
			count = maclist->count;
			bssinfo->assoc_cnt = 0;
			BSD_INFO("assoclist count = %d\n", count);

			/* Parse assoc list and read all sta_info */
			for (cnt = 0; cnt < count; cnt++) {
				bsd_sta_histo_t *stahisto;
				time_t gap;
				sta_info_t *sta_info;

				scb_val_t scb_val;
				int32 rssi;

				BSD_INFO("sta_info sta:"MACF"\n", ETHER_TO_MACF(maclist->ea[cnt]));

				/* skiiped the blocked sta */
				if (bsd_maclist_by_addr(bssinfo, &(maclist->ea[cnt]))) {
					BSD_INFO("Skipp STA:"MACF", found in maclist\n",
						ETHER_TO_MACF(maclist->ea[cnt]));
					continue;
				}
				memset(&scb_val, 0, sizeof(scb_val));
				memcpy(&scb_val.ea, &maclist->ea[cnt], ETHER_ADDR_LEN);

				BSD_RPC("RPC name:%s cmd: %d(WLC_GET_RSSI)\n",
					bssinfo->ifnames, WLC_GET_RSSI);
				ret = bsd_wl_ioctl(bssinfo, WLC_GET_RSSI,
					&scb_val, sizeof(scb_val));

				if (ret < 0) {
					BSD_ERROR("Err: reading intf:%s STA:"MACF" RSSI\n",
						bssinfo->ifnames, ETHER_TO_MACF(maclist->ea[cnt]));
					continue;
				}
				rssi = scb_val.val;
				BSD_HISTO("STA:"MACF" RSSI=%d\n",
					ETHER_TO_MACF(maclist->ea[cnt]), rssi);

				strcpy(ioctl_buf, "sta_info");
				buflen = strlen(ioctl_buf) + 1;
				param = (char *)(ioctl_buf + buflen);
				memcpy(param, &maclist->ea[cnt], ETHER_ADDR_LEN);

				BSD_RPC("RPC name:%s cmd: %d(WLC_GET_VAR: sta_info)\n",
					bssinfo->ifnames, WLC_GET_VAR);
				ret = bsd_wl_ioctl(bssinfo, WLC_GET_VAR,
					ioctl_buf, sizeof(ioctl_buf) - BSD_RPC_HEADER_LEN);

				if (ret < 0) {
					BSD_ERROR("Err: intf:%s STA:"MACF" sta_info\n",
						bssinfo->ifnames, ETHER_TO_MACF(maclist->ea[cnt]));
					continue;
				}
				stahisto = bsd_stahisto_by_addr(info, &(maclist->ea[cnt]));
				if (!stahisto) {
					BSD_HISTO("stahist:"MACF" doesn't exist. Adding...\n",
						ETHER_TO_MACF(maclist->ea[cnt]));
					bsd_set_stahisto_by_addr(info, bssinfo, &(maclist->ea[cnt]),
						TRUE, BSD_STA_ASSOCLIST);
				}
				else {
					BSD_HISTO("stahist:"MACF" found. Update timestamp:[%lu]\n",
						ETHER_TO_MACF(maclist->ea[cnt]),
						(unsigned long)now);
					stahisto->timestamp = now;
				}

				sta = bsd_sta_by_addr(info, bssinfo, &(maclist->ea[cnt]), TRUE);

				if (!sta) {
					BSD_ERROR("Exiting... Error update [%s] sta:"MACF"\n",
						bssinfo->ifnames, ETHER_TO_MACF(maclist->ea[cnt]));
					continue;
				}

				sta_info = (sta_info_t *)ioctl_buf;
				sta->rx_rate = (sta_info->rx_rate / 1000);
				sta->tx_rate = (sta_info->tx_rate / 1000);
				sta->rssi = rssi;
				if (now <= sta->timestamp)
					gap = info->status_poll;
				else
					gap = now - sta->timestamp;

				sta->rx_pkts = 0;
				if (sta_info->rx_tot_pkts > sta->rx_tot_pkts) {
					sta->rx_pkts = sta_info->rx_tot_pkts - sta->rx_tot_pkts;
					sta->rx_bps = sta->rx_pkts / (gap * 1000);
					BSD_INFO("Mac:"MACF" rx_bps[%d] = "
						"rx_pkts[%d](%d - %d)/gap[%lu] @ timestamp:[%lu]\n",
						ETHER_TO_MACF(maclist->ea[cnt]),
						sta->rx_bps, sta->rx_pkts,
						sta_info->rx_tot_pkts, sta->rx_tot_pkts,
						(unsigned long)gap, (unsigned long)now);
				}
				sta->tx_pkts = 0;
				if (sta_info->tx_tot_pkts > sta->tx_tot_pkts) {
					sta->tx_pkts = sta_info->tx_tot_pkts - sta->tx_tot_pkts;
					sta->rx_bps = sta->tx_pkts / (gap * 1000);
					BSD_INFO("Mac:"MACF" tx_bps[%d] = "
						"tx_pkts[%d](%d - %d)/gap[%lu] @ timestamp:[%lu]\n",
						ETHER_TO_MACF(maclist->ea[cnt]),
						sta->tx_bps, sta->tx_pkts,
						sta_info->tx_tot_pkts, sta->tx_tot_pkts,
						(unsigned long)gap, (unsigned long)now);
				}

				sta->tx_failures = 0;
				if (sta_info->tx_failures > sta->tx_failures) {
					sta->tx_failures = sta_info->tx_failures - sta->tx_failures;
					sta->tx_failures /= gap;
				}

				sta->rx_tot_pkts = sta_info->rx_tot_pkts;
				sta->tx_tot_pkts = sta_info->tx_tot_pkts;
				sta->tx_tot_failures = sta_info->tx_failures;
				sta->in = sta_info->in;
				sta->idle = sta_info->idle;
				sta->active = time(NULL);
				BSD_HISTO("sta[%p]:"MACF" active=%lu\n",
					sta, ETHER_TO_MACF(sta->addr),
					(unsigned long)(sta->active));

				/* cale STB tx/rx */
				if (sta->steerflag & BSD_BSSCFG_NOTSTEER) {
					tx_tot_pkts += sta_info->tx_tot_pkts;
					rx_tot_pkts += sta_info->rx_tot_pkts;

					BSD_STEER("[%s] "MACF" tx_tot_pkts[%d] rx_tot_pkts[%d]\n",
						bssinfo->ifnames, ETHER_TO_MACF(maclist->ea[cnt]),
						sta_info->tx_tot_pkts, sta_info->rx_tot_pkts);
				}
				else {
					(bssinfo->assoc_cnt)++;
				}


			}
			delta_rxframe = 0;
			delta_txframe = 0;

			if (tx_tot_pkts > bssinfo->tx_tot_pkts)
				delta_txframe = tx_tot_pkts - bssinfo->tx_tot_pkts;

			if (rx_tot_pkts > bssinfo->rx_tot_pkts)
				delta_rxframe = rx_tot_pkts - bssinfo->rx_tot_pkts;

			BSD_STEER("last: txframe[%d] rxframe[%d] cnt:txframe[%d] rxframe[%d]\n",
				bssinfo->tx_tot_pkts, bssinfo->rx_tot_pkts,
				tx_tot_pkts, rx_tot_pkts);

			BSD_STEER("delta[tx+rx]=%d threshold=%d\n",
				delta_txframe + delta_rxframe,
				info->counter_poll * info->idle_rate);

			bssinfo->video_idle = 0;
			if ((delta_txframe + delta_rxframe) <
				(info->counter_poll * info->idle_rate)) {
				bssinfo->video_idle = 1;
			}

			BSD_STEER("ifname: %s, video_idle=%d\n",
				bssinfo->ifnames, bssinfo->video_idle);

			bssinfo->tx_tot_pkts = tx_tot_pkts;
			bssinfo->rx_tot_pkts = rx_tot_pkts;
		}
	}

	BSD_EXIT();
}


/* Update video STA counters */
void bsd_update_stb_info(bsd_info_t *info)
{
	bsd_intf_info_t *intf_info;
	bsd_bssinfo_t *bssinfo;
	int idx, bssidx, cnt;

	struct maclist *maclist = (struct maclist *) maclist_buf;
	int count = 0;
	char *param;
	int buflen;
	int ret;
	uint32 tx_tot_pkts = 0, rx_tot_pkts = 0;
	uint32	delta_txframe, delta_rxframe;

	BSD_ENTER();

	for (idx = 0; idx < BSD_MAX_INTF; idx++) {
		intf_info = &(info->intf_info[idx]);
		BSD_STEER("idx=%d\n", idx);
		if (idx != info->ifidx) {
			BSD_STEER("skiiped idx=%d\n", idx);
			continue;
		}

		for (bssidx = 0; bssidx < WL_MAXBSSCFG; bssidx++) {
			bssinfo = &(intf_info->bsd_bssinfo[bssidx]);

			if (!(bssinfo->valid))
				continue;

			if (bssidx == info->bssidx) {
				BSD_STEER("skiiped bssidx=%d\n", bssidx);
				continue;
			}

			BSD_STEER("Cal: ifnames[%s] [%d]{%d]\n", bssinfo->ifnames, idx, bssidx);

			bsd_retrieve_bs_data(bssinfo);

			/* read assoclist */
			memset(maclist_buf, 0, sizeof(maclist_buf));
			maclist->count = (sizeof(maclist_buf) - sizeof(int))/ETHER_ADDR_LEN;

			BSD_RPC("RPC name:%s cmd: %d(WLC_GET_ASSOCLIST)\n",
				bssinfo->ifnames, WLC_GET_ASSOCLIST);
			ret = bsd_wl_ioctl(bssinfo,  WLC_GET_ASSOCLIST,
				(void *)maclist,  sizeof(maclist_buf) - BSD_RPC_HEADER_LEN);

			if (ret < 0) {
				BSD_ERROR("Err: ifnams[%s] get assoclist\n", bssinfo->ifnames);
				continue;
			}
			count = maclist->count;
			bssinfo->assoc_cnt = count;
			BSD_STEER("assoclist count = %d\n", count);

			/* Parse assoc list and read all sta_info */
			for (cnt = 0; cnt < count; cnt++) {
				sta_info_t *sta_info;

				BSD_STEER("sta_info sta:"MACF"\n", ETHER_TO_MACF(maclist->ea[cnt]));

				strcpy(ioctl_buf, "sta_info");
				buflen = strlen(ioctl_buf) + 1;
				param = (char *)(ioctl_buf + buflen);
				memcpy(param, &maclist->ea[cnt], ETHER_ADDR_LEN);

				BSD_RPC("RPC name:%s cmd: %d(WLC_GET_VAR: sta_info)\n",
					bssinfo->ifnames, WLC_GET_VAR);
				ret = bsd_wl_ioctl(bssinfo, WLC_GET_VAR, ioctl_buf,
					sizeof(ioctl_buf) - BSD_RPC_HEADER_LEN);

				if (ret < 0) {
					BSD_ERROR("Err: intf:%s STA:"MACF" sta_info\n",
						bssinfo->ifnames, ETHER_TO_MACF(maclist->ea[cnt]));
					continue;
				}


				sta_info = (sta_info_t *)ioctl_buf;

				tx_tot_pkts += sta_info->tx_tot_pkts;
				rx_tot_pkts += sta_info->rx_tot_pkts;

				BSD_STEER("intf:%s STA:"MACF" tx_tot_pkts[%d] rx_tot_pkts[%d]\n",
					bssinfo->ifnames, ETHER_TO_MACF(maclist->ea[cnt]),
					sta_info->tx_tot_pkts, sta_info->rx_tot_pkts);

			}
			delta_rxframe = 0;
			delta_txframe = 0;

			if (tx_tot_pkts > bssinfo->tx_tot_pkts)
				delta_txframe = tx_tot_pkts - bssinfo->tx_tot_pkts;

			if (rx_tot_pkts > bssinfo->rx_tot_pkts)
				delta_rxframe = rx_tot_pkts - bssinfo->rx_tot_pkts;

			BSD_STEER("last: txframe[%d] rxframe[%d] cnt:txframe[%d] rxframe[%d]\n",
				bssinfo->tx_tot_pkts, bssinfo->rx_tot_pkts,
				tx_tot_pkts, rx_tot_pkts);

			BSD_STEER("delta[tx+rx]=%d threshold=%d\n",
				delta_txframe + delta_rxframe,
				info->counter_poll * info->idle_rate);

			bssinfo->video_idle = 0;
			if ((delta_txframe + delta_rxframe) <
				(info->counter_poll * info->idle_rate)) {
				bssinfo->video_idle = 1;
			}

			BSD_STEER("ifname: %s, video_idle=%d\n",
				bssinfo->ifnames, bssinfo->video_idle);
			bssinfo->tx_tot_pkts = tx_tot_pkts;
			bssinfo->rx_tot_pkts = rx_tot_pkts;
		}
	}

	BSD_EXIT();
}


/* remove dead STA from list */
void bsd_timeout_sta(bsd_info_t *info)
{
	bsd_intf_info_t *intf_info;
	bsd_bssinfo_t *bssinfo;
	int idx, bssidx;
	bsd_sta_info_t *sta, *next, *prev, *head;
	time_t now = time(NULL);

	BSD_ENTER();

	for (idx = 0; idx < BSD_MAX_INTF; idx++) {
		intf_info = &(info->intf_info[idx]);
		BSD_INFO("idx=%d\n", idx);

		for (bssidx = 0; bssidx < WL_MAXBSSCFG; bssidx++) {
			bssinfo = &(intf_info->bsd_bssinfo[bssidx]);

			if (!(bssinfo->valid))
				continue;
			if (bssinfo->steerflag & BSD_BSSCFG_NOTSTEER)
				continue;

			BSD_INFO("bssidx=%d intf:%s\n", bssidx, bssinfo->ifnames);

			sta = bssinfo->assoclist;
			head = NULL;
			prev = NULL;

			while (sta) {
				BSD_INFO("sta[%p]:"MACF" active=%lu\n",
					sta, ETHER_TO_MACF(sta->addr),
					(unsigned long)(sta->active));
				if (now - sta->active > info->sta_timeout) {
					next = sta->next;
					BSD_TO("free(to) sta[%p]:"MACF" now[%lu] active[%lu]\n",
						sta, ETHER_TO_MACF(sta->addr),
						(unsigned long)now,
						(unsigned long)(sta->active));

					free(sta);
					sta = next;

					if (prev)
						prev->next = sta;

					continue;
				}

				if (head == NULL)
					head = sta;

				prev = sta;
				sta = sta->next;
			}
			bssinfo->assoclist = head;
		}
	}
	BSD_EXIT();
}

/* Update stahisto list */
bsd_sta_histo_t *bsd_set_stahisto_by_addr(bsd_info_t *info, bsd_bssinfo_t *bssinfo,
	struct ether_addr *addr, bool add, bsd_sta_state_t state)
{
	int hash_idx, idx;
	bsd_sta_histo_t *sta;
	time_t now = time(NULL);

	BSD_ENTER();

	hash_idx = BSD_MAC_HASH(*addr);
	sta = info->stahisto[hash_idx];

	while (sta) {
		BSD_HISTO("cmp: sta[%p]:"MACF"\n", sta, ETHER_TO_MACF(sta->addr));
		if (eacmp(&(sta->addr), addr) == 0) {
			break;
		}
		sta = sta->next;
	}

	BSD_HISTO("sta[%p]\n", sta);

	if (!sta && add) {
		sta = malloc(sizeof(bsd_sta_histo_t));
		if (!sta) {
			BSD_INFO("%s@%d: Malloc failure\n", __FUNCTION__, __LINE__);
			return NULL;
		}

		memset(sta, 0, sizeof(bsd_sta_histo_t));
		memcpy(&sta->addr, addr, sizeof(struct ether_addr));
		sta->next = info->stahisto[hash_idx];
		info->stahisto[hash_idx] = sta;
	}

	if (sta) {
		idx = sta->idx;
		sta->idx = (sta->idx + 1) % (BSD_MAX_STA_HISTO);
		sta->status[idx].state = state;

		sta->status[idx].timestamp = sta->timestamp = now;
		sta->status[idx].bssinfo = bssinfo;
		sta->band |= (bssinfo->intf_info)->band;

		BSD_HISTO("sta[%p]:"MACF" Band:%d\n", sta, ETHERP_TO_MACF(addr), sta->band);
	}

	BSD_EXIT();
	return sta;
}

/* Update stahisto list */
bsd_sta_histo_t *bsd_stahisto_by_addr(bsd_info_t *info, struct ether_addr *addr)
{
	int idx;
	bsd_sta_histo_t *sta;

	BSD_ENTER();

	idx = BSD_MAC_HASH(*addr);
	sta = info->stahisto[idx];

	while (sta) {
		BSD_HISTO("cmp: sta[%p]:"MACF"\n", sta, ETHER_TO_MACF(sta->addr));
		if (eacmp(&(sta->addr), addr) == 0) {
			break;
		}
		sta = sta->next;
	}

	BSD_HISTO("sta[%p]\n", sta);

	BSD_EXIT();
	return sta;
}

/* timeout stahisto-list */
void bsd_timeout_stahisto(bsd_info_t *info)
{
	int idx;
	bsd_sta_histo_t *sta, *next, *head, *prev;
	time_t now = time(NULL);

	BSD_ENTER();
	BSD_INFO("now[%lu]\n", (unsigned long)now);

	for (idx = 0; idx < BSD_PROBE_STA_HASH; idx++) {
		sta = info->stahisto[idx];
		head = NULL;
		prev = NULL;

		while (sta) {
			BSD_PROB("sta[%p]:"MACF" timestamp=%lu\n",
				sta, ETHER_TO_MACF(sta->addr),
				(unsigned long)(sta->timestamp));
			if (now - sta->timestamp > info->stahisto_timeout) {
				next = sta->next;
				BSD_TO("sta[%p]:"MACF"now[%lu] timestamp[%lu]\n",
					sta, ETHER_TO_MACF(sta->addr),
					(unsigned long)now,
					(unsigned long)(sta->timestamp));

				free(sta);
				sta = next;

				if (prev)
					prev->next = sta;

				continue;
			}

			if (head == NULL)
				head = sta;

			prev = sta;
			sta = sta->next;
		}
		info->stahisto[idx] = head;
	}

	BSD_EXIT();
}


/* serach probe list */
bsd_maclist_t *bsd_prbsta_by_addr(bsd_info_t *info, struct ether_addr *addr, bool enable)
{
	int idx;
	bsd_maclist_t *sta;

	BSD_PROB("Enter...\n");

	idx = BSD_MAC_HASH(*addr);
	sta = info->prbsta[idx];

	while (sta) {
		BSD_PROB("cmp: sta[%p]:"MACF"\n", sta, ETHER_TO_MACF(sta->addr));
		if (eacmp(&(sta->addr), addr) == 0) {
			break;
		}
		sta = sta->next;
	}

	if (!sta && enable) {
		sta = malloc(sizeof(bsd_maclist_t));
		if (!sta) {
			BSD_PROB("%s@%d: Malloc failure\n", __FUNCTION__, __LINE__);
			return NULL;
		}

		memset(sta, 0, sizeof(bsd_maclist_t));
		memcpy(&sta->addr, addr, sizeof(struct ether_addr));

		sta->timestamp = time(NULL);

		sta->next = info->prbsta[idx];
		info->prbsta[idx] = sta;

		BSD_PROB("sta[%p]:"MACF"\n", sta, ETHERP_TO_MACF(addr));
	}

	BSD_PROB("Exit...\n");
	return sta;
}


/* add probe STA from list */
void bsd_add_prbsta(bsd_info_t *info, char *ifname, uint8 remote, struct ether_addr *addr)
{
	bsd_bssinfo_t *bssinfo;
	bsd_maclist_t *sta;

	BSD_PROB("Entering...\n");

	bssinfo = bsd_bssinfo_by_ifname(info, ifname, remote);

	if (!bssinfo) {
		BSD_PROB("%s: not found ifname:%s\n", __FUNCTION__, ifname);
		return;
	}


	sta = bsd_prbsta_by_addr(info, addr, TRUE);
	if (sta) {
		sta->timestamp = time(NULL);
		sta->band |= bssinfo->intf_info->band;
	}

	BSD_PROB("Exit...\n");
}


/* timeout probe-list */
void bsd_timeout_prbsta(bsd_info_t *info)
{
	int idx;
	bsd_maclist_t *sta, *next, *head, *prev;
	time_t now = time(NULL);

	BSD_ENTER();
	BSD_INFO("now[%lu]\n", (unsigned long)now);

	for (idx = 0; idx < BSD_PROBE_STA_HASH; idx++) {
		sta = info->prbsta[idx];
		head = NULL;
		prev = NULL;

		while (sta) {
			BSD_INFO("sta[%p]:"MACF" timestamp=%lu\n",
				sta, ETHER_TO_MACF(sta->addr),
				(unsigned long)(sta->timestamp));
			if (now - sta->timestamp > info->probe_timeout) {
				next = sta->next;
				BSD_TO("sta[%p]:"MACF"now[%lu] timestamp[%lu]\n",
					sta, ETHER_TO_MACF(sta->addr),
					(unsigned long)now,
					(unsigned long)(sta->timestamp));

				free(sta);
				sta = next;

				if (prev)
					prev->next = sta;

				continue;
			}

			if (head == NULL)
				head = sta;

			prev = sta;
			sta = sta->next;
		}
		info->prbsta[idx] = head;
	}

	BSD_EXIT();
}

/* timeout maclist  */
void bsd_timeout_maclist(bsd_info_t *info)
{
	bsd_intf_info_t *intf_info;
	bsd_bssinfo_t *bssinfo;
	int idx, bssidx;
	bsd_maclist_t *sta, *head, *prev, *next;
	time_t now = time(NULL);

	BSD_ENTER();

	for (idx = 0; idx < BSD_MAX_INTF; idx++) {
		intf_info = &(info->intf_info[idx]);
		BSD_INFO("idx=%d\n", idx);

		for (bssidx = 0; bssidx < WL_MAXBSSCFG; bssidx++) {
			bssinfo = &(intf_info->bsd_bssinfo[bssidx]);
			if (!(bssinfo->valid))
				continue;
			if (bssinfo->steerflag & BSD_BSSCFG_NOTSTEER)
				continue;

			BSD_INFO("maclist[bssidx:%d] ifname:%s...\n", bssidx, bssinfo->ifnames);

			sta = bssinfo->maclist;
			head = NULL;
			prev = NULL;

			while (sta) {
				BSD_INFO("sta[%p]:"MACF" timestamp=%lu\n",
					sta, ETHER_TO_MACF(sta->addr),
					(unsigned long)(sta->timestamp));
				if (now - sta->timestamp > info->maclist_timeout) {
					next = sta->next;
					BSD_TO("sta[%p]:"MACF"now[%lu] timestamp[%lu]\n",
						sta, ETHER_TO_MACF(sta->addr),
						(unsigned long)now,
						(unsigned long)(sta->timestamp));

					free(sta);
					sta = next;

					if (prev)
						prev->next = sta;

					continue;
				}

				if (head == NULL)
					head = sta;

				prev = sta;
				sta = sta->next;
			}
			bssinfo->maclist = head;
			/* reset maclist */
			bsd_set_maclist(bssinfo);
		}
	}

	BSD_EXIT();
}

void bsd_update_cca_stats(bsd_info_t *info)
{
	bsd_intf_info_t *intf_info;
	bsd_bssinfo_t *bssinfo;
	uint8 idx, cnt;

	int ret = 0;
	wl_chanim_stats_t *list;
	wl_chanim_stats_t param;
	int buflen = BSD_IOCTL_MAXLEN;
	chanim_stats_t *stats;

	char *ptr;
	int tlen;

	BSD_CCAENTER();

	for (cnt = 0; cnt < 2; cnt++) {
		intf_info = &(info->intf_info[info->ifidx]);
		bssinfo = &(intf_info->bsd_bssinfo[info->bssidx]);

		if (cnt) {
			bssinfo = bssinfo->steer_bssinfo;
			intf_info = bssinfo->intf_info;
		}

		BSD_CCA("tick[%d] cnt[%d] idx[%d] intf_info[%p] bssinfo[%p]"
			" [%s] period[%d] cnt[%d]\n",
			intf_info->chan_util_info.ticks, cnt, intf_info->chan_util_info.idx,
			intf_info, bssinfo, bssinfo->ifnames,
			intf_info->chan_util_info.period, intf_info->chan_util_info.cnt);

		intf_info->chan_util_info.ticks += 1;

		if (intf_info->chan_util_info.period) {
			intf_info->chan_util_info.ticks %= intf_info->chan_util_info.period;
			if (intf_info->chan_util_info.ticks != 0)
				continue;
		}
		intf_info->chan_util_info.ticks = 0;

		BSD_CCA("Read cca stats from %s[%d][%d]\n", bssinfo->ifnames,
			intf_info->idx, bssinfo->idx);

		list = (wl_chanim_stats_t *) ioctl_buf;

		memset(&param, 0, sizeof(param));
		param.buflen = buflen;
		param.count = 1;
		param.version = WL_CHANIM_STATS_VERSION;

		memset(ioctl_buf, 0, sizeof(ioctl_buf));
		strcpy(ioctl_buf, "chanim_stats");
		tlen = strlen(ioctl_buf) + 1;
		ptr = (char *)(ioctl_buf + tlen);
		memcpy(ptr, &param, sizeof(wl_chanim_stats_t));

		BSD_RPC("---RPC name:%s cmd: %d(WLC_GET_VAR: chanim_stats) tlen=%d\n",
			bssinfo->ifnames, WLC_GET_VAR, tlen);
		bsd_rpc_dump((char *)ioctl_buf, 64, BSD_RPC_ENAB);

		ret = bsd_wl_ioctl(bssinfo, WLC_GET_VAR, ioctl_buf,
			sizeof(ioctl_buf)-BSD_RPC_HEADER_LEN);

		if (ret < 0) {
			BSD_ERROR("Err: intf:%s chanim_stats\n", bssinfo->ifnames);
			return;
		}

		BSD_CCA("ret:%d buflen: %d, version: %d count: %d\n",
			ret, list->buflen, list->version, list->count);

		if (list->version != WL_CHANIM_STATS_VERSION) {
			BSD_ERROR("Err: chanim_stats version %d doesn't match %d\n",
				list->version, WL_CHANIM_STATS_VERSION);
			BSD_CCAEXIT();
			return;
		}

		stats = list->stats;

		BSD_CCA_PLAIN("chanspec   tx   inbss   obss   nocat   nopkt   doze     txop     "
			   "goodtx  badtx   glitch   badplcp  knoise  timestamp   idle\n");
		BSD_CCA_PLAIN("0x%4x\t", stats->chanspec);

		for (idx = 0; idx < CCASTATS_MAX; idx++)
			BSD_CCA_PLAIN("%d\t", stats->ccastats[idx]);
		BSD_CCA_PLAIN("%d\t%d\t%d\t%d\t%d\n", stats->glitchcnt, stats->badplcp,
			stats->bgnoise, stats->timestamp, stats->chan_idle);

		idx = intf_info->chan_util_info.idx;
		memcpy(&(intf_info->chan_util_info.rec[idx].stats), list->stats,
			sizeof(chanim_stats_t));
		intf_info->chan_util_info.rec[idx].valid = 1;

		intf_info->chan_util_info.idx =
			MODINC((intf_info->chan_util_info.idx), BSD_CHANIM_STATS_MAX);
	}

	BSD_CCAEXIT();
	return;
}

/* chan busy detection: may need to be a generic algo */
void bsd_reset_chan_busy(bsd_info_t *info)
{
	bsd_intf_info_t *intf_info;
	bsd_bssinfo_t *bssinfo;
	uint8 idx, cnt, num;

	bsd_chan_util_info_t *chan_util_info;
	bsd_chanim_stats_t *rec;
	chanim_stats_t *stats;

	BSD_CCAENTER();

	intf_info = &(info->intf_info[info->ifidx]);
	bssinfo = &(intf_info->bsd_bssinfo[info->bssidx]);
	chan_util_info = &intf_info->chan_util_info;
	cnt = chan_util_info->cnt;

	idx = MODDEC(chan_util_info->idx, BSD_CHANIM_STATS_MAX);
	BSD_CCA("invalid ccs: ifname:%s[remote:%d] rec[%d] for %d\n",
		bssinfo->ifnames, intf_info->remote, idx, cnt);
	for (num = 0; num < cnt; num++) {
		rec = &(intf_info->chan_util_info.rec[idx]);
		stats = &rec->stats;
		rec->valid = 0;
		idx = MODINC(idx, BSD_CHANIM_STATS_MAX);
		BSD_CCA("invalid: rec[%d] idle[%d]\n", idx, stats->ccastats[CCASTATS_TXOP]);
	}

	BSD_CCAEXIT();
	return;
}
