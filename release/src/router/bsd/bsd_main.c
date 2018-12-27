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
 * $Id: bsd_main.c $
 */
#include "bsd.h"

bsd_info_t *bsd_info;
int bsd_msglevel = BSD_DEBUG_ERROR;
static bsd_info_t *bsd_info_alloc(void)
{
	bsd_info_t *info;

	BSD_ENTER();

	info = (bsd_info_t *)malloc(sizeof(bsd_info_t));
	if (info == NULL) {
		BSD_PRINT("malloc fails\n");
	}
	else {
		memset(info, 0, sizeof(bsd_info_t));
		BSD_INFO("info=%p\n", info);
	}

	BSD_EXIT();
	return info;
}

static int
bsd_init(bsd_info_t *info)
{
	int err = BSD_FAIL;
	char *str, *endptr = NULL;
	char tmp[16];

	BSD_ENTER();


	info->version = BSD_VERSION;
	info->event_fd = BSD_DFLT_FD;
	info->rpc_listenfd  = BSD_DFLT_FD;
	info->rpc_eventfd = BSD_DFLT_FD;
	info->rpc_ioctlfd = BSD_DFLT_FD;
	info->poll_interval = BSD_POLL_INTERVAL;
	info->mode = BSD_MODE_STEER;
	info->role = BSD_ROLE_STANDALONE;
	info->status_poll = BSD_STATUS_POLL_INTV;
	info->counter_poll = BSD_COUNTER_POLL_INTV;
	info->idle_rate = 10;

	if ((str = nvram_get("bsd_role"))) {
		info->role = (uint8)strtol(str, &endptr, 0);
		if (info->role >= BSD_ROLE_MAX) {
			BSD_ERROR("Err: bsd_role[%s] set to Primary.\n", str);
			info->role = BSD_ROLE_STANDALONE;
			sprintf(tmp, "%d", info->role);
			nvram_set("bsd_role", tmp);
		}
	}

	if ((str = nvram_get("bsd_helper"))) {
		BSDSTRNCPY(info->helper_addr, str, sizeof(info->helper_addr) - 1);
	}
	else {
		strcpy(info->helper_addr, BSD_DEFT_HELPER_ADDR);
		nvram_set("bsd_helper", BSD_DEFT_HELPER_ADDR);
	}

	info->hport = HELPER_PORT;
	if ((str = nvram_get("bsd_hport"))) {
		info->hport = (uint16)strtol(str, &endptr, 0);
	} else {
		sprintf(tmp, "%d", info->hport);
		nvram_set("bsd_hport", tmp);
	}

	if ((str = nvram_get("bsd_primary"))) {
		BSDSTRNCPY(info->primary_addr, str, sizeof(info->primary_addr) - 1);
	}
	else {
		strcpy(info->primary_addr, BSD_DEFT_PRIMARY_ADDR);
		nvram_set("bsd_primary", BSD_DEFT_PRIMARY_ADDR);
	}

	info->pport = PRIMARY_PORT;
	if ((str = nvram_get("bsd_pport"))) {
		info->pport = (uint16)strtol(str, &endptr, 0);
	}
	else {
		sprintf(tmp, "%d", info->pport);
		nvram_set("bsd_pport", tmp);
	}

	BSD_INFO("role:%d helper:%s[%d] primary:%s[%d]\n",
		info->role, info->helper_addr, info->hport,
		info->primary_addr, info->pport);

	info->scheme = BSD_SCHEME;
	if ((str = nvram_get("bsd_scheme"))) {
		info->scheme = (uint8)strtol(str, &endptr, 0);
		if (info->scheme >= bsd_get_max_scheme(info))
			info->scheme = BSD_SCHEME;
	}
	BSD_INFO("scheme:%d\n", info->scheme);

	err = bsd_info_init(info);
	if (err == BSD_OK) {
		bsd_retrieve_config(info);
		err = bsd_open_eventfd(info);
		if (err == BSD_OK)
			err = bsd_open_rpc_eventfd(info);
	}

	BSD_EXIT();
	return err;
}

static void
bsd_cleanup(bsd_info_t*info)
{
	if (info) {
		bsd_close_eventfd(info);
		bsd_close_rpc_eventfd(info);
		bsd_bssinfo_cleanup(info);
		free(info);
	}
}

static void
bsd_watchdog(bsd_info_t*info, uint ticks)
{

	BSD_ENTER();

	BSD_TO("\nticks[%d] [%lu]\n", ticks, (unsigned long)time(NULL));

	if ((info->role != BSD_ROLE_PRIMARY) &&
		(info->role != BSD_ROLE_STANDALONE)) {
		BSD_TO("no Watchdog operation fro helper...\n");
		BSD_EXIT();
		return;
	}

	if ((info->counter_poll != 0) && (ticks % info->counter_poll == 1)) {
		BSD_TO("bsd_update_counters [%d] ...\n", info->counter_poll);
		bsd_update_stb_info(info);
	}

	if ((info->status_poll != 0) && (ticks % info->status_poll == 1)) {
		BSD_TO("bsd_update_stainfo [%d] ...\n", info->status_poll);
		bsd_update_stainfo(info);
	}
	bsd_update_cca_stats(info);

	bsd_check_steer(info);

	if ((info->probe_timeout != 0) && (ticks % info->probe_timeout == 0)) {
		BSD_TO("bsd_timeout_prbsta [%d] ...\n", info->probe_timeout);
		bsd_timeout_prbsta(info);
	}

	if ((info->maclist_timeout != 0) && (ticks % info->maclist_timeout == 0)) {
		BSD_TO("bsd_timeout_maclist [%d] ...\n", info->maclist_timeout);
		bsd_timeout_maclist(info);
	}

	if ((info->sta_timeout != 0) &&(ticks % info->sta_timeout == 0)) {
		BSD_TO("bsd_timeout_sta [%d] ...\n", info->sta_timeout);
		bsd_timeout_sta(info);
	}

	if ((info->stahisto_timeout != 0) && (ticks % info->stahisto_timeout == 0)) {
		BSD_TO("bsd_timeout_stahisto [%d] ...\n", info->stahisto_timeout);
		bsd_timeout_stahisto(info);
	}

	BSD_EXIT();
}

static void bsd_hdlr(int sig)
{
	bsd_info->mode = BSD_MODE_DISABLE;
	return;
}

/* service main entry */
int main(int argc, char *argv[])
{
	int err = BSD_OK;
	struct timeval tv;
	char *val;
	int role;

	val = nvram_safe_get("bsd_role");
	role = strtoul(val, NULL, 0);
	if ((role != BSD_ROLE_PRIMARY) &&
		(role != BSD_ROLE_HELPER) &&
		(role != BSD_ROLE_STANDALONE)) {
		printf("BSD is not enabled: %s=%d\n", val, role);
		goto done;
	}

	val = nvram_safe_get("bsd_msglevel");
	if (strcmp(val, ""))
		bsd_msglevel = strtoul(val, NULL, 0);

	BSD_INFO("bsd start...\n");

	val = nvram_safe_get("acs_ifnames");
	if (!strcmp(val, "")) {
		BSD_ERROR("No interface specified, exiting...");
		return err;
	}

#if !defined(DEBUG)
	if (daemon(1, 1) == -1) {
		BSD_ERROR("err from daemonize.\n");
		goto done;
	}
#endif

	if ((bsd_info = bsd_info_alloc()) == NULL) {
		printf("BSD alloc fails. Aborting...\n");
		goto done;
	}

	if (bsd_init(bsd_info) != BSD_OK) {
		printf("BSD Aborting...\n");
		goto done;
	}

	tv.tv_sec = bsd_info->poll_interval;
	tv.tv_usec = 0;

	signal(SIGTERM, bsd_hdlr);

	while (bsd_info->mode != BSD_MODE_DISABLE) {

		if (tv.tv_sec == 0 && tv.tv_usec == 0) {
			bsd_info->ticks ++;
			tv.tv_sec = bsd_info->poll_interval;
			tv.tv_usec = 0;
			BSD_INFO("ticks: %d\n", bsd_info->ticks);

			bsd_watchdog(bsd_info, bsd_info->ticks);

			val = nvram_safe_get("bsd_msglevel");
			if (strcmp(val, ""))
				bsd_msglevel = strtoul(val, NULL, 0);

		}
		bsd_proc_socket(bsd_info, &tv);
	}

done:
	bsd_cleanup(bsd_info);
	return err;
}
