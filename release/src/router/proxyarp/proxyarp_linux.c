/*
 * Proxy ARP Linux Port: These functions handle the interface between Proxy ARP
 * and the native OS.
 *
 * Copyright (C) 2012, Broadcom Corporation
 * All Rights Reserved.
 * 
 * This is UNPUBLISHED PROPRIETARY SOURCE CODE of Broadcom Corporation;
 * the contents of this file may not be disclosed to third parties, copied
 * or duplicated in any form, in whole or in part, without the prior
 * written permission of Broadcom Corporation.
 *
 * $Id: proxyarp_linux.c 314649 2012-02-13 22:07:58Z $
 */
#include <linux/module.h>
#include <bcmnvram.h>
#include <bcmutils.h>
#include <osl.h>
#include <proxyarp/proxyarp.h>

MODULE_LICENSE("Proprietary");

static proxyarp_info_t spa_info;
static struct timer_list pa_timer;
static spinlock_t pa_lock;

void inline
proxyarp_lock(proxyarp_info_t *pah)
{
	spin_lock_bh((spinlock_t *)pah->lock);
}

void inline
proxyarp_unlock(proxyarp_info_t *pah)
{
	spin_unlock_bh((spinlock_t *)pah->lock);
}
#define PROXYARP_WATCHDOG_INTERVAL		HZ * 2
static void
proxyarp_watchdog(ulong data)
{
	struct timer_list *timer;
	proxyarp_info_t *pah = (proxyarp_info_t *)data;
	if (pah->count) {
		_proxyarp_watchdog(FALSE, NULL);
	}

	timer = (struct timer_list *)pah->timer;
	timer->expires = jiffies + PROXYARP_WATCHDOG_INTERVAL;
	add_timer(timer);
}

static int32 __init
proxyarp_module_init(void)
{
	proxyarp_info_t *pah = &spa_info;
	bzero(pah, sizeof(proxyarp_info_t));
	bzero(&pa_timer, sizeof(struct timer_list));
	bzero(&pa_lock, sizeof(spinlock_t));

	/* init osl handle */
	pah->osh = osl_attach(NULL, PCI_BUS, FALSE);
	if (pah->osh == NULL) {
		goto init_error;
	}

	/* init osl lock */
	pah->lock = (void *)&pa_lock;
	spin_lock_init((spinlock_t *)pah->lock);

	pah->timer = (void *)&pa_timer;
	init_timer(&pa_timer);
	pa_timer.data = (ulong)pah;
	pa_timer.function = proxyarp_watchdog;
	pa_timer.expires = jiffies + HZ;
	add_timer(&pa_timer);

	proxyarp_init(pah);

	return 0;

init_error:
	/* deinit osl timer */
	if (pah->timer) {
		del_timer((struct timer_list *)pah->timer);
	}

	/* deinit osh handler */
	if (pah->osh) {
		osl_detach(pah->osh);
	}

	return -1;
}

static void __exit
proxyarp_module_exit(void)
{
	proxyarp_info_t *pah = &spa_info;

	proxyarp_deinit();

	/* deinit osl timer */
	if (pah->timer) {
		del_timer((struct timer_list *)pah->timer);
	}

	/* deinit osh handler */
	if (pah->osh) {
		osl_detach(pah->osh);
	}
	return;
}

module_init(proxyarp_module_init);
module_exit(proxyarp_module_exit);
