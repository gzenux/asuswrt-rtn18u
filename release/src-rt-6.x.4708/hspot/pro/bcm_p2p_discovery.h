/*
 * P2P discovery state machine.
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

#ifndef _BCM_P2P_DISCOVERY_H_
#define _BCM_P2P_DISCOVERY_H_

typedef struct bcm_p2p_discovery bcm_p2p_discovery_t;

/* Opaque driver handle type. In dongle this is struct wlc_info_t, representing
 * the driver. On linux host this is struct ifreq, representing the primary OS
 * interface for a driver instance. To specify a virtual interface this should
 * be used together with a bsscfg index.
 */
struct bcm_p2p_discovery_wl_drv_hdl;

/* initialize P2P discovery */
int bcm_p2p_discovery_initialize(void);

/* deinitialize P2P discovery */
int bcm_p2p_discovery_deinitialize(void);

/* create P2P discovery */
bcm_p2p_discovery_t *bcm_p2p_discovery_create(
	struct bcm_p2p_discovery_wl_drv_hdl *drv, uint16 listenChannel);

/* destroy P2P discovery */
int bcm_p2p_discovery_destroy(bcm_p2p_discovery_t *disc);

/* reset P2P discovery */
int bcm_p2p_discovery_reset(bcm_p2p_discovery_t *disc);

/* start P2P discovery */
int bcm_p2p_discovery_start_discovery(bcm_p2p_discovery_t *disc);

/* start P2P extended listen */
/* for continuous listen set on=non-zero (e.g. 5000), off=0 */
int bcm_p2p_discovery_start_ext_listen(bcm_p2p_discovery_t *disc,
	uint16 listenOnTimeout, uint16 listenOffTimeout);

/* get bsscfg index of P2P discovery interface */
/* bsscfg index is valid only after started */
int bcm_p2p_discovery_get_bsscfg_index(bcm_p2p_discovery_t *disc);

/* wlan event handler */
void bcm_p2p_discovery_process_wlan_event(void *context, uint32 eventType,
	wl_event_msg_t *wlEvent, uint8 *data, uint32 length);

#endif /* _BCM_P2P_DISCOVERY_H_ */
