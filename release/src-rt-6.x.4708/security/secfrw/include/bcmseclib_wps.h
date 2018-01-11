/*
 * cfg_api.h
 * Platform independent configuration interface
 *
 * Copyright (C) 2014, Broadcom Corporation
 * All Rights Reserved.
 * 
 * This is UNPUBLISHED PROPRIETARY SOURCE CODE of Broadcom Corporation;
 * the contents of this file may not be disclosed to third parties, copied
 * or duplicated in any form, in whole or in part, without the prior
 * written permission of Broadcom Corporation.
 *
 * $Id: bcmseclib_wps.h,v 1.1 2010-08-09 19:28:58 $
*/

#ifndef __BCMSECLIB_EV_WPS_H__
#define __BCMSECLIB_EV_WPS_H__

#ifdef __cplusplus
extern "C" {
#endif


struct bcmseclib_ev_wps {
	brcm_wpscli_status status;
	union {
		char msg_type;
		brcm_wpscli_nw_settings nw_settings;
		uint8 peer_mac_addr[6];
	} u;
};


#ifdef __cplusplus
}
#endif

#endif /* __BCMSECLIB_EV_WPS_H__ */
