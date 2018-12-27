/*****************************************************************************
 * WPS configuration declarations
 * Copyright (C) 2014, Broadcom Corporation
 * All Rights Reserved.
 * 
 * This is UNPUBLISHED PROPRIETARY SOURCE CODE of Broadcom Corporation;
 * the contents of this file may not be disclosed to third parties, copied
 * or duplicated in any form, in whole or in part, without the prior
 * written permission of Broadcom Corporation.
 * $Id: wps_cfg.h,v 1.1 2010-08-09 19:28:58 $
 *****************************************************************************
*/


#if !defined(__WPS_CFG_H__)
#define __WPS_CFG_H__

enum {
	WPS_SUP_SUCCESS,
	WPS_SUP_REG_FAILURE,
	WPS_SUP_CONT
};

struct wps_enr_cred {
	char ssid[32];
	uint32 ssid_len;
	char key_mgmt[20];
	char nw_key[64];
	uint32 new_key_len;
	uint32 encr_type;
	uint16 wep_index;
};

#endif /* !defined(__WPS_CFG_H__) */
