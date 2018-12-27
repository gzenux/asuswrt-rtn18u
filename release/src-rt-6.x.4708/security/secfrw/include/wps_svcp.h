/*****************************************************************************
 * wps service (private)
 *
 * Copyright (C) 2014, Broadcom Corporation
 * All Rights Reserved.
 * 
 * This is UNPUBLISHED PROPRIETARY SOURCE CODE of Broadcom Corporation;
 * the contents of this file may not be disclosed to third parties, copied
 * or duplicated in any form, in whole or in part, without the prior
 * written permission of Broadcom Corporation.
 *****************************************************************************
*/

#if !defined(__wps_svcp_h__)
#define __wps_svcp_h__


struct wps_svc_dat {
	struct bind_sk *eapol_sk, *wlss_sk;
	void *eapol_binding, *wlss_binding;
#if defined(WPS_SVC_PRIVATE)
	struct wps_dat wps_dat;
#endif /* defined(WPS_SVC_PRIVATE) */
};

#endif /* !defined(__wps_svcp_h__) */
