/*****************************************************************************
 * bta adaptation layer
 * bta_cfg.h
 * Header file for bta cfg layer
 * Copyright (C) 2014, Broadcom Corporation
 * All Rights Reserved.
 * 
 * This is UNPUBLISHED PROPRIETARY SOURCE CODE of Broadcom Corporation;
 * the contents of this file may not be disclosed to third parties, copied
 * or duplicated in any form, in whole or in part, without the prior
 * written permission of Broadcom Corporation.
 * $Id: bta_cfg.h,v 1.1 2010-03-08 22:38:35 $
 *****************************************************************************
*/


#if !defined(__bta_cfg_h__)
#define __bta_cfg_h__

extern int
btaparent_cfg(struct wpa_dat *dat);

extern int
btaparent_cleanup(struct wpa_dat *dat);

extern void
bta_events(void *ctx, void *priv);

extern void
bta_parent_events(void *ctx, void *priv);

#endif /* __bta_cfg_h__ */
