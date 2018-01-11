/* 
 * bta_svc.h
 * Header file for btamp svc funs
 * Copyright (C) 2014, Broadcom Corporation
 * All Rights Reserved.
 * 
 * This is UNPUBLISHED PROPRIETARY SOURCE CODE of Broadcom Corporation;
 * the contents of this file may not be disclosed to third parties, copied
 * or duplicated in any form, in whole or in part, without the prior
 * written permission of Broadcom Corporation.
 * $Id: bta_svc.h,v 1.1 2010-03-08 22:38:35 $
 */

#ifndef _bta_svc_h_
#define _bta_svc_h_

extern int
btaparent_svc_init(struct cfg_ctx *ctx);

extern int
btaparent_svc_deinit(struct cfg_ctx *ctx);

extern int
btaparent_svc_cfg(struct cfg_ctx *ctx, const struct cfg_ctx_set_cfg *cfg);

extern int
btachild_svc_sup_init(struct cfg_ctx *ctx);

extern int
btachild_svc_sup_deinit(struct cfg_ctx *ctx);

extern int
btachild_svc_auth_init(struct cfg_ctx *ctx);

extern int
btachild_svc_auth_deinit(struct cfg_ctx *ctx);


extern int
btachild_svc_cfg(struct cfg_ctx *ctx, const struct cfg_ctx_set_cfg *cfg);


#endif /* _bta_svc_h_ */
