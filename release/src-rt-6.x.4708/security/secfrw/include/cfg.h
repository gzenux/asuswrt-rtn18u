/*
 * cfg.h
 * Platform independent internal configuration functions
 *
 * Copyright (C) 2014, Broadcom Corporation
 * All Rights Reserved.
 * 
 * This is UNPUBLISHED PROPRIETARY SOURCE CODE of Broadcom Corporation;
 * the contents of this file may not be disclosed to third parties, copied
 * or duplicated in any form, in whole or in part, without the prior
 * written permission of Broadcom Corporation.
 *
 * $Id: cfg.h,v 1.3 2010-08-09 19:28:58 $
*/

#ifndef _CFG_H_
#define _CFG_H_

#define CFG_MAX_HANDLES		4
/* Data structures for maintaining per ctx info */


struct svc;
struct pp_dat;

struct cfg_ctx {
/* public */
	struct cfg_ctx *next;

	unsigned char is_cfgd : 1;

	void *client_data;
	struct ctxcbs ctx_cb;
	
	const struct dev *dev;		/* device interface */

	struct svc *svc;			/* service interface */
	void *svc_dat;				/* service data */

	struct pp_dat *pp_dat;		/* per-port data */

	struct cfg_ctx *parent;		/* this ctx's parent: NULL if none */

#if defined(CFG_CTX_PRIVATE)
/* private */
	union svc_dat {
		struct wpa_svc_dat wpa;
		struct wps_svc_dat wps;
	} u_svc_dat;
#endif /* defined(CFG_CTX_PRIVATE) */
};

/* Data structures and messages we receive from the dispatcher's cfg input */
enum {
	CFG_CTX_INIT = 1,
	CFG_CTX_SET_CFG,
	CFG_CTX_DEINIT,
	CFG_TERMINATE_REQUEST,
	/* more to come ... */
};

typedef struct cfg_msg {
	int version;
	int type;			/* ctx req, config req, ... */
	void *ctx;			/* ctx pointer, may be NULL */
	int reserved;		/* for future (undefined) use */
	/* data follows */
} cfg_msg_t;


/* CFG_CTX_INIT msg data:
 * struct ctxcbs defined in bcmseclib_api.h
 */
typedef struct cfg_ctx_init {
	cfg_msg_t hdr;
	struct ctxcbs cbfns;
	clientdata_t *client;
}cfg_ctx_init_t;

/* CFG_CTX_SET_CFG msg data from struct sec_arg_t in bcmseclib_api.h */
typedef struct cfg_ctx_set_cfg {
	cfg_msg_t hdr;
	struct sec_args args;
}cfg_ctx_set_cfg_t;

/* CFG_CTX_DEINIT msg data:
 * Do we need any data at all for this?
 */
typedef struct cfg_ctx_deinit {
	cfg_msg_t hdr;
}cfg_ctx_deinit_t;

/* CFG_TERMINATE_REQUEST msg data */
typedef struct cfg_terminate {
	cfg_msg_t hdr;
} cfg_terminate_t;

/* Process [de]configuration requests
 * Issue callback function (previously registered by cfg api)
 * upon completion
 */
void cfg_process_cfgmsg(void *pkt);


/* Verify ctx arg actually points to valid ctx */
bool cfg_validate_ctx(void *ctx);

extern int
btaparent_create_child(struct cfg_ctx * ctx, uint8 bssidx, uint8 role);

extern int
btaparent_destroy_child(struct cfg_ctx * ctx, uint8 bssidx, uint8 role);

#endif /* _CFG_H_ */
