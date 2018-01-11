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
 * $Id: bcmseclib_api.h,v 1.3 2010-08-09 19:28:58 $
*/

#ifndef _CFG_API_H_
#define _CFG_API_H_

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Usage model
 * Startup/init the security library:
 * bcmseclib_init(struct maincbs *cbfns);
 * Return value indicates success/failure
 *
 * Create and run separate thread for bcmseclib_run()
 * Returns when terminated via bcmseclib_deinit() or unrecoverable error occurs.
 * 
 * Allocate a ctx (if possible):
 * bcmseclib_ctx_init(clientdata_t *client, struct ctxcbs *cbfns);
 * Upon success:
 * cb fun gives ctx pointer for caller's future reference
 * 
 *
 * Set a configuration (e.g. p2p) on the ctx created above
 * bcmseclib_set_config(struct sec_args *args, bcmseclib_ctx_t *ctx);
 * cb fun advises of success/failure
 *
 *
 * Termination:
 * De-init a ctx: frees resources used by this ctx
 * bcmseclib_ctx_cleanup(bcmseclib_ctx_t *ctx);
 * cb fun advises of status
 *
 * Terminate everything:
 * Frees all resources used by this library, terminates bcmseclib_run thread.
 * bcmseclib_deinit(void);
 * cb fun advises of status
 * [Other] ctx holders will receive error/termination message
 * via their registered callbacks
 *
 */


typedef void bcmseclib_ctx_t;
/* Callback functions */

/* Registered at init time
 * Called upon termination
 */
struct maincbs {
   void (*main_status)(int status);
};

struct ctxcbs {
	
	/* Notes on callback function cfg_status
	 * ctx is returned by bcmseclib_ctx_init call, valid only if status == ok
	 * client_data returned by all
	 * status returned by all, zero for ok, non-zero otherwise
	 */
   void (*cfg_status)(void *ctx, clientdata_t * client_data, int status);

   void (*event)(void *ctx, clientdata_t *client_data, const void *data);
};


/* startup
 * register error callback function
 * setup timers, allocate data structures ...
 * returns zero if successful, non-zero otherwise
 */
int bcmseclib_init(struct maincbs *cbfns);

/* run it:
 * This is the thread containing the dispatch loop.
 * Blocks on [io descriptors]
 * Only returns if error or terminated by bcmseclib_deinit
 */
int bcmseclib_run();


/* shutdown: terminate everything
 * disconnect, close descriptors, free memory, ...
 * Status reported in main_status cb
 * 
 */
int bcmseclib_deinit(void);

/* [re]configure */

#define CFG_MAX_USER_KEY_LEN	80
/* outsized to hold windows names */
#define MAX_IF_NAME_SIZE	80
/* Not all done! */
struct sec_args {
	char ifname[MAX_IF_NAME_SIZE + 1]; /* NULL terminated string */
	int	service;	/* wlan, btamp, other, ... */
	int role;		/* auth/supp */
	int WPA_auth;	/* WPA authentication mode bitvec, wlioctl.h */
	int wsec;	/* wireless security bitvec, wlioctl.h */
	int btamp_enabled;	/* this cfg is for btamp */
	uint8 ssid[DOT11_MAX_SSID_LEN];	/* ssid */
	int ssid_len;		/* ssid len */
	uint8 psk[CFG_MAX_USER_KEY_LEN];		/* passphrase */
	int psk_len;		/* passphrase len */
	int bsscfg_index;	/* bsscfg index */
	char pin[9]; /* wps pin (asciiz) */
	uint16 key_index; /* key index */
	uint8 peer_mac_addr[6];

	/* code will be TRUE for success, FALSE for failure (for a reason)
	 * reason is only valid for FALSE code
	 * TRUE means successful handshake & keys plumbed
	 * Reason values from src/include/proto/wpa.h
	 * 
	 * May be NULL if no reports desired.
	 */
   void (*result)(clientdata_t *, unsigned char code, unsigned char reason);

	/* Forward 8021x frames, events if desired
	 * Just set to NULL if no forwarding desired
	 */
	void (*cb_8021x)(clientdata_t *client, char *frame, int len);
	void (*cb_event)(clientdata_t *client, char *frame, int len);

	/* Other elements? WAPI et al
	 * Add them here ...
	 */

};


/* Init ctx, client is caller private, will be used as arg in cb funs
 * Status is reported by cb function supplied in arg list
 */
void bcmseclib_ctx_init(clientdata_t *client, struct ctxcbs *cbfns);

/* Shutdown "this" ctx
 * Use the ctx pointer returned by bcmseclib_ctx_init
 * returns status in previously registered cbfn
 */
void bcmseclib_ctx_cleanup(bcmseclib_ctx_t *ctx);

/* Use the ctx pointer from call to bcmseclib_ctx_init
 * Set the cfg for "this" ctx
 * Callback advises success/failure
 */
void bcmseclib_set_config(struct sec_args *args, bcmseclib_ctx_t *ctx);

#ifdef __cplusplus
}
#endif

#endif /* _CFG_API_H_ */
