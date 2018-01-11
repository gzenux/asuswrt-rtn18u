/*
 * dispatcher.h
 * Platform independent interface to dispatch loop
 *
 * Copyright (C) 2014, Broadcom Corporation
 * All Rights Reserved.
 * 
 * This is UNPUBLISHED PROPRIETARY SOURCE CODE of Broadcom Corporation;
 * the contents of this file may not be disclosed to third parties, copied
 * or duplicated in any form, in whole or in part, without the prior
 * written permission of Broadcom Corporation.
 *
 * $Id: dispatcher.h,v 1.2 2010-03-08 22:49:20 $
*/

#ifndef _DISPATCHER_H_
#define _DISPATCHER_H_

typedef int (*PDISPFN)(void *ctx, void *frame, int length);
typedef void (*PCFGDISPFN)(void *pkt);

enum {
	DISP_REG_EVENTS = 1,
	DISP_REG_8021X,
	/* more to come ...*/
};

/* Success: Returns a handle used for subsequent de-registration
 * Failure: returns NULL
 * type from enum list above
 */
void * disp_register(void *ctx, char *ifname, PDISPFN dfn, int type );
void *disp_register_proto(void *ctx, char *ifname, PDISPFN fn, uint16 proto);

/* Returns success (zero) or failure (non-zero) */
int disp_unregister(void *handle, void *ctx);

/* Perform any necessary initialization (startup only)
 * success: return zero
 * failure: return non-zero
 */
int disp_lib_init(PCFGDISPFN fn);

/* Perform any necessary cleanup for program termination
 * success: return zero
 * failure: return non-zero
 */
int disp_lib_deinit(void);

/* Entry point for [re] configuration
 * Forwards the prepared msg via the platform dependent method
 */

int disp_lib_cfg(char *msg, int len);

/* Run the dispatcher.
 * This needs to be in a separate thread.
 * It returns only if:
 * -- the dispatcher is signalled to quit
 * -- an unrecoverable error condition is encountered
 */
int disp_lib_run();


#endif /* _DISPATCHER_H_ */
