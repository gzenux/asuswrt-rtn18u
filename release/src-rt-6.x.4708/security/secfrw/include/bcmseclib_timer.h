/*
 * bcmseclib_timer.h -- timer library interface
 *
 * Copyright (C) 2014, Broadcom Corporation
 * All Rights Reserved.
 * 
 * This is UNPUBLISHED PROPRIETARY SOURCE CODE of Broadcom Corporation;
 * the contents of this file may not be disclosed to third parties, copied
 * or duplicated in any form, in whole or in part, without the prior
 * written permission of Broadcom Corporation.
 *
 * $Id: bcmseclib_timer.h,v 1.2 2010-12-11 00:06:34 $
 */

#ifndef _bcmseclib_timer_h_
#define _bcmseclib_timer_h_

#include <typedefs.h>


/* PRIVATE struct - only used internally within the timer module.
 *
 * Time structure with sec and usec units.
 */
typedef struct bcmseclib_time_t
{
	long sec;
	long usec;
} bcmseclib_time_t;

/* Opaque type for timer manager. */
typedef struct bcmseclib_timer_mgr bcmseclib_timer_mgr_t;


typedef struct bcmseclib_time_t exp_time_t;

typedef
struct bcmseclib_timer {
	struct bcmseclib_timer *next;
	void (*fn)(void *);
	void *arg; /* argument to fn */
	uint ms;
	bool periodic;
	bool set;
#ifdef BCMDBG
	char* name; /* Description of the timer */
#endif
	exp_time_t expiry_time;	/* time to expiry */
	bcmseclib_timer_mgr_t *mgr; /* timer manager */
} bcmseclib_timer_t;


/* Activate a [previously created] timer with specified parms */
void
bcmseclib_add_timer(bcmseclib_timer_t *t, uint ms, bool periodic);

/* De-activate timer but don't delete it */
bool
bcmseclib_del_timer(bcmseclib_timer_t *t);

/* Remove from timer list and free allocated memory */
void
bcmseclib_free_timer(bcmseclib_timer_t *t);

/* Create the data structures, fill in callback args,
 * but do NOT activate
 */
#define bcmseclib_init_timer(cb, arg, name) bcmseclib_init_timer_ex(NULL, (cb), (arg), (name))
bcmseclib_timer_t *
bcmseclib_init_timer_ex(bcmseclib_timer_mgr_t *mgr, void (*fn)(void *arg), void *arg, const char *name);

#define bcmseclib_init_timer_utilities(n) bcmseclib_init_timer_utilities_ex((n), NULL)
int
bcmseclib_init_timer_utilities_ex(int ntimers, bcmseclib_timer_mgr_t **mgr);

#define bcmseclib_deinit_timer_utilities() bcmseclib_deinit_timer_utilities_ex(NULL)
int
bcmseclib_deinit_timer_utilities_ex(bcmseclib_timer_mgr_t *mgr);

#define bcmseclib_get_timeout(t) bcmseclib_get_timeout_ex(NULL, (t))
bool
bcmseclib_get_timeout_ex(bcmseclib_timer_mgr_t *mgr, exp_time_t *t);

#define bcmseclib_process_timer_expiry() bcmseclib_process_timer_expiry_ex(NULL)
void
bcmseclib_process_timer_expiry_ex(bcmseclib_timer_mgr_t *mgr);

#endif /* _bcmseclib_timer_h_ */
