/*
 * Timer utility.
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

#include "trace.h"
#include "tmr.h"

/* create timer */
tmrT *tmrCreate(dspT *dsp, void (*fn)(void *arg), void *arg, const char *name)
{
	tmrT *tmr;
	tmr = bcmseclib_init_timer_ex(dspGetTimerMgr(dsp), fn, arg, name);
	if (tmr == 0) {
		TRACE(TRACE_ERROR, "failed to create timer\n");
	}
	return tmr;
}

/* destroy timer */
void tmrDestroy(tmrT *tmr)
{
	if (tmr == 0) {
		TRACE(TRACE_ERROR, "invalid timer\n");
		return;
	}

	bcmseclib_free_timer(tmr);
}

/* start timer */
void tmrStart(tmrT *tmr, uint32 ms, int isPeriodic)
{
	if (tmr == 0) {
		TRACE(TRACE_ERROR, "invalid timer\n");
		return;
	}

	bcmseclib_add_timer(tmr, ms, isPeriodic);
}

/* stop timer */
bool tmrStop(tmrT *tmr)
{
	if (tmr == 0) {
		TRACE(TRACE_ERROR, "invalid timer\n");
		return FALSE;
	}

	return bcmseclib_del_timer(tmr);
}
