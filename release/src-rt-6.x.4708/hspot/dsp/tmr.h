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

#ifndef _TMR_H_
#define _TMR_H_

#include "dsp.h"
#include "bcmseclib_timer.h"

typedef bcmseclib_timer_t tmrT;

/* create timer */
tmrT *tmrCreate(dspT *dsp, void (*fn)(void *arg), void *arg, const char *name);

/* destroy timer */
void tmrDestroy(tmrT *tmr);

/* start timer */
void tmrStart(tmrT *tmr, uint32 ms, int isPeriodic);

/* stop timer */
bool tmrStop(tmrT *tmr);

#endif /* _TMR_H_ */
