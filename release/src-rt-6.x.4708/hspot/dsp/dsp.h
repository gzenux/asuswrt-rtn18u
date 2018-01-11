/*
 * Dispatcher providing single-thread context.
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

#ifndef _DSP_H_
#define _DSP_H_

#include "typedefs.h"
#include "proto/ethernet.h"
#include "proto/bcmeth.h"
#include "proto/bcmevent.h"
#include "bcmseclib_timer.h"

/* wlan handler */
typedef void (*dspWlanHandlerT)(void * context, uint32 eventType,
	wl_event_msg_t *wlEvent, uint8 *data, uint32 length);

typedef struct dspStruct dspT;

/* get dispatcher instance */
dspT *dsp(void);

/* free dispatcher instance */
void dspFree(void);

/* create dispatcher */
dspT *dspCreate(void);

/* destroy dispatcher */
int dspDestroy(dspT *dsp);

/* dispatcher subscribe */
int dspSubscribe(dspT *dsp, void *context, dspWlanHandlerT wlan);

/* dispatcher unsubscribe */
int dspUnsubscribe(dspT *dsp, dspWlanHandlerT wlan);

/* start dispatcher processing */
int dspStart(dspT *dsp);

/* stop dispatcher processing */
int dspStop(dspT *dsp);

/* send request to dispatcher */
int dspRequest(dspT *dsp, void *context,
	int reqLength, uint8 *reqData);

/* send request to dispatcher and wait for response */
int dspRequestSynch(dspT *dsp, void *context,
	int reqLength, uint8 *reqData, uint8 *rspData);

/* get timer manager */
bcmseclib_timer_mgr_t *dspGetTimerMgr(dspT *dsp);

#endif /* _DSP_H_ */
