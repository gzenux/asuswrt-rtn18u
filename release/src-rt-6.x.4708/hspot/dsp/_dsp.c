/*
 * Test harness for dispatcher.
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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "trace.h"
#include "test.h"
#include "dsp.h"
#include "tmr.h"

/* request handler */
typedef void (*requestHandlerT)(void *context,
	int reqLength, uint8 *reqData, uint8 *rspData);

#define BUF_SIZE	32

typedef struct {
	requestHandlerT handler;
	uint8 data[BUF_SIZE];
} reqT;

TEST_DECLARE();

static void *testContext = (void *)0xabcd1234;
static tmrT *timer;

/* --------------------------------------------------------------- */

static void processReqEvent(void *context,
	int reqLength, uint8 *reqData, uint8 *rspData)
{
	reqT *req = (reqT *)reqData;

	TEST(context == testContext, "context incorrect");
	TEST(reqLength == sizeof(reqT), "request length incorrect");

	if (rspData != 0) {
		memcpy(rspData, req->data, sizeof(req->data));
	}
}

static void processWlanEvent(void *context, uint32 eventType,
	wl_event_msg_t *wlEvent, uint8 *data, uint32 length)
{
#if !TRACE_ENABLED
	(void)eventType;
#endif
	(void)context;
	(void)wlEvent;
	(void)data;
	(void)length;

	TRACE(TRACE_DEBUG, "event_type=%d\n", eventType);
}

static void
timeout(void *arg)
{
	(void)arg;
	TRACE(TRACE_DEBUG, "timeout callback\n");
}

static void testdsp(void)
{
	int i;
	reqT req;
	uint8 rsp[BUF_SIZE];

	req.handler = processReqEvent;
	for (i = 0; i < BUF_SIZE; i++)
		req.data[i] = i;

	TEST(dspSubscribe(dsp(), 0, processWlanEvent),
		"dspSubscribe failed");

	timer = tmrCreate(dsp(), timeout, 0, "test");
	tmrStart(timer, 5 * 1000, FALSE);

	for (i = 0; i < 10; i++)
		TEST(dspRequest(dsp(), testContext, sizeof(req), (uint8 *)&req),
			"dspData failed");

	for (i = 0; i < 10; i++) {
		memset(req.data, i, sizeof(req.data));
		memset(rsp, 0, sizeof(rsp));
		TRACE_HEX_DUMP(TRACE_DEBUG, "req bufffer", sizeof(req.data), req.data);
		TEST(dspRequestSynch(dsp(), testContext,
			sizeof(req), (uint8 *)&req, rsp), "dspDataSync failed");
		TRACE_HEX_DUMP(TRACE_DEBUG, "rsp bufffer", sizeof(rsp), rsp);
		TEST(memcmp(req.data, rsp, sizeof(rsp)) == 0, "response data incorrect");
	}

	sleep(1);

	TEST(dspUnsubscribe(dsp(), processWlanEvent),
		"dspUnsubscribe failed");
	dspFree();
}

int main(int argc, char **argv)
{
	(void) argc;
	(void) argv;

	TRACE_LEVEL_SET(TRACE_ALL);
	TEST_INITIALIZE();

	testdsp();

	TEST_FINALIZE();
	return 0;
}
