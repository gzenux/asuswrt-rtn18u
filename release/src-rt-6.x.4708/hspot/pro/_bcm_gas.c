/*
 * Test harness for 802.11u GAS state machine.
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
#include "wlu_api.h"
#include "bcm_gas.h"
#include "eventQ.h"

#define MAX_GAS_INSTANCE	8

static int gTestDataCount = 0;
static int gTestDataSize[2] = {500, 64*1024};

#define NEXT_TEST_DATA_SIZE()	gTestDataCount++; gTestDataCount %= 2;
#define TEST_DATA_SIZE			gTestDataSize[gTestDataCount]

TEST_DECLARE();

static eventQT *eventq;

/* --------------------------------------------------------------- */

void testProGasMaxInstance(void)
{
	uint16 channel = 11;
	struct ether_addr dst = {{0x11, 0x11, 0x11, 0x11, 0x11, 0x11}};
	bcm_gas_t *gas[MAX_GAS_INSTANCE];
	bcm_gas_t *fail;
	int i;

	bcm_gas_maximum_instances(MAX_GAS_INSTANCE);

	/* initialize GAS protocol */
	TEST(bcm_gas_initialize(), "bcm_gas_initialize failed");

	for (i = 0; i < MAX_GAS_INSTANCE; i++) {
		dst.octet[0] = i;
		gas[i] = bcm_gas_create(wl(), 0, channel, &dst);
		TEST(gas[i] != 0, "bcm_gas_create failed");
	}
	dst.octet[0] = i;
	fail = bcm_gas_create(wl(), 0, channel, &dst);
	TEST(fail == 0, "bcm_gas_create failed");

	for (i = 0; i < MAX_GAS_INSTANCE; i++) {
		TEST(bcm_gas_destroy(gas[i]), "bcm_gas_destroy failed");
	}

	sleep(1);

	/* deinitialize GAS protocol */
	TEST(bcm_gas_deinitialize(), "bcm_gas_deinitialize failed");
}

static void processQueryRequest(bcm_gas_t *gas, int len, uint8 *data)
{
#if !TRACE_ENABLED
	(void)len;
	(void)data;
#endif
	uint8 *rsp;
	TRACE_HEX_DUMP(TRACE_DEBUG, "query request", len, data);

	rsp = malloc(TEST_DATA_SIZE);
	if (rsp != 0) {
		int i;
		for (i = 0; i < TEST_DATA_SIZE; i++)
			rsp[i] = i;
		bcm_gas_set_query_response(gas, TEST_DATA_SIZE, rsp);
	}
	free(rsp);

	NEXT_TEST_DATA_SIZE();
}

static int eventHandler(bcm_gas_t *gas, bcm_gas_event_t *event)
{
	TRACE(TRACE_DEBUG, "*** event notification ***\n");
	TRACE_MAC_ADDR(TRACE_DEBUG, "   peer", &event->peer);
	TRACE(TRACE_DEBUG, "   dialog token = %d\n", event->dialogToken);

	if (event->type == BCM_GAS_EVENT_QUERY_REQUEST) {
		TRACE(TRACE_DEBUG, "   BCM_GAS_EVENT_QUERY_REQUEST\n");
		processQueryRequest(event->gas, event->queryReq.len, event->queryReq.data);
	}
	else if (event->type == BCM_GAS_EVENT_TX) {
		TRACE(TRACE_DEBUG, "   BCM_GAS_EVENT_TX\n");
	}
	else if (event->type == BCM_GAS_EVENT_RX) {
		TRACE(TRACE_DEBUG, "   BCM_GAS_EVENT_RX\n");
	}

	else if (event->type == BCM_GAS_EVENT_STATUS) {
#ifdef BCMDBG
		char *str;

		switch (event->status.statusCode)
		{
		case DOT11_SC_SUCCESS:
			str = "SUCCESS";
			break;
		case DOT11_SC_FAILURE:
			str = "UNSPECIFIED";
			break;
		case DOT11_SC_ADV_PROTO_NOT_SUPPORTED:
			str = "ADVERTISEMENT_PROTOCOL_NOT_SUPPORTED";
			break;
		case DOT11_SC_NO_OUTSTAND_REQ:
			str = "NO_OUTSTANDING_REQUEST";
			break;
		case DOT11_SC_RSP_NOT_RX_FROM_SERVER:
			str = "RESPONSE_NOT_RECEIVED_FROM_SERVER";
			break;
		case DOT11_SC_TIMEOUT:
			str = "TIMEOUT";
			break;
		case DOT11_SC_QUERY_RSP_TOO_LARGE:
			str = "QUERY_RESPONSE_TOO_LARGE";
			break;
		case DOT11_SC_SERVER_UNREACHABLE:
			str = "SERVER_UNREACHABLE";
			break;
		case DOT11_SC_TRANSMIT_FAILURE:
			str = "TRANSMISSION_FAILURE";
			break;
		default:
			str = "UNKNOWN";
			break;
		}

		TRACE(TRACE_DEBUG, "   status code = %s\n", str);
#endif	/* BCMDBG */

		/* if status is from own instance then GAS exchange is completed */
		if (gas == event->gas)
			return FALSE;
	}
	else {
		TRACE(TRACE_DEBUG, "   UNKOWN\n");
	}

	return TRUE;
}

static int waitForStatus(bcm_gas_t *gas, int timeout, uint16 *status)
{
	int incr = 100;
	int elapsed;
	bcm_gas_event_t event;

	TRACE(TRACE_DEBUG, "wait for status\n");

	/* process event queue until status received or timeout */
	for (elapsed = 0; elapsed < timeout; elapsed += incr) {
		while (1) {
			if (eventQReceive(eventq, (char *)&event) == -1)
				break;

			if (!eventHandler(gas, &event)) {
				TRACE(TRACE_DEBUG, "status received exit\n");
				*status = event.status.statusCode;
				return TRUE;
			}
		}
		usleep(incr * 1000);
	}
	TRACE(TRACE_DEBUG, "wait for status timeout\n");
	return FALSE;
}

static void eventCallback(void *context, bcm_gas_t *gas, bcm_gas_event_t *event)
{
	(void)gas;

	TRACE(TRACE_DEBUG, "event callback\n");

	TEST((int)context == 0x12345678, "invalid context");
	if (eventQSend(eventq, (char *)event) != 0) {
		TRACE(TRACE_ERROR, "failed to queue event\n");
	}
}

static void verifyResponseData(bcm_gas_t *gas, uint16 status)
{
	if (status == DOT11_SC_SUCCESS) {
		int length;
		uint8 *data;
		int retLen;

		length = bcm_gas_get_query_response_length(gas);
		TRACE(TRACE_DEBUG, "bcm_gas_get_query_response_length=%d\n", length);
		TEST(length == TEST_DATA_SIZE, "invalid length");
		data = malloc(length);
		if (data != 0) {
			int i;
			bcm_gas_get_query_response(gas, length, &retLen, data);
			TEST(length == retLen, "invalid data");
			for (i = 0; i < length; i++)
				TEST(data[i] == (uint8)i, "invalid data");
		}
		free(data);
	}

	NEXT_TEST_DATA_SIZE();
}

void testProGas(void)
{
	/* subscribe events */
	TEST(bcm_gas_subscribe_event((void *)0x12345678, eventCallback),
		"bcm_gas_subscribe_event failed");

	/* initialize GAS protocol */
	TEST(bcm_gas_initialize(), "bcm_gas_initialize failed");

	{
		uint16 channel = 11;
		struct ether_addr dst = {{0x00, 0x26, 0x5e, 0x1b, 0x13, 0x5e}};
		bcm_gas_t *gas;

		uint16 status;

		gas = bcm_gas_create(wl(), 0, channel, &dst);
		TEST(gas != 0, "bcm_gas_create failed");

		TEST(bcm_gas_set_query_request(gas, 10, (uint8 *)"helloworld"),
			"bcm_gas_set_query_request failed");

		TEST(bcm_gas_start(gas), "bcm_gas_start failed");
		waitForStatus(gas, 30 * 1000, &status);
		verifyResponseData(gas, status);
		TEST(bcm_gas_start(gas), "bcm_gas_start failed");
		waitForStatus(gas, 30 * 1000, &status);
		verifyResponseData(gas, status);

		TEST(bcm_gas_destroy(gas), "bcm_gas_destroy failed");
	}

	/* deinitialize GAS protocol */
	TEST(bcm_gas_deinitialize(), "bcm_gas_deinitialize failed");

	/* unsubscribe events */
	TEST(bcm_gas_unsubscribe_event(eventCallback), "proGasUnubscribeEvent failed");
}

void testProGasIncoming(void)
{
	uint16 status;

	/* subscribe events */
	TEST(bcm_gas_subscribe_event((void *)0x12345678, eventCallback),
		"bcm_gas_subscribe_event failed");

	/* initialize GAS protocol */
	TEST(bcm_gas_initialize(), "bcm_gas_initialize failed");

	while (1) {
		waitForStatus(0, 60 * 1000, &status);
	}

	/* deinitialize GAS protocol */
	TEST(bcm_gas_deinitialize(), "bcm_gas_deinitialize failed");

	/* unsubscribe events */
	TEST(bcm_gas_unsubscribe_event(eventCallback), "proGasUnubscribeEvent failed");
}

int main(int argc, char **argv)
{
	(void) argc;
	(void) argv;

	TRACE_LEVEL_SET(TRACE_ALL);
	TEST_INITIALIZE();

	eventq = eventQCreate("/eventq", 8, sizeof(bcm_gas_event_t));

#ifdef PRO_GAS_INCOMING
	testProGasIncoming();
#else
	/* run test multiple times */
	testProGasMaxInstance();
	testProGasMaxInstance();
	testProGasMaxInstance();

	testProGas();
#endif

	eventQDelete(eventq);

	/* disable wlan */
	wlFree();

	/* terminate dispatcher */
	dspFree();

	TEST_FINALIZE();
	return 0;
}
