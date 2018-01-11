/*
 * Test harness for WLAN functions.
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
#include "wlan.h"

TEST_DECLARE();

static void wlanEventCallback(void *context, uint32 eventType,
	wl_event_msg_t *wlEvent, uint8 *data, uint32 length)
{
	TEST((int)context == 0x12345678, "invalid context");
	if (eventType == WLC_E_ESCAN_RESULT) {
		if (wlEvent->status == WLC_E_STATUS_SUCCESS) {
			TRACE(TRACE_DEBUG,
				"WLC_E_ESCAN_RESULT - WLC_E_STATUS_SUCCESS %d\n", length);
		}
		else if (wlEvent->status == WLC_E_STATUS_PARTIAL) {
			wl_escan_result_t *escan_data = (wl_escan_result_t*)data;

			TRACE(TRACE_DEBUG,
				"WLC_E_ESCAN_RESULT - WLC_E_STATUS_PARTIAL\n");

			if (length >= sizeof(*escan_data)) {
				wl_bss_info_t *bi = &escan_data->bss_info[0];
				dump_bss_info(bi);
			}
		}
	}
}

/* --------------------------------------------------------------- */

static void testIfName(void)
{
	wlanT *wlan;

	wlan = wlanCreate();
	TEST(wlan != 0, "wlanCreate failed");
	TEST(strcmp(wlanIfName(wlan), "wlan0") == 0, "wlanIfName failed");
	TEST(wlanDestroy(wlan), "wlanDestroy failed");
}

static void testEtherAddr(void)
{
	wlanT *wlan;
	struct ether_addr addr;

	wlan = wlanCreate();
	TEST(wlan != 0, "wlanCreate failed");
	TEST(wlanEtherAddr(wlan, &addr), "wlanEtherAddr failed");
	TRACE_MAC_ADDR(TRACE_PRINTF, "ether addr", &addr);
	TEST(wlanDestroy(wlan), "wlanDestroy failed");
}

static void testEventMsg(void)
{
	wlanT *wlan;

	wlan = wlanCreate();
	TEST(wlan != 0, "wlanCreate failed");
	TEST(wlanDisableEventMsg(wlan, WLC_E_ACTION_FRAME_RX), "wlanEnableEventMsg failed");
	TEST(wlanEnableEventMsg(wlan, WLC_E_ACTION_FRAME_RX), "wlanEnableEventMsg failed");
	TEST(wlanDestroy(wlan), "wlanDestroy failed");
}

static void testVendorIe(void)
{
	wlanT *wlan;
	uint8 ie[] = "\x50\x6F\x9A\x10\x01\x02\x03";

	wlan = wlanCreate();
	TEST(wlan != 0, "wlanCreate failed");
	TEST(wlanAddVendorIe(wlan, VNDR_IE_PRBREQ_FLAG, sizeof(ie), ie),
		"wlanAddVendorIe failed");
	TEST(wlanDeleteVendorIe(wlan, VNDR_IE_PRBREQ_FLAG, sizeof(ie), ie),
		"wlanDeleteVendorIe failed");
	TEST(wlanDestroy(wlan), "wlanDestroy failed");
}

static void testEscan(void)
{
	wlanT *wlan;

	wlan = wlanCreate();
	TEST(wlan != 0, "wlanCreate failed");
	TEST(wlanStartEscan(wlan, TRUE, -1, -1, -1), "wlanStartEscan failed");
	sleep(1);
	TEST(wlanStopScan(wlan), "wlanStopScan failed");
	TEST(wlanDestroy(wlan), "wlanDestroy failed");
}

static void testBssTransitionQuery(void)
{
	wlanT *wlan;

	wlan = wlanCreate();
	TEST(wlan != 0, "wlanCreate failed");
	TEST(wlanBssTransitionQuery(wlan), "wlanBssTransitionQuery failed");
	TEST(wlanDestroy(wlan), "wlanDestroy failed");
}

static void testActionFrame(void)
{
	wlanT *wlan;
	struct ether_addr da = {{0x00, 0x11, 0x11, 0x11, 0x11, 0x11}};
	char data[256];
	int i;

	data[DOT11_ACTION_CAT_OFF] = DOT11_ACTION_CAT_PUBLIC;
	data[DOT11_ACTION_ACT_OFF] = GAS_REQUEST_ACTION_FRAME;
	for (i = DOT11_ACTION_ACT_OFF + 1; i < (int)sizeof(data); i++)
		data[i] = i;

	wlan = wlanCreate();
	TEST(wlan != 0, "wlanCreate failed");
	TEST(wlanActionFrame(wlan, (int)data, 1, 500, &da, &da, sizeof(data), (uint8 *)data),
		"wlanActionFrame faile");
	TEST(wlanDestroy(wlan), "wlanDestroy failed");
}

static void testAssociationStatus(void)
{
	wlanT *wlan;
	int isAssociated;
	char buffer[1024];

	wlan = wlanCreate();
	TEST(wlan != 0, "wlanCreate failed");
	TEST(wlanAssociationStatus(wlan, &isAssociated, sizeof(buffer), (wl_bss_info_t *)buffer),
		"wlanAssociationStatus failed");
	if (isAssociated) {
		dump_bss_info((wl_bss_info_t *)buffer);
	}
	else {
		printf("not associated\n");
	}
	TEST(wlanDestroy(wlan), "wlanDestroy failed");
}

static void testWnm(void)
{
	wlanT *wlan;
	int wMask, rMask;

	wlan = wlanCreate();
	TEST(wlan != 0, "wlanCreate failed");
	for (wMask = 0; wMask < 0x10; wMask++) {
		TEST(wlanWnm(wlan, wMask), "wlanWnm failed");
		TEST(wlanWnmGet(wlan, &rMask), "wlanWnmGet failed");
		TEST(wMask == rMask, "invalid data");
	}
	TEST(wlanDestroy(wlan), "wlanDestroy failed");
}
int main(int argc, char **argv)
{
	(void) argc;
	(void) argv;

	TRACE_LEVEL_SET(TRACE_ALL);
	TEST_INITIALIZE();

	wlanSubscribeEvent((void *)0x12345678, wlanEventCallback);
	wlanInitialize();

	testIfName();
	testEtherAddr();
	testEventMsg();
	testVendorIe();
	testEscan();
	testBssTransitionQuery();
	testActionFrame();
	testAssociationStatus();
	testWnm();

	wlFree();
	dspFree();

	wlanDeinitialize();
	wlanUnsubscribeEvent(wlanEventCallback);

	TEST_FINALIZE();
	return 0;
}
