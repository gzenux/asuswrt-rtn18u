/*
 * Test harness for encoding and decoding WNM packets
 *
 * Copyright (C) 2014, Broadcom Corporation
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
#include "proto/802.11.h"
#include "test.h"
#include "trace.h"
#include "bcm_encode_wnm.h"
#include "bcm_decode_wnm.h"

TEST_DECLARE();

#define BUFFER_SIZE		512
static uint8 buffer[BUFFER_SIZE];
static bcm_encode_t enc;

/* --------------------------------------------------------------- */

static void testEncodeSubscriptionRemediation(void)
{
	TEST(bcm_encode_init(&enc, sizeof(buffer), buffer), "bcm_encode_init failed");
	TEST(bcm_encode_wnm_subscription_remediation(&enc, 1, 10, "helloworld", 1),
		"bcm_encode_wnm_subscription_remediation failed");
	WL_PRPKT("encoded packet", bcm_encode_buf(&enc), bcm_encode_length(&enc));
}

static void testDecodeSubscriptionRemediation(void)
{
	bcm_decode_t dec;
	bcm_decode_wnm_subscription_remediation_t wnm;

	TEST(bcm_decode_init(&dec, bcm_encode_length(&enc),
		bcm_encode_buf(&enc)), "bcm_decode_init failed");
	WL_PRPKT("decode packet", bcm_decode_buf(&dec), bcm_decode_buf_length(&dec));

	TEST(bcm_decode_wnm_subscription_remediation(&dec, &wnm),
		"bcm_decode_wnm_subscription_remediation failed");
	TEST(wnm.dialogToken == 1, "invalid data");
	TEST(wnm.urlLength == 10, "invalid data");
	TEST(strcmp(wnm.url, "helloworld") == 0, "invalid data");
	TEST(wnm.serverMethod == 1, "invalid data");
}

static void testEncodeDeauthenticationImminent(void)
{
	TEST(bcm_encode_init(&enc, sizeof(buffer), buffer), "bcm_encode_init failed");
	TEST(bcm_encode_wnm_deauthentication_imminent(&enc, 2,
		HSPOT_DEAUTH_RC_ESS_DISALLOW, 1000, 10, "helloworld"),
		"bcm_encode_wnm_deauthentication_imminent failed");
	WL_PRPKT("encoded packet", bcm_encode_buf(&enc), bcm_encode_length(&enc));
}

static void testDecodeDeauthenticationImminent(void)
{
	bcm_decode_t dec;
	bcm_decode_wnm_deauthentication_imminent_t wnm;

	TEST(bcm_decode_init(&dec, bcm_encode_length(&enc),
		bcm_encode_buf(&enc)), "bcm_decode_init failed");
	WL_PRPKT("decode packet", bcm_decode_buf(&dec), bcm_decode_buf_length(&dec));

	TEST(bcm_decode_wnm_deauthentication_imminent(&dec, &wnm),
		"bcm_decode_wnm_deauthentication_imminent failed");
	TEST(wnm.dialogToken == 2, "invalid data");
	TEST(wnm.reason == HSPOT_DEAUTH_RC_ESS_DISALLOW, "invalid data");
	TEST(wnm.reauthDelay == 1000, "invalid data");
	TEST(wnm.urlLength == 10, "invalid data");
	TEST(strcmp(wnm.url, "helloworld") == 0, "invalid data");
}

int main(int argc, char **argv)
{
	(void) argc;
	(void) argv;

	TRACE_LEVEL_SET(TRACE_ALL);
	TEST_INITIALIZE();

	testEncodeSubscriptionRemediation();
	testDecodeSubscriptionRemediation();

	testEncodeDeauthenticationImminent();
	testDecodeDeauthenticationImminent();

	TEST_FINALIZE();
	return 0;
}
