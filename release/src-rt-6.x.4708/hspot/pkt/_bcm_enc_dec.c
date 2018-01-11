/*
 * Test harness for encoding and decoding base functions.
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
#include "test.h"
#include "trace.h"
#include "bcm_encode.h"
#include "bcm_decode.h"

TEST_DECLARE();

#define BUFFER_SIZE		256
static uint8 buffer[BUFFER_SIZE];
static bcm_encode_t enc;

/* --------------------------------------------------------------- */

static void testEncode(void)
{
	uint8 data[BUFFER_SIZE];

	TEST(bcm_encode_init(&enc, BUFFER_SIZE, buffer), "bcm_encode_init failed");

	TEST(bcm_encode_be16(&enc, 0x1122) == 2, "bcm_encode_be16 failed");
	TEST(bcm_encode_be32(&enc, 0x11223344) == 4, "bcm_encode_be32 failed");
	TEST(bcm_encode_le16(&enc, 0xaabb) == 2, "bcm_encode_le16 failed");
	TEST(bcm_encode_le32(&enc, 0xaabbccdd) == 4, "bcm_encode_le32 failed");

	/* packet full */
	TEST(bcm_encode_bytes(&enc, BUFFER_SIZE, data) == 0, "bcm_encode_bytes failed");
	TEST(bcm_encode_length(&enc) == 12, "bcm_encode_length failed");
}

static void testDecode(void)
{
	bcm_decode_t dec;
	uint16 data16;
	uint32 data32;

	TEST(bcm_decode_init(&dec, bcm_encode_length(&enc),
		bcm_encode_buf(&enc)), "bcm_decode_init failed");
	WL_PRPKT("decode packet", bcm_decode_buf(&dec), bcm_decode_buf_length(&dec));

	data16 = 0;
	TEST(bcm_decode_be16(&dec, &data16) == 2, "bcm_decode_be16 failed");
	TEST(data16 == 0x1122, "invalid data");
	data32 = 0;
	TEST(bcm_decode_be32(&dec, &data32) == 4, "bcm_decode_be32 failed");
	TEST(data32 == 0x11223344, "invalid data");
	data16 = 0;
	TEST(bcm_decode_le16(&dec, &data16) == 2, "bcm_decode_le16 failed");
	TEST(data16 == 0xaabb, "invalid data");
	data32 = 0;
	TEST(bcm_decode_le32(&dec, &data32) == 4, "bcm_decode_le32 failed");
	TEST(data32 == 0xaabbccdd, "invalid data");

	/* decode beyond buffer */
	TEST(bcm_decode_be16(&dec, &data16) == 0, "bcm_decode_be16 failed");
	TEST(bcm_decode_be32(&dec, &data32) == 0, "bcm_decode_be32 failed");
	TEST(bcm_decode_le16(&dec, &data16) == 0, "bcm_decode_le16 failed");
	TEST(bcm_decode_le32(&dec, &data32) == 0, "bcm_decode_le32 failed");
}


int main(int argc, char **argv)
{
	(void) argc;
	(void) argv;

	TRACE_LEVEL_SET(TRACE_ALL);
	TEST_INITIALIZE();

	testEncode();
	testDecode();

	TEST_FINALIZE();
	return 0;
}
