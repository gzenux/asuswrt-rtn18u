/*
 * Test harness for encoding and decoding QoS packets
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
#include "proto/bcmip.h"
#include "test.h"
#include "trace.h"
#include "bcm_encode_qos.h"
#include "bcm_decode_qos.h"

TEST_DECLARE();

#define BUFFER_SIZE		512
static uint8 buffer[BUFFER_SIZE];
static bcm_encode_t enc;

/* --------------------------------------------------------------- */

static uint8 dscpToUp(uint8 dscp, uint8 *qosMapIe)
{
	uint8 *ptr = qosMapIe;
	uint8 len;

	if (ptr != 0 &&
		ptr[0] == DOT11_MNG_QOS_MAP_ID && (len = ptr[1]) >= 16) {
		int i;

		ptr += 2;

		/* check dscp exceptions */
		for (; len > 16; len -= 2) {
			if (dscp == ptr[0])
				return ptr[1];
			ptr += 2;
		}

		/* check dscp/up ranges */
		for (i = 0; i < 16; i += 2) {
			uint8 low = ptr[i];
			uint high = ptr[i + 1];
			if (low == 255 && high == 255)
				continue;
			if (dscp >= low && dscp <= high)
				return (i / 2);
		}
	}

	return dscp >> IPV4_TOS_PREC_SHIFT;
}

static void testEncodeQosMap(void)
{
	TEST(bcm_encode_init(&enc, sizeof(buffer), buffer), "bcm_encode_init failed");
	TEST(bcm_encode_qos_map(&enc, 4, (uint8 *)"\x35\x02\x16\x06",
		8, 15, 0, 7, 255, 255, 16, 31, 32, 39, 255, 255, 40, 47, 255, 255),
		"bcm_encode_qos_map failed");
	WL_PRPKT("encoded packet", bcm_encode_buf(&enc), bcm_encode_length(&enc));

	TEST(dscpToUp(53, bcm_encode_buf(&enc) + 2) == 2,
		"dscpToUp failed");
	TEST(dscpToUp(22, bcm_encode_buf(&enc) + 2) == 6,
		"dscpToUp failed");
	TEST(dscpToUp(10, bcm_encode_buf(&enc) + 2) == 0,
		"dscpToUp failed");
	TEST(dscpToUp(0, bcm_encode_buf(&enc) + 2) == 1,
		"dscpToUp failed");
	TEST(dscpToUp(18, bcm_encode_buf(&enc) + 2) == 3,
		"dscpToUp failed");
	TEST(dscpToUp(26, bcm_encode_buf(&enc) + 2) == 3,
		"dscpToUp failed");
	TEST(dscpToUp(34, bcm_encode_buf(&enc) + 2) == 4,
		"dscpToUp failed");
	TEST(dscpToUp(46, bcm_encode_buf(&enc) + 2) == 6,
		"dscpToUp failed");
	TEST(dscpToUp(47, bcm_encode_buf(&enc) + 2) == 6,
		"dscpToUp failed");
	TEST(dscpToUp(48, bcm_encode_buf(&enc) + 2)
		== (48 >> IPV4_TOS_PREC_SHIFT), "dscpToUp failed");
}

static void testDecodeQosMap(void)
{
	bcm_decode_t dec;
	bcm_decode_qos_map_t qos;

	TEST(bcm_decode_init(&dec, bcm_encode_length(&enc),
		bcm_encode_buf(&enc)), "bcm_decode_init failed");
	WL_PRPKT("decode packet", bcm_decode_buf(&dec), bcm_decode_buf_length(&dec));

	TEST(bcm_decode_qos_map(&dec, &qos),
		"bcm_decode_qos_map failed");
	TEST(qos.exceptCount == 2, "invalid data");
	TEST(qos.except[0].dscp == 0x35, "invalid data");
	TEST(qos.except[0].up == 0x02, "invalid data");
	TEST(qos.except[1].dscp == 0x16, "invalid data");
	TEST(qos.except[1].up == 0x06, "invalid data");
	TEST(qos.up[0].low == 8, "invalid data");
	TEST(qos.up[0].high == 15, "invalid data");
	TEST(qos.up[1].low == 0, "invalid data");
	TEST(qos.up[1].high == 7, "invalid data");
	TEST(qos.up[2].low == 255, "invalid data");
	TEST(qos.up[2].high == 255, "invalid data");
	TEST(qos.up[3].low == 16, "invalid data");
	TEST(qos.up[3].high == 31, "invalid data");
	TEST(qos.up[4].low == 32, "invalid data");
	TEST(qos.up[4].high == 39, "invalid data");
	TEST(qos.up[5].low == 255, "invalid data");
	TEST(qos.up[5].high == 255, "invalid data");
	TEST(qos.up[6].low == 40, "invalid data");
	TEST(qos.up[6].high == 47, "invalid data");
	TEST(qos.up[7].low == 255, "invalid data");
	TEST(qos.up[7].high == 255, "invalid data");
}

static void testEncodeQosMap1(void)
{
	TEST(bcm_encode_init(&enc, sizeof(buffer), buffer), "bcm_encode_init failed");
	TEST(bcm_encode_qos_map(&enc, 0, 0,
		8, 15, 0, 7, 255, 255, 16, 31, 32, 39, 255, 255, 40, 47, 48, 63),
		"bcm_encode_qos_map failed");
	WL_PRPKT("encoded packet", bcm_encode_buf(&enc), bcm_encode_length(&enc));
}

static void testDecodeQosMap1(void)
{
	bcm_decode_t dec;
	bcm_decode_qos_map_t qos;

	TEST(bcm_decode_init(&dec, bcm_encode_length(&enc),
		bcm_encode_buf(&enc)), "bcm_decode_init failed");
	WL_PRPKT("decode packet", bcm_decode_buf(&dec), bcm_decode_buf_length(&dec));

	TEST(bcm_decode_qos_map(&dec, &qos),
		"bcm_decode_qos_map failed");
	TEST(qos.exceptCount == 0, "invalid data");
	TEST(qos.up[0].low == 8, "invalid data");
	TEST(qos.up[0].high == 15, "invalid data");
	TEST(qos.up[1].low == 0, "invalid data");
	TEST(qos.up[1].high == 7, "invalid data");
	TEST(qos.up[2].low == 255, "invalid data");
	TEST(qos.up[2].high == 255, "invalid data");
	TEST(qos.up[3].low == 16, "invalid data");
	TEST(qos.up[3].high == 31, "invalid data");
	TEST(qos.up[4].low == 32, "invalid data");
	TEST(qos.up[4].high == 39, "invalid data");
	TEST(qos.up[5].low == 255, "invalid data");
	TEST(qos.up[5].high == 255, "invalid data");
	TEST(qos.up[6].low == 40, "invalid data");
	TEST(qos.up[6].high == 47, "invalid data");
	TEST(qos.up[7].low == 48, "invalid data");
	TEST(qos.up[7].high == 63, "invalid data");
}

int main(int argc, char **argv)
{
	(void) argc;
	(void) argv;

	TRACE_LEVEL_SET(TRACE_ALL);
	TEST_INITIALIZE();

	testEncodeQosMap();
	testDecodeQosMap();

	testEncodeQosMap1();
	testDecodeQosMap1();

	TEST_FINALIZE();
	return 0;
}
