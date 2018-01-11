/*
 * Test harness for encoding and decoding information elements.
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
#include "proto/802.11.h"
#include "test.h"
#include "trace.h"
#include "bcm_encode_ie.h"
#include "bcm_decode_ie.h"

TEST_DECLARE();

#define BUFFER_SIZE		256
static uint8 buffer[BUFFER_SIZE];
static bcm_encode_t enc;

/* --------------------------------------------------------------- */

static void testEncode(void)
{
	uint8 adBuffer[BUFFER_SIZE];
	bcm_encode_t ad;

	TEST(bcm_encode_init(&enc, sizeof(buffer), buffer), "bcm_encode_init failed");

	TEST(bcm_encode_ie_hotspot_indication2(&enc, TRUE, HSPOT_RELEASE_2),
		"bcm_encode_ie_hotspot_indication2 failed");

	TEST(bcm_encode_ie_interworking(&enc,
		IW_ANT_WILDCARD_NETWORK, FALSE, FALSE, FALSE, FALSE,
		TRUE, 0, 0, (struct ether_addr *)"\xff\xff\xff\xff\xff\xff"),
		"bcm_encode_ie_interworking failed");

	TEST(bcm_encode_init(&ad, sizeof(adBuffer), adBuffer),
		"bcm_encode_init failed");
	TEST(bcm_encode_ie_advertisement_protocol_tuple(&ad,
		ADVP_PAME_BI_DEPENDENT, 0xff, ADVP_ANQP_PROTOCOL_ID),
		"bcm_encode_ie_advertisement_protocol_tuple failed");
	TEST(bcm_encode_ie_advertisement_protocol_from_tuple(&enc,
		bcm_encode_length(&ad),	bcm_encode_buf(&ad)),
		"bcm_encode_ie_advertisement_protocol_from_tuple failed");

	TEST(bcm_encode_ie_roaming_consortium(&enc, 0xff, 3, (uint8 *)"\x00\x11\x22",
		4, (uint8 *)"\x55\x66\x77\x88", 4, (uint8 *)"\xaa\xbb\xcc\xdd"),
		"bcm_encode_ie_roaming_consortium failed");

	TEST(bcm_encode_ie_extended_capabilities(&enc, 0x80000000),
		"bcm_encode_ie_extended_capabilities failed");

	WL_PRPKT("encoded IEs",	bcm_encode_buf(&enc), bcm_encode_length(&enc));
}

static void testDecode(void)
{
	bcm_decode_t dec;
	bcm_decode_ie_t ie;
	bcm_decode_t dec1;
	bcm_decode_hotspot_indication_t hotspot;
	bcm_decode_interworking_t interworking;
	bcm_decode_advertisement_protocol_t advertise;
	bcm_decode_roaming_consortium_t roam;
	uint32 cap;

	TEST(bcm_decode_init(&dec, bcm_encode_length(&enc),
		bcm_encode_buf(&enc)), "bcm_decode_init failed");
	WL_PRPKT("decode packet", bcm_decode_buf(&dec), bcm_decode_buf_length(&dec));

	TEST(bcm_decode_ie(&dec, &ie) == 5, "bcm_decode_ie failed");

	TEST(bcm_decode_init(&dec1, ie.hotspotIndicationLength,
		ie.hotspotIndication), "bcm_decode_init failed");
	TEST(bcm_decode_ie_hotspot_indication2(&dec1, &hotspot),
		"bcm_decode_ie_hotspot_indication2 failed");
	TEST(hotspot.isDgafDisabled == TRUE, "invalid data");
	TEST(hotspot.releaseNumber == HSPOT_RELEASE_2, "invalid data");

	TEST(bcm_decode_init(&dec1, ie.interworkingLength,
		ie.interworking), "bcm_decode_init failed");
	TEST(bcm_decode_ie_interworking(&dec1, &interworking), "bcm_decode_ie_interworking failed");
	TEST(interworking.accessNetworkType == IW_ANT_WILDCARD_NETWORK, "invalid data");
	TEST(interworking.isInternet == FALSE, "invalid data");
	TEST(interworking.isAsra == FALSE, "invalid data");
	TEST(interworking.isEsr == FALSE, "invalid data");
	TEST(interworking.isUesa == FALSE, "invalid data");
	TEST(interworking.isVenue == TRUE, "invalid data");
	TEST(interworking.venueGroup == 0, "invalid data");
	TEST(interworking.venueType == 0, "invalid data");
	TEST(interworking.isHessid == TRUE, "invalid data");
	TEST(memcmp(&interworking.hessid, "\xff\xff\xff\xff\xff\xff",
		sizeof(interworking.hessid)) == 0, "invalid data");

	TEST(bcm_decode_init(&dec1, ie.advertisementProtocolLength,
		ie.advertisementProtocol), "bcm_decode_init failed");
	TEST(bcm_decode_ie_advertisement_protocol(&dec1, &advertise),
		"bcm_decode_ie_advertisement_protocol failed");
	TEST(advertise.count == 1, "invalid data");
	TEST(advertise.protocol[0].queryResponseLimit == 0x7f, "invalid data");
	TEST(advertise.protocol[0].isPamebi == FALSE, "invalid data");
	TEST(advertise.protocol[0].protocolId == ADVP_ANQP_PROTOCOL_ID, "invalid data");

	TEST(bcm_decode_init(&dec1, ie.roamingConsortiumLength,
		ie.roamingConsortium), "bcm_decode_init failed");
	TEST(bcm_decode_ie_roaming_consortium(&dec1, &roam),
		"pktDecodeRoamingConsortium failed");
	TEST(roam.anqpOiCount == 0xff, "invalid data");
	TEST(roam.count == 3, "invalid data");
	TEST(memcmp(roam.oi[0].data, "\x00\x11\x22", roam.oi[0].length) == 0,
		"invalid data");
	TEST(memcmp(roam.oi[1].data, "\x55\x66\x77\x88", roam.oi[1].length) == 0,
		"invalid data");
	TEST(memcmp(roam.oi[2].data, "\xaa\xbb\xcc\xdd", roam.oi[2].length) == 0,
		"invalid data");

	TEST(bcm_decode_init(&dec1, ie.extendedCapabilityLength,
		ie.extendedCapability), "bcm_decode_init failed");
	TEST(bcm_decode_ie_extended_capabilities(&dec1, &cap),
		"bcm_decode_ie_extended_capabilities failed");
	TEST(cap == 0x80000000, "invalid data");
}

static void testDecodeCorruptLength(void)
{
	bcm_decode_t dec;
	bcm_decode_ie_t ie;
	uint8 *lenPtr;
	uint8 save;

	TEST(bcm_decode_init(&dec, bcm_encode_length(&enc),
		bcm_encode_buf(&enc)), "bcm_decode_init failed");
	WL_PRPKT("decode packet", bcm_decode_buf(&dec), bcm_decode_buf_length(&dec));

	lenPtr = &bcm_decode_buf(&dec)[1];
	save = *lenPtr;
	*lenPtr += 1;
	TEST(bcm_decode_ie(&dec, &ie) == 1, "bcm_decode_ie failed");
	*lenPtr = 0xff;
	TEST(bcm_decode_ie(&dec, &ie) == 0, "bcm_decode_ie failed");
	*lenPtr = save;
}

int main(int argc, char **argv)
{
	(void) argc;
	(void) argv;

	TRACE_LEVEL_SET(TRACE_ALL);
	TEST_INITIALIZE();

	testEncode();
	testDecode();
	testDecodeCorruptLength();

	TEST_FINALIZE();
	return 0;
}
