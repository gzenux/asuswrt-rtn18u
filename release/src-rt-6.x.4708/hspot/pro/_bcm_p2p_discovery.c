/*
 * Test harness for WiFi-Direct discovery state machine.
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
#include "bcm_p2p_discovery.h"

TEST_DECLARE();

/* --------------------------------------------------------------- */

void testP2PDiscovery(void)
{
	bcm_p2p_discovery_t *disc;

	TEST(bcm_p2p_discovery_initialize(), "bcm_p2p_discovery_initialize failed");
	disc = bcm_p2p_discovery_create(0, 11);
	TEST(disc != 0, "bcm_p2p_discovery_create failed");

	/* discovery */
	TEST(bcm_p2p_discovery_start_discovery(disc), "bcm_p2p_discovery_start_discovery failed");
	sleep(15);
	TEST(bcm_p2p_discovery_reset(disc), "bcm_p2p_discovery_reset failed");

	/* extended listen */
	TEST(bcm_p2p_discovery_start_ext_listen(disc, 500, 4500),
		"bcm_p2p_discovery_start_ext_listen failed");
	sleep(15);
	TEST(bcm_p2p_discovery_reset(disc), "bcm_p2p_discovery_reset failed");

	/* listen */
	TEST(bcm_p2p_discovery_start_ext_listen(disc, 5000, 0),
		"bcm_p2p_discovery_start_ext_listen failed");
	sleep(15);
	TEST(bcm_p2p_discovery_reset(disc), "bcm_p2p_discovery_reset failed");

	TEST(bcm_p2p_discovery_destroy(disc), "bcm_p2p_discovery_destroy failed");
	TEST(bcm_p2p_discovery_deinitialize(), "bcm_p2p_discovery_deinitialize failed");
}

int main(int argc, char **argv)
{
	(void) argc;
	(void) argv;

	TRACE_LEVEL_SET(TRACE_ERROR | TRACE_DEBUG);
	TEST_INITIALIZE();

	testP2PDiscovery();

	/* disable wlan */
	wlFree();

	/* terminate dispatcher */
	dspFree();

	TEST_FINALIZE();
	return 0;
}
