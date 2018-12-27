/*
 * Encoding of QoS packets.
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
#include "trace.h"
#include "bcm_hspot.h"
#include "bcm_encode_qos.h"

/* encode QoS map */
int bcm_encode_qos_map(bcm_encode_t *pkt,
	uint8 except_length, uint8 *except_data,
	uint8 up0_low, uint8 up0_high,
	uint8 up1_low, uint8 up1_high,
	uint8 up2_low, uint8 up2_high,
	uint8 up3_low, uint8 up3_high,
	uint8 up4_low, uint8 up4_high,
	uint8 up5_low, uint8 up5_high,
	uint8 up6_low, uint8 up6_high,
	uint8 up7_low, uint8 up7_high)
{
	int initLen = bcm_encode_length(pkt);

	bcm_encode_byte(pkt, DOT11_ACTION_CAT_QOS);
	bcm_encode_byte(pkt, DOT11_QOS_ACTION_QOS_MAP);
	bcm_encode_byte(pkt, DOT11_MNG_QOS_MAP_ID);
	bcm_encode_byte(pkt, 16 + except_length);
	if (except_length > 0)
		bcm_encode_bytes(pkt, except_length, except_data);
	bcm_encode_byte(pkt, up0_low);
	bcm_encode_byte(pkt, up0_high);
	bcm_encode_byte(pkt, up1_low);
	bcm_encode_byte(pkt, up1_high);
	bcm_encode_byte(pkt, up2_low);
	bcm_encode_byte(pkt, up2_high);
	bcm_encode_byte(pkt, up3_low);
	bcm_encode_byte(pkt, up3_high);
	bcm_encode_byte(pkt, up4_low);
	bcm_encode_byte(pkt, up4_high);
	bcm_encode_byte(pkt, up5_low);
	bcm_encode_byte(pkt, up5_high);
	bcm_encode_byte(pkt, up6_low);
	bcm_encode_byte(pkt, up6_high);
	bcm_encode_byte(pkt, up7_low);
	bcm_encode_byte(pkt, up7_high);

	return bcm_encode_length(pkt) - initLen;
}
