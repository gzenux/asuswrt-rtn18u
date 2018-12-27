/*
 * Decoding of QoS packets.
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
#include "bcm_decode_qos.h"

/* decode QoS map */
int bcm_decode_qos_map(bcm_decode_t *pkt, bcm_decode_qos_map_t *qos)
{
	uint8 byte;
	uint8 len, except_len;
	int i;

	WL_PRPKT("packet for QoS map decoding",
		bcm_decode_buf(pkt), bcm_decode_buf_length(pkt));

	memset(qos, 0, sizeof(*qos));

	if (!bcm_decode_byte(pkt, &byte) || byte != DOT11_ACTION_CAT_QOS) {
		WL_ERROR(("QoS action category\n"));
		return FALSE;
	}
	if (!bcm_decode_byte(pkt, &byte) || byte != DOT11_QOS_ACTION_QOS_MAP) {
		WL_ERROR(("QoS map\n"));
		return FALSE;
	}
	if (!bcm_decode_byte(pkt, &byte) || byte != DOT11_MNG_QOS_MAP_ID) {
		WL_ERROR(("QoS ID\n"));
		return FALSE;
	}
	if (!bcm_decode_byte(pkt, &len) || len < 16 || ((len % 2) == 1)) {
		WL_ERROR(("length\n"));
		return FALSE;
	}
	if (len > bcm_decode_remaining(pkt)) {
		WL_ERROR(("length exceeds packet %d > %d\n",
			len, bcm_decode_remaining(pkt)));
		return FALSE;
	}
	except_len = len - 16;
	for (i = 0; i < except_len / 2; i++) {
		if (!bcm_decode_byte(pkt, &qos->except[i].dscp) ||
			!bcm_decode_byte(pkt, &qos->except[i].up)) {
			WL_ERROR(("DSCP exception\n"));
			return FALSE;
		}
	}
	qos->exceptCount = i;
	for (i = 0; i < 16 / 2; i++) {
		if (!bcm_decode_byte(pkt, &qos->up[i].low) ||
			!bcm_decode_byte(pkt, &qos->up[i].high)) {
			WL_ERROR(("DSCP range\n"));
			return FALSE;
		}
	}

	return TRUE;
}
