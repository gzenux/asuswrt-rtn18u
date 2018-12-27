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

#ifndef _BCM_DECODE_QOS_H_
#define _BCM_DECODE_QOS_H_

#include "typedefs.h"
#include "bcm_decode.h"
#include "bcm_hspot.h"

#define BCM_DECODE_QOS_MAP_MAX_EXCEPT_LENGTH	128
#define BCM_DECODE_QOS_MAP_MAX_UP		8
typedef struct
{
	uint8 exceptCount;
	struct {
		uint8 dscp;
		uint8 up;
	} except[BCM_DECODE_QOS_MAP_MAX_EXCEPT_LENGTH];
	struct {
		uint8 low;
		uint8 high;
	} up[BCM_DECODE_QOS_MAP_MAX_UP];
} bcm_decode_qos_map_t;

/* decode QoS map */
int bcm_decode_qos_map(bcm_decode_t *pkt, bcm_decode_qos_map_t *qos);

#endif /* _BCM_DECODE_QOS_H_ */
