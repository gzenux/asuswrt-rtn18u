/*
 * Decode functions which provides decoding of GAS packets as defined in 802.11u.
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

#ifndef _BCM_DECODE_GAS_H_
#define _BCM_DECODE_GAS_H_

#include "typedefs.h"
#include "bcm_decode.h"
#include "bcm_decode_ie.h"

typedef struct {
	bcm_decode_ie_adv_proto_tuple_t apie;
	uint16 reqLen;
	uint8 *req;
} bcm_pkt_gas_request_t;

typedef struct {
	uint16 statusCode;
	uint16 comebackDelay;
	bcm_decode_ie_adv_proto_tuple_t apie;
	uint16 rspLen;
	uint8 *rsp;
} bcm_pkt_gas_response_t;

typedef struct {
	uint16 statusCode;
	uint8 fragmentId;
	uint16 comebackDelay;
	bcm_decode_ie_adv_proto_tuple_t apie;
	uint16 rspLen;
	uint8 *rsp;
} bcm_pkt_gas_comeback_response_t;

typedef struct {
	uint8 category;
	uint8 action;
	uint8 dialogToken;
	union {
		bcm_pkt_gas_request_t request;
		bcm_pkt_gas_response_t response;
		/* none for comeback request */
		bcm_pkt_gas_comeback_response_t comebackResponse;
	};
} bcm_decode_gas_t;

/* decode GAS frame */
int bcm_decode_gas(bcm_decode_t *pkt, bcm_decode_gas_t *gasDecode);

#endif /* _BCM_DECODE_GAS_H_ */
