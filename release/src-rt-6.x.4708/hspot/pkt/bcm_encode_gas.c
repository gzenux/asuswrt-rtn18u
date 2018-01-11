/*
 * Encode functions which provides encoding of GAS packets as defined in 802.11u.
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
#include "trace.h"
#include "bcm_encode_gas.h"

/* encode GAS request */
int bcm_encode_gas_request(bcm_encode_t *pkt, uint8 dialogToken,
	uint8 apieLen, uint8 *apie, uint16 reqLen, uint8 *req)
{
	int initLen = bcm_encode_length(pkt);

	bcm_encode_byte(pkt, DOT11_ACTION_CAT_PUBLIC);
	bcm_encode_byte(pkt, GAS_REQUEST_ACTION_FRAME);
	bcm_encode_byte(pkt, dialogToken);
	if (apieLen > 0) {
		bcm_encode_bytes(pkt, apieLen, apie);
	}
	bcm_encode_le16(pkt, reqLen);
	if (reqLen > 0) {
		bcm_encode_bytes(pkt, reqLen, req);
	}

	return bcm_encode_length(pkt) - initLen;
}

/* encode GAS response */
int bcm_encode_gas_response(bcm_encode_t *pkt, uint8 dialogToken,
	uint16 statusCode, uint16 comebackDelay, uint8 apieLen, uint8 *apie,
	uint16 rspLen, uint8 *rsp)
{
	int initLen = bcm_encode_length(pkt);

	bcm_encode_byte(pkt, DOT11_ACTION_CAT_PUBLIC);
	bcm_encode_byte(pkt, GAS_RESPONSE_ACTION_FRAME);
	bcm_encode_byte(pkt, dialogToken);
	bcm_encode_le16(pkt, statusCode);
	bcm_encode_le16(pkt, comebackDelay);
	if (apieLen > 0) {
		bcm_encode_bytes(pkt, apieLen, apie);
	}
	bcm_encode_le16(pkt, rspLen);
	if (rspLen > 0) {
		bcm_encode_bytes(pkt, rspLen, rsp);
	}

	return bcm_encode_length(pkt) - initLen;
}

/* encode GAS comeback request */
int bcm_encode_gas_comeback_request(bcm_encode_t *pkt, uint8 dialogToken)
{
	int initLen = bcm_encode_length(pkt);

	bcm_encode_byte(pkt, DOT11_ACTION_CAT_PUBLIC);
	bcm_encode_byte(pkt, GAS_COMEBACK_REQUEST_ACTION_FRAME);
	bcm_encode_byte(pkt, dialogToken);

	return bcm_encode_length(pkt) - initLen;
}

/* encode GAS response */
int bcm_encode_gas_comeback_response(bcm_encode_t *pkt, uint8 dialogToken,
	uint16 statusCode, uint8 fragmentId, uint16 comebackDelay,
	uint8 apieLen, uint8 *apie, uint16 rspLen, uint8 *rsp)
{
	int initLen = bcm_encode_length(pkt);

	bcm_encode_byte(pkt, DOT11_ACTION_CAT_PUBLIC);
	bcm_encode_byte(pkt, GAS_COMEBACK_RESPONSE_ACTION_FRAME);
	bcm_encode_byte(pkt, dialogToken);
	bcm_encode_le16(pkt, statusCode);
	bcm_encode_byte(pkt, fragmentId);
	bcm_encode_le16(pkt, comebackDelay);
	if (apieLen > 0) {
		bcm_encode_bytes(pkt, apieLen, apie);
	}
	bcm_encode_le16(pkt, rspLen);
	if (rspLen > 0) {
		bcm_encode_bytes(pkt, rspLen, rsp);
	}

	return bcm_encode_length(pkt) - initLen;
}
