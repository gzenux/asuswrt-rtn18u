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

#ifndef _BCM_ENCODE_GAS_H_
#define _BCM_ENCODE_GAS_H_

#include "typedefs.h"
#include "bcm_encode.h"

/* encode GAS request */
int bcm_encode_gas_request(bcm_encode_t *pkt, uint8 dialogToken,
	uint8 apieLen, uint8 *apie, uint16 reqLen, uint8 *req);

/* encode GAS response */
int bcm_encode_gas_response(bcm_encode_t *pkt, uint8 dialogToken,
	uint16 statusCode, uint16 comebackDelay, uint8 apieLen, uint8 *apie,
	uint16 rspLen, uint8 *rsp);

/* encode GAS comeback request */
int bcm_encode_gas_comeback_request(bcm_encode_t *pkt, uint8 dialogToken);

/* encode GAS response */
int bcm_encode_gas_comeback_response(bcm_encode_t *pkt, uint8 dialogToken,
	uint16 statusCode, uint8 fragmentId, uint16 comebackDelay,
	uint8 apieLen, uint8 *apie, uint16 rspLen, uint8 *rsp);

#endif /* _BCM_ENCODE_GAS_H_ */
