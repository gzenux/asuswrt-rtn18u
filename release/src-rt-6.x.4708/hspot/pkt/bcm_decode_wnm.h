/*
 * Decoding of WNM packets.
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

#ifndef _BCM_DECODE_WNM_H_
#define _BCM_DECODE_WNM_H_

#include "typedefs.h"
#include "bcm_decode.h"

#define BCM_DECODE_WNM_MAX_SERVER_URL_LENGTH	255
typedef struct
{
	uint8 dialogToken;
	uint8 urlLength;
	char url[BCM_DECODE_WNM_MAX_SERVER_URL_LENGTH + 1];	/* null terminated */
} bcm_decode_wnm_subscription_remediation_t;

/* decode WNM-notification request for subscription remediation */
int bcm_decode_wnm_subscription_remediation(bcm_decode_t *pkt,
	bcm_decode_wnm_subscription_remediation_t *wnm);

#endif /* _BCM_DECODE_WNM_H_ */
