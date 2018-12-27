/*
 * Encoding of WNM packets.
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

#ifndef _BCM_ENCODE_WNM_H_
#define _BCM_ENCODE_WNM_H_

#include "typedefs.h"
#include "bcm_encode.h"

/* encode WNM-notification request for subscription remediation */
int bcm_encode_wnm_subscription_remediation(bcm_encode_t *pkt,
	uint8 dialogToken, uint16 urlLen, char *url);

#endif /* _BCM_ENCODE_WNM_H_ */
