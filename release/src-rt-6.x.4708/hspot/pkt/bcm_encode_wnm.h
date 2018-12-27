/*
 * Encoding of WNM packets.
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

#ifndef _BCM_ENCODE_WNM_H_
#define _BCM_ENCODE_WNM_H_

#include "typedefs.h"
#include "bcm_encode.h"
#include "bcm_hspot.h"

/* encode WNM-notification request for subscription remediation */
int bcm_encode_wnm_subscription_remediation(bcm_encode_t *pkt,
	uint8 dialogToken, uint8 urlLen, char *url, uint8 serverMethod);

/* encode WNM-notification request for deauthentication imminent */
int bcm_encode_wnm_deauthentication_imminent(bcm_encode_t *pkt,
	uint8 dialogToken, uint8 reason, uint16 reauthDelay, uint8 urlLen, char *url);

#endif /* _BCM_ENCODE_WNM_H_ */
