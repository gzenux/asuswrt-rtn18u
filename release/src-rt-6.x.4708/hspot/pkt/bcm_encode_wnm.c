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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "proto/802.11.h"
#include "trace.h"
#include "bcm_hspot.h"
#include "bcm_encode_wnm.h"

/* encode WNM-notification request for subscription remediation */
int bcm_encode_wnm_subscription_remediation(bcm_encode_t *pkt,
	uint8 dialogToken, uint8 urlLen, char *url, uint8 serverMethod)
{
	int initLen = bcm_encode_length(pkt);

	bcm_encode_byte(pkt, DOT11_ACTION_CAT_WNM);
	bcm_encode_byte(pkt, DOT11_WNM_ACTION_NOTFCTN_REQ);
	bcm_encode_byte(pkt, dialogToken);
	bcm_encode_byte(pkt, HSPOT_WNM_TYPE);
	bcm_encode_byte(pkt, DOT11_MNG_VS_ID);
	if (urlLen > 0) {
		bcm_encode_byte(pkt, 6 + urlLen);
	}
	else
		bcm_encode_byte(pkt, 5);
	bcm_encode_bytes(pkt, WFA_OUI_LEN, (uint8 *)WFA_OUI);
	bcm_encode_byte(pkt, HSPOT_WNM_SUBSCRIPTION_REMEDIATION);
	bcm_encode_byte(pkt, urlLen);
	if (urlLen > 0) {
		bcm_encode_bytes(pkt, urlLen, (uint8 *)url);
		bcm_encode_byte(pkt, serverMethod);
	}

	return bcm_encode_length(pkt) - initLen;
}

/* encode WNM-notification request for deauthentication imminent */
int bcm_encode_wnm_deauthentication_imminent(bcm_encode_t *pkt,
	uint8 dialogToken, uint8 reason, uint16 reauthDelay, uint8 urlLen, char *url)
{
	int initLen = bcm_encode_length(pkt);

	bcm_encode_byte(pkt, DOT11_ACTION_CAT_WNM);
	bcm_encode_byte(pkt, DOT11_WNM_ACTION_NOTFCTN_REQ);
	bcm_encode_byte(pkt, dialogToken);
	bcm_encode_byte(pkt, HSPOT_WNM_TYPE);
	bcm_encode_byte(pkt, DOT11_MNG_VS_ID);
	bcm_encode_byte(pkt, 8 + urlLen);
	bcm_encode_bytes(pkt, WFA_OUI_LEN, (uint8 *)WFA_OUI);
	bcm_encode_byte(pkt, HSPOT_WNM_DEAUTHENTICATION_IMMINENT);
	bcm_encode_byte(pkt, reason);
	bcm_encode_le16(pkt, reauthDelay);
	bcm_encode_byte(pkt, urlLen);
	if (urlLen > 0) {
		bcm_encode_bytes(pkt, urlLen, (uint8 *)url);
	}

	return bcm_encode_length(pkt) - initLen;
}
