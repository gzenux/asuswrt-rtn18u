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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "proto/802.11.h"
#include "trace.h"
#include "bcm_hspot.h"
#include "bcm_decode_wnm.h"

/* decode WNM-notification request for subscription remediation */
int bcm_decode_wnm_subscription_remediation(
	bcm_decode_t *pkt, bcm_decode_wnm_subscription_remediation_t *wnm)
{
	uint8 byte, len;
	uint8 oui[WFA_OUI_LEN];

	WL_PRPKT("packet for WNM subscription remediation decoding",
		bcm_decode_buf(pkt), bcm_decode_buf_length(pkt));

	memset(wnm, 0, sizeof(*wnm));

	if (!bcm_decode_byte(pkt, &byte) || byte != DOT11_ACTION_CAT_WNM) {
		WL_ERROR(("WNM action category\n"));
		return FALSE;
	}
	if (!bcm_decode_byte(pkt, &byte) || byte != DOT11_WNM_ACTION_NOTFCTN_REQ) {
		WL_ERROR(("WNM notifcation request\n"));
		return FALSE;
	}
	if (!bcm_decode_byte(pkt, &wnm->dialogToken)) {
		WL_ERROR(("dialog token\n"));
		return FALSE;
	}
	if (!bcm_decode_byte(pkt, &byte) || byte != HSPOT_WNM_TYPE) {
		WL_ERROR(("WNM type\n"));
		return FALSE;
	}
	if (!bcm_decode_byte(pkt, &byte) || byte != DOT11_MNG_VS_ID) {
		WL_ERROR(("vendor specific ID\n"));
		return FALSE;
	}
	if (!bcm_decode_byte(pkt, &len) || len < 6) {
		WL_ERROR(("length\n"));
		return FALSE;
	}
	if (len > bcm_decode_remaining(pkt)) {
		WL_ERROR(("length exceeds packet %d > %d\n",
			len, bcm_decode_remaining(pkt)));
		return FALSE;
	}
	if (!bcm_decode_bytes(pkt, WFA_OUI_LEN, oui) ||
		memcmp(oui, WFA_OUI, WFA_OUI_LEN) != 0) {
		WL_ERROR(("WFA OUI\n"));
		return FALSE;
	}
	if (!bcm_decode_byte(pkt, &byte) || byte != HSPOT_WNM_OUI_TYPE) {
		WL_ERROR(("hotspot WNM OUI type\n"));
		return FALSE;
	}
	if (!bcm_decode_byte(pkt, &wnm->urlLength) ||
		wnm->urlLength > bcm_decode_remaining(pkt)) {
		WL_ERROR(("URL length\n"));
		return FALSE;
	}
	if (wnm->urlLength > 0) {
		bcm_decode_bytes(pkt, wnm->urlLength, (uint8 *)wnm->url);
	}
	wnm->url[wnm->urlLength] = 0;

	return TRUE;
}
