/*
 * Encode functions which provides encoding of information elements
 * as defined in 802.11.
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

#ifndef _BCM_ENCODE_IE_H_
#define _BCM_ENCODE_IE_H_

#include "typedefs.h"
#include "bcm_encode.h"
#include "bcm_hspot.h"

/* encode hotspot 2.0 indication */
int bcm_encode_ie_hotspot_indication(bcm_encode_t *pkt, uint8 hotspotConfig);

/* encode hotspot 2.0 indication release2 */
int bcm_encode_ie_hotspot_indication2(bcm_encode_t *pkt,
	int isDgafDisabled, uint8 releaseNumber);

/* encode interworking */
int bcm_encode_ie_interworking(bcm_encode_t *pkt, uint8 accessNetworkType,
	int isInternet, int isAsra, int isEsr, int isUesa,
	int isVenue, uint8 venueGroup, uint8 venueType, struct ether_addr *hessid);

/* encode advertisement protocol tuple */
int bcm_encode_ie_advertisement_protocol_tuple(bcm_encode_t *pkt,
	int isPamebi, uint8 qResponseLimit, uint8 protocolId);

/* encode advertisement protocol */
int bcm_encode_ie_advertisement_protocol_from_tuple(bcm_encode_t *pkt, uint8 len, uint8 *data);

/* encode roaming consortium */
int bcm_encode_ie_roaming_consortium(bcm_encode_t *pkt, uint8 numAnqpOi,
	uint8 oi1Len, uint8 *oi1, uint8 oi2Len, uint8 *oi2,
	uint8 oi3Len, uint8 *oi3);

/* encode extended capabilities */
int bcm_encode_ie_extended_capabilities(bcm_encode_t *pkt, uint32 cap);

/* encode advertisement protocol */
int bcm_encode_ie_advertisement_protocol(bcm_encode_t *pkt,
	uint8 pamebi, uint8 qRspLimit, uint8 id);

#endif /* _BCM_ENCODE_IE_H_ */
