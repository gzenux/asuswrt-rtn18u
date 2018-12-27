/*
 * Encode functions which provides encoding of Hotspot2.0 ANQP packets
 * as defined in Hotspot2.0 specification.
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

#ifndef _BCM_ENCODE_HSPOT_ANQP_H_
#define _BCM_ENCODE_HSPOT_ANQP_H_

#include "typedefs.h"
#include "bcm_encode.h"
#include "bcm_hspot.h"

/* encode query list */
int bcm_encode_hspot_anqp_query_list(bcm_encode_t *pkt, uint16 queryLen, uint8 *query);

/* encode capability list */
int bcm_encode_hspot_anqp_capability_list(bcm_encode_t *pkt, uint16 capLen, uint8 *cap);

/* encode operator friendly name */
int bcm_encode_hspot_anqp_operator_name_duple(bcm_encode_t *pkt, uint8 langLen, char *lang,
	uint8 nameLen, char *name);
int bcm_encode_hspot_anqp_operator_friendly_name(bcm_encode_t *pkt, uint16 nameLen, uint8 *name);

/* encode WAN metrics */
int bcm_encode_hspot_anqp_wan_metrics(bcm_encode_t *pkt, uint8 linkStatus, uint8 symmetricLink,
	uint8 atCapacity, uint32 dlinkSpeed, uint32 ulinkSpeed,
	uint8 dlinkLoad, uint8 ulinkLoad, uint16 lmd);

/* encode connection capability */
int bcm_encode_hspot_anqp_proto_port_tuple(bcm_encode_t *pkt,
	uint8 ipProtocol, uint16 portNumber, uint8 status);
int bcm_encode_hspot_anqp_connection_capability(bcm_encode_t *pkt, uint16 capLen, uint8 *cap);

/* encode NAI home realm query */
int bcm_encode_hspot_anqp_nai_home_realm_name(bcm_encode_t *pkt, uint8 encoding,
	uint8 nameLen, char *name);
int pktEncodeHspotAnqpNaiHomeRealmQuery(bcm_encode_t *pkt, uint8 count,
	uint16 nameLen, uint8 *name);

/* encode operating class indication */
int bcm_encode_hspot_anqp_operating_class_indication(bcm_encode_t *pkt,
	uint16 opClassLen, uint8 *opClass);

/* encode icon metadata */
int bcm_encode_hspot_anqp_icon_metadata(bcm_encode_t *pkt,
	uint16 width, uint16 height, char *lang,
	uint8 typeLength, uint8 *type, uint8 filenameLength, uint8 *filename);
/* encode OSU provider */
int bcm_encode_hspot_anqp_osu_provider(bcm_encode_t *pkt,
	uint16 nameLength, uint8 *name,	uint8 uriLength, uint8 *uri,
	uint8 methodLength, uint8 *method, uint16 iconLength, uint8 *icon,
	uint8 naiLength, uint8 *nai, uint16 descLength, uint8 *desc);
/* encode OSU provider list */
int bcm_encode_hspot_anqp_osu_provider_list(bcm_encode_t *pkt,
	uint8 osuSsidLength, uint8 *osuSsid,
	uint8 numOsuProvider, uint16 providerLength, uint8 *provider);


/* encode anonymous NAI */
int bcm_encode_hspot_anqp_anonymous_nai(bcm_encode_t *pkt, uint16 length, uint8 *nai);

/* encode icon request */
int bcm_encode_hspot_anqp_icon_request(bcm_encode_t *pkt, uint16 length, uint8 *filename);

/* encode icon binary file */
int bcm_encode_hspot_anqp_icon_binary_file(bcm_encode_t *pkt,
	uint8 status, uint8 typeLength, uint8 *type, uint16 length, uint8 *data);

#endif /* _BCM_ENCODE_HSPOT_ANQP_H_ */
