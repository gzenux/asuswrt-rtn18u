/*
 * Encode functions which provides encoding of ANQP packets as defined in 802.11u.
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

#ifndef _BCM_ENCODE_ANQP_H_
#define _BCM_ENCODE_ANQP_H_

#include "typedefs.h"
#include "bcm_encode.h"

/* encode ANQP query list */
int bcm_encode_anqp_query_list(bcm_encode_t *pkt, uint16 queryLen, uint16 *queryId);

/* encode ANQP capability list */
int bcm_encode_anqp_capability_list(bcm_encode_t *pkt, uint16 capLen, uint16 *capList,
	uint16 vendorLen, uint8 *vendorList);

/* encode venue name duple */
int bcm_encode_anqp_venue_duple(bcm_encode_t *pkt, uint8 langLen, char *lang,
	uint8 nameLen, char *name);

/* encode venue name */
int bcm_encode_anqp_venue_name(bcm_encode_t *pkt, uint8 group, uint8 type,
	uint16 nameLen, uint8 *name);

/* encode network authentication unit */
int bcm_encode_anqp_network_authentication_unit(bcm_encode_t *pkt, uint8 type,
	uint16 urlLen, char *url);

/* encode network authentication type */
int bcm_encode_anqp_network_authentication_type(bcm_encode_t *pkt, uint16 len, uint8 *data);

/* encode OI duple */
int bcm_encode_anqp_oi_duple(bcm_encode_t *pkt, uint8 oiLen, uint8 *oi);

/* encode roaming consortium */
int bcm_encode_anqp_roaming_consortium(bcm_encode_t *pkt, uint16 len, uint8 *data);

/* encode IP address type availability */
int bcm_encode_anqp_ip_type_availability(bcm_encode_t *pkt, uint8 ipv6, uint8 ipv4);

/* encode authentication parameter subfield */
int bcm_encode_anqp_authentication_subfield(bcm_encode_t *pkt,
	uint8 id, uint8 authLen, uint8 *auth);

/* encode EAP method subfield */
int bcm_encode_anqp_eap_method_subfield(bcm_encode_t *pkt, uint8 method,
	uint8 authCount, uint8 authLen, uint8 *auth);

/* encode EAP method */
int bcm_encode_anqp_eap_method(bcm_encode_t *pkt, uint8 method,
	uint8 authCount, uint16 authLen, uint8 *auth);

/* encode NAI realm data */
int bcm_encode_anqp_nai_realm_data(bcm_encode_t *pkt, uint8 encoding,
	uint8 realmLen, uint8 *realm,
	uint8 eapCount, uint16 eapLen, uint8 *eap);

/* encode NAI realm */
int bcm_encode_anqp_nai_realm(bcm_encode_t *pkt,
	uint16 realmCount, uint16 len, uint8 *data);

/* encode PLMN */
int bcm_encode_anqp_plmn(bcm_encode_t *pkt, char *mcc, char *mnc);

/* encode 3GPP cellular network */
int bcm_encode_anqp_3gpp_cellular_network(bcm_encode_t *pkt,
	uint8 plmnCount, uint16 plmnLen, uint8 *plmnData);

/* encode domain name */
int bcm_encode_anqp_domain_name(bcm_encode_t *pkt, uint8 nameLen, char *name);

/* encode domain name list */
int bcm_encode_anqp_domain_name_list(bcm_encode_t *pkt, uint16 domainLen, uint8 *domain);

/* encode ANQP query vendor specific */
int bcm_encode_anqp_query_vendor_specific(bcm_encode_t *pkt,
	uint16 serviceUpdateIndicator, uint16 dataLen, uint8 *data);

/* encode ANQP query request vendor specific TLV */
int bcm_encode_anqp_query_request_vendor_specific_tlv(bcm_encode_t *pkt,
	uint8 serviceProtocolType, uint8 serviceTransactionId,
	uint16 queryLen, uint8 *queryData);

/* encode ANQP query response vendor specific TLV */
int bcm_encode_anqp_query_response_vendor_specific_tlv(bcm_encode_t *pkt,
	uint8 serviceProtocolType, uint8 serviceTransactionId, uint8 statusCode,
	uint16 queryLen, uint8 *queryData);

#endif /* _BCM_ENCODE_ANQP_H_ */
