/*
 * Decode functions which provides decoding of information elements
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

#ifndef _BCM_DECODE_IE_H_
#define _BCM_DECODE_IE_H_

#include "typedefs.h"
#include "wlioctl.h"
#include "bcm_decode.h"
#include "bcm_decode_p2p.h"
#include "bcm_hspot.h"

typedef struct {
	int dsLength;
	uint8 *ds;
#ifndef BCMDRIVER	/* not used in dongle */
	int bssLoadLength;
	uint8 *bssLoad;
	int timeAdvertisementLength;
	uint8 *timeAdvertisement;
	int timeZoneLength;
	uint8 *timeZone;
	int interworkingLength;
	uint8 *interworking;
	int advertisementProtocolLength;
	uint8 *advertisementProtocol;
	int expeditedBandwidthRequestLength;
	uint8 *expeditedBandwidthRequest;
	int qosMapSetLength;
	uint8 *qosMapSet;
	int roamingConsortiumLength;
	uint8 *roamingConsortium;
	int emergencyAlertLength;
	uint8 *emergencyAlert;
	int extendedCapabilityLength;
	uint8 *extendedCapability;
	int rsnInfoLength;
	uint8 *rsnInfo;
#endif	/* BCMDRIVER */

	/* vendor specific */
	int hotspotIndicationLength;
	uint8 *hotspotIndication;
	int wpsIeLength;
	uint8 *wpsIe;
	int wfdIeLength;
	uint8 *wfdIe;
} bcm_decode_ie_t;

/* decode vendor IE */
int bcm_decode_ie(bcm_decode_t *pkt, bcm_decode_ie_t *ie);

/* decode hotspot 2.0 indication */
int bcm_decode_ie_hotspot_indication(bcm_decode_t *pkt, uint8 *hotspotConfig);

typedef struct
{
	int isDgafDisabled;
	uint8 releaseNumber;
} bcm_decode_hotspot_indication_t;

/* decode hotspot 2.0 indication release2 */
int bcm_decode_ie_hotspot_indication2(bcm_decode_t *pkt, bcm_decode_hotspot_indication_t *hotspot);

typedef struct
{
	uint8 accessNetworkType;
	int isInternet;
	int isAsra;
	int isEsr;
	int isUesa;
	int isVenue;
	uint8 venueGroup;
	uint8 venueType;
	int isHessid;
	struct ether_addr hessid;
} bcm_decode_interworking_t;

/* decode interworking */
int bcm_decode_ie_interworking(bcm_decode_t *pkt, bcm_decode_interworking_t *interworking);

typedef struct
{
	uint8 queryResponseLimit;
	int isPamebi;
	uint8 protocolId;
} bcm_decode_ie_adv_proto_tuple_t;

/* decode advertisement protocol tuple */
int bcm_decode_ie_advertisement_protocol_tuple(bcm_decode_t *pkt,
	bcm_decode_ie_adv_proto_tuple_t *tuple);

#define BCM_DECODE_IE_MAX_ADVERTISEMENT_PROTOCOL	8
typedef struct
{
	int count;
	bcm_decode_ie_adv_proto_tuple_t protocol[BCM_DECODE_IE_MAX_ADVERTISEMENT_PROTOCOL];
} bcm_decode_advertisement_protocol_t;

/* decode advertisement protocol */
int bcm_decode_ie_advertisement_protocol(bcm_decode_t *pkt,
	bcm_decode_advertisement_protocol_t *advertise);

#define BCM_DECODE_IE_MAX_IE_OI_LENGTH	15
typedef struct
{
	uint8 length;
	uint8 data[BCM_DECODE_IE_MAX_IE_OI_LENGTH];
} bcm_decode_oi_t;

#define BCM_DECODE_IE_MAX_IE_OI	3
typedef struct
{
	uint8 anqpOiCount;
	uint8 count;
	bcm_decode_oi_t oi[BCM_DECODE_IE_MAX_IE_OI];
} bcm_decode_roaming_consortium_t;

/* decode roaming consortium */
int bcm_decode_ie_roaming_consortium(bcm_decode_t *pkt, bcm_decode_roaming_consortium_t *roam);

/* decode extended capabilities */
int bcm_decode_ie_extended_capabilities(bcm_decode_t *pkt, uint32 *cap);

typedef struct
{
	uint16 year;
	uint8 month;
	uint8 day;
	uint8 hours;
	uint8 minutes;
	uint8 seconds;
	uint16 milliseconds;
	uint8 reserved;
} bcm_decode_time_t;

#define BCM_DECODE_IE_TIME_ERROR_LENGTH		5
#define BCM_DECODE_IE_TIME_UPDATE_LENGTH	1

typedef struct
{
	uint8 capabilities;
	bcm_decode_time_t timeValue;
	uint8 timeError[BCM_DECODE_IE_TIME_ERROR_LENGTH];
	uint8 timeUpdate[BCM_DECODE_IE_TIME_UPDATE_LENGTH];
} bcm_decode_time_advertisement_t;

/* decode time advertisement */
int bcm_decode_ie_time_advertisement(bcm_decode_t *pkt, bcm_decode_time_advertisement_t *time);

#define BCM_DECODE_IE_TIME_ZONE_LENGTH	255
typedef char bcm_decode_time_zone_t[BCM_DECODE_IE_TIME_ZONE_LENGTH + 1]; /* null terminated */

/* decode time zone */
int bcm_decode_ie_time_zone(bcm_decode_t *pkt, bcm_decode_time_zone_t *zone);

typedef struct
{
	uint16 stationCount;
	uint8 channelUtilization;
	uint16 availableAdmissionCapacity;
} bcm_decode_bss_load_t;

/* decode BSS load */
int bcm_decode_ie_bss_load(bcm_decode_t *pkt, bcm_decode_bss_load_t *load);

#define MAX_CIPHER_SUITE	8
#define PKMID_LENGTH		16

typedef struct
{
	uint16 version;
	uint32 groupCipherSuite;
	uint16 pairwiseCipherSuiteCount;
	uint32 pairwiseCipherSuite[MAX_CIPHER_SUITE];
	uint16 akmSuiteCount;
	uint32 akmSuite[MAX_CIPHER_SUITE];
	uint16 rsnCapabilities;
	uint16 pkmidCount;
	uint8 pkmid[MAX_CIPHER_SUITE][PKMID_LENGTH];
	uint32 groupManagementCipherSuite;
} bcm_decode_rsn_info_t;

/* decode RSN info */
int bcm_decode_ie_rsn_info(bcm_decode_t *pkt, bcm_decode_rsn_info_t *rsn);

typedef struct
{
	uint16 channel;
	int isP2P;
	int isP2PDeviceInfoDecoded;
	bcm_decode_p2p_device_info_t p2pDeviceInfo;
	int isP2PCapabilityDecoded;
	bcm_decode_p2p_capability_t p2pCapability;
	int isHotspotDecoded;
	uint8 hotspotConfig;
} bcm_decode_probe_response_t;

/* decode probe response from wl_bss_info_t */
int bcm_decode_ie_probe_response(wl_bss_info_t *bi, bcm_decode_probe_response_t *pr);

#endif /* _BCM_DECODE_IE_H_ */
