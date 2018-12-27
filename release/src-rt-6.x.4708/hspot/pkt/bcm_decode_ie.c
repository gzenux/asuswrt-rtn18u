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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "proto/802.11.h"
#include "proto/p2p.h"
#include "wlioctl.h"
#include "trace.h"
#include "bcm_decode.h"
#include "bcm_decode_p2p.h"
#include "bcm_decode_ie.h"

static void printIes(bcm_decode_ie_t *ie)
{
#if !defined(BCMDBG)
	(void)ie;
#endif
	WL_TRACE(("decoded IEs:\n"));

	WL_PRPKT("   DS",
		ie->ds, ie->dsLength);
	WL_PRPKT("   BSS load",
		ie->bssLoad, ie->bssLoadLength);
	WL_PRPKT("   time advertise",
		ie->timeAdvertisement, ie->timeAdvertisementLength);
	WL_PRPKT("   time zone",
		ie->timeZone, ie->timeZoneLength);
	WL_PRPKT("   interworking",
		ie->interworking, ie->interworkingLength);
	WL_PRPKT("   advertisement protocol",
		ie->advertisementProtocol, ie->advertisementProtocolLength);
	WL_PRPKT("   expedited bandwidth request",
		ie->expeditedBandwidthRequest, ie->expeditedBandwidthRequestLength);
	WL_PRPKT("   QOS map set",
		ie->qosMapSet, ie->qosMapSetLength);
	WL_PRPKT("   roaming consortium",
		ie->roamingConsortium, ie->roamingConsortiumLength);
	WL_PRPKT("   emergency alert",
		ie->emergencyAlert, ie->emergencyAlertLength);
	WL_PRPKT("   extended capability",
		ie->extendedCapability, ie->extendedCapabilityLength);
	WL_PRPKT("   hotspot indication",
		ie->hotspotIndication, ie->hotspotIndicationLength);
	WL_PRPKT("   WPS vendor specific",
		ie->wpsIe, ie->wpsIeLength);
	WL_PRPKT("   WFD vendor specific",
		ie->wfdIe, ie->wfdIeLength);
}

/* decode IE */
int bcm_decode_ie(bcm_decode_t *pkt, bcm_decode_ie_t *ie)
{
	int nextIeOffset = 0;
	int ieCount = 0;

	WL_PRPKT("packet for IE decoding",
		bcm_decode_buf(pkt), bcm_decode_buf_length(pkt));

	memset(ie, 0, sizeof(*ie));

	while (nextIeOffset < bcm_decode_buf_length(pkt)) {
		uint8 id;
		uint8 length;
		int dataLength;
		uint8 *dataPtr;

		bcm_decode_offset_set(pkt, nextIeOffset);
		WL_TRACE(("decoding offset 0x%x\n", bcm_decode_offset(pkt)));

		/* minimum ID and length */
		if (bcm_decode_remaining(pkt) < 2) {
			WL_P2PO(("ID and length too short\n"));
			break;
		}

		(void)bcm_decode_byte(pkt, &id);
		(void)bcm_decode_byte(pkt, &length);

		/* check length */
		if (length > bcm_decode_remaining(pkt)) {
			WL_P2PO(("length exceeds packet %d > %d\n",
				length, bcm_decode_remaining(pkt)));
			break;
		}
		nextIeOffset = bcm_decode_offset(pkt) + length;

		/* data */
		dataLength = length;
		dataPtr = bcm_decode_current_ptr(pkt);

		switch (id)
		{
		case DOT11_MNG_DS_PARMS_ID:
			ie->dsLength = dataLength;
			ie->ds = dataPtr;
			break;
#ifndef BCMDRIVER	/* not used in dongle */
		case DOT11_MNG_QBSS_LOAD_ID:
			ie->bssLoadLength = dataLength;
			ie->bssLoad = dataPtr;
			break;
		case DOT11_MNG_TIME_ADVERTISE_ID:
			ie->timeAdvertisementLength = dataLength;
			ie->timeAdvertisement = dataPtr;
			break;
		case DOT11_MNG_TIME_ZONE_ID:
			ie->timeZoneLength = dataLength;
			ie->timeZone = dataPtr;
			break;
		case DOT11_MNG_INTERWORKING_ID:
			ie->interworkingLength = dataLength;
			ie->interworking = dataPtr;
			break;
		case DOT11_MNG_ADVERTISEMENT_ID:
			ie->advertisementProtocolLength = dataLength;
			ie->advertisementProtocol = dataPtr;
			break;
		case DOT11_MNG_EXP_BW_REQ_ID:
			ie->expeditedBandwidthRequestLength = dataLength;
			ie->expeditedBandwidthRequest = dataPtr;
			break;
		case DOT11_MNG_QOS_MAP_ID:
			ie->qosMapSetLength = dataLength;
			ie->qosMapSet = dataPtr;
			break;
		case DOT11_MNG_ROAM_CONSORT_ID:
			ie->roamingConsortiumLength = dataLength;
			ie->roamingConsortium = dataPtr;
			break;
		case DOT11_MNG_EMERGCY_ALERT_ID:
			ie->emergencyAlertLength = dataLength;
			ie->emergencyAlert = dataPtr;
			break;
		case DOT11_MNG_EXT_CAP_ID:
			ie->extendedCapabilityLength = dataLength;
			ie->extendedCapability = dataPtr;
			break;
		case DOT11_MNG_RSN_ID:
			ie->rsnInfoLength = dataLength;
			ie->rsnInfo = dataPtr;
			break;
#endif	/* BCMDRIVER */
		case DOT11_MNG_VS_ID:
			if (dataLength >= WFA_OUI_LEN + 1 &&
				memcmp(dataPtr, WFA_OUI, WFA_OUI_LEN) == 0 &&
				dataPtr[WFA_OUI_LEN] == HSPOT_IE_OUI_TYPE) {
				ie->hotspotIndicationLength = dataLength;
				ie->hotspotIndication = dataPtr;
			}
			else if (dataLength >= WPS_OUI_LEN + 1 &&
				memcmp(dataPtr, WPS_OUI, WPS_OUI_LEN) == 0 &&
				dataPtr[WPS_OUI_LEN] == WPS_OUI_TYPE) {
				ie->wpsIeLength = dataLength;
				ie->wpsIe = dataPtr;
			}
			else if (dataLength >= WFA_OUI_LEN + 1 &&
				memcmp(dataPtr, WFA_OUI, WFA_OUI_LEN) == 0 &&
				dataPtr[WFA_OUI_LEN] == WFA_OUI_TYPE_P2P) {
				ie->wfdIeLength = dataLength;
				ie->wfdIe = dataPtr;
			}
			break;
		default:
			continue;
			break;
		}

		/* count IEs decoded */
		ieCount++;
	}

	if (ieCount > 0)
		printIes(ie);

	return ieCount;
}

/* decode hotspot 2.0 indication */
int bcm_decode_ie_hotspot_indication(bcm_decode_t *pkt, uint8 *hotspotConfig)
{
	uint8 oui[WFA_OUI_LEN];
	uint8 type;

	WL_PRPKT("packet for hotspot indication decoding",
		bcm_decode_buf(pkt), bcm_decode_buf_length(pkt));

	*hotspotConfig = 0;

	/* check OUI */
	if (!bcm_decode_bytes(pkt, WFA_OUI_LEN, oui) ||
		memcmp(oui, WFA_OUI, WFA_OUI_LEN) != 0) {
		WL_ERROR(("decode error\n"));
		return FALSE;
	}

	/* check type */
	if (!bcm_decode_byte(pkt, &type) || type != HSPOT_IE_OUI_TYPE) {
		WL_ERROR(("decode error\n"));
		return FALSE;
	}

	/* hotspot configuration */
	if (!bcm_decode_byte(pkt, hotspotConfig)) {
		WL_ERROR(("decode error\n"));
		return FALSE;
	}

	return TRUE;
}

/* decode hotspot 2.0 indication release2 */
int bcm_decode_ie_hotspot_indication2(bcm_decode_t *pkt, bcm_decode_hotspot_indication_t *hotspot)
{
	uint8 config;

	if (!bcm_decode_ie_hotspot_indication(pkt, &config))
		return FALSE;

	memset(hotspot, 0, sizeof(*hotspot));
	if (config & HSPOT_DGAF_DISABLED_MASK)
		hotspot->isDgafDisabled = TRUE;
	hotspot->releaseNumber =
		(config & HSPOT_RELEASE_MASK) >> HSPOT_RELEASE_SHIFT;
	return TRUE;
}

/* decode interworking */
int bcm_decode_ie_interworking(bcm_decode_t *pkt, bcm_decode_interworking_t *interworking)
{
	uint8 options;

	WL_PRPKT("packet for interworking decoding",
		bcm_decode_buf(pkt), bcm_decode_buf_length(pkt));

	memset(interworking, 0, sizeof(*interworking));

	if (!bcm_decode_byte(pkt, &options)) {
		WL_ERROR(("decode error\n"));
		return FALSE;
	}

	interworking->accessNetworkType = options & IW_ANT_MASK;
	if (options & IW_INTERNET_MASK)
		interworking->isInternet = TRUE;
	if (options & IW_ASRA_MASK)
		interworking->isAsra = TRUE;
	if (options & IW_ESR_MASK)
		interworking->isEsr = TRUE;
	if (options & IW_UESA_MASK)
		interworking->isUesa = TRUE;

	if (bcm_decode_remaining(pkt) == 0)
		return TRUE;

	if (bcm_decode_remaining(pkt) == 2 || bcm_decode_remaining(pkt) == 8) {
	if (!bcm_decode_byte(pkt, &interworking->venueGroup)) {
		WL_ERROR(("decode error\n"));
		return FALSE;
	}
	if (!bcm_decode_byte(pkt, &interworking->venueType)) {
		WL_ERROR(("decode error\n"));
		return FALSE;
	}
	interworking->isVenue = TRUE;
	}

	if (bcm_decode_remaining(pkt) == 0)
		return TRUE;

	if (!bcm_decode_bytes(pkt, sizeof(interworking->hessid),
		(uint8 *)&interworking->hessid)) {
		WL_ERROR(("decode error\n"));
		return FALSE;
	}
	interworking->isHessid = TRUE;

	return TRUE;
}

/* decode advertisement protocol tuple */
int bcm_decode_ie_advertisement_protocol_tuple(bcm_decode_t *pkt,
	bcm_decode_ie_adv_proto_tuple_t *tuple)
{
	uint8 info;

	memset(tuple, 0, sizeof(*tuple));

	if (!bcm_decode_byte(pkt, &info)) {
		WL_ERROR(("decode error\n"));
		return FALSE;
	}

	tuple->queryResponseLimit = info & ADVP_QRL_MASK;
	if (info & ADVP_PAME_BI_MASK)
		tuple->isPamebi = TRUE;

	if (!bcm_decode_byte(pkt, &tuple->protocolId)) {
		WL_ERROR(("decode error\n"));
		return FALSE;
	}

	return TRUE;
}

/* decode advertisement protocol */
int bcm_decode_ie_advertisement_protocol(bcm_decode_t *pkt,
	bcm_decode_advertisement_protocol_t *advertise)
{
	WL_PRPKT("packet for advertisement protocol decoding",
		bcm_decode_buf(pkt), bcm_decode_buf_length(pkt));

	memset(advertise, 0, sizeof(*advertise));

	while (bcm_decode_remaining(pkt) > 0 &&
		advertise->count < BCM_DECODE_IE_MAX_ADVERTISEMENT_PROTOCOL) {
		bcm_decode_ie_adv_proto_tuple_t *tuple =
			&advertise->protocol[advertise->count];

		if (!bcm_decode_ie_advertisement_protocol_tuple(pkt, tuple)) {
			WL_ERROR(("decode error\n"));
			return FALSE;
		}

		advertise->count++;
	}

	return TRUE;
}

/* decode roaming consortium */
int bcm_decode_ie_roaming_consortium(bcm_decode_t *pkt, bcm_decode_roaming_consortium_t *roam)
{
	uint8 oiLengths;
	uint8 oiLen1, oiLen2;
	bcm_decode_oi_t *oi;

	WL_PRPKT("packet for roaming consortium decoding",
		bcm_decode_buf(pkt), bcm_decode_buf_length(pkt));

	memset(roam, 0, sizeof(*roam));

	if (!bcm_decode_byte(pkt, &roam->anqpOiCount)) {
		WL_ERROR(("decode error\n"));
		return FALSE;
	}

	if (!bcm_decode_byte(pkt, &oiLengths)) {
		WL_ERROR(("decode error\n"));
		return FALSE;
	}

	oiLen1 = oiLengths & 0x0f;
	oiLen2 = oiLengths >> 4;

	if (oiLen1 == 0 && oiLen2 == 0)
		return TRUE;

	if (bcm_decode_remaining(pkt) < oiLen1 + oiLen2) {
		WL_ERROR(("decode error\n"));
		return FALSE;
	}

	oi = &roam->oi[0];
	oi->length = oiLen1;
	if (!bcm_decode_bytes(pkt, oi->length, oi->data)) {
		WL_ERROR(("decode error\n"));
		return FALSE;
	}
	roam->count++;

	if (oiLen2 == 0)
		return TRUE;

	oi = &roam->oi[1];
	oi->length = oiLen2;
	if (!bcm_decode_bytes(pkt, oi->length, oi->data)) {
		WL_ERROR(("decode error\n"));
		return FALSE;
	}
	roam->count++;

	if (bcm_decode_remaining(pkt) == 0)
		return TRUE;

	if (bcm_decode_remaining(pkt) > BCM_DECODE_IE_MAX_IE_OI_LENGTH) {
		WL_ERROR(("OI #3 length %d > %d\n",
			bcm_decode_remaining(pkt), BCM_DECODE_IE_MAX_IE_OI_LENGTH));
		return FALSE;
	}

	oi = &roam->oi[2];
	oi->length = bcm_decode_remaining(pkt);
	if (!bcm_decode_bytes(pkt, oi->length, oi->data)) {
		WL_ERROR(("decode error\n"));
		return FALSE;
	}
	roam->count++;

	return TRUE;
}

/* decode extended capabilities */
int bcm_decode_ie_extended_capabilities(bcm_decode_t *pkt, uint32 *cap)
{
	WL_PRPKT("packet for extended capabilities decoding",
		bcm_decode_buf(pkt), bcm_decode_buf_length(pkt));

	memset(cap, 0, sizeof(*cap));

	if (!bcm_decode_le32(pkt, cap)) {
		WL_ERROR(("decode error\n"));
		return FALSE;
	}

	return TRUE;
}

/* decode time advertisement */
int bcm_decode_ie_time_advertisement(bcm_decode_t *pkt, bcm_decode_time_advertisement_t *time)
{
	WL_PRPKT("packet for time advertisement decoding",
		bcm_decode_buf(pkt), bcm_decode_buf_length(pkt));

	memset(time, 0, sizeof(*time));

	if (!bcm_decode_byte(pkt, &time->capabilities)) {
		WL_ERROR(("decode error\n"));
		return FALSE;
	}

	if (bcm_decode_remaining(pkt) == 0)
		return TRUE;

	if (!bcm_decode_le16(pkt, &time->timeValue.year)) {
		WL_ERROR(("decode error\n"));
		return FALSE;
	}

	if (!bcm_decode_byte(pkt, &time->timeValue.month)) {
		WL_ERROR(("decode error\n"));
		return FALSE;
	}

	if (!bcm_decode_byte(pkt, &time->timeValue.day)) {
		WL_ERROR(("decode error\n"));
		return FALSE;
	}

	if (!bcm_decode_byte(pkt, &time->timeValue.hours)) {
		WL_ERROR(("decode error\n"));
		return FALSE;
	}

	if (!bcm_decode_byte(pkt, &time->timeValue.minutes)) {
		WL_ERROR(("decode error\n"));
		return FALSE;
	}

	if (!bcm_decode_byte(pkt, &time->timeValue.seconds)) {
		WL_ERROR(("decode error\n"));
		return FALSE;
	}

	if (!bcm_decode_le16(pkt, &time->timeValue.milliseconds)) {
		WL_ERROR(("decode error\n"));
		return FALSE;
	}

	if (!bcm_decode_byte(pkt, &time->timeValue.reserved)) {
		WL_ERROR(("decode error\n"));
		return FALSE;
	}

	if (bcm_decode_remaining(pkt) == 0)
		return TRUE;

	if (!bcm_decode_bytes(pkt, sizeof(time->timeError), time->timeError)) {
		WL_ERROR(("decode error\n"));
		return FALSE;
	}

	if (bcm_decode_remaining(pkt) == 0)
		return TRUE;

	if (!bcm_decode_bytes(pkt, sizeof(time->timeUpdate), time->timeUpdate)) {
		WL_ERROR(("decode error\n"));
		return FALSE;
	}

	return TRUE;
}

/* decode time zone */
int bcm_decode_ie_time_zone(bcm_decode_t *pkt, bcm_decode_time_zone_t *zone)
{
	WL_PRPKT("packet for time zone decoding",
		bcm_decode_buf(pkt), bcm_decode_buf_length(pkt));

	memset(zone, 0, sizeof(*zone));
	(void)bcm_decode_bytes(pkt, bcm_decode_buf_length(pkt), (uint8 *)zone);
	return TRUE;
}

/* decode BSS load */
int bcm_decode_ie_bss_load(bcm_decode_t *pkt, bcm_decode_bss_load_t *load)
{
	WL_PRPKT("packet for BSS load decoding",
		bcm_decode_buf(pkt), bcm_decode_buf_length(pkt));

	memset(load, 0, sizeof(*load));

	if (!bcm_decode_le16(pkt, &load->stationCount)) {
		WL_ERROR(("decode error\n"));
		return FALSE;
	}

	if (!bcm_decode_byte(pkt, &load->channelUtilization)) {
		WL_ERROR(("decode error\n"));
		return FALSE;
	}

	if (!bcm_decode_le16(pkt, &load->availableAdmissionCapacity)) {
		WL_ERROR(("decode error\n"));
		return FALSE;
	}

	return TRUE;
}

/* decode RSN info */
int bcm_decode_ie_rsn_info(bcm_decode_t *pkt, bcm_decode_rsn_info_t *rsn)
{
	int i;

	WL_PRPKT("packet for RSN info decoding",
		bcm_decode_buf(pkt), bcm_decode_buf_length(pkt));

	memset(rsn, 0, sizeof(*rsn));

	if (!bcm_decode_le16(pkt, &rsn->version)) {
		WL_ERROR(("decode error\n"));
		return FALSE;
	}
	if (!bcm_decode_le32(pkt, &rsn->groupCipherSuite)) {
		WL_ERROR(("decode error\n"));
		return FALSE;
	}

	if (bcm_decode_remaining(pkt) >= 2 &&
		!bcm_decode_le16(pkt, &rsn->pairwiseCipherSuiteCount)) {
		WL_ERROR(("decode error\n"));
		return FALSE;
	}
	for (i = 0; i < rsn->pairwiseCipherSuiteCount && i < MAX_CIPHER_SUITE; i++) {
		if (!bcm_decode_le32(pkt, &rsn->pairwiseCipherSuite[i])) {
			WL_ERROR(("decode error\n"));
			return FALSE;
		}
	}

	if (bcm_decode_remaining(pkt) >= 2 &&
		!bcm_decode_le16(pkt, &rsn->akmSuiteCount)) {
		WL_ERROR(("decode error\n"));
		return FALSE;
	}
	for (i = 0; i < rsn->akmSuiteCount && i < MAX_CIPHER_SUITE; i++) {
		if (!bcm_decode_le32(pkt, &rsn->akmSuite[i])) {
			WL_ERROR(("decode error\n"));
			return FALSE;
		}
	}

	if (bcm_decode_remaining(pkt) >= 2 &&
		!bcm_decode_le16(pkt, &rsn->rsnCapabilities)) {
		WL_ERROR(("decode error\n"));
		return FALSE;
	}

	if (bcm_decode_remaining(pkt) >= 2 &&
		!bcm_decode_le16(pkt, &rsn->pkmidCount)) {
		WL_ERROR(("decode error\n"));
		return FALSE;
	}
	for (i = 0; i < rsn->pkmidCount && i < MAX_CIPHER_SUITE; i++) {
		if (!bcm_decode_bytes(pkt, PKMID_LENGTH, rsn->pkmid[i])) {
			WL_ERROR(("decode error\n"));
			return FALSE;
		}
	}

	if (bcm_decode_remaining(pkt) >= 4 &&
		!bcm_decode_le32(pkt, &rsn->groupManagementCipherSuite)) {
		WL_ERROR(("decode error\n"));
		return FALSE;
	}

	return TRUE;
}

/* decode probe response from wl_bss_info_t */
int bcm_decode_ie_probe_response(wl_bss_info_t *bi, bcm_decode_probe_response_t *pr)
{
	memset(pr, 0, sizeof(*pr));

	/* deocde probe responses only */
	if ((bi->flags & WL_BSS_FLAGS_FROM_BEACON) == 0) {
		uint8 *biData = (uint8 *)bi;
		bcm_decode_t pkt;
		bcm_decode_ie_t ies;

		bcm_decode_init(&pkt, bi->ie_length, &biData[bi->ie_offset]);
		bcm_decode_ie(&pkt, &ies);

		/* channel from DS IE if available */
		pr->channel = ies.dsLength == 1 ? *ies.ds :
			wf_chspec_ctlchan(bi->chanspec);

		if (ies.wfdIe != 0) {
			bcm_decode_t dec1;
			bcm_decode_p2p_t wfd;

			pr->isP2P = TRUE;
			bcm_decode_init(&dec1, ies.wfdIeLength, ies.wfdIe);
			bcm_decode_p2p(&dec1, &wfd);

			if (wfd.deviceInfoBuffer) {
				bcm_decode_t dec2;

				bcm_decode_init(&dec2, wfd.deviceInfoLength,
					wfd.deviceInfoBuffer);
				pr->isP2PDeviceInfoDecoded =
					bcm_decode_p2p_device_info(&dec2, &pr->p2pDeviceInfo);
			}

			if (wfd.capabilityBuffer) {
				bcm_decode_t dec3;

				bcm_decode_init(&dec3, wfd.capabilityLength,
					wfd.capabilityBuffer);
				pr->isP2PCapabilityDecoded =
					bcm_decode_p2p_capability(&dec3, &pr->p2pCapability);
			}
		}

		if (ies.hotspotIndication != 0) {
			bcm_decode_t dec4;

			pr->isP2P = TRUE;
			bcm_decode_init(&dec4, ies.hotspotIndicationLength,
				ies.hotspotIndication);
			pr->isHotspotDecoded =
				bcm_decode_ie_hotspot_indication(&dec4, &pr->hotspotConfig);
		}

		return TRUE;
	}
	return FALSE;
}
