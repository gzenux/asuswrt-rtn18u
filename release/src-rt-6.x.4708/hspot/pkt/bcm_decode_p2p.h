/*
 * Decode functions which provides decoding of P2P attributes
 * as defined in P2P specification.
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

#ifndef _BCM_DECODE_P2P_H_
#define _BCM_DECODE_P2P_H_

#include "typedefs.h"
#include "bcm_decode.h"

typedef struct {
#ifndef BCMDRIVER	/* not used in dongle */
	int statusLength;
	uint8 *statusBuffer;
	int minorReasonCodeLength;
	uint8 *minorReasonCodeBuffer;
#endif	/* BCMDRIVER */
	int capabilityLength;
	uint8 *capabilityBuffer;
#ifndef BCMDRIVER	/* not used in dongle */
	int deviceIdLength;
	uint8 *deviceIdBuffer;
	int groupOwnerIntentLength;
	uint8 *groupOwnerIntentBuffer;
	int configurationTimeoutLength;
	uint8 *configurationTimeoutBuffer;
	int listenChannelLength;
	uint8 *listenChannelBuffer;
	int groupBssidLength;
	uint8 *groupBssidBuffer;
	int extendedListenTimingLength;
	uint8 *extendedListenTimingBuffer;
	int intendedInterfaceAddressLength;
	uint8 *intendedInterfaceAddressBuffer;
	int manageabilityLength;
	uint8 *manageabilityBuffer;
	int channelListLength;
	uint8 *channelListBuffer;
	int noticeOfAbsenceLength;
	uint8 *noticeOfAbsenseBuffer;
#endif	/* BCMDRIVER */
	int deviceInfoLength;
	uint8 *deviceInfoBuffer;
#ifndef BCMDRIVER	/* not used in dongle */
	int groupInfoLength;
	uint8 *groupInfoBuffer;
	int groupIdLength;
	uint8 *groupIdBuffer;
	int interfaceLength;
	uint8 *interfaceBuffer;
	int operatingChannelLength;
	uint8 *operatingChannelBuffer;
	int invitationFlagsLength;
	uint8 *invitationFlagsBuffer;
#endif	/* BCMDRIVER */
} bcm_decode_p2p_t;

/* decode P2P */
int bcm_decode_p2p(bcm_decode_t *pkt, bcm_decode_p2p_t *wfd);

typedef uint8 bcm_decode_p2p_device_type_t[8];
#define BCM_DECODE_P2P_MAX_SECONDARY_DEVICE_TYPE	4
#define BCM_DECODE_P2P_MAX_DEVICE_NAME	32

typedef struct
{
	struct ether_addr deviceAddress;
	uint16 configMethods;
	bcm_decode_p2p_device_type_t primaryType;
	uint8 numSecondaryType;
	bcm_decode_p2p_device_type_t secondaryType[BCM_DECODE_P2P_MAX_SECONDARY_DEVICE_TYPE];
	uint8 deviceName[BCM_DECODE_P2P_MAX_DEVICE_NAME + 1];
} bcm_decode_p2p_device_info_t;

/* decode device info */
int bcm_decode_p2p_device_info(bcm_decode_t *pkt, bcm_decode_p2p_device_info_t *device);

/* print decoded device info */
void bcm_decode_p2p_device_info_print(bcm_decode_p2p_device_info_t *device);

typedef struct
{
	uint8 device;
	uint8 group;
} bcm_decode_p2p_capability_t;

/* decode capability */
int bcm_decode_p2p_capability(bcm_decode_t *pkt, bcm_decode_p2p_capability_t *capability);

/* print decoded capability */
void bcm_decode_p2p_capability_print(bcm_decode_p2p_capability_t *capability);

#endif /* _BCM_DECODE_P2P_H_ */
