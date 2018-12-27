/*
 * Hotspot2.0 specific constants as defined in Hotspot2.0 specification.
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

#ifndef _BCM_HSPOT_H_
#define _BCM_HSPOT_H_

/* hotspot IE OUI type */
#define HSPOT_IE_OUI_TYPE		0x10

/* hotspot ANQP OUI type */
#define HSPOT_ANQP_OUI_TYPE		0x11
#define HSPOT_ANQP_OUI			"\x50\x6F\x9A\x11"

/* hotspot WNM OUI type */
#define HSPOT_WNM_OUI_TYPE		0x00

/* hostspot config */
#define HSPOT_IE_DGAF_DISABLED	0x01	/* downstream group-addressed forward */

/* hotspot config release2 */
#define HSPOT_DGAF_DISABLED_SHIFT	0
#define HSPOT_DGAF_DISABLED_MASK	(0x01 << HSPOT_DGAF_DISABLED_SHIFT)
#define HSPOT_RELEASE_SHIFT			4
#define HSPOT_RELEASE_MASK			(0x0f << HSPOT_RELEASE_SHIFT)

/* hotspot release numbers */
#define HSPOT_RELEASE_1		0
#define HSPOT_RELEASE_2		1

/* length includes OUI + type + subtype + reserved */
#define HSPOT_LENGTH_OVERHEAD	(WFA_OUI_LEN + 1 + 1 + 1)

/* subtype */
#define HSPOT_SUBTYPE_RESERVED						0
#define HSPOT_SUBTYPE_QUERY_LIST					1
#define HSPOT_SUBTYPE_CAPABILITY_LIST				2
#define HSPOT_SUBTYPE_OPERATOR_FRIENDLY_NAME		3
#define HSPOT_SUBTYPE_WAN_METRICS					4
#define HSPOT_SUBTYPE_CONNECTION_CAPABILITY			5
#define HSPOT_SUBTYPE_NAI_HOME_REALM_QUERY			6
#define HSPOT_SUBTYPE_OPERATING_CLASS_INDICATION	7
#define HSPOT_SUBTYPE_ONLINE_SIGNUP_PROVIDERS		8
#define HSPOT_SUBTYPE_ANONYMOUS_NAI					9
#define HSPOT_SUBTYPE_ICON_REQUEST					10
#define HSPOT_SUBTYPE_ICON_BINARY_FILE				11

/* WAN info - link status */
#define HSPOT_WAN_LINK_STATUS_SHIFT		0
#define HSPOT_WAN_LINK_STATUS_MASK		(0x03 << HSPOT_WAN_LINK_STATUS_SHIFT)
#define	HSPOT_WAN_LINK_UP				0x01
#define HSPOT_WAN_LINK_DOWN				0x02
#define HSPOT_WAN_LINK_TEST				0x03

/* WAN info - symmetric link */
#define HSPOT_WAN_SYMMETRIC_LINK_SHIFT	2
#define HSPOT_WAN_SYMMETRIC_LINK_MASK	(0x01 << HSPOT_WAN_SYMMETRIC_LINK_SHIFT)
#define HSPOT_WAN_SYMMETRIC_LINK		0x01
#define HSPOT_WAN_NOT_SYMMETRIC_LINK	0x00

/* WAN info - at capacity */
#define HSPOT_WAN_AT_CAPACITY_SHIFT		3
#define HSPOT_WAN_AT_CAPACITY_MASK		(0x01 << HSPOT_WAN_AT_CAPACITY_SHIFT)
#define HSPOT_WAN_AT_CAPACITY			0x01
#define HSPOT_WAN_NOT_AT_CAPACITY		0x00

/* connection capability */
#define HSPOT_CC_STATUS_CLOSED			0
#define HSPOT_CC_STATUS_OPEN			1
#define HSPOT_CC_STATUS_UNKNOWN			2

/* OSU method */
#define HSPOT_OSU_METHOD_OMA_DM			0
#define HSPOT_OSU_METHOD_SOAP_XML		1

/* icon download status */
#define HSPOT_ICON_STATUS_SUCCESS					0
#define HSPOT_ICON_STATUS_FILE_NOT_FOUND			1
#define HSPOT_ICON_STATUS_UNSPECIFIED_FILE_ERROR	2

/* WNM type */
#define HSPOT_WNM_TYPE		1

#endif /* _BCM_HSPOT_H_ */
