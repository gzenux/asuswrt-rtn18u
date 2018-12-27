/*
 * Encoding of QoS packets.
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

#ifndef _BCM_ENCODE_QOS_H_
#define _BCM_ENCODE_QOS_H_

#include "typedefs.h"
#include "bcm_encode.h"
#include "bcm_hspot.h"

/* encode QoS map */
int bcm_encode_qos_map(bcm_encode_t *pkt,
	uint8 except_length, uint8 *except_data,
	uint8 up0_low, uint8 up0_high,
	uint8 up1_low, uint8 up1_high,
	uint8 up2_low, uint8 up2_high,
	uint8 up3_low, uint8 up3_high,
	uint8 up4_low, uint8 up4_high,
	uint8 up5_low, uint8 up5_high,
	uint8 up6_low, uint8 up6_high,
	uint8 up7_low, uint8 up7_high);

#endif /* _BCM_ENCODE_QOS_H_ */
