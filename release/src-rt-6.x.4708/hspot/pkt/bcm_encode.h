/*
 * Encode base functions which provides encoding of basic data types
 * and provides bounds checking on the buffer to be encoded.
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

#ifndef _BCM_ENCODE_H_
#define _BCM_ENCODE_H_

#include "typedefs.h"

typedef struct
{
	int maxLength;
	int length;
	uint8 *buf;
} bcm_encode_t;

/* get encode length */
#define bcm_encode_length(pkt)	\
	((pkt)->length)

/* get encode buffer */
#define bcm_encode_buf(pkt)		\
	((pkt)->buf)

/* initialize pkt encode buffer */
int bcm_encode_init(bcm_encode_t *pkt, int maxLength, uint8 *buf);

/* encode byte */
int bcm_encode_byte(bcm_encode_t *pkt, uint8 byte);

/* encode 16-bit big endian */
int bcm_encode_be16(bcm_encode_t *pkt, uint16 value);

/* encode 32-bit big endian */
int bcm_encode_be32(bcm_encode_t *pkt, uint32 value);

/* encode 16-bit little endian */
int bcm_encode_le16(bcm_encode_t *pkt, uint16 value);

/* encode 32-bit little endian */
int bcm_encode_le32(bcm_encode_t *pkt, uint32 value);

/* encode bytes */
int bcm_encode_bytes(bcm_encode_t *pkt, int length, uint8 *bytes);

#endif /* _BCM_ENCODE_H_ */
