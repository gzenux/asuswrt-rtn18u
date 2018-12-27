/*
 * Decode base functions which provides decoding of basic data types
 * and provides bounds checking on the buffer to be decoded.
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
#include <assert.h>
#include "trace.h"
#include "bcm_decode.h"

static int isLengthValid(bcm_decode_t *pkt, int length)
{
	assert(pkt != 0);

	if (pkt == 0 || length < 0)
		return FALSE;

	if (pkt->offset + length > pkt->maxLength) {
		WL_ERROR(("exceeding data buffer %d > %d\n",
			pkt->offset + length, pkt->maxLength));
		return FALSE;
	}

	return TRUE;
}

/* initialize pkt decode with decode buffer */
int bcm_decode_init(bcm_decode_t *pkt, int maxLength, uint8 *data)
{
	assert(pkt != 0);

	pkt->maxLength = maxLength;
	pkt->offset = 0;
	pkt->buf = data;
	return TRUE;
}

/* decode byte */
int bcm_decode_byte(bcm_decode_t *pkt, uint8 *byte)
{
	assert(pkt != 0);
	assert(byte != 0);

	if (!isLengthValid(pkt, 1))
		return 0;

	*byte = pkt->buf[pkt->offset++];
	return 1;
}

/* decode 16-bit big endian */
int bcm_decode_be16(bcm_decode_t *pkt, uint16 *value)
{
	assert(pkt != 0);
	assert(value != 0);

	if (!isLengthValid(pkt, 2))
		return 0;

	*value =
		pkt->buf[pkt->offset] << 8 |
		pkt->buf[pkt->offset + 1];
	pkt->offset += 2;
	return 2;
}

/* decode 32-bit big endian */
int bcm_decode_be32(bcm_decode_t *pkt, uint32 *value)
{
	assert(pkt != 0);
	assert(value != 0);

	if (!isLengthValid(pkt, 4))
		return 0;

	*value =
		pkt->buf[pkt->offset] << 24 |
		pkt->buf[pkt->offset + 1] << 16 |
		pkt->buf[pkt->offset + 2] << 8 |
		pkt->buf[pkt->offset + 3];
	pkt->offset += 4;
	return 4;
}

/* decode 16-bit little endian */
int bcm_decode_le16(bcm_decode_t *pkt, uint16 *value)
{
	assert(pkt != 0);
	assert(value != 0);

	if (!isLengthValid(pkt, 2))
		return 0;

	*value =
		pkt->buf[pkt->offset] |
		pkt->buf[pkt->offset + 1] << 8;
	pkt->offset += 2;
	return 2;
}

/* decode 32-bit little endian */
int bcm_decode_le32(bcm_decode_t *pkt, uint32 *value)
{
	assert(pkt != 0);
	assert(value != 0);

	if (!isLengthValid(pkt, 4))
		return 0;

	*value =
		pkt->buf[pkt->offset] |
		pkt->buf[pkt->offset + 1] << 8 |
		pkt->buf[pkt->offset + 2] << 16 |
		pkt->buf[pkt->offset + 3] << 24;
	pkt->offset += 4;
	return 4;
}

/* decode bytes */
int bcm_decode_bytes(bcm_decode_t *pkt, int length, uint8 *bytes)
{
	assert(pkt != 0);
	assert(bytes != 0);

	if (!isLengthValid(pkt, length))
		return 0;

	memcpy(bytes, &pkt->buf[pkt->offset], length);
	pkt->offset += length;
	return length;
}
