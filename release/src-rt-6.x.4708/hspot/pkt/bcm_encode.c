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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include "trace.h"
#include "bcm_encode.h"

static int isLengthValid(bcm_encode_t *pkt, int length)
{
	assert(pkt != 0);

	if (pkt == 0 || length < 0)
		return FALSE;

	if (pkt->buf == 0)
		return FALSE;

	if (pkt->length + length > pkt->maxLength) {
		WL_ERROR(("length %d exceeds remaining buffer %d\n",
			length, pkt->maxLength - pkt->length));
		return FALSE;
	}

	return TRUE;
}

/* initialize pkt encode buffer */
int bcm_encode_init(bcm_encode_t *pkt, int maxLength, uint8 *buf)
{
	assert(pkt != 0);

	if (buf == 0)
		return FALSE;

	pkt->maxLength = maxLength;
	pkt->length = 0;
	pkt->buf = buf;

	return TRUE;
}

/* encode byte */
int bcm_encode_byte(bcm_encode_t *pkt, uint8 byte)
{
	assert(pkt != 0);

	if (!isLengthValid(pkt, 1))
		return 0;

	pkt->buf[pkt->length++] = byte;
	return 1;
}

/* encode 16-bit big endian */
int bcm_encode_be16(bcm_encode_t *pkt, uint16 value)
{
	assert(pkt != 0);

	if (!isLengthValid(pkt, 2))
		return 0;

	pkt->buf[pkt->length++] = value >> 8;
	pkt->buf[pkt->length++] = value;
	return 2;
}

/* encode 32-bit big endian */
int bcm_encode_be32(bcm_encode_t *pkt, uint32 value)
{
	assert(pkt != 0);

	if (!isLengthValid(pkt, 4))
		return 0;

	pkt->buf[pkt->length++] = value >> 24;
	pkt->buf[pkt->length++] = value >> 16;
	pkt->buf[pkt->length++] = value >> 8;
	pkt->buf[pkt->length++] = value;
	return 4;
}

/* encode 16-bit little endian */
int bcm_encode_le16(bcm_encode_t *pkt, uint16 value)
{
	assert(pkt != 0);

	if (!isLengthValid(pkt, 2))
		return 0;

	pkt->buf[pkt->length++] = value;
	pkt->buf[pkt->length++] = value >> 8;
	return 2;
}

/* encode 32-bit little endian */
int bcm_encode_le32(bcm_encode_t *pkt, uint32 value)
{
	assert(pkt != 0);

	if (!isLengthValid(pkt, 4))
		return 0;

	pkt->buf[pkt->length++] = value;
	pkt->buf[pkt->length++] = value >> 8;
	pkt->buf[pkt->length++] = value >> 16;
	pkt->buf[pkt->length++] = value >> 24;
	return 4;
}

/* encode bytes */
int bcm_encode_bytes(bcm_encode_t *pkt, int length, uint8 *bytes)
{
	assert(pkt != 0);
	assert(bytes != 0);

	if (!isLengthValid(pkt, length))
		return 0;

	memcpy(&pkt->buf[pkt->length], bytes, length);
	pkt->length += length;
	return length;
}
