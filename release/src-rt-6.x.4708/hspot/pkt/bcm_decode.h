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

#ifndef _BCM_DECODE_H_
#define _BCM_DECODE_H_

#include "typedefs.h"

typedef struct
{
	int maxLength;
	int offset;
	uint8 *buf;
} bcm_decode_t;


/* get decode buffer length */
#define bcm_decode_buf_length(pkt)	\
	((pkt)->maxLength)

/* get decode buffer */
#define bcm_decode_buf(pkt)			\
	((pkt)->buf)

/* get decode offset */
#define bcm_decode_offset(pkt)		\
	((pkt)->offset)

/* set decode offset */
#define bcm_decode_offset_set(pkt, value)	\
	((pkt)->offset = (value))

/* get decode remaining count */
#define bcm_decode_remaining(pkt)	\
	((pkt)->maxLength > (pkt)->offset ? (pkt)->maxLength - (pkt)->offset : 0)

/* get decode current pointer */
#define bcm_decode_current_ptr(pkt)	\
	(&(pkt)->buf[(pkt)->offset])

/* initialize pkt decode with decode buffer */
int bcm_decode_init(bcm_decode_t *pkt, int maxLength, uint8 *data);

/* decode byte */
int bcm_decode_byte(bcm_decode_t *pkt, uint8 *byte);

/* decode 16-bit big endian */
int bcm_decode_be16(bcm_decode_t *pkt, uint16 *value);

/* decode 32-bit big endian */
int bcm_decode_be32(bcm_decode_t *pkt, uint32 *value);

/* decode 16-bit little endian */
int bcm_decode_le16(bcm_decode_t *pkt, uint16 *value);

/* decode 32-bit little endian */
int bcm_decode_le32(bcm_decode_t *pkt, uint32 *value);

/* decode bytes */
int bcm_decode_bytes(bcm_decode_t *pkt, int length, uint8 *bytes);

#endif /* _BCM_DECODE_H_ */
