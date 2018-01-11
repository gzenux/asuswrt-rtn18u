/*
 * $Id: cdk_chip.h,v 1.15 Broadcom SDK $
 * $Copyright: Copyright 2013 Broadcom Corporation.
 * This program is the proprietary software of Broadcom Corporation
 * and/or its licensors, and may only be used, duplicated, modified
 * or distributed pursuant to the terms and conditions of a separate,
 * written license agreement executed between you and Broadcom
 * (an "Authorized License").  Except as set forth in an Authorized
 * License, Broadcom grants no license (express or implied), right
 * to use, or waiver of any kind with respect to the Software, and
 * Broadcom expressly reserves all rights in and to the Software
 * and all intellectual property rights therein.  IF YOU HAVE
 * NO AUTHORIZED LICENSE, THEN YOU HAVE NO RIGHT TO USE THIS SOFTWARE
 * IN ANY WAY, AND SHOULD IMMEDIATELY NOTIFY BROADCOM AND DISCONTINUE
 * ALL USE OF THE SOFTWARE.  
 *  
 * Except as expressly set forth in the Authorized License,
 *  
 * 1.     This program, including its structure, sequence and organization,
 * constitutes the valuable trade secrets of Broadcom, and you shall use
 * all reasonable efforts to protect the confidentiality thereof,
 * and to use this information only in connection with your use of
 * Broadcom integrated circuit products.
 *  
 * 2.     TO THE MAXIMUM EXTENT PERMITTED BY LAW, THE SOFTWARE IS
 * PROVIDED "AS IS" AND WITH ALL FAULTS AND BROADCOM MAKES NO PROMISES,
 * REPRESENTATIONS OR WARRANTIES, EITHER EXPRESS, IMPLIED, STATUTORY,
 * OR OTHERWISE, WITH RESPECT TO THE SOFTWARE.  BROADCOM SPECIFICALLY
 * DISCLAIMS ANY AND ALL IMPLIED WARRANTIES OF TITLE, MERCHANTABILITY,
 * NONINFRINGEMENT, FITNESS FOR A PARTICULAR PURPOSE, LACK OF VIRUSES,
 * ACCURACY OR COMPLETENESS, QUIET ENJOYMENT, QUIET POSSESSION OR
 * CORRESPONDENCE TO DESCRIPTION. YOU ASSUME THE ENTIRE RISK ARISING
 * OUT OF USE OR PERFORMANCE OF THE SOFTWARE.
 * 
 * 3.     TO THE MAXIMUM EXTENT PERMITTED BY LAW, IN NO EVENT SHALL
 * BROADCOM OR ITS LICENSORS BE LIABLE FOR (i) CONSEQUENTIAL,
 * INCIDENTAL, SPECIAL, INDIRECT, OR EXEMPLARY DAMAGES WHATSOEVER
 * ARISING OUT OF OR IN ANY WAY RELATING TO YOUR USE OF OR INABILITY
 * TO USE THE SOFTWARE EVEN IF BROADCOM HAS BEEN ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGES; OR (ii) ANY AMOUNT IN EXCESS OF
 * THE AMOUNT ACTUALLY PAID FOR THE SOFTWARE ITSELF OR USD 1.00,
 * WHICHEVER IS GREATER. THESE LIMITATIONS SHALL APPLY NOTWITHSTANDING
 * ANY FAILURE OF ESSENTIAL PURPOSE OF ANY LIMITED REMEDY.$
 *
 * Common chip definitions.
 */

#ifndef __CDK_CHIP_H__
#define __CDK_CHIP_H__

#include <cdk/cdk_types.h>
#include <cdk/cdk_string.h>
#include <cdk/cdk_error.h>

/* Max size of register/memory in words */
#define CDK_MAX_REG_WSIZE       32

/* Words in port bit maps */
#define CDK_PBMP_WORD_MAX       (((CDK_CONFIG_MAX_PORTS - 1) >> 5) + 1)

typedef struct cdk_pbmp_s {
    uint32_t w[CDK_PBMP_WORD_MAX];
} cdk_pbmp_t;

/* Port bitmap helper functions */
extern int
cdk_pbmp_is_null(const cdk_pbmp_t *pbmp);

#define CDK_BMP_ITER(_bmp, _base, _iter) \
    for ((_iter) = (_base); (_iter) < (_base) + 32; (_iter++)) \
        if ((_bmp) & LSHIFT32(1, ((_iter) - (_base)))) 

#define CDK_PBMP0_ITER(_bmp, _p) CDK_BMP_ITER(_bmp, 0, _p)
#define CDK_PBMP1_ITER(_bmp, _p) CDK_BMP_ITER(_bmp, 32, _p)
#define CDK_PBMP2_ITER(_bmp, _p) CDK_BMP_ITER(_bmp, 64, _p)

#define CDK_PBMP_MEMBER(_pbmp, _port) \
     ((&(_pbmp))->w[(_port) >> 5] & LSHIFT32(1, (_port) & 0x1f))

#define CDK_PBMP_ITER(_pbmp, _port) \
    for (_port = 0; _port < CDK_CONFIG_MAX_PORTS; _port++) \
        if (CDK_PBMP_MEMBER(_pbmp, _port))

#define CDK_PBMP_PORT_ADD(_pbmp, _port) \
     ((&(_pbmp))->w[(_port) >> 5] |= LSHIFT32(1, (_port) & 0x1f))
#define CDK_PBMP_PORT_REMOVE(_pbmp, _port) \
     ((&(_pbmp))->w[(_port) >> 5] &= ~(LSHIFT32(1, (_port) & 0x1f)))

#define CDK_PBMP_CLEAR(_pbmp) CDK_MEMSET(&_pbmp, 0, sizeof(cdk_pbmp_t))

#define CDK_PBMP_WORD_GET(_pbmp, _w)            ((&(_pbmp))->w[_w])
#define CDK_PBMP_WORD_SET(_pbmp, _w, _val)      ((&(_pbmp))->w[_w]) = (_val)

#define CDK_PBMP_BMOP(_pbmp0, _pbmp1, _op) \
    do { \
        int _w; \
        for (_w = 0; _w < CDK_PBMP_WORD_MAX; _w++) { \
            CDK_PBMP_WORD_GET(_pbmp0, _w) _op CDK_PBMP_WORD_GET(_pbmp1, _w); \
        } \
    } while (0)

#define CDK_PBMP_IS_NULL(_pbmp)         (cdk_pbmp_is_null(&(_pbmp)))
#define CDK_PBMP_NOT_NULL(_pbmp)        (!(cdk_pbmp_is_null(&(_pbmp))))

#define CDK_PBMP_ASSIGN(dst, src)       CDK_MEMCPY(&(dst), &(src), sizeof(cdk_pbmp_t))
#define CDK_PBMP_AND(_pbmp0, _pbmp1)    CDK_PBMP_BMOP(_pbmp0, _pbmp1, &=)
#define CDK_PBMP_OR(_pbmp0, _pbmp1)     CDK_PBMP_BMOP(_pbmp0, _pbmp1, |=)
#define CDK_PBMP_XOR(_pbmp0, _pbmp1)    CDK_PBMP_BMOP(_pbmp0, _pbmp1, ^=)
#define CDK_PBMP_REMOVE(_pbmp0, _pbmp1) CDK_PBMP_BMOP(_pbmp0, _pbmp1, &= ~)
#define CDK_PBMP_NEGATE(_pbmp0, _pbmp1) CDK_PBMP_BMOP(_pbmp0, _pbmp1, = ~)

/* Backward compatibility */
#define CDK_PBMP_ADD(_pbmp, _port)      CDK_PBMP_PORT_ADD(_pbmp, _port)

/* Initializer macros */
#define CDK_PBMP_1(_w0)                 { { _w0 } }
#define CDK_PBMP_2(_w0, _w1)            { { _w0, _w1 } }
#define CDK_PBMP_3(_w0, _w1, _w2)       { { _w0, _w1, _w2 } }
#define CDK_PBMP_4(_w0, _w1, _w2, _w3)  { { _w0, _w1, _w2, _w3 } }
#define CDK_PBMP_5(_w0, _w1, _w2, _w3, _w4) \
                                        { { _w0, _w1, _w2, _w3, _w4 } }

#define CDK_BYTES2BITS(x)       ((x) * 8)
#define CDK_BYTES2WORDS(x)      (((x) + 3) / 4)

#define CDK_WORDS2BITS(x)       ((x) * 32)
#define CDK_WORDS2BYTES(x)      ((x) * 4)

#endif /* __CDK_CHIP_H__ */
