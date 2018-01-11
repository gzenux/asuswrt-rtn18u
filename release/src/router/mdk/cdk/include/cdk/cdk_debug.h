/*
 * $Id: cdk_debug.h,v 1.9 Broadcom SDK $
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
 * CDK debug message functions.
 */

#ifndef __CDK_DEBUG_H__
#define __CDK_DEBUG_H__

#include <cdk/cdk_types.h>
#include <cdk/cdk_printf.h>

#if CDK_CONFIG_INCLUDE_DEBUG == 1

/*
 * These are the possible debug types/flags for cdk_debug_level (below).
 */
#define CDK_DBG_ERR       (1 << 0)    /* Print errors */
#define CDK_DBG_WARN      (1 << 1)    /* Print warnings */
#define CDK_DBG_VERBOSE   (1 << 2)    /* General verbose output */
#define CDK_DBG_VVERBOSE  (1 << 3)    /* Very verbose output */
#define CDK_DBG_DEV       (1 << 4)    /* Device access */
#define CDK_DBG_REG       (1 << 5)    /* Register access */
#define CDK_DBG_MEM       (1 << 6)    /* Memory access */
#define CDK_DBG_SCHAN     (1 << 7)    /* S-channel operations */
#define CDK_DBG_MIIM      (1 << 8)    /* MII managment access */
#define CDK_DBG_DMA       (1 << 9)    /* DMA operations */
#define CDK_DBG_HIGIG     (1 << 10)   /* HiGig information */
#define CDK_DBG_PACKET    (1 << 11)   /* Packet data */

#define CDK_DBG_NAMES   \
    "error",            \
    "warning",          \
    "verbose",          \
    "vverbose",         \
    "device",           \
    "register",         \
    "memory",           \
    "schannel",         \
    "miim",             \
    "dma",              \
    "higig",            \
    "packet"

extern uint32_t cdk_debug_level;
extern int (*cdk_debug_printf)(const char *format, ...);

#define CDK_DEBUG_CHECK(flags) (((flags) & cdk_debug_level) == (flags))

#ifdef CDK_CC_TYPE_CHECK
/* Allow compiler to check printf arguments */
#define CDK_DEBUG(flags, stuff) \
    if (CDK_DEBUG_CHECK(flags)) \
	CDK_PRINTF stuff
#else
/* Normal definition */
#define CDK_DEBUG(flags, stuff) \
    if (CDK_DEBUG_CHECK(flags) && cdk_debug_printf != 0) \
	(*cdk_debug_printf) stuff
#endif

#define CDK_ERR(stuff) CDK_DEBUG(CDK_DBG_ERR, stuff)
#define CDK_WARN(stuff) CDK_DEBUG(CDK_DBG_WARN, stuff)
#define CDK_VERB(stuff) CDK_DEBUG(CDK_DBG_VERBOSE, stuff)
#define CDK_VVERB(stuff) CDK_DEBUG(CDK_DBG_VVERBOSE, stuff)
#define CDK_DEBUG_DEV(stuff) CDK_DEBUG(CDK_DBG_DEV, stuff)
#define CDK_DEBUG_REG(stuff) CDK_DEBUG(CDK_DBG_REG, stuff)
#define CDK_DEBUG_MEM(stuff) CDK_DEBUG(CDK_DBG_MEM, stuff)
#define CDK_DEBUG_SCHAN(stuff) CDK_DEBUG(CDK_DBG_SCHAN, stuff)
#define CDK_DEBUG_MIIM(stuff) CDK_DEBUG(CDK_DBG_MIIM, stuff)
#define CDK_DEBUG_DMA(stuff) CDK_DEBUG(CDK_DBG_DMA, stuff)
#define CDK_DEBUG_HIGIG(stuff) CDK_DEBUG(CDK_DBG_HIGIG, stuff)
#define CDK_DEBUG_PACKET(stuff) CDK_DEBUG(CDK_DBG_PACKET, stuff)

#else /* CDK_CONFIG_INCLUDE_DEBUG == 0 */

#define CDK_DEBUG_CHECK(flags) 0
#define CDK_DEBUG(flags, stuff)

#define CDK_ERR(stuff)
#define CDK_WARN(stuff)
#define CDK_VERB(stuff)
#define CDK_VVERB(stuff)
#define CDK_DEBUG_DEV(stuff)
#define CDK_DEBUG_REG(stuff)
#define CDK_DEBUG_MEM(stuff)
#define CDK_DEBUG_SCHAN(stuff)
#define CDK_DEBUG_MIIM(stuff)
#define CDK_DEBUG_DMA(stuff)
#define CDK_DEBUG_HIGIG(stuff)
#define CDK_DEBUG_PACKET(stuff)

#endif /* CDK_CONFIG_INCLUDE_DEBUG */

#endif /* __CDK_DEBUG_H__ */
