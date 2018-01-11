/*
 * $Id: robo_chip.h,v 1.7 Broadcom SDK $
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
 */

#ifndef __ROBO_CHIP_H__
#define __ROBO_CHIP_H__

#include <cdk/cdk_types.h>
#include <cdk/cdk_device.h>
#include <cdk/cdk_chip.h>
#include <cdk/cdk_symbols.h>

/*
 * Block/port information structure
 */
typedef struct cdk_robo_block_s {
    /* Block Type */
    int type; 

    /* Port Bitmaps */
    cdk_pbmp_t pbmps;

} cdk_robo_block_t; 

/*
 * Chip information
 */
typedef struct cdk_robo_chip_info_s {    
    
    /* Block types */
    int nblktypes; 
    const char **blktype_names; 

    /* Offset/Address Vectors */
    uint32_t (*port_addr)(int port, int size, uint32_t offset); 

    /* Block structures */
    int nblocks; 
    const cdk_robo_block_t *blocks; 

    /* Valid ports for this chip */
    cdk_pbmp_t valid_pbmps;

    /* Chip Flags */
    uint32_t flags; 
    
#if CDK_CONFIG_INCLUDE_CHIP_SYMBOLS == 1
    /* Chip Symbol Table Pointer */
    const cdk_symbols_t *symbols; 
#endif

#if CDK_CONFIG_INCLUDE_PORT_MAP == 1
    /* Map of physical portnumbers */
    int nports;
    cdk_port_map_port_t *ports;
#endif

} cdk_robo_chip_info_t; 

/*
 * Get the port bitmap for a given block in the device
 */
extern int
cdk_robo_block_pbmp(int unit, int blktype, cdk_pbmp_t *pbmp);

extern uint32_t
cdk_robo_port_addr(int unit, int port, int size, uint32_t offset); 

/*
 * Useful Macros
 * Mostly unused withing the CDK, but provided as a convenience for driver development
 */

#define CDK_ROBO_INFO(unit) ((cdk_robo_chip_info_t *)cdk_device[unit].chip_info)

#if CDK_CONFIG_INCLUDE_CHIP_SYMBOLS == 1
#define CDK_ROBO_SYMBOLS(unit) CDK_ROBO_INFO(unit)->symbols
#else
#define CDK_ROBO_SYMBOLS(unit) NULL
#endif

/*
 * Union of bitmaps for all physical blocks of a specific block type
 */
#define CDK_ROBO_BLKTYPE_PBMP_GET(_u, _bt, _pbmp) \
    (cdk_robo_block_pbmp(_u, _bt, _pbmp))

/*
 * Architecture specific initialization functions
 */
extern int
cdk_robo_setup(cdk_dev_t *dev);

/*
 * Architecture specific probe function that extracts chip ID
 * information from the Robo PHY ID registers and optionally
 * retrieves model information from chip-specific register
 *
 * The reg_read functions has same prototype as the read
 * function in the cdk_dev_vectors_t type.
 */
extern int
cdk_robo_probe(void *dvc, cdk_dev_id_t *id,
               int (*reg_read)(void *, uint32_t, uint8_t *, uint32_t));

#endif /* __ROBO_CHIP_H__ */
