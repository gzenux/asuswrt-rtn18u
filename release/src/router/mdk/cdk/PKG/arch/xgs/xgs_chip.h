/*
 * $Id: xgs_chip.h,v 1.14 Broadcom SDK $
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

#ifndef __XGS_CHIP_H__
#define __XGS_CHIP_H__

#include <cdk/cdk_types.h>
#include <cdk/cdk_device.h>
#include <cdk/cdk_chip.h>
#include <cdk/cdk_symbols.h>

/* Block offset within register/memory address */
#define CDK_XGS_BLOCK_BP        20

/* High bits of block offset (if more than 16 blocks) */
#define CDK_XGS_BLOCK_BP_HI     30

/* Extract block number from address */
#define CDK_XGS_ADDR2BLOCK(addr) \
        (((addr >> CDK_XGS_BLOCK_BP) & 0xf) | \
         (addr >> (CDK_XGS_BLOCK_BP_HI - 4) & (0x3 << 4)))

/* Indicates that memory index must be multiplied by 2 */
#define CDK_XGS_MEM_FLAG_STEP2  0x00800000

#define CDK_XGS_MEM_OP_INSERT   1
#define CDK_XGS_MEM_OP_DELETE   2
#define CDK_XGS_MEM_OP_LOOKUP   3
#define CDK_XGS_MEM_OP_PUSH     4
#define CDK_XGS_MEM_OP_POP      5

typedef struct cdk_xgs_mem_op_info_s {
    int mem_op;
    int size;
    uint32_t addr;
    uint32_t *data;
    uint32_t *key;
    uint32_t idx_min;
    uint32_t idx_max;
} cdk_xgs_mem_op_info_t;

/*
 * Block/port information structure
 */
typedef struct cdk_xgs_block_s {
    /* Block Type */
    int type; 

    /* Physical block number */
    int blknum; 
    
    /* Port Bitmaps */
    cdk_pbmp_t pbmps;

} cdk_xgs_block_t; 

typedef struct cdk_xgs_pblk_s {

    /* Block Type */
    int btype; 
    /* Block Type Offset */
    int bindex; 

    /* Physical Block Number */
    int block; 
    /* Block physical port number */
    int bport; 

} cdk_xgs_pblk_t; 
    
/*
 * Info for register arrays with per-port variable size
 *
 * Since register arrays often have identical or similar
 * per-port arrays sizes, this information is stored as
 * shared encodings defined by two tables per chip.
 *
 * Each entry in the first table defines an index range
 * and an associated set of ports. Entries in this table
 * are referenced by a range ID which is simple the table
 * index (first entry is range waith ID 0, etc.)
 *
 * Each entry in the second table is a list of range IDs
 * that defines the encoding for one or more registers.
 *
 * An encoding is defined as an index into the second
 * table. Note that encoding 0 is reserved because the
 * first entry of the second table contains the size of
 * the table itself.
 */
typedef struct cdk_xgs_numel_range_s {

    /* Array index range */
    int min;
    int max;

    /* Ports for which index range is valid */
    cdk_pbmp_t pbmp;

}  cdk_xgs_numel_range_t;

typedef struct cdk_xgs_numel_encoding_s {

    /* List of range IDs, -1 marks end of list */
    int range_id[8];

}  cdk_xgs_numel_encoding_t;

typedef struct  cdk_xgs_numel_info_s {

    /* Table of all index ranges for this chip */
    cdk_xgs_numel_range_t *chip_ranges;

    /* Table of register array encodings for this chip */
    cdk_xgs_numel_encoding_t *encodings;

}  cdk_xgs_numel_info_t;

/*
 * Chip information
 */
typedef struct cdk_xgs_chip_info_s {    
    
    /* CMIC Block used in SCHAN operations */
    int cmic_block; 
    
    /* Other (non-CMIC) block types */
    int nblktypes; 
    const char **blktype_names; 

    /* Offset/Address Vectors */
    uint32_t (*block_port_addr)(int block, int port, uint32_t offset); 

    /* Block structures */
    int nblocks; 
    const cdk_xgs_block_t *blocks; 

    /* Valid ports for this chip */
    cdk_pbmp_t valid_pbmps; 

    /* 
     * Chip Flags
     *
     * Lower 16 bits are global XGS flags, which are defined below.
     * Upper 16 bits are chip-specific, e.g. for controlling bond-options.
     */

/* Use clause 45 style for clause 22 MII access */
#define CDK_XGS_CHIP_FLAG_CLAUSE45      0x1

/* Use special clause 45 style for clause 22 MII access */
#define CDK_XGS_CHIP_FLAG_C45_5673      0x2

/* Support extended S-channel buffer at offset 0x800 */
#define CDK_XGS_CHIP_FLAG_SCHAN_EXT     0x4

/* Source block is unused in S-channel message control word */
#define CDK_XGS_CHIP_FLAG_SCHAN_SB0     0x8

/* Mask block info from S-channel address word */
#define CDK_XGS_CHIP_FLAG_SCHAN_MBI     0x10
    uint32_t flags; 
    
#if CDK_CONFIG_INCLUDE_CHIP_SYMBOLS == 1
    /* Chip symbol table pointer */
    const cdk_symbols_t *symbols; 
#endif

#if CDK_CONFIG_INCLUDE_PORT_MAP == 1
    /* Map of physical portnumbers */
    int nports;
    cdk_port_map_port_t *ports;
#endif

    /* Variable size register arrays */
    cdk_xgs_numel_info_t *numel_info; 

    /* Get max index of a chip memory */
    uint32_t (*mem_maxidx)(uint32_t addr, uint32_t default_size); 

    /* Perform advanced memory access */
    int (*mem_op)(int unit, cdk_xgs_mem_op_info_t *mem_op_info); 

} cdk_xgs_chip_info_t; 

/*
 * Retrieve a device's block pointer for the given block number
 */
extern const cdk_xgs_block_t *
cdk_xgs_block(int unit, int blktype); 

/*
 * Get the port bitmap for a given block in the device
 */
extern int
cdk_xgs_block_pbmp(int unit, int blktype, cdk_pbmp_t *pbmp); 

/*
 * Block and port addresses for a given device
 */
extern uint32_t 
cdk_xgs_block_addr(int unit, int block, uint32_t offset); 

extern uint32_t
cdk_xgs_port_addr(int unit, int port, uint32_t offset); 

extern uint32_t 
cdk_xgs_blockport_addr(int unit, int block, int port, uint32_t offset); 

extern int
cdk_xgs_block_number(int unit, int blktype, int n); 

extern int
cdk_xgs_block_type(int unit, int block, int *blktype, int *n); 

extern int
cdk_xgs_port_block(int unit, int port, cdk_xgs_pblk_t *dst, 
                   int blktype); 

extern int
cdk_xgs_port_number(int unit, int block, int port); 

/*
 * Useful Macros.
 *
 * Mostly unused withing the CDK, but provided as a convenience 
 * for driver development.
 */

#define CDK_XGS_INFO(unit) ((cdk_xgs_chip_info_t *)cdk_device[unit].chip_info)
#define CDK_XGS_CMIC_BLOCK(unit) (CDK_XGS_INFO(unit)->cmic_block)
#define CDK_XGS_BLKTYPE_NAMES(unit) CDK_XGS_INFO(unit)->blktype_names
#define CDK_XGS_FLAGS(unit) (CDK_XGS_INFO(unit)->flags)

#if CDK_CONFIG_INCLUDE_CHIP_SYMBOLS == 1
#define CDK_XGS_SYMBOLS(unit) CDK_XGS_INFO(unit)->symbols
#else
#define CDK_XGS_SYMBOLS(unit) NULL
#endif

#define CDK_XGS_PORT_VALID(_u, _p) \
    (CDK_PBMP_MEMBER(CDK_XGS_INFO(_u)->valid_pbmps, _p))

/*
 * Union of bitmaps for all physical blocks of a specific block type
 */
#define CDK_XGS_BLKTYPE_PBMP_GET(_u, _bt, _pbmp) \
    (cdk_xgs_block_pbmp(_u, _bt, _pbmp))

/*
 * Global mode flags for XGS architecture
 */
#define CDK_XGS_CHIP_F_TREX_DEBUG       0x1
extern uint32_t cdk_xgs_chip_flags[];

#define CDK_XGS_CHIP_FLAGS(_u) cdk_xgs_chip_flags[_u]

#define CDK_XGS_CHIP_TREX_SET(_u, _v) do { \
    cdk_xgs_chip_flags[_u] &= ~CDK_XGS_CHIP_F_TREX_DEBUG; \
    if (_v) cdk_xgs_chip_flags[_u] |= CDK_XGS_CHIP_F_TREX_DEBUG; \
} while (0)

#define CDK_XGS_CHIP_TREX_GET(_u) \
    ((cdk_xgs_chip_flags[_u] & CDK_XGS_CHIP_F_TREX_DEBUG) ? 1 : 0)

/*
 * Architecture specific initialization functions
 */
extern int cdk_xgs_setup(cdk_dev_t *dev);

extern int cdk_xgs_cmic_init(int unit);

#endif /* __XGS_CHIP_H__ */
