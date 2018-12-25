/*
 * $Id: xgsm_chip.h,v 1.4 Broadcom SDK $
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

#ifndef __XGSM_CHIP_H__
#define __XGSM_CHIP_H__

#include <cdk/cdk_types.h>
#include <cdk/cdk_device.h>
#include <cdk/cdk_chip.h>
#include <cdk/cdk_symbols.h>

/* Extract block number from address extension */
#define CDK_XGSM_ADEXT2BLOCK(_adext) \
        ((_adext) & 0x3f)

/* Extract access type from address extension */
#define CDK_XGSM_ADEXT2ACCTYPE(_adext) \
        (((_adext) >> 8) & 0x7)

/* Modify block in existing address extension */
#define CDK_XGSM_ADEXT_BLOCK_SET(_adext, _block) \
        (_adext = ((_adext) & ~0xff) | (_block))

/* Extract access type from block/access info */
#define CDK_XGSM_BLKACC2ACCTYPE(_blkacc) \
        (((_blkacc) >> 20) & 0x7)

/* Convert block/access info to address extension */
#define CDK_XGSM_BLKACC2ADEXT(_blkacc) \
        (((_blkacc) >> 12) & 0x700)

/* Extract access type from symbol flags */
#define CDK_XGSM_SYMFLAGS2ACCTYPE(_flags) \
        CDK_XGSM_BLKACC2ACCTYPE(_flags)

#define CDK_XGSM_MEM_OP_INSERT   1
#define CDK_XGSM_MEM_OP_DELETE   2
#define CDK_XGSM_MEM_OP_LOOKUP   3
#define CDK_XGSM_MEM_OP_PUSH     4
#define CDK_XGSM_MEM_OP_POP      5

typedef struct cdk_xgsm_mem_op_info_s {
    int mem_op;
    int size;
    uint32_t addr;
    uint32_t *data;
    uint32_t *key;
    uint32_t idx_min;
    uint32_t idx_max;
} cdk_xgsm_mem_op_info_t;

/*
 * Block/port information structure
 */
typedef struct cdk_xgsm_block_s {
    /* Block Type */
    int type; 

    /* Physical block number */
    int blknum; 
    
    /* Default port type (physical vs logical) */
    int ptype; 
    
    /* Port Bitmaps */
    cdk_pbmp_t pbmps;

} cdk_xgsm_block_t; 

typedef struct cdk_xgsm_pblk_s {

    /* Block Type */
    int btype; 
    /* Block Type Offset */
    int bindex; 

    /* Physical Block Number */
    int block; 
    /* Block physical port number */
    int bport; 

} cdk_xgsm_pblk_t; 
    
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
typedef struct cdk_xgsm_numel_range_s {

    /* Array index range */
    int min;
    int max;

    /* Ports for which index range is valid */
    cdk_pbmp_t pbmp;

}  cdk_xgsm_numel_range_t;

typedef struct cdk_xgsm_numel_encoding_s {

    /* List of range IDs, -1 marks end of list */
    int range_id[8];

}  cdk_xgsm_numel_encoding_t;

typedef struct  cdk_xgsm_numel_info_s {

    /* Table of all index ranges for this chip */
    cdk_xgsm_numel_range_t *chip_ranges;

    /* Table of register array encodings for this chip */
    cdk_xgsm_numel_encoding_t *encodings;

}  cdk_xgsm_numel_info_t;

/*
 * Chip information
 */
typedef struct cdk_xgsm_chip_info_s {    
    
    /* CMIC Block used in SCHAN operations */
    int cmic_block; 
    
    /* Current CMC used in SCHAN operations */
    int cmic_cmc; 
    
    /* Other (non-CMIC) block types */
    int nblktypes; 
    const char **blktype_names; 

    /* Offset/Address Vectors */
    uint32_t (*block_port_addr)(int block, int port,
                                uint32_t offset, uint32_t idx); 

    /* Block structures */
    int nblocks; 
    const cdk_xgsm_block_t *blocks; 

    /* Valid ports for this chip */
    cdk_pbmp_t valid_pbmps; 

    /* 
     * Chip Flags
     *
     * Lower 16 bits are global XGS flags, which are defined below.
     * Upper 16 bits are chip-specific, e.g. for controlling bond-options.
     */

/* Use XGS-style addressing */
#define CDK_XGSM_CHIP_FLAG_XGS           0x1
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
    cdk_xgsm_numel_info_t *numel_info; 

    /* Get max index of a chip memory */
    uint32_t (*mem_maxidx)(int enum_val, uint32_t default_size); 

    /* Perform advanced memory access */
    int (*mem_op)(int unit, cdk_xgsm_mem_op_info_t *mem_op_info); 

} cdk_xgsm_chip_info_t; 

/*
 * Retrieve a device's block pointer for the given block number
 */
extern const cdk_xgsm_block_t *
cdk_xgsm_block(int unit, int blktype); 

/*
 * Get the port bitmap for a given block in the device
 */
extern int
cdk_xgsm_block_pbmp(int unit, int blktype, cdk_pbmp_t *pbmp); 

/*
 * Block and port addresses for a given device
 */
extern uint32_t
cdk_xgsm_port_addr(int unit, uint32_t blkacc, int port,
                   uint32_t offset, int idx, uint32_t *adext); 

/*
 * Note that blkport = -1 indicates that this is a memory address.
 * This is important if the chip driver implements an override
 * function, because register and memory calculations may differ.
 */
extern uint32_t 
cdk_xgsm_blockport_addr(int unit, int block, int blkport,
                        uint32_t offset, int idx); 

extern int
cdk_xgsm_block_number(int unit, int blktype, int n); 

extern int
cdk_xgsm_block_type(int unit, int block, int *blktype, int *n); 

extern int
cdk_xgsm_port_block(int unit, int port, cdk_xgsm_pblk_t *dst, 
                   int blktype); 

extern int
cdk_xgsm_port_number(int unit, int block, int port); 

/*
 * Useful Macros.
 *
 * Mostly unused withing the CDK, but provided as a convenience 
 * for driver development.
 */

#define CDK_XGSM_INFO(_u) ((cdk_xgsm_chip_info_t *)cdk_device[_u].chip_info)
#define CDK_XGSM_CMIC_BLOCK(_u) (CDK_XGSM_INFO(_u)->cmic_block)
#define CDK_XGSM_BLKTYPE_NAMES(_u) CDK_XGSM_INFO(_u)->blktype_names
#define CDK_XGSM_FLAGS(_u) (CDK_XGSM_INFO(_u)->flags)
#define CDK_XGSM_CMIC_CMC(_u) (CDK_XGSM_INFO(_u)->cmic_cmc)

#if CDK_CONFIG_INCLUDE_CHIP_SYMBOLS == 1
#define CDK_XGSM_SYMBOLS(_u) CDK_XGSM_INFO(_u)->symbols
#else
#define CDK_XGSM_SYMBOLS(_u) NULL
#endif

#define CDK_XGSM_PORT_VALID(_u, _p) \
    (CDK_PBMP_MEMBER(CDK_XGSM_INFO(_u)->valid_pbmps, _p))

/*
 * Union of bitmaps for all physical blocks of a specific block type
 */
#define CDK_XGSM_BLKTYPE_PBMP_GET(_u, _bt, _pbmp) \
    (cdk_xgsm_block_pbmp(_u, _bt, _pbmp))

/*
 * Global mode flags for XGS architecture
 */
#define CDK_XGSM_CHIP_F_TREX_DEBUG       0x1
extern uint32_t cdk_xgsm_chip_flags[];

#define CDK_XGSM_CHIP_FLAGS(_u) cdk_xgsm_chip_flags[_u]

#define CDK_XGSM_CHIP_TREX_SET(_u, _v) do { \
    cdk_xgsm_chip_flags[_u] &= ~CDK_XGSM_CHIP_F_TREX_DEBUG; \
    if (_v) cdk_xgsm_chip_flags[_u] |= CDK_XGSM_CHIP_F_TREX_DEBUG; \
} while (0)

#define CDK_XGSM_CHIP_TREX_GET(_u) \
    ((cdk_xgsm_chip_flags[_u] & CDK_XGSM_CHIP_F_TREX_DEBUG) ? 1 : 0)

/*
 * CMIC CMC selection for PCI interface
 */
#if defined(CDK_XGSM_CMC)
/* Allow override by hard-coded CMC selection */
#define CDK_XGSM_CMC_GET(_u)    CDK_XGSM_CMC
#define CDK_XGSM_CMC_SET(_u,_c)
#else
/* Use dynamic CMC selection by default */
#define CDK_XGSM_CMC_GET(_u)    CDK_XGSM_CMIC_CMC(_u)
#define CDK_XGSM_CMC_SET(_u,_c) CDK_XGSM_CMIC_CMC(_u) = _c;
#endif

/* CMC base address offset */
#define CDK_XGSM_CMC_OFFSET(_u) (CDK_XGSM_CMC_GET(_u) * 0x1000)

#define CDK_XGSM_CMC_READ(_u,_addr,_pval) \
    CDK_DEV_READ32(_u,(_addr)+CDK_XGSM_CMC_OFFSET(_u),_pval)
#define CDK_XGSM_CMC_WRITE(_u,_addr,_val) \
    CDK_DEV_WRITE32(_u,(_addr)+CDK_XGSM_CMC_OFFSET(_u),_val)

/*
 * Architecture specific initialization functions
 */
extern int cdk_xgsm_setup(cdk_dev_t *dev);

extern int cdk_xgsm_cmic_init(int unit);

#endif /* __XGSM_CHIP_H__ */
