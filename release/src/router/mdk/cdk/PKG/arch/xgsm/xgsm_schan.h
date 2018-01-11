/*
 * $Id: xgsm_schan.h,v 1.3 Broadcom SDK $
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
 * S-Channel Message: data structure used by firmware to transport
 * S-Channel Data into SOC via CMIC.
 */

#ifndef __CDK_SCHAN_H__
#define __CDK_SCHAN_H__

#include <cdk/cdk_types.h>

/* number of words to use when allocating space */
#define CMIC_SCHAN_WORDS_ALLOC 22

typedef uint32_t schan_header_t;

#define SCMH_CPU_GET(d)         __F_GET(d,0,1)
#define SCMH_CPU_SET(d,v)       __F_SET(d,0,1,v)
#define SCMH_COS_GET(d)         __F_GET(d,1,3)
#define SCMH_COS_SET(d,v)       __F_SET(d,1,3,v)
#define SCMH_ECODE_GET(d)       __F_GET(d,4,2)
#define SCMH_ECODE_SET(d,v)     __F_SET(d,4,2,v)
#define SCMH_EBIT_GET(d)        __F_GET(d,6,1)
#define SCMH_EBIT_SET(d,v)      __F_SET(d,6,1,v)
#define SCMH_DATALEN_GET(d)     __F_GET(d,7,7)
#define SCMH_DATALEN_SET(d,v)   __F_SET(d,7,7,v)
#define SCMH_ACCTYPE_GET(d)     __F_GET(d,14,3)
#define SCMH_ACCTYPE_SET(d,v)   __F_SET(d,14,3,v)
#define SCMH_DSTBLK_GET(d)      __F_GET(d,20,6)
#define SCMH_DSTBLK_SET(d,v)    __F_SET(d,20,6,v)
#define SCMH_OPCODE_GET(d)      __F_GET(d,26,6)
#define SCMH_OPCODE_SET(d,v)    __F_SET(d,26,6,v)

/*
 * Individual S-Channel message formats.
 * Different ways of peeking and poking at an S-Channel message
 * packet.  Applicable message types are listed inside each structure.
 */

typedef struct schan_msg_plain_s {
    /* GBP Full Notification */
    /* GBP Available Notification */
    /* Write Memory Ack */
    /* Write Register Ack */
    /* ARL Insert Complete */
    /* ARL Delete Complete */
    /* Memory Failed Notification */
    /* Initialize CFAP (Cell FAP) */
    /* Initialize SFAP (Slot FAP) */
    /* Enter Debug Mode */
    /* Exit Debug Mode */
    schan_header_t header;
} schan_msg_plain_t;

typedef struct schan_msg_bitmap_s {
    /* Back Pressure Warning Status */
    /* Back Pressure Discard Status */
    /* Link Status Notification (except 5695) */
    /* COS Queue Status Notification */
    /* HOL Status Notification */
    schan_header_t header;
    uint32_t bitmap;
    uint32_t bitmap_word1;  /* 5665 only, so far */
} schan_msg_bitmap_t;

typedef struct schan_msg_readcmd_s {
    /* Read Memory Command */
    /* Read Register Command */
    schan_header_t header;
    uint32_t address;
} schan_msg_readcmd_t;

typedef struct schan_msg_readresp_s {
    /* Read Memory Ack */
    /* Read Register Ack */
    schan_header_t header;
    uint32_t data[CMIC_SCHAN_WORDS_ALLOC - 1];
} schan_msg_readresp_t;

typedef struct schan_msg_writecmd_s {
    /* Write Memory Command */
    /* Write Register Command */
    schan_header_t header;
    uint32_t address;
    uint32_t data[CMIC_SCHAN_WORDS_ALLOC - 2];
} schan_msg_writecmd_t;

typedef struct schan_msg_arlins_s {
    /* ARL Insert Command */
    /* (Also: ARL Message Buffer Format) */
    /* (Also: ARL DMA Message Format) */
    schan_header_t header;
    uint32_t data[3];
} schan_msg_arlins_t;

typedef struct schan_msg_arldel_s {
    /* ARL Delete Command */
    schan_header_t header;
    uint32_t data[2];
} schan_msg_arldel_t;

typedef struct schan_msg_arllkup_s {
    /* ARL Lookup Command */
    schan_header_t header;
    uint32_t address;
    uint32_t data[2];
} schan_msg_arllkup_t;

typedef struct schan_msg_l3ins_s {
    /* L3 Insert Command */
    schan_header_t header;
    uint32_t data[4];
} schan_msg_l3ins_t;

typedef struct schan_msg_l3del_s {
    /* L3 Delete Command */
    schan_header_t header;
    uint32_t data[4];
} schan_msg_l3del_t;

typedef struct schan_msg_l3lkup_s {
    /* L3 Lookup Command */
    schan_header_t header;
    uint32_t address;
    uint32_t data[4];
} schan_msg_l3lkup_t;

typedef struct schan_msg_l2x2_s {
    /* L2 Insert/Delete/Lookup Command 56120 */
    schan_header_t header;
    uint32_t data[3];
} schan_msg_l2x2_t;

typedef struct schan_msg_l3x2_s {
    /* L3 Insert/Delete/Lookup Command 56120 */
    schan_header_t header;
    uint32_t data[13];
} schan_msg_l3x2_t;

typedef struct schan_msg_gencmd_s {
    /* Generic table Insert/Delete/Lookup Command 5661x */
    schan_header_t header;
    uint32_t address;
    uint32_t data[CMIC_SCHAN_WORDS_ALLOC - 2];
} schan_msg_gencmd_t;

#define SCGR_INDEX_GET(d)       __F_GET(d,0,20)
#define SCGR_INDEX_SET(d,v)     __F_SET(d,0,20,v)
#define SCGR_ERROR_GET(d)       __F_GET(d,21,4)
#define SCGR_ERROR_SET(d,v)     __F_SET(d,21,4,v)
#define SCGR_TYPE_GET(d)        __F_GET(d,26,4)
#define SCGR_TYPE_SET(d,v)      __F_SET(d,26,4,v)
#define SCGR_SRC_GET(d)         __F_GET(d,30,2)
#define SCGR_SRC_SET(d,v)       __F_SET(d,30,2,v)

#define SCGR_TYPE_FOUND         0
#define SCGR_TYPE_NOT_FOUND     1
#define SCGR_TYPE_FULL          2
#define SCGR_TYPE_INSERTED      3
#define SCGR_TYPE_REPLACED      4
#define SCGR_TYPE_DELETED       5
#define SCGR_TYPE_ENTRY_OLD     6
#define SCGR_TYPE_CLR_VALID     7
#define SCGR_TYPE_ERROR         15

#define SCGR_ERROR_BUSY         0
#define SCGR_ERROR_PARITY       1

typedef struct schan_msg_genresp_s {
    /* Generic table Insert/Delete/Lookup Command 5661x */
    schan_header_t header;
    uint32_t response;
    uint32_t data[CMIC_SCHAN_WORDS_ALLOC - 2];
} schan_msg_genresp_t;

typedef struct schan_msg_popcmd_s {
    /* Pop Memory Command */
    schan_header_t header;
    uint32_t address;
} schan_msg_popcmd_t;

typedef struct schan_msg_popresp_s {
    /* Pop Memory Response */
    schan_header_t header;
    uint32_t data[CMIC_SCHAN_WORDS_ALLOC - 1];
} schan_msg_popresp_t;

typedef struct schan_msg_pushcmd_s {
    /* Push Memory Command */
    schan_header_t header;
    uint32_t address;
    uint32_t data[CMIC_SCHAN_WORDS_ALLOC - 2];
} schan_msg_pushcmd_t;

typedef struct schan_msg_pushresp_s {
    /* Push Memory Response */
    schan_header_t header;
    uint32_t data[CMIC_SCHAN_WORDS_ALLOC - 1];
} schan_msg_pushresp_t;

/*
 * Union of all S-Channel message types (use to declare all message buffers)
 *
 * When building messages, address the union according to packet type.
 * When writing to PCI, address data.dwords.
 * When writing to I2C, address data.bytes.
 */

#define SCHAN_MSG_CLEAR(m)      ((m)->header = 0)

typedef union schan_msg_u {
    schan_header_t header;
    schan_msg_plain_t plain;
    schan_msg_bitmap_t bitmap;
    schan_msg_readcmd_t readcmd;
    schan_msg_readresp_t readresp;
    schan_msg_writecmd_t writecmd;
    schan_msg_arlins_t arlins;
    schan_msg_arldel_t arldel;
    schan_msg_arllkup_t arllkup;
    schan_msg_l3ins_t l3ins;
    schan_msg_l3del_t l3del;
    schan_msg_l3lkup_t l3lkup;
    schan_msg_l2x2_t l2x2;
    schan_msg_l3x2_t l3x2;
    schan_msg_gencmd_t gencmd;
    schan_msg_genresp_t genresp;
    schan_msg_popcmd_t  popcmd;
    schan_msg_popresp_t popresp;
    schan_msg_pushcmd_t  pushcmd;
    schan_msg_pushresp_t pushresp;
    uint32_t dwords[CMIC_SCHAN_WORDS_ALLOC];
    uint8_t bytes[sizeof(uint32_t) * CMIC_SCHAN_WORDS_ALLOC];
} schan_msg_t;

/*
 * S-Channel Message Types
 */

#define BP_WARN_STATUS_MSG            0x01
#define BP_DISCARD_STATUS_MSG         0x02
#define COS_QSTAT_NOTIFY_MSG          0x03      /* Not on XGS */
#define IPIC_HOL_STAT_MSG             0x03      /* 5665 (alias) */
#define HOL_STAT_NOTIFY_MSG           0x04
#define GBP_FULL_NOTIFY_MSG           0x05      /* 5605/5615/5625/xgsm only */
#define GBP_AVAIL_NOTIFY_MSG          0x06      /* 5605/5615/5625/xgsm only */
#define READ_MEMORY_CMD_MSG           0x07
#define READ_MEMORY_ACK_MSG           0x08
#define WRITE_MEMORY_CMD_MSG          0x09
#define WRITE_MEMORY_ACK_MSG          0x0a
#define READ_REGISTER_CMD_MSG         0x0b
#define READ_REGISTER_ACK_MSG         0x0c
#define WRITE_REGISTER_CMD_MSG        0x0d
#define WRITE_REGISTER_ACK_MSG        0x0e
#define ARL_INSERT_CMD_MSG            0x0f
#define ARL_INSERT_DONE_MSG           0x10
#define ARL_DELETE_CMD_MSG            0x11
#define ARL_DELETE_DONE_MSG           0x12
#define LINKSTAT_NOTIFY_MSG           0x13      /* Strata I/II only */
#define MEMORY_FAIL_NOTIFY            0x14
#define INIT_CFAP_MSG                 0x15      /* 5690 only */
#define IPIC_GBP_FULL_MSG             0x15      /* 5665 (alias) */
#define INIT_SFAP_MSG                 0x16      /* 5605/5615/5625 only */
#define IPIC_GBP_AVAIL_MSG            0x16      /* 5665 (alias) */
#define ENTER_DEBUG_MODE_MSG          0x17
#define EXIT_DEBUG_MODE_MSG           0x18
#define ARL_LOOKUP_CMD_MSG            0x19
#define L3_INSERT_CMD_MSG             0x1a
#define L3_INSERT_DONE_MSG            0x1b
#define L3_DELETE_CMD_MSG             0x1c
#define L3_DELETE_DONE_MSG            0x1d
#define L3_LOOKUP_CMD_MSG             0x1e      /* 5695 */
#define L2_LOOKUP_CMD_MSG             0x20      /* 56120 */
#define L2_LOOKUP_ACK_MSG             0x21      /* 56120 */
#define L3X2_LOOKUP_CMD_MSG           0x22      /* 56120 */
#define L3X2_LOOKUP_ACK_MSG           0x23      /* 56120 */
#define TABLE_INSERT_CMD_MSG          0x24      /* 5662x/5668x */
#define TABLE_INSERT_DONE_MSG         0x25      /* 5662x/5668x */
#define TABLE_DELETE_CMD_MSG          0x26      /* 5662x/5668x */
#define TABLE_DELETE_DONE_MSG         0x27      /* 5662x/5668x */
#define TABLE_LOOKUP_CMD_MSG          0x28      /* 5662x/5668x */
#define TABLE_LOOKUP_DONE_MSG         0x29      /* 5662x/5668x */
#define FIFO_POP_CMD_MSG              0x2a      /* 5661x */
#define FIFO_POP_DONE_MSG             0x2b      /* 5661x */
#define FIFO_PUSH_CMD_MSG             0x2c      /* 5661x */
#define FIFO_PUSH_DONE_MSG            0x2d      /* 5661x */

/*
 * Schan error types
 */
typedef enum soc_schan_err_e {
    SOC_SCERR_CFAP_OVER_UNDER,
    SOC_SCERR_SDRAM_CHKSUM,
    SOC_SCERR_UNEXP_FIRST_CELL,
    SOC_SCERR_MMU_SOFT_RST,
    SOC_SCERR_CBP_CELL_CRC,
    SOC_SCERR_CBP_HEADER_PARITY,
    SOC_SCERR_MMU_NPKT_CELLS,
    SOC_SCERR_MEMORY_PARITY,
    SOC_SCERR_PLL_DLL_LOCK_LOSS,
    SOC_SCERR_CELL_PTR_CRC,
    SOC_SCERR_CELL_DATA_CRC,
    SOC_SCERR_FRAME_DATA_CRC,
    SOC_SCERR_CELL_PTR_BLOCK_CRC,
    SOC_SCERR_MULTIPLE_ERR,
    SOC_SCERR_INVALID
} soc_schan_err_t;

/* Transact an S-Channel message to CMIC */
extern int cdk_xgsm_schan_op(int unit, schan_msg_t* msg,
                            int dwc_write, int dwc_read); 

#endif  /* !_CDK_SCHAN_H */
