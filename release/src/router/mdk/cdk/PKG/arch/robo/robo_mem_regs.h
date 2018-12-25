/*
 * $Id: robo_mem_regs.h,v 1.8 Broadcom SDK $
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
 * ROBO memory access register definitions.
 *
 * Note that all registers do not coexist on a single device. The register
 * set to use is defined by the access method for a particular memory.
 */

#ifndef __ROBO_MEM_REGS_H__
#define __ROBO_MEM_REGS_H__

#include <cdk/arch/robo_chip.h>
#include <cdk/arch/robo_reg.h>

/*******************************************************************************
 * REGISTER: MEM_CTRL
 ******************************************************************************/
#define ROBO_MEM_CTRLr 0x00000800

#define ROBO_MEM_CTRLr_SIZE 1

/*
 * This structure should be used to declare and program MEM_CTRL.
 *
 */
typedef union ROBO_MEM_CTRLr_s {
	uint32_t v[1];
	uint32_t mem_ctrl[1];
	uint32_t _mem_ctrl;
} ROBO_MEM_CTRLr_t;

#define ROBO_MEM_CTRLr_CLR(r) (r).mem_ctrl[0] = 0
#define ROBO_MEM_CTRLr_SET(r,d) (r).mem_ctrl[0] = d
#define ROBO_MEM_CTRLr_GET(r) (r).mem_ctrl[0]

/*
 * These macros can be used to access individual fields.
 *
 */

/* Old definition (BCM5395, etc.) */
#define ROBO_MEM_CTRLr_MEM_TYPEf_GET(r) ((((r).mem_ctrl[0]) >> 6) & 0x3)
#define ROBO_MEM_CTRLr_MEM_TYPEf_SET(r,f) (r).mem_ctrl[0]=(((r).mem_ctrl[0] & ~((uint32_t)0x3 << 6)) | ((((uint32_t)f) & 0x3) << 6))

/* New definition (BCM53280, etc.) */
#define ROBO_MEM_CTRLr_OP_CMDf_GET(r) (((r).mem_ctrl[0]) & 0x3f)
#define ROBO_MEM_CTRLr_OP_CMDf_SET(r,f) (r).mem_ctrl[0]=(((r).mem_ctrl[0] & ~((uint32_t)0x3f)) | (((uint32_t)f) & 0x3f))
#define ROBO_MEM_CTRLr_RESERVEDf_GET(r) ((((r).mem_ctrl[0]) >> 6) & 0x1)
#define ROBO_MEM_CTRLr_RESERVEDf_SET(r,f) (r).mem_ctrl[0]=(((r).mem_ctrl[0] & ~((uint32_t)0x1 << 6)) | ((((uint32_t)f) & 0x1) << 6))
#define ROBO_MEM_CTRLr_MEM_STDNf_GET(r) ((((r).mem_ctrl[0]) >> 7) & 0x1)
#define ROBO_MEM_CTRLr_MEM_STDNf_SET(r,f) (r).mem_ctrl[0]=(((r).mem_ctrl[0] & ~((uint32_t)0x1 << 7)) | ((((uint32_t)f) & 0x1) << 7))

/*
 * These macros can be used to access MEM_CTRL.
 *
 */
#define ROBO_READ_MEM_CTRLr(u,r) cdk_robo_reg_read(u,ROBO_MEM_CTRLr,(r._mem_ctrl),1)
#define ROBO_WRITE_MEM_CTRLr(u,r) cdk_robo_reg_write(u,ROBO_MEM_CTRLr,&(r._mem_ctrl),1)


/*******************************************************************************
 * REGISTER: MEM_INDEX
 ******************************************************************************/
#define ROBO_MEM_INDEXr 0x00000800

#define ROBO_MEM_INDEXr_SIZE 1

/*
 * This structure should be used to declare and program MEM_INDEX.
 *
 */
typedef union ROBO_MEM_INDEXr_s {
	uint32_t v[1];
	uint32_t mem_index[1];
	uint32_t _mem_index;
} ROBO_MEM_INDEXr_t;

#define ROBO_MEM_INDEXr_CLR(r) (r).mem_index[0] = 0
#define ROBO_MEM_INDEXr_SET(r,d) (r).mem_index[0] = d
#define ROBO_MEM_INDEXr_GET(r) (r).mem_index[0]

/*
 * These macros can be used to access individual fields.
 *
 */
#define ROBO_MEM_INDEXr_INDEXf_GET(r) (((r).mem_index[0]) & 0xff)
#define ROBO_MEM_INDEXr_INDEXf_SET(r,f) (r).mem_index[0]=(((r).mem_index[0] & ~((uint32_t)0xff)) | (((uint32_t)f) & 0xff))

/*
 * These macros can be used to access MEM_INDEX.
 *
 */
#define ROBO_READ_MEM_INDEXr(u,r) cdk_robo_reg_read(u,ROBO_MEM_INDEXr,(r._mem_index),1)
#define ROBO_WRITE_MEM_INDEXr(u,r) cdk_robo_reg_write(u,ROBO_MEM_INDEXr,&(r._mem_index),1)


/*******************************************************************************
 * REGISTER:  MEM_ADDR
 ******************************************************************************/
#define ROBO_MEM_ADDRr 0x00000801

#define ROBO_MEM_ADDRr_SIZE 2

/*
 * This structure should be used to declare and program MEM_ADDR.
 *
 */
typedef union ROBO_MEM_ADDRr_s {
	uint32_t v[1];
	uint32_t mem_addr[1];
	uint32_t _mem_addr;
} ROBO_MEM_ADDRr_t;

#define ROBO_MEM_ADDRr_CLR(r) (r).mem_addr[0] = 0
#define ROBO_MEM_ADDRr_SET(r,d) (r).mem_addr[0] = d
#define ROBO_MEM_ADDRr_GET(r) (r).mem_addr[0]

/*
 * These macros can be used to access individual fields.
 *
 */
#define ROBO_MEM_ADDRr_MEM_ADRf_GET(r) (((r).mem_addr[0]) & 0x3fff)
#define ROBO_MEM_ADDRr_MEM_ADRf_SET(r,f) (r).mem_addr[0]=(((r).mem_addr[0] & ~((uint32_t)0x3fff)) | (((uint32_t)f) & 0x3fff))
#define ROBO_MEM_ADDRr_MEM_RWf_GET(r) ((((r).mem_addr[0]) >> 14) & 0x1)
#define ROBO_MEM_ADDRr_MEM_RWf_SET(r,f) (r).mem_addr[0]=(((r).mem_addr[0] & ~((uint32_t)0x1 << 14)) | ((((uint32_t)f) & 0x1) << 14))
#define ROBO_MEM_ADDRr_MEM_STDNf_GET(r) ((((r).mem_addr[0]) >> 15) & 0x1)
#define ROBO_MEM_ADDRr_MEM_STDNf_SET(r,f) (r).mem_addr[0]=(((r).mem_addr[0] & ~((uint32_t)0x1 << 15)) | ((((uint32_t)f) & 0x1) << 15))

/*
 * These macros can be used to access MEM_ADDR.
 *
 */
#define ROBO_READ_MEM_ADDRr(u,r) cdk_robo_reg_read(u,ROBO_MEM_ADDRr,(r),2)
#define ROBO_WRITE_MEM_ADDRr(u,r) cdk_robo_reg_write(u,ROBO_MEM_ADDRr,&(r),2)


/*******************************************************************************
 * REGISTER:  MEM_ADDR_0
 ******************************************************************************/
#define ROBO_MEM_ADDR_0r 0x00000810

#define ROBO_MEM_ADDR_0r_SIZE 2

/*
 * This structure should be used to declare and program MEM_ADDR_0.
 *
 */
typedef union ROBO_MEM_ADDR_0r_s {
	uint32_t v[1];
	uint32_t mem_addr_0[1];
	uint32_t _mem_addr_0;
} ROBO_MEM_ADDR_0r_t;

#define ROBO_MEM_ADDR_0r_CLR(r) (r).mem_addr_0[0] = 0
#define ROBO_MEM_ADDR_0r_SET(r,d) (r).mem_addr_0[0] = d
#define ROBO_MEM_ADDR_0r_GET(r) (r).mem_addr_0[0]

/*
 * These macros can be used to access individual fields.
 *
 */
#define ROBO_MEM_ADDR_0r_MEM_ADDR_OFFSETf_GET(r) (((r).mem_addr_0[0]) & 0xffff)
#define ROBO_MEM_ADDR_0r_MEM_ADDR_OFFSETf_SET(r,f) (r).mem_addr_0[0]=(((r).mem_addr_0[0] & ~((uint32_t)0xffff)) | (((uint32_t)f) & 0xffff))

/*
 * These macros can be used to access MEM_ADDR_0.
 *
 */
#define ROBO_READ_MEM_ADDR_0r(u,r) cdk_robo_reg_read(u,ROBO_MEM_ADDR_0r,(r._mem_addr_0),2)
#define ROBO_WRITE_MEM_ADDR_0r(u,r) cdk_robo_reg_write(u,ROBO_MEM_ADDR_0r,&(r._mem_addr_0),2)


/*******************************************************************************
 * REGISTER:  MEM_DATA_0
 ******************************************************************************/
#define ROBO_MEM_DATA_0r 0x00000820

#define ROBO_MEM_DATA_0r_SIZE 8

/*
 * This structure should be used to declare and program MEM_DATA_0.
 *
 */
typedef union ROBO_MEM_DATA_0r_s {
	uint32_t v[2];
	uint32_t mem_data_0[2];
	uint32_t _mem_data_0;
} ROBO_MEM_DATA_0r_t;

#define ROBO_MEM_DATA_0r_CLR(r) CDK_MEMSET(&((r)._mem_data_0), 0, sizeof(ROBO_MEM_DATA_0r_t))
#define ROBO_MEM_DATA_0r_SET(r,i,d) (r).mem_data_0[i] = d
#define ROBO_MEM_DATA_0r_GET(r,i) (r).mem_data_0[i]

/*
 * These macros can be used to access individual fields.
 *
 */
#define ROBO_MEM_DATA_0r_MEM_DATAf_GET(r,a) cdk_field_get((r).mem_data_0,0,63,a)
#define ROBO_MEM_DATA_0r_MEM_DATAf_SET(r,a) cdk_field_set((r).mem_data_0,0,63,a)

/*
 * These macros can be used to access MEM_DATA_0.
 *
 */
#define ROBO_READ_MEM_DATA_0r(u,r) cdk_robo_reg_read(u,ROBO_MEM_DATA_0r,(r._mem_data_0),8)
#define ROBO_WRITE_MEM_DATA_0r(u,r) cdk_robo_reg_write(u,ROBO_MEM_DATA_0r,&(r._mem_data_0),8)


/*******************************************************************************
 * REGISTER:  ARLA_VTBL_RWCTRL
 ******************************************************************************/
#define ROBO_ARLA_VTBL_RWCTRLr 0x00000560

#define ROBO_ARLA_VTBL_RWCTRLr_SIZE 1

/*
 * This structure should be used to declare and program ARLA_VTBL_RWCTRL.
 *
 */
typedef union ROBO_ARLA_VTBL_RWCTRLr_s {
	uint32_t v[1];
	uint32_t arla_vtbl_rwctrl[1];
	uint32_t _arla_vtbl_rwctrl;
} ROBO_ARLA_VTBL_RWCTRLr_t;

#define ROBO_ARLA_VTBL_RWCTRLr_CLR(r) (r).arla_vtbl_rwctrl[0] = 0
#define ROBO_ARLA_VTBL_RWCTRLr_SET(r,d) (r).arla_vtbl_rwctrl[0] = d
#define ROBO_ARLA_VTBL_RWCTRLr_GET(r) (r).arla_vtbl_rwctrl[0]

/*
 * These macros can be used to access individual fields.
 *
 */
#define ROBO_ARLA_VTBL_RWCTRLr_ARLA_VTBL_RW_CLRf_GET(r) (((r).arla_vtbl_rwctrl[0]) & 0x3)
#define ROBO_ARLA_VTBL_RWCTRLr_ARLA_VTBL_RW_CLRf_SET(r,f) (r).arla_vtbl_rwctrl[0]=(((r).arla_vtbl_rwctrl[0] & ~((uint32_t)0x3)) | (((uint32_t)f) & 0x3))
#define ROBO_ARLA_VTBL_RWCTRLr_ARLA_VTBL_STDNf_GET(r) ((((r).arla_vtbl_rwctrl[0]) >> 7) & 0x1)
#define ROBO_ARLA_VTBL_RWCTRLr_ARLA_VTBL_STDNf_SET(r,f) (r).arla_vtbl_rwctrl[0]=(((r).arla_vtbl_rwctrl[0] & ~((uint32_t)0x1 << 7)) | ((((uint32_t)f) & 0x1) << 7))

/*
 * These macros can be used to access ARLA_VTBL_RWCTRL.
 *
 */
#define ROBO_READ_ARLA_VTBL_RWCTRLr(u,r) cdk_robo_reg_read(u,ROBO_ARLA_VTBL_RWCTRLr,(r._arla_vtbl_rwctrl),1)
#define ROBO_WRITE_ARLA_VTBL_RWCTRLr(u,r) cdk_robo_reg_write(u,ROBO_ARLA_VTBL_RWCTRLr,&(r._arla_vtbl_rwctrl),1)


/*******************************************************************************
 * REGISTER:  ARLA_VTBL_ADDR
 ******************************************************************************/
#define ROBO_ARLA_VTBL_ADDRr 0x00000561

#define ROBO_ARLA_VTBL_ADDRr_SIZE 2

/*
 * This structure should be used to declare and program ARLA_VTBL_ADDR.
 *
 */
typedef union ROBO_ARLA_VTBL_ADDRr_s {
	uint32_t v[1];
	uint32_t arla_vtbl_addr[1];
	uint32_t _arla_vtbl_addr;
} ROBO_ARLA_VTBL_ADDRr_t;

#define ROBO_ARLA_VTBL_ADDRr_CLR(r) (r).arla_vtbl_addr[0] = 0
#define ROBO_ARLA_VTBL_ADDRr_SET(r,d) (r).arla_vtbl_addr[0] = d
#define ROBO_ARLA_VTBL_ADDRr_GET(r) (r).arla_vtbl_addr[0]

/*
 * These macros can be used to access individual fields.
 *
 */
#define ROBO_ARLA_VTBL_ADDRr_VTBL_ADDR_INDEXf_GET(r) (((r).arla_vtbl_addr[0]) & 0xfff)
#define ROBO_ARLA_VTBL_ADDRr_VTBL_ADDR_INDEXf_SET(r,f) (r).arla_vtbl_addr[0]=(((r).arla_vtbl_addr[0] & ~((uint32_t)0xfff)) | (((uint32_t)f) & 0xfff))

/*
 * These macros can be used to access ARLA_VTBL_ADDR.
 *
 */
#define ROBO_READ_ARLA_VTBL_ADDRr(u,r) cdk_robo_reg_read(u,ROBO_ARLA_VTBL_ADDRr,(r._arla_vtbl_addr),2)
#define ROBO_WRITE_ARLA_VTBL_ADDRr(u,r) cdk_robo_reg_write(u,ROBO_ARLA_VTBL_ADDRr,&(r._arla_vtbl_addr),2)


/*******************************************************************************
 * REGISTER:  ARLA_VTBL_ENTRY
 ******************************************************************************/
#define ROBO_ARLA_VTBL_ENTRYr 0x00000563

#define ROBO_ARLA_VTBL_ENTRYr_SIZE 8

/*
 * This structure should be used to declare and program ARLA_VTBL_ENTRY.
 *
 */
typedef union ROBO_ARLA_VTBL_ENTRYr_s {
	uint32_t v[2];
	uint32_t arla_vtbl_entry[2];
	uint32_t _arla_vtbl_entry;
} ROBO_ARLA_VTBL_ENTRYr_t;

#define ROBO_ARLA_VTBL_ENTRYr_CLR(r) CDK_MEMSET(&(r), 0, sizeof(ROBO_ARLA_VTBL_ENTRYr_t))
#define ROBO_ARLA_VTBL_ENTRYr_SET(r,i,d) (r).arla_vtbl_entry[i] = d
#define ROBO_ARLA_VTBL_ENTRYr_GET(r,i) (r).arla_vtbl_entry[i]

/*
 * These macros can be used to access ARLA_VTBL_ENTRY.
 *
 */
#define ROBO_READ_ARLA_VTBL_ENTRYr(u,r) cdk_robo_reg_read(u,ROBO_ARLA_VTBL_ENTRYr,(r._arla_vtbl_entry),8)
#define ROBO_WRITE_ARLA_VTBL_ENTRYr(u,r) cdk_robo_reg_write(u,ROBO_ARLA_VTBL_ENTRYr,&(r._arla_vtbl_entry),8)


/*******************************************************************************
 * REGISTER:  ARLA_RWCTL
 ******************************************************************************/
#define ROBO_ARLA_RWCTLr 0x00000500

#define ROBO_ARLA_RWCTLr_SIZE 1

/*
 * This structure should be used to declare and program ARLA_RWCTL.
 *
 */
typedef union ROBO_ARLA_RWCTLr_s {
	uint32_t v[1];
	uint32_t arla_rwctl[1];
	uint32_t _arla_rwctl;
} ROBO_ARLA_RWCTLr_t;

#define ROBO_ARLA_RWCTLr_CLR(r) (r).arla_rwctl[0] = 0
#define ROBO_ARLA_RWCTLr_SET(r,d) (r).arla_rwctl[0] = d
#define ROBO_ARLA_RWCTLr_GET(r) (r).arla_rwctl[0]

/*
 * These macros can be used to access individual fields.
 *
 */
#define ROBO_ARLA_RWCTLr_TAB_RWf_GET(r) (((r).arla_rwctl[0]) & 0x1)
#define ROBO_ARLA_RWCTLr_TAB_RWf_SET(r,f) (r).arla_rwctl[0]=(((r).arla_rwctl[0] & ~((uint32_t)0x1)) | (((uint32_t)f) & 0x1))
#define ROBO_ARLA_RWCTLr_TAB_INDEXf_GET(r) ((((r).arla_rwctl[0]) >> 1) & 0x7)
#define ROBO_ARLA_RWCTLr_TAB_INDEXf_SET(r,f) (r).arla_rwctl[0]=(((r).arla_rwctl[0] & ~((uint32_t)0x7 << 1)) | ((((uint32_t)f) & 0x7) << 1))
#define ROBO_ARLA_RWCTLr_ARLA_RWCTL_RSRV0f_GET(r) ((((r).arla_rwctl[0]) >> 4) & 0x7)
#define ROBO_ARLA_RWCTLr_ARLA_RWCTL_RSRV0f_SET(r,f) (r).arla_rwctl[0]=(((r).arla_rwctl[0] & ~((uint32_t)0x7 << 4)) | ((((uint32_t)f) & 0x7) << 4))
#define ROBO_ARLA_RWCTLr_ARL_STRTDNf_GET(r) ((((r).arla_rwctl[0]) >> 7) & 0x1)
#define ROBO_ARLA_RWCTLr_ARL_STRTDNf_SET(r,f) (r).arla_rwctl[0]=(((r).arla_rwctl[0] & ~((uint32_t)0x1 << 7)) | ((((uint32_t)f) & 0x1) << 7))

/*
 * These macros can be used to access ARLA_RWCTL.
 *
 */
#define ROBO_READ_ARLA_RWCTLr(u,r) cdk_robo_reg_read(u,ROBO_ARLA_RWCTLr,(r._arla_rwctl),1)
#define ROBO_WRITE_ARLA_RWCTLr(u,r) cdk_robo_reg_write(u,ROBO_ARLA_RWCTLr,&(r._arla_rwctl),1)

/*******************************************************************************
 * End of 'ROBO_ARLA_RWCTLr'
 ******************************************************************************/


/*******************************************************************************
 * REGISTER:  OTHER_TABLE_INDEX
 ******************************************************************************/
#define ROBO_OTHER_TABLE_INDEXr 0x00000530

#define ROBO_OTHER_TABLE_INDEXr_SIZE 2

/*
 * This structure should be used to declare and program OTHER_TABLE_INDEX.
 *
 */
typedef union ROBO_OTHER_TABLE_INDEXr_s {
	uint32_t v[1];
	uint32_t other_table_index[1];
	uint32_t _other_table_index;
} ROBO_OTHER_TABLE_INDEXr_t;

#define ROBO_OTHER_TABLE_INDEXr_CLR(r) (r).other_table_index[0] = 0
#define ROBO_OTHER_TABLE_INDEXr_SET(r,d) (r).other_table_index[0] = d
#define ROBO_OTHER_TABLE_INDEXr_GET(r) (r).other_table_index[0]

/*
 * These macros can be used to access individual fields.
 *
 */
#define ROBO_OTHER_TABLE_INDEXr_TABLE_INDEXf_GET(r) (((r).other_table_index[0]) & 0xfff)
#define ROBO_OTHER_TABLE_INDEXr_TABLE_INDEXf_SET(r,f) (r).other_table_index[0]=(((r).other_table_index[0] & ~((uint32_t)0xfff)) | (((uint32_t)f) & 0xfff))
#define ROBO_OTHER_TABLE_INDEXr_RESERVED_Rf_GET(r) ((((r).other_table_index[0]) >> 12) & 0xf)
#define ROBO_OTHER_TABLE_INDEXr_RESERVED_Rf_SET(r,f) (r).other_table_index[0]=(((r).other_table_index[0] & ~((uint32_t)0xf << 12)) | ((((uint32_t)f) & 0xf) << 12))

/*
 * These macros can be used to access OTHER_TABLE_INDEX.
 *
 */
#define ROBO_READ_OTHER_TABLE_INDEXr(u,r) cdk_robo_reg_read(u,ROBO_OTHER_TABLE_INDEXr,(r._other_table_index),2)
#define ROBO_WRITE_OTHER_TABLE_INDEXr(u,r) cdk_robo_reg_write(u,ROBO_OTHER_TABLE_INDEXr,&(r._other_table_index),2)

/*******************************************************************************
 * End of 'ROBO_OTHER_TABLE_INDEXr'
 ******************************************************************************/


/*******************************************************************************
 * REGISTER:  ARLA_SRCH_CTL
 ******************************************************************************/
#define ROBO_ARLA_SRCH_CTLr 0x00000550

#define ROBO_ARLA_SRCH_CTLr_SIZE 1

/*
 * This structure should be used to declare and program ARLA_SRCH_CTL.
 *
 */
typedef union ROBO_ARLA_SRCH_CTLr_s {
	uint32_t v[1];
	uint32_t arla_srch_ctl[1];
	uint32_t _arla_srch_ctl;
} ROBO_ARLA_SRCH_CTLr_t;

#define ROBO_ARLA_SRCH_CTLr_CLR(r) (r).arla_srch_ctl[0] = 0
#define ROBO_ARLA_SRCH_CTLr_SET(r,d) (r).arla_srch_ctl[0] = d
#define ROBO_ARLA_SRCH_CTLr_GET(r) (r).arla_srch_ctl[0]

/*
 * These macros can be used to access individual fields.
 *
 */
#define ROBO_ARLA_SRCH_CTLr_ARLA_SRCH_VLIDf_GET(r) (((r).arla_srch_ctl[0]) & 0x1)
#define ROBO_ARLA_SRCH_CTLr_ARLA_SRCH_VLIDf_SET(r,f) (r).arla_srch_ctl[0]=(((r).arla_srch_ctl[0] & ~((uint32_t)0x1)) | (((uint32_t)f) & 0x1))
#define ROBO_ARLA_SRCH_CTLr_ARLA_SRCH_RSRV0f_GET(r) ((((r).arla_srch_ctl[0]) >> 1) & 0x3f)
#define ROBO_ARLA_SRCH_CTLr_ARLA_SRCH_RSRV0f_SET(r,f) (r).arla_srch_ctl[0]=(((r).arla_srch_ctl[0] & ~((uint32_t)0x3f << 1)) | ((((uint32_t)f) & 0x3f) << 1))
#define ROBO_ARLA_SRCH_CTLr_ARLA_SRCH_STDNf_GET(r) ((((r).arla_srch_ctl[0]) >> 7) & 0x1)
#define ROBO_ARLA_SRCH_CTLr_ARLA_SRCH_STDNf_SET(r,f) (r).arla_srch_ctl[0]=(((r).arla_srch_ctl[0] & ~((uint32_t)0x1 << 7)) | ((((uint32_t)f) & 0x1) << 7))

/*
 * These macros can be used to access ARLA_SRCH_CTL.
 *
 */
#define ROBO_READ_ARLA_SRCH_CTLr(u,r) cdk_robo_reg_read(u,ROBO_ARLA_SRCH_CTLr,(r._arla_srch_ctl),1)
#define ROBO_WRITE_ARLA_SRCH_CTLr(u,r) cdk_robo_reg_write(u,ROBO_ARLA_SRCH_CTLr,&(r._arla_srch_ctl),1)

/*******************************************************************************
 * End of 'ROBO_ARLA_SRCH_CTLr'
 ******************************************************************************/


/*******************************************************************************
 * REGISTER:  ARLA_SRCH_ADR
 ******************************************************************************/
#define ROBO_ARLA_SRCH_ADRr 0x00000552

#define ROBO_ARLA_SRCH_ADRr_SIZE 2

/*
 * This structure should be used to declare and program ARLA_SRCH_ADR.
 *
 */
typedef union ROBO_ARLA_SRCH_ADRr_s {
	uint32_t v[1];
	uint32_t arla_srch_adr[1];
	uint32_t _arla_srch_adr;
} ROBO_ARLA_SRCH_ADRr_t;

#define ROBO_ARLA_SRCH_ADRr_CLR(r) (r).arla_srch_adr[0] = 0
#define ROBO_ARLA_SRCH_ADRr_SET(r,d) (r).arla_srch_adr[0] = d
#define ROBO_ARLA_SRCH_ADRr_GET(r) (r).arla_srch_adr[0]

/*
 * These macros can be used to access individual fields.
 *
 */
#define ROBO_ARLA_SRCH_ADRr_SRCH_ADRf_GET(r) (((r).arla_srch_adr[0]) & 0x1fff)
#define ROBO_ARLA_SRCH_ADRr_SRCH_ADRf_SET(r,f) (r).arla_srch_adr[0]=(((r).arla_srch_adr[0] & ~((uint32_t)0x1fff)) | (((uint32_t)f) & 0x1fff))
#define ROBO_ARLA_SRCH_ADRr_RESERVED_Rf_GET(r) ((((r).arla_srch_adr[0]) >> 13) & 0x3)
#define ROBO_ARLA_SRCH_ADRr_RESERVED_Rf_SET(r,f) (r).arla_srch_adr[0]=(((r).arla_srch_adr[0] & ~((uint32_t)0x3 << 13)) | ((((uint32_t)f) & 0x3) << 13))
#define ROBO_ARLA_SRCH_ADRr_ARLA_SRCH_ADR_ENf_GET(r) ((((r).arla_srch_adr[0]) >> 15) & 0x1)
#define ROBO_ARLA_SRCH_ADRr_ARLA_SRCH_ADR_ENf_SET(r,f) (r).arla_srch_adr[0]=(((r).arla_srch_adr[0] & ~((uint32_t)0x1 << 15)) | ((((uint32_t)f) & 0x1) << 15))

/*
 * These macros can be used to access ARLA_SRCH_ADR.
 *
 */
#define ROBO_READ_ARLA_SRCH_ADRr(u,r) cdk_robo_reg_read(u,ROBO_ARLA_SRCH_ADRr,(r._arla_srch_adr),2)
#define ROBO_WRITE_ARLA_SRCH_ADRr(u,r) cdk_robo_reg_write(u,ROBO_ARLA_SRCH_ADRr,&(r._arla_srch_adr),2)

/*******************************************************************************
 * End of 'ROBO_ARLA_SRCH_ADRr'
 ******************************************************************************/


/*******************************************************************************
 *
 * Memory operations
 *
 ******************************************************************************/

#define ROBO_MEM_OP_WRITE               0
#define ROBO_MEM_OP_READ                1
#define ROBO_MEM_OP_CLEAR               2


/*******************************************************************************
 *
 * Additional definitions for register MEM_CTRL
 *
 ******************************************************************************/

#define ROBO_MEM_TYPE_VLAN              2
#define ROBO_MEM_TYPE_ARL               3


/*******************************************************************************
 *
 * Additional definitions for register GENMEM_CTL
 *
 ******************************************************************************/

#define ROBO_GENMEM_TYPE_ARL            0
#define ROBO_GENMEM_TYPE_TXDSC          1


/*******************************************************************************
 *
 * Additional definitions for register ARLA_RWCTL
 *
 ******************************************************************************/

#define ROBO_ARLA_TYPE_VLAN             1
#define ROBO_ARLA_TYPE_MCAST            2
#define ROBO_ARLA_TYPE_MSPT             3
#define ROBO_ARLA_TYPE_VLAN2VLAN        4
#define ROBO_ARLA_TYPE_MAC2VLAN         5
#define ROBO_ARLA_TYPE_PROTO2VLAN       6
#define ROBO_ARLA_TYPE_FLOW2VLAN        7


/*******************************************************************************
 *
 * Decoders for access throufg ARL search interface
 *
 ******************************************************************************/

#define ROBO_ARLA_SRCH_BCM53242         1


#endif /* __ROBO_MEM_REGS_H__ */
