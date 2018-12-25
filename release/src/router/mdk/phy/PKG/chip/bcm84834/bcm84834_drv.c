/*
 * $Id: bcm84834_drv.c,v 1.20 Broadcom SDK $
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
 * PHY driver for BCM84834.
 *
 */

#include <phy/phy.h>
#include <phy/ge_phy.h>
#include <cdk/cdk_device.h>

#include <phy/chip/bcm84834_defs.h>

extern unsigned char bcm84834_ucode[];
extern int bcm84834_ucode_len;

#define PHY_RESET_MSEC                  2000
#define ARM_DATA_WR_MSEC                10
#define MDIO_CMD_WAIT_MSEC              1000
#define MDIO_FREQ_MAX_KHZ               24000

#define C45_DEVAD(_a)                   LSHIFT32((_a),16)
#define DEVAD_PMA_PMD                   C45_DEVAD(MII_C45_DEV_PMA_PMD)

/* Probe registers */
#define PMD_PHY_ID0_REG                 (DEVAD_PMA_PMD + MII_PHY_ID0_REG)
#define PMD_PHY_ID1_REG                 (DEVAD_PMA_PMD + MII_PHY_ID1_REG)

#define BCM84834_PMD_PHY_ID0            0x0362
#define BCM84834_PMD_PHY_ID1            0x5c30
#define BCM84834_CHIP_ID                0x84834

/* MDIO Command Handler (MCH) flags */
#define MCH_F_SPECIAL                   (1L << 31)

/* MDIO commands */
#define MCH_C_NOP                       0x0000
#define MCH_C_GET_PAIR_SWAP             0x8000
#define MCH_C_SET_PAIR_SWAP             0x8001
#define MCH_C_GET_MACSEC_ENABLE         0x8002
#define MCH_C_SET_MACSEC_ENABLE         0x8003
#define MCH_C_GET_1588_ENABLE           0x8004
#define MCH_C_SET_1588_ENABLE           0x8005
#define MCH_C_GET_SHORT_REACH_ENABLE    0x8006
#define MCH_C_SET_SHORT_REACH_ENABLE    0x8007
#define MCH_C_GET_EEE_MODE              0x8008
#define MCH_C_SET_EEE_MODE              0x8009
#define MCH_C_GET_EMI_MODE_ENABLE       0x800a
#define MCH_C_SET_EMI_MODE_ENABLE       0x800b
#define MCH_C_GET_SNR                   0x8030
#define MCH_C_GET_CURRENT_TEMP          0x8031
#define MCH_C_SET_UPPER_TEMP_WARN_LVL   0x8032
#define MCH_C_GET_UPPER_TEMP_WARN_LVL   0x8033
#define MCH_C_SET_LOWER_TEMP_WARN_LVL   0x8034
#define MCH_C_GET_LOWER_TEMP_WARN_LVL   0x8035
#define MCH_C_PEEK_WORD                 0xc000
#define MCH_C_POKE_WORD                 0xc001
#define MCH_C_GET_DATA_BUF_ADDRESSES    0xc002

/* MDIO status values */
#define MCH_S_RECEIVED                  0x0001
#define MCH_S_IN_PROGRESS               0x0002
#define MCH_S_COMPLETE_PASS             0x0004
#define MCH_S_COMPLETE_ERROR            0x0008
#define MCH_S_OPEN_FOR_CMDS             0x0010
#define MCH_S_SYSTEM_BOOT               0x0020
#define MCH_S_NOT_OPEN_FOR_CMDS         0x0040
#define MCH_S_CLEAR_COMPLETE            0x0080
#define MCH_S_OPEN_OVERRIDE             0xA5A5

/* Low level debugging (off by default) */
#ifdef PHY_DEBUG_ENABLE
#define _PHY_DBG(_pc, _stuff) \
    PHY_VERB(_pc, _stuff)
#else
#define _PHY_DBG(_pc, _stuff)
#endif

/***********************************************************************
 *
 * HELPER FUNCTIONS
 *
 ***********************************************************************/


static int
_bcm84834_write_arm_addr(phy_ctrl_t *pc, uint32_t addr)
{
    int ioerr = 0;
    PHYC_MDIO2ARM_ADDR_LOWr_t arm_addr_lo;
    PHYC_MDIO2ARM_ADDR_HIGHr_t arm_addr_hi;

    PHYC_MDIO2ARM_ADDR_HIGHr_SET(arm_addr_hi, addr >> 16);
    ioerr += WRITE_PHYC_MDIO2ARM_ADDR_HIGHr(pc, arm_addr_hi);

    PHYC_MDIO2ARM_ADDR_LOWr_SET(arm_addr_lo, addr & 0xffff);
    ioerr += WRITE_PHYC_MDIO2ARM_ADDR_LOWr(pc, arm_addr_lo);

    return ioerr;
}
    
static int
_bcm84834_write_arm_data(phy_ctrl_t *pc, uint32_t data)
{
    int ioerr = 0;
    PHYC_MDIO2ARM_DATA_LOWr_t arm_data_lo;
    PHYC_MDIO2ARM_DATA_HIGHr_t arm_data_hi;
 
    PHYC_MDIO2ARM_DATA_HIGHr_SET(arm_data_hi, data >> 16);
    ioerr += WRITE_PHYC_MDIO2ARM_DATA_HIGHr(pc, arm_data_hi);

    /* Data gets written and the address gets auto-incremented upon write
       to PHYC_MDIO2ARM_DATA_LOWr if SELF_INC is set. So do not change 
       the order.
     */
    PHYC_MDIO2ARM_DATA_LOWr_SET(arm_data_lo, data & 0xffff);
    ioerr += WRITE_PHYC_MDIO2ARM_DATA_LOWr(pc, arm_data_lo);

    return ioerr;
}
    
static int
_bcm84834_halt(phy_ctrl_t *pc)
{
    int ioerr = 0;
    PHYC_MDIO2ARM_CTLr_t arm_ctl;
    CRG_RST_1r_t crg_rst_1r;
    CRG_GLB_RST_CTLr_t crg_glb_rst_ctl;
    PHYC_LED0_MASKr_t led0_mask;
    PHYC_LED0_MASK_Hr_t led0_mask_h;
    PHYC_LED0_BLINK_CYCLE_CNTr_t led0_blink_cycle_cnt;
    PHYC_LED1_MASKr_t led1_mask;
    PHYC_LED1_MASK_Hr_t led1_mask_h;
    PHYC_LED1_BLINK_CYCLE_CNTr_t led1_blink_cycle_cnt;
    PHYC_LED2_MASKr_t led2_mask;
    PHYC_LED2_MASK_Hr_t led2_mask_h;
    PHYC_LED2_BLINK_CYCLE_CNTr_t led2_blink_cycle_cnt;
    PHYC_LED3_MASKr_t led3_mask;
    PHYC_LED3_MASK_Hr_t led3_mask_h;
    PHYC_LED3_BLINK_CYCLE_CNTr_t led3_blink_cycle_cnt;
    PHYC_LED4_MASKr_t led4_mask;
    PHYC_LED4_MASK_Hr_t led4_mask_h;
    PHYC_LED4_BLINK_CYCLE_CNTr_t led4_blink_cycle_cnt;
    PHYC_LED_CTLr_t led_ctl;
    PHYC_LED_SOURCEr_t led_source;
    PHYC_LED_SOURCE_Hr_t led_source_h;

    /* LED control stuff */
    PHYC_LED0_MASKr_SET(led0_mask, 0xffff);
    ioerr += WRITE_PHYC_LED0_MASKr(pc, led0_mask);

    PHYC_LED0_MASK_Hr_SET(led0_mask_h, 0x0000);
    ioerr += WRITE_PHYC_LED0_MASK_Hr(pc, led0_mask_h);

    PHYC_LED0_BLINK_CYCLE_CNTr_SET(led0_blink_cycle_cnt, 0x0000);
    ioerr += WRITE_PHYC_LED0_BLINK_CYCLE_CNTr(pc, led0_blink_cycle_cnt);

    PHYC_LED1_MASKr_SET(led1_mask, 0x0000);
    ioerr += WRITE_PHYC_LED1_MASKr(pc, led1_mask);

    PHYC_LED1_MASK_Hr_SET(led1_mask_h, 0x0000);
    ioerr += WRITE_PHYC_LED1_MASK_Hr(pc, led1_mask_h);

    PHYC_LED1_BLINK_CYCLE_CNTr_SET(led1_blink_cycle_cnt, 0x0000);
    ioerr += WRITE_PHYC_LED1_BLINK_CYCLE_CNTr(pc, led1_blink_cycle_cnt);

    PHYC_LED2_MASKr_SET(led2_mask, 0x0000);
    ioerr += WRITE_PHYC_LED2_MASKr(pc, led2_mask);

    PHYC_LED2_MASK_Hr_SET(led2_mask_h, 0x0000);
    ioerr += WRITE_PHYC_LED2_MASK_Hr(pc, led2_mask_h);

    PHYC_LED2_BLINK_CYCLE_CNTr_SET(led2_blink_cycle_cnt, 0x0000);
    ioerr += WRITE_PHYC_LED2_BLINK_CYCLE_CNTr(pc, led2_blink_cycle_cnt);

    PHYC_LED3_MASKr_SET(led3_mask, 0x0000);
    ioerr += WRITE_PHYC_LED3_MASKr(pc, led3_mask);

    PHYC_LED3_MASK_Hr_SET(led3_mask_h, 0x0000);
    ioerr += WRITE_PHYC_LED3_MASK_Hr(pc, led3_mask_h);

    PHYC_LED3_BLINK_CYCLE_CNTr_SET(led3_blink_cycle_cnt, 0x0000);
    ioerr += WRITE_PHYC_LED3_BLINK_CYCLE_CNTr(pc, led3_blink_cycle_cnt);

    PHYC_LED4_MASKr_SET(led4_mask, 0x0000);
    ioerr += WRITE_PHYC_LED4_MASKr(pc, led4_mask);

    PHYC_LED4_MASK_Hr_SET(led4_mask_h, 0x0000);
    ioerr += WRITE_PHYC_LED4_MASK_Hr(pc, led4_mask_h);

    PHYC_LED4_BLINK_CYCLE_CNTr_SET(led4_blink_cycle_cnt, 0x0000);
    ioerr += WRITE_PHYC_LED4_BLINK_CYCLE_CNTr(pc, led4_blink_cycle_cnt);

    PHYC_LED_CTLr_SET(led_ctl, 0xb6db);
    ioerr += WRITE_PHYC_LED_CTLr(pc, led_ctl);

    PHYC_LED_SOURCEr_SET(led_source, 0xffff);
    ioerr += WRITE_PHYC_LED_SOURCEr(pc, led_source);

    PHYC_LED_SOURCE_Hr_SET(led_source_h, 0x0000);
    ioerr += WRITE_PHYC_LED_SOURCE_Hr(pc, led_source_h);

    /* Enable global reset */
    CRG_GLB_RST_CTLr_CLR(crg_glb_rst_ctl);
    CRG_GLB_RST_CTLr_BLK_RST_ENAf_SET(crg_glb_rst_ctl, 1);
    ioerr += WRITE_CRG_GLB_RST_CTLr(pc, crg_glb_rst_ctl);

    /* Assert reset for the whole ARM system */
    CRG_RST_1r_SET(crg_rst_1r, 0x017c);
    ioerr += WRITE_CRG_RST_1r(pc, crg_rst_1r);

    /* Deassert reset for the whole ARM system but the ARM processor */
    CRG_RST_1r_SET(crg_rst_1r, 0x0040);
    ioerr += WRITE_CRG_RST_1r(pc, crg_rst_1r);

    /*
     * Remove bottom write protection and set VINITHI signal to 1 in order
     * to have the ARM processor start executing bootrom space 0xffff0000
     */
    ioerr += _bcm84834_write_arm_addr(pc, 0xc3000000);
    ioerr += _bcm84834_write_arm_data(pc, 0x0000001e);

    PHYC_MDIO2ARM_CTLr_CLR(arm_ctl);
    PHYC_MDIO2ARM_CTLr_MDIO2ARM_SIZEf_SET(arm_ctl, 2);
    PHYC_MDIO2ARM_CTLr_MDIO2ARM_WRf_SET(arm_ctl, 1);
    ioerr += WRITE_PHYC_MDIO2ARM_CTLr(pc, arm_ctl);

    /*
     * Replace the first 32 bits of bootrom at 0xffff0000 with the
     * instruction "here BAL here" to loop the processor in the bootrom
     * address space.
     */
    ioerr += _bcm84834_write_arm_addr(pc, 0xffff0000);
    ioerr += _bcm84834_write_arm_data(pc, 0xeafffffe);

    PHYC_MDIO2ARM_CTLr_CLR(arm_ctl);
    PHYC_MDIO2ARM_CTLr_MDIO2ARM_SIZEf_SET(arm_ctl, 2);
    PHYC_MDIO2ARM_CTLr_MDIO2ARM_WRf_SET(arm_ctl, 1);
    ioerr += WRITE_PHYC_MDIO2ARM_CTLr(pc, arm_ctl);

    /* Deassert ARM processor reset */
    CRG_RST_1r_CLR(crg_rst_1r);
    ioerr += WRITE_CRG_RST_1r(pc, crg_rst_1r);

    return ioerr ? CDK_E_IO : CDK_E_NONE;
}

/*
 * Function:
 *      _bcm84834_fast_load_set
 * Purpose:
 *      Request optimized MDIO clock frequency
 * Parameters:
 *      pc - PHY control structure
 *      enable - turn optimized clock on/off
 * Returns:
 *      CDK_E_xxx
 */
static int
_bcm84834_fast_load_set(phy_ctrl_t *pc, int enable)
{
    int rv = CDK_E_UNAVAIL;
    int freq_khz;

    if (PHY_CTRL_FW_HELPER(pc)) {
        freq_khz = 0;
        if (enable && (PHY_CTRL_FLAGS(pc) & PHY_F_FAST_LOAD)) {
            freq_khz = MDIO_FREQ_MAX_KHZ;
            PHY_VERB(pc, ("enable fast MDIO clock\n"));
        }
        rv = PHY_CTRL_FW_HELPER(pc)(pc, freq_khz, 0, NULL);
    }
    return rv;
}

/*
 * Function:
 *      _bcm84834_write_to_arm
 * Purpose:
 *      Download firmware to PHY
 * Parameters:
 *      pc - PHY control structure
 *      addr - load address
 *      data - firmware data
 *      len - sife of firmware data
 * Returns:
 *      CDK_E_xxx
 */
static int
_bcm84834_write_to_arm(phy_ctrl_t *pc, uint32_t addr, uint8_t *data, int len)
{
    int ioerr = 0;
    int rv = CDK_E_NONE;
    PHYC_MDIO2ARM_CTLr_t arm_ctl;
    PHYC_MDIO2ARM_STSr_t arm_sts;
    int idx, usec;
    uint8_t *p8;
    uint32_t data32;

    /* Request fast MDIO clock */
    (void)_bcm84834_fast_load_set(pc, 1);

    /* Enable auto-incrementing address */
    PHYC_MDIO2ARM_CTLr_CLR(arm_ctl);
    PHYC_MDIO2ARM_CTLr_MDIO2ARM_SELF_INC_ADDRf_SET(arm_ctl, 1);
    PHYC_MDIO2ARM_CTLr_MDIO2ARM_BURSTf_SET(arm_ctl, 1);
    PHYC_MDIO2ARM_CTLr_MDIO2ARM_SIZEf_SET(arm_ctl, 2);
    PHYC_MDIO2ARM_CTLr_MDIO2ARM_WRf_SET(arm_ctl, 1);
    ioerr += WRITE_PHYC_MDIO2ARM_CTLr(pc, arm_ctl);

    ioerr += _bcm84834_write_arm_addr(pc, addr);
    
    for (idx = 0; idx < len; idx += 4) {

        p8 = &data[idx];
        data32 = (LSHIFT32(p8[3], 24) |
                  LSHIFT32(p8[2], 16) |
                  LSHIFT32(p8[1], 8)  |
                  LSHIFT32(p8[0], 0));

        ioerr += _bcm84834_write_arm_data(pc, data32);

        /*
         * Reads from a broadcast address always returns 0xffff and hence
         * the following check will always succeed for a broadcast address.
         */
        for (usec = 0; usec < ARM_DATA_WR_MSEC; usec++) {
            ioerr += READ_PHYC_MDIO2ARM_STSr(pc, &arm_sts);
            if (ioerr) {
                break;
            }
            if (PHYC_MDIO2ARM_STSr_MDIO2ARM_DONEf_GET(arm_sts)) {
                break;
            }
            PHY_SYS_USLEEP(1000);
        }

        if (PHYC_MDIO2ARM_STSr_MDIO2ARM_DONEf_GET(arm_sts) == 0) {
            _PHY_DBG(pc, ("MDIO2ARM write failed: addr=%08x\n", addr + idx));
            rv = CDK_E_TIMEOUT;
            break;
        }
    }

    PHYC_MDIO2ARM_CTLr_CLR(arm_ctl);
    ioerr += WRITE_PHYC_MDIO2ARM_CTLr(pc, arm_ctl);

    /* Restore MDIO clock */
    (void)_bcm84834_fast_load_set(pc, 0);


    return ioerr ? CDK_E_IO : rv;
}

/*
 * Function:
 *      _bcm84834_mdio_cmd_op
 * Purpose:
 *      PHY init.
 * Parameters:
 *      pc - PHY control structure
 *      cmd - MDIO command
 *      data - data associated with command
 *      wr_size - size of data provided by caller
 *      rd_size - size of data expected by caller
 * Returns:
 *      CDK_E_xxx
 */
static int
_bcm84834_mdio_cmd_op(phy_ctrl_t *pc, uint32_t cmd,
                      uint16_t *data, int wr_size, int rd_size)
{
    int ioerr = 0;
    int rv = CDK_E_NONE;
    TOP_MCH_CMDr_t mch_cmd; 
    TOP_MCH_STATr_t mch_stat; 
    TOP_MCH_DATAr_t mch_data; 
    uint32_t stat;
    int msec, idx;

    if (wr_size < 0 || wr_size > 5) {
        return CDK_E_PARAM;
    }

    if (rd_size < 0 || rd_size > 5) {
        return CDK_E_PARAM;
    }

    if (cmd & MCH_F_SPECIAL) {
        TOP_MCH_STATr_SET(mch_stat, MCH_S_OPEN_OVERRIDE);
        ioerr += WRITE_TOP_MCH_STATr(pc, mch_stat);
    }

    for (msec = 0; msec < MDIO_CMD_WAIT_MSEC; msec++) {
        ioerr += READ_TOP_MCH_STATr(pc, &mch_stat);
        stat = TOP_MCH_STATr_GET(mch_stat);
        if (ioerr) {
            break;
        }
        if ((stat & MCH_S_OPEN_FOR_CMDS) != 0) {
            break;
        }
        PHY_SYS_USLEEP(1000);
    }
    if ((stat & MCH_S_OPEN_FOR_CMDS) == 0) {
        PHY_WARN(pc, ("MDIO command not ready: status=%04"PRIx32"\n", stat));
        rv = CDK_E_TIMEOUT;
    }

    /* Strip command flags */
    cmd &= 0xffff;

    if (cmd == MCH_C_NOP) {
        return ioerr ? CDK_E_IO : rv;
    }

    for (idx = 0; idx < wr_size; idx++) {
        TOP_MCH_DATAr_SET(mch_data, data[idx]);
        ioerr += WRITE_TOP_MCH_DATAr(pc, idx, mch_data);
    }

    TOP_MCH_CMDr_SET(mch_cmd, cmd);
    ioerr += WRITE_TOP_MCH_CMDr(pc, mch_cmd);

    for (msec = 0; msec < MDIO_CMD_WAIT_MSEC; msec++) {
        ioerr += READ_TOP_MCH_STATr(pc, &mch_stat);
        stat = TOP_MCH_STATr_GET(mch_stat);
        if (ioerr) {
            break;
        }
        if ((stat & (MCH_S_COMPLETE_PASS | MCH_S_COMPLETE_ERROR)) != 0) {
            break;
        }
        PHY_SYS_USLEEP(1000);
    }
    if ((stat & MCH_S_COMPLETE_PASS) == 0) {
        PHY_WARN(pc, ("MDIO command not complete: "
                      "cmd=%04"PRIx32" status=%04"PRIx32"\n", 
                      cmd, stat));
                        
        rv = CDK_E_TIMEOUT;
    }

    for (idx = 0; idx < rd_size; idx++) {
        ioerr += READ_TOP_MCH_DATAr(pc, idx, &mch_data);
        data[idx] = TOP_MCH_DATAr_GET(mch_data);
    }

    TOP_MCH_STATr_SET(mch_stat, MCH_S_CLEAR_COMPLETE);
    ioerr += WRITE_TOP_MCH_STATr(pc, mch_stat);

    return ioerr ? CDK_E_IO : rv;
}

#ifdef _EEE_MODE
static int
_bcm84834_eee_mode_set(phy_ctrl_t *pc, uint32_t mode, uint32_t ag_th_high,
                       uint32_t ag_th_low, uint32_t latency )
{
    uint16_t data[5];

    data[0] = mode;
    data[1] = ag_th_high;
    data[2] = ag_th_low;
    data[3] = latency;

    return _bcm84834_mdio_cmd_op(pc, MCH_C_SET_EEE_MODE, data, 4, 0);
}

static int
_bcm84834_eee_mode_get(phy_ctrl_t *pc, uint32_t *mode, uint32_t *ag_th_high,
                       uint32_t *ag_th_low, uint32_t *latency )
{
    int rv;
    uint16_t data[5];

    rv = _bcm84834_mdio_cmd_op(pc, MCH_C_GET_EEE_MODE, data, 0, 4);

    if (mode) {
        *mode = data[0];
    }
    if (ag_th_high) {
        *ag_th_high = data[1];
    }
    if (ag_th_low) {
        *ag_th_low = data[2];
    }
    if (latency) {
        *latency = data[3];
    }
 
    return rv;
}
#endif

/*
 * Function:
 *      _bcm84834_mdi_pair_set
 * Purpose:
 *      Remap MDI pairs according to board layout
 * Parameters:
 *      pc - PHY control structure
 *      mdi_map - MDI mapping info
 * Returns:
 *      CDK_E_xxx
 * Notes:
 *      Mapping value consists of four 4-bit pair numbers, e.g.:
 *      0x3210 => identity mapping (A->A, B->B, C->C, D->D)
 *      0x0123 => reverse order  (A->D, B->C, C->B, D->A)
 */
static int
_bcm84834_mdi_pair_set(phy_ctrl_t *pc, uint32_t mdi_map)
{
    uint16_t data[2];

    data[0] = 0;
    data[1] =  (mdi_map & 0x3000) >> 6;
    data[1] |= (mdi_map & 0x0300) >> 4;
    data[1] |= (mdi_map & 0x0030) >> 2;
    data[1] |= (mdi_map & 0x0003);

    return _bcm84834_mdio_cmd_op(pc, MCH_C_SET_PAIR_SWAP | MCH_F_SPECIAL,
                                 data, 2, 0);
}

/*
 * Function:
 *      _bcm84834_force_link_down
 * Purpose:
 *      Ensure that formware picks up loopback speed
 * Parameters:
 *      pc - PHY control structure
 * Returns:
 *      CDK_E_xxx
 */
static int
_bcm84834_force_link_down(phy_ctrl_t *pc)
{
    return _bcm84834_mdio_cmd_op(pc, MCH_C_NOP | MCH_F_SPECIAL, NULL, 0, 0);
}

/*
 * Function:
 *      _bcm84834_init_stage_0
 * Purpose:
 *      PHY init.
 * Parameters:
 *      pc - PHY control structure
 * Returns:
 *      CDK_E_xxx
 */
static int
_bcm84834_init_stage_0(phy_ctrl_t *pc)
{
    int ioerr = 0;
    int rv = CDK_E_NONE;
    PMD_IEEE_CTL1r_t pmd_ieee_ctl1;
    COMBO_MII_CTRLr_t mii_ctrl;

    _PHY_DBG(pc, ("init_stage_0\n"));

    PHY_CTRL_FLAGS(pc) |= PHY_F_FIBER_MODE;

    ioerr += READ_COMBO_MII_CTRLr(pc, &mii_ctrl);
    COMBO_MII_CTRLr_RESETf_SET(mii_ctrl, 1);
    ioerr += WRITE_COMBO_MII_CTRLr(pc, mii_ctrl);

    ioerr += READ_PMD_IEEE_CTL1r(pc, &pmd_ieee_ctl1);
    PMD_IEEE_CTL1r_RESETf_SET(pmd_ieee_ctl1, 1);
    ioerr += WRITE_PMD_IEEE_CTL1r(pc, pmd_ieee_ctl1);

    return ioerr ? CDK_E_IO : rv;
}

/*
 * Function:
 *      _bcm84834_init_stage_1
 * Purpose:
 *      PHY init.
 * Parameters:
 *      pc - PHY control structure
 * Returns:
 *      CDK_E_xxx
 */
static int
_bcm84834_init_stage_1(phy_ctrl_t *pc)
{
    int ioerr = 0;
    int rv = CDK_E_NONE;
    XGP_PD_RW_14r_t xgp_pd_rw_14;
    XGP_PD_DEF_14r_t xgp_pd_def_14;

    _PHY_DBG(pc, ("init_stage_1\n"));

    XGP_PD_RW_14r_SET(xgp_pd_rw_14, 0xf003);
    ioerr += WRITE_XGP_PD_RW_14r(pc, xgp_pd_rw_14);
    XGP_PD_DEF_14r_SET(xgp_pd_def_14, 0x0401);
    ioerr += WRITE_XGP_PD_DEF_14r(pc, xgp_pd_def_14);
    ioerr +=
        _bcm84834_halt(pc);

    return ioerr ? CDK_E_IO : rv;
}

/*
 * Function:
 *      _bcm84834_init_stage_2
 * Purpose:
 *      PHY init.
 * Parameters:
 *      pc - PHY control structure
 * Returns:
 *      CDK_E_xxx
 */
static int
_bcm84834_init_stage_2(phy_ctrl_t *pc)
{
    int ioerr = 0;
    int rv = CDK_E_NONE;
    int orig_inst, phy_addr;
    PHYC_MDIO2ARM_CTLr_t arm_ctl;

    _PHY_DBG(pc, ("init_stage_2\n"));

    if (!(PHY_CTRL_FLAGS(pc) & PHY_F_BCAST_MSTR)) {
        return CDK_E_NONE;
    }
    phy_addr = PHY_CTRL_PHY_ADDR(pc);
    orig_inst = PHY_CTRL_PHY_INST(pc);

    if (phy_ctrl_change_inst(pc, (phy_addr & ~0x1f) - phy_addr, NULL) < 0) {
        return CDK_E_FAIL;
    }

    _PHY_DBG(pc, ("load firmware\n"));
    ioerr += _bcm84834_write_to_arm(pc, 0, bcm84834_ucode, bcm84834_ucode_len);

    /* Enable bottom write protection and set VINITHI signal to 0 */
    ioerr += _bcm84834_write_arm_addr(pc, 0xc3000000);
    ioerr += _bcm84834_write_arm_data(pc, 0x0000000c);

    PHYC_MDIO2ARM_CTLr_CLR(arm_ctl);
    PHYC_MDIO2ARM_CTLr_MDIO2ARM_SIZEf_SET(arm_ctl, 2);
    PHYC_MDIO2ARM_CTLr_MDIO2ARM_WRf_SET(arm_ctl, 1);
    ioerr += WRITE_PHYC_MDIO2ARM_CTLr(pc, arm_ctl);

    if (phy_ctrl_change_inst(pc, orig_inst, NULL) < 0) {
        return CDK_E_FAIL;
    }

    return ioerr ? CDK_E_IO : rv;

}

/*
 * Function:
 *      _bcm84834_init_stage_3
 * Purpose:
 *      PHY init.
 * Parameters:
 *      pc - PHY control structure
 * Returns:
 *      CDK_E_xxx
 */
static int
_bcm84834_init_stage_3(phy_ctrl_t *pc)
{
    int ioerr = 0;
    int rv = CDK_E_NONE;
    TOP_FW_VERr_t fw_ver;
    TOP_FW_DATEr_t fw_date;
    CRG_RST_1r_t crg_rst_1r;
    XGP_PD_DEF_14r_t xgp_pd_def_14;

    _PHY_DBG(pc, ("init_stage_3\n"));

    /* Turn off broadcast mode */
    XGP_PD_DEF_14r_SET(xgp_pd_def_14, 0x0000);
    ioerr += WRITE_XGP_PD_DEF_14r(pc, xgp_pd_def_14);

    /* Clear f/w ver. regs. */
    TOP_FW_VERr_SET(fw_ver, 0);
    TOP_FW_DATEr_SET(fw_date, 0);

    ioerr += WRITE_TOP_FW_VERr(pc, fw_ver);
    ioerr += WRITE_TOP_FW_DATEr(pc, fw_date);

    /* Now reset only the ARM core */
    CRG_RST_1r_SET(crg_rst_1r, 0x0040);
    ioerr += WRITE_CRG_RST_1r(pc, crg_rst_1r);

    CRG_RST_1r_SET(crg_rst_1r, 0x0000);
    ioerr += WRITE_CRG_RST_1r(pc, crg_rst_1r);

    return ioerr ? CDK_E_IO : rv;
}


/*
 * Function:
 *      _bcm84834_init_stage_4
 * Purpose:
 *      PHY init.
 * Parameters:
 *      pc - PHY control structure
 * Returns:
 *      CDK_E_xxx
 */
static int
_bcm84834_init_stage_4(phy_ctrl_t *pc)
{
    int ioerr = 0;
    int rv = CDK_E_NONE;
    PMD_IEEE_CTL1r_t pmd_ctl1;
    TOP_FW_VERr_t fw_ver;
    TOP_FW_DATEr_t fw_date;
    SHDW_MII_CTRLr_t shdw_mii_ctrl;
    int msec;

    _PHY_DBG(pc, ("init_stage_4\n"));

    /* Wait for reset completion */
    for (msec = 0; msec < PHY_RESET_MSEC; msec++) {
        ioerr += READ_PMD_IEEE_CTL1r(pc, &pmd_ctl1);
        ioerr += READ_TOP_FW_VERr(pc, &fw_ver);
        if (PMD_IEEE_CTL1r_RESETf_GET(pmd_ctl1) == 0 &&
            TOP_FW_VERr_GET(fw_ver) != 0) {
            break;
        }
        PHY_SYS_USLEEP(1000);
    }
    if (msec >= PHY_RESET_MSEC || TOP_FW_VERr_GET(fw_ver) == 0) {
        PHY_WARN(pc, ("firmware probably not running.\n"));
    }

    /*
     * NOTE:
     * Do not reset the PHY after downloading f/w in a ROM-less environment
     * as the may force a download from the ROM which is not there.
     */

    /* Disable super isolate */
    ioerr += READ_SHDW_MII_CTRLr(pc, &shdw_mii_ctrl);
    SHDW_MII_CTRLr_SUPER_ISOLATEf_SET(shdw_mii_ctrl, 0);
    ioerr += WRITE_SHDW_MII_CTRLr(pc, shdw_mii_ctrl);

    ioerr += READ_TOP_FW_DATEr(pc, &fw_date);

    PHY_VERB(pc, ("firmware version = %"PRIu32".%"PRIu32".%"PRIu32" "
                  "(%"PRIu32"/%"PRIu32"/20%02"PRIu32")\n",
                  TOP_FW_VERr_MAINf_GET(fw_ver),
                  TOP_FW_VERr_BRANCHf_GET(fw_ver),
                  TOP_FW_VERr_CHIP_REVf_GET(fw_ver),
                  TOP_FW_DATEr_MONTHf_GET(fw_date),
                  TOP_FW_DATEr_DAYf_GET(fw_date),
                  TOP_FW_DATEr_YEARf_GET(fw_date)));

    /* Small delay required before firmware will accept MDIO commands */
    if (PHY_CTRL_FLAGS(pc) & PHY_F_BCAST_MSTR) {
        PHY_SYS_USLEEP(50000);
    }

    /* Set default MDI pair mapping */
    if (CDK_SUCCESS(rv)) {
        rv = _bcm84834_mdi_pair_set(pc, 0x3210);
    }

    /* Set default medium */
    if (CDK_SUCCESS(rv)) {
        PHY_NOTIFY(pc, PhyEvent_ChangeToCopper);
    }

    return ioerr ? CDK_E_IO : rv;
}

/*
 * Function:
 *      _bcm84834_init_stage
 * Purpose:
 *      Execute specified init stage.
 * Parameters:
 *      pc - PHY control structure
 *      stage - init stage
 * Returns:
 *      CDK_E_xxx
 */
static int
_bcm84834_init_stage(phy_ctrl_t *pc, int stage)
{
    switch (stage) {
    case 0:
        return _bcm84834_init_stage_0(pc);
    case 1:
        return _bcm84834_init_stage_1(pc);
    case 2:
        return _bcm84834_init_stage_2(pc);
    case 3:
        return _bcm84834_init_stage_3(pc);
    case 4:
        return _bcm84834_init_stage_4(pc);
    default:
        break;
    }
    return CDK_E_UNAVAIL;
}

/***********************************************************************
 *
 * PHY DRIVER FUNCTIONS
 *
 ***********************************************************************/

#if PHY_CONFIG_INCLUDE_CHIP_SYMBOLS == 1
extern cdk_symbols_t bcm84834_symbols;
#define SET_SYMBOL_TABLE(_pc) \
    PHY_CTRL_SYMBOLS(_pc) = &bcm84834_symbols
#else
#define SET_SYMBOL_TABLE(_pc)
#endif

#if PHY_CONFIG_MDIO_FAST_LOAD == 1
#define SET_FAST_LOAD(_pc) \
    PHY_CTRL_FLAGS(_pc) |= PHY_F_FAST_LOAD
#else
#define SET_FAST_LOAD(_pc)
#endif

/*
 * Function:
 *      bcm84834_phy_probe
 * Purpose:     
 *      Probe for 84834 PHY
 * Parameters:
 *      pc - PHY control structure
 * Returns:     
 *      CDK_E_xxx
 */
static int
bcm84834_phy_probe(phy_ctrl_t *pc)
{
    uint32_t phyid0, phyid1;
    int ioerr = 0;

    PHY_CTRL_CHECK(pc);

    ioerr += PHY_BUS_READ(pc, PMD_PHY_ID0_REG, &phyid0);
    ioerr += PHY_BUS_READ(pc, PMD_PHY_ID1_REG, &phyid1);

    if (ioerr) {
        return CDK_E_IO;
    }

    if ((phyid0 == BCM84834_PMD_PHY_ID0) &&
        ((phyid1 & ~0xf) == (BCM84834_PMD_PHY_ID1 & ~0xf))) {
        SET_SYMBOL_TABLE(pc);
        SET_FAST_LOAD(pc);
        return CDK_E_NONE;
    }

    return CDK_E_NOT_FOUND;
}

/*
 * Function:
 *      bcm84834_phy_notify
 * Purpose:     
 *      Handle PHY notifications
 * Parameters:
 *      pc - PHY control structure
 *      event - PHY event
 * Returns:     
 *      CDK_E_xxx
 */
static int
bcm84834_phy_notify(phy_ctrl_t *pc, phy_event_t event)
{
    int rv = CDK_E_NONE;

    PHY_CTRL_CHECK(pc);

    switch (event) {
    case PhyEvent_ChangeToCopper:
        /* Upstream PHY should operate in fiber mode */
        event = PhyEvent_ChangeToFiber;
        break;
    default:
        break;
    }

    /* Call up the PHY chain */
    if (CDK_SUCCESS(rv)) {
        rv = PHY_NOTIFY(PHY_CTRL_NEXT(pc), event);
    }

    return rv;
}

/*
 * Function:
 *      bcm84834_phy_reset
 * Purpose:     
 *      Reset 84834 PHY
 * Parameters:
 *      pc - PHY control structure
 * Returns:     
 *      CDK_E_xxx
 */
static int
bcm84834_phy_reset(phy_ctrl_t *pc)
{
    int ioerr = 0;
    int rv = CDK_E_NONE;
    COMBO_MII_CTRLr_t mii_ctrl;

    READ_COMBO_MII_CTRLr(pc, &mii_ctrl);
    COMBO_MII_CTRLr_RESETf_SET(mii_ctrl, 1);
    WRITE_COMBO_MII_CTRLr(pc, mii_ctrl);

    /* Call up the PHY chain */
    if (CDK_SUCCESS(rv)) {
        rv = PHY_RESET(PHY_CTRL_NEXT(pc));
    }

    return ioerr ? CDK_E_IO : CDK_E_NONE;
}

/*
 * Function:
 *      bcm84834_phy_init
 * Purpose:     
 *      Initialize 84834 PHY driver
 * Parameters:
 *      pc - PHY control structure
 * Returns:     
 *      CDK_E_xxx
 */
static int
bcm84834_phy_init(phy_ctrl_t *pc)
{
    int rv = CDK_E_NONE;
    int stage;

    PHY_CTRL_CHECK(pc);

    if (PHY_CTRL_FLAGS(pc) & PHY_F_STAGED_INIT) {
        PHY_CTRL_FLAGS(pc) &= ~PHY_F_STAGED_INIT;
    }

    for (stage = 0; CDK_SUCCESS(rv); stage++) {
        rv = _bcm84834_init_stage(pc, stage);
    }

    if (rv == CDK_E_UNAVAIL) {
        /* Successfully completed all stages */
        rv = CDK_E_NONE;
    }

    /* Call up the PHY chain */
    if (CDK_SUCCESS(rv)) {
        rv = PHY_INIT(PHY_CTRL_NEXT(pc));
    }

    return rv;
}

/*
 * Function:    
 *      bcm84834_phy_link_get
 * Purpose:     
 *      Determine the current link up/down status
 * Parameters:
 *      pc - PHY control structure
 *      link - (OUT) non-zero indicates link established.
 * Returns:
 *      CDK_E_xxx
 */
static int
bcm84834_phy_link_get(phy_ctrl_t *pc, int *link, int *autoneg_done)
{
    int ioerr = 0;
    COMBO_INTSTATr_t int_stat;
    TOP_LINK_STATUSr_t link_stat;
    COMBO_MII_STATr_t mii_stat;

    PHY_CTRL_CHECK(pc);

    *link = 0;

    ioerr += READ_COMBO_INTSTATr(pc, &int_stat);
    if (COMBO_INTSTATr_LINK_STATUS_CHANGEf_GET(int_stat) == 0) {
        ioerr += READ_TOP_LINK_STATUSr(pc, &link_stat);
        if (TOP_LINK_STATUSr_COPPER_LINKf_GET(link_stat)) {
            *link = 1;
        }
    }

    if (autoneg_done) {
        *autoneg_done = 0;
        ioerr += READ_COMBO_MII_STATr(pc, &mii_stat);
        if (COMBO_MII_STATr_AUTONEG_COMPLETEf_GET(mii_stat)) {
            *autoneg_done = 1;
        }
    }

    return ioerr ? CDK_E_IO : CDK_E_NONE;
}

/*
 * Function:    
 *      bcm84834_phy_duplex_set
 * Purpose:     
 *      Set the current duplex mode (forced).
 * Parameters:
 *      pc - PHY control structure
 *      duplex - non-zero indicates full duplex, zero indicates half
 * Returns:     
 *      CDK_E_xxx
 */
static int
bcm84834_phy_duplex_set(phy_ctrl_t *pc, int duplex)
{
    int ioerr = 0;
    COMBO_MII_CTRLr_t mii_ctrl;

    PHY_CTRL_CHECK(pc);

    ioerr += READ_COMBO_MII_CTRLr(pc, &mii_ctrl);
    COMBO_MII_CTRLr_DUPLEX_MODEf_SET(mii_ctrl, duplex ? 1 : 0);
    ioerr += WRITE_COMBO_MII_CTRLr(pc, mii_ctrl);

    return ioerr ? CDK_E_IO : CDK_E_NONE;
}

/*
 * Function:    
 *      bcm84834_phy_duplex_get
 * Purpose:     
 *      Get the current operating duplex mode. If autoneg is enabled, 
 *      then operating mode is returned, otherwise forced mode is returned.
 * Parameters:
 *      pc - PHY control structure
 *      duplex - (OUT) non-zero indicates full duplex, zero indicates half
 * Returns:     
 *      CDK_E_xxx
 */
static int
bcm84834_phy_duplex_get(phy_ctrl_t *pc, int *duplex)
{
    int ioerr = 0;
    int rv;
    COMBO_AUXSTATSUMMARYr_t combo_stat;
    AN_X10GBASET_AUTONEGCTRLr_t an_ctrl_10g;
    AN_X10GBASET_AUTONEGSTATr_t an_stat_10g;
    /* PMD_IEEE_CTL1r_t pmd_ctl1; */
    COMBO_MII_CTRLr_t mii_ctrl;
    int autoneg;

    PHY_CTRL_CHECK(pc);

    *duplex = 0;

    rv = PHY_AUTONEG_GET(pc, &autoneg);
    if (CDK_FAILURE(rv)) {
        return rv;
    }

    if (autoneg) {
        /* Get combo status */
        ioerr += READ_COMBO_AUXSTATSUMMARYr(pc, &combo_stat);
        if (COMBO_AUXSTATSUMMARYr_AUTONEG_COMPLETEf_GET(combo_stat) == 0) {
            return CDK_E_NONE;
        }

        /* Check 10G status first */
        ioerr += READ_AN_X10GBASET_AUTONEGCTRLr(pc, &an_ctrl_10g);
        ioerr += READ_AN_X10GBASET_AUTONEGSTATr(pc, &an_stat_10g);
        if (AN_X10GBASET_AUTONEGCTRLr_X10GBASE_T_ABILf_GET(an_ctrl_10g) &&
            AN_X10GBASET_AUTONEGSTATr_LP_10GBASE_T_CAPf_GET(an_stat_10g)) {
            *duplex = 1;
        } else {
            switch (COMBO_AUXSTATSUMMARYr_AUTONEG_HCDf_GET(combo_stat)) {
            case 7:
            case 5:
                *duplex = 1;
                break;
            default:
                break;
            }
        }
    } else {
        ioerr += READ_COMBO_MII_CTRLr(pc, &mii_ctrl);
        *duplex = COMBO_MII_CTRLr_DUPLEX_MODEf_GET(mii_ctrl) ? 1 : 0;
    }
    return ioerr ? CDK_E_IO : CDK_E_NONE;
}


/*
 * Function:    
 *      bcm84834_phy_speed_set
 * Purpose:     
 *      Set the current operating speed (forced).
 * Parameters:
 *      pc - PHY control structure
 *      speed - new link speed
 * Returns:     
 *      CDK_E_xxx
 */
static int
bcm84834_phy_speed_set(phy_ctrl_t *pc, uint32_t speed)
{
    int ioerr = 0;
    int rv;
    PMD_IEEE_CTL1r_t pmd_ctl1;
    COMBO_MII_CTRLr_t mii_ctrl;
    int sp_sel_0, sp_sel_1, lb;

    PHY_CTRL_CHECK(pc);

    sp_sel_0 = 0;
    sp_sel_1 = 0;
    switch (speed) {
    case 10000:
        sp_sel_0 = 1;
        sp_sel_1 = 1;
        break;
    case 1000:
        sp_sel_1 = 1;
        break;
    case 100:
        sp_sel_0 = 1;
        break;
    default:
        return CDK_E_PARAM;
    }

    /* Select interface (XFI/SGMII) on upstream PHY */
    if (speed == 10000) {
        ioerr += PHY_NOTIFY(PHY_CTRL_NEXT(pc), PhyEvent_ChangeToFiber);
    } else {
        ioerr += PHY_NOTIFY(PHY_CTRL_NEXT(pc), PhyEvent_ChangeToPassthru);
    }

    /* Call up the PHY chain */
    rv = PHY_SPEED_SET(PHY_CTRL_NEXT(pc), speed);
    if (CDK_FAILURE(rv)) {
        return rv;
    }

    /* Make sure loopback is turned off while changing speeds */
    rv = PHY_LOOPBACK_GET(pc, &lb);
    if (CDK_SUCCESS(rv) && lb) {
        rv = PHY_LOOPBACK_SET(pc, 0);
    }
    if (CDK_FAILURE(rv)) {
        return rv;
    }

    ioerr += READ_PMD_IEEE_CTL1r(pc, &pmd_ctl1);
    PMD_IEEE_CTL1r_SPEED_SEL_0f_SET(pmd_ctl1, sp_sel_0);
    PMD_IEEE_CTL1r_SPEED_SEL_1f_SET(pmd_ctl1, sp_sel_1);
    ioerr += WRITE_PMD_IEEE_CTL1r(pc, pmd_ctl1);

    ioerr += READ_COMBO_MII_CTRLr(pc, &mii_ctrl);
    COMBO_MII_CTRLr_SPEED_SELECT_LSBf_SET(mii_ctrl, sp_sel_0);
    COMBO_MII_CTRLr_SPEED_SELECT_MSBf_SET(mii_ctrl, sp_sel_1);
    ioerr += WRITE_COMBO_MII_CTRLr(pc, mii_ctrl);

    /* Restore loopback setting */
    if (CDK_SUCCESS(rv) && lb) {
        if (CDK_SUCCESS(rv)) {
            rv = PHY_LOOPBACK_SET(pc, 1);
        }
    }

    return ioerr ? CDK_E_IO : CDK_E_NONE;
}

/*
 * Function:    
 *      bcm84834_phy_speed_get
 * Purpose:     
 *      Get the current operating speed. If autoneg is enabled, 
 *      then operating mode is returned, otherwise forced mode is returned.
 * Parameters:
 *      pc - PHY control structure
 *      speed - (OUT) current link speed
 * Returns:     
 *      CDK_E_xxx
 */
static int
bcm84834_phy_speed_get(phy_ctrl_t *pc, uint32_t *speed)
{
    int ioerr = 0;
    int rv;
    COMBO_AUXSTATSUMMARYr_t combo_stat;
    AN_X10GBASET_AUTONEGCTRLr_t an_ctrl_10g;
    AN_X10GBASET_AUTONEGSTATr_t an_stat_10g;
    PMD_IEEE_CTL1r_t pmd_ctl1;
    int autoneg;

    PHY_CTRL_CHECK(pc);

    *speed = 0;

    rv = PHY_AUTONEG_GET(pc, &autoneg);
    if (CDK_FAILURE(rv)) {
        return rv;
    }

    if (autoneg) {
        /* Get combo status */
        ioerr += READ_COMBO_AUXSTATSUMMARYr(pc, &combo_stat);
        if (COMBO_AUXSTATSUMMARYr_AUTONEG_COMPLETEf_GET(combo_stat) == 0) {
            return CDK_E_NONE;
        }

        /* Check 10G status first */
        ioerr += READ_AN_X10GBASET_AUTONEGCTRLr(pc, &an_ctrl_10g);
        ioerr += READ_AN_X10GBASET_AUTONEGSTATr(pc, &an_stat_10g);
        if (AN_X10GBASET_AUTONEGCTRLr_X10GBASE_T_ABILf_GET(an_ctrl_10g) &&
            AN_X10GBASET_AUTONEGSTATr_LP_10GBASE_T_CAPf_GET(an_stat_10g)) {
            *speed = 10000;
        } else {
            switch (COMBO_AUXSTATSUMMARYr_AUTONEG_HCDf_GET(combo_stat)) {
            case 7:
            case 6:
                *speed = 1000;
                break;
            case 5:
            case 4:
            case 3:
                *speed = 100;
                break;
            default:
                break;
            }
        }
    } else {
        /* Return fixed speed */
        ioerr += READ_PMD_IEEE_CTL1r(pc, &pmd_ctl1);
        if (PMD_IEEE_CTL1r_SPEED_SEL_0f_GET(pmd_ctl1)) {
            if (PMD_IEEE_CTL1r_SPEED_SEL_1f_GET(pmd_ctl1)) {
                *speed = 10000;
            } else {
                *speed = 100;
            }
        } else if (PMD_IEEE_CTL1r_SPEED_SEL_1f_GET(pmd_ctl1)) {
            *speed = 1000;
        }
    }

    return ioerr ? CDK_E_IO : CDK_E_NONE;
}

/*
 * Function:    
 *      bcm84834_phy_autoneg_set
 * Purpose:     
 *      Enable or disable auto-negotiation on the specified port.
 * Parameters:
 *      pc - PHY control structure
 *      autoneg - non-zero enables autoneg, zero disables autoneg
 * Returns:     
 *      CDK_E_xxx
 */
static int
bcm84834_phy_autoneg_set(phy_ctrl_t *pc, int autoneg)
{
    int ioerr = 0;
    int rv;
    COMBO_MII_CTRLr_t mii_ctrl;
    AN_AUTONEGCTRLr_t an_ctl;

    PHY_CTRL_CHECK(pc);

    if (autoneg) {
        /* Used as field value, so cannot be any non-zero value */
        autoneg = 1;
    }

    ioerr += READ_COMBO_MII_CTRLr(pc, &mii_ctrl);
    COMBO_MII_CTRLr_AUTONEG_ENABLEf_SET(mii_ctrl, autoneg);
    COMBO_MII_CTRLr_RESTART_AUTONEGf_SET(mii_ctrl, autoneg);
    ioerr += WRITE_COMBO_MII_CTRLr(pc, mii_ctrl);

    ioerr += READ_AN_AUTONEGCTRLr(pc, &an_ctl);
    AN_AUTONEGCTRLr_AN_ENABLEf_SET(an_ctl, autoneg);
    AN_AUTONEGCTRLr_RESTART_ANf_SET(an_ctl, autoneg);
    ioerr += WRITE_AN_AUTONEGCTRLr(pc, an_ctl);

    /* Disable autoneg in upstream PHY */
    rv = PHY_AUTONEG_SET(PHY_CTRL_NEXT(pc), 0);

    return ioerr ? rv : CDK_E_NONE;
}

/*
 * Function:    
 *      bcm84834_phy_autoneg_get
 * Purpose:     
 *      Get the current auto-negotiation setting.
 * Parameters:
 *      pc - PHY control structure
 *      autoneg - (OUT) non-zero indicates autoneg enabled
 * Returns:     
 *      CDK_E_xxx
 */
static int
bcm84834_phy_autoneg_get(phy_ctrl_t *pc, int *autoneg)
{
    int ioerr = 0;
    COMBO_MII_CTRLr_t mii_ctrl;

    PHY_CTRL_CHECK(pc);

    ioerr += READ_COMBO_MII_CTRLr(pc, &mii_ctrl);
    *autoneg = COMBO_MII_CTRLr_AUTONEG_ENABLEf_GET(mii_ctrl);

    return ioerr ? CDK_E_IO : CDK_E_NONE;
}

/*
 * Function:    
 *      bcm84834_phy_loopback_set
 * Purpose:     
 *      Set the internal PHY loopback mode.
 * Parameters:
 *      pc - PHY control structure
 *      enable - non-zero enables PHY loopback
 * Returns:     
 *      CDK_E_xxx
 */
static int
bcm84834_phy_loopback_set(phy_ctrl_t *pc, int enable)
{
    int ioerr = 0;
    int rv = CDK_E_NONE;
    PMD_IEEE_CTL1r_t pmd_ctl1;
    COMBO_MII_CTRLr_t mii_ctrl;
    PCS_IEEE_CTL1r_t pcs_ctl1;
    int sp_sel_0, sp_sel_1, pcs_lb, combo_lb;

    PHY_CTRL_CHECK(pc);

    if (enable) {
        /* Used as field value, so cannot be any non-zero value */
        enable = 1;
    }

    ioerr += READ_PMD_IEEE_CTL1r(pc, &pmd_ctl1);
    sp_sel_0 = PMD_IEEE_CTL1r_SPEED_SEL_0f_GET(pmd_ctl1);
    sp_sel_1 = PMD_IEEE_CTL1r_SPEED_SEL_1f_GET(pmd_ctl1);

    pcs_lb = 0;
    combo_lb = 0;
    if (sp_sel_0 && sp_sel_1) {
        pcs_lb = enable;
    } else {
        combo_lb = enable;
    }

    /* Force link down event in firmware */
    if (enable) {
        rv = _bcm84834_force_link_down(pc);
    }

    ioerr += READ_COMBO_MII_CTRLr(pc, &mii_ctrl);
    COMBO_MII_CTRLr_LOOPBACKf_SET(mii_ctrl, combo_lb);
    ioerr += WRITE_COMBO_MII_CTRLr(pc, mii_ctrl);

    ioerr += READ_PCS_IEEE_CTL1r(pc, &pcs_ctl1);
    PCS_IEEE_CTL1r_PCS_LPBKf_SET(pcs_ctl1, pcs_lb);
    ioerr += WRITE_PCS_IEEE_CTL1r(pc, pcs_ctl1);

    /* Force link down event in firmware */
    if (enable) {
        rv = _bcm84834_force_link_down(pc);
    }

    return ioerr ? CDK_E_IO : rv;
}

/*
 * Function:    
 *      bcm84834_phy_loopback_get
 * Purpose:     
 *      Get the local PHY loopback mode.
 * Parameters:
 *      pc - PHY control structure
 *      enable - (OUT) non-zero indicates PHY loopback enabled
 * Returns:     
 *      CDK_E_xxx
 */
static int
bcm84834_phy_loopback_get(phy_ctrl_t *pc, int *enable)
{
    int ioerr = 0;
    COMBO_MII_CTRLr_t mii_ctrl;
    PCS_IEEE_CTL1r_t pcs_ctl1;

    PHY_CTRL_CHECK(pc);

    ioerr += READ_COMBO_MII_CTRLr(pc, &mii_ctrl);
    *enable = COMBO_MII_CTRLr_LOOPBACKf_GET(mii_ctrl);

    if (*enable == 0) {
        ioerr += READ_PCS_IEEE_CTL1r(pc, &pcs_ctl1);
        *enable = PCS_IEEE_CTL1r_PCS_LPBKf_GET(pcs_ctl1);
    }

    return ioerr ? CDK_E_IO : CDK_E_NONE;
}

/*
 * Function:    
 *      bcm84834_phy_ability_get
 * Purpose:     
 *      Get the abilities of the PHY.
 * Parameters:
 *      pc - PHY control structure
 *      abil - (OUT) ability mask indicating supported options/speeds.
 * Returns:     
 *      CDK_E_xxx
 */
static int
bcm84834_phy_ability_get(phy_ctrl_t *pc, uint32_t *abil)
{
    PHY_CTRL_CHECK(pc);

    *abil = (PHY_ABIL_10GB | PHY_ABIL_1000MB_FD |
             PHY_ABIL_100MB_FD | PHY_ABIL_100MB_HD |
             PHY_ABIL_LOOPBACK); 

    return CDK_E_NONE;
}

/*
 * Function:
 *      bcm84834_phy_config_set
 * Purpose:
 *      Modify PHY configuration value.
 * Parameters:
 *      pc - PHY control structure
 *      cfg - Configuration parameter
 *      val - Configuration value
 *      cd - Additional configuration data (if any)
 * Returns:
 *      CDK_E_xxx
 */
static int
bcm84834_phy_config_set(phy_ctrl_t *pc, phy_config_t cfg, uint32_t val, void *cd)
{
    PHY_CTRL_CHECK(pc);

    switch (cfg) {
    case PhyConfig_Enable:
        return CDK_E_NONE;
    case PhyConfig_PortInterface:
        switch (val) {
        case PHY_IF_XFI:
            return CDK_E_NONE;
        default:
            break;
        }
        break;
    case PhyConfig_Mode:
        if (val == 0) {
            return CDK_E_NONE;
        }
        break;
    case PhyConfig_InitStage:
        if (PHY_CTRL_FLAGS(pc) & PHY_F_STAGED_INIT) {
            return _bcm84834_init_stage(pc, val);
        }
        break;
    case PhyConfig_MdiPairRemap:
        if (val) {
            return _bcm84834_mdi_pair_set(pc, val);
        }
        return CDK_E_PARAM;
    default:
        break;
    }

    return CDK_E_UNAVAIL;
}

/*
 * Function:
 *      bcm84834_phy_config_get
 * Purpose:
 *      Get PHY configuration value.
 * Parameters:
 *      pc - PHY control structure
 *      cfg - Configuration parameter
 *      val - (OUT) Configuration value
 *      cd - (OUT) Additional configuration data (if any)
 * Returns:
 *      CDK_E_xxx
 */
static int
bcm84834_phy_config_get(phy_ctrl_t *pc, phy_config_t cfg, uint32_t *val, void *cd)
{
    PHY_CTRL_CHECK(pc);

    switch (cfg) {
    case PhyConfig_Enable:
        *val = 1;
        return CDK_E_NONE;
    case PhyConfig_PortInterface:
        *val = PHY_IF_KR;
        return CDK_E_NONE;
    case PhyConfig_Mode:
        *val = PHY_MODE_LAN;
        return CDK_E_NONE;
    case PhyConfig_Clause45Devs:
        *val = 0x4000009a;
        return CDK_E_NONE;
    case PhyConfig_BcastAddr:
        *val = PHY_CTRL_BUS_ADDR(pc) & ~0x1f;
        return CDK_E_NONE;
    default:
        break;
    }

    return CDK_E_UNAVAIL;
}

/*
 * Variable:    bcm84834_drv
 * Purpose:     PHY Driver for BCM84834.
 */
phy_driver_t bcm84834_drv = {
    "bcm84834",
    "BCM84834 10-Gigabit PHY Driver",  
    0,
    bcm84834_phy_probe,                  /* pd_probe */
    bcm84834_phy_notify,                 /* pd_notify */
    bcm84834_phy_reset,                  /* pd_reset */
    bcm84834_phy_init,                   /* pd_init */
    bcm84834_phy_link_get,               /* pd_link_get */
    bcm84834_phy_duplex_set,             /* pd_duplex_set */
    bcm84834_phy_duplex_get,             /* pd_duplex_get */
    bcm84834_phy_speed_set,              /* pd_speed_set */
    bcm84834_phy_speed_get,              /* pd_speed_get */
    bcm84834_phy_autoneg_set,            /* pd_autoneg_set */
    bcm84834_phy_autoneg_get,            /* pd_autoneg_get */
    bcm84834_phy_loopback_set,           /* pd_loopback_set */
    bcm84834_phy_loopback_get,           /* pd_loopback_get */
    bcm84834_phy_ability_get,            /* pd_ability_get */
    bcm84834_phy_config_set,             /* pd_config_set */
    bcm84834_phy_config_get,             /* pd_config_get */
    NULL,                                /* pd_status_get */
    NULL                                 /* pd_cable_diag */
};
