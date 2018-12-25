/*
 * $Id: bcmi_warpcore3_xgxs_firmware_set.c,v 1.4 Broadcom SDK $
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
 * Warpcore firmware download support.
 *
 */

#include <phy/phy.h>

#include <phy/chip/bcmi_warpcore_xgxs_defs.h>
#include <phy/chip/bcmi_warpcore3_xgxs_firmware_set.h>

#ifndef WARPCORE3_CRC_DISABLE
#define WARPCORE3_CRC_DISABLE           0
#endif

#define DOWNLOAD_INIT_MSEC              200
#define CRC_CALC_MSEC                   100

#define FW_ALIGN_BYTES                  16
#define FW_ALIGN_MASK                   (FW_ALIGN_BYTES - 1)

/* Low level debugging (off by default) */
#ifdef BCM_WC_DEBUG_ENABLE
#define BCM_WC_DBG(_p) \
    CDK_WARN(_p)
#else
#define BCM_WC_DBG(_p)
#endif

/*
 * Function:
 *      bcmi_warpcore3_xgxs_firmware_set
 * Purpose:
 *      Download firmware to warpcore
 * Parameters:
 *      pc - PHY control structure
 *      fw_size - size of firmware byte array
 *      fw_data - firmware byte array
 * Returns:
 *      CDK_E_NONE if successful.
 */
int
bcmi_warpcore3_xgxs_firmware_set(phy_ctrl_t *pc, uint32_t offset,
                                 uint32_t fw_size, uint8_t *fw_data)
{
    int ioerr = 0;
    int rv = CDK_E_NONE;
    RAMWORDr_t ram_word;
    ADDRESSr_t addr;
    COMMANDr_t cmd;
    COMMAND2r_t cmd2;
    COMMAND3r_t cmd3;
    WRDATAr_t wr_data;
    DOWNLOAD_STATUSr_t dl_stat;
    CRCr_t crc;
    uint32_t cnt, idx, data;

    /* Just to be safe */
    if (fw_data == NULL) {
        return CDK_E_INTERNAL;
    }

    /* Initialize the RAM */
    COMMANDr_CLR(cmd);
    COMMANDr_INIT_CMDf_SET(cmd, 1);
    ioerr += WRITE_COMMANDr(pc, cmd);

    for (cnt = 0; cnt < DOWNLOAD_INIT_MSEC; cnt++) {
        ioerr += READ_DOWNLOAD_STATUSr(pc, &dl_stat);
        if (ioerr) {
            return CDK_E_IO;
        }
        if (DOWNLOAD_STATUSr_INIT_DONEf_GET(dl_stat)) {
            break;
        }
        PHY_SYS_USLEEP(1000);
    }
    if (DOWNLOAD_STATUSr_INIT_DONEf_GET(dl_stat) == 0) {
        PHY_WARN(pc, ("RAM init timeout\n"));
        return CDK_E_TIMEOUT;
    }

    /* Enable uC timers */
    ioerr += READ_COMMAND2r(pc, &cmd2);
    COMMAND2r_TMR_ENf_SET(cmd2, 0xf);
    ioerr += WRITE_COMMAND2r(pc, cmd2);

    /* Transfer size must be aligned */
    cnt = (fw_size + FW_ALIGN_MASK) & ~FW_ALIGN_MASK;
    RAMWORDr_SET(ram_word, cnt - 1);
    ioerr += WRITE_RAMWORDr(pc, ram_word);

    /* Starting RAM location */
    ADDRESSr_SET(addr, offset);
    ioerr += WRITE_ADDRESSr(pc, addr);

    /* Check for external loader */
    if (PHY_CTRL_FW_HELPER(pc)) {

        /* Allow external access to warpcore uC memory */
        ioerr += READ_COMMAND3r(pc, &cmd3);
        COMMAND3r_EXT_MEM_ENABLEf_SET(cmd3, 1);
        ioerr += WRITE_COMMAND3r(pc, cmd3);
        PHY_SYS_USLEEP(1000);
        COMMAND3r_EXT_CLK_ENABLEf_SET(cmd3, 1);
        ioerr += WRITE_COMMAND3r(pc, cmd3);
        PHY_SYS_USLEEP(1000);

        /* Invoke external loader */
        rv = PHY_CTRL_FW_HELPER(pc)(pc, 0, fw_size, fw_data);

        /* Disable external access to warpcore uC memory */
        ioerr += READ_COMMAND3r(pc, &cmd3);
        COMMAND3r_EXT_MEM_ENABLEf_SET(cmd3, 0);
        ioerr += WRITE_COMMAND3r(pc, cmd3);
        PHY_SYS_USLEEP(1000);
        COMMAND3r_EXT_CLK_ENABLEf_SET(cmd3, 0);
        ioerr += WRITE_COMMAND3r(pc, cmd3);
        PHY_SYS_USLEEP(1000);

    } else {

        /* Start write operation */
        COMMANDr_CLR(cmd);
        COMMANDr_WRITEf_SET(cmd, 1);
        COMMANDr_RUNf_SET(cmd, 1);
        ioerr += WRITE_COMMANDr(pc, cmd);

        /* Write 16-bit words to data register */
        PHY_VERB(pc, ("downloading %"PRIu32" bytes via MDIO\n", cnt));
        for (idx = 0; idx < cnt; idx++) {
            data = 0;
            if (idx < fw_size) {
                data |= fw_data[idx];
            }
            idx++;
            if (idx < fw_size) {
                data |= (fw_data[idx] << 8);
            }
            WRDATAr_SET(wr_data, data);
            ioerr += WRITE_WRDATAr(pc, wr_data);
        }

        /* Complete the write operation */
        COMMANDr_CLR(cmd);
        COMMANDr_STOPf_SET(cmd, 1);
        ioerr += WRITE_COMMANDr(pc, cmd);
    }

    ioerr += READ_DOWNLOAD_STATUSr(pc, &dl_stat);
    if (ioerr) {
        return CDK_E_IO;
    }
    if (DOWNLOAD_STATUSr_ERR0f_GET(dl_stat) != 0 ||
        DOWNLOAD_STATUSr_ERR1f_GET(dl_stat) != 0) {
        return CDK_E_FAIL;
    }

    /* Non-zero value disables CRC calculation */
    CRCr_SET(crc, WARPCORE3_CRC_DISABLE);
    ioerr += WRITE_CRCr(pc, crc);

    /* Start uC */
    COMMANDr_CLR(cmd);
    COMMANDr_MDIO_UC_RESET_Nf_SET(cmd, 1);
    ioerr += WRITE_COMMANDr(pc, cmd);

    return ioerr ? CDK_E_IO : rv;
}

/*
 * Function:
 *      bcmi_warpcore3_xgxs_firmware_check
 * Purpose:
 *      Start running downloaded firmware
 * Parameters:
 *      pc - PHY control structure
 * Returns:
 *      CDK_E_NONE if successful.
 */
int
bcmi_warpcore3_xgxs_firmware_check(phy_ctrl_t *pc)
{
    int ioerr = 0;
    VERSIONr_t vers;
#if (WARPCORE3_CRC_DISABLE == 0)
    CRCr_t crc;
    int cnt;

    for (cnt = 0; cnt < CRC_CALC_MSEC; cnt++) {
        ioerr += READ_CRCr(pc, &crc);
        if (ioerr) {
            return CDK_E_IO;
        }
        if (CRCr_GET(crc) != 0) {
            break;
        }
        PHY_SYS_USLEEP(1000);
    }
    if (CRCr_GET(crc) == 0) {
        PHY_WARN(pc, ("CRC timeout\n"));
        return CDK_E_TIMEOUT;
    }
    PHY_VERB(pc, ("firmware CRC = 0x%04"PRIx32"\n", CRCr_GET(crc)));
#endif
    ioerr += READ_VERSIONr(pc, &vers);
    PHY_VERB(pc, ("firmware version = 0x%04"PRIx32"\n", VERSIONr_GET(vers)));

    return ioerr ? CDK_E_IO : CDK_E_NONE;
}
