/*
 * $Id: bcm84740_drv.c,v 1.15 Broadcom SDK $
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
 * PHY driver for BCM84740.
 *
 */

#include <phy/phy.h>
#include <phy/ge_phy.h>
#include <cdk/cdk_device.h>

#define PHY_RESET_POLL_MAX              10
#define PHY_ROM_LOAD_POLL_MAX           500
#define PHY_LANES_POLL_MAX              1000
#define PHY_DOWNLOAD_MSEC               200

#define BCM84740_PMA_PMD_ID0             0x0362
#define BCM84740_PMA_PMD_ID1             0x5fd0
#define BCM84740_CHIP_ID                 0x84740

#define C45_DEVAD(_a)                   LSHIFT32((_a),16)
#define DEVAD_PMA_PMD                   C45_DEVAD(MII_C45_DEV_PMA_PMD)
#define DEVAD_PCS                       C45_DEVAD(MII_C45_DEV_PCS)
#define DEVAD_PHY_XS                    C45_DEVAD(MII_C45_DEV_PHY_XS)
#define DEVAD_AN                        C45_DEVAD(MII_C45_DEV_AN)

/* PMA/PMD registers */
#define PMA_PMD_CTRL_REG                (DEVAD_PMA_PMD + MII_CTRL_REG)
#define PMA_PMD_STAT_REG                (DEVAD_PMA_PMD + MII_STAT_REG)
#define PMA_PMD_ID0_REG                 (DEVAD_PMA_PMD + MII_PHY_ID0_REG)
#define PMA_PMD_ID1_REG                 (DEVAD_PMA_PMD + MII_PHY_ID1_REG)
#define PMA_PMD_SPEED_ABIL              (DEVAD_PMA_PMD + 0x0005)
#define PMA_PMD_DEV_IN_PKG              (DEVAD_PMA_PMD + 0x0006)
#define PMA_PMD_CTRL2_REG               (DEVAD_PMA_PMD + 0x0007)
#define PMA_PMD_STAT2_REG               (DEVAD_PMA_PMD + 0x0008)

#define SPEED_LINK_DETECT_STAT_REG      (DEVAD_PMA_PMD + 0xc820)
#define PMA_PMD_BCST_REG                (DEVAD_PMA_PMD + 0xc8fe)
#define PMA_PMD_CHIP_MODE_REG           (DEVAD_PMA_PMD + 0xc805)
#define PMA_PMD_SPI_CTRL_REG            (DEVAD_PMA_PMD + 0xc848)
#define PMA_PMD_MISC_CTRL1_REG          (DEVAD_PMA_PMD + 0xca85)
#define PMA_PMD_M8051_MSGIN_REG         (DEVAD_PMA_PMD + 0xca12)
#define PMA_PMD_M8051_MSGOUT_REG        (DEVAD_PMA_PMD + 0xca13)
#define PMA_PMD_AER_ADDR_REG            (DEVAD_PMA_PMD + 0xc702)

#define PMA_PMD_GEN_CTRL_STAT_REG       (DEVAD_PMA_PMD + 0xca10)
#define PMA_PMD_GEN_REG_0               (DEVAD_PMA_PMD + 0xca18)
#define PMA_PMD_GEN_REG_1               (DEVAD_PMA_PMD + 0xca19)
#define PMA_PMD_GEN_REG_2               (DEVAD_PMA_PMD + 0xca1a)
#define PMA_PMD_GEN_REG_3               (DEVAD_PMA_PMD + 0xca1b)
#define PMA_PMD_GEN_REG_4               (DEVAD_PMA_PMD + 0xca1c)
#define PMA_PMD_CE00_REG                (DEVAD_PMA_PMD + 0xce00)

#define PMA_PMD_MISC2_REG               (DEVAD_PMA_PMD + 0x8309)
#define PMA_PMD_CD17_REG                (DEVAD_PMA_PMD + 0xcd17)
#define PMA_PMD_0096_REG                (DEVAD_PMA_PMD + 0x0096)
#define PMA_PMD_CD53_REG                (DEVAD_PMA_PMD + 0xcd53)
#define PMA_PMD_C806_REG                (DEVAD_PMA_PMD + 0xc806)
#define PMA_PMD_C8E4_REG                (DEVAD_PMA_PMD + 0xc8e4)

#define PMA_PMD_FFFF_REG                (DEVAD_PMA_PMD + 0xffff)

#define PMA_PMD_CHIP_MODE_MASK          0x3
#define PMA_PMD_DAC_MODE_MASK           0x8
#define PMA_PMD_DAC_MODE                0x8
#define PMA_PMD_MODE_40G                0x1

/* PCS registers */
#define PCS_CTRL_REG                    (DEVAD_PCS + MII_CTRL_REG)
#define PCS_STAT_REG                    (DEVAD_PCS + MII_STAT_REG)
#define PCS_ID0_REG                     (DEVAD_PCS + MII_PHY_ID0_REG)
#define PCS_ID1_REG                     (DEVAD_PCS + MII_PHY_ID1_REG)
#define PCS_SPEED_ABIL                  (DEVAD_PCS + 0x0005)
#define PCS_DEV_IN_PKG                  (DEVAD_PCS + 0x0006)
#define PCS_CTRL2_REG                   (DEVAD_PCS + 0x0007)
#define PCS_STAT2_REG                   (DEVAD_PCS + 0x0008)

/* AN registers */
#define AN_CTRL_REG                     (DEVAD_AN + MII_CTRL_REG)
#define AN_STAT_REG                     (DEVAD_AN + MII_STAT_REG)
#define AN_MII_CTRL_REG                 (DEVAD_AN + 0xFFE0)
#define AN_MII_STAT_REG                 (DEVAD_AN + 0xFFE1)
#define AN_8309_REG                     (DEVAD_AN + 0x8309)



/* PMA/PMD Standard registers definations */
/* Control Register */
#define MII_CTRL_PMA_LOOPBACK      (1 << 0)

/* PMA/PMD User define registers  definations */
/* Speed Link Detect status register definations */
#define    AN_1G_MODE                0x0021

/* AN registers definations */
/* AN Status Register definations */
#define    AN_STAT_LA                0x0004

#define PMA_PMD_CTRL_SPEED_10G          (1L << 13)

#define PMA_PMD_CTRL2_PMA_TYPE_MASK    0xF
#define PMA_PMD_CTRL2_PMA_TYPE_1G_KX   0xD
#define PMA_PMD_CTRL2_PMA_TYPE_10G_KR  0xB
#define PMA_PMD_CTRL2_PMA_TYPE_10G_LRM 0x8
 
/* CL73 autoneg control register */

#define AN_EXT_NXT_PAGE    (1 << 13)
#define AN_ENABLE          (1 << 12)
#define AN_RESTART         (1 << 9)

/* autoneg status register */

#define AN_STATUS_REG      1
#define AN_LP_AN_ABILITY   (1 << 0)
#define AN_LINK            (1 << 2)
#define AN_DONE            (1 << 5)

/* autoneg advertisement register 0 */ 
#define AN_ADVERT_0_REG        0x10
#define AN_ADVERT_PAUSE        (1 << 10)
#define AN_ADVERT_PAUSE_ASYM   (1 << 11)

/* autoneg advertisement register 1 */

#define AN_ADVERT_1_REG        0x11
#define AN_ADVERT_10G          (1 << 7)
#define AN_ADVERT_1G           (1 << 5)

/* autoneg advertisement register 2 */

#define AN_ADVERT_2_REG        0x12
#define AN_ADVERT_FEC          (1 << 15)

/* Link Partner base ability page 0 */

#define AN_LP_ABILITY_0_REG    0x13

/* Link Partner base ability page 1 */

#define AN_LP_ABILITY_1_REG    0x14

/* Link Partner base ability page 2 */

#define AN_LP_ABILITY_2_REG    0x15

/* autoneg control register */
#define AN_EXT_NXT_PAGE    (1 << 13)
#define AN_ENABLE          (1 << 12) 
#define AN_RESTART         (1 << 9)
                                                                               
/* autoneg status register */
#define AN_STATUS_REG      1
#define AN_LINK            (1 << 2)
#define AN_DONE            (1 << 5)
                                                                               
/* 1G status register for both autoneg mode and forced mode */
#define AN_1G_STATUS_REG       0x8304
#define AN_1G_LINKUP           0x2
#define AN_1G_LINK_CHANGE      0x80

#define MEDIUM_TYPE_SR4_LR4   0x0
#define MEDIUM_TYPE_CR4       0x1
#define AN_ADVERT_40GCR4 (1 << 9)

#define RXLOS_OVERRIDE_ENABLE

#define PHY84740_SINGLE_PORT_MODE(_pc)  (CDK_PORT_CONFIG_SPEED_MAX(PHY_CTRL_UNIT(_pc), \
        PHY_CTRL_PORT(_pc)) == 40000)

#define PHY84740_SR4_LR4_TYPE(_pc)  ((_pc)->phy_mode == MEDIUM_TYPE_SR4_LR4)
#define PHY84740_MEDIUM_TYPE_SET(_pc,_type)  ((_pc)->phy_mode = (_type))

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
_bcm84740_single_to_quad_mode(phy_ctrl_t *pc)
{
    int      ioerr = 0;
    int      i;
    int      orig_inst;
    uint32_t temp32;

    /* clear DAC mode first. This register is bcst register in single port mode */
    ioerr += PHY_BUS_READ(pc, PMA_PMD_CHIP_MODE_REG, &temp32);
    temp32 &= ~PMA_PMD_DAC_MODE_MASK;
    ioerr += PHY_BUS_WRITE(pc, PMA_PMD_CHIP_MODE_REG, temp32);

    /* then configure quad chip mode */
    ioerr += PHY_BUS_READ(pc, PMA_PMD_CHIP_MODE_REG, &temp32);
    temp32 &= ~PMA_PMD_CHIP_MODE_MASK;
    ioerr += PHY_BUS_WRITE(pc, PMA_PMD_CHIP_MODE_REG, temp32);

    orig_inst = PHY_CTRL_PHY_INST(pc);

    for (i = 0; i < 4; i++) {
        if (phy_ctrl_change_inst(pc, orig_inst + i, NULL) < 0) {
            return CDK_E_FAIL;
        }

        /* Reset all 4 lanes. Only after reset, the mode is actually switched */
        ioerr += PHY_BUS_WRITE(pc, PMA_PMD_BCST_REG, 0xffff);
    }
    if (phy_ctrl_change_inst(pc, orig_inst, NULL) < 0) {
        return CDK_E_FAIL;
    }

    return ioerr ? CDK_E_IO : CDK_E_NONE;
}

static int
_bcm84740_quad_to_single_mode(phy_ctrl_t *pc)
{
    int      ioerr = 0;
    int      i;
    int      orig_inst;
    uint32_t temp32;

    orig_inst = PHY_CTRL_PHY_INST(pc);

    for (i = 0; i < 4; i++) {
        if (phy_ctrl_change_inst(pc, orig_inst + i, NULL) < 0) {
            return CDK_E_FAIL;
        }

        ioerr += PHY_BUS_WRITE(pc, PMA_PMD_BCST_REG, 0xffff);
    }
    if (phy_ctrl_change_inst(pc, orig_inst, NULL) < 0) {
        return CDK_E_FAIL;
    }

    /* then configure single mode */
    ioerr += PHY_BUS_READ(pc, PMA_PMD_CHIP_MODE_REG, &temp32);
    temp32 &= ~PMA_PMD_CHIP_MODE_MASK;
    temp32 |= PMA_PMD_MODE_40G;
    ioerr += PHY_BUS_WRITE(pc, PMA_PMD_CHIP_MODE_REG, temp32);

    /* configure DAC mode for LR4/SR4 */
    ioerr += PHY_BUS_READ(pc, PMA_PMD_CHIP_MODE_REG, &temp32);
    temp32 &= ~PMA_PMD_DAC_MODE_MASK;
    ioerr += PHY_BUS_WRITE(pc, PMA_PMD_CHIP_MODE_REG, temp32);

    /* BCM84740_MEDIUM_TYPE_SET(pc,MEDIUM_TYPE_SR4_LR4); */

    /* do a soft reset to switch to the configured mode
     * The reset should also clear the bcst register configuration
     */
    ioerr += PHY_BUS_WRITE(pc, PMA_PMD_CTRL_REG, MII_CTRL_RESET);

    return ioerr ? CDK_E_IO : CDK_E_NONE;
}

static int
_bcm84740_rom_firmware_download(phy_ctrl_t *pc)
{
    int ioerr = 0;
    int lane;
    uint32_t temp32;

    if (PHY84740_SINGLE_PORT_MODE(pc)) {
        for (lane = 3; lane >= 0; lane--) {
            ioerr += PHY_BUS_WRITE(pc, PMA_PMD_AER_ADDR_REG, lane);

            /* 0xca85[3]=1, 32K download */
            ioerr += PHY_BUS_READ(pc, PMA_PMD_MISC_CTRL1_REG, &temp32);
            temp32 |= (1 << 3);
            ioerr += PHY_BUS_WRITE(pc, PMA_PMD_MISC_CTRL1_REG, temp32);

            /* Clear message out register */
            ioerr += PHY_BUS_WRITE(pc, PMA_PMD_M8051_MSGOUT_REG, 0);
        }

        /* 0xc848[15]=1, SPI-ROM downloading to RAM, 0xc848[14]=1, serial boot */
        /* 0xc848[13]=0, SPI-ROM downloading not done, 0xc848[2]=0, spi port enable */

        ioerr += PHY_BUS_READ(pc, PMA_PMD_SPI_CTRL_REG, &temp32);
        temp32 |= (1 << 15) | (1 << 14);
        ioerr += PHY_BUS_WRITE(pc, PMA_PMD_SPI_CTRL_REG, temp32);

        ioerr += PHY_BUS_READ(pc, PMA_PMD_SPI_CTRL_REG, &temp32);
        temp32 &= ~((1 << 13) | (1 << 2));
        ioerr += PHY_BUS_WRITE(pc, PMA_PMD_SPI_CTRL_REG, temp32);

    } else { /* single lane */
        /* 0xca85[3]=1, 32K download */
        ioerr += PHY_BUS_READ(pc, PMA_PMD_MISC_CTRL1_REG, &temp32);
        temp32 |= (1 << 3);
        ioerr += PHY_BUS_WRITE(pc, PMA_PMD_MISC_CTRL1_REG, temp32);

        /* 0xc848[15]=1, SPI-ROM downloading to RAM, 0xc848[14]=1, serial boot */
        /* 0xc848[13]=0, SPI-ROM downloading not done, 0xc848[2]=0, spi port enable */

        ioerr += PHY_BUS_READ(pc, PMA_PMD_SPI_CTRL_REG, &temp32);
        temp32 |= (1 << 15) | (1 << 14);
        temp32 &= ~((1 << 13) | (1 << 2));
        ioerr += PHY_BUS_WRITE(pc, PMA_PMD_SPI_CTRL_REG, temp32);

        /* Clear message out register */
        ioerr += PHY_BUS_WRITE(pc, PMA_PMD_M8051_MSGOUT_REG, 0);
    }

    /* Apply software reset to download code from SPI-ROM */
    ioerr += PHY_BUS_WRITE(pc, PMA_PMD_CTRL_REG, MII_CTRL_RESET);

    return ioerr ? CDK_E_IO : CDK_E_NONE;
}

static int
_bcm84740_rom_firmware_wait(phy_ctrl_t *pc)
{
    int ioerr = 0;
    int lane;
    int cnt;
    uint32_t temp32;

    for (lane = 3; lane >= 0; lane--) {

        if (PHY84740_SINGLE_PORT_MODE(pc)) {
            ioerr += PHY_BUS_WRITE(pc, PMA_PMD_AER_ADDR_REG, lane);
        }

        for (cnt = 0; cnt < PHY_DOWNLOAD_MSEC; cnt++) {
            ioerr += PHY_BUS_READ(pc, PMA_PMD_M8051_MSGOUT_REG, &temp32);
            if (temp32 != 0) {
                break;
            }
            PHY_SYS_USLEEP(1000);
        }
        if (cnt >= PHY_DOWNLOAD_MSEC) {
            PHY_WARN(pc, ("download timeout\n"));
        }

        _PHY_DBG(pc, ("SPI-ROM download done msg 0x%"PRIx32"\n", temp32));

        if (!PHY84740_SINGLE_PORT_MODE(pc)) {
            break;
        }
    }
    return ioerr ? CDK_E_IO : CDK_E_NONE;
}

/*
 * Function:
 *      _bcm84740_init_stage_0
 * Purpose:
 *      PHY init.
 * Parameters:
 *      pc - PHY control structure
 * Returns:
 *      CDK_E_xxx
 */
static int
_bcm84740_init_stage_0(phy_ctrl_t *pc)
{
    int ioerr = 0;
    int rv = CDK_E_NONE;
    int cnt;
    uint32_t temp32;

    _PHY_DBG(pc, ("init_stage_0\n"));

    PHY_CTRL_FLAGS(pc) |= PHY_F_FIBER_MODE;

    ioerr += PHY_BUS_READ(pc, PMA_PMD_CHIP_MODE_REG, &temp32);

    if ((temp32 & PMA_PMD_CHIP_MODE_MASK) == PMA_PMD_MODE_40G) {
        /* switch to configured mode(quad mode) if current chip mode is single mode */
        if (!(PHY84740_SINGLE_PORT_MODE(pc))) {
        _PHY_DBG(pc, ("Single to Quad\n"));
                ioerr += _bcm84740_single_to_quad_mode(pc);

        } else {  /* configured mode is single mode */
            /* if configured mode(single mode) matches current chip mode. Make sure the
             * DAC mode is for SR4/LR4.
             */
        _PHY_DBG(pc, ("Clear DAC\n"));
            /* clear DAC mode for LR4/SR4  */
            ioerr += PHY_BUS_READ(pc, PMA_PMD_CHIP_MODE_REG, &temp32);
            temp32 &= ~PMA_PMD_DAC_MODE_MASK;
            ioerr += PHY_BUS_WRITE(pc, PMA_PMD_CHIP_MODE_REG, temp32);

            /* PHY84740_MEDIUM_TYPE_SET(pc,MEDIUM_TYPE_SR4_LR4); */

        }
    } else {  /* current chip mode is quad mode */
        /* switch to configured mode(single mode) if current chip mode is quad mode */
        if (PHY84740_SINGLE_PORT_MODE(pc)) {
            _PHY_DBG(pc, ("Quad to Single\n"));
            ioerr += _bcm84740_quad_to_single_mode(pc);

        } else { /* configured mode is quad mode */
            /* chip already in configured mode. Do nothing for now */
        }
    }

    ioerr += PHY_BUS_WRITE(pc, PMA_PMD_CTRL_REG, MII_CTRL_RESET);

    /* Wait for reset completion */
    for (cnt = 0; cnt < PHY_RESET_POLL_MAX; cnt++) {
        ioerr += PHY_BUS_READ(pc, PMA_PMD_CTRL_REG, &temp32);
        if ((temp32 & MII_CTRL_RESET) == 0) {
            break;
        }
    }
    if (cnt >= PHY_RESET_POLL_MAX) {
        PHY_WARN(pc, ("reset timeout\n"));
        rv = CDK_E_TIMEOUT;
    }

    if (CDK_SUCCESS(rv)) {
        rv = _bcm84740_rom_firmware_download(pc);
    }

    return ioerr ? CDK_E_IO : rv;
}

/*
 * Function:
 *      _bcm84740_init_stage_1
 * Purpose:
 *      PHY init.
 * Parameters:
 *      pc - PHY control structure
 * Returns:
 *      CDK_E_xxx
 */
static int
_bcm84740_init_stage_1(phy_ctrl_t *pc)
{
    int ioerr = 0;
    int rv = CDK_E_NONE;
    int i;
    uint32_t temp32;
    uint32_t ucode_ver;

    _PHY_DBG(pc, ("init_stage_1\n"));

    if (CDK_SUCCESS(rv)) {
        rv = _bcm84740_rom_firmware_wait(pc);
    }

    ioerr += PHY_BUS_READ(pc, PMA_PMD_CE00_REG, &ucode_ver);

    ioerr += PHY_BUS_READ(pc, PMA_PMD_GEN_REG_4, &temp32);

    if (temp32 != 0x600D || ioerr) {
        PHY_WARN(pc, ("SPI-ROM load: Bad Checksum\n"));
        return CDK_E_FAIL;
    }
    PHY_VERB(pc, ("SPI-ROM version = 0x%04"PRIx32"\n", ucode_ver));

    if (!(PHY84740_SINGLE_PORT_MODE(pc))) {
        /* clear 1.0xcd17 to enable the PCS */
        ioerr += PHY_BUS_WRITE(pc, PMA_PMD_CD17_REG, 0x0);
    } else {
        /* 40G no autoneg support */
        /* EDC mode for SR4/LR4 0x44, done in ucode, no need to set for CR4 */
        /* disable cl72 */
        ioerr += PHY_BUS_WRITE(pc, PMA_PMD_0096_REG, 0x0);
        /* disable AN */
        ioerr += PHY_BUS_WRITE(pc, AN_CTRL_REG, 0x0);

    }

#ifdef RXLOS_OVERRIDE_ENABLE
    if (PHY84740_SINGLE_PORT_MODE(pc)) {
        for (i = 0; i < 4; i++) {
            ioerr += PHY_BUS_WRITE(pc, PMA_PMD_AER_ADDR_REG, i);
            /* XXX temp 0xc0c0: RXLOS override: 0x0808 MOD_ABS override */
            ioerr += PHY_BUS_WRITE(pc, PMA_PMD_C8E4_REG, 0xc8c8);
        }
    } else {
        /* XXX temp 0xc0c0: RXLOS override: 0x0808 MOD_ABS override */
        ioerr += PHY_BUS_WRITE(pc, PMA_PMD_C8E4_REG, 0xc8c8);
    }
#endif

    return ioerr ? CDK_E_IO : rv;
}

/*
 * Function:
 *      _bcm84740_init_stage
 * Purpose:
 *      Execute specified init stage.
 * Parameters:
 *      pc - PHY control structure
 *      stage - init stage
 * Returns:
 *      CDK_E_xxx
 */
static int
_bcm84740_init_stage(phy_ctrl_t *pc, int stage)
{
    switch (stage) {
    case 0:
        return _bcm84740_init_stage_0(pc);
    case 1:
        return _bcm84740_init_stage_1(pc);
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

/*
 * Function:
 *      bcm84740_phy_probe
 * Purpose:     
 *      Probe for 84740 PHY
 * Parameters:
 *      pc - PHY control structure
 * Returns:     
 *      CDK_E_xxx
 */
static int
bcm84740_phy_probe(phy_ctrl_t *pc)
{
    uint32_t phyid0, phyid1;
    int ioerr = 0;

    PHY_CTRL_CHECK(pc);

    ioerr += PHY_BUS_READ(pc, PMA_PMD_ID0_REG, &phyid0);
    ioerr += PHY_BUS_READ(pc, PMA_PMD_ID1_REG, &phyid1);

    if (ioerr) {
        return CDK_E_IO;
    }

    if ((phyid0 == BCM84740_PMA_PMD_ID0) &&
        ((phyid1 & ~0xf) == (BCM84740_PMA_PMD_ID1 & ~0xf))) {
        return CDK_E_NONE;
    }

    return CDK_E_NOT_FOUND;
}

/*
 * Function:
 *      bcm84740_phy_notify
 * Purpose:     
 *      Handle PHY notifications
 * Parameters:
 *      pc - PHY control structure
 *      event - PHY event
 * Returns:     
 *      CDK_E_xxx
 */
static int
bcm84740_phy_notify(phy_ctrl_t *pc, phy_event_t event)
{
    int rv = CDK_E_NONE;

    PHY_CTRL_CHECK(pc);

    /* Call up the PHY chain */
    if (CDK_SUCCESS(rv)) {
        rv = PHY_NOTIFY(PHY_CTRL_NEXT(pc), event);
    }

    return rv;
}

/*
 * Function:
 *      bcm84740_phy_reset
 * Purpose:     
 *      Reset 84740 PHY
 * Parameters:
 *      pc - PHY control structure
 * Returns:     
 *      CDK_E_xxx
 */
static int
bcm84740_phy_reset(phy_ctrl_t *pc)
{
    uint32_t mmf_pma_pmd_ctrl;
    int cnt;
    int ioerr = 0;
    int rv = CDK_E_NONE;

    PHY_CTRL_CHECK(pc);

    ioerr += PHY_BUS_WRITE(pc, PMA_PMD_CTRL_REG, MII_CTRL_RESET);

    /* Wait for reset completion */
    for (cnt = 0; cnt < PHY_RESET_POLL_MAX; cnt++) {
        ioerr += PHY_BUS_READ(pc, PMA_PMD_CTRL_REG, &mmf_pma_pmd_ctrl);
        if ((mmf_pma_pmd_ctrl & MII_CTRL_RESET) == 0) {
            break;
        }
    }
    if (cnt >= PHY_RESET_POLL_MAX) {
        PHY_WARN(pc, ("reset timeout\n"));
    }

    /* Call up the PHY chain */
    if (CDK_SUCCESS(rv)) {
        rv = PHY_RESET(PHY_CTRL_NEXT(pc));
    }

    return ioerr ? CDK_E_IO : rv;
}

/*
 * Function:
 *      bcm84740_phy_init
 * Purpose:     
 *      Initialize 84740 PHY driver
 * Parameters:
 *      pc - PHY control structure
 * Returns:     
 *      CDK_E_xxx
 */
static int
bcm84740_phy_init(phy_ctrl_t *pc)
{
    int rv = CDK_E_NONE;
    int stage;

    PHY_CTRL_CHECK(pc);

    if (PHY_CTRL_FLAGS(pc) & PHY_F_STAGED_INIT) {
        PHY_CTRL_FLAGS(pc) &= ~PHY_F_STAGED_INIT;
    }

    for (stage = 0; CDK_SUCCESS(rv); stage++) {
        rv = _bcm84740_init_stage(pc, stage);
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
 *      bcm84740_phy_link_get
 * Purpose:     
 *      Determine the current link up/down status
 * Parameters:
 *      pc - PHY control structure
 *      link - (OUT) non-zero indicates link established.
 * Returns:
 *      CDK_E_xxx
 * Notes:
 *      MII_STATUS bit 2 reflects link state.
 */
static int
bcm84740_phy_link_get(phy_ctrl_t *pc, int *link, int *autoneg_done)
{
    uint32_t ctrl, stat, speed_val;
    int ioerr = 0, rv;
    int cur_speed, autoneg;

    PHY_CTRL_CHECK(pc);
    cur_speed = 0;
    *link = 0;

    ioerr += PHY_BUS_READ(pc, AN_MII_CTRL_REG, &ctrl);

    autoneg = (ctrl & AN_ENABLE);

    /* Check autoneg status before link status */
    if (autoneg_done) {
        ioerr += PHY_BUS_READ(pc, AN_MII_STAT_REG, &stat);
        *autoneg_done = (stat & AN_DONE);
    }

    if (PHY84740_SINGLE_PORT_MODE(pc)) {
        int serdes_link;
        rv = PHY_LINK_GET(PHY_CTRL_NEXT(pc), &serdes_link, NULL);
        if (CDK_FAILURE(rv)) {
            return CDK_E_FAIL;
        }
        ioerr += PHY_BUS_READ(pc, PMA_PMD_STAT_REG, &stat);
        *link = ((stat & MII_STAT_LA) && serdes_link) ? TRUE : FALSE;
        return CDK_E_NONE;
    }

        /* return link false if in the middle of autoneg */
    if (autoneg == TRUE && autoneg_done == FALSE) {
        *link = FALSE;
        return CDK_E_NONE;
    }

    if (!autoneg) {
        ioerr += PHY_BUS_READ(pc, PMA_PMD_CTRL2_REG, &speed_val);

        if ((speed_val & PMA_PMD_CTRL2_PMA_TYPE_MASK) !=
                                       PMA_PMD_CTRL2_PMA_TYPE_1G_KX) {
            cur_speed = 10000;
        }
    } else {
        cur_speed = 1000;
    }

    if (cur_speed == 10000) {
        /* 10G link must be up in PMA/PMD and PCS */
        *link = 0;
        ioerr += PHY_BUS_READ(pc, PMA_PMD_STAT_REG, &stat);
        if (stat & MII_STAT_LA) {
            ioerr += PHY_BUS_READ(pc, PCS_STAT_REG, &stat);
            if (stat & MII_STAT_LA) {
                *link = 1;
            }
        }
    } else {

        /* Check 1G link only if no 10G link */
        if (*link == 0) {
            ioerr += PHY_BUS_READ(pc, AN_MII_STAT_REG, &stat);
            *link = ((stat & AN_LINK) != 0);
        }
    }

    return ioerr ? CDK_E_IO : CDK_E_NONE;
}

/*
 * Function:    
 *      bcm84740_phy_duplex_set
 * Purpose:     
 *      Set the current duplex mode (forced).
 * Parameters:
 *      pc - PHY control structure
 *      duplex - non-zero indicates full duplex, zero indicates half
 * Returns:     
 *      CDK_E_xxx
 */
static int
bcm84740_phy_duplex_set(phy_ctrl_t *pc, int duplex)
{
    return (duplex != 0) ? CDK_E_NONE : CDK_E_PARAM;
}

/*
 * Function:    
 *      bcm84740_phy_duplex_get
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
bcm84740_phy_duplex_get(phy_ctrl_t *pc, int *duplex)
{
    *duplex = 1;

    return CDK_E_NONE;
}

/*
 * Function:    
 *      bcm84740_phy_speed_set
 * Purpose:     
 *      Set the current operating speed (forced).
 * Parameters:
 *      pc - PHY control structure
 *      speed - new link speed
 * Returns:     
 *      CDK_E_xxx
 */
static int
bcm84740_phy_speed_set(phy_ctrl_t *pc, uint32_t speed)
{
    uint32_t pma_pmd_ctrl, an_ctrl;
    uint32_t cur_speed;
    int lb, an;
    int ioerr = 0;
    int rv;

    PHY_CTRL_CHECK(pc);

    /* Check valid port speed */
    if (PHY84740_SINGLE_PORT_MODE(pc)) {
        switch (speed) {
        case 40000:
            PHY_CTRL_FLAGS(pc) |= PHY_F_PASSTHRU;
            break;
        default:
            return CDK_E_PARAM;
        }
    } else {
        switch (speed) {
        case 10000:
            PHY_CTRL_FLAGS(pc) &= ~PHY_F_PASSTHRU;
            break;
        case 1000:
            PHY_CTRL_FLAGS(pc) |= PHY_F_PASSTHRU;
            break;
        default:
            return CDK_E_PARAM;
        }
           
    }

    /* Call up the PHY chain */
    rv = PHY_SPEED_SET(PHY_CTRL_NEXT(pc), speed);
    if (CDK_FAILURE(rv)) {
        return rv;
    }

    /* Update loopback according to passthru mode */
    lb = 0;
    rv = PHY_LOOPBACK_GET(pc, &lb);
    if (CDK_SUCCESS(rv) && lb) {
        rv = PHY_LOOPBACK_SET(pc, 1);
    }
    if (CDK_FAILURE(rv)) {
        return rv;
    }

    /* Leave hardware alone if speed is unchanged */
    rv = PHY_SPEED_GET(pc, &cur_speed);
    if (CDK_SUCCESS(rv) && speed == cur_speed) {
        return CDK_E_NONE;
    }

    if (CDK_SUCCESS(rv)) {
        rv = PHY_AUTONEG_GET(pc, &an);
    }

    /* Leave hardware alone if auto-neg is enabled */
    if (CDK_SUCCESS(rv) && an == 0) {

        switch (speed) {
        case 40000:
            /* Single port mode */
            break;

        case 10000:
            /* Select 10G mode */
            ioerr += PHY_BUS_READ(pc, PMA_PMD_CTRL_REG, &pma_pmd_ctrl);
            pma_pmd_ctrl |= PMA_PMD_CTRL_SPEED_10G;
            ioerr += PHY_BUS_WRITE(pc, PMA_PMD_CTRL_REG, pma_pmd_ctrl);

            ioerr += PHY_BUS_WRITE(pc, PMA_PMD_CTRL2_REG,
                                   PMA_PMD_CTRL2_PMA_TYPE_10G_LRM);

            /* Restart auto-neg and wait */
            ioerr += PHY_BUS_READ(pc, AN_CTRL_REG, &an_ctrl);
            ioerr += PHY_BUS_WRITE(pc, AN_CTRL_REG,
                                   AN_ENABLE |
                                   AN_RESTART);
            PHY_SYS_USLEEP(40000);

            /* Restore auto-neg setting */
            ioerr += PHY_BUS_WRITE(pc, AN_CTRL_REG, an_ctrl);

            break;

        case 1000:
            /* Select 1G by-pass mode */
            ioerr += PHY_BUS_READ(pc, PMA_PMD_CTRL_REG, &pma_pmd_ctrl);
            pma_pmd_ctrl &= ~PMA_PMD_CTRL_SPEED_10G;
            ioerr += PHY_BUS_WRITE(pc, PMA_PMD_CTRL_REG, pma_pmd_ctrl);

            ioerr += PHY_BUS_WRITE(pc, PMA_PMD_CTRL2_REG,
                                   PMA_PMD_CTRL2_PMA_TYPE_1G_KX);
            break;
        default:
            break;
        }
    }

    return ioerr ? CDK_E_IO : rv;
}

/*
 * Function:    
 *      bcm84740_phy_speed_get
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
bcm84740_phy_speed_get(phy_ctrl_t *pc, uint32_t *speed)
{
    uint32_t pma_pmd_ctrl2, link_stat;
    int an;
    int ioerr = 0;
    int rv;

    PHY_CTRL_CHECK(pc);

    *speed = 0;

    if (PHY84740_SINGLE_PORT_MODE(pc)) {
        *speed = 40000;

        /* it is always in 40G speed */
        return CDK_E_NONE;
    }

    rv = PHY_AUTONEG_GET(pc, &an);
    if (CDK_SUCCESS(rv)) {
        if (an) {
            ioerr += PHY_BUS_READ(pc, AN_MII_STAT_REG, &link_stat);
            if (link_stat & AN_LINK) {
                *speed = 1000;
            }
        } else {
            ioerr += PHY_BUS_READ(pc, PMA_PMD_CTRL2_REG, &pma_pmd_ctrl2);
            if ((pma_pmd_ctrl2 & PMA_PMD_CTRL2_PMA_TYPE_MASK) 
                               == PMA_PMD_CTRL2_PMA_TYPE_1G_KX) {
                *speed = 1000;
            } else {
                *speed = 10000;
            }
        }
    }

    return ioerr ? CDK_E_IO : rv;
}

/*
 * Function:    
 *      bcm84740_phy_autoneg_set
 * Purpose:     
 *      Enable or disable auto-negotiation on the specified port.
 * Parameters:
 *      pc - PHY control structure
 *      autoneg - non-zero enables autoneg, zero disables autoneg
 * Returns:     
 *      CDK_E_xxx
 */
static int
bcm84740_phy_autoneg_set(phy_ctrl_t *pc, int autoneg)
{
    int ioerr = 0;
    int rv = CDK_E_NONE;
    uint32_t mode, temp;

    rv = PHY_AUTONEG_SET(PHY_CTRL_NEXT(pc), FALSE);
    if (PHY84740_SINGLE_PORT_MODE(pc)) {
        ioerr += PHY_BUS_READ(pc, PMA_PMD_CHIP_MODE_REG, &mode);
        /* no autoneg if in SR4/LR4 mode */
        if (!(mode & PMA_PMD_DAC_MODE_MASK)) {
            autoneg = 0;
        }
        rv = PHY_AUTONEG_SET(PHY_CTRL_NEXT(pc), autoneg);
        ioerr += PHY_BUS_WRITE(pc, PMA_PMD_0096_REG, autoneg ? 2:0);
        ioerr += PHY_BUS_WRITE(pc, AN_CTRL_REG, autoneg ? (AN_ENABLE | AN_RESTART) : 0);

        return ioerr ? CDK_E_IO : rv;
    }

    if (autoneg) {
        ioerr += PHY_BUS_WRITE(pc, AN_MII_CTRL_REG, MII_CTRL_AE | MII_CTRL_RAN);
        ioerr += PHY_BUS_READ(pc, AN_8309_REG, &temp);
        temp &= ~(1U << 5);
        ioerr += PHY_BUS_WRITE(pc, AN_8309_REG, temp);
    } else {
        ioerr += PHY_BUS_WRITE(pc, AN_MII_CTRL_REG, 0);
        ioerr += PHY_BUS_READ(pc, AN_8309_REG, &temp);
        temp |= (1U << 5);
        ioerr += PHY_BUS_WRITE(pc, AN_8309_REG, temp);
    }

    return ioerr ? CDK_E_IO : rv;
}

/*
 * Function:    
 *      bcm84740_phy_autoneg_get
 * Purpose:     
 *      Get the current auto-negotiation setting.
 * Parameters:
 *      pc - PHY control structure
 *      autoneg - (OUT) non-zero indicates autoneg enabled
 * Returns:     
 *      CDK_E_xxx
 */
static int
bcm84740_phy_autoneg_get(phy_ctrl_t *pc, int *autoneg)
{
    uint32_t ctrl;
    int ioerr = 0;
    int rv = CDK_E_NONE;

    if (PHY84740_SINGLE_PORT_MODE(pc)) {
        if (autoneg) {
            ioerr += PHY_BUS_READ(pc, AN_CTRL_REG, &ctrl);
            *autoneg = (ctrl & AN_ENABLE);
        }
    } else {
        if (autoneg) {
            ioerr += PHY_BUS_READ(pc, AN_MII_CTRL_REG, &ctrl);
            *autoneg = (ctrl & AN_ENABLE);
        }
    }

    return ioerr ? CDK_E_IO : rv;
}

/*
 * Function:    
 *      bcm84740_phy_loopback_set
 * Purpose:     
 *      Set the internal PHY loopback mode.
 * Parameters:
 *      pc - PHY control structure
 *      enable - non-zero enables PHY loopback
 * Returns:     
 *      CDK_E_xxx
 */
static int
bcm84740_phy_loopback_set(phy_ctrl_t *pc, int enable)
{
    uint32_t pma_pmd_ctrl;
    int ioerr = 0;
    int rv;
    int next_lb;

    next_lb = 0;
    if (PHY_CTRL_FLAGS(pc) & PHY_F_PASSTHRU) {
        next_lb = enable;
        enable = 0;
    }

    /* Set loopback on upstream PHY */
    rv = PHY_LOOPBACK_SET(PHY_CTRL_NEXT(pc), next_lb);

    /* Read loopback control registers */
    ioerr += PHY_BUS_READ(pc, PMA_PMD_CTRL_REG, &pma_pmd_ctrl);

    pma_pmd_ctrl &= ~(1U << 0);
    if (enable) {
        pma_pmd_ctrl |= (1U << 0);
    }

    /* Write updated loopback control registers */
    ioerr += PHY_BUS_WRITE(pc, PMA_PMD_CTRL_REG, pma_pmd_ctrl);

    return ioerr ? CDK_E_IO : rv;
}

/*
 * Function:    
 *      bcm84740_phy_loopback_get
 * Purpose:     
 *      Get the local PHY loopback mode.
 * Parameters:
 *      pc - PHY control structure
 *      enable - (OUT) non-zero indicates PHY loopback enabled
 * Returns:     
 *      CDK_E_xxx
 * Notes:
 *      Return correct value independently of passthru flag.
 */
static int
bcm84740_phy_loopback_get(phy_ctrl_t *pc, int *enable)
{
    uint32_t pma_pmd_ctrl;
    int ioerr = 0;
    int rv;

    *enable = 0;

    /* Get loopback of upstream PHY */
    rv = PHY_LOOPBACK_GET(PHY_CTRL_NEXT(pc), enable);

    if (*enable == 0) {
        /* Read loopback control registers */
        ioerr += PHY_BUS_READ(pc, PMA_PMD_CTRL_REG, &pma_pmd_ctrl);
        if (pma_pmd_ctrl & (1U << 0)) {
            *enable = 1;
        }
    }

    return ioerr ? CDK_E_IO : rv;
}

/*
 * Function:    
 *      bcm84740_phy_ability_get
 * Purpose:     
 *      Get the abilities of the PHY.
 * Parameters:
 *      pc - PHY control structure
 *      abil - (OUT) ability mask indicating supported options/speeds.
 * Returns:     
 *      CDK_E_xxx
 */
static int
bcm84740_phy_ability_get(phy_ctrl_t *pc, uint32_t *abil)
{
    PHY_CTRL_CHECK(pc);

    *abil = (PHY_ABIL_40GB | PHY_ABIL_10GB |
             PHY_ABIL_LOOPBACK | PHY_ABIL_1000MB_FD);

    return CDK_E_NONE;
}

/*
 * Function:
 *      bcm84740_phy_config_set
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
bcm84740_phy_config_set(phy_ctrl_t *pc, phy_config_t cfg, uint32_t val, void *cd)
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
            return _bcm84740_init_stage(pc, val);
        }
        break;
    default:
        break;
    }

    return CDK_E_UNAVAIL;
}

/*
 * Function:
 *      bcm84740_phy_config_get
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
bcm84740_phy_config_get(phy_ctrl_t *pc, phy_config_t cfg, uint32_t *val, void *cd)
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
        *val = 0x9a;
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
 * Variable:    bcm84740_drv
 * Purpose:     PHY Driver for BCM84740.
 */
phy_driver_t bcm84740_drv = {
    "bcm84740",
    "BCM84740 40-Gigabit PHY Driver",  
    0,
    bcm84740_phy_probe,                  /* pd_probe */
    bcm84740_phy_notify,                 /* pd_notify */
    bcm84740_phy_reset,                  /* pd_reset */
    bcm84740_phy_init,                   /* pd_init */
    bcm84740_phy_link_get,               /* pd_link_get */
    bcm84740_phy_duplex_set,             /* pd_duplex_set */
    bcm84740_phy_duplex_get,             /* pd_duplex_get */
    bcm84740_phy_speed_set,              /* pd_speed_set */
    bcm84740_phy_speed_get,              /* pd_speed_get */
    bcm84740_phy_autoneg_set,            /* pd_autoneg_set */
    bcm84740_phy_autoneg_get,            /* pd_autoneg_get */
    bcm84740_phy_loopback_set,           /* pd_loopback_set */
    bcm84740_phy_loopback_get,           /* pd_loopback_get */
    bcm84740_phy_ability_get,            /* pd_ability_get */
    bcm84740_phy_config_set,             /* pd_config_set */
    bcm84740_phy_config_get,             /* pd_config_get */
    NULL,                                /* pd_status_get */
    NULL                                 /* pd_cable_diag */
};
