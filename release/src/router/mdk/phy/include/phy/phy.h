/*
 * $Id: phy.h,v 1.46 Broadcom SDK $
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

#ifndef __PHY_H__
#define __PHY_H__

#include <phy_config.h>

#include <cdk/cdk_types.h>
#include <cdk/cdk_error.h>
#include <cdk/cdk_debug.h>

/*
 * Symbol support depends on CDK
 */
#if PHY_CONFIG_INCLUDE_CHIP_SYMBOLS == 1
#  if CDK_CONFIG_INCLUDE_CHIP_SYMBOLS == 1
#    include <cdk/cdk_symbols.h>
#  else
#    undef PHY_CONFIG_INCLUDE_CHIP_SYMBOLS
#    define PHY_CONFIG_INCLUDE_CHIP_SYMBOLS 0
#  endif
#endif

/*
 * Standard MII Registers
 */
#define MII_CTRL_REG            0x00    /* MII Control Register : r/w */
#define MII_STAT_REG            0x01    /* MII Status Register: ro */ 
#define MII_PHY_ID0_REG         0x02    /* MII PHY ID register: r/w */
#define MII_PHY_ID1_REG         0x03    /* MII PHY ID register: r/w */
#define MII_ANA_REG             0x04    /* MII Auto-Neg Advertisement: r/w */
#define MII_ANP_REG             0x05    /* MII Auto-Neg Link Partner: ro */
#define MII_AN_EXP_REG          0x06    /* MII Auto-Neg Expansion: ro */
#define MII_GB_CTRL_REG         0x09    /* MII 1000Base-T control register */
#define MII_GB_STAT_REG         0x0a    /* MII 1000Base-T Status register */
#define MII_ESR_REG             0x0f    /* MII Extended Status register */

/* 
 * MII Control Register: bit definitions
 */
#define MII_CTRL_RESET          (1L << 15) /* PHY reset */
#define MII_CTRL_LE             (1L << 14) /* Loopback enable */
#define MII_CTRL_SS_LSB         (1L << 13) /* Speed select, LSb */
#define MII_CTRL_AE             (1L << 12) /* Autonegotiation enable */
#define MII_CTRL_PD             (1L << 11) /* Power Down */
#define MII_CTRL_IP             (1L << 10) /* Isolate PHY */
#define MII_CTRL_RAN            (1L << 9)  /* Restart Autonegotiation */
#define MII_CTRL_FD             (1L << 8)  /* Full Duplex */
#define MII_CTRL_CST            (1L << 7)  /* Collision Signal test */
#define MII_CTRL_SS_MSB         (1L << 6)  /* Speed select, MSb */
#define MII_CTRL_FS_2500        (1L << 5)  /* Force speed to 2500 Mbps */

#define MII_CTRL_SS(_x)         ((_x) & (MII_CTRL_SS_LSB|MII_CTRL_SS_MSB))
#define MII_CTRL_SS_10          0
#define MII_CTRL_SS_100         (MII_CTRL_SS_LSB)
#define MII_CTRL_SS_1000        (MII_CTRL_SS_MSB)
#define MII_CTRL_SS_INVALID     (MII_CTRL_SS_LSB | MII_CTRL_SS_MSB)
#define MII_CTRL_SS_MASK        (MII_CTRL_SS_LSB | MII_CTRL_SS_MSB)

/* 
 * MII Status Register: See 802.3, 1998 pg 544 
 */
#define MII_STAT_100_T4         (1L << 15) /* Full duplex 100Mb/s supported */
#define MII_STAT_FD_100         (1L << 14) /* Full duplex 100Mb/s supported */
#define MII_STAT_HD_100         (1L << 13) /* Half duplex 100Mb/s supported */
#define MII_STAT_FD_10          (1L << 12) /* Full duplex 100Mb/s supported */
#define MII_STAT_HD_10          (1L << 11) /* Half duplex 100Mb/s supported */
#define MII_STAT_FD_100_T2      (1L << 10) /* Full duplex 100Mb/s supported */
#define MII_STAT_HD_100_T2      (1L << 9)  /* Half duplex 100Mb/s supported */
#define MII_STAT_ES             (1L << 8)  /* Extended status (R15) */
#define MII_STAT_UT_CAP         (1L << 7)  /* Unidirectional transmit capable */
#define MII_STAT_MF_PS          (1L << 6)  /* Preamble suppression */
#define MII_STAT_AN_DONE        (1L << 5)  /* Autoneg complete */
#define MII_STAT_RF             (1L << 4)  /* Remote Fault */
#define MII_STAT_AN_CAP         (1L << 3)  /* Autoneg capable */
#define MII_STAT_LA             (1L << 2)  /* Link Active */
#define MII_STAT_JBBR           (1L << 1)  /* Jabber Detected */
#define MII_STAT_EXT            (1L << 0)  /* Extended Registers */

/*
 * MII Link Advertisment
 */
#define MII_ANA_NP              (1L << 15) /* Next Page */
#define MII_ANA_RF              (1L << 13) /* Remote fault */
#define MII_ANA_ASYM_PAUSE      (1L << 11) /* Asymmetric pause supported */
#define MII_ANA_PAUSE           (1L << 10) /* Pause supported */
#define MII_ANA_T4              (1L << 9)  /* T4 */
#define MII_ANA_FD_100          (1L << 8)  /* Full duplex 100Mb/s supported */
#define MII_ANA_HD_100          (1L << 7)  /* Half duplex 100Mb/s supported */
#define MII_ANA_FD_10           (1L << 6)  /* Full duplex 10Mb/s supported */
#define MII_ANA_HD_10           (1L << 5)  /* Half duplex 10Mb/s supported */
#define MII_ANA_ASF             (1L << 0)  /* Advertise Selector Field */

#define MII_ANA_ASF_802_3       (1)       /* 802.3 PHY */

/*
 * 1000Base-T Control Register
 */
#define MII_GB_CTRL_MS_MAN      (1L << 12) /* Manual Master/Slave mode */
#define MII_GB_CTRL_MS          (1L << 11) /* Master/Slave negotiation mode */
#define MII_GB_CTRL_PT          (1L << 10) /* Port type */
#define MII_GB_CTRL_ADV_1000FD  (1L << 9)  /* Advertise 1000Base-T FD */
#define MII_GB_CTRL_ADV_1000HD  (1L << 8)  /* Advertise 1000Base-T HD */

/*
 * 1000Base-T Status Register
 */
#define MII_GB_STAT_MS_FAULT    (1L << 15) /* Master/Slave Fault */
#define MII_GB_STAT_MS          (1L << 14) /* Master/Slave, 1 == Master */
#define MII_GB_STAT_LRS         (1L << 13) /* Local receiver status */
#define MII_GB_STAT_RRS         (1L << 12) /* Remote receiver status */
#define MII_GB_STAT_LP_1000FD   (1L << 11) /* Link partner 1000FD capable */
#define MII_GB_STAT_LP_1000HD   (1L << 10) /* Link partner 1000HD capable */
#define MII_GB_STAT_IDE         (0xff)    /* Idle error count */

/*
 * IEEE Extended Status Register
 */
#define MII_ESR_1000_X_FD       (1L << 15) /* 1000Base-T FD capable */
#define MII_ESR_1000_X_HD       (1L << 14) /* 1000Base-T HD capable */
#define MII_ESR_1000_T_FD       (1L << 13) /* 1000Base-T FD capable */
#define MII_ESR_1000_T_HD       (1L << 12) /* 1000Base-T FD capable */

/*
 * Clause 45 Device Types
 */
#define MII_C45_DEV_RESERVED    0
#define MII_C45_DEV_PMA_PMD     1
#define MII_C45_DEV_WIS         2
#define MII_C45_DEV_PCS         3
#define MII_C45_DEV_PHY_XS      4
#define MII_C45_DEV_DTE_XS      5
#define MII_C45_DEV_AN          7

/* 
 * PHY Interface Types
 */
#define PHY_IF_NOCXN            0
#define PHY_IF_NULL             1
#define PHY_IF_MII              2
#define PHY_IF_GMII             3
#define PHY_IF_SGMII            4
#define PHY_IF_TBI              5
#define PHY_IF_XGMII            6
#define PHY_IF_RGMII            7
#define PHY_IF_RVMII            8
#define PHY_IF_XAUI             9
#define PHY_IF_XLAUI            10
#define PHY_IF_XFI              11
#define PHY_IF_SFI              12
#define PHY_IF_KR               13
#define PHY_IF_CR               14
#define PHY_IF_FIBER            15
#define PHY_IF_HIGIG            16

/*
 * Port MDIX Modes/Status
 */
#define PHY_MDIX_AUTO           0
#define PHY_MDIX_FORCEAUTO      1
#define PHY_MDIX_NORMAL         2
#define PHY_MDIX_XOVER          3

/*
 * PHY Medium Configuration/Status
 */
#define PHY_MEDIUM_NONE         0
#define PHY_MEDIUM_AUTO         1
#define PHY_MEDIUM_FIBER_PREF   2
#define PHY_MEDIUM_COPPER       3
#define PHY_MEDIUM_FIBER        4

/*
 * PHY Interface Modes
 */
#define PHY_MODE_LAN            0
#define PHY_MODE_WAN            1

/*
 * PHY EEE Modes
 */
#define PHY_EEE_NONE            0
#define PHY_EEE_802_3           1
#define PHY_EEE_AUTO            2

typedef enum {
    PhyEvent_ChangeToCopper,
    PhyEvent_ChangeToFiber,
    PhyEvent_ChangeToPassthru,
    PhyEvent_CopperDisable,
    PhyEvent_CopperEnable,
    PhyEvent_FiberDisable,
    PhyEvent_FiberEnable,
    PhyEvent_MacDisable,
    PhyEvent_MacEnable,
    PhyEvent_PhyDisable,
    PhyEvent_PhyEnable,
    PhyEvent_PortDrainStart,
    PhyEvent_PortDrainStop,
    PhyEvent_Count
}  phy_event_t;

typedef enum {
    PhyConfig_Enable,           /* TRUE/FALSE */
    PhyConfig_Master,           /* TRUE/FALSE */
    PhyConfig_RemoteLoopback,   /* TRUE/FALSE */
    PhyConfig_XauiTxLaneRemap,  /* 0x00000123: revert Tx lane order
                                   0xffffffff: auto
                                   0x00000000: disable */
    PhyConfig_XauiTxPolInvert,  /* TRUE:  invert Tx polarity
                                   FALSE: normal Tx polarity */
    PhyConfig_PcsTxPolInvert,   /* TRUE:  invert PCS Tx polarity
                                   FALSE: normal PCS Tx polarity */
    PhyConfig_XauiRxLaneRemap,  /* 0x00000123: revert Rx lane order
                                   0xffffffff: auto
                                   0x00000000: disable */
    PhyConfig_XauiRxPolInvert,  /* TRUE:  invert Rx polarity
                                   FALSE: normal Rx polarity */
    PhyConfig_PcsRxPolInvert,   /* TRUE:  invert PCS Rx polarity
                                   FALSE: normal PCS Rx polarity */
    PhyConfig_PortInterface,    /* PHY_IF_xxx */
    PhyConfig_Mode,             /* PHY_MODE_xxx */
    PhyConfig_AdvLocal,         /* PHY_ABIL_xxx */
    PhyConfig_AdvRemote,        /* PHY_ABIL_xxx (read-only) */
    PhyConfig_Clause45Devs,     /* Bitmask (read-only) */
    PhyConfig_TxPreemp,         /* Tx preemphasis post */
    PhyConfig_TxIDrv,           /* Tx driver current (main amplitude) */
    PhyConfig_TxPreIDrv,        /* Tx pre driver current */
    PhyConfig_EEE,              /* PHY_EEE_xxx */
    PhyConfig_BcastAddr,        /* Used to retrieve broadcast domain */
    PhyConfig_InitStage,        /* Used to perform multi-stage init */
    PhyConfig_Firmware,         /* Read/update PHY firmware */
    PhyConfig_MdiPairRemap,     /* 0x00003210: Change MDI pair order */
    PhyConfig_ChipRev,          /* Chip revision (read-only) */
    PhyConfig_Count
}  phy_config_t;

typedef enum {
    PhyStatus_PortMDIX,         /* PHY_MDIX_xxx */
    PhyStatus_Medium,           /* PHY_MEDIUM_xxx */
    PhyStatus_ErrorSymbols,     /* Counter */
    PhyStatus_RxEqTuning,       /* Rx equalizer tuning status */
    PhyStatus_LineInterface,    /* Line interface status */
    PhyStatus_Count
}  phy_status_t;

typedef enum {
    PhyPortCableState_Ok,
    PhyPortCableState_Open,
    PhyPortCableState_Short,
    PhyPortCableState_OpenShort,
    PhyPortCableState_Crosstalk,
    PhyPortCableState_Unknown,
    PhyPortCableState_Count
} phy_port_cable_state_t;

/* PHY abilities */
#define PHY_ABIL_LOOPBACK       (1L << 0)
#define PHY_ABIL_AN             (1L << 1)
#define PHY_ABIL_TBI            (1L << 2)
#define PHY_ABIL_MII            (1L << 3)
#define PHY_ABIL_GMII           (1L << 4)
#define PHY_ABIL_SGMII          (1L << 5)
#define PHY_ABIL_XGMII          (1L << 6)
#define PHY_ABIL_SERDES         (1L << 7)
#define PHY_ABIL_AN_SGMII       (1L << 8)
#define PHY_ABIL_RGMII          (1L << 9)
#define PHY_ABIL_RVMII          (1L << 10)
#define PHY_ABIL_XAUI           (1L << 11)
#define PHY_ABIL_PAUSE_TX       (1L << 13)
#define PHY_ABIL_PAUSE_RX       (1L << 14)
#define PHY_ABIL_PAUSE_ASYMM    (1L << 15)
#define PHY_ABIL_10MB_HD        (1L << 16)
#define PHY_ABIL_10MB_FD        (1L << 17)
#define PHY_ABIL_100MB_HD       (1L << 18)
#define PHY_ABIL_100MB_FD       (1L << 19)
#define PHY_ABIL_1000MB_HD      (1L << 20)
#define PHY_ABIL_1000MB_FD      (1L << 21)
#define PHY_ABIL_2500MB         (1L << 22)
#define PHY_ABIL_3000MB         (1L << 23)
#define PHY_ABIL_10GB           (1L << 24)
#define PHY_ABIL_13GB           (1L << 25)
#define PHY_ABIL_16GB           (1L << 26)
#define PHY_ABIL_21GB           (1L << 27)
#define PHY_ABIL_25GB           (1L << 28)
#define PHY_ABIL_30GB           (1L << 29)
#define PHY_ABIL_40GB           (1L << 30)

#define PHY_ABIL_PAUSE          (PHY_ABIL_PAUSE_TX  | PHY_ABIL_PAUSE_RX)
#define PHY_ABIL_10MB           (PHY_ABIL_10MB_HD   | PHY_ABIL_10MB_FD)
#define PHY_ABIL_100MB          (PHY_ABIL_100MB_HD  | PHY_ABIL_100MB_FD)
#define PHY_ABIL_1000MB         (PHY_ABIL_1000MB_HD | PHY_ABIL_1000MB_FD)

/* PHY flags */
#define PHY_F_ENABLE            (1L << 0)
#define PHY_F_PASSTHRU          (1L << 1)
#define PHY_F_FIBER_MODE        (1L << 2)
#define PHY_F_FIBER_PREF        (1L << 3)
#define PHY_F_MAC_DISABLE       (1L << 4)
#define PHY_F_PHY_DISABLE       (1L << 5)
#define PHY_F_PORT_DRAIN        (1L << 6)
#define PHY_F_SPEED_CHG         (1L << 7)
#define PHY_F_DUPLEX_CHG        (1L << 8)
#define PHY_F_WAN_MODE          (1L << 9)
#define PHY_F_R2_MODE           (1L << 10)
#define PHY_F_CLAUSE45          (1L << 11)
#define PHY_F_2LANE_MODE        (1L << 12)
#define PHY_F_SERDES_MODE       (1L << 13)
#define PHY_F_CUSTOM_MODE       (1L << 14)
#define PHY_F_ADDR_SHARE        (1L << 15)
#define PHY_F_SCRAMBLE          (1L << 16)
#define PHY_F_LINK_UP           (1L << 17)
#define PHY_F_STAGED_INIT       (1L << 18)
#define PHY_F_BCAST_MSTR        (1L << 19)
#define PHY_F_MULTI_CORE        (1L << 20)
#define PHY_F_FAST_LOAD         (1L << 21)
#define PHY_F_MAC_LOOPBACK      (1L << 22)
#define PHY_F_ADDR_VALID        (1L << 31)

/* PHY instance (uint16_t) */
#define PHY_INST_VALID          (1L << 15)

/* PHY lane (uint16_t) */
#define PHY_LANE_VALID          (1L << 15)

/* PHY Driver Flags */
#define PHY_DRIVER_F_INTERNAL   (1L << 0)

typedef struct phy_port_cable_diag_s {
    phy_port_cable_state_t	state;		/* state of all pairs */
    int				npairs;		/* pair_* elements valid */
    phy_port_cable_state_t	pair_state[4];	/* pair state */
    int				pair_len[4];	/* pair length in metres */
    int				fuzz_len;	/* len values +/- this */
} phy_port_cable_diag_t;


/*
 * Occasionally the phy_bus_t changes to support new features. This define
 * allows applications to write backward compatible PHY bus drivers.
 */
#define PHY_BUS_VERSION         4

/*
 * The PHY bus driver defines how to access PHY registers in a system.
 * A network port may be associated with multiple PHY buses for accessing
 * internal and external PHYs. PHY bus drivers for internal PHY will
 * usually be specific to the switch chip, whereas PHY bus drivers for
 * external PHYs will be board-specific because the PHY address typically
 * is strappable. 
 */
typedef struct phy_bus_s {

    /* String to identify PHY bus driver */
    const char *drv_name;

    /* Get PHY address from port number */
    uint32_t (*phy_addr)(int port);

    /* Read raw PHY data */
    int (*read)(int unit, uint32_t addr, uint32_t reg, uint32_t *data);

    /* Write raw PHY data */
    int (*write)(int unit, uint32_t addr, uint32_t reg, uint32_t data);

    /* Get instance within multi-PHY package (dual, quad, octal) */
    int (*phy_inst)(int port);

} phy_bus_t;

/*
 * The PHY control structure should normally not be accessed
 * directly by PHY drivers (or application code) except through
 * the provided macros.
 */
typedef struct phy_ctrl_s {
    struct phy_ctrl_s *next;
    struct phy_driver_s *drv;
    struct phy_bus_s *bus;
#if PHY_CONFIG_INCLUDE_CHIP_SYMBOLS == 1
    const cdk_symbols_t *symbols; 
#endif
    int (*fw_helper)(void *, uint32_t, uint32_t, void *);
    int unit;
    int port;
    int addr_offset;
    uint32_t flags;
    uint32_t addr;
    uint16_t lane;
    uint8_t lane_mask;
    uint8_t line_intf;
#if PHY_CONFIG_PRIVATE_DATA_WORDS > 0
    uint32_t priv[PHY_CONFIG_PRIVATE_DATA_WORDS];
#endif
} phy_ctrl_t;

/* PHY control access macros */
#define PHY_CTRL_NEXT(_pc) ((_pc)->next)
#define PHY_CTRL_SYMBOLS(_pc) ((_pc)->symbols)
#define PHY_CTRL_FW_HELPER(_pc) ((_pc)->fw_helper)
#define PHY_CTRL_UNIT(_pc) ((_pc)->unit)
#define PHY_CTRL_PORT(_pc) ((_pc)->port)
#define PHY_CTRL_FLAGS(_pc) ((_pc)->flags)
#define PHY_CTRL_ADDR(_pc) ((_pc)->addr)
#define PHY_CTRL_ADDR_OFFSET(_pc) ((_pc)->addr_offset)
#define PHY_CTRL_LANE(_pc) ((_pc)->lane)
#define PHY_CTRL_LANE_MASK(_pc) ((_pc)->lane_mask)
#define PHY_CTRL_LINE_INTF(_pc) ((_pc)->line_intf)
#define PHY_CTRL_PRIV(_pc) ((_pc)->priv)

#define PHY_CTRL_BUS_ADDR(_pc) phy_ctrl_addr(_pc, 1)
#define PHY_CTRL_PHY_ADDR(_pc) phy_ctrl_addr(_pc, 0)
#define PHY_CTRL_PHY_INST(_pc) ((_pc)->bus->phy_inst ? \
        (_pc)->bus->phy_inst((_pc)->port) : -1)

/* Provided for backward compatibility */
#define PHY_CTRL_INST(_pc) ((_pc)->bus->phy_inst ? \
        ((_pc)->bus->phy_inst((_pc)->port) | PHY_INST_VALID) : 0)

typedef struct phy_driver_s {
    const char *drv_name;
    const char *drv_desc;
    uint32_t flags; 
    int  (*pd_probe)(phy_ctrl_t *);
    int  (*pd_notify)(phy_ctrl_t *, phy_event_t);
    int  (*pd_reset)(phy_ctrl_t *);
    int  (*pd_init)(phy_ctrl_t *);
    int  (*pd_link_get)(phy_ctrl_t *, int *, int *);
    int  (*pd_duplex_set)(phy_ctrl_t *, int);
    int  (*pd_duplex_get)(phy_ctrl_t *, int *);
    int  (*pd_speed_set)(phy_ctrl_t *, uint32_t);
    int  (*pd_speed_get)(phy_ctrl_t *, uint32_t *);
    int  (*pd_autoneg_set)(phy_ctrl_t *, int);
    int  (*pd_autoneg_get)(phy_ctrl_t *, int *);
    int  (*pd_loopback_set)(phy_ctrl_t *, int);
    int  (*pd_loopback_get)(phy_ctrl_t *, int *);
    int  (*pd_ability_get)(phy_ctrl_t *, uint32_t *);
    int  (*pd_config_set)(phy_ctrl_t *, phy_config_t, uint32_t, void *);
    int  (*pd_config_get)(phy_ctrl_t *, phy_config_t, uint32_t *, void *);
    int  (*pd_status_get)(phy_ctrl_t *, phy_status_t, uint32_t *);
    int  (*pd_cable_diag)(phy_ctrl_t *, phy_port_cable_diag_t *);
} phy_driver_t;

#define PHY_CTRL_CHECK(_pc) \
    do { \
        if (phy_ctrl_check(_pc) < 0) return CDK_E_INTERNAL; \
    } while (0)

#define PHY_BUS_READ(_pc,_r,_v) phy_bus_read(_pc,_r,_v)
#define PHY_BUS_WRITE(_pc,_r,_v) phy_bus_write(_pc,_r,_v)

#define _PHY_CALL(_pc, _pf, _pa) \
        ((_pc) == NULL ? CDK_E_NONE : (_pc)->drv == NULL ? CDK_E_INIT : \
         ((_pc)->drv->_pf == NULL ? CDK_E_UNAVAIL : (_pc)->drv->_pf _pa))

#define PHY_PROBE(_pc) \
        _PHY_CALL((_pc), pd_probe, ((_pc)))

#define PHY_NOTIFY(_pc, _e) \
        _PHY_CALL((_pc), pd_notify, ((_pc), (_e)))

#define PHY_RESET(_pc) \
        _PHY_CALL((_pc), pd_reset, ((_pc)))

#define PHY_INIT(_pc) \
        _PHY_CALL((_pc), pd_init, ((_pc)))

#define PHY_LINK_GET(_pc, _l, _ad) \
        _PHY_CALL((_pc), pd_link_get, ((_pc), (_l), (_ad)))

#define PHY_DUPLEX_SET(_pc, _d) \
        _PHY_CALL((_pc), pd_duplex_set, ((_pc), (_d)))

#define PHY_DUPLEX_GET(_pc, _d) \
        _PHY_CALL((_pc), pd_duplex_get, ((_pc), (_d)))

#define PHY_SPEED_SET(_pc, _s) \
        _PHY_CALL((_pc), pd_speed_set, ((_pc), (_s)))

#define PHY_SPEED_GET(_pc, _s) \
        _PHY_CALL((_pc), pd_speed_get, ((_pc), (_s)))

#define PHY_AUTONEG_SET(_pc, _a) \
        _PHY_CALL((_pc), pd_autoneg_set, ((_pc), (_a)))

#define PHY_AUTONEG_GET(_pc, _a) \
        _PHY_CALL((_pc), pd_autoneg_get, ((_pc), (_a)))

#define PHY_LOOPBACK_SET(_pc, _l) \
        _PHY_CALL((_pc), pd_loopback_set, ((_pc), (_l)))

#define PHY_LOOPBACK_GET(_pc, _l) \
        _PHY_CALL((_pc), pd_loopback_get, ((_pc), (_l)))

#define PHY_ABILITY_GET(_pc, _m) \
        _PHY_CALL((_pc), pd_ability_get, ((_pc), (_m)))

#define PHY_CONFIG_SET(_pc, _c, _v, _cd) \
        _PHY_CALL((_pc), pd_config_set, ((_pc), (_c), (_v), (_cd)))

#define PHY_CONFIG_GET(_pc, _c, _v, _cd) \
        _PHY_CALL((_pc), pd_config_get, ((_pc), (_c), (_v), (_cd)))

#define PHY_STATUS_GET(_pc, _s, _v) \
        _PHY_CALL((_pc), pd_status_get, ((_pc), (_s), (_v)))

#define PHY_CABLE_DIAG(_pc, _status) \
        _PHY_CALL((_pc), pd_cable_diag, ((_pc), (_status)))

extern int
phy_bus_read(phy_ctrl_t *pc, uint32_t reg, uint32_t *data);

extern int
phy_bus_write(phy_ctrl_t *pc, uint32_t reg, uint32_t data);

extern uint32_t
phy_ctrl_addr(phy_ctrl_t *pc, int adjust);

extern int
phy_ctrl_check(phy_ctrl_t *pc);

extern int
phy_ctrl_change_inst(phy_ctrl_t *pc, int new_inst, int (*get_inst)(phy_ctrl_t *));

/*
 * Common debug message interface for PHY drivers that will prefix
 * each message with the PHY driver name and the unit/port.
 */
#define PHY_MSG(_func, _pc, _stuff) do { \
    _func(("%s[%d.%d]: ", (_pc)->drv->drv_name, \
              PHY_CTRL_UNIT(_pc), PHY_CTRL_PORT(_pc))); \
    _func(_stuff); \
} while (0)

#define PHY_WARN(_pc, _stuff) PHY_MSG(CDK_WARN, _pc, _stuff)
#define PHY_VERB(_pc, _stuff) PHY_MSG(CDK_VERB, _pc, _stuff)

#endif /* __PHY_H__ */
