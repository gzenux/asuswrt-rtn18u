/*
 * $Id: bmd_shcmd_phy.c,v 1.32 Broadcom SDK $
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
 * Read and write PHY data.
 */

#include <bmd/bmd.h>
#include <bmd/bmd_phy_ctrl.h>
#include <bmd/shell/shcmd_phy.h>
#include "bmd_shell_util.h"

#define DATA_INVALID 0xffffffff

#if BMD_CONFIG_INCLUDE_PHY == 1

static struct {
    char *str;
    int cfg;
    int sta;
} _pctl[] = {
    /* Config */
    { "enable", PhyConfig_Enable, 0 },
    { "txpreemp", PhyConfig_TxPreemp, 0 },
    { "txidrv", PhyConfig_TxIDrv, 0 },
    { "txpreidrv", PhyConfig_TxPreIDrv, 0 },
    /* Status */
    { "rxeqtuning", PhyStatus_RxEqTuning, 1 },
    { NULL, -1 }
};

static int
_show_phy_info(int unit, int port)
{
    char port_str[16];
    phy_ctrl_t *pc;
    uint32_t phy_addr;
    int px;

    /* Show port number */
    cdk_shell_lport(port_str, sizeof(port_str), unit, port);
    CDK_PRINTF("Port %s\n", port_str);

    pc = BMD_PORT_PHY_CTRL(unit, port);
    px = 0;

    if (pc == NULL) {
        CDK_PRINTF("    (no PHYs)\n");
    }

    while (pc && pc->drv) {
        phy_addr = 0xffff;
        if (pc->bus && pc->bus->phy_addr) {
            phy_addr = pc->bus->phy_addr(port);
        }
        CDK_PRINTF("    PHY[%d] at 0x%04"PRIx32": %s\n",
                   px, phy_addr, pc->drv->drv_name);
        pc = pc->next;
        px++;
    }

    return 0;
}
#endif /* BMD_CONFIG_INCLUDE_PHY */

int 
bmd_shcmd_phy(int argc, char* argv[])
{
    int rv = CDK_E_NONE;
#if BMD_CONFIG_INCLUDE_PHY == 1
    int unit;
    int ax, px, idx, dax;
    cdk_pbmp_t pbmp;
    int lport, port = -1;
    int phy_idx = -1;
    int reg = -1;
    int devad = -1;
    int reg_min, reg_max;
    uint32_t data = DATA_INVALID;
    uint32_t rdata;
    uint32_t devad_offset;
    uint32_t c45_devs;
    char *str;
    char tmp_str[16];
    phy_ctrl_t *pc;

    unit = cdk_shell_unit_arg_extract(&argc, argv, 1);

    if (!CDK_DEV_EXISTS(unit)) {
        return cdk_shell_error(CDK_E_UNIT);
    }

    if (argc == 0) {
        return CDK_SHELL_CMD_BAD_ARG;
    }

    if (CDK_STRCMP(argv[0], "ctrl") == 0) {
        if (argc < 4) {
            CDK_PRINTF("Supported PHY controls:\n");
            idx = 0;
            while (_pctl[idx].str != NULL) {
                CDK_PRINTF("%-16s (%s)\n",
                           _pctl[idx].str,
                           _pctl[idx].sta ? "status" : "config");
                idx++;
            }
            return CDK_SHELL_CMD_OK;
        }
        ax = 1;
        port = CDK_PORT_MAP_L2P(unit, CDK_STRTOL(argv[ax++], NULL, 0));
        phy_idx = CDK_STRTOL(argv[ax++], NULL, 0);
        idx = 0;
        str = argv[ax++];
        while (_pctl[idx].str != NULL) {
            if (CDK_STRCASECMP(str, _pctl[idx].str) == 0) {
                break;
            }
            idx++;
        }
        if (_pctl[idx].str == NULL) {
            return CDK_SHELL_CMD_BAD_ARG;
        }
        px = 0;
        pc = BMD_PORT_PHY_CTRL(unit, port);
        while (pc && pc->drv) {
            if (phy_idx == px) {
                if (ax == argc) {
                    if (_pctl[idx].sta) {
                        rv = PHY_STATUS_GET(pc, _pctl[idx].cfg, &data);
                    } else {
                        rv = PHY_CONFIG_GET(pc, _pctl[idx].cfg, &data, NULL);
                    }
                    if (CDK_SUCCESS(rv)) {
                        cdk_shell_lport(tmp_str, sizeof(tmp_str), unit, port);
                        CDK_PRINTF("Port %s:\n", tmp_str);
                        CDK_PRINTF("    PHY[0]: %s\n", pc->drv->drv_name);
                        CDK_PRINTF("\t%s = 0x%"PRIx32"  (%"PRIu32")\n",
                                   _pctl[idx].str, data, data);
                    }
                } else {
                    data = CDK_STRTOUL(argv[ax], NULL, 0);
                    rv = PHY_CONFIG_SET(pc, _pctl[idx].cfg, data, NULL);
                }
            }
            pc = pc->next;
            px++;
        }
        return cdk_shell_error(rv);
    }

    if (CDK_STRCMP(argv[0], "probe") == 0) {
        if (argc != 1) {
            return CDK_SHELL_CMD_BAD_ARG;
        }
        for (port = 0; port < BMD_CONFIG_MAX_PORTS; port++) {
            bmd_phy_probe(unit, port);
        }
        return cdk_shell_error(CDK_E_NONE);
    }

    if (CDK_STRCMP(argv[0], "info") == 0) {
        if (argc != 1 && argc != 2) {
            return CDK_SHELL_CMD_BAD_ARG;
        }
        if (argc == 1) {
            bmd_port_type_pbmp(unit, BMD_PORT_ALL, &pbmp);
        } else {
            if (bmd_shell_parse_port_str(unit, argv[1], &pbmp) < 0) {
                return CDK_SHELL_CMD_BAD_ARG;
            }
        }
        CDK_LPORT_ITER(unit, pbmp, lport, port) {
            _show_phy_info(unit, port);
        }
        return cdk_shell_error(CDK_E_NONE);
    }

    for (ax = 0; ax < argc; ax++) {
        if (port < 0) {
            port = CDK_STRTOL(argv[ax], NULL, 0);
        } else if (phy_idx < 0) {
            phy_idx = CDK_STRTOL(argv[ax], NULL, 0);
            /* Look for phy_idx.devad format */
            if ((str = CDK_STRSTR(argv[ax], ".")) != NULL) {
                devad = CDK_STRTOL(&str[1], NULL, 0);
            }
        } else if (reg < 0) {
#if CDK_CONFIG_INCLUDE_CHIP_SYMBOLS == 1 && PHY_CONFIG_INCLUDE_CHIP_SYMBOLS == 1
            if (!cdk_shell_parse_is_int(argv[ax])) {
                /*
                 * If the register address argument is not an integer
                 * then attempt symbolic decoding.
                 */
                pc = BMD_PORT_PHY_CTRL(unit, CDK_PORT_MAP_L2P(unit, port));
                px = 0;
                while (pc && pc->drv) {
                    if (phy_idx == px) {
                        rv = bmd_shell_phy_sym(pc, argc-ax, &argv[ax]);
                        return cdk_shell_error(rv);
                    }
                    pc = pc->next;
                    px++;
                }
                return CDK_SHELL_CMD_BAD_ARG;
            }
#endif
            reg = CDK_STRTOL(argv[ax], NULL, 0);
        } else if (data == DATA_INVALID) {
            data = CDK_STRTOUL(argv[ax], NULL, 0);
        } else {
            return CDK_SHELL_CMD_BAD_ARG;
        }
    }

    port = CDK_PORT_MAP_L2P(unit, port);

    if (port < 0) {
        return CDK_SHELL_CMD_BAD_ARG;
    }

    pc = BMD_PORT_PHY_CTRL(unit, port);
    px = 0;

    /* Show port number if read */
    if (data == DATA_INVALID) {
        cdk_shell_lport(tmp_str, sizeof(tmp_str), unit, port);
        CDK_PRINTF("Port %s\n", tmp_str);
    }

    while (pc && pc->drv) {
        if (phy_idx < 0 || phy_idx == px) {
            reg_min = 0;
            /* Check for clause 45 devices present */
            if (CDK_FAILURE(
                PHY_CONFIG_GET(pc, PhyConfig_Clause45Devs, &c45_devs, NULL))) {
                c45_devs = 0;
            }
            /* Loop over PHY devices */
            for (dax = 0; dax < 32; dax++) {
                /* If clause 22 then break after first iteration */
                if (c45_devs == 0 && dax > 0) {
                    break;
                }
                /* If access method specified then ignore DEVAD */
                if (reg >= 0 && PHY_REG_ACCESS_METHOD(reg) != 0) {
                    devad_offset = 0;
                    /* Break after first iteration */
                    if (dax > 0) {
                        break;
                    }
                } else {
                    /* If devad specified then loop until match */
                    if (devad >= 0 && devad != dax) {
                        continue;
                    }
                    /* If devad not specified then loop over devices present */
                    if (c45_devs && (c45_devs & (1 << dax)) == 0) {
                        continue;
                    }
                    /* Put devad in upper 16 bits */
                    devad_offset = LSHIFT32(dax, 16);
                }
                if (data != DATA_INVALID) {
                    /* Write data and exit loops */
                    rv = phy_reg_write(pc, reg + devad_offset, data);
                    break;
                }
                /* Show all 32 registers by default */
                reg_max = 0x1f;
                /* Show only first 16 registers if valid clause 45 device */
                if (c45_devs && dax > 0) {
                    reg_max = 0xf;
                }
                /* Print clause 45 device name */
                if (c45_devs) {
                    CDK_SPRINTF(tmp_str, ".%d", dax);
                    switch (dax) {
                    case 1: str = "(PMA/PMD)"; break;
                    case 2: str = "(WIS)"; break;
                    case 3: str = "(PCS)"; break;
                    case 4: str = "(PHY XS)"; break;
                    case 5: str = "(DTE XS)"; break;
                    case 6: str = "(TC)"; break;
                    case 7: str = "(AN)"; break;
                    case 29: str = "(Clause 22)"; break;
                    case 30: str = "(Vendor 1)"; break;
                    case 31: str = "(Vendor 2)"; break;
                    default: str = "(Reserved)"; break;
                    }
                } else {
                    tmp_str[0] = 0;
                    str = "";
                }
                CDK_PRINTF("    PHY[%d%s]: %s %s\n",
                           px, tmp_str, pc->drv->drv_name, str);
                /* If reg specified then show this reg only */
                if (reg >= 0) {
                    reg_min = reg_max = reg;
                }
                /* Loop over PHY registers */
                for (idx = reg_min; idx <= reg_max; idx++) {
                    phy_reg_read(pc, idx + devad_offset, &rdata);
                    CDK_PRINTF("\t0x%02x: 0x%04"PRIx32"", idx, rdata);
                    if (reg == idx || (idx & 3) == 3) {
                        CDK_PRINTF("\n");
                    }
                }
            }
        }
        pc = pc->next;
        px++;
    }
#else
    CDK_PRINTF("No PHY support.\n"); 
#endif /* BMD_CONFIG_INCLUDE_PHY */

    return cdk_shell_error(rv);
}
