#include <bmd_config.h>
#if CDK_CONFIG_INCLUDE_BCM53280_A0 == 1

/*
 * $Id: bcm53280_a0_bmd_init.c,v 1.7 Broadcom SDK $
 * 
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

#include <bmd/bmd.h>
#include <bmd/bmd_device.h>

#include <cdk/chip/bcm53280_a0_defs.h>
#include <cdk/arch/robo_chip.h>

#include "bcm53280_a0_bmd.h"
#include "bcm53280_a0_internal.h"

#define CDK_ROBO_FLAGS(unit) (CDK_ROBO_INFO(unit)->flags)

static int
_epic_init(int unit, int port)
{
    int ioerr = 0;
    TH_PCTLr_t th_pctl;
    STS_OVERRIDE_Pr_t sts_override_p;

    /* Clear link status */
    ioerr += READ_STS_OVERRIDE_Pr(unit, port, &sts_override_p);
    STS_OVERRIDE_Pr_LINK_STSf_SET(sts_override_p, 0);
    ioerr += WRITE_STS_OVERRIDE_Pr(unit, port, sts_override_p);

    /* Set forwarding state */
    ioerr += READ_TH_PCTLr(unit, port, &th_pctl);
    TH_PCTLr_STP_STATEf_SET(th_pctl, 3);
    ioerr += WRITE_TH_PCTLr(unit, port, th_pctl);

    return ioerr;
}

static int
_gpic_init(int unit, int port)
{
    int ioerr = 0;
    G_PCTLr_t g_pctl;
    STS_OVERRIDE_GPr_t sts_override_gp;

    /* Clear link status */
    ioerr += READ_STS_OVERRIDE_GPr(unit, port, &sts_override_gp);
    STS_OVERRIDE_GPr_LINK_STSf_SET(sts_override_gp, 0);
    ioerr += WRITE_STS_OVERRIDE_GPr(unit, port, sts_override_gp);

    /* Set forwarding state */
    ioerr += READ_G_PCTLr(unit, port, &g_pctl);
    G_PCTLr_G_STP_STATEf_SET(g_pctl, 3);
    ioerr += WRITE_G_PCTLr(unit, port, g_pctl);

    return ioerr;
}

int
bcm53280_a0_bmd_init(int unit)
{
    int ioerr = 0;
    int rv = CDK_E_NONE;
    MST_CONr_t mst_con;
    SWMODEr_t swmode;
    GMNGCFGr_t gmngcfg;
    STS_OVERRIDE_IMPr_t sts_override_imp; 
    IMP_PCTLr_t imp_pctl;
    PHYSCAN_CTLr_t physcan_ctrl;
    RST_TABLE_MEMr_t rst_table_mem;
    NEW_CONTROLr_t new_ctrl;
    SW_XOFF_PORT_CTLr_t sw_xoff_port_ctl;
    VLAN_GLOBAL_CTLr_t vlan_global_ctl;
    GLB_VLAN_ING_FILTER_CTLr_t glb_vlan_ing;
    MEM_INDEXr_t mem_index;
    MEM_CTRLr_t mem_ctrl;
    MEM_ADDR_0r_t mem_addr_0;
    MEM_DATA_0r_t mem_data_0;
    MEM_DATA_1r_t mem_data_1;
    uint32_t fval0[2]; 
    uint32_t fval1[2]; 
    int cnt;    
    int port, retry;
    cdk_pbmp_t pbmp;
    
    BMD_CHECK_UNIT(unit);

    /* bcm53280 VLAN not need to enable */
    /* Enable spanning tree */
    READ_MST_CONr(unit, &mst_con);
    MST_CONr_EN_802_1Sf_SET(mst_con, 1);
    WRITE_MST_CONr(unit, mst_con);
    /* Configure EPICs */
    CDK_ROBO_BLKTYPE_PBMP_GET(unit, BLKTYPE_EPIC, &pbmp);
    CDK_PBMP_ITER(pbmp, port) {
        ioerr += _epic_init(unit, port);
        if (CDK_SUCCESS(rv)) {
            rv = bmd_phy_attach(unit, port);
        }
    }
    /* Configure GPICs */
    CDK_ROBO_BLKTYPE_PBMP_GET(unit, BLKTYPE_GPIC, &pbmp);
    CDK_PBMP_ITER(pbmp, port) {
        ioerr += _gpic_init(unit, port);
        if (CDK_SUCCESS(rv)) {
            rv = bmd_phy_attach(unit, port);
        }
    }
    /* dma init */
    /* Enable frame forwarding */
    READ_SWMODEr(unit, &swmode);
    SWMODEr_SW_FWDG_MODEf_SET(swmode, 1);
    SWMODEr_SW_FWDG_ENf_SET(swmode, 1);
    WRITE_SWMODEr(unit, swmode);
    ioerr += READ_STS_OVERRIDE_IMPr(unit, &sts_override_imp);
    STS_OVERRIDE_IMPr_SW_OVERRIDEf_SET(sts_override_imp, 1);    
    STS_OVERRIDE_IMPr_SPEEDf_SET(sts_override_imp, 1);    
    STS_OVERRIDE_IMPr_DUPLX_MODEf_SET(sts_override_imp, 1);    
    STS_OVERRIDE_IMPr_LINK_STSf_SET(sts_override_imp, 1);
    ioerr += WRITE_STS_OVERRIDE_IMPr(unit, sts_override_imp);

    ioerr += READ_IMP_PCTLr(unit, &imp_pctl);
    IMP_PCTLr_RX_UC_DLF_ENf_SET(imp_pctl, 1);
    IMP_PCTLr_RX_MC_DLF_ENf_SET(imp_pctl, 1);
    IMP_PCTLr_RX_BC_ENf_SET(imp_pctl, 1);
    ioerr += WRITE_IMP_PCTLr(unit, imp_pctl);

    /* Enable management port */
    ioerr += READ_GMNGCFGr(unit, &gmngcfg);
    GMNGCFGr_FRM_MNGPf_SET(gmngcfg, 2);
    GMNGCFGr_RX_BPDU_ENf_SET(gmngcfg, 1);
    ioerr += WRITE_GMNGCFGr(unit, gmngcfg);
    /* end dma init */

    /* misc init */
    /* Disable PHY auto-scan */
    ioerr += READ_PHYSCAN_CTLr(unit, &physcan_ctrl);
    PHYSCAN_CTLr_EN_PHY_SCANf_SET(physcan_ctrl, 1);
    ioerr += WRITE_PHYSCAN_CTLr(unit, physcan_ctrl);
    /* TB misc_init :
     *  1. Port Mask table reset.
     *  2. Flow Control init :
     *      - global XOFF enable.
     *      - Port basis XOFF disable.
     *  3. User MAC address
     */
    /* Port Mask table reset. */   
    ioerr += READ_RST_TABLE_MEMr(unit, &rst_table_mem);
    RST_TABLE_MEMr_RST_PORT_MASKf_SET(rst_table_mem, 1);
    ioerr += WRITE_RST_TABLE_MEMr(unit, rst_table_mem);
    /* wait for complete */
    for (retry = 0; retry < 100; retry++) {
        ioerr += READ_RST_TABLE_MEMr(unit, &rst_table_mem);
        if (!(RST_TABLE_MEMr_RST_PORT_MASKf_GET(rst_table_mem))) {
            break;
        }
    }
    if (retry >= 100) {
        ioerr += CDK_E_TIMEOUT;
    }

    /* Flow control init : enable global XOFF */ 
    ioerr += READ_NEW_CONTROLr(unit, &new_ctrl);
    NEW_CONTROLr_EN_SW_FLOW_CONf_SET(new_ctrl, 1);
    ioerr += WRITE_NEW_CONTROLr(unit, new_ctrl);
    /* Flow control init : diable XOFF on each port */
    SW_XOFF_PORT_CTLr_SET(sw_xoff_port_ctl, 0, 0);
    ioerr += WRITE_SW_XOFF_PORT_CTLr(unit, sw_xoff_port_ctl);
    /* end misc init */
    

    /* -- get the MAC and VID for search -- 
     *  1. check SVL/IVL mode first for the VID desicion.!
     */
    ioerr += READ_VLAN_GLOBAL_CTLr(unit, &vlan_global_ctl);
    VLAN_GLOBAL_CTLr_VID_MAC_CTRLf_SET(vlan_global_ctl, 1);
    ioerr += WRITE_VLAN_GLOBAL_CTLr(unit, vlan_global_ctl);
    
    ioerr += READ_GLB_VLAN_ING_FILTER_CTLr(unit, &glb_vlan_ing);
    GLB_VLAN_ING_FILTER_CTLr_EN_UNREGISTERED_DROPf_SET(glb_vlan_ing, 1);
    ioerr += WRITE_GLB_VLAN_ING_FILTER_CTLr(unit, glb_vlan_ing);

    /* Select EVM table  */
    ioerr += READ_MEM_INDEXr(unit, &mem_index);
    MEM_INDEXr_INDEXf_SET(mem_index, 0x30);
    ioerr += WRITE_MEM_INDEXr(unit, mem_index);

    /* Set MEM_ADDR_0 to read, Addr = 0x10 */
    MEM_ADDR_0r_MEM_ADDR_OFFSETf_SET(mem_addr_0, 0);
    ioerr += WRITE_MEM_ADDR_0r(unit, mem_addr_0);

    /* Write */
    /* Set content from MEM_DATA */
    fval0[0] = 0x60000000;
    fval0[1] = 0x20000;
    fval1[0] = 0xfc000000;
    fval1[1] = 0x20000;
    MEM_DATA_0r_MEM_DATAf_SET(mem_data_0, &fval0[0]);
    ioerr += WRITE_MEM_DATA_0r(unit, mem_data_0);
    MEM_DATA_1r_MEM_DATAf_SET(mem_data_1, &fval1[0]);
    ioerr += WRITE_MEM_DATA_1r(unit, mem_data_1);

    /* Set MEM_CTRL, OP_CMD=0x02 MEM_STDN=1 */
    ioerr += READ_MEM_CTRLr(unit, &mem_ctrl);
    MEM_CTRLr_OP_CMDf_SET(mem_ctrl, 0x02);
    MEM_CTRLr_MEM_STDNf_SET(mem_ctrl, 1);
    ioerr += WRITE_MEM_CTRLr(unit, mem_ctrl);

    cnt = 0;
    while (cnt++ < 100) {
        ioerr += READ_MEM_CTRLr(unit, &mem_ctrl);
        if (ioerr == 0 && 
            MEM_CTRLr_MEM_STDNf_GET(mem_ctrl) == 0) {
            break;
        }
    }
    if (cnt >= 100) {
        ioerr += CDK_E_TIMEOUT;
    }
    
    
    return ioerr ? CDK_E_IO : rv;
}
#endif /* CDK_CONFIG_INCLUDE_BCM53280_A0 */
