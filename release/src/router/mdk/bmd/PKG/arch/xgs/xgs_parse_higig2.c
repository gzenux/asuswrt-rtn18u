/*
 * $Id: xgs_parse_higig2.c,v 1.5 Broadcom SDK $
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

#ifdef CDK_CONFIG_ARCH_XGS_INSTALLED

#include <bmd/bmd_device.h>

#include <bmdi/arch/xgs_dma.h>

#include <cdk/cdk_debug.h>

#if BMD_CONFIG_INCLUDE_HIGIG

/*
 * Function:
 *	bmd_xgs_parse_higig2
 * Purpose:
 *	Parse HiGig2 header into bmd_pkt_t.
 * Parameters:
 *	unit - BMD device
 *	pkt - BMD packet structure
 *	mh - HiGig2 module header (host format)
 * Returns:
 *      CDK_XXX
 */
int
bmd_xgs_parse_higig2(int unit, bmd_pkt_t *pkt, uint32_t *mh)
{
    int rv = CDK_E_NONE;
    HIGIG2_t *hg2_mh = (HIGIG2_t *)mh;
    int opcode;

    pkt->mh_src_mod = HIGIG2_SRC_MODIDf_GET(*hg2_mh);
    pkt->mh_src_port = HIGIG2_SRC_PIDf_GET(*hg2_mh);

    pkt->mh_dst_mod = HIGIG2_DST_MODID_MGIDHf_GET(*hg2_mh);
    pkt->mh_dst_port = HIGIG2_DST_PORT_MGIDLf_GET(*hg2_mh);

    opcode = HIGIG2_PPD0_OPCODEf_GET(*hg2_mh);
    pkt->mh_pkt_type = BMD_PKT_TYPE_FROM_HIGIG(opcode);

    return rv;
}

#endif
#endif /* CDK_CONFIG_ARCH_XGS_INSTALLED */
