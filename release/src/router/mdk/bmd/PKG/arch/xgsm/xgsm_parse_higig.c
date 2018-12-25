/*
 * $Id: xgsm_parse_higig.c,v 1.1 Broadcom SDK $
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

#ifdef CDK_CONFIG_ARCH_XGSM_INSTALLED

#include <bmd/bmd_device.h>

#include <bmdi/arch/xgsm_dma.h>

#include <cdk/cdk_debug.h>

#if BMD_CONFIG_INCLUDE_HIGIG == 1

/*
 * Function:
 *	bmd_xgsm_parse_higig
 * Purpose:
 *	Parse HiGig header into bmd_pkt_t.
 * Parameters:
 *	unit - BMD device
 *	pkt - BMD packet structure
 *	mh - HiGig/HiGig+ module header (host format)
 * Returns:
 *      CDK_XXX
 */
int
bmd_xgsm_parse_higig(int unit, bmd_pkt_t *pkt, uint32_t *mh)
{
    int rv = CDK_E_NONE;
    HIGIG_t *hg_mh = (HIGIG_t *)mh;

    pkt->mh_src_mod = HIGIG_SRC_MODID_LSf_GET(*hg_mh);
    pkt->mh_src_mod |= (HIGIG_SRC_MODID_5f_GET(*hg_mh) << 5);
    pkt->mh_src_mod |= (HIGIG_SRC_MODID_6f_GET(*hg_mh) << 6);
    pkt->mh_src_port = HIGIG_SRC_PORT_TGIDf_GET(*hg_mh);

    pkt->mh_dst_mod = HIGIG_DST_MODID_LSf_GET(*hg_mh);
    pkt->mh_dst_mod |= (HIGIG_DST_MODID_5f_GET(*hg_mh) << 5);
    pkt->mh_dst_mod |= (HIGIG_DST_MODID_6f_GET(*hg_mh) << 6);
    pkt->mh_dst_port = HIGIG_DST_PORTf_GET(*hg_mh);

    pkt->mh_pkt_type = BMD_PKT_TYPE_FROM_HIGIG(HIGIG_OPCODEf_GET(*hg_mh));

    return rv;
}

#endif
#endif /* CDK_CONFIG_ARCH_XGSM_INSTALLED */
