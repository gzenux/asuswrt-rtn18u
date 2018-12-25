/*
* <:copyright-BRCM:2006:proprietary:standard
* 
*    Copyright (c) 2006 Broadcom 
*    All Rights Reserved
* 
*  This program is the proprietary software of Broadcom and/or its
*  licensors, and may only be used, duplicated, modified or distributed pursuant
*  to the terms and conditions of a separate, written license agreement executed
*  between you and Broadcom (an "Authorized License").  Except as set forth in
*  an Authorized License, Broadcom grants no license (express or implied), right
*  to use, or waiver of any kind with respect to the Software, and Broadcom
*  expressly reserves all rights in and to the Software and all intellectual
*  property rights therein.  IF YOU HAVE NO AUTHORIZED LICENSE, THEN YOU HAVE
*  NO RIGHT TO USE THIS SOFTWARE IN ANY WAY, AND SHOULD IMMEDIATELY NOTIFY
*  BROADCOM AND DISCONTINUE ALL USE OF THE SOFTWARE.
* 
*  Except as expressly set forth in the Authorized License,
* 
*  1. This program, including its structure, sequence and organization,
*     constitutes the valuable trade secrets of Broadcom, and you shall use
*     all reasonable efforts to protect the confidentiality thereof, and to
*     use this information only in connection with your use of Broadcom
*     integrated circuit products.
* 
*  2. TO THE MAXIMUM EXTENT PERMITTED BY LAW, THE SOFTWARE IS PROVIDED "AS IS"
*     AND WITH ALL FAULTS AND BROADCOM MAKES NO PROMISES, REPRESENTATIONS OR
*     WARRANTIES, EITHER EXPRESS, IMPLIED, STATUTORY, OR OTHERWISE, WITH
*     RESPECT TO THE SOFTWARE.  BROADCOM SPECIFICALLY DISCLAIMS ANY AND
*     ALL IMPLIED WARRANTIES OF TITLE, MERCHANTABILITY, NONINFRINGEMENT,
*     FITNESS FOR A PARTICULAR PURPOSE, LACK OF VIRUSES, ACCURACY OR
*     COMPLETENESS, QUIET ENJOYMENT, QUIET POSSESSION OR CORRESPONDENCE
*     TO DESCRIPTION. YOU ASSUME THE ENTIRE RISK ARISING OUT OF USE OR
*     PERFORMANCE OF THE SOFTWARE.
* 
*  3. TO THE MAXIMUM EXTENT PERMITTED BY LAW, IN NO EVENT SHALL BROADCOM OR
*     ITS LICENSORS BE LIABLE FOR (i) CONSEQUENTIAL, INCIDENTAL, SPECIAL,
*     INDIRECT, OR EXEMPLARY DAMAGES WHATSOEVER ARISING OUT OF OR IN ANY
*     WAY RELATING TO YOUR USE OF OR INABILITY TO USE THE SOFTWARE EVEN
*     IF BROADCOM HAS BEEN ADVISED OF THE POSSIBILITY OF SUCH DAMAGES;
*     OR (ii) ANY AMOUNT IN EXCESS OF THE AMOUNT ACTUALLY PAID FOR THE
*     SOFTWARE ITSELF OR U.S. $1, WHICHEVER IS GREATER. THESE LIMITATIONS
*     SHALL APPLY NOTWITHSTANDING ANY FAILURE OF ESSENTIAL PURPOSE OF ANY
*     LIMITED REMEDY.
:>
*/
/***************************************************************************
 * File Name  : mld_snooping.c
 *
 * Description: API for MLD snooping processing
 *              
 ***************************************************************************/
#ifdef SUPPORT_MLD
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include "mcpd.h"
#include "common.h"
#include "mld.h"
#include "mld_snooping.h"
#include "mcpd_nl.h"

extern t_MCPD_ROUTER mcpd_router;

t_MCPD_RET_CODE mcpd_mld_snooping_init(void)
{
   return MCPD_RET_OK;
} /* mcpd_mld_snooping_init */

t_MCPD_RET_CODE mcpd_mld_update_snooping_info(t_MCPD_INTERFACE_OBJ *ifp_in,
                                              t_MCPD_GROUP_OBJ *gp, 
                                              t_MCPD_REP_OBJ *rep,
                                              UINT8 *src,
                                              int mode, 
                                              t_MCPD_PKT_INFO *pkt_info)
{
    t_MCPD_INTERFACE_OBJ *ifp = NULL;
    int idx = 0;

    if(!gp || !rep || !pkt_info)
    {
        MCPD_TRACE(MCPD_TRC_ERR, "invalid snoop entry");
        return MCPD_RET_GENERR;
    }

    struct in6_addr zero_addr = {.s6_addr32 = {0,0,0,0}};
    if (!src)
    {
        src = (UINT8 *)&zero_addr;
    }

    t_MCPD_WAN_INFO_ARRAY wan_info;
    bzero((char *)&wan_info, sizeof(t_MCPD_WAN_INFO_ARRAY));

    for(ifp = mcpd_router.interfaces; ifp; ifp = ifp->next)
    {
        if ((ifp->if_dir == MCPD_UPSTREAM) && (ifp->proto_enable & MCPD_IPV6_MCAST_ENABLE))
        {
            /* add entries for routed and bridge upstream interfaces 
               according to the downstream interface type */
            if((ifp_in->if_type & MCPD_IF_TYPE_ROUTED) &&
               (ifp->if_type & MCPD_IF_TYPE_ROUTED) &&
               (!IN6_IS_ADDR_UNSPECIFIED(&ifp->if_addr6))&&
               (mcpd_is_wan_service_associated_with_bridge(ifp, ifp_in) == MCPD_TRUE))
            {
                wan_info[idx].ifi = ifp->if_index;
                wan_info[idx].if_ops = MCPD_IF_TYPE_ROUTED;
                idx++;
            }

            if((ifp_in->if_type & MCPD_IF_TYPE_BRIDGED) &&
               (ifp->if_type & MCPD_IF_TYPE_BRIDGED) &&
               (MCPD_TRUE == mcpd_is_bridge_member(ifp_in->if_name, ifp->if_index)))
            {
                wan_info[idx].ifi = ifp->if_index;
                wan_info[idx].if_ops = MCPD_IF_TYPE_BRIDGED;
                idx++;
            }
        }

        if(idx >= MCPD_MAX_IFS) 
        {
            MCPD_ASSERT(0);
            break;
        }
    }

    if (bcm_mcast_api_update_mld_snoop(mcpd_router.sock_nl, 
                                       pkt_info->parent_ifi, 
                                       pkt_info->rxdev_ifi, 
                                       pkt_info->tci, 
                                       pkt_info->lanppp, 
                                       (const struct in6_addr *)gp->addr, 
                                       (const struct in6_addr *)src, 
                                       (const struct in6_addr *)rep->addr,
                                       (UINT8 *)pkt_info->repMac,
                                       rep->version,
                                       mode, 
                                       &wan_info) < 0)
    {
        MCPD_TRACE(MCPD_TRC_ERR, "Error while updating snooping info");
        return MCPD_RET_GENERR;
    }

    return MCPD_RET_OK;
} /* mcpd_mld_update_snooping_info */
#endif
