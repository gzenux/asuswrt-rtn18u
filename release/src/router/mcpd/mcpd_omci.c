/***********************************************************************
 *
 *  Copyright (c) 2006  Broadcom Corporation
 *  All Rights Reserved
 *
<:label-BRCM:2012:proprietary:standard

 This program is the proprietary software of Broadcom and/or its
 licensors, and may only be used, duplicated, modified or distributed pursuant
 to the terms and conditions of a separate, written license agreement executed
 between you and Broadcom (an "Authorized License").  Except as set forth in
 an Authorized License, Broadcom grants no license (express or implied), right
 to use, or waiver of any kind with respect to the Software, and Broadcom
 expressly reserves all rights in and to the Software and all intellectual
 property rights therein.  IF YOU HAVE NO AUTHORIZED LICENSE, THEN YOU HAVE
 NO RIGHT TO USE THIS SOFTWARE IN ANY WAY, AND SHOULD IMMEDIATELY NOTIFY
 BROADCOM AND DISCONTINUE ALL USE OF THE SOFTWARE.

 Except as expressly set forth in the Authorized License,

 1. This program, including its structure, sequence and organization,
    constitutes the valuable trade secrets of Broadcom, and you shall use
    all reasonable efforts to protect the confidentiality thereof, and to
    use this information only in connection with your use of Broadcom
    integrated circuit products.

 2. TO THE MAXIMUM EXTENT PERMITTED BY LAW, THE SOFTWARE IS PROVIDED "AS IS"
    AND WITH ALL FAULTS AND BROADCOM MAKES NO PROMISES, REPRESENTATIONS OR
    WARRANTIES, EITHER EXPRESS, IMPLIED, STATUTORY, OR OTHERWISE, WITH
    RESPECT TO THE SOFTWARE.  BROADCOM SPECIFICALLY DISCLAIMS ANY AND
    ALL IMPLIED WARRANTIES OF TITLE, MERCHANTABILITY, NONINFRINGEMENT,
    FITNESS FOR A PARTICULAR PURPOSE, LACK OF VIRUSES, ACCURACY OR
    COMPLETENESS, QUIET ENJOYMENT, QUIET POSSESSION OR CORRESPONDENCE
    TO DESCRIPTION. YOU ASSUME THE ENTIRE RISK ARISING OUT OF USE OR
    PERFORMANCE OF THE SOFTWARE.

 3. TO THE MAXIMUM EXTENT PERMITTED BY LAW, IN NO EVENT SHALL BROADCOM OR
    ITS LICENSORS BE LIABLE FOR (i) CONSEQUENTIAL, INCIDENTAL, SPECIAL,
    INDIRECT, OR EXEMPLARY DAMAGES WHATSOEVER ARISING OUT OF OR IN ANY
    WAY RELATING TO YOUR USE OF OR INABILITY TO USE THE SOFTWARE EVEN
    IF BROADCOM HAS BEEN ADVISED OF THE POSSIBILITY OF SUCH DAMAGES;
    OR (ii) ANY AMOUNT IN EXCESS OF THE AMOUNT ACTUALLY PAID FOR THE
    SOFTWARE ITSELF OR U.S. $1, WHICHEVER IS GREATER. THESE LIMITATIONS
    SHALL APPLY NOTWITHSTANDING ANY FAILURE OF ESSENTIAL PURPOSE OF ANY
    LIMITED REMEDY.
:>
 *
 ************************************************************************/
/***************************************************************************
 * File Name  : mcpd_omci.c
 *
 * Description: API for IGMP/OMCI operations
 *              
 ***************************************************************************/
#include <string.h>
#include <strings.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <net/if.h>
#include "cms.h"
#include "cms_msg.h"
#include "cms_tms.h"
#include "cms_log.h"
#include "mcpd.h"
#include "common.h"
#include "igmp_snooping.h"
#include "mcpd_nl.h"
#include "mcpd_omci.h"
#include "mcpd_main.h"
#include "obj_hndlr.h"

extern t_MCPD_ROUTER mcpd_router;
extern void *mcpdMsgHandle;

t_MCPD_RET_CODE mcpd_send_omcid_igmp_msg(const OmciIgmpMsgBody *msgBody);

t_MCPD_RET_CODE mcpd_omci_igmp_admission_control(int msg_type,
                                            int rxdev_ifi,
                                            UINT8 *gp,
                                            UINT8 *src,
                                            UINT8 *rep,
                                            unsigned short tci,
                                            UINT8 rep_proto_ver)
{
    t_MCPD_RET_CODE ret = MCPD_RET_OK;
    OmciIgmpMsgBody omci_obj;
    char ifname[IFNAMSIZ];
    char pname[IFNAMSIZ];
    int port;

    if (0 == mcpd_router.igmp_config.admission_required)
    {
        return ret;
    }

    switch ( msg_type )
    {
        case MCPD_ADMISSION_JOIN:
            msg_type = OMCI_IGMP_MSG_JOIN;
            break;
        case MCPD_ADMISSION_RE_JOIN:
            msg_type = OMCI_IGMP_MSG_RE_JOIN;
            break;
        case MCPD_ADMISSION_LEAVE:
            msg_type = OMCI_IGMP_MSG_LEAVE;
            break;
        default:
            return MCPD_RET_GENERR;
    }

    if ( if_indextoname(rxdev_ifi, ifname) == NULL )
    {
        return MCPD_RET_GENERR;
    }

    /* omcid does not support wl as of now */
    if(strncmp(ifname, "wl", 2) == 0)
        return ret;

    memset(&omci_obj, 0, sizeof(OmciIgmpMsgBody));

    omci_obj.tci = tci;
    if(src)
        omci_obj.sourceIpAddress = (UINT32)(((struct in_addr *)src)->s_addr);
    else
        omci_obj.sourceIpAddress = 0;
    omci_obj.groupIpAddress = (UINT32)(((struct in_addr *)gp)->s_addr);
    omci_obj.clientIpAddress = (UINT32)(((struct in_addr *)rep)->s_addr);
    if(strncmp(ifname, "eth", 3) == 0 || strncmp(ifname, "sid", 3) == 0)
    {                
        omci_obj.phyType = OMCI_IGMP_PHY_ETHERNET;
        sscanf(ifname, "%c%c%c%d", &pname[0], &pname[1], 
                                              &pname[2], &port);
        omci_obj.phyPort = port;
    }
    else if(strncmp(ifname, "wl", 2) == 0)
    {
        omci_obj.phyType = OMCI_IGMP_PHY_WIRELESS;
        sscanf(ifname, "%c%c%d", &pname[0], &pname[1], &port);
        omci_obj.phyPort = port;
    }
    else if(strncmp(ifname, "gpon", 4) == 0)
    {
        omci_obj.phyType = OMCI_IGMP_PHY_GPON;
        sscanf(ifname, "%c%c%c%c%d", &pname[0], &pname[1], 
                                                &pname[2], &pname[3],
                                                &port);
        omci_obj.phyPort = port;
    }
    else if(strncmp(ifname, "moca", 4) == 0)
    {
        omci_obj.phyType = OMCI_IGMP_PHY_MOCA;
        sscanf(ifname, "%c%c%c%c%d", &pname[0], &pname[1], 
                                                &pname[2], &pname[3],
                                                &port);
        omci_obj.phyPort = port;
    }
    else
    {
        omci_obj.phyType = OMCI_IGMP_PHY_NONE;
        omci_obj.phyPort = 0;
    }
    omci_obj.msgType = msg_type;
    omci_obj.igmpVersion = rep_proto_ver;

    return mcpd_send_omcid_igmp_msg(&omci_obj);
} /* mcpd_omci_igmp_admission_control */

t_MCPD_RET_CODE mcpd_send_omcid_igmp_msg(const OmciIgmpMsgBody *msgBody)
{
    CmsRet ret = CMSRET_SUCCESS;
    t_MCPD_RET_CODE rv;
    char buf[sizeof(CmsMsgHeader) + sizeof(OmciIgmpMsgBody)];
    CmsMsgHeader *msgReq=(CmsMsgHeader *) buf;
    OmciIgmpMsgBody *bodyReq = (OmciIgmpMsgBody *) (msgReq+1);

    memset(buf, 0, sizeof(CmsMsgHeader) + sizeof(OmciIgmpMsgBody));

    msgReq->type = CMS_MSG_OMCI_IGMP_ADMISSION_CONTROL;
    msgReq->src = EID_MCPD;
    msgReq->dst = EID_OMCID;
    msgReq->dataLength = sizeof(OmciIgmpMsgBody);
    msgReq->flags_request = 1;

    memcpy(bodyReq, msgBody, sizeof(OmciIgmpMsgBody));

    ret = cmsMsg_sendAndGetReplyWithTimeout(mcpdMsgHandle,
                                                msgReq,
                                                5*MSECS_IN_SEC);
    if (ret == CMSRET_SUCCESS)
    {
        cmsLog_notice("CMS_MSG_OMCI_IGMP_ADMISSION_CONTROL ok");
        rv = MCPD_RET_OK;
    }
    else if (ret == CMSRET_OBJECT_NOT_FOUND)
    {
        cmsLog_notice("CMS_MSG_OMCI_IGMP_ADMISSION_CONTROL failed, ret=%d", ret);
        rv = MCPD_RET_GENERR;
    }
    else
    {
        cmsLog_error("CMS_MSG_OMCI_IGMP_ADMISSION_CONTROL failed, ret=%d", ret);
        rv = MCPD_RET_GENERR;
    }

    return rv;
} /* mcpd_send_omcid_igmp_msg */

t_MCPD_RET_CODE mcpd_omci_mib_reset_handler(void)
{
    /* clean up all objects and flush snooping entries but do not 
       delete the interface */
    mcpd_interface_cleanup(NULL, 0, 1, MCPD_PROTO_MAX);

    /* cleanup all mcast forwarding entries*/
    if(bcm_mcast_api_fdb_cleanup(mcpd_router.sock_nl) < 0)
    {
        MCPD_TRACE(MCPD_TRC_ERR, "Error while sending clean up msg");
        return MCPD_RET_GENERR;
    }

    return MCPD_RET_OK;
} /* mcpd_omci_mib_reset_handler*/
