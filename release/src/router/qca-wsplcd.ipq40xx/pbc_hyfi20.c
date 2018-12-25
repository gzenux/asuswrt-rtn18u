/* @File: pbc_hyfi20.c  
 * @Notes:
 *
 * Copyright (c) 2011-2012 Qualcomm Atheros, Inc.
 * Qualcomm Atheros Confidential and Proprietary. 
 * All rights reserved.
 *
 */

#include "wsplcd.h"
#include "apclone.h"
#include "eloop.h"
#include "legacy_ap.h"
#include <fcntl.h>
#include <linux/wireless.h>
//#include <ath_ald_external.h>
#include <ieee80211_external.h>

#include "apac_priv.h"
#include "apac_hyfi20_wps.h"
#include "apac_hyfi20_mib.h"
#include "apac_hyfi20_ctrl.h"
/* This seems stupid, I will change this later. */
#ifdef ENABLE_PLC
#include "service_message.h"
#endif /* ENABLE_PLC */


extern apacHyfi20GlobalState_t apacS;

#ifdef ENABLE_PLC
void plcActivateSimpleConnect(apacHyfi20Data_t *pData) {
    struct sockaddr_un PlcClientAddr = {
        AF_UNIX,
        "/var/run/plc_socket_server"
    };
    char ServiceMsgFrame [SM_FRAME_LEN_MAX] = {
    };
    struct service_message *PtrServiceMsg = (struct service_message *)ServiceMsgFrame;
    
    apacHyfi20TRACE();

    memset(ServiceMsgFrame, 0, sizeof ServiceMsgFrame);
    PtrServiceMsg->cmd = SM_ACTIVATE_SIMPLE_CONNECT;
    if (sendto (pData->unPlcSock, ServiceMsgFrame, sizeof ServiceMsgFrame, 0, (struct sockaddr *) (&PlcClientAddr),
                    (socklen_t) (sizeof(PlcClientAddr)))  < 0) {
        perror("plcActivateSimpleConnect - sendto");
    }
    return;
}
#endif

/*
 * Wrapper functions
 */
void pbcActivateWifiWpsSta(apacHyfi20IF_t *pIF) { 
    
    apac_ctrl_activate_PBC(pIF); 
}

void pbcActivateWifiWpsAp(apacHyfi20IF_t *pIF) {
    
    apac_ctrl_activate_PBC(pIF); 
}

#ifdef ENABLE_PLC
void pbcActivatePlcSimpleConnect(apacHyfi20Data_t *pData) {
    
    plcActivateSimpleConnect(pData);
}

int pbcConvertPlcAvlnFromStr(char *str, u8 *plcAvln) {
    int i;
    unsigned int byte;
    char *ptr;

    if (!str || !plcAvln) {
        dprintf(MSG_ERROR, "%s, empty buffer!\n", __func__);
        return -1;
    }

    dprintf(MSG_DEBUG, "AVLN string: %s\n", str);
    
    ptr = str;
    for (i = 0; i < AVLN_LEN; i++) {
        if (sscanf(ptr, "%2x", &byte) != 1) {
            dprintf(MSG_ERROR, "%s, Invalid Address: %s\n", __func__, ptr);
            return -1;
        }
        plcAvln[i] = byte;
        ptr += 2;
    }
    printAvln(MSG_DEBUG, plcAvln);

    return 0;
}

apacBool_e pbcIsSimpleConnectRunning(apacHyfi20Data_t *pData, u8 *plcSmplStat) {

    struct sockaddr_un PlcClientAddr = {
        AF_UNIX,
        "/var/run/plc_socket_server"
    };
    char ServiceMsgFrame [SM_FRAME_LEN_MAX] = {
    };
    struct service_message *PtrServiceMsg = (struct service_message *)ServiceMsgFrame;
    struct pollfd pollfd = {
        pData->unPlcSock,
        POLLIN,
        0
    };

    //printf("%s, SM_SIMPLE_CONNECT_IDLE: %d, SM_SIMPLE_CONNECT_IN_PROGRESS: %d\n", __func__, SM_SIMPLE_CONNECT_IDLE, SM_SIMPLE_CONNECT_IN_PROGRESS);

    memset(ServiceMsgFrame, 0, sizeof ServiceMsgFrame);
    PtrServiceMsg->cmd = SM_GET_SIMPLE_CONNECT_STATE;
    if (sendto (pData->unPlcSock, ServiceMsgFrame, sizeof ServiceMsgFrame, 0, (struct sockaddr *) (&PlcClientAddr),
                    (socklen_t) (sizeof(PlcClientAddr)))  < 0) {
        perror("pbcIsSimpleConnectRunning - sendto");
        return APAC_FALSE;
    }
    if(poll (&pollfd, 1, 100) == 1)
    {
        if(recvfrom (pData->unPlcSock, ServiceMsgFrame, sizeof ServiceMsgFrame, 0, (struct sockaddr *) (0), (socklen_t *)(0)) >0)
        {
            if(PtrServiceMsg->cmd == SM_SIMPLE_CONNECT_IDLE)
            {
                *plcSmplStat = SM_SIMPLE_CONNECT_IDLE;
                return APAC_FALSE;
            }
            if(PtrServiceMsg->cmd == SM_SIMPLE_CONNECT_IN_PROGRESS)
            {
                *plcSmplStat = SM_SIMPLE_CONNECT_IN_PROGRESS;
                return APAC_TRUE;
            }
        }
    }
    return APAC_FALSE;
}

apacBool_e pbcGetPlcAvln(apacHyfi20Data_t *pData, u8 *plcAvln) {

    struct sockaddr_un PlcClientAddr = {
        AF_UNIX,
        "/var/run/plc_socket_server"
    };
    char ServiceMsgFrame [SM_FRAME_LEN_MAX] = {
    };
    struct service_message *PtrServiceMsg = (struct service_message *)ServiceMsgFrame;
    struct pollfd pollfd = {
        pData->unPlcSock,
        POLLIN,
        0
    };

    memset(ServiceMsgFrame, 0, sizeof ServiceMsgFrame);
    PtrServiceMsg->cmd = SM_GET_PLC_NID_REQ_FRM_WSPLCD;
    if (sendto (pData->unPlcSock, ServiceMsgFrame, sizeof ServiceMsgFrame, MSG_DONTWAIT, (struct sockaddr *) (&PlcClientAddr),
                    (socklen_t) (sizeof(PlcClientAddr)))  < 0) {
        perror("pbcGetPlcAvln - sendto");
        return APAC_FALSE;
    }
    if(poll (&pollfd, 1, 100) == 1)
    {
        if(recvfrom (pData->unPlcSock, ServiceMsgFrame, sizeof ServiceMsgFrame, 0, (struct sockaddr *) (0), (socklen_t *)(0)) >0)
        {
            if(PtrServiceMsg->cmd == SM_GET_PLC_NID_RSP)
            {
                //memcpy(plcAvln, PtrServiceMsg->data, 15);
                if (pbcConvertPlcAvlnFromStr((char *)PtrServiceMsg->data, plcAvln) < 0) {
                    return APAC_FALSE;
                }
                return APAC_TRUE;
            }
        }
    }
    return APAC_FALSE;
}
#endif

static void pbcHyfi20NetlinkEvents(apacHyfi20Data_t *pData, struct nlmsghdr *h, int len)
{
    struct ifinfomsg *ifi;
    int attrlen, nlmsg_len, rta_len;
    struct rtattr * attr;
    struct iw_event iwe_buf, *iwe = &iwe_buf;
    unsigned char *pos;
    unsigned char *custom;
    char *buf;

    if (len < (int) sizeof(*ifi)){
        dprintf(MSG_WARNING, "len < sizeof(*ifi)\n");
        return;
    }
    ifi = NLMSG_DATA(h);

    nlmsg_len = NLMSG_ALIGN(sizeof(struct ifinfomsg));

    attrlen = h->nlmsg_len - nlmsg_len;
    if (attrlen < 0) {
        printf("attrlen < 0\n");
        return;
    }
    attr = (struct rtattr *) (((char *) ifi) + nlmsg_len);

    rta_len = RTA_ALIGN(sizeof(struct rtattr));
    while (RTA_OK(attr, attrlen)) {
        if (attr->rta_type == IFLA_WIRELESS) {
            pos = ((unsigned char *) attr) + rta_len;
            memcpy(&iwe_buf, pos, sizeof(struct iw_event));

            if (iwe->len < IW_EV_LCP_LEN)
                break;
            custom = pos + IW_EV_POINT_LEN;
            if (iwe->cmd == IWEVCUSTOM) {
                char *dpos = (char *) &iwe_buf.u.data.length;
                int dlen = dpos - (char *) &iwe_buf;
                memcpy(dpos, pos + IW_EV_LCP_LEN,
                    sizeof(struct iw_event) - dlen);

                buf = malloc(iwe->u.data.length+1);
                if (buf == NULL){
                    break;
                }
                memcpy(buf, custom, iwe->u.data.length);
                buf[iwe->u.data.length] = '\0';
                if (strncmp(buf, "EthPUSH-BUTTON.indication", 25) == 0){
                    char *durp;
                    int duration;
                    dprintf(MSG_INFO, "Ev: %s\n",buf);
                    durp = strstr(buf, "dur=");
                    if (durp) {
                        durp+=4;
                        duration = atoi(durp);
                        dprintf(MSG_INFO, "Push duration = %d sec\n",duration);
                        if (duration <= PUSH_BUTTON_IGNORE_DUR) {
                            pbcHyfi20EventPushButtonActivated(pData);
                            /*HyFi 1.0 AP Cloning*/
                            if (pData->config.hyfi10_compatible)
                                wsplc_pushbutton_activated(HYFI20ToHYFI10(pData), duration);
                        }
                    }
                }
                free(buf);
            }
        }
        if (attr->rta_type == IFLA_IFNAME) {
 //           dprintf(MSG_MSGDUMP, "PBT RTATTR Ifname %s\n", ((unsigned char *) attr) + rta_len);
        }

        attr = RTA_NEXT(attr, attrlen);
    }

}
/*
 * CallBacks
 */
/* get push button signal */
void pbcHyfi20GetNLMsgCB(s32 sock, void *eloop_ctx, void *sock_ctx) {
    char buf[256];
    int left;
    struct sockaddr_nl from;
    socklen_t fromlen;
    struct nlmsghdr *h;
    apacHyfi20Data_t *pData = (apacHyfi20Data_t *)eloop_ctx;

    fromlen = sizeof(from);
    left = recvfrom(sock, buf, sizeof(buf), MSG_DONTWAIT,
        (struct sockaddr *) &from, &fromlen);
    if (left < 0) {
        perror("recvfrom (netlink)");
        return ;
    }

    h = (struct nlmsghdr *) buf;
    while (left >= (int) sizeof(*h)) {
        int len, plen;

        len = h->nlmsg_len;
        plen = len - sizeof(*h);
        if (len > left || plen < 0) {
            break;
        }

        if (h->nlmsg_type == RTM_NEWLINK) {
            pbcHyfi20NetlinkEvents(pData, h, plen);
            break;
        }

        len = NLMSG_ALIGN(len);
        left -= len;
        h = (struct nlmsghdr *) ((char *) h + len);
    }

    return;
}

void pbcHyfi20GetPipeMsgCB(s32 fd, void *eloop_ctx, void *sock_ctx) {
    char buf[256];
    char *pos;
    int  len;
    int  duration;
 
    apacHyfi20Data_t *pData = (apacHyfi20Data_t *)eloop_ctx;
    
    len = read(fd, buf, sizeof(buf) -1 );
    if (len <= 0) {
        perror("pbcHyfi20GetPipeMsgCB - read");
        apacHyfi20ResetPipeFd(pData);
        return;
    }
    buf[len] = '\0';

    dprintf(MSG_DEBUG, "Got event: %s\n", buf);
    if (strncmp(buf, "wps_pbc", 7) != 0)
    {
        dprintf(MSG_ERROR, "Unknown event: %s\n", buf);
        return;
    }

    pos = buf + 7;
    pbcHyfi20EventPushButtonActivated(pData);
    /*HyFi 1.0 AP Cloning*/
    if (pData->config.hyfi10_compatible)
    {
        duration = atoi(pos);
        dprintf(MSG_DEBUG, "Got duration: %d\n", duration);
        if (duration < 0)
            duration = 0;
        wsplc_pushbutton_activated(HYFI20ToHYFI10(pData), duration);
    }

    return;
}

#ifdef ENABLE_PLC
/* PLC add new node */
void pbcHyfi20GetUnixSockPlcMsgCB(s32 sock, void *eloop_ctx, void *sock_ctx) {

    char ServiceMsgFrame [SM_FRAME_LEN_MAX] = {
    };
    struct service_message *PtrServiceMsg = (struct service_message *)ServiceMsgFrame;

    if (recvfrom (sock, ServiceMsgFrame, sizeof ServiceMsgFrame, 0, (struct sockaddr *) (0), (socklen_t *)(0)) < 0) {
        perror("pbcHyfi20GetUnixSockPlcMsgCB - recvfrom");
        return;
    }
    switch (PtrServiceMsg->cmd) {
        case SM_EVENT_SMPL_CON_NODE_ADDED:
            pbcPlcSimpleConnectAddNode((u8 *)&PtrServiceMsg->data);
            break;
    }
    return;
}
#endif

/*
 * internal APIs
 */
int pbcGetBssid(char *ifName, u8 *bssid) {
    int32_t Sock;
    struct iwreq Wrq;

    apacHyfi20TRACE();

    if (!ifName || !bssid) {
        dprintf(MSG_ERROR, "%s - Invalid arguments: ifName or bssid is NULL", __func__);
        goto out;
    }

    if ((Sock = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
        dprintf(MSG_ERROR, "%s: Create ioctl socket failed!", __func__);
        goto out;
    }

    if (fcntl(Sock, F_SETFL, fcntl(Sock, F_GETFL) | O_NONBLOCK)) {
        dprintf(MSG_ERROR, "%s: fcntl() failed", __func__);
        goto err;
    }

    strncpy(Wrq.ifr_name, ifName, IFNAMSIZ);
    if (ioctl(Sock, SIOCGIWAP, &Wrq) < 0) {
        dprintf(MSG_ERROR, "%s: ioctl() failed, ifName: %s.\n", __func__, ifName);
        goto err;
    }

    os_memcpy(bssid, &Wrq.u.ap_addr.sa_data, ETH_ALEN);
    dprintf(MSG_DEBUG, "%s: interface: %s, \n", __func__, ifName);
    printMac(MSG_DEBUG, bssid);

    close(Sock);
    return 0;

err:
    close(Sock);
out:
    return -1;
}

/* WLAN mode, e.g. 80211na */
int pbcGetName(char *ifName, char *name) {
    int32_t Sock;
    struct iwreq Wrq;

    if (!ifName || !name) {
        dprintf(MSG_ERROR, "%s - Invalid arguments: ifName or name is NULL", __func__);
        goto out;
    }

    if ((Sock = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
        dprintf(MSG_ERROR, "%s: Create ioctl socket failed!", __func__);
        goto out;
    }

    if (fcntl(Sock, F_SETFL, fcntl(Sock, F_GETFL) | O_NONBLOCK)) {
        dprintf(MSG_ERROR, "%s: fcntl() failed", __func__);
        goto err;
    }

    strncpy(Wrq.ifr_name, ifName, IFNAMSIZ);
    if (ioctl(Sock, SIOCGIWNAME, &Wrq) < 0) {
        dprintf(MSG_ERROR, "%s: ioctl() failed, ifName: %s.\n", __func__, ifName);
        goto err;
    }

    strcpy(name, Wrq.u.name);

    dprintf(MSG_DEBUG, "%s, Interface %s, name: %s(%s) \n", __func__, ifName, name, Wrq.u.name);

    close(Sock);
    return 0;

err:
    close(Sock);
out:
    return -1;
}

int pbcGetVapStatus(char *ifName, s32 *isRunning) {
    int32_t Sock;
    struct iwreq Wrq;
    struct ald_stat_info Stats;

    apacHyfi20TRACE();

    if (!ifName) {
        dprintf(MSG_ERROR, "%s - Invalid arguments: ifName is NULL", __func__);
        goto out;
    }

    if ((Sock = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
        dprintf(MSG_ERROR, "%s: Create ioctl socket failed!", __func__);
        goto out;
    }

    if (fcntl(Sock, F_SETFL, fcntl(Sock, F_GETFL) | O_NONBLOCK)) {
        dprintf(MSG_ERROR, "%s: fcntl() failed", __func__);
        goto err;
    }

    strlcpy((char *)Stats.name, ifName,sizeof(Stats.name));
    Stats.cmd = IEEE80211_ALD_ALL;

    memset(&Wrq, 0, sizeof(struct iwreq));
    strlcpy(Wrq.ifr_name, ifName, IFNAMSIZ);

    Wrq.u.data.pointer = &Stats;
    Wrq.u.data.length = sizeof(Stats);

    if (ioctl(Sock, IEEE80211_IOCTL_ALD, &Wrq) < 0) {
        dprintf(MSG_ERROR, "%s: ioctl() failed, ifName: %s.\n", __func__, ifName);
        goto err;
    }

    *isRunning = Stats.vapstatus;
    dprintf(MSG_DEBUG, "%s: IF %s is running: %d, \n", __func__, ifName, *isRunning);

    close(Sock);
    return 0;
err:
    close(Sock);
out:
    return -1;

}

int pbcGetWlanInfTypeFromMib(int vap_index, u8 *infTypeClass, u8 *infTypePhy) {
    char standard[1024];
    int i;
    
    struct wlanTypes_t
    {
        const char* name;
        u8 infTypeClass;
        u8 infTypePhy;

    } wlanTypes[] =
        {
            { "a",      IEEE1905_MEDIA_TYPE_IEEE802_11, IEEE1905_MEDIA_DESCRIPTION_IEEE802_11A_5G},
            { "b",      IEEE1905_MEDIA_TYPE_IEEE802_11, IEEE1905_MEDIA_DESCRIPTION_IEEE802_11B_2_4G},
            { "g",      IEEE1905_MEDIA_TYPE_IEEE802_11, IEEE1905_MEDIA_DESCRIPTION_IEEE802_11G_2_4G},
            { "ng20",   IEEE1905_MEDIA_TYPE_IEEE802_11, IEEE1905_MEDIA_DESCRIPTION_IEEE802_11N_2_4G},
            { "ng40plus", IEEE1905_MEDIA_TYPE_IEEE802_11, IEEE1905_MEDIA_DESCRIPTION_IEEE802_11N_2_4G},
            { "ng40minus",IEEE1905_MEDIA_TYPE_IEEE802_11, IEEE1905_MEDIA_DESCRIPTION_IEEE802_11N_2_4G},
            { "na20",     IEEE1905_MEDIA_TYPE_IEEE802_11, IEEE1905_MEDIA_DESCRIPTION_IEEE802_11N_5G},
            { "na40plus", IEEE1905_MEDIA_TYPE_IEEE802_11, IEEE1905_MEDIA_DESCRIPTION_IEEE802_11N_5G},
            { "na40minus",IEEE1905_MEDIA_TYPE_IEEE802_11, IEEE1905_MEDIA_DESCRIPTION_IEEE802_11N_5G},
            { "acvht80",  IEEE1905_MEDIA_TYPE_IEEE802_11, IEEE1905_MEDIA_DESCRIPTION_IEEE802_11AC_5G},
            { "acvht40minus", IEEE1905_MEDIA_TYPE_IEEE802_11, IEEE1905_MEDIA_DESCRIPTION_IEEE802_11AC_5G},
            { "acvht40plus",  IEEE1905_MEDIA_TYPE_IEEE802_11, IEEE1905_MEDIA_DESCRIPTION_IEEE802_11AC_5G},
            { "acvht20",  	IEEE1905_MEDIA_TYPE_IEEE802_11, IEEE1905_MEDIA_DESCRIPTION_IEEE802_11AC_5G},
            { "ad",     	IEEE1905_MEDIA_TYPE_IEEE802_11, IEEE1905_MEDIA_DESCRIPTION_IEEE802_11AD_60G},
        };

    if ( apac_mib_get_wlan_standard_by_vapindex(vap_index, standard) < 0 ) {
        dprintf(MSG_ERROR, "%s, get standard error, vapIndex: %u\n", __func__, vap_index);
        return -1;
    }

    for(i = 0; i < sizeof(wlanTypes)/sizeof(wlanTypes[0]); i++)
    {
        /* Return correct type by string match */
        if( strcmp(standard, wlanTypes[i].name) == 0 )
        {
            *infTypeClass = wlanTypes[i].infTypeClass;
            *infTypePhy = wlanTypes[i].infTypePhy;
            dprintf(MSG_DEBUG, "%s: WiFi name: %s, class: %u, phy: %u\n", 
                __func__, standard, wlanTypes[i].infTypeClass, wlanTypes[i].infTypePhy);

            return 0;
        }
    }

    dprintf(MSG_ERROR, "%s, Can't find match. vap: %u, standard: %s\n", __func__, vap_index, standard);
    return -1;
}

/* write my ALID and MID in global variables 
 * Note: the information is not precies. i.e., if there are more than 
 * one 1905 IFs with native PBC method, the later one will overwrite the previous
 * one. This is okay because such information is only used by Join Message, which is 
 * completely discarded. 
 * If by any means Join Message is processed, this part needs to be revisited
 */
void pbcAddAlidMidForJoinMsg(u8 *srcAlid, u16 mid){
    os_memcpy(apacS.alidPbcJoin, srcAlid, ETH_ALEN);
    apacS.midPbcJoin = mid;
}

#define pbcMediaSpecificTLVGetNext(_tlv, _media) \
    ((ieee1905MediaType_t *)((u8 *)_tlv + sizeof(_media) + sizeof(ieee1905MediaType_t)))

#define pbcMediaTypeTLVGetNext(_pbcTLV) \
    ((ieee1905MediaType_t *)((u8 *)(_pbcTLV) + ntohs((_pbcTLV)->tlvHeader.length) + IEEE1905_TLV_MIN_LEN))

#define pbcMediaTypeTLVLenSet(_pbcTLV, _length, _total) \
    do{ (_pbcTLV)->tlvHeader.length = htons(ntohs((_pbcTLV)->tlvHeader.length) + _length); (_total) = ntohs((_pbcTLV)->tlvHeader.length) + IEEE1905_TLV_MIN_LEN; } while(0)

int pbcReceiveEventNotificationMsg(apacHyfi20Data_t *pData, u8 *frame, size_t frameLen){
    ieee1905Message_t *msg = (ieee1905Message_t *)frame;
    apacHyfi20IF_t *pIF = pData->hyif;
    int i;
    u32 processedLen;
    u8 *pTlvVal;
    ieee1905TLV_t *pTLV =  (ieee1905TLV_t *)msg->content;
    ieee1905TlvType_e tlvType;   
    u16 mid = ntohs(msg->ieee1905Header.mid);
    const int num_tlv = 2;
    apacBool_e hasWifiTlv = APAC_FALSE;
    apacBool_e activateWifiWPSDone = APAC_FALSE;

    apacHyfi20TRACE();
    printMsg(frame, frameLen, MSG_MSGDUMP);

    /* Message verification. */
    p1905TlvCheck_t tlvList[num_tlv];
    os_memset(tlvList, 0, sizeof(p1905TlvCheck_t)*num_tlv);
    apacHyfi20AddTlvToList(tlvList, num_tlv, IEEE1905_TLV_TYPE_AL_ID, APAC_FALSE);
    apacHyfi20AddTlvToList(tlvList, num_tlv, IEEE1905_TLV_TYPE_PUSH_BUTTON_EVENT, APAC_FALSE);

    /* Parse TLV */
    processedLen = ieee1905TLVLenGet(pTLV) + IEEE1905_ETH_HEAD_LEN + IEEE1905_HEAD_LEN;
    
    while (processedLen <= frameLen) {
        tlvType = ieee1905TLVTypeGet(pTLV);
        dprintf(MSG_DEBUG, "Get TLV type: %d\n", tlvType);

        if (tlvType == IEEE1905_TLV_TYPE_END_OF_MESSAGE) {
            break;
        }

        if (apacHyfi20FindTlvInList(tlvList, tlvType, num_tlv) == APAC_FALSE) {
            dprintf(MSG_ERROR, "%s - illegal TLV type: %d\n", __func__, tlvType);
            return -1;
        }

        pTlvVal = ieee1905TLVValGet(pTLV);

        if (tlvType ==  IEEE1905_TLV_TYPE_PUSH_BUTTON_EVENT) {
            ieee1905PushButtonEventTLV_t *pTlvPbEvent = (ieee1905PushButtonEventTLV_t *)pTLV; 
            ieee1905MediaType_t *pMediaType;
            u16 tlvLen_copy = ntohs(pTlvPbEvent->tlvHeader.length);
            u16 tlvLen;
            u8 numEntries = pTlvPbEvent->numEntries;
            int i;
           
            dprintf(MSG_DEBUG, "%s, number of Interfaces on the message: %u\n", __func__, 
                    pTlvPbEvent->numEntries);

            tlvLen = sizeof(pTlvPbEvent->numEntries);
            pMediaType = (ieee1905MediaType_t *)&(pTlvPbEvent->val);
            
            for (i = 0; i < numEntries; i++) {

                if (pMediaType->medtypeClass == IEEE1905_MEDIA_TYPE_IEEE1901) {
                    tlvLen += sizeof(ieee1905MediaSpecificHPAV_t) + sizeof(ieee1905MediaType_t); 

                    /* mostly santify check, information is not used */
                    dprintf(MSG_DEBUG, "%s - Sender has PLC interface: %u, AVLN: ", __func__, 
                            pMediaType->medtypeClass);

                    ieee1905MediaSpecificHPAV_t *pVal = (ieee1905MediaSpecificHPAV_t *)(pMediaType->val);
                    printAvln(MSG_DEBUG, pVal->avln);

                    pMediaType = pbcMediaSpecificTLVGetNext(pMediaType, ieee1905MediaSpecificHPAV_t);
                }
                else if (pMediaType->medtypeClass == IEEE1905_MEDIA_TYPE_IEEE802_11) {
                    
                    tlvLen += sizeof(ieee1905MediaSpecificWiFi_t) + sizeof(ieee1905MediaType_t); 
                    ieee1905MediaSpecificWiFi_t *pWlan = (ieee1905MediaSpecificWiFi_t *)&(pMediaType->val);
                    hasWifiTlv = APAC_TRUE;
                    
                    /* mostly santify check, information is not used */
                    dprintf(MSG_DEBUG, "%s - WLAN medtypeClass: %u, phy: %u, role: %u, bssid: ", 
                            __func__, pMediaType->medtypeClass, pMediaType->medtypePhy, pWlan->role);
                    printMac(MSG_DEBUG, pWlan->bssid);

                    pMediaType = pbcMediaSpecificTLVGetNext(pMediaType, ieee1905MediaSpecificWiFi_t);
                }
            }

            if (tlvLen != tlvLen_copy) {
                dprintf(MSG_ERROR, "%s - Error: length(%u) specified in TLV differs measured (%d)\n",
                        __func__, tlvLen_copy, tlvLen);

                return -1;
            }
        }
        else if (tlvType == IEEE1905_TLV_TYPE_AL_ID) {
            /* Check MID and discard the ones that have seen */
            if (apacHyfi20CheckMid(pTlvVal, mid) < 0) {
                return -1;
            }
            pbcAddAlidMidForJoinMsg(pTlvVal, mid);
        }

        processedLen += ieee1905TLVLenGet(pTLV);
        pTLV = ieee1905TLVGetNext(pTLV);
    }

    /* Check if all required TLVs have been received */
    if (apacHyfi20ValidateTlvList(tlvList, num_tlv) == APAC_FALSE) {
        dprintf(MSG_ERROR, "required TLV type missing in the message!\n");
        return -1;
    }

    /* Trigger push button for PLC and Designated PB AP (if no WifiInfo included) */
    for (i = 0; i < APAC_MAXNUM_HYIF; i++) {
        if (!(pIF[i].valid) || pIF[i].nonPBC) {
            continue;
        }

#ifdef ENABLE_PLC
        /* PLC interface */
        if (pIF[i].mediaType == APAC_MEDIATYPE_PLC) {
            /* Check if SimpleConnect is running already. If not, start simple connect */
            u8 scState = ~0;
            apacBool_e isSCRunning = pbcIsSimpleConnectRunning(pData, &scState);
            dprintf(MSG_DEBUG, "%s, PLC SimpleConnect Status: %u, isRunning: %u\n", __func__, scState, isSCRunning);

            if (isSCRunning == APAC_FALSE) {
                dprintf(MSG_DEBUG, "%s, PLC SC isn't running (status %u). Activate it.\n", 
                        __func__, scState);
                
                pbcActivatePlcSimpleConnect(pData);
            }
        }
#endif
        
        /* Wifi interface: only AP Registrar */
        if (pIF[i].mediaType != APAC_MEDIATYPE_WIFI) {
            continue;
        }
                
        if (pData->config.designated_pb_ap_enabled 
            && pIF[i].wlanDeviceMode == APAC_WLAN_AP
            && activateWifiWPSDone == APAC_FALSE) 
        {
            /* Activate WPS if Wifi Interface is not specified in the packet */
            if (hasWifiTlv == APAC_FALSE) {
                pbcActivateWifiWpsAp(&pIF[i]); 
                activateWifiWPSDone = APAC_TRUE;
                
                dprintf(MSG_DEBUG, "%s, IF%d is designated PB AP, Activate WPS\n", __func__, i);
            }
        }
    }
    
    return 0;
}

int pbcSendEventNotificationMsg(apacHyfi20Data_t *pData, u16 mid, u8 *bufMediaInfo, u32 bufLen) {
    u8 dest[ETH_ALEN] = APAC_MULTICAST_ADDR;
    u32 frameLen = IEEE1905_FRAME_MIN_LEN;
    u8 *frame = apacHyfi20GetXmitBuf();
    u8 *content = ((ieee1905Message_t *)frame)->content;
    ieee1905TLV_t *TLV = (ieee1905TLV_t *) content;
    int j;
    apacHyfi20IF_t *pIF = pData->hyif;

    apacHyfi20TRACE();

    /* set PBC event notification message header */
    apacHyfi20SetPktHeader(frame,IEEE1905_MSG_TYPE_PB_EVENT_NOTIFICATION,
        mid, 0, IEEE1905_HEADER_FLAG_LAST_FRAGMENT | IEEE1905_HEADER_FLAG_RELAY,
        pData->alid, dest);

    /* add ALID TLV */
    ieee1905TLVSet(TLV, IEEE1905_TLV_TYPE_AL_ID, ETH_ALEN, pData->alid, frameLen);

    /* add PB Event Notification TLV */    
    TLV = ieee1905TLVGetNext(TLV);
    os_memcpy((u8 *)TLV, bufMediaInfo, bufLen);
    frameLen += bufLen;
    
    /* Set EndOfTLV */
    TLV = ieee1905TLVGetNext(TLV);
    ieee1905EndOfTLVSet(TLV); 

    dprintf(MSG_MSGDUMP, "%s, Sending packet\t", __func__); 
    printMsg(frame, frameLen, MSG_MSGDUMP);
    
    for (j = 0; j < APAC_MAXNUM_HYIF; j++) {
        if (pIF[j].is1905Interface) {
           if (apacHyfi20SendL2Packet(&pIF[j], frame, frameLen) < 0) {
                perror("pbcSendNotificationMessage");
                //return -1;
            } 
            dprintf(MSG_DEBUG, "%s - Sent msg mid: %d on IF%d\n", __func__, mid, j);
        }
    }

    return 0;
}

void pbcHyfi20EventPushButtonActivated(apacHyfi20Data_t *pData) {
    u8 n = 0;
    int i, ret;
    apacHyfi20IF_t *pIF = pData->hyif;
    u16 mid = apacHyfi20GetMid();
#ifdef ENABLE_PLC
    u8 avln[AVLN_LEN];
#endif
    u8 bssid[ETH_ALEN] = {0};
    //u8 null_mac[ETH_ALEN] = MAC_ZEROS;
    const int MAX_SIZE_MEDIA_INFO = 200;

    u8 bufMediaInfo[MAX_SIZE_MEDIA_INFO];
    u8 bufLen = 0; 

    ieee1905PushButtonEventTLV_t *pbcTlv; 
    ieee1905MediaType_t *tlvMediaType;
    apacHyfi20ChanInfo_t chaninfo;

    // Flag indicating if a new WPS enrollee session is triggered
    apacBool_e newWPSEnrollee = APAC_FALSE;

    apacHyfi20TRACE();

    memset(bufMediaInfo, 0, MAX_SIZE_MEDIA_INFO);
    pbcTlv = (ieee1905PushButtonEventTLV_t *)bufMediaInfo;

    ieee1905TLVTypeSet(&(pbcTlv->tlvHeader), IEEE1905_TLV_TYPE_PUSH_BUTTON_EVENT);
    pbcMediaTypeTLVLenSet(pbcTlv, sizeof(pbcTlv->numEntries), bufLen);

    for (i = 0; i < APAC_MAXNUM_HYIF; i++) {

        if (!(pIF[i].valid) || pIF[i].nonPBC) {
            continue;
        }
        
#ifdef ENABLE_PLC
        /* process PLC interface */
        if (pIF[i].mediaType == APAC_MEDIATYPE_PLC) {
            apacBool_e ret;
            ieee1905MediaSpecificHPAV_t *plcInfo;

            /* Wsplcd doesn't initiate SimpleConnect on push button event. Let plcHost handle it*/
            //pbcActivatePlcSimpleConnect(pData);

            tlvMediaType = pbcMediaTypeTLVGetNext(pbcTlv);
            
            tlvMediaType->medtypeClass = IEEE1905_MEDIA_TYPE_IEEE1901;
            tlvMediaType->medtypePhy = IEEE1905_MEDIA_DESCRIPTION_IEEE1901_OFDM;
            
            ret = pbcGetPlcAvln(pData, avln);
            plcInfo = (ieee1905MediaSpecificHPAV_t *)tlvMediaType->val;
            if (ret == APAC_TRUE) {
                os_memcpy(plcInfo->avln, avln, AVLN_LEN);
            }
            else {
                dprintf(MSG_DEBUG, "%s, Can't find valid AVLN\n", __func__);
                os_memset(avln, 0, AVLN_LEN);
            }
            tlvMediaType->val_length = sizeof(ieee1905MediaSpecificHPAV_t);
            
            /* add length of medtype and val_length to TLV length */ 
            pbcMediaTypeTLVLenSet(pbcTlv, sizeof(ieee1905MediaType_t), bufLen);
            
            /* add length of val to TLV length */ 
            pbcMediaTypeTLVLenSet(pbcTlv, sizeof(ieee1905MediaSpecificHPAV_t), bufLen);

            n++; 

            pbcAddAlidMidForJoinMsg(pData->bridge.mac_addr, mid); 
        }
#endif
        
        /* process Wifi interface */
        if (pIF[i].mediaType != APAC_MEDIATYPE_WIFI) {
            continue;
        }

        if (pIF[i].wlanDeviceMode == APAC_WLAN_STA) {
            if (pIF[i].is1905Interface) {
                ieee1905MediaSpecificWiFi_t *wifiInfo; 
                int32_t isRunning; 

                ret = pbcGetVapStatus(pIF[i].ifName, &isRunning);

                /* If STA is associated, don't nothing; if not, start WPS */
                if (ret == 0 && isRunning == 0) { 
                    dprintf(MSG_DEBUG, "%s STA %s is not associated\n", __func__, pIF[i].ifName);
                    newWPSEnrollee = APAC_TRUE;

                    pbcActivateWifiWpsSta(&pIF[i]); 

                    /* write information */
                    tlvMediaType = pbcMediaTypeTLVGetNext(pbcTlv);

                    if (pbcGetWlanInfTypeFromMib(pIF[i].vapIndex, &(tlvMediaType->medtypeClass), 
                        &(tlvMediaType->medtypePhy)) < 0) {

                        return;
                    }

                    wifiInfo = (ieee1905MediaSpecificWiFi_t *)tlvMediaType->val;
                    if (ret < 0) {
                        u8 null_mac[ETH_ALEN] = {0x00};
                        dprintf(MSG_DEBUG, "%s - bssid is NULL for STA:%s\n", __func__, pIF[i].ifName);
                        os_memcpy(bssid, null_mac, ETH_ALEN);
                    }
                    else {
                        os_memcpy(wifiInfo->bssid, bssid, ETH_ALEN);
                    }

                    wifiInfo->role = IEEE1905_SPECIFIC_INFO_IEEE80211(IEEE1905_SPECIFIC_INFO_IEEE80211_STATION);
                    if ( apacHyfi20GetAPChannelInfo(pIF[i].ifName, &chaninfo) == 0)
                    {
                        wifiInfo->reserved[0] = chaninfo.width;
                        wifiInfo->reserved[1] = chaninfo.ifreq1;
                        wifiInfo->reserved[2] = chaninfo.ifreq2;
                    }
                    else
                    {
                        os_memset(wifiInfo->reserved, 0, sizeof(wifiInfo->reserved));
                    }

                    tlvMediaType->val_length = sizeof(ieee1905MediaSpecificWiFi_t);
            
                    pbcMediaTypeTLVLenSet(pbcTlv, sizeof(ieee1905MediaType_t), bufLen);
                    pbcMediaTypeTLVLenSet(pbcTlv, sizeof(ieee1905MediaSpecificWiFi_t), bufLen);
                    
                    n++; 
                    
                    pbcAddAlidMidForJoinMsg(pData->bridge.mac_addr, mid);
                } 

            } /* end if (pIF[i].is1905Interface) */
            else { /* Non 1905 Station */
                pbcActivateWifiWpsSta(&pIF[i]); 
            }
        }
        else { /* Wlan AP */
            ieee1905MediaSpecificWiFi_t *wifiInfo; 
            
            pbcActivateWifiWpsAp(&pIF[i]); 
            ret = pbcGetBssid(pIF[i].ifName, bssid);
            
            if (ret < 0) {
                dprintf(MSG_ERROR, "%s - bssid of AP %s is NULL!\n", __func__, pIF[i].ifName);
                return;
            }
                    
            tlvMediaType = pbcMediaTypeTLVGetNext(pbcTlv);

            if (pbcGetWlanInfTypeFromMib(pIF[i].vapIndex, &(tlvMediaType->medtypeClass),
                &(tlvMediaType->medtypePhy)) < 0) {

                return;
            }

            wifiInfo = (ieee1905MediaSpecificWiFi_t *)tlvMediaType->val;
            
            os_memcpy(wifiInfo->bssid, bssid, ETH_ALEN);
            wifiInfo->role = IEEE1905_SPECIFIC_INFO_IEEE80211(IEEE1905_SPECIFIC_INFO_IEEE80211_AP);
            if ( apacHyfi20GetAPChannelInfo(pIF[i].ifName, &chaninfo) == 0)
            {
                wifiInfo->reserved[0] = chaninfo.width;
                wifiInfo->reserved[1] = chaninfo.ifreq1;
                wifiInfo->reserved[2] = chaninfo.ifreq2;
            }
            else
            {
                os_memset(wifiInfo->reserved, 0, sizeof(wifiInfo->reserved));
            }

            tlvMediaType->val_length = sizeof(ieee1905MediaSpecificWiFi_t);
            
            pbcMediaTypeTLVLenSet(pbcTlv, sizeof(ieee1905MediaSpecificWiFi_t), bufLen);
            pbcMediaTypeTLVLenSet(pbcTlv, sizeof(ieee1905MediaType_t), bufLen);
            
            n++;

            pbcAddAlidMidForJoinMsg(pData->bridge.mac_addr, mid);
        }
    }

    if (newWPSEnrollee) {
        dprintf(MSG_INFO, "%s: Trying to associate with a new AP, "
                          "clear APAC configured flags on all AP interfaces\n",
                __func__);
        size_t i = 0;
        for (i = 0; i < APAC_NUM_WIFI_FREQ; i++) {
            pData->ap[i].isAutoConfigured = APAC_FALSE;
        }
    }

    /* write n */
    pbcTlv->numEntries = n;
    printMsg(bufMediaInfo, bufLen, MSG_MSGDUMP);

    if (pbcSendEventNotificationMsg(pData, mid, bufMediaInfo, bufLen) < 0) {
        dprintf(MSG_ERROR, "Send PBC ENM error\n");
    }
}

int pbcSendJoinMsg(u8 *txIfMac, u8 *newIfMac) {
    apacHyfi20Data_t *pData = apacS.pApacData;
    apacHyfi20IF_t *pIF = pData->hyif;
    
    int i;
    u8 dest[ETH_ALEN] = APAC_MULTICAST_ADDR;
    u32 frameLen = IEEE1905_FRAME_MIN_LEN;
    u8 *frame = apacHyfi20GetXmitBuf();
    ieee1905TLV_t *TLV = (ieee1905TLV_t *)(((ieee1905Message_t *)frame)->content);
    u16 mid = apacHyfi20GetMid();
    ieee1905PushButtonJoinTLV_t *pJoinTlv; 

    apacHyfi20TRACE();

    apacHyfi20SetPktHeader(frame,IEEE1905_MSG_TYPE_PB_JOIN_NOTIFICATION,
        mid, 0, IEEE1905_HEADER_FLAG_LAST_FRAGMENT | IEEE1905_HEADER_FLAG_RELAY,
        pData->alid, dest);

    /* Add ALID TLV */
    ieee1905TLVSet(TLV, IEEE1905_TLV_TYPE_AL_ID, ETH_ALEN, pData->alid, frameLen);

    /* Add PB Join TLV */
    TLV = ieee1905TLVGetNext(TLV);
    pJoinTlv = (ieee1905PushButtonJoinTLV_t *)TLV;

    /* set tlv header */
    ieee1905TLVTypeSet(&(pJoinTlv->tlvHeader), IEEE1905_TLV_TYPE_PUSH_BUTTON_JOIN);

    os_memcpy((u8 *)&(pJoinTlv->alID), apacS.alidPbcJoin, ETH_ALEN);
    pJoinTlv->midPBEvent = htons(apacS.midPbcJoin);
    os_memcpy((u8 *)&(pJoinTlv->txIfMac), txIfMac, ETH_ALEN);
    os_memcpy((u8 *)&(pJoinTlv->newIfMac), newIfMac, ETH_ALEN);

    ieee1905TLVLenSet(&(pJoinTlv->tlvHeader), (3 * ETH_ALEN + sizeof(pJoinTlv->midPBEvent)), frameLen);

    /* Add End of TLV */
    TLV = ieee1905TLVGetNext(TLV);
    ieee1905EndOfTLVSet(TLV);

    for (i = 0; i < APAC_MAXNUM_HYIF; i++) {
        if (pIF[i].is1905Interface) {
            if (apacHyfi20SendL2Packet(&pIF[i], frame, frameLen) < 0) {
                perror("pbcSendJoinMessage");
            }
            dprintf(MSG_DEBUG, "%s, Sent msg mid: %u on IF%u\n", __func__, mid, i);
        }
    }

    return 0;
}

/*
 * public APIs
 */
#ifdef ENABLE_PLC
/* 
 * The function gets called if SimpleConnect (activated by wsplcd) 
 * has successfully added a new node
 * (out) plc_mac: the PLC MAC address of the newly added node
 */
void pbcPlcSimpleConnectAddNode(u8 *mac_new_node) {
    int i;
    apacHyfi20IF_t *pIF = apacS.pApacData->hyif;

    apacHyfi20TRACE();
    dprintf(MSG_DEBUG, "Plc SC add node: ");
    printMac(MSG_DEBUG, mac_new_node);

    /* get PLC mac address */
    for (i = 0; i < APAC_MAXNUM_HYIF; i++) {
        if (pIF[i].mediaType == APAC_MEDIATYPE_PLC) {
            pbcSendJoinMsg(pIF[i].mac_addr, mac_new_node); 
            return;
        }
    }
    
    dprintf(MSG_ERROR, "%s, Func called with no PLC interface found!\n", __func__);
}
#endif

/* 
 * The function gets called if hostapd has activated (by wsplcd) WPS on an 1905 AP
 * and this AP successfully added a new node
 * (out) wifi_mac: the added WIFI MAC address of the new station
 */
void pbcWifiWpsAddNode(u8 *mac_ap, u8 *mac_sta) {
    apacHyfi20TRACE();
    pbcSendJoinMsg(mac_ap, mac_sta);
}

