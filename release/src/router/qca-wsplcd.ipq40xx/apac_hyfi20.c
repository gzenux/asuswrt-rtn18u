/* @File: apac_hyfi20.c  
 * @Notes:
 *
 * Copyright (c) 2011-2012 Qualcomm Atheros, Inc.
 * Qualcomm Atheros Confidential and Proprietary. 
 * All rights reserved.
 *
 */

#include "wsplcd.h"
#include "eloop.h"
#include "apac_priv.h"
#include "apac_hyfi20_wps.h"
#include "apac_hyfi20_mib.h"
#include "ieee1905_vendor.h"

/* Number of seconds when we want to send APAC search in a shorter interval
 * Currently this is used in two cases:
 *   1. Look for registrar on all bands after Wi-Fi WPS success;
 *   2. Look for registrar on a different band after APAC completes on one band. */
const u16 APAC_SEARCH_SHORT_INTERVAL = 2;
u16 apac_cfg_apply_interval=10;
u16 apac_cfg_restart_short_interval=5;
u16 apac_cfg_restart_long_interval=20;

#define APAC_NUM_CFG_APPLY_FRAMES 5

apacHyfi20GlobalState_t apacS;
apacHyfi20NodeTbl_t apacNodeTbl[APAC_MAXNUM_NTWK_NODES];

#define CFGMSG_VERSION_MAJOR_SHIFT 4
#define CFGMSG_VERSION_MINOR_SHIFT 0
#define CFGMSG_VERSION_COMPONENT_MASK 0xFF

/* CFG Major versions supported */
typedef enum cfgmsgMajorVersion_e {
    cfgmsgMajorVersion1 = 1
} cfgmsgMajorVersion_e;
    
/* ATF Minor versions supported */
typedef enum cfgmsgMinorVersion_e {
    cfgmsgMinorVersion0 = 0,
} cfgmsgMinorVersion_e;

// Pack the major/minor version numbers into a single value.
#define cfgmsgPackVersionNum(major, minor) \
    (((major & CFGMSG_VERSION_COMPONENT_MASK) \
        << CFGMSG_VERSION_MAJOR_SHIFT) | \
     ((minor & CFGMSG_VERSION_COMPONENT_MASK) \
        << CFGMSG_VERSION_MINOR_SHIFT))

// Extract the major and minor version numbers from the packed value.
#define cfgmsgExtractMajorVersionNum(version) \
    ((version >> CFGMSG_VERSION_MAJOR_SHIFT) \
        & CFGMSG_VERSION_COMPONENT_MASK)
#define cfgmsgExtractMinorVersionNum(version) \
    (version & CFGMSG_VERSION_COMPONENT_MASK)

u8 *apacHyfi20GetXmitBuf() {
    memset(apacS.xmitBuf, 0, ETH_FRAME_LEN);
    return apacS.xmitBuf;
}

/* Setup frame header (ether header and IEEE1905 message header   */
int apacHyfi20SetPktHeader(u8 *frame, ieee1905MessageType_e type, 
    u16 mid, u8 fid, u8 flags, u8 *src, u8 *dest) 
{
    ieee1905Message_t *msg = (ieee1905Message_t *)frame;
    
    /* sanity check */
    if (!frame) {
        dprintf(MSG_ERROR, "%s - null frame\n", __func__);
        return -1;
    }
    if( type >= IEEE1905_MSG_TYPE_RESERVED )
    {
        dprintf(MSG_ERROR, "%s - Invalid message type: %d", __func__, type );
        return -1;
    }
    
    /* set up Ethernet frame header and IEEE1905 message header */
    memset(msg, 0, IEEE1905_ETH_HEAD_LEN);
 
    msg->etherHeader.ether_type = htons(IEEE1905_ETHER_TYPE);
    memcpy(msg->etherHeader.ether_shost, src, ETH_ALEN);
    memcpy(msg->etherHeader.ether_dhost, dest, ETH_ALEN);
    
    msg->ieee1905Header.version = IEEE1905_PROTOCOL_VERSION;
    msg->ieee1905Header.type = (u16)htons(type);  
    msg->ieee1905Header.mid = htons(mid);
    msg->ieee1905Header.fid = fid;
    msg->ieee1905Header.flags = flags;
    msg->ieee1905Header.reserved = 0;

    return 0;
}

apacHyfi20NodeTbl_t *apacHyfi20GetNodeEntryByMac(u8 *alid) {
    int i;

    for (i = 0; i < APAC_MAXNUM_NTWK_NODES; i++) {
        if (apacNodeTbl[i].valid == APAC_FALSE) {
            continue;
        }

        if (os_memcmp(alid, apacNodeTbl[i].src_alid, ETH_ALEN) == 0) {
            return &apacNodeTbl[i];
        }
    }

    return NULL;
}

int apacHyfi20SendL2Packet(apacHyfi20IF_t *pIF, u8 *frame, u32 frameLen)
{
    int  ret = -1;
    int  ioerr = 0;

    if (pIF->sock > 0) 
    {
        ret =  send(pIF->sock, frame, frameLen, 0);
        if (ret  < 0 && errno == ENXIO )
            ioerr = 1;
    }

    if (pIF->sock <= 0 || ioerr == 1)
    {
        apacHyfi20ResetIeee1905TXSock(pIF);
        ret =  send(pIF->sock, frame, frameLen, 0);
    }

    return ret;
}

/* Send Config Ack message to Registrar */
int apacHyfi20SendConfigAckE(struct apac_wps_session *sess) {
    apacHyfi20Data_t *pData = sess->pData;
    apacHyfi20IF_t *pIF = pData->hyif;
    u8 *frame = apacHyfi20GetXmitBuf();
    ieee1905TLV_t *tlv = (ieee1905TLV_t *)((ieee1905Message_t *)frame)->content;
    u16 mid = apacHyfi20GetMid();
    u8 dest[ETH_ALEN], j = 0;
    size_t frameLen = IEEE1905_FRAME_MIN_LEN;
    u_int32_t bufferLen = 0;
    ieee1905QCAMessage_t *qcaMessage =
        (ieee1905QCAMessage_t *)ieee1905TLVValGet(tlv);
    ieee1905QCAVendorSpecificType_e type = IEEE1905_QCA_TYPE_CFG_ACK;

    os_memcpy(dest, sess->dest_addr, ETH_ALEN);

    apacHyfi20SetPktHeader(frame, IEEE1905_MSG_TYPE_VENDOR_SPECIFIC,
        mid, 0, IEEE1905_HEADER_FLAG_LAST_FRAGMENT,
        pData->alid, dest);

    ieee1905TLVTypeSet(tlv, IEEE1905_TLV_TYPE_VENDOR_SPECIFIC);
    ieee1905QCAOUIAndTypeSet(qcaMessage, type, bufferLen);
    *qcaMessage->content = cfgmsgPackVersionNum(cfgmsgMajorVersion1,
                                                  cfgmsgMinorVersion0);
    bufferLen++;
    ieee1905TLVLenSet(tlv, bufferLen, frameLen);

    tlv = ieee1905TLVGetNext(tlv);
    /* Add EndOfTlv */
    ieee1905EndOfTLVSet(tlv);

    // Send L2 
    if (pData->config.sendOnAllIFs == APAC_FALSE) {
        if (send(pData->bridge.sock, frame, frameLen, 0) < 0) {
           perror("apacHyfi20SendConfigAckE");
           return -1;
        } 
    } else {
        for (j = 0; j < APAC_MAXNUM_HYIF; j++) {
            if (pIF[j].ifIndex != -1) {
                if (apacHyfi20SendL2Packet(&pIF[j], frame, frameLen) < 0) {
                    perror("apacHyfi20SendConfigAckE");
                    return -1;
                }
                dprintf(MSG_INFO, "%s sent ConfigAck msg mid: %d on %s\n", __func__, mid, pIF[j].ifName);
            }
        }
    }

    return 0;
}

/* Send Config Apply multicast message to all Enrollees */
int apacHyfi20SendConfigApplyR(void *ptrData) {
    apacHyfi20Data_t *pData = (apacHyfi20Data_t *)ptrData;
    apacHyfi20IF_t *pIF = pData->hyif;
    u8 *frame = apacHyfi20GetXmitBuf();
    ieee1905TLV_t *tlv = (ieee1905TLV_t *)((ieee1905Message_t *)frame)->content;
    u16 mid = apacHyfi20GetMid();
    u8 dest[ETH_ALEN], i=0, j = 0;
    size_t frameLen = IEEE1905_FRAME_MIN_LEN;
    u_int32_t bufferLen = 0;
    ieee1905QCAMessage_t *qcaMessage =
        (ieee1905QCAMessage_t *)ieee1905TLVValGet(tlv);
    ieee1905QCAVendorSpecificType_e type = IEEE1905_QCA_TYPE_CFG_APPLY;

    os_memcpy(dest, APAC_MULTICAST_ADDR, ETH_ALEN);

    apacHyfi20SetPktHeader(frame, IEEE1905_MSG_TYPE_VENDOR_SPECIFIC,
        mid, 0, IEEE1905_HEADER_FLAG_LAST_FRAGMENT | IEEE1905_HEADER_FLAG_RELAY,
        pData->alid, dest);
    
    ieee1905TLVTypeSet(tlv, IEEE1905_TLV_TYPE_VENDOR_SPECIFIC);
    ieee1905QCAOUIAndTypeSet(qcaMessage, type, bufferLen);
    *qcaMessage->content = cfgmsgPackVersionNum(cfgmsgMajorVersion1,
                                                  cfgmsgMinorVersion0);
    bufferLen++;
    ieee1905TLVLenSet(tlv, bufferLen, frameLen);

    tlv = ieee1905TLVGetNext(tlv);
    /* Add EndOfTlv */
    ieee1905EndOfTLVSet(tlv);

    // Send L2 multicast for 5 times
    for (j = 0; j < APAC_MAXNUM_HYIF; j++) {
        if (pIF[j].ifIndex != -1) {
            for (i = 0; i < APAC_NUM_CFG_APPLY_FRAMES; i++) {
                if (apacHyfi20SendL2Packet(&pIF[j], frame, frameLen) < 0) {
                    perror("apacHyfi20SendConfigApplyE");
                    return -1;
                }
                dprintf(MSG_INFO, "%s sent ConfigApply msg mid: %d on %s\n", __func__, mid, pIF[j].ifName);
            }
        }
    }

    return 0;
}

/* Apply config after waiting for config apply message to come from registrar */
void apacHyfi20ConfigApplyTimeoutHandler(void *eloop_ctx, void *timeout_ctx) {
    apacHyfi20Data_t *pData = (apacHyfi20Data_t *)eloop_ctx;
    apacHyfi20Config_t *pConfig = &(pData->config);

    dprintf(MSG_DEBUG, "Config Apply Message Timeout. Applying config. \n");
    pData->wifiConfigHandle =
                apac_mib_apply_wifi_configuration(pData->wifiConfigHandle, APAC_TRUE);
    pData->wifiConfigWaitSecs = 0;
    pConfig->state = APAC_E_IDLE;
}     

/* add new node and mid to node table, return 0 for success, -1 for error */
int apacHyfi20AddEntryToNodeTbl(u8 *alid, u16 mid, int *index /*out*/) {
    int i;

    for (i = 0; i < APAC_MAXNUM_NTWK_NODES; i++) {
        if (apacNodeTbl[i].valid == APAC_FALSE) {
            apacNodeTbl[i].src_mid = mid;
            os_memcpy(apacNodeTbl[i].src_alid, alid, ETH_ALEN);
            apacNodeTbl[i].valid = APAC_TRUE;
            *index = i;

            return 0;
        }
    }

    dprintf(MSG_ERROR, "%s Node Table is full!\n", __func__);
    return -1;
}

/* calling centrailized IEEE1905 packets Mid generator. */
u16 apacHyfi20GetMid() {
    apacS.mid = messageId_getNext();
    return apacS.mid;
}

/* 
 * Check MID: return 0 for new mid; -1 for old mid or error 
 * Lei Note (3/19/2012): 
 *  MID is stored in apacNodeTbl, which has two fields: ALID and MID
 *  However, Not all 1905 packets include ALID TLV, but we have to check MID 
 *  for each of them
 *  The solution is to fill the ALID field with SA when ALID is not available. 
 *  Therefore, there may be multiple entries for one device. We assume the side
 *  effect can be safely ignored. 
 */
int apacHyfi20CheckMid(u8 *alid, u16 mid) {
    apacHyfi20NodeTbl_t *ptrEntry = apacHyfi20GetNodeEntryByMac(alid);
    
    if (!ptrEntry) {
        int index;
        return (apacHyfi20AddEntryToNodeTbl(alid, mid, &index));
    }

    /* valid message: bigger incoming message */
    if (mid > ptrEntry->src_mid) {
        ptrEntry->src_mid = mid;
        return 0;
    }

    /* same mid */
    if (mid == ptrEntry->src_mid) {
        dprintf(MSG_DEBUG, "%s - Packet with mid%d has been processed already. discard\n", __func__, mid);
        return -1;
    }

    /* smaller incoming mid: check if it is because device restart or MID rollover */
    if( ptrEntry->src_mid - mid > APAC_MID_DELTA ) {
        /* new message, update table */
        ptrEntry->src_mid = mid;
        return 0; 
    }
    else {
        dprintf(MSG_DEBUG, "%s - old mid (%d), current mid in record: %d\n", __func__, mid, ptrEntry->src_mid);
        return -1;
    }
}

/* Record Search MID sent */
void apacHyfi20SetSearchMid(u16 mid, apacHyfi20WifiFreq_e freq) {
    int i;

    for (i = 0; i < APAC_NUM_WIFI_FREQ; i++) {
        if (apacS.searchMidSent[i].freq == freq) {
            apacS.searchMidSent[i].valid = APAC_TRUE;
            apacS.searchMidSent[i].mid = mid;
            return;
        }
    }

    /* unlikely to be here */
    dprintf(MSG_ERROR, "%s, freq %u is not valid!\n", __func__, freq);
}

int apacHyfi20CheckMidOnResponseMsg(u16 mid, apacHyfi20WifiFreq_e freq) {
    int i;

    for (i = 0; i < APAC_NUM_WIFI_FREQ; i++) {
        if ( apacS.searchMidSent[i].valid && (apacS.searchMidSent[i].freq == freq)) {
            if (apacS.searchMidSent[i].mid == mid) {
                apacS.searchMidSent[i].valid = APAC_FALSE;
                return 0;
            }
            else {
                dprintf(MSG_DEBUG, "%s, received Mid(%u) is not Mid (%u) last sent\n", __func__, mid, apacS.searchMidSent[i].mid);
                return -1;
            }
        }
    }

    dprintf(MSG_DEBUG, "%s, invalid: mid(%u) and freq(%u) not recognized\n", __func__, mid, freq);
    return -1;
}

void printMsg(u8 *frame, size_t frameLen, s32 debugLevel) {
    size_t i;

    dprintf(debugLevel, "Packet len: %d\n", frameLen);
    for (i = 0; i < frameLen; i++) { 
        dprintf(debugLevel, "%02X ", frame[i]);
        if (((i+1) % 16) == 0) {
            dprintf(debugLevel, "\n");
        }
    }
    dprintf(debugLevel, "\n");
}

/* add TLV to list, return 0 for success, else for error */
int apacHyfi20AddTlvToList(p1905TlvCheck_t *tlvList, const int num, ieee1905TlvType_e tlvType, apacBool_e multi)
{   
    int i;

    for (i = 0; i < num; i++) {
        if (tlvList[i].tlvType == IEEE1905_TLV_TYPE_END_OF_MESSAGE /*0*/) {
            tlvList[i].tlvType = tlvType;
            tlvList[i].multiTlvAllowed = multi;
            tlvList[i].valid = APAC_FALSE;
            return 0;
        }
    }

    dprintf(MSG_ERROR, "%s - tlvList is full! can't add type %d\n", __func__, tlvType);
    return -1;
}

/* Check if received TLV is required */
apacBool_e apacHyfi20FindTlvInList(p1905TlvCheck_t *tlvList, ieee1905TlvType_e tlvType, const int num) 
{
    int i;
    
    /* does not record vendor specific TLV */
    if (tlvType == IEEE1905_TLV_TYPE_VENDOR_SPECIFIC)
        return APAC_TRUE;

    for (i = 0; i < num; i++) {
        if (tlvList[i].tlvType == tlvType) {
            if (tlvList[i].valid == APAC_FALSE) {
                tlvList[i].valid = APAC_TRUE;
                return APAC_TRUE;
            }
            else if (tlvList[i].multiTlvAllowed == APAC_TRUE) {
                return APAC_TRUE;
            }
            else {
                dprintf(MSG_ERROR, "Multiple TLVs for type %d are not allowed\n", tlvType);
                return APAC_FALSE;
            }
        }
    }

    dprintf(MSG_ERROR, "TLV type %d is not required!\n", tlvType);
    return APAC_FALSE;
}

apacBool_e apacHyfi20ValidateTlvList(p1905TlvCheck_t *list, const int num) {
    int i;

    for (i = 0; i < num; i++) {
        if (list[i].valid == APAC_FALSE) {
            dprintf(MSG_ERROR, "Valide TLV Error: TLV%d not included in the message\n", list[i].tlvType);
            return APAC_FALSE;
        }
    }

    return APAC_TRUE;
}


/* Restart wifi on Restart timer expiry */
void apacHyfi20ConfigRestartTimeoutHandler(void *eloop_ctx, void *timeout_ctx) {
    (void)timeout_ctx;
    apacHyfi20Data_t *pData = (apacHyfi20Data_t *)eloop_ctx;
    apacHyfi20Config_t *pConfig = &pData->config;

    if (pConfig->role == APAC_REGISTRAR) {
        dprintf(MSG_DEBUG, "%s: Registrar is Sending Config Apply \n", __func__);
        // Ask Enrollees to restart their service
        apacHyfi20SendConfigApplyR(pData);
    }

    dprintf(MSG_DEBUG, "%s: Invoking wifi restart. \n",__func__);
   
    //Call to restart wifi
    apac_mib_restart_wireless();
}     

/* receive IEEE1905 packet; check packet type and dispatch */
void apacHyfi20GetIEEE1905PktCB(s32 sock, void *eloop_ctx, void *sock_ctx) {
    apacHyfi20Data_t *pData = (apacHyfi20Data_t *)eloop_ctx;
    apacHyfi20Config_t *pConfig = &pData->config;

    u8 frame[ETH_FRAME_LEN];
    struct sockaddr_ll ll;
    socklen_t socklen;
    ssize_t frameLen;

    ieee1905Message_t *msg = (ieee1905Message_t *)frame;
    ieee1905MessageType_e msgType;
    ieee1905Header_t hdrIEEE1905;
    u16 mid;
    struct timeval t_now = {0};

    //apacHyfi20TRACE();

    memset(&ll, 0, sizeof(ll));
    socklen = sizeof(ll);

    frameLen = recvfrom(sock, frame, sizeof(frame), 0, (struct sockaddr *)&ll, &socklen);

    if (frameLen < 0) {
        perror("apacHyfi20GetIEEE905PktCB - recvfrom");
        apacHyfi20ResetIeee1905RXSock(pData);
        return;
    }

    if (frameLen < IEEE1905_FRAME_MIN_LEN)
    {
        dprintf(MSG_INFO, "%s -- invalid IEEE1905 packet with length %d! discard !\n", __func__, frameLen);
        return;
    }

    hdrIEEE1905 = msg->ieee1905Header;
    msgType = ntohs(hdrIEEE1905.type);
    mid = ntohs(hdrIEEE1905.mid);
 
    /* Sanity check */
    if ( msg->etherHeader.ether_type != ntohs(IEEE1905_ETHER_TYPE) )
    {
        dprintf(MSG_ERROR, "%s -- not IEEE1905 packet! discard\n", __func__);
        return;
    }

    //printMsg(frame, frameLen, MSG_MSGDUMP);
    if ( msg->ieee1905Header.version != 0 ) {
        dprintf(MSG_ERROR, "%s - message version != 0: %d\n",  __func__, ntohs(msg->ieee1905Header.version));
        return;
    }

    /* discard packet from my own */
    ieee1905Message_t *fPtr = (ieee1905Message_t *)frame;
    if ( os_memcmp(fPtr->etherHeader.ether_shost, pData->alid, ETH_ALEN) == 0) 
    {
        dprintf(MSG_DEBUG, "%s -- receive packet from my own, discard \n", __func__);
        return;
    }
    
    /* Discard fragmented packets (exclude WPS packets) */
    if ( !((hdrIEEE1905.flags & IEEE1905_HEADER_FLAG_LAST_FRAGMENT) && (hdrIEEE1905.fid == 0)) 
      && (msgType != IEEE1905_MSG_TYPE_AP_AUTOCONFIGURATION_WPS) )
    {
        dprintf(MSG_MSGDUMP, "%s -- receiving non-WPS fragmented packet; discard\n", __func__);
        return;
    }

    if (  !(msgType == IEEE1905_MSG_TYPE_AP_AUTOCONFIGURATION_SEARCH ||
                msgType == IEEE1905_MSG_TYPE_AP_AUTOCONFIGURATION_RESPONSE  ||
                msgType == IEEE1905_MSG_TYPE_AP_AUTOCONFIGURATION_WPS  ||
                msgType == IEEE1905_MSG_TYPE_AP_AUTOCONFIGURATION_RENEW  ||
                msgType == IEEE1905_MSG_TYPE_PB_EVENT_NOTIFICATION ||
                msgType == IEEE1905_MSG_TYPE_PB_JOIN_NOTIFICATION ||
                msgType == IEEE1905_MSG_TYPE_VENDOR_SPECIFIC ) )
    {
        return;
    }
    /* check relayed bit: Only WPS packet may set relay bit */
    else {
        if (msgType == IEEE1905_MSG_TYPE_AP_AUTOCONFIGURATION_WPS && hdrIEEE1905.flags & IEEE1905_HEADER_FLAG_RELAY) {
            dprintf(MSG_ERROR, "%s - msgtype(%d) shouldn't have relay bit set!\n", __func__, msgType);
            return;
        }
    }

    /* Check message type and dispatch it */
    switch (msgType) 
    {
    case IEEE1905_MSG_TYPE_AP_AUTOCONFIGURATION_SEARCH:
        dprintf(MSG_DEBUG, "%s, Receive Search Msg. My State: %u\n", __func__, pConfig->state);
        apacHyfi20ReceiveSearchR(pData, frame, frameLen);  
        break;
 
    case IEEE1905_MSG_TYPE_AP_AUTOCONFIGURATION_RESPONSE:
        dprintf(MSG_DEBUG, "%s, Receive Response Msg. My State: %u\n", __func__, pConfig->state);
        /* Check State */
        if (!(pConfig->state == APAC_E_PB_WAIT_RESP || pConfig->state == APAC_E_WAIT_RESP)) {
            dprintf(MSG_ERROR, "%s - State(%d) does not match!\n", __func__, pConfig->state);
            return;
        }
        apacHyfi20ReceiveResponseE(pData, frame, frameLen);
        break;

    case IEEE1905_MSG_TYPE_AP_AUTOCONFIGURATION_WPS:
        dprintf(MSG_DEBUG, "%s, Receive WPS Msg. My State: %u, role: %u\n", __func__, pConfig->state, pConfig->role);
        /* Check MID using SA as ALID and discard the ones that have seen */
        if (apacHyfi20CheckMid(msg->etherHeader.ether_shost, mid) < 0) {
            return;
        }
        apacHyfi20ReceiveWps(pData, frame, frameLen);
        break;

    case IEEE1905_MSG_TYPE_AP_AUTOCONFIGURATION_RENEW:
        dprintf(MSG_DEBUG, "%s, Receive Renew Msg. My State: %u, role: %u\n", __func__, pConfig->state, pConfig->role);
        apacHyfi20ReceiveRenewalE(pData, frame, frameLen);
        break;

    case IEEE1905_MSG_TYPE_PB_EVENT_NOTIFICATION: 
        dprintf(MSG_DEBUG, "%s, Receive PB Notification Msg. My State: %u, role: %u\n", __func__, pConfig->state, pConfig->role);
        pbcReceiveEventNotificationMsg(pData, frame, frameLen);
        break;

    case IEEE1905_MSG_TYPE_PB_JOIN_NOTIFICATION: 
        dprintf(MSG_DEBUG, "%s, Receive PB Join Msg. My State: %u, role: %u\n", __func__, pConfig->state, pConfig->role);
        /* do not process */
        break;
    case IEEE1905_MSG_TYPE_VENDOR_SPECIFIC:
        /* Check MID using SA as ALID and discard the ones that have seen */
        if (apacHyfi20CheckMid(msg->etherHeader.ether_shost, mid) < 0) {
            return;
        }
        dprintf(MSG_DEBUG, "%s, Received 1905 Vendor Specific Packet!!\n", __func__);
        apacHyfi20VendorSpecificHandle(pData, frame, frameLen);
        break;
    
    /* discard Non-security packets */
    default:
        dprintf(MSG_DEBUG, "Msg type(%d) is not for wsplcd, discard\n", msgType);
        return;
    }
    
    gettimeofday(&t_now, NULL);
    dprintf(MSG_DEBUG, "%s, time: %ld Received msg type: %u, mid: %u, My state: %u\n", 
            __func__, t_now.tv_sec, msgType, mid, pConfig->state);

}

const ieee1905QCAMessage_t *extractQCAMessage(const ieee1905TLV_t *tlv) {
      const ieee1905QCAMessage_t *qcaMessage =
          (const ieee1905QCAMessage_t *)ieee1905TLVValGet(tlv);

      // The TLVs we care about have a type field followed by a version
      // field, so ignore any that are of insufficient length.
      if (ieee1905TLVLenGet(tlv) >= IEEE1905_OUI_LENGTH + 2 &&
          ieee1905QCAIsQCAOUI(qcaMessage->oui) &&
          qcaMessage->type >= IEEE1905_QCA_TYPE_SYSTEM_INFO_REQ) {
                dprintf(MSG_INFO, "QCA TLV %s\n", __func__);
                return qcaMessage;
      }

      // Not a TLV we will handle.
      return NULL;
}

void apacHyfi20VendorSpecificHandle(apacHyfi20Data_t *pData, u8 *message, size_t frameLen) {
    ieee1905Message_t *frame = (ieee1905Message_t *)message;
    ieee1905TLV_t *tlv =  (ieee1905TLV_t *)frame->content;
    ieee1905TlvType_e tlvType = ieee1905TLVTypeGet(tlv);
    apacHyfi20Config_t *pConfig = &pData->config;

    apacHyfi20TRACE();

    // Process QCA vendor sub-type messages
    if( tlvType == IEEE1905_TLV_TYPE_VENDOR_SPECIFIC ) {
        const ieee1905QCAMessage_t *qcaMessage = extractQCAMessage(tlv);

        if (qcaMessage) {
            switch (ieee1905QCATypeGet(qcaMessage)) {
                case IEEE1905_QCA_TYPE_CFG_ACK:
                   // Start Restart Timer if Registrar and config has changed.
                   if ((pConfig->cfg_changed) && (pConfig->role == APAC_REGISTRAR)) {
                       dprintf(MSG_DEBUG, "%s: Received QCA TLV CFG_ACK from src: ", __func__); printMac(MSG_DEBUG, frame->etherHeader.ether_shost);
                       dprintf(MSG_DEBUG, "%s: Starting wifi restart long timer \n", __func__);
                       eloop_cancel_timeout(apacHyfi20ConfigRestartTimeoutHandler, pData, NULL);
                       eloop_register_timeout(apac_cfg_restart_long_interval, 0,
                               apacHyfi20ConfigRestartTimeoutHandler, pData, NULL);
                   } else {
                       dprintf(MSG_DEBUG, "%s: Ignoring received QCA TLV CFG_ACK as either config has not changed or we are not registrar.\n", __func__);
                   } 
                   break;
               case IEEE1905_QCA_TYPE_CFG_APPLY:
                   // Process this only if you are Enrollee
                   if (pConfig->role == APAC_ENROLLEE) {
                       dprintf(MSG_DEBUG, "%s: Received QCA TLV CFG_APPLY. Starting wifi restart short timer\n", __func__);
                       eloop_cancel_timeout(apacHyfi20ConfigApplyTimeoutHandler, pData, NULL);
                       eloop_register_timeout(apac_cfg_restart_short_interval, 0,
                               apacHyfi20ConfigRestartTimeoutHandler, pData, NULL);
                   } else {
                       dprintf(MSG_DEBUG, "%s: Ignoring received QCA TLV CFG_APPLY as we are not enrollee.\n", __func__);
                   } 
                   break;
               default:    
                   break;
            }
        }
        
        if(pConfig->atf_config_enabled == APAC_TRUE) {
            if(qcaMessage) {
                apacHyfi20ReceiveAtfConfig(message, frameLen);
            }
        }
    }
}


/* push button was actived */
void apacHyfi20EventPushButtonActivatedCB(void *eloop_ctx) {
    apacHyfi20Data_t *pData = (apacHyfi20Data_t *)eloop_ctx;
    apacHyfi20Config_t *pConfig = &pData->config;

    if (pConfig->role == APAC_REGISTRAR)  {

        pConfig->state = APAC_R_PB_WAIT_SEARCH;
    }
    else {
        apacHyfi20SendSearchE(pData);
        pConfig->state = APAC_E_PB_WAIT_RESP;

        eloop_register_timeout(pConfig->pb_search_to, 0,
                        apacHyfi20PbSearchTimeoutHandler, pData, NULL);
    }        
    eloop_register_timeout(pConfig->pushbutton_to, 0, 
                    apacHyfi20PushButtonTimeoutHandler, pData, NULL);
    
    return;
}

void apacHyfi20RMCollectTimeoutHandler(void *eloop_ctx, void *time_out) {
    apacHyfi20Data_t *pData = (apacHyfi20Data_t *)eloop_ctx;
    apacHyfi20Config_t *pConfig = &pData->config;
    apacHyfi20IF_t *pIF = pData->hyif;
    apacHyfi20AP_t *pAP = pData->ap;
    apacHyfi20WifiFreq_e band;
    apacHyfi20WifiFreq_e oldBand = APAC_WIFI_FREQ_INVALID;
    int i;

    if (!(pConfig->wlan_chip_cap == APAC_DB && pConfig->band_sel_enabled)) {
        dprintf(MSG_ERROR, "%s, Invalid!\n", __func__);
        return;
    }
    
    apacHyfi20TRACE();
        
    /* cancel any outstanding RMCollect timeout */
    eloop_cancel_timeout(apacHyfi20RMCollectTimeoutHandler, pData, NULL);

    dprintf(MSG_DEBUG, "%s, band supported by Reg: %u, band_choice: %u\n", __func__, 
            apacS.bandSupportedByReg, pConfig->band_choice);

    if ( apacS.bandSupportedByReg & (1 << pConfig->band_choice) ) {
        band = pConfig->band_choice;
    }
    else { /* XXX: currently only 2G and 5G are supported */
        if (apacS.bandSupportedByReg == (1 << APAC_WIFI_FREQ_2)) {
            band = APAC_WIFI_FREQ_2;
        }
        else if (apacS.bandSupportedByReg == (1 << APAC_WIFI_FREQ_5)) {
            band = APAC_WIFI_FREQ_5;
        }
        else if (apacS.bandSupportedByReg == (1 << APAC_WIFI_FREQ_60)) {  /* unlikely */
            band = APAC_WIFI_FREQ_60;
        }
        else {
            dprintf(MSG_INFO, "%s, No response or invalid band info (%u) from Registrar\n", 
                    __func__, apacS.bandSupportedByReg);
            return;
        }
    }

    /* update information */
    apacS.bandInRegistration = band;
    pData->config.wpsConf->rf_bands = apac_get_wps_rfband(band);
   
    /* reset info */
    for (i = 0; i < APAC_NUM_WIFI_FREQ; i++) {
        if (pAP[i].valid) {
            oldBand = pAP[i].freq;

            if (band == i) {
                break;              /*  no need to reset band */
            }

            pAP[band] = pAP[i];     /* copy the AP information */ 
            pAP[band].freq = band;  /* reset freq information */
            pAP[i].valid = APAC_FALSE; /* invalidate old AP in the previous freq band */
            break;
        }
    }

    if (oldBand == APAC_WIFI_FREQ_INVALID) {
        dprintf(MSG_ERROR, "%s, No valid band to select!\n", __func__);
        return;
    }
   
    if (oldBand != band) {
        for (i = 0; i < APAC_MAXNUM_HYIF; i++) {
            if ( pIF[i].mediaType == APAC_MEDIATYPE_WIFI && pIF[i].wifiFreq == oldBand ){
                pIF[i].wifiFreq = band;
                
                if (apacHyfi20Set80211Channel(pIF[i].ifName, band) < 0) {
                    dprintf(MSG_ERROR, "%s, can't set band to %u!\n", __func__, band);
                    return;
                }
            }
        }
    }
    
    /* for Debug */
    dprintf(MSG_DEBUG, "%s, Resetting Band...\n", __func__);
    for (i = 0; i < APAC_MAXNUM_HYIF; i++) {
        if (!pIF[i].valid)
            continue;

        if (strncmp(pIF[i].ifName, "ath", 3) == 0) {
            dprintf(MSG_DEBUG, "WlanIF: %s \tdevice mode: %u \tfreq: %u \tvapIndex: %u\n", 
                    pIF[i].ifName, pIF[i].wlanDeviceMode, pIF[i].wifiFreq, pIF[i].vapIndex); 
        

        }
    }

    dprintf(MSG_DEBUG, "%s, Start WPS registration with Wifi band %u...\n", __func__, band);

    /* Start Registration */
    if (apacHyfi20StartRegistrationE(pData, apacS.reg_src) < 0) {
        dprintf(MSG_ERROR, "%s Can't start registration \n", __func__);
        return;
    }
}

/* pushbutton times out, disabling autoconfig */ 
void apacHyfi20PushButtonTimeoutHandler(void *eloop_ctx, void *time_out) {
    apacHyfi20Data_t *pData = (apacHyfi20Data_t *)eloop_ctx;
    apacHyfi20Config_t *pConfig = &pData->config;
    
    if (pConfig->role == APAC_ENROLLEE) {
        eloop_cancel_timeout(apacHyfi20PbSearchTimeoutHandler, pData, NULL);
        pConfig->state = APAC_E_PB_IDLE;
    }
    else {
        pConfig->state = APAC_R_PB_IDLE;
    }
}    

/* resend Search Msg in PushButton mode */
void apacHyfi20PbSearchTimeoutHandler(void *eloop_ctx, void *timeout_ctx) {
    apacHyfi20Data_t *pData = (apacHyfi20Data_t *)eloop_ctx;

    apacHyfi20SendSearchE(pData);

    /* register PB search timeout callback */
    eloop_register_timeout(pData->config.pb_search_to, 0,
                    apacHyfi20PbSearchTimeoutHandler, pData, NULL);
}     

/* resend Search Msg in auto-config mode */
void apacHyfi20SearchTimeoutHandler(void *eloop_ctx, void *timeout_ctx) {
    apacHyfi20Data_t *pData = (apacHyfi20Data_t *)eloop_ctx;

    apacHyfi20SendSearchE(pData);

    const u16 *interval = (const u16 *)timeout_ctx;
    if (interval) {
        /* When an alternate interval is provided, it means we are still waiting for
           APAC complete on all band. */

        size_t i;
        u32 waitThreshold = pData->config.wait_wifi_config_secs_first;
        for (i = 0; i < APAC_NUM_WIFI_FREQ; i++) {
            if (pData->ap[i].isAutoConfigured) {
                // Wait shorter if there is already band configured
                waitThreshold = pData->config.wait_wifi_config_secs_other;
                break;
            }
        }
        pData->wifiConfigWaitSecs += *interval;
        if (pData->wifiConfigWaitSecs >= waitThreshold) {
            /* wait long enough */
            dprintf(MSG_INFO, "Abort waiting for all bands configured after %u seconds\n",
                    pData->wifiConfigWaitSecs);
            pData->wifiConfigHandle =
                apac_mib_apply_wifi_configuration(pData->wifiConfigHandle, APAC_TRUE);
            pData->wifiConfigWaitSecs = 0;
            /* Keep searching at long interval */
            interval = NULL;
        }
    }

    /* register PB search timeout callback */
    eloop_register_timeout(interval ? *interval : pData->config.search_to, 0,
                           apacHyfi20SearchTimeoutHandler, pData, (void *)interval);
}     

/* WPS session timer */ 
void apacHyfi20WpsSessionTimeoutHandler(void *eloop_ctx, void *timeout_ctx) {
    struct apac_wps_session *sess = (struct apac_wps_session *)eloop_ctx;
    apacHyfi20Data_t *pData;
    apacHyfi20Config_t *pConfig;

    if (!sess)
        return;

    pData = sess->pData;
    pConfig = &(pData->config);

    sess->wps_session_ts ++;
    if (sess->wps_session_ts >= pConfig->wps_session_to)
    {
        if (!sess->wps_sess_success)
            dprintf(MSG_ERROR, "%s session time out!\n", __func__);
        goto fail;
    }

    sess->wps_message_ts ++;
    if (sess->wps_message_ts >= pConfig->wps_per_msg_to)
    {
        if (!sess->wps_sess_success)
            dprintf(MSG_ERROR, "%s WPS packet[%d] response time out, session failed!\n", __func__, sess->state);
        goto fail;
    }

    sess->wps_retrans_ts ++;
    if (sess->wps_retrans_ts >= pConfig->wps_retransmit_to)
    {
        APAC_WPS_DATA *data = sess->pWpsData;

        if (sess->wps_sess_success)
        {
            /* Registrar need not retry when session finished
               but it response when it receives retried M7*/
        }
        else
        {
             dprintf(MSG_INFO, "%s WPS packet[%d] response time out, reqest it again!\n", __func__, sess->state);
            if (!data || !data->sndMsg || !data->sndMsgLen)
            {
                dprintf(MSG_ERROR, "%s failed to get last message!\n", __func__);
                goto fail;
            }
        
            if (apacHyfi20SendWps(sess, data->sndMsg, data->sndMsgLen) < 0) {
                dprintf(MSG_ERROR, "%s failed to retransmit last message!\n", __func__);
                return ;
            }
        }
        sess->wps_retrans_ts = 0;

    }

    eloop_register_timeout(1, 0, apacHyfi20WpsSessionTimeoutHandler, sess, NULL);
    return;

fail:
    apacHyfi20ResetState(sess, APAC_FALSE);
    apac_wps_del_session(sess);

    return;
}

/* STA scanning timeout, stop STA if it is not associated */
void apacHyfi20ScanningTimeoutHandler(void *eloop_ctx, void *timeout_ctx) {
    apacHyfi20IF_t *pIF = (apacHyfi20IF_t *)eloop_ctx;
    int32_t isRunning;
    int ret;

    ret = pbcGetVapStatus(pIF->ifName, &isRunning);
    if (ret == 0 && isRunning == 0) {
        apac_mib_set_vap_status(pIF->vapIndex, 0);
        dprintf(MSG_ERROR, "%s scanning timeout, stop VAP %s!\n", __func__, pIF->ifName);
    }
    
}

     
/* Channel polling timer */
void apacHyfi20ChannelPollingHandler(void *eloop_ctx, void *timeout_ctx) {
    apacHyfi20Data_t *pData = (apacHyfi20Data_t *)eloop_ctx;
    apacHyfi20AP_t *pAP = pData->ap;
    uint32_t oldChan;
    char oldStd[APAC_STD_MAX_LEN];
    int i, sendRenewal;

    for (i = 0; i < APAC_NUM_WIFI_FREQ; i++) {
        if (!pAP[i].valid || pAP[i].isStaOnly) 
            continue;
        sendRenewal = 0;
        oldChan = pAP[i].channel;
        strlcpy(oldStd, pAP[i].standard, APAC_STD_MAX_LEN);
        apacHyfi20GetChannel(&pAP[i]);
        apacHyfi20GetAPMode(&pAP[i]);
        if (oldChan != pAP[i].channel) {
            dprintf(MSG_INFO, "%s channel changed from %d to %d\n",
                    __func__, oldChan, pAP[i].channel);
            sendRenewal = 1;
        }
        if (strcmp(oldStd, pAP[i].standard) != 0) {
            dprintf(MSG_INFO, "%s standard changed from %s to %s\n",
                    __func__, oldStd, pAP[i].standard);
            sendRenewal = 1;
        }
        if (sendRenewal) {
            apacHyfi20SendRenewalR(pData);
        }
    }

    eloop_register_timeout(APAC_CHANNEL_POLLING_TIMEOUT, 0, 
        apacHyfi20ChannelPollingHandler, eloop_ctx, timeout_ctx);
}

/*
 * Internal APIs 
 */

/********************
 **** ENROLEE *******
 ********************/
/* Enrollee receives Renewal msg */
int apacHyfi20ReceiveRenewalE(apacHyfi20Data_t *pData, u8 *msg, u32 msgLen) {
    u32 processedLen;
    u8 *pTlvVal;
    ieee1905Message_t *frame = (ieee1905Message_t *)msg;
    ieee1905TLV_t *pTLV =  (ieee1905TLV_t *)frame->content;
    ieee1905TlvType_e tlvType;   
    u8 src[ETH_ALEN]; 
    //apacBool_e isBusy = APAC_TRUE;
    int i;

    apacBool_e isRoleMatching = APAC_FALSE;
    apacHyfi20WifiFreq_e supportedFreq = APAC_WIFI_FREQ_INVALID;
    const int num_tlv = 3;

    apacHyfi20TRACE();

    /* sanity check */
    /* Ignore Renew msg if in PB mode, or Search msg has been sent */
    if (pData->config.pbmode_enabled) {
        return 0;
    }
   
    #if 0
    /* check availability: Send Search Message if Enrollee (1) is in IDLE state, or 
     * (2) is waiting for Response Msg 
     */
    if (pData->config.state == APAC_E_IDLE || pData->config.state == APAC_E_WAIT_RESP) {
        isBusy = APAC_FALSE;
    }
    #endif

    /* check role */
    if (pData->config.role != APAC_ENROLLEE) {
        dprintf(MSG_ERROR, "%s, Device role (%u) is not ENROLLEE. Discard,\n", __func__, pData->config.role);
        return 0;
    }

    /* Message verification. */
    p1905TlvCheck_t tlvList[num_tlv];
    os_memset(tlvList, 0, sizeof(p1905TlvCheck_t)*num_tlv);
    apacHyfi20AddTlvToList(tlvList, num_tlv, IEEE1905_TLV_TYPE_AL_ID, APAC_FALSE);
    apacHyfi20AddTlvToList(tlvList, num_tlv, IEEE1905_TLV_TYPE_SUPPORTED_ROLE, APAC_FALSE);
    apacHyfi20AddTlvToList(tlvList, num_tlv, IEEE1905_TLV_TYPE_SUPPORTED_FREQ_BAND, APAC_FALSE);

    /* Parse TLV */
    processedLen = ieee1905TLVLenGet(pTLV) + IEEE1905_ETH_HEAD_LEN + IEEE1905_HEAD_LEN;
    while (processedLen <= msgLen) {
        tlvType = ieee1905TLVTypeGet(pTLV);
        dprintf(MSG_MSGDUMP, "Get TLV type: %d\n", tlvType);

        if (tlvType == IEEE1905_TLV_TYPE_END_OF_MESSAGE) {
            break;
        }

        if (apacHyfi20FindTlvInList(tlvList, tlvType, num_tlv) == APAC_FALSE) {
            dprintf(MSG_ERROR, "%s - illagel TLV type %d\n", __func__, tlvType);
            return -1;
        }

        pTlvVal = ieee1905TLVValGet(pTLV);

        if (tlvType ==  IEEE1905_TLV_TYPE_SUPPORTED_ROLE && 
            *pTlvVal == APAC_REGISTRAR)
        {
            isRoleMatching = APAC_TRUE; 
        }
        else if (tlvType == IEEE1905_TLV_TYPE_SUPPORTED_FREQ_BAND) {
            supportedFreq = *pTlvVal;
            dprintf(MSG_DEBUG, "Received Renewal For Freq %u\n", supportedFreq);
           
            #if 0 /* always sends Search Message on receiving a valid Renewal Message */
            /* check if need to process */
            if ((pData->ap[supportedFreq]).valid == APAC_FALSE) {
                dprintf(MSG_MSGDUMP, "%s, No valid AP/STA on Freq%u.\n", __func__, supportedFreq);
                return 0;
            }
            #endif

            if (supportedFreq < APAC_WIFI_FREQ_2 || supportedFreq > APAC_WIFI_FREQ_60) {
                dprintf(MSG_ERROR, "%s - received band(%d) is undefined!\n", __func__, supportedFreq);
                return -1;
            }
            dprintf(MSG_MSGDUMP, "Registrar supports freq#%d\n", *pTlvVal);

        }
        else if (tlvType == IEEE1905_TLV_TYPE_AL_ID) {
            memcpy(src, pTlvVal, ETH_ALEN);
            
            #if 0 /* disable CheckMid for renew packets */
            /* Check MID and discard the ones that have seen */
            if (apacHyfi20CheckMid(pTlvVal, mid) < 0) {
                return -1;
            }
            #endif 
        }

        processedLen += ieee1905TLVLenGet(pTLV);
        pTLV = ieee1905TLVGetNext(pTLV);
    }

    if (isRoleMatching == APAC_FALSE) {
        dprintf(MSG_ERROR, "%s Renewal is not from Registrar!\n", __func__);
        return -1;
    }

    /* Check if all required TLVs have been received */
    if (apacHyfi20ValidateTlvList(tlvList, num_tlv) == APAC_FALSE) {
        dprintf(MSG_ERROR, "required TLV type missing in the message!\n");
        return -1;
    }

    /* Clear out all AutoConfigured flags and send search messages */
    for (i = 0; i < APAC_NUM_WIFI_FREQ; i++) {
        pData->ap[i].isAutoConfigured = APAC_FALSE;
    }
    apacS.bandInRegistration = APAC_WIFI_FREQ_INVALID;
    apacS.bandSupportedByReg = 0; 

    /*delete unfinished WPS session if any*/
    {
        struct apac_wps_session* sess;
        sess = apac_wps_find_session(pData, src);

        if (sess)
        {
            dprintf(MSG_DEBUG, "Receive Renew Message, delete WPS session.\n");
            apac_wps_del_session(sess);
        }
    }
    
    /* send Search Messages and reset state */
    apacHyfi20SendSearchE(pData);
    eloop_register_timeout(pData->config.search_to, 0, apacHyfi20SearchTimeoutHandler, pData, NULL);
    
    #if 0
    /* send Search Message if Enrollee is not busy */
    if (!isBusy) {
        dprintf(MSG_DEBUG, "%s, Receive Renewal Mesage for Freq %u. Send Search\n", __func__, supportedFreq);
        apacHyfi20SendSearchE(pData);
    }

    /* Enrollee send Search msg */
    apacS.bandInRegistration = supportedFreq;
    pData->config.wpsConf->rf_bands = apac_get_wps_rfband(supportedFreq);
    dprintf(MSG_DEBUG, "%s, start registration for freq %d\n", __func__, supportedFreq);
    
    pData->ap[supportedFreq].isAutoConfigured = APAC_FALSE;
    if (apacHyfi20StartRegistrationE(pData, src) < 0) {
        dprintf(MSG_ERROR, "%s Can't start registration \n", __func__);
        return -1;    
    }
    #endif

    return 0;
}

/* Enrollee receives Response msg */
int apacHyfi20ReceiveResponseE(apacHyfi20Data_t *pData, u8 *msg, u32 msgLen) {
    apacHyfi20Config_t *pConfig = &pData->config;
    u32 processedLen;
    u8 *pTlvVal;
    ieee1905Message_t *frame = (ieee1905Message_t *)msg;
    ieee1905TLV_t *pTLV =  (ieee1905TLV_t *)frame->content;
    ieee1905TlvType_e tlvType;   
    u8 *src = frame->etherHeader.ether_shost;
    apacHyfi20WifiFreq_e supportedFreq = APAC_WIFI_FREQ_INVALID;
    u16 receivedMid; 

    apacBool_e isRoleMatching = APAC_FALSE;
    const int num_tlv = 2;

    apacHyfi20TRACE();

    if ( !(pConfig->state == APAC_E_PB_WAIT_RESP || 
           pConfig->state == APAC_E_WAIT_RESP) ) 
    {
        dprintf(MSG_ERROR, "%s state(%d) is not correct, discard\n", __func__, pConfig->state);  
        return -1;
    }

    receivedMid = ntohs(frame->ieee1905Header.mid);

    /* Message verification. */
    p1905TlvCheck_t tlvList[num_tlv];
    os_memset(tlvList, 0, sizeof(p1905TlvCheck_t)*num_tlv);
    apacHyfi20AddTlvToList(tlvList, num_tlv, IEEE1905_TLV_TYPE_SUPPORTED_ROLE, APAC_FALSE);
    apacHyfi20AddTlvToList(tlvList, num_tlv, IEEE1905_TLV_TYPE_SUPPORTED_FREQ_BAND, APAC_FALSE);

    /* Parse TLV */
    processedLen = ieee1905TLVLenGet(pTLV) + IEEE1905_ETH_HEAD_LEN + IEEE1905_HEAD_LEN;
    while (processedLen <= msgLen) {
        tlvType = ieee1905TLVTypeGet(pTLV);
        dprintf(MSG_MSGDUMP, "Get TLV type: %d\n", tlvType);

        if (tlvType == IEEE1905_TLV_TYPE_END_OF_MESSAGE) {
            break;
        }

        if (apacHyfi20FindTlvInList(tlvList, tlvType, num_tlv) == APAC_FALSE) {
            dprintf(MSG_ERROR, "%s - illegal TLV type %d, discard\n", __func__, tlvType);
            return -1;
        }

        pTlvVal = ieee1905TLVValGet(pTLV);

        if (tlvType ==  IEEE1905_TLV_TYPE_SUPPORTED_ROLE && 
            *pTlvVal == APAC_REGISTRAR)
        {
            isRoleMatching = APAC_TRUE; 
        }
        else if (tlvType == IEEE1905_TLV_TYPE_SUPPORTED_FREQ_BAND) {
            supportedFreq = *pTlvVal;
            dprintf(MSG_DEBUG, "Registrar supports freq#%d\n", *pTlvVal);
            
            if (supportedFreq < APAC_WIFI_FREQ_2 || supportedFreq > APAC_WIFI_FREQ_60) {
                dprintf(MSG_ERROR, "%s - received band(%d) is undefined!\n", __func__, supportedFreq);
                return -1;
            }

            if (apacHyfi20CheckMidOnResponseMsg(receivedMid, supportedFreq) < 0) {
                return -1;
            }
        }

        processedLen += ieee1905TLVLenGet(pTLV);
        pTLV = ieee1905TLVGetNext(pTLV);
    }

    if (isRoleMatching == APAC_FALSE) {
        dprintf(MSG_ERROR, "%s Reponser is not Registrar!\n", __func__);
        return -1;
    }

    /* Check if all required TLVs have been received */
    if (apacHyfi20ValidateTlvList(tlvList, num_tlv) == APAC_FALSE) {
        dprintf(MSG_ERROR, "required TLV type missing in the message!\n");
        return -1;
    }

    /* cancel Search timeout */
    if (pConfig->pbmode_enabled) {
        eloop_cancel_timeout(apacHyfi20PbSearchTimeoutHandler, pData, NULL);
        eloop_cancel_timeout(apacHyfi20PushButtonTimeoutHandler, pData, NULL);
    }

    /* For DB band adaptation, record band info and wait */
    if (pData->config.wlan_chip_cap == APAC_DB && pData->config.band_sel_enabled) {
        apacS.bandSupportedByReg |= (1 << supportedFreq);
        os_memcpy(apacS.reg_src, src, ETH_ALEN);
        return 0;
    }
    /* check if I have AP on the supported freq */
    if (supportedFreq == APAC_WIFI_FREQ_INVALID)
    {
        dprintf(MSG_ERROR, "Invalid Frequency!\n");
        return -1;
    }

    if (!(pData->ap[supportedFreq].valid) || pData->ap[supportedFreq].isAutoConfigured) {
        dprintf(MSG_ERROR, "Enrollee has no AP on band%d or is alread configured!\n", supportedFreq);
        return -1;
    }


    /* Start Registration */
    apacS.bandInRegistration = supportedFreq;
    pData->config.wpsConf->rf_bands = apac_get_wps_rfband(supportedFreq);
    dprintf(MSG_DEBUG, "%s, received Response include rf band %d\n", __func__, supportedFreq);
    
    if (apacHyfi20StartRegistrationE(pData, src) < 0) {
        dprintf(MSG_ERROR, "%s Can't start registration \n", __func__);
        return -1;
    }

    /* Disable 1.0 cloning client */
    if (pData->config.hyfi10_compatible)
        wsplc_disable_cloning(HYFI20ToHYFI10(pData));

    return 0;
}

/* Enrollee sends Search msg */
int apacHyfi20SendSearchE(apacHyfi20Data_t *pData) {
    apacHyfi20IF_t *pIF = pData->hyif;
    apacHyfi20AP_t *pAP = pData->ap;

    s32 i, j;
    u8 tlvValue;
    u8 dest[ETH_ALEN] = APAC_MULTICAST_ADDR;
    u32 frameLen = IEEE1905_FRAME_MIN_LEN;
    u8 *frame = apacHyfi20GetXmitBuf();
    u8 *content = ((ieee1905Message_t *)frame)->content;
    ieee1905TLV_t *TLV = (ieee1905TLV_t *) content;
    ieee1905TLV_t *TLV2;
    u8 freq;
    u32 frameLen2;
    u16 mid = 0;

    apacHyfi20TRACE();

    if (pData->config.role != APAC_ENROLLEE) {
        dprintf(MSG_ERROR, "%s, Device role (%u) is not ENROLLEE\n", __func__, pData->config.role);
        return -1;
    }

    apacHyfi20SetPktHeader(frame,IEEE1905_MSG_TYPE_AP_AUTOCONFIGURATION_SEARCH,
        mid, 0, IEEE1905_HEADER_FLAG_LAST_FRAGMENT | IEEE1905_HEADER_FLAG_RELAY,
        pData->alid, dest);

    /* Add ALID TLV */
    ieee1905TLVSet(TLV, IEEE1905_TLV_TYPE_AL_ID, ETH_ALEN, pData->alid, frameLen);
    TLV = ieee1905TLVGetNext(TLV);

    /* Add SearchedRole TLV */    
    tlvValue = APAC_REGISTRAR;
    ieee1905TLVSet(TLV, IEEE1905_TLV_TYPE_SEARCHED_ROLE, APAC_TLVLEN_ROLE, &tlvValue, frameLen);
    dprintf(MSG_MSGDUMP, "frameLen: %d\n", frameLen);

    /* Set freq TLV and send IEEE 1905 Packet from each configured IF */ 
    for (i = 0; i < APAC_NUM_WIFI_FREQ; i++) {
        if (pAP[i].valid == APAC_FALSE) {
            /* currently, only consider 2G/5G Dual Band */
            if ( !(pAP[i].freq == APAC_WIFI_FREQ_2 || pAP[i].freq == APAC_WIFI_FREQ_5) ) {
                dprintf(MSG_MSGDUMP, "%s, don't send Search Msg for freq%u .\n", __func__, i);
                continue;
            }
            if ( !(pData->config.wlan_chip_cap == APAC_DB && pData->config.band_sel_enabled) ) {
                dprintf(MSG_MSGDUMP, "%s, don't send Search Msg for freq%u .\n", __func__, i);
                continue;
            }
        }
        else if (pAP[i].isAutoConfigured) {
            dprintf(MSG_MSGDUMP, "%s - freq%d has APAC done, don't search Search Msg\n", __func__, i);
            continue;
        } 
        
        /* set up new MID for each band */
        mid = apacHyfi20GetMid();
        ((ieee1905Message_t *)frame)->ieee1905Header.mid = htons(mid);
    
        TLV2 = TLV;
        freq = pAP[i].freq;
        frameLen2 = frameLen;    
        
        /* Record Search MID sent */
        apacHyfi20SetSearchMid(mid, freq);

        TLV2 = ieee1905TLVGetNext(TLV2);
        ieee1905TLVSet(TLV2, IEEE1905_TLV_TYPE_FREQ_BAND, APAC_TLVLEN_FREQ,
           &freq, frameLen2);
        
        /* Set EndOfTLV */
        TLV2 = ieee1905TLVGetNext(TLV2);
        ieee1905EndOfTLVSet(TLV2); 

        for (j = 0; j < APAC_MAXNUM_HYIF; j++) {
            if (pIF[j].ifIndex != -1) {
                
               if (apacHyfi20SendL2Packet(&pIF[j], frame, frameLen2) < 0) {
                    perror("apacHyfi20SendSearchE"); /* could be configured AP is not started yet */
                    //return -1;  
                } 
                dprintf(MSG_DEBUG, "%s - Sent msg mid: %d on %s for freq: %d\n", __func__, mid, pIF[j].ifName, freq);
            }
        }
    }

    /* Set state after sending Search Msg */
    pData->config.state = APAC_E_WAIT_RESP;


    /* Wifi DB band selection enabled */
    if (pData->config.wlan_chip_cap == APAC_DB && pData->config.band_sel_enabled) {
        eloop_register_timeout(pData->config.rm_collect_to, 0, 
                        apacHyfi20RMCollectTimeoutHandler, pData, NULL);
    }
    return 0;
}


/********************
 **** REGISTRAR *****
 ********************/
/* Registrar receives Search msg */
int apacHyfi20ReceiveSearchR(apacHyfi20Data_t *ptrData, u8 *msg, u32 msgLen) {
    ieee1905Message_t *frame = (ieee1905Message_t *)msg;
    ieee1905TLV_t *TLV = (ieee1905TLV_t *)frame->content;
    ieee1905TlvType_e tlvType;
    u32 processedLen;
    u8 *tlvVal;
    apacBool_e isRoleMatching = APAC_FALSE;
    apacBool_e isFreqRequested[APAC_NUM_WIFI_FREQ] = {APAC_FALSE};
    u8 src_alid[ETH_ALEN]; 
    u16 mid = ntohs(frame->ieee1905Header.mid);
    u8 freq;
    const int num_tlv = 3;

    apacHyfi20TRACE();
    memcpy(src_alid, frame->etherHeader.ether_shost, ETH_ALEN);

    if (!((ptrData->config.state == APAC_R_NO_PB) || (ptrData->config.state == APAC_R_PB_WAIT_SEARCH))) {
        dprintf(MSG_DEBUG, "State(%d): discard Search Msg\n", ptrData->config.state);
        return -1;
    }

    if (ntohs(frame->ieee1905Header.type) != IEEE1905_MSG_TYPE_AP_AUTOCONFIGURATION_SEARCH) {
        dprintf(MSG_ERROR, "Msg Type %u is not SEARCH(7)\n", ntohs(frame->ieee1905Header.type));
        return -1;
    }

    /* Message verification. Search Msg TLVs: 1 ALID, 1 SearchRole, 1 FreqBand */
    p1905TlvCheck_t tlvList[num_tlv];
    os_memset(tlvList, 0, sizeof(p1905TlvCheck_t)*num_tlv);
    apacHyfi20AddTlvToList(tlvList, num_tlv, IEEE1905_TLV_TYPE_AL_ID, APAC_FALSE);
    apacHyfi20AddTlvToList(tlvList, num_tlv, IEEE1905_TLV_TYPE_SEARCHED_ROLE, APAC_FALSE);
    apacHyfi20AddTlvToList(tlvList, num_tlv, IEEE1905_TLV_TYPE_FREQ_BAND, APAC_FALSE);

    /* Parse TLV */
    processedLen = ieee1905TLVLenGet(TLV) + IEEE1905_ETH_HEAD_LEN + IEEE1905_HEAD_LEN;
    while (processedLen <= msgLen) {
        tlvType = ieee1905TLVTypeGet(TLV);
        dprintf(MSG_MSGDUMP, "Get TLV type: %d\n", tlvType);

        if (tlvType == IEEE1905_TLV_TYPE_END_OF_MESSAGE) {
            break;
        }

        tlvVal = ieee1905TLVValGet(TLV);

        if (apacHyfi20FindTlvInList(tlvList, tlvType, num_tlv) == APAC_FALSE) {
            dprintf(MSG_ERROR, "%s - illegal tlv type %d, discard\n", __func__, tlvType);
            return -1;
        }

        if (tlvType ==  IEEE1905_TLV_TYPE_SEARCHED_ROLE && 
            *tlvVal == APAC_REGISTRAR)
        {
            isRoleMatching = APAC_TRUE; 
        }
        else if (tlvType == IEEE1905_TLV_TYPE_FREQ_BAND) {
            isFreqRequested[*tlvVal] = APAC_TRUE;
            dprintf(MSG_DEBUG, "Enrollee request freq#%d\n", *tlvVal);
        }
        else if (tlvType == IEEE1905_TLV_TYPE_AL_ID) {
            /* Check MID and discard the ones that have seen */
            if (apacHyfi20CheckMid(tlvVal, mid) < 0) {
                return -1;
            }

            /* use src ALID as the destination address */
            memcpy(src_alid, tlvVal, ETH_ALEN);
        }

        processedLen += ieee1905TLVLenGet(TLV);
        TLV = ieee1905TLVGetNext(TLV);
    }

    if (isRoleMatching == APAC_FALSE) {
        dprintf(MSG_ERROR, "Search Msg not looking for Registrar!\n");
        return -1;
    }

    /* Check if all required TLVs have been received */
    if (apacHyfi20ValidateTlvList(tlvList, num_tlv) == APAC_FALSE) {
        dprintf(MSG_ERROR, "required TLV type missing in the message!\n");
        return -1;
    }
    /* Send response msg */
    for (freq = 0; freq < APAC_NUM_WIFI_FREQ; freq++) {
        if (ptrData->ap[freq].valid && isFreqRequested[freq]) {
            dprintf(MSG_MSGDUMP, "Send response for freq#%d\n", freq);
            apacHyfi20SendResponseR(ptrData, src_alid, freq, mid);
        }   
    } 

    if (ptrData->config.state == APAC_R_PB_WAIT_SEARCH) {
        ptrData->config.state = APAC_R_PB_WAIT_M1;
    } 

    /*delete unfinished WPS session if any*/
    {
        struct apac_wps_session* sess;
        sess = apac_wps_find_session(ptrData, src_alid);
        if (sess)
        {
            dprintf(MSG_DEBUG, "Searching received from Enrollee, delete stale session!\n");
            apac_wps_del_session(sess);
        }
    }
    return 0;
}

/* Registrar sends Response msg */
int apacHyfi20SendResponseR(apacHyfi20Data_t *pData, u8 *dest_mac, u8 freq, u16 mid) 
{    
    u8 tlvValue;
    u32 frameLen = IEEE1905_FRAME_MIN_LEN;
    u8 *frame = apacHyfi20GetXmitBuf();
    u8 *payload = ((ieee1905Message_t *)frame)->content;
    ieee1905TLV_t *TLV = (ieee1905TLV_t *)payload;

    apacHyfi20TRACE();

    apacHyfi20SetPktHeader(frame, IEEE1905_MSG_TYPE_AP_AUTOCONFIGURATION_RESPONSE, 
        mid, 0, IEEE1905_HEADER_FLAG_LAST_FRAGMENT, pData->alid, dest_mac);

    /* Add SupportedRole TLV */
    tlvValue = APAC_REGISTRAR;
    ieee1905TLVSet(TLV, IEEE1905_TLV_TYPE_SUPPORTED_ROLE, APAC_TLVLEN_ROLE, &tlvValue, frameLen);

    /* Set SupportedFreq TLV */
    TLV = ieee1905TLVGetNext(TLV);
    ieee1905TLVSet(TLV, IEEE1905_TLV_TYPE_SUPPORTED_FREQ_BAND, APAC_TLVLEN_ROLE, &freq, frameLen);

    /* Set EndOfTLV */
    TLV = ieee1905TLVGetNext(TLV);
    ieee1905EndOfTLVSet(TLV);

    /* Send the packt */
    if (pData->config.sendOnAllIFs == APAC_FALSE) {
        if (send(pData->bridge.sock, frame, frameLen, 0) < 0) {
            perror("apacHyfi20SendResponseR");
            return -1;
        }
    }
    else {  /* send unicast packet on all interfaces. Debug Only! */
        int i;
        for (i = 0; i < APAC_MAXNUM_HYIF; i++) {
            if (pData->hyif[i].ifIndex == -1) 
                continue;

            if (apacHyfi20SendL2Packet(&pData->hyif[i], frame, frameLen) < 0) {
                perror("apacHyfi20SendResponseR-onAllIFs");
            }
        }
    }

    dprintf(MSG_MSGDUMP, "%s - Sent msg mid: %d\n", __func__, mid);
    return 0;
}

/* Registrar sends Renewal msg */
int apacHyfi20SendRenewalR(apacHyfi20Data_t *pData){
    apacHyfi20IF_t *pIF = pData->hyif;
    apacHyfi20AP_t *pAP = pData->ap;

    s32 i, j;
    u8 tlvValue;
    u8 dest[ETH_ALEN] = APAC_MULTICAST_ADDR;
    u32 frameLen = IEEE1905_FRAME_MIN_LEN;
    u8 *frame = apacHyfi20GetXmitBuf();
    ieee1905TLV_t *TLV = (ieee1905TLV_t *)((ieee1905Message_t *)frame)-> content;
    ieee1905TLV_t *TLV2;
    u8 freq;
    u32 frameLen2;
    u16 mid = 0;

    apacHyfi20TRACE();

    apacHyfi20SetPktHeader(frame,IEEE1905_MSG_TYPE_AP_AUTOCONFIGURATION_RENEW,
        mid, 0, IEEE1905_HEADER_FLAG_LAST_FRAGMENT | IEEE1905_HEADER_FLAG_RELAY,
        pData->alid, dest);

    /* Add ALID TLV */
    ieee1905TLVSet(TLV, IEEE1905_TLV_TYPE_AL_ID, ETH_ALEN, pData->alid, frameLen);
    TLV = ieee1905TLVGetNext(TLV);

    /* Add SupportedRole TLV */    
    tlvValue = APAC_REGISTRAR;
    ieee1905TLVSet(TLV, IEEE1905_TLV_TYPE_SUPPORTED_ROLE, APAC_TLVLEN_ROLE, &tlvValue, frameLen);
    dprintf(MSG_MSGDUMP, "frameLen: %d\n", frameLen);

    /* Set freq TLV and send IEEE 1905 Packet from each configured IF */ 
    for (i = 0; i < APAC_NUM_WIFI_FREQ; i++) {
        if (pAP[i].valid == APAC_FALSE) {
            continue;
        }
       
        /* set up new MID for each band */
        mid = apacHyfi20GetMid();
        ((ieee1905Message_t *)frame)->ieee1905Header.mid = htons(mid);
    
        TLV2 = TLV;
        freq = pAP[i].freq;
        frameLen2 = frameLen;    

        TLV2 = ieee1905TLVGetNext(TLV2);
        ieee1905TLVSet(TLV2, IEEE1905_TLV_TYPE_SUPPORTED_FREQ_BAND, APAC_TLVLEN_FREQ,
           &freq, frameLen2);
        dprintf(MSG_MSGDUMP, "frameLen2: %d\t", frameLen2);
        dprintf(MSG_MSGDUMP, "set TLV (freq#%d: %d)\n", i, freq);
        
        /* Set EndOfTLV */
        TLV2 = ieee1905TLVGetNext(TLV2);
        ieee1905EndOfTLVSet(TLV2); 

        for (j = 0; j < APAC_MAXNUM_HYIF; j++) {
            if (pIF[j].ifIndex != -1) {
               if (apacHyfi20SendL2Packet(&pIF[j], frame, frameLen2) < 0) {
                    perror("apacHyfi20SendSearchE");
                    //return -1;
                } 
                dprintf(MSG_MSGDUMP, "%s - Sent msg mid: %d on IF%d for freq: %d\n", __func__, mid, j, i);
            }
        }
    }

    return 0;
}

/* Registrar/Enrollee sends WPS msg */
int apacHyfi20SendWps(struct apac_wps_session *sess, u8 *wpsMsg, size_t wpsMsgLen)
{
    //APAC_WPS_DATA *pWpsData = sess->pWpsData;

    u8 *frame;
    ieee1905MessageType_e msgType = IEEE1905_MSG_TYPE_AP_AUTOCONFIGURATION_WPS;
    u16 mid = apacHyfi20GetMid();
    u8 flags;
    u8 *src;
    u8 *dest;

    u8 fragNum;
    size_t frameLen;
    u8 *curWpsMsg = wpsMsg;
    size_t curWpsMsgLen = wpsMsgLen; 
    ieee1905TLV_t *TLV;

    /* Overhead: WPS TLV + EndTLV */   
    size_t maxWpsMsgLen = IEEE1905_CONTENT_MAXLEN - 2 * IEEE1905_TLV_MIN_LEN;

    apacHyfi20TRACE();
    src = sess->own_addr;
    dest = sess->dest_addr;

    if (!src || !dest) {
        dprintf(MSG_ERROR, "src or dest address is null!\n");
        dprintf(MSG_ERROR, " src: "); printMac(MSG_DEBUG, src);
        dprintf(MSG_ERROR, " dest: "); printMac(MSG_DEBUG, dest);

        return -1;
    }

    /* construct WPS packet */
    flags = 0;
    fragNum = 0;
    while (curWpsMsgLen > 0) {
        frame = apacHyfi20GetXmitBuf();
        frameLen = IEEE1905_FRAME_MIN_LEN;
        TLV = (ieee1905TLV_t *)((ieee1905Message_t *)frame)->content;

        /* last frame */
        if (curWpsMsgLen <= maxWpsMsgLen) {
            flags |= IEEE1905_HEADER_FLAG_LAST_FRAGMENT;

            /* Add WPS TLV */
            ieee1905TLVSet(TLV, IEEE1905_TLV_TYPE_WPS, curWpsMsgLen, curWpsMsg, frameLen); 
            curWpsMsg += curWpsMsgLen;
            curWpsMsgLen = 0;
        }
        else {
            ieee1905TLVSet(TLV, IEEE1905_TLV_TYPE_WPS, maxWpsMsgLen, curWpsMsg, frameLen); 

            curWpsMsgLen -= maxWpsMsgLen;
            curWpsMsg += maxWpsMsgLen;
        }
        dprintf(MSG_DEBUG, "fid: %d, wpsMsgLen: %u\n", fragNum, curWpsMsgLen);


        /* Add EndOfTlv */
        TLV = ieee1905TLVGetNext(TLV); 
        ieee1905EndOfTLVSet(TLV);

        /* set up packet header */
        apacHyfi20SetPktHeader(frame, msgType, mid, fragNum, flags, src, dest);

        /* send packet */
        if (sess->pData->config.sendOnAllIFs == APAC_FALSE) {
            if (send(sess->pData->bridge.sock, frame, frameLen, 0) < 0) {
                perror("apacHyfi20SendWps");
                return -1;
            }
        }
        else {  /* send unicast packet on all interfaces. Debug Only! */
            int i;
            for (i = 0; i < APAC_MAXNUM_HYIF; i++) {
                if (sess->pData->hyif[i].ifIndex == -1) 
                    continue;

                if (apacHyfi20SendL2Packet(&sess->pData->hyif[i], frame, frameLen) < 0) {
                    perror("apacHyfi20SendResponseR-onAllIFs");
                }
            }
        }

        

        dprintf(MSG_DEBUG, "%s len of msg sent: %u, mid: %u\n", __func__, frameLen, mid);
        fragNum++;
    }

    return 0;
}

/* Process WPS request in Registration Phase 
 * Registrar receives M1, M3, M5, and M7; sends M2, M4, M6 and M8
 * Enrollee sends M1, M3, M5, and M7; receives M2, M4, M6 and M8
 */
int apacHyfi20ReceiveWps(apacHyfi20Data_t *pData, u8 *buf, u32 len) {
#if 0
    srand((unsigned int) time(NULL));
    if (random() % 3 == 0)
    {
        /*drop packets*/
        dprintf(MSG_ERROR, "1905.1 AP Auto Configuration Packet dropped for testing\n");
        return 0;
    }
#endif

    if (pData->config.role == APAC_ENROLLEE) {
        return apacHyfi20ReceiveWpsE(pData, buf, len);
    }
    else if (pData->config.role == APAC_REGISTRAR) {
        return apacHyfi20ReceiveWpsR(pData, buf, len);
    }
    else {
        dprintf(MSG_ERROR, "%s Device role (%d) not supported!\n", __func__, pData->config.role);
        return -1;
    }
}

int apacHyfi20Startup(apacHyfi20Data_t *ptrData) {
    apacHyfi20Config_t *pConfig = &ptrData->config;

    /* XXX pushbutton enabled: only SM. APAC with PB feature is not supported (3/5/2012) */
    if (pConfig->pbmode_enabled == APAC_TRUE) {
        //XXX register PBActivatedCB when pushbutton signal is received
        
        /* Wait for push button signal */
        if (pConfig->role == APAC_REGISTRAR) {
            pConfig->state = APAC_R_PB_IDLE;
        }
        else {
            pConfig->state = APAC_E_PB_IDLE;
        }
        return 0;
    }

    /* pushbutton disabled */
    if (pConfig->role == APAC_REGISTRAR) {
        if ((pConfig->cfg_changed) && (pConfig->role == APAC_REGISTRAR)) {
            /* Start restart timer */
            eloop_register_timeout(apac_cfg_restart_long_interval, 0,
                            apacHyfi20ConfigRestartTimeoutHandler, ptrData, NULL);
        }
        apacHyfi20SendRenewalR(ptrData);
        pConfig->state = APAC_R_NO_PB;
        /* register channel polling timer */
        apacHyfi20ChannelPollingHandler(ptrData, NULL);
    }
    else {
        apacHyfi20SendSearchE(ptrData);
        pConfig->state = APAC_E_WAIT_RESP;

        /* register Search timout */
        eloop_register_timeout(pConfig->search_to, 0, 
                        apacHyfi20SearchTimeoutHandler, ptrData, NULL);
    }

    if(pConfig->atf_config_enabled == APAC_TRUE) {
        int rep_index = 0;
        for( rep_index = 0; rep_index < pConfig->apac_atf_num_repeaters; rep_index++) {
            dprintf(MSG_INFO, "Send ATF configuration\n\r");
            apacHyfi20SendAtfConfig(ptrData, rep_index);
        }
    }

    return 0;
}

void apacHyfi20ResetState(struct apac_wps_session *sess, apacBool_e success) {
    apacHyfi20Config_t *pConfig = &(sess->pData->config);
    apacHyfi20AP_t *pAP = sess->pData->ap;
    int i;

    if (!sess) {
        dprintf(MSG_ERROR, "%s sess is NULL!\n", __func__);
        return;
    }

    apacHyfi20TRACE();

    /* It may have been cancelled already, but just double make-sure */
    eloop_cancel_timeout(apacHyfi20WpsSessionTimeoutHandler, sess, NULL);

    if (pConfig->role == APAC_ENROLLEE) {
        apacHyfi20WifiFreq_e freq = apacS.bandInRegistration;

        apacS.bandSupportedByReg = 0; 
        
        if (freq == APAC_WIFI_FREQ_INVALID) {
            dprintf(MSG_ERROR, "%s - Invalid Band(%d)!\n", __func__, apacS.bandInRegistration);
            return;
        }

        /* Once APAC is successful, reset apacS band information  */
        if (success) {
            dprintf(MSG_DEBUG, "band %u is configured\n", freq);
            if (pAP[freq].isAutoConfigured) {
                dprintf(MSG_ERROR, "%s band#%u has been auto-configured before\n", __func__, freq);
            }
            else {
                pAP[freq].isAutoConfigured = APAC_TRUE;
            }
            apacS.bandInRegistration = APAC_WIFI_FREQ_INVALID;

            /* Enrollee, check if needs to resume search timeout */
            for (i = 0; i < APAC_NUM_WIFI_FREQ; i++) {
                if (!(pAP[i].isAutoConfigured) && pAP[i].valid) {
                    /* do not send search right away, give some time */
                    /* register search timeout callback */
                    dprintf(MSG_DEBUG, "%s, band %u not configured. Send search in %u seconds\n",
                            __func__, i, APAC_SEARCH_SHORT_INTERVAL);

                    /* Reset wait timer to make sure the other band has enough time to */
                    /* complete cloning */
                    sess->pData->wifiConfigWaitSecs = 0;
                    eloop_register_timeout(APAC_SEARCH_SHORT_INTERVAL, 0,
                                           apacHyfi20SearchTimeoutHandler,
                                           sess->pData, (void *)&APAC_SEARCH_SHORT_INTERVAL);
                    return;  
                }
            }

            /* All bands are configured */
            eloop_cancel_timeout(apacHyfi20SearchTimeoutHandler, sess->pData,
                                 (void *)&APAC_SEARCH_SHORT_INTERVAL);
            dprintf(MSG_DEBUG, "All bands configuration received, apply\n");
            // Send "Config Ack Message" here and start a Apply timer
            apacHyfi20SendConfigAckE(sess);

            dprintf(MSG_INFO, "Starting config apply timer %s\n", __func__);
            eloop_register_timeout(apac_cfg_apply_interval, 0,
                                   apacHyfi20ConfigApplyTimeoutHandler,
                                   sess->pData, NULL);

            return;
        }

        /* APAC is not successful, resend Search */
        apacS.bandInRegistration = APAC_WIFI_FREQ_INVALID;
        apacHyfi20SendSearchE(sess->pData);
        pConfig->state = APAC_E_WAIT_RESP;
        eloop_register_timeout(pConfig->search_to, 0, apacHyfi20SearchTimeoutHandler, sess->pData, NULL);
        return;  
    }
    else if (pConfig->role == APAC_REGISTRAR) {
        pConfig->state = (pConfig->pbmode_enabled ? APAC_R_PB_IDLE : APAC_R_NO_PB);
    }
    else {
        dprintf(MSG_INFO, "%s, device is neither Registrar nor Enrollee: %u\n", __func__, pConfig->role);
    }

}


