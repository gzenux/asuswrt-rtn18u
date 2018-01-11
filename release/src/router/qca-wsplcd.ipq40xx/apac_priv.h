/* @file: apac_priv.h
 * @Notes:
 *
 * Copyright (c) 2011-2012 Qualcomm Atheros, Inc.
 * Qualcomm Atheros Confidential and Proprietary. 
 * All rights reserved.
 *
 */

#ifndef _APAC_PRIV_H
#define _APAC_PRIV_H

#include "wsplcd.h"
#include "mid.h"
#include <ieee80211_external.h>

/********************************************************* 
 * AP Auto-Configuration(APAC) data structures 
 * Version HYFI-2.0
 *********************************************************/

#define MAC_ZEROS       "\x00\x00\x00\x00\x00\x00"

/* debug macro */
#define apacHyfi20TRACE()   \
    dprintf(MSG_DEBUG, "*********%s**********\n", __func__) 

/* validate state */
#define apacHyfi20CheckState(_S1, _S2)   \
    { if(_S1 != _S2) {\
    dprintf(MSG_DEBUG, "%s, my state(%d) != %d!\n", __func__, _S1, _S2);\
    return -1;}}

/* print MAC address */
#define printMac(_l, _mac)  \
    {dprintf(_l, "%02x:%02x:%02x:%02x:%02x:%02x \n", \
     _mac[0], _mac[1], _mac[2], _mac[3], _mac[4], _mac[5]);} \

/* print AVLN address */
#define printAvln(_l, _avln)  \
    {dprintf(_l, "%02x:%02x:%02x:%02x:%02x:%02x:%02x \n", \
     _avln[0], _avln[1], _avln[2], _avln[3], _avln[4], _avln[5], _avln[6]);} \


typedef struct p1905TlvCheck_t {
    ieee1905TlvType_e tlvType;
    apacBool_e valid;
    apacBool_e multiTlvAllowed;     /* allow multiple TLVs of the same type */ 

} p1905TlvCheck_t;

typedef struct apacHyfi20SearchMid_t {
    apacBool_e valid;
    apacHyfi20WifiFreq_e freq;
    u16 mid;
    
} apacHyfi20SearchMid_t;

typedef struct apacHyfi20GlobalState_t {
    u16 mid;
    apacHyfi20SearchMid_t searchMidSent[APAC_NUM_WIFI_FREQ];
    u8  xmitBuf[ETH_FRAME_LEN];
    
    apacHyfi20WifiFreq_e bandInRegistration;  /* support sequential registration of band info */
    
    u8  bandSupportedByReg;       /* support DB band adapation */
    u8  reg_src[ETH_ALEN];

    u8  alidPbcJoin[ETH_ALEN];   /* alid of mine or from the latest PBC Event Notificaiton Msg */
    u16 midPbcJoin;                /* mid of the latest PBC Event Notification Msg sent/received */
    apacHyfi20Data_t *pApacData;

} apacHyfi20GlobalState_t;

/* record mid/alid of received messages */
typedef struct apacHyfi20NodeTbl_t {
    apacBool_e valid; 

    u8 src_alid[ETH_ALEN];
    u16 src_mid;

} apacHyfi20NodeTbl_t;

typedef struct {
    enum ieee80211_cwm_width width;    /*channel bandwidth*/
    u_int8_t ifreq1;   /*center frequency index1, 0-200*/
    u_int8_t ifreq2;   /*certer frequency index2, 0-200*/
    u_int8_t offset;   /*channel offset*/
} apacHyfi20ChanInfo_t;

/*
 * CallBacks
 */
/* receive IEEE1905 packet; check packet type and dispatch */
void apacHyfi20GetIEEE1905PktCB(int sock, void *eloop_ctx, void *sock_ctx);

/* Receive Plc Call Back */
void pbcHyfi20GetUnixSockPlcMsgCB(s32 sock, void *eloop_ctx, void *sock_ctx);

/* receive netlink message */
void pbcHyfi20GetNLMsgCB(s32 sock, void *eloop_ctx, void *sock_ctx);

/* receive pipe message */
void pbcHyfi20GetPipeMsgCB(s32 fd, void *eloop_ctx, void *sock_ctx);

/* push button was actived */
void apacHyfi20EventPushButtonActivatedCB(void *eloop_ctx);

/* resend Search Msg in auto-config mode */
void apacHyfi20SearchTimeoutHandler(void *eloop_ctx, void *timeout_ctx);     

/* resend Search Msg in PushButton mode */
void apacHyfi20PbSearchTimeoutHandler(void *eloop_ctx, void *timeout_ctx);     

/* disable autoconfig */ 
void apacHyfi20PushButtonTimeoutHandler(void *eloop_ctx, void *time_out);    

/* WPS session time out */ 
void apacHyfi20WpsSessionTimeoutHandler(void *eloop_ctx, void *timeout_ctx);

/* STA scanning time out */
void apacHyfi20ScanningTimeoutHandler(void *eloop_ctx, void *timeout_ctx);

/*
 * Internal APIs 
 */
/* initialize  */
int apacHyfi20Init(apacHyfi20Data_t *ptrData);
void apacHyfi20ConfigInit(apacHyfi20Data_t *ptrData);
void apacHyfi20ConfigDump(apacHyfi20Data_t *ptrData);
void apacHyfi20CmdConfig(apacHyfi20Data_t *ptrData, int argc, char ** argv);
int apac_config_parse_file(apacHyfi20Data_t *pData, const char *fname);
char * apac_config_line_lex(char *buf, char **value_out);
int apacHyfi20InitDeviceInfo(apacHyfi20Data_t *ptrData); 
int apacHyfi20InitIEEE1905Sock(char* ifname);
int apacHyfi20InitNLSock();
int apacHyfi20InitPipeFd();
int apacHyfi20InitPlcUnixSock();
int apacHyfi20ResetPipeFd(apacHyfi20Data_t *pData);
int apacHyfi20ResetIeee1905TXSock(apacHyfi20IF_t *pIF);
int apacHyfi20ResetIeee1905RXSock(apacHyfi20Data_t *pData);

int apacHyfi20SendL2Packet(apacHyfi20IF_t *pIF, u8 *frame, u32 frameLen);
u8 *apacHyfi20GetXmitBuf();
int apacHyfi20SetPktHeader(u8 *frame, ieee1905MessageType_e type, 
    u16 mid, u8 fid, u8 flags, u8 *src, u8 *dest); 
int apacHyfi20Set80211Channel(const char *ifName, apacHyfi20WifiFreq_e freq);
int apacHyfi20GetChannel(apacHyfi20AP_t *pAP);
int apacHyfi20GetAPMode(apacHyfi20AP_t *pAP);
int apacHyfi20GetAPChannelInfo(const char *ifName, apacHyfi20ChanInfo_t *chaninfo);
int apacHyfi20GetWlanBestStandard(const int rindex, int chan, char *regStd, char **bestStd);

/**
 * @brief Parse log file mode from command line
 */
void apacHyfi20CmdLogFileMode(int argc, char **argv);

/* destroy sockets */
void apacHyfi20DeinitSock(apacHyfi20Data_t *ptrData);

/* device starting up; check its role*/
int apacHyfi20Startup(apacHyfi20Data_t *ptrData);

/* reset state when registration is done */
void apacHyfi20ResetState(struct apac_wps_session *sess, apacBool_e success);

/********************
 **** ENROLEE *******
 ********************/
/* Enrollee receives Renewal msg */
int apacHyfi20ReceiveRenewalE(apacHyfi20Data_t *ptrData, u8 *frame, u32 frameLen);

/* Enrollee receives Response msg */
int apacHyfi20ReceiveResponseE(apacHyfi20Data_t *ptrData, u8 *frame, u32 frameLen);

/* Enrollee sends Search msg */
int apacHyfi20SendSearchE(apacHyfi20Data_t *ptrData);

/* Upon receiving Response/Renewal msg, Registrar enters Registration Phase */
int apacHyfi20StartRegistrationE(apacHyfi20Data_t *pData, u8 *reg_mac);


/********************
 **** REGISTRAR *****
 ********************/
/* Registrar receives Search msg */
int apacHyfi20ReceiveSearchR(apacHyfi20Data_t *ptrData, u8 *frame, u32 frameLen);

/* Registrar sends Response msg */
int apacHyfi20SendResponseR(apacHyfi20Data_t *ptrData, u8 *dest_mac, u8 freq, u16 mid);

/* Registrar sends Renewal msg */
int apacHyfi20SendRenewalR(apacHyfi20Data_t *ptrData);

/* Registrar/Enrollee sends WPS packet */ 
int apacHyfi20SendWps(struct apac_wps_session *sess, u8 *wps, size_t wpsLen);

/* Receive APAC_WPS packet 
 * Registrar receives M1, M3, M5, and M7; sends M2, M4, M6 and M8
 * Enrollee sends M1, M3, M5, and M7; receives M2, M4, M6 and M8
 */
int apacHyfi20ReceiveWps(apacHyfi20Data_t *pData, u8 *buf, u32 len);
int apacHyfi20ReceiveWpsR(apacHyfi20Data_t *pData, u8 *payload, u32 payloadLen);
int apacHyfi20ReceiveWpsE(apacHyfi20Data_t *pData, u8 *payload, u32 payloadLen);

/* Push Button Configuration */
int pbcReceiveEventNotificationMsg(apacHyfi20Data_t *pData, u8 *frame, size_t frameLen);
void pbcHyfi20EventPushButtonActivated(apacHyfi20Data_t *pData);
void wsplc_pushbutton_activated(wsplcd_data_t* wspd, int duration);

void apacHyfi20VendorSpecificHandle(apacHyfi20Data_t *pData, u8 *frame, size_t frameLen);

/*
 * utility tools
 */

/* ioctl */
int apacHyfi20GetDeviceMode(apacHyfi20IF_t *pIF);
int apacHyfi20GetFreq(apacHyfi20IF_t *pIF);
int apacHyfi20GetVapStatus(const char *ifName, s32 *status);
int pbcGetName(char *ifName, char *name);
int pbcGetBssid(char *ifName, u8 *bssid); /* WLAN mode, e.g. 80211na */
int pbcGetVapStatus(char *ifName, s32 *isRunning);

/* mid */
u16 apacHyfi20GetMid();
int apacHyfi20CheckMid(u8 *alid, u16 mid);
apacBool_e apacHyfi20FindTlvInList(p1905TlvCheck_t *tlvList, ieee1905TlvType_e tlvType, int num);

/* Check TLV */
int apacHyfi20AddTlvToList(p1905TlvCheck_t *tlvList, const int num, 
    ieee1905TlvType_e tlvType, apacBool_e multi);

/* Check if received TLV is required */
apacBool_e apacHyfi20FindTlvInList(p1905TlvCheck_t *tlvList, ieee1905TlvType_e tlvType, const int num);

apacBool_e apacHyfi20ValidateTlvList(p1905TlvCheck_t *list, const int num);

void printMsg(u8 *frame, size_t frameLen, s32 dLevel);

/* convert between APAC_FREQ and WPS_RF_BAND */
u32 apac_get_wps_rfband(apacHyfi20WifiFreq_e freq); 
apacHyfi20WifiFreq_e apac_get_freq(u32 rf_band);

/* Number of seconds sending APAC search on a different band
 * after APAC completes on one band. */
extern const u16 APAC_SEARCH_SHORT_INTERVAL;

#endif // APAC_PRIV_H
