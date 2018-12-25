

#ifndef LIB1x_COMMON_H
#define LIB1x_COMMON_H


//--------------------------------------------------
// IEEE 802.1x Implementation
//
// File		: common.h
// Programmer	: Arunesh Mishra
//
// Contains all common declarations and definitions.
// Copyright (c) Arunesh Mishra 2002
// All rights reserved.
// Maryland Information and Systems Security Lab
// University of Maryland, College Park.
//--------------------------------------------------

#include<assert.h>
#include<stdarg.h>
#include<sys/types.h>
#include<stdio.h>
#include <syslog.h>	// david+2006-03-31, for add event to syslog

#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>

#ifndef RTL_WPA_CLIENT
#if !defined(CONFIG_RTL8186_TR) && !defined(CONFIG_RTL865X_AC)
#define RTL_WPA_CLIENT
	//#define DBG_WPA_CLIENT
#endif
#endif

#ifdef _RTL_WPA_WINDOWS

#else
#include "1x_types.h"
#include "1x_ethernet.h"
#include "1x_kmsm_keydef.h"
#endif

#ifdef RTL_WPA2	
#include "1x_list.h"
typedef struct pmksa_list_t
{
	u_long quota;
	struct list_head pmk_cache;
} PMKSA_LIST;
#endif 

#if defined(CONFIG_RTL8186_TR) || defined(CONFIG_RTL865X_SC) || defined(CONFIG_RTL865X_AC) || defined(CONFIG_RTL865X_KLD)
#define _NOTICE	"tag:NOTICE;log_num:13;msg:"
#define _CMD "exlog /tmp/log_web.lck /tmp/log_web"

#define LOG_MSG_NOTICE(fmt, args...) { \
	char tmpbuf[400]; \	
	sprintf(tmpbuf, "%s \"%s" fmt "\"", _CMD, _NOTICE, ## args); \
	system(tmpbuf); \
}
#endif

union PN48 {
	unsigned long long val48;

	struct {
		unsigned char TSC7;
		unsigned char TSC6;
		unsigned char TSC5;
		unsigned char TSC4;
		unsigned char TSC3;
		unsigned char TSC2;
		unsigned char TSC1;
		unsigned char TSC0;
	} _byte_;
};

#ifdef CONFIG_RTL_ETH_802DOT1X_SUPPORT
typedef enum {ETH_DOT1X_CLIENT_MODE=1,ETH_DOT1X_PROXY_MODE=2}ETH_DOT1X_MODE_T;
typedef enum {ETH_DOT1X_PROXY_PORT_BASE=1,ETH_DOT1X_PROXY_MAC_BASE=2}ETH_DOT1X_PROXY_TYPE_T;
#endif
#if defined(CONFIG_RTL_802_1X_CLIENT_SUPPORT) || defined(CONFIG_RTL_ETH_802DOT1X_CLIENT_MODE_SUPPORT)
typedef enum { EAP_MD5=0, EAP_TLS=1, EAP_PEAP=2,EAP_TTLS=3 } EAP_TYPE_T;

typedef enum { INSIDE_MSCHAPV2=0 } INSIDE_TYPE_T;
typedef enum { PHYBAND_OFF=0, PHYBAND_2G=1, PHYBAND_5G=2 } PHYBAND_TYPE_T;
#define MAX_EAP_USER_ID_LEN 			64
#define MAX_RS_USER_NAME_LEN 			64
#define MAX_RS_USER_PASS_LEN 			64
#define MAX_RS_USER_CERT_PASS_LEN 	64
//#define RS_USER_CERT 				"/var/1x/client.pem"
#define RS_USER_CERT_2G 				"/var/1x/client_2g.pem"
#define RS_USER_CERT_5G 				"/var/1x/client_5g.pem"
//#define RS_ROOT_CERT 				"/var/1x/ca.pem"
#define RS_ROOT_CERT_2G			"/var/1x/ca_2g.pem"
#define RS_ROOT_CERT_5G			"/var/1x/ca_5g.pem"
#ifdef CONFIG_RTL_ETH_802DOT1X_CLIENT_MODE_SUPPORT
#define RS_USER_CERT_ETH	"/var/1x/client_eth.pem"
#define RS_ROOT_CERT_ETH	"/var/1x/ca_eth.pem"
#endif
#ifdef RTL_TTLS_CLIENT
	typedef enum { TTLS_PHASE2_EAP=0,TTLS_PHASE2_PAP=1,TTLS_PHASE2_CHAP=2,TTLS_PHASE2_MSCHAP=3,TTLS_PHASE2_MSCHAPV2=4 } TTLS_PHASE2_TYPE_T;
	typedef enum { TTLS_PHASE2_EAP_MD5=0 } TTLS_PHASE2_EAP_METHOD_T;
#endif
//#define XSUP_CONF_FILE 				"/var/1x/1x.conf"
#define XSUP_CONF_FILE_NAME_FMT	"/var/1x/1x-%s.conf"
//#define XSUP_CONF_MODULE_FILE 	"/var/1x/1x_module.conf"
#define XSUP_MD5_CONF_MODULE_FILE 	"/var/1x/1x_module_md5.conf"
#define XSUP_TLS_CONF_MODULE_FILE 	"/var/1x/1x_module_tls.conf"
#define XSUP_PEAP_CONF_MODULE_FILE 	"/var/1x/1x_module_peap.conf"
#ifdef RTL_TTLS_CLIENT
#define XSUP_TTLS_CONF_MODULE_FILE 	"/var/1x/1x_module_ttls.conf"
#endif
#endif

#define  IP_ADDRSIZE        50

#define INC(X)	{ (X) = (X) + 1; if (X > 255) X = 0; /*write(1, "\n[INC]\n", sizeof("\n[INC]\n"));*/};

#define MESS_BUF_SIZE		512
#define MESS_DBG_AUTH 		1
#define MESS_DBG_AUTHSM 	9
#define MESS_DBG_AUTHNET	8
#define MESS_DBG_KRCSM 		5
#define MESS_DBG_KXSM 		6
#define MESS_DBG_SUPP		2
#define MESS_DBG_NAL		7
#define MESS_DBG_BSM		10
#define MESS_DBG_RAD		11
#define MESS_DBG_PTSM		13
#define MESS_AUTH_LOG 		4
#define MESS_ERROR_OK		16
#define MESS_ERROR_FATAL	17
#define MESS_DBG_SPECIAL        12
#define MESS_DBG_DAEMON		18
#define MESS_DBG_KEY_MANAGE	19
#define MESS_DBG_CONTROL        20	//2003-06-13
#define MESS_DBG_RSNINFO	21
#define MESS_DBG_CONFIG		22
#define MESS_DBG_ACCT		23
#define MESS_DBG_FIFO		24


#define MAX_SUPPLICANT		64
#define	MAX_RCV_FIFO		2048
//#define  LIB1X_RAD_SHARED	100



#define	LIB1X_AUTH_INDEX	0xfff
struct  PKT_LSTNR_tag;
struct  PKT_XMIT_tag;

//---- Basic Timer Unit in useconds ----
//#define LIB1X_BASIC_TIMER_UNIT 	100000
// kenny
//#define LIB1X_BASIC_TIMER_UNIT 		1000000
#define LIB1X_BASIC_TIMER_UNIT 		100000
#define	SECONDS_TO_TIMERCOUNT(x)	((x*1000000)/LIB1X_BASIC_TIMER_UNIT)
#define	USECONDS_TO_TIMERCOUNT(x)	(x/LIB1X_BASIC_TIMER_UNIT)
// use the following macro to replace usleep interrupt by timer
#define LIB_USLEEP(x)			{\
						int i;\
				 		for(i=0; i < USECONDS_TO_TIMERCOUNT(x) ; i++)\
				                                 if(usleep(x) == 0)\
									break;\
					}


#define	INC_GLOBAL_SESSION_ID(X)	((X==0xffffffff)?X=0:X++)
typedef struct	Timers_tag
{
	int		authWhile;
				// Used by the Supplicant PAE to determine how long to wait for 
				// a response from the Authenticator.
	int		aWhile;
				// Used by the Backend Authentication state machine in order to
				// determine timeout conditions in the exchanges between the
				// Authenticator and Supplicant or Auth Server.
	int		heldWhile;
				// Used by Supplicant state machine to define periods of time
				// during which it will not attempt to acquire an Authenticator.
	int		quietWhile;
				// During this period Authenticator will not acquire supplicant.
	int		reAuthWhen;
				// A timer used by the Reauthentication Timer state machine in
				// order to determine when re-authentication of the Supplicant
				// takes place.
	int		startWhen;
				// Used by Supplicant PAE state machine to determine when an
				// EAPOL start PDU is to be transmitted. 
	int		txWhen;
	
} Timers;

struct Auth_Pae_tag;
struct Supp_Pae_tag;	// these here to make "# includes" consistent
struct lib1x_ptsm;

//-----------------------------------------------------------------------
// RSN Related
//-----------------------------------------------------------------------
#define DOT11_MAX_ALGORITHMS     0x0a

typedef struct _DOT11_AlgoElement
{
	u_long				Index;
        u_long  			AlgoId;
        BOOLEAN    			Enabled;
}DOT11_AlgoElement;

typedef struct _DOT11_AlgoSuit
{
        u_long                          NumOfAlgo;
        DOT11_AlgoElement               AlgoTable[DOT11_MAX_ALGORITHMS];
}DOT11_AlgoSuit;

typedef struct _DOT11_RSN_AUTHENTICATOR_VARIABLE
{
	//RSN related variable
	OCTET_STRING                    AuthInfoElement;
	BOOLEAN                         isSupportUnicastCipher;
	BOOLEAN                         isSupportMulticastCipher;
	BOOLEAN                         isSupportPreAuthentication;
	BOOLEAN                         isSupportPairwiseAsDefaultKey;
	BOOLEAN				Dot1xEnabled;
	BOOLEAN				MacAuthEnabled;
	BOOLEAN                         RSNEnabled;
#ifdef RTL_WPA2        
	BOOLEAN				WPAEnabled;
	BOOLEAN				WPA2Enabled;
	int 				max_pmksa;
#endif
	BOOLEAN				TSNEnabled;
	int				WepMode;
	int                             NumOfUnicastCipher;
	int                             NumOfAuthCipher;
	DOT11_AlgoSuit                  UniCastCipherSuit;
#ifdef RTL_WPA2        
    DOT11_AlgoSuit                  WPA2UniCastCipherSuit;
#endif
	DOT11_AlgoSuit                  MulticastCipherSuit;
	DOT11_AlgoSuit                  AuthenticationSuit;
	u_char                          NumOfRxTSC;
	u_char                          MulticastCipher;
	u_char                          AuthKeyMethod;
#if defined( CONFIG_IEEE80211W) || defined(HS2_SUPPORT)
	enum mfp_options ieee80211w;
    unsigned sha256;	/*HS2_SUPPORT*/
	/* dot11AssociationSAQueryMaximumTimeout (in TUs) */
	unsigned int assoc_sa_query_max_timeout;
	/* dot11AssociationSAQueryRetryTimeout (in TUs) */
	int assoc_sa_query_retry_timeout;
#endif /* CONFIG_IEEE80211W */
#ifdef HS2_SUPPORT
	unsigned char bOSEN; // OSU Server-Only Authenticated L2 Encryption Network 
#endif

	u_char				PassPhrase[64];
// size is not enough because in PasswordHash(), it will use 40 bytes long. 2005-8-8 david
//	u_char				PassPhraseKey[32];
	u_char				PassPhraseKey[40];

	u_char				ssid[64];

#ifdef RTL_RADIUS_2SET
	BOOLEAN				rs2MacAuthEnabled;
#endif
}DOT11_RSN_AUTHENTICATOR_VARIABLE;

typedef struct _DOT11_RSN_SUPPLICANT_VARIABLE{
        OCTET_STRING                    SuppInfoElement;
	BOOLEAN                         isSuppSupportUnicastCipher;
        BOOLEAN                         isSuppSupportMulticastCipher;
        BOOLEAN                         isSuppSupportPreAuthentication;
        BOOLEAN                         isSuppSupportPairwiseAsDefaultKey;
        BOOLEAN                         RSNEnabled;
#ifdef RTL_WPA2        
	BOOLEAN				isPreAuth;
	BOOLEAN				WPAEnabled;
	BOOLEAN				WPA2Enabled;
	BOOLEAN				PMKCached;
	struct _WPA2_PMKSA_Node*         cached_pmk_node;
#endif        
        u_char                          UnicastCipher;
        u_char                          MulticastCipher;
		u_char							mgmt_group_cipher;
        u_char                          NumOfRxTSC;
        DOT11_AlgoSuit                  AuthSupportUnicastCipherSuit;
        DOT11_AlgoSuit                  AuthSupportAuthenticationCipherSuit;
        BOOLEAN                         isAuthSupportPreAuthentication;
        BOOLEAN                         isAuthSupportPairwiseAsDefaultKey;
        u_char                          AuthSupportMaxNumOfRxTSC;
}DOT11_RSN_SUPPLICANT_VARIABLE;


//-----------------------------------------------------------------------------
// Radius Key for RSN802dot1x or nonRSN802dot1x
//-----------------------------------------------------------------------------
#define RADIUS_KEY_LEN	64

typedef enum _RADIUS_KEY_STATUS
{
	MPPE_SDRCKEY_NONAVALIABLE = 0x00,
	MPPE_SENDKEY_AVALIABLE = 0x01,
	MPPE_RECVKEY_AVALIABLE = 0x02,
	MPPE_SDRCKEY_AVALIABLE = 0x03,
}RADIUS_KEY_STATUS;

typedef struct _RADIUS_KEY
{
	RADIUS_KEY_STATUS Status;
	OCTET_STRING	  SendKey;
	OCTET_STRING	  RecvKey;
}RADIUS_KEY;





//Added to support WPA
struct Auth_PairwiseKeyManage_tag;
struct Supp_PairwiseKeyManage_tag;
struct Auth_GroupKeyManage_tag;
struct _Dot1x_Authenticator;
struct _Dot1x_Client;
//End Added

typedef struct _Dot11RSNConfigEntry {
	//dot11RSNConfigIndex                     InterfaceIndexOrZero,
	int		Version;
	int		PairwiseKeysSupported;
	OCTET_STRING	MulticastCipher;
	int		GroupRekeyMethod;
	u_long		GroupRekeyTime;
	u_long		GroupRekeyPackets;
	BOOLEAN		GroupRekeyStrict; 
	OCTET_STRING	PSKValue;        
	//u_char*	PSKPassPhrase             DisplayString,
	BOOLEAN		TSNEnabled;
	u_long		GroupMasterRekeyTime;
	u_long		GroupUpdateTimeOut;
	u_long		GroupUpdateCount;
	u_long		PairwiseUpdateTimeOut;
	u_long		PairwiseUpdateCount;
}Dot11RSNConfigEntry;

typedef struct Global_Params_tag
{
	BOOLEAN		authAbort;
	BOOLEAN		authFail;
	BOOLEAN		authStart;
	BOOLEAN		authTimeout;
	BOOLEAN		authSuccess;
	int		currentId;		// Id for current authentication session
	BOOLEAN		initialize;
	PORT_MODE_TYPE	portControl;
	BOOLEAN		portEnabled;
	PORT_STATUS_TYPE 	portStatus;
	BOOLEAN		reAuthenticate;
	int		receivedId;
	PORT_STATUS_TYPE 	suppStatus;
#ifdef CONFIG_RTL_ETH_802DOT1X_SUPPORT
	int port_num;
#endif

	struct lib1x_ptsm     * timers;

	//ROLE		 currentRole;
	int		index;

	struct Auth_Pae_tag	* theAuthenticator;
	struct Supp_Pae_tag	* theSupplicant;

	struct TxRx_Params_tag	* TxRx;

	//Added to support WPA
	struct Auth_PairwiseKeyManage_tag      *akm_sm;
	struct Supp_PairwiseKeyManage_tag      *skm_sm;

        OCTET_STRING                    EAPOLMsgRecvd;          //The Overall 802.1x message
        OCTET_STRING                    EAPOLMsgSend;           //The Overall 802.1x message
        OCTET_STRING                    EapolKeyMsgRecvd;       //The start point of eapol-key payload
        OCTET_STRING                    EapolKeyMsgSend;
	int			        AuthKeyMethod;
	RADIUS_KEY                      RadiusKey;
        BOOLEAN                         PreshareKeyAvaliable;
#ifdef RTL_WPA2
	// kenny PMK_LEN should be enough
        u_char                          PSK[PMK_LEN];
#else        
        u_char                          PSK[PMK_LEN * 2];
#endif        
	u_char                          MaxRetryCounts;
	u_char                          EventId;
	BOOLEAN                         portSecure;
	u_char                          DescriptorType; //initialize to 254 in RSN
	u_char							KeyDescriptorVer;
	u_char                          CurrentAddress[ETHER_ADDRLEN];
	BOOLEAN							bMacAuthEnabled;
#ifdef CONFIG_IEEE80211W
	BOOLEAN 		mgmt_frame_prot;
#endif
#ifdef HS2_SUPPORT
	unsigned char   remed_URL[256];
	unsigned char   serverMethod;
	unsigned char   isTriggerWNM;
	unsigned char   isTriggerWNM_DEAUTH;
	u_char WNMDEAUTH_reason;
	u_short WNMDEAUTH_reAuthDelay;
	u_char WNMDEAUTH_URL[256];	
	unsigned char   isTriggerSessionInfo_URL;
	u_char SWT;
	u_char SessionInfo_URL[256]; // BSS Transition Management URL
	
#endif
	//RSNIE related variable
	struct _DOT11_RSN_SUPPLICANT_VARIABLE   RSNVariable;
	Dot11RSNConfigEntry		Dot11RSNConfig;

	struct _Dot1x_Authenticator	*auth;
	//End Added WPA

} Global_Params;


typedef struct TxRx_Params_tag
{
	u_char			oursvr_addr[ETHER_ADDRLEN];       // ethernet address of the server interface
	u_char			oursupp_addr[ETHER_ADDRLEN];       // ethernet address of the supplicant interface
	//u_char		supp_addr[ETHER_ADDRLEN];
	u_char			svr_addr[ETHER_ADDRLEN];

	// Device name
	u_char			* device_supp;
	u_char			* device_svr;

	u_char			* device_wlan0;
#ifdef CONFIG_RTL_ETH_802DOT1X_SUPPORT
	u_char			* device_eth0;
#endif
	// Interface to three daemon (1)ethernet (2)wireless (3)driver
	struct lib1x_nal_intfdesc	* network_svr;
	struct lib1x_nal_intfdesc	* network_supp;
#ifdef RTL_WPA2_PREAUTH
	struct lib1x_nal_intfdesc	* network_ds; // via the DS, i.e. eth0 or br0?
#endif
	int				fd_control;

	FILE			* debugsm;
	struct in_addr	ourip_inaddr, svrip_inaddr, acctip_inaddr;
	u_short			udp_ourport;
	u_short			udp_svrport;
	u_short			udp_acctport;
	struct sockaddr_in			radsvraddr;
	struct sockaddr_in			acctsvraddr;

#ifdef RTL_RADIUS_2SET
	struct lib1x_nal_intfdesc	* network_svr2;
	struct in_addr	svrip_inaddr2;
	u_short			udp_svrport2;
	struct sockaddr_in			radsvraddr2;
	u_short			flag_replaced;

	struct in_addr	acctip_inaddr2;
	u_short			udp_acctport2;
	struct sockaddr_in			acctsvraddr2;
#endif

	u_char			GlobalRadId;

	// Added to support fifo architecture
	int				readfifo;
	int				dummyfd;
	u_char			RecvBuf[MAX_RCV_FIFO];
	OCTET_STRING	RListenFIFO;

} TxRx_Params;


typedef enum { DISABLE, 	ENABLE } Switch;

typedef struct  _Dot1x_Supplicant
{
	int				index;
	BOOLEAN			isEnable;
	BOOLEAN			isEAPCapable;
	unsigned char	addr[ETHER_ADDRLEN];
	u_long			SessionTimeoutCounter;
	u_long			IdleTimeout;
	u_long			IdleTimeoutCounter;
	u_long			tx_packets;
	u_long			rx_packets;
	Global_Params	*global;
} Dot1x_Supplicant;


#ifdef CONFIG_RTL_ETH_802DOT1X_SUPPORT
#define DOT1X_MAX_DATA_LEN		1560
#define DOT1X_MAX_EAP_PACKET_LEN 1550
//#define MAXDATALEN      1560
#define DOT1X_EVENT_EAP_PACKET	  0x01
#define DOT1X_EVENT_PORT_DOWN	  0x02
#define DOT1X_EVENT_PORT_UP		  0x03




#define DOT1X_EAP_ID_INTERVAL	   17


typedef struct __rtl802Dot1xAuthResult
{
		unsigned char   type; /* 1:port base result/2:mac base result */
        unsigned char   port_num;
        char      		auth_state;
		unsigned char   mac_addr[ETHER_ADDRLEN];
}rtl802Dot1xAuthResult;

typedef struct __rtl802Dot1xPortStateInfo
{
		unsigned char	event_id;
		char			flag; /* more packets flag */
		unsigned int	port_mask;/* Bit0 = port0, Bit0=1 means down and so on */
}rtl802Dot1xPortStateInfo;

typedef struct __rtl802Dot1xEapPkt
{
		unsigned char   event_id;
		char			flag; /* more packets flag */
		unsigned char	rx_port_num;
        short			item_size;
        unsigned char	item[DOT1X_MAX_EAP_PACKET_LEN];
}rtl802Dot1xEapPkt;

typedef struct __rtl802Dot1xQueueNode
{
        short			item_size;
        unsigned char	item[DOT1X_MAX_DATA_LEN];
}rtl802Dot1xQueueNode;

#endif


#if 0
typedef struct
{
	unsigned short	aid;
	unsigned char	addr[6];
	unsigned long	tx_packets;
	unsigned long	rx_packets;
	unsigned long	expired_time;	// 10 msec unit
	unsigned short	flags;
	unsigned char	TxOperaRate;
	unsigned char	rssi;
	unsigned long	link_time;		// 1 sec unit
	unsigned long	tx_fail;
} RTL_STA_INFO;
#endif

typedef struct _sta_info_2_web {
	unsigned short	aid;
	unsigned char	addr[6];
	unsigned long	tx_packets;
	unsigned long	rx_packets;
	unsigned long	expired_time;	// 10 msec unit
	unsigned short	flags;
	unsigned char	TxOperaRate;
	unsigned char	rssi;
	unsigned long	link_time;		// 1 sec unit
	unsigned long	tx_fail;
	unsigned long	tx_bytes;
	unsigned long	rx_bytes;
	//CBN20130225 josh add start
	unsigned long	tx_bytes_1s;
	unsigned long	rx_bytes_1s;
	unsigned long	tx_pkts_1s;
	unsigned long	rx_pkts_1s;
	//CBN20130225 josh add end
	unsigned char	network;
	unsigned char	ht_info;		// bit0: 0=20M mode, 1=40M mode; bit1: 0=longGI, 1=shortGI
//#ifdef TLN_STATS
#if 1
	unsigned char	RxOperaRate;
	unsigned char	auth_type;
	unsigned char	enc_type;
	unsigned char 	resv[3];
#else
	unsigned char 	resv[6];
#endif
} sta_info_2_web;

#define RTL_STA_INFO sta_info_2_web

typedef struct  _Dot1x_Authenticator
{
	int						MaxSupplicant;
	int						NumOfSupplicant;
	ROLE					currentRole;
	TxRx_Params				*GlobalTxRx;
	Dot1x_Supplicant		*Supp[MAX_SUPPLICANT];
	OCTET_STRING			RadShared;            	/* NAS and RADIUS */
	OCTET_STRING			AcctShared;
	LARGE_INTEGER			Dot1xKeyReplayCounter;
	u_long					UsePassphrase;
	u_long					AuthTimerCount;
	u_long					KeyManageTimerCount;
	u_long					SessionInfoTimerCount;	// Abocom
	u_long					IgnoreEAPOLStartCounter;
	u_char					svrip[IP_ADDRSIZE+1];
	u_short					udp_svrport;
	u_char					acctip[IP_ADDRSIZE+1];
	u_short					udp_acctport;
#ifdef RTL_RADIUS_2SET
	u_short 				use_2nd_rad;
	u_char					svrip2[IP_ADDRSIZE+1];
	u_short 				udp_svrport2;
	OCTET_STRING			RadShared2;
	u_char					acctip2[IP_ADDRSIZE+1];
	u_short 				udp_acctport2;
	OCTET_STRING			AcctShared2;
#endif

	u_char					WepGroupKey[32];

	//Added to support WPA
	struct Auth_GroupKeyManage_tag		*gk_sm;
	OCTET32_INTEGER			Counter;
	u_char					CurrentAddress[ETHER_ADDRLEN];
	DOT11_RSN_AUTHENTICATOR_VARIABLE	RSNVariable;
	Dot11RSNConfigEntry					Dot11RSNConfig;
	u_char					IoctlBuf[1024];
	u_long					IoctlBufLen;
	BOOLEAN					IoctlFlag;
	//end Added

	//Accounting
	u_long					InterimTimeout;
	BOOLEAN					SessionTimeoutEnabled;
	BOOLEAN					IdleTimeoutEnabled;
	BOOLEAN					AccountingEnabled;
	BOOLEAN					UpdateInterimEnabled;
	u_long					GlobalSessionId;
	Dot1x_Supplicant		*authGlobal;

// david, fix to 128. If support sta is greater than 128 in wlan driver,
// this value need be modified.
//	RTL_STA_INFO				StaInfo[MAX_SUPPLICANT+1];
	RTL_STA_INFO			DrvStaInfo[128+1];
//-------------------------------------------------------------------------

	//Server config
	u_long					rsMaxReq;
	u_long					rsAWhile;
	u_long					rsReAuthTO;
	u_long					accountRsMaxReq;
	u_long					accountRsAWhile;

#ifdef RTL_WPA_CLIENT
	struct _Dot1x_Client	*client;
#endif

#ifdef RTL_WPA2
	struct pmksa_list_t		pmksa_list;
#endif

#if defined(CONFIG_RTL_802_1X_CLIENT_SUPPORT) || defined(CONFIG_RTL_ETH_802DOT1X_CLIENT_MODE_SUPPORT)
	char						eapType;
	char						eapInsideType;
	char						eapUserId[MAX_EAP_USER_ID_LEN+1];
	char						rsUserName[MAX_RS_USER_NAME_LEN+1];
	char						rsUserPasswd[MAX_RS_USER_PASS_LEN+1];
	char						rsUserCertPasswd[MAX_RS_USER_CERT_PASS_LEN+1];
	char						rsBandSel;
#ifdef RTL_TTLS_CLIENT
	char						ttlsPhase2Type;
	char						ttlsPhase2EapMethod;
#endif
#endif

#ifdef CONFIG_RTL_ETH_802DOT1X_SUPPORT
	int							ethDot1xMode;
	int							ethDot1xProxyType;
	int							ethDot1xProxyModePortMask;
	int							ethDot1xClientModePortMask;
	int							ethDot1xEapolUnicastEnabled;
#endif
#ifdef CONFIG_RTL8196C_AP_HCM
	unsigned char hostmac[13];
	unsigned int if_index;
#endif
} Dot1x_Authenticator;

void lib1x_print_etheraddr( char * s, u_char * addr );
#ifndef DEBUG_DISABLE //sc_yang
void lib1x_message( int type, char * msg, ... );
void lib1x_hexdump( FILE * fdesc, u_char * pkt, int numBytes );
void lib1x_totext_authpaestate( FILE * fdesc, AUTH_PAE_STATE state );
void lib1x_totext_bauthsmstate( FILE * fdesc, BAUTH_SM_STATE state );
void lib1x_chardump( FILE * fdesc, u_char * pkt, int numBytes );
void lib1x_hexdump2(int type, char *fun, u_char *buf, int size, char *comment);
void lib1x_PrintAddr(u_char *ucAddr);
void DUMP_GLOBAL_PARAMS( Global_Params *g, u_char *exp );
#else
#define lib1x_message(type, msg...)  do{}while(0)
#define lib1x_hexdump(a, b, c)  do{}while(0)
#define lib1x_totext_authpaestate(a, b)  do{}while(0)
#define lib1x_totext_bauthsmstate(a, b)  do{}while(0)
#define lib1x_chardump(a, b, c)  do{}while(0)
#define lib1x_hexdump2(a, b, c, e , f)  do{}while(0)
#define lib1x_PrintAddr(a)  do{}while(0)
#define DUMP_GLOBAL_PARAMS(a, b)  do{}while(0)
#endif





//sc_yang
extern void * lib1x_global_signal_info;
	// This variable points to struct lib1x_ptsm , the port timers state machine struct,
// because we need the signal handler to access some global variable.

extern u_char dev_supp[];	// david+2006-03-31, for add event to syslog
	
#ifdef _ABOCOM
#define	ABOCOM_ADD_STA	0
#define ABOCOM_DEL_STA	1
void lib1x_abocom(u_char *pucAddr,  int ulCommandType);
#endif




#define lib1x_Little_S2N(s,c)   (*((c) )=(unsigned char)(((s))&0xff), \
                         	*((c)+1)=(unsigned char)(((s)>>8)&0xff))

#define lib1x_Little_N2S(c,s)   s = 0,\
                         	(s =((unsigned long)(*((c)  ))), \
                         	s|=( (unsigned long) (*((c)+1))<<8)  )

#define lib1x_S2N(s,c)   (*((c) )=(unsigned char)(((s)>>8)&0xff), \
                         *((c)+1)=(unsigned char)(((s)    )&0xff))

#define lib1x_N2S(c,s)   s = 0,\
			 (s =((unsigned long)(*((c)  )))<<8, \
                         s|=((unsigned long)(*((c)+1))))

#define lib1x_L2N(l,c)   (*((c) )=(unsigned char)(((l)>>24)&0xff), \
                         *((c)+1)=(unsigned char)(((l)>>16)&0xff), \
                         *((c)+2)=(unsigned char)(((l)>> 8)&0xff), \
                         *((c)+3)=(unsigned char)(((l)    )&0xff))

#define lib1x_N2L(c,l)   l = 0,\
			 (l =((unsigned long)(*((c)  )))<<24, \
                         l|=((unsigned long)(*((c)+1)))<<16, \
                         l|=((unsigned long)(*((c)+2)))<< 8, \
                         l|=((unsigned long)(*((c)+3))))

//----------------------------------------------------------------
// 1x_kmsm_prf.c
//----------------------------------------------------------------
int PasswordHash (
	char *password,
	int passwordlength,
	unsigned char *ssid,
	int ssidlength,
	unsigned char *output);
	

#ifdef RTL_WPA2	
//----------------------------------------------------------------
// PMK Cache
//----------------------------------------------------------------

struct _WPA2_PMKSA
{
	u_long		SessionTimeout;
	u_long		IdleTimeout;
 	u_char		pmkid[PMKID_LEN];
// 	u_char		aa[6];	// Authenticator MAC Address 
 	u_char		pmk[PMK_LEN];
 //	u_long		lifetime;
 	u_long		aging;
 	u_char		akmp;
  	u_char		spa[ETHER_ADDRLEN];	// Supplicant MAC Address 	
};

struct _WPA2_PMKSA_Node
{
	struct list_head node;
        struct _WPA2_PMKSA pmksa;
};






//#define AUTH_DEBUGMSG
#ifdef AUTH_DEBUGMSG
#define AUTHDEBUG(fmt, args...) printf("[%s %d]"fmt,__FUNCTION__,__LINE__,## args)
#else
#define AUTHDEBUG(fmt, args...) {}
#endif

//#define PMF_DEBUGMSG
#ifdef PMF_DEBUGMSG
#define PMFDEBUG(fmt, args...) printf("[%s %d]"fmt,__FUNCTION__,__LINE__,## args)
#else
#define PMFDEBUG(fmt, args...) {}
#endif

//#define HS2_DEBUGMSG
#ifdef HS2_DEBUGMSG
#define HS2DEBUG(fmt, args...) printf("[%s %d]"fmt,__FUNCTION__,__LINE__,## args)
#else
#define HS2DEBUG(fmt, args...) {}
#endif

#endif /* RTL_WPA2 */

#endif /* LIB1x_COMMON_H */

