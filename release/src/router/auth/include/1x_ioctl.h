
/************************* 802.1x Message ***************************/

/*
 * Reason code for Disconnect
 */
typedef enum _ReasonCode{
        unspec_reason   = 0x01,
        auth_not_valid  = 0x02,
        deauth_lv_ss    = 0x03,
        inactivity              = 0x04,
        ap_overload             = 0x05,
        class2_err              = 0x06,
        class3_err              = 0x07,
        disas_lv_ss             = 0x08,
        asoc_not_auth   = 0x09,
#ifdef _RTL_WPA_UNIX
        RSN_invalid_info_element         	= 13,
        RSN_MIC_failure                         = 14,
        RSN_4_way_handshake_timeout             = 15,
        RSN_diff_info_element       		= 17,
        RSN_multicast_cipher_not_valid          = 18,
        RSN_unicast_cipher_not_valid            = 19,
        RSN_AKMP_not_valid                      = 20,
        RSN_unsupported_RSNE_version            = 21,
        RSN_invalid_RSNE_capabilities           = 22,
        RSN_ieee_802dot1x_failed                = 23,
        //belowing are Realtek definition
        RSN_PMK_not_avaliable                   = 24,
#endif
        expire					= 30,
        session_timeout				= 31,
        acct_idle_timeout			= 32,
        acct_user_request			= 33
}ReasonCode;


/*
 * Data structure for ioctl with driver
 */

#define MAXRSNIELEN     128
#define MacAddrLen      6
#ifdef WIFI_SIMPLE_CONFIG
#define PROBEIELEN	128
#endif

typedef unsigned char DOT11_KEY_RSC[8];


typedef enum{
        DOT11_KeyType_Group = 0,
        DOT11_KeyType_Pairwise = 1
#ifdef CONFIG_IEEE80211W
		,DOT11_KeyType_IGTK = 2
#endif
}DOT11_KEY_TYPE;

typedef enum{
        DOT11_KeyUsage_ENC,
        DOT11_KeyUsage_MIC
}DOT11_KEY_USAGE;

typedef enum{
	DOT11_Role_Auth,
	DOT11_Role_Supp
}DOT11_ROLE;

typedef enum{
        DOT11_VARIABLE_MACEnable,
        DOT11_VARIABLE_SystemAuthControl,
        DOT11_VARIABLE_AuthControlledPortStatus,
        DOT11_VARIABLE_AuthControlledPortControl,
	DOT11_VARIABLE_AuthenticationType,
	DOT11_VARIABLE_KeyManagement,
	DOT11_VARIABLE_MulticastCipher,
	DOT11_VARIABLE_UnicastCipher
} DOT11_VARIABLE_TYPE;

typedef enum{
	DOT11_SysAuthControl_Disabled,
	DOT11_SysAuthControl_Enabled
} DOT11_SYSTEM_AUTHENTICATION_CONTROL;

typedef enum{
        DOT11_PortControl_ForceUnauthorized,
        DOT11_PortControl_ForceAuthorized,
        DOT11_PortControl_Auto
} DOT11_PORT_CONTROL;

typedef enum{
        DOT11_PortStatus_Unauthorized,
        DOT11_PortStatus_Authorized
}DOT11_PORT_STATUS;

typedef enum{
        DOT11_Association_Fail,
        DOT11_Association_Success
}DOT11_ASSOCIATION_RESULT;

typedef enum{
	DOT11_AuthKeyType_RSNReserved = 0,
	DOT11_AuthKeyType_RSN = 1,
	DOT11_AuthKeyType_RSNPSK = 2,
#ifdef CONFIG_IEEE80211R
	DOT11_AuthKeyType_FT = 3,
#else
	DOT11_AuthKeyType_NonRSN802dot1x = 3,
#endif
	DOT11_AuthKeyType_802_1X_SHA256 = 5,
	DOT11_AuthKeyType_PSK_SHA256 = 6,
	DOT11_AuthKeyType_PRERSN = 255,
} DOT11_AUTHKEY_TYPE;

#ifdef HS2_SUPPORT
#define	WFA_AKM_ANONYMOUS_CLI_802_1X_SHA256 1
#endif

typedef enum{
        DOT11_Ioctl_Query = 0,
        DOT11_Ioctl_Set = 1,
} DOT11_Ioctl_Flag;

typedef enum{
        DOT11_ENC_NONE  = 0,
        DOT11_ENC_WEP40 = 1,
        DOT11_ENC_TKIP  = 2,
        DOT11_ENC_WRAP  = 3,
        DOT11_ENC_CCMP  = 4,
        DOT11_ENC_WEP104= 5,
        DOT11_ENC_BIP   = 6,
        DOT11_ENC_NOGA  = 7, //Group addressed traffic not allowed
	DOT11_ENC_UNKNOWN = 255,
} DOT11_ENC_ALGO;



typedef enum{
        DOT11_EVENT_NO_EVENT = 1,
        DOT11_EVENT_REQUEST = 2,
        DOT11_EVENT_ASSOCIATION_IND = 3,
        DOT11_EVENT_ASSOCIATION_RSP = 4,
        DOT11_EVENT_AUTHENTICATION_IND = 5,
        DOT11_EVENT_REAUTHENTICATION_IND = 6,
        DOT11_EVENT_DEAUTHENTICATION_IND = 7,
        DOT11_EVENT_DISASSOCIATION_IND = 8,
        DOT11_EVENT_DISCONNECT_REQ = 9,
        DOT11_EVENT_SET_802DOT11 = 10,
        DOT11_EVENT_SET_KEY = 11,
        DOT11_EVENT_SET_PORT = 12,
        DOT11_EVENT_DELETE_KEY = 13,
        DOT11_EVENT_SET_RSNIE = 14,
        DOT11_EVENT_GKEY_TSC = 15,
        DOT11_EVENT_MIC_FAILURE = 16,
        DOT11_EVENT_ASSOCIATION_INFO = 17,
        DOT11_EVENT_INIT_QUEUE = 18,
        DOT11_EVENT_EAPOLSTART = 19,
//2003-07-30 ------------
        DOT11_EVENT_ACC_SET_EXPIREDTIME = 31,
        DOT11_EVENT_ACC_QUERY_STATS = 32,
        DOT11_EVENT_ACC_QUERY_STATS_ALL = 33,
//-----------------------

// --- 2003-08-04 ---
        DOT11_EVENT_REASSOCIATION_IND = 34,
        DOT11_EVENT_REASSOCIATION_RSP = 35,
//-----------------------
        DOT11_EVENT_STA_QUERY_BSSID = 36,
        DOT11_EVENT_STA_QUERY_SSID = 37,

// jimmylin: pass EAP packet by event queue
        DOT11_EVENT_EAP_PACKET = 41,

#ifdef RTL_WPA2
        DOT11_EVENT_EAPOLSTART_PREAUTH = 45,
        DOT11_EVENT_EAP_PACKET_PREAUTH = 46,
#endif        

#ifdef RTL_WPA2_CLIENT
	DOT11_EVENT_WPA2_MULTICAST_CIPHER = 47,       
#endif

	DOT11_EVENT_WPA_MULTICAST_CIPHER = 48,       

#ifdef AUTO_CONFIG
	DOT11_EVENT_AUTOCONF_ASSOCIATION_IND = 50,
	DOT11_EVENT_AUTOCONF_ASSOCIATION_CONFIRM = 51,
	DOT11_EVENT_AUTOCONF_PACKET = 52,
	DOT11_EVENT_AUTOCONF_LINK_IND = 53,
#endif

#ifdef WIFI_SIMPLE_CONFIG
	DOT11_EVENT_WSC_SET_IE = 55,		
	DOT11_EVENT_WSC_PROBE_REQ_IND = 56,
	DOT11_EVENT_WSC_PIN_IND = 57,
	DOT11_EVENT_WSC_ASSOC_REQ_IE_IND = 58,
	DOT11_EVENT_WSC_SWITCH_MODE = 100,	// for P2P_SUPPORT
	DOT11_EVENT_WSC_STOP = 101,			// for P2P_SUPPORT		
	/* support  Assigned MAC Addr,Assigned SSID,dymanic change STA's PIN code, 2011-0505 */		
	DOT11_EVENT_WSC_SET_MY_PIN = 102,
	DOT11_EVENT_WSC_SPEC_SSID = 103,
	DOT11_EVENT_WSC_SPEC_MAC_IND = 104,	
	/* support  Assigned MAC Addr,Assigned SSID,dymanic change STA's PIN code, 2011-0505 */		
#ifdef CONFIG_IWPRIV_INTF
	DOT11_EVENT_WSC_START_IND = 70,
	//EV_MODE, EV_STATUS, EV_MEHOD, EV_STEP, EV_OOB
	DOT11_EVENT_WSC_MODE_IND = 71,
	DOT11_EVENT_WSC_STATUS_IND = 72,
	DOT11_EVENT_WSC_METHOD_IND = 73,
	DOT11_EVENT_WSC_STEP_IND = 74,
	DOT11_EVENT_WSC_OOB_IND = 75,
#endif  //ifdef CONFIG_IWPRIV_INTF
#endif	

    DOT11_EVENT_WSC_RM_PBC_STA=106,
#ifdef HS2_SUPPORT
	DOT11_EVENT_WNM_NOTIFY = 109,
	DOT11_EVENT_GAS_INIT_REQ = 110,
	DOT11_EVENT_GAS_COMEBACK_REQ = 111,
	DOT11_EVENT_HS2_SET_IE = 112,
	DOT11_EVENT_HS2_GAS_RSP = 113,
	DOT11_EVENT_HS2_GET_TSF = 114,
	DOT11_EVENT_HS2_TSM_REQ = 115,
	DOT11_EVENT_HS2_GET_RSN = 116,
	DOT11_EVENT_HS2_GET_MMPDULIMIT=117,
	DOT11_EVENT_WNM_DEAUTH_REQ = 118,
	DOT11_EVENT_QOS_MAP_CONF = 119,
#endif
#ifdef CONFIG_IEEE80211W
	DOT11_EVENT_SET_PMF = 120,
	DOT11_EVENT_GET_IGTK_PN = 121,
	DOT11_EVENT_INIT_PMF = 122,
#endif
#ifdef CONFIG_IEEE80211R
	DOT11_EVENT_FT_IMD_ASSOC_IND	= 126,
	DOT11_EVENT_FT_QUERY_INFO		= 133,
	DOT11_EVENT_FT_SET_INFO			= 134,
	DOT11_EVENT_FT_AUTH_INSERT_R0	= 135,
	DOT11_EVENT_FT_AUTH_INSERT_R1	= 136,
	DOT11_EVENT_FT_TRIGGER_EVENT	= 137,
#endif

    DOT11_EVENT_MAX = 200,
} DOT11_EVENT;



/* -------------------- MESSAGE DATA STRUCTURE--------------------- */

typedef struct _DOT11_GENERAL{
        unsigned char   EventId;
        unsigned char   IsMoreEvent;
	unsigned char	*Data;
}DOT11_GENERAL;

typedef struct _DOT11_NOEVENT{
        unsigned char   EventId;
        unsigned char   IsMoreEvent;
}DOT11_NO_EVENT;

typedef struct _DOT11_REQUEST{
        unsigned char   EventId;
}DOT11_REQUEST;

#ifdef RTL_WPA2_CLIENT
typedef struct _DOT11_WPA2_MULTICAST_CIPHER{
        unsigned char   EventId;
        unsigned char   IsMoreEvent;
        unsigned char	MulticastCipher;
}DOT11_WPA2_MULTICAST_CIPHER;
#endif /* RTL_WPA2_CLIENT */

typedef struct _DOT11_WPA_MULTICAST_CIPHER{
        unsigned char   EventId;
        unsigned char   IsMoreEvent;
        unsigned char	MulticastCipher;
}DOT11_WPA_MULTICAST_CIPHER;

typedef struct _DOT11_ASSOCIATION_IND{
        unsigned char   EventId;
        unsigned char   IsMoreEvent;
        unsigned char            MACAddr[MacAddrLen];
        unsigned short  RSNIELen;
        unsigned char            RSNIE[MAXRSNIELEN];
}DOT11_ASSOCIATION_IND;

typedef struct _DOT11_ASSOCIATION_RSP{
        unsigned char   EventId;
        unsigned char   IsMoreEvent;
        char            MACAddr[MacAddrLen];
        unsigned char   Status;
}DOT11_ASSOCIATION_RSP;


// --- 2003-08-04 ---
typedef struct _DOT11_REASSOCIATION_IND{
        unsigned char   EventId;
        unsigned char   IsMoreEvent;
        char            MACAddr[MacAddrLen];
        unsigned short  RSNIELen;
        char            RSNIE[MAXRSNIELEN];
        char            OldAPaddr[MacAddrLen];
}DOT11_REASSOCIATION_IND;

typedef struct _DOT11_REASSOCIATION_RSP{
        unsigned char   EventId;
        unsigned char   IsMoreEvent;
        char            MACAddr[MacAddrLen];
        unsigned char   Status;
        char            CurrAPaddr[MacAddrLen];
}DOT11_REASSOCIATIIN_RSP;
// --- ---------- ---



typedef struct _DOT11_AUTHENTICATION_IND{
        unsigned char   EventId;
        unsigned char   IsMoreEvent;
        char            MACAddr[MacAddrLen];
}DOT11_AUTHENTICATION_IND;

typedef struct _DOT11_REAUTHENTICATION_IND{
        unsigned char   EventId;
        unsigned char   IsMoreEvent;
        char            MACAddr[MacAddrLen];
}DOT11_REAUTHENTICATION_IND;

typedef struct _DOT11_DEAUTHENTICATION_IND{
        unsigned char   EventId;
        unsigned char   IsMoreEvent;
        char            MACAddr[MacAddrLen];
}DOT11_DEAUTHENTICATION_IND;

typedef struct _DOT11_DISASSOCIATION_IND{
	unsigned char   EventId;
        unsigned char   IsMoreEvent;
        char            MACAddr[MacAddrLen];
	unsigned long	tx_packets;       // == transmited packets
	unsigned long	rx_packets;       // == received packets
	unsigned long	tx_bytes;         // == transmited bytes
	unsigned long	rx_bytes;         // == received bytes
	unsigned long   Reason;
}DOT11_DISASSOCIATION_IND;

#if	defined( CONFIG_IEEE80211W	) || 	defined( HS2_SUPPORT	)
typedef struct _DOT11_WNM_NOTIFY{
        unsigned char   EventId;
        unsigned char   IsMoreEvent;
		unsigned char   macAddr[MacAddrLen];
        unsigned char   remedSvrURL[2048];
#if 1		
		unsigned char   serverMethod;
#endif
}DOT11_WNM_NOTIFY;

typedef struct _DOT11_WNM_DEAUTH_REQ{
        unsigned char   EventId;
        unsigned char   IsMoreEvent;
		unsigned char   macAddr[MacAddrLen];
		unsigned char   reason;
		unsigned short  reAuthDelay;
        unsigned char   URL[2048];
}DOT11_WNM_DEAUTH_REQ;

typedef struct _DOT11_BSS_SessInfo_URL{
        unsigned char   EventId;
        unsigned char   IsMoreEvent;
		unsigned char   macAddr[MacAddrLen];
		unsigned char   SWT;
        unsigned char   URL[2048];
}DOT11_BSS_SessInfo_URL;

typedef struct _DOT11_INIT_11W_Flags {
	unsigned char	EventId;
	unsigned char	IsMoreEvent;
	unsigned char   dot11IEEE80211W;
    unsigned char   dot11EnableSHA256;
}DOT11_INIT_11W_Flags;

typedef struct _DOT11_SET_11W_Flags {
	unsigned char	EventId;
	unsigned char	IsMoreEvent;
	unsigned char	macAddr[MacAddrLen];
	unsigned char   isPMF;
}DOT11_SET_11W_Flags;
#endif

typedef struct _DOT11_DISCONNECT_REQ{
        unsigned char   EventId;
        unsigned char   IsMoreEvent;
        unsigned short  Reason;
        char            MACAddr[MacAddrLen];
}DOT11_DISCONNECT_REQ;

typedef struct _DOT11_SET_802DOT11{
        unsigned char   EventId;
        unsigned char   IsMoreEvent;
        unsigned char   VariableType;
        unsigned char   VariableValue;
        char            MACAddr[MacAddrLen];
}DOT11_SET_802DOT11;

typedef struct _DOT11_SET_KEY{
        unsigned char   EventId;
        unsigned char   IsMoreEvent;
	unsigned long   KeyIndex;
	unsigned long   KeyLen;
	unsigned char   KeyType;
	unsigned char	EncType;
        unsigned char   MACAddr[MacAddrLen];
	DOT11_KEY_RSC   KeyRSC;
	unsigned char   KeyMaterial[64];
}DOT11_SET_KEY;

typedef struct _DOT11_SETPORT{
	unsigned char EventId;
	unsigned char PortStatus;
	unsigned char PortType;
	unsigned char MACAddr[MacAddrLen];
}DOT11_SETPORT;

typedef struct _DOT11_DELETE_KEY{
        unsigned char   EventId;
        unsigned char   IsMoreEvent;
        char            MACAddr[MacAddrLen];
        unsigned char   KeyType;
}DOT11_DELETE_KEY;

typedef struct _DOT11_SET_RSNIE{
        unsigned char   EventId;
        unsigned char   IsMoreEvent;
	unsigned short   Flag;
        unsigned short  RSNIELen;
        char            RSNIE[MAXRSNIELEN];
}DOT11_SET_RSNIE;

typedef struct _DOT11_GKEY_TSC{
        unsigned char   EventId;
        unsigned char   IsMoreEvent;
	unsigned char   KeyTSC[8];
}DOT11_GKEY_TSC;

#ifdef RTL_WPA_CLIENT
typedef struct _DOT11_STA_QUERY_BSSID{
	unsigned char	EventId;
	unsigned char	IsMoreEvent;
	unsigned long	IsValid;
	char			Bssid[MacAddrLen];
}DOT11_STA_QUERY_BSSID;

typedef struct _DOT11_STA_QUERY_SSID{
	unsigned char	EventId;
	unsigned char	IsMoreEvent;
	unsigned long	IsValid;
	char			ssid[32];
	int				ssid_len;
}DOT11_STA_QUERY_SSID;
#endif

typedef struct _DOT11_MIC_FAILURE{
        unsigned char   EventId;
        unsigned char   IsMoreEvent;
        char            MACAddr[MacAddrLen];
}DOT11_MIC_FAILURE;


typedef struct _DOT11_EAPOL_START{
        unsigned char   EventId;
        unsigned char   IsMoreEvent;
        char            MACAddr[MacAddrLen];
}DOT11_EAPOL_START;

//2003-07-30 --------------
typedef struct _DOT11_SET_EXPIREDTIME{
        unsigned char EventId;
        unsigned char IsMoreEvent;
        unsigned char MACAddr[MacAddrLen];
	unsigned long ExpireTime;
}DOT11_SET_EXPIREDTIME;

typedef struct _DOT11_QUERY_STATS{
	unsigned char   EventId;
	unsigned char   IsMoreEvent;
	unsigned char	MACAddr[MacAddrLen];
	unsigned long	IsSuccess;
	unsigned long	tx_packets;       // == transmited packets
	unsigned long	rx_packets;       // == received packets
	unsigned long	tx_bytes;         // == transmited bytes
	unsigned long	rx_bytes;         // == received bytes
}DOT11_QUERY_STATS;
//-------------------------

typedef struct _DOT11_EAP_PACKET{
	unsigned char	EventId;
	unsigned char	IsMoreEvent;
	unsigned short  packet_len;
	unsigned char	packet[1550];
}DOT11_EAP_PACKET;

#ifdef WIFI_SIMPLE_CONFIG
typedef struct _DOT11_WSC_PIN_IND{
	unsigned char EventId;
	unsigned char IsMoreEvent;
	unsigned char code[256];
} DOT11_WSC_PIN_IND;

typedef struct _DOT11_WSC_ASSOC_IND{
        unsigned char   EventId;
        unsigned char   IsMoreEvent;
        char            MACAddr[MacAddrLen];
        unsigned short  AssocIELen;
        char            AssocIE[PROBEIELEN];
	  unsigned char wscIE_included;
}DOT11_WSC_ASSOC_IND;
#endif


#define DOT11_AI_REQFI_CAPABILITIES      1
#define DOT11_AI_REQFI_LISTENINTERVAL    2
#define DOT11_AI_REQFI_CURRENTAPADDRESS  4

#define DOT11_AI_RESFI_CAPABILITIES      1
#define DOT11_AI_RESFI_STATUSCODE        2
#define DOT11_AI_RESFI_ASSOCIATIONID     4


typedef struct _DOT11_ASSOCIATION_INFORMATION
{

    unsigned char   EventId;
    unsigned char   IsMoreEvent;    
    unsigned char   SupplicantAddress[MacAddrLen];
    u_long Length;
    u_short AvailableRequestFixedIEs;
    struct _DOT11_AI_REQFI {
                u_short Capabilities;
                u_short ListenInterval;
        	char    CurrentAPAddress[MacAddrLen];
    } RequestFixedIEs;
    u_long RequestIELength;
    u_long OffsetRequestIEs;
    u_short AvailableResponseFixedIEs;
    struct _DOT11_AI_RESFI {
                u_short Capabilities;
                u_short StatusCode;
                u_short AssociationId;
    } ResponseFixedIEs;
    u_long ResponseIELength;
    u_long OffsetResponseIEs;
} DOT11_ASSOCIATION_INFORMATION, *PDOT11_ASSOCIATION_INFORMATION;

typedef struct _DOT11_INIT_QUEUE
{
    unsigned char EventId;
    unsigned char IsMoreEvent;
} DOT11_INIT_QUEUE, *PDOT11_INIT_QUEUE;
#ifdef CONFIG_IEEE80211R
typedef struct _DOT11_QUERY_FT_INFORMATION
{
    unsigned char EventId;
    unsigned char IsMoreEvent;
	unsigned char sta_addr[MacAddrLen];
	unsigned char ssid[32];
	unsigned int ssid_len;
	unsigned char mdid[2];
	unsigned char r0kh_id[48];
	unsigned int r0kh_id_len;
	unsigned char bssid[MacAddrLen];
	unsigned char over_ds;
	unsigned char res_request;
} DOT11_QUERY_FT_INFORMATION, *PDOT11_QUERY_FT_INFORMATION;

typedef struct _DOT11_SET_FT_INFORMATION
{
    unsigned char EventId;
    unsigned char IsMoreEvent;
	unsigned char sta_addr[MacAddrLen];
	unsigned char UnicastCipher;
	unsigned char MulticastCipher;
	unsigned char bInstallKey;
} DOT11_SET_FT_INFORMATION, *PDOT11_SET_FT_INFORMATION;

typedef struct _DOT11_AUTH_FT_INSERT_R0_KEY
{
    unsigned char EventId;
    unsigned char IsMoreEvent;
	unsigned char sta_addr[MacAddrLen];
	unsigned char pmk_r0[PMK_LEN];
	unsigned char pmk_r0_name[PMKID_LEN];
} DOT11_AUTH_FT_INSERT_R0_KEY, *PDOT11_AUTH_FT_INSERT_R0_KEY;

typedef struct _DOT11_AUTH_FT_INSERT_R1_KEY
{
    unsigned char EventId;
    unsigned char IsMoreEvent;
	unsigned char sta_addr[MacAddrLen];
	unsigned char bssid[MacAddrLen];
	unsigned char r0kh_id[48];
	unsigned int r0kh_id_len;
	unsigned char pmk_r1[PMK_LEN];
	unsigned char pmk_r1_name[PMKID_LEN];
	unsigned char pmk_r0_name[PMKID_LEN];
	unsigned int pairwise;
} DOT11_AUTH_FT_INSERT_R1_KEY, *PDOT11_AUTH_FT_INSERT_R1_KEY;

typedef struct _DOT11_AUTH_FT_TRIGGER_EVENT
{
    unsigned char EventId;
    unsigned char IsMoreEvent;
	unsigned char trigger_eventid;
	unsigned char sta_addr[MacAddrLen];
} DOT11_AUTH_FT_TRIGGER_EVENT, *PDOT11_AUTH_FT_TRIGGER_EVENT;
#endif


//------------------------------------------------------------
// For Key mapping key definition
//------------------------------------------------------------
//#define HW_CAM_CONFIG
#ifdef HW_CAM_CONFIG
struct rtl_priv_args
{
	unsigned char	arg_val;
	unsigned char	arg_name[16];
	unsigned char	arg_length;
};

#define PRIV_CMD_AP_KEYMAP_OPERATION		1
#define PRIV_CMD_AP_KEYMAP_MAC_ADDRESS		2
#define PRIV_CMD_AP_KEYMAP_KEY40		3
#define PRIV_CMD_AP_KEYMAP_KEY104		4
#define PRIV_CMD_AP_KEYMAP_KEY_INDEX		5
#define PRIV_CMD_AP_KEYMAP_KEY_TYPE		6
#define PRIV_CMD_AP_KEYMAP_KEY_VALID		7

static struct rtl_priv_args priv_cmd_keymap_args[] =
{
	{ PRIV_CMD_AP_KEYMAP_OPERATION, "KMOP", 4 },
	{ PRIV_CMD_AP_KEYMAP_MAC_ADDRESS, "KMAR", 4 },
	{ PRIV_CMD_AP_KEYMAP_KEY40, "KMKEY40", 7 },
	{ PRIV_CMD_AP_KEYMAP_KEY104, "KMKEY104", 8 },
	{ PRIV_CMD_AP_KEYMAP_KEY_INDEX, "KMIDX", 5 },
	{ PRIV_CMD_AP_KEYMAP_KEY_TYPE, "KMTYPE", 6 },
	{ PRIV_CMD_AP_KEYMAP_KEY_VALID, "KMVALID", 7 }
};


#define	KEYMAP_OPERATION_GET	0
#define	KEYMAP_OPERATION_SET	1
#define	KEYMAP_VALID_OFF	0
#define	KEYMAP_VALID_ON		1

static struct rtl_priv_args rtl_priv_kmop_args[] =
{
	{ KEYMAP_OPERATION_GET, "get", 3 },
	{ KEYMAP_OPERATION_SET, "set", 3 }
};


#define WEP_MODE_OFF        0
#define WEP_MODE_ON_40      1
#define WEP_MODE_ON_104     2
static struct rtl_priv_args rtl_priv_wepmode_args[] =
{
	{ WEP_MODE_OFF, "off", 3 },
	{ WEP_MODE_ON_40, "wep40", 5 },
	{ WEP_MODE_ON_104, "wep104", 6 }
};

static struct rtl_priv_args rtl_priv_kmvalid_args[] =
{
	{ KEYMAP_VALID_ON, "on", 2 },
	{ KEYMAP_VALID_OFF, "off", 3 }
};
#endif
//End of HW_CAM_CONFIG
//----------------------------------------------------------


/*--------------------  Function Definition ---------------*/
//use [ifdef] to exclude the following function definition
//in compile of dlisten

#include "1x_types.h"
#include "1x_common.h"

#ifdef RTL_WPA_CLIENT
#include "1x_supp_pae.h"
#endif

#define SIOCGIWIND      0x89ff
#define SIOCKEYMAP	0x89f9
#define SIOCGIWRTLSTAINFO  0x8B30



int lib1x_control_init();


int lib1x_control_STADisconnect(Global_Params *global, u_short reason);

int lib1x_control_RemovePTK(Global_Params *global, int keytype);

int lib1x_control_QueryRSC(Global_Params * global, OCTET_STRING * gRSC);

int lib1x_control_QuerySTA(Global_Params * global);

int lib1x_control_Query_All_Sta_Info(Dot1x_Authenticator * auth);

#ifdef RTL_WPA2
/*
	event_id: DOT11_EVENT_ASSOCIATION_IND or DOT11_EVENT_REASSOCIATION_IND
*/
int lib1x_control_AssociationRsp(Global_Params * global, int result, int event_id);
#else
int lib1x_control_AssociationRsp(Global_Params * global, int result);
#endif

//int lib1x_control_SetRSNIE(Global_Params * global, int role);

int lib1x_control_RSNIE(Dot1x_Authenticator * auth, u_char flag);

int lib1x_control_SetPTK(Global_Params * global);

int lib1x_control_SetGTK(Global_Params * global);

int lib1x_control_SetPORT(Global_Params * global, u_char status);

int lib1x_control_SetExpiredTime(Global_Params * global, u_long ulExpireTime);

int lib1x_control_Set802dot1x(Global_Params * global, u_char var_type, u_char var_val);

int lib1x_control_InitQueue(Dot1x_Authenticator * auth);

int lib1x_control_KeyMapping(Global_Params * global, u_char operation, u_char keytype, u_char keyvalid);

int lib1x_control_IndicateMICFail(Dot1x_Authenticator * auth, u_char *mac);

int lib1x_control_Poll(Dot1x_Authenticator * auth);


#ifdef RTL_WPA_CLIENT
int lib1x_control_STA_QUERY_BSSID(Supp_Global * pGlobal);
int lib1x_control_STA_QUERY_SSID(Supp_Global * pGlobal, unsigned char *pSSID);
int lib1x_control_STA_SetPTK(Supp_Global * pGlobal);
int lib1x_control_STA_SetPORT(Supp_Global * pGlobal, u_char status);
int lib1x_control_STA_SetGTK(Supp_Global * pGlobal, u_char * pucKey, int iKeyId);
int lib1x_control_AuthDisconnect(Dot1x_Authenticator * auth, u_char *pucMacAddr, u_short reason);
#endif
