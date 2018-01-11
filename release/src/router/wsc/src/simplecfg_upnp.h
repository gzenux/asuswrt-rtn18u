#ifndef SIMPLECFG_UPNP_H
#define SIMPLECFG_UPNP_H

#define PSIMPLECFG_INIT_DESC_DOC	"simplecfg"
#define PSIMPLECFG_INIT_CONF_DIR	"/var/wps/"
#define PSIMPLECFG_SERVICE_DESC_DOC "simplecfgservice"
//Brad add 20081205
#define PSIMPLECFG_INIT_DESC_PORT 52881
#define MACLEN 17
#ifndef __ECOS
#define IP_ADDRLEN 17
#endif
#define MAX_MSG_LEN 1600
#define UPNP_UUID_LEN 16
#define UPNP_SID_LEN 44
#define UPNP_WAIT_REBOOT 3
#define UPNP_INIT_TIMES 5

#define WSC_UPNP_SUCCESS 0
#define WSC_UPNP_FAIL -1
#define WSC_UPNPWEBSERVER_FAIL -2
#define WSC_UPNPROOTDEV_FAIL -3
#define WSC_UPNPSTATETABLE_FAIL -4
#define WSC_UPNPSENDADV_FAIL -5
#define WSC_UPNPINIT_FAIL -6
#define WSC_UPNP_GETDEVINFO_FAIL -7
#define WSC_UPNP_M2TOM8_FAIL -8

enum WSC_EventType_e {
	WSC_NOT_PROXY=0,
	WSC_PROBE_FRAME=1,
	WSC_8021XEAP_FRAME=2,
};

enum WSC_EventID_e {
	WSC_GETDEVINFO,
	WSC_M2M4M6M8,
	WSC_M3,
	WSC_M5,
	WSC_M7,
	WSC_RETURN_FROM_M8,
	WSC_PUTWLANRESPONSE,
	WSC_PUTWLANREQUEST,
	WSC_AP_STATUS,
	WSC_STA_STATUS,
	WSC_SETSELECTEDREGISTRA,
	WSC_GETAPSETTINGS,
	WSC_SETAPSETTINGS,
	WSC_DELAPSETTINGS,
	WSC_REBOOT,
	WSC_REBOOTAP,
	WSC_RESETAP,
	WSC_GETSTASETTINGS,
	WSC_SETSTASETTINGS,
	WSC_DELSTASETTINGS,
	WSC_REBOOTSTA,
	WSC_RESETSTA,
};

enum WSC_OpMode_e {
	WSC_AP_MODE,
	WSC_STA_MODE,
};

enum WSC_OpStatus_e {
	WSC_INITIAL=0,
	WSC_CONFIG_CHANGE=1,
	WSC_LOCKED=2,
};

typedef enum WSC_EventType_e WSC_EventType;
typedef enum WSC_EventID_e WSC_EventID;
typedef enum WSC_OpMode_e OpMode;
typedef enum WSC_OpStatus_e OpStatus;

struct WSC_packet {
	WSC_EventType EventType;
	WSC_EventID EventID;
	char IP[IP_ADDRLEN];
	char EventMac[MACLEN];
	unsigned char *tx_buffer;
	int tx_size;
	unsigned char rx_buffer[MAX_MSG_LEN];
	int rx_size;
};

struct WSC_profile {
	unsigned char uuid[UPNP_UUID_LEN];
	char *manufacturer;
	char *model_name;
	char *model_num;
	char *serial_num;
	char *device_name;
	char *manufacturerURL;
	char *modelDescription;
	char *modelURL;
	char *UPC;
};

struct subscription_info {
	unsigned char used;
	char Sid[UPNP_SID_LEN];
	int subscription_timeout;
};

typedef int  (*WSC_FunPtr) (struct WSC_packet *packet, void *Cookie);

//register callback function
extern int WSCRegisterCallBackFunc(WSC_FunPtr Fun, void *Cookie);

// need memset(profile, 0, sizeof(struct WSC_profile)) before calling this function
// ifname is "br0"
// will activate Upnp after this call
extern int WSCUpnpStart(char *ifname, OpMode mode, struct WSC_profile *profile);

// free Upnp resource when shutting down Upnp
extern void WSCUpnpStop(void);

extern int WSCUpnpTxmit(struct WSC_packet *packet);

#endif
