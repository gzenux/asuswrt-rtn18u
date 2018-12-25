/*
 *  Header file for WiFi Simple-Config
 *
 *	Copyright (C)2006, Realtek Semiconductor Corp. All rights reserved.
 *
 *	$Id: wsc.h,v 1.59 2010/08/09 09:27:13 pluswang Exp $
 */
/*================================================================*/

#ifndef INCLUDE_WSC_H
#define INCLUDE_WSC_H
#include <endian.h>
#if (defined(BYTE_ORDER) && (BYTE_ORDER == BIG_ENDIAN))
#define B_ENDIAN
#elif (defined(BYTE_ORDER) && (BYTE_ORDER == LITTLE_ENDIAN))
#define L_ENDIAN
#else
#error "Endian is not defined!"
#endif

#if defined(__ECOS) && defined(CONFIG_SDIO_HCI)
#include <cyg/kernel/kapi.h>
#include "wps_def.h" //export some definitions
#endif

/*================================================================*/
/* Define Flags */
#ifdef __ECOS
#define USE_MINI_UPNP
#define STAND_ALONE_MINIUPNP
#define NO_IWCONTROL
#define USE_PORTING_OPENSSL
#endif

//#define OUTPUT_LOG		// output debug message to log file /var/log/messages
#if 0
#define DEBUG
#define PRINT_ERR

#define TEST 
#define DEBUG_TRACE
#endif

#define WPS_FOR_ASUS 1
#define WPS_ASUS_CONCURRENTREPEATER 1

#define SUPPORT_ENROLLEE
#define SUPPORT_REGISTRAR
#define SUPPORT_UPNP
#define WIFI_SIMPLE_CONFIG		// must define
#define WSC_CLIENT_MODE
#define MUL_PBC_DETECTTION
//#define TEST_FOR_MULTIPLE_CREDENTIAL
#define PREVENT_PROBE_DEADLOCK
#define BLOCKED_ROGUE_STA
#define USE_MUTEX

#define CONNECT_PROXY_AP //_Eric add for wps_pin method to connect to wps proxy-ap
#define SUPPORT_HANDLE_MULTI_CREDENTIAL		// feature add 2011-1012


//auto decision at Makefile
#ifndef FOR_DUAL_BAND
#define FOR_DUAL_BAND
#endif

//define CONFIG_RTL_REPEATER_WPS_SUPPORT for use one wscd binary
#ifndef CONFIG_RTL_REPEATER_WPS_SUPPORT
#define CONFIG_RTL_REPEATER_WPS_SUPPORT
#endif

#if defined(__ECOS) && defined(CONFIG_SDIO_HCI)
#undef FOR_DUAL_BAND
#undef CONFIG_RTL_REPEATER_WPS_SUPPORT
#endif

#ifdef WPS2DOTX
#define V2VERSION	0x20
#define MAX_AUTHORIZED_MACS 5
//#define WPS2DOT0_DEBUG

//#define EAP_FRAGMENT
#define EAP_REASSEMBLY

//#define WSC_IE_FRAGMENT_STASIDE
#define WSC_IE_FRAGMENT_APSIDE

#endif


/*==========================================================*/

//#define WSC_KEEP_SUB

#ifdef USE_MINI_UPNP
	#undef PREVENT_PROBE_DEADLOCK
	#undef USE_MUTEX
#endif

#define WINDOW7



#ifdef DEBUG_TRACE
#define DBFENTER		printf("----->%s\n", __FUNCTION__)
#define DBFEXIT			printf("%s----->\n", __FUNCTION__)
#else
#define DBFENTER
#define DBFEXIT
#endif




#ifdef DEBUG

extern void wsc_debug_out(char *label, unsigned char *data, int data_length);

#ifdef OUTPUT_LOG
#define LOG_PATH "/var/log/messages"
	
#define WSC_DEBUG(fmt, args...)	\
	do { \
		if(outlog_fp){\
			sprintf(StringbufferOut , "%s %d:"fmt,__FUNCTION__ , __LINE__ , ## args);\
			fputs(StringbufferOut , outlog_fp);\
		}\
	} while (0)


#define TX_DEBUG(fmt, args...)	\
	do { \
		if(outlog_fp){\
			sprintf(StringbufferOut , "%s %d:"fmt,__FUNCTION__ , __LINE__ , ## args);\
			fputs(StringbufferOut , outlog_fp);\
		}\
	} while (0)
#define RX_DEBUG(fmt, args...)	\
	do { \
		if(outlog_fp){\
			sprintf(StringbufferOut , "%s %d:"fmt,__FUNCTION__ , __LINE__ , ## args);\
			fputs(StringbufferOut , outlog_fp);\
		}\
	} while (0)
	
#define UTIL_DEBUG(fmt, args...)	\
	do { \
		if(outlog_fp){\
			sprintf(StringbufferOut , "%s %d:"fmt,__FUNCTION__ , __LINE__ , ## args);\
			fputs(StringbufferOut , outlog_fp);\
		}\
	} while (0)
	
#define SUM_DEBUG(fmt, args...)	\
	do { \
		if(outlog_fp){\
			sprintf(StringbufferOut , "%s %d:"fmt,__FUNCTION__ , __LINE__ , ## args);\
			fputs(StringbufferOut , outlog_fp);\
		}\
	} while (0)

#define UPNP_DEBUG(fmt, args...)	\
	do { \
		if(outlog_fp){\
			sprintf(StringbufferOut , "%s %d:"fmt,__FUNCTION__ , __LINE__ , ## args);\
			fputs(StringbufferOut , outlog_fp);\
		}\
	} while (0)

#define P2P_DEBUG(fmt, args...)	\
	do { \
		if(outlog_fp){\
			sprintf(StringbufferOut , "%s %d:"fmt,__FUNCTION__ , __LINE__ , ## args);\
			fputs(StringbufferOut , outlog_fp);\
		}\
	} while (0)

		




#define _DEBUG_PRINT(fmt, args...)	\
	do { \
		if(outlog_fp){\
			sprintf(StringbufferOut ,fmt, ## args);\
			fputs(StringbufferOut , outlog_fp);\
		}\
	} while (0)

#define DEBUG_PRINT(fmt, args...)	\
	do { \
		if(pCtx->debug){\
		if(outlog_fp){\
			sprintf(StringbufferOut ,fmt, ## args);\
			fputs(StringbufferOut , outlog_fp);\
		}\
		}\
	} while (0)
#define DEBUG_PRINT2(fmt, args...)	\
	do { \
		if(pCtx->debug2){\
		if(outlog_fp){\
			sprintf(StringbufferOut ,fmt, ## args);\
			fputs(StringbufferOut , outlog_fp);\
		}\
		}\
	} while (0)
#define MAC_PRINT(fmt) 
#define UUID_PRINT(fmt)
	
#else	//OUTPUT_LOG

#define DEBUG_PRINT(fmt, args...) \
	if (pCtx->debug) printf(fmt, ## args)

#define DEBUG_PRINT2(fmt, args...) \
	if (pCtx->debug2) printf("%s %d"fmt,__FUNCTION__ , __LINE__ , ## args)


#define _DEBUG_PRINT(fmt, args...) printf(fmt, ## args)


#define WSC_DEBUG(fmt, args...) printf("[wsc]%s %d:"fmt,__FUNCTION__ , __LINE__ , ## args)
#define RX_DEBUG(fmt, args...)  printf("[rx]%s,%d:"fmt,__FUNCTION__ , __LINE__ , ## args)
#define TX_DEBUG(fmt, args...)  printf("[tx]%s,%d:"fmt,__FUNCTION__ , __LINE__ , ## args)
#define UTIL_DEBUG(fmt, args...) printf("[util]%s,%d:"fmt,__FUNCTION__ , __LINE__ , ## args)
#define SUM_DEBUG(fmt, args...) printf("[sum]%s,%d:"fmt,__FUNCTION__ , __LINE__ , ## args)
#define UPNP_DEBUG(fmt, args...) printf("[upnp]%s,%d:"fmt,__FUNCTION__ , __LINE__ , ## args)
#define P2P_DEBUG(fmt, args...) printf("[p2p-wsc]%s %d:"fmt,__FUNCTION__ , __LINE__ , ## args)		

#define MAC_PRINT(fmt) printf("(%s,%d):	%02X:%02X:%02X:%02X:%02X:%02X\n",\
		__FUNCTION__ , __LINE__ , fmt[0],fmt[1],fmt[2],fmt[3],fmt[4],fmt[5])
#define UUID_PRINT(fmt) printf("(%s,%d):	%02X%02x%02x%02x%02x %02x%02X%02x%02x%02x %02x%02x%02X%02x%02x%02x\n",\
									__FUNCTION__ , __LINE__ ,\
									fmt[0],fmt[1],fmt[2],fmt[3],fmt[4],fmt[5]\
									,fmt[6],fmt[7],fmt[8],fmt[9],fmt[10],fmt[11],\
									fmt[12],fmt[13],fmt[14],fmt[15])
#endif	// end of OUTPUT_LOG



#else

#define DEBUG_PRINT(fmt, args...)
#define DEBUG_PRINT2(fmt, args...)
#define _DEBUG_PRINT(fmt, args...)
#define wsc_debug_out(fmt, args...)

#define WSC_DEBUG(fmt, args...) 
#define RX_DEBUG(fmt, args...) 
#define TX_DEBUG(fmt, args...) 
#define UTIL_DEBUG(fmt, args...) 
#define SUM_DEBUG(fmt, args...) 
#define UPNP_DEBUG(fmt, args...)
#define MAC_PRINT(fmt) 
#define UUID_PRINT(fmt) 
#define P2P_DEBUG(fmt, args...) 
#endif

#ifdef PRINT_ERR
#ifdef OUTPUT_LOG
#define DEBUG_ERR(fmt, args...) \
	do { \
		if(outlog_fp){\
			sprintf(StringbufferOut , "%s %d:"fmt,__FUNCTION__ , __LINE__ , ## args);\
			fputs(StringbufferOut , outlog_fp);\
		}\
	} while (0)
	
#else
#define DEBUG_ERR(fmt, args...) printf(fmt, ## args)
#endif
#else
#define DEBUG_ERR(fmt, args...)
#endif

/*==========================================================*/

#define AUTO_LOCK_DOWN	// must under WPS2X
#ifdef AUTO_LOCK_DOWN
#define ALD_BRUTEFORCE_ATTACK_MITIGATION
#endif
/*=======Customization=========================*/

// for CUBE setting
//#define IKD

#ifdef IKD
/* 2011-11-28 for support start PBC from gpio module*/
#define TRIGGER_PBC_FROM_GPIO
#endif

//#define CBN_SPEC
#ifdef CBN_SPEC
#define REINIT_VIA_RELOAD_DAEMON
#endif


#ifdef DET_WPS_SPEC

	#define AUTO_LOCK_DOWN
	//#define	DET_WPS_SPEC_DEBUG
	//#define NO_IWCONTROL
	//#define USE_POLLING
	#ifndef WINDOW7
		#define  WINDOW7
	#endif	
#endif

#ifdef DET_WPS_SPEC_DEBUG
#define DET_DEBUG(fmt, args...) printf(fmt, ## args)
#else
#define DET_DEBUG(fmt, args...)
#endif // DEBUG

//#define SER_AP_SPEC

//#define CONFIG_RTL8186_KLD_REPEATER
//#define CONFIG_RTL865x_KLD_REPEATER
//#define CONFIG_CMO


#ifdef CONFIG_RTL8186_KB
	#define NO_IWCONTROL
	#define WSC_1SEC_TIMER
	//#ifdef MUL_PBC_DETECTTION
		//#undef MUL_PBC_DETECTTION
	//#endif
	#ifdef WSC_CLIENT_MODE
		#undef WSC_CLIENT_MODE
	#endif		
#endif

/*============Customization====================*/

//#define WSC_CLIENT_ONLY
#ifdef WSC_CLIENT_ONLY
//#undef SUPPORT_REGISTRAR
//#undef BLOCKED_ROGUE_STA
#undef SUPPORT_UPNP
#undef PREVENT_PROBE_DEADLOCK
#undef USE_MUTEX
#undef USE_MINI_UPNP
#ifdef FOR_DUAL_BAND
#undef FOR_DUAL_BAND
#endif

#define NO_IWCONTROL
#define WSC_1SEC_TIMER
#endif

/* Include Files */
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <unistd.h>
#include <signal.h>
#include <fcntl.h>
#include <sys/time.h>
#include <time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <sys/stat.h>
#ifndef __ECOS
#include <linux/if_packet.h>
#endif
#include <sys/ioctl.h>
#include <arpa/inet.h>
#ifndef __ECOS
#include <linux/wireless.h>
#include <sys/sysinfo.h>
#else
#include <net/if.h>			/* for IFNAMSIZ and co... */
#include <cyg/io/eth/rltk/819x/wrapper/wireless.h>
#endif
#ifdef USE_MUTEX
	#include <pthread.h> 
#endif

#include <openssl/crypto.h>
#include <openssl/bn.h>
#include <openssl/dh.h>
#include <openssl/rand.h>

#ifndef __ECOS
#include "built_time"
#endif

#ifdef SUPPORT_UPNP
	#include "simplecfg_upnp.h"
	#ifdef USE_MINI_UPNP
	#ifndef __ECOS
		#include <syslog.h>
	#endif
		#include "mini_upnp.h"
		#include "upnphttp.h"
		#include "upnpsoap.h"
		#include "upnpreplyparse.h"
		#include "minixml.h"
	#endif
#endif

/*================================================================*/
/* Macro Definitions */

#define DISPLAY_BANNER \
	printf("\nWiFi Simple Config %s (%s).\n\n", VERSION_STR, BUILT_TIME)

#ifdef WPS2DOTX
#define IS_PIN_METHOD(mode)	((mode & (CONFIG_METHOD_PIN|CONFIG_METHOD_VIRTUAL_PIN|CONFIG_METHOD_PHYSICAL_PIN)) ? 1 : 0)
#define IS_PBC_METHOD(mode)	((mode & (CONFIG_METHOD_PBC|CONFIG_METHOD_VIRTUAL_PBC|CONFIG_METHOD_PHYSICAL_PBC)) ? 1 : 0)

#define IS_PIN_MODE(mode)	((mode & (CONFIG_METHOD_PIN|CONFIG_METHOD_VIRTUAL_PIN|CONFIG_METHOD_PHYSICAL_PIN)) ? 1 : 0)
#define IS_PBC_MODE(mode)	((mode & (CONFIG_METHOD_PBC|CONFIG_METHOD_VIRTUAL_PBC|CONFIG_METHOD_PHYSICAL_PBC)) ? 1 : 0)
#else
#define IS_PIN_METHOD(mode)	((mode & CONFIG_METHOD_PIN) ? 1 : 0)
#define IS_PBC_METHOD(mode)	((mode & CONFIG_METHOD_PBC) ? 1 : 0)

#define IS_PIN_MODE(mode)	((mode & CONFIG_METHOD_PIN) ? 1 : 0)
#define IS_PBC_MODE(mode)	((mode & CONFIG_METHOD_PBC) ? 1 : 0)

#endif

#ifdef USE_MUTEX
#define WSC_pthread_mutex_init(x, y); 	pthread_mutex_init(x, y);
#define WSC_pthread_mutex_destroy(x); 	pthread_mutex_destroy(x);
#define WSC_pthread_mutex_lock(x);		pthread_mutex_lock(x);
#define WSC_pthread_mutex_unlock(x);	pthread_mutex_unlock(x);
#define WSC_pthread_mutex_t			pthread_mutex_t
#else
#define WSC_pthread_mutex_init(x, y);
#define WSC_pthread_mutex_destroy(x);
#define WSC_pthread_mutex_lock(x);
#define WSC_pthread_mutex_unlock(x);
#define WSC_pthread_mutex_t			unsigned char
#endif

//#ifdef CONFIG_RTL8186_TR
#if defined(CONFIG_RTL8186_TR) || defined(CONFIG_RTL865X_AC) || defined(CONFIG_RTL865X_KLD) || defined(CONFIG_RTL8196C_EC)
#define SET_LED_ON_FOR_10S() { \
	char tmpbuf[100]; \
	wlioctl_set_led(LED_WSC_OK); \
	sprintf(tmpbuf, "echo 1 > %s", LED_ON_10S_FILE); \
	system(tmpbuf); \
}
#endif

#ifdef FOR_DUAL_BAND
#define GET_CURRENT_ADDRESS ((pCtx->InterFaceComeIn == COME_FROM_WLAN1)?pCtx->our_addr2:pCtx->our_addr)
#else
#define GET_CURRENT_ADDRESS (pCtx->our_addr)
#endif

#ifdef FOR_DUAL_BAND
#define GET_CURRENT_INTERFACE ((pCtx->InterFaceComeIn == COME_FROM_WLAN1)?pCtx->wlan_interface_name2:pCtx->wlan_interface_name)
#else
#define GET_CURRENT_INTERFACE (pCtx->wlan_interface_name)
#endif

#ifdef FOR_DUAL_BAND
#define GET_CURRENT_SOCKET ((pCtx->InterFaceComeIn == COME_FROM_WLAN1)?pCtx->socket2:pCtx->socket)
#else
#define GET_CURRENT_SOCKET (pCtx->socket)
#endif


/*================================================================*/
/* Constant Definitions */

#define PROGRAM_NAME				"wscd"

#ifdef WPS2DOTX
#define VERSION_STR					"v2.20-wps2.0"
#else
#define VERSION_STR					"v2.20-wps1.0"
#endif

#ifdef __ECOS
#define DEFAULT_LAN_INTERFACE		("eth0")
extern char wscd_config[];			// "/tmp/wscd_config"
extern int wscd_status;			// "/tmp/wscd_status"
extern int wps_start_interface0;	// "/var/wps_start_interface0"
extern int wps_start_interface1;	// "/var/wps_start_interface1"
extern int wps_done;			// "/var/wps_done"
#else
#define DEFAULT_CONFIG_FILENAME		("/var/"PROGRAM_NAME".conf")
#define DEFAULT_PID_FILENAME		("/var/run/"PROGRAM_NAME)
#ifdef CONFIG_IWPRIV_INTF
#if     !defined(CONFIG_RTL8196C) && !defined(CONFIG_RTL_819X)
#define COMPATIBLE_CONFIG_FILE          ("/etc/Wirless/RTL8190N.dat")
#else
#define COMPATIBLE_CONFIG_FILE          ("/etc/Wirless/RTL8192CD.dat")
#endif
#endif
#define DEFAULT_LAN_INTERFACE		("br0")
#define REINIT_WEB_FILE				("/tmp/reinit_web")
#define REINIT_WSCD_FILE			("/tmp/reinit_wscd")
//#ifdef CONFIG_RTL8186_TR
#if defined(CONFIG_RTL8186_TR) || defined(CONFIG_RTL865X_AC) || defined(CONFIG_RTL865X_KLD) || defined(CONFIG_RTL8196C_EC)
#define LED_ON_10S_FILE				("/tmp/wps_led")
#endif
#define WSCD_BYEBYE_FILE			("/tmp/wscd_byebye")
#define WSCD_CONFIG_FILE			("/tmp/wscd_config")
#define WSCD_CONFIG_STATUS			("/tmp/wscd_status")
#define WSCD_CANCEL_PROTOCOL		("/tmp/wscd_cancel")
#define WSCD_LAST_SUCCESS_ENROLLEE	("/tmp/wscd_enrollee")	// 2011-0830 ; add for recored last success enrollee

#define WSCD_IND_ONLY_INTERFACE0  ("/var/wps_start_interface0")
#define WSCD_IND_ONLY_INTERFACE1  ("/var/wps_start_interface1")


#ifdef INBAND_WPS_OVER_HOST
#define HOST_MII_INTF "br0"
#endif
#ifdef AUTO_LOCK_DOWN
#define WSCD_LOCK_STAT		("/tmp/wscd_lock_stat")
#endif
#endif //__ECOS

#ifndef _WPS_DEF_H_
#define PIN_LEN						8
#endif
#define ETHER_ADDRLEN				6
#define ETHER_HDRLEN				14
#define TX_BUFFER_SIZE				1512
#define RX_BUFFER_SIZE				1600
#define MAX_MSG_SIZE				1600	/* byte number of FIFO event */

#define UUID_LEN					16
#define NONCE_LEN					16
#define PUBLIC_KEY_LEN				192
#ifndef _WPS_DEF_H_
#define MAX_MANUFACT_LEN			64
#define MAX_MODEL_NAME_LEN			32
#define MAX_MODEL_NUM_LEN			32
#define MAX_SERIAL_NUM_LEN			32
#define MAX_DEVICE_NAME_LEN			32
#define WSC_MAX_SSID_LEN			32
#define MAX_WEP_KEY_LEN				26
#define MAX_NETWORK_KEY_LEN			64
#endif
#define MIN_NETWORK_KEY_LEN			8

#define OUI_LEN						4
#define BYTE_LEN_64B				(64/8)
#define BYTE_LEN_128B				(128/8)
#define BYTE_LEN_256B				(256/8)
#define BYTE_LEN_640B				(640/8)

#define IV_LEN						16
#define MAX_WSC_IE_LEN				(256+128)
#define MACADDRLEN					6
#define MAX_BSS_DESC				64

#define PROBEIELEN					260


#define EAPOL_HDRLEN				4
#define EAP_HDRLEN					4
#define MSG_LEN_LEN					2	


#define RF_BAND_2G	1
#define RF_BAND_5G	2

#define ETHER_EAPOL_TYPE			0x888e
#define EAPOL_VER					1
#define EAPOL_EAPPKT				0
#define EAPOL_START					1
#define EAPOL_KEY					3

#define EAP_REQUEST					1
#define EAP_RESPONSE				2
#define EAP_SUCCESS					3
#define EAP_FAIL					4

#define EAP_TYPE_IDENTITY			1
#define EAP_TYPE_EXPANDED			254

#ifdef __ECOS
// force pCtx->rx_buffer + FIFO_HEADER_LEN to be 4-byte alignment
#define FIFO_HEADER_LEN			8
#else
#define FIFO_HEADER_LEN				5
#endif

#define WSC_MAX_STA_NUM				10
#define MAX_EXTERNAL_REGISTRAR_NUM	3
#define MAX_BLOCKED_STA_NUM			10


#ifdef CONNECT_PROXY_AP
#define MAX_RETRY_AP_NUM		2
#define MAX_BLOCKED_AP_NUM		(MAX_RETRY_AP_NUM+1)
#define MAX_RETRY_AP_TIME		5
#endif


#if defined(CONFIG_RTL865X_KLD)   
#define BUTTON_HOLD_TIME			1   
#elif defined(CONFIG_CMO) 
#define BUTTON_HOLD_TIME			2
#else
#define BUTTON_HOLD_TIME			3
#endif
#define PBC_WALK_TIME				120 // in sec


#define PIN_WALK_TIME				120 // in sec

#ifdef CONFIG_IWPRIV_INTF
#define RESET_WAIT_TIME				30 // in sec
#endif
#ifdef	AUTO_LOCK_DOWN

#ifdef ALD_BRUTEFORCE_ATTACK_MITIGATION	
#define ALD_INDEFINITE_TH	10
#endif

#define AUTH_FAIL_TIMES   	3
#define AUTH_FAIL_TIME_TH	60
#define AUTO_LOCKED_DOWN_TIME	60
//#define AUTO_LOCKED_DOWN_TIME	20		// for test


#if	0	//def DET_WPS_SPEC	// should no use ; fellow WFA SPEC 2.02 
#define AUTH_FAIL_TIMES   	30
#define AUTH_FAIL_TIME_TH	300    
#define AUTO_LOCKED_DOWN_TIME	300	
#endif


#endif
#define SETSELREG_WALK_TIME		120 // in sec
#define SESSION_OVERLAP_TIME		(pCtx->PBC_overlapping_LED_time_out)
#define WAIT_REBOOT_TIME			3

#define IS_UPNP_CONTROL_POINT		0x8000000
#ifdef SUPPORT_UPNP
#ifdef PREVENT_PROBE_DEADLOCK
#define MAX_WSC_PROBE_STA			10
#define PROBE_EXPIRED				10
#endif
#define MAX_SUBSCRIPTION_TIMEOUT  	180
#define UPNP_EXTERNAL_REG_EXPIRED	 (MAX_SUBSCRIPTION_TIMEOUT + 3)
#define MAX_SUBSCRIPTION_NUM		10
#endif
#define BASIC_TIMER_UNIT 			1000000

#ifdef BLOCKED_ROGUE_STA
#define DEFAULT_BLOCK_TIME			60
#endif

#define EAP_ID_ENROLLEE				("WFA-SimpleConfig-Enrollee-1-0")
#define EAP_ID_REGISTRAR			("WFA-SimpleConfig-Registrar-1-0")
#define KDF_STRING					("Wi-Fi Easy and Secure Key Derivation")

#define WSC_IE_ID					221
#define WSC_VENDOR_TYPE				1

#define WSC_OP_START				1
#define WSC_OP_ACK					2
#define WSC_OP_NACK					3
#define WSC_OP_MSG					4
#define WSC_OP_DONE					5
#define WSC_OP_FRAG_ACK				6	//for wps2.x

#define EAP_FR_MF				1	//	more fragments ; for wps2.x
#define EAP_FR_LF				2	//	length field   ; for wps2.x



#define TAG_AP_CHAN					0x1001
#define TAG_ASSOC_STATE				0x1002
#define TAG_AUTH_TYPE				0x1003
#define TAG_AUTH_TYPE_FLAGS			0x1004
#define TAG_AUTHENTICATOR			0x1005
#define TAG_CONFIG_METHODS 			0x1008
#define TAG_CONFIG_ERR				0x1009
#define TAG_CONFIG_URL4				0x100A
#define TAG_CONFIG_URL6				0x100B
#define TAG_CONNECT_TYPE			0x100C
#define TAG_CONNECT_TYPE_FLAGS		0x100D
#define TAG_CREDENTIAL				0x100E
#define TAG_DEVICE_NAME				0x1011
#define TAG_DEVICE_PASSWORD_ID		0x1012
#define TAG_E_HASH1					0x1014
#define TAG_E_HASH2					0x1015
#define TAG_E_SNONCE1				0x1016
#define TAG_E_SNONCE2				0x1017
#define TAG_ENCRYPT_SETTINGS		0x1018
#define TAG_ENCRYPT_TYPE			0x100F
#define TAG_ENCRYPT_TYPE_FLAGS		0x1010
#define TAG_EROLLEE_NONCE			0x101A
#define TAG_FEATURE_ID				0x101B
#define TAG_IDENTITY				0x101C
#define TAG_IDENTITY_PROOF			0x101D

#define TAG_INIT_VECTOR				0x1060
#define TAG_KEY_WRAP_AUTH			0x101E
#define TAG_KEY_IDENTIFIER			0x101F
#define TAG_MAC_ADDRESS				0x1020
#define TAG_MANUFACTURER			0x1021
#define TAG_MSG_TYPE				0x1022
#define TAG_MODEL_NAME				0x1023
#define TAG_MODEL_NUMBER			0x1024
#define TAG_NETWORK_INDEX			0x1026
#define TAG_NETWORK_KEY				0x1027
#define TAG_NETWORK_KEY_INDEX		0x1028
#define TAG_NEW_DEVICE_NAME			0x1029
#define TAG_NEW_PASSWORD			0x102A
#define TAG_OOB_DEVICE_PASSWORD		0x102C
#define TAG_OS_VERSION				0x102D
#define TAG_POWER_LEVEL				0x102F

#define TAG_PSK_CURRENT				0x1030
#define TAG_PSK_MAX					0x1031
#define TAG_PUB_KEY					0x1032
#define TAG_RADIO_ENABLED			0x1033
#define TAG_REBOOT					0x1034
#define TAG_REGISTRAR_CURRENT		0x1035
#define TAG_REGISTRAR_ESTAB			0x1036
#define TAG_REGISTRAR_LIST			0x1037
#define TAG_REGISTRAR_MAX			0x1038
#define TAG_REGISTRAR_NONCE			0x1039
#define TAG_REQUEST_TYPE			0x103A
#define TAG_RESPONSE_TYPE			0x103B
#define TAG_RF_BAND					0x103C
#define TAG_R_HASH1					0x103D
#define TAG_R_HASH2					0x103E
#define TAG_R_SNONCE1				0x103F

#define TAG_R_SNONCE2				0x1040
#define TAG_SELECTED_REGITRAR		0x1041
#define TAG_SERIAL_NUM				0x1042
#define TAG_SIMPLE_CONFIG_STATE		0x1044
#define TAG_SSID					0x1045
#define TAG_TOTAL_NETWORK			0x1046
#define TAG_UUID_E					0x1047
#define TAG_UUID_R					0x1048
#define TAG_VENDOR_EXT				0x1049
#define TAG_VERSION					0x104A
#define TAG_X509_CERTIFICATE_REQ	0x104B
#define TAG_X509_CERTIFICATE		0x104C
#define TAG_EAP_IDENTITY			0x104D
#define TAG_MSG_COUNTER				0x104E
#define TAG_PUB_KEY_HASH			0x104F

#define TAG_REKEY					0x1050
#define TAG_KEY_LIFETIME			0x1051
#define TAG_PERMITTED_CONFIG_METHODS	0x1052
#define TAG_SEL_REG_CONFIG_METHODS	0x1053
#define TAG_PRIMARY_DEVICE_TYPE		0x1054
#define TAG_SEC_DEVICE_TYPE_LIST	0x1055
#define TAG_PORTABLE_DEVICE			0x1056
#define TAG_AP_SETUP_LOCKED				0x1057	// AP Setup Locked
#define TAG_APPLICATION_EXTENSION		0x1058
#define TAG_EAP_TYPE					0x1059	// EAP Type
#define TAG_WEP_TRANSMIT_KEY			0x1064	// WEPTransmitKey
#define TAG_SETTING_DELAY_TIME			0x1065	// 
#define TAG_NETWORKKEY_SHAREABLE		0x1066	// NetworkKey shareable
#define TAG_VERSION2					0x1067	// Version2
#define TAG_REQ_TO_ENROLL				0x1068	// Request to Enroll
#define TAG_AUTHORIZED_MACs				0x1069	// AuthorizedMACs
#define TAG_REQ_DEV_TYPE				0x106A	// Requested Device Type

#define TAG_FOR_TEST_EXTEN				0x1090	// for test plan 4.2.8 Protocol extensibility
#define TAG_FOR_BOTH_BAND_CRED			0x10FF	// for both band credential


//======================================================================
//WFA vendor ID list (r51)
#define VENDOR_VERSION2 	0x00
#define VENDOR_AUTHMAC 		0x01
#define VENDOR_NETKEYSHARE 	0x02
#define VENDOR_REQENROLL 	0x03
#define VENDOR_SETDELTIME 	0x04
#define MAX_VENEXT_LEN		1024	// max vendor externsion
//======================================================================

#define WSC_VER						0x10

#define MSG_TYPE_M1					4
#define MSG_TYPE_M2					5
#define MSG_TYPE_M2D				6
#define MSG_TYPE_M3					7
#define MSG_TYPE_M4					8
#define MSG_TYPE_M5					9
#define MSG_TYPE_M6					10
#define MSG_TYPE_M7					11
#define MSG_TYPE_M8					12
#define MSG_TYPE_ACK				13
#define MSG_TYPE_NACK				14
#define MSG_TYPE_DONE				15

#define NOT_GREATER_THAN_MASK		0x80000000
#define SIOCGIWIND      			0x89ff
#define SIOCGIWRTLSCANREQ			0x8B33	// scan request
#define SIOCGIWRTLGETBSSDB			0x8B34	// get bss data base
#define SIOCGIWRTLGETMIB			0x89f2	// get mib (== RTL8190_IOCTL_GET_MIB)
#define SIOCGIWRTLJOINREQ			0x8B35	// join request
#define SIOCGIWRTLJOINREQSTATUS		0x8B36	// get status of join request
// for P2P P2P_SUPPORT
#define SIOCP2P_WSC_REPORT_STATE	0x8BD7
#define SIOCP2P_WSC_FAST_CONNECT	0x8BD9


#define FIFO_MODE					(S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH)
#if defined(CONFIG_RTL8196C_AP_HCM) || defined(INBAND_WPS_OVER_HOST)
#define WRITE_FLASH_PROG			("hcd")
#define PARAM_TEMP_FILE				("/tmp/wps_param")
#else
#define WRITE_FLASH_PROG			("flash")
#define PARAM_TEMP_FILE				("/tmp/flash_param")
#define PARAM_TEMP_FILE2			("/tmp/flash_param2")
#endif
#ifdef	DET_WPS_SPEC
#define BUTTON_NEED_NOT_HOLD	1
#define BUTTON_NEED_HOLD	2
#define M1_TEMP_FILE				("/tmp/wscd_M1")
#endif
#define WEB_PID_FILENAME			("/var/run/webs.pid")

#if defined(CONFIG_RTL8186_KB)

	#define LED_WSC_START			-1
	#define LED_WSC_END				-2
	#define LED_PBC_OVERLAPPED		-3
	#define LED_WSC_ERROR			-4
	#define LED_WSC_SUCCESS			-5

#elif defined(CONFIG_RTL8186_TR) || defined(CONFIG_RTL865X_AC) || defined(CONFIG_RTL865X_KLD) || defined(CONFIG_RTL8196C_EC)
	#define LED_WSC_START			2
	#define LED_WSC_END				0
	#define LED_PBC_OVERLAPPED		6	
	#define LED_WSC_OK				1

	#define LED_WSC_ERROR			TURNKEY_LED_WSC_NOP
	#define LED_WSC_SUCCESS			TURNKEY_LED_WSC_NOP

#elif defined(CONFIG_RTL865X_SC)	
	#define LED_WSC_START				TURNKEY_LED_WSC_START
	#define LED_WSC_END					TURNKEY_LED_WSC_END
	#define LED_PBC_OVERLAPPED		TURNKEY_LED_PBC_OVERLAPPED

	#define LED_WSC_ERROR				TURNKEY_LED_WSC_NOP
	#define LED_WSC_SUCCESS			TURNKEY_LED_WSC_NOP

#elif defined(DET_WPS_SPEC)	
	#define LED_WSC_START				TURNKEY_LED_WSC_START
	#define LED_WSC_END					TURNKEY_LED_WSC_END
	#define LED_PBC_OVERLAPPED		TURNKEY_LED_PBC_OVERLAPPED

	#define LED_WSC_ERROR				TURNKEY_LED_WSC_ERROR
	#define LED_WSC_SUCCESS			TURNKEY_LED_WSC_NOP


#else
	#define LED_WSC_START				TURNKEY_LED_WSC_START
	#define LED_WSC_END					TURNKEY_LED_WSC_END
	#define LED_PBC_OVERLAPPED		TURNKEY_LED_PBC_OVERLAPPED	

	#define LED_WSC_ERROR				TURNKEY_LED_WSC_NOP
	#define LED_WSC_SUCCESS			TURNKEY_LED_WSC_NOP

#endif
	#define TURNKEY_LED_WSC_START		-1
	#define TURNKEY_LED_WSC_END			-2
	#define TURNKEY_LED_PBC_OVERLAPPED	-3

	#define TURNKEY_LED_WSC_ERROR		-4
	#define TURNKEY_LED_WSC_SUCCESS		-5
	#define TURNKEY_LED_WSC_NOP			-6

#ifdef	AUTO_LOCK_DOWN
	#define TURNKEY_LED_LOCK_DOWN		-7
#endif

enum { RSP_TYPE_ENR, RSP_TYPE_ENR_1X, RSP_TYPE_REG, RSP_TYPE_AP };
enum { REQ_TYPE_ENR, REQ_TYPE_ENR_1X, REQ_TYPE_REG, REQ_TYPE_MANAGER };

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

        DOT11_EVENT_ACC_SET_EXPIREDTIME = 31,
        DOT11_EVENT_ACC_QUERY_STATS = 32,
        DOT11_EVENT_ACC_QUERY_STATS_ALL = 33,
        DOT11_EVENT_REASSOCIATION_IND = 34,
        DOT11_EVENT_REASSOCIATION_RSP = 35,
        DOT11_EVENT_STA_QUERY_BSSID = 36,
        DOT11_EVENT_STA_QUERY_SSID = 37,
        DOT11_EVENT_EAP_PACKET = 41,

#ifdef RTL_WPA2_PREAUTH
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
	DOT11_EVENT_WSC_START_IND = 70,
	DOT11_EVENT_WSC_MODE_IND = 71,
	DOT11_EVENT_WSC_STATUS_IND = 72,
	DOT11_EVENT_WSC_METHOD_IND = 73,
	DOT11_EVENT_WSC_STEP_IND = 74,
	DOT11_EVENT_WSC_OOB_IND = 75,
#endif
	DOT11_EVENT_WSC_PBC_IND = 76,
	// for WPS2DOTX
	DOT11_EVENT_WSC_SWITCH_MODE = 100,	// for P2P P2P_SUPPORT
	DOT11_EVENT_WSC_STOP = 101	,
	DOT11_EVENT_WSC_SET_MY_PIN = 102,		// for WPS2DOTX
	DOT11_EVENT_WSC_SPEC_SSID = 103,
	DOT11_EVENT_WSC_SPEC_MAC_IND = 104,
	DOT11_EVENT_WSC_CHANGE_MODE = 105,	
	DOT11_EVENT_WSC_RM_PBC_STA = 106,
	DOT11_EVENT_WSC_CHANGE_MAC_IND=107,	
    DOT11_EVENT_WSC_SWITCH_WLAN_MODE=108,
    DOT11_EVENT_UCFGING_LED = 139,
    DOT11_EVENT_LINK_CHANGE_IND = 140,
    DOT11_EVENT_USER_SETIE  = 141
} DOT11_EVENT;


/*================================================================*/
/* Type Declarations */

#define __PACK__	__attribute__ ((packed))

enum { PROXY=0, ENROLLEE=1, REGISTRAR=2 };
enum { METHOD_PIN=1, METHOD_PBC=2 };
//	do modify  for wps2.x
#ifndef _WPS_DEF_H_
enum { 
	CONFIG_METHOD_ETH=0x2, 
	CONFIG_METHOD_PIN=0x4, 
	CONFIG_METHOD_DISPLAY=0x8  ,		
	CONFIG_METHOD_PBC=0x80, 
	CONFIG_METHOD_KEYPAD=0x100,
	CONFIG_METHOD_VIRTUAL_PBC=0x280	,
	CONFIG_METHOD_PHYSICAL_PBC=0x480,
	CONFIG_METHOD_VIRTUAL_PIN=0x2008,
	CONFIG_METHOD_PHYSICAL_PIN=0x4008
};
#endif

#ifdef P2P_SUPPORT

typedef enum { 
	P2P_DEVICE=1, 
	P2P_PRE_CLIENT=2,
	P2P_CLIENT=3,
	P2P_PRE_GO=4,	 // after GO nego , we are GO and proceed WSC exchange
	P2P_TMP_GO=5	 // after GO nego , we are GO and proceed WSC exchange is done
} P2P_TPYE_ENUM_T;

enum { 
	P2P_PIN_METHOD = 1, 
	P2P_PBC_METHOD = 2
};

enum { 
	USE_TARGET_PIN = 1, 
	USE_MY_PIN = 2 
};

enum { 
	GO_WPS_SUCCESS = 1, 
	GO_WPS_FAIL = 2 
};

#endif

#ifndef _WPS_DEF_H_
enum { 
		MODE_AP_UNCONFIG=1, 			// AP unconfigured (enrollee)
		MODE_CLIENT_UNCONFIG=2, 		// client unconfigured (enrollee) 
		MODE_CLIENT_CONFIG=3,			// client configured (External registrar) 
		MODE_AP_PROXY=4, 				// AP configured (proxy)
		MODE_AP_PROXY_REGISTRAR=5,		// AP configured (proxy and registrar)
		MODE_CLIENT_UNCONFIG_REGISTRAR=6		// client unconfigured (registrar)
};
#endif

#ifndef _WPS_DEF_H_
enum { WSC_AUTH_OPEN=1, WSC_AUTH_WPAPSK=2, WSC_AUTH_SHARED=4, WSC_AUTH_WPA=8, WSC_AUTH_WPA2=0x10, WSC_AUTH_WPA2PSK=0x20, WSC_AUTH_WPA2PSKMIXED=0x22 };
enum { WSC_ENCRYPT_NONE=1, WSC_ENCRYPT_WEP=2, WSC_ENCRYPT_TKIP=4, WSC_ENCRYPT_AES=8, WSC_ENCRYPT_TKIPAES=12 };
#endif

enum { CONNECT_TYPE_BSS=1, CONNECT_TYPE_IBSS=2 };
enum { 
	EV_START, 
	EV_STOP, 
	EV_EAP, 
	EV_ASSOC_IND, 
	EV_PIN_INPUT, 
	EV_PB_PRESS, 
	EV_PROBEREQ_IND ,
	EV_UN_AUTO_LOCK_DOWN,
    EV_MODE, 
    EV_STATUS, 
    EV_METHOD, 
    EV_STEP, 
    EV_OOB,
    EV_P2P_SWITCH_MODE,
    EV_CHANGE_MY_PIN,
    EV_SPEC_SSID,
    EV_SET_SPEC_CONNECT_MAC,
	EV_CHANGE_MODE,
	EV_RM_PBC_STA,
	EV_MAC_HAS_CHANGED,
	EV_HELP_CHANGE_WLAN_MODE
    
};


enum { ASSOC_STATE_NOT_ASSOC, ASSOC_STATE_CONNECT_SUCCESS,
		ASSOC_STATE_CONFIG_FAIL, ASSOC_STATE_ASSOC_FAIL, ASSOC_STATE_IP_FAIL};
enum { CONFIG_STATE_UNCONFIGURED=1, CONFIG_STATE_CONFIGURED=2};
#ifndef _WPS_DEF_H_
enum { CONFIG_BY_INTERNAL_REGISTRAR=1, CONFIG_BY_EXTERNAL_REGISTRAR=2, MANUAL_SETTING_TO_ENROLLEE=3};
#endif
enum { ST_ENROLLE=0x80000000, ST_INT_REG=0x40000000, ST_EXT_REG=0x20000000 };

enum { ST_IDLE, ST_WAIT_REQ_ID, ST_WAIT_RSP_ID, ST_WAIT_START, ST_WAIT_M1,
		ST_WAIT_M2, ST_WAIT_M3, ST_WAIT_M4, ST_WAIT_M5, ST_WAIT_M6,
		ST_WAIT_M7, ST_WAIT_M8, ST_WAIT_ACK, ST_WAIT_DONE, 
#ifdef SUPPORT_UPNP
		ST_UPNP_DONE, ST_UPNP_WAIT_M1, ST_UPNP_PROXY, ST_UPNP_WAIT_REBOOT, ST_UPNP_WAIT_DONE,
#endif
		ST_WAIT_EAP_FAIL, ST_WAIT_EAPOL_START ,
		ST_WAIT_EAPOL_FRAG_ACK_M1,ST_WAIT_EAPOL_FRAG_ACK_M2,ST_WAIT_EAPOL_FRAG_ACK_M3,
		ST_WAIT_EAPOL_FRAG_ACK_M4,ST_WAIT_EAPOL_FRAG_ACK_M5,ST_WAIT_EAPOL_FRAG_ACK_M6,
		ST_WAIT_EAPOL_FRAG_ACK_M7,ST_WAIT_EAPOL_FRAG_ACK_M8};

enum { PASS_ID_DEFAULT, PASS_ID_USER, PASS_ID_MACHINE, PASS_ID_REKEY,
		PASS_ID_PB, PASS_ID_REG, PASS_ID_RESERVED };

enum {	REINIT_SYS=1, SYNC_FLASH_PARAMETER=2};
enum {TYPE_BYTE, TYPE_WORD, TYPE_DWORD, TYPE_STR, TYPE_BIN};

enum {SET_IE_FLAG_BEACON=1, SET_IE_FLAG_PROBE_RSP=2, SET_IE_FLAG_PROBE_REQ=3,
		SET_IE_FLAG_ASSOC_RSP=4, SET_IE_FLAG_ASSOC_REQ=5};
enum {CONFIG_ERR_NO_ERR=0, CONFIG_ERR_OOB_INTERFACE_READ_ERR=1,
		CONFIG_ERR_DECRYPTION_CRC_ERR=2, CONFIG_ERR_2_4_CH_NOT_SUPPORTED=3,
		CONFIG_ERR_5_0_CH_NOT_SUPPORTED=4, CONFIG_ERR_SIGNAL_TOO_WEAK=5,
		CONFIG_ERR_NET_AUTH_FAIL=6, CONFIG_ERR_NET_ASSOC_FAIL=7,
		CONFIG_ERR_NO_DHCP_RESPONSE=8, CONFIG_ERR_FAIL_DHCP_CONFIG=9,
		CONFIG_ERR_IP_ADDR_CONFLICT=10, CONFIG_ERR_CANNOT_CONNECT_TO_REG=11,
		CONFIG_ERR_MUL_PBC_DETECTED=12, CONFIG_ERR_ROGUE_ACT_SUSPECTED=13,
		CONFIG_ERR_DEV_BUSY=14, CONFIG_ERR_SETUP_LOCKED=15,
		CONFIG_ERR_MESSAGE_TIMEOUT=16, CONFIG_ERR_REG_SESSION_TIMEOUT=17,
		CONFIG_ERR_DEV_PASS_AUTH_FAIL=18};
#ifndef _WPS_DEF_H_
enum { WEP_DISABLED=0, WEP64=1, WEP128=2 };
enum { KEY_ASCII=0, KEY_HEX=1 };
#endif

#ifdef CONFIG_RTL865X_KLD
enum { PROTOCOL_START=99, PROTOCOL_PBC_OVERLAPPING=11,
		PROTOCOL_TIMEOUT=15, PROTOCOL_SUCCESS=9, SESSION_ABORT=10, 		
		PROTOCOL_MISMATCH_H1=16, PROTOCOL_MISMATCH_H2=17,
		PROTOCOL_S0=0, PROTOCOL_S1=1, PROTOCOL_S2=2, PROTOCOL_S3=3,
		PROTOCOL_S4=4, PROTOCOL_S5=5, PROTOCOL_S6=6, PROTOCOL_S7=7,
		PROTOCOL_S8=8,
		};
//#elif defined(DET_WPS_SPEC)
/*
enum {  PROTOCOL_START=0	, 
		PROTOCOL_PBC_OVERLAPPING=1	,
		PROTOCOL_TIMEOUT=2, 		
		PROTOCOL_SM2=4	,		
		PROTOCOL_SM7=5	,
		PROTOCOL_PIN_NUM_ERR=6	,
		PROTOCOL_SUCCESS=7  
	 };
	//    4: start authentication phase (i.e. M2 starts)
	//    5: start sending wireless configurations phase (i.e. M7 starts)"	
//#elif defined(CONFIG_IWPRIV_INTF)
*/
#else
#ifndef _WPS_DEF_H_
enum {  NOT_USED=-1, 
		PROTOCOL_START=0, PROTOCOL_PBC_OVERLAPPING=1,
		PROTOCOL_TIMEOUT=2, PROTOCOL_SUCCESS=3 ,

		SEND_EAPOL_START=4, RECV_EAPOL_START=5, SEND_EAP_IDREQ=6, RECV_EAP_IDRSP=7, 
        SEND_EAP_START=8, SEND_M1=9, RECV_M1=10, SEND_M2=11, 

        RECV_M2=12, RECV_M2D=13, SEND_M3=14, RECV_M3=15,
        SEND_M4=16, RECV_M4=17, SEND_M5=18, RECV_M5=19,

        SEND_M6=20, RECV_M6=21, SEND_M7=22, RECV_M7=23,
        SEND_M8=24, RECV_M8=25, PROC_EAP_ACK=26, WSC_EAP_FAIL=27,

        HASH_FAIL=28, HMAC_FAIL=29, PWD_AUTH_FAIL=30, PROTOCOL_PIN_NUM_ERR=31,
        PROC_EAP_DONE=32,SEND_PROTOCOL_ERR=33,PROC_PROTOCOL_ERR=34,SEND_PROTOCOL_NACK=35,PROC_PROTOCOL_NACK=36,
}; 
//#else
//enum { PROTOCOL_START=0, PROTOCOL_PBC_OVERLAPPING=1,
//		PROTOCOL_TIMEOUT=2, PROTOCOL_SUCCESS=3 };
#endif
#endif

#ifndef _WPS_DEF_H_
#define WSC_WPA_TKIP		1
#define WSC_WPA_AES			2
#define WSC_WPA2_TKIP		4
#define WSC_WPA2_AES		8
#endif

enum { wsc_mode, wsc_upnp, wsc_config_methods, wsc_auth_type, 
        wsc_encrypt, wsc_connection_type, wsc_manual, wsc_key,
        wsc_ssid, wsc_pin_code, wsc_rf_band, wsc_device_name
};

struct eap_rr_t {
	unsigned char type;	// The bytes after this are the data corresponding to the RR type
}__PACK__;

struct eap_wsc_t {
	unsigned char type;
	unsigned char vendor_id[3];
	unsigned long vendor_type;
	unsigned char op_code;
	unsigned char flags;
}__PACK__;

struct eap_t {
	unsigned char code;		// Identifies the type of EAP packet.
	unsigned char identifier;	// Aids in matching responses with requests.
	unsigned short length; 	// Length of EAP packet including code, id, len, data fields
}__PACK__;

struct eapol_t {
	unsigned char protocol_version;
	unsigned char packet_type;			// This makes it odd in number !
	unsigned short packet_body_length;
}__PACK__;

struct ethernet_t {
	unsigned char  ether_dhost[ETHER_ADDRLEN];    /* destination ethernet address */
	unsigned char  ether_shost[ETHER_ADDRLEN];    /* source ethernet address */
	unsigned short ether_type;                    /* packet type ID */
}__PACK__;
struct wsc_parms_t {
        unsigned char name[21];        //limit to 20-char
        unsigned char value[33];        //32 bytes base on SSID leangth
};

typedef struct _DOT11_WSC_ASSOC_IND{
        unsigned char   EventId;
        unsigned char   IsMoreEvent;
        unsigned char   MACAddr[ETHER_ADDRLEN];
        unsigned short  AssocIELen;
        unsigned char   AssocIE[PROBEIELEN];
	 	unsigned char 	wscIE_included;
}DOT11_WSC_ASSOC_IND;

typedef struct _DOT11_PROBE_REQUEST_IND{
        unsigned char   EventId;
        unsigned char   IsMoreEvent;
        unsigned char   MACAddr[6];
        unsigned short  ProbeIELen;
        unsigned char   ProbeIE[PROBEIELEN];
}DOT11_PROBE_REQUEST_IND;

typedef struct _DOT11_EAP_PACKET{
	unsigned char	EventId;
	unsigned char	IsMoreEvent;
	unsigned short  packet_len;
	unsigned char	packet[1550];
} DOT11_EAP_PACKET;

typedef struct _DOT11_WSC_PIN_IND{
	unsigned char	EventId;
	unsigned char	IsMoreEvent;
	char	code[256];
} DOT11_WSC_PIN_IND;
typedef struct _DOT11_WSC_IND{
	unsigned char EventId;
	unsigned char IsMoreEvent;
	unsigned int value;
} DOT11_WSC_IND;

/*	need sync with 8192cd_p2p.h	 P2P_SUPPORT*/
typedef struct _DOT11_P2P_INDICATE_WSC{
        unsigned char   EventId;
        unsigned char   IsMoreEvent;

		unsigned char 	modeSwitch ;
		char 	network_key[65] ;	
		char 	gossid[33] ;

		unsigned char 	trigger_method ;				
		unsigned char 	whosPINuse ;		
		char 	PINCode[9] ;		
		unsigned char 	requestor;		
		char 	interfacename[16];		        
}DOT11_P2P_INDICATE_WSC;

typedef struct _DOT11_SET_WSCIE {
	unsigned char EventId;
	unsigned char IsMoreEvent;
	unsigned short Flag;
	unsigned short RSNIELen;
	unsigned char  RSNIE[MAX_WSC_IE_LEN];
	unsigned char  MACAddr[MACADDRLEN];	
}DOT11_SET_WSCIE;

/* define at wlan driver
typedef struct _DOT11_SET_RSNIE{
        unsigned char   EventId;
        unsigned char   IsMoreEvent;
		unsigned short	Flag;
        unsigned short  RSNIELen;
        char            RSNIE[MAXRSNIELEN];
		char            MACAddr[MACADDRLEN];
}DOT11_SET_RSNIE;
*/



typedef struct _DOT11_DISCONNECT_REQ{
        unsigned char   EventId;
        unsigned char   IsMoreEvent;
        unsigned short  Reason;
        char            MACAddr[ETHER_ADDRLEN];
}DOT11_DISCONNECT_REQ;

#ifdef WSC_CLIENT_MODE
#define	WIFI_WPS		0x01000000

#ifndef _WPS_DEF_H_
typedef enum { BAND_11B=1, BAND_11G=2, BAND_11BG=3, BAND_11A=4, BAND_11N=8 } BAND_TYPE_T;
#endif

typedef enum _Capability {
    cESS 		= 0x01,
    cIBSS		= 0x02,
    cPollable		= 0x04,
    cPollReq		= 0x01,
    cPrivacy		= 0x10,
    cShortPreamble	= 0x20,
} Capability;

typedef enum _Synchronization_Sta_State{
    STATE_Min		= 0,
    STATE_No_Bss	= 1,
    STATE_Bss		= 2,
    STATE_Ibss_Active	= 3,
    STATE_Ibss_Idle	= 4,
    STATE_Act_Receive	= 5,
    STATE_Pas_Listen	= 6,
    STATE_Act_Listen	= 7,
    STATE_Join_Wait_Beacon = 8,
    STATE_Max		= 9
} Synchronization_Sta_State;

typedef struct _OCTET_STRING {
    unsigned char *Octet;
    unsigned short Length;
} OCTET_STRING;

typedef enum _BssType {
    infrastructure = 1,
    independent = 2,
} BssType;

typedef	struct _IbssParms {
    unsigned short	atimWin;
} IbssParms;

typedef struct _bss_info {
    unsigned char state;
    unsigned char channel;
    unsigned char txRate;
    unsigned char bssid[6];
    unsigned char rssi, sq;	// RSSI  and signal strength
    unsigned char ssid[WSC_MAX_SSID_LEN+1];
} bss_info;


/*!!!!!!!!!!!!!!need  sync with wlan driver ieee80211.h
struct bss_desc {
	unsigned char	bssid[MACADDRLEN];
	unsigned char	ssid[32];
	unsigned char	*ssidptr;			// unused, for backward compatible
	unsigned short	ssidlen;
	unsigned char	meshid[MESH_ID_LEN];
	unsigned char	*meshidptr;			// unused, for backward compatible
	unsigned short	meshidlen;
	unsigned int	bsstype;
	unsigned short	beacon_prd;
	unsigned char	dtim_prd;
	unsigned int	t_stamp[2];
	struct ibss_priv	ibss_par;
	unsigned short	capability;
	unsigned char	channel;
	unsigned int	basicrate;
	unsigned int	supportrate;
	unsigned char	bdsa[MACADDRLEN];
	unsigned char	rssi;
	unsigned char	sq;
	unsigned char	network;
};
*/
typedef struct _BssDscr {
    unsigned char bdBssId[6];
    char bdSsIdBuf[WSC_MAX_SSID_LEN];
    OCTET_STRING  bdSsId;
//Do not use define flag in this structure, it will cause mismatch with wlan driver!
	unsigned char meshid[32]; 
	unsigned char *meshidptr; // unused, for backward compatible 
	unsigned short meshidlen; 	

    BssType bdType;
    unsigned short bdBcnPer;			// beacon period in Time Units
    unsigned char bdDtimPer;			// DTIM period in beacon periods
    unsigned long bdTstamp[2];			// 8 Octets from ProbeRsp/Beacon
    IbssParms bdIbssParms;				// empty if infrastructure BSS
    unsigned short bdCap;				// capability information
    unsigned char ChannelNumber;		// channel number
    unsigned long bdBrates;
    unsigned long bdSupportRates;		
    unsigned char bdsa[6];			// SA address
    unsigned char rssi, sq;			// RSSI and signal strength
    unsigned char network;			//BAND_11B=1, BAND_11G=2, BAND_11BG=3, BAND_11A=4, BAND_11N=8
	/* P2P_SUPPORT */
	unsigned char	p2pdevname[33];		
	unsigned char	p2prole;	
	unsigned short	p2pwscconfig;		
	unsigned char	p2paddress[MACADDRLEN];	    	
    /* multi-stage 2.3.0 */
    unsigned char	stage;	    
    
} BssDscr, *pBssDscr;

typedef struct _sitesurvey_status {
    unsigned char number;
    unsigned char pad[3];
    BssDscr bssdb[MAX_BSS_DESC];
} SS_STATUS_T, *SS_STATUS_Tp;

#if 0   // replaced by following ; for sync with wlan driver
struct wps_ie_info {
	unsigned char rssi;
	unsigned char data[MAX_WSC_IE_LEN];	
};
#endif
struct wps_ie_info {
	unsigned char rssi;
    unsigned int wps_ie_len;
	unsigned char data[MAX_WSC_IE_LEN];
    char ssid[33];
};

typedef struct _sitesurvey_ie {
    unsigned char number;
    unsigned char pad[3];
    struct wps_ie_info ie[MAX_BSS_DESC];
} SS_IE_T, *SS_IE_Tp;

#endif // WSC_CLIENT_MODE


#define EAP_FRAMENT_LEN 1024

#define COMEFROM5G 5
#define COMEFROM24G 2
#define COMEFROM524G 7

#define COME_FROM_WLAN0 1
#define COME_FROM_WLAN1 2

typedef struct sta_ctx 
{

	int used;
#ifdef SUPPORT_UPNP
	char ip_addr[IP_ADDRLEN];
	unsigned char setip;
	time_t time_stamp;
#endif
	int locked;
	int state;
	unsigned char eap_reqid;
#ifdef WPS2DOTX
	/*process EAP reassembly*/ 
	int total_message_len;
	int each_message_len;
	int frag_state;
	unsigned char ReassemblyData[EAP_FRAMENT_LEN]; 
	
	/*process EAP frag*/ 
	//int wait_frag_act;
	int sendToSta_MegTotalSize ;
	int RetVal;
#endif	
	/* for delay send eap-fail when ER > 1 ;search related code by 20101102 */	
	int ER_RspM2D_delaytime;
	unsigned char addr[ETHER_ADDRLEN];
	unsigned char msg_addr[ETHER_ADDRLEN]; // for Intel SDK
	unsigned char uuid[UUID_LEN];
	int tx_size;
	unsigned char tx_buffer[TX_BUFFER_SIZE];	
	int reg_timeout;
	//	int timeout;
	int tx_timeout;
	int retry;
	int config_method;
	int device_password_id;
	DH *dh_enrollee;
	DH *dh_registrar;	
	unsigned char dh_shared_key[PUBLIC_KEY_LEN];
	unsigned char dh_digest_key[BYTE_LEN_256B];	
	unsigned char auth_key[BYTE_LEN_256B];	
	unsigned char key_wrap_key[BYTE_LEN_128B];	
	unsigned char EMSK[BYTE_LEN_256B];		
	unsigned char nonce_enrollee[NONCE_LEN];
	unsigned char nonce_registrar[NONCE_LEN];		
	unsigned char r_s1[NONCE_LEN];
	unsigned char r_s2[NONCE_LEN];
	unsigned char e_s1[NONCE_LEN];
	unsigned char e_s2[NONCE_LEN];
	unsigned char r_h1[BYTE_LEN_256B];
	unsigned char r_h2[BYTE_LEN_256B];
	unsigned char e_h1[BYTE_LEN_256B];
	unsigned char e_h2[BYTE_LEN_256B];
	unsigned char last_tx_msg_buffer[TX_BUFFER_SIZE*2];	
	int last_tx_msg_size;
	unsigned char *last_rx_msg;
	int last_rx_msg_size;	
	int auth_type_flags;	
	int encrypt_type_flags;
	unsigned char Assoc_wscIE_included;
	unsigned char invoke_security_gen;
#ifdef BLOCKED_ROGUE_STA
	unsigned char blocked;
#endif
	unsigned char ap_role;
#if defined(WSC_CLIENT_MODE) && defined(SUPPORT_REGISTRAR)
	unsigned char config_state;
#endif
	unsigned char do_not_rescan;
	unsigned char allow_reconnect_count;
} STA_CTX, *STA_CTX_Tp;

typedef struct pbc_node_context *pbc_node_ptr;
struct pbc_node_context {
     	time_t time_stamp;
	unsigned char uuid[UUID_LEN];
	unsigned char addr[ETHER_ADDRLEN];
     	pbc_node_ptr next_pbc_sta;
#ifdef OVERLAPPING_BY_BAND		
	unsigned char rf_band;		
	int iface_come_in; 
#endif
};

#ifdef PREVENT_PROBE_DEADLOCK
struct probe_node {
	unsigned char used;
	char ProbeIE[PROBEIELEN];
	int ProbeIELen;
	unsigned char ProbeMACAddr[6];
	time_t time_stamp;
	unsigned char sent;
};
#endif

struct blocked_sta {
	unsigned char used;
	int expired_time;
	unsigned char addr[ETHER_ADDRLEN];
};

#ifdef CONNECT_PROXY_AP

struct blocked_ap {
	unsigned char used;
	unsigned char used_unselected;
	unsigned char addr[ETHER_ADDRLEN];
};

#endif

#pragma pack(push, 4)
typedef struct context 
{
#ifdef __ECOS
	int kill_wsc_upnp;
	cyg_flag_t wsc_upnp_flag;
	cyg_handle_t *wsc_upnp_thread;
#ifdef CONFIG_SDIO_HCI
	wsc_flash_param_cb_func_t	*wsc_flash_param_cb_func;
	wsc_event_cb_func_t	*wsc_event_cb_func;
#endif
#endif

#ifdef BLOCKED_ROGUE_STA
	unsigned char blocked_expired_time;
	struct blocked_sta blocked_sta_list[MAX_BLOCKED_STA_NUM];
#endif

#ifdef CONNECT_PROXY_AP
	struct blocked_ap blocked_ap_list[MAX_BLOCKED_AP_NUM];
	int blocked_unselected_ap;
#endif


	//int wlan_inter_num; // remove 20110328
	int mode_switch;	
#ifdef P2P_SUPPORT

	int p2p_trigger_type;	
	char p2p_peers_ssid[WSC_MAX_SSID_LEN+1];
	char p2p_peers_psk[MAX_NETWORK_KEY_LEN+1];    
#endif

	int wlan0_wsc_disabled;/* FOR_DUAL_BAND  */
	int wlan1_wsc_disabled;/* FOR_DUAL_BAND  */
#ifdef FOR_DUAL_BAND
	int socket2;
	char wlan_interface_name2[40];
	int InterFaceComeIn;
	unsigned char our_addr2[ETHER_ADDRLEN];
    unsigned char prefer_band; /*for used by dual band client mode: 0: 5G, 1: 2G*/
#ifndef __ECOS
	char fifo_name2[50];
#endif
	char SSID2[WSC_MAX_SSID_LEN+1];
	int auth_type2;			
	int auth_type_flash2;	
	int encrypt_type2;		
	int encrypt_type_flash2;
	int mixedmode2;	
	int fifo2;
	
	unsigned char inter0only;
	unsigned char inter1only;
	unsigned char both_band_credential;    
#endif	

	int button_hold_time_for_first_if;
	
	int socket;	
	char wlan_interface_name[40];
#ifndef __ECOS
	char fifo_name[50];
#endif
	unsigned char our_addr[ETHER_ADDRLEN];
	int STAmodeNegoWith;	
	
#ifdef WPS2DOTX
		unsigned char authorized_macs[MAX_AUTHORIZED_MACS][ETHER_ADDRLEN];
		/*for process EAP Fragment*/
		int EAP_frag_threshold;
		//int origeMgsSize;
		struct eapol_t *Feapol;
		struct eap_t *Feap;
		struct eap_wsc_t *Fwsc;

		/*client mode do probeReq WSC_IE Fragment*/
		int probeReq_need_wscIE_frag;
		//int ProbeReq_wscIE_frag_tag;


		/*AP mode do probeRsp WSC_IE Fragment*/		
		int probeRsp_need_wscIE_frag;		
		//int ProbeRsp_wscIE_frag_tag;		

		/*AP mode process Reassembly via WSC_IE Fragment*/
		unsigned char ReassembData[1024];
		int ReassDataLen;
		unsigned char VENDOR_DTAT[50];		
		int extension_tag;
#endif

	unsigned char is_ap;	
	int start;

	
	int mode;
	int upnp;
	int role;
	int original_role; 
	int use_ie;
	int config_state;
	int config_method;
	char SSID[WSC_MAX_SSID_LEN+1];	

	int auth_type;
	int auth_type_flags;	
	int auth_type_flash;
	int encrypt_type;
	int mixedmode;
	int rf_band;	
	
	int encrypt_type_flags;	
	int encrypt_type_flash;
	
	int connect_type;
	int manual_config;
	int pb_pressed;
	int pb_pressed_time;
	int pin_assigned;
	int peer_pin_id;
	int device_category_id;
	int device_sub_category_id;

	int device_password_id;
	int config_err;
	int os_ver;
	int rx_size;
	int lock;

	int tx_timeout;
	int resent_limit;
	int reg_timeout;
	int wait_reinit;
	int pb_timeout;
	int pin_timeout;
	int c_pin_timeout ; 
	int setSelectedRegTimeout;
	int assigned_auth_type;
	int assigned_encrypt_type;
	int wait_reboot;
	int num_sta;
	unsigned int num_ext_registrar;
#ifdef SUPPORT_UPNP	
	int TotalSubscriptions;
#ifndef USE_MINI_UPNP
	struct subscription_info upnp_subscription_info[MAX_SUBSCRIPTION_NUM];
#endif	
	char lan_interface_name[40];
	char SetSelectedRegistrar_ip[IP_ADDRLEN];
	unsigned char status_changed;
	unsigned char upnp_wait_reboot_timeout;
	STA_CTX cached_sta;
	unsigned char ERisDTM;
#ifdef USE_MINI_UPNP
	mini_upnp_CTX_T upnp_info;
#endif
#endif

#ifndef __ECOS
#ifdef NO_IWCONTROL
	int wl_chr_fd;
#else
	int	fifo;
#endif
#endif

#ifdef WSC_CLIENT_MODE	
	int join_idx;
	int connect_fail;
	int connect_method;
#ifdef __ECOS
	time_t start_time;
#else
	unsigned long start_time;
#endif
	//int wait_assoc_ind;
	int STAmodeSuccess;
	SS_STATUS_T ss_status;
	SS_IE_T ss_ie;
	STA_CTX_Tp sta_to_clear;
	/* support  Assigned MAC Addr, 2011-0505 */		 	
	unsigned char SPEC_MAC[6];
	char SPEC_SSID[33];	
	/* support  Assigned SSID, 2011-0505 */		

#ifdef FOR_DUAL_BAND	
    int join_band; /*the band of join_idx,  0:wlan0, 1:wlan1*/
    SS_STATUS_T ss_status2;
    SS_IE_T ss_ie2;
#endif
    
#endif

#ifdef MUL_PBC_DETECTTION
	int SessionOverlapTimeout;
	pbc_node_ptr active_pbc_staList;
	unsigned char active_pbc_sta_count;
	WSC_pthread_mutex_t PBCMutex;
	int disable_MulPBC_detection;
	int PBC_overlapping_LED_time_out;
	int WPS_PBC_overlapping_GPIO_number;
#endif

#ifdef PREVENT_PROBE_DEADLOCK
	unsigned int probe_list_count;
	struct probe_node probe_list[MAX_WSC_PROBE_STA];
#endif
		
#ifdef TEST
	int	test;
#endif


	int	debug;
	int debug2;
	char cfg_filename[100];

	char pin_code[PIN_LEN+1];
	char original_pin_code[PIN_LEN+1]; 
	char peer_pin_code[PIN_LEN+1];
#ifndef __ECOS
	char pid_filename[100];
#endif
	unsigned char uuid[UUID_LEN];
	char manufacturer[MAX_MANUFACT_LEN+1];
	char model_name[MAX_MODEL_NAME_LEN+1];
	char model_num[MAX_MODEL_NUM_LEN+1];	
	char serial_num[MAX_SERIAL_NUM_LEN+1];
	char manufacturerURL[MAX_MANUFACT_LEN+1];//Brad add 20080721
	char model_URL[MAX_MANUFACT_LEN+1];//Brad add 20080721
	char manufacturerDesc[MAX_MANUFACT_LEN+1];//Brad add 20090206
	char UPC[13];
	unsigned char device_oui[OUI_LEN];
	char device_name[MAX_DEVICE_NAME_LEN+1];
	unsigned char rx_buffer[RX_BUFFER_SIZE*2];

	/*for support read ssid prefix from config file*/
	char ssid_prefix[WSC_MAX_SSID_LEN+1];
	char network_key[MAX_NETWORK_KEY_LEN+1];
	unsigned char wep_key2[MAX_NETWORK_KEY_LEN+1];
	unsigned char wep_key3[MAX_NETWORK_KEY_LEN+1];
	unsigned char wep_key4[MAX_NETWORK_KEY_LEN+1];	
	unsigned char wep_transmit_key;
	int network_key_len;	
	
	// FOR_DUAL_BAND
#ifdef FOR_DUAL_BAND	
	char network_key2[MAX_NETWORK_KEY_LEN+1];
	unsigned char wep_key22[MAX_NETWORK_KEY_LEN+1];
	unsigned char wep_key32[MAX_NETWORK_KEY_LEN+1];
	unsigned char wep_key42[MAX_NETWORK_KEY_LEN+1];	
	unsigned char wep_transmit_key2;
	int network_key_len2;	
#endif	
	
	unsigned char nonce_enrollee[NONCE_LEN];	
	char assigned_ssid[WSC_MAX_SSID_LEN+1];
	char assigned_network_key[MAX_NETWORK_KEY_LEN+1];
	char assigned_wep_key_1[MAX_WEP_KEY_LEN+1];
	char assigned_wep_key_2[MAX_WEP_KEY_LEN+1];
	char assigned_wep_key_3[MAX_WEP_KEY_LEN+1];
	char assigned_wep_key_4[MAX_WEP_KEY_LEN+1];
	unsigned char assigned_wep_transmit_key;
	unsigned char assigned_wep_key_len;
	unsigned char assigned_wep_key_format;


	int assigned_valid_2;	
	int assigned_auth_type_2;
	int assigned_encrypt_type_2;
	char assigned_ssid_2[WSC_MAX_SSID_LEN+1];
	char assigned_network_key_2[MAX_NETWORK_KEY_LEN+1];
	char assigned_wep_key_1_2[MAX_WEP_KEY_LEN+1];
	char assigned_wep_key_2_2[MAX_WEP_KEY_LEN+1];
	char assigned_wep_key_3_2[MAX_WEP_KEY_LEN+1];
	char assigned_wep_key_4_2[MAX_WEP_KEY_LEN+1];
	unsigned char assigned_wep_transmit_key_2;
	unsigned char assigned_wep_key_len_2;
	unsigned char assigned_wep_key_format_2;
	
	STA_CTX *sta[WSC_MAX_STA_NUM];
	//STA_comeFrom staComeFromList[MAX_STA_NUM];	
	unsigned char registration_on; 
#ifndef __ECOS
	WSC_pthread_mutex_t RegMutex;
#endif
	STA_CTX_Tp sta_invoke_reg;
	int disable_configured_by_exReg;
	int WPS_START_LED_GPIO_number;
	int WPS_END_LED_unconfig_GPIO_number;
	int WPS_END_LED_config_GPIO_number;
	int No_ifname_for_flash_set;

	int LedTimeout;
	int WPS_ERROR_LED_time_out;
	int WPS_ERROR_LED_GPIO_number;
	int WPS_SUCCESS_LED_time_out;
	int WPS_SUCCESS_LED_GPIO_number;

	int daemon; 				// run as daemon
	int disable_disconnect;		// disable disconnect after WPS is done
	int disable_auto_gen_ssid; // disable auto generate SSID		
	int manual_key_type; 		// auto generated encryption type, 0: disable, 1: WPA-TKIP, 2: WPA2-AES, 3: both	
	char manual_key[MAX_NETWORK_KEY_LEN+1];
	int disable_hidden_ap;
	int button_hold_time;
	
#ifdef	AUTO_LOCK_DOWN
	/*at auto_lock_down time PIN will be disabled 
	that is mean "don't accept configurated from external registrar"*/

	int auto_lock_down ; 

#ifdef ALD_BRUTEFORCE_ATTACK_MITIGATION	
	int ADL_pin_attack_count;
	int MaxPinFailThresHold;
#else
	int ald_virgin ;
	time_t ald_timestamp[AUTH_FAIL_TIMES];//ald_authfail_timestamp
	int ald_h;	// head
	int ald_t;	// tail
#endif	
#endif

#if defined(DET_WPS_SPEC) || defined(CONFIG_IWPRIV_INTF) 

	int current_config_mode;
#endif
#if defined(CONFIG_IWPRIV_INTF)
        int start_config_client;
#endif
#if defined(DET_WPS_SPEC)
	char M1DevName[MAX_DEVICE_NAME_LEN+1];
	unsigned char M1MacAddr[6+1];	
	int report_state;
	int button_hold_method;	
#endif
	int fix_wzc_wep; 			// disable/enable the issue for WZC in WEP
	int wps_triggered;			// wps has been triggered	
	int config_by_ext_reg;		// configured by external registrar
	int random_psk_len;			//when manual_key_type=0 use this len as random key len	
	int manauall_random_psk_len;	//when manual_key_type=1~3 , use this len as random key len
#ifdef FULL_SECURITY_CLONE
	unsigned char TagAPConfigStat;
	unsigned char BackupTagAPBSSID[6];
	unsigned char waitReScanMode;	
#endif
	unsigned char ProfileDontBothApply;
#ifdef WSC_CLIENT_MODE
	/*for correctly handle multi-credentials,test plan 5.1.1 ;2012-03-09*/
	char negoApSSID[33];
	unsigned char negoAPConfigStat;
#endif
} CTX_T, *CTX_Tp;

#pragma pack(pop)

#if defined(SUPPORT_UPNP) && !defined(USE_MINI_UPNP)
typedef struct _IPCon {
  char *ifname;
} _IPCon;

typedef struct _IPCon *IPCon;
#endif


/*================================================================*/
// Macro definitions
#ifdef __ECOS
#define DISABLE_HIDDEN_AP(pCtx, tmpbuf) { \
	RunSystemCmd(NULL_FILE, "iwpriv", pCtx->wlan_interface_name, "set_mib", "wsc_enable=4", NULL_STR); \
}

#define RESTORE_HIDDEN_AP(pCtx, tmpbuf) { \
	RunSystemCmd(NULL_FILE, "iwpriv", pCtx->wlan_interface_name, "set_mib", "wsc_enable=5", NULL_STR); \
}
#else
#ifdef INBAND_WPS_OVER_HOST
#define DISABLE_HIDDEN_AP(pCtx, tmpbuf) { \
        	sprintf(tmpbuf,"iwpriv %s set_mib wsc_enable=4", pCtx->wlan_interface_name); \
	        inband_remote_cmd(tmpbuf); \
	}
#define RESTORE_HIDDEN_AP(pCtx, tmpbuf) { \
        	sprintf(tmpbuf,"iwpriv %s set_mib wsc_enable=5", pCtx->wlan_interface_name); \
        	system(tmpbuf); \
	}
#else
#define DISABLE_HIDDEN_AP(pCtx, tmpbuf) { \
	sprintf(tmpbuf,"iwpriv %s set_mib wsc_enable=4", pCtx->wlan_interface_name); \
	system(tmpbuf); \
}

#define RESTORE_HIDDEN_AP(pCtx, tmpbuf) { \
	sprintf(tmpbuf,"iwpriv %s set_mib wsc_enable=5", pCtx->wlan_interface_name); \
	system(tmpbuf); \
}
#endif	//INBAND_WPS_OVER_HOST
#endif  //__ECOS

/*================================================================*/

// exported variables and routines of wsc.c
extern unsigned char WSC_VENDOR_ID[3];
extern unsigned char wsc_prime_num[];
extern int init_wlan(CTX_Tp pCtx, int reinit);
#ifdef AUTO_LOCK_DOWN
extern void InOut_auto_lock_down(CTX_Tp pCtx , int enter);
#endif
#ifdef WSC_CLIENT_MODE
extern int issue_scan_req(CTX_Tp pCtx, int method);
#endif
#ifdef FULL_SECURITY_CLONE

extern void APConfigStateChk(CTX_Tp pCtx);
extern void waitingClonedAP(CTX_Tp pCtx);
#endif

// exported variables and routines of txpkt.c
extern int send_wlan(CTX_Tp pCtx, unsigned char *data, int size);
extern int send_eap_reqid(CTX_Tp pCtx, STA_CTX_Tp pSta);
extern int send_wsc_done(CTX_Tp pCtx, STA_CTX_Tp pSta);
extern int send_wsc_start(CTX_Tp pCtx, STA_CTX_Tp pSta);
extern int send_eap_fail(CTX_Tp pCtx, STA_CTX_Tp pSta);
extern int send_wsc_nack(CTX_Tp pCtx, STA_CTX_Tp pSta, int err_code);
extern int send_wsc_ack(CTX_Tp pCtx, STA_CTX_Tp pSta);
extern int send_wsc_M8(CTX_Tp pCtx, STA_CTX_Tp pSta);
extern int send_wsc_M6(CTX_Tp pCtx, STA_CTX_Tp pSta);
extern int send_wsc_M4(CTX_Tp pCtx, STA_CTX_Tp pSta);
extern int send_wsc_M2(CTX_Tp pCtx, STA_CTX_Tp pSta);
#ifdef SUPPORT_ENROLLEE
extern int send_wsc_M7(CTX_Tp pCtx, STA_CTX_Tp pSta);
extern int send_wsc_M5(CTX_Tp pCtx, STA_CTX_Tp pSta);
extern int send_wsc_M3(CTX_Tp pCtx, STA_CTX_Tp pSta);
extern int send_wsc_M1(CTX_Tp pCtx, STA_CTX_Tp pSta);
extern int send_eap_rspid(CTX_Tp pCtx, STA_CTX_Tp pSta);
extern int send_eapol_start(CTX_Tp pCtx, STA_CTX_Tp pSta);
#endif
#ifdef SUPPORT_UPNP
extern int send_upnp_to_wlan(CTX_Tp pCtx, STA_CTX_Tp pSta, struct WSC_packet *packet);
#endif

#ifdef WPS2DOTX
extern int send_frag_msg(CTX_Tp pCtx, STA_CTX_Tp pSta ,  int NextStat , int times );

extern int send_wsc_frag_ack(CTX_Tp pCtx, STA_CTX_Tp pSta);
#endif

// exported variables and routines of rxpkt.c
#ifdef SUPPORT_ENROLLEE
int pktHandler_reqid(CTX_Tp pCtx, STA_CTX_Tp pSta, unsigned char id);
int pktHandler_wsc_start(CTX_Tp pCtx, STA_CTX_Tp pSta);
#endif
extern int pktHandler_rspid(CTX_Tp pCtx, STA_CTX_Tp pSta, unsigned char *id, int len);
extern int pktHandler_wsc_ack(CTX_Tp pCtx, STA_CTX_Tp pSta, struct eap_wsc_t *wsc);
extern int pktHandler_wsc_nack(CTX_Tp pCtx, STA_CTX_Tp pSta, struct eap_wsc_t *wsc);
extern int pktHandler_wsc_done(CTX_Tp pCtx, STA_CTX_Tp pSta);
extern int pktHandler_eap_fail(CTX_Tp pCtx, STA_CTX_Tp pSta);
extern int pktHandler_wsc_msg(CTX_Tp pCtx, STA_CTX_Tp pSta, struct eap_wsc_t * wsc, int len);
#ifdef SUPPORT_UPNP
extern int pktHandler_upnp_select_msg(CTX_Tp pCtx, STA_CTX_Tp pSta, struct WSC_packet *packet);
#endif


// exported variables and routines of utils.c

#ifdef WPS2DOTX
extern unsigned char WSC_VENDOR_OUI[3];
extern unsigned char BroadCastMac[6];
extern unsigned char WSC_VENDOR_V2[6];
extern unsigned char WSC_VENDOR_V57[6] ;
extern unsigned char EXT_ATTRI_TEST[6] ;

#ifdef __ECOS
extern int interface_down(const char *intf);
extern int interface_up(const char *intf);
#endif

extern void registrar_remove_authorized_mac(CTX_Tp pCtx,const unsigned char *addr);
extern void registrar_remove_all_authorized_mac(CTX_Tp pCtx);
extern void registrar_add_authorized_mac(CTX_Tp pCtx, const  unsigned char *addr);
extern unsigned char *search_VendorExt_tag(unsigned char *data, unsigned char id, int len, int *out_len);
extern int report_authoriedMacCount(CTX_Tp pCtx);
extern int add_v2andAuthTag(CTX_Tp pCtx );
extern void func_off_wlan_acl(CTX_Tp pCtx, unsigned char *interfacename);



#endif
extern CTX_Tp pGlobalCtx;
extern int wlioctl_get_mib(	char *interfacename , char* mibname ,int *result );
#ifdef DEBUG
void wsc_debug_out(char *label, unsigned char *data, int data_length);
#endif
extern void convert_bin_to_str(unsigned char *bin, int len, char *out);
extern unsigned char *add_tlv(unsigned char *data, unsigned short id, int len, void *val);
extern unsigned char *append(unsigned char *src, unsigned char *data, int data_len);
extern int wlioctl_set_led(int flag);
extern int __wlioctl_set_wsc_ie(char *interface, unsigned char *data, int len, int id, int flag);
extern int wlioctl_set_wsc_ie(unsigned char *data, int len, int id, int flag);
extern int wlioctl_get_button_state(int *pState);
extern int derive_key(CTX_Tp pCtx, STA_CTX_Tp pSta);
extern void write_param_to_tmpfile(char *msg);
extern int write_param_to_flash(CTX_Tp pCtx, int is_local);
extern int write_param_to_flash2(CTX_Tp pCtx, int is_local); // 1001
extern int write_param_to_flash_both_band(CTX_Tp pCtx, int is_local, int cred_idx, int intface);
extern void signal_webs(int condition);
extern int get_hidden_mib(CTX_Tp pCtx , char *interfacename);
extern int get_both_band_cred_mib(CTX_Tp pCtx , char *interfacename);
extern void func_off_wlan_tx(CTX_Tp pCtx , char *interfacename);
extern void func_on_wlan_tx(CTX_Tp pCtx , char *interfacename);

extern int validate_pin_code(unsigned long code);
extern DH *generate_dh_parameters(int prime_len, unsigned char *data, int generator);
extern void reset_sta(CTX_Tp pCtx, STA_CTX_Tp pSta, int need_free);
extern void reset_ctx_state(CTX_Tp pCtx);
extern void hmac_sha256(unsigned char *text, int text_len, unsigned char *key, int key_len, unsigned char *digest, int *digest_len);
extern void Encrypt_aes_128_cbc(unsigned char *key, unsigned char *iv, unsigned char *plaintext, unsigned int plainlen, unsigned char *ciphertext, unsigned int *cipherlen);
extern void Decrypt_aes_128_cbc(unsigned char *key,  unsigned char *iv, unsigned char *plaintext, unsigned int *plainlen, unsigned char *ciphertext, unsigned int cipherlen);
extern void wsc_kdf(
	unsigned char *key,                // pointer to authentication key 
	int             key_len,            // length of authentication key 
	unsigned char *text,               // pointer to data stream 
	int	text_len,           // length of data stream 
	int 	expect_key_len,   //expect total key length in bit number
	unsigned char *digest             // caller digest to be filled in 
	);

extern int build_beacon_ie(CTX_Tp pCtx, unsigned char selected, unsigned short passid, \
				unsigned short method, unsigned char *data);
extern int build_probe_rsp_ie(CTX_Tp pCtx, unsigned char selected, unsigned short passid, \
				unsigned short method, unsigned char *data);
extern int build_assoc_response_ie(CTX_Tp pCtx, unsigned char *data);
extern int build_provisioning_service_ie(unsigned char *data);
extern unsigned char *search_tag(unsigned char *data, unsigned short id, int len, int *out_len);
extern int IssueDisconnect(unsigned char *pucMacAddr, unsigned short reason);
#ifdef P2P_SUPPORT
extern int wlioctl_report_ssid_psk(char *interface, char* SSID_in, char* psk_in);
#endif

#ifdef WSC_CLIENT_MODE
extern int wlioctl_scan_reqest(char *interface, int *pStatus);
extern int wlioctl_scan_result(char *interface, SS_STATUS_Tp pStatus);
extern void update_ie_client(CTX_Tp pCtx, unsigned short passid);
extern int getWlJoinRequest(char *interface, pBssDscr pBss, unsigned char *res);
extern int getWlJoinResult(char *interface, unsigned char *res);
#endif

extern void client_set_WlanDriver_WscEnable(const CTX_Tp pCtx, const int wps_enabled);

#ifdef SUPPORT_UPNP
#ifndef USE_MINI_UPNP
extern IPCon IPCon_New(char *ifname);
extern IPCon IPCon_Destroy(IPCon this);
extern struct in_addr *IPCon_GetIpAddr(IPCon this);
extern char *IPCon_GetIpAddrByStr(IPCon this);
#endif
//extern int isUpnpSubscribed(CTX_Tp pCtx);
extern void convert_bin_to_str_UPnP(unsigned char *bin, int len, char *out);
extern void reset_sta_UPnP(CTX_Tp pCtx, STA_CTX_Tp pSta);
#endif
extern void clear_SetSelectedRegistrar_flag(CTX_Tp pCtx);
extern int check_wep_key_format(unsigned char *msg, int msg_len, unsigned char *key_format, unsigned char *key_len, unsigned char *msg_out, int *msg_out_len);
#ifdef MUL_PBC_DETECTTION
extern void search_active_pbc_sta(CTX_Tp pCtx, unsigned char *addr, unsigned char *uuid, unsigned char *pMsg, int msg_len);
#ifdef OVERLAPPING_BY_BAND
int search_active_sta_by_band(CTX_Tp pCtx, int band);
int get_band(CTX_Tp pCtx);
int wlioctl_get_mib_byte(char *interfacename , char* mibname ,unsigned char *result);
#endif
extern void remove_active_pbc_sta(CTX_Tp pCtx, unsigned char* staAddr, unsigned char mode);
extern void SwitchSessionOverlap_LED_On(CTX_Tp pCtx);
#endif // MUL_PBC_DETECTTION
#ifdef BLOCKED_ROGUE_STA
extern unsigned char search_blocked_list(CTX_Tp pCtx, unsigned char *addr);
extern struct blocked_sta *add_into_blocked_list(CTX_Tp pCtx, STA_CTX_Tp pSta);
extern void disassociate_blocked_list(CTX_Tp pCtx);
extern void countdown_blocked_list(CTX_Tp pCtx);
#endif // BLOCKED_ROGUE_STA

#ifdef CONNECT_PROXY_AP
extern unsigned char search_blocked_ap_list(CTX_Tp pCtx, int idx, int selected);
extern void add_into_blocked_ap_list(CTX_Tp pCtx, int idx, int selected);
extern void clear_blocked_ap_list(CTX_Tp pCtx);
#endif 
extern void enable_WPS_LED(void);

extern void report_WPS_STATUS(int status);

#if	defined(CONFIG_RTL865x_KLD_REPEATER) || defined(CONFIG_RTL_REPEATER_WPS_SUPPORT)
extern int isWlanRootConnect(unsigned char *wlanif_name);
#endif

extern int is_zero_ether_addr(const unsigned char *a);
extern int string_to_hex(char *string, unsigned char *key, int len);
#ifdef P2P_SUPPORT
extern int ReportWPSstate(char *interface, unsigned char *res);
#endif

extern unsigned char *check_tag(CTX_Tp pCtx, unsigned char *pMsg, int msg_len, int tag, int check_len, 
	char *name, int type, int *o_len);

#ifdef OUTPUT_LOG
extern 	FILE *outlog_fp; 
extern char StringbufferOut[80];
//extern unsigned char logstring[60];
//extern unsigned char cmdstring[80];
#endif

extern void show_auth_encry_help(void);


#define PIXIE_DUST_ATTACK
//#define DEBUG_PIXIE_DUST_ATTACK

extern unsigned char *generate_random(unsigned char *data, int len);
extern void convert_char_to_str(char *bin, int len, char *out);


#endif // INCLUDE_WSC_H

