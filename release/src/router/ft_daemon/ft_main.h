#ifndef FT_MAIN_H
#define FT_MAIN_H

#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <fcntl.h>
#include <errno.h>
#include <pthread.h>
#include <endian.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <linux/if_packet.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <linux/wireless.h>
//#include <openssl/aes.h>		//turnkey
#ifdef USE_RTK_LIB
#include <libmd5wrapper.h>
#define MD5_CTX		struct MD5Context
#define MD5_Init	MD5Init
#define MD5_Update	MD5Update
#define MD5Final	MD5_Final
#else
//#include "../openssl/include/openssl/aes.h"
//#include <openssl/md5.h>
#endif

#define DEBUG
#define DEBUG_DUMP

#ifdef DEBUG
#define FT_ERROR(fmt, args...)	if(pGlobalCtx && pGlobalCtx->debug_level>=1) printf("\033[0;31mFT-err: "fmt"\033[m", ##args)
#define FT_DEBUG(fmt, args...)	if(pGlobalCtx && pGlobalCtx->debug_level>=2) printf("FT-dbg: "fmt, ##args)
#define FT_DEBUG2(fmt, args...)	if(pGlobalCtx && pGlobalCtx->debug_level>=2) printf(fmt, ##args)
#define FT_TRACE(fmt, args...)	if(pGlobalCtx && pGlobalCtx->debug_level>=3) printf("\033[0;34mFT-trc: "fmt"\033[m", ##args)
#else
#define FT_DEBUG(fmt, args...)
#define FT_ERROR(fmt, args...)
#define FT_TRACE(fmt, args...)
#endif

#define MAC2STR(x) x[0],x[1],x[2],x[3],x[4],x[5]
#define PKTLEN				8192
#define MSGLEN				2000

#define MAX_FILENAME_SIZE		30
#define MAX_WLAN_INF_NUM		10

#ifdef __GNUC__
#define PRINTF_FORMAT(a,b) __attribute__ ((format (printf, (a), (b))))
#define STRUCT_PACKED __attribute__ ((packed))
#define __WLAN_ATTRIB_PACK__ __attribute__ ((packed))
#else
#define PRINTF_FORMAT(a,b)
#define STRUCT_PACKED
#define __WLAN_ATTRIB_PACK__
#endif

// default parameters
#define DEF_ETH_INTF_NAME		"br0"
#define DEF_WLAN_INTF_NAME		"wl0"
//#define DEF_WLAN_INTF_NAME		"wlan0"
#define DEF_PID_FILENAME		"/var/run/ft.pid"
#define DEF_CONFIG_FILENAME		"/etc/ft.conf"

#define ETH_P_RRB				0x890D

typedef unsigned int u32;
typedef unsigned short u16;
typedef unsigned char u8;

struct l2_ethhdr {
	u8 h_dest[ETH_ALEN];
	u8 h_source[ETH_ALEN];
	u16 h_proto;
} STRUCT_PACKED;

struct ft_rrb_frame {
	u8 frame_type; /* RSN_REMOTE_FRAME_TYPE_FT_RRB */
	u8 packet_type; /* FT_PACKET_REQUEST/FT_PACKET_RESPONSE */
	u16 action_length; /* little endian length of action_frame */
	u8 ap_address[ETH_ALEN];
	/*
	 * Followed by action_length bytes of FT Action frame (from Category
	 * field to the end of Action Frame body.
	 */
} STRUCT_PACKED;

struct ft_action_frame {
	u8 category; /* 6: Fast BSS Transition */
	u8 ft_action; /* 1: FT Request, 2: FT Response, 3: FT Confirm, 4: FT Ack */
	u8 sta_address[ETH_ALEN]; /* FTO's MAC address */
	u8 target_ap_address[ETH_ALEN]; /* BSSID of target AP */
	/*
	 * FT Request/Response/Confirm/Ack frame body
	 */
} STRUCT_PACKED;

//+++++++++++++++++++
#if defined(__LP32__)
#define MD5_LONG unsigned long
#elif defined(OPENSSL_SYS_CRAY) || defined(__ILP64__)
#define MD5_LONG unsigned long
#define MD5_LONG_LOG2 3
/*
 * _CRAY note. I could declare short, but I have no idea what impact
 * does it have on performance on none-T3E machines. I could declare
 * int, but at least on C90 sizeof(int) can be chosen at compile time.
 * So I've chosen long...
 *					<appro@fy.chalmers.se>
 */
#else
#define MD5_LONG unsigned int
#endif

#define MD5_CBLOCK	64
#define MD5_LBLOCK	(MD5_CBLOCK/4)
#define AES_MAXNR 14

struct aes_key_st {
#ifdef AES_LONG
    unsigned long rd_key[4 *(AES_MAXNR + 1)];
#else
    unsigned int rd_key[4 *(AES_MAXNR + 1)];
#endif
    int rounds;
};
typedef struct aes_key_st AES_KEY;

typedef struct MD5state_st
{
	unsigned long A,B,C,D;
	MD5_LONG Nl,Nh;
	MD5_LONG data[MD5_LBLOCK];
	unsigned int num;
} MD5_CTX;
//-------------------------

/* IEEE 802.11i */
#define PMKID_LEN 16
#define PMK_LEN 32
#define WPA_REPLAY_COUNTER_LEN 8
#define WPA_NONCE_LEN 32
#define WPA_KEY_RSC_LEN 8
#define WPA_GMK_LEN 32
#define WPA_GTK_MAX_LEN 32

/* IEEE 802.11r */
#define MOBILITY_DOMAIN_ID_LEN 2
#define FT_R0KH_ID_MAX_LEN 48
#define FT_R1KH_ID_LEN 6
#define WPA_PMK_NAME_LEN 16

#define RSN_REMOTE_FRAME_TYPE_FT_RRB 1

#define FT_PACKET_REQUEST 0
#define FT_PACKET_RESPONSE 1

/* Vendor-specific types */
#define FT_PACKET_INFORM         100
#define FT_PACKET_R0KH_R1KH_PULL 200
#define FT_PACKET_R0KH_R1KH_RESP 201
#define FT_PACKET_R0KH_R1KH_PUSH 202

#define FT_R0KH_R1KH_PULL_DATA_LEN 44
#define FT_R0KH_R1KH_RESP_DATA_LEN 76
#define FT_R0KH_R1KH_PUSH_DATA_LEN 88
#define FT_R0KH_R1KH_PULL_NONCE_LEN 16
#define FT_INFORM_DATA_LEN 11

#define FT_KH_ADD 1
#define FT_KH_DEL 2
typedef struct ft_remote_r0kh {
	struct ft_remote_r0kh *next;
	u8 addr[ETH_ALEN];
	u8 id[FT_R0KH_ID_MAX_LEN];
	size_t id_len;
	u8 key[16];
	u8 intf[IFNAMSIZ+1];
} R0KH_T, *R0KH_Tp;

typedef struct ft_remote_r1kh {
	struct ft_remote_r1kh *next;
	u8 addr[ETH_ALEN];
	u8 id[FT_R1KH_ID_LEN];
	u8 key[16];
	u8 intf[IFNAMSIZ+1];
} R1KH_T, *R1KH_Tp;

struct ft_r0kh_r1kh_pull_frame {
	u8 frame_type; /* RSN_REMOTE_FRAME_TYPE_FT_RRB */
	u8 packet_type; /* FT_PACKET_R0KH_R1KH_PULL */
	u16 data_length; /* little endian length of data (44) */
	u8 ap_address[ETH_ALEN];

	u8 nonce[FT_R0KH_R1KH_PULL_NONCE_LEN];
	u8 pmk_r0_name[WPA_PMK_NAME_LEN];
	u8 r1kh_id[FT_R1KH_ID_LEN];
	u8 s1kh_id[ETH_ALEN];
	u8 pad[4]; /* 8-octet boundary for AES key wrap */
	u8 key_wrap_extra[8];
} STRUCT_PACKED;

struct ft_r0kh_r1kh_resp_frame {
	u8 frame_type; /* RSN_REMOTE_FRAME_TYPE_FT_RRB */
	u8 packet_type; /* FT_PACKET_R0KH_R1KH_RESP */
	u16 data_length; /* little endian length of data (76) */
	u8 ap_address[ETH_ALEN];

	u8 nonce[FT_R0KH_R1KH_PULL_NONCE_LEN]; /* copied from pull */
	u8 r1kh_id[FT_R1KH_ID_LEN]; /* copied from pull */
	u8 s1kh_id[ETH_ALEN]; /* copied from pull */
	u8 pmk_r1[PMK_LEN];
	u8 pmk_r1_name[WPA_PMK_NAME_LEN];
	u16 pairwise;
	u8 pad[2]; /* 8-octet boundary for AES key wrap */
	u8 key_wrap_extra[8];
} STRUCT_PACKED;

struct ft_r0kh_r1kh_push_frame {
	u8 frame_type; /* RSN_REMOTE_FRAME_TYPE_FT_RRB */
	u8 packet_type; /* FT_PACKET_R0KH_R1KH_PUSH */
	u16 data_length; /* little endian length of data (88) */
	u8 ap_address[ETH_ALEN];

	/* Encrypted with AES key-wrap */
	u8 timestamp[4]; /* current time in seconds since unix epoch, little
			  * endian */
	u8 r1kh_id[FT_R1KH_ID_LEN];
	u8 s1kh_id[ETH_ALEN];
	u8 pmk_r0_name[WPA_PMK_NAME_LEN];
	u8 pmk_r1[PMK_LEN];
	u8 pmk_r1_name[WPA_PMK_NAME_LEN];
	u16 pairwise;
	u8 pad[6]; /* 8-octet boundary for AES key wrap */
	u8 key_wrap_extra[8];
} STRUCT_PACKED;

struct ft_inform_frame {
	u8 frame_type; /* RSN_REMOTE_FRAME_TYPE_FT_RRB */
	u8 packet_type; /* FT_PACKET_INFORM */
	u16 data_length; /* little endian length of data (11) */
	u8 ap_address[ETH_ALEN];

	/* Encrypted with AES key-wrap */
	u32 timestamp; /* current time in seconds since unix epoch, little endian */
	u8 inform_type; /* 1:ROAMING, 2:KEY_EXPIRE */
	u8 addr[ETH_ALEN];
	u8 pad[5]; /* 8-octet boundary for AES key wrap */
	u8 key_wrap_extra[8];
} STRUCT_PACKED;

typedef struct context {
	/* eth */
	int				socket;
	char			eth_intf_name[IFNAMSIZ+1];
	int				eth_intf_index;
	unsigned char	own_addr[ETH_ALEN];
	/* wlan */
	int				wlan_socket;
	char			wlan_intf_name[MAX_WLAN_INF_NUM][IFNAMSIZ+1];
	unsigned char	wlan_intf_addr[MAX_WLAN_INF_NUM][ETH_ALEN];
	int				wlan_intf_num;
	/* pid */
	char			pid_filename[MAX_FILENAME_SIZE+1];
	pthread_mutex_t RegMutex;
	/* kh */
	R0KH_Tp			r0kh_list;
	R1KH_Tp			r1kh_list;
	char			config_filename[MAX_FILENAME_SIZE+1];
	/* other */
	int				debug_level;
} CTX_T, *CTX_Tp;

// driver define
#define MACADDRLEN			6
#define MAX_R0KHID_LEN		48
#define FT_PMKID_LEN		16
#define FT_PMK_LEN			32
#define MAXDATALEN			1560
#define MAX_FTACTION_LEN	MAXDATALEN - 20

#define SIOCGIWRTLGETMIB	0x89f2
#define SIOCSIWRTLSETFTPID	0x8BF7
#define SIOCGIFTGETEVENT	0x8BE8
#define SIOCGIFTGETKEY		0x8BE9
#define SIOCSIFTSETKEY		0x8BEA
#define SIOCSIFTINFORM		0x8BEB
#define SIOCSIFTACTION		0x8BEC

typedef enum{
	DOT11_EVENT_NO_EVENT			= 1,
	DOT11_EVENT_FT_GET_EVENT		= 125,
	DOT11_EVENT_FT_IMD_ASSOC_IND	= 126,
	DOT11_EVENT_FT_GET_KEY			= 127,
	DOT11_EVENT_FT_SET_KEY			= 128,
	DOT11_EVENT_FT_PULL_KEY_IND		= 129,
	DOT11_EVENT_FT_ASSOC_IND		= 130,
	DOT11_EVENT_FT_KEY_EXPIRE_IND	= 131,
	DOT11_EVENT_FT_ACTION_IND		= 132,
	DOT11_EVENT_UNKNOWN
} DOT11_EVENT;

typedef struct _DOT11_FT_IMD_ASSOC_IND{
	unsigned char EventId;
	unsigned char IsMoreEvent;
	unsigned char MACAddr[MACADDRLEN];
} __WLAN_ATTRIB_PACK__ DOT11_FT_IMD_ASSOC_IND;

typedef struct _DOT11_FT_PULL_KEY_IND{
	unsigned char EventId;
	unsigned char IsMoreEvent;
	unsigned char Type;
	unsigned char r0kh_id[MAX_R0KHID_LEN];
	unsigned int Length;
	unsigned char nonce[FT_R0KH_R1KH_PULL_NONCE_LEN];
	unsigned char pmk_r0_name[FT_PMKID_LEN];
	unsigned char r1kh_id[MACADDRLEN];
	unsigned char s1kh_id[MACADDRLEN];
} __WLAN_ATTRIB_PACK__ DOT11_FT_PULL_KEY_IND;

enum _FTKEY_TYPE{
	FTKEY_TYPE_PUSH		= 1,
	FTKEY_TYPE_PULL		= 2,
};

typedef struct _DOT11_FT_GET_KEY{
	unsigned char EventId;
	unsigned char IsMoreEvent;
	unsigned char Type;
	unsigned int Length;
	unsigned char r1kh_id[MACADDRLEN];
	unsigned char s1kh_id[MACADDRLEN];
} __WLAN_ATTRIB_PACK__ DOT11_FT_GET_KEY;

typedef struct _DOT11_FT_GET_KEY_PUSH{
	unsigned char EventId;
	unsigned char IsMoreEvent;
	unsigned char Type;
	unsigned int Length;
	unsigned int timestamp;
	unsigned char r1kh_id[MACADDRLEN];
	unsigned char s1kh_id[MACADDRLEN];
	unsigned char pmk_r0_name[FT_PMKID_LEN];
	unsigned char pmk_r1[FT_PMK_LEN];
	unsigned char pmk_r1_name[FT_PMKID_LEN];
	unsigned short pairwise;
} __WLAN_ATTRIB_PACK__ DOT11_FT_GET_KEY_PUSH;

typedef struct _DOT11_FT_GET_KEY_PULL{
	unsigned char EventId;
	unsigned char IsMoreEvent;
	unsigned char Type;
	unsigned int Length;
	unsigned char nonce[FT_R0KH_R1KH_PULL_NONCE_LEN];
	unsigned char r1kh_id[MACADDRLEN];
	unsigned char s1kh_id[MACADDRLEN];
	unsigned char pmk_r1[FT_PMK_LEN];
	unsigned char pmk_r1_name[FT_PMKID_LEN];
	unsigned short pairwise;
} __WLAN_ATTRIB_PACK__ DOT11_FT_GET_KEY_PULL;

typedef struct _DOT11_FT_SET_KEY_PUSH{
	unsigned char EventId;
	unsigned char IsMoreEvent;
	unsigned char Type;
	unsigned int Length;
	unsigned int timestamp;
	unsigned char r1kh_id[MACADDRLEN];
	unsigned char s1kh_id[MACADDRLEN];
	unsigned char pmk_r0_name[FT_PMKID_LEN];
	unsigned char pmk_r1[FT_PMK_LEN];
	unsigned char pmk_r1_name[FT_PMKID_LEN];
	unsigned short pairwise;
} __WLAN_ATTRIB_PACK__ DOT11_FT_SET_KEY_PUSH;

typedef struct _DOT11_FT_SET_KEY_PULL{
	unsigned char EventId;
	unsigned char IsMoreEvent;
	unsigned char Type;
	unsigned int Length;
	unsigned char nonce[FT_R0KH_R1KH_PULL_NONCE_LEN];
	unsigned char r1kh_id[MACADDRLEN];
	unsigned char s1kh_id[MACADDRLEN];
	unsigned char pmk_r1[FT_PMK_LEN];
	unsigned char pmk_r1_name[FT_PMKID_LEN];
	unsigned short pairwise;
} __WLAN_ATTRIB_PACK__ DOT11_FT_SET_KEY_PULL;

typedef struct _DOT11_FT_ASSOC_IND{
	unsigned char EventId;
	unsigned char IsMoreEvent;
	unsigned char MACAddr[MACADDRLEN];
} __WLAN_ATTRIB_PACK__ DOT11_FT_ASSOC_IND;

typedef struct _DOT11_FT_KEY_EXPIRE_IND{
	unsigned char EventId;
	unsigned char IsMoreEvent;
	unsigned char MACAddr[MACADDRLEN];
} __WLAN_ATTRIB_PACK__ DOT11_FT_KEY_EXPIRE_IND;

typedef struct _DOT11_FT_ACTION{
	unsigned char EventId;
	unsigned char IsMoreEvent;
	unsigned char MACAddr[MACADDRLEN];
	unsigned char ActionCode;
	unsigned int packet_len;
	unsigned char packet[MAX_FTACTION_LEN];
} __WLAN_ATTRIB_PACK__ DOT11_FT_ACTION;

enum _INFORM_TYPE {
	INFORM_TYPE_ROAMING		= 1,
	INFORM_TYPE_KEY_EXPIRE	= 2
};

#endif /* FT_MAIN_H */
