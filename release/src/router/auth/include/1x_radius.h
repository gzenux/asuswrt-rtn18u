
//--------------------------------------------------
// IEEE 802.1x Implementation
//
// File		: 1x_radius.h
// Programmer	: Arunesh Mishra
//
//  BASIC RADIUS PROXY 
//
//
// Copyright (c) Arunesh Mishra 2002
// All rights reserved.
// Maryland Information and Systems Security Lab
// University of Maryland, College Park.
//
//
//--------------------------------------------------
#ifndef LIB1X_RADIUS_H
#define LIB1X_RADIUS_H

#include <sys/types.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>

#include "1x_nal.h"

#define  LIB1X_ETH_IP	0x0800		/* Internet Protocol packet	*/


#define  LIB1X_RAD_ACCREQ	1	// Access Request
#define  LIB1X_RAD_ACCACT	2	// Access Accept
#define  LIB1X_RAD_ACCREJ	3	// Access Reject
#define  LIB1X_RAD_ACCCHL	11	// Access Challenge
#define  LIB1X_RAD_ACCTREQ	4	// Account Request
#define  LIB1X_RAD_ACCTRSP	5	// Account Respond
/*HS2 SUPPORT*/
#define  LIB1X_RAD_DISCONNECT_REQ	40	// Disconnect Request
#define  LIB1X_RAD_DISCONNECT_ACK	41	// Disconnect ACK
#define  LIB1X_RAD_DISCONNECT_NACK	42	// Disconnect NACK

#define  LIB1X_RAD_COA_REQ	43	// COA (Change-of-Authorization) Request
#define  LIB1X_RAD_COA_ACK	44	// COA ACK
#define  LIB1X_RAD_COA_NACK	45	// COA NACK

/*HS2 SUPPORT*/

#define  LIB1X_LIL_ENDIAN


#define  LIB1X_IPHDRLEN		20 	// Assume for now	 TODO
#define  LIB1X_UDPHDRLEN	8
#define  LIB1X_RADHDRLEN	20	// RADIUS Header length
#define  LIB1X_RADATTRLEN	2	// length of attr field without data part

/* RADIUS attribute definitions. Also from RFC 2138 */
#define LIB1X_RAD_USER_NAME              1
#define LIB1X_RAD_PASSWORD               2
#define LIB1X_RAD_NAS_IP_ADDRESS         4
#define LIB1X_RAD_NAS_PORT	         5
#define LIB1X_RAD_SERVICE_TYPE           6
#define LIB1X_RAD_FRAMED_MTU		 12
#define LIB1X_RAD_REPLY_MESSAGE          18
#define LIB1X_RAD_STATE                  24
#define LIB1X_RAD_VENDOR_SPECIFIC	 26
#define LIB1X_RAD_SESSION_TIMEOUT        27
#define LIB1X_RAD_IDLE_TIMEOUT		 28
#define LIB1X_RAD_CALLED_STID		 30
#define LIB1X_RAD_CALLING_STID		 31
#define LIB1X_RAD_NAS_IDENTIFIER         32
#define LIB1X_RAD_NAS_PORTTYPE		 61
#define LIB1X_RAD_CONNECTINFO		 77
#define LIB1X_RAD_EAP_MESSAGE		 79 	// eap message .. from RFC 2869
#define LIB1X_RAD_MESS_AUTH		 80	// Message Authenticator
//Accounting related
#define	LIB1X_RAD_ACCT_STATUS_TYPE	 40
#define	LIB1X_RAD_ACCT_DELAY_TIME	 41
#define	LIB1X_RAD_ACCT_INPUT_OCTETS	 42
#define	LIB1X_RAD_ACCT_OUTPUT_OCTETS	 43
#define	LIB1X_RAD_ACCT_SESSION_ID	 44
#define LIB1X_RAD_ACCT_AUTHENTIC	 45
#define	LIB1X_RAD_ACCT_SESSION_TIME	 46
#define	LIB1X_RAD_ACCT_INPUT_PACKETS	 47
#define	LIB1X_RAD_ACCT_OUTPUT_PACKETS	 48
#define LIB1X_RAD_ACCT_TERMINATE_CAUSE	 49
#define	LIB1X_RAD_ACCT_INPUT_GIGAWORDS	 52
#define	LIB1X_RAD_ACCT_OUTPUT_GIGAWORDS	 53
//HS2 SUPPORT
#define	LIB1X_RAD_ACCT_EVT_TIMESTAMP	 55
#define LIB1X_RAD_ACCT_INTERIM_TIMEOUT	 85

//HS2 SUPPORT
#define LIB1X_RAD_ACCT_CHARGEABLE_USER_ID	 89
/* Radius vendor specific definition from RFC 2548
   Microsoft Vendor-specific RADIUS attributes   */
#define LIB1X_RADVENDOR_MS			  311 // 0x00000137
#define LIB1X_RADVENDOR_MS_MPPE_SEND_KEY 	  16
#define LIB1X_RADVENDOR_MS_MPPE_RECV_KEY 	  17
#define LIB1X_RADVENDOR_MS_MPPE_ENCRYPTION_POLICY 7
#define LIB1X_RADVENDOR_MS_MPPE_ENCRYPTION_TYPES  8

/*HS2_SUPPORT*/
#ifdef HS2_SUPPORT
/* Radius vendor specific definition 
   WFA Vendor-specific RADIUS attributes   */
#define LIB1X_RADVENDOR_WFA			  40808
// Hotspot 2.0 Subtype
#define LIB1X_RADVENDOR_WFA_ST_SUB_RED_SVR 1// Hotspot 2.0 subscription remediation needed
#define LIB1X_RADVENDOR_WFA_ST_AP_VER 2 // Hotspot 2.0 AP version
#define LIB1X_RADVENDOR_WFA_ST_STA_VER 3 // Hotspot 2.0 STA version
#define LIB1X_RADVENDOR_WFA_ST_DEAUTH_REQ 4 // Hotspot 2.0 deauthentication request
#define LIB1X_RADVENDOR_WFA_ST_SESSION_URL 5 // Hotspot 2.0 Session Information URL
#endif
/*HS2_SUPPORT*/

/* Accounting related Attribute */
#define LIB1X_RADACCT_STATUS_TYPE_START		  1
#define LIB1X_RADACCT_STATUS_TYPE_STOP		  2
#define LIB1X_RADACCT_STATUS_TYPE_INTERIM_UPDATE   3
#define LIB1X_RADACCT_STATUS_TYPE_ACCOUNTING_ON    7
#define LIB1X_RADACCT_STATUS_TYPE_ACCOUNTING_OFF   8
#define LIB1X_RADACCT_AUTHENTIC_RADIUS		  1
#define LIB1X_RADACCT_AUTHENTIC_LOCAL		  2
#define LIB1X_RADACCT_AUTHENTIC_REMOTE		  3
#define LIB1X_RADACCT_TERMINATE_CAUSE_USER_REQUEST	1
#define LIB1X_RADACCT_TERMINATE_CAUSE_LOST_CARRIER	2
#define LIB1X_RADACCT_TERMINATE_CAUSE_LOST_SERVICE	3
#define LIB1X_RADACCT_TERMINATE_CAUSE_IDLE_TIMEOUT	4
#define LIB1X_RADACCT_TERMINATE_CAUSE_SESSION_TIMEOUT	5
#define LIB1X_RADACCT_TERMINATE_CAUSE_ADMIN_RESET	6
#define LIB1X_RADACCT_TERMINATE_CAUSE_ADMIN_REBOOT	7
#define LIB1X_RADACCT_TERMINATE_CAUSE_PORT_ERROR	8
#define LIB1X_RADACCT_TERMINATE_CAUSE_NAS_ERROR		9
#define LIB1X_RADACCT_TERMINATE_CAUSE_NAS_REQUEST	10
#define LIB1X_RADACCT_TERMINATE_CAUSE_NAS_REBOOT	11
#define LIB1X_RADACCT_TERMINATE_CAUSE_PORT_INNEEDED	12
#define LIB1X_RADACCT_TERMINATE_CAUSE_PORT_PREEMPTED	13
#define LIB1X_RADACCT_TERMINATE_CAUSE_PORT_SUSPENDED	14
#define LIB1X_RADACCT_TERMINATE_CAUSE_SERVICE_UNAVAILABLE	15
#define LIB1X_RADACCT_TERMINATE_CAUSE_CALLBACK		16
#define LIB1X_RADACCT_TERMINATE_CAUSE_USER_ERROR	17
#define LIB1X_RADACCT_TERMINATE_CAUSE_HOST_REQUEST	18

#define LIB1X_RADACCT_ACTION_ACCOUNT_START	1
#define LIB1X_RADACCT_ACTION_ACCOUNT_STOP	2
#define LIB1X_RADACCT_ACTION_ACCOUNT_ON		3
#define LIB1X_RADACCT_ACTION_INTERIM_UPDATE	4
#define LIB1X_RADACCT_ACTION_TERMINATE_CAUSE	5

#define LIB1X_RAD_ACCT_STATUS_ON		1
#define	LIB1X_RAD_AUTH_MAC_AUTHENTICATION	2

#define LIB1X_IPPROTO_UDP		 17

#define LIB1X_80211_NAS_PORTTYPE	19	/* port type for 802.11 */

#ifdef CONFIG_RTL_ETH_802DOT1X_SUPPORT
#define LIB1X_802DOT3_NAS_PORTTYPE	15	/* port type for 802.3 */
#endif



#define	LIB1X_RADACCT_ACCT_ON_USER_NAME		"ACCT_ON"

#define LIB1X_RAD_SERVICE_TYPE_FRAMED		2

#pragma pack(1)


#define LIB1X_CKSUM_CARRY(x) \
    (x = (x >> 16) + (x & 0xffff), (~(x + (x >> 16)) & 0xffff))

#define LIB1X_INC_RAD_IDENTIFIER(x) ((x==255)?x=0:x++)
//Abocom
	
//#define LIB1X_DEAFULT_SESSION_TIMEOUT   0x1
//#define LIB1X_DEFAULT_IDLE_TIMEOUT      0x2
//#define LIB1X_DEFAULT_INTERIM_TIMEOUT   0x3
	
#define	LIB1X_DEAFULT_SESSION_TIMEOUT	0xffffffff
#define	LIB1X_DEFAULT_IDLE_TIMEOUT	0xffffffff
#define LIB1X_DEFAULT_INTERIM_TIMEOUT	0xffffffff

struct lib1x_radiushdr
{
	u_char   code;
	u_char   identifier;
	u_short   length;
	u_char   authenticator_str[16];

};

/*HS2_SUPPORT*/
struct lib1x_radius_das_attr
{
	u_char *sta_addr;
	u_char *user_name;
	int		user_name_len;
	u_char *acct_session_id;
	int     acct_session_id_len;
	u_char *cui;
	int    cui_len;
};
/*HS2_SUPPORT*/
struct lib1x_radiusattr
{
	u_char  type;
	u_char  length;	// is the lengh of entire attribute including the type and length fields
};

struct lib1x_radius_vendorattr
{

	u_char type;
	u_char length;
	u_char * string;
};

struct lib1x_udphdr
{
 	u_short sport;   /* soure port */
	u_short dport;   /* destination port */
	u_short len;    /* length */
	u_short sum;     /* checksum */
};



struct lib1x_radiuspkt	/* this struct is used for parsing only */
{
	u_char  s_ethaddr[6];
	u_char  d_ethaddr[6];

        struct in_addr ip_src, ip_dst; /* source and dest address */
	u_short dst_port, src_port;
	struct lib1x_radiushdr *rhdr;	 // pointer to the radius start in the packet
};

struct lib1x_radius_const	/* this struct is used for cosntructing packets */
{
	u_char    * pkt;
	struct lib1x_radiushdr * rhdr;
	u_short   pktlen;	/* length of the complete packet */
	u_char    * ptr_messauth;
	int       * nas_porttype;
};

#ifdef _ON_RTL8181_TARGET
#undef LIB1X_LIL_ENDIAN
#endif

struct lib1x_iphdr
{
#ifdef LIB1X_LIL_ENDIAN
	   u_char ip_hl:4,         /* header length */
	          ip_v:4;         /* version */
#endif
#ifdef LIB1X_BIG_ENDIAN
           u_char ip_v:4,          /* version */
                 ip_hl:4;        /* header length */
#endif
          u_char ip_tos;          /* type of service */
          u_short ip_len;         /* total length */
          u_short ip_id;          /* identification */
          u_short ip_off;
#ifndef IP_RF
#define IP_RF 0x8000        /* reserved fragment flag */
#endif
#ifndef IP_DF
#define IP_DF 0x4000        /* dont fragment flag */
#endif
#ifndef IP_MF
#define IP_MF 0x2000        /* more fragments flag */
#endif
#ifndef IP_OFFMASK
#define IP_OFFMASK 0x1fff   /* mask for fragmenting bits */
#endif
          u_char ip_ttl;          /* time to live */
          u_char ip_p;            /* protocol */
          u_short ip_sum;         /* checksum */
          struct in_addr ip_src, ip_dst; /* source and dest address */
};

#define LIB1X_FRMSUPP_RESPID		1
#define LIB1X_FRMSUPP_RESPOTH		2
#define LIB1X_RAD_SHARED		64
#define MAX_NAS_ID_LEN			50 //sc_yang

struct radius_info	 /* one struct for radius related bookkeeping */
{
	u_char     req_authenticator[16];
	u_char     mess_authenticator[16];
	u_char     identifier;			/* the identifier field in a radius packet */
					       /* needs to be changed for every unique packet */
	u_char	   * global_identifier;
	u_char     eap_message_frmsupp[ LIB1X_MAXEAPLEN ]; /* defined in 1x_nal.h */
	u_char     eap_messtype_frmsupp;		   /* we store the received eap message from supp*/
	int        eap_messlen_frmsupp;

	u_char     eap_message_frmserver[ LIB1X_MAXEAPLEN ]; /* defined in 1x_nal.h */
	u_char     eap_messtype_frmserver;		     /* store the eap mess from server */
	int        eap_messlen_frmserver;

	//u_char	   rad_shared[LIB1X_RAD_SHARED];	    /* NAS and RADIUS */ 

	u_char    username[80];			/* the username attribute is what the supplicant sends in */
						/* response to eap request/identity packet                */ 
	u_char	  username_len;			/* length of the username attribute */

	u_char	 nas_identifier[MAX_NAS_ID_LEN];		/* string identifying the Authenticator TODO .. this is so static now !	*/
	u_char   connectinfo[50];		/* = "CONNECT 11 Mbps 802.11b" */

	u_char   radius_state[ LIB1X_MAXEAPLEN ]; /* State attribute .. needs to be copied back */
	BOOLEAN  rad_stateavailable;		   /* available or not */
	u_short  rad_statelength;		  /* length of the State attribute .. type 24 */
};

struct Auth_Pae_tag;

#ifdef HS2_SUPPORT
int lib1x_rad_vendor_attr_WFA(	Global_Params * global,	u_char * rattr_ptr,	int length) ;
#endif

void lib1x_create_reqauth( struct Auth_Pae_tag * auth_pae );
u_short lib1x_ip_check(u_short *addr, int len);
void lib1x_do_checksum_udp(u_char *buf,  int len);
void lib1x_do_checksum_ip(u_char *buf,  int len);
int lib1x_in_cksum(u_short *addr, int len);
void lib1x_radconst_finalize( struct lib1x_radius_const * rconst );
void lib1x_create_messauth( struct Auth_Pae_tag * auth_pae, struct lib1x_radius_const * rconst, u_char * messauth);
void lib1x_radconst_addattr( struct lib1x_radius_const * rconst, u_char attrtype,  u_char attrlen, u_char * attrdata );
void lib1x_rad_eapresp_svr( struct Auth_Pae_tag * auth_pae, struct lib1x_packet * srcpkt, int msgtype);
void lib1x_rad_eapresp_supp( struct Auth_Pae_tag * auth_pae, struct lib1x_packet * pkt);

struct lib1x_radius_const *  lib1x_radconst_create( struct Auth_Pae_tag * auth_pae, u_char * pkt , u_char rcode, u_char rid, int udp_type);

int lib1x_rad_vendor_attr(Global_Params * global, u_char * rattr_ptr,int length
);
void lib1x_hmac_md5(unsigned char*  text, int text_len, unsigned char*  key,int key_len, caddr_t digest);

void lib1x_radconst_addEAPMessAttr( struct lib1x_radius_const * rconst,  int attrlen, u_char * attrdata );
void lib1x_radconst_calradlength( struct lib1x_radius_const * rconst );

//Accounting
void lib1x_rad_session_timeout(Global_Params * global, u_char * rattr_ptr, int length);
void lib1x_rad_idle_timeout(Global_Params * global, u_char * rattr_ptr, int length);
void lib1x_rad_interim_timeout(Global_Params * global, u_char * rattr_ptr, int length);
void lib1x_rad_special_type( Auth_Pae * auth_pae, u_long ulRequestType);
void lib1x_create_reqauth_acct(Auth_Pae * auth_pae, struct lib1x_radius_const * rconst);

//MAC Authentication
int lib1x_radpassword_create( Auth_Pae * auth_pae, u_char* pucPassword, u_long ulPasswordLength);
//sc_yang
#pragma pack()
#endif
