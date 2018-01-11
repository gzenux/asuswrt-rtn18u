
#ifndef LIB1x_AUTH_PAE_H
#define LIB1x_AUTH_PAE_H


#include "1x_types.h"
#include "1x_common.h"
#include "1x_ethernet.h"
#include "1x_reauth_sm.h"
#include "1x_bauth_sm.h"
#include "1x_cdsm.h"
#include "1x_krc_sm.h"
#include "1x_kxsm.h"
#include "1x_ptsm.h"
#include "1x_acct_sm.h"
//#include "1x_radius.h"


#include <stdio.h>
//--------------------------------------------------
// IEEE 802.1x Implementation
//
// File		: auth_pae.h
// Programmer	: Arunesh Mishra
//
// Contains declarations for Authenticator PAE
// state machine.
// Refer 8.5.4.1  page 53 in the IEEE 802.1x spec.
//
//
// Copyright (c) Arunesh Mishra 2002
// All rights reserved.
// Maryland Information and Systems Security Lab
// University of Maryland, College Park.
//
//--------------------------------------------------


#define LIB1X_AP_QUIET_PERIOD		 	60  	// seconds
//#define LIB1X_AP_QUIET_PERIOD		 	1  	// seconds
//#define LIB1X_AP_REAUTHMAX			20	// attempts
#define LIB1X_AP_REAUTHMAX                      3
#if defined(CONFIG_RTL_ETH_802DOT1X_SUPPORT)
#define LIB1X_AP_ETH_REAUTHMAX			20	// attempts
#endif
#define LIB1X_AP_NAKMAX				4	// received times
//#define LIB1X_AP_TXPERIOD			30	// seconds
#define LIB1X_AP_TXPERIOD                       5    // seconds

#define LIB1X_AP_SENDBUFLEN			1600
#define LIB1X_ACCTING_SENDBUFLEN		1600


#define MAX_EAP_BUFFER				10
		// The reauthentication period
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>

struct pktbuf
{
	u_char  * pkt;
	u_short   length;	// -1 indicates no packet is stored in this slot
	u_char    eap_code;
	u_char    eap_id;
	u_char    eaprr_type;   // = 255 if not valid i.e. the EAP packet is not a request/response pkt
};

struct Global_Params_tag;

struct Auth_Pae_tag
{
	// The machine state
	AUTH_PAE_STATE		state;

	// The Variables.
	BOOLEAN			eapLogoff;
	BOOLEAN			eapStart;
	PORT_MODE_TYPE		portMode;
	int			reAuthCount;
	int			nakCount;
	BOOLEAN			rxRespId;

	BOOLEAN			isSuppPresent;	// true if we have a supp to communicate with


	// The constants
	int			quietPeriod;
	int			reAuthMax;
	int			txPeriod;
	

	// A listing of the other state machines we are going to use.
	// TODO something about the port timers machine.
	PT_SM		*  port_timers;

	// Reauthentication Timer State Machine
	Reauth_SM 	*  reauth_sm;

	// Backend Authentication State Machine
	Bauth_SM	*  bauth_sm;

	// Controlled Directions State Machine
	CtrlDirSM 	*  ctrl_sm;

	// Key Receive State Machine
	Krc_SM		*  krc_sm;

	// Authenticator Key Transmit State Machine
	Auth_KeyxmitSM	*  keyxmit_sm;

	// Accouting State Machine
	Acct_SM * acct_sm; 



	u_char		 * sendBuffer;
	int		   sendbuflen;

	u_char           * acct_sendBuffer;
        int                acct_sendbuflen;

	BOOLEAN            sendreplyready;		/* signals that the reply is ready  for authentication message*/
	BOOLEAN		   sendhandshakeready;		/* signals that the reply is ready  for key management message */
	struct lib1x_eap * send_eapptr;		/* used to communicate the start of eap pkt in sendbuf */

	//u_char		oursvr_addr[ETHER_ADDRLEN];       // ethernet address of the server interface
	
	//u_char		oursupp_addr[ETHER_ADDRLEN];       // ethernet address of the supplicant interface
	
	u_char		supp_addr[ETHER_ADDRLEN];
	//u_char		svr_addr[ETHER_ADDRLEN];

	struct Global_Params_tag	* global;


	struct pktbuf   fromsupp; 	// buffers of length one to store latest packet  from
	struct pktbuf   fromsvr; 		// supplicant / server

	//struct lib1x_nal_intfdesc * network_svr;   
	//struct lib1x_nal_intfdesc * network_supp;   
	FILE 		* debugsm;
	//struct	in_addr	ourip_inaddr, svrip_inaddr;
	//u_short 	udp_ourport, udp_svrport;
	struct radius_info    * rinfo; /* structure for radius related bookkeeping with respect
					 to sending packets to the radius server*/

	struct sockaddr_in  radsvraddr;
	int              udpsock;

	struct lib1x_radius_const * rconst;



};


typedef struct Auth_Pae_tag Auth_Pae;
typedef struct lib1x_packet lib1x_packet_tag;
typedef struct lib1x_nal_intfdesc lib1x_nal_intfdesc_tag;


#ifdef START_AUTH_IN_LIB

typedef struct auth_param {
	int encryption;		// 2:WPA, 4:WPA2, 6:both
	int wpaCipher;		// 1:TKIP, 2:AES, 3:both
#ifdef RTL_WPA2	
	int wpa2Cipher;		// 1:TKIP, 2:AES, 3:both
#endif	
	unsigned char ssid[40];
	unsigned char psk[64];
	int role;			// 0:AP, 1:infra-client, 2:adhoc 
	int terminate;		// 0:run, 1:terminate
} auth_param_t;

#endif // START_AUTH_IN_LIB


// Now the function declarations follow:



//-----------------------------------------------------
// Initialization Function
//-----------------------------------------------------
int lib1x_init_authRSNConfig(
	Dot1x_Authenticator * auth);

int lib1x_init_authGlobal(
	Dot1x_Authenticator * auth);

int lib1x_init_authTimer(
	Dot1x_Authenticator * auth);

TxRx_Params * lib1x_init(
	u_char * oursvr_addr,
	u_char * svr_addr ,
	u_char * oursupp_addr,
	u_char * ourip_addr,
	u_char * svrip_addr,
	u_short udp_ourport,
	u_short udp_svrport ,
	u_char *dev_svr,
	u_char * dev_supp);

Global_Params *  lib1x_init_authenticator(
	Dot1x_Authenticator * auth,
	TxRx_Params * dev_txrx);

TxRx_Params * lib1x_init_txrx(
	Dot1x_Authenticator *auth,
	u_char * oursvr_addr,
	u_char * svr_addr,
	u_char * oursupp_addr,
	u_char * ourip_addr,
	u_char * svrip_addr,
	u_short udp_ourport,
	u_short udp_svrport,
	u_char * acctip_addr,
	u_short udp_acctport,
#ifdef RTL_RADIUS_2SET
	u_char * svrip_addr2,
	u_short udp_svrport2,
	u_char * acctip_addr2,
	u_short udp_acctport2,
#endif
	u_char * dev_svr,
	u_char * dev_supp);

int lib1x_init_auth(
	Dot1x_Authenticator * auth);

//-----------------------------------------------------
// For 802.11 authentication and key management
//-----------------------------------------------------
void lib1x_get_NumSTA( Dot1x_Authenticator * auth);
int  lib1x_do_authenticator( Dot1x_Authenticator * auth);
void lib1x_auth_process(Dot1x_Authenticator * auth );
void lib1x_reset_authenticator(Global_Params * global);
int lib1x_timer_authenticator(int signum);


//-----------------------------------------------------
// Porcedures for processing data
//-----------------------------------------------------
void lib1x_authsm_capture_supp( Global_Params *, lib1x_nal_intfdesc_tag * nal, lib1x_packet_tag * );
void lib1x_authsm_capture_svr( Global_Params *, lib1x_nal_intfdesc_tag * nal, lib1x_packet_tag * );
int lib1x_capture_control(Global_Params * global, lib1x_nal_intfdesc_tag * nal, lib1x_packet_tag * spkt);


//-----------------------------------------------------
// Procedure called by key management state machine
//-----------------------------------------------------
void lib1x_akmsm_Timer_proc(Dot1x_Authenticator * auth);

//-----------------------------------------------------
// packet xmit routines.
//-----------------------------------------------------
void lib1x_auth_txCannedSuccess( Auth_Pae * auth_pae, int identifier );
void lib1x_auth_txCannedFail( Auth_Pae * auth_pae, int identifier );
void lib1x_auth_txReqId( Auth_Pae * auth_pae, int identifier );
void lib1x_authsm_dump( FILE *  fdesc, Auth_Pae * auth_pae );


//-----------------------------------------------------
// sta table management function
//-----------------------------------------------------
int lib1x_search_supp(Dot1x_Authenticator * auth , lib1x_packet_tag * spkt, u_char inttype);
int lib1x_insert_supp(Dot1x_Authenticator *auth, u_char * supp_addr);
int lib1x_del_supp(Dot1x_Authenticator *auth, u_char * supp_addr);

#endif

