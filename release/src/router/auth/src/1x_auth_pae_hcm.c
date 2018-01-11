
//--------------------------------------------------
// IEEE 802.1x Implementation
//
// File		: 1x_auth_pae.c
// Programmer	: Arunesh Mishra

// Copyright (c) Arunesh Mishra 2002
// All rights reserved.
// Maryland Information and Systems Security Lab
// University of Maryland, College Park.
//
// Contains the Authenticator implementation.
// Implements the Auth PAE state machine,
// the Authenticator Key Transmit state machine and
// the Controlled Directions State Machine.
//--------------------------------------------------


#include <netinet/in.h>
#include <sys/time.h>
#include <signal.h>
#include <unistd.h>
#include <stdlib.h>

#include "1x_common.h"
#include "1x_auth_pae.h"
#include "1x_reauth_sm.h"
#include "1x_bauth_sm.h"
#include "1x_eapol.h"
#include "1x_ethernet.h"
#include "1x_nal.h"
#include "1x_radius.h"
#include "1x_ptsm.h"
#include "1x_ioctl.h"
#include "1x_kmsm.h"
#include "1x_info.h"


#ifdef RTL_WPA_CLIENT
#include "1x_supp_pae.h"
extern Dot1x_Client		RTLClient;
#endif

#ifdef CONFIG_RTL8196C_AP_HCM
#define INBAND_DEBUG 0
#define DEST_MAC ("00E04C8196C1")
#define ETH_P_RTK_NOTIFY 0x9001
#endif


#include "1x_kmsm_eapolkey.h"

u_char SuppTestInfoElement[] = {        0xdd, 0x18, 0x00, 0x50, 0xf2, 0x01, 0x01, 0x00,
        0x00, 0x50, 0xf2, 0x01,
        0x01, 0x00, 0x00, 0x50, 0xf2, 0x02,
        0x01, 0x00, 0x00, 0x50, 0xf2, 0x00,
        0x06, 0x00 };
u_char AuthTestInfoElement[] = {        0xdd, 0x0a, 0x00, 0x50, 0xf2, 0x01, 0x01, 0x00,
        0x00, 0x50, 0xf2, 0x01};
u_char	EMPTY_ADDR[] = {0xEE, 0xEE, 0xEE, 0xEE, 0xEE, 0xEE};


// The "internal" function declarations:
// david
//void lib1x_authsm_listen_action( Dot1x_Authenticator *auth, TxRx_Params *txrx);
int lib1x_authsm_listen_action(int which, Dot1x_Authenticator *auth, TxRx_Params *txrx);

void lib1x_authsm_initialize( Auth_Pae * auth_pae , Global_Params * global);
void lib1x_authsm_disconnected( Auth_Pae * auth_pae , Global_Params * global);
void lib1x_authsm_connecting( Auth_Pae * auth_pae , Global_Params * global);
void lib1x_authsm_authenticated( Auth_Pae * auth_pae , Global_Params * global);
void lib1x_authsm_authenticating( Auth_Pae * auth_pae , Global_Params * global);
void lib1x_authsm_aborting( Auth_Pae * auth_pae , Global_Params * global);
void lib1x_authsm_force_unauth( Auth_Pae * auth_pae , Global_Params * global);
void lib1x_authsm_force_auth( Auth_Pae * auth_pae , Global_Params * global);
void lib1x_authsm_execute_authsm( Global_Params * global );

BOOLEAN lib1x_trans_authsm( Global_Params * global );



//----if 0706
void lib1x_handle_eapol_start(Global_Params * global);
void lib1x_handle_eapsupp( Global_Params * global,  struct lib1x_packet * pkthdr);
void lib1x_handle_eapsvr( Global_Params * global, u_char * packet , struct lib1x_packet * pkthdr);
void lib1x_store_eap( Auth_Pae * auth_pae, u_char * packet , struct lib1x_packet * pkthdr, u_char eap_code, u_char eap_id, u_char eaprr_type, u_char fromsupp, u_char fromserver);

void lib1x_process_radiuschallenge( Global_Params * ,  struct lib1x_packet * );
void lib1x_process_radiusaccept( Global_Params * global, struct lib1x_packet * spkt);
void lib1x_process_radiusacct( Global_Params * global, struct lib1x_packet * spkt);


int lib1x_acct_request_on( Auth_Pae * auth_pae);



#ifdef _RTL_WPA_UNIX
void lib1x_handle_eapsupp_key( Global_Params * global,  struct lib1x_packet * pkthdr);
#endif

extern Dot1x_Authenticator     RTLAuthenticator;
u_char lib1x_nas_id[MAX_NAS_ID_LEN]="Realtek Access Point. 8186";




inline void PRINT_AUTH_PAE_STATE( Auth_Pae *auth_pae )
{

	switch( auth_pae->state )
	{
		case 	apsm_Initialize:
			printf("%s: AUTH_PAE_STATE - apsm_Initialize\n", __FUNCTION__);
			break;
		case 	apsm_Disconnected:
			printf("%s: AUTH_PAE_STATE - apsm_Disconnected\n", __FUNCTION__);
			break;
		case 	apsm_Connecting:
			printf("%s: AUTH_PAE_STATE - apsm_Connecting\n", __FUNCTION__);
			break;
		case 	apsm_Authenticated:
			printf("%s: AUTH_PAE_STATE - apsm_Authenticated\n", __FUNCTION__);
			break;
		case	apsm_Authenticating:
			printf("%s: AUTH_PAE_STATE - apsm_Authenticating\n", __FUNCTION__);
			break;
		case	apsm_Aborting:
			printf("%s: AUTH_PAE_STATE - apsm_Aborting\n", __FUNCTION__);
			break;
		case	apsm_Held:
			printf("%s: AUTH_PAE_STATE - apsm_Held\n", __FUNCTION__);
			break;
		case	apsm_Force_Unauth:
			printf("%s: AUTH_PAE_STATE - apsm_Force_Unauth\n", __FUNCTION__);
			break;
		case	apsm_Force_Auth:
			printf("%s: AUTH_PAE_STATE - apsm_Force_Auth\n", __FUNCTION__);
			break;
		default:
			printf("%s: AUTH_PAE_STATE - apsm_Unknown\n", __FUNCTION__);
			break;
	}
}



//--------------------------------------------------
// lib1x_init_authenticator:
//  Initialize various other state machines and construct a
// complete authenticator.
// We need the supplicant ethernet address from lower layers
	// The  Authenticator requires the following state machines :
	// 	1. Port Timers
	// 	2. Auth PAE
	// 	3. Reauth Timer
	// 	4. Backend Auth
	// 	5. Controlled Dir
	// 	6. Key Receive
	// 	7. Auth Key xmit
//--------------------------------------------------
//TODO : Separate the authenticator initialization from global initialization.
//This function creates a complete context for an authenticator
TxRx_Params * lib1x_init_txrx(Dot1x_Authenticator * auth, u_char * oursvr_addr, u_char * svr_addr,
				u_char * oursupp_addr, u_char * ourip_addr,
				u_char * svrip_addr, u_short udp_ourport, u_short udp_svrport,
#ifdef RTL_RADIUS_2SET
				u_char * svrip_addr2, u_short udp_svrport2,
#endif
				u_char * acctip_addr, u_short udp_acctport,
				u_char * dev_svr, u_char * dev_supp)
{

#if defined(CONFIG_RTL8196C_AP_HCM)
	int hostmac[6]= {0};
	unsigned char line[18]={"\0"};
	FILE *proc_hostmac=NULL;
#endif
	TxRx_Params	*	dev_txrx;

	dev_txrx = (TxRx_Params * ) malloc ( sizeof(TxRx_Params) );

	memcpy( dev_txrx->oursvr_addr, oursvr_addr, ETHER_ADDRLEN );
	memcpy( dev_txrx->oursupp_addr, oursupp_addr, ETHER_ADDRLEN );
	memcpy( dev_txrx->svr_addr, svr_addr, ETHER_ADDRLEN );

#ifndef PSK_ONLY
	//-------------------------------
	// ethernet device initialization
	//-------------------------------
	//----if 0802
	if(auth->RSNVariable.Dot1xEnabled || auth->RSNVariable.MacAuthEnabled)
	//----else
	//if(auth->RSNVariable.Dot1xEnabled )
	//----endif
	{
		dev_txrx->device_svr = (u_char*)malloc(IFNAMSIZ + 10);
		memset( dev_txrx->device_svr, 0, sizeof(dev_txrx->device_svr));
#ifdef RTL_WPA2_PREAUTH
		strcpy( dev_txrx->device_svr, dev_svr );

		//---------------------------------
		// DS device initialization
		//---------------------------------
		//dev_txrx->network_ds =  lib1x_nal_initialize( "eth0", oursupp_addr, LIB1X_IT_PKTSOCK);
	        dev_txrx->network_ds =  lib1x_nal_initialize( dev_txrx->device_svr, oursupp_addr, LIB1X_IT_PKTSOCK);
	        //printf("dev_txrx->device_svr = %s\n", dev_txrx->device_svr);
#else
		strcpy( dev_txrx->device_svr, dev_supp );
#endif

		dev_txrx->network_svr =  lib1x_nal_initialize( dev_txrx->device_svr, oursvr_addr , LIB1X_IT_UDPSOCK);
		dev_txrx->radsvraddr.sin_family = PF_INET;   // we need to 'connect' on udp to the server
		dev_txrx->radsvraddr.sin_port = htons( udp_svrport );
		dev_txrx->radsvraddr.sin_addr.s_addr = inet_addr( svrip_addr );

#if defined(CONFIG_RTL8196C_AP_HCM)
#else
		if(lib1x_nal_connect( dev_txrx->network_svr,  & dev_txrx->radsvraddr, sizeof(struct sockaddr_in ), LIB1X_IT_UDPSOCK_AUTH) < 0)
		{
			auth->RSNVariable.Dot1xEnabled = FALSE ;
			auth->RSNVariable.MacAuthEnabled = FALSE;

		}
#endif

		if ( inet_aton( ourip_addr, & dev_txrx->ourip_inaddr ) == 0 )
			lib1x_message(MESS_ERROR_FATAL, "Invalid OUR IP addr ");
		if (inet_aton( svrip_addr, & dev_txrx->svrip_inaddr ) == 0 )
			lib1x_message(MESS_ERROR_FATAL, "Invalid OUR IP addr ");
		dev_txrx->udp_ourport = udp_ourport;
		dev_txrx->udp_svrport = udp_svrport;

#ifdef RTL_RADIUS_2SET
		if (auth->use_2nd_rad) {
			dev_txrx->network_svr2 =  lib1x_nal_initialize( dev_txrx->device_svr, oursvr_addr , LIB1X_IT_UDPSOCK);
			dev_txrx->radsvraddr2.sin_family = PF_INET;   // we need to 'connect' on udp to the server
			dev_txrx->radsvraddr2.sin_port = htons( udp_svrport2 );
			dev_txrx->radsvraddr2.sin_addr.s_addr = inet_addr( svrip_addr2 );

			if(lib1x_nal_connect( dev_txrx->network_svr2,  & dev_txrx->radsvraddr2, sizeof(struct sockaddr_in ), LIB1X_IT_UDPSOCK_AUTH) < 0)
			{
				auth->RSNVariable.Dot1xEnabled = FALSE ;
				auth->RSNVariable.MacAuthEnabled = FALSE;
			}

			if (inet_aton( svrip_addr2, & dev_txrx->svrip_inaddr2 ) == 0 )
				lib1x_message(MESS_ERROR_FATAL, "Invalid OUR IP addr ");
			dev_txrx->udp_svrport2 = udp_svrport2;
			dev_txrx->flag_replaced = 0;
		}
#endif

		if(auth->AccountingEnabled)
		{
			dev_txrx->acctsvraddr.sin_family = PF_INET;   // we need to 'connect' on udp to the server
			dev_txrx->acctsvraddr.sin_port = htons( udp_acctport );
			dev_txrx->acctsvraddr.sin_addr.s_addr = inet_addr( acctip_addr );
			if(lib1x_nal_connect( dev_txrx->network_svr,  & dev_txrx->acctsvraddr, sizeof(struct sockaddr_in ), LIB1X_IT_UDPSOCK_ACCT) < 0)
				auth->AccountingEnabled = FALSE ;
			if (inet_aton( acctip_addr, & dev_txrx->acctip_inaddr ) == 0 )
				lib1x_message(MESS_ERROR_FATAL, "Invalid OUR IP addr ");

		}
#ifdef _ABOCOM
		{
			//Accounting-on Packet Identifier should be different whenever AP turn on
			struct 		timeval tv;
		        struct 		timezone tz;

			gettimeofday(&tv, &tz);
			tv.tv_sec ^= getpid();
			dev_txrx->GlobalRadId = (u_char)(tv.tv_sec & 0xff);
		}
#endif

	}

#endif // !PSK_ONLY        

	//---------------------------------
	// wireless device initialization
	//---------------------------------
	dev_txrx->device_supp = (u_char*)malloc(IFNAMSIZ + 10);
	memset( dev_txrx->device_supp, 0, sizeof(dev_txrx->device_supp));
        strcpy( dev_txrx->device_supp, dev_supp );
        dev_txrx->network_supp =  lib1x_nal_initialize( dev_txrx->device_supp, oursupp_addr, LIB1X_IT_PKTSOCK);

        //---------------------------------
	// wireless device initialization
	//---------------------------------
        dev_txrx->device_wlan0 = (u_char*)malloc(IFNAMSIZ + 10);
        memset( dev_txrx->device_wlan0, 0, sizeof(dev_txrx->device_wlan0));
	//sc_yang
	//strncpy( dev_txrx->device_wlan0, "wlan0", sizeof("wlan0") );
	strcpy( dev_txrx->device_wlan0, dev_txrx->device_supp);


	//---------------------------------
	// driver interface initialization
	//---------------------------------
	dev_txrx->fd_control = lib1x_control_init();

#if defined(CONFIG_RTL8196C_AP_HCM)
	/*
	if( (proc_hostmac = fopen("/proc/br_hostmac","r")) != NULL) {
		fgets(line, sizeof(line), proc_hostmac);
		sscanf(line,"%d:%d:%d:%d:%d:%d",&hostmac[0],&hostmac[1],&hostmac[2],&hostmac[3],&hostmac[4],&hostmac[5]);
		fclose(proc_hostmac);
		printf("!!!%s %d:%d:%d:%d:%d:%d\n",line,hostmac[0],hostmac[1],hostmac[2],hostmac[3],hostmac[4],hostmac[5]);
	}
	dev_txrx->network_svr->inband_channel = inband_open("br0",hostmac,ETH_P_RTK_NOTIFY,INBAND_DEBUG);
	*/
	//dev_txrx->network_svr->inband_channel = inband_open("br0",DEST_MAC,ETH_P_RTK_NOTIFY,INBAND_DEBUG);
	memcpy(dev_txrx->network_svr->host_mac,auth->hostmac,13);
	dev_txrx->network_svr->if_index = auth->if_index ;
	dev_txrx->network_svr->inband_channel = inband_open("br0",auth->hostmac,ETH_P_RTK_NOTIFY,INBAND_DEBUG);
	if( dev_txrx->network_svr->inband_channel < 0 )
		lib1x_message(MESS_ERROR_FATAL, "Allocate channel to host failed !.\n");
	else
		dev_txrx->network_svr->udpsock = get_inband_socket(dev_txrx->network_svr->inband_channel);
#endif //CONFIG_RTL8196C_AP_HCM

	return dev_txrx;
}

#ifdef _RTL_WPA_UNIX
//-----------------------------------------------------------------
// lib1x_init_auth:
//	init normal authenticator variable, called after init_txrx
//-----------------------------------------------------------------
int lib1x_init_auth(Dot1x_Authenticator * auth)
{

	struct 		timeval tv;
        struct 		timezone tz;
	u_long		ulUserName;
	u_char		szUTF8[6];
	u_long		ulUTF8Len;
	//---- Initialized auth variables

	auth->SessionTimeoutEnabled = TRUE;
	auth->IdleTimeoutEnabled = TRUE;
	auth->UpdateInterimEnabled = TRUE;

	auth->SessionInfoTimerCount = SECONDS_TO_TIMERCOUNT(1);




	//Accounting-on Packet Identifier should be different whenever AP turn on
	gettimeofday(&tv, &tz);
	tv.tv_sec ^= getpid();
	auth->GlobalSessionId = tv.tv_sec;


	auth->authGlobal = (Dot1x_Supplicant * ) malloc ( sizeof (Dot1x_Supplicant) );
	auth->authGlobal->index = LIB1X_AUTH_INDEX;
	auth->authGlobal->isEnable = TRUE;
	auth->authGlobal->global  = lib1x_init_authenticator( auth, auth->GlobalTxRx );
	auth->authGlobal->global->theAuthenticator->rinfo->global_identifier = &auth->GlobalTxRx->GlobalRadId;

	if(auth->AccountingEnabled)
	{
		//User-name in Accounting-on field should be random value
		ulUserName = tv.tv_sec;
		lib1x_acct_UCS4_TO_UTF8( ulUserName, (u_char*)szUTF8, &ulUTF8Len);
		auth->authGlobal->global->theAuthenticator->rinfo->username_len = ulUTF8Len;
		memcpy(auth->authGlobal->global->theAuthenticator->rinfo->username, szUTF8, ulUTF8Len);
		lib1x_acctsm_request( auth->authGlobal->global, acctsm_Acct_On, 0);
		//lib1x_rad_special_type( auth->authGlobal->global->theAuthenticator, LIB1X_RAD_ACCT_STATUS_ON);

	}
#ifdef RTL_WPA2
        INIT_LIST_HEAD(&auth->pmk_cache);
#endif
	return TRUE;

}
//---------------------------------------------------
// lib1x_init_authRSNConfig:
//	Called after parsing configure file
//---------------------------------------------------
int lib1x_init_authRSNConfig(Dot1x_Authenticator * auth)
{

        int retVal = 0;

	//---------------------------------------------------------------
	// Part of Configuration are read from script file
	//---------------------------------------------------------------


	//---------------------------------------------------------------
	// Default configuration that does not open to user interface
	//---------------------------------------------------------------



	//----Some Default Value
        auth->RSNVariable.isSupportMulticastCipher = TRUE;
        auth->RSNVariable.isSupportUnicastCipher = TRUE;


	//---- Initialize RSN Configuration variable ----
	auth->Dot11RSNConfig.Version = desc_type_RSN;
        auth->Dot11RSNConfig.GroupUpdateTimeOut = 5000;
        auth->Dot11RSNConfig.GroupUpdateCount = 2;
        auth->Dot11RSNConfig.PairwiseUpdateTimeOut = 5000;

	/*
		2008-12-16, For Corega CG-WLCB54GL 54Mbps NIC interoperability issue.
		The behavior of this NIC when it connect to the other AP with WPA/TKIP is:
			AP	<----------------------> 	STA
				....................
				------------> Assoc Rsp (ok)
				------------> EAPOL-key (4-way msg 1)
				<------------ unknown TKIP encryption data
				------------> EAPOL-key (4-way msg 1)
				<------------ unknown TKIP encryption data
				.....................
				<------------ disassoc (code=8, STA is leaving) when the 5 seconds timer timeout counting from Assoc_Rsp is got.
				....................
				------------> Assoc Rsp (ok)
				<-----------> EAPOL-key (4-way handshake success)

		If PairwiseUpdateCount=2, our AP will send disassoc (code=15, 4-way timeout) to STA before STA sending disassoc to AP.
		And this NIC will always can not connect to our AP.			
		set PairwiseUpdateCount=5 can fix this issue.
	 */	
        //auth->Dot11RSNConfig.PairwiseUpdateCount = 2;
        auth->Dot11RSNConfig.PairwiseUpdateCount = 5;


	//---- Timer Initialization ----
 	auth->KeyManageTimerCount = SECONDS_TO_TIMERCOUNT(3);		//(3 * 1000000)/ LIB1X_BASIC_TIMER_UNIT;
	//auth->AuthTimerCount = (auth->Dot11RSNConfig.GroupUpdateTimeOut * 1000) / LIB1X_BASIC_TIMER_UNIT;
	auth->AuthTimerCount = SECONDS_TO_TIMERCOUNT(1);
	auth->IgnoreEAPOLStartCounter = SECONDS_TO_TIMERCOUNT(1);




	//---- RSN Information Element including capability field setting
	auth->RSNVariable.NumOfRxTSC = 1;
#ifndef RTL_WPA2_PREAUTH
	// isSupportPreAuthentication was set in lib1x_load_config()
	auth->RSNVariable.isSupportPreAuthentication = FALSE;
#endif
	auth->RSNVariable.isSupportPairwiseAsDefaultKey = FALSE;
        auth->RSNVariable.AuthInfoElement.Octet = (u_char*)malloc(INFO_ELEMENT_SIZE);
        lib1x_authRSN_constructIE(auth, auth->RSNVariable.AuthInfoElement.Octet,
                                         &auth->RSNVariable.AuthInfoElement.Length, TRUE);

	//lib1x_hexdump2(MESS_DBG_CONTROL, "main", auth->RSNVariable.AuthInfoElement.Octet,
	//	auth->RSNVariable.AuthInfoElement.Length, "Info Element");


// david ----------------------
#if 0
	//Set RSNIE and
	//--For Authenticator mode : Enable Tx/Rx
	//--For Supplicant mode : SET RSNIE and Start Probe Response
	lib1x_control_RSNIE(auth, DOT11_Ioctl_Set);
	lib1x_control_InitQueue(auth);
#endif

#ifdef RTL_WPA_CLIENT
	if ( auth->currentRole != role_Supplicant_adhoc && auth->currentRole != role_wds)
#endif
	{
		//Set RSNIE and
		//--For Authenticator mode : Enable Tx/Rx
		//--For Supplicant mode : SET RSNIE and Start Probe Response
		lib1x_control_InitQueue(auth); // david, init queue before start driver
		lib1x_control_RSNIE(auth, DOT11_Ioctl_Set);
	}
//----------------------------

        return retVal;
}
int lib1x_init_authGlobal(Dot1x_Authenticator *auth)
{

        //---- Counter is initialized whenever boot time ----
        GenNonce(auth->Counter.charData, (u_char*)"addr");

        //---- Initialize Goup Key state machine ----
        auth->gk_sm = (AGKeyManage_SM *)malloc(sizeof (AGKeyManage_SM));
        auth->gk_sm->GNonce.Octet = (u_char*)malloc(KEY_NONCE_LEN);
        auth->gk_sm->GNonce.Length = KEY_NONCE_LEN;
        auth->gk_sm->GN = 1;
        auth->gk_sm->GM = 2;
        auth->gk_sm->GKeyFailure = FALSE;
        auth->gk_sm->GTKRekey = FALSE;
        auth->gk_sm->GTKAuthenticator = TRUE;
        auth->gk_sm->GInitDone = FALSE;
        auth->gk_sm->GKeyDoneStations = 0;
        auth->gk_sm->GkeyReady = FALSE;
        auth->gk_sm->GResetCounter = FALSE;
        auth->gk_sm->GRekeyCounts = auth->Dot11RSNConfig.GroupRekeyTime * (1000000 / LIB1X_BASIC_TIMER_UNIT);

	return TRUE;
}

#endif

//------------------------------------------------------
//  lib1x_init_authenticator:
//	malloc the variable
//-------------------------------------------------------

Global_Params *  lib1x_init_authenticator(Dot1x_Authenticator *auth, TxRx_Params * dev_txrx)
{
	Global_Params 	*	global;
	Auth_Pae	*	auth_pae;
	/*Supp_Pae	*	supp_pae;  only needed for supplicant code*/

	PT_SM		*	port_timers;
	Reauth_SM       *  	reauth_sm;
	Bauth_SM        *  	bauth_sm;
	CtrlDirSM       *  	ctrl_sm;
	Krc_SM		*	krc_sm;
	Auth_KeyxmitSM	*	keyxmit_sm;
	Acct_SM		*	acct_sm;


	//u_char	   device[ LIB1X_MAXDEVLEN ];


	global = ( Global_Params * ) malloc ( sizeof(Global_Params ) ) ;
	bzero( global, sizeof(Global_Params) );
	global->auth = auth;
	global->TxRx = dev_txrx;
	//lib1x_pktlst_init( dev_svr , global );
	auth_pae = ( Auth_Pae * ) malloc( sizeof( Auth_Pae) );
	bzero( auth_pae, sizeof(Auth_Pae) );
	global->theAuthenticator = auth_pae;

	// 1. Init port timers
	port_timers = ( PT_SM * ) malloc( sizeof( PT_SM ) );
	lib1x_ptsm_initialize( global, port_timers );

	// 2. Init Reauthentication State Machine
	reauth_sm = ( Reauth_SM * ) malloc ( sizeof( Reauth_SM ) );
	lib1x_reauthsm_init( reauth_sm , auth->rsReAuthTO );

	// 3. Init Backend Authentication State Machine
	bauth_sm = ( Bauth_SM *) malloc ( sizeof( Bauth_SM ) );
	lib1x_bauthsm_init( bauth_sm , auth->rsMaxReq, auth->rsAWhile);

	// 4. Init Controlled Directions State Machine
	ctrl_sm = ( CtrlDirSM *)  malloc( sizeof( CtrlDirSM ) );
	lib1x_cdsm_init( ctrl_sm );

	// 5. Key Receive State Machine
	krc_sm = ( Krc_SM * ) malloc( sizeof( Krc_SM ) );
	lib1x_krcsm_init( krc_sm );

	// 6. Authenticator Key Transmit State Machine
	keyxmit_sm = ( Auth_KeyxmitSM * ) malloc ( sizeof( Auth_KeyxmitSM ) );
	lib1x_kxsm_init( keyxmit_sm );

	// 7. Accounting state machine
	acct_sm = (Acct_SM*)malloc(sizeof(Acct_SM));
	lib1x_acctsm_init( acct_sm, auth->accountRsMaxReq, auth->accountRsAWhile);

	// 8. Initialize Authenticator Port Access Entity .. state machine also !
	auth_pae->state = apsm_Connecting;
	auth_pae->eapLogoff = FALSE;
	auth_pae->eapStart = FALSE;
	auth_pae->portMode = pmt_Auto;
	auth_pae->reAuthCount = 0;
	auth_pae->nakCount = 0;
	auth_pae->rxRespId = FALSE;

 	// the constants
	auth_pae->quietPeriod = LIB1X_AP_QUIET_PERIOD;
	auth_pae->reAuthMax = LIB1X_AP_REAUTHMAX;
	auth_pae->txPeriod = LIB1X_AP_TXPERIOD;
	//auth_pae->reAuthMax = global->auth->rsReAuthMax;
	//auth_pae->txPeriod = global->auth->rsTxPeriod;

	auth_pae->port_timers = port_timers;
        auth_pae->reauth_sm = reauth_sm;
	auth_pae->bauth_sm = bauth_sm;
	auth_pae->ctrl_sm = ctrl_sm;
	auth_pae->krc_sm = krc_sm;
	auth_pae->keyxmit_sm = keyxmit_sm;
	auth_pae->acct_sm = acct_sm;

	auth_pae->sendbuflen = LIB1X_AP_SENDBUFLEN;
	// auth_pae->sendbuflen = 1600; //sc_yang
	auth_pae->sendBuffer = (u_char *) malloc ( auth_pae->sendbuflen * sizeof(u_char ));

	if(auth->AccountingEnabled)
	{
		auth_pae->acct_sendbuflen = LIB1X_ACCTING_SENDBUFLEN;
		auth_pae->acct_sendBuffer = (u_char *) malloc ( auth_pae->acct_sendbuflen * sizeof(u_char ));
	}

	if ( auth_pae->sendBuffer == NULL )
	{
		printf("\nCould not allocate memory for send buffer.");
		exit(1);
	}

	auth_pae->isSuppPresent = TRUE;


	// 8. Now gotta intialize the global state info.
	global->authAbort = FALSE;
	global->authFail  = FALSE;
	global->authStart = FALSE;
	global->authTimeout = FALSE;
	global->authSuccess = FALSE;
	global->currentId = 0;
	global->initialize = FALSE;
	global->portControl = pmt_Auto;
	global->portEnabled = TRUE;
	global->portStatus = pst_Unauthorized;
	global->reAuthenticate = FALSE;
	global->receivedId = -1;	// Should be in range 0..255 for legal values.
	global->suppStatus = pst_Unauthorized;


	global->timers = port_timers;
	global->theSupplicant = NULL;


	auth_pae->global = global;		// we need a back reference
	global->theAuthenticator = auth_pae;
	global->theAuthenticator->sendhandshakeready = FALSE;



	// allocate memory for eap buffer
	auth_pae->fromsupp.pkt =  ( u_char * ) malloc ( sizeof(u_char) * LIB1X_MAXEAPLEN);
	auth_pae->fromsupp.length = 0;
	auth_pae->fromsvr.pkt =  ( u_char * ) malloc ( sizeof(u_char) * LIB1X_MAXEAPLEN);
	auth_pae->fromsvr.length = 0;

	auth_pae->rinfo = ( struct radius_info *) malloc( sizeof(struct radius_info ));
	auth_pae->rconst  = ( struct lib1x_radius_const * ) malloc ( sizeof(struct lib1x_radius_const ) );


	/* RADIUS initializations ..  might want to separate this out later TODO*/

	//strcpy( auth_pae->rinfo->nas_identifier, "Realtek Access Point. 8181");
	strcpy( auth_pae->rinfo->nas_identifier, lib1x_nas_id); //sc_yang
	strcpy( auth_pae->rinfo->connectinfo, "CONNECT 11Mbps 802.11b");
	auth_pae->rinfo->rad_stateavailable = FALSE;
	auth_pae->rinfo->rad_statelength = 0;


#ifdef _RTL_WPA_UNIX

	//-------------------------------------------------
	// Initialize varaible for each supplicant
	//-------------------------------------------------


        global->akm_sm = ( struct Auth_PairwiseKeyManage_tag *)malloc(sizeof( struct Auth_PairwiseKeyManage_tag) );
        global->akm_sm->global = global;

        global->EAPOLMsgRecvd.Length =  (auth_pae->sendbuflen * sizeof(u_char ));
        global->EAPOLMsgSend.Length = ( auth_pae->sendbuflen * sizeof(u_char ));

        global->akm_sm->SuppInfoElement.Octet = (u_char*)malloc(INFO_ELEMENT_SIZE);
        global->akm_sm->SuppInfoElement.Length = sizeof(SuppTestInfoElement);
        memcpy(global->akm_sm->SuppInfoElement.Octet, SuppTestInfoElement, sizeof(SuppTestInfoElement));
        global->akm_sm->AuthInfoElement.Octet = (u_char*)malloc(INFO_ELEMENT_SIZE);
        global->akm_sm->AuthInfoElement.Length = sizeof(AuthTestInfoElement);
        memcpy(global->akm_sm->AuthInfoElement.Octet, AuthTestInfoElement, sizeof(AuthTestInfoElement));

        global->akm_sm->ANonce.Octet = (u_char*)malloc(KEY_NONCE_LEN);
        global->akm_sm->ANonce.Length = KEY_NONCE_LEN;
        SetNonce(global->akm_sm->ANonce, global->auth->Counter);
        global->akm_sm->SNonce.Octet = (u_char*)malloc(KEY_NONCE_LEN);
        global->akm_sm->SNonce.Length = KEY_NONCE_LEN;


	//---- External trigger event related variable
	global->akm_sm->AuthenticationRequest = FALSE;
	global->akm_sm->DeauthenticationRequest = FALSE;
	global->akm_sm->Disconnect = FALSE;

	//802.1x related vairable
	global->akm_sm->eapStart = FALSE;
	global->RadiusKey.Status = MPPE_SDRCKEY_NONAVALIABLE;
	global->RadiusKey.SendKey.Octet = (u_char*)malloc(RADIUS_KEY_LEN);
	global->RadiusKey.SendKey.Length = 0;
	memset(global->RadiusKey.SendKey.Octet, 0, RADIUS_KEY_LEN);
	global->RadiusKey.RecvKey.Octet = (u_char*)malloc(RADIUS_KEY_LEN);
	global->RadiusKey.RecvKey.Length = 0;
	memset(global->RadiusKey.RecvKey.Octet, 0, RADIUS_KEY_LEN);



	//---- Configuration related variable
        global->DescriptorType = global->auth->Dot11RSNConfig.Version;

// Kenny
    //    global->KeyDescriptorVer = key_desc_ver1;
#ifdef CONFIG_IEEE80211W	
    if (global->auth->RSNVariable.MulticastCipher == DOT11_ENC_BIP)
		global->KeyDescriptorVer = key_desc_ver3;
	else 
#endif	
	if (global->auth->RSNVariable.MulticastCipher == DOT11_ENC_CCMP)
		global->KeyDescriptorVer = key_desc_ver2;
	else
		global->KeyDescriptorVer = key_desc_ver1;

	//global->AuthKeyMethod = DOT11_AuthKeyType_PRERSN;
	//memset(global->PSK, 0, sizeof( global->PSK));
	memcpy(global->PSK, global->auth->RSNVariable.PassPhraseKey, sizeof(global->auth->RSNVariable.PassPhraseKey));
	global->PreshareKeyAvaliable = TRUE;

	//RSN related vairable
	global->RSNVariable.isSuppSupportPairwiseAsDefaultKey = FALSE;
	global->RSNVariable.isSuppSupportPreAuthentication = FALSE;
	global->RSNVariable.NumOfRxTSC = 2;
	global->RSNVariable.isSuppSupportMulticastCipher = global->auth->RSNVariable.isSupportMulticastCipher;
	global->RSNVariable.isSuppSupportUnicastCipher = global->auth->RSNVariable.isSupportUnicastCipher;
#ifdef RTL_WPA2
	global->RSNVariable.WPA2Enabled= FALSE;
#endif
// Kenny
//	global->RSNVariable.UnicastCipher = DOT11_ENC_TKIP;
	if (auth->RSNVariable.UniCastCipherSuit.AlgoTable[DOT11_ENC_CCMP].Enabled)
		global->RSNVariable.UnicastCipher = DOT11_ENC_CCMP;
	else
		global->RSNVariable.UnicastCipher = DOT11_ENC_TKIP;

	global->RSNVariable.MulticastCipher = auth->RSNVariable.MulticastCipher;
	//printf("%s-4: auth->RSNVariable.MulticastCipher = %d\n", __FUNCTION__, auth->RSNVariable.MulticastCipher);


	//---- RSN Config Entry related variable
	global->Dot11RSNConfig.GroupUpdateTimeOut
			= auth->Dot11RSNConfig.GroupUpdateTimeOut;
	global->Dot11RSNConfig.GroupUpdateCount
	 		= auth->Dot11RSNConfig.GroupUpdateCount;
	global->Dot11RSNConfig.PairwiseUpdateTimeOut
			= auth->Dot11RSNConfig.PairwiseUpdateTimeOut;
	global->Dot11RSNConfig.PairwiseUpdateCount
			= auth->Dot11RSNConfig.PairwiseUpdateCount;


	//---- State machine related variable
 	global->akm_sm->state = akmsm_AUTHENTICATION2;
	global->akm_sm->gstate = gkmsm_REKEYNEGOTIATING;
	global->akm_sm->CurrentReplayCounter.field.HighPart = 0;
	global->akm_sm->CurrentReplayCounter.field.LowPart = 0;
	global->akm_sm->TimeoutCtr = 0;
	//sc_yang
	global->akm_sm->TickCnt = SECONDS_TO_TIMERCOUNT(1);
	global->akm_sm->TimeoutEvt = 0;
	global->akm_sm->IfCalcMIC = 0;
	global->akm_sm->PInitAKeys = FALSE;
	global->akm_sm->bWaitForPacket = FALSE;
	global->akm_sm->IgnoreEAPOLStartCounter = REJECT_EAPOLSTART_COUNTER;
	global->bMacAuthEnabled = auth->RSNVariable.MacAuthEnabled;

	//---- For Accounting
	global->akm_sm->SessionTimeout = LIB1X_DEAFULT_SESSION_TIMEOUT;//Abocom
	global->akm_sm->SessionTimeoutCounter = 0;
	global->akm_sm->SessionTimeoutEnabled = FALSE;
	global->akm_sm->IdleTimeout = LIB1X_DEFAULT_IDLE_TIMEOUT;
	global->akm_sm->IdleTimeoutCounter = LIB1X_DEFAULT_IDLE_TIMEOUT;
	global->akm_sm->IdleTimeoutEnabled = FALSE;
	global->akm_sm->InterimTimeout = LIB1X_DEFAULT_INTERIM_TIMEOUT;
	global->akm_sm->InterimTimeoutCounter = 0;
	global->akm_sm->InterimTimeoutEnabled = FALSE;


#endif
	return global;
}

//----------------------------------------------------------
// lib1x_reset_authenticator:
//	Called whenever Association request or Reassociation
//	Request	(but not EAPOL_START)
//----------------------------------------------------------
void lib1x_reset_authenticator(Global_Params * global)
{

	Auth_Pae        *       auth_pae = global->theAuthenticator;

	Dot1x_Authenticator *	auth = global->auth;

	lib1x_message(MESS_DBG_SPECIAL, "lib1x_reset_authenticator");

	// 1. Init port timers
	lib1x_ptsm_initialize( global, auth_pae->port_timers );

	// 2. Init Reauthentication State Machine
	lib1x_reauthsm_init( auth_pae->reauth_sm , auth->rsReAuthTO );

	// 3. Init Backend Authentication State Machine
	lib1x_bauthsm_init( auth_pae->bauth_sm, auth->rsMaxReq, auth->rsAWhile );

	// 4. Init Controlled Directions State Machine
	lib1x_cdsm_init( auth_pae->ctrl_sm );

	// 5. Key Receive State Machine
	lib1x_krcsm_init( auth_pae->krc_sm );

	// 6. Authenticator Key Transmit State Machine
	lib1x_kxsm_init( auth_pae->keyxmit_sm );

	// 7. Accounting state machine
	lib1x_acctsm_init( auth_pae->acct_sm, auth->accountRsMaxReq, auth->accountRsAWhile);

	// 8. Initialize Authenticator Port Access Entity .. state machine also !
#ifdef RTL_WPA2
	if (global->RSNVariable.PMKCached) {
		auth_pae->state = apsm_Authenticated;
	} else {
#endif
	auth_pae->state = apsm_Connecting;
#ifdef RTL_WPA2
	}
#endif
	auth_pae->eapLogoff = FALSE;
	auth_pae->eapStart = FALSE;
	auth_pae->portMode = pmt_Auto;
	auth_pae->reAuthCount = 0;
	auth_pae->nakCount = 0;
	auth_pae->rxRespId = FALSE;

 // the constants
	auth_pae->quietPeriod = LIB1X_AP_QUIET_PERIOD;
	auth_pae->reAuthMax = LIB1X_AP_REAUTHMAX;
	auth_pae->txPeriod = LIB1X_AP_TXPERIOD;
	//auth_pae->reAuthMax = global->auth->rsReAuthMax;
	//auth_pae->txPeriod = global->auth->rsTxPeriod;



	// 8. Now gotta intialize the global state info.
	global->authAbort = FALSE;
	global->authFail  = FALSE;
	global->authStart = FALSE;
	global->authTimeout = FALSE;
	global->authSuccess = FALSE;
	global->currentId = 0;
	global->initialize = FALSE;
	global->portControl = pmt_Auto;
	global->portEnabled = TRUE;
	global->portStatus = pst_Unauthorized;
	global->reAuthenticate = FALSE;
	global->receivedId = -1;	// Should be in range 0..255 for legal values.
	global->suppStatus = pst_Unauthorized;


	global->theSupplicant = NULL;



	auth_pae->fromsupp.length = 0;
	auth_pae->fromsvr.length = 0;

	/* RADIUS initializations ..  might want to separate this out later TODO*/

	auth_pae->rinfo->rad_stateavailable = FALSE;
	auth_pae->rinfo->rad_statelength = 0;





	global->akm_sm->global = global;

	global->EAPOLMsgRecvd.Length =  (auth_pae->sendbuflen * sizeof(u_char ));
	global->EAPOLMsgSend.Length = ( auth_pae->sendbuflen * sizeof(u_char ));


	global->akm_sm->SuppInfoElement.Length = sizeof(SuppTestInfoElement);
	memcpy(global->akm_sm->SuppInfoElement.Octet, SuppTestInfoElement, sizeof(SuppTestInfoElement));
	memcpy(global->akm_sm->AuthInfoElement.Octet, AuthTestInfoElement, sizeof(AuthTestInfoElement));

	global->akm_sm->ANonce.Length = KEY_NONCE_LEN;
#ifndef RTL_WPA2_PREAUTH
	SetNonce(global->akm_sm->ANonce, global->auth->Counter);
#endif
	global->akm_sm->SNonce.Length = KEY_NONCE_LEN;


	//---- External trigger event related variable
	global->akm_sm->AuthenticationRequest = FALSE;
	global->akm_sm->DeauthenticationRequest = FALSE;
	global->akm_sm->Disconnect = FALSE;

	//802.1x related vairable
	global->akm_sm->eapStart = FALSE;
	global->RadiusKey.Status = MPPE_SDRCKEY_NONAVALIABLE;
	global->RadiusKey.SendKey.Length = 0;
	memset(global->RadiusKey.SendKey.Octet, 0, RADIUS_KEY_LEN);
	global->RadiusKey.RecvKey.Length = 0;
	memset(global->RadiusKey.RecvKey.Octet, 0, RADIUS_KEY_LEN);



	//---- Configuration related variable
	global->DescriptorType = desc_type_RSN;

//Kenny
	// global->KeyDescriptorVer = key_desc_ver1;
#ifdef CONFIG_IEEE80211W	
	if (global->auth->RSNVariable.MulticastCipher == DOT11_ENC_BIP)
		global->KeyDescriptorVer = key_desc_ver3;
	else 
#endif	
	if (global->auth->RSNVariable.MulticastCipher == DOT11_ENC_CCMP)
		global->KeyDescriptorVer = key_desc_ver2;
	else
		global->KeyDescriptorVer = key_desc_ver1;

// Fix the bug of using incorrect length, david+01-04-2007
//	memcpy(global->PSK, global->auth->RSNVariable.PassPhraseKey, sizeof(global->auth->RSNVariable.PassPhraseKey));
	memcpy(global->PSK, global->auth->RSNVariable.PassPhraseKey, sizeof(global->PSK));


	//RSN related vairable
	global->RSNVariable.isSuppSupportPairwiseAsDefaultKey = FALSE;
	global->RSNVariable.isSuppSupportPreAuthentication = FALSE;
	global->RSNVariable.NumOfRxTSC = 2;
	global->RSNVariable.isSuppSupportMulticastCipher = global->auth->RSNVariable.isSupportMulticastCipher;
	global->RSNVariable.isSuppSupportUnicastCipher = global->auth->RSNVariable.isSupportUnicastCipher;


	//---- State machine related variable
	/*
 	global->akm_sm->state = akmsm_AUTHENTICATION2;
	global->akm_sm->gstate = gkmsm_REKEYNEGOTIATING;
	global->akm_sm->IfCalcMIC = 0;
	global->akm_sm->PInitAKeys = FALSE;
	global->akm_sm->bWaitForPacket = FALSE;
	global->akm_sm->IgnoreEAPOLStartCounter = 0;
	*/


	global->akm_sm->state = akmsm_AUTHENTICATION2;
	global->akm_sm->gstate = gkmsm_REKEYNEGOTIATING;
	global->akm_sm->TimeoutCtr = 0;
	global->akm_sm->TickCnt = SECONDS_TO_TIMERCOUNT(1);
	global->akm_sm->TimeoutEvt = 0;
	global->akm_sm->PInitAKeys = FALSE;
	global->akm_sm->bWaitForPacket = FALSE;
//	global->akm_sm->IgnoreEAPOLStartCounter = REJECT_EAPOLSTART_COUNTER;

//2003-09-07
	global->akm_sm->IgnoreEAPOLStartCounter = 0;


	global->bMacAuthEnabled = global->auth->RSNVariable.MacAuthEnabled;

	//---- For Accounting
	global->akm_sm->SessionTimeout = LIB1X_DEAFULT_SESSION_TIMEOUT;//Abocom
	global->akm_sm->SessionTimeoutCounter = 0;
	global->akm_sm->SessionTimeoutEnabled = FALSE;
	global->akm_sm->IdleTimeout = LIB1X_DEFAULT_IDLE_TIMEOUT;
	global->akm_sm->IdleTimeoutCounter = LIB1X_DEFAULT_IDLE_TIMEOUT;
	global->akm_sm->IdleTimeoutEnabled = FALSE;
	global->akm_sm->InterimTimeout = LIB1X_DEFAULT_INTERIM_TIMEOUT;
	global->akm_sm->InterimTimeoutCounter = 0;
	global->akm_sm->InterimTimeoutEnabled = FALSE;



}

//---------------------------
// Return 0: success
//---------------------------

int lib1x_init_authTimer(Dot1x_Authenticator *auth)
{
        struct itimerval val;
        struct sigaction  action;

	action.sa_handler = (void (*)())lib1x_timer_authenticator;
        action.sa_flags = SA_RESTART;

        if (sigaction(SIGALRM,&action,0)==-1)
        {
                perror( "sigaction");
                return 1;
        }


		val.it_interval.tv_sec  = 0;
        val.it_interval.tv_usec = LIB1X_BASIC_TIMER_UNIT;
        val.it_value.tv_sec     = 0;
        val.it_value.tv_usec    = LIB1X_BASIC_TIMER_UNIT;

        if (setitimer( ITIMER_REAL, &val, 0 ) == -1)
	{
                perror("alarm" );
		return -1;
	}
	return 0;
}

//--------------------------------------------------------------------
// This function was called per LIB1X_BASIC_TIMER_UNIT micro seconds
//--------------------------------------------------------------------
int lib1x_timer_authenticator(int signum)
{

	Dot1x_Authenticator   *auth = &RTLAuthenticator;

#ifdef RTL_WPA_CLIENT
	Dot1x_Client	      *client = &RTLClient;
#endif

	struct itimerval val;
	static u_long Counter = 0, CounterReGroupKey = 0;

	// kenny
	if(!(auth->RSNVariable.Dot1xEnabled || auth->RSNVariable.RSNEnabled || auth->RSNVariable.MacAuthEnabled))
		return 0;

    if(signum != SIGALRM)
    	return 0;

	val.it_interval.tv_sec  = 0;
	val.it_interval.tv_usec = LIB1X_BASIC_TIMER_UNIT;
	val.it_value.tv_sec     = 0;
	val.it_value.tv_usec    = LIB1X_BASIC_TIMER_UNIT;

	Counter++;
	if(Counter == 0xffffffff)
		Counter = 0;

#ifdef RTL_WPA_CLIENT
	if(auth->currentRole == role_Authenticator)
#endif
	{

		if(auth->gk_sm->GResetCounter)
		{
			CounterReGroupKey = 0;
			auth->gk_sm->GResetCounter = FALSE;
		}

		CounterReGroupKey++;
		if(CounterReGroupKey == 0xffffffff)
			CounterReGroupKey = 0;

		if( (auth->gk_sm->GRekeyCounts != 0) &&
			((CounterReGroupKey % (auth->gk_sm->GRekeyCounts)) == 0) )
		{
			if(auth->gk_sm->GkeyReady == TRUE)
				lib1x_akmsm_GroupReKey_Timer_proc(auth);
		}

		//sc_yang
		//if( (Counter % (auth->KeyManageTimerCount)) == 0)
		{
			lib1x_akmsm_Timer_proc(auth);
		}

		//----Ignore EAPOL_SATRT within 3 seconds after receiving association request
		if((Counter % (auth->IgnoreEAPOLStartCounter)) == 0)
		{
			lib1x_akmsm_EAPOLStart_Timer_proc(auth);
		}



		//----SessionTimeout ,IdleTimeout and Interim processing
		if((Counter % (auth->SessionInfoTimerCount)) == 0)
		{
			//----if 0802
			if(auth->RSNVariable.Dot1xEnabled || auth->RSNVariable.MacAuthEnabled)
			//----else
			//if(auth->RSNVariable.Dot1xEnabled)
			//----endif
			{
				if(auth->SessionTimeoutEnabled ||
					(auth->AccountingEnabled && auth->UpdateInterimEnabled))
				{
					lib1x_akmsm_Account_Timer_proc(auth);
				}
			}
		}



		//ToDo  : Implement re-send packet mechanism!!!
		if( (Counter % (auth->AuthTimerCount)) == 0)
		{
			//----if 0802
			if(auth->RSNVariable.Dot1xEnabled || auth->RSNVariable.MacAuthEnabled)
			//else
			//if(auth->RSNVariable.Dot1xEnabled)
			//endif
				lib1x_ptsm_timer(auth);

		}
	}
#ifdef RTL_WPA_CLIENT
// david
//	else if(auth->currentRole == role_Supplicant)
	else if(auth->currentRole == role_Supplicant_infra)
	{
		if( (Counter % (client->global->ConstTimerCount)) == 0)
			lib1x_supp_timer_proc(client);
#ifdef CLIENT_TLS
		static int XsuppTimerCount = SECONDS_TO_TIMERCOUNT(1);
		if( (Counter % (XsuppTimerCount)) == 0)
			alrmclock();
#endif

	}
#endif



/*
	if (setitimer( ITIMER_REAL, &val, 0 ) == -1)
                perror("alarm" );
*/
	return TRUE;

}

#ifndef COMPACK_SIZE
void lib1x_get_NumSTA( Dot1x_Authenticator * auth)
{

	int	i;
	u_long ulNumSTA = 0;

	for(i = 0 ; i <  auth->MaxSupplicant ; i++ )
// reduce pre-alloc memory size, david+2006-02-06		
//		if(auth->Supp[i]->isEnable)
		if(auth->Supp[i] && auth->Supp[i]->isEnable)
			ulNumSTA++;
	auth->NumOfSupplicant = ulNumSTA;
}
#endif

//--------------------------------------------------
// lib1x_auth_process:
//	Execute state machine for event from ethernet,
//	wireless, driver interface
//--------------------------------------------------
void lib1x_auth_process(Dot1x_Authenticator * auth )
{

	Global_Params	*global;
	Auth_Pae 	* auth_pae;
	BOOLEAN		transitionResult;
	int		i;

	for(i = 0; i < auth->MaxSupplicant ; i++)
	{
// reduce pre-alloc memory size, david+2006-02-06
//		if(! auth->Supp[i]->isEnable)
		if(auth->Supp[i]==NULL || !auth->Supp[i]->isEnable)
			continue;

		lib1x_message( MESS_DBG_AUTH, "supp index:%d\n",i);

		global = auth->Supp[i]->global;
		auth_pae = global->theAuthenticator;

		if(auth->RSNVariable.Dot1xEnabled || auth->RSNVariable.MacAuthEnabled)
		{
			transitionResult = lib1x_trans_authsm( global );
			lib1x_message(MESS_DBG_AUTH," Executing Initialization");

			if(transitionResult)
			{
				lib1x_authsm_dump( stdout, auth_pae );
			}

			if ( transitionResult )
				lib1x_authsm_execute_authsm( global );


			// Reauthentication Timer State Machine.
			lib1x_message(MESS_DBG_AUTH," Running Reauthentication Timer State Machine");
			lib1x_trans_reauthsm( global , auth_pae->reauth_sm);


			// Backend Authentication State Machine
			lib1x_message(MESS_DBG_AUTH," Running Backend Authentication State Machine");
			lib1x_bauthsm( auth_pae, global, auth_pae->bauth_sm );


			// Authenticator Key Transmit State Machine.
			lib1x_message(MESS_DBG_AUTH," Authenticator Key Transmit State Machine");
			lib1x_trans_kxsm(  auth_pae, global, auth_pae->keyxmit_sm );


			// Controlled Directions State Machine
			lib1x_message(MESS_DBG_AUTH," Running Controlled Directions State Machine");
			lib1x_trans_cdsm(  auth_pae,  global, auth_pae->ctrl_sm );


			lib1x_message(MESS_DBG_AUTH," Running Key Receive State Machine");
			lib1x_trans_krcsm(  global, auth_pae->krc_sm );


			// Accounting State Machine.

			if(auth->AccountingEnabled)
			{

				//lib1x_acctsm( auth_pae, global, auth_pae->acct_sm);
			}

		}//if(do_event && auth->RSNVariable.Dot1xEnabled || auth->RSNVariable.MacAuthEnabled)
		//lib1x_message(MESS_DBG_KEY_MANAGE, " Running Key Manage State Machine");
		if((transitionResult = lib1x_akmsm_trans( global )))
			lib1x_akmsm_execute( global );

	}//for i

}


//--------------------------------------------------
// lib1x_do_authenticator:
// This function does an authenticator's job .. i.e. runs
// the state machines .. one transition.
//  Call this in a loop !
//--------------------------------------------------
int lib1x_do_authenticator( Dot1x_Authenticator * auth )
{
	/*
	Global_Params	*global;
	Auth_Pae 	* auth_pae;
	BOOLEAN		transitionResult;
	int		i;
	*/

	// david ------
	//int loop, do_event;
	int do_event;



	if (  auth == NULL )
	{
		lib1x_message(MESS_ERROR_FATAL, " Null argument received.");
		exit(1);
	}
	if ( auth->currentRole != role_Authenticator)
	{
		lib1x_message(MESS_ERROR_FATAL, " lib1x_do_authenticator: Called with Supplicant Role.");
		return TRUE;
	}


// david -----------------------------
//	for (loop=0; loop<3; loop++)
	{
		do_event = 1;
//------------


		lib1x_message(MESS_DBG_AUTH,"Calling the packet listener");

// david -----------------------------
//		lib1x_authsm_listen_action( auth, auth->GlobalTxRx);		// captures packets, updates variables.
		while (do_event) {
			// emily
			lib1x_nal_receive(auth);
   			//do_event=lib1x_authsm_listen_action(loop, auth, auth->GlobalTxRx);
   			lib1x_auth_process(auth);
//-------------------------------------

// emily -----------------------------
/*

			for(i = 0; i < auth->MaxSupplicant && auth->Supp[i]->isEnable ; i++)
			{

				global = auth->Supp[i]->global;
				auth_pae = global->theAuthenticator;

				// First check receipt of any packets.
				// first the auth_pae state machine

// for debug
// david
			if(auth->RSNVariable.Dot1xEnabled || auth->RSNVariable.MacAuthEnabled)
//				if(do_event && auth->RSNVariable.Dot1xEnabled || auth->RSNVariable.MacAuthEnabled)
				{
					//printf("test\n");
					transitionResult = lib1x_trans_authsm( global );
					lib1x_message(MESS_DBG_AUTH," Executing Initialization");

					if(transitionResult)
					{
						lib1x_authsm_dump( stdout, auth_pae );
					}

					if ( transitionResult )
						lib1x_authsm_execute_authsm( global );


					// Reauthentication Timer State Machine.
					lib1x_message(MESS_DBG_AUTH," Running Reauthentication Timer State Machine");
					lib1x_trans_reauthsm( global , auth_pae->reauth_sm);


					// Backend Authentication State Machine
					lib1x_message(MESS_DBG_AUTH," Running Backend Authentication State Machine");
					lib1x_bauthsm( auth_pae, global, auth_pae->bauth_sm );


					// Authenticator Key Transmit State Machine.
					lib1x_message(MESS_DBG_AUTH," Authenticator Key Transmit State Machine");
					lib1x_trans_kxsm(  auth_pae, global, auth_pae->keyxmit_sm );


					// Controlled Directions State Machine
					lib1x_message(MESS_DBG_AUTH," Running Controlled Directions State Machine");
					lib1x_trans_cdsm(  auth_pae,  global, auth_pae->ctrl_sm );


					lib1x_message(MESS_DBG_AUTH," Running Key Receive State Machine");
					lib1x_trans_krcsm(  global, auth_pae->krc_sm );


					// Accounting State Machine.

					if(auth->AccountingEnabled)
					{

						//lib1x_acctsm( auth_pae, global, auth_pae->acct_sm);
					}

				}//if(do_event && auth->RSNVariable.Dot1xEnabled || auth->RSNVariable.MacAuthEnabled)
				//lib1x_message(MESS_DBG_KEY_MANAGE, " Running Key Manage State Machine");
				if((transitionResult = lib1x_akmsm_trans( global )))
					lib1x_akmsm_execute( global );

			}//for(i = 0; i < auth->MaxSupplicant && auth->Supp[i]->isEnable ; i++)
*/
//------------------------
// david ------------
//			if (!do_event)
//				break;

	   	}//while (do_event)
	}//for (loop=0; loop<3; loop++)
//--------------------


	return TRUE;

}


//--------------------------------------------------
// lib1x_authsm_listen_action:
//  This function parses the eapol packet and takes
//  various actions.
//  Here we assume that the role is Authenticator
//--------------------------------------------------
// david
#if 0
int lib1x_authsm_listen_action( int which, Dot1x_Authenticator *auth, TxRx_Params * txrx)
{
	//Auth_Pae      		* auth_pae = global->theAuthenticator;
	Global_Params		global;
// david
//	static	u_char		which = 0;
int ret = 0;
	/* which determines which interface to poll, we poll one interface at a time - this
	*  provides us the abstraction of a sequence of events being processed by the
	*  state machines
	*/


	// TODO: Need a generic technique for confirming the source address.
	// 1. Get packets from nal.
	// 2. parse out EAPOL packets.

	// check both interfaces


	if ((which%3) == 0)
	{
		//printf("-------CALL Wireless\n");

// david
//		lib1x_nal_receivepoll( auth, txrx->network_supp , lib1x_authsm_capture_supp,  ( u_char * )&global);
ret=lib1x_nal_receivepoll( auth, txrx->network_supp , lib1x_authsm_capture_supp,  ( u_char * )&global);
	}
	else	if ((which%3) == 1  && (auth->RSNVariable.Dot1xEnabled || auth->RSNVariable.MacAuthEnabled))

	{
		//printf("-------CALL Ethernet\n");
// david
//		lib1x_nal_receivepoll( auth, txrx->network_svr , lib1x_authsm_capture_svr ,  ( u_char * )&global);
ret=lib1x_nal_receivepoll( auth, txrx->network_svr , lib1x_authsm_capture_svr ,  ( u_char * )&global);

	}

	else	if ((which%3) == 2)
	{
		//printf("Receive fifo\n");
// david
//		lib1x_nal_receivefifo(auth);
ret=lib1x_nal_receivefifo(auth);



	}
return ret; // david


// david
//	which++;
//	if(which == 3)
//		which = 0;

	//which = !which;

	//lib1x_nal_receivefifo( auth );

}
#endif


//--------------------------------------------------
// Callback handler for libpcap for packets
// from supplicant
//--------------------------------------------------
void lib1x_authsm_capture_supp( Global_Params * global, struct lib1x_nal_intfdesc * nal, struct lib1x_packet * spkt )
{
	struct lib1x_eapol     * eapol;
	struct lib1x_ethernet  * eth;
	Auth_Pae	       * auth_pae;

	u_char		       * packet;

	packet = (u_char *) spkt->data;
	eth = (struct lib1x_ethernet * ) packet;
	eapol = ( struct lib1x_eapol * ) ( packet + ETHER_HDRLEN );
	if ( spkt->caplen <= ( ETHER_HDRLEN + LIB1X_EAPOL_HDRLEN ) )
	{
	       lib1x_message( MESS_DBG_AUTHNET, "Too small a packet received from nal.");
	       //return;
	}
	auth_pae = global->theAuthenticator;

	//lib1x_message(MESS_DBG_AUTHNET, "Received a packet - SUPPLICANT ! phew !\n");
#ifdef RTL_WPA2_PREAUTH
	if ( (eth->ether_type != htons(PREAUTH_ETHER_EAPOL_TYPE))
	     && (eth->ether_type != htons(LIB1X_ETHER_EAPOL_TYPE)) )
#else
	if ( eth->ether_type != htons(LIB1X_ETHER_EAPOL_TYPE) )
#endif
		return;

	if(eapol->packet_type != LIB1X_EAPOL_START)
		KeyDump("lib1x_authsm_capture_supp", packet, spkt->caplen,"Receive EAPOL-KEY");



	switch( eapol->packet_type )
	{
		case	LIB1X_EAPOL_LOGOFF :
			// Page 53.
			auth_pae->eapLogoff = TRUE;
			if(global->auth->AccountingEnabled)
			{
				// 0825
				global->akm_sm->ErrorRsn = acct_user_request;
				global->EventId = akmsm_EVENT_Disconnect;
				lib1x_akmsm_Disconnect( global );
				lib1x_acctsm_request(global, acctsm_Acct_Stop, LIB1X_ACCT_REASON_USER_REQUEST);
				//
			}
			lib1x_message( MESS_DBG_AUTHNET, " EAPOL LOGOFF");
			break;
		case	LIB1X_EAPOL_START  :

			/*
			if(!global->akm_sm->IgnoreEAPOLStartCounter)
			{
				lib1x_message(MESS_DBG_SPECIAL, "*************************Receive EAPOL_START********************************\n");
				auth_pae->eapStart = TRUE;
				global->akm_sm->eapStart = TRUE;
			}else
			{
				lib1x_message(MESS_DBG_SPECIAL, "*************************Dircard EAPOL_START\n");

			}

			// make sure the state m/c is enabled !
			auth_pae->isSuppPresent = TRUE;



			if(global->AuthKeyMethod == DOT11_AuthKeyType_PRERSN)
			{
				global->AuthKeyMethod = DOT11_AuthKeyType_NonRSN802dot1x;
				global->RSNVariable.UnicastCipher = global->auth->RSNVariable.WepMode;
				//global->AuthKeyMethod = DOT11_AuthKeyType_RSN;
			}
			lib1x_message( MESS_DBG_SPECIAL, "AUTHENTICATOR> EAPOL START");
			//---- If 0706
			lib1x_handle_eapol_start(global);
			//----Else
			//----Endif
			*/
			break;

		case	LIB1X_EAPOL_EAPPKT:
			// Page 53.
			// TODO: Parse EAP PACKET and if EAP Response/Identity Packet
			// is received set rxRespId of authpae to TRUE;
			lib1x_message( MESS_DBG_SPECIAL, "AUTHENTICATOR> EAPOL EAP PKT");
			if(global->AuthKeyMethod == DOT11_AuthKeyType_PRERSN)
			{
				global->AuthKeyMethod = DOT11_AuthKeyType_NonRSN802dot1x;
				global->RSNVariable.UnicastCipher = global->auth->RSNVariable.WepMode;

			}
			lib1x_handle_eapsupp( global, spkt);


			break;
#ifdef _RTL_WPA_UNIX
		case	LIB1X_EAPOL_KEY:
			lib1x_message( MESS_DBG_SPECIAL, "AUTHENTICATOR> EAPOL KEY");
			lib1x_handle_eapsupp_key(global, spkt);
			break;
#endif
	}
	//lib1x_akmsm_dump(global);



}


#ifndef COMPACK_SIZE
//--------------------------------------------------
// filter out packets .. return TRUE only for 'our' pkts
//--------------------------------------------------
BOOLEAN lib1x_filter( struct lib1x_packet * pkt, u_char * ether_src, struct in_addr * ip_src, struct in_addr * ip_dst, u_short srcport,
		 u_short dstport )
{
	struct lib1x_ethernet * eth;
	struct lib1x_iphdr       * ip;
	struct lib1x_udphdr      * udp;

	eth = ( struct lib1x_ethernet * ) pkt->data;

	if ( memcmp( eth->ether_shost, ether_src, ETHER_HDRLEN ) != 0 )
	{
		lib1x_message(MESS_DBG_RAD, "lib1x_filter: Mismatch SRC ADDR ");
		return FALSE;
	}
	if ( ntohs(eth->ether_type) != LIB1X_ETHER_IP )
	{
		lib1x_message(MESS_DBG_RAD, "lib1x_filter: NOT AN IP PACKET");
		return FALSE;
	}
	ip = ( struct lib1x_iphdr * ) ( pkt->data + ETHER_HDRLEN );
	if ( memcmp( &(ip->ip_src), ip_src , sizeof( struct in_addr ) ) != 0 )
	{
		lib1x_message(MESS_DBG_RAD, "lib1x_filter: Incorrect Source Address");
		return FALSE;
	}
	if ( memcmp( &ip->ip_dst, ip_dst , sizeof( struct in_addr ) ) != 0 )
	{
		lib1x_message(MESS_DBG_RAD, "lib1x_filter: Incorrect Destination Address");
		return FALSE;
	}
        udp = ( struct lib1x_udphdr * )  ( pkt->data + ETHER_HDRLEN + LIB1X_IPHDRLEN + LIB1X_UDPHDRLEN ) ;
	if  ( (ntohs( udp->sport )!=srcport) || (ntohs(udp->dport)!=dstport) )
	{
		lib1x_message(MESS_DBG_RAD, "lib1x_filter: Port Mismatch");
		return FALSE;

	}
	return TRUE;
}
#endif
#ifndef COMPACK_SIZE
//--------------------------------------------------
// The RADIUS server sends - IP packets and
// actually they do get fragmented !!
//--------------------------------------------------
struct lib1x_packet *  lib1x_checkfragments( Global_Params * global, struct lib1x_nal_intfdesc * nal, struct lib1x_packet * pkt )
{
	static u_char *frag_buffer = NULL;
	static int    frag_len = 0;
	static  u_short   pid; /* packet id for matching fragments */

	Auth_Pae      * auth_pae;
	struct lib1x_iphdr  * ip;
	struct      lib1x_packet * newpkt;
	u_short	     cid;


	/* no harm in allocating some good memory here */
	/* set frag_len to zero if its a new packet */
	auth_pae = global->theAuthenticator;
	if (  ! lib1x_filter( pkt, global->TxRx->svr_addr, & global->TxRx->svrip_inaddr, & global->TxRx->ourip_inaddr, global->TxRx->udp_svrport, global->TxRx->udp_ourport ) )
	       return NULL;
	ip = ( struct lib1x_iphdr * ) ( pkt->data + ETHER_HDRLEN );
	newpkt = ( struct lib1x_packet * ) malloc( sizeof(struct lib1x_packet ) );
	if ( frag_len == 0 )	/* new sequence of fragments ! */
	{
		if   ( ! ( ip->ip_off & IP_MF ))
		{
			newpkt->data = pkt->data + ETHER_HDRLEN + LIB1X_IPHDRLEN; /* return ptr to UDP data directly */
			newpkt->caplen = pkt->caplen - ETHER_HDRLEN - LIB1X_IPHDRLEN;
			return newpkt;
		}
		memcpy( frag_buffer, pkt->data, pkt->caplen );
		frag_len = ETHER_HDRLEN + ip->ip_len;	/* so that we dont get weird bytes at the end */
		pid = ntohs(ip->ip_off & IP_OFFMASK);	/* get the fragment identifier */
	}
	else
	{
		cid = ip->ip_off & IP_OFFMASK;
		if ( cid != pid ) /* ignore packet ? */
		{
			lib1x_message(MESS_DBG_RAD,"lib1x_checkfragments: cid!= pid");
			return NULL;
		}

				// LEFT CODING HERE as far as the fragments are concerned.
	}
	return newpkt;
}
#endif

#ifdef _RTL_WPA_UNIX
//--------------------------------------------------
// Handler for message from driver
//--------------------------------------------------

int lib1x_capture_control(Global_Params * global, struct lib1x_nal_intfdesc * nal, struct lib1x_packet * spkt)
{

	u_char  *msg = (u_char *) spkt->data;
	int retVal = 0, retResult;
	u_char event;
	u_short	usLength;
	u_long data;
	DOT11_ASSOCIATION_IND * pAssoInd;
	DOT11_DISASSOCIATION_IND * pDisAssoInd;
	u_char	wpaIETag[] = {0x00, 0x50, 0xf2, 0x01};
#ifdef RTL_WPA2
	u_char	wpa2IETag[] = {0x01, 0x00};
	BOOLEAN bWPA2 = FALSE;
#endif

        // The first byte is [event type]
        // The second byte is [more event] flag
        // The starting of thrid byte is message content


	event = *(msg+0);

	//switch event type
	switch(event)
	{
	case DOT11_EVENT_ASSOCIATION_IND:
	case DOT11_EVENT_REASSOCIATION_IND:

			lib1x_message(MESS_DBG_CONTROL, "lib1x_capture_control, Receive DOT11_EVENT_ASSOCIATION_IND(DOT11_EVENT_REASSOCIATION_IND) from Driver");
			pAssoInd = (DOT11_ASSOCIATION_IND *)msg;
			lib1x_N2S((u_char*)&pAssoInd->RSNIELen, usLength);

#if defined(CONFIG_RTL8186_TR) || defined(CONFIG_RTL865X_SC) || defined(CONFIG_RTL865X_AC) || defined(CONFIG_RTL865X_KLD) || defined(CONFIG_RTL8196C_EC)
			LOG_MSG_NOTICE("Wireless PC connected;note:%02x-%02x-%02x-%02x-%02x-%02x;",
				(u_char)pAssoInd->MACAddr[0], (u_char)pAssoInd->MACAddr[1],
				(u_char)pAssoInd->MACAddr[2], (u_char)pAssoInd->MACAddr[3],
				(u_char)pAssoInd->MACAddr[4], (u_char)pAssoInd->MACAddr[5]);	
#endif

			lib1x_message(MESS_DBG_RSNINFO, "RSNIELen = %d", usLength);
#ifdef RTL_WPA2
//			bWPA2 = strncmp(wpa2IETag, pAssoInd->RSNIE, sizeof (wpa2IETag)) == 0? TRUE:FALSE;
			bWPA2 = (pAssoInd->RSNIE[0] == WPA2_ELEMENT_ID) && !strncmp(wpa2IETag, (pAssoInd->RSNIE + 2), sizeof (wpa2IETag))? TRUE:FALSE;
			global->RSNVariable.WPA2Enabled = bWPA2;


			if(usLength && ( (!strncmp(wpaIETag, (pAssoInd->RSNIE + 2), sizeof (wpaIETag))) || bWPA2 ))

#else
			if(usLength && (!strncmp(wpaIETag, pAssoInd->RSNIE, sizeof wpaIETag)) )
#endif
			//---- RSN Client ----
			{

				//---- Add Element ID and Length ----
#ifdef RTL_WPA2
				memcpy(global->akm_sm->SuppInfoElement.Octet, pAssoInd->RSNIE, usLength);
				global->akm_sm->SuppInfoElement.Length = usLength;
#else
				global->akm_sm->SuppInfoElement.Octet[0] = RSN_ELEMENT_ID;
				global->akm_sm->SuppInfoElement.Octet[1] = usLength;
				memcpy(global->akm_sm->SuppInfoElement.Octet + 2, pAssoInd->RSNIE, usLength);
				global->akm_sm->SuppInfoElement.Length = usLength + 2;
#endif

				//---- Disassociate STA if there is fatal error ----
#ifdef RTL_WPA2
				if (bWPA2)
					retResult = lib1x_authWPA2_parseIE(global->auth, global,
								global->akm_sm->SuppInfoElement.Octet,
								global->akm_sm->SuppInfoElement.Length);
				else
					retResult = lib1x_authRSN_parseIE(global->auth, global,
								global->akm_sm->SuppInfoElement.Octet,
								global->akm_sm->SuppInfoElement.Length);
				if ( retResult )
#else
				if((retResult = lib1x_authRSN_parseIE(global->auth, global,
								global->akm_sm->SuppInfoElement.Octet,
								global->akm_sm->SuppInfoElement.Length)))
#endif
				{
					lib1x_message(MESS_DBG_RSNINFO, "lib1x_authRSN_parseIE return Fail");
					lib1x_message(MESS_DBG_RSNINFO, lib1x_authRSN_err(retResult));
#ifdef RTL_WPA2
					lib1x_control_AssociationRsp(global, -retResult, event);
#else
					lib1x_control_AssociationRsp(global, -retResult);
#endif
					global->akm_sm->Disconnect = TRUE;
					goto lib1x_capture_control_END;
				}

				//---- Disassociate STA if request of following policy from STA
				//---- (1)Unicast Cipher Suit (2)  Multicast Cipher suit (3) Authentication Key management
				//---- is not supported by Authenticator

				lib1x_message(MESS_DBG_RSNINFO, "lib1x_authRSN_parseIE return Success\n");
#ifdef RTL_WPA2
				retResult = lib1x_authRSN_match(global->auth, global, bWPA2);
#else
				retResult = lib1x_authRSN_match(global->auth, global);
#endif
				if(retResult)
				{
					lib1x_message(MESS_DBG_RSNINFO, "lib1x_authRSN_match return Fail\n");
					lib1x_message(MESS_DBG_RSNINFO, "Error Reason:%s\n", lib1x_authRSN_err(retResult));
#ifdef RTL_WPA2
					lib1x_control_AssociationRsp(global, -retResult, event);
#else
					lib1x_control_AssociationRsp(global, -retResult);
#endif
					global->akm_sm->Disconnect = TRUE;
					goto lib1x_capture_control_END;
				}

#ifdef RTL_WPA2
				lib1x_control_AssociationRsp(global, 0, event);	// successful
#else
				lib1x_control_AssociationRsp(global, 0);	// successful
#endif

#ifdef RTL_WPA2_PREAUTH
				//printf("%s successful\n", event == DOT11_EVENT_ASSOCIATION_IND?"DOT11_EVENT_ASSOCIATION_IND":"DOT11_EVENT_REASSOCIATION_IND");
#endif
				global->theAuthenticator->eapStart = TRUE;
				global->akm_sm->AuthenticationRequest = TRUE;
				// reset replay counter, david+12-01-2006				
//				memset(&global->akm_sm->CurrentReplayCounter, '\0', sizeof(LARGE_INTEGER));
				
				lib1x_message(MESS_DBG_RSNINFO, "lib1x_authRSN_match return Success\n");
				// david+2006-03-31, add event to syslog
				{
					char *pmsg;
					switch (global->RSNVariable.UnicastCipher) {
						case DOT11_ENC_NONE: pmsg="none"; break;
						case DOT11_ENC_WEP40:	pmsg = "WEP40"; break;
						case DOT11_ENC_TKIP: 	pmsg = "TKIP"; break;
						case DOT11_ENC_WRAP: pmsg = "AES"; break;
					    case DOT11_ENC_CCMP: pmsg = "AES"; break;
						case DOT11_ENC_WEP104: pmsg = "WEP104"; break;
						default: pmsg = "invalid algorithm"; break;
					}
					syslog(LOG_AUTH|LOG_INFO, "%s: %s-%s %s authentication in progress...\n", 
						dev_supp, 
						(bWPA2 ? "WPA2" : "WPA"), 
						pmsg,
						(global->auth->RSNVariable.Dot1xEnabled ?  "RADIUS" : "PSK"));
				}
				// jimmylin+2006-12-06, query wlan mac address because it may be updated when mac-cloned is enabled
				{	
					int skfd;
					struct ifreq ifr;
					struct sockaddr hwaddr;

					skfd = socket(AF_INET, SOCK_DGRAM, 0);
					strcpy(ifr.ifr_name, dev_supp);
					if (ioctl(skfd, SIOCGIFFLAGS, &ifr) >=0) {
						if (ioctl(skfd, SIOCGIFHWADDR, &ifr) >= 0) {
							memcpy(&hwaddr, &ifr.ifr_hwaddr, sizeof(struct sockaddr));
							memcpy(global->TxRx->oursupp_addr, hwaddr.sa_data, 6);
						}
					}
					close(skfd);
				}

			}else
			//---- Not RSN Client. either STA without 802.1x or 802.1x client
			{
				global->AuthKeyMethod = DOT11_AuthKeyType_PRERSN;

				//---- If Association or Re-association happen within expire timeout or idle time-out
				//---- (the state is is authenticated state, send Acct_status-stop with termicate cause)
				if(global->auth->AccountingEnabled)
				{
					lib1x_acctsm_request(global, acctsm_Acct_Stop, LIB1X_ACCT_REASON_USER_REQUEST);
				}

				lib1x_reset_authenticator(global);
				lib1x_control_RemovePTK(global, DOT11_KeyType_Pairwise);
   				lib1x_control_SetPORT(global, DOT11_PortStatus_Unauthorized);

				global->theAuthenticator->eapStart = TRUE;
				global->akm_sm->AuthenticationRequest = TRUE;

#if 0				
				// do not reject if WPA or WPA2 is not set, david 20050708
				if (global->RSNVariable.RSNEnabled ||
#ifdef RTL_WPA2
					global->RSNVariable.WPA2Enabled
#endif
					) {				
#endif
				// Reject if PSK is used when there is IE included, david+2007-0607
				if (global->auth->RSNVariable.AuthenticationSuit.AlgoTable[DOT11_AuthKeyType_RSNPSK].Enabled){
					
					// send assoc response by jimmylin 20050505
					lib1x_message(MESS_DBG_RSNINFO, "without RSNIE");
					lib1x_message(MESS_DBG_RSNINFO, lib1x_authRSN_err(ERROR_INVALID_RSNIE));
#ifdef RTL_WPA2
					lib1x_control_AssociationRsp(global, -ERROR_INVALID_RSNIE, event);
#else
					lib1x_control_AssociationRsp(global, -ERROR_INVALID_RSNIE);
#endif
					global->akm_sm->Disconnect = TRUE;
					goto lib1x_capture_control_END;
				}

				// david+2006-03-31, add event to syslog
				syslog(LOG_AUTH|LOG_INFO, "%s: RADIUS authentication in progress...\n", dev_supp); 
			}
			break;

	case DOT11_EVENT_AUTHENTICATION_IND:
			goto lib1x_capture_control_END;
	    	break;
	case DOT11_EVENT_DEAUTHENTICATION_IND:
	 		//global->akm_sm->DeauthenticationRequest = TRUE;
	 		break;
	case DOT11_EVENT_DISASSOCIATION_IND:
			//printf("\n---------------------------------------------------------------------\n");
			//printf("---------------DOT11_EVENT_DISASSOCIATION_IND------------------------\n");
			//printf("---------------------------------------------------------------------\n");
			pDisAssoInd = (DOT11_DISASSOCIATION_IND *)msg;
			memcpy(&global->theAuthenticator->acct_sm->tx_packets, (void *)((unsigned int)pDisAssoInd + (int)(&((DOT11_DISASSOCIATION_IND *)0)->tx_packets)), sizeof(unsigned long));       // == transmited packets
	 		memcpy(&global->theAuthenticator->acct_sm->rx_packets, (void *)((unsigned int)pDisAssoInd + (int)(&((DOT11_DISASSOCIATION_IND *)0)->rx_packets)), sizeof(unsigned long));       // == received packets
	 		memcpy(&global->theAuthenticator->acct_sm->tx_bytes, (void *)((unsigned int)pDisAssoInd + (int)(&((DOT11_DISASSOCIATION_IND *)0)->tx_bytes)), sizeof(unsigned long));         // == transmited bytes
	 		memcpy(&global->theAuthenticator->acct_sm->rx_bytes, (void *)((unsigned int)pDisAssoInd + (int)(&((DOT11_DISASSOCIATION_IND *)0)->rx_bytes)), sizeof(unsigned long));         // == received bytes
	 		lib1x_message(MESS_DBG_ACCT, "tx_packets= %d", global->theAuthenticator->acct_sm->tx_packets);
	 		lib1x_message(MESS_DBG_ACCT, "rx_packets= %d", global->theAuthenticator->acct_sm->rx_packets);
	 		lib1x_message(MESS_DBG_ACCT, "tx_bytes= %d", global->theAuthenticator->acct_sm->tx_bytes);
	 		lib1x_message(MESS_DBG_ACCT, "rx_bytes= %d", global->theAuthenticator->acct_sm->rx_bytes);
	 		global->EventId = akmsm_EVENT_Disassociate;

			//sc_yang 1x doesn't have to disconnect again
			//global->akm_sm->Disconnect = TRUE;

			memcpy(&data, (void *)((unsigned int)pDisAssoInd + (int)(&((DOT11_DISASSOCIATION_IND *)0)->Reason)), sizeof(unsigned long));
			global->akm_sm->ErrorRsn = (u_short)data;
			lib1x_message(MESS_DBG_SPECIAL, "Disassiciate Reason is %d\n", global->akm_sm->ErrorRsn);
			//lib1x_hexdump2(MESS_DBG_SPECIAL, "lib1x_capture_control", (u_char*)pDisAssoInd, sizeof(DOT11_DISASSOCIATION_IND), "Disassociation");
			//sc_yang to disconnect from 1x  only (disconnect)
			lib1x_akmsm_Disconnect(global);
			break;

	    //----If 07-06
	case DOT11_EVENT_EAPOLSTART:
			if(global->bMacAuthEnabled && !global->authSuccess)
			{
#ifndef _ABOCOM
				if(global->auth->RSNVariable.Dot1xEnabled)
				{
					global->bMacAuthEnabled = FALSE;
					global->theAuthenticator->eapStart = TRUE;
					global->akm_sm->eapStart = TRUE;
				}
#else
				lib1x_message(MESS_DBG_SPECIAL, "Dircard EAPOL_START because MacAuthEnabled is enabled\n");
#endif
			}
			else if(global->bMacAuthEnabled && global->authSuccess)
			{
#ifndef _ABOCOM
				if(global->auth->RSNVariable.Dot1xEnabled)
				{
					global->theAuthenticator->eapStart = TRUE;
					global->akm_sm->eapStart = TRUE;
				}
#else
				lib1x_message(MESS_DBG_SPECIAL, "According to ABOCOM Project, MAC Authentication success STA can not reauthentication with EAP-MD5\n");
#endif
			}
			else if(!global->bMacAuthEnabled)
			{
				//Two cases : 	(1)AP does not turn on MAC in UI
				//		(2)AP Turns on MAC in UI, but STA fails to authenticate with MAC authentication
				if(!global->akm_sm->IgnoreEAPOLStartCounter)
				{
					lib1x_message(MESS_DBG_SPECIAL, "Receive EAPOL_START, Take effect in state machine\n");
					global->theAuthenticator->eapStart = TRUE;
					global->akm_sm->eapStart = TRUE;
				}else
				{
					lib1x_message(MESS_DBG_SPECIAL, "Dircard EAPOL_START because EAP-ReqestID has already been sent\n");
				}
			}

			// make sure the state m/c is enabled !
			global->theAuthenticator->isSuppPresent = TRUE;

			//0825
			if(global->AuthKeyMethod == DOT11_AuthKeyType_PRERSN ||
				global->AuthKeyMethod == DOT11_AuthKeyType_NonRSN802dot1x||
				global->AuthKeyMethod == DOT11_AuthKeyType_RSNReserved)
			{
				global->AuthKeyMethod = DOT11_AuthKeyType_NonRSN802dot1x;
				global->RSNVariable.UnicastCipher = global->auth->RSNVariable.WepMode;
				//0825
				if(global->akm_sm->eapStart == TRUE)
					lib1x_reset_authenticator(global);
			}

			break;
#ifdef RTL_WPA2_PREAUTH
	case DOT11_EVENT_EAPOLSTART_PREAUTH:
			lib1x_message(MESS_DBG_SPECIAL, "Receive EAPOL_START_PREAUTH, Take effect in state machine\n");
			global->theAuthenticator->eapStart = TRUE;
			global->akm_sm->eapStart = TRUE;
			global->akm_sm->AuthenticationRequest = TRUE;
			// make sure the state m/c is enabled !
			global->theAuthenticator->isSuppPresent = TRUE;
			global->RSNVariable.isPreAuth = TRUE;
			printf("global->AuthKeyMethod = %d\n", global->AuthKeyMethod);
			global->AuthKeyMethod = DOT11_AuthKeyType_RSN;
			global->akm_sm->state = akmsm_AUTHENTICATION2;
			global->akm_sm->gstate = gkmsm_REKEYNEGOTIATING;
			break;
#endif

	}//end switch(event)

	//lib1x_akmsm_dump(global);


	if(lib1x_akmsm_trans(global))
	{
		lib1x_akmsm_execute(global);
		if(event == DOT11_EVENT_ASSOCIATION_IND || event == DOT11_EVENT_REASSOCIATION_IND)
			 global->akm_sm->IgnoreEAPOLStartCounter = REJECT_EAPOLSTART_COUNTER;
	}


lib1x_capture_control_END:
        return retVal;

}


#endif //_RTL_WPA_UNIX


#define _AUTH_DBGMSG(fmt, args...)	\
			do {printf("[%s-%d]-DEBUG-: " fmt "\n", __FUNCTION__, __LINE__, ## args);} while (0)


//--------------------------------------------------
// Callback handler for libpcap for packets from
// authentication server BIG TODO HERE !!!!!!!
//--------------------------------------------------
void lib1x_authsm_capture_svr( Global_Params * global, struct lib1x_nal_intfdesc * nal, struct lib1x_packet * pkt )
{
	struct lib1x_radiushdr * rhdr;

	Auth_Pae 	       * auth_pae;




	//lib1x_message(MESS_DBG_AUTHNET, "Received a packet - SERVER! phew !\n");
	auth_pae = global->theAuthenticator;
	rhdr = ( struct lib1x_radiushdr * ) pkt->data;
	lib1x_message( MESS_DBG_SPECIAL, "Radius code:%d\n",rhdr->code);
	switch( rhdr->code )
	{
		case	LIB1X_RAD_ACCACT:

						auth_pae->bauth_sm->aSuccess = TRUE;
						auth_pae->rinfo->rad_stateavailable = FALSE;
						lib1x_process_radiusaccept( global, pkt);
						lib1x_message( MESS_DBG_SPECIAL, "AUTHENTICATION SUCCEEDED ! Accept Packet received from AuthServer");
						break;
		case	LIB1X_RAD_ACCREJ:
						auth_pae->bauth_sm->aFail = TRUE;
						if(global->bMacAuthEnabled)
						{
							lib1x_message(MESS_DBG_SPECIAL, "MacAuthentication Fail\n");
							if(global->auth->RSNVariable.Dot1xEnabled)
							{
								//If Mac Authentication fail, and EAP is choosed, send req userID
								auth_pae->bauth_sm->aFail = FALSE;
								global->reAuthenticate = TRUE;
								global->bMacAuthEnabled = FALSE;
								lib1x_message(MESS_DBG_SPECIAL, "Change from Phase 1 MAC Auth to Phase 2 Radius\n");
							}
						}
						else
						{

							global->EventId = akmsm_EVENT_Disconnect;
							global->akm_sm->Disconnect = TRUE;
							global->akm_sm->ErrorRsn = auth_not_valid;
							lib1x_akmsm_Disconnect(global);

						}
						lib1x_message( MESS_AUTH_LOG, "AUTHENTICATION FAILED ! Reject Packet received from AuthServer");
						break;
		case	LIB1X_RAD_ACCCHL:
						lib1x_process_radiuschallenge( global,  pkt);
						lib1x_message( MESS_DBG_SPECIAL, "AUTHENTICATION RADIUS CHAL");						
						break;
		case 	LIB1X_RAD_ACCTRSP:
						lib1x_process_radiusacct(global, pkt);
						lib1x_message( MESS_DBG_SPECIAL, "AUTHENTICATION RADIUS Accounting Respond");
						break;
	}

}

//--------------------------------------------------
// Process the radius accept message
// to dereive MS-MPPE-Key. start with radius header
//--------------------------------------------------
void lib1x_process_radiusaccept( Global_Params * global, struct lib1x_packet * spkt)
{

	Auth_Pae		* auth_pae;
        struct lib1x_radiushdr  * rhdr;
        struct lib1x_radiusattr * rattr;
	struct lib1x_eap        * eap;
        u_char done;
        u_short  unexplen;
        int  tmplen;
        u_char *eap_ptr;
	u_char *vendor_ptr;
	u_long vendor;
        BOOLEAN first_eap = FALSE;      /* the first EAP attribute */

	lib1x_message( MESS_DBG_RAD, "lib1x_process_radiusaccept(1)");
	auth_pae = global->theAuthenticator;

        rhdr = ( struct lib1x_radiushdr * ) spkt->data ;
        rattr = ( struct lib1x_radiusattr * ) ( spkt->data + LIB1X_RADHDRLEN );

	done = 0;
	unexplen = ntohs(rhdr->length) - LIB1X_RADHDRLEN;

        // cycle through the attributes
	eap_ptr = auth_pae->rinfo->eap_message_frmserver;
        auth_pae->rinfo->eap_messlen_frmserver = 0;
        first_eap = FALSE;
        auth_pae->rinfo->rad_stateavailable = FALSE;

	while (!done )
        {
		if ( rattr->type == LIB1X_RAD_EAP_MESSAGE )
		//ToDo: Process EAP Message
                {
                        tmplen = rattr->length - 2; // 2 is the size of len + type fields
                        memcpy( eap_ptr + auth_pae->rinfo->eap_messlen_frmserver , ((u_char * ) rattr) + 2, tmplen );
                        auth_pae->rinfo->eap_messlen_frmserver += tmplen ;
                        if ( first_eap == FALSE )
                        {
                                first_eap = TRUE;
                                eap = ( struct lib1x_eap * ) (  ( ( u_char *  )rattr ) + 2 );
                                auth_pae->send_eapptr = ( struct lib1x_eap * )eap_ptr;
                                lib1x_store_eap( auth_pae,  ( u_char *  )eap  , spkt, 0, 0, 0, 0, 1 );
                                //lib1x_message( MESS_DBG_RAD," FIRST EAP ATTRIBUTE");
                        }
                        else
			{
                                //lib1x_message( MESS_DBG_RAD," NEXT EAP ATTRIBUTE");
			}
                        if ( tmplen <= 3 )
                                lib1x_message( MESS_ERROR_OK,"Received very short malformed EAP message field from RADIUS server ");
                        lib1x_message(MESS_DBG_RAD," RESP FROM SERVER: EAP MESSAGE FOUND LENGTH : %d ", rattr->length );
                }
                if ( rattr->type == LIB1X_RAD_VENDOR_SPECIFIC)
                {
			vendor_ptr = ( ( u_char *  )rattr ) + 2;
			lib1x_N2L(vendor_ptr, vendor);
			if(vendor == LIB1X_RADVENDOR_MS)
				lib1x_rad_vendor_attr(global, ((u_char *)rattr) + 6, rattr->length - 6);
                }
		//Accounting
		if( rattr->type == LIB1X_RAD_SESSION_TIMEOUT)
		{
			lib1x_rad_session_timeout(global, ((u_char *)rattr), rattr->length);
		}
		if( rattr->type == LIB1X_RAD_IDLE_TIMEOUT)
		{
			lib1x_rad_idle_timeout(global, ((u_char *)rattr), rattr->length);
		}
		if( rattr->type == LIB1X_RAD_ACCT_INTERIM_TIMEOUT)
			lib1x_rad_interim_timeout(global, ((u_char *)rattr), rattr->length);
		//
                if (!done )
                {
                        unexplen -= rattr->length;
                        lib1x_message( MESS_DBG_RAD," -------  UNEXP LEN = %d", unexplen );
                        if ( unexplen <= 2 )
                        {
                                if ( first_eap == FALSE )
					lib1x_message(MESS_DBG_RAD, "No EAP message found in radius packet");
                                done = 1;
                        } else
                        {
                                rattr = ( struct lib1x_radiusattr * )(  (  (u_char *) rattr ) + rattr->length );
                                /* this should send rattr to the next rattr */
                        }
                        if (rattr->length <= 0 ) done =1 ;
                }
        }


        if ( done )
        {
		if(global->bMacAuthEnabled ||
		   (global->RSNVariable.UnicastCipher == DOT11_ENC_NONE ||
		   ((global->RSNVariable.UnicastCipher == DOT11_ENC_WEP40 || global->RSNVariable.UnicastCipher == DOT11_ENC_WEP104) &&
		    global->theAuthenticator->keyxmit_sm->keyAvailable == FALSE)) //Ex: EAP-MD5 with static wep encrypption
		   )
			lib1x_control_SetPORT(global, DOT11_PortStatus_Authorized);
#ifdef _ABOCOM
		lib1x_abocom(global->theAuthenticator->supp_addr, ABOCOM_ADD_STA);
#endif
		lib1x_rad_eapresp_svr( auth_pae, spkt, LIB1X_RAD_ACCACT);
                lib1x_message(MESS_DBG_RAD,"-------------   Done parsing RADIUS packet");
        }
}



//--------------------------------------------------
// Process the radius challenge message .. radpkt
// should start with the radius header.
//--------------------------------------------------
void lib1x_process_radiuschallenge( Global_Params * global, struct lib1x_packet * spkt)
{
	Auth_Pae                * auth_pae;
	struct lib1x_radiushdr  * rhdr;
	struct lib1x_radiusattr * rattr;
	struct lib1x_eap        * eap;
	struct lib1x_eap	teap;
	u_char done;
	u_short  unexplen;
	int  tmplen;
	u_char *eap_ptr;
	BOOLEAN first_eap;	/* the first EAP attribute */


	auth_pae = global->theAuthenticator;

	rhdr = ( struct lib1x_radiushdr * ) spkt->data ;

	rattr = ( struct lib1x_radiusattr * ) ( spkt->data + LIB1X_RADHDRLEN );

	eap = ( struct lib1x_eap *  )&teap;

	done = 0;
	unexplen = ntohs(rhdr->length) - LIB1X_RADHDRLEN;
	// cycle through the attributes
	// we need to combine many messages of len 255 if needed
	eap_ptr = auth_pae->rinfo->eap_message_frmserver;

	auth_pae->rinfo->eap_messlen_frmserver = 0;
	first_eap = FALSE;
	auth_pae->rinfo->rad_stateavailable = FALSE;
	while (!done )
	{
		rattr->type = ntohs(rattr->type);
		if ( rattr->type == LIB1X_RAD_EAP_MESSAGE )
		{
			tmplen = rattr->length - 2; // 2 is the size of len + type fields
			memcpy( eap_ptr + auth_pae->rinfo->eap_messlen_frmserver , ((u_char * ) rattr) + 2, tmplen );
			auth_pae->rinfo->eap_messlen_frmserver += tmplen ;
			if ( first_eap == FALSE )
			{
				first_eap = TRUE;
				eap = ( struct lib1x_eap * ) (  ( ( u_char *  )rattr ) + 2 );
				auth_pae->send_eapptr = ( struct lib1x_eap * )eap_ptr;
				lib1x_store_eap( auth_pae,  ( u_char *  )eap  , spkt, 0, 0, 0, 0, 1 );
				lib1x_message( MESS_DBG_RAD," FIRST EAP ATTRIBUTE");
			}
			else {
				lib1x_message( MESS_DBG_RAD," NEXT EAP ATTRIBUTE");
			}
			if ( tmplen <= 3 ) {
				lib1x_message( MESS_ERROR_OK,"Received very short malformed EAP message field from RADIUS server ");
			}
			lib1x_message(MESS_DBG_RAD," RESP FROM SERVER: EAP MESSAGE FOUND LENGTH : %d ", rattr->length );
		}
		if ( rattr->type == LIB1X_RAD_MESS_AUTH )
		{
			lib1x_message(MESS_AUTH_LOG," Received Message Authenticator from radius server");
		}
		if ( rattr->type == LIB1X_RAD_STATE )
		{
			auth_pae->rinfo->rad_stateavailable = TRUE;
			memcpy( auth_pae->rinfo->radius_state, ( (u_char *)rattr) + 2 , rattr->length - 2 );
			auth_pae->rinfo->rad_statelength = rattr->length - 2;
			lib1x_message(MESS_DBG_RAD," Received STATE Attribute from radius server");
		}
		if (!done )
		{
			unexplen -= rattr->length;
			lib1x_message( MESS_DBG_RAD," -------  UNEXP LEN = %d", unexplen );
			if ( unexplen <= 2 )
			{
				if ( first_eap == FALSE ) lib1x_message(MESS_ERROR_OK, "No EAP message found in radius packet");
				if ( first_eap == FALSE ) _AUTH_DBGMSG(">>>  No EAP message found in radius packet");
				done = 1;
			} else
			{
				rattr = ( struct lib1x_radiusattr * )(  (  (u_char *) rattr ) + rattr->length );
				/* this should send rattr to the next rattr */
			}
			if (rattr->length <= 0 ) done =1 ;
		}
	}


	if ( done )
	{
		lib1x_rad_eapresp_svr( auth_pae, spkt, LIB1X_RAD_ACCCHL);
		auth_pae->bauth_sm->aReq = TRUE;
		auth_pae->bauth_sm->idFromServer = eap->identifier;
		lib1x_message(MESS_DBG_RAD,"-------------   Done parsing RADIUS packet that is will be forwarded to Supp[%d]", global->index);
	}

}

//--------------------------------------------------
// Process response from accounting server
//--------------------------------------------------
void lib1x_process_radiusacct( Global_Params * global, struct lib1x_packet * spkt)
{
	global->theAuthenticator->acct_sm->waitRespond = FALSE;

}
//--------------------------------------------------
// finds an empty slot and stores it
//--------------------------------------------------
void lib1x_store_eap( Auth_Pae * auth_pae, u_char * packet , struct lib1x_packet * pkthdr, u_char eap_code, u_char eap_id ,u_char eaprr_type, u_char fromsupp, u_char fromserver)
{

	int copylen = LIB1X_MAXEAPLEN -1; // just to be sure


	if ( fromsupp == 1 )
	{
		auth_pae->fromsupp.length = pkthdr->caplen;
		if ( copylen > pkthdr->caplen ) copylen = pkthdr->caplen;
		//auth_pae->fromsupp.pkt = ( u_char *) malloc( copylen + 1 );
		memcpy( auth_pae->fromsupp.pkt, packet,  copylen );
		auth_pae->fromsupp.eap_code = eap_code;
		auth_pae->fromsupp.eap_id = eap_id;
		auth_pae->fromsupp.eaprr_type = eaprr_type;
	}

	if ( fromserver  == 1 )
	{
		auth_pae->fromsvr.length = pkthdr->caplen;
		if ( copylen > pkthdr->caplen ) copylen = pkthdr->caplen;
		//auth_pae->fromsvr.pkt = ( u_char *) malloc( copylen + 1 );
		memcpy( auth_pae->fromsvr.pkt, packet,  copylen );
		auth_pae->fromsvr.eap_code = eap_code;
		auth_pae->fromsvr.eap_id = eap_id;
		auth_pae->fromsvr.eaprr_type = eaprr_type;
	}


}

//--------------------------------------------------
//  handle eap parsing etc for packets from
//  supplicant
//--------------------------------------------------
void lib1x_handle_eapsupp( Global_Params * global,  struct lib1x_packet * pkthdr)
{
	struct lib1x_eapol     * eapol;
	struct lib1x_ethernet  * eth;
	struct lib1x_eap       * eap;
	struct lib1x_eap_rr    * eaprr;
	Auth_Pae 	       * auth_pae;

	u_short		       eap_length;
	u_char		       * packet;

	packet = (u_char *) pkthdr->data;


	eth = (struct lib1x_ethernet * ) packet;
	eapol = ( struct lib1x_eapol * ) ( packet + ETHER_HDRLEN );
	eap = (struct lib1x_eap * ) (packet + ETHER_HDRLEN +  LIB1X_EAPOL_HDRLEN);
	eaprr = ( struct lib1x_eap_rr *) ( packet + ETHER_HDRLEN +  LIB1X_EAPOL_HDRLEN + LIB1X_EAP_HDRLEN ) ;

	auth_pae = global->theAuthenticator;
	eap_length = ntohs( eap->length);

	lib1x_message(MESS_DBG_SPECIAL,"lib1x_handle_eapsupp" );
	if (  eap->code == LIB1X_EAP_RESPONSE  )
	{
		eaprr = ( struct lib1x_eap_rr *) ( packet + ETHER_HDRLEN +  LIB1X_EAPOL_HDRLEN + LIB1X_EAP_HDRLEN ) ;
					//Note :IMportant only if it is a response / request
					// packet ..we are sure of existence of such a field.
		/*
		switch(eaprr->type)
		{
		case	LIB1X_EAP_RRIDENTITY:

			if ( global->currentId  != eap->identifier )
			{
				lib1x_message(MESS_ERROR_OK," Received EAP Response Identity packet with mismatching identifier field");
				return;
			}
			auth_pae->rxRespId = TRUE;
			lib1x_store_eap( auth_pae, (u_char *) packet , pkthdr, eap->code, eap->identifier, eaprr->type, 1, 0);
			//---- parses the packet,creates a reply in sendbuf ----
			auth_pae->bauth_sm->rxResp = TRUE;
			lib1x_rad_eapresp_supp( auth_pae, pkthdr );

			break;
		case	LIB1X_EAP_RRNAK:
		case	LIB1X_EAP

			if ( global->currentId  != eap->identifier )
			{
				lib1x_message(MESS_ERROR_OK," Received EAP Response Identity packet with mismatching identifier field");
				return;
			}
			lib1x_store_eap( auth_pae, (u_char *) packet , pkthdr, eap->code, eap->identifier, eaprr->type, 1, 0);
			//---- parses the packet,creates a reply in sendbuf ----
			auth_pae->bauth_sm->rxResp = TRUE;
			lib1x_rad_eapresp_supp( auth_pae, pkthdr );

			break;

		}
		return;
		*/

		if ( eaprr->type  == LIB1X_EAP_RRIDENTITY || eaprr->type  == LIB1X_EAP_RRNAK)
		{

			//if ( memcmp( auth_pae->supp_addr, eth->ether_shost, ETHER_ADDRLEN) != 0 )
			//{
			//	lib1x_message(MESS_ERROR_OK," Received EAP Response Identity packet from non-supplicant ?");
			//	return;
			//}

			if ( global->currentId  != eap->identifier )
			{
				lib1x_message(MESS_ERROR_OK," Received EAP Response Identity packet with mismatching identifier field");
				return;
			}
			auth_pae->rxRespId = TRUE;
			lib1x_store_eap( auth_pae, (u_char *) packet , pkthdr, eap->code, eap->identifier, eaprr->type, 1, 0);

		}

         	auth_pae->bauth_sm->rxResp = TRUE;

		//---- parses the packet,creates a reply in sendbuf ----
		lib1x_rad_eapresp_supp( auth_pae, pkthdr );

		return;

	}

	// ---- if we receive request .. basically sth is wrong ..----

	if (  eap->code == LIB1X_EAP_REQUEST  ) 	// EAP REQUEST PACKET
	{
		return;
	}


}

#ifdef _RTL_WPA_UNIX
#ifndef COMPACK_SIZE
//----if 0706
void lib1x_handle_eapol_start(Global_Params * global)
{
	//---- Delete pairwise key if eapol-start is received
	if(lib1x_akmsm_trans(global))
		lib1x_akmsm_execute( global );

}
#endif
//----else
//----endif
//--------------------------------------------------
//  handle eapol key  parsing etc for packets from
//  supplicant
//--------------------------------------------------
void lib1x_handle_eapsupp_key( Global_Params * global,  struct lib1x_packet * pkthdr)
{
	Auth_Pae 		* auth_pae;
        u_char                 * packet;


	auth_pae = global->theAuthenticator;
	packet = (u_char *) pkthdr->data;

	global->EAPOLMsgRecvd.Octet = packet;
	global->EAPOLMsgRecvd.Length = pkthdr->caplen;
	global->EAPOLMsgSend.Octet = auth_pae->sendBuffer;

	global->EventId = akmsm_EVENT_EAPOLKeyRecvd;
	lib1x_akmsm_execute( global );	//Packet will be sent in this function

}
#endif //_RTL_WPA_UNIX

#ifndef COMPACK_SIZE
//--------------------------------------------------
//  handle eap parsing etc for packets from
//  authentication server
//--------------------------------------------------
void lib1x_handle_eapsvr( Global_Params * global, u_char * packet , struct lib1x_packet * pkthdr)
{
	struct lib1x_eapol     * eapol;
	struct lib1x_ethernet  * eth;
	struct lib1x_eap       * eap;
	struct lib1x_eap_rr    * eaprr;
	Auth_Pae 	       * auth_pae;

	u_short		       eap_length;


	eth = (struct lib1x_ethernet * ) packet;
	eapol = ( struct lib1x_eapol * ) ( packet + ETHER_HDRLEN );
	eap = (struct lib1x_eap * ) (packet + ETHER_HDRLEN +  LIB1X_EAPOL_HDRLEN);
	eaprr = ( struct lib1x_eap_rr *) ( packet + ETHER_HDRLEN +  LIB1X_EAPOL_HDRLEN + LIB1X_EAP_HDRLEN ) ;

	auth_pae = global->theAuthenticator;
	eap_length = ntohs( eap->length);


	if (  eap->code == LIB1X_EAP_RESPONSE  )
	{
		eaprr = ( struct lib1x_eap_rr *) ( eap + LIB1X_EAP_HDRLEN ) ;
					//Note :IMportant only if it is a response / request
					// packet ..we are sure of existence of such a field.

	        if ( eaprr->type  == LIB1X_EAP_RRIDENTITY )
		{
			if ( memcmp( auth_pae->supp_addr, eth->ether_shost, ETHER_ADDRLEN) != 0 )
			{
				lib1x_message(MESS_ERROR_OK," Received EAP Response Identity packet from non-supplicant ?");
				return;
			}
			if ( global->currentId  != eap->identifier )
			{
				lib1x_message(MESS_ERROR_OK," Received EAP Response Identity packet with mismatching identifier field");
				return;
			}
			auth_pae->rxRespId = TRUE;
			lib1x_store_eap( auth_pae, (u_char *) packet , pkthdr, eap->code, eap->identifier, eaprr->type, 1, 0);
		}
	}



	if (  eap->code == LIB1X_EAP_REQUEST  ) 	// EAP REQUEST PACKET
	{
		eaprr = ( struct lib1x_eap_rr *) ( eap + LIB1X_EAP_HDRLEN ) ;
		if ( global->currentId == eap->identifier )		// MATCH ID FIELD
		{

			if ( memcmp( auth_pae->supp_addr, eth->ether_shost, ETHER_ADDRLEN) == 0 )	// RCVD FROM SUPP
				auth_pae->bauth_sm->rxResp = TRUE;
			else
				lib1x_message(MESS_ERROR_OK," Received EAP Request packet from non-supplicant ?");
		}
		else lib1x_message(MESS_ERROR_OK," Received EAP Request packet with mismatch ID field");
	}


}
#endif

// These are transition functions for respective states of the Authenticator State Machine
void lib1x_authsm_initialize( Auth_Pae * auth_pae , Global_Params * global)
{
	auth_pae->state = apsm_Initialize;
	global->currentId = 0;

}


void lib1x_authsm_disconnected( Auth_Pae * auth_pae , Global_Params * global)
{


	global->portStatus = pst_Unauthorized;
	auth_pae->eapLogoff = FALSE;
	auth_pae->reAuthCount = 0;
	auth_pae->nakCount = 0;
	lib1x_auth_txCannedFail( auth_pae , global->currentId );	// TODO

	INC( global->currentId );
}

/*
void lib1x_authsm_connecting( Auth_Pae * auth_pae , Global_Params * global)
{
	auth_pae->eapStart = FALSE;
	global->reAuthenticate = FALSE;
	global->timers->txWhen = auth_pae->txPeriod;
	auth_pae->rxRespId = FALSE;
	lib1x_auth_txReqId( auth_pae, global->currentId );	// TODO

	INC( auth_pae->reAuthCount );

}
*/
//0802
void lib1x_authsm_connecting( Auth_Pae * auth_pae , Global_Params * global)
{


	auth_pae->eapStart = FALSE;
	global->reAuthenticate = FALSE;
	global->timers->txWhen = auth_pae->txPeriod;

	// jimmylin+20080813, modify for MAC authentication
	if((global->bMacAuthEnabled) && (!global->auth->RSNVariable.Dot1xEnabled))
	{
		auth_pae->rxRespId = TRUE;
		lib1x_rad_special_type( auth_pae, LIB1X_RAD_AUTH_MAC_AUTHENTICATION);
	}
	else
	{
		auth_pae->rxRespId = FALSE;
		lib1x_auth_txReqId( auth_pae, global->currentId );	// TODO
	}

	INC( auth_pae->reAuthCount );

}

void lib1x_authsm_authenticated( Auth_Pae * auth_pae , Global_Params * global)
{

	global->portStatus = pst_Authorized;
	auth_pae->reAuthCount = 0;
	auth_pae->nakCount = 0;
	INC( global->currentId) ;

}


void lib1x_authsm_authenticating( Auth_Pae * auth_pae , Global_Params * global)
{
	lib1x_message(MESS_DBG_SPECIAL,"AUTHSM> Into AUTHENTICATING state");
	global->authSuccess = FALSE;
	global->authFail = FALSE;
	global->authTimeout = FALSE;
	global->authStart = TRUE;
}

void lib1x_authsm_aborting( Auth_Pae * auth_pae, Global_Params * global)
{

	global->authAbort = TRUE;
	INC( global->currentId );
}

void lib1x_authsm_force_unauth( Auth_Pae * auth_pae , Global_Params * global)
{

	global->portStatus = pst_Unauthorized;
	auth_pae->portMode = pmt_ForceUnauthorized;
	auth_pae->eapStart = FALSE;
	lib1x_auth_txCannedFail( auth_pae, global->currentId );

	//0825
	if(global->auth->AccountingEnabled)
	{
		lib1x_acctsm_request(global, acctsm_Acct_Stop, LIB1X_ACCT_REASON_USER_REQUEST);
		lib1x_akmsm_Disconnect( global );
	}
	//

	INC( global->currentId );
}




void lib1x_authsm_force_auth( Auth_Pae * auth_pae , Global_Params * global)
{

	global->portStatus = pst_Authorized;
	auth_pae->portMode = pmt_ForceAuthorized;
	auth_pae->eapStart = FALSE;
	lib1x_auth_txCannedSuccess( auth_pae, global->currentId );
	INC( global->currentId );
}



//--------------------------------------------------
// lib1x_execute_authsm : This function executes the code on entry to a state.
//--------------------------------------------------
void lib1x_authsm_execute_authsm( Global_Params * global )
{
	Auth_Pae * auth_pae = global->theAuthenticator;

	if ( auth_pae == NULL  || global == NULL )
	{
		fprintf(stderr," Fatal: Null argument received.");
		exit(1);
	}

		switch( auth_pae->state )
		{
			case 	apsm_Initialize:
						lib1x_message(MESS_DBG_AUTHSM,"Into Initialize");
						lib1x_authsm_initialize( auth_pae , global);
						break;
			case 	apsm_Disconnected:
						lib1x_message(MESS_DBG_AUTHSM,"Into Disconnected");
						lib1x_authsm_disconnected( auth_pae, global );
						break;
			case 	apsm_Connecting:
						lib1x_message(MESS_DBG_AUTHSM,"Into Connecting");
						lib1x_authsm_connecting( auth_pae , global);
						break;
			case	apsm_Authenticated:
						lib1x_message(MESS_DBG_AUTHSM,"Into Authenticated");
						lib1x_authsm_authenticated( auth_pae, global);
						break;
			case 	apsm_Authenticating:
						lib1x_message(MESS_DBG_AUTHSM,"Into Authenticating");
						lib1x_authsm_authenticating( auth_pae, global);
						break;
			case	apsm_Aborting:
						lib1x_message(MESS_DBG_AUTHSM,"Into Aborting");
						lib1x_authsm_aborting( auth_pae, global);
						break;
			case 	apsm_Force_Auth:
						lib1x_message(MESS_DBG_AUTHSM,"Into Force Auth");
						lib1x_authsm_force_auth( auth_pae, global);
						break;
			case	apsm_Force_Unauth:
						lib1x_message(MESS_DBG_AUTHSM,"Into Force Unauth");
						lib1x_authsm_force_unauth( auth_pae, global);
						break;
		}

}





#ifdef RTL_RADIUS_2SET
void lib1x_auth_radius2_exchange(Global_Params * global)
{
	struct lib1x_nal_intfdesc	*tmp_network_svr;
	struct in_addr	tmp_svrip_inaddr;
	u_short			tmp_udp_svrport;
	struct sockaddr_in			tmp_radsvraddr;
	OCTET_STRING	tmp_RadShared;
	BOOLEAN			tmp_MacAuthEnabled;

	tmp_network_svr = global->TxRx->network_svr;
	global->TxRx->network_svr = global->TxRx->network_svr2;
	global->TxRx->network_svr2 = tmp_network_svr;

	tmp_svrip_inaddr = global->TxRx->svrip_inaddr;
	global->TxRx->svrip_inaddr = global->TxRx->svrip_inaddr2;
	global->TxRx->svrip_inaddr2 = tmp_svrip_inaddr;

	tmp_udp_svrport = global->TxRx->udp_svrport;
	global->TxRx->udp_svrport = global->TxRx->udp_svrport2;
	global->TxRx->udp_svrport2 = tmp_udp_svrport;

	tmp_radsvraddr = global->TxRx->radsvraddr;
	global->TxRx->radsvraddr = global->TxRx->radsvraddr2;
	global->TxRx->radsvraddr2 = tmp_radsvraddr;

	tmp_RadShared.Length = global->auth->RadShared.Length;
	tmp_RadShared.Octet = global->auth->RadShared.Octet;
	global->auth->RadShared.Length = global->auth->RadShared2.Length;
	global->auth->RadShared.Octet = global->auth->RadShared2.Octet;
	global->auth->RadShared2.Length = tmp_RadShared.Length;
	global->auth->RadShared2.Octet = tmp_RadShared.Octet;

	tmp_MacAuthEnabled = global->auth->RSNVariable.rs2MacAuthEnabled;
	global->auth->RSNVariable.MacAuthEnabled = global->auth->RSNVariable.rs2MacAuthEnabled;
	global->auth->RSNVariable.rs2MacAuthEnabled = tmp_MacAuthEnabled;
}
#endif





//--------------------------------------------------
// lib1x_trans_authsm :
// This function transitions the auth pae state
// machine.
//--------------------------------------------------

BOOLEAN lib1x_trans_authsm( Global_Params * global )
{
	BOOLEAN		transitionDone = FALSE;
	Auth_Pae	* auth_pae;


	auth_pae = global->theAuthenticator;


	if ( auth_pae == NULL  || global == NULL )
	{
		fprintf(stderr," Fatal: Null argument received.");
		exit(1);
	}


	// Check Global Conditions Here.

	// Condition 1:

	if ( (( global->portControl == pmt_Auto ) && ( auth_pae->portMode != global->portControl ))
		||( global->initialize )
		|| ! global->portEnabled )
	{
		printf("%s: Check Global Condition - 1\n", __FUNCTION__);
		auth_pae->state = apsm_Initialize;
		return TRUE;
	}


	// Condition 2:
	if ( ( global->portControl == pmt_ForceAuthorized ) &&
	     ( auth_pae->portMode != global->portControl ) &&
	     ( ! global->initialize ) && ( global->portEnabled ) )
	{
		printf("%s: Check Global Condition - 2\n", __FUNCTION__);
		auth_pae->state = apsm_Force_Auth;
		return TRUE;
	}


	// Condition 3:
	if ( ( global->portControl == pmt_ForceUnauthorized ) &&
	     ( auth_pae->portMode != global->portControl ) &&
	     ( ! global->initialize ) && ( global->portEnabled ) )
	{
		printf("%s: Check Global Condition - 3\n", __FUNCTION__);
		auth_pae->state = apsm_Force_Unauth;
		return TRUE;
	}

	switch( auth_pae->state )
	{
		case 	apsm_Initialize:
			auth_pae->state = apsm_Disconnected;	// Unconditional transfer
			transitionDone = TRUE;
			break;
		case 	apsm_Disconnected:
			auth_pae->state = apsm_Connecting;	// Unconditional transfer
			transitionDone = TRUE;
			break;
		case 	apsm_Connecting:
			if ( auth_pae->rxRespId  &&
			( auth_pae->reAuthCount <= auth_pae->reAuthMax ) )
			{
				auth_pae->state = apsm_Authenticating;
				transitionDone = TRUE;
				break;
			}
			if(auth_pae->reAuthCount > auth_pae->reAuthMax)
			{
#ifdef RTL_WPA2_PREAUTH
				//printf("%s-%d: global->EventId = akmsm_EVENT_Disconnect\n", __FUNCTION__,__LINE__);
#endif
				global->EventId = akmsm_EVENT_Disconnect;
				global->akm_sm->Disconnect = TRUE;
				global->akm_sm->ErrorRsn = auth_not_valid;
				lib1x_akmsm_Disconnect(global);
			}

			if (
			( ( global->timers->txWhen == 0 ) ||
			auth_pae->eapStart  ||
			global->reAuthenticate) &&
			( auth_pae->reAuthCount <= auth_pae->reAuthMax ) )
			{
				auth_pae->state = apsm_Connecting;
				transitionDone = TRUE;
			}

			break;
		case 	apsm_Authenticated:
			if ( auth_pae->eapStart || global->reAuthenticate )
			{
				auth_pae->state = apsm_Connecting;
				transitionDone = TRUE;
				break;
			}
			if ( auth_pae->eapLogoff )
			{
				auth_pae->state = apsm_Disconnected ;
				transitionDone = TRUE;
			}
			break;

		case	apsm_Authenticating:
			if ( global->authSuccess )
			{
				lib1x_message( MESS_DBG_SPECIAL,"Received authSuccess, into Authenticated state.");

				global->EventId = akmsm_EVENT_AuthenticationRequest;//2003-09-16
				auth_pae->state = apsm_Authenticated;
				transitionDone = TRUE;
				break;
			}
			if ( global->authFail )
			{
#if defined(CONFIG_RTL8186_TR) || defined(CONFIG_RTL865X_SC) || defined(CONFIG_RTL865X_AC) || defined(CONFIG_RTL865X_KLD) || defined(CONFIG_RTL8196C_EC)
				LOG_MSG_NOTICE("Authentication failed;note:%02x-%02x-%02x-%02x-%02x-%02x;",
						global->theAuthenticator->supp_addr[0],
						global->theAuthenticator->supp_addr[1],
						global->theAuthenticator->supp_addr[2],
						global->theAuthenticator->supp_addr[3],
						global->theAuthenticator->supp_addr[4],
						global->theAuthenticator->supp_addr[5]);
#endif
			
				auth_pae->state = apsm_Held;
				transitionDone = TRUE;
				break;
			}
			if ( global->reAuthenticate || auth_pae->eapStart ||
				auth_pae->eapLogoff ||
				global->authTimeout )
			{

#if defined(CONFIG_RTL8186_TR) || defined(CONFIG_RTL865X_SC) || defined(CONFIG_RTL865X_AC) || defined(CONFIG_RTL865X_KLD) || defined(CONFIG_RTL8196C_EC)
				LOG_MSG_NOTICE("Authentication timeout;note:%02x-%02x-%02x-%02x-%02x-%02x;",
						global->theAuthenticator->supp_addr[0],
						global->theAuthenticator->supp_addr[1],
						global->theAuthenticator->supp_addr[2],
						global->theAuthenticator->supp_addr[3],
						global->theAuthenticator->supp_addr[4],
						global->theAuthenticator->supp_addr[5]);
#endif

			
#ifdef RTL_RADIUS_2SET
				if (global->authTimeout) {
					if ( global->auth->use_2nd_rad == 1 )
					{
						if (global->TxRx->flag_replaced) {
							lib1x_auth_radius2_exchange(global);
							global->TxRx->flag_replaced = 0;
						}
						else {
							lib1x_auth_radius2_exchange(global);
							global->TxRx->flag_replaced = 1;
						}
					}
				}
#endif
				auth_pae->state = apsm_Aborting;
				transitionDone = TRUE;
			}
			break;
		case	apsm_Aborting:
			if ( auth_pae->eapLogoff && !global->authAbort )
			{
				auth_pae->state = apsm_Disconnected;
				transitionDone = TRUE;
				break;
			}
			if ( !auth_pae->eapLogoff && !global->authAbort )
			{
				auth_pae->state = apsm_Connecting;
				transitionDone = TRUE;
			}
			break;
		case	apsm_Held:
			if ( global->timers->quietWhile == 0 )
			{
				auth_pae->state = apsm_Connecting;
				transitionDone = TRUE;
			}
			break;

		case	apsm_Force_Unauth:
			if ( auth_pae->eapStart )
				transitionDone = TRUE;			// New state is also the same
			break;
		case	apsm_Force_Auth:
			if ( auth_pae->eapStart )
				transitionDone = TRUE;			// New state is also the same
			break;
	}

//	PRINT_AUTH_PAE_STATE( auth_pae );



	return transitionDone;
}





//--------------------------------------------------
// lib1x_auth_txCannedSuccess:
//  Send a success EAP packet to supplicant.
//--------------------------------------------------
void lib1x_auth_txCannedSuccess( Auth_Pae * auth_pae, int identifier )
{
	struct lib1x_eapol * eapol;
	struct lib1x_eap * eap;
	u_char * packet = auth_pae->sendBuffer;
	struct lib1x_ethernet * eth_hdr;
	Global_Params * global;
	int size;

	// Note: Every time this authpae sends a packet the SAME send buffer is used.
	//


	global = auth_pae->global;

	size = ETHER_HDRLEN + sizeof( struct lib1x_eapol ) + sizeof( struct lib1x_eap ) + 1;
	bzero( auth_pae->sendBuffer, size );

	eth_hdr = ( struct lib1x_ethernet * ) packet;
	memcpy ( eth_hdr->ether_dhost , auth_pae->supp_addr, ETHER_ADDRLEN );
	memcpy ( eth_hdr->ether_shost , auth_pae->global->TxRx->oursupp_addr, ETHER_ADDRLEN );

	eapol = ( struct lib1x_eapol * )  ( packet +  ETHER_HDRLEN )  ;
					// We subtract 2 because of the common type field

#ifdef RTL_WPA2_PREAUTH
	if (global->RSNVariable.isPreAuth)
		eth_hdr->ether_type = htons(PREAUTH_ETHER_EAPOL_TYPE);
	else
	eth_hdr->ether_type = htons(LIB1X_ETHER_EAPOL_TYPE);
#else
	eth_hdr->ether_type = htons(LIB1X_ETHER_EAPOL_TYPE);
#endif
	eapol->protocol_version = LIB1X_EAPOL_VER;
	eapol->packet_type = LIB1X_EAPOL_EAPPKT;

	eap = (struct lib1x_eap * ) ( ( (u_char *) eapol) + LIB1X_EAPOL_HDRLEN );
	eap->code =  LIB1X_EAP_SUCCESS;
	eap->identifier = identifier;
	eap->length = htons(LIB1X_EAP_HDRLEN);

	eapol->packet_body_length = htons(LIB1X_EAP_HDRLEN);

	lib1x_message(MESS_DBG_AUTHNET, "Sending SUCCESS EAP packet to Supplicant");

	lib1x_message(MESS_DBG_AUTHNET,"<<<<<<<<<<<<<<<<<< TO supplicant ");

#ifdef RTL_WPA2_PREAUTH
	if (global->RSNVariable.isPreAuth)  {
		lib1x_nal_send( auth_pae->global->TxRx->network_ds, auth_pae->sendBuffer,  size );
	} else
	lib1x_nal_send( auth_pae->global->TxRx->network_supp, auth_pae->sendBuffer,  size );
#else
	lib1x_nal_send( auth_pae->global->TxRx->network_supp, auth_pae->sendBuffer,  size );
#endif

#if defined(CONFIG_RTL8186_TR) || defined(CONFIG_RTL865X_SC) || defined(CONFIG_RTL865X_AC) || defined(CONFIG_RTL865X_KLD) || defined(CONFIG_RTL8196C_EC)
	LOG_MSG_NOTICE("EAP-Success;note:%02x-%02x-%02x-%02x-%02x-%02x;", 
		auth_pae->supp_addr[0], auth_pae->supp_addr[1], auth_pae->supp_addr[2],
		auth_pae->supp_addr[3], auth_pae->supp_addr[4], auth_pae->supp_addr[5]);	
#endif


}


//--------------------------------------------------
// lib1x_auth_txReqId :
//  Send a request/identity packet
//--------------------------------------------------
void lib1x_auth_txReqId( Auth_Pae * auth_pae, int identifier )
{
	struct lib1x_eapol * eapol;
	struct lib1x_eap * eap;
	u_char * packet;
	struct lib1x_ethernet * eth_hdr;
	struct lib1x_eap_rr * eaprr;
	Global_Params * global;
	int size;

	// Note: Every time this authpae sends a packet the SAME send buffer is used.
	//


	global = auth_pae->global;

	size = 2+ ETHER_HDRLEN + sizeof( struct lib1x_eapol ) + sizeof( struct lib1x_eap ) + 1;
	bzero( auth_pae->sendBuffer, size );
	packet = auth_pae->sendBuffer;


	eth_hdr = ( struct lib1x_ethernet * ) packet;

	memcpy ( eth_hdr->ether_dhost , auth_pae->supp_addr, ETHER_ADDRLEN );
	memcpy ( eth_hdr->ether_shost , auth_pae->global->TxRx->oursupp_addr, ETHER_ADDRLEN );


	eapol = ( struct lib1x_eapol * )  ( packet +  ETHER_HDRLEN )  ;
	// We subtract 2 because of the common type field

#ifdef RTL_WPA2_PREAUTH
	if (global->RSNVariable.isPreAuth)
		eth_hdr->ether_type = htons(PREAUTH_ETHER_EAPOL_TYPE);
	else
	eth_hdr->ether_type = htons(LIB1X_ETHER_EAPOL_TYPE);
#else
	eth_hdr->ether_type = htons(LIB1X_ETHER_EAPOL_TYPE);
#endif
	eapol->protocol_version = LIB1X_EAPOL_VER;

	eapol->packet_type = LIB1X_EAPOL_EAPPKT;

	eap = (struct lib1x_eap * ) ( ( (u_char *) eapol) + LIB1X_EAPOL_HDRLEN );
	eap->code =  LIB1X_EAP_REQUEST;
	eap->identifier = identifier;
	eap->length = htons(LIB1X_EAP_HDRLEN + 1) ; // add 1 for the type "identity" in EAP message

	eapol->packet_body_length = htons(LIB1X_EAP_HDRLEN  + 1);	// for RR field
	eaprr = (struct lib1x_eap_rr * ) ( ( ( u_char *)eapol) + LIB1X_EAPOL_HDRLEN  + LIB1X_EAP_HDRLEN);
	eaprr->type =  LIB1X_EAP_RRIDENTITY;

	lib1x_message(MESS_DBG_AUTHNET, "Sending REQUEST / Identity EAP packet to Supplicant");
	lib1x_message(MESS_DBG_AUTHNET,"<<<<<<<<<<<<<<<<<< TO supplicant ");
#ifdef RTL_WPA2_PREAUTH
	//wpa2_hexdump("\nREQUEST / Identity EAP packet", auth_pae->sendBuffer, size);
	//printf("kenny: %s(), global->RSNVariable.isPreAuth = %s\n", __FUNCTION__, global->RSNVariable.isPreAuth?"TRUE":"FALSE");
	if (global->RSNVariable.isPreAuth)  {
		lib1x_nal_send( auth_pae->global->TxRx->network_ds, auth_pae->sendBuffer,  size );
	} else
		lib1x_nal_send( auth_pae->global->TxRx->network_supp, auth_pae->sendBuffer,  size );
#else
	lib1x_nal_send( auth_pae->global->TxRx->network_supp, auth_pae->sendBuffer,  size );
#endif

#if defined(CONFIG_RTL8186_TR) || defined(CONFIG_RTL865X_SC) || defined(CONFIG_RTL865X_AC) || defined(CONFIG_RTL865X_KLD) || defined(CONFIG_RTL8196C_EC)
	LOG_MSG_NOTICE("EAP-Request/Identity;");
#endif

}

//--------------------------------------------------
// lib1x_auth_txCannedFail:
//  Send a fail EAP packet to supplicant.
//--------------------------------------------------
void lib1x_auth_txCannedFail( Auth_Pae * auth_pae, int identifier )
{
	struct lib1x_eapol * eapol;
	struct lib1x_eap * eap;
	u_char * packet = auth_pae->sendBuffer;
	struct lib1x_ethernet * eth_hdr;
	Global_Params * global;
	int size;

	// Note: Every time this authpae sends a packet the SAME send buffer is used.


	global = auth_pae->global;

	size = ETHER_HDRLEN + sizeof( struct lib1x_eapol ) + sizeof( struct lib1x_eap ) + 1;
	bzero( auth_pae->sendBuffer, size );

	eth_hdr = ( struct lib1x_ethernet * ) packet;
	memcpy ( eth_hdr->ether_dhost , auth_pae->supp_addr, ETHER_ADDRLEN );
	memcpy ( eth_hdr->ether_shost , auth_pae->global->TxRx->oursupp_addr, ETHER_ADDRLEN );

	eapol = ( struct lib1x_eapol * )  ( packet +  ETHER_HDRLEN )  ;
					// We subtract 2 because of the common type field

#ifdef RTL_WPA2_PREAUTH
	if (global->RSNVariable.isPreAuth)
		eth_hdr->ether_type = htons(PREAUTH_ETHER_EAPOL_TYPE);
	else
		eth_hdr->ether_type = htons(LIB1X_ETHER_EAPOL_TYPE);
#else
	eth_hdr->ether_type = htons(LIB1X_ETHER_EAPOL_TYPE);
#endif
	eapol->protocol_version = LIB1X_EAPOL_VER;
	eapol->packet_type = LIB1X_EAPOL_EAPPKT;

	eap = (struct lib1x_eap * ) ( ( (u_char *) eapol) + LIB1X_EAPOL_HDRLEN );
	eap->code =  LIB1X_EAP_FAILURE;
	eap->identifier = identifier;
	eap->length = htons(LIB1X_EAP_HDRLEN);

	eapol->packet_body_length = htons(LIB1X_EAP_HDRLEN);

#if defined(CONFIG_RTL8186_TR) || defined(CONFIG_RTL865X_SC) || defined(CONFIG_RTL865X_AC) || defined(CONFIG_RTL865X_KLD) || defined(CONFIG_RTL8196C_EC)
	LOG_MSG_NOTICE("EAP-Failure;note:%02x-%02x-%02x-%02x-%02x-%02x;",
		auth_pae->supp_addr[0],auth_pae->supp_addr[1],auth_pae->supp_addr[2],
		auth_pae->supp_addr[3],auth_pae->supp_addr[4],auth_pae->supp_addr[5]);
#endif

	syslog(LOG_AUTH|LOG_INFO, "%s: Authentication failled from radius server!\n", dev_supp); // david+2006-03-31, add event to syslog

	lib1x_message(MESS_DBG_AUTHNET, "Sending FAILURE EAP packet to Supplicant");

	lib1x_message(MESS_DBG_AUTHNET,"<<<<<<<<<<<<<<<<<< TO supplicant ");
#ifdef RTL_WPA2_PREAUTH
	if (global->RSNVariable.isPreAuth)  {
		lib1x_nal_send( auth_pae->global->TxRx->network_ds, auth_pae->sendBuffer,  size );
	} else
	lib1x_nal_send( auth_pae->global->TxRx->network_supp, auth_pae->sendBuffer,  size );
#else
	lib1x_nal_send( auth_pae->global->TxRx->network_supp, auth_pae->sendBuffer,  size );
#endif
}





//--------------------------------------------------
// dump state machine routines.
// writes to fdesc.
//--------------------------------------------------
//#define VERBO_AUTHSM_DUMP
void lib1x_authsm_dump( FILE *  fdesc, Auth_Pae * auth_pae )
{
#ifdef VERBO_AUTHSM_DUMP
	char etheraddr[40];

	Global_Params * global;

	global = auth_pae->global;

	if ( auth_pae == NULL )
		lib1x_message( MESS_ERROR_FATAL, "NULL auth_pae received.");


	lib1x_message(MESS_DBG_SPECIAL, "\n Authenticator PAE State Machine Dump \n");
	lib1x_message(MESS_DBG_SPECIAL, "State : ");
	switch( auth_pae->state )
	{
		case apsm_Initialize      :lib1x_message(MESS_DBG_SPECIAL, "Initialize"); break;
		case apsm_Disconnected    :lib1x_message(MESS_DBG_SPECIAL, "Disconnected"); break;
		case apsm_Connecting      :lib1x_message(MESS_DBG_SPECIAL, "Connecting"); break;
		case apsm_Authenticating  :lib1x_message(MESS_DBG_SPECIAL, "Authenticating"); break;
		case apsm_Authenticated   :lib1x_message(MESS_DBG_SPECIAL, "Authenticated"); break;
		case apsm_Aborting        :lib1x_message(MESS_DBG_SPECIAL, "Aborting"); break;
		case apsm_Held            :lib1x_message(MESS_DBG_SPECIAL, "Held"); break;
		case apsm_Force_Auth      :lib1x_message(MESS_DBG_SPECIAL, "Force_Auth"); break;
		case apsm_Force_Unauth    :lib1x_message(MESS_DBG_SPECIAL, "Force_Unauth"); break;
	}




	if ( auth_pae->eapStart ) printf("eapStart : TRUE\n");
		else printf("eapStart : FALSE \n");

	if ( auth_pae->rxRespId ) printf("rxRespId : TRUE\n");
		else printf("rxRespId : FALSE \n");
	printf("Quiet Period = %d\n", auth_pae->quietPeriod );
	printf("ReAuthMax = %d\n", auth_pae->reAuthMax);
	printf("Tx Period = %d\n", auth_pae->txPeriod );

	lib1x_print_etheraddr( etheraddr, auth_pae->global->TxRx->oursvr_addr );
	printf("Our 802.3 interface addr : %s\n", etheraddr );

	lib1x_print_etheraddr( etheraddr, auth_pae->global->TxRx->svr_addr );
	printf("The Server addr : %s\n", etheraddr );

	lib1x_print_etheraddr( etheraddr, auth_pae->global->TxRx->oursupp_addr );
	printf("Our 802.11 interface addr : %s\n", etheraddr );

	lib1x_print_etheraddr( etheraddr, auth_pae->supp_addr );
	printf("The supplicant addr : %s\n", etheraddr );
	printf(" OUR UDP Port : %d  Server UDP Port : %d\n", global->TxRx->udp_ourport, global->TxRx->udp_svrport );
	printf(" Our IP Address: %s " , inet_ntoa( global->TxRx->ourip_inaddr ) );
	printf("  Server IP Address : %s\n ", inet_ntoa ( global->TxRx->svrip_inaddr ) );

#endif
	fflush(fdesc);
}

////////////////////////////////////////////////////////////////////////////////////////////////////
// Emily: For RTL8181 AP
///////////////////////////////////////////////////////////////////////////////////////////////////

/* Return the existing entry id, or return the new id if there is unused entry
   ELSE Return -1
*/
int	lib1x_search_supp(Dot1x_Authenticator * auth , struct lib1x_packet * spkt, u_char inttype)
{

	int i = 0, suppid;
	Auth_Pae * auth_pae;

	////////////////////////////////////////////////
	//For EAPOL pakcet from supplicant
	//

	u_char buf[100], *packet;
	struct lib1x_ethernet * eth;
	struct lib1x_eapol     * eapol;

	/////////////////////////////////////////////////
	//For UDP packet from server
	//
	struct lib1x_radiushdr * rhdr;


	//----------------------------------------------------------------------------------------
	// Process packet from wireless interface
	//----------------------------------------------------------------------------------------
	if( inttype == LIB1X_IT_PKTSOCK)
	{
		packet = (u_char *)spkt->data;
		bzero(buf, sizeof buf);


		if ( spkt == NULL )
		{
			lib1x_message( MESS_DBG_NAL, "parser: spkt null ");
			return -1;
		}
		eth = ( struct lib1x_ethernet * ) spkt->data;
		eapol = ( struct lib1x_eapol * ) ( packet + ETHER_HDRLEN );

#ifdef RTL_WPA2_PREAUTH
		if ( htons(eth->ether_type) != LIB1X_ETHER_EAPOL_TYPE
		     && htons(eth->ether_type) != PREAUTH_ETHER_EAPOL_TYPE){
#else
		if ( htons(eth->ether_type) != LIB1X_ETHER_EAPOL_TYPE ){
#endif
			return -1;
		}

		switch( eapol->packet_type )
		{
		case    LIB1X_EAPOL_LOGOFF :
			//lib1x_message( MESS_DBG_AUTHNET, " EAPOL LOGOFF");
			break;

		case    LIB1X_EAPOL_START  :
			/*
			{
			u_char src_addr[ETHER_ADDRLEN];
			//memcpy( src_addr, eth->ether_shost, ETHER_ADDRLEN );                		                              //lib1x_message( MESS_DBG_SPECIAL, "AUTHENTICATOR> EAPOL START");
			for( i = 0; i < auth->MaxSupplicant ; i++)
			{
				if( auth->Supp[i]->isEnable )
				{
					auth_pae = auth->Supp[i]->global->theAuthenticator;
					if(!memcmp( auth_pae->supp_addr, eth->ether_shost,  ETHER_ADDRLEN))
					{

						return  i;
					}
				}
			}
			if((suppid = lib1x_insert_supp(auth, eth->ether_shost)) != -1);
			{
				//auth->Supp[suppid]->isEnable = 1;
				return suppid;
			}
			return -1;

			break;
			}

    			*/
		case    LIB1X_EAPOL_EAPPKT:
		case 	LIB1X_EAPOL_KEY:

			//memcpy( src_addr, eth->ether_shost, ETHER_ADDRLEN );
			for( i = 0; i < auth->MaxSupplicant ; i++)
			{
// reduce pre-alloc memory size, david+2006-02-06			
//				if( auth->Supp[i]->isEnable )
				if( auth->Supp[i] && auth->Supp[i]->isEnable )
				{
					auth_pae = auth->Supp[i]->global->theAuthenticator;
					if(!memcmp( auth_pae->supp_addr , eth->ether_shost,  ETHER_ADDRLEN))
					{
						return  i;
					}
				}
			}

			return -1;

			break;

		}// end switch( eapol->packet_type )

	}//end if( inttype == LIB1X_IT_PKTSOCK)
	//----------------------------------------------------------------------------------------
	// Process ioctl return message from driver
	//----------------------------------------------------------------------------------------
	else if(inttype == LIB1X_IT_CTLSOCK)
	{
		// The first byte is [event type], the second byte is [more event] fag
		// The thrid byte is MAC address for ASSOCIATION_IND, DISCONNECT_IND and MIC_RAILURE
		packet = (u_char *) spkt->data;
		//lib1x_hexdump2(MESS_DBG_CONTROL, "lib1x_search_supp", packet + 2, spkt->caplen -2, "general Data");

		switch(*packet)
		{
			case DOT11_EVENT_ASSOCIATION_IND:
			case DOT11_EVENT_REASSOCIATION_IND:
			case DOT11_EVENT_EAPOLSTART:
#ifdef RTL_WPA2_PREAUTH
			case DOT11_EVENT_EAPOLSTART_PREAUTH:
				if (*packet == DOT11_EVENT_EAPOLSTART_PREAUTH)
					printf("%s: got DOT11_EVENT_EAPOLSTART_PREAUTH\n", __FUNCTION__);
#endif

				for( i = 0; i < auth->MaxSupplicant ; i++)
				{
// reduce pre-alloc memory size, david+2006-02-06			
//					if( auth->Supp[i]->isEnable )
					if( auth->Supp[i] && auth->Supp[i]->isEnable )
					{
						auth_pae = auth->Supp[i]->global->theAuthenticator;
						if(!memcmp( auth_pae->supp_addr, packet + 2,  ETHER_ADDRLEN))
						{
							lib1x_message(MESS_DBG_SPECIAL, "Find Supp[%d] in Table in EVENT_ASSOCIATION_IND\n", i);
							return  i;
						}
					}
				}

				if((suppid = lib1x_insert_supp(auth, packet + 2)) != -1);
				{
					lib1x_message(MESS_DBG_SPECIAL, "\n[Insert suppid=%d into table]\n", suppid);
					return suppid;
				}

				return -1;

				break;

			case DOT11_EVENT_AUTHENTICATION_IND:
			case DOT11_EVENT_DEAUTHENTICATION_IND:
			case DOT11_EVENT_DISASSOCIATION_IND:
				for( i = 0; i < auth->MaxSupplicant ; i++)
				{
// reduce pre-alloc memory size, david+2006-02-06			
//					if( auth->Supp[i]->isEnable )
					if( auth->Supp[i] && auth->Supp[i]->isEnable )
					{
						auth_pae = auth->Supp[i]->global->theAuthenticator;
						if(!memcmp( auth_pae->supp_addr , packet + 2,  ETHER_ADDRLEN))
						{
							return  i;
						}
					}
				}
				lib1x_message(MESS_DBG_SPECIAL, "Receive Other Indcation from driver, Station is not in Table");
				return -1;
				break;

			default:
				return -1;
				break;

		}//end switch(*packet)

	}//end else if(inttype == LIB1X_IT_CTLSOCK)
	//----------------------------------------------------------------------------------------
	// Process packet from ethernet interface
	//----------------------------------------------------------------------------------------
	else if(inttype == LIB1X_IT_UDPSOCK)
	{
		rhdr = ( struct lib1x_radiushdr * ) spkt->data;

		//if(auth->AccountingEnabled)
		// kenny
		if(rhdr->code == LIB1X_RAD_ACCTRSP && auth->AccountingEnabled)
		{
			if(auth->authGlobal->global->theAuthenticator->rinfo->identifier == rhdr->identifier)
				return LIB1X_AUTH_INDEX;
		}

		for( i = 0; i < auth->MaxSupplicant ; i++)
                {
// reduce pre-alloc memory size, david+2006-02-06                
//			if( auth->Supp[i]->isEnable )
			if(auth->Supp[i] && auth->Supp[i]->isEnable )
			{
				if( auth->Supp[i]->global->theAuthenticator->rinfo->identifier == rhdr->identifier)
					return  i;
			}
		}
		// Add code to deal with this condition
		return -1;
	}

	return -1;

}


// reduce pre-alloc memory size -------------------------------------
static int alloc_supp(Dot1x_Authenticator *auth, int i)
{
	auth->Supp[i] = (Dot1x_Supplicant * ) malloc ( sizeof (Dot1x_Supplicant) );
	if (auth->Supp[i]==NULL)
		return 0;

	bzero( auth->Supp[i], sizeof (Dot1x_Supplicant) );
	auth->Supp[i]->index = i;
	auth->Supp[i]->isEnable = FALSE;
	auth->Supp[i]->global = lib1x_init_authenticator( auth, auth->GlobalTxRx );
	auth->Supp[i]->global->index = i;
	auth->Supp[i]->global->theAuthenticator->rinfo->global_identifier = &auth->GlobalTxRx->GlobalRadId;
	return 1;
}
//------------------------------ david+2006-02-06

int	lib1x_insert_supp(Dot1x_Authenticator *auth, u_char * supp_addr)
{
	int i;
	Auth_Pae * auth_pae;
	Global_Params * global;



	for( i = 0; i < auth->MaxSupplicant ; i++)
	{
// reduce pre-alloc memory size -----------------
		if (auth->Supp[i] == NULL) {
			if (!alloc_supp(auth, i)) {
				printf("Error, allocate memory failed for supplicant!\n");
				return -1;
			}
		}
//------------------------------ david+2006-02-06

		auth_pae = auth->Supp[i]->global->theAuthenticator;
		global = auth->Supp[i]->global;

		if( !memcmp( auth_pae->supp_addr, supp_addr, ETHER_ADDRLEN ) ){
			//supplicant exists in table

//			PRINT_MAC_ADDRESS(supp_addr, "Supplicant exists in table");

			auth->Supp[i]->isEnable = TRUE;
			lib1x_reset_authenticator(global);
//			lib1x_control_RemovePTK(global, DOT11_KeyType_Pairwise);
//   		lib1x_control_SetPORT(global, DOT11_PortStatus_Unauthorized);
//			global->theAuthenticator->eapStart = TRUE;
//			global->akm_sm->AuthenticationRequest = TRUE;
			global->index = i;
			global->theAuthenticator->rinfo->global_identifier = &auth->GlobalTxRx->GlobalRadId;
		}
		else{
			//supplicant does NOT exist in table
			if( !auth->Supp[i]->isEnable)
			{
				auth->Supp[i]->isEnable = TRUE;
				auth_pae = auth->Supp[i]->global->theAuthenticator;
				memcpy(auth_pae->supp_addr, supp_addr, ETHER_ADDRLEN);
				auth->NumOfSupplicant++;

//				PRINT_MAC_ADDRESS(supp_addr, "lib1x_insert_supp->supp_addr");

				lib1x_message(MESS_DBG_SPECIAL, "<lib1x_insert_supp> Number of Supplicant = %d\n",auth->NumOfSupplicant);
				return i;
			}
			else{
			//	printf("%s: Supplicant does NOT exist in table. isEnable == FALSE -------\n", __FUNCTION__);
			}
		}
	}

	return -1;
}

int lib1x_del_supp(Dot1x_Authenticator *auth, u_char * supp_addr)
{
	int i;
	Auth_Pae * auth_pae;
	Global_Params * global;


//	printf("%s: addr = %02x:%02x:%02x:%02x:%02x:%02x\n", __FUNCTION__,
//			supp_addr[0], supp_addr[1], supp_addr[2], supp_addr[3], supp_addr[4], supp_addr[5] );


	for( i = 0; i < auth->MaxSupplicant ; i++)
	{
// reduce pre-alloc memory size -----------------
		if (auth->Supp[i] == NULL)
			continue;
//------------------------------ david+2006-02-06
		
		auth_pae = auth->Supp[i]->global->theAuthenticator;
		global = auth->Supp[i]->global;

		if( !memcmp( auth_pae->supp_addr, EMPTY_ADDR, ETHER_ADDRLEN ) ){
			continue;
		}

		if( !memcmp( auth_pae->supp_addr, supp_addr, ETHER_ADDRLEN ) ){
			//supplicant exists in table
			//---- Update variable in RTLAuthenticator ----

//			PRINT_MAC_ADDRESS(supp_addr, "lib1x_del_supp->supp_addr");
//			printf("%s: global->index = %d\n", __FUNCTION__, global->index);

			global->auth->Supp[global->index]->isEnable = FALSE;
			lib1x_message(MESS_DBG_KEY_MANAGE, "Delete STA from Table");

			memcpy(auth_pae->supp_addr, EMPTY_ADDR, ETHER_ADDRLEN);

			global->akm_sm->CurrentReplayCounter.field.HighPart = 0;
			global->akm_sm->CurrentReplayCounter.field.LowPart = 0;

			auth->Supp[i]->isEnable = FALSE;
			global->auth->NumOfSupplicant --;

			lib1x_message(MESS_DBG_SPECIAL, "<lib1x_del_supp> Number of Supplicant = %d\n",auth->NumOfSupplicant);
			return i;
		}
		else{
		}
	}

	if(i == auth->MaxSupplicant){
		//supplicant does NOT exist in table
//		printf("%s: Supplicant does NOT exist in table.\n", __FUNCTION__);
	}

	return -1;
}

