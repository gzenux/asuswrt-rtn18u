


//--------------------------------------------------
// IEEE 802.1x Implementation
//
// File		: 1x_bauth_sm.c
// Programmer	: Arunesh Mishra
// Copyright (c) Arunesh Mishra 2002
// All rights reserved.
// Maryland Information and Systems Security Lab
// University of Maryland, College Park.
//
// Implementation of the Backend Authentication State Machine.
//--------------------------------------------------


#include "1x_common.h"
#include "1x_auth_pae.h"
#include "1x_eapol.h"
#include "1x_nal.h"
#include "1x_radius.h"
#include "1x_bauth_sm.h"

// Some funtion prototype decls
void lib1x_exec_bauthsm_request( Auth_Pae * , Global_Params * , Bauth_SM * );
void lib1x_exec_bauthsm_response( Auth_Pae * , Global_Params * , Bauth_SM * );
void lib1x_exec_bauthsm_success( Auth_Pae * , Global_Params * , Bauth_SM * );
void lib1x_exec_bauthsm_fail( Auth_Pae * , Global_Params * , Bauth_SM * );
void lib1x_exec_bauthsm_timeout( Auth_Pae * , Global_Params * , Bauth_SM * );
void lib1x_exec_bauthsm_idle( Auth_Pae * , Global_Params * , Bauth_SM * );
void lib1x_exec_bauthsm_initialize( Auth_Pae * , Global_Params * , Bauth_SM * );

void lib1x_bauthsm_txReq( Global_Params * global, int identifier );
void lib1x_bauthsm_sendRespToServer( Global_Params * global, int identifier );

int lib1x_acctsm_sendReqToServer( Global_Params * global);
//--------------------------------------------------
// Initialize it.
//--------------------------------------------------
void lib1x_bauthsm_init( Bauth_SM * bauth_sm, int maxReq, int aWhile )
{
	assert( bauth_sm != NULL );

	bauth_sm->state = basm_Initialize;
	bauth_sm->reqCount = 0;
	bauth_sm->rxResp = FALSE;
	bauth_sm->aSuccess = FALSE;
	bauth_sm->aFail = FALSE;
	bauth_sm->aReq = FALSE;
	bauth_sm->idFromServer = -1;  // Neg value = invalid value

	// These are the constants initialized to their respective default values.
	bauth_sm->suppTimeout = aWhile;
	bauth_sm->serverTimeout = aWhile;
	bauth_sm->maxReq = maxReq;



}

//--------------------------------------------------
// Handles transitions and inits for the transitions.
//--------------------------------------------------
void lib1x_bauthsm( Auth_Pae * auth_pae, Global_Params * global, Bauth_SM * bauth_sm )
{
	BOOLEAN transitionDone;


	transitionDone = lib1x_trans_bauthsm( auth_pae, global, bauth_sm );
	if ( transitionDone )
	{
		lib1x_exec_bauthsm( auth_pae, global,  bauth_sm );

	}
}


//--------------------------------------------------
// lib1x_trans_bauthsm :
//  This function implements a single transition for the Backend Authentication
//  State Machine. .. but not the initialization !!
//--------------------------------------------------
BOOLEAN lib1x_trans_bauthsm( Auth_Pae * auth_pae, Global_Params * global, Bauth_SM 	* bauth_sm )
{


	// Global Transitions first !
	if ( ( global->portControl  != pmt_Auto ) || ( global->initialize ) || ( global->authAbort ) )
	{
		bauth_sm->state = basm_Initialize;
		return TRUE;
	}


	switch ( bauth_sm->state )
	{
		case	basm_Request :
				 if ( bauth_sm->rxResp )
				 {
					 bauth_sm->state = basm_Response;
					 return TRUE;
				 }
				 if ( ( global->timers->aWhile == 0 ) && ( bauth_sm->reqCount != bauth_sm->maxReq ) )
				 {
					 // No change in state
					 return TRUE;
				 }
				 if ( ( global->timers->aWhile == 0 ) && ( bauth_sm->reqCount >= bauth_sm->maxReq ) )
				 {
					 bauth_sm->state = basm_Timeout;
					 return TRUE;
				 }
				 break;
		case	basm_Response:
//added by Emily 2003/11/26
				 if ( bauth_sm->rxResp )
				 {
					 bauth_sm->state = basm_Response;
					 return TRUE;
				 }


				 if ( bauth_sm->aReq )
				 {
					 bauth_sm->state = basm_Request;
					 return TRUE;
				 }
				 if ( global->timers->aWhile == 0 )
				 {
					 bauth_sm->state = basm_Timeout;
					 return TRUE;
				 }
				 if ( bauth_sm->aFail )
				 {
					 bauth_sm->state = basm_Fail;
					 return TRUE;
				 }
				 if ( bauth_sm->aSuccess )
				 {
					 bauth_sm->state = basm_Success;
					 return TRUE;
				 }
				 break;
		case	basm_Success:
				 bauth_sm->state = basm_Idle ; 	// Unconditional Transfer !
				 return TRUE;
				 break;

		case 	basm_Timeout:
				 bauth_sm->state = basm_Idle ; 	// Unconditional Transfer !
				 return TRUE;
				 break;

		case	basm_Initialize:
				 bauth_sm->state = basm_Idle ; 	// Unconditional Transfer !
				 return TRUE;
				 break;
		case	basm_Fail:
				 bauth_sm->state = basm_Idle ; 	// Unconditional Transfer !
				 return TRUE;
				 break;
		case 	basm_Idle:
				 if ( global->authStart )
				 {
					 bauth_sm->state = basm_Response;
					 return TRUE;
				 }
				 break;


	}
	return FALSE;

}




//--------------------------------------------------
// lib1x_exec_bauthsm:
//  This function implements the init functions that have to be executed on
//  entry to a state.
//--------------------------------------------------
void lib1x_exec_bauthsm( Auth_Pae * auth_pae, Global_Params * global, Bauth_SM * bauth_sm )
{


	switch ( bauth_sm->state )
	{
		case	basm_Request :
				lib1x_exec_bauthsm_request(  auth_pae,   global,   bauth_sm );
				 break;
		case	basm_Response:
				lib1x_exec_bauthsm_response(  auth_pae,   global,   bauth_sm );
				 break;
		case	basm_Success:
				lib1x_exec_bauthsm_success(  auth_pae,   global,   bauth_sm );
				 break;

		case 	basm_Timeout:
				lib1x_exec_bauthsm_timeout(  auth_pae,   global,   bauth_sm );
				 break;

		case	basm_Initialize:
				lib1x_exec_bauthsm_initialize(  auth_pae,   global,   bauth_sm );
				 break;

		case	basm_Fail:
				lib1x_exec_bauthsm_fail(  auth_pae,   global,   bauth_sm );
				 break;

		case 	basm_Idle:
				lib1x_exec_bauthsm_idle(  auth_pae,   global,   bauth_sm );
				 break;


	}
}

// Inits for the request state.
void lib1x_exec_bauthsm_request( Auth_Pae * auth_pae, Global_Params * global, Bauth_SM * bauth_sm )
{
	lib1x_message(MESS_DBG_SPECIAL,"BAUTHSM> Entering REQ state.");
	global->currentId = bauth_sm->idFromServer;
	lib1x_bauthsm_txReq( global, global->currentId ); // TODO
	global->timers->aWhile = bauth_sm->suppTimeout;
	bauth_sm->reqCount ++;
}


// Response state inits.
void lib1x_exec_bauthsm_response( Auth_Pae * auth_pae, Global_Params * global, Bauth_SM * bauth_sm )
{
	lib1x_message(MESS_DBG_SPECIAL,"BAUTHSM> Entering RESPONSE state.");
	bauth_sm->aReq = bauth_sm->aSuccess = FALSE;
	global->authTimeout = FALSE;
	bauth_sm->rxResp = bauth_sm->aFail = FALSE;
	global->timers->aWhile = bauth_sm->serverTimeout;
	bauth_sm->reqCount = 0;
	lib1x_bauthsm_sendRespToServer(global, global->currentId);	// TODO
}

// Success state inits.
void lib1x_exec_bauthsm_success( Auth_Pae * auth_pae, Global_Params * global, Bauth_SM * bauth_sm )
{
	global->currentId = bauth_sm->idFromServer;
	lib1x_auth_txCannedSuccess( auth_pae, global->currentId ); //TODO
	global->authSuccess = TRUE;
	lib1x_message( MESS_DBG_SPECIAL,"BAUTHSM> SUCCESS STATE.");

}

// Fail state inits.
void lib1x_exec_bauthsm_fail( Auth_Pae * auth_pae, Global_Params * global, Bauth_SM * bauth_sm )
{
	global->currentId = bauth_sm->idFromServer;
	lib1x_auth_txCannedFail( auth_pae, global->currentId );	// TODO
	global->authFail = TRUE;
}

// Timeout state inits.
void lib1x_exec_bauthsm_timeout( Auth_Pae * auth_pae, Global_Params * global, Bauth_SM * bauth_sm )
{
	if ( global->portStatus == pst_Unauthorized )
	{
		lib1x_auth_txCannedFail( auth_pae, global->currentId ); //TODO
	}
	global->authTimeout = TRUE;
}


// Idle state inits.
void lib1x_exec_bauthsm_idle( Auth_Pae * auth_pae, Global_Params * global, Bauth_SM * bauth_sm )
{
	global->authStart = FALSE;
	bauth_sm->reqCount = 0;
}



// Initialize state inits.
void lib1x_exec_bauthsm_initialize( Auth_Pae * auth_pae, Global_Params * global, Bauth_SM * bauth_sm )
{
	lib1x_bauthsm_abortAuth(); //TODO
	global->authAbort = FALSE;
}



//----------------------------------------
// lib1x_bauthsm_abortAuth()
// TODO
// bauthsm releases any system resources and
// informs auth sm of auth abort.
//----------------------------------------
void lib1x_bauthsm_abortAuth()
{
	lib1x_message(MESS_ERROR_OK,"Backend Authentication SM: abortAuth: Authentication Aborted.");
}


//----------------------------------------
// txReq(x): EAPOL frame of type
// EAP Request
//----------------------------------------
void lib1x_bauthsm_txReq( Global_Params * global, int identifier )
{
	struct lib1x_eapol * eapol;
	struct lib1x_eap * eap;
	struct lib1x_ethernet * eth_hdr;
	Auth_Pae * auth_pae;
	int size;
	u_char * packet;
	struct pktbuf * bufpkt;
	struct lib1x_packet printPkt;
#ifdef CONFIG_RTL_ETH_802DOT1X_SUPPORT
	unsigned char dot1x_group_mac[ETHER_HDRLEN] = {0x01,0x80,0xC2,0x00,0x00,0x03};
#endif


	// Note: Every time this authpae sends a packet the SAME send buffer is used.
	//


	auth_pae = global->theAuthenticator;
        if ( auth_pae->sendreplyready )	/* if we prefabricated */
	{
		packet = auth_pae->sendBuffer;
		size = auth_pae->sendbuflen;
		lib1x_message(MESS_DBG_BSM, "Sending PREFABRICATED EAP packet to SUPPLICANT");
		printPkt.data = auth_pae->sendBuffer;
		printPkt.caplen = size;

#ifdef RTL_WPA2_PREAUTH
	if (global->RSNVariable.isPreAuth)  {
		lib1x_nal_send(auth_pae->global->TxRx->network_ds, auth_pae->sendBuffer,  size );
	} else
		lib1x_nal_send(auth_pae->global->TxRx->network_supp, auth_pae->sendBuffer,  size );
#else
		lib1x_nal_send(auth_pae->global->TxRx->network_supp, auth_pae->sendBuffer,  size );
#endif
		auth_pae->sendreplyready = FALSE;
		return;
	}
	else lib1x_message(MESS_ERROR_FATAL," Attempt to send non-prefabricated packet");

	packet = auth_pae->sendBuffer;
	bufpkt = & auth_pae->fromsvr;	// i.e. to supplicant
	if ( bufpkt->length <= 0 )
	{
		lib1x_message(MESS_ERROR_OK," lib1x_bauthsm_txReq: Request for Xmit .. but no packet buffered !");
		return;
	}

	size = ETHER_HDRLEN + sizeof( struct lib1x_eapol ) + sizeof( struct lib1x_eap ) + 1 + bufpkt->length;
	if ( size >= LIB1X_AP_SENDBUFLEN ) size = LIB1X_AP_SENDBUFLEN - 1 ;
	bzero( auth_pae->sendBuffer, size );

	eth_hdr = ( struct lib1x_ethernet * ) packet;
#ifdef CONFIG_RTL_ETH_802DOT1X_SUPPORT
	if(auth_pae->global->auth->currentRole == role_eth && (!auth_pae->global->auth->ethDot1xEapolUnicastEnabled))
		memcpy ( eth_hdr->ether_dhost, dot1x_group_mac, ETHER_HDRLEN);
	else
#endif

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
	eap->length = htons( LIB1X_EAP_HDRLEN + bufpkt->length );

	eapol->packet_body_length = htons( LIB1X_EAP_HDRLEN + bufpkt->length );
	memcpy( ( ( u_char *) eap ) + LIB1X_EAP_HDRLEN, bufpkt->pkt, bufpkt->length );
#if defined(CONFIG_RTL_ETH_802DOT1X_SUPPORT)
	if((auth_pae->global->auth->currentRole == role_eth) && (!auth_pae->global->auth->ethDot1xEapolUnicastEnabled)&&(global->auth->ethDot1xMode & ETH_DOT1X_PROXY_MODE))
	{
		lib1x_add_portinfo_to_eap_pkt(auth_pae->sendBuffer, &size,LIB1X_AP_SENDBUFLEN, global->port_num);
	}
#endif

	lib1x_message(MESS_DBG_AUTH, "Sending Request EAP packet to Supplicant");

#ifdef RTL_WPA2_PREAUTH
	if (global->RSNVariable.isPreAuth)  {
		lib1x_nal_send( auth_pae->global->TxRx->network_ds, auth_pae->sendBuffer,  size );
	} else
	lib1x_nal_send( auth_pae->global->TxRx->network_supp, auth_pae->sendBuffer,  size );
#else
	lib1x_nal_send( auth_pae->global->TxRx->network_supp, auth_pae->sendBuffer,  size );
#endif
}

//----------------------------------------
// sendRespToServer(x): frame of type
// EAP Response to server
//----------------------------------------
void lib1x_bauthsm_sendRespToServer( Global_Params * global, int identifier )
{
	struct lib1x_eapol * eapol;
	struct lib1x_eap * eap;
	struct lib1x_ethernet * eth_hdr;
	Auth_Pae * auth_pae;
	int size;
	u_char * packet;
	struct pktbuf * bufpkt;
	struct lib1x_packet  printPkt;
	u_char * sendptr;

	// Note: Every time this authpae sends a packet the SAME send buffer is used.
	//


	auth_pae = global->theAuthenticator;

	if ( auth_pae->sendreplyready )
	{
		packet = auth_pae->sendBuffer;
		size = auth_pae->sendbuflen;
		lib1x_message(MESS_DBG_BSM, "Sending PREFABRICATED EAP packet to Server");
		printPkt.data = auth_pae->sendBuffer;
		printPkt.caplen = size;
		/* temporary hack to use udp sockets  TODO*/
		sendptr = auth_pae->sendBuffer + ETHER_HDRLEN + LIB1X_IPHDRLEN + LIB1X_UDPHDRLEN;
		size -= ETHER_HDRLEN + LIB1X_IPHDRLEN + LIB1X_UDPHDRLEN;

		lib1x_nal_send( auth_pae->global->TxRx->network_svr, sendptr,  size );
		lib1x_message( MESS_DBG_BSM, " Sending RADIUS EAP Response to server.");
		auth_pae->sendreplyready = FALSE;
		return;
	}
	else lib1x_message(MESS_ERROR_FATAL," Attempt to send non-prefabricated packet");

	packet = auth_pae->sendBuffer;
	bufpkt = &auth_pae->fromsupp;	// i.e. to server
	if ( bufpkt->length <= 0 )
	{
		lib1x_message(MESS_ERROR_OK," lib1x_bauthsm_sendRespToServer: Request for Xmit .. but no packet buffered !");
		return;
	}

	size = ETHER_HDRLEN + sizeof( struct lib1x_eapol ) + sizeof( struct lib1x_eap ) + 1 + bufpkt->length;
	if ( size >= LIB1X_AP_SENDBUFLEN ) size = LIB1X_AP_SENDBUFLEN - 1 ;
	bzero( auth_pae->sendBuffer, size );

	eth_hdr = ( struct lib1x_ethernet * ) packet;
	memcpy ( eth_hdr->ether_dhost , auth_pae->global->TxRx->svr_addr, ETHER_ADDRLEN );
	memcpy ( eth_hdr->ether_shost , auth_pae->global->TxRx->oursvr_addr, ETHER_ADDRLEN );

	eapol = ( struct lib1x_eapol * )  ( packet +  ETHER_HDRLEN )  ;
					// We subtract 2 because of the common type field

	eth_hdr->ether_type = htons(LIB1X_ETHER_EAPOL_TYPE);
	eapol->protocol_version = LIB1X_EAPOL_VER;
	eapol->packet_type = LIB1X_EAPOL_EAPPKT;

	eap = (struct lib1x_eap * ) ( ( (u_char *) eapol) + LIB1X_EAPOL_HDRLEN );
	eap->code =  LIB1X_EAP_REQUEST;
	eap->identifier = identifier;
	eap->length = LIB1X_EAP_HDRLEN + bufpkt->length;

	eapol->packet_body_length = LIB1X_EAP_HDRLEN + bufpkt->length;
	memcpy( ( ( u_char *) eap ) + LIB1X_EAP_HDRLEN, bufpkt->pkt, bufpkt->length );

	lib1x_message(MESS_DBG_AUTH, "Sending Response EAP packet to Server");

	lib1x_nal_send( auth_pae->global->TxRx->network_svr, auth_pae->sendBuffer,  size );
}
