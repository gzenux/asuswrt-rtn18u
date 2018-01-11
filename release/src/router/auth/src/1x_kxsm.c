
//--------------------------------------------------
// IEEE 802.1x Implementation
//
// File		: 1x_kxsm.c
// Programmer	: Arunesh Mishra
//
// Copyright (c) Arunesh Mishra 2002
// All rights reserved.
// Maryland Information and Systems Security Lab
// University of Maryland, College Park.
// Key Transmit State Machine
//--------------------------------------------------

#include "1x_kxsm.h"
#include "1x_common.h"
#include "1x_auth_pae.h"
#include "1x_ioctl.h"
#include "1x_eapol.h"
#include "1x_kmsm_eapolkey.h"
#include "1x_nal.h"

#include <stddef.h>
//#include <openssl/hmac.h>
//#include <openssl/evp.h>
#include "1x_rc4.h"


//--------------------------------------------------
// init function for the Authenticator Key Transmit State Machine.
//--------------------------------------------------
void lib1x_kxsm_init( Auth_KeyxmitSM * key_sm )
{
	assert( key_sm != NULL );

	key_sm->state = kxsm_No_Key_Transmit;
	key_sm->keyAvailable = FALSE;
	key_sm->keyTxEnabled = TRUE;
}

//--------------------------------------------------
// lib1x_trans_authxmitsm:
// This function implements one transition of the Authenticator Key Transmit State Machine.
//--------------------------------------------------
void lib1x_trans_kxsm( Auth_Pae * auth_pae, Global_Params * global, Auth_KeyxmitSM * key_sm )
{

#ifdef CONFIG_IEEE80211R
	if(global->AuthKeyMethod == DOT11_AuthKeyType_RSN ||
		global->AuthKeyMethod == DOT11_AuthKeyType_RSNPSK ||
		global->AuthKeyMethod == DOT11_AuthKeyType_FT)
		return;
#else
	if(global->AuthKeyMethod != DOT11_AuthKeyType_NonRSN802dot1x ||
		(global->AuthKeyMethod == DOT11_AuthKeyType_NonRSN802dot1x && global->RSNVariable.UnicastCipher == DOT11_ENC_NONE && global->RSNVariable.MulticastCipher == DOT11_ENC_NONE) )
		return;
#endif
	if(key_sm->keyAvailable)
		lib1x_message(MESS_DBG_KXSM, "key_sm->keyAvailable=%d\n", key_sm->keyAvailable);



	// Global condition first :
	if ( global->initialize || global->portControl != pmt_Auto )
	{
		key_sm->state = kxsm_No_Key_Transmit;
		// Note: No initialization for this state.
		return;
	}


	if ( key_sm->state == kxsm_No_Key_Transmit  &&
		(  key_sm->keyTxEnabled  && key_sm->keyAvailable  &&
			   ( global->portStatus == pst_Authorized ) )
	   )
	{
		key_sm->state = kxsm_Key_Transmit;
		lib1x_kxsm_key_transmit( auth_pae, global, key_sm );
		return;
	}

	if ( key_sm->state == kxsm_Key_Transmit &&
		       key_sm->keyAvailable )
	{
		// Next state is the same state : key_transmit
		lib1x_kxsm_key_transmit( auth_pae, global, key_sm );
		return;
	}

	if ( key_sm->state == kxsm_Key_Transmit &&
			( ! key_sm->keyTxEnabled || global->portStatus == pst_Unauthorized ) )
	{
		key_sm->state = kxsm_No_Key_Transmit;
		// Note : No initialization for entry to this state.
		return;
	}


}


//--------------------------------------------------
// lib1x_authxmitsm_key_transmit:
//  This function has the initialization for entry to state Key_Transmit for the
//  Authenticator Key Transmit State Machine.
//--------------------------------------------------
void lib1x_kxsm_key_transmit( Auth_Pae * auth_pae, Global_Params * global, Auth_KeyxmitSM *  key_sm )
{


	struct lib1x_ethernet * eth;
	struct lib1x_eapol * eapol;
	struct lib1x_eapolkey_dot1x *eapol_key;

	OCTET_STRING	ocCounter;
	u_long		ulKeyLen = 5;
	RC4_KEY         rc4key;

	//TODO read default key with ioctl
	/*
	u_char		szDefaultKey[16] = {0x11, 0x11,0x11, 0x11,0x11, 0x11,0x11, 0x11,
	 				    0x11, 0x11,0x11, 0x11,0x11, 0x11,0x11, 0x11};
	*/
	u_char 		szIV[16] = {0x22, 0x22,0x22, 0x22,0x22, 0x22,0x22, 0x22,
	 			    0x22, 0x22,0x22, 0x22,0x22, 0x22,0x22, 0x22};
	u_char		szKeyBuf[64];


	// Set the from / to ethernet addresses.
	memset(auth_pae->sendBuffer, 0, 100);
	eth = ( struct lib1x_ethernet * ) auth_pae->sendBuffer;
	memcpy ( eth->ether_dhost, auth_pae->supp_addr, ETHER_HDRLEN);
	memcpy ( eth->ether_shost, auth_pae->global->TxRx->oursupp_addr, ETHER_HDRLEN);
	eth->ether_type = htons( LIB1X_ETHER_EAPOL_TYPE );

	eapol = ( struct lib1x_eapol * )( auth_pae->sendBuffer + ETHER_HDRLEN );
	eapol->protocol_version = LIB1X_EAPOL_VER;
	eapol->packet_type = LIB1X_EAPOL_KEY;


	if(global->RSNVariable.UnicastCipher == DOT11_ENC_WEP40)
		ulKeyLen = 5;
	else if(global->RSNVariable.UnicastCipher == DOT11_ENC_WEP104)
		ulKeyLen = 13;
	//
	else if(global->RSNVariable.UnicastCipher == DOT11_ENC_NONE)
		ulKeyLen = 13;
	//

	if(auth_pae->sendreplyready == TRUE)
	{

		//----------------------------------------
		//(1)Send Group Key using default key
		//----------------------------------------

		eapol_key = (struct lib1x_eapolkey_dot1x *) ( ( (u_char *) eapol) + LIB1X_EAPOL_HDRLEN );

		eapol_key->type = LIB1X_KEY_TYPE_RC4;
		lib1x_S2N(ulKeyLen, (u_char*)&eapol_key->length);

		ocCounter.Octet = (u_char*)malloc(LIB1X_RC_LEN);
		ocCounter.Length = LIB1X_RC_LEN;
		ReplayCounter_LI2OC(ocCounter, &global->auth->Dot1xKeyReplayCounter);
		memcpy(eapol_key->counter, ocCounter.Octet, LIB1X_RC_LEN);
		INCLargeInteger(&global->auth->Dot1xKeyReplayCounter);

		//printf("Higg = %d, Low = %d\n", global->auth->Dot1xKeyReplayCounter.field.HighPart,
		//global->auth->Dot1xKeyReplayCounter.field.LowPart);

		//TODO:Generate Random number as Key IV
		memcpy(eapol_key->iv, szIV, LIB1X_IV_LEN);
		eapol_key->index = 0;
		eapol_key->index |= (EAPOL_GROUP_KEY|EAPOL_GROUP_INDEX);


		memcpy(szKeyBuf, szIV, LIB1X_IV_LEN);
		memcpy(&szKeyBuf[16], global->RadiusKey.RecvKey.Octet, global->RadiusKey.RecvKey.Length);
		RC4_set_key(&rc4key, LIB1X_IV_LEN + global->RadiusKey.RecvKey.Length, szKeyBuf);
		//lib1x_hexdump2(MESS_DBG_RAD, "TestFun", szKeyBuf, LIB1X_IV_LEN + global->RadiusKey.RecvKey.Length, "szKeyBuf");

		//Need to be removed
		/*
		memcpy(	global->auth->gk_sm->GTK[global->auth->gk_sm->GN] ,
			szDefaultKey,
			global->RSNVariable.MulticastCipher == DOT11_ENC_WEP40 ? 5:13);
		*/
		//RC4(&rc4key, ulKeyLen, (u_char*)szDefaultKey, (u_char*)(eapol_key->material));
		RC4(&rc4key, ulKeyLen, (u_char*)global->auth->WepGroupKey, (u_char*)(eapol_key->material));

		eapol->packet_body_length = htons(LIB1X_EAPOLKEY_HDRLEN + ulKeyLen);
		//lib1x_hexdump2(MESS_DBG_KXSM, "lib1x_kxsm_key_transmit", auth_pae->sendBuffer, 100, "snedBuffer");
		memset(eapol_key->mic, 0, sizeof(eapol_key->mic));

		hmac_md5((u_char*)eapol,
			  LIB1X_EAPOL_HDRLEN + LIB1X_EAPOLKEY_HDRLEN + ulKeyLen,
			  global->RadiusKey.SendKey.Octet,
			  global->RadiusKey.SendKey.Length,
			  eapol_key->mic);

		auth_pae->sendbuflen = ETHER_HDRLEN + LIB1X_EAPOL_HDRLEN + LIB1X_EAPOLKEY_HDRLEN + ulKeyLen;
#ifdef ALLOW_DBG_KXSM
		lib1x_hexdump2(MESS_DBG_KXSM, "lib1x_kxsm_key_transmit", auth_pae->sendBuffer, auth_pae->sendbuflen, "Send EAPOL-KEY of Group Key");
#endif

		if(global->auth->RSNVariable.MulticastCipher == DOT11_ENC_WEP40 ||
			global->auth->RSNVariable.MulticastCipher == DOT11_ENC_WEP104)
			lib1x_nal_send( auth_pae->global->TxRx->network_supp, auth_pae->sendBuffer,
				auth_pae->sendbuflen );

		lib1x_control_SetGTK(global);

 		//----------------------------------------
		//(2)Send Key-mapping-Key
		//----------------------------------------


		eapol_key = (struct lib1x_eapolkey_dot1x *) ( ( (u_char *) eapol) + LIB1X_EAPOL_HDRLEN );

		eapol_key->type = LIB1X_KEY_TYPE_RC4;
		lib1x_S2N(ulKeyLen, (u_char*)&eapol_key->length);

		ocCounter.Length = LIB1X_RC_LEN;
		ReplayCounter_LI2OC(ocCounter, &global->auth->Dot1xKeyReplayCounter);
		memcpy(eapol_key->counter, ocCounter.Octet, LIB1X_RC_LEN);
		INCLargeInteger(&global->auth->Dot1xKeyReplayCounter);

		//printf("Higg = %d, Low = %d\n", global->auth->Dot1xKeyReplayCounter.field.HighPart,
		//global->auth->Dot1xKeyReplayCounter.field.LowPart);

		//TODO:Generate Random number as Key IV
		memcpy(eapol_key->iv, szIV, LIB1X_IV_LEN);
		eapol_key->index = 0;
		eapol_key->index |= (EAPOL_PAIRWISE_KEY|EAPOL_PAIRWISE_INDEX);



		eapol->packet_body_length = htons(LIB1X_EAPOLKEY_HDRLEN);
		memset(eapol_key->mic, 0, sizeof(eapol_key->mic));

		hmac_md5((u_char*)eapol,
			  LIB1X_EAPOL_HDRLEN + LIB1X_EAPOLKEY_HDRLEN,
			  global->RadiusKey.SendKey.Octet,
			  global->RadiusKey.SendKey.Length,
			  eapol_key->mic);

		auth_pae->sendbuflen = ETHER_HDRLEN + LIB1X_EAPOL_HDRLEN + LIB1X_EAPOLKEY_HDRLEN;
#ifdef ALLOW_DBG_KXSM
		lib1x_hexdump2(MESS_DBG_KXSM, "lib1x_kxsm_key_transmit", auth_pae->sendBuffer, auth_pae->sendbuflen, "Send EAPOL-KEY of key-mapping-key");
#endif
		if(global->RSNVariable.UnicastCipher == DOT11_ENC_WEP40 ||
			global->RSNVariable.UnicastCipher == DOT11_ENC_WEP104)
                	lib1x_nal_send( auth_pae->global->TxRx->network_supp,
					auth_pae->sendBuffer,auth_pae->sendbuflen );


 		//----Set key-mapping key to driver
		//----Key Mapping is for 5280
		//lib1x_control_KeyMapping(global, KEYMAP_OPERATION_SET, WEP_MODE_ON_40, KEYMAP_VALID_ON);
		//----SetPTK is for software encryption

		lib1x_control_SetPORT(global, DOT11_PortStatus_Authorized);
		lib1x_control_SetPTK(global);

	}

	//lib1x_authxmitsm_txKey( auth_pae , global->currentId );	// TODO

	auth_pae->sendreplyready = FALSE;
	key_sm->keyAvailable = FALSE;
	global->RadiusKey.Status = MPPE_SDRCKEY_NONAVALIABLE;

	free(ocCounter.Octet);

}

#ifndef COMPACK_SIZE
//--------------------------------------------------
// Transmit key to authenticator. TODO
//--------------------------------------------------
void lib1x_authxmitsm_txKey( Auth_Pae * auth_pae, int currentId )
{




	if ( auth_pae->sendreplyready )       /* if we prefabricated */
	{
		lib1x_nal_send( auth_pae->global->TxRx->network_supp, auth_pae->sendBuffer,
			auth_pae->sendbuflen );
		auth_pae->sendreplyready = FALSE;
	}
	lib1x_message(MESS_DBG_KXSM,"Key Transmit SM: Transmit Key to Authenticator");


}
#endif

