#include "stdafx.h"
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>

#include "1x_info.h"
#include "1x_ioctl.h"
#include "1x_kmsm_eapolkey.h"
#include "1x_supp_pae.h"
#include "1x_eapol.h"
#include "1x_nal.h"

#define SUPP_MAX_RETRY 3
#define STA_START_WAIT_PACKET(pGlobal)	(pGlobal->supp_kmsm->bWaitForPacket = TRUE)
#define STA_CLEAR_WAIT_PACKET(pGlobal)  (pGlobal->supp_kmsm->bWaitForPacket = FALSE)

#ifdef RTL_WPA_CLIENT

#ifdef CLIENT_TLS
#include "xsup_src/profile.h"
#include "xsup_src/xsup_err.h"
#include "xsup_src/xsup_debug.h"

extern struct interface_data *int_list;
#endif

#ifdef RTL_WPA2_CLIENT
extern void CalcPMKID(char* pmkid, char* pmk, char* aa, char* spa
#ifdef CONFIG_IEEE80211W
, int use_sha256
#endif
);

#endif

#if defined(CONFIG_RTL865X_KLD)
unsigned char ap_mac[6];
#endif

extern void wpa2_hexdump(char *name, u_char *buf, int size);
extern struct _WPA2_PMKSA_Node* find_pmksa(u_char *pmkid);
extern int DecWPA2KeyData(Supp_Global *pGlobal, u_char *key, int keylen, u_char *kek, int keklen, u_char *kout);

/*==================================================================
 Initialize Supplicnat
==================================================================*/
Supp_Global * lib1x_init_supp(Dot1x_Authenticator * pAuth, Dot1x_Client *pClient)
{

	Supp_Global 	* pGlobal;
	Supp_Pae_Params * pSuppPae;

	pGlobal = ( Supp_Global * ) malloc ( sizeof(Supp_Global ) ) ;
	if(pGlobal == NULL)
		return NULL;

	pSuppPae = (Supp_Pae_Params *) malloc ( sizeof(Supp_Pae_Params));
	if(pSuppPae == NULL)
		return NULL;

	pGlobal->supp_kmsm = (Supp_Kmsm *) malloc ( sizeof(Supp_Kmsm));
	if(pGlobal->supp_kmsm == NULL)
		return NULL;

	//Initialize only once
	pGlobal->auth = pAuth;
#ifdef RTL_WPA_CLIENT
	pGlobal->auth->client = pClient;
#endif
	pGlobal->supp_pae = pSuppPae;
	pSuppPae->global = pGlobal;
	pClient->auth = pAuth;
	pClient->supp_pae = pSuppPae;
	pClient->global = pGlobal;

	//pSuppPae->sendbuflen = 1600;
	pSuppPae->sendbuflen = LIB1X_AP_SENDBUFLEN ; //sc_yang
	pSuppPae->sendBuffer = (u_char *) malloc ( pSuppPae->sendbuflen * sizeof(u_char ));

	if ( pSuppPae->sendBuffer == NULL )
	{
		printf("\nCould not allocate memory for send buffer.");
		exit(1);
	}

	// Initialize Supplicnat Global Parameters
	pGlobal->EAPOLMsgRecvd.Length =  (pSuppPae->sendbuflen * sizeof(u_char ));
        pGlobal->EAPOLMsgSend.Length = ( pSuppPae->sendbuflen * sizeof(u_char ));

	// Read and Copy from result of parsing wpa.conf in 1x_config.c
	if(pAuth->RSNVariable.AuthenticationSuit.AlgoTable[DOT11_AuthKeyType_RSNPSK].Enabled)
		pGlobal->AuthKeyMethod = DOT11_AuthKeyType_RSNPSK;
#ifdef CLIENT_TLS
	else if(pAuth->RSNVariable.AuthenticationSuit.AlgoTable[DOT11_AuthKeyType_RSN].Enabled){
		pGlobal->AuthKeyMethod = DOT11_AuthKeyType_RSN;
	}else if(pAuth->RSNVariable.AuthenticationSuit.AlgoTable[DOT11_AuthKeyType_802_1X_SHA256].Enabled){//CONFIG_IEEE80211W_CLI
		pGlobal->AuthKeyMethod = DOT11_AuthKeyType_802_1X_SHA256;	
	}
#endif

#ifdef RTL_WPA2_CLIENT
	if(pAuth->RSNVariable.WPA2Enabled) {
		if (pAuth->RSNVariable.WPA2UniCastCipherSuit.AlgoTable[DOT11_ENC_TKIP].Enabled)
			pGlobal->RSNVariable.UnicastCipher = DOT11_ENC_TKIP;
		else if(pAuth->RSNVariable.WPA2UniCastCipherSuit.AlgoTable[DOT11_ENC_CCMP].Enabled)
			pGlobal->RSNVariable.UnicastCipher = DOT11_ENC_CCMP;
	} else {
		if(pAuth->RSNVariable.UniCastCipherSuit.AlgoTable[DOT11_ENC_TKIP].Enabled)
			pGlobal->RSNVariable.UnicastCipher = DOT11_ENC_TKIP;
		else if(pAuth->RSNVariable.UniCastCipherSuit.AlgoTable[DOT11_ENC_CCMP].Enabled)
			pGlobal->RSNVariable.UnicastCipher = DOT11_ENC_CCMP;
	}
#else

	if(pAuth->RSNVariable.UniCastCipherSuit.AlgoTable[DOT11_ENC_TKIP].Enabled)
		pGlobal->RSNVariable.UnicastCipher = DOT11_ENC_TKIP;
	else if(pAuth->RSNVariable.UniCastCipherSuit.AlgoTable[DOT11_ENC_CCMP].Enabled)
		pGlobal->RSNVariable.UnicastCipher = DOT11_ENC_CCMP;
#endif

	//only PSK is supported
	memcpy(pGlobal->supp_kmsm->PMK,
		pAuth->RSNVariable.PassPhraseKey,
		PMK_LEN);//For PSK mode


	pGlobal->DescriptorType = pGlobal->auth->Dot11RSNConfig.Version;
//	pGlobal->KeyDescriptorVer = key_desc_ver1;
#ifdef CONFIG_IEEE80211W
	if (pGlobal->auth->RSNVariable.MulticastCipher == DOT11_ENC_BIP)
		pGlobal->KeyDescriptorVer = key_desc_ver3; 
	else 
#endif	
	if (pGlobal->auth->RSNVariable.MulticastCipher == DOT11_ENC_CCMP)
		pGlobal->KeyDescriptorVer = key_desc_ver2;
	else
		pGlobal->KeyDescriptorVer = key_desc_ver1;

//debug
	{
		pGlobal->TxRx = pGlobal->auth->GlobalTxRx;
	}
	pGlobal->ConstTimerCount = SECONDS_TO_TIMERCOUNT(1);

//debug should be read from configuration file
//	pGlobal->RSNVariable.MulticastCipher = DOT11_ENC_TKIP;
	pGlobal->RSNVariable.MulticastCipher = pGlobal->auth->RSNVariable.MulticastCipher;


	//Initilize Supplicant key management state machine
        pGlobal->supp_kmsm->ANonce.Octet = (u_char*)malloc(KEY_NONCE_LEN);
	pGlobal->supp_kmsm->ANonce.Length = KEY_NONCE_LEN;
	pGlobal->supp_kmsm->SNonce.Octet = (u_char*)malloc(KEY_NONCE_LEN);
	pGlobal->supp_kmsm->SNonce.Length = KEY_NONCE_LEN;
	pGlobal->supp_kmsm->PairwiseUpdateCount = SUPP_MAX_RETRY;
	pGlobal->supp_kmsm->AuthInfoElement.Octet = (u_char*)malloc(INFO_ELEMENT_SIZE);
	pGlobal->supp_kmsm->AuthInfoElement.Length = 0;
	pGlobal->supp_kmsm->SuppInfoElement.Octet = (u_char*)malloc(INFO_ELEMENT_SIZE);
//debug
	{
		//kenny for client bug
		memcpy(pGlobal->supp_kmsm->SuppInfoElement.Octet, pAuth->RSNVariable.AuthInfoElement.Octet, pAuth->RSNVariable.AuthInfoElement.Length);
		pGlobal->supp_kmsm->SuppInfoElement.Length =  pAuth->RSNVariable.AuthInfoElement.Length ;


	}


#ifdef RTL_WPA2_CLIENT
	GenNonce(pGlobal->supp_kmsm->Counter.charData, (u_char*)"addr");
	SetNonce(pGlobal->supp_kmsm->SNonce, pGlobal->supp_kmsm->Counter);
	pGlobal->supp_kmsm->SNonce.Length = KEY_NONCE_LEN;
#endif

	//Initialize whenever reset
	lib1x_reset_supp(pGlobal);
	return pGlobal;
}

//-------------------------
//Initialize whenever reset
//-------------------------
void lib1x_reset_supp(Supp_Global * pGlobal)
{


	pGlobal->supp_kmsm->CurrentReplayCounter.field.HighPart = DEFAULT_KEY_REPLAY_COUNTER_LONG;
	pGlobal->supp_kmsm->CurrentReplayCounter.field.LowPart = DEFAULT_KEY_REPLAY_COUNTER_LONG;

#ifndef RTL_WPA2_CLIENT
	GenNonce(pGlobal->supp_kmsm->Counter.charData, (u_char*)"addr");
	SetNonce(pGlobal->supp_kmsm->SNonce, pGlobal->supp_kmsm->Counter);
	pGlobal->supp_kmsm->SNonce.Length = KEY_NONCE_LEN;
#endif


	pGlobal->supp_kmsm->TimeoutCtr = 0;
	pGlobal->supp_kmsm->PairwiseUpdateCount = 3;
	pGlobal->supp_kmsm->bWaitForPacket = TRUE;
	pGlobal->supp_kmsm->bIsSetKey = FALSE;
#ifdef RTL_WPA2_CLIENT
	pGlobal->supp_kmsm->bIsSetGTK = FALSE;
#endif
	pGlobal->supp_kmsm->bAuthProgressing = FALSE;

	// jimmylin 20050824
	pGlobal->supp_kmsm->bIsHndshkDone = FALSE;
}



/*==================================================================
 Procedure called during execution of state machine
==================================================================*/
void lib1x_do_supplicant( Dot1x_Authenticator * pAuth, Supp_Global * pSupp )
{

	int do_event;

	if (  pAuth == NULL || pSupp == NULL)
	{
		lib1x_message(MESS_ERROR_FATAL, " Null argument received.");
		exit(1);
	}

	do_event = 1;
	while (do_event) {
		do_event=lib1x_nal_receive(pAuth);
	}

//#ifdef CLIENT_TLS	//Deleted for test
#if 0
	printf("%s(%d): pSupp->AuthKeyMethod(%d)=============== \n",__FUNCTION__,__LINE__,pSupp->AuthKeyMethod);//Added for test
	if (pSupp->AuthKeyMethod == DOT11_AuthKeyType_RSN)
	{
	  char newframe[1518], respframe[1518];
	  int framesize = 0, respsize, retval=0;
	  struct eapol_header *temp;
	  char *inframe = NULL;    // A pointer to our frame data.  (Normally will point
			    		// to the newframe[] array.)
	  struct interface_data *workint = int_list;
	  // Process our state machine.
	  printf("%s(%d): ========================= \n",__FUNCTION__,__LINE__);//Added for test
	  if (workint != NULL && statemachine_run(workint, inframe, framesize,
			       (char *)&respframe, &respsize) == XDATA)
	    {
	      // Send a frame out.
	  printf("%s(%d): to sendframe========================= \n",__FUNCTION__,__LINE__);//Added for test
	      sendframe(workint, (char *)&respframe, respsize);
	    }
	}
#endif /* CLIENT_TLS */

}


void lib1x_supp_timer_proc(Dot1x_Client *pClient)
{



	Supp_Global * pGlobal = pClient->global;
	Supp_Kmsm * pSupp_kmsm = pGlobal->supp_kmsm;

	if(pSupp_kmsm->bWaitForPacket && pGlobal->supp_kmsm->bAuthProgressing)
	{
		if(pSupp_kmsm->TimeoutCtr <= pSupp_kmsm->PairwiseUpdateCount )
		{
			if(pSupp_kmsm->TimeoutCtr >= 1)
			{
				lib1x_message(MESS_DBG_SUPP, "Wait for packet Timeout, Resent");
				//lib1x_hexdump2(MESS_DBG_SUPP, "lib1x_skmsm_EAPOLKeySend", pGlobal->supp_pae->sendBuffer, pGlobal->EAPOLMsgSend.Length, "Client send");
				lib1x_nal_send( pGlobal->TxRx->network_supp, pGlobal->supp_pae->sendBuffer, pGlobal->EAPOLMsgSend.Length );

				//Activate Retry Mechanism
				if(Message_KeyType(pGlobal->EapolKeyMsgSend) == type_Pairwise)
				{
					STA_START_WAIT_PACKET(pGlobal);
				}
				else if(Message_KeyType(pGlobal->EapolKeyMsgSend) == type_Group)
				{
					STA_CLEAR_WAIT_PACKET(pGlobal);
				}
			}


			pSupp_kmsm->TimeoutCtr++;
		}else
		{
			lib1x_message(MESS_DBG_SUPP, "Maxmun Retry. Disassociate with AP\n");
//remove
			//lib1x_control_AuthDisconnect(pClient->auth, pGlobal->supp_pae->auth_addr, RSN_4_way_handshake_timeout);

			lib1x_reset_supp(pGlobal);
		}

	}

}
#ifdef CONFIG_RTL_ETH_802DOT1X_CLIENT_MODE_SUPPORT
void lib1x_eth_1sec_timer()
{
	struct interface_data *intcur;
	char respframe[1518];
	int  respsize;
  	intcur = int_list;
	if (intcur != NULL && intcur->statemachine != NULL)
	{
	     if(statemachine_run(intcur, NULL, 0, respframe, &respsize) == XDATA){
			sendframe(intcur, (char *)&respframe, respsize);
		}
	}
}
#endif
//--------------------------------------------------
// Process event indicated from driver
//--------------------------------------------------
void lib1x_suppsm_capture_control( Supp_Global * pGlobal, lib1x_nal_intfdesc_tag * nal, lib1x_packet_tag * spkt )
{
	u_char *msg = (u_char *)spkt->data;
	u_char event = *(msg+0);

	DOT11_DISASSOCIATION_IND * pDisAssoInd;

#ifdef RTL_WPA2_CLIENT
	DOT11_WPA2_MULTICAST_CIPHER * pWpa2MuticastCipher;
	DOT11_ASSOCIATION_IND * pAssoInd;
	Supp_Kmsm * supp_kmsm = pGlobal->supp_kmsm;
#endif
	DOT11_WPA_MULTICAST_CIPHER *pWpaMuticastCipher; // david
	unsigned char ssid[40];

	//u_long	ulRSNIELen;


	switch(event)
	{
	case DOT11_EVENT_DISASSOCIATION_IND:
		pDisAssoInd = (DOT11_DISASSOCIATION_IND *)msg;
		lib1x_reset_supp(pGlobal);
		lib1x_message(MESS_DBG_SUPP, "Receive Disassociation Indication, Reason Code = %d. Reset State Machine\n", pDisAssoInd->Reason);
		break;
	case DOT11_EVENT_ASSOCIATION_IND:
		lib1x_reset_supp(pGlobal);
		lib1x_message(MESS_DBG_SUPP, "Receive association Indication, Reset State Machine\n");

		// reset PMK
		if (pGlobal->auth->UsePassphrase) {
			lib1x_control_STA_QUERY_SSID(pGlobal, ssid);
			if (strcmp(pGlobal->auth->RSNVariable.ssid, ssid)) {
				strcpy(pGlobal->auth->RSNVariable.ssid, ssid);			
				PasswordHash(pGlobal->auth->RSNVariable.PassPhrase, strlen(pGlobal->auth->RSNVariable.PassPhrase),
					(unsigned char *)pGlobal->auth->RSNVariable.ssid, strlen(pGlobal->auth->RSNVariable.ssid), pGlobal->auth->RSNVariable.PassPhraseKey);
				memcpy(pGlobal->supp_kmsm->PMK,
					pGlobal->auth->RSNVariable.PassPhraseKey,
					PMK_LEN);
			}
		}

#ifdef RTL_WPA2_CLIENT
		pAssoInd = (DOT11_ASSOCIATION_IND *)msg;
		//wpa2_hexdump("pGlobal->TxRx->oursupp_addr", pGlobal->TxRx->oursupp_addr, 6);
		//wpa2_hexdump("pAssoInd->MACAddr", pAssoInd->MACAddr, 6);
		if ( pGlobal->auth->RSNVariable.WPA2Enabled) {
#ifdef CONFIG_IEEE80211W
			if(pGlobal->auth->RSNVariable.ieee80211w != NO_MGMT_FRAME_PROTECTION) {
		
				CalcPMKID(
						supp_kmsm->PMKID,
						supp_kmsm->PMK, 	 // PMK
						pAssoInd->MACAddr,	 // AA
						pGlobal->TxRx->oursupp_addr, // SPA
						(pGlobal->AuthKeyMethod==DOT11_AuthKeyType_802_1X_SHA256)); 
			} else
#endif //CONFIG_IEEE80211W
			{
				CalcPMKID(
						supp_kmsm->PMKID,
						supp_kmsm->PMK, 	 // PMK
						pAssoInd->MACAddr,   // AA
						pGlobal->TxRx->oursupp_addr
#ifdef CONFIG_IEEE80211W
						,(pGlobal->AuthKeyMethod==DOT11_AuthKeyType_802_1X_SHA256)
#endif

						); // SPA
			}
		}
#endif

			// david+2006-03-31, add event to syslog
			{
				char *pmsg;
				switch (pGlobal->RSNVariable.UnicastCipher) {
					case DOT11_ENC_NONE: pmsg="none"; break;
					case DOT11_ENC_WEP40:	pmsg = "WEP40"; break;
					case DOT11_ENC_TKIP: 	pmsg = "TKIP"; break;
					case DOT11_ENC_WRAP: pmsg = "AES"; break;
				    case DOT11_ENC_CCMP: pmsg = "AES"; break;
					case DOT11_ENC_WEP104: pmsg = "WEP104"; break;
					default: pmsg = "invalid algorithm"; break;
				}
				syslog(LOG_AUTH|LOG_INFO, "%s: %s-%s PSK authentication in progress...\n", 
					dev_supp, 
					(pGlobal->auth->RSNVariable.WPA2Enabled ? "WPA2" : "WPA"), 
					pmsg);
#if defined(CONFIG_RTL865X_KLD)
				DOT11_ASSOCIATION_IND *pAssoc = (DOT11_ASSOCIATION_IND *)msg;
				memcpy(ap_mac,  pAssoc->MACAddr, 6);
				LOG_MSG_NOTICE("Authenticating......;note:%02x-%02x-%02x-%02x-%02x-%02x;", 
					ap_mac[0],ap_mac[1],ap_mac[2],ap_mac[3],ap_mac[4],ap_mac[5]);				
#endif
			}

			// david+2006-04-26, query wlan mac address because it may be updated when mac-cloned is enabled
			{	
			    int skfd;
				struct ifreq ifr;
				struct sockaddr hwaddr;
	
			    skfd = socket(AF_INET, SOCK_DGRAM, 0);
			    strcpy(ifr.ifr_name, dev_supp);
			    if (ioctl(skfd, SIOCGIFFLAGS, &ifr) >=0) {
			    	if (ioctl(skfd, SIOCGIFHWADDR, &ifr) >= 0) {
						memcpy(&hwaddr, &ifr.ifr_hwaddr, sizeof(struct sockaddr));
						memcpy(pGlobal->TxRx->oursupp_addr, hwaddr.sa_data, 6);				
    				}
			   	}
				close(skfd);
			}
			
		/*
		//---- Add Element ID and Length ----
		pAssoInd = (DOT11_ASSOCIATION_IND *)msg;
		lib1x_N2S((u_char*)&pAssoInd->RSNIELen, ulRSNIELen);
		supp_kmsm->AuthInfoElement.Octet[0] = RSN_ELEMENT_ID;
		supp_kmsm->AuthInfoElement.Octet[1] = ulRSNIELen;
		memcpy(supp_kmsm->AuthInfoElement.Octet + 2,
			pAssoInd->RSNIE, ulRSNIELen);
		supp_kmsm->AuthInfoElement.Length = ulRSNIELen + 2;


		//Check RSNIE from Association Response.
		//Compare content without capability field and IE Length, hence, 0x16-2 bytes
		if(supp_kmsm->SuppInfoElement.Octet[0] == supp_kmsm->AuthInfoElement.Octet[0] &&
			!memcmp(supp_kmsm->SuppInfoElement.Octet+2, supp_kmsm->AuthInfoElement.Octet+2, 20))
		{
			lib1x_message(MESS_DBG_SUPP, "Recieve Association Response. Start Wait 4-way handshake\n");
			lib1x_reset_supp(pGlobal);
			STA_START_WAIT_PACKET(pGlobal);
		}else
		{
			lib1x_message(MESS_DBG_SUPP, "RSN Element ID Does not ,match. Disassociate with Auth\n");
			lib1x_control_AuthDisconnect(pGlobal->auth,
				pGlobal->supp_pae->auth_addr,
				RSN_invalid_RSNE_capabilities);
		}	lib1x_reset_supp(pGlobal);
		*/
		break;
#ifdef RTL_WPA2_CLIENT
	case DOT11_EVENT_WPA2_MULTICAST_CIPHER:
		lib1x_message(MESS_DBG_SPECIAL, "Receive DOT11_EVENT_WPA2_MULTICAST_CIPHER\n");
		if (pGlobal->auth->RSNVariable.WPA2Enabled) {
			pWpa2MuticastCipher = (DOT11_WPA2_MULTICAST_CIPHER *)msg;
			pGlobal->RSNVariable.MulticastCipher = pWpa2MuticastCipher->MulticastCipher;
			//wpa2_hexdump("pGlobal->auth->RSNVariable.AuthInfoElement.Octet", pGlobal->auth->RSNVariable.AuthInfoElement.Octet, pGlobal->auth->RSNVariable.AuthInfoElement.Length);
			pGlobal->auth->RSNVariable.AuthInfoElement.Octet[7] = pGlobal->RSNVariable.MulticastCipher;
			pGlobal->supp_kmsm->SuppInfoElement.Octet[7] = pGlobal->RSNVariable.MulticastCipher;
			//wpa2_hexdump("pGlobal->auth->RSNVariable.AuthInfoElement.Octet", pGlobal->auth->RSNVariable.AuthInfoElement.Octet, pGlobal->auth->RSNVariable.AuthInfoElement.Length);
			//lib1x_control_RSNIE(pGlobal->auth, DOT11_Ioctl_Set);
		}
		break;
#endif

// david, add wep multicast cipher support in WPA ---------------------------------
	case DOT11_EVENT_WPA_MULTICAST_CIPHER:
		lib1x_message(MESS_DBG_SPECIAL, "Receive DOT11_EVENT_WPA_MULTICAST_CIPHER\n");
		if (pGlobal->auth->RSNVariable.WPAEnabled) {
			pWpaMuticastCipher = (DOT11_WPA_MULTICAST_CIPHER *)msg;
			pGlobal->RSNVariable.MulticastCipher = pWpaMuticastCipher->MulticastCipher;
			pGlobal->auth->RSNVariable.AuthInfoElement.Octet[7] = pGlobal->RSNVariable.MulticastCipher;
			pGlobal->supp_kmsm->SuppInfoElement.Octet[11] = pGlobal->RSNVariable.MulticastCipher;
		}
		break;
//------------------------------------------------------------------------------

	}
}

//--------------------------------------------------
// Callback handler for libpcap for packets
// from supplicant
//--------------------------------------------------
void lib1x_suppsm_capture_auth( Supp_Global * pGlobal, lib1x_nal_intfdesc_tag * nal, lib1x_packet_tag * spkt )
{
	struct lib1x_eapol     * eapol;
	struct lib1x_ethernet  * eth;
	u_char		       * packet;
	int 		       iRet;

	if(pGlobal == NULL)
	{
		printf("pGlobal is NULL");
		return;
	}
	if(nal == NULL)
	{
		printf("lib1x_nal_intfdesc is NULL");
		return;
	}
	if(spkt == NULL)
	{
		printf("spkt is NULL");
		return;
	}
	packet = (u_char *) spkt->data;
	eth = (struct lib1x_ethernet * ) packet;
	eapol = ( struct lib1x_eapol * ) ( packet + ETHER_HDRLEN );

	if ( spkt->caplen <= ( ETHER_HDRLEN + LIB1X_EAPOL_HDRLEN ) )
	{
	       lib1x_message( MESS_DBG_SUPP, "Too small a packet received from nal.");
	       return;
	}


	if ( eth->ether_type != htons(LIB1X_ETHER_EAPOL_TYPE) )
		return;
#ifdef CONFIG_RTL_ETH_802DOT1X_CLIENT_MODE_SUPPORT
	if(pGlobal->auth->currentRole != role_eth)
#endif
	if(lib1x_control_STA_QUERY_BSSID(pGlobal) != 0 )
		return;

#ifdef CLIENT_TLS
	lib1x_message(MESS_DBG_SUPP, "packet type = %s\n", eapol->packet_type == LIB1X_EAPOL_KEY? "LIB1X_EAPOL_KEY":"LIB1X_EAPOL_PACKET");
#endif
	switch( eapol->packet_type )
	{
		case	LIB1X_EAPOL_KEY:
			pGlobal->EAPOLMsgRecvd.Octet = (u_char*)spkt->data;
// Get eapol packet lebgth by refer eapol header, david+2007-10-30 ----
//			pGlobal->EAPOLMsgRecvd.Length = spkt->caplen;
			pGlobal->EAPOLMsgRecvd.Length = ntohs(eapol->packet_body_length) + ETHER_HDRLEN + LIB1X_EAPOL_HDRLEN;
//--------------------------------------------------------------
			pGlobal->EAPOLMsgSend.Octet = pGlobal->supp_pae->sendBuffer;


			if(!memcmp(eth->ether_dhost, pGlobal->auth->GlobalTxRx->oursupp_addr, ETHER_ADDRLEN))
			{

				//lib1x_hexdump2(MESS_DBG_SUPP, "lib1x_suppsm_capture_auth",
						//(u_char*)spkt->data, spkt->caplen, "Client Recv Packet");
				iRet = lib1x_skmsm_EAPOLKeyRecvd(pGlobal);
				if(!iRet)
					lib1x_skmsm_EAPOLKeySend(pGlobal);
				else
					lib1x_message(MESS_ERROR_OK, KM_STRERR(iRet));

			}
			break;
#ifdef CLIENT_TLS
		case	LIB1X_EAPOL_EAPPKT:
			{
				char respframe[1518];
				int  respsize;

				char *newframe = (u_char*)spkt->data;
				int framesize = spkt->caplen;
				struct interface_data *workint = int_list;
//				struct eap_header *myeap;

				eap_process_header(workint, (char *)newframe, framesize);
				// Process our state machine.
				if (statemachine_run(workint, newframe, framesize,
					(char *)&respframe, &respsize) == XDATA)
				{
					// Send a frame out.
					sendframe(workint, (char *)&respframe, respsize);
				}

			}
			break;
#endif /* CLIENT_TLS */

	}

}




/*==================================================================
 Key handshaking procedure
==================================================================*/

//--------------------------------------------------
// Return 0  for Success
//	  <0 for Error
//--------------------------------------------------

int lib1x_skmsm_EAPOLKeyRecvd(Supp_Global * pGlobal)
{
	int 		retVal = 1;

	OCTET_STRING	ocIV, ocKRC, ocKeyID, ocRSC, ocNonce;
	u_char	szIV[KEY_IV_LEN], szKRC[KEY_RSC_LEN], szKeyID[KEY_ID_LEN], szRSC[KEY_RSC_LEN], szNonce[KEY_NONCE_LEN];
	LARGE_INTEGER	liKRC;
#ifdef RTL_WPA2_CLIENT
	u_char*	 pKeyData;
	unsigned short keyDataLength;
#endif

	// Initialize pointer to send/recv packet
	pGlobal->EapolKeyMsgRecvd.Octet = pGlobal->EAPOLMsgRecvd.Octet + (ETHER_HDRLEN + LIB1X_EAPOL_HDRLEN);
	pGlobal->EapolKeyMsgRecvd.Length = pGlobal->EAPOLMsgRecvd.Length - (ETHER_HDRLEN + LIB1X_EAPOL_HDRLEN);

	pGlobal->EapolKeyMsgSend.Octet = pGlobal->EAPOLMsgSend.Octet + (ETHER_HDRLEN + LIB1X_EAPOL_HDRLEN);
	pGlobal->EapolKeyMsgSend.Length = pGlobal->EAPOLMsgSend.Length - (ETHER_HDRLEN + LIB1X_EAPOL_HDRLEN);

	//lib1x_eapol_key	* eapol_key_recvd = (lib1x_eapol_key * )pGlobal->EapolKeyMsgRecvd.Octet;
	//lib1x_eapol_key	* eapol_key_send = (lib1x_eapol_key * )pGlobal->EapolKeyMsgSend.Octet;

	// Initialize data structure
	ocKRC.Octet = &szKRC[0];
	ocKRC.Length = KEY_RSC_LEN;
	ocIV.Octet = &szIV[0];
	ocIV.Length = KEY_IV_LEN;
	ocRSC.Octet = &szRSC[0];
	ocRSC.Length = KEY_RSC_LEN;
	ocKeyID.Octet = &szKeyID[0];
	ocKeyID.Length = KEY_ID_LEN;
	ocNonce.Octet = &szNonce[0];
	ocNonce.Length = KEY_NONCE_LEN;

	// Process Message
	// (1) 1st message of 4-way handshake is received
	if( (Message_KeyType(pGlobal->EapolKeyMsgRecvd) == type_Pairwise) &&
		Message_KeyMIC(pGlobal->EapolKeyMsgRecvd) == FALSE)
	{
		lib1x_message(MESS_DBG_KEY_MANAGE, "Message 4-1");
#ifdef RTL_WPA2_CLIENT
		printf("4-1 received\n");
#endif
		// jimmylin 20050824
		if(pGlobal->supp_kmsm->bIsHndshkDone == TRUE)
		{
			lib1x_message(MESS_DBG_KEY_MANAGE, "AP trigger pairwise rekey\n");
			lib1x_reset_supp(pGlobal);
		}
		ocKRC = Message_ReplayCounter(pGlobal->EapolKeyMsgRecvd);
		ReplayCounter_OC2LI(ocKRC, &liKRC);
		if(!Message_DefaultReplayCounter(pGlobal->supp_kmsm->CurrentReplayCounter) &&
			Message_SmallerEqualReplayCounter(pGlobal->supp_kmsm->CurrentReplayCounter, pGlobal->EapolKeyMsgRecvd) )
		{
			lib1x_message(MESS_DBG_KEY_MANAGE, "Message 4-1 ERROR_EQUALSMALLER_REPLAYCOUNTER %d, (%d, %d)\n", __LINE__, Message_DefaultReplayCounter(pGlobal->supp_kmsm->CurrentReplayCounter), Message_SmallerEqualReplayCounter(pGlobal->supp_kmsm->CurrentReplayCounter,
			pGlobal->EapolKeyMsgRecvd));
			lib1x_message(MESS_DBG_KEY_MANAGE, "\n");
			retVal = ERROR_EQUALSMALLER_REPLAYCOUNTER;
#ifdef RTL_WPA2_CLIENT
		} else if ( pGlobal->auth->RSNVariable.WPA2Enabled && Message_DescType(pGlobal->EapolKeyMsgRecvd) == desc_type_WPA2) {
			static char PMKID_KDE_TYPE[] = { 0xDD, 0x14, 0x00, 0x0F, 0xAC, 0x04 };

			if ( Message_KeyDataLength(pGlobal->EapolKeyMsgRecvd) == 0x16
			     && !memcmp(pGlobal->EapolKeyMsgRecvd.Octet + KeyDataPos, PMKID_KDE_TYPE, sizeof (PMKID_KDE_TYPE))) {
// do not check PMKID for better compatibility, david 03/08/2005
//			     if ( pGlobal->AuthKeyMethod == DOT11_AuthKeyType_RSNPSK
//			          && memcmp(pGlobal->supp_kmsm->PMKID, pGlobal->EapolKeyMsgRecvd.Octet + KeyDataPos + sizeof (PMKID_KDE_TYPE), PMKID_LEN) != 0) {
			     if (0) {	
				printf("Message 4-1 ERROR_PMKID (PSK)");
				wpa2_hexdump("pGlobal->supp_kmsm->PMKID", pGlobal->supp_kmsm->PMKID, PMKID_LEN);
				wpa2_hexdump("4-1 PMKID", (pGlobal->EapolKeyMsgRecvd.Octet + KeyDataPos + sizeof (PMKID_KDE_TYPE)), PMKID_LEN);
				retVal = ERROR_PMKID_PSK;
				goto lib1x_skmsm_EAPOLKeyRecvd_End;
			     } 
				 // do not check PMKID for better compatibility for 802.1x wlan client mode, jianZhang 08/04/2010
				 // Test: wlan client mode 802.1x-tls, wpa-1x/wpa2-1x aes/tkip connect linksys(wrt300n) OK! 
				 //else if (pGlobal->AuthKeyMethod == DOT11_AuthKeyType_RSN) {
				 else if(0) {
				struct _WPA2_PMKSA_Node* pmksa = find_pmksa((unsigned char*) (pGlobal->EapolKeyMsgRecvd.Octet + KeyDataPos + 7));
			     	if ( pmksa == NULL) {
					syslog(LOG_AUTH|LOG_INFO, "%s: Authentication failled! (4-1: ERROR_PMKID)\n", dev_supp); // david+2006-03-31, add event to syslog			     		
#if defined(CONFIG_RTL865X_KLD)
					LOG_MSG_NOTICE("Authentication failed;note:%02x-%02x-%02x-%02x-%02x-%02x;", 
						ap_mac[0],ap_mac[1],ap_mac[2],ap_mac[3],ap_mac[4],ap_mac[5]);	
#endif											
					printf("Message 4-1 ERROR_PMKID (TLS)");
					retVal = ERROR_PMKID_TLS;
					goto lib1x_skmsm_EAPOLKeyRecvd_End;
			     	}
			     }

			     goto WPA2_PMKID_CHECK_OK;
			} else {
				if (Message_KeyDataLength(pGlobal->EapolKeyMsgRecvd) == 0) // with 1x
			     		goto WPA2_PMKID_CHECK_OK;
				else {
					printf("%s:%d ERROR!\n", __FUNCTION__, __LINE__);
				}
			}

		} else 	{
WPA2_PMKID_CHECK_OK:
#else
		}else
		{
#endif

			//printf("Enter %s, pSupp_kmsm->bWaitForPacket=%d\n", __FUNCTION__, pGlobal->supp_kmsm->bWaitForPacket);
			//printf("STA_CLEAR_WAIT_PACKET(2)(No Clear)\n");
			pGlobal->supp_kmsm->bAuthProgressing = TRUE;
//remove
			STA_CLEAR_WAIT_PACKET(pGlobal);

			pGlobal->supp_kmsm->ANonce = Message_KeyNonce(pGlobal->EapolKeyMsgRecvd);

			//construct message 2 of 4-way

			lib1x_message(MESS_DBG_KEY_MANAGE, "Message 4-2");
			lib1x_message(MESS_DBG_KEY_MANAGE, "\n");
#ifdef RTL_WPA2_CLIENT
			printf("4-2 sent\n");
#endif

			memset(pGlobal->EapolKeyMsgSend.Octet, 0, MAX_EAPOLKEYMSG_LEN);

#ifdef RTL_WPA2_CLIENT
			pGlobal->KeyDescriptorVer = Message_KeyDescVer(pGlobal->EapolKeyMsgRecvd);
			Message_setDescType(pGlobal->EapolKeyMsgSend, Message_DescType(pGlobal->EapolKeyMsgRecvd));
#else
			Message_setDescType(pGlobal->EapolKeyMsgSend, pGlobal->DescriptorType);
#endif
			Message_setKeyDescVer(pGlobal->EapolKeyMsgSend, Message_KeyDescVer(pGlobal->EapolKeyMsgRecvd));
			Message_setKeyType(pGlobal->EapolKeyMsgSend, Message_KeyType(pGlobal->EapolKeyMsgRecvd));
			Message_setKeyIndex(pGlobal->EapolKeyMsgSend, 0);
			Message_setInstall(pGlobal->EapolKeyMsgSend, Message_KeyIndex(pGlobal->EapolKeyMsgRecvd));
			Message_setKeyAck(pGlobal->EapolKeyMsgSend, 0);
			Message_setKeyMIC(pGlobal->EapolKeyMsgSend, 1);
			Message_setSecure(pGlobal->EapolKeyMsgSend, Message_Secure(pGlobal->EapolKeyMsgRecvd));
			Message_setError(pGlobal->EapolKeyMsgSend, Message_Error(pGlobal->EapolKeyMsgRecvd));
			Message_setRequest(pGlobal->EapolKeyMsgSend, Message_Request(pGlobal->EapolKeyMsgRecvd));
			Message_setReserved(pGlobal->EapolKeyMsgSend, 0);

			Message_setKeyLength(pGlobal->EapolKeyMsgSend, Message_KeyLength(pGlobal->EapolKeyMsgRecvd));
			Message_CopyReplayCounter(pGlobal->EapolKeyMsgSend, pGlobal->EapolKeyMsgRecvd);

			INCOctet32_INTEGER(&pGlobal->supp_kmsm->Counter);

#ifndef RTL_WPA2_CLIENT
			// fix the SNonce until 4 way is finished
			SetNonce(pGlobal->supp_kmsm->SNonce, pGlobal->supp_kmsm->Counter);
#endif
			Message_setKeyNonce(pGlobal->EapolKeyMsgSend, pGlobal->supp_kmsm->SNonce);

			CalcPTK(pGlobal->EAPOLMsgRecvd.Octet, pGlobal->EAPOLMsgRecvd.Octet + 6,
				pGlobal->supp_kmsm->ANonce.Octet, pGlobal->supp_kmsm->SNonce.Octet,
				pGlobal->supp_kmsm->PMK, PMK_LEN, pGlobal->supp_kmsm->PTK, (pGlobal->AuthKeyMethod == DOT11_AuthKeyType_802_1X_SHA256)?48:PTK_LEN_TKIP
#ifdef CONFIG_IEEE80211W
					, (pGlobal->AuthKeyMethod == DOT11_AuthKeyType_802_1X_SHA256)
#endif				
				);


			memset(ocIV.Octet, 0, ocIV.Length);
			Message_setKeyIV(pGlobal->EapolKeyMsgSend, ocIV);
			memset(ocRSC.Octet, 0, ocRSC.Length);
			Message_setKeyRSC(pGlobal->EapolKeyMsgSend, ocRSC);
			memset(ocKeyID.Octet, 0, ocKeyID.Length);
			Message_setKeyID(pGlobal->EapolKeyMsgSend, ocKeyID);
			Message_setKeyDataLength(pGlobal->EapolKeyMsgSend, pGlobal->supp_kmsm->SuppInfoElement.Length);
			Message_setKeyData(pGlobal->EapolKeyMsgSend, pGlobal->supp_kmsm->SuppInfoElement);

			pGlobal->EapolKeyMsgSend.Length = EAPOLMSG_HDRLEN + pGlobal->supp_kmsm->SuppInfoElement.Length;
			pGlobal->EAPOLMsgSend.Length = ETHER_HDRLEN + LIB1X_EAPOL_HDRLEN + pGlobal->EapolKeyMsgSend.Length;

//remove
			retVal = 0;

		} //if(Replay counter Valid)
	}

	// (2) 3rd message of 4-way handshake is received
	else if( (Message_KeyType(pGlobal->EapolKeyMsgRecvd) == type_Pairwise) &&
			   Message_KeyMIC(pGlobal->EapolKeyMsgRecvd) == TRUE)
	{
		lib1x_message(MESS_DBG_KEY_MANAGE, "Message 4-3");
#ifdef RTL_WPA2_CLIENT
		printf("4-3 received\n");
#endif
		ocKRC = Message_ReplayCounter(pGlobal->EapolKeyMsgRecvd);
		ReplayCounter_OC2LI(ocKRC, &liKRC);

		//lib1x_hexdump2(MESS_DBG_KEY_MANAGE,  __FUNCTION__, (pGlobal->supp_kmsm->ANonce.Octet), pGlobal->supp_kmsm->ANonce.Length, "A Nonce");
		//lib1x_hexdump2(MESS_DBG_KEY_MANAGE, __FUNCTION__, (pGlobal->EapolKeyMsgRecvd.Octet+KeyNoncePos), KEY_NONCE_LEN, "Received Nonce");
		if(!Message_DefaultReplayCounter(pGlobal->supp_kmsm->CurrentReplayCounter) &&
			Message_SmallerEqualReplayCounter(pGlobal->supp_kmsm->CurrentReplayCounter, pGlobal->EapolKeyMsgRecvd) )
		{
			lib1x_message(MESS_DBG_KEY_MANAGE, "Message 4-3:ERROR_EQUALSMALLER_REPLAYCOUNTER %d", __LINE__);
			// jimmylin remove, 2006-08-22
			//syslog(LOG_AUTH|LOG_INFO, "%s: Authentication failled! (4-3: ERROR_EQUALSMALLER_REPLAYCOUNTER)\n", dev_supp); // david+2006-03-31, add event to syslog
			retVal = ERROR_EQUALSMALLER_REPLAYCOUNTER;
		}else if(!Message_EqualKeyNonce(pGlobal->EapolKeyMsgRecvd, pGlobal->supp_kmsm->ANonce))
		{
			lib1x_message(MESS_DBG_KEY_MANAGE, "Message 4-3:ERROR_NONEQUAL_NONCE %d", __LINE__);
			syslog(LOG_AUTH|LOG_INFO, "%s: Authentication failled! (4-3: ERROR_NONEQUAL_NONCE)\n", dev_supp); // david+2006-03-31, add event to syslog			
#if defined(CONFIG_RTL865X_KLD)
			LOG_MSG_NOTICE("Authentication failed;note:%02x-%02x-%02x-%02x-%02x-%02x;", 
					ap_mac[0],ap_mac[1],ap_mac[2],ap_mac[3],ap_mac[4],ap_mac[5]);	
#endif			
			retVal = ERROR_NONEQUAL_NONCE;
		}
		else if(!CheckMIC(pGlobal->EAPOLMsgRecvd, pGlobal->supp_kmsm->PTK, PTK_LEN_EAPOLMIC))
		{
			lib1x_message(MESS_DBG_KEY_MANAGE, "Message 4-3:ERROR_MIC_FAIL %d", __LINE__);
			syslog(LOG_AUTH|LOG_INFO, "%s: Authentication failled! (4-3: MIC error)\n", dev_supp); // david+2006-03-31, add event to syslog			
#if defined(CONFIG_RTL865X_KLD)
			LOG_MSG_NOTICE("Authentication failed;note:%02x-%02x-%02x-%02x-%02x-%02x;", 
					ap_mac[0],ap_mac[1],ap_mac[2],ap_mac[3],ap_mac[4],ap_mac[5]);	
#endif										
			retVal = ERROR_MIC_FAIL;
		}else
		{
			STA_CLEAR_WAIT_PACKET(pGlobal);

			pGlobal->supp_kmsm->CurrentReplayCounter.field.HighPart = liKRC.field.HighPart;
			pGlobal->supp_kmsm->CurrentReplayCounter.field.LowPart = liKRC.field.LowPart;

#ifdef RTL_WPA2_CLIENT
if ( pGlobal->auth->RSNVariable.WPA2Enabled && Message_DescType(pGlobal->EapolKeyMsgRecvd) == desc_type_WPA2)
{
			u_char decrypted_data[128];
			u_char GTK_KDE_OUI[] = { 0x00, 0x0F, 0xAC, 0x01 };
			u_char WPA_IE_OUI[] = { 0x00, 0x50, 0xF2, 0x01 };
			u_char *pGTK_KDE;
			// dump Key Data Length and Key Data
			//wpa2_hexdump("4-3 EAPOL KEY Message", pGlobal->EapolKeyMsgRecvd.Octet, pGlobal->EapolKeyMsgRecvd.Length);
			keyDataLength = Message_KeyDataLength(pGlobal->EapolKeyMsgRecvd);
			//printf("4-3 KeyDataLength = %04X\n", keyDataLength);
			pKeyData = pGlobal->EapolKeyMsgRecvd.Octet + KeyDataPos;
			//wpa2_hexdump("4-3 KeyData",pKeyData,keyDataLength);
			//DecGTK(pGlobal->EAPOLMsgRecvd, u_char *kek, int keklen, int keylen,u_char *kout)
// Use RC4 or AES to decode the keydata by checking desc-ver, david-2006-01-06
//			if(!DecWPA2KeyData(pKeyData, keyDataLength, pGlobal->supp_kmsm->PTK + PTK_LEN_EAPOLMIC, PTK_LEN_EAPOLENC
			if(!DecWPA2KeyData(pGlobal, pKeyData, keyDataLength, pGlobal->supp_kmsm->PTK + PTK_LEN_EAPOLMIC, PTK_LEN_EAPOLENC
				, decrypted_data))

			{
				wpa2_hexdump("4-3 KeyData (Decrypted) ERROR",decrypted_data,keyDataLength);
				printf("Message 4-3:ERROR_AESKEYWRAP_MIC_FAIL %d", __LINE__);
				syslog(LOG_AUTH|LOG_INFO, "%s: Authentication failled! (4-3: ERROR_AESKEYWRAP_MIC_FAIL)\n", dev_supp); // david+2006-03-31, add event to syslog
#if defined(CONFIG_RTL865X_KLD)
				LOG_MSG_NOTICE("Authentication failed;note:%02x-%02x-%02x-%02x-%02x-%02x;", 
					ap_mac[0],ap_mac[1],ap_mac[2],ap_mac[3],ap_mac[4],ap_mac[5]);	
#endif											
				retVal = ERROR_AESKEYWRAP_MIC_FAIL;
				goto lib1x_skmsm_EAPOLKeyRecvd_End;
			}
			//wpa2_hexdump("4-3 KeyData (Decrypted)",decrypted_data,keyDataLength);
			if ( decrypted_data[0] == WPA2_ELEMENT_ID) {
				pGTK_KDE = &decrypted_data[2] + (u_char)decrypted_data[1];
				//printf("*pGTK_KDE = %02X\n", *pGTK_KDE);
				if ( *pGTK_KDE == WPA2_ELEMENT_ID ) {
					// The second optional RSNIE is present
					printf("The second optional RSNIE is present! Cannot handle it yet!");
					retVal = ERROR_SECOND_RSNIE;
					goto lib1x_skmsm_EAPOLKeyRecvd_End;
				} else if ( *pGTK_KDE == WPA_ELEMENT_ID ) {
					// if contain RSN IE, skip it
					if (!memcmp((pGTK_KDE+2), WPA_IE_OUI, sizeof(WPA_IE_OUI)))
						pGTK_KDE += (u_char)*(pGTK_KDE+1) + 2;

					if (!memcmp((pGTK_KDE+2), GTK_KDE_OUI, sizeof(GTK_KDE_OUI))) {
						// GTK Key Data Encapsulation Format
						u_char gtk_len = (u_char)*(pGTK_KDE+1) - 6;
						u_char keyID = (u_char)*(pGTK_KDE+6) & 0x03;
						pGlobal->supp_kmsm->GTK_KEYID = keyID;
						memcpy(pGlobal->supp_kmsm->GTK[keyID], (pGTK_KDE+8), gtk_len);
						//wpa2_hexdump("Decrypted GTK", pGlobal->supp_kmsm->GTK[keyID], gtk_len);
						pGlobal->supp_kmsm->bIsSetGTK = TRUE;
					}
				}
			}
}
#endif	/* RTL_WPA2_CLIENT */
			//construct message 4
			lib1x_message(MESS_DBG_KEY_MANAGE, "Message 4-4");
#ifdef RTL_WPA2_CLIENT
			printf("4-4 sent\n");
#endif
			memset(pGlobal->EapolKeyMsgSend.Octet, 0, MAX_EAPOLKEYMSG_LEN);

#ifdef RTL_WPA2_CLIENT
			Message_setDescType(pGlobal->EapolKeyMsgSend, Message_DescType(pGlobal->EapolKeyMsgRecvd));
#else
			Message_setDescType(pGlobal->EapolKeyMsgSend, pGlobal->DescriptorType);
#endif

			Message_setKeyDescVer(pGlobal->EapolKeyMsgSend, Message_KeyDescVer(pGlobal->EapolKeyMsgRecvd));
			Message_setKeyType(pGlobal->EapolKeyMsgSend, Message_KeyType(pGlobal->EapolKeyMsgRecvd));
			Message_setKeyIndex(pGlobal->EapolKeyMsgSend, Message_KeyIndex(pGlobal->EapolKeyMsgRecvd));
			Message_setInstall(pGlobal->EapolKeyMsgSend, 0);
			Message_setKeyAck(pGlobal->EapolKeyMsgSend, 0);
			Message_setKeyMIC(pGlobal->EapolKeyMsgSend, 1);
			Message_setSecure(pGlobal->EapolKeyMsgSend, Message_Secure(pGlobal->EapolKeyMsgRecvd));
			Message_setError(pGlobal->EapolKeyMsgSend, Message_Error(pGlobal->EapolKeyMsgRecvd));
			Message_setRequest(pGlobal->EapolKeyMsgSend, Message_Request(pGlobal->EapolKeyMsgRecvd));
			Message_setReserved(pGlobal->EapolKeyMsgSend, 0);

			Message_setKeyLength(pGlobal->EapolKeyMsgSend, Message_KeyLength(pGlobal->EapolKeyMsgRecvd));
			Message_CopyReplayCounter(pGlobal->EapolKeyMsgSend, pGlobal->EapolKeyMsgRecvd);
#ifndef RTL_WPA2_CLIENT
#ifndef DBG_WPA_CLIENT
			SetNonce(pGlobal->supp_kmsm->SNonce, pGlobal->supp_kmsm->Counter);
#endif
#endif /* RTL_WPA2_CLIENT */

#ifdef RTL_WPA2_CLIENT
			if ( pGlobal->auth->RSNVariable.WPA2Enabled && Message_DescType(pGlobal->EapolKeyMsgRecvd) == desc_type_WPA2) {
			} else {
				Message_setKeyNonce(pGlobal->EapolKeyMsgSend, pGlobal->supp_kmsm->SNonce);
			}
#else
			Message_setKeyNonce(pGlobal->EapolKeyMsgSend, pGlobal->supp_kmsm->SNonce);
#endif
			memset(ocIV.Octet, 0, ocIV.Length);
			Message_setKeyIV(pGlobal->EapolKeyMsgSend, ocIV);
			memset(ocRSC.Octet, 0, ocRSC.Length);
			Message_setKeyRSC(pGlobal->EapolKeyMsgSend, ocRSC);
			memset(ocKeyID.Octet, 0, ocKeyID.Length);
			Message_setKeyID(pGlobal->EapolKeyMsgSend, ocKeyID);
			Message_setKeyDataLength(pGlobal->EapolKeyMsgSend, 0);

			pGlobal->EapolKeyMsgSend.Length = EAPOLMSG_HDRLEN;
			pGlobal->EAPOLMsgSend.Length = ETHER_HDRLEN + LIB1X_EAPOL_HDRLEN + pGlobal->EapolKeyMsgSend.Length;

			//MLME_SETKEYS.request() after 4 message is sent;
			pGlobal->supp_kmsm->bIsSetKey = TRUE;

			retVal = 0;
#ifdef RTL_WPA2_CLIENT
			// fix the SNonce until 4 way is finished
			SetNonce(pGlobal->supp_kmsm->SNonce, pGlobal->supp_kmsm->Counter);
#endif
			printf("4-Way Message 4-4 done\n");
			syslog(LOG_AUTH|LOG_INFO, "%s: Open and authenticated\n", dev_supp); // david+2006-03-31, add event to syslog
#if defined(CONFIG_RTL865X_KLD)
			LOG_MSG_NOTICE("Authentication Success;note:%02x-%02x-%02x-%02x-%02x-%02x;", 
					ap_mac[0],ap_mac[1],ap_mac[2],ap_mac[3],ap_mac[4],ap_mac[5]);	
#endif			
		}
	}

	// (2) 1st message of 2-way handshake is received
	else if( Message_KeyType(pGlobal->EapolKeyMsgRecvd) == type_Group)
	{

		lib1x_message(MESS_DBG_KEY_MANAGE, "Message 2-1");
		ocKRC = Message_ReplayCounter(pGlobal->EapolKeyMsgRecvd);
		ReplayCounter_OC2LI(ocKRC, &liKRC);

		if(	Message_SmallerEqualReplayCounter(pGlobal->supp_kmsm->CurrentReplayCounter, pGlobal->EapolKeyMsgRecvd) )
		{
			lib1x_message(MESS_DBG_KEY_MANAGE, "Message 2-1:ERROR_EQUALSMALLER_REPLAYCOUNTER %d", __LINE__);
			retVal = ERROR_EQUALSMALLER_REPLAYCOUNTER;
		}else if(!CheckMIC(pGlobal->EAPOLMsgRecvd, pGlobal->supp_kmsm->PTK, PTK_LEN_EAPOLMIC))
		{
			lib1x_message(MESS_DBG_KEY_MANAGE, "Message 2-1:ERROR_MIC_FAIL %d", __LINE__);
			retVal = ERROR_MIC_FAIL;
		}else if(!DecGTK(pGlobal->EAPOLMsgRecvd, pGlobal->supp_kmsm->PTK + PTK_LEN_EAPOLMIC, PTK_LEN_EAPOLENC,
			((pGlobal->RSNVariable.MulticastCipher == DOT11_ENC_TKIP) ? 32:16),
			pGlobal->supp_kmsm->GTK[Message_KeyIndex(pGlobal->EapolKeyMsgRecvd)]))
		{
			lib1x_message(MESS_DBG_KEY_MANAGE, "Message 2-1:ERROR_AESKEYWRAP_MIC_FAIL %d", __LINE__);
			retVal = ERROR_AESKEYWRAP_MIC_FAIL;
		}else
		{
			u_char decrypted_data[128];
			u_char GTK_KDE_OUI[] = { 0x00, 0x0F, 0xAC, 0x01 };
			u_char *pGTK_KDE;
			u_char keyID;

			STA_CLEAR_WAIT_PACKET(pGlobal);
			keyID = Message_KeyIndex(pGlobal->EapolKeyMsgRecvd);
#ifdef RTL_WPA2_CLIENT
			if ( pGlobal->auth->RSNVariable.WPA2Enabled && 
				Message_DescType(pGlobal->EapolKeyMsgRecvd) == desc_type_WPA2) {

				memcpy(decrypted_data, 
					pGlobal->supp_kmsm->GTK[keyID],
					Message_KeyDataLength(pGlobal->EapolKeyMsgRecvd));

				pGTK_KDE = decrypted_data;
				if ( *pGTK_KDE == 0xDD && 
						!memcmp((pGTK_KDE+2), GTK_KDE_OUI, sizeof(GTK_KDE_OUI))) {
					// GTK Key Data Encapsulation Format
					u_char gtk_len = (u_char)*(pGTK_KDE+1) - 6;
					keyID = (u_char)*(pGTK_KDE+6) & 0x03;
					pGlobal->supp_kmsm->GTK_KEYID = keyID;
					memcpy(pGlobal->supp_kmsm->GTK[keyID], (pGTK_KDE+8), gtk_len);		
					pGlobal->supp_kmsm->bIsSetGTK = TRUE;			
				}

			}
			
#endif	// RTL_WPA2_CLIENT

			//MLME_SETKEYS.request() to set Group Key;
			lib1x_control_STA_SetGTK(pGlobal,
				pGlobal->supp_kmsm->GTK[keyID],
				keyID);

			pGlobal->supp_kmsm->CurrentReplayCounter.field.HighPart = liKRC.field.HighPart;
			pGlobal->supp_kmsm->CurrentReplayCounter.field.LowPart = liKRC.field.LowPart;

			//construct message 2 of 2-way handshake
			memset(pGlobal->EapolKeyMsgSend.Octet, 0, MAX_EAPOLKEYMSG_LEN);

			Message_setDescType(pGlobal->EapolKeyMsgSend, pGlobal->DescriptorType);
			Message_setKeyDescVer(pGlobal->EapolKeyMsgSend, Message_KeyDescVer(pGlobal->EapolKeyMsgRecvd));
			Message_setKeyType(pGlobal->EapolKeyMsgSend, Message_KeyType(pGlobal->EapolKeyMsgRecvd));
			Message_setKeyIndex(pGlobal->EapolKeyMsgSend, keyID);
			Message_setInstall(pGlobal->EapolKeyMsgSend, 0);
			Message_setKeyAck(pGlobal->EapolKeyMsgSend, 0);
			Message_setKeyMIC(pGlobal->EapolKeyMsgSend, 1);
			Message_setSecure(pGlobal->EapolKeyMsgSend, 1);
			Message_setError(pGlobal->EapolKeyMsgSend, 0);
			Message_setRequest(pGlobal->EapolKeyMsgSend, 0);
			Message_setReserved(pGlobal->EapolKeyMsgSend, 0);

			Message_setKeyLength(pGlobal->EapolKeyMsgSend, Message_KeyLength(pGlobal->EapolKeyMsgRecvd));
			Message_CopyReplayCounter(pGlobal->EapolKeyMsgSend, pGlobal->EapolKeyMsgRecvd);
			memset(ocNonce.Octet, 0, KEY_NONCE_LEN);
			Message_setKeyNonce(pGlobal->EapolKeyMsgSend, ocNonce);
			memset(ocIV.Octet, 0, ocIV.Length);
			Message_setKeyIV(pGlobal->EapolKeyMsgSend, ocIV);
			memset(ocRSC.Octet, 0, ocRSC.Length);
			Message_setKeyRSC(pGlobal->EapolKeyMsgSend, ocRSC);
			memset(ocKeyID.Octet, 0, ocKeyID.Length);
			Message_setKeyID(pGlobal->EapolKeyMsgSend, ocKeyID);
			Message_setKeyDataLength(pGlobal->EapolKeyMsgSend, 0);

			pGlobal->EapolKeyMsgSend.Length = EAPOLMSG_HDRLEN;
			pGlobal->EAPOLMsgSend.Length = ETHER_HDRLEN + LIB1X_EAPOL_HDRLEN + pGlobal->EapolKeyMsgSend.Length;

			// jimmylin 20050824
			pGlobal->supp_kmsm->bIsHndshkDone = TRUE;

			retVal = 0;
			printf("Group Message 2-2 done\n");

		}
	}

#ifdef RTL_WPA2_CLIENT
lib1x_skmsm_EAPOLKeyRecvd_End:
#endif
	return retVal;

}

void lib1x_skmsm_EAPOLKeySend(Supp_Global * pGlobal)
{

	Supp_Pae_Params  	*supp_pae = pGlobal->supp_pae;

        struct lib1x_eapol 	* eapol;
        struct lib1x_ethernet 	* eth_hdr;

	eth_hdr = ( struct lib1x_ethernet * )pGlobal->EAPOLMsgSend.Octet;


	//lib1x_hexdump2(MESS_DBG_SUPP, "lib1x_skmsm_EAPOLKeySend", pGlobal->supp_pae->auth_addr, 6, "Bssid");
	memcpy ( eth_hdr->ether_dhost , pGlobal->supp_pae->auth_addr, ETHER_ADDRLEN );
	memcpy ( eth_hdr->ether_shost , supp_pae->global->TxRx->oursupp_addr, ETHER_ADDRLEN );

	eth_hdr->ether_type = htons(LIB1X_ETHER_EAPOL_TYPE);

	eapol = ( struct lib1x_eapol * )  ( pGlobal->EAPOLMsgSend.Octet +  ETHER_HDRLEN )  ;
	eapol->protocol_version = LIB1X_EAPOL_VER;
	eapol->packet_type =  LIB1X_EAPOL_KEY;

	eapol->packet_body_length = htons(pGlobal->EapolKeyMsgSend.Length);


	//MIC is calculated
	CalcMIC(pGlobal->EAPOLMsgSend, pGlobal->KeyDescriptorVer, pGlobal->supp_kmsm->PTK, PTK_LEN_EAPOLMIC);

	//lib1x_hexdump2(MESS_DBG_SUPP, "lib1x_skmsm_EAPOLKeySend", supp_pae->sendBuffer, pGlobal->EAPOLMsgSend.Length, "Client send");
	lib1x_nal_send( pGlobal->TxRx->network_supp, supp_pae->sendBuffer, pGlobal->EAPOLMsgSend.Length );

	//Activate Retry Mechanism
	pGlobal->supp_kmsm->TimeoutCtr = 0;

	if(Message_KeyType(pGlobal->EapolKeyMsgSend) == type_Pairwise)
		STA_START_WAIT_PACKET(pGlobal);
	else if(Message_KeyType(pGlobal->EapolKeyMsgSend) == type_Group)
	{
		STA_CLEAR_WAIT_PACKET(pGlobal);
	}

	if(pGlobal->supp_kmsm->bIsSetKey)
	{
		lib1x_control_STA_SetPTK(pGlobal);
		lib1x_control_STA_SetPORT(pGlobal, DOT11_PortStatus_Authorized);
		pGlobal->supp_kmsm->bIsSetKey = FALSE;
	}

#ifdef RTL_WPA2_CLIENT
	if(pGlobal->supp_kmsm->bIsSetGTK) {
		lib1x_control_STA_SetGTK(pGlobal,
			pGlobal->supp_kmsm->GTK[pGlobal->supp_kmsm->GTK_KEYID],
			pGlobal->supp_kmsm->GTK_KEYID);

// david+2006-01-06, fix the issue that Linksys AP will use keyid=2 in broadcast packet but set ID=1
		lib1x_control_STA_SetGTK(pGlobal,
			pGlobal->supp_kmsm->GTK[pGlobal->supp_kmsm->GTK_KEYID],
			((pGlobal->supp_kmsm->GTK_KEYID==1) ? 2 : 1));
		
		pGlobal->supp_kmsm->bIsSetGTK = FALSE;
		if(Message_KeyType(pGlobal->EapolKeyMsgSend) == type_Pairwise)
			STA_CLEAR_WAIT_PACKET(pGlobal);

		// jimmylin 20050824
		pGlobal->supp_kmsm->bIsHndshkDone = TRUE;
	}
#endif
}

#endif // RTL_WPA_CLIENT
