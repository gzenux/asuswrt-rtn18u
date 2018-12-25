#include <stdlib.h>
#include <string.h>

#include "1x_kmsm.h"
#include "1x_info.h"
#include "1x_types.h"
#include "1x_kmsm_eapolkey.h"
#include "1x_ioctl.h"

#include "1x_auth_pae.h"
#include "1x_eapol.h"
#include "1x_radius.h"


#ifdef DBG_WPA_CLIENT
#include "1x_supp_pae.h"
extern Dot1x_Client		RTLClient;
#endif
static u_long global_pmksa_aging = 0;
//#define FOURWAY_DEBUG

#define SOLVE_DUP_4_2
//-------------------------------------------------------------
// Execution of state machine in 802.11i/D3.0 p.113
//-------------------------------------------------------------
int lib1x_akmsm_AssociationRequest( Global_Params * global);
int lib1x_akmsm_AuthenticationRequest( Global_Params * global);
int lib1x_akmsm_AuthenticationSuccess( Global_Params * global);
int lib1x_akmsm_Disconnect( Global_Params * global);
int lib1x_akmsm_EAPOLKeyRecvd( Global_Params * global);
int lib1x_akmsm_IntegrityFailure( Global_Params * global);

//-------------------------------------------------------------
// Procedure called by key management state machine block
//-------------------------------------------------------------
int  lib1x_akmsm_ProcessEAPOL_proc(Global_Params * global);
int  lib1x_akmsm_SendEAPOL_proc(Global_Params * global);
void lib1x_akmsm_Timer_proc(Dot1x_Authenticator * auth);
int  lib1x_akmsm_GroupReKey_Timer_proc(Dot1x_Authenticator * auth);
int  lib1x_akmsm_UpdateGK_proc(Dot1x_Authenticator *auth);

//-------------------------------------------------------------
// Called by external global authenticator
//-------------------------------------------------------------
void lib1x_akmsm_execute( Global_Params * global);

#ifdef HS2_SUPPORT
static int isFileExist(char *file_name)
{
    struct stat status;

    if ( stat(file_name, &status) < 0)
        return 0;

    return 1;
}
static int hs2_check_dgaf_disable(unsigned char *ifname)
{
	unsigned char pfile[100];

	if (!strcmp(ifname, "wlan0"))	{
		sprintf(pfile, "tmp/dgaf_%s", ifname);
	}
	else if (!strcmp(ifname, "wlan0-va0"))   {
        sprintf(pfile, "tmp/dgaf_%s", ifname);
    }
	else if (!strcmp(ifname, "wlan0-va1"))   {
        sprintf(pfile, "tmp/dgaf_%s", ifname);
    }
	else if (!strcmp(ifname, "wlan0-va2"))   {
        sprintf(pfile, "tmp/dgaf_%s", ifname);
    }
	else if (!strcmp(ifname, "wlan0-va3"))   {
        sprintf(pfile, "tmp/dgaf_%s", ifname);
    }
	else if (!strcmp(ifname, "wlan1"))   {
        sprintf(pfile, "tmp/dgaf_%s", ifname);
    }
	else if (!strcmp(ifname, "wlan1-va0"))   {
        sprintf(pfile, "tmp/dgaf_%s", ifname);
    }
	else if (!strcmp(ifname, "wlan1-va1"))   {
        sprintf(pfile, "tmp/dgaf_%s", ifname);
    }
	else if (!strcmp(ifname, "wlan1-va2"))   {
        sprintf(pfile, "tmp/dgaf_%s", ifname);
    }
	else if (!strcmp(ifname, "wlan1-va3"))   {
        sprintf(pfile, "tmp/dgaf_%s", ifname);
    }    
	else	{
		printf("!!!unknown interface:[%s], check!!\n", ifname);
		return 0;
	}

    if(isFileExist(pfile))
    {
        FILE *fp=NULL;
        unsigned char tmp_str[10];

        memset(tmp_str,0x00,sizeof(tmp_str));

        fp=fopen(pfile, "r");
        if(fp!=NULL)
        {
            fgets((char *)tmp_str,sizeof(tmp_str),fp);
            fclose(fp);

            if(strlen((char *)tmp_str) != 0)
			{
				if (tmp_str[0] == '1')
					return 1;
			}
		}
	}
	return 0;
}
#endif

inline void PRINT_GLOBAL_EVENTID(Global_Params * global)
{
	switch( global->EventId )
	{
	case	akmsm_EVENT_AuthenticationRequest:
		printf("%s: EventId = akmsm_EVENT_AuthenticationRequest\n", __FUNCTION__);
		break;
	case	akmsm_EVENT_ReAuthenticationRequest:
		printf("%s: EventId = akmsm_EVENT_ReAuthenticationRequest\n", __FUNCTION__);
		break;

	case    akmsm_EVENT_AuthenticationSuccess:
		printf("%s: EventId = akmsm_EVENT_AuthenticationSuccess\n", __FUNCTION__);
		break;

	case	akmsm_EVENT_Disconnect:
		printf("%s: EventId = akmsm_EVENT_Disconnect\n", __FUNCTION__);
		break;
	case	akmsm_EVENT_DeauthenticationRequest:
		printf("%s: EventId = akmsm_EVENT_DeauthenticationRequest\n", __FUNCTION__);
		break;
	case    akmsm_EVENT_Init:
		printf("%s: EventId = akmsm_EVENT_Init\n", __FUNCTION__);
		break;
	case    akmsm_EVENT_Disassociate:
		printf("%s: EventId = akmsm_EVENT_Disassociate\n", __FUNCTION__);
		break;

	case	akmsm_EVENT_IntegrityFailure:
		printf("%s: EventId = akmsm_EVENT_IntegrityFailure\n", __FUNCTION__);
		break;
	case	akmsm_EVENT_EAPOLKeyRecvd:
		printf("%s: EventId = akmsm_EVENT_EAPOLKeyRecvd\n", __FUNCTION__);
		break;

	case    akmsm_EVENT_TimeOut:
		printf("%s: EventId = akmsm_EVENT_TimeOut\n", __FUNCTION__);
		break;

	default:
		printf("%s: Unknown EventId = %d\n", __FUNCTION__, global->EventId);
		break;
	}//switch
}


#ifndef COMPACK_SIZE
inline void PRINT_GLOBAL_AKM_SM_STATE(Global_Params * global)
{
	switch(global->akm_sm->state)
	{
	case akmsm_AUTHENTICATION2:
    		printf("%s: akm_sm->state = akmsm_AUTHENTICATION2\n", __FUNCTION__);
			break;
	case akmsm_PTKSTART:
    		printf("%s: akm_sm->state = akmsm_PTKSTART\n", __FUNCTION__);
			break;
	case akmsm_PTKINITNEGOTIATING:
    		printf("%s: akm_sm->state = akmsm_PTKINITNEGOTIATING\n", __FUNCTION__);
			break;
	default:
    		printf("%s: akm_sm->state = akmsm_Unknown\n", __FUNCTION__);
			break;
        /*
        case akmsm_PTKSTART:
        case akmsm_PTKINITNEGOTIATING:
        case akmsm_PTKINITDONE:
                global->EventId = akmsm_EVENT_EAPOLKeyRecvd;
                retVal = TRUE;
        */
	}
}
#endif

#ifndef COMPACK_SIZE
inline void PRINT_GLOBAL_AKM_SM_GSTATE(Global_Params * global)
{
	switch(global->akm_sm->gstate)
	{
	case gkmsm_REKEYNEGOTIATING:
    		printf("%s: akm_sm->state = gkmsm_REKEYNEGOTIATING\n", __FUNCTION__);
			break;
	default:
    		printf("%s: akm_sm->state = gkmsm_Unknown\n", __FUNCTION__);
			break;
	}
}
#endif


#ifndef COMPACK_SIZE
inline void PRINT_MAC_ADDRESS(u_char *a, u_char *s)
{
	printf("%s: %02x:%02x:%02x:%02x:%02x:%02x\n", s, a[0], a[1], a[2], a[3], a[4], a[5]);
}
#endif



int lib1x_akmsm_SendEAPOL_proc(Global_Params * global)
{
	APKeyManage_SM	*	akm_sm = global->akm_sm;
	AGKeyManage_SM	*   gkm_sm = global->auth->gk_sm;
	OCTET_STRING	IV, RSC, KeyID, MIC, KeyData;
	lib1x_eapol_key *eapol_key;
	u_short tmpKeyData_Length;
#ifdef RTL_WPA2
    struct _WPA2_PMKSA_Node* pmksa_node_eap=NULL;
#endif
	global->EAPOLMsgSend.Octet = global->theAuthenticator->sendBuffer;
	global->EapolKeyMsgSend.Octet = global->EAPOLMsgSend.Octet + ETHER_HDRLEN + LIB1X_EAPOL_HDRLEN ;
	eapol_key = (lib1x_eapol_key  * )global->EapolKeyMsgSend.Octet;

	//lib1x_message(MESS_DBG_KEY_MANAGE, "lib1x_akmsm_SendEAPOL_proc\n");

	IV.Octet = (u_char*)malloc(KEY_IV_LEN);
	IV.Length = KEY_IV_LEN;
	RSC.Octet = (u_char*)malloc(KEY_RSC_LEN);
	RSC.Length = KEY_RSC_LEN;
	KeyID.Octet = (u_char*)malloc(KEY_ID_LEN);
	KeyID.Length = KEY_ID_LEN;
	MIC.Octet = (u_char*)malloc(KEY_MIC_LEN);
	MIC.Length = KEY_MIC_LEN;
	KeyData.Octet = (u_char*)malloc(INFO_ELEMENT_SIZE);
	KeyData.Length = 0;

	switch(akm_sm->state)
	{
		case akmsm_PTKSTART:

			//send 1st message of 4-way handshake
#ifdef FOURWAY_DEBUG
			printf("4-1\n");
#endif
			memset(global->EapolKeyMsgSend.Octet, 0, MAX_EAPOLKEYMSG_LEN);
#ifdef RTL_WPA2
#ifdef FOURWAY_DEBUG
			printf("supp_addr = %02X:%02X:%02X:%02X:%02X:%02X\n",
				global->theAuthenticator->supp_addr[0],
				global->theAuthenticator->supp_addr[1],
				global->theAuthenticator->supp_addr[2],
				global->theAuthenticator->supp_addr[3],
				global->theAuthenticator->supp_addr[4],
				global->theAuthenticator->supp_addr[5]);
			printf("4-1: WPA2Enabled = %s\n", global->RSNVariable.WPA2Enabled?"TRUE":"FALSE");
#endif

#if defined(CONFIG_RTL8186_TR) || defined(CONFIG_RTL865X_SC) || defined(CONFIG_RTL865X_AC) || defined(CONFIG_RTL865X_KLD)
			LOG_MSG_NOTICE("Authenticating......;note:%02x-%02x-%02x-%02x-%02x-%02x;",
				global->theAuthenticator->supp_addr[0],
				global->theAuthenticator->supp_addr[1],
				global->theAuthenticator->supp_addr[2],
				global->theAuthenticator->supp_addr[3],
				global->theAuthenticator->supp_addr[4],
				global->theAuthenticator->supp_addr[5]);
#endif

			if ( global->RSNVariable.WPA2Enabled ) {
#ifdef HS2_SUPPORT				
				if(global->auth->RSNVariable.bOSEN && global->AuthKeyMethod == WFA_AKM_ANONYMOUS_CLI_802_1X_SHA256) 
					global->KeyDescriptorVer = 0; 
				else 
#endif
#ifdef CONFIG_IEEE80211W			
				if (global->AuthKeyMethod == DOT11_AuthKeyType_802_1X_SHA256 )
					global->KeyDescriptorVer = key_desc_ver3; 
				else 
#endif				
				if ( global->RSNVariable.UnicastCipher == DOT11_ENC_CCMP )
					global->KeyDescriptorVer = key_desc_ver2; 
#ifdef HS2_SUPPORT
				if(global->auth->RSNVariable.bOSEN)
					Message_setDescType(global->EapolKeyMsgSend, 2); // for OSEN	
				else	
#endif					
				    Message_setDescType(global->EapolKeyMsgSend, desc_type_WPA2);
			} else {
#ifdef CONFIG_IEEE80211W			
				if (global->AuthKeyMethod == DOT11_AuthKeyType_802_1X_SHA256)
					global->KeyDescriptorVer = key_desc_ver3; 
				else 
#endif				
				if ( global->RSNVariable.UnicastCipher == DOT11_ENC_CCMP )
					global->KeyDescriptorVer = key_desc_ver2;
				Message_setDescType(global->EapolKeyMsgSend, desc_type_RSN);
			}
#else
			Message_setDescType(global->EapolKeyMsgSend, global->DescriptorType);
#endif            
    		Message_setKeyDescVer(global->EapolKeyMsgSend, global->KeyDescriptorVer);
			Message_setKeyType(global->EapolKeyMsgSend, type_Pairwise);
			Message_setKeyIndex(global->EapolKeyMsgSend, 0);
			Message_setInstall(global->EapolKeyMsgSend, 0);
			Message_setKeyAck(global->EapolKeyMsgSend, 1);
			Message_setKeyMIC(global->EapolKeyMsgSend, 0);
			Message_setSecure(global->EapolKeyMsgSend, 0);
			Message_setError(global->EapolKeyMsgSend, 0);
			Message_setRequest(global->EapolKeyMsgSend, 0);
			Message_setReserved(global->EapolKeyMsgSend, 0);

			Message_setKeyLength(global->EapolKeyMsgSend, (global->RSNVariable.UnicastCipher  == DOT11_ENC_TKIP) ? 32:16);
#ifdef RTL_WPA2
			// make 4-1's ReplyCounter increased
			Message_setReplayCounter(global->EapolKeyMsgSend, global->akm_sm->CurrentReplayCounter.field.HighPart, global->akm_sm->CurrentReplayCounter.field.LowPart);
			memcpy(&global->akm_sm->ReplayCounterStarted, &global->akm_sm->CurrentReplayCounter, sizeof(LARGE_INTEGER)); // save started reply counter, david+1-11-2007
			INCLargeInteger(&global->akm_sm->CurrentReplayCounter);
#else
			Message_setReplayCounter(global->EapolKeyMsgSend, global->akm_sm->CurrentReplayCounter.field.HighPart, global->akm_sm->CurrentReplayCounter.field.LowPart);
#endif

			INCOctet32_INTEGER(&global->auth->Counter);
#ifndef RTL_WPA2_PREAUTH
			// ANonce is only updated in lib1x_init_authenticator()
			// or after 4-way handshake
			// To avoid different ANonce values among multiple issued 4-1 messages because of multiple association requests
			// Different ANonce values among multiple 4-1 messages induce 4-2 MIC failure.
			SetNonce(global->akm_sm->ANonce, global->auth->Counter);
#endif
			Message_setKeyNonce(global->EapolKeyMsgSend, global->akm_sm->ANonce);

			memset(IV.Octet, 0, IV.Length);
			Message_setKeyIV(global->EapolKeyMsgSend, IV);
			memset(RSC.Octet, 0, RSC.Length);
			Message_setKeyRSC(global->EapolKeyMsgSend, RSC);
			memset(KeyID.Octet, 0, KeyID.Length);
			Message_setKeyID(global->EapolKeyMsgSend, KeyID);
#ifdef RTL_WPA2
			if(global->RSNVariable.PMKCached){
				pmksa_node_eap = find_pmksa_by_supp(global->theAuthenticator->supp_addr);
				if(pmksa_node_eap) {
					global->RSNVariable.cached_pmk_node = pmksa_node_eap;
                    
					// otherwise PMK cache
					lib1x_message(MESS_DBG_KEY_MANAGE, "4-1, PMKSA %s", (global->RSNVariable.PMKCached)? "Cached, Carry it":"Not Cached");
				} else {
					lib1x_message(MESS_DBG_KEY_MANAGE, "4-1, PMKSA NOT Cached");
				}
			}
		
			if ( global->RSNVariable.WPA2Enabled && (global->AuthKeyMethod == DOT11_AuthKeyType_RSNPSK || pmksa_node_eap) ) {
				static char PMKID_KDE_TYPE[] = { 0xDD, 0x14, 0x00, 0x0F, 0xAC, 0x04 };
				Message_setKeyDataLength(global->EapolKeyMsgSend, 22);
				memcpy(global->EapolKeyMsgSend.Octet + KeyDataPos,
					PMKID_KDE_TYPE, sizeof(PMKID_KDE_TYPE));
				if(pmksa_node_eap && !global->RSNVariable.PMKCached)
					memcpy(global->EapolKeyMsgSend.Octet+KeyDataPos+sizeof(PMKID_KDE_TYPE),
						&pmksa_node_eap->pmksa.pmkid, PMKID_LEN);
				else
					memcpy(global->EapolKeyMsgSend.Octet+KeyDataPos+sizeof(PMKID_KDE_TYPE),
						global->akm_sm->PMKID, PMKID_LEN);
			} else
#endif
			Message_setKeyDataLength(global->EapolKeyMsgSend, 0);

			memset(MIC.Octet, 0, MIC.Length);
			Message_setMIC(global->EapolKeyMsgSend, MIC);

#ifdef RTL_WPA2
			if ( global->RSNVariable.WPA2Enabled ) {
				global->EapolKeyMsgSend.Length = EAPOLMSG_HDRLEN + Message_KeyDataLength(global->EapolKeyMsgSend);
			} else
#endif
			global->EapolKeyMsgSend.Length = EAPOLMSG_HDRLEN ;

			global->EAPOLMsgSend.Length = ETHER_HDRLEN + LIB1X_EAPOL_HDRLEN + global->EapolKeyMsgSend.Length;			
			break;

		case akmsm_PTKINITNEGOTIATING:
			//send 2nd message of 4-way handshake
			//message has been constructed in the lib1x_akmsm_ProcessEAPOL_proc()

			break;
		case akmsm_PTKINITDONE:
			//send 1st message of 2-way handshake
#ifdef FOURWAY_DEBUG
			printf("2-1\n");
#endif
			memset(global->EapolKeyMsgSend.Octet, 0, MAX_EAPOLKEYMSG_LEN);
#ifdef RTL_WPA2
			if ( global->RSNVariable.WPA2Enabled ) {
				Message_setDescType(global->EapolKeyMsgSend, desc_type_WPA2);
			} else
#endif
				Message_setDescType(global->EapolKeyMsgSend, global->DescriptorType);

			Message_setKeyDescVer(global->EapolKeyMsgSend, global->KeyDescriptorVer);
			Message_setKeyType(global->EapolKeyMsgSend, type_Group);
			Message_setKeyIndex(global->EapolKeyMsgSend, 1);
			Message_setInstall(global->EapolKeyMsgSend, 1);
			Message_setKeyAck(global->EapolKeyMsgSend, 1);
			Message_setKeyMIC(global->EapolKeyMsgSend, 1);
			Message_setSecure(global->EapolKeyMsgSend, 1);
			Message_setError(global->EapolKeyMsgSend, 0);
			Message_setRequest(global->EapolKeyMsgSend, 0);
			Message_setReserved(global->EapolKeyMsgSend, 0);

			global->EapolKeyMsgSend.Octet[1] = 0x03;
// kenny
//			global->EapolKeyMsgSend.Octet[2] = 0x91;
			if(global->KeyDescriptorVer == key_desc_ver1 )
				global->EapolKeyMsgSend.Octet[2] = 0x91;
			else
				global->EapolKeyMsgSend.Octet[2] = 0x92;

			Message_setKeyLength(global->EapolKeyMsgSend, (global->RSNVariable.MulticastCipher == DOT11_ENC_TKIP) ? 32:16);

			Message_setReplayCounter(global->EapolKeyMsgSend, global->akm_sm->CurrentReplayCounter.field.HighPart, global->akm_sm->CurrentReplayCounter.field.LowPart);
			INCLargeInteger(&global->akm_sm->CurrentReplayCounter);
			// kenny: n+2
			INCLargeInteger(&global->akm_sm->CurrentReplayCounter);

			SetNonce(global->auth->gk_sm->GNonce, global->auth->Counter);
			Message_setKeyNonce(global->EapolKeyMsgSend, global->auth->gk_sm->GNonce);
			if(global->KeyDescriptorVer == key_desc_ver1 )
				memset(IV.Octet, 0, IV.Length);
			else {
				memset(IV.Octet, 0, IV.Length);
				//memset(IV.Octet, 0xA6, IV.Length);
				//INCOctet32_INTEGER(&global->auth->Counter);
				//SetEAPOL_KEYIV(IV, global->auth->Counter);

			}

			Message_setKeyIV(global->EapolKeyMsgSend, IV);
			lib1x_control_QueryRSC(global, &RSC);
			Message_setKeyRSC(global->EapolKeyMsgSend, RSC);

			memset(KeyID.Octet, 0, KeyID.Length);
			Message_setKeyID(global->EapolKeyMsgSend, KeyID);

#ifdef RTL_WPA2
			if ( global->RSNVariable.WPA2Enabled ) {
				char key_data[128];
				char * key_data_pos = key_data;
				static char GTK_KDE_TYPE[] = { 0xDD, 0x16, 0x00, 0x0F, 0xAC, 0x01, 0x01, 0x00 };
				memcpy(key_data_pos, GTK_KDE_TYPE, sizeof(GTK_KDE_TYPE));
//fix the bug of using default KDE length -----------
				key_data_pos[1] = (unsigned char) 6 + ((global->RSNVariable.MulticastCipher == DOT11_ENC_TKIP) ? 32:16);
//------------------------------ david+2006-04-04
				
				key_data_pos += sizeof(GTK_KDE_TYPE);

				global->EapolKeyMsgSend.Octet[1] = 0x13;

				if(global->KeyDescriptorVer == key_desc_ver1)
				{
// david+2006-01-06, fix the bug of using 0 as group key id					
//					global->EapolKeyMsgSend.Octet[2] = 0x81;
					Message_setKeyDescVer(global->EapolKeyMsgSend, key_desc_ver1);					
					Message_setKeyDataLength(global->EapolKeyMsgSend,
						sizeof(GTK_KDE_TYPE) + (((global->RSNVariable.MulticastCipher == DOT11_ENC_TKIP) ? 32:16)));
				}else if(global->KeyDescriptorVer == key_desc_ver2)
				{
// david+2006-01-06, fix the bug of using 0 as group key id					
//					global->EapolKeyMsgSend.Octet[2] = 0x82;
					Message_setKeyDescVer(global->EapolKeyMsgSend, key_desc_ver2);
					Message_setKeyDataLength(global->EapolKeyMsgSend,
					    	sizeof(GTK_KDE_TYPE) + ((8 + ((global->RSNVariable.MulticastCipher == DOT11_ENC_TKIP) ? 32:16)) ));
				} 
#ifdef CONFIG_IEEE80211W				
				else if(global->KeyDescriptorVer == key_desc_ver3)
				{

					Message_setKeyDescVer(global->EapolKeyMsgSend, key_desc_ver3);
					Message_setKeyDataLength(global->EapolKeyMsgSend, sizeof(GTK_KDE_TYPE) + (8 + 16) );
				}		
#endif						
				memcpy(key_data_pos, gkm_sm->GTK[gkm_sm->GN], (global->RSNVariable.MulticastCipher == DOT11_ENC_TKIP) ? 32:16);


				EncGTK(global, global->akm_sm->PTK + PTK_LEN_EAPOLMIC, PTK_LEN_EAPOLENC,
					key_data,
					sizeof(GTK_KDE_TYPE) + ((global->RSNVariable.MulticastCipher == DOT11_ENC_TKIP) ? 32:16),
					 KeyData.Octet, &tmpKeyData_Length);
			} else {
#endif

			if(global->KeyDescriptorVer == key_desc_ver1)
			{
				Message_setKeyDataLength(global->EapolKeyMsgSend,
					((global->RSNVariable.MulticastCipher == DOT11_ENC_TKIP) ? 32:16));
			}else if(global->KeyDescriptorVer == key_desc_ver2)
			{
				Message_setKeyDataLength(global->EapolKeyMsgSend,
				    	(8 + ((global->RSNVariable.MulticastCipher == DOT11_ENC_TKIP) ? 32:16) ));
			}
#ifdef CONFIG_IEEE80211W			
			else if(global->KeyDescriptorVer == key_desc_ver3)
			{
				Message_setKeyDataLength(global->EapolKeyMsgSend, (8 + 16));
			}
#endif
			EncGTK(global, global->akm_sm->PTK + PTK_LEN_EAPOLMIC, PTK_LEN_EAPOLENC,
				gkm_sm->GTK[gkm_sm->GN],
				(global->RSNVariable.MulticastCipher == DOT11_ENC_TKIP) ? 32:16,
				 KeyData.Octet, &tmpKeyData_Length);
#ifdef RTL_WPA2
			}
#endif
			KeyData.Length = (int)tmpKeyData_Length;
			Message_setKeyData(global->EapolKeyMsgSend, KeyData);

/* Kenny
			global->EapolKeyMsgSend.Length = EAPOLMSG_HDRLEN +
					((global->RSNVariable.MulticastCipher == DOT11_ENC_TKIP) ? 32:16);
*/
			global->EapolKeyMsgSend.Length = EAPOLMSG_HDRLEN +
					KeyData.Length;

			global->EAPOLMsgSend.Length = ETHER_HDRLEN + LIB1X_EAPOL_HDRLEN +
					global->EapolKeyMsgSend.Length;


			global->akm_sm->IfCalcMIC = TRUE;
			//sc_yang
			global->akm_sm->TickCnt = SECONDS_TO_TIMERCOUNT(1);
			//sc_yang to count the tick interrupt by timer
			 //LIB_USLEEP(500000);
			//usleep(500000); // for debug

			break;
		default:
			break;

	}//switch

	//lib1x_hexdump2(MESS_DBG_AUTH, "1x_daemon", global->EAPOLMsgSend.Octet, global->EAPOLMsgSend.Length, "Send");
	//KeyDump("lib1x_akmsm_SendEAPOL_proc", global->EAPOLMsgSend.Octet,global->EAPOLMsgSend.Length, "Send EAPOL-KEY");
	//Avaya If the packet is sent first, the TimeoutCtr should be clear, otherwise(if resent), it will not be clear
	akm_sm->TimeoutCtr = 0;
	global->akm_sm->TickCnt = SECONDS_TO_TIMERCOUNT(1);
	global->theAuthenticator->sendhandshakeready = TRUE;

	free(IV.Octet);
	free(RSC.Octet);
	free(KeyID.Octet);
	free(MIC.Octet);
	free(KeyData.Octet);
	return TRUE;
}

#ifdef CONFIG_IEEE80211R
#define _MOBILITY_DOMAIN_IE_		54
#define _FAST_BSS_TRANSITION_IE_	55
#define _TIMEOUT_INTERVAL_IE_		56
#define _RIC_DATA_IE_				57
#define _RIC_DESCRIPTOR_IE_			75
#define _FT_R1KH_ID_SUB_IE_			1
#define _FT_GTK_SUB_IE_				2
#define _FT_R0KH_ID_SUB_IE_			3
#define TIE_TYPE_REASSOC_DEADLINE	1
#define TIE_TYPE_KEY_LIFETIME		2
#define _FAST_BSS_TRANSITION_CATEGORY_ID_	6
#define _FT_REQUEST_ACTION_ID_		1
#define _FT_RESPONSE_ACTION_ID_		2
#define _FT_CONFIRM_ACTION_ID_		3
#define _FT_ACK_ACTION_ID_			4

#define _RSN_IE_2_				48

enum { PSK_WPA=1, PSK_WPA2=2};

#define BIT(x)	(1 << (x))

#define GetFTMDID(pbuf)		((unsigned char *)pbuf + 2)
#define GetFTOverDS(pbuf)	(((*(unsigned char *)((unsigned long)pbuf + 4)) & BIT(0)) != 0)
#define GetFTResReq(pbuf)	(((*(unsigned char *)((unsigned long)pbuf + 4)) & BIT(1)) != 0)
#define SetFTMICCtrl(pbuf, v)	(*(unsigned char *)((unsigned long)pbuf + 1)) = v	


unsigned char *get_ie(unsigned char *pbuf, int index, int *len, int limit)
{
	unsigned int tmp,i;
	unsigned char *p;
 
	if (limit < 1)
		return NULL;
 
	p = pbuf;
	i = 0;
	*len = 0;
	while(1)
	{
		if (*p == index)
		{
			*len = *(p + 1);
			return (p);
		}
		else
		{
			tmp = *(p + 1);
			p += (tmp + 2);
			i += (tmp + 2);
		}
		if (i >= limit)
			break;
	}
	return NULL;
}

 unsigned char *set_ie(unsigned char *pbuf, int index, unsigned int len, unsigned char *source,
				unsigned int *frlen)
{
	*pbuf = index;
	*(pbuf + 1) = len;
	if (len > 0)
		memcpy((void *)(pbuf + 2), (void *)source, len);
	*frlen = *frlen + (len + 2);
	return (pbuf + len + 2);
}

unsigned char *construct_mobility_domain_ie(Global_Params * global, unsigned char *pbuf, unsigned int *frlen)
{
	unsigned char temp[3];

	memset(temp, 0, sizeof(temp));
	memcpy(temp, global->akm_sm->mdid, 2);
	if (global->akm_sm->over_ds_enabled)
		temp[2] |= BIT(0);
	if (global->akm_sm->resource_request_support)
		temp[2] |= BIT(1);

	pbuf = set_ie(pbuf, _MOBILITY_DOMAIN_IE_, 3, temp, frlen);
	return pbuf;
}

unsigned char *construct_fast_bss_transition_ie(Global_Params * global, unsigned char *pbuf, unsigned int *frlen) 
{
	unsigned char temp[512];
	unsigned char gkout[128], *pos;
	unsigned short gkout_len;
	
	memset(temp, 0, sizeof(temp));
	pos = temp;

	pos += 18;

	// ANonce, SNonce
		pos += (2 * KEY_NONCE_LEN);

	// R1KH-ID
	*pos++ = _FT_R1KH_ID_SUB_IE_;
	*pos++ = MacAddrLen;
	memcpy(pos, global->akm_sm->bssid, MacAddrLen);
	pos += MacAddrLen;


	// R0KH-ID
		*pos++ = _FT_R0KH_ID_SUB_IE_;
		*pos++ = global->akm_sm->r0kh_id_len;
		memcpy(pos, global->akm_sm->r0kh_id, global->akm_sm->r0kh_id_len);
		pos += global->akm_sm->r0kh_id_len;

	pbuf = set_ie(pbuf, _FAST_BSS_TRANSITION_IE_, pos - temp, temp, frlen);
	return pbuf;
}

unsigned char *construct_timeout_interval_ie(unsigned char *pbuf, unsigned int *frlen, int type, int value)
{
	unsigned char temp[5];

	if (type < TIE_TYPE_REASSOC_DEADLINE || type > TIE_TYPE_KEY_LIFETIME)
		return pbuf;

	temp[0] = type;
	temp[1] = value & 0xff;
	temp[2] = (value & 0xff00) >> 8;
	temp[3] = (value & 0xff0000) >> 16;
	temp[4] = (value & 0xff000000) >> 24;

	pbuf = set_ie(pbuf, _TIMEOUT_INTERVAL_IE_, 5, temp, frlen);
	return pbuf;
}

static int validateMDIE(Global_Params * global, unsigned char *pbuf)
{
	if ( (memcmp(GetFTMDID(pbuf), global->akm_sm->mdid, 2) == 0) &&
			(GetFTOverDS(pbuf) == global->akm_sm->over_ds_enabled) &&
			(GetFTResReq(pbuf) == global->akm_sm->resource_request_support) )
		return 1;
	else
		return 0;
}

static unsigned char *getPMKID(unsigned int index, unsigned char *rsnie, unsigned int rsnie_len)
{
	unsigned char *pos;
	unsigned int pmk_cnt;
	unsigned short count;

	pos = rsnie + 8; 
	lib1x_Little_N2S(pos, count);
	pos += 2 + 4 * count;
	lib1x_Little_N2S(pos, count);
	pos += 2 + 4 * count;
	pos += 2;
	lib1x_Little_N2S(pos, count);
	pmk_cnt = count;
	pos += 2;
	if (index < pmk_cnt && (pos + index * 16) < (rsnie + rsnie_len))
		return (pos + index * 16);
	return NULL;
}

static int isFTAuth(Global_Params * global, unsigned char *rsnie, unsigned int rsnie_len, int psk)
{
	unsigned int akm_cnt, i;
	unsigned char akm_ft[4] = {0x00, 0x0f, 0xac, 0x03};
	unsigned char akm_ft_psk[4] = {0x00, 0x0f, 0xac, 0x04};
	unsigned char *pos = rsnie;
	unsigned short count;

	pos += 8;
	lib1x_Little_N2S(pos, count);
	pos += 2 + 4 * count;
	lib1x_Little_N2S(pos, count);
	akm_cnt = count;
	pos += 2;

	for (i = 0; i< akm_cnt; i++) {
		if ( (!psk && !memcmp(pos + (i * 4), akm_ft, 4)) ||
			 ((psk & PSK_WPA2) && !memcmp(pos + (i * 4), akm_ft_psk, 4)) )
			return 1;
	}

	return 0;
}


int ft_check_imd_4way(Global_Params * global, unsigned char *pbuf, unsigned int limit, unsigned int *status)
{
	unsigned char *p;
	unsigned int len;

	printf("==> %s\n", __FUNCTION__);

	// Check MDIE
	p = get_ie(pbuf, _MOBILITY_DOMAIN_IE_, &len, limit);
	if (!p || !validateMDIE(global, p)) {
		*status = _STATS_INVALID_MDIE_;
		return -1;
	}

	// Check RSNIE
	p = get_ie(pbuf, _RSN_IE_2_, &len, limit);
	if (p == NULL) {
		*status = __STATS_INVALID_IE_;
		return -1;
	}

	// Check AKM
	if (!isFTAuth(global, p, len + 2, FALSE)) {
		*status = __STATS_INVALID_AKMP_;
		return -1;
	}

	// Check PMK-R1-Name
	if (memcmp(global->akm_sm->pmk_r1_name, getPMKID(0, p, len + 2), PMKID_LEN)) {
		*status = _STATS_INVALID_PMKID_;
		return -1;
	}

	return 0;

}

#endif

int lib1x_akmsm_ProcessEAPOL_proc(Global_Params * global)
/*++
Routine Description:

    Check if the received message is valid. If valid, construct next message
Return Value:
	0	: Suucess. Next sent message is constructed
	not 0 : Fail. Refer to ERROR Message in 1x_kmsm.h

--*/
{
	APKeyManage_SM	*	akm_sm = global->akm_sm;
	int	retVal = 0;
	OCTET_STRING	 IV, RSC, KeyID, MIC;
	lib1x_eapol_key * eapol_key_recvd, * eapol_key_send;
#ifdef RTL_WPA2
	LARGE_INTEGER recievedRC;
	u_short tmpKeyData_Length;
	AGKeyManage_SM	*   	gkm_sm = global->auth->gk_sm;
	OCTET_STRING	 KeyData;
#ifdef CONFIG_IEEE80211R
	OCTET_STRING tmpKeyData;
	unsigned int status = 0;
#endif

	KeyData.Octet = (u_char*)malloc(INFO_ELEMENT_SIZE);
	KeyData.Length = 0;
#endif


	global->EapolKeyMsgRecvd.Octet = global->EAPOLMsgRecvd.Octet + (ETHER_HDRLEN + LIB1X_EAPOL_HDRLEN);
	global->EapolKeyMsgRecvd.Length = global->EAPOLMsgRecvd.Length - (ETHER_HDRLEN + LIB1X_EAPOL_HDRLEN);

	global->EapolKeyMsgSend.Octet = global->EAPOLMsgSend.Octet + (ETHER_HDRLEN + LIB1X_EAPOL_HDRLEN);
	global->EapolKeyMsgSend.Length = global->EAPOLMsgSend.Length - (ETHER_HDRLEN + LIB1X_EAPOL_HDRLEN);

	eapol_key_recvd = (lib1x_eapol_key * )global->EapolKeyMsgRecvd.Octet;
	eapol_key_send = (lib1x_eapol_key * )global->EapolKeyMsgSend.Octet;

	IV.Octet = (u_char*)malloc(KEY_IV_LEN);
	IV.Length = KEY_IV_LEN;
	RSC.Octet = (u_char*)malloc(KEY_RSC_LEN);
	RSC.Length = KEY_RSC_LEN;
	KeyID.Octet = (u_char*)malloc(KEY_ID_LEN);
	KeyID.Length = KEY_ID_LEN;
	MIC.Octet = (u_char*)malloc(KEY_MIC_LEN);
	MIC.Length = KEY_MIC_LEN;




	if(Message_KeyType(global->EapolKeyMsgRecvd) == type_Pairwise)
	{
		switch(akm_sm->state)
		{
			case akmsm_PTKSTART:
			//receive 2nd message and send third
#ifdef FOURWAY_DEBUG
				printf("4-2\n");
#endif
			//check replay counter
#ifdef RTL_WPA2
				Message_ReplayCounter_OC2LI(global->EapolKeyMsgRecvd, &recievedRC);
				INCLargeInteger(&recievedRC);
				if ( !(global->akm_sm->CurrentReplayCounter.field.HighPart == recievedRC.field.HighPart
			             && global->akm_sm->CurrentReplayCounter.field.LowPart == recievedRC.field.LowPart))
#else
				if(!Message_EqualReplayCounter(global->akm_sm->CurrentReplayCounter, global->EapolKeyMsgRecvd))
#endif
				{
#ifdef FOURWAY_DEBUG
					printf("4-2: ERROR_NONEEQUL_REPLAYCOUNTER\n");
#endif
//					syslog(LOG_AUTH|LOG_INFO, "%s: Authentication failled! (4-2: ERROR_NONEEQUL_REPLAYCOUNTER)\n", dev_supp); // david+2006-03-31, add event to syslog
					
					retVal = ERROR_NONEEQUL_REPLAYCOUNTER;
				}else
				{
#ifndef RTL_WPA2
					// kenny: already increase CurrentReplayCounter after 4-1. Do it at the end of 4-2
					INCLargeInteger(&global->akm_sm->CurrentReplayCounter);
#endif
					global->akm_sm->SNonce = Message_KeyNonce(global->EapolKeyMsgRecvd);

                    int ISSHA256 = 0;

                    #ifdef CONFIG_IEEE80211W
                    ISSHA256 = (global->AuthKeyMethod == DOT11_AuthKeyType_802_1X_SHA256
                      #ifdef HS2_SUPPORT                        
					  || global->auth->RSNVariable.bOSEN
                      #endif					  
					  );
                    #endif

					CalcPTK(global->EAPOLMsgRecvd.Octet, global->EAPOLMsgRecvd.Octet + 6,
					global->akm_sm->ANonce.Octet, global->akm_sm->SNonce.Octet,
					global->akm_sm->PMK, PMK_LEN, global->akm_sm->PTK, (ISSHA256?48:PTK_LEN_TKIP)
                    #ifdef CONFIG_IEEE80211W
					, ISSHA256
                    #endif				
                     );

#ifdef DBG_WPA_CLIENT
					{
						memcpy(RTLClient.global->supp_kmsm->PTK, global->akm_sm->PTK, PTK_LEN_TKIP);
						memcpy(RTLClient.global->supp_kmsm->SNonce.Octet, global->akm_sm->SNonce.Octet, KEY_NONCE_LEN);
					}
#endif

					if(!CheckMIC(global->EAPOLMsgRecvd, global->akm_sm->PTK, PTK_LEN_EAPOLMIC))
					{
						global->akm_sm->Disconnect = TRUE;
						global->akm_sm->ErrorRsn = RSN_MIC_failure;
#ifdef RTL_WPA2
						printf("4-2: ERROR_MIC_FAIL\n");

						syslog(LOG_AUTH|LOG_INFO, "%s: Authentication failled! (4-2: MIC error)\n", dev_supp); // david+2006-03-31, add event to syslog

#if defined(CONFIG_RTL8186_TR) || defined(CONFIG_RTL865X_SC) || defined(CONFIG_RTL865X_AC) || defined(CONFIG_RTL865X_KLD)
						LOG_MSG_NOTICE("Authentication failed;note:%02x-%02x-%02x-%02x-%02x-%02x;",
						global->theAuthenticator->supp_addr[0],
						global->theAuthenticator->supp_addr[1],
						global->theAuthenticator->supp_addr[2],
						global->theAuthenticator->supp_addr[3],
						global->theAuthenticator->supp_addr[4],
						global->theAuthenticator->supp_addr[5]);
#endif			

						wpa2_hexdump("PTK:", global->akm_sm->PTK, PTK_LEN);
						wpa2_hexdump("Message 2:", global->EAPOLMsgRecvd.Octet + 14, global->EAPOLMsgRecvd.Length);

						if (global->RSNVariable.PMKCached ) {
							printf("\n%s:%d del_pmksa due to 4-2 ERROR_MIC_FAIL\n", __FUNCTION__, __LINE__);
							del_pmksa_by_spa(global->theAuthenticator->supp_addr);
							if(is_pmksa_empty())
								global->RSNVariable.PMKCached = FALSE;
						}
#endif
						retVal = ERROR_MIC_FAIL;
					}
                    else
					{
						//lib1x_control_AssocInfo(global, 0, &global->akm_sm->SuppInfoElement);
						//if(!Message_EqualRSNIE(	Message_KeyData(global->EapolKeyMsgRecvd, Message_ReturnKeyDataLength(global->EapolKeyMsgRecvd)),
						//		global->akm_sm->SuppInfoElement, global->akm_sm->SuppInfoElement.Length))
						if(0)
						{
							global->akm_sm->Disconnect = TRUE;
							global->akm_sm->ErrorRsn = RSN_diff_info_element;
							retVal = ERROR_NONEQUAL_RSNIE;
							printf("4-2: ERROR_NONEQUAL_RSNIE\n");
						}else
						{
							//Construct Message3
#ifdef FOURWAY_DEBUG
							printf("4-3\n");
#endif
							memset(global->EapolKeyMsgSend.Octet, 0, MAX_EAPOLKEYMSG_LEN);
#ifdef RTL_WPA2
							if ( global->RSNVariable.WPA2Enabled ) {
								
#ifdef HS2_SUPPORT
								if(global->auth->RSNVariable.bOSEN)
									Message_setDescType(global->EapolKeyMsgSend, 2); // for OSEN	
								else	
#endif					
								    Message_setDescType(global->EapolKeyMsgSend, desc_type_WPA2);
							} else
								Message_setDescType(global->EapolKeyMsgSend, desc_type_RSN);
#else
							Message_setDescType(global->EapolKeyMsgSend, global->DescriptorType);
#endif
							Message_setKeyDescVer(global->EapolKeyMsgSend, Message_KeyDescVer(global->EapolKeyMsgRecvd));
							Message_setKeyType(global->EapolKeyMsgSend, Message_KeyType(global->EapolKeyMsgRecvd));
							Message_setKeyIndex(global->EapolKeyMsgSend, Message_KeyIndex(global->EapolKeyMsgRecvd));


							//lib1x_message(MESS_DBG_KEY_MANAGE, "lib1x_akmsm_ProcessEAPOL_proc, will install bit set = %d\n", global->RSNVariable.isSuppSupportUnicastCipher ? 1:0);
							//Message_setInstall(global->EapolKeyMsgSend, global->RSNVariable.isSuppSupportUnicastCipher ? 1:0);
							Message_setInstall(global->EapolKeyMsgSend, 1);
							Message_setKeyAck(global->EapolKeyMsgSend, 1);
							Message_setKeyMIC(global->EapolKeyMsgSend, 1);
							Message_setSecure(global->EapolKeyMsgSend, global->RSNVariable.isSuppSupportMulticastCipher ? 0:1);
							Message_setError(global->EapolKeyMsgSend, 0);
							Message_setRequest(global->EapolKeyMsgSend, 0);
							Message_setReserved(global->EapolKeyMsgSend, 0);

							Message_setKeyLength(global->EapolKeyMsgSend, (global->RSNVariable.UnicastCipher  == DOT11_ENC_TKIP) ? 32:16);
							Message_setReplayCounter(global->EapolKeyMsgSend, global->akm_sm->CurrentReplayCounter.field.HighPart, global->akm_sm->CurrentReplayCounter.field.LowPart);
							Message_setKeyNonce(global->EapolKeyMsgSend, global->akm_sm->ANonce);
							memset(IV.Octet, 0, IV.Length);
							Message_setKeyIV(global->EapolKeyMsgSend, IV);


#ifdef RTL_WPA2
							if ( global->RSNVariable.WPA2Enabled ) {
#ifdef CONFIG_IEEE80211R
								unsigned char key_data[384];
#else
								unsigned char key_data[128];
#endif
								unsigned char * key_data_pos = key_data;
								int i;
								unsigned char GTK_KDE_TYPE[] = {0xDD, 0x16, 0x00, 0x0F, 0xAC, 0x01, 0x01, 0x00 };
#ifdef CONFIG_IEEE80211W
								unsigned char IGTK_KDE_TYPE[] = {0xDD, 0x1C, 0x00, 0x0F, 0xAC, 0x09};
#endif
#ifdef CONFIG_IEEE80211R
								unsigned int frlen = 0;
#endif

								global->EapolKeyMsgSend.Octet[1] = 0x13;

								if(global->KeyDescriptorVer == key_desc_ver2 
#if defined(CONFIG_IEEE80211W) || defined(CONFIG_IEEE80211R)								
									|| global->KeyDescriptorVer == key_desc_ver3
#endif									
								) { 
									INCOctet32_INTEGER(&global->auth->Counter);
									SetEAPOL_KEYIV(IV, global->auth->Counter);
									//memset(IV.Octet, 0x0, IV.Length);
									Message_setKeyIV(global->EapolKeyMsgSend, IV);
								}

								// RSN IE
								//HS2DEBUG("RSN IE[0]=[%02X]\n", global->auth->RSNVariable.AuthInfoElement.Octet[0]);
#ifdef HS2_SUPPORT
								if (global->auth->RSNVariable.bOSEN && global->auth->RSNVariable.AuthInfoElement.Octet[0] == 0xdd) {						
									
									int len = (unsigned char)global->auth->RSNVariable.AuthInfoElement.Octet[1] + 2;
									printf("4.3 EAPOL-KEY, copy OSEN IE to key data, len=%d\n",len);
									memcpy(key_data_pos, global->auth->RSNVariable.AuthInfoElement.Octet, len);
									key_data_pos += len;
								}
								else
#endif
								if (global->auth->RSNVariable.AuthInfoElement.Octet[0] == WPA2_ELEMENT_ID) {
									int len = (unsigned char)global->auth->RSNVariable.AuthInfoElement.Octet[1] + 2;
									memcpy(key_data_pos, global->auth->RSNVariable.AuthInfoElement.Octet, len);
									key_data_pos += len;
								} else {
									//find WPA2_ELEMENT_ID 0x30
									int len = (unsigned char)global->auth->RSNVariable.AuthInfoElement.Octet[1] + 2;
									//printf("%s: global->auth->RSNVariable.AuthInfoElement.Octet[%d] = %02X\n", __FUNCTION__, len, global->auth->RSNVariable.AuthInfoElement.Octet[len]);
									if (global->auth->RSNVariable.AuthInfoElement.Octet[len] == WPA2_ELEMENT_ID) {
										int len2 = (unsigned char)global->auth->RSNVariable.AuthInfoElement.Octet[len+1] + 2;
										memcpy(key_data_pos, global->auth->RSNVariable.AuthInfoElement.Octet+len, len2);
										key_data_pos += len2;
									} else {
										printf("kenny: %s-%d ERROR!\n", __FUNCTION__, __LINE__);
									}
								}

#ifdef CONFIG_IEEE80211R
								if (akm_sm->isFT) {
#ifdef CONFIG_IEEE80211W
									if (global->auth->RSNVariable.ieee80211w != NO_MGMT_FRAME_PROTECTION) {
										memcpy(key_data_pos - 4, key_data_pos - 4 + PMKID_LEN, 4);
										lib1x_Little_S2N(1, key_data_pos - 6);
										memcpy(key_data_pos - 4, akm_sm->pmk_r1_name, PMKID_LEN);
										key_data_pos += PMKID_LEN;
										key_data[1] += PMKID_LEN;
									} else
#endif
									{
										lib1x_Little_S2N(1, key_data_pos);
									memcpy(key_data_pos, akm_sm->pmk_r1_name, PMKID_LEN);
										key_data_pos += PMKID_LEN;
										key_data[1] += (2 + PMKID_LEN);
									}
								}
#endif

#ifdef CONFIG_IEEE80211R
								if (akm_sm->isFT) {
									key_data_pos = construct_mobility_domain_ie(global, key_data_pos , &frlen);
								}
#endif

								memcpy(key_data_pos, GTK_KDE_TYPE, sizeof(GTK_KDE_TYPE));
								key_data_pos[1] = (unsigned char) 6 + ((global->RSNVariable.MulticastCipher == DOT11_ENC_TKIP) ? 32:16);
								key_data_pos += sizeof(GTK_KDE_TYPE);


								// FIX GROUPKEY ALL ZERO
								global->auth->gk_sm->GInitAKeys = TRUE;
								lib1x_akmsm_UpdateGK_proc(global->auth);
								memcpy(key_data_pos, gkm_sm->GTK[gkm_sm->GN], (global->RSNVariable.MulticastCipher == DOT11_ENC_TKIP) ? 32:16);

								key_data_pos += (global->RSNVariable.MulticastCipher == DOT11_ENC_TKIP) ? 32:16;

								//=================================================
								// IGTK KDE
#ifdef CONFIG_IEEE80211W
								if(global->mgmt_frame_prot) {
									memcpy(key_data_pos, IGTK_KDE_TYPE, sizeof(IGTK_KDE_TYPE));
									key_data_pos += sizeof(IGTK_KDE_TYPE);
									// Key ID
									*(key_data_pos) = (unsigned char)gkm_sm->GN_igtk;
									*(key_data_pos+1) = 0;
									key_data_pos += 2;
									// IPN
									lib1x_control_GetIGTK_PN(global->auth);
									*(key_data_pos++) = gkm_sm->IGTK_PN._byte_.TSC0;
									*(key_data_pos++) = gkm_sm->IGTK_PN._byte_.TSC1;
									*(key_data_pos++) = gkm_sm->IGTK_PN._byte_.TSC2;
									*(key_data_pos++) = gkm_sm->IGTK_PN._byte_.TSC3;
									*(key_data_pos++) = gkm_sm->IGTK_PN._byte_.TSC4;
									*(key_data_pos++) = gkm_sm->IGTK_PN._byte_.TSC5;									
									memcpy(key_data_pos, gkm_sm->IGTK[gkm_sm->GN_igtk-4], 16);
									#if 0
									printf("%s(%d)\n", __FUNCTION__, __LINE__);
									printf("IGTK=");
									for(i=0;i<16;i++)
										printf("%x",gkm_sm->IGTK[gkm_sm->GN_igtk-4][i]);
									printf("\n");
									#endif
									
									key_data_pos += 16;
								}
#endif
#ifdef CONFIG_IEEE80211R
								if (akm_sm->isFT) {
									key_data_pos = construct_fast_bss_transition_ie(global, key_data_pos, &frlen);
									key_data_pos = construct_timeout_interval_ie(key_data_pos, &frlen,
											TIE_TYPE_REASSOC_DEADLINE, 0);
									key_data_pos = construct_timeout_interval_ie(key_data_pos, &frlen,
											TIE_TYPE_KEY_LIFETIME, 0);
								}
#endif

								// Padding
								i = (key_data_pos - key_data) % 8;
								if ( i != 0 ) {
									*key_data_pos = 0xdd;
									key_data_pos++;
									for (i=i+1; i<8; i++) {
										*key_data_pos = 0x0;
										key_data_pos++;
									}

								}

								EncGTK(global, global->akm_sm->PTK + PTK_LEN_EAPOLMIC, PTK_LEN_EAPOLENC,
									key_data,
									(key_data_pos - key_data),
									 KeyData.Octet, &tmpKeyData_Length);

								KeyData.Length = (int)tmpKeyData_Length;
								Message_setKeyData(global->EapolKeyMsgSend, KeyData);
								Message_setKeyDataLength(global->EapolKeyMsgSend, KeyData.Length);

								global->EapolKeyMsgSend.Length = EAPOLMSG_HDRLEN +
										KeyData.Length;
								lib1x_control_QueryRSC(global, &RSC);
								Message_setKeyRSC(global->EapolKeyMsgSend, RSC);


							} else {
								memset(RSC.Octet, 0, RSC.Length);
								Message_setKeyRSC(global->EapolKeyMsgSend, RSC);
								memset(KeyID.Octet, 0, KeyID.Length);
								Message_setKeyID(global->EapolKeyMsgSend, KeyID);
								//lib1x_hexdump2(MESS_DBG_KEY_MANAGE, "lib1x_akmsm_ProcessEAPOL_proc", global->auth->RSNVariable.AuthInfoElement.Octet, global->auth->RSNVariable.AuthInfoElement.Length,"Append Authenticator Information Element");

								{ //WPA 0xDD
									//printf("%s: global->auth->RSNVariable.AuthInfoElement.Octet[0] = %02X\n", __FUNCTION__, global->auth->RSNVariable.AuthInfoElement.Octet[0]);

									int len = (unsigned char)global->auth->RSNVariable.AuthInfoElement.Octet[1] + 2;

									if (global->auth->RSNVariable.AuthInfoElement.Octet[0] == RSN_ELEMENT_ID) {
										memcpy(KeyData.Octet, global->auth->RSNVariable.AuthInfoElement.Octet, len);
										KeyData.Length = len;
									} else {
										// impossible case??
										int len2 = (unsigned char)global->auth->RSNVariable.AuthInfoElement.Octet[len+1] + 2;
										memcpy(KeyData.Octet, global->auth->RSNVariable.AuthInfoElement.Octet+len, len2);
										KeyData.Length = len2;
									}
								}
								Message_setKeyDataLength(global->EapolKeyMsgSend, KeyData.Length);
								Message_setKeyData(global->EapolKeyMsgSend, KeyData);
								global->EapolKeyMsgSend.Length = EAPOLMSG_HDRLEN + KeyData.Length;
							}

							INCLargeInteger(&global->akm_sm->CurrentReplayCounter);

#else
							memset(RSC.Octet, 0, RSC.Length);
							Message_setKeyRSC(global->EapolKeyMsgSend, RSC);
							memset(KeyID.Octet, 0, KeyID.Length);
							Message_setKeyID(global->EapolKeyMsgSend, KeyID);
							//lib1x_hexdump2(MESS_DBG_KEY_MANAGE, "lib1x_akmsm_ProcessEAPOL_proc", global->auth->RSNVariable.AuthInfoElement.Octet, global->auth->RSNVariable.AuthInfoElement.Length,"Append Authenticator Information Element");
							Message_setKeyDataLength(global->EapolKeyMsgSend, global->auth->RSNVariable.AuthInfoElement.Length);
							Message_setKeyData(global->EapolKeyMsgSend, global->auth->RSNVariable.AuthInfoElement);
							//Message_setKeyDataLength(global->EapolKeyMsgSend, global->akm_sm->AuthInfoElement.Length);
							//Message_setKeyData(global->EapolKeyMsgSend, global->akm_sm->AuthInfoElement);
							global->EapolKeyMsgSend.Length = EAPOLMSG_HDRLEN + global->auth->RSNVariable.AuthInfoElement.Length;
#endif /* RTL_WPA2 */
							global->EAPOLMsgSend.Length = ETHER_HDRLEN + LIB1X_EAPOL_HDRLEN + global->EapolKeyMsgSend.Length;

							global->akm_sm->IfCalcMIC = TRUE;
						}//Message_EqualRSNIE
					}//CheckMIC
				}//Message_EqualReplayCounter
				break;

			case akmsm_PTKINITNEGOTIATING:
			// test 2nd or 4th message

#if 1
// check replay counter to determine if msg 2 or 4 received, david+1-11-2007
//				if ( Message_KeyDataLength(global->EapolKeyMsgRecvd) != 0)
				if(Message_EqualReplayCounter(global->akm_sm->ReplayCounterStarted, global->EapolKeyMsgRecvd))
				{
#ifndef SOLVE_DUP_4_2						
#ifdef FOURWAY_DEBUG
					printf("4-2 in akmsm_PTKINITNEGOTIATING: ERROR_NONEEQUL_REPLAYCOUNTER\n");
#endif
					retVal = ERROR_NONEEQUL_REPLAYCOUNTER;
#else /* SOLVE_DUP_4 */
#ifdef FOURWAY_DEBUG
					printf("4-2 in akmsm_PTKINITNEGOTIATING: resend 4-3\n");
#endif

// copy 4-2 processing from above
				retVal = ERROR_RECV_4WAY_MESSAGE2_AGAIN;
#if 0 // Don't check replay counter during dup 4-2							
#ifdef RTL_WPA2
				Message_ReplayCounter_OC2LI(global->EapolKeyMsgRecvd, &recievedRC);
				INCLargeInteger(&recievedRC);
				if ( !(global->akm_sm->CurrentReplayCounter.field.HighPart == recievedRC.field.HighPart
			             && global->akm_sm->CurrentReplayCounter.field.LowPart == recievedRC.field.LowPart))
#else
				if(!Message_EqualReplayCounter(global->akm_sm->CurrentReplayCounter, global->EapolKeyMsgRecvd))
#endif
				{
#ifdef FOURWAY_DEBUG
					printf("4-2: ERROR_NONEEQUL_REPLAYCOUNTER\n");
					printf("global->akm_sm->CurrentReplayCounter.field.LowPart = %d\n", global->akm_sm->CurrentReplayCounter.field.LowPart);
					printf("recievedRC.field.LowPart = %d\n", recievedRC.field.LowPart);
#endif
					retVal = ERROR_NONEEQUL_REPLAYCOUNTER;
				}else
#endif // Don't check replay counter during dup 4-2				
				{
#ifndef RTL_WPA2
					// kenny: already increase CurrentReplayCounter after 4-1. Do it at the end of 4-2
					INCLargeInteger(&global->akm_sm->CurrentReplayCounter);
#endif
					global->akm_sm->SNonce = Message_KeyNonce(global->EapolKeyMsgRecvd);
                    int ISSHA256 = 0;
#ifdef CONFIG_IEEE80211R
					if (global->akm_sm->isFT)
						CalcFTPTK(global, global->akm_sm->PTK, 48);
					else
#endif
                    #ifdef CONFIG_IEEE80211W
                    ISSHA256 = (global->AuthKeyMethod == DOT11_AuthKeyType_802_1X_SHA256
                    #ifdef HS2_SUPPORT                        
					  || global->auth->RSNVariable.bOSEN
                    #endif					  
					  );
                    #endif                    
					CalcPTK(global->EAPOLMsgRecvd.Octet, global->EAPOLMsgRecvd.Octet + 6,
					global->akm_sm->ANonce.Octet, global->akm_sm->SNonce.Octet,
					global->akm_sm->PMK, PMK_LEN, global->akm_sm->PTK, 
					ISSHA256?48:PTK_LEN_TKIP
                    #ifdef CONFIG_IEEE80211W
					, ISSHA256 					
                    #endif
                    );

#ifdef DBG_WPA_CLIENT
					{
						memcpy(RTLClient.global->supp_kmsm->PTK, global->akm_sm->PTK, PTK_LEN_TKIP);
						memcpy(RTLClient.global->supp_kmsm->SNonce.Octet, global->akm_sm->SNonce.Octet, KEY_NONCE_LEN);
					}
#endif

#ifdef CONFIG_IEEE80211R
					if (global->akm_sm->isFT) {
						OCTET_STRING eapol_content;
						eapol_content.Octet = global->EAPOLMsgRecvd.Octet+ + 14 + 4; // eth hdr + eapol header
						eapol_content.Length = global->EAPOLMsgRecvd.Length - 14 - 4;
						tmpKeyData = Message_KeyData(eapol_content, Message_KeyDataLength(eapol_content));

						if (ft_check_imd_4way(global, tmpKeyData.Octet, tmpKeyData.Length, &status)) {
							switch (status)
							{
							case __STATS_INVALID_IE_:
#ifdef FOURWAY_DEBUG
								printf("4-2: RSNIE not present in FT Message 2\n");
#endif
								global->akm_sm->ErrorRsn = RSN_invalid_info_element;
								break;
							case _STATS_INVALID_MDIE_:
#ifdef FOURWAY_DEBUG
								printf("4-2: Invalid MDIE in FT Message 2\n");
#endif
								global->akm_sm->ErrorRsn = RSN_invalid_info_element;
								break;
							case __STATS_INVALID_AKMP_:
#ifdef FOURWAY_DEBUG
								printf("4-2: Invalid AKM Suite\n");
#endif
								global->akm_sm->ErrorRsn = RSN_AKMP_not_valid;
								break;
							case _STATS_INVALID_PMKID_:
#ifdef FOURWAY_DEBUG
								printf("4-2: PMKR1-Name not match\n");
#endif
								global->akm_sm->ErrorRsn = RSN_invalid_info_element;
								break;
							default:
								break;
							}
							global->akm_sm->Disconnect = TRUE;
						}
					}

					if (global->akm_sm->Disconnect) {
						retVal = ERROR_NONEQUAL_RSNIE;
					} else
#endif
					if(!CheckMIC(global->EAPOLMsgRecvd, global->akm_sm->PTK, PTK_LEN_EAPOLMIC))
					{
						global->akm_sm->Disconnect = TRUE;
						global->akm_sm->ErrorRsn = RSN_MIC_failure;
#ifdef RTL_WPA2
						printf("4-2: ERROR_MIC_FAIL\n");

						syslog(LOG_AUTH|LOG_INFO, "%s: Authentication failled! (4-2: MIC error)\n", dev_supp); // david+2006-03-31, add event to syslog

#if defined(CONFIG_RTL8186_TR) || defined(CONFIG_RTL865X_SC) || defined(CONFIG_RTL865X_AC) || defined(CONFIG_RTL865X_KLD)
						LOG_MSG_NOTICE("Authentication failed;note:%02x-%02x-%02x-%02x-%02x-%02x;",
						global->theAuthenticator->supp_addr[0],
						global->theAuthenticator->supp_addr[1],
						global->theAuthenticator->supp_addr[2],
						global->theAuthenticator->supp_addr[3],
						global->theAuthenticator->supp_addr[4],
						global->theAuthenticator->supp_addr[5]);
#endif

						wpa2_hexdump("PTK:", global->akm_sm->PTK, PTK_LEN);
						wpa2_hexdump("Message 2:", global->EAPOLMsgRecvd.Octet + 14, global->EAPOLMsgRecvd.Length);

						if (global->RSNVariable.PMKCached ) {
							printf("\n%s:%d del_pmksa due to 4-2 ERROR_MIC_FAIL\n", __FUNCTION__, __LINE__);
							del_pmksa_by_spa(global->theAuthenticator->supp_addr);
							if(is_pmksa_empty())
								global->RSNVariable.PMKCached = FALSE;
						}
#endif
						retVal = ERROR_MIC_FAIL;
					}else
					{
						//lib1x_control_AssocInfo(global, 0, &global->akm_sm->SuppInfoElement);
						//if(!Message_EqualRSNIE(	Message_KeyData(global->EapolKeyMsgRecvd, Message_ReturnKeyDataLength(global->EapolKeyMsgRecvd)),
						//		global->akm_sm->SuppInfoElement, global->akm_sm->SuppInfoElement.Length))
						if(0)
						{
							global->akm_sm->Disconnect = TRUE;
							global->akm_sm->ErrorRsn = RSN_diff_info_element;
							retVal = ERROR_NONEQUAL_RSNIE;
							printf("4-2: ERROR_NONEQUAL_RSNIE\n");
						}else
						{
							//Construct Message3
#ifdef FOURWAY_DEBUG
							printf("4-3\n");
#endif
							memset(global->EapolKeyMsgSend.Octet, 0, MAX_EAPOLKEYMSG_LEN);
#ifdef RTL_WPA2
							if ( global->RSNVariable.WPA2Enabled ) {
								Message_setDescType(global->EapolKeyMsgSend, desc_type_WPA2);
							} else
								Message_setDescType(global->EapolKeyMsgSend, desc_type_RSN);
#else
							Message_setDescType(global->EapolKeyMsgSend, global->DescriptorType);
#endif
							Message_setKeyDescVer(global->EapolKeyMsgSend, Message_KeyDescVer(global->EapolKeyMsgRecvd));
							Message_setKeyType(global->EapolKeyMsgSend, Message_KeyType(global->EapolKeyMsgRecvd));
							Message_setKeyIndex(global->EapolKeyMsgSend, Message_KeyIndex(global->EapolKeyMsgRecvd));


							//lib1x_message(MESS_DBG_KEY_MANAGE, "lib1x_akmsm_ProcessEAPOL_proc, will install bit set = %d\n", global->RSNVariable.isSuppSupportUnicastCipher ? 1:0);
							//Message_setInstall(global->EapolKeyMsgSend, global->RSNVariable.isSuppSupportUnicastCipher ? 1:0);
							Message_setInstall(global->EapolKeyMsgSend, 1);
							Message_setKeyAck(global->EapolKeyMsgSend, 1);
							Message_setKeyMIC(global->EapolKeyMsgSend, 1);
							Message_setSecure(global->EapolKeyMsgSend, global->RSNVariable.isSuppSupportMulticastCipher ? 0:1);
							Message_setError(global->EapolKeyMsgSend, 0);
							Message_setRequest(global->EapolKeyMsgSend, 0);
							Message_setReserved(global->EapolKeyMsgSend, 0);

							Message_setKeyLength(global->EapolKeyMsgSend, (global->RSNVariable.UnicastCipher  == DOT11_ENC_TKIP) ? 32:16);
							Message_setReplayCounter(global->EapolKeyMsgSend, global->akm_sm->CurrentReplayCounter.field.HighPart, global->akm_sm->CurrentReplayCounter.field.LowPart);
							Message_setKeyNonce(global->EapolKeyMsgSend, global->akm_sm->ANonce);
							memset(IV.Octet, 0, IV.Length);
							Message_setKeyIV(global->EapolKeyMsgSend, IV);


#ifdef RTL_WPA2
							if ( global->RSNVariable.WPA2Enabled ) {
								unsigned char key_data[128];
								unsigned char * key_data_pos = key_data;
								int i;
								unsigned char GTK_KDE_TYPE[] = {0xDD, 0x16, 0x00, 0x0F, 0xAC, 0x01, 0x01, 0x00 };

								global->EapolKeyMsgSend.Octet[1] = 0x13;

								if(global->KeyDescriptorVer == key_desc_ver2 ) {
									INCOctet32_INTEGER(&global->auth->Counter);
									SetEAPOL_KEYIV(IV, global->auth->Counter);
									//memset(IV.Octet, 0x0, IV.Length);
									Message_setKeyIV(global->EapolKeyMsgSend, IV);
								}

								// RSN IE
								//printf("%s: global->auth->RSNVariable.AuthInfoElement.Octet[0] = %02X\n", __FUNCTION__, global->auth->RSNVariable.AuthInfoElement.Octet[0]);
								if (global->auth->RSNVariable.AuthInfoElement.Octet[0] == WPA2_ELEMENT_ID) {
									int len = (unsigned char)global->auth->RSNVariable.AuthInfoElement.Octet[1] + 2;
									memcpy(key_data_pos, global->auth->RSNVariable.AuthInfoElement.Octet, len);
									key_data_pos += len;
								} else {
									//find WPA2_ELEMENT_ID 0x30
									int len = (unsigned char)global->auth->RSNVariable.AuthInfoElement.Octet[1] + 2;
									//printf("%s: global->auth->RSNVariable.AuthInfoElement.Octet[%d] = %02X\n", __FUNCTION__, len, global->auth->RSNVariable.AuthInfoElement.Octet[len]);
									if (global->auth->RSNVariable.AuthInfoElement.Octet[len] == WPA2_ELEMENT_ID) {
										int len2 = (unsigned char)global->auth->RSNVariable.AuthInfoElement.Octet[len+1] + 2;
										memcpy(key_data_pos, global->auth->RSNVariable.AuthInfoElement.Octet+len, len2);
										key_data_pos += len2;
									} else {
										printf("kenny: %s-%d ERROR!\n", __FUNCTION__, __LINE__);
									}
								}


								memcpy(key_data_pos, GTK_KDE_TYPE, sizeof(GTK_KDE_TYPE));
								key_data_pos[1] = (unsigned char) 6 + ((global->RSNVariable.MulticastCipher == DOT11_ENC_TKIP) ? 32:16);
								key_data_pos += sizeof(GTK_KDE_TYPE);


								// FIX GROUPKEY ALL ZERO
								global->auth->gk_sm->GInitAKeys = TRUE;
								lib1x_akmsm_UpdateGK_proc(global->auth);
								memcpy(key_data_pos, gkm_sm->GTK[gkm_sm->GN], (global->RSNVariable.MulticastCipher == DOT11_ENC_TKIP) ? 32:16);

								key_data_pos += (global->RSNVariable.MulticastCipher == DOT11_ENC_TKIP) ? 32:16;
								i = (key_data_pos - key_data) % 8;
								if ( i != 0 ) {
									*key_data_pos = 0xdd;
									key_data_pos++;
									for (i=i+1; i<8; i++) {
										*key_data_pos = 0x0;
										key_data_pos++;
									}

								}

								EncGTK(global, global->akm_sm->PTK + PTK_LEN_EAPOLMIC, PTK_LEN_EAPOLENC,
									key_data,
									(key_data_pos - key_data),
									 KeyData.Octet, &tmpKeyData_Length);

								KeyData.Length = (int)tmpKeyData_Length;
								Message_setKeyData(global->EapolKeyMsgSend, KeyData);
								Message_setKeyDataLength(global->EapolKeyMsgSend, KeyData.Length);

								global->EapolKeyMsgSend.Length = EAPOLMSG_HDRLEN +
										KeyData.Length;
								lib1x_control_QueryRSC(global, &RSC);
								Message_setKeyRSC(global->EapolKeyMsgSend, RSC);


							} else {
								memset(RSC.Octet, 0, RSC.Length);
								Message_setKeyRSC(global->EapolKeyMsgSend, RSC);
								memset(KeyID.Octet, 0, KeyID.Length);
								Message_setKeyID(global->EapolKeyMsgSend, KeyID);
								//lib1x_hexdump2(MESS_DBG_KEY_MANAGE, "lib1x_akmsm_ProcessEAPOL_proc", global->auth->RSNVariable.AuthInfoElement.Octet, global->auth->RSNVariable.AuthInfoElement.Length,"Append Authenticator Information Element");

								{ //WPA 0xDD
									//printf("%s: global->auth->RSNVariable.AuthInfoElement.Octet[0] = %02X\n", __FUNCTION__, global->auth->RSNVariable.AuthInfoElement.Octet[0]);

									int len = (unsigned char)global->auth->RSNVariable.AuthInfoElement.Octet[1] + 2;

									if (global->auth->RSNVariable.AuthInfoElement.Octet[0] == RSN_ELEMENT_ID) {
										memcpy(KeyData.Octet, global->auth->RSNVariable.AuthInfoElement.Octet, len);
										KeyData.Length = len;
									} else {
										// impossible case??
										int len2 = (unsigned char)global->auth->RSNVariable.AuthInfoElement.Octet[len+1] + 2;
										memcpy(KeyData.Octet, global->auth->RSNVariable.AuthInfoElement.Octet+len, len2);
										KeyData.Length = len2;
									}
								}
								Message_setKeyDataLength(global->EapolKeyMsgSend, KeyData.Length);
								Message_setKeyData(global->EapolKeyMsgSend, KeyData);
								global->EapolKeyMsgSend.Length = EAPOLMSG_HDRLEN + KeyData.Length;
							}

							INCLargeInteger(&global->akm_sm->CurrentReplayCounter);

#else
							memset(RSC.Octet, 0, RSC.Length);
							Message_setKeyRSC(global->EapolKeyMsgSend, RSC);
							memset(KeyID.Octet, 0, KeyID.Length);
							Message_setKeyID(global->EapolKeyMsgSend, KeyID);
							//lib1x_hexdump2(MESS_DBG_KEY_MANAGE, "lib1x_akmsm_ProcessEAPOL_proc", global->auth->RSNVariable.AuthInfoElement.Octet, global->auth->RSNVariable.AuthInfoElement.Length,"Append Authenticator Information Element");
							Message_setKeyDataLength(global->EapolKeyMsgSend, global->auth->RSNVariable.AuthInfoElement.Length);
							Message_setKeyData(global->EapolKeyMsgSend, global->auth->RSNVariable.AuthInfoElement);
							//Message_setKeyDataLength(global->EapolKeyMsgSend, global->akm_sm->AuthInfoElement.Length);
							//Message_setKeyData(global->EapolKeyMsgSend, global->akm_sm->AuthInfoElement);
							global->EapolKeyMsgSend.Length = EAPOLMSG_HDRLEN + global->auth->RSNVariable.AuthInfoElement.Length;
#endif /* RTL_WPA2 */
							global->EAPOLMsgSend.Length = ETHER_HDRLEN + LIB1X_EAPOL_HDRLEN + global->EapolKeyMsgSend.Length;

							global->akm_sm->IfCalcMIC = TRUE;
						}//Message_EqualRSNIE
					}//CheckMIC
				}//Message_EqualReplayCounter
				break;
					
#endif /* SOLVE_DUP_4_2 */					
				}else if(!CheckMIC(global->EAPOLMsgRecvd, global->akm_sm->PTK, PTK_LEN_EAPOLMIC))
#else
				if(!CheckMIC(global->EAPOLMsgRecvd, global->akm_sm->PTK, PTK_LEN_EAPOLMIC))

#endif
				{
					global->akm_sm->Disconnect = TRUE;
                                        global->akm_sm->ErrorRsn = RSN_MIC_failure;
					retVal = ERROR_MIC_FAIL;
#ifdef RTL_WPA2
					printf("4-4: RSN_MIC_failure\n");

					syslog(LOG_AUTH|LOG_INFO, "%s: Authentication failled! (4-4: RSN MIC error)\n", dev_supp); // david+2006-03-31, add event to syslog

#if defined(CONFIG_RTL8186_TR) || defined(CONFIG_RTL865X_SC) || defined(CONFIG_RTL865X_AC) || defined(CONFIG_RTL865X_KLD)
					LOG_MSG_NOTICE("Authentication failed;note:%02x-%02x-%02x-%02x-%02x-%02x;",
						global->theAuthenticator->supp_addr[0],
						global->theAuthenticator->supp_addr[1],
						global->theAuthenticator->supp_addr[2],
						global->theAuthenticator->supp_addr[3],
						global->theAuthenticator->supp_addr[4],
						global->theAuthenticator->supp_addr[5]);
#endif

					if (global->RSNVariable.PMKCached ) {
						printf("\n%s:%d del_pmksa due to 4-4 RSN_MIC_failure\n", __FUNCTION__, __LINE__);
						del_pmksa_by_spa(global->theAuthenticator->supp_addr);
						if(is_pmksa_empty())
							global->RSNVariable.PMKCached = FALSE;
					}
#endif

				}else
				{
#ifdef FOURWAY_DEBUG
					printf("4-4\n");
#endif
#ifdef RTL_WPA2_PREAUTH
					// update ANonce for next 4-way handshake
					SetNonce(akm_sm->ANonce, global->auth->Counter);
#endif
					syslog(LOG_AUTH|LOG_INFO, "%s: Open and authenticated\n", dev_supp); // david+2006-03-31, add event to syslog

#if defined(CONFIG_RTL8186_TR) || defined(CONFIG_RTL865X_SC) || defined(CONFIG_RTL865X_AC) || defined(CONFIG_RTL865X_KLD)
					LOG_MSG_NOTICE("Authentication Success;note:%02x-%02x-%02x-%02x-%02x-%02x;",
						global->theAuthenticator->supp_addr[0],
						global->theAuthenticator->supp_addr[1],
						global->theAuthenticator->supp_addr[2],
						global->theAuthenticator->supp_addr[3],
						global->theAuthenticator->supp_addr[4],
						global->theAuthenticator->supp_addr[5]);
#endif

					//MLME-SETKEYS.request
					INCLargeInteger(&global->akm_sm->CurrentReplayCounter);
					// kenny: n+2
					INCLargeInteger(&global->akm_sm->CurrentReplayCounter);
				}
				break;
			case akmsm_PTKINITDONE:

				//receive message [with request bit set]
				if(Message_Request(global->EapolKeyMsgRecvd))
				//supp request to initiate 4-way handshake
				{

				}

				break;
			default:
				printf("%s: akm_sm->state = Unknown.\n", __FUNCTION__);
				break;
		}//switch
	}else if(Message_KeyType(global->EapolKeyMsgRecvd) == type_Group)
	{
#ifdef FOURWAY_DEBUG
		printf("2-2\n");
#endif
		if(!Message_Request(global->EapolKeyMsgRecvd))
		//2nd message of 2-way handshake
		{
			//verify that replay counter maches one it has used in the Group Key handshake

			if(Message_LargerReplayCounter(global->akm_sm->CurrentReplayCounter, global->EapolKeyMsgRecvd))
			{
				retVal = ERROR_LARGER_REPLAYCOUNTER;
			}else if(!CheckMIC(global->EAPOLMsgRecvd, global->akm_sm->PTK, PTK_LEN_EAPOLMIC))
			{
				global->akm_sm->Disconnect = TRUE;
				global->akm_sm->ErrorRsn = RSN_MIC_failure;
				retVal = ERROR_MIC_FAIL;
			}else
			{
				//complete one supplicant group key update
				retVal = 0;
			}

		}else //if(!Message_Request(global->EapolKeyMsgRecvd))
		//supp request to change group key
		{
			printf("%s: Message_Request(global->EapolKeyMsgRecvd).\n", __FUNCTION__);
		}
	}

	free(IV.Octet);
	free(RSC.Octet);
	free(KeyID.Octet);
	free(MIC.Octet);
#ifdef RTL_WPA2
	free(KeyData.Octet);
#endif
	return retVal;
};

#ifndef COMPACK_SIZE
//process 2nd message sent from supplicant and generate 3rd message sent to supplicant
int lib1x_akmsm_PTKSTART_proc(Global_Params * global)
{
	lib1x_message(MESS_DBG_KEY_MANAGE, "lib1x_akmsm_PTKSTART_proc\n");
	return TRUE;
}

//process 4th message from supplicant
int lib1x_akmsm_PTKINITNEGOTIAONT_proc(Global_Params * global)
{
	lib1x_message(MESS_DBG_KEY_MANAGE, "lib1x_akmsm_PTKINITNEGOTIAONT_proc\n");
	return TRUE;
}
#endif
//-------------------------------------------------------------
// Start 2-way handshake after receiving 4th message
// Return 1 success
//-------------------------------------------------------------
int lib1x_akmsm_UpdateGK_proc(Dot1x_Authenticator *auth)
{
	Global_Params *		pGlobal;
	AGKeyManage_SM *	gkm_sm = auth->gk_sm;


	int i, retVal = TRUE;

	lib1x_message(MESS_DBG_KEY_MANAGE, "lib1x_akmsm_UpdateGK_proc\n");

#ifdef HS2_SUPPORT
	printf("au:%d,gtk:%d,initak:%d,initdone:%d\n", gkm_sm->GTKAuthenticator, gkm_sm->GTKRekey, gkm_sm->GInitAKeys, gkm_sm->GInitDone);

	printf("interface=%s\n\n", auth->GlobalTxRx->device_wlan0);
	if (hs2_check_dgaf_disable(auth->GlobalTxRx->device_wlan0))
    {
        printf("==>lib1x_akmsm_UpdateGK_proc:dgaf disable=enable\n");
        gkm_sm->GInitDone = FALSE;
    }
    else
        gkm_sm->GInitDone = TRUE;
#endif

	//------------------------------------------------------------
        // Execute Global Group key state machine
        //------------------------------------------------------------
	if( gkm_sm->GTKAuthenticator &&
		(gkm_sm->GTKRekey || (gkm_sm->GInitAKeys && !gkm_sm->GInitDone)) )
	{
		lib1x_message(MESS_DBG_KEY_MANAGE, "lib1x_akmsm_UpdateGK_proc, New Group Key Will generated\n");
		if(gkm_sm->GTKRekey)
			lib1x_message(MESS_DBG_KEY_MANAGE, "gkm_sm->GTKRekey = TRUE\n");
		if(gkm_sm->GInitAKeys)
			lib1x_message(MESS_DBG_KEY_MANAGE, "gkm_sm->GInitAKeys = TRUE\n");
		if(!gkm_sm->GInitDone)
			lib1x_message(MESS_DBG_KEY_MANAGE, "!gkm_sm->GInitDone = TRUE\n");

		
		if(!gkm_sm->GInitDone)
		{
			lib1x_message(MESS_DBG_KEY_MANAGE, "lib1x_akmsm_UpdateGK_proc, Group key is first generated\n");
			for(i = 0; i < NumGroupKey; i++)
				memset(gkm_sm->GTK[i], 0, sizeof(gkm_sm->GTK[i]));
			gkm_sm->GN = 1;
			gkm_sm->GM = 2;

		}
		//---- If 0607
		//---- Empty
		//---- Else
		/*else
			SWAP(gkm_sm->GN, gkm_sm->GM);
		*/
		//---- Endif

		gkm_sm->GInitDone = TRUE;

		INCOctet32_INTEGER(&auth->Counter);

		// kenny:??? GNonce should be a random number ???
		SetNonce(gkm_sm->GNonce , auth->Counter);
		CalcGTK(auth->CurrentAddress, gkm_sm->GNonce.Octet,
				gkm_sm->GMK, GMK_LEN, gkm_sm->GTK[gkm_sm->GN], GTK_LEN,(u_char*)GMK_EXPANSION_CONST);

#ifdef HS2_SUPPORT
		if(gkm_sm->GTKRekey)
#endif			
		gkm_sm->GUpdateStationKeys = TRUE;
		gkm_sm->GkeyReady = FALSE;

		gkm_sm->GTKRekey = FALSE;

		//---- In the case of updating GK to all STAs, only the STA that has finished
		//---- 4-way handshake is needed to be sent with 2-way handshake
		//gkm_sm->GKeyDoneStations = auth->NumOfSupplicant;
		gkm_sm->GKeyDoneStations = 0;
		//sc_yang
		for(i = 0 ; i < auth->MaxSupplicant ; i++)
// reduce pre-alloc memory size, david+2006-02-06			
//			if(auth->Supp[i]->global->akm_sm->state == akmsm_PTKINITDONE &&
			if(auth->Supp[i] && auth->Supp[i]->global->akm_sm->state == akmsm_PTKINITDONE &&
				auth->Supp[i]->isEnable)
				gkm_sm->GKeyDoneStations++;
		lib1x_message(MESS_DBG_KEY_MANAGE, "GKeyDoneStations : Number of stations left to have their Group key updated = %d\n", gkm_sm->GKeyDoneStations);
	}

#ifdef CONFIG_IEEE80211W
	if(auth->RSNVariable.ieee80211w != NO_MGMT_FRAME_PROTECTION) {
		CalcGTK(auth->CurrentAddress, gkm_sm->GNonce.Octet,
				gkm_sm->GMK, GMK_LEN, gkm_sm->IGTK[gkm_sm->GN_igtk-4], IGTK_LEN,(u_char*)IGMK_EXPANSION_CONST);
	}		
#endif // CONFIG_IEEE80211W

	//------------------------------------------------------------
	// Execute Group key state machine of each STA
	//------------------------------------------------------------
	lib1x_message(MESS_DBG_KEY_MANAGE, "Execute Group key state machine of each STA");
	//sc_yang
	for(i = 0 ; i < auth->MaxSupplicant ; i++)
        {
// reduce pre-alloc memory size, david+2006-02-06			        
//		if(!auth->Supp[i]->isEnable)
		if(auth->Supp[i]==NULL || !auth->Supp[i]->isEnable)
			continue;
		pGlobal = auth->Supp[i]->global;

		//----if 0706
		lib1x_message(MESS_DBG_KEY_MANAGE, "Supp[%d] is enable, update group key\n", i);
		//----else
		//lib1x_message(MESS_DBG_KEY_MANAGE, "Supp[i] is enable, update group key\n", i);
		//----endif


		//---- Group key handshake to only one supplicant ----
		if(pGlobal->akm_sm->state == akmsm_PTKINITDONE &&
			(gkm_sm->GkeyReady && pGlobal->akm_sm->PInitAKeys))
		{
			lib1x_message(MESS_DBG_KEY_MANAGE, "Group Key Update One : STA[%d]\n", auth->Supp[i]->index);
			pGlobal->akm_sm->PInitAKeys = FALSE;
			pGlobal->akm_sm->gstate = gkmsm_REKEYNEGOTIATING;	// set proper gstat, david+2006-04-06
                        lib1x_akmsm_SendEAPOL_proc(pGlobal);

		}
		//---- Updata group key to all supplicant----
		else if(pGlobal->akm_sm->state == akmsm_PTKINITDONE &&           //Done 4-way handshake
                      (gkm_sm->GUpdateStationKeys      ||                     //When new key is generated
                       pGlobal->akm_sm->gstate == gkmsm_REKEYNEGOTIATING))  //1st message is not yet sent
                {
                        lib1x_message(MESS_DBG_KEY_MANAGE, "Group KEY Update ALL : STA[%d]\n", auth->Supp[i]->index);
			pGlobal->akm_sm->PInitAKeys = FALSE;
			pGlobal->akm_sm->gstate = gkmsm_REKEYNEGOTIATING;	// set proper gstat, david+2006-04-06			
			lib1x_akmsm_SendEAPOL_proc(pGlobal);
                }

       }
       gkm_sm->GUpdateStationKeys = FALSE;

	return retVal;
};


void lib1x_akmsm_Timer_proc(Dot1x_Authenticator * auth)
{
	int 			i;
	Global_Params *		global;
	APKeyManage_SM  *       akm_sm;


	/*
	if(lib1x_global_signal_info != NULL)
		auth = (Dot1x_Authenticator *) lib1x_global_signal_info;
	else
		return 0;
	*/


	//sc_yang
	for(i = 0 ; i < auth->MaxSupplicant ; i++)
        {
// reduce pre-alloc memory size, david+2006-02-06        
//		if(!auth->Supp[i]->isEnable)
		if(auth->Supp[i]==NULL || !auth->Supp[i]->isEnable)
			continue;

		global = auth->Supp[i]->global;
		akm_sm = global->akm_sm;

		//lib1x_akmsm_dump(global);


		if(akm_sm->state == akmsm_PTKSTART ||
		   akm_sm->state == akmsm_PTKINITNEGOTIATING ||
		   ( akm_sm->state == akmsm_PTKINITDONE && akm_sm->gstate == gkmsm_REKEYNEGOTIATING) ||
		   akm_sm->bWaitForPacket)
		{
			//sc_yang
			if( --akm_sm->TickCnt == 0){
				akm_sm->TickCnt = SECONDS_TO_TIMERCOUNT(1);
			akm_sm->TimeoutCtr++;
			}
			else
				continue;

#ifdef ALLOW_DBG_KEY_MANAGE
			if(akm_sm->state == akmsm_PTKSTART) printf("akm_sm->state == akmsm_PTKSTART\n");
			if(akm_sm->state == akmsm_PTKINITNEGOTIATING) printf("akm_sm->state == akmsm_PTKINITNEGOTIATING\n");
			if(akm_sm->state == akmsm_PTKINITDONE && akm_sm->gstate == gkmsm_REKEYNEGOTIATING)			printf("akm_sm->state == akmsm_PTKINITDONE && akm_sm->gstate == gkmsm_REKEYNEGOTIATING\n");
			if(akm_sm->bWaitForPacket) printf("akm_sm->bWaitForPacket\n");
#endif

			//lib1x_message(MESS_DBG_KEY_MANAGE, "Supplicant [%d] Timeout Counter = %d", global->index, akm_sm->TimeoutCtr);
			if((akm_sm->state == akmsm_PTKSTART || akm_sm->state == akmsm_PTKINITNEGOTIATING) &&
			    akm_sm->TimeoutCtr > 0)
			    //akm_sm->TimeoutCtr == global->Dot11RSNConfig.PairwiseUpdateCount
			//---- Pairwise Key state machine time out ----
			{


				lib1x_message(MESS_DBG_KEY_MANAGE, "akm_sm->TimeoutCtr = %d, global->Dot11RSNConfig.PairwiseUpdateCount = %d\n", akm_sm->TimeoutCtr, global->Dot11RSNConfig.PairwiseUpdateCount);
				if(akm_sm->TimeoutCtr <= global->Dot11RSNConfig.PairwiseUpdateCount)
				{
					//----Resent packet in buffer
					lib1x_message(MESS_DBG_KEY_MANAGE, "[****Pairwise Key state machine time out], Re-sent Packet\n");
					lib1x_PrintAddr(global->theAuthenticator->supp_addr);
					akm_sm->TimeoutEvt = TRUE;
					
// increase replay counter ----------------------
#if 0
					Message_setReplayCounter(global->EapolKeyMsgSend, global->akm_sm->CurrentReplayCounter.field.HighPart, global->akm_sm->CurrentReplayCounter.field.LowPart);
		                        INCLargeInteger(&global->akm_sm->CurrentReplayCounter);
					global->akm_sm->IfCalcMIC = TRUE;					
#endif					
//----------------------------- david, 2006-08-09	
				}
				else
				{
					//----Clear Timeout Counter, stop send packet
					lib1x_PrintAddr(global->theAuthenticator->supp_addr);
					lib1x_message(MESS_DBG_KEY_MANAGE, "[****Pairwise Key state machine time out], Maxmum Retry time\n");
					akm_sm->TimeoutCtr = 0;
					//global->akm_sm->ErrorRsn = disas_lv_ss;
					global->akm_sm->ErrorRsn = RSN_4_way_handshake_timeout;
					global->akm_sm->Disconnect = TRUE;
#ifdef RTL_WPA2
					if (global->RSNVariable.PMKCached && (akm_sm->state == akmsm_PTKSTART || akm_sm->state == akmsm_PTKINITNEGOTIATING) ) {
						printf("\n%s:%d del_pmksa due to 4-1 or 4-3 timeout\n", __FUNCTION__, __LINE__);
						del_pmksa_by_spa(global->theAuthenticator->supp_addr);
						if(is_pmksa_empty())
							global->RSNVariable.PMKCached = FALSE;
					}
#endif
				}
			}
			//---- Group Key state machine time out ----


			if(
			    (akm_sm->state == akmsm_PTKINITDONE && akm_sm->gstate == gkmsm_REKEYNEGOTIATING) &&
			     akm_sm->TimeoutCtr > 0)
			     //akm_sm->TimeoutCtr == global->Dot11RSNConfig.GroupUpdateCount

			{
				//The Authenticator must increment and use a new Replay Counter value in every Message 1 instance

				lib1x_message(MESS_DBG_KEY_MANAGE, "akm_sm->TimeoutCtr = %d, global->Dot11RSNConfig.GroupUpdateCount = %d\n", akm_sm->TimeoutCtr, global->Dot11RSNConfig.GroupUpdateCount);


				if(akm_sm->TimeoutCtr <= global->Dot11RSNConfig.GroupUpdateCount)
				{

					lib1x_message(MESS_DBG_KEY_MANAGE, "[*****Group Key state machine time out], Resent Packet\n");
					lib1x_PrintAddr(global->theAuthenticator->supp_addr);
					//07-15
					Message_setReplayCounter(global->EapolKeyMsgSend, global->akm_sm->CurrentReplayCounter.field.HighPart, global->akm_sm->CurrentReplayCounter.field.LowPart);
		                        INCLargeInteger(&global->akm_sm->CurrentReplayCounter);

					//sc_yang n+2
		                        INCLargeInteger(&global->akm_sm->CurrentReplayCounter);

					//
					akm_sm->TimeoutEvt = TRUE;
					global->akm_sm->IfCalcMIC = TRUE;
				}
				else
				{
					lib1x_message(MESS_DBG_KEY_MANAGE, "[*****Group Key state machine time out], Maximun Retry time\n");
					lib1x_PrintAddr(global->theAuthenticator->supp_addr);
					akm_sm->TimeoutCtr = 0;
					global->akm_sm->ErrorRsn = disas_lv_ss;
					global->akm_sm->Disconnect = TRUE;

// set group key to driver and reset rekey timer when GKeyDoneStations=0 -------
					if(global->auth->gk_sm->GKeyDoneStations > 0)
						global->auth->gk_sm->GKeyDoneStations--;

					if (global->auth->gk_sm->GKeyDoneStations == 0 && !global->auth->gk_sm->GkeyReady)
	                {
	                
                	        if(lib1x_control_SetGTK(global) == 0)//success
							{
								printf("last node of group key unpdate expired!\n");
           	            		global->auth->gk_sm->GkeyReady = TRUE;
								global->auth->gk_sm->GResetCounter = TRUE;
							}
						#ifdef CONFIG_IEEE80211W
							if(lib1x_control_SetIGTK(global) != 0)//success
							{
								printf("Auth fail to install IGTK !\n");
           	            		global->auth->gk_sm->GkeyReady = FALSE;
								global->auth->gk_sm->GResetCounter = FALSE;
							}
						#endif	
	                }		
//--------------------------------------------------------- david+2006-04-06					
				}
			}

		}

	}

}


//--------------------------------------------------------------------
// Return 1 for success
//--------------------------------------------------------------------
int lib1x_akmsm_GroupReKey_Timer_proc(Dot1x_Authenticator * auth)
{

	Global_Params * global;
	Auth_Pae      * auth_pae;


        struct lib1x_eapol 	* eapol;
        struct lib1x_ethernet 	* eth_hdr;


	int i, retVal = TRUE;
	lib1x_message(MESS_DBG_KEY_MANAGE, "=================================");
	lib1x_message(MESS_DBG_KEY_MANAGE, "lib1x_akmsm_GroupReKey_Timer_proc");
	lib1x_message(MESS_DBG_KEY_MANAGE, "=================================");
	auth->gk_sm->GTKRekey = TRUE;
	lib1x_akmsm_UpdateGK_proc(auth);

	//sc_yang
	for(i = 0 ; i < auth->MaxSupplicant ; i++)
        {
// reduce pre-alloc memory size, david+2006-02-06        
//		if(!auth->Supp[i]->isEnable)
		if(auth->Supp[i]==NULL || !auth->Supp[i]->isEnable)
			continue;

		global = auth->Supp[i]->global;
		auth_pae = global->theAuthenticator;

		if( auth_pae->sendhandshakeready )
		{
			//ethernet and eapol header initialization
			eth_hdr = ( struct lib1x_ethernet * )global->EAPOLMsgSend.Octet;
			memcpy ( eth_hdr->ether_dhost , auth_pae->supp_addr, ETHER_ADDRLEN );
			memcpy ( eth_hdr->ether_shost , auth_pae->global->TxRx->oursupp_addr, ETHER_ADDRLEN );
			eth_hdr->ether_type = htons(LIB1X_ETHER_EAPOL_TYPE);

			eapol = ( struct lib1x_eapol * )  ( global->EAPOLMsgSend.Octet +  ETHER_HDRLEN )  ;
			eapol->protocol_version = LIB1X_EAPOL_VER;
			eapol->packet_type =  LIB1X_EAPOL_KEY;

			eapol->packet_body_length = htons(global->EapolKeyMsgSend.Length);

			//lib1x_hexdump2(MESS_DBG_KEY_MANAGE, "lib1x_akmsm_execute", auth_pae->sendBuffer, global->EAPOLMsgSend.Length, "Send EAPOL-KEY Message");

			if(global->akm_sm->IfCalcMIC)
			{
				//lib1x_hexdump2(MESS_DBG_KEY_MANAGE, "lib1x_akmsm_execute",global->akm_sm->PTK, PTK_LEN_EAPOLMIC, "Key for calculate MIC");
    				CalcMIC(global->EAPOLMsgSend, global->KeyDescriptorVer, global->akm_sm->PTK, PTK_LEN_EAPOLMIC);
				global->akm_sm->IfCalcMIC = FALSE;
			}
			global->akm_sm->TimeoutEvt = 0;
			//global->akm_sm->TimeoutCtr = 0;

			KeyDump("lib1x_akmsm_SendEAPOL_proc", global->EAPOLMsgSend.Octet,global->EAPOLMsgSend.Length, "Send EAPOL-KEY");
			lib1x_nal_send( auth_pae->global->TxRx->network_supp, auth_pae->sendBuffer,
	global->EAPOLMsgSend.Length );
			global->akm_sm->bWaitForPacket = TRUE;
			auth_pae->sendhandshakeready = FALSE;
		}


	}

	return retVal;

}


void lib1x_akmsm_EAPOLStart_Timer_proc(Dot1x_Authenticator * auth)
{
	int	i;
	Global_Params *		global;
	APKeyManage_SM  *       akm_sm;
	Auth_Pae 	       * auth_pae;


	for(i = 0 ; i < auth->MaxSupplicant /*&& auth->Supp[i]->isEnable*/ ; i++)
	{
	// reduce pre-alloc memory size, david+2006-02-06        
		if (auth->Supp[i]==NULL)
			continue;

		global = auth->Supp[i]->global;
		akm_sm = global->akm_sm;
		auth_pae = global->theAuthenticator;

		if( auth->Supp[i]->isEnable ){
//	        	printf("%s: CurrentAddress = %02x:%02x:%02x:%02x:%02x:%02x\n", __FUNCTION__,
//					auth_pae->supp_addr[0], auth_pae->supp_addr[1], auth_pae->supp_addr[2],
//					auth_pae->supp_addr[3], auth_pae->supp_addr[4], auth_pae->supp_addr[5]	);

			if(akm_sm->IgnoreEAPOLStartCounter !=0 )
			{
				if(global->authSuccess){
					akm_sm->IgnoreEAPOLStartCounter = 0;
				}
				else{
					if( (akm_sm->IgnoreEAPOLStartCounter > 0) &&
						(akm_sm->IgnoreEAPOLStartCounter <= REJECT_EAPOLSTART_COUNTER) )
					{
						akm_sm->IgnoreEAPOLStartCounter--;
					}
				}

				//printf("%s: global->authSuccess = %d\n", __FUNCTION__, global->authSuccess);
				//printf("%s: IgnoreEAPOLStartCounter = %d\n", __FUNCTION__, akm_sm->IgnoreEAPOLStartCounter);
			}
			else{
			}
		}
		else{
//			printf("%s: auth->Supp[i]->isEnable = FALSE\n", __FUNCTION__);
		}
	}
}


int lib1x_akmsm_Update_Station_Status(Global_Params * global)
{

	int i, j;
	Dot1x_Authenticator * auth = global->auth;
	for(i=0 ;i < auth->MaxSupplicant ; i++)
	{
		if(global->auth->DrvStaInfo[i].aid != 0)
		{
			for( j = 0; j <auth->MaxSupplicant ; j++)
			{
				if( auth->Supp[j] && auth->Supp[j]->isEnable )
				{
					if(!memcmp( auth->Supp[j]->addr, (global->auth->DrvStaInfo[i].addr),  ETHER_ADDRLEN)) {
						auth->Supp[j]->tx_packets = global->auth->DrvStaInfo[i].tx_packets;
						auth->Supp[j]->rx_packets = global->auth->DrvStaInfo[i].rx_packets;
						break;
					}
				}
			}
		}
	}
	return 0;

}

void lib1x_akmsm_Account_Timer_proc(Dot1x_Authenticator * auth)
{
	int	i=-1, j=-1;
	int	iStationStatus;

	Global_Params *		global;
	APKeyManage_SM  *       akm_sm;
	//Get All Station Info if there is any station in session

	if(auth->IdleTimeoutEnabled)
		lib1x_control_Query_All_Sta_Info(auth);

	if(auth->AccountingEnabled)
		lib1x_acctsm(auth->authGlobal->global);

	//sc_yang
	for(i = 0 ; i < auth->MaxSupplicant ; i++)
	{
// reduce pre-alloc memory size, david+2006-02-06       
//		if(!auth->Supp[i]->isEnable)
		if(auth->Supp[i]==NULL || !auth->Supp[i]->isEnable)
			continue;

		global = auth->Supp[i]->global;
		akm_sm = global->akm_sm;

		//----------------------------------
		// Process accounting state machine
		//----------------------------------
		lib1x_acctsm( global);

		//----------------------------------
		// Process Session Timeout
		//----------------------------------
		if(auth->SessionTimeoutEnabled && global->akm_sm->SessionTimeoutEnabled)
		{
			if(auth->Supp[i]->SessionTimeoutCounter)
			{
				lib1x_message(MESS_DBG_RAD, "STA(%02x:%02x:%02x:%02x:%02x:%02x) session left:%d",
					auth->Supp[i]->addr[0],auth->Supp[i]->addr[1],auth->Supp[i]->addr[2],
					auth->Supp[i]->addr[3],auth->Supp[i]->addr[4],auth->Supp[i]->addr[5],auth->Supp[i]->SessionTimeoutCounter);
				auth->Supp[i]->SessionTimeoutCounter--;
			} else {
				global->akm_sm->SessionTimeoutEnabled = FALSE;
				global->EventId = akmsm_EVENT_Disconnect;
				lib1x_message(MESS_DBG_RAD,"Kick STA(%02x:%02x:%02x:%02x:%02x:%02x) because session terminated",
					auth->Supp[i]->addr[0],auth->Supp[i]->addr[1],auth->Supp[i]->addr[2],
					auth->Supp[i]->addr[3],auth->Supp[i]->addr[4],auth->Supp[i]->addr[5]);
				global->akm_sm->ErrorRsn = session_timeout;
				lib1x_akmsm_Disconnect( global );
			}
		}
        //----------------------------------
		// Process Idle Timeout
		//----------------------------------
		if(auth->IdleTimeoutEnabled && global->akm_sm->IdleTimeoutEnabled)
		{
			if((auth->Supp[i]->IdleTimeoutCounter == auth->Supp[i]->IdleTimeout) && auth->Supp[i]->IdleTimeout) {
				global->akm_sm->IdleTimeoutEnabled = FALSE;
				global->akm_sm->ErrorRsn = inactivity;//Idle Time out
				global->EventId = akmsm_EVENT_Disconnect;
				lib1x_message(MESS_DBG_RAD,"Kick STA(%02x:%02x:%02x:%02x:%02x:%02x) because keep idle for %d seconds",
					auth->Supp[i]->addr[0],auth->Supp[i]->addr[1],auth->Supp[i]->addr[2],
					auth->Supp[i]->addr[3],auth->Supp[i]->addr[4],auth->Supp[i]->addr[5], auth->Supp[i]->IdleTimeout);
				lib1x_akmsm_Disconnect( global );
				if(auth->AccountingEnabled)
					lib1x_acctsm_request(global, acctsm_Acct_Stop, LIB1X_ACCT_REASON_IDLE_TIMEOUT);
				//ignore update procedure below
				continue;
			}

			for(j=0 ;j < auth->MaxSupplicant ; j++)
			{
				if(global->auth->DrvStaInfo[j].aid != 0)
				{
					if(!memcmp( auth->Supp[i]->addr, &(global->auth->DrvStaInfo[j].addr),  ETHER_ADDRLEN)) {
                        if(auth->Supp[i]->tx_packets == 0 && auth->Supp[i]->rx_packets == 0){
			                //first tick update
							auth->Supp[i]->tx_packets = global->auth->DrvStaInfo[j].tx_packets;
							auth->Supp[i]->rx_packets = global->auth->DrvStaInfo[j].rx_packets;
							lib1x_message(MESS_DBG_RAD, "Initialize STA's(%02x:%02x:%02x:%02x:%02x:%02x) traffic status TX packets = %d, RX packets = %d", 
								auth->Supp[i]->addr[0],auth->Supp[i]->addr[1],auth->Supp[i]->addr[2],
								auth->Supp[i]->addr[3],auth->Supp[i]->addr[4],auth->Supp[i]->addr[5],
			                    auth->Supp[i]->tx_packets, auth->Supp[i]->rx_packets);
						}

						if( (auth->Supp[i]->tx_packets == global->auth->DrvStaInfo[j].tx_packets) &&
			                (auth->Supp[i]->rx_packets == global->auth->DrvStaInfo[j].rx_packets)) {
							auth->Supp[i]->IdleTimeoutCounter++;
							lib1x_message(MESS_DBG_RAD, "STA(%02x:%02x:%02x:%02x:%02x:%02x) Is Idle, Counter = %d", 
								auth->Supp[i]->addr[0],auth->Supp[i]->addr[1],auth->Supp[i]->addr[2],
								auth->Supp[i]->addr[3],auth->Supp[i]->addr[4],auth->Supp[i]->addr[5],
								auth->Supp[i]->IdleTimeoutCounter);
						} else {
							auth->Supp[i]->IdleTimeoutCounter = 0;
							auth->Supp[i]->tx_packets = global->auth->DrvStaInfo[j].tx_packets;
							auth->Supp[i]->rx_packets = global->auth->DrvStaInfo[j].rx_packets;
							lib1x_message(MESS_DBG_RAD, "STA(%02x:%02x:%02x:%02x:%02x:%02x) Is Not Idle, Counter Reset", 
								auth->Supp[i]->addr[0],auth->Supp[i]->addr[1],auth->Supp[i]->addr[2],
								auth->Supp[i]->addr[3],auth->Supp[i]->addr[4],auth->Supp[i]->addr[5]);
						}
						break;
					}
				}
			}
		}
		//----------------------------------
		// Process Interim Update
		//----------------------------------
		if(auth->AccountingEnabled && auth->UpdateInterimEnabled && global->akm_sm->InterimTimeoutEnabled)
		{
			//lib1x_message(MESS_DBG_KEY_MANAGE,"STA[%d] InterimTimeoutCounter = %d, akm_sm->InterimTimeout = %d\n",
			//		global->index, akm_sm->InterimTimeoutCounter, auth->Supp[0]->global->akm_sm->InterimTimeout);
			if(akm_sm->InterimTimeoutCounter >= akm_sm->InterimTimeout)
			{

				//global->theAuthenticator->acct_sm->action = acctsm_Interim_On;
				lib1x_acctsm_request(global, acctsm_Interim_On, 0);
				akm_sm->InterimTimeoutCounter = 0;
			}else
				akm_sm->InterimTimeoutCounter++;
		}
		global->theAuthenticator->acct_sm->elapsedSessionTime++;
	}

}

///////////////////////////////////////////////////////////////////////////////////////////////////////
int lib1x_akmsm_AuthenticationRequest( Global_Params * global)
{
        APKeyManage_SM  *       akm_sm = global->akm_sm;
        int retVal = TRUE;
	static unsigned int RC_toggle = 0;

	//----------------------------------
	// Clear all state to initial value
	//----------------------------------
	lib1x_reset_authenticator(global);

	if( global->EventId == akmsm_EVENT_AuthenticationRequest)
	{
		// 802.11i/D3.0 p.95
		akm_sm->CurrentReplayCounter.field.HighPart = 0;
		akm_sm->CurrentReplayCounter.field.LowPart = 0;

		// For some STA that can only process if Replay Counter is not 0
		if((RC_toggle++)%2)
			INCLargeInteger(&akm_sm->CurrentReplayCounter);

		memset(akm_sm->PTK, 0, sizeof(akm_sm->PTK));
		lib1x_message(MESS_DBG_KEY_MANAGE, "*************************Process Event akmsm_EVENT_AuthenticationRequest\n");
		lib1x_message(MESS_DBG_KEY_MANAGE, "*************************CALL lib1x_control_RemovePTK\n");
		lib1x_control_RemovePTK(global, DOT11_KeyType_Pairwise);
		if(global->AuthKeyMethod == DOT11_AuthKeyType_RSN ||
			global->AuthKeyMethod == DOT11_AuthKeyType_RSNPSK 
#ifdef CONFIG_IEEE80211R
			|| global->AuthKeyMethod == DOT11_AuthKeyType_FT
#else
			|| global->AuthKeyMethod == DOT11_AuthKeyType_NonRSN802dot1x
#endif
		)
		{
			lib1x_control_SetPORT(global, DOT11_PortStatus_Unauthorized);
		}
	}

	if(global->EventId == akmsm_EVENT_AuthenticationRequest
		|| global->EventId == akmsm_EVENT_ReAuthenticationRequest )
	{
		lib1x_message(MESS_DBG_KEY_MANAGE, "*************************Process Event akmsm_EVENT_AuthenticationRequest and akmsm_EVENT_ReAuthenticationRequest\n");
		INCOctet32_INTEGER(&global->auth->Counter);
#ifndef RTL_WPA2_PREAUTH
		SetNonce(akm_sm->ANonce, global->auth->Counter);
#endif
	}

	if(global->AuthKeyMethod == DOT11_AuthKeyType_RSNPSK)
	{
		if( global->PreshareKeyAvaliable)//Always TRUE
		{
			memcpy(akm_sm->PMK, global->PSK, sizeof(global->PSK));
#ifdef RTL_WPA2
#ifdef CONFIG_IEEE80211W
			if(global->auth->RSNVariable.ieee80211w != NO_MGMT_FRAME_PROTECTION) {
				CalcPMKID(	akm_sm->PMKID,
						akm_sm->PMK,	 // PMK
						global->theAuthenticator->global->TxRx->oursupp_addr,	// AA
						global->theAuthenticator->supp_addr,			// SPA
						(global->AuthKeyMethod==DOT11_AuthKeyType_802_1X_SHA256)); 
			}
			else
#endif //CONFIG_IEEE80211W
			{
			CalcPMKID(	akm_sm->PMKID,
					akm_sm->PMK, 	 // PMK
					global->theAuthenticator->global->TxRx->oursupp_addr,   // AA
					global->theAuthenticator->supp_addr
#ifdef CONFIG_IEEE80211W
					,(global->AuthKeyMethod==DOT11_AuthKeyType_802_1X_SHA256)
#endif
					); 			// SPA
			}
#endif
			akm_sm->state = akmsm_PTKSTART;

			//send 1st message
			lib1x_akmsm_SendEAPOL_proc(global);
		}
	}
#ifdef HS2_SUPPORT	
	else if(global->auth->RSNVariable.bOSEN && global->AuthKeyMethod == WFA_AKM_ANONYMOUS_CLI_802_1X_SHA256)
	{
		// no PMKcache function in WFA client anonymous TLS
		akm_sm->state = akmsm_AUTHENTICATION2;
	}
#endif	
	else if(global->AuthKeyMethod == DOT11_AuthKeyType_RSN 
#ifdef CONFIG_IEEE80211R
		|| global->AuthKeyMethod == DOT11_AuthKeyType_FT
#endif
#ifdef CONFIG_IEEE80211W			
		|| global->AuthKeyMethod == DOT11_AuthKeyType_802_1X_SHA256
#endif
		)
	{
#ifdef RTL_WPA2
		if (!global->RSNVariable.isPreAuth
		    && global->RSNVariable.PMKCached) {
			memcpy(akm_sm->PMK, global->RSNVariable.cached_pmk_node->pmksa.pmk, PMK_LEN);
			wpa2_hexdump("\nCached PMKID", global->RSNVariable.cached_pmk_node->pmksa.pmkid, PMKID_LEN);
			//wpa2_hexdump("Cached PMK", akm_sm->PMK, PMK_LEN);
			akm_sm->state = akmsm_PTKSTART;

			if(global->RSNVariable.cached_pmk_node->pmksa.IdleTimeout > 0) {
				global->akm_sm->IdleTimeoutEnabled = TRUE;
				global->auth->Supp[global->index]->IdleTimeout = global->RSNVariable.cached_pmk_node->pmksa.IdleTimeout;
			}
			//send 1st message
			lib1x_akmsm_SendEAPOL_proc(global);
		} else {
#endif
		akm_sm->state = akmsm_AUTHENTICATION2;

#ifdef RTL_WPA2
		}
#endif
	}


	//If Receive Association Request, discard eapol-start message in 3 seconds
	global->akm_sm->IgnoreEAPOLStartCounter = REJECT_EAPOLSTART_COUNTER;

	return retVal;
}


int lib1x_akmsm_AuthenticationSuccess( Global_Params * global)
{
	APKeyManage_SM  *       akm_sm = global->akm_sm;
	int retVal = TRUE;


	lib1x_message(MESS_DBG_KEY_MANAGE, "lib1x_akmsm_AuthenticationSuccess");

	if((global->AuthKeyMethod == DOT11_AuthKeyType_RSN 
#ifdef CONFIG_IEEE80211R
		|| global->AuthKeyMethod == DOT11_AuthKeyType_FT
#else
		|| global->AuthKeyMethod == DOT11_AuthKeyType_NonRSN802dot1x
#endif
#ifdef CONFIG_IEEE80211W		
		|| global->AuthKeyMethod == DOT11_AuthKeyType_802_1X_SHA256 
#endif
		) && global->authSuccess && akm_sm->state == akmsm_AUTHENTICATION2)
	{
		//TODO*****ONLY FOR TEST*****
		global->RadiusKey.Status = MPPE_SDRCKEY_AVALIABLE;

		if( global->RadiusKey.Status == MPPE_SDRCKEY_AVALIABLE)
		{
#ifdef RTL_WPA2
			struct _WPA2_PMKSA_Node* pmksa_node;
			pmksa_node = get_pmksa_node();
#endif
			lib1x_message(MESS_DBG_KEY_MANAGE, "lib1x_akmsm_AuthenticationSuccess:Radius Key is Avaliable");
			memcpy(akm_sm->PMK, global->RadiusKey.RecvKey.Octet, global->RadiusKey.RecvKey.Length);
#ifdef CONFIG_IEEE80211R
			if (akm_sm->isFT) {
				memcpy(akm_sm->xxkey, global->RadiusKey.SendKey.Octet, PMK_LEN);
			}
#endif
			//lib1x_control_AssociationRsp(global, DOT11_Association_Success);
#ifdef RTL_WPA2
			if(global->auth->RSNVariable.max_pmksa) {
				//printf("\n802.1x authentication done\n");
#ifdef HS2_SUPPORT
			if(global->auth->RSNVariable.bOSEN && global->AuthKeyMethod == WFA_AKM_ANONYMOUS_CLI_802_1X_SHA256) {
				memset(akm_sm->PMKID, 0, PMKID_LEN);
			}
			else
#endif
#ifdef CONFIG_IEEE80211W
			if(global->auth->RSNVariable.ieee80211w != NO_MGMT_FRAME_PROTECTION) {
				CalcPMKID(	akm_sm->PMKID,
						akm_sm->PMK,	 // PMK
						global->theAuthenticator->global->TxRx->oursupp_addr,	// AA
						global->theAuthenticator->supp_addr,					// SPA
						(global->AuthKeyMethod==DOT11_AuthKeyType_802_1X_SHA256)); 
			}
			else
#endif //CONFIG_IEEE80211W
			{
			CalcPMKID(	akm_sm->PMKID,
					akm_sm->PMK, 	 // PMK
					global->theAuthenticator->global->TxRx->oursupp_addr,   // AA
					global->theAuthenticator->supp_addr
#ifdef CONFIG_IEEE80211W
					,(global->AuthKeyMethod==DOT11_AuthKeyType_802_1X_SHA256)
#endif
					); 			// SPA
			}
				//printf("Before cache_pmk\n");
				//dump_pmk_cache();
				// Save this PMKSA
				if (pmksa_node != NULL) {
					memcpy(pmksa_node->pmksa.pmkid, akm_sm->PMKID, PMKID_LEN);
					memcpy(pmksa_node->pmksa.pmk, akm_sm->PMK, PMK_LEN);
					memcpy(pmksa_node->pmksa.spa, global->theAuthenticator->supp_addr, ETHER_ADDRLEN);
					pmksa_node->pmksa.akmp = global->AuthKeyMethod;
					if(global_pmksa_aging == 0xffffffff)
	                    global_pmksa_aging = 0;
	                global_pmksa_aging++;
	                pmksa_node->pmksa.aging = global_pmksa_aging;
					if(global->akm_sm->SessionTimeout > 0)
						pmksa_node->pmksa.SessionTimeout = global->akm_sm->SessionTimeout;
					if(global->auth->Supp[global->index]->IdleTimeout > 0)
						pmksa_node->pmksa.IdleTimeout = global->auth->Supp[global->index]->IdleTimeout;
					cache_pmksa(pmksa_node);
				} else {
					printf("%s:%d, pmksa_node == NULL\n", __FUNCTION__, __LINE__);
					exit(1);
				}
				//printf("After cache_pmk\n");
				//dump_pmk_cache();
			}

			if ( global->RSNVariable.isPreAuth) {
				wpa2_hexdump("PreAuth done: ", global->theAuthenticator->supp_addr, ETHER_ADDRLEN);
				global->RSNVariable.isPreAuth = FALSE;
				lib1x_del_supp(global->auth, global->theAuthenticator->supp_addr);
			} else {
				akm_sm->state = akmsm_PTKSTART;
				//send 1st message
				//sleep(1);
				lib1x_akmsm_SendEAPOL_proc(global);
			}
#else
			akm_sm->state = akmsm_PTKSTART;
			//send 1st message
			//sleep(1);
			lib1x_akmsm_SendEAPOL_proc(global);
#endif
		}

	}

	return retVal;
}


int lib1x_akmsm_Disconnect( Global_Params * global)
{
	Auth_Pae                * auth_pae = global->theAuthenticator;
	APKeyManage_SM	*	akm_sm = global->akm_sm;
	int retVal = TRUE;

	lib1x_message(MESS_DBG_KEY_MANAGE, "lib1x_akmsm_Disconnect(1), global->theAuthenticator->supp_addr:%02x:%02x:%02x:%02x:%02x:%02x\n",
		global->theAuthenticator->supp_addr[0],global->theAuthenticator->supp_addr[1],global->theAuthenticator->supp_addr[2],
		global->theAuthenticator->supp_addr[3],global->theAuthenticator->supp_addr[4],global->theAuthenticator->supp_addr[5]);

	//Disconnect is request from 1x daemon, Disassociate if indication from driver
	if(global->EventId == akmsm_EVENT_Disconnect || global->EventId == akmsm_EVENT_Disassociate)
	{
		if(global->EventId == akmsm_EVENT_Disconnect)
			lib1x_message(MESS_DBG_KEY_MANAGE, "lib1x_akmsm_Disconnect(2) :Request from 802.1x daemon\n");
		else if(global->EventId == akmsm_EVENT_Disassociate)
			lib1x_message(MESS_DBG_KEY_MANAGE, "lib1x_akmsm_Disconnect(2) :Request from wlan driver\n");


		if(global->auth->AccountingEnabled)
		{
			if(global->theAuthenticator->acct_sm->status == acctsm_Start)
			{
				if(global->EventId == akmsm_EVENT_Disconnect)
				{
					//Query tx/rx packet and byte counts
					lib1x_control_QuerySTA(auth_pae->global);
				}
				 else if(global->EventId == akmsm_EVENT_Disassociate)
				{
				 	//tx/rx packet bytes count has already been recorded
				}

				lib1x_acctsm_request(global, acctsm_Acct_Stop, lib1x_acct_maperr_wlan2acct(global->akm_sm->ErrorRsn));

			}
		}

		if(global->EventId == akmsm_EVENT_Disconnect)
		{

#ifdef	_ABOCOM
			lib1x_abocom(global->theAuthenticator->supp_addr, ABOCOM_DEL_STA);

#else
			lib1x_control_STADisconnect(global, global->akm_sm->ErrorRsn);
#endif
		}else if(global->EventId == akmsm_EVENT_Disassociate)
		{

#ifdef _ABOCOM
			//For Abocom Expiration mechanism
			//After Driver indicating an expiration with disassociate event,
			//MAC-Link is disconnected, Daemon-session is kept

			lib1x_abocom(global->theAuthenticator->supp_addr, ABOCOM_DEL_STA);
			lib1x_message(MESS_DBG_KEY_MANAGE, "Disassociate(expire) happend, keep session");
			return 1;
#endif

#ifdef RTL_RADIUS_2SET
	if(global->auth->use_2nd_rad==1)
		return 1;
#endif
		}

	}
#if 0	//sc_yang move to later for delete supplicant
	if(global->EventId == akmsm_EVENT_Disconnect ||
	   global->EventId == akmsm_EVENT_Disassociate ||
		global->EventId ==  akmsm_EVENT_DeauthenticationRequest)
	{

//		PRINT_MAC_ADDRESS(global->theAuthenticator->supp_addr, "global->theAuthenticator->supp_addr");

		lib1x_del_supp(global->auth, global->theAuthenticator->supp_addr);

//2003-09-07
#if 0

		//---- Update variable in RTLAuthenticator ----
		global->auth->Supp[global->index]->isEnable = FALSE;
		lib1x_message(MESS_DBG_KEY_MANAGE, "Delete STA from Table");

		global->akm_sm->CurrentReplayCounter.field.HighPart = 0;
		global->akm_sm->CurrentReplayCounter.field.LowPart = 0;

		lib1x_message(MESS_DBG_KEY_MANAGE, "Number of Supplicant = %d\n",global->auth->NumOfSupplicant);
//		global->auth->NumOfSupplicant --;

		//0818
		//lib1x_get_NumSTA(global->auth);
#endif
	}
#endif



	memset(akm_sm->PMK, 0, sizeof(akm_sm->PMK));

	global->auth->gk_sm->GInitAKeys = FALSE;
	akm_sm->PInitAKeys = FALSE;
	akm_sm->IntegrityFailed = FALSE;

	if(global->auth->RSNVariable.isSupportUnicastCipher && global->RSNVariable.isSuppSupportUnicastCipher)
		akm_sm->Pair = TRUE;
		if(global->EventId != akmsm_EVENT_Disassociate) //sc_yang
			lib1x_control_RemovePTK(global, DOT11_KeyType_Pairwise);

	//---- Initialize 802.1x related variable ----

	if(global->AuthKeyMethod == DOT11_AuthKeyType_RSN ||
		global->AuthKeyMethod == DOT11_AuthKeyType_RSNPSK 
#ifdef CONFIG_IEEE80211R
		|| global->AuthKeyMethod == DOT11_AuthKeyType_FT
#else
		|| global->AuthKeyMethod == DOT11_AuthKeyType_NonRSN802dot1x
#endif
		)
		if(global->EventId != akmsm_EVENT_Disassociate)	//sc_yang
			lib1x_control_SetPORT(global, DOT11_PortStatus_Unauthorized);


	//sc_yang :delete supplicant last
	if(global->EventId == akmsm_EVENT_Disconnect ||
	   global->EventId == akmsm_EVENT_Disassociate ||
		global->EventId ==  akmsm_EVENT_DeauthenticationRequest)
	{

//		PRINT_MAC_ADDRESS(global->theAuthenticator->supp_addr, "global->theAuthenticator->supp_addr");

#if !defined(CONFIG_RTL8186_TR) && !defined(CONFIG_RTL865X_SC) && !defined(CONFIG_RTL865X_AC) && !defined(CONFIG_RTL865X_KLD)
		lib1x_del_supp(global->auth, global->theAuthenticator->supp_addr);
#endif

//2003-09-07
#if 0

		//---- Update variable in RTLAuthenticator ----
		global->auth->Supp[global->index]->isEnable = FALSE;
		lib1x_message(MESS_DBG_KEY_MANAGE, "Delete STA from Table");

		global->akm_sm->CurrentReplayCounter.field.HighPart = 0;
		global->akm_sm->CurrentReplayCounter.field.LowPart = 0;

		lib1x_message(MESS_DBG_KEY_MANAGE, "Number of Supplicant = %d\n",global->auth->NumOfSupplicant);
//		global->auth->NumOfSupplicant --;

		//0818
		//lib1x_get_NumSTA(global->auth);
#endif
	}
	akm_sm->state = akmsm_INITIALIZE;
	global->EventId = akmsm_EVENT_NoEvent;
	global->akm_sm->SessionTimeoutCounter = 0;
	global->akm_sm->IdleTimeoutCounter = 0;
	global->akm_sm->InterimTimeoutCounter = LIB1X_DEFAULT_IDLE_TIMEOUT;

	return retVal;
}


int lib1x_akmsm_EAPOLKeyRecvd( Global_Params * global)
{
	APKeyManage_SM	*	akm_sm = global->akm_sm;
	int retVal = 0, result = -1;

	global->EapolKeyMsgRecvd.Octet = global->EAPOLMsgRecvd.Octet + ETHER_HDRLEN + LIB1X_EAPOL_HDRLEN;


	//----IEEE 802.11-03/156r2. MIC report : (1)MIC bit (2)error bit (3) request bit
	//----Check if it is MIC failure report. If it is, indicate to driver
	if(Message_KeyMIC(global->EapolKeyMsgRecvd) && Message_Error(global->EapolKeyMsgRecvd)
		&& Message_Request(global->EapolKeyMsgRecvd))
	{
		lib1x_control_IndicateMICFail(global->auth, global->theAuthenticator->supp_addr);
		return retVal;
	}


	if(Message_KeyType(global->EapolKeyMsgRecvd) == type_Pairwise)
	{

		switch(akm_sm->state)
		{
		case akmsm_PTKSTART:

			//---- Receive 2nd message and send third
			if(!(result = lib1x_akmsm_ProcessEAPOL_proc(global)))
			{
				lib1x_message(MESS_DBG_KEY_MANAGE, "lib1x_akmsm_EAPOLKeyRecvd:Receive EAPOL-KEY and check [successfully] in akmsm_PTKSTART state");
				akm_sm->state = akmsm_PTKINITNEGOTIATING;
				global->akm_sm->bWaitForPacket = FALSE;
				lib1x_akmsm_SendEAPOL_proc(global);
			}else
			{
				lib1x_message(MESS_DBG_KEY_MANAGE, "lib1x_akmsm_EAPOLKeyRecvd:Receive EAPOL-KEY and check [Fail] in akmsm_PTKSTART state");
			}

			break;

		case akmsm_PTKINITNEGOTIATING:

			//---- Receive 4th message ----
			if(!(result = lib1x_akmsm_ProcessEAPOL_proc(global)))
			{
				lib1x_message(MESS_DBG_KEY_MANAGE, "lib1x_akmsm_EAPOLKeyRecvd:Receive EAPOL-KEY and check [successfully] in akmsm_PTKINITNEGOTIATING state");
				//if( akm_sm->Pair)
				lib1x_control_SetPTK(global);
				lib1x_control_SetPORT(global, DOT11_PortStatus_Authorized);				
				global->auth->gk_sm->GInitAKeys = TRUE;
				akm_sm->PInitAKeys = TRUE;
				akm_sm->state = akmsm_PTKINITDONE;
				global->akm_sm->bWaitForPacket = FALSE;

				//lib1x_akmsm_UpdateGK_proc() calls lib1x_akmsm_SendEAPOL_proc for 2-way
				//if group key sent is needed, send msg 1 of 2-way handshake
#ifdef RTL_WPA2
				if ( global->RSNVariable.WPA2Enabled ) {
					lib1x_message(MESS_DBG_KEY_MANAGE, "lib1x_akmsm_EAPOLKeyRecvd : Receive 4 message of 4-way handshake and check successfully\n");
					global->akm_sm->bWaitForPacket = FALSE;
					//------------------------------------------------------
					// Only when the group state machine is in the state of
					// (1) The first STA Connected,
					// (2) UPDATE GK to all station
					// does the GKeyDoneStations needed to be decreased
					//------------------------------------------------------

					if(global->auth->gk_sm->GKeyDoneStations > 0)
						global->auth->gk_sm->GKeyDoneStations--;

					lib1x_message(MESS_DBG_KEY_MANAGE, " global->auth->gk_sm->GKeyDoneStations=%d\n",  global->auth->gk_sm->GKeyDoneStations);
					//Avaya akm_sm->TimeoutCtr = 0;
					//To Do : set port secure to driver
					global->portSecure = TRUE;
					//akm_sm->state = akmsm_PTKINITDONE;
					akm_sm->gstate = gkmsm_REKEYESTABLISHED;


					if( global->auth->gk_sm->GKeyDoneStations == 0 && !global->auth->gk_sm->GkeyReady)
					{
						if(lib1x_control_SetGTK(global) == 0)//success
						{
							global->auth->gk_sm->GkeyReady = TRUE;
							global->auth->gk_sm->GResetCounter = TRUE;
						}
					#ifdef CONFIG_IEEE80211W
						if(lib1x_control_SetIGTK(global) != 0)//Fail
						{
							printf("Auth fail to install IGTK !\n");	
							global->auth->gk_sm->GkeyReady = FALSE;
							global->auth->gk_sm->GResetCounter = FALSE;
						}					
					#endif
					}

					if (global->RSNVariable.PMKCached) {
						global->portStatus = pst_Authorized;
						global->RSNVariable.PMKCached = FALSE;  // reset
					}
#ifdef CONFIG_IEEE80211W
					lib1x_control_SetPMF(global);
#endif					
#ifdef CONFIG_IEEE80211R
					if (akm_sm->isFT)
						lib1x_control_ft_trigger_event(global->auth, global->theAuthenticator->supp_addr, DOT11_EVENT_FT_IMD_ASSOC_IND);
#endif					
#ifdef HS2_SUPPORT
					if(global->isTriggerWNM) {
						lib1x_control_WNM_NOTIFY(global,global->remed_URL, global->serverMethod);
						global->isTriggerWNM = 0;
					}
					if(global->isTriggerWNM_DEAUTH) {
						lib1x_control_WNM_DEAUTH_REQ(global, global->WNMDEAUTH_reason, global->WNMDEAUTH_reAuthDelay, global->WNMDEAUTH_URL);			
						global->isTriggerWNM_DEAUTH = 0;
					}
					
					if(global->isTriggerSessionInfo_URL) {
						HS2DEBUG("\n");
						lib1x_control_SessionInfo_URL(global, global->SWT, global->SessionInfo_URL);
						global->isTriggerSessionInfo_URL = 0;
					}
					
#endif
					printf("WPA2: 4-way handshake done\n");
					//printf("-----------------------------------------------------------------------------\n\n\n\n\n\n\n");

				} else {
#ifdef FOURWAY_DEBUG
					//printf("\nkenny: global->RSNVariable.WPA2Enabled == FALSE\n");
#endif
#endif /* RTL_WPA2 */
				if(!Message_Secure(global->EapolKeyMsgRecvd))
					lib1x_akmsm_UpdateGK_proc(global->auth);
#ifdef RTL_WPA2
				}
#endif /* RTL_WPA2 */
			}else
			{
				if(result == ERROR_RECV_4WAY_MESSAGE2_AGAIN )
					lib1x_message(MESS_DBG_KEY_MANAGE, "lib1x_akmsm_EAPOLKeyRecvd:Receive EAPOL-KEY 4way  message 2 again ");
				else
				lib1x_message(MESS_DBG_KEY_MANAGE, "lib1x_akmsm_EAPOLKeyRecvd:Receive EAPOL-KEY and check [Fail] in akmsm_PTKINITNEGOTIATING state");
			}
			break;

		case akmsm_PTKINITDONE:

			if(!(result = lib1x_akmsm_ProcessEAPOL_proc(global)))
			{
				lib1x_message(MESS_DBG_KEY_MANAGE, "lib1x_akmsm_EAPOLKeyRecvd:Receive EAPOL-KEY and check [successfully] in akmsm_PTKINITDONE state");
				global->akm_sm->bWaitForPacket = FALSE;
				//------------------------------------------------
				// Supplicant request to init 4 or 2 way handshake
				//------------------------------------------------
				if(Message_Request(global->EapolKeyMsgRecvd))
				{
					akm_sm->state = akmsm_PTKSTART;
					 if(Message_KeyType(global->EapolKeyMsgRecvd) == type_Pairwise)
					 {
						if(Message_Error(global->EapolKeyMsgRecvd))
							lib1x_akmsm_IntegrityFailure(global);
					 }else if(Message_KeyType(global->EapolKeyMsgRecvd) == type_Group)
					 {
						if(Message_Error(global->EapolKeyMsgRecvd))
						{
							//auth change group key, initilate 4-way handshake with supp and execute
							//the Group key handshake to all Supplicants
							global->auth->gk_sm->GKeyFailure = TRUE;
							lib1x_akmsm_IntegrityFailure(global);
						}
					 }

					 //---- Start 4-way handshake ----
					 lib1x_akmsm_SendEAPOL_proc(global);
				}
#ifdef RTL_WPA2_PREAUTH
				lib1x_message(MESS_DBG_KEY_MANAGE, "%s() in akmsm_PTKINITDONE state. Call lib1x_akmsm_UpdateGK_proc()\n", __FUNCTION__);
#endif
				//---- Execute Group Key state machine for each STA ----
				lib1x_akmsm_UpdateGK_proc(global->auth);
			}else
			{
				lib1x_message(MESS_DBG_KEY_MANAGE, "lib1x_akmsm_EAPOLKeyRecvd:Receive EAPOL-KEY and check [Fail] in akmsm_PTKINITDONE state");
				lib1x_message(MESS_ERROR_OK, KM_STRERR(result));
			}

			break;
		default:
			break;

		}//switch

	}else if(Message_KeyType(global->EapolKeyMsgRecvd) == type_Group)
	{
		lib1x_message(MESS_DBG_KEY_MANAGE, "global->auth->gk_sm->GKeyDoneStations=%d\n", global->auth->gk_sm->GKeyDoneStations);

		//---- Receive 2nd message of 2-way handshake ----
		if(!(result = lib1x_akmsm_ProcessEAPOL_proc(global)))
		//Avaya
		//if(1)
		{

			lib1x_message(MESS_DBG_KEY_MANAGE, "lib1x_akmsm_EAPOLKeyRecvd : Receive 2 message of 2-way handshake and check successfully\n");
			global->akm_sm->bWaitForPacket = FALSE;
			//------------------------------------------------------
			// Only when the group state machine is in the state of
			// (1) The first STA Connected,
			// (2) UPDATE GK to all station
			// does the GKeyDoneStations needed to be decreased
			//------------------------------------------------------

			if(global->auth->gk_sm->GKeyDoneStations > 0)
				global->auth->gk_sm->GKeyDoneStations--;

			lib1x_message(MESS_DBG_KEY_MANAGE, " global->auth->gk_sm->GKeyDoneStations=%d\n",  global->auth->gk_sm->GKeyDoneStations);
			//Avaya akm_sm->TimeoutCtr = 0;
			//To Do : set port secure to driver
			global->portSecure = TRUE;
			akm_sm->state = akmsm_PTKINITDONE;
			akm_sm->gstate = gkmsm_REKEYESTABLISHED;


			if( global->auth->gk_sm->GKeyDoneStations == 0 && !global->auth->gk_sm->GkeyReady)
	                {
                	        if(lib1x_control_SetGTK(global) == 0)//success
				{

					printf("2-way Handshake is finished\n");
                        		global->auth->gk_sm->GkeyReady = TRUE;
					global->auth->gk_sm->GResetCounter = TRUE;
				}
	                }

		}else
		{
			lib1x_message(MESS_DBG_KEY_MANAGE, " Receive bad group key handshake");
             		lib1x_message(MESS_ERROR_OK, KM_STRERR(result));
                }
	}

	// Deal with the erro when processing EAPOL-Key that may result in Disconnect
	// (1) RSN_MIC_failure (2)RSN_diff_info_element
	if(result)
	{
                lib1x_message(MESS_ERROR_OK, KM_STRERR(result));
		//To Do : do we need to send disassociate right now?

	}
	return retVal;
}

int lib1x_akmsm_IntegrityFailure( Global_Params * global)
{

	APKeyManage_SM	*	akm_sm = global->akm_sm;
	int retVal = TRUE;

	akm_sm->IntegrityFailed = FALSE;
	if(global->auth->gk_sm->GKeyFailure)
	{
		global->auth->gk_sm->GTKRekey = TRUE;
		global->auth->gk_sm->GKeyFailure = FALSE;
	}
	//waitupto60;

	INCOctet32_INTEGER(&global->auth->Counter);
	SetNonce(global->akm_sm->ANonce, global->auth->Counter);

	INCOctet32_INTEGER(&global->auth->Counter);
	SetNonce(global->akm_sm->ANonce, global->auth->Counter);

	return retVal;

}

//---------------------------------------------------------------------------------
// lib1x_akmsm_trans : Check if key manage state machine execution is required
//	according to whether there is external event or change of internal variable
// Retrun : TRUE is required/ FALSE is non-required
//---------------------------------------------------------------------------------
int lib1x_akmsm_trans(Global_Params * global)
{
        int     retVal = 0;


	if(global->AuthKeyMethod != DOT11_AuthKeyType_RSN &&
	   global->AuthKeyMethod != DOT11_AuthKeyType_RSNPSK 
#ifdef CONFIG_IEEE80211R
	   && global->AuthKeyMethod != DOT11_AuthKeyType_FT
#endif
#ifdef CONFIG_IEEE80211W	   
	   && global->AuthKeyMethod != DOT11_AuthKeyType_802_1X_SHA256
#endif
	   )
		return retVal;

	switch(global->akm_sm->state)
	{
        case akmsm_AUTHENTICATION2:
		// Check global->theAuthenticator->rxRespId because when eapStart is set,
		// the pae state machine enters into CONNECTING state which do not clear
		// authSuccess to FALSE
			switch(global->AuthKeyMethod)
			{
				case DOT11_AuthKeyType_RSN:
#ifdef CONFIG_IEEE80211W	   					
				case DOT11_AuthKeyType_802_1X_SHA256:	
#endif
					if(global->authSuccess && global->theAuthenticator->rxRespId ){
						global->EventId = akmsm_EVENT_AuthenticationSuccess;
						retVal = TRUE;
					}
					break;
				case DOT11_AuthKeyType_RSNPSK:
					global->EventId = akmsm_EVENT_AuthenticationSuccess;
					retVal = TRUE;
					break;
#ifdef CONFIG_IEEE80211R
				case DOT11_AuthKeyType_FT:	
					if(global->authSuccess && global->theAuthenticator->rxRespId ){		
						global->EventId = akmsm_EVENT_AuthenticationSuccess;			
						retVal = TRUE;		
					}
					break;
#else
				case DOT11_AuthKeyType_NonRSN802dot1x:
					break;
#endif
				default:
					printf("%s: Unknown AuthKeyMethod\n", __FUNCTION__);
					break;
			}

                break;
		case akmsm_PTKSTART:
		case akmsm_PTKINITNEGOTIATING:
			switch(global->AuthKeyMethod)
			{
				case DOT11_AuthKeyType_RSN:
				case DOT11_AuthKeyType_RSNPSK:
#ifdef CONFIG_IEEE80211R		
				case DOT11_AuthKeyType_FT:
#endif
					if(global->akm_sm->TimeoutEvt)
					{

						global->EventId = akmsm_EVENT_TimeOut;
						retVal = TRUE;
					}
					break;
#ifndef CONFIG_IEEE80211R
				case DOT11_AuthKeyType_NonRSN802dot1x:
					break;
#endif
			}
		default:
			break;
	        /*
	        case akmsm_PTKSTART:
	        case akmsm_PTKINITNEGOTIATING:
	        case akmsm_PTKINITDONE:
	                global->EventId = akmsm_EVENT_EAPOLKeyRecvd;
	                retVal = TRUE;
	        */
	}

	switch(global->akm_sm->gstate)
	{
		case gkmsm_REKEYNEGOTIATING:
			switch(global->AuthKeyMethod)
			{
				case DOT11_AuthKeyType_RSN:
				case DOT11_AuthKeyType_RSNPSK:
#ifdef CONFIG_IEEE80211R		
				case DOT11_AuthKeyType_FT:
#endif
					if(global->akm_sm->TimeoutEvt)
					{
						global->EventId = akmsm_EVENT_TimeOut;
						retVal = TRUE;
					}
					break;
#ifndef CONFIG_IEEE80211R
				case DOT11_AuthKeyType_NonRSN802dot1x:
					break;
#endif
			}//switch(global->AuthKeyMethod)
			break;
	}
//	PRINT_GLOBAL_AKM_SM_STATE(global);
//	PRINT_GLOBAL_AKM_SM_GSTATE(global);

	//ToDo : Check out the order of this event
	if( global->akm_sm->eapStart == TRUE)
	{
		if(global->akm_sm->state == akmsm_AUTHENTICATION2)
		//The first time to do authentication
		{
			lib1x_message(MESS_DBG_KEY_MANAGE, "Judge eapStart in state akmsm_AUTHENTICATION2\n");
			global->EventId = akmsm_EVENT_AuthenticationRequest;
		}
		else
		//Reauthentication because of supplicant sending eapol satrt
		{
			lib1x_message(MESS_DBG_KEY_MANAGE, "Judge eapStart not in state akmsm_AUTHENTICATION2\n");
			global->EventId = akmsm_EVENT_ReAuthenticationRequest;
		}
		global->akm_sm->eapStart = FALSE;
		retVal = TRUE;

	}

	//Besides checking eapol start message sending from client, we should also check
	//if Supplicnat send 802.11 authentication management
	//To prevent from client not sending eapol start.
	if( global->akm_sm->AuthenticationRequest == TRUE)
    {
		lib1x_message(MESS_DBG_KEY_MANAGE,"global->akm_sm->AuthenticationRequest == TRUE");
		global->EventId = akmsm_EVENT_AuthenticationRequest;
		global->akm_sm->AuthenticationRequest = FALSE;
		retVal = TRUE;
    }
    else if(global->akm_sm->DeauthenticationRequest == TRUE)
    {
		global->EventId = akmsm_EVENT_DeauthenticationRequest;
		global->akm_sm->DeauthenticationRequest = FALSE;
		retVal = TRUE;
    }
    else if(global->akm_sm->Disconnect == TRUE )
    {
#ifdef RTL_WPA2_PREAUTH
	//printf("%s-%d: global->EventId = akmsm_EVENT_Disconnect\n", __FUNCTION__,__LINE__);
#endif
		global->EventId = akmsm_EVENT_Disconnect;
		global->akm_sm->Disconnect = FALSE;
		retVal = TRUE;
    }

	if(retVal)
		lib1x_akmsm_dump(global);

//	PRINT_GLOBAL_EVENTID(global);

	return retVal;
}



void lib1x_akmsm_dump(Global_Params * global)
{
#ifdef ALLOW_DBG_KEY_MANAGE

	lib1x_message(MESS_DBG_KEY_MANAGE, "-------Dump Supplicant [%d] Key Manage State Machine-----------", global->index);
	lib1x_PrintAddr(global->theAuthenticator->supp_addr);
        switch(global->akm_sm->state)
        {
        case akmsm_AUTHENTICATION2 :    lib1x_message(MESS_DBG_KEY_MANAGE, "state :AUTHENTICATION2"); break;
        case akmsm_PTKSTART:            lib1x_message(MESS_DBG_KEY_MANAGE, "state :PTKSTAR"); break;
        case akmsm_PTKINITNEGOTIATING:  lib1x_message(MESS_DBG_KEY_MANAGE, "state :PTKINITNEGOTIATING"); break;
        case akmsm_PTKINITDONE:         lib1x_message(MESS_DBG_KEY_MANAGE, "state :PTKINITDONE"); break;
        }

	switch(global->akm_sm->gstate)
	{
	case gkmsm_REKEYNEGOTIATING:	lib1x_message(MESS_DBG_KEY_MANAGE, "gstate :REKEYNEGOTIATING"); break;
	case gkmsm_REKEYESTABLISHED:	lib1x_message(MESS_DBG_KEY_MANAGE, "gstate :REKEYESTABLISHED"); break;
	case gkmsm_KEYERROR:		lib1x_message(MESS_DBG_KEY_MANAGE, "gstate :KEYERROR"); break;

	}

	switch( global->EventId )
	{

        case    akmsm_EVENT_NoEvent:
		lib1x_message(MESS_DBG_KEY_MANAGE, "event :NoEvent");
		break;
        case    akmsm_EVENT_AssociationRequest:
		lib1x_message(MESS_DBG_KEY_MANAGE, "event :AssociationRequest");
		break;
        case    akmsm_EVENT_ReAssociationRequest:
		lib1x_message(MESS_DBG_KEY_MANAGE, "event :ReAssociationRequest");
		break;
        case    akmsm_EVENT_AuthenticationRequest:
		lib1x_message(MESS_DBG_KEY_MANAGE, "event :AuthenticationRequest");
		break;
        case    akmsm_EVENT_ReAuthenticationRequest:
		lib1x_message(MESS_DBG_KEY_MANAGE, "event :ReAuthenticationRequest");
		break;
        case    akmsm_EVENT_AuthenticationSuccess:
		lib1x_message(MESS_DBG_KEY_MANAGE, "event :AuthenticationSuccess");
		break;
        case    akmsm_EVENT_Disconnect:
		lib1x_message(MESS_DBG_KEY_MANAGE, "event :Disconnect");
		break;
        case    akmsm_EVENT_DeauthenticationRequest:
		lib1x_message(MESS_DBG_KEY_MANAGE, "event :DeauthenticationRequest");
		break;
        case    akmsm_EVENT_Init:
		lib1x_message(MESS_DBG_KEY_MANAGE, "event :Init");
		break;
        case    akmsm_EVENT_IntegrityFailure:
		lib1x_message(MESS_DBG_KEY_MANAGE, "event :IntegrityFailure");
		break;
        case    akmsm_EVENT_EAPOLKeyRecvd:
		lib1x_message(MESS_DBG_KEY_MANAGE, "event :EAPOLKeyRecvd");
		break;
        }//switch


	switch(global->AuthKeyMethod)
	{
		case 	DOT11_AuthKeyType_RSN:
		lib1x_message(MESS_DBG_KEY_MANAGE, "AuthKeyMethod :RSN");
		break;
        case 	DOT11_AuthKeyType_RSNPSK:
		lib1x_message(MESS_DBG_KEY_MANAGE, "AuthKeyMethod :RSNPSK");
		break;
#ifdef CONFIG_IEEE80211R
		case	DOT11_AuthKeyType_FT:
		lib1x_message(MESS_DBG_KEY_MANAGE, "AuthKeyMethod :FT");
		break;
#else
		case	DOT11_AuthKeyType_NonRSN802dot1x:
		lib1x_message(MESS_DBG_KEY_MANAGE, "AuthKeyMethod :NonRSN802dot1x");
		break;
#endif
		case    DOT11_AuthKeyType_PRERSN:
		lib1x_message(MESS_DBG_KEY_MANAGE, "AuthKeyMethod :PRERSN");
		break;

	}
	lib1x_message(MESS_DBG_KEY_MANAGE, "AuthenticationRequest : %d", global->akm_sm->AuthenticationRequest);
	lib1x_message(MESS_DBG_KEY_MANAGE, "ReAuthenticationRequest : %d", global->akm_sm->ReAuthenticationRequest);
	lib1x_message(MESS_DBG_KEY_MANAGE, "DeauthenticationRequest : %d", global->akm_sm->DeauthenticationRequest);
	lib1x_message(MESS_DBG_KEY_MANAGE, "Disconnect : %d", global->akm_sm->Disconnect);
	lib1x_message(MESS_DBG_KEY_MANAGE, "Init : %d", global->akm_sm->Init);
	//lib1x_message(MESS_DBG_KEY_MANAGE, " : %d", global->akm_sm->);
	//lib1x_message(MESS_DBG_KEY_MANAGE, " : %d", global->akm_sm->);
	//lib1x_message(MESS_DBG_KEY_MANAGE, " : %d", global->akm_sm->);
	//lib1x_message(MESS_DBG_KEY_MANAGE, " : %d", global->akm_sm->);
	//lib1x_message(MESS_DBG_KEY_MANAGE, " : %d", global->akm_sm->);




	lib1x_message(MESS_DBG_KEY_MANAGE, "------------------------------------------------------------\n",
global->index);
#endif
}


void lib1x_akmsm_execute( Global_Params * global)
{

        Auth_Pae                * auth_pae;
        struct lib1x_eapol 	* eapol;
        struct lib1x_ethernet 	* eth_hdr;

	BOOLEAN	bFlag = FALSE;
#ifdef CONFIG_RTL_ETH_802DOT1X_SUPPORT
	unsigned char dot1x_group_mac[ETHER_HDRLEN] = {0x01,0x80,0xC2,0x00,0x00,0x03};
#endif

	auth_pae = global->theAuthenticator;

//	PRINT_GLOBAL_EVENTID(global);


	switch( global->EventId )
	{


	case	akmsm_EVENT_AuthenticationRequest:
	case	akmsm_EVENT_ReAuthenticationRequest:
		lib1x_akmsm_AuthenticationRequest( global );
		break;

        case    akmsm_EVENT_AuthenticationSuccess:
                lib1x_akmsm_AuthenticationSuccess(global);
                break;

	case	akmsm_EVENT_Disconnect:
	case	akmsm_EVENT_DeauthenticationRequest:
	case    akmsm_EVENT_Init:
	case    akmsm_EVENT_Disassociate:
		lib1x_akmsm_Disconnect( global );
		break;

	case	akmsm_EVENT_IntegrityFailure:
		lib1x_akmsm_IntegrityFailure( global );
		break;
	case	akmsm_EVENT_EAPOLKeyRecvd:
		bFlag = TRUE;
		lib1x_message(MESS_DBG_KEY_MANAGE, "lib1x_akmsm_execute: Receive EAPOL Key\n");
		lib1x_akmsm_EAPOLKeyRecvd( global );
		break;

	case    akmsm_EVENT_TimeOut:
		auth_pae->sendhandshakeready = TRUE;
		//ToDo : Update Replay Counter ( or not )
		break;
	}//switch

	global->EventId = akmsm_EVENT_NoEvent;


	if( auth_pae->sendhandshakeready )
        {
		lib1x_message(MESS_DBG_KEY_MANAGE, "lib1x_akmsm_execute: Has EAPOL Key Packet sent to supplicant\n");
		lib1x_PrintAddr(global->theAuthenticator->supp_addr);
                //ethernet and eapol header initialization
                eth_hdr = ( struct lib1x_ethernet * )global->EAPOLMsgSend.Octet;
#ifdef CONFIG_RTL_ETH_802DOT1X_SUPPORT
			if(auth_pae->global->auth->currentRole == role_eth && (!auth_pae->global->auth->ethDot1xEapolUnicastEnabled))
				memcpy ( eth_hdr->ether_dhost, dot1x_group_mac, ETHER_HDRLEN);
			else
#endif
			{
  	          memcpy ( eth_hdr->ether_dhost , auth_pae->supp_addr, ETHER_ADDRLEN );
  	        }
	        memcpy ( eth_hdr->ether_shost , auth_pae->global->TxRx->oursupp_addr, ETHER_ADDRLEN );
			eth_hdr->ether_type = htons(LIB1X_ETHER_EAPOL_TYPE);

                eapol = ( struct lib1x_eapol * )  ( global->EAPOLMsgSend.Octet +  ETHER_HDRLEN )  ;
                eapol->protocol_version = LIB1X_EAPOL_VER;
                eapol->packet_type =  LIB1X_EAPOL_KEY;

                eapol->packet_body_length = htons(global->EapolKeyMsgSend.Length);

		//lib1x_hexdump2(MESS_DBG_KEY_MANAGE, "lib1x_akmsm_execute", auth_pae->sendBuffer, global->EAPOLMsgSend.Length, "Send EAPOL-KEY Message");

		if(global->akm_sm->IfCalcMIC)
		{
			CalcMIC(global->EAPOLMsgSend, global->KeyDescriptorVer, global->akm_sm->PTK, PTK_LEN_EAPOLMIC);
			global->akm_sm->IfCalcMIC = FALSE;
		}
		global->akm_sm->TimeoutEvt = 0;
                //global->akm_sm->TimeoutCtr = 0;


		//lib1x_hexdump2(MESS_DBG_KEY_MANAGE, "lib1x_akmsm_execute", auth_pae->sendBuffer, global->EAPOLMsgSend.Length, "AP Send EAPOL-KEY Message");

		lib1x_nal_send( auth_pae->global->TxRx->network_supp, auth_pae->sendBuffer, global->EAPOLMsgSend.Length );
                auth_pae->sendhandshakeready = FALSE;
		global->akm_sm->bWaitForPacket = TRUE;
        }
}
