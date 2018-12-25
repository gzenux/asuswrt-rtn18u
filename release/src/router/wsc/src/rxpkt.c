/*
 *  Receive packet handler for WiFi Simple-Config
 *
 *	Copyright (C)2006, Realtek Semiconductor Corp. All rights reserved.
 *
 *	$Id: rxpkt.c,v 1.33 2010/08/09 09:27:13 pluswang Exp $
 */

/*================================================================*/
/* Include Files */
#ifdef __ECOS
#include <network.h>
//#include "apmib.h"
#include "mini_upnp_global.h"
//#include "sys_utility.h"
#endif

#include "wsc.h"

// WPS2DOTX
extern unsigned char WSC_VENDOR_OUI[3];
/*================================================================*/

#ifdef	AUTO_LOCK_DOWN
#ifdef ALD_BRUTEFORCE_ATTACK_MITIGATION
void	record_and_check_AuthFail(CTX_Tp pCtx )
{
	if(pCtx->auto_lock_down)
		return;

	RX_DEBUG("\n");
	pCtx->ADL_pin_attack_count++;	
	RX_DEBUG("	consecutive attempts times [%d]\n",pCtx->ADL_pin_attack_count);		

//	if(pCtx->ADL_pin_attack_count >= ALD_INDEFINITE_TH){
	if(pCtx->ADL_pin_attack_count >= pCtx->MaxPinFailThresHold){
		pCtx->auto_lock_down = 0x7FFFFFFF;
		InOut_auto_lock_down(pCtx,1);			
	}
}

#else

void	record_and_check_AuthFail(CTX_Tp pCtx )
{
	int i;
#ifndef __ECOS	
	struct sysinfo info ;
#endif
	unsigned int time_offset ;	
	/*if now rdy lock stats , need not check and record*/ 
	if(pCtx->auto_lock_down)
		return;

	RX_DEBUG("\n");
	
	if(pCtx->ald_virgin == 0){
		
		for(i=0 ; i<AUTH_FAIL_TIMES ;i++){
			pCtx->ald_timestamp[i] = 0 ;
		}
		
		pCtx->ald_h = 0; // head
		pCtx->ald_t = 0; // tail		 

#ifdef __ECOS
		time(&pCtx->ald_timestamp[pCtx->ald_t]);
#else
		sysinfo(&info);			
		pCtx->ald_timestamp[pCtx->ald_t] = (unsigned long)info.uptime;
#endif

		pCtx->ald_t++; 
		pCtx->ald_virgin = 1;
		return ;
	}

#ifdef __ECOS
	time(&pCtx->ald_timestamp[pCtx->ald_t]);
#else
	sysinfo(&info);			
	pCtx->ald_timestamp[pCtx->ald_t] = (unsigned long)info.uptime;
#endif

	if(( ( pCtx->ald_h - pCtx->ald_t) == 1 ) || 
		( (pCtx->ald_t - pCtx->ald_h) == ( AUTH_FAIL_TIMES - 1)) )
	{


		time_offset = difftime(pCtx->ald_timestamp[pCtx->ald_t],pCtx->ald_timestamp[pCtx->ald_h]);
		
		if(time_offset < AUTH_FAIL_TIME_TH){
			pCtx->auto_lock_down = AUTO_LOCKED_DOWN_TIME ; 			

		
			InOut_auto_lock_down(pCtx,1);
			pCtx->ald_virgin = 0;			
			return ; 
		}
	}

	/*circle array; when array is full ,
	  last-timeStamp replace first-timeStamp*/ 	
	pCtx->ald_t++;
	pCtx->ald_t %= AUTH_FAIL_TIMES;
	if(pCtx->ald_t == pCtx->ald_h){
		pCtx->ald_h++;
		pCtx->ald_h %= AUTH_FAIL_TIMES;
	}
	
}
#endif
#endif
/* Implementation Routines */
#if 0
int isUpnpSubscribed(CTX_Tp pCtx)
{
	int i;

	for (i=0; i<WSC_MAX_STA_NUM; i++) {
		if (pCtx->sta[i].used && 
			(pCtx->sta[i].used & IS_UPNP_CONTROL_POINT))
			return 1;
	}
	//DEBUG_PRINT("No UPnP external registrar subscribes!\n");
	return 0;
}
#endif

unsigned char *check_tag(CTX_Tp pCtx, unsigned char *pMsg, int msg_len, int tag, int check_len, 
	char *name, int type, int *o_len)
{
	unsigned char *pData;
	int tag_len;

	pData = search_tag(pMsg, tag, msg_len, &tag_len);
	if (pData == NULL) {
		DEBUG_ERR("\n can't find %s tag!\n", name);
		return NULL;
	}
	if (check_len) {
		if (check_len & NOT_GREATER_THAN_MASK) {
			if (tag_len > (check_len&~NOT_GREATER_THAN_MASK)) {
				DEBUG_ERR("Invalid tag length of %s [%d]!\n", name, tag_len);
				return NULL;
			}			
		}
		else { // equal
			if (tag_len != check_len) {
				DEBUG_ERR("Invalid tag length of %s [%d]!\n", name, tag_len);
				return NULL;
			}
		}		
	}	
#ifdef DEBUG
	if (pCtx->debug2) {
		unsigned short usVal;
		unsigned long ulVal;
		char tmp[512];
		
		if (type == TYPE_BYTE) {
			printf("%s: 0x%x\n", name, pData[0]);
		}
		else if (type == TYPE_WORD) {
			memcpy(&usVal, pData, 2);
			printf("%s: 0x%x\n", name, ntohs(usVal));			
		}
		else if (type == TYPE_DWORD) {
			memcpy(&ulVal, pData, 4);
			printf("%s: 0x%x\n", name, (int)ntohl(ulVal));			
		}
		else if (type == TYPE_STR) {
			memcpy(tmp, pData, tag_len);
			if (tmp[tag_len-1] != 0)
				tmp[tag_len] = '\0';
			printf("%s: %s\n", name, tmp);
		}
		else // TYPE_BIN
		{
			wsc_debug_out(name, pData, tag_len);
		}
	}
#endif
	*o_len = tag_len;
	return pData;
}

static int check_authenticator_attr(STA_CTX_Tp pSta, unsigned char *pMsg, int msg_len)
{
	unsigned char *pData;
	int tag_len, size;
	unsigned char tmp[100];

	pData = search_tag(pMsg, TAG_AUTHENTICATOR, msg_len, &tag_len);
	if (pData == NULL) {
		DEBUG_ERR("Can't find TAG_AUTHENTICATOR!\n");
		return -1;
	}
	if (tag_len != BYTE_LEN_64B) {
		DEBUG_ERR("Invalid length of Authenticator [%d]!\n", tag_len);
		return -1;
	}
	
#ifdef DEBUG
//	if (pCtx->debug) 
//		wsc_debug_out("Authenticator", pData, tag_len);	
#endif
	size = (int)(((unsigned long)pData) - ((unsigned long)pMsg) - 4);
	append(&pSta->last_tx_msg_buffer[pSta->last_tx_msg_size], pMsg, size);
	hmac_sha256((unsigned char*)pSta->last_tx_msg_buffer, pSta->last_tx_msg_size+size, pSta->auth_key, BYTE_LEN_256B, tmp, &size);
	if (memcmp(tmp, pData, BYTE_LEN_64B)) {
		DEBUG_ERR("hmac value of Authenticator mismatched!\n");
		report_WPS_STATUS(HMAC_FAIL);
		return -1;
	}
	return 0;
}

static int decrypt_attr(CTX_Tp pCtx, STA_CTX_Tp pSta, unsigned char *pMsg, int msg_len, unsigned char *out)
{
	unsigned char *pData;
	int tag_len, size;
#ifdef DEBUG
	char tmp[200];
#endif

	pData = search_tag(pMsg, TAG_ENCRYPT_SETTINGS, msg_len, &tag_len);
	if (pData == NULL) {
		DEBUG_ERR("Can't find TAG_ENCRYPT_SETTINGS\n");
		return -1;
	}

	if (tag_len < (BYTE_LEN_128B+4+NONCE_LEN+4+BYTE_LEN_64B)) {
		DEBUG_ERR("Invalid length (of EncryptedSettings [%d]!\n", tag_len);
		return -1;		
	}

#ifdef DEBUG
//	if (pCtx->debug)
//		wsc_debug_out("IV", pData, BYTE_LEN_128B);
#endif

	Decrypt_aes_128_cbc(pSta->key_wrap_key, pData, out, (unsigned int *)(&size), &pData[BYTE_LEN_128B], tag_len-BYTE_LEN_128B);

#ifdef DEBUG
	if (pCtx->debug2) {
		sprintf(tmp, "Plaintext of EncryptedSettings: len=%d", size);
		wsc_debug_out(tmp, out, size);		
	}
#endif

	pData = check_tag(pCtx, out, size, TAG_KEY_WRAP_AUTH, BYTE_LEN_64B, "KeyWrapAuthenticator", TYPE_BIN, &tag_len);
	if (pData == NULL)
		return -1;

#ifdef DEBUG
	if (pCtx->debug2){ 
		wsc_debug_out("KeyWrapAuthenticator", pData, tag_len);	
	}
#endif
	size = size-BYTE_LEN_64B-4;
#if 0
	hmac_sha256(out, size, pSta->auth_key, BYTE_LEN_256B, tmp, &tag_len);
	if (memcmp(&out[size-BYTE_LEN_64B], tmp, BYTE_LEN_64B)) {
		DEBUG_ERR("hmac value of KWA mismatched!\n");
		return -1;		
	}
#endif	
	return (size);
}

static int GetNetworkProfile(const CTX_Tp pCtx, const unsigned char *pMsg, const int msg_len)
{
	unsigned char *pData, *pVal, *pMsg_start=NULL;
	int size, tag_len;
	unsigned short sVal;
	unsigned char key_index=0, num_of_assigned_wep_key=0;
//	unsigned char pre_wep_key_format=0;
//    unsigned char  pre_wep_key_len=0;
	unsigned char wep_key_tmp[MAX_WEP_KEY_LEN+1];
	int assigned_wep_len=0;
		
	int network_key_count=0;
		
	pData = (unsigned char *)pMsg;
	size = msg_len;

#ifdef WPS2DOTX
	//wsc_debug_out("GetNetworkProfile:",pMsg,msg_len);

	// TAG_NETWORKKEY_SHAREABLE
	pVal = check_tag(pCtx, pData, size, TAG_NETWORKKEY_SHAREABLE,1 , "network key shareable", TYPE_BYTE, &tag_len);
	if (pVal){
			RX_DEBUG("network key shareable set to %d\n",pVal[0]);
	}
	
#endif

	RX_DEBUG("Profile from Registrar:\n");	
	/*get SSID*/
	pVal = check_tag(pCtx, pData, size, TAG_SSID, 
				NOT_GREATER_THAN_MASK|WSC_MAX_SSID_LEN, "SSID", TYPE_STR, &tag_len);
	if (pVal == NULL || tag_len < 1) {
		DEBUG_ERR("Invalid SSID!\n");
		return -1;
	}
	memcpy((unsigned char*)pCtx->assigned_ssid, pVal, tag_len);
	pCtx->assigned_ssid[tag_len] = '\0';
	if(strncmp(pCtx->negoApSSID, pCtx->assigned_ssid, tag_len)) {
		RX_DEBUG("SSID: %s != negoApSSID:%s\n",pCtx->assigned_ssid,pCtx->negoApSSID);	
	}
	_DEBUG_PRINT("	SSID:\"%s\"\n",pCtx->assigned_ssid);

	
	/*get member mac addr*/
	if (check_tag(pCtx, pData, size, TAG_MAC_ADDRESS, NOT_GREATER_THAN_MASK|ETHER_ADDRLEN, 
		"MAC Address", TYPE_BIN, &tag_len) == NULL)
		return CONFIG_ERR_CANNOT_CONNECT_TO_REG;
	
	/*get Auth Type*/	
	pVal = check_tag(pCtx, pData, size, TAG_AUTH_TYPE, 2, "AuthenticationType", TYPE_WORD, &tag_len);
	if (pVal == NULL)
		return -1;
	memcpy(&sVal, pVal, 2);	
	pCtx->assigned_auth_type = ntohs(sVal);	

	if (!(pCtx->assigned_auth_type & pCtx->auth_type_flags)) {
#ifdef WPS2DOTX		
		if(pCtx->is_ap==1 && pCtx->assigned_auth_type == WSC_AUTH_WPAPSK){

		}else
#endif		
		{
			DEBUG_ERR("Invalid assigned_auth_type = %d; not supported\n", pCtx->assigned_auth_type);
			return CONFIG_ERR_CANNOT_CONNECT_TO_REG;
		}
	}


	/*get Encrypt Type*/	
	pVal = check_tag(pCtx, pData, size, TAG_ENCRYPT_TYPE, 2, "EncryptionType", TYPE_WORD, &tag_len);
	if (pVal == NULL)
		return -1;
	memcpy(&sVal, pVal, 2);	
	pCtx->assigned_encrypt_type = ntohs(sVal);

	RX_DEBUG("Auth :0x%02X \n",pCtx->assigned_auth_type);
	RX_DEBUG("Encrypt :%d \n",pCtx->assigned_encrypt_type);	
	//show_auth_encry_help();

	if (!(pCtx->assigned_encrypt_type & pCtx->encrypt_type_flags)) {

#ifdef WPS2DOTX		
		if(pCtx->is_ap==1 && pCtx->assigned_encrypt_type == WSC_ENCRYPT_TKIP){

		}else
#endif
		{
			RX_DEBUG("Invalid assigned_encrypt_type = %d; not supported\n", pCtx->assigned_encrypt_type);
			return CONFIG_ERR_CANNOT_CONNECT_TO_REG;
		}
	}

#ifdef WPS2DOTX
	/* habdle When 1.0 ER want to set WPA only or TKIP only security mode 
	let AP setting to Mixed mode; test plan 4.1.12 ; win7*/ 
	if (pCtx->assigned_auth_type == WSC_AUTH_WPAPSK ||
		 pCtx->assigned_encrypt_type == WSC_ENCRYPT_TKIP)
	{
		pCtx->assigned_auth_type = WSC_AUTH_WPA2PSKMIXED;
		pCtx->assigned_encrypt_type = WSC_ENCRYPT_TKIPAES;
		RX_DEBUG("	under WPS2.0 ;when ER config us (WPA only or TKIP only) then tune to Mixed mode!!!\n");

	}	

	/* habdle When 1.0 ER want to set WEP security mode ;return NACK ; test plan 4.1.10*/ 
	if(	pCtx->assigned_encrypt_type == WSC_ENCRYPT_WEP ){
		RX_DEBUG("	under WPS2.0 ; reject it when Encrpty = WEP !!\n");
		if (pCtx->pin_timeout>3) {
			pCtx->pin_timeout=3;
		}
		if (pCtx->pb_timeout>3) {
			pCtx->pb_timeout=3;
		}
		
		return CONFIG_ERR_CANNOT_CONNECT_TO_REG;
	}
#endif


	// Add WPA2-TKIP support for WLK v1.2, david+2008-05-27
	#if 0
	//#ifdef CONFIG_RTL8186_KB
		if (pCtx->assigned_auth_type == WSC_AUTH_WPA2PSK && 
			pCtx->assigned_encrypt_type == WSC_ENCRYPT_TKIP)
			return CONFIG_ERR_CANNOT_CONNECT_TO_REG;
	#endif

	if ((pCtx->assigned_auth_type == WSC_AUTH_OPEN && pCtx->assigned_encrypt_type > WSC_ENCRYPT_WEP) ||
		((pCtx->assigned_auth_type != WSC_AUTH_OPEN && pCtx->assigned_auth_type != WSC_AUTH_SHARED)
			&& pCtx->assigned_encrypt_type <= WSC_ENCRYPT_WEP)) {
		DEBUG_ERR("Invalid assigned_auth_type = %d and assigned_encrypt_type = %d\n", pCtx->assigned_auth_type, pCtx->assigned_encrypt_type);
		return CONFIG_ERR_CANNOT_CONNECT_TO_REG;
	}




	
	while (1) {	
		//currently only support multiple keys in wep mode
		if (pCtx->assigned_encrypt_type == WSC_ENCRYPT_WEP) {

#ifdef WPS2DOTX
			RX_DEBUG("WEP under WPS2.0 is be deprecated\n");
			break;
#endif

			pMsg_start = pData;
			pVal = check_tag(pCtx, pData, size, TAG_NETWORK_KEY_INDEX, 1, "NetworkKeyIndex", TYPE_BYTE, &tag_len);
			
			if (pVal == NULL) {
				if (!num_of_assigned_wep_key) { //no TAG_NETWORK_KEY_INDEX tag; default to 1
					key_index = 1;
				}
				else if (num_of_assigned_wep_key == 1) {

					if(strlen(pCtx->assigned_wep_key_1)){
						strcpy(pCtx->assigned_wep_key_2, pCtx->assigned_wep_key_1);
						strcpy(pCtx->assigned_wep_key_3, pCtx->assigned_wep_key_1);
						strcpy(pCtx->assigned_wep_key_4, pCtx->assigned_wep_key_1);

					}else if(strlen(pCtx->assigned_wep_key_2)){
						strcpy(pCtx->assigned_wep_key_1, pCtx->assigned_wep_key_2);
						strcpy(pCtx->assigned_wep_key_3, pCtx->assigned_wep_key_2);
						strcpy(pCtx->assigned_wep_key_4, pCtx->assigned_wep_key_2);

					}
					else if(strlen(pCtx->assigned_wep_key_3)){
						strcpy(pCtx->assigned_wep_key_1, pCtx->assigned_wep_key_3);
						strcpy(pCtx->assigned_wep_key_2, pCtx->assigned_wep_key_3);
						strcpy(pCtx->assigned_wep_key_4, pCtx->assigned_wep_key_3);

					}
					else if(strlen(pCtx->assigned_wep_key_4)){
						strcpy(pCtx->assigned_wep_key_1, pCtx->assigned_wep_key_4);
						strcpy(pCtx->assigned_wep_key_2, pCtx->assigned_wep_key_4);
						strcpy(pCtx->assigned_wep_key_3, pCtx->assigned_wep_key_4);

					}					
					DEBUG_PRINT("pCtx->assigned_wep_key_len = %d\n", pCtx->assigned_wep_key_len);
					DEBUG_PRINT("pCtx->assigned_wep_key_format = %d\n", pCtx->assigned_wep_key_format);
					break;
				}
				else if (num_of_assigned_wep_key == 2 || num_of_assigned_wep_key == 3) {

#ifdef DEBUG					
					RX_DEBUG("only 2/3 WEP key \n");

					if(!strlen(pCtx->assigned_wep_key_1))
						RX_DEBUG("WEP key 1=NULL\n");

					if(!strlen(pCtx->assigned_wep_key_2))
						RX_DEBUG("WEP key 2=NULL\n");

					if(!strlen(pCtx->assigned_wep_key_3))
						RX_DEBUG("WEP key 3=NULL\n");

					if(!strlen(pCtx->assigned_wep_key_4))
						RX_DEBUG("WEP key 4=NULL\n");
#endif

					break;
				}
				else if (num_of_assigned_wep_key == 4) {
					break;
				}
				else {
					DEBUG_ERR("Multiple wep keys not supported if number of provided keys is %d\n", num_of_assigned_wep_key);
					return CONFIG_ERR_CANNOT_CONNECT_TO_REG;
				}
			}
			else{
				key_index = *pVal;
				RX_DEBUG("get key index =%d \n",key_index);
			}

			num_of_assigned_wep_key++;
			if (num_of_assigned_wep_key > 4) {
				DEBUG_ERR("Multiple wep keys not supported if number of provided keys is greater than %d\n", num_of_assigned_wep_key);
				return CONFIG_ERR_CANNOT_CONNECT_TO_REG;
			}
		}

		pVal = check_tag(pCtx, pData, size, TAG_NETWORK_KEY, 
			NOT_GREATER_THAN_MASK|MAX_NETWORK_KEY_LEN, "NetworkKey", TYPE_BIN, &tag_len);

		/*2011-0519 found at Gemtek,when ER is Intel and encrypt is NONE intel will not include this attri*/		
		if (pCtx->assigned_encrypt_type != WSC_ENCRYPT_NONE) {		
			if (pVal == NULL){

				/*under wep key case maybe has multikey , so when WEP has >=1 key then just */ 
				if(network_key_count==0){	
					RX_DEBUG("!!!network key == NULL \n");					
					return -1;
				}
			}else{
				network_key_count++;			
				RX_DEBUG("got network key\n");
			}
		}

		if (pCtx->assigned_encrypt_type == WSC_ENCRYPT_NONE) {
			memset((unsigned char*)pCtx->assigned_network_key, 0, MAX_NETWORK_KEY_LEN+1);
#if 0
			memcpy(pCtx->assigned_network_key, pVal, tag_len);
			pCtx->assigned_network_key[tag_len] = '\0';
			if (strlen(pCtx->assigned_network_key) > 0) {
				DEBUG_ERR("Error! auth type = %d, encrypt type = %d, network key = %s\n",
				pCtx->assigned_auth_type, pCtx->assigned_encrypt_type, pCtx->assigned_network_key);
					return -1;
			}
#endif
			break;
		}
		else if (pCtx->assigned_encrypt_type == WSC_ENCRYPT_WEP) {

#ifdef WPS2DOTX
			RX_DEBUG("don't accept WEP under WPS2.0!!\n");
			break;
#endif
			
			#if 0
			if (key_index != num_of_assigned_wep_key) {
				DEBUG_ERR("Not supported: invalid wep key index = %d; num_of_assigned_wep_key = %d!\n", key_index, num_of_assigned_wep_key);
				return CONFIG_ERR_CANNOT_CONNECT_TO_REG;
			}
			#endif
			
			if (check_wep_key_format(pVal, tag_len, &pCtx->assigned_wep_key_format, &pCtx->assigned_wep_key_len, wep_key_tmp, &assigned_wep_len) < 0)
				return CONFIG_ERR_CANNOT_CONNECT_TO_REG;
			else {
				#if 0				
				if (key_index > 1 && (pre_wep_key_format != pCtx->assigned_wep_key_format ||
					pre_wep_key_len != pCtx->assigned_wep_key_len)) {
					DEBUG_ERR("Format or length mismatch among assigned keys\n");
					return CONFIG_ERR_CANNOT_CONNECT_TO_REG;
				}
				#endif				
				//pre_wep_key_format = pCtx->assigned_wep_key_format;
				//pre_wep_key_len = pCtx->assigned_wep_key_len;
			}

			RX_DEBUG("KEY = \"%s\" , index = %d\n",wep_key_tmp , key_index);	

			#ifdef DEBUG
			if(pCtx->assigned_wep_key_format==KEY_ASCII){
				RX_DEBUG("KEY format = ASCII\n");	
			}else if(pCtx->assigned_wep_key_format==KEY_HEX){
				RX_DEBUG("KEY format = HEX\n");	
			}
			#endif				
				
			switch (key_index)
			{
				case 1:
					memcpy(pCtx->assigned_wep_key_1, wep_key_tmp, assigned_wep_len);
					pCtx->assigned_wep_key_1[assigned_wep_len] = '\0';
					break;
				case 2:
					memcpy(pCtx->assigned_wep_key_2, wep_key_tmp, assigned_wep_len);
					pCtx->assigned_wep_key_2[assigned_wep_len] = '\0';
					break;
				case 3:
					memcpy(pCtx->assigned_wep_key_3, wep_key_tmp, assigned_wep_len);
					pCtx->assigned_wep_key_3[assigned_wep_len] = '\0';
					break;
				case 4:
					memcpy(pCtx->assigned_wep_key_4, wep_key_tmp, assigned_wep_len);
					pCtx->assigned_wep_key_4[assigned_wep_len] = '\0';
					break;
				default: //should not go in here; just in case
					DEBUG_ERR("Error: invalid wep key index = %d!\n", key_index);
					return CONFIG_ERR_CANNOT_CONNECT_TO_REG;
			}

			pData = pVal + tag_len;
			size -= (pData - pMsg_start);
			RX_DEBUG("wep go next\n");
		}
		else {
			memcpy((unsigned char*)pCtx->assigned_network_key, pVal, tag_len);
			pCtx->assigned_network_key[tag_len] = '\0';
			if (strlen(pCtx->assigned_network_key) < 8) {
				RX_DEBUG("Error! network key too short [%s] (<8) \n", pCtx->assigned_network_key);
					return -1;
			}

			break; //not support multiple keys yet
		}
	}

	_DEBUG_PRINT("	key :\"%s\"\n",pCtx->assigned_network_key);	
		
	if (pCtx->assigned_encrypt_type == WSC_ENCRYPT_WEP) {
		if ((pVal = check_tag(pCtx, pData, size, TAG_WEP_TRANSMIT_KEY, 1, "WEPTransmitKey", TYPE_BYTE, &tag_len)) == NULL){
			//no TAG_NETWORK_KEY_INDEX tag; default to 1			
			//pCtx->assigned_wep_transmit_key = 1;
			pCtx->assigned_wep_transmit_key = key_index;
		}else{
			pCtx->assigned_wep_transmit_key = *pVal;
		}
		
		RX_DEBUG("wep_transmit_key = %d\n", pCtx->assigned_wep_transmit_key);
	}
	
	return 0;
}

static int GetNetworkProfile2(const CTX_Tp pCtx, const unsigned char *pMsg, const int msg_len)
{
	unsigned char *pData, *pVal, *pMsg_start=NULL;
	int size, tag_len;
	unsigned short sVal;
	unsigned char key_index=0, num_of_assigned_wep_key=0;
	//unsigned char pre_wep_key_format=0;
    //    unsigned char  pre_wep_key_len=0;
	unsigned char wep_key_tmp[MAX_WEP_KEY_LEN+1];
	int assigned_wep_len=0;
		
	int network_key_count=0;
		
	pData = (unsigned char *)pMsg;
	size = msg_len;

#ifdef WPS2DOTX

	// TAG_NETWORKKEY_SHAREABLE
	pVal = check_tag(pCtx, pData, size, TAG_NETWORKKEY_SHAREABLE,1 , "network key shareable", TYPE_BYTE, &tag_len);
	if (pVal){
			RX_DEBUG("network key shareable set to %d\n",pVal[0]);
	}
	
#endif

	RX_DEBUG("Profile from Registrar:\n");	
	/*get SSID*/
	pVal = check_tag(pCtx, pData, size, TAG_SSID, 
				NOT_GREATER_THAN_MASK|WSC_MAX_SSID_LEN, "SSID", TYPE_STR, &tag_len);
	if (pVal == NULL || tag_len < 1) {
		DEBUG_ERR("Invalid SSID!\n");
		return -1;
	}
	memcpy(pCtx->assigned_ssid_2, pVal, tag_len);
	pCtx->assigned_ssid_2[tag_len] = '\0';
	
	if(strncmp(pCtx->negoApSSID,pCtx->assigned_ssid_2,tag_len)){	
		RX_DEBUG("SSID: %s != negoApSSID:%s\n",pCtx->assigned_ssid_2,pCtx->negoApSSID);	
	}
	_DEBUG_PRINT("	SSID:\"%s\"\n",pCtx->assigned_ssid_2);

	
	/*get member mac addr*/
	if (check_tag(pCtx, pData, size, TAG_MAC_ADDRESS, NOT_GREATER_THAN_MASK|ETHER_ADDRLEN, 
		"MAC Address", TYPE_BIN, &tag_len) == NULL)
		return CONFIG_ERR_CANNOT_CONNECT_TO_REG;
	
	/*get Auth Type*/	
	pVal = check_tag(pCtx, pData, size, TAG_AUTH_TYPE, 2, "AuthenticationType", TYPE_WORD, &tag_len);
	if (pVal == NULL)
		return -1;
	memcpy(&sVal, pVal, 2);	
	pCtx->assigned_auth_type_2 = ntohs(sVal);	

	if (!(pCtx->assigned_auth_type_2 & pCtx->auth_type_flags)) {
#ifdef WPS2DOTX		
		if(pCtx->is_ap==1 && pCtx->assigned_auth_type_2 == WSC_AUTH_WPAPSK){

		}else
#endif		
		{
			DEBUG_ERR("Invalid assigned_auth_type = %d; not supported\n", pCtx->assigned_auth_type_2);
			return CONFIG_ERR_CANNOT_CONNECT_TO_REG;
		}
	}


	/*get Encrypt Type*/	
	pVal = check_tag(pCtx, pData, size, TAG_ENCRYPT_TYPE, 2, "EncryptionType", TYPE_WORD, &tag_len);
	if (pVal == NULL)
		return -1;
	memcpy(&sVal, pVal, 2);	
	pCtx->assigned_encrypt_type_2 = ntohs(sVal);

	RX_DEBUG("Auth[0x%02X]\n",pCtx->assigned_auth_type_2);
	RX_DEBUG("Encrypt[%d]\n",pCtx->assigned_encrypt_type_2);	
	//show_auth_encry_help();

	if (!(pCtx->assigned_encrypt_type_2 & pCtx->encrypt_type_flags)) {

#ifdef WPS2DOTX		
		if(pCtx->is_ap==1 && pCtx->assigned_encrypt_type_2 == WSC_ENCRYPT_TKIP){

		}else
#endif
		{
			RX_DEBUG("Invalid assigned_encrypt_type = %d; not supported\n", pCtx->assigned_encrypt_type_2);
			return CONFIG_ERR_CANNOT_CONNECT_TO_REG;
		}
	}

#ifdef WPS2DOTX
	/* habdle When 1.0 ER want to set WPA only or TKIP only security mode 
	let AP setting to Mixed mode; test plan 4.1.12 ; win7*/ 
	if (pCtx->assigned_auth_type_2 == WSC_AUTH_WPAPSK ||
		 pCtx->assigned_encrypt_type_2 == WSC_ENCRYPT_TKIP)
	{
		pCtx->assigned_auth_type_2 = WSC_AUTH_WPA2PSKMIXED;
		pCtx->assigned_encrypt_type_2 = WSC_ENCRYPT_TKIPAES;
		RX_DEBUG("	under WPS2.0 ;when ER config us (WPA only or TKIP only) then tune to Mixed mode!!!\n");

	}	

	/* habdle When 1.0 ER want to set WEP security mode ;return NACK ; test plan 4.1.10*/ 
	if(	pCtx->assigned_encrypt_type_2 == WSC_ENCRYPT_WEP ){
		RX_DEBUG("	under WPS2.0 ; reject it when Encrpty = WEP !!\n");
		if (pCtx->pin_timeout>3) {
			pCtx->pin_timeout=3;
		}
		if (pCtx->pb_timeout>3) {
			pCtx->pb_timeout=3;
		}
		
		return CONFIG_ERR_CANNOT_CONNECT_TO_REG;
	}
#endif


	// Add WPA2-TKIP support for WLK v1.2, david+2008-05-27
	#if 0
	//#ifdef CONFIG_RTL8186_KB
		if (pCtx->assigned_auth_type == WSC_AUTH_WPA2PSK && 
			pCtx->assigned_encrypt_type == WSC_ENCRYPT_TKIP)
			return CONFIG_ERR_CANNOT_CONNECT_TO_REG;
	#endif

	if ((pCtx->assigned_auth_type_2 == WSC_AUTH_OPEN && pCtx->assigned_encrypt_type_2 > WSC_ENCRYPT_WEP) ||
		((pCtx->assigned_auth_type_2 != WSC_AUTH_OPEN && pCtx->assigned_auth_type_2 != WSC_AUTH_SHARED)
			&& pCtx->assigned_encrypt_type_2 <= WSC_ENCRYPT_WEP)) {
		DEBUG_ERR("Invalid assigned_auth_type = %d and assigned_encrypt_type = %d\n", pCtx->assigned_auth_type_2, pCtx->assigned_encrypt_type_2);
		return CONFIG_ERR_CANNOT_CONNECT_TO_REG;
	}




	
	while (1) {	
		//currently only support multiple keys in wep mode
		if (pCtx->assigned_encrypt_type_2 == WSC_ENCRYPT_WEP) {

#ifdef WPS2DOTX
			RX_DEBUG("WEP under WPS2.0 is be deprecated\n");
			break;
#endif

			pMsg_start = pData;
			pVal = check_tag(pCtx, pData, size, TAG_NETWORK_KEY_INDEX, 1, "NetworkKeyIndex", TYPE_BYTE, &tag_len);
			
			if (pVal == NULL) {
				if (!num_of_assigned_wep_key) { //no TAG_NETWORK_KEY_INDEX tag; default to 1
					key_index = 1;
				}
				else if (num_of_assigned_wep_key == 1) {

					if(strlen(pCtx->assigned_wep_key_1_2)){
						strcpy(pCtx->assigned_wep_key_2_2, pCtx->assigned_wep_key_1_2);
						strcpy(pCtx->assigned_wep_key_3_2, pCtx->assigned_wep_key_1_2);
						strcpy(pCtx->assigned_wep_key_4_2, pCtx->assigned_wep_key_1_2);

					}else if(strlen(pCtx->assigned_wep_key_2_2)){
						strcpy(pCtx->assigned_wep_key_1_2, pCtx->assigned_wep_key_2_2);
						strcpy(pCtx->assigned_wep_key_3_2, pCtx->assigned_wep_key_2_2);
						strcpy(pCtx->assigned_wep_key_4_2, pCtx->assigned_wep_key_2_2);

					}
					else if(strlen(pCtx->assigned_wep_key_3_2)){
						strcpy(pCtx->assigned_wep_key_1_2, pCtx->assigned_wep_key_3_2);
						strcpy(pCtx->assigned_wep_key_2_2, pCtx->assigned_wep_key_3_2);
						strcpy(pCtx->assigned_wep_key_4_2, pCtx->assigned_wep_key_3_2);

					}
					else if(strlen(pCtx->assigned_wep_key_4_2)){
						strcpy(pCtx->assigned_wep_key_1_2, pCtx->assigned_wep_key_4_2);
						strcpy(pCtx->assigned_wep_key_2_2, pCtx->assigned_wep_key_4_2);
						strcpy(pCtx->assigned_wep_key_3_2, pCtx->assigned_wep_key_4_2);

					}					
					DEBUG_PRINT("pCtx->assigned_wep_key_len = %d\n", pCtx->assigned_wep_key_len_2);
					DEBUG_PRINT("pCtx->assigned_wep_key_format = %d\n", pCtx->assigned_wep_key_format_2);
					break;
				}
				else if (num_of_assigned_wep_key == 2 || num_of_assigned_wep_key == 3) {

#ifdef DEBUG					
					RX_DEBUG("only 2/3 WEP key \n");

					if(!strlen(pCtx->assigned_wep_key_1_2))
						RX_DEBUG("WEP key 1=NULL\n");

					if(!strlen(pCtx->assigned_wep_key_2_2))
						RX_DEBUG("WEP key 2=NULL\n");

					if(!strlen(pCtx->assigned_wep_key_3_2))
						RX_DEBUG("WEP key 3=NULL\n");

					if(!strlen(pCtx->assigned_wep_key_4_2))
						RX_DEBUG("WEP key 4=NULL\n");
#endif

					break;
				}
				else if (num_of_assigned_wep_key == 4) {
					break;
				}
				else {
					DEBUG_ERR("Multiple wep keys not supported if number of provided keys is %d\n", num_of_assigned_wep_key);
					return CONFIG_ERR_CANNOT_CONNECT_TO_REG;
				}
			}
			else{
				key_index = *pVal;
				RX_DEBUG("get key index =%d \n",key_index);
			}

			num_of_assigned_wep_key++;
			if (num_of_assigned_wep_key > 4) {
				DEBUG_ERR("Multiple wep keys not supported if number of provided keys is greater than %d\n", num_of_assigned_wep_key);
				return CONFIG_ERR_CANNOT_CONNECT_TO_REG;
			}
		}

		pVal = check_tag(pCtx, pData, size, TAG_NETWORK_KEY, 
			NOT_GREATER_THAN_MASK|MAX_NETWORK_KEY_LEN, "NetworkKey", TYPE_BIN, &tag_len);

		/*2011-0519 found at Gemtek,when ER is Intel and encrypt is NONE intel will not include this attri*/		
		if (pCtx->assigned_encrypt_type_2 != WSC_ENCRYPT_NONE) {		
			if (pVal == NULL){

				/*under wep key case maybe has multikey , so when WEP has >=1 key then just */ 
				if(network_key_count==0){	
					RX_DEBUG("!!!network key == NULL \n");					
					return -1;
				}
			}else{
				network_key_count++;			
				RX_DEBUG("got network key\n");
			}
		}

		if (pCtx->assigned_encrypt_type_2 == WSC_ENCRYPT_NONE) {
			memset((unsigned char *)pCtx->assigned_network_key_2, 0, MAX_NETWORK_KEY_LEN+1);
#if 0
			memcpy((unsigned char *)pCtx->assigned_network_key, pVal, tag_len);
			pCtx->assigned_network_key[tag_len] = '\0';
			if (strlen(pCtx->assigned_network_key) > 0) {
				DEBUG_ERR("Error! auth type = %d, encrypt type = %d, network key = %s\n",
				pCtx->assigned_auth_type, pCtx->assigned_encrypt_type, pCtx->assigned_network_key);
					return -1;
			}
#endif
			break;
		}
		else if (pCtx->assigned_encrypt_type_2 == WSC_ENCRYPT_WEP) {

#ifdef WPS2DOTX
			RX_DEBUG("don't accept WEP under WPS2.0!!\n");
			break;
#endif
			
			#if 0
			if (key_index != num_of_assigned_wep_key) {
				DEBUG_ERR("Not supported: invalid wep key index = %d; num_of_assigned_wep_key = %d!\n", key_index, num_of_assigned_wep_key);
				return CONFIG_ERR_CANNOT_CONNECT_TO_REG;
			}
			#endif
			
			if (check_wep_key_format(pVal, tag_len, &pCtx->assigned_wep_key_format_2, &pCtx->assigned_wep_key_len_2, wep_key_tmp, &assigned_wep_len) < 0)
				return CONFIG_ERR_CANNOT_CONNECT_TO_REG;
			else {
				#if 0				
				if (key_index > 1 && (pre_wep_key_format != pCtx->assigned_wep_key_format ||
					pre_wep_key_len != pCtx->assigned_wep_key_len)) {
					DEBUG_ERR("Format or length mismatch among assigned keys\n");
					return CONFIG_ERR_CANNOT_CONNECT_TO_REG;
				}
				#endif				
				//pre_wep_key_format = pCtx->assigned_wep_key_format_2;
				//pre_wep_key_len = pCtx->assigned_wep_key_len_2;
			}

			RX_DEBUG("KEY = \"%s\" , index = %d\n",wep_key_tmp , key_index);	

			#ifdef DEBUG
			if(pCtx->assigned_wep_key_format_2==KEY_ASCII){
				RX_DEBUG("KEY format = ASCII\n");	
			}else if(pCtx->assigned_wep_key_format_2==KEY_HEX){
				RX_DEBUG("KEY format = HEX\n");	
			}
			#endif				
				
			switch (key_index)
			{
				case 1:
					memcpy((unsigned char *)pCtx->assigned_wep_key_1_2, wep_key_tmp, assigned_wep_len);
					pCtx->assigned_wep_key_1_2[assigned_wep_len] = '\0';
					break;
				case 2:
					memcpy((unsigned char *)pCtx->assigned_wep_key_2_2, wep_key_tmp, assigned_wep_len);
					pCtx->assigned_wep_key_2_2[assigned_wep_len] = '\0';
					break;
				case 3:
					memcpy((unsigned char *)pCtx->assigned_wep_key_3_2, wep_key_tmp, assigned_wep_len);
					pCtx->assigned_wep_key_3_2[assigned_wep_len] = '\0';
					break;
				case 4:
					memcpy((unsigned char *)pCtx->assigned_wep_key_4_2, wep_key_tmp, assigned_wep_len);
					pCtx->assigned_wep_key_4_2[assigned_wep_len] = '\0';
					break;
				default: //should not go in here; just in case
					DEBUG_ERR("Error: invalid wep key index = %d!\n", key_index);
					return CONFIG_ERR_CANNOT_CONNECT_TO_REG;
			}

			pData = pVal + tag_len;
			size -= (pData - pMsg_start);
			RX_DEBUG("wep go next\n");
		}
		else {
			memcpy(pCtx->assigned_network_key_2, pVal, tag_len);
			pCtx->assigned_network_key_2[tag_len] = '\0';
			if (strlen(pCtx->assigned_network_key_2) < 8) {
				RX_DEBUG("Error! network key too short [%s] (<8) \n", pCtx->assigned_network_key_2);
					return -1;
			}

			break; //not support multiple keys yet
		}
	}

	_DEBUG_PRINT("	key :\"%s\"\n",pCtx->assigned_network_key_2);	
		
	if (pCtx->assigned_encrypt_type_2 == WSC_ENCRYPT_WEP) {
		if ((pVal = check_tag(pCtx, pData, size, TAG_WEP_TRANSMIT_KEY, 1, "WEPTransmitKey", TYPE_BYTE, &tag_len)) == NULL){
			//no TAG_NETWORK_KEY_INDEX tag; default to 1			
			//pCtx->assigned_wep_transmit_key = 1;
			pCtx->assigned_wep_transmit_key_2 = key_index;
		}else{
			pCtx->assigned_wep_transmit_key_2 = *pVal;
		}
		
		RX_DEBUG("wep_transmit_key = %d\n", pCtx->assigned_wep_transmit_key_2);
	}
	
	return 0;
}

static int decrypt_setting(CTX_Tp pCtx, STA_CTX_Tp pSta, unsigned char *pMsg, int msg_len)
{
	unsigned char tmpbuf[1024], *pData;
	int size=0;	
	int ret=0;
	int tag_len;
#ifdef SUPPORT_HANDLE_MULTI_CREDENTIAL	
#ifdef FOR_DUAL_BAND
	unsigned char  *CRED1Ptr=NULL;	
	unsigned char  *CRED2Ptr=NULL;		
	int ret1 = 0;
	int ret2 = -1; // must be non zero
	int size1=0;
	int size2=0;
#endif    
	int cred_idx=1;
	int CredenOffset=0;
	unsigned char	*PreCred =NULL;
	int PreCredSize = 0 ;
	unsigned char	*HighestCredent =NULL;
	int HighestCredentSize=0;
	
	unsigned short AuthType=0;
	unsigned short EnptyType=0;	
	unsigned short AuthTypeHi=0;
	unsigned short EnptyTypeHi=0;	
	
	int needReplace=0;
#endif	

	size = decrypt_attr(pCtx, pSta, pMsg, msg_len, tmpbuf);
	if (size < 0)
		return -1;

	
#ifdef SUPPORT_HANDLE_MULTI_CREDENTIAL		
	//wsc_debug_out("attr data:",tmpbuf,size);
	_DEBUG_PRINT("\n");	
	while(1){		
		PreCred =
			search_tag(tmpbuf + CredenOffset, TAG_CREDENTIAL, size - CredenOffset, &PreCredSize);
		
		if(PreCred==NULL){
			//RX_DEBUG("end of Credential\n");	
			break;
		}else{

			//RX_DEBUG("This one Credential Size=%02x \n",PreCredSize);	
			//debug_out("content:",PreCred , PreCredSize);			

			/*for correctly handle multi-credentials,test plan 5.1.1 ;2012-03-09*/
			/* the two credentials have the same auth and encry ,just ssid different*/ 	

			/*get SSID Type*/	
			pData = check_tag(pCtx, PreCred, PreCredSize, TAG_SSID, 
						NOT_GREATER_THAN_MASK|WSC_MAX_SSID_LEN, "SSID", TYPE_STR, &tag_len);

#ifdef FOR_DUAL_BAND
			if (pCtx->both_band_credential){
				if(CRED1Ptr==NULL){
					CRED1Ptr = PreCred; // 1st cred
					size1 = PreCredSize;			
				}else{	
					CRED2Ptr = PreCred; // 2nd cred
					size2 = PreCredSize;							
			    }
			}
#endif
			if(pData){

				#if 0 //def DEBUG								
				_DEBUG_PRINT("	SSID:");				                
				int idx=0;
				for(;idx<tag_len;idx++)
					printf("%c",pData[idx]);
				
				printf("\n");
				#endif				

			}else{
				RX_DEBUG("SSID=NULL!\n");
				RX_DEBUG("chk next Credential......\n");				
				CredenOffset += (PreCredSize+4);				
				continue;				
			}
			
			/*SSID exist and target AP is under configed state*/
			if(!pCtx->is_ap && pData && pCtx->negoAPConfigStat == CONFIG_STATE_CONFIGURED){
#ifdef FOR_DUAL_BAND                
				if (pCtx->both_band_credential){					
					if(memcmp(pCtx->negoApSSID,pData,tag_len)==0){
						//RX_DEBUG("SSID matched!\n");
					}
				}else
#endif
                {
    				if(memcmp(pCtx->negoApSSID,pData,tag_len)==0){
    					//RX_DEBUG("SSID matched!\n");
    				}else{
    					//RX_DEBUG("SSID not matched!!\n");
    					//RX_DEBUG("chk next Credential......\n");
    					CredenOffset += (PreCredSize+4);
    					continue;
    				}
			    }
			}
			/*for correctly handle multi-credentials,test plan 5.1.1 ;2012-03-09*/

			/*get Encrypt Type*/	
			pData = check_tag(pCtx, PreCred, PreCredSize,
				TAG_ENCRYPT_TYPE, 2, "EncryptionType", TYPE_WORD, &tag_len);
			
			if (pData == NULL){
				RX_DEBUG("Encrypt=NULL\n");
				RX_DEBUG("chk next Credential......\n");
				CredenOffset += (PreCredSize+4);
				continue;				
			}
			
			memcpy(&EnptyType, pData, 2);	
			//EnptyType = ntohs(EnptyType);
			//_DEBUG_PRINT("	Encry[%d]\n",EnptyType);	
			//_DEBUG_PRINT("NONE=1,WEP=2,TKIP=4,AES=8,TKIPAES=12\n");
			
			if(EnptyTypeHi==0){
				EnptyTypeHi = EnptyType ;
				HighestCredent = PreCred;
				HighestCredentSize = PreCredSize;

			}else if(EnptyType>EnptyTypeHi){
				EnptyTypeHi = EnptyType ;
				needReplace = 1;								
				
				HighestCredent = PreCred;
				HighestCredentSize = PreCredSize;
				
				_DEBUG_PRINT("replace by encry\n");	
			}

			
			/*get Auth Type*/	
			pData = check_tag(pCtx, PreCred, PreCredSize,
				TAG_AUTH_TYPE, 2, "AuthenticationType", TYPE_WORD, &tag_len);
			
			if (pData == NULL){
				RX_DEBUG("Auth=NULL\n");
				RX_DEBUG("chk next Credential......\n");
				CredenOffset += (PreCredSize+4);
				continue;
			}
			memcpy(&AuthType, pData, 2);	
			//AuthType = ntohs(AuthType);
			//_DEBUG_PRINT("	Auth :0x%02X ; ",AuthType);
			//_DEBUG_PRINT("OPEN=1,WPAPSK=2,SHARED=4,WPA2PSK=0x20,MIXED=0x22\n");	
			
			if(needReplace ==1){
				AuthTypeHi = AuthType;   // replace
				
			}else{
				// first time
				if(AuthTypeHi==0){
					AuthTypeHi = AuthType;
				}
				
				if(EnptyType==EnptyTypeHi && AuthType>AuthTypeHi){
					AuthTypeHi = AuthType;	// replace										
					HighestCredent = PreCred;
					HighestCredentSize = PreCredSize;	
				}
			}			

			//RX_DEBUG("chk next Credential......\n");
			cred_idx++;
			CredenOffset += (PreCredSize+4);			
		}
	}

	if(HighestCredent){
		pData = HighestCredent;
		size = HighestCredentSize;
		
	}else{
		pData = tmpbuf;
	}
#else

	pData = search_tag(tmpbuf, TAG_CREDENTIAL, size, &tag_len);
	if (pData == NULL) 
		pData = tmpbuf;
	else
		size = tag_len;
	
#endif



#ifdef WPS2DOTX
	/*under WPS2.0 deprecated NetworkKetIndex*/
#else
	if (!pCtx->is_ap) {
		if (check_tag(pCtx, pData, size, TAG_NETWORK_INDEX, 1, "NetworkIndex", TYPE_BYTE, &tag_len) == NULL)
			return -1;
	}
#endif	
#ifdef FOR_DUAL_BAND
	if (pCtx->both_band_credential){
		ret1 = GetNetworkProfile(pCtx,CRED1Ptr,size1); //1st
		
        pCtx->assigned_valid_2 = 0;
		if(CRED2Ptr!=NULL){// There might not exists 2nd credential		
            pCtx->assigned_valid_2 = 1;
			ret2 = GetNetworkProfile2(pCtx,CRED2Ptr,size2); //2nd
		}
		if (ret1 ==0 || ret2 ==0) /* some one can use then OK*/
			ret = 0;
		else if(ret1)
			ret = ret1;
		else if(ret2)
			ret = ret2;
	}else
#endif	
	{
		ret = GetNetworkProfile(pCtx, pData, size);
	}
	return ret ;
}

static int check_nonce(unsigned char *pMsg, int msg_len, int tag, unsigned char *nonce, char *name)
{
	unsigned char *pData;
	int tag_len;

	pData = search_tag(pMsg, tag, msg_len, &tag_len);
	if (pData == NULL) {
		DEBUG_ERR("Can't find %s tag!\n", name);
		return -1;
	}
	if (tag_len != NONCE_LEN) {
		DEBUG_ERR("Invalid length of %s [%d]!\n", name, tag_len);
		return -1;
	}	
#ifdef DEBUG
//	if (pCtx->debug) 
//		wsc_debug_out("Enrollee Nonce", pData, tag_len);	
#endif

	if (memcmp(pData, nonce, NONCE_LEN)) {
		DEBUG_ERR("%s mismatch!\n", name);
		return -1;
	}
	return 0;
}

#ifdef SUPPORT_REGISTRAR
static int msgHandler_M7(CTX_Tp pCtx, STA_CTX_Tp pSta, unsigned char *pMsg, int msg_len)
{
	unsigned char *pData, *ptr;
	int tag_len, size, ret;
	unsigned char tmpbuf[1024];
	unsigned char tmp1[200], tmp2[200], tmp[200];

	DBFENTER;

	_DEBUG_PRINT("<< Receive EAP WSC_MSG M7(size=%d)\n\n",msg_len);

#ifdef CONFIG_RTL865X_KLD		
	report_WPS_STATUS(PROTOCOL_S7);

#else
    report_WPS_STATUS(RECV_M7);
#endif
	if (pSta->state != ST_WAIT_M7) {
		RX_DEBUG("Invalid state [%d]!\n", pSta->state);
		return 0;
	}
#ifdef MUL_PBC_DETECTTION
		if (pCtx->is_ap && IS_PBC_METHOD(pCtx->config_method) && 
			pSta->device_password_id == PASS_ID_PB &&
			!pCtx->disable_MulPBC_detection) {
			WSC_pthread_mutex_lock(&pCtx->PBCMutex);
			//DEBUG_PRINT("%s %d Lock PBC mutex\n", __FUNCTION__, __LINE__);
			search_active_pbc_sta(pCtx, pSta->addr, pSta->uuid, pMsg, msg_len);
			WSC_pthread_mutex_unlock(&pCtx->PBCMutex);
			//DEBUG_PRINT("%s %d unlock PBC mutex\n", __FUNCTION__, __LINE__);
		}
#endif
	

	if (check_authenticator_attr(pSta, pMsg, msg_len) < 0)
		return -1;

	if (check_nonce(pMsg, msg_len, TAG_REGISTRAR_NONCE,  pSta->nonce_registrar, "RegistarNonce") < 0)
		return -1;

	size = decrypt_attr(pCtx, pSta, pMsg, msg_len, tmpbuf);
	if (size < 0)
		return -1;

	pData = check_tag(pCtx, tmpbuf, size, TAG_E_SNONCE2, NONCE_LEN, "E-S2", TYPE_BIN, &tag_len);
	if (pData == NULL)
		return -1;
	memcpy(pSta->e_s2, pData, tag_len);

#if defined(WSC_CLIENT_MODE) && defined(SUPPORT_REGISTRAR)
	if (!pCtx->is_ap && pCtx->role == REGISTRAR && 
		pSta->config_state == CONFIG_STATE_CONFIGURED) 
	{

		RX_DEBUG("i am ER and AP is CONFIGURED\n\n");				
		ret = GetNetworkProfile(pCtx, tmpbuf, size);
		if (ret != 0) {
			memset((unsigned char*)pCtx->assigned_ssid, 0, ((unsigned long)pCtx->sta - (unsigned long)pCtx->assigned_ssid));
			return ret;
		}
		else {
			send_wsc_nack(pCtx, pSta, CONFIG_ERR_NO_ERR);
			pCtx->start = 0;
			pCtx->wait_reinit = write_param_to_flash(pCtx, 0);
			return 0;
		}
	}
#ifdef DEBUG	
	else{
		if (!pCtx->is_ap && pCtx->role == REGISTRAR && 
			pSta->config_state == CONFIG_STATE_UNCONFIGURED) 
				RX_DEBUG("i am ER and AP is UNCONFIGURED\n\n");			

	}
#endif	
#endif

	/*check E-Hash1*/ 
	hmac_sha256((unsigned char *)pCtx->peer_pin_code, strlen(pCtx->peer_pin_code)/2, pSta->auth_key, BYTE_LEN_256B, tmp, &size);
	memcpy(tmpbuf, pSta->e_s1, NONCE_LEN);
	ptr = append(&tmpbuf[BYTE_LEN_128B], tmp, BYTE_LEN_128B);

	BN_bn2bin(pSta->dh_enrollee->p, tmp1);
	ptr = append(ptr, tmp1, PUBLIC_KEY_LEN);

	BN_bn2bin(pSta->dh_registrar->pub_key, tmp2);
	ptr = append(ptr, tmp2, PUBLIC_KEY_LEN);
	
	size = (int)(((unsigned long)ptr) - ((unsigned long)tmpbuf));
	hmac_sha256(tmpbuf, size, pSta->auth_key, BYTE_LEN_256B, tmp, &size);	
	
	if (memcmp(tmp, pSta->e_h1, BYTE_LEN_256B)) 
	{

#ifdef DEBUG
		if (pCtx->debug2) {
			RX_DEBUG("E-Hash1 mismatched!\n");		
			wsc_debug_out("E-Hash1(enrollee)", tmp, BYTE_LEN_256B);
			wsc_debug_out("E-Hash1(my keep)", pSta->e_h1, BYTE_LEN_256B);		
		}
#endif
		
#ifdef CONFIG_RTL865X_KLD		
		report_WPS_STATUS(PROTOCOL_MISMATCH_H1);
#else
		report_WPS_STATUS(HASH_FAIL);
#endif	
		return -1;
	}
		
	/*check E-Hash2*/ 
	hmac_sha256((unsigned char *)(&pCtx->peer_pin_code[strlen(pCtx->peer_pin_code)/2]), strlen(pCtx->peer_pin_code)/2, pSta->auth_key, BYTE_LEN_256B, tmp, &size);
	memcpy(tmpbuf, pSta->e_s2, NONCE_LEN);
	ptr = append(&tmpbuf[BYTE_LEN_128B], tmp, BYTE_LEN_128B);
	ptr = append(ptr, tmp1, PUBLIC_KEY_LEN);
	ptr = append(ptr, tmp2, PUBLIC_KEY_LEN);

	size = (int)(((unsigned long)ptr) - ((unsigned long)tmpbuf));
	hmac_sha256(tmpbuf, size, pSta->auth_key, BYTE_LEN_256B, tmp, &size);

	if (memcmp(tmp, pSta->e_h2, BYTE_LEN_256B)) 
	{

#ifdef DEBUG
		if (pCtx->debug2){
			RX_DEBUG("E-Hash2 mismatched!\n");
			wsc_debug_out("E-Hash2(Enrollee)", tmp, BYTE_LEN_256B);			
			wsc_debug_out("E-Hash2(my keep)", pSta->e_h2, BYTE_LEN_256B);
		}
#endif
	
#ifdef CONFIG_RTL865X_KLD		
		report_WPS_STATUS(PROTOCOL_MISMATCH_H2);
#else
		report_WPS_STATUS(HASH_FAIL);
#endif			
		return -1;
	}

	pSta->tx_timeout = pCtx->tx_timeout;
	ret = send_wsc_M8(pCtx, pSta);
#ifdef WPS2DOTX
	if(pSta->state == ST_WAIT_EAPOL_FRAG_ACK_M8){

	}else
#endif
	{
		if (ret < 0) {
			if (pSta->invoke_security_gen)
				pSta->invoke_security_gen = 0;
			return -1;
		}
		if (ret > 0) {
				return ret;
			}

		pSta->state = ST_WAIT_DONE;
		pSta->tx_timeout = pCtx->tx_timeout;	
		pSta->retry = 0;
	}	
	return 0;
}

static int msgHandler_M5(CTX_Tp pCtx, STA_CTX_Tp pSta, unsigned char *pMsg, int msg_len)
{
	unsigned char *pData;
	int tag_len, size;
	unsigned char tmpbuf[1024];
	int retval=0;

	DBFENTER;

	_DEBUG_PRINT("<< Receive EAP WSC_MSG M5(size=%d)\n\n",msg_len);
	
#ifdef CONFIG_RTL865X_KLD		
	report_WPS_STATUS(PROTOCOL_S5);
#else

        report_WPS_STATUS(RECV_M5);
#endif	
	
	if (pSta->state != ST_WAIT_M5) {
		RX_DEBUG("Invalid state [%d]!\n", pSta->state);
		return 0;
	}

	if (check_authenticator_attr(pSta, pMsg, msg_len) < 0)
		return -1;

	if (check_nonce(pMsg, msg_len, TAG_REGISTRAR_NONCE,  pSta->nonce_registrar, "RegistarNonce") < 0)
		return -1;

	size = decrypt_attr(pCtx, pSta, pMsg, msg_len, tmpbuf);
	if (size < 0)
		return -1;

	pData = check_tag(pCtx, tmpbuf, size, TAG_E_SNONCE1, NONCE_LEN, "E-S1", TYPE_BIN, &tag_len);
	if (pData == NULL)
		return -1;

	// got E-S1
	memcpy(pSta->e_s1, pData, tag_len);

	pSta->tx_timeout = pCtx->tx_timeout;
	retval = send_wsc_M6(pCtx, pSta);

	if(retval!=0){
		return retval;
	}
	
#ifdef WPS2DOTX
	if(pSta->state == ST_WAIT_EAPOL_FRAG_ACK_M6){

	}else
#endif
	{
		pSta->state = ST_WAIT_M7;
		pSta->tx_timeout = pCtx->tx_timeout;	
		pSta->retry = 0;
	}
	return 0;
}

static int msgHandler_M3(CTX_Tp pCtx, STA_CTX_Tp pSta, unsigned char *pMsg, int msg_len)
{
	unsigned char *pData;
	int tag_len;
	int retval=0;

	DBFENTER;

	_DEBUG_PRINT("<< Receive EAP WSC_MSG M3(size=%d)\n\n",msg_len);

#ifdef CONFIG_RTL865X_KLD		
	report_WPS_STATUS(PROTOCOL_S3);
#else
    report_WPS_STATUS(RECV_M3);
#endif	

	if (pSta->state != ST_WAIT_M3) {
		RX_DEBUG("Invalid state [%d]!\n", pSta->state);
		return 0;
	}

	if (check_authenticator_attr(pSta, pMsg, msg_len) < 0)
		return -1;

	if (check_nonce(pMsg, msg_len, TAG_REGISTRAR_NONCE,  pSta->nonce_registrar, "RegistarNonce") < 0)
		return -1;

	pData = check_tag(pCtx, pMsg, msg_len, TAG_E_HASH1, BYTE_LEN_256B, "E-Hash1", TYPE_BIN, &tag_len);
	if (pData == NULL)
		return -1;
	memcpy(pSta->e_h1, pData, tag_len);

	pData = check_tag(pCtx, pMsg, msg_len, TAG_E_HASH2, BYTE_LEN_256B, "E-Hash2", TYPE_BIN, &tag_len);
	if (pData == NULL)
		return -1;
	memcpy(pSta->e_h2, pData, tag_len);
	

#ifdef DEBUG
	if(pCtx->debug2){
		wsc_debug_out("M3 E-Hash1", pSta->e_h1, BYTE_LEN_256B);		
		wsc_debug_out("M3 E-Hash2", pSta->e_h2, BYTE_LEN_256B);
	}
#endif	
	pSta->tx_timeout = pCtx->tx_timeout;
	
	retval = send_wsc_M4(pCtx, pSta);	
	if(retval!=0){
		return retval;
	}
	
#ifdef WPS2DOTX
	if(pSta->state == ST_WAIT_EAPOL_FRAG_ACK_M4){

	}else
#endif
	{
		pSta->state = ST_WAIT_M5;
		pSta->tx_timeout = pCtx->tx_timeout;
		pSta->retry = 0;
	}

	return 0;
}

static int msgHandler_M1(CTX_Tp pCtx, STA_CTX_Tp pSta, unsigned char *pMsg, int msg_len)
{
	unsigned char *pData;
	int tag_len, ret;
	unsigned short sVal;

	DBFENTER;

	_DEBUG_PRINT("<< Receive EAP WSC_MSG M1(size=%d)\n\n",msg_len);
	
#ifdef CONFIG_RTL865X_KLD		
	report_WPS_STATUS(PROTOCOL_S1);
#else

        report_WPS_STATUS(RECV_M1);
#endif	

	if (pSta->state != ST_WAIT_M1) {
		RX_DEBUG("Invalid state [%d]!\n", pSta->state);
		return 0;
	}
#ifdef MUL_PBC_DETECTTION
		if (pCtx->is_ap && IS_PBC_METHOD(pCtx->config_method) && 
			pSta->device_password_id == PASS_ID_PB &&
			!pCtx->disable_MulPBC_detection) {
			WSC_pthread_mutex_lock(&pCtx->PBCMutex);
			//DEBUG_PRINT("%s %d Lock PBC mutex\n", __FUNCTION__, __LINE__);
			search_active_pbc_sta(pCtx, pSta->addr, pSta->uuid, pMsg, msg_len);
			WSC_pthread_mutex_unlock(&pCtx->PBCMutex);
			//DEBUG_PRINT("%s %d unlock PBC mutex\n", __FUNCTION__, __LINE__);
		}
#endif

	pData = check_tag(pCtx, pMsg, msg_len, TAG_UUID_E, UUID_LEN, "UUID-E", TYPE_BIN, &tag_len);
	if (pData == NULL)
		return -1;
	memcpy(pSta->uuid, pData, UUID_LEN);

	pData = check_tag(pCtx, pMsg, msg_len, TAG_MAC_ADDRESS, ETHER_ADDRLEN, "MACAddress", TYPE_BIN, &tag_len);
	if (pData == NULL){		
		return -1;
	}
#ifdef DET_WPS_SPEC	
	else{
		memcpy(pCtx->M1MacAddr , pData ,ETHER_ADDRLEN);
	}
#endif
#if 0  // for Intel SDK
	if (memcmp(pData, pSta->addr, ETHER_ADDRLEN)) {
		DEBUG_ERR("MAC address is mismatched![%02x:%02x:%02x:%02x:%02x:%02x]\n",
			pData[0],pData[1],pData[2],pData[3],pData[4],pData[5]);
		return -1;		
	}
#else
	memcpy(pSta->msg_addr, pData, ETHER_ADDRLEN);
#endif

#if	0	//def WPS2DOTX
	pData = check_tag(pCtx, pMsg, msg_len, TAG_REQ_TO_ENROLL, 1, "Req to Enroll", TYPE_BYTE, &tag_len);	
	
	if(pData){
		Ptr = pSta->msg_addr;
		RX_DEBUG("found REQ_TO_ENROLL [from %02x%02x%02x-%02x%02x%02x]\n",Ptr[0],Ptr[1],Ptr[2],Ptr[3],Ptr[4],Ptr[5]);
	}
#endif

	pData = check_tag(pCtx, pMsg, msg_len, TAG_EROLLEE_NONCE, NONCE_LEN, "EnrolleeNonce", TYPE_BIN, &tag_len);
	if (pData == NULL)
		return -1;
	memcpy(pCtx->nonce_enrollee, pData, tag_len);
	memcpy(pSta->nonce_enrollee, pData, tag_len);


	pData = check_tag(pCtx, pMsg, msg_len, TAG_PUB_KEY, PUBLIC_KEY_LEN, "PublicKey", TYPE_BIN, &tag_len);
	if (pData == NULL)
		return -1;


	
	pSta->dh_enrollee = generate_dh_parameters(PUBLIC_KEY_LEN*8, pData, DH_GENERATOR_2);
	if (pSta->dh_enrollee == NULL)
		return -1;

	

	if ((pData = check_tag(pCtx, pMsg, msg_len, TAG_AUTH_TYPE_FLAGS, 2, "AuthenticationTypeFlags", TYPE_WORD, &tag_len)) == NULL)
		return CONFIG_ERR_NET_AUTH_FAIL;
#ifdef __ECOS
	memcpy(&sVal, pData, 2);
	pSta->auth_type_flags = ntohs(sVal);
#else
	pSta->auth_type_flags = ntohs(*((unsigned short *)pData));
#endif

#if 0	// sometimes STA's Auth is wrong , for IOT let it by pass
	if (!(pSta->auth_type_flags & pCtx->auth_type_flags)) {
		RX_DEBUG("Enrollee uses auth_type_flags= %d; not supported by current setting\n", pSta->auth_type_flags);
		return -1;
	}
#endif
	if ((pData = check_tag(pCtx, pMsg, msg_len, TAG_ENCRYPT_TYPE_FLAGS, 2, "EncryptionTypeFlags", TYPE_WORD, &tag_len)) == NULL)
		return CONFIG_ERR_NET_AUTH_FAIL;
#ifdef __ECOS
	memcpy(&sVal, pData, 2);
	pSta->encrypt_type_flags = ntohs(sVal);
#else
	pSta->encrypt_type_flags = ntohs(*((unsigned short *)pData));
#endif
	
    #if 0   //def DEBUG
	RX_DEBUG("STA support Auth:0x%02X\n",pSta->auth_type_flags);
	RX_DEBUG("STA support Encrypt: %d\n",pSta->encrypt_type_flags);
	show_auth_encry_help();
    #endif	

#if 0	// sometimes STA's Encry is wrong , for IOT let it by pass
	if (!(pSta->encrypt_type_flags & pCtx->encrypt_type_flags)) {
		RX_DEBUG("Enrollee uses encrypt_type_flags= %d; not supported by current setting\n", pSta->encrypt_type_flags);
		return -1;
	}
#endif

#ifdef WPS2DOTX
	if(pSta->encrypt_type_flags==WSC_ENCRYPT_WEP) {
		RX_DEBUG("Enrollee only support WEP Encrypt_type (%d) not supported by 2.0 AP\n", 
			pSta->encrypt_type_flags);
		return -1;
	}	
#endif

	if (check_tag(pCtx, pMsg, msg_len, TAG_CONNECT_TYPE_FLAGS, 1, "ConnectionTypeFlags", TYPE_BYTE, &tag_len) == NULL)
		return -1;
	pData = check_tag(pCtx, pMsg, msg_len, TAG_CONFIG_METHODS, 2, "ConfigMethods", TYPE_WORD, &tag_len);
	if (pData == NULL)
		return -1;
	memcpy(&sVal, pData, 2);
	sVal = ntohs(sVal);	
	pSta->config_method = sVal;

	pData = check_tag(pCtx, pMsg, msg_len, TAG_SIMPLE_CONFIG_STATE, 1, "SimpleConfigState", TYPE_BYTE, &tag_len);
	if (pData == NULL)
		return -1;

#if defined(WSC_CLIENT_MODE) && defined(SUPPORT_REGISTRAR)
	if (!pCtx->is_ap && pCtx->role == REGISTRAR) {
		pSta->config_state = (unsigned char)(*pData);
        #ifdef DEBUG_UPNP
		RX_DEBUG("(ER)Enrollee's state = %d\n", (int)pSta->config_state);
        #endif
	}
#endif

	if (check_tag(pCtx, pMsg, msg_len, TAG_MANUFACTURER, 
			NOT_GREATER_THAN_MASK|MAX_MANUFACT_LEN, "Manufacture", TYPE_STR, &tag_len) == NULL)
		return -1;
	if (check_tag(pCtx, pMsg, msg_len, TAG_MODEL_NAME, 
			NOT_GREATER_THAN_MASK|MAX_MODEL_NAME_LEN, "ModelName", TYPE_STR, &tag_len) == NULL)
		return -1;
	if (check_tag(pCtx, pMsg, msg_len, TAG_MODEL_NUMBER, 
			NOT_GREATER_THAN_MASK|MAX_MODEL_NUM_LEN, "ModelNumber", TYPE_STR, &tag_len) == NULL)
		return -1;
	if (check_tag(pCtx, pMsg, msg_len, TAG_SERIAL_NUM, 
			NOT_GREATER_THAN_MASK|MAX_SERIAL_NUM_LEN, "SerailNumber", TYPE_STR, &tag_len) == NULL)
		return -1;

	pData = search_tag(pMsg, TAG_PRIMARY_DEVICE_TYPE, msg_len, &tag_len);
	if (pData == NULL) {
		DEBUG_ERR("Can't find TAG_PRIMARY_DEVICE_TYPE\n");
		return -1;
	}




	pData = check_tag(pCtx, pMsg, msg_len, TAG_DEVICE_NAME, 
		NOT_GREATER_THAN_MASK|MAX_DEVICE_NAME_LEN, "DeviceName", TYPE_STR, &tag_len);
	if ( pData == NULL){
		return -1;
	}
#ifdef DET_WPS_SPEC	
	else{
		strcpy(pCtx->M1DevName , pData);	
	}
#endif
	if (check_tag(pCtx, pMsg, msg_len, TAG_RF_BAND, 1, "RFBand", TYPE_BYTE, &tag_len) == NULL)
		return -1;
	if (check_tag(pCtx, pMsg, msg_len, TAG_ASSOC_STATE, 2, "AssociationState", TYPE_WORD, &tag_len) == NULL)
		return -1;
	pData = check_tag(pCtx, pMsg, msg_len, TAG_DEVICE_PASSWORD_ID, 2, "DevicePasswordID", TYPE_WORD, &tag_len);
	if (pData == NULL)
		return -1;
	memcpy(&sVal, pData, 2);
	pSta->device_password_id = ntohs(sVal);

	if (check_tag(pCtx, pMsg, msg_len, TAG_CONFIG_ERR, 2, "ConfigurationError", TYPE_WORD, &tag_len) == NULL)
		return -1;
	if (check_tag(pCtx, pMsg, msg_len, TAG_OS_VERSION, 4, "OSVersion", TYPE_DWORD, &tag_len) == NULL)
		return -1;

#ifdef DEBUG
	if(pCtx->debug2){
		DEBUG_PRINT("Primary Device Type: len=%d, category_id=0x%x, oui=%02x%02x%02x%02x, sub_category_id=0x%x\n",
		tag_len, ntohs(*((unsigned short *)pData)), pData[2],pData[3],pData[4],pData[5],ntohs(*((unsigned short *)&pData[6])));

		wsc_debug_out("dh_enrollee" ,(void *)pSta->dh_enrollee , sizeof(struct dh_st));

		wsc_debug_out("PUBLIC_KEY" ,pData , PUBLIC_KEY_LEN);

		wsc_debug_out("N1 (nonce from enrollee)" ,pSta->nonce_enrollee , tag_len);
	}
#endif
	pSta->tx_timeout = pCtx->tx_timeout;
	ret = send_wsc_M2(pCtx, pSta);

#ifdef WPS2DOTX
	if(pSta->state == ST_WAIT_EAPOL_FRAG_ACK_M2){

	}else
#endif	
	{
		if (ret < 0) {
			DEBUG_ERR("send_wsc_M2() error!\n");
			return -1;
		}	
		if (ret == MSG_TYPE_M2){
			//RX_DEBUG("pSta->state = ST_WAIT_M3\n\n");
			pSta->state = ST_WAIT_M3;
		}else if(ret == MSG_TYPE_M2D){
			pSta->state = ST_WAIT_ACK;
		}
		
		pSta->tx_timeout = pCtx->tx_timeout;
		pSta->retry = 0;
	}
	if(ret == MSG_TYPE_M2 || ret == MSG_TYPE_M2D)
		return 0;
	else
		return ret;
	
}
#endif // SUPPORT_REGISTRAR

#ifdef SUPPORT_ENROLLEE
static int msgHandler_M8(CTX_Tp pCtx, STA_CTX_Tp pSta, unsigned char *pMsg, int msg_len)
{
	int ret = 0;
	
	DBFENTER;
	
	_DEBUG_PRINT("\n<< Receive EAP WSC_MSG M8\n\n");
	report_WPS_STATUS(RECV_M8);

	if (pSta->state != ST_WAIT_M8) {
		RX_DEBUG("Invalid state [%d]!\n", pSta->state);
		return 0;
	}

	if (check_authenticator_attr(pSta, pMsg, msg_len) < 0)
		return -1;

	if (check_nonce(pMsg, msg_len, TAG_EROLLEE_NONCE,  pSta->nonce_enrollee, "EnrolleeNonce") < 0)
		return -1;

	ret = decrypt_setting(pCtx, pSta, pMsg, msg_len);
	if (ret != 0) {
		memset((unsigned char*)pCtx->assigned_ssid, 0, ((unsigned long)pCtx->sta - (unsigned long)pCtx->assigned_ssid));
		return ret;
	}

	
	send_wsc_done(pCtx, pSta);

    #ifdef P2P_SUPPORT
    if(pCtx->p2p_trigger_type==P2P_PRE_CLIENT){
		RX_DEBUG("\n\n");
        strcpy(pCtx->p2p_peers_ssid,pCtx->assigned_ssid);
        strcpy(pCtx->p2p_peers_psk,pCtx->assigned_network_key);        
    }else
    #endif  
    {
        #ifdef FOR_DUAL_BAND
    	if(pCtx->is_ap){ 
    		if(pCtx->InterFaceComeIn == COME_FROM_WLAN0)
    			pCtx->wait_reinit = write_param_to_flash(pCtx, 0);
    		else if(pCtx->InterFaceComeIn == COME_FROM_WLAN1)
    			pCtx->wait_reinit = write_param_to_flash2(pCtx, 0);  //  1001
    	}
    	else{
    		if(pCtx->both_band_credential && pCtx->assigned_valid_2){	            
    			if(pCtx->InterFaceComeIn == COME_FROM_WLAN0 && !strncmp(pCtx->negoApSSID,pCtx->assigned_ssid,strlen(pCtx->assigned_ssid))){
    				pCtx->wait_reinit = write_param_to_flash_both_band(pCtx, 0,1,COME_FROM_WLAN0);				
    				pCtx->wait_reinit = write_param_to_flash_both_band(pCtx, 0,2,COME_FROM_WLAN1);
    			}else if (pCtx->InterFaceComeIn == COME_FROM_WLAN0 && !strncmp(pCtx->negoApSSID,pCtx->assigned_ssid_2,strlen(pCtx->assigned_ssid_2))){
    				pCtx->wait_reinit = write_param_to_flash_both_band(pCtx, 0,2,COME_FROM_WLAN0);				
    				pCtx->wait_reinit = write_param_to_flash_both_band(pCtx, 0,1,COME_FROM_WLAN1);
    			}else if (pCtx->InterFaceComeIn == COME_FROM_WLAN1 && !strncmp(pCtx->negoApSSID,pCtx->assigned_ssid,strlen(pCtx->assigned_ssid))){
    				pCtx->wait_reinit = write_param_to_flash_both_band(pCtx, 0,1,COME_FROM_WLAN1);				
    				pCtx->wait_reinit = write_param_to_flash_both_band(pCtx, 0,2,COME_FROM_WLAN0);
    			}else if (pCtx->InterFaceComeIn == COME_FROM_WLAN1 && !strncmp(pCtx->negoApSSID,pCtx->assigned_ssid_2,strlen(pCtx->assigned_ssid_2))){
    				pCtx->wait_reinit = write_param_to_flash_both_band(pCtx, 0,2,COME_FROM_WLAN1);				
    				pCtx->wait_reinit = write_param_to_flash_both_band(pCtx, 0,1,COME_FROM_WLAN0);
    			}
    		}
    		else {
                if(pCtx->InterFaceComeIn == COME_FROM_WLAN0)
    			    pCtx->wait_reinit = write_param_to_flash(pCtx, 0);
    		    else if(pCtx->InterFaceComeIn == COME_FROM_WLAN1)
    			    pCtx->wait_reinit = write_param_to_flash2(pCtx, 0);
            }
    	}
        #else
    	pCtx->wait_reinit = write_param_to_flash(pCtx, 0);
        #endif			
    }

#ifdef FULL_SECURITY_CLONE
	if(pCtx->TagAPConfigStat!=1)
#endif
	if (pCtx->wait_reinit != REINIT_SYS)
		memset(pCtx->assigned_ssid, 0, ((unsigned long)pCtx->sta - (unsigned long)pCtx->assigned_ssid));


	report_WPS_STATUS(PROTOCOL_SUCCESS);

	if (pCtx->is_ap)
		reset_ctx_state(pCtx);

	if (wlioctl_set_led(LED_WSC_SUCCESS) < 0) {
		DEBUG_ERR("issue wlan ioctl set_led error!\n");	
	}


#ifdef MUL_PBC_DETECTTION
	if (pCtx->is_ap && IS_PBC_METHOD(pCtx->config_method) && 
		pSta->device_password_id == PASS_ID_PB &&
		!pCtx->disable_MulPBC_detection) {
		WSC_pthread_mutex_lock(&pCtx->PBCMutex);
		//DEBUG_PRINT("%s %d Lock PBC mutex\n", __FUNCTION__, __LINE__);
		RX_DEBUG("rm pbc sta from list\n");					
		remove_active_pbc_sta(pCtx, pSta->addr, 1);
		WSC_pthread_mutex_unlock(&pCtx->PBCMutex);
		//DEBUG_PRINT("%s %d unlock PBC mutex\n", __FUNCTION__, __LINE__);
	}
#endif

#ifdef SUPPORT_UPNP
	if (pSta->used & IS_UPNP_CONTROL_POINT) {
		pCtx->upnp_wait_reboot_timeout = UPNP_WAIT_REBOOT;
		pSta->tx_timeout = 0;
		pCtx->status_changed = 1;
	}
	else
#endif
	{	if (pCtx->is_ap)
			pSta->state = ST_WAIT_ACK;
		else
			pSta->state = ST_WAIT_EAP_FAIL;
		pSta->tx_timeout = pCtx->tx_timeout;
	}
	pSta->retry = 0;

#if	0	//def WSC_CLIENT_MODE ; no need  ; remove
	if (!pCtx->is_ap && pCtx->wait_reinit){
		RX_DEBUG("signal_webs\n");		
		signal_webs(pCtx->wait_reinit);		
		pCtx->had_sigWeb=1;
	}
#endif	
	
	return 0;
}

static int msgHandler_M6(CTX_Tp pCtx, STA_CTX_Tp pSta, unsigned char *pMsg, int msg_len)
{
	unsigned char *pData, *ptr;
	int tag_len, size;
	unsigned char tmpbuf[1024];
	unsigned char tmp1[200], tmp[200], tmp2[200];

	DBFENTER;
	
	_DEBUG_PRINT("\n<< Receive EAP WSC_MSG M6\n\n");
        report_WPS_STATUS(RECV_M6);

	if (pSta->state != ST_WAIT_M6) {
		RX_DEBUG("Invalid state [%d]!\n", pSta->state);
		return 0;
	}

	if (check_authenticator_attr(pSta, pMsg, msg_len) < 0)
		return -1;

	if (check_nonce(pMsg, msg_len, TAG_EROLLEE_NONCE,  pSta->nonce_enrollee, "EnrolleeNonce") < 0)
		return -1;

	size = decrypt_attr(pCtx, pSta, pMsg, msg_len, tmpbuf);
	if (size < 0)
		return -1;

	pData = check_tag(pCtx, tmpbuf, size, TAG_R_SNONCE2, NONCE_LEN, "R-S2", TYPE_BIN, &tag_len);
	if (pData == NULL)
		return -1;
	memcpy(pSta->r_s2, pData, tag_len);

#if 0	// has moved to M4 check,need not do again here
	/* check R-Hash1 */ 
	hmac_sha256(pCtx->pin_code, strlen(pCtx->pin_code)/2, pSta->auth_key, BYTE_LEN_256B, tmp, &size);
	memcpy(tmpbuf, pSta->r_s1, NONCE_LEN);
	ptr = append(&tmpbuf[BYTE_LEN_128B], tmp, BYTE_LEN_128B);
	BN_bn2bin(pSta->dh_enrollee->pub_key, tmp1);
	ptr = append(ptr, tmp1, PUBLIC_KEY_LEN);
	BN_bn2bin(pSta->dh_registrar->p, tmp2);
	ptr = append(ptr, tmp2, PUBLIC_KEY_LEN);
	size = (int)(((unsigned long)ptr) - ((unsigned long)tmpbuf));
	hmac_sha256(tmpbuf, size, pSta->auth_key, BYTE_LEN_256B, tmp, &size);
	if (memcmp(tmp, pSta->r_h1, BYTE_LEN_256B)) {
		RX_DEBUG("M6 R-Hash1 mismatched!\n");

		wsc_debug_out("My keep:", pSta->r_h1, BYTE_LEN_256B);
		wsc_debug_out("from STA:", tmp, BYTE_LEN_256B);
		report_WPS_STATUS(HASH_FAIL);
		return CONFIG_ERR_DEV_PASS_AUTH_FAIL ;		
	}
#endif

	/* check R-Hash2 */ 
	hmac_sha256((unsigned char *)(&pCtx->pin_code[strlen(pCtx->pin_code)/2]), strlen(pCtx->pin_code)/2, pSta->auth_key, BYTE_LEN_256B, tmp, &size);
	memcpy(tmpbuf, pSta->r_s2, NONCE_LEN);
	ptr = append(&tmpbuf[BYTE_LEN_128B], tmp, BYTE_LEN_128B);
	BN_bn2bin(pSta->dh_enrollee->pub_key, tmp1);	
	BN_bn2bin(pSta->dh_registrar->p, tmp2);	
	ptr = append(ptr, tmp1, PUBLIC_KEY_LEN);
	ptr = append(ptr, tmp2, PUBLIC_KEY_LEN);
	size = (int)(((unsigned long)ptr) - ((unsigned long)tmpbuf));
	hmac_sha256(tmpbuf, size, pSta->auth_key, BYTE_LEN_256B, tmp, &size);
	if (memcmp(tmp, pSta->r_h2, BYTE_LEN_256B)) {
		RX_DEBUG("M6 R-Hash2 mismatched!\n");
		wsc_debug_out("My keep:", pSta->r_h2, BYTE_LEN_256B);
		wsc_debug_out("from STA:", tmp, BYTE_LEN_256B);		
		report_WPS_STATUS(HASH_FAIL);

        #ifdef	AUTO_LOCK_DOWN
        if(pCtx->is_ap){
            record_and_check_AuthFail(pCtx);
        }
        #endif
        
		return CONFIG_ERR_DEV_PASS_AUTH_FAIL ;		
	}
#ifdef	AUTO_LOCK_DOWN
#ifdef ALD_BRUTEFORCE_ATTACK_MITIGATION				
	/*if even PIN is correct recount it*/
	pCtx->ADL_pin_attack_count=0;	
	RX_DEBUG("Reset pin fail count to 0\n");
#endif
#endif

#ifdef	DET_WPS_SPEC
	if(pCtx->role != PROXY)
		wlioctl_set_led(LED_WSC_START);
#endif




	send_wsc_M7(pCtx, pSta);

#ifdef WPS2DOTX	
	if(pSta->state == ST_WAIT_EAPOL_FRAG_ACK_M7){
		return 0;
	} 
#endif

	pSta->state = ST_WAIT_M8;
	if (!(pSta->used & IS_UPNP_CONTROL_POINT))
		pSta->tx_timeout = pCtx->tx_timeout;
	else
		pSta->tx_timeout = 15;
	pSta->retry = 0;

	return 0;
}

static int msgHandler_M4(CTX_Tp pCtx, STA_CTX_Tp pSta, unsigned char *pMsg, int msg_len)
{
	unsigned char *pData;
	unsigned char *ptr;	
	int tag_len, size;
	unsigned char tmpbuf[1024];
	unsigned char tmp1[200], tmp[200], tmp2[200];

	DBFENTER;
	
	_DEBUG_PRINT("\n<< Receive EAP WSC_MSG M4\n\n");
	report_WPS_STATUS(RECV_M4);

	if (pSta->state != ST_WAIT_M4 ) 
	{
		RX_DEBUG("Invalid state [%d]!\n", pSta->state);
		//brad modify for pass Vista WCN Error Handling and Tempering, return 0 will cause re-send M3 to Vista, the action 
		//can not pass the test
		//if (pCtx->is_ap) 
			return -1;
		//else
		//	return 0;
	}

	if (check_authenticator_attr(pSta, pMsg, msg_len) < 0)
		return -1;

	if (check_nonce(pMsg, msg_len, TAG_EROLLEE_NONCE,  pSta->nonce_enrollee, "EnrolleeNonce") < 0)
		return -1;

	pData = check_tag(pCtx, pMsg, msg_len, TAG_R_HASH1, BYTE_LEN_256B, "R-Hash1", TYPE_BIN, &tag_len);
	if (pData == NULL)
		return -1;
	memcpy(pSta->r_h1, pData, tag_len);

	pData = check_tag(pCtx, pMsg, msg_len, TAG_R_HASH2, BYTE_LEN_256B, "R-Hash2", TYPE_BIN, &tag_len);
	if (pData == NULL)
		return -1;
	memcpy(pSta->r_h2, pData, tag_len);

	size = decrypt_attr(pCtx, pSta, pMsg, msg_len, tmpbuf);
	if (size < 0)
		return -1;

	pData = check_tag(pCtx, tmpbuf, size, TAG_R_SNONCE1, NONCE_LEN, "R-S1", TYPE_BIN, &tag_len);
	if (pData == NULL)
		return -1;
	memcpy(pSta->r_s1, pData, tag_len);


	/* check R-Hash1 for detect PIN number left half Error*/ 
	hmac_sha256((unsigned char*)pCtx->pin_code, strlen(pCtx->pin_code)/2, pSta->auth_key, BYTE_LEN_256B, tmp, &size);
	memcpy(tmpbuf, pSta->r_s1, NONCE_LEN);
	ptr = append(&tmpbuf[BYTE_LEN_128B], tmp, BYTE_LEN_128B);
	BN_bn2bin(pSta->dh_enrollee->pub_key, tmp1);
	ptr = append(ptr, tmp1, PUBLIC_KEY_LEN);
	BN_bn2bin(pSta->dh_registrar->p, tmp2);
	ptr = append(ptr, tmp2, PUBLIC_KEY_LEN);
	size = (int)(((unsigned long)ptr) - ((unsigned long)tmpbuf));
	hmac_sha256(tmpbuf, size, pSta->auth_key, BYTE_LEN_256B, tmp, &size);

	if (memcmp(tmp, pSta->r_h1, BYTE_LEN_256B)) {

#ifdef DEBUG
	if(pCtx->debug2){
		wsc_debug_out("M4(My) R-Hash1", tmp, BYTE_LEN_256B);
		wsc_debug_out("M4(Reg) R-Hash1", pSta->r_h1, BYTE_LEN_256B);
	}
#endif		


        #ifdef	AUTO_LOCK_DOWN
        if(pCtx->is_ap){
	    	record_and_check_AuthFail(pCtx);
        }
        #endif		
		DEBUG_ERR("R-Hash1 mismatched!\n");
		return CONFIG_ERR_DEV_PASS_AUTH_FAIL ;		
	}

	send_wsc_M5(pCtx, pSta);
#ifdef WPS2DOTX	
	if(pSta->state == ST_WAIT_EAPOL_FRAG_ACK_M5){
		return 0;
	}
#endif	

	
	pSta->state = ST_WAIT_M6;
	if (!(pSta->used & IS_UPNP_CONTROL_POINT))
		pSta->tx_timeout = pCtx->tx_timeout;
	else
		pSta->tx_timeout = 15;
	pSta->retry = 0;
	
	return 0;
}

static int msgHandler_M2(CTX_Tp pCtx, STA_CTX_Tp pSta, unsigned char *pMsg, int msg_len, int code)
{
	unsigned char *pData;
	int tag_len, is_m2=0, tmp;
	unsigned short sVal;

	DBFENTER;
	
#ifdef DET_WPS_SPEC
	DET_DEBUG("msgHandler_M2\n");
#endif





	if (code == MSG_TYPE_M2)
		is_m2 = 1;


#ifdef AUTO_LOCK_DOWN
	if(pCtx->auto_lock_down)
		return CONFIG_ERR_SETUP_LOCKED;
#endif


	report_WPS_STATUS(((is_m2 == 1) ? RECV_M2 : RECV_M2D ));
	_DEBUG_PRINT("\n<< Receive EAP WSC_MSG %s\n\n", ((is_m2 == 1) ? "M2" : "M2D")); 

	if (pSta->state != ST_WAIT_M2 && pSta->state != ST_WAIT_EAP_FAIL) {
		RX_DEBUG("Invalid state [%d]!\n", pSta->state);
		return CONFIG_ERR_OOB_INTERFACE_READ_ERR;	//WPS2.0
	}


	
	if (check_nonce(pMsg, msg_len, TAG_EROLLEE_NONCE, pSta->nonce_enrollee, "EnrolleeNonce") < 0)
		return CONFIG_ERR_OOB_INTERFACE_READ_ERR;	//WPS2.0

	pData = check_tag(pCtx, pMsg, msg_len, TAG_REGISTRAR_NONCE, NONCE_LEN, "RegistrarNonce", TYPE_BIN, &tag_len);
	if (pData == NULL)
		return CONFIG_ERR_OOB_INTERFACE_READ_ERR;	//WPS2.0
	
	memcpy(pSta->nonce_registrar, pData, tag_len);

	/*Disable configured by ER*/
	if(pCtx->is_ap){
		/*whatever config or unconfig state all reject config by ER*/		
		if ((pCtx->disable_configured_by_exReg == 2))	 
		{
			RX_DEBUG("	Disable configured by ER!!\n\n");
			return CONFIG_ERR_CANNOT_CONNECT_TO_REG;
		}	
		else if ((pCtx->disable_configured_by_exReg == 1))	 
		{
			if(pCtx->config_state == CONFIG_STATE_CONFIGURED){
				RX_DEBUG("	Disable configured by ER!!\n\n");
				return CONFIG_ERR_CANNOT_CONNECT_TO_REG;
			}
			#ifdef DEBUG
			else{
				RX_DEBUG("under unconfigured state allow config by ER\n\n");
			}
			#endif
		}	
		
	}
	pData = check_tag(pCtx, pMsg, msg_len, TAG_UUID_R, UUID_LEN, "UUID-R", TYPE_BIN, &tag_len);
	if (pData == NULL)
		return CONFIG_ERR_OOB_INTERFACE_READ_ERR;	//WPS2.0

	//#ifdef MUL_PBC_DETECTTION
	memcpy(pSta->uuid, pData, UUID_LEN);
//#endif

	if (is_m2) {
		pData = check_tag(pCtx, pMsg, msg_len, TAG_PUB_KEY, PUBLIC_KEY_LEN, "PublicKey", TYPE_BIN, &tag_len);
		if (pData == NULL)
			return CONFIG_ERR_OOB_INTERFACE_READ_ERR;	//WPS2.0

		pSta->dh_registrar= generate_dh_parameters(PUBLIC_KEY_LEN*8, pData, DH_GENERATOR_2);
		if (pSta->dh_registrar == NULL)
			return CONFIG_ERR_OOB_INTERFACE_READ_ERR;	//WPS2.0		
	}

	pData = check_tag(pCtx, pMsg, msg_len, TAG_AUTH_TYPE_FLAGS, 2, "AuthenticationTypeFlags", TYPE_WORD, &tag_len);
	if (pData == NULL)
		return CONFIG_ERR_NET_AUTH_FAIL;
	else {
		if (code == MSG_TYPE_M2) {
#ifdef __ECOS
			memcpy(&sVal, pData, 2);
			tmp = ntohs(sVal);
#else
			tmp = ntohs(*((unsigned short *)pData));
#endif
			if (!(tmp & pCtx->auth_type_flags)) {
				DEBUG_ERR("Registrar Authentication Type Flags = %d; not supported!\n", tmp);
				return CONFIG_ERR_CANNOT_CONNECT_TO_REG;
			}
		}
	}

	pData = check_tag(pCtx, pMsg, msg_len, TAG_ENCRYPT_TYPE_FLAGS, 2, "EncryptionTypeFlags", TYPE_WORD, &tag_len);
	if (pData == NULL)
		return CONFIG_ERR_NET_AUTH_FAIL;
	else {
		if (code == MSG_TYPE_M2) {
#ifdef __ECOS
			memcpy(&sVal, pData, 2);
			tmp = ntohs(sVal);
#else
			tmp = ntohs(*((unsigned short *)pData));
#endif
			if (!(tmp & pCtx->encrypt_type_flags)) {
				DEBUG_ERR("Registrar Encryption Type Flags = %d; not supported!\n", tmp);
				return CONFIG_ERR_CANNOT_CONNECT_TO_REG;
			}
#ifdef WPS2DOTX
			if(tmp ==WSC_ENCRYPT_WEP){
				RX_DEBUG(" Target dev Encrypt_type_flags= %d; WEP only !!\n", tmp);
				return -1;
			}			
#endif

		}
	}
	
	if (check_tag(pCtx, pMsg, msg_len, TAG_CONNECT_TYPE_FLAGS, 1, "ConnectionTypeFlags", TYPE_BYTE, &tag_len) == NULL)
		return -1;

	pData = check_tag(pCtx, pMsg, msg_len, TAG_CONFIG_METHODS, 2, "ConfigMethods", TYPE_WORD, &tag_len);
	if (pData == NULL)
		return CONFIG_ERR_NET_AUTH_FAIL;
#if 0 // for Intel SDK
	else {
		if (code == MSG_TYPE_M2) {
#ifdef __ECOS
			memcpy(&sVal, pData, 2);
			tmp = ntohs(sVal);
#else
			tmp = ntohs(*((unsigned short *)pData));
#endif
			if (pCtx->config_method & tmp) {
				int i=0;
				if (pCtx->config_method & CONFIG_METHOD_ETH)
					i = pCtx->config_method - CONFIG_METHOD_ETH;
				if (tmp & CONFIG_METHOD_ETH)
					tmp -= CONFIG_METHOD_ETH;
				if (!(i & tmp)) {
					DEBUG_ERR("Config method not supported!\n");
					return CONFIG_ERR_CANNOT_CONNECT_TO_REG;
				}
			}
			else {
				DEBUG_ERR("Config method not supported!\n");
				return CONFIG_ERR_CANNOT_CONNECT_TO_REG;
			}
		}
	}
#endif

	if (pCtx->is_ap) {
		if (code == MSG_TYPE_M2) {

			//tmp = ntohs(*((unsigned short *)pData));
			//Fix, makes wscd silently killed running on TI platform
#ifdef __ECOS
			memcpy(&sVal, pData, 2);
			tmp = ntohs(sVal);
#else
			memcpy(&tmp,pData,sizeof(short));
			tmp = ntohs(tmp);
#endif
			if (tmp == CONFIG_METHOD_PBC) {
				DEBUG_ERR("PBC could not be supported when AP is configured by an external registrar!\n");
				return CONFIG_ERR_CANNOT_CONNECT_TO_REG;
			}
		}
	}

	if (check_tag(pCtx, pMsg, msg_len, TAG_MANUFACTURER, 
		NOT_GREATER_THAN_MASK|MAX_MANUFACT_LEN, "Manufacture", TYPE_STR, &tag_len) == NULL)
		return -1;
	
	if (check_tag(pCtx, pMsg, msg_len, TAG_MODEL_NAME, 
		NOT_GREATER_THAN_MASK|MAX_MODEL_NAME_LEN, "ModelName", TYPE_STR, &tag_len) == NULL)
		return -1;
	
	if (check_tag(pCtx, pMsg, msg_len, TAG_MODEL_NUMBER, 
		NOT_GREATER_THAN_MASK|MAX_MODEL_NUM_LEN, "ModelNumber", TYPE_STR, &tag_len) == NULL)
		return -1;
	if (check_tag(pCtx, pMsg, msg_len, TAG_SERIAL_NUM, 
		NOT_GREATER_THAN_MASK|MAX_SERIAL_NUM_LEN, "SerailNumber", TYPE_STR, &tag_len) == NULL)
		return -1;

	pData = search_tag(pMsg, TAG_PRIMARY_DEVICE_TYPE, msg_len, &tag_len);
	if (pData == NULL) {
		DEBUG_ERR("Can't find TAG_PRIMARY_DEVICE_TYPE\n");
		return -1;
	}


	if (check_tag(pCtx, pMsg, msg_len, TAG_DEVICE_NAME, 
		NOT_GREATER_THAN_MASK|MAX_DEVICE_NAME_LEN, "DeviceName", TYPE_STR, &tag_len) == NULL)
		return -1;
	if (check_tag(pCtx, pMsg, msg_len, TAG_RF_BAND, 1, "RFBand", TYPE_BYTE, &tag_len) == NULL)
		return -1;
	if (check_tag(pCtx, pMsg, msg_len, TAG_ASSOC_STATE, 2, "AssociationState", TYPE_WORD, &tag_len) == NULL)
		return -1;
	if (is_m2) {
		pData = check_tag(pCtx, pMsg, msg_len, TAG_DEVICE_PASSWORD_ID, 2, "DevicePasswordID", TYPE_WORD, &tag_len);
		if (pData == NULL)
			return -1;
		memcpy(&sVal, pData, 2);
		pSta->device_password_id = ntohs(sVal);
		
#ifdef MUL_PBC_DETECTTION
		if (pCtx->is_ap && IS_PBC_METHOD(pCtx->config_method) &&
			pSta->device_password_id == PASS_ID_PB &&
			!pCtx->disable_MulPBC_detection) {
			WSC_pthread_mutex_lock(&pCtx->PBCMutex);
			//DEBUG_PRINT("%s %d Lock PBC mutex\n", __FUNCTION__, __LINE__);
			
			search_active_pbc_sta(pCtx, pSta->addr, pSta->uuid, pMsg, msg_len);
#ifdef OVERLAPPING_BY_BAND
			if (search_active_sta_by_band(pCtx, get_band(pCtx)) > 1 && pCtx->pb_pressed) {
#else			
			if (pCtx->active_pbc_sta_count > 1 && pCtx->pb_pressed) {
#endif				
				RX_DEBUG("\n\n		!!Multiple PBC sessions [%d] detected!\n\n", pCtx->active_pbc_sta_count);
				WSC_pthread_mutex_unlock(&pCtx->PBCMutex);
				//DEBUG_PRINT("%s %d unlock PBC mutex\n", __FUNCTION__, __LINE__);
				
				SwitchSessionOverlap_LED_On(pCtx);
				return CONFIG_ERR_MUL_PBC_DETECTED;
			}
			
			WSC_pthread_mutex_unlock(&pCtx->PBCMutex);
			//DEBUG_PRINT("%s %d unlock PBC mutex\n", __FUNCTION__, __LINE__);
		}
#endif
	}
	if (check_tag(pCtx, pMsg, msg_len, TAG_CONFIG_ERR, 2, "ConfigurationError", TYPE_WORD, &tag_len) == NULL)
		return -1;
	if (check_tag(pCtx, pMsg, msg_len, TAG_OS_VERSION, 4, "OSVersion", TYPE_DWORD, &tag_len) == NULL)
		return -1;


#ifdef DEBUG
	if(pCtx->debug2){
		DEBUG_PRINT("Primary Device Type: len=%d, category_id=0x%x, oui=%02x%02x%02x%02x, sub_category_id=0x%x\n",
		tag_len, ntohs(*((unsigned short *)pData)), pData[2],pData[3],pData[4],pData[5],ntohs(*((unsigned short *)&pData[6])));
	}
#endif

	if (is_m2) {
		if (derive_key(pCtx, pSta) < 0)
			return -1;

		if (check_authenticator_attr(pSta, pMsg, msg_len) < 0)
			return -1;

		send_wsc_M3(pCtx, pSta);

#ifdef WPS2DOTX	
		if(pSta->state == ST_WAIT_EAPOL_FRAG_ACK_M3){
			return 0;
		}
#endif				
		pSta->state = ST_WAIT_M4;
	}
	else {	/*handle M2D*/
		if (!(pSta->used & IS_UPNP_CONTROL_POINT)) {
			if (pCtx->is_ap){
				send_wsc_nack(pCtx, pSta, CONFIG_ERR_NO_ERR);
			}else {
				send_wsc_ack(pCtx, pSta);
				pSta->state = ST_WAIT_EAP_FAIL;
			}
		}
		else {
			 send_wsc_ack(pCtx, pSta);
			 pSta->state = ST_WAIT_ACK;
			 return -1;
		}
	}

	if (!(pSta->used & IS_UPNP_CONTROL_POINT))
		pSta->tx_timeout = pCtx->tx_timeout;
	else
		pSta->tx_timeout = 15;
	pSta->retry = 0;

	return 0;
}

int pktHandler_reqid(CTX_Tp pCtx, STA_CTX_Tp pSta, unsigned char id)
{
	DBFENTER;
	
	report_WPS_STATUS(SEND_EAP_IDREQ);
	
	_DEBUG_PRINT("\n<< Receive EAP REQUEST / Identity packet\n");

	//fix problem: when DUT is STA mode ;multiple EAP  id-reqs from AP only the first processed	
	if( pSta->state == ST_WAIT_START )
		pSta->state = ST_WAIT_REQ_ID;

	if (pSta->state != ST_WAIT_REQ_ID) {
		RX_DEBUG("Invalid state [%d], discard packet!\n", pSta->state);
		return 0;
	}
	pSta->eap_reqid = id;

	send_eap_rspid(pCtx, pSta);

	if (pCtx->role == ENROLLEE)
		pSta->state = ST_WAIT_START;
	else
		pSta->state = ST_WAIT_M1;

	pSta->tx_timeout = pCtx->tx_timeout;
	pSta->retry = 0;
	
	return 0;
}

int pktHandler_wsc_start(CTX_Tp pCtx, STA_CTX_Tp pSta)
{
	DBFENTER;

	_DEBUG_PRINT("\n<< Receive EAP WSC_Start\n");

	if (pSta->state != ST_WAIT_START) {
		RX_DEBUG("Invalid state [%d], discard packet!\n", pSta->state);
		return 0;
	}
	report_WPS_STATUS(RECV_EAPOL_START);

	send_wsc_M1(pCtx, pSta);

#ifdef WPS2DOTX	
	if(pSta->state == ST_WAIT_EAPOL_FRAG_ACK_M1){
		return 0;
	} 
#endif	
	
	pSta->state = ST_WAIT_M2;
	pSta->tx_timeout = pCtx->tx_timeout;
	pSta->retry = 0;

	return 0;
}
#endif // SUPPORT_ENROLLEE

int pktHandler_rspid(CTX_Tp pCtx, STA_CTX_Tp pSta, unsigned char *id, int len)
{
#if defined(DEBUG) || defined(PRINT_ERR)
	char eap_id[512];

	memcpy(eap_id, id, len);
	eap_id[len] = '\0';
#endif

	DBFENTER;

	_DEBUG_PRINT("<<Received EAP RESPONSE/Identity packet>>\n Rsp-id = %s\n", eap_id);

	if (pSta->state != ST_WAIT_RSP_ID) {
		RX_DEBUG("Invalid state [%d], discard packet!\n", pSta->state);
		return 0;
	}
	report_WPS_STATUS(RECV_EAP_IDRSP);

	//WSC_pthread_mutex_lock(&pCtx->RegMutex);
	//DEBUG_PRINT("%s %d Lock mutex\n", __FUNCTION__, __LINE__);
	
	if (pCtx->registration_on == 0) {
		pCtx->role = pCtx->original_role;
		//DEBUG_PRINT("\nRoll back role to : %s\n", (pCtx->role==PROXY ? "Proxy" : (pCtx->role==ENROLLEE ? "Enrollee" : "Registrar")));
	}
	else {
		DEBUG_PRINT("%s %d Registration protocol is already in progress\n ignore <<Rx EAP RESPONSE/Identity packet>\n", __FUNCTION__, __LINE__);
		
		// Reason code 5 : Disassociated because AP is unable to handle all currently associated stations
		if ((len == strlen(EAP_ID_ENROLLEE) && !memcmp(id, EAP_ID_ENROLLEE, len)) ||
			(len == strlen(EAP_ID_REGISTRAR) && !memcmp(id, EAP_ID_REGISTRAR, len)) ||
			pSta->Assoc_wscIE_included){
			
			IssueDisconnect(pSta->addr, 5);			
			RX_DEBUG("IssueDisconnect\n\n");
		}
		reset_sta(pCtx, pSta, 1);
		
		//WSC_pthread_mutex_unlock(&pCtx->RegMutex);
		//DEBUG_PRINT("%s %d unlock mutex\n", __FUNCTION__, __LINE__);
		
		return -1;
	}
		
	if (len == strlen(EAP_ID_ENROLLEE) && !memcmp(id, EAP_ID_ENROLLEE, len)) {
#ifdef SUPPORT_UPNP
		// Fix the issue of WLK v1.2 M1<->M2D proxy ---------------
		//	if ((pCtx->original_role == REGISTRAR || pCtx->original_role == PROXY) &&
		if (!pCtx->pb_pressed && !pCtx->pin_assigned && 
				pCtx->upnp && pCtx->TotalSubscriptions){
			pCtx->role = PROXY;
		}else		//------------------------------------ david+2008-05-27			
#endif
		{
			pCtx->role = REGISTRAR;
		}



	}
	else if (len == strlen(EAP_ID_REGISTRAR) && !memcmp(id, EAP_ID_REGISTRAR, len)) {

#if 1			
        if (pCtx->is_ap && pCtx->pb_timeout)    /*now is AP under PBC duration not allow ER nego with DUT*/
        {
            #ifdef BLOCKED_ROGUE_STA				
            add_into_blocked_list(pCtx, pSta);
            #endif
            reset_sta(pCtx, pSta, 1);
            return -1;
        }
#endif                   
		pCtx->role = ENROLLEE;
		pSta->ap_role = ENROLLEE;	


	}
	else {
		DEBUG_ERR("Invalid EAP-Response ID = %s\n", eap_id);
		if (pSta->Assoc_wscIE_included) {
			// Reason code 1 : Unspecified reason
			IssueDisconnect(pSta->addr, 1);
			RX_DEBUG("IssueDisconnect\n\n");
		}
		reset_sta(pCtx, pSta, 1);

		//WSC_pthread_mutex_unlock(&pCtx->RegMutex);
		//DEBUG_PRINT("%s %d unlock mutex\n", __FUNCTION__, __LINE__);
		return -1;		
	}

	DEBUG_PRINT2("Modify role to : %s\n", (pCtx->role==PROXY ? "Proxy" : (pCtx->role==ENROLLEE ? "Enrollee" : "Registrar")));

	if (pCtx->role == REGISTRAR) {
		send_wsc_start(pCtx, pSta);
		pSta->state = ST_WAIT_M1;
	}
#ifdef SUPPORT_UPNP
	else if (pCtx->role == PROXY) {
		send_wsc_start(pCtx, pSta);
		pSta->state = ST_UPNP_WAIT_M1;
	}
#endif
	else {
#ifdef SUPPORT_ENROLLEE		
		send_wsc_M1(pCtx, pSta);
		pSta->state = ST_WAIT_M2;
#endif		
	}
		
	//WSC_pthread_mutex_unlock(&pCtx->RegMutex);
	//DEBUG_PRINT("%s %d unlock mutex\n", __FUNCTION__, __LINE__);
		
	pSta->tx_timeout = pCtx->tx_timeout;
	pSta->retry = 0;
	
	return 0;
}

int pktHandler_wsc_ack(CTX_Tp pCtx, STA_CTX_Tp pSta, struct eap_wsc_t *wsc)
{
	DBFENTER;

	_DEBUG_PRINT("<< Receive WSC_ACK packet\n");
	report_WPS_STATUS(PROC_EAP_ACK);

#ifdef SUPPORT_UPNP

   /*
	* for delay send eap-fail when ER > 1 ;search related code by 20101102 
	* if have >1  ER exist then there are >1 M2D will Rsp from ER , 
	* Enroll will Rsp for each M2D; AP(Proxy mode ) will send EAP-fail 
	* after last EAP-ACK(from Enroll) 
	*/
	if (pCtx->role == PROXY && pCtx->TotalSubscriptions  &&
			 pSta->state == ST_WAIT_ACK  
	){ 

		pSta->ER_RspM2D_delaytime = 2; 
		RX_DEBUG("	Rx ACK from STA (Rsp M2D)\n");
		return 0;
	}


	// Fix the issue of WLK v1.2 M1<->M2D proxy ---------------
	if (pCtx->role == PROXY && pCtx->TotalSubscriptions > 1 &&
					pSta->state != ST_UPNP_WAIT_DONE
					
	){ 
		return 0;
	}
#endif		
//------------------------------------ david+2008-05-27

	send_eap_fail(pCtx, pSta);

	sleep(1);
	
	// Reason code 1 : Unspecified reason
	if (pCtx->is_ap && !pCtx->disable_disconnect){
		IssueDisconnect(pSta->addr, 1);		
		RX_DEBUG("IssueDisconnect\n\n");
		}
	
	reset_sta(pCtx, pSta, 1);

	return 0;	

}

int pktHandler_wsc_nack(CTX_Tp pCtx, STA_CTX_Tp pSta, struct eap_wsc_t *wsc)
{
	DBFENTER;

	_DEBUG_PRINT("\n<< Receive WSC_NACK packet\n");

	report_WPS_STATUS(PROC_PROTOCOL_NACK);	
	
	// Reason code 1 : Unspecified reason
	if (pCtx->is_ap) {
		send_eap_fail(pCtx, pSta);

#ifdef WPS2DOTX
	if (pCtx->is_ap && pCtx->use_ie)
		clear_SetSelectedRegistrar_flag(pCtx);
#endif
		sleep(1);
		
#ifdef	DET_WPS_SPEC
	if (pCtx->current_config_mode == CONFIG_METHOD_PIN) {

		if (pSta->state == ST_WAIT_M5 || pSta->state == ST_WAIT_M7) {
			report_WPS_STATUS(PROTOCOL_PIN_NUM_ERR );
			_DEBUG_PRINT("\n\ninput client's PIN-code is wrong\n\n");  //error case1
			if (wlioctl_set_led(LED_WSC_ERROR) < 0) {
				DEBUG_ERR("issue wlan ioctl set_led error!\n");
			}		
		}
	}
#ifdef	DET_WPS_SPEC_DEBUG
	else{
		_DEBUG_PRINT("\n\n pktHandler_wsc_nack() and not in PIN method\n\n");
	}
#endif	
#endif


#ifdef BLOCKED_ROGUE_STA
		if (pCtx->blocked_expired_time &&
			(pSta->state >= ST_WAIT_M4 && pSta->state <= ST_WAIT_M8) &&
			(pCtx->sta_invoke_reg == pSta && pCtx->registration_on >= 1) &&
			(pSta->ap_role != ENROLLEE)) {
			add_into_blocked_list(pCtx, pSta);
		}
		else
#endif
		{
			IssueDisconnect(pSta->addr, 1);	
			RX_DEBUG("IssueDisconnect\n\n");
		}		
#ifdef	DET_WPS_SPEC
		/*when client config me(AP as ENROLLEE) and don't do any change ; finally we should shutdown LED*/
		if(pSta->state == ST_WAIT_M8 
			&& pCtx->auto_lock_down == 0
			&& pCtx->role != PROXY
		){
			pCtx->LedTimeout = 15 ;
			DET_DEBUG("Setting LedTimeout = 15 secs\n");
		}
#endif			
		reset_sta(pCtx, pSta, 1);
	}
	else {
		send_wsc_nack(pCtx, pSta, CONFIG_ERR_NO_ERR);
		pSta->state = ST_WAIT_EAP_FAIL;
		pSta->tx_timeout = pCtx->tx_timeout;
		pSta->retry = 0;
	}

	return 0;	
}

int pktHandler_wsc_done(CTX_Tp pCtx, STA_CTX_Tp pSta)
{
	char tmp[40];	// 2011-0830 add	

	DBFENTER;

	_DEBUG_PRINT("\n<< Receive WSC_Done packet\n");
	//report_WPS_STATUS(PROC_EAP_DONE);
	report_WPS_STATUS(PROTOCOL_SUCCESS);		

#ifdef P2P_SUPPORT
	unsigned char Report2wlan ;
#endif
    
	if (pSta->state != ST_WAIT_DONE 
#ifdef SUPPORT_UPNP		
		&& pSta->state != ST_UPNP_WAIT_DONE
#endif		
		) {
		RX_DEBUG("Invalid state [%d]!\n", pSta->state);
		return 0;
	}
	if (pCtx->is_ap) {
		if (send_eap_fail(pCtx, pSta) < 0) {
			DEBUG_ERR("send_eap_fail() error!\n");
			return -1;
		}

#ifdef MUL_PBC_DETECTTION
		if (IS_PBC_METHOD(pCtx->config_method) && pSta->device_password_id == PASS_ID_PB &&
			!pCtx->disable_MulPBC_detection) 
		{
			WSC_pthread_mutex_lock(&pCtx->PBCMutex);
			//RX_DEBUG("rm pbc sta from list\n");			
			remove_active_pbc_sta(pCtx, pSta->addr, 1);
			WSC_pthread_mutex_unlock(&pCtx->PBCMutex);
			//DEBUG_PRINT("%s %d unlock PBC mutex\n", __FUNCTION__, __LINE__);
		}
#endif

#ifndef __ECOS //TBD
		/* 2011-0830 add ;Registrat mode; 
			Record enrollee's mac addr that last success wps with me*/
		sprintf(tmp, "echo %02X:%02X:%02X:%02X:%02X:%02X > %s", 
			pSta->addr[0],pSta->addr[1],
			pSta->addr[2],pSta->addr[3],
			pSta->addr[4],pSta->addr[5],
			WSCD_LAST_SUCCESS_ENROLLEE);
		system(tmp);
		/* 2011-0830 */
#endif		

		DEBUG_PRINT("WPS protocol down(SUCCESS)\n");

		//sleep(1); // wait a while till eap-fail is sent-out 

		// Reason code 1 : Unspecified reason	
		if (!pCtx->disable_disconnect 
#ifdef	CONFIG_RTL865x_KLD_REPEATER
		&& strcmp(pCtx->wlan_interface_name ,"wlan0-vxd")
#endif
		)
		{
			RX_DEBUG("IssueDisconnect\n");
			IssueDisconnect(pSta->addr, 1);
		}

#ifdef P2P_SUPPORT
        //indicate wlan driver that  WPS is success
        Report2wlan = GO_WPS_SUCCESS ;
        if (ReportWPSstate(GET_CURRENT_INTERFACE, &Report2wlan) < 0) {
            WSC_DEBUG("\n   Report p2p WPS state fail \n");
        }
        
        WSC_DEBUG("Report P2P GO WPS success\n");               
#endif
		reset_sta(pCtx, pSta, 1);
		reset_ctx_state(pCtx);	
		
		/* start blinking when success*/
		if (wlioctl_set_led(LED_WSC_SUCCESS) < 0) {
			DEBUG_ERR("issue wlan ioctl set_led error!\n");	
		}

	}
	else {		
		if (send_wsc_ack(pCtx, pSta) < 0) {
			if (pSta->invoke_security_gen)
				pSta->invoke_security_gen = 0;
			DEBUG_ERR("send_wsc_ack() error!\n");
			return -1;
		}

		if (pSta->invoke_security_gen
#ifdef P2P_SUPPORT
           || (pCtx->p2p_trigger_type==P2P_PRE_GO)
#endif
        ) 
        {

#ifdef FOR_DUAL_BAND
			if(pCtx->InterFaceComeIn == COME_FROM_WLAN1)
				pCtx->wait_reinit = write_param_to_flash2(pCtx, 1);  //  1001
		    else
#endif
		        pCtx->wait_reinit = write_param_to_flash(pCtx, 1);

			
			pSta->invoke_security_gen = 0;
		}
		else {
			if (pSta->state == ST_WAIT_DONE)
				pCtx->wait_reinit = REINIT_SYS;
		}
		
		pSta->state = ST_WAIT_EAP_FAIL;
		pSta->tx_timeout = pCtx->tx_timeout;
		pSta->retry = 0;		
	}
	return 0;
}



int pktHandler_eap_fail(CTX_Tp pCtx, STA_CTX_Tp pSta)
{
	DBFENTER;
	
	_DEBUG_PRINT("\n<< Receive EAP FAIL packet\n");

	#ifdef FULL_SECURITY_CLONE
	if(!pCtx->is_ap && pCtx->TagAPConfigStat==1){
		waitingClonedAP(pCtx);
	}
	#endif




#if	0	//def WSC_CLIENT_MODE	 
	/*2011-0728 sgs item 5.4.3 ; IssueDisconnect will move to connect_wps_ap ; and wlan driver 
     need do chk*/
	/*2011-07-20 ;PlusWang; everytime STA mode rx eap-fail ; we must issue disconnect
	  to AP that we nego with ,else some AP  eg BroadCom will don't care our EAPOL_START packet	
	  on next run , test environment (i am STAUT)--IO-DATA(i guess it is BroadCom AP)----WIN7(ER)*/
	if (!pCtx->is_ap) {	
		RX_DEBUG("enrollee RX EAP-fail IssueDisconnect to REG\n");
		MAC_PRINT(pSta->addr);
		IssueDisconnect(pSta->addr, 1);
	}
#endif			



	
	if (pCtx->wait_reinit) {

		report_WPS_STATUS(PROTOCOL_SUCCESS);
		if (wlioctl_set_led(LED_WSC_SUCCESS) < 0) {
			DEBUG_ERR("issue wlan ioctl set_led error!\n");	
		}
		
		RX_DEBUG("	Success!, signal_webs wait to reinit\n");
		signal_webs(pCtx->wait_reinit);	
		pCtx->STAmodeSuccess = 1;
		reset_ctx_state(pCtx);

	}
     #ifdef P2P_SUPPORT
     if(pCtx->p2p_trigger_type==P2P_PRE_CLIENT && strlen(pCtx->p2p_peers_ssid)>9){
        RX_DEBUG("P2P_PRE_CLIENT do WPS DONE\n");
        wlioctl_report_ssid_psk(GET_CURRENT_INTERFACE,pCtx->p2p_peers_ssid,pCtx->p2p_peers_psk);
		reset_ctx_state(pCtx);                
        RX_DEBUG("p2p_peers_ssid[%s]\n",pCtx->p2p_peers_ssid);
        RX_DEBUG("p2p_peers_psk[%s]\n",pCtx->p2p_peers_psk);        
     }
     #endif		

	// Reason code 1 : Unspecified reason
	if (pCtx->is_ap && !pCtx->disable_disconnect) {//should not happen; just in case
#ifdef BLOCKED_ROGUE_STA
		if (pCtx->blocked_expired_time &&
			(pSta->state >= ST_WAIT_M4 && pSta->state <= ST_WAIT_M8) &&
			(pCtx->sta_invoke_reg == pSta && pCtx->registration_on >= 1) &&
			(pSta->ap_role != ENROLLEE)) {
			add_into_blocked_list(pCtx, pSta);
		}
		else
#endif
		{
			IssueDisconnect(pSta->addr, 1);
			RX_DEBUG("IssueDisconnect\n\n");
		}
	}

	reset_sta(pCtx, pSta, 1);
	RX_DEBUG("\n");		
	return 0;
}

int pktHandler_wsc_msg(CTX_Tp pCtx, STA_CTX_Tp pSta, struct eap_wsc_t * wsc, int len)
{
	unsigned char *pMsg, *pData;
	int msg_len, tag_len, ret=0;
	
	DBFENTER;

#ifdef FOR_DUAL_BAND
#ifdef DEBUG
	if(pCtx->debug2){
		if(pCtx->InterFaceComeIn == COME_FROM_WLAN1){
			RX_DEBUG("nego with %s\n", pCtx->wlan_interface_name2);
		}else 	if(pCtx->InterFaceComeIn == COME_FROM_WLAN0){
			RX_DEBUG("nego with %s\n", pCtx->wlan_interface_name);
		}else{
			RX_DEBUG("nego with ?\n");
		}
	}
#endif	
#endif
	
#ifdef SUPPORT_UPNP
	if (pSta->used & IS_UPNP_CONTROL_POINT) {
		msg_len = len;
		pMsg = ((struct WSC_packet *)wsc)->rx_buffer;		
	}
	else
#endif
	{
		msg_len = len - sizeof(struct eap_wsc_t);
		pMsg = (((unsigned char *)wsc) + sizeof(struct eap_wsc_t));
	}

#ifdef SUPPORT_UPNP
	if (pSta->state == ST_UPNP_WAIT_M1) { 
		pData = search_tag(pMsg, TAG_MSG_TYPE, msg_len, &tag_len);
		if (pData == NULL) {
			RX_DEBUG("Can't find TAG_MSG_TYPE\n");
			#ifdef DEBUG
			if(pCtx->debug2){
				wsc_debug_out("pmsg from Enroller",pMsg , msg_len);
			}
			#endif
			return -1;
		}
		if (pData[0] == MSG_TYPE_M1) {
			pSta->tx_timeout = 0;
			pSta->state = ST_UPNP_PROXY;
		}
		else {
			RX_DEBUG("Invalid Message Type [%d]! for UPnP-proxy\n", pData[0]);
			return -1;					
		}		
	}

	if (pSta->state == ST_UPNP_PROXY ||
		pSta->state == ST_UPNP_WAIT_DONE) { // UPnP msg, forward to ER
		
		struct WSC_packet packet;

		packet.EventType = WSC_8021XEAP_FRAME;
		packet.EventID = WSC_PUTWLANREQUEST;
		sprintf(packet.EventMac, "%02x:%02x:%02x:%02x:%02x:%02x",
			pSta->addr[0], pSta->addr[1], pSta->addr[2],
			pSta->addr[3], pSta->addr[4], pSta->addr[5]);
		packet.tx_buffer = pMsg;
		packet.tx_size = msg_len;		

		_DEBUG_PRINT("\n>> Forward STA's ( ");
#ifdef DEBUG
		pData = search_tag(pMsg, TAG_MSG_TYPE, msg_len, &tag_len);
	    if(pData[0]==MSG_TYPE_M1){
			_DEBUG_PRINT("M1");
	 	}else if(pData[0]==MSG_TYPE_M3){
			_DEBUG_PRINT("M3");	
		}else if(pData[0]==MSG_TYPE_M5){
			_DEBUG_PRINT("M5");
		}else if(pData[0]==MSG_TYPE_M7){
			_DEBUG_PRINT("M7");				
		}else if(pData[0]==MSG_TYPE_ACK){
			_DEBUG_PRINT("ACK");				
		}else if(pData[0]==MSG_TYPE_NACK){
			_DEBUG_PRINT("NACK");
		}else if(pData[0]==MSG_TYPE_DONE){
			_DEBUG_PRINT("DONE");			
		}
#endif			
		_DEBUG_PRINT(" ) to ER\n");
			   
		if (WSCUpnpTxmit(&packet) != WSC_UPNP_SUCCESS) {
			DEBUG_ERR("WSCUpnpTxmit() return error!\n");
			return -1;			
		}
		return 0;
	}
#ifdef DEBUG	
	else{	// 2011-0502 for debug 
		if(pSta->state == ST_WAIT_ACK){
			RX_DEBUG("Rx M2D before ,state change to ST_WAIT_ACK ,no forwarding EAP to Upnp\n");
			MAC_PRINT(pSta->addr);
		}
	}
#endif	
#endif

	pData = search_tag(pMsg, TAG_VERSION, msg_len, &tag_len);
	if (pData == NULL) {
		DEBUG_ERR("Can't find TAG_VERSION\n");
		return -1;
	}

	//DEBUG_PRINT("Version: len=%d, val=0x%x\n", tag_len, pData[0]);

#ifdef WPS2DOTX
	unsigned char *StmpPtr = pMsg;
	int msg_len_tmp = msg_len;
	int wvfound = 0;
	for (;;)
	{
		pData = search_tag(StmpPtr, TAG_VENDOR_EXT, msg_len_tmp, &tag_len);	
		if (pData != NULL) {
			if(!memcmp(pData , WSC_VENDOR_OUI ,3 ))
			{
				//RX_DEBUG("found WFA vendor OUI!!\n");
				#ifdef DEBUG
				if(pCtx->debug2){
					wsc_debug_out("verdor ext:",pData,tag_len );				
				}
				#endif
				
				wvfound = 1 ;
				break;
			}else{
				StmpPtr = pData + 4 + tag_len ;
				msg_len_tmp = msg_len - (int)((unsigned long)StmpPtr - (unsigned long)pMsg)  ;
			}				
		}
		else{
			break;
		}
	}
    #if 0   //def PRINT_ERR    
	if(wvfound){
		int lent2=0;
		StmpPtr = search_VendorExt_tag(pData ,VENDOR_VERSION2 , tag_len , &lent2);

		if(StmpPtr){
			RX_DEBUG("Rev version2(0x%x) EAP\n",StmpPtr[0]);
		}

	}	
    #endif    
#endif

	if (pData) { //sanity check
		DEBUG_PRINT2("Version: len=%d, val=0x%x\n", tag_len, pData[0]);
	}

	pData = search_tag(pMsg, TAG_MSG_TYPE, msg_len, &tag_len);
	if (pData == NULL) {
		DEBUG_ERR("Can't find TAG_MSG_TYPE\n");
		return -1;
	}

	DEBUG_PRINT2("Message Type: len=%d, val=0x%x\n", tag_len, pData[0]);

	pSta->last_rx_msg = pMsg;
	pSta->last_rx_msg_size = msg_len;

#ifdef SUPPORT_UPNP
	if ((pSta->used & IS_UPNP_CONTROL_POINT) &&
			(pData[0] != MSG_TYPE_M2 && pData[0] != MSG_TYPE_M4 &&
			pData[0] != MSG_TYPE_M6 && pData[0] != MSG_TYPE_M8 &&
			pData[0] != MSG_TYPE_NACK && pData[0] != MSG_TYPE_M2D)) {
		RX_DEBUG("Invalid Message Type [%d]! for UPnP\n", pData[0]);
		return -1;		
	}

	if ((pSta->used & IS_UPNP_CONTROL_POINT) && (pData[0] == MSG_TYPE_NACK)) {
		RX_DEBUG("\n>>Receive WSC NACK from UPnP\n");
		return CONFIG_ERR_CANNOT_CONNECT_TO_REG;
	}
#endif

	switch (pData[0]) {
#ifdef SUPPORT_REGISTRAR		
		case MSG_TYPE_M1:
			ret = msgHandler_M1(pCtx, pSta, pMsg, msg_len);

#ifdef	DET_WPS_SPEC

		char tmpbuf[MAX_DEVICE_NAME_LEN+1];
		FILE *fp=NULL;
		fp = fopen(M1_TEMP_FILE, "w+");		// can R/W
		if(fp){
			if(pCtx->M1MacAddr[1]!= 0x0 || pCtx->M1MacAddr[2]!=0x0
				|| pCtx->M1MacAddr[3]!=0x0 )
			{
				sprintf(tmpbuf, "mac=%02x:%02x:%02x:%02x:%02x:%02x\n",
				pCtx->M1MacAddr[0],pCtx->M1MacAddr[1],pCtx->M1MacAddr[2],
				pCtx->M1MacAddr[3],pCtx->M1MacAddr[4],pCtx->M1MacAddr[5]);			
			
				fputs(tmpbuf, fp);

			}
			
			if(strlen(pCtx->M1DevName)){
				sprintf(tmpbuf, "device_name=\"%s\"\n",pCtx->M1DevName);				
				fputs(tmpbuf, fp);

			}

			
			fclose(fp);			
		}
#endif
			return ret;
		case MSG_TYPE_M3:
			return msgHandler_M3(pCtx, pSta, pMsg, msg_len);
		
		case MSG_TYPE_M5:
			return msgHandler_M5(pCtx, pSta, pMsg, msg_len);

		case MSG_TYPE_M7:
			return msgHandler_M7(pCtx, pSta, pMsg, msg_len);
#endif // SUPPORT_REGISTRAR

#ifdef SUPPORT_ENROLLEE
		case MSG_TYPE_M2:
		case MSG_TYPE_M2D:
		{
			if (pData[0] == MSG_TYPE_M2) {
				WSC_pthread_mutex_lock(&pCtx->RegMutex);

				if (pCtx->registration_on >= 1 && pCtx->sta_invoke_reg != pSta) {
					RX_DEBUG("Registration protocol is already in progress; ignore M2\n");
					/*
						Reason code 5 : Disassociated because AP is unable to 
						handle all currently associated stations
					*/ 
					if (!(pSta->used & IS_UPNP_CONTROL_POINT) && pCtx->is_ap) {
						IssueDisconnect(pSta->addr, 5);						
						RX_DEBUG("IssueDisconnect\n\n");
						reset_sta(pCtx, pSta, 1);
					}
					WSC_pthread_mutex_unlock(&pCtx->RegMutex);
					return CONFIG_ERR_DEV_BUSY;
				}
				else { //still possible for proxy ?
					if (pCtx->role != ENROLLEE) {
						pCtx->role = ENROLLEE;
						DEBUG_PRINT("Change role to Enrollee\n");
					}
					pCtx->registration_on = 1;
					pCtx->sta_invoke_reg = pSta;

					DEBUG_PRINT2("set registration_on to %d\n", pCtx->registration_on);

					
					if (pCtx->pb_pressed) {
						strcpy(pCtx->pin_code, "00000000");
						//RX_DEBUG("set pCtx->pin_code = 00000000 due to PBC\n");
					}
				}
				WSC_pthread_mutex_unlock(&pCtx->RegMutex);
			}
			ret = msgHandler_M2(pCtx, pSta, pMsg, msg_len, (int)pData[0]);
			return ret;
		}
			
		case MSG_TYPE_M4:
			return msgHandler_M4(pCtx, pSta, pMsg, msg_len);
			
		case MSG_TYPE_M6:
			return msgHandler_M6(pCtx, pSta, pMsg, msg_len);
			
		case MSG_TYPE_M8:
			return msgHandler_M8(pCtx, pSta, pMsg, msg_len);			
#endif // SUPPORT_ENROLLEE

		default:
			DEBUG_ERR("Invalid Message Type [%d]!\n", pData[0]);
	}

	return 0;		
}		


#ifdef SUPPORT_UPNP
int pktHandler_upnp_select_msg(CTX_Tp pCtx, STA_CTX_Tp pSta, struct WSC_packet *packet)
{
	unsigned char *pData;
	int tag_len, len;
	unsigned char selectedReg;
	unsigned short passid=0, method=0;
	unsigned char tmpbuf[256];
#ifdef WPS2DOTX
	unsigned char tmpMac[6+1];	
#endif
	DBFENTER;
	
	_DEBUG_PRINT("\n<< Rec UPnP SetSelectedRegistrar msg>>\n\n");

	if (pCtx->registration_on >= 1 && pCtx->sta_invoke_reg != pSta) {
		DEBUG_PRINT("%s %d Registration protocol is already in progress; abort  UPnP SetSelectedRegistrar msg!\n", __FUNCTION__, __LINE__);
		return -1;
	}
		
	if (!( pCtx->is_ap && 
		   (pCtx->role == REGISTRAR || pCtx->role == PROXY) 
		  // &&   (pCtx->original_role != ENROLLEE)//For fix issue: unconfigured state can not pass DTM-case 651
		  )) 
	{
		DEBUG_PRINT("\n<<!!! Unable to set UPnP SetSelectedRegistrar flag>>\n");
		RX_DEBUG("pCtx->is_ap =%d \n",pCtx->is_ap);
		RX_DEBUG("pCtx->role =%d ; PROXY=0, ENROLLEE=1, REGISTRAR=2\n",pCtx->role);
		RX_DEBUG("pCtx->original_role =%d \n",pCtx->original_role);		
					
		return -1;
	}
			
	pData = check_tag(pCtx, packet->rx_buffer, packet->rx_size, TAG_VERSION, 1, "Version", TYPE_BYTE, &tag_len);
	if (pData == NULL){
		RX_DEBUG(" TAG_VERSION == NULL, return\n");
		return -1;
	}
	
	pData = check_tag(pCtx, packet->rx_buffer, packet->rx_size, TAG_SELECTED_REGITRAR, 1, "SelectedRegistrar", TYPE_BYTE, &tag_len);
	if (pData == NULL){
		RX_DEBUG(" TAG_SELECTED_REGITRAR == NULL, return\n");
		return -1;
	}

	selectedReg = pData[0];
	
#ifdef WPS2DOTX
	unsigned char *StmpPtr=NULL ;
	//	int msg_len_tmp = packet->rx_size;
	int wvfound = 0;
	int lent2=0;
	
	// just for check if have some one include TAG_AUTHORIZED_MACs in EAP
	//pData = check_tag(pCtx, packet->rx_buffer, packet->rx_size, TAG_AUTHORIZED_MACs,
	//ETHER_ADDRLEN,"AuthorizedMACs", TYPE_BIN, &tag_len);
	//if(pData)
	//	RX_DEBUG("found TAG_AUTHORIZED_MACs at upnp SelReg packet\n");


	//pData = check_tag(pCtx, packet->rx_buffer, packet->rx_size, TAG_VENDOR_EXT,
	//		MAX_VENEXT_LEN,"VENDOR_EXT", TYPE_BYTE, &tag_len);

	pData = search_tag(packet->rx_buffer, TAG_VENDOR_EXT,  packet->rx_size, &tag_len);
	if (pData == NULL) {
		RX_DEBUG("\n can't find TAG_VENDOR_EXT!\n");
	}
	
	// just for debug
	//wsc_debug_out("message form ER:",packet->rx_buffer,packet->rx_size );

	if (pData != NULL) {
		if(!memcmp(pData , WSC_VENDOR_OUI ,3 ))
		{
			//RX_DEBUG("WFA vendor OUI!!\n");
			wsc_debug_out("verdor ext:",pData,tag_len );				
			wvfound = 1 ;

		}				
	}
	if(wvfound){	/* include VENDOR_EXT tag */ 

		StmpPtr = search_VendorExt_tag(pData ,VENDOR_VERSION2 , tag_len , &lent2);
		if(StmpPtr){
			RX_DEBUG("Rev version2(0x%x) EAP\n",StmpPtr[0]);
		}
		
		if(selectedReg){
			StmpPtr = search_VendorExt_tag(pData ,VENDOR_AUTHMAC , tag_len , &lent2);
			if(StmpPtr){
				RX_DEBUG("Include AuthMAC[%x:%x:%x:%x:%x:%x] from ER\n",
					StmpPtr[0],StmpPtr[1],StmpPtr[2],StmpPtr[3],StmpPtr[4],StmpPtr[5]);				
				registrar_add_authorized_mac(pCtx , StmpPtr);
			}else{
				/*no assigned ; add wildcard addr*/ 
				RX_DEBUG("no assigned AuthMac; add wildcard addr\n");				
				registrar_add_authorized_mac(pCtx , BroadCastMac);
			}		
		}
	}else{
		if(selectedReg){
			/*no assigned ; add wildcard addr*/ 
			RX_DEBUG("no assigned AuthMac; add wildcard addr\n");							
			registrar_add_authorized_mac(pCtx , BroadCastMac);
		}
	}
		
#endif




	if (selectedReg) {
		pData = check_tag(pCtx, packet->rx_buffer, packet->rx_size, TAG_DEVICE_PASSWORD_ID, 2, "DevicePasswordID", TYPE_WORD, &tag_len);
		if (pData == NULL){
			RX_DEBUG(" TAG_DEVICE_PASSWORD_ID == NULL, return\n");
			return -1;
		}
		
		memcpy(&passid, pData, 2);

		pData = check_tag(pCtx, packet->rx_buffer, packet->rx_size, TAG_SEL_REG_CONFIG_METHODS, 2, 								
				"SelectedRegistrarConfigMethod", TYPE_WORD, &tag_len);
		if (pData == NULL){
			RX_DEBUG(" TAG_SEL_REG_CONFIG_METHODS == NULL, return\n");
			return -1;
		}
		memcpy(&method, pData, 2);

		pCtx->setSelectedRegTimeout = SETSELREG_WALK_TIME;
		memcpy(pCtx->SetSelectedRegistrar_ip, packet->IP, IP_ADDRLEN);

		// for DNI request ; when AP as proxy role ; don't blink LED as START mode.(0721-2009)
#ifndef DET_WPS_SPEC
		if (wlioctl_set_led(LED_WSC_START) < 0) {
			DEBUG_ERR("issue wlan ioctl set_led error!\n");
		}
#endif		

#ifdef WPS2DOTX	// HIDDEN_AP Deprecated in 2.0

#else
		if (pCtx->is_ap && pCtx->disable_hidden_ap)
		{
			//DISABLE_HIDDEN_AP(pCtx, tmpbuf);
#ifdef	FOR_DUAL_BAND
			if(pCtx->wlan0_wsc_disabled==0)
#endif				
			{
				sprintf((char*)tmpbuf,"iwpriv %s set_mib wsc_enable=4", pCtx->wlan_interface_name); 
				system((char*)tmpbuf); 
			}
#ifdef	FOR_DUAL_BAND
			if(pCtx->wlan1_wsc_disabled==0)
			{
				sprintf((char*)tmpbuf,"iwpriv %s set_mib wsc_enable=4", pCtx->wlan_interface_name2); 
				system((char*)tmpbuf); 
			}
#endif
		}
#endif		
		
		if (pCtx->is_ap)
			pCtx->wps_triggered = 1;	
		
#ifdef MUL_PBC_DETECTTION		
		if (pCtx->SessionOverlapTimeout) {
			DEBUG_PRINT("Clear session overlapping stuff!\n");
			pCtx->SessionOverlapTimeout = 0;
		}
#endif		
		if(pCtx->pb_timeout || pCtx->pb_pressed) {
			RX_DEBUG("Clear PBC stuff!\n");
			pCtx->pb_pressed = 0;
			pCtx->pb_timeout = 0;
			pCtx->pin_assigned = 0;
		}
		if (pCtx->pin_timeout) {
			DEBUG_PRINT("Clear PIN stuff!\n");
			pCtx->pin_timeout = 0; //clear PIN timeout
			pCtx->pin_assigned = 0;
		}
	}
	else{
		pCtx->setSelectedRegTimeout = 0;
		#ifdef WPS2DOTX
		registrar_remove_authorized_mac(pCtx , tmpMac);		
		#endif
	}

	if (pCtx->use_ie) {
		len = build_beacon_ie(pCtx, selectedReg, passid, method, tmpbuf);

	#ifndef WPS2DOTX
		if (pCtx->encrypt_type == WSC_ENCRYPT_WEP) // add provisioning service ie
		{
			len += build_provisioning_service_ie((unsigned char *)(tmpbuf+len));
		}
	#endif	

        if (wlioctl_set_wsc_ie(tmpbuf, len,DOT11_EVENT_WSC_SET_IE, SET_IE_FLAG_BEACON) < 0)
            return -1;  
	
		len = build_probe_rsp_ie(pCtx, selectedReg, passid, method, tmpbuf);

	#ifndef WPS2DOTX
		if (pCtx->encrypt_type == WSC_ENCRYPT_WEP) // add provisioning service ie
		{
			len += build_provisioning_service_ie((unsigned char *)(tmpbuf+len));
		}
	#endif
		
		if (len > MAX_WSC_IE_LEN) {
			DEBUG_ERR("Length of IE exceeds %d\n", MAX_WSC_IE_LEN);
			return -1;
		}
        if (wlioctl_set_wsc_ie(tmpbuf, len, DOT11_EVENT_WSC_SET_IE, SET_IE_FLAG_PROBE_RSP) < 0)
            return -1;
	}

#ifdef BLOCKED_ROGUE_STA
	if (pCtx->is_ap && pCtx->blocked_expired_time)
		disassociate_blocked_list(pCtx);
#endif

	return 0;	
}
#endif // SUPPORT_UPNP
