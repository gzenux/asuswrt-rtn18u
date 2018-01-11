
#include <sys/types.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "1x_config.h"
#include "1x_common.h"
#include "1x_ioctl.h"
#include "1x_radius.h"

#ifdef RTL_WPA2
typedef enum
{
	EncModeMap_WEP = 0x01,
	EncModeMap_WPA = 0x02,
	EncModeMap_WPA2 = 0x04,
}EnModeMap;

#endif

typedef enum
{
	EncAlgoMap_TKIP = 0x01,
	EncAlgoMap_AES = 0x02,
}EncAlgoMap;

typedef enum
{
	NonWPA_WEP = 0x01,
	NonWPA_DOT1X = 0x02,
}NonWPAMAP;

char * lib1x_config_err(int err)
{

        switch(err)
        {
		case ERROR_FILE_NOTEXIST:
                        return CFG_STRERROR_FILE_NOTEXIST;
                case ERROR_UNDEFINE_PARAMETER:
                        return CFG_STRERROR_UNDEFINE_PARAMETER;
		case ERROR_UNDEFINE_TAG:
			return CFG_STRERROR_UNDEFINE_TAG;
        }
        return "Uknown Failure";
}


//--------------------------------------------------------------------------
//  Reads a tag out of a file in the form
//  tag = value
//  return 0 on success -1 on fail
//--------------------------------------------------------------------------
/*
int lib1x_config_parse(char *confFileName, char *confTag, char *confVal) {

	FILE *confFile = fopen(confFileName, "r");
	char tmpTag[CONFIG_PARSE_TAG], tmpVal[CONFIG_PARSE_VALUE];

	if (confFile == NULL) {
		return ERROR_FILE_NOTEXIST;
	}
	while (fscanf(confFile, "%s = %s", tmpTag, tmpVal) != EOF) {
		if (strcmp(confTag, tmpTag) == 0 && strlen(tmpVal) < CONFIG_PARSE_VALUE) {
			printf("confTag = %s,tmpVal = %s\n", confTag,tmpVal);
			strncpy(confVal, tmpVal, CONFIG_PARSE_VALUE);
			fclose(confFile);
			return 0;
		}

	}

	fclose(confFile);

	return ERROR_UNDEFINE_TAG;
}
*/


int lib1x_config_parse(char *confFileName, char *confTag, char *confVal)
{
        FILE *confFile = fopen(confFileName, "r");
        char tmpTag[CONFIG_PARSE_TAG], tmpVal[CONFIG_PARSE_VALUE];
	char tmps[CONFIG_PARSE_TAG+CONFIG_PARSE_VALUE];
	char *ptr = &tmps[0];
	int lenTag, lenVal;


	if (confFile == NULL) {
                return ERROR_FILE_NOTEXIST;
        }

	while( fgets( tmps, CONFIG_PARSE_TAG+CONFIG_PARSE_VALUE, confFile ) ){

        //printf("%s", tmps);
        //printf("[%c|0x%02x]",*ptr,*ptr);

		ptr = &tmps[0];

		lenTag = 0;
		do{
			lenTag ++;
		}while( *ptr++ != '=' && lenTag < CONFIG_PARSE_TAG );
		lenTag -= 2;	//remove ' ' and '='

		strncpy( tmpTag, tmps, lenTag );
		tmpTag[lenTag] = 0;

		ptr += 1 ;

		if( *ptr == '"' ){
		    int idx=0;
		  	ptr++;
			for (lenVal=0; ;lenVal++) {
				if (ptr[lenVal] == '\n')
					break;
			}
			for (idx=lenVal; idx>0; idx--) {
				if (ptr[idx] == '"')
					break;
			}
			lenVal = idx;
 			strncpy( tmpVal, &tmps[lenTag+4], lenVal );
		        tmpVal[lenVal] = 0;
		  
		}
		else{
			lenVal = 0;
			do{
				lenVal++;
			}while( /**ptr++ != 0 &&*/ *ptr++ != 0x0a && lenVal < CONFIG_PARSE_VALUE ); // 0x0a == end of line
			lenVal -= 1;
	                strncpy( tmpVal, &tmps[lenTag+3], lenVal );
	                tmpVal[lenVal] = 0;
		}

		//printf("\n(a) lenTag = %d, tmpTag = <%s>", lenTag, tmpTag);
		//printf("\n(b) lenVal = %d, tmpVal = <%s>", lenVal,  tmpVal);

		if (strcmp(confTag, tmpTag) == 0 && strlen(tmpVal) < CONFIG_PARSE_VALUE) {
                        //printf("\nconfTag = <%s>, tmpVal = <%s>\n", confTag,tmpVal);
			//lib1x_message(MESS_DBG_CONFIG, "confTag = <%s>, tmpVal = <%s>", confTag,tmpVal);


			strncpy(confVal, tmpVal, CONFIG_PARSE_VALUE);
                        fclose(confFile);
                        return 0;
		}

	}

        fclose(confFile);
        return ERROR_UNDEFINE_TAG;
}


void lib1x_config_text2bin(u_char * pucDst, u_char  * pucSrc, int len)
{
	int i = 0, j = 0;
	lib1x_message(MESS_DBG_CONFIG, "wepGroupKey = %s\n", pucSrc);
	for(i=0 ; i<len ; i+=2, j++)
	{
		pucDst[j] = 0x0;
		pucDst[j] |= (u_char)((pucSrc[i] & 0x0f) <<4);
		pucDst[j] |= (u_char)(pucSrc[i+1] & 0x0f);
	}
	//lib1x_hexdump2(MESS_DBG_CONFIG, "lib1x_config_text2bin", pucDst, j, "wepGroupKey After parsing");

}



//--------------------------------------------------------------------------
//  Init Algorithm Table
//  UniCastCipherSuit, MulticastCipherSuit, AuthenticationSuit
//--------------------------------------------------------------------------
void lib1x_init_algo(Dot1x_Authenticator * auth)
{

	u_long		ulAlgoSuit, ulAlgoTable;
#ifdef RTL_WPA2
	DOT11_AlgoSuit	* pAlgoSuit[4];


	pAlgoSuit[0] = &auth->RSNVariable.UniCastCipherSuit;
	pAlgoSuit[1] = &auth->RSNVariable.MulticastCipherSuit;
	pAlgoSuit[2] = &auth->RSNVariable.AuthenticationSuit;
	pAlgoSuit[3] = &auth->RSNVariable.WPA2UniCastCipherSuit;

	for(ulAlgoSuit = 0; ulAlgoSuit < 4; ulAlgoSuit++)
	{
		pAlgoSuit[ulAlgoSuit]->NumOfAlgo = DOT11_MAX_ALGORITHMS;
		for(ulAlgoTable = 0 ; ulAlgoTable < DOT11_MAX_ALGORITHMS ; ulAlgoTable++)
		{

			pAlgoSuit[ulAlgoSuit]->AlgoTable[ulAlgoTable].Index = ulAlgoTable;
			pAlgoSuit[ulAlgoSuit]->AlgoTable[ulAlgoTable].AlgoId = ulAlgoTable;
			pAlgoSuit[ulAlgoSuit]->AlgoTable[ulAlgoTable].Enabled = FALSE;
		}

	}
#else
	DOT11_AlgoSuit	* pAlgoSuit[3];


	pAlgoSuit[0] = &auth->RSNVariable.UniCastCipherSuit;
	pAlgoSuit[1] = &auth->RSNVariable.MulticastCipherSuit;
	pAlgoSuit[2] = &auth->RSNVariable.AuthenticationSuit;

	for(ulAlgoSuit = 0; ulAlgoSuit < 3; ulAlgoSuit++)
	{
		pAlgoSuit[ulAlgoSuit]->NumOfAlgo = DOT11_MAX_ALGORITHMS;
		for(ulAlgoTable = 0 ; ulAlgoTable < DOT11_MAX_ALGORITHMS ; ulAlgoTable++)
		{

			pAlgoSuit[ulAlgoSuit]->AlgoTable[ulAlgoTable].Index = ulAlgoTable;
			pAlgoSuit[ulAlgoSuit]->AlgoTable[ulAlgoTable].AlgoId = ulAlgoTable;
			pAlgoSuit[ulAlgoSuit]->AlgoTable[ulAlgoTable].Enabled = FALSE;
		}

	}
#endif
}

static int gain_wlan_index(unsigned char *name)
{
	unsigned char *ptr=NULL;
	unsigned int if_idx=-1,bss_idx=1,i,j,ret=0;

	ptr = strstr(name,"wlan");
	if( ptr ){
		if_idx = *(ptr+4)-'0'+1;
	}

	ptr = strstr(name,"-va");
	if( ptr ){
		bss_idx = *(ptr+3)-'0'+1;
	} else {
		bss_idx = 1;
	}

	for( i=0;i<if_idx;i++ )
		for( j=0;j<bss_idx;j++ )
			ret++;

	return ret;
}


//--------------------------------------------------------------------------
//  Reads configure file
//  return 0 on success -1 on fail
//--------------------------------------------------------------------------

int lib1x_load_config(Dot1x_Authenticator * auth, char *confFileName)
{

	char authTag[CONFIG_PARSE_TAG];
    	char authVal[CONFIG_PARSE_VALUE];
	int retResult;
	int tagIndex;
#ifdef RTL_RADIUS_2SET
	int rad2nd_ip = 0, rad2nd_port = 0, rad2nd_pswd = 0;
#endif



	DOT11_AlgoSuit	*pUnicast = &auth->RSNVariable.UniCastCipherSuit;
#ifdef RTL_WPA2
	DOT11_AlgoSuit	*pWPA2Unicast = &auth->RSNVariable.WPA2UniCastCipherSuit;
#endif
	DOT11_AlgoSuit  *pMulticast =  &auth->RSNVariable.MulticastCipherSuit;
	DOT11_AlgoSuit	*pAuth = &auth->RSNVariable.AuthenticationSuit;
	u_long	ulNumOfTag;

	u_long ulEnable1x = 0;
	u_long ulEncryption = 0;
	u_long ulAccountEnabled = 0;
	u_long ulUnicastCipher = 0;
#ifdef RTL_WPA2
        u_long ulWPA2UnicastCipher = 0;
#endif
	u_long ulWepKey = 0;
	u_long ulEnableMacAuth = 0;
	u_long ulUsePassphrase = 0;
	u_char szWepGroupKey[32];

	FILE *confFile = fopen(confFileName, "r");

#ifdef CONFIG_RTL8196C_AP_HCM
	auth->if_index = gain_wlan_index(confFileName);
#endif

	if (confFile == NULL) {
		fclose(confFile);
		return ERROR_FILE_NOTEXIST;
	}else
		fclose(confFile);


	lib1x_init_algo(auth);

	ulNumOfTag = sizeof(ConfigTag)/32;

#ifdef RTL_WPA2_PREAUTH
	// init
	auth->RSNVariable.isSupportPreAuthentication = FALSE;
#endif

	for(tagIndex=0 ; tagIndex< ulNumOfTag; tagIndex++)
	{

		memset(authTag, 0, sizeof authTag);
		strncpy(authTag, ConfigTag[tagIndex], strlen(ConfigTag[tagIndex]));

		if ( ! (retResult = lib1x_config_parse(confFileName, authTag, authVal)) ) {
			lib1x_message(MESS_DBG_CONFIG, "%s = %d", authTag, atoi(authVal));

		}else
		{
			lib1x_message(MESS_DBG_CONFIG, "%s->%s", lib1x_config_err(retResult), authTag);
			continue;
		}

		if(!strcmp(ConfigTag[tagIndex], "ssid"))
		{
			memset(auth->RSNVariable.ssid, 0, sizeof(auth->RSNVariable.ssid));
			memcpy(auth->RSNVariable.ssid, authVal, strlen(authVal));
			//printf("auth->RSNVariable.ssid = %s\n", auth->RSNVariable.ssid);
		}else if(!strcmp(ConfigTag[tagIndex], "enable1x"))
		{
			ulEnable1x = atoi(authVal);

		}else if(!strcmp(ConfigTag[tagIndex], "enableMacAuth"))
		{
			ulEnableMacAuth = atoi(authVal);

		}
		//---- Authentication Suit ----
		else if(!strcmp(ConfigTag[tagIndex], "authentication"))
		{

			if(atoi(authVal) == DOT11_AuthKeyType_RSN)
			{
				pAuth->AlgoTable[DOT11_AuthKeyType_RSN].Enabled = TRUE;
				lib1x_message(MESS_DBG_CONFIG, "authentication = %s\n","DOT11_AuthKeyType_RSN");
			}
			else if(atoi(authVal) == DOT11_AuthKeyType_RSNPSK)
			{
				pAuth->AlgoTable[DOT11_AuthKeyType_RSNPSK].Enabled = TRUE;
				lib1x_message(MESS_DBG_CONFIG, "authentication = %s\n","DOT11_AuthKeyType_RSNPSK");
			}
#ifdef CONFIG_IEEE80211R
			else if(atoi(authVal) == DOT11_AuthKeyType_FT)
			{
				pAuth->AlgoTable[DOT11_AuthKeyType_RSN].Enabled = TRUE;
				lib1x_message(MESS_DBG_CONFIG, "authentication = %s\n","DOT11_AuthKeyType_RSN");

				pAuth->AlgoTable[DOT11_AuthKeyType_FT].Enabled = TRUE;
				lib1x_message(MESS_DBG_CONFIG, "authentication = %s\n","DOT11_AuthKeyType_FT");
			}
#endif
#ifdef CONFIG_IEEE80211W
			else  if(atoi(authVal) == DOT11_AuthKeyType_802_1X_SHA256)
			{
				
				pAuth->AlgoTable[DOT11_AuthKeyType_RSN].Enabled = FALSE;
				pAuth->AlgoTable[DOT11_AuthKeyType_802_1X_SHA256].Enabled = TRUE;
				lib1x_message(MESS_DBG_CONFIG, "authentication = %s\n","DOT11_AuthKeyType_802_1X_SHA256");
			}	
#endif		

		}else if(!strcmp(ConfigTag[tagIndex], "unicastCipher"))
		{
			ulUnicastCipher = atoi(authVal);
			lib1x_message(MESS_DBG_CONFIG, "ulUnicastCipher = %d\n", ulUnicastCipher);
			pUnicast->AlgoTable[DOT11_ENC_TKIP].Enabled = (ulUnicastCipher & EncAlgoMap_TKIP) ? TRUE:FALSE;
			pUnicast->AlgoTable[DOT11_ENC_CCMP].Enabled = (ulUnicastCipher & EncAlgoMap_AES ) ? TRUE:FALSE;
		}
#ifdef CONFIG_IEEE80211W
		else if(!strcmp(ConfigTag[tagIndex], "ieee80211w"))
		{						
			auth->RSNVariable.ieee80211w = atoi(authVal);
			PMFDEBUG("11w=[%d]\n",auth->RSNVariable.ieee80211w);
		}

		else if(!strcmp(ConfigTag[tagIndex], "sha256"))
		{					
			//if(MGMT_FRAME_PROTECTION_REQUIRED != auth->RSNVariable.ieee80211w)
			auth->RSNVariable.sha256= atoi(authVal);
			pAuth->AlgoTable[DOT11_AuthKeyType_802_1X_SHA256].Enabled = atoi(authVal);	
			PMFDEBUG("sha256=[%d]\n",pAuth->AlgoTable[DOT11_AuthKeyType_802_1X_SHA256].Enabled);            
		}
#endif
#ifdef HS2_SUPPORT
		else if(!strcmp(ConfigTag[tagIndex], "OSEN"))
		{						
			auth->RSNVariable.bOSEN = atoi(authVal);
			HS2DEBUG("OSEN=[%d]\n",auth->RSNVariable.bOSEN);
		}
#endif
#ifdef RTL_WPA2
		else if(!strcmp(ConfigTag[tagIndex], "wpa2UnicastCipher"))
		{
			ulWPA2UnicastCipher = atoi(authVal);
			lib1x_message(MESS_DBG_CONFIG, "ulWPA2UnicastCipher = %d\n", ulWPA2UnicastCipher);
			pWPA2Unicast->AlgoTable[DOT11_ENC_TKIP].Enabled = (ulWPA2UnicastCipher & EncAlgoMap_TKIP) ? TRUE:FALSE;
			pWPA2Unicast->AlgoTable[DOT11_ENC_CCMP].Enabled = (ulWPA2UnicastCipher & EncAlgoMap_AES ) ? TRUE:FALSE;
		}
		else if(!strcmp(ConfigTag[tagIndex], "enablePreAuth"))
		{
			auth->RSNVariable.isSupportPreAuthentication = (atoi(authVal)==0? FALSE:TRUE);
		}
        else if(!strcmp(ConfigTag[tagIndex], "MaxPmksa"))
		{
			auth->RSNVariable.max_pmksa = atoi(authVal);
		}
#endif
		//---- RSN/TSN Enabled
		else if(!strcmp(ConfigTag[tagIndex], "encryption"))
		{
			ulEncryption = atoi(authVal);
#ifdef RTL_WPA2
			//(None/WEP/WPA/WPA2/WPA2-WPA-mixed) -->(0/1/2/4/6)
			auth->RSNVariable.WPAEnabled = (ulEncryption & EncModeMap_WPA)? TRUE:FALSE;
			auth->RSNVariable.WPA2Enabled = (ulEncryption & EncModeMap_WPA2)? TRUE:FALSE;
			auth->RSNVariable.RSNEnabled = (ulEncryption >= 2 )? TRUE:FALSE;
#else
			auth->RSNVariable.RSNEnabled = (atoi(authVal) == 2)? TRUE:FALSE;
#endif
		}
		else if(!strcmp(ConfigTag[tagIndex], "supportNonWpaClient"))
		{
			/*
			u_long ulNonWPA = atoi(authVal);
			auth->RSNVariable.Dot1xEnabled = (ulNonWPA & NonWPA_DOT1X) ? TRUE:FALSE;
			auth->RSNVariable.TSNEnabled = atoi(authVal) ? TRUE:FALSE;
			*/

		}else if(!strcmp(ConfigTag[tagIndex], "wepKey"))
		{
			ulWepKey = atoi(authVal);
			if(ulWepKey == 1)
				auth->RSNVariable.WepMode = DOT11_ENC_WEP40;
			else if(ulWepKey == 2)
				auth->RSNVariable.WepMode = DOT11_ENC_WEP104;
			else
				auth->RSNVariable.WepMode = DOT11_ENC_NONE;

		}else if(!strcmp(ConfigTag[tagIndex], "wepGroupKey"))
		{
			memset(szWepGroupKey, 0, sizeof szWepGroupKey);
			memcpy(szWepGroupKey, authVal, strlen(authVal));
		}
		//---- Authenticator config

		else if(!strcmp(ConfigTag[tagIndex], "groupRekeyTime"))
		{
			auth->Dot11RSNConfig.GroupRekeyTime = atoi(authVal);
		}

		//---- PassPhrase

		else if(!strcmp(ConfigTag[tagIndex], "psk"))
		{

			memset(auth->RSNVariable.PassPhrase, 0, sizeof(auth->RSNVariable.PassPhrase));
			memcpy(auth->RSNVariable.PassPhrase, authVal, strlen(authVal));

			//printf("strlen(authVal) = %d\n", strlen(authVal) );
			//printf("auth->RSNVariable.PassPhrase = %s\n", auth->RSNVariable.PassPhrase);

			//printf("Calculate PSK auth->RSNVariable.ssid = %s\n", auth->RSNVariable.ssid);

			//PasswordHash(auth->RSNVariable.PassPhrase, strlen(auth->RSNVariable.PassPhrase),
			//(unsigned char *)auth->RSNVariable.ssid, strlen(auth->RSNVariable.ssid), auth->RSNVariable.PassPhraseKey);

			//lib1x_hexdump2(MESS_DBG_CONFIG, "lib1x_config_parse",auth->RSNVariable.PassPhraseKey,
			//	sizeof(auth->RSNVariable.PassPhraseKey), "PassPhraseKey");


		}else if(!strcmp(ConfigTag[tagIndex], "usePassphrase"))
		{

			ulUsePassphrase = atoi(authVal);
			auth->UsePassphrase = ulUsePassphrase;
		}
		//---- Radius Server
		else if(!strcmp(ConfigTag[tagIndex], "rsPort"))
		{
			lib1x_message(MESS_DBG_CONFIG, "rsPort = %d\n", atoi(authVal));
			auth->udp_svrport = atoi(authVal);


		}else if(!strcmp(ConfigTag[tagIndex], "rsIP"))
		{
			lib1x_message(MESS_DBG_CONFIG, "rsIP = %s\n", authVal);
			memset(auth->svrip, 0, sizeof auth->svrip);
			memcpy(auth->svrip, authVal, strlen(authVal));



		}else if(!strcmp(ConfigTag[tagIndex], "rsPassword"))
		{

			auth->RadShared.Octet = (u_char*)malloc(LIB1X_RAD_SHARED);
			memset(auth->RadShared.Octet, 0, LIB1X_RAD_SHARED);
			memcpy(auth->RadShared.Octet, authVal, strlen(authVal));
			auth->RadShared.Length = strlen(authVal);
			lib1x_message(MESS_DBG_CONFIG, "Radius Shared Key = %s\n", auth->RadShared.Octet);

		}
#ifdef CONFIG_RTL8196C_AP_HCM
		else if(!strcmp(ConfigTag[tagIndex], "hostmac"))
		{
			memset(auth->hostmac,0,sizeof auth->hostmac);
			memcpy(auth->hostmac,authVal,strlen(authVal));
		}
#endif
#ifdef RTL_RADIUS_2SET
		else if(!strcmp(ConfigTag[tagIndex], "rs2Port"))
		{
			lib1x_message(MESS_DBG_CONFIG, "rs2Port = %d\n", atoi(authVal));
			auth->udp_svrport2 = atoi(authVal);
			rad2nd_port = 1;

		}else if(!strcmp(ConfigTag[tagIndex], "rs2IP"))
		{
			lib1x_message(MESS_DBG_CONFIG, "rs2IP = %s\n", authVal);
			memset(auth->svrip2, 0, sizeof auth->svrip2);
			memcpy(auth->svrip2, authVal, strlen(authVal));
			rad2nd_ip = 1;
		}else if(!strcmp(ConfigTag[tagIndex], "rs2Password"))
		{
			auth->RadShared2.Octet = (u_char*)malloc(LIB1X_RAD_SHARED);
			memset(auth->RadShared2.Octet, 0, LIB1X_RAD_SHARED);
			memcpy(auth->RadShared2.Octet, authVal, strlen(authVal));
			auth->RadShared2.Length = strlen(authVal);
			lib1x_message(MESS_DBG_CONFIG, "Radius2 Shared Key = %s\n", auth->RadShared2.Octet);
			rad2nd_pswd = 1;
		}else if(!strcmp(ConfigTag[tagIndex], "rs2enableMacAuth"))
		{
			if (atoi(authVal) == 1)
				auth->RSNVariable.rs2MacAuthEnabled = TRUE;
			else
				auth->RSNVariable.rs2MacAuthEnabled = FALSE;
		}
#endif
#if defined(CONFIG_RTL_802_1X_CLIENT_SUPPORT) || defined(CONFIG_RTL_ETH_802DOT1X_CLIENT_MODE_SUPPORT)
		else if(!strcmp(ConfigTag[tagIndex], "eapType")){
			auth->eapType = atoi(authVal);
		}
		else if(!strcmp(ConfigTag[tagIndex], "eapInsideType")){
			auth->eapInsideType = atoi(authVal);
		}
		else if(!strcmp(ConfigTag[tagIndex], "eapUserId")){
			memset(auth->eapUserId, 0, sizeof(auth->eapUserId));
			strcpy(auth->eapUserId,authVal);
		}
		else if(!strcmp(ConfigTag[tagIndex], "rsUserName")){
			memset(auth->rsUserName, 0, sizeof(auth->rsUserName));
			strcpy(auth->rsUserName,authVal);
		}
		else if(!strcmp(ConfigTag[tagIndex], "rsUserPasswd")){
			memset(auth->rsUserPasswd, 0, sizeof(auth->rsUserPasswd));
			strcpy(auth->rsUserPasswd,authVal);
		}
		else if(!strcmp(ConfigTag[tagIndex], "rsUserCertPasswd")){
			memset(auth->rsUserCertPasswd, 0, sizeof(auth->rsUserCertPasswd));
			strcpy(auth->rsUserCertPasswd,authVal);
		}
		else if(!strcmp(ConfigTag[tagIndex], "rsBandSel")){
			auth->rsBandSel = atoi(authVal);
		}
#endif
#ifdef RTL_TTLS_CLIENT
		else if(!strcmp(ConfigTag[tagIndex], "eapPhase2Type")){
			auth->ttlsPhase2Type = atoi(authVal);
		}
		else if(!strcmp(ConfigTag[tagIndex], "phase2EapMethod")){
			auth->ttlsPhase2EapMethod = atoi(authVal);
		}
#endif

		else if(!strcmp(ConfigTag[tagIndex], "rsMaxReq"))
		{
			auth->rsMaxReq = atoi(authVal);
			lib1x_message(MESS_DBG_CONFIG, "Radius Retry Max = %d\n", auth->rsMaxReq);

		}else if(!strcmp(ConfigTag[tagIndex], "rsAWhile"))
		{
			auth->rsAWhile = atoi(authVal);
			lib1x_message(MESS_DBG_CONFIG, "Radius Tx Period = %d\n", auth->rsAWhile);



		}
		else if(!strcmp(ConfigTag[tagIndex], "accountRsEnabled"))
		{
			ulAccountEnabled = atoi(authVal);
			lib1x_message(MESS_DBG_CONFIG, "accountRsEnabled = %d \n", ulAccountEnabled);

		}else if(!strcmp(ConfigTag[tagIndex], "accountRsPort"))
		{
			auth->udp_acctport = atoi(authVal);
		}else if(!strcmp(ConfigTag[tagIndex], "accountRsIP"))
		{
			memset(auth->acctip, 0, sizeof auth->acctip);
			memcpy(auth->acctip, authVal, strlen(authVal));

		}else if(!strcmp(ConfigTag[tagIndex], "accountRsPassword"))
		{
			auth->AcctShared.Octet = (u_char*)malloc(LIB1X_RAD_SHARED);
			memset(auth->AcctShared.Octet, 0, LIB1X_RAD_SHARED);
			memcpy(auth->AcctShared.Octet, authVal, strlen(authVal));
			auth->AcctShared.Length = strlen(authVal);
			lib1x_message(MESS_DBG_CONFIG, "Acct Shared Key = %s\n", auth->AcctShared.Octet);

		}
#ifdef RTL_RADIUS_2SET
		else if(!strcmp(ConfigTag[tagIndex], "accountRs2Port"))
		{
			auth->udp_acctport2 = atoi(authVal);
		}else if(!strcmp(ConfigTag[tagIndex], "accountRs2IP"))
		{
			memset(auth->acctip2, 0, sizeof auth->acctip2);
			memcpy(auth->acctip2, authVal, strlen(authVal));

		}else if(!strcmp(ConfigTag[tagIndex], "accountRs2Password"))
		{
			auth->AcctShared2.Octet = (u_char*)malloc(LIB1X_RAD_SHARED);
			memset(auth->AcctShared2.Octet, 0, LIB1X_RAD_SHARED);
			memcpy(auth->AcctShared2.Octet, authVal, strlen(authVal));
			auth->AcctShared2.Length = strlen(authVal);
			lib1x_message(MESS_DBG_CONFIG, "Accts Shared Key = %s\n", auth->AcctShared2.Octet);

		}
#endif
		else if(!strcmp(ConfigTag[tagIndex], "accountRsMaxReq"))
		{
			auth->accountRsMaxReq = atoi(authVal);

		}else if(!strcmp(ConfigTag[tagIndex], "accountRsAWhile"))
		{
			auth->accountRsAWhile = atoi(authVal);
		}else if(!strcmp(ConfigTag[tagIndex], "rsNasId"))
		{
			//sc_yang
			extern u_char lib1x_nas_id[MAX_NAS_ID_LEN] ;
			strncpy(lib1x_nas_id, authVal, MAX_NAS_ID_LEN);
		}else if(!strcmp(ConfigTag[tagIndex], "rsReAuthTO"))
		{
			auth->rsReAuthTO = atoi(authVal);
			lib1x_message(MESS_DBG_CONFIG, "rsReAuthTO = %d\n", auth->rsReAuthTO);
		}
#ifdef CONFIG_RTL_ETH_802DOT1X_SUPPORT
		else if(!strcmp(ConfigTag[tagIndex], "ethDot1xMode"))
		{
			auth->ethDot1xMode = atoi(authVal);
			lib1x_message(MESS_DBG_CONFIG, "ethDot1xMode = %d\n", auth->ethDot1xMode);
		}
		else if(!strcmp(ConfigTag[tagIndex], "ethDot1xProxyType"))
		{
			auth->ethDot1xProxyType = atoi(authVal);
			lib1x_message(MESS_DBG_CONFIG, "ethDot1xProxyType = %d\n", auth->ethDot1xProxyType);
		}
		else if(!strcmp(ConfigTag[tagIndex], "ethDot1xProxyModePortMask"))
		{
			auth->ethDot1xProxyModePortMask = atoi(authVal);
			lib1x_message(MESS_DBG_CONFIG, "ethDot1xProxyModePortMask = %d\n", auth->ethDot1xProxyModePortMask);
		}
		else if(!strcmp(ConfigTag[tagIndex], "ethDot1xClientModePortMask"))
		{
			auth->ethDot1xClientModePortMask = atoi(authVal);
			lib1x_message(MESS_DBG_CONFIG, "ethDot1xClientModePortMask = %d\n", auth->ethDot1xClientModePortMask);
		}
		else if(!strcmp(ConfigTag[tagIndex], "ethDot1xEapolUnicastEnabled"))
		{
			auth->ethDot1xEapolUnicastEnabled = atoi(authVal);
			lib1x_message(MESS_DBG_CONFIG, "ethDot1xEapolUnicastEnabled = %d\n", auth->ethDot1xEapolUnicastEnabled);
		}
#endif


	}


#ifdef RTL_WPA2
	if(ulEncryption >= 2)//WPA/WPA2
#else
	if(ulEncryption == 2)//WPA
#endif
	{
		if(auth->RSNVariable.RSNEnabled)
		{
	
#ifdef RTL_WPA_CLIENT
			if (auth->currentRole == role_Supplicant_infra && ulEncryption == 2
													&& ulUnicastCipher == 3) {
				printf("Can't set WPA TKIP+AES cipher for client mode. Use TKIP.\n");
				pUnicast->AlgoTable[DOT11_ENC_CCMP].Enabled =  FALSE;
				ulUnicastCipher = 1;				
			}
#ifdef RTL_WPA2
			if (auth->currentRole == role_Supplicant_infra && ulEncryption == 4
												&& ulWPA2UnicastCipher == 3) {
				printf("Can't set WPA2 TKIP+AES cipher for client mode. Use TKIP.\n");
				pWPA2Unicast->AlgoTable[DOT11_ENC_CCMP].Enabled = FALSE;
				ulWPA2UnicastCipher = 1;				
			}
#endif
#endif
		
			if(pAuth->AlgoTable[DOT11_AuthKeyType_RSN].Enabled
#ifdef CONFIG_IEEE80211R
			  || pAuth->AlgoTable[DOT11_AuthKeyType_FT].Enabled
#endif
#ifdef CONFIG_IEEE80211W
			  || pAuth->AlgoTable[DOT11_AuthKeyType_802_1X_SHA256].Enabled	
#endif
			)
				auth->RSNVariable.Dot1xEnabled = TRUE;
			else if(pAuth->AlgoTable[DOT11_AuthKeyType_RSNPSK].Enabled)
			{
				auth->RSNVariable.Dot1xEnabled = FALSE;

				if(ulUsePassphrase)
				{
					PasswordHash(auth->RSNVariable.PassPhrase, strlen(auth->RSNVariable.PassPhrase),
						(unsigned char *)auth->RSNVariable.ssid, strlen(auth->RSNVariable.ssid), auth->RSNVariable.PassPhraseKey);
				//	printf("Use PassPhrase\n");
				}
				else
				{	int i;
					for (i=0; i<32; i++) {
						unsigned char tmpBuf[4];
						memcpy(tmpBuf, &auth->RSNVariable.PassPhrase[i*2], 2);
						tmpBuf[2] = '\0';
						auth->RSNVariable.PassPhraseKey[i] =
							(unsigned char)strtol(tmpBuf, (char **)NULL, 16);
					}

				//	lib1x_hexdump2(MESS_DBG_CONFIG, "lib1x_config_parse",auth->RSNVariable.PassPhraseKey,
				//		sizeof(auth->RSNVariable.PassPhraseKey), "PassPhraseKey");
				}

			}

			lib1x_message(MESS_DBG_CONFIG, "ulUnicastCipher = %d (1:TKIP, 2: AES)\n", ulUnicastCipher);
			if(ulUnicastCipher == 1){
				auth->RSNVariable.MulticastCipher = DOT11_ENC_TKIP;
			}
			else if(ulUnicastCipher == 2 ){
				auth->RSNVariable.MulticastCipher = DOT11_ENC_CCMP;
			}
			else if (ulUnicastCipher == 3 ){ // WPA TKIP + AES
				auth->RSNVariable.MulticastCipher = DOT11_ENC_TKIP;
			}
#ifdef RTL_WPA2
			lib1x_message(MESS_DBG_CONFIG, "ulWPA2UnicastCipher = %d (1:TKIP, 2: AES)\n", ulWPA2UnicastCipher);
#if 0 // kenny: Should be disabled after WPA2 is supportd in wpa.conf
			printf("\n%s: ulWPA2UnicastCipher = %d (1:TKIP, 2: AES)!!\n", __FUNCTION__, ulWPA2UnicastCipher);
			pWPA2Unicast->AlgoTable[DOT11_ENC_CCMP].Enabled = TRUE;
			printf("%s-%d: WPA2 AES is be set unconditionally now! Should be changed after WPA2 is supportd in wpa.conf\n", __FUNCTION__, __LINE__);
			auth->RSNVariable.isSupportPreAuthentication = TRUE;
			printf("%s-%d: isSupportPreAuthentication is be set unconditionally now! Should be changed after enablePreAuth is supportd in wpa.conf\n", __FUNCTION__, __LINE__);
#endif	// #if 0
			if (ulEncryption == 4) { // WPA2-only
				if (auth->RSNVariable.WPA2UniCastCipherSuit.AlgoTable[DOT11_ENC_TKIP].Enabled)
					auth->RSNVariable.MulticastCipher = DOT11_ENC_TKIP;
				else
					auth->RSNVariable.MulticastCipher = DOT11_ENC_CCMP;
			} else if(ulEncryption == 6) { // WPA2-WPA-mixed mode
				auth->RSNVariable.MulticastCipher = DOT11_ENC_TKIP;
			}
#endif /* RTL_WPA2 */
			lib1x_message(MESS_DBG_CONFIG, "auth->RSNVariable.MulticastCipher = %d (2:TKIP, 4:AES)\n", auth->RSNVariable.MulticastCipher);

			// jimmylin+20080813, modify for MAC authentication
			if(ulEnableMacAuth)
				auth->RSNVariable.MacAuthEnabled = TRUE;
		}

	}else 	if(ulEncryption == 1 )//WEP
	{
		if(ulEnable1x)
			auth->RSNVariable.Dot1xEnabled = TRUE;
		else
			auth->RSNVariable.Dot1xEnabled = FALSE;

		if(ulWepKey == 1)
		{
			auth->RSNVariable.WepMode = DOT11_ENC_WEP40;
			auth->RSNVariable.MulticastCipher = DOT11_ENC_WEP40;

			if(auth->RSNVariable.Dot1xEnabled)
				lib1x_config_text2bin(auth->WepGroupKey, szWepGroupKey, 10);

		}
		else if(ulWepKey == 2)
		{
			auth->RSNVariable.WepMode = DOT11_ENC_WEP104;
			auth->RSNVariable.MulticastCipher = DOT11_ENC_WEP104;

			if(auth->RSNVariable.Dot1xEnabled)
				lib1x_config_text2bin(auth->WepGroupKey, szWepGroupKey, 26);

		}
		else
		{
			auth->RSNVariable.WepMode = DOT11_ENC_NONE;
			auth->RSNVariable.MulticastCipher = DOT11_ENC_NONE;
		}




	}else if(ulEncryption == 0)//None
	{
		if(ulEnable1x)
		{
			auth->RSNVariable.Dot1xEnabled = TRUE;
		}
		else
			auth->RSNVariable.Dot1xEnabled = FALSE;
		auth->RSNVariable.WepMode = DOT11_ENC_NONE;
		auth->RSNVariable.MulticastCipher = DOT11_ENC_NONE;//Unicast Cipher for STA will be set later
		if(ulEnableMacAuth)
		{
			auth->RSNVariable.MacAuthEnabled = TRUE;
		}

	}

// Fix the issue that Radius authentication will fail if WPA/WPA2 has been set 
	if (ulEncryption < 2) { //not WPA/WPA2
		pAuth->AlgoTable[DOT11_AuthKeyType_RSN].Enabled = FALSE;
#ifdef CONFIG_IEEE80211W		
		pAuth->AlgoTable[DOT11_AuthKeyType_802_1X_SHA256].Enabled = FALSE;
#endif
		pAuth->AlgoTable[DOT11_AuthKeyType_RSNPSK].Enabled = FALSE;	
	}
//---------------------------------------------- david+2008-03-04
	
	// Set Mutlicast Capability Table
	if(auth->RSNVariable.MulticastCipher < pMulticast->NumOfAlgo)
		pMulticast->AlgoTable[auth->RSNVariable.MulticastCipher].Enabled = TRUE;

	// Enable/Disable Accounting
	if(auth->RSNVariable.Dot1xEnabled || auth->RSNVariable.MacAuthEnabled )
		if(ulAccountEnabled)
		{
			auth->AccountingEnabled = TRUE;
		}


	if(ulEncryption == 2)
		lib1x_message(MESS_DBG_CONFIG, "Encryption : WPA");
#ifdef RTL_WPA2
	else if(ulEncryption == 4)
		lib1x_message(MESS_DBG_CONFIG, "Encryption : WPA2");
	else if(ulEncryption == 6)
		lib1x_message(MESS_DBG_CONFIG, "Encryption : WPA2-mixed");
#endif
	else if(ulEncryption == 1)
		lib1x_message(MESS_DBG_CONFIG, "Encryption : WEP");
	else if(ulEncryption == 0)
		lib1x_message(MESS_DBG_CONFIG, "Encryption : NONE");

	if(auth->RSNVariable.RSNEnabled)
		lib1x_message(MESS_DBG_CONFIG, "RSNEnabled : TRUE");
	else
		lib1x_message(MESS_DBG_CONFIG, "RSNEnabled : FALSE");

#ifdef RTL_WPA2
	if(auth->RSNVariable.WPAEnabled)
		lib1x_message(MESS_DBG_CONFIG, "WPAEnabled : TRUE");
	else
		lib1x_message(MESS_DBG_CONFIG, "WPAEnabled : FALSE");

	if(auth->RSNVariable.WPA2Enabled)
		lib1x_message(MESS_DBG_CONFIG, "WPA2Enabled : TRUE");
	else
		lib1x_message(MESS_DBG_CONFIG, "WPA2Enabled : FALSE");

	if(auth->RSNVariable.isSupportPreAuthentication)
		lib1x_message(MESS_DBG_CONFIG, "isSupportPreAuthentication : TRUE");
	else
		lib1x_message(MESS_DBG_CONFIG, "isSupportPreAuthentication : FALSE");

#endif

	if(auth->RSNVariable.Dot1xEnabled)
		lib1x_message(MESS_DBG_CONFIG, "Dot1xEnabled : TRUE");
	else
		lib1x_message(MESS_DBG_CONFIG, "Dot1xEnabled : FALSE");

	if(ulEnableMacAuth)
		lib1x_message(MESS_DBG_CONFIG, "MacAuthEnabled : TRUE");
	else
		lib1x_message(MESS_DBG_CONFIG, "MacAuthEnabled : FALSE");


	if(auth->AccountingEnabled)
		lib1x_message(MESS_DBG_CONFIG, "AccountingEnabled : TRUE");
	else
		lib1x_message(MESS_DBG_CONFIG, "AccountingEnabled : FALSE");


#ifdef RTL_RADIUS_2SET
	if (rad2nd_ip && rad2nd_port && rad2nd_pswd)
		auth->use_2nd_rad = 1;
	else
		auth->use_2nd_rad = 0;
#endif

	return 0;
}


#ifdef START_AUTH_IN_LIB
//--------------------------------------------------------------------------
//  Set configuration by auth_param_t
//  	Assume, use passphrase, groupkey rekey time=86400
//--------------------------------------------------------------------------
int lib1x_load_config_param(Dot1x_Authenticator *auth, auth_param_t *pParam)
{
	DOT11_AlgoSuit	*pUnicast = &auth->RSNVariable.UniCastCipherSuit;
#ifdef RTL_WPA2
	DOT11_AlgoSuit	*pWPA2Unicast = &auth->RSNVariable.WPA2UniCastCipherSuit;
#endif
	DOT11_AlgoSuit  *pMulticast =  &auth->RSNVariable.MulticastCipherSuit;
	DOT11_AlgoSuit	*pAuth = &auth->RSNVariable.AuthenticationSuit;

	u_long ulEnable1x = 0;
	u_long ulEncryption = 0;
	u_long ulAccountEnabled = 0;
	u_long ulUnicastCipher = 0;
#ifdef RTL_WPA2
        u_long ulWPA2UnicastCipher = 0;
#endif
	u_long ulWepKey = 0;
	u_long ulEnableMacAuth = 0;
	u_long ulUsePassphrase = 0;
	u_char szWepGroupKey[32];

	lib1x_init_algo(auth);

	strcpy(auth->RSNVariable.ssid, pParam->ssid);
	ulEnable1x = 1;
	ulEnableMacAuth = 0;

	pAuth->AlgoTable[DOT11_AuthKeyType_RSNPSK].Enabled = TRUE;
	pUnicast->AlgoTable[DOT11_ENC_TKIP].Enabled = (pParam->wpaCipher & EncAlgoMap_TKIP) ? TRUE:FALSE;
	pUnicast->AlgoTable[DOT11_ENC_CCMP].Enabled = (pParam->wpaCipher & EncAlgoMap_AES ) ? TRUE:FALSE;
	ulUnicastCipher = pParam->wpaCipher;

	ulEncryption = pParam->encryption;
#ifdef RTL_WPA2
	ulWPA2UnicastCipher = pParam->wpa2Cipher;
	pWPA2Unicast->AlgoTable[DOT11_ENC_TKIP].Enabled = (ulWPA2UnicastCipher & EncAlgoMap_TKIP) ? TRUE:FALSE;
	pWPA2Unicast->AlgoTable[DOT11_ENC_CCMP].Enabled = (ulWPA2UnicastCipher & EncAlgoMap_AES ) ? TRUE:FALSE;
	auth->RSNVariable.WPAEnabled = (ulEncryption & EncModeMap_WPA)? TRUE:FALSE;
	auth->RSNVariable.WPA2Enabled = (ulEncryption & EncModeMap_WPA2)? TRUE:FALSE;
	auth->RSNVariable.RSNEnabled = (ulEncryption >= 2 )? TRUE:FALSE;
#else
	auth->RSNVariable.RSNEnabled = (ulEncryption & EncModeMap_WPA)? TRUE:FALSE;
#endif

	auth->Dot11RSNConfig.GroupRekeyTime = 86400;
	strcpy(auth->RSNVariable.PassPhrase, pParam->psk);
	ulUsePassphrase = 1;

	auth->udp_svrport = 1812;
	auth->rsMaxReq = 3;
	auth->rsAWhile = 5;
	auth->rsReAuthTO = 0;

	if(ulEncryption >= 2)//WPA/WPA2
	{
		if(auth->RSNVariable.RSNEnabled)
		{
			if(pAuth->AlgoTable[DOT11_AuthKeyType_RSN].Enabled
#ifdef CONFIG_IEEE80211W
			  || pAuth->AlgoTable[DOT11_AuthKeyType_802_1X_SHA256].Enabled
#endif
			)
				auth->RSNVariable.Dot1xEnabled = TRUE;
			else if(pAuth->AlgoTable[DOT11_AuthKeyType_RSNPSK].Enabled)
			{
				auth->RSNVariable.Dot1xEnabled = FALSE;

				if(ulUsePassphrase)
				{
					PasswordHash(auth->RSNVariable.PassPhrase, strlen(auth->RSNVariable.PassPhrase),
						(unsigned char *)auth->RSNVariable.ssid, strlen(auth->RSNVariable.ssid), auth->RSNVariable.PassPhraseKey);
				//	printf("Use PassPhrase\n");
				}
				else
				{	int i;
					for (i=0; i<32; i++) {
						unsigned char tmpBuf[4];
						memcpy(tmpBuf, &auth->RSNVariable.PassPhrase[i*2], 2);
						tmpBuf[2] = '\0';
						auth->RSNVariable.PassPhraseKey[i] =
							(unsigned char)strtol(tmpBuf, (char **)NULL, 16);
					}

				//	lib1x_hexdump2(MESS_DBG_CONFIG, "lib1x_config_parse",auth->RSNVariable.PassPhraseKey,
				//		sizeof(auth->RSNVariable.PassPhraseKey), "PassPhraseKey");
				}

			}

			lib1x_message(MESS_DBG_CONFIG, "ulUnicastCipher = %d (1:TKIP, 2: AES)\n", ulUnicastCipher);
			if(ulUnicastCipher == 1){
				auth->RSNVariable.MulticastCipher = DOT11_ENC_TKIP;
			}
			else if(ulUnicastCipher == 2 ){
				auth->RSNVariable.MulticastCipher = DOT11_ENC_CCMP;
			}
			else if (ulUnicastCipher == 3 ){ // WPA TKIP + AES
				auth->RSNVariable.MulticastCipher = DOT11_ENC_TKIP;
			}
#ifdef RTL_WPA2
			lib1x_message(MESS_DBG_CONFIG, "ulWPA2UnicastCipher = %d (1:TKIP, 2: AES)\n", ulWPA2UnicastCipher);
#if 0 // kenny: Should be disabled after WPA2 is supportd in wpa.conf
			printf("\n%s: ulWPA2UnicastCipher = %d (1:TKIP, 2: AES)!!\n", __FUNCTION__, ulWPA2UnicastCipher);
			pWPA2Unicast->AlgoTable[DOT11_ENC_CCMP].Enabled = TRUE;
			printf("%s-%d: WPA2 AES is be set unconditionally now! Should be changed after WPA2 is supportd in wpa.conf\n", __FUNCTION__, __LINE__);
			auth->RSNVariable.isSupportPreAuthentication = TRUE;
			printf("%s-%d: isSupportPreAuthentication is be set unconditionally now! Should be changed after enablePreAuth is supportd in wpa.conf\n", __FUNCTION__, __LINE__);
#endif	// #if 0
			if (ulEncryption == 4) { // WPA2-only
				if (auth->RSNVariable.WPA2UniCastCipherSuit.AlgoTable[DOT11_ENC_TKIP].Enabled)
					auth->RSNVariable.MulticastCipher = DOT11_ENC_TKIP;
				else
					auth->RSNVariable.MulticastCipher = DOT11_ENC_CCMP;
			} else if(ulEncryption == 6) { // WPA2-WPA-mixed mode
				auth->RSNVariable.MulticastCipher = DOT11_ENC_TKIP;
			}
#endif /* RTL_WPA2 */
			lib1x_message(MESS_DBG_CONFIG, "auth->RSNVariable.MulticastCipher = %d (2:TKIP, 4:AES)\n", auth->RSNVariable.MulticastCipher);

		}

	}
	else 	if(ulEncryption == 1 )//WEP
	{
		if(ulEnable1x)
			auth->RSNVariable.Dot1xEnabled = TRUE;
		else
			auth->RSNVariable.Dot1xEnabled = FALSE;

		if(ulWepKey == 1)
		{
			auth->RSNVariable.WepMode = DOT11_ENC_WEP40;
			auth->RSNVariable.MulticastCipher = DOT11_ENC_WEP40;

			if(auth->RSNVariable.Dot1xEnabled)
				lib1x_config_text2bin(auth->WepGroupKey, szWepGroupKey, 10);

		}
		else if(ulWepKey == 2)
		{
			auth->RSNVariable.WepMode = DOT11_ENC_WEP104;
			auth->RSNVariable.MulticastCipher = DOT11_ENC_WEP104;

			if(auth->RSNVariable.Dot1xEnabled)
				lib1x_config_text2bin(auth->WepGroupKey, szWepGroupKey, 26);

		}
		else
		{
			auth->RSNVariable.WepMode = DOT11_ENC_NONE;
			auth->RSNVariable.MulticastCipher = DOT11_ENC_NONE;
		}

	}else if(ulEncryption == 0)//None
	{
		if(ulEnable1x)
		{
			auth->RSNVariable.Dot1xEnabled = TRUE;
		}
		else
			auth->RSNVariable.Dot1xEnabled = FALSE;
		auth->RSNVariable.WepMode = DOT11_ENC_NONE;
		auth->RSNVariable.MulticastCipher = DOT11_ENC_NONE;//Unicast Cipher for STA will be set later
		if(ulEnableMacAuth)
		{
			auth->RSNVariable.MacAuthEnabled = TRUE;
		}

	}

	// Set Mutlicast Capability Table
	if(auth->RSNVariable.MulticastCipher < pMulticast->NumOfAlgo)
		pMulticast->AlgoTable[auth->RSNVariable.MulticastCipher].Enabled = TRUE;

	// Enable/Disable Accounting
	if(auth->RSNVariable.Dot1xEnabled || auth->RSNVariable.MacAuthEnabled )
		if(ulAccountEnabled)
		{
			auth->AccountingEnabled = TRUE;
		}


	if(ulEncryption == 2)
		lib1x_message(MESS_DBG_CONFIG, "Encryption : WPA");
#ifdef RTL_WPA2
	else if(ulEncryption == 4)
		lib1x_message(MESS_DBG_CONFIG, "Encryption : WPA2");
	else if(ulEncryption == 6)
		lib1x_message(MESS_DBG_CONFIG, "Encryption : WPA2-mixed");
#endif
	else if(ulEncryption == 1)
		lib1x_message(MESS_DBG_CONFIG, "Encryption : WEP");
	else if(ulEncryption == 0)
		lib1x_message(MESS_DBG_CONFIG, "Encryption : NONE");

	if(auth->RSNVariable.RSNEnabled)
		lib1x_message(MESS_DBG_CONFIG, "RSNEnabled : TRUE");
	else
		lib1x_message(MESS_DBG_CONFIG, "RSNEnabled : FALSE");

#ifdef RTL_WPA2
	if(auth->RSNVariable.WPAEnabled)
		lib1x_message(MESS_DBG_CONFIG, "WPAEnabled : TRUE");
	else
		lib1x_message(MESS_DBG_CONFIG, "WPAEnabled : FALSE");

	if(auth->RSNVariable.WPA2Enabled)
		lib1x_message(MESS_DBG_CONFIG, "WPA2Enabled : TRUE");
	else
		lib1x_message(MESS_DBG_CONFIG, "WPA2Enabled : FALSE");

	if(auth->RSNVariable.isSupportPreAuthentication)
		lib1x_message(MESS_DBG_CONFIG, "isSupportPreAuthentication : TRUE");
	else
		lib1x_message(MESS_DBG_CONFIG, "isSupportPreAuthentication : FALSE");

#endif

	if(auth->RSNVariable.Dot1xEnabled)
		lib1x_message(MESS_DBG_CONFIG, "Dot1xEnabled : TRUE");
	else
		lib1x_message(MESS_DBG_CONFIG, "Dot1xEnabled : FALSE");

	if(ulEnableMacAuth)
		lib1x_message(MESS_DBG_CONFIG, "MacAuthEnabled : TRUE");
	else
		lib1x_message(MESS_DBG_CONFIG, "MacAuthEnabled : FALSE");


	if(auth->AccountingEnabled)
		lib1x_message(MESS_DBG_CONFIG, "AccountingEnabled : TRUE");
	else
		lib1x_message(MESS_DBG_CONFIG, "AccountingEnabled : FALSE");

	return 0;
}
#endif // START_AUTH_IN_LIB
