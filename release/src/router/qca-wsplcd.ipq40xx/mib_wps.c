/*
 * Copyright (c) 2010, Atheros Communications Inc.
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

 /* 
 * Author: Zhi Chen, November, 2010 zhichen@atheros.com
 */

/**************************************************************************

Copyright (c) 2006-2007 Sony Corporation. All Rights Reserved.

 Redistribution and use in source and binary forms, with or without
 modification, are permitted provided that the following conditions
 are met:

   * Redistributions of source code must retain the above copyright
     notice, this list of conditions and the following disclaimer.
   * Redistributions in binary form must reproduce the above copyright
     notice, this list of conditions and the following disclaimer in
     the documentation and/or other materials provided with the
     distribution.
   * Neither the name of Sony Corporation nor the names of its
     contributors may be used to endorse or promote products derived
     from this software without specific prior written permission.

 THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

**************************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <string.h>
#include <syslog.h>

#include "common.h"
#include "defs.h"
#include "wps_parser.h"
#include "mib_wps.h"
#include "wsplcd.h"
#include "legacy_ap.h"
#include "wps_config.h"
#include "storage.h"
#include "apac_priv.h" /* to use config_line_lex() */

const struct mib_param_set clone_param_sets[] =
{
   { "RADIO",	APCLONE_TYPE_RADIO,			WPS_VALTYPE_PTR},
   { "BSS",	APCLONE_TYPE_BSS,			WPS_VALTYPE_PTR},
   { NULL, 0, 0},
};

const struct mib_param_set radio_param_sets[] = 
{
   { "Channel",					RADIO_TYPE_CHANNEL,				WPS_VALTYPE_U32},
   { "RadioEnabled",				RADIO_TYPE_RADIOENABLED,		WPS_VALTYPE_BOOL},
   { "X_ATH-COM_Powerlevel",		RADIO_TYPE_POWERLEVEL,			WPS_VALTYPE_ENUM},
   { "X_ATH-COM_Rxchainmask",		RADIO_TYPE_RXCHAINMASK,		WPS_VALTYPE_U32},
   { "X_ATH-COM_Txchainmask",		RADIO_TYPE_TXCHAINMASK,		WPS_VALTYPE_U32},
   { "X_ATH-COM_TBRLimit",			RADIO_TYPE_TBRLIMIT,				WPS_VALTYPE_U32},
   { "X_ATH-COM_AMPDUEnabled",	RADIO_TYPE_AMPDUENABLED,		WPS_VALTYPE_BOOL},
   { "X_ATH-COM_AMPDULimit",		RADIO_TYPE_AMPDULIMIT,			WPS_VALTYPE_U32},
   { "X_ATH-COM_AMPDUFrames",	RADIO_TYPE_AMPDUFRAMES,		WPS_VALTYPE_U32},
   { NULL, 0, 0},
};

const struct mib_param_set bss_param_sets[] = 
{
   { "Enable",						BSS_TYPE_ENABLE,				WPS_VALTYPE_BOOL},
   { "X_ATH-COM_RadioIndex",		BSS_TYPE_RADIOINDEX,			WPS_VALTYPE_U32},		
   { "SSID",						BSS_TYPE_SSID,					WPS_VALTYPE_PTR},						
   { "BeaconType",					BSS_TYPE_BEACONTYPE,			WPS_VALTYPE_ENUM},
   { "Standard",					BSS_TYPE_STANDARD,				WPS_VALTYPE_ENUM},
   { "WEPKeyIndex",				BSS_TYPE_WEPKEYINDEX,			WPS_VALTYPE_U32},
   { "KeyPassphrase",				BSS_TYPE_KEYPASSPHRASE,			WPS_VALTYPE_PTR},
   { "BasicEncryptionModes",			BSS_TYPE_BASIC_ENCRYPTIONMODE,	WPS_VALTYPE_ENUM},
   { "BasicAuthenticationMode",		BSS_TYPE_BASIC_AUTHMODE,		WPS_VALTYPE_ENUM},
   { "WPAEncryptionModes",			BSS_TYPE_WPA_ENCRYPTIONMODE,	WPS_VALTYPE_ENUM},
   { "WPAAuthenticationMode",		BSS_TYPE_WPA_AUTHMODE,			WPS_VALTYPE_ENUM},
   { "IEEE11iEncryptionModes",		BSS_TYPE_11I_ENCRYPTIONMODE,	WPS_VALTYPE_ENUM},
   { "IEEE11iAuthenticationMode",		BSS_TYPE_11I_AUTHMODE,			WPS_VALTYPE_ENUM},
#if GATEWAY_WLAN_WAPI 
   { "WAPIAuthenticationMode",		BSS_TYPE_WAPI_AUTHMODE,		WPS_VALTYPE_ENUM},
   { "WAPIPSKType",				BSS_TYPE_WAPI_PSKTYPE,			WPS_VALTYPE_ENUM},
   { "WAPIPreAuth",				BSS_TYPE_WAPI_PREAUTH,			WPS_VALTYPE_BOOL},
   { "WAPIPSK",					BSS_TYPE_WAPI_PSK,				WPS_VALTYPE_PTR},
   { "WAPICertContent",				BSS_TYPE_WAPI_CERTCONTENT,		WPS_VALTYPE_PTR},
   { "WAPICertIndex",				BSS_TYPE_WAPI_CERTINDEX,		WPS_VALTYPE_ENUM},
   { "WAPICertStatus",				BSS_TYPE_WAPI_CERTSTATUS,		WPS_VALTYPE_ENUM},
   { "WAPICertMode",				BSS_TYPE_WAPI_CERTMODE,		WPS_VALTYPE_ENUM},
   { "WAPIASUAddress",				BSS_TYPE_WAPI_ASUADDRESS,		WPS_VALTYPE_PTR},
   { "WAPIASUPort",				BSS_TYPE_WAPI_ASUPORT,			WPS_VALTYPE_U32},
   { "WAPIUcastRekeyTime",			BSS_TYPE_WAPI_UCASTREKEYTIME,	WPS_VALTYPE_U32},	
   { "WAPIUcastRekeyPacket",		BSS_TYPE_WAPI_UCASTREKEYPACKET,	WPS_VALTYPE_U32},
   { "WAPIMcastRekeyTime",			BSS_TYPE_WAPI_MCASTREKEYTIME,	WPS_VALTYPE_U32},
   { "WAPIMcastRekeyPacket",		BSS_TYPE_WAPI_MCASTREKEYPACKET,	WPS_VALTYPE_U32},
#endif
   { "BasicDataTransmitRates",		BSS_TYPE_BASIC_DATA_TXRATES,	WPS_VALTYPE_PTR},
   { "RTS",						BSS_TYPE_RTS,					WPS_VALTYPE_PTR},
   { "Fragmentation",				BSS_TYPE_FRAGMENTATION,			WPS_VALTYPE_PTR},
   { "AuthenticationServiceMode",		BSS_TYPE_AUTH_SERVICE_MODE,	WPS_VALTYPE_ENUM},
   { "X_ATH-COM_EAPReauthPeriod",	BSS_TYPE_EAP_REAUTH_PERIOD,		WPS_VALTYPE_ENUM},
   { "X_ATH-COM_WEPRekeyPeriod",	BSS_TYPE_WEP_REKEY_PERIOD,		WPS_VALTYPE_U32},
   { "X_ATH-COM_AuthServerAddr",	BSS_TYPE_AUTH_SERVER_ADDR,		WPS_VALTYPE_PTR},
   { "X_ATH-COM_AuthServerPort",	BSS_TYPE_AUTH_SERVER_PORT,		WPS_VALTYPE_U32},
   { "X_ATH-COM_AuthServerSecret",	BSS_TYPE_AUTH_SERVER_SECRET,	WPS_VALTYPE_PTR},
   { "X_ATH-COM_RSNPreAuth",		BSS_TYPE_RSN_PREAUTH,			WPS_VALTYPE_BOOL},
   { "X_ATH-COM_SSIDHide",		BSS_TYPE_SSID_HIDE,				WPS_VALTYPE_BOOL},
   { "X_ATH-COM_APModuleEnable",	BSS_TYPE_APMODULE_ENABLE,		WPS_VALTYPE_BOOL},
   { "X_ATH-COM_WPSPin",			BSS_TYPE_WPS_PIN,				WPS_VALTYPE_PTR},
   { "X_ATH-COM_WPSConfigured",	BSS_TYPE_WPS_CONFIGURED,		WPS_VALTYPE_ENUM},
   { "X_ATH-COM_ShortGI",			BSS_TYPE_SHORT_GI,				WPS_VALTYPE_BOOL},
   { "X_ATH-COM_CWMEnable",		BSS_TYPE_CWM_ENABLE,			WPS_VALTYPE_BOOL},
   { "X_ATH-COM_WMM",			BSS_TYPE_WMM,					WPS_VALTYPE_BOOL},
   { "X_ATH-COM_HT40Coexist",		BSS_TYPE_HT40COEXIST,			WPS_VALTYPE_BOOL},
   { "X_ATH-COM_HBREnable",		BSS_TYPE_HBRENABLE,				WPS_VALTYPE_BOOL},
   { "X_ATH-COM_HBRPERLow",		BSS_TYPE_HBRPERLOW,			WPS_VALTYPE_U32},
   { "X_ATH-COM_HBRPERHigh",		BSS_TYPE_HBRPERHIGH,			WPS_VALTYPE_U32},
   { "X_ATH-COM_MEMode",			BSS_TYPE_MEMODE,				WPS_VALTYPE_ENUM},
   { "X_ATH-COM_MELength",		BSS_TYPE_MELENGTH,				WPS_VALTYPE_U32},
   { "X_ATH-COM_METimer",			BSS_TYPE_METIMER,				WPS_VALTYPE_U32},
   { "X_ATH-COM_METimeout",		BSS_TYPE_METIMEOUT,				WPS_VALTYPE_U32},
   { "X_ATH-COM_MEDropMcast",		BSS_TYPE_MEDROPMCAST,			WPS_VALTYPE_BOOL},
   { "WEPKey.1.WEPKey",			BSS_TYPE_WEPKEY_1,				WPS_VALTYPE_PTR},
   { "WEPKey.2.WEPKey",			BSS_TYPE_WEPKEY_2,				WPS_VALTYPE_PTR},
   { "WEPKey.3.WEPKey",			BSS_TYPE_WEPKEY_3,				WPS_VALTYPE_PTR},
   { "WEPKey.4.WEPKey",			BSS_TYPE_WEPKEY_4,				WPS_VALTYPE_PTR},
//   { "DeviceOperationMode",			BSS_TYPE_DEV_OPMODE,			WPS_VALTYPE_PTR},
   { "X_ATH-COM_GroupRekeyPeriod", BSS_TYPE_GROUP_REKEY_PERIOD, 	WPS_VALTYPE_PTR},
   { "PreSharedKey.1.PreSharedKey", 	BSS_TYPE_PRESHARED_KEY, 		WPS_VALTYPE_PTR},
   { NULL, 0, 0},
};

int mib_get_tlv(const struct mib_param_set *mibset, const char *value,  struct wps_tlv **tlv)
{
	u16 type;
	size_t length;
	Boolean b_value = FALSE;
	u8 u8_value = 0;
	u16 u16_value = 0;
	u32 u32_value = 0;
	u8 *ptr_value = 0;

	if (! mibset || !value  || !tlv)
		return -1;

	*tlv = 0;
	type = mibset->type;

	switch (mibset->value_type) {
	case WPS_VALTYPE_BOOL:
		length = 1;
		b_value = atoi(value);
		break;
	case WPS_VALTYPE_U8:
		length = 1;
		u8_value = atoi(value);
		break;
	case WPS_VALTYPE_U16:
		length = 2;
		u16_value = atoi(value);
		break;
	case WPS_VALTYPE_U32:
		length = 4;
		u32_value = atoi(value);
		break;
	case WPS_VALTYPE_PTR:
		length = strlen(value);
		ptr_value = (u8 *)malloc(length);
		if (!ptr_value)
			return -1; /* Memory allocation error */
		memcpy(ptr_value, value, length);
		break;
	default:
		return -1;
	}

	*tlv = (struct wps_tlv *)calloc(1, sizeof(struct wps_tlv));
	if (0 == *tlv) {
		if (ptr_value)
			free(ptr_value);
		return -1; /* Memory allocation error */
	}

	(*tlv)->type = type;
	(*tlv)->length = length;
	(*tlv)->value_type = mibset->value_type;
	switch ((*tlv)->value_type) {
	case WPS_VALTYPE_BOOL:
		(*tlv)->value.bool_ = (u8)b_value;
		break;
	case WPS_VALTYPE_U8:
		(*tlv)->value.u8_ = u8_value;
		break;
	case WPS_VALTYPE_U16:
		(*tlv)->value.u16_ = u16_value;
		break;
	case WPS_VALTYPE_U32:
		(*tlv)->value.u32_ = u32_value;
		break;
	case WPS_VALTYPE_PTR:
		(*tlv)->value.ptr_ = ptr_value;
		break;
	default:
		return -1;
	}

	return 0;
}



int mib_parse_value(const struct mib_param_set *mibset, const char *buf, size_t length, char **value)
{
	Boolean b_value = FALSE;
	u8 u8_value = 0;
	u16 u16_value = 0;
	u32 u32_value = 0;

	if (! mibset || !buf )
		return -1;

	*value = 0;

	*value = (char *)malloc(length+32);/*space enough for any kind type*/
	if (!(*value))
		return -1; /* Memory allocation error */
	
	switch (mibset->value_type) {
	case WPS_VALTYPE_BOOL:
		b_value = *(Boolean*)buf;
		length = sprintf(*value, "%u", b_value);
		break;
	case WPS_VALTYPE_U8:
		u8_value = *(u8*)buf;
		length = sprintf(*value, "%u", u8_value);
		break;
	case WPS_VALTYPE_U16:
		u16_value = *(u16*)buf;
		length = sprintf(*value, "%u", u16_value);
		break;
	case WPS_VALTYPE_U32:
		u32_value = *(u32*)buf;
		length = sprintf(*value, "%u", u32_value);
		break;
	case WPS_VALTYPE_PTR:
		memcpy(*value, buf, length);
		(*value)[length] = '\0';
		break;
	default:
		free (*value);
		return -1;
	}

	return 0;
}

static int add_tlv(struct wps_data *data, struct wps_tlv *tlv)
{

	data->tlvs = (struct wps_tlv **)realloc(data->tlvs,
				sizeof(struct wps_tlv *) * (data->count + 1));

	if (!data->tlvs)
		return -1;	/* Memory allocation error */
		data->tlvs[data->count++] = tlv;

	return 0;
}

/* open configuration file to read wlan setting parameters
 */
int mib_get_object(char * path, struct wps_data *data, const struct mib_param_set * mibsets)
{
    char *fname = g_cfg_file;
    const struct mib_param_set * mibset;	
    FILE *f;
    char mibpath[256];
    char buf[256];
    char *tag;
    char *value;
    int  param_num = 0;

    /*Open config file*/
    f = fopen(fname, "r");
    if (f == NULL) {
        dprintf(MSG_ERROR, "%s, couldn't open configuration file: '%s'. \n", __func__, fname);
        return -1;
    }

    /*get the line from config file by path and name,
    and copy value string*/
    while (fgets(buf, sizeof(buf), f) != NULL) {
        tag = apac_config_line_lex(buf, &value);
        
        if (tag == NULL || *tag == 0) {
            continue;
        }
            
        mibset = mibsets; 	
        while(mibset && mibset->name) {
            struct wps_tlv *tlv;
            
            sprintf(mibpath, "%s.%s", path, mibset->name); 
            
            if (strcmp(mibpath, tag) == 0) {
                if(mib_get_tlv(mibset, value ,& tlv) < 0)
                {
                    dprintf(MSG_ERROR, "Fails: Path [%s], value [%s]\n", path, value);
                    break;
                }
                
                add_tlv(data,  tlv);
                param_num ++;
                break;
            }
            mibset ++;
        }
    }

    /*Close config file*/
    fclose(f);

    if (param_num > 0)
        return 0;
    else
        return -1;
}

int mib_set_object(char * path, struct wps_data *data, const struct mib_param_set * mibsets)
{
    void *mibHandle = NULL;
    int fail = 0;
    char  mibpath[256];
    char buf[4096];
    size_t len;
    char *value;
    

    mibHandle = storage_getHandle();
    if(NULL == mibHandle)
    {
         return -1;
    }

    while(mibsets && mibsets->name)
    {
       len = sizeof(buf);
	if (wps_get_value(data, mibsets->type, buf, &len)==0)
	{
		if( mib_parse_value(mibsets, buf, len, &value) != 0)
		{
			dprintf(MSG_ERROR, "Value parse error %s\n", mibsets->name);
			mibsets++;
			continue;
		}
		sprintf(mibpath, "%s.%s", path, mibsets->name);
//		fprintf(stderr,"set %s = %s\n", mibpath, value);
		storage_setParam(mibHandle,mibpath,value);
		free (value);
		value = 0;
		
	}
	else
		dprintf(MSG_ERROR, "Value get error %s\n", mibsets->name);
		
	mibsets ++;
    }


    fail = storage_apply(mibHandle);
    if(fail)
    {
         dprintf(MSG_ERROR, "failed when set:%s!\n",path);
    }

    return fail;

}


int mib_update_credential(struct wps_credential* cred)
{
    void *mibHandle = NULL;
    int fail = 0;	
    char path[128];	
    char value[128]; 
    int i;	
    char *root = CONFIG_WLAN"1.";

    mibHandle = storage_getHandle();
    if(NULL == mibHandle)
    {
         return -1;
    }

    if (!cred || strlen((char *)cred->ssid) ==0)
        return -1;

    /*set SSID*/
    sprintf(path, "%s%s", root, "SSID");	
    storage_setParam(mibHandle,path,(char*)cred->ssid);	

    if (cred->auth_type & WPS_AUTHTYPE_WPA2PSK) {
    /*WPA2PSK or WPA2PSK/WPAPSK*/        

    /*set BeaconType*/  
        sprintf(path, "%s%s", root, "BeaconType");
        if (cred->auth_type & WPS_AUTHTYPE_WPAPSK) {
            sprintf(value, "%s", "WPAand11i");
        } else {
            sprintf(value, "%s", "11i");
        }
        storage_setParam(mibHandle,path,value);


    /*set auth type*/ 
        sprintf(path, "%s%s", root, "IEEE11iAuthenticationMode");
        sprintf(value, "%s", "PSKAuthentication");
        storage_setParam(mibHandle,path,value);

    /*set encr type*/  
        sprintf(path, "%s%s", root, "IEEE11iEncryptionModes");
        if (cred->encr_type & WPS_ENCRTYPE_AES) {
            if (cred->encr_type & WPS_ENCRTYPE_TKIP) {
                sprintf(value, "%s", "TKIPandAESEncryption");
            } else {
                sprintf(value, "%s", "AESEncryption");
            }
        } else {
            sprintf(value, "%s", "TKIPEncryption");
        }
        storage_setParam(mibHandle,path,value); 

    /*set PSK or passphrase*/
        sprintf(path, "%s%s", root, "PreSharedKey.1.PreSharedKey");		
        if (cred->key_len == 64)
        {
            storage_setParam(mibHandle,path,(char*)cred->key); 
        }
        else
        {
            storage_setParam(mibHandle,path,"");    
			
            sprintf(path, "%s%s", root, "KeyPassphrase");				
            storage_setParam(mibHandle,path,(char*)cred->key);        
        }

    } 
    else if (cred->auth_type & WPS_AUTHTYPE_WPAPSK) {
    /*WPAPSK*/
    /*set BeaconType*/    
        sprintf(path, "%s%s", root, "BeaconType");	
        sprintf(value, "%s", "WPA");
        storage_setParam(mibHandle,path,value);   

    /*set auth type*/ 
        sprintf(path, "%s%s", root, "WPAAuthenticationMode");	
        sprintf(value, "%s", "PSKAuthentication");
        storage_setParam(mibHandle,path,value);

    /*set encr type*/  
        sprintf(path, "%s%s", root, "WPAEncryptionModes");
        if (cred->encr_type & WPS_ENCRTYPE_AES) {
            if (cred->encr_type & WPS_ENCRTYPE_TKIP) {
                sprintf(value, "%s", "TKIPandAESEncryption");
            } else {
                sprintf(value, "%s", "AESEncryption");
            }
        } else {
            sprintf(value, "%s", "TKIPEncryption");
        }
        storage_setParam(mibHandle,path,value); 

    /*set PSK or passphrase*/
        sprintf(path, "%s%s", root, "PreSharedKey.1.PreSharedKey");		
        if (cred->key_len == 64)
        {
            storage_setParam(mibHandle,path,(char*)cred->key); 
        }
        else
        {
            storage_setParam(mibHandle,path,"");          
            sprintf(path, "%s%s", root, "KeyPassphrase");				
            storage_setParam(mibHandle,path,(char*)cred->key); 	       
        }
	
    } 
    else if (cred->auth_type & WPS_AUTHTYPE_OPEN) {
    /*WEP or OPEN*/
        if (cred->encr_type & WPS_ENCRTYPE_WEP) {
        /*WEP*/
        /*set beacon type*/
             sprintf(path, "%s%s", root, "BeaconType");	
            sprintf(value, "%s", "Basic");
            storage_setParam(mibHandle,path,value);      
		
        /*set wep key idx*/
            sprintf(path, "%s%s", root, "WEPKeyIndex");			
            sprintf(value, "%d", cred->key_idx);
            storage_setParam(mibHandle,path,value);      

            for (i = 1; i <= 4; i ++) {
        /*set wep keys*/
                sprintf(path, "%sWEPKey.%d.WEPKey", root, i);
                if (i == cred->key_idx)
			storage_setParam(mibHandle,path,(char*)cred->key);
                else
                    storage_setParam(mibHandle,path,"");
            }
        }
        else {
        /*OPEN*/ 
        /*set beacon type*/
            sprintf(path, "%s%s", root, "BeaconType");	
            sprintf(value, "%s", "None");
            storage_setParam(mibHandle,path,value); 
        }        
    }

    /*set authentication server mode to none*/
    sprintf(path, "%s%s", root, "AuthenticationServiceMode");
    sprintf(value, "%s", "None");
    storage_setParam(mibHandle,path,value); 

    fail = storage_apply(mibHandle);
    if(fail)
    {
         dprintf(MSG_ERROR, "failed when set:%s!\n", root);
    }
 
    return fail;	
}

