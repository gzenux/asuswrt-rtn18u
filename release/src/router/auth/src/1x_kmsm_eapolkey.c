#include "stdafx.h"
#include "stdlib.h"
#include "string.h"
//#include <openssl/md5.h>
//#include <openssl/rc4.h>
#include "1x_rc4.h"
#include <time.h>

#include "1x_eapol.h"
#include "1x_kmsm.h"
#include "1x_kmsm_eapolkey.h"

#ifdef RTL_WPA2_CLIENT 
#include "1x_supp_pae.h"
#endif

#ifdef CONFIG_IEEE80211R
#include "sha256.h"
#include "1x_ioctl.h"
#endif

#define PMK_EXPANSION_CONST 	        "Pairwise key expansion"
#define PMK_EXPANSION_CONST_SIZE		22
#ifdef RTL_WPA2
#define PMKID_NAME_CONST 	        "PMK Name"
#define PMKID_NAME_CONST_SIZE 	        	8
#endif /* RTL_WPA2 */
#define GMK_EXPANSION_CONST 	        "Group key expansion"
#define GMK_EXPANSION_CONST_SIZE		19
#define RANDOM_EXPANSION_CONST 	        "Init Counter"
#define RANDOM_EXPANSION_CONST_SIZE		12

#define	EAPOLKEY_DEBUG 2

int MIN(u_char * ucStr1, u_char * ucStr2, u_long ulLen)
{
        int i;
        for(i=0 ; i<ulLen ; i++)
        {
                //printf("i=%d, 1=%x, 2=%x\n", i, ucStr1[i], ucStr2[i]);
                if((u_char)ucStr1[i] < (u_char)ucStr2[i])
                        return -1;
                else if((u_char)ucStr1[i] > (u_char)ucStr2[i])
                        return 1;
                else if(i == ulLen - 1)
                        return 0;
                else
                        continue;
        }
	return 0;
}


void PrintHex(u_char *str, u_char *buf, int size);
char * KM_STRERR(int err)
{

	switch(err)
	{
		case ERROR_NULL_PSK:
			return KM_STRERROR_NULL_PSK;
		case ERROR_TIMEOUT:
			return KM_STRERROR_TIMEOUT;
		case ERROR_MIC_FAIL:
			return KM_STRERROR_MIC_FAIL;
		case ERROR_SET_PTK:
			return KM_STRERROR_SET_PTK;
		case ERROR_NONEEQUL_REPLAYCOUNTER:
			return KM_STRERROR_NONEEQUL_REPLAYCOUNTER;
		case ERROR_EQUALSMALLER_REPLAYCOUNTER:
			return KM_STRERROR_EQUALSMALLER_REPLAYCOUNTER;
		case ERROR_NONEQUAL_NONCE:
			return KM_STRERROR_NONEQUAL_NONCE;
		case ERROR_AESKEYWRAP_MIC_FAIL:
			return KM_STRERROR_AESKEYWRAP_MIC_FAIL;
		case ERROR_LARGER_REPLAYCOUNTER:
			return KM_STRERROR_LARGER_REPLAYCOUNTER;
		case ERROR_UNMATCHED_GROUPKEY_LEN:
			return KM_STRERROR_UNMATCHED_GROUPKEY_LEN;
		case ERROR_NONEQUAL_RSNIE:
			return KM_STRERROR_NONEQUAL_RSNIE;



	}
	return "Uknown Failure";
}

int	CheckMIC(OCTET_STRING EAPOLMsgRecvd, u_char *key, int keylen)
{

	int			retVal = 0;

	OCTET_STRING		EapolKeyMsgRecvd;
	char			ucAlgo;

	OCTET_STRING		tmp; //copy of overall 802.1x message
	struct lib1x_eapol	* tmpeapol;
	lib1x_eapol_key * 	tmpeapolkey;
	u_char sha1digest[20];

	EapolKeyMsgRecvd.Octet = EAPOLMsgRecvd.Octet +\
					ETHER_HDRLEN + LIB1X_EAPOL_HDRLEN;
	EapolKeyMsgRecvd.Length = EAPOLMsgRecvd.Length -\
					(ETHER_HDRLEN + LIB1X_EAPOL_HDRLEN);
	ucAlgo = Message_KeyDescVer(EapolKeyMsgRecvd);

	tmp.Length = EAPOLMsgRecvd.Length;
	tmp.Octet = (u_char*)malloc(EAPOLMsgRecvd.Length);
	memcpy(tmp.Octet, EAPOLMsgRecvd.Octet, EAPOLMsgRecvd.Length);
	tmpeapol = (struct lib1x_eapol *)(tmp.Octet + ETHER_HDRLEN);
	tmpeapolkey = (lib1x_eapol_key *)(tmp.Octet + ETHER_HDRLEN +
LIB1X_EAPOL_HDRLEN);
	memset(tmpeapolkey->key_mic, 0, KEY_MIC_LEN);

	AUTHDEBUG("unicast key mic Algo=[%d]\n",ucAlgo);
	if(ucAlgo == key_desc_ver1)
	{
		hmac_md5((u_char*)tmpeapol, EAPOLMsgRecvd.Length - ETHER_HDRLEN ,
					key, keylen, tmpeapolkey->key_mic);
#ifdef DEBUG_MIC
		lib1x_hexdump2(MESS_DBG_KEY_MANAGE, "CheckMIC", EapolKeyMsgRecvd.Octet +
					KeyMICPos, KEY_MIC_LEN, "Original");
		lib1x_hexdump2(MESS_DBG_KEY_MANAGE, "CheckMIC", tmpeapolkey->key_mic,
					KEY_MIC_LEN, "Calculated");
#endif
		if(!memcmp(tmpeapolkey->key_mic, EapolKeyMsgRecvd.Octet + KeyMICPos,
KEY_MIC_LEN))
			retVal = 1;
	}

	else if(ucAlgo == key_desc_ver2)
	{


		hmac_sha1((u_char*)tmpeapol, EAPOLMsgRecvd.Length - ETHER_HDRLEN ,
					key, keylen, sha1digest);
		if(!memcmp(sha1digest, EapolKeyMsgRecvd.Octet + KeyMICPos, KEY_MIC_LEN))
			retVal = 1;
	}
#if defined(CONFIG_IEEE80211W) || defined(CONFIG_IEEE80211R)
	else if(ucAlgo == key_desc_ver3 || ucAlgo == 0)		/*HS2_SUPPORT  ; || ucAlgo == 0*/
	{
		omac1_aes_128(key, (u_char*)tmpeapol, EAPOLMsgRecvd.Length - ETHER_HDRLEN, tmpeapolkey->key_mic);
		if(!memcmp(tmpeapolkey->key_mic, EapolKeyMsgRecvd.Octet + KeyMICPos, KEY_MIC_LEN))
			retVal = 1;
	}
#endif

	free(tmp.Octet); // david+2006-03-31, fix memory leak
	return retVal;


}

#ifdef RTL_WPA2
void CalcPMKID(char* pmkid, char* pmk, char* aa, char* spa
#ifdef CONFIG_IEEE80211W
, int use_sha256
#endif
)
{
	//u_char data[sizeof(PMKID_NAME_CONST) + 2*ETHER_ADDRLEN];
	u_char data[PMKID_NAME_CONST_SIZE + 2*ETHER_ADDRLEN];
	u_char	sha1digest[20];
	memcpy(data, PMKID_NAME_CONST, PMKID_NAME_CONST_SIZE);
	memcpy(data+PMKID_NAME_CONST_SIZE, aa, ETHER_ADDRLEN);
	memcpy(data+PMKID_NAME_CONST_SIZE+ETHER_ADDRLEN, spa, ETHER_ADDRLEN);

	//printf("CalcPMKID\n");
	//wpa2_hexdump("AA", aa, ETHER_ADDRLEN);
	//wpa2_hexdump("SPA", spa, ETHER_ADDRLEN);
	//wpa2_hexdump("PMK", pmk, PMK_LEN);
	//wpa2_hexdump("DATA", data, sizeof(data));
#ifdef CONFIG_IEEE80211W
	if(use_sha256)
		hmac_sha256((u_char*)data, sizeof(data), pmk, PMK_LEN, sha1digest);
	else
#endif
		hmac_sha1((u_char*)data, sizeof(data), pmk, PMK_LEN, sha1digest);
	memcpy(pmkid, sha1digest, PMKID_LEN);
	//wpa2_hexdump("PMKID", pmkid, PMKID_LEN);

}
#endif /* RTL_WPA2 */

void CalcMIC(OCTET_STRING EAPOLMsgSend, int algo, u_char *key, int keylen)
{


	struct lib1x_eapol * eapol = (struct lib1x_eapol *)(EAPOLMsgSend.Octet +
					ETHER_HDRLEN);

	lib1x_eapol_key *   eapolkey = (lib1x_eapol_key *)(EAPOLMsgSend.Octet +
					ETHER_HDRLEN + LIB1X_EAPOL_HDRLEN);
	u_char	sha1digest[20];

	memset(eapolkey->key_mic, 0, KEY_MIC_LEN);

	// kenny
//	lib1x_message(MESS_DBG_KEY_MANAGE, "CaclMIC Algorithm = %d ", algo);
//	lib1x_hexdump2(MESS_DBG_KEY_MANAGE, "CalcMIC(1)", key, keylen, "PTK");
//	lib1x_hexdump2(MESS_DBG_KEY_MANAGE, "CalcMIC(2)", (u_char*)eapol, EAPOLMsgSend.Length - ETHER_HDRLEN , "Packet");

	if(algo == key_desc_ver1)
	{

  		hmac_md5((u_char*)eapol, EAPOLMsgSend.Length - ETHER_HDRLEN ,
					key, keylen, eapolkey->key_mic);
	}
	else if(algo == key_desc_ver2)
	{
		hmac_sha1((u_char*)eapol, EAPOLMsgSend.Length - ETHER_HDRLEN ,
					key, keylen, sha1digest);
		memcpy(eapolkey->key_mic, sha1digest, KEY_MIC_LEN);
	}
	else if (algo == key_desc_ver3 || algo == 0) {				/*HS2_SUPPORT  ; || ucAlgo == 0*/
		omac1_aes_128(key, (unsigned char*)eapol, EAPOLMsgSend.Length - ETHER_HDRLEN, eapolkey->key_mic);
	}
	// kenny
//	lib1x_hexdump2(MESS_DBG_KEY_MANAGE, "CalcMIC(3)", eapolkey->key_mic, KEY_MIC_LEN, "MIC");

}

void CalcPTK(u_char *addr1, u_char *addr2, u_char *nonce1, u_char *nonce2,
			 u_char * keyin, int keyinlen,
			 u_char * keyout, int keyoutlen
#ifdef CONFIG_IEEE80211W
  			 ,int use_sha256
#endif			 
			 )
{
	u_char data[2*ETHER_ADDRLEN + 2*KEY_NONCE_LEN], tmpPTK[128];

	if(MIN(addr1, addr2, ETHER_ADDRLEN)<=0)
	{
		memcpy(data, addr1, ETHER_ADDRLEN);
		memcpy(data + ETHER_ADDRLEN, addr2, ETHER_ADDRLEN);
	}else
	{
		memcpy(data, addr2, ETHER_ADDRLEN);
		memcpy(data + ETHER_ADDRLEN, addr1, ETHER_ADDRLEN);
	}
	if(MIN(nonce1, nonce2, KEY_NONCE_LEN)<=0)
	{
		memcpy(data + 2*ETHER_ADDRLEN, nonce1, KEY_NONCE_LEN);
		memcpy(data + 2*ETHER_ADDRLEN + KEY_NONCE_LEN, nonce2, KEY_NONCE_LEN);
	}else
	{
		memcpy(data + 2*ETHER_ADDRLEN, nonce2, KEY_NONCE_LEN);
		memcpy(data + 2*ETHER_ADDRLEN + KEY_NONCE_LEN, nonce1, KEY_NONCE_LEN);
	}

#ifdef CONFIG_IEEE80211W		
	if (use_sha256) {
		sha256_prf(keyin, keyinlen, (unsigned char*)PMK_EXPANSION_CONST, data, sizeof(data),
			   tmpPTK, keyoutlen);
	}
	else
#endif

	i_PRF(keyin, keyinlen, (u_char*)PMK_EXPANSION_CONST,
						PMK_EXPANSION_CONST_SIZE, data,sizeof(data),
						tmpPTK, PTK_LEN_TKIP);
	memcpy(keyout, tmpPTK, keyoutlen);

#if 0 // for debug
	lib1x_hexdump2(MESS_DBG_KEY_MANAGE, "CalcPTK", nonce1, KEY_NONCE_LEN, "ANonce");
	lib1x_hexdump2(MESS_DBG_KEY_MANAGE, "CalcPTK", nonce2, KEY_NONCE_LEN, "SNonce");
	//lib1x_hexdump2(MESS_DBG_KEY_MANAGE, "CalcPTK", data, sizeof(data), "data");
	lib1x_hexdump2(MESS_DBG_KEY_MANAGE, "CalcPTK", keyin, keyinlen, "PMK");
	lib1x_hexdump2(MESS_DBG_KEY_MANAGE, "CalcPTK", keyout, keyoutlen, "PTK");
#endif

}

#ifdef CONFIG_IEEE80211R
#define FT_PMKR0_CONST					"FT-R0"
#define FT_PMKR0_CONST_SIZE				5
#define FT_PMKR0_NAME_CONST				"FT-R0N"
#define FT_PMKR0_NAME_CONST_SIZE		6
#define FT_PMKR1_CONST					"FT-R1"
#define FT_PMKR1_CONST_SIZE				5
#define FT_PMKR1_NAME_CONST				"FT-R1N"
#define FT_PMKR1_NAME_CONST_SIZE		6
#define FT_PMK_EXPANSION_CONST			"FT-PTK"
#define FT_PMK_EXPANSION_CONST_SIZE		6

#define BIT(x)	(1 << (x))


unsigned int mapPairwise(unsigned char enc)
{
	if (enc == DOT11_ENC_TKIP)
		return BIT(3);
	else if (enc == DOT11_ENC_CCMP)
		return BIT(4);
	else
		return BIT(0);
}

void CalcFTPTK(Global_Params * global, u_char * keyout, int keyoutlen)
{
	struct _Dot1x_Authenticator *auth = global->auth;
	unsigned char data[512];
	unsigned char *pos;
	unsigned char tmpBuf[128];
	unsigned char *data_vec[4];
	size_t len_vec[4];
	unsigned char pmk_r0[PMK_LEN], pmk_r1[PMK_LEN];
	unsigned char pmk_r0_name[PMKID_LEN], pmk_r1_name[PMKID_LEN];
	unsigned char salt_buff[PMKID_LEN];
	DOT11_QUERY_FT_INFORMATION ft_info;
	DOT11_SET_FT_INFORMATION set_info;
	
	if (lib1x_control_query_ft_info(auth, global->theAuthenticator->supp_addr, &ft_info)) {
		printf("lib1x_control_query_ft_info failed\n");
		return;
	}
	memset(global->akm_sm->ssid, 0, sizeof(global->akm_sm->ssid));
	memcpy(global->akm_sm->ssid, ft_info.ssid, ft_info.ssid_len);
	global->akm_sm->ssid_len = ft_info.ssid_len;
	memcpy(global->akm_sm->mdid, ft_info.mdid, 2);
	memset(global->akm_sm->r0kh_id, 0, sizeof(global->akm_sm->r0kh_id));
	memcpy(global->akm_sm->r0kh_id, ft_info.r0kh_id, ft_info.r0kh_id_len);
	global->akm_sm->r0kh_id_len = ft_info.r0kh_id_len;
	memcpy(global->akm_sm->bssid, ft_info.bssid, MacAddrLen);
	global->akm_sm->over_ds_enabled = ft_info.over_ds;
	global->akm_sm->resource_request_support = ft_info.res_request;

	set_info.EventId = DOT11_EVENT_FT_SET_INFO;
	memcpy(set_info.sta_addr, global->theAuthenticator->supp_addr, MacAddrLen);
	set_info.UnicastCipher = global->RSNVariable.UnicastCipher;
	set_info.MulticastCipher = global->RSNVariable.MulticastCipher;
	set_info.bInstallKey = 0;
	if (lib1x_control_set_ft_info(auth, &set_info)) {
		printf("lib1x_control_set_ft_info failed\n");
	}
	
	// Calc PMK-R0
	pos = data;
	*pos++ = (unsigned char)ft_info.ssid_len;
	memcpy(pos, ft_info.ssid, ft_info.ssid_len);
	pos += ft_info.ssid_len;
	memcpy(pos, ft_info.mdid, 2);
	pos += 2;
	*pos++ = ft_info.r0kh_id_len;
	memcpy(pos, ft_info.r0kh_id, ft_info.r0kh_id_len);
	pos += ft_info.r0kh_id_len;
	memcpy(pos, ft_info.sta_addr, MacAddrLen);
	pos += MacAddrLen;
	sha256_prf(global->akm_sm->xxkey, PMK_LEN, (unsigned char*)FT_PMKR0_CONST, data, pos - data, tmpBuf, 48);	
	memcpy(pmk_r0, tmpBuf, PMK_LEN);
	memcpy(salt_buff, tmpBuf + PMK_LEN, PMKID_LEN);

	// Calc PMK-R0Name
	data_vec[0] = FT_PMKR0_NAME_CONST;
	len_vec[0] = FT_PMKR0_NAME_CONST_SIZE;
	data_vec[1] = salt_buff;
	len_vec[1] = PMKID_LEN;
	if (sha256_vector(2, data_vec, len_vec, tmpBuf)) {
		printf("Error: sha256 fail\n");
		return;
	}
	memcpy(pmk_r0_name, tmpBuf, PMKID_LEN);


	wpa2_hexdump("PSK: Generate PMK_R0_Name=", pmk_r0_name, PMKID_LEN);

	if (lib1x_control_ft_set_r0(auth, global->theAuthenticator->supp_addr, pmk_r0, pmk_r0_name)) {
		printf("Error: can't store r0kh\n");
		return;
	}

	// Calc PMK-R1
	pos = data;
	memcpy(pos, ft_info.bssid, MacAddrLen);
	pos += MacAddrLen;
	memcpy(pos, ft_info.sta_addr, MacAddrLen);
	pos += MacAddrLen;
	sha256_prf(pmk_r0, PMK_LEN, (unsigned char *)FT_PMKR1_CONST,
		data, pos - data, tmpBuf, 32);
	memcpy(pmk_r1, tmpBuf, PMK_LEN);


	wpa2_hexdump("PSK: Generate PMK_R1=", pmk_r1, PMK_LEN);


	// Calc PMK-R1Name
	data_vec[0] = FT_PMKR1_NAME_CONST;
	len_vec[0] = FT_PMKR1_NAME_CONST_SIZE;
	data_vec[1] = pmk_r0_name;
	len_vec[1] = PMKID_LEN;
	data_vec[2] = ft_info.bssid;
	len_vec[2] = MacAddrLen;
	data_vec[3] = ft_info.sta_addr;
	len_vec[3] = MacAddrLen;
	if (sha256_vector(4, data_vec, len_vec, tmpBuf)) {
		printf("Error: sha256 fail\n");
		return;
	}
	memcpy(pmk_r1_name, tmpBuf, PMKID_LEN);

	// Backup pmk_r1_name
	memcpy(global->akm_sm->pmk_r1_name, pmk_r1_name, PMKID_LEN);
	
	wpa2_hexdump("PSK: Generate PMK_R1_Name=", pmk_r1_name, PMKID_LEN);


	// Calc PTK
	pos = data;
	memcpy(pos, global->akm_sm->SNonce.Octet, KEY_NONCE_LEN);
	pos += KEY_NONCE_LEN;
	memcpy(pos, global->akm_sm->ANonce.Octet, KEY_NONCE_LEN);
	pos += KEY_NONCE_LEN;
	memcpy(pos, ft_info.bssid, MacAddrLen);
	pos += MacAddrLen;
	memcpy(pos, ft_info.sta_addr, MacAddrLen);
	pos += MacAddrLen;
	sha256_prf(pmk_r1, PMK_LEN, (unsigned char *)FT_PMK_EXPANSION_CONST,
		data, pos - data, tmpBuf, keyoutlen);
	memcpy(keyout, tmpBuf, keyoutlen);

	if (lib1x_control_ft_set_r1(auth, ft_info.sta_addr, ft_info.bssid, ft_info.r0kh_id, ft_info.r0kh_id_len, 
			pmk_r1, pmk_r1_name, pmk_r0_name, mapPairwise(global->RSNVariable.UnicastCipher) )) {
		printf("Error: fail to store r1kh\n");
		return;
	}

}
#endif


// ////////////   Nonce generation function 802.11i/D3.0 p117, p.189/
void GenNonce(u_char * nonce, u_char * addr)
{

        u_char  secret[256], random[256], result[256];
        time_t  t;

        time(&t);
        memcpy(random, (u_char*)&t, sizeof(t));
        memset(secret, 0, sizeof secret);
        //memset(random, 0, sizeof random);

        i_PRF(secret, sizeof(secret), (u_char*)RANDOM_EXPANSION_CONST, RANDOM_EXPANSION_CONST_SIZE,
                        random, sizeof(random), result, KEY_NONCE_LEN);
        memcpy(nonce, result, KEY_NONCE_LEN);

}

/* GTK-PRF-X
   X = 256 in TKIP
   X = 128 in CCMP, WRAP, and WEP
*/
void CalcGTK(u_char *addr, u_char *nonce,
			 u_char * keyin, int keyinlen,
			 u_char * keyout, int keyoutlen,
			 u_char * label	 )
{
	u_char data[ETHER_ADDRLEN + KEY_NONCE_LEN], tmp[64];


	memcpy(data, addr, ETHER_ADDRLEN);
	memcpy(data + ETHER_ADDRLEN, nonce, KEY_NONCE_LEN);

#ifdef CONFIG_IEEE80211W
	sha256_prf(keyin, keyinlen, label, data, sizeof(data), tmp, keyoutlen);
#else
	
	i_PRF(keyin, keyinlen, label,
						GMK_EXPANSION_CONST_SIZE, data, sizeof(data),
						tmp, keyoutlen);
#endif
	memcpy(keyout, tmp, keyoutlen);

}
void EncGTK(Global_Params * global, u_char *kek, int keklen, u_char *key,
			int keylen, u_char *out, u_short *outlen)
{

	u_char 		tmp1[257], tmp2[257];
	RC4_KEY		rc4key;
	// kenny
	u_char		default_key_iv[] = { 0xA6,0xA6,0xA6,0xA6,0xA6,0xA6,0xA6,0xA6 };

	//struct lib1x_eapol		* eapol = (struct lib1x_eapol *)(global->EAPOLMsgSend.Octet + ETHER_HDRLEN);
	lib1x_eapol_key * eapolkey = (lib1x_eapol_key *)(global->EAPOLMsgSend.Octet +
					ETHER_HDRLEN + LIB1X_EAPOL_HDRLEN);


// should refer tx packet, david+2006-04-06
//	if(Message_KeyDescVer(global->EapolKeyMsgRecvd) == key_desc_ver1)
	if(Message_KeyDescVer(global->EapolKeyMsgSend) == key_desc_ver1)

	{
			memcpy(tmp1, eapolkey->key_iv, KEY_IV_LEN);
			memcpy(tmp1 + KEY_IV_LEN, kek, keklen);

			RC4_set_key(&rc4key, KEY_IV_LEN + keklen, tmp1);
			//first 256 bytes are discarded
			RC4(&rc4key, 256, (u_char*)tmp1, (u_char*)tmp2);
            		RC4(&rc4key, keylen, (u_char*)key, out);
			*outlen = keylen;
// should refer tx packet, david+2006-04-06
//	}else if(Message_KeyDescVer(global->EapolKeyMsgRecvd) == key_desc_ver2)
	}else if(Message_KeyDescVer(global->EapolKeyMsgSend) == key_desc_ver2)
	{
			//according to p75 of 11i/D3.0, the IV should be put in the least significant octecs of
			//KeyIV field which shall be padded with 0, so eapolkey->key_iv + 8
			AES_WRAP(key, keylen, default_key_iv, 8, kek, keklen, out, outlen);
	}else if(Message_KeyDescVer(global->EapolKeyMsgSend) == key_desc_ver3 
	|| Message_KeyDescVer(global->EapolKeyMsgSend) == 0)  /*HS2_SUPPORT  ; || Message_KeyDescVer(global->EapolKeyMsgSend) == 0 */
	{
			//according to p75 of 11i/D3.0, the IV should be put in the least significant octecs of
			//KeyIV field which shall be padded with 0, so eapolkey->key_iv + 8
			AES_WRAP(key, keylen, default_key_iv, 8, kek, keklen, out, outlen);
	}
			// Kenny
	//lib1x_hexdump2(MESS_DBG_KEY_MANAGE, "EncGTK", kek, keklen, "Group Key encryption key");
	//lib1x_hexdump2(MESS_DBG_KEY_MANAGE, "EncGTK", key, keylen, "Group Key");
	//lib1x_hexdump2(MESS_DBG_KEY_MANAGE, "EncGTK", default_key_iv, 8, "Group Key encryption IV");
	//lib1x_hexdump2(MESS_DBG_KEY_MANAGE, "EncGTK", out, *outlen, "Encryted Group Key");

}


#ifdef RTL_WPA2_CLIENT
/*
	decrypt WPA2 Message 3's Key Data
*/
// Use RC4 or AES to decode the keydata by checking desc-ver, david-2006-01-06
//int DecWPA2KeyData(u_char *key, int keylen, u_char *kek, int keklen, u_char *kout)
int DecWPA2KeyData(Supp_Global* pGlobal, u_char *key, int keylen, u_char *kek, int keklen, u_char *kout)
{
	int	retVal = 0;
	u_char	default_key_iv[] = { 0xA6,0xA6,0xA6,0xA6,0xA6,0xA6,0xA6,0xA6 };
	u_char 	tmp2[257];

// Use RC4 or AES to decode the keydata by checking desc-ver, david-2006-01-06
	u_char 	tmp1[257];
	RC4_KEY	rc4key;

	lib1x_eapol_key *eapolkey = (lib1x_eapol_key *)(pGlobal->EAPOLMsgRecvd.Octet +
					ETHER_HDRLEN + LIB1X_EAPOL_HDRLEN);

	if (Message_KeyDescVer(pGlobal->EapolKeyMsgRecvd) == key_desc_ver1) {
		memcpy(tmp1, eapolkey->key_iv, KEY_IV_LEN);
		memcpy(tmp1+KEY_IV_LEN, kek, keklen);
		RC4_set_key(&rc4key, KEY_IV_LEN + keklen, tmp1);

		//first 256 bits is discard
		RC4(&rc4key, 256, (u_char*)tmp1, (u_char*)tmp2);
            		//RC4(&rc4key, keylen, eapol_key->key_data, global->skm_sm->GTK[Message_KeyIndex(global->EapolKeyMsgRecvd)]);
		RC4(&rc4key, keylen, pGlobal->EapolKeyMsgRecvd.Octet + KeyDataPos, (u_char*)tmp2);
		memcpy(kout, tmp2, keylen);
			//memcpy(&global->supp_kmsm->GTK[Message_KeyIndex(global->EapolKeyMsgRecvd)], tmp2, keylen);
			retVal = 1;
	}
	else
	{
//--------------------------------------------------------
	
		AES_UnWRAP(key, keylen, kek, keklen, tmp2);
#if 0
		wpa2_hexdump("DecGTK: kek", kek, keklen);
		wpa2_hexdump("DecGTK: key", key, keylen);
		wpa2_hexdump("DecGTK: out", tmp2, 8+keylen);
#endif
		if(memcmp(tmp2, default_key_iv, 8))
			retVal = 0;
		else {
			memcpy(kout, tmp2+8, keylen);
			retVal = 1;
		}
	}
	return retVal;
}

#endif /* RTL_WPA2_CLIENT */

/*

   The routine will set the key into state machine data structure for RC$
encryption and
   for AES_WRAP when DecGTK success.

   "DecGTK successful" means MIC of AES_WRAP algorithm has no data integrity
failure.
*/
int DecGTK(OCTET_STRING EAPOLMsgRecvd, u_char *kek, int keklen, int keylen,
u_char *kout)
{
	int		retVal = 0;

	u_char 		tmp1[257], tmp2[257];
	RC4_KEY		rc4key;


	lib1x_eapol_key * eapol_key = (lib1x_eapol_key *)(EAPOLMsgRecvd.Octet +
						ETHER_HDRLEN + LIB1X_EAPOL_HDRLEN);


	OCTET_STRING	EapolKeyMsgRecvd;
	EapolKeyMsgRecvd.Octet = EAPOLMsgRecvd.Octet +
					ETHER_HDRLEN + LIB1X_EAPOL_HDRLEN;
	EapolKeyMsgRecvd.Length = EAPOLMsgRecvd.Length -
					(ETHER_HDRLEN + LIB1X_EAPOL_HDRLEN);




	if(Message_KeyDescVer(EapolKeyMsgRecvd) == key_desc_ver1)
	{

			memcpy(tmp1, eapol_key->key_iv, KEY_IV_LEN);
			memcpy(tmp1 + KEY_IV_LEN, kek, keklen);
			RC4_set_key(&rc4key, KEY_IV_LEN + keklen, tmp1);
			//first 256 bits is discard
			RC4(&rc4key, 256, (u_char*)tmp1, (u_char*)tmp2);
            		//RC4(&rc4key, keylen, eapol_key->key_data, global->skm_sm->GTK[Message_KeyIndex(global->EapolKeyMsgRecvd)]);
			RC4(&rc4key, keylen, EapolKeyMsgRecvd.Octet + KeyDataPos, (u_char*)tmp2);
			memcpy(kout, tmp2, keylen);
			//memcpy(&global->supp_kmsm->GTK[Message_KeyIndex(global->EapolKeyMsgRecvd)], tmp2, keylen);
			retVal = 1;

	}else if(Message_KeyDescVer(EapolKeyMsgRecvd) == key_desc_ver2)
	{
			// kenny: should use default IV 0xA6A6A6A6A6A6A6A6
			u_char	default_key_iv[] = { 0xA6,0xA6,0xA6,0xA6,0xA6,0xA6,0xA6,0xA6 };
// david, get key len from eapol packet
//			AES_UnWRAP(EapolKeyMsgRecvd.Octet + KeyDataPos, keylen + 8, kek, keklen, tmp2);

			keylen = Message_KeyDataLength(EapolKeyMsgRecvd);
			AES_UnWRAP(EapolKeyMsgRecvd.Octet + KeyDataPos, keylen, kek, keklen, tmp2);
//------------------------- 2005-08-01

			//if(memcmp(tmp2, eapol_key->key_iv + 8, 8))
			if(memcmp(tmp2, default_key_iv, 8))
				retVal = 0;
			else
			{
				//memcpy(kout, tmp2, keylen);
				//memcpy(global->supp_kmsm->GTK[Message_KeyIndex(global->EapolKeyMsgRecvd)], tmp2 + 8, keylen - 8);
				memcpy(kout, tmp2+8, keylen);
				retVal = 1;
			}
	}

	return retVal;

}

#ifndef COMPACK_SIZE
void PrintHex(u_char *str, u_char *buf, int size)
{
	int i;
	printf("\t%s:", str);
	for(i=0 ; i<size ; i++){
			if(i%16 == 0 ) printf("\n\t\t");
				printf("%2x ", *(buf + i));
		}

	printf("\n");

}
#endif

//#define ENABLE_KEYDUMP
#ifdef ENABLE_KEYDUMP
void KeyDump(char *fun, u_char *buf, int size, char *comment)
{


	u_char *ptr;
	short len;
	struct lib1x_ethernet * eth = (struct lib1x_ethernet *)buf;
	lib1x_eapol_key * eapol_key = (lib1x_eapol_key *)(buf + ETHER_HDRLEN +
LIB1X_EAPOL_HDRLEN);


	printf("$$ %s $$: %s, packet length=%d\n", fun, comment, size);
	if (buf != NULL && EAPOLKEY_DEBUG >=2) {

		PrintHex((u_char*)"DstAddr", eth->ether_dhost, sizeof(eth->ether_dhost));
		PrintHex((u_char*)"SrcAddr", eth->ether_shost, sizeof(eth->ether_shost));
		//PrintHex((u_char*)"EtherType", (u_char*)eth->ether_type, sizeof(eth->
ether_type));

		//PrintHex((u_char*)"EAPOLHeader", (u_char*)(buf +  ETHER_HDRLEN),
LIB1X_EAPOL_HDRLEN);
		//printf("\tKeyDescVer:%x\n",  eapol_key->key_desc_ver);
		PrintHex((u_char *)"KeyInfo", eapol_key->key_info, sizeof(eapol_key->
key_info));
		//PrintHex((u_char *)"KeyLength", eapol_key->key_len, sizeof(eapol_key->
key_len));
		PrintHex((u_char *)"KeyReplayCounter", eapol_key->key_replay_counter,
sizeof(eapol_key->key_replay_counter));
		//PrintHex((u_char *)"KeyNonce", eapol_key->key_nounce, sizeof(eapol_key->
key_nounce));
		//PrintHex((u_char *)"KeyIV", eapol_key->key_iv, sizeof(eapol_key->
key_iv));
		//PrintHex((u_char *)"KeyReplaySequenceCounter", eapol_key->key_rsc,
sizeof(eapol_key->key_rsc));
		//PrintHex((u_char *)"KeyID", eapol_key->key_id, sizeof(eapol_key->
key_id));
		//PrintHex((u_char *)"KeyMIC", eapol_key->key_mic, sizeof(eapol_key->
key_mic));
		//PrintHex((u_char *)"KeyDataLength", eapol_key->key_data_len,
sizeof(eapol_key->key_data_len));
		ptr = buf + KeyDataLenPos;
		net2short(ptr, len);
		if(!len)
			PrintHex((u_char *)"KeyData", buf + KeyDataPos, len);
	}
	printf("\n");

}
#else
void KeyDump(char *fun, u_char *buf, int size, char *comment)
{}
#endif

/*-----------------------------------------------------------------------------
 LargeInteger
	Inline Function definition
-------------------------------------------------------------------------------*/
inline  void INCLargeInteger(LARGE_INTEGER * x){

	if( x->field.LowPart == 0xffffffff){
		if( x->field.HighPart == 0xffffffff)
		{
			x->field.HighPart = 0;
			x->field.LowPart = 0;
		}else
		{
			x->field.HighPart++;
			x->field.LowPart = 0;
		}
	}else
		x->field.LowPart++;
}

/*-----------------------------------------------------------------------------
 Octet16Integer
	Inline Function definition
-------------------------------------------------------------------------------*/

inline  void INCOctet16_INTEGER(OCTET16_INTEGER * x){

	if( LargeIntegerOverflow(x->field.LowPart)){
		if( LargeIntegerOverflow(x->field.HighPart))
		{
			LargeIntegerZero( x->field.HighPart);
			LargeIntegerZero( x->field.LowPart);
		}else
		{
			INCLargeInteger(&x->field.HighPart);
			LargeIntegerZero( x->field.LowPart);
		}
	}else
		INCLargeInteger(&x->field.LowPart);

}

/*-----------------------------------------------------------------------------
 OCTET32_INTEGER
	Inline Function definition
-------------------------------------------------------------------------------*/
inline OCTET32_INTEGER * INCOctet32_INTEGER(OCTET32_INTEGER * x)
{

	if( Octet16IntegerOverflow(x->field.LowPart)){
		if( Octet16IntegerOverflow(x->field.HighPart))
		{
			Octet16IntegerZero( x->field.HighPart);
			Octet16IntegerZero( x->field.LowPart);
		}else
		{
			INCOctet16_INTEGER(&x->field.HighPart);
			Octet16IntegerZero( x->field.LowPart);
		}
	}else
		INCOctet16_INTEGER(&x->field.LowPart);
	return x;
}

/*-----------------------------------------------------------------------------
 EAPOLKey field process
	Inline Function definition
	Macro definition
-------------------------------------------------------------------------------*/

inline
OCTET_STRING	SubStr(OCTET_STRING	f,	u_short	s,u_short	l)	{			\
			OCTET_STRING		res;	\
			res.Length = l;			\
			res.Octet = f.Octet+s;	\
			return	res;			\
		}


inline	void Message_ReplayCounter_OC2LI(OCTET_STRING f, LARGE_INTEGER * li){

	li->field.HighPart = ((u_long)(*(f.Octet + ReplayCounterPos + 3)))
					     + ((u_long)(*(f.Octet + ReplayCounterPos+ 2)) <<8 )
						 + ((u_long)(*(f.Octet + ReplayCounterPos + 1)) <<  16)
						 + ((u_long)(*(f.Octet + ReplayCounterPos + 0)) <<24);
	li->field.LowPart =  ((u_long)(*(f.Octet + ReplayCounterPos + 7)))
						 + ((u_long)(*(f.Octet + ReplayCounterPos + 6)) <<8 )
					  	 + ((u_long)(*(f.Octet + ReplayCounterPos + 5)) <<  16)
						 + ((u_long)(*(f.Octet + ReplayCounterPos + 4)) <<24);
}

inline	void ReplayCounter_OC2LI(OCTET_STRING f, LARGE_INTEGER * li){

	li->field.HighPart = ((u_long)(*(f.Octet + 3)))
					     + ((u_long)(*(f.Octet + 2)) <<8 )
						 + ((u_long)(*(f.Octet + 1)) << 16)
						 + ((u_long)(*(f.Octet + 0)) <<24);
	li->field.LowPart =  ((u_long)(*(f.Octet + 7)))
						 + ((u_long)(*(f.Octet + 6)) <<8 )
					  	 + ((u_long)(*(f.Octet + 5)) << 16)
						 + ((u_long)(*(f.Octet + 4)) <<24);
}

inline  void ReplayCounter_LI2OC(OCTET_STRING f, LARGE_INTEGER * li){

	*(f.Octet + 0) = (li->field.HighPart >> 24) & 0xff;
	*(f.Octet + 1) = (li->field.HighPart >> 16) & 0xff;
	*(f.Octet + 2) = (li->field.HighPart >>  8) & 0xff;
	*(f.Octet + 3) = (li->field.HighPart >>  0) & 0xff;

	*(f.Octet + 4) = (li->field.LowPart >> 24) & 0xff;
        *(f.Octet + 5) = (li->field.LowPart >> 16) & 0xff;
        *(f.Octet + 6) = (li->field.LowPart >>  8) & 0xff;
        *(f.Octet + 7) = (li->field.LowPart >>  0) & 0xff;
}

/*-----------------------------------------------------------------------------------------------
	f is EAPOL-KEY message
------------------------------------------------------------------------------------------------*/
inline int Message_EqualReplayCounter(LARGE_INTEGER li1, OCTET_STRING f)
{
	LARGE_INTEGER li2;
	Message_ReplayCounter_OC2LI(f, &li2);
	if(li1.field.HighPart == li2.field.HighPart && li1.field.LowPart ==
li2.field.LowPart)
		return 1;
	else
		return 0;
}
/*-------------------------------------------------------------------------------------------
	li1 is recorded replay counter on STA
	f is the replay counter from EAPOL-KEY message
---------------------------------------------------------------------------------------------*/
inline int Message_SmallerEqualReplayCounter(LARGE_INTEGER li1, OCTET_STRING f)
//f<li1
{
	LARGE_INTEGER li2;
	Message_ReplayCounter_OC2LI(f, &li2);
	if(li2.field.HighPart > li1.field.HighPart)
		return 0;
	else if(li2.field.HighPart < li1.field.HighPart)
		return 1;
	else if(li2.field.LowPart > li1.field.LowPart)
		return 0;
	else if(li2.field.LowPart <= li1.field.LowPart)
		return 1;
	else
		return 0;
}

/*---------------------------------------------------------------------------------------------
	li1 is recorded replay counter on STA
	f is the replay counter from EAPOL-KEY message
-----------------------------------------------------------------------------------------------*/
inline int Message_LargerReplayCounter(LARGE_INTEGER li1, OCTET_STRING f)
{
	LARGE_INTEGER li2;
	Message_ReplayCounter_OC2LI(f, &li2);

	//lib1x_message(MESS_DBG_KEY_MANAGE, "Authenticator : HighPart = %d, LowPart = %d\n", li1.field.HighPart, li1.field.LowPart);
	//lib1x_message(MESS_DBG_KEY_MANAGE, "Supplicant : HighPart = %d, LowPart = %d\n", li2.field.HighPart, li2.field.LowPart);

	if(li2.field.HighPart > li1.field.HighPart)
		return 1;
	else if(li2.field.LowPart > li1.field.LowPart)
		return 1;
	else
		return 0;

}


inline  void Message_setReplayCounter(OCTET_STRING f, u_long h, u_long l){

	LARGE_INTEGER *li = (LARGE_INTEGER *)(f.Octet + ReplayCounterPos);
	li->charData[0] = (u_char)(h >> 24) & 0xff;
	li->charData[1] = (u_char)(h >> 16) & 0xff;
	li->charData[2] = (u_char)(h >>  8) & 0xff;
	li->charData[3] = (u_char)(h >>  0) & 0xff;
	li->charData[4] = (u_char)(l >> 24) & 0xff;
	li->charData[5] = (u_char)(l >> 16) & 0xff;
	li->charData[6] = (u_char)(l >>  8) & 0xff;
	li->charData[7] = (u_char)(l >>  0) & 0xff;

}

void SetNonce(OCTET_STRING ocDst, OCTET32_INTEGER oc32Counter)
{
	u_char *ptr = ocDst.Octet;

	long2net(oc32Counter.field.HighPart.field.HighPart.field.HighPart, ptr);
	ptr+=4;
	long2net(oc32Counter.field.HighPart.field.HighPart.field.LowPart, ptr);
	ptr+=4;
	long2net(oc32Counter.field.HighPart.field.LowPart.field.HighPart, ptr);
	ptr+=4;
	long2net(oc32Counter.field.HighPart.field.LowPart.field.LowPart, ptr);
	ptr+=4;
	long2net(oc32Counter.field.LowPart.field.HighPart.field.HighPart, ptr);
        ptr+=4;
        long2net(oc32Counter.field.LowPart.field.HighPart.field.LowPart, ptr);
        ptr+=4;
        long2net(oc32Counter.field.LowPart.field.LowPart.field.HighPart, ptr);
        ptr+=4;
        long2net(oc32Counter.field.LowPart.field.LowPart.field.LowPart, ptr);



}

#ifdef RTL_WPA2
void SetEAPOL_KEYIV(OCTET_STRING ocDst, OCTET32_INTEGER oc32Counter)
{
	u_char *ptr = ocDst.Octet;

	long2net(oc32Counter.field.LowPart.field.HighPart.field.HighPart, ptr);
        ptr+=4;
        long2net(oc32Counter.field.LowPart.field.HighPart.field.LowPart, ptr);
        ptr+=4;
        long2net(oc32Counter.field.LowPart.field.LowPart.field.HighPart, ptr);
        ptr+=4;
        long2net(oc32Counter.field.LowPart.field.LowPart.field.LowPart, ptr);
}
#endif /* RTL_WPA2 */


