/* @File: apac_hyfi20_wps.c  
 * @Notes:
 *
 * Copyright (c) 2011-2012 Qualcomm Atheros, Inc.
 * Qualcomm Atheros Confidential and Proprietary. 
 * All rights reserved.
 *
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


#include "wsplcd.h"
#include "apclone.h"
#include "eloop.h"

#include "apac_hyfi20_wps.h"
#include "apac_hyfi20_mib.h"
#include "apac_priv.h"

static int apac_wps_set_wifi_configuration(struct apac_wps_session* sess, u8 *buf, size_t len);
static int apac_wps_clear_target_info(struct apac_wps_data *data);
static int is_hex(const u8 *data, size_t len)
{
        size_t i;

        for (i = 0; i < len; i++) {
                if (data[i] < 32 || data[i] >= 127)
                        return 1;
        }
        return 0;
}

u32 apac_get_wps_rfband(apacHyfi20WifiFreq_e freq) {
    switch (freq) {
        case (APAC_WIFI_FREQ_2):
            return WPS_RFBAND_24GHZ;
        case (APAC_WIFI_FREQ_5): 
            return WPS_RFBAND_50GHZ;
        case (APAC_WIFI_FREQ_60):
            return WPS_RFBAND_600GHZ;
       
        default:
            dprintf(MSG_ERROR, "%s, Freq#%u not recognized!\n", __func__, freq);
            return ~0;
    }
}

apacHyfi20WifiFreq_e apac_get_freq(u32 rf_band) {
    switch (rf_band) {
        case (WPS_RFBAND_24GHZ):
            return APAC_WIFI_FREQ_2;
        case (WPS_RFBAND_50GHZ):
            return APAC_WIFI_FREQ_5;
        case (WPS_RFBAND_600GHZ):
            return APAC_WIFI_FREQ_60;
       
        default:
            dprintf(MSG_ERROR, "%s, rf_band#%u not recognized!\n", __func__, rf_band);
            return APAC_WIFI_FREQ_INVALID;
    }
}

/* Allocate memory for apac_wps_data and target */
static int
apac_wps_init_apacwps_data(struct apac_wps_session* sess)
{
    // allocate memory for eapwps data
    sess->pWpsData = os_zalloc(sizeof(APAC_WPS_DATA));
    if (!sess->pWpsData) {
        dprintf(MSG_ERROR, "Failed to alloc mem for eapwps data\n");
        return -1;
    }
  
     /*Device Password for PBC*/
    os_memcpy(sess->pWpsData->dev_pwd, "00000000", 8);
    sess->pWpsData->dev_pwd_len = 8;
    sess->pWpsData->dev_pwd_id  = WPS_DEVICEPWDID_PUSH_BTN;

    // now alloc mem for target info
    sess->pWpsData->target = os_zalloc(sizeof(struct apac_wps_target_info));
    if (!sess->pWpsData->target) {
        dprintf(MSG_ERROR, "Failed to alloc mem for eapwps target data\n");
        return -1;
    }

    return 0;
}


static void
apac_wps_deinit_apacwps_data(struct apac_wps_session* sess)
{
    APAC_WPS_DATA    *data = sess->pWpsData;

    if (!data)
        return;

    if (data->sndMsg) {
        os_free(data->sndMsg);
    }

    if (data->rcvMsg) {
        os_free(data->rcvMsg);
    }

    apac_wps_clear_target_info(data);
    if (data->target) {
        // free target data memory
        os_free(data->target);
        data->target = NULL;
    }

    if (data->config)
        os_free(data->config);

    // free eapwps data
    os_free(data);
}


struct apac_wps_session*
apac_wps_new_session(apacHyfi20Data_t* pData)
{
    struct apac_wps_session* sess;
    sess = (struct apac_wps_session*)os_zalloc(sizeof(struct apac_wps_session));
    if( !sess)
    {
        dprintf(MSG_ERROR, "Session alloc failure\n");	
        return NULL;
    }
    os_memset(sess, 0, sizeof(struct apac_wps_session));

    sess->state = (pData->config.role == APAC_REGISTRAR ? APAC_WPS_R_INIT : APAC_WPS_E_M1_SENT);
    sess->wps_session_ts = 0;
    sess->wps_retrans_ts = 0;
    sess->wps_message_ts = 0;
    sess->pData = pData;
    sess->prev = NULL;
    sess->next = NULL;
    os_memcpy(sess->own_addr, pData->alid, ETH_ALEN);

    if (apac_wps_init_apacwps_data(sess)) {
        dprintf(MSG_ERROR, "Failed to Allocate APACWPS data\n");
	    os_free (sess);
        return NULL;
    }
	
    sess->next = pData->sess_list;
    if (sess->next) {
    	sess->next->prev = sess; 
    }
    pData->sess_list =sess;

    eloop_register_timeout(1, 0, 
		apacHyfi20WpsSessionTimeoutHandler, sess, NULL);

    dprintf(MSG_INFO, "%s, 1905.1 AP Auto Configuration Start\n", __func__);	
    return sess;
}

void apac_wps_del_session(struct apac_wps_session* sess)
{
    apacHyfi20Data_t* pData;
    pData = sess->pData;
    /* Information to user*/
    {
        APAC_WPS_DATA *data;
        data = sess->pWpsData;
        if (sess->wps_sess_success && data)
            dprintf(MSG_INFO, "%s, 1905.1 AP Auto Configuration Done, Peer "MACSTR", Freq %d\n", 
                __func__, MAC2STR(sess->dest_addr), apac_get_freq(data->target->rf_bands));
    }


    eloop_cancel_timeout(apacHyfi20WpsSessionTimeoutHandler, sess, NULL); 

    apac_wps_deinit_apacwps_data(sess);

    if (sess == pData->sess_list)
    {
	pData->sess_list = sess ->next;
    }
    else
    {
        sess->prev->next = sess->next;
    }
	
    if (sess->next)
    	sess->next->prev = sess->prev; 	


    if (sess->wsc_msg)
	free (sess->wsc_msg);
    free (sess);	

}

struct apac_wps_session*
apac_wps_find_session(apacHyfi20Data_t* pData, u8 *mac)
{
    struct apac_wps_session* sess;
    sess = pData->sess_list;
    while (sess)
    {
        if (os_memcmp(sess->dest_addr, mac, ETH_ALEN) == 0) return sess;
	    sess = sess ->next;
    }

    return NULL;	
}

int apac_wps_finish_session(struct apac_wps_session* sess)
{
    struct apac_wps_data *data = sess->pWpsData;
    struct apac_wps_target_info *target;

    if (data && data->target)
    {
	target = data->target;
        if (target->config && target->config_len)
        {
           if (apac_wps_set_wifi_configuration(sess, target->config, target->config_len))
              dprintf(MSG_DEBUG, "Invalid config,  AP autoconfig session fails\n");
           else
              dprintf(MSG_DEBUG, "AP autoconfig session success\n");
        }
    }

    return 0;
}


static int apac_wps_get_wifi_configuration(
	struct apac_wps_session* sess,
        u8 **buf,       /* output, allocated i.e. buffer */
        size_t *len)    /* output, length of data in buffer */
{
    apacHyfi20Data_t* pApacData = sess->pData;
    //struct wps_config *conf = pApacData->config.wpsConf;
    APAC_WPS_DATA *data = sess->pWpsData;
    apacHyfi20WifiFreq_e freq;

    int ret = -1;
    struct wps_data *wps = 0;

    apacHyfi20AP_t* apinfo;
    u8 *nwKey = NULL;
    size_t nw_key_length = 0;
    int allocated = 0;

    apacHyfi20TRACE();

    if (!data->target)
    {
        dprintf(MSG_ERROR, "%s, target is invalid\n", __func__);
        return -1; 
    }
    freq = apac_get_freq(data->target->rf_bands);

    if (freq == APAC_WIFI_FREQ_INVALID) {
        dprintf(MSG_ERROR, "%s, freq#%u is undefined!\n", __func__, freq);
        return -1; 
    }

    apinfo = &pApacData->ap[freq];

    do {
        if (!buf || !len)
            break;

        *buf = 0;
        *len = 0;

        if (apac_mib_get_wifi_configuration(&pApacData->ap[freq], apinfo->vap_index) < 0 )
        {
           break;  
        }

        if (wps_create_wps_data(&wps))
            break;


        if (wps_set_value(wps, WPS_TYPE_SSID, apinfo->ssid, apinfo->ssid_len))
        {
            dprintf(MSG_ERROR, "%s - Set SSID error! ssid: %s\n", __func__, apinfo->ssid);
            break;
        }

        /* Authentication Type */
        if (wps_set_value(wps, WPS_TYPE_AUTH_TYPE, &apinfo->auth, 0))
        {
           dprintf(MSG_ERROR, "%s - Set AuthType error! auth: %u\n", __func__, apinfo->auth);
           break;
        }

        /* Encryption Type */
        if (wps_set_value(wps, WPS_TYPE_ENCR_TYPE, &apinfo->encr, 0))
        {
            dprintf(MSG_ERROR, "%s - Set EncrType error! encr: %u\n", __func__, apinfo->encr);
            break;
        }

        /*in case buffer overflow*/
        if (apinfo->nw_key_len > MAX_NW_KEY_LEN)
        {
            dprintf(MSG_ERROR, "Invalid length[%d] of network key\n", apinfo->nw_key_len);
            break;
        }

        if (apinfo->nw_key_index > 0) { /* WEP Network Key*/
            if (wps_set_value(wps, WPS_TYPE_NW_KEY_INDEX, &apinfo->nw_key_index  , 0))
                break;

            if (is_hex((u8 *)apinfo->nw_key, apinfo->nw_key_len)) {
                nwKey = wpa_zalloc(apinfo->nw_key_len * 2 + 1);
                if (!nwKey)
                    break;
                allocated = 1;
                nw_key_length = wpa_snprintf_hex_uppercase((char *)nwKey, apinfo->nw_key_len * 2 + 1,
                     (u8 *)apinfo->nw_key, apinfo->nw_key_len);
                if (nw_key_length != apinfo->nw_key_len * 2) {
                    os_free(nwKey);
                    allocated = 0;
                    break;
                }
            } else {
                nw_key_length = apinfo->nw_key_len;
                nwKey = (u8 *)apinfo->nw_key;
            }
        } else if (apinfo->nw_key_index == 0) {
            /* Not WEP */
            if (is_hex((u8 *)apinfo->nw_key, apinfo->nw_key_len) && apinfo->nw_key_len == 64) {                                
                nwKey = wpa_zalloc(64 + 1);
                if (!nwKey)
                    break;
                allocated = 1;
                nw_key_length = wpa_snprintf_hex_uppercase((char *)nwKey, 64 + 1, (u8 *)apinfo->nw_key, apinfo->nw_key_len);
                if (nw_key_length != 64) {
                    os_free(nwKey);
                    allocated = 0;
                    break;
                }


            } else{
                nw_key_length = apinfo->nw_key_len;
                nwKey = (u8 *)apinfo->nw_key;
            }
        }

        /* Network Key */
        if (nwKey && nw_key_length) {
            if (wps_set_value(wps, WPS_TYPE_NW_KEY, nwKey, nw_key_length)) 
            {
                dprintf(MSG_ERROR, "%s - Set NwKey error! nw_key: %s\n", __func__, apinfo->nw_key);
                break;
            }
        }

        if (nwKey && allocated) {
            os_free(nwKey);
            nwKey = NULL;
        }

        /* MAC address -- AP's MAC when Enrollee is AP*/
        if (wps_set_value(wps, WPS_TYPE_MAC_ADDR, data->target->mac, 6))
        {
            dprintf(MSG_ERROR, "Set Enrollee's MAC error! %s\n", __func__);
            break;
        }
        

        /* QCA Vendor Extension */
        if (pApacData->config.deep_clone_enabled
            && apac_mib_get_qca_ext(&pApacData->ap[freq], apinfo->vap_index) == 0)
        {
            if (wps_set_value(wps, WPS_TYPE_VENDOR_EXT,
               pApacData->ap[freq].qca_ext, 
               pApacData->ap[freq].qca_ext_len)) 
            {
                dprintf(MSG_ERROR, "Set QCA Extention error!\n");
                break;
            }
            dprintf(MSG_DEBUG, "Get QCA Extention with length %d!\n", pApacData->ap[freq].qca_ext_len);
        }

        if (wps_write_wps_data(wps, buf, len))
            break;

        ret = 0;
    } while (0);

    (void)wps_destroy_wps_data(&wps);
  
    if (ret) {
        if (buf && *buf) {
                os_free(*buf);
                *buf = 0;
        }
        if (len)
                *len = 0;
    }

    return ret;
}


static int apac_wps_set_wifi_configuration(
	struct apac_wps_session* sess,
        u8 *buf,   
        size_t len)
{
    apacHyfi20Data_t* pApacData = sess->pData;
    APAC_WPS_DATA *data = sess->pWpsData;
    apacHyfi20WifiFreq_e freq = apac_get_freq(data->target->rf_bands);
    int ret = -1;
    apacHyfi20AP_t* apinfo;
    struct wps_data *wps = 0;
    int itlv;
    size_t mlen = ETH_ALEN;
    apacBool_e changeBand = APAC_FALSE;

    if (freq == APAC_WIFI_FREQ_INVALID) {
        dprintf(MSG_ERROR, "%s, freq#%u is undefined!\n", __func__, freq);
        return -1; 
    }

    apinfo = &pApacData->ap[freq];
    if (!apinfo->valid) {
        dprintf(MSG_ERROR, "%s, No valid AP (or STA) on freq%u!\n", __func__, freq);
        return -1;
    }

    apinfo->channel = 0;
    if (apinfo->qca_ext)
    {
        free (apinfo->qca_ext);
        apinfo->qca_ext_len = 0;
    }

    do {

        if(wps_create_wps_data(&wps))
            return ret;

        if (wps_parse_wps_data(buf, len , wps))
        {
            dprintf(MSG_ERROR, "Cred parse error\n");
            goto fail;
        }

      for (itlv = 0; itlv < wps->count; itlv++) {
        struct wps_tlv *tlv = wps->tlvs[itlv];
        if (tlv == NULL)
            break;
        switch (tlv->type) {
            case WPS_TYPE_SSID:
                apinfo->ssid_len = MAX_SSID_LEN ; 
                if (wps_tlv_get_value(tlv, apinfo->ssid, &apinfo->ssid_len) < 0)
                {
                    dprintf(MSG_ERROR, "Invalid SSID length\n");
                    goto fail;
                }
                apinfo->ssid[apinfo->ssid_len] = '\0';		
                dprintf(MSG_INFO, "Receive cred SSID: '%s',length: %d\n", apinfo->ssid, apinfo->ssid_len);
                break;
				
            case WPS_TYPE_AUTH_TYPE:
                apinfo->auth = tlv->value.u16_;
                dprintf(MSG_INFO, "Receive cred AUTH: 0x%04x\n", apinfo->auth);
                break;
				
            case WPS_TYPE_ENCR_TYPE:
                apinfo->encr= tlv->value.u16_;
                dprintf(MSG_INFO, "Receive cred ENCR: 0x%04x\n", apinfo->encr);
                break;
				
            case WPS_TYPE_NW_KEY_INDEX:
                apinfo->nw_key_index = tlv->value.u8_;
                if ((apinfo->nw_key_index< 1) || (apinfo->nw_key_index> 4)) {
                    dprintf(MSG_INFO, "Invalid KEY Index: 0x%02x\n", apinfo->nw_key_index);					
                    apinfo->nw_key_index = 1;
                }
                dprintf(MSG_INFO, "Receive cred KEY Index: 0x%02x\n", apinfo->nw_key_index);				
                break;
				
            case WPS_TYPE_NW_KEY:
                apinfo->nw_key_len = MAX_NW_KEY_LEN;
                if (wps_tlv_get_value(tlv, apinfo->nw_key, &apinfo->nw_key_len) < 0)
                {
                    dprintf(MSG_ERROR, "Invalid KEY length\n");
                    goto fail;
                }
                apinfo->nw_key[apinfo->nw_key_len] =  '\0';					
                dprintf(MSG_INFO, "Receive cred KEY: %s, length: %d\n", apinfo->nw_key, apinfo->nw_key_len);				
                break;

            case WPS_TYPE_MAC_ADDR:
                if (wps_tlv_get_value(tlv, apinfo->ap_mac, &mlen) < 0)
                {
                    dprintf(MSG_ERROR, "Invalid MAC length\n");
                    goto fail;
                }
                dprintf(MSG_INFO, "Receive MAC of Enrollee: "MACSTR"\n", MAC2STR(apinfo->ap_mac));
                break;

            case WPS_TYPE_KEY_WRAP_AUTH:
                break;

            case WPS_TYPE_VENDOR_EXT:
                if (!pApacData->config.deep_clone_enabled)
                    break;
                apinfo->qca_ext = os_malloc(1024);
                if (!apinfo->qca_ext)
                {
                    dprintf(MSG_ERROR, "QCA vendor extension malloc failed\n");
                    goto fail;
                }
                apinfo->qca_ext_len = 1024;
                if (wps_tlv_get_value(tlv, apinfo->qca_ext, &apinfo->qca_ext_len) < 0)
                {
                    dprintf(MSG_ERROR, "Invalid QCA Extension\n");
                    goto fail;
                }
                dprintf(MSG_INFO, "Receive QCA Extension, length: %d\n", apinfo->qca_ext_len);	
                break;
            default:
                dprintf(MSG_INFO, "Unknown credential type: 0x%04X\n", tlv->type);	
				
        }
      }
  
    } while(0);

    /* Configure STA */
    if(pApacData->config.config_sta == APAC_TRUE)
    {
        int i;
        apacHyfi20IF_t *pIF = pApacData->hyif;

        for (i = 0; i < APAC_MAXNUM_HYIF; i++) {
            if (!pIF[i].valid)
                continue;
            if (pIF[i].mediaType == APAC_MEDIATYPE_WIFI
                && pIF[i].wlanDeviceMode == APAC_WLAN_STA
                && pIF[i].wifiFreq == freq)
            {

                int unmanaged = apac_mib_get_wsplcdUnmanaged_by_vapindex(pIF[i].vapIndex);
                if (unmanaged < 0) {
                    dprintf(MSG_ERROR, "%s: Failed to resolve wsplcd unmanaged flag on %s\n",
                            __func__, pIF[i].ifName);
                    goto fail;
                } else if (unmanaged) {
                    dprintf(MSG_DEBUG, "%s: %s is marked as WSPLCD unmanaged\n",
                            __func__, pIF[i].ifName);
                    continue;
                }

                /* check if need to enable band adaptation */
                if (apinfo->isStaOnly && pApacData->config.band_sel_enabled &&                   
		(pApacData->config.wlan_chip_cap == APAC_DB)) {
                    changeBand = APAC_TRUE;
                }
               ret = apac_mib_set_wifi_configuration(pApacData->wifiConfigHandle,
                                                     apinfo, APAC_WLAN_STA,
                                                     pIF[i].vapIndex, "", changeBand,

                                                     pApacData->config.manage_vap_ind,
                                                     pApacData->config.deep_clone_no_bssid);
               if (ret)
               {
                   dprintf(MSG_ERROR, "set STA[%s] configuration failed\n", pIF[i].ifName);  
               }
               else
               {
                   /* Stop STA if it is not associated when scanning timeout*/
#if 0
                   if(apinfo->channel == 0)
                   {
                       eloop_register_timeout(20, 0, apacHyfi20ScanningTimeoutHandler, pIF, NULL);
                   }
#endif
               }

               /* Assume: there is maximal one STA per radio*/
               break;
            }
        }

    }

    /* there is an AP on this freq */
    if (!apinfo->isStaOnly) {
        changeBand = pApacData->config.band_sel_enabled &&
                     (pApacData->config.wlan_chip_cap == APAC_DB);

        ret = apac_mib_set_wifi_configuration(pApacData->wifiConfigHandle, apinfo,
                                              APAC_WLAN_AP, apinfo->vap_index,
                                              pApacData->config.ssid_suffix,
                                              changeBand,
                                              pApacData->config.manage_vap_ind,
                                              pApacData->config.deep_clone_no_bssid);
	if (ret)
        {
            dprintf(MSG_ERROR, "set AP configuration failed\n");  
            goto fail;
        }
    }

fail:
    wps_destroy_wps_data(&wps);
    return ret;
}

static int apac_wps_generate_sha256hash(u8 *inbuf, int inbuf_len, u8 *outbuf)
{
	int ret = -1;

	do {
		if (!inbuf || !inbuf_len || !outbuf)
			break;

        const u8 *vec[1];
        size_t vlen[1];
        vec[0] = inbuf;
        vlen[0] = inbuf_len;
        sha256_vector(1, vec, vlen, outbuf);

		ret = 0;
	} while (0);

	return ret;
}

static int apac_wps_free_dh(void **dh)
{
	int ret = -1;
	do {
		if (!dh || !*dh)
			break;

        os_free(*dh);
        *dh = NULL;
        ret = 0;
	} while (0);

	return ret;
}


static int apac_wps_generate_public_key(void **dh_secret, u8 *public_key)
{
	int ret = -1;

    if (dh_secret) *dh_secret = NULL;

	do {
        size_t len;
		if (!dh_secret || !public_key)
			break;

        /* We here generate both private key and public key.
        * For compatibility with the openssl version of code
        * (from Sony), dh_secret retains the private key
        * it is NOT the Diffie-Helman shared secret!).
        * The private key is used later to generate various other
        * data that can be decrypted by recipient using the public key.
        */
        *dh_secret = os_malloc(SIZE_PUB_KEY);
        if (*dh_secret == NULL) break;
        RAND_bytes(*dh_secret, SIZE_PUB_KEY);  /* make private key */
        len = SIZE_PUB_KEY;
        if (crypto_mod_exp(
                DH_G_VALUE,
                sizeof(DH_G_VALUE),
                *dh_secret,     /* private key */
                SIZE_PUB_KEY,
                DH_P_VALUE,
                sizeof(DH_P_VALUE),
                public_key,     /* output */
                &len            /* note: input/output */
                ) ) break;
        if (0 < len && len < SIZE_PUB_KEY) {
                /* Convert to fixed size big-endian integer */
                memmove(public_key+(SIZE_PUB_KEY-len),
                    public_key, len);
                memset(public_key, 0, (SIZE_PUB_KEY-len));
        } else if (len != SIZE_PUB_KEY) 
                break;
        ret = 0;
    } while (0);

    if (ret) {
        if (dh_secret && *dh_secret) os_free(*dh_secret);
        if (dh_secret) *dh_secret = NULL;
    }

    return ret;
}


static int apac_wps_generate_kdk(struct apac_wps_data *data, u8 *e_nonce, u8 *mac,
								u8 *r_nonce, u8 *kdk)
{
    int ret = -1;

    do {
        u8 *dh_secret = data->dh_secret;  /* actually, is private key*/
            u8 dhkey[SIZE_DHKEY/*32 bytes*/];
        u8 shared_secret[SIZE_PUB_KEY];  /* the real DH Shared Secret*/
            const u8 *vec[3];
            size_t vlen[3];

		if (!dh_secret || !e_nonce || !mac || !r_nonce || !kdk)
			break;

        /* Calculate the Diffie-Hellman shared secret g^AB mod p
        * by calculating (PKr)^A mod p
        * (For compatibility with Sony code, dh_secret is NOT
        * the Diffie-Hellman Shared Secret but instead contains
        * just the private key).
        */
        size_t len = SIZE_PUB_KEY;
        if (crypto_mod_exp(
                data->target->pubKey,
                SIZE_PUB_KEY,
                dh_secret,              /* our private key */
                SIZE_PUB_KEY,
                DH_P_VALUE,
                sizeof(DH_P_VALUE),
                shared_secret,         /* output */
                &len               /* in/out */
                )) break;
        if (0 < len && len < SIZE_PUB_KEY) {
                /* Convert to fixed size big-endian integer */
                memmove(shared_secret+(SIZE_PUB_KEY-len),
                    shared_secret, len);
                memset(shared_secret, 0, (SIZE_PUB_KEY-len));
        } else if (len != SIZE_PUB_KEY) 
                break;

        /* Calculate DHKey (hash of DHSecret)
        */
        vec[0] = shared_secret;
        vlen[0] = SIZE_PUB_KEY;  /* DH Secret size, 192 bytes */
        sha256_vector(
                1,  // num_elem
                vec,
                vlen,
                dhkey   /* output: 32 bytes */
                );

        /* Calculate KDK (Key Derivation Key)
        */
        vec[0] = e_nonce;
        vlen[0] = SIZE_NONCE;
        vec[1] = mac;
        vlen[1] = SIZE_MAC_ADDR;
        vec[2] = r_nonce;
        vlen[2] = SIZE_NONCE;
        hmac_sha256_vector(
                dhkey,
                SIZE_DHKEY,
                3,              /* num_elem */
                vec,
                vlen,
                kdk     /* output: 32 bytes */
                );
        ret = 0;
   } while (0);

	return ret;
}


static int apac_wps_key_derive_func(struct apac_wps_data *data, 
						   u8 *kdk,
						   u8 keys[KDF_OUTPUT_SIZE])
{
    const char *personalization = WPS_PERSONALIZATION_STRING;
	int ret = -1;

	do {
        const u8 *vec[3];
        size_t vlen[3];
        u8 cb1[4];
        u8 cb2[4];
        int iter;

		WPA_PUT_BE32(cb2, KDF_KEY_BITS/*== 640*/);
        vec[0] = cb1;   /* Note: cb1 modified in loop below */
        vlen[0] = sizeof(cb1);
        vec[1] = (void *)personalization;
        vlen[1] = os_strlen(personalization);
        vec[2] = cb2;
        vlen[2] = sizeof(cb2);

        for (iter = 0; iter < KDF_N_ITERATIONS; iter++) {
            WPA_PUT_BE32(cb1, iter+1);
            hmac_sha256_vector(
                    kdk,
                    SIZE_KDK,
                    3,      /* num_elem */
                    vec,
                    vlen,
                    keys + SHA256_MAC_LEN*iter  /* out: 32 bytes/iteration */
                    );
        }
        ret = 0;
    } while (0);
    return ret;
}

static int apac_wps_hmac_validation(struct apac_wps_data *data,
	   u8 *authenticator, u8 *auth_key)
{
	int ret = -1;

	struct wps_data *wps = 0;
	u8 *buf = 0;
	size_t buf_len;
	u8 hmac[SIZE_256_BITS];

	do {
		if (!data || !authenticator || !auth_key)
			break;

        /* Atheros note: this Sony code goes to a lot of extra effort 
         * to parse the data, remove the authenticator and then
         * recreate the original packet minus the authenticator...
         * not necessary since the authenticator will always
         * be at the end... so it could be optimized...
         */

		if (wps_create_wps_data(&wps))
			break;

		if (wps_parse_wps_data(data->rcvMsg, data->rcvMsgLen, wps))
			break;

		if (wps_remove_value(wps, WPS_TYPE_AUTHENTICATOR))
			break;

		if (wps_write_wps_data(wps, &buf, &buf_len))
			break;

        {
            const u8 *vec[2];
            size_t vlen[2];
            vec[0] = data->sndMsg;
            vlen[0] = data->sndMsgLen;
            vec[1] = buf;
            vlen[1] = buf_len;
            hmac_sha256_vector(
                auth_key,
                SIZE_AUTH_KEY,
                2,  /* num_elem */
                vec,
                vlen,
                hmac);

////////////////// DEBUG /////////////////////////////////////////////////
            {
                int dlevel = MSG_MSGDUMP;
                int i=0;
                dprintf(dlevel, "Computed Authenticator from M2:\n");
                for(;i<SIZE_256_BITS;i++){
                    dprintf(dlevel, "%02X ", hmac[i]);
                }
                dprintf(dlevel, "\n");

                dprintf(dlevel, "%s -- vec0 len:%u\n", __func__, vlen[0]);
                printMsg((u8 *)vec[0], vlen[0], dlevel);

                dprintf(dlevel, "%s -- vec1 len:%u\n", __func__, vlen[1]);
                printMsg((u8 *)vec[1], vlen[1], dlevel);


                dprintf(dlevel, "%s -- authenticator:\n", __func__);
                for(i=0;i<SIZE_256_BITS;i++){
                    dprintf(dlevel, "%02X ", authenticator[i]);
                }
                dprintf(dlevel, "\n");
            }
//////////////////////////////////////////////////////////////////////////
        }

		if (os_memcmp(hmac, authenticator, SIZE_64_BITS))
			break;

		ret = 0;
	} while (0);

	if (buf)
		os_free(buf);

	(void)wps_destroy_wps_data(&wps);

	return ret;
}

static int apac_wps_encrypt_data(struct apac_wps_data *data,
								u8 *inbuf, int inbuf_len,
								u8 *encrKey,
								u8 *iv, u8 **cipher, int *cipher_len)
{
	int ret = -1;

        #ifdef CONFIG_CRYPTO_INTERNAL

        void *aesHandle = NULL;

        if (cipher) *cipher = NULL;
        do {
                u8 *lastcipher;
                u8 *thiscipher;
                aesHandle = aes_encrypt_init(encrKey, ENCR_DATA_BLOCK_SIZE);
                if (aesHandle == NULL)
                    break;

		RAND_bytes(iv, ENCR_DATA_BLOCK_SIZE);
                lastcipher = iv;

		if (!cipher || !cipher_len)
			break;

                /* The output is up to one block larger than the input */
                *cipher = os_malloc(inbuf_len+ENCR_DATA_BLOCK_SIZE);
                if (*cipher == NULL)
                    break;

                *cipher_len = 0;
                thiscipher = *cipher;
                for (;; ) {
                        u8 block[ENCR_DATA_BLOCK_SIZE];
                        int i;
                        int thislen = inbuf_len;
                        if (thislen > ENCR_DATA_BLOCK_SIZE)
                                thislen = ENCR_DATA_BLOCK_SIZE;
                        if (thislen > 0) 
                                memcpy(block, inbuf, thislen );
                        if (thislen < ENCR_DATA_BLOCK_SIZE) {
                                /* Last block: 
                                 * pad out with a byte value that gives the 
                                 * number of padding bytes.
                                 */
                                int npad = ENCR_DATA_BLOCK_SIZE - thislen;
                                int ipad;
                                for (ipad = 0; ipad < npad; ipad++) {
                                        block[ENCR_DATA_BLOCK_SIZE-ipad-1] = 
                                                npad;
                                }
                        }
                        /* Cipher Block Chaining (CBC) -- 
                         * xor the plain text with the last AES output
                         * (or initially, the "initialization vector").
                         */
                        for (i = 0; i < ENCR_DATA_BLOCK_SIZE; i++) {
                                block[i] ^= lastcipher[i];
                        }
                        /* And encrypt and store in output */
                        aes_encrypt(aesHandle, block, thiscipher);
                        lastcipher = thiscipher;
                        thiscipher += ENCR_DATA_BLOCK_SIZE;
                        *cipher_len += ENCR_DATA_BLOCK_SIZE;
                        if ( thislen < ENCR_DATA_BLOCK_SIZE ) {
                                ret = 0;
                                break;
                        }
                        inbuf += ENCR_DATA_BLOCK_SIZE;
                        inbuf_len -= ENCR_DATA_BLOCK_SIZE;
                }
        } while (0);
        if (aesHandle) aes_encrypt_deinit(aesHandle);

        #else   /* CONFIG_CRYPTO_INTERNAL */

	EVP_CIPHER_CTX ctx;
	u8 buf[1024];
	int buf_len;
	int length, curr_len; int block_size;

        if (cipher) *cipher = NULL;
	do {
		RAND_bytes(iv, SIZE_128_BITS);

		if (!cipher || !cipher_len)
			break;

		if (!EVP_EncryptInit(&ctx, EVP_aes_128_cbc(), encrKey, iv))
			break;

		length = inbuf_len;
		block_size = sizeof(buf) - SIZE_128_BITS;

		*cipher = 0;
		*cipher_len  = 0;
		while (length) {
			if (length > block_size)
				curr_len = block_size;
			else
				curr_len = length;

			if (!EVP_EncryptUpdate(&ctx, buf, &buf_len, inbuf, curr_len))
				break;
			*cipher = (u8 *)os_realloc(*cipher, *cipher_len + buf_len);
			os_memcpy(*cipher + *cipher_len, buf, buf_len);
			*cipher_len += buf_len;
			length -= curr_len;
		}

		if (length)
			break;

		if (!EVP_EncryptFinal(&ctx, buf, &buf_len))
			break;

		*cipher = (u8 *)os_realloc(*cipher, *cipher_len + buf_len);
		os_memcpy(*cipher + *cipher_len, buf, buf_len);
		*cipher_len += buf_len;

		ret = 0;
	} while (0);

        #endif   /* CONFIG_CRYPTO_INTERNAL */

	if (ret) {
		if (cipher_len)
			*cipher_len = 0;
		if (cipher && *cipher) {
			os_free(*cipher);
			*cipher = 0;
		}
	}

	return ret;
}


static int apac_wps_decrypt_data(struct apac_wps_data *data, u8 *iv,
								u8 *cipher, int cipher_len,
								u8 *encrKey, u8 **plain, int *plain_len)
{
	int ret = -1;

        #ifdef CONFIG_CRYPTO_INTERNAL

        void *aesHandle = NULL;
        if (plain) *plain = NULL;

	do {
                u8 *out;
                int out_len = 0;

		if (!iv || !cipher || !encrKey || !plain || !plain_len)
			break;
                if (cipher_len <= 0 || 
                            (cipher_len & (ENCR_DATA_BLOCK_SIZE-1)) != 0) 
                        break;

                /* The plain text length is always less than the cipher
                 * text length (which contains 1 to 16 bytes of padding).
                 * No harm in allocating more than we need.
                 */
		*plain = os_malloc(cipher_len);
		*plain_len = 0;
                if (*plain == NULL) break;
                out = *plain;

                aesHandle = aes_decrypt_init(encrKey, ENCR_DATA_BLOCK_SIZE);
                if (aesHandle == NULL) break;

                while (cipher_len >= ENCR_DATA_BLOCK_SIZE) {
                        int block_len = ENCR_DATA_BLOCK_SIZE;
                        int i;
                        aes_decrypt(aesHandle, cipher, out);
                        /* Cipher Block Chaining (CBC) -- xor the plain text with
                         * the last AES output (or initially, the "initialization vector").
                         */
                        for (i = 0; i < ENCR_DATA_BLOCK_SIZE; i++) {
                                out[i] ^= iv[i];
                        }
                        iv = cipher;
                        cipher += ENCR_DATA_BLOCK_SIZE;
                        cipher_len -= ENCR_DATA_BLOCK_SIZE;
                        if (cipher_len < ENCR_DATA_BLOCK_SIZE) {
                                int npad;
                                /* cipher_len should be exactly 0
                                 * at this point... it must be a multiple
                                 * of blocks.  The last block should contain
                                 * between 1 and 16 bytes of padding,
                                 * with the last byte of padding saying
                                 * how many.
                                 */
                                if (cipher_len != 0) break;
                                npad = out[ENCR_DATA_BLOCK_SIZE-1];
                                if (npad > 0 && npad <= ENCR_DATA_BLOCK_SIZE) {
                                        block_len -= npad;
                                } else goto bad;
                        }
                        out += block_len;
                        out_len += block_len;
                }
                *plain_len = out_len;
                ret = 0;
                break;
        } while (0);
        bad:
        if (aesHandle) aes_decrypt_deinit(aesHandle);

        #else /* CONFIG_CRYPTO_INTERNAL */

	EVP_CIPHER_CTX ctx;
	u8 buf[1024];
	int buf_len = sizeof(buf);
	int length, curr_len;
	int block_size;

	do {
		if (!iv || !cipher || !encrKey || !plain || !plain_len)
			break;

		*plain = 0;
		*plain_len = 0;

		if (!EVP_DecryptInit(&ctx, EVP_aes_128_cbc(), encrKey, iv))
			break;

		length = cipher_len;
		block_size = sizeof(buf) - SIZE_128_BITS;

		while (length) {
			if (length > block_size)
				curr_len = block_size;
			else
				curr_len = length;

			if (!EVP_DecryptUpdate(&ctx, buf, &buf_len, cipher, curr_len))
				break;
			*plain = (u8 *)os_realloc(*plain, *plain_len + buf_len);
			os_memcpy(*plain + *plain_len, buf, buf_len);
			*plain_len += buf_len;
			length -= curr_len;
		}

		if (length)
			break;

		if (!EVP_DecryptFinal(&ctx, buf, &buf_len))
			break;

		*plain = (u8 *)os_realloc(*plain, *plain_len + buf_len);
		os_memcpy(*plain + *plain_len, buf, buf_len);
		*plain_len += buf_len;

		ret = 0;
	} while (0);

        #endif /* CONFIG_CRYPTO_INTERNAL */

	if (ret) {
		if (plain_len)
			*plain_len = 0;
		if (plain && *plain) {
			os_free(*plain);
			*plain = 0;
		}
	}

	return ret;
}

static int apac_wps_encrsettings_creation(
        struct apac_wps_data *data,
        u16 nonce_type, u8 *nonce,
        u8 *buf, size_t buf_len,
        u8 *auth_key, u8 *key_wrap_auth,
        u8 **encrs, size_t *encrs_len)
{
	int ret = -1;
	struct wps_data *wps = 0;
	u8 hmac[SIZE_256_BITS];
	size_t length = 0;
	u8 *tmp = 0;
	u8 *cipher = 0, iv[SIZE_128_BITS];
	int cipher_len;
	size_t nw_key_len = 0;

	do {
		if (!auth_key || !key_wrap_auth || !encrs || !encrs_len)
			break;

		*encrs = 0;
		*encrs_len = 0;

		if (wps_create_wps_data(&wps))
			break;


		if (nonce) {
			length = SIZE_NONCE;
			if (wps_set_value(wps, nonce_type, nonce, length))
				break;

			length = 0;
			if (wps_write_wps_data(wps, &tmp, &length))
				break;
		}

		if (buf && buf_len) {
			(void)wps_destroy_wps_data(&wps);

			tmp = os_realloc(tmp, length + buf_len);
			if (!tmp)
				break;
			os_memcpy(tmp + length, buf, buf_len);
			length += buf_len;

			if (wps_create_wps_data(&wps))
				break;

			if (wps_parse_wps_data(tmp, length, wps))
				break;
                        os_free(tmp); tmp = NULL; /* will be recreated below*/

                        nw_key_len=0;
                        (void)wps_get_nw_key_len(wps, &nw_key_len);
                        /* Required for WCN - add NW key attribute even if open mode*/
                        if (!nw_key_len) {
        		        if (wps_set_value(wps, WPS_TYPE_NW_KEY, "", 0)) {
	        			break;
		                }
                        }

			if (wps_write_wps_data(wps, &tmp, &length))
				break;
		}

                #ifdef CONFIG_CRYPTO_INTERNAL

                {
                        const u8 *vec[1];
                        size_t vlen[1];
                        vec[0] = tmp;
                        vlen[0] = length;
                        hmac_sha256_vector(
                                auth_key,
                                SIZE_AUTH_KEY,  /* auth_key size */
                                1,              /* num_elem */
                                vec,
                                vlen,
                                hmac     /* output: 32 bytes */
                                );
                }

                #else /* CONFIG_CRYPTO_INTERNAL */

		if (!HMAC(EVP_sha256(), auth_key, SIZE_AUTH_KEY, tmp, length, hmac, NULL))
			break;

                #endif /* CONFIG_CRYPTO_INTERNAL */

		if (wps_set_value(wps, WPS_TYPE_KEY_WRAP_AUTH, hmac, SIZE_64_BITS))
			break;

		os_free(tmp);
		tmp = 0;

		length = 0;
		if (wps_write_wps_data(wps, &tmp, &length))
			break;

		if (apac_wps_encrypt_data(data, tmp, length, key_wrap_auth, iv, &cipher, &cipher_len))
			break;

		*encrs = os_malloc(SIZE_128_BITS + cipher_len);
		if (!*encrs)
			break;
		os_memcpy(*encrs, iv, SIZE_128_BITS);
		os_memcpy(*encrs + SIZE_128_BITS, cipher, cipher_len);
		*encrs_len = SIZE_128_BITS + cipher_len;

		ret = 0;
	} while (0);

	if (tmp)
		os_free(tmp);
	if (cipher)
		os_free(cipher);

	if (ret) {
		if (encrs_len)
			*encrs_len = 0;
		if (encrs && *encrs) {
			os_free(*encrs);
			*encrs = 0;
		}
	}

	(void)wps_destroy_wps_data(&wps);

	return ret;
}

static int apac_wps_encrsettings_validation(struct apac_wps_data *data,
										   u8 *plain, int plain_len,
										   u8 *auth_key, u16 nonce_type,
										   u8 *nonce, u8 *key_wrap_auth)
{
	int ret = -1;
	struct wps_data *wps = 0;
	size_t length;
	u8 *buf = 0;
	u8 hmac[SIZE_256_BITS];

	do {
		if (!plain || !plain_len || !key_wrap_auth)
			break;
		
		if (wps_create_wps_data(&wps))
			break;
		if (wps_parse_wps_data(plain, plain_len, wps))
			break;

		if (nonce) {
		/* Nonce */
			length = SIZE_NONCE;
			if (wps_get_value(wps, nonce_type, nonce, &length))
				break;
		}

		/* Key Wrap Authenticator */
		length = SIZE_8_BYTES;
		if (wps_get_value(wps, WPS_TYPE_KEY_WRAP_AUTH, key_wrap_auth, &length))
			break;

		if (wps_remove_value(wps, WPS_TYPE_KEY_WRAP_AUTH))
			break;

		length = 0;
		if (wps_write_wps_data(wps, &buf, &length))
			break;

                #ifdef CONFIG_CRYPTO_INTERNAL

                {
                        const u8 *vec[1];
                        size_t vlen[1];
                        vec[0] = buf;
                        vlen[0] = length;
                        hmac_sha256_vector(
                                auth_key,
                                SIZE_AUTH_KEY,  /* auth_key size */
                                1,              /* num_elem */
                                vec,
                                vlen,
                                hmac     /* output: 32 bytes */
                                );
                }

                #else /* CONFIG_CRYPTO_INTERNAL */

		if (!HMAC(EVP_sha256(), auth_key, SIZE_AUTH_KEY, buf, length, hmac, NULL))
			break;

                #endif /* CONFIG_CRYPTO_INTERNAL */

		if (os_memcmp(hmac, key_wrap_auth, SIZE_64_BITS))
			break;

		ret = 0;
	} while (0);

	(void)wps_destroy_wps_data(&wps);

	if (ret) {
		if (nonce)
			os_memset(nonce, 0, SIZE_NONCE);
		if (key_wrap_auth)
			os_memset(key_wrap_auth, 0, SIZE_8_BYTES);
	}

        if (buf)
                free(buf);
	return ret;
}

static int apac_wps_generate_hash(struct apac_wps_data *data,
		 u8 *src, int src_len,
		 u8 *pub_key1, u8 *pub_key2,
		 u8 *auth_key,
		 u8 *psk, u8 *es, u8 *hash)
{
	int ret = -1;

        #ifdef CONFIG_CRYPTO_INTERNAL

	do {
                const u8 *vec[4];
                size_t vlen[4];
	        u8 hash_tmp[SHA256_MAC_LEN];

		if (!src || !pub_key1 || !pub_key2 || !psk || !es || !auth_key)
			break;

                /* Generate psk1 or psk2 while we are at it 
                 * (based on parts of the wps password == PIN) 
                 */
                vec[0] = src;
                vlen[0] = src_len;
                hmac_sha256_vector(
                        auth_key,
                        SIZE_AUTH_KEY,
                        1,              /* num_elem */
                        vec,
                        vlen,
                        hash_tmp     /* output: 32 bytes */
                        );
		os_memcpy(psk, hash_tmp, SIZE_128_BITS); /* first 16 bytes */

                /* Generate a nonce while we are at it */
		RAND_bytes(es, SIZE_128_BITS);

                /* Generate hash (includes above nonce and psk portion) */
                vec[0] = es;
                vlen[0] = SIZE_128_BITS;
                vec[1] = psk;
                vlen[1] = SIZE_128_BITS;        /* first 16 bytes only */
                vec[2] = pub_key1;
                vlen[2] = SIZE_PUB_KEY;
                vec[3] = pub_key2;
                vlen[3] = SIZE_PUB_KEY;
                hmac_sha256_vector(
                        auth_key,
                        SIZE_AUTH_KEY,  /* auth_key size */
                        4,              /* num_elem */
                        vec,
                        vlen,
                        hash     /* output: 32 bytes */
                        );
		ret = 0;
	} while (0);

        #else /* CONFIG_CRYPTO_INTERNAL */

	u8 hash_tmp[SIZE_256_BITS];
	u8 hash_src[SIZE_128_BITS * 2 + SIZE_PUB_KEY * 2];
	u8 *tmp;

	do {
		if (!src || !pub_key1 || !pub_key2 || !psk || !es || !auth_key)
			break;

		if (!HMAC(EVP_sha256(), auth_key, SIZE_256_BITS, src, src_len,
			 hash_tmp, NULL))
			break;
		os_memcpy(psk, hash_tmp, SIZE_128_BITS);

		RAND_bytes(es, SIZE_128_BITS);

		tmp = hash_src;
		os_memcpy(tmp, es, SIZE_128_BITS);
		tmp += SIZE_128_BITS;
		os_memcpy(tmp, psk, SIZE_128_BITS);
		tmp += SIZE_128_BITS;
		os_memcpy(tmp, pub_key1, SIZE_PUB_KEY);
		tmp += SIZE_PUB_KEY;
		os_memcpy(tmp, pub_key2, SIZE_PUB_KEY);
		tmp += SIZE_PUB_KEY;

		if (!HMAC(EVP_sha256(), auth_key, SIZE_256_BITS,
				  hash_src, tmp - hash_src, hash, NULL))
			break;

		ret = 0;
	} while (0);

        #endif /* CONFIG_CRYPTO_INTERNAL */

	return ret;
}

static int apac_wps_calcurate_authenticator(struct apac_wps_data *data,
										   u8 *sndmsg, size_t sndmsg_len,
										   u8 *auth_key, u8 *authenticator)
{
	int ret = -1;

        #ifdef CONFIG_CRYPTO_INTERNAL

	u8 hmac[SIZE_256_BITS];

	do {
                const u8 *vec[2];
                size_t vlen[2];

		if (!data || !sndmsg || !authenticator)
			break;

                vec[0] = data->rcvMsg;
                vlen[0] = data->rcvMsgLen;
                vec[1] = sndmsg;
                vlen[1] = sndmsg_len;
                hmac_sha256_vector(
                        auth_key,
                        SIZE_256_BITS,  /* auth_key size */
                        2,              /* num_elem */
                        vec,
                        vlen,
                        hmac     /* output: 32 bytes */
                        );
		os_memcpy(authenticator, hmac, SIZE_64_BITS);
		ret = 0;
	} while (0);

        #else /* CONFIG_CRYPTO_INTERNAL */

	u8 *hmac_src = 0;
	int hmac_src_len;
	u8 hmac[SIZE_256_BITS];

	do {
		if (!data || !sndmsg || !authenticator)
			break;

		hmac_src_len = data->rcvMsgLen + sndmsg_len;
		hmac_src = os_malloc(hmac_src_len);
		os_memcpy(hmac_src, data->rcvMsg, data->rcvMsgLen);
		os_memcpy(hmac_src + data->rcvMsgLen, sndmsg, sndmsg_len);

		if (!HMAC(EVP_sha256(), auth_key, SIZE_256_BITS,
				  hmac_src, hmac_src_len, hmac, NULL))
			break;

		os_memcpy(authenticator, hmac, SIZE_64_BITS);

		ret = 0;
	} while (0);

	if (hmac_src)
		os_free(hmac_src);

        #endif /* CONFIG_CRYPTO_INTERNAL */

	return ret;
}

static int apac_wps_clear_target_info(struct apac_wps_data *data)
{
	int ret = -1;
	struct apac_wps_target_info *target;

	do {
		if (!data || !data->target)
			break;

		target = data->target;

		os_free(target->manufacturer);
		os_free(target->model_name);
		os_free(target->model_number);
		os_free(target->serial_number);
		os_free(target->dev_name);
		if (target->config) {
			os_free(target->config);
			target->config = 0;
			target->config_len = 0;
		}

		os_memset(target, 0, sizeof(*target));
		ret = 0;
	} while (0);

	return ret;
}

static int apac_wps_oobdevpwd_public_key_hash_validation(const u8 *hashed, const u8 *raw)
{
	int ret = -1;
	u8 src[SIZE_256_BITS];

	do {
		if (!hashed || !raw)
			break;

		if (apac_wps_generate_sha256hash((u8 *)raw, SIZE_PUB_KEY, src))
			break;

		if (os_memcmp(hashed, src, SIZE_20_BYTES))
			break;

		ret = 0;
	} while (0);

	return ret;
}

static int apac_wps_calculate_authenticator(struct apac_wps_data *data,
										   u8 *sndmsg, size_t sndmsg_len,
										   u8 *auth_key, u8 *authenticator)
{
	int ret = -1;

	u8 hmac[SIZE_256_BITS];

	do {
        const u8 *vec[2];
        size_t vlen[2];

		if (!data || !sndmsg || !authenticator)
			break;

        vec[0] = data->rcvMsg;
        vlen[0] = data->rcvMsgLen;
        vec[1] = sndmsg;
        vlen[1] = sndmsg_len;
        hmac_sha256_vector(
                auth_key,
                SIZE_256_BITS,  /* auth_key size */
                2,              /* num_elem */
                vec,
                vlen,
                hmac     /* output: 32 bytes */
                );
		os_memcpy(authenticator, hmac, SIZE_64_BITS);
		ret = 0;

////////////////// DEBUG /////////////////////////////////////////////////
        {
            int i=0;
            dprintf(MSG_MSGDUMP, "%s vec0 len:%u\n", __func__, vlen[0]);
            printMsg((u8 *)vec[0], vlen[0], MSG_MSGDUMP);

            dprintf(MSG_MSGDUMP, "%s vec1 len:%u\n", __func__, vlen[1]);
            printMsg((u8 *)vec[1], vlen[1], MSG_MSGDUMP);

            dprintf(MSG_MSGDUMP, "%s -- authenticator:\n", __func__);
            for(i=0;i<SIZE_256_BITS;i++){
                dprintf(MSG_MSGDUMP, "%02X ", authenticator[i]);
            }
            dprintf(MSG_MSGDUMP, "\n");
        }
//////////////////////////////////////////////////////////////////////////

	} while (0);

	return ret;
}


static int apac_wps_hash_validation(struct apac_wps_data *data,
								   u8 *compared,
								   u8 *rsnonce, u8 *psk,
								   u8 *pub_key1, u8 *pub_key2,
								   u8 *auth_key)
{
	int ret = -1;

        #ifdef CONFIG_CRYPTO_INTERNAL

        do {
	        u8 target[SIZE_256_BITS];
                const u8 *vec[4];
                size_t vlen[4];

		if (!compared || !rsnonce || !psk || !pub_key1 || !pub_key2 || !auth_key)
			break;

                vec[0] = rsnonce;
                vlen[0] = SIZE_128_BITS;
                vec[1] = psk;
                vlen[1] = SIZE_128_BITS;
                vec[2] = pub_key1;
                vlen[2] = SIZE_PUB_KEY;
                vec[3] = pub_key2;
                vlen[3] = SIZE_PUB_KEY;
                hmac_sha256_vector(
                        auth_key,
                        SIZE_256_BITS,  /* auth_key size */
                        4,              /* num_elem */
                        vec,
                        vlen,
                        target     /* output: 32 bytes */
                        );

		if (os_memcmp(compared, target, SIZE_256_BITS))
			break;

                ret = 0;
        } while (0);

        #else /* CONFIG_CRYPTO_INTERNAL */

	u8 hash_src[SIZE_128_BITS * 2 + SIZE_PUB_KEY * 2];
	u8 *tmp;
	u8 target[SIZE_256_BITS];

	do {
		if (!compared || !rsnonce || !psk || !pub_key1 || !pub_key2 || !auth_key)
			break;

		tmp = hash_src;
		os_memcpy(tmp, rsnonce, SIZE_128_BITS);
		tmp += SIZE_128_BITS;
		os_memcpy(tmp, psk, SIZE_128_BITS);
		tmp += SIZE_128_BITS;
		os_memcpy(tmp, pub_key1, SIZE_PUB_KEY);
		tmp += SIZE_PUB_KEY;
		os_memcpy(tmp, pub_key2, SIZE_PUB_KEY);
		tmp += SIZE_PUB_KEY;

		if (!HMAC(EVP_sha256(), auth_key, SIZE_256_BITS, hash_src, tmp - hash_src, target, NULL))
			 	break;

		if (os_memcmp(compared, target, SIZE_256_BITS))
			break;

		ret = 0;
	} while (0);

        #endif /* CONFIG_CRYPTO_INTERNAL */

	return ret;
}

static int apac_wps_build_wfa_ext(struct wps_data *wps)
{
    int ret = -1;
    int len;
    u8  wfa_ext[32];
    const u8 wfa_smi_oui[] = {
        0x00, 0x37, 0x2A
    };
    const u8 wps_version2[] = {
        0x00, 0x01, 0x20
    };

    os_memcpy(wfa_ext, wfa_smi_oui, sizeof(wfa_smi_oui));
    os_memcpy(wfa_ext + sizeof(wfa_smi_oui), wps_version2, sizeof(wps_version2));


    len = sizeof(wfa_smi_oui) + sizeof(wps_version2);
    ret = wps_set_value(wps, WPS_TYPE_VENDOR_EXT, wfa_ext, len);

    return ret;
}

u8 * apac_wps_build_message_M1(struct apac_wps_session* sess,
	size_t *msg_len)
{
	u8 *msg = 0;

	APAC_WPS_DATA *data = sess->pWpsData;
    struct wps_config *conf = sess->pData->config.wpsConf;
	struct wps_data *wps = 0;
	u8 u8val;
	size_t length;
	do {
		if (!msg_len)
			break;

		/* Create empty WPS data structure */
		if (wps_create_wps_data(&wps))
			break;

		/* Version */
		u8val = WPS_VERSION;
		if (wps_set_value(wps, WPS_TYPE_VERSION, &u8val, 0))
			break;

		/* Message Type */
		u8val = WPS_MSGTYPE_M1;
		if (wps_set_value(wps, WPS_TYPE_MSG_TYPE, &u8val, 0))
			break;

		/* UUID-E */
		if (!conf->uuid_set)
			break;
		if (wps_set_value(wps, WPS_TYPE_UUID_E, conf->uuid, sizeof(conf->uuid)))
			break;

		/* MAC Address */
		if (wps_set_value(wps, WPS_TYPE_MAC_ADDR, sess->pData->alid, ETH_ALEN))
			break;

		/* Enrollee Nonce */
		RAND_bytes(data->nonce, sizeof(data->nonce));
		if (wps_set_value(wps, WPS_TYPE_ENROLLEE_NONCE, data->nonce, sizeof(data->nonce)))
			break;

		/* Public Key */
		if (!data->preset_pubKey) {
			if (data->dh_secret)
				apac_wps_free_dh(&data->dh_secret);
			if (apac_wps_generate_public_key(&data->dh_secret, data->pubKey))
				break;
		}
		if (wps_set_value(wps, WPS_TYPE_PUBLIC_KEY, data->pubKey, sizeof(data->pubKey)))
			break;

		/* Authentication Type Flags */
		if (wps_set_value(wps, WPS_TYPE_AUTH_TYPE_FLAGS, &conf->auth_type_flags, 0))
			break;

		/* Encryption Type Flags */
		if (wps_set_value(wps, WPS_TYPE_ENCR_TYPE_FLAGS, &conf->encr_type_flags, 0))
			break;

		/* Connection Type Flags */
		if (wps_set_value(wps, WPS_TYPE_CONN_TYPE_FLAGS, &conf->conn_type_flags, 0))
			break;

		/* Config Methods */
		if (wps_set_value(wps, WPS_TYPE_CONFIG_METHODS, &conf->config_methods, 0))
			break;

		/* Wi-Fi Protected Setup State */
		if (wps_set_value(wps, WPS_TYPE_WPSSTATE, &conf->wps_state, 0))
			break;
		/* Manufacturer */
                #if WPS_HACK_PADDING() /* do NOT add padding*/
		if (wps_set_value(wps, WPS_TYPE_MANUFACTURER, conf->manufacturer, strlen(conf->manufacturer)))
                #else   /* original */
		if (wps_set_value(wps, WPS_TYPE_MANUFACTURER, conf->manufacturer, conf->manufacturer_len))
                #endif  /* WPS_HACK_PADDING */
			break;

		/* Model Name */
                #if WPS_HACK_PADDING() /* do NOT add padding*/
		if (wps_set_value(wps, WPS_TYPE_MODEL_NAME, conf->model_name, strlen(conf->model_name)))
                #else   /* original */
		if (wps_set_value(wps, WPS_TYPE_MODEL_NAME, conf->model_name, conf->model_name_len))
                #endif
			break;

		/* Model Number */
                #if WPS_HACK_PADDING() /* do NOT add padding*/
		if (wps_set_value(wps, WPS_TYPE_MODEL_NUMBER, conf->model_number, strlen(conf->model_number)))
                #else
		if (wps_set_value(wps, WPS_TYPE_MODEL_NUMBER, conf->model_number, conf->model_number_len))
                #endif
			break;

		/* Serial Number */
                #if WPS_HACK_PADDING() /* do NOT add padding*/
		if (wps_set_value(wps, WPS_TYPE_SERIAL_NUM, conf->serial_number, strlen(conf->serial_number)))
                #else
		if (wps_set_value(wps, WPS_TYPE_SERIAL_NUM, conf->serial_number, conf->serial_number_len))
                #endif
			break;

		/* Primary Device Type */
		if (wps_set_value(wps, WPS_TYPE_PRIM_DEV_TYPE, conf->prim_dev_type, sizeof(conf->prim_dev_type)))
			break;

		/* Device Name */
                #if WPS_HACK_PADDING() /* do NOT add padding*/
		if (wps_set_value(wps, WPS_TYPE_DEVICE_NAME, conf->dev_name, strlen(conf->dev_name)))
                #else
		if (wps_set_value(wps, WPS_TYPE_DEVICE_NAME, conf->dev_name, conf->dev_name_len))
                #endif
		    break;

		/* RF Bands */
		if (wps_set_value(wps, WPS_TYPE_RF_BANDS, &conf->rf_bands, 0))
			break;

		/* Association State */
		if (wps_set_value(wps, WPS_TYPE_ASSOC_STATE, &data->assoc_state, 0))
			break;

		/* Device Passwork ID */
		if (wps_set_value(wps, WPS_TYPE_DEVICE_PWD_ID, &data->dev_pwd_id, 0))
			break;

		/* Configuration Error */
		if (wps_set_value(wps, WPS_TYPE_CONFIG_ERROR, &data->config_error, 0))
			break;

		/* OS Version */
		if (wps_set_value(wps, WPS_TYPE_OS_VERSION, &conf->os_version, 0))
			break;

		/* WPS2*/
		if (apac_wps_build_wfa_ext(wps))
			break;

		if (wps_write_wps_data(wps, &msg, &length))
			break;

		*msg_len = length;

		if (data->sndMsg) {
			os_free(data->sndMsg);
			data->sndMsg = 0;
			data->sndMsgLen = 0;
		}

		data->sndMsg = os_malloc(*msg_len);
		if (!data->sndMsg) {
			os_free(msg);
			msg = 0;
			*msg_len = 0;
			break;
		}

		os_memcpy(data->sndMsg, msg, *msg_len);
		data->sndMsgLen = *msg_len;

	} while (0);

	(void)wps_destroy_wps_data(&wps);

	return msg;
}

static int
apac_wps_config_build_message_M2_M2D(
        struct wps_config *conf,
	    APAC_WPS_DATA *data, 
        struct wps_data *wps)
{
	int ret = -1;

	do {
		if (!conf || !data || !wps)
			break;

		/* Authentication Type Flags */
		if (wps_set_value(wps, WPS_TYPE_AUTH_TYPE_FLAGS, &conf->auth_type_flags, 0))
			break;

		/* Encryption Type Flags */
		if (wps_set_value(wps, WPS_TYPE_ENCR_TYPE_FLAGS, &conf->encr_type_flags, 0))
			break;

		/* Connection Type Flags */
		if (wps_set_value(wps, WPS_TYPE_CONN_TYPE_FLAGS, &conf->conn_type_flags, 0))
			break;

		/* Config Methods */
		if (wps_set_value(wps, WPS_TYPE_CONFIG_METHODS, &conf->config_methods, 0))
			break;

		/* Manufacturer */
		if (wps_set_value(wps, WPS_TYPE_MANUFACTURER, conf->manufacturer, conf->manufacturer_len))
			break;

		/* Model Name */
		if (wps_set_value(wps, WPS_TYPE_MODEL_NAME, conf->model_name, conf->model_name_len))
			break;

		/* Model Number */
		if (wps_set_value(wps, WPS_TYPE_MODEL_NUMBER, conf->model_number, conf->model_number_len))
			break;

		/* Serial Number */
		if (wps_set_value(wps, WPS_TYPE_SERIAL_NUM, conf->serial_number, conf->serial_number_len))
			break;

		/* Primary Device Type */
		if (wps_set_value(wps, WPS_TYPE_PRIM_DEV_TYPE, conf->prim_dev_type, sizeof(conf->prim_dev_type)))
			break;

		/* Device Name */
		if (wps_set_value(wps, WPS_TYPE_DEVICE_NAME, conf->dev_name, conf->dev_name_len))
			break;

		/* RF Bands */
		if (wps_set_value(wps, WPS_TYPE_RF_BANDS, &conf->rf_bands, 0))
			break;

		/* Association State */
		if (wps_set_value(wps, WPS_TYPE_ASSOC_STATE, &data->assoc_state, 0))
			break;

		/* Configuration Error */
		if (wps_set_value(wps, WPS_TYPE_CONFIG_ERROR, &data->config_error, 0))
			break;

		ret = 0;
	} while (0);

	return ret;
}

static u8 * apac_wps_build_message_M2(struct apac_wps_session* sess,
		size_t *msg_len)
{
	u8 *msg = 0;
	struct apac_wps_data *data = sess->pWpsData;
	struct apac_wps_target_info *target;
	struct wps_data *wps = 0;
	u8 kdk[SIZE_256_BITS];
	u8 keys[KDF_OUTPUT_SIZE];
	u8 authenticator[SIZE_8_BYTES];
	u8 *encrs = NULL;
	u8 u8val;
	size_t length, encrs_len = 0;
        struct wps_config *conf = sess->pData->config.wpsConf;
        apacHyfi20Config_t *ptrConfig = &sess->pData->config;

	do {
		if (!data || !data->target || !msg_len)
			break;
		target = data->target;

		if (wps_create_wps_data(&wps))
			break;

		/* Version */
		u8val = WPS_VERSION;
		if (wps_set_value(wps, WPS_TYPE_VERSION, &u8val, 0))
			break;

		/* Message Type */
		u8val = WPS_MSGTYPE_M2;
		if (wps_set_value(wps, WPS_TYPE_MSG_TYPE, &u8val, 0))
			break;

		/* Enrollee Nonce */
		if (wps_set_value(wps, WPS_TYPE_ENROLLEE_NONCE, target->nonce, sizeof(target->nonce)))
			break;

		/* Registrar Nonce */
		RAND_bytes(data->nonce, sizeof(data->nonce));
		if (wps_set_value(wps, WPS_TYPE_REGISTRAR_NONCE, data->nonce, sizeof(data->nonce)))
			break;

		/* UUID-R */
		if (!conf->uuid_set)
			break;
		if (wps_set_value(wps, WPS_TYPE_UUID_R, conf->uuid, sizeof(conf->uuid)))
			break;

		/* Public Key */
		if (!data->preset_pubKey) {
			if (data->dh_secret)
				apac_wps_free_dh(&data->dh_secret);
			if (apac_wps_generate_public_key(&data->dh_secret, data->pubKey))
				break;
		}
		if (wps_set_value(wps, WPS_TYPE_PUBLIC_KEY, data->pubKey, sizeof(data->pubKey)))
			break;

		/* M2/M2D common data */
		if (apac_wps_config_build_message_M2_M2D(conf, data, wps))
			break;

		/* Device Password ID */
		if (wps_set_value(wps, WPS_TYPE_DEVICE_PWD_ID, &data->dev_pwd_id, 0))
			break;

		/* OS Version */
		if (wps_set_value(wps, WPS_TYPE_OS_VERSION, &conf->os_version, 0))
			break;

		/* WPS version 2*/
		if (apac_wps_build_wfa_ext(wps))
			break;

		/* Generate KDK */
		if (apac_wps_generate_kdk(data, target->nonce, target->mac, data->nonce, kdk))
			break;

		/* Key Derivation Function */
		if (apac_wps_key_derive_func(data, kdk, keys))
			break;
		os_memcpy(data->authKey, keys, SIZE_256_BITS);
		os_memcpy(data->keyWrapKey, keys + SIZE_256_BITS, SIZE_128_BITS);
		os_memcpy(data->emsk, keys + SIZE_256_BITS + SIZE_128_BITS, SIZE_256_BITS);
                /* last 16 bytes are unused */

////////////////// DEBUG /////////////////////////////////////////////////
        {
            int dlevel = MSG_DEBUG;
            int i=0;
            dprintf(dlevel, "KeyWrapKey:\n");
            for(;i<SIZE_128_BITS;i++){
                dprintf(dlevel, "%02X ", data->keyWrapKey[i]);
            }
            dprintf(dlevel, "\n");
            dprintf(dlevel, "AuthKey:\n");
            for(;i<SIZE_256_BITS;i++){
                dprintf(dlevel, "%02X ", data->authKey[i]);
            }
            dprintf(dlevel, "\n");

        }
//////////////////////////////////////////////////////////////////////////
                /* Encrypted Settings */
		if (ptrConfig->wps_method == APAC_WPS_M2){
			if (apac_wps_get_wifi_configuration(sess, &data->config, &data->config_len)) {
				dprintf(MSG_ERROR, "Failed to get WiFi configuration\n");
				break;
			}

			if (apac_wps_encrsettings_creation(data, 0, 0, data->config, data->config_len,
				data->authKey, data->keyWrapKey, &encrs, &encrs_len))
				break;

			if (wps_set_value(wps, WPS_TYPE_ENCR_SETTINGS, encrs, encrs_len))
			break;
		}

		/* Authenticator */
		length = 0;
		if (wps_write_wps_data(wps, &msg, &length))
			break;
                dprintf(MSG_MSGDUMP, "write_wps_data - msg len: %d\n", length);

		if (apac_wps_calculate_authenticator(data, msg, length,
									data->authKey, authenticator)) {
			os_free(msg);
			msg = 0;
			break;
		}
                dprintf(MSG_MSGDUMP, "calculate_authen - msg len: %d\n", length);
////////////////// DEBUG /////////////////////////////////////////////////
        {
            int dlevel = MSG_MSGDUMP;
            int i=0;
            dprintf(dlevel, "%s, authenticator:\n", __func__);
            for(i=0;i<SIZE_8_BYTES;i++){
                dprintf(dlevel, "%02X ", authenticator[i]);
            }
            dprintf(dlevel, "\n");
        }
//////////////////////////////////////////////////////////////////////////

		os_free(msg);
		msg = 0;
		if (wps_set_value(wps, WPS_TYPE_AUTHENTICATOR, authenticator, sizeof(authenticator)))
			break;
                dprintf(MSG_MSGDUMP, "set_value - msg len: %d\n", length);

		if (wps_write_wps_data(wps, &msg, &length))
			break;
                dprintf(MSG_MSGDUMP, "write_wps_data - msg len: %d\n", length);

		*msg_len = length;

		if (data->sndMsg) {
			os_free(data->sndMsg);
			data->sndMsg = 0;
			data->sndMsgLen = 0;
		}
		data->sndMsg = os_malloc(*msg_len);
		if (!data->sndMsg) {
			os_free(msg);
			msg = 0;
			*msg_len = 0;
			break;
		}

		os_memcpy(data->sndMsg, msg, *msg_len);
		data->sndMsgLen = *msg_len;

	} while (0);

        if (encrs)
            os_free(encrs);

	(void)wps_destroy_wps_data(&wps);

	return msg;
}

int apac_wps_process_message_M1(struct apac_wps_session* sess, u8 *rcvMsg, int rcvMsgLen)
{
	int ret = -1;
	struct wps_data *wps = 0;
	u8 msg_type;

	struct apac_wps_data *data = sess->pWpsData;
	struct apac_wps_target_info *target;
	size_t length;

	dprintf(MSG_DEBUG, "Process M1 with len = %d\n", rcvMsgLen);

	do {
		if (!data || !data->target)
			break;
		target = data->target;
#if 0
        if (data->rcvMsg)
            os_free(data->rcvMsg);
        data->rcvMsg = os_malloc(rcvMsgLen);
        if (data->rcvMsg) {
            os_memcpy(data->rcvMsg, rcvMsg, rcvMsgLen);
            data->rcvMsgLen = rcvMsgLen;
        }
#endif
		apac_wps_clear_target_info(data);

		if (wps_create_wps_data(&wps))
			break;

		if (wps_parse_wps_data(rcvMsg, rcvMsgLen, wps))
			break;
        dprintf(MSG_DEBUG, "Successfully parsed WPS M1-data\n");

		/* Version */
		if (wps_get_value(wps, WPS_TYPE_VERSION, &target->version, 0))
			break;
		if ((target->version != WPS_VERSION) && (target->version != WPS_VERSION_EX))
			break;

		if (wps_get_value(wps, WPS_TYPE_MSG_TYPE, &msg_type, 0))
			break;
		if (msg_type != WPS_MSGTYPE_M1)
			break;
        dprintf(MSG_DEBUG, "WPS_MSG_TYPE = %04X\n", msg_type);
#if 0
		/* UUID-E */
		length = sizeof(target->uuid);
		if (wps_get_value(wps, WPS_TYPE_UUID_E, target->uuid, &length))
			break;
#endif
		/* MAC Address */
		length = sizeof(target->mac);
		if (wps_get_value(wps, WPS_TYPE_MAC_ADDR, target->mac, &length))
			break;
		target->mac_set = 1;

		/* Enrollee Nonce */
		length = sizeof(target->nonce);
		if (wps_get_value(wps, WPS_TYPE_ENROLLEE_NONCE, target->nonce, &length))
			break;

		/* Public Key */
		length = sizeof(target->pubKey);
		if (wps_get_value(wps, WPS_TYPE_PUBLIC_KEY, target->pubKey, &length))
			break;
        if (0 < length && length < SIZE_PUB_KEY) {
            /* Defensive programming in case other side omitted
            *   leading zeroes 
            */
            memmove(target->pubKey+(SIZE_PUB_KEY-length), 
                target->pubKey, length);
            memset(target->pubKey, 0, (SIZE_PUB_KEY-length));
        } else if (length != SIZE_PUB_KEY)
            break;
		if (data->preset_pubKey) {
			if (apac_wps_oobdevpwd_public_key_hash_validation(data->pubKey, target->pubKey))
				break;

			os_memset(data->pubKey, 0, sizeof(data->pubKey));
			data->preset_pubKey = 0;
		}
        dprintf(MSG_DEBUG, "Parsed Pub Key\n");
//#if 0
		/* Authentication Type Flags */
		if (wps_get_value(wps, WPS_TYPE_AUTH_TYPE_FLAGS, &target->auth_type_flags, 0))
			break;

		/* Encryption Type Flags */
		if (wps_get_value(wps, WPS_TYPE_ENCR_TYPE_FLAGS, &target->encr_type_flags, 0))
			break;

		/* Connection Type Flags */
		if (wps_get_value(wps, WPS_TYPE_CONN_TYPE_FLAGS, &target->conn_type_flags, 0))
			break;

		/* Config Methods */
		if (wps_get_value(wps, WPS_TYPE_CONFIG_METHODS, &target->config_methods, 0))
			break;

		/* Manufacturer */
		(void)wps_get_value(wps, WPS_TYPE_MANUFACTURER, 0, &length);
		if (!length)
			break;
		target->manufacturer = os_zalloc(length+1);
		target->manufacturer_len = length;
		if (wps_get_value(wps, WPS_TYPE_MANUFACTURER, target->manufacturer, &length))
			break;

		/* Model Name */
		(void)wps_get_value(wps, WPS_TYPE_MODEL_NAME, 0, &length);
		if (!length)
			break;
		target->model_name = os_zalloc(length+1);
		target->model_name_len = length;
		if (wps_get_value(wps, WPS_TYPE_MODEL_NAME, target->model_name, &length))
			break;

		/* Model Number */
		(void)wps_get_value(wps, WPS_TYPE_MODEL_NUMBER, 0, &length);
		if (!length)
			break;
		target->model_number = os_zalloc(length+1);
		target->model_number_len = length;
		if (wps_get_value(wps, WPS_TYPE_MODEL_NUMBER, target->model_number, &length))
			break;

		/* Serial Number */
		(void)wps_get_value(wps, WPS_TYPE_SERIAL_NUM, 0, &length);
		if (!length)
			break;
		target->serial_number = os_zalloc(length+1);
		target->serial_number_len = length;
		if (wps_get_value(wps, WPS_TYPE_SERIAL_NUM, target->serial_number, &length))
			break;

		/* Primary Device Type */
		length = sizeof(target->prim_dev_type);
		if (wps_get_value(wps, WPS_TYPE_PRIM_DEV_TYPE, target->prim_dev_type, &length))
			break;

		/* Device Name */
		(void)wps_get_value(wps, WPS_TYPE_DEVICE_NAME, 0, &length);
		if (!length)
			break;
		target->dev_name = os_zalloc(length+1);
		target->dev_name_len = length;
		if (wps_get_value(wps, WPS_TYPE_DEVICE_NAME, target->dev_name, &length))
			break;

		/* RF Bands */
		if (wps_get_value(wps, WPS_TYPE_RF_BANDS, &target->rf_bands, 0))
			break;
        sess->pData->config.wpsConf->rf_bands = target->rf_bands;
        dprintf(MSG_DEBUG, "%s, received WPS has rf band %u\n", __func__, target->rf_bands);

		/* Association State */
		if (wps_get_value(wps, WPS_TYPE_ASSOC_STATE, &target->assoc_state, 0))
			break;

		/* Configuration Error */
		if (wps_get_value(wps, WPS_TYPE_CONFIG_ERROR, &target->config_error, 0))
			break;

		/* OS Version */
		if (wps_get_value(wps, WPS_TYPE_OS_VERSION, &target->os_version, 0))
			break;
		ret = 0;
	} while (0);

	if (ret)
		apac_wps_clear_target_info(data);

	(void)wps_destroy_wps_data(&wps);

	return ret;
}

int apac_wps_process_message_M2(struct apac_wps_session* sess, u8* rcvMsg, int rcvMsgLen)
{
	int ret = -1;
	apacHyfi20Data_t* pData = sess->pData;
	struct apac_wps_data *data = sess->pWpsData;
	struct apac_wps_target_info *target;
	struct wps_data *wps = 0;
	u8 msg_type;
	u8 kdk[SIZE_256_BITS];
	u8 keys[KDF_OUTPUT_SIZE];
	u8 tmp[SIZE_64_BYTES];
	size_t length;
	u8 authenticator[SIZE_8_BYTES];
        u8 keyWrapAuth[SIZE_64_BITS];

    dprintf(MSG_DEBUG, "%s - to process M2 with len = %d\n", __func__, rcvMsgLen);

	do {
		if (!data || !data->target)
			break;
		target = data->target;

		if (wps_create_wps_data(&wps))
			break;

		if (wps_parse_wps_data(rcvMsg, rcvMsgLen, wps))
			break;

		/* Version */
		if (wps_get_value(wps, WPS_TYPE_VERSION, &target->version, 0))
			break;

		/* Message Type */
		if (wps_get_value(wps, WPS_TYPE_MSG_TYPE, &msg_type, 0))
			break;
		if (msg_type != WPS_MSGTYPE_M2)
			break;

                /* Enrollee Nonce */
                length = sizeof(tmp);
                if (wps_get_value(wps, WPS_TYPE_ENROLLEE_NONCE, tmp, &length))
                    break;
                if (os_memcmp(data->nonce, tmp, sizeof(data->nonce)))
                    break;

                /* Registrar Nonce */
                length = sizeof(target->nonce);
                if (wps_get_value(wps, WPS_TYPE_REGISTRAR_NONCE, target->nonce, &length))
                    break;

		/* Public Key */
		length = sizeof(target->pubKey);
		if (wps_get_value(wps, WPS_TYPE_PUBLIC_KEY, target->pubKey, &length))
			break;
                if (0 < length && length < SIZE_PUB_KEY) {
                        /* Defensive programming in case other side omitted
                        *   leading zeroes 
                        */
                        memmove(target->pubKey+(SIZE_PUB_KEY-length), 
                            target->pubKey, length);
                        memset(target->pubKey, 0, (SIZE_PUB_KEY-length));
                } else if (length != SIZE_PUB_KEY)
                        break;
		/* Device Password ID */
		if (wps_get_value(wps, WPS_TYPE_DEVICE_PWD_ID, &target->dev_pwd_id, 0))
			break;

		/* RF Bands */
		if (wps_get_value(wps, WPS_TYPE_RF_BANDS, &target->rf_bands, 0))
			break;
                if (sess->pData->config.wpsConf->rf_bands != target->rf_bands) {
                    dprintf(MSG_ERROR, "%s, target rf(%u) != my wps_conf rf(%u)!\n", 
                        __func__, target->rf_bands, sess->pData->config.wpsConf->rf_bands);
                    break;
                }
                dprintf(MSG_DEBUG, "%s, received WPS has rf band %d\n", __func__, target->rf_bands);
		
                /* Authenticator */
		length = sizeof(authenticator);
		if (wps_get_value(wps, WPS_TYPE_AUTHENTICATOR, authenticator, &length))
			break;

		/* Generate KDK */
		if (apac_wps_generate_kdk(data, data->nonce, pData->alid, target->nonce, kdk))
			break;

		/* Key Derivation Function */
		if (apac_wps_key_derive_func(data, kdk, keys))
			break;
		os_memcpy(data->authKey, keys, SIZE_256_BITS);
		os_memcpy(data->keyWrapKey, keys + SIZE_256_BITS, SIZE_128_BITS);
		os_memcpy(data->emsk, keys + SIZE_256_BITS + SIZE_128_BITS, SIZE_256_BITS);
                /* last 16 bytes are unused */
        {
            int dlevel = MSG_DEBUG;    
            int i=0;
            dprintf(dlevel, "KeyWrapKey:\n");
            for(;i<SIZE_128_BITS;i++){
                dprintf(dlevel, "%02X ", data->keyWrapKey[i]);
            }
            dprintf(dlevel, "\n");
            dprintf(dlevel, "AuthKey:\n");
            for(;i<SIZE_256_BITS;i++){
                dprintf(dlevel, "%02X ", data->authKey[i]);
            }
            dprintf(dlevel, "\n");
        }

		/* HMAC validation */
		if (apac_wps_hmac_validation(data, authenticator, data->authKey)) {
			dprintf(MSG_ERROR, "Authenticator validation failed in M2\n");
			break;
                }

		/* Encrypted Settings */
		length = 0;
		(void)wps_get_value(wps, WPS_TYPE_ENCR_SETTINGS, 0, &length);
                if (length) {
                    u8 *encrs = 0;
                    u8 *iv, *cipher;
                    int cipher_len;
                    u8 *config = 0;
                    int config_len;
                    int fail = 1;

	            do {
                        encrs = os_malloc(length);
                        if (!encrs) {
                            dprintf(MSG_ERROR, "%s - encrs is null\n", __func__);
                            break;
                        }
                        if (wps_get_value(wps, WPS_TYPE_ENCR_SETTINGS, encrs, &length)) {
                            dprintf(MSG_ERROR, "%s - wps_get_value for ENCR_SETTINGS ERROR\n", __func__);
                            break;
                        }

                        {
                            int dlevel = MSG_DEBUG;
                            int i = 0;
                            dprintf(dlevel, "%s, configData len: %u\n", __func__, length);
                            for(i=0;i<length;i++){
                                dprintf(dlevel, "%02X ", encrs[i]);
                            }
                            dprintf(dlevel, "\n");
                        }

                        iv = encrs;
                        cipher = encrs + SIZE_128_BITS;
                        cipher_len = length - SIZE_128_BITS;
                        if (apac_wps_decrypt_data(data, iv, cipher, cipher_len, data->keyWrapKey, &config, &config_len))
                        {
                            dprintf(MSG_ERROR, "%s - decrpyt_data ERROR\n", __func__);
                            break;
                        }
                        if (apac_wps_encrsettings_validation(data, config, config_len, data->authKey, 0, 0, keyWrapAuth))
                        {
                            dprintf(MSG_ERROR, "%s - encrsettings_validation ERROR\n", __func__);
                            break;
                        }

                        {
                            int i=0;
                            dprintf(MSG_MSGDUMP, "Rcvd Config Data: \n");
                            for (i=0; i < config_len; i++){
                                dprintf(MSG_MSGDUMP, "%02X ", config[i]);
                                if (((i+1) % 16) == 0){
                                    dprintf(MSG_MSGDUMP, "\n");
                                }
                            }
                            dprintf(MSG_MSGDUMP, "\n");
                        }

                        target->config = config;
                        target->config_len = config_len;

                        fail = 0;
                    } while (0);
			
                    if (encrs)
                        os_free(encrs);
                    if (fail && config) {
                        os_free(config);
                        target->config = 0;
                        target->config_len = 0;
                    }
                    if (fail) {
                        dprintf(MSG_ERROR, "%s - process failed\n", __func__);
                        break;
                    }
                }

		ret = 0;
	} while (0);

	(void)wps_destroy_wps_data(&wps);

	return ret;
}

u8 * apac_wps_build_message_M3(struct apac_wps_session* sess, size_t *msg_len)
{
	u8 *msg = 0;
        struct apac_wps_data *data = sess->pWpsData;
        struct apac_wps_target_info *target;
	struct wps_data *wps = 0;
	u8 authenticator[SIZE_8_BYTES];
	u8 u8val;
	size_t length;

	do {
		if (!data || !data->target || !msg_len)
			break;
		target = data->target;

		if (wps_create_wps_data(&wps))
			break;

		/* Version */
		u8val = WPS_VERSION;
		if (wps_set_value(wps, WPS_TYPE_VERSION, &u8val, 0))
			break;

		/* Message Type */
		u8val = WPS_MSGTYPE_M3;
		if (wps_set_value(wps, WPS_TYPE_MSG_TYPE, &u8val, 0))
			break;

		/* Registrar Nonce */
		if (wps_set_value(wps, WPS_TYPE_REGISTRAR_NONCE, target->nonce, sizeof(target->nonce)))
			break;

		if (!data->dev_pwd_len) {
			break;
		}

		/* E-Hash1 */
		if (apac_wps_generate_hash(data, data->dev_pwd,
								   data->dev_pwd_len/2 + data->dev_pwd_len%2,
								   data->pubKey, target->pubKey, data->authKey,
								   data->psk1, data->snonce1, data->hash1))
			break;
		if(wps_set_value(wps, WPS_TYPE_E_HASH1, data->hash1, sizeof(data->hash1)))
			break;

		/* E-Hash2 */
		if (apac_wps_generate_hash(data, data->dev_pwd + data->dev_pwd_len/2 + data->dev_pwd_len%2,
								   data->dev_pwd_len/2,
								   data->pubKey, target->pubKey, data->authKey,
								   data->psk2, data->snonce2, data->hash2))
			break;
		if(wps_set_value(wps, WPS_TYPE_E_HASH2, data->hash2, sizeof(data->hash2)))
			break;

		/* WPS version 2*/
		if (apac_wps_build_wfa_ext(wps))
			break;

		/* Authenticator */
		length = 0;
		if (wps_write_wps_data(wps, &msg, &length))
			break;
		if (apac_wps_calcurate_authenticator(data, msg, length,
									data->authKey, authenticator)) {
			os_free(msg);
			msg = 0;
			break;
		}
		os_free(msg);
		msg = 0;
		if (wps_set_value(wps, WPS_TYPE_AUTHENTICATOR, authenticator, sizeof(authenticator)))
			break;

		if (wps_write_wps_data(wps, &msg, &length))
			break;

		*msg_len = length;

		if (data->sndMsg) {
			os_free(data->sndMsg);
			data->sndMsg = 0;
			data->sndMsgLen = 0;
		}
		data->sndMsg = os_malloc(*msg_len);
		if (!data->sndMsg) {
			os_free(msg);
			msg = 0;
			*msg_len = 0;
			break;
		}

		os_memcpy(data->sndMsg, msg, *msg_len);
		data->sndMsgLen = *msg_len;
	} while (0);

	(void)wps_destroy_wps_data(&wps);

	return msg;
}



int apac_wps_process_message_M3(struct apac_wps_session* sess, u8* rcvMsg, int rcvMsgLen)
{
	int ret = -1;
	struct apac_wps_data *data = sess->pWpsData;
	struct apac_wps_target_info *target;
	struct wps_data *wps = 0;
	u8 msg_type;
	u8 tmp[SIZE_64_BYTES];
	size_t length;
	u8 authenticator[SIZE_8_BYTES];

	do {
                if (!data || !data->target || !rcvMsgLen)
                        break;

		target = data->target;

		if (wps_create_wps_data(&wps))
			break;

		if (wps_parse_wps_data(data->rcvMsg, data->rcvMsgLen, wps))
			break;

		/* Message Type */
		if (wps_get_value(wps, WPS_TYPE_MSG_TYPE, &msg_type, 0))
			break;
		if (msg_type != WPS_MSGTYPE_M3)
			break;

		/* Registrar Nonce */
		length = sizeof(tmp);
		if (wps_get_value(wps, WPS_TYPE_REGISTRAR_NONCE, tmp, &length))
			break;
		if (os_memcmp(tmp, data->nonce, sizeof(data->nonce)))
			break;

		/* E-Hash1 */
		length = sizeof(target->hash1);
		if (wps_get_value(wps, WPS_TYPE_E_HASH1, target->hash1, &length))
			break;

		/* E-Hash2 */
		length = sizeof(target->hash2);
		if (wps_get_value(wps, WPS_TYPE_E_HASH2, target->hash2, &length))
			break;

		/* Authenticator */
		length = sizeof(authenticator);
		if (wps_get_value(wps, WPS_TYPE_AUTHENTICATOR, authenticator, &length))
			break;

		/* HMAC validation */
		if (apac_wps_hmac_validation(data, authenticator, data->authKey))
			break;

		ret = 0;
	} while (0);

	(void)wps_destroy_wps_data(&wps);

	return ret;
}

u8 *apac_wps_build_message_M4(struct apac_wps_session* sess, size_t *msg_len)
{
	u8 *msg = 0;
        struct apac_wps_data *data = sess->pWpsData;
        struct apac_wps_target_info *target;
        struct wps_config *conf = sess->pData->config.wpsConf;
	struct wps_data *wps = 0;
	u8 authenticator[SIZE_8_BYTES];
	u8 u8val;
	size_t length;
	u8 *encrs = NULL;
	size_t encrs_len = 0;

	do {
		if (!conf || !data || !data->target || !msg_len)
			break;
		target = data->target;

		if (wps_create_wps_data(&wps))
			break;

		/* Version */
		u8val = WPS_VERSION;
		if (wps_set_value(wps, WPS_TYPE_VERSION, &u8val, 0))
			break;

		/* Message Type */
		u8val = WPS_MSGTYPE_M4;
		if (wps_set_value(wps, WPS_TYPE_MSG_TYPE, &u8val, 0))
			break;

		/* Enrollee Nonce */
		if (wps_set_value(wps, WPS_TYPE_ENROLLEE_NONCE, target->nonce, sizeof(target->nonce)))
			break;

		if (!data->dev_pwd_len)
			break;

		/* R-Hash1 */
		if (apac_wps_generate_hash(data, data->dev_pwd,
								   data->dev_pwd_len/2 + data->dev_pwd_len%2,
								   target->pubKey, data->pubKey, data->authKey,
								   data->psk1, data->snonce1, data->hash1))
			break;
		if(wps_set_value(wps, WPS_TYPE_R_HASH1, data->hash1, sizeof(data->hash1)))
			break;

		/* R-Hash2 */
		if (apac_wps_generate_hash(data, data->dev_pwd + data->dev_pwd_len/2 + data->dev_pwd_len%2,
								   data->dev_pwd_len/2,
								   target->pubKey, data->pubKey, data->authKey,
								   data->psk2, data->snonce2, data->hash2))
			break;
		if(wps_set_value(wps, WPS_TYPE_R_HASH2, data->hash2, sizeof(data->hash2)))
			break;

		/* Encrypted Settings */
		if (apac_wps_encrsettings_creation(data, WPS_TYPE_R_SNONCE1, data->snonce1, 0, 0, data->authKey, data->keyWrapKey, &encrs, &encrs_len))
			break;
		if (wps_set_value(wps, WPS_TYPE_ENCR_SETTINGS, encrs, (u16)encrs_len))
			break;

		/* WPS version 2*/
		if (apac_wps_build_wfa_ext(wps))
			break;

		/* Authenticator */
		length = 0;
		if (wps_write_wps_data(wps, &msg, &length))
			break;
		if (apac_wps_calcurate_authenticator(data, msg, length,
									data->authKey, authenticator)) {
			os_free(msg);
			msg = 0;
			break;
		}
		os_free(msg);
		msg = 0;
		if (wps_set_value(wps, WPS_TYPE_AUTHENTICATOR, authenticator, sizeof(authenticator)))
			break;

		if (wps_write_wps_data(wps, &msg, &length))
			break;

		*msg_len = length;

		if (data->sndMsg) {
			os_free(data->sndMsg);
			data->sndMsg = 0;
			data->sndMsgLen = 0;
		}
		data->sndMsg = os_malloc(*msg_len);
		if (!data->sndMsg) {
			os_free(msg);
			msg = 0;
			*msg_len = 0;
			break;
		}

		os_memcpy(data->sndMsg, msg, *msg_len);
		data->sndMsgLen = *msg_len;
	} while (0);

	if (encrs)
		os_free(encrs);

	(void)wps_destroy_wps_data(&wps);

	return msg;
}


int apac_wps_process_message_M4(struct apac_wps_session* sess, u8* rcvMsg, int rcvMsgLen)
{
	int ret = -1;
	struct apac_wps_data *data = sess->pWpsData;
	struct apac_wps_target_info *target;
        struct wps_config *conf = sess->pData->config.wpsConf;
	struct wps_data *wps = 0;
	u8 version;
	u8 msg_type;
	u8 nonce[SIZE_NONCE];
	size_t length;
	u8 *tmp = 0, *iv, *cipher, *decrypted = 0;
	int cipher_len, decrypted_len;
	u8 authenticator[SIZE_8_BYTES];
	u8 rsnonce[SIZE_NONCE];
	u8 keyWrapAuth[SIZE_64_BITS];

	do {
		if (!conf || !data || !data->target)
			break;
		target = data->target;

		if (wps_create_wps_data(&wps))
			break;

		if (wps_parse_wps_data(data->rcvMsg, data->rcvMsgLen, wps))
			break;

		/* Version */
		if (wps_get_value(wps, WPS_TYPE_VERSION, &version, 0))
			break;
		if ((version != WPS_VERSION) && (version != WPS_VERSION_EX))
			break;

		/* Message Type */
		if (wps_get_value(wps, WPS_TYPE_MSG_TYPE, &msg_type, 0))
			break;
		if (msg_type != WPS_MSGTYPE_M4)
			break;

		/* Enrollee Nonce */
		length = sizeof(nonce);
		if (wps_get_value(wps, WPS_TYPE_ENROLLEE_NONCE, nonce, &length))
			break;
		if (os_memcmp(data->nonce, nonce, sizeof(data->nonce)))
			break;

		/* R-Hash1 */
		length = sizeof(target->hash1);
		if (wps_get_value(wps, WPS_TYPE_R_HASH1, target->hash1, &length))
			break;

		/* R-Hash2 */
		length = sizeof(target->hash2);
		if (wps_get_value(wps, WPS_TYPE_R_HASH2, target->hash2, &length))
			break;

		/* Encrypted Settings */
		length = 0;
		(void)wps_get_value(wps, WPS_TYPE_ENCR_SETTINGS, 0, &length);
		if (!length)
			break;
		tmp = os_malloc(length);
		if (!tmp)
			break;
		if (wps_get_value(wps, WPS_TYPE_ENCR_SETTINGS, tmp, &length))
			break;
		iv = tmp;
		cipher = tmp + SIZE_128_BITS;
		cipher_len = length - SIZE_128_BITS;
		if (apac_wps_decrypt_data(data, iv, cipher, cipher_len, data->keyWrapKey, &decrypted, &decrypted_len))
			break;
		if (apac_wps_encrsettings_validation(data, decrypted, decrypted_len, data->authKey,
											WPS_TYPE_R_SNONCE1, rsnonce, keyWrapAuth))
			break;

		/* Authenticator */
		length = sizeof(authenticator);
		if (wps_get_value(wps, WPS_TYPE_AUTHENTICATOR, authenticator, &length))
			break;

		/* HMAC validation */
		if (apac_wps_hmac_validation(data, authenticator, data->authKey))
			break;

		/* RHash1 validation */
		if (apac_wps_hash_validation(data, target->hash1, rsnonce, data->psk1, data->pubKey, target->pubKey, data->authKey)) {
                        /* WCN requires us to use particular config error */
                        target->config_error = WPS_ERROR_DEV_PWD_AUTH_FAIL;
			break;
                }

		ret = 0;
	} while (0);

	if (tmp)
		os_free(tmp);
	if (decrypted)
		os_free(decrypted);

	(void)wps_destroy_wps_data(&wps);

	return ret;
}

u8 *apac_wps_build_message_M5(struct apac_wps_session* sess, size_t *msg_len)
{
	u8 *msg = 0;
        struct apac_wps_data *data = sess->pWpsData;
        struct apac_wps_target_info *target;
        struct wps_config *conf = sess->pData->config.wpsConf;
	struct wps_data *wps = 0;
	u8 u8val;
	size_t length;
	u8 *encrs = 0;
	size_t encrs_len;
	u8 authenticator[SIZE_8_BYTES];

	do {
		if (!conf || !data || !data->target || !msg_len)
			break;
		target = data->target;

		if (wps_create_wps_data(&wps))
			break;

		/* Version */
		u8val = WPS_VERSION;
		if (wps_set_value(wps, WPS_TYPE_VERSION, &u8val, 0))
			break;

		/* Message Type */
		u8val = WPS_MSGTYPE_M5;
		if (wps_set_value(wps, WPS_TYPE_MSG_TYPE, &u8val, 0))
			break;

		/* Registrar Nonce */
		if (wps_set_value(wps, WPS_TYPE_REGISTRAR_NONCE, target->nonce, sizeof(target->nonce)))
			break;

		/* Encrypted Settings */
		if (apac_wps_encrsettings_creation(data, WPS_TYPE_E_SNONCE1, data->snonce1, 0, 0, data->authKey, data->keyWrapKey, &encrs, &encrs_len))
			break;
		if (wps_set_value(wps, WPS_TYPE_ENCR_SETTINGS, encrs, (u16)encrs_len))
			break;

		/* WPS version 2*/
		if (apac_wps_build_wfa_ext(wps))
			break;

		/* Authenticator */
		length = 0;
		if (wps_write_wps_data(wps, &msg, &length))
			break;
		if (apac_wps_calcurate_authenticator(data, msg, length,
									data->authKey, authenticator)) {
			os_free(msg);
			msg = 0;
			break;
		}
		os_free(msg);
		msg = 0;
		if (wps_set_value(wps, WPS_TYPE_AUTHENTICATOR, authenticator, sizeof(authenticator)))
			break;

		if (wps_write_wps_data(wps, &msg, &length))
			break;

		*msg_len = length;

		if (data->sndMsg) {
			os_free(data->sndMsg);
			data->sndMsg = 0;
			data->sndMsgLen = 0;
		}
		data->sndMsg = os_malloc(*msg_len);
		if (!data->sndMsg) {
			os_free(msg);
			msg = 0;
			*msg_len = 0;
			break;
		}

		os_memcpy(data->sndMsg, msg, *msg_len);
		data->sndMsgLen = *msg_len;
	} while (0);

	if (encrs)
		os_free(encrs);

	(void)wps_destroy_wps_data(&wps);

	return msg;
}


int apac_wps_process_message_M5(struct apac_wps_session* sess, u8* rcvMsg, int rcvMsgLen)
{
	int ret = -1;
	struct apac_wps_data *data = sess->pWpsData;
	struct apac_wps_target_info *target;
        struct wps_config *conf = sess->pData->config.wpsConf;
	u8 version;
	struct wps_data *wps = 0;
	u8 msg_type;
	u8 nonce[SIZE_NONCE];
	size_t length;
	u8 *tmp = 0, *iv, *cipher, *decrypted = 0;
	int cipher_len, decrypted_len;
	u8 authenticator[SIZE_8_BYTES];
	u8 rsnonce[SIZE_NONCE];
	u8 keyWrapAuth[SIZE_64_BITS];

	do {
		if (!conf || !data || !data->target)
			break;
		target = data->target;

		if (wps_create_wps_data(&wps))
			break;

		if (wps_parse_wps_data(data->rcvMsg, data->rcvMsgLen, wps))
			break;

		/* Version */
		if (wps_get_value(wps, WPS_TYPE_VERSION, &version, 0))
			break;
		if ((version != WPS_VERSION) && (version != WPS_VERSION_EX))
			break;

		/* Message Type */
		if (wps_get_value(wps, WPS_TYPE_MSG_TYPE, &msg_type, 0))
			break;
		if (msg_type != WPS_MSGTYPE_M5)
			break;

		/* Registrar Nonce */
		length = sizeof(nonce);
		if (wps_get_value(wps, WPS_TYPE_REGISTRAR_NONCE, nonce, &length))
			break;
		if (os_memcmp(data->nonce, nonce, sizeof(data->nonce)))
			break;

		/* Encrypted Settings */
		length = 0;
		(void)wps_get_value(wps, WPS_TYPE_ENCR_SETTINGS, 0, &length);
		if (!length)
			break;
		tmp = os_malloc(length);
		if (!tmp)
			break;
		if (wps_get_value(wps, WPS_TYPE_ENCR_SETTINGS, tmp, &length))
			break;
		iv = tmp;
		cipher = tmp + SIZE_128_BITS;
		cipher_len = length - SIZE_128_BITS;
		if (apac_wps_decrypt_data(data, iv, cipher, cipher_len, data->keyWrapKey, &decrypted, &decrypted_len))
			break;
		if (apac_wps_encrsettings_validation(data, decrypted, decrypted_len, data->authKey,
											WPS_TYPE_E_SNONCE1, rsnonce, keyWrapAuth))
			break;

		/* Authenticator */
		length = sizeof(authenticator);
		if (wps_get_value(wps, WPS_TYPE_AUTHENTICATOR, authenticator, &length))
			break;

		/* HMAC validation */
		if (apac_wps_hmac_validation(data, authenticator, data->authKey))
			break;

		/* EHash1 validation */
		if (apac_wps_hash_validation(data, target->hash1, rsnonce, data->psk1, target->pubKey, data->pubKey, data->authKey))
			break;

		ret = 0;
	} while (0);

	if (tmp)
		os_free(tmp);
	if (decrypted)
		os_free(decrypted);

	(void)wps_destroy_wps_data(&wps);

	return ret;
}



u8 *apac_wps_build_message_M6(struct apac_wps_session* sess, size_t *msg_len)
{
	u8 *msg = 0;
        struct apac_wps_data *data = sess->pWpsData;
        struct apac_wps_target_info *target;
        struct wps_config *conf = sess->pData->config.wpsConf;
	struct wps_data *wps = 0;
	u8 u8val;
	size_t length;
	u8 *encrs = 0;
	size_t encrs_len;
	u8 authenticator[SIZE_8_BYTES];

	do {
		if (!conf || !data || !data->target || !msg_len)
			break;
		target = data->target;

		if (wps_create_wps_data(&wps))
			break;

		/* Version */
		u8val = WPS_VERSION;
		if (wps_set_value(wps, WPS_TYPE_VERSION, &u8val, 0))
			break;

		/* Message Type */
		u8val = WPS_MSGTYPE_M6;
		if (wps_set_value(wps, WPS_TYPE_MSG_TYPE, &u8val, 0))
			break;

		/* Enrollee Nonce */
		if (wps_set_value(wps, WPS_TYPE_ENROLLEE_NONCE, target->nonce, sizeof(target->nonce)))
			break;

		/* Encrypted Settings */
		if (apac_wps_encrsettings_creation(data, WPS_TYPE_R_SNONCE2, data->snonce2, 0, 0, data->authKey, data->keyWrapKey, &encrs, &encrs_len))
			break;
		if (wps_set_value(wps, WPS_TYPE_ENCR_SETTINGS, encrs, (u16)encrs_len))
			break;

		/* WPS version 2*/
		if (apac_wps_build_wfa_ext(wps))
			break;

		/* Authenticator */
		length = 0;
		if (wps_write_wps_data(wps, &msg, &length))
			break;
		if (apac_wps_calcurate_authenticator(data, msg, length,
									data->authKey, authenticator)) {
			os_free(msg);
			msg = 0;
			break;
		}
		os_free(msg);
		msg = 0;
		if (wps_set_value(wps, WPS_TYPE_AUTHENTICATOR, authenticator, sizeof(authenticator)))
			break;

		if (wps_write_wps_data(wps, &msg, &length))
			break;

		*msg_len = length;

		if (data->sndMsg) {
			os_free(data->sndMsg);
			data->sndMsg = 0;
			data->sndMsgLen = 0;
		}
		data->sndMsg = os_malloc(*msg_len);
		if (!data->sndMsg) {
			os_free(msg);
			msg = 0;
			*msg_len = 0;
			break;
		}

		os_memcpy(data->sndMsg, msg, *msg_len);
		data->sndMsgLen = *msg_len;
	} while (0);

	if (encrs)
		os_free(encrs);

	(void)wps_destroy_wps_data(&wps);

	return msg;
}


int apac_wps_process_message_M6(struct apac_wps_session* sess, u8* rcvMsg, int rcvMsgLen)
{
	int ret = -1;
	struct apac_wps_data *data = sess->pWpsData;
	struct apac_wps_target_info *target;
        struct wps_config *conf = sess->pData->config.wpsConf;
	struct wps_data *wps = 0;
	u8 version;
	u8 msg_type;
	u8 nonce[SIZE_NONCE];
	size_t length;
	u8 *tmp = 0, *iv, *cipher, *decrypted = 0;
	int cipher_len, decrypted_len;
	u8 authenticator[SIZE_8_BYTES];
	u8 rsnonce[SIZE_NONCE];
	u8 keyWrapAuth[SIZE_64_BITS];

	do {
		if (!conf || !data || !data->target)
			break;
		target = data->target;

		if (wps_create_wps_data(&wps))
			break;

		if (wps_parse_wps_data(data->rcvMsg, data->rcvMsgLen, wps))
			break;

		/* Version */
		if (wps_get_value(wps, WPS_TYPE_VERSION, &version, 0))
			break;
		if ((version != WPS_VERSION) && (version != WPS_VERSION_EX))
			break;

		/* Message Type */
		if (wps_get_value(wps, WPS_TYPE_MSG_TYPE, &msg_type, 0))
			break;
		if (msg_type != WPS_MSGTYPE_M6)
			break;

		/* Enrollee Nonce */
		length = sizeof(nonce);
		if (wps_get_value(wps, WPS_TYPE_ENROLLEE_NONCE, nonce, &length))
			break;
		if (os_memcmp(data->nonce, nonce, sizeof(data->nonce)))
			break;

		/* Encrypted Settings */
		length = 0;
		(void)wps_get_value(wps, WPS_TYPE_ENCR_SETTINGS, 0, &length);
		if (!length)
			break;
		tmp = os_malloc(length);
		if (!tmp)
			break;
		if (wps_get_value(wps, WPS_TYPE_ENCR_SETTINGS, tmp, &length))
			break;
		iv = tmp;
		cipher = tmp + SIZE_128_BITS;
		cipher_len = length - SIZE_128_BITS;
		if (apac_wps_decrypt_data(data, iv, cipher, cipher_len, data->keyWrapKey, &decrypted, &decrypted_len))
			break;
		if (apac_wps_encrsettings_validation(data, decrypted, decrypted_len, data->authKey,
											WPS_TYPE_R_SNONCE2, rsnonce, keyWrapAuth))
			break;

		/* Authenticator */
		length = sizeof(authenticator);
		if (wps_get_value(wps, WPS_TYPE_AUTHENTICATOR, authenticator, &length))
			break;

		/* HMAC validation */
		if (apac_wps_hmac_validation(data, authenticator, data->authKey))
			break;

		/* RHash2 validation */
		if (apac_wps_hash_validation(data, target->hash2, rsnonce, data->psk2, data->pubKey, target->pubKey, data->authKey)) {
                        /* WCN requires us to use particular config error */
                        target->config_error = WPS_ERROR_DEV_PWD_AUTH_FAIL;
			break;
                }
		ret = 0;
	} while (0);

	if (tmp)
		os_free(tmp);
	if (decrypted)
		os_free(decrypted);

	(void)wps_destroy_wps_data(&wps);

	return ret;
}


u8 *apac_wps_build_message_M7(struct apac_wps_session* sess, size_t *msg_len)
{
	u8 *msg = 0;
        struct apac_wps_data *data = sess->pWpsData;
        struct apac_wps_target_info *target;
        struct wps_config *conf = sess->pData->config.wpsConf;
	struct wps_data *wps = 0;
	u8 u8val;
	size_t length;
	u8 *encrs = 0;
	size_t encrs_len;
	u8 authenticator[SIZE_8_BYTES];

	do {
		if (!conf || !data || !data->target || !msg_len)
			break;
		target = data->target;

		if (wps_create_wps_data(&wps))
			break;

		/* Version */
		u8val = WPS_VERSION;
		if (wps_set_value(wps, WPS_TYPE_VERSION, &u8val, 0))
			break;

		/* Message Type */
		u8val = WPS_MSGTYPE_M7;
		if (wps_set_value(wps, WPS_TYPE_MSG_TYPE, &u8val, 0))
			break;

		/* Registrar Nonce */
		if (wps_set_value(wps, WPS_TYPE_REGISTRAR_NONCE, target->nonce, sizeof(target->nonce)))
			break;

		/* Encrypted Settings */
		if (apac_wps_encrsettings_creation(data, WPS_TYPE_E_SNONCE2, data->snonce2, data->config, data->config_len, data->authKey, data->keyWrapKey, &encrs, &encrs_len))
			break;


		if (wps_set_value(wps, WPS_TYPE_ENCR_SETTINGS, encrs, (u16)encrs_len))
			break;

		/* WPS version 2*/
		if (apac_wps_build_wfa_ext(wps))
			break;

		/* Authenticator */
		length = 0;
		if (wps_write_wps_data(wps, &msg, &length))
			break;
		if (apac_wps_calcurate_authenticator(data, msg, length,
									data->authKey, authenticator)) {
			os_free(msg);
			msg = 0;
			break;
		}
		os_free(msg);
		msg = 0;
		if (wps_set_value(wps, WPS_TYPE_AUTHENTICATOR, authenticator, sizeof(authenticator)))
			break;

		if (wps_write_wps_data(wps, &msg, &length))
			break;

		*msg_len = length;

		if (data->sndMsg) {
			os_free(data->sndMsg);
			data->sndMsg = 0;
			data->sndMsgLen = 0;
		}
		data->sndMsg = os_malloc(*msg_len);
		if (!data->sndMsg) {
			os_free(msg);
			msg = 0;
			*msg_len = 0;
			break;
		}

		os_memcpy(data->sndMsg, msg, *msg_len);
		data->sndMsgLen = *msg_len;
	} while (0);

	if (encrs)
		os_free(encrs);

	(void)wps_destroy_wps_data(&wps);

	return msg;
}


int apac_wps_process_message_M7(struct apac_wps_session* sess, u8* rcvMsg, int rcvMsgLen)
{
	int ret = -1;
	struct apac_wps_data *data = sess->pWpsData;
	struct apac_wps_target_info *target;
        struct wps_config *conf = sess->pData->config.wpsConf;
	struct wps_data *wps = 0;
	u8 version;
	u8 msg_type;
	u8 nonce[SIZE_NONCE];
	size_t length;
	u8 *tmp = 0, *iv, *cipher, *decrypted = 0;
	int cipher_len, decrypted_len;
	u8 authenticator[SIZE_8_BYTES];
	u8 rsnonce[SIZE_NONCE];
	u8 keyWrapAuth[SIZE_64_BITS];

	do {
		if (!conf || !data || !data->target)
			break;
		target = data->target;

		if (wps_create_wps_data(&wps))
			break;

		if (wps_parse_wps_data(data->rcvMsg, data->rcvMsgLen, wps))
			break;

		/* Version */
		if (wps_get_value(wps, WPS_TYPE_VERSION, &version, 0))
			break;
		if ((version != WPS_VERSION) && (version != WPS_VERSION_EX))
			break;

		/* Message Type */
		if (wps_get_value(wps, WPS_TYPE_MSG_TYPE, &msg_type, 0))
			break;
		if (msg_type != WPS_MSGTYPE_M7)
			break;

		/* Registrar Nonce */
		length = sizeof(nonce);
		if (wps_get_value(wps, WPS_TYPE_REGISTRAR_NONCE, nonce, &length))
			break;
		if (os_memcmp(data->nonce, nonce, sizeof(data->nonce)))
			break;

		/* Encrypted Settings */
		length = 0;
		(void)wps_get_value(wps, WPS_TYPE_ENCR_SETTINGS, 0, &length);
		if (!length)
			break;
		tmp = os_malloc(length);
		if (!tmp)
			break;
		if (wps_get_value(wps, WPS_TYPE_ENCR_SETTINGS, tmp, &length))
			break;
		iv = tmp;
		cipher = tmp + SIZE_128_BITS;
		cipher_len = length - SIZE_128_BITS;
		if (apac_wps_decrypt_data(data, iv, cipher, cipher_len, data->keyWrapKey, &decrypted, &decrypted_len))
			break;
		if (apac_wps_encrsettings_validation(data, decrypted, decrypted_len, data->authKey,
											WPS_TYPE_E_SNONCE2, rsnonce, keyWrapAuth))
			break;
		if (target->config)
			os_free(target->config);
		target->config = decrypted;
		target->config_len = decrypted_len;

		/* Authenticator */
		length = sizeof(authenticator);
		if (wps_get_value(wps, WPS_TYPE_AUTHENTICATOR, authenticator, &length))
			break;

		/* HMAC validation */
		if (apac_wps_hmac_validation(data, authenticator, data->authKey))
			break;

		/* EHash2 validation */
		if (apac_wps_hash_validation(data, target->hash2, rsnonce, data->psk2, target->pubKey, data->pubKey, data->authKey))
			break;

		ret = 0;
	} while (0);

	if (tmp)
		os_free(tmp);
	if (ret && decrypted) {
		os_free(decrypted);
		if (data->target) {
			target = data->target;
			target->config = 0;
			target->config_len = 0;
		}
	}

	(void)wps_destroy_wps_data(&wps);

	return ret;
}

u8 *apac_wps_build_message_M8(struct apac_wps_session* sess, size_t *msg_len)
{
	u8 *msg = 0;
        struct apac_wps_data *data = sess->pWpsData;
        struct apac_wps_target_info *target;
        struct wps_config *conf = sess->pData->config.wpsConf;
	struct wps_data *wps = 0;
	u8 u8val;
	size_t length;
	u8 *encrs = 0;
	size_t encrs_len;
	u8 authenticator[SIZE_8_BYTES];

	do {
		if (!conf || !data || !data->target || !msg_len)
			break;
		target = data->target;

		if (wps_create_wps_data(&wps))
			break;

		/* Version */
		u8val = WPS_VERSION;
		if (wps_set_value(wps, WPS_TYPE_VERSION, &u8val, 0))
			break;

		/* Message Type */
		u8val = WPS_MSGTYPE_M8;
		if (wps_set_value(wps, WPS_TYPE_MSG_TYPE, &u8val, 0))
			break;

		/* Enrollee Nonce */
		if (wps_set_value(wps, WPS_TYPE_ENROLLEE_NONCE, target->nonce, sizeof(target->nonce)))
			break;

		/* Encrypted Settings */
                if (apac_wps_get_wifi_configuration(sess, &data->config, &data->config_len)) {
                    dprintf(MSG_ERROR, "Failed to get WiFi configuration\n");
                    break;
                }

		if (apac_wps_encrsettings_creation(data, 0, 0,
					data->config, data->config_len,
					data->authKey, data->keyWrapKey, &encrs, &encrs_len))
			break;

		if (wps_set_value(wps, WPS_TYPE_ENCR_SETTINGS, encrs, (u16)encrs_len))
			break;

		/* WPS version 2*/
		if (apac_wps_build_wfa_ext(wps))
			break;

		/* Authenticator */
		length = 0;
		if (wps_write_wps_data(wps, &msg, &length))
			break;
		if (apac_wps_calcurate_authenticator(data, msg, length,
									data->authKey, authenticator)) {
			os_free(msg);
			msg = 0;
			break;
		}
		os_free(msg);
		msg = 0;
		if (wps_set_value(wps, WPS_TYPE_AUTHENTICATOR, authenticator, sizeof(authenticator)))
			break;

		if (wps_write_wps_data(wps, &msg, &length))
			break;

		*msg_len = length;

		if (data->sndMsg) {
			os_free(data->sndMsg);
			data->sndMsg = 0;
			data->sndMsgLen = 0;
		}
		data->sndMsg = os_malloc(*msg_len);
		if (!data->sndMsg) {
			os_free(msg);
			msg = 0;
			*msg_len = 0;
			break;
		}

		os_memcpy(data->sndMsg, msg, *msg_len);
		data->sndMsgLen = *msg_len;
	} while (0);

	if (encrs)
		os_free(encrs);

	(void)wps_destroy_wps_data(&wps);

	return msg;
}


int apac_wps_process_message_M8(struct apac_wps_session* sess, u8* rcvMsg, int rcvMsgLen)
{
	int ret = -1;
	struct apac_wps_data *data = sess->pWpsData;
	struct apac_wps_target_info *target;
        struct wps_config *conf = sess->pData->config.wpsConf;
	struct wps_data *wps = 0;
	u8 version;
	u8 msg_type;
	u8 nonce[SIZE_NONCE];
	size_t length;
	u8 *tmp = 0, *iv, *cipher, *decrypted = 0;
	int cipher_len, decrypted_len;
	u8 authenticator[SIZE_8_BYTES];
	u8 keyWrapAuth[SIZE_64_BITS];

	do {
		if (!conf || !data || !data->target)
			break;
		target = data->target;

		if (wps_create_wps_data(&wps))
			break;

		if (wps_parse_wps_data(data->rcvMsg, data->rcvMsgLen, wps))
			break;

		/* Version */
		if (wps_get_value(wps, WPS_TYPE_VERSION, &version, 0))
			break;
		if ((version != WPS_VERSION) && (version != WPS_VERSION_EX))
			break;

		/* Message Type */
		if (wps_get_value(wps, WPS_TYPE_MSG_TYPE, &msg_type, 0))
			break;
		if (msg_type != WPS_MSGTYPE_M8)
			break;

		/* Enrollee Nonce */
		length = sizeof(nonce);
		if (wps_get_value(wps, WPS_TYPE_ENROLLEE_NONCE, nonce, &length))
			break;
		if (os_memcmp(data->nonce, nonce, sizeof(data->nonce)))
			break;

		/* Encrypted Settings */
		length = 0;
		(void)wps_get_value(wps, WPS_TYPE_ENCR_SETTINGS, 0, &length);
		if (!length)
			break;
		tmp = os_malloc(length);
		if (!tmp)
			break;
		if (wps_get_value(wps, WPS_TYPE_ENCR_SETTINGS, tmp, &length))
			break;
		iv = tmp;
		cipher = tmp + SIZE_128_BITS;
		cipher_len = length - SIZE_128_BITS;
		if (apac_wps_decrypt_data(data, iv, cipher, cipher_len, data->keyWrapKey, &decrypted, &decrypted_len))
			break;
		if (apac_wps_encrsettings_validation(data, decrypted, decrypted_len,
											data->authKey, 0, 0, keyWrapAuth))
			break;

		/* Authenticator */
		length = sizeof(authenticator);
		if (wps_get_value(wps, WPS_TYPE_AUTHENTICATOR, authenticator, &length))
			break;

		/* HMAC validation */
		if (apac_wps_hmac_validation(data, authenticator, data->authKey))
			break;

		if (target->config)
			os_free(target->config);
		target->config = decrypted;
		target->config_len = decrypted_len;

		ret = 0;
	} while (0);

	if (tmp)
		os_free(tmp);
	if (ret && decrypted)
		os_free(decrypted);

	(void)wps_destroy_wps_data(&wps);

	return ret;
}


/* Remove IEEE1905 Wrapper, and get WPS content 
 * Such packet is formatted as: HDR + 1905TLV_WPS(WPSTLV) + ENDTLV 
 */
u8 *apacHyfi20RemoveIeee1905Tlv(u8 *frame, s32 frameLen, s16 *wpsContentLen) {
    u8 *pWpsContent;
    ieee1905TLV_t *pTLV = (ieee1905TLV_t *)((ieee1905Message_t *)frame)->content;
    ieee1905TlvType_e tlvType;

    apacHyfi20TRACE();

    tlvType = ieee1905TLVTypeGet(pTLV);
    dprintf(MSG_MSGDUMP, "Get TLV type: %d\n", tlvType);
    
    /* Message verification. */
    if (tlvType != IEEE1905_TLV_TYPE_WPS) {
        dprintf(MSG_ERROR, "%s TLV type is not WPS!\n", __func__);
        wpsContentLen = 0;
        return NULL;
    }

    *wpsContentLen = ieee1905TLVLenGet(pTLV);
    pWpsContent = ieee1905TLVValGet(pTLV);

    pTLV = ieee1905TLVGetNext(pTLV);
    tlvType = ieee1905TLVTypeGet(pTLV);
    dprintf(MSG_MSGDUMP, "Get TLV type: %d\n", tlvType);

    /* Message verification. */
    if (tlvType != IEEE1905_TLV_TYPE_END_OF_MESSAGE) {
        dprintf(MSG_ERROR, "%s TLV type is not EndOfTLV!\n", __func__);
        wpsContentLen = 0;
        return NULL;
    }

    /* error check */
    if (frameLen != *wpsContentLen + IEEE1905_FRAME_MIN_LEN + IEEE1905_TLV_MIN_LEN) {
        dprintf(MSG_ERROR, "%s frameLen(%d) != wpsLen(%d) + ethHdr(%d) \
            + 1905Hdr(%d) + 2 * min_tlv(%d)\n",
            __func__, frameLen, *wpsContentLen, 
            IEEE1905_ETH_HEAD_LEN, IEEE1905_HEAD_LEN,
            IEEE1905_TLV_MIN_LEN);
        wpsContentLen = 0;
        return NULL;
    } 

    return pWpsContent;
}

/* Process WPS request in Registration Phase 
 * Registrar receives M1, M3, M5, and M7; sends M2, M4, M6 and M8
 * Enrollee sends M1, M3, M5, and M7; receives M2, M4, M6 and M8
 */
int apacHyfi20ReceiveWpsE(apacHyfi20Data_t *pData, u8 *frame, u32 frameLen) {
    struct apac_wps_session* sess;
    struct ether_header ethHdr = ((ieee1905Message_t *)frame)->etherHeader;
    struct ieee1905Header_t ieee1905Hdr = ((ieee1905Message_t *)frame)->ieee1905Header;
    u8 *src = ethHdr.ether_shost;
    u8 *wpsMsg = NULL;
    s16 wpsMsgLen = 0;
    s32 wpsMsgType;
    APAC_WPS_DATA *data;
    size_t len;
    apacBool_e done = APAC_FALSE;
    apacHyfi20WifiFreq_e freq;

    apacHyfi20TRACE();

    sess = apac_wps_find_session(pData, src);

    /* session not found */
    if (!sess) {
        dprintf(MSG_ERROR, "%s -- can't find session \n", __func__);
        return -1;
    }

    data = sess->pWpsData;
    if (!data) {
        dprintf(MSG_ERROR, "%s -- can't find eapwps data \n", __func__);
        return -1;
    }
    wpsMsg = apacHyfi20RemoveIeee1905Tlv(frame, frameLen, &wpsMsgLen);

    if (wpsMsg == NULL) {
        dprintf(MSG_ERROR, "%s not WPS info retrieved\n", __func__);
        return -1;
    }

    dprintf(MSG_MSGDUMP, "%s -- received WPS M2 msg len: %u\n", __func__, wpsMsgLen);
    //printMsg(wpsMsg, wpsMsgLen,  MSG_MSGDUMP);

    /* the first fragment of a new message */
    if (ieee1905Hdr.fid == 0) {
        if (data->rcvMsg) {
            os_free(data->rcvMsg);
        }
        data->rcvMsg = os_malloc(wpsMsgLen);
        if (data->rcvMsg) {
            os_memcpy(data->rcvMsg, wpsMsg, wpsMsgLen);
            data->rcvMsgLen = wpsMsgLen;
        }
    }
    else {
        data->rcvMsg = (u8 *)os_realloc(data->rcvMsg, data->rcvMsgLen + wpsMsgLen);
        if (data->rcvMsg) {
            os_memcpy(data->rcvMsg + data->rcvMsgLen, wpsMsg, wpsMsgLen);
            data->rcvMsgLen += wpsMsgLen;
        }
    }
        
    if (!data->rcvMsg) {
        data->rcvMsgLen = 0;
        dprintf(MSG_ERROR, "%s, faliure to alloc memory for rcvMsg!\n", __func__);
        return -1; 
    }
    //printMsg(data->rcvMsg, data->rcvMsgLen, MSG_MSGDUMP);

    /* stop if this not last fragment */
    if (!(ieee1905Hdr.flags & IEEE1905_HEADER_FLAG_LAST_FRAGMENT)) {
        dprintf(MSG_DEBUG, "%s -- not last fragment, skip packet processing\n", __func__);
        return 0; 
    }
	
    /* Process message */
    wpsMsgType = wps_get_message_type(data->rcvMsg, data->rcvMsgLen);
    wpsMsg = NULL;
    wpsMsgLen = 0;

    switch (wpsMsgType) { 
    case (WPS_MSGTYPE_M2):
        if (sess->state != APAC_WPS_E_M1_SENT && 
            sess->state != APAC_WPS_E_M3_SENT)
        {
            dprintf(MSG_ERROR, "M2 received, but WPS state[%d] is incorrect\n", sess->state);
            return -1;
        }
        if (sess->state == APAC_WPS_E_M3_SENT)
        {
            dprintf(MSG_INFO, "Retransmitted M2 received, response it again\n");
            goto retransmit;
        }

        if (apac_wps_process_message_M2(sess, data->rcvMsg, data->rcvMsgLen) < 0) {
            dprintf(MSG_ERROR, "process M2 error\n");
            return -1;
        }

        //TODO debug M1-M2 only
        freq = apac_get_freq(data->target->rf_bands);
        if (freq == APAC_WIFI_FREQ_INVALID) {
            done = APAC_FALSE;
        }
        else if(data->target && data->target->config)
        {
            done = APAC_TRUE;
            break;
        }

        dprintf(MSG_DEBUG, "WPS Build Enrollee M3\n");
        wpsMsg = apac_wps_build_message_M3(sess, &len);
        sess->state = APAC_WPS_E_M3_SENT;

        break;

    case (WPS_MSGTYPE_M4):
        if (sess->state != APAC_WPS_E_M3_SENT && 
            sess->state != APAC_WPS_E_M5_SENT)
        {
            dprintf(MSG_ERROR, "M4 received, but WPS state[%d] is incorrect\n", sess->state);
            return -1;
        }
        if (sess->state == APAC_WPS_E_M5_SENT)
        {
            dprintf(MSG_INFO, "Retransmitted M4 received, response it again\n");
            goto retransmit;
        }

        if (apac_wps_process_message_M4(sess, data->rcvMsg, data->rcvMsgLen) < 0) {
            dprintf(MSG_ERROR, "process M4 error\n");
            return -1;
        }
        dprintf(MSG_DEBUG, "WPS Build Enrollee M5\n");
        wpsMsg = apac_wps_build_message_M5(sess, &len);
        sess->state = APAC_WPS_E_M5_SENT;
        break;

    case (WPS_MSGTYPE_M6):
        if (sess->state != APAC_WPS_E_M5_SENT && 
            sess->state != APAC_WPS_E_M7_SENT)
        {
            dprintf(MSG_ERROR, "M6 received, but WPS state[%d] is incorrect\n", sess->state);
            return -1;
        }
        if (sess->state == APAC_WPS_E_M7_SENT)
        {
            dprintf(MSG_INFO, "Retransmitted M6 received, response it again\n");
            goto retransmit;
        }
        if (apac_wps_process_message_M6(sess, data->rcvMsg, data->rcvMsgLen) < 0) {
            dprintf(MSG_ERROR, "process M6 error\n");
            return -1;
        }
        dprintf(MSG_DEBUG, "WPS Build Enrollee M7\n");
        wpsMsg = apac_wps_build_message_M7(sess, &len);
        sess->state = APAC_WPS_E_M7_SENT;
        break;

    case (WPS_MSGTYPE_M8):
        if (sess->state != APAC_WPS_E_M7_SENT)
        {
            dprintf(MSG_ERROR, "M8 received, but WPS state[%d] is incorrect\n", sess->state);
            return -1;
        }

        if (apac_wps_process_message_M8(sess, data->rcvMsg, data->rcvMsgLen) < 0) {
            dprintf(MSG_ERROR, "process M8 error\n");
            return -1;
        }
        done = APAC_TRUE;
        break;

    default: 
        dprintf(MSG_ERROR, "%s, can't handle WPS_MSTYPE(%d)!\n", __func__, wpsMsgType);
        return -1;
    }

    if (wpsMsg && len)
    {
        if (apacHyfi20SendWps(sess, wpsMsg, len) < 0) {
            dprintf(MSG_ERROR, "%s failed to send WPS Message!\n", __func__);
            return -1;
        }
        sess->wps_retrans_ts = 0;
        sess->wps_message_ts = 0;
    }        
    else if (done != APAC_TRUE)
    {
        dprintf(MSG_ERROR, "Failed to build response for msg %d\n", wpsMsgType);
        dprintf(MSG_DEBUG, "len: %d, wpsMsg: 0x08%x\n", len, (unsigned int)wpsMsg);
        return -1;
    }

    if (done) {
        /* Set up Wifi configuration */
        if (apac_wps_finish_session(sess) == 0) {
            sess->wps_sess_success = 1;
            apacHyfi20ResetState(sess, APAC_TRUE);
            apac_wps_del_session(sess);
            return 0;
        }
        else {
            /* session failed, go to IDLE state and send Search again */
            dprintf(MSG_ERROR, "AP Auto Configuration Failed, reason unkown!");
            apacHyfi20ResetState(sess, APAC_FALSE);
            apac_wps_del_session(sess);
            return -1;
        }
        
    }
    else {
        return -1;
    }

    return 0;

retransmit:
    if (!data->sndMsg || !data->sndMsgLen)
    {
        dprintf(MSG_ERROR, "%s failed to get last message!\n", __func__);
        return -1;
    }

    if (apacHyfi20SendWps(sess, data->sndMsg, data->sndMsgLen) < 0) {
        dprintf(MSG_ERROR, "%s failed to retransmit last message!\n", __func__);
        return -1;
    }
    sess->wps_retrans_ts = 0;
    return 0;
}

int apacHyfi20ReceiveWpsR(apacHyfi20Data_t *pData, u8 *frame, u32 frameLen) {
    struct apac_wps_session* sess;
    struct ether_header ethHdr = ((ieee1905Message_t *)frame)->etherHeader;
    struct ieee1905Header_t ieee1905Hdr = ((ieee1905Message_t *)frame)->ieee1905Header;
    u8 *src = ethHdr.ether_shost;
    u8 *wpsMsg = NULL;
    s16 wpsMsgLen = 0;
    s32 wpsMsgType;
    APAC_WPS_DATA *data;
    size_t len = 0;
    apacBool_e isNewSession = APAC_FALSE;
    apacBool_e done = APAC_FALSE;

    if (pData->config.role != APAC_REGISTRAR) {
        dprintf(MSG_ERROR, "%s, not registrar!\n", __func__);
        return -1;
    }

    apacHyfi20TRACE();

    sess = apac_wps_find_session(pData, src);

    /* session not found */
    if (!sess) {

        /* initialize the start session*/
        sess = apac_wps_new_session(pData);
        if (!sess) {
            dprintf(MSG_ERROR, "can't open new session!\n");
            return -1;
        }

        /* write sender's mac in the session data */
        os_memcpy(sess->dest_addr, src, ETH_ALEN);
        isNewSession = APAC_TRUE;
    }
    dprintf(MSG_DEBUG, "%s after finding session\n", __func__);
    dprintf(MSG_DEBUG, "src: "); printMac(MSG_DEBUG, sess->own_addr);
    dprintf(MSG_DEBUG, "dest: "); printMac(MSG_DEBUG, sess->dest_addr);

    data = sess->pWpsData;
    if (!data) {
        dprintf(MSG_ERROR, "%s -- can't find eapwps data \n", __func__);
        return -1;
    }

    wpsMsg = apacHyfi20RemoveIeee1905Tlv(frame, frameLen, &wpsMsgLen);

    if (wpsMsg == NULL) {
        dprintf(MSG_ERROR, "%s no WPS info retrieved\n", __func__);
        return -1;
    }


    /* the first fragment of a new message */
    if (ieee1905Hdr.fid == 0) {
        if (data->rcvMsg) {
            os_free(data->rcvMsg);
        }
        data->rcvMsg = os_malloc(wpsMsgLen);
        if (data->rcvMsg) {
            os_memcpy(data->rcvMsg, wpsMsg, wpsMsgLen);
            data->rcvMsgLen = wpsMsgLen;
        }
    }
    else {
        data->rcvMsg = (u8 *)os_realloc(data->rcvMsg, data->rcvMsgLen + wpsMsgLen);
        if (data->rcvMsg) {
            os_memcpy(data->rcvMsg + data->rcvMsgLen, wpsMsg, wpsMsgLen);
            data->rcvMsgLen += wpsMsgLen;
        }
    }
        
    if (!data->rcvMsg) {
        data->rcvMsgLen = 0;
        dprintf(MSG_ERROR, "%s, faliure to alloc memory for rcvMsg!\n", __func__);
        return -1; 
    }

    /* stop if there are more frags to come */
    if (!(ieee1905Hdr.flags & IEEE1905_HEADER_FLAG_LAST_FRAGMENT)) {
        dprintf(MSG_DEBUG, "%s -- there are more fragmented messages \n", __func__);
        return 0;
    }
	
    /* Process message */
    wpsMsgType = wps_get_message_type(data->rcvMsg, data->rcvMsgLen);
    if (wpsMsgType > WPS_MSGTYPE_M1 && isNewSession == APAC_TRUE) {
        dprintf(MSG_ERROR, "%s -- set up new session but WPS message type(%d) is not M1\n", __func__, wpsMsgType);
        apac_wps_del_session(sess);
        return -1;
    }

   
    dprintf(MSG_DEBUG, "%s received WPS %d msg len: %u\n", __func__, wpsMsgType, data->rcvMsgLen);
    switch (wpsMsgType) { 
    case (WPS_MSGTYPE_M1):
        if (sess->state != APAC_WPS_R_INIT && 
            sess->state != APAC_WPS_R_M2_SENT)
        {
            dprintf(MSG_ERROR, "M1 received, but WPS state[%d] is incorrect\n", sess->state);
            return -1;
        }
        if (sess->state == APAC_WPS_R_M2_SENT)
        {
            dprintf(MSG_INFO, "Retransmitted M1 received, response it again\n");
            goto retransmit;
        }

        if (apac_wps_process_message_M1(sess, data->rcvMsg, data->rcvMsgLen) < 0) {
            dprintf(MSG_ERROR, "process M1 error\n");
            return -1;
        }
        dprintf(MSG_DEBUG, "WPS Build Registrar M2\n");
        wpsMsg = apac_wps_build_message_M2(sess, &len);
        sess->state = APAC_WPS_R_M2_SENT;
        if (pData->config.wps_method == APAC_WPS_M2)
            done = APAC_TRUE;
        break;

    case (WPS_MSGTYPE_M3):
        if (sess->state != APAC_WPS_R_M2_SENT && 
            sess->state != APAC_WPS_R_M4_SENT)
        {
            dprintf(MSG_ERROR, "M3 received, but WPS state[%d] is incorrect\n", sess->state);
            return -1;
        }
        if (sess->state == APAC_WPS_R_M4_SENT)
        {
            dprintf(MSG_INFO, "Retransmitted M3 received, response it again\n");
            goto retransmit;
        }

        if (apac_wps_process_message_M3(sess, data->rcvMsg, data->rcvMsgLen) < 0) {
            dprintf(MSG_ERROR, "process M3 error\n");
            return -1;
        }
        dprintf(MSG_DEBUG, "WPS Build Registrar M4\n");
        wpsMsg = apac_wps_build_message_M4(sess, &len);
        sess->state = APAC_WPS_R_M4_SENT;
        break;
    case (WPS_MSGTYPE_M5):
        if (sess->state != APAC_WPS_R_M4_SENT && 
            sess->state != APAC_WPS_R_M6_SENT)
        {
            dprintf(MSG_ERROR, "M5 received, but WPS state[%d] is incorrect\n", sess->state);
            return -1;
        }
        if (sess->state == APAC_WPS_R_M6_SENT)
        {
            dprintf(MSG_INFO, "Retransmitted M5 received, response it again\n");
            goto retransmit;
        }
        if (apac_wps_process_message_M5(sess, data->rcvMsg, data->rcvMsgLen) < 0) {
            dprintf(MSG_ERROR, "process M5 error\n");
            return -1;
        }
        dprintf(MSG_DEBUG, "WPS Build Registrar M6\n");
        wpsMsg = apac_wps_build_message_M6(sess, &len);
        sess->state = APAC_WPS_R_M6_SENT;
        break;
    case (WPS_MSGTYPE_M7):
        if (sess->state != APAC_WPS_R_M6_SENT && 
            sess->state != APAC_WPS_R_M8_SENT)
        {
            dprintf(MSG_ERROR, "M7 received, but WPS state[%d] is incorrect\n", sess->state);
            return -1;
        }
        if (sess->state == APAC_WPS_R_M8_SENT)
        {
            dprintf(MSG_INFO, "Retransmitted M7 received, response it again\n");
            goto retransmit;
        }
        if (apac_wps_process_message_M7(sess, data->rcvMsg, data->rcvMsgLen) < 0) {
            dprintf(MSG_ERROR, "process M7 error\n");
            return -1;
        }
        dprintf(MSG_DEBUG, "WPS Build Registrar M8\n");
        wpsMsg = apac_wps_build_message_M8(sess, &len);
        sess->state = APAC_WPS_R_M8_SENT;
        done = APAC_TRUE;
        break;
    default: 
        dprintf(MSG_ERROR, "%s, can't handle WPS_MSTYPE(%d)!\n", __func__, wpsMsgType);
        return -1;
    }

    /* Send WPS Message */
    if (wpsMsg && len)
    {
        dprintf(MSG_DEBUG, "%s sent WPS Message msg len: %u\n", __func__, len);
        //printMsg(wpsMsg, len, MSG_MSGDUMP);


        if (apacHyfi20SendWps(sess, wpsMsg, len) < 0) {
            dprintf(MSG_ERROR, "%s failed to send WPS Message!\n", __func__);
            return -1;
        }
        sess->wps_retrans_ts = 0;
        sess->wps_message_ts = 0;     

        if (done == APAC_TRUE)
        {
            sess->wps_sess_success = 1;
            /*Give enrollee chances to retry when M2/M8 missed, 
              we don't delete Registrar session untill packet time out*/
        }

    }
    else
    {
        dprintf(MSG_ERROR, "Failed to build response for msg %d\n", wpsMsgType);
        dprintf(MSG_DEBUG, "len: %d, wpsMsg: 0x08%x\n", len, (unsigned int)wpsMsg);
        return -1;
    }
    return 0;

retransmit:
    if (!data->sndMsg || !data->sndMsgLen)
    {
        dprintf(MSG_ERROR, "%s failed to get last message!\n", __func__);
        return -1;
    }

    if (apacHyfi20SendWps(sess, data->sndMsg, data->sndMsgLen) < 0) {
        dprintf(MSG_ERROR, "%s failed to retransmit last message!\n", __func__);
        return -1;
    }
    sess->wps_retrans_ts = 0;
    return 0;
}


/* Upon receiving Response/Renewal msg, Enrollee enters Registration Phase */
int apacHyfi20StartRegistrationE(apacHyfi20Data_t *pData, u8 *reg_mac) {
    size_t msg_len = 0;
    u8 *wpsMsg;
    struct apac_wps_session *sess;
    
    pData->config.state = APAC_E_WPS;

    /*  check if session is opened already */
    sess = apac_wps_find_session(pData, reg_mac);
    if (sess) {
        dprintf(MSG_ERROR, "%s - ERROR: An old session with this Registrar is active!\n", __func__);
        return -1;
    }

    apacHyfi20TRACE();

    sess = apac_wps_new_session(pData);
    if (!sess) {
        dprintf(MSG_INFO, "%s can't create new wps session!\n", __func__);
        return -1;
    }

    dprintf(MSG_DEBUG, "WPS Build Enrollee M1\n");
    wpsMsg = apac_wps_build_message_M1(sess, &msg_len);
    if (!wpsMsg || !msg_len) {
        dprintf(MSG_ERROR, "%s failed to build M1!\n", __func__);
        return -1;
    }

    /* cancel Search timeout during WPS registration, resume when WPS is done */
    eloop_cancel_timeout(apacHyfi20SearchTimeoutHandler, pData, NULL);
    eloop_cancel_timeout(apacHyfi20SearchTimeoutHandler, pData, (void *)&APAC_SEARCH_SHORT_INTERVAL);

    os_memcpy(sess->dest_addr, reg_mac, ETH_ALEN);

    dprintf(MSG_DEBUG, "%s WPS msg len: %u\n", __func__, msg_len);

    if (apacHyfi20SendWps(sess, wpsMsg, msg_len) < 0) {
        dprintf(MSG_ERROR, "%s failed to send M1!\n", __func__);
        return -1;
    }
     
    return 0;
}





