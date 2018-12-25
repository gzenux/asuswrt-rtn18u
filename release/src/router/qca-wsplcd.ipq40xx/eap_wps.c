/**************************************************************************
//
//  Copyright (c) 2006-2007 Sony Corporation. All Rights Reserved.
//
//  File Name: eap_wps.c
//  Description: EAP-WPS main source
//
//   Redistribution and use in source and binary forms, with or without
//   modification, are permitted provided that the following conditions
//   are met:
//
//     * Redistributions of source code must retain the above copyright
//       notice, this list of conditions and the following disclaimer.
//     * Redistributions in binary form must reproduce the above copyright
//       notice, this list of conditions and the following disclaimer in
//       the documentation and/or other materials provided with the
//       distribution.
//     * Neither the name of Sony Corporation nor the names of its
//       contributors may be used to endorse or promote products derived
//       from this software without specific prior written permission.
//
//   THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
//   "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
//   LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
//   A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
//   OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
//   SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
//   LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
//   DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
//   THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
//   (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
//   OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
**************************************************************************/

/*
 * Copyright (c) 2011-2012 Qualcomm Atheros, Inc.
 */

#include "wsplcd.h"
#include "apclone.h"
#include "eloop.h"
#include "eap_wps.h"
#include <sys/wait.h>

static unsigned char mcast_dest[ETH_ALEN] = EAPOL_MULTICAST_GROUP;

int eap_wps_build_send_eapol_start(struct eap_session* sess);
static int eap_wps_clear_target_info(struct eap_wps_data *data);

static int
eap_wps_init_eapwps_data(struct eap_session* sess)
{
    // allocate memory for eapwps data
    sess->eapWpsData = os_zalloc(sizeof(EAP_WPS_DATA));
    if (!sess->eapWpsData) {
        dprintf(MSG_ERROR, "Failed to alloc mem for eapwps data\n");
        return -1;
    }

    // now alloc mem for target info
    sess->eapWpsData->target = os_zalloc(sizeof(struct eap_wps_target_info));
    if (!sess->eapWpsData->target) {
        dprintf(MSG_ERROR, "Failed to alloc mem for eapwps target data\n");
        return -1;
    }

    return 0;
}


static void
eap_wps_deinit_eapwps_data(struct eap_session* sess)
{
    EAP_WPS_DATA    *data = sess->eapWpsData;

    if (!data)
        return;

    if (data->sndMsg) {
        os_free(data->sndMsg);
    }

    if (data->rcvMsg) {
        os_free(data->rcvMsg);
    }

    eap_wps_clear_target_info(data);
    if (data->target) {
        // free target data memory
        os_free(data->target);
        data->target = NULL;
    }

    // free eapwps data
    os_free(data);
}


static void eap_wps_reset_repeat_timeout(struct eap_session* sess)
{
	sess->repeat_time = sess->wspd->wsplcConfig.repeat_timeout;
}

static void eap_wps_reset_internal_timeout(struct eap_session* sess)
{
	sess->internal_time = sess->wspd->wsplcConfig.internal_timeout;
}

static void eap_wps_session_timer(void *eloop_ctx, void *timeout_ctx)
{
    struct eap_session* sess= (struct eap_session*)eloop_ctx;

    if (sess->state == WSPLC_EAPOL_START_SENT   && sess->repeat_time >0 )
    {
	sess->repeat_time--;
	if (sess->repeat_time == 0)
	{
	    eap_wps_build_send_eapol_start(sess);
	    eap_wps_reset_repeat_timeout(sess);
	}
    }

    if(sess->state > WSPLC_EAPOL_START_SENT && sess->internal_time >0)
    {
        sess->internal_time --;
        if (sess->internal_time == 0)
        {
		dprintf(MSG_INFO, "Session intenal timeout, close session\n");
		goto failure;
		
        }
    }

    if(sess->walk_time > 0)
    {
        sess->walk_time --;
        if (sess->walk_time == 0)
        {
		dprintf(MSG_INFO, "Session walk timeout, close session\n");
		goto failure;
        }
    }

    eloop_register_timeout(1, 0, 
		eap_wps_session_timer, sess, NULL);	
    return ;
	
failure:
    eap_wps_del_session(sess);
    return;
}


static int eap_wps_check_session_overlap(wsplcd_data_t* wspd)
{
    struct eap_session* sess;
    int wsc_num = 0; 
    sess = wspd->sess_list;
    while (sess)
    {
        if (sess->wsc_flag)
		wsc_num++;
	 sess = sess ->next;
    }

    if (wsc_num >1)
	return 1;
    return 0;	
}

struct eap_session*
eap_wps_new_session(wsplcd_data_t* wspd)
{
    struct eap_session* sess;
    sess = (struct eap_session*)os_zalloc(sizeof(struct eap_session));
    if( !sess)
    {
        dprintf(MSG_ERROR, "Session alloc failure\n");	
        return NULL;
    }
    os_memset(sess, 0, sizeof(struct eap_session));

    sess->state = WSPLC_PUSH_BUTTON_ACTIVATED;
    sess->repeat_time  = wspd->wsplcConfig.repeat_timeout;
    sess->internal_time = wspd->wsplcConfig.internal_timeout;
    sess->walk_time = wspd->wsplcConfig.walk_timeout;
    sess->wspd = wspd;
    sess->prev = NULL;
    sess->next = NULL;
    os_memcpy(sess->own_addr, wspd->own_addr, ETH_ALEN);

    if (eap_wps_init_eapwps_data(sess)) {
        dprintf(MSG_ERROR, "Failed to Allocate EAPWPS data\n");
	 os_free (sess);
        return NULL;
    }
	
    sess->next = wspd->sess_list;
    if (sess->next)
    	sess->next->prev = sess; 
    wspd->sess_list =sess;

    eloop_register_timeout(1, 0, 
		eap_wps_session_timer, sess, NULL);

    dprintf(MSG_INFO, "New AP Cloing Sesstion start\n");	
    return sess;
}


void eap_wps_del_session(struct eap_session* sess)
{
    wsplcd_data_t* wspd;
    wspd = sess->wspd;
    eloop_cancel_timeout(eap_wps_session_timer, sess, NULL); 

    eap_wps_deinit_eapwps_data(sess);

    if (sess == wspd->sess_list)
    {
	wspd->sess_list = sess ->next;
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

    if (wspd->mode == MODE_CLIENT 
		&& wspd->sess_list == NULL
		&& wsplc_is_cloning_runnig(wspd))
    {
	struct eap_session* sess = eap_wps_new_session(wspd);
	if (!sess)
		return;
	eap_wps_start_session(sess);
	
    }	
}

void eap_wps_start_session(struct eap_session* sess)
{
	eap_wps_build_send_eapol_start(sess);
	sess->state = WSPLC_EAPOL_START_SENT;
}

void eap_wps_finish_session(struct eap_session* sess)
{
    /*In hyfi 2.0 wsplcd will restart when wlan parameters changed, the MIB procedure would be broken
    because there are more than one MIB jobs, so here I fork a process to complete the MIB jobs*/
    int pid;

    if (!sess->wsc_msg || sess->state < WSPLC_EAP_RESP_WSC_DONE_SENT)
    {
       dprintf(MSG_ERROR, "Invalid state or WSC MSG, session fails\n");
	return;
    }

    pid = fork();
    if (pid != 0)
    {
        wait(NULL);
        return ;
    }

    if (apc_set_clone_data((unsigned char*)sess->wsc_msg, sess->wsc_len) != 0)
    {
	 dprintf(MSG_ERROR, "Cloning fails\n");
    }
    else
    {
	dprintf(MSG_ERROR, "Cloning success\n");
    }

    exit(0);
}


struct eap_session*
eap_wps_find_session(wsplcd_data_t* wspd, u8 *mac)
{
    struct eap_session* sess;
    sess = wspd->sess_list;
    while (sess)
    {
        if (os_memcmp(sess->dest_addr, mac, ETH_ALEN) == 0)
		break;
	 sess = sess ->next;
    }

    return sess;	
}


int eap_wps_is_new_session(wsplcd_data_t* wspd, u8 *buf, int len)
{
    L2_ETHHDR       *eth_hdr;
    IEEE8021X_HDR   *ieee8021x_hdr;
    EAP_HDR         *eapHdr;
    u8              *eapPayload;	

    eth_hdr = (struct l2_ethhdr *)buf;
    ieee8021x_hdr = (struct ieee802_1x_hdr *)(eth_hdr+1);	

    /*new session:server only accept eapol_start*/
    if (wspd->mode == MODE_SERVER && 
        ieee8021x_hdr->type !=IEEE802_1X_TYPE_EAPOL_START)    
        return 0;

    /*new session:client only accept eap request identity*/
    if(wspd->mode == MODE_CLIENT)
    {

        if (len < sizeof(L2_ETHHDR) + sizeof(IEEE8021X_HDR) + sizeof(EAP_HDR) +1)
            return 0;
        eapHdr=(EAP_HDR*)(ieee8021x_hdr+1);
	 eapPayload = (u8*)(eapHdr+1);
	 if (ieee8021x_hdr->type !=IEEE802_1X_TYPE_EAP_PACKET||
	     eapHdr->code !=EAP_CODE_REQUEST ||
	     *eapPayload != EAP_TYPE_IDENTITY)
	     return 0;	   	
       }

	return 1;
}


static int eap_wps_get_wifi_configuration(
	struct eap_session* sess,
        u8 **buf,       /* output, allocated i.e. buffer */
        size_t *len)    /* output, length of data in buffer */
{
        int ret = -1;
        wsplcd_data_t* wspd = sess->wspd;
        WSPLCD_CONFIG   *pConfig = &wspd->wsplcConfig;
        struct wps_data *wps = 0;

        do {
            if (!buf || !len)
                break;
            *buf = 0;
            *len = 0;

            if (wps_create_wps_data(&wps))
                break;

            /* SSID */
            if (wps_set_value(wps, WPS_TYPE_SSID, pConfig->ssid, pConfig->ssid_len))
                break;

            /* Authentication Type */
            if (wps_set_value(wps, WPS_TYPE_AUTH_TYPE, &pConfig->auth, 0))
                break;

            /* Encryption Type */
            if (wps_set_value(wps, WPS_TYPE_ENCR_TYPE, &pConfig->encr, 0))
                break;

            /* Network Key */
            if (wps_set_value(wps, WPS_TYPE_NW_KEY, pConfig->passphrase, pConfig->passphraseLen)) {
                break;
            }

            do{
                char * apc_buf;
                size_t  apc_len;		
                if (apc_get_clone_data(&apc_buf, &apc_len) == 0)
                {
                    dprintf(MSG_DEBUG, "Get apclonig data len %d\n", apc_len);
    			wps_set_value(wps, WPS_TYPE_ENCR_SETTINGS, apc_buf, apc_len);
    			os_free (apc_buf);
                }
		   
            }while(0);

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

static void eap_wps_parse_wifi_conf(struct eap_session* sess, u8 *buf, size_t len)
{
    struct wps_data *wps = 0;
    u8  ssid[MAX_SSID_LEN], nw_key[MAX_PASSPHRASE_LEN];
    size_t  ssid_len = MAX_SSID_LEN;
    size_t  nw_len = MAX_PASSPHRASE_LEN;
    u16 val;

    do {
        if (wps_create_wps_data(&wps))
            break;

        if (wps_parse_wps_data(buf, len, wps))
            break;

        if (wps_get_value(wps, WPS_TYPE_SSID, ssid, &ssid_len))
            break;

        ssid[ssid_len] = '\0';
        dprintf(MSG_DEBUG, "ssid: %s\n", ssid);

        if (wps_get_value(wps, WPS_TYPE_AUTH_TYPE, &val, 0))
            break;

        dprintf(MSG_DEBUG, "Auth Type: %d\n", val);

        if (wps_get_value(wps, WPS_TYPE_ENCR_TYPE, &val, 0))
            break;

        dprintf(MSG_DEBUG, "Cipher Type: %d\n", val);


        if (wps_get_value(wps, WPS_TYPE_NW_KEY, nw_key, &nw_len))
            break;
        nw_key[nw_len] = '\0';
        dprintf(MSG_DEBUG, "nw key: %s\n", nw_key);

        do{
            char * apc_buf;
            size_t  apc_len;

            apc_buf = os_malloc(len);
            apc_len = len;
            if (apc_buf == NULL)
            {
                break;
            }

            if (wps_get_value(wps, WPS_TYPE_ENCR_SETTINGS, apc_buf, &apc_len))
            {
                os_free (apc_buf);
		   dprintf(MSG_ERROR, "No cloning MSG available\n");		
                break;
            }

	     if (sess->wsc_msg)
		 free (sess->wsc_msg);

            sess->wsc_msg = apc_buf;
	     sess->wsc_len = apc_len;		
          
        }while(0);		

        wps_destroy_wps_data(&wps);
    } while(0);
}


static int eap_wps_generate_sha256hash(u8 *inbuf, int inbuf_len, u8 *outbuf)
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


static int eap_wps_free_dh(void **dh)
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


static int eap_wps_generate_public_key(void **dh_secret, u8 *public_key)
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


static int eap_wps_generate_kdk(struct eap_wps_data *data, u8 *e_nonce, u8 *mac,
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


static int eap_wps_key_derive_func(struct eap_wps_data *data, 
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

static int eap_wps_hmac_validation(struct eap_wps_data *data,
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
            {
                int i=0;
                dprintf(MSG_MSGDUMP, "Computed Authenticator from M2:\n");
                for(;i<SIZE_256_BITS;i++){
                    dprintf(MSG_MSGDUMP, "%02X ", hmac[i]);
                }
                dprintf(MSG_MSGDUMP, "\n");

            }

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

static int eap_wps_encrypt_data(
								u8 *inbuf, int inbuf_len,
								u8 *encrKey,
								u8 *iv, u8 **cipher, int *cipher_len)
{
	int ret = -1;

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


static int eap_wps_decrypt_data(u8 *iv,
								u8 *cipher, int cipher_len,
								u8 *encrKey, u8 **plain, int *plain_len)
{
	int ret = -1;
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

static int eap_wps_encrsettings_creation(
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

	do {
		if (!auth_key || !key_wrap_auth || !encrs || !encrs_len || !buf || !buf_len)
			break;

		*encrs = 0;
		*encrs_len = 0;

        if (wps_create_wps_data(&wps))
            break;
        if (wps_parse_wps_data(buf, buf_len, wps))
            break;

        {
            const u8 *vec[1];
            size_t vlen[1];
            vec[0] = buf;
            vlen[0] = buf_len;
            hmac_sha256_vector(
                    auth_key,
                    SIZE_AUTH_KEY,  /* auth_key size */
                    1,              /* num_elem */
                    vec,
                    vlen,
                    hmac     /* output: 32 bytes */
                    );
        }

		if (wps_set_value(wps, WPS_TYPE_KEY_WRAP_AUTH, hmac, SIZE_64_BITS))
			break;

		if (wps_write_wps_data(wps, &tmp, &length))
			break;

		if (eap_wps_encrypt_data(tmp, length, key_wrap_auth, iv, &cipher, &cipher_len))
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


static int eap_wps_encrsettings_validation(
										   u8 *plain, int plain_len,
										   u8 *auth_key, u8 *key_wrap_auth)
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

		/* Key Wrap Authenticator */
		length = SIZE_8_BYTES;
		if (wps_get_value(wps, WPS_TYPE_KEY_WRAP_AUTH, key_wrap_auth, &length))
			break;

		if (wps_remove_value(wps, WPS_TYPE_KEY_WRAP_AUTH))
			break;

		length = 0;
		if (wps_write_wps_data(wps, &buf, &length))
			break;

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
		if (os_memcmp(hmac, key_wrap_auth, SIZE_64_BITS))
			break;

		ret = 0;
	} while (0);

	(void)wps_destroy_wps_data(&wps);

	if (ret) {
		if (key_wrap_auth)
			os_memset(key_wrap_auth, 0, SIZE_8_BYTES);
	}

    if (buf)
        free(buf);
	return ret;
}

static int eap_wps_clear_target_info(struct eap_wps_data *data)
{
	int ret = -1;
	struct eap_wps_target_info *target;

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

static int eap_wps_oobdevpwd_public_key_hash_validation(const u8 *hashed, const u8 *raw)
{
	int ret = -1;
	u8 src[SIZE_256_BITS];

	do {
		if (!hashed || !raw)
			break;

		if (eap_wps_generate_sha256hash((u8 *)raw, SIZE_PUB_KEY, src))
			break;

		if (os_memcmp(hashed, src, SIZE_20_BYTES))
			break;

		ret = 0;
	} while (0);

	return ret;
}

static int eap_wps_calculate_authenticator(struct eap_wps_data *data,
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
	} while (0);

	return ret;
}

u8 * eap_wps_build_message_M1(struct eap_session* sess,
	size_t *msg_len)
{
	u8 *msg = 0;

	EAP_WPS_DATA *data = sess->eapWpsData;
	struct wps_data *wps = 0;
	u8 u8val;
	size_t length;

	do {
		if (!msg_len)
			break;

		if (wps_create_wps_data(&wps))
			break;

		u8val = WPS_VERSION;
		if (wps_set_value(wps, WPS_TYPE_VERSION, &u8val, 0))
			break;

		/* Message Type */
		u8val = WPS_MSGTYPE_M1;
		if (wps_set_value(wps, WPS_TYPE_MSG_TYPE, &u8val, 0))
			break;

#if 0
		/* UUID-E */
		if (!conf->uuid_set)
			break;
		if (wps_set_value(wps, WPS_TYPE_UUID_E, conf->uuid, sizeof(conf->uuid)))
			break;
#endif
		/* MAC Address */
		if (wps_set_value(wps, WPS_TYPE_MAC_ADDR, sess->wspd->own_addr, ETH_ALEN))
			break;

		/* Enrollee Nonce */
		RAND_bytes(data->nonce, sizeof(data->nonce));
		if (wps_set_value(wps, WPS_TYPE_ENROLLEE_NONCE, data->nonce, sizeof(data->nonce)))
			break;

		/* Public Key */
		if (!data->preset_pubKey) {
			if (data->dh_secret)
				eap_wps_free_dh(&data->dh_secret);
			if (eap_wps_generate_public_key(&data->dh_secret, data->pubKey))
				break;
		}
		if (wps_set_value(wps, WPS_TYPE_PUBLIC_KEY, data->pubKey, sizeof(data->pubKey)))
			break;

#if 0
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

                #if 0   /* This breaks some stations and is not necessary */
                /* Atheros Extensions */
                if (wps_config_add_atheros_wps_ext(hapd, wps))
                        break;
                #endif
#endif
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

static u8 * eap_wps_build_message_M2(struct eap_session* sess,
		size_t *msg_len)
{
	u8 *msg = 0;
	struct eap_wps_data *data = sess->eapWpsData;
	struct eap_wps_target_info *target;
	struct wps_data *wps = 0;
	u8 kdk[SIZE_256_BITS];
	u8 keys[KDF_OUTPUT_SIZE];
	u8 authenticator[SIZE_8_BYTES];
	u8 *configData, *encrs = NULL;
	u8 u8val;
	size_t length, configDataLen, encrs_len = 0;

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

#if 0
		/* UUID-R */
		if (!conf->uuid_set)
			break;
		if (wps_set_value(wps, WPS_TYPE_UUID_R, conf->uuid, sizeof(conf->uuid)))
			break;
#endif
		/* Public Key */
		if (!data->preset_pubKey) {
			if (data->dh_secret)
				eap_wps_free_dh(&data->dh_secret);
			if (eap_wps_generate_public_key(&data->dh_secret, data->pubKey))
				break;
		}
		if (wps_set_value(wps, WPS_TYPE_PUBLIC_KEY, data->pubKey, sizeof(data->pubKey)))
			break;

#if 0
		/* M2/M2D common data */
		if (eap_wps_config_build_message_M2_M2D(hapd, conf, data, wps))
			break;

		/* Device Password ID */
		if (wps_set_value(wps, WPS_TYPE_DEVICE_PWD_ID, &data->dev_pwd_id, 0))
			break;

		/* OS Version */
		if (wps_set_value(wps, WPS_TYPE_OS_VERSION, &conf->os_version, 0))
			break;
#endif

		/* Generate KDK */
		if (eap_wps_generate_kdk(data, target->nonce, target->mac, data->nonce, kdk))
			break;

		dprintf(MSG_DEBUG, "KDK Success\n");

		/* Key Derivation Function */
		if (eap_wps_key_derive_func(data, kdk, keys))
			break;
		os_memcpy(data->authKey, keys, SIZE_256_BITS);
		os_memcpy(data->keyWrapKey, keys + SIZE_256_BITS, SIZE_128_BITS);
		os_memcpy(data->emsk, keys + SIZE_256_BITS + SIZE_128_BITS, SIZE_256_BITS);
                /* last 16 bytes are unused */

        {
            int i=0;
            dprintf(MSG_MSGDUMP, "KeyWrapKey:\n");
            for(;i<SIZE_128_BITS;i++){
                dprintf(MSG_MSGDUMP, "%02X ", data->keyWrapKey[i]);
            }
            dprintf(MSG_MSGDUMP, "\n");
            dprintf(MSG_MSGDUMP, "AuthKey:\n");
            for(;i<SIZE_256_BITS;i++){
                dprintf(MSG_MSGDUMP, "%02X ", data->authKey[i]);
            }
            dprintf(MSG_MSGDUMP, "\n");
        }

        if (eap_wps_get_wifi_configuration(sess, &configData, &configDataLen)) {
            dprintf(MSG_ERROR, "Failed to get WiFi configuration\n");
            break;
        }

        /* Create Encrypted settings */
        if (eap_wps_encrsettings_creation(configData, configDataLen,
            data->authKey, data->keyWrapKey, &encrs, &encrs_len))
            break;

        /* Encrypted Settings */
        if (wps_set_value(wps, WPS_TYPE_ENCR_SETTINGS, encrs, encrs_len))
            break;

        /* Release ConfigData & encr memories */
        os_free(configData);
        os_free(encrs);

		/* Authenticator */
		length = 0;
		if (wps_write_wps_data(wps, &msg, &length))
			break;

		if (eap_wps_calculate_authenticator(data, msg, length,
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
#if 0
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
#endif
	} while (0);

	(void)wps_destroy_wps_data(&wps);

	return msg;
}

int eap_wps_build_send_eap_req_resp(struct eap_session* sess, u8 eapCode, u8 eapType,
	u8 eapXtop_code, u8 flags,  u8 *payload, int payloadlen)
{
    L2_ETHHDR       *eth_hdr;
    IEEE8021X_HDR   *ieee8021x_hdr;
    EAP_HDR         *eapHdr;
    EAP_FORMAT      *eap_fmt;
    u8              *buf, *eapPayload;
    int             frlen, extraPayloadlen, eaplen;
    int             ret,i;
    int             status =0;

	
    extraPayloadlen = (eapType != EAP_TYPE_EXPANDED) ? 1 : sizeof(*eap_fmt);
    eaplen = sizeof(*eapHdr) + extraPayloadlen + payloadlen;
    frlen = sizeof(*eth_hdr) + sizeof(*ieee8021x_hdr) + eaplen;

    buf = os_malloc(frlen);

    if (buf == NULL) {
        dprintf(MSG_ERROR, "Failed to alloc memory\n");
        return 1;
    }

    memset(buf, 0, frlen);

    // Fill the Ethernet Header
    eth_hdr = (L2_ETHHDR*)buf;
    memcpy(eth_hdr->h_dest, sess->dest_addr, ETH_ALEN);
    memcpy(eth_hdr->h_source, sess->own_addr, ETH_ALEN);
    eth_hdr->h_proto = htons(ETH_P_EAPOL);


    ieee8021x_hdr = (IEEE8021X_HDR*)(eth_hdr+1);
    ieee8021x_hdr->version = EAPOL_VERSION;
    ieee8021x_hdr->type = IEEE802_1X_TYPE_EAP_PACKET;
    ieee8021x_hdr->length = htons(eaplen);

    // Fill the EAP Hdr
    eapHdr = (EAP_HDR*)(ieee8021x_hdr+1);
    eapHdr->code = eapCode;
    eapHdr->identifier = (eapCode == EAP_CODE_REQUEST) ? sess->eapIdNum++ : sess->rxeapIdNum;
    eapHdr->length = htons(eaplen);

    // Fill the EAP Payload
    if (eapType != EAP_TYPE_EXPANDED) {
        eapPayload = ((u8*)(eapHdr+1));
        *eapPayload++ = eapType;
    } else {
        eap_fmt = (EAP_FORMAT*)(eapHdr+1);
        eap_fmt->type = EAP_TYPE_EXPANDED;
        os_memcpy(eap_fmt->vendor_id, EAP_VENDOR_ID_WPS, sizeof(eap_fmt->vendor_id));
        os_memcpy(eap_fmt->vendor_type, EAP_VENDOR_TYPE_WPS, sizeof(eap_fmt->vendor_type));
        eap_fmt->op_code = eapXtop_code;
        eap_fmt->flags = flags;
        eapPayload = (u8*)(eap_fmt+1);
    }

    os_memcpy(eapPayload, payload, payloadlen);

    // Now send the pkt
    ret = send(sess->wspd->txSkt, buf, frlen, 0);
    if (ret < 0) {
        dprintf(MSG_ERROR, "EAP send failure");
        status = 1;
    }

    dprintf(MSG_INFO, "EAP Pkt Sent Successfully with length %d\n", frlen);

    for (i=0; i < frlen; i++){
        dprintf(MSG_MSGDUMP, "%02X ", buf[i]);
        if (((i+1) % 16) == 0){
            dprintf(MSG_MSGDUMP, "\n");
        }
    }
    dprintf(MSG_MSGDUMP, "\n");

    // Free memory
    free(buf);

    return status;
}

int eap_wps_build_send_eap_req_resp_frags(struct eap_session* sess, u8 eapCode, u8 eapType,
	u8 eapXtop_code,  u8 flags, u8 *payload, int payloadlen)
{
    
    int  status =0;
    int i;	
    u8  fragFlags;
    u8*  fragPos;
    int fragLen;
    int maxEapLoad = 1500 - 
		sizeof(L2_ETHHDR) - 
		sizeof(IEEE8021X_HDR) -
		sizeof(EAP_HDR) -
		sizeof(EAP_FORMAT);
    int fragNum = (payloadlen +maxEapLoad - 1)/maxEapLoad;

    if (fragNum > 1)
	dprintf(MSG_DEBUG, "Sent fragmentation %d, maxload %d payload %d\n", fragNum, maxEapLoad, payloadlen);
	
    for (i=0; i<fragNum; i++)
    {
        fragFlags = flags;
        fragPos = payload + i * maxEapLoad;
        if ( i  != fragNum -1)
        {
            fragLen = 	maxEapLoad;
            fragFlags |= EAP_FLAG_MF;
        }
        else
        {
            fragLen = payloadlen % maxEapLoad;
            if (fragLen == 0 && payloadlen != 0)
                fragLen = maxEapLoad;
        }
	  status =   eap_wps_build_send_eap_req_resp(sess, eapCode, eapType,
            eapXtop_code, fragFlags, fragPos, fragLen);
	  if (status)
	      break;
    }
  
  
    return status;
}

int eap_wps_build_send_eapol_start(struct eap_session* sess)
{
    L2_ETHHDR       *eth_hdr;
    IEEE8021X_HDR   *ieee8021x_hdr;
    u8              *buf;
    int             frlen;
    int             ret;
    int             status =0;

    frlen = sizeof(*eth_hdr) + sizeof(*ieee8021x_hdr);
	
    buf = malloc(frlen);
    if (buf == NULL) {
        dprintf(MSG_ERROR, "Failed to alloc mem for EAPOL Start\n");
        return 1;
    }

    // Fill the Ethernet Header
    eth_hdr = (struct l2_ethhdr *)buf;
    memcpy(eth_hdr->h_dest, mcast_dest, ETH_ALEN);
    memcpy(eth_hdr->h_source, sess->own_addr, ETH_ALEN);
    eth_hdr->h_proto = htons(ETH_P_EAPOL);

    // Fill the EAPOL Header
    ieee8021x_hdr = (struct ieee802_1x_hdr *)(eth_hdr+1);
    ieee8021x_hdr->version = EAPOL_VERSION;
    ieee8021x_hdr->type = IEEE802_1X_TYPE_EAPOL_START;
    ieee8021x_hdr->length = 0;

    // Now send the EAPOL pkt
    ret = send(sess->wspd->txSkt, buf, frlen, 0);
    if (ret < 0) {
        dprintf(MSG_ERROR, "EAPOL send failure");
        status = 1;
    }

    dprintf(MSG_DEBUG, "EAPOL Start Sent Successfully with length %d\n", frlen);

    // Free memory
    free(buf);

    return status;
}

int eap_wps_build_send_eapfail(struct eap_session* sess)
{
    L2_ETHHDR       *eth_hdr;
    IEEE8021X_HDR   *ieee8021x_hdr;
    EAP_HDR         *eapHdr;
    u8              *buf;
    int             frlen;
    int             ret;
    int             status =0;


    frlen = sizeof(*eth_hdr) + sizeof(*ieee8021x_hdr) + sizeof(*eapHdr);

    buf = malloc(frlen);
    if (buf == NULL) {
        dprintf(MSG_ERROR, "Failed to alloc mem for EAPFail\n");
        return 1;
    }

    // Fill the Ethernet Header
    eth_hdr = (struct l2_ethhdr *)buf;
    memcpy(eth_hdr->h_dest, sess->dest_addr, ETH_ALEN);
    memcpy(eth_hdr->h_source, sess->own_addr, ETH_ALEN);
    eth_hdr->h_proto = htons(ETH_P_EAPOL);

	
    // Fill the EAPOL Header
    ieee8021x_hdr = (struct ieee802_1x_hdr *)(eth_hdr+1);
    ieee8021x_hdr->version = EAPOL_VERSION;
    ieee8021x_hdr->type = IEEE802_1X_TYPE_EAP_PACKET;
    ieee8021x_hdr->length = htons(sizeof(*eapHdr));

    // Fill the EAP Hdr
    eapHdr = (EAP_HDR*)(ieee8021x_hdr+1);
    eapHdr->code = EAP_CODE_FAILURE;
    eapHdr->identifier = sess->eapIdNum++;
    eapHdr->length = htons(sizeof(*eapHdr));

    // Now send the EAPOL pkt
    ret = send(sess->wspd->txSkt, buf, frlen, 0);
    if (ret < 0) {
        dprintf(MSG_ERROR, "EAP Fail send failure");
        status = 1;
    }

    dprintf(MSG_INFO, "EAP Fail Sent Successfully with length %d\n", frlen);

    // Free memory
    free(buf);

    return status;
}

int eap_wps_process_message_M1(struct eap_session* sess, u8 *rcvMsg, int rcvMsgLen)
{
	int ret = -1;
	struct wps_data *wps = 0;
	u8 msg_type;

	struct eap_wps_data *data = sess->eapWpsData;
	struct eap_wps_target_info *target;
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
		eap_wps_clear_target_info(data);

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
			if (eap_wps_oobdevpwd_public_key_hash_validation(data->pubKey, target->pubKey))
				break;

			os_memset(data->pubKey, 0, sizeof(data->pubKey));
			data->preset_pubKey = 0;
		}
        dprintf(MSG_DEBUG, "Parsed Pub Key\n");
#if 0
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

		/* Association State */
		if (wps_get_value(wps, WPS_TYPE_ASSOC_STATE, &target->assoc_state, 0))
			break;

		/* Configuration Error */
		if (wps_get_value(wps, WPS_TYPE_CONFIG_ERROR, &target->config_error, 0))
			break;

		/* OS Version */
		if (wps_get_value(wps, WPS_TYPE_OS_VERSION, &target->os_version, 0))
			break;
#endif
		ret = 0;
	} while (0);

	if (ret)
		eap_wps_clear_target_info(data);

	(void)wps_destroy_wps_data(&wps);

	return ret;
}

int eap_wps_process_message_M2(struct eap_session* sess, u8* rcvMsg, int rcvMsgLen)
{
	int ret = -1;
	wsplcd_data_t* wspd = sess->wspd;
	struct eap_wps_data *data = sess->eapWpsData;
	struct eap_wps_target_info *target;
	struct wps_data *wps = 0;
	u8 msg_type;
	u8 kdk[SIZE_256_BITS];
	u8 keys[KDF_OUTPUT_SIZE];
	u8 tmp[SIZE_64_BYTES];
	size_t length;
	u8 authenticator[SIZE_8_BYTES];

    dprintf(MSG_DEBUG, "Process M2 with len = %d\n", rcvMsgLen);

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
		if (wps_create_wps_data(&wps))
			break;

		if (wps_parse_wps_data(rcvMsg, rcvMsgLen, wps))
			break;
        dprintf(MSG_DEBUG, "Successfully parsed WPS M2-data\n");

		/* Version */
		if (wps_get_value(wps, WPS_TYPE_VERSION, &target->version, 0))
			break;

		/* Message Type */
		if (wps_get_value(wps, WPS_TYPE_MSG_TYPE, &msg_type, 0))
			break;
		if (msg_type != WPS_MSGTYPE_M2)
			break;
        dprintf(MSG_DEBUG, "WPS_MSG_TYPE = %04X\n", msg_type);

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
#if 0
		/* Device Password ID */
		if (wps_get_value(wps, WPS_TYPE_DEVICE_PWD_ID, &target->dev_pwd_id, 0))
			break;
#endif

		/* Authenticator */
		length = sizeof(authenticator);
		if (wps_get_value(wps, WPS_TYPE_AUTHENTICATOR, authenticator, &length))
			break;

		/* Generate KDK */
		if (eap_wps_generate_kdk(data, data->nonce, wspd->own_addr, target->nonce, kdk))
			break;

		/* Key Derivation Function */
		if (eap_wps_key_derive_func(data, kdk, keys))
			break;
		os_memcpy(data->authKey, keys, SIZE_256_BITS);
		os_memcpy(data->keyWrapKey, keys + SIZE_256_BITS, SIZE_128_BITS);
		os_memcpy(data->emsk, keys + SIZE_256_BITS + SIZE_128_BITS, SIZE_256_BITS);
                /* last 16 bytes are unused */
        {
            int i=0;
            dprintf(MSG_MSGDUMP, "KeyWrapKey:\n");
            for(;i<SIZE_128_BITS;i++){
                dprintf(MSG_MSGDUMP, "%02X ", data->keyWrapKey[i]);
            }
            dprintf(MSG_MSGDUMP, "\n");
            dprintf(MSG_MSGDUMP, "AuthKey:\n");
            for(;i<SIZE_256_BITS;i++){
                dprintf(MSG_MSGDUMP, "%02X ", data->authKey[i]);
            }
            dprintf(MSG_MSGDUMP, "\n");
        }

		/* HMAC validation */
		if (eap_wps_hmac_validation(data, authenticator, data->authKey)) {
			dprintf(MSG_ERROR, "Authenticator validation failed in M2\n");
			break;
        } else {
            dprintf(MSG_INFO, "Authenticator validated in M2\n");
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
				if (!encrs)
					break;
				if (wps_get_value(wps, WPS_TYPE_ENCR_SETTINGS, encrs, &length))
					break;

				iv = encrs;
				cipher = encrs + SIZE_128_BITS;
				cipher_len = length - SIZE_128_BITS;
				if (eap_wps_decrypt_data(iv, cipher, cipher_len, data->keyWrapKey, &config, &config_len))
					break;
                if (eap_wps_encrsettings_validation(config, config_len, data->authKey, data->keyWrapKey))
                    break;

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
                    eap_wps_parse_wifi_conf(sess, config, config_len);
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
			if (fail)
				break;
		}

		ret = 0;
	} while (0);

	(void)wps_destroy_wps_data(&wps);

	return ret;
}


void eap_wps_process_identity_enrollee(struct eap_session* sess, u8* eapPkt, int pktLen)
{
    int status;
    char identity[256];	

    /*skip type */
    eapPkt ++;		
    if ( sess->state != WSPLC_EAPOL_START_SENT && sess->state != WSPLC_PUSH_BUTTON_ACTIVATED)
    {
        dprintf(MSG_INFO, "Invalid status  %d for eap_identity\n", sess->state);
        return ;
    }
	
    snprintf(identity, pktLen < sizeof (identity)? pktLen:sizeof (identity), "%s", eapPkt);
    identity[sizeof (identity)-1] = '\0'; 	
    dprintf(MSG_INFO, "Peer EAP Identity:%s\n" , identity);

    if (os_memcmp(eapPkt, WSPLC_EAP_ID_SERVER_STRING, os_strlen(WSPLC_EAP_ID_SERVER_STRING) )
		!=0 )
    {
        dprintf(MSG_INFO, "Invalid EAP Identity\n" );    
        eap_wps_del_session(sess);
        return ;	
    }
    else
    {
        sess->wsc_flag = 1;
        if (eap_wps_check_session_overlap(sess->wspd))
        {
            dprintf(MSG_WARNING, "Session Overlap\n" );
            wsplc_stop_cloning(sess->wspd);
            return;
        }
    
    }
    
    status = eap_wps_build_send_eap_req_resp(sess,	
		EAP_CODE_RESPONSE, EAP_TYPE_IDENTITY, 0, 0,
    		(u8*)WSPLC_EAP_ID_CLIENT_STRING, 
    		os_strlen(WSPLC_EAP_ID_CLIENT_STRING));
    if(!status) {
        sess->state = WSPLC_EAP_RESP_ID_SENT;
        dprintf(MSG_WARNING, "EAP Resp ID Sent success, state = %d\n", sess->state);
    }

}


void eap_wps_process_identity_registrar(struct eap_session* sess, u8* eapPkt, int pktLen)
{
    int status;
    char identity[256];

    eapPkt ++;	
    if ( sess->state != WSPLC_EAP_REQ_ID_SENT)
    {
        dprintf(MSG_INFO, "Invalid status  %d for eap_identity\n", sess->state);
        return ;
    }
    snprintf(identity, pktLen < sizeof (identity)? pktLen:sizeof (identity), "%s", eapPkt);
    identity[sizeof (identity)-1] = '\0'; 	
    dprintf(MSG_INFO, "Peer EAP Identity:%s\n" , identity);	
	
    if (os_memcmp(eapPkt, WSPLC_EAP_ID_CLIENT_STRING, os_strlen(WSPLC_EAP_ID_CLIENT_STRING) )
		!=0 )
    {
        dprintf(MSG_INFO, "Invalid EAP Identity\n" );
        eap_wps_del_session(sess);
        return;	
    }
    
    else if (sess->wspd->wsplcConfig.button_mode == WSPLC_ONE_BUTTON)
    {
        sess->wsc_flag = 1;
        if (eap_wps_check_session_overlap(sess->wspd))
        {
            dprintf(MSG_WARNING, "Session Overlap\n" );
            wsplc_stop_cloning(sess->wspd);
            return;
        }
        
    }	
    
    status = eap_wps_build_send_eap_req_resp(sess, 
		EAP_CODE_REQUEST, EAP_TYPE_EXPANDED, 
		EAP_OPCODE_WPS_START, 0,
    		NULL, 0);
    if(!status) {
        sess->state = WSPLC_EAP_REQ_WSC_START_SENT;
        dprintf(MSG_WARNING, "EAP Req WSC_START Sent success, state = %d\n", sess->state);
    }
}

void eap_wps_process_eapexp(struct eap_session* sess, u8* eapPkt, int pktLen)
{
    u8              *msg;
    size_t          msg_len = 0;
    struct eap_format *eap_fmt;
    u8 *raw;
    u16 len;
    EAP_WPS_DATA *data = sess->eapWpsData;	
    //reassembly
    eap_fmt = (struct eap_format *)eapPkt;
    raw = (u8 *)(eap_fmt + 1);
    len = pktLen - sizeof(*eap_fmt);

    if (data->fragment) {
        data->fragment = 0;
        data->rcvMsg = (u8 *)os_realloc(data->rcvMsg, data->rcvMsgLen + len);
        if (data->rcvMsg) {
            os_memcpy(data->rcvMsg + data->rcvMsgLen, raw, len);
            data->rcvMsgLen += len;
        }
    } else {
        if (data->rcvMsg)
            os_free(data->rcvMsg);
        data->rcvMsg = os_malloc(len);
        if (data->rcvMsg) {
            os_memcpy(data->rcvMsg, raw, len);
            data->rcvMsgLen = len;
        }
    }
    
    if (!data->rcvMsg) {
        data->rcvMsgLen = 0;
        dprintf(MSG_ERROR, "Receive memory allocation error\n");		
        return;
    }
    
    if (eap_fmt->flags & EAP_FLAG_MF) {
        data->fragment = 1;
        dprintf(MSG_INFO, "Receive EAP fragmentation\n");			
        return;
    }

    switch(eap_fmt->op_code) {
    case EAP_OPCODE_WPS_START:
        dprintf(MSG_INFO, "Rcvd WPS_START\n");
        if (sess->state != WSPLC_EAP_RESP_ID_SENT) {
            dprintf(MSG_WARNING, "WSPLC State = %d Invalid to Gen M1\n", sess->state);
            break;
        }
        // Generate M1
        msg = eap_wps_build_message_M1(sess, &msg_len);
        if (!msg || !msg_len) {
            dprintf(MSG_ERROR, "Failed to build M1\n");
            break;
        }
        eap_wps_build_send_eap_req_resp_frags(sess, EAP_CODE_RESPONSE, EAP_TYPE_EXPANDED,
            EAP_OPCODE_WPS_MSG, 0, msg, msg_len);
        sess->state = WSPLC_EAP_RESP_M1_SENT;
        // free wps data memory
        os_free(msg);
        dprintf(MSG_DEBUG, "Sent M1\n");
        break;

    case EAP_OPCODE_WPS_MSG:
        dprintf(MSG_INFO, "Rcvd WPS_MSG\n");
        switch (sess->wspd->mode) { 
        case MODE_SERVER:
            if (sess->state != WSPLC_EAP_REQ_WSC_START_SENT) {
                dprintf(MSG_WARNING, "WSPLC Mode = %d, State = %d Invalid to Gen M2\n",
                    sess->wspd->mode, sess->state);
                break;
            }
            // Process M1
            eap_wps_process_message_M1(sess, data->rcvMsg, data->rcvMsgLen);
            // Generate M2
            msg = eap_wps_build_message_M2(sess, &msg_len);
            if (!msg || !msg_len) {
                dprintf(MSG_ERROR, "Failed to build M2\n");
                break;
            }
            // Send M2
            eap_wps_build_send_eap_req_resp_frags(sess, EAP_CODE_REQUEST, EAP_TYPE_EXPANDED,
                EAP_OPCODE_WPS_MSG, 0, msg, msg_len);
            sess->state = WSPLC_EAP_REQ_M2_SENT;
            // free wps data memory
            os_free(msg);
            dprintf(MSG_DEBUG, "Sent M2\n");
            break;

        case MODE_CLIENT:
            if (sess->state != WSPLC_EAP_RESP_M1_SENT) {
                dprintf(MSG_WARNING, "WSPLC Mode = %d, State = %d Invalid to Process M2\n",
                    sess->wspd->mode, sess->state);
                break;
            }
            // Process M2
            eap_wps_process_message_M2(sess, data->rcvMsg, data->rcvMsgLen);
            // Generate WPS_DONE
            // Send WPS_DONE
            eap_wps_build_send_eap_req_resp(sess, EAP_CODE_RESPONSE, EAP_TYPE_EXPANDED,
                EAP_OPCODE_WPS_DONE, 0, NULL, 0);
            sess->state = WSPLC_EAP_RESP_WSC_DONE_SENT;
            printf("Sent WPS_DONE\n");
            break;

        default:
            dprintf(MSG_WARNING, "Invalid mode = %d when rcvd WPS_MSG\n", sess->wspd->mode);
        }
        break;

    case EAP_OPCODE_WPS_DONE:
        dprintf(MSG_INFO, "Rcvd WPS_DONE\n");
        if (sess->state != WSPLC_EAP_REQ_M2_SENT) {
            dprintf(MSG_WARNING, "WSPLC State = %d Invalid to Process WPS_DONE\n", sess->state);
            break;
        }
        // Send EAP_FAIL
        eap_wps_build_send_eapfail(sess);
	 eap_wps_del_session(sess);	
        wsplc_stop_cloning(sess->wspd);		
	
		
        break;

    case EAP_OPCODE_WPS_NACK:
        break;

    case EAP_OPCODE_WPS_ACK:
    case EAP_OPCODE_WPS_FLAG_ACK:
        break;

    default:
        dprintf(MSG_WARNING, "Unhandled EAP_OPCODE: %d\n", eap_fmt->op_code);
        break;
    }

}

void eap_wps_process_eap(struct eap_session* sess, u8* eapPkt, int eapPktlen, u8* fromaddr)
{
    EAP_HDR         *eapHdr;
    u8              *eapPayload;
    int               eapPayloadLen;	
    eapHdr = (EAP_HDR*)eapPkt;
   

    if (eapPktlen != ntohs(eapHdr->length)){
        dprintf(MSG_WARNING, "EAP pkt len mismatch.Inputlen = %d, LenFromHdr = %d\n", eapPktlen, ntohs(eapHdr->length));
        return;
    }

    sess->rxeapIdNum = eapHdr->identifier;
    eapPayload = (u8*)(eapHdr+1);
    eapPayloadLen =  ntohs(eapHdr->length) - sizeof(EAP_HDR);

	
    dprintf(MSG_DEBUG, "Rcvd EAP Code = %d with EAP Type = %d Len = %d\n", eapHdr->code, *eapPayload, ntohs(eapHdr->length));

    switch(eapHdr->code) {
    case EAP_CODE_REQUEST:
        if (sess->wspd->mode != MODE_CLIENT)
        {
        	 dprintf(MSG_INFO, "Receive EAP Request, invalid mode\n");
        	 break ;
        }		
        switch(*eapPayload) {
        case EAP_TYPE_IDENTITY:
             eap_wps_process_identity_enrollee(sess, eapPayload, eapPayloadLen);
		break;

        case EAP_TYPE_EXPANDED:
            // Process Expanded EAP Type pkt
            eap_wps_process_eapexp(sess, eapPayload, eapPayloadLen);
            break;

        default:
            dprintf(MSG_WARNING, "Can't handle EAP Type = %d\n", *eapPayload);
            break;
        }
        break;

    case EAP_CODE_RESPONSE:
        if (sess->wspd->mode != MODE_SERVER)
        {
        	 dprintf(MSG_INFO, "Receive EAP Response, invalid mode\n");
        	 break ;
        }			
        switch(*eapPayload) {
        case EAP_TYPE_IDENTITY:
            eap_wps_process_identity_registrar(sess, eapPayload, eapPayloadLen);
            break;
        
        case EAP_TYPE_EXPANDED:
            // Process Expanded EAP Type pkt
            eap_wps_process_eapexp(sess, eapPayload, eapPayloadLen);
            break;
        
        default:
            dprintf(MSG_WARNING, "Can't handle EAP Type = %d\n", *eapPayload);
            break;
        }
        break;

        break;

    case EAP_CODE_SUCCESS:
        dprintf(MSG_INFO, "EAP SUCCESS is not handled in this protocol\n");
        break;

    case EAP_CODE_FAILURE:
        // End of protocol handshake
        dprintf(MSG_INFO, "Received EAP FAIL. Protocol handshake completed\n");
        eap_wps_finish_session(sess);
	 if (sess->state == WSPLC_EAP_RESP_WSC_DONE_SENT)
	 	wsplc_stop_cloning(sess->wspd);
	 else
	 	eap_wps_del_session(sess);
        break;
    default:
        dprintf(MSG_INFO, "Invalid EAP Pkt with EAP Code %d\n", eapHdr->code);
    }
}

void eap_wps_process_eapol(wsplcd_data_t* wspd, u8 *buf, int len)
{
    L2_ETHHDR       *eth_hdr;
    IEEE8021X_HDR   *ieee8021x_hdr;
    int status;
    struct eap_session* sess;
    int ismcast = 0;

    eth_hdr = (struct l2_ethhdr *)buf;
    ieee8021x_hdr = (struct ieee802_1x_hdr *)(eth_hdr+1);
    if (ntohs(eth_hdr->h_proto) == ETH_P_EAPOL) {
        dprintf(MSG_DEBUG, "Rcvd EAPOL pkt from %02X-%02X-%02X-%02X-%02X-%02X\n",
               eth_hdr->h_source[0], eth_hdr->h_source[1], eth_hdr->h_source[2],
               eth_hdr->h_source[3], eth_hdr->h_source[4], eth_hdr->h_source[5]);
    }
    else
    {
	dprintf(MSG_INFO, "Invalid protocol type = %d\n", eth_hdr->h_proto);
	return ;
    }

    if (os_memcmp(mcast_dest, eth_hdr->h_dest, ETH_ALEN) == 0) 
        ismcast = 1;
    if (!ismcast && os_memcmp(wspd->own_addr, eth_hdr->h_dest, ETH_ALEN) != 0)
    {
        dprintf(MSG_DEBUG, "Not my packet, discard\n");
        return;
    }
    if (ismcast && wspd->mode != MODE_SERVER)
    {
        dprintf(MSG_DEBUG, "Client can't aceept mcast packet, discard\n");
        return;
    }
	
    sess = eap_wps_find_session(wspd, eth_hdr->h_source);
    if ( wspd->clone_running == 0 && !sess)
    {

	 dprintf(MSG_DEBUG, "AP cloning disabled, new session not allowed\n");
        return ;
    }

    if (sess)
    {
        if (ieee8021x_hdr->type == IEEE802_1X_TYPE_EAPOL_START)
        {
            dprintf(MSG_DEBUG, "New AP cloning session detected, previous sesion may have broken\n");
            return;
        }
    }

    else
    {
        u8 null_mac[6] = {0x0,0x0,0x0,0x0,0x0,0x0};
        if (!eap_wps_is_new_session(wspd,buf, len))
    	 {
            dprintf(MSG_INFO, "Stale packet received, discard\n");
	      return ;
    	 }
        /* terminate the eapol_start session*/
        sess =  eap_wps_find_session(wspd, null_mac);
        if (!sess)
            sess = eap_wps_new_session(wspd);
        if (!sess)
            return;
    }
    os_memcpy(sess->dest_addr,eth_hdr->h_source , ETH_ALEN);
	
    if (sess->state >= WSPLC_PUSH_BUTTON_ACTIVATED) {
        dprintf(MSG_DEBUG, " With Type = %d\n", ieee8021x_hdr->type);
        switch (ieee8021x_hdr->type) {
        case IEEE802_1X_TYPE_EAPOL_START: 
            if (sess->wspd->mode != MODE_SERVER ||
		  sess->state != WSPLC_PUSH_BUTTON_ACTIVATED)
            	{
            	  dprintf(MSG_INFO, "Invalid mode or state for eapol_start %d \n", sess->state);
	         return ;
            	}

            // Send EAP-Req ID Pkt
            status = 
            eap_wps_build_send_eap_req_resp(sess, EAP_CODE_REQUEST, EAP_TYPE_IDENTITY, 0, 0,
                (u8*)WSPLC_EAP_ID_SERVER_STRING, strlen(WSPLC_EAP_ID_SERVER_STRING));
            if (!status) {
                // EAP-Req ID pkt sent successfully change state
                sess->state = WSPLC_EAP_REQ_ID_SENT;
            }
            break;
        case IEEE802_1X_TYPE_EAP_PACKET:
            eap_wps_reset_internal_timeout(sess);	
            eap_wps_process_eap(sess, (u8*)(ieee8021x_hdr+1), 
                ntohs(ieee8021x_hdr->length), 
                eth_hdr->h_source);
		
            break;

        default:
            dprintf(MSG_WARNING, "Unknow EAPOL Type %d\n", ieee8021x_hdr->type);
            break;
        }
    } 
	
    return;
}



