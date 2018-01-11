/**************************************************************************
//
//  Copyright (c) 2006-2007 Sony Corporation. All Rights Reserved.
//
//  File Name: eap_wps.h
//  Description: EAP-WPS header file
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

#ifndef EAP_WPS_H
#define EAP_WPS_H



#include "wps_config.h"

#include "crypto.h"
#include "sha256.h"
#include "os.h"
#include "wsplcd.h"
/* openssl provides RAND_bytes; os_get_random is equivalent */
#define RAND_bytes(buf,n) os_get_random(buf,n)

#ifdef _MSC_VER
#pragma pack(push, 1)
#endif /* _MSC_VER */

struct eap_wps_target_info {
	u8		version;
	u8		uuid[SIZE_UUID];
	int		uuid_set;

	u8		mac[SIZE_MAC_ADDR];
	int		mac_set;

	u16		auth_type_flags;
	u16		encr_type_flags;
	u8		conn_type_flags;
	u16		config_methods;
	u8		wps_state;
	char		*manufacturer;
	size_t	manufacturer_len;
	char		*model_name;
	size_t	model_name_len;
	char		*model_number;
	size_t	model_number_len;
	char		*serial_number;
	size_t	serial_number_len;
	u8		prim_dev_type[SIZE_8_BYTES];
	char		*dev_name;
	size_t	dev_name_len;
	u8		rf_bands;
	u8		cur_rf_band;
	u16		assoc_state;
	u16		config_error;
	u32		os_version;

	u8		nonce[SIZE_NONCE];
	u8		pubKey[SIZE_PUB_KEY];
	int		pubKey_set;
	u16		dev_pwd_id;
	u8		hash1[SIZE_WPS_HASH];
	u8		hash2[SIZE_WPS_HASH];

	u8		*config;
	size_t	config_len;
};

/* eap_wps_data is data for one WPS session.
 */
struct eap_wps_data {
	enum STATE {START, M1, M2, M2D1, M2D2, M3, M4, M5, M6, M7, M8, DONE, ACK, NACK, FAILURE} state;
	enum STATE prev_enrollee_state;
	enum STATE prev_registrar_state;
        /* interface is what role WE are playing */
	enum {NONE, REGISTRAR, ENROLLEE} interface;

        /* rcvMsg is last message we receive from station via wifi */
	u8		*rcvMsg;
	u32		rcvMsgLen;
	Boolean	fragment;

        /* sndMsg is last message we built OR proxy from external registrar,
         * and send to station via wifi.
         */
	u8		*sndMsg;        
	u32		sndMsgLen;

	u16		dev_pwd_id;
	u8		dev_pwd[SIZE_64_BYTES];
	u16		dev_pwd_len;

	u16		assoc_state;
	u16		config_error;

	u8		nonce[SIZE_NONCE];
	u8		pubKey[SIZE_PUB_KEY];
	int		preset_pubKey;

	void	*dh_secret;

	u8		authKey[SIZE_AUTH_KEY];
	u8		keyWrapKey[SIZE_KEY_WRAP_KEY];
	u8		emsk[SIZE_EMSK];

	u8		snonce1[SIZE_NONCE];
	u8		snonce2[SIZE_NONCE];
	u8		psk1[SIZE_128_BITS];
	u8		psk2[SIZE_128_BITS];
	u8		hash1[SIZE_WPS_HASH];
	u8		hash2[SIZE_WPS_HASH];

    enum wps_config_who config_who;
	int             is_push_button;
    int             autoconfig;     /* nonzero if we invent configuration*/
	u8		*config;
	size_t	config_len;

	struct eap_wps_target_info *target;
};

const static u8 DH_P_VALUE[SIZE_1536_BITS] = 
{
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xC9, 0x0F, 0xDA, 0xA2, 0x21, 0x68, 0xC2, 0x34,
    0xC4, 0xC6, 0x62, 0x8B, 0x80, 0xDC, 0x1C, 0xD1,
    0x29, 0x02, 0x4E, 0x08, 0x8A, 0x67, 0xCC, 0x74,
    0x02, 0x0B, 0xBE, 0xA6, 0x3B, 0x13, 0x9B, 0x22,
    0x51, 0x4A, 0x08, 0x79, 0x8E, 0x34, 0x04, 0xDD,
    0xEF, 0x95, 0x19, 0xB3, 0xCD, 0x3A, 0x43, 0x1B,
    0x30, 0x2B, 0x0A, 0x6D, 0xF2, 0x5F, 0x14, 0x37,
    0x4F, 0xE1, 0x35, 0x6D, 0x6D, 0x51, 0xC2, 0x45,
    0xE4, 0x85, 0xB5, 0x76, 0x62, 0x5E, 0x7E, 0xC6,
    0xF4, 0x4C, 0x42, 0xE9, 0xA6, 0x37, 0xED, 0x6B,
    0x0B, 0xFF, 0x5C, 0xB6, 0xF4, 0x06, 0xB7, 0xED,
    0xEE, 0x38, 0x6B, 0xFB, 0x5A, 0x89, 0x9F, 0xA5,
    0xAE, 0x9F, 0x24, 0x11, 0x7C, 0x4B, 0x1F, 0xE6,
    0x49, 0x28, 0x66, 0x51, 0xEC, 0xE4, 0x5B, 0x3D,
    0xC2, 0x00, 0x7C, 0xB8, 0xA1, 0x63, 0xBF, 0x05,
    0x98, 0xDA, 0x48, 0x36, 0x1C, 0x55, 0xD3, 0x9A,
    0x69, 0x16, 0x3F, 0xA8, 0xFD, 0x24, 0xCF, 0x5F,
    0x83, 0x65, 0x5D, 0x23, 0xDC, 0xA3, 0xAD, 0x96,
    0x1C, 0x62, 0xF3, 0x56, 0x20, 0x85, 0x52, 0xBB,
    0x9E, 0xD5, 0x29, 0x07, 0x70, 0x96, 0x96, 0x6D,
    0x67, 0x0C, 0x35, 0x4E, 0x4A, 0xBC, 0x98, 0x04,
    0xF1, 0x74, 0x6C, 0x08, 0xCA, 0x23, 0x73, 0x27,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
};


const static u8 DH_G_VALUE[] = { 2 };

struct eap_format {
	u8 type;
	u8 vendor_id[3];
	u8 vendor_type[4];
	u8 op_code;
	u8 flags;
};

#ifdef _MSC_VER
#pragma pack(pop)
#endif /* _MSC_VER */

/* As a security measure, lock the AP after too many failures
 * (could be someone trying to guess the PIN!).
 * Recover will require restarting hostapd or using RECONFIGURE command.
 */
#define EAP_WPS_FAILURE_LIMIT   20


#define EAP_OPCODE_WPS_START	0x01
#define EAP_OPCODE_WPS_ACK		0x02
#define EAP_OPCODE_WPS_NACK		0x03
#define EAP_OPCODE_WPS_MSG		0x04
#define EAP_OPCODE_WPS_DONE		0x05
#define EAP_OPCODE_WPS_FLAG_ACK	0x06

#define EAP_FLAG_MF	            0x01
#define EAP_FLAG_LF	            0x02

#define EAP_VENDOR_ID_WPS	    "\x00\x37\x2a"
#define EAP_VENDOR_TYPE_WPS	    "\x00\x00\x00\x01"

/* Polling period */
#define EAP_WPS_PERIOD_SEC		1
#define EAP_WPS_PERIOD_USEC		0
/* Default timeout period after which session expires */
#define EAP_WPS_TIMEOUT_SEC		120
#define EAP_WPS_TIMEOUT_USEC	0

/* Message retry period and count.
 * WPS spec reccommends 5 second retransmit time with overall limit
 * of 15 seconds; my experience is that a shorter retransmit time
 * works well.
 */
#define EAP_WPS_RETRANS_SECONDS 3
#define EAP_WPS_MAX_RETRANS     5

#define WPS_LED_OFF             1
#define WPS_LED_ON              2
#define WPS_LED_BLINK           3

#define WSPLC_EAP_ID_CLIENT_STRING  "WSPLC-Client-1-0"
#define WSPLC_EAP_ID_SERVER_STRING  "WSPLC-Server-1-0"

// State Machine States for server and client modes
enum {
    WSPLC_INITIALIZED,
    WSPLC_PUSH_BUTTON_ACTIVATED,
    WSPLC_EAPOL_START_SENT,
    WSPLC_EAP_REQ_ID_SENT,
    WSPLC_EAP_RESP_ID_SENT,
    WSPLC_EAP_REQ_WSC_START_SENT,
    WSPLC_EAP_RESP_M1_SENT,
    WSPLC_EAP_REQ_M2_SENT,
    WSPLC_EAP_RESP_WSC_DONE_SENT,
    WSPLC_EAP_FAIL_SENT
};

typedef struct eap_wps_data EAP_WPS_DATA;

struct eap_session{
    struct eap_session *prev;
    struct eap_session *next;
    u32    state;
    u32    walk_time;
    u32    repeat_time;
    u32    internal_time;
    u8      own_addr[ETH_ALEN];	
    u8      dest_addr[ETH_ALEN];	
    u8      eapIdNum;
    u8      rxeapIdNum;

    EAP_WPS_DATA    *eapWpsData;	
/*Session overlap
    Overlap could be found while Register received Identity response
    or Enrollee received  Identity request.
    Only after then, both know each other's actor. 
*/
    int      wsc_flag;
    char* wsc_msg;
    int     wsc_len;
    wsplcd_data_t* wspd;	

};

void eap_wps_process_eapol(wsplcd_data_t* wspd, u8 *buf, int len);
struct eap_session* eap_wps_new_session(wsplcd_data_t* wspd);
void eap_wps_del_session(struct eap_session* sess);
void eap_wps_start_session(struct eap_session* sess);
void eap_wps_finish_session(struct eap_session* sess);
struct eap_session* eap_wps_find_session(wsplcd_data_t* wspd, u8 *mac);

#endif /* EAP_WPS_H */
