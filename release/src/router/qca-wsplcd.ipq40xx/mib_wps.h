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
#ifndef _MIB_WPS_H
#define _MIB_WPS_H


/*
APCLONE TYPE for WPS:
	0x0000-0x00ff: reserved for other non-WLAN parameters
	0x0100-0x01ff: RADIO
	0x0200-0x02ff: BSS
	0x0300-        : reserved
	low byte of RADIO and BSS  used as index 
*/
#define APCLONE_TYPE_MASK              0xff00


#define APCLONE_TYPE_RADIO		0x0100
#define APCLONE_TYPE_BSS			0x0200


#define RADIO_TYPE_CHANNEL			0x0001
#define RADIO_TYPE_RADIOENABLED		0x0002
#define RADIO_TYPE_POWERLEVEL		0x0003
#define RADIO_TYPE_RXCHAINMASK		0x0004
#define RADIO_TYPE_TXCHAINMASK		0x0005
#define RADIO_TYPE_TBRLIMIT			0x0006
#define RADIO_TYPE_AMPDUENABLED		0x0007
#define RADIO_TYPE_AMPDULIMIT			0x0008
#define RADIO_TYPE_AMPDUFRAMES		0x0009



#define BSS_TYPE_ENABLE					0x0001
#define BSS_TYPE_RADIOINDEX				0x0002
#define BSS_TYPE_SSID						0x0003
#define BSS_TYPE_BEACONTYPE				0x0004
#define BSS_TYPE_STANDARD					0x0005
#define BSS_TYPE_WEPKEYINDEX				0x0006
#define BSS_TYPE_KEYPASSPHRASE			0x0007
#define BSS_TYPE_BASIC_ENCRYPTIONMODE	0x0008
#define BSS_TYPE_BASIC_AUTHMODE			0x0009
#define BSS_TYPE_WPA_ENCRYPTIONMODE		0x000A
#define BSS_TYPE_WPA_AUTHMODE			0x000B
#define BSS_TYPE_11I_ENCRYPTIONMODE		0x000C
#define BSS_TYPE_11I_AUTHMODE				0x000D
#define BSS_TYPE_WAPI_AUTHMODE			0x000E
#define BSS_TYPE_WAPI_PSKTYPE				0x000F
#define BSS_TYPE_WAPI_PREAUTH			0x0010
#define BSS_TYPE_WAPI_PSK					0x0011
#define BSS_TYPE_WAPI_CERTCONTENT		0x0012
#define BSS_TYPE_WAPI_CERTINDEX			0x0013
#define BSS_TYPE_WAPI_CERTSTATUS			0x0014
#define BSS_TYPE_WAPI_CERTMODE			0x0015
#define BSS_TYPE_WAPI_ASUADDRESS			0x0016
#define BSS_TYPE_WAPI_ASUPORT			0x0017
#define BSS_TYPE_WAPI_UCASTREKEYTIME		0x0018
#define BSS_TYPE_WAPI_UCASTREKEYPACKET		0x001A
#define BSS_TYPE_WAPI_MCASTREKEYTIME		0x001B
#define BSS_TYPE_WAPI_MCASTREKEYPACKET		0x001C
#define BSS_TYPE_BASIC_DATA_TXRATES			0x001D
#define BSS_TYPE_RTS							0x001E
#define BSS_TYPE_FRAGMENTATION				0x001F
#define BSS_TYPE_AUTH_SERVICE_MODE			0x0020
#define BSS_TYPE_EAP_REAUTH_PERIOD			0x0021
#define BSS_TYPE_WEP_REKEY_PERIOD			0x0022
#define BSS_TYPE_AUTH_SERVER_ADDR			0x0023
#define BSS_TYPE_AUTH_SERVER_PORT			0x0024
#define BSS_TYPE_AUTH_SERVER_SECRET			0x0025
#define BSS_TYPE_RSN_PREAUTH					0x0026
#define BSS_TYPE_SSID_HIDE						0x0027
#define BSS_TYPE_APMODULE_ENABLE				0x0028
#define BSS_TYPE_WPS_PIN						0x0029
#define BSS_TYPE_WPS_CONFIGURED				0x002A
#define BSS_TYPE_SHORT_GI						0x002B
#define BSS_TYPE_CWM_ENABLE					0x002C
#define BSS_TYPE_WMM							0x002D
#define BSS_TYPE_HT40COEXIST					0x002E
#define BSS_TYPE_HBRENABLE					0x002F
#define BSS_TYPE_HBRPERLOW					0x0030
#define BSS_TYPE_HBRPERHIGH					0x0031
#define BSS_TYPE_MEMODE						0x0032
#define BSS_TYPE_MELENGTH						0x0033
#define BSS_TYPE_METIMER						0x0034
#define BSS_TYPE_METIMEOUT					0x0035
#define BSS_TYPE_MEDROPMCAST					0x0036
#define BSS_TYPE_WEPKEY_1						0x0037
#define BSS_TYPE_WEPKEY_2						0x0038
#define BSS_TYPE_WEPKEY_3						0x0039
#define BSS_TYPE_WEPKEY_4						0x003A
#define BSS_TYPE_DEV_OPMODE					0x003B
#define BSS_TYPE_GROUP_REKEY_PERIOD			0x003C
#define BSS_TYPE_PRESHARED_KEY				0x003D


/*Enum currently handled as string, but may be optimized as interger int the future*/
#define WPS_VALTYPE_ENUM WPS_VALTYPE_PTR


typedef struct mib_session_t{
    const char * mib_path;
    struct wps_data* mib_data;;
    const struct mib_param_set * mib_sets;
}mib_session;


struct mib_param_set {
	char		*name;
	u16		type;
	u16		value_type;
};

extern const struct mib_param_set clone_param_sets[];
extern const struct mib_param_set radio_param_sets[];
extern const struct mib_param_set bss_param_sets[];
struct wps_credential;

int mib_get_tlv(const struct mib_param_set *mibset, const char *value,  struct wps_tlv **tlv);
int mib_parse_value(const struct mib_param_set *mibset, const char *buf, size_t length, char **value);
int mib_get_object(char * path, struct wps_data *data, const struct mib_param_set * mibsets);
int mib_set_object(char * path, struct wps_data *data, const struct mib_param_set * mibsets);
int mib_del_object(const char * const mibpath);
int mib_add_object(const char * const mibpath);
int mib_update_credential(struct wps_credential* cred);
#endif

