/*
 * Copyright (C) 2014, Broadcom Corporation
 * All Rights Reserved.
 * 
 * This is UNPUBLISHED PROPRIETARY SOURCE CODE of Broadcom Corporation;
 * the contents of this file may not be disclosed to third parties, copied
 * or duplicated in any form, in whole or in part, without the prior
 * written permission of Broadcom Corporation.
 *
 * $Id:$
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <time.h>
#include <ctype.h>
#include "epivers.h"
#include "trace.h"
#include "dsp.h"
#include "wlu_api.h"
#include "bcm_gas.h"
#include "bcm_encode_ie.h"
#include "bcm_encode_anqp.h"
#include "bcm_encode_hspot_anqp.h"
#include "bcm_encode_wnm.h"
#include "bcm_encode_qos.h"
#include "bcm_decode_anqp.h"
#include "bcm_decode_hspot_anqp.h"
#include "bcm_decode_ie.h"
#include "tcp_srv.h"
#include "proto/bcmeth.h"
#include "proto/bcmevent.h"
#include "proto/802.11.h"
#include <bcmnvram.h>
#include <shutils.h>

/* Hspotap Flags */
#define HSFLG_NEXT_2			0x00008000	/* Bit 16 -  0 */
#define HSFLG_NEXT_1			0x00004000	/* Bit 15 -  0 */
#define HSFLG_DS_ANQP_RESP		0X00002000	/* Bit 14 -  0 */
#define HSFLG_USE_SIM			0x00001000	/* Bit 13 -  0 */
#define HSFLG_ICMPV4_ECHO		0x00000800	/* Bit 12 -  1 */
#define HSFLG_L2_TRF			0x00000400	/* Bit 11 -  1 */
#define HSFLG_DGAF_DS			0x00000200	/* Bit 10 -  0 */
#define HSFLG_OSEN			0x00000100	/* Bit 09 -  0 */
#define HSFLG_P2P_CRS			0x00000080	/* Bit 08 -  0 */
#define HSFLG_P2P			0x00000040	/* Bit 07 -  1 */
#define HSFLG_MIH			0x00000020	/* Bit 06 -  0 */
#define HSFLG_ANQP			0x00000010	/* Bit 05 -  1 */
#define HSFLG_IWINT_EN			0x00000008	/* Bit 04 -  0 */
#define HSFLG_IW_EN			0x00000004	/* Bit 03 -  1 */
#define HSFLG_U11_EN			0x00000002	/* Bit 02 -  1 */
#define HSFLG_HS_EN			0x00000001	/* Bit 01 -  1 */

#define BUILT_IN_FILTER

#ifndef min
#define min(a, b)	(((a) < (b)) ? (a) : (b))
#endif

#define MAX_NVPARSE				16

#define MIH_PROTOCOL_ID			1
#define NATI_UNSPECIFIED		-1

/* enable testing mode */
#define TESTING_MODE			0

/* home realm */
#define HOME_REALM "example.com"

#define URL	"https://tandc-server.wi-fi.org"

#define OSU_SERVER_URI "https://osu-server.r2-testbed.wi-fi.org/"

#define WIFI_VENUE "Wi-Fi Alliance\n2989 Copper Road\nSanta Clara, CA 95051, USA"

#define ENGLISH_FRIENDLY_NAME "Wi-Fi Alliance"
#define CHINESE_FRIENDLY_NAME "\x57\x69\x2d\x46\x69\xe8\x81\x94\xe7\x9b\x9f"

#define HESSID_DEFAULT "50:6F:9A:00:11:22"

/* Realm List */
#define REALMLIST_ID1 "mail.example.com+0+21=2,4#5,7?"\
			"cisco.com+0+21=2,4#5,7?"\
			"wi-fi.org+0+21=2,4#5,7;13=5,6?"\
			"example.com+0+13=5,6"

#define REALMLIST_ID1_SIM "cisco.com+0+21=2,4#5,7?"\
			"wi-fi.org+0+21=2,4#5,7;13=5,6?"\
			"example.com+0+13=5,6?"\
			"mail.example.com+0+18=5,2"

#define REALMLIST_ID2 "wi-fi.org+0+21=2,4#5,7"

#define REALMLIST_ID3 "cisco.com+0+21=2,4#5,7?"\
			"wi-fi.org+0+21=2,4#5,7;13=5,6?"\
			"example.com+0+13=5,6"

#define REALMLIST_ID4 "mail.example.com+0+21=2,4#5,7;13=5,6"

#define REALMLIST_ID5 "wi-fi.org+0+21=2,4#5,7?"\
			"ruckuswireless.com+0+21=2,4#5,7"

#define REALMLIST_ID6 "wi-fi.org+0+21=2,4#5,7?"\
			"mail.example.com+0+21=2,4#5,7"

#define REALMLIST_ID7 "wi-fi.org+0+13=5,6;21=2,4#5,7"

/* local buffer size */
#define BUFFER_SIZE				256
#define BUFFER_SIZE1			(4 * 1024)
#define BUFFER_SIZE2			512
#define NVRAM_MAX_VAL_LEN		(2 * 1024)
#define BUFF_PRINTGASEVENT		64
#define CODE_BUFF				20

#define MAX_OSU_PROVIDERS		4

/* query request buffer size */
#define QUERY_REQUEST_BUFFER	(64 * 1024)

/* Proxy ARP for WNM bit mask */
#define WNM_DEFAULT_BITMASK		(WL_WNM_BSSTRANS | WL_WNM_NOTIF)

#define KOREAN				"kor"
#define SPANISH				"spa"
#define LANG_ZXX			"zxx"
#define ENGLISH				"eng"
#define CHINESE				"chi"

#define ENG_OPNAME_SP_RED			"SP Red Test Only"
#define ENG_OPNAME_SP_BLUE			"SP Blue Test Only"
#define ENG_OPNAME_SP_GREEN			"SP Green Test Only"
#define ENG_OPNAME_SP_ORANGE		"SP Orange Test Only"
#define ENG_OPNAME_WBA				"Wireless Broadband Alliance"

#define ICON_FILENAME_RED_ZXX		"icon_red_zxx.png"
#define ICON_FILENAME_GREEN_ZXX		"icon_green_zxx.png"
#define ICON_FILENAME_BLUE_ZXX		"icon_blue_zxx.png"
#define ICON_FILENAME_ORANGE_ZXX	"icon_orange_zxx.png"
#define ICON_FILENAME_RED			"icon_red_eng.png"
#define ICON_FILENAME_GREEN			"icon_green_eng.png"
#define ICON_FILENAME_BLUE			"icon_blue_eng.png"
#define ICON_FILENAME_ORANGE		"icon_orange_eng.png"
#define ICON_FILENAME_ABGN			"wifi-abgn-logo_270x73.png"

#define ICON_TYPE_ID1				"image/png"
#define OSU_SERVICE_DESC_ID1		"Free service for test purpose"

#define OSU_NAI_TEST_WIFI			"test-anonymous@wi-fi.org"
#define OSU_NAI_ANON_HS				"anonymous@hotspot.net"

#define MAIL				"mail.example.com"
#define CISCO				"cisco.com"
#define WIFI				"wi-fi.org"
#define RUCKUS				"ruckuswireless.com"
#define EXAMPLE4			"example.com"

#define ICONPATH			"/bin/"

uint8 chinese_venue_name[] =
	{0x57, 0x69, 0x2d, 0x46, 0x69, 0xe8, 0x81, 0x94,
	0xe7, 0x9b, 0x9f, 0xe5, 0xae, 0x9e, 0xe9, 0xaa,
	0x8c, 0xe5, 0xae, 0xa4, 0x0a, 0xe4, 0xba, 0x8c,
	0xe4, 0xb9, 0x9d, 0xe5, 0x85, 0xab, 0xe4, 0xb9,
	0x9d, 0xe5, 0xb9, 0xb4, 0xe5, 0xba, 0x93, 0xe6,
	0x9f, 0x8f, 0xe8, 0xb7, 0xaf, 0x0a, 0xe5, 0x9c,
	0xa3, 0xe5, 0x85, 0x8b, 0xe6, 0x8b, 0x89, 0xe6,
	0x8b, 0x89, 0x2c, 0x20, 0xe5, 0x8a, 0xa0, 0xe5,
	0x88, 0xa9, 0xe7, 0xa6, 0x8f, 0xe5, 0xb0, 0xbc,
	0xe4, 0xba, 0x9a, 0x39, 0x35, 0x30, 0x35, 0x31,
	0x2c, 0x20, 0xe7, 0xbe, 0x8e, 0xe5, 0x9b, 0xbd};

uint8 kor_opname_sp_red[] =
	{0x53, 0x50, 0x20, 0xEB, 0xB9, 0xA8, 0xEA, 0xB0,
	0x95, 0x20, 0xED, 0x85, 0x8C, 0xEC, 0x8A, 0xA4,
	0xED, 0x8A, 0xB8, 0x20, 0xEC, 0xA0, 0x84, 0xEC,
	0x9A, 0xA9};

uint8 kor_opname_sp_blu[] =
	{0x53, 0x50, 0x20, 0xED, 0x8C, 0x8C, 0xEB, 0x9E,
	0x91, 0x20, 0xED, 0x85, 0x8C, 0xEC, 0x8A, 0xA4,
	0xED, 0x8A, 0xB8, 0x20, 0xEC, 0xA0, 0x84, 0xEC,
	0x9A, 0xA9};

uint8 kor_opname_sp_grn[] =
	{0x53, 0x50, 0x20, 0xEC, 0xB4, 0x88, 0xEB, 0xA1,
	0x9D, 0x20, 0xED, 0x85, 0x8C, 0xEC, 0x8A, 0xA4,
	0xED, 0x8A, 0xB8, 0x20, 0xEC, 0xA0, 0x84, 0xEC,
	0x9A, 0xA9};

uint8 kor_opname_sp_orng[] =
	{0x53, 0x50, 0x20, 0xEC, 0x98, 0xA4, 0xEB, 0xA0,
	0x8C, 0xEC, 0xA7, 0x80, 0x20, 0xED, 0x85, 0x8C,
	0xEC, 0x8A, 0xA4, 0xED, 0x8A, 0xB8, 0x20, 0xEC,
	0xA0, 0x84, 0xEC, 0x9A, 0xA9};

uint8 kor_opname_wba[] =
	{0xEC, 0x99, 0x80, 0xEC, 0x9D, 0xB4, 0xEC, 0x96,
	0xB4, 0xEB, 0xA6, 0xAC, 0xEC, 0x8A, 0xA4, 0x20,
	0xEB, 0xB8, 0x8C, 0xEB, 0xA1, 0x9C, 0xEB, 0x93,
	0x9C, 0xEB, 0xB0, 0xB4, 0xEB, 0x93, 0x9C, 0x20,
	0xEC, 0x96, 0xBC, 0xEB, 0x9D, 0xBC, 0xEC, 0x9D,
	0xB4, 0xEC, 0x96, 0xB8, 0xEC, 0x8A, 0xA4};

uint8 kor_desc_name_id1[] =
	{0xED, 0x85, 0x8C, 0xEC, 0x8A, 0xA4, 0xED, 0x8A,
	0xB8, 0x20, 0xEB, 0xAA, 0xA9, 0xEC, 0xA0, 0x81,
	0xEC, 0x9C, 0xBC, 0xEB, 0xA1, 0x9C, 0x20, 0xEB,
	0xAC, 0xB4, 0xEB, 0xA3, 0x8C, 0x20, 0xEC, 0x84,
	0x9C, 0xEB, 0xB9, 0x84, 0xEC, 0x8A, 0xA4};


typedef struct {
	uint32 pktflag;
	int ieLength;
	uint8 ieData[VNDR_IE_MAX_LEN];
} vendorIeT;

typedef struct
{
	/* wl interface */
	void *ifr;

	/* wl prefix */
	char prefix[MAX_NVPARSE];

	/* dialog token */
	uint8 dialogToken;

	/* Passpoint Vendor IE */
	vendorIeT vendorIeHSI;

	/* P2P vendor IE */
	vendorIeT vendorIeP2P;

	/* for testing */
	int gas_cb_delay;
	int isGasPauseForServerResponse;
	int testResponseSize;

	/* BSS transition request */
	uint8 *url;				/* session information URL */
	uint8 url_len;			/* session information URL length */
	uint8 req_token;

	uint8 qos_id;
	uint8 bssload_id;

	/* Passpoint vendor IE flag */
	bool hs_ie_enabled;

	/* Interworking Info */
	bool iw_enabled;
	bool iw_isInternet;
	uint8 iw_ANT;
	bool iw_isHESSIDPresent;
	struct ether_addr iw_HESSID;

	/* Venue List */
	bcm_decode_anqp_venue_name_t venuelist;

	/* Network Authentication List */
	bcm_decode_anqp_network_authentication_type_t netauthlist;

	/* Roaming Consortium List */
	bcm_decode_anqp_roaming_consortium_t ouilist;

	/* IP Address Type Availability */
	bcm_decode_anqp_ip_type_t ipaddrAvail;

	/* NAI Realm List ID */
	bcm_decode_anqp_nai_realm_list_t realmlist;

	/* 3GPP Cellular Info List */
	bcm_decode_anqp_3gpp_cellular_network_t gpp3list;

	/* Domain Name List */
	bcm_decode_anqp_domain_name_list_t domainlist;

	/* Operating Class */
	bcm_decode_hspot_anqp_operating_class_indication_t opclass;

	/* Operator Friendly Name List */
	bcm_decode_hspot_anqp_operator_friendly_name_t oplist;

	/* OSU Provider List Info */
	bcm_decode_hspot_anqp_osu_provider_list_t osuplist;
	int osuicon_id;

	/* Annonymous NAI */
	bcm_decode_hspot_anqp_anonymous_nai_t anonai;

	/* WAN Metrics */
	bcm_decode_hspot_anqp_wan_metrics_t wanmetrics;

	/* Connection Capability ID */
	int conn_id;

	/* NAI Home Realm Query List */
	bcm_decode_hspot_anqp_nai_home_realm_query_t homeqlist;

	/* Passpoint Capability */
	int hs_capable;

} hspotApT;

static hspotApT *hspotaps[MAX_WLIF_NUM];
static int hspotap_num = 0;
static hspotApT *current_hspotap = NULL;

/* tcp server for remote control */
static int tcpServerEnabled = 0;
static int tcpServerPort;

static int update_iw_ie(hspotApT *hspotap, bool disable);
static int update_rc_ie(hspotApT *hspotap);
static int update_ap_ie(hspotApT *hspotap);
static int update_qosmap_ie(hspotApT *hspotap, bool enable);
static int update_osen_ie(hspotApT *hspotap, bool disable);
static int update_bssload_ie(hspotApT *hspotap, bool isStatic, bool enable);

/* --------------------------------------------------------------- */
/* Functions to Load & Save Complex NVRAMs */

/* static unsigned long long getTimestamp(void) */
/* { */
/*	unsigned long long ts; */
/*	struct timeval now; */
/*	gettimeofday(&now, NULL); */
/*	ts = (unsigned long long)now.tv_sec * 1000 + now.tv_usec / 1000; */
/*	return ts; */
/* } */

char* strncpy_n(char *destination, const char *source, size_t num)
{
	char* ret = strncpy(destination, source, num - 1);
	destination[num - 1] = '\0';
	return ret;
}

void BytestoHex(uchar* str, int strbuflen, uchar* utf8, int utf8buflen)
{
	char temp[3];
	uchar *src = str, *dst = utf8;
	int len = strlen((char*)src), i, optlen;
	optlen = len < (utf8buflen-1) ? len : (utf8buflen-1);

	for (i = 0; i < optlen; i++)
	{
		memset(temp, 0, sizeof(temp));
		snprintf(temp, sizeof(temp), "%02X", (uchar)src[i]);
		*dst++ = temp[0];
		*dst++ = temp[1];
	}
}

void HextoBytes(uchar* str, int strbuflen, uchar* utf8, int utf8buflen)
{
	char temp[3];
	uchar *src = utf8, *dst = str;
	int len = strlen((char*)src)/2, i, optlen;
	optlen = len < strbuflen ? len : strbuflen;

	for (i = 0; i < optlen; i++)
	{
		memset(temp, 0, sizeof(temp));
		temp[0] = src[0];
		temp[1] = src[1];
		temp[2] = '\0';
		*dst++ = (uchar) strtoul(temp, NULL, 16);
		src += 2;
	}
}

int Get_hspot_flag(char *prefix, unsigned int flagName)
{
	char varname[NVRAM_MAX_PARAM_LEN] = {0};
	char *ptr;
	int flag = -1;
	int value = 0;

	ptr = nvram_get(strcat_r(prefix, "hsflag", varname));

	if (ptr) {
		value = atoi(ptr);
		flag = value & flagName;
	}
	else {
		/* printf("\n%s is not defined in NVRAM\n", varname); */
		return flag;
	}
	return (flag ? 1 : 0);
}

int Set_hspot_flag(char *prefix, unsigned int flagName, bool enable)
{
	char varname[NVRAM_MAX_PARAM_LEN] = {0};
	char varvalue[NVRAM_MAX_VALUE_LEN] = {0};
	char *ptr;
	int err = 0, ret;
	int value = 0;

	ptr = nvram_get(strcat_r(prefix, "hsflag", varname));

	if (ptr) {
		value = atoi(ptr);

		if (enable) {
			value |= flagName;
		}
		else {
			value &= (~flagName);
		}
		snprintf(varvalue, sizeof(varvalue), "%d", value);
		ret = nvram_set(strcat_r(prefix, "hsflag", varname), varvalue);
		if (ret) {
			/* printf("nvram_set %s=%s failure\n", varname, varvalue); */
			err = -1;
		}
		nvram_commit();
	}
	else {
		/* printf("\n%s is not defined in NVRAM\n", varname); */
		err = -1;
	}

	return err;
}

int Reset_hspot_flag(char *prefix, bool bInit)
{
	int ret, err = 0;
	char varname[NVRAM_MAX_PARAM_LEN];
	char varvalue[NVRAM_MAX_VALUE_LEN];

	if (!bInit)
	{
		ret = nvram_unset(strcat_r(prefix, "hsflag", varname));
		if (ret) {
			/* printf("nvram_unset %s failure\n", varname); */
			err = -1;
		}
	}
	else
	{
		ret = nvram_set(strcat_r(prefix, "hs2en", varname), "0");
		if (ret) {
			/* printf("nvram_set %s=%s failure\n", varname, varvalue); */
			err = -1;
		}
		ret = nvram_set(strcat_r(prefix, "u11en", varname), "0");
		if (ret) {
			/* printf("nvram_set %s=%s failure\n", varname, varvalue); */
			err = -1;
		}
		snprintf(varvalue, sizeof(varvalue), "%d", HSFLG_HS_EN | HSFLG_U11_EN |
			HSFLG_IW_EN |HSFLG_ANQP | HSFLG_P2P | HSFLG_L2_TRF | HSFLG_ICMPV4_ECHO);
		ret = nvram_set(strcat_r(prefix, "hsflag", varname), varvalue);
		if (ret) {
			/* printf("nvram_set %s=%s failure\n", varname, varvalue); */
			err = -1;
		}
	}
	nvram_commit();
	return err;
}


static int
get_hex_data(uchar *data_str, uchar *hex_data, int len)
{
	uchar *src, *dest;
	uchar val;
	int idx;
	char hexstr[3];

	src = data_str;
	dest = hex_data;

	for (idx = 0; idx < len; idx++) {
		hexstr[0] = src[0];
		hexstr[1] = src[1];
		hexstr[2] = '\0';

		val = (uchar) strtoul(hexstr, NULL, 16);

		*dest++ = val;
		src += 2;
	}

	return 0;
}

static bool strToEther(char *str, struct ether_addr *bssid)
{
	int hex[ETHER_ADDR_LEN];
	int i;

	if (sscanf(str, "%02x:%02x:%02x:%02x:%02x:%02x",
		&hex[0], &hex[1], &hex[2], &hex[3], &hex[4], &hex[5]) != 6)
		return FALSE;

	for (i = 0; i < ETHER_ADDR_LEN; i++)
		bssid->octet[i] = hex[i];

	return TRUE;
}

int Reset_OUIList(hspotApT *hspotap, bool bInit)
{
	int ret, err = 0;
	char varname[NVRAM_MAX_PARAM_LEN];
	memset(&hspotap->ouilist, 0, sizeof(bcm_decode_anqp_roaming_consortium_t));

	if (!bInit)
	{
		ret = nvram_unset(strcat_r(hspotap->prefix, "ouilist", varname));
		if (ret) {
			/* printf("nvram_unset %s failure\n", varname); */
			err = -1;
		}
	}
	else
	{
		hspotap->ouilist.numOi = 2;
		memcpy(hspotap->ouilist.oi[0].oi, WFA_OUI, strlen(WFA_OUI));
		hspotap->ouilist.oi[0].oiLen = strlen(WFA_OUI);
		hspotap->ouilist.oi[1].oi[0] = 0x00;
		hspotap->ouilist.oi[1].oi[1] = 0x1B;
		hspotap->ouilist.oi[1].oi[2] = 0xC5;
		hspotap->ouilist.oi[1].oi[3] = 0x04;
		hspotap->ouilist.oi[1].oi[4] = 0xBD;
		hspotap->ouilist.oi[1].oiLen = 5;
		hspotap->ouilist.isDecodeValid = TRUE;

		ret = nvram_set(strcat_r(hspotap->prefix, "ouilist", varname), "506F9A;001BC504BD");
		if (ret) {
			/* printf("nvram_set %s=%s failure\n", varname, "506F9A;001BC504BD"); */
			err = -1;
		}
	}

	nvram_commit();
	return err;
}

int Reset_3GPPList(hspotApT *hspotap, bool bInit)
{
	int ret, err = 0;
	char varname[NVRAM_MAX_PARAM_LEN];
	memset(&hspotap->gpp3list, 0, sizeof(bcm_decode_anqp_3gpp_cellular_network_t));

	if (!bInit)
	{
		ret = nvram_unset(strcat_r(hspotap->prefix, "3gpplist", varname));
		if (ret) {
			/* printf("nvram_unset %s failure\n", varname); */
			err = -1;
		}
	}
	else
	{
		hspotap->gpp3list.isDecodeValid = TRUE;
		ret = nvram_set(strcat_r(hspotap->prefix, "3gpplist", varname), "");
		if (ret) {
			/* printf("nvram_set %s=%s failure\n", varname, ""); */
			err = -1;
		}
	}

	nvram_commit();
	return err;
}

int Reset_DomainList(hspotApT *hspotap, bool bInit)
{
	int ret, err = 0;
	char varname[NVRAM_MAX_PARAM_LEN];
	memset(&hspotap->domainlist, 0, sizeof(bcm_decode_anqp_domain_name_list_t));

	if (!bInit)
	{
		ret = nvram_unset(strcat_r(hspotap->prefix, "domainlist", varname));
		if (ret) {
			/* printf("nvram_unset %s failure\n", varname); */
			err = -1;
		}
	}
	else
	{
		hspotap->domainlist.isDecodeValid = TRUE;
		ret = nvram_set(strcat_r(hspotap->prefix, "domainlist", varname), "");
		if (ret) {
			/* printf("nvram_set %s=%s failure\n", varname, ""); */
			err = -1;
		}
	}

	nvram_commit();
	return err;
}

int Reset_VenueList(hspotApT *hspotap, bool bInit, unsigned int flag)
{
	int ret, err = 0;
	char varname[NVRAM_MAX_PARAM_LEN];

	if (!bInit)
	{
		memset(&hspotap->venuelist, 0, sizeof(bcm_decode_anqp_venue_name_t));
		if (flag & 0x0001) {
			ret = nvram_unset(strcat_r(hspotap->prefix, "venuetype", varname));
			if (ret) {
				/* printf("nvram_unset %s failure\n", varname); */
				err = -1;
			}
		}
		if (flag & 0x0002) {
			ret = nvram_unset(strcat_r(hspotap->prefix, "venuegrp", varname));
			if (ret) {
				/* printf("nvram_unset %s failure\n", varname); */
				err = -1;
			}
		}
		if (flag & 0x0004) {
			ret = nvram_unset(strcat_r(hspotap->prefix, "venuelist", varname));
			if (ret) {
				/* printf("nvram_unset %s failure\n", varname); */
				err = -1;
			}
		}
	}
	else
	{
		hspotap->venuelist.isDecodeValid = TRUE;

		if (flag & 0x0001) {
			hspotap->venuelist.type = 8;
			ret = nvram_set(strcat_r(hspotap->prefix, "venuetype", varname), "8");
			if (ret) {
				/* printf("nvram_set %s=%s failure\n", varname, "8"); */
				err = -1;
			}
		}
		if (flag & 0x0002) {
			hspotap->venuelist.group = 2;
			ret = nvram_set(strcat_r(hspotap->prefix, "venuegrp", varname), "2");
			if (ret) {
				/* printf("nvram_set %s=%s failure\n", varname, "2"); */
				err = -1;
			}
		}
		if (flag & 0x0004) {

			memset(hspotap->venuelist.venueName, 0,
				sizeof(hspotap->venuelist.venueName));

			hspotap->venuelist.numVenueName = 2;

			strncpy_n(hspotap->venuelist.venueName[0].name, WIFI_VENUE,
				VENUE_NAME_SIZE + 1);
			hspotap->venuelist.venueName[0].nameLen = strlen(WIFI_VENUE);
			strncpy_n(hspotap->venuelist.venueName[0].lang, ENGLISH,
				VENUE_LANGUAGE_CODE_SIZE + 1);
			hspotap->venuelist.venueName[0].langLen = strlen(ENGLISH);

			strncpy_n(hspotap->venuelist.venueName[1].name,
				(char *)chinese_venue_name, VENUE_NAME_SIZE + 1);
			hspotap->venuelist.venueName[1].nameLen = sizeof(chinese_venue_name);
			strncpy_n(hspotap->venuelist.venueName[1].lang,
				CHINESE, VENUE_LANGUAGE_CODE_SIZE +1);
			hspotap->venuelist.venueName[1].langLen = strlen(CHINESE);

			ret = nvram_set(strcat_r(hspotap->prefix, "venuelist", varname),
					"57692D466920416C6C69616E63650A"
					"3239383920436F7070657220526F61640A"
					"53616E746120436C6172612C2043412039"
					"353035312C2055534121656E677C"
					"57692D4669E88194E79B9FE5AE9EE9AA8CE5AEA40A"
					"E4BA8CE4B99DE585ABE4B99DE5B9B4E5BA93E69F8FE8B7AF0A"
					"E59CA3E5858BE68B89E68B892C20E58AA0E588A9E7A68FE5B0"
					"BCE4BA9A39353035312C20E7BE8EE59BBD21636869");
			if (ret) {
				/* printf("nvram_set %s=%s failure\n", varname, */
				/* "Wi-Fi Alliance\n2989 Copper Road\nSanta Clara," */
				/* " CA 95051, USA!eng|"); */
				err = -1;
			}
		}
	}

	nvram_commit();
	return err;
}

int Reset_IPaddr(hspotApT *hspotap, bool bInit)
{
	int ret, err = 0;
	char varname[NVRAM_MAX_PARAM_LEN];
	memset(&hspotap->ipaddrAvail, 0, sizeof(bcm_decode_anqp_ip_type_t));

	if (!bInit)
	{
		ret = nvram_unset(strcat_r(hspotap->prefix, "ipv4addr", varname));
		if (ret) {
			/* printf("nvram_unset %s failure\n", varname); */
			err = -1;
		}
		ret = nvram_unset(strcat_r(hspotap->prefix, "ipv6addr", varname));
		if (ret) {
			/* printf("nvram_unset %s failure\n", varname); */
			err = -1;
		}
	}
	else
	{
		hspotap->ipaddrAvail.isDecodeValid = TRUE;
		hspotap->ipaddrAvail.ipv4 = IPA_IPV4_SINGLE_NAT;
		hspotap->ipaddrAvail.ipv6 = IPA_IPV6_NOT_AVAILABLE;

		ret = nvram_set(strcat_r(hspotap->prefix, "ipv4addr", varname), "3");
		if (ret) {
			/* printf("nvram_set %s=%s failure\n", varname, "3"); */
			err = -1;
		}
		ret = nvram_set(strcat_r(hspotap->prefix, "ipv6addr", varname), "0");
		if (ret) {
			/* printf("nvram_set %s=%s failure\n", varname, "0"); */
			err = -1;
		}
	}

	nvram_commit();
	return err;
}

int Reset_NatList(hspotApT *hspotap, bool bInit)
{
	int ret, err = 0;
	char varname[NVRAM_MAX_PARAM_LEN];
	memset(&hspotap->netauthlist, 0, sizeof(bcm_decode_anqp_network_authentication_type_t));

	if (!bInit)
	{
		ret = nvram_unset(strcat_r(hspotap->prefix, "netauthlist", varname));
		if (ret) {
			/* printf("nvram_unset %s failure\n", varname); */
			err = -1;
		}
	}
	else
	{
		hspotap->netauthlist.isDecodeValid = TRUE;
		hspotap->netauthlist.numAuthenticationType = 2;

		hspotap->netauthlist.unit[0].type = (uint8)NATI_ACCEPTANCE_OF_TERMS_CONDITIONS;
		hspotap->netauthlist.unit[0].urlLen = 0;
		strncpy_n((char*)hspotap->netauthlist.unit[0].url,
			"", BCM_DECODE_ANQP_MAX_URL_LENGTH + 1);

		hspotap->netauthlist.unit[1].type = (uint8)NATI_HTTP_HTTPS_REDIRECTION;
		hspotap->netauthlist.unit[1].urlLen = strlen(URL);
		strncpy_n((char*)hspotap->netauthlist.unit[1].url,
			URL, BCM_DECODE_ANQP_MAX_URL_LENGTH + 1);

		ret = nvram_set(strcat_r(hspotap->prefix, "netauthlist", varname),
			"accepttc=+httpred=https://tandc-server.wi-fi.org");
		if (ret) {
			/* printf("nvram_set %s=%s failure\n", varname, */
			/* "accepttc=+httpred=https://tandc-server.wi-fi.org"); */
			err = -1;
		}
	}

	nvram_commit();
	return err;
}

int Reset_Opclass(hspotApT *hspotap, bool bInit)
{
	int ret, err = 0;
	char varname[NVRAM_MAX_PARAM_LEN];

	if (!bInit)
	{
		ret = nvram_unset(strcat_r(hspotap->prefix, "opercls", varname));
		if (ret) {
			/* printf("nvram_unset %s failure\n", varname); */
			err = -1;
		}
	}
	else
	{
		uint8 opClass3 [2] = {81, 115};
		hspotap->opclass.opClassLen = sizeof(opClass3);
		memcpy(hspotap->opclass.opClass, opClass3, sizeof(opClass3));

		ret = nvram_set(strcat_r(hspotap->prefix, "opercls", varname), "3");
		if (ret) {
			/* printf("nvram_set %s=%s failure\n", varname, "3"); */
			err = -1;
		}
	}
	nvram_commit();
	return err;
}

int Reset_Anonai(hspotApT *hspotap, bool bInit)
{
	int ret, err = 0;
	char varname[NVRAM_MAX_PARAM_LEN];
	memset(&hspotap->anonai, 0, sizeof(bcm_decode_hspot_anqp_anonymous_nai_t));

	if (!bInit)
	{
		ret = nvram_unset(strcat_r(hspotap->prefix, "anonai", varname));
		if (ret) {
			/* printf("nvram_unset %s failure\n", varname); */
			err = -1;
		}
	}
	else
	{
		hspotap->anonai.isDecodeValid = TRUE;

		strncpy_n(hspotap->anonai.nai,
			"anonymous.com", BCM_DECODE_HSPOT_ANQP_MAX_NAI_SIZE + 1);
		hspotap->anonai.naiLen = strlen(hspotap->anonai.nai);

		ret = nvram_set(strcat_r(hspotap->prefix, "anonai", varname), "anonymous.com");
		if (ret) {
			/* printf("nvram_set %s=%s failure\n", varname, "anonymous.com"); */
			err = -1;
		}
	}
	nvram_commit();
	return err;
}

int Reset_Osuplist(hspotApT *hspotap, bool bInit, unsigned int flag)
{
	int ret, err = 0, iter = 0;
	char varname[NVRAM_MAX_PARAM_LEN];
	uint8 osu_method[1];

	if (!bInit)
	{
		/* OSU_SSID */
		if (flag & 0x0001) {
			hspotap->osuplist.isDecodeValid = FALSE;
			memset(hspotap->osuplist.osuSsid, 0, sizeof(hspotap->osuplist.osuSsid));
			hspotap->osuplist.osuSsidLength = 0;
			hspotap->osuplist.osuProviderCount = 0;
			ret = nvram_unset(strcat_r(hspotap->prefix, "osu_ssid", varname));
			if (ret) {
				/* printf("nvram_unset %s failure\n", varname); */
				err = -1;
			}
		}
		/* OSU_Friendly_Name */
		if (flag & 0x0002) {
			for (iter = 0; iter < MAX_OSU_PROVIDERS; iter++)
				memset(&hspotap->osuplist.osuProvider[iter].name, 0,
					sizeof(hspotap->osuplist.osuProvider[iter].name));
			hspotap->osuplist.osuProviderCount = 0;
			ret = nvram_unset(strcat_r(hspotap->prefix, "osu_frndname", varname));
			if (ret) {
				/* printf("nvram_unset %s failure\n", varname); */
				err = -1;
			}
		}
		/* OSU_Server_URI */
		if (flag & 0x0004) {
			for (iter = 0; iter < MAX_OSU_PROVIDERS; iter++)
			{
				memset(hspotap->osuplist.osuProvider[iter].uri, 0,
					sizeof(hspotap->osuplist.osuProvider[iter].uri));
				hspotap->osuplist.osuProvider[iter].uriLength = 0;
			}
			hspotap->osuplist.osuProviderCount = 0;
			ret = nvram_unset(strcat_r(hspotap->prefix, "osu_uri", varname));
			if (ret) {
				/* printf("nvram_unset %s failure\n", varname); */
				err = -1;
			}
		}
		/* OSU_Method */
		if (flag & 0x0008) {
			for (iter = 0; iter < MAX_OSU_PROVIDERS; iter++)
			{
				memset(hspotap->osuplist.osuProvider[iter].method, 0,
					sizeof(hspotap->osuplist.osuProvider[iter].method));
				hspotap->osuplist.osuProvider[iter].methodLength = 0;
			}
			hspotap->osuplist.osuProviderCount = 0;
			ret = nvram_unset(strcat_r(hspotap->prefix, "osu_method", varname));
			if (ret) {
				/* printf("nvram_unset %s failure\n", varname); */
				err = -1;
			}
		}
		/* OSU_Icons */
		if (flag & 0x0010) {
			for (iter = 0; iter < MAX_OSU_PROVIDERS; iter++)
			{
				memset(hspotap->osuplist.osuProvider[iter].iconMetadata, 0,
					sizeof(hspotap->osuplist.osuProvider[iter].iconMetadata));
				hspotap->osuplist.osuProvider[iter].iconMetadataCount = 0;
			}
			hspotap->osuplist.osuProviderCount = 0;
			ret = nvram_unset(strcat_r(hspotap->prefix, "osu_icons", varname));
			if (ret) {
				/* printf("nvram_unset %s failure\n", varname); */
				err = -1;
			}
		}
		/* OSU_NAI */
		if (flag & 0x0020) {
			for (iter = 0; iter < MAX_OSU_PROVIDERS; iter++)
			{
				memset(hspotap->osuplist.osuProvider[iter].nai, 0,
					sizeof(hspotap->osuplist.osuProvider[iter].nai));
				hspotap->osuplist.osuProvider[iter].naiLength = 0;
			}
			ret = nvram_unset(strcat_r(hspotap->prefix, "osu_nai", varname));
			if (ret) {
				/* printf("nvram_unset %s failure\n", varname); */
				err = -1;
			}
		}
		/* OSU_Server_Desc */
		if (flag & 0x0040) {
			for (iter = 0; iter < MAX_OSU_PROVIDERS; iter++)
			{
				memset(&hspotap->osuplist.osuProvider[iter].desc, 0,
					sizeof(hspotap->osuplist.osuProvider[iter].desc));
			}
			ret = nvram_unset(strcat_r(hspotap->prefix, "osu_servdesc", varname));
			if (ret) {
				/* printf("nvram_unset %s failure\n", varname); */
				err = -1;
			}
		}
		/* OSU_ICON_ID */
		if (flag & 0x0080) {
			hspotap->osuicon_id = 1;
			ret = nvram_unset(strcat_r(hspotap->prefix, "osuicon_id", varname));
			if (ret) {
				/* printf("nvram_unset %s failure\n", varname); */
				err = -1;
			}
		}
	}
	else
	{
		hspotap->osuplist.isDecodeValid = TRUE;
		hspotap->osuplist.osuProviderCount = 1;
		/* OSU_SSID */
		if (flag & 0x0001) {
			strncpy_n((char*)hspotap->osuplist.osuSsid, "OSU",
				BCM_DECODE_HSPOT_ANQP_MAX_OSU_SSID_LENGTH + 1);
			hspotap->osuplist.osuSsidLength = strlen("OSU");
			ret = nvram_set(strcat_r(hspotap->prefix, "osu_ssid", varname),
				"OSU");
			if (ret) {
				/* printf("nvram_set %s=%s failure\n", varname, "OSU"); */
				err = -1;
			}
		}
		/* OSU_Friendly_Name */
		if (flag & 0x0002) {
			hspotap->osuplist.osuProvider[0].name.isDecodeValid = TRUE;
			hspotap->osuplist.osuProvider[0].name.numName = 2;
			strncpy_n((char*)hspotap->osuplist.osuProvider[0].name.duple[0].lang,
				ENGLISH, VENUE_LANGUAGE_CODE_SIZE +1);
			hspotap->osuplist.osuProvider[0].name.duple[0].langLen =
				strlen(ENGLISH);
			strncpy_n((char*)hspotap->osuplist.osuProvider[0].name.duple[0].name,
				ENG_OPNAME_SP_RED, VENUE_NAME_SIZE + 1);
			hspotap->osuplist.osuProvider[0].name.duple[0].nameLen =
				strlen(ENG_OPNAME_SP_RED);
			strncpy_n(hspotap->osuplist.osuProvider[0].name.duple[1].lang,
				KOREAN, VENUE_LANGUAGE_CODE_SIZE +1);
			hspotap->osuplist.osuProvider[0].name.duple[1].langLen =
				strlen(KOREAN);
			strncpy_n(hspotap->osuplist.osuProvider[0].name.duple[1].name,
				(char *)kor_opname_sp_red, VENUE_NAME_SIZE + 1);
			hspotap->osuplist.osuProvider[0].name.duple[1].nameLen =
				sizeof(kor_opname_sp_red);
			ret = nvram_set(strcat_r(hspotap->prefix, "osu_frndname", varname),
				"SP Red Test Only!eng|"
				"\x53\x50\x20\xEB\xB9\xA8\xEA\xB0\x95\x20\xED\x85\x8C"
				"\xEC\x8A\xA4\xED\x8A\xB8\x20\xEC\xA0\x84\xEC\x9A\xA9!kor");
			if (ret) {
				/* printf("nvram_set %s=%s failure\n", varname, */
				/* "SP Red Test Only!eng|" */
				/* "\x53\x50\x20\xEB\xB9\xA8\xEA\xB0\x95\x20\xED\x85\x8C" */
				/* "\xEC\x8A\xA4\xED\x8A\xB8\x20\xEC\xA0\x84\xEC\x9A\xA9!kor"); */
				err = -1;
			}
			for (iter = 1; iter < MAX_OSU_PROVIDERS; iter++)
				memset(&hspotap->osuplist.osuProvider[iter].name, 0,
					sizeof(hspotap->osuplist.osuProvider[iter].name));
		}
		/* OSU_Server_URI */
		if (flag & 0x0004) {
			strncpy_n((char*)hspotap->osuplist.osuProvider[0].uri, OSU_SERVER_URI,
				BCM_DECODE_HSPOT_ANQP_MAX_URI_LENGTH + 1);
			hspotap->osuplist.osuProvider[0].uriLength =
				strlen(OSU_SERVER_URI);
			ret = nvram_set(strcat_r(hspotap->prefix, "osu_uri", varname),
				"https://osu-server.r2-testbed.wi-fi.org/");
			if (ret) {
				/* printf("nvram_set %s=%s failure\n", varname, */
				/* "https://osu-server.r2-testbed.wi-fi.org/"); */
				err = -1;
			}
			for (iter = 1; iter < MAX_OSU_PROVIDERS; iter++)
			{
				memset(hspotap->osuplist.osuProvider[iter].uri, 0,
					sizeof(hspotap->osuplist.osuProvider[iter].uri));
				hspotap->osuplist.osuProvider[iter].uriLength = 0;
			}
		}
		/* OSU_Method */
		if (flag & 0x0008) {
			osu_method[0] = HSPOT_OSU_METHOD_SOAP_XML;
			memcpy(hspotap->osuplist.osuProvider[0].method,
				osu_method, sizeof(osu_method));
			hspotap->osuplist.osuProvider[0].methodLength = sizeof(osu_method);
			ret = nvram_set(strcat_r(hspotap->prefix, "osu_method", varname),
				"1");
			if (ret) {
				/* printf("nvram_set %s=%s failure\n", varname, */
				/* "1"); */
				err = -1;
			}
			for (iter = 1; iter < MAX_OSU_PROVIDERS; iter++)
			{
				memset(hspotap->osuplist.osuProvider[iter].method, 0,
					sizeof(hspotap->osuplist.osuProvider[iter].method));
				hspotap->osuplist.osuProvider[iter].methodLength = 0;
			}
		}
		/* OSU_Icons */
		if (flag & 0x0010) {
			hspotap->osuplist.osuProvider[0].iconMetadataCount = 2;
			hspotap->osuplist.osuProvider[0].iconMetadata[0].width = 128;
			hspotap->osuplist.osuProvider[0].iconMetadata[0].height = 61;
			strncpy_n((char*)hspotap->osuplist.osuProvider[0].iconMetadata[0].lang,
				LANG_ZXX, VENUE_LANGUAGE_CODE_SIZE +1);
			strncpy_n((char*)hspotap->osuplist.osuProvider[0].iconMetadata[0].type,
				ICON_TYPE_ID1, BCM_DECODE_HSPOT_ANQP_MAX_ICON_TYPE_LENGTH + 1);
			hspotap->osuplist.osuProvider[0].iconMetadata[0].typeLength
						= strlen(ICON_TYPE_ID1);
			strncpy_n((char*)
			hspotap->osuplist.osuProvider[0].iconMetadata[0].filename,
				ICON_FILENAME_RED_ZXX,
				BCM_DECODE_HSPOT_ANQP_MAX_ICON_FILENAME_LENGTH + 1);
			hspotap->osuplist.osuProvider[0].iconMetadata[0].filenameLength =
				strlen(ICON_FILENAME_RED_ZXX);
			/* Icon Metadata 2 */
			hspotap->osuplist.osuProvider[0].iconMetadata[1].width = 160;
			hspotap->osuplist.osuProvider[0].iconMetadata[1].height = 76;
			strncpy_n((char*)hspotap->osuplist.osuProvider[0].iconMetadata[1].lang,
				ENGLISH, VENUE_LANGUAGE_CODE_SIZE +1);
			strncpy_n((char*)hspotap->osuplist.osuProvider[0].iconMetadata[1].type,
				ICON_TYPE_ID1,
				BCM_DECODE_HSPOT_ANQP_MAX_ICON_TYPE_LENGTH + 1);
			hspotap->osuplist.osuProvider[0].iconMetadata[1].typeLength
					= strlen(ICON_TYPE_ID1);
			strncpy_n((char*)hspotap->osuplist.osuProvider[0].iconMetadata[1].filename,
				ICON_FILENAME_RED,
				BCM_DECODE_HSPOT_ANQP_MAX_ICON_FILENAME_LENGTH + 1);
			hspotap->osuplist.osuProvider[0].iconMetadata[1].filenameLength =
				strlen(ICON_FILENAME_RED);
			ret = nvram_set(strcat_r(hspotap->prefix, "osu_icons", varname),
				"icon_red_zxx.png+icon_red_eng.png");
			if (ret) {
				/* printf("nvram_set %s=%s failure\n", varname, */
				/* "icon_red_zxx.png+icon_red_eng.png"); */
				err = -1;
			}
			for (iter = 1; iter < MAX_OSU_PROVIDERS; iter++)
			{
				memset(hspotap->osuplist.osuProvider[iter].iconMetadata, 0,
					sizeof(hspotap->osuplist.osuProvider[iter].iconMetadata));
				hspotap->osuplist.osuProvider[iter].iconMetadataCount = 0;
			}
		}
		/* OSU_NAI */
		if (flag & 0x0020) {
			strncpy_n((char*)hspotap->osuplist.osuProvider[0].nai, "",
				BCM_DECODE_HSPOT_ANQP_MAX_NAI_LENGTH + 1);
			hspotap->osuplist.osuProvider[0].naiLength = 0;
			ret = nvram_set(strcat_r(hspotap->prefix, "osu_nai", varname),
				"");
			if (ret) {
				/* printf("nvram_set %s=%s failure\n", varname, */
				/* ""); */
				err = -1;
			}
			for (iter = 1; iter < MAX_OSU_PROVIDERS; iter++)
			{
				memset(hspotap->osuplist.osuProvider[iter].nai, 0,
					sizeof(hspotap->osuplist.osuProvider[iter].nai));
				hspotap->osuplist.osuProvider[iter].naiLength = 0;
			}
		}
		/* OSU_Server_Desc */
		if (flag & 0x0040) {
			hspotap->osuplist.osuProvider[0].desc.isDecodeValid = TRUE;
			hspotap->osuplist.osuProvider[0].desc.numName = 2;
			strncpy_n((char*)hspotap->osuplist.osuProvider[0].desc.duple[0].lang,
				ENGLISH, VENUE_LANGUAGE_CODE_SIZE +1);
			hspotap->osuplist.osuProvider[0].desc.duple[0].langLen =
				strlen(ENGLISH);
			strncpy_n((char*)hspotap->osuplist.osuProvider[0].desc.duple[0].name,
				OSU_SERVICE_DESC_ID1, VENUE_NAME_SIZE + 1);
			hspotap->osuplist.osuProvider[0].desc.duple[0].nameLen =
				strlen(OSU_SERVICE_DESC_ID1);
			strncpy_n((char*)hspotap->osuplist.osuProvider[0].desc.duple[1].lang,
				KOREAN, VENUE_LANGUAGE_CODE_SIZE +1);
			hspotap->osuplist.osuProvider[0].desc.duple[1].langLen =
				strlen(KOREAN);
			strncpy_n((char*)hspotap->osuplist.osuProvider[0].desc.duple[1].name,
				(char *)kor_desc_name_id1, VENUE_NAME_SIZE + 1);
			hspotap->osuplist.osuProvider[0].desc.duple[1].nameLen =
				sizeof(kor_desc_name_id1);
			ret = nvram_set(strcat_r(hspotap->prefix, "osu_servdesc", varname),
				"Free service for test purpose!eng|"
				"\xED\x85\x8C\xEC\x8A\xA4\xED\x8A\xB8\x20\xEB\xAA\xA9"
				"\xEC\xA0\x81\xEC\x9C\xBC\xEB\xA1\x9C\x20\xEB\xAC\xB4"
				"\xEB\xA3\x8C\x20\xEC\x84\x9C\xEB\xB9\x84\xEC\x8A\xA4!kor");
			if (ret) {
				/* printf("nvram_set %s=%s failure\n", varname, */
				/* "Free service for test purpose!eng|" */
				/* "\xED\x85\x8C\xEC\x8A\xA4\xED\x8A\xB8\x20\xEB\xAA\xA9" */
				/* "\xEC\xA0\x81\xEC\x9C\xBC\xEB\xA1\x9C\x20\xEB\xAC\xB4" */
				/* "\xEB\xA3\x8C\x20\xEC\x84\x9C\xEB\xB9\x84\xEC\x8A\xA4!kor"); */
				err = -1;
			}
			for (iter = 1; iter < MAX_OSU_PROVIDERS; iter++)
			{
				memset(&hspotap->osuplist.osuProvider[iter].desc, 0,
					sizeof(hspotap->osuplist.osuProvider[iter].desc));
			}
		}
		/* OSU_ICON_ID */
		if (flag & 0x0080) {
			hspotap->osuicon_id = 1;
			ret = nvram_set(strcat_r(hspotap->prefix, "osuicon_id", varname), "1");
			if (ret) {
				/* printf("nvram_set %s=%s failure\n", varname, "1"); */
				err = -1;
			}
		}
	}
	nvram_commit();
	return err;
}


int Reset_Realmlist(hspotApT *hspotap, bool bInit)
{
	int ret, err = 0, useSim = 0, iR = 0;
	char varname[NVRAM_MAX_PARAM_LEN] = {0};
	uint8 auth_MSCHAPV2[1]		= { (uint8)REALM_MSCHAPV2 };
	uint8 auth_UNAMPSWD[1]		= { (uint8)REALM_USERNAME_PASSWORD };
	uint8 auth_CERTIFICATE[1]	= { (uint8)REALM_CERTIFICATE };
	uint8 auth_SIM[1]		= { (uint8)REALM_SIM };

	memset(&hspotap->realmlist, 0, sizeof(bcm_decode_anqp_nai_realm_list_t));

	if (!bInit)
	{
		ret = nvram_unset(strcat_r(hspotap->prefix, "realmlist", varname));
		if (ret) {
			/* printf("nvram_unset %s failure\n", varname); */
			err = -1;
		}
	}
	else
	{
	/* Fill the bcm_decode_anqp_nai_realm_list_t structure for Realm_id = 1 */
	/* And set NVRAM value for wl_realmlist */

	hspotap->realmlist.isDecodeValid = TRUE;
	hspotap->realmlist.realmCount = 4;

	useSim = Get_hspot_flag(hspotap->prefix, HSFLG_USE_SIM);
	iR = 0;

	if (!useSim) {
	/* Realm 1 --------------------------------------------- */
	hspotap->realmlist.realm[iR].encoding = (uint8)REALM_ENCODING_RFC4282;
	hspotap->realmlist.realm[iR].realmLen = strlen(MAIL);
	strncpy_n((char*)hspotap->realmlist.realm[iR].realm, MAIL,
		BCM_DECODE_ANQP_MAX_REALM_LENGTH + 1);
	hspotap->realmlist.realm[iR].eapCount = 1;
	/* EAP 1.1 */
	hspotap->realmlist.realm[iR].eap[0].eapMethod = (uint8)REALM_EAP_TTLS;
	hspotap->realmlist.realm[iR].eap[0].authCount = 2;
	/* Auth 1.1.1 */
	hspotap->realmlist.realm[iR].eap[0].auth[0].id = (uint8)REALM_NON_EAP_INNER_AUTHENTICATION;
	hspotap->realmlist.realm[iR].eap[0].auth[0].len = sizeof(auth_MSCHAPV2);
	memcpy(hspotap->realmlist.realm[iR].eap[0].auth[0].value,
		auth_MSCHAPV2, sizeof(auth_MSCHAPV2));
	/* Auth 1.1.2 */
	hspotap->realmlist.realm[iR].eap[0].auth[1].id = (uint8)REALM_CREDENTIAL;
	hspotap->realmlist.realm[iR].eap[0].auth[1].len = sizeof(auth_UNAMPSWD);
	memcpy(hspotap->realmlist.realm[iR].eap[0].auth[1].value,
		auth_UNAMPSWD, sizeof(auth_UNAMPSWD));
	iR++;
	/* -------------------------------------------------- */
	}

	/* Realm 2 --------------------------------------------- */
	hspotap->realmlist.realm[iR].encoding = (uint8)REALM_ENCODING_RFC4282;
	hspotap->realmlist.realm[iR].realmLen = strlen(CISCO);
	strncpy_n((char*)hspotap->realmlist.realm[iR].realm, CISCO,
		BCM_DECODE_ANQP_MAX_REALM_LENGTH + 1);
	hspotap->realmlist.realm[iR].eapCount = 1;
	/* EAP 2.1 */
	hspotap->realmlist.realm[iR].eap[0].eapMethod = (uint8)REALM_EAP_TTLS;
	hspotap->realmlist.realm[iR].eap[0].authCount = 2;
	/* Auth 2.1.1 */
	hspotap->realmlist.realm[iR].eap[0].auth[0].id = (uint8)REALM_NON_EAP_INNER_AUTHENTICATION;
	hspotap->realmlist.realm[iR].eap[0].auth[0].len = sizeof(auth_MSCHAPV2);
	memcpy(hspotap->realmlist.realm[iR].eap[0].auth[0].value,
		auth_MSCHAPV2, sizeof(auth_MSCHAPV2));
	/* Auth 2.1.2 */
	hspotap->realmlist.realm[iR].eap[0].auth[1].id = (uint8)REALM_CREDENTIAL;
	hspotap->realmlist.realm[iR].eap[0].auth[1].len = sizeof(auth_UNAMPSWD);
	memcpy(hspotap->realmlist.realm[iR].eap[0].auth[1].value,
		auth_UNAMPSWD, sizeof(auth_UNAMPSWD));
	iR++;
	/* -------------------------------------------------- */

	/* Realm 3 --------------------------------------------- */
	hspotap->realmlist.realm[iR].encoding = (uint8)REALM_ENCODING_RFC4282;
	hspotap->realmlist.realm[iR].realmLen = strlen(WIFI);
	strncpy_n((char*)hspotap->realmlist.realm[iR].realm, WIFI,
		BCM_DECODE_ANQP_MAX_REALM_LENGTH + 1);
	hspotap->realmlist.realm[iR].eapCount = 2;
	/* EAP 3.1 */
	hspotap->realmlist.realm[iR].eap[0].eapMethod = (uint8)REALM_EAP_TTLS;
	hspotap->realmlist.realm[iR].eap[0].authCount = 2;
	/* Auth 3.1.1 */
	hspotap->realmlist.realm[iR].eap[0].auth[0].id = (uint8)REALM_NON_EAP_INNER_AUTHENTICATION;
	hspotap->realmlist.realm[iR].eap[0].auth[0].len = sizeof(auth_MSCHAPV2);
	memcpy(hspotap->realmlist.realm[iR].eap[0].auth[0].value,
		auth_MSCHAPV2, sizeof(auth_MSCHAPV2));
	/* Auth 3.1.2 */
	hspotap->realmlist.realm[iR].eap[0].auth[1].id = (uint8)REALM_CREDENTIAL;
	hspotap->realmlist.realm[iR].eap[0].auth[1].len = sizeof(auth_UNAMPSWD);
	memcpy(hspotap->realmlist.realm[iR].eap[0].auth[1].value,
		auth_UNAMPSWD, sizeof(auth_UNAMPSWD));
	/* EAP 3.2 */
	hspotap->realmlist.realm[iR].eap[1].eapMethod = (uint8)REALM_EAP_TLS;
	hspotap->realmlist.realm[iR].eap[1].authCount = 1;
	/* Auth 3.2.1 */
	hspotap->realmlist.realm[iR].eap[1].auth[0].id = (uint8)REALM_CREDENTIAL;
	hspotap->realmlist.realm[iR].eap[1].auth[0].len = sizeof(auth_CERTIFICATE);
	memcpy(hspotap->realmlist.realm[iR].eap[1].auth[0].value,
		auth_CERTIFICATE, sizeof(auth_CERTIFICATE));
	iR++;
	/* -------------------------------------------------- */

	/* Realm 4 --------------------------------------------- */
	hspotap->realmlist.realm[iR].encoding = (uint8)REALM_ENCODING_RFC4282;
	hspotap->realmlist.realm[iR].realmLen = strlen(EXAMPLE4);
	strncpy_n((char*)hspotap->realmlist.realm[iR].realm, EXAMPLE4,
		BCM_DECODE_ANQP_MAX_REALM_LENGTH + 1);
	hspotap->realmlist.realm[iR].eapCount = 1;
	/* EAP 4.1 */
	hspotap->realmlist.realm[iR].eap[0].eapMethod = (uint8)REALM_EAP_TLS;
	hspotap->realmlist.realm[iR].eap[0].authCount = 1;
	/* Auth 4.1.1 */
	hspotap->realmlist.realm[iR].eap[0].auth[0].id = (uint8)REALM_CREDENTIAL;
	hspotap->realmlist.realm[iR].eap[0].auth[0].len = sizeof(auth_CERTIFICATE);
	memcpy(hspotap->realmlist.realm[iR].eap[0].auth[0].value,
		auth_CERTIFICATE, sizeof(auth_CERTIFICATE));
	iR++;
	/* -------------------------------------------------- */

	if (useSim) {
	/* Realm 4 --------------------------------------------- */
	hspotap->realmlist.realm[iR].encoding = (uint8)REALM_ENCODING_RFC4282;
	hspotap->realmlist.realm[iR].realmLen = strlen(MAIL);
	strncpy_n((char*)hspotap->realmlist.realm[iR].realm, MAIL,
		BCM_DECODE_ANQP_MAX_REALM_LENGTH + 1);
	hspotap->realmlist.realm[iR].eapCount = 1;
	/* EAP 4.1 */
	hspotap->realmlist.realm[iR].eap[0].eapMethod = (uint8)REALM_EAP_SIM;
	hspotap->realmlist.realm[iR].eap[0].authCount = 1;
	/* Auth 4.1.1 */
	hspotap->realmlist.realm[iR].eap[0].auth[0].id = (uint8)REALM_CREDENTIAL;
	hspotap->realmlist.realm[iR].eap[0].auth[0].len = sizeof(auth_SIM);
	memcpy(hspotap->realmlist.realm[iR].eap[0].auth[0].value,
		auth_SIM, sizeof(auth_SIM));
	}
	/* -------------------------------------------------- */

	/* set NVRAM value */
	ret = nvram_set(strcat_r(hspotap->prefix, "realmlist", varname),
	useSim ? REALMLIST_ID1_SIM : REALMLIST_ID1);
	if (ret) {
		/* printf("nvram_set %s=%s failure\n", varname, */
			/* useSim ? REALMLIST_ID1_SIM : REALMLIST_ID1); */
		err = -1;
	}
	}
	nvram_commit();
	return err;
}


int Reset_ConnCaplist(hspotApT *hspotap, bool bInit)
{
	int ret, err = 0;
	char varname[NVRAM_MAX_PARAM_LEN];

	if (!bInit)
	{
		hspotap->conn_id = 0;
		ret = nvram_unset(strcat_r(hspotap->prefix, "conn_id", varname));
		if (ret) {
			/* printf("nvram_unset %s failure\n", varname); */
			err = -1;
		}
	}
	else
	{
		hspotap->conn_id = 1;
		ret = nvram_set(strcat_r(hspotap->prefix, "conn_id", varname), "1");
		if (ret) {
			/* printf("nvram_set %s=%s failure\n", varname, "1"); */
			err = -1;
		}
	}
	nvram_commit();
	return err;
}

int Reset_IW(hspotApT *hspotap, bool bInit, unsigned int flag)
{
	int ret, err = 0;
	char varname[NVRAM_MAX_PARAM_LEN];
	char varvalue[NVRAM_MAX_VALUE_LEN];

	strToEther(HESSID_DEFAULT, &hspotap->iw_HESSID);

	if (!bInit)
	{
		if (flag & 0x0001) {
			hspotap->iw_enabled = FALSE;
			ret = nvram_unset(strcat_r(hspotap->prefix, "u11en", varname));
			if (ret) {
				/* printf("nvram_unset %s failure\n", varname); */
				err = -1;
			}
		}
		if (flag & 0x0002) {
			hspotap->iw_isInternet = FALSE;
			ret = nvram_unset(strcat_r(hspotap->prefix, "iwint", varname));
			if (ret) {
				/* printf("nvram_unset %s failure\n", varname); */
				err = -1;
			}
		}
		if (flag & 0x0004) {
			hspotap->iw_ANT = 0;
			ret = nvram_unset(strcat_r(hspotap->prefix, "iwnettype", varname));
			if (ret) {
				/* printf("nvram_unset %s failure\n", varname); */
				err = -1;
			}
		}
		if (flag & 0x0008) {
			ret = nvram_unset(strcat_r(hspotap->prefix, "hessid", varname));
			if (ret) {
				/* printf("nvram_unset %s failure\n", varname); */
				err = -1;
			}
		}
	}
	else
	{
		if (flag & 0x0001) {
			hspotap->iw_enabled = TRUE;
			ret = nvram_set(strcat_r(hspotap->prefix, "u11en", varname), "1");
			if (ret) {
				/* printf("nvram_set %s=%s failure\n", varname, "0"); */
				err = -1;
			}
		}
		if (flag & 0x0002) {
			hspotap->iw_isInternet = FALSE;
			ret = nvram_set(strcat_r(hspotap->prefix, "iwint", varname), "0");
			if (ret) {
				/* printf("nvram_set %s=%s failure\n", varname, "0"); */
				err = -1;
			}
		}
		if (flag & 0x0004) {
			  hspotap->iw_ANT = 2;
			ret = nvram_set(strcat_r(hspotap->prefix, "iwnettype", varname), "2");
			if (ret) {
				/* printf("nvram_set %s=%s failure\n", varname, "2"); */
				err = -1;
			}
		}
		if (flag & 0x0008) {
			snprintf(varvalue, sizeof(varvalue), "%02x:%02x:%02x:%02x:%02x:%02x",
				hspotap->iw_HESSID.octet[0], hspotap->iw_HESSID.octet[1],
				hspotap->iw_HESSID.octet[2], hspotap->iw_HESSID.octet[3],
				hspotap->iw_HESSID.octet[4], hspotap->iw_HESSID.octet[5]);
			ret = nvram_set(strcat_r(hspotap->prefix, "hessid", varname), varvalue);
			if (ret) {
				/* printf("nvram_set %s=%s failure\n", varname, varvalue); */
				err = -1;
			}
		}
	}
	nvram_commit();
	return err;
}

int Reset_HSCap(hspotApT *hspotap, bool bInit)
{
	int ret, err = 0;
	char varname[NVRAM_MAX_PARAM_LEN];

	if (!bInit)
	{
		ret = nvram_unset(strcat_r(hspotap->prefix, "hs2cap", varname));
		if (ret) {
			/* printf("nvram_unset %s failure\n", varname); */
			err = -1;
		}
	}
	else
	{
		ret = nvram_set(strcat_r(hspotap->prefix, "hs2cap", varname), "1");
		if (ret) {
			/* printf("nvram_set %s=%s failure\n", varname, "1"); */
			err = -1;
		}
	}
	nvram_commit();
	return err;
}

int Reset_Oplist(hspotApT *hspotap, bool bInit)
{
	int ret, err = 0;
	char varname[NVRAM_MAX_PARAM_LEN];
	memset(&hspotap->oplist, 0, sizeof(bcm_decode_hspot_anqp_operator_friendly_name_t));

	if (!bInit)
	{
		ret = nvram_unset(strcat_r(hspotap->prefix, "oplist", varname));
		if (ret) {
			/* printf("nvram_unset %s failure\n", varname); */
			err = -1;
		}
	}
	else
	{
		hspotap->oplist.isDecodeValid = TRUE;
		hspotap->oplist.numName = 2;

		strncpy_n(hspotap->oplist.duple[0].name,
		ENGLISH_FRIENDLY_NAME, VENUE_NAME_SIZE + 1);
		hspotap->oplist.duple[0].nameLen = strlen(ENGLISH_FRIENDLY_NAME);
		strncpy_n(hspotap->oplist.duple[0].lang, ENGLISH, VENUE_LANGUAGE_CODE_SIZE +1);
		hspotap->oplist.duple[0].langLen = strlen(ENGLISH);

		strncpy_n(hspotap->oplist.duple[1].name,
		CHINESE_FRIENDLY_NAME, VENUE_NAME_SIZE + 1);
		hspotap->oplist.duple[1].nameLen = strlen(CHINESE_FRIENDLY_NAME);
		strncpy_n(hspotap->oplist.duple[1].lang, CHINESE, VENUE_LANGUAGE_CODE_SIZE +1);
		hspotap->oplist.duple[1].langLen = strlen(CHINESE);

		ret = nvram_set(strcat_r(hspotap->prefix, "oplist", varname), "Wi-Fi Alliance!eng|"
			"\x57\x69\x2d\x46\x69\xe8\x81\x94\xe7\x9b\x9f!chi");
		if (ret) {
			/* printf("nvram_set %s=%s failure\n", varname, "Wi-Fi Alliance!eng|" */
			/* "\x57\x69\x2d\x46\x69\xe8\x81\x94\xe7\x9b\x9f!chi"); */
			err = -1;
		}
	}

	nvram_commit();
	return err;
}

int Reset_WanMetrics(hspotApT *hspotap, bool bInit)
{
	int ret, err = 0;
	char varname[NVRAM_MAX_PARAM_LEN];
	memset(&hspotap->wanmetrics, 0, sizeof(bcm_decode_hspot_anqp_wan_metrics_t));

	if (!bInit)
	{
		ret = nvram_unset(strcat_r(hspotap->prefix, "wanmetrics", varname));
		if (ret) {
			/* printf("nvram_unset %s failure\n", varname); */
			err = -1;
		}
	}
	else
	{
		hspotap->wanmetrics.isDecodeValid	= TRUE;
		hspotap->wanmetrics.linkStatus		= HSPOT_WAN_LINK_UP;
		hspotap->wanmetrics.symmetricLink	= HSPOT_WAN_NOT_SYMMETRIC_LINK;
		hspotap->wanmetrics.atCapacity		= HSPOT_WAN_NOT_AT_CAPACITY;
		hspotap->wanmetrics.dlinkSpeed		= 2500;
		hspotap->wanmetrics.ulinkSpeed		= 384;
		hspotap->wanmetrics.dlinkLoad		= 0;
		hspotap->wanmetrics.ulinkLoad		= 0;
		hspotap->wanmetrics.lmd			= 0;

		ret = nvram_set(strcat_r(hspotap->prefix, "wanmetrics", varname),
			"1:0:0=2500>384=0>0=0");
		if (ret) {
			/* printf("nvram_set %s=%s failure\n", varname, */
			/* "1:0:0=2500>384=0>0=0"); */
			err = -1;
		}
	}

	nvram_commit();
	return err;
}

int Reset_Homeqlist(hspotApT *hspotap, bool bInit)
{
	int ret, err = 0;
	char varname[NVRAM_MAX_PARAM_LEN];
	memset(&hspotap->homeqlist, 0, sizeof(bcm_decode_hspot_anqp_nai_home_realm_query_t));

	if (!bInit)
	{
		ret = nvram_unset(strcat_r(hspotap->prefix, "homeqlist", varname));
		if (ret) {
			/* printf("nvram_unset %s failure\n", varname); */
			err = -1;
		}
	}
	else
	{
		hspotap->homeqlist.isDecodeValid = TRUE;
		hspotap->homeqlist.count = 1;
		strncpy_n(hspotap->homeqlist.data[0].name, HOME_REALM, VENUE_NAME_SIZE + 1);
		hspotap->homeqlist.data[0].nameLen = strlen(HOME_REALM);
		hspotap->homeqlist.data[0].encoding = (uint8)REALM_ENCODING_RFC4282;

		ret = nvram_set(strcat_r(hspotap->prefix, "homeqlist", varname),
			"mail.example.com:rfc4282");
		if (ret) {
			/* printf("nvram_set %s=%s failure\n", varname, */
			/* "mail.example.com:rfc4282"); */
			err = -1;
		}
	}

	nvram_commit();
	return err;
}


/* --------------------------------------------------------------- */


/* --------------------------------------------------------------- */
int hspot_send_BTM_Req_frame(hspotApT *hspotap, struct ether_addr *da)
{
	int err = 0;
	dot11_bsstrans_req_t *transreq;
	wnm_url_t *url;
	uint16 len;

	len = DOT11_BSSTRANS_REQ_LEN + hspotap->url_len + 1;
	transreq = (dot11_bsstrans_req_t *)malloc(len);
	if (transreq == NULL) {
		/* printf("malloc failed\n"); */
		return -1;
	}
	transreq->category = DOT11_ACTION_CAT_WNM;
	transreq->action = DOT11_WNM_ACTION_BSSTRANS_REQ;
	transreq->token = hspotap->req_token;
	transreq->reqmode = DOT11_BSSTRANS_REQMODE_ESS_DISASSOC_IMNT;
	transreq->disassoc_tmr = 0;
	transreq->validity_intrvl = 0;
	url = (wnm_url_t *)&transreq->data[0];
	url->len = hspotap->url_len;
	if (hspotap->url_len) {
		memcpy(url->data, hspotap->url, hspotap->url_len);
	}

	if (wl_wifiaction(hspotap->ifr, (uint32)hspotap, da, len, (uint8 *)transreq) < 0) {
		err = -1;
		TRACE(TRACE_ERROR, "wl_wifiaction failed\n");
	}

	hspotap->req_token++;
	if (hspotap->req_token == 0)
		hspotap->req_token = 1;

	free(transreq);
	return err;
}

static char *afStr(char *buf, int af, int length, uint8 fragmentId)
{
	switch (af)
	{
	case GAS_REQUEST_ACTION_FRAME:
		snprintf(buf, BUFF_PRINTGASEVENT,
			"request(%d)", length);
		break;
	case GAS_RESPONSE_ACTION_FRAME:
		snprintf(buf, BUFF_PRINTGASEVENT,
			"response(%d)", length);
		break;
	case GAS_COMEBACK_REQUEST_ACTION_FRAME:
		snprintf(buf, BUFF_PRINTGASEVENT,
			"comeback request(%d)", length);
		break;
	case GAS_COMEBACK_RESPONSE_ACTION_FRAME:
		snprintf(buf, BUFF_PRINTGASEVENT,
			"comeback response(%d, 0x%02x)", length, fragmentId);
		break;
	default:
		strncpy_n(buf, "unknown", BUFF_PRINTGASEVENT+1);
		break;
	}

	return buf;
}

int reallocateString(char** string, const char* newstring)
{
	int newlength = 0;

	if (newstring)
		newlength = strlen(newstring);

	if (*string)
		free(*string);

	if (newlength <= 0)
		return 0;

	*string = (char*)malloc(newlength+1);
	if (*string == 0)
		return 0;

	strcpy(*string, newstring);

	return 1;
}

void hspotPrintGasEvent(bcm_gas_event_t *event)
{
	char buf[BUFF_PRINTGASEVENT + 1];

	if ((event->type == BCM_GAS_EVENT_TX &&
		event->tx.gasActionFrame == GAS_REQUEST_ACTION_FRAME) ||
		(event->type == BCM_GAS_EVENT_RX &&
		event->rx.gasActionFrame == GAS_REQUEST_ACTION_FRAME)) {
		/* printf("\npeer MAC     : %02X:%02X:%02X:%02X:%02X:%02X\n", */
		/* event->peer.octet[0], event->peer.octet[1], event->peer.octet[2], */
		/* event->peer.octet[3], event->peer.octet[4], event->peer.octet[5]); */
		/* printf("dialog token : %d\n\n", event->dialogToken); */
	}

	if (event->type == BCM_GAS_EVENT_QUERY_REQUEST) {
		TRACE(TRACE_DEBUG, "   BCM_GAS_EVENT_QUERY_REQUEST\n");
	}
	else if (event->type == BCM_GAS_EVENT_TX) {
		/* printf("%30s  ----->\n", */
		/* afStr(buf, event->tx.gasActionFrame, */
		/* event->tx.length, event->tx.fragmentId)); */
	}
	else if (event->type == BCM_GAS_EVENT_RX) {
		/* printf("%30s  <-----  %s\n", "", */
		/* afStr(buf, event->rx.gasActionFrame, */
		/* event->rx.length, event->rx.fragmentId)); */
	}
	else if (event->type == BCM_GAS_EVENT_STATUS) {
		char *str;

		switch (event->status.statusCode)
		{
		case DOT11_SC_SUCCESS:
			str = "SUCCESS";
			break;
		case DOT11_SC_FAILURE:
			str = "UNSPECIFIED";
			break;
		case DOT11_SC_ADV_PROTO_NOT_SUPPORTED:
			str = "ADVERTISEMENT_PROTOCOL_NOT_SUPPORTED";
			break;
		case DOT11_SC_NO_OUTSTAND_REQ:
			str = "NO_OUTSTANDING_REQUEST";
			break;
		case DOT11_SC_RSP_NOT_RX_FROM_SERVER:
			str = "RESPONSE_NOT_RECEIVED_FROM_SERVER";
			break;
		case DOT11_SC_TIMEOUT:
			str = "TIMEOUT";
			break;
		case DOT11_SC_QUERY_RSP_TOO_LARGE:
			str = "QUERY_RESPONSE_TOO_LARGE";
			break;
		case DOT11_SC_SERVER_UNREACHABLE:
			str = "SERVER_UNREACHABLE";
			break;
		case DOT11_SC_TRANSMIT_FAILURE:
			str = "TRANSMISSION_FAILURE";
			break;
		default:
			str = "unknown GAS status";
			break;
		}

		/* printf("\n\nstatus = %s\n", str); */
	}
	else {
		TRACE(TRACE_DEBUG, "   unknown event type %d\n", event->type);
	}
}

static hspotApT *getHspotApByWlif(void *ifr)
{
	int i;

	for (i = 0; i < hspotap_num; i++) {
		if (hspotaps[i]->ifr == ifr)
			return hspotaps[i];
	}
	return NULL;
}

static hspotApT *getHspotApByIfname(char *ifname)
{
	int i;

	if (ifname == NULL)
		return hspotaps[0];

	for (i = 0; i < hspotap_num; i++) {
		if (strcmp(wl_ifname(hspotaps[i]->ifr), ifname) == 0)
			return hspotaps[i];
	}
	return NULL;
}

static hspotApT *getHspotApByBSSID(char *HESSIDstr)
{
	struct ether_addr da;
	struct ether_addr sa;
	int i;

	if (HESSIDstr == NULL)
		return hspotaps[0];

	if (!strToEther(HESSIDstr, &da)) {
		/* printf("wrong format parameter in command dest\n"); */
		return hspotaps[0];
	}

	for (i = 0; i < hspotap_num; i++) {
		wl_cur_etheraddr(hspotaps[i]->ifr, DEFAULT_BSSCFG_INDEX, &sa);
		if (bcmp(da.octet, sa.octet, ETHER_ADDR_LEN) == 0)
			return hspotaps[i];
	}

	return hspotaps[0];
}
/*
static hspotApT *getHspotApBySSID(char *ssid)
{
	int i;
	char tmp[BUFFER_SIZE];
	char* wl_ssid;

	if (ssid == NULL)
		return hspotaps[0];

	for (i = 0; i < hspotap_num; i++) {

		wl_ssid = nvram_safe_get(strcat_r(hspotaps[i]->prefix, "ssid", tmp));

		if (strcmp(wl_ssid, ssid) == 0)
			return hspotaps[i];
	}
	return NULL;
}
 */

static void encodeAnqpCapabilityList(hspotApT *hspotap, bcm_encode_t *pkt)
{
	uint8 buffer[BUFFER_SIZE];
	bcm_encode_t vendor;
	uint8 vendorCap[] = {
		HSPOT_SUBTYPE_QUERY_LIST,
		HSPOT_SUBTYPE_CAPABILITY_LIST,
		HSPOT_SUBTYPE_OPERATOR_FRIENDLY_NAME,
		HSPOT_SUBTYPE_WAN_METRICS,
		HSPOT_SUBTYPE_CONNECTION_CAPABILITY,
		HSPOT_SUBTYPE_NAI_HOME_REALM_QUERY,
		HSPOT_SUBTYPE_OPERATING_CLASS_INDICATION,
		HSPOT_SUBTYPE_ONLINE_SIGNUP_PROVIDERS,
		HSPOT_SUBTYPE_ANONYMOUS_NAI,
		HSPOT_SUBTYPE_ICON_REQUEST,
		HSPOT_SUBTYPE_ICON_BINARY_FILE };

	uint16 cap[] = {
		ANQP_ID_QUERY_LIST,
		ANQP_ID_CAPABILITY_LIST,
		ANQP_ID_VENUE_NAME_INFO,
		ANQP_ID_EMERGENCY_CALL_NUMBER_INFO,
		ANQP_ID_NETWORK_AUTHENTICATION_TYPE_INFO,
		ANQP_ID_ROAMING_CONSORTIUM_LIST,
		ANQP_ID_IP_ADDRESS_TYPE_AVAILABILITY_INFO,
		ANQP_ID_NAI_REALM_LIST,
		ANQP_ID_G3PP_CELLULAR_NETWORK_INFO,
		ANQP_ID_AP_GEOSPATIAL_LOCATION,
		ANQP_ID_AP_CIVIC_LOCATION,
		ANQP_ID_AP_LOCATION_PUBLIC_ID_URI,
		ANQP_ID_DOMAIN_NAME_LIST,
		ANQP_ID_EMERGENCY_ALERT_ID_URI,
		ANQP_ID_EMERGENCY_NAI };

	/* encode vendor specific capability */
	bcm_encode_init(&vendor, sizeof(buffer), buffer);
	bcm_encode_hspot_anqp_capability_list(&vendor,
	sizeof(vendorCap) / sizeof(uint8), vendorCap);

	/* encode capability with vendor specific appended */
	bcm_encode_anqp_capability_list(pkt, sizeof(cap) / sizeof(uint16), cap,
	bcm_encode_length(&vendor), bcm_encode_buf(&vendor));
}

static void encodeVenueName(hspotApT *hspotap, bcm_encode_t *pkt)
{
	uint8 buffer[BUFFER_SIZE];
	bcm_encode_t duple;

	bcm_encode_init(&duple, sizeof(buffer), buffer);

	int i;
	for (i = 0; i < hspotap->venuelist.numVenueName; i++) {
		bcm_encode_anqp_venue_duple(&duple,
			hspotap->venuelist.venueName[i].langLen,
			hspotap->venuelist.venueName[i].lang,
			hspotap->venuelist.venueName[i].nameLen,
			hspotap->venuelist.venueName[i].name);
	}

	bcm_encode_anqp_venue_name(pkt, hspotap->venuelist.group,
		hspotap->venuelist.type, bcm_encode_length(&duple), bcm_encode_buf(&duple));
}

static void encodeNetworkAuthenticationType(hspotApT *hspotap, bcm_encode_t *pkt)
{
	uint8 buffer[BUFFER_SIZE];
	bcm_encode_t network;

	bcm_encode_init(&network, sizeof(buffer), buffer);

	int i;
	for (i = 0; i < hspotap->netauthlist.numAuthenticationType; i++) {
		bcm_encode_anqp_network_authentication_unit(&network,
			hspotap->netauthlist.unit[i].type, hspotap->netauthlist.unit[i].urlLen,
			(char*)hspotap->netauthlist.unit[i].url);
	}

	bcm_encode_anqp_network_authentication_type(pkt,
		bcm_encode_length(&network), bcm_encode_buf(&network));
}

static void encodeRoamingConsortium(hspotApT *hspotap, bcm_encode_t *pkt)
{
	uint8 buffer[BUFFER_SIZE];
	bcm_encode_t oi;

	bcm_encode_init(&oi, sizeof(buffer), buffer);

	int i;
	for (i = 0; i < hspotap->ouilist.numOi; i++) {
		bcm_encode_anqp_oi_duple(&oi, hspotap->ouilist.oi[i].oiLen,
			hspotap->ouilist.oi[i].oi);
	}

	bcm_encode_anqp_roaming_consortium(pkt,
		bcm_encode_length(&oi), bcm_encode_buf(&oi));
}

static void encodeIpAddressType(hspotApT *hspotap, bcm_encode_t *pkt)
{
	bcm_encode_anqp_ip_type_availability(pkt,
		hspotap->ipaddrAvail.ipv6, hspotap->ipaddrAvail.ipv4);
}

static void encodeNaiRealmList(hspotApT *hspotap, bcm_encode_t *pkt)
{
	uint8 RealmBuf[BUFFER_SIZE], EapBuf[BUFFER_SIZE], AuthBuf[BUFFER_SIZE];
	bcm_encode_t Realm, Eap, Auth;
	int iR, iE, iA;

	/* Initialize Realm Buffer */
	bcm_encode_init(&Realm, sizeof(RealmBuf), RealmBuf);

	for (iR = 0; iR < hspotap->realmlist.realmCount; iR++) {

		/* Initialize Eap Buffer */
		bcm_encode_init(&Eap, sizeof(EapBuf), EapBuf);

		for (iE = 0; iE < hspotap->realmlist.realm[iR].eapCount; iE++) {

			/* Initialize Auth Buffer */
			bcm_encode_init(&Auth, sizeof(AuthBuf), AuthBuf);

			for (iA = 0; iA < hspotap->realmlist.realm[iR].eap[iE].authCount; iA++) {

				bcm_encode_anqp_authentication_subfield(&Auth,
					hspotap->realmlist.realm[iR].eap[iE].auth[iA].id,
					hspotap->realmlist.realm[iR].eap[iE].auth[iA].len,
					hspotap->realmlist.realm[iR].eap[iE].auth[iA].value);
				}

			bcm_encode_anqp_eap_method_subfield(&Eap,
				hspotap->realmlist.realm[iR].eap[iE].eapMethod,
				hspotap->realmlist.realm[iR].eap[iE].authCount,
				bcm_encode_length(&Auth), bcm_encode_buf(&Auth));
			}

		bcm_encode_anqp_nai_realm_data(&Realm,
			hspotap->realmlist.realm[iR].encoding,
			hspotap->realmlist.realm[iR].realmLen,
			hspotap->realmlist.realm[iR].realm,
			hspotap->realmlist.realm[iR].eapCount,
			bcm_encode_length(&Eap), bcm_encode_buf(&Eap));
	}

	bcm_encode_anqp_nai_realm(pkt, hspotap->realmlist.realmCount,
		bcm_encode_length(&Realm), bcm_encode_buf(&Realm));
}

static void encode3GppCellularNetwork(hspotApT *hspotap, bcm_encode_t *pkt)
{
	uint8 plmnBuf[BUFFER_SIZE];
	bcm_encode_t plmn;

	bcm_encode_init(&plmn, BUFFER_SIZE, plmnBuf);

	int i;
	for (i = 0; i < hspotap->gpp3list.plmnCount; i++) {
		bcm_encode_anqp_plmn(&plmn, hspotap->gpp3list.plmn[i].mcc,
			hspotap->gpp3list.plmn[i].mnc);
	}

	bcm_encode_anqp_3gpp_cellular_network(pkt,
		hspotap->gpp3list.plmnCount, bcm_encode_length(&plmn), bcm_encode_buf(&plmn));
}

static void encodeDomainNameList(hspotApT *hspotap, bcm_encode_t *pkt)
{
	uint8 buffer[BUFFER_SIZE];
	bcm_encode_t name;

	bcm_encode_init(&name, sizeof(buffer), buffer);

	if (hspotap->domainlist.numDomain) {
		int i;
		for (i = 0; i < hspotap->domainlist.numDomain; i++) {
			bcm_encode_anqp_domain_name(&name, hspotap->domainlist.domain[i].len,
				hspotap->domainlist.domain[i].name);
		}
	}

	bcm_encode_anqp_domain_name_list(pkt,
		bcm_encode_length(&name), bcm_encode_buf(&name));
}

static void encodeHspotCapabilityList(hspotApT *hspotap, bcm_encode_t *pkt)
{
	uint8 cap[] = {
		HSPOT_SUBTYPE_QUERY_LIST,
		HSPOT_SUBTYPE_CAPABILITY_LIST,
		HSPOT_SUBTYPE_OPERATOR_FRIENDLY_NAME,
		HSPOT_SUBTYPE_WAN_METRICS,
		HSPOT_SUBTYPE_CONNECTION_CAPABILITY,
		HSPOT_SUBTYPE_NAI_HOME_REALM_QUERY,
		HSPOT_SUBTYPE_OPERATING_CLASS_INDICATION,
		HSPOT_SUBTYPE_ONLINE_SIGNUP_PROVIDERS,
		HSPOT_SUBTYPE_ANONYMOUS_NAI,
		HSPOT_SUBTYPE_ICON_REQUEST,
		HSPOT_SUBTYPE_ICON_BINARY_FILE };

	bcm_encode_hspot_anqp_capability_list(pkt, sizeof(cap) / sizeof(uint8), cap);
}

static void encodeHspotOperatingClassIndication(hspotApT *hspotap, bcm_encode_t *pkt)
{
	bcm_encode_hspot_anqp_operating_class_indication(pkt,
		hspotap->opclass.opClassLen, hspotap->opclass.opClass);
}

static void encodeOperatorFriendlyName(hspotApT *hspotap, bcm_encode_t *pkt)
{
	uint8 buffer[BUFFER_SIZE];
	bcm_encode_t name; int i;

	bcm_encode_init(&name, sizeof(buffer), buffer);

	for (i = 0; i < hspotap->oplist.numName; i++) {
		bcm_encode_hspot_anqp_operator_name_duple(&name,
			hspotap->oplist.duple[i].langLen, hspotap->oplist.duple[i].lang,
			hspotap->oplist.duple[i].nameLen, hspotap->oplist.duple[i].name);
	}

	bcm_encode_hspot_anqp_operator_friendly_name(pkt,
		bcm_encode_length(&name), bcm_encode_buf(&name));
}

static void encodeHspotOsuProviders(hspotApT *hspotap, bcm_encode_t *pkt)
{
	uint8 osuBuf[BUFFER_SIZE1], iconBuf[BUFFER_SIZE];
	uint8 nameBuf[BUFFER_SIZE], descBuf[BUFFER_SIZE];
	bcm_encode_t osu, icon, name, desc;
	int ip = 0, ic = 0, in = 0, id = 0;

	for (ip = 0; ip < hspotap->osuplist.osuProviderCount; ip++)
	{
		/* Encode OSU_Friendly_Name */
		bcm_encode_init(&name, sizeof(nameBuf), nameBuf);
		for (in = 0;
				in < hspotap->osuplist.osuProvider[ip].name.numName;
				in++)
		{
			bcm_encode_hspot_anqp_operator_name_duple(&name,
				hspotap->osuplist.osuProvider[ip].name.duple[in].langLen,
				(char *)hspotap->osuplist.osuProvider[ip].name.duple[in].lang,
				hspotap->osuplist.osuProvider[ip].name.duple[in].nameLen,
				(char *)hspotap->osuplist.osuProvider[ip].name.duple[in].name);
		}
		/* Encode OSU_Icons */
		bcm_encode_init(&icon, sizeof(iconBuf), iconBuf);
		for (ic = 0;
				ic < hspotap->osuplist.osuProvider[ip].iconMetadataCount;
				ic++)
		{
			bcm_encode_hspot_anqp_icon_metadata(&icon,
				hspotap->osuplist.osuProvider[ip].iconMetadata[ic].width,
				hspotap->osuplist.osuProvider[ip].iconMetadata[ic].height,
				(char *)hspotap->osuplist.osuProvider[ip].iconMetadata[ic].lang,
				hspotap->osuplist.osuProvider[ip].iconMetadata[ic].typeLength,
				(uint8 *)hspotap->osuplist.osuProvider[ip].iconMetadata[ic].type,
				hspotap->osuplist.osuProvider[ip].iconMetadata[ic].filenameLength,
				(uint8 *)
				hspotap->osuplist.osuProvider[ip].iconMetadata[ic].filename);
		}
		/* Encode OSU_Friendly_Name */
		bcm_encode_init(&desc, sizeof(descBuf), descBuf);
		for (id = 0;
				id < hspotap->osuplist.osuProvider[ip].desc.numName;
				id++)
		{
			bcm_encode_hspot_anqp_operator_name_duple(&desc,
				hspotap->osuplist.osuProvider[ip].desc.duple[id].langLen,
				(char *)hspotap->osuplist.osuProvider[ip].desc.duple[id].lang,
				hspotap->osuplist.osuProvider[ip].desc.duple[id].nameLen,
				(char *)hspotap->osuplist.osuProvider[ip].desc.duple[id].name);
		}

		/* Encode Provider */
		bcm_encode_init(&osu, sizeof(osuBuf), osuBuf);
		bcm_encode_hspot_anqp_osu_provider(&osu,
			bcm_encode_length(&name), bcm_encode_buf(&name),
			hspotap->osuplist.osuProvider[ip].uriLength,
			(uint8 *)hspotap->osuplist.osuProvider[ip].uri,
			hspotap->osuplist.osuProvider[ip].methodLength,
			(uint8 *)hspotap->osuplist.osuProvider[ip].method,
			bcm_encode_length(&icon), bcm_encode_buf(&icon),
			hspotap->osuplist.osuProvider[ip].naiLength,
			(uint8 *)hspotap->osuplist.osuProvider[ip].nai,
			bcm_encode_length(&desc), bcm_encode_buf(&desc));
}

	/* Encode Providers List */
	bcm_encode_hspot_anqp_osu_provider_list(pkt,
		strlen((char*)hspotap->osuplist.osuSsid),
		(uint8 *)hspotap->osuplist.osuSsid,
		hspotap->osuplist.osuProviderCount,
		bcm_encode_length(&osu), bcm_encode_buf(&osu));
}

static void encodeHspotAnonymousNai(hspotApT *hspotap, bcm_encode_t *pkt)
{
	bcm_encode_hspot_anqp_anonymous_nai(pkt,
		hspotap->anonai.naiLen, (uint8 *)hspotap->anonai.nai);
}

static void encodeWanMetrics(hspotApT *hspotap, bcm_encode_t *pkt)
{
	bcm_encode_hspot_anqp_wan_metrics(pkt, hspotap->wanmetrics.linkStatus,
		hspotap->wanmetrics.symmetricLink, hspotap->wanmetrics.atCapacity,
		hspotap->wanmetrics.dlinkSpeed, hspotap->wanmetrics.ulinkSpeed,
		hspotap->wanmetrics.dlinkLoad, hspotap->wanmetrics.ulinkLoad,
		hspotap->wanmetrics.lmd);
}

static void encodeConnectionCapability(hspotApT *hspotap, bcm_encode_t *pkt)
{
	uint8 buffer[BUFFER_SIZE];
	bcm_encode_t cap;

	bcm_encode_init(&cap, sizeof(buffer), buffer);

	if (hspotap->conn_id == 1) {
		bcm_encode_hspot_anqp_proto_port_tuple(&cap,
			0x1, 0x0, HSPOT_CC_STATUS_CLOSED);
		bcm_encode_hspot_anqp_proto_port_tuple(&cap,
			0x6, 0x14, HSPOT_CC_STATUS_OPEN);
		bcm_encode_hspot_anqp_proto_port_tuple(&cap,
			0x6, 0x16, HSPOT_CC_STATUS_CLOSED);
		bcm_encode_hspot_anqp_proto_port_tuple(&cap,
			0x6, 0x50, HSPOT_CC_STATUS_OPEN);
		bcm_encode_hspot_anqp_proto_port_tuple(&cap,
			0x6, 0x1bb, HSPOT_CC_STATUS_OPEN);
		bcm_encode_hspot_anqp_proto_port_tuple(&cap,
			0x6, 0x6bb, HSPOT_CC_STATUS_CLOSED);
		bcm_encode_hspot_anqp_proto_port_tuple(&cap,
			0x6, 0x13c4, HSPOT_CC_STATUS_CLOSED);
		bcm_encode_hspot_anqp_proto_port_tuple(&cap,
			0x11, 0x1f4, HSPOT_CC_STATUS_OPEN);
		bcm_encode_hspot_anqp_proto_port_tuple(&cap,
			0x11, 0x13c4, HSPOT_CC_STATUS_CLOSED);
		bcm_encode_hspot_anqp_proto_port_tuple(&cap,
			0x11, 0x1194, HSPOT_CC_STATUS_OPEN);
		bcm_encode_hspot_anqp_proto_port_tuple(&cap,
			0x32, 0x0, HSPOT_CC_STATUS_OPEN);
	}
	else if (hspotap->conn_id == 2) {
		bcm_encode_hspot_anqp_proto_port_tuple(&cap,
			0x6, 0x50, HSPOT_CC_STATUS_OPEN);
		bcm_encode_hspot_anqp_proto_port_tuple(&cap,
			0x6, 0x1bb, HSPOT_CC_STATUS_OPEN);
		bcm_encode_hspot_anqp_proto_port_tuple(&cap,
			0x11, 0x13c4, HSPOT_CC_STATUS_OPEN);
		bcm_encode_hspot_anqp_proto_port_tuple(&cap,
			0x6, 0x13c4, HSPOT_CC_STATUS_OPEN);
	}
	else if (hspotap->conn_id == 3) {
		bcm_encode_hspot_anqp_proto_port_tuple(&cap,
			0x6, 0x50, HSPOT_CC_STATUS_OPEN);
		bcm_encode_hspot_anqp_proto_port_tuple(&cap,
			0x6, 0x1bb, HSPOT_CC_STATUS_OPEN);
	}
	else if (hspotap->conn_id == 4) {
		bcm_encode_hspot_anqp_proto_port_tuple(&cap,
			0x6, 0x50, HSPOT_CC_STATUS_OPEN);
		bcm_encode_hspot_anqp_proto_port_tuple(&cap,
			0x6, 0x1bb, HSPOT_CC_STATUS_OPEN);
		bcm_encode_hspot_anqp_proto_port_tuple(&cap,
			0x6, 0x13c4, HSPOT_CC_STATUS_OPEN);
		bcm_encode_hspot_anqp_proto_port_tuple(&cap,
			0x11, 0x13c4, HSPOT_CC_STATUS_OPEN);
	}
	else if (hspotap->conn_id == 5) {
	}

	bcm_encode_hspot_anqp_connection_capability(pkt,
		bcm_encode_length(&cap), bcm_encode_buf(&cap));
}

static void encodeNaiHomeRealmQuery(hspotApT *hspotap, bcm_encode_t *pkt)
{
	uint8 buffer[BUFFER_SIZE];
	bcm_encode_t name; int i;

	bcm_encode_init(&name, sizeof(buffer), buffer);

	for (i = 0; i < hspotap->homeqlist.count; i++) {
		bcm_encode_hspot_anqp_nai_home_realm_name(&name,
			hspotap->homeqlist.data[i].encoding,
			hspotap->homeqlist.data[i].nameLen,
			hspotap->homeqlist.data[i].name);
	}

	pktEncodeHspotAnqpNaiHomeRealmQuery(pkt, hspotap->homeqlist.count,
		bcm_encode_length(&name), bcm_encode_buf(&name));
}

static void encodeHomeRealm(hspotApT *hspotap, bcm_encode_t *pkt)
{
	uint8 tlsAuthBuf[BUFFER_SIZE];
	bcm_encode_t tlsAuth;
	uint8 tlsEapBuf[BUFFER_SIZE];
	bcm_encode_t tlsEap;
	uint8 realmBuf[BUFFER_SIZE];
	bcm_encode_t realm;
	uint8 credential;

	/* TLS - certificate */
	bcm_encode_init(&tlsAuth, sizeof(tlsAuthBuf), tlsAuthBuf);
	credential = REALM_CERTIFICATE;
	bcm_encode_anqp_authentication_subfield(&tlsAuth,
		REALM_CREDENTIAL, sizeof(credential), &credential);
	bcm_encode_init(&tlsEap, sizeof(tlsEapBuf), tlsEapBuf);
	bcm_encode_anqp_eap_method_subfield(&tlsEap, REALM_EAP_TLS,
		1, bcm_encode_length(&tlsAuth), bcm_encode_buf(&tlsAuth));

	bcm_encode_init(&realm, sizeof(realmBuf), realmBuf);

	/* example */
	bcm_encode_anqp_nai_realm_data(&realm, REALM_ENCODING_RFC4282,
		strlen(HOME_REALM), (uint8 *)HOME_REALM, 1,
		bcm_encode_length(&tlsEap), bcm_encode_buf(&tlsEap));
	bcm_encode_anqp_nai_realm(pkt, 1,
		bcm_encode_length(&realm), bcm_encode_buf(&realm));
}

/* malloc'ed buffer returned must be freed by caller */
int hspotReadFile(char *filename, int *bufSize, uint8 **buf)
{
	int ret = FALSE;
	FILE *fp;
	long int size;
	uint8 *buffer;
	size_t result;

	fp = fopen(filename, "rb");
	if (fp == 0) {
		/* printf("error %d opening %s\n", errno, filename); */
		/* free(filename); */
		return ret;
	}

	fseek(fp, 0, SEEK_END);
	size = ftell(fp);
	rewind(fp);

	buffer = malloc(size);
	if (buffer == 0) {
		goto done;
	}

	result = fread(buffer, 1, size, fp);
	if ((int)result != size) {
		goto done;
	}

	/* printf("read %d bytes from %s\n", (int)size, filename); */
	*bufSize = size;
	*buf = buffer;
	ret = TRUE;

	done:
	fclose(fp);
	return ret;
}

static void processQueryRequest(hspotApT *hspotap,
	bcm_gas_t *gas, int len, uint8 *data)
{
	/* Get Timestamp */
	/* unsigned long long now = getTimestamp(); */
	/* printf("HS_TRACE : 0 Timestamp for starting processQueryRequest : %llu \n", now ); */

	int bufferSize = QUERY_REQUEST_BUFFER;
	uint8 *buffer;
	bcm_decode_t pkt;
	bcm_decode_anqp_t anqp;
	bcm_encode_t rsp;
	int responseSize, disable_ANQP_response;

	TRACE_HEX_DUMP(TRACE_DEBUG, "query request", len, data);

	if (hspotap->testResponseSize > QUERY_REQUEST_BUFFER) {
		bufferSize = hspotap->testResponseSize;
	}

	buffer = malloc(bufferSize);
	if (buffer == 0)
		return;

	memset(buffer, 0, bufferSize);

	bcm_encode_init(&rsp, bufferSize, buffer);

	/* decode ANQP */
	bcm_decode_init(&pkt, len, data);
	bcm_decode_anqp(&pkt, &anqp);

	/* decode query list and encode response */
	if (anqp.anqpQueryListLength > 0) {
		bcm_decode_t ie;
		bcm_decode_anqp_query_list_t queryList;
		int i;

		bcm_decode_init(&ie, anqp.anqpQueryListLength, anqp.anqpQueryListBuffer);
		if (bcm_decode_anqp_query_list(&ie, &queryList))
			bcm_decode_anqp_query_list_print(&queryList);
		/* else */
			/* printf("failed to decode query list\n"); */

		for (i = 0; i < queryList.queryLen; i++) {
			switch (queryList.queryId[i])
			{
			case ANQP_ID_QUERY_LIST:
				break;
			case ANQP_ID_CAPABILITY_LIST:
				encodeAnqpCapabilityList(hspotap, &rsp);
				break;
			case ANQP_ID_VENUE_NAME_INFO:
				encodeVenueName(hspotap, &rsp);
				break;
			case ANQP_ID_EMERGENCY_CALL_NUMBER_INFO:
				break;
			case ANQP_ID_NETWORK_AUTHENTICATION_TYPE_INFO:
				encodeNetworkAuthenticationType(hspotap, &rsp);
				break;
			case ANQP_ID_ROAMING_CONSORTIUM_LIST:
				encodeRoamingConsortium(hspotap, &rsp);
				break;
			case ANQP_ID_IP_ADDRESS_TYPE_AVAILABILITY_INFO:
				encodeIpAddressType(hspotap, &rsp);
				break;
			case ANQP_ID_NAI_REALM_LIST:
				encodeNaiRealmList(hspotap, &rsp);
				break;
			case ANQP_ID_G3PP_CELLULAR_NETWORK_INFO:
				encode3GppCellularNetwork(hspotap, &rsp);
				break;
			case ANQP_ID_AP_GEOSPATIAL_LOCATION:
				break;
			case ANQP_ID_AP_CIVIC_LOCATION:
				break;
			case ANQP_ID_AP_LOCATION_PUBLIC_ID_URI:
				break;
			case ANQP_ID_DOMAIN_NAME_LIST:
				encodeDomainNameList(hspotap, &rsp);
				break;
			case ANQP_ID_EMERGENCY_ALERT_ID_URI:
				break;
			case ANQP_ID_EMERGENCY_NAI:
				break;
			case ANQP_ID_VENDOR_SPECIFIC_LIST:
				break;
			default:
				break;
			}
		}
	}

	if (anqp.hspot.queryListLength > 0) {
		bcm_decode_t ie;
		bcm_decode_hspot_anqp_query_list_t queryList;
		int i;

		bcm_decode_init(&ie, anqp.hspot.queryListLength, anqp.hspot.queryListBuffer);
		if (bcm_decode_hspot_anqp_query_list(&ie, &queryList))
			bcm_decode_hspot_anqp_query_list_print(&queryList);
		/* else */
			/* printf("failed to decode passpoint query list\n"); */

		for (i = 0; i < queryList.queryLen; i++) {
			switch (queryList.queryId[i])
			{
			case HSPOT_SUBTYPE_QUERY_LIST:
				break;
			case HSPOT_SUBTYPE_CAPABILITY_LIST:
				encodeHspotCapabilityList(hspotap, &rsp);
				break;
			case HSPOT_SUBTYPE_OPERATOR_FRIENDLY_NAME:
				encodeOperatorFriendlyName(hspotap, &rsp);
				break;
			case HSPOT_SUBTYPE_WAN_METRICS:
				encodeWanMetrics(hspotap, &rsp);
				break;
			case HSPOT_SUBTYPE_CONNECTION_CAPABILITY:
				encodeConnectionCapability(hspotap, &rsp);
				break;
			case HSPOT_SUBTYPE_NAI_HOME_REALM_QUERY:
				encodeNaiHomeRealmQuery(hspotap, &rsp);
				break;
			case HSPOT_SUBTYPE_OPERATING_CLASS_INDICATION:
				encodeHspotOperatingClassIndication(hspotap, &rsp);
				break;
			case HSPOT_SUBTYPE_ONLINE_SIGNUP_PROVIDERS:
				encodeHspotOsuProviders(hspotap, &rsp);
				break;
			case HSPOT_SUBTYPE_ANONYMOUS_NAI:
				encodeHspotAnonymousNai(hspotap, &rsp);
				break;
			case HSPOT_SUBTYPE_ICON_BINARY_FILE:
				break;
			default:
				break;
			}
		}
	}

	if (anqp.hspot.naiHomeRealmQueryLength > 0) {

		bcm_decode_t ie;
		bcm_decode_hspot_anqp_nai_home_realm_query_t realm;
		int i;
		int isMatch = FALSE;

		bcm_decode_init(&ie, anqp.hspot.naiHomeRealmQueryLength,
			anqp.hspot.naiHomeRealmQueryBuffer);
		if (bcm_decode_hspot_anqp_nai_home_realm_query(&ie, &realm))
			bcm_decode_hspot_anqp_nai_home_realm_query_print(&realm);
		/* else */
			/* printf("failed to decode passpoint hrq\n"); */

		for (i = 0; i < realm.count; i++) {
			if (strcmp(realm.data[i].name, HOME_REALM) == 0)
				isMatch = TRUE;
		}

		if (isMatch)
			encodeHomeRealm(hspotap, &rsp);
		else
			bcm_encode_anqp_nai_realm(&rsp, 0, 0, 0);
	}

	if (anqp.hspot.iconRequestLength > 0) {
		bcm_decode_t ie;
		bcm_decode_hspot_anqp_icon_request_t request;

		bcm_decode_init(&ie, anqp.hspot.iconRequestLength,
			anqp.hspot.iconRequestBuffer);
		if (bcm_decode_hspot_anqp_icon_request(&ie, &request)) {
			int size;
			uint8 *buf;

			bcm_decode_hspot_anqp_icon_request_print(&request);

			char fullpath[NVRAM_MAX_VALUE_LEN];
			char filename[NVRAM_MAX_PARAM_LEN];
			memset(filename, 0, sizeof(filename));
			memset(fullpath, 0, sizeof(fullpath));
			if (hspotap->osuicon_id == 2) {
				strncpy_n(filename,
					"wifi-abgn-logo_270x73.png", NVRAM_MAX_PARAM_LEN);
			}
			else {
				strncpy_n(filename, request.filename, NVRAM_MAX_PARAM_LEN);
			}

			/* printf("Icon Path name = %s \n", filename); */
			if (filename != NULL) {
				strncpy_n(fullpath, ICONPATH, NVRAM_MAX_VALUE_LEN);
				strncat(fullpath, filename, min(strlen(filename),
					NVRAM_MAX_VALUE_LEN-strlen(fullpath)));
				if (hspotReadFile(fullpath, &size, &buf)) {
					bcm_encode_hspot_anqp_icon_binary_file(&rsp,
						HSPOT_ICON_STATUS_SUCCESS, 9,
						(uint8 *)"image/png", size, buf);
					free(buf);
				}
				else {
					bcm_encode_hspot_anqp_icon_binary_file(&rsp,
					HSPOT_ICON_STATUS_FILE_NOT_FOUND, 0, 0, 0, 0);
				}
			}
			/* else */
				/* printf("Icon File name is Empty\n"); */
		}
	}

	responseSize = bcm_encode_length(&rsp);

	/* pad response to testResponseSize */
	if (hspotap->testResponseSize > responseSize) {
		responseSize = hspotap->testResponseSize;
	}

	disable_ANQP_response = Get_hspot_flag(hspotap->prefix, HSFLG_DS_ANQP_RESP);

	/* printf("%30s  <-----  query response %d bytes %d\n", "", */
	/* responseSize, disable_ANQP_response); */

	if (!disable_ANQP_response)
		bcm_gas_set_query_response(gas, responseSize, bcm_encode_buf(&rsp));

	/* unsigned long long then = getTimestamp(); */
	/* printf("HS_TRACE : 100 Timestamp for starting processQueryRequest : %llu \n", then ); */
	/* printf("===================================================== \n"); */
	/* printf("HS_TRACE : Final: Timestamp for processQueryRequest : %llu \n", then-now ); */
	/* printf("===================================================== \n"); */

	free(buffer);
}

static int gasEventHandler(hspotApT *hspotap, bcm_gas_event_t *event, uint16 *status)
{
	hspotPrintGasEvent(event);

	if (event->type == BCM_GAS_EVENT_QUERY_REQUEST) {
		processQueryRequest(hspotap, event->gas,
			event->queryReq.len, event->queryReq.data);
	}
	else if (event->type == BCM_GAS_EVENT_STATUS) {
#if TESTING_MODE
		/* toggle setting */
		hspotap->isGasPauseForServerResponse =
			hspotap->isGasPauseForServerResponse ? FALSE : TRUE;
		TRACE(TRACE_DEBUG, "pause for server response: %s\n",
			hspotap->isGasPauseForServerResponse ? "TRUE" : "FALSE");
		bcm_gas_set_if_gas_pause(hspotap->isGasPauseForServerResponse, hspotap->ifr);
#endif
		if (status != 0)
			*status = event->status.statusCode;
		return TRUE;
	}

	return FALSE;
}

static void gasEventCallback(void *context, bcm_gas_t *gas, bcm_gas_event_t *event)
{
	(void)context;
	hspotApT *hspotap;
	hspotap = getHspotApByWlif(bcm_gas_get_drv(gas));
	if (hspotap == NULL) {
		/* printf("can't find matched hspotap\n"); */
		return;
	}

	if (gasEventHandler(hspotap, event, 0))
	{
		/* printf("EVENT_GAS_DONE\n"); */
	}
}

static int update_dgaf_disable(hspotApT *hspotap)
{
	int err = 0, isDgafDisabled;
	isDgafDisabled = Get_hspot_flag(hspotap->prefix, HSFLG_DGAF_DS);

	if (isDgafDisabled) {
		if (wl_dhcp_unicast(hspotap->ifr, 1) < 0) {
			err = -1;
			TRACE(TRACE_ERROR, "wl_dhcp_unicast failed\n");
		}
		if (wl_block_multicast(hspotap->ifr, 1) < 0) {
			err = -1;
			TRACE(TRACE_ERROR, "wl_block_multicast failed\n");
		}
		if (wl_gtk_per_sta(hspotap->ifr, 1) < 0) {
			err = -1;
			TRACE(TRACE_ERROR, "wl_gtk_per_sta failed\n");
		}
	} else {
		if (wl_gtk_per_sta(hspotap->ifr, 0) < 0) {
			err = -1;
			TRACE(TRACE_ERROR, "wl_gtk_per_sta failed\n");
		}
		if (wl_block_multicast(hspotap->ifr, 0) < 0) {
			err = -1;
			TRACE(TRACE_ERROR, "wl_block_multicast failed\n");
		}
		if (wl_dhcp_unicast(hspotap->ifr, 0) < 0) {
			err = -1;
			TRACE(TRACE_ERROR, "wl_dhcp_unicast failed\n");
		}
	}

	return err;
}

static int update_l2_traffic_inspect(hspotApT *hspotap)
{
	int err = 0, icmpv4_echo, l2_traffic_inspect;
	l2_traffic_inspect = Get_hspot_flag(hspotap->prefix, HSFLG_L2_TRF);
	icmpv4_echo = Get_hspot_flag(hspotap->prefix, HSFLG_ICMPV4_ECHO);

	if (l2_traffic_inspect) {
		if (wl_block_ping(hspotap->ifr, !icmpv4_echo) < 0) {
			err = -1;
			TRACE(TRACE_ERROR, "wl_block_ping failed\n");
		}
		if (wl_block_sta(hspotap->ifr, 0) < 0) {
			err = -1;
			TRACE(TRACE_ERROR, "wl_block_sta failed\n");
		}
		if (wl_ap_isolate(hspotap->ifr, 0) < 0) {
			err = -1;
			TRACE(TRACE_ERROR, "wl_ap_isolate failed\n");
		}
	}
	else {
		if (wl_block_ping(hspotap->ifr, 0) < 0) {
			err = -1;
			TRACE(TRACE_ERROR, "wl_block_ping failed\n");
		}
		if (wl_block_sta(hspotap->ifr, 1) < 0) {
			err = -1;
			TRACE(TRACE_ERROR, "wl_block_sta failed\n");
		}
		if (wl_ap_isolate(hspotap->ifr, 1) < 0) {
			err = -1;
			TRACE(TRACE_ERROR, "wl_ap_isolate failed\n");
		}
	}
	return err;
}

static void init_wlan_hspot(hspotApT *hspotap)
{
	/* delete interworking IE */
	if (hspotap->hs_ie_enabled) {
		if (wl_bssload(hspotap->ifr, 1) < 0)
			TRACE(TRACE_ERROR, "wl_bssload failed\n");
	}
	else if (wl_bssload(hspotap->ifr, 0) < 0)
		TRACE(TRACE_ERROR, "wl_bssload failed\n");

	if (wl_dls(hspotap->ifr, 1) < 0)
		TRACE(TRACE_ERROR, "wl_dls failed\n");

	if (wl_wnm(hspotap->ifr, WNM_DEFAULT_BITMASK) < 0)
		TRACE(TRACE_ERROR, "wl_wnm failed\n");
	if (wl_interworking(hspotap->ifr, 1) < 0)
		TRACE(TRACE_ERROR, "wl_interworking failed\n");

	if (wl_probresp_sw(hspotap->ifr, 1) < 0)
		TRACE(TRACE_ERROR, "wl_probresp_sw failed\n");
#ifdef __CONFIG_DHDAP__
	if (!dhd_probe(hspotap->ifr)) {
		int index = -1;
		get_ifname_unit(hspotap->ifr, NULL, &index);
		if (dhd_bssiovar_setint(hspotap->ifr, "proxy_arp",
			((index == -1) ? 0 : index), 1) < 0)
			TRACE(TRACE_ERROR, "dhd proxy_arp failed\n");
	} else
#endif
	/* enable proxy ARP */
	if ((wl_wnm(hspotap->ifr, WNM_DEFAULT_BITMASK | WL_WNM_PROXYARP) < 0) ||
		(wl_wnm_parp_discard(hspotap->ifr, 1) < 0) ||
		(wl_wnm_parp_allnode(hspotap->ifr, 0) < 0))
		TRACE(TRACE_ERROR, "wl_proxy_arp failed\n");

	if (wl_grat_arp(hspotap->ifr, 1) < 0)
		TRACE(TRACE_ERROR, "wl_grat_arp failed\n");

	if (wl_block_tdls(hspotap->ifr, 1) < 0)
		TRACE(TRACE_ERROR, "wl_block_tdls failed\n");
	if (wl_dls_reject(hspotap->ifr, 1) < 0)
		TRACE(TRACE_ERROR, "wl_dls_reject failed\n");

	update_dgaf_disable(hspotap);
	update_l2_traffic_inspect(hspotap);
}


static void addIes_u11(hspotApT *hspotap)
{
	/* enable interworking */
	if (wl_interworking(hspotap->ifr, 1) < 0)
		TRACE(TRACE_ERROR, "wl_interworking failed\n");

	update_iw_ie(hspotap, TRUE);
}

static void addIes_hs(hspotApT *hspotap)
{
	vendorIeT *vendorIeHSI = &hspotap->vendorIeHSI;
	vendorIeT *vendorIeP2P = &hspotap->vendorIeP2P;

	int p2p_ie_enabled, p2p_cross_enabled, isDgafDisabled;
	p2p_ie_enabled = Get_hspot_flag(hspotap->prefix, HSFLG_P2P);
	p2p_cross_enabled = Get_hspot_flag(hspotap->prefix, HSFLG_P2P_CRS);
	isDgafDisabled = Get_hspot_flag(hspotap->prefix, HSFLG_DGAF_DS);

	bcm_encode_t ie;

	/* encode Passpoint vendor IE */
	bcm_encode_init(&ie, sizeof(vendorIeHSI->ieData), vendorIeHSI->ieData);
	bcm_encode_ie_hotspot_indication2(&ie, !isDgafDisabled, hspotap->hs_capable,
		FALSE, 0, FALSE, 0);
	vendorIeHSI->ieLength = bcm_encode_length(&ie);

	/* add to beacon and probe response */
	vendorIeHSI->pktflag = VNDR_IE_BEACON_FLAG | VNDR_IE_PRBRSP_FLAG;

	/* delete IEs first if not a clean shutdown */
	wl_del_vndr_ie(hspotap->ifr, DEFAULT_BSSCFG_INDEX, vendorIeHSI->pktflag,
		vendorIeHSI->ieLength - 2, vendorIeHSI->ieData + 2);

	bcm_encode_init(&ie, sizeof(vendorIeHSI->ieData), vendorIeHSI->ieData);
	bcm_encode_ie_hotspot_indication2(&ie, isDgafDisabled, hspotap->hs_capable,
		FALSE, 0, FALSE, 0);

	/* delete IEs first if not a clean shutdown */
	wl_del_vndr_ie(hspotap->ifr, DEFAULT_BSSCFG_INDEX, vendorIeHSI->pktflag,
		vendorIeHSI->ieLength - 2, vendorIeHSI->ieData + 2);

	/* don't need first 2 bytes (0xdd + len) */
	if (wl_add_vndr_ie(hspotap->ifr, DEFAULT_BSSCFG_INDEX, vendorIeHSI->pktflag,
		vendorIeHSI->ieLength - 2, vendorIeHSI->ieData + 2) < 0)
		TRACE(TRACE_ERROR, "failed to add vendor IE\n");


	if (p2p_ie_enabled) {

		/* encode P2P vendor IE */
		/* P2P Manageability attribute with P2P Device Management bit (B0) set to 1 and */
		/* the Cross Connection Permitted bit (B1) set to zero */
		vendorIeP2P->ieLength = 10;
		vendorIeP2P->ieData[0] = 0xDD;
		vendorIeP2P->ieData[1] = 0x08;
		vendorIeP2P->ieData[2] = 0x50;
		vendorIeP2P->ieData[3] = 0x6f;
		vendorIeP2P->ieData[4] = 0x9a;
		vendorIeP2P->ieData[5] = 0x09;
		vendorIeP2P->ieData[6] = 0x0a;
		vendorIeP2P->ieData[7] = 0x01;
		vendorIeP2P->ieData[8] = 0x00;
		vendorIeP2P->ieData[9] = 0x03;

		/* add to beacon and probe response */
		vendorIeP2P->pktflag = VNDR_IE_BEACON_FLAG | VNDR_IE_PRBRSP_FLAG;

		/* delete IEs first if not a clean shutdown */
		wl_del_vndr_ie(hspotap->ifr, DEFAULT_BSSCFG_INDEX, vendorIeP2P->pktflag,
			vendorIeP2P->ieLength - 2, vendorIeP2P->ieData + 2);

		vendorIeP2P->ieData[9] = 0x01;
		/* delete IEs first if not a clean shutdown */
		wl_del_vndr_ie(hspotap->ifr, DEFAULT_BSSCFG_INDEX, vendorIeP2P->pktflag,
			vendorIeP2P->ieLength - 2, vendorIeP2P->ieData + 2);
		if (p2p_cross_enabled)
			vendorIeP2P->ieData[9] = 0x03;
		/* don't need first 2 bytes (0xdd + len) */
		if (wl_add_vndr_ie(hspotap->ifr, DEFAULT_BSSCFG_INDEX, vendorIeP2P->pktflag,
			vendorIeP2P->ieLength - 2, vendorIeP2P->ieData + 2) < 0)
			TRACE(TRACE_ERROR, "failed to add vendor IE\n");
	}

	update_rc_ie(hspotap);

	Set_hspot_flag(hspotap->prefix, HSFLG_ANQP, TRUE);
	Set_hspot_flag(hspotap->prefix, HSFLG_MIH, FALSE);
	update_ap_ie(hspotap);

	update_qosmap_ie(hspotap, FALSE);
	update_bssload_ie(hspotap, FALSE, TRUE);

	update_osen_ie(hspotap, TRUE);

	init_wlan_hspot(hspotap);
}

static void addIes(hspotApT *hspotap)
{
	if (hspotap->iw_enabled)
		addIes_u11(hspotap);

	if (hspotap->hs_ie_enabled)
		addIes_hs(hspotap);
}

static void deleteIes_u11(hspotApT *hspotap)
{
	/* delete interworking IE */
	if (wl_ie(hspotap->ifr, DOT11_MNG_INTERWORKING_ID, 0, 0) < 0)
		TRACE(TRACE_ERROR, "failed delete IW IE\n");

	/* disable interworking - need to make it per BSS */
	/* if (wl_interworking(hspotap->ifr, 0) < 0) */
	/*	TRACE(TRACE_ERROR, "wl_interworking failed\n"); */
}

static void deleteIes_hs(hspotApT *hspotap)
{
	vendorIeT *vendorIeHSI = &hspotap->vendorIeHSI;
	vendorIeT *vendorIeP2P = &hspotap->vendorIeP2P;
	int p2p_ie_enabled;
	p2p_ie_enabled = Get_hspot_flag(hspotap->prefix, HSFLG_P2P);

	/* delete Passpoint vendor IE */
	wl_del_vndr_ie(hspotap->ifr, DEFAULT_BSSCFG_INDEX, vendorIeHSI->pktflag,
		vendorIeHSI->ieLength - 2, vendorIeHSI->ieData + 2);

	/* delete P2P vendor IE */
	if (p2p_ie_enabled) {
		wl_del_vndr_ie(hspotap->ifr, DEFAULT_BSSCFG_INDEX, vendorIeP2P->pktflag,
			vendorIeP2P->ieLength - 2, vendorIeP2P->ieData + 2);
	}

	/* delete advertisement protocol IE */
	if (wl_ie(hspotap->ifr, DOT11_MNG_ADVERTISEMENT_ID, 0, 0) < 0)
		TRACE(TRACE_ERROR, "failed delete AP IE\n");

	/* delete roaming consortium IE */
	if (wl_ie(hspotap->ifr, DOT11_MNG_ROAM_CONSORT_ID, 0, 0) < 0)
		TRACE(TRACE_ERROR, "failed delete RC IE\n");

	/* delete QoS Map IE */
	if (wl_ie(hspotap->ifr, DOT11_MNG_QOS_MAP_ID, 0, 0) < 0)
		TRACE(TRACE_ERROR, "failed delete QOS Map IE\n");

	/* delete BSS Load IE */
	hspotap->bssload_id = 0;
	update_bssload_ie(hspotap, FALSE, FALSE);

	/* disable OSEN */
	if (wl_osen(hspotap->ifr, 0) < 0)
		TRACE(TRACE_ERROR, "wl_osen failed\n");

}

static void deleteIes(hspotApT *hspotap)
{
	if (hspotap->hs_ie_enabled)
		deleteIes_hs(hspotap);

	if (hspotap->iw_enabled)
		deleteIes_u11(hspotap);
}

static int update_iw_ie(hspotApT *hspotap, bool disable)
{
	int err = 0;

	if (hspotap->iw_enabled) {
		bcm_encode_t ie;
		uint8 buffer[BUFFER_SIZE];

		/* encode interworking IE */
		bcm_encode_init(&ie, sizeof(buffer), buffer);
		bcm_encode_ie_interworking(&ie, hspotap->iw_ANT, hspotap->iw_isInternet,
			FALSE, FALSE, FALSE,
			TRUE, hspotap->venuelist.group, hspotap->venuelist.type,
			hspotap->iw_isHESSIDPresent ? &hspotap->iw_HESSID : 0);

		/* add interworking IE */
		err = wl_ie(hspotap->ifr, DOT11_MNG_INTERWORKING_ID,
		bcm_encode_length(&ie) - 2, bcm_encode_buf(&ie) + 2);
		if (err)
			TRACE(TRACE_ERROR, "failed add IW IE\n");
	}
	else if (disable) {
		/* delete interworking IE */
		err = wl_ie(hspotap->ifr, DOT11_MNG_INTERWORKING_ID, 0, 0);
		if (err)
			TRACE(TRACE_ERROR, "failed delete IW IE\n");
	}
	return err;
}

static int update_qosmap_ie(hspotApT *hspotap, bool enable)
{
	int err = 0;

	if (enable)
	{
		bcm_encode_t ie;
		uint8 buffer[BUFFER_SIZE];

		/* encode QoS Map IE */
		bcm_encode_init(&ie, sizeof(buffer), buffer);
		if (hspotap->qos_id == 1) {
			bcm_encode_qos_map(&ie, 4, (uint8 *)"\x35\x02\x16\x06",
				8, 15, 0, 7, 255, 255, 16, 31, 32, 39, 255, 255, 40, 47, 255, 255);
		}
		else if (hspotap->qos_id == 2) {
			bcm_encode_qos_map(&ie, 0, NULL,
				8, 15, 0, 7, 255, 255, 16, 31, 32, 39, 255, 255, 40, 47, 48, 63);
		}

		/* add QoS Map IE */
		err = wl_ie(hspotap->ifr, DOT11_MNG_QOS_MAP_ID,
		bcm_encode_length(&ie) - 4, bcm_encode_buf(&ie) + 4);

		if (err)
			TRACE(TRACE_ERROR, "failed add QOS Map IE\n");
	}
	else {
		/* delete QoS Map IE */
		err = wl_ie(hspotap->ifr, DOT11_MNG_QOS_MAP_ID, 0, 0);
		if (err)
			TRACE(TRACE_ERROR, "failed delete QOS Map IE\n");
	}
	return err;
}


static int update_bssload_ie(hspotApT *hspotap, bool isStatic, bool enable)
{
	int err = 0;

	wl_bssload_static_t bssload;
	memset(&bssload, 0, sizeof(bssload));

	if (enable && isStatic) {

		/* Static BSS Load IE Enabled */
		bssload.is_static = TRUE;
		bssload.sta_count = 1;
		bssload.aac = 65535;
		bssload.chan_util =
			(hspotap->bssload_id == 1 ? 50 : (hspotap->bssload_id == 2 ? 200 : 75));
	}

	/* Static /Dynamic BSS Load IE choosen */
	err = wl_bssload_static(hspotap->ifr, bssload.is_static,
		bssload.sta_count, bssload.chan_util, bssload.aac);
	if (err < 0)
		TRACE(TRACE_ERROR, "wl_bssload_static failed\n");

	/* BSS Load IE Enabled /Disabled */
	err = wl_bssload(hspotap->ifr, enable);
	if (err < 0)
		TRACE(TRACE_ERROR, "wl_bssload failed\n");

	return err;

}

static int update_osen_ie(hspotApT *hspotap, bool disable)
{
	int osen_ie_enabled = Get_hspot_flag(hspotap->prefix, HSFLG_OSEN);

	if (osen_ie_enabled)
	{
		/* Enable OSEN */
		if (wl_osen(hspotap->ifr, osen_ie_enabled) < 0) {
			TRACE(TRACE_ERROR, "wl_osen failed\n");
		}
	}
	else if (disable) {
		/* Disable OSEN */
		if (wl_osen(hspotap->ifr, 0) < 0) {
			TRACE(TRACE_ERROR, "wl_osen failed\n");
		}
	}
	return 0;
}

static int update_rc_ie(hspotApT *hspotap)
{
	int err = 0;

	if (hspotap->ouilist.numOi) {

		bcm_encode_t ie;
		uint8 buffer[BUFFER_SIZE];
		/* encode roaming consortium IE */
		bcm_encode_init(&ie, sizeof(buffer), buffer);
		bcm_encode_ie_roaming_consortium(&ie,
			hspotap->ouilist.numOi > 3 ? (hspotap->ouilist.numOi - 3) : 0,
			hspotap->ouilist.numOi > 0 ? hspotap->ouilist.oi[0].oiLen : 0,
			hspotap->ouilist.oi[0].oi,
			hspotap->ouilist.numOi > 1 ? hspotap->ouilist.oi[1].oiLen : 0,
			hspotap->ouilist.oi[1].oi,
			hspotap->ouilist.numOi > 2 ? hspotap->ouilist.oi[2].oiLen : 0,
			hspotap->ouilist.oi[2].oi);

		/* add roaming consortium IE */
		err = wl_ie(hspotap->ifr, DOT11_MNG_ROAM_CONSORT_ID,
		bcm_encode_length(&ie) - 2, bcm_encode_buf(&ie) + 2);
		if (err)
			TRACE(TRACE_ERROR, "failed add RC IE\n");
	}
	else {
		/* delete roaming consortium IE */
		err = wl_ie(hspotap->ifr, DOT11_MNG_ROAM_CONSORT_ID, 0, 0);
		if (err)
			TRACE(TRACE_ERROR, "failed delete RC IE\n");
	}
	return err;
}

static int update_ap_ie(hspotApT *hspotap)
{
	int ap_ANQPenabled = Get_hspot_flag(hspotap->prefix, HSFLG_ANQP);
	int ap_MIHenabled  = Get_hspot_flag(hspotap->prefix, HSFLG_MIH);

	int err = 0;
	if (ap_ANQPenabled || ap_MIHenabled) {
		bcm_encode_t ie;
		uint8 buffer[BUFFER_SIZE];
		uint8 adBuffer[BUFFER_SIZE];
		bcm_encode_t ad;

		/* encode advertisement protocol IE */
		bcm_encode_init(&ie, sizeof(buffer), buffer);
		bcm_encode_init(&ad, sizeof(adBuffer), adBuffer);
		bcm_encode_ie_advertisement_protocol_tuple(&ad, 0x7f, FALSE,
			ap_ANQPenabled ? ADVP_ANQP_PROTOCOL_ID : MIH_PROTOCOL_ID);
		bcm_encode_ie_advertisement_protocol_from_tuple(&ie,
			bcm_encode_length(&ad), bcm_encode_buf(&ad));

		/* add advertisement protocol IE */
		err = wl_ie(hspotap->ifr, DOT11_MNG_ADVERTISEMENT_ID,
		bcm_encode_length(&ie) - 2, bcm_encode_buf(&ie) + 2);
		if (err)
			TRACE(TRACE_ERROR, "failed add AP IE\n");
	}
	else {
		/* delete advertisement protocol IE */
		err = wl_ie(hspotap->ifr, DOT11_MNG_ADVERTISEMENT_ID, 0, 0);
		if (err)
			TRACE(TRACE_ERROR, "failed delete AP IE\n");
	}
	return err;
}

static int hspot_cmd_osen_handler(hspotApT *hspotap,
	char **argv, char *txData, bool *set_tx_data)
{
	int err = 0, osen_ie_enabled;

	if (argv[0] == NULL) {
		printf("missing parameter in command osen_ie_enabled\n");
		return -1;
	}

	osen_ie_enabled = (atoi(argv[0]) != 0);
	Set_hspot_flag(hspotap->prefix, HSFLG_OSEN, osen_ie_enabled);
	/* printf("osen_ie_enabled %d\n", osen_ie_enabled); */

	/* OSEN enabled and DGAF disabled are always done together */
	Set_hspot_flag(hspotap->prefix, HSFLG_DGAF_DS, osen_ie_enabled);
	err = update_dgaf_disable(hspotap);

	err = update_osen_ie(hspotap, TRUE);
	return err;
}

static int hspot_cmd_internet_handler(hspotApT *hspotap,
	char **argv, char *txData, bool *set_tx_data)
{
	int err = 0, ret;
	char varvalue[NVRAM_MAX_VALUE_LEN];
	char varname[NVRAM_MAX_PARAM_LEN];

	if (argv[0] == NULL) {
		printf("missing parameter in command internet\n");
		return -1;
	}

	hspotap->iw_isInternet = (atoi(argv[0]) != 0);
	printf("iw_isInternet %d\n", hspotap->iw_isInternet);

	snprintf(varvalue, sizeof(varvalue), "%d", hspotap->iw_isInternet);
	ret = nvram_set(strcat_r(hspotap->prefix, "iwint", varname), varvalue);
	if (ret) {
		printf("nvram_set %s=%s failure\n", varname, varvalue);
		err = -1;
	}
	nvram_commit();

	err = update_iw_ie(hspotap, FALSE);
	return err;
}

static int hspot_cmd_accs_net_type_handler(hspotApT *hspotap,
	char **argv, char *txData, bool *set_tx_data)
{
	int err = 0, ret;
	char varvalue[NVRAM_MAX_VALUE_LEN];
	char varname[NVRAM_MAX_PARAM_LEN];

	if (argv[0] == NULL) {
		printf("missing parameter in command accs_net_type\n");
		return -1;
	}

	hspotap->iw_ANT = atoi(argv[0]);
	printf("iw_ANT %d\n", hspotap->iw_ANT);

	snprintf(varvalue, sizeof(varvalue), "%d", hspotap->iw_ANT);
	ret = nvram_set(strcat_r(hspotap->prefix, "iwnettype", varname), varvalue);
	if (ret) {
		printf("nvram_set %s=%s failure\n", varname, varvalue);
		err = -1;
	}
	nvram_commit();

	err = update_iw_ie(hspotap, FALSE);
	return err;
}

static int hspot_cmd_hessid_handler(hspotApT *hspotap,
	char **argv, char *txData, bool *set_tx_data)
{
	int err = 0, ret;
	char varvalue[NVRAM_MAX_VALUE_LEN];
	char varname[NVRAM_MAX_PARAM_LEN];

	if (argv[0] == NULL) {
		hspotap->iw_isHESSIDPresent = FALSE;
		printf("HESSID is not present\n");
	}
	else {
		hspotap->iw_isHESSIDPresent = TRUE;
		if (!strToEther(argv[0], &hspotap->iw_HESSID)) {
			printf("wrong format parameter in command hessid\n");
			return -1;
		}

		snprintf(varvalue, sizeof(varvalue), "%02x:%02x:%02x:%02x:%02x:%02x",
			hspotap->iw_HESSID.octet[0], hspotap->iw_HESSID.octet[1],
			hspotap->iw_HESSID.octet[2], hspotap->iw_HESSID.octet[3],
			hspotap->iw_HESSID.octet[4], hspotap->iw_HESSID.octet[5]);
		ret = nvram_set(strcat_r(hspotap->prefix, "hessid", varname), varvalue);
		if (ret) {
			printf("nvram_set %s=%s failure\n", varname, varvalue);
			err = -1;
		}
		nvram_commit();

		printf("HESSID 0x%x 0x%x 0x%x 0x%x 0x%x 0x%x\n",
			hspotap->iw_HESSID.octet[0], hspotap->iw_HESSID.octet[1],
			hspotap->iw_HESSID.octet[2], hspotap->iw_HESSID.octet[3],
			hspotap->iw_HESSID.octet[4], hspotap->iw_HESSID.octet[5]);
	}

	err = update_iw_ie(hspotap, FALSE);
	return err;
}

static int hspot_cmd_venue_type_handler(hspotApT *hspotap,
	char **argv, char *txData, bool *set_tx_data)
{
	int ret, err = 0;
	char varvalue[NVRAM_MAX_VALUE_LEN];
	char varname[NVRAM_MAX_PARAM_LEN];

	if (argv[0] == NULL) {
		printf("missing parameter in command venue_type\n");
		return -1;
	}

	hspotap->venuelist.type = atoi(argv[0]);
	printf("venuelist.type %d\n", hspotap->venuelist.type);

	memset(varvalue, 0, NVRAM_MAX_VALUE_LEN);
	snprintf(varvalue, sizeof(varvalue), "%d", hspotap->venuelist.type);
	ret = nvram_set(strcat_r(hspotap->prefix, "venuetype", varname), varvalue);
	if (ret) {
		printf("nvram_set %s=%s failure\n", varname, varvalue);
		err = -1;
	}
	nvram_commit();

	err = update_iw_ie(hspotap, FALSE);

	return err;
}

static int hspot_cmd_venue_grp_handler(hspotApT *hspotap,
	char **argv, char *txData, bool *set_tx_data)
{
	int ret, err = 0;
	char varvalue[NVRAM_MAX_VALUE_LEN];
	char varname[NVRAM_MAX_PARAM_LEN];

	if (argv[0] == NULL) {
		printf("missing parameter in command venue_grp\n");
		return -1;
	}

	hspotap->venuelist.group = atoi(argv[0]);
	printf("venuelist.group %d\n", hspotap->venuelist.group);

	memset(varvalue, 0, NVRAM_MAX_VALUE_LEN);
	snprintf(varvalue, sizeof(varvalue), "%d", hspotap->venuelist.group);
	ret = nvram_set(strcat_r(hspotap->prefix, "venuegrp", varname), varvalue);
	if (ret) {
		printf("nvram_set %s=%s failure\n", varname, varvalue);
		err = -1;
	}
	nvram_commit();

	err = update_iw_ie(hspotap, FALSE);

	return err;
}

static int hspot_cmd_venue_name_handler(hspotApT *hspotap,
	char **argv, char *txData, bool *set_tx_data)
{
	int err = 0, venue_id = 1;

	if (argv[0] == NULL) {
		printf("missing parameter in command venue_name\n");
		return -1;
	}

	venue_id = atoi(argv[0]);
	printf("venue_id %d\n", venue_id);

	if (venue_id == 1)
		err = Reset_VenueList(hspotap, TRUE, 0x0004);

	return err;
}

static int hspot_cmd_anonymous_nai_handler(hspotApT *hspotap,
	char **argv, char *txData, bool *set_tx_data)
{
	int err = 0;
	char varname[NVRAM_MAX_PARAM_LEN];
	int ret;

	memset(&hspotap->anonai, 0, sizeof(bcm_decode_hspot_anqp_anonymous_nai_t));
	hspotap->anonai.isDecodeValid = TRUE;

	if (argv[0] == NULL) {
		printf("missing parameter in command anonymous_nai\n");
		strncpy_n(hspotap->anonai.nai,
		"anonymous.com", BCM_DECODE_HSPOT_ANQP_MAX_NAI_SIZE + 1);
	}
	else {
		printf("Anonymous_NAI = %s\n", argv[0]);
		strncpy_n(hspotap->anonai.nai, argv[0], BCM_DECODE_HSPOT_ANQP_MAX_NAI_SIZE + 1);
	}

	hspotap->anonai.naiLen = strlen(hspotap->anonai.nai);

	ret = nvram_set(strcat_r(hspotap->prefix, "anonai", varname), argv[0]);
	if (ret) {
		printf("nvram_set %s=%s failure\n", varname, argv[0]);
		err = -1;
	}

	nvram_commit();
	return err;
}

static int hspot_cmd_osu_provider_list_handler(hspotApT *hspotap,
	char **argv, char *txData, bool *set_tx_data)
{
	int err = 0, ret, osup_id = 1, index = 0;
	char varname[NVRAM_MAX_PARAM_LEN];

	if (argv[0] == NULL) {
		printf("missing parameter in command osu_provider_list\n");
		osup_id = 1;
	}
	else {
		osup_id = atoi(argv[0]);
		printf("osu_provider_list id = %d\n", osup_id);
	}

	switch (osup_id)
	{
	case 1:
	{
		hspotap->osuplist.isDecodeValid = TRUE;
		hspotap->osuplist.osuProviderCount = 1;
		/* OSU_Friendly_Name */
		hspotap->osuplist.osuProvider[0].name.isDecodeValid = TRUE;
		hspotap->osuplist.osuProvider[0].name.numName = 2;
		strncpy_n((char*)hspotap->osuplist.osuProvider[0].name.duple[0].lang,
			ENGLISH, VENUE_LANGUAGE_CODE_SIZE +1);
		hspotap->osuplist.osuProvider[0].name.duple[0].langLen =
			strlen(ENGLISH);
		strncpy_n((char*)hspotap->osuplist.osuProvider[0].name.duple[0].name,
			ENG_OPNAME_SP_RED, VENUE_NAME_SIZE + 1);
		hspotap->osuplist.osuProvider[0].name.duple[0].nameLen =
			strlen(ENG_OPNAME_SP_RED);
		strncpy_n(hspotap->osuplist.osuProvider[0].name.duple[1].lang,
			KOREAN, VENUE_LANGUAGE_CODE_SIZE +1);
		hspotap->osuplist.osuProvider[0].name.duple[1].langLen =
			strlen(KOREAN);
		strncpy_n(hspotap->osuplist.osuProvider[0].name.duple[1].name,
			(char *)kor_opname_sp_red, VENUE_NAME_SIZE + 1);
		hspotap->osuplist.osuProvider[0].name.duple[1].nameLen =
			sizeof(kor_opname_sp_red);
		ret = nvram_set(strcat_r(hspotap->prefix, "osu_frndname", varname),
			"SP Red Test Only!eng|"
			"\x53\x50\x20\xEB\xB9\xA8\xEA\xB0\x95\x20\xED\x85\x8C"
			"\xEC\x8A\xA4\xED\x8A\xB8\x20\xEC\xA0\x84\xEC\x9A\xA9!kor");
		if (ret) {
			printf("nvram_set %s=%s failure\n", varname,
			"SP Red Test Only!eng|"
			"\x53\x50\x20\xEB\xB9\xA8\xEA\xB0\x95\x20\xED\x85\x8C"
			"\xEC\x8A\xA4\xED\x8A\xB8\x20\xEC\xA0\x84\xEC\x9A\xA9!kor");
			err = -1;
		}
		/* OSU_Icons */
		hspotap->osuplist.osuProvider[0].iconMetadataCount = 2;
		hspotap->osuplist.osuProvider[0].iconMetadata[0].width = 128;
		hspotap->osuplist.osuProvider[0].iconMetadata[0].height = 61;
		strncpy_n((char*)hspotap->osuplist.osuProvider[0].iconMetadata[0].lang,
			LANG_ZXX, VENUE_LANGUAGE_CODE_SIZE +1);
		strncpy_n((char*)hspotap->osuplist.osuProvider[0].iconMetadata[0].type,
			ICON_TYPE_ID1, BCM_DECODE_HSPOT_ANQP_MAX_ICON_TYPE_LENGTH + 1);
		hspotap->osuplist.osuProvider[0].iconMetadata[0].typeLength = strlen(ICON_TYPE_ID1);
		strncpy_n((char*)hspotap->osuplist.osuProvider[0].iconMetadata[0].filename,
			ICON_FILENAME_RED_ZXX, BCM_DECODE_HSPOT_ANQP_MAX_ICON_FILENAME_LENGTH + 1);
		hspotap->osuplist.osuProvider[0].iconMetadata[0].filenameLength =
			strlen(ICON_FILENAME_RED_ZXX);
		/* Icon Metadata 2 */
		hspotap->osuplist.osuProvider[0].iconMetadata[1].width = 160;
		hspotap->osuplist.osuProvider[0].iconMetadata[1].height = 76;
		strncpy_n((char*)hspotap->osuplist.osuProvider[0].iconMetadata[1].lang,
			ENGLISH, VENUE_LANGUAGE_CODE_SIZE +1);
		strncpy_n((char*)hspotap->osuplist.osuProvider[0].iconMetadata[1].type,
			ICON_TYPE_ID1, BCM_DECODE_HSPOT_ANQP_MAX_ICON_TYPE_LENGTH + 1);
		hspotap->osuplist.osuProvider[0].iconMetadata[1].typeLength = strlen(ICON_TYPE_ID1);
		strncpy_n((char*)hspotap->osuplist.osuProvider[0].iconMetadata[1].filename,
			ICON_FILENAME_RED, BCM_DECODE_HSPOT_ANQP_MAX_ICON_FILENAME_LENGTH + 1);
		hspotap->osuplist.osuProvider[0].iconMetadata[1].filenameLength =
			strlen(ICON_FILENAME_RED);
		ret = nvram_set(strcat_r(hspotap->prefix, "osu_icons", varname),
			"icon_red_zxx.png+icon_red_eng.png");
		if (ret) {
			printf("nvram_set %s=%s failure\n", varname,
			"icon_red_zxx.png+icon_red_eng.png");
			err = -1;
		}
		/* OSU_NAI */
		strncpy_n((char*)hspotap->osuplist.osuProvider[0].nai, "",
			BCM_DECODE_HSPOT_ANQP_MAX_NAI_LENGTH + 1);
		hspotap->osuplist.osuProvider[0].naiLength = 0;
		ret = nvram_set(strcat_r(hspotap->prefix, "osu_nai", varname),
			"");
		if (ret) {
			printf("nvram_set %s=%s failure\n", varname,
			"");
			err = -1;
		}
		/* OSU_Server_Desc */
		hspotap->osuplist.osuProvider[0].desc.isDecodeValid = TRUE;
		hspotap->osuplist.osuProvider[0].desc.numName = 2;
		strncpy_n((char*)hspotap->osuplist.osuProvider[0].desc.duple[0].lang,
			ENGLISH, VENUE_LANGUAGE_CODE_SIZE +1);
		hspotap->osuplist.osuProvider[0].desc.duple[0].langLen =
			strlen(ENGLISH);
		strncpy_n((char*)hspotap->osuplist.osuProvider[0].desc.duple[0].name,
			OSU_SERVICE_DESC_ID1, VENUE_NAME_SIZE + 1);
		hspotap->osuplist.osuProvider[0].desc.duple[0].nameLen =
			strlen(OSU_SERVICE_DESC_ID1);
		strncpy_n((char*)hspotap->osuplist.osuProvider[0].desc.duple[1].lang,
			KOREAN, VENUE_LANGUAGE_CODE_SIZE +1);
		hspotap->osuplist.osuProvider[0].desc.duple[1].langLen =
			strlen(KOREAN);
		strncpy_n((char*)hspotap->osuplist.osuProvider[0].desc.duple[1].name,
			(char *)kor_desc_name_id1, VENUE_NAME_SIZE + 1);
		hspotap->osuplist.osuProvider[0].desc.duple[1].nameLen =
			sizeof(kor_desc_name_id1);

		ret = nvram_set(strcat_r(hspotap->prefix, "osu_servdesc", varname),
			"Free service for test purpose!eng|"
			"\xED\x85\x8C\xEC\x8A\xA4\xED\x8A\xB8\x20\xEB\xAA\xA9"
			"\xEC\xA0\x81\xEC\x9C\xBC\xEB\xA1\x9C\x20\xEB\xAC\xB4"
			"\xEB\xA3\x8C\x20\xEC\x84\x9C\xEB\xB9\x84\xEC\x8A\xA4!kor");
		if (ret) {
			printf("nvram_set %s=%s failure\n", varname,
			"Free service for test purpose!eng|"
			"\xED\x85\x8C\xEC\x8A\xA4\xED\x8A\xB8\x20\xEB\xAA\xA9"
			"\xEC\xA0\x81\xEC\x9C\xBC\xEB\xA1\x9C\x20\xEB\xAC\xB4"
			"\xEB\xA3\x8C\x20\xEC\x84\x9C\xEB\xB9\x84\xEC\x8A\xA4!kor");
			err = -1;
		}

		for (index = 1; index < MAX_OSU_PROVIDERS; index++)
			memset(&hspotap->osuplist.osuProvider[index], 0,
				sizeof(hspotap->osuplist.osuProvider[index]));
	}
	break;

	case 2:
	{
		hspotap->osuplist.isDecodeValid = TRUE;
		hspotap->osuplist.osuProviderCount = 1;
		/* OSU_Friendly_Name */
		hspotap->osuplist.osuProvider[0].name.isDecodeValid = TRUE;
		hspotap->osuplist.osuProvider[0].name.numName = 2;
		strncpy_n((char*)hspotap->osuplist.osuProvider[0].name.duple[0].lang,
			ENGLISH, VENUE_LANGUAGE_CODE_SIZE +1);
		hspotap->osuplist.osuProvider[0].name.duple[0].langLen =
			strlen(ENGLISH);
		strncpy_n((char*)hspotap->osuplist.osuProvider[0].name.duple[0].name,
			ENG_OPNAME_WBA, VENUE_NAME_SIZE + 1);
		hspotap->osuplist.osuProvider[0].name.duple[0].nameLen =
			strlen(ENG_OPNAME_WBA);
		strncpy_n(hspotap->osuplist.osuProvider[0].name.duple[1].lang,
			KOREAN, VENUE_LANGUAGE_CODE_SIZE +1);
		hspotap->osuplist.osuProvider[0].name.duple[1].langLen =
			strlen(KOREAN);
		strncpy_n(hspotap->osuplist.osuProvider[0].name.duple[1].name,
			(char *)kor_opname_wba, VENUE_NAME_SIZE + 1);
		hspotap->osuplist.osuProvider[0].name.duple[1].nameLen =
			sizeof(kor_opname_wba);
		ret = nvram_set(strcat_r(hspotap->prefix, "osu_frndname", varname),
			"Wireless Broadband Allianc!eng|"
			"\xEC\x99\x80\xEC\x9D\xB4\xEC\x96\xB4\xEB\xA6\xAC\xEC\x8A\xA4\x20"
			"\xEB\xB8\x8C\xEB\xA1\x9C\xEB\x93\x9C\xEB\xB0\xB4\xEB\x93\x9C\x20"
			"\xEC\x96\xBC\xEB\x9D\xBC\xEC\x9D\xB4\xEC\x96\xB8\xEC\x8A\xA4!kor");
		if (ret) {
			printf("nvram_set %s=%s failure\n", varname,
			"Wireless Broadband Allianc!eng|"
			"\xEC\x99\x80\xEC\x9D\xB4\xEC\x96\xB4\xEB\xA6\xAC\xEC\x8A\xA4\x20"
			"\xEB\xB8\x8C\xEB\xA1\x9C\xEB\x93\x9C\xEB\xB0\xB4\xEB\x93\x9C\x20"
			"\xEC\x96\xBC\xEB\x9D\xBC\xEC\x9D\xB4\xEC\x96\xB8\xEC\x8A\xA4!kor");
			err = -1;
		}
		/* OSU_Icons */
		hspotap->osuplist.osuProvider[0].iconMetadataCount = 1;
		hspotap->osuplist.osuProvider[0].iconMetadata[0].width = 128;
		hspotap->osuplist.osuProvider[0].iconMetadata[0].height = 61;
		strncpy_n((char*)hspotap->osuplist.osuProvider[0].iconMetadata[0].lang,
			LANG_ZXX, VENUE_LANGUAGE_CODE_SIZE +1);
		strncpy_n((char*)hspotap->osuplist.osuProvider[0].iconMetadata[0].type,
			ICON_TYPE_ID1, BCM_DECODE_HSPOT_ANQP_MAX_ICON_TYPE_LENGTH + 1);
		hspotap->osuplist.osuProvider[0].iconMetadata[0].typeLength = strlen(ICON_TYPE_ID1);
		strncpy_n((char*)hspotap->osuplist.osuProvider[0].iconMetadata[0].filename,
			ICON_FILENAME_GREEN_ZXX,
			BCM_DECODE_HSPOT_ANQP_MAX_ICON_FILENAME_LENGTH + 1);
		hspotap->osuplist.osuProvider[0].iconMetadata[0].filenameLength =
			strlen(ICON_FILENAME_GREEN_ZXX);
		ret = nvram_set(strcat_r(hspotap->prefix, "osu_icons", varname),
			"icon_green_zxx.png");
		if (ret) {
			printf("nvram_set %s=%s failure\n", varname,
			"icon_green_zxx.png");
			err = -1;
		}
		/* OSU_NAI */
		strncpy_n((char*)hspotap->osuplist.osuProvider[0].nai, "",
			BCM_DECODE_HSPOT_ANQP_MAX_NAI_LENGTH + 1);
		hspotap->osuplist.osuProvider[0].naiLength = 0;
		ret = nvram_set(strcat_r(hspotap->prefix, "osu_nai", varname),
			"");
		if (ret) {
			printf("nvram_set %s=%s failure\n", varname,
			"");
			err = -1;
		}
		/* OSU_Server_Desc */
		hspotap->osuplist.osuProvider[0].desc.isDecodeValid = TRUE;
		hspotap->osuplist.osuProvider[0].desc.numName = 2;
		strncpy_n((char*)hspotap->osuplist.osuProvider[0].desc.duple[0].lang,
			ENGLISH, VENUE_LANGUAGE_CODE_SIZE +1);
		hspotap->osuplist.osuProvider[0].desc.duple[0].langLen =
			strlen(ENGLISH);
		strncpy_n((char*)hspotap->osuplist.osuProvider[0].desc.duple[0].name,
			OSU_SERVICE_DESC_ID1, VENUE_NAME_SIZE + 1);
		hspotap->osuplist.osuProvider[0].desc.duple[0].nameLen =
			strlen(OSU_SERVICE_DESC_ID1);
		strncpy_n((char*)hspotap->osuplist.osuProvider[0].desc.duple[1].lang,
			KOREAN, VENUE_LANGUAGE_CODE_SIZE +1);
		hspotap->osuplist.osuProvider[0].desc.duple[1].langLen =
			strlen(KOREAN);
		strncpy_n((char*)hspotap->osuplist.osuProvider[0].desc.duple[1].name,
			(char *)kor_desc_name_id1, VENUE_NAME_SIZE + 1);
		hspotap->osuplist.osuProvider[0].desc.duple[1].nameLen =
			sizeof(kor_desc_name_id1);

		ret = nvram_set(strcat_r(hspotap->prefix, "osu_servdesc", varname),
			"Free service for test purpose!eng|"
			"\xED\x85\x8C\xEC\x8A\xA4\xED\x8A\xB8\x20\xEB\xAA\xA9"
			"\xEC\xA0\x81\xEC\x9C\xBC\xEB\xA1\x9C\x20\xEB\xAC\xB4"
			"\xEB\xA3\x8C\x20\xEC\x84\x9C\xEB\xB9\x84\xEC\x8A\xA4!kor");
		if (ret) {
			printf("nvram_set %s=%s failure\n", varname,
			"Free service for test purpose!eng|"
			"\xED\x85\x8C\xEC\x8A\xA4\xED\x8A\xB8\x20\xEB\xAA\xA9"
			"\xEC\xA0\x81\xEC\x9C\xBC\xEB\xA1\x9C\x20\xEB\xAC\xB4"
			"\xEB\xA3\x8C\x20\xEC\x84\x9C\xEB\xB9\x84\xEC\x8A\xA4!kor");
			err = -1;
		}

		for (index = 1; index < MAX_OSU_PROVIDERS; index++)
			memset(&hspotap->osuplist.osuProvider[index], 0,
				sizeof(hspotap->osuplist.osuProvider[index]));
	}
	break;

	case 3:
	{
		hspotap->osuplist.isDecodeValid = TRUE;
		hspotap->osuplist.osuProviderCount = 1;
		/* OSU_Friendly_Name */
		hspotap->osuplist.osuProvider[0].name.isDecodeValid = TRUE;
		hspotap->osuplist.osuProvider[0].name.numName = 1;
		strncpy_n((char*)hspotap->osuplist.osuProvider[0].name.duple[0].lang,
			SPANISH, VENUE_LANGUAGE_CODE_SIZE +1);
		hspotap->osuplist.osuProvider[0].name.duple[0].langLen =
			strlen(SPANISH);
		strncpy_n((char*)hspotap->osuplist.osuProvider[0].name.duple[0].name,
			ENG_OPNAME_SP_RED, VENUE_NAME_SIZE + 1);
		hspotap->osuplist.osuProvider[0].name.duple[0].nameLen =
			strlen(ENG_OPNAME_SP_RED);
		ret = nvram_set(strcat_r(hspotap->prefix, "osu_frndname", varname),
			"SP Red Test Only!spa");
		if (ret) {
			printf("nvram_set %s=%s failure\n", varname,
			"SP Red Test Only!spa");
			err = -1;
		}
		/* OSU_Icons */
		hspotap->osuplist.osuProvider[0].iconMetadataCount = 1;
		hspotap->osuplist.osuProvider[0].iconMetadata[0].width = 128;
		hspotap->osuplist.osuProvider[0].iconMetadata[0].height = 61;
		strncpy_n((char*)hspotap->osuplist.osuProvider[0].iconMetadata[0].lang,
			LANG_ZXX, VENUE_LANGUAGE_CODE_SIZE +1);
		strncpy_n((char*)hspotap->osuplist.osuProvider[0].iconMetadata[0].type,
			ICON_TYPE_ID1, BCM_DECODE_HSPOT_ANQP_MAX_ICON_TYPE_LENGTH + 1);
		hspotap->osuplist.osuProvider[0].iconMetadata[0].typeLength = strlen(ICON_TYPE_ID1);
		strncpy_n((char*)hspotap->osuplist.osuProvider[0].iconMetadata[0].filename,
			ICON_FILENAME_RED_ZXX, BCM_DECODE_HSPOT_ANQP_MAX_ICON_FILENAME_LENGTH + 1);
		hspotap->osuplist.osuProvider[0].iconMetadata[0].filenameLength =
			strlen(ICON_FILENAME_RED_ZXX);
		ret = nvram_set(strcat_r(hspotap->prefix, "osu_icons", varname),
			"icon_red_zxx.png");
		if (ret) {
			printf("nvram_set %s=%s failure\n", varname,
			"icon_red_zxx.png");
			err = -1;
		}
		/* OSU_NAI */
		strncpy_n((char*)hspotap->osuplist.osuProvider[0].nai, "",
			BCM_DECODE_HSPOT_ANQP_MAX_NAI_LENGTH + 1);
		hspotap->osuplist.osuProvider[0].naiLength = 0;
		ret = nvram_set(strcat_r(hspotap->prefix, "osu_nai", varname),
			"");
		if (ret) {
			printf("nvram_set %s=%s failure\n", varname,
			"");
			err = -1;
		}
		/* OSU_Server_Desc */
		hspotap->osuplist.osuProvider[0].desc.isDecodeValid = TRUE;
		hspotap->osuplist.osuProvider[0].desc.numName = 1;
		strncpy_n((char*)hspotap->osuplist.osuProvider[0].desc.duple[0].lang,
			SPANISH, VENUE_LANGUAGE_CODE_SIZE +1);
		hspotap->osuplist.osuProvider[0].desc.duple[0].langLen =
			strlen(SPANISH);
		strncpy_n((char*)hspotap->osuplist.osuProvider[0].desc.duple[0].name,
			OSU_SERVICE_DESC_ID1, VENUE_NAME_SIZE + 1);
		hspotap->osuplist.osuProvider[0].desc.duple[0].nameLen =
			strlen(OSU_SERVICE_DESC_ID1);

		ret = nvram_set(strcat_r(hspotap->prefix, "osu_servdesc", varname),
			"Free service for test purpose!spa");
		if (ret) {
			printf("nvram_set %s=%s failure\n", varname,
			"Free service for test purpose!spa");
			err = -1;
		}

		for (index = 1; index < MAX_OSU_PROVIDERS; index++)
			memset(&hspotap->osuplist.osuProvider[index], 0,
				sizeof(hspotap->osuplist.osuProvider[index]));
	}
	break;

	case 4:
	{
		hspotap->osuplist.isDecodeValid = TRUE;
		hspotap->osuplist.osuProviderCount = 1;
		/* OSU_Friendly_Name */
		hspotap->osuplist.osuProvider[0].name.isDecodeValid = TRUE;
		hspotap->osuplist.osuProvider[0].name.numName = 2;
		strncpy_n((char*)hspotap->osuplist.osuProvider[0].name.duple[0].lang,
			ENGLISH, VENUE_LANGUAGE_CODE_SIZE +1);
		hspotap->osuplist.osuProvider[0].name.duple[0].langLen =
			strlen(ENGLISH);
		strncpy_n((char*)hspotap->osuplist.osuProvider[0].name.duple[0].name,
			ENG_OPNAME_SP_BLUE, VENUE_NAME_SIZE + 1);
		hspotap->osuplist.osuProvider[0].name.duple[0].nameLen =
			strlen(ENG_OPNAME_SP_BLUE);
		strncpy_n(hspotap->osuplist.osuProvider[0].name.duple[1].lang,
			KOREAN, VENUE_LANGUAGE_CODE_SIZE +1);
		hspotap->osuplist.osuProvider[0].name.duple[1].langLen =
			strlen(KOREAN);
		strncpy_n(hspotap->osuplist.osuProvider[0].name.duple[1].name,
			(char *)kor_opname_sp_blu, VENUE_NAME_SIZE + 1);
		hspotap->osuplist.osuProvider[0].name.duple[1].nameLen =
			sizeof(kor_opname_sp_blu);
		ret = nvram_set(strcat_r(hspotap->prefix, "osu_frndname", varname),
			"SP Blue Test Only!eng|"
			"\x53\x50\x20\xED\x8C\x8C\xEB\x9E\x91\x20\xED\x85\x8C"
			"\xEC\x8A\xA4\xED\x8A\xB8\x20\xEC\xA0\x84\xEC\x9A\xA9!kor");
		if (ret) {
			printf("nvram_set %s=%s failure\n", varname,
			"SP Blue Test Only!eng|"
			"\x53\x50\x20\xED\x8C\x8C\xEB\x9E\x91\x20\xED\x85\x8C"
			"\xEC\x8A\xA4\xED\x8A\xB8\x20\xEC\xA0\x84\xEC\x9A\xA9!kor");
			err = -1;
		}
		/* OSU_Icons */
		hspotap->osuplist.osuProvider[0].iconMetadataCount = 2;
		hspotap->osuplist.osuProvider[0].iconMetadata[0].width = 128;
		hspotap->osuplist.osuProvider[0].iconMetadata[0].height = 61;
		strncpy_n((char*)hspotap->osuplist.osuProvider[0].iconMetadata[0].lang,
			LANG_ZXX, VENUE_LANGUAGE_CODE_SIZE +1);
		strncpy_n((char*)hspotap->osuplist.osuProvider[0].iconMetadata[0].type,
			ICON_TYPE_ID1, BCM_DECODE_HSPOT_ANQP_MAX_ICON_TYPE_LENGTH + 1);
		hspotap->osuplist.osuProvider[0].iconMetadata[0].typeLength = strlen(ICON_TYPE_ID1);
		strncpy_n((char*)hspotap->osuplist.osuProvider[0].iconMetadata[0].filename,
			ICON_FILENAME_BLUE_ZXX, BCM_DECODE_HSPOT_ANQP_MAX_ICON_FILENAME_LENGTH + 1);
		hspotap->osuplist.osuProvider[0].iconMetadata[0].filenameLength =
			strlen(ICON_FILENAME_BLUE_ZXX);
		/* Icon Metadata 2 */
		hspotap->osuplist.osuProvider[0].iconMetadata[1].width = 160;
		hspotap->osuplist.osuProvider[0].iconMetadata[1].height = 76;
		strncpy_n((char*)hspotap->osuplist.osuProvider[0].iconMetadata[1].lang,
			ENGLISH, VENUE_LANGUAGE_CODE_SIZE +1);
		strncpy_n((char*)hspotap->osuplist.osuProvider[0].iconMetadata[1].type,
			ICON_TYPE_ID1, BCM_DECODE_HSPOT_ANQP_MAX_ICON_TYPE_LENGTH + 1);
		hspotap->osuplist.osuProvider[0].iconMetadata[1].typeLength = strlen(ICON_TYPE_ID1);
		strncpy_n((char*)hspotap->osuplist.osuProvider[0].iconMetadata[1].filename,
			ICON_FILENAME_BLUE, BCM_DECODE_HSPOT_ANQP_MAX_ICON_FILENAME_LENGTH + 1);
		hspotap->osuplist.osuProvider[0].iconMetadata[1].filenameLength =
			strlen(ICON_FILENAME_BLUE);
		ret = nvram_set(strcat_r(hspotap->prefix, "osu_icons", varname),
			"icon_blue_zxx.png+icon_blue_eng.png");
		if (ret) {
			printf("nvram_set %s=%s failure\n", varname,
			"icon_blue_zxx.png+icon_blue_eng.png");
			err = -1;
		}
		/* OSU_NAI */
		strncpy_n((char*)hspotap->osuplist.osuProvider[0].nai, "",
			BCM_DECODE_HSPOT_ANQP_MAX_NAI_LENGTH + 1);
		hspotap->osuplist.osuProvider[0].naiLength = 0;
		ret = nvram_set(strcat_r(hspotap->prefix, "osu_nai", varname),
			"");
		if (ret) {
			printf("nvram_set %s=%s failure\n", varname,
			"");
			err = -1;
		}
		/* OSU_Server_Desc */
		hspotap->osuplist.osuProvider[0].desc.isDecodeValid = TRUE;
		hspotap->osuplist.osuProvider[0].desc.numName = 2;
		strncpy_n((char*)hspotap->osuplist.osuProvider[0].desc.duple[0].lang,
			ENGLISH, VENUE_LANGUAGE_CODE_SIZE +1);
		hspotap->osuplist.osuProvider[0].desc.duple[0].langLen =
			strlen(ENGLISH);
		strncpy_n((char*)hspotap->osuplist.osuProvider[0].desc.duple[0].name,
			OSU_SERVICE_DESC_ID1, VENUE_NAME_SIZE + 1);
		hspotap->osuplist.osuProvider[0].desc.duple[0].nameLen =
			strlen(OSU_SERVICE_DESC_ID1);
		strncpy_n((char*)hspotap->osuplist.osuProvider[0].desc.duple[1].lang,
			KOREAN, VENUE_LANGUAGE_CODE_SIZE +1);
		hspotap->osuplist.osuProvider[0].desc.duple[1].langLen =
			strlen(KOREAN);
		strncpy_n((char*)hspotap->osuplist.osuProvider[0].desc.duple[1].name,
			(char *)kor_desc_name_id1, VENUE_NAME_SIZE + 1);
		hspotap->osuplist.osuProvider[0].desc.duple[1].nameLen =
			sizeof(kor_desc_name_id1);

		ret = nvram_set(strcat_r(hspotap->prefix, "osu_servdesc", varname),
			"Free service for test purpose!eng|"
			"\xED\x85\x8C\xEC\x8A\xA4\xED\x8A\xB8\x20\xEB\xAA\xA9"
			"\xEC\xA0\x81\xEC\x9C\xBC\xEB\xA1\x9C\x20\xEB\xAC\xB4"
			"\xEB\xA3\x8C\x20\xEC\x84\x9C\xEB\xB9\x84\xEC\x8A\xA4!kor");
		if (ret) {
			printf("nvram_set %s=%s failure\n", varname,
			"Free service for test purpose!eng|"
			"\xED\x85\x8C\xEC\x8A\xA4\xED\x8A\xB8\x20\xEB\xAA\xA9"
			"\xEC\xA0\x81\xEC\x9C\xBC\xEB\xA1\x9C\x20\xEB\xAC\xB4"
			"\xEB\xA3\x8C\x20\xEC\x84\x9C\xEB\xB9\x84\xEC\x8A\xA4!kor");
			err = -1;
		}

		for (index = 1; index < MAX_OSU_PROVIDERS; index++)
			memset(&hspotap->osuplist.osuProvider[index], 0,
				sizeof(hspotap->osuplist.osuProvider[index]));
	}
	break;

	case 5:
	{
		hspotap->osuplist.isDecodeValid = TRUE;
		hspotap->osuplist.osuProviderCount = 1;
		/* OSU_Friendly_Name */
		hspotap->osuplist.osuProvider[0].name.isDecodeValid = TRUE;
		hspotap->osuplist.osuProvider[0].name.numName = 2;
		strncpy_n((char*)hspotap->osuplist.osuProvider[0].name.duple[0].lang,
			ENGLISH, VENUE_LANGUAGE_CODE_SIZE +1);
		hspotap->osuplist.osuProvider[0].name.duple[0].langLen =
			strlen(ENGLISH);
		strncpy_n((char*)hspotap->osuplist.osuProvider[0].name.duple[0].name,
			ENG_OPNAME_SP_BLUE, VENUE_NAME_SIZE + 1);
		hspotap->osuplist.osuProvider[0].name.duple[0].nameLen =
			strlen(ENG_OPNAME_SP_BLUE);
		strncpy_n(hspotap->osuplist.osuProvider[0].name.duple[1].lang,
			KOREAN, VENUE_LANGUAGE_CODE_SIZE +1);
		hspotap->osuplist.osuProvider[0].name.duple[1].langLen =
			strlen(KOREAN);
		strncpy_n(hspotap->osuplist.osuProvider[0].name.duple[1].name,
			(char *)kor_opname_sp_blu, VENUE_NAME_SIZE + 1);
		hspotap->osuplist.osuProvider[0].name.duple[1].nameLen =
			sizeof(kor_opname_sp_blu);
		ret = nvram_set(strcat_r(hspotap->prefix, "osu_frndname", varname),
			"SP Blue Test Only!eng|"
			"\x53\x50\x20\xED\x8C\x8C\xEB\x9E\x91\x20\xED\x85\x8C"
			"\xEC\x8A\xA4\xED\x8A\xB8\x20\xEC\xA0\x84\xEC\x9A\xA9!kor");
		if (ret) {
			printf("nvram_set %s=%s failure\n", varname,
			"SP Blue Test Only!eng|"
			"\x53\x50\x20\xED\x8C\x8C\xEB\x9E\x91\x20\xED\x85\x8C"
			"\xEC\x8A\xA4\xED\x8A\xB8\x20\xEC\xA0\x84\xEC\x9A\xA9!kor");
			err = -1;
		}
		/* OSU_Icons */
		hspotap->osuplist.osuProvider[0].iconMetadataCount = 1;
		hspotap->osuplist.osuProvider[0].iconMetadata[0].width = 128;
		hspotap->osuplist.osuProvider[0].iconMetadata[0].height = 61;
		strncpy_n((char*)hspotap->osuplist.osuProvider[0].iconMetadata[0].lang,
			LANG_ZXX, VENUE_LANGUAGE_CODE_SIZE +1);
		strncpy_n((char*)hspotap->osuplist.osuProvider[0].iconMetadata[0].type,
			ICON_TYPE_ID1, BCM_DECODE_HSPOT_ANQP_MAX_ICON_TYPE_LENGTH + 1);
		hspotap->osuplist.osuProvider[0].iconMetadata[0].typeLength = strlen(ICON_TYPE_ID1);
		strncpy_n((char*)hspotap->osuplist.osuProvider[0].iconMetadata[0].filename,
			ICON_FILENAME_BLUE_ZXX, BCM_DECODE_HSPOT_ANQP_MAX_ICON_FILENAME_LENGTH + 1);
		hspotap->osuplist.osuProvider[0].iconMetadata[0].filenameLength =
			strlen(ICON_FILENAME_BLUE_ZXX);
		ret = nvram_set(strcat_r(hspotap->prefix, "osu_icons", varname),
			"icon_blue_zxx.png");
		if (ret) {
			printf("nvram_set %s=%s failure\n", varname,
			"icon_blue_zxx.png");
			err = -1;
		}
		/* OSU_NAI */
		strncpy_n((char*)hspotap->osuplist.osuProvider[0].nai, "",
			BCM_DECODE_HSPOT_ANQP_MAX_NAI_LENGTH + 1);
		hspotap->osuplist.osuProvider[0].naiLength = 0;
		ret = nvram_set(strcat_r(hspotap->prefix, "osu_nai", varname),
			"");
		if (ret) {
			printf("nvram_set %s=%s failure\n", varname,
			"");
			err = -1;
		}
		/* OSU_Server_Desc */
		hspotap->osuplist.osuProvider[0].desc.isDecodeValid = TRUE;
		hspotap->osuplist.osuProvider[0].desc.numName = 2;
		strncpy_n((char*)hspotap->osuplist.osuProvider[0].desc.duple[0].lang,
			ENGLISH, VENUE_LANGUAGE_CODE_SIZE +1);
		hspotap->osuplist.osuProvider[0].desc.duple[0].langLen =
			strlen(ENGLISH);
		strncpy_n((char*)hspotap->osuplist.osuProvider[0].desc.duple[0].name,
			OSU_SERVICE_DESC_ID1, VENUE_NAME_SIZE + 1);
		hspotap->osuplist.osuProvider[0].desc.duple[0].nameLen =
			strlen(OSU_SERVICE_DESC_ID1);
		strncpy_n((char*)hspotap->osuplist.osuProvider[0].desc.duple[1].lang,
			KOREAN, VENUE_LANGUAGE_CODE_SIZE +1);
		hspotap->osuplist.osuProvider[0].desc.duple[1].langLen =
			strlen(KOREAN);
		strncpy_n((char*)hspotap->osuplist.osuProvider[0].desc.duple[1].name,
			(char *)kor_desc_name_id1, VENUE_NAME_SIZE + 1);
		hspotap->osuplist.osuProvider[0].desc.duple[1].nameLen =
			sizeof(kor_desc_name_id1);

		ret = nvram_set(strcat_r(hspotap->prefix, "osu_servdesc", varname),
			"Free service for test purpose!eng|"
			"\xED\x85\x8C\xEC\x8A\xA4\xED\x8A\xB8\x20\xEB\xAA\xA9"
			"\xEC\xA0\x81\xEC\x9C\xBC\xEB\xA1\x9C\x20\xEB\xAC\xB4"
			"\xEB\xA3\x8C\x20\xEC\x84\x9C\xEB\xB9\x84\xEC\x8A\xA4!kor");
		if (ret) {
			printf("nvram_set %s=%s failure\n", varname,
			"Free service for test purpose!eng|"
			"\xED\x85\x8C\xEC\x8A\xA4\xED\x8A\xB8\x20\xEB\xAA\xA9"
			"\xEC\xA0\x81\xEC\x9C\xBC\xEB\xA1\x9C\x20\xEB\xAC\xB4"
			"\xEB\xA3\x8C\x20\xEC\x84\x9C\xEB\xB9\x84\xEC\x8A\xA4!kor");
			err = -1;
		}

		for (index = 1; index < MAX_OSU_PROVIDERS; index++)
			memset(&hspotap->osuplist.osuProvider[index], 0,
				sizeof(hspotap->osuplist.osuProvider[index]));
	}
	break;

	case 6:
	{
		hspotap->osuplist.isDecodeValid = TRUE;
		hspotap->osuplist.osuProviderCount = 2;
		/* PROVIDER 1 */
		/* OSU_Friendly_Name */
		hspotap->osuplist.osuProvider[0].name.isDecodeValid = TRUE;
		hspotap->osuplist.osuProvider[0].name.numName = 2;
		strncpy_n((char*)hspotap->osuplist.osuProvider[0].name.duple[0].lang,
			ENGLISH, VENUE_LANGUAGE_CODE_SIZE +1);
		hspotap->osuplist.osuProvider[0].name.duple[0].langLen =
			strlen(ENGLISH);
		strncpy_n((char*)hspotap->osuplist.osuProvider[0].name.duple[0].name,
			ENG_OPNAME_SP_GREEN, VENUE_NAME_SIZE + 1);
		hspotap->osuplist.osuProvider[0].name.duple[0].nameLen =
			strlen(ENG_OPNAME_SP_GREEN);
		strncpy_n(hspotap->osuplist.osuProvider[0].name.duple[1].lang,
			KOREAN, VENUE_LANGUAGE_CODE_SIZE +1);
		hspotap->osuplist.osuProvider[0].name.duple[1].langLen =
			strlen(KOREAN);
		strncpy_n(hspotap->osuplist.osuProvider[0].name.duple[1].name,
			(char *)kor_opname_sp_grn, VENUE_NAME_SIZE + 1);
		hspotap->osuplist.osuProvider[0].name.duple[1].nameLen =
			sizeof(kor_opname_sp_grn);

		/* OSU_Icons */
		hspotap->osuplist.osuProvider[0].iconMetadataCount = 1;
		hspotap->osuplist.osuProvider[0].iconMetadata[0].width = 128;
		hspotap->osuplist.osuProvider[0].iconMetadata[0].height = 61;
		strncpy_n((char*)hspotap->osuplist.osuProvider[0].iconMetadata[0].lang,
			LANG_ZXX, VENUE_LANGUAGE_CODE_SIZE +1);
		strncpy_n((char*)hspotap->osuplist.osuProvider[0].iconMetadata[0].type,
			ICON_TYPE_ID1, BCM_DECODE_HSPOT_ANQP_MAX_ICON_TYPE_LENGTH + 1);
		hspotap->osuplist.osuProvider[0].iconMetadata[0].typeLength = strlen(ICON_TYPE_ID1);
		strncpy_n((char*)hspotap->osuplist.osuProvider[0].iconMetadata[0].filename,
			ICON_FILENAME_GREEN_ZXX,
			BCM_DECODE_HSPOT_ANQP_MAX_ICON_FILENAME_LENGTH + 1);
		hspotap->osuplist.osuProvider[0].iconMetadata[0].filenameLength =
			strlen(ICON_FILENAME_GREEN_ZXX);

		/* OSU_NAI */
		strncpy_n((char*)hspotap->osuplist.osuProvider[0].nai, "",
			BCM_DECODE_HSPOT_ANQP_MAX_NAI_LENGTH + 1);
		hspotap->osuplist.osuProvider[0].naiLength = 0;

		/* OSU_Server_Desc */
		memset(&hspotap->osuplist.osuProvider[0].desc, 0,
			sizeof(hspotap->osuplist.osuProvider[0].desc));

		/* PROVIDER 2 */
		/* OSU_Friendly_Name */
		hspotap->osuplist.osuProvider[1].name.isDecodeValid = TRUE;
		hspotap->osuplist.osuProvider[1].name.numName = 2;
		strncpy_n(hspotap->osuplist.osuProvider[1].name.duple[0].lang,
			ENGLISH, VENUE_LANGUAGE_CODE_SIZE +1);
		hspotap->osuplist.osuProvider[1].name.duple[0].langLen =
			strlen(ENGLISH);
		strncpy_n(hspotap->osuplist.osuProvider[1].name.duple[0].name,
			ENG_OPNAME_SP_ORANGE, VENUE_NAME_SIZE + 1);
		hspotap->osuplist.osuProvider[1].name.duple[0].nameLen =
			strlen(ENG_OPNAME_SP_ORANGE);
		strncpy_n(hspotap->osuplist.osuProvider[1].name.duple[1].lang,
			KOREAN, VENUE_LANGUAGE_CODE_SIZE +1);
		hspotap->osuplist.osuProvider[1].name.duple[1].langLen =
			strlen(KOREAN);
		strncpy_n(hspotap->osuplist.osuProvider[1].name.duple[1].name,
			(char *)kor_opname_sp_orng, VENUE_NAME_SIZE + 1);
		hspotap->osuplist.osuProvider[1].name.duple[1].nameLen =
			sizeof(kor_opname_sp_orng);

		ret = nvram_set(strcat_r(hspotap->prefix, "osu_frndname", varname),
			"SP Green Test Only!eng|"
			"\x53\x50\x20\xEC\xB4\x88\xEB\xA1\x9D\x20\xED\x85\x8C"
			"\xEC\x8A\xA4\xED\x8A\xB8\x20\xEC\xA0\x84\xEC\x9A\xA9!kor;"
			"SP Orange Test Only!eng|"
			"\x53\x50\x20\xEC\x98\xA4\xEB\xA0\x8C\xEC\xA7\x80\x20\xED"
			"\x85\x8C\xEC\x8A\xA4\xED\x8A\xB8\x20\xEC\xA0\x84\xEC\x9A\xA9!kor");
		if (ret) {
			printf("nvram_set %s=%s failure\n", varname,
			"SP Green Test Only!eng|"
			"\x53\x50\x20\xEC\xB4\x88\xEB\xA1\x9D\x20\xED\x85\x8C"
			"\xEC\x8A\xA4\xED\x8A\xB8\x20\xEC\xA0\x84\xEC\x9A\xA9!kor;"
			"SP Orange Test Only!eng|"
			"\x53\x50\x20\xEC\x98\xA4\xEB\xA0\x8C\xEC\xA7\x80\x20\xED"
			"\x85\x8C\xEC\x8A\xA4\xED\x8A\xB8\x20\xEC\xA0\x84\xEC\x9A\xA9!kor");
			err = -1;
		}

		/* OSU_Icons */
		hspotap->osuplist.osuProvider[1].iconMetadataCount = 1;
		hspotap->osuplist.osuProvider[1].iconMetadata[0].width = 128;
		hspotap->osuplist.osuProvider[1].iconMetadata[0].height = 61;
		strncpy_n((char*)hspotap->osuplist.osuProvider[1].iconMetadata[0].lang,
			LANG_ZXX, VENUE_LANGUAGE_CODE_SIZE +1);
		strncpy_n((char*)hspotap->osuplist.osuProvider[1].iconMetadata[0].type,
			ICON_TYPE_ID1, BCM_DECODE_HSPOT_ANQP_MAX_ICON_TYPE_LENGTH + 1);
		hspotap->osuplist.osuProvider[1].iconMetadata[0].typeLength = strlen(ICON_TYPE_ID1);
		strncpy_n((char*)hspotap->osuplist.osuProvider[1].iconMetadata[0].filename,
			ICON_FILENAME_ORANGE_ZXX,
			BCM_DECODE_HSPOT_ANQP_MAX_ICON_FILENAME_LENGTH + 1);
		hspotap->osuplist.osuProvider[1].iconMetadata[0].filenameLength =
			strlen(ICON_FILENAME_ORANGE_ZXX);

		ret = nvram_set(strcat_r(hspotap->prefix, "osu_icons", varname),
			"icon_green_zxx.png;"
			 "icon_orange_zxx.png");
		if (ret) {
			printf("nvram_set %s=%s failure\n", varname,
			"icon_green_zxx.png;"
			"icon_orange_zxx.png");
			err = -1;
		}

		/* OSU_NAI */
		strncpy_n((char*)hspotap->osuplist.osuProvider[1].nai, "",
			BCM_DECODE_HSPOT_ANQP_MAX_NAI_LENGTH + 1);
		hspotap->osuplist.osuProvider[1].naiLength = 0;
		ret = nvram_set(strcat_r(hspotap->prefix, "osu_nai", varname),
			"");
		if (ret) {
			printf("nvram_set %s=%s failure\n", varname,
			"");
			err = -1;
		}
		/* OSU_Server_Desc */
		memset(&hspotap->osuplist.osuProvider[1].desc, 0,
			sizeof(hspotap->osuplist.osuProvider[1].desc));

		ret = nvram_set(strcat_r(hspotap->prefix, "osu_servdesc", varname),
			"");
		if (ret) {
			printf("nvram_set %s=%s failure\n", varname,
			"");
			err = -1;
		}

		for (index = 2; index < MAX_OSU_PROVIDERS; index++)
			memset(&hspotap->osuplist.osuProvider[index], 0,
				sizeof(hspotap->osuplist.osuProvider[index]));
	}
	break;

	case 7:
	{
		hspotap->osuplist.isDecodeValid = TRUE;
		hspotap->osuplist.osuProviderCount = 1;
		/* OSU_Friendly_Name */
		hspotap->osuplist.osuProvider[0].name.isDecodeValid = TRUE;
		hspotap->osuplist.osuProvider[0].name.numName = 2;
		strncpy_n((char*)hspotap->osuplist.osuProvider[0].name.duple[0].lang,
			ENGLISH, VENUE_LANGUAGE_CODE_SIZE +1);
		hspotap->osuplist.osuProvider[0].name.duple[0].langLen =
			strlen(ENGLISH);
		strncpy_n((char*)hspotap->osuplist.osuProvider[0].name.duple[0].name,
			ENG_OPNAME_SP_ORANGE, VENUE_NAME_SIZE + 1);
		hspotap->osuplist.osuProvider[0].name.duple[0].nameLen =
			strlen(ENG_OPNAME_SP_ORANGE);
		strncpy_n(hspotap->osuplist.osuProvider[0].name.duple[1].lang,
			KOREAN, VENUE_LANGUAGE_CODE_SIZE +1);
		hspotap->osuplist.osuProvider[0].name.duple[1].langLen =
			strlen(KOREAN);
		strncpy_n(hspotap->osuplist.osuProvider[0].name.duple[1].name,
			(char *)kor_opname_sp_orng, VENUE_NAME_SIZE + 1);
		hspotap->osuplist.osuProvider[0].name.duple[1].nameLen =
			sizeof(kor_opname_sp_orng);
		ret = nvram_set(strcat_r(hspotap->prefix, "osu_frndname", varname),
			"SP Orange Test Only!eng|"
			"\x53\x50\x20\xEC\x98\xA4\xEB\xA0\x8C\xEC\xA7\x80\x20"
			"\xED\x85\x8C\xEC\x8A\xA4\xED\x8A\xB8\x20\xEC\xA0\x84\xEC\x9A\xA9!kor");
		if (ret) {
			printf("nvram_set %s=%s failure\n", varname,
			"SP Orange Test Only!eng|"
			"\x53\x50\x20\xEC\x98\xA4\xEB\xA0\x8C\xEC\xA7\x80\x20"
			"\xED\x85\x8C\xEC\x8A\xA4\xED\x8A\xB8\x20\xEC\xA0\x84\xEC\x9A\xA9!kor");
			err = -1;
		}
		/* OSU_Icons */
		hspotap->osuplist.osuProvider[0].iconMetadataCount = 2;
		hspotap->osuplist.osuProvider[0].iconMetadata[0].width = 128;
		hspotap->osuplist.osuProvider[0].iconMetadata[0].height = 61;
		strncpy_n((char*)hspotap->osuplist.osuProvider[0].iconMetadata[0].lang,
			LANG_ZXX, VENUE_LANGUAGE_CODE_SIZE +1);
		strncpy_n((char*)hspotap->osuplist.osuProvider[0].iconMetadata[0].type,
			ICON_TYPE_ID1, BCM_DECODE_HSPOT_ANQP_MAX_ICON_TYPE_LENGTH + 1);
		hspotap->osuplist.osuProvider[0].iconMetadata[0].typeLength = strlen(ICON_TYPE_ID1);
		strncpy_n((char*)hspotap->osuplist.osuProvider[0].iconMetadata[0].filename,
			ICON_FILENAME_ORANGE_ZXX,
			BCM_DECODE_HSPOT_ANQP_MAX_ICON_FILENAME_LENGTH + 1);
		hspotap->osuplist.osuProvider[0].iconMetadata[0].filenameLength =
			strlen(ICON_FILENAME_ORANGE_ZXX);
		/* Icon Metadata 2 */
		hspotap->osuplist.osuProvider[0].iconMetadata[1].width = 160;
		hspotap->osuplist.osuProvider[0].iconMetadata[1].height = 76;
		strncpy_n((char*)hspotap->osuplist.osuProvider[0].iconMetadata[1].lang,
			ENGLISH, VENUE_LANGUAGE_CODE_SIZE +1);
		strncpy_n((char*)hspotap->osuplist.osuProvider[0].iconMetadata[1].type,
			ICON_TYPE_ID1, BCM_DECODE_HSPOT_ANQP_MAX_ICON_TYPE_LENGTH + 1);
		hspotap->osuplist.osuProvider[0].iconMetadata[1].typeLength = strlen(ICON_TYPE_ID1);
		strncpy_n((char*)hspotap->osuplist.osuProvider[0].iconMetadata[1].filename,
			ICON_FILENAME_ORANGE, BCM_DECODE_HSPOT_ANQP_MAX_ICON_FILENAME_LENGTH + 1);
		hspotap->osuplist.osuProvider[0].iconMetadata[1].filenameLength =
			strlen(ICON_FILENAME_ORANGE);
		ret = nvram_set(strcat_r(hspotap->prefix, "osu_icons", varname),
			"icon_orange_zxx.png+icon_orange_eng.png");
		if (ret) {
			printf("nvram_set %s=%s failure\n", varname,
			"icon_orange_zxx.png+icon_orange_eng.png");
			err = -1;
		}
		/* OSU_NAI */
		strncpy_n((char*)hspotap->osuplist.osuProvider[0].nai, "",
			BCM_DECODE_HSPOT_ANQP_MAX_NAI_LENGTH + 1);
		hspotap->osuplist.osuProvider[0].naiLength = 0;
		ret = nvram_set(strcat_r(hspotap->prefix, "osu_nai", varname),
			"");
		if (ret) {
			printf("nvram_set %s=%s failure\n", varname,
			"");
			err = -1;
		}
		/* OSU_Server_Desc */
		hspotap->osuplist.osuProvider[0].desc.isDecodeValid = TRUE;
		hspotap->osuplist.osuProvider[0].desc.numName = 2;
		strncpy_n((char*)hspotap->osuplist.osuProvider[0].desc.duple[0].lang,
			ENGLISH, VENUE_LANGUAGE_CODE_SIZE +1);
		hspotap->osuplist.osuProvider[0].desc.duple[0].langLen =
			strlen(ENGLISH);
		strncpy_n((char*)hspotap->osuplist.osuProvider[0].desc.duple[0].name,
			OSU_SERVICE_DESC_ID1, VENUE_NAME_SIZE + 1);
		hspotap->osuplist.osuProvider[0].desc.duple[0].nameLen =
			strlen(OSU_SERVICE_DESC_ID1);
		strncpy_n((char*)hspotap->osuplist.osuProvider[0].desc.duple[1].lang,
			KOREAN, VENUE_LANGUAGE_CODE_SIZE +1);
		hspotap->osuplist.osuProvider[0].desc.duple[1].langLen =
			strlen(KOREAN);
		strncpy_n((char*)hspotap->osuplist.osuProvider[0].desc.duple[1].name,
			(char *)kor_desc_name_id1, VENUE_NAME_SIZE + 1);
		hspotap->osuplist.osuProvider[0].desc.duple[1].nameLen =
			sizeof(kor_desc_name_id1);

		ret = nvram_set(strcat_r(hspotap->prefix, "osu_servdesc", varname),
			"Free service for test purpose!eng|"
			"\xED\x85\x8C\xEC\x8A\xA4\xED\x8A\xB8\x20\xEB\xAA\xA9"
			"\xEC\xA0\x81\xEC\x9C\xBC\xEB\xA1\x9C\x20\xEB\xAC\xB4"
			"\xEB\xA3\x8C\x20\xEC\x84\x9C\xEB\xB9\x84\xEC\x8A\xA4!kor");
		if (ret) {
			printf("nvram_set %s=%s failure\n", varname,
			"Free service for test purpose!eng|"
			"\xED\x85\x8C\xEC\x8A\xA4\xED\x8A\xB8\x20\xEB\xAA\xA9"
			"\xEC\xA0\x81\xEC\x9C\xBC\xEB\xA1\x9C\x20\xEB\xAC\xB4"
			"\xEB\xA3\x8C\x20\xEC\x84\x9C\xEB\xB9\x84\xEC\x8A\xA4!kor");
			err = -1;
		}

		for (index = 1; index < MAX_OSU_PROVIDERS; index++)
			memset(&hspotap->osuplist.osuProvider[index], 0,
				sizeof(hspotap->osuplist.osuProvider[index]));
	}
	break;

	case 8:
	{
		hspotap->osuplist.isDecodeValid = TRUE;
		hspotap->osuplist.osuProviderCount = 1;
		/* OSU_Friendly_Name */
		hspotap->osuplist.osuProvider[0].name.isDecodeValid = TRUE;
		hspotap->osuplist.osuProvider[0].name.numName = 2;
		strncpy_n((char*)hspotap->osuplist.osuProvider[0].name.duple[0].lang,
			ENGLISH, VENUE_LANGUAGE_CODE_SIZE +1);
		hspotap->osuplist.osuProvider[0].name.duple[0].langLen =
			strlen(ENGLISH);
		strncpy_n((char*)hspotap->osuplist.osuProvider[0].name.duple[0].name,
			ENG_OPNAME_SP_RED, VENUE_NAME_SIZE + 1);
		hspotap->osuplist.osuProvider[0].name.duple[0].nameLen =
			strlen(ENG_OPNAME_SP_RED);
		strncpy_n(hspotap->osuplist.osuProvider[0].name.duple[1].lang,
			KOREAN, VENUE_LANGUAGE_CODE_SIZE +1);
		hspotap->osuplist.osuProvider[0].name.duple[1].langLen =
			strlen(KOREAN);
		strncpy_n(hspotap->osuplist.osuProvider[0].name.duple[1].name,
			(char *)kor_opname_sp_red, VENUE_NAME_SIZE + 1);
		hspotap->osuplist.osuProvider[0].name.duple[1].nameLen =
			sizeof(kor_opname_sp_red);
		ret = nvram_set(strcat_r(hspotap->prefix, "osu_frndname", varname),
			"SP Red Test Only!eng|"
			"\x53\x50\x20\xEB\xB9\xA8\xEA\xB0\x95\x20\xED\x85\x8C"
			"\xEC\x8A\xA4\xED\x8A\xB8\x20\xEC\xA0\x84\xEC\x9A\xA9!kor");
		if (ret) {
			printf("nvram_set %s=%s failure\n", varname,
			"SP Red Test Only!eng|"
			"\x53\x50\x20\xEB\xB9\xA8\xEA\xB0\x95\x20\xED\x85\x8C"
			"\xEC\x8A\xA4\xED\x8A\xB8\x20\xEC\xA0\x84\xEC\x9A\xA9!kor");
			err = -1;
		}
		/* OSU_Icons */
		hspotap->osuplist.osuProvider[0].iconMetadataCount = 1;
		hspotap->osuplist.osuProvider[0].iconMetadata[0].width = 128;
		hspotap->osuplist.osuProvider[0].iconMetadata[0].height = 61;
		strncpy_n((char*)hspotap->osuplist.osuProvider[0].iconMetadata[0].lang,
			LANG_ZXX, VENUE_LANGUAGE_CODE_SIZE +1);
		strncpy_n((char*)hspotap->osuplist.osuProvider[0].iconMetadata[0].type,
			ICON_TYPE_ID1, BCM_DECODE_HSPOT_ANQP_MAX_ICON_TYPE_LENGTH + 1);
		hspotap->osuplist.osuProvider[0].iconMetadata[0].typeLength = strlen(ICON_TYPE_ID1);
		strncpy_n((char*)hspotap->osuplist.osuProvider[0].iconMetadata[0].filename,
			ICON_FILENAME_RED_ZXX, BCM_DECODE_HSPOT_ANQP_MAX_ICON_FILENAME_LENGTH + 1);
		hspotap->osuplist.osuProvider[0].iconMetadata[0].filenameLength =
			strlen(ICON_FILENAME_RED_ZXX);
		ret = nvram_set(strcat_r(hspotap->prefix, "osu_icons", varname),
			"icon_red_zxx.png");
		if (ret) {
			printf("nvram_set %s=%s failure\n", varname,
			"icon_red_zxx.png");
			err = -1;
		}
		/* OSU_NAI */
		strncpy_n((char*)hspotap->osuplist.osuProvider[0].nai, OSU_NAI_ANON_HS,
			BCM_DECODE_HSPOT_ANQP_MAX_NAI_LENGTH + 1);
		hspotap->osuplist.osuProvider[0].naiLength = strlen(OSU_NAI_ANON_HS);
		ret = nvram_set(strcat_r(hspotap->prefix, "osu_nai", varname),
			"anonymous@hotspot.net");
		if (ret) {
			printf("nvram_set %s=%s failure\n", varname,
			"anonymous@hotspot.net");
			err = -1;
		}
		/* OSU_Server_Desc */
		hspotap->osuplist.osuProvider[0].desc.isDecodeValid = TRUE;
		hspotap->osuplist.osuProvider[0].desc.numName = 2;
		strncpy_n((char*)hspotap->osuplist.osuProvider[0].desc.duple[0].lang,
			ENGLISH, VENUE_LANGUAGE_CODE_SIZE +1);
		hspotap->osuplist.osuProvider[0].desc.duple[0].langLen =
			strlen(ENGLISH);
		strncpy_n((char*)hspotap->osuplist.osuProvider[0].desc.duple[0].name,
			OSU_SERVICE_DESC_ID1, VENUE_NAME_SIZE + 1);
		hspotap->osuplist.osuProvider[0].desc.duple[0].nameLen =
			strlen(OSU_SERVICE_DESC_ID1);
		strncpy_n((char*)hspotap->osuplist.osuProvider[0].desc.duple[1].lang,
			KOREAN, VENUE_LANGUAGE_CODE_SIZE +1);
		hspotap->osuplist.osuProvider[0].desc.duple[1].langLen =
			strlen(KOREAN);
		strncpy_n((char*)hspotap->osuplist.osuProvider[0].desc.duple[1].name,
			(char *)kor_desc_name_id1, VENUE_NAME_SIZE + 1);
		hspotap->osuplist.osuProvider[0].desc.duple[1].nameLen =
			sizeof(kor_desc_name_id1);

		ret = nvram_set(strcat_r(hspotap->prefix, "osu_servdesc", varname),
			"Free service for test purpose!eng|"
			"\xED\x85\x8C\xEC\x8A\xA4\xED\x8A\xB8\x20\xEB\xAA\xA9"
			"\xEC\xA0\x81\xEC\x9C\xBC\xEB\xA1\x9C\x20\xEB\xAC\xB4"
			"\xEB\xA3\x8C\x20\xEC\x84\x9C\xEB\xB9\x84\xEC\x8A\xA4!kor");
		if (ret) {
			printf("nvram_set %s=%s failure\n", varname,
			"Free service for test purpose!eng|"
			"\xED\x85\x8C\xEC\x8A\xA4\xED\x8A\xB8\x20\xEB\xAA\xA9"
			"\xEC\xA0\x81\xEC\x9C\xBC\xEB\xA1\x9C\x20\xEB\xAC\xB4"
			"\xEB\xA3\x8C\x20\xEC\x84\x9C\xEB\xB9\x84\xEC\x8A\xA4!kor");
			err = -1;
		}

		for (index = 1; index < MAX_OSU_PROVIDERS; index++)
			memset(&hspotap->osuplist.osuProvider[index], 0,
				sizeof(hspotap->osuplist.osuProvider[index]));
	}
	break;

	case 9:
	{
		hspotap->osuplist.isDecodeValid = TRUE;
		hspotap->osuplist.osuProviderCount = 1;
		/* OSU_Friendly_Name */
		hspotap->osuplist.osuProvider[0].name.isDecodeValid = TRUE;
		hspotap->osuplist.osuProvider[0].name.numName = 1;
		strncpy_n((char*)hspotap->osuplist.osuProvider[0].name.duple[0].lang,
			ENGLISH, VENUE_LANGUAGE_CODE_SIZE +1);
		hspotap->osuplist.osuProvider[0].name.duple[0].langLen =
			strlen(ENGLISH);
		strncpy_n((char*)hspotap->osuplist.osuProvider[0].name.duple[0].name,
			ENG_OPNAME_SP_GREEN, VENUE_NAME_SIZE + 1);
		hspotap->osuplist.osuProvider[0].name.duple[0].nameLen =
			strlen(ENG_OPNAME_SP_GREEN);
		ret = nvram_set(strcat_r(hspotap->prefix, "osu_frndname", varname),
			"SP Green Test Only!eng");
		if (ret) {
			printf("nvram_set %s=%s failure\n", varname,
			"SP Green Test Only!eng");
			err = -1;
		}
		/* OSU_Icons */
		hspotap->osuplist.osuProvider[0].iconMetadataCount = 1;
		hspotap->osuplist.osuProvider[0].iconMetadata[0].width = 128;
		hspotap->osuplist.osuProvider[0].iconMetadata[0].height = 61;
		strncpy_n((char*)hspotap->osuplist.osuProvider[0].iconMetadata[0].lang,
			LANG_ZXX, VENUE_LANGUAGE_CODE_SIZE +1);
		strncpy_n((char*)hspotap->osuplist.osuProvider[0].iconMetadata[0].type,
			ICON_TYPE_ID1, BCM_DECODE_HSPOT_ANQP_MAX_ICON_TYPE_LENGTH +1);
		hspotap->osuplist.osuProvider[0].iconMetadata[0].typeLength = strlen(ICON_TYPE_ID1);
		strncpy_n((char*)hspotap->osuplist.osuProvider[0].iconMetadata[0].filename,
			ICON_FILENAME_GREEN_ZXX,
			BCM_DECODE_HSPOT_ANQP_MAX_ICON_FILENAME_LENGTH + 1);
		hspotap->osuplist.osuProvider[0].iconMetadata[0].filenameLength =
			strlen(ICON_FILENAME_GREEN_ZXX);
		ret = nvram_set(strcat_r(hspotap->prefix, "osu_icons", varname),
			"icon_green_zxx.png");
		if (ret) {
			printf("nvram_set %s=%s failure\n", varname,
			"icon_green_zxx.png");
			err = -1;
		}
		/* OSU_NAI */
		strncpy_n((char*)hspotap->osuplist.osuProvider[0].nai, OSU_NAI_TEST_WIFI,
			BCM_DECODE_HSPOT_ANQP_MAX_NAI_LENGTH + 1);
		hspotap->osuplist.osuProvider[0].naiLength = strlen(OSU_NAI_TEST_WIFI);
		ret = nvram_set(strcat_r(hspotap->prefix, "osu_nai", varname),
			"test-anonymous@wi-fi.org");
		if (ret) {
			printf("nvram_set %s=%s failure\n", varname,
			"test-anonymous@wi-fi.org");
			err = -1;
		}
		/* OSU_Server_Desc */
		memset(&hspotap->osuplist.osuProvider[0].desc, 0,
			sizeof(hspotap->osuplist.osuProvider[0].desc));

		ret = nvram_set(strcat_r(hspotap->prefix, "osu_servdesc", varname),
			"");
		if (ret) {
			printf("nvram_set %s=%s failure\n", varname,
			"");
			err = -1;
		}

		for (index = 1; index < MAX_OSU_PROVIDERS; index++)
			memset(&hspotap->osuplist.osuProvider[index], 0,
				sizeof(hspotap->osuplist.osuProvider[index]));
	}
	break;
	}

	nvram_commit();
	return err;
}

static int hspot_cmd_osu_icon_tag_handler(hspotApT *hspotap,
	char **argv, char *txData, bool *set_tx_data)
{
	int err = 0, ret;
	char varname[NVRAM_MAX_PARAM_LEN] = {0};
	char varvalue[NVRAM_MAX_VALUE_LEN] = {0};

	if (argv[0] == NULL) {
		printf("missing parameter in command osu_icon_tag\n");
		hspotap->osuicon_id = 1;
	}
	else {
		hspotap->osuicon_id = atoi(argv[0]);
		printf("osu_provider_list id = %d\n", hspotap->osuicon_id);
	}

	snprintf(varvalue, sizeof(varvalue), "%d", hspotap->osuicon_id);
	ret = nvram_set(strcat_r(hspotap->prefix, "osuicon_id", varname), varvalue);
	if (ret) {
		printf("nvram_set %s=%s failure\n", varname, varvalue);
		err = -1;
	}
	nvram_commit();
	return err;
}

static int hspot_cmd_osu_ssid_handler(hspotApT *hspotap,
	char **argv, char *txData, bool *set_tx_data)
{
	int err = 0, ret;
	char varname[NVRAM_MAX_PARAM_LEN] = {0};

	hspotap->osuplist.isDecodeValid = TRUE;

	if (argv[0] == NULL) {
		printf("missing parameter in command osu_ssid\n");
		strncpy_n((char*)hspotap->osuplist.osuSsid,
			"OSU", BCM_DECODE_HSPOT_ANQP_MAX_OSU_SSID_LENGTH + 1);
		hspotap->osuplist.osuSsidLength = strlen("OSU");
	}
	else {
		strncpy_n((char*)hspotap->osuplist.osuSsid,
			argv[0], BCM_DECODE_HSPOT_ANQP_MAX_OSU_SSID_LENGTH + 1);
		hspotap->osuplist.osuSsidLength = strlen(argv[0]);
	}

	printf("osu_ssid = %s\n", hspotap->osuplist.osuSsid);

	ret = nvram_set(strcat_r(hspotap->prefix, "osu_ssid", varname),
		(char*)hspotap->osuplist.osuSsid);
	if (ret) {
		printf("nvram_set %s=%s failure\n", varname, hspotap->osuplist.osuSsid);
		err = -1;
	}
	nvram_commit();
	return err;
}

static int hspot_cmd_osu_server_uri_handler(hspotApT *hspotap,
	char **argv, char *txData, bool *set_tx_data)
{
	int err = 0, i = 0, ret, iter;
	char varname[NVRAM_MAX_PARAM_LEN] = {0};
	char varvalue[BUFFER_SIZE2] = {0};

	if (argv[0] == NULL) {
		printf("missing parameter in command osu_server_uri\n");
		strncpy_n(varvalue, "https://osu-server.R2-testbed.wi-fi.org",
			BUFFER_SIZE2);
	}
	else {
		while (argv[i])
		{
			strncpy_n((char*)hspotap->osuplist.osuProvider[i].uri,
				argv[i], BCM_DECODE_HSPOT_ANQP_MAX_URI_LENGTH + 1);

			hspotap->osuplist.osuProvider[i].uriLength = strlen(argv[i]);

			if (i)
				strncat(varvalue, ";",
					min(1, BUFFER_SIZE2 - strlen(varvalue)));

			strncat(varvalue, argv[i],
				min(strlen(argv[i]), BUFFER_SIZE2 - strlen(varvalue)));

			i++;
		}
	}

	for (iter = i; iter < MAX_OSU_PROVIDERS; iter++)
	{
		memset(hspotap->osuplist.osuProvider[iter].uri, 0,
			sizeof(hspotap->osuplist.osuProvider[iter].uri));
		hspotap->osuplist.osuProvider[iter].uriLength = 0;
	}

	ret = nvram_set(strcat_r(hspotap->prefix, "osu_uri", varname), varvalue);
	if (ret) {
		printf("nvram_set %s=%s failure\n", varname, varvalue);
		err = -1;
	}
	nvram_commit();
	return err;
}

static int hspot_cmd_osu_method_handler(hspotApT *hspotap,
	char **argv, char *txData, bool *set_tx_data)
{
	int err = 0, i = 0, ret, iter;
	char varname[NVRAM_MAX_PARAM_LEN] = {0};
	char varvalue[NVRAM_MAX_PARAM_LEN] = {0};
	uint8 osu_method[1];

	if (argv[0] == NULL) {
		printf("missing parameter in command osu_method\n");
		strncpy_n(varvalue, "SOAP", NVRAM_MAX_PARAM_LEN);
	}
	else {
		while (argv[i])
		{
			osu_method[0] = (!strncasecmp(argv[i], "OMADM", 5)) ?
				HSPOT_OSU_METHOD_OMA_DM : HSPOT_OSU_METHOD_SOAP_XML;
			memcpy(hspotap->osuplist.osuProvider[i].method,
				osu_method, sizeof(osu_method));
			hspotap->osuplist.osuProvider[i].methodLength = sizeof(osu_method);
			if (i)
				strncat(varvalue, ";",
					min(1, NVRAM_MAX_PARAM_LEN - strlen(varvalue)));

			strncat(varvalue, (!strncasecmp(argv[i], "OMADM", 5)) ? "1" : "0",
				min(1, NVRAM_MAX_PARAM_LEN - strlen(varvalue)));

			i++;
		}
	}

	for (iter = i; iter < MAX_OSU_PROVIDERS; iter++)
	{
		memset(hspotap->osuplist.osuProvider[iter].method, 0,
			sizeof(hspotap->osuplist.osuProvider[iter].method));
		hspotap->osuplist.osuProvider[iter].methodLength = 0;
	}

	ret = nvram_set(strcat_r(hspotap->prefix, "osu_method", varname), varvalue);
	if (ret) {
		printf("nvram_set %s=%s failure\n", varname, varvalue);
		err = -1;
	}
	nvram_commit();
	return err;
}

static int hspot_cmd_domain_list_handler(hspotApT *hspotap,
	char **argv, char *txData, bool *set_tx_data)
{
	int err = 0, i = 0;
	char varvalue[NVRAM_MAX_VALUE_LEN] = {0};
	char varname[NVRAM_MAX_PARAM_LEN] = {0};
	int ret;

	if (argv[0] == NULL) {
		printf("missing parameter in command domain_list\n");
		return -1;
	}

	strncpy_n(varvalue, "", NVRAM_MAX_VALUE_LEN);
	memset(&hspotap->domainlist, 0, sizeof(bcm_decode_anqp_domain_name_list_t));
	hspotap->domainlist.isDecodeValid = TRUE;
	hspotap->domainlist.numDomain = 0;

	while (argv[i])
	{
		strncpy_n(hspotap->domainlist.domain[i].name, argv[i],
			BCM_DECODE_ANQP_MAX_DOMAIN_NAME_SIZE+1);
		hspotap->domainlist.domain[i].len = strlen(argv[i]);

		if (i)
			strncat(varvalue, " ", min(1,
			NVRAM_MAX_VALUE_LEN-strlen(varvalue)));
		strncat(varvalue, argv[i], min(strlen(argv[i]),
			NVRAM_MAX_VALUE_LEN-strlen(varvalue)));

		i++;
	}
	hspotap->domainlist.numDomain = i;

	ret = nvram_set(strcat_r(hspotap->prefix, "domainlist", varname), varvalue);
	if (ret) {
		printf("nvram_set %s=%s failure\n", varname, varvalue);
		err = -1;
	}

	nvram_commit();
	return err;
}

static int hspot_cmd_roaming_cons_handler(hspotApT *hspotap,
	char **argv, char *txData, bool *set_tx_data)
{
	int err = 0, i = 0;
	char varvalue[NVRAM_MAX_VALUE_LEN] = {0};
	char varname[NVRAM_MAX_PARAM_LEN] = {0};
	int ret, data_len = 0;


	if (argv[0] == NULL) {
		printf("missing parameter in command roaming_cons\n");
		return -1;
	}

	if (!strncasecmp(argv[0], "disabled", 8)) {
		printf("Roaming consortium OI is not present\n");
		Reset_OUIList(hspotap, FALSE);
	}
	else {
		strncpy_n(varvalue, "", NVRAM_MAX_VALUE_LEN);
		memset(&hspotap->ouilist, 0, sizeof(bcm_decode_anqp_roaming_consortium_t));
		hspotap->ouilist.isDecodeValid = TRUE;
		hspotap->ouilist.numOi = 0;

		while (argv[i])
		{
			data_len = strlen(argv[i]) / 2;

			if (data_len && (data_len <= BCM_DECODE_ANQP_MAX_OI_LENGTH)) {

				get_hex_data((uchar *)argv[i], hspotap->ouilist.oi[i].oi, data_len);
				hspotap->ouilist.oi[i].oiLen = data_len;

				printf("OI %d:0x%x 0x%x 0x%x\n", i, hspotap->ouilist.oi[i].oi[0],
				  hspotap->ouilist.oi[i].oi[1], hspotap->ouilist.oi[i].oi[2]);

				if (i)
					strncat(varvalue, ";", min(1,
					NVRAM_MAX_VALUE_LEN-strlen(varvalue)));
				strncat(varvalue, argv[i], min(strlen(argv[i]),
					NVRAM_MAX_VALUE_LEN-strlen(varvalue)));
				i++;
			}
		}
		hspotap->ouilist.numOi = i;

		ret = nvram_set(strcat_r(hspotap->prefix, "ouilist", varname), varvalue);
		if (ret) {
			printf("nvram_set %s=%s failure\n", varname, varvalue);
			err = -1;
		}
		nvram_commit();
	}

	err = update_rc_ie(hspotap);
	return err;
}

static int hspot_cmd_anqp_handler(hspotApT *hspotap,
	char **argv, char *txData, bool *set_tx_data)
{
	int err = 0, ap_ANQPenabled;

	if (argv[0] == NULL) {
		printf("missing parameter in command anqp\n");
		return -1;
	}

	ap_ANQPenabled = (atoi(argv[0]) != 0);
	Set_hspot_flag(hspotap->prefix, HSFLG_ANQP, ap_ANQPenabled);
	printf("ap_ANQPenabled %d\n", ap_ANQPenabled);

	err = update_ap_ie(hspotap);
	return err;
}

static int hspot_cmd_mih_handler(hspotApT *hspotap,
	char **argv, char *txData, bool *set_tx_data)
{
	int err = 0, ap_MIHenabled;

	if (argv[0] == NULL) {
		printf("missing parameter in command mih\n");
		return -1;
	}

	ap_MIHenabled = (atoi(argv[0]) != 0);
	Set_hspot_flag(hspotap->prefix, HSFLG_MIH, ap_MIHenabled);
	printf("ap_MIHenabled %d\n", ap_MIHenabled);

	err = update_ap_ie(hspotap);
	return err;
}

static int hspot_cmd_dgaf_disable_handler(hspotApT *hspotap,
	char **argv, char *txData, bool *set_tx_data)
{
	vendorIeT *vendorIeHSI = &hspotap->vendorIeHSI;
	bcm_encode_t ie;
	int err = 0;
	bool inflag, isDgafDisabled;

	if (argv[0] == NULL) {
		printf("missing parameter in command dgaf_disable\n");
		return -1;
	}

	isDgafDisabled = Get_hspot_flag(hspotap->prefix, HSFLG_DGAF_DS);
	inflag = (atoi(argv[0]) != 0);
	printf("isDgafDisabled %d\n", inflag);

	if (isDgafDisabled != inflag) {
		Set_hspot_flag(hspotap->prefix, HSFLG_DGAF_DS, inflag);

		/* delete Passpoint vendor IE */
		if (hspotap->hs_ie_enabled)
			wl_del_vndr_ie(hspotap->ifr, DEFAULT_BSSCFG_INDEX, vendorIeHSI->pktflag,
				vendorIeHSI->ieLength - 2, vendorIeHSI->ieData + 2);

		/* encode Passpoint vendor IE */
		bcm_encode_init(&ie, sizeof(vendorIeHSI->ieData), vendorIeHSI->ieData);
		bcm_encode_ie_hotspot_indication2(&ie, inflag, hspotap->hs_capable,
			FALSE, 0, FALSE, 0);

		if (hspotap->hs_ie_enabled) {
			/* don't need first 2 bytes (0xdd + len) */
			if (wl_add_vndr_ie(hspotap->ifr, DEFAULT_BSSCFG_INDEX, vendorIeHSI->pktflag,
				vendorIeHSI->ieLength - 2, vendorIeHSI->ieData + 2) < 0) {
				TRACE(TRACE_ERROR, "failed to add vendor IE\n");
			}
		}

		err = update_dgaf_disable(hspotap);
	}
	return err;
}

static int hspot_cmd_l2_traffic_inspect_handler(hspotApT *hspotap,
	char **argv, char *txData, bool *set_tx_data)
{
	int err = 0, l2_traffic_inspect;

	if (argv[0] == NULL) {
		printf("missing parameter in command l2_traffic_inspect\n");
		return -1;
	}

	l2_traffic_inspect = (atoi(argv[0]) != 0);
	Set_hspot_flag(hspotap->prefix, HSFLG_L2_TRF, l2_traffic_inspect);
	printf("l2_traffic_inspect %d\n", l2_traffic_inspect);
	err = update_l2_traffic_inspect(hspotap);

	return err;
}

static int hspot_cmd_icmpv4_echo_handler(hspotApT *hspotap,
	char **argv, char *txData, bool *set_tx_data)
{
	int err = 0, icmpv4_echo, l2_traffic_inspect;
	l2_traffic_inspect = Get_hspot_flag(hspotap->prefix, HSFLG_L2_TRF);

	if (argv[0] == NULL) {
		printf("missing parameter in command icmpv4_echo\n");
		return -1;
	}

	icmpv4_echo = (atoi(argv[0]) != 0);
	printf("icmpv4_echo %d\n", icmpv4_echo);
	Set_hspot_flag(hspotap->prefix, HSFLG_ICMPV4_ECHO, icmpv4_echo);

	if (l2_traffic_inspect) {
		if (wl_block_ping(hspotap->ifr, !icmpv4_echo) < 0) {
			err = -1;
			TRACE(TRACE_ERROR, "wl_block_ping failed\n");
		}
	}

	return err;
}

static int hspot_cmd_plmn_mcc_handler(hspotApT *hspotap,
	char **argv, char *txData, bool *set_tx_data)
{
	int ret, err = 0, i = 0;
	char item_value[NVRAM_MAX_VALUE_LEN] = {0};
	char varvalue[NVRAM_MAX_VALUE_LEN] = {0};
	char varname[NVRAM_MAX_PARAM_LEN] = {0};

	if (argv[0] == NULL) {
		printf("missing parameter in command plmn_mcc\n");
		return -1;
	}

	hspotap->gpp3list.plmnCount = 0;
	while ((i < BCM_DECODE_ANQP_MAX_PLMN) && argv[i]) {

		memset(item_value, 0, sizeof(item_value));

		if (strlen(argv[i]) > BCM_DECODE_ANQP_MCC_LENGTH) {
			printf("wrong MCC length %d\n", strlen(argv[i]));
			return -1;
		}

		strncpy_n(hspotap->gpp3list.plmn[i].mcc, argv[i], BCM_DECODE_ANQP_MCC_LENGTH + 1);
		printf("plmn_mcc %d: %s\n", i, hspotap->gpp3list.plmn[i].mcc);

		if (!strlen(hspotap->gpp3list.plmn[i].mnc))
			strncpy_n(hspotap->gpp3list.plmn[i].mnc, "000",
			BCM_DECODE_ANQP_MCC_LENGTH + 1);

		strncat(item_value, hspotap->gpp3list.plmn[i].mcc,
			min(BCM_DECODE_ANQP_MCC_LENGTH, NVRAM_MAX_VALUE_LEN-strlen(item_value)));
		strncat(item_value, ":", min(1, NVRAM_MAX_VALUE_LEN-strlen(item_value)));
		strncat(item_value, hspotap->gpp3list.plmn[i].mnc,
			min(BCM_DECODE_ANQP_MNC_LENGTH, NVRAM_MAX_VALUE_LEN-strlen(item_value)));

		if (i)
			strncat(varvalue, ";", min(1,
			NVRAM_MAX_VALUE_LEN-strlen(varvalue)));
		strncat(varvalue, item_value, min(strlen(item_value),
			NVRAM_MAX_VALUE_LEN-strlen(varvalue)));

		i++;
	}
	hspotap->gpp3list.plmnCount = i;

	ret = nvram_set(strcat_r(hspotap->prefix, "3gpplist", varname), varvalue);
	if (ret) {
		printf("nvram_set %s=%s failure\n", varname, varvalue);
		err = -1;
	}

	nvram_commit();
	return err;
}

static int hspot_cmd_plmn_mnc_handler(hspotApT *hspotap,
	char **argv, char *txData, bool *set_tx_data)
{
	int ret, err = 0, i = 0;
	char item_value[NVRAM_MAX_VALUE_LEN] = {0};
	char varvalue[NVRAM_MAX_VALUE_LEN] = {0};
	char varname[NVRAM_MAX_PARAM_LEN] = {0};

	if (argv[0] == NULL) {
		printf("missing parameter in command plmn_mnc\n");
		return -1;
	}

	hspotap->gpp3list.plmnCount = 0;
	while ((i < BCM_DECODE_ANQP_MAX_PLMN) && argv[i]) {

		memset(item_value, 0, sizeof(item_value));

		if (strlen(argv[i]) > BCM_DECODE_ANQP_MNC_LENGTH) {
			printf("wrong MNC length %d\n", strlen(argv[i]));
			hspotap->gpp3list.plmnCount = 0;
			return -1;
		}

		strncpy_n(hspotap->gpp3list.plmn[i].mnc, argv[i], BCM_DECODE_ANQP_MNC_LENGTH + 1);
		printf("plmn_mnc %d: %s\n", i, hspotap->gpp3list.plmn[i].mnc);

		if (!strlen(hspotap->gpp3list.plmn[i].mcc))
			strncpy_n(hspotap->gpp3list.plmn[i].mcc, "000",
			BCM_DECODE_ANQP_MNC_LENGTH + 1);

		strncat(item_value, hspotap->gpp3list.plmn[i].mcc,
			min(BCM_DECODE_ANQP_MCC_LENGTH, NVRAM_MAX_VALUE_LEN-strlen(item_value)));
		strncat(item_value, ":", min(1, NVRAM_MAX_VALUE_LEN-strlen(item_value)));
		strncat(item_value, hspotap->gpp3list.plmn[i].mnc,
			min(BCM_DECODE_ANQP_MNC_LENGTH, NVRAM_MAX_VALUE_LEN-strlen(item_value)));

		if (i)
			strncat(varvalue, ";", min(1,
			NVRAM_MAX_VALUE_LEN-strlen(varvalue)));
		strncat(varvalue, item_value, min(strlen(item_value),
			NVRAM_MAX_VALUE_LEN-strlen(varvalue)));

		i++;
	}
	hspotap->gpp3list.plmnCount = i;

	ret = nvram_set(strcat_r(hspotap->prefix, "3gpplist", varname), varvalue);
	if (ret) {
		printf("nvram_set %s=%s failure\n", varname, varvalue);
		err = -1;
	}

	nvram_commit();
	return err;
}

static int hspot_cmd_proxy_arp_handler(hspotApT *hspotap,
	char **argv, char *txData, bool *set_tx_data)
{
	int err = 0;
	int proxy_arp = 0;
	if (argv[0] == NULL) {
		printf("missing parameter in proxy_arp\n");
		return -1;
	}

	proxy_arp = (atoi(argv[0]) != 0) ? WL_WNM_PROXYARP : 0;
	printf("proxy_arp %d\n", proxy_arp);

#ifdef __CONFIG_DHDAP__
	int is_dhd = !dhd_probe(hspotap->ifr);
	if (is_dhd) {
		int index = -1;
		proxy_arp = (proxy_arp == WL_WNM_PROXYARP)? 1 : 0;
		get_ifname_unit(hspotap->ifr, NULL, &index);
		if (dhd_bssiovar_setint(hspotap->ifr, "proxy_arp",
			((index == -1) ? 0 : index), proxy_arp) < 0)
			TRACE(TRACE_ERROR, "dhd proxy_arp failed\n");
	} else
#endif

	if ((wl_wnm(hspotap->ifr, WNM_DEFAULT_BITMASK | proxy_arp) < 0) ||
		(wl_wnm_parp_discard(hspotap->ifr, (atoi(argv[0]) != 0)) < 0) ||
		(wl_wnm_parp_allnode(hspotap->ifr, !(atoi(argv[0]) != 0)) < 0)) {
		err = -1;
		TRACE(TRACE_ERROR, "wl_proxy_arp failed\n");
	}

	if (wl_grat_arp(hspotap->ifr, proxy_arp) < 0) {
		err = -1;
		TRACE(TRACE_ERROR, "wl_grat_arp failed\n");
	}
	return err;
}

static int hspot_cmd_bcst_uncst_handler(hspotApT *hspotap,
	char **argv, char *txData, bool *set_tx_data)
{
	int err = 0;
	bool bcst_uncst;
	if (argv[0] == NULL) {
		printf("missing parameter in bcst_uncst\n");
		return -1;
	}

	bcst_uncst = (atoi(argv[0]) != 0);
	printf("bcst_uncst %d\n", bcst_uncst);

	if (wl_dhcp_unicast(hspotap->ifr, bcst_uncst) < 0) {
		err = -1;
		TRACE(TRACE_ERROR, "wl_dhcp_unicast failed\n");
	}
	return err;
}

static int hspot_cmd_gas_cb_delay_handler(hspotApT *hspotap,
	char **argv, char *txData, bool *set_tx_data)
{
	int err = 0;
	int gas_cb_delay;
	char varvalue[NVRAM_MAX_VALUE_LEN];
	char varname[NVRAM_MAX_PARAM_LEN];
	int ret;

	if (argv[0] == NULL) {
		printf("missing parameter in gas_cb_delay\n");
		return -1;
	}

	gas_cb_delay = atoi(argv[0]);
	printf("gas_cb_delay %d\n", gas_cb_delay);

	if (gas_cb_delay) {
		hspotap->isGasPauseForServerResponse = FALSE;
		bcm_gas_set_if_cb_delay_unpause(gas_cb_delay, hspotap->ifr);
	}
	else {
		hspotap->isGasPauseForServerResponse = TRUE;
	}
	bcm_gas_set_if_gas_pause(hspotap->isGasPauseForServerResponse, hspotap->ifr);

	hspotap->gas_cb_delay = gas_cb_delay;

	snprintf(varvalue, sizeof(varvalue), "%d", hspotap->gas_cb_delay);
	ret = nvram_set(strcat_r(hspotap->prefix, "gascbdel", varname), varvalue);
	if (ret) {
		printf("nvram_set %s=%s failure\n", varname, varvalue);
		err = -1;
	}
	nvram_commit();

	return err;
}

static int hspot_cmd_4_frame_gas_handler(hspotApT *hspotap,
	char **argv, char *txData, bool *set_tx_data)
{
	int err = 0;
	char varvalue[NVRAM_MAX_VALUE_LEN];
	char varname[NVRAM_MAX_PARAM_LEN];
	int ret;

	if (argv[0] == NULL) {
		printf("missing parameter in 4_frame_gas\n");
		return -1;
	}

	hspotap->isGasPauseForServerResponse = (atoi(argv[0]) == 0);
	printf("4_frame_gas %d\n", !(hspotap->isGasPauseForServerResponse));
	bcm_gas_set_if_gas_pause(hspotap->isGasPauseForServerResponse, hspotap->ifr);

	snprintf(varvalue, sizeof(varvalue), "%d", (!(hspotap->isGasPauseForServerResponse)));
	ret = nvram_set(strcat_r(hspotap->prefix, "4framegas", varname), varvalue);
	if (ret) {
		printf("nvram_set %s=%s failure\n", varname, varvalue);
		err = -1;
	}
	nvram_commit();

	return err;
}

static int hspot_cmd_sess_info_url_handler(hspotApT *hspotap,
	char **argv, char *txData, bool *set_tx_data)
{
	int err = 0;

	if (argv[0] == NULL) {
		printf("missing parameter in command sess_info_url\n");
		return -1;
	}

	if (hspotap->url_len)
		free(hspotap->url);

	hspotap->url_len = strlen(argv[0]);
	if (hspotap->url_len == 0) {
		printf("sess_info_url: length is zero\n");
		wl_wnm_url(hspotap->ifr, 0, 0);
		return err;
	}

	hspotap->url = malloc(hspotap->url_len + 1);
	if (hspotap->url == NULL) {
		hspotap->url_len = 0;
		wl_wnm_url(hspotap->ifr, 0, 0);
		printf("sess_info_url: malloc failed\n");
		return -1;
	}

	strncpy_n((char *)hspotap->url, argv[0], hspotap->url_len + 1);

	printf("sess_info_url: %s, len %d\n", hspotap->url, hspotap->url_len);

	err = wl_wnm_url(hspotap->ifr, hspotap->url_len, hspotap->url);
	return err;
}

static int hspot_cmd_dest_handler(hspotApT *hspotap,
	char **argv, char *txData, bool *set_tx_data)
{
	int err = 0;
	struct ether_addr da;

	if (argv[0] == NULL) {
		printf("missing parameter in command dest\n");
		return -1;
	}

	if (!strToEther(argv[0], &da)) {
		printf("wrong format parameter in command dest\n");
		return -1;
	}

	printf("dest 0x%x 0x%x 0x%x 0x%x 0x%x 0x%x\n", da.octet[0],
		da.octet[1], da.octet[2],
		da.octet[3], da.octet[4],
		da.octet[5]);

	err = hspot_send_BTM_Req_frame(hspotap, &da);
	return err;
}

static int hspot_cmd_interworking_handler(hspotApT *hspotap,
	char **argv, char *txData, bool *set_tx_data)
{
	int err = 0, ret;
	bool enabled = TRUE;
	char varvalue[NVRAM_MAX_VALUE_LEN];
	char varname[NVRAM_MAX_PARAM_LEN];

	if (argv[0] == NULL) {
		printf("missing parameter in command interworking\n");
		return -1;
	}

	enabled = (atoi(argv[0]) != 0);
	printf("U11 enabled %d\n", enabled);

	if (hspotap->iw_enabled != enabled) {

		if (hspotap->iw_enabled) {
			deleteIes_hs(hspotap);
			deleteIes_u11(hspotap);

			hspotap->hs_ie_enabled = enabled;

			snprintf(varvalue, sizeof(varvalue), "%d", hspotap->hs_ie_enabled);
			ret = nvram_set(strcat_r(hspotap->prefix, "hs2en", varname), varvalue);
			if (ret) {
				printf("nvram_set %s=%s failure\n", varname, varvalue);
				err = -1;
			}
		}

		hspotap->iw_enabled = enabled;

		if (enabled) {
			addIes_u11(hspotap);
		}

		snprintf(varvalue, sizeof(varvalue), "%d", hspotap->iw_enabled);
		ret = nvram_set(strcat_r(hspotap->prefix, "u11en", varname), varvalue);
		if (ret) {
			printf("nvram_set %s=%s failure\n", varname, varvalue);
			err = -1;
		}
		nvram_commit();
	}
	return err;
}

static int hspot_cmd_hs2_handler(hspotApT *hspotap,
	char **argv, char *txData, bool *set_tx_data)
{
	int err = 0, ret;
	bool enabled = TRUE;
	char varvalue[NVRAM_MAX_VALUE_LEN];
	char varname[NVRAM_MAX_PARAM_LEN];

	if (argv[0] == NULL) {
		printf("missing parameter in command hs2\n");
		return -1;
	}

	enabled = (atoi(argv[0]) != 0);
	printf("hs2 enabled %d\n", enabled);

	if (hspotap->hs_ie_enabled != enabled) {
		if (hspotap->hs_ie_enabled) {
			deleteIes_hs(hspotap);
		}

		hspotap->hs_ie_enabled = enabled;

		if (enabled) {
			hspotap->iw_enabled = enabled;
			addIes(hspotap);

			snprintf(varvalue, sizeof(varvalue), "%d", hspotap->iw_enabled);
			ret = nvram_set(strcat_r(hspotap->prefix, "u11en", varname), varvalue);
			if (ret) {
				printf("nvram_set %s=%s failure\n", varname, varvalue);
				err = -1;
			}
		}

		snprintf(varvalue, sizeof(varvalue), "%d", hspotap->hs_ie_enabled);
		ret = nvram_set(strcat_r(hspotap->prefix, "hs2en", varname), varvalue);
		if (ret) {
			printf("nvram_set %s=%s failure\n", varname, varvalue);
			err = -1;
		}
		nvram_commit();
	}

	return err;
}

static int hspot_cmd_p2p_ie_handler(hspotApT *hspotap,
	char **argv, char *txData, bool *set_tx_data)
{
	vendorIeT *vendorIeP2P = &hspotap->vendorIeP2P;
	int err = 0, p2p_ie_enabled, p2p_cross_enabled;
	bool enabled = TRUE;

	if (argv[0] == NULL) {
		printf("missing parameter in command u11\n");
		return -1;
	}

	p2p_ie_enabled = Get_hspot_flag(hspotap->prefix, HSFLG_P2P);
	p2p_cross_enabled = Get_hspot_flag(hspotap->prefix, HSFLG_P2P_CRS);
	enabled = (atoi(argv[0]) != 0);

	printf("p2p enabled %d\n", enabled);
	if (p2p_ie_enabled != enabled) {

		/* delete P2P vendor IE */
		wl_del_vndr_ie(hspotap->ifr, DEFAULT_BSSCFG_INDEX, vendorIeP2P->pktflag,
			vendorIeP2P->ieLength - 2, vendorIeP2P->ieData + 2);

		vendorIeP2P->ieData[9] = p2p_cross_enabled ? 0x03 : 0x01;

		if (enabled) {
			if (wl_add_vndr_ie(hspotap->ifr, DEFAULT_BSSCFG_INDEX, vendorIeP2P->pktflag,
				vendorIeP2P->ieLength - 2, vendorIeP2P->ieData + 2) < 0) {
				err = -1;
				TRACE(TRACE_ERROR, "failed to add vendor IE\n");
			}
		}
		Set_hspot_flag(hspotap->prefix, HSFLG_P2P, enabled);
	}

	return err;
}

static int hspot_cmd_p2p_cross_connect_handler(hspotApT *hspotap,
	char **argv, char *txData, bool *set_tx_data)
{
	vendorIeT *vendorIeP2P = &hspotap->vendorIeP2P;
	int err = 0, p2p_cross_enabled;
	bool enabled = TRUE;

	if (argv[0] == NULL) {
		printf("missing parameter in command p2p_cross_connect\n");
		return -1;
	}

	p2p_cross_enabled = Get_hspot_flag(hspotap->prefix, HSFLG_P2P_CRS);
	enabled = (atoi(argv[0]) != 0);
	printf("p2p_cross_connect enabled %d\n", enabled);

	if (p2p_cross_enabled != enabled) {
		/* delete P2P vendor IE */
		wl_del_vndr_ie(hspotap->ifr, DEFAULT_BSSCFG_INDEX, vendorIeP2P->pktflag,
			vendorIeP2P->ieLength - 2, vendorIeP2P->ieData + 2);

		vendorIeP2P->ieData[9] = enabled ? 0x03 : 0x01;

		/* don't need first 2 bytes (0xdd + len) */
		if (wl_add_vndr_ie(hspotap->ifr, DEFAULT_BSSCFG_INDEX, vendorIeP2P->pktflag,
			vendorIeP2P->ieLength - 2, vendorIeP2P->ieData + 2) < 0) {
			err = -1;
			TRACE(TRACE_ERROR, "failed to add vendor IE\n");
		}
		Set_hspot_flag(hspotap->prefix, HSFLG_P2P_CRS, enabled);
	}

	return err;
}

static int hspot_cmd_ip_add_type_avail_handler(hspotApT *hspotap,
	char **argv, char *txData, bool *set_tx_data)
{
	int ret, err = 0, ipa_id = 1;
	char varvalue[NVRAM_MAX_VALUE_LEN];
	char varname[NVRAM_MAX_PARAM_LEN];

	if (argv[0] == NULL) {
		printf("missing parameter in command ip_add_type_avail\n");
		return -1;
	}

	ipa_id = atoi(argv[0]);
	printf("ip_add_type_avail id %d\n", ipa_id);

	memset(&hspotap->ipaddrAvail, 0, sizeof(bcm_decode_anqp_ip_type_t));

	if (ipa_id == 1)
	{
		hspotap->ipaddrAvail.isDecodeValid = TRUE;
		hspotap->ipaddrAvail.ipv4 = IPA_IPV4_SINGLE_NAT;
		hspotap->ipaddrAvail.ipv6 = IPA_IPV6_NOT_AVAILABLE;
	}

	snprintf(varvalue, sizeof(varvalue), "%d", hspotap->ipaddrAvail.ipv4);
	ret = nvram_set(strcat_r(hspotap->prefix, "ipv4addr", varname), varvalue);
	if (ret) {
		printf("nvram_set %s=%s failure\n", varname, varvalue);
		err = -1;
	}
	snprintf(varvalue, sizeof(varvalue), "%d", hspotap->ipaddrAvail.ipv6);
	ret = nvram_set(strcat_r(hspotap->prefix, "ipv6addr", varname), varvalue);
	if (ret) {
		printf("nvram_set %s=%s failure\n", varname, varvalue);
		err = -1;
	}

	nvram_commit();
	return err;
}

static int hspot_cmd_hs_reset_handler(hspotApT *hspotap,
	char **argv, char *txData, bool *set_tx_data)
{
	vendorIeT *vendorIeHSI = &hspotap->vendorIeHSI;
	vendorIeT *vendorIeP2P = &hspotap->vendorIeP2P;
	bcm_encode_t ie;
	int err = 0, p2p_cross_enabled, isDgafDisabled;
	char varvalue[NVRAM_MAX_VALUE_LEN];
	char varname[NVRAM_MAX_PARAM_LEN];
	int ret;

	printf("hs_reset\n");

	Reset_IW(hspotap, TRUE, 0x000F);
	Reset_VenueList(hspotap, TRUE, 0x0007);
	update_iw_ie(hspotap, TRUE);

	Reset_OUIList(hspotap, TRUE);
	update_rc_ie(hspotap);

	Set_hspot_flag(hspotap->prefix, HSFLG_ANQP, TRUE);
	Set_hspot_flag(hspotap->prefix, HSFLG_MIH, FALSE);
	update_ap_ie(hspotap);

	hspotap->qos_id = 1;
	update_qosmap_ie(hspotap, FALSE);

	hspotap->bssload_id = 1;
	update_bssload_ie(hspotap, FALSE, TRUE);

	Set_hspot_flag(hspotap->prefix, HSFLG_OSEN, FALSE);
	update_osen_ie(hspotap, TRUE);

	Reset_Osuplist(hspotap, TRUE, 0x001F);

	Reset_HSCap(hspotap, TRUE);

	isDgafDisabled = Get_hspot_flag(hspotap->prefix, HSFLG_DGAF_DS);

	if (isDgafDisabled) {
		Set_hspot_flag(hspotap->prefix, HSFLG_DGAF_DS, FALSE);
		/* delete Passpoint vendor IE */
		if (hspotap->hs_ie_enabled)
			wl_del_vndr_ie(hspotap->ifr, DEFAULT_BSSCFG_INDEX, vendorIeHSI->pktflag,
				vendorIeHSI->ieLength - 2, vendorIeHSI->ieData + 2);
		/* encode Passpoint vendor IE */
		bcm_encode_init(&ie, sizeof(vendorIeHSI->ieData), vendorIeHSI->ieData);
		bcm_encode_ie_hotspot_indication2(&ie,
			isDgafDisabled, hspotap->hs_capable, FALSE, 0, FALSE, 0);
		hspotap->hs_ie_enabled = FALSE;
		update_dgaf_disable(hspotap);
	}

	if (hspotap->hs_ie_enabled == FALSE) {
		hspotap->hs_ie_enabled = TRUE;
		/* don't need first 2 bytes (0xdd + len) */
		if (wl_add_vndr_ie(hspotap->ifr, DEFAULT_BSSCFG_INDEX, vendorIeHSI->pktflag,
			vendorIeHSI->ieLength - 2, vendorIeHSI->ieData + 2) < 0) {
			TRACE(TRACE_ERROR, "failed to add vendor IE\n");
		}
	}

	Reset_3GPPList(hspotap, TRUE);
#ifdef __CONFIG_DHDAP__
	if (!dhd_probe(hspotap->ifr)) {
		int index = -1;
		get_ifname_unit(hspotap->ifr, NULL, &index);
		if (dhd_bssiovar_setint(hspotap->ifr, "proxy_arp",
			((index == -1) ? 0 : index), 0) < 0)
			TRACE(TRACE_ERROR, "dhd proxy_arp failed\n");
	} else
#endif
	{
		/* disable proxy ARP */
		wl_wnm(hspotap->ifr, WNM_DEFAULT_BITMASK);
		wl_wnm_parp_discard(hspotap->ifr, 0);
		wl_wnm_parp_allnode(hspotap->ifr, 1);
	}
	wl_grat_arp(hspotap->ifr, 0);

	bcm_gas_set_if_cb_delay_unpause(1000, hspotap->ifr);
	bcm_gas_set_comeback_delay_response_pause(1);
	hspotap->isGasPauseForServerResponse = TRUE;
	bcm_gas_set_if_gas_pause(hspotap->isGasPauseForServerResponse, hspotap->ifr);
	hspotap->gas_cb_delay = 0;
	Reset_DomainList(hspotap, TRUE);
	wl_wnm_url(hspotap->ifr, 0, 0);
	if (hspotap->url_len)
		free(hspotap->url);
	hspotap->url_len = 0;

	p2p_cross_enabled = Get_hspot_flag(hspotap->prefix, HSFLG_P2P_CRS);

	if (p2p_cross_enabled) {
		/* delete P2P vendor IE */
		wl_del_vndr_ie(hspotap->ifr, DEFAULT_BSSCFG_INDEX, vendorIeP2P->pktflag,
			vendorIeP2P->ieLength - 2, vendorIeP2P->ieData + 2);

		vendorIeP2P->ieData[9] = 0x01;

		/* don't need first 2 bytes (0xdd + len) */
		if (wl_add_vndr_ie(hspotap->ifr, DEFAULT_BSSCFG_INDEX, vendorIeP2P->pktflag,
			vendorIeP2P->ieLength - 2, vendorIeP2P->ieData + 2) < 0) {
			TRACE(TRACE_ERROR, "failed to add vendor IE\n");
		}
		Set_hspot_flag(hspotap->prefix, HSFLG_P2P_CRS, FALSE);
	}

	Set_hspot_flag(hspotap->prefix, HSFLG_ICMPV4_ECHO, TRUE);
	Set_hspot_flag(hspotap->prefix, HSFLG_L2_TRF, TRUE);
	update_l2_traffic_inspect(hspotap);

	snprintf(varvalue, sizeof(varvalue), "%d", hspotap->hs_ie_enabled);
	ret = nvram_set(strcat_r(hspotap->prefix, "hs2en", varname), varvalue);
	if (ret) {
		printf("nvram_set %s=%s failure\n", varname, varvalue);
		err = -1;
	}

	Reset_Opclass(hspotap, TRUE);
	Reset_Anonai(hspotap, TRUE);

	/* ---- Passpoint Flags  ----------------------------------- */
	snprintf(varvalue, sizeof(varvalue), "%d", hspotap->gas_cb_delay);
	ret = nvram_set(strcat_r(hspotap->prefix, "gascbdelay", varname), varvalue);
	if (ret) {
		printf("nvram_set %s=%s failure\n", varname, varvalue);
		err = -1;
	}

	snprintf(varvalue, sizeof(varvalue), "%d", (!(hspotap->isGasPauseForServerResponse)));
	ret = nvram_set(strcat_r(hspotap->prefix, "4framegas", varname), varvalue);
	if (ret) {
		printf("nvram_set %s=%s failure\n", varname, varvalue);
		err = -1;
	}

	Set_hspot_flag(hspotap->prefix, HSFLG_USE_SIM, FALSE);

	Reset_Oplist(hspotap, TRUE);
	Reset_WanMetrics(hspotap, TRUE);
	Reset_Homeqlist(hspotap, TRUE);

	/* ---- temporary ----------------------------------- */
	Reset_ConnCaplist(hspotap, TRUE);

	/* ////////////////// U 11 /////////////////// */
	Reset_IPaddr(hspotap, TRUE);
	Reset_NatList(hspotap, TRUE);

	/* ---- temporary U11 ----------------------------------- */
	Reset_Realmlist(hspotap, TRUE);

	nvram_commit();

	return err;
}

/* ------------------------------------------------------------------------------ */
static int
hspot_cmd_nai_realm_list_handler(hspotApT *hspotap,
	char **argv, char *txData, bool *set_tx_data)
{
	int err = 0, ret = 0, useSim = 0, realm_id = 1, iR = 0;
	char varname[NVRAM_MAX_PARAM_LEN] = {0};
	uint8 auth_MSCHAPV2[1]		= { (uint8)REALM_MSCHAPV2 };
	uint8 auth_UNAMPSWD[1]		= { (uint8)REALM_USERNAME_PASSWORD };
	uint8 auth_CERTIFICATE[1]	= { (uint8)REALM_CERTIFICATE };
	uint8 auth_SIM[1]		= { (uint8)REALM_SIM };

	memset(&hspotap->realmlist, 0, sizeof(bcm_decode_anqp_nai_realm_list_t));

	if (argv[0] == NULL) {
		printf("missing parameter in command nai_realm_list\n");
		return -1;
	}

	realm_id = atoi(argv[0]);

	switch (realm_id)
	{

	case 1:
	hspotap->realmlist.isDecodeValid = TRUE;
	hspotap->realmlist.realmCount = 4;

	useSim = Get_hspot_flag(hspotap->prefix, HSFLG_USE_SIM);
	iR = 0;

	if (!useSim) {
	/* Realm 1 --------------------------------------------- */
	hspotap->realmlist.realm[iR].encoding = (uint8)REALM_ENCODING_RFC4282;
	hspotap->realmlist.realm[iR].realmLen = strlen(MAIL);
	strncpy_n((char*)hspotap->realmlist.realm[iR].realm, MAIL,
		BCM_DECODE_ANQP_MAX_REALM_LENGTH + 1);
	hspotap->realmlist.realm[iR].eapCount = 1;
	/* EAP 1.1 */
	hspotap->realmlist.realm[iR].eap[0].eapMethod = (uint8)REALM_EAP_TTLS;
	hspotap->realmlist.realm[iR].eap[0].authCount = 2;
	/* Auth 1.1.1 */
	hspotap->realmlist.realm[iR].eap[0].auth[0].id = (uint8)REALM_NON_EAP_INNER_AUTHENTICATION;
	hspotap->realmlist.realm[iR].eap[0].auth[0].len = sizeof(auth_MSCHAPV2);
	memcpy(hspotap->realmlist.realm[iR].eap[0].auth[0].value,
		auth_MSCHAPV2, sizeof(auth_MSCHAPV2));
	/* Auth 1.1.2 */
	hspotap->realmlist.realm[iR].eap[0].auth[1].id = (uint8)REALM_CREDENTIAL;
	hspotap->realmlist.realm[iR].eap[0].auth[1].len = sizeof(auth_UNAMPSWD);
	memcpy(hspotap->realmlist.realm[iR].eap[0].auth[1].value,
		auth_UNAMPSWD, sizeof(auth_UNAMPSWD));
	iR++;
	/* -------------------------------------------------- */
	}

	/* Realm 2 --------------------------------------------- */
	hspotap->realmlist.realm[iR].encoding = (uint8)REALM_ENCODING_RFC4282;
	hspotap->realmlist.realm[iR].realmLen = strlen(CISCO);
	strncpy_n((char*)hspotap->realmlist.realm[iR].realm, CISCO,
		BCM_DECODE_ANQP_MAX_REALM_LENGTH + 1);
	hspotap->realmlist.realm[iR].eapCount = 1;
	/* EAP 2.1 */
	hspotap->realmlist.realm[iR].eap[0].eapMethod = (uint8)REALM_EAP_TTLS;
	hspotap->realmlist.realm[iR].eap[0].authCount = 2;
	/* Auth 2.1.1 */
	hspotap->realmlist.realm[iR].eap[0].auth[0].id = (uint8)REALM_NON_EAP_INNER_AUTHENTICATION;
	hspotap->realmlist.realm[iR].eap[0].auth[0].len = sizeof(auth_MSCHAPV2);
	memcpy(hspotap->realmlist.realm[iR].eap[0].auth[0].value,
		auth_MSCHAPV2, sizeof(auth_MSCHAPV2));
	/* Auth 2.1.2 */
	hspotap->realmlist.realm[iR].eap[0].auth[1].id = (uint8)REALM_CREDENTIAL;
	hspotap->realmlist.realm[iR].eap[0].auth[1].len = sizeof(auth_UNAMPSWD);
	memcpy(hspotap->realmlist.realm[iR].eap[0].auth[1].value,
		auth_UNAMPSWD, sizeof(auth_UNAMPSWD));
	iR++;
	/* -------------------------------------------------- */

	/* Realm 3 --------------------------------------------- */
	hspotap->realmlist.realm[iR].encoding = (uint8)REALM_ENCODING_RFC4282;
	hspotap->realmlist.realm[iR].realmLen = strlen(WIFI);
	strncpy_n((char*)hspotap->realmlist.realm[iR].realm, WIFI,
		BCM_DECODE_ANQP_MAX_REALM_LENGTH + 1);
	hspotap->realmlist.realm[iR].eapCount = 2;
	/* EAP 3.1 */
	hspotap->realmlist.realm[iR].eap[0].eapMethod = (uint8)REALM_EAP_TTLS;
	hspotap->realmlist.realm[iR].eap[0].authCount = 2;
	/* Auth 3.1.1 */
	hspotap->realmlist.realm[iR].eap[0].auth[0].id = (uint8)REALM_NON_EAP_INNER_AUTHENTICATION;
	hspotap->realmlist.realm[iR].eap[0].auth[0].len = sizeof(auth_MSCHAPV2);
	memcpy(hspotap->realmlist.realm[iR].eap[0].auth[0].value,
		auth_MSCHAPV2, sizeof(auth_MSCHAPV2));
	/* Auth 3.1.2 */
	hspotap->realmlist.realm[iR].eap[0].auth[1].id = (uint8)REALM_CREDENTIAL;
	hspotap->realmlist.realm[iR].eap[0].auth[1].len = sizeof(auth_UNAMPSWD);
	memcpy(hspotap->realmlist.realm[iR].eap[0].auth[1].value,
		auth_UNAMPSWD, sizeof(auth_UNAMPSWD));
	/* EAP 3.2 */
	hspotap->realmlist.realm[iR].eap[1].eapMethod = (uint8)REALM_EAP_TLS;
	hspotap->realmlist.realm[iR].eap[1].authCount = 1;
	/* Auth 3.2.1 */
	hspotap->realmlist.realm[iR].eap[1].auth[0].id = (uint8)REALM_CREDENTIAL;
	hspotap->realmlist.realm[iR].eap[1].auth[0].len = sizeof(auth_CERTIFICATE);
	memcpy(hspotap->realmlist.realm[iR].eap[1].auth[0].value,
		auth_CERTIFICATE, sizeof(auth_CERTIFICATE));
	iR++;
	/* -------------------------------------------------- */

	/* Realm 4 --------------------------------------------- */
	hspotap->realmlist.realm[iR].encoding = (uint8)REALM_ENCODING_RFC4282;
	hspotap->realmlist.realm[iR].realmLen = strlen(EXAMPLE4);
	strncpy_n((char*)hspotap->realmlist.realm[iR].realm, EXAMPLE4,
		BCM_DECODE_ANQP_MAX_REALM_LENGTH + 1);
	hspotap->realmlist.realm[iR].eapCount = 1;
	/* EAP 4.1 */
	hspotap->realmlist.realm[iR].eap[0].eapMethod = (uint8)REALM_EAP_TLS;
	hspotap->realmlist.realm[iR].eap[0].authCount = 1;
	/* Auth 4.1.1 */
	hspotap->realmlist.realm[iR].eap[0].auth[0].id = (uint8)REALM_CREDENTIAL;
	hspotap->realmlist.realm[iR].eap[0].auth[0].len = sizeof(auth_CERTIFICATE);
	memcpy(hspotap->realmlist.realm[iR].eap[0].auth[0].value,
		auth_CERTIFICATE, sizeof(auth_CERTIFICATE));
	iR++;
	/* -------------------------------------------------- */

	if (useSim) {
	/* Realm 4 --------------------------------------------- */
	hspotap->realmlist.realm[iR].encoding = (uint8)REALM_ENCODING_RFC4282;
	hspotap->realmlist.realm[iR].realmLen = strlen(MAIL);
	strncpy_n((char*)hspotap->realmlist.realm[iR].realm, MAIL,
		BCM_DECODE_ANQP_MAX_REALM_LENGTH + 1);
	hspotap->realmlist.realm[iR].eapCount = 1;
	/* EAP 4.1 */
	hspotap->realmlist.realm[iR].eap[0].eapMethod = (uint8)REALM_EAP_SIM;
	hspotap->realmlist.realm[iR].eap[0].authCount = 1;
	/* Auth 4.1.1 */
	hspotap->realmlist.realm[iR].eap[0].auth[0].id = (uint8)REALM_CREDENTIAL;
	hspotap->realmlist.realm[iR].eap[0].auth[0].len = sizeof(auth_SIM);
	memcpy(hspotap->realmlist.realm[iR].eap[0].auth[0].value,
		auth_SIM, sizeof(auth_SIM));
	}
	/* -------------------------------------------------- */

	/* set NVRAM value */
	ret = nvram_set(strcat_r(hspotap->prefix, "realmlist", varname),
	useSim ? REALMLIST_ID1_SIM : REALMLIST_ID1);

	break;

	case 2:
	hspotap->realmlist.isDecodeValid = TRUE;
	hspotap->realmlist.realmCount = 1;

	/* Realm 1 --------------------------------------------- */
	hspotap->realmlist.realm[0].encoding = (uint8)REALM_ENCODING_RFC4282;
	hspotap->realmlist.realm[0].realmLen = strlen(WIFI);
	strncpy_n((char*)hspotap->realmlist.realm[0].realm, WIFI,
		BCM_DECODE_ANQP_MAX_REALM_LENGTH + 1);
	hspotap->realmlist.realm[0].eapCount = 1;
	/* EAP 1.1 */
	hspotap->realmlist.realm[0].eap[0].eapMethod = (uint8)REALM_EAP_TTLS;
	hspotap->realmlist.realm[0].eap[0].authCount = 2;
	/* Auth 1.1.1 */
	hspotap->realmlist.realm[0].eap[0].auth[0].id = (uint8)REALM_NON_EAP_INNER_AUTHENTICATION;
	hspotap->realmlist.realm[0].eap[0].auth[0].len = sizeof(auth_MSCHAPV2);
	memcpy(hspotap->realmlist.realm[0].eap[0].auth[0].value,
		auth_MSCHAPV2, sizeof(auth_MSCHAPV2));
	/* Auth 1.1.2 */
	hspotap->realmlist.realm[0].eap[0].auth[1].id = (uint8)REALM_CREDENTIAL;
	hspotap->realmlist.realm[0].eap[0].auth[1].len = sizeof(auth_UNAMPSWD);
	memcpy(hspotap->realmlist.realm[0].eap[0].auth[1].value,
		auth_UNAMPSWD, sizeof(auth_UNAMPSWD));
	/* -------------------------------------------------- */

	/* set NVRAM value */
	ret = nvram_set(strcat_r(hspotap->prefix, "realmlist", varname), REALMLIST_ID2);
	break;

	case 3:
	hspotap->realmlist.isDecodeValid = TRUE;
	hspotap->realmlist.realmCount = 3;

	/* Realm 1 --------------------------------------------- */
	hspotap->realmlist.realm[0].encoding = (uint8)REALM_ENCODING_RFC4282;
	hspotap->realmlist.realm[0].realmLen = strlen(CISCO);
	strncpy_n((char*)hspotap->realmlist.realm[0].realm, CISCO,
		BCM_DECODE_ANQP_MAX_REALM_LENGTH + 1);
	hspotap->realmlist.realm[0].eapCount = 1;
	/* EAP 1.1 */
	hspotap->realmlist.realm[0].eap[0].eapMethod = (uint8)REALM_EAP_TTLS;
	hspotap->realmlist.realm[0].eap[0].authCount = 2;
	/* Auth 1.1.1 */
	hspotap->realmlist.realm[0].eap[0].auth[0].id = (uint8)REALM_NON_EAP_INNER_AUTHENTICATION;
	hspotap->realmlist.realm[0].eap[0].auth[0].len = sizeof(auth_MSCHAPV2);
	memcpy(hspotap->realmlist.realm[0].eap[0].auth[0].value,
		auth_MSCHAPV2, sizeof(auth_MSCHAPV2));
	/* Auth 1.1.2 */
	hspotap->realmlist.realm[0].eap[0].auth[1].id = (uint8)REALM_CREDENTIAL;
	hspotap->realmlist.realm[0].eap[0].auth[1].len = sizeof(auth_UNAMPSWD);
	memcpy(hspotap->realmlist.realm[0].eap[0].auth[1].value,
		auth_UNAMPSWD, sizeof(auth_UNAMPSWD));
	/* -------------------------------------------------- */

	/* Realm 2 --------------------------------------------- */
	hspotap->realmlist.realm[1].encoding = (uint8)REALM_ENCODING_RFC4282;
	hspotap->realmlist.realm[1].realmLen = strlen(WIFI);
	strncpy_n((char*)hspotap->realmlist.realm[1].realm, WIFI,
		BCM_DECODE_ANQP_MAX_REALM_LENGTH + 1);
	hspotap->realmlist.realm[1].eapCount = 2;
	/* EAP 2.1 */
	hspotap->realmlist.realm[1].eap[0].eapMethod = (uint8)REALM_EAP_TTLS;
	hspotap->realmlist.realm[1].eap[0].authCount = 2;
	/* Auth 2.1.1 */
	hspotap->realmlist.realm[1].eap[0].auth[0].id = (uint8)REALM_NON_EAP_INNER_AUTHENTICATION;
	hspotap->realmlist.realm[1].eap[0].auth[0].len = sizeof(auth_MSCHAPV2);
	memcpy(hspotap->realmlist.realm[1].eap[0].auth[0].value,
		auth_MSCHAPV2, sizeof(auth_MSCHAPV2));
	/* Auth 2.1.2 */
	hspotap->realmlist.realm[1].eap[0].auth[1].id = (uint8)REALM_CREDENTIAL;
	hspotap->realmlist.realm[1].eap[0].auth[1].len = sizeof(auth_UNAMPSWD);
	memcpy(hspotap->realmlist.realm[1].eap[0].auth[1].value,
		auth_UNAMPSWD, sizeof(auth_UNAMPSWD));
	/* EAP 2.2 */
	hspotap->realmlist.realm[1].eap[1].eapMethod = (uint8)REALM_EAP_TLS;
	hspotap->realmlist.realm[1].eap[1].authCount = 1;
	/* Auth 2.2.1 */
	hspotap->realmlist.realm[1].eap[1].auth[0].id = (uint8)REALM_CREDENTIAL;
	hspotap->realmlist.realm[1].eap[1].auth[0].len = sizeof(auth_CERTIFICATE);
	memcpy(hspotap->realmlist.realm[1].eap[1].auth[0].value,
		auth_CERTIFICATE, sizeof(auth_CERTIFICATE));
	/* -------------------------------------------------- */

	/* Realm 3 --------------------------------------------- */
	hspotap->realmlist.realm[2].encoding = (uint8)REALM_ENCODING_RFC4282;
	hspotap->realmlist.realm[2].realmLen = strlen(EXAMPLE4);
	strncpy_n((char*)hspotap->realmlist.realm[2].realm, EXAMPLE4,
		BCM_DECODE_ANQP_MAX_REALM_LENGTH + 1);
	hspotap->realmlist.realm[2].eapCount = 1;
	/* EAP 3.1 */
	hspotap->realmlist.realm[2].eap[0].eapMethod = (uint8)REALM_EAP_TLS;
	hspotap->realmlist.realm[2].eap[0].authCount = 1;
	/* Auth 3.1.1 */
	hspotap->realmlist.realm[2].eap[0].auth[0].id = (uint8)REALM_CREDENTIAL;
	hspotap->realmlist.realm[2].eap[0].auth[0].len = sizeof(auth_CERTIFICATE);
	memcpy(hspotap->realmlist.realm[2].eap[0].auth[0].value,
		auth_CERTIFICATE, sizeof(auth_CERTIFICATE));
	/* -------------------------------------------------- */

	/* set NVRAM value */
	ret = nvram_set(strcat_r(hspotap->prefix, "realmlist", varname), REALMLIST_ID3);
	break;

	case 4:
	hspotap->realmlist.isDecodeValid = TRUE;
	hspotap->realmlist.realmCount = 1;

	/* Realm 1 --------------------------------------------- */
	hspotap->realmlist.realm[0].encoding = (uint8)REALM_ENCODING_RFC4282;
	hspotap->realmlist.realm[0].realmLen = strlen(MAIL);
	strncpy_n((char*)hspotap->realmlist.realm[0].realm, MAIL,
		BCM_DECODE_ANQP_MAX_REALM_LENGTH + 1);
	hspotap->realmlist.realm[0].eapCount = 2;
	/* EAP 1.1 */
	hspotap->realmlist.realm[0].eap[0].eapMethod = (uint8)REALM_EAP_TTLS;
	hspotap->realmlist.realm[0].eap[0].authCount = 2;
	/* Auth 1.1.1 */
	hspotap->realmlist.realm[0].eap[0].auth[0].id = (uint8)REALM_NON_EAP_INNER_AUTHENTICATION;
	hspotap->realmlist.realm[0].eap[0].auth[0].len = sizeof(auth_MSCHAPV2);
	memcpy(hspotap->realmlist.realm[0].eap[0].auth[0].value,
		auth_MSCHAPV2, sizeof(auth_MSCHAPV2));
	/* Auth 1.1.2 */
	hspotap->realmlist.realm[0].eap[0].auth[1].id = (uint8)REALM_CREDENTIAL;
	hspotap->realmlist.realm[0].eap[0].auth[1].len = sizeof(auth_UNAMPSWD);
	memcpy(hspotap->realmlist.realm[0].eap[0].auth[1].value,
		auth_UNAMPSWD, sizeof(auth_UNAMPSWD));
	/* EAP 1.2 */
	hspotap->realmlist.realm[0].eap[1].eapMethod = (uint8)REALM_EAP_TLS;
	hspotap->realmlist.realm[0].eap[1].authCount = 1;
	/* Auth 1.2.1 */
	hspotap->realmlist.realm[0].eap[1].auth[0].id = (uint8)REALM_CREDENTIAL;
	hspotap->realmlist.realm[0].eap[1].auth[0].len = sizeof(auth_CERTIFICATE);
	memcpy(hspotap->realmlist.realm[0].eap[1].auth[0].value,
		auth_CERTIFICATE, sizeof(auth_CERTIFICATE));
	/* -------------------------------------------------- */

	/* set NVRAM value */
	ret = nvram_set(strcat_r(hspotap->prefix, "realmlist", varname), REALMLIST_ID4);
	break;

	case 5:
	hspotap->realmlist.isDecodeValid = TRUE;
	hspotap->realmlist.realmCount = 2;

	/* Realm 1 --------------------------------------------- */
	hspotap->realmlist.realm[0].encoding = (uint8)REALM_ENCODING_RFC4282;
	hspotap->realmlist.realm[0].realmLen = strlen(WIFI);
	strncpy_n((char*)hspotap->realmlist.realm[0].realm, WIFI,
		BCM_DECODE_ANQP_MAX_REALM_LENGTH + 1);
	hspotap->realmlist.realm[0].eapCount = 1;
	/* EAP 1 */
	hspotap->realmlist.realm[0].eap[0].eapMethod = (uint8)REALM_EAP_TTLS;
	hspotap->realmlist.realm[0].eap[0].authCount = 2;
	/* Auth 1.1 */
	hspotap->realmlist.realm[0].eap[0].auth[0].id = (uint8)REALM_NON_EAP_INNER_AUTHENTICATION;
	hspotap->realmlist.realm[0].eap[0].auth[0].len = sizeof(auth_MSCHAPV2);
	memcpy(hspotap->realmlist.realm[0].eap[0].auth[0].value,
		auth_MSCHAPV2, sizeof(auth_MSCHAPV2));
	/* Auth 1.1.2 */
	hspotap->realmlist.realm[0].eap[0].auth[1].id = (uint8)REALM_CREDENTIAL;
	hspotap->realmlist.realm[0].eap[0].auth[1].len = sizeof(auth_UNAMPSWD);
	memcpy(hspotap->realmlist.realm[0].eap[0].auth[1].value,
		auth_UNAMPSWD, sizeof(auth_UNAMPSWD));
	/* -------------------------------------------------- */

	/* Realm 2 --------------------------------------------- */
	hspotap->realmlist.realm[1].encoding = (uint8)REALM_ENCODING_RFC4282;
	hspotap->realmlist.realm[1].realmLen = strlen(RUCKUS);
	strncpy_n((char*)hspotap->realmlist.realm[1].realm, RUCKUS,
		BCM_DECODE_ANQP_MAX_REALM_LENGTH + 1);
	hspotap->realmlist.realm[1].eapCount = 1;
	/* EAP 2.1 */
	hspotap->realmlist.realm[1].eap[0].eapMethod = (uint8)REALM_EAP_TTLS;
	hspotap->realmlist.realm[1].eap[0].authCount = 2;
	/* Auth 2.1.1 */
	hspotap->realmlist.realm[1].eap[0].auth[0].id = (uint8)REALM_NON_EAP_INNER_AUTHENTICATION;
	hspotap->realmlist.realm[1].eap[0].auth[0].len = sizeof(auth_MSCHAPV2);
	memcpy(hspotap->realmlist.realm[1].eap[0].auth[0].value,
		auth_MSCHAPV2, sizeof(auth_MSCHAPV2));
	/* Auth 2.1.2 */
	hspotap->realmlist.realm[1].eap[0].auth[1].id = (uint8)REALM_CREDENTIAL;
	hspotap->realmlist.realm[1].eap[0].auth[1].len = sizeof(auth_UNAMPSWD);
	memcpy(hspotap->realmlist.realm[1].eap[0].auth[1].value,
		auth_UNAMPSWD, sizeof(auth_UNAMPSWD));
	/* -------------------------------------------------- */

	/* set NVRAM value */
	ret = nvram_set(strcat_r(hspotap->prefix, "realmlist", varname), REALMLIST_ID5);
	break;

	case 6:
	hspotap->realmlist.isDecodeValid = TRUE;
	hspotap->realmlist.realmCount = 2;

	/* Realm 1 --------------------------------------------- */
	hspotap->realmlist.realm[0].encoding = (uint8)REALM_ENCODING_RFC4282;
	hspotap->realmlist.realm[0].realmLen = strlen(WIFI);
	strncpy_n((char*)hspotap->realmlist.realm[0].realm, WIFI,
		BCM_DECODE_ANQP_MAX_REALM_LENGTH + 1);
	hspotap->realmlist.realm[0].eapCount = 1;
	/* EAP 1.1 */
	hspotap->realmlist.realm[0].eap[0].eapMethod = (uint8)REALM_EAP_TTLS;
	hspotap->realmlist.realm[0].eap[0].authCount = 2;
	/* Auth 1.1.1 */
	hspotap->realmlist.realm[0].eap[0].auth[0].id = (uint8)REALM_NON_EAP_INNER_AUTHENTICATION;
	hspotap->realmlist.realm[0].eap[0].auth[0].len = sizeof(auth_MSCHAPV2);
	memcpy(hspotap->realmlist.realm[0].eap[0].auth[0].value,
		auth_MSCHAPV2, sizeof(auth_MSCHAPV2));
	/* Auth 1.1.2 */
	hspotap->realmlist.realm[0].eap[0].auth[1].id = (uint8)REALM_CREDENTIAL;
	hspotap->realmlist.realm[0].eap[0].auth[1].len = sizeof(auth_UNAMPSWD);
	memcpy(hspotap->realmlist.realm[0].eap[0].auth[1].value,
		auth_UNAMPSWD, sizeof(auth_UNAMPSWD));
	/* -------------------------------------------------- */

	/* Realm 2 --------------------------------------------- */
	hspotap->realmlist.realm[1].encoding = (uint8)REALM_ENCODING_RFC4282;
	hspotap->realmlist.realm[1].realmLen = strlen(MAIL);
		strncpy_n((char*)hspotap->realmlist.realm[1].realm, MAIL,
		BCM_DECODE_ANQP_MAX_REALM_LENGTH + 1);
	hspotap->realmlist.realm[1].eapCount = 1;
	/* EAP 2.1 */
	hspotap->realmlist.realm[1].eap[0].eapMethod = (uint8)REALM_EAP_TTLS;
	hspotap->realmlist.realm[1].eap[0].authCount = 2;
	/* Auth 2.1.1 */
	hspotap->realmlist.realm[1].eap[0].auth[0].id = (uint8)REALM_NON_EAP_INNER_AUTHENTICATION;
	hspotap->realmlist.realm[1].eap[0].auth[0].len = sizeof(auth_MSCHAPV2);
	memcpy(hspotap->realmlist.realm[1].eap[0].auth[0].value,
		auth_MSCHAPV2, sizeof(auth_MSCHAPV2));
	/* Auth 2.1.2 */
	hspotap->realmlist.realm[1].eap[0].auth[1].id = (uint8)REALM_CREDENTIAL;
	hspotap->realmlist.realm[1].eap[0].auth[1].len = sizeof(auth_UNAMPSWD);
	memcpy(hspotap->realmlist.realm[1].eap[0].auth[1].value,
		auth_UNAMPSWD, sizeof(auth_UNAMPSWD));
	/* -------------------------------------------------- */

	/* set NVRAM value */
	ret = nvram_set(strcat_r(hspotap->prefix, "realmlist", varname), REALMLIST_ID6);
	break;

	case 7:
	hspotap->realmlist.isDecodeValid = TRUE;
	hspotap->realmlist.realmCount = 1;

	/* Realm 1 --------------------------------------------- */
	hspotap->realmlist.realm[0].encoding = (uint8)REALM_ENCODING_RFC4282;
	hspotap->realmlist.realm[0].realmLen = strlen(WIFI);
	strncpy_n((char*)hspotap->realmlist.realm[0].realm, WIFI,
		BCM_DECODE_ANQP_MAX_REALM_LENGTH + 1);
	hspotap->realmlist.realm[0].eapCount = 2;
	/* EAP 1.1 */
	hspotap->realmlist.realm[0].eap[0].eapMethod = (uint8)REALM_EAP_TLS;
	hspotap->realmlist.realm[0].eap[0].authCount = 1;
	/* Auth 1.1.1 */
	hspotap->realmlist.realm[0].eap[0].auth[0].id = (uint8)REALM_CREDENTIAL;
	hspotap->realmlist.realm[0].eap[0].auth[0].len = sizeof(auth_CERTIFICATE);
	memcpy(hspotap->realmlist.realm[0].eap[0].auth[0].value,
		auth_CERTIFICATE, sizeof(auth_CERTIFICATE));
	/* EAP 1.2 */
	hspotap->realmlist.realm[0].eap[1].eapMethod = (uint8)REALM_EAP_TTLS;
	hspotap->realmlist.realm[0].eap[1].authCount = 2;
	/* Auth 1.2.1 */
	hspotap->realmlist.realm[0].eap[1].auth[0].id = (uint8)REALM_NON_EAP_INNER_AUTHENTICATION;
	hspotap->realmlist.realm[0].eap[1].auth[0].len = sizeof(auth_MSCHAPV2);
	memcpy(hspotap->realmlist.realm[0].eap[1].auth[0].value,
		auth_MSCHAPV2, sizeof(auth_MSCHAPV2));
	/* Auth 1.2.2 */
	hspotap->realmlist.realm[0].eap[1].auth[1].id = (uint8)REALM_CREDENTIAL;
	hspotap->realmlist.realm[0].eap[1].auth[1].len = sizeof(auth_UNAMPSWD);
	memcpy(hspotap->realmlist.realm[0].eap[1].auth[1].value,
		auth_UNAMPSWD, sizeof(auth_UNAMPSWD));
	/* -------------------------------------------------- */

	/* set NVRAM value */
	ret = nvram_set(strcat_r(hspotap->prefix, "realmlist", varname), REALMLIST_ID7);
	break;
	}

	if (ret) {
		printf("nvram_set %s=%s failure\n", varname, "");
		err = -1;
	}

	nvram_commit();
	return err;
}

static int hspot_cmd_oper_name_handler(hspotApT *hspotap,
	char **argv, char *txData, bool *set_tx_data)
{
	int err = 0, oper_id = 1;

	if (argv[0] == NULL) {
		printf("missing parameter in command oper_name\n");
		return -1;
	}

	oper_id = atoi(argv[0]);
	printf("oper_name id %d\n", oper_id);

	if (oper_id == 1)
		err = Reset_Oplist(hspotap, TRUE);

	return err;
}

static int hspot_cmd_wan_metrics_handler(hspotApT *hspotap,
	char **argv, char *txData, bool *set_tx_data)
{
	int ret, err = 0, wanm_id = 1;
	char varvalue[NVRAM_MAX_VALUE_LEN];
	char varname[NVRAM_MAX_PARAM_LEN];

	if (argv[0] == NULL) {
		printf("missing parameter in command wan_metrics\n");
		return -1;
	}

	wanm_id = atoi(argv[0]);
	printf("wan_metrics id %d\n", wanm_id);

	memset(&hspotap->wanmetrics, 0, sizeof(bcm_decode_hspot_anqp_wan_metrics_t));

	hspotap->wanmetrics.isDecodeValid	= TRUE;
	hspotap->wanmetrics.linkStatus		= HSPOT_WAN_LINK_UP;
	hspotap->wanmetrics.symmetricLink	= HSPOT_WAN_NOT_SYMMETRIC_LINK;
	hspotap->wanmetrics.atCapacity		= HSPOT_WAN_NOT_AT_CAPACITY;
	hspotap->wanmetrics.lmd				= 10;

	if (wanm_id == 1) {
		hspotap->wanmetrics.dlinkSpeed	= 2500;
		hspotap->wanmetrics.ulinkSpeed	= 384;
		hspotap->wanmetrics.dlinkLoad	= 0;
		hspotap->wanmetrics.ulinkLoad	= 0;
	}
	else if (wanm_id == 2) {
		hspotap->wanmetrics.dlinkSpeed	= 1500;
		hspotap->wanmetrics.ulinkSpeed	= 384;
		hspotap->wanmetrics.dlinkLoad	= 20;
		hspotap->wanmetrics.ulinkLoad	= 20;
	}
	else if (wanm_id == 3) {
		hspotap->wanmetrics.dlinkSpeed	= 2000;
		hspotap->wanmetrics.ulinkSpeed	= 1000;
		hspotap->wanmetrics.dlinkLoad	= 20;
		hspotap->wanmetrics.ulinkLoad	= 20;
	}
	else if (wanm_id == 4) {
		hspotap->wanmetrics.dlinkSpeed	= 8000;
		hspotap->wanmetrics.ulinkSpeed	= 1000;
		hspotap->wanmetrics.dlinkLoad	= 20;
		hspotap->wanmetrics.ulinkLoad	= 20;
	}
	else if (wanm_id == 5) {
		hspotap->wanmetrics.dlinkSpeed	= 9000;
		hspotap->wanmetrics.ulinkSpeed	= 5000;
		hspotap->wanmetrics.dlinkLoad	= 20;
		hspotap->wanmetrics.ulinkLoad	= 20;
	}

	memset(varname, 0, sizeof(varname));
	snprintf(varvalue, sizeof(varvalue), "%d:%d:%d=%d>%d=%d>%d=%d",
		(int)hspotap->wanmetrics.linkStatus, (int)hspotap->wanmetrics.symmetricLink,
		(int)hspotap->wanmetrics.atCapacity, (int)hspotap->wanmetrics.dlinkSpeed,
		(int)hspotap->wanmetrics.ulinkSpeed, (int)hspotap->wanmetrics.dlinkLoad,
		(int)hspotap->wanmetrics.ulinkLoad, (int)hspotap->wanmetrics.lmd);

	ret = nvram_set(strcat_r(hspotap->prefix, "wanmetrics", varname), varvalue);
	if (ret) {
		printf("nvram_set %s=%s failure\n", varname, varvalue);
		err = -1;
	}

	nvram_commit();
	return err;
}

static int hspot_cmd_conn_cap_handler(hspotApT *hspotap,
	char **argv, char *txData, bool *set_tx_data)
{
	int err = 0, ret;
	char varname[NVRAM_MAX_PARAM_LEN];
	char varvalue[NVRAM_MAX_VALUE_LEN];

	if (argv[0] == NULL) {
		printf("missing parameter in command conn_cap\n");
		return -1;
	}

	hspotap->conn_id = atoi(argv[0]);
	printf("conn_cap id %d\n", hspotap->conn_id);

	snprintf(varvalue, sizeof(varvalue), "%d", hspotap->conn_id);
	ret = nvram_set(strcat_r(hspotap->prefix, "conn_id", varname), varvalue);
	if (ret) {
		printf("nvram_set %s=%s failure\n", varname, varvalue);
		err = -1;
	}

	nvram_commit();
	return err;
}

static int hspot_cmd_oper_class_handler(hspotApT *hspotap,
	char **argv, char *txData, bool *set_tx_data)
{
	int err = 0, ret, Operating_Class = 0;
	char varvalue[NVRAM_MAX_VALUE_LEN];
	char varname[NVRAM_MAX_PARAM_LEN];
	uint8 opClass1 [1] = {81};
	uint8 opClass2 [1] = {115};
	uint8 opClass3 [2] = {81, 115};

	if (argv[0] == NULL) {
		printf("missing parameter in command conn_cap\n");
		return -1;
	}

	memset(&hspotap->opclass, 0, sizeof(bcm_decode_hspot_anqp_operating_class_indication_t));
	hspotap->opclass.isDecodeValid = TRUE;

	Operating_Class = atoi(argv[0]);
	printf("conn_cap id %d\n", Operating_Class);

	if (Operating_Class == 3) {
		hspotap->opclass.opClassLen = sizeof(opClass3);
		memcpy(hspotap->opclass.opClass, opClass3, sizeof(opClass3));
	}
	else if (Operating_Class == 2) {
		hspotap->opclass.opClassLen = sizeof(opClass2);
		memcpy(hspotap->opclass.opClass, opClass3, sizeof(opClass2));
	}
	else if (Operating_Class == 1) {
		hspotap->opclass.opClassLen = sizeof(opClass1);
		memcpy(hspotap->opclass.opClass, opClass3, sizeof(opClass1));
	}
	else {
		hspotap->opclass.opClassLen = 0;
		memcpy(hspotap->opclass.opClass, opClass3, sizeof(opClass3));
	}

	snprintf(varvalue, sizeof(varvalue), "%d", Operating_Class);
	ret = nvram_set(strcat_r(hspotap->prefix, "opercls", varname), varvalue);
	if (ret) {
		printf("nvram_set %s=%s failure\n", varname, varvalue);
		err = -1;
	}
	nvram_commit();

	return err;
}

static int hspot_cmd_net_auth_type_handler(hspotApT *hspotap,
	char **argv, char *txData, bool *set_tx_data)
{
	int ret, err = 0, nat_id = 1;
	char varvalue[NVRAM_MAX_VALUE_LEN] = {0};
	char varname[NVRAM_MAX_PARAM_LEN] = {0};

	if (argv[0] == NULL) {
		printf("missing parameter in command net_auth_type\n");
		return -1;
	}

	nat_id = atoi(argv[0]);
	printf("net_auth_type id %d\n", nat_id);

	memset(varvalue, 0, sizeof(varvalue));
	memset(&hspotap->netauthlist, 0, sizeof(bcm_decode_anqp_network_authentication_type_t));
	hspotap->netauthlist.isDecodeValid = TRUE;

	if (nat_id == 1)
	{
		#define URL	"https://tandc-server.wi-fi.org"

		hspotap->netauthlist.numAuthenticationType = 2;

		hspotap->netauthlist.unit[0].type = (uint8)NATI_ACCEPTANCE_OF_TERMS_CONDITIONS;
		hspotap->netauthlist.unit[0].urlLen = 0;
		strncpy_n((char*)hspotap->netauthlist.unit[0].url, "",
			BCM_DECODE_ANQP_MAX_URL_LENGTH + 1);

		hspotap->netauthlist.unit[1].type = (uint8)NATI_HTTP_HTTPS_REDIRECTION;
		hspotap->netauthlist.unit[1].urlLen = strlen(URL);
		strncpy_n((char*)hspotap->netauthlist.unit[1].url, URL,
			BCM_DECODE_ANQP_MAX_URL_LENGTH + 1);

		strncpy_n(varvalue, "accepttc=+httpred=https://tandc-server.wi-fi.org",
			NVRAM_MAX_VALUE_LEN);
	}
	else if (nat_id == 2)
	{
		hspotap->netauthlist.numAuthenticationType = 1;

		hspotap->netauthlist.unit[0].type = (uint8)NATI_ONLINE_ENROLLMENT_SUPPORTED;
		hspotap->netauthlist.unit[0].urlLen = 0;
		strncpy_n((char*)hspotap->netauthlist.unit[0].url, "",
			BCM_DECODE_ANQP_MAX_URL_LENGTH + 1);

		strncpy_n(varvalue, "online=", NVRAM_MAX_VALUE_LEN);
	}

	ret = nvram_set(strcat_r(hspotap->prefix, "netauthlist", varname), varvalue);
	if (ret) {
		printf("nvram_set %s=%s failure\n", varname, varvalue);
		err = -1;
	}

	nvram_commit();
	return err;
}

static int hspot_cmd_qos_map_set_handler(hspotApT *hspotap,
	char **argv, char *txData, bool *set_tx_data)
{
	int err = 0, sta_mac = 0;
	struct ether_addr addr, bssid;
	bcm_encode_t enc;
	uint8 buffer[BUFFER_SIZE];

	if (argv[0] == NULL) {
		printf("missing parameter in command qos_map_set\n");
		return err;
	}

	hspotap->qos_id = atoi(argv[0]);
	printf("qos_map_set id = %d\n", hspotap->qos_id);

	if (argv[1] != NULL) {
		if (!strToEther(argv[1], &addr)) {
			printf("<addr> format is 00:11:22:33:44:55\n");
			return -1;
		}
		sta_mac = 1;
	}

	err = update_qosmap_ie(hspotap, TRUE);

	/* Sending QoS Map Configure frame */
	bcm_encode_init(&enc, sizeof(buffer), buffer);
	if (hspotap->qos_id == 1) {
		bcm_encode_qos_map(&enc, 4, (uint8 *)"\x35\x02\x16\x06",
			8, 15, 0, 7, 255, 255, 16, 31, 32, 39, 255, 255, 40, 47, 255, 255);
	}
	else if (hspotap->qos_id == 2) {
		bcm_encode_qos_map(&enc, 0, NULL,
			8, 15, 0, 7, 255, 255, 16, 31, 32, 39, 255, 255, 40, 47, 48, 63);
	}

	/* get bssid */
	wl_cur_etheraddr(hspotap->ifr, DEFAULT_BSSCFG_INDEX, &bssid);

	if (sta_mac) {
		/* send action frame */
		wl_actframe(hspotap->ifr, DEFAULT_BSSCFG_INDEX,
			(uint32)bcm_encode_buf(&enc), 0, 250, &bssid, &addr,
			bcm_encode_length(&enc), bcm_encode_buf(&enc));
	}
	else {

	}

	return err;
}

static int hspot_cmd_bss_load_handler(hspotApT *hspotap,
	char **argv, char *txData, bool *set_tx_data)
{
	int err = 0, bssload_id = 0;

	if (argv[0] == NULL) {
		printf("missing parameter in command bss_load\n");
		return -1;
	}

	hspotap->bssload_id = bssload_id = atoi(argv[0]);
	printf("bss_load id = %d\n", hspotap->bssload_id);

	if (bssload_id < 0)
		err = update_bssload_ie(hspotap, FALSE, FALSE);
	else if (bssload_id == 0)
		err = update_bssload_ie(hspotap, FALSE, TRUE);
	else if (bssload_id > 0)
		err = update_bssload_ie(hspotap, TRUE, TRUE);

	return err;
}

static int hspot_cmd_pause_handler(hspotApT *hspotap,
	char **argv, char *txData, bool *set_tx_data)
{
	int err = 0;

	if (argv[0] == NULL) {
		printf("missing parameter in command pause\n");
		return -1;
	}

	hspotap->isGasPauseForServerResponse = (atoi(argv[0]) != 0);
	bcm_gas_set_if_gas_pause(hspotap->isGasPauseForServerResponse, hspotap->ifr);
	printf("isGasPauseForServerResponse %d\n", hspotap->isGasPauseForServerResponse);

	return err;
}

static int hspot_cmd_dis_anqp_response_handler(hspotApT *hspotap,
	char **argv, char *txData, bool *set_tx_data)
{
	int err = 0, disable_ANQP_response;

	if (argv[0] == NULL) {
		printf("missing parameter in command dis_anqp_response\n");
		return -1;
	}

	disable_ANQP_response = (atoi(argv[0]) != 0);
	printf("disable_ANQP_response %d\n", disable_ANQP_response);
	Set_hspot_flag(hspotap->prefix, HSFLG_DS_ANQP_RESP, disable_ANQP_response);

	return err;
}

static int hspot_cmd_sim_handler(hspotApT *hspotap,
	char **argv, char *txData, bool *set_tx_data)
{
	int err = 0, useSim;

	if (argv[0] == NULL) {
		printf("missing parameter in command sim\n");
		return -1;
	}

	useSim = (atoi(argv[0]) != 0);
	Set_hspot_flag(hspotap->prefix, HSFLG_USE_SIM, useSim);
	printf("useSim %d\n", useSim);

	return err;
}

static int hspot_cmd_response_size_handler(hspotApT *hspotap,
	char **argv, char *txData, bool *set_tx_data)
{
	int err = 0;

	if (argv[0] == NULL) {
		printf("missing parameter in command response_size\n");
		return -1;
	}

	hspotap->testResponseSize = atoi(argv[0]);
	printf("response_size %d\n", hspotap->testResponseSize);

	return err;
}

static int hspot_cmd_pause_cb_delay_handler(hspotApT *hspotap,
	char **argv, char *txData, bool *set_tx_data)
{
	int err = 0;
	int pause_cb_delay;

	if (argv[0] == NULL) {
		printf("missing parameter in command pause_cb_delay\n");
		return -1;
	}

	pause_cb_delay = atoi(argv[0]);
	printf("pause_cb_delay %d\n", pause_cb_delay);
	bcm_gas_set_comeback_delay_response_pause(pause_cb_delay);
	return err;
}

static int hspot_cmd_sr_handler(hspotApT *hspotap,
	char **argv, char *txData, bool *set_tx_data)
{
	int err = 0;
	struct ether_addr addr, bssid;
	char *url;
	int urlLength;
	int serverMethod;
	bcm_encode_t enc;
	uint8 buffer[BUFFER_SIZE];

	if ((argv[0] == NULL) || (argv[1] == NULL) || (argv[2] == NULL)) {
		printf("Invalid Number of Parameters\n");
		return err;
	}

	if (!strToEther(argv[0], &addr)) {
		printf("<addr> format is 00:11:22:33:44:55\n");
		return err;
	}

	url = argv[1];
	urlLength = strlen(url);
	if (urlLength > 255) {
		printf("<url> too long");
		return err;
	}

	serverMethod = atoi(argv[2]);

	bcm_encode_init(&enc, sizeof(buffer), buffer);
	bcm_encode_wnm_subscription_remediation(&enc,
		hspotap->dialogToken++, urlLength, url, serverMethod);

	/* get bssid */
	wl_cur_etheraddr(hspotap->ifr, DEFAULT_BSSCFG_INDEX, &bssid);
	/* send action frame */
	wl_actframe(hspotap->ifr, DEFAULT_BSSCFG_INDEX,
		(uint32)bcm_encode_buf(&enc), 0, 250, &bssid, &addr,
		bcm_encode_length(&enc), bcm_encode_buf(&enc));

	return err;
}

static int hspot_cmd_di_handler(hspotApT *hspotap,
	char **argv, char *txData, bool *set_tx_data)
{
	int err = 0;
	struct ether_addr addr, bssid;
	uint8 reason;
	int16 reauthDelay;
	char *url = 0;
	int urlLength = 0;
	bcm_encode_t enc;
	uint8 buffer[BUFFER_SIZE];

	if ((argv[0] == NULL) || (argv[1] == NULL) || (argv[2] == NULL))  {
		printf("invalid number of parameters\n");
		return err;
	}
	if (!strToEther(argv[0], &addr)) {
		printf("<addr> format is 00:11:22:33:44:55\n");
		return err;
	}
	reason = atoi(argv[1]);
	reauthDelay = atoi(argv[2]);

	if (argv[3] != NULL) {
		url = argv[3];
		urlLength = strlen(url);
	}

	if (urlLength > 255) {
		printf("<url> too long");
		return err;
	}

	/* Sending WNM Deauthentication Imminent Frame */
	bcm_encode_init(&enc, sizeof(buffer), buffer);
	bcm_encode_wnm_deauthentication_imminent(&enc,
		hspotap->dialogToken++, reason, reauthDelay, urlLength, url);

	/* get bssid */
	wl_cur_etheraddr(hspotap->ifr, DEFAULT_BSSCFG_INDEX, &bssid);

	/* send action frame */
	wl_actframe(hspotap->ifr, DEFAULT_BSSCFG_INDEX,
		(uint32)bcm_encode_buf(&enc), 0, 250, &bssid, &addr,
		bcm_encode_length(&enc), bcm_encode_buf(&enc));

	return err;
}

static int hspot_cmd_btredi_handler(hspotApT *hspotap,
	char **argv, char *txData, bool *set_tx_data)
{
	int err = 0;
	char *url;
	uint16 disassocTimer = 100;

	if (argv[0] == NULL) {
		printf("missing parameter in command btredi\n");
		return -1;
	}

	url = argv[0];

	if (strlen(url) > 255) {
		printf("<url> too long");
		return err;
	}

	if (wl_wnm_url(hspotap->ifr, strlen(url), (uchar *)url) < 0) {
		printf("wl_wnm_url failed\n");
		return err;
	}

	/* Sending BSS Transition Request Frame */
	if (wl_wnm_bsstrans_req(hspotap->ifr,
		/* DOT11_BSSTRANS_REQMODE_PREF_LIST_INCL | */
		DOT11_BSSTRANS_REQMODE_DISASSOC_IMMINENT |
		DOT11_BSSTRANS_REQMODE_ESS_DISASSOC_IMNT,
		disassocTimer, 0, TRUE) < 0)
	{
		printf("wl_wnm_bsstrans_req failed\n");
		return err;
	}
	return err;
}

static int hspot_cmd_help_handler(hspotApT *hspotap,
	char **argv, char *txData, bool *set_tx_data)
{
	int err = 0;

	printf("\n");
	printf("==============================================================================\n");
	printf("\t\t\tHspotAP Application - CLI Commands \n");
	printf("==============================================================================\n");
	printf(" Command 01\t: interface <interface_name> \n"
		" Example\t: interface eth1 \n"
		" Purpose\t: Make an interface active, so all following CLI commands goes on \n"
		" \t\t  this interface, used to make primary interfaces(wl0,wl1) as \n"
		" \t\t  current interface \n");
	printf("------------------------------------------------------------------------------\n");
	printf(" Command 02\t: bss <BSSID> \n"
		" Example\t: bss 00:11:22:33:44:55:66 \n"
		" Purpose\t: Make a BSSID(MAC) active, so all following CLI commands goes on \n"
		" \t\t  this interface, used to make virtual interfaces(wl0.1,wl1.1) as \n"
		" \t\t  current interface \n");
	printf("------------------------------------------------------------------------------\n");
	printf(" Command 03\t: interworking <0/1> \n"
		" Example\t: interworking 1 \n"
		" Purpose\t: Enable/Disable interworking \n");
	printf("------------------------------------------------------------------------------\n");
	printf(" Command 04\t: accs_net_type <0/1/2/3/4/5/14/15> \n"
		" Example\t: accs_net_type 3 \n"
		" Purpose\t: Change Access Network Type \n");
	printf("------------------------------------------------------------------------------\n");
	printf(" Command 05\t: internet <0/1> \n"
		" Example\t: internet 1 \n"
		" Purpose\t: Enable/Disable internet available field in interworking IE \n");
	printf("------------------------------------------------------------------------------\n");
	printf(" Command 06\t: venue_grp <0/1/2/3/4/5/6/7/8/9/10/11> \n"
		" Example\t: venue_grp 2 \n"
		" Purpose\t: Change Venue Group field in interworking IE \n");
	printf("------------------------------------------------------------------------------\n");
	printf(" Command 07\t: venue_type  <0/1/2/3/4/5/6/7/8/9/10/11> \n"
		" Example\t: venue_type 8 \n"
		" Purpose\t: Change Venue Type field in interworking IE \n");
	printf("------------------------------------------------------------------------------\n");
	printf(" Command 08\t: hessid <Vendor Specific HESSID> \n"
		" Example\t: hessid 00:11:22:33:44:55:66 \n"
		" Purpose\t: Change HESSID field in interworking IE \n");
	printf("------------------------------------------------------------------------------\n");
	printf(" Command 09\t: roaming_cons <oui1> <oui2> ... \n"
		" Example\t: roaming_cons 506F9A 1122334455 \n"
		" Purpose\t: List of Roaming Consortium OI in hex separated by \" \", \n"
		" \t\t  in case of multiple values, String \"Disabled\" is used to Disable \n"
		" \t\t  Roaming Consortium IE \n");
	printf("------------------------------------------------------------------------------\n");
	printf(" Command 10\t: anqp <0/1> \n"
		" Example\t: anqp 1 \n"
		" Purpose\t: Enable/Disable ANQP in Advertisement Protocol IE \n");
	printf("------------------------------------------------------------------------------\n");
	printf(" Command 11\t: mih <0/1> \n"
		" Example\t: mih 0 \n"
		" Purpose\t: Enable/Disable MIH in Advertisement Protocol IE \n");
	printf("------------------------------------------------------------------------------\n");
	printf(" Command 12\t: dgaf_disable <0/1> \n"
		" Example\t: dgaf_disable 0 \n"
		" Purpose\t: Enable/Disable Downstream Group-Addressed Forwarding bit \n"
		" \t\t  in Passpoint Vendor IE \n");
	printf("------------------------------------------------------------------------------\n");
	printf(" Command 13\t: l2_traffic_inspect <0/1> \n"
		" Example\t: l2_traffic_inspect 1 \n"
		" Purpose\t: Enable/Disable L2 Traffic Inspection and Filtering (Applies to  APs \n"
		" \t\t  which support built-in inspection and filtering function)\n");
	printf("------------------------------------------------------------------------------\n");
	printf(" Command 14\t: icmpv4_echo <0/1> \n"
		" Example\t:icmpv4_echo 1 \n"
		" Purpose\t: Filter function for ICMPv4 Echo Requests, Enabled(1) allow \n"
		" \t\t  ICMP Echo request, Disabled(0) Deny ICMP echo request \n");
	printf("------------------------------------------------------------------------------\n");
	printf(" Command 15\t: plmn_mcc <mcc1> <mcc2> <mcc3> ... \n"
		" Example\t: plmn_mcc 111 222 333 \n"
		" Purpose\t: 3GPP Cellular Network infromation : Country Code (list of MCCs \n"
		" \t\t  separated by \" \", in case of multiple values) \n");
	printf("------------------------------------------------------------------------------\n");
	printf(" Command 16\t: plmn_mnc <mnc1> <mnc2> <mnc3> ... \n"
		" Example\t: plmn_mnc 010 011 012 \n"
		" Purpose\t: 3GPP Cellular Network infromation : Network Code (list of MCCs \n"
		" \t\t  separated by \" \", in case of multiple values) \n");
	printf("------------------------------------------------------------------------------\n");
	printf(" Command 17\t: proxy_arp <0/1> \n"
		" Example\t: proxy_arp 1 \n"
		" Purpose\t: Enable/Disable ProxyARP \n");
	printf("------------------------------------------------------------------------------\n");
	printf(" Command 18\t: bcst_uncst <0/1> \n"
		" Example\t: bcst_uncst 0 \n"
		" Purpose\t: Broadcast to Unicast conversion functionality. Disabling the \n"
		" \t\t  conversion is a special mode only required for test bed APs. \n"
		" \t\t  Enabled(1)/Disabled(0) \n");
	printf("------------------------------------------------------------------------------\n");
	printf(" Command 19\t: gas_cb_delay <intval> \n"
		" Example\t: gas_cb_delay 100 \n"
		" Purpose\t: GAS Comeback Delay in TUs (Applies only to AP that supports \n"
		" \t\t  4-frame GAS exchange). Testbed devices only \n");
	printf("------------------------------------------------------------------------------\n");
	printf(" Command 20\t: 4_frame_gas <0/1> \n"
		" Example\t: 4_frame_gas 1 \n"
		" Purpose\t: Enabled(1)/Disabled(0) : Four Frame GAS exchange \n");
	printf("------------------------------------------------------------------------------\n");
	printf(" Command 21\t: domain_list <domain1> <domain2> ... \n"
		" Example\t: domain_list wi-fi1.org wi-fi2.org \n"
		" Purpose\t: Domain Name List separated by \" \", in case of multiple values \n");
	printf("------------------------------------------------------------------------------\n");
	printf(" Command 22\t: hs2 <0/1> \n"
		" Example\t: hs2 1 \n"
		" Purpose\t: HS 2.0 Indication element : Enabled(1)/Disabled(0) \n");
	printf("------------------------------------------------------------------------------\n");
	printf(" Command 23\t: p2p_ie <0/1> \n"
		" Example\t: p2p_ie 1 \n"
		" Purpose\t: P2P Indication element : Enabled(1)/Disabled(0) \n");
	printf("------------------------------------------------------------------------------\n");
	printf(" Command 24\t: p2p_cross_connect <0/1> \n"
		" Example\t: p2p_cross_connect 0 \n"
		" Purpose\t: Enable/Disable : P2P Cross Connect field in P2P IE \n");
	printf("------------------------------------------------------------------------------\n");
	printf(" Command 25\t: osu_provider_list <1/2/3/4/5/6/7/8/9/10/11> \n"
		" Example\t: osu_provider_list 1 \n"
		" Purpose\t: Change OSU Provider List #ID ( as per Test Plan). \n"
		" \t\t  Testbed devices only \n");
	printf("------------------------------------------------------------------------------\n");
	printf(" Command 26\t: osu_icon_tag <1/2> \n"
		" Example\t: osu_icon_tag 1 \n"
		" Purpose\t: Change icon content to common icon filename for OSU Providers List. \n"
		" \t\t  Testbed devices only \n");
	printf("------------------------------------------------------------------------------\n");
	printf(" Command 27\t: osu_server_uri <uri1> <uri2> <uri3> ... \n"
		" Example\t: osu_server_uri www.ruckus.com www.aruba.com \n"
		" Purpose\t: List of OSU Server URIs separated by \" \",  in case of multiple \n"
		" \t\t  OSU Providers are present. Testbed devices only \n");
	printf("------------------------------------------------------------------------------\n");
	printf(" Command 28\t: osu_method <method1> <method2> ... \n"
		" Example\t: osu_method SOAP OMADM SOAP \n"
		" Purpose\t: List of OSU Methods separated by \" \",  in case of multiple \n"
		" \t\t  OSU Providers are present. Testbed devices only \n");
	printf("------------------------------------------------------------------------------\n");
	printf(" Command 29\t: osu_ssid <ssid> \n"
		" Example\t: osu_ssid OSU_Encrypted \n"
		" Purpose\t: SSID of OSU ESS for OSU Providers List \n");
	printf("------------------------------------------------------------------------------\n");
	printf(" Command 30\t: anonymous_nai <nai_val> \n"
		" Example\t: anonymous_nai anonymous.com \n"
		" Purpose\t: Change Anonymous NAI value \n");
	printf("------------------------------------------------------------------------------\n");
	printf(" Command 31\t: ip_add_type_avail <ID> \n"
		" Example\t: ip_add_type_avail 1 \n"
		" Purpose\t: ID number. Refer HS2.0 test plan Appdex B.1 for details. \n"
		" \t\t  Testbed devices only \n");
	printf("------------------------------------------------------------------------------\n");
	printf(" Command 32\t: hs_reset \n"
		" Example\t: hs_reset \n"
		" Purpose\t: Reset AP. Testbed devices only \n");
	printf("------------------------------------------------------------------------------\n");
	printf(" Command 33\t: nai_realm_list <ID> \n"
		" Example\t: nai_realm_list 1 \n"
		" Purpose\t: ID number. Refer HS2.0 test plan Appdex B.1 for details. \n"
		" \t\t  Testbed devices only \n");
	printf("------------------------------------------------------------------------------\n");
	printf(" Command 34\t: oper_name <ID> \n"
		" Example\t: oper_name 1 \n"
		" Purpose\t: ID number. Refer HS2.0 test plan Appdex B.1 for details. \n"
		" \t\t  Testbed devices only \n");
	printf("------------------------------------------------------------------------------\n");
	printf(" Command 35\t: venue_name <ID> \n"
		" Example\t: venue_name 1 \n"
		" Purpose\t: ID number. Refer HS2.0 test plan Appdex B.1 for details. \n"
		" \t\t  Testbed devices only \n");
	printf("------------------------------------------------------------------------------\n");
	printf(" Command 36\t: wan_metrics <ID> \n"
		" Example\t: wan_metrics 1 \n"
		" Purpose\t: ID number. Refer HS2.0 test plan Appdex B.1 for details. \n"
		" \t\t  Testbed devices only \n");
	printf("------------------------------------------------------------------------------\n");
	printf(" Command 37\t: conn_cap <ID> \n"
		" Example\t: conn_cap 1 \n"
		" Purpose\t: ID number. Refer HS2.0 test plan Appdex B.1 for details. \n"
		" \t\t  Testbed devices only \n");
	printf("------------------------------------------------------------------------------\n");
	printf(" Command 38\t: oper_class <ID> \n"
		" Example\t: oper_class 3 \n"
		" Purpose\t: ID number. Refer HS2.0 test plan Appdex B.1 for details. \n"
		" \t\t  Testbed devices only \n");
	printf("------------------------------------------------------------------------------\n");
	printf(" Command 39\t: net_auth_type <ID> \n"
		" Example\t: net_auth_type 1 \n"
		" Purpose\t: ID number. Refer HS2.0 test plan Appdex B.1 for details. \n"
		" \t\t  Testbed devices only \n");
	printf("------------------------------------------------------------------------------\n");
	printf(" Command 40\t: sim <0/1> \n"
		" Example\t: sim 0 \n"
		" Purpose\t: Use sim credentials in OSU Provider List \n");
	printf("------------------------------------------------------------------------------\n");
	printf(" Command 41\t: sr <STA_MAC> <URL> \n"
		" Example\t: sr 00:11:22:33:44:55 www.ruckus.com \n"
		" Purpose\t: Send Subscription Remediation WNM Action Frame to specific \n"
		" \t\t  associated STA, with URL of the Subscription Remediation Server \n");
	printf("------------------------------------------------------------------------------\n");
	printf(" Command 42\t: di <STA_MAC> <Reason Code> <Reauth Delay> <URL> \n"
		" Example\t: di 00:11:22:33:44:55 1 100 www.ruckus.com \n"
		" Purpose\t: Send De-authentication Immenent Notice WNM Action Frame to specific \n"
		" \t\t  associated STA, with Reason Code as BSS or ESS, delay in seconds that a \n"
		" \t\t  mobile device waits before attempting re-association to the same \n"
		" \t\t  BSS/ESS, and Reason URL which provides a webpage explaining why \n"
		" \t\t  the mobile device was not authorized \n");
	printf("------------------------------------------------------------------------------\n");
	printf(" Command 43\t: btredi <URL> \n"
		" Example\t: btredi www.ruckus.com \n"
		" Purpose\t: Send BSS Transition Request Frame to STA, \n"
		" \t\t  with session information URL \n");
	printf("------------------------------------------------------------------------------\n");
	printf(" Command 44\t: qos_map_set <ID> \n"
		" Example\t: qos_map_set 2 \n"
		" Purpose\t: Set QoS_Map_Set IE as per ID number. Refer HS2.0 test plan \n"
		" \t\t  Appdex B.1 for details. Testbed devices only \n");
	printf("------------------------------------------------------------------------------\n");
	printf(" Command 45\t: bss_load <ID> \n"
		" Example\t: bss_load 2 \n"
		" Purpose\t: Set Static BSS_Load value as per ID number. Refer HS2.0 test plan \n"
		" \t\t  Appdex B.1 for details. Testbed devices only \n");
	printf("------------------------------------------------------------------------------\n");
	printf(" Command 46\t: osen <0/1> \n"
		" Example\t: osen 0 \n"
		" Purpose\t: Enable/Disable OSEN IE \n");
	printf("------------------------------------------------------------------------------\n");
	printf(" Command 47\t: help \n"
		" Example\t: help \n"
		" Purpose\t: Lists all CLI Commands used with Hspotap application in CLI mode \n");
	printf("------------------------------------------------------------------------------\n");

	printf("==============================================================================\n");

	return err;
}


static int processCommand(hspotApT *hspotap, char **argv, char *txData)
{
	int err = 0;
	bool set_tx_data = TRUE;

	if (argv[0] == NULL) {
		printf("NULL command\n");
		err = -1;
	}
	else if (strcmp(argv[0], "interface") == 0) {
		hspotApT *new_hspotap;
		new_hspotap = getHspotApByIfname(argv[1]);
		if (new_hspotap == NULL) {
			printf("wrong interface name %s\n", argv[1]);
			err = -1;
		} else {
			current_hspotap = new_hspotap;
			err = 0;
			printf("change interface to %s\n", wl_ifname(current_hspotap->ifr));
		}
	}
	else if (strcmp(argv[0], "bss") == 0) {
		hspotApT *new_hspotap;
		new_hspotap = getHspotApByBSSID(argv[1]);
		if (new_hspotap == NULL) {
			printf("wrong interface name %s\n", argv[1]);
			err = -1;
		} else {
			current_hspotap = new_hspotap;
			err = 0;
			printf("change interface to %s\n", wl_ifname(current_hspotap->ifr));
		}
	}
	else if (strcmp(argv[0], "interworking") == 0) {
		argv++;
		err = hspot_cmd_interworking_handler(hspotap, argv, txData, &set_tx_data);
	}
	else if (strcmp(argv[0], "accs_net_type") == 0) {
		argv++;
		err = hspot_cmd_accs_net_type_handler(hspotap, argv, txData, &set_tx_data);
	}
	else if (strcmp(argv[0], "internet") == 0) {
		argv++;
		err = hspot_cmd_internet_handler(hspotap, argv, txData, &set_tx_data);
	}
	else if (strcmp(argv[0], "venue_grp") == 0) {
		argv++;
		err = hspot_cmd_venue_grp_handler(hspotap, argv, txData, &set_tx_data);
	}
	else if (strcmp(argv[0], "venue_type") == 0) {
		argv++;
		err = hspot_cmd_venue_type_handler(hspotap, argv, txData, &set_tx_data);
	}
	else if (strcmp(argv[0], "hessid") == 0) {
		argv++;
		err = hspot_cmd_hessid_handler(hspotap, argv, txData, &set_tx_data);
	}
	else if (strcmp(argv[0], "roaming_cons") == 0) {
		argv++;
		err = hspot_cmd_roaming_cons_handler(hspotap, argv, txData, &set_tx_data);
	}
	else if (strcmp(argv[0], "anqp") == 0) {
		argv++;
		err = hspot_cmd_anqp_handler(hspotap, argv, txData, &set_tx_data);
	}
	else if (strcmp(argv[0], "mih") == 0) {
		argv++;
		err = hspot_cmd_mih_handler(hspotap, argv, txData, &set_tx_data);
	}
	else if (strcmp(argv[0], "dgaf_disable") == 0) {
		argv++;
		err = hspot_cmd_dgaf_disable_handler(hspotap, argv, txData, &set_tx_data);
	}
	else if (strcmp(argv[0], "l2_traffic_inspect") == 0) {
		argv++;
		err = hspot_cmd_l2_traffic_inspect_handler(hspotap, argv, txData, &set_tx_data);
	}
	else if (strcmp(argv[0], "icmpv4_echo") == 0) {
		argv++;
		err = hspot_cmd_icmpv4_echo_handler(hspotap, argv, txData, &set_tx_data);
	}
	else if (strcmp(argv[0], "plmn_mcc") == 0) {
		argv++;
		err = hspot_cmd_plmn_mcc_handler(hspotap, argv, txData, &set_tx_data);
	}
	else if (strcmp(argv[0], "plmn_mnc") == 0) {
		argv++;
		err = hspot_cmd_plmn_mnc_handler(hspotap, argv, txData, &set_tx_data);
	}
	else if (strcmp(argv[0], "proxy_arp") == 0) {
		argv++;
		err = hspot_cmd_proxy_arp_handler(hspotap, argv, txData, &set_tx_data);
	}
	else if (strcmp(argv[0], "bcst_uncst") == 0) {
		argv++;
		err = hspot_cmd_bcst_uncst_handler(hspotap, argv, txData, &set_tx_data);
	}
	else if (strcmp(argv[0], "gas_cb_delay") == 0) {
		argv++;
		err = hspot_cmd_gas_cb_delay_handler(hspotap, argv, txData, &set_tx_data);
	}
	else if (strcmp(argv[0], "4_frame_gas") == 0) {
		argv++;
		err = hspot_cmd_4_frame_gas_handler(hspotap, argv, txData, &set_tx_data);
	}
	else if (strcmp(argv[0], "domain_list") == 0) {
		argv++;
		err = hspot_cmd_domain_list_handler(hspotap, argv, txData, &set_tx_data);
	}
	else if (strcmp(argv[0], "sess_info_url") == 0) {
		argv++;
		err = hspot_cmd_sess_info_url_handler(hspotap, argv, txData, &set_tx_data);
	}
	else if (strcmp(argv[0], "dest") == 0) {
		argv++;
		err = hspot_cmd_dest_handler(hspotap, argv, txData, &set_tx_data);
	}
	else if (strcmp(argv[0], "hs2") == 0) {
		argv++;
		err = hspot_cmd_hs2_handler(hspotap, argv, txData, &set_tx_data);
	}
	else if (strcmp(argv[0], "p2p_ie") == 0) {
		argv++;
		err = hspot_cmd_p2p_ie_handler(hspotap, argv, txData, &set_tx_data);
	}
	else if (strcmp(argv[0], "p2p_cross_connect") == 0) {
		argv++;
		err = hspot_cmd_p2p_cross_connect_handler(hspotap, argv, txData, &set_tx_data);
	}
	else if (strcmp(argv[0], "osu_provider_list") == 0) {
		argv++;
		err = hspot_cmd_osu_provider_list_handler(hspotap, argv, txData, &set_tx_data);
	}
	else if (strcmp(argv[0], "osu_icon_tag") == 0) {
		argv++;
		err = hspot_cmd_osu_icon_tag_handler(hspotap, argv, txData, &set_tx_data);
	}
	else if (strcmp(argv[0], "osu_server_uri") == 0) {
		argv++;
		err = hspot_cmd_osu_server_uri_handler(hspotap, argv, txData, &set_tx_data);
	}
	else if (strcmp(argv[0], "osu_method") == 0) {
		argv++;
		err = hspot_cmd_osu_method_handler(hspotap, argv, txData, &set_tx_data);
	}
	else if (strcmp(argv[0], "osu_ssid") == 0) {
		argv++;
		err = hspot_cmd_osu_ssid_handler(hspotap, argv, txData, &set_tx_data);
	}
	else if (strcmp(argv[0], "anonymous_nai") == 0) {
		argv++;
		err = hspot_cmd_anonymous_nai_handler(hspotap, argv, txData, &set_tx_data);
	}
	else if (strcmp(argv[0], "ip_add_type_avail") == 0) {
		argv++;
		err = hspot_cmd_ip_add_type_avail_handler(hspotap, argv, txData, &set_tx_data);
	}
	else if (strcmp(argv[0], "hs_reset") == 0) {
		argv++;
		err = hspot_cmd_hs_reset_handler(hspotap, argv, txData, &set_tx_data);
	}
	else if (strcmp(argv[0], "nai_realm_list") == 0) {
		argv++;
		err = hspot_cmd_nai_realm_list_handler(hspotap, argv, txData, &set_tx_data);
	}
	else if (strcmp(argv[0], "oper_name") == 0) {
		argv++;
		err = hspot_cmd_oper_name_handler(hspotap, argv, txData, &set_tx_data);
	}
	else if (strcmp(argv[0], "venue_name") == 0) {
		argv++;
		err = hspot_cmd_venue_name_handler(hspotap, argv, txData, &set_tx_data);
	}
	else if (strcmp(argv[0], "wan_metrics") == 0) {
		argv++;
		err = hspot_cmd_wan_metrics_handler(hspotap, argv, txData, &set_tx_data);
	}
	else if (strcmp(argv[0], "conn_cap") == 0) {
		argv++;
		err = hspot_cmd_conn_cap_handler(hspotap, argv, txData, &set_tx_data);
	}
	else if (strcmp(argv[0], "oper_class") == 0) {
		argv++;
		err = hspot_cmd_oper_class_handler(hspotap, argv, txData, &set_tx_data);
	}
	else if (strcmp(argv[0], "net_auth_type") == 0) {
		argv++;
		err = hspot_cmd_net_auth_type_handler(hspotap, argv, txData, &set_tx_data);
	}
	else if (strcmp(argv[0], "pause") == 0) {
		argv++;
		err = hspot_cmd_pause_handler(hspotap, argv, txData, &set_tx_data);
	}
	else if (strcmp(argv[0], "dis_anqp_response") == 0) {
		argv++;
		err = hspot_cmd_dis_anqp_response_handler(hspotap, argv, txData, &set_tx_data);
	}
	else if (strcmp(argv[0], "sim") == 0) {
		argv++;
		err = hspot_cmd_sim_handler(hspotap, argv, txData, &set_tx_data);
	}
	else if (strcmp(argv[0], "response_size") == 0) {
		argv++;
		err = hspot_cmd_response_size_handler(hspotap, argv, txData, &set_tx_data);
	}
	else if (strcmp(argv[0], "pause_cb_delay") == 0) {
		argv++;
		err = hspot_cmd_pause_cb_delay_handler(hspotap, argv, txData, &set_tx_data);
	}
	else if (strcmp(argv[0], "sr") == 0) {
		argv++;
		err = hspot_cmd_sr_handler(hspotap, argv, txData, &set_tx_data);
	}
	else if (strcmp(argv[0], "di") == 0) {
		argv++;
		err = hspot_cmd_di_handler(hspotap, argv, txData, &set_tx_data);
	}
	else if (strcmp(argv[0], "btredi") == 0) {
		argv++;
		err = hspot_cmd_btredi_handler(hspotap, argv, txData, &set_tx_data);
	}
	else if (strcmp(argv[0], "qos_map_set") == 0) {
		argv++;
		err = hspot_cmd_qos_map_set_handler(hspotap, argv, txData, &set_tx_data);
	}
	else if (strcmp(argv[0], "bss_load") == 0) {
		argv++;
		err = hspot_cmd_bss_load_handler(hspotap, argv, txData, &set_tx_data);
	}
	else if (strcmp(argv[0], "osen") == 0) {
		argv++;
		err = hspot_cmd_osen_handler(hspotap, argv, txData, &set_tx_data);
	}
	else if (strcmp(argv[0], "help") == 0) {
		argv++;
		err = hspot_cmd_help_handler(hspotap, argv, txData, &set_tx_data);
	}
	else
	{
		printf("unknown command %s\n", argv[0]);
		err = -1;
	}

	if (set_tx_data) {
		if (err) {
			strcpy(txData, "ERROR");
			/* sprintf(txData, "ERROR %d", err); */
		} else {
			strcpy(txData, "OK");
		}
	}

	return err;
}

static void tcpReceiveHandler(void *handle, char *rxData, char *txData)
{
	(void)handle;

	/* receive and send back with OK
	   test with test.tcl test ap_set_hs2 to see what strings are being passed
	 */

	int argc = 0;
	char *argv[64], *token;
	int status;

	printf("received %s\n", rxData);
	/* sprintf(txData, "OK %s", rxData); */

	/* convert input to argc/argv format */
	while ((argc < (int)(sizeof(argv) / sizeof(char *) - 1)) &&
		((token = strtok(argc ? NULL : rxData, " \t\n")) != NULL)) {
		argv[argc++] = token;
	}
	argv[argc] = NULL;

	status = processCommand(current_hspotap, argv, txData);
}
/*
static void setTestParameters(char *testName, hspotApT *hspotap)
{
	printf("test case --%s--\n", testName);

	if (!strcmp(testName, "test5.2-AP1:NAI")) {
		printf("3GPP enabled, NAI realm disabled\n");
		hspotap->isRealmDisabled = TRUE;
		hspotap->is3GppDisabled = FALSE;
		hspotap->useDefaultANQPValue = TRUE;
		hspotap->nai_id = 1;
		hspotap->ipa_id = 1;
	}
	else if (!strcmp(testName, "test5.2-AP2:NAI")) {
		printf("NAI realm enabled, 3GPP disabled\n");
		hspotap->isRealmDisabled = FALSE;
		hspotap->is3GppDisabled = TRUE;
		hspotap->useDefaultANQPValue = TRUE;
		hspotap->nai_id = 1;
		hspotap->ipa_id = 1;
	}
	else if (!strcmp(testName, "test5.2-AP3:NAI")) {
		printf("NAI realm disabled, 3GPP disabled\n");
		hspotap->isRealmDisabled = TRUE;
		hspotap->is3GppDisabled = TRUE;
		hspotap->emptyANQPInfo = TRUE;
	}
}
*/

int IsPrimaryRadioOn(int primaryInx)
{
	char prefix[16];
	char *ptr; int err = 0;
	char varname[NVRAM_MAX_PARAM_LEN];

	snprintf(prefix, sizeof(prefix), "wl%d_", primaryInx);

	ptr = nvram_get(strcat_r(prefix, "radio", varname));
	if (ptr) {
		return atoi(ptr);
	} else {
		/* printf("%s is not defined in NVRAM\n", varname); */
		err = -1;
	}

	return err;
}

static void hspotapFree(void)
{
	int i, primaryInx = 0;

	for (i = 0; i < hspotap_num; i++) {

		sscanf(hspotaps[i]->prefix, "wl%d", &primaryInx);

		if (hspotaps[i]->prefix &&
			hspotaps[i]->ifr &&
			IsPrimaryRadioOn(primaryInx))
		{
			/* delete IEs */
			deleteIes(hspotaps[i]);

			wl_wnm_url(hspotaps[i]->ifr, 0, 0);

			if (hspotaps[i]->url_len)
				free(hspotaps[i]->url);

			free(hspotaps[i]);
		}
	}

	hspotap_num = 0;

	wlFree();
}


int GetImageSize(const char *fn, int *x, int *y)
{
	unsigned char buf[24];
	int ret = 0;
	FILE *f = fopen(fn, "rb");

	if (f == 0) {
		ret = -1;
		return ret;
	}

	if (fseek(f, 0, SEEK_END) == -1) {
		ret = -1;
		goto GETIMAGESIZE_DONE;
	}

	long len = ftell(f);

	if (fseek(f, 0, SEEK_SET) == -1) {
		ret = -1;
		goto GETIMAGESIZE_DONE;
	}

	if (len < 24) {
		ret = -1;
		goto GETIMAGESIZE_DONE;
	}

	/*
	Strategy:
	reading GIF dimensions requires the first 10 bytes of the file
	reading PNG dimensions requires the first 24 bytes of the file
	reading JPEG dimensions requires scanning through jpeg chunks
	In all formats, the file is at least 24 bytes big, so we'll read that always
	*/

	if (fread(buf, 1, 24, f) < 24) {
		ret = -1;
		goto GETIMAGESIZE_DONE;
	}

	/* For JPEGs, we need to read the first 12 bytes of each chunk.
	 We'll read those 12 bytes at buf+2...buf+14, i.e. overwriting the existing buf.
	*/

	if ((buf[0] == 0xFF) && (buf[1] == 0xD8) &&
		(buf[2] == 0xFF) && (buf[3] == 0xE0) &&
		(buf[6] == 'J') && (buf[7] == 'F') &&
		(buf[8] == 'I') && (buf[9] == 'F'))
	{
		long pos = 2;
		while (buf[2] == 0xFF)
		{
			if ((buf[3] == 0xC0) || (buf[3] == 0xC1) ||
				(buf[3] == 0xC2) || (buf[3] == 0xC3) ||
				(buf[3] == 0xC9) || (buf[3] == 0xCA) ||
				(buf[3] == 0xCB))
					break;
			pos += 2 + (buf[4]<<8) + buf[5];

			if (pos+12 > len)
				break;

			if (fseek(f, pos, SEEK_SET) == -1) {
				ret = -1;
				goto GETIMAGESIZE_DONE;
			}

			if (fread(buf+2, 1, 12, f) < 12) {
				ret = -1;
				goto GETIMAGESIZE_DONE;
			}
		}
	}
	/*
	JPEG:first two bytes of buf are
	first two bytes of the jpeg file;
	rest of buf is the DCT frame
	*/

	if ((buf[0] == 0xFF) &&
		(buf[1] == 0xD8) && (buf[2] == 0xFF))
	{
		*y = (buf[7] << 8) + buf[8];
		*x = (buf[9] << 8) + buf[10];
		ret = 0;
		goto GETIMAGESIZE_DONE;
	}

	/* GIF: first three bytes say "GIF", next three give version number. Then dimensions */
	if ((buf[0] == 'G') &&
		(buf[1] == 'I') &&
		(buf[2] == 'F'))
	{
		*x = buf[6] + (buf[7] << 8);
		*y = buf[8] + (buf[9] << 8);
		ret = 0;
		goto GETIMAGESIZE_DONE;
	}

	/* PNG: the first frame is by definition an IHDR frame, which gives dimensions */

	if ((buf[0] == 0x89) && (buf[1] == 'P') &&
		(buf[2] == 'N') && (buf[3] == 'G') &&
		(buf[4] == 0x0D) && (buf[5] == 0x0A) &&
		(buf[6] == 0x1A) && (buf[7] == 0x0A) &&
		(buf[12] == 'I') &&
		(buf[13] == 'H') &&
		(buf[14] == 'D') &&
		(buf[15] == 'R'))
	{
		*x = (buf[16]<<24) + (buf[17]<<16) + (buf[18]<<8) + (buf[19]<<0);
		*y = (buf[20]<<24) + (buf[21]<<16) + (buf[22]<<8) + (buf[23]<<0);
		ret = 0;
		goto GETIMAGESIZE_DONE;
	}

GETIMAGESIZE_DONE :
	fclose(f);
	return ret;
}

int GetMimeType(const char *fn, char *MIME_type, int size)
{
	/* From File Extension decide the MIME Type */
	char *pch = strrchr(fn, '.');
	if (pch != NULL)
	{
		if ((!strcmp(pch, ".bmp")) ||
			(!strcmp(pch, ".dib")) ||
			(!strcmp(pch, ".rle")))
				strncpy_n(MIME_type, "image/bmp", size);
		else if ((!strcmp(pch, ".jpg")) ||
			(!strcmp(pch, ".jpeg")) ||
			(!strcmp(pch, ".jpe")) ||
			(!strcmp(pch, ".jfif")))
			strncpy_n(MIME_type, "image/jpeg", size);
		else if ((!strcmp(pch, ".gif")))
			strncpy_n(MIME_type, "image/gif", size);
		else if ((!strcmp(pch, ".emf")))
			strncpy_n(MIME_type, "image/emf", size);
		else if ((!strcmp(pch, ".wmf")))
			strncpy_n(MIME_type, "image/wmf", size);
		else if ((!strcmp(pch, ".tif")) || (!strcmp(pch, ".tiff")))
			strncpy_n(MIME_type, "image/tiff", size);
		else if ((!strcmp(pch, ".png")))
			strncpy_n(MIME_type, "image/png", size);
		else if ((!strcmp(pch, ".ico")))
			strncpy_n(MIME_type, "image/x-icon", size);
		else
			strncpy_n(MIME_type, "image/unknown", size);
	}
	return 0;
}

int main(int argc, char **argv)
{
	int i, total_ifr = 0;
	void *ifr;

	TRACE_LEVEL_SET(TRACE_ERROR);

	printf("\n");
	printf("Hotspot2.0 - version %s\n", EPI_VERSION_STR);
	printf("Copyright Broadcom Corporation\n");

	if (wl() == NULL) {
		printf("can't find wl interface\n");
		exit(1);
	}

	/* look for enabled/disabled radio interfaces */
	int prim;
	int radio[MAX_NVPARSE];
	for (prim = 0; prim < MAX_NVPARSE; prim++) {
		radio[prim] = IsPrimaryRadioOn(prim);
	}

	while ((ifr = wlif(total_ifr)) != NULL) {
		char *osifname = NULL;
		char varname[NVRAM_MAX_PARAM_LEN] = {0};
		char *tokenParse = NULL;
		char item_value[NVRAM_MAX_VALUE_LEN] = {0};
		char *venue, *lang;
		char *ptr = NULL;
		char ptrv[NVRAM_MAX_VAL_LEN] = {0};
		char ptrUTF8[NVRAM_MAX_VAL_LEN] = {0};
		int pri = 0, sec = 0;
		bool find = FALSE, conti_flag = FALSE;
		char prefix[16] = {0};
		hspotApT *hspotap = NULL;

		/* Get me the next interface, anyhow */
		total_ifr++;
		osifname = wl_ifname(ifr);
		find = FALSE;
		conti_flag = FALSE;

		/* look for interface name on the primary interfaces first */
		for (pri = 0; pri < MAX_NVPARSE; pri++) {
			snprintf(varname, sizeof(varname),
				"wl%d_ifname", pri);

			if (nvram_match(varname, osifname)) {
				find = TRUE;
				snprintf(prefix, sizeof(prefix), "wl%d_", pri);

				if (!radio[pri])
					conti_flag = TRUE;

				break;
			}
		}

		if (conti_flag)
			continue;

		if (!find) {
			/* look for interface name on the multi-instance interfaces */
			for (pri = 0; pri < MAX_NVPARSE; pri++) {
				for (sec = 0; sec < MAX_NVPARSE; sec++) {
					snprintf(varname, sizeof(varname),
						"wl%d.%d_ifname", pri, sec);
					if (nvram_match(varname, osifname)) {
						find = TRUE;
						snprintf(prefix, sizeof(prefix),
							"wl%d.%d_", pri, sec);

					if (!radio[pri])
						conti_flag = TRUE;

					break;
					}
				}

			}
		}

		if (conti_flag || !find)
			continue;

		hspotap = malloc(sizeof(hspotApT));
		if (!hspotap) {
			printf("malloc failure\n");
			hspotapFree();
			exit(1);
		}
		memset(hspotap, 0, sizeof(hspotApT));
		hspotaps[hspotap_num] = hspotap;
		hspotap_num ++;

		/* Reset_IW(hspotap, TRUE, 0x0008); */

		/* printf("HS_TRACE : 1 main ; hspotap_num = %d ####	\n", hspotap_num); */
		/* printf("HS_TRACE : 2 main ; Prefix = %s ####	\n", prefix); */

		hspotap->ifr = ifr;

		/* token start from 1 */
		hspotap->dialogToken = 1;
		hspotap->req_token = 1;

		hspotap->qos_id = 1;
		hspotap->bssload_id = 1;

		hspotap->hs_ie_enabled = FALSE;
		hspotap->iw_enabled = FALSE;

		hspotap->isGasPauseForServerResponse = TRUE;

		if (find) {

		ptr = nvram_get(strcat_r(prefix, "u11en", varname));
		if (ptr) {
			hspotap->iw_enabled = atoi(ptr);
			/* printf("%s: %d\n", varname, hspotap->iw_enabled); */
		} else {
			/* printf("%s is not defined in NVRAM\n", varname); */
		}

		ptr = nvram_get(strcat_r(prefix, "hs2en", varname));
		if (ptr) {
			hspotap->hs_ie_enabled = atoi(ptr);
			/* printf("%s: %d\n", varname, hspotap->hs_ie_enabled); */
		} else {
			/* printf("%s is not defined in NVRAM\n", varname); */
		}

		if (!hspotap->iw_enabled && hspotap->hs_ie_enabled)
		{
			hspotap->hs_ie_enabled = 0;
			if (nvram_set(strcat_r(prefix, "hs2en", varname), "0")) {
				printf("nvram_set %s=%s failure\n", varname, "0");
			}
			nvram_commit();
			/* printf("Error : U11 must be enabled before HS, Thus disable HS.\n"); */
		}
		/* ---- Passpoint Flags  ----------------------------------- */
		ptr = nvram_get(strcat_r(prefix, "gascbdel", varname));
		if (ptr) {
			hspotap->gas_cb_delay = atoi(ptr);
			if (hspotap->gas_cb_delay) {
				hspotap->isGasPauseForServerResponse = FALSE;
			}
			/* printf("%s: %d\n", varname, hspotap->gas_cb_delay); */
		} else {
			/* printf("%s is not defined in NVRAM\n", varname); */
		}

		ptr = nvram_get(strcat_r(prefix, "4framegas", varname));
		if (ptr) {
			hspotap->isGasPauseForServerResponse = (atoi(ptr) == 0);
			/* printf("%s: %d\n", varname, */
			/*!(hspotap->isGasPauseForServerResponse)); */
		} else {
			/* printf("%s is not defined in NVRAM\n", varname); */
		}

		/* //////////////////// U 11 /////////////////// */

		/* Interworking Info ----------------------------------------- */
		ptr = nvram_get(strcat_r(prefix, "iwint", varname));
		if (ptr) {
			hspotap->iw_isInternet = atoi(ptr);
			/* printf("%s: %d\n", varname, hspotap->iw_isInternet); */
		} else {
			/* printf("%s is not defined in NVRAM\n", varname); */
		}

		ptr = nvram_get(strcat_r(prefix, "iwnettype", varname));
		if (ptr) {
			hspotap->iw_ANT = atoi(ptr);
			/* printf("%s: %d\n", varname, hspotap->iw_ANT); */
		} else {
			/* printf("%s is not defined in NVRAM\n", varname); */
		}

		ptr = nvram_get(strcat_r(prefix, "hessid", varname));
		if (ptr) {
			if (!strToEther(ptr, &hspotap->iw_HESSID)) {
				/* printf("wrong format hessid in NVRAM\n"); */
			}
			else if (ETHER_ISNULLADDR(hspotap->iw_HESSID.octet)) {
				hspotap->iw_isHESSIDPresent = FALSE;
			}
			else {
				hspotap->iw_isHESSIDPresent = TRUE;
				/* printf("HESSID 0x%x 0x%x 0x%x 0x%x 0x%x 0x%x\n", */
				/* hspotap->iw_HESSID.octet[0], */
				/* hspotap->iw_HESSID.octet[1], */
				/* hspotap->iw_HESSID.octet[2], */
				/* hspotap->iw_HESSID.octet[3], */
				/* hspotap->iw_HESSID.octet[4], */
				/* hspotap->iw_HESSID.octet[5]); */
			}
		} else {
			/* printf("%s is not defined in NVRAM\n", varname); */
		}
		/* Interworking Info ----------------------------------------- */

		/* Venue List ------------------------------------------------ */
		memset(&hspotap->venuelist, 0, sizeof(bcm_decode_anqp_venue_name_t));
		hspotap->venuelist.isDecodeValid = TRUE;

		ptr = nvram_get(strcat_r(prefix, "venuetype", varname));
		if (ptr) {
			hspotap->venuelist.type = atoi(ptr);
			/* printf("%s: %d\n", varname, hspotap->venuelist.type); */
		} else {
			/* printf("%s is not defined in NVRAM\n", varname); */
		}

		ptr = nvram_get(strcat_r(prefix, "venuegrp", varname));
		if (ptr) {
			hspotap->venuelist.group = atoi(ptr);
			/* printf("%s: %d\n", varname, hspotap->venuelist.group); */
		} else {
			/* printf("%s is not defined in NVRAM\n", varname); */
		}

		ptr = nvram_get(strcat_r(prefix, "venuelist", varname));
		if (ptr) {
			strncpy_n(ptrUTF8, ptr, NVRAM_MAX_VAL_LEN);
			HextoBytes((uchar*)ptrv, NVRAM_MAX_VAL_LEN,
				(uchar*)ptrUTF8, NVRAM_MAX_VAL_LEN);

			hspotap->venuelist.numVenueName = 0;
			if (strlen(ptrv) > 0) {
				tokenParse = NULL;
				i = 0;
				while ((i < BCM_DECODE_ANQP_MAX_PLMN) &&
					((tokenParse = strtok(i ? NULL : ptrv, "|")) != NULL)) {

					strncpy_n(item_value, tokenParse, NVRAM_MAX_VALUE_LEN);

					lang = item_value;
					venue = strsep(&lang, "!");

					if (venue && lang) {
					strncpy_n(hspotap->venuelist.venueName[i].name, venue,
						VENUE_NAME_SIZE + 1);
					hspotap->venuelist.venueName[i].nameLen = strlen(venue);
					strncpy_n(hspotap->venuelist.venueName[i].lang, lang,
						VENUE_LANGUAGE_CODE_SIZE +1);
					hspotap->venuelist.venueName[i].langLen = strlen(lang);
					}

					/* printf("VenueList %d: name = %s, lang = %s\n", i, */
					/* hspotap->venuelist.venueName[i].name, */
					/* hspotap->venuelist.venueName[i].lang); */

					i++;
				}
				hspotap->venuelist.numVenueName  = i;
			}
		} else {
			/* printf("%s is not defined in NVRAM\n", varname); */
		}
		/* Venue List ------------------------------------------------ */

		/* Network Authentication List ------------------------------- */
		char *nettype, *redirecturl;
		memset(&hspotap->netauthlist, 0,
			sizeof(bcm_decode_anqp_network_authentication_type_t));
		hspotap->netauthlist.isDecodeValid = TRUE;
		hspotap->netauthlist.numAuthenticationType = 0;

		ptr = nvram_get(strcat_r(prefix, "netauthlist", varname));
		if (ptr) {
			strncpy_n(ptrv, ptr, NVRAM_MAX_VAL_LEN);
			if (strlen(ptrv) > 0) {
				tokenParse = NULL;
				i = 0;

				while ((i < BCM_DECODE_ANQP_MAX_DOMAIN) &&
					((tokenParse = strtok(i ? NULL : ptrv, "+")) != NULL)) {

					strncpy_n(item_value, tokenParse, NVRAM_MAX_VALUE_LEN);

					redirecturl = item_value;
					nettype		= strsep(&redirecturl, "=");

					if (nettype) {
					if (!strncasecmp(nettype, "accepttc", 8))
						hspotap->netauthlist.unit[i].type =
						NATI_ACCEPTANCE_OF_TERMS_CONDITIONS;
					else if (!strncasecmp(nettype, "online", 6))
						hspotap->netauthlist.unit[i].type =
						NATI_ONLINE_ENROLLMENT_SUPPORTED;
					else if (!strncasecmp(nettype, "httpred", 7))
						hspotap->netauthlist.unit[i].type =
						NATI_HTTP_HTTPS_REDIRECTION;
					else if (!strncasecmp(nettype, "dnsred", 6))
						hspotap->netauthlist.unit[i].type
							= NATI_DNS_REDIRECTION;
					else
						hspotap->netauthlist.unit[i].type
							= NATI_UNSPECIFIED;

					if (((hspotap->netauthlist.unit[i].type
						== NATI_HTTP_HTTPS_REDIRECTION) && redirecturl) ||
						((hspotap->netauthlist.unit[i].type
						== NATI_DNS_REDIRECTION) && redirecturl)) {
						strncpy_n((char*)hspotap->netauthlist.unit[i].url,
							redirecturl,
							BCM_DECODE_ANQP_MAX_URL_LENGTH + 1);
						hspotap->netauthlist.unit[i].urlLen
							= strlen(redirecturl);
					} else {
						strncpy_n((char*)hspotap->netauthlist.unit[i].url,
							"", BCM_DECODE_ANQP_MAX_URL_LENGTH + 1);
						hspotap->netauthlist.unit[i].urlLen = 0;
					}
					}

					i++;
				}
				hspotap->netauthlist.numAuthenticationType = i;
			}
		}
		else {
			/* printf("%s is not defined in NVRAM\n", varname); */
		}
		/* Network Authentication List ------------------------------- */

		/* Roaming Consortium List ----------------------------------- */
		int data_len = 0;
		memset(&hspotap->ouilist, 0, sizeof(bcm_decode_anqp_roaming_consortium_t));
		hspotap->ouilist.isDecodeValid = TRUE;
		hspotap->ouilist.numOi = 0;

		ptr = nvram_get(strcat_r(prefix, "ouilist", varname));
		if (ptr) {
		strncpy_n(ptrv, ptr, NVRAM_MAX_VAL_LEN);
		if (strlen(ptrv) > 0) {
			i = 0;
			tokenParse = NULL;
			while ((i < BCM_DECODE_ANQP_MAX_OI) &&
				((tokenParse = strtok(i ? NULL : ptrv, ";")) != NULL)) {

				data_len = strlen(tokenParse) / 2;

				if (data_len && (data_len <= BCM_DECODE_ANQP_MAX_OI_LENGTH)) {

					get_hex_data((uchar *)tokenParse,
						hspotap->ouilist.oi[i].oi, data_len);
					hspotap->ouilist.oi[i].oiLen = data_len;

					/* printf("OI %d:0x%x 0x%x 0x%x\n", i, */
					/* hspotap->ouilist.oi[i].oi[0], */
					/* hspotap->ouilist.oi[i].oi[1], */
					/* hspotap->ouilist.oi[i].oi[2]); */
					i++;
				}
			}
			hspotap->ouilist.numOi = i;
		}
		}
		else {
			/* printf("%s is not defined in NVRAM\n", varname); */
		}
		/* Roaming Consortium List ----------------------------------- */

		/* IP Address Type Availability ------------------------------ */
		memset(&hspotap->ipaddrAvail, 0, sizeof(bcm_decode_anqp_ip_type_t));
		hspotap->ipaddrAvail.isDecodeValid = TRUE;

		ptr = nvram_get(strcat_r(prefix, "ipv4addr", varname));
		if (ptr) {
			hspotap->ipaddrAvail.ipv4 = atoi(ptr);
			/* printf("%s: %d\n", varname, hspotap->ipaddrAvail.ipv4); */
		} else {
			/* printf("%s is not defined in NVRAM\n", varname); */
		}
		ptr = nvram_get(strcat_r(prefix, "ipv6addr", varname));
		if (ptr) {
			hspotap->ipaddrAvail.ipv6 = atoi(ptr);
			/* printf("%s: %d\n", varname, hspotap->ipaddrAvail.ipv6); */
		} else {
			/* printf("%s is not defined in NVRAM\n", varname); */
		}
		/* IP Address Type Availability ------------------------------ */

		/* Realm List ------------------------------------------------ */
		char *realm, *realm_left, *realm_right;
		char *eap, *eap_left, *eap_right;
		char *auth, *auth_left, *auth_right;
		char* realm_name, *realm_encode, *eap_method, *auth_id, *auth_param;
		int iR = 0, iE = 0, iA = 0;
		uint8 auth_param_val[1];

		memset(&hspotap->realmlist, 0, sizeof(bcm_decode_anqp_nai_realm_list_t));
		hspotap->realmlist.isDecodeValid = TRUE;
		hspotap->realmlist.realmCount = 0;

		ptr = nvram_get(strcat_r(prefix, "realmlist", varname));
		if (ptr) {
		strncpy_n(ptrv, ptr, NVRAM_MAX_VAL_LEN);
		if (strlen(ptrv) > 0) {

		realm = ptrv;
		realm_right = realm;

		while (realm) {

		iE = 0;
		realm_left = strsep(&realm_right, "?");

		eap = realm_left;
		realm_name   = strsep(&eap, "+");
		realm_encode = strsep(&eap, "+");

		/* Fill Realm Encoding */
		hspotap->realmlist.realm[iR].encoding
			= (uint8)atoi(realm_encode);

		/* Fill Realm Name and length */
		hspotap->realmlist.realm[iR].realmLen = strlen(realm_name);
		strncpy_n((char*)hspotap->realmlist.realm[iR].realm,
			realm_name, BCM_DECODE_ANQP_MAX_REALM_LENGTH + 1);

		/* printf("Realm Name = %s\n", realm_name); */
		/* printf("Realm Encode = %s\n", realm_encode); */

		while (eap) {

			iA = 0;
			eap_right = eap;
			eap_left = strsep(&eap_right, ";");

			auth = eap_left;
			eap_method = strsep(&auth, "=");

			/* Fill EAP Method */
			hspotap->realmlist.realm[iR].eap[iE].eapMethod
				= (uint8)atoi(eap_method);

			/* printf("EAP Method = %s\n", eap_method); */

			while (auth) {

				auth_right = auth;
				auth_left = strsep(&auth_right, "#");

				auth_param = auth_left;
				auth_id = strsep(&auth_param, ",");

				/* Fill Auth ID */
				hspotap->realmlist.realm[iR].eap[iE].auth[iA].id
					= (uint8)atoi(auth_id);

				/* Fill Auth Param */
				auth_param_val[0] = (uint8)atoi(auth_param);
				memcpy(hspotap->realmlist.realm[iR].eap[iE].auth[iA].value,
					auth_param_val, sizeof(auth_param_val));

				/* Fill Auth Len */
				hspotap->realmlist.realm[iR].eap[iE].auth[iA].len
					= sizeof(auth_param_val);

				/* printf("Auth ID = %s\n", auth_id); */
				/* printf("Auth Param = %s\n", auth_param); */

				auth = auth_right;
				iA++;
			}
			/* Fill Auth Count */
			hspotap->realmlist.realm[iR].eap[iE].authCount = iA;
			/* printf("Auth Count for this EAP = %d\n", iA); */
			eap = eap_right;
			iE++;
		}
		/* Fill Eap Count */
		hspotap->realmlist.realm[iR].eapCount = iE;
		/* printf("Eap Count for this REALM = %d\n\n", iE); */

		realm = realm_right;
		iR++;
		}
		/* Fill Realm Count */
		hspotap->realmlist.realmCount = iR;
		/* printf("Realm Count for this Program = %d\n", iR); */
		}
		}
		/* Realm List ------------------------------------------------ */

		/* 3GPP Cellular Info List ----------------------------------- */
		char *mcc, *mnc;
		memset(&hspotap->gpp3list, 0, sizeof(bcm_decode_anqp_3gpp_cellular_network_t));
		hspotap->gpp3list.isDecodeValid = TRUE;
		hspotap->gpp3list.plmnCount = 0;

		ptr = nvram_get(strcat_r(prefix, "3gpplist", varname));
		if (ptr) {
			strncpy_n(ptrv, ptr, NVRAM_MAX_VAL_LEN);
			if (strlen(ptrv) > 0) {
				i = 0;
				tokenParse = NULL;

				while ((i < BCM_DECODE_ANQP_MAX_PLMN) &&
					((tokenParse = strtok(i ? NULL : ptrv, ";")) != NULL)) {

					strncpy_n(item_value, tokenParse, NVRAM_MAX_VALUE_LEN);

					mnc  = item_value;
					mcc  = strsep(&mnc, ":");

					if (mcc && mnc)
					{
						strncpy_n(hspotap->gpp3list.plmn[i].mcc, mcc,
							BCM_DECODE_ANQP_MCC_LENGTH + 1);
						strncpy_n(hspotap->gpp3list.plmn[i].mnc, mnc,
							BCM_DECODE_ANQP_MNC_LENGTH + 1);
					}
					/* printf("3GPP %d: mcc = %s, mnc = %s\n", i, */
					/* hspotap->gpp3list.plmn[i].mcc, */
					/* hspotap->gpp3list.plmn[i].mnc); */

					i++;
				}
				hspotap->gpp3list.plmnCount = i;
			}
		} else {
			/* printf("%s is not defined in NVRAM\n", varname); */
		}
		/* 3GPP Cellular Info List ----------------------------------- */

		/* Domain Name List ------------------------------------------ */
		memset(&hspotap->domainlist, 0, sizeof(bcm_decode_anqp_domain_name_list_t));
		hspotap->domainlist.isDecodeValid = TRUE;
		hspotap->domainlist.numDomain = 0;

		ptr = nvram_get(strcat_r(prefix, "domainlist", varname));
		if (ptr) {
			strncpy_n(ptrv, ptr, NVRAM_MAX_VAL_LEN);
			if (strlen(ptrv) > 0) {
				tokenParse = NULL;
				i = 0;

				while ((i < BCM_DECODE_ANQP_MAX_DOMAIN) &&
					((tokenParse = strtok(i ? NULL : ptrv, " ")) != NULL)) {

					strncpy_n(hspotap->domainlist.domain[i].name, tokenParse,
						BCM_DECODE_ANQP_MAX_DOMAIN_NAME_SIZE+1);
					hspotap->domainlist.domain[i].len = strlen(tokenParse);
					/* printf("Domain %d: %s, len %d\n", i, */
					/* hspotap->domainlist.domain[i].name, */
					/* hspotap->domainlist.domain[i].len); */

					i++;
				}
				hspotap->domainlist.numDomain = i;
			}
		} else {
			/* printf("%s is not defined in NVRAM\n", varname); */
		}
		/* Domain Name List ------------------------------------------ */

		/* Operating Class ------------------------------------------- */
		int Operating_Class = 1;
		uint8 opClass1 [1] = {81};
		uint8 opClass2 [1] = {115};
		uint8 opClass3 [2] = {81, 115};

		memset(&hspotap->opclass, 0,
			sizeof(bcm_decode_hspot_anqp_operating_class_indication_t));
		hspotap->opclass.isDecodeValid = TRUE;

		ptr = nvram_get(strcat_r(prefix, "opercls", varname));
		if (ptr) {
			Operating_Class = atoi(ptr);

			if (Operating_Class == 3) {
				hspotap->opclass.opClassLen = sizeof(opClass3);
				memcpy(hspotap->opclass.opClass, opClass3, sizeof(opClass3));
			}
			else if (Operating_Class == 2) {
				hspotap->opclass.opClassLen = sizeof(opClass2);
				memcpy(hspotap->opclass.opClass, opClass3, sizeof(opClass2));
			}
			else if (Operating_Class == 1) {
				hspotap->opclass.opClassLen = sizeof(opClass1);
				memcpy(hspotap->opclass.opClass, opClass3, sizeof(opClass1));
			}
			else {
				hspotap->opclass.opClassLen = 0;
				memcpy(hspotap->opclass.opClass, opClass3, sizeof(opClass3));
			}

			/* printf("%s: %d\n", varname, Operating_Class); */
		} else {
			/* printf("%s is not defined in NVRAM\n", varname); */
		}
		/* Operating Class ------------------------------------------- */

		/* Operator Friendly Name List ------------------------------- */
		char *oper, *lang;
		memset(&hspotap->oplist, 0, sizeof(bcm_decode_hspot_anqp_operator_friendly_name_t));
		hspotap->oplist.numName = 0;
		hspotap->oplist.isDecodeValid = TRUE;

		ptr = nvram_get(strcat_r(prefix, "oplist", varname));
		if (ptr) {
			strncpy_n(ptrv, ptr, NVRAM_MAX_VAL_LEN);
			if (strlen(ptrv) > 0) {
				tokenParse = NULL;
				i = 0;
				while ((i < BCM_DECODE_ANQP_MAX_PLMN) &&
					((tokenParse = strtok(i ? NULL : ptrv, "|")) != NULL)) {

					strncpy_n(item_value, tokenParse, NVRAM_MAX_VALUE_LEN);

					lang = item_value;
					oper = strsep(&lang, "!");

					if (oper && lang)
					{
						strncpy_n(hspotap->oplist.duple[i].name, oper,
							VENUE_NAME_SIZE + 1);
						hspotap->oplist.duple[i].nameLen = strlen(oper);
						strncpy_n(hspotap->oplist.duple[i].lang, lang,
							VENUE_LANGUAGE_CODE_SIZE +1);
						hspotap->oplist.duple[i].langLen = strlen(lang);
					}

					/* printf("OperatorList %d: name = %s, lang = %s\n", i, */
					/* hspotap->oplist.duple[i].name, */
					/* hspotap->oplist.duple[i].lang); */

					i++;
				}
				hspotap->oplist.numName  = i;
			}
		} else {
			/* printf("%s is not defined in NVRAM\n", varname); */
		}
		/* Operator Friendly Name List ------------------------------- */

		/* OSU Provider List Info ------------------------------------ */
		/* OSU_icon_ID */
		ptr = nvram_get(strcat_r(prefix, "osuicon_id", varname));
		if (ptr) {
			hspotap->osuicon_id = atoi(ptr);
			/* printf("%s: %d\n", varname, hspotap->osuicon_id); */
		} else {
			/* printf("%s is not defined in NVRAM\n", varname); */
		}
		/* OSU_SSID */
		ptr = nvram_get(strcat_r(prefix, "osu_ssid", varname));
		if (ptr) {
			strncpy_n((char*)hspotap->osuplist.osuSsid, ptr,
				BCM_DECODE_HSPOT_ANQP_MAX_OSU_SSID_LENGTH + 1);
			hspotap->osuplist.osuSsidLength = strlen(ptr);
			hspotap->osuplist.isDecodeValid = TRUE;
			/* printf("%s: %s\n", varname, hspotap->osuplist.osuSsid); */
		} else {
			/* printf("%s is not defined in NVRAM\n", varname); */
		}
		/* OSU_Server_URI */
		ptr = nvram_get(strcat_r(prefix, "osu_uri", varname));
		if (ptr) {
			strncpy_n(ptrv, ptr, NVRAM_MAX_VAL_LEN);
			if (strlen(ptrv) > 0) {
				tokenParse = NULL;
				i = 0;
				while ((i < BCM_DECODE_HSPOT_ANQP_MAX_OSU_PROVIDER) &&
					((tokenParse = strtok(i ? NULL : ptrv, ";")) != NULL)) {

					strncpy_n((char*)hspotap->osuplist.osuProvider[i].uri,
						tokenParse,
						BCM_DECODE_HSPOT_ANQP_MAX_URI_LENGTH + 1);
					hspotap->osuplist.osuProvider[i].uriLength
						= strlen(tokenParse);

				/* printf("OSU Server URI %d: URI = %s, Length = %d\n", i, */
				/* hspotap->osuplist.osuProvider[i].uri, */
				/* hspotap->osuplist.osuProvider[i].uriLength); */

					i++;
				}
				hspotap->osuplist.osuProviderCount = i;
			}
		} else {
			/* printf("%s is not defined in NVRAM\n", varname); */
		}
		/* OSU_Method */
		uint8 osu_method[1];
		ptr = nvram_get(strcat_r(prefix, "osu_method", varname));
		if (ptr) {
			strncpy_n(ptrv, ptr, NVRAM_MAX_VAL_LEN);
			if (strlen(ptrv) > 0) {
				tokenParse = NULL;
				i = 0;
				while ((i < BCM_DECODE_HSPOT_ANQP_MAX_OSU_PROVIDER) &&
					((tokenParse = strtok(i ? NULL : ptrv, ";")) != NULL)) {

					osu_method[0] = (!strncasecmp(tokenParse, "0", 1)) ?
						HSPOT_OSU_METHOD_OMA_DM : HSPOT_OSU_METHOD_SOAP_XML;
					memcpy(hspotap->osuplist.osuProvider[i].method,
						osu_method, sizeof(osu_method));
					hspotap->osuplist.osuProvider[i].methodLength
						= sizeof(osu_method);

					/* printf("OSU Method %d: Method = %s, Length = %d\n", i, */
					/* osu_method[0] ? "OMADM" : "SOAP", */
					/* hspotap->osuplist.osuProvider[i].methodLength); */

					i++;
				}
			}
		} else {
			/* printf("%s is not defined in NVRAM\n", varname); */
		}
		/* OSU_Friendly_Name */
		char *provider = NULL, *provider_left = NULL, *provider_right = NULL;
		char ptrFrndlyName[NVRAM_MAX_VAL_LEN] = {0};
		int iP = 0, iD = 0;
		oper = NULL,  lang = NULL;
		memset(ptrFrndlyName, 0, sizeof(ptrFrndlyName));
		ptr = nvram_get(strcat_r(prefix, "osu_frndname", varname));
		if (ptr) {
			strncpy_n(ptrv, ptr, NVRAM_MAX_VAL_LEN);
			if (strlen(ptrv) > 0) {
				provider = ptrv;
				provider_right = provider;

				while ((iP < BCM_DECODE_HSPOT_ANQP_MAX_OSU_PROVIDER) && provider)
				{
				tokenParse = NULL;
				iD = 0;

				provider_left = strsep(&provider_right, ";");
				strncpy_n(ptrFrndlyName, provider_left,
					NVRAM_MAX_VAL_LEN);

				while ((iD < BCM_DECODE_HSPOT_ANQP_MAX_OPERATOR_NAME) &&
					((tokenParse =
					strtok(iD ? NULL : ptrFrndlyName, "|"))
					!= NULL)) {

				strncpy_n(item_value,
					tokenParse,
					NVRAM_MAX_VALUE_LEN);

				lang = item_value;
				oper = strsep(&lang, "!");

				if (oper && lang)
				{
				strncpy_n(hspotap->osuplist.osuProvider[iP].name.duple[iD].name,
					oper, VENUE_NAME_SIZE + 1);
				hspotap->osuplist.osuProvider[iP].name.duple[iD].nameLen
					= strlen(oper);
				strncpy_n(hspotap->osuplist.osuProvider[iP].name.duple[iD].lang,
					lang,
					VENUE_LANGUAGE_CODE_SIZE +1);
				hspotap->osuplist.osuProvider[iP].name.duple[iD].langLen
					= strlen(lang);

				/* printf("Provider # %d: OSU Friendly Name %d:" */
				/* " name = %s, lang = %s\n", iP, iD, */
				/* hspotap->osuplist.osuProvider[iP].name.duple[iD].name, */
				/* hspotap->osuplist.osuProvider[iP].name.duple[iD].lang); */
				}

				iD++;
				}
				hspotap->osuplist.osuProvider[iP].name.numName  = iD;
				provider = provider_right;
				iP++;
				}
			}
		} else {
			/* printf("%s is not defined in NVRAM\n", varname); */
		}
		/* OSU_Server_Desc */
		provider = NULL, provider_left = NULL, provider_right = NULL;
		memset(ptrFrndlyName, 0, sizeof(ptrFrndlyName));
		iP = 0, iD = 0;
		oper = NULL,  lang = NULL;
		ptr = nvram_get(strcat_r(prefix, "osu_servdesc", varname));
		if (ptr) {
			strncpy_n(ptrv, ptr, NVRAM_MAX_VAL_LEN);
			if (strlen(ptrv) > 0) {

				provider = ptrv;
				provider_right = provider;

				while ((iP < BCM_DECODE_HSPOT_ANQP_MAX_OSU_PROVIDER) && provider)
				{
				tokenParse = NULL;
				iD = 0;

				provider_left = strsep(&provider_right, ";");
				strncpy_n(ptrFrndlyName,
					provider_left,
					NVRAM_MAX_VAL_LEN);

				while ((iD < BCM_DECODE_HSPOT_ANQP_MAX_OPERATOR_NAME) &&
					((tokenParse =
					strtok(iD ? NULL : ptrFrndlyName, "|"))
					!= NULL))
				{

				strncpy_n(item_value,
					tokenParse,
					NVRAM_MAX_VALUE_LEN);

				lang = item_value;
				oper = strsep(&lang, "!");

				if (oper && lang)
				{
				strncpy_n(hspotap->osuplist.osuProvider[iP].desc.duple[iD].name,
					oper, VENUE_NAME_SIZE + 1);
				hspotap->osuplist.osuProvider[iP].desc.duple[iD].nameLen
					= strlen(oper);
				strncpy_n(hspotap->osuplist.osuProvider[iP].desc.duple[iD].lang,
					lang,
					VENUE_LANGUAGE_CODE_SIZE +1);
				hspotap->osuplist.osuProvider[iP].desc.duple[iD].langLen
					= strlen(lang);

				/* printf("Provider # %d: OSU Serv Desc %d:" */
				/* " name = %s, lang = %s\n", iP, iD, */
				/* hspotap->osuplist.osuProvider[iP].desc.duple[iD].name, */
				/* hspotap->osuplist.osuProvider[iP].desc.duple[iD].lang); */

				}
				iD++;
				}
				hspotap->osuplist.osuProvider[iP].desc.numName  = iD;
				provider = provider_right;
				iP++;
				}
			}
		} else {
			/* printf("%s is not defined in NVRAM\n", varname); */
		}
		/* OSU_NAI */
		ptr = nvram_get(strcat_r(prefix, "osu_nai", varname));
		if (ptr) {
			strncpy_n(ptrv, ptr, NVRAM_MAX_VAL_LEN);
			if (strlen(ptrv) > 0) {
				tokenParse = NULL;
				i = 0;
				while ((i < BCM_DECODE_HSPOT_ANQP_MAX_OSU_PROVIDER) &&
					((tokenParse = strtok(i ? NULL : ptrv, ";")) != NULL)) {
					strncpy_n((char*)hspotap->osuplist.osuProvider[i].nai,
						tokenParse,
						BCM_DECODE_HSPOT_ANQP_MAX_NAI_LENGTH + 1);
					hspotap->osuplist.osuProvider[i].naiLength
						= strlen(tokenParse);

				/* printf("OSU Server URI %d: URI = %s, Length = %d\n", i, */
				/* hspotap->osuplist.osuProvider[i].nai, */
				/* hspotap->osuplist.osuProvider[i].naiLength); */

					i++;
				}
			}
		} else {
			/* printf("%s is not defined in NVRAM\n", varname); */
		}
		/* OSU_Icons */
		char icon_path[BUFFER_SIZE] = {0};
		char mime_type[BCM_DECODE_HSPOT_ANQP_MAX_ICON_TYPE_LENGTH + 1] = {0};
		int width = 0, height = 0;

		memset(mime_type, 0, sizeof(mime_type));

		provider = NULL, provider_left = NULL, provider_right = NULL;
		memset(ptrFrndlyName, 0, sizeof(ptrFrndlyName));
		iP = 0, iD = 0;
		oper = NULL,  lang = NULL;
		ptr = nvram_get(strcat_r(prefix, "osu_icons", varname));
		if (ptr) {
		strncpy_n(ptrv, ptr, NVRAM_MAX_VAL_LEN);
		if (strlen(ptrv) > 0)
		{
		provider = ptrv;
		provider_right = provider;

		while ((iP < BCM_DECODE_HSPOT_ANQP_MAX_OSU_PROVIDER) && provider)
		{
		tokenParse = NULL;
		iD = 0;

		provider_left = strsep(&provider_right, ";");
		strncpy_n(ptrFrndlyName,
			provider_left,
			NVRAM_MAX_VAL_LEN);

		while ((iD < BCM_DECODE_HSPOT_ANQP_MAX_OPERATOR_NAME) &&
			((tokenParse
				= strtok(iD ? NULL : ptrFrndlyName, "+")) != NULL))
		{

		strncpy_n(hspotap->osuplist.osuProvider[iP].iconMetadata[iD].filename,
			tokenParse,
			BCM_DECODE_HSPOT_ANQP_MAX_ICON_FILENAME_LENGTH + 1);
		hspotap->osuplist.osuProvider[iP].
			iconMetadata[iD].filenameLength
				= strlen(tokenParse);

		/* Write a function to Fill Icon Metadata */
		width = 0, height = 0;
		memset(icon_path, 0, sizeof(icon_path));
		strncpy_n(icon_path, "/bin/", BUFFER_SIZE);
		strncat(icon_path,
			hspotap->osuplist.osuProvider[iP].iconMetadata[iD].filename,
			min(strlen(hspotap->osuplist.osuProvider[iP].iconMetadata[iD].filename),
			BUFFER_SIZE-strlen(icon_path)));

		GetImageSize(icon_path, &width, &height);
		GetMimeType(icon_path, mime_type, BCM_DECODE_HSPOT_ANQP_MAX_ICON_TYPE_LENGTH + 1);
		hspotap->osuplist.osuProvider[iP].iconMetadata[iD].width
				= width;
		hspotap->osuplist.osuProvider[iP].iconMetadata[iD].height
				= height;

		strncpy_n(hspotap->osuplist.osuProvider[iP].iconMetadata[iD].lang,
			strstr(hspotap->osuplist.osuProvider[iP].iconMetadata[iD].filename,
			"_zxx.") ? LANG_ZXX : ENGLISH, VENUE_LANGUAGE_CODE_SIZE +1);

		strncpy_n((char*)
				hspotap->osuplist.osuProvider[iP].iconMetadata[iD].type,
				mime_type,
				BCM_DECODE_HSPOT_ANQP_MAX_ICON_TYPE_LENGTH + 1);
		hspotap->osuplist.osuProvider[iP].iconMetadata[iD].typeLength
			= strlen(mime_type);

		/* printf("Provider # %d: OSU Icons %d:\n" */
		/* " Filename = %s, Length = %d\n" */
		/* " Type = %s, Type_Length = %d\n" */
		/* " lang = %s, height = %d, width = %d\n", iP, iD, */
		/* hspotap->osuplist.osuProvider[iP].iconMetadata[iD].filename, */
		/* hspotap->osuplist.osuProvider[iP].iconMetadata[iD].filenameLength, */
		/* hspotap->osuplist.osuProvider[iP].iconMetadata[iD].type, */
		/* hspotap->osuplist.osuProvider[iP].iconMetadata[iD].typeLength, */
		/* hspotap->osuplist.osuProvider[iP].iconMetadata[iD].lang, */
		/* hspotap->osuplist.osuProvider[iP].iconMetadata[iD].height, */
		/* hspotap->osuplist.osuProvider[iP].iconMetadata[iD].width); */

		iD++;
		}
		hspotap->osuplist.osuProvider[iP].iconMetadataCount = iD;
		provider = provider_right;
		iP++;
		}
		}
		} else {
			/* printf("%s is not defined in NVRAM\n", varname); */
		}
		for (i = iP; i < MAX_OSU_PROVIDERS; i++)
			memset(&hspotap->osuplist.osuProvider[i], 0,
				sizeof(hspotap->osuplist.osuProvider[i]));
		/* OSU Provider List Info ------------------------------------ */

		/* Annonymous NAI -------------------------------------------- */
		memset(&hspotap->anonai, 0, sizeof(bcm_decode_hspot_anqp_anonymous_nai_t));
		hspotap->anonai.isDecodeValid = TRUE;

		ptr = nvram_get(strcat_r(prefix, "anonai", varname));
		if (ptr) {
			strncpy_n(hspotap->anonai.nai, ptr,
				BCM_DECODE_HSPOT_ANQP_MAX_NAI_SIZE + 1);
			hspotap->anonai.naiLen = strlen(hspotap->anonai.nai);
			/* printf("%s: %s\n", varname, hspotap->anonai.nai); */
		} else {
			/* printf("%s is not defined in NVRAM\n", varname); */
		}
		/* Annonymous NAI -------------------------------------------- */

		/* WAN Metrics ----------------------------------------------- */
		char *p_linkStatus, *p_symmetricLink, *p_atCapacity, *p_dlinkSpeed;
		char *p_ulinkSpeed, *p_dlinkLoad, *p_ulinkLoad, *p_lmd;

		memset(&hspotap->wanmetrics, 0, sizeof(bcm_decode_hspot_anqp_wan_metrics_t));
		hspotap->wanmetrics.isDecodeValid = TRUE;

		ptr = nvram_get(strcat_r(prefix, "wanmetrics", varname));
		if (ptr) {
			strncpy_n(ptrv, ptr, NVRAM_MAX_VAL_LEN);
			if (strlen(ptrv) > 0) {
				p_dlinkSpeed = ptrv;
				p_linkStatus = strsep(&p_dlinkSpeed, "=");

				p_dlinkLoad = p_dlinkSpeed;
				p_dlinkSpeed = strsep(&p_dlinkLoad, "=");

				p_lmd = p_dlinkLoad;
				p_dlinkLoad = strsep(&p_lmd, "=");

				/* Parse next 2 params >>	p_dlinkLoad>p_ulinkLoad */
				p_ulinkLoad = p_dlinkLoad;
				p_dlinkLoad = strsep(&p_ulinkLoad, ">");

				/* Parse next 2 params >>	p_dlinkSpeed>p_ulinkSpeed */
				p_ulinkSpeed = p_dlinkSpeed;
				p_dlinkSpeed = strsep(&p_ulinkSpeed, ">");

				/* Parse first 3 params >> */
				/* p_linkStatus:p_symmetricLink:p_atCapacity */
				p_atCapacity	= p_linkStatus;
				p_linkStatus	= strsep(&p_atCapacity, ":");
				p_symmetricLink = strsep(&p_atCapacity, ":");

				if (p_linkStatus && p_symmetricLink &&
					p_atCapacity && p_dlinkSpeed && p_ulinkSpeed &&
					p_dlinkLoad && p_ulinkLoad && p_lmd)
				{
					hspotap->wanmetrics.linkStatus = atoi(p_linkStatus);
					hspotap->wanmetrics.symmetricLink = atoi(p_symmetricLink);
					hspotap->wanmetrics.atCapacity = atoi(p_atCapacity);
					hspotap->wanmetrics.dlinkSpeed = atoi(p_dlinkSpeed);
					hspotap->wanmetrics.ulinkSpeed = atoi(p_ulinkSpeed);
					hspotap->wanmetrics.dlinkLoad = atoi(p_dlinkLoad);
					hspotap->wanmetrics.ulinkLoad = atoi(p_ulinkLoad);
					hspotap->wanmetrics.lmd = atoi(p_lmd);
				}
			}
		} else {
			/* printf("%s is not defined in NVRAM\n", varname); */
		}
		/* WAN Metrics ----------------------------------------------- */

		/* Connection Capability ID ---------------------------------- */
		ptr = nvram_get(strcat_r(prefix, "conn_id", varname));
		if (ptr) {
			hspotap->conn_id = atoi(ptr);
			/* printf("%s: %d\n", varname, hspotap->conn_id); */
		} else {
			/* printf("%s is not defined in NVRAM\n", varname); */
		}
		/* Connection Capability ID ---------------------------------- */

		/* NAI Home Realm Query List --------------------------------- */
		char *homerealm, *encode;
		memset(&hspotap->homeqlist, 0,
			sizeof(bcm_decode_hspot_anqp_nai_home_realm_query_t));
		hspotap->homeqlist.isDecodeValid = TRUE;
		hspotap->homeqlist.count = 0;

		ptr = nvram_get(strcat_r(prefix, "homeqlist", varname));
		if (ptr) {
		strncpy_n(ptrv, ptr, NVRAM_MAX_VAL_LEN);
		if (strlen(ptrv) > 0) {
			tokenParse = NULL;
			i = 0;
			while ((i < BCM_DECODE_ANQP_MAX_PLMN) &&
				((tokenParse = strtok(i ? NULL : ptrv, ";")) != NULL)) {

				strncpy_n(item_value, tokenParse, NVRAM_MAX_VALUE_LEN);

				encode = item_value;
				homerealm = strsep(&encode, ":");

				if (homerealm && encode)
				{
					strncpy_n(hspotap->homeqlist.data[i].name, homerealm,
						VENUE_NAME_SIZE + 1);
					hspotap->homeqlist.data[i].nameLen = strlen(homerealm);

					if (!strncasecmp(encode, "rfc4282", 7))
						hspotap->homeqlist.data[i].encoding
							= REALM_ENCODING_RFC4282;
					else if (!strncasecmp(encode, "utf8", 4))
						hspotap->homeqlist.data[i].encoding
							= REALM_ENCODING_UTF8;
				}

				/* printf("HomeRealmQueryList %d: name = %s, encoding = %d\n", i, */
				/* hspotap->homeqlist.data[i].name, */
				/* (int)hspotap->homeqlist.data[i].encoding); */

				i++;
			}
			hspotap->homeqlist.count = i;
		}
		} else {
			/* printf("%s is not defined in NVRAM\n", varname); */
		}
		/* NAI Home Realm Query List --------------------------------- */

		/* Passpoint Capability ---------------------------------------- */
		ptr = nvram_get(strcat_r(prefix, "hs2cap", varname));
		if (ptr) {
			hspotap->hs_capable = atoi(ptr);
			/* printf("%s: %d\n", varname, hspotap->hs_capable); */
		} else {
			/* printf("%s is not defined in NVRAM\n", varname); */
		}
		/* Passpoint Capability ---------------------------------------- */

		strncpy_n(hspotap->prefix, prefix, MAX_NVPARSE);
		} else {
			/* printf("can't find NVRAM ifname for %s\n", osifname); */
		}

		if (hspotap_num == 1) {
			for (i = 1; i < argc; i++) {
				if (strcmp(argv[i], "-help") == 0) {
					printf("\n");
					printf(" -debug      		enable debug output\n");
					printf(" -verbose    		enable verbose output\n");
					printf(" -help       		print this menu\n");
					printf(" -dgaf       		disable DGAF\n");
					printf(" -tcp_port <port>   Run hspotap in CLI mode\n");
					printf("\n");
					printf("To redirect to file use 'tee' "
						"(eg. %s -d | tee log.txt).\n", argv[0]);
					printf("\n");
					hspotapFree();
					exit(1);
				}
				else if (strcmp(argv[i], "-debug") == 0) {
					TRACE_LEVEL_SET(TRACE_ERROR | TRACE_DEBUG | TRACE_PACKET);
				}
				else if (strcmp(argv[i], "-verbose") == 0) {
					TRACE_LEVEL_SET(TRACE_ALL);
				}
				else if (strcmp(argv[i], "-dgaf") == 0) {
					Set_hspot_flag(hspotap->prefix, HSFLG_DGAF_DS, TRUE);
				}
				else if (strcmp(argv[i], "-tcp_port") == 0) {
					if (i == (argc - 1)) {
						printf("Not enough args for tcp port option\n");
						hspotapFree();
						exit(1);
					}
					tcpServerPort = atol(argv[i+1]);
					tcpServerEnabled = 1;
					i++;
				}
				else if (strcmp(argv[i], "-test") == 0) {
					if (i == (argc - 1)) {
						printf("Not enough arguments for test option\n");
						hspotapFree();
						exit(1);
					}
					/* setTestParameters(argv[i+1], hspotap); */
					i++;
				}
				else if (strcmp(argv[i], "-respSize") == 0) {
					if (i == (argc - 1)) {
						printf("Not enough args for respSize option\n");
						hspotapFree();
						exit(1);
					}
					hspotap->testResponseSize = atoi(argv[i+1]);
					i++;
				}
				else if (strcmp(argv[i], "-gas4FramesOn") == 0) {
					printf("GAS 4 Frames is ON\n");
					hspotap->testResponseSize = 20000;
					hspotap->isGasPauseForServerResponse = FALSE;
					hspotap->gas_cb_delay = 1000;
					printf("testResponseSize %d\n", hspotap->testResponseSize);
				}
				else {
					printf("%s invalid\n", argv[i]);
					hspotapFree();
					exit(1);
				}
			}
		}

		if (wl_disable_event_msg(ifr, WLC_E_P2P_PROBREQ_MSG) < 0)
			TRACE(TRACE_ERROR, "failed to disable event msg %d\n",
				WLC_E_P2P_PROBREQ_MSG);

		/* add IEs */
		addIes(hspotap);

		/* init_wlan_hspot(hspotap); */

		wl_wnm_url(ifr, 0, 0);

		if (hspotap_num >= MAX_WLIF_NUM)
			break;
	}

	current_hspotap = hspotaps[0];

	/* initialize GAS protocol */
	bcm_gas_subscribe_event(0, gasEventCallback);
	bcm_gas_init_dsp();
	bcm_gas_init_wlan_handler();

	if (tcpServerEnabled) {
		tcpSubscribeTcpHandler(0, tcpReceiveHandler);
		tcpSrvCreate(tcpServerPort);
	}

	for (i = 0; i < hspotap_num; i++) {
		if (hspotaps[i]->gas_cb_delay) {
			bcm_gas_set_if_cb_delay_unpause(
				hspotaps[i]->gas_cb_delay, hspotaps[i]->ifr);
		}
		bcm_gas_set_if_gas_pause(
			hspotaps[i]->isGasPauseForServerResponse, hspotaps[i]->ifr);
	}
	dspStart(dsp());

	/* deinitialize GAS protocol */
	bcm_gas_deinitialize();
	bcm_gas_unsubscribe_event(gasEventCallback);

	/* terminate dispatcher */
	dspFree();

	if (tcpServerEnabled) {
		tcpSubscribeTcpHandler(0, NULL);
		tcpSrvDestroy();
		tcpServerEnabled = 0;
	}

	hspotapFree();
	return 0;
}
