/**************************************************************************
//
//  Copyright (c) 2006-2007 Sony Corporation. All Rights Reserved.
//
//  File Name: wps_parser.c
//  Description: EAP-WPS parser source
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

#include "includes.h"

#include "defs.h"
#include "common.h"
#include "wps_config.h"
#include "wps_parser.h"

#define GENERIC_INFO_ELEM 0xdd
#define RSN_INFO_ELEM 0x30

#define WPS_LENTYPE_FIX		0
#define WPS_LENTYPE_MAX		1
#define WPS_LENTYPE_MIN		2

struct wps_tlv_set {
	u16		type;
	u16		length;
	u16		length_type;
	u16		value_type;
};

const struct wps_tlv_set wps_tlv_sets [] = {
	{WPS_TYPE_AP_CHANNEL,			2,		WPS_LENTYPE_FIX,	WPS_VALTYPE_U16},
	{WPS_TYPE_ASSOC_STATE,			2,		WPS_LENTYPE_FIX,	WPS_VALTYPE_U16},
	{WPS_TYPE_AUTH_TYPE,			2,		WPS_LENTYPE_FIX,	WPS_VALTYPE_U16},
	{WPS_TYPE_AUTH_TYPE_FLAGS,		2,		WPS_LENTYPE_FIX,	WPS_VALTYPE_U16},
	{WPS_TYPE_AUTHENTICATOR,		8,		WPS_LENTYPE_FIX,	WPS_VALTYPE_PTR},
	{WPS_TYPE_CONFIG_METHODS,		2,		WPS_LENTYPE_FIX,	WPS_VALTYPE_U16},
	{WPS_TYPE_CONFIG_ERROR,			2,		WPS_LENTYPE_FIX,	WPS_VALTYPE_U16},
	{WPS_TYPE_CONF_URL4,			64,		WPS_LENTYPE_MAX,	WPS_VALTYPE_PTR},
	{WPS_TYPE_CONF_URL6,			76,		WPS_LENTYPE_MAX,	WPS_VALTYPE_PTR},
	{WPS_TYPE_CONN_TYPE,			1,		WPS_LENTYPE_FIX,	WPS_VALTYPE_U8},
	{WPS_TYPE_CONN_TYPE_FLAGS,		1,		WPS_LENTYPE_FIX,	WPS_VALTYPE_U8},
	{WPS_TYPE_CREDENTIAL,			0xFFFF,	WPS_LENTYPE_MAX,	WPS_VALTYPE_PTR},
	{WPS_TYPE_DEVICE_NAME,			32,		WPS_LENTYPE_MAX,	WPS_VALTYPE_PTR},
	{WPS_TYPE_DEVICE_PWD_ID,		2,		WPS_LENTYPE_FIX,	WPS_VALTYPE_U16},
	{WPS_TYPE_E_HASH1,				32,		WPS_LENTYPE_FIX,	WPS_VALTYPE_PTR},
	{WPS_TYPE_E_HASH2,				32,		WPS_LENTYPE_FIX,	WPS_VALTYPE_PTR},
	{WPS_TYPE_E_SNONCE1,			16,		WPS_LENTYPE_FIX,	WPS_VALTYPE_PTR},
	{WPS_TYPE_E_SNONCE2,			16,		WPS_LENTYPE_FIX,	WPS_VALTYPE_PTR},
	{WPS_TYPE_ENCR_SETTINGS,		0xFFFF,	WPS_LENTYPE_MAX,	WPS_VALTYPE_PTR},
	{WPS_TYPE_ENCR_TYPE,			2,		WPS_LENTYPE_FIX,	WPS_VALTYPE_U16},
	{WPS_TYPE_ENCR_TYPE_FLAGS,		2,		WPS_LENTYPE_FIX,	WPS_VALTYPE_U16},
	{WPS_TYPE_ENROLLEE_NONCE,		16,		WPS_LENTYPE_FIX,	WPS_VALTYPE_PTR},
	{WPS_TYPE_FEATURE_ID,			4,		WPS_LENTYPE_FIX,	WPS_VALTYPE_U32},
	{WPS_TYPE_IDENTITY,				80,		WPS_LENTYPE_MAX,	WPS_VALTYPE_PTR},
	{WPS_TYPE_IDENTITY_PROOF,		0xFFFF,	WPS_LENTYPE_MAX,	WPS_VALTYPE_PTR},
	{WPS_TYPE_KEY_WRAP_AUTH,		8,		WPS_LENTYPE_FIX,	WPS_VALTYPE_PTR},
	{WPS_TYPE_KEY_IDENTIFIER,		16,		WPS_LENTYPE_FIX,	WPS_VALTYPE_PTR},
	{WPS_TYPE_MAC_ADDR,				6,		WPS_LENTYPE_FIX,	WPS_VALTYPE_PTR},
	{WPS_TYPE_MANUFACTURER,			64,		WPS_LENTYPE_MAX,	WPS_VALTYPE_PTR},
	{WPS_TYPE_MSG_TYPE,				1,		WPS_LENTYPE_FIX,	WPS_VALTYPE_U8},
	{WPS_TYPE_MODEL_NAME,			32,		WPS_LENTYPE_MAX,	WPS_VALTYPE_PTR},
	{WPS_TYPE_MODEL_NUMBER,			32,		WPS_LENTYPE_MAX,	WPS_VALTYPE_PTR},
	{WPS_TYPE_NW_INDEX,				1,		WPS_LENTYPE_FIX,	WPS_VALTYPE_U8},
	{WPS_TYPE_NW_KEY,				64,		WPS_LENTYPE_MAX,	WPS_VALTYPE_PTR},
	{WPS_TYPE_NW_KEY_INDEX,			1,		WPS_LENTYPE_FIX,	WPS_VALTYPE_U8},
	{WPS_TYPE_NEW_DEVICE_NAME,		32,		WPS_LENTYPE_MAX,	WPS_VALTYPE_PTR},
	{WPS_TYPE_NEW_PWD,				64,		WPS_LENTYPE_MAX,	WPS_VALTYPE_PTR},
	{WPS_TYPE_OOB_DEV_PWD,			58,		WPS_LENTYPE_MAX,	WPS_VALTYPE_PTR},
	{WPS_TYPE_OS_VERSION,			4,		WPS_LENTYPE_FIX,	WPS_VALTYPE_U32},
	{WPS_TYPE_POWER_LEVEL,			1,		WPS_LENTYPE_FIX,	WPS_VALTYPE_U8},
	{WPS_TYPE_PSK_CURRENT,			1,		WPS_LENTYPE_FIX,	WPS_VALTYPE_U8},
	{WPS_TYPE_PSK_MAX,				1,		WPS_LENTYPE_FIX,	WPS_VALTYPE_U8},
	{WPS_TYPE_PUBLIC_KEY,			192,	WPS_LENTYPE_FIX,	WPS_VALTYPE_PTR},
	{WPS_TYPE_RADIO_ENABLED,		1,		WPS_LENTYPE_FIX,	WPS_VALTYPE_BOOL},
	{WPS_TYPE_REBOOT,				1,		WPS_LENTYPE_FIX,	WPS_VALTYPE_BOOL},
	{WPS_TYPE_REGISTRAR_CURRENT,	1,		WPS_LENTYPE_FIX,	WPS_VALTYPE_U8},
	{WPS_TYPE_REGISTRAR_ESTBLSHD,	1,		WPS_LENTYPE_FIX,	WPS_VALTYPE_BOOL},
	{WPS_TYPE_REGISTRAR_LIST,		512,	WPS_LENTYPE_MAX,	WPS_VALTYPE_PTR},
	{WPS_TYPE_REGISTRAR_MAX,		1,		WPS_LENTYPE_FIX,	WPS_VALTYPE_U8},
	{WPS_TYPE_REGISTRAR_NONCE,		16,		WPS_LENTYPE_FIX,	WPS_VALTYPE_PTR},
	{WPS_TYPE_REQ_TYPE,				1,		WPS_LENTYPE_FIX,	WPS_VALTYPE_U8},
	{WPS_TYPE_RESP_TYPE,			1,		WPS_LENTYPE_FIX,	WPS_VALTYPE_U8},
	{WPS_TYPE_RF_BANDS,				1,		WPS_LENTYPE_FIX,	WPS_VALTYPE_U8},
	{WPS_TYPE_R_HASH1,				32,		WPS_LENTYPE_FIX,	WPS_VALTYPE_PTR},
	{WPS_TYPE_R_HASH2,				32,		WPS_LENTYPE_FIX,	WPS_VALTYPE_PTR},
	{WPS_TYPE_R_SNONCE1,			16,		WPS_LENTYPE_FIX,	WPS_VALTYPE_PTR},
	{WPS_TYPE_R_SNONCE2,			16,		WPS_LENTYPE_FIX,	WPS_VALTYPE_PTR},
	{WPS_TYPE_SEL_REGISTRAR,		1,		WPS_LENTYPE_FIX,	WPS_VALTYPE_BOOL},
	{WPS_TYPE_SERIAL_NUM,			32,		WPS_LENTYPE_MAX,	WPS_VALTYPE_PTR},
	{WPS_TYPE_WPSSTATE,				1,		WPS_LENTYPE_FIX,	WPS_VALTYPE_U8},
	{WPS_TYPE_SSID,					32,		WPS_LENTYPE_MAX,	WPS_VALTYPE_PTR},
	{WPS_TYPE_TOT_NETWORKS,			1,		WPS_LENTYPE_FIX,	WPS_VALTYPE_U8},
	{WPS_TYPE_UUID_E,				16,		WPS_LENTYPE_FIX,	WPS_VALTYPE_PTR},
	{WPS_TYPE_UUID_R,				16,		WPS_LENTYPE_FIX,	WPS_VALTYPE_PTR},
	{WPS_TYPE_VENDOR_EXT,			1024,	WPS_LENTYPE_MAX,	WPS_VALTYPE_PTR},
	{WPS_TYPE_VERSION,				1,		WPS_LENTYPE_FIX,	WPS_VALTYPE_U8},
	{WPS_TYPE_X509_CERT_REQ,		0xFFFF,	WPS_LENTYPE_MAX,	WPS_VALTYPE_PTR},
	{WPS_TYPE_X509_CERT,			0xFFFF,	WPS_LENTYPE_MAX,	WPS_VALTYPE_PTR},
	{WPS_TYPE_EAP_IDENTITY,			64,		WPS_LENTYPE_MAX,	WPS_VALTYPE_PTR},
	{WPS_TYPE_MSG_COUNTER,			8,		WPS_LENTYPE_FIX,	WPS_VALTYPE_PTR},
	{WPS_TYPE_PUBKEY_HASH,			20,		WPS_LENTYPE_FIX,	WPS_VALTYPE_PTR},
	{WPS_TYPE_REKEY_KEY,			32,		WPS_LENTYPE_FIX,	WPS_VALTYPE_PTR},
	{WPS_TYPE_KEY_LIFETIME,			4,		WPS_LENTYPE_FIX,	WPS_VALTYPE_U32},
	{WPS_TYPE_PERM_CFG_METHODS,		2,		WPS_LENTYPE_FIX,	WPS_VALTYPE_U16},
	{WPS_TYPE_SEL_REG_CFG_METHODS,	2,		WPS_LENTYPE_FIX,	WPS_VALTYPE_U16},
	{WPS_TYPE_PRIM_DEV_TYPE,		8,		WPS_LENTYPE_FIX,	WPS_VALTYPE_PTR},
	{WPS_TYPE_SEC_DEV_TYPE_LIST,	128,	WPS_LENTYPE_MAX,	WPS_VALTYPE_PTR},
	{WPS_TYPE_PORTABLE_DEVICE,		1,		WPS_LENTYPE_FIX,	WPS_VALTYPE_BOOL},
	{WPS_TYPE_AP_SETUP_LOCKED,		1,		WPS_LENTYPE_FIX,	WPS_VALTYPE_BOOL},
	{WPS_TYPE_APP_EXT,				512,	WPS_LENTYPE_MAX,	WPS_VALTYPE_PTR},
	{WPS_TYPE_EAP_TYPE,				8,		WPS_LENTYPE_MAX,	WPS_VALTYPE_PTR},
	{WPS_TYPE_INIT_VECTOR,			32,		WPS_LENTYPE_FIX,	WPS_VALTYPE_PTR},
	{WPS_TYPE_KEY_PROVIDED_AUTO,	1,		WPS_LENTYPE_FIX,	WPS_VALTYPE_BOOL},
	{WPS_TYPE_8021X_ENABLED,		1,		WPS_LENTYPE_FIX,	WPS_VALTYPE_BOOL},
	{WPS_TYPE_APP_SESS_KEY,			128,	WPS_LENTYPE_MAX,	WPS_VALTYPE_PTR},
	{WPS_TYPE_WEP_TX_KEY,			1,		WPS_LENTYPE_FIX,	WPS_VALTYPE_BOOL},
	{0, 0, 0, 0},
};

static int wps_create_tlv(struct wps_tlv **tlv)
{
	if (!tlv)
		return -1;

	*tlv = (struct wps_tlv *)calloc(1, sizeof(struct wps_tlv));
	if (!*tlv)
		return -1;	/* Memory allocation error */

	return 0;
}

static int wps_destroy_tlv(struct wps_tlv **tlv)
{
	if (!tlv || !*tlv)
		return -1;

	if (WPS_VALTYPE_PTR == (*tlv)->value_type) {
		if ((*tlv)->value.ptr_)
			os_free((*tlv)->value.ptr_);
	}

	os_free(*tlv);
	*tlv = 0;

	return 0;
}

static const struct wps_tlv_set *wps_get_tlv_set(
	const u16 type)
{
	const struct wps_tlv_set *set = wps_tlv_sets;

	while (set->type) {
		if (type == set->type)
			break;
		set++;
	}

	if (!set->type)
		return 0;	/* Invalidate tlv */

	return set;
}

static const struct wps_tlv_set *wps_match_tlv(
	const u16 type, const size_t length)
{
	const struct wps_tlv_set *set = wps_tlv_sets;

	while (set->type) {
		if (type == set->type) {
			if (WPS_LENTYPE_FIX == set->length_type) {
				if (length == set->length)
					break;
			} else if (WPS_LENTYPE_MAX == set->length_type) {
				if (length <= set->length)
					break;
			} else if (WPS_LENTYPE_MIN == set->length_type) {
				if (length < set->length)
					break;
			} else
				return 0;	/* Application Error */
		}
		set++;
	}

	if (!set->type)
		return 0;	/* Invalidate tlv */

	return set;
}


/* Sets **tlv to point to an allocated memory describing the first 
 * TLV in the buffer.
 * Only TLVs of known type are so handled; if the known type is not
 * scalar then additional memory is allocated to hold the copy.
 */
static int wps_get_tlv(const u8 *buf, size_t len,
	struct wps_tlv **tlv)
{
	const u8 *pos = buf;
	const struct wps_tlv_set *set;
	u16 type;
	size_t length;
	Boolean b_value = FALSE;
	u8 u8_value = 0;
	u16 u16_value = 0;
	u32 u32_value = 0;
	u8 *ptr_value = 0;

	if (!buf || 4 >= len || !tlv)
		return -1;

	*tlv = 0;

	type = WPA_GET_BE16(pos);
	length = WPA_GET_BE16(pos+2);

	set = wps_match_tlv(type, length);
	if (!set)
		return -1;	/* Invalidate tlv */

	if (length + 4 > len)
		return -1;	/* Buffer too short */

	switch (set->value_type) {
	case WPS_VALTYPE_BOOL:
		if (length != 1)
			return -1;
		b_value = (Boolean)*(pos+4);
		break;
	case WPS_VALTYPE_U8:
		if (length != 1)
			return -1;
		u8_value = *(pos+4);
		break;
	case WPS_VALTYPE_U16:
		if (length != 2)
			return -1;
		u16_value = WPA_GET_BE16(pos+4);
		break;
	case WPS_VALTYPE_U32:
		if (length != 4)
			return -1;
		u32_value = WPA_GET_BE32(pos+4);
		break;
	case WPS_VALTYPE_PTR:
		ptr_value = (u8 *)os_malloc(length);
		if (!ptr_value)
			return -1; /* Memory allocation error */
		os_memcpy(ptr_value, pos+4, length);
		break;
	default:
		return -1;
	}

	if (0 != wps_create_tlv(tlv)) {
		if (ptr_value)
			os_free(ptr_value);
		return -1; /* Memory allocation error */
	}

	(*tlv)->type = type;
	(*tlv)->length = length;
	(*tlv)->value_type = set->value_type;
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


/* Expands data->tlvs to hold another TLV, which is either copied from the
 * given *tlv (if allocate is true) or else the given *tlv is directly
 * linked in (you give up ownership of it).
 */
static int wps_add_tlv(struct wps_data *data, struct wps_tlv *tlv, Boolean allocate)
{
	const struct wps_tlv_set *set;

	set = wps_match_tlv(tlv->type, tlv->length);
	if (!set)
		return -1;	/* Invalid tlv */

	data->tlvs = (struct wps_tlv **)os_realloc(data->tlvs,
				sizeof(struct wpa_tlv *) * (data->count + 1));

	if (!data->tlvs)
		return -1;	/* Memory allocation error */

	if (allocate) {
		Boolean fail_adding = 1;
		struct wps_tlv * newTlv = NULL;
		do {
			if (wps_create_tlv(&newTlv))
				break;
			os_memcpy(newTlv, tlv, sizeof(struct wps_tlv));
			if (WPS_VALTYPE_PTR == set->value_type) {
				if (tlv->length) {
					newTlv->value.ptr_ = (u8 *)os_malloc(tlv->length);
					if (!newTlv->value.ptr_) {
						os_free(newTlv);
						newTlv = 0;
						break;
					}
					os_memcpy(newTlv->value.ptr_, tlv->value.ptr_, tlv->length);
				} else
					newTlv->value.ptr_ = 0;
			}
			data->tlvs[data->count++] = newTlv;
			fail_adding = 0;
		} while (0);

		if (fail_adding) {
			if (data->count)
				data->tlvs = (struct wps_tlv **)os_realloc(data->tlvs,
							sizeof(struct wpa_tlv *) * data->count);
			else {
				os_free(data->tlvs);
				data->tlvs = 0;
			}
			return -1;
		}
	} else
		data->tlvs[data->count++] = tlv;

	return 0;
}

/* Delete TLV of given type from data->tlvs, or does nothing but
 * return nonzero if not found.
 */
static int wps_del_tlv(struct wps_data *data, const u16 type)
{
	int index, found = 0;

	for ( index = 0; index < data->count; index++) {
	        struct wps_tlv *tlv;
		tlv = data->tlvs[index];
		if (tlv->type == type) {
			wps_destroy_tlv(&tlv);
			found = 1;
			break;
		}
	}

	if (found) {
		for ( index++; index < data->count; index++) {
			data->tlvs[index-1] = data->tlvs[index];
		}

		if (0 < data->count - 1) {
			data->tlvs = (struct wps_tlv **)os_realloc(data->tlvs,
							sizeof(struct wps_tlv *) * (--data->count));
			if (!data->tlvs)
				return -1;
		} else {
			os_free(data->tlvs);
			data->tlvs = 0;
			data->count = 0;
		}
	}

	return found?0:-1;
}


/* Set up new, empty WPS data structure */
int wps_create_wps_data(struct wps_data **data)
{
	if (!data)
		return -1;

	*data = calloc(1, sizeof(struct wps_data));
	if (!*data)
		return -1;

	return 0;
}

/* Free WPS data structure and all linked data 
 */
int wps_destroy_wps_data(struct wps_data **data)
{
	if (!data | !*data)
		return -1;

	while((*data)->count--)
		wps_destroy_tlv(&((*data)->tlvs[(*data)->count]));

	os_free((*data)->tlvs);
	(*data)->tlvs = 0;

	os_free(*data);
	*data = 0;

	return 0;
}

int wps_parse_wps_ie(const u8 *wps_ie, size_t wps_ie_len,
	struct wps_data *data)
{
	const u8 *pos = wps_ie;

	if (!wps_ie || 4 >= wps_ie_len || !data)
		return -1;

	if (pos[0] == GENERIC_INFO_ELEM && pos[1] >= 4 &&
		os_memcmp(pos + 2, "\x00\x50\xf2\x04", 4) == 0) {
		pos += 6;
		return wps_parse_wps_data(pos, wps_ie_len - 6, data);
	}

	return -1;
}

/* Using a buffer of TLVs, add copies thereof into end of data->tlvs.
 * It is an error if a TLV of same type as one found is already in
 * data->tlvs.
 */
int wps_parse_wps_data(const u8 *buf, size_t len,
	struct wps_data *data)
{
	const u8 *pos = buf;
	const u8 *end = buf + len;
	struct wps_tlv *tlv;

	if (!buf || 4 >= len || !data)
		return -1;

	data->count = 0;
	while (pos + 4 < end) {
		if (0 != wps_get_tlv(pos, end - pos, &tlv))
			return -1;

		wps_add_tlv(data, tlv, 0);

		pos += 4 + tlv->length;
	}

	return 0;
}

int wps_write_wps_ie(struct wps_data * data, u8 **ie, size_t *length)
{
	int ret = -1;
	u8 *buf = 0;
	size_t len;

	do {
		if (!data || !ie || !length)
			break;

		*ie = 0;
		*length = 0;

		if (wps_write_wps_data(data, &buf, &len))
			break;

		if ((len + 4) > 255)
			break;

		*ie = (u8 *)os_malloc(len + 6);
		if (!*ie)
			break;
		*(*ie) = GENERIC_INFO_ELEM;
		*((*ie)+1) = (u8)(len + 4);
		os_memcpy((*ie)+2, "\x00\x50\xf2\x04", 4);
		os_memcpy((*ie)+6, buf, len);
		*length = len + 6;

		ret = 0;
	} while (0);

	if (buf)
		os_free(buf);

	if (ret) {
		if (ie && *ie) {
			os_free(*ie);
			*ie = 0;
		}
		if (length)
			*length = 0;
	}

	return ret;
}


/* Convert from data->tlvs to contiguous buffer of TLVs
 */
int wps_write_wps_data(struct wps_data * data, u8 **buf, size_t *length)
{
	Boolean err = 0;
	u8 index;
	u8 *tmp;
	struct wps_tlv *tlv;
	if (!buf | !length)
		return -1;

	*buf = 0;
	*length = 0;

	if (!data)
		return -1;

	for (index = 0; index < data->count && !err; index++) {
		tlv = data->tlvs[index];
		*buf = (u8 *)os_realloc(*buf, *length + 4 + tlv->length);
		if (!*buf) {
			err = -1;
			break;
		}
		tmp = *buf + *length;
		*length += 4 + tlv->length;

		WPA_PUT_BE16(tmp, tlv->type);
		WPA_PUT_BE16(tmp+2, tlv->length);
		switch(tlv->value_type) {
		case WPS_VALTYPE_BOOL:
			*(tmp+4) = (u8)tlv->value.bool_;
			break;
		case WPS_VALTYPE_U8:
			*(tmp+4) = tlv->value.u8_;
			break;
		case WPS_VALTYPE_U16:
			WPA_PUT_BE16(tmp+4, tlv->value.u16_);
			break;
		case WPS_VALTYPE_U32:
			WPA_PUT_BE32(tmp+4, tlv->value.u32_);
			break;
		case WPS_VALTYPE_PTR:
			os_memcpy(tmp+4, tlv->value.ptr_, tlv->length);
			break;
		default:
			err = -1;
			break;
		}
	}

	if (err) {
		os_free(*buf);
		*buf = 0;
		*length = 0;
	}

	return err;
}

int wps_tlv_get_value(const struct wps_tlv *tlv, void *value, size_t *length)
{
	int ret = 0;
	if (!tlv)
		return -1;

	switch (tlv->value_type) {
	case WPS_VALTYPE_BOOL:
		if (value)
			*(Boolean*)value = tlv->value.bool_;
		break;
	case WPS_VALTYPE_U8:
		if (value)
			*(u8 *)value = tlv->value.u8_;
		break;
	case WPS_VALTYPE_U16:
		if (value)
			*(u16 *)value = tlv->value.u16_;
		break;
	case WPS_VALTYPE_U32:
		if (value)
			*(u32 *)value = tlv->value.u32_;
		break;
	case WPS_VALTYPE_PTR:
		if (!length || (*length < tlv->length))
			ret = -1;
		else if (value && tlv->value.ptr_)
			os_memcpy(value, tlv->value.ptr_, tlv->length);
		break;
	default:
		ret = -1;
		break;
	}

	if (length)
		*length = tlv->length;

	if (!value)
		ret = -1;

	return ret;
}

int wps_get_value(const struct wps_data *data, u16 type, void *value, size_t *length)
{
	int ret = 0;
	struct wps_tlv *tlv = 0;
	int i;

	for (i = 0; i < data->count; i++) {
		if ((data->tlvs[i])->type == type) {
			tlv = data->tlvs[i];
			break;
		}
	}

	if (!tlv)
		return -1;

        ret = wps_tlv_get_value(tlv, value, length);
	return ret;
}

/* This function takes a wps data TLV which is already packed with
 *  many TLVs as data for that TLV. We search for network key data
 * and retrive the key length
 */
int wps_get_nw_key_len (const struct wps_data *data, size_t *length)
{
        u8 *tmp,*tmp1;
        u16 *p;
        *length=0;
       
       /* data counrt will be atleast 2 for multiple credentials */
       if ((data->count == 1 || data->count == 2) && data->tlvs[0]->type == WPS_TYPE_CREDENTIAL)
        {
                tmp = data->tlvs[0]->value.ptr_;
                tmp1 = tmp +  data->tlvs[0]->length;
                while (tmp < tmp1)
                {
                        p = (u16 *)tmp;
                        if (p[0] == WPS_TYPE_NW_KEY) {
                                *length = p[1]; // just return length
                                return 0;
                        }
                        tmp = tmp + 4 + p[1];
                }
        }
        /* If not a credential, return NW_KEY_LEN the old way */
        return wps_get_value(data, WPS_TYPE_NW_KEY, NULL, length);
}

/*
 * Historical note: Sony wrote this so that it did NOT copy
 * the data (only the pointer) for WPS_VALTYPE_PTR,
 * and would later free the pointer.
 * I (Ted Merrill) modified this to make a copy (which is later
 * freed as before)...
 */
int wps_set_value(const struct wps_data *data, u16 type, void *value, size_t length)
{
	const struct wps_tlv_set *set = 0;
	struct wps_tlv tlv;

	if (!value)
		return -1;

	set = wps_get_tlv_set(type);
	if (!set)
		return -1;

	tlv.value_type = set->value_type;
	switch (tlv.value_type) {
	case WPS_VALTYPE_BOOL:
		tlv.type = type;
		tlv.length = 1;
		tlv.value.bool_ = *(u8*)value;
		break;
	case WPS_VALTYPE_U8:
		tlv.type = type;
		tlv.length = 1;
		tlv.value.u8_ = *(u8*)value;
		break;
	case WPS_VALTYPE_U16:
		tlv.type = type;
		tlv.length = 2;
		tlv.value.u16_ = *(u16*)value;
		break;
	case WPS_VALTYPE_U32:
		tlv.type = type;
		tlv.length = 4;
		tlv.value.u32_ = *(u16*)value;
		break;
	case WPS_VALTYPE_PTR:
		tlv.type = type;
		tlv.length = length;
		tlv.value.ptr_ = (u8*)value;
                /* Note: wps_add_tlv() copies the value */
		break;
	default:
		return -1;
	}

	return wps_add_tlv((struct wps_data *)data, &tlv, 1);
}

int wps_remove_value(struct wps_data *data, u16 type)
{
	return wps_del_tlv(data, type);
}


u8 wps_get_message_type(u8 *buf, size_t length)
{
	u8 msg_type = -1;
	struct wps_data *wps = 0;

	do {
		if (wps_create_wps_data(&wps))
			break;

		if (wps_parse_wps_data(buf, length, wps))
			break;

		/* Message Type */
		if (wps_get_value(wps, WPS_TYPE_MSG_TYPE, &msg_type, 0))
			break;

	} while (0);

	(void)wps_destroy_wps_data(&wps);

	return msg_type;
}


