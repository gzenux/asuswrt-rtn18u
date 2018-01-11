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
#include "storage.h"

static const struct mib_param_set *apc_match_tlv(
	const u16 type, const size_t length, const struct mib_param_set *parse_table)
{
	const struct mib_param_set *set = parse_table;

	while (set->type) {
		if ((set->type & APCLONE_TYPE_MASK) && 
			(set->type == (type & APCLONE_TYPE_MASK)))
			break;
			
		if (type == set->type) 
			break;
			
		set++;
	}

	if (!set->type)
		return 0;	/* Invalidate tlv */

	return set;
}


static int apc_parse_tlv(const u8 *buf, size_t len,
	struct wps_tlv **tlv, const struct mib_param_set *parse_table)
{
	const u8 *pos = buf;
	const struct mib_param_set *set;
	u16 type;
	size_t length;
	Boolean b_value = FALSE;
	u8 u8_value = 0;
	u16 u16_value = 0;
	u32 u32_value = 0;
	u8 *ptr_value = 0;

	if (!buf || 4 > len || !tlv)
		return -1;

	*tlv = 0;

	type = WPA_GET_BE16(pos);
	length = WPA_GET_BE16(pos+2);

	set = apc_match_tlv(type, length, parse_table);
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

	*tlv = (struct wps_tlv *)calloc(1, sizeof(struct wps_tlv));
	if (0 == *tlv) {
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


static int apc_add_tlv(struct wps_data *data, struct wps_tlv *tlv)
{

	data->tlvs = (struct wps_tlv **)realloc(data->tlvs,
				sizeof(struct wps_tlv *) * (data->count + 1));

	if (!data->tlvs)
		return -1;	/* Memory allocation error */
		data->tlvs[data->count++] = tlv;

	return 0;
}


static int apc_add_wps_data(struct wps_data *data, u16 type, u8 *buf, size_t length)
{

	struct wps_tlv *tlv;
	tlv = (struct wps_tlv *)calloc(1, sizeof(struct wps_tlv));
	if (0 == tlv) {
		free (buf);
		return -1;
	}

	tlv->type = type;
	tlv->length = length;
	tlv->value_type = WPS_VALTYPE_PTR;
	tlv->value.ptr_ = (u8*)buf;
	apc_add_tlv(data,  tlv);

	return 0;
}


static int apc_parse_wps_data(const u8 *buf, size_t len,
	struct wps_data *data, const struct mib_param_set *parse_table)
{
	const u8 *pos = buf;
	const u8 *end = buf + len;
	struct wps_tlv *tlv;

	if (!buf || 4 > len || !data)
		return -1;

	data->count = 0;
	while (pos + 4 <= end) {
		if (0 != apc_parse_tlv(pos, end - pos, &tlv, parse_table))
		{
			dprintf(MSG_ERROR, "Unknown mib type %d, length %d\n",	WPA_GET_BE16(pos), WPA_GET_BE16(pos+2));
			pos += 4 + WPA_GET_BE16(pos+2);
			continue;
		}
		apc_add_tlv(data, tlv);

		pos += 4 + tlv->length;
	}

	return 0;
}


static int apc_get_mib_data(char * path, const struct mib_param_set * mibsets, u8 **buf, size_t *length)
{
	struct wps_data *data;
	int ret;

	if(wps_create_wps_data(&data) < 0)
		return -1;
	
	if(mib_get_object(path, data, mibsets) != 0)
	{
		wps_destroy_wps_data(&data);
		return -1;
	}

	ret = wps_write_wps_data(data, buf, length);
	
	wps_destroy_wps_data(&data);

	return ret;

}



static int apc_set_mib_data(char * path, const struct mib_param_set * mibsets, 
	struct wps_data *data, u16 type, int dyn_obj)
{

	struct wps_data *wlan_data = 0;
	int local_configed = 0;
	int remote_configed = 0;
	size_t local_dlen, remote_dlen;
	u8 *local_buf = NULL;
	u8 *remote_buf = NULL;
	int ret = -1;
	char  mibpath[256];

	remote_buf= calloc(1, 4096);
	remote_dlen= 4096;
	if (!remote_buf)
	{
		dprintf(MSG_ERROR, "Malloc error\n");
		goto failure;
	}

	strcpy(mibpath,path);
	
	if (apc_get_mib_data(mibpath, mibsets, &local_buf, &local_dlen) == 0)
		local_configed = 1;
	
	if (wps_get_value(data, type, remote_buf, &remote_dlen) ==0)
		remote_configed =1;

	if ( !local_configed && !remote_configed){
		goto success;	
	}
	else if ( local_configed &&  !remote_configed ){
		dprintf(MSG_INFO, "Remote doesn't have mib: %s\n",mibpath);
		if (!dyn_obj)
			goto failure;	
		storage_delVAP(atoi (mibpath + strlen(CONFIG_WLAN)));
		goto success;
		
	}
	else if ( !local_configed &&  remote_configed ){
		int obj_index;
		char* path_end;
		dprintf(MSG_INFO, "Local doesn't have mib: %s\n",mibpath);
		if (!dyn_obj)
			goto failure;	

		//strip last '.' and num for path 	
		path_end = strrchr(mibpath,'.');
		if (path_end) 
			*path_end = '\0';
		obj_index = storage_addVAP();

		if (obj_index <=0)
		{
			dprintf(MSG_WARNING, "Can't add object %s\n",mibpath);
			goto failure;
		}
		sprintf(mibpath, "%s.%d", mibpath, obj_index);
		dprintf(MSG_INFO, "bss path :%s\n", mibpath);

	}

	else if (local_dlen == remote_dlen &&
		memcmp(local_buf, remote_buf, local_dlen) == 0)
	{
		dprintf(MSG_INFO, "Mib %s unchanged!\n", path);
		goto success;
	}


	if(wps_create_wps_data(&wlan_data))
		goto failure;	

	if (apc_parse_wps_data((u8*)remote_buf, remote_dlen, wlan_data, mibsets))
	{
		dprintf(MSG_ERROR, "Mib %s parse error\n", mibpath);
		(void)wps_destroy_wps_data(&wlan_data);
		goto failure;	
	}

	mib_set_object(mibpath, wlan_data, mibsets);

	(void)wps_destroy_wps_data(&wlan_data);		

success:
	ret = 0;
	
failure:
	if (local_buf)
		free (local_buf);
	if(remote_buf)
		free (remote_buf);
	return ret;
	
}


int apc_get_wlan_data(struct wps_data *data)
{
	int i;
	char  mibpath[256];
	const struct mib_param_set * mibsets;
	u8 *buf;
	size_t length;


	mibsets = radio_param_sets;
	for (i=0; i < MAX_RADIO_CONFIGURATION; i++)
	{
		sprintf(mibpath,CONFIG_RADIO"%d", i+1);
		if ( apc_get_mib_data(mibpath, mibsets, &buf, &length) == 0)
		{
			apc_add_wps_data(data, APCLONE_TYPE_RADIO|(u8)i, buf, length);
		}

	}

	mibsets = bss_param_sets;
	for (i=0; i < MAX_WLAN_CONFIGURATION; i++)
	{
		sprintf(mibpath,CONFIG_WLAN"%d", i+1);
		if ( apc_get_mib_data(mibpath, mibsets, &buf, &length) == 0)
		{
			apc_add_wps_data(data, APCLONE_TYPE_BSS|(u8)i, buf, length);
		}

	}	


	return 0;
}


int apc_set_wlan_data(struct wps_data *data)
{
	int i;

	char  mibpath[256];
	const struct mib_param_set * mibsets;


	mibsets = radio_param_sets;
	for (i=0; i < MAX_RADIO_CONFIGURATION; i++)
	{
	
		sprintf(mibpath,CONFIG_RADIO"%d", i+1);
		apc_set_mib_data(mibpath,  mibsets, data, APCLONE_TYPE_RADIO|(u8)i, 0);

	}

	mibsets = bss_param_sets;
	for (i=0; i < MAX_WLAN_CONFIGURATION; i++)
	{
		sprintf(mibpath,CONFIG_WLAN"%d", i+1);
		apc_set_mib_data(mibpath,  mibsets, data, APCLONE_TYPE_BSS|(u8)i, 1);
	}	

	return 0;

}


int apc_set_clone_data(const u8 *buf, size_t len)
{

	struct wps_data *data = 0;
	int ret = -1;

	do {
		
		if(wps_create_wps_data(&data))
			break;

		if (apc_parse_wps_data(buf, len, data, clone_param_sets))
		{
			dprintf(MSG_ERROR, "Parse error\n");
			break;
		}

		if(apc_set_wlan_data(data))
			break;
		
		/*other non-wlan paramters can be handled here*/

		ret = 0;

	}while (0);
	
	(void)wps_destroy_wps_data(&data);

	return ret;
}



int apc_get_clone_data(char **buf, size_t* len)
{
	struct wps_data *data = 0;
	int ret = -1;

	do {
		if(wps_create_wps_data(&data))
			break;
		
		if (apc_get_wlan_data(data))
			break;

		/*other non-wlan paramters can be added here*/
		
		if (wps_write_wps_data(data, (u8**)buf, len))
			break;

		ret = 0;

	} while (0);

	(void)wps_destroy_wps_data(&data);

	return ret;

}




