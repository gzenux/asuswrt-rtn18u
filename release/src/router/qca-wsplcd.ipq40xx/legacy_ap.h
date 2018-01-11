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
 * Author: Zhi Chen, November, 2011 zhichen@atheros.com
 */
#ifndef _LEGACY_AP
#define _LEGACY_AP

#include <sys/un.h>

struct _wsplcd_data;

#define RADIONAME "wifi0"
#define VAPNAME "athx100"


struct wps_credential {
    u8 ssid[33];
    size_t ssid_len;
    u16 auth_type;
    u16 encr_type;
    u8 key_idx;
    u8 key[65];
    size_t key_len;
}l;	
	
	

struct wpa_sup{
    int pid;
    int ctrl_sock;
    struct sockaddr_un dest_addr;
    struct sockaddr_un local_addr;

    int timeout;
    int running;
    int success;	
    struct wps_credential cred;	
};


int legacy_apcloning_init(struct _wsplcd_data* wspd);
void legacy_apcloning_start(struct wpa_sup* wpas);
void legacy_apcloning_stop(struct wpa_sup* wpas);

#endif
 
