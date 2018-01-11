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
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/un.h>
#include <signal.h>
#include <sys/types.h>
#include <errno.h>
#include <ctype.h>
#include <time.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/uio.h>
#include <sys/time.h>
#include <net/if.h>
#include <sys/wait.h>


#include "wsplcd.h"
#include "wps_config.h"
#include "eloop.h"
#include "legacy_ap.h"
#include "mib_wps.h"

#include "compat.h"
#ifdef NOT_UMAC
#include "net80211/ieee80211.h"
#include "net80211/ieee80211_crypto.h"
#include "net80211/ieee80211_ioctl.h"
#else
#include "ieee80211_external.h"
#endif

#define WPS_WORKAROUNDS

static int wpa_vap_create( const char *devname, const char *ifname)
{   
    struct ifreq ifr;
    struct ieee80211_clone_params cp;

    int sock = -1;

    sock = socket(AF_INET, SOCK_DGRAM, 0);	
    if(sock < 0)
        return -1;

    memset(&ifr, 0, sizeof(ifr));
    memset(&cp, 0, sizeof(cp));
    
    strlcpy(ifr.ifr_name, ifname, IFNAMSIZ);
    ioctl(sock, SIOC80211IFDESTROY, &ifr);

    memset(&ifr, 0, sizeof(ifr));

    strlcpy(cp.icp_name, ifname, IFNAMSIZ);
    cp.icp_opmode = IEEE80211_M_STA;
    cp.icp_flags = IEEE80211_CLONE_BSSID;
    cp.icp_flags |= IEEE80211_NO_STABEACONS;

    strlcpy(ifr.ifr_name, devname, IFNAMSIZ);
    
  
    ifr.ifr_data = (void *) &cp;
    
    if (ioctl(sock, SIOC80211IFCREATE, &ifr) < 0) {
        close(sock);
        return -1;
    }
    
    close(sock);
    return 0;
}


static int wpa_vap_destroy(const char *ifname)
{
    struct ifreq ifr;
    int sock = -1;

    sock = socket(AF_INET, SOCK_DGRAM, 0);	
    if(sock < 0)
        return -1;    
    
    memset(&ifr, 0, sizeof(ifr));
    strlcpy(ifr.ifr_name, ifname, IFNAMSIZ);
    if (ioctl(sock, SIOC80211IFDESTROY, &ifr) < 0) {
        close(sock);
        return -1;
    }

    close(sock);
    return 0;	
}


static int wpa_process_start(struct wpa_sup* wpas)
{
    int pid;
    char* argv[10];

    argv[0] = "wpa_supplicant";
    argv[1] = "-i";
    argv[2] = VAPNAME;
    argv[3] = "-c";
    argv[4] = "/etc/"VAPNAME".conf";
    argv[5] = "-Dathr";
    argv[6] = NULL;

    pid = fork();
	
    if (pid ==0)
    {
        execvp(argv[0], (void *)argv);
        fprintf(stderr, "Failed to exec %s errno %d<<\n", argv[0], errno);
    }

    wpas->pid = pid;
    dprintf(MSG_INFO, "Start wpa_supplicant with pid %d \n", pid);	
    return pid;	
}


static void wpa_process_stop(struct wpa_sup* wpas)
{
    int status;
    int pid;
	
    kill(wpas->pid, SIGKILL);

    for (;;) {
        errno = 0;
        pid = waitpid(wpas->pid, &status, 0);
        if (errno == EINTR)
            continue;
        break;
    }	
    dprintf(MSG_INFO, "wpa_supplicant pid %d[%d]  stopped, status %d\n", wpas->pid, pid, status);		
}


static int wpa_ctrl_open(struct wpa_sup* wpas)
{
    int sock;
	
    sock = socket(PF_UNIX, SOCK_DGRAM, 0);
    if (sock < 0) {
        return -1;
    }

    wpas->ctrl_sock = sock;

    wpas->dest_addr.sun_family = AF_UNIX;
    snprintf(wpas->dest_addr.sun_path, sizeof(wpas->dest_addr.sun_path),
                "%s/%s", "/var/run/wpa_supplicant",VAPNAME);

    wpas->local_addr.sun_family = AF_UNIX;
    snprintf(wpas->local_addr.sun_path, sizeof(wpas->local_addr.sun_path) , 
                "/var/run/legacy.athx");	

    unlink(wpas->local_addr.sun_path);
    if (bind(wpas->ctrl_sock, (struct sockaddr *) &wpas->local_addr, 
            sizeof(wpas->local_addr)) < 0) 
    {
        dprintf(MSG_ERROR,  "ERR : Bind to wpa_supplicant ctrl innterface  failed\n");
        goto fail;
    }

    dprintf(MSG_INFO, "Open CTRL socket with path %s \n", wpas->dest_addr.sun_path);	

    return 0;	

fail:

    close(wpas->ctrl_sock);	
    wpas->ctrl_sock = 0;    	
    return -1;
}


static void wpa_ctrl_close(struct wpa_sup* wpas)
{
    if (wpas->ctrl_sock > 0)
        close(wpas->ctrl_sock);
    wpas->ctrl_sock = -1;	
}


static int wpa_ctrl_exec(struct wpa_sup* wpas, char *command, int cmdlen)
{

    int errn;
    if ((errn = send(wpas->ctrl_sock, (const char*)command, (size_t)cmdlen, 0)) < 0) {
        dprintf(MSG_ERROR, "ERR , errn:%d: Fail to send command %s to wpa_supplicant",
            errn, command);

        return -1;
    }

    dprintf(MSG_DEBUG, "Send cmd <%s> OK\n", command);	
    return 0;
}



static void wpa_ctrl_attach(void *eloop_ctx, void *timeout_ctx)
{
    struct wpa_sup* wpas = (struct wpa_sup*)eloop_ctx;

    if (connect(wpas->ctrl_sock, (struct sockaddr *) &wpas->dest_addr, sizeof(wpas->dest_addr)) < 0) 
    {
        dprintf(MSG_ERROR,  "ERR : Connect to wpa_supplicant ctrl innterface  failed\n");
        goto fail;        
    }   

    if (wpa_ctrl_exec(wpas, "ATTACH", 6) <0)
    {
        dprintf(MSG_INFO, "CTRL socket attach fails\n");
        goto fail;      
    }

    if (wpa_ctrl_exec(wpas, "WPS_PBC", 7) <0)
    {
        dprintf(MSG_INFO, "CTRL socket virtual PBC fails\n");
        return;
    }

    dprintf(MSG_INFO, "CTRL connection OK\n");	
    return ;	

fail:
    dprintf(MSG_INFO, "CTRL attach fails, retry later\n");	
    eloop_register_timeout(1, 0, wpa_ctrl_attach, wpas, NULL);		
	
}


static void wpa_ctrl_detach(struct wpa_sup* wpas)
{
     if (wpa_ctrl_exec(wpas, "DETACH", 6) <0)
    {
        dprintf(MSG_INFO, "CTRL socket detach fails\n");
       
    }

}

static void wpa_ctrl_keeplive(void *eloop_ctx, void *timeout_ctx)
{
    struct wpa_sup* wpas = (struct wpa_sup*)eloop_ctx;
    if (wpa_ctrl_exec(wpas, "PING", 4) <0)
    {
        dprintf(MSG_INFO, "CTRL socket keeplive fails\n");
        return;
    }
	
    eloop_register_timeout(5, 0, wpa_ctrl_keeplive, wpas, NULL);	

}

int wpa_ctrl_cred_verify(unsigned char* buf, int* msglen)
{
    const u8 *pos, *end;
    u16 type, len;
    u16 prev_type = 0;
#ifdef WPS_WORKAROUNDS	
    u8 buffix[1024] = {0};
    u8 *posfix = buffix;       	
#endif

    pos = buf;
    end = pos + *msglen;

    while (pos < end) {
        if (end - pos < 4) {
            dprintf(MSG_ERROR, "WPS: Invalid message - %lu bytes remaining\n",
                (unsigned long) (end - pos));
            return -1;
        }

        type = WPA_GET_BE16(pos);
        pos += 2;
        len = WPA_GET_BE16(pos);
        pos += 2;
        dprintf(MSG_DEBUG,  "WPS: attr type=0x%x len=%u\n", type, len);
        if (len > end - pos) {
            dprintf(MSG_INFO, "WPS: Attribute overflow\n");
#ifdef WPS_WORKAROUNDS
            /*
             * Some deployed APs seem to have a bug in encoding of
             * Network Key attribute in the Credential attribute
             * where they add an extra octet after the Network Key
             * attribute at least when open network is being
             * provisioned.
             */
            if ((type & 0xff00) != 0x1000 &&
                prev_type == WPS_TYPE_NW_KEY) {
                dprintf(MSG_INFO, "WPS: Workaround - try "
                    "to skip unexpected octet after "
                    "Network Key\n");
                pos -= 3;
                continue;
            }
#endif /* WPS_WORKAROUNDS */
            return -1;
        }

#ifdef WPS_WORKAROUNDS
        memcpy(posfix, pos-4, len+4);
        posfix = posfix + 4 + len;
#endif
			
        prev_type = type;
        pos += len;
    }

#ifdef WPS_WORKAROUNDS
    if (posfix -buffix != *msglen)
    {
        *msglen = posfix - buffix; 
        memcpy(buf, buffix, *msglen);
    }
#endif

    return 0;
}


void wpa_ctrl_parse_cred(struct wpa_sup* wpas, char* cred, int len)
{

    unsigned char buf[1024];	
    struct wps_data *data = 0;	
    int itlv;	

    dprintf(MSG_INFO, "Receive cred len %d\n", len);
    memset(&wpas->cred, 0 ,sizeof(wpas->cred));
    hexstr2bin(cred, buf, len);

    len = len /2 -4;
    if (wpa_ctrl_cred_verify(buf + 4, &len)!= 0)
    {
        return;
    }

    if(wps_create_wps_data(&data))
        return;

    if (wps_parse_wps_data(buf+4, len , data))
    {
        dprintf(MSG_ERROR, "Cred parse error\n");
        goto fail;
    }

    for (itlv = 0; itlv < data->count; itlv++) {
        struct wps_tlv *tlv = data->tlvs[itlv];
        if (tlv == NULL)
            break;
        switch (tlv->type) {
            case WPS_TYPE_SSID:
                wpas->cred.ssid_len = sizeof(wpas->cred.ssid) -1 ;   /* max */
                if (wps_tlv_get_value(tlv, wpas->cred.ssid, &wpas->cred.ssid_len) < 0)
                {
                    dprintf(MSG_ERROR, "Invalid SSID length\n");
                    goto fail;
                }
                wpas->cred.ssid[wpas->cred.ssid_len] = '\0';		
                dprintf(MSG_INFO, "Receive cred SSID: %s,length: %d\n", wpas->cred.ssid, wpas->cred.ssid_len);				
                break;
				
            case WPS_TYPE_AUTH_TYPE:
                wpas->cred.auth_type = tlv->value.u16_;
                dprintf(MSG_INFO, "Receive cred AUTH: 0x%04x\n", wpas->cred.auth_type);
                break;
				
            case WPS_TYPE_ENCR_TYPE:
                wpas->cred.encr_type = tlv->value.u16_;
                dprintf(MSG_INFO, "Receive cred ENCR: 0x%04x\n", wpas->cred.encr_type);
                break;
				
            case WPS_TYPE_NW_KEY_INDEX:
                wpas->cred.key_idx = tlv->value.u8_;
                if ((wpas->cred.key_idx< 1) || (wpas->cred.key_idx> 4)) {
                    dprintf(MSG_INFO, "Invalid KEY Index: 0x%02x\n", wpas->cred.key_idx);					
                    wpas->cred.key_idx = 1;
                }
                dprintf(MSG_INFO, "Receive cred KEY Index: 0x%02x\n", wpas->cred.key_idx);				
                break;
				
            case WPS_TYPE_NW_KEY:
                wpas->cred.key_len = sizeof(wpas->cred.key) -1;
                if (wps_tlv_get_value(tlv, wpas->cred.key, &wpas->cred.key_len) < 0)
                {
                    dprintf(MSG_ERROR, "Invalid KEY length\n");
                    goto fail;
                }
                wpas->cred.key[wpas->cred.key_len] =  '\0';					
                dprintf(MSG_INFO, "Receive cred KEY: %s, length: %d\n", wpas->cred.key, wpas->cred.key_len);				
                break;
				
            default:
                dprintf(MSG_INFO, "Unknown credential type: 0x%04X\n", tlv->type);	
				
        }

    }

fail:

(void)wps_destroy_wps_data(&data);


}


void wpa_ctrl_get_msg(int sock, void *eloop_ctx, void *sock_ctx)
{
	char buf[2048];
	int len;
	struct sockaddr_un from;
	socklen_t fromlen;
	char *pos;
	char *end;

	struct wpa_sup* wpas = (struct wpa_sup* )eloop_ctx;

	fromlen = sizeof(from);
	len = recvfrom(sock, buf, sizeof(buf), 0,
			(struct sockaddr *) &from, &fromlen);
	if (len < 0) {
		perror("recvfrom (unix)");
		return ;
	}
      dprintf(MSG_DEBUG, "get ctrl msg %d\n", len); 
      buf[len] = '\0';  
      dprintf(MSG_DEBUG, "[%s]\n", buf); 

    pos = buf;
    end = buf + len;
    if (*pos == '<') {
    /*skip priority*/
        pos = strchr(pos, '>');
        if (pos)
            pos ++;
        else
            pos = buf;        
    }

    if (strncmp(pos, "FAIL", 4) == 0)
    {
        return;
    }
    else if (strncmp(pos, "OK", 2) == 0)
    {
        return;
    }	
    else if (strncmp(pos, "PONG", 4) == 0)
    {
        return;
    }
    else if (strncmp(pos, "WPS-CRED-RECEIVED", strlen("WPS-CRED-RECEIVED")) ==0)
    {
        pos +=  strlen("WPS-CRED-RECEIVED")+1;
        wpa_ctrl_parse_cred(wpas, pos, end - pos);
        return;
    }
    else if (strncmp(pos, "WPS-SUCCESS", strlen("WPS-SUCCESS")) == 0)
    {
        dprintf(MSG_INFO, "WPS-SUCCESS, waiting session finishing\n");   
        wpas->success = 1;	
    }
    else if (strncmp(pos, "CTRL-EVENT-EAP-FAILURE", strlen("CTRL-EVENT-EAP-FAILURE")) == 0)
    {
        dprintf(MSG_INFO, "CTRL-EVENT-EAP-FAILURE, WPS session ending\n");   
        if (wpas->success)
        {
            legacy_apcloning_stop(wpas);
            if (mib_update_credential(&wpas->cred) < 0)
                dprintf(MSG_ERROR, "Credential update fails\n");		
        }
    }
    else
    {
        dprintf(MSG_INFO, "Message not handled[%s]\n", pos); 
        return;
    }
      	  
}	

static void legacy_apcloning_timeout(void *eloop_ctx, void *timeout_ctx)
{
    struct wpa_sup* wpas = (struct wpa_sup*)eloop_ctx;
    dprintf(MSG_INFO, "Legacy AP cloning timeout\n");  		
    legacy_apcloning_stop(wpas);	
	
}


void legacy_apcloning_start(struct wpa_sup* wpas)
{

    if (!wpas)
        return;

    if (wpas->running)
        return;
	
    if (wpa_vap_create(RADIONAME, VAPNAME) < 0)
    {
        dprintf(MSG_ERROR, "VAP create fails\n");
        return;
    }
	
    wpa_process_start(wpas);

    if (wpas->pid == 0)
    {
        dprintf(MSG_ERROR, "Process fork fails\n");
        return;        
    }
	
    if (wpa_ctrl_open(wpas) < 0)
    {
        dprintf(MSG_ERROR, "CTRL interface fails\n");
        return;
    }


    eloop_register_timeout(wpas->timeout, 0, legacy_apcloning_timeout, wpas, NULL);	
    eloop_register_timeout(1, 0, wpa_ctrl_attach, wpas, NULL);
    eloop_register_timeout(5, 0, wpa_ctrl_keeplive, wpas, NULL);		
    eloop_register_read_sock(wpas->ctrl_sock, wpa_ctrl_get_msg, wpas, NULL);

    wpas->running = 1;
}

void legacy_apcloning_stop(struct wpa_sup* wpas)
{

    eloop_unregister_read_sock(wpas->ctrl_sock);
    eloop_cancel_timeout(legacy_apcloning_timeout, wpas, NULL);
    eloop_cancel_timeout(wpa_ctrl_attach, wpas, NULL);	
    eloop_cancel_timeout(wpa_ctrl_keeplive, wpas, NULL);	

    wpa_ctrl_detach(wpas);
    wpa_ctrl_close(wpas);
    wpa_process_stop(wpas);
    wpa_vap_destroy(VAPNAME);
    wpas->running = 0;
    wpas->success = 0;
}


int legacy_apcloning_init(wsplcd_data_t* wspd)
{
    struct wpa_sup* wpas;
    wpas = malloc(sizeof (struct wpa_sup));
	
    if (wpas == NULL)
    {
        dprintf(MSG_ERROR,  "ERR : legacy_apcloning_init malloc");
        return -1;
    }
    memset(wpas, 0, sizeof(struct wpa_sup));

    wpas->timeout = wspd->wsplcConfig.clone_timeout;
    wspd->wpas = wpas;
    return 0;	
}
