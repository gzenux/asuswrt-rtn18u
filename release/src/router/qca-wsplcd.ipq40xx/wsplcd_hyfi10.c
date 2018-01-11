/* @File: wsplcd_hyfi10.c
 *  
 * @Notes:
 *
 * Copyright (c) 2011-2012 Qualcomm Atheros, Inc.
 * Qualcomm Atheros Confidential and Proprietary. 
 * All rights reserved.
 *
 */


#include "wsplcd.h"
#include "apclone.h"
#include "eap_wps.h"
#include "eloop.h"
#include "legacy_ap.h"

int wsplc_disable_cloning(wsplcd_data_t* wspd)
{
    if (wspd->mode == MODE_NONE)
        return 0;

    wsplc_stop_cloning(wspd);
    wspd->mode = MODE_NONE;
    return 0; 
}

static void wsplc_cloning_timeout(void *eloop_ctx, void *timeout_ctx)
{
    wsplcd_data_t* wspd= (wsplcd_data_t*)eloop_ctx;
    wspd->clone_running = 0;
    dprintf(MSG_INFO, "Cloning timeout, disable cloning\n");	

    if (wspd->mode == MODE_CLIENT )
    {
        struct eap_session *sess, *next;
        sess = wspd->sess_list;
        while (sess)
        {
	     next = sess->next;
	     if (sess->state <= WSPLC_EAPOL_START_SENT) 
	         eap_wps_del_session(sess);
	     sess = next;
        }
    }

    if (wspd ->sess_list)
    {
	dprintf(MSG_INFO, "Session still in progress\n");	
    }	
}


int wsplc_is_cloning_runnig(wsplcd_data_t* wspd)
{
    return (wspd->clone_running == 1);
}

int wsplc_reset_cloning_timeout(wsplcd_data_t* wspd)
{
    eloop_cancel_timeout(wsplc_cloning_timeout, wspd, NULL);
    eloop_register_timeout(wspd->wsplcConfig.clone_timeout, 0, 
		wsplc_cloning_timeout, wspd, NULL);	

    dprintf(MSG_INFO, "Cloning timeout reset  to %d sec\n",
		wspd->wsplcConfig.clone_timeout);	

    if (wspd->mode == MODE_CLIENT 
		&& wspd->sess_list == NULL)
    {
	struct eap_session* sess = eap_wps_new_session(wspd);
	if (!sess)
		return -1;
	eap_wps_start_session(sess);
	
    }		
    return 0;
}

int wsplc_start_cloning_client(wsplcd_data_t* wspd)
{
    wspd->clone_running = 1;

    eloop_register_timeout(wspd->wsplcConfig.clone_timeout, 0, 
		wsplc_cloning_timeout, wspd, NULL);
    dprintf(MSG_INFO, "Cloning client enabled in %d sec\n",
		wspd->wsplcConfig.clone_timeout);	

    if (wspd->sess_list == NULL)
    {
	struct eap_session* sess = eap_wps_new_session(wspd);
	if (!sess)
		return -1;
	eap_wps_start_session(sess);
	
    }
	
    return 0;

}


int wsplc_start_cloning_server(wsplcd_data_t* wspd)
{

    wspd->clone_running = 1;

    eloop_register_timeout(wspd->wsplcConfig.clone_timeout, 0, 
		wsplc_cloning_timeout, wspd, NULL);
	
    dprintf(MSG_INFO, "Cloning server enabled in %d sec\n",
		wspd->wsplcConfig.clone_timeout);

    return 0;    	
}


int wsplc_stop_cloning(wsplcd_data_t* wspd)
{
    struct eap_session* sess;

    if (wspd->mode == MODE_SERVER &&
		wspd->wsplcConfig.button_mode == WSPLC_ONE_BUTTON)
	return 0;
	
    wspd->clone_running = 0;

    eloop_cancel_timeout(wsplc_cloning_timeout, wspd, NULL);
	
    dprintf(MSG_INFO, "Cloning %s disabled\n", 
		wspd->mode == MODE_SERVER? "server":"client");

    sess = wspd->sess_list;
    while (sess)
    {
        eap_wps_del_session(sess);
	 sess = wspd->sess_list;
    }

    return 0;    	
}

void wsplc_process_button_event(wsplcd_data_t* wspd)
{
    if (wspd->mode == MODE_CLIENT) {
	if (wsplc_is_cloning_runnig(wspd))
		wsplc_reset_cloning_timeout(wspd);
	else
		wsplc_start_cloning_client(wspd);							
				
     } 
    else if (wspd->mode == MODE_SERVER){
        if (wspd->wsplcConfig.button_mode == WSPLC_ONE_BUTTON)
        {
             dprintf(MSG_INFO, "Server runs in One Button mode, cloning always enabled\n");
		return;
        }
	if (wsplc_is_cloning_runnig(wspd))
		wsplc_reset_cloning_timeout(wspd);
	else
		wsplc_start_cloning_server(wspd);

   }
}


void
wsplc_pushbutton_activated(wsplcd_data_t* wspd, int duration)
{
    static struct os_time first_push_tv = {0,0};
    static int push_times = 0;
    struct os_time now,diff;

    if (wspd->mode != MODE_SERVER && wspd->mode != MODE_CLIENT)
        return;

    if (duration >= PUSH_BUTTON_IGNORE_DUR)
        return;

    if (wspd->mode == MODE_SERVER)
    {
        wsplc_process_button_event(wspd);
        return;   
    }

    //wsplc or legacy ap cloning
    /*5 times short push in 3 second for legacy ap cloning*/
    os_get_time(&now);
    if (first_push_tv.sec == 0 && first_push_tv.usec == 0)
    {
        first_push_tv.sec = now.sec;
        first_push_tv.usec = now.usec;
    }

    os_time_sub(&now, &first_push_tv, &diff);
    if (duration >= 1)
    {
        first_push_tv.sec = 0;
        first_push_tv.usec = 0; 
        push_times = 0;                                
    }
    else if (diff.sec >= 3)
    {
        first_push_tv.sec = now.sec;
        first_push_tv.usec = now.usec; 
        push_times = 1;
    }
    else
    {
        push_times ++;
        if (push_times > 1)
            dprintf(MSG_DEBUG, "Consecutive short pushes in 3 seconds, times %d \n", push_times);	
    }	

    if (push_times >= 5)
    {
        dprintf(MSG_INFO, "Consecutive 5 short pushes, start Legacy AP cloning\n");	
        first_push_tv.sec = 0;
        first_push_tv.usec = 0; 
        push_times = 0;
                         
        if (wsplc_is_cloning_runnig(wspd))
            wsplc_stop_cloning(wspd);

        legacy_apcloning_start(wspd->wpas);							  
    }
    else if (wspd->wpas->running)
    {
        dprintf(MSG_DEBUG, "Legacy AP cloning is running, ignore single short push\n");
    }
    else
    {
        wsplc_process_button_event(wspd);
    }

}



void wsplc_get_l2_pkt(int sock, void *eloop_ctx, void *sock_ctx)
{
	unsigned char buf[1514];
	int res,i;
	struct sockaddr_ll ll;
	socklen_t fromlen;
	wsplcd_data_t* wspd = (wsplcd_data_t* )eloop_ctx;

	memset(&ll, 0, sizeof(ll));
	fromlen = sizeof(ll);
	res = recvfrom(sock, buf, sizeof(buf), 0, (struct sockaddr *) &ll,
		       &fromlen);
	if (res < 0) {
		perror("wsplcd l2_packet_receive - recvfrom");
		return;
	}
    		
	dprintf(MSG_DEBUG, "Rcvd pkt  with len %d\n", res);
	for (i=0; i < res; i++){
		dprintf(MSG_MSGDUMP, "%02X ", buf[i]);
		if (((i+1) % 16) == 0){
			dprintf(MSG_MSGDUMP, "\n");
		}
	}
	dprintf(MSG_MSGDUMP, "\n");

	eap_wps_process_eapol(wspd, buf, res);
    
}



int wsplc_init_l2_skt(char *ifname)
{
    struct ifreq ifr;
    struct sockaddr_ll ll;
    struct packet_mreq mreq;	
    u8 multicastgroup_eapol[6] = EAPOL_MULTICAST_GROUP;	
    int sock;	

    sock= socket(PF_PACKET, SOCK_RAW, htons(ETH_P_EAPOL));
    if (sock < 0) {
        perror("socket(PF_PACKET)");
        return -1;
    }

    memset(&ifr, 0, sizeof(struct ifreq));
    memcpy(ifr.ifr_name, ifname, IFNAMSIZ);
    if (ioctl(sock, SIOCGIFINDEX, &ifr) < 0) {
        perror("ioctl[SIOCGIFINDEX]");
        close(sock);
        return -1;
    }


    memset(&ll, 0, sizeof(ll));
    ll.sll_family = PF_PACKET;
    ll.sll_ifindex = ifr.ifr_ifindex;
    ll.sll_protocol = htons(ETH_P_EAPOL);
    if (bind(sock, (struct sockaddr *) &ll, sizeof(ll)) < 0) {
        perror("bind[PF_PACKET]");
        close(sock);
        return -1;
    }

    memset(&mreq, 0, sizeof(mreq));
    mreq.mr_ifindex = ifr.ifr_ifindex;
    mreq.mr_type = PACKET_MR_MULTICAST;
    mreq.mr_alen = 6;
    memcpy(mreq.mr_address,multicastgroup_eapol , mreq.mr_alen);

    if (setsockopt(sock, SOL_PACKET, PACKET_ADD_MEMBERSHIP, &mreq,
        sizeof(mreq)) < 0) {
        perror("setsockopt[SOL_SOCKET,PACKET_ADD_MEMBERSHIP]");
        close(sock);		
        return -1;
    }

    return sock;
}

int wsplc_init_sockets(wsplcd_data_t* wspd)
{
    
    struct ifreq ifr;
    int sock = -1;
  
    // get the interface mac
    sock = socket(PF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        perror("socket[PF_INET,SOCK_DGRAM]");
        return -1;
    }
    
    memset(&ifr, 0, sizeof(ifr));
    memcpy(ifr.ifr_name, wspd->txIfName, sizeof(wspd->txIfName));

    if (ioctl(sock, SIOCGIFHWADDR, &ifr) < 0) {
        perror("ioctl[SIOCGIFHWADDR]");
        close(sock);
        return -1;
    }

    memcpy(wspd->own_addr, ifr.ifr_hwaddr.sa_data, ETH_ALEN);
    dprintf(MSG_DEBUG, "Txif mac addr = %02X-%02X-%02X-%02X-%02X-%02X\n",
            wspd->own_addr[0], wspd->own_addr[1], wspd->own_addr[2],
            wspd->own_addr[3], wspd->own_addr[4], wspd->own_addr[5]);
	memset(&ifr, 0, sizeof(ifr));
	memcpy(ifr.ifr_name, wspd->txIfName, sizeof(wspd->txIfName));
	if (ioctl(sock, SIOCGIFINDEX, &ifr) != 0) {
		perror("ioctl(SIOCGIFINDEX)");
		close (sock);
		return -1;
	}

    dprintf(MSG_DEBUG,"TX ifname %s, ifindex %d\n", wspd->txIfName, ifr.ifr_ifindex);

    wspd->txIfIndex = ifr.ifr_ifindex;

    close (sock);



    wspd->txSkt = wsplc_init_l2_skt(wspd->txIfName);
	
    if (wspd->txSkt < 0) {
        dprintf(MSG_ERROR, "Failed to L2 Pkt Txsocket\n");
        goto fail;
    }

    wspd->rxSkt = wsplc_init_l2_skt(wspd->rxIfName);
    if (wspd->rxSkt < 0) {
        dprintf(MSG_ERROR, "Failed to L2 Pkt Rxsocket\n");
        goto fail;
    }

	
    eloop_register_read_sock(wspd->txSkt, wsplc_get_l2_pkt, wspd, NULL);	
    eloop_register_read_sock(wspd->rxSkt, wsplc_get_l2_pkt, wspd, NULL);
	
    return 0;

fail:
	
    if (wspd->txSkt > 0)
        close (wspd->txSkt);	

    if (wspd->rxSkt > 0)
        close (wspd->rxSkt);	

    return -1;
}


int wsplc_deinit_sockets(wsplcd_data_t* wspd)
{

    if (wspd->txSkt > 0)
        close (wspd->txSkt);	

    if (wspd->rxSkt > 0)
        close (wspd->rxSkt);	
	
    return 0;
}


void wsplcd_hyfi10_dump(wsplcd_data_t* wspd)
{
    WSPLCD_CONFIG   *pConfig = &wspd->wsplcConfig;		

    dprintf(MSG_DEBUG, "Hyfi 1.0 AP Clonining configuration dump begin\n");
    if (wspd->mode == MODE_CLIENT)
    {
        dprintf(MSG_DEBUG, "Mode: client\n");
    }
    else if(wspd->mode == MODE_SERVER)
    {
        dprintf(MSG_DEBUG, "Mode: server\n");
        dprintf(MSG_DEBUG, "Button Mode:%d\n", pConfig->button_mode);		
    }
    else
    {
        dprintf(MSG_DEBUG, "Mode: unknown\n");
    }

    dprintf(MSG_DEBUG, "TX Interface: %s\n", wspd->txIfName);
    dprintf(MSG_DEBUG, "RX Interface: %s\n", wspd->rxIfName);
    dprintf(MSG_DEBUG, "Debug Level: %d\n", pConfig->debug_level);

    dprintf(MSG_DEBUG, "Clone Timeout: %d\n", pConfig->clone_timeout);
    dprintf(MSG_DEBUG, "Walk Timeout: %d\n", pConfig->walk_timeout);	
    dprintf(MSG_DEBUG, "Repeat Timeout: %d\n", pConfig->repeat_timeout);	
    dprintf(MSG_DEBUG, "Internal Timeout: %d\n", pConfig->internal_timeout);		

    dprintf(MSG_DEBUG, "Configuration dump end\n");	

}

int wsplcd_hyfi10_init(wsplcd_data_t* wspd)
{
    WSPLCD_CONFIG *pConfig = &wspd->wsplcConfig;
    os_memcpy(pConfig->ssid, "wsplc_network", os_strlen("wsplc_network"));
    pConfig->ssid_len   = os_strlen("wsplc_network");
    pConfig->auth       = WPS_AUTHTYPE_WPA2PSK;
    pConfig->encr       = WPS_ENCRTYPE_AES;
    os_memcpy(pConfig->passphrase, "wsplc_pp", os_strlen("wsplc_pp"));
    pConfig->passphraseLen = os_strlen("wsplc_pp");

    strcpy(wspd->txIfName, WSPLC_EAPMSG_TXIFNAME);
    strcpy(wspd->rxIfName, WSPLC_EAPMSG_RXIFNAME);
    wspd->mode = MODE_SERVER;
	
    pConfig->clone_timeout = WSPLC_CLONE_TIMEOUT;
    pConfig->walk_timeout  = WSPLC_WALK_TIMEOUT;
    pConfig->repeat_timeout = WSPLC_REPEAT_TIMEOUT;
    pConfig->internal_timeout = WSPLC_INTERNAL_TIMEOUT;
    pConfig->button_mode= WSPLC_ONE_BUTTON;	
    pConfig->debug_level = MSG_INFO;
   
    return 0;
}

int wsplcd_hyfi10_startup(wsplcd_data_t* wspd)
{
    /*Get shared config from hyfi 2.0*/
    apacHyfi20IF_t *pIF = HYFI10ToHYFI20(wspd)->hyif;
    int j; 

    for (j = 0; j < APAC_MAXNUM_HYIF; j++) {
        if (pIF[j].valid && 
                pIF[j].mediaType == APAC_MEDIATYPE_PLC) {
            memcpy(wspd->txIfName, pIF[j].ifName, IFNAMSIZ);
            break;
        }
    }
    memcpy(wspd->rxIfName,
        HYFI10ToHYFI20(wspd)->bridge.ifName, IFNAMSIZ);

    if (HYFI10ToHYFI20(wspd)->config.role == APAC_REGISTRAR)
        wspd->mode = MODE_SERVER;
    else  if (HYFI10ToHYFI20(wspd)->config.role == APAC_ENROLLEE)
        wspd->mode = MODE_CLIENT;
    else
        wspd->mode = MODE_NONE;

    wsplcd_hyfi10_dump(wspd);
    /*One button mode of server, cloning always enabled*/

    if (wspd->mode == MODE_SERVER 
	&& wspd->wsplcConfig.button_mode == WSPLC_ONE_BUTTON)
    wspd->clone_running = 1;

    if (wsplc_init_sockets(wspd) <0)
    {
        dprintf(MSG_ERROR, "Failed to Init Sockets\n");
        return -1;
    }

    if (legacy_apcloning_init(wspd) < 0)
    {
        dprintf(MSG_ERROR, "Failed to Init Legacy AP\n");
        return -1;
    }    


    return 0;
}


int wsplcd_hyfi10_stop(wsplcd_data_t* wspd)
{
    wsplc_deinit_sockets(wspd);
    return 0;
}




