/* apac_hyfi20_ctrl.c 
 * @Notes:
 *
 * Copyright (c) 2011-2012 Qualcomm Atheros, Inc.
 * Qualcomm Atheros Confidential and Proprietary. 
 * All rights reserved.
 *
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
#include <sys/stat.h>

#include "eloop.h"
#include "wsplcd.h"
#include "apac_priv.h"
#include "apac_hyfi20_ctrl.h"

/*----------------------------------------------------------- 
 *Status of CTRL socket
 *1.Attach ----attached to hostpad/wpa_supplicant
               periodic keeplive is called to check this stauts
 *2.Detach   ----Detach from hostpad/wpa_supplicant
 ------------------------------------------------------------*/



static void apac_ctrl_get_msg(int sock, void *eloop_ctx, void *sock_ctx);
static void apac_ctrl_keeplive(void *eloop_ctx, void *timeout_ctx);

static int convertMacStringToHex(char *str, char *mac)
{
    int i;
    unsigned char hbyte, lbyte;
    char ch, *pos;

    if (!str || !mac)
        return -1;

    pos = str;
    for (i=0; i<6; i++)
    {     
        ch = tolower(*pos++);
        if( !(ch>='0' && ch<='9') 
            && !(ch>='a' && ch<='f'))
            return -1;
        hbyte = isdigit (ch) ? (ch - '0') : (ch - 'a' + 10);        
   
        ch = tolower(*pos++);
        if( !(ch>='0' && ch<='9') 
            && !(ch>='a' && ch<='f'))
            return -1;
        lbyte = isdigit (ch) ? (ch - '0') : (ch - 'a' + 10); 
            
        mac[i] = hbyte<<4 | lbyte;
             
        if( i<5 && *pos != ':' )
            return -1;
        pos++;
    }

    return 0;
}

static int apac_ctrl_open(apacHyfi20IF_t *pIF)
{
    int sock;
    struct sockaddr_un local_addr;

    sock = socket(PF_UNIX, SOCK_DGRAM, 0);
    if (sock < 0) {
        return -1;
    }

    pIF->ctrlSock = sock;
    
    local_addr.sun_family = AF_UNIX;
    snprintf(local_addr.sun_path, sizeof(local_addr.sun_path), 
                "/var/run/wsplcd_ctrl_%s",pIF->ifName);

    unlink(local_addr.sun_path);
    if (bind(sock, (struct sockaddr *)&local_addr, 
        sizeof(local_addr)) < 0) 
    {
        dprintf(MSG_ERROR,  "ERR : Bind to ctrl interface  %s failed\n", pIF->ifName);
        goto fail;
    }

    dprintf(MSG_DEBUG, "Open CTRL socket with local path %s \n", local_addr.sun_path);
    return 0;

fail:
    close(sock);
    pIF->ctrlSock = -1; 
    return -1;
}


static void apac_ctrl_close(apacHyfi20IF_t *pIF)
{
    if (pIF->ctrlSock > 0)
        close(pIF->ctrlSock);
    pIF->ctrlSock = -1;	
}


static int apac_ctrl_cmd(apacHyfi20IF_t *pIF, char *command, int cmdlen)
{

    int errn;
    if (pIF->ctrlSock <= 0)
    {
        dprintf(MSG_ERROR, "Invalid socket, cmd <%s> failed\n", command);
        return -1;
    }

    if ((errn = send(pIF->ctrlSock, (const char*)command, (size_t)cmdlen, 0)) < 0) {
        dprintf(MSG_ERROR, "ERR , errn:%d: Fail to send command %s to hostapd/wpa_supplicant\n",
            errn, command);

        return -1;
    }

    dprintf(MSG_MSGDUMP, "Send cmd <%s> OK\n", command);
    return 0;
}

static int apac_ctrl_get_ctlpath(char *ifname, int isap, struct sockaddr_un *skaddr)
{
    char parent_path[64];
    char parent[64];
    FILE *fp;
    struct stat st;
    int len;

    /*Try the path in LSDK*/
    if (isap)
    {
        snprintf(skaddr->sun_path, sizeof(skaddr->sun_path),
                "/var/run/hostapd/%s", ifname);
    }
    else
    {
        snprintf(skaddr->sun_path, sizeof(skaddr->sun_path),
                "/var/run/wpa_supplicant/%s", ifname);
    }

    if (stat(skaddr->sun_path, &st) == 0)
    {
        return 0;
    }

    /*Try the path in QSDK*/
    if (isap)
    {
        snprintf(parent_path, sizeof(parent_path), 
            "/sys/class/net/%s/parent", ifname);
        fp = fopen(parent_path, "r");
        if (!fp)
        {
            return -1;
        }

        memset(parent, 0, sizeof(parent));
        fread(parent, sizeof(parent), 1, fp);
        fclose(fp);

        len = strlen(parent);
        if (len > 0 && len <= sizeof(parent) && parent[len-1] == '\n')
            parent[len-1] = '\0';

        snprintf(skaddr->sun_path, sizeof(skaddr->sun_path),
                "/var/run/hostapd-%s/%s", parent, ifname);
    }
    else
    {
        snprintf(skaddr->sun_path, sizeof(skaddr->sun_path),
                "/var/run/wpa_supplicant-%s/%s", ifname, ifname);
    }

    if (stat(skaddr->sun_path, &st) == 0)
    {
        return 0;
    }

    return -1;
}

static void apac_ctrl_attach(void *eloop_ctx, void *timeout_ctx)
{
    struct sockaddr_un dest_addr;
    apacHyfi20IF_t *pIF = (apacHyfi20IF_t*)eloop_ctx;

    if (apac_ctrl_open(pIF) < 0 )
    {
        goto fail;
    }

    dest_addr.sun_family = AF_UNIX;
    if (apac_ctrl_get_ctlpath(pIF->ifName, 
        (pIF->wlanDeviceMode == APAC_WLAN_AP), 
        &dest_addr) != 0)
    {
        goto fail;
    }

    if (connect(pIF->ctrlSock, (struct sockaddr *) &dest_addr, sizeof(dest_addr)) < 0) 
    {
        goto fail;
    }

    if (apac_ctrl_cmd(pIF, "ATTACH", 6) < 0 )
    {
        goto fail;
    }

    dprintf(MSG_MSGDUMP, "CTRL connection[%s] OK\n", pIF->ifName);
    eloop_register_read_sock(pIF->ctrlSock, apac_ctrl_get_msg, pIF, timeout_ctx);
    eloop_register_timeout(CTRL_KEEPLIVE_TIMEOUT, 0, apac_ctrl_keeplive, pIF, timeout_ctx);
    return ;	

fail:
    dprintf(MSG_DEBUG, "Failed to establish CTRL connection[%s], retry later\n", pIF->ifName);
    eloop_register_timeout(CTRL_REATTACH_TIMEOUT, 0, apac_ctrl_attach, pIF, timeout_ctx);
    apac_ctrl_close(pIF);

}


static void apac_ctrl_detach(apacHyfi20IF_t *pIF)
{
     if (apac_ctrl_cmd(pIF, "DETACH", 6) < 0)
    {
       dprintf(MSG_INFO, "Failed to detach CTRL connection[%s]\n", pIF->ifName);
    }
    
    eloop_unregister_read_sock(pIF->ctrlSock);
    apac_ctrl_close(pIF);
}

static void apac_ctrl_keeplive(void *eloop_ctx, void *timeout_ctx)
{
    apacHyfi20IF_t *pIF = (apacHyfi20IF_t*)eloop_ctx;
    if (apac_ctrl_cmd(pIF, "PING", 4) < 0)
    {
        dprintf(MSG_DEBUG,  "ERR : Keeplive to CTRL socket[%s] failed\n", pIF->ifName);
        eloop_unregister_read_sock(pIF->ctrlSock);
        apac_ctrl_close(pIF);
        eloop_register_timeout(CTRL_REATTACH_TIMEOUT, 0, apac_ctrl_attach, pIF, timeout_ctx);
    }
    else
    {	
        eloop_register_timeout(CTRL_KEEPLIVE_TIMEOUT, 0, apac_ctrl_keeplive, pIF, timeout_ctx);
    }

}

static void apac_ctrl_get_msg(int sock, void *eloop_ctx, void *sock_ctx)
{
    char buf[2048];
    int len;
    struct sockaddr_un from;
    socklen_t fromlen;
    char *pos;

    apacHyfi20IF_t *pIF = (apacHyfi20IF_t* )eloop_ctx;

    fromlen = sizeof(from);
    len = recvfrom(sock, buf, sizeof(buf), 0,
        (struct sockaddr *) &from, &fromlen);
    if (len < 0) {
        perror("recvfrom (unix)");
        return ;
    }
    dprintf(MSG_MSGDUMP, "get ctrl msg %d\n", len); 
    buf[len] = '\0'; 
    dprintf(MSG_MSGDUMP, "[%s]", buf);

    pos = buf;
    if (*pos == '<') {
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
    else if (strncmp(pos, "WPS-SUCCESS", strlen("WPS-SUCCESS")) == 0)
    {
        dprintf(MSG_INFO, "WPS-SUCCESS\n");
        /* On Wi-Fi WPS success on Enrollee, we'd like to send APAC search
           message immediately. So the timer is rescheduled with a short
           interval (leave some time) for STA interface up and running.
           But in the test, this WPS-SUCCESS message has always been sent
           twice, with very short interval. So a check is added here to make
           sure the second success will be ignored if it comes within 1 second
           from the first one. */
        struct os_time now, diff;
        os_get_time(&now);
        os_time_sub(&now, &pIF->last_wps_success_time, &diff);
        apacHyfi20Data_t *pData = (apacHyfi20Data_t *)sock_ctx;
        if (pData->config.role == APAC_ENROLLEE && diff.sec >= 1) {
            eloop_cancel_timeout(apacHyfi20SearchTimeoutHandler, pData, NULL);
            eloop_register_timeout(APAC_SEARCH_SHORT_INTERVAL * 2, 0,
                                   apacHyfi20SearchTimeoutHandler, pData,
                                   (void *)&APAC_SEARCH_SHORT_INTERVAL);
        }
        pIF->last_wps_success_time = now;
    }
    else if (strncmp(pos, "WPS-REG-SUCCESS", strlen("WPS-REG-SUCCESS")) == 0)
    {
        //WPS-REG-SUCCESS c4:17:fe:d1:54:1c 4be0c35a-a873-da42-89e6-2144c128e16f
        u8 wpsEnrolleeMAC[6];
        dprintf(MSG_INFO, "WPS-REG-SUCCESS\n");

        if (pIF->wlanDeviceMode != APAC_WLAN_AP)
            return;
        pos += strlen("WPS-REG-SUCCESS") + 1;
        if (convertMacStringToHex(pos, (char*)wpsEnrolleeMAC) < 0 )
        {
             dprintf(MSG_INFO, "Invalid Enrollee MAC address\n");
             return;
        }
        dprintf(MSG_INFO, "Wifi node added by WPS:");
        printMac(MSG_INFO, wpsEnrolleeMAC);
        /*hostapd will send WPS-REG-SUCCESS to all control interfaces with same UUID.
          So we will receive this message more than once if multi-AP used. 
          Todo: we should know which AP the STA is really associated with*/
        pbcWifiWpsAddNode(pIF->mac_addr, wpsEnrolleeMAC);
        
    }
    else if (strncmp(pos, "CTRL-EVENT-EAP-FAILURE", strlen("CTRL-EVENT-EAP-FAILURE")) == 0)
    {
        dprintf(MSG_INFO, "CTRL-EVENT-EAP-FAILURE, WPS session ending\n"); 
    }
    else
    {
        return;
    }

}


int apac_ctrl_register_IF(apacHyfi20IF_t *pIF, apacHyfi20Data_t *pData)
{
    apac_ctrl_attach(pIF, pData);
    return 0;
}



int apac_ctrl_unregister_IF(apacHyfi20IF_t *pIF, apacHyfi20Data_t *pData)
{
    eloop_cancel_timeout(apac_ctrl_attach, pIF, pData);
    eloop_cancel_timeout(apac_ctrl_keeplive, pIF, pData);
    apac_ctrl_detach(pIF);
    return 0;
}


int apac_ctrl_activate_PBC(apacHyfi20IF_t *pIF)
{

    if (apac_ctrl_cmd(pIF, "WPS_PBC", 7) < 0)
    {
        dprintf(MSG_INFO, "CTRL socket virtual PBC failed\n");
        return -1 ;
    }
    return 0;
}

int apac_ctrl_init(apacHyfi20Data_t* pApacData)
{
    int i;
    apacHyfi20IF_t *pIF = pApacData->hyif;

    for (i = 0; i < APAC_MAXNUM_HYIF; i++) {
        if (!pIF[i].valid ||  pIF[i].mediaType != APAC_MEDIATYPE_WIFI)
            continue;
       
        if (apac_ctrl_register_IF(&pIF[i], pApacData) < 0)
            dprintf(MSG_ERROR, "CTRL socket[%s] register failed\n", pIF[i].ifName);  
        else
            dprintf(MSG_INFO, "CTRL socket[%s] register OK\n", pIF[i].ifName); 
    }
    return 0;
}


int apac_ctrl_deinit(apacHyfi20Data_t* pApacData)
{
    int i;
    apacHyfi20IF_t *pIF = pApacData->hyif;

    for (i = 0; i < APAC_MAXNUM_HYIF; i++) {
        if (!pIF[i].valid ||  pIF[i].mediaType != APAC_MEDIATYPE_WIFI)
            continue;
       
        if (apac_ctrl_unregister_IF(&pIF[i], pApacData) < 0)
            dprintf(MSG_ERROR, "CTRL socket[%s] unregister failed\n", pIF[i].ifName);  
        else
            dprintf(MSG_INFO, "CTRL socket[%s] unregister OK\n", pIF[i].ifName); 
    }
    return 0;
}




