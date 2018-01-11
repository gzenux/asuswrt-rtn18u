#include "1x_fifo.h"
#include "1x_common.h"
#include "1x_kmsm.h"
#include "1x_kmsm_eapolkey.h"
#include "1x_ioctl.h"
#include "1x_types.h"
#include "1x_auth_pae.h"
#include "1x_supp_pae.h"
#include "1x_info.h"
#include "1x_eapol.h"

#include <unistd.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <features.h>    /* for the glibc version number */
#if __GLIBC__ >= 2 && __GLIBC_MINOR >= 1
#include <netpacket/packet.h>
#include <net/ethernet.h>     /* the L2 protocols */
#else
#include <asm/types.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>   /* The L2 protocols */
#endif

#include <sys/ioctl.h>
#include <errno.h>

// marked by chilong
//#include <linux/wireless.h>

// modified by chilong
#ifdef __ASUS_DVD__
	#include "./dlisten/wireless_asus_2421.h"
#else
#include <linux/wireless.h>
#endif
// modified by chilong
#if defined(CONFIG_RTL_ETH_802DOT1X_SUPPORT)
#define	RTL8651_IOCTL_DOT1X_SETPID		           2300
#define RTL8651_IOCTL_DOT1X_GET_INFO                2301
#define RTL8651_IOCTL_DOT1X_SET_AUTH_RESULT   	   2302
#endif





struct lib1xx_nal_intfdesc;
struct lib1x_packet;

#ifdef CONFIG_RTL_ETH_802DOT1X_SUPPORT
int lib1x_control_eth_SetPORT(Global_Params * global, u_char status);
#endif


/*------------------------------------------------------------------*/
/*
 * Open a socket.
 * Depending on the protocol present, open the right socket. The socket
 * will allow us to talk to the driver.
 */
int
sockets_open(void)
{
        int ipx_sock = -1;              /* IPX socket                   */
        int ax25_sock = -1;             /* AX.25 socket                 */
        int inet_sock = -1;             /* INET socket                  */
        int ddp_sock = -1;              /* Appletalk DDP socket         */

        /*
         * Now pick any (exisiting) useful socket family for generic queries
         * Note : don't open all the socket, only returns when one matches,
         * all protocols might not be valid.
         * Workaround by Jim Kaba <jkaba@sarnoff.com>
         * Note : in 99% of the case, we will just open the inet_sock.
         * The remaining 1% case are not fully correct...
         */
        inet_sock=socket(AF_INET, SOCK_DGRAM, 0);
        if(inet_sock!=-1)
                return inet_sock;
        ipx_sock=socket(AF_IPX, SOCK_DGRAM, 0);
        if(ipx_sock!=-1)
                return ipx_sock;
        ax25_sock=socket(AF_AX25, SOCK_DGRAM, 0);
        if(ax25_sock!=-1)
                return ax25_sock;
        ddp_sock=socket(AF_APPLETALK, SOCK_DGRAM, 0);
        /*
         * If this is -1 we have no known network layers and its time to jump.
         */
        return ddp_sock;
}

int lib1x_control_init()
{
	int skfd = -1;                /* generic raw socket desc.     */

    /* Create a channel to the NET kernel. */

    if((skfd = sockets_open()) < 0)
    {
        perror("socket");
        exit(-1);
    }

    return skfd;

}


int lib1x_control_process(u_char * msg, int msglen)
{
	switch(*msg)//switch event id
	{
		case DOT11_EVENT_ASSOCIATION_IND:
			break;
		case DOT11_EVENT_DISASSOCIATION_IND:
			break;
		case DOT11_EVENT_MIC_FAILURE:
			break;

	}
	return 0;
}

int lib1x_control_RequestIndication(
        int                    skfd,
        char *                 ifname)
{

    struct iwreq          wrq;
    DOT11_REQUEST         * req;

    /* Get wireless name */
    strncpy(wrq.ifr_name, ifname, IFNAMSIZ);

    req = (DOT11_REQUEST *)malloc(sizeof(DOT11_REQUEST));
    wrq.u.data.pointer = (caddr_t)req;
    req->EventId = DOT11_EVENT_REQUEST;
    wrq.u.data.length = sizeof(DOT11_EVENT_REQUEST);
    
    if(ioctl(skfd, SIOCGIWIND, &wrq) < 0)
	{
    	free(req);
        return(-1);
	}
    else{
        
        lib1x_message(MESS_DBG_CONTROL, "[RequestIndication]"," : Return\n");
        #ifdef ALLOW_DBG_CONTROL
        lib1x_hexdump2(MESS_DBG_CONTROL, "RequestIndication", wrq.u.data.pointer, wrq.u.data.length, "receive message from driver");
        #endif
    	lib1x_control_process(wrq.u.data.pointer, wrq.u.data.length);
		free(req);
    }

    return 1;
}

#ifdef HS2_SUPPORT
int     lib1x_control_WNM_NOTIFY(Global_Params * global, u_char * WNM_URL, u_char serverMethod)
{

	int retVal = 0;
	struct iwreq          	wrq;
	DOT11_WNM_NOTIFY	WNM_Req;
	int i;

	HS2DEBUG(" WNM Notification[%s]\n", WNM_URL);

	strncpy(wrq.ifr_name, global->auth->GlobalTxRx->device_wlan0, IFNAMSIZ);
	wrq.u.data.pointer = (caddr_t)&WNM_Req;
	wrq.u.data.length = sizeof(DOT11_WNM_NOTIFY);
	WNM_Req.EventId = DOT11_EVENT_WNM_NOTIFY;
	WNM_Req.IsMoreEvent = FALSE;
	memcpy(WNM_Req.macAddr,global->theAuthenticator->supp_addr,6);
	strcpy(WNM_Req.remedSvrURL, WNM_URL);
    #if 1	
	WNM_Req.serverMethod = serverMethod;
    #endif

    if(ioctl(global->auth->GlobalTxRx->fd_control, SIOCGIWIND, &wrq) < 0)
        retVal = -1;
	else
		retVal = 0;

    return retVal;

}

int     lib1x_control_WNM_DEAUTH_REQ(Global_Params * global, u_char reason, u_short reAuthDelay, u_char * WNM_URL)
{

	int retVal = 0;
	struct iwreq          	wrq;
	DOT11_WNM_DEAUTH_REQ	WNM_Req;
	int i;

	HS2DEBUG("WNM Deauth Req[%s]\n", WNM_URL);

	strncpy(wrq.ifr_name, global->auth->GlobalTxRx->device_wlan0, IFNAMSIZ);
	wrq.u.data.pointer = (caddr_t)&WNM_Req;
	wrq.u.data.length = sizeof(DOT11_WNM_DEAUTH_REQ);
	WNM_Req.EventId = DOT11_EVENT_WNM_DEAUTH_REQ;
	WNM_Req.IsMoreEvent = FALSE;

	memcpy(WNM_Req.macAddr,global->theAuthenticator->supp_addr,6);	
	WNM_Req.reason = reason;
	WNM_Req.reAuthDelay = reAuthDelay;
	if(WNM_URL)
		strcpy(WNM_Req.URL, WNM_URL);
	else
		WNM_Req.URL[0] = '\0';
	
	if(ioctl(global->auth->GlobalTxRx->fd_control, SIOCGIWIND, &wrq) < 0)
        retVal = -1;
	else
		retVal = 0;

        return retVal;

}

int lib1x_control_SessionInfo_URL(Global_Params * global, u_char SWT, u_char * URL)
{
	int retVal = 0;
	struct iwreq          	wrq;
	DOT11_BSS_SessInfo_URL	SessInfo_URL;
	int i;

	HS2DEBUG("Session Info URL[%s]\n", SessInfo_URL.URL);

	strncpy(wrq.ifr_name, global->auth->GlobalTxRx->device_wlan0, IFNAMSIZ);
	wrq.u.data.pointer = (caddr_t)&SessInfo_URL;
	wrq.u.data.length = sizeof(DOT11_BSS_SessInfo_URL);
	SessInfo_URL.EventId = DOT11_EVENT_HS2_TSM_REQ;
	SessInfo_URL.IsMoreEvent = FALSE;

	memcpy(SessInfo_URL.macAddr,global->theAuthenticator->supp_addr,6);	
	SessInfo_URL.SWT = SWT;
	
	if(URL)
		strcpy(SessInfo_URL.URL, URL);
	else
		SessInfo_URL.URL[0] = '\0';
	
	if(ioctl(global->auth->GlobalTxRx->fd_control, SIOCGIWIND, &wrq) < 0)
        retVal = -1;
	else
		retVal = 0;

    return retVal;
}
	
#endif // HS2_SUPPORT

int     lib1x_control_STADisconnect(Global_Params * global, u_short reason)
{

	int retVal = 0;
	struct iwreq          	wrq;
	DOT11_DISCONNECT_REQ	Disconnect_Req;

#ifdef CONFIG_RTL_ETH_802DOT1X_SUPPORT
	if(global->auth->currentRole == role_eth){
		return retVal;
	}
#endif
	lib1x_message(MESS_DBG_CONTROL, "lib1x_control_STADisconnect(1) %02x:%02x:%02x:%02x:%02x:%02x:\n",
		global->theAuthenticator->supp_addr[0],global->theAuthenticator->supp_addr[1],global->theAuthenticator->supp_addr[2],
		global->theAuthenticator->supp_addr[3],global->theAuthenticator->supp_addr[4],global->theAuthenticator->supp_addr[5]);

	strncpy(wrq.ifr_name, global->auth->GlobalTxRx->device_wlan0, IFNAMSIZ);

	wrq.u.data.pointer = (caddr_t)&Disconnect_Req;
	wrq.u.data.length = sizeof(DOT11_DISCONNECT_REQ);

	Disconnect_Req.EventId = DOT11_EVENT_DISCONNECT_REQ;
	Disconnect_Req.IsMoreEvent = FALSE;
	Disconnect_Req.Reason = reason;
	memcpy(Disconnect_Req.MACAddr,  global->theAuthenticator->supp_addr, MacAddrLen);

	if(ioctl(global->auth->GlobalTxRx->fd_control, SIOCGIWIND, &wrq) < 0)
		retVal = -1;
	else
		retVal = 0;

    return retVal;

};

//------------------------------------------------------------------------
// Retrun Association Request result to driver
//------------------------------------------------------------------------
#ifdef RTL_WPA2
/*
	event_id: DOT11_EVENT_ASSOCIATION_IND or DOT11_EVENT_REASSOCIATION_IND
*/
int     lib1x_control_AssociationRsp(Global_Params * global, int result, int event_id)
#else
int     lib1x_control_AssociationRsp(Global_Params * global, int result)
#endif
{
        int retVal = 0;
	struct iwreq wrq;
	DOT11_ASSOCIATION_RSP 	Association_Rsp;

	lib1x_message(MESS_DBG_CONTROL, "lib1x_control_AssociationRsp(1)\n");

	strncpy(wrq.ifr_name, global->auth->GlobalTxRx->device_wlan0, IFNAMSIZ);

	wrq.u.data.pointer = (caddr_t)&Association_Rsp;
	wrq.u.data.length = sizeof(DOT11_ASSOCIATION_RSP);

    #ifdef RTL_WPA2

	if (event_id == DOT11_EVENT_ASSOCIATION_IND)
    	Association_Rsp.EventId = DOT11_EVENT_ASSOCIATION_RSP;
	else
		Association_Rsp.EventId = DOT11_EVENT_REASSOCIATION_RSP;
    
    #else
    
	Association_Rsp.EventId = DOT11_EVENT_ASSOCIATION_RSP;
    
    #endif
    
	Association_Rsp.IsMoreEvent = FALSE;
	Association_Rsp.Status = result;
	memcpy(&Association_Rsp.MACAddr, global->theAuthenticator->supp_addr, MacAddrLen);

	if(ioctl(global->auth->GlobalTxRx->fd_control, SIOCGIWIND, &wrq) < 0)
        retVal = -1;
    else
        retVal = 0;

    return retVal;
}

int     lib1x_control_RemovePTK(Global_Params * global, int keytype)
{
	int retVal = 0;
	struct iwreq wrq;
	DOT11_DELETE_KEY Delete_Key;

#ifdef CONFIG_RTL_ETH_802DOT1X_SUPPORT
	if(global->auth->currentRole == role_eth){
		return retVal;
	}
#endif
	lib1x_message(MESS_DBG_CONTROL, "lib1x_control_RemovePTK(1)\n");

	strncpy(wrq.ifr_name, global->auth->GlobalTxRx->device_wlan0, IFNAMSIZ);
	wrq.u.data.pointer = (caddr_t)&Delete_Key;
	wrq.u.data.length = sizeof(DOT11_DELETE_KEY);

	Delete_Key.EventId = DOT11_EVENT_DELETE_KEY;
	Delete_Key.IsMoreEvent = FALSE;
	Delete_Key.KeyType = keytype;
	memcpy(&Delete_Key.MACAddr, global->theAuthenticator->supp_addr, MacAddrLen);

    if(ioctl(global->auth->GlobalTxRx->fd_control, SIOCGIWIND, &wrq) < 0)
        retVal = -1;
    else
        retVal = 0;

	return retVal;
}

int lib1x_control_QueryRSC(Global_Params * global, OCTET_STRING * gRSC)
{

	int retVal = 0;
	struct iwreq wrq;
	DOT11_GKEY_TSC Gkey_Tsc;
	DOT11_GKEY_TSC * pGkey_Tsc ;

	gRSC->Length = KEY_RSC_LEN;
	lib1x_message(MESS_DBG_CONTROL, "lib1x_control_QueryRSC(1)\n");

	strncpy(wrq.ifr_name, global->auth->GlobalTxRx->device_wlan0, IFNAMSIZ);
	wrq.u.data.pointer = (caddr_t)&Gkey_Tsc;
	wrq.u.data.length = sizeof(DOT11_GKEY_TSC);

	Gkey_Tsc.EventId = DOT11_EVENT_GKEY_TSC;
	Gkey_Tsc.IsMoreEvent = FALSE;

	if(ioctl(global->auth->GlobalTxRx->fd_control, SIOCGIWIND, &wrq) < 0)
        retVal = -1;
    else
	{
		lib1x_message(MESS_DBG_CONTROL, "lib1x_control_QueryRSC", wrq.u.data.pointer, 64);
		pGkey_Tsc = (DOT11_GKEY_TSC *)wrq.u.data.pointer;
		memcpy(gRSC->Octet, pGkey_Tsc->KeyTSC, KEY_RSC_LEN);
                retVal = 0;
	}

        return retVal;

}

#ifdef RTL_WPA_CLIENT
//Return -1 if STA is not associated to ap
// 	  0 if Success
int lib1x_control_STA_QUERY_BSSID(Supp_Global * pGlobal)
{

	int retVal = 0;
	struct iwreq wrq;
	DOT11_STA_QUERY_BSSID Query, * pQueryRet;

    //lib1x_message(MESS_DBG_CONTROL, "lib1x_control_STA_QUERY_BSSID(1)\n");

	strncpy(wrq.ifr_name, pGlobal->auth->GlobalTxRx->device_wlan0, IFNAMSIZ);
	wrq.u.data.pointer = (caddr_t)&Query;
	wrq.u.data.length = sizeof(DOT11_STA_QUERY_BSSID);

	Query.EventId = DOT11_EVENT_STA_QUERY_BSSID;
	Query.IsMoreEvent = FALSE;

	if(ioctl(pGlobal->auth->GlobalTxRx->fd_control, SIOCGIWIND, &wrq) < 0){
        retVal = -1;
	}
    else
	{
		pQueryRet = (DOT11_STA_QUERY_BSSID *)wrq.u.data.pointer;
		if(pQueryRet->IsValid)
		{
			memcpy(pGlobal->supp_pae->auth_addr, pQueryRet->Bssid, MacAddrLen);
			return 0;
		}
		else{
            retVal = -1;
		}
	}

    return retVal;

}

int lib1x_control_STA_QUERY_SSID(Supp_Global * pGlobal, unsigned char *pSSID)
{

	int retVal = 0;
	struct iwreq wrq;
	DOT11_STA_QUERY_SSID Query, * pQueryRet;

	lib1x_message(MESS_DBG_CONTROL, "lib1x_control_STA_QUERY_SSID(1)\n");

	strncpy(wrq.ifr_name, pGlobal->auth->GlobalTxRx->device_wlan0, IFNAMSIZ);
	wrq.u.data.pointer = (caddr_t)&Query;
	wrq.u.data.length = sizeof(DOT11_STA_QUERY_SSID);

	Query.EventId = DOT11_EVENT_STA_QUERY_SSID;
	Query.IsMoreEvent = FALSE;

	if(ioctl(pGlobal->auth->GlobalTxRx->fd_control, SIOCGIWIND, &wrq) < 0)
        retVal = -1;
    else
	{
		pQueryRet = (DOT11_STA_QUERY_SSID *)wrq.u.data.pointer;
		if(pQueryRet->IsValid)
		{
			memcpy(pSSID, pQueryRet->ssid, pQueryRet->ssid_len);
			pSSID[pQueryRet->ssid_len] = '\0';
			return 0;
		}
		else{
           	retVal = -1;
        }
	}

    return retVal;

}

int lib1x_control_STA_SetPTK(Supp_Global * pGlobal)
{
	int retVal = 0;
	u_long	ulKeyLength = 0;
	u_char * ptr;
	u_char * pucKeyMaterial = 0;
	struct iwreq wrq;
	DOT11_SET_KEY	Set_Key;


	lib1x_message(MESS_DBG_CONTROL, "lib1x_control_STA_SetPTK\n");


	strncpy(wrq.ifr_name, pGlobal->auth->GlobalTxRx->device_wlan0, IFNAMSIZ);
	wrq.u.data.pointer = (caddr_t)&Set_Key;


	Set_Key.EventId = DOT11_EVENT_SET_KEY;
	Set_Key.IsMoreEvent = FALSE;
	ptr = (u_char*)&Set_Key.KeyIndex;
	long2net(0, ptr);

	Set_Key.KeyType = DOT11_KeyType_Pairwise;
	memcpy(&Set_Key.MACAddr, pGlobal->supp_pae->auth_addr, MacAddrLen);


	if(pGlobal->AuthKeyMethod == DOT11_AuthKeyType_RSNPSK 
        #ifdef CLIENT_TLS
        || pGlobal->AuthKeyMethod == DOT11_AuthKeyType_RSN
        #endif
    ){
		switch(pGlobal->RSNVariable.UnicastCipher)
		{
			case DOT11_ENC_TKIP:
				ulKeyLength =  PTK_LEN_TKIP - (PTK_LEN_EAPOLMIC + PTK_LEN_EAPOLENC);
				break;
			case DOT11_ENC_CCMP:
				ulKeyLength =  PTK_LEN_CCMP - (PTK_LEN_EAPOLMIC + PTK_LEN_EAPOLENC);
				break;
		}
		pucKeyMaterial = pGlobal->supp_kmsm->PTK + (PTK_LEN_EAPOLMIC + PTK_LEN_EAPOLENC);
		lib1x_message(MESS_DBG_CONTROL, "STA Set RSN key\n");

	}
    #ifdef CLIENT_TLS
	else {
		printf("pGlobal->AuthKeyMethod (%d) not supported !!\n", pGlobal->AuthKeyMethod);
	}
    #endif

	memset(Set_Key.KeyMaterial,0, 64);
	memcpy(Set_Key.KeyMaterial, pucKeyMaterial, ulKeyLength);
	Set_Key.EncType = pGlobal->RSNVariable.UnicastCipher;
	ptr = (u_char*)&Set_Key.KeyLen;
	long2net(ulKeyLength, ptr);

	wrq.u.data.length = sizeof(DOT11_SET_KEY) - 1 + ulKeyLength;
		
    #ifdef ALLOW_DBG_CONTROL
	lib1x_hexdump2(MESS_DBG_SUPP, "lib1x_control_STA_SetPTK", wrq.u.data.pointer, wrq.u.data.length, "Set Pairwise Key");
    #endif
    
	if(ioctl(pGlobal->auth->GlobalTxRx->fd_control, SIOCGIWIND, &wrq) < 0)
        retVal = -1;
    else
        retVal = 0;
    
    return retVal;

}

int lib1x_control_STA_SetGTK(Supp_Global * pGlobal, u_char * pucKey, int iKeyId)
{

	int retVal = 0;
	u_long	ulKeyLength = 0;
	u_char * ptr;
	struct iwreq wrq;
	DOT11_SET_KEY  Set_Key;
	u_char	szBradcast[] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};

    memset(&Set_Key, 0, sizeof(DOT11_SET_KEY));
	lib1x_message(MESS_DBG_CONTROL, "lib1x_control_STA_SetGTK\n");

	strncpy(wrq.ifr_name, pGlobal->auth->GlobalTxRx->device_wlan0, IFNAMSIZ);
	wrq.u.data.pointer = (caddr_t)&Set_Key;
	wrq.u.data.length = sizeof(DOT11_SET_KEY);

	Set_Key.EventId = DOT11_EVENT_SET_KEY;
	Set_Key.IsMoreEvent = FALSE;
	ptr = (u_char*)&Set_Key.KeyIndex;
	long2net(iKeyId, ptr);
	Set_Key.KeyType = DOT11_KeyType_Group;

 	if (pGlobal->auth->currentRole == role_wds)
		memset(Set_Key.MACAddr, '\0',  MacAddrLen);
 	else
		memcpy(Set_Key.MACAddr, szBradcast, MacAddrLen);


	Set_Key.EncType = pGlobal->RSNVariable.MulticastCipher;

	switch(pGlobal->RSNVariable.MulticastCipher)
	{

		case DOT11_ENC_TKIP:
			ulKeyLength = 32;
			memcpy(Set_Key.KeyMaterial ,
				pucKey,
				ulKeyLength);
			break;
		case DOT11_ENC_CCMP:
			ulKeyLength = 16;
			memcpy(Set_Key.KeyMaterial ,
				pucKey,
				ulKeyLength);
			break;

        // david, add wep multicast cipher support in WPA -----
		case DOT11_ENC_WEP40:
			ulKeyLength = 5;
			memcpy(Set_Key.KeyMaterial ,
				pucKey,
				ulKeyLength);
			break;

		case DOT11_ENC_WEP104:
			ulKeyLength = 13;
			memcpy(Set_Key.KeyMaterial ,
				pucKey,
				ulKeyLength);
			break;
        // ------------------------------------------------

	}

	ptr = (u_char*)&Set_Key.KeyLen;
	long2net(ulKeyLength, ptr);

	wrq.u.data.length = sizeof(DOT11_SET_KEY) - 1 + ulKeyLength;

    #ifdef ALLOW_DBG_CONTROL
	lib1x_hexdump2(MESS_DBG_SUPP, "lib1x_control_STA_SetGTK", wrq.u.data.pointer, wrq.u.data.length, "Set Group Key");
    #endif

    if(ioctl(pGlobal->auth->GlobalTxRx->fd_control, SIOCGIWIND, &wrq) < 0)
        retVal = -1;
    else
        retVal = 0;

    return retVal;
}


int lib1x_control_STA_SetPORT(Supp_Global * pGlobal, u_char status)
{
	int retVal = 0;
	struct iwreq wrq;
	DOT11_SETPORT	Set_Port;


	lib1x_message(MESS_DBG_CONTROL, "lib1x_control_STA_SetPORT\n");


	strncpy(wrq.ifr_name, pGlobal->auth->GlobalTxRx->device_wlan0, IFNAMSIZ);
	wrq.u.data.pointer = (caddr_t)&Set_Port;
	wrq.u.data.length = sizeof(DOT11_SETPORT);


	Set_Port.EventId = DOT11_EVENT_SET_PORT;

	Set_Port.PortStatus = status;
	Set_Port.PortType = pGlobal->AuthKeyMethod;

	memcpy(&Set_Port.MACAddr, pGlobal->supp_pae->auth_addr, MacAddrLen);

	if(Set_Port.PortStatus == DOT11_PortStatus_Authorized)
	{
		lib1x_message(MESS_DBG_CONTROL, "Set Port Authorized for STA =>");
	}
	else if(Set_Port.PortStatus == DOT11_PortStatus_Unauthorized)
	{
		lib1x_message(MESS_DBG_CONTROL, "Set Port Unathorized for STA =>\n");
	}

    #ifdef ALLOW_DBG_CONTROL
	lib1x_hexdump2(MESS_DBG_SUPP, "lib1x_control_STA_SetPORT", wrq.u.data.pointer, wrq.u.data.length, "Set PORT");
    #endif

	if(ioctl(pGlobal->auth->GlobalTxRx->fd_control, SIOCGIWIND, &wrq) < 0)
        retVal = -1;
    else
        retVal = 0;


    return retVal;


}
int lib1x_control_AuthDisconnect(Dot1x_Authenticator * auth, u_char *pucMacAddr, u_short reason)
{

	int retVal = 0;
	struct iwreq          	wrq;
	DOT11_DISCONNECT_REQ	Disconnect_Req;


	lib1x_message(MESS_DBG_CONTROL, "lib1x_control_AuthDisconnect\n");


        strncpy(wrq.ifr_name, auth->GlobalTxRx->device_wlan0, IFNAMSIZ);

	wrq.u.data.pointer = (caddr_t)&Disconnect_Req;
	wrq.u.data.length = sizeof(DOT11_DISCONNECT_REQ);

	Disconnect_Req.EventId = DOT11_EVENT_DISCONNECT_REQ;
	Disconnect_Req.IsMoreEvent = FALSE;
	Disconnect_Req.Reason = reason;
	memcpy(Disconnect_Req.MACAddr,  pucMacAddr, MacAddrLen);

	if(ioctl(auth->GlobalTxRx->fd_control, SIOCGIWIND, &wrq) < 0)
        retVal = -1;
	else
		retVal = 0;

    return retVal;

}
#endif

int lib1x_control_QuerySTA(Global_Params * global)
{

	int retVal = 0;
	struct iwreq wrq;
	DOT11_QUERY_STATS	Query_Stat;
	DOT11_QUERY_STATS       *pQuery_Stat;


	lib1x_message(MESS_DBG_CONTROL, "lib1x_control_QuerySTA(1)\n");

	strncpy(wrq.ifr_name, global->auth->GlobalTxRx->device_wlan0, IFNAMSIZ);
	wrq.u.data.pointer = (caddr_t)&Query_Stat;
	wrq.u.data.length = sizeof(DOT11_QUERY_STATS);

	Query_Stat.EventId = DOT11_EVENT_ACC_QUERY_STATS;
	Query_Stat.IsMoreEvent = FALSE;
	memcpy(&Query_Stat.MACAddr, global->theAuthenticator->supp_addr, MacAddrLen);

	if(ioctl(global->auth->GlobalTxRx->fd_control, SIOCGIWIND, &wrq) < 0)
	{
        retVal = -1;
		lib1x_message(MESS_DBG_CONTROL, "lib1x_control_QuerySTA(1) retun -1\n");
	}
    else
	{
		pQuery_Stat = (DOT11_QUERY_STATS * )wrq.u.data.pointer;
		if(pQuery_Stat->IsSuccess)
		{
			lib1x_message(MESS_DBG_CONTROL, "lib1x_control_QuerySTA(1) retun success\n");
			global->theAuthenticator->acct_sm->tx_packets = pQuery_Stat->tx_packets;       // == transmited packets
			global->theAuthenticator->acct_sm->rx_packets = pQuery_Stat->rx_packets;       // == received packets
			global->theAuthenticator->acct_sm->tx_bytes = pQuery_Stat->tx_bytes;         // == transmited bytes
			global->theAuthenticator->acct_sm->rx_bytes = pQuery_Stat->rx_bytes;         // == received bytes
		} else {
			lib1x_message(MESS_DBG_CONTROL, "lib1x_control_QuerySTA(1): Unknown STA \n");
		}

		retVal = 0;
   	}

    return retVal;

}


int lib1x_control_Query_All_Sta_Info(Dot1x_Authenticator * auth)
{

	int retVal = 0;
	struct iwreq wrq;


	//lib1x_message(MESS_DBG_CONTROL, "lib1x_control_Query_All_Sta_Info\n");

	strncpy(wrq.ifr_name, auth->GlobalTxRx->device_wlan0, IFNAMSIZ);

	memset(auth->DrvStaInfo, 0, sizeof(RTL_STA_INFO)*(MAX_SUPPLICANT+1));
	wrq.u.data.pointer = (caddr_t)&auth->DrvStaInfo;
	wrq.u.data.length = sizeof(RTL_STA_INFO)*(MAX_SUPPLICANT+1);
	*((unsigned char *)wrq.u.data.pointer) = MAX_SUPPLICANT; //david, only copy MAX_SUPPLICANT entry up

	if(ioctl(auth->GlobalTxRx->fd_control, SIOCGIWRTLSTAINFO, &wrq) < 0)
        retVal = -1;
    else
	{
        retVal = 0;
	}

    return retVal;

}

int lib1x_control_RSNIE(Dot1x_Authenticator * auth, u_char flag)
{
	int retVal = 0;
    //	u_char * ptr;
	struct iwreq wrq;
	DOT11_SET_RSNIE Set_Rsnie;

	lib1x_message(MESS_DBG_CONTROL, "lib1x_control_SetRSNIE(1)\n");

	if(auth->RSNVariable.AuthInfoElement.Length <= 0)
	{
		retVal = -1;
		return retVal;
	}

	strncpy(wrq.ifr_name, auth->GlobalTxRx->device_wlan0, IFNAMSIZ);
	wrq.u.data.pointer = (caddr_t)&Set_Rsnie;
	wrq.u.data.length = sizeof(DOT11_SET_RSNIE);


	Set_Rsnie.EventId = DOT11_EVENT_SET_RSNIE;
	Set_Rsnie.IsMoreEvent = FALSE;
	Set_Rsnie.Flag = flag;

	if(flag == DOT11_Ioctl_Set)
	{

    // marked by david	
    //		ptr = (u_char*)&Set_Rsnie.RSNIELen;
    //		short2net(auth->RSNVariable.AuthInfoElement.Length, ptr);
	Set_Rsnie.RSNIELen = auth->RSNVariable.AuthInfoElement.Length;
		memcpy(&Set_Rsnie.RSNIE,
			auth->RSNVariable.AuthInfoElement.Octet,
			auth->RSNVariable.AuthInfoElement.Length);
	}else if(flag == DOT11_Ioctl_Query)
	{

	}

	//lib1x_hexdump2(MESS_DBG_SUPP, "lib1x_control_set_RSNIE",
	//(u_char*)wrq.u.data.pointer, wrq.u.data.length, "RSNIE Content");

    if(ioctl(auth->GlobalTxRx->fd_control, SIOCGIWIND, &wrq) < 0) // If no wireless name : no wireless extensions        
        retVal = -1;
    else
        retVal = 0;

    return retVal;

}

#ifdef CONFIG_IEEE80211W
/*HS2_SUPPORT R2 LOGO*/
int lib1x_control_InitPMF(Dot1x_Authenticator * auth)
{
 	int retVal = 0;
	struct iwreq wrq;
	DOT11_INIT_11W_Flags flags;


    memset(&flags, 0, sizeof(flags));
	flags.EventId = DOT11_EVENT_INIT_PMF;	     
	flags.IsMoreEvent = FALSE;
    flags.dot11IEEE80211W = auth->RSNVariable.ieee80211w;
    flags.dot11EnableSHA256= auth->RSNVariable.sha256;

	strncpy(wrq.ifr_name, auth->GlobalTxRx->device_wlan0, IFNAMSIZ);	
	wrq.u.data.pointer = (caddr_t)&flags;
	wrq.u.data.length = sizeof(flags);

    if(ioctl(auth->GlobalTxRx->fd_control, SIOCGIWIND, &wrq) < 0)
        retVal = -1;
    else
        retVal = 0;


    PMFDEBUG("set 11W[%d] , SHA256[%d] to driver[%s]\n",flags.dot11IEEE80211W,flags.dot11EnableSHA256,auth->GlobalTxRx->device_wlan0);
    
    return retVal;
}


int lib1x_control_SetPMF(Global_Params * global)
{
 	int retVal = 0;
	struct iwreq wrq;
	DOT11_SET_11W_Flags flags;
	
	flags.EventId = DOT11_EVENT_SET_PMF;	     
    flags.isPMF = global->mgmt_frame_prot;
	flags.IsMoreEvent = FALSE;
    memcpy(flags.macAddr, global->theAuthenticator->supp_addr,6);
	strncpy(wrq.ifr_name, global->auth->GlobalTxRx->device_wlan0, IFNAMSIZ);	
	wrq.u.data.pointer = (caddr_t)&flags;
	wrq.u.data.length = sizeof(flags);
    if(ioctl(global->auth->GlobalTxRx->fd_control, SIOCGIWIND, &wrq) < 0) // If no wireless name : no wireless extensions    
        retVal = -1;
    else
        retVal = 0;

    return retVal;
}

int lib1x_control_GetIGTK_PN(Dot1x_Authenticator * auth)
{
	int retVal = 0;
	struct iwreq wrq;

	DOT11_REQUEST * req;
	unsigned char EventID;
	unsigned char *ptr;

	/* Get wireless qame */
	strncpy(wrq.ifr_name, auth->GlobalTxRx->device_wlan0, IFNAMSIZ);

	req = (DOT11_REQUEST *)malloc(sizeof(DOT11_REQUEST));	
	wrq.u.data.pointer = (caddr_t)req;
	req->EventId = DOT11_EVENT_GET_IGTK_PN;
	wrq.u.data.length = sizeof(DOT11_REQUEST);
	
	if(ioctl(auth->GlobalTxRx->fd_control, SIOCGIWIND, &wrq) < 0) {
		free(req);
		retVal = -1;
	}
	else
	{				
		ptr = wrq.u.data.pointer;
		memcpy(&auth->gk_sm->IGTK_PN.val48, wrq.u.data.pointer, sizeof(union PN48));
		//auth->gk_sm->IGTK_PN.val48 = *(unsigned long long *)wrq.u.data.pointer;
		#if 0
		PMFDEBUG("auth:IGTK_PN.val48=%x %x %x %x %x %x\n",auth->gk_sm->IGTK_PN._byte_.TSC0
		,auth->gk_sm->IGTK_PN._byte_.TSC1 ,auth->gk_sm->IGTK_PN._byte_.TSC2,auth->gk_sm->IGTK_PN._byte_.TSC3
		,auth->gk_sm->IGTK_PN._byte_.TSC4,auth->gk_sm->IGTK_PN._byte_.TSC5);
		#endif
		retVal = 0;
	}

	return retVal;

}

#endif // CONFIG_IEEE80211W

int lib1x_control_AssocInfo(Global_Params * global, int Set, OCTET_STRING * RSNInfo)
{
 	int retVal = 0;
	DOT11_ASSOCIATION_INFORMATION     Assoc_Info = {0};
	DOT11_ASSOCIATION_INFORMATION *RAssoc_Info = NULL;
	struct iwreq wrq;


	lib1x_message(MESS_DBG_CONTROL, "lib1x_control_AssocInfo(1)\n");


	Assoc_Info.EventId = DOT11_EVENT_ASSOCIATION_INFO;
	Assoc_Info.IsMoreEvent = FALSE;
	memcpy(Assoc_Info.SupplicantAddress, global->theAuthenticator->supp_addr, MacAddrLen);
	Assoc_Info.Length = sizeof(DOT11_ASSOCIATION_INFORMATION);

	strncpy(wrq.ifr_name, global->auth->GlobalTxRx->device_wlan0, IFNAMSIZ);
	if(!Set) //Query
	{
		memcpy(wrq.u.data.pointer, &Assoc_Info, sizeof(DOT11_ASSOCIATION_INFORMATION));
		wrq.u.data.length = sizeof(DOT11_ASSOCIATION_INFORMATION);
	}else   //Set
	{
		Assoc_Info.RequestIELength = global->akm_sm->SuppInfoElement.Length;
		Assoc_Info.OffsetRequestIEs = sizeof(DOT11_ASSOCIATION_INFORMATION);
		memcpy(wrq.u.data.pointer, &Assoc_Info, sizeof(DOT11_ASSOCIATION_INFORMATION));
		memcpy(wrq.u.data.pointer + sizeof(DOT11_ASSOCIATION_INFORMATION), global->akm_sm->SuppInfoElement.Octet, global->akm_sm->SuppInfoElement.Length);
		wrq.u.data.length = sizeof(DOT11_ASSOCIATION_INFORMATION) + global->akm_sm->SuppInfoElement.Length;
	}


   if(ioctl(global->auth->GlobalTxRx->fd_control, SIOCGIWIND, &wrq) < 0)
       retVal = -1;
    else
	{
		//Check returned data length
		RAssoc_Info = (DOT11_ASSOCIATION_INFORMATION*)wrq.u.data.pointer;
		memcpy(RSNInfo->Octet, wrq.u.data.pointer + RAssoc_Info->OffsetResponseIEs, RAssoc_Info->ResponseIELength);
		RSNInfo->Length = RAssoc_Info->ResponseIELength;
        retVal = 0;
	}


        return retVal;
}

int lib1x_control_SetPTK(Global_Params * global)
{
	int retVal = 0;
	u_long	ulKeyLength = 0;
	u_char * ptr;
	u_char * pucKeyMaterial = 0;
	struct iwreq wrq;
	DOT11_SET_KEY	Set_Key;

	/*
	u_char		szDefaultKey[16] = {0x11, 0x11,0x11, 0x11,0x11, 0x11,0x11, 0x11,
	 				    0x11, 0x11,0x11, 0x11,0x11, 0x11,0x11, 0x11};
	*/
	lib1x_message(MESS_DBG_CONTROL, "lib1x_control_SetPTK(1)\n");


	strncpy(wrq.ifr_name, global->auth->GlobalTxRx->device_wlan0, IFNAMSIZ);
	wrq.u.data.pointer = (caddr_t)&Set_Key;


	Set_Key.EventId = DOT11_EVENT_SET_KEY;
	Set_Key.IsMoreEvent = FALSE;
	ptr = (u_char*)&Set_Key.KeyIndex;
	long2net(0, ptr);

	Set_Key.KeyType = DOT11_KeyType_Pairwise;
	memcpy(&Set_Key.MACAddr, global->theAuthenticator->supp_addr, MacAddrLen);

	if(global->AuthKeyMethod == DOT11_AuthKeyType_RSN || global->AuthKeyMethod == DOT11_AuthKeyType_RSNPSK
#ifdef CONFIG_IEEE80211R
		|| global->AuthKeyMethod == DOT11_AuthKeyType_FT
#endif
#ifdef CONFIG_IEEE80211W
		|| global->AuthKeyMethod == DOT11_AuthKeyType_802_1X_SHA256
#endif
	)
	{
		switch(global->RSNVariable.UnicastCipher)
		{
			case DOT11_ENC_TKIP:
				ulKeyLength =  PTK_LEN_TKIP - (PTK_LEN_EAPOLMIC + PTK_LEN_EAPOLENC);
				break;
			// Kenny
			case DOT11_ENC_CCMP:
				ulKeyLength =  PTK_LEN_CCMP - (PTK_LEN_EAPOLMIC + PTK_LEN_EAPOLENC);
				break;
		}
		pucKeyMaterial = global->akm_sm->PTK + (PTK_LEN_EAPOLMIC + PTK_LEN_EAPOLENC);
		lib1x_message(MESS_DBG_CONTROL, "Set RSN key\n");

	}
#ifndef CONFIG_IEEE80211R
	else if(global->AuthKeyMethod == DOT11_AuthKeyType_NonRSN802dot1x)
	{
		//Follow INTERNET-DRAFT IEEE 802.1X RADIUS Usage Guidelines
		switch(global->RSNVariable.UnicastCipher)
		{
			case DOT11_ENC_NONE:
				ulKeyLength =	0;
				//sc_yang
				break;
			case DOT11_ENC_WEP40:
				ulKeyLength =	5;
				long2net(EAPOL_PAIRWISE_INDEX, ptr); //sc_yang
				break;
			case DOT11_ENC_WEP104:
				ulKeyLength =	13;
				long2net(EAPOL_PAIRWISE_INDEX, ptr); //sc_yang
				break;
		}
		pucKeyMaterial = global->RadiusKey.RecvKey.Octet;
		//pucKeyMaterial = szDefaultKey;
		lib1x_message(MESS_DBG_CONTROL, "Set NonRSN802.1x key\n");
	}
#endif

	//sc_yang
	memset(Set_Key.KeyMaterial,0, 64);
	memcpy(Set_Key.KeyMaterial, pucKeyMaterial, ulKeyLength);
	Set_Key.EncType = global->RSNVariable.UnicastCipher;
	ptr = (u_char*)&Set_Key.KeyLen;
	long2net(ulKeyLength, ptr);




	wrq.u.data.length = sizeof(DOT11_SET_KEY) - 1 + ulKeyLength;
#ifdef ALLOW_DBG_CONTROL
	lib1x_hexdump2(MESS_DBG_CONTROL, "lib1x_control_SetPTK", wrq.u.data.pointer, wrq.u.data.length, "Set Pairwise Key");
#endif
	if(ioctl(global->auth->GlobalTxRx->fd_control, SIOCGIWIND, &wrq) < 0)
                retVal = -1;
        else
                retVal = 0;


        return retVal;


}

//------------------------------------------------------------
// Return 0 for Success
//------------------------------------------------------------
int lib1x_control_SetGTK(Global_Params * global)
{


	int retVal = 0;
	u_long	ulKeyLength = 0;
	u_long  ulKeyIndex = 0;
	u_char * ptr;
	struct iwreq wrq;
	DOT11_SET_KEY  Set_Key;
	u_char	szBradcast[] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};

	/*
	u_char	szDefaultKey[16] = {0x11, 0x11,0x11, 0x11,0x11, 0x11,0x11, 0x11,
					0x11, 0x11,0x11, 0x11,0x11, 0x11,0x11, 0x11};
	*/
    memset(&Set_Key, 0, sizeof(DOT11_SET_KEY));

	lib1x_message(MESS_DBG_CONTROL, "lib1x_control_SetGTK(1)\n");

	strncpy(wrq.ifr_name, global->auth->GlobalTxRx->device_wlan0, IFNAMSIZ);
	wrq.u.data.pointer = (caddr_t)&Set_Key;
	wrq.u.data.length = sizeof(DOT11_SET_KEY);

	Set_Key.EventId = DOT11_EVENT_SET_KEY;
	Set_Key.IsMoreEvent = FALSE;

	Set_Key.KeyType = DOT11_KeyType_Group;
	memcpy(&Set_Key.MACAddr, szBradcast, MacAddrLen);

	lib1x_message(MESS_DBG_CONTROL, "global->RSNVariable.MulticastCipher = %d\n", global->RSNVariable.MulticastCipher);

	Set_Key.EncType = global->RSNVariable.MulticastCipher;
	//sc_yang
	memset(Set_Key.KeyMaterial,0, 64);
	switch(global->RSNVariable.MulticastCipher)
	{
		case DOT11_ENC_NONE:
			ulKeyLength = 0;
			lib1x_message(MESS_DBG_CONTROL, "global->RSNVariable.MulticastCipher = %s\n", "DOT11_ENC_NONE");
			break;
		case DOT11_ENC_WEP40:
			ulKeyLength = 5;
			ulKeyIndex = EAPOL_GROUP_KEY;
			memcpy(Set_Key.KeyMaterial ,
				global->auth->WepGroupKey, //szDefaultKey ,
				ulKeyLength);
			lib1x_message(MESS_DBG_CONTROL, "global->RSNVariable.MulticastCipher = %s\n", "DOT11_ENC_WEP40");
			break;
		case DOT11_ENC_WEP104:
			ulKeyLength =	13;
			ulKeyIndex = EAPOL_GROUP_KEY;
			memcpy(Set_Key.KeyMaterial ,
				global->auth->WepGroupKey, //szDefaultKey ,
				ulKeyLength);
			lib1x_message(MESS_DBG_CONTROL, "global->RSNVariable.MulticastCipher = %s\n", "DOT11_ENC_WEP104");
			break;
		case DOT11_ENC_TKIP:
			ulKeyLength = 32;
			ulKeyIndex = global->auth->gk_sm->GN;
			memcpy(Set_Key.KeyMaterial ,
				global->auth->gk_sm->GTK[global->auth->gk_sm->GN] ,
				ulKeyLength);
			lib1x_message(MESS_DBG_CONTROL, "global->RSNVariable.MulticastCipher = %s\n", "DOT11_ENC_TKIP");
			break;
		// Kenny
		case DOT11_ENC_CCMP:
			ulKeyLength = 16;
			ulKeyIndex = global->auth->gk_sm->GN;
			memcpy(Set_Key.KeyMaterial ,
				global->auth->gk_sm->GTK[global->auth->gk_sm->GN] ,
				ulKeyLength);
			lib1x_message(MESS_DBG_CONTROL, "global->RSNVariable.MulticastCipher = %s\n", "DOT11_ENC_CCMP");
			break;
#ifdef CONFIG_IEEE80211W
		case DOT11_ENC_BIP:
			ulKeyLength = 16;
			ulKeyIndex = global->auth->gk_sm->GN_igtk;
			memcpy(Set_Key.KeyMaterial ,
				global->auth->gk_sm->IGTK[global->auth->gk_sm->GN_igtk] ,
				ulKeyLength);
			lib1x_message(MESS_DBG_CONTROL, "global->RSNVariable.MulticastCipher = %s\n", "DOT11_ENC_BIP");
			break;
#endif
	}

#ifdef RTL_WPA2
	//wpa2_hexdump("lib1x_control_SetGTK: GTK",Set_Key.KeyMaterial,ulKeyLength);
#endif

	ptr = (u_char*)&Set_Key.KeyLen;
	long2net(ulKeyLength, ptr);

	ptr = (u_char*)&Set_Key.KeyIndex;
	long2net(ulKeyIndex, ptr);

	wrq.u.data.length = sizeof(DOT11_SET_KEY) - 1 + ulKeyLength;

#ifdef ALLOW_DBG_CONTROL
	lib1x_hexdump2(MESS_DBG_CONTROL, "lib1x_control_SetGTK", wrq.u.data.pointer, wrq.u.data.length, "Set Group Key");
#endif
	lib1x_akmsm_dump(global);
        if(ioctl(global->auth->GlobalTxRx->fd_control, SIOCGIWIND, &wrq) < 0)
                retVal = -1;
        else
                retVal = 0;

        return retVal;
#if 0
	int retVal = 0;
	u_long	ulKeyLength = 0;
	u_char * ptr;
	struct iwreq wrq;
	DOT11_SET_KEY  Set_Key;
	u_char	szBradcast[] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};


	lib1x_message(MESS_DBG_CONTROL, "lib1x_control_SetGTK(1)\n");

	strncpy(wrq.ifr_name, global->auth->GlobalTxRx->device_wlan0, IFNAMSIZ);
	wrq.u.data.pointer = (caddr_t)&Set_Key;
	wrq.u.data.length = sizeof(DOT11_SET_KEY);

	Set_Key.EventId = DOT11_EVENT_SET_KEY;
	Set_Key.IsMoreEvent = FALSE;
	ptr = (u_char*)&Set_Key.KeyIndex;
#ifndef RTL_WPA_CLIENT
	long2net(global->auth->gk_sm->GN, ptr);
#endif
	Set_Key.KeyType = DOT11_KeyType_Group;
	memcpy(&Set_Key.MACAddr, szBradcast, MacAddrLen);

	lib1x_message(MESS_DBG_CONTROL, "global->RSNVariable.MulticastCipher = %d\n", global->RSNVariable.MulticastCipher);

	Set_Key.EncType = global->RSNVariable.MulticastCipher;

	switch(global->RSNVariable.MulticastCipher)
	{
		case DOT11_ENC_NONE:
			ulKeyLength = 0;
			lib1x_message(MESS_DBG_CONTROL, "global->RSNVariable.MulticastCipher = %s\n", "DOT11_ENC_NONE");
			break;
		case DOT11_ENC_WEP40:
			ulKeyLength = 5;
			memcpy(Set_Key.KeyMaterial ,
				global->auth->WepGroupKey, //szDefaultKey ,
				ulKeyLength);
#ifdef RTL_WPA_CLIENT
			long2net(0, ptr);
#endif

			lib1x_message(MESS_DBG_CONTROL, "global->RSNVariable.MulticastCipher = %s\n", "DOT11_ENC_WEP40");
			break;
		case DOT11_ENC_WEP104:
			ulKeyLength =	13;
			memcpy(Set_Key.KeyMaterial ,
				global->auth->WepGroupKey, //szDefaultKey ,
				ulKeyLength);
#ifdef RTL_WPA_CLIENT
                        long2net(0, ptr);
#endif
			lib1x_message(MESS_DBG_CONTROL, "global->RSNVariable.MulticastCipher = %s\n", "DOT11_ENC_WEP104");
			break;
		case DOT11_ENC_TKIP:
			ulKeyLength = 32;
			memcpy(Set_Key.KeyMaterial ,
				global->auth->gk_sm->GTK[global->auth->gk_sm->GN] ,
				ulKeyLength);
#ifdef RTL_WPA_CLIENT
			long2net(global->auth->gk_sm->GN, ptr);
#endif
			lib1x_message(MESS_DBG_CONTROL, "global->RSNVariable.MulticastCipher = %s\n", "DOT11_ENC_TKIP");
			break;


	}


	ptr = (u_char*)&Set_Key.KeyLen;
	long2net(ulKeyLength, ptr);

	wrq.u.data.length = sizeof(DOT11_SET_KEY) - 1 + ulKeyLength;

#ifdef ALLOW_DBG_CONTROL
	lib1x_hexdump2(MESS_DBG_CONTROL, "lib1x_control_SetGTK", wrq.u.data.pointer, wrq.u.data.length, "Set Group Key");
#endif
	lib1x_akmsm_dump(global);
        if(ioctl(global->auth->GlobalTxRx->fd_control, SIOCGIWIND, &wrq) < 0)
                retVal = -1;
        else
                retVal = 0;

        return retVal;
#endif
}
#ifdef CONFIG_IEEE80211W
int lib1x_control_SetIGTK(Global_Params * global)
{


	int retVal = 0;
	u_long	ulKeyLength = 0;
	u_long  ulKeyIndex = 0;
	u_char * ptr;
	struct iwreq wrq;
	DOT11_SET_KEY  Set_Key;
	u_char	szBradcast[] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};

	/*
	u_char	szDefaultKey[16] = {0x11, 0x11,0x11, 0x11,0x11, 0x11,0x11, 0x11,
					0x11, 0x11,0x11, 0x11,0x11, 0x11,0x11, 0x11};
	*/


	lib1x_message(MESS_DBG_CONTROL, "lib1x_control_SetIGTK\n");

	strncpy(wrq.ifr_name, global->auth->GlobalTxRx->device_wlan0, IFNAMSIZ);
	wrq.u.data.pointer = (caddr_t)&Set_Key;
	wrq.u.data.length = sizeof(DOT11_SET_KEY);

	Set_Key.EventId = DOT11_EVENT_SET_KEY;
	Set_Key.IsMoreEvent = FALSE;

	Set_Key.KeyType = DOT11_KeyType_IGTK;
	memcpy(&Set_Key.MACAddr, szBradcast, MacAddrLen);

	Set_Key.EncType = DOT11_ENC_BIP;
	//sc_yang
	memset(Set_Key.KeyMaterial,0, 64);

	// Set IGTK
	ulKeyLength = 16;
	ulKeyIndex = global->auth->gk_sm->GN_igtk;
	memcpy(Set_Key.KeyMaterial ,
		global->auth->gk_sm->IGTK[global->auth->gk_sm->GN_igtk-4] ,
		ulKeyLength);
	lib1x_message(MESS_DBG_CONTROL, "global->RSNVariable.MulticastCipher = %s\n", "DOT11_ENC_BIP");

#ifdef RTL_WPA2
	//wpa2_hexdump("lib1x_control_SetGTK: GTK",Set_Key.KeyMaterial,ulKeyLength);
#endif

	ptr = (u_char*)&Set_Key.KeyLen;
	long2net(ulKeyLength, ptr);

	ptr = (u_char*)&Set_Key.KeyIndex;
	long2net(ulKeyIndex, ptr);

	wrq.u.data.length = sizeof(DOT11_SET_KEY) - 1 + ulKeyLength;

#ifdef ALLOW_DBG_CONTROL
	lib1x_hexdump2(MESS_DBG_CONTROL, "lib1x_control_SetGTK", wrq.u.data.pointer, wrq.u.data.length, "Set Group Key");
#endif
	lib1x_akmsm_dump(global);
        if(ioctl(global->auth->GlobalTxRx->fd_control, SIOCGIWIND, &wrq) < 0)
                retVal = -1;
        else
                retVal = 0;

        return retVal;

}
#endif

int lib1x_control_SetPORT(Global_Params * global, u_char status)
{
	int retVal = 0;
	struct iwreq wrq;
	DOT11_SETPORT	Set_Port;


	lib1x_message(MESS_DBG_CONTROL, "lib1x_control_SetPORT(1)\n");
#ifdef CONFIG_RTL_ETH_802DOT1X_SUPPORT
	if(global->auth->currentRole == role_eth){
		return lib1x_control_eth_SetPORT(global,status);
	}
#endif

	strncpy(wrq.ifr_name, global->auth->GlobalTxRx->device_wlan0, IFNAMSIZ);
	wrq.u.data.pointer = (caddr_t)&Set_Port;
	wrq.u.data.length = sizeof(DOT11_SETPORT);


	Set_Port.EventId = DOT11_EVENT_SET_PORT;

	Set_Port.PortStatus = status;
	Set_Port.PortType = global->AuthKeyMethod;

	memcpy(&Set_Port.MACAddr, global->theAuthenticator->supp_addr, MacAddrLen);


	if(Set_Port.PortStatus == DOT11_PortStatus_Authorized)
	{
		lib1x_message(MESS_DBG_CONTROL, "Set Port Authorized for STA =>");
	}
	else if(Set_Port.PortStatus == DOT11_PortStatus_Unauthorized)
	{
		lib1x_message(MESS_DBG_CONTROL, "Set Port Unathorized for STA =>\n");
	}
	lib1x_PrintAddr(global->theAuthenticator->supp_addr);

	if(ioctl(global->auth->GlobalTxRx->fd_control, SIOCGIWIND, &wrq) < 0)
                retVal = -1;
        else
                retVal = 0;


        return retVal;


}

int lib1x_control_SetExpiredTime(Global_Params * global, u_long ulExpireTime)
{
	int retVal = 0;
	struct iwreq wrq;
	DOT11_SET_EXPIREDTIME	Set_Expiretime;


	lib1x_message(MESS_DBG_CONTROL, "lib1x_control_SetExpiredTime(1)\n");


	strncpy(wrq.ifr_name, global->auth->GlobalTxRx->device_wlan0, IFNAMSIZ);
	wrq.u.data.pointer = (caddr_t)&Set_Expiretime;
	wrq.u.data.length = sizeof(DOT11_SET_EXPIREDTIME);


	Set_Expiretime.EventId = DOT11_EVENT_ACC_SET_EXPIREDTIME;
	Set_Expiretime.ExpireTime = ulExpireTime;
	memcpy(&Set_Expiretime.MACAddr, global->theAuthenticator->supp_addr, MacAddrLen);



	if(ioctl(global->auth->GlobalTxRx->fd_control, SIOCGIWIND, &wrq) < 0)
                retVal = -1;
        else
                retVal = 0;


        return retVal;


}


int lib1x_control_Set802dot1x(Global_Params * global, u_char var_type, u_char var_val)
{

	int retVal = 0;
	struct iwreq wrq;
	DOT11_SET_802DOT11 Set_802dot1x;

	lib1x_message(MESS_DBG_CONTROL, "lib1x_control_Set802dot1x\n");

	strncpy(wrq.ifr_name, global->auth->GlobalTxRx->device_wlan0, IFNAMSIZ);
	wrq.u.data.pointer = (caddr_t)&Set_802dot1x;
	wrq.u.data.length = sizeof(DOT11_SET_802DOT11);

	Set_802dot1x.EventId = DOT11_EVENT_SET_802DOT11;
	Set_802dot1x.IsMoreEvent = FALSE;
	Set_802dot1x.VariableType = var_type;
	Set_802dot1x.VariableValue = var_val;
	memcpy(&Set_802dot1x.MACAddr, global->theAuthenticator->supp_addr, MacAddrLen);


    if(ioctl(global->auth->GlobalTxRx->fd_control, SIOCGIWIND, &wrq) < 0)
       retVal = -1;
    else
       retVal = 0;

    return retVal;
}

int lib1x_control_InitQueue(Dot1x_Authenticator * auth)
{
	int retVal = 0;
	struct iwreq wrq;
	DOT11_INIT_QUEUE Init_Queue;

	lib1x_message(MESS_DBG_CONTROL, "lib1x_control_InitQueue\n");

	strncpy(wrq.ifr_name, auth->GlobalTxRx->device_wlan0, IFNAMSIZ);
	wrq.u.data.pointer = (caddr_t)&Init_Queue;
	wrq.u.data.length = sizeof(DOT11_INIT_QUEUE);

	Init_Queue.EventId = DOT11_EVENT_INIT_QUEUE;

	if(ioctl(auth->GlobalTxRx->fd_control, SIOCGIWIND, &wrq) < 0)
        retVal = -1;
    else
        retVal = 0;

    return retVal;

}

/*-----------------------------------------------------------------------
 char2str:
 change character to string ex: 0x0a->'A' 0x08->'8'
 uzOut : the output string buffer
 ulOutStart : the start address of where the converted string is put in
-----------------------------------------------------------------------*/
void char2str(u_char * uzIn, u_long ulLen, u_char * uzOut, u_long ulOutStart)
{
        u_long i, j=ulOutStart;
        char cHigh, cLow;

        int iIntDist = '0' - 0x00;
        int iCharDist = 'A' - 0x0a;

        for(i=0 ; i<ulLen ; i++)
        {
            cHigh = (uzIn[i]>>4) & 0x0f;
            cLow  = (uzIn[i]) & 0x0f;

            //0x0~0x9 or 0xa~0xf
            uzOut[j++] = (cHigh>=0 && cHigh<=9) ? (cHigh + iIntDist) : (cHigh + iCharDist);
            uzOut[j++] = (cLow >=0 && cLow <=9) ? (cLow  + iIntDist) : (cLow  + iCharDist);

        }
        uzOut[j] = 0;


}
//----------------------------------------------------------
// Check if key is avaliable before this function is called
//----------------------------------------------------------
#ifdef HW_CAM_CONFIG
int lib1x_control_KeyMapping(Global_Params * global, u_char operation, u_char keytype, u_char keyvalid)
{

	int retVal = 0;
	u_long	ulLen = 0;
	u_char	szCmd[512];
	struct iwreq wrq;


	lib1x_message(MESS_DBG_CONTROL, "lib1x_control_KeyMapping\n");


	strncpy(wrq.ifr_name, global->auth->GlobalTxRx->device_wlan0, IFNAMSIZ);
	wrq.u.data.pointer = (caddr_t)szCmd;
	wrq.u.data.length = sizeof(DOT11_INIT_QUEUE);

	memset(szCmd, 0, sizeof szCmd);

	//----PRIV_CMD_AP_KEYMAP_OPERATION----
	sprintf(szCmd, "KMOP=%s,", (u_char*)rtl_priv_kmop_args[operation].arg_name);
	ulLen = strlen(szCmd);



	//----PRIV_CMD_AP_KEYMAP_MAC_ADDRESS----
	sprintf(szCmd + ulLen, "KMAR=");
	ulLen += strlen("KMAR=");
 	char2str(global->theAuthenticator->supp_addr, MacAddrLen, szCmd, ulLen);
	szCmd[ulLen + MacAddrLen*2] = ',';
	ulLen = strlen(szCmd);

	//---- PRIV_CMD_AP_KEYMAP_KEY40 or PRIV_CMD_AP_KEYMAP_KEY104
	if(global->RSNVariable.UnicastCipher == DOT11_ENC_WEP40 )
	{
		sprintf(szCmd + ulLen, "KMKEY40=");
		ulLen += strlen("KMKEY40=");
		char2str(global->RadiusKey.RecvKey.Octet, 5, szCmd, ulLen);
		szCmd[ulLen + 5*2] = ',';
		ulLen = strlen(szCmd);

	}else if(global->RSNVariable.UnicastCipher == DOT11_ENC_WEP104 )
	{
		sprintf(szCmd + ulLen, "KMKEY104");
		ulLen += strlen("KMKEY104");
		char2str(global->RadiusKey.RecvKey.Octet, 13, szCmd, ulLen);
		szCmd[ulLen + 13*2] = ',';
		ulLen = strlen(szCmd);

	}


	//---- PRIV_CMD_AP_KEYMAP_KEY_INDEX ----
	sprintf(szCmd + ulLen, "KMIDX=0x3,");//according to IETF dratf, key-mapping-key use index 3
	ulLen = strlen(szCmd);

	//---- PRIV_CMD_AP_KEYMAP_KEY_TYPE ----
	sprintf(szCmd + ulLen, "KMTYPE=%s,", rtl_priv_wepmode_args[keytype].arg_name);
	ulLen = strlen(szCmd);

	//---- PRIV_CMD_AP_KEYMAP_KEY_VALID ----
	sprintf(szCmd + ulLen, "KMVALID=%s",  rtl_priv_kmvalid_args[keyvalid].arg_name);
	ulLen = strlen(szCmd);


	//=================================================================================


	return retVal;
}
#endif

int lib1x_control_Poll(Dot1x_Authenticator * auth)
{
	int 		retVal = 0;
 	struct iwreq          wrq;
	DOT11_REQUEST         * req;
	unsigned char  		szEvent[64];


	/* Get wireless qame */
	strncpy(wrq.ifr_name, auth->GlobalTxRx->device_wlan0, IFNAMSIZ);

	req = (DOT11_REQUEST *)malloc(sizeof(DOT11_REQUEST));
	wrq.u.data.pointer = (caddr_t)req;
	req->EventId = DOT11_EVENT_REQUEST;
	wrq.u.data.length = sizeof(DOT11_EVENT_REQUEST);

	auth->IoctlBufLen = 0;

    if(ioctl(auth->GlobalTxRx->fd_control, SIOCGIWIND, &wrq) < 0)
	{
		free(req);
        return(-1);
	}
    else{
       	memset(auth->IoctlBuf, 0, sizeof auth->IoctlBuf);
    	memcpy(auth->IoctlBuf,wrq.u.data.pointer, wrq.u.data.length);
    	memset(szEvent, 0, sizeof szEvent);
    	switch(auth->IoctlBuf[0])
    	{
        	case	DOT11_EVENT_NO_EVENT:
        		sprintf(szEvent, (char*)"Receive Event %s", "NO_EVENT");
        		break;
        	case	DOT11_EVENT_ASSOCIATION_IND:
        		sprintf(szEvent, (char*)"Receive Event %s", "ASSOCIATION_IND");
        		auth->IoctlBufLen = wrq.u.data.length;
        		break;
        	case	DOT11_EVENT_REASSOCIATION_IND:
        		sprintf(szEvent, (char*)"Receive Event %s", "REASSOCIATION_IND");
        		auth->IoctlBufLen = wrq.u.data.length;
        		break;
        	case 	DOT11_EVENT_AUTHENTICATION_IND:
        		sprintf(szEvent, (char*)"Receive Event %s", "AUTHENTICATION_IND");
        		//auth->IoctlBufLen = wrq.u.data.length;
        		break;
        	case	DOT11_EVENT_REAUTHENTICATION_IND:
        		sprintf(szEvent, (char*)"Receive Event %s", "REAUTHENTICATION_IND");
        		auth->IoctlBufLen = wrq.u.data.length;
        		break;
        	case	DOT11_EVENT_DEAUTHENTICATION_IND:
        		sprintf(szEvent, (char*)"Receive Event %s", "DEAUTHENTICATION_IND");
        		auth->IoctlBufLen = wrq.u.data.length;
        		break;
        	case	DOT11_EVENT_DISASSOCIATION_IND:
        		sprintf(szEvent, (char*)"Receive Event %s", "DISASSOCIATION_IND");
        		auth->IoctlBufLen = wrq.u.data.length;
        		break;
        	case 	DOT11_EVENT_MIC_FAILURE:
        		sprintf(szEvent, (char*)"Receive Event %s", "MIC_FAILURE");
        		auth->IoctlBufLen = wrq.u.data.length;
        		break;
        	default:
        		sprintf(szEvent, (char*)"Receive %s Event id %d ", "Invalid", auth->IoctlBuf[0]);
        		break;

    	}


    	if(auth->IoctlBufLen)
    	{
    		lib1x_message(MESS_DBG_CONTROL, szEvent);
    		//lib1x_nal_receiveioctl(auth);
    		//lib1x_capture_control_x(auth->Supp[0]->global);
    		//write(1, "end of lib1x_capture_control_x\n", sizeof("lib1x_capture_control_x\n"));
    	}
    	free(req);
    	retVal = 0;

    }

        return retVal;
}



int lib1x_control_IndicateMICFail(Dot1x_Authenticator * auth, u_char *mac)
{
	int retVal = 0;
	struct iwreq wrq;
	DOT11_MIC_FAILURE MIC_Failure;

	lib1x_message(MESS_DBG_CONTROL, "lib1x_control_IndicateMICFail\n");

	strncpy(wrq.ifr_name, auth->GlobalTxRx->device_wlan0, IFNAMSIZ);
	wrq.u.data.pointer = (caddr_t)&MIC_Failure;
	wrq.u.data.length = sizeof(DOT11_INIT_QUEUE);

	MIC_Failure.EventId = DOT11_EVENT_MIC_FAILURE;
	//sc_yang
	memcpy(MIC_Failure.MACAddr, mac, MacAddrLen);
	lib1x_PrintAddr(MIC_Failure.MACAddr);

	if(ioctl(auth->GlobalTxRx->fd_control, SIOCGIWIND, &wrq) < 0)
        retVal = -1;
    else
        retVal = 0;


        return retVal;
}

#ifdef CONFIG_RTL_ETH_802DOT1X_SUPPORT
/*      IOCTL system call */
int re865xIoctl(char *name, unsigned int arg0, unsigned int arg1, unsigned int arg2, unsigned int arg3)
{
	unsigned int args[4];
	struct ifreq ifr;
	int sockfd;

	args[0] = arg0;
	args[1] = arg1;
	args[2] = arg2;
	args[3] = arg3;
	//printf("%s-->%d,%s\n",__FUNCTION__,__LINE__,name);
	if ((sockfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0)
	{
		perror("fatal error socket\n");
		return -3;
	}
  
	strcpy((char*)&ifr.ifr_name, name);
	((unsigned int *)(&ifr.ifr_data))[0] = (unsigned int)args;

	if (ioctl(sockfd, SIOCDEVPRIVATE, &ifr)<0)
	{
	  perror("device ioctl:");
	  close(sockfd);
	  return -1;
	}
	close(sockfd);
	return 0;
	
}
//static rtl802Dot1xAuthResult result;
int lib1x_control_eth_SetPORT(Global_Params * global, u_char status)
{
	//unsigned int arg[0];
	unsigned int ret;
	rtl802Dot1xAuthResult result;
	
	lib1x_message(MESS_DBG_CONTROL, "lib1x_control_eth_SetPORT\n");
	//arg[0] = (unsigned int)&result;
	memset(&result, 0x00, sizeof(rtl802Dot1xAuthResult));
	result.type = global->auth->ethDot1xProxyType;
	result.port_num = global->port_num;
	lib1x_message(MESS_DBG_CONTROL, "Set auth result type=%d portnumber %d (unsigned int)&result=0x%x\n", result.type, result.port_num, (unsigned int)&result);
	
	if (result.type == ETH_DOT1X_PROXY_PORT_BASE)
	{
		lib1x_message(MESS_DBG_CONTROL, "Set auth result port base\n");
	}
	else if (result.type == ETH_DOT1X_PROXY_MAC_BASE)
	{
		lib1x_message(MESS_DBG_CONTROL, "Set auth result mac base\n");
	}
	memcpy(&result.mac_addr, global->theAuthenticator->supp_addr, MacAddrLen);
	result.auth_state = status;
	
	lib1x_message(MESS_DBG_CONTROL, "Set auth result.auth_state=%d\n", result.auth_state);
	if(result.auth_state == DOT11_PortStatus_Authorized)
	{
		lib1x_message(MESS_DBG_CONTROL, "Set auth result Authorized\n");
	}
	else if(result.auth_state == DOT11_PortStatus_Unauthorized)
	{
		lib1x_message(MESS_DBG_CONTROL, "Set auth result Unathorized\n");
	}
	lib1x_PrintAddr(global->theAuthenticator->supp_addr);
		
	return re865xIoctl(global->auth->GlobalTxRx->device_eth0, RTL8651_IOCTL_DOT1X_SET_AUTH_RESULT, (unsigned int)&result, 0, (unsigned int)&ret) ;

	return 0;
}


int lib1x_control_eth_register_pid(Dot1x_Authenticator * auth)
{
	int arg[0];
	int pid,ret;
	lib1x_message(MESS_DBG_CONTROL, "lib1x_control_eth_register_pid\n");
	pid = getpid();
	arg[0] = pid;
	
	return re865xIoctl(auth->GlobalTxRx->device_eth0, RTL8651_IOCTL_DOT1X_SETPID, (unsigned int )arg, 0, (unsigned int)&ret) ;

}
/* return more flag */
int lib1x_control_Eth_Poll(Dot1x_Authenticator * auth)
{
	int 		retVal = 0;
	int arg[0];
	//rtl802Dot1xQueueNode *eap;
	unsigned char *event_id = NULL;
	rtl802Dot1xEapPkt *eap;
	rtl802Dot1xPortStateInfo *port_state;
	
	lib1x_message(MESS_DBG_CONTROL, "lib1x_control_Eth_Poll\n");
	memset(auth->GlobalTxRx->RecvBuf, 0, sizeof(auth->GlobalTxRx->RecvBuf));
	if(re865xIoctl(auth->GlobalTxRx->device_eth0, RTL8651_IOCTL_DOT1X_GET_INFO, (unsigned int )arg, 0, (unsigned int)auth->GlobalTxRx->RecvBuf) < 0)
	{
        // If no wireless name : no wireless extensions
        return(-1);
	}
    else{
		event_id = (unsigned char *)auth->GlobalTxRx->RecvBuf;
		if (*event_id == DOT1X_EVENT_PORT_DOWN)
		{
			port_state = (rtl802Dot1xPortStateInfo *) auth->GlobalTxRx->RecvBuf;
			retVal = port_state->flag;
			//portdown handler
			lib1x_process_eth_port_down_event(auth);
		}
		else if (*event_id == DOT1X_EVENT_EAP_PACKET)
		{
			eap = (rtl802Dot1xEapPkt *) auth->GlobalTxRx->RecvBuf;
		
			lib1x_message(MESS_DBG_CONTROL, "Receive ethernet eap packet!!\n");
			lib1x_message(MESS_DBG_CONTROL,"Rx port number = %d\n",eap->rx_port_num);
			retVal = eap->flag;
			lib1x_process_eth_eap_event(auth);
		}
		else if (*event_id == DOT1X_EVENT_PORT_UP)
		{
			port_state = (rtl802Dot1xPortStateInfo *) auth->GlobalTxRx->RecvBuf;
			retVal = port_state->flag;
			//portup handler
			lib1x_process_eth_port_up_event(auth);
		}
#if 0
		memset(szEvent, 0, sizeof szEvent);
		switch(auth->IoctlBuf[0])
		{
		case	DOT11_EVENT_NO_EVENT:
			sprintf(szEvent, (char*)"Receive Event %s", "NO_EVENT");
			break;
		case	DOT11_EVENT_ASSOCIATION_IND:
			sprintf(szEvent, (char*)"Receive Event %s", "ASSOCIATION_IND");
			auth->IoctlBufLen = wrq.u.data.length;
			break;
		case	DOT11_EVENT_REASSOCIATION_IND:
			sprintf(szEvent, (char*)"Receive Event %s", "REASSOCIATION_IND");
			auth->IoctlBufLen = wrq.u.data.length;
			break;
		case 	DOT11_EVENT_AUTHENTICATION_IND:
			sprintf(szEvent, (char*)"Receive Event %s", "AUTHENTICATION_IND");
			//auth->IoctlBufLen = wrq.u.data.length;
			break;
		case	DOT11_EVENT_REAUTHENTICATION_IND:
			sprintf(szEvent, (char*)"Receive Event %s", "REAUTHENTICATION_IND");
			auth->IoctlBufLen = wrq.u.data.length;
			break;
		case	DOT11_EVENT_DEAUTHENTICATION_IND:
			sprintf(szEvent, (char*)"Receive Event %s", "DEAUTHENTICATION_IND");
			auth->IoctlBufLen = wrq.u.data.length;
			break;
		case	DOT11_EVENT_DISASSOCIATION_IND:
			sprintf(szEvent, (char*)"Receive Event %s", "DISASSOCIATION_IND");
			auth->IoctlBufLen = wrq.u.data.length;
			break;
		case 	DOT11_EVENT_MIC_FAILURE:
			sprintf(szEvent, (char*)"Receive Event %s", "MIC_FAILURE");
			auth->IoctlBufLen = wrq.u.data.length;
			break;
		default:
			sprintf(szEvent, (char*)"Receive %s Event id %d ", "Invalid", auth->IoctlBuf[0]);
			break;

		}
#endif
		//free(req);
		//retVal = 0;

        }

        return retVal;
}
#endif

#ifdef CONFIG_IEEE80211R
int lib1x_control_query_ft_info(Dot1x_Authenticator * auth, u_char *mac, DOT11_QUERY_FT_INFORMATION *ft_info)
{
	int retVal = 0;
	struct iwreq wrq;

	lib1x_message(MESS_DBG_CONTROL, "lib1x_control_query_ft_info\n");

	strncpy(wrq.ifr_name, auth->GlobalTxRx->device_wlan0, IFNAMSIZ);
	wrq.u.data.pointer = (caddr_t)ft_info;
	wrq.u.data.length = sizeof(DOT11_QUERY_FT_INFORMATION);

	ft_info->EventId = DOT11_EVENT_FT_QUERY_INFO;
	memcpy(ft_info->sta_addr, mac, MacAddrLen);

	if(ioctl(auth->GlobalTxRx->fd_control, SIOCGIWIND, &wrq) < 0)
		retVal = -1;

	return retVal;
}

int lib1x_control_set_ft_info(Dot1x_Authenticator * auth, DOT11_SET_FT_INFORMATION *ft_info)
{
	int retVal = 0;
	struct iwreq wrq;

	lib1x_message(MESS_DBG_CONTROL, "lib1x_control_query_ft_info\n");

	strncpy(wrq.ifr_name, auth->GlobalTxRx->device_wlan0, IFNAMSIZ);
	wrq.u.data.pointer = (caddr_t)ft_info;
	wrq.u.data.length = sizeof(DOT11_SET_FT_INFORMATION);

	ft_info->EventId = DOT11_EVENT_FT_SET_INFO;

	if(ioctl(auth->GlobalTxRx->fd_control, SIOCGIWIND, &wrq) < 0)
		retVal = -1;

	return retVal;
}

int lib1x_control_ft_set_r0(Dot1x_Authenticator * auth, u_char *mac, u_char *pmk_r0, u_char *pmk_r0_name)
{
	int retVal = 0;
	struct iwreq wrq;
	DOT11_AUTH_FT_INSERT_R0_KEY r0_key;
	
	lib1x_message(MESS_DBG_CONTROL, "lib1x_control_ft_set_r0\n");

	strncpy(wrq.ifr_name, auth->GlobalTxRx->device_wlan0, IFNAMSIZ);
	wrq.u.data.pointer = (caddr_t)&r0_key;
	wrq.u.data.length = sizeof(DOT11_AUTH_FT_INSERT_R0_KEY);

	memset(&r0_key, 0, sizeof(DOT11_AUTH_FT_INSERT_R0_KEY));
	r0_key.EventId = DOT11_EVENT_FT_AUTH_INSERT_R0;
	memcpy(r0_key.sta_addr, mac, MacAddrLen);
	memcpy(r0_key.pmk_r0, pmk_r0, PMK_LEN);
	memcpy(r0_key.pmk_r0_name, pmk_r0_name, PMKID_LEN);

	if(ioctl(auth->GlobalTxRx->fd_control, SIOCGIWIND, &wrq) < 0)
		retVal = -1;

	return retVal;
}

int lib1x_control_ft_set_r1(Dot1x_Authenticator * auth, u_char *mac, u_char *bssid, u_char *r0kh_id, unsigned int r0kh_id_len, 
	u_char *pmk_r1, u_char *pmk_r1_name, u_char *pmk_r0_name, int pairwise)
{
	int retVal = 0;
	struct iwreq wrq;
	DOT11_AUTH_FT_INSERT_R1_KEY r1_key;
	
	lib1x_message(MESS_DBG_CONTROL, "lib1x_control_ft_set_r1\n");

	strncpy(wrq.ifr_name, auth->GlobalTxRx->device_wlan0, IFNAMSIZ);
	wrq.u.data.pointer = (caddr_t)&r1_key;
	wrq.u.data.length = sizeof(DOT11_AUTH_FT_INSERT_R1_KEY);

	memset(&r1_key, 0, sizeof(DOT11_AUTH_FT_INSERT_R1_KEY));
	r1_key.EventId = DOT11_EVENT_FT_AUTH_INSERT_R1;
	memcpy(r1_key.sta_addr, mac, MacAddrLen);
	memcpy(r1_key.bssid, bssid, MacAddrLen);
	memcpy(r1_key.r0kh_id, r0kh_id, r0kh_id_len);
	r1_key.r0kh_id_len = r0kh_id_len;
	memcpy(r1_key.pmk_r1, pmk_r1, PMK_LEN);
	memcpy(r1_key.pmk_r1_name, pmk_r1_name, PMKID_LEN);
	memcpy(r1_key.pmk_r0_name, pmk_r0_name, PMKID_LEN);
	r1_key.pairwise = pairwise;

	if(ioctl(auth->GlobalTxRx->fd_control, SIOCGIWIND, &wrq) < 0)
		retVal = -1;

	return retVal;
}

int lib1x_control_ft_trigger_event(Dot1x_Authenticator * auth, u_char *mac, u_char event_id)
{
	int retVal = 0;
	struct iwreq wrq;
	DOT11_AUTH_FT_TRIGGER_EVENT event;

	lib1x_message(MESS_DBG_CONTROL, "lib1x_control_ft_trigger_event\n");

	strncpy(wrq.ifr_name, auth->GlobalTxRx->device_wlan0, IFNAMSIZ);
	wrq.u.data.pointer = (caddr_t)&event;
	wrq.u.data.length = sizeof(DOT11_AUTH_FT_TRIGGER_EVENT);

	event.EventId = DOT11_EVENT_FT_TRIGGER_EVENT;
	event.trigger_eventid = event_id;
	memcpy(event.sta_addr, mac, MacAddrLen);

	if(ioctl(auth->GlobalTxRx->fd_control, SIOCGIWIND, &wrq) < 0)
		retVal = -1;

	return retVal;

}

#endif

