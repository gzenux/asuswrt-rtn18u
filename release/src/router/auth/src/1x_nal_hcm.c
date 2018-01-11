
//--------------------------------------------------
// IEEE 802.1x Implementation
//
// File		: 1x_nal
// Programmer	: Arunesh Mishra
// This file implements the 1x-Network Abstraction
// Layer part.
// Copyright (c) Arunesh Mishra 2002
// All rights reserved.
// Maryland Information and Systems Security Lab
// University of Maryland, College Park.
//--------------------------------------------------




#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>
#include <sys/poll.h>
#include <netinet/in.h>
#include <unistd.h>
#include <fcntl.h>
#include <error.h>
#include <string.h>


#include "1x_nal.h"
#include "1x_ethernet.h"
#include "1x_eapol.h"
#include "1x_auth_pae.h"
#include "1x_fifo.h"
#include "1x_ioctl.h"



#ifdef RTL_WPA_CLIENT
#include "1x_supp_pae.h"
extern Dot1x_Client		RTLClient;
#endif

#ifdef START_AUTH_IN_LIB
extern int read_wlan_evt(	int skfd, char *ifname, char *out);
#endif

#define INBAND_HDRLEN 24
#ifdef CONFIG_RTL8196C_AP_HCM
#define INBAND_DEBUG 0
#define DEST_MAC ("00E04C8196C1")
#define ETH_P_RTK_NOTIFY 0x9001
#endif


#define EAP_BY_QUEUE

//--------------------------------------------------
// initialize pkt sender and receiver
// TODO: currently  cannot get our own ethernet
// addr .. needs to be fixed.
//--------------------------------------------------
struct lib1x_nal_intfdesc *  lib1x_nal_initialize( u_char * intdev , u_char * ouraddr, u_char inttype)
{
	 struct lib1x_nal_intfdesc * desc;
#ifndef EAP_BY_QUEUE
	 struct ifreq ifr;
	 int flags;
	 int retval;
#endif

	if ( intdev == NULL )
		 lib1x_message( MESS_ERROR_FATAL, "lib1x_nal_intfdesc: Received NULL interface to open.");

	//1. General initializations
	 desc = ( struct lib1x_nal_intfdesc * ) malloc( sizeof ( struct lib1x_nal_intfdesc ) );
	 strncpy(desc->device, intdev, LIB1X_MAXDEVLEN);
	 desc->device[LIB1X_MAXDEVLEN] = '\0';

	 desc->inttype = inttype;
	 memcpy( desc->ouraddr, ouraddr, ETHER_ADDRLEN);
	 //2. Specific to the listener
         desc->promisc_mode = LIB1X_LSTNR_PROMISCMODE;
	 desc->snaplen = LIB1X_LSTNR_SNAPLEN;
	 desc->read_timeout = LIB1X_LSTNR_RDTIMEOUT;
	 //desc->packet_handler = NULL ;
	//desc->global = global;	// not sure if we need this sort of backlink
	//sc_yang
#if 0
	 //desc->pcap_desc =  lib1x_nal_setup_pcap( desc );
         if ( desc->pcap_desc == NULL )
         {
              fprintf(stderr," Could not open device : %s", intdev  );
              exit(1);
         }
#endif

	/* 1. Create a socket */
#ifndef EAP_BY_QUEUE
	 desc->pf_sock = socket( PF_PACKET, SOCK_RAW, htons(ETH_P_ALL ) );	// P_ALL coz we dont have P_EAPOL yet in if_ether.h !
	 if ( desc->pf_sock > 0 ) lib1x_message( MESS_DBG_NAL,"PF_PACKET socket created ");
#endif
	// kenny
	// desc->pf_sock = pcap_fileno(desc->pcap_desc);



	 if ( inttype == LIB1X_IT_PKTSOCK )
	 {
#ifndef EAP_BY_QUEUE
	 /* 2. Bind to an eth interface */
	 /* to do the bind we need to get if_index i.e. the interface index */
	 	strncpy( ifr.ifr_name, desc->device, IFNAMSIZ -1  );
	 	if ( ( retval = ioctl( desc->pf_sock, SIOCGIFINDEX , & ifr )) < 0 )    /* SIOCGIFINDEX gets the if_index into the ifr struct */
			 lib1x_message( MESS_ERROR_FATAL, "nal: IOCTL failed on %s", desc->device );

	 	// prepare for bind .. : man netdevice
	 	desc->sock_device.sll_protocol = htons( ETH_P_ALL );
	 	desc->sock_device.sll_family = AF_PACKET;
	 	desc->sock_device.sll_ifindex = ifr.ifr_ifindex;
	 	if ( ( retval = bind( desc->pf_sock,  (struct sockaddr *)&desc->sock_device, sizeof(struct sockaddr_ll ))) != 0 )
		 	lib1x_message( MESS_ERROR_FATAL, "nal: BIND failed on %s retval : %d errorstr : %s", desc->device , retval, strerror(errno));


	 	flags = fcntl(desc->pf_sock, F_GETFL );
	 	if ( fcntl( desc->pf_sock, F_SETFL, flags | O_NONBLOCK) != 0 )
		 	lib1x_message( MESS_ERROR_FATAL, "nal: FCNTL failed on %s", desc->device );
#endif

		//3. Specific to the transmitter
		desc->libnet_desc = libnet_open_link_interface( intdev , desc->l_errbuf );
	 	if ( desc->libnet_desc == NULL )
		 	lib1x_message( MESS_ERROR_FATAL, "lib1x_nal_intfdesc: Could not open libnet interface ");
	}
	 else
	 {
	 	//---- Radius Authentication Server
		desc->udpsock = socket( PF_INET, SOCK_DGRAM, IPPROTO_UDP);\
		if ( desc->udpsock == -1 )
			lib1x_message(MESS_ERROR_FATAL,"lib1x_nal_initialize: Could not open Radius Authentication UDP socket !");

		desc->acctsock = socket( PF_INET, SOCK_DGRAM, IPPROTO_UDP);\
		if ( desc->acctsock == -1 )
			lib1x_message(MESS_ERROR_FATAL,"lib1x_nal_initialize: Could not open Radius Accounting UDP socket !");

	 //	 flags = fcntl(desc->udpsock, F_GETFL );
	 //	if ( fcntl( desc->udpsock, F_SETFL, flags | O_NONBLOCK) != 0 )
	//	 	lib1x_message( MESS_ERROR_FATAL, "nal: FCNTL failed on UDP socket" );
	 }
	desc->packet_buffer = ( u_char * ) malloc( LIB1X_MAXEAPLEN * sizeof(u_char));


	return desc;
}

//--------------------------------------------------
// Bind to the RADIUS server, and connect: this function specifically
// for the wired interface.
// Return 0: Success, Return -1 Fail
//--------------------------------------------------
int lib1x_nal_connect( struct lib1x_nal_intfdesc * desc,  /*u_short udp_ourport,*/ struct sockaddr_in *svraddr ,
			int addrlen, int udpsock_type)
{
	int flags;
	struct sockaddr_in myaddr;


	if ( desc->inttype != LIB1X_IT_UDPSOCK )
		return -1;

	// First bind to a local port
	memset( &myaddr, 0, sizeof(myaddr));
	myaddr.sin_family = AF_INET;
	myaddr.sin_addr.s_addr = htonl(INADDR_ANY);
	myaddr.sin_port = htons(0);

	switch(udpsock_type)
	{
	case LIB1X_IT_UDPSOCK_AUTH:

		if ( bind( desc->udpsock, (struct sockaddr *) & myaddr, sizeof( struct sockaddr_in)) != 0)
			lib1x_message( MESS_ERROR_FATAL,"Could not BIND Authentication server UDP socket.");


		desc->radsvraddr = svraddr;
		if (svraddr == NULL )
		{
			lib1x_message(MESS_DBG_NAL,"lib1x_nal_connect: NULL argument svraddr ");
			return -1;

		}

		// wait till succeed
		while (1) {
			if (connect( desc->udpsock, (struct sockaddr *)svraddr, addrlen ) != 0 )
			{
				lib1x_message(MESS_DBG_NAL,"lib1x_nal_connect: Could not connect to Authentication Server . ");
				sleep(1);
			}
			else
				break;
		}		

		flags = fcntl(desc->udpsock, F_GETFL );
		if ( fcntl( desc->udpsock, F_SETFL, flags | O_NONBLOCK) != 0 )
			lib1x_message( MESS_ERROR_FATAL, "lib1x_nal_connect : FCNTL failed on UDP socket" );
		break;

	case LIB1X_IT_UDPSOCK_ACCT:


		if ( bind( desc->acctsock, (struct sockaddr *) & myaddr, sizeof( struct sockaddr_in)) != 0)
			lib1x_message( MESS_ERROR_FATAL,"Could not BIND Accounting server UDP socket.");


		desc->acctsvraddr = svraddr;
		if (svraddr == NULL )
		{
			lib1x_message(MESS_DBG_NAL,"lib1x_nal_connect: NULL argument svraddr ");
			return -1;

		}
		if ( connect( desc->acctsock, (struct sockaddr *)svraddr, addrlen ) != 0 )
		{
			lib1x_message(MESS_DBG_NAL,"lib1x_nal_connect: Could not connect to Accounting Server. ");
			return -1;

		}

		flags = fcntl(desc->acctsock, F_GETFL );
		if ( fcntl( desc->acctsock, F_SETFL, flags | O_NONBLOCK) != 0 )
			lib1x_message( MESS_ERROR_FATAL, "lib1x_nal_connect : FCNTL failed on UDP socket" );

		break;

	default:
		break;
	}

	return 0;
	//--- TESTING PART
	/*
	for ( i = 0; i < 100; i ++ )
		pkt[i] = (u_char) i % 255;

	//errcode = sendto( desc->udpsock, (u_char *) pkt, 99, 0, desc->radsvraddr, sizeof( struct sockaddr_in));
	errcode = sendto( desc->acctsock, (u_char *) pkt, 99, 0, desc->acctsvraddr, sizeof( struct sockaddr_in));
	if(errcode <= 0)
		printf("\n\n HEY the error for lib1x_nal_connect is %s", strerror(errno) );
	fflush(stdout);
	*/

}
#if 0 //sc_yang
/* just print a count every time we have a packet...                        */
void my_callback(u_char *useless,const struct pcap_pkthdr* pkthdr,const u_char*
        packet)
{
    static int count = 1;
    fprintf(stdout,"%d, ",count);
    fflush(stdout);
    count++;
}
//--------------------------------------------------
// initializes pcap
//--------------------------------------------------
pcap_t *  lib1x_nal_setup_pcap( struct lib1x_nal_intfdesc * nd )
{
	 pcap_t* pcap_descr;                   /* pcap connection */
	 bpf_u_int32 pcap_maskp;               /* subnet mask */
	 bpf_u_int32 pcap_netp;                /* ip (not really sure) */
	 char pcap_filter[100];                /* filter for EAPOL pack */
	 struct bpf_program pcap_fp;           /* To hold the compiled filter */
	 u_char * eapol_src;

	 pcap_lookupnet( nd->device , &pcap_netp, &pcap_maskp, nd->p_errbuf );
	 pcap_descr = pcap_open_live( nd->device, nd->snaplen, 0, -1, nd->p_errbuf);

        /* Open Socket */
        if(pcap_descr == NULL)
	{
		    printf("pcap_open_live(): %s\n", nd->p_errbuf);
		    exit(1);
	}

	eapol_src = nd->ouraddr;
	  /* Setup filter */


	 sprintf(pcap_filter, "ether dst %x:%x:%x:%x:%x:%x and ether proto 0x%x",
		            eapol_src[0], eapol_src[1], eapol_src[2], eapol_src[3],
		              eapol_src[4], eapol_src[5],  LIB1X_ETHER_EAPOL_TYPE );

	//sprintf(pcap_filter, "ether proto 0x%x", LIB1X_ETHER_EAPOL_TYPE );


        if(pcap_compile(pcap_descr,&pcap_fp,pcap_filter,0,pcap_netp) == -1)
		          {
				  fprintf(stderr,"Error calling pcap_compile\n");
				  exit(1);
			  }


	//sprintf(pcap_filter, "src 172.20.13.220");
        //printf("SET FILTER: %s\n", pcap_filter);
	/*

        if(pcap_compile(pcap_descr,&pcap_fp,pcap_filter,0,pcap_netp) == -1)
                          {
                                  fprintf(stderr,"Error calling pcap_compile\n");
                                  exit(1);
                          }
	*/
        if(pcap_setfilter(pcap_descr,&pcap_fp) == -1)
			    {
				    fprintf(stderr,"Error setting filter\n");
				    exit(1);
			    }

	 //pcap_loop(pcap_descr,-1,my_callback,NULL);
         return pcap_descr;
}
#endif //sc_yang

//--------------------------------------------------
// lib1x_nal_receivepoll:
//   This function polls the interface for any packets
//   that might have come.
//   TODO: Currently we expose the libpcap handler to
//   the EAP layer. We need to put a level of abstraction here.
//--------------------------------------------------

#define _AUTH_DBGMSG(fmt, args...)	\
			do {printf("[%s-%d]-DEBUG-: " fmt "\n", __FUNCTION__, __LINE__, ## args);} while (0)


int lib1x_nal_receive(Dot1x_Authenticator * auth)
{

	struct lib1x_nal_intfdesc * descSupp = auth->GlobalTxRx->network_supp;
#ifdef RTL_RADIUS_2SET
	struct lib1x_nal_intfdesc * descSvr2 = auth->GlobalTxRx->network_svr2;
#endif
	int suppid;
#ifdef PSK_ONLY
	int nRead=0;
#ifndef START_AUTH_IN_LIB
	fd_set fsRead;
#endif
#else
	struct lib1x_nal_intfdesc * descSvr = auth->GlobalTxRx->network_svr;
	int numread;
	int res;
	fd_set fsRead;
	struct timeval tvTimeOut;
	int 	iFD_SETSIZE = 0;
	unsigned char inband_cmd, *inband_rx_pkt;
	int inband_rx=0;

	tvTimeOut.tv_sec = 0;
	tvTimeOut.tv_usec = 0;
	FD_ZERO ( &fsRead);
#ifndef EAP_BY_QUEUE
	FD_SET( descSupp->pf_sock, &fsRead);
	iFD_SETSIZE = descSupp->pf_sock;
#endif

	if(auth->RSNVariable.Dot1xEnabled || auth->RSNVariable.MacAuthEnabled)
	{
#ifdef CONFIG_RTL8196C_AP_HCM
		descSvr->udpsock = get_inband_socket(descSvr->inband_channel);
#endif
		FD_SET( descSvr->udpsock, &fsRead);
		iFD_SETSIZE = (iFD_SETSIZE > descSvr->udpsock)?iFD_SETSIZE:descSvr->udpsock;
		if(auth->AccountingEnabled)
		{
			FD_SET( descSvr->acctsock, &fsRead);
			iFD_SETSIZE = (iFD_SETSIZE > descSvr->acctsock)?iFD_SETSIZE:descSvr->acctsock;
		}
#ifdef RTL_RADIUS_2SET
		if (auth->use_2nd_rad)
		{
			FD_SET( descSvr2->udpsock, &fsRead);
			iFD_SETSIZE = (iFD_SETSIZE > descSvr2->udpsock)?iFD_SETSIZE:descSvr2->udpsock;
		}
#endif
	}
	FD_SET( auth->GlobalTxRx->readfifo, &fsRead);
	iFD_SETSIZE = (iFD_SETSIZE > auth->GlobalTxRx->readfifo)?iFD_SETSIZE:auth->GlobalTxRx->readfifo;
	iFD_SETSIZE += 1;

// david
//	res = select( iFD_SETSIZE, &fsRead, NULL, NULL, &tvTimeOut);

res = select( iFD_SETSIZE, &fsRead, NULL, NULL, NULL);

	if ( res <= 0 )
	{
		return 0;
	}
	else
	{

#ifndef EAP_BY_QUEUE
		if(FD_ISSET(descSupp->pf_sock, &fsRead))
		{

			numread = recv( descSupp->pf_sock, descSupp->packet_buffer, LIB1X_MAXEAPLEN , 0);
			if ( numread <= 0 )
			{
				lib1x_message(MESS_ERROR_FATAL," NUMREAD = 0 after recv !");
				return 0;
			}

			descSupp->packet.caplen = numread;
			descSupp->packet.data = descSupp->packet_buffer;
#ifdef RTL_WPA_CLIENT
// david ----------------
#if 0
			if(auth->currentRole == role_Supplicant)
			{
				lib1x_suppsm_capture_auth( auth->client->global, descSupp, & descSupp->packet );
			}else
#endif

			if(auth->currentRole == role_Supplicant_infra)
			{
				lib1x_suppsm_capture_auth( auth->client->global, descSupp, & descSupp->packet );
			}else if (auth->currentRole == role_Authenticator)
//------------------------
#endif
			{
				suppid = lib1x_search_supp(auth, & descSupp->packet, descSupp->inttype);

				if(suppid != -1 && !memcmp(descSupp->packet.data, auth->GlobalTxRx->oursupp_addr, ETHER_ADDRLEN ))
				{
					lib1x_authsm_capture_supp(auth->Supp[suppid]->global, descSupp, & descSupp->packet);
					lib1x_auth_process(auth);
				}
			}


		}
#endif

		if((auth->RSNVariable.Dot1xEnabled || auth->RSNVariable.MacAuthEnabled)
		   && FD_ISSET(descSvr->udpsock, &fsRead))
		{
#ifdef CONFIG_RTL8196C_AP_HCM
			numread = inband_rcv_indexed_data(descSvr->inband_channel,&inband_cmd,&inband_rx_pkt, -1, auth->if_index);
			if( auth->if_index != *(unsigned int *)inband_rx_pkt ) {
				lib1x_message(MESS_ERROR_OK," Interface index not matched!");
				return 0;
			} else {
				lib1x_message(MESS_ERROR_OK," Interface index matched!");
				inband_rx_pkt += sizeof(int);
				numread -= sizeof(int);
			}
#else
			numread = recv( descSvr->udpsock, descSvr->packet_buffer, LIB1X_MAXEAPLEN , 0);
#endif
			if ( numread <= 0 )
			{
				lib1x_message(MESS_ERROR_FATAL," NUMREAD = 0 after recv !");
				return 0;
			}
#ifdef CONFIG_RTL8196C_AP_HCM
			memcpy(descSvr->packet_buffer,inband_rx_pkt,numread);
			//hex_dump(descSvr->packet_buffer, numread);
			//_AUTH_DBGMSG(">>> Process packet from inband\n");
#endif
			descSvr->packet.caplen = numread;
			descSvr->packet.data = descSvr->packet_buffer;
			suppid = lib1x_search_supp(auth, & descSvr->packet, descSvr->inttype);

			if(suppid != -1)
			{
				lib1x_authsm_capture_svr(auth->Supp[suppid]->global, descSvr, & descSvr->packet);
				lib1x_auth_process(auth);
				//_AUTH_DBGMSG(">>> Process packet from udp socket\n");
			}
		}

//#if defined(CONFIG_RTL8196C_AP_HCM)
#if 0
		numread = inband_rcv_data(descSvr->inband_channel,&inband_cmd,&inband_rx_pkt, -1);

		if ( numread > 0 ) {
			memcpy(descSvr->packet_buffer,inband_rx_pkt,numread);
			//hex_dump(descSvr->packet_buffer, numread);
			_AUTH_DBGMSG(">>> Process packet from row socket\n");

			descSvr->packet.caplen = numread;
			descSvr->packet.data = descSvr->packet_buffer;
			suppid = lib1x_search_supp(auth, &descSvr->packet, descSvr->inttype);

			if(suppid != -1){
				lib1x_authsm_capture_svr(auth->Supp[suppid]->global, descSvr, & descSvr->packet);
				lib1x_auth_process(auth);
			} else {
				lib1x_message(MESS_ERROR_FATAL," suppid mismatched!!");
			}
			inband_rx = 0;
		} else {
			_AUTH_DBGMSG(" NUMREAD = 0 after recv !(while access RRCP socket)");
		}
#endif //defined(CONFIG_RTL8196C_AP_HCM)

#ifdef RTL_RADIUS_2SET
		if((auth->RSNVariable.Dot1xEnabled || auth->RSNVariable.MacAuthEnabled)
		   && auth->use_2nd_rad && FD_ISSET(descSvr2->udpsock, &fsRead))
		{
			numread = recv( descSvr2->udpsock, descSvr2->packet_buffer, LIB1X_MAXEAPLEN , 0);

			if ( numread <= 0 )
			{
				lib1x_message(MESS_ERROR_FATAL," NUMREAD = 0 after recv !");
				return 0;
			}

			descSvr2->packet.caplen = numread;
			descSvr2->packet.data = descSvr2->packet_buffer;
			suppid = lib1x_search_supp(auth, & descSvr2->packet, descSvr2->inttype);

			if(suppid != -1)
			{
				lib1x_authsm_capture_svr(auth->Supp[suppid]->global, descSvr2, & descSvr2->packet);
				lib1x_auth_process(auth);
			}
		}
#endif
#endif // !PSK_ONLY

#ifndef START_AUTH_IN_LIB
		if(FD_ISSET(auth->GlobalTxRx->readfifo, &fsRead))
#else
		nRead = read_wlan_evt(auth->GlobalTxRx->fd_control, auth->GlobalTxRx->device_supp, auth->GlobalTxRx->RecvBuf);
		if (nRead)
#endif
		{
#ifndef START_AUTH_IN_LIB
			int nRead;
			nRead = read(auth->GlobalTxRx->readfifo, auth->GlobalTxRx->RecvBuf, RWFIFOSIZE);

			if(nRead <= 0)
				return 0;
#endif 
			auth->GlobalTxRx->network_supp->packet.data = auth->GlobalTxRx->RecvBuf + FIFO_HEADER_LEN;
			auth->GlobalTxRx->network_supp->packet.caplen = nRead - FIFO_HEADER_LEN;

			if(auth->GlobalTxRx->RecvBuf[FIFO_HEADER_LEN - 1] == FIFO_TYPE_DLISTEN)
			{

#ifdef EAP_BY_QUEUE
#ifdef RTL_WPA2_PREAUTH
				if(auth->GlobalTxRx->RecvBuf[FIFO_HEADER_LEN] == DOT11_EVENT_EAP_PACKET
				   || auth->GlobalTxRx->RecvBuf[FIFO_HEADER_LEN] == DOT11_EVENT_EAP_PACKET_PREAUTH)
#else
				if(auth->GlobalTxRx->RecvBuf[FIFO_HEADER_LEN] == DOT11_EVENT_EAP_PACKET)
#endif // RTL_WPA2
				{
					void *eap_packet = (void *)&(auth->GlobalTxRx->RecvBuf[FIFO_HEADER_LEN]);
					unsigned short packet_len;

					memcpy(&packet_len, (void *)((unsigned int)eap_packet + (int)(&((DOT11_EAP_PACKET *)0)->packet_len)), sizeof(unsigned short));
					descSupp->packet.caplen = packet_len;
					memcpy(descSupp->packet_buffer, (void *)((unsigned int)eap_packet + (int)(&((DOT11_EAP_PACKET *)0)->packet)), descSupp->packet.caplen);
					descSupp->packet.data = descSupp->packet_buffer;

#ifdef RTL_WPA_CLIENT
					if(auth->currentRole == role_Supplicant_infra)
					{
						lib1x_suppsm_capture_auth( auth->client->global, descSupp, & descSupp->packet );
					}else if (auth->currentRole == role_Authenticator)
#endif
					{
						suppid = lib1x_search_supp(auth, & descSupp->packet, descSupp->inttype);

						if(suppid != -1 && !memcmp(descSupp->packet.data, auth->GlobalTxRx->oursupp_addr, ETHER_ADDRLEN ))
						{
							lib1x_authsm_capture_supp(auth->Supp[suppid]->global, descSupp, & descSupp->packet);
							lib1x_auth_process(auth);
						}
					}
				}
				else
				{
#endif
#ifdef RTL_WPA_CLIENT
// david -----------------------------
#if 0
				if(auth->currentRole == role_Supplicant)
				{
					lib1x_message(MESS_DBG_SUPP, "Receive driver indication\n");
					lib1x_suppsm_capture_control( auth->client->global, descSupp, & descSupp->packet );
				}else
#endif

				if(auth->currentRole == role_Supplicant_infra)
				{
					lib1x_message(MESS_DBG_SUPP, "Receive driver indication\n");
					lib1x_suppsm_capture_control( auth->client->global, descSupp, & descSupp->packet );
				}else if(auth->currentRole == role_Authenticator)
//------------------------------------
#endif
				{
					suppid = lib1x_search_supp(auth, (struct lib1x_packet *)& auth->GlobalTxRx->network_supp->packet, LIB1X_IT_CTLSOCK);

					if(suppid != -1)
					{
						lib1x_capture_control( auth->Supp[suppid]->global,auth->GlobalTxRx->network_supp ,& auth->GlobalTxRx->network_supp->packet);
						lib1x_auth_process(auth);
					}

				}

#ifdef EAP_BY_QUEUE
				}
#endif

			}
		}

#ifdef PSK_ONLY
		if (nRead <= 0)
			return 0;
#else
		if(((auth->RSNVariable.Dot1xEnabled || auth->RSNVariable.MacAuthEnabled)&& (auth->AccountingEnabled))
		   && FD_ISSET(descSvr->acctsock, &fsRead))
		{

			numread = recv( descSvr->acctsock, descSvr->packet_buffer, LIB1X_MAXEAPLEN , 0);

			if ( numread <= 0 )
			{
				lib1x_message(MESS_ERROR_FATAL," NUMREAD = 0 after recv !");
				return 0;
			}

			descSvr->packet.caplen = numread;
			descSvr->packet.data = descSvr->packet_buffer;
			suppid = lib1x_search_supp(auth, & descSvr->packet, descSvr->inttype);

			if(suppid == LIB1X_AUTH_INDEX)
				lib1x_authsm_capture_svr(auth->authGlobal->global, descSvr, & descSvr->packet);
			else if(suppid != -1)
			{
				lib1x_authsm_capture_svr(auth->Supp[suppid]->global, descSvr, & descSvr->packet);
				lib1x_auth_process(auth);
			}


		}


	}
#endif // !PSK_ONLY

	return 1; // david
}
#if 0 //sc_yang
//int lib1x_nal_receivepoll( Dot1x_Authenticator * auth, struct lib1x_nal_intfdesc * desc , lib1x_nal_genpkt_handler * pkt_handler, u_char * info)
int lib1x_nal_receivepoll( Dot1x_Authenticator * auth, struct lib1x_nal_intfdesc * desc , lib1x_nal_genpkt_handler * pkt_handler, u_char * info)
{
	struct pollfd pfd;
	int pret;
	int numread;
	int res;
	int suppid;

	struct timeval timeout;
	fd_set readfs;

	static int which = 1;

	if ( pkt_handler == NULL )
		lib1x_message( MESS_ERROR_FATAL," lib1x_nal_receivepoll called with NULL handler! ");

	timeout.tv_sec = 0;
//	timeout.tv_usec = 100;
	timeout.tv_usec = 0;

	if ( desc->inttype == LIB1X_IT_PKTSOCK )
	{

		pfd.fd = desc->pf_sock;
		pfd.events = POLLIN;
		pret = poll( &pfd, 1, 0 );
		if ( pret < 0 )
		{
			//if(pret != EINTR)
			//	lib1x_message( MESS_DBG_NAL," errno = %d%s", errno, strerror(errno));
		}
		if ( pret == 0 )
		{
			return 0;
		}

		numread = recv( desc->pf_sock, desc->packet_buffer, LIB1X_MAXEAPLEN , 0);
		if ( numread <= 0 )
		{
			return 0;
		}

		desc->packet.caplen = numread;
		desc->packet.data = desc->packet_buffer;

		suppid = lib1x_search_supp(auth, & desc->packet, desc->inttype);

		if(suppid != -1 && !memcmp(desc->packet.data, auth->GlobalTxRx->oursupp_addr, ETHER_ADDRLEN ))
			(*pkt_handler)(auth->Supp[suppid]->global, desc, & desc->packet);



	}
	else // udp socket
	{


		if(auth->AccountingEnabled)
			which = !which;
		//-------------------------------------------------------------------------
		// For UDP socket from Authentication Server
		//-------------------------------------------------------------------------
		if(which)
		{
			FD_ZERO ( &readfs);
			FD_SET( desc->udpsock, &readfs);
			res = select( desc->udpsock +1, &readfs, NULL, NULL, &timeout);
			if ( res == -1 )
			{
				return 0;
			}
			if ( res <= 0 )	 return 0;

			numread = recv( desc->udpsock, desc->packet_buffer, LIB1X_MAXEAPLEN , 0);

			if ( numread <= 0 )
			{
				lib1x_message(MESS_ERROR_FATAL," NUMREAD = 0 after poll !");
				return 0;
			}

			lib1x_message(MESS_DBG_SPECIAL, "Received message on UDP socket");

			desc->packet.caplen = numread;
			desc->packet.data = desc->packet_buffer;
			suppid = lib1x_search_supp(auth, & desc->packet, desc->inttype);
			//lib1x_hexdump2(MESS_DBG_NAL, "lib1x_nal_receive_poll", desc->packet.data, desc->packet.caplen, "receive UDP packet");
			if(suppid != -1)
				(*pkt_handler)(auth->Supp[suppid]->global, desc, & desc->packet);


			lib1x_message( MESS_DBG_SPECIAL, "READ %d BYTES FROM AUTH UDP SOCKET", numread );
		}else
		//-------------------------------------------------------------------------
		// For UDP socket from Accounting Server
		//-------------------------------------------------------------------------
		{
			FD_ZERO ( &readfs);
			FD_SET( desc->acctsock, &readfs);
			res = select( desc->acctsock +1, &readfs, NULL, NULL, &timeout);
			if ( res == -1 )
			{
				return 0;
			}

			if ( res <= 0 )	 return 0;
			numread = recv( desc->acctsock, desc->packet_buffer, LIB1X_MAXEAPLEN , 0);

			if ( numread <= 0 )
			{
				lib1x_message(MESS_ERROR_FATAL," NUMREAD = 0 after poll !");
				return 0;
			}

			desc->packet.caplen = numread;
			desc->packet.data = desc->packet_buffer;
			suppid = lib1x_search_supp(auth, & desc->packet, desc->inttype);
			//lib1x_hexdump2(MESS_DBG_NAL, "lib1x_nal_receive_poll", desc->packet.data, desc->packet.caplen, "receive UDP packet");

			if(suppid == LIB1X_AUTH_INDEX)
				(*pkt_handler)(auth->authGlobal->global, desc, & desc->packet);
			else if(suppid != -1)
				(*pkt_handler)(auth->Supp[suppid]->global, desc, & desc->packet);


			lib1x_message( MESS_DBG_SPECIAL, "READ %d BYTES FROM ACCT UDP SOCKET", numread );

		}
	}

	return 1; // david
}
#endif
#ifndef COMPACK_SIZE
//----------------------------------------------------------------
// lib1x_nal_receivefifo:
//	This function receive data from fifo.
//	Three sources of data are ceceived from fifo including:
//	(1) 8181 Wireless Interface
//	(2) Ethernet interface
//	(3) Ioctl return from 8181 driver
//
//	Data received from fifo(1, 2) has the header
//     _________________________________________________
//     | pid (4 bytes) | fifo type (1 byte) | data (*) |
//     -------------------------------------------------
//-----------------------------------------------------------------
int lib1x_nal_receivefifo(Dot1x_Authenticator * auth )
{

	ssize_t	nRead;
	int suppid;

	nRead = read(auth->GlobalTxRx->readfifo, auth->GlobalTxRx->RecvBuf, RWFIFOSIZE);


	if(nRead <= 0)
		return 0;
#ifdef ALLOW_DBG_NAL
	lib1x_hexdump2(MESS_DBG_NAL, "1x_daemon", auth->GlobalTxRx->RecvBuf,  nRead, "read from fifo");
	lib1x_message(MESS_DBG_FIFO, "rx event id=%d\n",  *((int *)auth->GlobalTxRx->RecvBuf));
#endif

	auth->GlobalTxRx->network_supp->packet.data = auth->GlobalTxRx->RecvBuf + FIFO_HEADER_LEN;
	auth->GlobalTxRx->network_supp->packet.caplen = nRead - FIFO_HEADER_LEN;

	switch(auth->GlobalTxRx->RecvBuf[FIFO_HEADER_LEN - 1])
	{

	case FIFO_TYPE_DLISTEN:

		suppid = lib1x_search_supp(auth, (struct lib1x_packet *)& auth->GlobalTxRx->network_supp->packet.data, LIB1X_IT_CTLSOCK);
		//lib1x_hexdump2(MESS_DBG_NAL, "lib1x_nal_receivefifo", (u_char*)&auth->GlobalTxRx->network_supp->packet.data, auth->GlobalTxRx->network_supp->packet.caplen, "receive from driver");

		if(suppid != -1)
		{
			lib1x_capture_control( auth->Supp[suppid]->global,auth->GlobalTxRx->network_supp ,& auth->GlobalTxRx->network_supp->packet);

		}else
			lib1x_message(MESS_DBG_NAL, "***********************NOT in TABLE");

		break;

	}

	return 1; // david

}
#endif
#ifndef COMPACK_SIZE
void lib1x_nal_receiveioctl(Dot1x_Authenticator * auth)
{


	int suppid = -1;

	lib1x_control_Poll(auth);

	if(auth->IoctlBufLen)
	{


		lib1x_hexdump2(MESS_DBG_NAL, "lib1x_nal_receiveioctl", auth->IoctlBuf, auth->IoctlBufLen, "receive from driver");
		auth->GlobalTxRx->network_supp->packet.data = auth->IoctlBuf;
		auth->GlobalTxRx->network_supp->packet.caplen = auth->IoctlBufLen;



		suppid = lib1x_search_supp(auth, (struct lib1x_packet *)& auth->GlobalTxRx->network_supp->packet.data, LIB1X_IT_CTLSOCK);


		if(suppid != -1)
		{

			lib1x_capture_control( auth->Supp[suppid]->global,auth->GlobalTxRx->network_supp ,& auth->GlobalTxRx->network_supp->packet);
		}

		auth->IoctlBufLen = 0;


	}

}
#endif

//--------------------------------------------------
//--------------------------------------------------
#ifndef COMPACK_SIZE
void lib1x_nal_close( struct lib1x_nal_intfdesc * desc )
{

	// Close the listener part.
	//sc_yang
//	pcap_close( desc->pcap_desc );

	// Close the xmitter part.
	if (libnet_close_link_interface( desc->libnet_desc) == -1 )
		lib1x_message( MESS_ERROR_OK,"lib1x_nal_close: Error closing libnet channel.");
}
#endif




#if 0 //sc_yang
//--------------------------------------------------
// lib1x_nal_packet_handler:
//  This function will be called by pcap for each packet.
//--------------------------------------------------
void lib1x_nal_pcappkt_handler( u_char * lib1x_data , const struct pcap_pkthdr * packet_header, const u_char * the_packet)
{
	struct lib1x_nal_intfdesc *  desc;
	struct lib1x_ethernet * ehdr;

	u_int	caplen;
	u_int	length;
	u_short	ether_type;



	desc = ( struct lib1x_nal_intfdesc * ) lib1x_data;
	caplen = packet_header->caplen;
	length = packet_header->len;

	if ( caplen < ETHER_HDRLEN )
	{
		fprintf(stderr,"\n One packet missed .. captured length too small");
		return ;
	}
	ehdr = (struct lib1x_ethernet * ) the_packet;
	ether_type = ntohs( ehdr->ether_type );

	printf("\n packet received.");

	// We need to call the appropriate handler which is
	// given by desc->packet_handler.
}
#endif


//--------------------------------------------------
// lib1x_nal_send:
//  Make sure from and to addresses are proper
//  in the ethernet header .. coz i dont check
//  that here.
//--------------------------------------------------
BOOLEAN lib1x_nal_send( struct lib1x_nal_intfdesc * desc,  char * packet , int size)
{
	int num_sent = 0;

	if ( desc->inttype == LIB1X_IT_PKTSOCK )
	{
	//	if ( size > 1499 ) size = 1499; /* needed for ethernet only if you are not handling fragmentation */
		if ( desc->libnet_desc  == NULL )
			lib1x_message( MESS_ERROR_FATAL, "lib1x_nal_send: Descriptor contains invalid network identifier.");
		num_sent = libnet_write_link_layer( desc->libnet_desc, desc->device ,
			packet, size );
		lib1x_message(MESS_DBG_NAL, "libnet_write_link_layer send packets %d\n", num_sent);

#ifdef DBG_WPA_CLIENT
		{
			struct lib1x_packet  spkt;
			spkt.data = packet;
			spkt.caplen = size;

			lib1x_suppsm_capture_auth( RTLClient.global, desc, &spkt );

		}
#endif
	}
	else
	{
#if defined(CONFIG_RTL8196C_AP_HCM)
		unsigned char *inband_packet=NULL;

		inband_packet = (unsigned char *)malloc(size+sizeof(int));
		if( inband_packet ) {
			//hex_dump(packet, size);
			memset(inband_packet,0,size+sizeof(int));
			memcpy(inband_packet,&desc->if_index,sizeof(int));
			memcpy(inband_packet+sizeof(int),packet,size);
			size += sizeof(int);

			/*
			desc->inband_channel = inband_open("br0",desc->host_mac,ETH_P_RTK_NOTIFY,INBAND_DEBUG);
			*/
			if( desc->inband_channel < 0 )
				lib1x_message(MESS_ERROR_FATAL, "Allocate channel to host failed !.\n");
			else {
				if( (num_sent = inband_indexed_write(desc->inband_channel,0,0x0,inband_packet,size,0,desc->if_index)-INBAND_HDRLEN) )
					;//_AUTH_DBGMSG("success\n");
				else
					;//_AUTH_DBGMSG("fail\n");
			}
			//inband_close(desc->inband_channel);

			//hex_dump(inband_packet, size);
			//_AUTH_DBGMSG(">>> %s %d inband_write bytes:%d, packet size:%d\n",__FUNCTION__,__LINE__,num_sent,size);
		} else {
			printf("%s ALLOCATE pkt to send with index:%d FAILED!!!!\n",__FUNCTION__,desc->if_index);
		}
#else
		num_sent =  send( desc->udpsock, (void*) packet, size, 0); /* flags = 0 */
#endif
		lib1x_message( MESS_DBG_SPECIAL, "lib1x_nal_send: Sending UDP packet.");
	}
	if ( num_sent != size )
	{
		lib1x_message( MESS_ERROR_OK, "lib1x_nal_send: Mismatch in send size!");
		lib1x_message( MESS_ERROR_FATAL," NUM_SENT : %d . actual %d", num_sent, size );
		return FALSE;
	}
	return TRUE;
}

