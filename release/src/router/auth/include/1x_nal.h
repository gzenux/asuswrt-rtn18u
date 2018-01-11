//--------------------------------------------------
// IEEE 802.1x Implementation
//
// File		: 1x_nal.h
// Programmer	: Arunesh Mishra
// Declarations for the Network Abstraction Layer
//
//
// Copyright (c) Arunesh Mishra 2002
// All rights reserved.
// Maryland Information and Systems Security Lab
// University of Maryland, College Park.
//
//--------------------------------------------------

#ifndef LIB1X_NAL_H
#define LIB1X_NAL_H

#include <sys/types.h>
#ifdef _ON_RTL8181_TARGET
//#include <pcap.h>
#else
//#include <pcap/pcap.h>
#endif

#include "libnet.h"
//#include "/usr/include/libnet.h"

#include "1x_types.h"
#include "1x_common.h"
#include "1x_ethernet.h"
#include "1x_auth_pae.h"

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
#include <net/if.h>
#include <errno.h>


// The address types
#define 	LIB1X_NAL_MACADDR	1
#define         LIB1X_NAL_IPADDR	2

// Interface types.
#define         LIB1X_NAL_IT_ETHLAN	1
#define         LIB1X_NAL_IT_WLAN	2

#define		LIB1X_MAXDEVLEN		IFNAMSIZ + 10 /* be safe */	
//#define         LIB1X_MAXEAPLEN		5500
#define         LIB1X_MAXEAPLEN		1600 //sc_yang


// This structure defines an "address". This could
// be an IP address or a MAC address, thus doing it
// this way  gives us a "generic" interface.
struct lib1x_nal_addr
{
	unsigned char * addr;
	int len;
	int addr_type;
};

// Abstracts the notion of an interface, which could be a socket
// or an actual device
struct lib1x_nal_intdev
{
	unsigned char * interface;
	int type;
};


/* Generic packet struct .. passed to the handler */

struct lib1x_packet
{
	u_char  *data;
	int	caplen;
};



// We shall use the Berkeley Packet Capture Utility.
#define	 LIB1X_LSTNR_PROMISCMODE		1
#define	 LIB1X_LSTNR_SNAPLEN			2500	// I guess we need the entire packet.
#define	 LIB1X_LSTNR_RDTIMEOUT			1000	// Just using what the tcpdump guys used !

#define  LIB1X_IT_PKTSOCK			1
#define  LIB1X_IT_UDPSOCK			2
#define	 LIB1X_IT_CTLSOCK			3

#define  LIB1X_IT_UDPSOCK_AUTH			1
#define  LIB1X_IT_UDPSOCK_ACCT			2
#if 0 //sc_yang
void lib1x_nal_pcappkt_handler(  u_char *  lib1x_data, const struct pcap_pkthdr * packet_header, const u_char * the_packet );
struct lib1x_nal_intfdesc;

typedef void lib1x_nal_genpkt_handler( Global_Params * , struct lib1x_nal_intfdesc * , struct lib1x_packet * ); 
#endif
// Interface descriptor
struct lib1x_nal_intfdesc 
{


//1. The listener datastructures
#if 0  //sc_yang
	pcap_t		* pcap_desc;

	u_char		p_errbuf[PCAP_ERRBUF_SIZE + 1];
#endif
	BOOLEAN		promisc_mode;	
	int		snaplen;
	int		read_timeout;

	int		pf_sock;	// socket : PF_PACKET	since libpcap needs to get discarded

//	struct lib1x_nal_intdev  * device;
	u_char		device[ LIB1X_MAXDEVLEN + 1];
#if 0
	lib1x_nal_genpkt_handler * packet_handler;	/* not using currently, it is dynamic */
#endif



	struct  sockaddr_ll sock_device;

	u_char		* packet_buffer;

	struct  lib1x_packet  packet;

//2. The Xmitter datastructures

     struct             libnet_link_int * libnet_desc;
     u_char             l_errbuf[LIBNET_ERRBUF_SIZE];

//3. general ..
     u_char		ouraddr[ ETHER_ADDRLEN ];
     u_char		inttype; 	/* interface type, packet socket or udp socket */

/*4. If we are having a UDP authentication socket */
     int		udpsock;
#ifdef CONFIG_RTL8196C_AP_HCM
	 int		inband_channel;
	 unsigned int if_index;
	 unsigned char host_mac[13];
#endif
     struct sockaddr_in *radsvraddr;

/*5. If we are having a UDP accouting socket */
     int		acctsock;
     struct sockaddr_in *acctsvraddr;

};

struct lib1x_nal_intfdesc * lib1x_nal_initialize( u_char * intdev , u_char * ouraddr, u_char inttype);

BOOLEAN lib1x_nal_send( struct lib1x_nal_intfdesc * desc,  char * packet , int size);

// david
//void lib1x_nal_receivepoll( Dot1x_Authenticator * auth, struct lib1x_nal_intfdesc * desc , lib1x_nal_genpkt_handler * pkt_handler, u_char *  info);
//void lib1x_nal_receivefifo(Dot1x_Authenticator * auth);
#if 0
int lib1x_nal_receivepoll( Dot1x_Authenticator * auth, struct lib1x_nal_intfdesc * desc , lib1x_nal_genpkt_handler * pkt_handler, u_char *  info);
int lib1x_nal_receivefifo(Dot1x_Authenticator * auth);
#endif
int lib1x_nal_receive(Dot1x_Authenticator * auth);

void lib1x_nal_close( struct lib1x_nal_intfdesc * desc );
//pcap_t *  lib1x_nal_setup_pcap( struct lib1x_nal_intfdesc * nd );
int lib1x_nal_connect( struct lib1x_nal_intfdesc * desc,  /*u_short udp_ourport,*/ struct sockaddr_in *svraddr , int addrlen, int udpsock_type);

#endif

