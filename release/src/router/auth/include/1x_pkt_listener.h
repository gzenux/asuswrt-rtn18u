

//#ifndef 1X_PKT_LISTENER_H
//#define 1X_PKT_LISTENER_H 


//--------------------------------------------------
// IEEE 802.1x Implementation
//
// File		: 1x_pkt_listener.h
// Programmer	: Arunesh Mishra
// 
// Contains code for packet listening.
// Copyright (c) Arunesh Mishra 2002
// All rights reserved.
// Maryland Information and Systems Security Lab
// University of Maryland, College Park.
//--------------------------------------------------

// We shall use the Berkeley Packet Capture Utility.
#include <sys/types.h>
#include <pcap.h>
#include "1x_types.h"
#include "1x_common.h"

#define	 LIB1X_LSTNR_PROMISCMODE		1
#define	 LIB1X_LSTNR_SNAPLEN			1500	// I guess we need the entire packet.
#define	 LIB1X_LSTNR_RDTIMEOUT			1000	// Just using what the tcpdump guys used !


typedef struct 	PKT_LSTNR_tag
{
	pcap_t		* pkt_desc;

	u_char		error_buf[PCAP_ERRBUF_SIZE + 1];
	BOOLEAN		promisc_mode;	
	int		snaplen;
	int		read_timeout;
	char		*device;

	pcap_handler	packet_handler;

	Global_Params	* global;

} PKT_LSTNR;

void lib1x_pktlst_packet_handler( u_char * lib1x_data , const struct pcap_pkthdr * packet_header,
	       		const u_char * the_packet);


PKT_LSTNR *  lib1x_pktlst_init( char * device , Global_Params * global );

void lib1x_pktlst_process( PKT_LSTNR * listener );




//#endif
