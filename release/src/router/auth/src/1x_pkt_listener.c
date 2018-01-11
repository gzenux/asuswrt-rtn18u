# include <sys/types.h>
# include <netinet/in.h>
# include "1x_pkt_listener.h"
# include "1x_ethernet.h"
# include "1x_eapol.h"
# include "1x_common.h"




//--------------------------------------------------
// IEEE 802.1x Implementation
//
// File		: 1x_pkt_listener.c
// Programmer	: Arunesh Mishra
//
// Copyright (c) Arunesh Mishra 2002
// All rights reserved.
// Maryland Information and Systems Security Lab
// University of Maryland, College Park.
// Implementation of the packet listening interface.
//--------------------------------------------------





//--------------------------------------------------
// lib1x_pktlst_init:
//  Perform initialization of the pcap interface.
//--------------------------------------------------
void lib1x_pktlst_init( char * device , Global_Params * global )
{
	PKT_LSTNR * listener;

	listener = ( PKT_LSTNR * ) malloc( sizeof ( PKT_LSTNR) );
	listener->promisc_mode = LIB1X_LSTNR_PROMISCMODE;
	listener->snaplen = LIB1X_LSTNR_SNAPLEN;
	listener->read_timeout = LIB1X_LSTNR_RDTIMEOUT;
	listener->device = device;
	listener->packet_handler = lib1x_pktlst_packet_handler;
	listener->global = global;

	listener->pkt_desc = pcap_open_live( device, listener->snaplen, listener->read_timeout,
			listener->promisc_mode, listener->error_buf);
	if ( listener->pkt_desc == NULL )
	{
		fprintf(stderr," Could not open device : %s", device );
		exit(1);
	}
}



void lib1x_pktlst_process( PKT_LSTNR * listener )
{
	pcap_dispatch( listener->pkt_desc, -1, listener->packet_handler, (u_char *) listener );
}




//--------------------------------------------------
// lib1x_pktlst_packet_handler:
//  This function will be called by pcap for each packet.
//--------------------------------------------------
void lib1x_pktlst_packet_handler( u_char * lib1x_data , const struct pcap_pkthdr * packet_header, const u_char * the_packet)
{
	PKT_LSTNR  * listener;
	struct lib1x_ethernet_hdr * ehdr;
	Lib1x_Eapol_Header * eapol_hdr;

	u_int	caplen;
	u_int	length;
	u_short	ether_type;




	listener = (PKT_LSTNR * ) lib1x_data;	// This is directly passed.
	caplen = packet_header->caplen;
	length = packet_header->length;

	if ( caplen < ETHER_HDR_LEN )
	{
		printf(stderr,"\n One packet missed .. captured length too small");
		return ;
	}
	ehdr = (struct lib1x_ethernet_hdr * ) the_packet;
	ether_type = ntohs( ehdr->ether_type );

	if ( ether_type == LIB1X_ETHER_EAPOL_TYPE )		// Now that it is an eapol packet
	{
		// Now we've got to parse the eapol header.
		eapol_hdr = (Lib1x_Eapol_Header * )( the_packet + ETHER_HDR_LEN - 2) ;	// -2 because the type field is common.
		lib1x_pktlst_perform_action( eapol_hdr , listener );
	}
	printf("\n packet received.");
}


void lib1x_pktlst_close( PKT_LSTNR * listener )
{
	pcap_close( listener->pd );
}



//--------------------------------------------------
// lib1x_pktlst_perform_action:
//  This function parses the eapol packet and takes
//  various actions.
//--------------------------------------------------
void lib1x_pktlst_perform_action( Lib1x_Eapol_Header * eapol_hdr , PKT_LSTNR * listener)
{
	Global_Params 		* global = listener->global;
	Auth_Pae      		* auth_pae = global->auth_pae;
	Lib1x_EAP_PKTHDR	* eap_hdr;
	u_short			* eap_rr_id;	// The Request/Response type


	// TODO: Need a generic technique for confirming the source address.

	if ( global->currentRole == Authenticator )
	{

		switch( eapol_hdr->packet_type )
		{
			case	LIB1X_EAPOL_LOGOFF :
							// Page 53.
							auth_pae->eapLogoff = TRUE;
							break;
			case	LIB1X_EAPOL_START  :
							// Page 53.
							auth_pae->eapStart = TRUE;
							break;
			case	LIB1X_EAPOL_EAPPKT:
							// Page 53.
							// TODO: Parse EAP PACKET and if EAP Response/Identity Packet
							// is received set rxRespId of authpae to TRUE;
							eap_hdr = (Lib1x_EAP_PKTHDR * ) (eapol_hdr +  LIB1X_EAPOL_HDR_LEN);
							if (  eap_hdr->code == LIB1X_EAP_RESPONSE  )
							{
								eap_rr_id = (u_short*) ( eap_hdr + LIB1X_EAP_HDRLEN ) ;
										//Note :IMportant only if it is a response / request
										// packet ..we are sure of existence of such a field.

							        if ( *eap_rr_id == LIB1X_EAP_RRIDENTITY )
								{
									auth_pae->rxRespId = TRUE;
								}

							}
							break;

		}
	}



}
