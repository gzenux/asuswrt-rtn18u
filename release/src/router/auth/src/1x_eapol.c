
//--------------------------------------------------
// IEEE 802.1x Implementation
//
// File		: 1x_eapol.c
// Programmer	: Arunesh Mishra
//
//
// Copyright (c) Arunesh Mishra 2002
// All rights reserved.
// Maryland Information and Systems Security Lab
// University of Maryland, College Park.
//
//--------------------------------------------------



#include "1x_eapol.h"




//--------------------------------------------------
// lib1x_construct_eapol_frame :
//  This manually constucts the ethernet frame
//  We cannot use libnet routines for some obvious
//  reasons ..maybe someday this will find its way
//  there
//--------------------------------------------------
void lib1x_construct_eapol_frame( Lib1x_Eapol_Header * the_header , u_char * packet , u_char * eapol_body, u_char * eapol_body_length)
{
	int packet_size;
    	struct libnet_ethernet_hdr eth_hdr;


	if ( the_header == NULL )
		{
			// Error handling here
			printf("lib1x_construct_eapol_frame: Fatal .. received null argument ");
			exit(1);
		}
	packet_size = LIB1x_EAPOL_HDR_LEN + LIBNET_ETH_H + the_header->packet_body_length_int ;

	// Get memory for the packet

	if (libnet_init_packet( packet_size, &packet) == -1 )
	{
		libnet_error( LIBNET_ERR_FATAL, "libnet_init_packet failed\n");
	}

	if ( the_header->eth_dst == NULL || the_header->eth_src == NULL )
	{
			// Error handling here
			printf("lib1x_construct_eapol_frame: Fatal .. received null argument ");
			exit(1);

	}

	// The best place to put eapol header construction would be in libnet itself !!!
	// No idea what type of ethernet packet this is.
	//

	// Build the entire packet here ::


    	if (!buf)
    	{
		printf("lib1x_construct_eapol_frame: Fatal .. received null argument ");
        	exit (1);
    	}

    	memcpy(eth_hdr.ether_dhost, the_header->eth_dst, the_header->eth_dst_len);  /* destination address */
    	memcpy(eth_hdr.ether_shost, the_header->eth_src, the_header->eth_src_len);  /* source address */
    	eth_hdr.ether_type = htons(ETHERTYPE_IP);                  /* packet type : TODO incorrect currently */

        memcpy(packet + LIBNET_ETH_H, the_header, LIB1x_EAPOL_HDR_LEN);
        memcpy(packet + LIBNET_ETH_H + LIB1X_EAPOL_HDR_LEN , eapol_body, eapol_body_length);

    	memcpy(packet, &eth_hdr, sizeof(eth_hdr));


}
