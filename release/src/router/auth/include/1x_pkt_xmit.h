
#ifndef 1X_PKT_XMIT_H
#define 1X_PKT_XMIT_H

#include <libnet.h>

//--------------------------------------------------
// IEEE 802.1x Implementation
//
// File		: 1x_pkt_xmit.h
// Programmer	: Arunesh Mishra
// Structure for libnet.
// Copyright (c) Arunesh Mishra 2002
// All rights reserved.
// Maryland Information and Systems Security Lab
// University of Maryland, College Park.
//--------------------------------------------------



typedef struct PKT_XMIT_tag
{


     struct 		libnet_link_int	* network;
     u_char		*device;
     u_char		errbuf[LIBNET_ERRBUF_SIZE];

     Global_Params 	* global;
	
} PKT_XMIT;

#endif
