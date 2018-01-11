
#ifndef LIB1X_ETHERNET_H
#define LIB1X_ETHERNET_H

#include <sys/types.h>

//--------------------------------------------------
// IEEE 802.1x Implementation
//
// File		: lib1x_ethernet.h
// Programmer	: Arunesh Mishra
// Contains some declarations for the 802.3 ethernet.
//
//
// Copyright (c) Arunesh Mishra 2002
// All rights reserved.
// Maryland Information and Systems Security Lab
// University of Maryland, College Park.
//
//--------------------------------------------------

#define ETHER_ADDRLEN		6
#define ETHER_HDRLEN		14
#define LIB1X_ETHER_EAPOL_TYPE	0x888E
#ifdef RTL_WPA2_PREAUTH
#define PREAUTH_ETHER_EAPOL_TYPE	0x88C7
#endif
#define LIB1X_ETHER_IP		0x800

struct lib1x_ethernet
{
	u_char  ether_dhost[ETHER_ADDRLEN];    /* destination ethernet address */
	u_char  ether_shost[ETHER_ADDRLEN];    /* source ethernet address */
	u_short ether_type;                     /* packet type ID */
};    
#endif
