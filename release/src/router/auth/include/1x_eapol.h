
#ifndef LIB1x_EAPOL_H
#define LIB1x_EAPOL_H



//#include <libnet.h>

//--------------------------------------------------
// IEEE 802.1x Implementation
//
// File		: 1x_eapol.h
// Programmer	: Arunesh Mishra
//
// This contains the EAPOL packet routine 
// declarations.
//
//
// Copyright (c) Arunesh Mishra 2002
// All rights reserved.
// Maryland Information and Systems Security Lab
// University of Maryland, College Park.
//--------------------------------------------------

#define LIB1X_EAPOL_HDRLEN	4		// Just the header Note:
						// is different from struct

#define	LIB1X_EAPOL_LOGOFF	2               //0000 0010B
#define LIB1X_EAPOL_EAPPKT	0               //0000 0000B
#define LIB1X_EAPOL_START	1		//0000 0001B
#define LIB1X_EAPOL_KEY		3		//0000 0011B
#define LIB1X_EAPOL_ENCASFALERT 4		//0000 0100B

#ifdef _DATA_PATH
#define	REALTEK_802dot1x_TYPE	0xcc
#endif

#define	LIB1X_EAP_REQUEST	1
#define LIB1X_EAP_RESPONSE	2
#define LIB1X_EAP_SUCCESS	3
#define LIB1X_EAP_FAILURE	4

#define	LIB1X_EAP_HDRLEN	4


#define LIB1X_EAP_RRIDENTITY	1
#define LIB1X_EAP_RRNOTIF	2
#define LIB1X_EAP_RRNAK		3
#define LIB1X_EAP_RRMD5		4
#define LIB1X_EAP_RROTP		5
#define LIB1X_EAP_RRGEN		6

#define LIB1x_EAP_RRLEN	1

#define	LIB1X_EAPOL_VER		1		//00000001B

#define LIB1X_EAPOLKEY_HDRLEN	44
#define LIB1X_RC_LEN		8
#define LIB1X_IV_LEN		16
#define LIB1X_MIC_LEN		16
#define LIB1X_KEY_TYPE_RC4	1


#pragma pack (1)	// Set our value.

struct lib1x_eapol
{
//	u_short	ether_type;   // not including this here .. it overlaps with the ethernet header.
	u_char	protocol_version;
	u_char	packet_type;			// This makes it odd in number !
	u_short packet_body_length;
};






struct lib1x_eap
{
	u_char	code;		// Identifies the type of EAP packet.
	u_char  identifier;	// Aids in matching responses with requests.
	u_short length; 	// Length of EAP packet including code, id, len, data fields
};


#define EAPOL_PAIRWISE_KEY	0x80
#define EAPOL_GROUP_KEY		0

#define EAPOL_PAIRWISE_INDEX	0x3
#define EAPOL_GROUP_INDEX	0x0
struct lib1x_eapolkey_dot1x
{
	u_char 	type;
	u_short length;
	u_char	counter[LIB1X_RC_LEN];
	u_char  iv[LIB1X_IV_LEN];
	u_char	index;
	u_char  mic[LIB1X_MIC_LEN];
	u_char  material[1];
};


struct lib1x_eap_rr
{
	u_char	type;	// The bytes after this are the data corresponding to the RR type
};



void lib1x_construct_eapol_frame( struct lib1x_eapol * the_header, u_char * packet );
//sc_yang
#pragma pack ()	// Set our value.
#endif
