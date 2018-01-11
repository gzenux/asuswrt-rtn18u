
//--------------------------------------------------
// IEEE 802.1x Implementation
//
// File	: 1x_parser.c
// Programmer	: Arunesh Mishra

// Copyright (c) Arunesh Mishra 2002
// All rights reserved.
// Maryland Information and Systems Security Lab
// University of Maryland, College Park.
//--------------------------------------------------
//
#include "1x_ethernet.h"
#include "1x_eapol.h"
#include "1x_nal.h"
#include "1x_common.h"
#include "1x_radius.h"
#include "1x_auth_pae.h"
#include <stdio.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>



/*

void lib1x_parsePrint( FILE * fdesc, Auth_Pae * auth_pae, struct lib1x_packet * spkt )
{
	struct lib1x_ethernet * eth;
	struct lib1x_eapol    * eapol;
	struct lib1x_eap      * eap;
	u_char etheraddr[40];
	struct timeval 	       tod;
	struct lib1x_iphdr    *ip;
	struct lib1x_udphdr   *udp;
	struct lib1x_radiushdr *rhdr;
	struct lib1x_radiusattr *rattr;

	int	unexplen;


	if ( spkt == NULL )
	{
		lib1x_message( MESS_DBG_NAL, "parser: spkt null ");
		return;
	}
	eth = ( struct lib1x_ethernet * ) spkt->data;
	fprintf(fdesc, "\n--------------------------------------START PKT DUMP---------------------------------------------\n");
	if ( gettimeofday( & tod ,NULL ) == 0 )
		fprintf(fdesc, " TIMESTAMP : %ld seconds : %ld microseconds ", tod.tv_sec, tod.tv_usec );
	fprintf(fdesc, "    Packet Length: %d",spkt->caplen );

	// 1. parse ethernet header
	lib1x_print_etheraddr( etheraddr, eth->ether_dhost );
	fprintf(fdesc, "\n DEST Ethernet Addr : %s", etheraddr );
	lib1x_print_etheraddr( etheraddr, eth->ether_shost );
	fprintf(fdesc, "   SRC Ethernet Addr : %s", etheraddr );
	fprintf(fdesc, "\n Ether Type : 0x%04X  ", htons(eth->ether_type) );

	if ( eth->ether_type == htons(LIB1X_ETHER_EAPOL_TYPE ))
	{
		fprintf(fdesc, " - EAPOL Packet. \n");
		eapol = ( struct lib1x_eapol * ) ( spkt->data + ETHER_HDRLEN );
		fprintf(fdesc, "\nEAPOL: Protocol Version: %d", eapol->protocol_version );
		fprintf(fdesc, "  Packet Type : %d", eapol->packet_type );
		fprintf(fdesc, "  Body Length: %d\n", htons(eapol->packet_body_length));

		if ( eapol->packet_type == LIB1X_EAPOL_LOGOFF )
		{
			fprintf(fdesc, "EAPOL: LOGOFF message \n");
		}
		if ( eapol->packet_type == LIB1X_EAPOL_EAPPKT )
		{
			fprintf(fdesc, "EAPOL: EAP packet \n");
			eap = ( struct lib1x_eap * ) ( spkt->data + ETHER_HDRLEN + LIB1X_EAPOL_HDRLEN);
			fprintf(fdesc, "  EAP:  Code : %u", eap->code );
			fprintf(fdesc, "  Identifier: %u", eap->identifier );
			fprintf(fdesc, "  Length : %u\n", htons(eap->length) );

			if ( eap->code == LIB1X_EAP_REQUEST )
			{
				fprintf(fdesc, "   EAP: REQuest Message\n");
				lib1x_hexdump( fdesc, ( spkt->data + ETHER_HDRLEN + LIB1X_EAPOL_HDRLEN + LIB1X_EAP_HDRLEN ), htons(eap->length) - LIB1X_EAP_HDRLEN );
			}
			if ( eap->code == LIB1X_EAP_SUCCESS )
			{
				fprintf(fdesc, "   EAP: SUCcess Message\n");
			}
			if ( eap->code == LIB1X_EAP_FAILURE )
			{
				fprintf(fdesc, "   EAP: FAILure Message\n");
			}
			if ( eap->code == LIB1X_EAP_RESPONSE )
			{
				fprintf(fdesc, "   EAP: RESPonse Message\n");
			}
		}
		if ( eapol->packet_type == LIB1X_EAPOL_START )
		{
			fprintf(fdesc, "EAPOL: START Message ");
		}
		if ( eapol->packet_type == LIB1X_EAPOL_KEY )
		{
			fprintf(fdesc, "EAPOL: KEY Message ");
		}
		if ( eapol->packet_type == LIB1X_EAPOL_ENCASFALERT )
		{
			fprintf(fdesc, "EAPOL: Encasf alert Message -? ");
		}
	}
	if ( eth->ether_type == htons(LIB1X_ETHER_IP ))
	{
		fprintf(fdesc," - IP packet.\n");
		ip = ( struct lib1x_iphdr * ) ( spkt->data + ETHER_HDRLEN );
		fprintf(fdesc,"   IP:  Source: %s", inet_ntoa( ip->ip_src ));
		fprintf(fdesc,"   Dest: %s \n", inet_ntoa( ip->ip_dst ));
		fprintf(fdesc,"   IP: Length : %d", ntohs( ip->ip_len ));
		fprintf(fdesc,"   IP: Checksum: %04d", ip->ip_sum );
		fprintf(fdesc,"   IP: Protocol: %d", ip->ip_p );

		if ( ip->ip_p == LIB1X_IPPROTO_UDP )
		{
			udp = ( struct lib1x_udphdr * ) ( spkt->data + ETHER_HDRLEN + LIB1X_IPHDRLEN );
			fprintf(fdesc," - UDP Protocol.\n");
			fprintf(fdesc,"      UDP: Source Port: %d    Dest Port: %d", ntohs(udp->sport), ntohs(udp->dport));
			fprintf(fdesc,"      AUTHPAE: Source Port: %ud    Dest Port: %ud", auth_pae->global->TxRx->udp_ourport, auth_pae->global->TxRx->udp_svrport);
			fprintf(fdesc,"   Length: %d - ", ntohs( udp->len ));
			if  (    ( udp->sport == htons(auth_pae->global->TxRx->udp_ourport ) ) || TRUE ||  // this IF Statement is JUST NOT WORKING .. auth_pae->udp_ourport gets some weird value
				 ( udp->sport == htons(auth_pae->global->TxRx->udp_svrport ) ) )	// radius response
			{
				rhdr = ( struct lib1x_radiushdr * ) ( spkt->data + ETHER_HDRLEN + LIB1X_IPHDRLEN + LIB1X_UDPHDRLEN );
				fprintf(fdesc,"      RADIUS PACKET\n");
				fprintf(fdesc,"      RAD: Code : %d  Identifier:  %d  Length: %d \n", rhdr->code, rhdr->identifier, ntohs(rhdr->length ));
				unexplen = ntohs(rhdr->length ) - LIB1X_RADHDRLEN;
				rattr = ( struct lib1x_radiusattr * ) ( spkt->data + ETHER_HDRLEN + LIB1X_IPHDRLEN + LIB1X_UDPHDRLEN + LIB1X_RADHDRLEN );

				while ( ( unexplen > 0 )  && ( rattr->length > 0 ) )
				{
					fprintf(fdesc, "         RAD-Attr:  Type: %d   Length: %d \n", rattr->type, rattr->length );
					fprintf(fdesc," RAD-Attr:DATA >> \n");
					lib1x_hexdump(fdesc,  ( ( u_char * ) rattr ) + 2, rattr->length - 2 );
					unexplen -= rattr->length;
					rattr = ( struct lib1x_radiusattr * )(  (  (u_char *) rattr ) + rattr->length );

				}
			} else fprintf(fdesc," - OTHER. \n ");
		}
		else fprintf(fdesc,"  - OTHER. \n ");
	}
	fprintf(fdesc, "\n--------------------------------------END DUMP---------------------------------------------\n");
	lib1x_hexdump(fdesc, spkt->data, spkt->caplen );
	fflush(fdesc );
}

*/

#ifndef COMPACK_SIZE
void lib1x_parsePrint( FILE * fdesc, Auth_Pae * auth_pae, struct lib1x_packet * spkt )
{
	struct lib1x_ethernet * eth;
	struct lib1x_iphdr    *ip;
	struct lib1x_udphdr   *udp;
	struct lib1x_radiushdr *rhdr;
	struct lib1x_radiusattr *rattr;

	int	unexplen;


	if ( spkt == NULL )
	{
		lib1x_message( MESS_DBG_NAL, "parser: spkt null ");
		return;
	}
	eth = ( struct lib1x_ethernet * ) spkt->data;

	printf("eth->ether_type = %x\n", eth->ether_type);
	fprintf(fdesc, "\n--------------------------------------START PKT DUMP---------------------------------------------\n");

	if ( eth->ether_type == htons(LIB1X_ETHER_EAPOL_TYPE ))
	{
		return;
	}
	if ( eth->ether_type == htons(LIB1X_ETHER_IP ))
	{
		fprintf(fdesc," - IP packet.\n");
		ip = ( struct lib1x_iphdr * ) ( spkt->data + ETHER_HDRLEN );
		fprintf(fdesc,"   IP:  Source: %s", inet_ntoa( ip->ip_src ));
		fprintf(fdesc,"   Dest: %s \n", inet_ntoa( ip->ip_dst ));

		if ( ip->ip_p == LIB1X_IPPROTO_UDP )
		{
			udp = ( struct lib1x_udphdr * ) ( spkt->data + ETHER_HDRLEN + LIB1X_IPHDRLEN );
			fprintf(fdesc," - UDP Protocol.\n");
			fprintf(fdesc,"      UDP: Source Port: %d    Dest Port: %d", ntohs(udp->sport), ntohs(udp->dport));
			//fprintf(fdesc,"      AUTHPAE: Source Port: %ud    Dest Port: %ud", auth_pae->global->TxRx->udp_ourport, auth_pae->global->TxRx->udp_svrport);
			if  (TRUE )	// radius response
			{
				rhdr = ( struct lib1x_radiushdr * ) ( spkt->data + ETHER_HDRLEN + LIB1X_IPHDRLEN + LIB1X_UDPHDRLEN );
				fprintf(fdesc,"      RADIUS PACKET\n");
				fprintf(fdesc,"      RAD: Code : %d  Identifier:  %d  Length: %d \n", rhdr->code, rhdr->identifier, ntohs(rhdr->length ));
				unexplen = ntohs(rhdr->length ) - LIB1X_RADHDRLEN;
				rattr = ( struct lib1x_radiusattr * ) ( spkt->data + ETHER_HDRLEN + LIB1X_IPHDRLEN + LIB1X_UDPHDRLEN + LIB1X_RADHDRLEN );
			} else fprintf(fdesc," - OTHER. \n ");
		}
		else fprintf(fdesc,"  - OTHER. \n ");
	}
	fprintf(fdesc, "\n--------------------------------------END DUMP---------------------------------------------\n");
	//lib1x_hexdump(fdesc, spkt->data, spkt->caplen );
	fflush(fdesc );
}
#endif

