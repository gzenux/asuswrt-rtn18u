
//--------------------------------------------------
// IEEE 802.1x Implementation
//
// File		: 1x_radius.c
// Programmer	: Arunesh Mishra
//
//  BASIC RADIUS PROXY
// Copyright (c) Arunesh Mishra 2002
// All rights reserved.
// Maryland Information and Systems Security Lab
// University of Maryland, College Park.
//--------------------------------------------------



#include "1x_auth_pae.h"
#include "1x_common.h"
#include "1x_radius.h"
#include "1x_ethernet.h"
#include "1x_eapol.h"
#include "1x_ioctl.h"
#include "1x_kmsm.h"
#include <sys/types.h>
#include <sys/time.h>
#include <unistd.h>
//#include <openssl/hmac.h>
//#include <openssl/evp.h>
#include "1x_md5c.h"
#include "1x_kmsm_eapolkey.h"
#include <libnet.h>


//#define ALLOW_DBG_RAD
#ifndef COMPACK_SIZE
//--------------------------------------------------
// return values from the radius packet.
//--------------------------------------------------

void lib1x_parse_radiuspkt( u_char * packet , struct lib1x_radiuspkt * rpkt)
{
	struct lib1x_ethernet   * eth;
	struct lib1x_iphdr	* iphdr;
	struct lib1x_udphdr	* udphdr;


	eth = ( struct lib1x_ethernet *) packet;
	if ( rpkt == NULL )
		lib1x_message(MESS_ERROR_FATAL,"lib1x_parse_radiuspkt: Received NULL rpkt argument.");

	memcpy( rpkt->s_ethaddr, eth->ether_shost, ETHER_ADDRLEN );
	memcpy( rpkt->d_ethaddr, eth->ether_dhost, ETHER_ADDRLEN );

	if ( ntohs(eth->ether_type) != LIB1X_ETHER_IP )
	{
		lib1x_message(MESS_ERROR_OK, "lib1x_parse_radiuspkt: Attempt to parse non-ip packet !");
	}
	iphdr = ( struct lib1x_iphdr * ) ( packet + ETHER_HDRLEN );
	memcpy( & rpkt->ip_src, & iphdr->ip_src, sizeof(struct in_addr ));
	memcpy( & rpkt->ip_dst, & iphdr->ip_dst, sizeof(struct in_addr ));


	udphdr = ( struct lib1x_udphdr * ) ( packet + ETHER_HDRLEN + LIB1X_IPHDRLEN);
	rpkt->dst_port = udphdr->dport;
	rpkt->src_port = udphdr->sport;

	rpkt->rhdr = ( struct lib1x_radiushdr * ) ( packet + ETHER_HDRLEN + LIB1X_IPHDRLEN + LIB1X_UDPHDRLEN);
	lib1x_message(MESS_DBG_RAD," lib1x_parse_radiuspkt: length of packet : %d", ntohs(rpkt->rhdr->length) );

}
#endif

//--------------------------------------------------
// tackle response messages from supplicant.
//   NAS port = port of the bridge
//   NAS IP address
//--------------------------------------------------
void lib1x_rad_eapresp_supp( Auth_Pae * auth_pae, struct lib1x_packet * pkt)
{
	struct lib1x_eap     * eap;
        struct lib1x_eap_rr  * eaprr;
	struct radius_info   * rinfo;
	struct lib1x_radius_const * rconst;
	int		nas_port;	/* TODO .. currently this is a fixed value */
	int		nas_port_type;
	int    copysize, copysize_reqid;
	u_char		szAttr[4];
	u_char		   etheraddr[32];	/* to store ether addresses */
	u_char		 messauth[20];          /* is 16 bytes .. but 20 to be safe */
	struct lib1x_packet  the_packet;
	int		framed_mtu, val;
#ifdef _ABOCOM
	u_long	ulOutput;
#endif
	char	*src;

	nas_port = 0;
#ifdef CONFIG_RTL_ETH_802DOT1X_SUPPORT
	if(auth_pae->global->auth->currentRole == role_eth) /*IEEE802.3*/
		nas_port_type = LIB1X_802DOT3_NAS_PORTTYPE;
	else
#endif
	nas_port_type = LIB1X_80211_NAS_PORTTYPE;	/* IEEE 802.11 */
	eap = (struct lib1x_eap * ) ( pkt->data + ETHER_HDRLEN + LIB1X_EAPOL_HDRLEN );
        eaprr = ( struct lib1x_eap_rr *) ( pkt->data + ETHER_HDRLEN +  LIB1X_EAPOL_HDRLEN + LIB1X_EAP_HDRLEN ) ;

	framed_mtu = htonl( 1400 );		/* TODO : this is our framed mtu */
	rinfo = auth_pae->rinfo;                      /* get a handle */
	if ( eaprr->type ==  LIB1X_EAP_RRIDENTITY )	/* we have to handle response / identity packets differently */
	{
		copysize = ntohs( eap->length )  ;
		memcpy( rinfo->eap_message_frmsupp, (( u_char * )eap) , copysize );	/* copy the entire eap message !*/
		if ( copysize > (LIB1X_EAP_HDRLEN + 1) )	/* ie. we do have sth as username */
		{
			copysize_reqid = ntohs( eap->length ) - LIB1X_EAP_HDRLEN - 1; /* THE 1 is for eaprr->type ;) */
			memcpy( rinfo->username, (( u_char * )eaprr) + 1, copysize_reqid );
			rinfo->username_len = copysize_reqid;
		} else
		{
			rinfo->username_len = 0;
		}

#if defined(CONFIG_RTL8186_TR) || defined(CONFIG_RTL865X_SC) || defined(CONFIG_RTL865X_AC) || defined(CONFIG_RTL865X_KLD)
		rinfo->username[rinfo->username_len] = '\0';
		LOG_MSG_NOTICE("EAP-Response/Identity;note:%s;", rinfo->username);
#endif

		rinfo->eap_messtype_frmsupp = LIB1X_FRMSUPP_RESPID;
  		rinfo->eap_messlen_frmsupp = copysize;

		LIB1X_INC_RAD_IDENTIFIER(auth_pae->global->TxRx->GlobalRadId);
		rinfo->identifier = auth_pae->global->TxRx->GlobalRadId;
		lib1x_create_reqauth( auth_pae );


		/* create the reply to the radius server : */
		rconst = lib1x_radconst_create( auth_pae, auth_pae->sendBuffer , LIB1X_RAD_ACCREQ, rinfo->identifier, LIB1X_IT_UDPSOCK_AUTH);

		if ( rinfo->username_len != 0 )
			lib1x_radconst_addattr( rconst, LIB1X_RAD_USER_NAME , rinfo->username_len, rinfo->username);
		lib1x_radconst_addattr( rconst, LIB1X_RAD_NAS_IP_ADDRESS, 4, (u_char* ) &auth_pae->global->TxRx->ourip_inaddr );

		// jimmylin+20080813, modify for MAC authentication
		if ( !auth_pae->global->bMacAuthEnabled ) {
			lib1x_radconst_addattr( rconst, LIB1X_RAD_NAS_PORT, 4,  (u_char * ) & nas_port);
#ifndef _ABOCOM
			lib1x_print_etheraddr( etheraddr, auth_pae->global->TxRx->oursvr_addr );
#else
			lib1x_acct_MAC_TO_DASH_ASCII(auth_pae->global->TxRx->oursvr_addr, MacAddrLen, etheraddr, &ulOutput);
#endif
			lib1x_radconst_addattr( rconst, LIB1X_RAD_CALLED_STID, strlen( etheraddr),  etheraddr );

#ifndef _ABOCOM
			lib1x_print_etheraddr( etheraddr, auth_pae->supp_addr );

#else
			lib1x_acct_MAC_TO_DASH_ASCII(auth_pae->global->TxRx->oursvr_addr, MacAddrLen, etheraddr, &ulOutput);
#endif
			lib1x_radconst_addattr( rconst, LIB1X_RAD_CALLING_STID, strlen( etheraddr),  etheraddr );
		}
		else {
			sprintf(etheraddr, "%02X-%02X-%02X-%02X-%02X-%02X", auth_pae->supp_addr[0], auth_pae->supp_addr[1],
				auth_pae->supp_addr[2], auth_pae->supp_addr[3], auth_pae->supp_addr[4], auth_pae->supp_addr[5]);
			lib1x_radconst_addattr( rconst, LIB1X_RAD_CALLING_STID, strlen( etheraddr),  etheraddr );
		}

		// jimmylin+20080813, modify for MAC authentication
		if ( !auth_pae->global->bMacAuthEnabled ) {
			lib1x_radconst_addattr( rconst, LIB1X_RAD_NAS_IDENTIFIER, strlen( rinfo->nas_identifier), rinfo->nas_identifier );
			lib1x_radconst_addattr( rconst, LIB1X_RAD_FRAMED_MTU, 4, (u_char *) & framed_mtu );
		}
		lib1x_radconst_addattr( rconst, LIB1X_RAD_NAS_PORTTYPE, 4, (u_char * )  & nas_port_type ); //TODO
		val = htonl( nas_port_type );
		src = (char *) rconst->nas_porttype;
		memcpy( src, (char *)&val, sizeof(int) );		// jimmylin modify for unaligned access
		//*( rconst->nas_porttype ) = htonl( nas_port_type ); /* we need this coz, just copy would not work, the prev call just creates space */
		// jimmylin+20080813, modify for MAC authentication
		if ( !auth_pae->global->bMacAuthEnabled ) {
			lib1x_L2N(LIB1X_RAD_SERVICE_TYPE_FRAMED, szAttr);
			lib1x_radconst_addattr( rconst, LIB1X_RAD_SERVICE_TYPE, 4, (u_char *)szAttr );

			lib1x_radconst_addattr( rconst, LIB1X_RAD_CONNECTINFO, strlen( rinfo->connectinfo), rinfo->connectinfo );
		}
		lib1x_radconst_addEAPMessAttr( rconst,  rinfo->eap_messlen_frmsupp, rinfo->eap_message_frmsupp );

		if ( rinfo->rad_stateavailable ) lib1x_radconst_addattr( rconst, LIB1X_RAD_STATE, rinfo->rad_statelength, rinfo->radius_state );
		/* we are not sending NAS port id .. rather NAS port is being sent */
		bzero(messauth, 16);
		lib1x_radconst_addattr( rconst, LIB1X_RAD_MESS_AUTH, 16, messauth );
		lib1x_radconst_calradlength( rconst );
		lib1x_create_messauth( auth_pae, rconst, rconst->ptr_messauth ); /* this has to be done in this order so that the message authenticator has everything */
		/* lib1x_radconst_finalize( rconst );
		* we do the finalize call only when we implement our own stack
		*/
		auth_pae->sendbuflen = rconst->pktlen;
		auth_pae->sendreplyready = TRUE;

		the_packet.data = auth_pae->sendBuffer;
		the_packet.caplen = auth_pae->sendbuflen;


	}
	else
	{
		lib1x_message(MESS_DBG_RAD, "Receive messages from supplicant ");
		copysize = ntohs( eap->length )  ;
		memcpy( rinfo->eap_message_frmsupp, (( u_char * )eap) , copysize );	/* copy the entire eap message !*/
		rinfo->eap_messtype_frmsupp = LIB1X_FRMSUPP_RESPOTH;
		rinfo->eap_messlen_frmsupp = copysize;

		//rinfo->identifier ++;
		LIB1X_INC_RAD_IDENTIFIER(auth_pae->global->TxRx->GlobalRadId);
                rinfo->identifier = auth_pae->global->TxRx->GlobalRadId;

		lib1x_create_reqauth( auth_pae );

		/* create the reply to the radius server : */
		//bzero( auth_pae->sendBuffer, 5000 );	/* TODO .. this shd be safe enuf */
		//sc_yang
		bzero( auth_pae->sendBuffer, LIB1X_AP_SENDBUFLEN);	/* TODO .. this shd be safe enuf */
		rconst = lib1x_radconst_create( auth_pae, auth_pae->sendBuffer , LIB1X_RAD_ACCREQ, rinfo->identifier, LIB1X_IT_UDPSOCK_AUTH);
		if ( rinfo->username_len != 0 )
			lib1x_radconst_addattr( rconst, LIB1X_RAD_USER_NAME , rinfo->username_len, rinfo->username);
		lib1x_radconst_addattr( rconst, LIB1X_RAD_NAS_IP_ADDRESS, 4, (u_char* ) & auth_pae->global->TxRx->ourip_inaddr );
		lib1x_radconst_addattr( rconst, LIB1X_RAD_NAS_PORT, 4,  (u_char * ) & nas_port);
#ifndef _ABOCOM
		lib1x_print_etheraddr( etheraddr, auth_pae->global->TxRx->oursvr_addr );
		lib1x_radconst_addattr( rconst, LIB1X_RAD_CALLED_STID, strlen( etheraddr),  etheraddr );
#else
		lib1x_acct_MAC_TO_DASH_ASCII(auth_pae->global->TxRx->oursvr_addr, MacAddrLen, etheraddr, &ulOutput);
		lib1x_radconst_addattr( rconst, LIB1X_RAD_CALLED_STID, ulOutput,  etheraddr );
#endif

#ifndef _ABOCOM
		lib1x_print_etheraddr( etheraddr, auth_pae->supp_addr );
		lib1x_radconst_addattr( rconst, LIB1X_RAD_CALLING_STID, strlen( etheraddr),  etheraddr );
#else
		lib1x_acct_MAC_TO_DASH_ASCII(auth_pae->global->TxRx->oursvr_addr, MacAddrLen, etheraddr, &ulOutput);
		lib1x_radconst_addattr( rconst, LIB1X_RAD_CALLED_STID, ulOutput,  etheraddr );
#endif

		lib1x_radconst_addattr( rconst, LIB1X_RAD_NAS_IDENTIFIER, strlen( rinfo->nas_identifier), rinfo->nas_identifier );
		lib1x_radconst_addattr( rconst, LIB1X_RAD_NAS_PORTTYPE, 4, (u_char * )  & nas_port_type );
		val = htonl( nas_port_type );
		src = (char *) rconst->nas_porttype;
		memcpy( src, &val, sizeof(int) );		// jimmylin modify for unaligned access
		//*( rconst->nas_porttype ) = htonl( nas_port_type );	/* we need this coz, just copy would not work, the prev call just creates space */
		lib1x_L2N(LIB1X_RAD_SERVICE_TYPE_FRAMED, szAttr);
		lib1x_radconst_addattr( rconst, LIB1X_RAD_SERVICE_TYPE, 4, (u_char *)szAttr );

		lib1x_radconst_addattr( rconst, LIB1X_RAD_CONNECTINFO, strlen( rinfo->connectinfo), rinfo->connectinfo );
		lib1x_radconst_addEAPMessAttr( rconst,  rinfo->eap_messlen_frmsupp, rinfo->eap_message_frmsupp );
		if ( rinfo->rad_stateavailable ) lib1x_radconst_addattr( rconst, LIB1X_RAD_STATE, rinfo->rad_statelength, rinfo->radius_state );
		/* we are not sending NAS port id .. rather NAS port is being sent */
		bzero(messauth, 16);
		lib1x_radconst_addattr( rconst, LIB1X_RAD_MESS_AUTH, 16, messauth );
		lib1x_radconst_calradlength( rconst );
		lib1x_create_messauth( auth_pae, rconst, rconst->ptr_messauth ); /* this has to be done in this order so that the message authenticator has everything */
		/* lib1x_radconst_finalize( rconst );
		* we do the finalize call only when we implement our own stack
		*/
		//lib1x_parsePrint( stdout, auth_pae , & the_packet );
		auth_pae->sendbuflen = rconst->pktlen;
		auth_pae->sendreplyready = TRUE;
	}
}


//--------------------------------------------------
// calculate and fill the length of the radius pkt so
// that we can then calculate the message authenticator
//--------------------------------------------------
void lib1x_radconst_calradlength( struct lib1x_radius_const * rconst )
{
	struct lib1x_radiushdr * rhdr;


	rhdr = ( struct lib1x_radiushdr * ) ( rconst->pkt + ETHER_HDRLEN + LIB1X_IPHDRLEN + LIB1X_UDPHDRLEN );
	rhdr->length = htons(rconst->pktlen - ETHER_HDRLEN - LIB1X_IPHDRLEN - LIB1X_UDPHDRLEN) ;

}



//--------------------------------------------------
// tackle messages from the server
//--------------------------------------------------
void lib1x_rad_eapresp_svr( Auth_Pae * auth_pae, struct lib1x_packet * srcpkt, int msgtype)
{
	struct lib1x_ethernet * eth;
	struct lib1x_eapol * eapol;
	struct lib1x_eap   * eap;
#ifdef CONFIG_RTL_ETH_802DOT1X_SUPPORT
	unsigned char dot1x_group_mac[ETHER_HDRLEN] = {0x01,0x80,0xC2,0x00,0x00,0x03};
#endif

	switch(msgtype)
	{
	case LIB1X_RAD_ACCCHL:

		// Set the from / to ethernet addresses.
		eth = ( struct lib1x_ethernet * ) auth_pae->sendBuffer;
#ifdef CONFIG_RTL_ETH_802DOT1X_SUPPORT
		if(auth_pae->global->auth->currentRole == role_eth && (!auth_pae->global->auth->ethDot1xEapolUnicastEnabled))
			memcpy ( eth->ether_dhost, dot1x_group_mac, ETHER_HDRLEN);
		else
#endif
		memcpy ( eth->ether_dhost, auth_pae->supp_addr, ETHER_HDRLEN);
		memcpy ( eth->ether_shost, auth_pae->global->TxRx->oursupp_addr, ETHER_HDRLEN);
#ifdef RTL_WPA2_PREAUTH
		if (auth_pae->global->RSNVariable.isPreAuth)
			eth->ether_type = htons(PREAUTH_ETHER_EAPOL_TYPE);
		else
			eth->ether_type = htons( LIB1X_ETHER_EAPOL_TYPE );
#else
		eth->ether_type = htons( LIB1X_ETHER_EAPOL_TYPE );
#endif

		eapol = ( struct lib1x_eapol * )( auth_pae->sendBuffer + ETHER_HDRLEN );
		eapol->protocol_version = LIB1X_EAPOL_VER;

		//---- Tackle message from Radius server to supplicant ----//
		eapol->packet_type = LIB1X_EAPOL_EAPPKT;
		eapol->packet_body_length = htons( auth_pae->rinfo->eap_messlen_frmserver)  ;

		eap = (struct lib1x_eap * ) ( ( (u_char *) eapol) + LIB1X_EAPOL_HDRLEN );
		eap->code =  LIB1X_EAP_REQUEST;
		eap->identifier = auth_pae->global->currentId;

		memcpy((u_char *  )eap , auth_pae->rinfo->eap_message_frmserver, auth_pae->rinfo->eap_messlen_frmserver);
		/*memcpy((((u_char *  )eap ) + LIB1X_EAP_HDRLEN), auth_pae->rinfo->eap_message_frmserver, auth_pae->rinfo->eap_messlen_frmserver);*/
		if ( auth_pae->sendreplyready != FALSE )
		{
			lib1x_message( MESS_ERROR_FATAL, "Double use of send buffer ? packet not sent !");
		}
		auth_pae->sendbuflen = ETHER_HDRLEN + LIB1X_EAPOL_HDRLEN + auth_pae->rinfo->eap_messlen_frmserver ;
		eap->length = htons(  auth_pae->rinfo->eap_messlen_frmserver);
		auth_pae->sendreplyready = TRUE;
#if defined(CONFIG_RTL_ETH_802DOT1X_SUPPORT)
		if((auth_pae->global->auth->currentRole == role_eth) && (!auth_pae->global->auth->ethDot1xEapolUnicastEnabled)&&(auth_pae->global->auth->ethDot1xMode & ETH_DOT1X_PROXY_MODE))
		{
			lib1x_add_portinfo_to_eap_pkt(auth_pae->sendBuffer, &auth_pae->sendbuflen,LIB1X_AP_SENDBUFLEN, auth_pae->global->port_num);
		}
#endif
		break;
	case LIB1X_RAD_ACCACT:
		//---- Send EAPOL-KEY to client in Non-RSN802dot1x ---- //
		if(auth_pae->keyxmit_sm->keyAvailable)
		{
			//---- EAPOL-KEY message is constructed in key state machine because there are two
			//---- message two send at one transition
   			auth_pae->sendreplyready = TRUE;
		}
		//----- Send Acct-Start to indicate the start of a user session ----//
		if(auth_pae->global->auth->AccountingEnabled)
		{
			lib1x_acctsm_request(auth_pae->global, acctsm_Acct_Start, 0);

		}
		break;
	}


}

//--------------------------------------------------
// create the request authenticator field for the
// radius packets.
//  depends only on rinfo->identifier from the auth_pae
//  and stores it into rinfo->req_authenticator
//--------------------------------------------------
void lib1x_create_reqauth( Auth_Pae * auth_pae )
{
	 struct timeval tv;
	 struct timezone tz;
	 MD5_CTX the_md5;
	 struct radius_info * rinfo;

	 rinfo = auth_pae->rinfo;

        // Use the time of day with the best resolution the system can
	//    give us -- often close to microsecond accuracy.
        gettimeofday(&tv,&tz);

          tv.tv_sec ^= getpid() * (rinfo->identifier); /* add some secret information: session */

          /* Hash things to get some cryptographically strong pseudo-random numbers */
          MD5_Init(&the_md5);
          MD5_Update(&the_md5, (unsigned char *) &tv, sizeof(tv));
          MD5_Update(&the_md5, (unsigned char *) &tz, sizeof(tz));
          MD5_Final(rinfo->req_authenticator, &the_md5);          /* set the final vector */
	  /* MD5 outputs a 16 byte value by default */
}

//--------------------------------------------------
// create the request authenticator field for the
// radius packets.
//  depends only on rinfo->identifier from the auth_pae
//  and stores it into rinfo->req_authenticator
// MD5 of Code||Identifier||Length||16 octetcs||request attr||shared secret
//--------------------------------------------------

void lib1x_create_reqauth_acct(Auth_Pae * auth_pae, struct lib1x_radius_const * rconst)
{
	u_char	szBuf[1024];
	u_long	ulRadPacketLen;
	MD5_CTX the_md5;
	struct lib1x_radiushdr * rhdr;

	memset(szBuf, 0, sizeof szBuf);
	rhdr = (struct lib1x_radiushdr * )  ( rconst->pkt  + ETHER_HDRLEN + LIB1X_IPHDRLEN + LIB1X_UDPHDRLEN ) ;
	memset(rhdr->authenticator_str, 0, sizeof rhdr->authenticator_str);

	ulRadPacketLen = rconst->pktlen - ETHER_HDRLEN - LIB1X_IPHDRLEN - LIB1X_UDPHDRLEN;

	memcpy(szBuf,
		rconst->pkt  + ETHER_HDRLEN + LIB1X_IPHDRLEN + LIB1X_UDPHDRLEN,
		ulRadPacketLen);
#ifdef ALLOW_DBG_RAD
	lib1x_hexdump2(MESS_DBG_RAD, "lib1x_create_reqauth_acct",szBuf, ulRadPacketLen,"Calculate Auth");
#endif

	MD5_Init(&the_md5);
	MD5_Update(&the_md5, (unsigned char *) szBuf, ulRadPacketLen);
	MD5_Update(&the_md5, (unsigned char *) auth_pae->global->auth->AcctShared.Octet, auth_pae->global->auth->AcctShared.Length);
	MD5_Final(rhdr->authenticator_str, &the_md5);          /* set the final vector */


}

//--------------------------------------------------
//.. creates a partial radius packet.
// call this after calculating the request authenticator.
//rcode = radius code, rid = radius identifier.
//--------------------------------------------------
struct lib1x_radius_const *  lib1x_radconst_create( Auth_Pae * auth_pae, u_char * pkt , u_char rcode,
	u_char rid, int udp_type)
{
	struct lib1x_ethernet * eth;
	struct lib1x_iphdr * iph;
	struct lib1x_udphdr * udp;
	struct lib1x_radius_const * rconst;


	// Set the from / to ethernet addresses.
	eth = ( struct lib1x_ethernet * ) pkt;
	memcpy ( eth->ether_dhost, auth_pae->global->TxRx->svr_addr, ETHER_HDRLEN);
	memcpy ( eth->ether_shost, auth_pae->global->TxRx->oursvr_addr, ETHER_HDRLEN);
	eth->ether_type = htons( LIB1X_ETH_IP );

	iph = ( struct lib1x_iphdr * ) ( pkt + ETHER_HDRLEN );
	iph->ip_v = 4;		        /* version 4 */
	iph->ip_hl = 5;		/* 20 byte header */
	iph->ip_ttl = 0xFF;
	iph->ip_off = htons(IP_DF );  /* dont fragment */
	iph->ip_id = htons( 0x000);	/* ip identifier */
	iph->ip_p = LIB1X_IPPROTO_UDP;
	iph->ip_sum = 0;
	memcpy( & iph->ip_src, & auth_pae->global->TxRx->ourip_inaddr, sizeof( struct in_addr ));
	memcpy( & iph->ip_dst, & auth_pae->global->TxRx->svrip_inaddr, sizeof( struct in_addr ));

	udp = ( struct lib1x_udphdr * ) ( pkt + ETHER_HDRLEN  + LIB1X_IPHDRLEN);
	udp->sport = htons( auth_pae->global->TxRx->udp_ourport );
	if(udp_type == LIB1X_IT_UDPSOCK_AUTH)
		udp->dport = htons( auth_pae->global->TxRx->udp_svrport );
	else if(udp_type == LIB1X_IT_UDPSOCK_ACCT)
		udp->dport = htons( auth_pae->global->TxRx->udp_acctport );
	udp->sum = 0x000;	 /* do the checksum later  and the length*/

	//rconst  = ( struct lib1x_radius_const * ) malloc ( sizeof(struct lib1x_radius_const ) );
	memset(auth_pae->rconst, 0, sizeof(struct lib1x_radius_const));
	rconst = auth_pae->rconst;
	rconst->pkt = pkt;
	rconst->rhdr =  (struct lib1x_radiushdr * ) ( ( ( u_char *) udp ) + LIB1X_UDPHDRLEN );
	rconst->pktlen = ETHER_HDRLEN + LIB1X_IPHDRLEN + LIB1X_UDPHDRLEN + LIB1X_RADHDRLEN;
	rconst->rhdr->code = rcode;
	rconst->rhdr->identifier = rid;
	memcpy( rconst->rhdr->authenticator_str , auth_pae->rinfo->req_authenticator , 16 ); /* 128 bits */
	return rconst;
	/* note, we are not setting the length + checksum fields for udp + ip headers*/


}


//--------------------------------------------------
// Breaks a BIG EAP message into consecutive blocks of 255 byte
// messages.
//--------------------------------------------------
void lib1x_radconst_addEAPMessAttr( struct lib1x_radius_const * rconst,  int attrlen, u_char * attrdata )
{
	struct lib1x_radiusattr * rattr;
	u_char actual_len;
	u_char * dataptr;


//	lib1x_message( MESS_DBG_RAD," Adding EAP MESSAGE length %d", attrlen );
//	lib1x_chardump( stderr, attrdata, attrlen );
//	lib1x_message( MESS_DBG_RAD," Packet Length %d", rconst->pktlen );
	dataptr = attrdata;
	for (; attrlen > 0; attrlen -= 253 )
	{
		if ( attrlen > 253 ) actual_len = 253;
		else actual_len = attrlen;
		rattr = ( struct lib1x_radiusattr * )  & ( rconst->pkt[rconst->pktlen]);
		rattr->type = LIB1X_RAD_EAP_MESSAGE;
		rattr->length = actual_len + 2;
		memcpy ( ( ( u_char* ) rattr) + LIB1X_RADATTRLEN , dataptr, actual_len  );
		dataptr += actual_len;
		rconst->pktlen += rattr->length;
	}

}



//--------------------------------------------------
// attr type is the type of radius attribute
// attr len is the length of attrdata
//--------------------------------------------------
void lib1x_radconst_addattr( struct lib1x_radius_const * rconst, u_char attrtype,  u_char attrlen, u_char * attrdata )
{
	struct lib1x_radiusattr * rattr;


//	lib1x_message( MESS_DBG_RAD," Adding Attribute type %d length %d", attrtype, attrlen );
//	lib1x_chardump( stderr, attrdata, attrlen );
//	lib1x_message( MESS_DBG_RAD," Packet Length %d", rconst->pktlen );
	rattr = ( struct lib1x_radiusattr * )  & ( rconst->pkt[rconst->pktlen]);
	rattr->type = attrtype;
	rattr->length = attrlen + 2;
	memcpy ( ( ( u_char* ) rattr) + LIB1X_RADATTRLEN , attrdata, attrlen  );
	rconst->pktlen += rattr->length;

	/* handle special casses here */
	if ( attrtype == LIB1X_RAD_MESS_AUTH )
		rconst->ptr_messauth = ( ( u_char* ) rattr) + LIB1X_RADATTRLEN;
	if ( attrtype == LIB1X_RAD_NAS_PORTTYPE )
		rconst->nas_porttype = (int *)(( ( u_char* ) rattr) + LIB1X_RADATTRLEN);
}


//--------------------------------------------------
// create the message authenticator field for the
// radius packets.
//--------------------------------------------------
void lib1x_create_messauth( Auth_Pae * auth_pae, struct lib1x_radius_const * rconst, u_char * messauth)
{

	 //HMAC_CTX   the_md5;

	 struct lib1x_radiushdr * rhdr;
	 int dummylen;
	 struct radius_info * rinfo;
	 //int  flen;



	rinfo = auth_pae->rinfo;
	rhdr = (struct lib1x_radiushdr * )  ( rconst->pkt  + ETHER_HDRLEN + LIB1X_IPHDRLEN + LIB1X_UDPHDRLEN ) ;
	dummylen = (  ETHER_HDRLEN + LIB1X_IPHDRLEN + LIB1X_UDPHDRLEN );
	/*--------------------------------------------------------------------------- */
#if 0
	HMAC_Init( & the_md5, auth_pae->global->auth->RadShared.Octet,
			auth_pae->global->auth->RadShared.Length, EVP_md5() );
	//HMAC_Init( & the_md5, rinfo->rad_shared, strlen ( rinfo->rad_shared), EVP_md5() );

	/*HMAC_Update(&the_md5, (unsigned char *) &rhdr->code , sizeof(u_char));
	HMAC_Update(&the_md5, (unsigned char *) &rhdr->identifier, sizeof(u_char));
	HMAC_Update(&the_md5, (unsigned char *) &rhdr->length, sizeof(u_short));
	HMAC_Update(&the_md5, (unsigned char *) ( rconst->pkt + dummylen) , rconst->pktlen - dummylen );	// 128 bits  */
	HMAC_Update(&the_md5, (unsigned char *) ( rconst->pkt + dummylen) , rconst->pktlen - dummylen );	// take the complete radius packet
	flen = 16;	// not sure what flen returns
	HMAC_Final(&the_md5, messauth, &flen );          // set the final vector
	if ( flen != 16 ) lib1x_message( MESS_ERROR_FATAL, "Incorrect length here !");
#endif
	/*
	// MD5 outputs a 16 byte value by default
	// */
	//lib1x_hmac_md5( (u_char *) rhdr, rhdr->length, rinfo->rad_shared, strlen(rinfo->rad_shared), messauth );
	hmac_md5( (unsigned char *) ( rconst->pkt + dummylen), rconst->pktlen - dummylen,
	auth_pae->global->auth->RadShared.Octet, auth_pae->global->auth->RadShared.Length, messauth );
}

//--------------------------------------------------
// HMAC code from RFC 2104 ..
//--------------------------------------------------
#if 0
void lib1x_hmac_md5(
	unsigned char*  text,                /* pointer to data stream */
	int             text_len,            /* length of data stream */
	unsigned char*  key,                 /* pointer to authentication key */
	int             key_len,             /* length of authentication key */
	caddr_t         digest              /* caller digest to be filled in */
)

{
	  MD5_CTX context;
	  unsigned char k_ipad[65];    /* inner padding -
	                                * key XORd with ipad
                                        */
          unsigned char k_opad[65];    /* outer padding -
                                        * key XORd with opad
                                        */
          unsigned char tk[16];
	  int i;
	  /* if key is longer than 64 bytes reset it to key=MD5(key) */
	  if (key_len > 64) {

	                MD5_CTX      tctx;
                        MD5_Init(&tctx);
			MD5_Update(&tctx, key, key_len);
		        MD5_Final(tk, &tctx);
                        key = tk;
		        key_len = 16;
          }
/*
 * the HMAC_MD5 transform looks like:
 *
 * MD5(K XOR opad, MD5(K XOR ipad, text))
 *
 * where K is an n byte key
 * ipad is the byte 0x36 repeated 64 times
 * opad is the byte 0x5c repeated 64 times
 * and text is the data being protected
 */
/* start out by storing key in pads */
         bzero( k_ipad, sizeof k_ipad);
         bzero( k_opad, sizeof k_opad);
	 bcopy( key, k_ipad, key_len);
	 bcopy( key, k_opad, key_len);
/* XOR key with ipad and opad values */
         for (i=0; i<64; i++) {
	         k_ipad[i] ^= 0x36;
		 k_opad[i] ^= 0x5c;
         }
	/*
	 * perform inner MD5
	 */
	MD5_Init(&context);                   /* init context for 1st
	                                       * pass */
        MD5_Update(&context, k_ipad, 64);     /* start with inner pad */
	MD5_Update(&context, text, text_len); /* then text of datagram */
	MD5_Final(digest, &context);          /* finish up 1st pass */
	/*
	 * perform outer MD5
	 */
	MD5_Init(&context);                   /* init context for 2nd
	                                      * pass */
        MD5_Update(&context, k_opad, 64);     /* start with outer pad */
	MD5_Update(&context, digest, 16);     /* then results of 1st
	                                       * hash */
        MD5_Final(digest, &context);          /* finish up 2nd pass */
}

#endif
#ifndef COMPACK_SIZE
//--------------------------------------------------
// lib1x_radconst_finalize : finalize the packet .. calculate all checksums etc
//--------------------------------------------------
void lib1x_radconst_finalize( struct lib1x_radius_const * rconst )
{
 // set the lengths
	struct lib1x_iphdr * ip;
	struct lib1x_udphdr * udp;

	u_short newsum;

	ip = ( struct lib1x_iphdr * ) ( rconst->pkt + ETHER_HDRLEN );
	ip->ip_len = htons( rconst->pktlen - ETHER_HDRLEN );
	udp = ( struct lib1x_udphdr * ) ( rconst->pkt + ETHER_HDRLEN + LIB1X_IPHDRLEN);
	udp->len = htons( rconst->pktlen - ETHER_HDRLEN  - LIB1X_IPHDRLEN );

// do the checksums ...
	lib1x_do_checksum_udp( rconst->pkt + ETHER_HDRLEN , rconst->pktlen - ETHER_HDRLEN - LIB1X_IPHDRLEN);
	newsum = libnet_ip_check( (u_short*) (rconst->pkt + ETHER_HDRLEN) , LIB1X_IPHDRLEN );
	libnet_do_checksum( rconst->pkt + ETHER_HDRLEN , IPPROTO_IP, LIB1X_IPHDRLEN);
	lib1x_message( MESS_DBG_RAD, " IP CHECKSUM new : 0x%04X", newsum );
	if ( libnet_ip_check( (u_short*) (rconst->pkt + ETHER_HDRLEN) , rconst->pktlen - ETHER_HDRLEN ) != ip->ip_sum ) lib1x_message(MESS_ERROR_OK, " Checksum failed");
}
#endif


//-----------------------------------------------------
// Decrypt the MPPE Sned/Recv Keys
// 	input    pEncryptionKeys : From the field of Salt
//		 ulLength : Length From field of salt
//	return   0 for success / others for fail
//-----------------------------------------------------

int lib1x_decrypt_MPPESendRecvKeys(
	OCTET_STRING * pRadiusSecret,
	u_char * pRequestAuthenticator,
	u_long ulLength,
	u_char * pEncryptionKeys,
	int * iKeyLength
)
{
	int    retVal = 0;

	u_char * pbValue = (u_char *)pEncryptionKeys + 2;
	u_char abCipherText[16];
	u_char szDigest[16];
	MD5_CTX md5Ctx;
	u_long ulIndex;
	u_long ulBlock;
	u_long ulNumBlocks;
	ulNumBlocks = ( ulLength - 2 ) / 16;
	//
	// Walk thru the blocks
	//
#ifdef ALLOW_DBG_RAD
	lib1x_hexdump2(MESS_DBG_RAD, "lib1x_decrypt_MPPESendRecvKeys",pRequestAuthenticator, 16,"pRequestAuthenticator");
#endif

	for ( ulBlock = 0; ulBlock < ulNumBlocks; ulBlock++ )
	{
		MD5_Init( &md5Ctx );
		MD5_Update( &md5Ctx, (u_char *)(pRadiusSecret->Octet), pRadiusSecret->Length);
		if ( ulBlock == 0 )
			{
			//
			// Use the Request Authenticator and salt for the first block
			//
			MD5_Update( &md5Ctx, pRequestAuthenticator, 16 );
			MD5_Update( &md5Ctx, pEncryptionKeys, 2 );
		}
		else
		{
			//
			// Use the previous block of cipherText
			//
			MD5_Update( &md5Ctx, abCipherText, 16 );
		}
		MD5_Final( szDigest, &md5Ctx );
		//
		// Save the cipherText from this block.
		//
		memcpy(abCipherText, pbValue, sizeof(abCipherText));
		for ( ulIndex = 0; ulIndex < 16; ulIndex++ )
		{
			*pbValue ^= szDigest[ulIndex];
			pbValue++;
		}
	}

	*iKeyLength = pEncryptionKeys[2];
	return retVal;
}

#ifdef HS2_SUPPORT
int lib1x_rad_vendor_attr_WFA(
	Global_Params * global,
	u_char * rattr_ptr,
	int length
) 
{
	struct lib1x_radius_vendorattr  * vattr = (struct lib1x_radius_vendorattr*) rattr_ptr;	
	unsigned char *URL;
	if(length != vattr->length)
		return -1;
	
	if(vattr->type == LIB1X_RADVENDOR_WFA_ST_SUB_RED_SVR)
	{
		int i;
		printf("RED_SVR, vattr->string=%x, length=%d\n",vattr->string,vattr->length);

		if (vattr->string == NULL) {
			printf("WNM String is NULL\n");
			return -1;
		}
#if 0
		printf("RED_SVR, vattr->string=");
		for(i=0;i<vattr->length;i++) {
			printf("%02x ",rattr_ptr[i]);
		}
		printf("\n");
#endif	
#if 1
		global->serverMethod = rattr_ptr[2];
#endif
		memcpy(global->remed_URL, rattr_ptr+3, vattr->length-3);
		printf("RED URL=%s\n",global->remed_URL);
		global->isTriggerWNM = 1;
		//lib1x_control_WNM_NOTIFY(global,URL);
			
		printf("WNM_Notify done\n");
		free(URL);
		return 0;
		// Send a WNM Notification Message to Driver
		// vattr->string : URL of the Subscription Remediation Server
		
	} 
	else if(vattr->type == LIB1X_RADVENDOR_WFA_ST_DEAUTH_REQ)
	{		
		int i;
		printf("DEAUTH, vattr->string=%x, length=%d\n",vattr->string,vattr->length);		
		
		if (vattr->string == NULL) {
			printf("WNM Deauth String is NULL\n");
			return -1;
		}
		
		printf("DEAUTH, vattr->string=");
		for(i=0;i<vattr->length;i++) {
			printf("%02x",rattr_ptr[i]);
		}
		printf("\n");
		
		global->WNMDEAUTH_reason= *(unsigned char *)(rattr_ptr+2);
		//global->WNMDEAUTH_reAuthDelay = *(unsigned short *)(rattr_ptr+3);
		//lib1x_N2S(rattr_ptr+3, global->WNMDEAUTH_reAuthDelay);
		lib1x_Little_N2S((u_char*)rattr_ptr+3, global->WNMDEAUTH_reAuthDelay);
		if(vattr->length-5 > 0) {
			memcpy(global->WNMDEAUTH_URL,rattr_ptr+5,vattr->length-5);
			global->WNMDEAUTH_URL[vattr->length-5] = '\0';
		} else if(vattr->length-5 == 0) {
			global->WNMDEAUTH_URL[0] = '\0';
		} else {
			printf("WNM Deauth String length is too small\n");
		}
		printf("WNMDEAUTH_URL=%s\n", global->WNMDEAUTH_URL);	
		
		global->isTriggerWNM_DEAUTH = 1;
		//lib1x_control_WNM_DEAUTH_REQ(global, code, reAuthDelay, URL);			
		
		return 0;
	}
	else if(vattr->type == LIB1X_RADVENDOR_WFA_ST_SESSION_URL) {
		unsigned char SWT;
		int i;
		
		printf("Session Information URL, vattr->string=%x, length=%d\n",vattr->string,vattr->length);
		
		
		if (vattr->string == NULL) {
			printf("SessionInfo URL String is NULL\n");
			return -1;
		}
		
		printf("Session Information URL, rattr_ptr=");
		for(i=0;i<vattr->length;i++) {
			printf("%02x",rattr_ptr[i]);
		}
		printf("\n");
		
		global->SWT = *(unsigned char *)(rattr_ptr+2);
		
		//URL = (unsigned char *) malloc(vattr->length-2);
		memcpy(global->SessionInfo_URL,rattr_ptr+3,vattr->length-3);
		global->SessionInfo_URL[vattr->length-3] = '\0';
		printf("4.12 , !!SessionInfo_URL=%s\n", global->SessionInfo_URL);
		global->isTriggerSessionInfo_URL = 1;
		//lib1x_control_SessionInfo_URL(global, SWT, URL);
				
		free(URL);
		return 0;
	}
	else {
		printf("Auth (1x_radius.c): HS2 Radius Subtype %d is not supported\n",vattr->type);
		return -1;
	}
	return -1;
}
#endif

//---------------------------------------------------
// lib1x_rad_vendor_attr : process MPPE-Send/Recv-Key
// Return : 0 for success / others for fail
//---------------------------------------------------
int lib1x_rad_vendor_attr(
	Global_Params * global,
	u_char * rattr_ptr,
	int length
)
{


	struct lib1x_radius_vendorattr  * vattr = (struct lib1x_radius_vendorattr*) rattr_ptr;

	if(length != vattr->length)
		return -1;
	switch(vattr->type)
	{
	case LIB1X_RADVENDOR_MS_MPPE_SEND_KEY:
		if(vattr->length < 4)
                        return -1;
		//ToDo : check 2 Octets Salt
		lib1x_decrypt_MPPESendRecvKeys(
			&global->auth->RadShared,
			global->theAuthenticator->rinfo->req_authenticator,
			vattr->length - 2,
			((u_char*)rattr_ptr + 2),
			&global->RadiusKey.SendKey.Length);
#ifdef ALLOW_DBG_RAD
		lib1x_hexdump2(MESS_DBG_RAD, "lib1x_rad_vendor_attr",
			((u_char*)rattr_ptr + 2), vattr->length -2,"MS_MPPE_SEND_KEY");
#endif

		if(global->RadiusKey.SendKey.Length <= RADIUS_KEY_LEN )
			memcpy( global->RadiusKey.SendKey.Octet,
				(u_char*)(rattr_ptr + 5),
				global->RadiusKey.SendKey.Length);

		global->RadiusKey.Status |= MPPE_SENDKEY_AVALIABLE;
		if(global->RadiusKey.Status == MPPE_SDRCKEY_AVALIABLE 
#ifndef CONFIG_IEEE80211R
		&& global->AuthKeyMethod == DOT11_AuthKeyType_NonRSN802dot1x
#endif
		)
			global->theAuthenticator->keyxmit_sm->keyAvailable = TRUE;
		//lib1x_message(MESS_DBG_RAD, "global->theAuthenticator->keyxmit_sm->keyAvailable = %x \n",global->theAuthenticator->keyxmit_sm->keyAvailable);
		//lib1x_hexdump2(MESS_DBG_RAD, "lib1x_rad_vendor_attr",
		//	global->RadiusKey.SendKey.Octet, global->RadiusKey.SendKey.Length,"MS_MPPE_SEND_KEY");

		//lib1x_message(MESS_DBG_RAD, "KeyStatus = %x \n",global->RadiusKey.Status);

		break;
	case LIB1X_RADVENDOR_MS_MPPE_RECV_KEY:
		if(vattr->length < 4)
                        return -1;
		//ToDo : check 2 Octes Salt
		lib1x_decrypt_MPPESendRecvKeys(
			&global->auth->RadShared,
			global->theAuthenticator->rinfo->req_authenticator,
			vattr->length - 2,
			((u_char*)rattr_ptr + 2),
			&global->RadiusKey.RecvKey.Length);
#ifdef ALLOW_DBG_RAD
		lib1x_hexdump2(MESS_DBG_RAD, "lib1x_rad_vendor_attr",
			((u_char*)rattr_ptr + 2), vattr->length -2,"MS_MPPE_RECV_KEY");
#endif
		if(global->RadiusKey.RecvKey.Length <= RADIUS_KEY_LEN )
			memcpy( global->RadiusKey.RecvKey.Octet,
				(u_char*)(rattr_ptr + 5),
				global->RadiusKey.RecvKey.Length);
		global->RadiusKey.Status |= MPPE_RECVKEY_AVALIABLE;
  		if(global->RadiusKey.Status == MPPE_SDRCKEY_AVALIABLE 
#ifndef CONFIG_IEEE80211R
		&& global->AuthKeyMethod == DOT11_AuthKeyType_NonRSN802dot1x
#endif
		)
			global->theAuthenticator->keyxmit_sm->keyAvailable = TRUE;

		//lib1x_message(MESS_DBG_RAD, "global->theAuthenticator->keyxmit_sm->keyAvailable = %x \n",global->theAuthenticator->keyxmit_sm->keyAvailable);
		//lib1x_hexdump2(MESS_DBG_RAD, "lib1x_rad_vendor_attr",
		//	global->RadiusKey.RecvKey.Octet, global->RadiusKey.RecvKey.Length,"MS_MPPE_RECV_KEY");
		//lib1x_message(MESS_DBG_RAD, "KeyStatus = %x \n",global->RadiusKey.Status);

		break;
	case LIB1X_RADVENDOR_MS_MPPE_ENCRYPTION_POLICY:
		if(vattr->length != 6)
			return -1;
		break;
	case LIB1X_RADVENDOR_MS_MPPE_ENCRYPTION_TYPES:
		if(vattr->length != 6)
			return -1;
		break;

	}//switch


	return 0;

}

#ifndef COMPACK_SIZE
int lib1x_in_cksum(u_short *addr, int len)
{
    int sum;
    int nleft;
    u_short ans;
    u_short *w;

    sum = 0;
    ans = 0;
    nleft = len;
    w = addr;

    while (nleft > 1)
    {
        sum += *w++;
        nleft -= 2;
    }
    if (nleft == 1)
    {
        *(u_char *)(&ans) = *(u_char *)w;
        sum += ans;
    }
    return (sum);
}
#endif

#ifndef COMPACK_SIZE
void lib1x_do_checksum_ip(u_char *buf,  int len)
{
    struct lib1x_iphdr *iph_p;
    int ip_hl;
    int sum;

    sum = 0;
    iph_p = (struct lib1x_iphdr *)buf;
    ip_hl = iph_p->ip_hl << 2;

    /*
     *  Dug Song came up with this very cool checksuming implementation
     *  eliminating the need for explicit psuedoheader use.  Check it out.
     */
    iph_p->ip_sum = 0;
    sum = libnet_in_cksum((u_short *)iph_p, len);
    iph_p->ip_sum = LIB1X_CKSUM_CARRY(sum);
}
#endif

#ifndef COMPACK_SIZE
/* send ptr to an ip packet .. */
void lib1x_do_checksum_udp(u_char *buf,  int len)
{
    struct lib1x_iphdr *iph_p;
    struct lib1x_udphdr * udph_p;
    int ip_hl;
    int sum;

    sum = 0;
    iph_p = (struct lib1x_iphdr *)buf;
    ip_hl = iph_p->ip_hl << 2;

    udph_p = (struct lib1x_udphdr *)(buf + ip_hl);

    udph_p->sum = 0;
    sum = lib1x_in_cksum((u_short *)&iph_p->ip_src, 8);
    sum += ntohs(LIB1X_IPPROTO_UDP + len);
    sum += libnet_in_cksum((u_short *)udph_p, len);
    udph_p->sum = LIB1X_CKSUM_CARRY(sum);
}
#endif

#ifndef COMPACK_SIZE
u_short lib1x_ip_check(u_short *addr, int len)
{
    int sum;

    sum = libnet_in_cksum(addr, len);
    return (LIB1X_CKSUM_CARRY(sum));
}
#endif





//////////////////////////////////////////////////////////////////////////////////////////////
// MAC Authentication
//////////////////////////////////////////////////////////////////////////////////////////////
//--------------------------------------------------------------
//Borrow the late STA sendBuffer to send LIB1X_RAD_ACCT_STATUS_ON (MAX_SUPPLICANT-1)
//--------------------------------------------------------------

void lib1x_rad_special_type( Auth_Pae * auth_pae, u_long ulRequestType)
{
	struct radius_info   * rinfo;
	struct lib1x_radius_const * rconst = 0;
	int		nas_port;
	int		nas_port_type;
	u_char		szAttr[4];
	u_long		ulPasswordLength;
	u_char		szPassword[20];	/* to store ether addresses */
	u_char		szOutput[64];
	u_long		ulOutput;
	int		framed_mtu = 1400, val;
	struct 		timeval tv;
	struct 		timezone tz;
	char		*src;


	nas_port = 0;
	nas_port_type = LIB1X_80211_NAS_PORTTYPE;	// IEEE 802.11


	rinfo = auth_pae->rinfo;                      // get a handle

	LIB1X_INC_RAD_IDENTIFIER(auth_pae->global->TxRx->GlobalRadId);
	rinfo->identifier = auth_pae->global->TxRx->GlobalRadId;

	//---- create the Accouting Request to  radius server :
	switch(ulRequestType)
	{
		case LIB1X_RAD_AUTH_MAC_AUTHENTICATION:

			lib1x_message(MESS_DBG_RAD, "Send Auth-Request of MAC Authentication to Radius Server");
			lib1x_create_reqauth( auth_pae );
			rconst = lib1x_radconst_create( auth_pae, auth_pae->sendBuffer , LIB1X_RAD_ACCREQ, rinfo->identifier,LIB1X_IT_UDPSOCK_ACCT);
			//user name is mac address of station


			lib1x_print_etheraddr( szOutput, auth_pae->supp_addr );
			lib1x_radconst_addattr( rconst, LIB1X_RAD_USER_NAME, 2*MacAddrLen, (u_char*)szOutput);

			memset(szPassword, 0, sizeof szPassword);
			lib1x_print_etheraddr( szPassword, auth_pae->supp_addr );
			ulPasswordLength = 16*(((2*MacAddrLen)/16) + 1);
			lib1x_radpassword_create( auth_pae, (u_char*)szPassword, ulPasswordLength);
			lib1x_radconst_addattr( rconst, LIB1X_RAD_PASSWORD, 16,  szPassword );


			lib1x_acct_MAC_TO_DASH_ASCII(auth_pae->global->TxRx->oursvr_addr, MacAddrLen, szOutput, &ulOutput);
			lib1x_radconst_addattr( rconst, LIB1X_RAD_CALLED_STID, ulOutput, (u_char*)szOutput);

			lib1x_acct_MAC_TO_DASH_ASCII(auth_pae->supp_addr, MacAddrLen, szOutput, &ulOutput);
			lib1x_radconst_addattr( rconst, LIB1X_RAD_CALLING_STID, ulOutput, (u_char*)szOutput);

			lib1x_radconst_addattr( rconst, LIB1X_RAD_NAS_IDENTIFIER, strlen( rinfo->nas_identifier), rinfo->nas_identifier );

			lib1x_L2N(nas_port, szAttr);
			lib1x_radconst_addattr( rconst, LIB1X_RAD_NAS_PORT, 4,  (u_char *)szAttr);

			lib1x_L2N(LIB1X_80211_NAS_PORTTYPE, szAttr);
			lib1x_radconst_addattr( rconst, LIB1X_RAD_NAS_PORTTYPE, 4, (u_char *)szAttr); //TODO
			val = htonl( nas_port_type );
			src = (char *) rconst->nas_porttype;
			memcpy( src, &val, sizeof(int) );		// jimmylin modify for unaligned access
			//*( rconst->nas_porttype ) = htonl( nas_port_type );

			lib1x_L2N(LIB1X_RAD_SERVICE_TYPE_FRAMED, szAttr);
			lib1x_radconst_addattr( rconst, LIB1X_RAD_SERVICE_TYPE, 4, (u_char *)szAttr );

			lib1x_L2N(framed_mtu, szAttr);
			lib1x_radconst_addattr( rconst, LIB1X_RAD_FRAMED_MTU, 4, (u_char *)szAttr );




			lib1x_radconst_addattr( rconst, LIB1X_RAD_CONNECTINFO, strlen( rinfo->connectinfo), rinfo->connectinfo );



			break;

		case LIB1X_RAD_ACCT_STATUS_ON:
			rconst = lib1x_radconst_create( auth_pae, auth_pae->acct_sendBuffer , LIB1X_RAD_ACCTREQ, rinfo->identifier,LIB1X_IT_UDPSOCK_ACCT);
			lib1x_L2N(LIB1X_RADACCT_STATUS_TYPE_ACCOUNTING_ON, szAttr);
			lib1x_radconst_addattr( rconst, LIB1X_RAD_ACCT_STATUS_TYPE, 4, szAttr);

			lib1x_radconst_addattr( rconst, LIB1X_RAD_USER_NAME, strlen(LIB1X_RADACCT_ACCT_ON_USER_NAME), (u_char*)LIB1X_RADACCT_ACCT_ON_USER_NAME);

			//Use random number as session id
			gettimeofday(&tv, &tz);
			tv.tv_sec ^= getpid();
			lib1x_acct_UCS4_TO_UTF8(tv.tv_sec, (u_char*)szOutput, &ulOutput);
			lib1x_radconst_addattr( rconst, LIB1X_RAD_ACCT_SESSION_ID, ulOutput, szOutput);


			break;

	}


	lib1x_radconst_addattr( rconst, LIB1X_RAD_NAS_IP_ADDRESS, 4, (u_char* ) &auth_pae->global->TxRx->ourip_inaddr );
	lib1x_radconst_calradlength( rconst );

	switch(ulRequestType)
	{
		case LIB1X_RAD_AUTH_MAC_AUTHENTICATION:
			break;

		case LIB1X_RAD_ACCT_STATUS_ON:
			lib1x_create_reqauth_acct(auth_pae, rconst);
			break;

	}







	switch(ulRequestType)
	{
		case LIB1X_RAD_AUTH_MAC_AUTHENTICATION:
			{
				auth_pae->sendbuflen = rconst->pktlen;
				auth_pae->sendreplyready = TRUE;
			}
			break;
		case LIB1X_RAD_ACCT_STATUS_ON:
			lib1x_acctsm_sendReqToServer( auth_pae->global);
			break;

	}

}

/*HS2 SUPPORT*/
void lib1x_rad_disconnect_type( Auth_Pae * auth_pae, u_long ulRequestType)
{
	struct radius_info   * rinfo;
	struct lib1x_radius_const * rconst = 0;
	int		nas_port;
	int		nas_port_type;
	u_char		szAttr[4];
	u_long		ulPasswordLength;
	u_char		szPassword[20];	/* to store ether addresses */
	u_char		szOutput[64];
	u_long		ulOutput;
	int		framed_mtu = 1400, val;
	struct 		timeval tv;
	struct 		timezone tz;
	char		*src;


	nas_port = 0;
	nas_port_type = LIB1X_80211_NAS_PORTTYPE;	// IEEE 802.11


	rinfo = auth_pae->rinfo;                      // get a handle
	rinfo->identifier = auth_pae->acct_sm->sessionId;

	rconst = lib1x_radconst_create( auth_pae, auth_pae->sendBuffer , ulRequestType, rinfo->identifier,LIB1X_IT_UDPSOCK_ACCT);	
	lib1x_radconst_calradlength( rconst );

	auth_pae->acct_sendbuflen = rconst->pktlen;
	auth_pae->sendreplyready = TRUE;
	lib1x_acctsm_sendReqToServer( auth_pae->global);

	//switch(ulRequestType)
	//{
	//	case LIB1X_RAD_AUTH_MAC_AUTHENTICATION:
	//		{
	//			auth_pae->sendbuflen = rconst->pktlen;
	//		lib1x_acctsm_sendReqToServer( auth_pae->global);
	//		break;

	//}
	

}
/*HS2 SUPPORT*/

int lib1x_radpassword_create( Auth_Pae * auth_pae, u_char* pucPassword, u_long ulPasswordLength)
{

	struct radius_info   * rinfo;
	Dot1x_Authenticator *auth = auth_pae->global->auth;
	int	i, j;
	u_char* szBufC[16], szBufB[16];
	u_char* pucPtrPW = pucPassword;
	MD5_CTX the_md5;

	rinfo = auth_pae->rinfo;

	//lib1x_hexdump2(MESS_DBG_RAD, "lib1x_radpassword_create",pucPassword, ulPasswordLength, "pucPassword");

	memcpy(szBufC, rinfo->req_authenticator, sizeof rinfo->req_authenticator);

	////////////////////

	for(i=0 ; i<ulPasswordLength/16 ; i++)
	{


		MD5_Init(&the_md5);
		MD5_Update(&the_md5, (unsigned char *) auth->RadShared.Octet, auth->RadShared.Length);
		MD5_Update(&the_md5, (unsigned char *) szBufC, 16);
		//lib1x_hexdump2(MESS_DBG_RAD, "lib1x_radpassword_create",auth->RadShared.Octet, auth->RadShared.Length, "Update1");
		//lib1x_hexdump2(MESS_DBG_RAD, "lib1x_radpassword_create",(u_char*)szBufC, 16, "szBufC");
		MD5_Final(szBufB, &the_md5);
		//lib1x_hexdump2(MESS_DBG_RAD, "lib1x_radpassword_create",(u_char*)szBufB, 16, "szBufB");
		for(j=0;j<16;j++)
		{
			pucPassword[j] = pucPtrPW[j] ^ szBufB[j];
		}
		//lib1x_hexdump2(MESS_DBG_RAD, "lib1x_radpassword_create",pucPassword, 16, "pucPassword");
		memcpy(szBufC, pucPassword, 16);
		pucPtrPW += 16;


	}
	return 1;

}
//////////////////////////////////////////////////////////////////////////////////////////////
// Accounting Functionality
//////////////////////////////////////////////////////////////////////////////////////////////
//---------------------------------------------------
// lib1x_rad_vendor_attr : process Session_timeout
// Return : 0 for success / others for fail
//---------------------------------------------------
void lib1x_rad_session_timeout(
	Global_Params * global,
	u_char * rattr_ptr,
	int length
)
{
	struct lib1x_radiusattr * rattr = (struct lib1x_radiusattr * )rattr_ptr;
	u_char * pucValue;

	//atribute value is number of consecutive seconds
	pucValue = ( ( u_char *  )rattr ) + 2;
	lib1x_N2L(pucValue, global->akm_sm->SessionTimeout);
	global->akm_sm->SessionTimeoutEnabled = TRUE;
	//global->akm_sm->SessionTimeout = 80;
	lib1x_message(MESS_DBG_RAD, "STA[%d], Session Timeout : %d",global->index, global->auth->Supp[global->index]->SessionTimeoutCounter);
	global->auth->Supp[global->index]->SessionTimeoutCounter = global->akm_sm->SessionTimeout;
	lib1x_PrintAddr(global->theAuthenticator->supp_addr);
}

void lib1x_rad_idle_timeout(
	Global_Params * global,
	u_char * rattr_ptr,
	int length
)
{
	struct lib1x_radiusattr * rattr = (struct lib1x_radiusattr * )rattr_ptr;
	u_char * pucValue;


	//attribute is number of consecutive seconds
	pucValue = ( ( u_char *  )rattr ) + 2;
	lib1x_N2L(pucValue, global->akm_sm->IdleTimeout);
	global->akm_sm->IdleTimeoutEnabled = TRUE;
	lib1x_message(MESS_DBG_RAD, "Idle Timeout : %d", global->auth->Supp[global->index]->IdleTimeout);
	global->auth->Supp[global->index]->IdleTimeout = global->akm_sm->IdleTimeout;
	//lib1x_control_SetExpiredTime(global, 20 * 100);//in 10 mili-seconds
}

void lib1x_rad_interim_timeout(
	Global_Params * global,
	u_char * rattr_ptr,
	int length
)
{
	struct lib1x_radiusattr * rattr = (struct lib1x_radiusattr * )rattr_ptr;
	u_char * pucValue;


	//attribute is number of consecutive seconds
	pucValue = ( ( u_char *  )rattr ) + 2;
	lib1x_N2L(pucValue, global->akm_sm->InterimTimeout);
	global->akm_sm->InterimTimeoutEnabled = TRUE;
	//global->akm_sm->InterimTimeout = 5;
	lib1x_message(MESS_DBG_RAD, "STA[%d], Interim Timeout : %d",global->index, global->akm_sm->InterimTimeout);

}


//end Abocom


