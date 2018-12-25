#include "1x_common.h"
#include "1x_auth_pae.h"
#include "1x_nal.h"
#include "1x_radius.h"
#include "1x_ioctl.h"
#include "1x_kmsm.h"
#include <error.h>
#include <string.h>



void lib1x_acctsm_init(Acct_SM * acct_sm, int maxReq, int aWhile)
{

	acct_sm->status = acctsm_Stop;
	acct_sm->elapsedSessionTime = 0;

	acct_sm->reqCount = 0;
	acct_sm->waitRespond = FALSE;
	acct_sm->serverTimeout = aWhile;
	acct_sm->maxReq = maxReq;
}

void lib1x_acctsm( Global_Params * global)
{

	struct Auth_Pae_tag * auth_pae = global->theAuthenticator;
	Acct_SM * acct_sm = auth_pae->acct_sm;

	/*
	lib1x_message(MESS_DBG_ACCT, "\n-----------\nlib1x_acctsm\n-----------");
	lib1x_message(MESS_DBG_ACCT, "waitRespond = %d", acct_sm->waitRespond);
	lib1x_message(MESS_DBG_ACCT, "aWhile = %d", acct_sm->aWhile);
	lib1x_message(MESS_DBG_ACCT, "reqCount = %d", acct_sm->reqCount);
	lib1x_message(MESS_DBG_ACCT, "maxReq = %d", acct_sm->maxReq);
	*/
	if(acct_sm->waitRespond )
	{
		if(acct_sm->aWhile >=0 )
		{
			acct_sm->aWhile--;
		}
		else
		{
			if(acct_sm->reqCount <= acct_sm->maxReq)
			{
				acct_sm->reqCount++;
				lib1x_acctsm_sendReqToServer( global );
				acct_sm->aWhile = acct_sm->serverTimeout;
			}else
			{


				acct_sm->aWhile = acct_sm->serverTimeout;
				acct_sm->waitRespond = FALSE;
			}
		}

	}


}

BOOLEAN lib1x_acctsm_request( struct Global_Params_tag * global, int iAction, int iTerminateCause)
{
	struct Auth_Pae_tag * auth_pae = global->theAuthenticator;
	Acct_SM * acct_sm = auth_pae->acct_sm;

	switch(iAction)
	{

		case	acctsm_Acct_Start:
			lib1x_message(MESS_DBG_ACCT,"acctsm_Acct_Start\n");
			//reauthenticaton through eapol-start (not association request) do not send Acct-Start
			if(acct_sm->status == acctsm_Stop)
			{

				acct_sm->status = acctsm_Start;
				acct_sm->sessionId = global->auth->GlobalSessionId;
				lib1x_message(MESS_DBG_ACCT, "==============================================\n");
				lib1x_message(MESS_DBG_ACCT, "global->auth->GlobalSessionId = %d\n", global->auth->GlobalSessionId);
				lib1x_message(MESS_DBG_ACCT, "==============================================\n");
				lib1x_acct_request( auth_pae, LIB1X_RADACCT_ACTION_ACCOUNT_START, 0);
				global->auth->GlobalSessionId++;
			}


			break;
		case	acctsm_Acct_Stop:
			lib1x_message(MESS_DBG_ACCT,"acctsm_Acct_Stop\n");
			if(acct_sm->status == acctsm_Start)
			{
				lib1x_acct_request( auth_pae, LIB1X_RADACCT_ACTION_ACCOUNT_STOP, iTerminateCause);
				acct_sm->status = acctsm_Stop;
			}
			break;
		case	acctsm_Acct_On:
			lib1x_acct_request( auth_pae, LIB1X_RADACCT_ACTION_ACCOUNT_ON, 0);
			break;
		case	acctsm_Interim_On:
			if(acct_sm->status == acctsm_Start)
			{
				lib1x_acct_request( auth_pae, LIB1X_RADACCT_ACTION_INTERIM_UPDATE, 0);
			}
			break;

	}

	//acct_sm->action = acctsm_Acct_No_Action;
	return TRUE;

}

BOOLEAN lib1x_nal_send_acct( Auth_Pae * auth_pae, struct lib1x_nal_intfdesc * desc,  char * packet , int size)
{
	int num_sent = 0;
	Acct_SM * acct_sm = auth_pae->acct_sm;

	//lib1x_hexdump2(MESS_DBG_NAL, "lib1x_nal_send",  packet, size, "Send Out Packet");
	if ( desc->inttype == LIB1X_IT_PKTSOCK )
	{
	//	if ( size > 1499 ) size = 1499; /* needed for ethernet only if you are not handling fragmentation */
		if ( desc->libnet_desc  == NULL )
			lib1x_message( MESS_ERROR_FATAL, "lib1x_nal_send: Descriptor contains invalid network identifier.");

		num_sent = libnet_write_link_layer( desc->libnet_desc, desc->device ,
			packet, size );
		lib1x_message(MESS_DBG_NAL, "libnet_write_link_layer send packets %d\n", num_sent);
	}
	else
	{
		num_sent =  send( desc->acctsock, (void*) packet, size, 0); /* flags = 0 */
		acct_sm->waitRespond = TRUE;
		acct_sm->aWhile = acct_sm->serverTimeout;
		lib1x_message( MESS_DBG_SPECIAL, "lib1x_nal_send: Sending Accounting UDP packet.");
	}
	if ( num_sent != size )
	{
		lib1x_message( MESS_ERROR_OK, "lib1x_nal_send: Mismatch in send size!");
		lib1x_message( MESS_ERROR_FATAL," NUM_SENT : %d . actual %d", num_sent, size );
		return FALSE;
	}
	return TRUE;
}

int lib1x_acctsm_sendReqToServer( Global_Params * global)
{


	Auth_Pae * auth_pae;
	int size;
	u_char * sendptr;

	auth_pae = global->theAuthenticator;

	lib1x_message( MESS_DBG_ACCT, " lib1x_acctsm_sendReqToServer================.");
	//if ( auth_pae->sendreplyready )
	{


		/* temporary hack to use udp sockets  TODO*/
		sendptr = auth_pae->acct_sendBuffer + ETHER_HDRLEN + LIB1X_IPHDRLEN + LIB1X_UDPHDRLEN;
		size = auth_pae->acct_sendbuflen;

		size -= ETHER_HDRLEN + LIB1X_IPHDRLEN + LIB1X_UDPHDRLEN;

		lib1x_nal_send_acct( auth_pae, auth_pae->global->TxRx->network_svr, sendptr,  size );
		lib1x_message( MESS_DBG_ACCT, " Sending Accouting information to server.");
		//auth_pae->sendreplyready = FALSE;

	}
	return TRUE;

}

int lib1x_acct_request( Auth_Pae * auth_pae, unsigned int msg_type, int iTerminateCause)
{
	struct radius_info   * rinfo;
	struct lib1x_radius_const * rconst;
	 Acct_SM * acct_sm = auth_pae->acct_sm;
	int		nas_port;
	int		nas_port_type;
	u_char		szAttr[4];
	u_char		szUTF8[6];
	u_long		ulUTF8Len;

	u_char		szOutput[64];
	u_long		ulOutput;
	struct 		timeval tv;
	struct 		timezone tz;
	int			val;
	char		*src;




	nas_port = 0;
	nas_port_type = LIB1X_80211_NAS_PORTTYPE;	// IEEE 802.11


	rinfo = auth_pae->rinfo;                      // get a handle

	lib1x_message(MESS_DBG_ACCT, "Send Acct-Request to Radius Server");


	rinfo->username_len = strlen(rinfo->username);
	auth_pae->global->TxRx->GlobalRadId ++;
	rinfo->identifier = auth_pae->global->TxRx->GlobalRadId;
	lib1x_create_reqauth( auth_pae );

	//---- create the Accouting Request to  radius server :
	rconst = lib1x_radconst_create( auth_pae, auth_pae->acct_sendBuffer , LIB1X_RAD_ACCTREQ, rinfo->identifier,LIB1X_IT_UDPSOCK_ACCT);

	if ( rinfo->username_len != 0 )
		lib1x_radconst_addattr( rconst, LIB1X_RAD_USER_NAME , rinfo->username_len, rinfo->username);

#ifdef HS2_SUPPORT
	u_char HS2_AP_VER_ATTR[9]={0x68,0x9F,0x00,0x00,0x02,0x03,0x01}; // hs20-radius.txt
	lib1x_radconst_addattr( rconst, LIB1X_RAD_VENDOR_SPECIFIC , 9, HS2_AP_VER_ATTR);
	u_char HS2_DEVICE_VER_ATTR[9]={0x68,0x9F,0x00,0x00,0x03,0x03,0x01}; // hs20-radius.txt
	lib1x_radconst_addattr( rconst, LIB1X_RAD_VENDOR_SPECIFIC , 9, HS2_DEVICE_VER_ATTR);	
#endif

	if(msg_type != LIB1X_RADACCT_ACTION_ACCOUNT_ON)
	{
		lib1x_radconst_addattr( rconst, LIB1X_RAD_NAS_PORTTYPE, 4, (u_char * )  & nas_port_type ); //TODO
		val = htonl( nas_port_type );
		src = (char *) rconst->nas_porttype;
		memcpy( src, &val, sizeof(int) );		// jimmylin modify for unaligned access
		//*( rconst->nas_porttype ) = htonl( nas_port_type );
		//lib1x_radconst_addattr( rconst, LIB1X_RAD_CONNECTINFO, strlen( rinfo->connectinfo), rinfo->connectinfo );


		lib1x_acct_UCS4_TO_UTF8( auth_pae->acct_sm->sessionId, (u_char*)szUTF8, &ulUTF8Len);
		lib1x_radconst_addattr( rconst, LIB1X_RAD_ACCT_SESSION_ID, ulUTF8Len, szUTF8);
	}
	//lib1x_message(MESS_DBG_ACCT, "==============================================\n");
	//lib1x_message(MESS_DBG_ACCT, "auth_pae->acct_sm->sessionId = %d\n", auth_pae->acct_sm->sessionId);
	//lib1x_hexdump2(MESS_DBG_ACCT, "lib1x_acct_request", szUTF8, ulUTF8Len, "Session-ID");
	//lib1x_message(MESS_DBG_ACCT, "==============================================\n");

	// Accounting Information

	switch(msg_type)
	{
		case LIB1X_RADACCT_ACTION_ACCOUNT_START:
			lib1x_L2N(LIB1X_RADACCT_STATUS_TYPE_START, szAttr);
			lib1x_radconst_addattr( rconst, LIB1X_RAD_ACCT_STATUS_TYPE, 4, szAttr);
			lib1x_L2N(LIB1X_RADACCT_AUTHENTIC_RADIUS, szAttr);
			lib1x_radconst_addattr( rconst, LIB1X_RAD_ACCT_AUTHENTIC, 4, szAttr);
			lib1x_message(MESS_DBG_ACCT, "LIB1X_RADACCT_ACTION_ACCOUNT_START");
			break;

		case LIB1X_RADACCT_ACTION_ACCOUNT_STOP:
			lib1x_L2N(LIB1X_RADACCT_STATUS_TYPE_STOP, szAttr);
			lib1x_radconst_addattr( rconst, LIB1X_RAD_ACCT_STATUS_TYPE, 4, szAttr);

			//lib1x_control_QuerySTA(auth_pae->global, &Query_Stat);

			lib1x_L2N(acct_sm->rx_bytes, szAttr);
			lib1x_radconst_addattr( rconst, LIB1X_RAD_ACCT_INPUT_OCTETS, 4, szAttr);

			lib1x_L2N(acct_sm->tx_bytes, szAttr);
			lib1x_radconst_addattr( rconst, LIB1X_RAD_ACCT_OUTPUT_OCTETS, 4, szAttr);

			lib1x_L2N(acct_sm->rx_packets, szAttr);
			lib1x_radconst_addattr( rconst, LIB1X_RAD_ACCT_INPUT_PACKETS, 4, szAttr);

			lib1x_L2N(acct_sm->tx_packets, szAttr);
			lib1x_radconst_addattr( rconst, LIB1X_RAD_ACCT_OUTPUT_PACKETS, 4, szAttr);


			//lib1x_L2N(0, szAttr);
			//lib1x_radconst_addattr( rconst, LIB1X_RAD_ACCT_INPUT_GIGAWORDS, 4, szAttr);

			//lib1x_L2N(0, szAttr);
			//lib1x_radconst_addattr( rconst, LIB1X_RAD_ACCT_OUTPUT_GIGAWORDS, 4, szAttr);


			lib1x_L2N(auth_pae->acct_sm->elapsedSessionTime, szAttr);
			lib1x_radconst_addattr( rconst, LIB1X_RAD_ACCT_SESSION_TIME, 4, szAttr);

			//ulTerminateCause = lib1x_acct_maperr_wlan2acct(auth_pae->global->akm_sm->ErrorRsn);
			lib1x_L2N(iTerminateCause, szAttr);
			lib1x_radconst_addattr( rconst, LIB1X_RAD_ACCT_TERMINATE_CAUSE, 4, szAttr);

			lib1x_message(MESS_DBG_ACCT, "LIB1X_RADACCT_ACTION_ACCOUNT_STOP");
			break;

		case LIB1X_RADACCT_ACTION_ACCOUNT_ON:

			lib1x_L2N(LIB1X_RADACCT_STATUS_TYPE_ACCOUNTING_ON, szAttr);
			lib1x_radconst_addattr( rconst, LIB1X_RAD_ACCT_STATUS_TYPE, 4, szAttr);

			//Use random number as session id
			gettimeofday(&tv, &tz);
			tv.tv_sec ^= getpid();
			lib1x_acct_UCS4_TO_UTF8(tv.tv_sec, (u_char*)szOutput, &ulOutput);
			lib1x_radconst_addattr( rconst, LIB1X_RAD_ACCT_SESSION_ID, ulOutput, szOutput);

			break;

		case LIB1X_RADACCT_ACTION_INTERIM_UPDATE:




			lib1x_L2N(LIB1X_RADACCT_STATUS_TYPE_INTERIM_UPDATE, szAttr);
			lib1x_radconst_addattr( rconst, LIB1X_RAD_ACCT_STATUS_TYPE, 4, szAttr);

			lib1x_control_QuerySTA(auth_pae->global);
  			//lib1x_message(MESS_DBG_ACCT, "tx_packets= %d", Query_Stat.tx_packets);
			//lib1x_message(MESS_DBG_ACCT, "rx_packets= %d", Query_Stat.rx_packets);
			//lib1x_message(MESS_DBG_ACCT, "tx_bytes= %d", Query_Stat.tx_bytes);
			//lib1x_message(MESS_DBG_ACCT, "rx_bytes= %d", Query_Stat.rx_bytes);
			lib1x_message(MESS_DBG_ACCT, "tx_packets= %d", auth_pae->global->theAuthenticator->acct_sm->tx_packets);
			lib1x_message(MESS_DBG_ACCT, "rx_packets= %d", auth_pae->global->theAuthenticator->acct_sm->rx_packets);
			lib1x_message(MESS_DBG_ACCT, "tx_bytes= %d", auth_pae->global->theAuthenticator->acct_sm->tx_bytes);
			lib1x_message(MESS_DBG_ACCT, "rx_bytes= %d", auth_pae->global->theAuthenticator->acct_sm->rx_bytes);




			lib1x_L2N(acct_sm->rx_bytes, szAttr);
			lib1x_radconst_addattr( rconst, LIB1X_RAD_ACCT_INPUT_OCTETS, 4, szAttr);

			lib1x_L2N(acct_sm->tx_bytes, szAttr);
			lib1x_radconst_addattr( rconst, LIB1X_RAD_ACCT_OUTPUT_OCTETS, 4, szAttr);

			lib1x_L2N(acct_sm->rx_packets, szAttr);
			lib1x_radconst_addattr( rconst, LIB1X_RAD_ACCT_INPUT_PACKETS, 4, szAttr);

			lib1x_L2N(acct_sm->tx_packets, szAttr);
			lib1x_radconst_addattr( rconst, LIB1X_RAD_ACCT_OUTPUT_PACKETS, 4, szAttr);


			//lib1x_L2N(0, szAttr);
			//lib1x_radconst_addattr( rconst, LIB1X_RAD_ACCT_INPUT_GIGAWORDS, 4, szAttr);

			//lib1x_L2N(0, szAttr);
			//lib1x_radconst_addattr( rconst, LIB1X_RAD_ACCT_OUTPUT_GIGAWORDS, 4, szAttr);


			lib1x_L2N(auth_pae->acct_sm->elapsedSessionTime, szAttr);
			lib1x_radconst_addattr( rconst, LIB1X_RAD_ACCT_SESSION_TIME, 4, szAttr);


			lib1x_message(MESS_DBG_ACCT, "LIB1X_RADACCT_ACTION_INTERIM_UPDATE");


			break;

		case LIB1X_RADACCT_ACTION_TERMINATE_CAUSE:
			lib1x_L2N(iTerminateCause, szAttr);
			lib1x_radconst_addattr( rconst, LIB1X_RADACCT_ACTION_TERMINATE_CAUSE, 4, szAttr);
			lib1x_message(MESS_DBG_ACCT, "LIB1X_RADACCT_ACTION_TERMINATE_CAUSE");
			break;
	}


	lib1x_radconst_addattr( rconst, LIB1X_RAD_NAS_IP_ADDRESS, 4, (u_char* ) &auth_pae->global->TxRx->ourip_inaddr );


	if(msg_type != LIB1X_RADACCT_ACTION_ACCOUNT_ON)
	{
		lib1x_radconst_addattr( rconst, LIB1X_RAD_NAS_PORT, 4,  (u_char * ) & nas_port);
		lib1x_radconst_addattr( rconst, LIB1X_RAD_NAS_IDENTIFIER, strlen( rinfo->nas_identifier), rinfo->nas_identifier );

		lib1x_L2N(0, szAttr);
		lib1x_radconst_addattr( rconst, LIB1X_RAD_ACCT_DELAY_TIME, 4, szAttr);

#ifndef _ABOCOM
		lib1x_print_etheraddr( szOutput, auth_pae->global->TxRx->oursvr_addr );
#else
		lib1x_acct_MAC_TO_DASH_ASCII(auth_pae->global->TxRx->oursvr_addr, MacAddrLen, szOutput, &ulOutput);
#endif
		lib1x_radconst_addattr( rconst, LIB1X_RAD_CALLED_STID, strlen( szOutput),  szOutput );

#ifndef _ABOCOM
		lib1x_print_etheraddr( szOutput, auth_pae->supp_addr );

#else
		lib1x_acct_MAC_TO_DASH_ASCII(auth_pae->supp_addr, MacAddrLen, szOutput, &ulOutput);
#endif
		lib1x_radconst_addattr( rconst, LIB1X_RAD_CALLING_STID, strlen( szOutput),  szOutput );
	}

	lib1x_radconst_calradlength( rconst );

	lib1x_create_reqauth_acct(auth_pae, rconst);

	auth_pae->acct_sendbuflen = rconst->pktlen;
	auth_pae->sendreplyready = TRUE;

	lib1x_acctsm_sendReqToServer( auth_pae->global);

	return TRUE;
}



u_long lib1x_acct_maperr_wlan2acct(u_long ulReason)
{
	u_long	retVal = unspec_reason;
	switch(ulReason)
	{
		case	unspec_reason:
			retVal = LIB1X_ACCT_REASON_LOST_SERVICE;
			break;

        	case	auth_not_valid:
			retVal = LIB1X_ACCT_REASON_LOST_CARRIER;
			break;

   		case	deauth_lv_ss:
			retVal = LIB1X_ACCT_REASON_LOST_CARRIER;
			break;

        	case	inactivity:
			retVal = LIB1X_ACCT_REASON_IDLE_TIMEOUT;
			break;

        	case	ap_overload:
			retVal = LIB1X_ACCT_REASON_LOST_SERVICE;
			break;

        	case	class2_err:
			retVal = LIB1X_ACCT_REASON_LOST_CARRIER;
			break;

        	case	class3_err:
			retVal = LIB1X_ACCT_REASON_LOST_CARRIER;
			break;

        	case	disas_lv_ss:
			retVal = LIB1X_ACCT_REASON_LOST_SERVICE;
			break;

        	case	asoc_not_auth:
			retVal = LIB1X_ACCT_REASON_LOST_SERVICE;
			break;


        	case	RSN_invalid_info_element:
			retVal = LIB1X_ACCT_REASON_LOST_SERVICE;
			break;

        	case	RSN_MIC_failure:
			retVal = LIB1X_ACCT_REASON_LOST_SERVICE;
			break;

        	case	RSN_4_way_handshake_timeout:
			retVal = LIB1X_ACCT_REASON_LOST_SERVICE;
			break;

        	case	RSN_diff_info_element:
			retVal = LIB1X_ACCT_REASON_LOST_SERVICE;
			break;

        	case	RSN_multicast_cipher_not_valid:
			retVal = LIB1X_ACCT_REASON_LOST_SERVICE;
			break;

        	case	RSN_unicast_cipher_not_valid:
			retVal = LIB1X_ACCT_REASON_LOST_SERVICE;
			break;

        	case	RSN_AKMP_not_valid:
			retVal = LIB1X_ACCT_REASON_LOST_SERVICE;
			break;

        	case	RSN_unsupported_RSNE_version:
			retVal = LIB1X_ACCT_REASON_LOST_SERVICE;
			break;

        	case	RSN_invalid_RSNE_capabilities:
			retVal = LIB1X_ACCT_REASON_LOST_SERVICE;
			break;

        	case	RSN_ieee_802dot1x_failed:
			retVal = LIB1X_ACCT_REASON_LOST_SERVICE;
			break;

			case	session_timeout:
			retVal = LIB1X_ACCT_REASON_SESSION_TIMEOUT;

	}
	return retVal;
}
void lib1x_acct_UCS4_TO_UTF8(u_long ud, u_char * pucUTF8, u_long * ulUTF8Len)
{

	//From Unicode UCS-4 to UTF-8:
	//Start with the Unicode number expressed as a decimal number and call this ud.

	if( ud <128) //(7F hex)
	{
		*ulUTF8Len = 1;
		pucUTF8[0] = (u_char)ud;

	}

	if( ud >=128 && ud<=2047)// (7FF hex) then UTF-8 is 2 bytes long.
	{
		*ulUTF8Len = 2;
		pucUTF8[0] = 192 + (ud / 64);
		pucUTF8[1] = 128 + (ud % 64);
	}

	if( ud >=2048 && ud<=65535)// (FFFF hex) then UTF-8 is 3 bytes long.
	{
		*ulUTF8Len = 3;
		pucUTF8[0] = 224 + (ud / 4096);
		pucUTF8[1] = 128 + ((ud / 64) % 64);
		pucUTF8[2] = 128 + (ud % 64);
	}

	if( ud >=65536 && ud<=2097151)// (1FFFFF hex) then UTF-8 is 4 bytes long.
	{
		*ulUTF8Len = 4;
		pucUTF8[0] = 240 + (ud / 262144);
		pucUTF8[1] = 128 + ((ud / 4096) % 64);
		pucUTF8[2] = 128 + ((ud / 64) % 64);
		pucUTF8[3] = 128 + (ud % 64);
	}

	if( ud >=2097152 && ud<=67108863)// (3FFFFFF hex) then UTF-8 is 5 bytes long.
	{
		*ulUTF8Len = 5;
		pucUTF8[0] = 248 + (ud / 16777216);
		pucUTF8[1] = 128 + ((ud / 262144) % 64);
		pucUTF8[2] = 128 + ((ud / 4096) % 64);
		pucUTF8[3] = 128 + ((ud / 64) % 64);
		pucUTF8[4] = 128 + (ud % 64);
	}

	if( ud >=67108864 && ud<=2147483647)// (7FFFFFFF hex) then UTF-8 is 6 bytes long.
	{
		*ulUTF8Len = 6;
		pucUTF8[0] = 252 + (ud / 1073741824);
		pucUTF8[1] = 128 + ((ud / 16777216) % 64);
		pucUTF8[2] = 128 + ((ud / 262144) % 64);
		pucUTF8[3] = 128 + ((ud / 4096) % 64);
		pucUTF8[4] = 128 + ((ud / 64) % 64);
		pucUTF8[5] = 128 + (ud % 64);
	}

}
#ifndef COMPACK_SIZE
void lib1x_acct_MAC_TO_UTF8(u_char * pucInput, u_long ulInput, u_char * pucOutput, u_long * ulOutputLen)
{

	//From Unicode UCS-4 to UTF-8:
	//Start with the Unicode number expressed as a decimal number and call this ud.

	u_long ulIndex;
	int i = 0;
	u_long	ulOutLen = 0;


	for(ulIndex = 0;ulIndex < ulInput; ulIndex++)
	{
		printf("ulIndex = %d\n", (int)ulIndex);
		if(pucInput[ulIndex] < 128)
		{
			pucOutput[i++] = pucInput[ulIndex];
			ulOutLen++;
		}
		else
		{
			pucOutput[i++] = 192 + (pucInput[ulIndex] / 64);
			pucOutput[i++] = 128 + (pucInput[ulIndex] % 64);
			ulOutLen +=2;
		}
		printf("ulOutputLen = %d\n", (int)ulOutLen);
	}
	*ulOutputLen = ulOutLen;
	printf("ulOutputLen = %d\n", (int)*ulOutputLen);

}
#endif
void lib1x_acct_MAC_TO_DASH_ASCII(u_char * pucInput, u_long ulInput, u_char * pucOutput, u_long * ulOutputLen)
{

	//From Unicode UCS-4 to UTF-8:
	//Start with the Unicode number expressed as a decimal number and call this ud.
	/*
	u_long ulIndex;
	int i = 0;
	u_long	ulOutLen = 0;


	for(ulIndex = 0;ulIndex < ulInput; ulIndex++)
	{
		pucOutput[i++] = ((pucInput[ulIndex]& 0xf0)>>4) + 0x30;
		pucOutput[i++] = ((pucInput[ulIndex]& 0x0f)) + 0x30;
		ulOutLen +=2;
	}
	*ulOutputLen = ulOutLen;
	*/
	 sprintf(pucOutput,"%02x-%02x-%02x-%02x-%02x-%02x", pucInput[0], pucInput[1], pucInput[2],
	 	pucInput[3], pucInput[4], pucInput[5] );
	*ulOutputLen = 17;

}
