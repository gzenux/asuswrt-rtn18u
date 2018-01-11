


//--------------------------------------------------
// IEEE 802.1x Implementation
//
// File		: 1x_common.c
// Programmer	: Arunesh Mishra
// Common routines
//
//
// Copyright (c) Arunesh Mishra 2002
// All rights reserved.
// Maryland Information and Systems Security Lab
// University of Maryland, College Park.
//--------------------------------------------------

#ifdef _RTL_WPA_WINDOWS
#else
#include "1x_common.h"
#endif
#include <stdio.h>

//#define ALLOW_ERR_OK
//#define ALLOW_ERR_FATAL
//#define ALLOW_DBG_AUTH		/* state machines et al */
//#define ALLOW_DBG_AUTHSM
//#define ALLOW_DBG_AUTHNET		/* the network packets part of authenticator */
//#define ALLOW_DBG_KRCSM
//#define ALLOW_DBG_KXSM
//#define ALLOW_AUTH_LOG
//#define ALLOW_DBG_NAL
//#define ALLOW_DBG_BSM
//#define ALLOW_DBG_RAD
//#define ALLOW_DBG_SPECIAL
//#define ALLOW_DBG_DAEMON
//#define ALLOW_DBG_KEY_MANAGE
//#define ALLOW_DBG_CONTROL
//#define ALLOW_DBG_PTSM
//#define ALLOW_DBG_RSNINFO
//#define ALLOW_DBG_CONFIG
//#define ALLOW_DBG_ACCT
//#define ALLOW_DBG_FIFO
//#define ALLOW_DBG_SUPP

#ifndef DEBUG_DISABLE

// Message printing routine.
//--------------------------------------------------
void lib1x_message( int type, char * msg, ... )
{

	va_list ap;
	static char buf[MESS_BUF_SIZE];	// made static for optimization


	 va_start(ap, msg);
	 vsnprintf(buf, sizeof(buf) - 1, msg, ap);
	 switch( type )
	 {
#ifdef ALLOW_ERR_OK
		 case MESS_ERROR_OK:
					printf("\n ERROR OK: %s", buf);
					break;
#endif
#ifdef ALLOW_ERR_FATAL
		 case MESS_ERROR_FATAL:
		 			printf("\n FATAL :%s", buf );
	 				//fprintf(stderr, "\n FATAL :%s", buf );
					//exit(0);
					break;
#endif
#ifdef ALLOW_DBG_AUTH
		 case MESS_DBG_AUTH:
	 				fprintf(stderr, "\n Authenticator: %s",buf );
					fflush(stderr);
				break;
#endif
#ifdef ALLOW_DBG_AUTHNET
		 case MESS_DBG_AUTHNET:
	 				fprintf(stderr, "\n Auth Network : %s",buf );
					fflush(stderr);
				break;
#endif
#ifdef ALLOW_DBG_AUTHSM
		 case MESS_DBG_AUTHSM:
	 				fprintf(stderr, "\n Auth States: %s",buf );
					fflush(stderr);
				break;
#endif
#ifdef ALLOW_DBG_KRCSM
		 case MESS_DBG_KRCSM:
	 				fprintf(stderr, "\n Key Receive State Machine: %s",buf );
					fflush(stderr);
				break;
#endif
#ifdef ALLOW_DBG_KXSM
		 case MESS_DBG_KXSM:
	 				fprintf(stderr, "\n Key Transmit State Machine: %s",buf );
					fflush(stderr);
				break;
#endif
#ifdef ALLOW_AUTH_LOG
		 case MESS_AUTH_LOG:
	 				fprintf(stderr, "\n Authenticator Log: %s",buf );
					fflush(stderr);
				break;
#endif
#ifdef ALLOW_DBG_NAL
		 case MESS_DBG_NAL:
	 				fprintf(stderr, "\n NAL DEBUG: %s",buf );
					fflush(stderr);
				break;
#endif
#ifdef ALLOW_DBG_BSM
		 case MESS_DBG_BSM:
					printf("\n Bauthsm DEBUG:%s\n", buf);
				break;
#endif
#ifdef ALLOW_DBG_RAD
		 case MESS_DBG_RAD:
					printf("\n Radius DEBUG:%s\n", buf);
				break;
#endif
#ifdef ALLOW_DBG_PTSM
		case MESS_DBG_PTSM:
					printf("\n PTSM Debuf: %s", buf);
					break;
					
#endif
#ifdef ALLOW_DBG_DAEMON
		case MESS_DBG_DAEMON:
					printf("\n DAEMON DEBUG: %s", buf);
				break;
#endif
#ifdef ALLOW_DBG_SPECIAL
		 case MESS_DBG_SPECIAL:
					printf("\n Special Debug:%s\n", buf);
					break;
#endif
#ifdef ALLOW_DBG_KEY_MANAGE
                 case MESS_DBG_KEY_MANAGE:
					printf("\n Key Management DEBUG: %s", buf);
                                        break;
#endif

#ifdef ALLOW_DBG_CONTROL
                case MESS_DBG_CONTROL:
                                        printf("\n Control Debug: %s", buf);
                                        //fprintf(stderr, "\n CONTROL DEBUG: %s",buf );
                                        //fflush(stderr);
                                break;
#endif


#ifdef ALLOW_DBG_RSNINFO
                case MESS_DBG_RSNINFO:
                                        printf("\n RSNINFO Debug: %s", buf);
                                        //fprintf(stderr, "\n CONTROL DEBUG: %s",buf );
                                        //fflush(stderr);
                                break;
#endif

#ifdef ALLOW_DBG_CONFIG
                case MESS_DBG_CONFIG:
                                        printf("\n Config Debug: %s", buf);
                                        //fprintf(stderr, "\n CONTROL DEBUG: %s",buf );
                                        //fflush(stderr);
                                break;
#endif


#ifdef ALLOW_DBG_ACCT
		case MESS_DBG_ACCT:
					printf("\n Acct Debug: %s", buf);
				break;
#endif

#ifdef ALLOW_DBG_FIFO
		case MESS_DBG_FIFO:
                                        printf("\n Fifo Debug: %s", buf);
	                                break;
#endif

#ifdef ALLOW_DBG_SUPP
		case MESS_DBG_SUPP:
					printf("\n SUPP Debug: %s", buf);
	                                break;
#endif
	 }
	 va_end(ap);
					
}
	


/* better pass argument as a multiple of eight */
void lib1x_hexdump( FILE * fdesc, u_char * pkt, int numBytes )
{
	int i;
	fprintf( fdesc, "\n\n Packet Dump \n");
	for ( i = 0; i < numBytes; i += 8  )
	{
		fprintf(fdesc, " %02X :    %02X %02X %02X %02X     %02X %02X %02X %02X  \n", i, pkt[i], pkt[i+1], pkt[i+2], pkt[i+3],
				pkt[i+4], pkt[i+5], pkt[i+6], pkt[i+7] );
	}
	fprintf(fdesc, "\n\n");

}


void lib1x_totext_authpaestate( FILE * fdesc, AUTH_PAE_STATE state )
{
	switch(  state )
	{
		case apsm_Initialize      :fprintf(fdesc, "Initialize"); break;
		case apsm_Disconnected    :fprintf(fdesc, "Disconnected"); break;
		case apsm_Connecting      :fprintf(fdesc, "Connecting"); break;
		case apsm_Authenticating  :fprintf(fdesc, "Authenticating"); break;
		case apsm_Authenticated   :fprintf(fdesc, "Authenticated"); break;
		case apsm_Aborting        :fprintf(fdesc, "Aborting"); break;
		case apsm_Held            :fprintf(fdesc, "Held"); break;
		case apsm_Force_Auth      :fprintf(fdesc, "Force_Auth"); break;
		case apsm_Force_Unauth    :fprintf(fdesc, "Force_Unauth"); break;
	}
}


void lib1x_totext_bauthsmstate( FILE * fdesc, BAUTH_SM_STATE state )
{
	switch(  state )
	{
		case basm_Request 	  :fprintf(fdesc, "Request "); break;
		case basm_Response	  :fprintf(fdesc, "Response "); break;
		case basm_Success	  :fprintf(fdesc, "Success"); break;
		case basm_Fail	          :fprintf(fdesc, "Fail"); break;
		case basm_Timeout 	  :fprintf(fdesc, "Timeout"); break;
		case basm_Idle	          :fprintf(fdesc, "Idle"); break;
		case basm_Initialize      :fprintf(fdesc, "Initialize"); break;
	}
}

void lib1x_chardump( FILE * fdesc, u_char * pkt, int numBytes )
{
	int i;
	fprintf( fdesc, "\n\n Packet Dump : CHAR\n");
	for ( i = 0; i < numBytes; i += 8  )
	{
		fprintf(fdesc, " %02X :    %02X  '%c'    %02X  '%c'    %02X  '%c'     %02X  '%c'         %02X  '%c'     %02X  '%c'     %02X  '%c'     %02X  '%c'      \n", i, pkt[i], pkt[i], pkt[i+1], pkt[i+ 1], pkt[i+2], pkt[i+2],  pkt[i+3], pkt[i+3], 
				pkt[i+4],pkt[i+4], pkt[i+5],pkt[i+5], pkt[i+6],pkt[i+6], pkt[i+7], pkt[i+7] );
	}
	fprintf(fdesc, "\n\n");

}


void lib1x_hexdump2(int type, char *fun, u_char *buf, int size, char *comment)
{
	int i;

	
	lib1x_message(type, "$$ %s $$: %s", fun, comment);

	if(type)
	{
		if (buf != NULL /*&& EAPOL_DEBUG >=2 */) {
			lib1x_message(type, "\tMessage is %d bytes %x hex", size, size);
			for (i = 0; i < size; i++) {
				if (i % 16 == 0) printf("\n\t\t");
					printf("%2x ", *(buf+i));
			}
	  	}
		printf("\n");
	}

}


void lib1x_PrintAddr(u_char * ucAddr)
{

#ifdef ALLOW_DBG_SPECIAL	
	int i;
	for(i=0 ;i<6; i++)
		printf("%2x ", *(ucAddr+i));
	printf("\n");
#endif
}

#ifdef _ABOCOM
void lib1x_abocom(u_char *pucAddr,  int ulCommandType)
{
	u_char szCommand[256];
	memset(szCommand, 0, sizeof szCommand);
	switch(ulCommandType)		
	{
		
		case ABOCOM_ADD_STA:
			sprintf(szCommand, "acl -a  %02x:%02x:%02x:%02x:%02x:%02x",
				pucAddr[0], pucAddr[1], pucAddr[2], pucAddr[3], pucAddr[4], pucAddr[5]);
			break;
			
		case ABOCOM_DEL_STA:
			sprintf(szCommand, "acl -d  %02x:%02x:%02x:%02x:%02x:%02x",
				pucAddr[0], pucAddr[1], pucAddr[2], pucAddr[3], pucAddr[4], pucAddr[5]);

			break;
	}
	printf("\n============================================\n");
	printf(szCommand);
	printf("\n==========================================\n");
	system(szCommand);

}
#endif

#define PRINT_BOOLEAN(s,val) printf("%s = %s\n", s, (val)?"TRUE":"FALSE" );
#define PRINT_INT(s,val) printf("%s = %d\n", s, val);

void DUMP_GLOBAL_PARAMS( Global_Params *g, u_char *exp )
{

	u_char *p = g->CurrentAddress;

	printf("- %s - %02x:%02x:%02x:%02x:%02x:%02x -\n", exp, p[0], p[1], p[2], p[3], p[4], p[5]);

	printf("g->authStart = %d\n", g->authStart );
	printf("g->authSuccess = %d\n", g->authSuccess );
	printf("g->currentId = %d\n", g->currentId );
	printf("g->portEnabled = %d\n", g->portEnabled );
	printf("g->receivedId = %d\n", g->receivedId );

	printf("g->reAuthenticate = %d\n", g->reAuthenticate );
	printf("g->AuthKeyMethod = %d\n", g->AuthKeyMethod );
	printf("g->PreshareKeyAvaliable = %d\n", g->PreshareKeyAvaliable );
	printf("g->MaxRetryCounts = %d\n", g->MaxRetryCounts );
	printf("g->EventId = %d\n", g->EventId  );
	printf("g->portSecure = %d\n", g->portSecure );
	printf("g->DescriptorType = %d\n", g->DescriptorType );
	printf("g->KeyDescriptorVer = %d\n", g->KeyDescriptorVer );
}
#endif

void lib1x_print_etheraddr( char * s, u_char * addr )
{
	sprintf(s,"%02x%02x%02x%02x%02x%02x", addr[0], addr[1], addr[2], addr[3], addr[4],
			addr[5] );

}


