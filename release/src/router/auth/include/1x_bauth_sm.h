



#ifndef  LIB1x_BAUTH_SM_H
#define  LIB1x_BAUTH_SM_H 

//--------------------------------------------------
// IEEE 802.1x Implementation
//
// File		: 1x_bauth_sm.h
// Programmer	: Arunesh Mishra
//
//
// Copyright (c) Arunesh Mishra 2002
// All rights reserved.
// Maryland Information and Systems Security Lab
// University of Maryland, College Park.
//
//--------------------------------------------------

#define	LIB1X_BSM_SUPPTIMEOUT		30
#define	LIB1X_BSM_SVRTIMEOUT		30
#define	LIB1X_BSM_MAXREQ			2


#include <stdio.h>

struct Auth_Pae_tag;
struct Global_Params_tag;

typedef struct Bauth_SM_tag
{
	BAUTH_SM_STATE		state;

	int			reqCount;
					// A counter used to determine how many EAP Request packets
					// have been sent to the Supplicant without receiving a response.
	BOOLEAN			rxResp; // if a EAPOL PDU of type EAP packet rcvd from supp carrying a Request
	BOOLEAN			aSuccess; 	// if Accept pkt recvd from Auth Server
	BOOLEAN			aFail;		// true if reject pkt rcvd from auth svr.
	BOOLEAN			aReq;		// true if eap req pkt rcvd frm auth svr.
	int			idFromServer;	// most recent EAP success, failure or req pkt rcvd frm auth svr.


	int			suppTimeout;
	int			serverTimeout;
	int			maxReq;

	FILE			* debugsm;
	
} Bauth_SM;

// The functions exported.
void lib1x_bauthsm_init( Bauth_SM * bauth_sm, int maxReq, int aWhile );

void lib1x_bauthsm( struct Auth_Pae_tag * , struct Global_Params_tag * , Bauth_SM * );

BOOLEAN lib1x_trans_bauthsm( struct Auth_Pae_tag * , struct Global_Params_tag *, Bauth_SM * );

void lib1x_exec_bauthsm( struct Auth_Pae_tag * , struct Global_Params_tag * , Bauth_SM * );
void lib1x_bauthsm_abortAuth();
#endif 
