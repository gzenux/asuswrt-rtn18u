
#ifndef LIB1x_PTSM_H
#define LIB1x_PTSM_H


//--------------------------------------------------
// IEEE 802.1x Implementation
//
// File		: 1x_ptsm.h 
// Programmer	: Arunesh Mishra
//
// Port timers state machine H file.
// Copyright (c) Arunesh Mishra 2002
// All rights reserved.
// Maryland Information and Systems Security Lab
// University of Maryland, College Park.
//--------------------------------------------------



struct lib1x_ptsm
{
	int authWhile;
		// authwhile is a timer used by supp to wait for a resp from 
		// authenticator before timing out.
	int aWhile;
		// timer used by backend auth state machine. 
	int heldWhile;
		//timer for supp - during which it does not attempt to authenticate
	int quietWhile;
		// timer used by auth sm during which it does not acquire a supp.
	int reAuthWhen;
		// reauthentication timer state machine = reAuthPeriod.
	int startWhen;
		// timer for supp - EAPOL start message
	int txWhen;
		// used by auth sm 


};

void lib1x_ptsm_alarm( int signum );
void lib1x_ptsm_initialize( Global_Params * global, struct lib1x_ptsm * ptsm );
void lib1x_ptsm_timer(Dot1x_Authenticator * auth);


typedef struct lib1x_ptsm PT_SM;


#endif
