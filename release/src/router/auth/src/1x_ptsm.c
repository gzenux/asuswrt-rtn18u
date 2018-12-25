
//--------------------------------------------------
// IEEE 802.1x Implementation
//
// File		: 1x_ptsm.c
// Programmer	: Arunesh Mishra
//
// Copyright (c) Arunesh Mishra 2002
// All rights reserved.
// Maryland Information and Systems Security Lab
// University of Maryland, College Park.
// Contains the port timers state machine.
//--------------------------------------------------



#include "1x_common.h"
#include "1x_ptsm.h"
#include "1x_auth_pae.h"
#include <signal.h>
#include <stddef.h>

#include <sys/time.h>


//-------------------------------------------------------------------------------
// Original implementation (Without WPA)
//-------------------------------------------------------------------------------
//sc_yang to move form 1x_common.h

void * lib1x_global_signal_info;

#ifndef _RTL_WPA_UNIX

// Set the 1 sec periodic timer.
// Use: Allocate memory and call this function, also take care of free()
void lib1x_ptsm_initialize( Global_Params * global, struct lib1x_ptsm * ptsm )
{

	lib1x_global_signal_info = (void * ) ptsm;
	signal( SIGALRM, lib1x_ptsm_alarm );
	ptsm->authWhile = ptsm->aWhile = ptsm->heldWhile = 0;
	ptsm->quietWhile = ptsm->reAuthWhen = ptsm->startWhen = ptsm->txWhen = 0;

	//---- PTSM timer state machine is triggered per one seconds ----
	ptsm->wakeupCounts  = 1000000 / LIB1X_BASIC_TIMER_UNIT;
}


//---- the signal handler.. needs to be a quick piece of code ----
void lib1x_ptsm_alarm( int signum )
{
	struct lib1x_ptsm * ptsm;

	if (signum == SIGALRM)
	{
		if ( lib1x_global_signal_info != NULL )
		{
			ptsm = ( struct lib1x_ptsm * ) lib1x_global_signal_info;
			if (ptsm->authWhile >= 0 ) ptsm->authWhile --;
			if (ptsm->aWhile >= 0 ) ptsm->aWhile --;
			if (ptsm->heldWhile >= 0 ) ptsm->heldWhile --;
			if (ptsm->quietWhile >= 0 ) ptsm->quietWhile --;
			if (ptsm->reAuthWhen >= 0 ) ptsm->reAuthWhen --;
			if (ptsm->startWhen >= 0 ) ptsm->startWhen --;
			if (ptsm->txWhen >= 0 ) ptsm->txWhen --;
		}
		alarm(1);	// schedule next alarm
	}
}

#else
//--------------------------------------------------------------------------
// Implementation with WPA Support
//--------------------------------------------------------------------------


void lib1x_ptsm_initialize( Global_Params * global, struct lib1x_ptsm * ptsm )
{

        ptsm->authWhile = ptsm->aWhile = ptsm->heldWhile = 0;
        ptsm->quietWhile = ptsm->reAuthWhen = ptsm->startWhen = ptsm->txWhen = 0;

}

void lib1x_ptsm_dump(Global_Params * global)
{
	struct lib1x_ptsm * ptsm = global->theAuthenticator->port_timers;
	lib1x_message(MESS_DBG_PTSM, "----------- Dump PTSM Supplicant [%d]------------", global->index);
	lib1x_message(MESS_DBG_PTSM, "ptsm->authWhile = %d", ptsm->authWhile);
	lib1x_message(MESS_DBG_PTSM, "ptsm->aWhile= %d", ptsm->aWhile);
	lib1x_message(MESS_DBG_PTSM, "ptsm->heldWhile = %d", ptsm->heldWhile);
	lib1x_message(MESS_DBG_PTSM, "ptsm->quietWhile = %d", ptsm->quietWhile);
	lib1x_message(MESS_DBG_PTSM, "ptsm->reAuthWhen = %d", ptsm->reAuthWhen);
	lib1x_message(MESS_DBG_PTSM, "ptsm->startWhen = %d", ptsm->startWhen);
	lib1x_message(MESS_DBG_PTSM, "ptsm->txWhen = %d", ptsm->txWhen);
	lib1x_message(MESS_DBG_PTSM, "--------------------------------------------------");
}

void lib1x_ptsm_timer(Dot1x_Authenticator * auth)
{
	int 	i;
	struct lib1x_ptsm * ptsm;
	Global_Params * global;

	//sc_yang
	for(i = 0 ; i < auth->MaxSupplicant ; i++)
        {
// reduce pre-alloc memory size, david+2006-02-06       
//		if(!auth->Supp[i]->isEnable)
		if(auth->Supp[i]==NULL || !auth->Supp[i]->isEnable)
			continue;

		global = auth->Supp[i]->global;
		ptsm = global->theAuthenticator->port_timers;
		lib1x_ptsm_dump(global);
		//sc_yang >=0 to > 0
        	if (ptsm->authWhile > 0 ) ptsm->authWhile --;
                if (ptsm->aWhile > 0 ) ptsm->aWhile --;
	        if (ptsm->heldWhile > 0 ) ptsm->heldWhile --;
        	if (ptsm->quietWhile > 0 ) ptsm->quietWhile --;
                if (ptsm->reAuthWhen > 0 ) ptsm->reAuthWhen --;
	        if (ptsm->startWhen > 0 ) ptsm->startWhen --;
        	if (ptsm->txWhen > 0 ) ptsm->txWhen --;

	}

}


#endif
