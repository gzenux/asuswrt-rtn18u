//--------------------------------------------------
// IEEE 802.1x Implementation
//
// File		: 1x_reauth_sm.c
// Programmer	: Arunesh Mishra
// Reauthentication State Machine.
//
//
// Copyright (c) Arunesh Mishra 2002
// All rights reserved.
// Maryland Information and Systems Security Lab
// University of Maryland, College Park.
//
//--------------------------------------------------


#include "1x_common.h"
#include "1x_auth_pae.h"
#include <stddef.h>
#include "1x_reauth_sm.h"
#include "assert.h"


//--------------------------------------------------
// init function.
//--------------------------------------------------
void lib1x_reauthsm_init( Reauth_SM * reauth_sm , int reAuthTO )
{
	assert ( reauth_sm != NULL );

	reauth_sm->state = resm_Initialize;        // Not sure if I should start in the initialize state.
	if ( reAuthTO == 0 )
	{
		reauth_sm->reAuthEnabled = FALSE;
		reauth_sm->reAuthPeriod = LIB1X_RSM_REAUTHPERIOD;
	}
	else
	{
		reauth_sm->reAuthEnabled = TRUE;
		reauth_sm->reAuthPeriod = reAuthTO;
	}
}


//--------------------------------------------------
// One transition and state specific inits.
//--------------------------------------------------
void lib1x_trans_reauthsm( Global_Params * global , Reauth_SM * reauth_sm)
{



	// Global Transitions first :
	if ( ( global->portControl != pmt_Auto ) || global->initialize ||
			( global->portStatus == pst_Unauthorized) || ! reauth_sm->reAuthEnabled )
	{
		reauth_sm->state = resm_Initialize;
		global->timers->reAuthWhen = reauth_sm->reAuthPeriod;
		// TODO: Any initialization of timers here.
		return;
	}

	// Specific Transitions:
	if ( reauth_sm->state == resm_Initialize )
	{
		if ( global->timers->reAuthWhen == 0 )
		{
			reauth_sm->state = resm_Reauthenticate;
			global->reAuthenticate = TRUE;
			return;
		}
		return;
	}
	if ( reauth_sm->state == resm_Reauthenticate )
	{
		reauth_sm->state = resm_Initialize;
		global->timers->reAuthWhen = reauth_sm->reAuthPeriod;
		// resaon code = 30, expire
		lib1x_control_STADisconnect(global, 30);
		return;
	}

}


