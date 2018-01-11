


#include "1x_common.h"
#include "1x_supp_pae.h"

//--------------------------------------------------
// IEEE 802.1x Implementation
//
// File		: 1x_supp_pae.c
// Programmer	: Arunesh Mishra
// Implements the Supplicant PAE
// Copyright (c) Arunesh Mishra 2002
// All rights reserved.
// Maryland Information and Systems Security Lab
// University of Maryland, College Park.
//--------------------------------------------------


BOOLEAN	lib1x_trans_suppsm( Supp_Pae_Params * supp_params, Global * global )
{

	// Global conditions first
	if ( ( supp_params->userLogoff && !supp_params->logoffSent ) &&
			!( global->initialize || ! global->portEnabled ) )
	{
		supp_params->state = Logoff;
		return TRUE;
	}

	if ( global->initialize || ! global->portEnabled )
	{
		supp_params->state = Disconnected ;
		return TRUE;
	}

	if ( supp_params->eapFail &&
			! ( global->initialize || ! global->portEnabled )
			&& ! supp_params->userLogoff && ! supp_params->logoffSent )
	{
		supp_params->state = Held;
		return TRUE;
	}

	if ( supp_params->eapSuccess &&
			!( global->initialize || ! global->portEnabled )
			&& ! supp_params->userLogoff || ! supp_params->logoffSent )
	{
		supp_parms->state = Authenticated;
		return TRUE;
	}


	// Actual Transition function i.e. non -global transitions
	switch ( supp_params->state )
	{
		case	Logoff:
				if ( ! supp_params->userLogoff )
				{
					supp_params->state = Disconnected;
					return TRUE;
				}
				break;


		case	Disconnected:
				supp_params->state = Connecting; 	// Unconditional Transfer !
				return TRUE;
				break;

		case	Connecting:
				if ( ( global->timers->startWhen == 0 ) &&
						( supp_params->startCount >= supp_params->maxStart ))
				{
					supp_params->state = Authenticated;
					return TRUE;
				}
				if ( supp_params->reqId )
				{
					supp_params->state = Acquired;
					return TRUE;
				}
				if ( ( global->timers->startWhen == 0 ) &&
						( supp_params->startCount < supp_params->maxStart ) )
				{
					// Same state
					return TRUE;
				}
				break;


		case	Held:
				if ( global->timers->heldWhile == 0 )
				{
					supp_params->state = Connecting;
					return TRUE;
				}
				if ( supp_params->reqId )
				{
					supp_params->state = Acquired;
					return TRUE;
				}
				break;


		case	Authenticating:
				if ( supp_params->reqAuth )
				{
					// same state
					return TRUE;
				}
				if ( supp_params->reqId )
				{
					supp_params->state = Acquired;
					return TRUE;
				}

				if ( global->timers->authWhile == 0	)
				{
					supp_params->state = Connecting;
					return TRUE;
				}
				break;
		case	Acquired:

				if ( supp_params->reqId )
				{
					// Same state
					return TRUE;
				}
				if ( supp_params->reqAuth )
				{
					supp_params->state = Authenticating;
					return TRUE;
				}
				if ( global->timers->authWhile == 0 )
				{
					supp_params->state = Authenticating;
					return TRUE;
				}
				break;

		case	Authenticated:
				if ( supp_params->reqId )
				{
					supp_params->state = Acquired;
					return TRUE;
				}
				break;


	}
}



void 	lib1x_exec_suppsm( Supp_Pae_Params * supp_params, Global * global )
{
	switch ( supp_params->state )
	{
		case	Logoff:
				lib1x_suppsm_logoff( supp_params, global );
				break;


		case	Disconnected:
				lib1x_suppsm_disconnected( supp_params, global );
				break;

		case	Connecting:
				lib1x_suppsm_connecting( supp_params, global );
				break;


		case	Held:
				lib1x_suppsm_held( supp_params, global );
				break;


		case	Authenticating:
				lib1x_suppsm_authenticating( supp_params, global );
				break;
		case	Acquired:
				lib1x_suppsm_acquired( supp_params, global );
				break;

		case	Authenticated:
				lib1x_suppsm_authenticated( supp_params, global );
				break;


	}
}



void lib1x_suppsm_logoff( Supp_Pae_Params *  supp_params, Global * global )
{
	lib1x_suppsm_txLogoff();
	supp_params->logoffSent = TRUE;
	supp_params->suppStatus = Unauthorized;
}


void lib1x_suppsm_disconnected( Supp_Pae_Params *  supp_params, Global * global )
{
	supp_params->eapSuccess = FALSE;
	supp_params->eapFail = FALSE;
	supp_params->startCount = 0;
	supp_params->logoffSent = FALSE;
	supp_params->previousId = 256;
	supp_params->suppStatus = Unauthorized;
}

void lib1x_suppsm_connecting( Supp_Pae_Params *  supp_params, Global * global )
{
	global->timers->startWhen = supp_params->startPeriod;
	supp_params->startCount ++;
	supp_params->reqId = FALSE;
	lib1x_suppsm_txStart();
}



void lib1x_suppsm_acquired( Supp_Pae_Params *  supp_params, Global * global )
{

	global->timers->authWhile = supp_params->authPeriod;
	supp_params->startCount = 0;
	supp_params->reqId = FALSE;
	supp_params->reqAuth = FALSE;
	lib1x_suppsm_txRspId( global->receivedId, supp_params->previousId );
	supp_params->previousId = global->receivedId;
}



void lib1x_suppsm_authenticating( Supp_Pae_Params *  supp_params, Global * global )
{

	global->timers->authWhile = supp_params->authPeriod;
	supp_params->reqAuth = FALSE;
	lib1x_suppsm_txRspAuth( global->receivedId, supp_params->previousId );
	supp_params->previousId = global->receivedId;
}


void lib1x_suppsm_held( Supp_Pae_Params *  supp_params, Global * global )
{
	global->timers->heldWhile = supp_params->heldPeriod;
	supp_params->eapFail = FALSE;
	supp_params->eapSuccess = FALSE;
	supp_params->suppStatus = Unauthorized;
}

void lib1x_suppsm_authenticated( Supp_Pae_Params *  supp_params, Global * global )
{

	supp_params->eapSuccess = FALSE;
	supp_params->eapFail = FALSE;
	supp_params->suppStatus = Authorized;
}
