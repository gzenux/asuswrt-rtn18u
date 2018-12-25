
//--------------------------------------------------
// IEEE 802.1x Implementation
//
// File		: 1x_cdsm.c
// Programmer	: Arunesh Mishra
//
// Copyright (c) Arunesh Mishra 2002
// All rights reserved.
// Maryland Information and Systems Security Lab
// University of Maryland, College Park.
// Controlled Directions State Machine
//--------------------------------------------------





#include "1x_common.h"
#include "1x_auth_pae.h"
#include "1x_cdsm.h"
#include <stddef.h>




//--------------------------------------------------
//  init function for the Controlled Directions State Machine.
//--------------------------------------------------
void lib1x_cdsm_init( CtrlDirSM * ctrl_sm )
{

	assert( ctrl_sm != NULL );

	ctrl_sm->state = cdsm_In_Or_Both;
	ctrl_sm->adminControlledDirections = dir_Both; // TODO: Not sure .. how this would be initialised.
	ctrl_sm->operControlledDirections = dir_Both;
}




//--------------------------------------------------
// lib1x_trans_dirsm :
//  One transition of the Controlled Directions State Machine and also the initializations
//--------------------------------------------------
void  lib1x_trans_cdsm( Auth_Pae * auth_pae, Global_Params * global, CtrlDirSM * dirsm)
{
	if ( dirsm->state == cdsm_Force_Both )
	{
		if ( global->initialize )
		{
			dirsm->state = cdsm_In_Or_Both;
			dirsm->operControlledDirections = dirsm->adminControlledDirections;
			return;
		}
		if ( global->portEnabled && !dirsm->bridgeDetected )
		{
			dirsm->state = cdsm_In_Or_Both;
			dirsm->operControlledDirections = dirsm->adminControlledDirections;
			return;
		}
	}

	if ( dirsm->state == cdsm_In_Or_Both )
	{
		if ( dirsm->operControlledDirections != dirsm->adminControlledDirections )
		{
			// Same state again but perform initializations
			dirsm->operControlledDirections = dirsm->adminControlledDirections;
			return;
		}
		if ( !global->portEnabled || dirsm->bridgeDetected )
		{
			dirsm->state = cdsm_Force_Both;
			dirsm->operControlledDirections = dir_Both;
		}

	}
}
