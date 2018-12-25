
#ifndef LIB1x_CDSM_H
#define LIB1x_CDSM_H

#include "1x_types.h"

//--------------------------------------------------
// IEEE 802.1x Implementation
//
// File		: auth_pae.h
// Programmer	: Arunesh Mishra
//
// H file for Controlled Directions State Machine
// Copyright (c) Arunesh Mishra 2002
// All rights reserved.
// Maryland Information and Systems Security Lab
// University of Maryland, College Park.
//--------------------------------------------------




struct Auth_Pae_tag;
struct Global_Params_tag;	/* These have been defined in 1x_common.h */

typedef struct CtrlDirSM_tag
{
	CTRL_SM_STATE		state;

	DIRECTION		adminControlledDirections;
	DIRECTION		operControlledDirections;
	BOOLEAN			bridgeDetected;

} CtrlDirSM;


void lib1x_cdsm_init( CtrlDirSM * ctrl_sm );
void lib1x_trans_cdsm( struct Auth_Pae_tag * auth_params, struct Global_Params_tag * global, CtrlDirSM * dirsm);


#endif

