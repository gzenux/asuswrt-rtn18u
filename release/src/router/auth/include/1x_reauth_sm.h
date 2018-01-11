

#ifndef LIB1x_REAUTH_SM_H
#define LIB1x_REAUTH_SM_H


//--------------------------------------------------
// IEEE 802.1x Implementation
//
// File		: 1x_reauth_sm.h
// Programmer	: Arunesh Mishra
// Reauthentication Timer State Machine.
// Copyright (c) Arunesh Mishra 2002
// All rights reserved.
// Maryland Information and Systems Security Lab
// University of Maryland, College Park.
//--------------------------------------------------
#include "1x_common.h"

#define LIB1X_RSM_REAUTHPERIOD       3600    //seconds   
typedef struct Reauth_SM_tag
{

	REAUTH_SM_STATE		state;

// These are just constants as far as the ReauthSM goes.

	int	reAuthPeriod;
	int	reAuthEnabled;
} Reauth_SM;



void lib1x_reauthsm_init( Reauth_SM * reauth_sm , int reAuthTO );
void lib1x_trans_reauthsm( Global_Params * global , Reauth_SM * reauth_sm );
#endif
