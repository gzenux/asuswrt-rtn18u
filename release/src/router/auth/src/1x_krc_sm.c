


//--------------------------------------------------
// IEEE 802.1x Implementation
//
// File		: 1x_krc_sm.c
// Programmer	: Arunesh Mishra
// Key Receive State Machine Implementation
//
//
// Copyright (c) Arunesh Mishra 2002
// All rights reserved.
// Maryland Information and Systems Security Lab
// University of Maryland, College Park.
//--------------------------------------------------
#include "1x_common.h"
#include "1x_krc_sm.h"
#include <stddef.h>



void lib1x_krcsm_init( Krc_SM * krc_sm )
{
	assert( krc_sm != NULL );


 	krc_sm->state = krcsm_No_Key_Receive;
	krc_sm->rxKey = FALSE;
}


//--------------------------------------------------
// lib1x_trans_krcsm:
//  One transition of the Key Receive State Machine.
//--------------------------------------------------
void lib1x_trans_krcsm(	Global_Params 	* global, Krc_SM  * krc_sm )
{
	if ( global->initialize || ! global->portEnabled )
	{
		krc_sm->state = krcsm_No_Key_Receive;
		return;
	}
	if ( krc_sm->state == krcsm_No_Key_Receive )
	{
		if ( krc_sm->rxKey == TRUE )
		{
			krc_sm->state = krcsm_Key_Receive;
			lib1x_krcsm_processKey();   // TODO
			krc_sm->state = FALSE;
			return;
		}
		return;
	}
	if ( krc_sm->state == krcsm_Key_Receive )
	{
		if ( krc_sm->rxKey == TRUE )
		{
			krc_sm->state = krcsm_Key_Receive;
			lib1x_krcsm_processKey();  // TODO
			krc_sm->state = FALSE;
			return;
		}
	}
}

//--------------------------------------------------
// Key process. TODO
//--------------------------------------------------
void lib1x_krcsm_processKey()
{
	lib1x_message( MESS_DBG_KRCSM," Key Receive State Machine: PROCESS KEY ?");
}
