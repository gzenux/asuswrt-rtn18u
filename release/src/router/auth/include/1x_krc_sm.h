

#ifndef LIB1X_KRC_SM_H
#define LIB1X_KRC_SM_H



//--------------------------------------------------
// IEEE 802.1x Implementation
//
// File		: 1x_krc_sm.h
// Programmer	: Arunesh Mishra
// The Key Receive State Machine
// Copyright (c) Arunesh Mishra 2002
// All rights reserved.
// Maryland Information and Systems Security Lab
// University of Maryland, College Park.
//--------------------------------------------------


typedef struct	Krc_SM_tag
{
	KRC_SM	state;	
	BOOLEAN	rxKey;
}	Krc_SM;



void lib1x_krcsm_processKey();
void lib1x_krcsm_init( Krc_SM * krc_sm );
void lib1x_trans_krcsm( Global_Params   * global, Krc_SM  * krc_sm );



#endif
