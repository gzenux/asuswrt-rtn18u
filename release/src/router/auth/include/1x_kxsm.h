
#ifndef LIB1x_KXSM_H
#define LIB1x_KXSM_H

#include "1x_types.h"

//--------------------------------------------------
// IEEE 802.1x Implementation
//
// File		: 1x_kxsm.h
// Programmer	: Arunesh Mishra
//
//  H file Key Transmit State Machine.
// Copyright (c) Arunesh Mishra 2002
// All rights reserved.
// Maryland Information and Systems Security Lab
// University of Maryland, College Park.
//--------------------------------------------------

struct Auth_Pae_tag;
struct Global_Params_tag;

typedef struct Auth_keyxmitSM_tag
{
	AUTH_KEYSM	state;
	
	BOOLEAN		keyAvailable;


	// Constants
	BOOLEAN		keyTxEnabled;
} Auth_KeyxmitSM;


void lib1x_trans_kxsm( struct Auth_Pae_tag * auth_pae, struct Global_Params_tag * global, Auth_KeyxmitSM * key_sm );
void lib1x_kxsm_init( Auth_KeyxmitSM * key_sm );
void lib1x_kxsm_key_transmit( struct Auth_Pae_tag * auth_pae, struct Global_Params_tag * global, Auth_KeyxmitSM *  key_sm );

void lib1x_authxmitsm_txKey( struct Auth_Pae_tag * auth_pae, int currentId);


#endif
