

#ifndef LIB1x_TYPES_H
#define LIB1x_TYPES_H


//--------------------------------------------------
// IEEE 802.1x Implementation
//
// File		: common.h
// Programmer	: Arunesh Mishra
//
// Contains all declarations of all common types.
//
//
// Copyright (c) Arunesh Mishra 2002
// All rights reserved.
// Maryland Information and Systems Security Lab
// University of Maryland, College Park.
//
//--------------------------------------------------

#ifdef _RTL_WPA_WINDOWS
typedef unsigned char u_char;
typedef unsinged short u_short;
typedef unsinged long u_long;
#else
#include <sys/types.h>
#endif

typedef enum	{ apsm_Initialize, apsm_Disconnected, apsm_Connecting, apsm_Authenticating, apsm_Authenticated, apsm_Aborting,
		apsm_Held, apsm_Force_Auth, apsm_Force_Unauth }	AUTH_PAE_STATE;

typedef enum    { kxsm_No_Key_Transmit, kxsm_Key_Transmit }	AUTH_KEYSM;

typedef enum	{ pmt_ForceUnauthorized, pmt_ForceAuthorized, pmt_Auto }	PORT_MODE_TYPE;
typedef enum	{ pst_Unauthorized, pst_Authorized }	PORT_STATUS_TYPE;


typedef enum 	{ basm_Request, basm_Response, basm_Success, basm_Fail, basm_Timeout, basm_Idle, basm_Initialize } 	BAUTH_SM_STATE;

typedef	enum	{ cdsm_Force_Both, cdsm_In_Or_Both }	CTRL_SM_STATE;

typedef enum 	{ dir_Both,	dir_In }			DIRECTION;

typedef enum	{ spsm_Logoff, spsm_Disconnected, spsm_Held, spsm_Authenticated, spsm_Connecting, spsm_Acquired, spsm_Authenticating }	SUPP_PAE_STATE;

typedef	enum	{ resm_Initialize, resm_Reauthenticate } REAUTH_SM_STATE;
typedef enum	{ krcsm_No_Key_Receive, krcsm_Key_Receive }	KRC_SM;

// david
//typedef	enum 	{ role_Authenticator, role_Supplicant } ROLE;



typedef	enum 	{ role_Authenticator, role_Supplicant_infra, role_Supplicant_adhoc,  role_wds, role_eth } ROLE;

typedef enum    { acctsm_Acct_No_Action, acctsm_Acct_Start, acctsm_Acct_Stop, acctsm_Acct_On, acctsm_Interim_On, acctsm_Terminate_Cause } ACCT_SM;

typedef enum	{ acctsm_Start, acctsm_Stop } ACCT_SM_STATE;

typedef enum    { akmsm_status_NotInDriverTable, akmsm_status_Idle , akmsm_status_NotIdle } AKM_SM_STATUS;

#if defined( CONFIG_IEEE80211W) || defined(HS2_SUPPORT)
enum mfp_options {
	NO_MGMT_FRAME_PROTECTION = 0,
	MGMT_FRAME_PROTECTION_OPTIONAL = 1,
	MGMT_FRAME_PROTECTION_REQUIRED = 2
};
#endif

typedef int	BOOLEAN;

#define	FALSE 	0
#define TRUE	1

//Added to support WPA
typedef enum    { key_desc_ver1 = 1, key_desc_ver2 = 2, key_desc_ver3 = 3 } KeyDescVer;
#ifdef RTL_WPA2
typedef enum    { desc_type_WPA2 = 2, desc_type_RSN = 254 } DescTypeRSN;
#else
typedef enum    { desc_type_RSN = 254 } DescTypeRSN;
#endif
typedef enum     { type_Group = 0, type_Pairwise = 1 } KeyType;
//

typedef	struct _OCTET_STRING
{
#ifdef RTL_WPA2
	u_char	* Octet;
#else
	char	* Octet;
#endif	
	int	Length;
}OCTET_STRING;

typedef union _LARGE_INTEGER {
        u_char  charData[8];

        struct{
                u_long  HighPart;
                u_long  LowPart;
        }field;
} LARGE_INTEGER, *PLARGE_INTEGER;

typedef union _OCTET16_INTEGER {
        u_char  charData[16];

        struct{
                LARGE_INTEGER   HighPart;
                LARGE_INTEGER   LowPart;
        }field;
} OCTET16_INTEGER;

typedef union  _OCTET32_INTEGER {
        u_char charData[32];
        struct{
                OCTET16_INTEGER HighPart;
                OCTET16_INTEGER LowPart;
        }field;
}OCTET32_INTEGER;


#endif 
