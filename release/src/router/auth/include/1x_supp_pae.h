
#ifndef LIB1X_SUPP_PAE_H
#define LIB1X_SUPP_PAE_H


#include "1x_common.h"
//#include "1x_nal.h"
#include "1x_types.h"
#include "1x_kmsm.h"
#include "1x_auth_pae.h"



#define 	LIB1X_SUPP_AUTHPERIOD		30
#define 	LIB1X_SUPP_HELDPERIOD		60
#define 	LIB1X_SUPP_STARTPERIOD		30
#define 	LIB1X_SUPP_MAXSTART		3


typedef enum   {
	skmsm_INITIALIZE,
	skmsm_DISCONNECTED,
	skmsm_AUTHENTICATION,
	skmsm_STAKEYSTART,
	skmsm_KEYUPDATE,
} SUPP_KMSM_STATE;

typedef enum {
        skmsm_EVENT_AuthenticationRequest,
	skmsm_EVENT_IntegrityFailure,
        skmsm_EVENT_Updatekeys,
	skmsm_EVENT_EAPOLKeyRecvd,
	skmsm_EVENT_AuthenticationFailed,
        skmsm_EVENT_DeauthenticationRequest,
	skmsm_EVENT_Init,
} SUPP_KEY_MANAGE_EVENT;


struct Supp_Global_tag;
struct Supp_Kmsm_tag;

typedef struct Supp_Pae_Params_tag
{
	SUPP_KMSM_STATE 	skmsm_state;
	struct 	Supp_Global_tag *global;

	u_char		 	* sendBuffer;
	int		   	sendbuflen;
	u_char          	auth_addr[ETHER_ADDRLEN];


} Supp_Pae_Params;

typedef struct Supp_Global_tag
{


	// Pointer to Global Variable
	Dot1x_Authenticator 	*auth;
	struct TxRx_Params_tag	* TxRx;

	// Pointer to State machine
	Supp_Pae_Params  	*supp_pae;
	struct Supp_Kmsm_tag	*supp_kmsm;


	// Processing EAPOL Packet
	OCTET_STRING		EAPOLMsgRecvd;          //The Overall 802.1x message
        OCTET_STRING            EAPOLMsgSend;           //The Overall 802.1x message
        OCTET_STRING            EapolKeyMsgRecvd;       //The start point of eapol-key payload
        OCTET_STRING            EapolKeyMsgSend;

	//Timer related variable
	u_long			ConstTimerCount;

	// Key handshake related
	u_char                  DescriptorType;
	u_char			KeyDescriptorVer;
	int			AuthKeyMethod;

	//RSNIE related variable
	struct _DOT11_RSN_SUPPLICANT_VARIABLE   RSNVariable;






} Supp_Global;

typedef struct _Dot1x_Client
{
	Dot1x_Authenticator 	*auth;
	Supp_Global 		*global;
	Supp_Pae_Params  	*supp_pae;
}Dot1x_Client;

typedef struct Supp_Kmsm_tag{

	LARGE_INTEGER		CurrentReplayCounter;
	OCTET_STRING		ANonce;
	OCTET_STRING		SNonce;
	u_char			PMK[PMK_LEN];
#ifdef RTL_WPA2_CLIENT
	u_char			PMKID[PMKID_LEN];
#endif	
	u_char			PTK[PTK_LEN];
	u_char			GTK[NumGroupKey][GMK_LEN];
#ifdef RTL_WPA2_CLIENT
	u_char			GTK_KEYID;
#endif
	OCTET32_INTEGER		Counter;
	BOOLEAN			bIsSetKey;
#ifdef RTL_WPA2_CLIENT
	BOOLEAN			bIsSetGTK;
#endif
	BOOLEAN			bAuthProgressing;

	//Retry Mechanism
	//u_long			TimeCtr;
	//u_long			ConstTimeCtrPeriod;
	u_long			TimeoutCtr;
	u_long			PairwiseUpdateCount;

	BOOLEAN			bWaitForPacket;

	// Key handshake related
	OCTET_STRING		SuppInfoElement;
	OCTET_STRING		AuthInfoElement;

	// jimmylin 20050824
	BOOLEAN			bIsHndshkDone;
} Supp_Kmsm;





Supp_Global * lib1x_init_supp(
	Dot1x_Authenticator * pAuth,
	Dot1x_Client *pClient);

void lib1x_supp_timer_proc(
	Dot1x_Client *pClient);

void lib1x_reset_supp(
	Supp_Global * pGlobal);

void lib1x_do_supplicant(
	Dot1x_Authenticator * pAuth,
	Supp_Global * pGlobal);

void lib1x_suppsm_capture_auth(
	Supp_Global * pGlobal,
	lib1x_nal_intfdesc_tag * nal,
	lib1x_packet_tag * spkt);

void lib1x_suppsm_capture_control(
	Supp_Global * pGlobal,
	lib1x_nal_intfdesc_tag * nal,
	lib1x_packet_tag * spkt );

int lib1x_skmsm_EAPOLKeyRecvd(
	Supp_Global * pGlobal);

void lib1x_skmsm_EAPOLKeySend(
	Supp_Global * pGlobal);

void lib1x_supp_timer_proc(
	Dot1x_Client *pClient);
/*
typedef struct Supp_PairwiseKeyManage_tag
{
	// The machine state
	SUPP_KEYSTATE	state;

	// The Variables.
	BOOLEAN					AuthenticationRequest;
	BOOLEAN					ReAuthenticationRequest;
	BOOLEAN					DeauthenticationRequest;
	BOOLEAN					RadiusKeyAvailable;
	BOOLEAN					EAPOLKeyReceived;
	BOOLEAN					EAPOLKeySend;	//added by Emily
	BOOLEAN					TimeoutEvt;
	int						TimeoutCtr;
	BOOLEAN					L2Failure;
	BOOLEAN					MICVerified;
	BOOLEAN					IntegrityFailed;

	BOOLEAN					PInitAKeys;
	OCTET_STRING				ANonce;
	OCTET_STRING				SNonce;	//added by Emily
	OCTET_STRING				GNonce; //added by Emily

	u_char					PMK[PMK_LEN];
	u_char					PTK[PTK_LEN];
	OCTET_STRING				SuppInfoElement;
	LARGE_INTEGER				CurrentReplayCounter;
	
	u_char					ErrorNo;
	

	struct Global_Params_tag		*global;
	

	u_char					GTK[NumGroupKey][GMK_LEN];
	int					GN;
	int					GM;
	int					ErroKeyType;

	OCTET32_INTEGER				Counter;

	// Added variables that are not in IEEE 802.11i/D3.0  8.5.6.2
	// but appears in state machine diagram in Figure 53(p.113)
	BOOLEAN					Disconnect;
	BOOLEAN					Init;
	BOOLEAN					Pair;
	// The constants
}SPKeyManage_SM;
*/
#endif

