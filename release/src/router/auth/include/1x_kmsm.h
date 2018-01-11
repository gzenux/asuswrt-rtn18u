#ifndef LIB1X_KMSM_H
#define LIB1X_KMSM_H

#include "1x_common.h"


#define TRUE	1
#define FALSE	0
#define SWAP(a, b) { tmp = b; b = a; a = tmp;}



#define	NumGroupKey 4
#define REJECT_EAPOLSTART_COUNTER	3

typedef enum {SUCCESS = 0, ERROR_NULL_PSK = -1, ERROR_TIMEOUT = -2, ERROR_MIC_FAIL = -3,
	ERROR_SET_PTK = -4, ERROR_NONEEQUL_REPLAYCOUNTER = -5, 
	ERROR_EQUALSMALLER_REPLAYCOUNTER = -6, ERROR_NONEQUAL_NONCE = -7, ERROR_AESKEYWRAP_MIC_FAIL = -8,
	ERROR_LARGER_REPLAYCOUNTER = -9, ERROR_UNMATCHED_GROUPKEY_LEN = -10,
#ifdef RTL_WPA2_CLIENT	
	ERROR_NONEQUAL_RSNIE = -11, ERROR_RECV_4WAY_MESSAGE2_AGAIN = -12, ERROR_PMKID_PSK = -13, ERROR_PMKID_TLS = -14, ERROR_SECOND_RSNIE = -15} KMSM_ERROR_ID;
#else
	ERROR_NONEQUAL_RSNIE = -11, ERROR_RECV_4WAY_MESSAGE2_AGAIN = -12} KMSM_ERROR_ID;
#endif	

#define KM_STRERROR_NULL_PSK					"NUUL Pairwise Share Key"
#define KM_STRERROR_TIMEOUT						"Time Out"
#define KM_STRERROR_MIC_FAIL					"MIC Failure"
#define KM_STRERROR_SET_PTK						"Fail to set Pairwise Transient Key"
#define KM_STRERROR_NONEEQUL_REPLAYCOUNTER		"Non Equal Replay "
#define KM_STRERROR_EQUALSMALLER_REPLAYCOUNTER	"Equal/Smaller Replay "
#define KM_STRERROR_NONEQUAL_NONCE				"Non Equal Nonce received in 3rd Message"
#define KM_STRERROR_AESKEYWRAP_MIC_FAIL			"AES_WRAP MIC Fail"
#define KM_STRERROR_LARGER_REPLAYCOUNTER		"Larger Replay "
#define KM_STRERROR_UNMATCHED_GROUPKEY_LEN		"Invalid Group key length received"
#define KM_STRERROR_NONEQUAL_RSNIE                      "Non Equal RSN Information Element received"






typedef enum { akmsm_DEAUTHENTICATE, akmsm_DISCONNECTED, akmsm_INITIALIZE, \
	akmsm_AUTHENTICATION, akmsm_INITPMK, akmsm_INITPSK, \
	akmsm_PTKSTART, akmsm_PTKINITNEGOTIATING, \
	akmsm_PTKINITDONE, akmsm_UPDATEKEYS, akmsm_MICFAILURE,\
	akmsm_SETKEYS, akmsm_SETKEYSDONE, \
	// Added states that are not in IEEE 802.11i/D3.0  8.5.6.1
	// but appears in state machine diagram in Figure 53(p.113)
	akmsm_DISCONNECT, akmsm_AUTHENTICATION2, aksm_INITPSK, aksm_PTKINITDONE, \
	akmsm_INTEGRITYFAILURE, \
	// Added states 
	akmsm_ERRORHANDLE} AUTH_PAIRWISEKEY_STATE;


typedef enum {gkmsm_REKEYNEGOTIATING, gkmsm_REKEYESTABLISHED, gkmsm_KEYERROR} AUTH_GROUPKEY_STATE;



typedef enum { 
	akmsm_EVENT_NoEvent,
	akmsm_EVENT_AssociationRequest, akmsm_EVENT_ReAssociationRequest,
	akmsm_EVENT_AuthenticationRequest,  akmsm_EVENT_ReAuthenticationRequest,
	akmsm_EVENT_AuthenticationSuccess,
	akmsm_EVENT_Disconnect, akmsm_EVENT_DeauthenticationRequest, akmsm_EVENT_Init, akmsm_EVENT_Disassociate,
	akmsm_EVENT_IntegrityFailure, akmsm_EVENT_EAPOLKeyRecvd,
	akmsm_EVENT_TimeOut}Auth_Key_Manage_Event;




struct Global_Params_tag;
typedef struct Auth_GroupKeyManage_tag
{


	// The Variables.
	BOOLEAN					GTKAuthenticator;
	int					GKeyDoneStations;
	BOOLEAN					GTKRekey;
	BOOLEAN					GInitAKeys;
	BOOLEAN					GInitDone;
	BOOLEAN					GUpdateStationKeys;
	//int					GNoStations;	//== auth->NumOfSupplicant
	BOOLEAN					GkeyReady;
	BOOLEAN					GKeyFailure;	//added by Emily

	OCTET_STRING				GNonce;
	u_char					GTK[NumGroupKey][GTK_LEN];
	u_char					GMK[GMK_LEN];
	int					GN;
	int					GM;
	
#ifdef CONFIG_IEEE80211W
		unsigned char IGTK[2][IGTK_LEN];
		int GN_igtk, GM_igtk;
		union PN48 IGTK_PN;
#endif //CONFIG_IEEE80211W

	u_long					GRekeyCounts;
	BOOLEAN					GResetCounter;
}AGKeyManage_SM;


typedef struct Auth_PairwiseKeyManage_tag
{
	// The machine state
	AUTH_PAIRWISEKEY_STATE	state;
	AUTH_GROUPKEY_STATE		gstate;
	// The Variables.
	//802.1x related variable
	BOOLEAN				eapStart;
	u_long				SessionTimeout;
	u_long				SessionTimeoutCounter;
	u_long				SessionTimeoutEnabled;
	u_long				IdleTimeout;
	u_long				IdleTimeoutCounter;
	u_long				IdleTimeoutEnabled;
	u_long				InterimTimeout;
	u_long				InterimTimeoutCounter;
	u_long				InterimTimeoutEnabled;
	//-----------Event
	BOOLEAN				AuthenticationRequest;
	BOOLEAN				ReAuthenticationRequest;
	BOOLEAN				DeauthenticationRequest;
	BOOLEAN				Disconnect;
	BOOLEAN				Init;
	BOOLEAN				Pair;
	BOOLEAN				RadiusKeyAvailable;
	BOOLEAN				EAPOLKeyReceived;
	BOOLEAN				EAPOLKeySend;   //added by Emily
	BOOLEAN				TimeoutEvt;
	int					TimeoutCtr;
	//sc_yang	
	int					TickCnt;
	BOOLEAN				L2Failure;
	BOOLEAN				MICVerified;
	BOOLEAN				IntegrityFailed;

	BOOLEAN				PInitAKeys;
	//int                                     ; //sc_yang
	OCTET_STRING		ANonce;
	OCTET_STRING		SNonce; //added by Emily

	u_char				PMK[PMK_LEN];
#ifdef RTL_WPA2
	u_char				PMKID[PMKID_LEN];	
#endif        
	u_char				PTK[PTK_LEN];

	OCTET_STRING		SuppInfoElement;
	OCTET_STRING		AuthInfoElement;
	LARGE_INTEGER		CurrentReplayCounter;
	LARGE_INTEGER		ReplayCounterStarted; // david+1-11-2007
	u_short				ErrorRsn;

	struct Global_Params_tag	*global;

	BOOLEAN				IfCalcMIC;
	BOOLEAN				bWaitForPacket;
	int					IgnoreEAPOLStartCounter;
	//Abocom
	/*
        u_long                          SessionTimeout;
        u_long                          IdleTimeout;
	u_long				InterimTimeout;
        u_long                          SessionTimeoutCounter;
        u_long                          IdleTimeoutCounter;
	u_long				InterimTimeoutCounter;
	*/
#ifdef CONFIG_IEEE80211R
	u_char					isFT;
	u_char					xxkey[PMK_LEN];
	u_char					ssid[32];
	int						ssid_len;
	u_char					mdid[2];
	u_char					r0kh_id[48];
	int						r0kh_id_len;
	u_char					bssid[6];
	u_char					pmk_r1_name[PMKID_LEN];
	u_char					over_ds_enabled;
	u_char					resource_request_support;
#endif

}APKeyManage_SM;







int lib1x_akmsm_SendEAPOL_proc(Global_Params * global);
int lib1x_akmsm_ProcessEAPOL_proc(Global_Params * global);
int lib1x_akmsm_trans( Global_Params * global);
void lib1x_akmsm_execute( Global_Params * global);
void lib1x_akmsm_dump(Global_Params * global );
void lib1x_skmsm_execute( Global_Params * global);
int lib1x_skmsm_ProcessEAPOL_proc(Global_Params * global);
void lib1x_akmsm_EAPOLStart_Timer_proc(Dot1x_Authenticator * auth);
void lib1x_akmsm_Account_Timer_proc(Dot1x_Authenticator * auth);
int lib1x_akmsm_Disconnect( Global_Params * global);

int MIN(u_char * ucStr1, u_char * ucStr2, u_long ulLen);
void CalcPTK(u_char *addr1, u_char *addr2, u_char  *nonce1, 
			 u_char *nonce2, u_char * keyin, int keyinlen, 
			 u_char * keyout, int keyoutlen
#ifdef CONFIG_IEEE80211W
  			 ,int use_sha256
#endif				 
			 );
void GenNonce(u_char * nonce, u_char * szRandom);
char * KM_STRERR(int err);
void KeyDump(char *fun, u_char *buf, int siz, char *comment);
OCTET32_INTEGER * INCOctet32_INTEGER(OCTET32_INTEGER * x);
int _tmain();

#ifdef CONFIG_IEEE80211R
void CalcFTPTK(Global_Params * global, u_char * keyout, int keyoutlen);
#endif

#endif //LIB1X_KMSM_H
