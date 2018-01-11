#include "1x_types.h"
struct Auth_Pae_tag;
struct Global_Params_tag;


#define LIB1X_ACCT_REASON_USER_REQUEST	 1
#define LIB1X_ACCT_REASON_LOST_CARRIER	 2
#define LIB1X_ACCT_REASON_LOST_SERVICE	 3
#define LIB1X_ACCT_REASON_IDLE_TIMEOUT	 4
#define LIB1X_ACCT_REASON_SESSION_TIMEOUT 5
#define LIB1X_ACCT_REASON_ADMIN_RESET 	 6
#define LIB1X_ACCT_REASON_ADMIN_REBOOT	 7

typedef struct ACCT_SM_tag
{

	int		terminate_cause;
	int		status;
	u_long		elapsedSessionTime;
	u_long		sessionId;
	int		serverTimeout;
	int		maxReq;
	int		reqCount;
	int		aWhile;
	BOOLEAN		waitRespond;
        unsigned long   tx_packets;       // == transmited packets
        unsigned long   rx_packets;       // == received packets
        unsigned long   tx_bytes;         // == transmited bytes
        unsigned long   rx_bytes;         // == received bytes


} Acct_SM;

void lib1x_acctsm( Global_Params * global);
void lib1x_acctsm_init(Acct_SM * acct_sm, int maxReq, int aWhile);
BOOLEAN lib1x_acctsm_request( struct Global_Params_tag * global, int iAction, int iTerminateCause);
int lib1x_acct_request( struct Auth_Pae_tag * auth_pae, unsigned int msg_type, int iTerminateCause);
void lib1x_acct_UCS4_TO_UTF8(u_long ud, u_char * pucUTF8, u_long * ulUTF8Len);
void lib1x_acct_MAC_TO_DASH_ASCII(u_char * pucInput, u_long ulInput, u_char * pucOutput, u_long * ulOutputLen);
u_long lib1x_acct_maperr_wlan2acct(u_long ulReason);
int lib1x_acctsm_sendReqToServer( Global_Params * global);
