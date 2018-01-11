#ifdef _RTL_WPA_WINDOWS
typedef unsigned short u_short;
typedef unsigned char u_char;
#else
#include <sys/types.h>
#endif

#include "1x_common.h"

#define NONE		-1
#define CIPHER_WEP40		0
//#define CIPHER_TKIP		1
#define CIPHER_AESCCMP		2
#define CIPHER_AESWRAP		3
#define CIPHER_WEP104		4
#define IEEE802_1X	0
#define ELEMENTID	0xdd
#define GROUPFLAG	0x02
#define REPLAYBITSSHIFT 2
#define REPLAYBITS	0x03

struct InfoElement {
	u_char Elementid;
	u_char length;
	u_char oui[4];
	u_short version;
	u_char multicast[4];
	u_short ucount;
	struct {
		u_char oui[4];
	}unicast[1]; // the rest is variable so need to
				  // overlay ieauth structure
};

struct _ieauth {
	u_short acount;
	struct {
		u_char oui[4];
	}auth[1];
};

//---- Error number is the negative value
//---- that follows 802/11i D3.0 Failure Association Request reason code ----
typedef enum{ERROR_BUFFER_TOO_SMALL = -1, ERROR_INVALID_PARA = -2, ERROR_INVALID_RSNIE = -13,
		ERROR_INVALID_MULTICASTCIPHER = -18, ERROR_INVALID_UNICASTCIPHER = -19,
		ERROR_INVALID_AUTHKEYMANAGE = -20,
		ERROR_UNSUPPORTED_RSNEVERSION = -21,  ERROR_INVALID_CAPABILITIES = -22,
		ERROR_MGMT_FRAME_PROTECTION_VIOLATION = -31}INFO_ERROR;

#ifdef CONFIG_IEEE80211R
typedef enum{__STATS_INVALID_IE_ = 40, __STATS_INVALID_AKMP_ = 43, _STATS_INVALID_PMKID_ = 53, 
		_STATS_INVALID_MDIE_ = 54, } INFO_ERROR_FT;
#endif

#define RSN_STRERROR_BUFFER_TOO_SMALL           "Input Buffer too small"
#define RSN_STRERROR_INVALID_PARAMETER          "Invalid RSNIE Parameter"
#define RSN_STRERROR_INVALID_RSNIE              "Invalid RSNIE"
#define RSN_STRERROR_INVALID_MULTICASTCIPHER 	"Multicast Cipher is not valid"
#define RSN_STRERROR_INVALID_UNICASTCIPHER 	"Unicast Cipher is not valid"
#define RSN_STRERROR_INVALID_AUTHKEYMANAGE      "Authentication Key Management Protocol is not valid"
#define RSN_STRERROR_UNSUPPORTED_RSNEVERSION 	"Unsupported RSNE version"
#define RSN_STRERROR_INVALID_CAPABILITIES 	"Invalid RSNE Capabilities"
#define RSN_STRERROR_MGMT_FRAME_PROTECTION_VIOLATION "Robust management frame policy violation"

#define RSN_ELEMENT_ID                          221
#ifdef RTL_WPA2
#define WPA_ELEMENT_ID                          0xDD
#define WPA2_ELEMENT_ID                         0x30
#endif
#define RSN_VER1                                0x01
//#define DOT11_MAX_CIPHER_ALGORITHMS     	0x0a


typedef struct _DOT11_RSN_IE_HEADER {
        u_char  ElementID;
        u_char  Length;
	u_char  OUI[4];
        u_short Version;
}DOT11_RSN_IE_HEADER;

#ifdef HS2_SUPPORT
typedef struct _DOT11_OSEN_IE_HEADER {
    u_char  ElementID;
    u_char  Length;
	u_char  OUI[3];
    u_char Type;
}DOT11_OSEN_IE_HEADER;
#endif
#ifdef RTL_WPA2
#define WPA2_ELEMENT_ID                          0x30
typedef struct _DOT11_WPA2_IE_HEADER {
        u_char  ElementID;
        u_char  Length;
        u_short Version;
}DOT11_WPA2_IE_HEADER;
#endif

typedef struct _DOT11_RSN_IE_SUITE{
        u_char  OUI[3];
        u_char  Type;
}DOT11_RSN_IE_SUITE;


typedef struct _DOT11_RSN_IE_COUNT_SUITE{

        u_short 		SuiteCount;
        DOT11_RSN_IE_SUITE      dot11RSNIESuite[DOT11_MAX_ALGORITHMS];

}DOT11_RSN_IE_COUNT_SUITE, *PDOT11_RSN_IE_COUNT_SUITE;

typedef union _DOT11_RSN_CAPABILITY{

        u_short shortData;
        u_char  charData[2];
#ifdef RTL_WPA2
        struct
        {
				u_short MFPC:1; // B7
                u_short MFPR:1; // B6
                u_short GtksaReplayCounter:2; // B5 B4
                u_short PtksaReplayCounter:2; // B3 B2
                u_short NoPairwise:1; // B1
                u_short PreAuthentication:1; // B0
                u_short Reserved2:8;
        }field;
#else        
        struct
        {
                u_short PreAuthentication:1;
                u_short PairwiseAsDefaultKey:1;
                u_short NumOfReplayCounter:2;
                u_short Reserved:12;
        }field;
#endif

}DOT11_RSN_CAPABILITY;


#define DOT11_NUM_ENTRY     0x0a
//-------------------------------------------------
//--  Unicast Cipher Suite configuration table
//-------------------------------------------------
//--dot11RSNConfigUnicastCiphersEntry OBJECT-TYPE
	//"The table entry, indexed by the interface index (or all interfaces) and the unicast cipher."

//-- dot11RSNConfigUnicastCiphersTable OBJECT-TYPE
	//"This table lists the unicast ciphers supported by this entity.
	//It allows enabling and disabling of each unicast cipher by network management.
	//The Unicast Cipher Suite list in the RSN Information Element is formed using the information in this table."

typedef struct _Dot11RSNConfigUnicastCiphersEntry
{
	u_long		Index;
	OCTET_STRING	Cipher;	//It consists of an OUI (the three most significant octets) and a cipher suite identifier (the least significant octet)."
	BOOLEAN		Enabled;
}Dot11RSNConfigUnicastCiphersEntry;

typedef struct _Dot11RSNConfigUnicastCiphersTable
{
	u_long					NumEntry;
	Dot11RSNConfigUnicastCiphersEntry	Table[DOT11_NUM_ENTRY];

}Dot11RSNConfigUnicastCiphersTable;

//-----------------------------------------------------------
//  The Authentication Suites Table
//-----------------------------------------------------------

//----dot11RSNConfigAuthenticationSuitesEntry OBJECT-TYPE
	//"An entry (row) in the dot11RSNConfigAuthenticationSuitesTable."

//----dot11RSNConfigAuthenticationSuitesTable OBJECT-TYPE
	//"This table lists the authentication suites supported by this entity.
	//Each authentication suite can be individually enabled and disabled.
	//The Authentication Suite List in the RSN IE is formed using the information in this table."

typedef struct _Dot11RSNConfigAuthenticationSuitesEntry
{
	u_long		Index;
	OCTET_STRING	Suite;	//It consists of an OUI (the three most significant octets) and a cipher suite identifier (the least significant octet). "
	BOOLEAN		Enabled;
}Dot11RSNConfigAuthenticationSuitesEntry;

typedef struct _Dot11RSNConfigAuthenticationSuitesTable{
	u_long					NumEntry;
	Dot11RSNConfigUnicastCiphersEntry	Table[DOT11_NUM_ENTRY];
}Dot11RSNConfigAuthenticationSuitesTable;





char * lib1x_authRSN_err(int err);


int lib1x_authRSN_constructIE(Dot1x_Authenticator * auth,
                              u_char * pucOut,
                              int * usOutLen,
                              BOOLEAN bAttachIEHeader);
int lib1x_authRSN_parseIE(Dot1x_Authenticator * auth,
                          Global_Params * global,
                         u_char * pucIE, u_long ulIELength);

//int lib1x_authRSN_parseIE(Dot1x_Authenticator * auth,
//                          Global_Params * global,
//                          u_char * pucIE, u_long ulIELength);

#ifdef RTL_WPA2					
int lib1x_authRSN_match(Dot1x_Authenticator * auth, Global_Params * global, BOOLEAN bWPA2);
#else
int lib1x_authRSN_match(Dot1x_Authenticator * auth, Global_Params * global);
#endif
