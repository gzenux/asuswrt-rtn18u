
#ifndef _CONFIG_PARSE_H
#define _CONFIG_PARSE_H

#define CONFIG_PARSE_TAG 80
#define CONFIG_PARSE_VALUE 80


typedef enum {  ERROR_FILE_NOTEXIST = -1, ERROR_UNDEFINE_PARAMETER = -2,
	ERROR_UNDEFINE_TAG = -3 } CONFIG_ERROR_ID;


#define CFG_STRERROR_FILE_NOTEXIST		"Configuration file not exist"
#define CFG_STRERROR_UNDEFINE_PARAMETER		"Undefine parameter in configuration file"
#define CFG_STRERROR_UNDEFINE_TAG		"Undefine tag in configuration file"

typedef enum { tagUnicastCipher = 0, tagMulticastCipher = 1, tagAuthKeyMethod = 2} CONFIG_TAG_TABLE;

u_char ConfigTag[][32] =
{
	"ssid",
	"encryption",
	"enable1x",
	"enableMacAuth",
	"supportNonWpaClient",
	"wepKey",
	"wepGroupKey",
	"authentication",
	"unicastCipher",
#ifdef RTL_WPA2
	"wpa2UnicastCipher",
	"enablePreAuth",
#endif
	"usePassphrase",
	"groupRekeyTime",
	"psk",
	"rsPort",
	"rsIP",
	"rsPassword",
#ifdef RTL_RADIUS_2SET
	"rs2Port",
	"rs2IP",
	"rs2Password",
	"rs2enableMacAuth",
#endif
#if defined(CONFIG_RTL_802_1X_CLIENT_SUPPORT) || defined(CONFIG_RTL_ETH_802DOT1X_CLIENT_MODE_SUPPORT)
	"eapType",
	"eapInsideType",
	"eapUserId",
	"rsUserName",
	"rsUserPasswd",
	"rsUserCertPasswd",
	"rsBandSel",
#endif
#ifdef RTL_TTLS_CLIENT
	"eapPhase2Type",
	"phase2EapMethod",
#endif
	"rsMaxReq",
	"rsAWhile",
	"rsNasId",
	"rsReAuthTO",
	"accountRsEnabled",
	"accountRsPort",
	"accountRsIP",
	"accountRsPassword",
#ifdef RTL_RADIUS_2SET
	"accountRs2Port",
	"accountRs2IP",
	"accountRs2Password",
#endif
	"accountRsMaxReq",
	"accountRsAWhile",
	"accountRsUpdateEnabled",
	"accountRsUpdateTime",
#ifdef CONFIG_RTL_ETH_802DOT1X_SUPPORT
	"ethDot1xMode",
	"ethDot1xProxyType",
	"ethDot1xProxyModePortMask",
	"ethDot1xClientModePortMask",
	"ethDot1xEapolUnicastEnabled",
#endif

#ifdef CONFIG_RTL8196C_AP_HCM
	"hostmac",
#endif
#ifdef CONFIG_IEEE80211W
	"ieee80211w",
	"sha256",
#endif
#ifdef HS2_SUPPORT
	"OSEN"
#endif
};


/**
 * Reads a tag out of a file in the form
 *   tag = value
 *
 * return 0 on success -1 on fail
 */
int configParse(char *, /* File name */
		char *, /* Tag */
		char * /* value */
		);

#endif /* _CONFIG_PARSE_H_ */

/*** EOF ***/
