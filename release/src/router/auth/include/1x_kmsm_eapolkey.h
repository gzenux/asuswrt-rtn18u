
#ifndef LIB1X_KMSM_EAPOLKEY_H
#define LIB1X_KMSM_EAPOLKEY_H



#include <string.h>



#ifdef _RTL_WPA_WINDOWS
typedef unsigned short u_short;
typedef unsigned char u_char;
typedef unsigned long u_long;
} OCTET_STRING, *POCTET_STRING, EAPOL_KEY;
#else
#include <sys/types.h>
#include "1x_kmsm_keydef.h"
#include "1x_types.h"
#endif

//original in 1x_ether.h and 1x_eapol.h
#define ETHER_HDRLEN		14
#define LIB1X_EAPOL_HDRLEN	4
#define ETHER_ADDRLEN		6

//
#define GMK_EXPANSION_CONST 	        "Group key expansion"
#define GMK_EXPANSION_CONST_SIZE		19
#define RANDOM_EXPANSION_CONST 	        "Init Counter"
#define RANDOM_EXPANSION_CONST_SIZE		12
#define IGMK_EXPANSION_CONST 	        "IGTK key expansion"
#define IGMK_EXPANSION_CONST_SIZE		18

//size of the field in information element
/*
#define PMK_LEN			32
#define PTK_LEN			64
#define PTK_LEN_TKIP		64
#define PTK_LEN_NO_TKIP		48	//for CCMP, WRAP, WEP
#define PTK_LEN_CCMP		48
#define PTK_LEN_WRAP		48
#define PTK_LEN_WEP		48
#define PTK_LEN_EAPOLMIC	16
#define PTK_LEN_EAPOLENC	16

#define	GMK_LEN			32	
#define GTK_LEN			32
#define	GTK_LEN_TKIP		32	//32 for TKIP and 16 for CCMP, WRAP, WEP
#define GTK_LEN_NO_TKIP		16
#define GTK_LEN_CCMP		16
#define GTK_LEN_WRAP		16
#define GTK_LEN_WEP		16

#define INFO_ELEMENT_SIZE	128

#define	MAX_EAPOLMSG_LEN	512
#define MAX_EAPOLKEYMSG_LEN MAX_EAPOLMSG_LEN - (ETHER_HDRLEN + LIB1X_EAPOL_HDRLEN)
#define EAPOLMSG_HDRLEN		95	//EAPOL-key payload length without KeyData

#define	KEY_RC_LEN			8
#define KEY_NONCE_LEN		32
#define	KEY_IV_LEN			16
#define KEY_RSC_LEN			8
#define KEY_ID_LEN			8
#define KEY_MIC_LEN			16
#define KEY_MATERIAL_LEN	2

#define DescTypePos			0
#define KeyInfoPos			1
#define KeyLenPos			3
#define ReplayCounterPos	5
#define KeyNoncePos			13
#define KeyIVPos			45
#define KeyRSCPos			61
#define KeyIDPos			69
#define KeyMICPos			77
#define KeyDataLenPos		93
#define KeyDataPos			95
*/

/*-----------------------------------------------------------------------------
 Network and machine byte oder conversion 
	Macro definition
-------------------------------------------------------------------------------*/
// david --------------------------------------------------
// marked by chilong

#ifdef AUTH_BIG_ENDIAN
// !!NOTES: chilong
//  we define AUTH_BIG_ENDIAN instead of BIG_ENDIAN
// because kernel header in directory "[root_dir]/mipsel-linux/sys-include/netinet/in.h"
// has defined BIG_ENDIAN
#define long2net(l,c)    (*((c) )=(unsigned char)(((l)>>24)&0xff), \
                         *((c)+1)=(unsigned char)(((l)>>16)&0xff), \
						 *((c)+2)=(unsigned char)(((l)>> 8)&0xff), \
						 *((c)+3)=(unsigned char)(((l)    )&0xff))

#define net2long(c,l)    (l =((unsigned long)(*((c)  )))<<24, \
                         l|=((unsigned long)(*((c)+1)))<<16, \
						 l|=((unsigned long)(*((c)+2)))<< 8, \
		                 l|=((unsigned long)(*((c)+3))))

#define short2net(s,c)        (*((c))=(unsigned char)(((s)>> 8)&0xff), \
								 *((c)+1)=(unsigned char)(((s)    )&0xff))

#define net2short(c,s)        (s =((unsigned short)(*((c))))<< 8, \
								s|=((unsigned short)(*((c)+1))))
#else
#define long2net(l,c)    (*((unsigned long *)c) = l)
#define net2long(c,l)    (l = *((unsigned long *)c))
#define short2net(s,c)   (*((unsigned short *)c) = s)
#define net2short(c,s)   (s = *((unsigned short *)c))
#endif

//------------------------------------------------------
//-------------------------------------------------

#define lint2net(l,c)	(long2net(l.HighPart, c) , long2net(l.LowPart, c+4))
#define net2lint(c,l)	(net2long(c, l.HighPart) , net2long(c+4, l.LowPart))
	
/*-----------------------------------------------------------------------------
 LargeInteger
	Inline Function definition
	Macro definition
-------------------------------------------------------------------------------*/
#define LargeIntegerOverflow(x) (x.field.HighPart == 0xffffffff) && \
								(x.field.LowPart == 0xffffffff)
#define LargeIntegerZero(x) memset(&x.charData, 0, 8);



/*-----------------------------------------------------------------------------
 Octet16Integer
	Inline Function definition
	Macro definition
-------------------------------------------------------------------------------*/
#define Octet16IntegerOverflow(x) LargeIntegerOverflow(x.field.HighPart) && \
								  LargeIntegerOverflow(x.field.LowPart)
#define Octet16IntegerZero(x) memset(&x.charData, 0, 16);

/*-----------------------------------------------------------------------------
 EAPOLKey field process
	Inline Function definition
	Macro definition
-------------------------------------------------------------------------------*/

inline
OCTET_STRING	SubStr(OCTET_STRING	f,	u_short	s,u_short	l);


#define	SetSubStr(f,a,l)	memcpy(f.Octet+l,a.Octet,a.Length)
#define	GetKeyInfo0(f, mask)  ( (f.Octet[KeyInfoPos + 1] & mask) ? 1 :0)
#define	SetKeyInfo0(f,mask,b)	( f.Octet[KeyInfoPos + 1] = (f.Octet[KeyInfoPos + 1] & ~mask) | ( b?mask:0x0) )
#define	GetKeyInfo1(f, mask)  ( (f.Octet[KeyInfoPos] & mask) ? 1 :0)
#define	SetKeyInfo1(f,mask,b)	( f.Octet[KeyInfoPos] = (f.Octet[KeyInfoPos] & ~mask) | ( b?mask:0x0) )


// EAPOLKey
#define Message_DescType(f)		(f.Octet[DescTypePos])
#define Message_setDescType(f, type)	(f.Octet[DescTypePos] = type)
// Key Information Filed
#define Message_KeyDescVer(f)		(f.Octet[KeyInfoPos+1] & 0x07)//(f.Octet[KeyInfoPos+1] & 0x01) | (f.Octet[KeyInfoPos+1] & 0x02) <<1 | (f.Octet[KeyInfoPos+1] & 0x04) <<2
#define Message_setKeyDescVer(f, v)	(f.Octet[KeyInfoPos+1] &= 0xf8) , f.Octet[KeyInfoPos+1] |= (v & 0x07)//(f.Octet[KeyInfoPos+1] |= ((v&0x01)<<7 | (v&0x02)<<6 | (v&0x04)<<5) )
#define	Message_KeyType(f)		GetKeyInfo0(f,0x08)
#define	Message_setKeyType(f, b)	SetKeyInfo0(f,0x08,b)
#define Message_KeyIndex(f)		((f.Octet[KeyInfoPos+1] & 0x30) >> 4) & 0x03//(f.Octet[KeyInfoPos+1] & 0x20) | (f.Octet[KeyInfoPos+1] & 0x10) <<1
#define Message_setKeyIndex(f, v)	(f.Octet[KeyInfoPos+1] &= 0xcf), f.Octet[KeyInfoPos+1] |= ((v<<4) & 0x07)//(f.Octet[KeyInfoPos+1] |= ( (v&0x01)<<5 | (v&0x02)<<4)  )
#define	Message_Install(f)		GetKeyInfo0(f,0x40)
#define	Message_setInstall(f, b)	SetKeyInfo0(f,0x40,b)
#define	Message_KeyAck(f)		GetKeyInfo0(f,0x80)
#define	Message_setKeyAck(f, b)		SetKeyInfo0(f,0x80,b)

#define	Message_KeyMIC(f)		GetKeyInfo1(f,0x01)
#define	Message_setKeyMIC(f, b)		SetKeyInfo1(f,0x01,b)
#define	Message_Secure(f)		GetKeyInfo1(f,0x02)
#define	Message_setSecure(f, b)		SetKeyInfo1(f,0x02,b)
#define	Message_Error(f)		GetKeyInfo1(f,0x04)
#define	Message_setError(f, b)		SetKeyInfo1(f,0x04,b)
#define	Message_Request(f)		GetKeyInfo1(f,0x08)
#define	Message_setRequest(f, b)	SetKeyInfo1(f,0x08,b)
#define	Message_Reserved(f)		(f.Octet[KeyInfoPos] & 0xf0)
#define	Message_setReserved(f, v)	(f.Octet[KeyInfoPos] |= (v<<4&0xff))


#define Message_KeyLength(f)		((u_short)(f.Octet[KeyLenPos] <<8) + (u_short)(f.Octet[KeyLenPos+1]))
#define Message_setKeyLength(f, v)	(f.Octet[KeyLenPos] = (v&0xff00) >>8 ,  f.Octet[KeyLenPos+1] = (v&0x00ff))


/* Replay Counter process function */
#define DEFAULT_KEY_REPLAY_COUNTER_LONG		0xffffffff
#define Message_DefaultReplayCounter(li)	((li.field.HighPart == DEFAULT_KEY_REPLAY_COUNTER_LONG) && (li.field.LowPart == DEFAULT_KEY_REPLAY_COUNTER_LONG) ) ?1:0
#define Message_ReplayCounter(f)			SubStr(f, ReplayCounterPos, KEY_RC_LEN)
#define Message_CopyReplayCounter(f1, f2)	memcpy(f1.Octet + ReplayCounterPos, f2.Octet + ReplayCounterPos, KEY_RC_LEN)
inline	void Message_ReplayCounter_OC2LI(OCTET_STRING f, LARGE_INTEGER * li);
inline	void ReplayCounter_OC2LI(OCTET_STRING f, LARGE_INTEGER * li);
inline int Message_EqualReplayCounter(LARGE_INTEGER li1, OCTET_STRING f);
inline int Message_SmallerEqualReplayCounter(LARGE_INTEGER li1, OCTET_STRING f);
inline int Message_LargerReplayCounter(LARGE_INTEGER li1, OCTET_STRING f);
inline void Message_setReplayCounter(OCTET_STRING f, u_long h, u_long l);


//#define SetNonce(x,y) memcpy(x.Octet, y.charData, 32);
void SetNonce(OCTET_STRING osDst, OCTET32_INTEGER oc32Counter);
#define	Message_KeyNonce(f)					SubStr(f,KeyNoncePos,KEY_NONCE_LEN)
#define Message_setKeyNonce(f, v)			SetSubStr(f, v, KeyNoncePos)
#define Message_EqualKeyNonce(f1, f2)		memcmp(f1.Octet + KeyNoncePos, f2.Octet, KEY_NONCE_LEN)? 0:1
#define Message_KeyIV(f)					Substr(f, KeyIVPos, KEY_IV_LEN)
#define Message_setKeyIV(f, v)				SetSubStr(f, v, KeyIVPos)
#define Message_KeyRSC(f)					Substr(f, KeyRSCPos, KEY_RSC_LEN)
#define Message_setKeyRSC(f, v)				SetSubStr(f, v, KeyRSCPos)
#define Message_KeyID(f)					Substr(f, KeyIDPos, KEY_ID_LEN)
#define Message_setKeyID(f, v)				SetSubStr(f, v, KeyIDPos)
#define Message_MIC(f)						Substr(f, KeyMICPos, KEY_MIC_LEN)
#define Message_setMIC(f, v)				SetSubStr(f, v, KeyMICPos)
#define Message_clearMIC(f)					memset(f.Octet+KeyMICPos, 0, KEY_MIC_LEN)
#define Message_KeyDataLength(f)			((u_short)(f.Octet[KeyDataLenPos] <<8) + (u_short)(f.Octet[KeyDataLenPos+1]))
#define Message_setKeyDataLength(f, v)		(f.Octet[KeyDataLenPos] = (v&0xff00) >>8 ,  f.Octet[KeyDataLenPos+1] = (v&0x00ff))
#define Message_KeyData(f, l)				SubStr(f, KeyDataPos, l)
#define Message_setKeyData(f, v)			SetSubStr(f, v, KeyDataPos);
#define Message_EqualRSNIE(f1 , f2, l)		memcmp(f1.Octet, f2.Octet, l) ? 0:1
#define Message_ReturnKeyDataLength(f)		f.Length - (ETHER_HDRLEN + LIB1X_EAPOL_HDRLEN + EAPOLMSG_HDRLEN)

typedef	union _KeyInfo
{
	u_short	shortData;
	u_char	charData[2];
	struct
	{
		u_short	KeyDescVersion:3;
		u_short	KeyType:1;
		u_short	KeyIndex:2;
		u_short	Install:1;
		u_short	KeyAck:1;
		u_short	KeyMIC:1;
		u_short	Secure:1;
		u_short	Error:1;
		u_short	Request:1;
		u_short	Reserved:4;
	}field;
}KeyInfo;

#define KeyInfo_KeyDescVersion(f)	( ((KeyInfo	*)((f).Octet))	->field.KeyDescVersion)
#define KeyInfo_KeyType(f)			( ((KeyInfo	*)((f).Octet))	->field.KeyType)
#define KeyInfo_KeyIndex(f)			( ((KeyInfo	*)((f).Octet))	->field.KeyIndex)
#define KeyInfo_Install(f)			( ((KeyInfo	*)((f).Octet))	->field.Install)
#define KeyInfo_KeyAck(f)			( ((KeyInfo	*)((f).Octet))	->field.KeyAck)
#define KeyInfo_KeyMic(f)			( ((KeyInfo	*)((f).Octet))	->field.KeyMic)
#define KeyInfo_Secure(f)			( ((KeyInfo	*)((f).Octet))	->field.Secure)
#define KeyInfo_Error(f)			( ((KeyInfo	*)((f).Octet))	->field.Error)
#define KeyInfo_Request(f)			( ((KeyInfo	*)((f).Octet))	->field.Request)
#define KeyInfo_Reserved(f)			( ((KeyInfo	*)((f).Octet))	->field.Reserved)




struct _LIB1X_EAPOL_KEY
{
		u_char			key_desc_ver;
		//KeyInfo			key_info;
		u_char			key_info[2];
		u_char			key_len[sizeof(u_short)];
		u_char			key_replay_counter[KEY_RC_LEN];
		u_char			key_nounce[KEY_NONCE_LEN];
		u_char			key_iv[KEY_IV_LEN];
		u_char			key_rsc[KEY_RSC_LEN];
		u_char			key_id[KEY_ID_LEN];
		u_char			key_mic[KEY_MIC_LEN];
		u_char			key_data_len[KEY_MATERIAL_LEN];
		u_char			*key_data;
};

typedef struct _LIB1X_EAPOL_KEY lib1x_eapol_key;


//---------------------------------------------------------------------
// Definition for 1x_kmsm_eapolkey.c
//---------------------------------------------------------------------
inline  void INCLargeInteger(
	LARGE_INTEGER * x);

inline  void ReplayCounter_LI2OC(
	OCTET_STRING f,
	LARGE_INTEGER * li);

void EncGTK(
	Global_Params * global,
	u_char *kek,
	int keklen,
	u_char *key,
	int keylen,
	u_char *out,
	u_short *outlen);

int  CheckMIC(
	OCTET_STRING EAPOLMsgRecvd,
	u_char *key,
	int keylen);

void CalcMIC(
	OCTET_STRING EAPOLMsgSend,
	int algo,
	u_char *key,
	int keylen);

void CalcGTK(
	u_char *addr,
	u_char *nonce,
	u_char * keyin,
	int keyinlen,
	u_char * keyout,
	int keyoutlen,
	u_char * label
	);

int DecGTK(
	OCTET_STRING EAPOLMsgRecvd, 
	u_char *kek, 
	int keklen, 
	int keylen, 
	u_char *kout);	


//------------------------------------------------------------------------
// Definition file for 1x_kmsm_hmac.c
//------------------------------------------------------------------------
void hmac_sha(
	unsigned char*    k,     /* secret key */
	int      lk,    /* length of the key in bytes */
	unsigned char*    d,     /* data */
	int      ld,    /* length of data in bytes */
	unsigned char*    out,   /* output buffer, at least "t" bytes */
	int      t
	);
void hmac_sha1(
	unsigned char *text,
	int text_len,
	unsigned char *key,
	int key_len,
	unsigned char *digest);

void
hmac_md5(
	unsigned char *text,
	int text_len,
	unsigned char *key,
	int key_len,
	void * digest);

//------------------------------------------------------------------------
// Definition file for 1x_kmsm_prf.c
//------------------------------------------------------------------------
void i_PRF(
	unsigned char*	secret,
	int				secret_len,
	unsigned char*	prefix,
	int				prefix_len,
	unsigned char*	random,
	int				random_len,
	unsigned char*  digest,             // caller digest to be filled in
	int				digest_len			// in byte
	);
//------------------------------------------------------------------------
// Definition file for 1x_kmsm_aes.c
//------------------------------------------------------------------------
typedef unsigned char   u08b; /* an 8 bit unsigned character type */
typedef unsigned short  u16b; /* a 16 bit unsigned integer type   */
typedef unsigned long   u32b; /* a 32 bit unsigned integer type   */
void AES_WRAP(
	u08b * plain,
	int plain_len,
	u08b * iv,
	int iv_len,
	u08b * kek,
	int kek_len,
	u08b *cipher,
	u16b *cipher_len);

void AES_UnWRAP(
	u08b * cipher,
	int cipher_len,
	u08b * kek,
	int kek_len,
	u08b * plain);


#endif
