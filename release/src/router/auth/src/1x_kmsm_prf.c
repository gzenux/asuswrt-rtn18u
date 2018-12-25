#include "stdafx.h"
#include "stdlib.h"
#include "string.h"
#include "1x_common.h"
#include "1x_kmsm_eapolkey.h"


void i_P_SHA1(
	unsigned char*  key,                // pointer to authentication key 
	int             key_len,            // length of authentication key 
	unsigned char*  text,               // pointer to data stream 
	int             text_len,           // length of data stream 
	unsigned char*  digest,             // caller digest to be filled in 
	int				digest_len			// in byte
	)
{
	int i;
	int offset=0;
	int step=20;
	int IterationNum=(digest_len+step-1)/step;

	for(i=0;i<IterationNum;i++)
	{
		text[text_len]=(unsigned char)i;
		hmac_sha(key,key_len,text,text_len+1,digest+offset,step);
		offset+=step;
	}
}

void i_PRF(
	unsigned char*	secret,
	int				secret_len,
	unsigned char*	prefix,
	int				prefix_len,
	unsigned char*	random,
	int				random_len,
	unsigned char*  digest,             // caller digest to be filled in 
	int				digest_len			// in byte
	)
{
	unsigned char data[1000];
	memcpy(data,prefix,prefix_len);
	data[prefix_len++]=0;
	memcpy(data+prefix_len,random,random_len);
	i_P_SHA1(secret,secret_len,data,prefix_len+random_len,digest,digest_len);
}
#ifndef COMPACK_SIZE
// PRF : added by Emily
// Length of output is in octets rather than bits
// since length is always a multiple of 8
// output array is organized so first N octets starting from 0
// contains PRF output
//
// supported inputs are 16, 32, 48, 64
// output array must be 80 octets in size to allow for sha1 overflow
//
void PRF(unsigned char *key, int key_len, unsigned char *prefix, 
    int prefix_len, unsigned char *data, int data_len,
    unsigned char *output, int len)
{
	int i;
	unsigned char input[1024]; // concatenated input
	int currentindex = 0;
	int total_len;
	memcpy(input, prefix, prefix_len);
	input[prefix_len] = 0;		// single octet 0
	memcpy(&input[prefix_len+1], data, data_len);
	total_len = prefix_len + 1 + data_len;
	input[total_len] = 0;		// single octet count, starts at 0
	total_len++;
	for(i = 0; i < (len+19)/20; i++) {
		hmac_sha1(input, total_len, key, key_len, &output[currentindex]);
		currentindex += 20;	// next concatenation location
		input[total_len-1]++;	// increment octet count
	}
}
#endif

#define A_SHA_DIGEST_LEN 20
/*
 * F(P, S, c, i) = U1 xor U2 xor ... Uc
 * U1 = PRF(P, S || Int(i))
 * U2 = PRF(P, U1)
 * Uc = PRF(P, Uc-1)
 */

void F(
	char *password,
	int passwordlength, 
	unsigned char *ssid,
	int ssidlength,
	int iterations,
	int count,
	unsigned char *output)
{
	unsigned char digest[36], digest1[A_SHA_DIGEST_LEN];
	int i, j;

	/* U1 = PRF(P, S || int(i)) */
	memcpy(digest, ssid, ssidlength);
	digest[ssidlength] = (unsigned char)((count>>24) & 0xff);
	digest[ssidlength+1] = (unsigned char)((count>>16) & 0xff);
	digest[ssidlength+2] = (unsigned char)((count>>8) & 0xff);
	digest[ssidlength+3] = (unsigned char)(count & 0xff);
	hmac_sha1(digest, ssidlength + 4,
		(unsigned char*) password, (int)strlen(password),
           	digest1);

	/*
	hmac_sha1((unsigned char*) password, passwordlength,
           digest, ssidlength+4, digest1);
	*/

	/* output = U1 */
	memcpy(output, digest1, A_SHA_DIGEST_LEN);

	for (i = 1; i < iterations; i++) {
		/* Un = PRF(P, Un-1) */
		hmac_sha1(digest1, A_SHA_DIGEST_LEN, (unsigned char*) password, 
				(int)strlen(password), digest);
		//hmac_sha1((unsigned char*) password, passwordlength,digest1, A_SHA_DIGEST_LEN, digest);
		memcpy(digest1, digest, A_SHA_DIGEST_LEN);

		/* output = output xor Un */
		for (j = 0; j < A_SHA_DIGEST_LEN; j++) {
			output[j] ^= digest[j];
		}
	}
}

/*
 * password - ascii string up to 63 characters in length
 * ssid - octet string up to 32 octets
 * ssidlength - length of ssid in octets
 * output must be 40 octets in length and outputs 256 bits of key
 */
int PasswordHash (
	char *password,
	int passwordlength,
	unsigned char *ssid,
	int ssidlength,
	unsigned char *output)
{
	if ((strlen(password) > 63) || (ssidlength > 32))
		return 0;

	F(password, passwordlength, ssid, ssidlength, 4096, 1, output);
	F(password, passwordlength, ssid, ssidlength, 4096, 2, &output[A_SHA_DIGEST_LEN]);
	return 1;
}

#ifndef COMPACK_SIZE
void TestPassPhrases()
{
	int	i;
	unsigned char output[3][32];

	PasswordHash("password", 8, (unsigned char *)"IEEE", 4, output[0]);
	PasswordHash("ThisIsAPassword", 15, (unsigned char *)"ThisIsASSID", 11, output[1]);
	PasswordHash("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", 32,  
		(unsigned char *)"ZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZ", 32 , output[2]);

	for(i=0 ; i<3 ; i++)
		lib1x_hexdump2(MESS_DBG_KEY_MANAGE, "TestPassPhrases", output[i], sizeof(output[i]), "Result key");

}
#endif

#ifndef COMPACK_SIZE
#define PMK_EXPANSION_CONST          "Pairwise key expansion"
#define PMK_EXPANSION_CONST_SIZE             22
void TestPRF()
{
	u_char PMK[]=	{0x0d, 0xc0, 0xd6, 0xeb, 0x90, 0x55, 0x5e, 0xd6,
			 0x41, 0x97, 0x56, 0xb9, 0xa1, 0x5e, 0xc3, 0xe3,
			 0x20, 0x9b, 0x63, 0xdf, 0x70, 0x7d, 0xd5, 0x08,
			 0xd1, 0x45, 0x81, 0xf8, 0x98, 0x27, 0x21, 0xaf};
	u_char AA[]=	{0xa0, 0xa1, 0xa1, 0xa3, 0xa4, 0xa5};
	u_char SA[]=	{0xb0, 0xb1, 0xb2, 0xb3, 0xb4, 0xb5};
	u_char SNonce[]={0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7, 0xc8, 0xc9,
			 0xd0, 0xd1, 0xd2, 0xd3, 0xd4, 0xd5, 0xd6, 0xd7, 0xd8, 0xd9};
	u_char ANonce[]={0xe0, 0xe1, 0xe2, 0xe3, 0xe4, 0xe5, 0xe6, 0xe7, 0xe8, 0xe9,
			 0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9};


	u_char Data[256];
	u_char tmpPTK[128];
	memset(Data, 0, sizeof Data);
	memcpy(Data, AA, sizeof AA);
	memcpy(Data+6, SA, sizeof SA);
	memcpy(Data+12,SNonce, sizeof SNonce);
	memcpy(Data+32,ANonce, sizeof ANonce);

	lib1x_hexdump2(MESS_DBG_KEY_MANAGE, "TestPRF", Data, 52, "Data");

	i_PRF(PMK, sizeof PMK, (u_char*)PMK_EXPANSION_CONST,
		PMK_EXPANSION_CONST_SIZE, Data,52,
		tmpPTK, PTK_LEN_TKIP);

	lib1x_hexdump2(MESS_DBG_KEY_MANAGE, "TestPRF", tmpPTK, 64, "KEY");


}
#endif

#ifndef COMPACK_SIZE
//#include <openssl/rc4.h>
#include "1x_rc4.h"
void TestRC4()
{

	u_char Key[]	={0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef};
	u_char Input[]	={0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef};
	u_char Output[8]; //= {0x75, 0xb7, 0x87, 0x80, 0x99, 0xe0, 0xc5, 0x96 }

	RC4_KEY		rc4key;

	RC4_set_key(&rc4key, sizeof Key, Key);
	RC4(&rc4key, sizeof Input, (u_char*)Input, Output);
	lib1x_hexdump2(MESS_DBG_KEY_MANAGE, "TestRC4", Output, sizeof Output, "CipherText");


}
#endif

#ifndef COMPACK_SIZE
void testMIC()
{


	u_char data[] ={
		0x1,  0x3, 0x0,  0x79,  0xfe,  0x1,  0x8,  0x0,  0x0,  0x0,  0x0,  0x0,  0x0, 0x0,  0x0,  0x0,
		0x0,  0x9d,  0xb2,  0x5,  0xec,  0xf0,  0xfa,  0x79,  0x8b,  0x7f,  0x2c,  0x77,  0xc8, 0xd6,  0x79,  0xf0,
		0xfb,  0xe,  0x8f,  0xa3,  0xe1,  0x2,  0x18,  0xce,  0xf3,  0xd7,  0x62,  0xe1,  0xb, 0x6c,  0x63,  0x33,
		0x4f,  0x0,  0x0,  0x0,  0x0,  0x0,  0x0,  0x0,  0x0,  0x0,  0x0,  0x0,  0x0, 0x0,  0x0,0x0,
		0x0, 0x0,  0x0,0x0,  0x0,0x0,  0x0,0x0,  0x0,0x0,  0x0,0x0,  0x0, 0x0, 0x0, 0x0,
		0x0,0x0,  0x0,0x0,  0x0,0x0,  0x0,0x0,  0x0,0x0,  0x0,0x0,  0x0,0x0,  0x0,0x0,
		0x0,0x0, 0x1a, 0xdd, 0x18, 0x0, 0x50, 0xf2, 0x1, 0x1, 0x0, 0x0, 0x50,0xf2, 0x2, 0x1,
		0x0, 0x0, 0x50, 0xf2, 0x1, 0x1, 0x0, 0x0, 0x50, 0xf2, 0x2, 0xa , 0x0};

	u_char key[] =
		{0x92, 0x4e, 0xbc, 0xb0, 0x64, 0x70, 0xc7, 0x7e, 0x6d, 0xe1, 0x1, 0xc5, 0xe9, 0x27, 0x81, 0xc3};

	u_char micout[16];
	lib1x_hexdump2(MESS_DBG_KEY_MANAGE, "testMIC", data, sizeof data, "data");

	hmac_md5((u_char*)data, sizeof(data)-12 , key, sizeof key, micout);
	lib1x_hexdump2(MESS_DBG_KEY_MANAGE, "testMIC", micout, sizeof micout, "micout");

	//lib1x_hmac_md5((u_char*)data, sizeof(data)-12 , key, sizeof key, micout);
	//lib1x_hexdump2(MESS_DBG_KEY_MANAGE, "testMIC", micout, sizeof micout, "micout");



}
#endif
