/* ucpk_hyfi20.c 
 * @Notes:
 *
 * Copyright (c) 2011-2012 Qualcomm Atheros, Inc.
 * Qualcomm Atheros Confidential and Proprietary. 
 * All rights reserved.
 *
 */

#include "defs.h"
#include "common.h"
#include <sha1.h>
#include <sha256.h>
#include <stdio.h>
#include <string.h>

char *msg_array_wifi =     "1905 easily creates interoperable Hybrid networks with deployed Wi-Fi";
char *msg_array_1901 =     "1905 easily creates interoperable Hybrid networks with deployed 1901";
char *msg_array_moca =     "1905 easily creates interoperable Hybrid networks with deployed MoCA";
char *msg_array_ethernet = "1905 easily creates interoperable Hybrid networks with deployed Ethernet";
char *nwkey_salt_default = "Backward interoperability is a feature of 1905.1";


void ucpkHyfi20NwkeyFromPassphrase(const char *passphrase, char *salt, unsigned char nwkey[32])
{

   if (salt == NULL || strlen(salt) == 0)
       salt = nwkey_salt_default;

   pbkdf2_sha1(passphrase, salt, strlen(salt), 4096, nwkey, 32); 
}


void ucpkHyfi20GetWPAPsk(unsigned char key[32], char psk[63])
{
    char *msg = msg_array_wifi;
    unsigned char digest[32];
    int i;

    hmac_sha256(key, 32, (unsigned char *)msg, strlen(msg), digest);
    /*the least significant 248-bit, lowercase ASCII characters*/
    for (i=0; i<31; i++ )
    {
       sprintf((char *)&psk[i*2], "%02x", digest[i]);
    }

}

void ucpkHify20Get1901NMK(unsigned char key[32], char nmk[33])
{
    char *msg = msg_array_1901;
    unsigned char digest[32];
    int i;

    hmac_sha256(key, 32, (unsigned char *)msg, strlen(msg), digest);
    /*the least significant 128-bit, hexadecimal ASCII characters*/
    for (i=0; i<16; i++ )
    {
       sprintf((char *)&nmk[i*2], "%02x", digest[i]);
    }
}


int ucpkHyfi20Init(char* ucpk, char* salt, int shortphrase, char* wpapsk, char* plcnmk)
{
    int ucpklen;
    int wpapsklen;
    unsigned char nwkey[32];

    ucpklen = strlen(ucpk);
    if ( ucpklen < 8 || ucpklen > 64)
        return -1;

    if (ucpklen == 64)
    {
        if (hexstr2bin(ucpk, nwkey, 32) < 0)
            return -1;
    }
    else
    {
        ucpkHyfi20NwkeyFromPassphrase(ucpk, salt, nwkey);
    }

    memset(wpapsk, 0, 62+1);
    ucpkHyfi20GetWPAPsk(nwkey, wpapsk); 

    if (shortphrase &&
        ucpklen >= 1  &&
        ucpklen <= 31 )
        wpapsklen = ucpklen * 2;
    else
        wpapsklen = 62;

    wpapsk[wpapsklen] = '\0';
    

    memset(plcnmk, 0, 32+1);
    ucpkHify20Get1901NMK(nwkey, plcnmk);

    return 0;
}


#if 0
void ucpkTest()
{
    printf("1905.1 UCPK Testing\n");
    /*test case from IEEE802.11 2007  WPA passphrase to key */
    {
    char *Passphrase = "password";
    char *SSID = "IEEE";
    int  SSIDLength = 4;
    char *ExpectedPSK = "f42c6fc52df0ebef9ebb4b90b38a5f902e83fe1b135a70e23aed762e9710a12e";
    unsigned char PSK[32];
    unsigned char PSKHex[64 + 1];
    int i;

    pbkdf2_sha1(Passphrase, SSID, SSIDLength, 4096, PSK, 32);
    for (i =0; i< 32; i++)
        sprintf(&PSKHex[i*2] ,"%02x", PSK[i]);
    if (memcmp(PSKHex, ExpectedPSK, 64) == 0)
    {
        printf("WPA passphrase to key OK\n");
    }
    else
    {
        printf("WPA passphrase to key failed\n");
    }
    }


    /*test case for 1905.1 UCPK */
    {
    char *Passphrase = "password";
    char *ExpectedKey = "4320b5d140946ab78cc78b081ba0fbe0402e8c1d5fd9763b993825db38896678";
    char *ExpectedWPAPSK = "678492b577bc00ee5de390a754ff734dcf178bca76179dbd50c9e1c7e9be38";
    char *ExpectedPLCNMK = "aa440e5ccfe785b15f075a690904006b";

    unsigned char key[32];
    unsigned char keyHex[64 + 1];
    unsigned char wpaPSK[62 + 1];
    unsigned char plcNMK[32 + 1];
    int i;

    /* 1905.1 UCPK passphrase to key */
    ucpkHyfi20NwkeyFromPassphrase(Passphrase, key);
    for (i =0; i< 32; i++){
        sprintf(&keyHex[i*2] ,"%02x", key[i]);
    }
    if (memcmp(keyHex, ExpectedKey, 64) == 0)
    {
        printf("1905.1 UCPK passphrase to key OK\n");
    }
    else
    {
        printf("1905.1 UCPK passphrase to key failed\n");
    }

    /*1905.1 UCPK to WPA PSK*/
    ucpkHyfi20GetWPAPsk(key, wpaPSK);
    if (memcmp(wpaPSK, ExpectedWPAPSK, 62) == 0)
    {
        printf("1905.1 UCPK to to WPA PSK OK\n");
    }
    else
    {
        printf("1905.1 UCPK to to WPA PSK failed\n");
    }

    /*1905.1 UCPK to PLC NMK*/
    ucpkHify20Get1901NMK(key, plcNMK);
    if (memcmp(plcNMK, ExpectedPLCNMK, 32) == 0)
    {
        printf("1905.1 UCPK to PLC NMK OK\n");
    }
    else
    {
        printf("1905.1 UCPK to PLC NMK failed\n");
    }
    }

    printf("End of UCPK Testing\n");
}
#endif


