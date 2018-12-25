/* @File: ucpkgen.c  
 * @Notes: tools for generate WLAN, 1901, MoCA needed passwords from 1905.1 UCPK
 *
 * Copyright (c) 2011-2012 Qualcomm Atheros, Inc.
 * Qualcomm Atheros Confidential and Proprietary. 
 * All rights reserved.
 *
 */

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include "ucpk_hyfi20.h"
#include "common.h"

void usage()
{
     printf("%s\n%s\nUsage:\n", "1905.1 UCPK tools, Copyright (c) 2011-2012 Qualcomm Atheros, Inc.",
             "Copyright (c) 2005-2006, Jouni Malinen <j@w1.fi>");
     printf("\tucpkgen [-l|-s] [-n salt] passphrase/key\n");
     printf("\t-l: long wpa passphrase, default\n");
     printf("\t-s: short wpa passphrase\n");
     printf("\t-n: UCPK salt, it could be 1905.1 Network Name\n");
     printf("\tpassphrase: 8-63 ASCII characters\n");
     printf("\tkey: 64 hexadecimal ASCII characters\n");

}


int main(int argc, char **argv)
{
    int ucpklen;
    int wpapsklen;
    unsigned char nwkey[32];
    char wpapsk[62+1];
    char plcnmk[32+1];
    int i;
    char *ucpk;
    int  shortphrase = 0;
    char *salt = NULL;
    int ch;

    if( argc < 2)
    {
        usage();
        return -1;
    }

    opterr = 0;
    while((ch = getopt(argc,argv, "n:ls"))!= -1)
    {
       switch(ch)
       {
           case 'l':
               shortphrase = 0;
               break;
           case 's':
               shortphrase = 1;
               break;
           case 'n':
               salt = optarg;
               break;
           default:
               printf("Unknown option: %d\n", ch);
               usage();
               return -1;
       }
    }

    if (optind != argc -1)
    {
        printf("Unknown parameter: %s\n", argv[optind]);
        usage();
        return -1;
    } 

    ucpk = argv[optind];
 
    ucpklen = strlen(ucpk);
    if ( ucpklen < 8 || ucpklen > 64)
    {
        printf("Invalid ucpk length\n");
        return -1; 
    }

    if (ucpklen == 64)
    {
        if (hexstr2bin(ucpk, nwkey, 32) < 0)
        {
            printf("Invalid ucpk key\n");
            return -1;
        }
    }
    else
    {
        ucpkHyfi20NwkeyFromPassphrase(ucpk, salt, nwkey);
    }

    memset(wpapsk, 0, sizeof (wpapsk));
    ucpkHyfi20GetWPAPsk(nwkey, wpapsk); 

    memset(plcnmk, 0, sizeof (plcnmk));
    ucpkHify20Get1901NMK(nwkey, plcnmk);

    if (shortphrase &&
        ucpklen >= 1  &&
        ucpklen <= 31 )
        wpapsklen = ucpklen * 2;
    else
        wpapsklen = 62;

    wpapsk[wpapsklen] = '\0';

    if (ucpklen != 64)
        printf("1905.1 UCPK passphrase \t:%s\n",ucpk);
    else
        printf("1905.1 UCPK passphrase \t:\n");

    printf("1905.1 UCPK key \t:");
    for (i=0; i<32; i++)
        printf("%02X", nwkey[i]);
    printf("\n");

    printf("WPA PSK \t\t:%s\n", wpapsk);
    printf("1901 NMK \t\t:%s\n", plcnmk);

    return 0;
}



