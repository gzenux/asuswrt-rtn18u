/* @file: ucpk_hyfi20.h
 * @Notes:
 *
 * Copyright (c) 2011-2012 Qualcomm Atheros, Inc.
 * Qualcomm Atheros Confidential and Proprietary. 
 * All rights reserved.
 *
 */
#ifndef _UCPK_HYFI20_H
#define _UCPK_HYFI20_H

void ucpkHyfi20NwkeyFromPassphrase(const char *passphrase, char *salt, unsigned char nwkey[32]);
void ucpkHyfi20GetWPAPsk(unsigned char key[32], char psk[62]);
void ucpkHify20Get1901NMK(unsigned char key[32], char nmk[32]);
int ucpkHyfi20Init(char* ucpk, char *salt, int shortphrase, char* wpapsk, char* plcnmk);

#endif

