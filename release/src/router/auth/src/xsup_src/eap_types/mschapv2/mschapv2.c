/**
 * A client-side 802.1x implementation supporting EAP/TLS
 *
 * This code is released under both the GPL version 2 and BSD licenses.
 * Either license may be used.  The respective licenses are found below.
 *
 * Copyright (C) 2002 Bryan D. Payne & Nick L. Petroni Jr.
 * All Rights Reserved
 *
 * --- GPL Version 2 License ---
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 *
 * --- BSD License ---
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 *  - Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 *  - Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *  - All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *       This product includes software developed by the University of
 *       Maryland at College Park and its contributors.
 *  - Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

/*******************************************************************
 * EAPMSCHAPv2 Function implementations
 *
 * File: mschapv2.c
 *
 * Authors: Chris.Hessing@utah.edu
 *
 * $Id: mschapv2.c,v 1.1.1.1 2007/08/06 10:04:42 root Exp $
 * $Date: 2007/08/06 10:04:42 $
 * $Log: mschapv2.c,v $
 * Revision 1.1.1.1  2007/08/06 10:04:42  root
 * Initial import source to CVS
 *
 * Revision 1.1.1.1  2004/08/12 10:33:31  ysc
 *
 *
 * Revision 1.1  2004/07/24 00:52:57  kennylin
 *
 * Client mode TLS
 *
 * Revision 1.1  2004/07/24 00:40:55  kennylin
 *
 * Client mode TLS
 *
 * Revision 1.7  2004/04/05 17:19:30  chessing
 *
 * Added additional checks against pointers to try to help prevent segfaults.  (This still needs to be completed.)  Fixed a problem with PEAP where a NULL input packet would result in a huge unencrypted packet, and a segfault.  (This was triggered when using one of the gui password tools.  When the password was in the config file, it wouldn't be triggered.)
 *
 * Revision 1.6  2004/04/02 20:50:20  chessing
 *
 * Attempt to fix PEAP with IAS. At this point, we can get through the TLS piece of the PEAP authentication, and successfully attempt a phase 2 authentication.  But, for some reason MS-CHAPv2 is failing when used with IAS.  (But at least we are one step closer!)  Also, removed the des pieces that were needed for eap-mschapv2, since we can use the OpenSSL routines instead.  The proper way to handle DES was found while looking at the CVS code for wpa_supplicant.  The fix for phase 1 of PEAP was found while looking at the commit notes for wpa_supplicant.  (wpa_supplicant is part of hostap, and is written/maintained by Jouni Malinen.)
 *
 * Revision 1.5  2004/02/06 06:13:31  chessing
 *
 * Cleaned up some unneeded stuff in the configure.in file as per e-mail from Rakesh Patel.  Added all 12 patches from Jouni Malinen (Including wpa_supplicant patch, until we can add true wpa support in xsupplicant.)
 *
 * Revision 1.4  2003/11/27 02:33:25  chessing
 *
 * Added LEAP code from Marios Karagiannopoulos.  Keying still needs to be completed.
 *
 * Revision 1.3  2003/11/21 05:09:47  chessing
 *
 * PEAP now works!
 *
 * Revision 1.2  2003/11/20 00:05:32  chessing
 *
 * EAP-MSCHAPv2 now supports generation of keys.  (New feature)
 *
 * Revision 1.1.1.1  2003/11/19 04:13:28  chessing
 * New source tree
 *
 *
 *******************************************************************/

// This code was taken from the pseudo code in RFC 2759.

#include <openssl/ssl.h>
#include <openssl/des.h>
#include <openssl/evp.h>
#include <string.h>
#include <strings.h>
#include <ctype.h>
#include <stdint.h>
#include "../../xsup_debug.h"
#include "../../xsup_err.h"

void ChallengeHash(char *PeerChallenge, char *AuthenticatorChallenge,
		   char *UserName, char *Challenge)
{
  EVP_MD_CTX cntx;
  char Digest[30];
  int retLen;

  if ((!PeerChallenge) || (!AuthenticatorChallenge) || (!UserName) ||
      (!Challenge))
    {
      debug_printf(DEBUG_NORMAL, "Invalid data passed in to ChallengeHash()!\n");
      return;
    }

  bzero(Digest, 30);
  EVP_DigestInit(&cntx, EVP_sha1());
  EVP_DigestUpdate(&cntx, PeerChallenge, 16);
  EVP_DigestUpdate(&cntx, AuthenticatorChallenge, 16);
  EVP_DigestUpdate(&cntx, UserName, strlen(UserName));
  EVP_DigestFinal(&cntx, (char *)&Digest, &retLen);

  memcpy(Challenge, Digest, 8);
}

char *to_unicode(char *non_uni)
{
  char *retUni;
  int i;

  if (!non_uni)
    {
      debug_printf(DEBUG_NORMAL, "Invalid value passed in to to_unicode()!\n");
      return NULL;
    }

  retUni = (char *)malloc((strlen(non_uni)+1)*2);
  if (retUni == NULL)
    {
      debug_printf(DEBUG_NORMAL, "Error with MALLOC in to_unicode()!\n");
      return NULL;
    }
  bzero(retUni, ((strlen(non_uni)+1)*2));

  for (i=0; i<strlen(non_uni); i++)
    {
      retUni[(2*i)] = non_uni[i];
    }
  return retUni;
}

void NtPasswordHash(char *Password, char *PasswordHash)
{
  EVP_MD_CTX cntx;
  char retVal[20];
  int i, len;
  char *uniPassword;

  if ((!Password) || (!PasswordHash))
    {
      debug_printf(DEBUG_NORMAL, "Invalid data passed in to NtPasswordHash()!\n");
      return;
    }

  bzero(retVal, 20);
  uniPassword = to_unicode(Password);
  len = (strlen(Password))*2;

  EVP_DigestInit(&cntx, EVP_md4());
  EVP_DigestUpdate(&cntx, uniPassword, len);
  EVP_DigestFinal(&cntx, (char *)&retVal, (int *)&i);
  memcpy(PasswordHash, &retVal, 16);
  free(uniPassword);
}

void HashNtPasswordHash(char *PasswordHash, char *PasswordHashHash)
{
  EVP_MD_CTX cntx;
  int i;

  if ((!PasswordHash) || (!PasswordHashHash))
    {
      debug_printf(DEBUG_NORMAL, "Invalid values passed in to HashNtPasswordHash()!\n");
      return;
    }

  EVP_DigestInit(&cntx, EVP_md4());
  EVP_DigestUpdate(&cntx, PasswordHash, 16);
  EVP_DigestFinal(&cntx, PasswordHashHash, &i);
}

// Shamelessly take from the hostap code written by Jouni Malinen
void des_encrypt(uint8_t *clear, uint8_t *key, uint8_t *cypher)
{
  uint8_t pkey[8], next, tmp;
  int i;
  DES_key_schedule ks;

  if ((!clear) || (!key) || (!cypher))
    {
      debug_printf(DEBUG_NORMAL, "Invalid parameters passed to des_encrypt()!\n");
      return;
    }

  /* Add parity bits to key */
  next = 0;
  for (i=0; i<7; i++)
    {
      tmp = key[i];
      pkey[i] = (tmp >> i) | next | 1;
      next = tmp << (7-i);
    }
  pkey[i] = next | 1;

  DES_set_key(&pkey, &ks);
  DES_ecb_encrypt((DES_cblock *) clear, (DES_cblock *) cypher, &ks,
		  DES_ENCRYPT);
}

char ctonibble(char cnib)
{
  char retVal=0x00;
  char testval=0x00;

  if ((cnib>='0') && (cnib<='9'))
    {
      retVal = cnib - '0';
    } else {
      testval = toupper(cnib);
      if ((testval>='A') && (testval<='F'))
	{
	  retVal = ((testval - 'A') +10);
	} else {
	  debug_printf(DEBUG_NORMAL, "Error in conversion!  (Check ctonibble()) -- %02x\n",testval);
	}
    }
  return retVal;
}

// Convert an ASCII string to a binary version of it.
void process_hex(char *instr, int size, char *outstr)
{
  int i;

  if ((!instr) || (!outstr))
    {
      debug_printf(DEBUG_NORMAL, "Invalid parameter passed in to process_hex()!\n");
      return;
    }

  // Make sure we don't try to convert something that isn't byte aligned.
  if ((size % 2) != 0)
    {
      debug_printf(DEBUG_NORMAL, "Hex string isn't an even number of chars!!!\n");
      return;
    }

  for (i=0;i<(size/2);i++)
    {
      if (instr[i*2] != 0x00)
	{
	  outstr[i] = (ctonibble(instr[i*2]) << 4) + ctonibble(instr[(i*2)+1]);
	}
    }
}

void GenerateAuthenticatorResponse(char *Password, char *NTResponse,
				   char *PeerChallenge, 
				   char *AuthenticatorChallenge, char *UserName,
				   char *AuthenticatorResponse)
{
  char PasswordHash[16];
  char PasswordHashHash[16];
  EVP_MD_CTX context;
  int Digest_len;
  char Digest[20];
  char Challenge[8];

  char Magic1[39] =
    {0x4D, 0x61, 0x67, 0x69, 0x63, 0x20, 0x73, 0x65, 0x72, 0x76,
     0x65, 0x72, 0x20, 0x74, 0x6F, 0x20, 0x63, 0x6C, 0x69, 0x65,
     0x6E, 0x74, 0x20, 0x73, 0x69, 0x67, 0x6E, 0x69, 0x6E, 0x67,
     0x20, 0x63, 0x6F, 0x6E, 0x73, 0x74, 0x61, 0x6E, 0x74};

  char Magic2[41] =
    {0x50, 0x61, 0x64, 0x20, 0x74, 0x6F, 0x20, 0x6D, 0x61, 0x6B,
     0x65, 0x20, 0x69, 0x74, 0x20, 0x64, 0x6F, 0x20, 0x6D, 0x6F,
     0x72, 0x65, 0x20, 0x74, 0x68, 0x61, 0x6E, 0x20, 0x6F, 0x6E,
     0x65, 0x20, 0x69, 0x74, 0x65, 0x72, 0x61, 0x74, 0x69, 0x6F,
     0x6E};

  if ((!Password) || (!NTResponse) || (!PeerChallenge) || 
      (!AuthenticatorChallenge) || (!UserName) || (!AuthenticatorResponse))
    {
      debug_printf(DEBUG_NORMAL, "Invalid parameter passed in to GenerateAuthenticatorResponse()!\n");
      return;
    }

  NtPasswordHash(Password, (char *)&PasswordHash);
  HashNtPasswordHash((char *)&PasswordHash, (char *)&PasswordHashHash);

  EVP_DigestInit(&context, EVP_sha1());
  EVP_DigestUpdate(&context, &PasswordHashHash, 16);
  EVP_DigestUpdate(&context, NTResponse, 24);
  EVP_DigestUpdate(&context, Magic1, 39);
  EVP_DigestFinal(&context, (char *)&Digest, &Digest_len);

  ChallengeHash(PeerChallenge, AuthenticatorChallenge, UserName, Challenge);

  EVP_DigestInit(&context, EVP_sha1());
  EVP_DigestUpdate(&context, &Digest, 20);
  EVP_DigestUpdate(&context, &Challenge, 8);
  EVP_DigestUpdate(&context, Magic2, 41);
  EVP_DigestFinal(&context, (char *)&Digest, &Digest_len);

  memcpy(AuthenticatorResponse, &Digest, Digest_len);
}



void CheckAuthenticatorResponse(char *Password, char *NtResponse,
				char *PeerChallenge, 
				char *AuthenticatorChallenge, char *UserName,
				char *ReceivedResponse, int *ResponseOK)
{
  char MyResponse[20], procResp[20];

  if ((!Password) || (!NtResponse) || (!PeerChallenge) || 
      (!AuthenticatorChallenge) || (!UserName) || (!ReceivedResponse) ||
      (!ResponseOK))
    {
      debug_printf(DEBUG_NORMAL, "Invalid parameters passed in to CheckAuthenticatorResponse()!\n");
      return;
    }

  GenerateAuthenticatorResponse(Password, NtResponse, PeerChallenge,
				AuthenticatorChallenge, UserName, 
				(char *)&MyResponse);

  process_hex(ReceivedResponse, strlen(ReceivedResponse), (char *)&procResp);

  if (memcmp((char *)&MyResponse, (char *)&procResp, 20) == 0)
    {
      *ResponseOK = 1;
    } else {
      *ResponseOK = 0;
    }
}

// Take from hostap code by Jouni Malinen, and modified to work with
// XSupplicant.
void ChallengeResponse(char *Challenge, char *PasswordHash, char *Response)
{
  uint8_t zpwd[7];

  if ((!Challenge) || (!PasswordHash) || (!Response))
    {
      debug_printf(DEBUG_NORMAL, "Invalid parameters passed in to ChallengeResponse()!\n");
      return;
    }

  des_encrypt(Challenge, PasswordHash, Response);
  des_encrypt(Challenge, PasswordHash + 7, Response+8);
  zpwd[0] = PasswordHash[14];
  zpwd[1] = PasswordHash[15];
  memset(zpwd + 2, 0, 5);
  des_encrypt(Challenge, zpwd, Response+16);
}

void NtChallengeResponse(char *Challenge, char *Password, char *Response)
{
  char password_hash[16];

  if ((!Challenge) || (!Password) || (!Response))
    {
      debug_printf(DEBUG_NORMAL, "Invalid parameters passed in to NtChallengeResponse()!\n");
      return;
    }

  NtPasswordHash(Password, (char *)&password_hash);
  ChallengeResponse(Challenge, (char *)&password_hash, Response);
}

void GenerateNTResponse(char *AuthenticatorChallenge, char *PeerChallenge,
			char *UserName, char *Password, char *Response)
{
  char Challenge[8], PasswordHash[16];

  if ((!AuthenticatorChallenge) || (!PeerChallenge) || (!UserName) ||
      (!Password) || (!Response))
    {
      debug_printf(DEBUG_NORMAL, "Invalid parameters passed in to GenerateNTResponse()!\n");
      return;
    }
  
  ChallengeHash(PeerChallenge, AuthenticatorChallenge, UserName, (char *)&Challenge);
  debug_printf(DEBUG_AUTHTYPES, "PeerChallenge : ");
  debug_hex_printf(DEBUG_AUTHTYPES, PeerChallenge, 8);
  debug_printf(DEBUG_AUTHTYPES, "AuthenticatorChallenge : ");
  debug_hex_printf(DEBUG_AUTHTYPES, AuthenticatorChallenge, 8);
  debug_printf(DEBUG_AUTHTYPES, "Username : %s\n",UserName);
  debug_printf(DEBUG_AUTHTYPES, "Challenge : ");
  debug_hex_printf(DEBUG_AUTHTYPES, Challenge, 8);
  NtPasswordHash(Password, (char *)&PasswordHash);
  debug_printf(DEBUG_AUTHTYPES, "PasswordHash : ");
  debug_hex_printf(DEBUG_AUTHTYPES, PasswordHash, 16);
  ChallengeResponse(Challenge, (char *)&PasswordHash, Response);
  debug_printf(DEBUG_AUTHTYPES, "Response : ");
  debug_hex_printf(DEBUG_AUTHTYPES, Response, 24);
}

void GetMasterKey(char *PasswordHashHash, char *NTResponse, char *MasterKey)
{
  EVP_MD_CTX cntx;
  char Digest[20];
  int retLen;

  char Magic1[27] =
    {0x54, 0x68, 0x69, 0x73, 0x20, 0x69, 0x73, 0x20, 0x74,
     0x68, 0x65, 0x20, 0x4d, 0x50, 0x50, 0x45, 0x20, 0x4d,
     0x61, 0x73, 0x74, 0x65, 0x72, 0x20, 0x4b, 0x65, 0x79};

  if ((!PasswordHashHash) || (!NTResponse) || (!MasterKey))
    {
      debug_printf(DEBUG_NORMAL, "Invalid parameters passed in to GetMasterKey()!\n");
      return;
    }
  
  bzero(&Digest, 20);

  EVP_DigestInit(&cntx, EVP_sha1());
  EVP_DigestUpdate(&cntx, PasswordHashHash, 16);
  EVP_DigestUpdate(&cntx, NTResponse, 24);
  EVP_DigestUpdate(&cntx, (char *)&Magic1, 27);
  EVP_DigestFinal(&cntx, (char *)&Digest, &retLen);

  memcpy(MasterKey, &Digest, 16);
}

void GetMasterLEAPKey(char *PasswordHashHash, char *APC, char *APR, char *PC, char *PR, char *MasterKey)
{
  EVP_MD_CTX cntx;
  char Digest[20];
  int retLen;

  if ((!PasswordHashHash) || (!APC) || (!APR) || (!PC) || (!PR) ||
      (!MasterKey))
    {
      debug_printf(DEBUG_NORMAL, "Invalid data passed in to GetMasterLEAPKey()!\n");
      return;
    }

  bzero(&Digest, 20);

  EVP_DigestInit(&cntx, EVP_md5());
  EVP_DigestUpdate(&cntx, PasswordHashHash, 16);
  EVP_DigestUpdate(&cntx, APC, 8);
  EVP_DigestUpdate(&cntx, APR, 24);
  EVP_DigestUpdate(&cntx, PC, 8);
  EVP_DigestUpdate(&cntx, PR, 24); 
  EVP_DigestFinal(&cntx, (char *)&Digest, &retLen);
  
  memcpy(MasterKey, &Digest, 16);
  
}

void GetAsymetricStartKey(char *MasterKey, char *SessionKey, 
			  int SessionKeyLength, int IsSend, int IsServer)
{
  EVP_MD_CTX cntx;
  char Digest[20];
  char Magic[84];
  int retLen;

  char Magic2[84] =
    {0x4f, 0x6e, 0x20, 0x74, 0x68, 0x65, 0x20, 0x63, 0x6c, 0x69,
     0x65, 0x6e, 0x74, 0x20, 0x73, 0x69, 0x64, 0x65, 0x2c, 0x20,
     0x74, 0x68, 0x69, 0x73, 0x20, 0x69, 0x73, 0x20, 0x74, 0x68,
     0x65, 0x20, 0x73, 0x65, 0x6e, 0x64, 0x20, 0x6b, 0x65, 0x79,
     0x3b, 0x20, 0x6f, 0x6e, 0x20, 0x74, 0x68, 0x65, 0x20, 0x73,
     0x65, 0x72, 0x76, 0x65, 0x72, 0x20, 0x73, 0x69, 0x64, 0x65,
     0x2c, 0x20, 0x69, 0x74, 0x20, 0x69, 0x73, 0x20, 0x74, 0x68,
     0x65, 0x20, 0x72, 0x65, 0x63, 0x65, 0x69, 0x76, 0x65, 0x20,
     0x6b, 0x65, 0x79, 0x2e};

  char Magic3[84] =
    {0x4f, 0x6e, 0x20, 0x74, 0x68, 0x65, 0x20, 0x63, 0x6c, 0x69,
     0x65, 0x6e, 0x74, 0x20, 0x73, 0x69, 0x64, 0x65, 0x2c, 0x20,
     0x74, 0x68, 0x69, 0x73, 0x20, 0x69, 0x73, 0x20, 0x74, 0x68,
     0x65, 0x20, 0x72, 0x65, 0x63, 0x65, 0x69, 0x76, 0x65, 0x20,
     0x6b, 0x65, 0x79, 0x3b, 0x20, 0x6f, 0x6e, 0x20, 0x74, 0x68,
     0x65, 0x20, 0x73, 0x65, 0x72, 0x76, 0x65, 0x72, 0x20, 0x73,
     0x69, 0x64, 0x65, 0x2c, 0x20, 0x69, 0x74, 0x20, 0x69, 0x73,
     0x20, 0x74, 0x68, 0x65, 0x20, 0x73, 0x65, 0x6e, 0x64, 0x20,
     0x6b, 0x65, 0x79, 0x2e};

  char SHSpad1[40] =
    {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

  char SHSpad2[40] =
    {0xf2, 0xf2, 0xf2, 0xf2, 0xf2, 0xf2, 0xf2, 0xf2, 0xf2, 0xf2,
     0xf2, 0xf2, 0xf2, 0xf2, 0xf2, 0xf2, 0xf2, 0xf2, 0xf2, 0xf2,
     0xf2, 0xf2, 0xf2, 0xf2, 0xf2, 0xf2, 0xf2, 0xf2, 0xf2, 0xf2,
     0xf2, 0xf2, 0xf2, 0xf2, 0xf2, 0xf2, 0xf2, 0xf2, 0xf2, 0xf2};

  if ((!MasterKey) || (!SessionKey))
    {
      debug_printf(DEBUG_NORMAL, "Invalid parameters passed in to GetAsymetricStartKey()!\n");
      return;
    }

  bzero(&Digest, 20);

  if (IsSend) {
    if (IsServer) {
      memcpy(&Magic, &Magic3, 84);
    } else {
      memcpy(&Magic, &Magic2, 84);
    }
  } else {
    if (IsServer) {
      memcpy(&Magic, &Magic2, 84);
    } else {
      memcpy(&Magic, &Magic3, 84);
    }
  }

  EVP_DigestInit(&cntx, EVP_sha1());
  EVP_DigestUpdate(&cntx, MasterKey, 16);
  EVP_DigestUpdate(&cntx, SHSpad1, 40);
  EVP_DigestUpdate(&cntx, (char *)&Magic, 84);
  EVP_DigestUpdate(&cntx, SHSpad2, 40);
  EVP_DigestFinal(&cntx, (char *)&Digest, &retLen);

  memcpy(SessionKey, &Digest, SessionKeyLength);
}

