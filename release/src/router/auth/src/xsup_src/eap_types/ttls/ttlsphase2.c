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
 * EAPTTLS Phase 2 Function implementations
 *
 * File: ttlsphase2.c
 *
 * Authors: Chris.Hessing@utah.edu
 *
 * $Id: ttlsphase2.c,v 1.1.1.1 2007/08/06 10:04:43 root Exp $
 * $Date: 2007/08/06 10:04:43 $
 * $Log: ttlsphase2.c,v $
 * Revision 1.1.1.1  2007/08/06 10:04:43  root
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
 * Revision 1.17  2004/04/26 20:51:15  chessing
 *
 * Patch to attempt to fix the init_interface_* errors reported on the list.  Removed password clearing on failed authentication attempts.  Password clearing currently has some issues that will prevent it from being in the 1.0 stable.
 *
 * Revision 1.16  2004/04/14 21:09:33  chessing
 *
 * Finished up extra error checking code.  Added ability to have passwords removed from memory on an authentication failure, so that a new password can be entered.  However, this feature has been disabled at this point due to a few small issues.  It will probably show up in 1.1. ;)  (It just isn't stable enough right now.)
 *
 * Revision 1.15  2004/04/13 22:13:46  chessing
 *
 * Additional error checking in all eap methods.
 *
 * Revision 1.14  2004/04/12 18:43:44  chessing
 *
 * A few small cosmetic fixups.
 *
 * Revision 1.13  2004/04/07 22:23:13  chessing
 *
 * Fixed a segfault when a phase 2 method wasn't defined for TTLS.  Also, fixed an issue with TTLS authentication with Funk's Steel-Belted Radius.  The Funk Server would claim that we send a connection termination message.  However, the issue was that we were sending a length value in our encrypted TLS packets, and it didn't like this.  (I am not sure if Funk uses the Microsoft Crypto Provider, but it may be a strange behavior in MCP.)
 *
 * Revision 1.12  2004/04/06 20:31:27  chessing
 *
 * PEAP NOW WORKS WITH IAS!!!!!! (Thanks to help from Matthew Gast!! (We love you! ;))  Also, added patches from yesterday's testing at iLabs, including some keying fixes, some segfault fixes, and a few other misc. issues.  iLabs testing has been worth it!
 *
 * Revision 1.11  2004/03/26 09:34:26  galimorerpg
 * Fixed a nasty bug where we would try to execute code @ 0x0 with TTLS phase 2.
 *
 * This fix adds a phase2 "bogus" function call that prints out an error message
 * and exits xsupplicant instead of crashing.
 *
 * Revision 1.10  2004/03/22 05:33:48  chessing
 * Fixed some potential issues with the example config in etc.  Fixed several memory leaks in various locations.  Re-tested all EAP types except SIM/OTP/GTC/LEAP.  (Those test will happen this next week.) Getting close to a 1.0pre release!
 *
 * Revision 1.9  2004/03/19 23:43:57  chessing
 *
 * Lots of changes.  Changed the password prompting code to no longer require the EAP methods to maintain their own stale frame buffer.  (Frame buffer pointers should be moved out of generic_eap_data before a final release.)  Instead, EAP methods should set need_password in generic_eap_data to 1, along with the variables that identify the eap type being used, and the challenge data (if any -- only interesting to OTP/GTC at this point).  Also fixed up xsup_set_pwd.c, and got it back in CVS.  (For some reason, it was in limbo.)  Added xsup_monitor under gui_tools/cli.  xsup_monitor will eventually be a cli program that will monitor XSupplicant (running as a daemon) and display status information, and request passwords when they are not in the config.
 *
 * Revision 1.8  2004/03/17 21:21:41  chessing
 *
 * Hopefully xsup_set_pwd is in the right place now. ;)  Added the functions needed for xsupplicant to request a password from a GUI client.  (Still needs to be tested.)  Updated TTLS and PEAP to support password prompting.  Fixed up curState change in statemachine.c, so it doesn't print [ALL] in front of the current state.
 *
 * Revision 1.7  2004/01/20 03:44:32  chessing
 *
 * A couple of small updates.  TTLS now uses the correct phase 2 type as defined by the config file.  Setting dest_mac now works, and has the desired results.  One small fix to EAP-SIM.
 *
 * Revision 1.6  2004/01/17 21:16:16  chessing
 *
 * Various segfault fixes.  PEAP now works correctly again.  Some new error checking in the tls handlers.  Fixes for the way we determine if we have changed ESSIDs.  We now quit when we don't have a config, or when the config is bad. Added code to check and see if a frame is in the queue, and don't sleep if there is.  "Fixed" ID issue by inheriting the ID from the parent where needed.  However, assigning an ID inside of a handler will override the parent ID.  This could cause problems with some EAP types.  We should add a "username" field to PEAP to allow configuration of the inner EAP identity.
 *
 * Revision 1.5  2004/01/13 01:55:56  chessing
 *
 * Major changes to EAP related code.  We no longer pass in an interface_data struct to EAP handlers.  Instead, we hand in a generic_eap_data struct which containsnon-interface specific information.  This will allow EAP types to be reused as phase 2 type easier.  However, this new code may create issues with EAP types that make use of the identity in the eap type.  Somehow, the identity value needs to propigate down to the EAP method.  It currently does not.  This should be any easy fix, but more testing will be needed.
 *
 * Revision 1.4  2004/01/06 23:35:08  chessing
 *
 * Fixed a couple known bugs in SIM.  Config file support should now be in place!!! But, because of the changes, PEAP is probably broken.  We will need to reconsider how the phase 2 piece of PEAP works.
 *
 * Revision 1.3  2003/12/07 06:20:20  chessing
 *
 * Changes to deal with new config file style.  Beginning of IPC code.
 *
 * Revision 1.2  2003/11/29 03:50:04  chessing
 *
 * Added NAK code, EAP Type checking, split out daemon config from user config, added Display of EAP-Notification text, revamped phase 2 selection method for TTLS.
 *
 * Revision 1.1.1.1  2003/11/19 04:13:26  chessing
 * New source tree
 *
 *
 *******************************************************************/

#include <inttypes.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdio.h>
#include <ctype.h>
#include <netinet/in.h>
#include <openssl/ssl.h>
#ifdef RTL_TTLS_MD5_CLIENT
#include "xsup_err.h"
#include "../md5/eapmd5.h"
#endif
#include "config.h"
#include "profile.h"
#include "eap.h"
#include "interactive.h"
#include "../tls/tls_crypt.h"
#include "xsup_debug.h"
#include "../mschapv2/mschapv2.h"
#include "ttlsphase2.h"


// A few numbers from the radius dictionary. 8-)
#define USER_NAME_AVP        1
#define USER_PASSWORD_AVP    2
#define CHAP_PASSWORD_AVP    3
#define CHAP_CHALLENGE_AVP   60
#ifdef RTL_TTLS_MD5_CLIENT
#define EAP_MESSAGE          79
#endif


// Defines for MS-CHAP values also from the dictionary.
#define MS_VENDOR_ATTR       311
#define MS_CHAP_RESPONSE     1
#define MS_CHAP_CHALLENGE    11
#define MS_CHAP2_RESPONSE    25

#define MANDITORY_FLAG       0x40
#define VENDOR_FLAG          0x80
#define TTLS_CHALLENGE       "ttls challenge"    // Need to generate implied challenge.
#define TTLS_CHALLENGE_SIZE  14

#define TTLS_PHASE2_DEBUG    1

uint32_t avp_code;
uint32_t bitmask_avp_len;

struct phase2_handler {
  char *phase2name;
#ifdef RTL_TTLS_MD5_CLIENT
  void (*phase2handler)(struct generic_eap_data *, char *, int , char *, int *);
#else
  void (*phase2handler)(struct generic_eap_data *, char *, int *);
#endif
  ttls_phase2_type phase2type;
};

struct phase2_handler phase2types[] = {
  {"UNDEFINED", ttls_do_bogus, TTLS_PHASE2_UNDEFINED},
  {"PAP", ttls_do_pap, TTLS_PHASE2_PAP},
  {"CHAP", ttls_do_chap, TTLS_PHASE2_CHAP},
  {"MSCHAP", ttls_do_mschap, TTLS_PHASE2_MSCHAP},
  {"MSCHAPV2", ttls_do_mschapv2, TTLS_PHASE2_MSCHAPV2},
#ifdef RTL_TTLS_MD5_CLIENT
  {"EAP_MD5", ttls_do_eap_md5, TTLS_PHASE2_EAP_MD5},
#endif
  {NULL, ttls_do_bogus, -1}
};

// This is from section 10.1 of the TTLS RFC.
char *implicit_challenge(struct generic_eap_data *thisint)
{
  if (!thisint)
    {
      debug_printf(DEBUG_NORMAL, "Invalid structure passed to implicit_challenge()!\n");
      return NULL;
    }

  return tls_crypt_gen_keyblock(thisint, TTLS_CHALLENGE, TTLS_CHALLENGE_SIZE);
}

void build_avp(uint32_t avp_value, uint32_t avp_vendor, uint64_t avp_flags, uint8_t *in_value, uint64_t in_value_len, uint8_t *out_value, int *out_size)
{
  int avp_padded;
  uint32_t avp_vendor_stuff;

  avp_code = htonl(avp_value);
  avp_vendor_stuff = htonl(avp_vendor);

  if (avp_vendor != 0) 
    {
      in_value_len = in_value_len +4;
    }

  if ((in_value_len % 4) != 0)
    {
      avp_padded = (in_value_len + (4 - (in_value_len % 4)));
    } else {
      avp_padded = in_value_len;
    }
  bitmask_avp_len = htonl((avp_flags << 24) + in_value_len + 8);

  bzero(out_value, avp_padded+12);
  memcpy(&out_value[0], &avp_code, 4);
  memcpy(&out_value[4], &bitmask_avp_len, 4);
  if (avp_vendor != 0)
    {
      memcpy(&out_value[8], &avp_vendor_stuff, 4);
      memcpy(&out_value[12], in_value, in_value_len);
      *out_size = avp_padded+8;
    } else {
      memcpy(&out_value[8], in_value, in_value_len);
      *out_size = avp_padded+8;
    }
}

#ifdef RTL_TTLS_MD5_CLIENT
void ttls_do_mschapv2(struct generic_eap_data *thisint,  char *indata, int insize,char *out_data, int *out_size)
#else
void ttls_do_mschapv2(struct generic_eap_data *thisint, char *out_data, int *out_size)
#endif
{
  u_char mschap_challenge[16], mschap_answer[50];
  u_char mschap_result[24];
  char *username = NULL, *password = NULL, *challenge = NULL;
  int avp_offset, avp_out_size, username_size, id;
  struct config_mschapv2 *phase2data;
  struct config_eap_ttls *outerdata;
  struct config_ttls_phase2 *userdata;

  if ((!thisint) || (!thisint->eap_conf_data))
    {
      debug_printf(DEBUG_NORMAL, "Invalid configuration structure in ttls_do_mschapv2().\n");
      return;
    }

  outerdata = (struct config_eap_ttls *)thisint->eap_conf_data;

  if (!outerdata->phase2)
    {
      debug_printf(DEBUG_NORMAL, "Invalid phase 2 data.\n");
      return;
    }

  userdata = (struct config_ttls_phase2 *)outerdata->phase2;

  while ((userdata != NULL) && (userdata->phase2_type != TTLS_PHASE2_MSCHAPV2))
    {
      userdata = userdata->next;
    }


  if (!userdata->phase2_data)
    {
      debug_printf(DEBUG_NORMAL, "Invalid phase 2 config in MS-CHAPv2!\n");
      return;
    }

  phase2data = (struct config_mschapv2 *)userdata->phase2_data;

  // Check that we have a password.
  if ((phase2data->password == NULL) && (thisint->tempPwd == NULL))
    {
      debug_printf(DEBUG_AUTHTYPES, "Phase 2 doesn't appear to have a password.  Requesting one!\n");
      thisint->need_password = 1;
      thisint->eaptype = strdup("EAP-TTLS Phase 2 (MS-CHAPv2)");
      thisint->eapchallenge = NULL;
      *out_size = 0;
      return;
    }

  if ((phase2data->password == NULL) && (thisint->tempPwd != NULL))
    {
      phase2data->password = thisint->tempPwd;
      thisint->tempPwd = NULL;
    }

  if (phase2data->username == NULL)
    {
      username = thisint->identity;
    } else {
      username = phase2data->username;
    }
  username_size = strlen(username);

  // Send the Username AVP
  build_avp(USER_NAME_AVP, 0, MANDITORY_FLAG, username, username_size, out_data, &avp_out_size);

  avp_offset = avp_out_size;

  challenge = implicit_challenge(thisint);

  if (challenge == NULL)
    {
      debug_printf(DEBUG_NORMAL, "Invalid implicit challenge in MS-CHAPv2!\n");
      return;
    }

  memcpy(&mschap_challenge, challenge, 16);
  id = challenge[17];

  // Send the MS-CHAP AVP
  build_avp(MS_CHAP_CHALLENGE, MS_VENDOR_ATTR, (MANDITORY_FLAG | VENDOR_FLAG), (char *)&mschap_challenge, 16, &out_data[avp_offset], &avp_out_size);

  avp_offset+=avp_out_size;

  bzero(&mschap_answer, 50);  // Clear it out.
  memcpy(&mschap_answer, &mschap_challenge, 16);

  // The first 24 bytes should be left as 0s.
  password = phase2data->password;    // Get our password.

  GenerateNTResponse((char *)&mschap_challenge, (char *)&mschap_challenge, username, password, (char *)&mschap_result);

  mschap_answer[0] = id;
  mschap_answer[1] = 0;
  memcpy(&mschap_answer[2], &mschap_challenge, 16);
  memcpy(&mschap_answer[26], &mschap_result, 24);

  build_avp(MS_CHAP2_RESPONSE, MS_VENDOR_ATTR, (MANDITORY_FLAG | VENDOR_FLAG), (char *)&mschap_answer, 50, &out_data[avp_offset], &avp_out_size);
  avp_offset+=avp_out_size;
  *out_size = avp_offset;
}


// For phase 2 MS-CHAP, we get 8 bytes implicit challenge, and 1 byte for ID.
#ifdef RTL_TTLS_MD5_CLIENT
void ttls_do_mschap(struct generic_eap_data *thisint,  char *indata, int insize,char *out_data, int *out_size)
#else
void ttls_do_mschap(struct generic_eap_data *thisint, char *out_data, int *out_size)
#endif
{
  u_char mschap_challenge[8], mschap_answer[49];
  u_char mschap_result[24];
  char *username = NULL, *password = NULL, *challenge = NULL;
  int avp_offset, avp_out_size, username_size, id;
  struct config_ttls_phase2 *userdata;
  struct config_eap_ttls *outerdata;
  struct config_mschap *phase2data;

  if ((!thisint) || (!thisint->eap_conf_data))
    {
      debug_printf(DEBUG_NORMAL, "Invalid configuration struct in MS-CHAP!\n");
      return;
    }

  outerdata = (struct config_eap_ttls *)thisint->eap_conf_data;

  if (!outerdata)
    {
      debug_printf(DEBUG_NORMAL, "Invalid configuration data in MS-CHAP!\n");
      return;
    }

  userdata = (struct config_ttls_phase2 *)outerdata->phase2;

  while ((userdata != NULL) && (userdata->phase2_type != TTLS_PHASE2_MSCHAP))
    {
      userdata = userdata->next;
    }

  phase2data = (struct config_mschap *)userdata->phase2_data;

  // Check that we have a password.
  if ((phase2data->password == NULL) && (thisint->tempPwd == NULL))
    {
      debug_printf(DEBUG_AUTHTYPES, "Phase 2 doesn't appear to have a password.  Requesting one!\n");
      thisint->need_password = 1;
      thisint->eaptype = strdup("EAP-TTLS Phase 2 (MS-CHAP)");
      thisint->eapchallenge = NULL;
      *out_size = 0;
      return;
    }

  if ((phase2data->password == NULL) && (thisint->tempPwd != NULL))
    {
      phase2data->password = thisint->tempPwd;
      thisint->tempPwd = NULL;
    }

  if (phase2data->username == NULL)
    {
      username = thisint->identity;
    } else {
      username = phase2data->username;
    }
  username_size = strlen(username);

  // Send the Username AVP
  build_avp(USER_NAME_AVP, 0, MANDITORY_FLAG, username, username_size, out_data, &avp_out_size);

  avp_offset = avp_out_size;

  challenge = implicit_challenge(thisint);

  if (challenge == NULL)
    {
      debug_printf(DEBUG_NORMAL, "Invalid implicit challenge!\n");
      return;
    }

  memcpy((char *)&mschap_challenge[0], challenge, 8);
  id = challenge[9];

  // Send the MS-CHAP AVP
  build_avp(MS_CHAP_CHALLENGE, MS_VENDOR_ATTR, (MANDITORY_FLAG | VENDOR_FLAG), (char *)&mschap_challenge, 8, &out_data[avp_offset], &avp_out_size);

  avp_offset+=avp_out_size;

  bzero((char *)&mschap_answer[0], 49);  // Clear it out.

  password = phase2data->password;    // Get our password.

  NtChallengeResponse((char *)&mschap_challenge, password, (char *)&mschap_result);

  mschap_answer[0] = id;
  mschap_answer[1] = 1; // Use NT Style Passwords.
  memcpy((char *)&mschap_answer[26], (char *)&mschap_result, 24);

  build_avp(MS_CHAP_RESPONSE, MS_VENDOR_ATTR, (MANDITORY_FLAG | VENDOR_FLAG), (char *)&mschap_answer, 50, &out_data[avp_offset], &avp_out_size);
  avp_offset+=avp_out_size;

  *out_size = avp_offset;
} 

// For phase 2 CHAP, we need to get an implicit_challenge from the phase 1,
// and use the first 16 bytes for challenge, and the 17th byte as the ID.
// Then, to find the CHAP password hash, we find MD5(id + password + 
// challenge).  Then, we need to send 3 AVPs back to the authenticator.
// The username, challenge, and password AVPs.  Where the challenge is the
// 16 bytes from the implicit challenge. 
#ifdef RTL_TTLS_MD5_CLIENT
void ttls_do_chap(struct generic_eap_data *thisint, char *indata, int insize, char *out_data, int *out_size)
#else
void ttls_do_chap(struct generic_eap_data *thisint, char *out_data, int *out_size)
#endif
{
  u_char *challenge = NULL, *tohash = NULL;
  u_char *user_passwd = NULL;
  u_char chap_challenge[18], chap_hash[17];
  uint8_t session_id;
  int username_size, avp_out_size;
  int avp_offset, md5_length, hashlen;
  EVP_MD_CTX *ctx=NULL;
  char *username = NULL;
  struct config_ttls_phase2 *userdata;
  struct config_eap_ttls *outerdata;
  struct config_chap *phase2data;

  if ((!thisint) || (!thisint->eap_conf_data))
    {
      debug_printf(DEBUG_NORMAL, "Invalid structure passed in to ttls_do_chap()!\n");
      return;
    }

  outerdata = (struct config_eap_ttls *)thisint->eap_conf_data;

  if (!outerdata->phase2)
    {
      debug_printf(DEBUG_NORMAL, "Invalid phase 2 data in ttls_do_chap()!\n");
      return;
    }

  userdata = (struct config_ttls_phase2 *)outerdata->phase2;

  while ((userdata != NULL) && (userdata->phase2_type != TTLS_PHASE2_CHAP))
    {
      userdata = userdata->next;
    }

  phase2data = (struct config_chap *)userdata->phase2_data;

  // Check that we have a password.
  if ((phase2data->password == NULL) && (thisint->tempPwd == NULL))
    {
      debug_printf(DEBUG_AUTHTYPES, "Phase 2 doesn't appear to have a password.  Requesting one!\n");
      thisint->need_password = 1;
      thisint->eaptype = strdup("EAP-TTLS Phase 2 (CHAP)");
      thisint->eapchallenge = NULL;
      *out_size = 0;
      return;
    }

  if ((phase2data->password == NULL) && (thisint->tempPwd != NULL))
    {
      phase2data->password = thisint->tempPwd;
      thisint->tempPwd = NULL;
    }

  if (phase2data->username == NULL)
    {
      username = thisint->identity;
    } else {
      username = phase2data->username;
    }
  username_size = strlen(username);
  build_avp(USER_NAME_AVP, 0, MANDITORY_FLAG, username, username_size, out_data, &avp_out_size);

  avp_offset = avp_out_size;

  // Get the implicit challenge.
  challenge = implicit_challenge(thisint);
  if (challenge == NULL)
    {
      debug_printf(DEBUG_NORMAL, "Invalid implicit challenge in ttls_do_chap()!\n");
      return;
    }

  memcpy(&chap_challenge, challenge, 16);
  session_id = challenge[16];

  // Build the password hash.
  ctx = (EVP_MD_CTX *)malloc(sizeof(EVP_MD_CTX));
  if (ctx == NULL)
    {
      debug_printf(DEBUG_NORMAL, "Error with malloc of ctx in ttls_do_chap().\n");
      return;
    }

  user_passwd = phase2data->password;

  tohash = (char *)malloc(1+16+strlen(user_passwd));
  if (tohash == NULL)
    {
      debug_printf(DEBUG_NORMAL, "Error with malloc of \"tohash\" in ttls_do_chap().\n");
      return;
    }

  tohash[0] = session_id;
  memcpy(&tohash[1], user_passwd, strlen(user_passwd));
  memcpy(&tohash[1+strlen(user_passwd)], &chap_challenge, 16);
  hashlen = 1+strlen(user_passwd)+16;

  EVP_DigestInit(ctx, EVP_md5());
  EVP_DigestUpdate(ctx, tohash, hashlen);
  EVP_DigestFinal(ctx, (char *)&chap_hash[1], (int *)&md5_length);
  
  if (md5_length != 16)  // We didn't get back a valid hash!
    {
      debug_printf(DEBUG_NORMAL, "CHAP (MD5) hash length was not 16!\n");
    }
  chap_hash[0]=session_id;

  build_avp(CHAP_PASSWORD_AVP, 0, MANDITORY_FLAG, chap_hash, 17, &out_data[avp_offset], &avp_out_size);

  avp_offset += avp_out_size;

  build_avp(CHAP_CHALLENGE_AVP, 0, MANDITORY_FLAG, (char *)&chap_challenge, 16, &out_data[avp_offset], &avp_out_size);

  if (tohash != NULL)
    {
      free(tohash);
      tohash = NULL;
    }

  if (ctx != NULL)
    {
      free(ctx);
      ctx = NULL;
    }

  *out_size = avp_offset+avp_out_size;
}
#ifdef RTL_TTLS_MD5_CLIENT
void ttls_do_bogus(struct generic_eap_data *thisint, char *indata, int insize, char *out_data, int *out_size)
#else
void ttls_do_bogus(struct generic_eap_data *thisint, char *out_data, int *out_size)
#endif
{
  debug_printf(DEBUG_NORMAL, "Attempting to call an undefined Phase 2!\n");

  // We probably really don't want to die here.  We need to reconsider.
  exit(255);
}
#ifdef RTL_TTLS_MD5_CLIENT
void ttls_do_pap(struct generic_eap_data *thisint,  char *indata, int insize,char *out_data, int *out_size)
#else
void ttls_do_pap(struct generic_eap_data *thisint, char *out_data, int *out_size)
#endif
{
  char *tempbuf, *username;
  int passwd_size, avp_out_size, avp_offset;
  struct config_ttls_phase2 *userdata;
  struct config_eap_ttls *outerdata;
  struct config_pap *phase2data;
  if ((!thisint) || (!thisint->eap_conf_data))
    {
      debug_printf(DEBUG_NORMAL, "Invalid structure passed in to ttls_do_pap()!\n");
      return;
    }

  outerdata = (struct config_eap_ttls *)thisint->eap_conf_data;

  if (!outerdata->phase2)
    {
      debug_printf(DEBUG_NORMAL, "Invalid phase 2 data in ttls_do_pap()!\n");
      return;
    }

  userdata = (struct config_ttls_phase2 *)outerdata->phase2;

  while ((userdata != NULL) && (userdata->phase2_type != TTLS_PHASE2_PAP))
    {
      userdata =userdata->next;
    }

  phase2data = (struct config_pap *)userdata->phase2_data;

  // Check that we have a password.
  if ((phase2data->password == NULL) && (thisint->tempPwd == NULL))
    {
      debug_printf(DEBUG_AUTHTYPES, "Phase 2 doesn't appear to have a password.  Requesting one!\n");
      thisint->need_password = 1;
      thisint->eaptype = strdup("EAP-TTLS Phase 2 (PAP)");
      thisint->eapchallenge = NULL;
      *out_size = 0;
      return;
    }

  if ((phase2data->password == NULL) && (thisint->tempPwd != NULL))
    {
      phase2data->password = thisint->tempPwd;
      thisint->tempPwd = NULL;
    }

  if (phase2data->username == NULL)
    {
      username = thisint->identity;
    } else {
      username = phase2data->username;
    }

  debug_printf(DEBUG_AUTHTYPES, "Phase 2 Username : %s\n",username);

  avp_offset = 0;

  build_avp(USER_NAME_AVP, 0, MANDITORY_FLAG, username, 
	    strlen(username), out_data, &avp_out_size);

  avp_offset += avp_out_size;

  // We have the username AVP loaded, so it's time to build the password AVP.
  passwd_size = (strlen(phase2data->password) + 
		 (16-(strlen(phase2data->password) % 16)));

  tempbuf = (char *)malloc(passwd_size);
  if (tempbuf == NULL)
    {
      debug_printf(DEBUG_NORMAL, "Error with malloc of tempbuf in ttls_do_pap().\n");
      return;
    }

  bzero(tempbuf, passwd_size);
  memcpy(tempbuf, phase2data->password, strlen(phase2data->password));

  build_avp(USER_PASSWORD_AVP, 0, MANDITORY_FLAG, tempbuf, passwd_size, &out_data[avp_offset], &avp_out_size);

  *out_size = avp_offset + avp_out_size;
  
  if (tempbuf != NULL)
    {
      free(tempbuf);
      tempbuf = NULL;
    }

  debug_printf(DEBUG_AUTHTYPES, "Returning from do_pap :\n");
  debug_hex_dump(DEBUG_AUTHTYPES, out_data, *out_size);
}

// We don't do anything with the "in" stuff for now..
void ttls_do_phase2(struct generic_eap_data *thisint, char *in, int in_size, char *out, int *out_size)
{
  int toencsize, i;
  char *toencout;
  struct config_eap_ttls *userdata;
  struct config_ttls_phase2 *phase2data;
 #ifdef RTL_TTLS_MD5_CLIENT
  int decrsize = 0;
  char decr_data[1550];
 #endif
  if ((!thisint) || (!thisint->eap_conf_data) || (!out))
    {
      debug_printf(DEBUG_NORMAL, "Invalid data pased in to ttls_do_phase2()!\n");
      return;
    }

  userdata = (struct config_eap_ttls *)thisint->eap_conf_data;

  if (!userdata->phase2)
    {
      debug_printf(DEBUG_NORMAL, "Invalid userdata in ttls_do_phase2()!\n");
      return;
    }

  phase2data = (struct config_ttls_phase2 *)userdata->phase2;

#ifdef RTL_TTLS_MD5_CLIENT
   if ((in_size > 0) && (in[0] != 0x14))
    {
      // We have something to decrypt!
      tls_crypt_decrypt(thisint, (uint8_t *) in, in_size, (uint8_t *) decr_data, &decrsize);

      debug_printf(DEBUG_AUTHTYPES, "Decrypted Inner (%d) : \n", in_size);
      //debug_hex_dump(DEBUG_AUTHTYPES, (uint8_t *) decr_data, decrsize);



      if ((decr_data[0] == 0x00) && (userdata->phase2_type != TTLS_PHASE2_EAP_MD5))
	{
	  debug_printf(DEBUG_AUTHTYPES, "(Hack) Acking for second inner phase "
		       "packet!\n");
	  out[0] = 0x00;  // ACK
	  *out_size = 1;
	  return XENONE;
	}
    }
#endif
	toencout = (char *)malloc(1550);
  if (toencout == NULL)
  {
      debug_printf(DEBUG_NORMAL, "Couldn't allocate memory needed for encryption!\n");
      return;
  }
  toencsize = 1550;

  // We need to see what phase 2 method we should use.
  i = 0;

  while ((phase2types[i].phase2type != -1) && 
	 (userdata->phase2_type != phase2types[i].phase2type))
    {
      i++;
    }
	 //printf("phase 2 type = %d\n", phase2data->phase2_type);
  if (phase2types[i].phase2type > 0)
    {
      debug_printf(DEBUG_AUTHTYPES, "Doing Phase 2 %s!\n", phase2types[i].phase2name);
#ifdef RTL_TTLS_MD5_CLIENT
      (*phase2types[i].phase2handler)(thisint, decr_data, decrsize,toencout, &toencsize);
#else
	  (*phase2types[i].phase2handler)(thisint, toencout, &toencsize);
#endif
    } else {
      debug_printf(DEBUG_NORMAL, "ERROR!  : No phase 2 TTLS method was defined!\n");
      toencsize = 0;
    }
	
  if (toencsize == 0)
    {
      *out_size = 0;
      free(toencout);
      return;
    }

  tls_crypt_encrypt_nolen(thisint, toencout, toencsize, out, out_size);
  free(toencout);

  debug_printf(DEBUG_AUTHTYPES, "Returning from (TTLS) do_phase2 : \n");
  debug_hex_dump(DEBUG_AUTHTYPES, out, *out_size);
}


void ttls_phase2_failed(struct generic_eap_data *thisint)
{
  struct config_eap_ttls *userdata;
  /*
  struct config_ttls_phase2 *phase2data;
  struct config_pap *papphase2;
  struct config_chap *chapphase2;
  struct config_mschap *mschapphase2;
  struct config_mschapv2 *mschapv2phase2;
  int i=0;
  */

  if ((!thisint) || (!thisint->eap_conf_data))
    {
      debug_printf(DEBUG_NORMAL, "Invalid data passed to ttls_phase2_failed()!\n");
      return;
    }

  userdata = (struct config_eap_ttls *)thisint->eap_conf_data;

  if (!userdata->phase2)
    {
      debug_printf(DEBUG_NORMAL, "Invalid userdata in ttls_phase2_failed()!\n");
      return;
    }
  /*
  phase2data = (struct config_ttls_phase2 *)userdata->phase2;

  while ((phase2types[i].phase2type != -1) && 
	 (userdata->phase2_type != phase2types[i].phase2type))
    {
      i++;
    }

  if (!phase2data->phase2_data)
    {
      debug_printf(DEBUG_NORMAL, "No phase 2 user data!\n");
      return;
    }

  if (thisint->tempPwd != NULL)
    {
      debug_printf(DEBUG_AUTHTYPES, "Freeing tempPwd!\n");
      free(thisint->tempPwd);
      thisint->tempPwd = NULL;
    }

  switch(phase2types[i].phase2type)
    {
    case TTLS_PHASE2_PAP:
      papphase2 = (struct config_pap *)phase2data->phase2_data;
      if (papphase2->password)
	{
	  debug_printf(DEBUG_NORMAL, "Freed inner PAP password!\n");
	  free(papphase2->password);
	  papphase2->password = NULL;
	}
      break;

    case TTLS_PHASE2_CHAP:
      chapphase2 = (struct config_chap *)phase2data->phase2_data;
      if (chapphase2->password)
	{
	  free(chapphase2->password);
	  chapphase2->password = NULL;
	}
      break;

    case TTLS_PHASE2_MSCHAP:
      mschapphase2 = (struct config_mschap *)phase2data->phase2_data;
      if (mschapphase2->password)
	{
	  free(mschapphase2->password);
	  mschapphase2->password = NULL;
	}
      break;

    case TTLS_PHASE2_MSCHAPV2:
      mschapv2phase2 = (struct config_mschapv2 *)phase2data->phase2_data;
      if (mschapv2phase2->password)
	{
	  free(mschapv2phase2->password);
	  mschapv2phase2->password = NULL;
	}
      break;

    default :
      // Do nothing for now....
      break;
    }
  */
}
#ifdef RTL_TTLS_MD5_CLIENT 
/**************************************************************
 *
 * Do an EAP-MD5 authentication.  This could easily be converted to a 
 * generic EAP authentication handler, with little effort.  (There would
 * be more effort involved in the configuration parse code. ;)
 *
 **************************************************************/
void ttls_do_eap_md5(struct generic_eap_data *thisint, char *indata, 
		     int insize, char *out_data, int *out_size)
{
  int eapid = 1;
  char eapdata[1500];  // Temporary buffer to store EAP response.
  int eapsize = 0;
  char *identity;
  struct config_eap_md5 *md5data;
  struct config_eap_ttls *ttlsdata;
  struct config_ttls_phase2 *phase2data;
  struct config_eap_method eapmethod;

  ttlsdata = (struct config_eap_ttls *)thisint->eap_conf_data;
  if (!ttlsdata)
    {
      debug_printf(DEBUG_NORMAL, "Error gathering TTLS data.\n");
      return;
    }

  phase2data = (struct config_ttls_phase2 *)ttlsdata->phase2;
  if (phase2data == NULL)
    {
      debug_printf(DEBUG_NORMAL, "No phase 2 data available!\n");
      return;
    }

  while ((phase2data != NULL) && 
	 (phase2data->phase2_type != TTLS_PHASE2_EAP_MD5))
    {
      phase2data = phase2data->next;
    }

  if (!phase2data->phase2_data)
    {
      debug_printf(DEBUG_NORMAL, "Invalid phase 2 config in MS-CHAPv2!\n");
      return;
    }

  md5data = (struct config_eap_md5 *)phase2data->phase2_data;
  if (!md5data)
    {
      debug_printf(DEBUG_NORMAL, "Error gathering MD5 data.\n");
      return;
    }

  // DO NOT free *identity!  It points to memory that will be freed
  // later.
  if (md5data->username)
    {
      identity = md5data->username;
    }
  else
    {
      identity = thisint->identity;
    }

  if (insize == 0)
    {
    
      eap_ttls_md5_request_id(identity, eapid, (char *) &eapdata, &eapsize);

      debug_printf(DEBUG_INT, "EAP Identity dump (%d) : \n", eapsize);
     // debug_hex_dump(DEBUG_INT, eapdata, eapsize);

      build_avp(EAP_MESSAGE, 0, MANDITORY_FLAG, (uint8_t *) eapdata, eapsize, 
		(uint8_t *) out_data, out_size);

      debug_printf(DEBUG_INT, "EAP Identity AVP dump (%d) : \n", (*out_size));
     // debug_hex_dump(DEBUG_INT, out_data, (*out_size));
      return;
    }

  // Then process it.
  debug_printf(DEBUG_NORMAL, "(TTLS phase 2 EAP) In data (%d) : \n", insize);
 // debug_hex_dump(DEBUG_NORMAL, indata, insize);

  // Skip past the AVP data.
  // XXX Clean this up, we should verify that it is really the EAP AVP!
  indata+=8;
  insize -= 8;

  debug_printf(DEBUG_NORMAL, "(TTLS phase 2 EAP) sans AVP (%d) : \n", insize);
  //debug_hex_dump(DEBUG_NORMAL, indata, insize);

  if (eap_create_active_method(&ttlsdata->phase2_eap_data,
			       identity,
			       thisint->tempPwd,
			       thisint->intName) != 0)
    {
      debug_printf(DEBUG_NORMAL, "Couldn't build active method!  Phase 2 "
		   "authentication will not happen!\n");
      return;
    }

  // We need to create a config_eap_method struct to pass in.
  eapmethod.method_num = EAP_TYPE_MD5; 
  eapmethod.method_data = (void *)md5data;
  eapmethod.next = NULL;

  eap_ttls_md5_request_auth(ttlsdata->phase2_eap_data, &eapmethod, (char *) indata, 
		   insize, (char *) eapdata, &eapsize);
  debug_printf(DEBUG_INT, "Response data (%d) :\n", eapsize);
  //debug_hex_dump(DEBUG_INT, eapdata, eapsize);

  build_avp(EAP_MESSAGE, 0, MANDITORY_FLAG, (uint8_t *) eapdata, eapsize,
	    (uint8_t *) out_data, out_size);
  debug_printf(DEBUG_INT, "TTLS Phase 2 EAP dump (%d) : \n", (*out_size));
  //debug_hex_dump(DEBUG_INT, out_data, (*out_size));
}
#endif


