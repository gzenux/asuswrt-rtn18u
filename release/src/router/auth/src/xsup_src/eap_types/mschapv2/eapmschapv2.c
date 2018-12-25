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
 * EAP-MSCHAPv2 Function implementations
 * 
 * File: eapmschapv2.c
 *
 * Authors: Chris.Hessing@utah.edu
 *
 * $Id: eapmschapv2.c,v 1.1.1.1 2007/08/06 10:04:42 root Exp $
 * $Date: 2007/08/06 10:04:42 $
 * $Log: eapmschapv2.c,v $
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
 * Revision 1.20  2004/04/26 20:51:14  chessing
 *
 * Patch to attempt to fix the init_interface_* errors reported on the list.  Removed password clearing on failed authentication attempts.  Password clearing currently has some issues that will prevent it from being in the 1.0 stable.
 *
 * Revision 1.19  2004/04/13 22:13:29  chessing
 *
 * Additional error checking in all eap methods.
 *
 * Revision 1.18  2004/04/06 20:31:26  chessing
 *
 * PEAP NOW WORKS WITH IAS!!!!!! (Thanks to help from Matthew Gast!! (We love you! ;))  Also, added patches from yesterday's testing at iLabs, including some keying fixes, some segfault fixes, and a few other misc. issues.  iLabs testing has been worth it!
 *
 * Revision 1.17  2004/04/05 17:19:17  chessing
 *
 * Added additional checks against pointers to try to help prevent segfaults.  (This still needs to be completed.)  Fixed a problem with PEAP where a NULL input packet would result in a huge unencrypted packet, and a segfault.  (This was triggered when using one of the gui password tools.  When the password was in the config file, it wouldn't be triggered.)
 *
 * Revision 1.16  2004/04/02 20:50:20  chessing
 *
 * Attempt to fix PEAP with IAS. At this point, we can get through the TLS piece of the PEAP authentication, and successfully attempt a phase 2 authentication.  But, for some reason MS-CHAPv2 is failing when used with IAS.  (But at least we are one step closer!)  Also, removed the des pieces that were needed for eap-mschapv2, since we can use the OpenSSL routines instead.  The proper way to handle DES was found while looking at the CVS code for wpa_supplicant.  The fix for phase 1 of PEAP was found while looking at the commit notes for wpa_supplicant.  (wpa_supplicant is part of hostap, and is written/maintained by Jouni Malinen.)
 *
 * Revision 1.15  2004/03/22 05:33:47  chessing
 * Fixed some potential issues with the example config in etc.  Fixed several memory leaks in various locations.  Re-tested all EAP types except SIM/OTP/GTC/LEAP.  (Those test will happen this next week.) Getting close to a 1.0pre release!
 *
 * Revision 1.14  2004/03/19 23:43:56  chessing
 *
 * Lots of changes.  Changed the password prompting code to no longer require the EAP methods to maintain their own stale frame buffer.  (Frame buffer pointers should be moved out of generic_eap_data before a final release.)  Instead, EAP methods should set need_password in generic_eap_data to 1, along with the variables that identify the eap type being used, and the challenge data (if any -- only interesting to OTP/GTC at this point).  Also fixed up xsup_set_pwd.c, and got it back in CVS.  (For some reason, it was in limbo.)  Added xsup_monitor under gui_tools/cli.  xsup_monitor will eventually be a cli program that will monitor XSupplicant (running as a daemon) and display status information, and request passwords when they are not in the config.
 *
 * Revision 1.13  2004/02/16 05:06:00  chessing
 *
 * Added support for the deny_interfaces, and allow_interfaces options in the config file.  (We should now have support for *EVERYTHING* in the new config file format!)  Updated EAP types other than SIM to use the new password prompt/delay code.  Phase 2 of TTLS still needs to be completed, along with the code that actually notifies the GUI.
 *
 * Revision 1.12  2004/02/06 06:13:31  chessing
 *
 * Cleaned up some unneeded stuff in the configure.in file as per e-mail from Rakesh Patel.  Added all 12 patches from Jouni Malinen (Including wpa_supplicant patch, until we can add true wpa support in xsupplicant.)
 *
 * Revision 1.11  2004/01/20 05:57:05  chessing
 *
 * All EAP types except PEAP and TTLS now support having their passwords sent in via the command line program.  (This means no more gets() call in OTP!)  A config_eap_otp structure was created in config.h to support GTC/OTP.  We need to define an eap_otp and eap_gtc config section.  Since both require some kind of information be presented there are no attributes that need to be defined in their part of the configuration.
 *
 * Revision 1.10  2004/01/17 21:16:16  chessing
 *
 * Various segfault fixes.  PEAP now works correctly again.  Some new error checking in the tls handlers.  Fixes for the way we determine if we have changed ESSIDs.  We now quit when we don't have a config, or when the config is bad. Added code to check and see if a frame is in the queue, and don't sleep if there is.  "Fixed" ID issue by inheriting the ID from the parent where needed.  However, assigning an ID inside of a handler will override the parent ID.  This could cause problems with some EAP types.  We should add a "username" field to PEAP to allow configuration of the inner EAP identity.
 *
 * Revision 1.9  2004/01/15 23:45:11  chessing
 *
 * Fixed a segfault when looking for wireless interfaces when all we had was a wired interface.  Fixed external command execution so that junk doesn't end up in the processed string anymore.  Changed the state machine to call txRspAuth even if there isn't a frame to process.  This will enable EAP methods to request information from a GUI interface (such as passwords, or supply challenge information that might be needed to generate passwords).  EAP methods now must decide what to do when they are handed NULL for the pointer to the in frame.  If they don't need any more data, they should quietly exit.
 *
 * Revision 1.8  2004/01/15 01:12:45  chessing
 *
 * Fixed a keying problem (keying material wasn't being generated correctly).  Added support for global counter variables from the config file. (Such as auth_period)  Added support for executing command defined in the config file based on different events.  (Things such as what to do on reauth.)  Added the ability to roam to a different SSID.  We now check to make sure our BSSID hasn't changed, and we follow it, if it has.  Fixed a sefault when the program was terminated in certain states.  Added attempt at better garbage collection on program termination. Various small code cleanups.
 *
 * Revision 1.7  2004/01/14 05:44:48  chessing
 *
 * Added pid file support. (Very basic for now, needs to be improved a little.)  Attempted to add setup of global variables. (Need to figure out why it is segfaulting.)  Added more groundwork for IPC.
 *
 * Revision 1.6  2004/01/13 01:55:55  chessing
 *
 * Major changes to EAP related code.  We no longer pass in an interface_data struct to EAP handlers.  Instead, we hand in a generic_eap_data struct which containsnon-interface specific information.  This will allow EAP types to be reused as phase 2 type easier.  However, this new code may create issues with EAP types that make use of the identity in the eap type.  Somehow, the identity value needs to propigate down to the EAP method.  It currently does not.  This should be any easy fix, but more testing will be needed.
 *
 * Revision 1.5  2004/01/06 23:35:07  chessing
 *
 * Fixed a couple known bugs in SIM.  Config file support should now be in place!!! But, because of the changes, PEAP is probably broken.  We will need to reconsider how the phase 2 piece of PEAP works.
 *
 * Revision 1.4  2003/11/22 06:10:38  chessing
 *
 * Changes to the eap type process calls, to remove a pointless parameter.
 *
 * Revision 1.3  2003/11/21 05:09:47  chessing
 *
 * PEAP now works!
 *
 * Revision 1.2  2003/11/20 00:05:32  chessing
 *
 * EAP-MSCHAPv2 now supports generation of keys.  (New feature)
 *
 * Revision 1.1.1.1  2003/11/19 04:13:27  chessing
 * New source tree
 *
 *
 *******************************************************************/

#include <openssl/rand.h>
#include <string.h>
#include <netinet/in.h>

#include "profile.h"
#include "config.h"
#include "xsup_debug.h"
#include "xsup_err.h"
#include "frame_structs.h"
#include "eapmschapv2.h"
#include "mschapv2.h"
#include "eap.h"
#include "interactive.h"


int eapmschapv2_setup(struct generic_eap_data *thisint)
{
  struct mschapv2_vars *myvars;

  if (!thisint)
    {
      debug_printf(DEBUG_NORMAL, "Invalid interface structure passed in to eapmschapv2_setup()!\n");
      return XEMALLOC;
    }

  thisint->eap_data = (u_char *)malloc(sizeof(struct mschapv2_vars));
  if (thisint->eap_data == NULL) return XEMALLOC;
  memset(thisint->eap_data, 0, sizeof(struct mschapv2_vars));

  myvars = thisint->eap_data;

  myvars->AuthenticatorChallenge = NULL;
  myvars->PeerChallenge = NULL;
  myvars->NtResponse = NULL;
  myvars->keyingMaterial = NULL;

  return XENONE;
}

int eapmschapv2_process(struct generic_eap_data *thisint, u_char *dataoffs, 
			int insize, u_char *outframe, int *outsize)
{
  struct mschapv2_challenge *challenge;
  struct mschapv2_response *response;
  struct mschapv2_success_request *success;
  struct mschapv2_vars *myvars;
  char *username;
  int respOk;
  u_char recv[41];
  u_char NtHash[16], NtHashHash[16], MasterKey[16];
  u_char mppeSend[16], mppeRecv[16];
  struct config_eap_mschapv2 *userdata;

  if (!thisint)
    {
      debug_printf(DEBUG_NORMAL, "Invalid interface structure passed in to eapmschapv2_process()!\n");
      return XEMALLOC;
    }
  
  if (!outframe)
    {
      debug_printf(DEBUG_NORMAL, "Invalid return buffer in eapmschapv2_process()!\n");
      return XEMALLOC;
    }

  if (!thisint->eap_conf_data)
    {
      debug_printf(DEBUG_NORMAL, "No valid configuration data available for MSCHAP-V2!\n");
      return XEMALLOC;
    }

  userdata = (struct config_eap_mschapv2 *)thisint->eap_conf_data;

  if (!thisint->eap_data)
    {
      debug_printf(DEBUG_NORMAL, "Invalid state configuration in MSCHAP-V2!\n");
      return XEMALLOC;
    }

  myvars = (struct mschapv2_vars *)thisint->eap_data;

  if ((thisint->tempPwd == NULL) && (userdata->password == NULL))
    {
      thisint->need_password = 1;
      thisint->eaptype = strdup("EAP-MS-CHAPv2");
      thisint->eapchallenge = NULL;
      *outsize = 0;
      return XENONE;
    }

  // Make sure we have something to process...
  if (dataoffs == NULL) return XENONE;

  if (userdata->username == NULL)
    {
      username = thisint->identity;
    } else {
      username = userdata->username;
    }

  if ((userdata->password == NULL) && (thisint->tempPwd != NULL))
    {
      userdata->password = thisint->tempPwd;
      thisint->tempPwd = NULL;
    }

  switch ((uint8_t)dataoffs[0])
    {
    case MS_CHAPV2_CHALLENGE:
      debug_printf(DEBUG_AUTHTYPES, "(EAP-MSCHAPv2) Challenge\n");
      challenge = (struct mschapv2_challenge *)dataoffs;
      response = (struct mschapv2_response *)outframe;

      debug_printf(DEBUG_AUTHTYPES, "(EAP-MS-CHAPv2) ID : %02X\n",
		   challenge->MS_CHAPv2_ID);

      // This value should *ALWAYS* be 16!
      if (challenge->Value_Size != 0x10)
	{
	  debug_printf(DEBUG_NORMAL, "(EAP-MS-CHAPv2) Invalid Value-Size! (%d)\n", challenge->Value_Size);
	  return XEMSCHAPV2LEN;
	}

      if (myvars->AuthenticatorChallenge != NULL)
	{
	  free(myvars->AuthenticatorChallenge);
	  myvars->AuthenticatorChallenge = NULL;
	}

      myvars->AuthenticatorChallenge = (u_char *)malloc(16);
      if (myvars->AuthenticatorChallenge == NULL) return XEMALLOC;

      memcpy(myvars->AuthenticatorChallenge, &challenge->Challenge, 16);
      
      debug_printf(DEBUG_AUTHTYPES, "Authenticator Challenge : ");
      debug_hex_printf(DEBUG_AUTHTYPES, myvars->AuthenticatorChallenge, 16);

      if (myvars->PeerChallenge != NULL)
	{
	  free(myvars->PeerChallenge);
	  myvars->PeerChallenge = NULL;
	}

      // Ignore the RADIUS host, we probably don't care.
      myvars->PeerChallenge = (u_char *)malloc(16);
      if (myvars->PeerChallenge == NULL) return XEMALLOC;

      RAND_bytes(myvars->PeerChallenge, 16);

      debug_printf(DEBUG_AUTHTYPES, "Generated PeerChallenge : ");
      debug_hex_printf(DEBUG_AUTHTYPES, myvars->PeerChallenge,16);

      if (myvars->NtResponse != NULL)
	{
	  free(myvars->NtResponse);
	  myvars->NtResponse = NULL;
	}

      myvars->NtResponse = (u_char *)malloc(24);
      if (myvars->NtResponse == NULL) return XEMALLOC;

      GenerateNTResponse(myvars->AuthenticatorChallenge, myvars->PeerChallenge,
			 username, userdata->password, myvars->NtResponse);

      debug_printf(DEBUG_AUTHTYPES, "myvars->NtResponse = ");
      debug_hex_printf(DEBUG_AUTHTYPES, myvars->NtResponse, 24);

      response->OpCode = MS_CHAPV2_RESPONSE;
      response->MS_CHAPv2_ID = challenge->MS_CHAPv2_ID;
      response->MS_Length = htons(54+strlen(username));   
      response->Value_Size = 49;
      memcpy((u_char *)&response->Peer_Challenge, myvars->PeerChallenge, 16);
      bzero((u_char *)&response->Reserved, 8);
      memcpy((u_char *)&response->NT_Response, myvars->NtResponse, 24);
      debug_printf(DEBUG_AUTHTYPES, "response->NT_Response = ");
      debug_hex_printf(DEBUG_AUTHTYPES, response->NT_Response, 24);
      response->Flags = 0;
      memcpy(&outframe[54],username, strlen(username));
      *outsize = (54 + strlen(username));
      break;

    case MS_CHAPV2_RESPONSE:
      debug_printf(DEBUG_NORMAL, "Got an MS-CHAPv2 Response!?  Ignoring.\n");
      *outsize = 0;
      break;

    case MS_CHAPV2_SUCCESS:
      debug_printf(DEBUG_AUTHTYPES, "(EAP-MSCHAPv2) Success!\n");
      success = (struct mschapv2_success_request *)dataoffs;

      bzero((u_char *)&recv[0], 41);
      memcpy((u_char *)&recv[0], (u_char *)&success->MsgField[2], 40);
      CheckAuthenticatorResponse(userdata->password, 
				 myvars->NtResponse, myvars->PeerChallenge,
				 myvars->AuthenticatorChallenge,
				 username, (u_char *)&recv[0], &respOk);

      if (respOk == 1)
	{
	  debug_printf(DEBUG_AUTHTYPES, "Server authentication check success!  Sending phase 2 success!\n");
	  outframe[0] = MS_CHAPV2_SUCCESS;
	  
	  // We were successful, so generate keying material.
	  NtPasswordHash(userdata->password, (u_char *)&NtHash);
	  HashNtPasswordHash((u_char *)&NtHash, (u_char *)&NtHashHash);
	  GetMasterKey((u_char *)&NtHashHash, myvars->NtResponse, (u_char *)&MasterKey);
	  
	  // Now, get the send key.
	  GetAsymetricStartKey((u_char *)&MasterKey, (u_char *)&mppeSend, 16, TRUE, FALSE);

	  // And the recv key.
	  GetAsymetricStartKey((u_char *)&MasterKey, (u_char *)&mppeRecv, 16, FALSE, FALSE);

	  // Finally, populate our myvars->keyingMaterial.
	  if (myvars->keyingMaterial != NULL)
	    {
	      free(myvars->keyingMaterial);
	      myvars->keyingMaterial = NULL;
	    }
	  myvars->keyingMaterial = (u_char *)malloc(64);  // 32 bytes each.
	  if (myvars->keyingMaterial == NULL) return XEMALLOC;

	  bzero(myvars->keyingMaterial, 64);
	  memcpy(&myvars->keyingMaterial[32], &mppeRecv, 16);
	  memcpy(myvars->keyingMaterial, &mppeSend, 16);
	} else {
	  debug_printf(DEBUG_AUTHTYPES, "Server verification check failed!  Sending PHASE 2 FAILURE!\n");
	  outframe[0] = MS_CHAPV2_FAILURE;
	}
      *outsize = 1;

      

      break;

    case MS_CHAPV2_FAILURE:
      debug_printf(DEBUG_NORMAL, "MS-CHAPv2 Authentication Failure!\n");
      *outsize = 0;
      // We should probably process the failure info, and respond as needed,
      // but, we really don't care if a failure is retryable, as 802.1x will
      // just try again anyway. ;)
      break;

    case MS_CHAPV2_CHANGE_PWD:
      debug_printf(DEBUG_NORMAL, "Password changing is not supported!\n");
      break;
    }

  return XENONE;
}

int eapmschapv2_get_keys(struct interface_data *thisint)
{
  struct mschapv2_vars *myconf;

  if ((!thisint) || (!thisint->userdata) || (!thisint->userdata->activemethod) || (!thisint->userdata->activemethod->eap_data))
      return XEMALLOC;

  myconf = (struct mschapv2_vars *)thisint->userdata->activemethod->eap_data;
  if (thisint->keyingMaterial != NULL)
    {
      free(thisint->keyingMaterial);
    }

  thisint->keyingMaterial = (char *)malloc(64);
  if (thisint->keyingMaterial == NULL) return -1;

  memcpy(thisint->keyingMaterial, myconf->keyingMaterial, 64);
  
  return XENONE;
}

int eapmschapv2_failed(struct generic_eap_data *thisint)
{
  struct config_eap_mschapv2 *userdata;

  if ((!thisint) || (!thisint->eap_conf_data))
    {
      debug_printf(DEBUG_AUTHTYPES, "No EAP MS-CHAPv2 configuration data!  Nothing to do!\n");
      return XEMALLOC;
    }

  userdata = (struct config_eap_mschapv2 *)thisint->eap_conf_data;

#ifndef NO_PWD_RESET
  /*
  if (userdata->password != NULL)
    {
      free(userdata->password);
      userdata->password = NULL;
    }
  */
#endif

  return XENONE;
}

int eapmschapv2_cleanup(struct generic_eap_data *thisint)
{
  struct mschapv2_vars *myvars;

  if (!thisint)
    {
      debug_printf(DEBUG_NORMAL, "Invalid interface structure in eapmschapv2_cleanup()!\n");
      return XEMALLOC;
    }

  myvars = (struct mschapv2_vars *)thisint->eap_data;

  if (thisint->eap_data != NULL)
    {
      if (myvars->AuthenticatorChallenge != NULL)
	{
	  free(myvars->AuthenticatorChallenge);
	  myvars->AuthenticatorChallenge = NULL;
	}

      if (myvars->PeerChallenge != NULL)
	{
	  free(myvars->PeerChallenge);
	  myvars->PeerChallenge = NULL;
	}

      if (myvars->NtResponse != NULL)
	{
	  free(myvars->NtResponse);
	  myvars->NtResponse = NULL;
	}
      
      if (myvars->keyingMaterial != NULL)
	{
	  free(myvars->keyingMaterial);
	  myvars->keyingMaterial = NULL;
	}

      free(thisint->eap_data);
      thisint->eap_data = NULL;
    }
  return XENONE;
}
