/**
 * A client-side 802.1x implementation 
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
 * The driver function for a Linux application layer EAPOL 
 * implementation
 * File: eapmd5.c
 *
 * Authors: Chris.Hessing@utah.edu
 *
 * $Id: eapmd5.c,v 1.1.1.1 2007/08/06 10:04:42 root Exp $
 * $Date: 2007/08/06 10:04:42 $
 * $Log: eapmd5.c,v $
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
 * Revision 1.15  2004/04/26 20:51:13  chessing
 *
 * Patch to attempt to fix the init_interface_* errors reported on the list.  Removed password clearing on failed authentication attempts.  Password clearing currently has some issues that will prevent it from being in the 1.0 stable.
 *
 * Revision 1.14  2004/04/13 22:13:29  chessing
 *
 * Additional error checking in all eap methods.
 *
 * Revision 1.13  2004/04/05 17:19:17  chessing
 *
 * Added additional checks against pointers to try to help prevent segfaults.  (This still needs to be completed.)  Fixed a problem with PEAP where a NULL input packet would result in a huge unencrypted packet, and a segfault.  (This was triggered when using one of the gui password tools.  When the password was in the config file, it wouldn't be triggered.)
 *
 * Revision 1.12  2004/03/22 05:33:47  chessing
 * Fixed some potential issues with the example config in etc.  Fixed several memory leaks in various locations.  Re-tested all EAP types except SIM/OTP/GTC/LEAP.  (Those test will happen this next week.) Getting close to a 1.0pre release!
 *
 * Revision 1.11  2004/03/19 23:43:56  chessing
 *
 * Lots of changes.  Changed the password prompting code to no longer require the EAP methods to maintain their own stale frame buffer.  (Frame buffer pointers should be moved out of generic_eap_data before a final release.)  Instead, EAP methods should set need_password in generic_eap_data to 1, along with the variables that identify the eap type being used, and the challenge data (if any -- only interesting to OTP/GTC at this point).  Also fixed up xsup_set_pwd.c, and got it back in CVS.  (For some reason, it was in limbo.)  Added xsup_monitor under gui_tools/cli.  xsup_monitor will eventually be a cli program that will monitor XSupplicant (running as a daemon) and display status information, and request passwords when they are not in the config.
 *
 * Revision 1.10  2004/02/16 05:05:59  chessing
 *
 * Added support for the deny_interfaces, and allow_interfaces options in the config file.  (We should now have support for *EVERYTHING* in the new config file format!)  Updated EAP types other than SIM to use the new password prompt/delay code.  Phase 2 of TTLS still needs to be completed, along with the code that actually notifies the GUI.
 *
 * Revision 1.9  2004/02/09 21:50:06  chessing
 *
 * Added patches from Jouni Malinen.  Includes an EAP-MD5 fix, dec_if_nz() patch, more debugging information from the state machine, and global state changes.
 *
 * Revision 1.8  2004/01/20 05:57:05  chessing
 *
 * All EAP types except PEAP and TTLS now support having their passwords sent in via the command line program.  (This means no more gets() call in OTP!)  A config_eap_otp structure was created in config.h to support GTC/OTP.  We need to define an eap_otp and eap_gtc config section.  Since both require some kind of information be presented there are no attributes that need to be defined in their part of the configuration.
 *
 * Revision 1.7  2004/01/17 21:16:16  chessing
 *
 * Various segfault fixes.  PEAP now works correctly again.  Some new error checking in the tls handlers.  Fixes for the way we determine if we have changed ESSIDs.  We now quit when we don't have a config, or when the config is bad. Added code to check and see if a frame is in the queue, and don't sleep if there is.  "Fixed" ID issue by inheriting the ID from the parent where needed.  However, assigning an ID inside of a handler will override the parent ID.  This could cause problems with some EAP types.  We should add a "username" field to PEAP to allow configuration of the inner EAP identity.
 *
 * Revision 1.6  2004/01/15 23:45:11  chessing
 *
 * Fixed a segfault when looking for wireless interfaces when all we had was a wired interface.  Fixed external command execution so that junk doesn't end up in the processed string anymore.  Changed the state machine to call txRspAuth even if there isn't a frame to process.  This will enable EAP methods to request information from a GUI interface (such as passwords, or supply challenge information that might be needed to generate passwords).  EAP methods now must decide what to do when they are handed NULL for the pointer to the in frame.  If they don't need any more data, they should quietly exit.
 *
 * Revision 1.5  2004/01/15 01:12:45  chessing
 *
 * Fixed a keying problem (keying material wasn't being generated correctly).  Added support for global counter variables from the config file. (Such as auth_period)  Added support for executing command defined in the config file based on different events.  (Things such as what to do on reauth.)  Added the ability to roam to a different SSID.  We now check to make sure our BSSID hasn't changed, and we follow it, if it has.  Fixed a sefault when the program was terminated in certain states.  Added attempt at better garbage collection on program termination. Various small code cleanups.
 *
 * Revision 1.4  2004/01/13 01:55:55  chessing
 *
 * Major changes to EAP related code.  We no longer pass in an interface_data struct to EAP handlers.  Instead, we hand in a generic_eap_data struct which containsnon-interface specific information.  This will allow EAP types to be reused as phase 2 type easier.  However, this new code may create issues with EAP types that make use of the identity in the eap type.  Somehow, the identity value needs to propigate down to the EAP method.  It currently does not.  This should be any easy fix, but more testing will be needed.
 *
 * Revision 1.3  2004/01/06 23:35:07  chessing
 *
 * Fixed a couple known bugs in SIM.  Config file support should now be in place!!! But, because of the changes, PEAP is probably broken.  We will need to reconsider how the phase 2 piece of PEAP works.
 *
 * Revision 1.2  2003/11/22 06:10:37  chessing
 *
 * Changes to the eap type process calls, to remove a pointless parameter.
 *
 * Revision 1.1.1.1  2003/11/19 04:13:25  chessing
 * New source tree
 *
 *
 *
 *******************************************************************/

#include <openssl/ssl.h>
#include <string.h>
#include <strings.h>

#include "xsup_debug.h"
#include "xsup_err.h"
#include "frame_structs.h"
#include "config.h"   // For config_eap_md5 struct.
#include "eap.h"
#include "eapmd5.h"
#include "interactive.h"

#define MD5_LENGTH    0x10

/*****************************************************
 *
 * Setup to handle MD5 EAP requests
 *
 * This function is called each time we recieve a packet of the EAP type MD5.
 * At a minimum, it should check to make sure it's stub in the structure 
 * exists, and if not, set up any variables it may need.  Since MD5 doesn't
 * have any state that needs to survive successive calls, we don't need to 
 * do anything here.
 *
 *****************************************************/
int eapmd5_setup(struct generic_eap_data *thisint)
{
  // Do anything special that might be needed for this EAP type to work.
  debug_printf(DEBUG_EVERYTHING, "Initalized EAP-MD5!\n");

  if (!thisint)
    {
      debug_printf(DEBUG_NORMAL, "Invalid EAP structure passed in to eapmd5_setup()!\n");
      return XEMALLOC;
    }

  thisint->eap_data = (int *)malloc(sizeof(int));
  if (thisint->eap_data == NULL) return XEMALLOC;

  return XENONE;
}


/*****************************************************
 *
 * Process MD5 EAP Requests
 *
 *
 ******************************************************/
int eapmd5_process(struct generic_eap_data *thisint, u_char *dataoffs, 
		   int insize, u_char *outframe, int *outsize)
{
  struct md5_values *md5data, *md5out;
  struct config_eap_md5 *userdata;
  u_char md5_result[16];
  u_char *tohash;
  char *username;
  int tohashlen;
  int *processReady;

  if (!thisint->eap_data)
    {
      debug_printf(DEBUG_NORMAL, "Invalid EAP data passed in to eapmd5_process()!\n");
      return XEMALLOC;
    }

  if (!outframe)
    {
      debug_printf(DEBUG_NORMAL, "Invalid buffer for return data in eapmd5_process()!\n");
      return XEMALLOC;
    }

  processReady = (int *)thisint->eap_data;
  userdata = (struct config_eap_md5 *)thisint->eap_conf_data;

  debug_printf(DEBUG_EVERYTHING, "(EAP-MD5) Processing.\n");

  if ((thisint->tempPwd == NULL) && (userdata->password == NULL))
    {
      thisint->need_password = 1;
      thisint->eaptype = strdup("EAP-MD5");
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
      /*      debug_printf(DEBUG_AUTHTYPES, "Passed in password : %s\n",
	      userdata->password);*/
    }

  // Actually process, and respond to challenges.
  md5data = (struct md5_values *)dataoffs;
  md5out = (struct md5_values *)outframe;
  
  if (md5data->length != MD5_LENGTH)
    {
      debug_printf(DEBUG_NORMAL, "(EAP-MD5) Incorrect length value for MD5 random value.\n");
      return XEMD5LEN;
    }

  tohashlen = (1+md5data->length+strlen(userdata->password));
  tohash = (u_char *)malloc(tohashlen);
  if (tohash == NULL)
    {
      debug_printf(DEBUG_NORMAL, "(EAP-MD5) Couldn't allocate memory for building hash source!\n");
      return XEMALLOC;
    }

  // Make sure we clean out the memory space.
  bzero(tohash, tohashlen);
  
  // Build the information we need to hash. Start with the EAP identifier.
  tohash[0] = thisint->eapid;

  // Then, we need the password.
  memcpy(&tohash[1], userdata->password, strlen(userdata->password));
  
  // Then the random value sent to us.
  memcpy(&tohash[1+strlen(userdata->password)], &md5data->randval, MD5_LENGTH);

  // Now, run it through the hash routine.
  MD5(tohash, tohashlen, &md5_result[0]);

  // We are done with tohash, so free it.
  free(tohash);

  // Set up our response frame.
  md5out->length = MD5_LENGTH;
  memcpy(&md5out->randval[0], &md5_result[0], MD5_LENGTH);

  memcpy(&outframe[sizeof(struct md5_values)], username, strlen(username));

  *outsize = (sizeof(struct md5_values)+strlen(username));

  return XENONE;
}

/*******************************************************
 *
 * Set our keys, if we can.
 *
 *******************************************************/
int eapmd5_get_keys(struct interface_data *thisint)
{
  // We don't key, so return -1.  (We return 0 if we set a key.)
  return -1;
}

/*******************************************************
 *
 * Clean up after ourselves.  This will get called when we get a packet that
 * needs to be processed requests a different EAP type.  It will also be 
 * called on termination of the program.
 *
 *******************************************************/
int eapmd5_cleanup(struct generic_eap_data *thisint)
{
  // Clean up after ourselves.

  debug_printf(DEBUG_AUTHTYPES, "(EAP-MD5) Cleaning up.\n");

  if (thisint->eap_data != NULL)
    {
      free(thisint->eap_data);
      thisint->eap_data = NULL;
    }

  return XENONE;
}

/*******************************************************
 *
 * If we fail an authentication, we will call this routine.  It should clean
 * up anything that shouldn't live in to the next authentication attempt.
 *
 *******************************************************/
int eapmd5_failed(struct generic_eap_data *thisint)
{
  struct config_eap_md5 *userdata;

  if ((thisint == NULL) || (thisint->eap_conf_data == NULL))
    {
      debug_printf(DEBUG_AUTHTYPES, "Invalid MD5 configuration data!\n");
      return XEMALLOC;
    }

  userdata = (struct config_eap_md5 *)thisint->eap_conf_data;

  // If configure was passed the no password reset flag, we shouldn't do
  // anything!
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
